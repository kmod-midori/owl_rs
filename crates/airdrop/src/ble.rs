// SPDX-License-Identifier: GPL-3.0-or-later
//! BlueZ LE wake scanning and advertising through bluer.
use anyhow::{Context, Result};
use bluer::{
    Adapter, Session,
    adv::{Advertisement, AdvertisementHandle, Type},
};
use std::{collections::BTreeMap, time::Duration};
pub fn payload(tag: [u8; 3], hashes: [u8; 8]) -> Vec<u8> {
    let mut data = vec![5, 18, 0x40];
    data.extend(tag);
    data.extend([0; 4]);
    data.push(3);
    data.extend(hashes);
    data.push(0);
    data
}

// Scanning and advertising share adapter power. Releasing an Off-mode scanner
// must not power down an outgoing sender that still holds an advertisement.
static POWER: tokio::sync::Mutex<BTreeMap<String, (usize, bool)>> =
    tokio::sync::Mutex::const_new(BTreeMap::new());
struct PowerLease {
    adapter: Adapter,
    held: bool,
    restore_timeout: Duration,
}
impl PowerLease {
    async fn acquire(adapter: &Adapter, restore_timeout: Duration) -> Result<Self> {
        let mut users = POWER.lock().await;
        if let Some((count, _)) = users.get_mut(adapter.name()) {
            *count += 1;
            return Ok(Self {
                adapter: adapter.clone(),
                held: true,
                restore_timeout,
            });
        }
        let powered = adapter.is_powered().await?;
        users.insert(adapter.name().to_owned(), (1, powered));
        let mut lease = Self {
            adapter: adapter.clone(),
            held: true,
            restore_timeout,
        };
        if !powered && let Err(error) = adapter.set_powered(true).await {
            drop(users);
            lease.release().await;
            return Err(error.into());
        }
        Ok(lease)
    }
    async fn release(&mut self) {
        if self.held {
            let adapter = self.adapter.clone();
            let timeout = self.restore_timeout;
            let release = tokio::spawn(async move {
                release_power(&adapter, timeout).await;
            });
            self.held = false;
            // Cancellation of this actor must not discard an already-owned
            // decrement while another scanner/advertiser still runs.
            let _ = release.await;
        }
    }
}
async fn release_power(adapter: &Adapter, timeout: Duration) {
    let mut users = POWER.lock().await;
    if let Some((count, powered)) = users.get_mut(adapter.name()) {
        *count -= 1;
        if *count == 0 {
            let restore_off = !*powered;
            users.remove(adapter.name());
            if restore_off {
                let _ = tokio::time::timeout(timeout, adapter.set_powered(false)).await;
            }
        }
    }
}
impl Drop for PowerLease {
    fn drop(&mut self) {
        if self.held
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            let adapter = self.adapter.clone();
            let timeout = self.restore_timeout;
            runtime.spawn(async move {
                release_power(&adapter, timeout).await;
            });
        }
    }
}

pub struct Wake {
    _session: Session,
    handle: Option<AdvertisementHandle>,
    power: PowerLease,
    pub tag: [u8; 3],
}
impl Wake {
    pub async fn start(
        adapter_name: Option<&str>,
        hashes: [u8; 8],
        timeouts: crate::timeouts::Timeouts,
    ) -> Result<Self> {
        let session = Session::new().await.context("connect to BlueZ")?;
        let adapter = match adapter_name {
            Some(name) => session.adapter(name)?,
            None => session
                .default_adapter()
                .await
                .context("no Bluetooth adapter available")?,
        };
        let mut tag = [0; 3];
        openssl::rand::rand_bytes(&mut tag)?;
        let mut power = PowerLease::acquire(&adapter, timeouts.ble_power_restore).await?;
        let advert = Advertisement {
            advertisement_type: Type::Peripheral,
            manufacturer_data: BTreeMap::from([(0x004c, payload(tag, hashes))]),
            min_interval: Some(Duration::from_millis(100)),
            max_interval: Some(Duration::from_millis(100)),
            ..Default::default()
        };
        let handle = match adapter.advertise(advert).await {
            Ok(h) => h,
            Err(e) => {
                power.release().await;
                return Err(e.into());
            }
        };
        tracing::info!(adapter = adapter.name(), "AirDrop BLE wake-up advertising");
        Ok(Self {
            _session: session,
            handle: Some(handle),
            power,
            tag,
        })
    }
    pub async fn stop(&mut self) {
        self.handle.take();
        self.power.release().await;
    }
}

/// Decode Apple manufacturer TLVs. Addresses and short hashes are not identities.
#[derive(Clone, Copy)]
pub(crate) struct WakeHint {
    pub hashes: [u8; 8],
}
fn wake_hint(mut data: &[u8]) -> Option<WakeHint> {
    let mut tag = None;
    while !data.is_empty() {
        let (&kind, rest) = data.split_first()?;
        let (&length, rest) = rest.split_first()?;
        let (body, rest) = rest.split_at_checked(usize::from(length))?;
        if kind == 5 {
            if body.len() != 18 || tag.is_some() {
                return None;
            }
            tag = Some(WakeHint {
                hashes: body[9..17].try_into().ok()?,
            });
        }
        data = rest;
    }
    tag
}

// The same filter is checked again immediately before starting or refreshing
// a session: a queued Everyone wake must not bypass a later Contacts policy.
pub(crate) async fn eligible(hint: WakeHint, policy: crate::visibility::Policy) -> bool {
    use crate::visibility::Visibility;
    match policy.mode {
        Visibility::Off => false,
        Visibility::Everyone => true,
        Visibility::Contacts => match policy.contacts {
            Some(contacts) => {
                tokio::task::spawn_blocking(move || contacts.matches_ble(&hint.hashes))
                    .await
                    .is_ok_and(|result| result.unwrap_or(false))
            }
            None => false,
        },
    }
}

// Reject cached discovery snapshots; only live ManufacturerData changes can wake
// Wi-Fi. BlueZ duplicate-data events are enabled to see unchanged fresh adverts.
pub(crate) async fn listen(
    adapter_name: Option<&str>,
    mut policy: tokio::sync::watch::Receiver<crate::visibility::Policy>,
    cancel: tokio_util::sync::CancellationToken,
    wakes: tokio::sync::mpsc::Sender<WakeHint>,
    listening: tokio::sync::watch::Sender<bool>,
    timeouts: crate::timeouts::Timeouts,
) -> Result<()> {
    use crate::visibility;
    use bluer::{AdapterEvent, DeviceEvent, DeviceProperty, DiscoveryFilter, DiscoveryTransport};
    use futures_util::{StreamExt, stream::SelectAll};
    use std::collections::HashSet;
    loop {
        while !policy.borrow().mode.enabled() {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                _ = visibility::changed(&mut policy) => (),
            }
        }
        let session = Session::new()
            .await
            .context("connect BLE listener to BlueZ")?;
        let adapter = match adapter_name {
            Some(name) => session.adapter(name)?,
            None => session
                .default_adapter()
                .await
                .context("no BLE adapter available")?,
        };
        let mut power = PowerLease::acquire(&adapter, timeouts.ble_power_restore).await?;
        let result = async {
            adapter.set_discovery_filter(DiscoveryFilter {
                transport: DiscoveryTransport::Le,
                duplicate_data: true,
                discoverable: false,
                ..Default::default()
            }).await?;
            let devices = adapter.discover_devices().await?;
            tokio::pin!(devices);
            let mut watched = HashSet::new();
            let mut changes = SelectAll::new();
            listening.send_replace(true);
            tracing::info!("listening for AirDrop BLE wake requests");
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = visibility::changed(&mut policy) => {
                        if !policy.borrow().mode.enabled() { break; }
                    }
                    event = devices.next() => match event.context("BLE discovery stopped")? {
                        AdapterEvent::DeviceAdded(address) if watched.len() < 512 && !watched.contains(&address) => {
                            // Devices can disappear between discovery and subscription.
                            // A per-device failure must not release the adapter's scan.
                            let events = match adapter.device(address) {
                                Ok(device) => device.events().await,
                                Err(error) => Err(error),
                            };
                            match events {
                                Ok(events) => {
                                    watched.insert(address);
                                    changes.push(events.map(move |event| (address, event)).boxed());
                                }
                                Err(error) => tracing::debug!(%address, %error, "BLE device subscription unavailable"),
                            }
                        }
                        AdapterEvent::DeviceRemoved(address) => { watched.remove(&address); }
                        _ => (),
                    },
                    Some((_address, event)) = changes.next(), if !changes.is_empty() => {
                        let DeviceEvent::PropertyChanged(DeviceProperty::ManufacturerData(data)) = event else { continue; };
                        if !policy.borrow().mode.enabled() { continue; }
                        let Some(hint) = data.get(&0x004c).and_then(|data| wake_hint(data)) else { continue; };
                        let observed = tokio::time::Instant::now();
                        let current = policy.borrow().clone();
                        if !eligible(hint, current.clone()).await { continue; }
                        if policy.borrow().revision != current.revision || !policy.borrow().mode.enabled() { continue; }
                        tracing::debug!(filter_ms=observed.elapsed().as_millis(), "eligible AirDrop BLE advertisement observed");
                        let _ = wakes.try_send(hint);
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        }.await;
        // Dropping the discovery stream releases bluer's BlueZ discovery token.
        listening.send_replace(false);
        power.release().await;
        result?;
        if cancel.is_cancelled() {
            return Ok(());
        }
    }
}

pub(crate) async fn receiving(
    adapter_name: Option<&str>,
    hashes: [u8; 8],
    mut policy: tokio::sync::watch::Receiver<crate::visibility::Policy>,
    cancel: tokio_util::sync::CancellationToken,
    timeouts: crate::timeouts::Timeouts,
) -> Result<()> {
    use crate::visibility;
    let mut wake: Option<Wake> = None;
    loop {
        if policy.borrow().mode.enabled() && wake.is_none() {
            match Wake::start(adapter_name, hashes, timeouts).await {
                Ok(advert) => wake = Some(advert),
                Err(error) => {
                    tracing::warn!("receiving BLE advertising unavailable: {error:#}");
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = visibility::changed(&mut policy) => (),
                        _ = tokio::time::sleep(timeouts.ble_retry) => (),
                    }
                    continue;
                }
            }
        } else if !policy.borrow().mode.enabled()
            && let Some(mut advert) = wake.take()
        {
            advert.stop().await;
        }
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = visibility::changed(&mut policy) => (),
        }
    }
    if let Some(mut advert) = wake {
        advert.stop().await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wake_tlvs_require_complete_unambiguous_airdrop_frames() {
        let advert = payload([1, 2, 3], [0; 8]);
        assert_eq!(wake_hint(&advert).map(|hint| hint.hashes), Some([0; 8]));
        for end in 1..advert.len() {
            assert_eq!(wake_hint(&advert[..end]).map(|hint| hint.hashes), None);
        }
        let mut composite = vec![9, 1, 42];
        composite.extend(&advert);
        assert_eq!(wake_hint(&composite).map(|hint| hint.hashes), Some([0; 8]));
        composite.extend(&advert);
        assert_eq!(wake_hint(&composite).map(|hint| hint.hashes), None);
        let mut trailing = advert.clone();
        trailing.push(9);
        assert_eq!(wake_hint(&trailing).map(|hint| hint.hashes), None);
        assert_eq!(wake_hint(&[9, 1, 42]).map(|hint| hint.hashes), None);
        let mut bad_length = advert;
        bad_length[1] = 17;
        assert_eq!(wake_hint(&bad_length).map(|hint| hint.hashes), None);
    }
}
