// SPDX-License-Identifier: GPL-3.0-or-later
//! BlueZ LE advertising through bluer; handles unregister when dropped.
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
pub struct Wake {
    _session: Session,
    adapter: Adapter,
    handle: Option<AdvertisementHandle>,
    was_powered: bool,
    pub tag: [u8; 3],
}
impl Wake {
    pub async fn start(adapter_name: Option<&str>, hashes: [u8; 8]) -> Result<Self> {
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
        let was_powered = adapter.is_powered().await?;
        if !was_powered {
            adapter.set_powered(true).await?;
        }
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
                if !was_powered {
                    let _ = adapter.set_powered(false).await;
                }
                return Err(e.into());
            }
        };
        tracing::info!(adapter = adapter.name(), "AirDrop BLE wake-up advertising");
        Ok(Self {
            _session: session,
            adapter,
            handle: Some(handle),
            was_powered,
            tag,
        })
    }
    pub async fn stop(&mut self) {
        self.handle.take();
        if !self.was_powered {
            let _ = self.adapter.set_powered(false).await;
        }
    }
}
