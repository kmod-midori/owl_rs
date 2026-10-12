// SPDX-License-Identifier: GPL-3.0-or-later
//! Scoped Tokio netlink connections; kernel ACKs complete every mutation.
use crate::protocol::Mac;
use anyhow::{Context, Result, bail};
use futures_util::{StreamExt, TryStreamExt};
use rtnetlink::{
    LinkUnspec,
    packet_route::{
        AddressFamily,
        address::{AddressAttribute, AddressFlags, AddressHeaderFlags, AddressScope},
        link::{LinkFlags, LinkMessage},
        neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourMessage},
    },
};
use std::{future::Future, net::IpAddr, sync::Arc, time::Duration};
use tokio::task::JoinHandle;
use wl_nl80211::{
    Nl80211Attr as Attr, Nl80211BandInfo, Nl80211BssInfo, Nl80211Command as Cmd, Nl80211Features,
    Nl80211FrequencyInfo as FreqInfo, Nl80211Handle, Nl80211HtWiphyChannelType,
    Nl80211InterfaceType as IfType, Nl80211Message,
    packet_core::{
        DefaultNla, Emitable, NLA_F_NESTED, NLM_F_ACK, NLM_F_REQUEST, NetlinkMessage,
        NetlinkPayload,
    },
    packet_generic::GenlMessage,
};

#[derive(Clone)]
pub struct Netlink(Arc<Connections>);
struct Connections {
    route: rtnetlink::Handle,
    wifi: Nl80211Handle,
    route_task: JoinHandle<()>,
    wifi_task: JoinHandle<()>,
}
impl Drop for Connections {
    fn drop(&mut self) {
        self.route_task.abort();
        self.wifi_task.abort();
    }
}
#[derive(Clone, Debug)]
pub struct Interface {
    pub index: u32,
    pub name: String,
    pub phy: u32,
    pub kind: IfType,
    pub frequency: Option<u32>,
}
async fn bounded<T, E: Into<anyhow::Error>>(
    f: impl Future<Output = std::result::Result<T, E>>,
) -> Result<T> {
    tokio::time::timeout(Duration::from_secs(5), f)
        .await
        .context("netlink request timed out")?
        .map_err(Into::into)
}

// Stable Linux UAPI attributes not yet given typed variants by wl-nl80211.
// include/uapi/linux/nl80211.h: MNTR_FLAGS=23, MNTR_FLAG_ACTIVE=6,
// FREQ_FIXED=60, BEACON_INTERVAL=12. Netlink numbers/lengths use native endian.
fn monitor_flags(active: bool) -> Attr {
    let flags = if active {
        vec![DefaultNla::new(6, vec![])]
    } else {
        vec![]
    };
    let mut bytes = vec![0; flags.as_slice().buffer_len()];
    flags.as_slice().emit(&mut bytes);
    Attr::Other(DefaultNla::new(23 | NLA_F_NESTED, bytes))
}
fn tx_frequency(info: &[FreqInfo]) -> Option<u32> {
    if info.iter().any(|a| {
        matches!(
            a,
            FreqInfo::Disabled | FreqInfo::NoIr | FreqInfo::NoIbss | FreqInfo::Radar
        )
    }) {
        return None;
    }
    info.iter().find_map(|a| {
        if let FreqInfo::Freq(f) = a {
            Some(*f)
        } else {
            None
        }
    })
}
impl Netlink {
    pub fn new() -> Result<Self> {
        let (route, route_handle, _) =
            rtnetlink::new_connection().context("open routing netlink")?;
        let (wifi, wifi_handle, _) =
            wl_nl80211::new_connection().context("open wireless netlink")?;
        Ok(Self(Arc::new(Connections {
            route: route_handle,
            wifi: wifi_handle,
            route_task: tokio::spawn(route),
            wifi_task: tokio::spawn(wifi),
        })))
    }
    pub async fn link(&self, name: &str) -> Result<LinkMessage> {
        bounded(
            self.0
                .route
                .link()
                .get()
                .match_name(name)
                .execute()
                .try_next(),
        )
        .await?
        .with_context(|| format!("interface {name} not found"))
    }
    async fn index(&self, name: &str) -> Result<u32> {
        Ok(self.link(name).await?.header.index)
    }
    pub async fn set_up(&self, name: &str, up: bool) -> Result<()> {
        let builder = LinkUnspec::new_with_index(self.index(name).await?);
        let msg = if up { builder.up() } else { builder.down() }.build();
        bounded(self.0.route.link().set(msg).execute())
            .await
            .with_context(|| format!("set {name} up={up}"))
    }
    pub async fn set_mac(&self, name: &str, mac: Mac) -> Result<()> {
        let msg = LinkUnspec::new_with_index(self.index(name).await?)
            .address(mac.0.to_vec())
            .build();
        bounded(self.0.route.link().set(msg).execute())
            .await
            .context("set interface MAC")
    }
    pub async fn is_up(&self, name: &str) -> Result<bool> {
        Ok(self.link(name).await?.header.flags.contains(LinkFlags::Up))
    }
    async fn wifi_request(&self, cmd: Cmd, attributes: Vec<Attr>) -> Result<()> {
        let mut handle = self.0.wifi.clone();
        let mut msg = NetlinkMessage::from(GenlMessage::from_payload(Nl80211Message {
            cmd,
            attributes,
        }));
        msg.header.flags = NLM_F_REQUEST | NLM_F_ACK;
        bounded(async {
            let mut responses = handle.request(msg).await?;
            while let Some(response) = responses.next().await {
                match response?.payload {
                    NetlinkPayload::Error(error) if error.code.is_some() => {
                        return Err(wl_nl80211::Nl80211Error::NetlinkError(error).into());
                    }
                    NetlinkPayload::Overrun(_) => bail!("wireless netlink overrun"),
                    _ => (),
                }
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .with_context(|| format!("nl80211 {cmd:?}"))
    }
    pub async fn interfaces(&self) -> Result<Vec<Interface>> {
        let msgs: Vec<_> = bounded(async {
            self.0
                .wifi
                .interface()
                .get(vec![])
                .execute()
                .await
                .try_collect()
                .await
        })
        .await?;
        let mut interfaces = Vec::new();
        for msg in msgs {
            let (mut index, mut name, mut phy, mut kind, mut frequency) =
                (None, None, None, None, None);
            for attr in msg.payload.attributes {
                match attr {
                    Attr::IfIndex(v) => index = Some(v),
                    Attr::IfName(v) => name = Some(v),
                    Attr::Wiphy(v) => phy = Some(v),
                    Attr::IfType(v) => kind = Some(v),
                    Attr::WiphyFreq(v) => frequency = Some(v),
                    _ => (),
                }
            }
            let Some(index) = index else { continue };
            interfaces.push(Interface {
                index,
                name: name.context("missing Wi-Fi name")?,
                phy: phy.context("missing Wi-Fi PHY")?,
                kind: kind.context("missing Wi-Fi type")?,
                frequency,
            });
        }
        Ok(interfaces)
    }

    pub async fn interface(&self, name: &str) -> Result<Interface> {
        self.interfaces()
            .await?
            .into_iter()
            .find(|i| i.name == name)
            .with_context(|| format!("Wi-Fi interface {name} not found"))
    }
    /// Read cached BSS state without triggering an active scan. Status 1 is
    /// associated; status 2 is an IBSS join. Authentication alone is not a link.
    pub async fn linked_frequency(&self, name: &str, ibss: bool) -> Result<Option<u32>> {
        let index = self.index(name).await?;
        let msgs: Vec<_> = bounded(async {
            self.0
                .wifi
                .scan()
                .dump(index)
                .execute()
                .await
                .try_collect()
                .await
        })
        .await?;
        for msg in msgs {
            for attr in msg.payload.attributes {
                if let Attr::Bss(info) = attr
                    && info.iter().any(
                        |a| matches!(a, Nl80211BssInfo::Status(v) if *v == if ibss {2} else {1}),
                    )
                {
                    return Ok(info.iter().find_map(|a| {
                        if let Nl80211BssInfo::Frequency(v) = a {
                            Some(*v)
                        } else {
                            None
                        }
                    }));
                }
            }
        }
        Ok(None)
    }
    pub async fn phy_capabilities(&self, phy: u32) -> Result<(Vec<u32>, bool)> {
        let msgs: Vec<_> = bounded(async {
            self.0
                .wifi
                .wireless_physic()
                .get()
                .wiphy_index(phy)
                .execute()
                .await
                .try_collect()
                .await
        })
        .await?;
        let mut frequencies = Vec::new();
        let mut active_monitor = false;
        for msg in msgs {
            for attr in msg.payload.attributes {
                match attr {
                    Attr::Features(flags) => {
                        active_monitor |= flags.contains(Nl80211Features::ActiveMonitor)
                    }
                    Attr::WiphyBands(bands) => {
                        for band in bands {
                            for attr in band.info {
                                if let Nl80211BandInfo::Freqs(freqs) = attr {
                                    frequencies
                                        .extend(freqs.iter().filter_map(|f| tx_frequency(&f.info)));
                                }
                            }
                        }
                    }
                    _ => (),
                }
            }
        }
        frequencies.sort_unstable();
        frequencies.dedup();
        Ok((frequencies, active_monitor))
    }
    pub async fn set_type(&self, name: &str, kind: IfType) -> Result<()> {
        let mut attrs = vec![Attr::IfIndex(self.index(name).await?), Attr::IfType(kind)];
        if kind == IfType::Monitor {
            // Drivers may reject a separate flags update after converting the interface.
            attrs.push(monitor_flags(false));
        }
        self.wifi_request(Cmd::SetInterface, attrs)
            .await
            .with_context(|| format!("set {name} interface type to {kind:?}"))
    }
    pub async fn create_interface(
        &self,
        phy: u32,
        name: &str,
        kind: IfType,
        active: bool,
    ) -> Result<()> {
        let mut attrs = vec![
            Attr::Wiphy(phy),
            Attr::IfName(name.into()),
            Attr::IfType(kind),
        ];
        if kind == IfType::Monitor {
            attrs.push(monitor_flags(active));
        }
        self.wifi_request(Cmd::NewInterface, attrs).await
    }
    pub async fn delete_interface(&self, name: &str) -> Result<()> {
        self.wifi_request(
            Cmd::DelInterface,
            vec![Attr::IfIndex(self.index(name).await?)],
        )
        .await
    }
    pub async fn tune(&self, name: &str, frequency: u32) -> Result<()> {
        self.wifi_request(
            Cmd::SetWiphy,
            vec![
                Attr::IfIndex(self.index(name).await?),
                Attr::WiphyFreq(frequency),
                Attr::WiphyChannelType(Nl80211HtWiphyChannelType::Ht20),
            ],
        )
        .await
        .with_context(|| format!("tune {name} to {frequency} MHz"))
    }
    pub async fn join_ibss(&self, name: &str, frequency: u32) -> Result<()> {
        self.wifi_request(
            Cmd::JoinIbss,
            vec![
                Attr::IfIndex(self.index(name).await?),
                Attr::Ssid("owl_rs".into()),
                Attr::WiphyFreq(frequency),
                Attr::WiphyChannelType(Nl80211HtWiphyChannelType::Ht20),
                Attr::Mac(crate::protocol::BSSID.0),
                Attr::Other(DefaultNla::new(60, vec![])),
                Attr::Other(DefaultNla::new(12, 10000u32.to_ne_bytes().to_vec())),
            ],
        )
        .await
    }
    pub async fn leave_ibss(&self, name: &str) -> Result<()> {
        self.wifi_request(Cmd::LeaveIbss, vec![Attr::IfIndex(self.index(name).await?)])
            .await
    }
    pub async fn address(&self, name: &str, mac: Mac) -> Result<()> {
        let mut req = self
            .0
            .route
            .address()
            .add(self.index(name).await?, IpAddr::V6(mac.ipv6()), 64)
            .replace();
        let message = req.message_mut();
        message.header.scope = AddressScope::Link;
        message.header.flags |= AddressHeaderFlags::Nodad;
        message
            .attributes
            .push(AddressAttribute::Flags(AddressFlags::Nodad));
        bounded(req.execute()).await
    }
    pub async fn address_ready(&self, name: &str, mac: Mac) -> Result<bool> {
        let msgs: Vec<_> = bounded(
            self.0
                .route
                .address()
                .get()
                .set_link_index_filter(self.index(name).await?)
                .execute()
                .try_collect(),
        )
        .await?;
        Ok(msgs.iter().any(|msg| {
            let mut flags = AddressFlags::from_bits_retain(msg.header.flags.bits().into());
            let mut matches = false;
            for attr in &msg.attributes {
                match attr {
                    AddressAttribute::Flags(f) => flags |= *f,
                    AddressAttribute::Address(IpAddr::V6(a))
                    | AddressAttribute::Local(IpAddr::V6(a)) => matches |= *a == mac.ipv6(),
                    _ => (),
                }
            }
            matches && !flags.intersects(AddressFlags::Dadfailed | AddressFlags::Tentative)
        }))
    }
    pub async fn neighbor(&self, name: &str, mac: Mac, add: bool) -> Result<()> {
        let index = self.index(name).await?;
        if add {
            bounded(
                self.0
                    .route
                    .neighbours()
                    .add(index, IpAddr::V6(mac.ipv6()))
                    .link_layer_address(&mac.0)
                    .replace()
                    .execute(),
            )
            .await
        } else {
            let mut msg = NeighbourMessage::default();
            msg.header.family = AddressFamily::Inet6;
            msg.header.ifindex = index;
            msg.attributes
                .push(NeighbourAttribute::Destination(NeighbourAddress::Inet6(
                    mac.ipv6(),
                )));
            bounded(self.0.route.neighbours().del(msg).execute()).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wl_nl80211::packet_core::{Nla, NlaBuffer, NlasIterator};
    #[test]
    fn monitor_flag_nesting_and_regulatory_exclusions() {
        let active = monitor_flags(true);
        assert_eq!(active.kind(), 23 | NLA_F_NESTED);
        let mut value = vec![0; active.value_len()];
        active.emit_value(&mut value);
        let flags: Vec<_> = NlasIterator::new(&value).collect();
        assert_eq!(flags.len(), 1);
        let flag: &NlaBuffer<_> = flags[0].as_ref().unwrap();
        assert_eq!(flag.kind(), 6);
        assert!(flag.value().is_empty());
        assert_eq!(monitor_flags(false).value_len(), 0);
        for restriction in [
            FreqInfo::Disabled,
            FreqInfo::NoIr,
            FreqInfo::NoIbss,
            FreqInfo::Radar,
        ] {
            assert_eq!(tx_frequency(&[FreqInfo::Freq(5745), restriction]), None);
        }
        assert_eq!(tx_frequency(&[FreqInfo::Freq(5745)]), Some(5745));
    }
}
