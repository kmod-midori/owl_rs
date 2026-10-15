// SPDX-License-Identifier: GPL-3.0-or-later
//! Scoped Tokio netlink connections; kernel ACKs complete every mutation.
use crate::channel::ChannelDefinition;
use crate::protocol::{BandCapabilities, HtCapabilities, Mac, RadioCapabilities, VhtCapabilities};
use anyhow::{Context, Result, bail};
use futures_util::{StreamExt, TryStreamExt};
use rtnetlink::{
    LinkUnspec,
    packet_route::{
        AddressFamily,
        address::{AddressAttribute, AddressFlags, AddressHeaderFlags, AddressScope},
        link::{LinkAttribute, LinkFlags, LinkMessage},
        neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourMessage},
    },
};
use std::{future::Future, net::IpAddr, sync::Arc, time::Duration};
use tokio::task::JoinHandle;
use wl_nl80211::{
    Nl80211Attr as Attr, Nl80211BandInfo, Nl80211BandType, Nl80211BssInfo, Nl80211ChannelWidth,
    Nl80211Command as Cmd, Nl80211Features, Nl80211FrequencyInfo as FreqInfo, Nl80211Handle,
    Nl80211HtWiphyChannelType, Nl80211InterfaceType as IfType, Nl80211Message,
    packet_core::{
        DefaultNla, Emitable, NLA_F_NESTED, NLM_F_ACK, NLM_F_REQUEST, NetlinkMessage,
        NetlinkPayload,
    },
    packet_generic::GenlMessage,
};

fn is_busy(error: &anyhow::Error) -> bool {
    matches!(error.downcast_ref::<wl_nl80211::Nl80211Error>(),
        Some(wl_nl80211::Nl80211Error::NetlinkError(message))
            if message.code.is_some_and(|code| code.get() == -nix::libc::EBUSY))
}

async fn retry_busy<T, F, Fut>(timeout: Duration, mut operation: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    let mut retries = 0;
    loop {
        let result = tokio::time::timeout_at(deadline, operation())
            .await
            .context("netlink operation deadline expired")?;
        match result {
            Err(error) if is_busy(&error) => {
                let next = tokio::time::Instant::now() + Duration::from_millis(100);
                if next >= deadline {
                    return Err(error).context("adapter remained busy until the retry deadline");
                }
                if retries == 0 {
                    tracing::debug!("adapter busy; retrying without releasing radio ownership");
                }
                retries += 1;
                tokio::time::sleep_until(next).await;
            }
            result => return result,
        }
    }
}

#[derive(Clone)]
pub struct Netlink(Arc<Connections>);
struct Connections {
    timeout: Duration,
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
    pub width_mhz: Option<u32>,
    pub center_frequency_mhz: Option<u32>,
}
impl Interface {
    pub fn channel_definition(&self) -> Option<ChannelDefinition> {
        let channel = match self.frequency? {
            2437 => 6,
            5180 => 36,
            5220 => 44,
            5745 => 149,
            _ => return None,
        };
        let definition = ChannelDefinition {
            channel,
            width_mhz: self.width_mhz?,
            center_frequency_mhz: self.center_frequency_mhz?,
        };
        (definition.opclass() != 0).then_some(definition)
    }
}
#[derive(Clone, Debug, Default)]
pub struct PhyCapabilities {
    pub frequencies: Vec<u32>,
    pub active_monitor: bool,
    pub radio: RadioCapabilities,
    pub tuning: Vec<ChannelDefinition>,
}
// Wiphy dumps split each band's attributes across multiple messages. Keep partial
// HT/VHT data until the whole dump has arrived; missing attributes are not defaults.
#[derive(Default)]
struct BandDump {
    ht_cap: Option<u16>,
    ht_mcs: Option<[u8; 4]>,
    ht_tx_mask: Option<[u8; 4]>,
    ampdu_factor: Option<u8>,
    ampdu_density: Option<u8>,
    vht_cap: Option<u32>,
    vht_mcs: Option<wl_nl80211::Ieee80211VhtMcsInfo>,
}
impl BandDump {
    fn update(&mut self, attr: Nl80211BandInfo) {
        match attr {
            Nl80211BandInfo::HtCapa(c) => self.ht_cap = Some(c.bits()),
            Nl80211BandInfo::HtMcsSet(m) => {
                let mask = [m.rx_mask[0], m.rx_mask[1], m.rx_mask[2], m.rx_mask[3]];
                self.ht_mcs = Some(mask);
                // Without an equal defined TX set, RX bits do not prove TX support.
                self.ht_tx_mask = (m.tx_params.mcs_set_defined
                    && !m.tx_params.tx_rx_mcs_set_not_equal)
                    .then_some(mask);
            }
            Nl80211BandInfo::HtAmpduFactor(f) => self.ampdu_factor = Some(f),
            Nl80211BandInfo::HtAmpduDensity(d) => self.ampdu_density = Some(d),
            Nl80211BandInfo::VhtCap(c) => self.vht_cap = Some(c.bits()),
            Nl80211BandInfo::VhtMcsSet(m) => self.vht_mcs = Some(m),
            _ => (),
        }
    }
    fn capabilities(self) -> BandCapabilities {
        let ht = match (
            self.ht_cap,
            self.ht_mcs,
            self.ampdu_factor,
            self.ampdu_density,
        ) {
            (Some(cap_info), Some(rx_mask), Some(f), Some(d))
                if rx_mask.iter().any(|b| *b != 0) && f <= 3 && d <= 7 =>
            {
                Some(HtCapabilities {
                    cap_info,
                    rx_mask,
                    tx_mask: self.ht_tx_mask,
                    ampdu_params: f | (d << 2),
                })
            }
            _ => None,
        };
        let vht = match (self.vht_cap, self.vht_mcs) {
            (Some(cap_info), Some(m)) if m.rx_mcs_map != 0xffff => Some(VhtCapabilities {
                cap_info,
                rx_mcs_map: m.rx_mcs_map,
                rx_highest: m.rx_highest,
                tx_mcs_map: m.tx_mcs_map,
                tx_highest: m.tx_highest,
            }),
            _ => None,
        };
        BandCapabilities { ht, vht }
    }
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
fn tuning_candidates(
    radio: &RadioCapabilities,
    frequencies: &std::collections::BTreeMap<u32, Vec<FreqInfo>>,
) -> Vec<ChannelDefinition> {
    let mut candidates = Vec::new();
    for channel in [6, 36, 44, 149] {
        for width in [80, 40, 20] {
            // Discovery and 2.4 GHz traffic retain the interoperable HT20 context.
            if channel == 6 && width != 20 {
                continue;
            }
            let Ok(definition) = ChannelDefinition::new(channel, width) else {
                continue;
            };
            let caps = radio.for_channel(channel);
            if width == 80 && caps.vht.is_none() {
                continue;
            }
            if width == 40 && !caps.ht.as_ref().is_some_and(|ht| ht.cap_info & 2 != 0) {
                continue;
            }
            let primary = ChannelDefinition::frequency(channel).unwrap();
            if width == 40
                && frequencies
                    .get(&primary)
                    .is_none_or(|info| info.contains(&FreqInfo::NoHt40Plus))
            {
                continue;
            }
            let first = definition.center_frequency_mhz - width / 2 + 10;
            let last = definition.center_frequency_mhz + width / 2 - 10;
            if (first..=last).step_by(20).all(|f| {
                frequencies.get(&f).is_some_and(|info| {
                    tx_frequency(info).is_some()
                        && (width != 80 || !info.contains(&FreqInfo::No80Mhz))
                        && (width != 40 || f == primary || !info.contains(&FreqInfo::NoHt40Minus))
                })
            }) {
                candidates.push(definition);
            }
        }
    }
    candidates
}

fn decode_phy(attributes: impl IntoIterator<Item = Attr>) -> PhyCapabilities {
    let mut frequency_info = std::collections::BTreeMap::<u32, Vec<FreqInfo>>::new();
    let mut active_monitor = false;
    let (mut ghz2, mut ghz5) = (BandDump::default(), BandDump::default());
    for attr in attributes {
        match attr {
            Attr::Features(flags) => {
                active_monitor |= flags.contains(Nl80211Features::ActiveMonitor)
            }
            Attr::WiphyBands(bands) => {
                for band in bands {
                    for attr in band.info {
                        if let Nl80211BandInfo::Freqs(freqs) = &attr {
                            for freq in freqs {
                                if let Some(f) = freq.info.iter().find_map(|a| {
                                    if let FreqInfo::Freq(f) = a {
                                        Some(*f)
                                    } else {
                                        None
                                    }
                                }) {
                                    frequency_info
                                        .entry(f)
                                        .or_default()
                                        .extend(freq.info.clone());
                                }
                            }
                        }
                        match band.kind {
                            Nl80211BandType::Band2GHz => ghz2.update(attr),
                            Nl80211BandType::Band5GHz => ghz5.update(attr),
                            _ => (),
                        }
                    }
                }
            }
            _ => (),
        }
    }
    let radio = RadioCapabilities {
        ghz2: ghz2.capabilities(),
        ghz5: ghz5.capabilities(),
    };
    let tuning = tuning_candidates(&radio, &frequency_info);
    PhyCapabilities {
        frequencies: frequency_info
            .values()
            .filter_map(|info| tx_frequency(info))
            .collect(),
        active_monitor,
        radio,
        tuning,
    }
}

impl Netlink {
    async fn bounded<T, E: Into<anyhow::Error>>(
        &self,
        f: impl Future<Output = std::result::Result<T, E>>,
    ) -> Result<T> {
        tokio::time::timeout(self.0.timeout, f)
            .await
            .context("netlink request timed out")?
            .map_err(Into::into)
    }

    pub fn new() -> Result<Self> {
        Self::with_timeout(crate::timeouts::Timeouts::default().netlink)
    }
    pub fn with_timeout(timeout: Duration) -> Result<Self> {
        let (route, route_handle, _) =
            rtnetlink::new_connection().context("open routing netlink")?;
        let (wifi, wifi_handle, _) =
            wl_nl80211::new_connection().context("open wireless netlink")?;
        Ok(Self(Arc::new(Connections {
            timeout,
            route: route_handle,
            wifi: wifi_handle,
            route_task: tokio::spawn(route),
            wifi_task: tokio::spawn(wifi),
        })))
    }
    pub async fn link(&self, name: &str) -> Result<LinkMessage> {
        self.bounded(
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
        self.bounded(self.0.route.link().set(msg).execute())
            .await
            .with_context(|| format!("set {name} up={up}"))
    }
    pub async fn mtu(&self, name: &str) -> Result<u32> {
        self.link(name)
            .await?
            .attributes
            .into_iter()
            .find_map(|a| match a {
                LinkAttribute::Mtu(mtu) => Some(mtu),
                _ => None,
            })
            .with_context(|| format!("interface {name} did not report its MTU"))
    }
    pub async fn set_mtu(&self, name: &str, mtu: u32) -> Result<()> {
        let msg = LinkUnspec::new_with_index(self.index(name).await?)
            .mtu(mtu)
            .build();
        self.bounded(self.0.route.link().set(msg).execute())
            .await
            .with_context(|| format!("set {name} MTU to {mtu}"))
    }
    pub async fn set_mac(&self, name: &str, mac: Mac) -> Result<()> {
        let msg = LinkUnspec::new_with_index(self.index(name).await?)
            .address(mac.0.to_vec())
            .build();
        self.bounded(self.0.route.link().set(msg).execute())
            .await
            .context("set interface MAC")
    }
    pub async fn is_up(&self, name: &str) -> Result<bool> {
        Ok(self.link(name).await?.header.flags.contains(LinkFlags::Up))
    }
    async fn wifi_request(&self, cmd: Cmd, attributes: Vec<Attr>) -> Result<()> {
        if matches!(cmd, Cmd::SetInterface | Cmd::NewInterface | Cmd::SetWiphy) {
            retry_busy(self.0.timeout, || {
                self.wifi_request_once(cmd, attributes.clone())
            })
            .await
        } else {
            self.wifi_request_once(cmd, attributes).await
        }
    }
    async fn wifi_request_once(&self, cmd: Cmd, attributes: Vec<Attr>) -> Result<()> {
        let mut handle = self.0.wifi.clone();
        let mut msg = NetlinkMessage::from(GenlMessage::from_payload(Nl80211Message {
            cmd,
            attributes,
        }));
        msg.header.flags = NLM_F_REQUEST | NLM_F_ACK;
        self.bounded(async {
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
    /// Regulatory hints are asynchronous: wait for GET_REG to confirm the domain
    /// before callers inspect the PHY's permitted channels and widths.
    pub async fn set_reg_region(&self, region: &str) -> Result<()> {
        // NL80211_ATTR_REG_ALPHA2 is not typed by wl-nl80211 yet.
        let alpha2 = DefaultNla::new(33, [region.as_bytes(), &[0]].concat());
        self.wifi_request(Cmd::ReqSetReg, vec![Attr::Other(alpha2.clone())])
            .await?;
        self.bounded(async {
            loop {
                let mut handle = self.0.wifi.clone();
                let mut msg = NetlinkMessage::from(GenlMessage::from_payload(Nl80211Message {
                    cmd: Cmd::GetReg,
                    attributes: vec![],
                }));
                msg.header.flags = NLM_F_REQUEST | NLM_F_ACK;
                let mut responses = handle.request(msg).await?;
                while let Some(response) = responses.next().await {
                    match response?.payload {
                        NetlinkPayload::InnerMessage(message)
                            if message
                                .payload
                                .attributes
                                .iter()
                                .any(|a| matches!(a, Attr::Other(v) if *v == alpha2)) =>
                        {
                            tracing::info!(region, "kernel regulatory region confirmed");
                            return Ok(());
                        }
                        NetlinkPayload::Error(error) if error.code.is_some() => {
                            return Err(wl_nl80211::Nl80211Error::NetlinkError(error).into());
                        }
                        NetlinkPayload::Overrun(_) => bail!("wireless netlink overrun"),
                        _ => (),
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .with_context(|| format!("wait for regulatory region {region}"))
    }
    async fn interface_messages(&self) -> Result<Vec<GenlMessage<Nl80211Message>>> {
        self.bounded(async {
            self.0
                .wifi
                .interface()
                .get(vec![])
                .execute()
                .await
                .try_collect()
                .await
        })
        .await
    }
    /// P2P devices have no ifindex, so the ordinary netdev list omits them.
    pub async fn handoff_blockers(&self, station: &str, phy: u32) -> Result<Vec<String>> {
        let mut blockers = Vec::new();
        for msg in self.interface_messages().await? {
            let attrs = &msg.payload.attributes;
            if !attrs
                .iter()
                .any(|a| matches!(a, Attr::Wiphy(p) if *p == phy))
            {
                continue;
            }
            let kind = attrs.iter().find_map(|a| match a {
                Attr::IfType(k) => Some(*k),
                _ => None,
            });
            let name = attrs.iter().find_map(|a| match a {
                Attr::IfName(n) => Some(n.as_str()),
                _ => None,
            });
            if kind == Some(IfType::P2pDevice) {
                blockers.push(format!("P2P device {}", name.unwrap_or("without netdev")));
            } else if let Some(name) = name
                && name != station
                && kind != Some(IfType::Monitor)
                && self.is_up(name).await?
            {
                blockers.push(format!("{name} ({kind:?}) is up"));
            }
        }
        Ok(blockers)
    }
    pub async fn interfaces(&self) -> Result<Vec<Interface>> {
        let mut interfaces = Vec::new();
        for msg in self.interface_messages().await? {
            let (mut index, mut name, mut phy, mut kind, mut frequency) =
                (None, None, None, None, None);
            let (mut width_mhz, mut center_frequency_mhz) = (None, None);
            for attr in msg.payload.attributes {
                match attr {
                    Attr::ChannelWidth(Nl80211ChannelWidth::Mhz(w)) => width_mhz = Some(w),
                    Attr::ChannelWidth(Nl80211ChannelWidth::NoHt20) => width_mhz = Some(20),
                    Attr::CenterFreq1(f) => center_frequency_mhz = Some(f),
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
                width_mhz,
                center_frequency_mhz,
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
        let msgs: Vec<_> = self
            .bounded(async {
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
    pub async fn phy_capabilities(&self, phy: u32) -> Result<PhyCapabilities> {
        let msgs: Vec<_> = self
            .bounded(async {
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
        Ok(decode_phy(
            msgs.into_iter().flat_map(|msg| msg.payload.attributes),
        ))
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
    /// Try the widest permitted definition first; kernel rejection narrows it.
    pub async fn tune(&self, name: &str, channel: u8, max_width: u32) -> Result<ChannelDefinition> {
        let iface = self.interface(name).await?;
        let caps = self.phy_capabilities(iface.phy).await?;
        let mut error = anyhow::anyhow!("no permitted channel definition for {channel}");
        for definition in caps
            .tuning
            .into_iter()
            .filter(|d| d.channel == channel && d.width_mhz <= max_width)
        {
            match self.set_channel(name, iface.index, definition).await {
                Ok(actual) => return Ok(actual),
                Err(e) if is_busy(&e) => return Err(e).context("channel tuning remained busy"),
                Err(e) => {
                    tracing::warn!(
                        channel,
                        width_mhz = definition.width_mhz,
                        "channel definition rejected: {e:#}"
                    );
                    error = e;
                }
            }
        }
        Err(error).with_context(|| format!("tune {name} to channel {channel}"))
    }
    async fn set_channel(
        &self,
        name: &str,
        index: u32,
        definition: ChannelDefinition,
    ) -> Result<ChannelDefinition> {
        self.wifi_request(
            Cmd::SetWiphy,
            vec![
                Attr::IfIndex(index),
                Attr::WiphyFreq(ChannelDefinition::frequency(definition.channel)?),
                Attr::ChannelWidth(Nl80211ChannelWidth::Mhz(definition.width_mhz)),
                Attr::CenterFreq1(definition.center_frequency_mhz),
            ],
        )
        .await?;
        // mac80211 may omit monitor readback when an active monitor is open
        // beside a passive one: get_channel requires open_count == virt_monitors
        // in the absence of a per-vif channel context. The ACK is still binding.
        let observed = self.interface(name).await?;
        let actual = match observed.channel_definition() {
            Some(actual) => actual,
            None if observed.frequency.is_none() => {
                tracing::debug!(
                    ?definition,
                    "monitor channel readback unavailable; using acknowledged definition"
                );
                definition
            }
            None => bail!("kernel reported an unsupported or incomplete channel definition"),
        };
        anyhow::ensure!(
            actual == definition,
            "kernel channel definition differs: requested {definition:?}, got {actual:?}"
        );
        Ok(actual)
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
        self.bounded(req.execute()).await
    }
    pub async fn address_ready(&self, name: &str, mac: Mac) -> Result<bool> {
        let msgs: Vec<_> = self
            .bounded(
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
            self.bounded(
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
            self.bounded(self.0.route.neighbours().del(msg).execute())
                .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wl_nl80211::packet_core::{Nla, NlaBuffer, NlasIterator};
    #[tokio::test(start_paused = true)]
    async fn busy_retries_are_bounded_and_do_not_retry_other_errors() {
        fn error(errno: i32) -> anyhow::Error {
            let mut message = wl_nl80211::packet_core::ErrorMessage::default();
            message.code = std::num::NonZeroI32::new(-errno);
            anyhow::Error::new(wl_nl80211::Nl80211Error::NetlinkError(message))
                .context("nl80211 SetWiphy")
        }
        let mut attempts = 0;
        retry_busy(Duration::from_secs(1), || {
            attempts += 1;
            std::future::ready(if attempts < 3 {
                Err(error(nix::libc::EBUSY))
            } else {
                Ok(())
            })
        })
        .await
        .unwrap();
        assert_eq!(attempts, 3);
        attempts = 0;
        let failure = retry_busy(Duration::from_millis(250), || {
            attempts += 1;
            std::future::ready::<Result<()>>(Err(error(nix::libc::EBUSY)))
        })
        .await
        .unwrap_err();
        assert!(is_busy(&failure));
        assert_eq!(attempts, 3);
        attempts = 0;
        retry_busy(Duration::from_secs(1), || {
            attempts += 1;
            std::future::ready::<Result<()>>(Err(error(nix::libc::EINVAL)))
        })
        .await
        .unwrap_err();
        assert_eq!(attempts, 1);
    }
    #[test]
    fn split_phy_replies_merge_by_band_without_guessing_missing_fields() {
        use wl_nl80211::{
            Ieee80211HtCaps, Ieee80211HtMcsInfo, Ieee80211VhtCapInfo, Ieee80211VhtMcsInfo,
            Nl80211Band, packet_core::Parseable,
        };
        let mut mcs = [0; 16];
        mcs[..2].copy_from_slice(&[255, 255]);
        mcs[4] = 1; // MCS 32 cannot be represented in compact AWDL HT.
        mcs[12] = 1; // Defined TX set equals RX.
        let ht = vec![
            Nl80211BandInfo::HtMcsSet(Ieee80211HtMcsInfo::parse(&mcs[..]).unwrap()),
            Nl80211BandInfo::HtCapa(Ieee80211HtCaps::from_bits_retain(0x01ff)),
            Nl80211BandInfo::HtAmpduFactor(3),
        ];
        let band = |kind, info| Attr::WiphyBands(vec![Nl80211Band { kind, info }]);
        let first = band(Nl80211BandType::Band2GHz, ht.clone());
        assert!(decode_phy([first.clone()]).radio.ghz2.ht.is_none());
        let mut five = ht;
        five.extend([
            Nl80211BandInfo::HtAmpduDensity(0),
            Nl80211BandInfo::VhtCap(Ieee80211VhtCapInfo::from_bits_retain(0x318001b0)),
            Nl80211BandInfo::VhtMcsSet(Ieee80211VhtMcsInfo {
                rx_mcs_map: 0xfffa,
                rx_highest: 0,
                tx_mcs_map: 0xfffa,
                tx_highest: 0,
            }),
        ]);
        let caps = decode_phy([
            first,
            band(Nl80211BandType::Band5GHz, five),
            band(
                Nl80211BandType::Band2GHz,
                vec![Nl80211BandInfo::HtAmpduDensity(6)],
            ),
            band(
                Nl80211BandType::Band5GHz,
                vec![Nl80211BandInfo::Freqs(vec![])],
            ),
        ])
        .radio;
        assert_eq!(caps.ghz2.ht.unwrap().ampdu_params, 27);
        assert!(caps.ghz2.vht.is_none());
        let ht = caps.ghz5.ht.unwrap();
        assert_eq!(
            (ht.cap_info, ht.ampdu_params, ht.rx_mask),
            (0x01ff, 3, [255, 255, 0, 0])
        );
        assert_eq!(ht.tx_mask, Some([255, 255, 0, 0]));
        for params in [0, 3] {
            // Undefined or asymmetric TX must not be inferred from RX.
            mcs[12] = params;
            let mut dump = BandDump::default();
            dump.update(Nl80211BandInfo::HtMcsSet(
                Ieee80211HtMcsInfo::parse(&mcs[..]).unwrap(),
            ));
            assert!(dump.ht_tx_mask.is_none());
        }
        assert_eq!(caps.ghz5.vht.unwrap().rx_mcs_map, 0xfffa);
    }

    #[test]
    fn wide_channels_require_hardware_and_every_permitted_subchannel() {
        let mut radio = RadioCapabilities {
            ghz5: BandCapabilities {
                ht: Some(HtCapabilities {
                    cap_info: 2,
                    ampdu_params: 0,
                    rx_mask: [255, 0, 0, 0],
                    tx_mask: Some([255, 0, 0, 0]),
                }),
                vht: Some(VhtCapabilities {
                    cap_info: 0,
                    rx_mcs_map: 0xfffe,
                    rx_highest: 0,
                    tx_mcs_map: 0xfffe,
                    tx_highest: 0,
                }),
            },
            ..Default::default()
        };
        let mut frequencies = std::collections::BTreeMap::new();
        for f in [2437, 5180, 5200, 5220, 5240, 5745, 5765, 5785, 5805] {
            frequencies.insert(f, vec![FreqInfo::Freq(f)]);
        }
        let widths = |radio: &RadioCapabilities,
                      freqs: &std::collections::BTreeMap<u32, Vec<FreqInfo>>,
                      c| {
            tuning_candidates(radio, freqs)
                .into_iter()
                .filter(|d| d.channel == c)
                .map(|d| (d.width_mhz, d.center_frequency_mhz, d.opclass()))
                .collect::<Vec<_>>()
        };
        assert_eq!(widths(&radio, &frequencies, 6), [(20, 2437, 81)]);
        assert_eq!(
            widths(&radio, &frequencies, 44),
            [(80, 5210, 128), (40, 5230, 116), (20, 5220, 115)]
        );
        assert_eq!(
            widths(&radio, &frequencies, 149),
            [(80, 5775, 128), (40, 5755, 126), (20, 5745, 124)]
        );
        frequencies.get_mut(&5785).unwrap().push(FreqInfo::No80Mhz);
        assert_eq!(
            widths(&radio, &frequencies, 149),
            [(40, 5755, 126), (20, 5745, 124)]
        );
        frequencies.get_mut(&5765).unwrap().push(FreqInfo::NoIr);
        assert_eq!(widths(&radio, &frequencies, 149), [(20, 5745, 124)]);
        frequencies
            .get_mut(&5220)
            .unwrap()
            .push(FreqInfo::NoHt40Plus);
        radio.ghz5.vht = None;
        assert_eq!(widths(&radio, &frequencies, 44), [(20, 5220, 115)]);
        frequencies.remove(&5180);
        assert!(widths(&radio, &frequencies, 36).is_empty());
    }

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
