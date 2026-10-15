// SPDX-License-Identifier: GPL-3.0-or-later
//! PHY rates and per-peer delivery feedback. Auto is resolved before encoding.
use crate::{channel::ChannelDefinition, protocol::BandCapabilities};
use radiotap::field::ext::{Bandwidth, GuardInterval, ht_rate, vht_rate};
use serde::{Serialize, Serializer};
use std::{fmt, str::FromStr};

// Injection policy: MCS9 stalled transfers despite advertised support.
// Keep the hardware capability maps intact for advertisement and reception.
const MAX_TX_VHT_MCS: u8 = 8;

/// Requested data-frame coding, independent of PHY rate selection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum FecPolicy {
    Auto,
    #[default]
    Bcc,
    Ldpc,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Coding {
    #[default]
    Bcc,
    Ldpc,
}
impl fmt::Display for Coding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Bcc => "bcc",
            Self::Ldpc => "ldpc",
        })
    }
}
/// Concrete per-frame parameters, also used as the radiotap cache key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct TxParameters {
    pub rate: Rate,
    pub coding: Coding,
}
impl From<Rate> for TxParameters {
    fn from(rate: Rate) -> Self {
        Self {
            rate,
            coding: Coding::Bcc,
        }
    }
}
impl FecPolicy {
    pub fn validate_rate(self, rate: Rate) -> Result<(), crate::protocol::Error> {
        if self == Self::Ldpc && matches!(rate, Rate::Legacy(_)) {
            return Err(crate::protocol::Error::Invalid(
                "LDPC requires an HT or VHT data rate",
            ));
        }
        Ok(())
    }
    pub fn resolve(
        self,
        rate: Rate,
        tx_ldpc: bool,
        peer: &BandCapabilities,
    ) -> Result<TxParameters, crate::protocol::Error> {
        // Discovery and legacy fallback frames always use BCC.
        if matches!(rate, Rate::Legacy(_)) || self == Self::Bcc {
            return Ok(rate.into());
        }
        let receiver_ldpc = match rate {
            Rate::Mcs { .. } => peer.ht.as_ref().is_some_and(|h| h.cap_info & 1 != 0),
            Rate::Vht { .. } => peer
                .vht
                .as_ref()
                .is_some_and(|v| v.cap_info & (1 << 4) != 0),
            _ => false,
        };
        let coding = if tx_ldpc && receiver_ldpc {
            Coding::Ldpc
        } else {
            if self == Self::Ldpc {
                return Err(crate::protocol::Error::Invalid(
                    "LDPC requires a supported injection driver and peer RX LDPC capability",
                ));
            }
            Coding::Bcc
        };
        Ok(TxParameters { rate, coding })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Rate {
    #[default]
    Auto,
    Legacy(u8),
    Mcs {
        width: u8,
        index: u8,
        sgi: bool,
    },
    Vht {
        index: u8,
        nss: u8,
        width: u8,
        sgi: bool,
    },
}
impl fmt::Display for Rate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let suffix = |sgi| if sgi { "-sgi" } else { "" };
        match *self {
            Self::Auto => f.write_str("auto"),
            Self::Legacy(n) => write!(f, "{n}"),
            Self::Mcs { index, width, sgi } => {
                write!(f, "mcs{index}")?;
                if width != 20 {
                    write!(f, "-{width}")?;
                }
                f.write_str(suffix(sgi))
            }
            Self::Vht {
                index,
                nss,
                width,
                sgi,
            } => write!(f, "vht{index}-nss{nss}-bw{width}{}", suffix(sgi)),
        }
    }
}
impl Serialize for Rate {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}
impl<'de> serde::Deserialize<'de> for Rate {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <String as serde::Deserialize>::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}
impl FromStr for Rate {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        if s == "auto" {
            return Ok(Self::Auto);
        }
        let original = s;
        let (s, sgi) = s.strip_suffix("-sgi").map_or_else(
            || (s.strip_suffix("-lgi").unwrap_or(s), false),
            |s| (s, true),
        );
        let parsed = (|| {
            if let Some(s) = s.strip_prefix("vht") {
                let mut fields = s.split('-');
                let rate = Self::Vht {
                    index: number(fields.next()?)?,
                    nss: number(fields.next()?.strip_prefix("nss")?)?,
                    width: number(fields.next()?.strip_prefix("bw")?)?,
                    sgi,
                };
                fields.next().is_none().then_some(rate)
            } else if let Some(s) = s.strip_prefix("mcs") {
                let mut fields = s.split('-');
                let index = number(fields.next()?)?;
                let width = fields.next().map_or(Some(20), number)?;
                fields
                    .next()
                    .is_none()
                    .then_some(Self::Mcs { index, width, sgi })
            } else if s == original {
                Some(Self::Legacy(number(s)?))
            } else {
                None
            }
        })();
        parsed.filter(|rate| rate.phy_mbps().is_some()).ok_or_else(||
            "use auto, legacy Mbps (6,9,12,18,24,36,48,54), mcsN[-20|-40][-lgi|-sgi] (0–31), or vhtN-nssS-bwW[-sgi] (MCS 0–9, NSS 1–8, width 20/40/80)".into())
    }
}
fn number(s: &str) -> Option<u8> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}
pub(crate) fn vht_width_code(width: u8) -> Option<u8> {
    match width {
        20 => Some(0),
        40 => Some(1),
        80 => Some(4),
        _ => None,
    }
}
fn bandwidth(width: u8) -> Option<Bandwidth> {
    Bandwidth::new(vht_width_code(width)?).ok()
}
fn gi(sgi: bool) -> GuardInterval {
    if sgi {
        GuardInterval::Short
    } else {
        GuardInterval::Long
    }
}
fn max_mcs(map: u16, nss: u8) -> Option<u8> {
    match (map >> (2 * (nss - 1))) & 3 {
        0 => Some(7),
        1 => Some(8),
        2 => Some(9),
        _ => None,
    }
}
impl Rate {
    pub(crate) const DISCOVERY: Self = Self::Legacy(12);
    pub(crate) fn fallback(self) -> Self {
        match self {
            Self::Auto | Self::Vht { .. } | Self::Mcs { width: 40, .. } => Self::DISCOVERY,
            _ => self,
        }
    }
    /// A valid concrete PHY rate; Auto has no wire representation.
    pub(crate) fn phy_mbps(self) -> Option<f32> {
        match self {
            Self::Auto => None,
            Self::Legacy(n) if [6, 9, 12, 18, 24, 36, 48, 54].contains(&n) => Some(f32::from(n)),
            Self::Legacy(_) => None,
            Self::Mcs { index, width, sgi } if matches!(width, 20 | 40) => {
                ht_rate(index, bandwidth(width)?, gi(sgi)).ok()
            }
            Self::Mcs { .. } => None,
            Self::Vht {
                index,
                nss,
                width,
                sgi,
            } if (1..=8).contains(&nss) => vht_rate(index, bandwidth(width)?, gi(sgi), nss).ok(),
            Self::Vht { .. } => None,
        }
    }
    fn fastest(rates: impl Iterator<Item = Self>) -> Self {
        rates
            .filter_map(|rate| rate.phy_mbps().map(|speed| (rate, speed)))
            .max_by(|a, b| a.1.total_cmp(&b.1))
            .map_or(Self::DISCOVERY, |(rate, _)| rate)
    }
    /// Resolve Auto or constrain VHT to local TX, peer RX and channel availability.
    pub fn for_peer(
        self,
        channel: ChannelDefinition,
        local: &BandCapabilities,
        peer: &BandCapabilities,
        peer_width: u32,
    ) -> Self {
        if self == Self::Auto {
            let vht = Self::Vht {
                index: MAX_TX_VHT_MCS,
                nss: 8,
                width: 80,
                sgi: true,
            }
            .for_peer(channel, local, peer, peer_width);
            let ht = local
                .ht
                .as_ref()
                .zip(peer.ht.as_ref())
                .into_iter()
                .flat_map(|(tx, rx)| {
                    let sgi = local.short_gi(20) && peer.short_gi(20);
                    (0..32).filter_map(move |index| {
                        let byte = index as usize / 8;
                        let allowed = !(peer.single_stream() && index >= 8)
                            && tx.tx_mask?[byte] & rx.rx_mask[byte] & (1 << (index % 8)) != 0;
                        allowed.then_some(Self::Mcs {
                            index,
                            width: 20,
                            sgi,
                        })
                    })
                });
            return Self::fastest(ht.chain(std::iter::once(vht)));
        }
        if let Self::Mcs {
            index,
            width: 40,
            sgi,
        } = self
        {
            let (Some(tx), Some(rx)) = (&local.ht, &peer.ht) else {
                return Self::DISCOVERY;
            };
            let width = if channel.width_mhz >= 40
                && peer_width >= 40
                && tx.cap_info & rx.cap_info & 2 != 0
            {
                40
            } else {
                20
            };
            let sgi = sgi && local.short_gi(width) && peer.short_gi(width);
            return Self::fastest((0..=index.min(31)).filter_map(|index| {
                let byte = usize::from(index / 8);
                let supported = !(peer.single_stream() && index >= 8)
                    && tx.tx_mask?[byte] & rx.rx_mask[byte] & (1 << (index % 8)) != 0;
                supported.then_some(Self::Mcs { index, width, sgi })
            }));
        }
        let Self::Vht {
            index,
            nss,
            width,
            sgi,
        } = self
        else {
            return self;
        };
        if channel.channel <= 14 {
            return Self::DISCOVERY;
        }
        let (Some(tx), Some(rx)) = (&local.vht, &peer.vht) else {
            return Self::DISCOVERY;
        };
        let width = u32::from(width).min(channel.width_mhz).min(peer_width);
        let ht40 = [local, peer]
            .iter()
            .all(|c| c.ht.as_ref().is_some_and(|h| h.cap_info & 2 != 0));
        let width = if width >= 80 {
            80
        } else if width >= 40 && ht40 {
            40
        } else {
            20
        };
        let sgi = sgi && local.short_gi(width) && peer.short_gi(width);
        let nss = if peer.single_stream() {
            nss.min(1)
        } else {
            nss.min(8)
        };
        let rates = (1..=nss).filter_map(|streams| {
            let limit = index
                .min(MAX_TX_VHT_MCS)
                .min(max_mcs(tx.tx_mcs_map, streams)?)
                .min(max_mcs(rx.rx_mcs_map, streams)?);
            (0..=limit)
                .rev()
                .map(|index| Self::Vht {
                    index,
                    nss: streams,
                    width,
                    sgi,
                })
                .find(|rate| rate.phy_mbps().is_some())
        });
        Self::fastest(rates)
    }
}
impl BandCapabilities {
    fn single_stream(&self) -> bool {
        // Static SMPS needs one stream; dynamic SMPS needs RTS/CTS, which raw
        // injection does not arrange. Multiple streams require disabled SMPS.
        self.ht.as_ref().is_some_and(|h| (h.cap_info >> 2) & 3 != 3)
    }
    fn short_gi(&self, width: u8) -> bool {
        match width {
            80 => self
                .vht
                .as_ref()
                .is_some_and(|v| v.cap_info & (1 << 5) != 0),
            _ => self
                .ht
                .as_ref()
                .is_some_and(|h| h.cap_info & (1 << if width == 40 { 6 } else { 5 }) != 0),
        }
    }
}

/// Hardware ACK policy, independent of channel scheduling.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    clap::ValueEnum,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum AckPolicy {
    #[default]
    Auto,
    Normal,
    Noack,
}
impl AckPolicy {
    pub fn noack(self, profile_noack: bool) -> bool {
        match self {
            Self::Auto => profile_noack,
            Self::Normal => false,
            Self::Noack => true,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct AutoRate {
    context: Option<(ChannelDefinition, u32, BandCapabilities, BandCapabilities)>,
    rates: Vec<Rate>,
    selected: usize,
    failures: u16,
    frames: u16,
    retries: u32,
    clean: u16,
    pub generation: u64,
}
impl AutoRate {
    pub fn select(
        &mut self,
        channel: ChannelDefinition,
        local: &BandCapabilities,
        peer: &BandCapabilities,
        peer_width: u32,
    ) -> Rate {
        let context = (channel, peer_width, local.clone(), peer.clone());
        if self.context.as_ref() != Some(&context) {
            let generation = self.generation.wrapping_add(1);
            *self = Self {
                generation,
                ..Self::default()
            };
            self.context = Some(context);
            let mut rates = vec![Rate::Legacy(6), Rate::DISCOVERY, Rate::Legacy(24)];
            for width in [20, 40, 80] {
                if width > channel.width_mhz || width > peer_width {
                    continue;
                }
                for index in 0..=MAX_TX_VHT_MCS {
                    for nss in 1..=8 {
                        for sgi in [false, true] {
                            let rate = Rate::Vht {
                                index,
                                nss,
                                width: width as u8,
                                sgi,
                            };
                            if rate.phy_mbps().is_some()
                                && rate.for_peer(channel, local, peer, peer_width) == rate
                            {
                                rates.push(rate);
                            }
                        }
                    }
                }
            }
            if let (Some(tx), Some(rx)) = (&local.ht, &peer.ht) {
                for index in 0..32 {
                    let byte = index as usize / 8;
                    if peer.single_stream() && index >= 8 {
                        continue;
                    }
                    if tx
                        .tx_mask
                        .is_none_or(|mask| mask[byte] & rx.rx_mask[byte] & (1 << (index % 8)) == 0)
                    {
                        continue;
                    }
                    for sgi in [false, true] {
                        if !sgi || (local.short_gi(20) && peer.short_gi(20)) {
                            rates.push(Rate::Mcs {
                                index,
                                width: 20,
                                sgi,
                            });
                        }
                    }
                }
            }
            // Start with the same capability ceiling as Auto; lower rates are recovery choices.
            let ceiling = Rate::Auto
                .for_peer(channel, local, peer, peer_width)
                .phy_mbps()
                .unwrap_or(12.0);
            rates.retain(|r| r.phy_mbps().is_some_and(|v| v <= ceiling));
            rates.sort_by(|a, b| b.phy_mbps().unwrap().total_cmp(&a.phy_mbps().unwrap()));
            rates.dedup();
            self.rates = rates;
        }
        self.rates
            .get(self.selected)
            .copied()
            .unwrap_or(Rate::DISCOVERY)
    }
    pub fn feedback(&mut self, requested: Rate, failed: bool, retries: u8) {
        // Delayed completions from an older selection cannot undo a backoff.
        if self.rates.get(self.selected) != Some(&requested) {
            return;
        }
        let previous = self.selected;
        self.frames += 1;
        self.failures += u16::from(failed);
        self.retries += u32::from(retries);
        self.clean = if failed || retries != 0 {
            0
        } else {
            self.clean + 1
        };
        if self.failures >= 4 || (self.frames >= 16 && self.retries >= u32::from(self.frames) * 2) {
            let speed = requested.phy_mbps().unwrap_or(12.0) * 0.85;
            self.selected = ((self.selected + 1)..self.rates.len())
                .find(|&i| self.rates[i].phy_mbps().unwrap() <= speed)
                .unwrap_or(self.rates.len().saturating_sub(1));
            self.clean = 0;
            self.frames = 0;
            self.failures = 0;
            self.retries = 0;
        } else if self.clean >= 128 {
            self.selected = self.selected.saturating_sub(1);
            self.clean = 0;
            self.frames = 0;
            self.failures = 0;
            self.retries = 0;
        } else if self.frames >= 32 {
            self.frames = 0;
            self.failures = 0;
            self.retries = 0;
        }
        if self.selected != previous {
            self.generation = self.generation.wrapping_add(1);
        }
    }
}

pub(crate) fn reported_rate(radio: &radiotap::Radiotap) -> Option<Rate> {
    use radiotap::field::ext::GuardInterval;
    if let Some(vht) = &radio.vht {
        let user = vht.users[0]?;
        return Some(Rate::Vht {
            index: user.index,
            nss: user.nss,
            width: vht.bw?.bandwidth,
            sgi: vht.gi? == GuardInterval::Short,
        });
    }
    if let Some(mcs) = &radio.mcs {
        let width = mcs.bw?.bandwidth;
        if !matches!(width, 20 | 40) {
            return None;
        }
        return Some(Rate::Mcs {
            width,
            index: mcs.index?,
            sgi: mcs.gi? == GuardInterval::Short,
        });
    }
    let value = radio.rate?.value;
    (value.fract() == 0.0).then_some(Rate::Legacy(value as u8))
}
