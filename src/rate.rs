// SPDX-License-Identifier: GPL-3.0-or-later
//! PHY rate parsing and capability-based selection. Auto is resolved before encoding.
use crate::{channel::ChannelDefinition, protocol::BandCapabilities};
use radiotap::field::ext::{Bandwidth, GuardInterval, ht_rate, vht_rate};
use serde::{Serialize, Serializer};
use std::{fmt, str::FromStr};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Rate {
    #[default]
    Auto,
    Legacy(u8),
    Mcs {
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
            Self::Mcs { index, sgi } => write!(f, "mcs{index}{}", suffix(sgi)),
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
        let (s, sgi) = s.strip_suffix("-sgi").map_or((s, false), |s| (s, true));
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
                Some(Self::Mcs {
                    index: number(s)?,
                    sgi,
                })
            } else if !sgi {
                Some(Self::Legacy(number(s)?))
            } else {
                None
            }
        })();
        parsed.filter(|rate| rate.phy_mbps().is_some()).ok_or_else(||
            "use auto, legacy Mbps (6,9,12,18,24,36,48,54), mcsN[-sgi] (0–31), or vhtN-nssS-bwW[-sgi] (MCS 0–9, NSS 1–8, width 20/40/80)".into())
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
            Self::Auto | Self::Vht { .. } => Self::DISCOVERY,
            _ => self,
        }
    }
    /// A valid concrete PHY rate; Auto has no wire representation.
    pub(crate) fn phy_mbps(self) -> Option<f32> {
        match self {
            Self::Auto => None,
            Self::Legacy(n) if [6, 9, 12, 18, 24, 36, 48, 54].contains(&n) => Some(f32::from(n)),
            Self::Legacy(_) => None,
            Self::Mcs { index, sgi } => ht_rate(index, bandwidth(20)?, gi(sgi)).ok(),
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
                index: 9,
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
                        allowed.then_some(Self::Mcs { index, sgi })
                    })
                });
            return Self::fastest(ht.chain(std::iter::once(vht)));
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
