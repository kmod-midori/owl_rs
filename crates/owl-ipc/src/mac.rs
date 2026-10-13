// SPDX-License-Identifier: GPL-3.0-or-later
use serde::{Serialize, Serializer};
use std::{fmt, net::Ipv6Addr, str::FromStr};
#[derive(Debug, thiserror::Error)]
#[error("invalid MAC address")]
pub struct MacError;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Mac(pub [u8; 6]);
impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}
impl Serialize for Mac {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}
impl<'de> serde::Deserialize<'de> for Mac {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        <String as serde::Deserialize>::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}
impl FromStr for Mac {
    type Err = MacError;
    fn from_str(s: &str) -> Result<Self, MacError> {
        let mut bytes = [0; 6];
        let mut parts = s.split(':');
        for b in &mut bytes {
            let p = parts.next().ok_or(MacError)?;
            if p.len() != 2 {
                return Err(MacError);
            }
            *b = u8::from_str_radix(p, 16).map_err(|_| MacError)?;
        }
        if parts.next().is_some() {
            return Err(MacError);
        }
        Ok(Self(bytes))
    }
}
impl Mac {
    pub fn random() -> Self {
        let mut bytes = [0; 6];
        bytes.copy_from_slice(&uuid::Uuid::new_v4().as_bytes()[..6]);
        bytes[0] = (bytes[0] | 2) & !1;
        Self(bytes)
    }
    pub fn multicast(self) -> bool {
        self.0[0] & 1 != 0
    }
    pub fn valid_unicast(self) -> bool {
        !self.multicast() && self.0 != [0; 6]
    }
    pub fn ipv6(self) -> Ipv6Addr {
        let b = self.0;
        Ipv6Addr::new(
            0xfe80,
            0,
            0,
            0,
            u16::from_be_bytes([b[0] ^ 2, b[1]]),
            u16::from_be_bytes([b[2], 255]),
            u16::from_be_bytes([254, b[3]]),
            u16::from_be_bytes([b[4], b[5]]),
        )
    }
}
