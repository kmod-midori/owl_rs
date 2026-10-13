// SPDX-License-Identifier: GPL-3.0-or-later
use crate::channel::Sequence;
use serde::{Serialize, Serializer};
use std::{fmt, net::Ipv6Addr, str::FromStr};

pub const BSSID: Mac = Mac([0, 0x25, 0, 0xff, 0x94, 0x73]);
pub const BROADCAST: Mac = Mac([255; 6]);
pub const MAX_FRAME: usize = 65535;

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
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        let mut bytes = [0; 6];
        let mut parts = s.split(':');
        for b in &mut bytes {
            let p = parts.next().ok_or(Error::Invalid("MAC address"))?;
            if p.len() != 2 {
                return Err(Error::Invalid("MAC address"));
            }
            *b = u8::from_str_radix(p, 16).map_err(|_| Error::Invalid("MAC address"))?;
        }
        if parts.next().is_some() {
            return Err(Error::Invalid("MAC address"));
        }
        Ok(Self(bytes))
    }
}
impl Mac {
    pub fn random() -> Result<Self, openssl::error::ErrorStack> {
        let mut bytes = [0; 6];
        openssl::rand::rand_bytes(&mut bytes)?;
        bytes[0] = (bytes[0] | 2) & !1;
        Ok(Self(bytes))
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
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("truncated frame or TLV")]
    Truncated,
    #[error("invalid {0}")]
    Invalid(&'static str),
    #[error("radiotap: {0}")]
    Radiotap(String),
}
/// Checked, borrowed byte views. No pointer casts or unaligned reads.
pub struct Reader<'a> {
    remaining: &'a [u8],
}
impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { remaining: data }
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.remaining.len() {
            return Err(Error::Truncated);
        }
        let (head, tail) = self.remaining.split_at(n);
        self.remaining = tail;
        Ok(head)
    }
    pub fn rest(&self) -> &'a [u8] {
        self.remaining
    }
    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    pub fn le16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().map_err(|_| Error::Truncated)?,
        ))
    }
    pub fn be16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| Error::Truncated)?,
        ))
    }
    pub fn le32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| Error::Truncated)?,
        ))
    }
    pub fn mac(&mut self) -> Result<Mac, Error> {
        Ok(Mac(self
            .take(6)?
            .try_into()
            .map_err(|_| Error::Truncated)?))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rate {
    Legacy(u8),
    Mcs { index: u8, sgi: bool },
}
impl fmt::Display for Rate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Legacy(n) => write!(f, "{n}"),
            Self::Mcs { index, sgi } => write!(f, "mcs{index}{}", if *sgi { "-sgi" } else { "" }),
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
impl Default for Rate {
    fn default() -> Self {
        Self::Legacy(12)
    }
}
impl FromStr for Rate {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        if let Some(m) = s.strip_prefix("mcs") {
            let (m, sgi) = m.strip_suffix("-sgi").map_or((m, false), |v| (v, true));
            if !m.is_empty()
                && m.bytes().all(|b| b.is_ascii_digit())
                && let Ok(index) = m.parse::<u8>()
                && index <= 15
            {
                return Ok(Self::Mcs { index, sgi });
            }
        } else if let Ok(n) = s.parse::<u8>()
            && [6, 9, 12, 18, 24, 36, 48, 54].contains(&n)
        {
            return Ok(Self::Legacy(n));
        }
        Err("use 6, 9, 12, 18, 24, 36, 48, 54, mcs0..mcs15, or mcsN-sgi".into())
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Election {
    pub master: Mac,
    pub sync: Mac,
    pub counter: u32,
    pub height: u32,
    pub metric: u32,
    pub self_metric: u32,
    pub self_counter: u32,
}
impl Election {
    pub fn own(mac: Mac) -> Self {
        Self {
            master: mac,
            sync: mac,
            counter: 0,
            height: 0,
            metric: 60,
            self_metric: 60,
            self_counter: 0,
        }
    }
}
#[derive(Clone, Debug)]
pub struct SyncParams {
    pub next: u16,
    pub counter: u16,
}
#[derive(Clone, Debug)]
pub struct Action {
    pub subtype: u8,
    pub sync: Option<SyncParams>,
    pub sequence: Option<Sequence>,
    pub election: Option<Election>,
    pub v2: bool,
    pub name: Option<String>,
    pub version: Option<u8>,
    pub devclass: Option<u8>,
}
#[derive(Debug)]
pub enum Body {
    Action(Action),
    Data(Vec<Vec<u8>>),
}
#[derive(Debug)]
pub struct Frame {
    pub source: Mac,
    pub destination: Mac,
    pub sequence: u16,
    pub retry: bool,
    pub rssi: Option<i8>,
    pub frequency: Option<u16>,
    pub body: Body,
}

pub fn parse(bytes: &[u8]) -> Result<Option<Frame>, Error> {
    let (radio, mut data) =
        radiotap::Radiotap::parse(bytes).map_err(|e| Error::Radiotap(e.to_string()))?;
    let flags = radio.flags.as_ref();
    if flags.is_some_and(|f| f.bad_fcs) {
        return Ok(None);
    }
    if flags.is_some_and(|f| f.fcs) {
        data = data
            .get(..data.len().checked_sub(4).ok_or(Error::Truncated)?)
            .ok_or(Error::Truncated)?;
    }
    let mut r = Reader::new(data);
    let fc = r.le16()?;
    if fc & 0x000c == 4 {
        return Ok(None);
    } // Control frames do not have three addresses.
    if fc & 0x4303 != 0 || fc & 0x0400 != 0 {
        return Ok(None);
    } // Version, DS, protected, fragmented.
    r.take(2)?;
    let destination = r.mac()?;
    let source = r.mac()?;
    if r.mac()? != BSSID {
        return Ok(None);
    }
    let seq = r.le16()?;
    if seq & 15 != 0 {
        return Ok(None);
    }
    let header_len = if fc & 0x00fc == 0x88 {
        r.take(2)?;
        if fc & 0x8000 != 0 {
            r.take(4)?;
            30
        } else {
            26
        }
    } else {
        24
    };
    let qos = if fc & 0x00fc == 0x88 {
        u16::from_le_bytes(data[24..26].try_into().map_err(|_| Error::Truncated)?)
    } else {
        0
    };
    if flags.is_some_and(|f| f.data_pad) {
        r.take((4 - header_len % 4) % 4)?;
    }
    let body = match fc & 0x00fc {
        0xd0 => match parse_action(r.rest())? {
            Some(a) => Body::Action(a),
            None => return Ok(None),
        },
        0x08 | 0x88 => Body::Data(if qos & 0x80 != 0 {
            parse_amsdu(r.rest())?
        } else {
            vec![parse_data(r.rest(), source, destination)?]
        }),
        _ => return Ok(None),
    };
    Ok(Some(Frame {
        source,
        destination,
        sequence: seq >> 4,
        retry: fc & 0x0800 != 0,
        rssi: radio.antenna_signal.map(|v| v.value),
        frequency: radio.channel.map(|v| v.freq),
        body,
    }))
}
fn parse_action(data: &[u8]) -> Result<Option<Action>, Error> {
    let mut r = Reader::new(data);
    if r.take(6)? != [127, 0, 0x17, 0xf2, 8, 0x10] {
        return Ok(None);
    }
    let subtype = r.u8()?;
    if subtype != 0 && subtype != 3 {
        return Ok(None);
    }
    r.take(9)?;
    let mut a = Action {
        subtype,
        sync: None,
        sequence: None,
        election: None,
        v2: false,
        name: None,
        version: None,
        devclass: None,
    };
    while !r.rest().is_empty() {
        let kind = r.u8()?;
        let len = r.le16()? as usize;
        let value = r.take(len)?;
        let mut v = Reader::new(value);
        match kind {
            4 => {
                v.take(1)?;
                let next = v.le16()?;
                v.take(2)?;
                let period = v.le16()?;
                v.take(20)?;
                let presence = v.u8()?;
                v.take(1)?;
                let counter = v.le16()?;
                if period != 16 || presence != 4 || !(1..=64).contains(&next) {
                    return Err(Error::Invalid("sync parameters"));
                }
                a.sync = Some(SyncParams { next, counter });
            }
            18 => a.sequence = Some(Sequence::parse(value)?),
            5 if !a.v2 => {
                v.take(3)?;
                let height = v.u8()? as u32;
                v.take(1)?;
                let master = v.mac()?;
                let metric = v.le32()?;
                let self_metric = v.le32()?;
                a.election = Some(Election {
                    master,
                    sync: Mac::default(),
                    counter: 0,
                    height,
                    metric,
                    self_metric,
                    self_counter: 0,
                });
            }
            24 => {
                let master = v.mac()?;
                let sync = v.mac()?;
                let counter = v.le32()?;
                let height = v.le32()?;
                let metric = v.le32()?;
                let self_metric = v.le32()?;
                v.take(8)?;
                let self_counter = v.le32()?;
                a.election = Some(Election {
                    master,
                    sync,
                    counter,
                    height,
                    metric,
                    self_metric,
                    self_counter,
                });
                a.v2 = true;
            }
            16 => {
                v.u8()?;
                let n = v.u8()? as usize;
                if n > 64 {
                    return Err(Error::Invalid("ARPA name length"));
                }
                a.name = Some(String::from_utf8_lossy(v.take(n)?).into_owned());
            }
            21 => {
                a.version = Some(v.u8()?);
                a.devclass = Some(v.u8()?);
            }
            _ => {}
        }
    }
    Ok(Some(a))
}
fn parse_data(data: &[u8], source: Mac, destination: Mac) -> Result<Vec<u8>, Error> {
    let mut r = Reader::new(data);
    let llc = r.take(8)?;
    // Some peers use the zero SNAP OUI; the PID remains AWDL's 0x0800.
    if llc[..3] != [0xaa, 0xaa, 3] || llc[6..] != [8, 0] {
        return Err(Error::Invalid("AWDL LLC"));
    }
    if r.le16()? != 0x0403 {
        return Err(Error::Invalid("AWDL data header"));
    }
    r.le16()?;
    if r.le16()? != 0 {
        return Err(Error::Invalid("AWDL data padding"));
    }
    let ether = r.be16()?;
    if ether != 0x86dd {
        return Err(Error::Invalid("AWDL EtherType"));
    }
    if r.rest().len() > 1500 {
        return Err(Error::Invalid("Ethernet payload size"));
    }
    let mut out = Vec::with_capacity(14 + r.rest().len());
    out.extend_from_slice(&destination.0);
    out.extend_from_slice(&source.0);
    out.extend_from_slice(&ether.to_be_bytes());
    out.extend_from_slice(r.rest());
    Ok(out)
}
fn parse_amsdu(data: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let mut r = Reader::new(data);
    let mut out = Vec::new();
    while !r.rest().is_empty() {
        if out.len() == 64 {
            return Err(Error::Invalid("A-MSDU subframe count"));
        }
        let destination = r.mac()?;
        let source = r.mac()?;
        let len = r.be16()? as usize;
        out.push(parse_data(r.take(len)?, source, destination)?);
        if !r.rest().is_empty() {
            r.take((4 - (14 + len) % 4) % 4)?;
        }
    }
    Ok(out)
}

pub fn radiotap_tx(rate: Rate, noack: bool, fcs: bool) -> Vec<u8> {
    let mut present = 0u32;
    let mut fields = Vec::new();
    if fcs {
        present |= 1 << 1;
        fields.push(0x10);
    }
    if let Rate::Legacy(rate) = rate {
        present |= 1 << 2;
        fields.push(rate * 2);
    }
    if noack {
        present |= 1 << 15;
        if (8 + fields.len()) % 2 != 0 {
            fields.push(0);
        }
        fields.extend_from_slice(&8u16.to_le_bytes());
    }
    if let Rate::Mcs { index, sgi } = rate {
        present |= 1 << 19;
        fields.extend_from_slice(&[7, if sgi { 4 } else { 0 }, index]);
    }
    let mut out = vec![0, 0];
    out.extend_from_slice(&((8 + fields.len()) as u16).to_le_bytes());
    out.extend_from_slice(&present.to_le_bytes());
    out.extend(fields);
    out
}
fn header(out: &mut Vec<u8>, source: Mac, destination: Mac, sequence: u16, fc: u16) {
    out.extend_from_slice(&fc.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&destination.0);
    out.extend_from_slice(&source.0);
    out.extend_from_slice(&BSSID.0);
    out.extend_from_slice(&((sequence & 4095) << 4).to_le_bytes());
}
fn tlv(out: &mut Vec<u8>, kind: u8, value: &[u8]) {
    out.push(kind);
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value);
}
fn le16(v: &mut Vec<u8>, n: u16) {
    v.extend_from_slice(&n.to_le_bytes());
}
fn le32(v: &mut Vec<u8>, n: u32) {
    v.extend_from_slice(&n.to_le_bytes());
}
/// AWDL's compact HT field carries RX MCS 0–31, not the full IEEE HT MCS set.
#[derive(Clone, Debug, Serialize)]
pub struct HtCapabilities {
    pub cap_info: u16,
    pub ampdu_params: u8,
    pub rx_mask: [u8; 4],
}
#[derive(Clone, Debug, Serialize)]
pub struct VhtCapabilities {
    pub cap_info: u32,
    pub rx_mcs_map: u16,
    pub rx_highest: u16,
    pub tx_mcs_map: u16,
    pub tx_highest: u16,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct BandCapabilities {
    pub ht: Option<HtCapabilities>,
    pub vht: Option<VhtCapabilities>,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct RadioCapabilities {
    pub ghz2: BandCapabilities,
    pub ghz5: BandCapabilities,
}
impl RadioCapabilities {
    pub fn for_channel(&self, channel: u8) -> &BandCapabilities {
        if channel <= 14 {
            &self.ghz2
        } else {
            &self.ghz5
        }
    }
}

#[derive(Clone, Debug)]
pub struct Advertisement<'a> {
    pub mac: Mac,
    pub name: &'a str,
    pub capabilities: &'a BandCapabilities,
    pub sequence: &'a Sequence,
    pub election: &'a Election,
    pub channel: u8,
    pub master_channel: u8,
    pub next: u16,
    pub aw_counter: u16,
    pub now_us: i64,
}

pub fn encode_action(a: &Advertisement<'_>, subtype: u8, sequence: u16) -> Vec<u8> {
    let mut out = radiotap_tx(Rate::default(), false, false);
    header(&mut out, a.mac, BROADCAST, sequence, 0xd0);
    out.extend_from_slice(&[127, 0, 0x17, 0xf2, 8, 0x10, subtype, 0]);
    le32(&mut out, a.now_us as u32);
    le32(&mut out, a.now_us as u32);
    let mut sync = vec![a.channel];
    le16(&mut sync, a.next);
    sync.extend_from_slice(&[a.master_channel, 0]);
    for n in [16, 110, 0x1800, 16, 16, a.next.saturating_sub(48)] {
        le16(&mut sync, n);
    }
    sync.extend_from_slice(&[3, 3, 3, 3]);
    sync.extend_from_slice(&a.election.master.0);
    sync.extend_from_slice(&[4, 0]);
    le16(&mut sync, a.aw_counter);
    le16(&mut sync, a.aw_counter);
    sync.extend(a.sequence.encode());
    sync.extend_from_slice(&[0, 0]);
    tlv(&mut out, 4, &sync);
    let mut e = vec![0, 0, 0, a.election.height as u8, 0];
    e.extend_from_slice(&a.election.master.0);
    le32(&mut e, a.election.metric);
    le32(&mut e, a.election.self_metric);
    e.extend_from_slice(&[0, 0]);
    tlv(&mut out, 5, &e);
    let mut seq = a.sequence.encode();
    seq.extend_from_slice(&[0, 0, 0]);
    tlv(&mut out, 18, &seq);
    let mut e = Vec::new();
    e.extend_from_slice(&a.election.master.0);
    e.extend_from_slice(&a.election.sync.0);
    for n in [
        a.election.counter,
        a.election.height,
        a.election.metric,
        a.election.self_metric,
        0,
        0,
        a.election.self_counter,
    ] {
        le32(&mut e, n);
    }
    tlv(&mut out, 24, &e);
    tlv(&mut out, 6, &[0; 9]);
    if subtype == 3 {
        if let Some(ht) = &a.capabilities.ht
            && let Some(last) = ht.rx_mask.iter().rposition(|b| *b != 0)
        {
            let mut value = vec![0, 0];
            le16(&mut value, ht.cap_info);
            value.push(ht.ampdu_params);
            value.extend_from_slice(&ht.rx_mask[..=last]);
            value.extend_from_slice(&[0, 0]);
            tlv(&mut out, 7, &value);
        }
        if let Some(vht) = &a.capabilities.vht {
            // IEEE VHT Capability IE (191, length 12) inside AWDL container 17.
            let mut value = vec![191, 12];
            le32(&mut value, vht.cap_info);
            for n in [
                vht.rx_mcs_map,
                vht.rx_highest,
                vht.tx_mcs_map,
                vht.tx_highest,
            ] {
                le16(&mut value, n);
            }
            tlv(&mut out, 17, &value);
        }
        let name = &a.name.as_bytes()[..a.name.len().min(64)];
        let mut arpa = vec![3, name.len() as u8];
        arpa.extend_from_slice(name);
        arpa.extend_from_slice(&[0xc0, 0x0c]);
        tlv(&mut out, 16, &arpa);
    }
    let mut path = vec![0x24, 0x8f, b'X', b'0', 0];
    le16(
        &mut path,
        match a.master_channel {
            6 => 1,
            44 => 2,
            _ => 4,
        },
    );
    path.extend_from_slice(&a.mac.0);
    le16(&mut path, 0);
    tlv(&mut out, 12, &path);
    tlv(&mut out, 21, &[0x34, 1]);
    out
}
pub fn encode_data(
    ethernet: &[u8],
    sequence: u16,
    data_sequence: u16,
    rate: Rate,
    fixed: bool,
    fcs: bool,
) -> Result<Vec<u8>, Error> {
    let mut r = Reader::new(ethernet);
    let destination = r.mac()?;
    let source = r.mac()?;
    let ethertype = r.be16()?;
    if ethertype != 0x86dd || r.rest().len() > 1500 {
        return Err(Error::Invalid("outgoing Ethernet frame"));
    }
    let mut out = radiotap_tx(rate, fixed && !destination.multicast(), fcs);
    let header_start = out.len();
    header(&mut out, source, destination, sequence, 8);
    out.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0x17, 0xf2, 8, 0]);
    le16(&mut out, 0x0403);
    le16(&mut out, data_sequence);
    le16(&mut out, 0);
    out.extend_from_slice(&ethertype.to_be_bytes());
    out.extend_from_slice(r.rest());
    if fcs {
        let crc = crc32fast::hash(&out[header_start..]);
        out.extend_from_slice(&crc.to_le_bytes());
    }
    Ok(out)
}

/// AWDL service-response records use Apple's fixed DNS compression dictionary.
/// Ported from the existing mkpsf.py service-only implementation.
pub fn airdrop_service(mac: Mac, hostname: &str, port: u16) -> Vec<u8> {
    fn label(s: &[u8]) -> Vec<u8> {
        let mut out = vec![s.len() as u8];
        out.extend(s);
        out
    }
    fn record(out: &mut Vec<u8>, name: &[u8], kind: u8, data: &[u8]) {
        let mut body = Vec::new();
        le16(&mut body, (name.len() + 1) as u16);
        body.extend(name);
        body.push(kind);
        le16(&mut body, data.len() as u16);
        body.extend([0, 0]);
        body.extend(data);
        tlv(out, 2, &body);
    }
    let id: String = mac.0.iter().map(|b| format!("{b:02x}")).collect();
    let mut instance = label(id.as_bytes());
    instance.extend([0xc0, 7]);
    let mut ptr = label(id.as_bytes());
    ptr.extend([0xc0, 0]);
    let mut srv = vec![0, 0, 0, 0];
    srv.extend(port.to_be_bytes());
    srv.extend(label(&hostname.as_bytes()[..hostname.len().min(63)]));
    srv.extend([0xc0, 12]);
    let mut out = Vec::new();
    record(&mut out, &[0xc0, 7], 12, &ptr);
    record(&mut out, &instance, 33, &srv);
    record(&mut out, &instance, 16, &label(b"flags=137"));
    out
}
