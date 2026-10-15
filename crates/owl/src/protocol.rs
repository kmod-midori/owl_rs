// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{
    channel::Sequence,
    rate::{Coding, Rate, TxParameters, vht_width_code},
};
use serde::Serialize;

pub const BSSID: Mac = Mac([0, 0x25, 0, 0xff, 0x94, 0x73]);
pub const BROADCAST: Mac = Mac([255; 6]);
pub const MAX_FRAME: usize = 65535;
pub const MAX_AMSDU: usize = 7935;
pub const MAX_AMSDU_PACKETS: usize = 64;

pub(crate) fn tcp_frame(ethernet: &[u8]) -> bool {
    matches!(
        etherparse::SlicedPacket::from_ethernet(ethernet)
            .ok()
            .and_then(|p| p.transport),
        Some(etherparse::TransportSlice::Tcp(_))
    )
}

pub use owl_ipc::Mac;
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
    /// Sender queue delay, with the 32-bit microsecond clock wrapping naturally.
    pub tx_delay_us: u32,
    pub sync: Option<SyncParams>,
    pub sequence: Option<Sequence>,
    pub election: Option<Election>,
    pub v2: bool,
    pub name: Option<String>,
    pub version: Option<u8>,
    pub devclass: Option<u8>,
    pub capabilities: BandCapabilities,
}
#[derive(Debug)]
pub struct TxStatus {
    pub failed: bool,
    pub retries: u8,
    pub noack: bool,
    pub rate: Option<Rate>,
    pub fingerprint: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddBaRequest {
    pub dialog_token: u8,
    pub parameters: u16,
    pub timeout: u16,
    /// Sequence control, including fragment bits (which must be zero).
    pub starting_sequence: u16,
}
impl AddBaRequest {
    pub fn tid(self) -> u8 {
        ((self.parameters >> 2) & 15) as u8
    }
    pub fn window(self) -> u16 {
        let requested = self.parameters >> 6;
        if requested == 0 {
            64
        } else {
            requested.min(64)
        }
    }
}
#[derive(Debug)]
pub enum Body {
    TxStatus(TxStatus),
    Action(Action),
    AddBaRequest(AddBaRequest),
    Bar { tid: u8, sequence: u16 },
    DelBa { tid: u8, initiator: bool },
    Data(Vec<Vec<u8>>),
}
#[derive(Debug)]
pub struct Frame {
    pub source: Mac,
    pub destination: Mac,
    pub sequence: u16,
    /// QoS sequence space; non-QoS data has a separate sequence space.
    pub tid: Option<u8>,
    pub retry: bool,
    pub amsdu: bool,
    /// MPDU body bytes, excluding radiotap, MAC header and FCS.
    pub body_bytes: usize,
    /// Driver-reported A-MPDU membership; absence does not prove no aggregation.
    pub ampdu: bool,
    pub ampdu_last: bool,
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
        if fc & 0x00ff != 0x84 || fc & 0x4300 != 0 {
            return Ok(None);
        }
        r.take(2)?;
        let destination = r.mac()?;
        let source = r.mac()?;
        let control = r.le16()?;
        let sequence = r.le16()?;
        // Single-TID basic/compressed BAR: 16-byte header and four-byte body.
        if control & 0x0ffa != 0 || sequence & 15 != 0 {
            return Ok(None);
        }
        return Ok(Some(Frame {
            source,
            destination,
            sequence: sequence >> 4,
            tid: Some((control >> 12) as u8),
            retry: fc & 0x800 != 0,
            amsdu: false,
            body_bytes: 4,
            ampdu: false,
            ampdu_last: false,
            rssi: radio.antenna_signal.map(|s| s.value),
            frequency: radio.channel.map(|c| c.freq),
            body: Body::Bar {
                tid: (control >> 12) as u8,
                sequence: sequence >> 4,
            },
        }));
    }
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
    let completion = radio
        .tx_flags
        .zip(radio.data_retries)
        .filter(|_| matches!(fc & 0x00fc, 0x08 | 0x88));
    let body_bytes = r.rest().len();
    let body = if let Some((flags, retries)) = completion {
        Body::TxStatus(TxStatus {
            failed: flags.fail,
            retries: retries.value,
            noack: flags.no_ack,
            rate: crate::rate::reported_rate(&radio),
            fingerprint: tx_fingerprint(r.rest(), qos & 0x80 != 0).ok_or(Error::Truncated)?,
        })
    } else {
        match fc & 0x00fc {
            0xd0 if r.rest().starts_with(&[3, 0]) => {
                r.take(2)?; // Block Ack category, ADDBA request.
                let request = AddBaRequest {
                    dialog_token: r.u8()?,
                    parameters: r.le16()?,
                    timeout: r.le16()?,
                    starting_sequence: r.le16()?,
                };
                Body::AddBaRequest(request)
            }
            0xd0 if r.rest().starts_with(&[3, 2]) => {
                r.take(2)?;
                let parameters = r.le16()?;
                r.take(2)?; // Reason code.
                Body::DelBa {
                    tid: (parameters >> 12) as u8,
                    initiator: parameters & 0x800 != 0,
                }
            }
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
        }
    };
    Ok(Some(Frame {
        source,
        destination,
        sequence: seq >> 4,
        tid: (fc & 0x00fc == 0x88).then_some((qos & 0x0f) as u8),
        retry: fc & 0x0800 != 0,
        amsdu: qos & 0x80 != 0,
        body_bytes,
        ampdu: radio.ampdu_status.is_some(),
        ampdu_last: radio
            .ampdu_status
            .is_some_and(|status| status.last == Some(true)),
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
    r.take(1)?; // Reserved.
    let phy_time = r.le32()?;
    let target_time = r.le32()?;
    let mut a = Action {
        subtype,
        tx_delay_us: phy_time.wrapping_sub(target_time),
        sync: None,
        sequence: None,
        election: None,
        v2: false,
        name: None,
        version: None,
        devclass: None,
        capabilities: BandCapabilities::default(),
    };
    while !r.rest().is_empty() {
        // Zero-filled action suffixes can end with an incomplete tag-0 header.
        // Only allow that at a TLV boundary, never inside a declared value.
        if r.rest().len() < 3 && r.rest().iter().all(|&b| b == 0) {
            break;
        }
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
            7 => {
                // Reserved prefix, HT flags, A-MPDU parameters, RX MCS mask, reserved suffix.
                if value.len() < 8 {
                    return Err(Error::Invalid("HT capabilities length"));
                }
                v.take(2)?;
                let cap_info = v.le16()?;
                let ampdu_params = v.u8()?;
                let mut rx_mask = [0; 4];
                let mask = v.take(value.len() - 7)?;
                // Keep MCS 0–31; extended masks must not discard the action.
                let supported = mask.len().min(rx_mask.len());
                rx_mask[..supported].copy_from_slice(&mask[..supported]);
                a.capabilities.ht = Some(HtCapabilities {
                    cap_info,
                    ampdu_params,
                    rx_mask,
                    tx_mask: None,
                });
            }
            17 => {
                // AWDL's container can hold multiple IEEE capability IEs.
                while !v.rest().is_empty() {
                    let id = v.u8()?;
                    let len = v.u8()? as usize;
                    let mut ie = Reader::new(v.take(len)?);
                    // Unsupported optional IE layouts do not invalidate timing.
                    // v.take(len) above still rejects a truncated container.
                    if id == 191 && len == 12 {
                        a.capabilities.vht = Some(VhtCapabilities {
                            cap_info: ie.le32()?,
                            rx_mcs_map: ie.le16()?,
                            rx_highest: ie.le16()?,
                            tx_mcs_map: ie.le16()?,
                            tx_highest: ie.le16()?,
                        });
                    }
                }
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
                let n = v.u8()?;
                match n {
                    0..=64 => {
                        a.name = Some(String::from_utf8_lossy(v.take(n as usize)?).into_owned())
                    }
                    // AWDL uses two-byte compressed DNS labels too. Without a
                    // preceding literal label there is no hostname to retain.
                    0xc0..=0xff => {
                        v.u8()?;
                    }
                    _ => {} // Unsupported label encodings are optional metadata.
                }
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
        if out.len() == MAX_AMSDU_PACKETS {
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

pub fn radiotap_tx(parameters: TxParameters, noack: bool, fcs: bool) -> Result<Vec<u8>, Error> {
    let TxParameters { rate, coding } = parameters;
    if coding == Coding::Ldpc && !matches!(rate, Rate::Mcs { .. } | Rate::Vht { .. }) {
        return Err(Error::Invalid("LDPC requires an HT or VHT rate"));
    }
    if rate.phy_mbps().is_none() {
        return Err(Error::Invalid("concrete transmit rate"));
    }
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
    // Shared-mode injection can be adopted by the matching station interface.
    // Preserve our sequence number so hardware reports still match the ledger.
    present |= 1 << 15;
    if (8 + fields.len()) % 2 != 0 {
        fields.push(0);
    }
    fields.extend_from_slice(&(0x10u16 | if noack { 8 } else { 0 }).to_le_bytes());
    if let Rate::Mcs { index, width, sgi } = rate {
        present |= 1 << 19;
        let ldpc = coding == Coding::Ldpc;
        fields.extend_from_slice(&[
            7 | if ldpc { 0x10 } else { 0 },
            (if sgi { 4 } else { 0 }) | if ldpc { 0x10 } else { 0 } | u8::from(width == 40),
            index,
        ]);
    }
    if let Rate::Vht {
        index,
        nss,
        width,
        sgi,
    } = rate
    {
        if coding == Coding::Ldpc {
            // Linux 7.2's VHT injection parser ignores its coding byte. A preceding
            // MCS field sets TX_CTL_LDPC; VHT overrides the rate, keeping that flag.
            // HAVE_MCS is required: a FEC-only MCS field is skipped by mac80211.
            present |= 1 << 19;
            fields.extend_from_slice(&[0x12, 0x10, 0]);
        }
        present |= 1 << 21;
        if (8 + fields.len()) % 2 != 0 {
            fields.push(0);
        }
        // VHT known GI/bandwidth, SU user 0, selected FEC, no beamforming or STBC.
        fields.extend_from_slice(&0x0044u16.to_le_bytes());
        fields.extend_from_slice(&[
            if sgi { 4 } else { 0 },
            vht_width_code(width).ok_or(Error::Invalid("VHT width"))?,
            (index << 4) | nss,
            0,
            0,
            0,
            u8::from(coding == Coding::Ldpc),
            0,
            0,
            0,
        ]);
    }
    let mut out = vec![0, 0];
    out.extend_from_slice(&((8 + fields.len()) as u16).to_le_bytes());
    out.extend_from_slice(&present.to_le_bytes());
    out.extend(fields);
    Ok(out)
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HtCapabilities {
    pub cap_info: u16,
    pub ampdu_params: u8,
    pub rx_mask: [u8; 4],
    /// Local TX mask from nl80211; absent from AWDL's compact receive-only HT TLV.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_mask: Option<[u8; 4]>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VhtCapabilities {
    pub cap_info: u32,
    pub rx_mcs_map: u16,
    pub rx_highest: u16,
    pub tx_mcs_map: u16,
    pub tx_highest: u16,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
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

/// Respond with immediate BA, A-MSDU-in-A-MPDU support, and no inactivity timeout.
pub fn encode_addba_response(
    source: Mac,
    destination: Mac,
    request: AddBaRequest,
    sequence: u16,
    noack: bool,
    accept: bool,
) -> Vec<u8> {
    let mut out = radiotap_tx(Rate::DISCOVERY.into(), noack, false).expect("valid management rate");
    header(&mut out, source, destination, sequence, 0xd0);
    out.extend_from_slice(&[3, 1, request.dialog_token]);
    le16(&mut out, if accept { 0 } else { 37 }); // WLAN_STATUS_REQUEST_DECLINED.
    le16(
        &mut out,
        if accept {
            // Bit 0 advertises our receive support, independently of the request.
            (request.parameters & 0x003c) | 3 | (request.window() << 6)
        } else {
            request.parameters & 0x003e
        },
    );
    le16(&mut out, 0);
    out
}

/// Update only the PHY timestamp immediately before submitting a generated AF.
/// The target timestamp and countdown retain their frame-construction time.
pub fn stamp_action_tx(frame: &mut [u8], now_us: i64) -> Result<(), Error> {
    let mut r = Reader::new(frame);
    r.take(2)?;
    let radio_len = r.le16()? as usize;
    let offset = radio_len + 24;
    if frame.get(offset..offset + 6) != Some(&[127, 0, 0x17, 0xf2, 8, 0x10]) {
        return Err(Error::Invalid("action timestamp header"));
    }
    frame
        .get_mut(offset + 8..offset + 12)
        .ok_or(Error::Truncated)?
        .copy_from_slice(&(now_us as u32).to_le_bytes());
    Ok(())
}

pub fn encode_action(a: &Advertisement<'_>, subtype: u8, sequence: u16) -> Vec<u8> {
    let mut out = radiotap_tx(Rate::DISCOVERY.into(), false, false).expect("valid discovery rate");
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
    if subtype == 3 {
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
fn ethernet_payload(ethernet: &[u8]) -> Result<(Mac, Mac, &[u8]), Error> {
    let mut r = Reader::new(ethernet);
    let destination = r.mac()?;
    let source = r.mac()?;
    if r.be16()? != 0x86dd || r.rest().len() > 1500 {
        return Err(Error::Invalid("outgoing Ethernet frame"));
    }
    Ok((destination, source, r.rest()))
}
pub(crate) fn amsdu_subframe_len(ethernet: &[u8]) -> Option<usize> {
    let (_, _, ipv6) = ethernet_payload(ethernet).ok()?;
    Some(14 + 16 + ipv6.len())
}
fn data_payload(out: &mut Vec<u8>, ipv6: &[u8], sequence: u16) {
    out.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0x17, 0xf2, 8, 0]);
    le16(out, 0x0403);
    le16(out, sequence);
    le16(out, 0);
    out.extend_from_slice(&0x86ddu16.to_be_bytes());
    out.extend_from_slice(ipv6);
}
fn finish_data(mut out: Vec<u8>, header_start: usize, fcs: bool) -> Vec<u8> {
    if fcs {
        let crc = crc32fast::hash(&out[header_start..]);
        out.extend_from_slice(&crc.to_le_bytes());
    }
    out
}
pub fn encode_data(
    ethernet: &[u8],
    sequence: u16,
    data_sequence: u16,
    parameters: TxParameters,
    noack: bool,
    fcs: bool,
) -> Result<Vec<u8>, Error> {
    let (destination, source, ipv6) = ethernet_payload(ethernet)?;
    let mut out = radiotap_tx(parameters, noack && !destination.multicast(), fcs)?;
    let header_start = out.len();
    header(&mut out, source, destination, sequence, 8);
    data_payload(&mut out, ipv6, data_sequence);
    Ok(finish_data(out, header_start, fcs))
}
/// One QoS MPDU containing same-address AWDL MSDUs, padded only between subframes.
pub fn encode_amsdu(
    packets: &[&[u8]],
    sequence: u16,
    data_sequence: u16,
    parameters: TxParameters,
    noack: bool,
    fcs: bool,
) -> Result<Vec<u8>, Error> {
    if !(2..=MAX_AMSDU_PACKETS).contains(&packets.len()) {
        return Err(Error::Invalid("A-MSDU packet count"));
    }
    let (destination, source, _) = ethernet_payload(packets[0])?;
    if !destination.valid_unicast() || !source.valid_unicast() {
        return Err(Error::Invalid("A-MSDU address"));
    }
    let mut out = radiotap_tx(parameters, noack, fcs)?;
    let header_start = out.len();
    header(&mut out, source, destination, sequence, 0x88);
    out.extend_from_slice(&[0x80, 0]); // TID 0, A-MSDU present, normal on-air ACK policy.
    let body_start = out.len();
    for (i, packet) in packets.iter().enumerate() {
        let (dst, src, ipv6) = ethernet_payload(packet)?;
        if dst != destination || src != source {
            return Err(Error::Invalid("A-MSDU address mismatch"));
        }
        if i != 0 {
            out.resize(out.len() + (4 - (out.len() - body_start) % 4) % 4, 0);
        }
        if out.len() - body_start + 14 + 16 + ipv6.len() > MAX_AMSDU {
            return Err(Error::Invalid("A-MSDU length"));
        }
        out.extend_from_slice(&destination.0);
        out.extend_from_slice(&source.0);
        out.extend_from_slice(&((16 + ipv6.len()) as u16).to_be_bytes());
        data_payload(&mut out, ipv6, data_sequence.wrapping_add(i as u16));
    }
    Ok(finish_data(out, header_start, fcs))
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

/// Identity of one injected MPDU; excludes mutable frame-control/duration fields.
pub(crate) fn transmit_key(bytes: &[u8]) -> Option<(Mac, u16, u32)> {
    let rt = u16::from_le_bytes(bytes.get(2..4)?.try_into().ok()?) as usize;
    if rt < 8 {
        return None;
    }
    let data = bytes.get(rt..)?;
    let dst = Mac(data.get(4..10)?.try_into().ok()?);
    let seq = u16::from_le_bytes(data.get(22..24)?.try_into().ok()?) >> 4;
    let fc = u16::from_le_bytes(data.get(..2)?.try_into().ok()?);
    let qos = fc & 0x00fc == 0x88;
    let control = if qos {
        u16::from_le_bytes(data.get(24..26)?.try_into().ok()?)
    } else {
        0
    };
    let header = if qos {
        26 + if fc & 0x8000 != 0 { 4 } else { 0 }
    } else {
        24
    };
    Some((
        dst,
        seq,
        tx_fingerprint(data.get(header..)?, control & 0x80 != 0)?,
    ))
}

// mt76 USB completion SKBs retain up to seven bytes of DMA alignment/trailer
// padding. Determine the logical MPDU body from checked protocol lengths;
// never trim zeros from application payload or accept unbounded suffixes.
fn tx_fingerprint(body: &[u8], aggregate: bool) -> Option<u32> {
    fn msdu_len(body: &[u8]) -> Option<usize> {
        if body.get(16)? >> 4 != 6 {
            return None;
        }
        Some(56 + u16::from_be_bytes(body.get(20..22)?.try_into().ok()?) as usize)
    }
    let end = if aggregate {
        let mut at = 0usize;
        loop {
            let len = u16::from_be_bytes(body.get(at + 12..at + 14)?.try_into().ok()?) as usize;
            let end = at.checked_add(14 + len)?;
            let subframe = body.get(at + 14..end)?;
            if msdu_len(subframe)? != len {
                return None;
            }
            let tail = body.get(end..)?;
            if tail.len() <= 7 && tail.iter().all(|&b| b == 0) {
                break end;
            }
            at = (end + 3) & !3;
        }
    } else {
        msdu_len(body)?
    };
    let tail = body.get(end..)?;
    if tail.len() > 7 || tail.iter().any(|&b| b != 0) {
        return None;
    }
    Some(crc32fast::hash(body.get(..end)?))
}
