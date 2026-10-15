// SPDX-License-Identifier: GPL-3.0-or-later
//! AWDL link TX queue: opportunistic A-MSDU batching and atomic injection retries.
use crate::{
    engine::{AckTiming, Engine},
    protocol::{self, BandCapabilities, Mac},
    rate::{Rate, TxParameters},
};
use std::collections::{BTreeMap, VecDeque};
use tracing::{debug, warn};

pub(crate) const QUEUE_LIMIT: usize = 128;
pub(crate) enum InjectionError<E> {
    Backpressure,
    TooLarge(E),
    Fatal(E),
}
#[derive(Default)]
pub(crate) struct Report {
    pub last_sent_us: Option<i64>,
    pub last_tcp_us: Option<i64>,
}
#[derive(Clone, Copy)]
enum Block {
    Schedule,
    Airtime,
}
struct Ack {
    id: u64,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgment: u32,
    window: u16,
    timestamp: Option<u32>,
    options_crc: u32,
    schedule_blocked: bool,
    airtime_blocked: bool,
    backpressured: bool,
}
fn tcp_metadata(ethernet: &[u8]) -> (bool, Option<Ack>) {
    let Ok(packet) = etherparse::SlicedPacket::from_ethernet(ethernet) else {
        return (false, None);
    };
    let Some(etherparse::TransportSlice::Tcp(tcp)) = packet.transport else {
        return (false, None);
    };
    let ack = (tcp.ack() && !tcp.syn() && !tcp.fin() && !tcp.rst() && tcp.payload().is_empty())
        .then(|| Ack {
            id: 0,
            source_port: tcp.source_port(),
            destination_port: tcp.destination_port(),
            sequence: tcp.sequence_number(),
            acknowledgment: tcp.acknowledgment_number(),
            window: tcp.window_size(),
            timestamp: tcp
                .options_iterator()
                .find_map(|option| match option.ok()? {
                    etherparse::TcpOptionElement::Timestamp(value, _) => Some(value),
                    _ => None,
                }),
            options_crc: crc32fast::hash(tcp.options()),
            schedule_blocked: false,
            airtime_blocked: false,
            backpressured: false,
        });
    (true, ack)
}
impl AckTiming {
    fn finished(&mut self, ack: &Ack) {
        self.schedule_blocked += u64::from(ack.schedule_blocked);
        self.airtime_blocked += u64::from(ack.airtime_blocked);
        self.backpressured += u64::from(ack.backpressured);
    }
}
struct Packet {
    ethernet: Vec<u8>,
    queued_us: i64,
    tcp: bool,
    ack: Option<Ack>,
}
impl Packet {
    fn dropped(&self, timing: &mut AckTiming, now: i64, reason: &'static str) {
        if let Some(ack) = &self.ack {
            timing.dropped += 1;
            timing.finished(ack);
            debug!(
                ack_id = ack.id,
                queued_us = self.queued_us,
                dropped_us = now,
                queue_wait_us = now.saturating_sub(self.queued_us).max(0),
                reason,
                "AWDL TCP ACK dropped"
            );
        }
    }
}
struct Injection {
    id: u64,
    channel: u8,
    parameters: TxParameters,
    started_us: i64,
    finished_us: i64,
}
struct Frame {
    packets: Vec<Packet>,
    encoded: Option<(TxParameters, Vec<u8>)>,
}
impl Frame {
    fn blocked(&mut self, reason: Block) {
        for ack in self.packets.iter_mut().filter_map(|p| p.ack.as_mut()) {
            match reason {
                Block::Schedule => ack.schedule_blocked = true,
                Block::Airtime => ack.airtime_blocked = true,
            }
        }
    }
    fn record_injection<E>(
        &mut self,
        engine: &mut Engine,
        injection: Injection,
        result: &Result<(), InjectionError<E>>,
    ) {
        let Injection {
            id: injection_id,
            channel,
            parameters,
            started_us: injection_started_us,
            finished_us: injection_finished_us,
        } = injection;
        let injection_us = injection_finished_us
            .saturating_sub(injection_started_us)
            .max(0) as u64;
        let outcome = match result {
            Ok(()) => "accepted",
            Err(InjectionError::Backpressure) => "backpressure",
            Err(InjectionError::TooLarge(_)) => "too_large",
            Err(InjectionError::Fatal(_)) => "failed",
        };
        if self.packets.iter().any(|p| p.ack.is_some()) {
            let timing = &mut engine.stats.tx_ack;
            let count = self.packets.len();
            let dst = self.destination();
            timing.injection_attempts += 1;
            timing.injection_us_total = timing.injection_us_total.saturating_add(injection_us);
            timing.injection_us_max = timing.injection_us_max.max(injection_us);
            for p in &mut self.packets {
                if let Some(ack) = &mut p.ack {
                    ack.backpressured |= matches!(result, Err(InjectionError::Backpressure));
                    let queue_wait_us =
                        injection_started_us.saturating_sub(p.queued_us).max(0) as u64;
                    if result.is_ok() {
                        timing.injected += 1;
                        timing.finished(ack);
                        timing.queue_wait_us_total =
                            timing.queue_wait_us_total.saturating_add(queue_wait_us);
                        timing.queue_wait_us_max = timing.queue_wait_us_max.max(queue_wait_us);
                    }
                    debug!(
                        ack_id=ack.id, injection_id, peer=%dst,
                        source_port=ack.source_port, destination_port=ack.destination_port,
                        sequence=ack.sequence, acknowledgment=ack.acknowledgment,
                        window=ack.window, timestamp=?ack.timestamp, options_crc=ack.options_crc,
                        queued_us=p.queued_us, injection_started_us, injection_finished_us,
                        queue_wait_us, injection_us, outcome, channel,
                        slot=engine.clock.slot(injection_started_us), rate=%parameters.rate, coding=%parameters.coding,
                        aggregate_packets=count, schedule_blocked=ack.schedule_blocked,
                        airtime_blocked=ack.airtime_blocked, backpressured=ack.backpressured,
                        "AWDL TCP ACK injection"
                    );
                }
            }
        }
    }
    fn single(packet: Packet) -> Self {
        Self {
            packets: vec![packet],
            encoded: None,
        }
    }
    fn destination(&self) -> Mac {
        Mac(self.packets[0].ethernet[..6]
            .try_into()
            .expect("checked Ethernet header"))
    }
    fn body_len(&self) -> Option<usize> {
        let mut len = 0;
        for (i, p) in self.packets.iter().enumerate() {
            if i != 0 {
                len = (len + 3) & !3;
            }
            len += protocol::amsdu_subframe_len(&p.ethernet)?;
        }
        Some(len)
    }
    fn encoded(
        &mut self,
        engine: &mut Engine,
        parameters: TxParameters,
    ) -> Result<&[u8], protocol::Error> {
        let destination = self.destination();
        if let Some((previous, bytes)) = &mut self.encoded {
            if *previous != parameters {
                let old_len = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
                bytes.splice(
                    ..old_len,
                    protocol::radiotap_tx(
                        parameters,
                        engine.config.tx_noack && !destination.multicast(),
                        false,
                    )?,
                );
                *previous = parameters;
            }
        } else {
            let packets: Vec<_> = self.packets.iter().map(|p| p.ethernet.as_slice()).collect();
            self.encoded = Some((parameters, engine.data_frame(&packets, parameters)?));
        }
        Ok(&self.encoded.as_ref().expect("encoded frame").1)
    }
}
struct ManagementFrame {
    peer: Mac,
    request: protocol::AddBaRequest,
    queued_us: i64,
    sequence: u16,
}
pub(crate) struct Queue {
    frames: VecDeque<Frame>,
    management: VecDeque<ManagementFrame>,
    aggregation: bool,
    reserved_until_us: i64,
    next_ack_id: u64,
    next_injection_id: u64,
}
impl Default for Queue {
    fn default() -> Self {
        Self {
            frames: VecDeque::new(),
            management: VecDeque::new(),
            aggregation: true,
            reserved_until_us: 0,
            next_ack_id: 1,
            next_injection_id: 1,
        }
    }
}
impl Queue {
    pub fn len(&self) -> usize {
        self.frames.iter().map(|f| f.packets.len()).sum()
    }
    pub fn pending_acks(&self) -> usize {
        self.frames
            .iter()
            .flat_map(|f| &f.packets)
            .filter(|p| p.ack.is_some())
            .count()
    }
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty() && self.management.is_empty()
    }
    pub fn is_idle(&self, now: i64, quiet_us: i64) -> bool {
        self.is_empty() && now.saturating_sub(self.reserved_until_us) >= quiet_us
    }
    pub fn has_pending_airtime(&self, now: i64) -> bool {
        self.reserved_until_us > now
    }
    pub fn has_tcp(&self) -> bool {
        self.frames.iter().flat_map(|f| &f.packets).any(|p| p.tcp)
    }
    pub fn push(&mut self, ethernet: Vec<u8>, queued_us: i64) {
        assert!(
            ethernet.len() >= 14 && self.len() < QUEUE_LIMIT,
            "checked bounded Ethernet queue"
        );
        let (tcp, mut ack) = tcp_metadata(&ethernet);
        if let Some(ack) = &mut ack {
            ack.id = self.next_ack_id;
            self.next_ack_id = self.next_ack_id.wrapping_add(1);
        }
        self.frames.push_back(Frame::single(Packet {
            ethernet,
            queued_us,
            tcp,
            ack,
        }));
    }
    pub fn respond_addba(
        &mut self,
        engine: &mut Engine,
        peer: Mac,
        request: protocol::AddBaRequest,
        now: i64,
    ) {
        // Collapse retransmissions only while their response is still queued.
        // A later request must get another reply if the first one was lost.
        if self
            .management
            .iter()
            .any(|f| f.peer == peer && f.request == request)
        {
            return;
        }
        self.cancel_ba(peer, Some(request.tid()));
        if self.management.len() == QUEUE_LIMIT {
            engine.stats.dropped += 1;
            return;
        }
        self.management.push_back(ManagementFrame {
            peer,
            request,
            queued_us: now,
            sequence: engine.next_sequence(),
        });
    }
    pub fn cancel_ba(&mut self, peer: Mac, tid: Option<u8>) {
        self.management
            .retain(|f| f.peer != peer || tid.is_some_and(|tid| f.request.tid() != tid));
    }
    fn split(&mut self, index: usize, frame: Frame) {
        for packet in frame.packets.into_iter().rev() {
            self.frames.insert(index, Frame::single(packet));
        }
    }
    pub fn flush<E: std::fmt::Display + Into<anyhow::Error>>(
        &mut self,
        engine: &mut Engine,
        channel: u8,
        monitor_limit: usize,
        mut now: impl FnMut() -> i64,
        mut inject: impl FnMut(&[u8]) -> Result<(), InjectionError<E>>,
    ) -> anyhow::Result<Report> {
        let mut report = Report::default();
        // MAC management responses share airtime accounting but never enter TAP
        // or A-MSDU aggregation. Bound retries/expiry like the Ethernet queue.
        for _ in 0..self.management.len() {
            let frame = self.management.pop_front().expect("management queue count");
            let time = now();
            if time.saturating_sub(frame.queued_us)
                >= engine.config.pending_timeout.as_micros() as i64
                || !engine.peers.get(&frame.peer).is_some_and(|p| p.valid)
            {
                engine.stats.dropped += 1;
                continue;
            }
            let accept =
                engine.config.rx_ampdu && engine.reorder.can_start(frame.peer, frame.request);
            let bytes = protocol::encode_addba_response(
                engine.config.mac,
                frame.peer,
                frame.request,
                frame.sequence,
                engine.config.tx_noack,
                accept,
            );
            let outstanding = self.reserved_until_us.saturating_sub(time).max(0);
            if channel != engine.current_channel(time)
                || !fits_window(
                    Rate::DISCOVERY,
                    bytes.len(),
                    engine
                        .tx_window_us(frame.peer, time)
                        .saturating_sub(outstanding),
                )
            {
                self.management.push_back(frame);
                continue;
            }
            match inject(&bytes) {
                Ok(()) => {
                    self.reserved_until_us = self
                        .reserved_until_us
                        .max(time)
                        .saturating_add(airtime_us(Rate::DISCOVERY, bytes.len()).unwrap_or(0));
                    if accept {
                        engine.reorder.start(frame.peer, frame.request);
                        engine.stats.tx_addba_acceptances += 1;
                    } else {
                        engine.stats.tx_addba_rejections += 1;
                    }
                    report.last_sent_us = Some(time);
                    debug!(peer=%frame.peer, dialog_token=frame.request.dialog_token,
                        tid=(frame.request.parameters >> 2) & 15, accepted=accept, channel,
                        "ADDBA response submitted");
                }
                Err(InjectionError::Backpressure) => {
                    engine.stats.tx_backpressure += 1;
                    self.management.push_front(frame);
                    return Ok(report);
                }
                Err(InjectionError::TooLarge(error) | InjectionError::Fatal(error)) => {
                    return Err(error.into());
                }
            }
        }
        let mut examined = 0;
        let budget = self.len();
        let mut blocked = BTreeMap::new();
        let mut index = 0;
        while examined < budget {
            let Some(mut frame) = self.frames.remove(index) else {
                break;
            };
            let time = now();
            let old_len = frame.packets.len();
            examined += old_len;
            frame.packets.retain(|p| {
                let keep = time.saturating_sub(p.queued_us)
                    < engine.config.pending_timeout.as_micros() as i64;
                if !keep {
                    p.dropped(&mut engine.stats.tx_ack, time, "expired");
                }
                keep
            });
            let expired = old_len - frame.packets.len();
            engine.stats.dropped += expired as u64;
            if expired != 0 {
                frame.encoded = None;
            }
            if frame.packets.is_empty() {
                continue;
            }
            let dst = frame.destination();
            if !dst.multicast() && !engine.peers.get(&dst).is_some_and(|p| p.valid) {
                engine.stats.dropped += frame.packets.len() as u64;
                for p in &frame.packets {
                    p.dropped(&mut engine.stats.tx_ack, time, "unknown_peer");
                }
                continue;
            }
            let reason = blocked.get(&dst).copied().or_else(|| {
                (channel != engine.current_channel(time) || !engine.send_ready(dst, time))
                    .then_some(Block::Schedule)
            });
            if let Some(reason) = reason {
                frame.blocked(reason);
                blocked.insert(dst, reason);
                self.frames.insert(index, frame);
                index += 1;
                continue;
            }
            let parameters = engine.data_parameters(dst)?;
            let rate = parameters.rate;
            let limit = if self.aggregation {
                aggregate_limit(engine, dst, parameters, monitor_limit)
            } else {
                0
            };
            if frame.packets.len() > 1 && frame.body_len().is_none_or(|len| len > limit) {
                // A cached frame has never been accepted by the backend. Repack its
                // members when capabilities/rate no longer permit the aggregate.
                self.split(index, frame);
                continue;
            }
            let outstanding = self.reserved_until_us.saturating_sub(time).max(0);
            let window = engine.tx_window_us(dst, time).saturating_sub(outstanding);
            if frame.packets.len() == 1 && frame.encoded.is_none() && limit != 0 {
                let mut body_len = frame.body_len().unwrap_or(limit + 1);
                while frame.packets.len() < protocol::MAX_AMSDU_PACKETS {
                    let Some(next) = self.frames.get(index) else {
                        break;
                    };
                    if next.packets.len() != 1 || next.encoded.is_some() {
                        break;
                    }
                    let next_packet = &next.packets[0];
                    let Some(next_len) = protocol::amsdu_subframe_len(&next_packet.ethernet) else {
                        break;
                    };
                    let length = ((body_len + 3) & !3) + next_len;
                    if next_packet.ethernet[..12] != frame.packets[0].ethernet[..12]
                        || time.saturating_sub(next_packet.queued_us)
                            >= engine.config.pending_timeout.as_micros() as i64
                        || length > limit
                        || !fits_window(rate, length + 30, window)
                    {
                        break;
                    }
                    let next = self.frames.remove(index).expect("next frame");
                    frame.packets.extend(next.packets);
                    body_len = length;
                    examined += 1;
                }
            }
            let physical_len = if frame.packets.len() > 1 {
                frame.body_len().unwrap_or(usize::MAX).saturating_add(30)
            } else {
                frame.packets[0].ethernet.len() + 30
            };
            if !fits_window(rate, physical_len, window) {
                frame.blocked(Block::Airtime);
                blocked.insert(dst, Block::Airtime);
                self.frames.insert(index, frame);
                index += 1;
                continue;
            }
            let count = frame.packets.len();
            let bytes = match frame.encoded(engine, parameters) {
                Ok(bytes) => bytes,
                Err(_) => {
                    engine.stats.dropped += count as u64;
                    for p in &frame.packets {
                        p.dropped(&mut engine.stats.tx_ack, time, "encoding");
                    }
                    continue;
                }
            };
            let injection_started_us = now();
            let result = inject(bytes);
            let injection_finished_us = now();
            let injection = Injection {
                id: self.next_injection_id,
                channel,
                parameters,
                started_us: injection_started_us,
                finished_us: injection_finished_us,
            };
            self.next_injection_id = self.next_injection_id.wrapping_add(1);
            if result.is_ok() {
                engine.record_tx(bytes, parameters, injection_finished_us);
            }
            frame.record_injection(engine, injection, &result);
            match result {
                Ok(()) => {
                    self.reserved_until_us = self
                        .reserved_until_us
                        .max(time)
                        .saturating_add(airtime_us(rate, physical_len).unwrap_or(0));
                    report.last_sent_us = Some(time);
                    if frame.packets.iter().any(|p| p.tcp) {
                        report.last_tcp_us = Some(time);
                    }
                    engine.stats.tx_data += 1;
                    engine.stats.tx_packets += count as u64;
                    if dst.multicast() {
                        engine.stats.tx_multicast += 1;
                    } else {
                        engine.stats.tx_unicast += 1;
                    }
                    if count > 1 {
                        engine.stats.tx_amsdu += 1;
                        engine.stats.tx_aggregated_packets += count as u64;
                    }
                }
                Err(InjectionError::Backpressure) => {
                    engine.stats.tx_backpressure += 1;
                    self.frames.insert(index, frame);
                    break;
                }
                Err(InjectionError::TooLarge(error)) if count > 1 => {
                    warn!(%error, "driver rejected A-MSDU size; retrying queued packets individually");
                    self.aggregation = false;
                    engine.stats.tx_aggregation_rejected += 1;
                    self.split(index, frame);
                }
                Err(InjectionError::TooLarge(error) | InjectionError::Fatal(error)) => {
                    return Err(error.into());
                }
            }
        }
        Ok(report)
    }
}
fn airtime_us(rate: Rate, bytes: usize) -> Option<i64> {
    // Conservative preamble/ACK allowance. Hardware queue latency is driver-owned.
    rate.phy_mbps()
        .map(|mbps| ((bytes as f64 * 8.0 / f64::from(mbps)).ceil() as i64).saturating_add(256))
}
fn fits_window(rate: Rate, bytes: usize, window: i64) -> bool {
    airtime_us(rate, bytes).is_some_and(|airtime| airtime <= window)
}
fn receive_limit(caps: &BandCapabilities, rate: Rate) -> Option<usize> {
    let ht = caps.ht.as_ref()?;
    let amsdu = if ht.cap_info & 0x0800 != 0 {
        protocol::MAX_AMSDU
    } else {
        3839
    };
    match rate {
        Rate::Mcs { .. } => Some(amsdu),
        Rate::Vht { .. } => {
            let mpdu = match caps.vht.as_ref()?.cap_info & 3 {
                0 => 3895,
                1 => 7991,
                2 => 11454,
                _ => return None,
            };
            Some(amsdu.min(mpdu - 30)) // QoS header and hardware FCS.
        }
        _ => None,
    }
}
fn aggregate_limit(
    engine: &Engine,
    dst: Mac,
    parameters: TxParameters,
    monitor_limit: usize,
) -> usize {
    let rate = parameters.rate;
    if dst.multicast() {
        return 0;
    }
    let Some(peer) = engine.peers.get(&dst).filter(|p| p.valid) else {
        return 0;
    };
    let local = engine
        .config
        .capabilities
        .for_channel(engine.config.channel);
    let (Some(local), Some(remote)) = (
        receive_limit(local, rate),
        receive_limit(&peer.capabilities, rate),
    ) else {
        return 0;
    };
    let Ok(radiotap) = protocol::radiotap_tx(parameters, engine.config.tx_noack, false) else {
        return 0;
    };
    local
        .min(remote)
        .min(monitor_limit.saturating_sub(radiotap.len() + 26))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        channel::{ChannelDefinition, SLOT_US, Sequence, Strategy},
        engine::Config,
        protocol::{Advertisement, Body, Election, HtCapabilities},
        rate::FecPolicy,
        timeouts::Timeouts,
    };
    type TestError = pcap::Error;
    const OWN: Mac = Mac([2, 0, 0, 0, 0, 1]);
    const PEER: Mac = Mac([2, 0, 0, 0, 0, 2]);
    fn engine() -> Engine {
        let timeouts = Timeouts::default();
        let mut engine = Engine::new(
            Config {
                peer_timeout: timeouts.peer_idle,
                retry_timeout: timeouts.retry_cache,
                pending_timeout: timeouts.queued_packet,
                mac: OWN,
                name: "fixture".into(),
                airdrop_port: None,
                channel: 6,
                strategy: Strategy::Pin,
                fixed_radio: true,
                tx_noack: false,
                rx_ampdu: false,
                metric_first: true,
                election_metric: 60,
                election_counter: 0,
                widen: 4,
                filter_rssi: false,
                rate: "mcs7-sgi".parse().unwrap(),
                fec: FecPolicy::Bcc,
                tx_ldpc: true,
                capabilities: Default::default(),
                operating_channel: Some(ChannelDefinition::new(6, 20).unwrap()),
            },
            0,
        );
        engine.config.capabilities.ghz2.ht = Some(HtCapabilities {
            cap_info: 0x006f,
            ampdu_params: 3,
            rx_mask: [255, 255, 0, 0],
            tx_mask: Some([255, 255, 0, 0]),
        });
        add_peer(&mut engine, PEER);
        engine
    }
    fn add_peer(engine: &mut Engine, peer: Mac) {
        let frame = protocol::encode_action(
            &Advertisement {
                mac: peer,
                name: "fixture",
                capabilities: &engine.config.capabilities.ghz2,
                sequence: &Sequence::fixed(6),
                election: &Election::own(peer),
                channel: 6,
                master_channel: 6,
                next: 64,
                aw_counter: 0,
                now_us: 0,
            },
            3,
            0,
        );
        engine.receive(&frame, 0).unwrap();
    }
    fn packet(dst: Mac, marker: u8) -> Vec<u8> {
        let builder = etherparse::PacketBuilder::ethernet2(OWN.0, dst.0)
            .ipv6(OWN.ipv6().octets(), dst.ipv6().octets(), 64)
            .tcp(1234, 8771, u32::from(marker), 65535);
        let mut packet = Vec::new();
        builder.write(&mut packet, &vec![marker; 1390]).unwrap();
        packet
    }
    fn packets(frame: &[u8]) -> Vec<Vec<u8>> {
        let Body::Data(packets) = protocol::parse(frame).unwrap().unwrap().body else {
            panic!("data")
        };
        packets
    }
    fn flush(
        queue: &mut Queue,
        engine: &mut Engine,
        mtu: usize,
        time: i64,
        inject: impl FnMut(&[u8]) -> Result<(), InjectionError<TestError>>,
    ) -> Report {
        let channel = engine.current_channel(time);
        queue.flush(engine, channel, mtu, || time, inject).unwrap()
    }
    fn send(queue: &mut Queue, engine: &mut Engine, mtu: usize, time: i64) -> Vec<Vec<Vec<u8>>> {
        let mut sent = Vec::new();
        flush(queue, engine, mtu, time, |bytes| {
            sent.push(packets(bytes));
            Ok(())
        });
        sent
    }
    fn completion(bytes: &[u8], failed: bool, retries: u8) -> Vec<u8> {
        // Independent Linux TX-status layout: RATE, TX_FLAGS, DATA_RETRIES.
        let rt = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
        let mut out = vec![
            0,
            0,
            13,
            0,
            4,
            0x80,
            2,
            0,
            24,
            0,
            u8::from(failed),
            0,
            retries,
        ];
        out.extend_from_slice(&bytes[rt..]);
        out.extend([0; 7]); // USB DMA padding must not break correlation.
        out
    }
    #[test]
    fn unicast_delivery_feedback_is_correlated_and_never_enters_rx() {
        let mut engine = engine();
        engine.config.rate = Rate::Auto;
        let initial = engine.data_parameters(PEER).unwrap();
        let transmit = |engine: &mut Engine, now| {
            let parameters = engine.data_parameters(PEER).unwrap();
            let bytes = engine.data_frame(&[&packet(PEER, 1)], parameters).unwrap();
            engine.record_tx(&bytes, parameters, now);
            bytes
        };
        let mut queue = Queue::default();
        queue.push(packet(PEER, 1), 10_000);
        queue.push(packet(PEER, 2), 10_000);
        let mut encoded = Vec::new();
        flush(&mut queue, &mut engine, 8192, 10_000, |bytes| {
            // Channel pinning must not disable hardware acknowledgments, even in an aggregate.
            let flags = radiotap::Radiotap::from_bytes(bytes)
                .unwrap()
                .tx_flags
                .unwrap();
            assert!(!flags.no_ack && flags.no_seq);
            encoded.push(bytes.to_vec());
            Ok(())
        });
        assert!(engine.has_pending_tx(10_000));
        let report = completion(&encoded[0], false, 2);
        // mt76's missing-status cleanup can claim ACKed with no known rate.
        let mut synthetic = report.clone();
        synthetic.drain(8..10);
        synthetic[2] = 11;
        synthetic[4] = 0;
        engine.receive(&synthetic, 10_500).unwrap();
        assert_eq!(engine.stats.tx_status_acked, 0);
        assert!(engine.has_pending_tx(10_500));
        let before_rx = engine.stats.rx_data;
        let last_seen = engine.peers[&PEER].last_seen_us;
        let (frames, events) = engine.receive(&report, 11_000).unwrap();
        assert!(frames.is_empty() && events.is_empty());
        assert_eq!(engine.stats.rx_data, before_rx);
        assert_eq!(engine.peers[&PEER].last_seen_us, last_seen);
        assert_eq!(engine.stats.tx_status_acked, 1);
        assert_eq!(engine.stats.tx_status_retries, 2);
        assert!(!engine.has_pending_tx(11_000));
        engine.receive(&report, 12_000).unwrap(); // A duplicate is not a second success.
        assert_eq!(engine.stats.tx_status_acked, 1);
        let late = transmit(&mut engine, 13_000);
        for n in 0..4 {
            let bytes = transmit(&mut engine, 14_000 + n);
            let mut foreign = completion(&bytes, false, 0);
            let last_payload = foreign.len() - 8;
            foreign[last_payload] ^= 1;
            engine.receive(&foreign, 15_000 + n).unwrap();
            engine
                .receive(&completion(&bytes, true, 0), 16_000 + n)
                .unwrap();
        }
        let lower = engine.data_parameters(PEER).unwrap();
        assert!(lower.rate.phy_mbps().unwrap() <= initial.rate.phy_mbps().unwrap() * 0.85);
        engine
            .receive(&completion(&late, false, 0), 20_000)
            .unwrap();
        assert_eq!(engine.data_parameters(PEER).unwrap(), lower);
        for n in 0..16 {
            let bytes = transmit(&mut engine, 21_000 + n);
            engine
                .receive(&completion(&bytes, false, 3), 22_000 + n)
                .unwrap();
        }
        let heavily_retried = engine.data_parameters(PEER).unwrap();
        assert!(heavily_retried.rate.phy_mbps() < lower.rate.phy_mbps());
        for n in 0..128 {
            let bytes = transmit(&mut engine, 30_000 + n);
            engine
                .receive(&completion(&bytes, false, 0), 31_000 + n)
                .unwrap();
        }
        assert!(
            engine.data_parameters(PEER).unwrap().rate.phy_mbps() > heavily_retried.rate.phy_mbps()
        );
        // Fixed-rate commands still collect diagnostics but do not adapt.
        engine.config.rate = Rate::Legacy(12);
        for n in 0..4 {
            let bytes = transmit(&mut engine, 40_000 + n);
            engine
                .receive(&completion(&bytes, true, 0), 41_000 + n)
                .unwrap();
        }
        assert_eq!(engine.data_parameters(PEER).unwrap().rate, Rate::Legacy(12));
        // Reports outside the ledger's age bound cannot change selection or success totals.
        let expired = transmit(&mut engine, 50_000);
        let successes = engine.stats.tx_status_acked;
        engine
            .receive(&completion(&expired, false, 0), 3_000_000)
            .unwrap();
        assert_eq!(engine.stats.tx_status_acked, successes);
        engine.config.tx_noack = true;
        let bytes = transmit(&mut engine, 3_001_000);
        assert!(
            radiotap::Radiotap::from_bytes(&bytes)
                .unwrap()
                .tx_flags
                .unwrap()
                .no_ack
        );
    }
    #[test]
    fn addba_rejection_checks_wire_target_and_preserves_scheduled_retries() {
        let mut engine = engine();
        engine.config.tx_noack = true;
        let request = protocol::AddBaRequest {
            dialog_token: 7,
            parameters: 0x1017,
            timeout: 0,
            starting_sequence: 0,
        };
        let mut raw = protocol::radiotap_tx(Rate::DISCOVERY.into(), false, false).unwrap();
        raw.extend_from_slice(&[0xd0, 0, 0, 0]);
        raw.extend_from_slice(&OWN.0);
        raw.extend_from_slice(&PEER.0);
        raw.extend_from_slice(&protocol::BSSID.0);
        raw.extend_from_slice(&[0, 0, 3, 0, 7, 0x17, 0x10, 0, 0, 0, 0]);
        for n in 0..raw.len() {
            let _ = engine.receive(&raw[..n], 10_000);
        }
        assert_eq!(engine.stats.rx_addba_requests, 0);
        let (data, events) = engine.receive(&raw, 10_000).unwrap();
        assert!(data.is_empty());
        assert!(
            matches!(&events[..], [crate::engine::Event::AddBaRequest { peer: PEER, request: r }] if *r == request)
        );
        let mut foreign = raw.clone();
        let offset = u16::from_le_bytes([raw[2], raw[3]]) as usize;
        foreign[offset + 4..offset + 10].copy_from_slice(&protocol::BROADCAST.0);
        assert!(engine.receive(&foreign, 10_000).unwrap().1.is_empty());
        let mut queue = Queue::default();
        queue.respond_addba(&mut engine, PEER, request, 10_000);
        queue.respond_addba(&mut engine, PEER, request, 10_000);
        assert_eq!(queue.management.len(), 1);
        let mut submitted = Vec::new();
        queue
            .flush(
                &mut engine,
                6,
                8192,
                || 10_000,
                |bytes| {
                    submitted = bytes.to_vec();
                    Err::<(), _>(InjectionError::<TestError>::Backpressure)
                },
            )
            .unwrap();
        assert_eq!(engine.stats.tx_addba_rejections, 0);
        engine.config.channel = 149;
        queue
            .flush::<TestError>(&mut engine, 6, 8192, || 11_000, |_| panic!("wrong channel"))
            .unwrap();
        engine.config.channel = 6;
        queue
            .flush(
                &mut engine,
                6,
                8192,
                || 12_000,
                |bytes| {
                    assert_eq!(bytes, submitted);
                    Ok::<(), InjectionError<TestError>>(())
                },
            )
            .unwrap();
        let (radio, body) = radiotap::Radiotap::parse(&submitted).unwrap();
        assert!(radio.tx_flags.unwrap().no_ack);
        assert_eq!(&body[4..10], &PEER.0);
        assert_eq!(&body[10..16], &OWN.0);
        assert_eq!(&body[16..22], &protocol::BSSID.0);
        assert_eq!(&body[24..], &[3, 1, 7, 37, 0, 0x16, 0, 0, 0]);
        assert!(queue.is_empty());
        assert_eq!(engine.stats.tx_addba_rejections, 1);
        queue.respond_addba(&mut engine, PEER, request, 20_000);
        queue
            .flush(
                &mut engine,
                6,
                8192,
                || 3_000_000,
                |_| -> Result<(), InjectionError<TestError>> { panic!("expired reply") },
            )
            .unwrap();
        assert!(queue.is_empty());
        assert_eq!(engine.stats.tx_addba_rejections, 1);
    }
    #[test]
    fn addba_acceptance_reordering_bar_and_delba_lifecycle() {
        let mut engine = engine();
        engine.config.rx_ampdu = true;
        let mut queue = Queue::default();
        let request = protocol::AddBaRequest {
            dialog_token: 9,
            parameters: 2 | (4 << 6),
            timeout: 100,
            starting_sequence: 10 << 4,
        };
        queue.respond_addba(&mut engine, PEER, request, 10_000);
        queue
            .flush(
                &mut engine,
                6,
                8192,
                || 10_000,
                |_| Err::<(), _>(InjectionError::<TestError>::Backpressure),
            )
            .unwrap();
        assert!(!engine.reorder.contains(PEER, 0));
        queue
            .flush(
                &mut engine,
                6,
                8192,
                || 11_000,
                |bytes| {
                    let (_, body) = radiotap::Radiotap::parse(bytes).unwrap();
                    assert_eq!(&body[24..], &[3, 1, 9, 0, 0, 2, 1, 0, 0]);
                    Ok::<(), InjectionError<TestError>>(())
                },
            )
            .unwrap();
        assert!(engine.reorder.contains(PEER, 0));
        assert_eq!(engine.stats.tx_addba_acceptances, 1);
        let data = |seq| {
            let mut ethernet = packet(OWN, seq as u8);
            ethernet[6..12].copy_from_slice(&PEER.0);
            let mut bytes =
                protocol::encode_data(&ethernet, seq, 0, Rate::DISCOVERY.into(), false, false)
                    .unwrap();
            let offset = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
            bytes[offset] = 0x88;
            bytes.splice(offset + 24..offset + 24, [0, 0]); // QoS TID 0.
            bytes
        };
        assert!(engine.receive(&data(11), 12_000).unwrap().0.is_empty());
        assert!(engine.receive(&data(11), 12_001).unwrap().0.is_empty()); // No Retry bit required.
        assert_eq!(engine.receive(&data(10), 12_002).unwrap().0.len(), 2);
        assert!(engine.receive(&data(10), 12_003).unwrap().0.is_empty());
        assert!(engine.receive(&data(14), 12_004).unwrap().0.is_empty());
        let mut bar = vec![0, 0, 8, 0, 0, 0, 0, 0, 0x84, 0, 0, 0];
        bar.extend_from_slice(&OWN.0);
        bar.extend_from_slice(&PEER.0);
        bar.extend_from_slice(&[4, 0, 14 << 4, 0]);
        assert_eq!(bar.len(), 28); // Eight bytes radiotap + twenty bytes BAR.
        for n in 0..bar.len() {
            assert!(!matches!(protocol::parse(&bar[..n]), Ok(Some(_))));
        }
        let mut multi = bar.clone();
        multi[24] |= 2;
        assert!(protocol::parse(&multi).unwrap().is_none());
        let mut fcs = vec![0, 0, 9, 0, 2, 0, 0, 0, 0x10];
        fcs.extend_from_slice(&bar[8..]);
        fcs.extend_from_slice(&[0; 4]);
        assert!(matches!(
            protocol::parse(&fcs).unwrap().unwrap().body,
            Body::Bar { sequence: 14, .. }
        ));
        fcs[8] |= 0x40;
        assert!(protocol::parse(&fcs).unwrap().is_none());
        let mut foreign = bar.clone();
        foreign[12] ^= 2;
        assert!(engine.receive(&foreign, 12_005).unwrap().0.is_empty());
        assert_eq!(engine.receive(&bar, 12_006).unwrap().0.len(), 1);
        assert!(engine.receive(&data(16), 12_007).unwrap().0.is_empty());
        let mut delba = vec![0, 0, 8, 0, 0, 0, 0, 0, 0xd0, 0, 0, 0];
        delba.extend_from_slice(&OWN.0);
        delba.extend_from_slice(&PEER.0);
        delba.extend_from_slice(&protocol::BSSID.0);
        delba.extend_from_slice(&[0, 0, 3, 2, 0, 0, 1, 0]);
        assert!(engine.receive(&delba, 12_008).unwrap().1.is_empty()); // Recipient DELBA is for TX.
        assert!(engine.reorder.contains(PEER, 0));
        queue.respond_addba(&mut engine, PEER, request, 12_009);
        delba[35] = 8; // Sender/originator DELBA for our RX agreement.
        let (frames, events) = engine.receive(&delba, 12_010).unwrap();
        assert_eq!(frames.len(), 1);
        let [crate::engine::Event::DelBa { peer, tid }] = events.as_slice() else {
            panic!("DELBA event");
        };
        queue.cancel_ba(*peer, Some(*tid));
        assert!(queue.is_empty());
        assert!(!engine.reorder.contains(PEER, 0));
        assert_eq!(engine.reorder.stats.duplicate_mpdus, 1);
        assert_eq!(engine.reorder.stats.old_mpdus, 1);
        // Renegotiation releases the old window before newly received data,
        // even if capture wins the select before the scheduler polls.
        engine.reorder.start(PEER, request);
        assert!(engine.receive(&data(11), 13_000).unwrap().0.is_empty());
        let replacement = protocol::AddBaRequest {
            dialog_token: 10,
            starting_sequence: 20 << 4,
            ..request
        };
        engine.reorder.start(PEER, replacement);
        let frames = engine.receive(&data(20), 13_001).unwrap().0;
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].last(), Some(&11));
        assert_eq!(frames[1].last(), Some(&20));
    }
    #[test]
    fn ack_timing_keeps_identity_and_counts_members_once_across_retries() {
        use std::cell::Cell;
        let ack_packet = |marker, payload: &[u8]| {
            let mut packet = Vec::new();
            etherparse::PacketBuilder::ethernet2(OWN.0, PEER.0)
                .ipv6(OWN.ipv6().octets(), PEER.ipv6().octets(), 64)
                .tcp(1234, 8771, marker, 65535)
                .ack(5000)
                .write(&mut packet, payload)
                .unwrap();
            packet
        };
        assert!(tcp_metadata(&ack_packet(1, b"data")).1.is_none());
        let mut fin = ack_packet(1, &[]);
        fin[14 + 40 + 13] |= 1;
        assert!(tcp_metadata(&fin).1.is_none());
        let mut engine = engine();
        let mut queue = Queue::default();
        queue.push(ack_packet(1, &[]), 0);
        queue.push(ack_packet(2, &[]), 500);
        assert_eq!(queue.pending_acks(), 2);
        engine.peers.get_mut(&PEER).unwrap().sequence = Some(Sequence::fixed(149));
        flush(&mut queue, &mut engine, 8192, 1_000, |_| {
            panic!("off channel")
        });
        assert_eq!(engine.stats.tx_ack.injection_attempts, 0);
        engine.peers.get_mut(&PEER).unwrap().sequence = Some(Sequence::fixed(6));
        flush(&mut queue, &mut engine, 8192, 10_000, |_| {
            Err(InjectionError::Backpressure)
        });
        assert_eq!(
            queue.frames[0]
                .packets
                .iter()
                .map(|p| p.ack.as_ref().unwrap().id)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(engine.stats.tx_ack.injected, 0);
        let clock = Cell::new(25_000);
        queue
            .flush(
                &mut engine,
                6,
                8192,
                || clock.get(),
                |_| {
                    clock.set(clock.get() + 37);
                    Ok::<(), InjectionError<TestError>>(())
                },
            )
            .unwrap();
        assert_eq!(queue.pending_acks(), 0);
        let timing = &engine.stats.tx_ack;
        assert_eq!((timing.injected, timing.injection_attempts), (2, 2));
        assert_eq!(
            (timing.queue_wait_us_total, timing.queue_wait_us_max),
            (49_500, 25_000)
        );
        assert_eq!(
            (timing.injection_us_total, timing.injection_us_max),
            (37, 37)
        );
        assert_eq!((timing.schedule_blocked, timing.backpressured), (2, 2));
        assert_eq!(
            (engine.stats.tx_amsdu, engine.stats.tx_aggregated_packets),
            (1, 2)
        );

        queue.push(ack_packet(3, &[]), 150_000);
        flush(&mut queue, &mut engine, 8192, 2_150_000, |_| {
            panic!("expired")
        });
        assert_eq!(engine.stats.tx_ack.dropped, 1);
        assert_eq!(engine.stats.tx_ack.injected, 2);
    }
    #[test]
    fn aggregation_retries_recheck_slots_and_preserve_sequences_on_rate_changes() {
        let mut engine = engine();
        let mut queue = Queue::default();
        let first = packet(PEER, 1);
        let second = packet(PEER, 2);
        queue.push(first.clone(), 0);
        queue.push(second.clone(), 0);
        let mut original = Vec::new();
        flush(&mut queue, &mut engine, 8192, 10_000, |bytes| {
            original = bytes.to_vec();
            Err(InjectionError::Backpressure)
        });
        assert_eq!(queue.len(), 2);
        assert_eq!(engine.stats.tx_data, 0);
        assert_eq!(packets(&original), [first.clone(), second.clone()]);
        engine.config.fec = FecPolicy::Ldpc;
        flush(&mut queue, &mut engine, 8192, 10_000, |bytes| {
            let (rt, body) = radiotap::Radiotap::parse(bytes).unwrap();
            assert_eq!(body, radiotap::Radiotap::parse(&original).unwrap().1);
            assert_eq!(rt.mcs.unwrap().index, Some(7));
            assert_eq!(rt.mcs.unwrap().fec, Some(radiotap::field::ext::FEC::LDPC));
            Err(InjectionError::Backpressure)
        });
        engine
            .peers
            .get_mut(&PEER)
            .unwrap()
            .sequence
            .as_mut()
            .unwrap()
            .slots[1] = [149, 124];
        flush(&mut queue, &mut engine, 8192, SLOT_US + 10_000, |_| {
            panic!("peer is off channel")
        });
        assert_eq!(queue.len(), 2);
        engine.config.rate = "mcs3".parse().unwrap();
        let time = 2 * SLOT_US + 10_000;
        let report = flush(&mut queue, &mut engine, 8192, time, |bytes| {
            assert_eq!(
                radiotap::Radiotap::parse(bytes).unwrap().1,
                radiotap::Radiotap::parse(&original).unwrap().1
            );
            assert_ne!(bytes, original);
            Ok(())
        });
        assert!(queue.is_empty());
        assert!(queue.has_pending_airtime(time));
        assert!(!queue.is_idle(time, 0));
        assert!(!queue.is_idle(time + 100_000, 100_000));
        assert!(queue.is_idle(time + 200_000, 100_000));
        assert_eq!(report.last_tcp_us, Some(time));
        assert_eq!(
            (
                engine.stats.tx_data,
                engine.stats.tx_packets,
                engine.stats.tx_amsdu,
                engine.stats.tx_aggregated_packets
            ),
            (1, 2, 1, 2)
        );
        assert_eq!(engine.stats.tx_backpressure, 2);
        // Do not inject a long aggregate near the end of a matching window.
        engine.config.rate = "mcs0".parse().unwrap();
        queue.push(first, 0);
        queue.push(second.clone(), 0);
        let mut counts = Vec::new();
        flush(
            &mut queue,
            &mut engine,
            8192,
            17 * SLOT_US - 6_000,
            |bytes| {
                counts.push(packets(bytes).len());
                Ok(())
            },
        );
        assert_eq!(counts, [1]);
        assert_eq!(queue.len(), 1);
        // A rotated peer can leave before our own slot boundary.
        engine.config.strategy = Strategy::Rotate;
        engine.peers.get_mut(&PEER).unwrap().sync_offset_us = Some(5_000);
        assert_eq!(
            engine.tx_window_us(PEER, SLOT_US - 10_000),
            5_000 - 3 * 1024
        );
        // Rotating multicast cannot reserve airtime beyond its discovery guard.
        engine.config.fixed_radio = false;
        assert_eq!(
            engine.tx_window_us(protocol::BROADCAST, SLOT_US - 20_000),
            20_000 - 16 * 1024
        );
    }
    #[test]
    fn aggregation_respects_bounds_fifo_expiry_and_backend_fallback() {
        let mut engine = engine();
        let mut queue = Queue::default();
        let first = packet(PEER, 1);
        let second = packet(PEER, 2);
        let third = packet(PEER, 3);
        queue.push(first.clone(), 0);
        queue.push(second.clone(), 0);
        queue.push(third.clone(), 0);
        let sent = send(&mut queue, &mut engine, 8192, 10_000);
        assert_eq!(
            sent,
            [vec![first.clone(), second.clone()], vec![third.clone()]]
        ); // 3839-byte peer limit.
        let mut queue = Queue::default();
        queue.push(first.clone(), 0);
        queue.push(second.clone(), 0);
        let sent = send(&mut queue, &mut engine, 2048, 10_000);
        assert_eq!(sent, [vec![first.clone()], vec![second.clone()]]);
        // Rejecting an aggregate must not lose packets or alter their FIFO order.
        let mut queue = Queue::default();
        queue.push(first.clone(), 0);
        queue.push(second.clone(), 0);
        flush(&mut queue, &mut engine, 8192, 10_000, |_| {
            Err(InjectionError::TooLarge(TestError::PcapError(
                "size".into(),
            )))
        });
        assert_eq!(queue.len(), 2);
        let sent = send(&mut queue, &mut engine, 8192, 10_000);
        assert_eq!(sent, [vec![first.clone()], vec![second.clone()]]);
        assert_eq!(engine.stats.tx_aggregation_rejected, 1);
        // A capability change can also require repacking an unsent aggregate.
        let mut queue = Queue::default();
        queue.push(first.clone(), 0);
        queue.push(second.clone(), 0);
        flush(&mut queue, &mut engine, 8192, 10_000, |_| {
            Err(InjectionError::Backpressure)
        });
        engine.config.rate = Rate::Legacy(12);
        flush(&mut queue, &mut engine, 8192, 10_000, |_| {
            panic!("repacking")
        });
        let sent = send(&mut queue, &mut engine, 8192, 10_000);
        assert_eq!(sent, [vec![first.clone()], vec![second.clone()]]);
        engine.config.rate = "mcs7-sgi".parse().unwrap();
        // Only expired members are discarded from a cached aggregate.
        let mut queue = Queue::default();
        queue.push(first.clone(), 0);
        queue.push(second.clone(), 1_500_000);
        flush(&mut queue, &mut engine, 8192, 1_600_000, |_| {
            Err(InjectionError::Backpressure)
        });
        let dropped = engine.stats.dropped;
        let sent = send(&mut queue, &mut engine, 8192, 2_010_000);
        assert_eq!(sent, [vec![second.clone()]]);
        assert_eq!(engine.stats.dropped, dropped + 1);
        // Different peers stay separate; an off-channel peer cannot block another.
        let other = Mac([2, 0, 0, 0, 0, 3]);
        add_peer(&mut engine, other);
        engine.peers.get_mut(&PEER).unwrap().sequence = Some(Sequence::fixed(149));
        let mut queue = Queue::default();
        queue.push(first.clone(), 0);
        queue.push(packet(other, 4), 0);
        queue.push(second.clone(), 0);
        let sent = send(&mut queue, &mut engine, 8192, 10_000);
        assert_eq!(sent, [vec![packet(other, 4)]]);
        assert_eq!(queue.len(), 2);
        // A later peer's backpressure cannot move older deferred packets behind newer ones.
        let mut queue = Queue::default();
        queue.push(first.clone(), 0);
        queue.push(packet(other, 4), 0);
        queue.push(second.clone(), 0);
        flush(&mut queue, &mut engine, 8192, 10_000, |_| {
            Err(InjectionError::Backpressure)
        });
        engine.peers.get_mut(&PEER).unwrap().sequence = Some(Sequence::fixed(6));
        let sent = send(&mut queue, &mut engine, 8192, 10_000);
        assert_eq!(sent, [vec![first], vec![packet(other, 4)], vec![second]]);
        let mut engine = self::engine();
        let channel = ChannelDefinition::new(149, 80).unwrap();
        engine.set_operating_channel(channel);
        engine.config.capabilities.ghz5 = engine.config.capabilities.ghz2.clone();
        engine.config.capabilities.ghz5.vht = Some(protocol::VhtCapabilities {
            cap_info: 1 | (1 << 4) | (1 << 5),
            rx_mcs_map: 0xfffa,
            tx_mcs_map: 0xfffa,
            rx_highest: 0,
            tx_highest: 0,
        });
        engine.peers.get_mut(&PEER).unwrap().capabilities = engine.config.capabilities.ghz5.clone();
        engine.peers.get_mut(&PEER).unwrap().sequence = Some(Sequence::fixed_definition(channel));
        engine.config.rate = "vht8-nss2-bw80-sgi".parse().unwrap();
        let bcc = engine.data_parameters(PEER).unwrap();
        let mut queue = Queue::default();
        queue.push(packet(PEER, 1), 0);
        queue.push(packet(PEER, 2), 0);
        let mut original = Vec::new();
        flush(&mut queue, &mut engine, 8192, 10_000, |bytes| {
            original = bytes.to_vec();
            Err(InjectionError::Backpressure)
        });
        engine.config.fec = FecPolicy::Ldpc;
        let ldpc = engine.data_parameters(PEER).unwrap();
        flush(&mut queue, &mut engine, 8192, 10_000, |bytes| {
            assert_eq!(bytes.len(), original.len() + 4);
            assert_eq!(
                radiotap::Radiotap::parse(bytes).unwrap().1,
                radiotap::Radiotap::parse(&original).unwrap().1
            );
            Err(InjectionError::Backpressure)
        });
        assert_eq!(
            aggregate_limit(&engine, PEER, bcc, 2048) - aggregate_limit(&engine, PEER, ldpc, 2048),
            4
        );
        // Repack a cached aggregate after the available monitor MTU shrinks.
        flush(&mut queue, &mut engine, 2048, 10_000, |_| {
            panic!("repacking")
        });
        flush(&mut queue, &mut engine, 2048, 10_000, |bytes| {
            assert!(bytes.len() <= 2048);
            assert_eq!(packets(bytes).len(), 1);
            Ok(())
        });
        assert!(queue.is_empty());
        engine
            .peers
            .get_mut(&PEER)
            .unwrap()
            .capabilities
            .vht
            .as_mut()
            .unwrap()
            .cap_info &= !(1 << 4);
        queue.push(packet(PEER, 3), 0);
        let error = queue
            .flush(
                &mut engine,
                149,
                8192,
                || 10_000,
                |_| -> Result<(), InjectionError<TestError>> {
                    panic!("unsupported peer must not be injected")
                },
            )
            .err()
            .expect("unsupported peer");
        assert!(error.to_string().contains("peer RX LDPC"));
        engine.config.fec = FecPolicy::Bcc;
        queue.push(packet(PEER, 4), 0);
        let error = queue
            .flush(
                &mut engine,
                149,
                8192,
                || 20_000,
                |_| {
                    Err(InjectionError::Fatal(TestError::PcapError(
                        "backend failure".into(),
                    )))
                },
            )
            .err()
            .expect("backend failure");
        assert!(error.downcast_ref::<TestError>().is_some());
    }
}
