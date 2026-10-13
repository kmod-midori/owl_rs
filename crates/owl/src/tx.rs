// SPDX-License-Identifier: GPL-3.0-or-later
//! AWDL link TX queue: opportunistic A-MSDU batching and atomic injection retries.
use crate::{
    engine::Engine,
    protocol::{self, BandCapabilities, Mac},
    rate::Rate,
};
use std::collections::{BTreeSet, VecDeque};
use tracing::warn;

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
struct Packet {
    ethernet: Vec<u8>,
    queued_us: i64,
}
struct Frame {
    packets: Vec<Packet>,
    encoded: Option<(Rate, Vec<u8>)>,
}
impl Frame {
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
    fn encoded(&mut self, engine: &mut Engine, rate: Rate) -> Result<&[u8], protocol::Error> {
        let destination = self.destination();
        if let Some((previous, bytes)) = &mut self.encoded {
            if *previous != rate {
                let old_len = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
                bytes.splice(
                    ..old_len,
                    protocol::radiotap_tx(
                        rate,
                        engine.config.fixed_radio && !destination.multicast(),
                        false,
                    )?,
                );
                *previous = rate;
            }
        } else {
            let packets: Vec<_> = self.packets.iter().map(|p| p.ethernet.as_slice()).collect();
            self.encoded = Some((rate, engine.data_frame(&packets, rate)?));
        }
        Ok(&self.encoded.as_ref().expect("encoded frame").1)
    }
}
pub(crate) struct Queue {
    frames: VecDeque<Frame>,
    aggregation: bool,
    reserved_until_us: i64,
}
impl Default for Queue {
    fn default() -> Self {
        Self {
            frames: VecDeque::new(),
            aggregation: true,
            reserved_until_us: 0,
        }
    }
}
impl Queue {
    pub fn len(&self) -> usize {
        self.frames.iter().map(|f| f.packets.len()).sum()
    }
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
    pub fn is_idle(&self, now: i64, quiet_us: i64) -> bool {
        self.is_empty() && now.saturating_sub(self.reserved_until_us) >= quiet_us
    }
    pub fn has_pending_airtime(&self, now: i64) -> bool {
        self.reserved_until_us > now
    }
    pub fn has_tcp(&self) -> bool {
        self.frames
            .iter()
            .flat_map(|f| &f.packets)
            .any(|p| protocol::tcp_frame(&p.ethernet))
    }
    pub fn push(&mut self, ethernet: Vec<u8>, queued_us: i64) {
        assert!(
            ethernet.len() >= 14 && self.len() < QUEUE_LIMIT,
            "checked bounded Ethernet queue"
        );
        self.frames.push_back(Frame::single(Packet {
            ethernet,
            queued_us,
        }));
    }
    fn split(&mut self, index: usize, frame: Frame) {
        for packet in frame.packets.into_iter().rev() {
            self.frames.insert(index, Frame::single(packet));
        }
    }
    pub fn flush<E: std::fmt::Display>(
        &mut self,
        engine: &mut Engine,
        channel: u8,
        monitor_limit: usize,
        mut now: impl FnMut() -> i64,
        mut inject: impl FnMut(&[u8]) -> Result<(), InjectionError<E>>,
    ) -> Result<Report, E> {
        let mut report = Report::default();
        let mut examined = 0;
        let budget = self.len();
        let mut blocked = BTreeSet::new();
        let mut index = 0;
        while examined < budget {
            let Some(mut frame) = self.frames.remove(index) else {
                break;
            };
            let time = now();
            let old_len = frame.packets.len();
            examined += old_len;
            frame.packets.retain(|p| {
                time.saturating_sub(p.queued_us) < engine.config.pending_timeout.as_micros() as i64
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
                continue;
            }
            if blocked.contains(&dst)
                || channel != engine.current_channel(time)
                || !engine.send_ready(dst, time)
            {
                blocked.insert(dst);
                self.frames.insert(index, frame);
                index += 1;
                continue;
            }
            let rate = engine.data_rate(dst);
            let limit = if self.aggregation {
                aggregate_limit(engine, dst, rate, monitor_limit)
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
                blocked.insert(dst);
                self.frames.insert(index, frame);
                index += 1;
                continue;
            }
            let count = frame.packets.len();
            let bytes = match frame.encoded(engine, rate) {
                Ok(bytes) => bytes,
                Err(_) => {
                    engine.stats.dropped += count as u64;
                    continue;
                }
            };
            match inject(bytes) {
                Ok(()) => {
                    self.reserved_until_us = self
                        .reserved_until_us
                        .max(time)
                        .saturating_add(airtime_us(rate, physical_len).unwrap_or(0));
                    report.last_sent_us = Some(time);
                    if frame
                        .packets
                        .iter()
                        .any(|p| protocol::tcp_frame(&p.ethernet))
                    {
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
                    return Err(error);
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
fn aggregate_limit(engine: &Engine, dst: Mac, rate: Rate, monitor_limit: usize) -> usize {
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
    let Ok(radiotap) = protocol::radiotap_tx(rate, engine.config.fixed_radio, false) else {
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
        timeouts::Timeouts,
    };
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
                metric_first: true,
                election_metric: 60,
                election_counter: 0,
                widen: 4,
                filter_rssi: false,
                rate: "mcs7-sgi".parse().unwrap(),
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
        inject: impl FnMut(&[u8]) -> Result<(), InjectionError<&'static str>>,
    ) -> Report {
        queue.flush(engine, 6, mtu, || time, inject).unwrap()
    }
    fn send(queue: &mut Queue, engine: &mut Engine, mtu: usize, time: i64) -> Vec<Vec<Vec<u8>>> {
        let mut sent = Vec::new();
        flush(queue, engine, mtu, time, |bytes| {
            sent.push(packets(bytes));
            Ok(())
        });
        sent
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
        assert_eq!(engine.stats.tx_backpressure, 1);
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
            Err(InjectionError::TooLarge("size"))
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
    }
}
