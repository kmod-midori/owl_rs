// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{
    channel::{Clock, SLOT_US, SLOTS, Sequence, Strategy},
    protocol::{self, Action, Advertisement, Body, Election, Error, Frame, Mac},
    rate::{FecPolicy, Rate, TxParameters},
};
use serde::Serialize;
use std::collections::{BTreeMap, VecDeque};
use tracing::{debug, info};

const MAX_PEERS: usize = 512;
const MAX_PENDING_SYNS: usize = 128;
struct PendingSyn {
    source: Mac,
    key: (u16, u16, u32),
    ethernet: Vec<u8>,
    sequence: u16,
    queued_us: i64,
}
fn syn_key(ethernet: &[u8], source: Mac, local: Mac) -> Option<(u16, u16, u32)> {
    if ethernet.get(..6)? != local.0 || ethernet.get(6..12)? != source.0 {
        return None;
    }
    let packet = etherparse::SlicedPacket::from_ethernet(ethernet).ok()?;
    let Some(etherparse::NetSlice::Ipv6(ip)) = packet.net else {
        return None;
    };
    if ip.header().source_addr() != source.ipv6() || ip.header().destination_addr() != local.ipv6()
    {
        return None;
    }
    let Some(etherparse::TransportSlice::Tcp(tcp)) = packet.transport else {
        return None;
    };
    (tcp.syn() && !tcp.fin() && !tcp.rst() && tcp.payload().is_empty()).then(|| {
        (
            tcp.source_port(),
            tcp.destination_port(),
            tcp.sequence_number(),
        )
    })
}
#[derive(Clone, Debug, Serialize)]
pub struct Peer {
    pub mac: Mac,
    pub name: String,
    pub version: u8,
    pub devclass: u8,
    pub election: Election,
    pub sequence: Option<Sequence>,
    pub last_seen_us: i64,
    pub valid: bool,
    pub sync_offset_us: Option<i64>,
    pub rssi: Option<i8>,
    pub capabilities: protocol::BandCapabilities,
    pub tx_parameters: Option<TxParameters>,
    #[serde(skip)]
    rate_control: crate::rate::AutoRate,
    #[serde(skip)]
    mif: bool,
    #[serde(skip)]
    v2: bool,
    #[serde(skip)]
    recent: VecDeque<(u16, i64)>,
}
impl Peer {
    fn new(mac: Mac, now: i64) -> Self {
        Self {
            mac,
            name: String::new(),
            version: 0,
            devclass: 0,
            election: Election::own(mac),
            sequence: None,
            last_seen_us: now,
            valid: false,
            sync_offset_us: None,
            rssi: None,
            capabilities: protocol::BandCapabilities::default(),
            tx_parameters: None,
            rate_control: Default::default(),
            mif: false,
            v2: false,
            recent: VecDeque::new(),
        }
    }
}
#[derive(Clone, Debug)]
pub struct Config {
    pub peer_timeout: std::time::Duration,
    pub retry_timeout: std::time::Duration,
    pub pending_timeout: std::time::Duration,
    pub mac: Mac,
    pub name: String,
    pub airdrop_port: Option<u16>,
    pub channel: u8,
    pub strategy: Strategy,
    pub fixed_radio: bool,
    pub tx_noack: bool,
    pub metric_first: bool,
    pub election_metric: u32,
    pub election_counter: u32,
    pub widen: usize,
    pub filter_rssi: bool,
    pub rate: Rate,
    pub fec: FecPolicy,
    /// TX encoder support supplied by the radio backend, not RX advertisements.
    pub tx_ldpc: bool,
    pub capabilities: protocol::RadioCapabilities,
    pub operating_channel: Option<crate::channel::ChannelDefinition>,
}
impl Config {
    fn fixed_sequence(&self, channel: u8) -> Sequence {
        self.operating_channel
            .filter(|d| d.channel == channel)
            .map(Sequence::fixed_definition)
            .unwrap_or_else(|| Sequence::fixed(channel))
    }
}
/// Link-local diagnostics for payload-free TCP ACKs, independent of AirDrop.
#[derive(Clone, Debug, Default, Serialize)]
pub struct AckTiming {
    pub injected: u64,
    pub dropped: u64,
    pub schedule_blocked: u64,
    pub airtime_blocked: u64,
    pub backpressured: u64,
    pub queue_wait_us_total: u64,
    pub queue_wait_us_max: u64,
    pub injection_attempts: u64,
    pub injection_us_total: u64,
    pub injection_us_max: u64,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct Stats {
    pub captured: u64,
    pub rx_action: u64,
    pub rx_addba_requests: u64,
    pub tx_addba_rejections: u64,
    pub rx_data: u64,
    pub rx_unknown: u64,
    pub rx_ignored: u64,
    pub rx_duplicates: u64,
    pub rx_syn_buffered: u64,
    pub rx_syn_released: u64,
    pub rx_syn_expired: u64,
    pub tx_action: u64,
    pub tx_data: u64,
    pub tx_backpressure: u64,
    pub tx_unicast: u64,
    pub tx_packets: u64,
    pub tx_status_acked: u64,
    pub tx_status_failed: u64,
    pub tx_status_retries: u64,
    pub tx_status_ignored: u64,
    pub tx_ack: AckTiming,
    pub tx_amsdu: u64,
    pub tx_aggregated_packets: u64,
    pub tx_aggregation_rejected: u64,
    pub tx_multicast: u64,
    pub dropped: u64,
    pub peers_discovered: u64,
}
#[derive(Clone, Debug)]
pub enum Event {
    Added(Mac),
    Removed(Mac),
    AddBaRequest {
        peer: Mac,
        request: protocol::AddBaRequest,
    },
}
#[derive(Debug, Serialize)]
pub struct Summary<'a> {
    pub stats: &'a Stats,
    pub peers: Vec<&'a Peer>,
    pub election: &'a Election,
    pub sequence: &'a Sequence,
    pub frequencies_mhz: &'a BTreeMap<u16, u64>,
}
struct PendingTx {
    destination: Mac,
    sequence: u16,
    fingerprint: u32,
    rate: Rate,
    channel: Option<crate::channel::ChannelDefinition>,
    sent_us: i64,
    generation: u64,
}
pub struct Engine {
    pub config: Config,
    pub clock: Clock,
    pub election: Election,
    pub sequence: Sequence,
    pub peers: BTreeMap<Mac, Peer>,
    pub stats: Stats,
    pub frequencies: BTreeMap<u16, u64>,
    ieee_sequence: u16,
    data_sequence: u16,
    rotation: Option<usize>,
    pending_rotation: Option<usize>,
    source: Option<Mac>,
    pending_syns: VecDeque<PendingSyn>,
    pending_tx: VecDeque<PendingTx>,
}
impl Engine {
    pub fn new(config: Config, now: i64) -> Self {
        let mut election = Election::own(config.mac);
        election.metric = config.election_metric;
        election.self_metric = config.election_metric;
        election.counter = config.election_counter;
        election.self_counter = config.election_counter;
        Self {
            clock: Clock::new(now),
            election,
            sequence: config.fixed_sequence(config.channel),
            config,
            peers: BTreeMap::new(),
            stats: Stats::default(),
            frequencies: BTreeMap::new(),
            ieee_sequence: 0,
            data_sequence: 0,
            rotation: None,
            pending_rotation: None,
            source: None,
            pending_syns: VecDeque::new(),
            pending_tx: VecDeque::new(),
        }
    }
    pub fn summary(&self) -> Summary<'_> {
        Summary {
            stats: &self.stats,
            peers: self.peers.values().filter(|p| p.valid).collect(),
            election: &self.election,
            sequence: &self.sequence,
            frequencies_mhz: &self.frequencies,
        }
    }
    pub fn receive(&mut self, bytes: &[u8], now: i64) -> Result<(Vec<Vec<u8>>, Vec<Event>), Error> {
        self.stats.captured += 1;
        self.expire_syns(now);
        let frame = match protocol::parse(bytes) {
            Ok(Some(f)) => f,
            Ok(None) => {
                self.stats.rx_ignored += 1;
                return Ok((vec![], vec![]));
            }
            Err(e) => {
                self.stats.rx_unknown += 1;
                return Err(e);
            }
        };
        if let Body::TxStatus(status) = &frame.body {
            self.tx_status(&frame, status, now);
            return Ok((vec![], vec![]));
        }
        if let Some(freq) = frame.frequency {
            *self.frequencies.entry(freq).or_default() += 1;
        }
        if frame.source == self.config.mac || !frame.source.valid_unicast() {
            self.stats.rx_ignored += 1;
            return Ok((vec![], vec![]));
        }
        match &frame.body {
            Body::TxStatus(_) => unreachable!("handled before RX"),
            Body::AddBaRequest(request) => {
                if frame.destination != self.config.mac
                    || !self.peers.get(&frame.source).is_some_and(|p| p.valid)
                {
                    self.stats.rx_ignored += 1;
                    return Ok((vec![], vec![]));
                }
                self.stats.rx_addba_requests += 1;
                Ok((
                    vec![],
                    vec![Event::AddBaRequest {
                        peer: frame.source,
                        request: *request,
                    }],
                ))
            }
            Body::Action(a) => {
                let events = self.action(&frame, a, now)?;
                let frames = if events
                    .iter()
                    .any(|e| matches!(e, Event::Added(mac) if *mac == frame.source))
                {
                    self.release_syns(frame.source, now)
                } else {
                    vec![]
                };
                Ok((frames, events))
            }
            Body::Data(frames) => {
                let Some(peer) = self.peers.get_mut(&frame.source).filter(|p| p.valid) else {
                    // A phone may send its TCP handshake just before its MIF.
                    // Cache only bare SYNs addressed to us; data cannot promote a peer.
                    let mut buffered = false;
                    for ethernet in frames {
                        if let Some(key) = syn_key(ethernet, frame.source, self.config.mac) {
                            buffered = true;
                            if self
                                .pending_syns
                                .iter()
                                .any(|p| p.source == frame.source && p.key == key)
                            {
                                continue;
                            }
                            if self.pending_syns.len() == MAX_PENDING_SYNS {
                                self.pending_syns.pop_front();
                                self.stats.dropped += 1;
                            }
                            self.pending_syns.push_back(PendingSyn {
                                source: frame.source,
                                key,
                                ethernet: ethernet.clone(),
                                sequence: frame.sequence,
                                queued_us: now,
                            });
                            self.stats.rx_syn_buffered += 1;
                        }
                    }
                    if !buffered {
                        self.stats.rx_ignored += 1;
                    }
                    return Ok((vec![], vec![]));
                };
                // Fully parsed data, including retries, proves a known peer is alive.
                // Busy phones may skip action frames while uploading.
                peer.last_seen_us = now;
                peer.recent
                    .retain(|&(_, time)| now - time < self.config.retry_timeout.as_micros() as i64);
                if frame.retry && peer.recent.iter().any(|&(seq, _)| seq == frame.sequence) {
                    self.stats.rx_duplicates += 1;
                    return Ok((vec![], vec![]));
                }
                if peer.recent.len() >= 128 {
                    peer.recent.pop_front();
                }
                peer.recent.push_back((frame.sequence, now));
                self.stats.rx_data += 1;
                // Monitor capture is promiscuous; never inject another node's unicast into TAP.
                let mut out = Vec::new();
                for ethernet in frames {
                    let dst = Mac(ethernet[..6].try_into().map_err(|_| Error::Truncated)?);
                    let src = Mac(ethernet[6..12].try_into().map_err(|_| Error::Truncated)?);
                    if (dst.multicast() || dst == self.config.mac)
                        && self.peers.get(&src).is_some_and(|p| p.valid)
                    {
                        out.push(ethernet.clone());
                    }
                }
                Ok((out, vec![]))
            }
        }
    }
    fn expire_syns(&mut self, now: i64) {
        let before = self.pending_syns.len();
        let timeout = self.config.pending_timeout.as_micros() as i64;
        self.pending_syns
            .retain(|p| now.saturating_sub(p.queued_us) < timeout);
        self.stats.rx_syn_expired += (before - self.pending_syns.len()) as u64;
    }
    fn release_syns(&mut self, source: Mac, now: i64) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        for _ in 0..self.pending_syns.len() {
            let packet = self.pending_syns.pop_front().expect("pending SYN count");
            if packet.source != source {
                self.pending_syns.push_back(packet);
                continue;
            }
            let peer = self.peers.get_mut(&source).expect("validated peer");
            if peer.recent.len() == 128 {
                peer.recent.pop_front();
            }
            peer.recent.push_back((packet.sequence, now));
            frames.push(packet.ethernet);
        }
        self.stats.rx_data += frames.len() as u64;
        self.stats.rx_syn_released += frames.len() as u64;
        frames
    }
    fn action(&mut self, f: &Frame, a: &Action, now: i64) -> Result<Vec<Event>, Error> {
        let old = self.peers.get(&f.source);
        if self.config.filter_rssi
            && f.rssi
                .is_some_and(|r| r < if old.is_some() { -70 } else { -65 })
        {
            self.stats.rx_ignored += 1;
            return Ok(vec![]);
        }
        if old.is_none() && self.peers.len() >= MAX_PEERS {
            self.stats.dropped += 1;
            return Ok(vec![]);
        }
        // Parsing completed before mutation: malformed trailing TLVs cannot poison state.
        let mut peer = old.cloned().unwrap_or_else(|| Peer::new(f.source, now));
        let valid_before = peer.valid;
        peer.last_seen_us = now;
        peer.rssi = f.rssi;
        if let Some(name) = &a.name {
            peer.name = name.clone();
        }
        if let Some(version) = a.version {
            peer.version = version;
        }
        if let Some(devclass) = a.devclass {
            peer.devclass = devclass;
        }
        if let Some(sequence) = &a.sequence {
            peer.sequence = Some(sequence.clone());
        }
        if let Some(e) = &a.election
            && (a.v2 || !peer.v2)
        {
            peer.election = e.clone();
            if !a.v2 {
                peer.election.sync = f.source;
            }
            peer.v2 |= a.v2;
        }
        if let Some(sync) = &a.sync {
            peer.sync_offset_us = Some(self.clock.error_tu(now, sync.next, sync.counter) * 1024);
            if self.election.sync == f.source {
                self.clock.update(now, sync.next, sync.counter);
            }
        }
        if a.subtype == 3 {
            peer.capabilities = a.capabilities.clone();
        }
        peer.mif |= a.subtype == 3;
        peer.valid = peer.mif && peer.version != 0 && peer.devclass != 0;
        let added = peer.valid && !valid_before;
        if added {
            info!("add peer {} ({})", peer.mac, peer.name);
            self.stats.peers_discovered += 1;
        }
        self.peers.insert(f.source, peer);
        self.stats.rx_action += 1;
        Ok(if added {
            vec![Event::Added(f.source)]
        } else {
            vec![]
        })
    }
    pub fn tick(&mut self, now: i64) -> Vec<Event> {
        self.expire_syns(now);
        let expired: Vec<_> = self
            .peers
            .values()
            .filter(|p| now - p.last_seen_us > self.config.peer_timeout.as_micros() as i64)
            .map(|p| (p.mac, p.valid))
            .collect();
        let mut events = Vec::new();
        for (mac, valid) in expired {
            if let Some(p) = self.peers.remove(&mac)
                && valid
            {
                info!("remove peer {} ({})", mac, p.name);
                events.push(Event::Removed(mac));
            }
        }
        self.elect();
        self.adopt_sequence(now);
        events
    }
    fn elect(&mut self) {
        let old = self.election.clone();
        let mut selected = Election::own(self.config.mac);
        let mut selected_mac = self.config.mac;
        // The upstream election resets only the selected master, retaining our metrics.
        selected.self_metric = old.self_metric;
        selected.metric = old.self_metric;
        selected.self_counter = old.self_counter;
        selected.counter = old.self_counter;
        for peer in self.peers.values().filter(|p| p.valid) {
            let e = &peer.election;
            if e.height >= 10 || e.sync == self.config.mac {
                continue;
            }
            let rank = if self.config.metric_first {
                (e.metric, e.counter)
            } else {
                (e.counter, e.metric)
            };
            let best = if self.config.metric_first {
                (selected.metric, selected.counter)
            } else {
                (selected.counter, selected.metric)
            };
            if rank < best
                || (rank == best
                    && (e.height > selected.height
                        || (e.height == selected.height && peer.mac <= selected_mac)))
            {
                continue;
            }
            selected = e.clone();
            selected_mac = peer.mac;
        }
        if selected_mac != self.config.mac {
            selected.height += 1;
            selected.sync = selected_mac;
        }
        selected.self_metric = old.self_metric;
        selected.self_counter = old.self_counter;
        if selected.master != old.master || selected.sync != old.sync {
            debug!(master=%selected.master,sync=%selected.sync,metric=selected.metric,counter=selected.counter,"new election tree");
        }
        self.election = selected;
    }
    fn adopt_sequence(&mut self, now: i64) {
        let Some(peer) = self
            .peers
            .get(&self.election.sync)
            .filter(|p| p.sequence.is_some())
        else {
            self.sequence = self.config.fixed_sequence(self.config.channel);
            self.source = None;
            self.rotation = None;
            self.pending_rotation = None;
            return;
        };
        let src = peer.sequence.as_ref().expect("checked sequence");
        let sequence = match self.config.strategy {
            Strategy::Verbatim => src.clone(),
            Strategy::Pin => {
                let c = if self.config.fixed_radio {
                    self.config.channel
                } else {
                    src.dominant(self.config.channel)
                };
                if c == 0 {
                    return;
                }
                self.config.fixed_sequence(c)
            }
            Strategy::Widen => src.widen(self.config.widen),
            Strategy::Rotate => {
                let delta = (self.clock.slot(now + peer.sync_offset_us.unwrap_or(0)) + SLOTS
                    - self.clock.slot(now))
                    % SLOTS;
                if self.source != Some(peer.mac) {
                    self.rotation = None;
                    self.pending_rotation = None;
                }
                if self.rotation.is_none() {
                    self.rotation = Some(delta);
                } else if self.rotation != Some(delta) {
                    if self.pending_rotation == Some(delta) {
                        self.rotation = Some(delta);
                        self.pending_rotation = None;
                    } else {
                        self.pending_rotation = Some(delta);
                        return;
                    }
                } else {
                    self.pending_rotation = None;
                }
                src.rotate(self.rotation.unwrap_or(0))
            }
            Strategy::Intersect => {
                let mut seq = src.intersect(self.config.channel);
                if self.config.fixed_radio {
                    for p in self.peers.values().filter(|p| p.valid && p.mac != peer.mac) {
                        if let (Some(other), Some(offset)) = (&p.sequence, p.sync_offset_us) {
                            let phase = (offset / 1024 + 512).rem_euclid(1024) - 512;
                            if other.encoding == src.encoding && phase.abs() <= 16 {
                                for i in 0..SLOTS {
                                    if seq.channel(i) == 0
                                        && other.channel(i) == self.config.channel
                                    {
                                        seq.slots[i] = other.slots[i];
                                    }
                                }
                            }
                        }
                    }
                }
                if !(0..SLOTS).any(|i| seq.channel(i) != 0) {
                    info!(
                        "NO OVERLAP with {} on ch {} - peer wants ch {}",
                        peer.mac,
                        self.config.channel,
                        src.dominant(0)
                    );
                    return;
                }
                seq
            }
        };
        let sequence = match self.config.operating_channel {
            Some(definition) => sequence.with_definition(definition),
            None => sequence,
        };
        if sequence != self.sequence {
            debug!(source=%peer.mac,?sequence,"following sync master channel sequence");
            self.sequence = sequence;
        }
        self.source = Some(peer.mac);
    }
    pub fn current_channel(&self, now: i64) -> u8 {
        if self.config.fixed_radio {
            self.config.channel
        } else {
            self.sequence.channel(self.clock.slot(now))
        }
    }
    fn same_channel(&self, p: &Peer, now: i64) -> bool {
        let Some(seq) = &p.sequence else {
            return false;
        };
        let peer_time = if self.config.strategy == Strategy::Rotate {
            now + p.sync_offset_us.unwrap_or(0)
        } else {
            now
        };
        let channel = self.current_channel(now);
        channel != 0 && channel == seq.channel(self.clock.slot(peer_time))
    }
    pub fn send_ready(&self, destination: Mac, now: i64) -> bool {
        if destination.multicast() {
            return (self.config.fixed_radio || matches!(self.clock.slot(now), 0 | 10))
                && self
                    .clock
                    .guard_delay(now, if self.config.fixed_radio { 3 } else { 16 })
                    == 0;
        }
        let Some(peer) = self.peers.get(&destination).filter(|p| p.valid) else {
            return false;
        };
        if !self.same_channel(peer, now) {
            return false;
        }
        let next = self.clock.next_us(now);
        let guard = 3 * 1024;
        if next < guard {
            self.same_channel(peer, now + SLOT_US)
        } else if SLOT_US - next < guard {
            self.same_channel(peer, now - SLOT_US)
        } else {
            true
        }
    }
    pub(crate) fn addba_rejection(
        &mut self,
        peer: Mac,
        request: protocol::AddBaRequest,
    ) -> Vec<u8> {
        let sequence = self.next_sequence();
        protocol::encode_addba_rejection(
            self.config.mac,
            peer,
            request,
            sequence,
            self.config.tx_noack,
        )
    }
    fn next_sequence(&mut self) -> u16 {
        let n = self.ieee_sequence;
        self.ieee_sequence = (n + 1) & 4095;
        n
    }
    pub fn set_operating_channel(&mut self, definition: crate::channel::ChannelDefinition) {
        self.config.channel = definition.channel;
        self.config.operating_channel = Some(definition);
        self.sequence = if self.config.strategy == Strategy::Pin {
            Sequence::fixed_definition(definition)
        } else {
            self.sequence.with_definition(definition)
        };
    }
    pub fn action_frame(&mut self, subtype: u8, now: i64) -> Vec<u8> {
        self.action_frame_on_channel(subtype, now, self.current_channel(now))
    }
    /// Encode the physical channel; the fixed sequence is committed after tuning.
    pub fn action_frame_on_channel(&mut self, subtype: u8, now: i64, channel: u8) -> Vec<u8> {
        let seq = self.next_sequence();
        let a = Advertisement {
            mac: self.config.mac,
            name: &self.config.name,
            capabilities: self.config.capabilities.for_channel(channel),
            sequence: &self.sequence,
            election: &self.election,
            channel,
            master_channel: self.config.channel,
            next: self.clock.next_tu(now),
            aw_counter: self.clock.current_aw(now),
            now_us: now,
        };
        let mut frame = protocol::encode_action(&a, subtype, seq);
        if subtype == 3
            && let Some(port) = self.config.airdrop_port
        {
            frame.extend(protocol::airdrop_service(
                self.config.mac,
                &self.config.name,
                port,
            ));
        }
        frame
    }
    pub(crate) fn has_pending_tx(&self, now: i64) -> bool {
        self.pending_tx
            .iter()
            .any(|p| now.saturating_sub(p.sent_us) < self.config.pending_timeout.as_micros() as i64)
    }
    pub(crate) fn record_tx(&mut self, bytes: &[u8], parameters: TxParameters, now: i64) {
        if self.config.tx_noack {
            return;
        }
        let Some((destination, sequence, fingerprint)) = protocol::transmit_key(bytes) else {
            return;
        };
        if destination.multicast() {
            return;
        }
        // Bound memory and reject old completions after sequence-number wrap.
        self.pending_tx.retain(|p| {
            now.saturating_sub(p.sent_us) < self.config.pending_timeout.as_micros() as i64
        });
        if self.pending_tx.len() == 1024 {
            self.pending_tx.pop_front();
        }
        self.pending_tx.push_back(PendingTx {
            destination,
            sequence,
            fingerprint,
            rate: parameters.rate,
            channel: self.config.operating_channel,
            sent_us: now,
            generation: self
                .peers
                .get(&destination)
                .map_or(0, |p| p.rate_control.generation),
        });
    }
    fn tx_status(&mut self, frame: &Frame, status: &protocol::TxStatus, now: i64) {
        // mt76 may synthesize an ACK when TX status is lost; those reports have
        // no PHY rate. They do not prove delivery and must not train Auto.
        if status.rate.is_none() || status.noack || self.config.tx_noack {
            self.stats.tx_status_ignored += 1;
            return;
        }
        let at = self.pending_tx.iter().position(|p| {
            frame.source == self.config.mac
                && frame.destination == p.destination
                && frame.sequence == p.sequence
                && status.fingerprint == p.fingerprint
        });
        let Some(at) = at else {
            self.stats.tx_status_ignored += 1;
            return;
        };
        let pending = self.pending_tx.remove(at).expect("matched pending TX");
        if now.saturating_sub(pending.sent_us) >= self.config.pending_timeout.as_micros() as i64 {
            self.stats.tx_status_ignored += 1;
            return;
        }
        self.stats.tx_status_acked += u64::from(!status.failed);
        self.stats.tx_status_failed += u64::from(status.failed);
        self.stats.tx_status_retries += u64::from(status.retries);
        debug!(peer=%frame.destination, sequence=frame.sequence, requested_rate=%pending.rate, reported_rate=?status.rate, failed=status.failed, retries=status.retries, completion_us=now.saturating_sub(pending.sent_us), "AWDL TX completion");
        if self.config.rate == Rate::Auto
            && pending.channel == self.config.operating_channel
            && let Some(peer) = self.peers.get_mut(&frame.destination).filter(|p| p.valid)
            && pending.generation == peer.rate_control.generation
        {
            peer.rate_control
                .feedback(pending.rate, status.failed, status.retries);
        }
    }
    pub fn data_parameters(&mut self, destination: Mac) -> Result<TxParameters, Error> {
        let requested = self.config.rate;
        let fallback = requested.fallback();
        // Automatic/VHT multicast discovery stays at the robust legacy rate.
        if destination.multicast() {
            return Ok(fallback.into());
        }
        let Some(peer) = self.peers.get_mut(&destination).filter(|p| p.valid) else {
            return Ok(fallback.into());
        };
        let rate = self.config.operating_channel.map_or(fallback, |channel| {
            let local = self.config.capabilities.for_channel(channel.channel);
            let width = peer
                .sequence
                .as_ref()
                .map_or(20, |s| s.width_mhz(channel.channel));
            if requested == Rate::Auto && !self.config.tx_noack {
                peer.rate_control
                    .select(channel, local, &peer.capabilities, width)
            } else {
                requested.for_peer(channel, local, &peer.capabilities, width)
            }
        });
        let parameters = self
            .config
            .fec
            .resolve(rate, self.config.tx_ldpc, &peer.capabilities)?;
        if peer.tx_parameters != Some(parameters) {
            info!(peer=%destination, %requested, %rate, requested_fec=?self.config.fec, coding=%parameters.coding, "selected data injection parameters");
            peer.tx_parameters = Some(parameters);
        }
        Ok(parameters)
    }
    pub(crate) fn data_frame(
        &mut self,
        packets: &[&[u8]],
        parameters: TxParameters,
    ) -> Result<Vec<u8>, Error> {
        let seq = self.next_sequence();
        let data_seq = self.data_sequence;
        self.data_sequence = self.data_sequence.wrapping_add(packets.len() as u16);
        match packets {
            [packet] => protocol::encode_data(
                packet,
                seq,
                data_seq,
                parameters,
                self.config.tx_noack,
                false,
            ),
            _ => protocol::encode_amsdu(
                packets,
                seq,
                data_seq,
                parameters,
                self.config.tx_noack,
                false,
            ),
        }
    }
    /// Remaining common-channel airtime, excluding the existing boundary guard.
    pub(crate) fn tx_window_us(&self, destination: Mac, now: i64) -> i64 {
        if !self.send_ready(destination, now) {
            return 0;
        }
        if destination.multicast() {
            return if self.config.fixed_radio {
                SLOT_US
            } else {
                (self.clock.next_us(now) - 16 * 1024).max(0)
            };
        }
        let peer = &self.peers[&destination];
        let offset = if self.config.strategy == Strategy::Rotate {
            peer.sync_offset_us.unwrap_or(0)
        } else {
            0
        };
        let horizon = SLOTS as i64 * SLOT_US;
        let mut remaining = 0;
        // Both schedules can have boundaries within one local slot. Stop at
        // the first loss of overlap, including a peer's unsynchronized boundary.
        for _ in 0..2 * SLOTS + 1 {
            let time = now + remaining;
            remaining += self
                .clock
                .next_us(time)
                .min(self.clock.next_us(time + offset));
            remaining = remaining.min(horizon);
            if remaining == horizon || !self.same_channel(peer, now + remaining) {
                break;
            }
        }
        (remaining - 3 * 1024).max(0)
    }
}
