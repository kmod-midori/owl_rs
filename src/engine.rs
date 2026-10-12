// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{
    channel::{Clock, SLOT_US, SLOTS, Sequence, Strategy},
    protocol::{self, Action, Advertisement, Body, Election, Error, Frame, Mac, Rate},
};
use serde::Serialize;
use std::collections::{BTreeMap, VecDeque};
use tracing::{debug, info};

const MAX_PEERS: usize = 512;
const PEER_TIMEOUT: i64 = 5_000_000;
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
            mif: false,
            v2: false,
            recent: VecDeque::new(),
        }
    }
}
#[derive(Clone, Debug)]
pub struct Config {
    pub mac: Mac,
    pub name: String,
    pub airdrop_port: Option<u16>,
    pub channel: u8,
    pub strategy: Strategy,
    pub fixed_radio: bool,
    pub metric_first: bool,
    pub election_metric: u32,
    pub election_counter: u32,
    pub widen: usize,
    pub filter_rssi: bool,
    pub rate: Rate,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct Stats {
    pub captured: u64,
    pub rx_action: u64,
    pub rx_data: u64,
    pub rx_unknown: u64,
    pub rx_ignored: u64,
    pub rx_duplicates: u64,
    pub tx_action: u64,
    pub tx_data: u64,
    pub tx_backpressure: u64,
    pub tx_unicast: u64,
    pub tx_multicast: u64,
    pub dropped: u64,
    pub peers_discovered: u64,
}
#[derive(Clone, Debug)]
pub enum Event {
    Added(Mac),
    Removed(Mac),
}
#[derive(Debug, Serialize)]
pub struct Summary<'a> {
    pub stats: &'a Stats,
    pub peers: Vec<&'a Peer>,
    pub election: &'a Election,
    pub sequence: &'a Sequence,
    pub frequencies_mhz: &'a BTreeMap<u16, u64>,
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
            sequence: Sequence::fixed(config.channel),
            config,
            peers: BTreeMap::new(),
            stats: Stats::default(),
            frequencies: BTreeMap::new(),
            ieee_sequence: 0,
            data_sequence: 0,
            rotation: None,
            pending_rotation: None,
            source: None,
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
        if let Some(freq) = frame.frequency {
            *self.frequencies.entry(freq).or_default() += 1;
        }
        if frame.source == self.config.mac || !frame.source.valid_unicast() {
            self.stats.rx_ignored += 1;
            return Ok((vec![], vec![]));
        }
        match &frame.body {
            Body::Action(a) => self.action(&frame, a, now).map(|events| (vec![], events)),
            Body::Data(frames) => {
                let Some(peer) = self.peers.get_mut(&frame.source).filter(|p| p.valid) else {
                    self.stats.rx_ignored += 1;
                    return Ok((vec![], vec![]));
                };
                // Fully parsed data, including retries, proves a known peer is alive.
                // Busy phones may skip action frames while uploading.
                peer.last_seen_us = now;
                peer.recent.retain(|&(_, time)| now - time < 500_000);
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
        let expired: Vec<_> = self
            .peers
            .values()
            .filter(|p| now - p.last_seen_us > PEER_TIMEOUT)
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
            self.sequence = Sequence::fixed(self.config.channel);
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
                Sequence::fixed(c)
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
    fn next_sequence(&mut self) -> u16 {
        let n = self.ieee_sequence;
        self.ieee_sequence = (n + 1) & 4095;
        n
    }
    pub fn set_transmit_channel(&mut self, channel: u8) {
        self.config.channel = channel;
        self.sequence = Sequence::fixed(channel);
    }
    pub fn action_frame(&mut self, subtype: u8, now: i64) -> Vec<u8> {
        self.action_frame_on_channel(subtype, now, self.current_channel(now))
    }
    /// A discovery visit changes the physical-channel field, not our fixed schedule.
    pub fn action_frame_on_channel(&mut self, subtype: u8, now: i64, channel: u8) -> Vec<u8> {
        let seq = self.next_sequence();
        let a = Advertisement {
            mac: self.config.mac,
            name: &self.config.name,
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
    pub fn data_frame(&mut self, ethernet: &[u8]) -> Result<Vec<u8>, Error> {
        let seq = self.next_sequence();
        let data_seq = self.data_sequence;
        self.data_sequence = self.data_sequence.wrapping_add(1);
        protocol::encode_data(
            ethernet,
            seq,
            data_seq,
            self.config.rate,
            self.config.fixed_radio,
            false,
        )
    }
}
