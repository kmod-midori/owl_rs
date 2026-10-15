// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded receive Block Ack agreements. One slot holds one whole decoded MPDU.
use crate::protocol::{AddBaRequest, Mac};
use serde::Serialize;
use std::collections::BTreeMap;

const MAX_SESSIONS: usize = 8;
const GAP_US: i64 = 100_000;
fn distance(sequence: u16, head: u16) -> u16 {
    sequence.wrapping_sub(head) & 4095
}
#[derive(Debug, Default, Serialize)]
pub struct Stats {
    pub sessions_started: u64,
    pub buffered_mpdus: u64,
    pub duplicate_mpdus: u64,
    pub old_mpdus: u64,
    pub skipped_sequences: u64,
    pub gap_timeouts: u64,
    pub bars: u64,
}
struct Held {
    frames: Vec<Vec<u8>>,
    since: i64,
}
struct Session {
    request: AddBaRequest,
    head: u16,
    held: BTreeMap<u16, Held>,
}
impl Session {
    fn advance(&mut self, count: u16, out: &mut Vec<Vec<u8>>, stats: &mut Stats) {
        for _ in 0..count {
            if let Some(held) = self.held.remove(&self.head) {
                out.extend(held.frames);
            } else {
                stats.skipped_sequences += 1;
            }
            self.head = (self.head + 1) & 4095;
        }
    }
    fn contiguous(&mut self, out: &mut Vec<Vec<u8>>) {
        while let Some(held) = self.held.remove(&self.head) {
            out.extend(held.frames);
            self.head = (self.head + 1) & 4095;
        }
    }
    fn flush(&mut self, out: &mut Vec<Vec<u8>>, stats: &mut Stats) {
        if let Some(last) = self.held.keys().map(|&sn| distance(sn, self.head)).max() {
            self.advance(last + 1, out, stats);
        }
    }
}
#[derive(Default)]
pub(crate) struct Reorder {
    sessions: BTreeMap<(Mac, u8), Session>,
    pub stats: Stats,
    ready: Vec<(Mac, Vec<Vec<u8>>)>,
}
impl Reorder {
    pub fn contains(&self, peer: Mac, tid: u8) -> bool {
        self.sessions.contains_key(&(peer, tid))
    }
    pub fn can_start(&self, peer: Mac, request: AddBaRequest) -> bool {
        request.parameters & 2 != 0 // Immediate Block Ack only.
            && request.starting_sequence & 15 == 0
            && (self.contains(peer, request.tid()) || self.sessions.len() < MAX_SESSIONS)
    }
    /// Called only after the acceptance response was submitted successfully.
    pub fn start(&mut self, peer: Mac, request: AddBaRequest) {
        let key = (peer, request.tid());
        if self
            .sessions
            .get(&key)
            .is_some_and(|s| s.request == request)
        {
            return; // A retransmitted request must not rewind an active window.
        }
        if !self.can_start(peer, request) {
            return;
        }
        if let Some(mut old) = self.sessions.remove(&key) {
            let mut frames = Vec::new();
            old.flush(&mut frames, &mut self.stats);
            self.ready.push((peer, frames));
        }
        self.sessions.insert(
            key,
            Session {
                request,
                head: request.starting_sequence >> 4,
                held: BTreeMap::new(),
            },
        );
        self.stats.sessions_started += 1;
    }
    pub fn receive(
        &mut self,
        peer: Mac,
        tid: u8,
        sequence: u16,
        frames: Vec<Vec<u8>>,
        now: i64,
    ) -> Vec<Vec<u8>> {
        let Some(session) = self.sessions.get_mut(&(peer, tid)) else {
            return frames;
        };
        let mut out = Vec::new();
        let delta = distance(sequence, session.head);
        if delta >= 2048 {
            self.stats.old_mpdus += 1;
            return out;
        }
        if session.held.contains_key(&sequence) {
            self.stats.duplicate_mpdus += 1;
            return out;
        }
        let size = session.request.window();
        if delta >= size {
            session.advance(delta - size + 1, &mut out, &mut self.stats);
        }
        if sequence != session.head {
            self.stats.buffered_mpdus += 1;
        }
        session.held.insert(sequence, Held { frames, since: now });
        session.contiguous(&mut out);
        out
    }
    pub fn bar(&mut self, peer: Mac, tid: u8, sequence: u16) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if let Some(session) = self.sessions.get_mut(&(peer, tid)) {
            let delta = distance(sequence, session.head);
            if delta < 2048 {
                self.stats.bars += 1;
                session.advance(delta, &mut out, &mut self.stats);
                session.contiguous(&mut out);
            }
        }
        out
    }
    pub fn stop(&mut self, peer: Mac, tid: u8) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if let Some(mut session) = self.sessions.remove(&(peer, tid)) {
            session.flush(&mut out, &mut self.stats);
        }
        out
    }
    pub fn remove_peer(&mut self, peer: Mac) {
        self.sessions.retain(|&(mac, _), _| mac != peer);
        self.ready.retain(|(mac, _)| *mac != peer);
    }
    pub fn pending(&self) -> bool {
        !self.ready.is_empty() || self.sessions.values().any(|s| !s.held.is_empty())
    }
    pub fn take_ready(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.ready)
            .into_iter()
            .flat_map(|(_, frames)| frames)
            .collect()
    }
    pub fn poll(&mut self, now: i64) -> Vec<Vec<u8>> {
        let mut out = self.take_ready();
        for session in self.sessions.values_mut() {
            let last = session
                .held
                .iter()
                .filter(|(_, held)| now.saturating_sub(held.since) >= GAP_US)
                .map(|(&sn, _)| distance(sn, session.head))
                .max();
            if let Some(last) = last {
                self.stats.gap_timeouts += 1;
                session.advance(last + 1, &mut out, &mut self.stats);
                session.contiguous(&mut out);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PEER: Mac = Mac([2, 0, 0, 0, 0, 1]);
    fn request(tid: u8, head: u16) -> AddBaRequest {
        AddBaRequest {
            dialog_token: 1,
            parameters: 2 | (u16::from(tid) << 2) | (4 << 6),
            timeout: 10,
            starting_sequence: head << 4,
        }
    }
    fn packet(n: u8) -> Vec<Vec<u8>> {
        vec![vec![n]]
    }
    #[test]
    fn ordering_wrap_gaps_bars_and_tid_isolation() {
        let mut r = Reorder::default();
        r.start(PEER, request(0, 4094));
        r.start(PEER, request(1, 7));
        assert!(r.receive(PEER, 0, 0, packet(0), 0).is_empty());
        assert!(r.receive(PEER, 0, 0, packet(9), 1).is_empty());
        assert_eq!(r.receive(PEER, 1, 7, packet(7), 1), packet(7));
        assert_eq!(r.receive(PEER, 0, 4094, packet(4), 1), packet(4));
        assert_eq!(
            r.receive(PEER, 0, 4095, packet(5), 1),
            vec![vec![5], vec![0]]
        );
        r.start(PEER, request(0, 4094)); // Lost response retransmission cannot rewind.
        assert!(r.receive(PEER, 0, 4094, packet(9), 2).is_empty());
        assert!(r.receive(PEER, 0, 3, vec![vec![3], vec![33]], 3).is_empty());
        assert!(r.poll(100_002).is_empty());
        assert_eq!(r.poll(100_003), vec![vec![3], vec![33]]);
        assert!(r.receive(PEER, 0, 6, packet(6), 100_004).is_empty());
        assert!(r.bar(PEER, 0, 3).is_empty()); // Stale BAR must not rewind.
        assert_eq!(r.bar(PEER, 0, 6), packet(6));
        assert!(r.receive(PEER, 0, 8, packet(8), 100_005).is_empty());
        // Advancing past the window releases held MPDUs before the new one.
        assert_eq!(r.receive(PEER, 0, 12, packet(12), 100_006), packet(8));
        assert_eq!(r.stop(PEER, 0), packet(12));
        assert_eq!(r.stats.duplicate_mpdus, 1);
        assert_eq!(r.stats.old_mpdus, 1);
        assert_eq!(r.stats.gap_timeouts, 1);
        assert_eq!(r.stats.sessions_started, 2);
    }
    #[test]
    fn capacity_rejects_new_agreements_and_peer_cleanup_drops_held_frames() {
        let mut r = Reorder::default();
        for tid in 0..MAX_SESSIONS as u8 {
            r.start(PEER, request(tid, 10));
        }
        assert!(!r.can_start(PEER, request(8, 10)));
        r.start(PEER, request(8, 10));
        assert!(!r.contains(PEER, 8));
        let mut invalid = request(0, 10);
        invalid.parameters &= !2;
        assert!(!r.can_start(PEER, invalid));
        invalid = request(0, 10);
        invalid.starting_sequence |= 1;
        assert!(!r.can_start(PEER, invalid));
        assert!(r.receive(PEER, 0, 11, packet(11), 0).is_empty());
        let mut changed = request(0, 20);
        changed.dialog_token += 1;
        r.start(PEER, changed);
        assert!(r.pending());
        r.remove_peer(PEER);
        assert!(!r.pending());
        assert!(r.poll(200_000).is_empty());
        assert!(r.can_start(PEER, request(8, 10)));
    }
}
