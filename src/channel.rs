// SPDX-License-Identifier: GPL-3.0-or-later
use crate::protocol::{Error, Reader};
use clap::ValueEnum;
use serde::Serialize;

pub const SLOTS: usize = 16;
pub const SLOT_US: i64 = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[repr(u8)]
pub enum Encoding {
    Simple = 0,
    Legacy = 1,
    Opclass = 3,
}
impl Encoding {
    pub fn parse(n: u8) -> Result<Self, Error> {
        match n {
            0 => Ok(Self::Simple),
            1 => Ok(Self::Legacy),
            3 => Ok(Self::Opclass),
            _ => Err(Error::Invalid("channel encoding")),
        }
    }
    pub fn width(self) -> usize {
        if self == Self::Simple { 1 } else { 2 }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Sequence {
    pub encoding: Encoding,
    pub slots: [[u8; 2]; SLOTS],
}
impl Sequence {
    pub fn fixed(channel: u8) -> Self {
        Self {
            encoding: Encoding::Opclass,
            slots: [[channel, if channel > 14 { 0x80 } else { 0x51 }]; SLOTS],
        }
    }
    pub fn channel(&self, i: usize) -> u8 {
        self.slots[i % SLOTS][usize::from(self.encoding == Encoding::Legacy)]
    }
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(data);
        if r.u8()? != 15 {
            return Err(Error::Invalid("channel sequence count"));
        }
        let encoding = Encoding::parse(r.u8()?)?;
        if r.u8()? != 0 || r.u8()? != 3 || r.le16()? != 0xffff {
            return Err(Error::Invalid("channel sequence parameters"));
        }
        let mut slots = [[0; 2]; SLOTS];
        for slot in &mut slots {
            let bytes = r.take(encoding.width())?;
            slot[..bytes.len()].copy_from_slice(bytes);
        }
        Ok(Self { encoding, slots })
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![15, self.encoding as u8, 0, 3, 255, 255];
        for s in &self.slots {
            bytes.extend_from_slice(&s[..self.encoding.width()]);
        }
        bytes
    }
    pub fn dominant(&self, prefer: u8) -> u8 {
        let mut counts = [0u8; 256];
        for i in 0..SLOTS {
            let c = self.channel(i);
            if c != 0 {
                counts[c as usize] += 1;
            }
        }
        let best = (1..256)
            .max_by_key(|&i| (counts[i], std::cmp::Reverse(i)))
            .unwrap_or(0);
        if counts[best] == 0 {
            0
        } else if prefer != 0 && counts[prefer as usize] == counts[best] {
            prefer
        } else {
            best as u8
        }
    }
    /// Rank usable channels by full-slot overlap; zero/unsupported channels do not count.
    pub fn ranked_channels(&self, allowed: &[u8], prefer: u8) -> Vec<u8> {
        let mut counts = [0u8; 256];
        for i in 0..SLOTS {
            counts[self.channel(i) as usize] += 1;
        }
        let mut channels: Vec<_> = allowed.iter().copied().filter(|&c| c != 0).collect();
        channels.sort_unstable();
        channels.dedup();
        channels.sort_by_key(|&c| (std::cmp::Reverse(counts[c as usize]), c != prefer, c));
        channels
    }
    pub fn rotate(&self, delta: usize) -> Self {
        Self {
            encoding: self.encoding,
            slots: std::array::from_fn(|i| self.slots[(i + delta) % SLOTS]),
        }
    }
    pub fn widen(&self, max: usize) -> Self {
        let mut seq = self.clone();
        let dominant = self.dominant(0);
        if dominant == 0 {
            return seq;
        }
        let fill = self.slots[(0..SLOTS)
            .find(|&i| self.channel(i) == dominant)
            .unwrap_or(0)];
        let mut filled = 0;
        for i in 1..SLOTS {
            if seq.channel(i) == 0 && filled < max {
                seq.slots[i] = fill;
                filled += 1;
            }
        }
        seq
    }
    pub fn intersect(&self, channel: u8) -> Self {
        Self {
            encoding: self.encoding,
            slots: std::array::from_fn(|i| {
                if self.channel(i) == channel && channel != 0 {
                    self.slots[i]
                } else {
                    [0, 0]
                }
            }),
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum, Serialize)]
pub enum Strategy {
    #[default]
    Verbatim,
    Rotate,
    Pin,
    Widen,
    Intersect,
}

/// Signed phase avoids epoch underflow and models 16-bit AW counter rollover.
#[derive(Clone, Debug)]
pub struct Clock {
    pub epoch_us: i64,
    pub counter: u16,
}
impl Clock {
    pub fn new(now: i64) -> Self {
        Self {
            epoch_us: now,
            counter: 0,
        }
    }
    pub fn current_aw(&self, now: i64) -> u16 {
        self.counter
            .wrapping_add((now - self.epoch_us).div_euclid(16 * 1024) as u16)
    }
    pub fn slot(&self, now: i64) -> usize {
        (self.current_aw(now) / 4) as usize % SLOTS
    }
    pub fn next_us(&self, now: i64) -> i64 {
        SLOT_US - (now - self.epoch_us).rem_euclid(SLOT_US)
    }
    pub fn next_tu(&self, now: i64) -> u16 {
        (64 - (now - self.epoch_us).div_euclid(1024).rem_euclid(64)) as u16
    }
    pub fn error_tu(&self, now: i64, next: u16, counter: u16) -> i64 {
        let delta = ((counter / 4).wrapping_sub(self.current_aw(now) / 4) << 2) as i16 as i64;
        delta * 16 - (next as i64 - self.next_tu(now) as i64)
    }
    pub fn update(&mut self, now: i64, next: u16, counter: u16) {
        self.epoch_us = now - (64 - next as i64) * 1024;
        self.counter = counter & !3;
    }
    pub fn guard_delay(&self, now: i64, guard_tu: i64) -> i64 {
        let next = self.next_us(now);
        let guard = guard_tu * 1024;
        if next < guard {
            next + guard
        } else {
            (guard - (SLOT_US - next)).max(0)
        }
    }
}

/// Operation-scoped discovery visits are separate from the advertised fixed schedule.
#[derive(Clone, Debug, Serialize)]
pub struct ChannelPlan {
    pub discovery_channel: u8,
    pub transmit_channel: u8,
    pub preferred_channel: u8,
    pub allowed_channels: Vec<u8>,
    pub failed_channels: Vec<u8>,
    pub discovering: bool,
    #[serde(skip)]
    deadline_us: i64,
    #[serde(skip)]
    discovery_duration_us: i64,
}
const CYCLE_US: i64 = SLOT_US * SLOTS as i64;
impl ChannelPlan {
    pub fn new(discovery: u8, preferred: u8, allowed: Vec<u8>) -> Self {
        Self {
            discovery_channel: discovery,
            transmit_channel: preferred,
            preferred_channel: preferred,
            allowed_channels: allowed,
            failed_channels: Vec::new(),
            discovering: true,
            deadline_us: 3 * CYCLE_US,
            discovery_duration_us: 3 * CYCLE_US,
        }
    }
    /// A sync-parent schedule implies follower mode. A root uses its preference.
    pub fn desired(&mut self, now: i64, parent: Option<&Sequence>, busy: bool) -> Option<u8> {
        if now >= self.deadline_us {
            if self.discovering {
                self.discovering = false;
                self.deadline_us = now + 10_000_000;
            } else if !busy && !self.failed_channels.contains(&self.discovery_channel) {
                self.discovering = true;
                self.discovery_duration_us = CYCLE_US;
                self.deadline_us = now + CYCLE_US;
            }
        }
        if self.discovering && !self.failed_channels.contains(&self.discovery_channel) {
            return Some(self.discovery_channel);
        }
        // A failed discovery tune goes straight to the transmit candidates.
        self.discovering = false;
        let own = Sequence::fixed(self.preferred_channel);
        let channels = parent
            .unwrap_or(&own)
            .ranked_channels(&self.allowed_channels, self.preferred_channel);
        channels
            .into_iter()
            .find(|c| !self.failed_channels.contains(c))
    }
    /// Tuning latency must not consume the actual discovery dwell window.
    pub fn discovery_ready(&mut self, channel: u8, now: i64) {
        if self.discovering && channel == self.discovery_channel {
            self.deadline_us = now + self.discovery_duration_us;
        }
    }
    pub fn failed(&mut self, channel: u8) {
        if !self.failed_channels.contains(&channel) {
            self.failed_channels.push(channel);
        }
    }
    /// Publish a new fixed schedule only after successful kernel tuning.
    pub fn applied(&mut self, channel: u8) -> bool {
        if !self.discovering && self.transmit_channel != channel {
            self.transmit_channel = channel;
            true
        } else {
            false
        }
    }
}
