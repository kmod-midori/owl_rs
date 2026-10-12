// SPDX-License-Identifier: GPL-3.0-or-later
use owl_rs::{
    channel::{Clock, Encoding, SLOT_US, Sequence, Strategy},
    engine::{Config, Engine},
    protocol::{self, Advertisement, Body, Election, Mac, Rate},
};
fn config(mac: Mac) -> Config {
    Config {
        airdrop_port: None,
        mac,
        name: "test".into(),
        channel: 6,
        strategy: Strategy::Intersect,
        fixed_radio: true,
        metric_first: true,
        election_metric: 60,
        election_counter: 0,
        widen: 4,
        filter_rssi: false,
        rate: Rate::default(),
    }
}
fn mif(mac: Mac, metric: u32, counter: u32, seq: &Sequence) -> Vec<u8> {
    let mut election = Election::own(mac);
    election.metric = metric;
    election.counter = counter;
    protocol::encode_action(
        &Advertisement {
            mac,
            name: "fixture",
            sequence: seq,
            election: &election,
            channel: 6,
            master_channel: 6,
            next: 64,
            aw_counter: 0,
            now_us: 0,
        },
        3,
        0,
    )
}
#[test]
fn malformed_lengths_never_panic_and_cannot_mutate_peers() {
    let peer = Mac([2, 1, 2, 3, 4, 5]);
    let frame = mif(peer, 518, 367, &Sequence::fixed(6));
    for len in 0..frame.len() {
        let _ = protocol::parse(&frame[..len]);
    }
    let mut bad = frame.clone();
    bad.pop();
    let mut engine = Engine::new(config(Mac([2, 0, 0, 0, 0, 1])), 0);
    assert!(engine.receive(&bad, 0).is_err());
    assert!(engine.peers.is_empty());
    for n in 0..frame.len() {
        let mut bad = frame.clone();
        bad[n] = 255;
        let _ = protocol::parse(&bad);
    }
}
#[test]
fn mcs_noack_alignment_and_ethernet_roundtrip() {
    for rate in ["12", "mcs0", "mcs7-sgi", "mcs15"] {
        assert!(rate.parse::<Rate>().is_ok());
    }
    for rate in ["0", "mcs", "mcs16", "mcs-1", "12x", "mcs7-sgix"] {
        assert!(rate.parse::<Rate>().is_err());
    }
    assert_eq!(
        protocol::radiotap_tx(Rate::default(), true, false),
        [0, 0, 12, 0, 4, 128, 0, 0, 24, 0, 8, 0]
    );
    assert_eq!(
        protocol::radiotap_tx("mcs7-sgi".parse().unwrap(), true, false),
        [0, 0, 13, 0, 0, 128, 8, 0, 8, 0, 7, 4, 7]
    );
    for rate in [Rate::default(), "mcs15-sgi".parse().unwrap()] {
        let mut maximum = vec![2, 0, 0, 0, 0, 1, 2, 1, 2, 3, 4, 5, 0x86, 0xdd];
        maximum.extend(vec![0; owl_rs::runtime::HOST_MTU as usize]);
        assert!(
            protocol::encode_data(&maximum, 0, 0, rate, true, false)
                .unwrap()
                .len()
                <= 1514
        );
    }
    let mut ethernet = vec![2, 0, 0, 0, 0, 1, 2, 1, 2, 3, 4, 5, 0x86, 0xdd];
    ethernet.extend_from_slice(&[0x60; 48]);
    for fcs in [false, true] {
        let frame =
            protocol::encode_data(&ethernet, 4095, 65535, Rate::default(), true, fcs).unwrap();
        let parsed = protocol::parse(&frame).unwrap().unwrap();
        let Body::Data(frames) = parsed.body else {
            panic!("not data");
        };
        assert_eq!(frames, [ethernet.clone()]);
    }
}
#[test]
fn counter_rollover_and_negative_phase() {
    let mut clock = Clock::new(0);
    clock.counter = 65532;
    assert_eq!(clock.current_aw(64 * 1024), 0);
    assert_eq!(clock.slot(64 * 1024), 0);
    assert_eq!(clock.error_tu(64 * 1024, 64, 0), 0);
    clock.update(1, 32, 8);
    assert_eq!(clock.next_tu(1), 32);
    assert_eq!(Clock::new(0).error_tu(0, 64, 65532), -64);
}
#[test]
fn metric_first_election_and_fixed_radio_intersection_union() {
    let own = Mac([2, 0, 0, 0, 0, 1]);
    let a = Mac([2, 0, 0, 0, 0, 2]);
    let b = Mac([2, 0, 0, 0, 0, 3]);
    let mut sa = Sequence::fixed(149);
    sa.slots[0] = [6, 0x51];
    let mut sb = Sequence::fixed(149);
    sb.slots[8] = [6, 0x51];
    let mut e = Engine::new(config(own), 0);
    e.receive(&mif(a, 522, 393, &sa), 0).unwrap();
    e.receive(&mif(b, 510, 3214, &sb), 0).unwrap();
    e.tick(0);
    assert_eq!(e.election.sync, a);
    assert_eq!(e.sequence.channel(0), 6);
    assert_eq!(e.sequence.channel(8), 6);
    e.config.metric_first = false;
    e.tick(0);
    assert_eq!(e.election.sync, b);
    e.tick(5_000_001);
    assert!(e.peers.is_empty());
    assert_eq!(e.election.sync, own);

    // Both ranking orders must preserve our configured candidate and its wire
    // fields, while synchronization timing remains independent of election rank.
    let mut preferred = config(own);
    preferred.election_metric = 600;
    preferred.election_counter = 20_000;
    preferred.channel = 149;
    preferred.strategy = Strategy::Pin;
    let mut e = Engine::new(preferred, 0);
    e.receive(&mif(a, 539, 10_000, &sa), 0).unwrap();
    for metric_first in [true, false] {
        e.config.metric_first = metric_first;
        e.tick(0);
        assert_eq!(e.election.master, own);
        assert_eq!(e.election.sync, own);
        assert_eq!(e.election.height, 0);
        assert_eq!(e.sequence, Sequence::fixed(149));
        let frame = protocol::encode_action(
            &Advertisement {
                mac: own,
                name: "master fixture",
                sequence: &e.sequence,
                election: &e.election,
                channel: 149,
                master_channel: 149,
                next: 64,
                aw_counter: 0,
                now_us: 0,
            },
            3,
            0,
        );
        let Body::Action(action) = protocol::parse(&frame).unwrap().unwrap().body else {
            panic!()
        };
        let advertised = action.election.unwrap();
        assert_eq!((advertised.metric, advertised.self_metric), (600, 600));
        assert_eq!(
            (advertised.counter, advertised.self_counter),
            (20_000, 20_000)
        );
        assert_eq!(action.sync.unwrap().counter, 0);
    }
}
#[test]
fn amsdu_bounds_and_retry_deduplication() {
    let own = Mac([2, 0, 0, 0, 0, 1]);
    let peer = Mac([2, 0, 0, 0, 0, 2]);
    let mut e = Engine::new(config(own), 0);
    e.receive(&mif(peer, 518, 1, &Sequence::fixed(6)), 0)
        .unwrap();
    let mut ethernet = vec![];
    ethernet.extend(own.0);
    ethernet.extend(peer.0);
    ethernet.extend([0x86, 0xdd]);
    ethernet.extend([0x60; 48]);
    let frame = protocol::encode_data(&ethernet, 1, 1, Rate::default(), false, false).unwrap();
    assert_eq!(e.receive(&frame, 10).unwrap().0.len(), 1);
    let mut retry = frame.clone();
    retry[10] |= 8;
    assert!(e.receive(&retry, 20).unwrap().0.is_empty());
    assert_eq!(e.stats.rx_duplicates, 1);
    let mut amsdu = frame[..9 + 24].to_vec();
    amsdu[9] = 0x88;
    amsdu.extend([0x80, 0]);
    amsdu.extend(own.0);
    amsdu.extend(peer.0);
    let payload = &frame[9 + 24..];
    amsdu.extend((payload.len() as u16).to_be_bytes());
    amsdu.extend(payload);
    let Body::Data(frames) = protocol::parse(&amsdu).unwrap().unwrap().body else {
        panic!()
    };
    assert_eq!(frames, [ethernet]);
    amsdu.pop();
    assert!(protocol::parse(&amsdu).is_err());
}

#[test]
fn busy_peer_data_refreshes_liveness_without_discovering_unknown_peers() {
    let own = Mac([2, 0, 0, 0, 0, 1]);
    let peer = Mac([2, 0, 0, 0, 0, 2]);
    let mut engine = Engine::new(config(own), 0);
    let mut ethernet = vec![];
    ethernet.extend(own.0);
    ethernet.extend(peer.0);
    ethernet.extend([0x86, 0xdd]);
    ethernet.extend([0x60; 48]);
    let frame = protocol::encode_data(&ethernet, 1, 1, Rate::default(), false, false).unwrap();
    assert!(engine.receive(&frame, 0).unwrap().0.is_empty());
    assert!(engine.peers.is_empty());
    engine
        .receive(&mif(peer, 518, 1, &Sequence::fixed(6)), 0)
        .unwrap();
    engine.tick(3_000_000);
    assert!(engine.peers.contains_key(&peer));
    assert_eq!(engine.receive(&frame, 4_900_000).unwrap().0.len(), 1);
    engine.tick(5_000_001);
    assert!(engine.peers.contains_key(&peer));
    let mut retry = frame.clone();
    retry[10] |= 8;
    assert!(engine.receive(&retry, 5_100_000).unwrap().0.is_empty());
    assert_eq!(engine.peers[&peer].last_seen_us, 5_100_000);
    let mut truncated = frame;
    truncated.truncate(35);
    assert!(engine.receive(&truncated, 10_000_000).is_err());
    assert_eq!(engine.peers[&peer].last_seen_us, 5_100_000);
    engine.tick(10_100_001);
    assert!(engine.peers.is_empty());
}

#[test]
fn discovery_plan_ranks_overlap_and_falls_back_without_publishing_failed_tunes() {
    use owl_rs::channel::ChannelPlan;
    let cycle = SLOT_US * 16;
    let mut peer = Sequence::fixed(149);
    peer.slots[0] = [6, 0x51];
    peer.slots[1] = [44, 0x80];
    peer.slots[2] = [44, 0x80];
    peer.slots[3] = [36, 0x80]; // Infrastructure channel is unavailable to our radio.
    peer.slots[4] = [0, 0];
    assert_eq!(peer.ranked_channels(&[6, 44, 149], 6), [149, 44, 6]);
    assert_eq!(peer.ranked_channels(&[6, 44], 6), [44, 6]);
    let mut legacy = peer.clone();
    legacy.encoding = Encoding::Legacy;
    for slot in &mut legacy.slots {
        slot.swap(0, 1);
    }
    assert_eq!(Sequence::parse(&legacy.encode()).unwrap(), legacy);
    assert_eq!(legacy.ranked_channels(&[6, 44, 149], 6), [149, 44, 6]);
    assert_eq!(
        Sequence::fixed(0).ranked_channels(&[149, 44, 6, 6, 0], 149),
        [149, 6, 44]
    );
    let mut plan = ChannelPlan::new(6, 6, vec![6, 44, 149]);
    assert_eq!(plan.desired(0, Some(&peer), false), Some(6));
    assert!(!plan.applied(6));
    assert_eq!(plan.desired(3 * cycle, Some(&peer), false), Some(149));
    // A request alone, including a failed request, cannot alter the schedule.
    assert_eq!(plan.transmit_channel, 6);
    plan.failed(149);
    assert_eq!(plan.desired(3 * cycle + 1, Some(&peer), false), Some(44));
    assert!(plan.applied(44));
    assert_eq!(plan.transmit_channel, 44);
    let next = 3 * cycle + 10_000_000;
    assert_eq!(plan.desired(next, Some(&peer), true), Some(44));
    assert!(!plan.discovering);
    assert_eq!(plan.desired(next + 1, Some(&peer), false), Some(6));
    assert!(plan.discovering);
    assert!(!plan.applied(6)); // Discovery never replaces the transmit schedule.
    assert_eq!(plan.transmit_channel, 44);
    // A slow IBSS tune must still leave a full discovery window after arriving.
    plan.discovery_ready(6, next + 2 * cycle);
    assert_eq!(
        plan.desired(next + 3 * cycle - 1, Some(&peer), false),
        Some(6)
    );
    assert_eq!(plan.desired(next + 3 * cycle, Some(&peer), false), Some(44));
    assert_eq!(plan.desired(next + 3 * cycle + 1, None, false), Some(6));
    assert!(plan.applied(6)); // Without a sync parent, return to our preferred channel.
    plan.failed(44);
    plan.failed(6);
    assert_eq!(plan.desired(next + 3 * cycle + 2, Some(&peer), false), None);
}

#[test]
fn discovery_advertises_constant_transmit_slots_and_data_waits_for_overlap() {
    let own = Mac([2, 0, 0, 0, 0, 1]);
    let peer = Mac([2, 0, 0, 0, 0, 2]);
    let mut cfg = config(own);
    cfg.channel = 149;
    cfg.strategy = Strategy::Pin;
    let mut engine = Engine::new(cfg, 0);
    let mut sequence = Sequence::fixed(149);
    sequence.slots[0] = [6, 0x51];
    engine.receive(&mif(peer, 518, 10, &sequence), 0).unwrap();
    engine.tick(0);
    assert!(!engine.send_ready(peer, 10_000));
    assert!(engine.send_ready(peer, SLOT_US + 10_000));
    let bytes = engine.action_frame_on_channel(3, 10_000, 6);
    let Body::Action(action) = protocol::parse(&bytes).unwrap().unwrap().body else {
        panic!("action frame");
    };
    assert_eq!(action.sequence, Some(Sequence::fixed(149)));
    engine.set_transmit_channel(44);
    let bytes = engine.action_frame_on_channel(3, 10_000, 44);
    let Body::Action(action) = protocol::parse(&bytes).unwrap().unwrap().body else {
        panic!("action frame");
    };
    assert_eq!(action.sequence, Some(Sequence::fixed(44)));
    assert!(!engine.send_ready(peer, SLOT_US + 10_000));
}
