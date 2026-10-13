// SPDX-License-Identifier: GPL-3.0-or-later
use owl_rs::{
    channel::{Clock, Encoding, SLOT_US, Sequence, Strategy},
    engine::{Config, Engine},
    protocol::{self, Advertisement, Body, Election, Mac, Rate},
};
fn config(mac: Mac) -> Config {
    Config {
        peer_timeout: owl_rs::timeouts::Timeouts::default().peer_idle,
        retry_timeout: owl_rs::timeouts::Timeouts::default().retry_cache,
        pending_timeout: owl_rs::timeouts::Timeouts::default().queued_packet,
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
        capabilities: Default::default(),
        operating_channel: None,
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
            capabilities: &Default::default(),
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
                capabilities: &Default::default(),
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
fn early_syns_wait_for_peer_validation_and_are_bounded_deduplicated_and_expired() {
    let own = Mac([2, 0, 0, 0, 0, 1]);
    let peer = Mac([2, 0, 0, 0, 0, 2]);
    let syn = |source: Mac, destination: Mac, seq: u32, payload: &[u8]| {
        let mut ethernet = Vec::new();
        etherparse::PacketBuilder::ethernet2(source.0, destination.0)
            .ipv6(source.ipv6().octets(), destination.ipv6().octets(), 64)
            .tcp(12345, 8771, seq, 65535)
            .syn()
            .write(&mut ethernet, payload)
            .unwrap();
        let frame = protocol::encode_data(
            &ethernet,
            seq as u16,
            seq as u16,
            Rate::default(),
            false,
            false,
        )
        .unwrap();
        (ethernet, frame)
    };
    let mut engine = Engine::new(config(own), 0);
    let (ethernet, frame) = syn(peer, own, 1, &[]);
    assert!(engine.receive(&frame, 0).unwrap().0.is_empty());
    assert!(engine.receive(&frame, 1).unwrap().0.is_empty());
    assert!(engine.peers.is_empty());
    assert_eq!(engine.stats.rx_syn_buffered, 1);
    // Foreign unicast and SYNs containing application data are never staged.
    engine
        .receive(&syn(peer, Mac([2, 0, 0, 0, 0, 3]), 2, &[]).1, 2)
        .unwrap();
    engine.receive(&syn(peer, own, 3, &[1]).1, 3).unwrap();
    assert_eq!(engine.stats.rx_syn_buffered, 1);
    let (released, _) = engine
        .receive(&mif(peer, 518, 1, &Sequence::fixed(6)), 4)
        .unwrap();
    assert_eq!(released, [ethernet]);
    assert_eq!(engine.stats.rx_syn_released, 1);
    assert!(
        engine
            .receive(&mif(peer, 518, 1, &Sequence::fixed(6)), 5)
            .unwrap()
            .0
            .is_empty()
    );
    let mut expired = Engine::new(config(own), 0);
    expired.receive(&frame, 0).unwrap();
    assert!(
        expired
            .receive(&mif(peer, 518, 1, &Sequence::fixed(6)), 2_000_000)
            .unwrap()
            .0
            .is_empty()
    );
    assert_eq!(expired.stats.rx_syn_expired, 1);
    let mut bounded = Engine::new(config(own), 0);
    for n in 0..130 {
        bounded.receive(&syn(peer, own, n, &[]).1, 0).unwrap();
    }
    assert_eq!(bounded.stats.dropped, 2);
    assert_eq!(
        bounded
            .receive(&mif(peer, 518, 1, &Sequence::fixed(6)), 1)
            .unwrap()
            .0
            .len(),
        128
    );
}

#[test]
fn discovery_plan_ranks_overlap_and_falls_back_without_publishing_failed_tunes() {
    use owl_rs::channel::ChannelPlan;
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
    assert_eq!(plan.desired(Some(&peer), false), Some(6));
    assert!(plan.discovering);
    assert!(!plan.applied(6));
    assert_eq!(plan.desired(Some(&peer), true), Some(149));
    assert!(!plan.discovering);
    // A request alone, including a failed request, cannot alter the schedule.
    assert_eq!(plan.transmit_channel, 6);
    plan.failed(149);
    assert_eq!(plan.desired(Some(&peer), true), Some(44));
    assert!(plan.applied(44));
    assert_eq!(plan.transmit_channel, 44);
    // A paused exchange or a changed sync parent must not trigger discovery
    // visits or channel hopping. The next exchange re-evaluates the schedule.
    assert_eq!(plan.desired(Some(&Sequence::fixed(6)), true), Some(44));
    assert_eq!(plan.desired(None, true), Some(44));
    assert_eq!(plan.desired(Some(&peer), false), Some(6));
    assert!(plan.discovering);
    assert!(!plan.applied(6));
    assert_eq!(plan.transmit_channel, 44);
    assert_eq!(plan.desired(Some(&Sequence::fixed(6)), true), Some(6));
    assert!(!plan.discovering); // Channel 6 can itself be the best transfer channel.
    assert!(plan.applied(6));
    plan.failed(44);
    plan.failed(6);
    assert_eq!(plan.desired(Some(&peer), true), None);
    assert_eq!(plan.desired(Some(&peer), false), None);
}

#[test]
fn discovery_and_transfer_advertise_committed_channels_and_wait_for_overlap() {
    let own = Mac([2, 0, 0, 0, 0, 1]);
    let peer = Mac([2, 0, 0, 0, 0, 2]);
    let mut cfg = config(own);
    cfg.channel = 6;
    cfg.strategy = Strategy::Pin;
    let mut engine = Engine::new(cfg, 0);
    let mut sequence = Sequence::fixed(149);
    sequence.slots[0] = [6, 0x51];
    engine.receive(&mif(peer, 518, 10, &sequence), 0).unwrap();
    engine.tick(0);
    assert!(engine.send_ready(peer, 10_000));
    assert!(!engine.send_ready(peer, SLOT_US + 10_000));
    let bytes = engine.action_frame_on_channel(3, 10_000, 6);
    let Body::Action(action) = protocol::parse(&bytes).unwrap().unwrap().body else {
        panic!("action frame");
    };
    assert_eq!(action.sequence, Some(Sequence::fixed(6)));
    engine.set_operating_channel(owl_rs::channel::ChannelDefinition::new(149, 20).unwrap());
    assert!(!engine.send_ready(peer, 10_000));
    assert!(engine.send_ready(peer, SLOT_US + 10_000));
    let bytes = engine.action_frame_on_channel(3, 10_000, 149);
    let Body::Action(action) = protocol::parse(&bytes).unwrap().unwrap().body else {
        panic!("action frame");
    };
    assert_eq!(action.sequence, Some(Sequence::fixed(149)));
    engine.set_operating_channel(owl_rs::channel::ChannelDefinition::new(6, 20).unwrap());
    assert!(engine.send_ready(peer, 10_000));
    assert!(!engine.send_ready(peer, SLOT_US + 10_000));
    for (width, class) in [(80, 128), (40, 126), (20, 124)] {
        let definition = owl_rs::channel::ChannelDefinition::new(149, width).unwrap();
        engine.set_operating_channel(definition);
        engine.tick(10_000); // Following a parent must not erase the confirmed width.
        for subtype in [0, 3] {
            let bytes = engine.action_frame_on_channel(subtype, 10_000, 149);
            let Body::Action(action) = protocol::parse(&bytes).unwrap().unwrap().body else {
                panic!("action frame")
            };
            assert_eq!(action.sequence.unwrap().slots, [[149, class]; 16]);
        }
    }
    let mut sparse =
        Sequence::fixed_definition(owl_rs::channel::ChannelDefinition::new(149, 80).unwrap());
    sparse.slots[1] = [0, 0];
    let mut cfg = config(own);
    cfg.channel = 149;
    cfg.fixed_radio = false;
    cfg.operating_channel = Some(owl_rs::channel::ChannelDefinition::new(149, 20).unwrap());
    let mut shared = Engine::new(cfg, 0);
    shared.receive(&mif(peer, 518, 10, &sparse), 0).unwrap();
    shared.tick(0);
    // A wider parent must not overwrite our AP's width or unavailable slots.
    assert_eq!(shared.sequence.slots[0], [149, 124]);
    assert_eq!(shared.sequence.slots[1], [0, 0]);
}

#[test]
fn hardware_capabilities_use_current_band_and_awdl_wire_layout() {
    use protocol::{BandCapabilities, HtCapabilities, RadioCapabilities, VhtCapabilities};
    fn tags(frame: &[u8]) -> std::collections::BTreeMap<u8, Vec<u8>> {
        let rt_len = u16::from_le_bytes([frame[2], frame[3]]) as usize;
        let mut bytes = &frame[rt_len + 24 + 16..];
        let mut tags = std::collections::BTreeMap::new();
        while !bytes.is_empty() {
            let len = u16::from_le_bytes([bytes[1], bytes[2]]) as usize;
            tags.insert(bytes[0], bytes[3..3 + len].to_vec());
            bytes = &bytes[3 + len..];
        }
        tags
    }
    let ht = HtCapabilities {
        cap_info: 0x01ff,
        ampdu_params: 3,
        rx_mask: [255, 255, 0, 0],
    };
    let mut cfg = config(Mac([2, 0, 0, 0, 0, 1]));
    cfg.capabilities = RadioCapabilities {
        ghz2: BandCapabilities {
            ht: Some(ht.clone()),
            vht: None,
        },
        ghz5: BandCapabilities {
            ht: Some(ht),
            vht: Some(VhtCapabilities {
                cap_info: 0x338001b0,
                rx_mcs_map: 0xfffa,
                rx_highest: 0x1234,
                tx_mcs_map: 0xfffa,
                tx_highest: 0x5678,
            }),
        },
    };
    let mut engine = Engine::new(cfg, 0);
    let two = tags(&engine.action_frame_on_channel(3, 0, 6));
    assert_eq!(two[&7], [0, 0, 0xff, 1, 3, 0xff, 0xff, 0, 0]);
    assert!(!two.contains_key(&17));
    let five = tags(&engine.action_frame_on_channel(3, 0, 149));
    assert_eq!(five[&7], two[&7]);
    assert_eq!(
        five[&17],
        [
            191, 12, 0xb0, 1, 0x80, 0x33, 0xfa, 0xff, 0x34, 0x12, 0xfa, 0xff, 0x78, 0x56
        ]
    );
    for (mask, expected) in [
        ([0xff, 0, 0, 0], vec![0, 0, 0xff, 1, 3, 0xff, 0, 0]),
        (
            [0xff, 0xff, 0xff, 0x7f],
            vec![0, 0, 0xff, 1, 3, 0xff, 0xff, 0xff, 0x7f, 0, 0],
        ),
    ] {
        engine.config.capabilities.ghz2.ht.as_mut().unwrap().rx_mask = mask;
        assert_eq!(tags(&engine.action_frame_on_channel(3, 0, 6))[&7], expected);
    }
    let psf = tags(&engine.action_frame_on_channel(0, 0, 149));
    assert!(!psf.contains_key(&7) && !psf.contains_key(&17));
    engine.config.capabilities = RadioCapabilities::default();
    let absent = tags(&engine.action_frame_on_channel(3, 0, 149));
    assert!(!absent.contains_key(&7) && !absent.contains_key(&17));
}
