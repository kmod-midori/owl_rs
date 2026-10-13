// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{
    channel::{ChannelDefinition, ChannelPlan},
    engine::{Config, Engine, Event},
    netlink::Netlink,
    protocol::{MAX_FRAME, Mac},
    rate::Rate,
};
use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use nix::errno::Errno;
use pcap::{Capture, Packet, PacketCodec, PacketHeader};
use std::{
    collections::VecDeque,
    path::Path,
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, watch},
    time,
};
use tracing::{debug, info, warn};
use tun_rs::{AsyncDevice, DeviceBuilder, Layer};
use wl_nl80211::Nl80211InterfaceType as IfType;

#[derive(Clone, Debug)]
pub struct Options {
    pub timeouts: crate::timeouts::Timeouts,
    pub input: String,
    pub host: String,
    pub listen_only: bool,
    pub duration: Option<u64>,
    pub save: Option<String>,
    pub save_invalid: Option<String>,
    pub summary: Option<String>,
    pub channel_plan: Option<ChannelPlan>,
    pub ibss_interface: Option<String>,
    /// Shared AP contexts must never be retuned.
    pub retune: bool,
}
fn tcp_frame(ethernet: &[u8]) -> bool {
    matches!(
        etherparse::SlicedPacket::from_ethernet(ethernet)
            .ok()
            .and_then(|p| p.transport),
        Some(etherparse::TransportSlice::Tcp(_))
    )
}
struct OwnedPacket {
    header: PacketHeader,
    data: Vec<u8>,
}
struct Codec;
impl PacketCodec for Codec {
    type Item = OwnedPacket;
    fn decode(&mut self, p: Packet<'_>) -> OwnedPacket {
        OwnedPacket {
            header: *p.header,
            data: p.data.to_vec(),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TuneRequest {
    channel: u8,
    max_width: u32,
}
async fn channel_worker(
    net: Netlink,
    iface: String,
    ibss: Option<String>,
    mut rx: mpsc::Receiver<TuneRequest>,
    results: mpsc::Sender<(TuneRequest, Result<ChannelDefinition>)>,
    timeouts: crate::timeouts::Timeouts,
) {
    while let Some(request) = rx.recv().await {
        let result = if let Some(ibss) = &ibss {
            time::timeout(
                timeouts.ibss_tune,
                crate::radio::tune_ibss(&net, ibss, request.channel, timeouts),
            )
            .await
            .context("IBSS retune timed out")
            .and_then(|result| result)
            .and_then(|()| ChannelDefinition::new(request.channel, 20).map_err(Into::into))
        } else {
            net.tune(&iface, request.channel, request.max_width).await
        };
        if results.send((request, result)).await.is_err() {
            break;
        }
    }
}
async fn neighbor_worker(net: Netlink, host: String, mut rx: mpsc::Receiver<Event>) {
    while let Some(event) = rx.recv().await {
        let (mac, add) = match event {
            Event::Added(mac) => (mac, true),
            Event::Removed(mac) => (mac, false),
        };
        let result = net.neighbor(&host, mac, add).await;
        if let Err(e) = result {
            warn!(%mac,"neighbor update failed: {e:#}");
        }
    }
}
pub async fn run(config: Config, opts: Options) -> Result<()> {
    live(config, &opts, None).await
}
async fn write_summary(engine: &Engine, path: Option<&str>) -> Result<()> {
    let text = serde_json::to_string_pretty(&engine.summary())?;
    if let Some(path) = path {
        tokio::fs::write(path, format!("{text}\n")).await?;
    } else {
        println!("{text}");
    }
    Ok(())
}
pub async fn replay(config: Config, opts: &Options) -> Result<()> {
    let mut cap = Capture::from_file(&opts.input).context("open capture")?;
    if cap.get_datalink() != pcap::Linktype::IEEE802_11_RADIOTAP {
        bail!("capture must use radiotap link type (127)");
    }
    let mut engine = Engine::new(config, 0);
    let mut first = None;
    let mut last_tick = 0;
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                let stamp = packet
                    .header
                    .ts
                    .tv_sec
                    .saturating_mul(1_000_000)
                    .saturating_add(packet.header.ts.tv_usec);
                let base = *first.get_or_insert(stamp);
                let now = (stamp - base).max(0) + 10_000_000;
                if now - last_tick >= 1_000_000 {
                    engine.tick(now);
                    last_tick = now;
                }
                if let Err(e) = engine.receive(packet.data, now) {
                    debug!("replay rejected frame: {e}");
                }
            }
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => return Err(e.into()),
        }
    }
    write_summary(&engine, opts.summary.as_deref()).await
}
pub struct Control {
    pub cancel: tokio_util::sync::CancellationToken,
    pub ready: Option<tokio::sync::oneshot::Sender<()>>,
    pub snapshot: watch::Sender<serde_json::Value>,
    pub(crate) policy: watch::Receiver<crate::visibility::Policy>,
    pub(crate) traffic: watch::Receiver<usize>,
}
pub async fn controlled(config: Config, opts: Options, control: Control) -> Result<()> {
    live(config, &opts, Some(control)).await
}
async fn live(mut config: Config, opts: &Options, mut control: Option<Control>) -> Result<()> {
    let net = Netlink::with_timeout(opts.timeouts.netlink)?;
    crate::radio::interface_name(&opts.input)?;
    crate::radio::interface_name(&opts.host)?;
    let radio = net.interface(&opts.input).await?;
    if radio.kind != IfType::Monitor {
        bail!("AWDL diagnostics require a prepared monitor interface");
    }
    let initial_definition = config
        .operating_channel
        .or_else(|| radio.channel_definition());
    config.operating_channel = initial_definition;
    // Before opening TAP, reject existing names rather than adopting another process's device.
    if !opts.listen_only && Path::new(&format!("/sys/class/net/{}", opts.host)).exists() {
        bail!("host interface {} already exists", opts.host);
    }
    let mut cap = Capture::from_device(opts.input.as_str())?
        .snaplen(MAX_FRAME as i32)
        .promisc(true)
        .immediate_mode(true)
        .timeout(opts.timeouts.capture_read.as_millis().max(1) as i32)
        .open()?
        .setnonblock()?;
    if cap.get_datalink() != pcap::Linktype::IEEE802_11_RADIOTAP {
        bail!("radio must supply radiotap frames");
    }
    cap.direction(pcap::Direction::In)?;
    cap.filter("wlan addr3 00:25:00:ff:94:73", true)?;
    let mut save = opts.save.as_ref().map(|p| cap.savefile(p)).transpose()?;
    let mut invalid = opts
        .save_invalid
        .as_ref()
        .map(|p| Capture::dead(pcap::Linktype::IEEE802_11_RADIOTAP)?.savefile(p))
        .transpose()?;
    let mut stream = cap.stream(Codec)?;
    let tap = if opts.listen_only {
        None
    } else {
        Some(
            DeviceBuilder::new()
                .name(&opts.host)
                .layer(Layer::L2)
                .mac_addr(config.mac.0)
                .mtu(HOST_MTU)
                .enable(false)
                .build_async()
                .context("create AWDL TAP")?,
        )
    };
    if tap.is_some() {
        // This TAP belongs to this operation. Disable DAD before the first up,
        // so there is no tentative-address startup delay or global sysctl change.
        tokio::fs::write(
            format!("/proc/sys/net/ipv6/conf/{}/accept_dad", opts.host),
            b"0\n",
        )
        .await?;
        net.address(&opts.host, config.mac).await?;
        net.set_up(&opts.host, true).await?;
    }
    if let Some(control) = &mut control
        && let Some(ready) = control.ready.take()
    {
        let _ = ready.send(());
    }
    let deadline = opts
        .duration
        .map(|seconds| {
            Instant::now()
                .checked_add(Duration::from_secs(seconds))
                .context("duration exceeds the monotonic clock range")
        })
        .transpose()?
        .map(time::Instant::from);
    // Signal setup can fail; do it before spawning owned workers.
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut usr1 = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())?;
    let (neigh_tx, neigh_rx) = mpsc::channel(1024);
    let neigh_task = tokio::spawn(neighbor_worker(net.clone(), opts.host.clone(), neigh_rx));
    let (channel_tx, channel_rx) = mpsc::channel(1);
    let (result_tx, mut result_rx) = mpsc::channel(1);
    let channel_task = tokio::spawn(channel_worker(
        net.clone(),
        opts.input.clone(),
        opts.ibss_interface.clone(),
        channel_rx,
        result_tx,
        opts.timeouts,
    ));
    let mut plan = opts.channel_plan.clone();
    let mut applied_definition = initial_definition;
    let mut applied_request = initial_definition.map(|d| TuneRequest {
        channel: d.channel,
        max_width: if opts.channel_plan.is_some() {
            20
        } else {
            d.width_mhz
        },
    });
    let mut pending_channel = None;
    let start = Instant::now();
    let advertised_port = config.airdrop_port;
    let mut engine = Engine::new(config, 0);
    let mut clean = time::interval(Duration::from_secs(1));
    let mut stats = time::interval(Duration::from_secs(10));
    let mut scheduler = time::interval(Duration::from_micros(500));
    scheduler.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let mut host_buf = vec![0; MAX_FRAME];
    let mut queue: VecDeque<PendingPacket> = VecDeque::new();
    let mut psf_at = 110 * 1024;
    let mut mif_at = 0;
    let mut last_tcp = None;
    let mut draining = None;
    let mut last_traffic = 0;
    info!("WLAN device: {} (addr {})", opts.input, engine.config.mac);
    if tap.is_some() {
        info!("Host device: {}", opts.host);
    }
    let result: Result<()> = async {
        loop {
            tokio::select! {
                _ = wait_cancel(&control), if draining.is_none() => {
                    draining = Some(elapsed_us(start));
                },
                _ = tokio::signal::ctrl_c(), if draining.is_none() => {
                    if control.is_none() { break; }
                    draining = Some(elapsed_us(start));
                },
                _ = term.recv(), if draining.is_none() => {
                    if control.is_none() { break; }
                    draining = Some(elapsed_us(start));
                },
                _ = wait_deadline(deadline) => break,
                _ = usr1.recv() => info!(?engine.stats, "STATISTICS"),
                _ = stats.tick() => log_stats(&engine),
                response = result_rx.recv(), if pending_channel.is_some() => {
                    let (request, result) = response.context("channel worker stopped")?;
                    pending_channel = None;
                    match result {
                        Ok(definition) => {
                            applied_definition = Some(definition);
                            applied_request = Some(request);
                            engine.set_operating_channel(definition);
                            mif_at = 0;
                            psf_at = 0;
                            info!(?definition, "committed AWDL channel definition");
                        }
                        Err(error) => {
                            warn!(channel=request.channel, "channel request failed: {error:#}");
                            if let Some(plan) = &mut plan { plan.failed(request.channel); }
                            else { return Err(error); }
                        }
                    }
                },
                _ = clean.tick() => {
                    let now = elapsed_us(start);
                    for event in engine.tick(now) {
                        if tap.is_some() {
                            neigh_tx.send(event).await.context("neighbor task stopped")?;
                        }
                    }
                    if let Some(c) = &control {
                        let mut snapshot = serde_json::to_value(engine.summary())?;
                        if let Some(plan) = &plan { snapshot["channel_plan"] = serde_json::to_value(plan)?; }
                        snapshot["physical_channel"] = serde_json::to_value(applied_definition.map(|d| d.channel))?;
                        snapshot["physical_channel_definition"] = serde_json::to_value(applied_definition)?;
                        let _ = c.snapshot.send(snapshot);
                    }
                },
                packet = stream.next() => {
                    let packet = packet.context("radio stream ended")??;
                    let view = Packet { header: &packet.header, data: &packet.data };
                    if let Some(save) = &mut save {
                        save.write(&view);
                    }
                    match engine.receive(&packet.data, elapsed_us(start)) {
                        Ok((frames, events)) => {
                            for event in events {
                                if tap.is_some() {
                                    neigh_tx.send(event).await.context("neighbor task stopped")?;
                                }
                            }
                            if let Some(tap) = &tap {
                                for frame in frames {
                                    if tcp_frame(&frame) { last_tcp = Some(elapsed_us(start)); }
                                    send_tap(tap, &frame).await.context("deliver AWDL Ethernet frame to TAP")?;
                                }
                            }
                        },
                        Err(e) => {
                            debug!("rejected frame: {e}");
                            if let Some(save) = &mut invalid {
                                save.write(&view);
                            }
                        },
                    }
                },
                received = receive_tap(&tap, &mut host_buf), if tap.is_some() && queue.len() < 128 => {
                    let len = received?;
                    if len >= 14 {
                        last_traffic = elapsed_us(start);
                        queue.push_back(PendingPacket::new(host_buf[..len].to_vec(), last_traffic));
                    }
                },
                _ = scheduler.tick() => {
                    let now = elapsed_us(start);
                    // HTTP/TLS shutdown only writes into the kernel/TAP. Keep AWDL
                    // alive until queued replies, FINs and discovery goodbyes have
                    // been injected, with a quiet interval for their ACKs. A lost
                    // peer cannot prolong restoration past the configured drain budget.
                    if let Some(since) = draining
                        && (now - since >= opts.timeouts.radio_drain.as_micros() as i64
                            || (queue.is_empty() && now - since >= opts.timeouts.radio_quiet.as_micros() as i64
                                && now - last_traffic >= opts.timeouts.radio_quiet.as_micros() as i64)) {
                        break;
                    }
                    // Observation must not retune an interface owned by another session.
                    if opts.listen_only { continue; }
                    // Only one tune can be in flight. Invalidating immediately prevents
                    // injection on the old channel while the kernel changes frequency.
                    if pending_channel.is_some() { continue; }
                    let desired = if let Some(plan) = &mut plan {
                        let parent = engine.peers.get(&engine.election.sync)
                            .filter(|p| p.valid).and_then(|p| p.sequence.as_ref());
                        // Discover/TLS traffic stays on discovery. An approved
                        // transfer holds its chosen channel, including final TCP
                        // acknowledgements queued after its transport lease ends.
                        let busy = control.as_ref().is_some_and(|c| *c.traffic.borrow() > 0)
                            || (!plan.discovering && (
                                last_tcp.is_some_and(|t| now - t < opts.timeouts.queued_packet.as_micros() as i64)
                                || queue.iter().any(|p| tcp_frame(&p.ethernet))
                            ));
                        plan.desired(parent, busy).context("no usable AWDL channel remains")?
                    } else { engine.current_channel(now) };
                    let request = TuneRequest {
                        channel: desired,
                        max_width: if desired == 6 || opts.ibss_interface.is_some()
                            || plan.as_ref().is_some_and(|p| p.discovering) { 20 } else { 80 },
                    };
                    if desired != 0 && opts.retune && applied_request != Some(request) {
                        applied_definition = None;
                        pending_channel = Some(request);
                        channel_tx.send(request).await.context("channel worker stopped")?;
                        continue;
                    }
                    if let Some(plan) = &mut plan
                        && applied_definition.is_some_and(|d| d.channel == desired) {
                        plan.applied(desired);
                    }
                    let on_channel = desired != 0 && applied_definition.is_some_and(|d| d.channel == desired);
                    if on_channel {
                        if let Some(control) = &control {
                            engine.config.airdrop_port = control.policy.borrow().mode.enabled().then_some(advertised_port).flatten();
                        }
                        if now >= mif_at {
                            if !inject(stream.capture_mut(), &engine.action_frame_on_channel(3, now, desired))? { continue; }
                            if engine.stats.tx_action == 0 {
                                debug!(channel=desired, "first AWDL action frame submitted to radio");
                            }
                            engine.stats.tx_action += 1;
                            mif_at = now + engine.clock.next_us(now) + SLOT_MIDDLE;
                        }
                        if now >= psf_at {
                            if !inject(stream.capture_mut(), &engine.action_frame_on_channel(0, now, desired))? { continue; }
                            engine.stats.tx_action += 1;
                            psf_at = now + 110 * 1024;
                        }
                        // Inspect the whole bounded queue: an unavailable unicast peer must
                        // not block multicast or traffic for another available peer.
                        for _ in 0..queue.len() {
                            let Some(mut packet) = queue.pop_front() else { break; };
                            let dst = Mac(packet.ethernet[..6].try_into()?);
                            if dst == engine.config.mac {
                                if let Some(tap) = &tap {
                                    send_tap(tap, &packet.ethernet).await.context("deliver AWDL Ethernet frame to TAP")?;
                                }
                                continue;
                            }
                            // Injection of earlier packets can consume part of a slot.
                            // Recheck current time and the applied channel for every frame.
                            let transmit_now = elapsed_us(start);
                            let known = dst.multicast() || engine.peers.get(&dst).is_some_and(|p| p.valid);
                            if transmit_now - packet.queued_us > opts.timeouts.queued_packet.as_micros() as i64 || !known {
                                engine.stats.dropped += 1;
                                continue;
                            }
                            if applied_definition.is_none_or(|d| d.channel != engine.current_channel(transmit_now)) {
                                queue.push_back(packet);
                                continue;
                            }
                            match packet.transmit(&mut engine, transmit_now, |bytes| inject(stream.capture_mut(), bytes))? {
                                Transmission::Sent => {
                                    last_traffic = transmit_now;
                                    engine.stats.tx_data += 1;
                                    if dst.multicast() {
                                        engine.stats.tx_multicast += 1;
                                    } else {
                                        if tcp_frame(&packet.ethernet) { last_tcp = Some(transmit_now); }
                                        engine.stats.tx_unicast += 1;
                                    }
                                },
                                Transmission::WaitForSlot => queue.push_back(packet),
                                Transmission::QueueFull => {
                                    engine.stats.tx_backpressure += 1;
                                    queue.push_front(packet);
                                    // Yield to RX/TAP and recheck the slot on the next tick.
                                    break;
                                },
                                Transmission::Invalid => engine.stats.dropped += 1,
                            }
                        }
                    }
                },
            }
        }
        Ok(())
    }.await;
    // Drop nonpersistent TAP and finish owned tasks on success AND failure.
    drop(neigh_tx);
    drop(channel_tx);
    drop(tap);
    neigh_task.abort();
    channel_task.abort();
    let _ = neigh_task.await;
    let _ = channel_task.await;
    if let Some(save) = &mut save {
        save.flush()?;
    }
    if let Some(save) = &mut invalid {
        save.flush()?;
    }
    if control.is_none() || opts.summary.is_some() {
        write_summary(&engine, opts.summary.as_deref()).await?;
    }
    result
}
/// Match C OWL: leave room for radiotap, 802.11, LLC, and AWDL headers.
pub const HOST_MTU: u16 = 1450;
const SLOT_MIDDLE: i64 = 32 * 1024;
async fn receive_tap(tap: &Option<AsyncDevice>, buf: &mut [u8]) -> std::io::Result<usize> {
    if let Some(tap) = tap {
        tap.recv(buf).await
    } else {
        std::future::pending().await
    }
}

fn elapsed_us(start: Instant) -> i64 {
    start.elapsed().as_micros().min(i64::MAX as u128) as i64
}
async fn wait_deadline(deadline: Option<time::Instant>) {
    match deadline {
        Some(deadline) => time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}
// libpcap's sendpacket reports only text; capture errno synchronously before
// any logging or await. Clear stale errno so unrelated failures cannot retry.
fn inject(cap: &mut Capture<pcap::Active>, bytes: &[u8]) -> Result<bool, pcap::Error> {
    Errno::clear();
    let result = cap.sendpacket(bytes);
    injection_result(result, Errno::last())
}
fn injection_result(result: Result<(), pcap::Error>, errno: Errno) -> Result<bool, pcap::Error> {
    match result {
        Ok(()) => Ok(true),
        Err(_) if matches!(errno, Errno::EAGAIN | Errno::ENOBUFS) => Ok(false),
        Err(error) => Err(error),
    }
}
struct PendingPacket {
    ethernet: Vec<u8>,
    queued_us: i64,
    encoded: Option<(Rate, Vec<u8>)>,
}
enum Transmission {
    Sent,
    WaitForSlot,
    QueueFull,
    Invalid,
}
impl PendingPacket {
    fn new(ethernet: Vec<u8>, queued_us: i64) -> Self {
        Self {
            ethernet,
            queued_us,
            encoded: None,
        }
    }
    fn transmit(
        &mut self,
        engine: &mut Engine,
        now: i64,
        mut send: impl FnMut(&[u8]) -> Result<bool, pcap::Error>,
    ) -> Result<Transmission, pcap::Error> {
        let dst = Mac(self.ethernet[..6]
            .try_into()
            .expect("checked Ethernet header"));
        if !engine.send_ready(dst, now) {
            return Ok(Transmission::WaitForSlot);
        }
        let rate = engine.data_rate(dst);
        if let Some((previous, bytes)) = &mut self.encoded {
            if *previous != rate {
                // A retune/capability update must not reuse an over-wide PHY header.
                // Preserve the queued packet's 802.11/AWDL sequence numbers.
                let old_len = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
                let Ok(header) = crate::protocol::radiotap_tx(
                    rate,
                    engine.config.fixed_radio && !dst.multicast(),
                    false,
                ) else {
                    return Ok(Transmission::Invalid);
                };
                bytes.splice(..old_len, header);
                *previous = rate;
            }
        } else {
            let Ok(encoded) = engine.data_frame(&self.ethernet, rate) else {
                return Ok(Transmission::Invalid);
            };
            self.encoded = Some((rate, encoded));
        }
        // Both Ethernet bytes and AWDL sequence numbers survive backpressure.
        let (_, bytes) = self.encoded.as_ref().expect("encoded packet");
        Ok(if send(bytes)? {
            Transmission::Sent
        } else {
            Transmission::QueueFull
        })
    }
}
async fn send_tap(tap: &AsyncDevice, frame: &[u8]) -> Result<()> {
    if tap.send(frame).await? != frame.len() {
        bail!("partial TAP frame write");
    }
    Ok(())
}
fn log_stats(engine: &Engine) {
    let s = &engine.stats;
    info!(
        "STATS tx_action {} tx_data {} tx_unicast {} tx_multicast {} | rx_action {} rx_data {} rx_unknown {} | tx_backpressure {} dropped {}",
        s.tx_action,
        s.tx_data,
        s.tx_unicast,
        s.tx_multicast,
        s.rx_action,
        s.rx_data,
        s.rx_unknown,
        s.tx_backpressure,
        s.dropped,
    );
}

async fn wait_cancel(control: &Option<Control>) {
    if let Some(c) = control {
        c.cancel.cancelled().await;
    } else {
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        channel::{SLOT_US, SLOTS, Sequence, Strategy},
        protocol::{self, Advertisement, Election},
    };

    #[test]
    fn injection_backpressure_preserves_packet_and_rechecks_peer_slot() {
        let own = Mac([2, 0, 0, 0, 0, 1]);
        let peer = Mac([2, 0, 0, 0, 0, 2]);
        let mut engine = Engine::new(
            Config {
                peer_timeout: crate::timeouts::Timeouts::default().peer_idle,
                retry_timeout: crate::timeouts::Timeouts::default().retry_cache,
                pending_timeout: crate::timeouts::Timeouts::default().queued_packet,
                mac: own,
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
                rate: Rate::default(),
                capabilities: Default::default(),
                operating_channel: None,
            },
            0,
        );
        let mut sequence = Sequence::fixed(149);
        sequence.slots[0] = [6, 0x51];
        let mif = protocol::encode_action(
            &Advertisement {
                mac: peer,
                name: "fixture",
                capabilities: &Default::default(),
                sequence: &sequence,
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
        engine.receive(&mif, 0).unwrap();
        let mut ethernet = vec![];
        ethernet.extend(peer.0);
        ethernet.extend(own.0);
        ethernet.extend([0x86, 0xdd]);
        ethernet.extend([0x60; 48]);
        let mut packet = PendingPacket::new(ethernet.clone(), 0);
        let mut attempts = vec![];
        for errno in [Errno::EAGAIN, Errno::ENOBUFS] {
            assert!(matches!(
                packet
                    .transmit(&mut engine, 10_000, |bytes| {
                        attempts.push(bytes.to_vec());
                        injection_result(Err(pcap::Error::PcapError("queue full".into())), errno)
                    })
                    .unwrap(),
                Transmission::QueueFull
            ));
        }
        assert_eq!(attempts[0], attempts[1]);
        assert_eq!(packet.ethernet, ethernet);
        assert_eq!(packet.queued_us, 0);
        assert!(matches!(
            packet
                .transmit(&mut engine, SLOT_US + 10_000, |_| panic!(
                    "must not inject after the peer changes channel"
                ))
                .unwrap(),
            Transmission::WaitForSlot
        ));
        assert!(matches!(
            packet
                .transmit(&mut engine, SLOT_US * SLOTS as i64 + 10_000, |bytes| {
                    assert_eq!(bytes, attempts[0]);
                    injection_result(Ok(()), Errno::EAGAIN)
                })
                .unwrap(),
            Transmission::Sent
        ));
        // Retuning while a VHT packet is backpressured updates only radiotap.
        let caps = protocol::BandCapabilities {
            ht: Some(protocol::HtCapabilities {
                cap_info: 0x6e,
                ampdu_params: 3,
                rx_mask: [255, 255, 0, 0],
                tx_mask: Some([255, 255, 0, 0]),
            }),
            vht: Some(protocol::VhtCapabilities {
                cap_info: 1 << 5,
                rx_mcs_map: 0xfffa,
                tx_mcs_map: 0xfffa,
                rx_highest: 0,
                tx_highest: 0,
            }),
        };
        let definition = crate::channel::ChannelDefinition::new(149, 80).unwrap();
        engine.config.rate = "vht9-nss2-bw80-sgi".parse().unwrap();
        engine.config.capabilities.ghz5 = caps.clone();
        engine.peers.get_mut(&peer).unwrap().capabilities = caps;
        engine.peers.get_mut(&peer).unwrap().sequence =
            Some(Sequence::fixed_definition(definition));
        engine.set_operating_channel(definition);
        let mut packet = PendingPacket::new(ethernet, 0);
        let mut first = vec![];
        assert!(matches!(
            packet
                .transmit(&mut engine, 10_000, |bytes| {
                    first = bytes.to_vec();
                    Ok(false)
                })
                .unwrap(),
            Transmission::QueueFull
        ));
        engine.set_operating_channel(crate::channel::ChannelDefinition::new(149, 20).unwrap());
        assert!(matches!(
            packet
                .transmit(&mut engine, 10_000, |bytes| {
                    let (rt, data) = radiotap::Radiotap::parse(bytes).unwrap();
                    assert_eq!(rt.vht.unwrap().bw.unwrap().bandwidth, 20);
                    assert_eq!(rt.vht.unwrap().users[0].unwrap().index, 8);
                    assert_eq!(data, radiotap::Radiotap::parse(&first).unwrap().1);
                    Ok(true)
                })
                .unwrap(),
            Transmission::Sent
        ));
        assert!(
            injection_result(
                Err(pcap::Error::PcapError("device gone".into())),
                Errno::ENODEV
            )
            .is_err()
        );
        assert!(
            injection_result(
                Err(pcap::Error::PcapError("unspecified".into())),
                Errno::from_raw(0)
            )
            .is_err()
        );
    }
}
