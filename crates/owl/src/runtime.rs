// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{
    channel::{ChannelDefinition, ChannelPlan},
    engine::{Config, Engine, Event},
    netlink::Netlink,
    protocol::MAX_FRAME,
    tx,
};
use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use nix::errno::Errno;
use pcap::{Capture, Packet, PacketCodec, PacketHeader};
use std::{
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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
    pub max_bandwidth: u32,
    /// Shared AP contexts must never be retuned.
    pub retune: bool,
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
            Event::AddBaRequest { .. } | Event::DelBa { .. } => continue,
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
    pub(crate) policy: watch::Receiver<bool>,
    pub(crate) traffic: watch::Receiver<owl_ipc::TransferState>,
    pub(crate) channel_ready: watch::Sender<Option<u64>>,
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
    let monitor_limit = net.mtu(&opts.input).await? as usize;
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
        .tstamp_type(pcap::TimestampType::Host)
        .precision(pcap::Precision::Micro)
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
    let mut capture_clock = CaptureClock::new(wall_us(), elapsed_us(start));
    if let Some(clock_epoch_us) = capture_clock.epoch_us {
        info!(clock_epoch_us, "AWDL runtime clock");
    }
    let advertised_port = config.airdrop_port;
    let mut engine = Engine::new(config, 0);
    let mut clean = time::interval(Duration::from_secs(1));
    let mut stats = time::interval(Duration::from_secs(10));
    let mut scheduler = time::interval(Duration::from_micros(500));
    scheduler.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let mut host_buf = vec![0; MAX_FRAME];
    let mut queue = tx::Queue::default();
    let mut psf_at = 110 * 1024;
    let mut mif_at = 0;
    let mut keepalive_at = 0;
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
                        if let Event::Removed(peer) = &event { queue.cancel_ba(*peer, None); }
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
                    let received = capture_clock.receive_time(
                        packet.header.ts.tv_sec, packet.header.ts.tv_usec,
                        wall_us(), elapsed_us(start),
                    );
                    let view = Packet { header: &packet.header, data: &packet.data };
                    if let Some(save) = &mut save {
                        save.write(&view);
                    }
                    match engine.receive(&packet.data, received) {
                        Ok((frames, events)) => {
                            for event in events {
                                match event {
                                    Event::AddBaRequest { peer, request } => {
                                        if !opts.listen_only && draining.is_none() {
                                            queue.respond_addba(&mut engine, peer, request, elapsed_us(start));
                                        }
                                    }
                                    Event::DelBa { peer, tid } => queue.cancel_ba(peer, Some(tid)),
                                    event => if tap.is_some() {
                                        neigh_tx.send(event).await.context("neighbor task stopped")?;
                                    },
                                }
                            }
                            if let Some(tap) = &tap {
                                for frame in frames {
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
                received = receive_tap(&tap, &mut host_buf), if tap.is_some() && queue.len() < tx::QUEUE_LIMIT => {
                    let len = received?;
                    if len >= 14 {
                        last_traffic = elapsed_us(start);
                        if host_buf[..6] == engine.config.mac.0 {
                            if let Some(tap) = &tap { send_tap(tap, &host_buf[..len]).await?; }
                        } else { queue.push(host_buf[..len].to_vec(), last_traffic); }
                    }
                },
                _ = scheduler.tick() => {
                    let now = elapsed_us(start);
                    let released = engine.reorder.poll(now);
                    if let Some(tap) = &tap {
                        for frame in released {
                            send_tap(tap, &frame).await.context("deliver reordered AWDL frame")?;
                        }
                    }
                    // HTTP/TLS shutdown only writes into the kernel/TAP. Keep AWDL
                    // alive until queued replies, FINs and discovery goodbyes have
                    // been injected, with a quiet interval for their ACKs. A lost
                    // peer cannot prolong restoration past the configured drain budget.
                    if let Some(since) = draining
                        && (now - since >= opts.timeouts.radio_drain.as_micros() as i64
                            || (queue.is_idle(now, opts.timeouts.radio_quiet.as_micros() as i64)
                                && !engine.has_pending_tx(now)
                                && !engine.reorder.pending()
                                && now - since >= opts.timeouts.radio_quiet.as_micros() as i64
                                && now - last_traffic >= opts.timeouts.radio_quiet.as_micros() as i64)) {
                        break;
                    }
                    // Observation must not retune an interface owned by another session.
                    if opts.listen_only { continue; }
                    // Only one tune can be in flight. Invalidating immediately prevents
                    // injection on the old channel while the kernel changes frequency.
                    if pending_channel.is_some() { continue; }
                    // Selection and its readiness reply must use the same revision.
                    // A concurrent new transfer must not acknowledge discovery tuning.
                    let transfer_state = control.as_ref()
                        .map(|c| *c.traffic.borrow()).unwrap_or_default();
                    let desired = if let Some(plan) = &plan {
                        plan.desired().context("scheduled AWDL channel is unavailable")?
                    } else { engine.current_channel(now) };
                    let request = TuneRequest {
                        channel: desired,
                        max_width: if desired == 6 || opts.ibss_interface.is_some() { 20 } else { opts.max_bandwidth },
                    };
                    if desired != 0 && opts.retune && applied_request != Some(request) {
                        applied_definition = None;
                        pending_channel = Some(request);
                        channel_tx.send(request).await.context("channel worker stopped")?;
                        continue;
                    }
                    let on_channel = desired != 0 && applied_definition.is_some_and(|d| d.channel == desired);
                    if on_channel {
                        // Acknowledge only after the chosen channel/width is committed.
                        // Keep this independent of snapshots and peer slot availability.
                        if let Some(control) = &control
                            && transfer_state.transfers > 0 {
                            control.channel_ready.send_if_modified(|ready| {
                                if *ready == Some(transfer_state.epoch) { return false; }
                                *ready = Some(transfer_state.epoch);
                                true
                            });
                        }
                        if let Some(control) = &control {
                            engine.config.airdrop_port = (*control.policy.borrow()).then_some(advertised_port).flatten();
                        }
                        if now >= mif_at {
                            let mut frame = engine.action_frame_on_channel(3, now, desired);
                            crate::protocol::stamp_action_tx(&mut frame, elapsed_us(start))?;
                            if !inject(stream.capture_mut(), &frame)? { continue; }
                            if engine.stats.tx_action == 0 {
                                debug!(channel=desired, "first AWDL action frame submitted to radio");
                            }
                            engine.stats.tx_action += 1;
                            mif_at = now + engine.clock.next_us(now) + SLOT_MIDDLE;
                        }
                        if now >= psf_at {
                            let mut frame = engine.action_frame_on_channel(0, now, desired);
                            crate::protocol::stamp_action_tx(&mut frame, elapsed_us(start))?;
                            if !inject(stream.capture_mut(), &frame)? { continue; }
                            engine.stats.tx_action += 1;
                            psf_at = now + 110 * 1024;
                        }
                        // Neighbor-learning probes belong to the link, not mDNS.
                        if draining.is_none() && now >= keepalive_at {
                            for peer in engine.peers.values().filter(|peer| peer.valid) {
                                if queue.len() == tx::QUEUE_LIMIT { break; }
                                let own = engine.config.mac;
                                let builder = etherparse::PacketBuilder::ethernet2(own.0, peer.mac.0)
                                    .ipv6(own.ipv6().octets(), peer.mac.ipv6().octets(), 255)
                                    .icmpv6_echo_request(0x4157, 0);
                                let mut packet = Vec::new();
                                builder.write(&mut packet, b"owl_rs")?;
                                queue.push(packet, now);
                            }
                            keepalive_at = now + 3_000_000;
                        }
                        let report = queue.flush(
                            &mut engine, desired, monitor_limit,
                            || elapsed_us(start),
                            |bytes| inject_packet(stream.capture_mut(), bytes),
                        )?;
                        if let Some(time) = report.last_sent_us { last_traffic = time; }
                    }
                },
            }
        }
        Ok(())
    }.await;
    log_stats(&engine);
    info!(
        pending_packets = queue.len(),
        pending_acks = queue.pending_acks(),
        "AWDL TX queue stopped"
    );
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

fn wall_us() -> Option<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|time| i64::try_from(time.as_micros()).ok())
}

/// libpcap host timestamps use CLOCK_REALTIME; the engine uses Instant elapsed time.
struct CaptureClock {
    epoch_us: Option<i64>,
}
impl CaptureClock {
    const MAX_CLOCK_SHIFT_US: u64 = 10_000;
    const MAX_CAPTURE_AGE_US: i64 = 5_000_000;
    const SAMPLE_SKEW_US: i64 = 1_000;

    fn new(wall: Option<i64>, now: i64) -> Self {
        Self {
            epoch_us: wall.and_then(|wall| wall.checked_sub(now)),
        }
    }
    fn receive_time(&mut self, seconds: i64, micros: i64, wall: Option<i64>, now: i64) -> i64 {
        let Some(epoch) = self.epoch_us else {
            return now;
        };
        // A wall-clock step makes buffered timestamps ambiguous. Fall back for
        // this session instead of propagating the step into AWDL synchronization.
        if wall
            .and_then(|wall| wall.checked_sub(now))
            .is_none_or(|current| current.abs_diff(epoch) > Self::MAX_CLOCK_SHIFT_US)
        {
            self.epoch_us = None;
            warn!("capture clock changed; using processing time for this session");
            return now;
        }
        if seconds <= 0 || !(0..1_000_000).contains(&micros) {
            return now;
        }
        let received = seconds
            .checked_mul(1_000_000)
            .and_then(|stamp| stamp.checked_add(micros))
            .and_then(|stamp| stamp.checked_sub(epoch));
        // Reject missing, implausibly old or future timestamps, allowing a small
        // sampling skew. Signed times also support packets captured during setup.
        received
            .filter(|&time| {
                (now.saturating_sub(Self::MAX_CAPTURE_AGE_US)
                    ..=now.saturating_add(Self::SAMPLE_SKEW_US))
                    .contains(&time)
            })
            .map(|time| time.min(now))
            .unwrap_or(now)
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
    match inject_packet(cap, bytes) {
        Ok(()) => Ok(true),
        Err(tx::InjectionError::Backpressure) => Ok(false),
        Err(tx::InjectionError::TooLarge(error) | tx::InjectionError::Fatal(error)) => Err(error),
    }
}
fn inject_packet(
    cap: &mut Capture<pcap::Active>,
    bytes: &[u8],
) -> Result<(), tx::InjectionError<pcap::Error>> {
    Errno::clear();
    let result = cap.sendpacket(bytes);
    injection_result(result, Errno::last())
}
fn injection_result(
    result: Result<(), pcap::Error>,
    errno: Errno,
) -> Result<(), tx::InjectionError<pcap::Error>> {
    match result {
        Ok(()) => Ok(()),
        Err(_) if matches!(errno, Errno::EAGAIN | Errno::ENOBUFS) => {
            Err(tx::InjectionError::Backpressure)
        }
        Err(error) if errno == Errno::EMSGSIZE => Err(tx::InjectionError::TooLarge(error)),
        Err(error) => Err(tx::InjectionError::Fatal(error)),
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
        "STATS tx_action {} tx_data {} tx_unicast {} tx_multicast {} | tx_packets {} tx_amsdu {} tx_aggregated_packets {} tx_aggregation_rejected {} | rx_action {} rx_data {} rx_unknown {} | tx_backpressure {} dropped {}",
        s.tx_action,
        s.tx_data,
        s.tx_unicast,
        s.tx_multicast,
        s.tx_packets,
        s.tx_amsdu,
        s.tx_aggregated_packets,
        s.tx_aggregation_rejected,
        s.rx_action,
        s.rx_data,
        s.rx_unknown,
        s.tx_backpressure,
        s.dropped,
    );
    info!(
        acked = s.tx_status_acked,
        failed = s.tx_status_failed,
        retries = s.tx_status_retries,
        ignored = s.tx_status_ignored,
        "AWDL TX delivery"
    );
    let rx = &s.rx_aggregation;
    info!(
        mpdus = rx.mpdus, retries = rx.retry_mpdus, duplicates = rx.duplicate_mpdus,
        amsdu = rx.amsdu_mpdus, members = rx.amsdu_members,
        body_bytes = rx.amsdu_body_bytes, max_body_bytes = rx.amsdu_max_body_bytes,
        member_counts = ?rx.amsdu_member_counts, size_buckets = ?rx.amsdu_size_buckets,
        ampdu_reported = rx.ampdu_reported_mpdus, ampdu_last = rx.ampdu_reported_last_mpdus,
        "AWDL RX aggregation"
    );
    if s.rx_addba_requests != 0 {
        info!(
            received = s.rx_addba_requests,
            rejected = s.tx_addba_rejections,
            accepted = s.tx_addba_acceptances,
            reorder = ?engine.reorder.stats,
            "ADDBA negotiation"
        );
    }
    if s.tx_ack.injection_attempts != 0 || s.tx_ack.dropped != 0 {
        info!(timing=?s.tx_ack, "AWDL TCP ACK timing");
    }
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
    #[test]
    fn capture_time_removes_queue_delay_and_rejects_clock_steps() {
        let epoch = 1_700_000_000_000_000;
        let mut clock = CaptureClock::new(Some(epoch + 100), 100);
        // Queued captures, setup captures before our epoch, and invalid stamps.
        for (seconds, micros, expected) in [
            (epoch / 1_000_000, 12_345, 12_345),
            (epoch / 1_000_000 - 1, 999_000, -1_000),
            (0, 0, 40_000),
            (epoch / 1_000_000, 1_000_000, 40_000),
            (epoch / 1_000_000 + 1, 0, 40_000),
        ] {
            assert_eq!(
                clock.receive_time(seconds, micros, Some(epoch + 40_000), 40_000),
                expected
            );
        }
        for jump in [-1_000_000, 1_000_000] {
            let mut clock = CaptureClock::new(Some(epoch), 0);
            assert_eq!(
                clock.receive_time(
                    epoch / 1_000_000,
                    12_345,
                    Some(epoch + 40_000 + jump),
                    40_000
                ),
                40_000
            );
            // Do not reinterpret queued pre-step packets using a new clock epoch.
            assert_eq!(
                clock.receive_time(epoch / 1_000_000, 12_345, Some(epoch + 50_000), 50_000),
                50_000
            );
        }
    }
    #[test]
    fn injection_errors_distinguish_backpressure_oversize_and_failure() {
        for errno in [Errno::EAGAIN, Errno::ENOBUFS] {
            assert!(matches!(
                injection_result(Err(pcap::Error::PcapError("busy".into())), errno),
                Err(tx::InjectionError::Backpressure)
            ));
        }
        assert!(matches!(
            injection_result(Err(pcap::Error::PcapError("large".into())), Errno::EMSGSIZE),
            Err(tx::InjectionError::TooLarge(_))
        ));
        assert!(matches!(
            injection_result(Err(pcap::Error::PcapError("gone".into())), Errno::ENODEV),
            Err(tx::InjectionError::Fatal(_))
        ));
        // A stale errno must never turn successful submission into an error.
        assert!(injection_result(Ok(()), Errno::EMSGSIZE).is_ok());
        assert!(matches!(
            injection_result(
                Err(pcap::Error::PcapError("unknown".into())),
                Errno::from_raw(0)
            ),
            Err(tx::InjectionError::Fatal(_))
        ));
    }
}
