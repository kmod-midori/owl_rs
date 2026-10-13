// SPDX-License-Identifier: GPL-3.0-or-later
use anyhow::{Context, Result, ensure};
use clap::Args;
use owl_rs::{
    channel::Strategy,
    engine::Config,
    protocol::{Mac, Rate},
    runtime::{self, Options},
};
use std::path::PathBuf;

#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
struct Input {
    /// Prepared monitor interface for live AWDL diagnostics.
    #[arg(long)]
    interface: Option<String>,
    /// Replay a radiotap PCAP without radio, TAP, or root privileges.
    #[arg(long, conflicts_with_all = ["host_interface", "listen_only", "duration", "save", "save_invalid"])]
    read: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct Arguments {
    #[command(flatten)]
    input: Input,
    /// Ethernet TAP name for live diagnostics.
    #[arg(long, default_value = "awdl0")]
    host_interface: String,
    /// Initial radio channel; retained throughout the session with --fixed-radio.
    #[arg(long, default_value_t = 6, value_parser = parse_channel)]
    channel: u8,
    /// Derive our advertised schedule from the elected sync master.
    #[arg(long, value_enum, default_value = "verbatim")]
    strategy: Strategy,
    /// Maximum unavailable slots filled by the widen strategy.
    #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u8).range(0..=16))]
    widen: u8,
    /// Legacy Mbps or mcsN[-sgi] data rate; actions use 12 Mbps.
    #[arg(long, default_value = "12")]
    rate: Rate,
    /// AWDL/TAP MAC; defaults to the monitor MAC or a local MAC for replay.
    #[arg(long)]
    mac: Option<Mac>,
    /// Keep the physical channel fixed, relax multicast gates, and disable unicast retries.
    #[arg(long)]
    fixed_radio: bool,
    /// Rank election metric before counter.
    #[arg(long)]
    metric_first: bool,
    /// Experimental local election metric.
    #[arg(long, default_value_t = 60)]
    election_metric: u32,
    /// Experimental fixed election counter, separate from AW timing.
    #[arg(long, default_value_t = 0)]
    election_counter: u32,
    /// Accept action frames regardless of RSSI.
    #[arg(long)]
    no_rssi_filter: bool,
    /// Observe peers without TAP creation or AWDL transmission.
    #[arg(long)]
    listen_only: bool,
    /// Stop live diagnostics after this many seconds.
    #[arg(long)]
    duration: Option<u64>,
    /// Save incoming radiotap frames to this PCAP.
    #[arg(long)]
    save: Option<String>,
    /// Save malformed received frames to this PCAP.
    #[arg(long)]
    save_invalid: Option<String>,
    /// Write final statistics/peers JSON here instead of stdout.
    #[arg(long)]
    summary: Option<String>,
    /// Advertised hostname, at most 64 bytes.
    #[arg(long)]
    name: Option<String>,
}
fn parse_channel(s: &str) -> Result<u8, String> {
    let c = s.parse().map_err(|_| "invalid channel")?;
    if [6, 36, 44, 149].contains(&c) {
        Ok(c)
    } else {
        Err("use channel 6, 36, 44, or 149".into())
    }
}
pub async fn run(args: Arguments, timeouts: owl_rs::timeouts::Timeouts) -> Result<()> {
    timeouts.validate()?;
    let offline = args.input.read.is_some();
    let input = match args.input.read {
        Some(path) => path
            .to_str()
            .context("capture path must be UTF-8")?
            .to_owned(),
        None => args.input.interface.context("missing AWDL input")?,
    };
    if !offline {
        owl_rs::radio::interface_name(&input)?;
    }
    let mac = match args.mac {
        Some(mac) => mac,
        None if offline => Mac([2, 0, 0, 0, 0, 1]),
        None => std::fs::read_to_string(format!("/sys/class/net/{input}/address"))
            .context("read interface MAC")?
            .trim()
            .parse()?,
    };
    ensure!(mac.valid_unicast(), "AWDL MAC must be nonzero and unicast");
    let name = args.name.unwrap_or_else(|| {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap_or_else(|_| "owl-rs".into())
            .trim()
            .into()
    });
    ensure!(name.len() <= 64, "name must be at most 64 bytes");
    let capabilities = if offline {
        Default::default()
    } else {
        let net = owl_rs::netlink::Netlink::with_timeout(timeouts.netlink)?;
        let iface = net.interface(&input).await?;
        net.phy_capabilities(iface.phy).await?.radio
    };
    let config = Config {
        peer_timeout: timeouts.peer_idle,
        retry_timeout: timeouts.retry_cache,
        pending_timeout: timeouts.queued_packet,
        airdrop_port: None,
        mac,
        name,
        channel: args.channel,
        strategy: args.strategy,
        fixed_radio: args.fixed_radio,
        metric_first: args.metric_first,
        election_metric: args.election_metric,
        election_counter: args.election_counter,
        widen: args.widen as usize,
        filter_rssi: !args.no_rssi_filter,
        rate: args.rate,
        capabilities,
        operating_channel: None,
    };
    let opts = Options {
        timeouts,
        input,
        host: args.host_interface,
        listen_only: args.listen_only,
        duration: args.duration,
        save: args.save,
        save_invalid: args.save_invalid,
        summary: args.summary,
        channel_plan: None,
        ibss_interface: None,
        retune: true,
    };
    if offline {
        runtime::replay(config, &opts).await
    } else {
        runtime::run(config, opts).await
    }
}
