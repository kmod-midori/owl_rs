// SPDX-License-Identifier: GPL-3.0-or-later
//! Radio/AWDL link lifecycle; no HTTPS server or transfer operations.
use crate::{
    channel::{ChannelPlan, Strategy},
    engine::Config,
    protocol::Mac,
    radio::{Mode, Radio, RadioArgs},
    rate::{FecPolicy, Rate},
    runtime,
};
use anyhow::{Context, Result, ensure};
use std::{net::Ipv6Addr, path::PathBuf, time::Duration};
use tokio::sync::{oneshot, watch};
use tokio_util::sync::CancellationToken;

pub(crate) struct Options {
    pub radio: RadioArgs,
    pub timeouts: crate::timeouts::Timeouts,
    pub run_dir: PathBuf,
    pub loopback: Option<Ipv6Addr>,
    pub service_port: u16,
    pub save: Option<String>,
    pub rate: Rate,
    pub fec: FecPolicy,
    pub election_metric: u32,
    pub election_counter: u32,
}
pub(crate) struct Link {
    radio: Option<Radio>,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
    cancel: CancellationToken,
    pub snapshot: watch::Receiver<serde_json::Value>,
    pub channel_ready: watch::Receiver<Option<u64>>,
    pub mac: Mac,
    pub address: Ipv6Addr,
    pub scope: u32,
    pub interface: Option<String>,
}
impl Link {
    pub fn stopped(&self) -> bool {
        self.task.as_ref().is_some_and(|t| t.is_finished())
    }
    pub async fn start(
        opts: &Options,
        policy: watch::Receiver<bool>,
        mac: Mac,
        traffic: watch::Receiver<owl_ipc::TransferState>,
    ) -> Result<Self> {
        let cancel = CancellationToken::new();
        let (tx, snapshot) = watch::channel(serde_json::json!({}));
        let (channel_tx, channel_ready) = watch::channel(None);
        if let Some(ip) = opts.loopback {
            ensure!(
                ip.is_loopback(),
                "--no-radio listener must be loopback; use radio setup for AWDL"
            );
            return Ok(Self {
                radio: None,
                task: None,
                cancel,
                snapshot,
                channel_ready,
                mac,
                address: ip,
                scope: 0,
                interface: None,
            });
        }
        let radio = Radio::prepare(&opts.radio, &opts.run_dir, mac, &opts.timeouts).await?;
        let mut network = Self {
            radio: Some(radio),
            task: None,
            cancel,
            snapshot,
            channel_ready,
            mac,
            address: Ipv6Addr::UNSPECIFIED,
            scope: 0,
            interface: Some(opts.radio.host_interface.clone()),
        };
        if let Err(error) = network
            .initialize(opts, tx, policy, traffic, channel_tx)
            .await
        {
            return match network.stop().await {
                Ok(()) => Err(error),
                Err(cleanup) => {
                    Err(error.context(format!("AWDL runtime/restoration failed: {cleanup:#}")))
                }
            };
        }
        Ok(network)
    }
    async fn initialize(
        &mut self,
        opts: &Options,
        tx: watch::Sender<serde_json::Value>,
        policy: watch::Receiver<bool>,
        traffic: watch::Receiver<owl_ipc::TransferState>,
        channel_ready: watch::Sender<Option<u64>>,
    ) -> Result<()> {
        let net = crate::netlink::Netlink::with_timeout(opts.timeouts.netlink)?;
        let radio = self.radio.as_ref().context("radio has not been prepared")?;
        let mac =
            std::fs::read_to_string(format!("/sys/class/net/{}/address", opts.radio.monitor))?
                .trim()
                .parse::<Mac>()?;
        let tx_ldpc = radio.probe.profile.supports_tx_ldpc;
        ensure!(
            opts.fec != FecPolicy::Ldpc || tx_ldpc,
            "LDPC injection is unsupported by driver {}",
            radio.probe.profile.driver
        );
        let config = Config {
            peer_timeout: opts.timeouts.peer_idle,
            retry_timeout: opts.timeouts.retry_cache,
            pending_timeout: opts.timeouts.queued_packet,
            airdrop_port: Some(opts.service_port),
            mac,
            name: mac.0.iter().map(|b| format!("{b:02x}")).collect(),
            channel: radio.transmit_channel,
            strategy: Strategy::Pin,
            fixed_radio: true,
            tx_noack: opts.radio.tx_ack.noack(radio.probe.profile.tx_noack),
            rx_ampdu: radio.probe.profile.rx_ampdu,
            metric_first: radio.probe.profile.mode == Mode::Exclusive,
            election_metric: opts.election_metric,
            election_counter: opts.election_counter,
            widen: 4,
            filter_rssi: false,
            rate: opts.rate,
            fec: opts.fec,
            tx_ldpc,
            capabilities: radio.probe.capabilities.clone(),
            operating_channel: radio.operating_channel,
        };
        let ropts = runtime::Options {
            input: opts.radio.monitor.clone(),
            host: opts.radio.host_interface.clone(),
            listen_only: false,
            duration: None,
            save: opts.save.clone(),
            save_invalid: None,
            summary: None,
            channel_plan: (radio.probe.profile.mode == Mode::Exclusive)
                .then(|| ChannelPlan::new(radio.transmit_channel)),
            ibss_interface: radio.ibss_interface(),
            max_bandwidth: opts.radio.max_bandwidth,
            retune: radio.probe.profile.mode == Mode::Exclusive,
            timeouts: opts.timeouts,
        };
        let (ready, rx) = oneshot::channel();
        let control = runtime::Control {
            cancel: self.cancel.clone(),
            ready: Some(ready),
            snapshot: tx,
            policy,
            traffic,
            channel_ready,
        };
        self.task = Some(tokio::spawn(runtime::controlled(config, ropts, control)));
        tokio::time::timeout(opts.timeouts.radio_startup, rx)
            .await
            .context("AWDL startup readiness timed out")?
            .context("AWDL stopped before startup readiness")?;
        ensure!(
            !self.task.as_ref().unwrap().is_finished(),
            "AWDL stopped during startup"
        );
        // LinkManager must not autoconfigure the temporary Ethernet TAP.
        if let Err(e) = crate::radio::nmcli(
            opts.timeouts.network_manager,
            &["device", "set", &opts.radio.host_interface, "managed", "no"],
        )
        .await
        {
            tracing::warn!("could not mark AWDL TAP unmanaged: {e:#}");
        }
        // The runtime brings up its TAP with nodad before reporting readiness.
        // Verify the specific link-local address before binding HTTPS.
        tokio::time::timeout(opts.timeouts.address_ready, async {
            while !net.address_ready(&opts.radio.host_interface, mac).await? {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("AWDL link-local IPv6 address did not become ready")??;
        let index = std::fs::read_to_string(format!(
            "/sys/class/net/{}/ifindex",
            opts.radio.host_interface
        ))?
        .trim()
        .parse()?;
        self.mac = mac;
        self.address = mac.ipv6();
        self.scope = index;
        Ok(())
    }
    pub async fn stop(&mut self) -> Result<()> {
        self.cancel.cancel();
        let mut error = None;
        if let Some(task) = self.task.take()
            && let Err(e) = task.await.map_err(anyhow::Error::from).and_then(|v| v)
        {
            error = Some(e);
        }
        if let Some(radio) = &mut self.radio {
            radio.shutdown().await?;
        }
        if let Some(e) = error {
            tracing::error!("AWDL runtime exited: {e:#}");
            return Err(e);
        }
        Ok(())
    }
}
