// SPDX-License-Identifier: GPL-3.0-or-later
//! Transactional radio setup. The recovery journal survives a killed daemon.
use crate::{netlink::Netlink, protocol::Mac};
use anyhow::{Context, Result, bail};
use clap::{Args, ValueEnum};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::process::Command;
use wl_nl80211::Nl80211InterfaceType as IfType;

// Enough room for the largest supported A-MSDU plus radiotap and MAC headers.
const MONITOR_MTU: u32 = 8192;

pub fn driver_name(interface: &str) -> Result<String> {
    interface_name(interface)?;
    Ok(
        std::fs::canonicalize(format!("/sys/class/net/{interface}/device/driver"))?
            .file_name()
            .context("missing radio driver")?
            .to_string_lossy()
            .into_owned(),
    )
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    Shared,
    Exclusive,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Backend {
    Ibss,
    ActiveMonitor,
}
fn default_reg_region() -> String {
    "US".into()
}
fn reg_region(value: &str) -> std::result::Result<String, String> {
    if value == "00" || (value.len() == 2 && value.bytes().all(|b| b.is_ascii_alphabetic())) {
        Ok(value.to_ascii_uppercase())
    } else {
        Err("regulatory region must be a two-letter country code or 00".into())
    }
}
fn primary_channel(value: &str) -> std::result::Result<u8, String> {
    match value {
        "6" => Ok(6),
        "44" => Ok(44),
        "149" => Ok(149),
        _ => Err("primary channel must be 6, 44, or 149".into()),
    }
}
fn legacy_discovery_channel(value: &str) -> std::result::Result<u8, String> {
    if value == "6" {
        Ok(6)
    } else {
        Err("--discovery-channel is obsolete; only the compatibility value 6 is accepted".into())
    }
}
fn default_max_bandwidth() -> u32 {
    40
}
fn max_bandwidth(value: &str) -> std::result::Result<u32, String> {
    match value {
        "20" => Ok(20),
        "40" => Ok(40),
        "80" => Ok(80),
        _ => Err("maximum bandwidth must be 20, 40, or 80 MHz".into()),
    }
}
fn default_tx_ack() -> crate::rate::AckPolicy {
    crate::rate::AckPolicy::Noack
}
#[derive(Clone, Debug, Args, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadioArgs {
    /// Station interface; auto chooses the first managed Wi-Fi interface.
    #[arg(long, default_value = "auto")]
    pub interface: String,
    #[arg(long, value_enum)]
    pub mode: Option<Mode>,
    /// Explicit exclusive radio model; otherwise use the driver profile.
    #[arg(long, value_enum)]
    pub backend: Option<Backend>,
    /// Global kernel regulatory region requested when starting a radio session.
    #[arg(long, default_value = "US", value_parser = reg_region)]
    #[serde(default = "default_reg_region")]
    pub reg_region: String,
    /// Fixed exclusive-mode channel. Shared mode uses the AP channel.
    #[arg(long = "primary-channel", visible_aliases = ["channel", "transmit-channel"], default_value = "149", value_parser = primary_channel)]
    pub channel: Option<u8>,
    /// Maximum exclusive-mode channel bandwidth in MHz; shared mode uses the AP width.
    #[arg(long, default_value_t = 40, value_parser = max_bandwidth)]
    #[serde(default = "default_max_bandwidth")]
    pub max_bandwidth: u32,
    /// Ignored compatibility option; only 6 is accepted.
    #[arg(long, value_parser = legacy_discovery_channel)]
    #[serde(default)]
    pub discovery_channel: Option<u8>,
    #[arg(long, default_value = "owlmon0")]
    pub monitor: String,
    #[arg(long, default_value = "awdl0")]
    pub host_interface: String,
    /// Driver profiles in TOML format.
    #[arg(long)]
    pub profiles: Option<PathBuf>,
    #[arg(long)]
    pub allow_untested: bool,
    /// Unicast ACK policy; auto follows the driver profile, independent of channel pinning.
    #[arg(long, value_enum, default_value = "noack")]
    #[serde(default = "default_tx_ack")]
    pub tx_ack: crate::rate::AckPolicy,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MonMac {
    Station,
    Own,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    #[serde(default)]
    pub driver: String,
    pub tested: bool,
    pub mode: Mode,
    pub mon_mac: MonMac,
    pub reconnect: bool,
    pub mt76_pm: bool,
    /// TX encoder support; independent of RX advertisements and --fec selection.
    #[serde(default)]
    pub supports_tx_ldpc: bool,
    /// Driver workaround: transmit without hardware ACK waiting or TX feedback.
    #[serde(default)]
    pub tx_noack: bool,
    /// Experimental: hardware must generate Block Ack in active monitor mode.
    #[serde(default)]
    pub rx_ampdu: bool,
    pub exclusive_backend: Backend,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profiles {
    profiles: std::collections::BTreeMap<String, Profile>,
}
impl Profile {
    pub fn load(driver: &str, path: Option<&Path>) -> Result<Self> {
        let table = match path {
            Some(path) => std::fs::read_to_string(path)?,
            None => include_str!("../../../profiles.toml").into(),
        };
        Self::parse(&table, driver)
    }
    pub fn parse(table: &str, driver: &str) -> Result<Self> {
        let mut profiles: Profiles = toml::from_str(table).context("parse radio profiles TOML")?;
        let mut profile = profiles
            .profiles
            .remove(driver)
            .or_else(|| profiles.profiles.remove("default"))
            .context("no matching driver profile or default profile")?;
        profile.driver = driver.into();
        if profile.mode == Mode::Exclusive
            && profile.exclusive_backend == Backend::ActiveMonitor
            && profile.mon_mac != MonMac::Station
        {
            bail!("active-monitor requires mon_mac=station");
        }
        profile.validate_rx_ampdu()?;
        Ok(profile)
    }
    fn validate_rx_ampdu(&self) -> Result<()> {
        anyhow::ensure!(
            !self.rx_ampdu
                || (self.mode == Mode::Exclusive
                    && self.exclusive_backend == Backend::ActiveMonitor
                    && self.mon_mac == MonMac::Station),
            "rx_ampdu requires exclusive active-monitor with mon_mac=station and hardware Block Ack support"
        );
        Ok(())
    }
}
pub(crate) async fn nmcli(timeout: Duration, args: &[&str]) -> Result<String> {
    let p = tokio::time::timeout(
        timeout,
        Command::new("nmcli").args(args).kill_on_drop(true).output(),
    )
    .await
    .context("NetworkManager command timed out")??;
    if !p.status.success() {
        bail!(
            "nmcli {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&p.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&p.stdout).trim().to_owned())
}
pub fn interface_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 15
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
    {
        bail!("invalid interface name: {name}");
    }
    Ok(())
}
pub(crate) fn freq(channel: u8) -> Result<u32> {
    match channel {
        6 => Ok(2437),
        44 => Ok(5220),
        149 => Ok(5745),
        _ => bail!("AWDL radio channel must be 6, 44 or 149"),
    }
}
pub(crate) fn channel(f: u32) -> Option<u8> {
    match f {
        2437 => Some(6),
        5220 => Some(44),
        5745 => Some(149),
        _ => None,
    }
}
fn process_stamp(pid: u32) -> Result<String> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    Ok(s.rsplit_once(')')
        .context("invalid process stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("missing process start time")?
        .into())
}
#[derive(Clone, Debug, Serialize)]
pub struct Probe {
    pub station: String,
    pub phy: String,
    pub mac: Mac,
    pub profile: Profile,
    pub associated: bool,
    pub ap_channel: Option<u8>,
    pub channels: Vec<u8>,
    pub active_monitor: bool,
    pub capabilities: crate::protocol::RadioCapabilities,
    pub operating_channel: Option<crate::channel::ChannelDefinition>,
    pub tuning: Vec<crate::channel::ChannelDefinition>,
}
pub async fn probe(args: &RadioArgs, timeouts: &crate::timeouts::Timeouts) -> Result<Probe> {
    timeouts.validate()?;
    probe_with(args, &Netlink::with_timeout(timeouts.netlink)?).await
}
async fn probe_with(args: &RadioArgs, net: &Netlink) -> Result<Probe> {
    let iface = if args.interface == "auto" {
        net.interfaces().await?.into_iter().find(|i| i.kind == IfType::Station)
            .context("no managed Wi-Fi interface found; stop any active session or recover the interrupted session with its original --run-dir")?
    } else {
        net.interface(&args.interface).await?
    };
    let station = iface.name.clone();
    interface_name(&station)?;
    interface_name(&args.monitor)?;
    interface_name(&args.host_interface)?;
    if station == args.monitor
        || station == args.host_interface
        || args.monitor == args.host_interface
    {
        bail!("station, monitor and TAP names must differ");
    }
    let base = PathBuf::from(format!("/sys/class/net/{station}"));
    let phy = format!("phy{}", iface.phy);
    let driver = driver_name(&station)?;
    let mut profile = Profile::load(&driver, args.profiles.as_deref())?;
    if let Some(mode) = args.mode {
        profile.mode = mode;
    }
    if let Some(backend) = args.backend {
        profile.exclusive_backend = backend;
    }
    let linked = net.linked_frequency(&station, false).await?;
    let associated = linked.is_some();
    let ap_channel = linked.and_then(|frequency| {
        iface
            .channel_definition()
            .filter(|_| iface.frequency == Some(frequency))
            .map(|d| d.channel)
            .or_else(|| channel(frequency))
    });
    let caps = net.phy_capabilities(iface.phy).await?;
    let allowed: Vec<_> = caps.frequencies.into_iter().filter_map(channel).collect();
    profile.validate_rx_ampdu()?;
    let order = if profile.exclusive_backend == Backend::ActiveMonitor {
        [6, 44, 149]
    } else {
        [44, 149, 6]
    };
    let channels = order.into_iter().filter(|c| allowed.contains(c)).collect();
    let mac = std::fs::read_to_string(base.join("address"))?
        .trim()
        .parse()?;
    Ok(Probe {
        station,
        phy,
        mac,
        profile,
        associated,
        ap_channel,
        channels,
        active_monitor: caps.active_monitor,
        capabilities: caps.radio,
        operating_channel: iface.channel_definition(),
        tuning: caps.tuning,
    })
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Journal {
    #[serde(default)]
    timeouts: crate::timeouts::Timeouts,
    pid: u32,
    stamp: String,
    station: String,
    monitor: String,
    ibss: String,
    phy: String,
    mac: Mac,
    up: bool,
    managed: Option<bool>,
    connection: Option<String>,
    touched: bool,
    mon_created: bool,
    ibss_created: bool,
    profile: Profile,
    pm: Option<(String, String, String)>,
}
pub struct Radio {
    pub probe: Probe,
    pub channel: u8,
    pub transmit_channel: u8,
    pub operating_channel: Option<crate::channel::ChannelDefinition>,
    state: Journal,
    journal: PathBuf,
    _lock: File,
    net: Netlink,
    mac: Mac,
}
impl Radio {
    pub async fn prepare(
        args: &RadioArgs,
        run_dir: &Path,
        session_mac: Mac,
        timeouts: &crate::timeouts::Timeouts,
    ) -> Result<Self> {
        timeouts.validate()?;
        anyhow::ensure!(
            session_mac.valid_unicast(),
            "AWDL MAC must be nonzero and unicast"
        );
        if !nix::unistd::geteuid().is_root() {
            bail!("radio setup requires root; run this command with sudo");
        }
        std::fs::create_dir_all(run_dir)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(run_dir.join("radio.lock"))?;
        lock.try_lock_exclusive()
            .context("another owl_rs process owns the radio")?;
        let journal = run_dir.join("radio.json");
        recover_file(&journal, None).await?;
        let net = Netlink::with_timeout(timeouts.netlink)?;
        anyhow::ensure!(
            matches!(args.max_bandwidth, 20 | 40 | 80),
            "maximum bandwidth must be 20, 40, or 80 MHz"
        );
        let region = reg_region(&args.reg_region).map_err(anyhow::Error::msg)?;
        net.set_reg_region(&region).await?;
        let probe = probe_with(args, &net).await?;
        if !probe.profile.tested && !args.allow_untested {
            bail!(
                "untested driver {}; use --allow-untested after choosing a profile",
                probe.profile.driver
            );
        }
        if probe.profile.mode == Mode::Exclusive
            && probe.profile.exclusive_backend == Backend::ActiveMonitor
            && (!probe.active_monitor || probe.profile.mon_mac == MonMac::Own)
        {
            bail!("active-monitor requires hardware support and mon_mac=station");
        }
        let (channels, transmit_channel) = if probe.profile.mode == Mode::Shared {
            let ap = probe
                .ap_channel
                .context("shared mode requires a supported AP channel")?;
            (vec![ap], ap)
        } else {
            let primary = args.channel.unwrap_or(149);
            anyhow::ensure!(
                matches!(primary, 6 | 44 | 149),
                "primary channel must be 6, 44, or 149"
            );
            anyhow::ensure!(
                args.discovery_channel.is_none_or(|c| c == 6),
                "--discovery-channel is obsolete; only the compatibility value 6 is accepted"
            );
            anyhow::ensure!(
                probe.channels.contains(&primary),
                "channel {primary} must permit transmission"
            );
            (vec![primary], primary)
        };

        let ibss = "owlibss0".to_string();
        for name in [&args.monitor, &args.host_interface, &ibss] {
            if Path::new(&format!("/sys/class/net/{name}")).exists() {
                bail!("interface {name} already exists; stop its owner first");
            }
        }
        let up = net.is_up(&probe.station).await?;
        let nm = nmcli(
            timeouts.network_manager,
            &[
                "-g",
                "GENERAL.NM-MANAGED,GENERAL.CON-UUID",
                "device",
                "show",
                &probe.station,
            ],
        )
        .await
        .ok();
        let managed = nm.as_deref().and_then(|s| match s.lines().next()? {
            "yes" => Some(true),
            "no" => Some(false),
            _ => None,
        });
        let connection = nm
            .as_deref()
            .and_then(|s| s.lines().nth(1))
            .filter(|s| !s.is_empty() && *s != "--")
            .map(str::to_owned);
        if probe.associated && probe.profile.mode == Mode::Exclusive && connection.is_none() {
            bail!(
                "cannot save the connected AP for restoration; NetworkManager connection UUID is unavailable"
            );
        }
        let state = Journal {
            timeouts: *timeouts,
            pid: std::process::id(),
            stamp: process_stamp(std::process::id())?,
            station: probe.station.clone(),
            monitor: args.monitor.clone(),
            ibss,
            phy: probe.phy.clone(),
            mac: probe.mac,
            up,
            managed,
            connection,
            touched: false,
            mon_created: false,
            ibss_created: false,
            profile: probe.profile.clone(),
            pm: None,
        };
        // Shared injection/ACKs may require the associated station address.
        let mac = if probe.profile.mode == Mode::Shared {
            probe.mac
        } else {
            session_mac
        };
        let mut radio = Self {
            mac,
            probe,
            channel: channels[0],
            transmit_channel,
            operating_channel: None,
            state,
            journal,
            _lock: lock,
            net,
        };
        radio.persist()?;
        let setup = async {
            radio.setup(&channels).await?;
            radio.operating_channel = Some(
                radio
                    .net
                    .interface(&radio.state.monitor)
                    .await?
                    .channel_definition()
                    .or(radio.operating_channel)
                    .or(radio.probe.operating_channel)
                    .context("radio did not report its channel width and center frequency")?,
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if let Err(error) = setup {
            if let Err(cleanup) = radio.shutdown().await {
                tracing::error!("radio rollback failed: {cleanup:#}");
            }
            return Err(error);
        }
        Ok(radio)
    }
    pub fn ibss_interface(&self) -> Option<String> {
        (self.probe.profile.mode == Mode::Exclusive
            && self.probe.profile.exclusive_backend == Backend::Ibss)
            .then(|| self.state.ibss.clone())
    }
    fn persist(&self) -> Result<()> {
        let tmp = self.journal.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&self.state)?)?;
        std::fs::rename(tmp, &self.journal)?;
        Ok(())
    }
    async fn create(&mut self, ibss: bool, active: bool) -> Result<()> {
        let name = if ibss {
            &self.state.ibss
        } else {
            &self.state.monitor
        };
        // Record ownership intent before the kernel mutation, so SIGKILL cannot
        // leave a created vif outside the recovery journal.
        if ibss {
            self.state.ibss_created = true;
        } else {
            self.state.mon_created = true;
        }
        self.persist()?;
        let phy = self
            .state
            .phy
            .strip_prefix("phy")
            .context("invalid PHY name")?
            .parse()?;
        self.net
            .create_interface(
                phy,
                name,
                if ibss { IfType::Adhoc } else { IfType::Monitor },
                active,
            )
            .await?;
        let name = if ibss {
            &self.state.ibss
        } else {
            &self.state.monitor
        };
        let _ = nmcli(
            self.state.timeouts.network_manager,
            &["device", "set", name, "managed", "no"],
        )
        .await;
        let mut mac = self.mac;
        if !ibss
            && self.state.profile.mode == Mode::Exclusive
            && self.state.profile.mon_mac == MonMac::Own
        {
            mac.0[0] = (mac.0[0] | 2) & !1;
            mac.0[5] ^= 1;
        }
        self.net.set_mac(name, mac).await?;
        if !ibss && let Err(error) = self.net.set_mtu(name, MONITOR_MTU).await {
            tracing::warn!(%error, "monitor MTU enlargement rejected; TX aggregation will use the current limit");
        }
        let ipv6 = PathBuf::from(format!("/proc/sys/net/ipv6/conf/{name}/disable_ipv6"));
        if ipv6.exists() {
            tokio::fs::write(ipv6, b"1\n").await?;
        }
        self.net.set_up(name, true).await
    }
    async fn setup(&mut self, channels: &[u8]) -> Result<()> {
        let station = self.state.station.clone();
        if self.state.profile.mode == Mode::Exclusive {
            self.state.touched = true;
            self.persist()?;
            if self.state.managed == Some(true) {
                nmcli(
                    self.state.timeouts.network_manager,
                    &["device", "set", &station, "managed", "no"],
                )
                .await?;
                // The property update can precede NetworkManager's device
                // transition, which may still bring the station down.
                tokio::time::timeout(self.state.timeouts.network_manager, async {
                    loop {
                        let state = nmcli(
                            self.state.timeouts.network_manager,
                            &["-g", "GENERAL.STATE", "device", "show", &station],
                        )
                        .await?;
                        if state.split_whitespace().next() == Some("10") {
                            return Ok::<_, anyhow::Error>(());
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                })
                .await
                .context("NetworkManager did not release the Wi-Fi interface")??;
            }
            // No disassociate command is issued for an offline station.
            self.net.set_up(&station, false).await?;
            if self.state.profile.exclusive_backend == Backend::ActiveMonitor {
                self.net.set_type(&station, IfType::Monitor).await?;
                self.net.set_mac(&station, self.mac).await?;
                self.net.set_up(&station, true).await?;
                // Establish the discovery context before the active monitor
                // joins it; its initial context must not conflict with tuning.
                let mut tuned = Err(anyhow::anyhow!("no allowed AWDL channel"));
                for &c in channels {
                    tuned = self.net.tune(&station, c, 20).await.map(|definition| {
                        self.operating_channel = Some(definition);
                    });
                    if tuned.is_ok() {
                        self.channel = c;
                        break;
                    }
                }
                tuned.context("failed to prepare an allowed AWDL monitor channel")?;
                self.create(false, true).await?;
            } else {
                self.create(true, false).await?;
                let mut chosen = None;
                for &c in channels {
                    if join_ibss(
                        &self.net,
                        &self.state.ibss,
                        c,
                        self.state.timeouts.ibss_ready,
                    )
                    .await
                    .is_ok()
                    {
                        chosen = Some(c);
                        break;
                    }
                    let _ = self.net.leave_ibss(&self.state.ibss).await;
                }
                self.channel = chosen.context("failed to join AWDL IBSS on an allowed channel")?;
                self.create(false, false).await?;
            }
        } else {
            self.create(false, false).await?;
        }
        if self.state.profile.mt76_pm {
            let base = format!("/sys/kernel/debug/ieee80211/{}/mt76", self.state.phy);
            if let (Ok(a), Ok(b)) = (
                std::fs::read_to_string(format!("{base}/runtime-pm")),
                std::fs::read_to_string(format!("{base}/deep-sleep")),
            ) {
                self.state.pm = Some((base.clone(), a, b));
                self.persist()?;
                std::fs::write(format!("{base}/runtime-pm"), b"0\n")?;
                std::fs::write(format!("{base}/deep-sleep"), b"0\n")?;
            } else {
                tracing::warn!(
                    "mt76 power-management controls unavailable; leaving power settings unchanged"
                );
            }
        }
        tracing::info!(station=%station,channel=self.channel,backend=?self.state.profile.exclusive_backend,"radio ready");
        Ok(())
    }
    pub async fn shutdown(&mut self) -> Result<()> {
        restore(&self.state).await?;
        match std::fs::remove_file(&self.journal) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}
async fn restore(state: &Journal) -> Result<()> {
    let net = Netlink::with_timeout(state.timeouts.netlink)?;
    let mut errors = Vec::new();
    if state.mon_created
        && Path::new(&format!("/sys/class/net/{}", state.monitor)).exists()
        && let Err(e) = net.delete_interface(&state.monitor).await
    {
        errors.push(e.to_string());
    }
    if state.ibss_created && Path::new(&format!("/sys/class/net/{}", state.ibss)).exists() {
        let _ = net.leave_ibss(&state.ibss).await;
        if let Err(e) = net.delete_interface(&state.ibss).await {
            errors.push(e.to_string());
        }
    }
    if let Some((base, a, b)) = &state.pm {
        for (key, value) in [("runtime-pm", a), ("deep-sleep", b)] {
            if let Err(e) = std::fs::write(format!("{base}/{key}"), value) {
                errors.push(e.to_string());
            }
        }
    }
    if state.touched {
        let result = async {
            net.set_up(&state.station, false).await?;
            if state.profile.exclusive_backend == Backend::ActiveMonitor {
                net.set_type(&state.station, IfType::Station).await?;
            }
            net.set_mac(&state.station, state.mac).await?;
            net.set_up(&state.station, state.up).await?;
            if let Some(managed) = state.managed {
                nmcli(
                    state.timeouts.network_manager,
                    &[
                        "device",
                        "set",
                        &state.station,
                        "managed",
                        if managed { "yes" } else { "no" },
                    ],
                )
                .await?;
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if let Err(e) = result {
            errors.push(e.to_string());
        }
    }
    // Reassociate only the saved connected AP, never an offline station.
    if (state.touched || state.profile.reconnect)
        && state.managed == Some(true)
        && let Some(uuid) = &state.connection
        && let Err(e) = nmcli(
            state.timeouts.network_manager,
            &[
                "--wait",
                &state.timeouts.reconnect.as_secs_f64().ceil().to_string(),
                "connection",
                "up",
                "uuid",
                uuid,
                "ifname",
                &state.station,
            ],
        )
        .await
    {
        errors.push(e.to_string());
    }
    if !errors.is_empty() {
        bail!("radio restoration: {}", errors.join("; "));
    }
    Ok(())
}
async fn recover_file(journal: &Path, timeouts: Option<&crate::timeouts::Timeouts>) -> Result<()> {
    if !journal.exists() {
        return Ok(());
    }
    let mut state: Journal = serde_json::from_slice(&std::fs::read(journal)?)?;
    if let Some(timeouts) = timeouts {
        state.timeouts = *timeouts;
    }
    if process_stamp(state.pid).is_ok_and(|s| s == state.stamp) {
        bail!("radio journal belongs to live PID {}", state.pid);
    }
    tracing::warn!("restoring radio from an interrupted session");
    restore(&state).await?;
    std::fs::remove_file(journal)?;
    Ok(())
}
pub async fn recover(run_dir: &Path, timeouts: &crate::timeouts::Timeouts) -> Result<()> {
    timeouts.validate()?;
    if !nix::unistd::geteuid().is_root() {
        bail!("recovery requires root");
    }
    std::fs::create_dir_all(run_dir)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(run_dir.join("radio.lock"))?;
    lock.try_lock_exclusive()
        .context("radio still owned by a running process")?;
    recover_file(&run_dir.join("radio.json"), Some(timeouts)).await
}

async fn join_ibss(net: &Netlink, iface: &str, channel: u8, ready: Duration) -> Result<()> {
    let frequency = freq(channel)?;
    net.join_ibss(iface, frequency).await?;
    let deadline = tokio::time::Instant::now() + ready;
    loop {
        if tokio::time::timeout_at(deadline, net.linked_frequency(iface, true))
            .await
            .is_ok_and(|r| r.is_ok_and(|f| f == Some(frequency)))
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    bail!("IBSS did not become ready on channel {channel}")
}
pub async fn tune_ibss(
    net: &Netlink,
    iface: &str,
    channel: u8,
    timeouts: crate::timeouts::Timeouts,
) -> Result<()> {
    if net.linked_frequency(iface, true).await?.is_some() {
        net.leave_ibss(iface).await?;
    }
    join_ibss(net, iface, channel, timeouts.ibss_ready).await
}
