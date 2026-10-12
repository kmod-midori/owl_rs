// SPDX-License-Identifier: GPL-3.0-or-later
//! Native service lifecycle and authenticated Unix control socket.
use crate::{
    archive::{self, Item},
    ble::Wake,
    channel::{ChannelPlan, Strategy},
    discovery::Discovery,
    engine::Config,
    identity::Identity,
    protocol::{Mac, Rate},
    radio::{Mode, Radio, RadioArgs},
    runtime,
    transfer::{Receiver, Sender, Transfer},
};
use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddrV6,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::{Mutex, oneshot, watch},
};
use tokio_util::sync::CancellationToken;
#[derive(Clone, Debug, Args, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    #[command(flatten)]
    pub radio: RadioArgs,
    #[arg(long, default_value = "owl-rs")]
    pub name: String,
    /// User who owns the control socket, identity and received files (root daemons).
    #[arg(long)]
    pub owner: Option<String>,
    #[arg(long)]
    pub keys: Option<PathBuf>,
    #[arg(long)]
    pub output: Option<PathBuf>,
    #[arg(long, default_value = "/run/owl_rs")]
    pub run_dir: PathBuf,
    /// Skip Wi-Fi setup for local IPv6 loopback HTTPS testing.
    #[arg(long)]
    pub no_radio: bool,
    /// Loopback listener; with radio setup, only its port is used.
    #[arg(long, default_value = "[::1]:8771")]
    pub listen: std::net::SocketAddr,
    #[arg(long)]
    pub no_bluetooth: bool,
    #[arg(long)]
    pub bluetooth_adapter: Option<String>,
    /// Accept all offers without prompting (default requires accept/reject commands).
    #[arg(long)]
    pub auto_accept: bool,
    #[arg(long,default_value_t=4*1024*1024*1024)]
    pub max_bytes: u64,
    /// Limit the daemon or active session lifetime in seconds.
    #[arg(long)]
    pub duration: Option<u64>,
    #[arg(long)]
    pub save: Option<String>,
    #[arg(long, default_value = "12")]
    pub rate: Rate,
    /// Experimental local master-election preference; peers decide whether to follow.
    #[arg(long, default_value_t = 60)]
    pub election_metric: u32,
    /// Experimental advertised local election counter (fixed, not availability-window timing).
    #[arg(long, default_value_t = 0)]
    pub election_counter: u32,
}
pub fn owner(name: Option<&str>) -> Result<(u32, u32, PathBuf)> {
    if let Some(name) = name {
        let user = nix::unistd::User::from_name(name)?.context("owner user not found")?;
        ensure!(
            nix::unistd::geteuid().is_root() || user.uid == nix::unistd::getuid(),
            "only root can select another owner"
        );
        return Ok((user.uid.as_raw(), user.gid.as_raw(), user.dir));
    }
    let uid = if nix::unistd::geteuid().is_root() {
        std::env::var("SUDO_UID")
            .ok()
            .map(|s| s.parse())
            .transpose()?
            .unwrap_or(0)
    } else {
        nix::unistd::getuid().as_raw()
    };
    let user =
        nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))?.context("user not found")?;
    Ok((uid, user.gid.as_raw(), user.dir))
}
const RECEIVE_COMPLETION_GRACE: Duration = Duration::from_secs(5);

struct Network {
    radio: Option<Radio>,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
    cancel: CancellationToken,
    snapshot: watch::Receiver<serde_json::Value>,
    mac: Mac,
    address: SocketAddrV6,
    interface: Option<String>,
}
impl Network {
    async fn start(opts: &Options) -> Result<Self> {
        let cancel = CancellationToken::new();
        let (tx, snapshot) = watch::channel(serde_json::json!({}));
        if opts.no_radio {
            ensure!(
                opts.listen.ip().is_loopback(),
                "--no-radio listener must be loopback; use radio setup for AWDL"
            );
            let std::net::IpAddr::V6(ip) = opts.listen.ip() else {
                bail!("AirDrop requires an IPv6 listener");
            };
            return Ok(Self {
                radio: None,
                task: None,
                cancel,
                snapshot,
                mac: Mac([2, 0, 0, 0, 0, 1]),
                address: SocketAddrV6::new(ip, opts.listen.port(), 0, 0),
                interface: None,
            });
        }
        let radio = Radio::prepare(&opts.radio, &opts.run_dir).await?;
        let mut network = Self {
            radio: Some(radio),
            task: None,
            cancel,
            snapshot,
            mac: Mac([0; 6]),
            address: SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, opts.listen.port(), 0, 0),
            interface: Some(opts.radio.host_interface.clone()),
        };
        if let Err(error) = network.initialize(opts, tx).await {
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
    ) -> Result<()> {
        let net = crate::netlink::Netlink::new()?;
        let radio = self.radio.as_ref().context("radio has not been prepared")?;
        let mac =
            std::fs::read_to_string(format!("/sys/class/net/{}/address", opts.radio.monitor))?
                .trim()
                .parse::<Mac>()?;
        let config = Config {
            airdrop_port: Some(opts.listen.port()),
            mac,
            name: mac.0.iter().map(|b| format!("{b:02x}")).collect(),
            channel: radio.transmit_channel,
            strategy: if radio.probe.profile.mode == Mode::Exclusive {
                Strategy::Pin
            } else {
                Strategy::Intersect
            },
            fixed_radio: radio.probe.profile.mode == Mode::Exclusive,
            metric_first: radio.probe.profile.mode == Mode::Exclusive,
            election_metric: opts.election_metric,
            election_counter: opts.election_counter,
            widen: 4,
            filter_rssi: false,
            rate: opts.rate,
        };
        let ropts = runtime::Options {
            input: opts.radio.monitor.clone(),
            host: opts.radio.host_interface.clone(),
            listen_only: false,
            duration: None,
            save: opts.save.clone(),
            save_invalid: None,
            summary: None,
            channel_plan: (radio.probe.profile.mode == Mode::Exclusive).then(|| {
                ChannelPlan::new(
                    radio.channel,
                    radio.transmit_channel,
                    radio.probe.channels.clone(),
                )
            }),
            ibss_interface: radio.ibss_interface(),
            initial_channel: Some(radio.channel),
        };
        let (ready, rx) = oneshot::channel();
        let control = runtime::Control {
            cancel: self.cancel.clone(),
            ready: Some(ready),
            snapshot: tx,
        };
        self.task = Some(tokio::spawn(runtime::controlled(config, ropts, control)));
        tokio::time::timeout(Duration::from_secs(15), rx)
            .await
            .context("AWDL startup readiness timed out")?
            .context("AWDL stopped before startup readiness")?;
        ensure!(
            !self.task.as_ref().unwrap().is_finished(),
            "AWDL stopped during startup"
        );
        // NetworkManager must not autoconfigure the temporary Ethernet TAP.
        if let Err(e) =
            crate::radio::nmcli(&["device", "set", &opts.radio.host_interface, "managed", "no"])
                .await
        {
            tracing::warn!("could not mark AWDL TAP unmanaged: {e:#}");
        }
        // The runtime brings up its TAP with nodad before reporting readiness.
        // Verify the specific link-local address before binding HTTPS.
        tokio::time::timeout(Duration::from_secs(5), async {
            while !net.address_ready(&opts.radio.host_interface, mac).await? {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("AWDL link-local IPv6 address did not become ready")??;
        let index = crate::discovery::scope(&opts.radio.host_interface)?;
        self.mac = mac;
        self.address = SocketAddrV6::new(mac.ipv6(), opts.listen.port(), 0, index);
        Ok(())
    }
    async fn stop(&mut self) -> Result<()> {
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
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Command {
    Status,
    Peers {
        timeout: u64,
    },
    Transfers,
    Accept {
        id: String,
    },
    Reject {
        id: String,
    },
    Cancel {
        id: String,
    },
    Stop,
    Receive {
        once: bool,
        #[serde(default)]
        options: serde_json::Value,
    },
    Send {
        to: String,
        direct: Option<SocketAddrV6>,
        items: Vec<Item>,
        urls: Vec<String>,
        bytes: u64,
        #[serde(default)]
        icon: Option<Vec<u8>>,
        timeout: u64,
        #[serde(default)]
        options: serde_json::Value,
    },
}
async fn read_line<R: AsyncRead + Unpin>(reader: &mut BufReader<R>) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        let buf = reader.fill_buf().await?;
        ensure!(!buf.is_empty(), "control connection closed before request");
        let n = buf
            .iter()
            .position(|b| *b == b'\n')
            .map(|n| n + 1)
            .unwrap_or(buf.len());
        ensure!(
            line.len() + n <= 1024 * 1024,
            "control message exceeds 1 MiB"
        );
        line.extend_from_slice(&buf[..n]);
        reader.consume(n);
        if line.last() == Some(&b'\n') {
            return Ok(line);
        }
    }
}
#[derive(Clone)]
struct State {
    receiver: Receiver,
    sender: Option<Sender>,
    discovery: Discovery,
    cancel: CancellationToken,
    snapshot: watch::Receiver<serde_json::Value>,
    scope: u32,
}
impl State {
    async fn names(
        &self,
        deadline: tokio::time::Instant,
    ) -> Vec<(crate::discovery::Peer, Option<String>)> {
        use futures_util::{StreamExt, stream};
        let Some(sender) = &self.sender else {
            return Vec::new();
        };
        let mut candidates: Vec<_> = self
            .discovery
            .list()
            .await
            .into_iter()
            .map(|p| (p, false))
            .collect();
        if self.scope != 0 {
            let snapshot = self.snapshot.borrow().clone();
            if let Some(peers) = snapshot.get("peers").and_then(serde_json::Value::as_array) {
                for peer in peers.iter().take(512) {
                    if peer.get("valid").and_then(serde_json::Value::as_bool) != Some(true) {
                        continue;
                    }
                    if let Some(mac) = peer.get("mac").and_then(serde_json::Value::as_str)
                        && let Ok(mac) = mac.parse::<Mac>()
                        && mac.valid_unicast()
                        && !candidates
                            .iter()
                            .any(|(p, _)| *p.address.ip() == mac.ipv6())
                    {
                        candidates.push((crate::discovery::Peer::from_awdl(mac, self.scope), true));
                    }
                }
            }
        }
        stream::iter(candidates)
            .map(|(peer, fallback)| async move {
                let end = deadline.min(tokio::time::Instant::now() + Duration::from_secs(8));
                let name = tokio::time::timeout_at(end, sender.discover(peer.address))
                    .await
                    .ok()
                    .and_then(Result::ok);
                (peer, name, fallback)
            })
            .buffer_unordered(8)
            .filter_map(|(peer, name, fallback)| async move {
                if fallback && name.is_none() {
                    None
                } else {
                    Some((peer, name))
                }
            })
            .collect()
            .await
    }
    async fn named_peers(&self, seconds: u64) -> Vec<serde_json::Value> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds.clamp(1, 300));
        loop {
            let peers = self.names(deadline).await;
            if !peers.is_empty() || tokio::time::Instant::now() >= deadline {
                return peers.into_iter().map(|(p,name)|serde_json::json!({"id":p.id,"name":name,"address":p.address,"flags":p.flags})).collect();
            }
            tokio::select! {
                _ = self.cancel.cancelled() => return Vec::new(),
                _ = tokio::time::sleep(Duration::from_millis(250)) => (),
            }
        }
    }
    async fn target(
        &self,
        to: &str,
        direct: Option<SocketAddrV6>,
        seconds: u64,
    ) -> Result<SocketAddrV6> {
        if let Some(address) = direct {
            ensure!(
                address.ip().is_loopback() || address.ip().is_unicast_link_local(),
                "direct AirDrop address must be loopback or link-local"
            );
            return Ok(address);
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds.clamp(1, 300));
        loop {
            for peer in self.discovery.list().await {
                if peer.id.eq_ignore_ascii_case(to) {
                    return Ok(peer.address);
                }
            }
            for (peer, name) in self.names(deadline).await {
                if name.is_some_and(|n| n.eq_ignore_ascii_case(to)) {
                    return Ok(peer.address);
                }
            }
            ensure!(
                tokio::time::Instant::now() < deadline,
                "receiver {to} was not found"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
    async fn command(
        &self,
        command: Command,
        archive: Option<tempfile::NamedTempFile>,
    ) -> Result<serde_json::Value> {
        match command {
            Command::Status => Ok(
                serde_json::json!({"name":self.receiver.name,"awdl":self.snapshot.borrow().clone(),"sending":[],"transfers":self.receiver.transfers().await}),
            ),
            Command::Peers { timeout } => {
                ensure!(
                    self.sender.is_some(),
                    "receive session does not browse outgoing receivers"
                );
                Ok(serde_json::to_value(self.named_peers(timeout).await)?)
            }
            Command::Transfers => Ok(serde_json::to_value(self.receiver.transfers().await)?),
            Command::Accept { id } => {
                self.receiver.decide(&id, true).await?;
                Ok(serde_json::json!({"accepted":id}))
            }
            Command::Reject { id } => {
                self.receiver.decide(&id, false).await?;
                Ok(serde_json::json!({"rejected":id}))
            }
            Command::Cancel { .. } | Command::Stop | Command::Receive { .. } => {
                bail!("command requires the control service")
            }
            Command::Send {
                to,
                direct,
                items,
                urls,
                timeout,
                icon,
                ..
            } => {
                let sender = self
                    .sender
                    .as_ref()
                    .context("receive-only session cannot send")?;
                ensure!(
                    urls.len() <= 4096 && items.len() <= 4096,
                    "too many transfer items"
                );
                for url in &urls {
                    ensure!(
                        url.len() <= 16384 && !url.contains(['\n', '\r', '\0']),
                        "invalid link"
                    );
                }
                for item in &items {
                    archive::safe_path(&item.name)?;
                }
                let cancel = self.cancel.child_token();
                let result = tokio::select! {
                    _ = cancel.cancelled() => Err(anyhow::anyhow!("send cancelled")),
                    result = async {
                        let address = self.target(&to, direct, timeout).await?;
                        sender.send(address, items, urls, archive.as_ref().map(|f| f.path().into()), icon).await
                    } => result,
                };
                let id = result?;
                Ok(serde_json::json!({"sent":id,"receiver":to}))
            }
        }
    }
}
/// An orphaned Unix socket survives SIGKILL. The daemon lock still guards
/// replacement, so a concurrent live daemon cannot be overwritten at startup.
pub async fn control_available(run_dir: &Path) -> Result<bool> {
    match UnixStream::connect(run_dir.join("control.sock")).await {
        Ok(_socket) => Ok(true),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(error).context("connect to owl_rs control socket"),
    }
}
pub async fn client(
    run_dir: &Path,
    command: Command,
    archive: Option<&Path>,
) -> Result<serde_json::Value> {
    let mut socket = UnixStream::connect(run_dir.join("control.sock"))
        .await
        .context("connect to owl_rs daemon (start `owl_rs daemon` first)")?;
    socket.write_all(&serde_json::to_vec(&command)?).await?;
    socket.write_all(b"\n").await?;
    if let Some(path) = archive {
        let mut file = tokio::fs::File::open(path).await?;
        tokio::io::copy(&mut file, &mut socket).await?;
    }
    let value: serde_json::Value =
        serde_json::from_slice(&read_line(&mut BufReader::new(socket)).await?)?;
    if let Some(error) = value.get("error") {
        bail!("{}", error.as_str().unwrap_or("daemon error"));
    }
    Ok(value.get("ok").context("invalid daemon response")?.clone())
}
async fn signals(cancel: CancellationToken, duration: Option<u64>) {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("Unix signals");
    tokio::select! {
        _ = cancel.cancelled() => (),
        _ = tokio::signal::ctrl_c() => cancel.cancel(),
        _ = term.recv() => cancel.cancel(),
        _ = async {
            if let Some(s) = duration {
                tokio::time::sleep(Duration::from_secs(s)).await
            } else {
                std::future::pending().await
            }
        } => cancel.cancel(),
    }
}
pub type Request = (Command, Option<tempfile::NamedTempFile>);
async fn session(opts: Options, active: Active, request: Request) -> Result<()> {
    ensure!(
        !opts.name.is_empty() && opts.name.len() <= 64,
        "name must be 1..64 bytes"
    );
    ensure!(opts.max_bytes > 0, "max-bytes must be positive");
    let (uid, gid, home) = owner(opts.owner.as_deref())?;
    let keys = opts
        .keys
        .clone()
        .unwrap_or_else(|| home.join(".local/share/owl_rs/identity"));
    let output = opts
        .output
        .clone()
        .unwrap_or_else(|| home.join("Downloads/AirDrop"));
    let new_identity = !keys.join("key.pem").exists() && !keys.join("cert.pem").exists();
    crate::identity::private_directory(
        &keys,
        if nix::unistd::geteuid().is_root() {
            Some((uid, gid))
        } else {
            None
        },
    )?;
    let identity = Identity::load(&keys, &opts.name)?;
    if new_identity && nix::unistd::geteuid().is_root() {
        for entry in walkdir::WalkDir::new(&keys) {
            nix::unistd::chown(
                entry?.path(),
                Some(nix::unistd::Uid::from_raw(uid)),
                Some(nix::unistd::Gid::from_raw(gid)),
            )?;
        }
    }
    ensure!(
        !active.cancel.is_cancelled(),
        "session cancelled before startup"
    );
    let mut network = Network::start(&opts).await?;
    let mut wake = if opts.no_bluetooth || opts.no_radio {
        None
    } else {
        match Wake::start(opts.bluetooth_adapter.as_deref(), identity.hashes).await {
            Ok(w) => Some(w),
            Err(e) => {
                tracing::warn!(
                    "BLE unavailable: {e:#}; receivers may require the AirDrop screen open"
                );
                None
            }
        }
    };
    let result = async {
        let receiving = matches!(request.0, Command::Receive { .. });
        let once = matches!(request.0, Command::Receive { once: true, .. });
        let receiver = Receiver::new(
            opts.name.clone(),
            identity.clone(),
            output,
            opts.max_bytes,
            opts.auto_accept,
            if nix::unistd::geteuid().is_root() {
                Some((uid, gid))
            } else {
                None
            },
        ).with_once(once);
        let sender = (!receiving).then(|| Sender {
            name: opts.name.clone(),
            id: network.mac.0.iter().map(|b| format!("{b:02x}")).collect(),
            identity,
            tag: wake.as_ref().map(|w| w.tag),
            ask_timeout: Duration::from_secs(60),
        });
        let discovery = if receiving { Discovery::receiving() } else { Discovery::default() };
        // Keep AWDL alive until discovery has sent its goodbye and services drained.
        let cancel = active.cancel.clone();
        let mut tasks = tokio::task::JoinSet::new();
        let listener = crate::transfer::listener(network.address.into(), network.interface.as_deref()).await?;
        tasks.spawn({
            let cancel = cancel.clone();
            let receiver = receiver.clone();
            async move {
                receiver
                    .serve(listener, cancel)
                    .await
                    .context("AirDrop HTTPS server")
            }
        });
        if let Some(interface) = &network.interface {
            tasks.spawn({
                let interface = interface.clone();
                let discovery = discovery.clone();
                let cancel = cancel.clone();
                let id = network.mac.0.iter().map(|b| format!("{b:02x}")).collect::<String>();
                let address = *network.address.ip();
                let port = network.address.port();
                let snapshot = network.snapshot.clone();
                async move {
                    discovery
                        .run(&interface, &id, address, port, cancel, snapshot)
                        .await
                        .context("mDNS discovery")
                }
            });
        }
        let state = State {
            receiver,
            sender,
            discovery,
            cancel: cancel.clone(),
            snapshot: network.snapshot.clone(),
            scope: network.address.scope_id(),
        };
        *active.live.lock().await = Some(state.clone());
        tracing::info!(id=%active.id, kind=active.kind, address=%network.address, "AirDrop session ready");
        let operation = tokio::select! {
            _ = cancel.cancelled() => {
                if receiving { Ok(()) } else { Err(anyhow::anyhow!("send cancelled")) }
            },
            _ = async {
                if let Some(seconds) = opts.duration {
                    tokio::time::sleep(Duration::from_secs(seconds)).await;
                } else { std::future::pending().await }
            } => {
                if receiving { Ok(()) } else { Err(anyhow::anyhow!("send session duration expired")) }
            },
            result = state.command(request.0, request.1), if !receiving => {
                match result {
                    Ok(value) => { *active.result.lock().await = Some(value); Ok(()) },
                    Err(error) => Err(error),
                }
            },
            done = tasks.join_next() => {
                match done {
                    Some(result) => result.context("AirDrop service task").and_then(|r| r),
                    None => Err(anyhow::anyhow!("AirDrop services stopped")),
                }
            },
            _ = async {
                loop {
                    if network.task.as_ref().is_some_and(|t| t.is_finished()) { break; }
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            } => Err(anyhow::anyhow!("AWDL runtime stopped")),
        };
        if once && operation.is_ok()
            && state.receiver.transfers().await.iter().any(|t| t.state == "completed") {
            // HTTPS has drained, but leave the radio and advertisements active
            // briefly so the phone can finish its transfer UI before teardown.
            tracing::info!(seconds=RECEIVE_COMPLETION_GRACE.as_secs(), "receive completed; keeping AWDL active before teardown");
            tokio::select! {
                _ = tokio::time::sleep(RECEIVE_COMPLETION_GRACE) => (),
                _ = cancel.cancelled() => (),
            }
        }
        cancel.cancel();
        let drained = tokio::time::timeout(Duration::from_secs(2), async {
            while tasks.join_next().await.is_some() {}
        })
        .await;
        if drained.is_err() {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
        operation
    }
    .await;
    if let Some(wake) = &mut wake {
        wake.stop().await;
    }
    let cleanup = network.stop().await;
    match (result, cleanup) {
        (Err(e), Err(cleanup)) => {
            Err(e.context(format!("runtime/restoration failed: {cleanup:#}")))
        }
        (result, Ok(())) => result,
        (Ok(()), Err(e)) => Err(e),
    }
}

#[derive(Clone)]
struct Active {
    id: String,
    kind: &'static str,
    cancel: CancellationToken,
    live: Arc<Mutex<Option<State>>>,
    result: Arc<Mutex<Option<serde_json::Value>>>,
}
#[derive(Clone)]
struct Daemon {
    opts: Options,
    cancel: CancellationToken,
    active: Arc<Mutex<Option<Active>>>,
    history: Arc<Mutex<Vec<Transfer>>>,
    sessions: tokio_util::task::TaskTracker,
}
fn merge_options(base: &mut serde_json::Value, overrides: &serde_json::Value) -> Result<()> {
    if overrides.is_null() {
        return Ok(());
    }
    let object = overrides
        .as_object()
        .context("session options must be an object")?;
    let target = base.as_object_mut().context("invalid session defaults")?;
    for (key, value) in object {
        let slot = target
            .get_mut(key)
            .with_context(|| format!("unknown session option {key}"))?;
        if key == "radio" {
            merge_options(slot, value)?;
        } else {
            *slot = value.clone();
        }
    }
    Ok(())
}
impl Daemon {
    async fn serve_control(&self, listener: UnixListener, uid: u32) -> Result<()> {
        let clients = Arc::new(tokio::sync::Semaphore::new(16));
        let mut connections = tokio::task::JoinSet::new();
        let result = async {
            loop {
                tokio::select! {
                    _ = self.cancel.cancelled() => break,
                    done = connections.join_next(), if !connections.is_empty() => {
                        if let Some(Err(e)) = done {
                            tracing::debug!("control task: {e}");
                        }
                    }
                    accept = listener.accept() => {
                        let (socket, _) = accept?;
                        let Ok(permit) = clients.clone().try_acquire_owned() else {
                            continue;
                        };
                        let state = self.clone();
                        connections.spawn(async move {
                            let _permit = permit;
                            if let Err(e) = state.connection(socket, uid).await {
                                tracing::debug!("control request: {e:#}");
                            }
                        });
                    }
                }
            }
            Ok(())
        }
        .await;
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        result
    }

    fn options(&self, overrides: &serde_json::Value) -> Result<Options> {
        let mut base = serde_json::to_value(&self.opts)?;
        base["duration"] = serde_json::Value::Null;
        merge_options(&mut base, overrides)?;
        let opts: Options = serde_json::from_value(base)?;
        ensure!(
            opts.run_dir == self.opts.run_dir,
            "session run-dir must match the control socket"
        );
        ensure!(
            owner(opts.owner.as_deref())?.0 == owner(self.opts.owner.as_deref())?.0,
            "session owner must match the daemon owner"
        );
        Ok(opts)
    }
    async fn live(&self) -> Result<State> {
        let active = self
            .active
            .lock()
            .await
            .clone()
            .context("no active AirDrop session; start send or receive")?;
        active
            .live
            .lock()
            .await
            .clone()
            .context("AirDrop session is starting")
    }
    async fn start(
        &self,
        request: Request,
        client_cancel: CancellationToken,
    ) -> Result<serde_json::Value> {
        let (kind, overrides) = match &request.0 {
            Command::Receive { options, .. } => ("receive", options),
            Command::Send { options, .. } => ("send", options),
            _ => bail!("not a session request"),
        };
        let opts = self.options(overrides)?;
        let active = Active {
            id: uuid::Uuid::new_v4().to_string(),
            kind,
            cancel: client_cancel,
            live: Arc::default(),
            result: Arc::default(),
        };
        {
            let mut current = self.active.lock().await;
            ensure!(
                current.is_none(),
                "an AirDrop session is already active; finish or cancel it first"
            );
            *current = Some(active.clone());
        }
        let daemon = self.clone();
        let (reply, result) = oneshot::channel();
        self.sessions.spawn(async move {
            let outcome = session(opts, active.clone(), request).await;
            let mut received = Vec::new();
            if let Some(live) = active.live.lock().await.take() {
                let transfers = live.receiver.transfers().await;
                received.extend(
                    transfers
                        .iter()
                        .filter(|t| t.state == "completed")
                        .map(|t| t.offer.id.clone()),
                );
                let mut history = daemon.history.lock().await;
                history.extend(transfers);
                let extra = history.len().saturating_sub(256);
                history.drain(..extra);
            }
            *daemon.active.lock().await = None;
            let outcome = match outcome {
                Ok(()) => Ok(active
                    .result
                    .lock()
                    .await
                    .take()
                    .unwrap_or_else(|| serde_json::json!({"received":received}))),
                Err(error) => Err(error),
            };
            let _ = reply.send(outcome);
        });
        result.await.context("session task stopped")?
    }
    async fn command(
        &self,
        command: Command,
        archive: Option<tempfile::NamedTempFile>,
        client_cancel: CancellationToken,
    ) -> Result<serde_json::Value> {
        match command {
            Command::Receive { .. } | Command::Send { .. } => {
                self.start((command, archive), client_cancel).await
            }
            Command::Status => {
                let active = self.active.lock().await.clone();
                if let Some(active) = active {
                    let live = active.live.lock().await.clone();
                    let mut value = if let Some(live) = live {
                        live.command(Command::Status, None).await?
                    } else {
                        serde_json::json!({"name":self.opts.name,"awdl":{},"sending":[],"transfers":[]})
                    };
                    value["sending"] = if active.kind == "send" {
                        serde_json::json!([active.id])
                    } else {
                        serde_json::json!([])
                    };
                    value["session"] = serde_json::json!({"id":active.id,"kind":active.kind,"phase":if active.live.lock().await.is_some(){"active"}else{"starting"}});
                    Ok(value)
                } else {
                    Ok(
                        serde_json::json!({"name":self.opts.name,"session":null,"awdl":{},"sending":[],"transfers":self.history.lock().await.clone()}),
                    )
                }
            }
            Command::Transfers => {
                let mut transfers = self.history.lock().await.clone();
                if let Ok(live) = self.live().await {
                    transfers.extend(live.receiver.transfers().await);
                }
                Ok(serde_json::to_value(transfers)?)
            }
            Command::Cancel { id } => {
                let active = self
                    .active
                    .lock()
                    .await
                    .clone()
                    .context("no active session")?;
                ensure!(active.id == id, "unknown session ID");
                active.cancel.cancel();
                Ok(serde_json::json!({"cancelled":id}))
            }
            Command::Stop => Ok(serde_json::json!({"stopping":true})),
            command => self.live().await?.command(command, archive).await,
        }
    }
    async fn connection(&self, socket: UnixStream, uid: u32) -> Result<()> {
        let peer = socket.peer_cred()?;
        ensure!(
            peer.uid() == uid || peer.uid() == 0,
            "control client is not the daemon owner"
        );
        let mut reader = BufReader::new(socket);
        let command: Command = serde_json::from_slice(
            &tokio::time::timeout(Duration::from_secs(10), read_line(&mut reader)).await??,
        )?;
        let archive = if let Command::Send {
            bytes,
            items,
            urls,
            options,
            ..
        } = &command
        {
            let opts = self.options(options)?;
            ensure!(
                *bytes <= opts.max_bytes,
                "control archive exceeds size limit"
            );
            ensure!(
                (*bytes > 0 && !items.is_empty() && urls.is_empty())
                    || (*bytes == 0 && items.is_empty() && !urls.is_empty()),
                "invalid send framing"
            );
            if *bytes > 0 {
                let file = tempfile::NamedTempFile::new()?;
                let mut writer = tokio::fs::File::from_std(file.reopen()?);
                let n = tokio::time::timeout(
                    Duration::from_secs(600),
                    tokio::io::copy(&mut (&mut reader).take(*bytes), &mut writer),
                )
                .await??;
                ensure!(n == *bytes, "truncated control archive");
                writer.flush().await?;
                Some(file)
            } else {
                None
            }
        } else {
            None
        };
        let stop = matches!(command, Command::Stop);
        let cancellation = self.cancel.child_token();
        let operation = self.command(command, archive, cancellation.clone());
        tokio::pin!(operation);
        let mut unexpected = [0];
        let result = tokio::select! {
            result = &mut operation => Some(result),
            _ = reader.read(&mut unexpected) => {
                cancellation.cancel();
                let _ = operation.await;
                None
            }
        };
        if let Some(result) = result {
            let value = match result {
                Ok(value) => serde_json::json!({"ok":value}),
                Err(e) => serde_json::json!({"error":format!("{e:#}")}),
            };
            let mut socket = reader.into_inner();
            socket.write_all(&serde_json::to_vec(&value)?).await?;
            socket.write_all(b"\n").await?;
        }
        if stop {
            self.cancel.cancel();
        }
        Ok(())
    }
}
pub async fn run(opts: Options, initial: Option<Request>) -> Result<()> {
    let (uid, gid, _) = owner(opts.owner.as_deref())?;
    std::fs::create_dir_all(&opts.run_dir)?;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(opts.run_dir.join("daemon.lock"))?;
    fs2::FileExt::try_lock_exclusive(&lock).context("another daemon is running")?;
    let socket_path = opts.run_dir.join("control.sock");
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }
    let listener = UnixListener::bind(&socket_path)?;
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
    if nix::unistd::geteuid().is_root() {
        nix::unistd::chown(
            &socket_path,
            Some(nix::unistd::Uid::from_raw(uid)),
            Some(nix::unistd::Gid::from_raw(gid)),
        )?;
    }
    let cancel = CancellationToken::new();
    let daemon = Daemon {
        opts: opts.clone(),
        cancel: cancel.clone(),
        active: Arc::default(),
        history: Arc::default(),
        sessions: tokio_util::task::TaskTracker::new(),
    };
    let server = tokio::spawn({
        let daemon = daemon.clone();
        async move { daemon.serve_control(listener, uid).await }
    });
    let signal = tokio::spawn(signals(
        cancel.clone(),
        if initial.is_none() {
            opts.duration
        } else {
            None
        },
    ));
    tracing::info!(control=%socket_path.display(), "AirDrop control ready; radio and HTTPS inactive");
    let result = if let Some(request) = initial {
        daemon
            .command(request.0, request.1, cancel.child_token())
            .await
            .map(|value| {
                println!("{value:#}");
            })
    } else {
        tokio::select! {
            _ = cancel.cancelled() => Ok(()),
            _ = async { loop { if server.is_finished() {break;} tokio::time::sleep(Duration::from_millis(100)).await;} } => Err(anyhow::anyhow!("control server stopped")),
        }
    };
    cancel.cancel();
    daemon.sessions.close();
    daemon.sessions.wait().await;
    let cleanup = server
        .await
        .context("control server task")
        .and_then(|result| result);
    signal.abort();
    let _ = signal.await;
    let _ = std::fs::remove_file(&socket_path);
    result.and(cleanup)
}
