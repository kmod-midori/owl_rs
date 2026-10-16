// SPDX-License-Identifier: GPL-3.0-or-later
//! Native service lifecycle and authenticated Unix control socket.
use crate::{
    archive,
    ble::Wake,
    discovery::Discovery,
    identity::Identity,
    link::Link,
    session::{Activity, Lease},
    transfer::{Receiver, Sender, Transfer},
    transport::Transport,
    visibility::{self, Policy},
};
use anyhow::{Context, Result, bail, ensure};
use std::{net::SocketAddrV6, os::unix::fs::PermissionsExt, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::{Mutex, watch},
};
use tokio_util::sync::CancellationToken;
#[cfg(feature = "tray")]
#[path = "desktop/mod.rs"]
mod desktop;
use airdrop_client::control::read_line;
pub use airdrop_client::control::{
    Command, ContactAction, Options, client, current_user, default_run_dir,
};
#[derive(Clone)]
struct State {
    receiver: Receiver,
    sender: Sender,
    discovery: Discovery,
    cancel: CancellationToken,
    snapshot: watch::Receiver<serde_json::Value>,
    scope: u32,
    activity: Arc<Activity>,
}
impl State {
    async fn probe_receivers(
        &self,
        deadline: tokio::time::Instant,
    ) -> impl futures_util::Stream<Item = (crate::discovery::Peer, Option<String>)> + '_ {
        use futures_util::{StreamExt, stream};
        let sender = &self.sender;
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
                        && let Ok(mac) = mac.parse::<owl_ipc::Mac>()
                        && mac.valid_unicast()
                        && !candidates
                            .iter()
                            .any(|(p, _)| *p.address.ip() == mac.ipv6())
                    {
                        candidates.push((
                            crate::discovery::Peer::from_awdl(
                                mac,
                                self.scope,
                                self.sender.timeouts.discovery_fallback,
                            ),
                            true,
                        ));
                    }
                }
            }
        }
        stream::iter(candidates)
            .map(move |(peer, fallback)| async move {
                let end =
                    deadline.min(tokio::time::Instant::now() + self.sender.timeouts.name_probe);
                let Ok(_exchange) = self.activity.acquire() else {
                    return (peer, None, fallback);
                };
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
    }
    async fn named_peers(&self, seconds: u64) -> Vec<serde_json::Value> {
        use futures_util::StreamExt;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds.clamp(1, 86400));
        loop {
            let peers: Vec<_> = self.probe_receivers(deadline).await
                .map(|(p, name)| serde_json::json!({"id":p.id,"name":name,"address":p.address,"flags":p.flags}))
                .collect().await;
            if !peers.is_empty() || tokio::time::Instant::now() >= deadline {
                return peers;
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
        use futures_util::StreamExt;
        if let Some(address) = direct {
            ensure!(
                address.ip().is_loopback() || address.ip().is_unicast_link_local(),
                "direct AirDrop address must be loopback or link-local"
            );
            return Ok(address);
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds.clamp(1, 86400));
        loop {
            for peer in self.discovery.list().await {
                if peer.id.eq_ignore_ascii_case(to) {
                    return Ok(peer.address);
                }
            }
            let probes = self.probe_receivers(deadline).await;
            futures_util::pin_mut!(probes);
            while let Some((peer, name)) = probes.next().await {
                if let Some(name) = name
                    && name.eq_ignore_ascii_case(to)
                {
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
        self.command_with_progress(command, archive, None).await
    }
    async fn command_with_progress(
        &self,
        command: Command,
        archive: Option<tempfile::NamedTempFile>,
        progress: Option<crate::progress::Progress>,
    ) -> Result<serde_json::Value> {
        match command {
            Command::Status => Ok(
                serde_json::json!({"name":self.receiver.name,"visibility":self.receiver.visibility(),"awdl":self.snapshot.borrow().clone(),"sending":[],"transfers":self.receiver.transfers().await}),
            ),
            Command::Peers { timeout } => {
                Ok(serde_json::to_value(self.named_peers(timeout).await)?)
            }
            Command::Transfers => Ok(serde_json::to_value(self.receiver.transfers().await)?),
            Command::Accept { id: Some(id) } => {
                self.receiver.decide(&id, true).await?;
                Ok(serde_json::json!({"accepted":id}))
            }
            Command::Reject { id } => {
                self.receiver.decide(&id, false).await?;
                Ok(serde_json::json!({"rejected":id}))
            }
            Command::SendPaths { .. }
            | Command::Contact { .. }
            | Command::Cancel { .. }
            | Command::Stop
            | Command::Discoverable { .. }
            | Command::Accept { id: None } => {
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
                let sender = &self.sender;
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
                        sender.send_with_context(address, items, urls, archive.as_ref().map(|f| f.path().into()), icon, crate::transfer::SendContext { activity: Some(&self.activity), progress }).await
                    } => result,
                };
                let id = result?;
                Ok(serde_json::json!({"sent":id,"receiver":to}))
            }
        }
    }
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
async fn expires(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}
pub type Request = (Command, Option<tempfile::NamedTempFile>);
async fn session(active: &Active) -> Result<()> {
    let opts = &active.opts;
    let (_, home) = current_user()?;
    let keys = opts
        .keys
        .clone()
        .unwrap_or_else(|| home.join(".local/share/owl_rs/identity"));
    let output = opts
        .output
        .clone()
        .unwrap_or_else(|| home.join("Downloads/AirDrop"));
    crate::identity::private_directory(&keys)?;
    let identity = Identity::load(&keys, &opts.name)?;
    ensure!(
        !active.cancel.is_cancelled(),
        "session cancelled before startup"
    );
    let mut link = if opts.no_radio {
        let std::net::IpAddr::V6(ip) = opts.listen.ip() else {
            bail!("AirDrop requires an IPv6 listener")
        };
        Link::loopback(ip)?
    } else {
        Link::start(
            &opts.owl_socket,
            opts.listen.port(),
            opts.timeouts,
            active.policy.clone(),
            active.activity.traffic(),
        )
        .await?
    };
    if !opts.no_radio {
        active
            .activity
            .set_channel_ready(link.channel_ready.clone());
    }
    let result = async {
        let receiver = Receiver::new(
            opts.name.clone(), identity.clone(), output, opts.max_bytes,
            opts.auto_accept,
        )
        .with_policy(active.policy.clone())
        .with_activity(active.activity.clone()).with_timeouts(opts.timeouts);
        let sender = Sender {
            name: opts.name.clone(),
            id: link.mac.0.iter().map(|b| format!("{b:02x}")).collect(),
            identity, tag: None, timeouts: opts.timeouts,
        };
        let bluetooth = !opts.no_bluetooth && !opts.no_radio;
        let mut transport = Transport::start(
            receiver, sender, &link, active.policy.clone(), opts.listen.port(),
            bluetooth, opts.bluetooth_adapter.clone(),
        ).await?;
        link.announce();
        let state = State {
            receiver: transport.receiver.clone(),
            sender: transport.sender.clone(),
            discovery: transport.discovery.clone(),
            cancel: active.cancel.clone(),
            snapshot: link.snapshot.clone(), scope: link.scope,
            activity: active.activity.clone(),
        };
        *active.live.lock().await = Some(state);
        active.phase.send_replace(Phase::Ready);
        tracing::info!(id=%active.id, address=%link.address, "AirDrop session ready");
        let result = tokio::select! {
            _ = active.cancel.cancelled() => Ok(()),
            _ = active.activity.idle(active.policy.clone()) => Ok(()),
            done = transport.tasks.join_next() => match done {
                Some(result) => result.context("AirDrop service task").and_then(|r| r),
                None => Err(anyhow::anyhow!("AirDrop transport stopped")),
            },
            _ = async { while !link.stopped() { tokio::time::sleep(Duration::from_millis(250)).await; } } => Err(anyhow::anyhow!("AWDL link stopped")),
        };
        active.phase.send_replace(Phase::Closing);
        active.activity.close();
        active.cancel.cancel();
        transport.stop().await;
        result
    }.await;
    // The transport has sent its goodbyes and released its sockets before the
    // link drains queued frames and restores the WLAN journal.
    let cleanup = link.stop().await;
    match (result, cleanup) {
        (Err(error), Err(cleanup)) => {
            Err(error.context(format!("link restoration failed: {cleanup:#}")))
        }
        (result, Ok(())) => result,
        (Ok(()), Err(error)) => Err(error),
    }
}

#[derive(Clone)]
enum Phase {
    Starting,
    Ready,
    Closing,
    Stopped(Option<String>),
}
#[derive(Clone)]
struct Active {
    id: String,
    opts: Options,
    cancel: CancellationToken,
    live: Arc<Mutex<Option<State>>>,
    phase: watch::Sender<Phase>,
    policy: watch::Receiver<Policy>,
    activity: Arc<Activity>,
    sending: watch::Sender<std::collections::BTreeSet<String>>,
}
impl Active {
    async fn ready(&self) -> Result<State> {
        let mut phase = self.phase.subscribe();
        loop {
            let current = phase.borrow_and_update().clone();
            match current {
                Phase::Ready => {
                    return self
                        .live
                        .lock()
                        .await
                        .clone()
                        .context("AirDrop transport stopped");
                }
                Phase::Closing => bail!("AirDrop session is closing"),
                Phase::Stopped(error) => {
                    bail!("{}", error.as_deref().unwrap_or("AirDrop session stopped"))
                }
                Phase::Starting => (),
            }
            phase
                .changed()
                .await
                .context("AirDrop session task stopped")?;
        }
    }
    async fn stopped(&self) -> Result<()> {
        let mut phase = self.phase.subscribe();
        loop {
            if let Phase::Stopped(error) = phase.borrow_and_update().clone() {
                return error.map_or(Ok(()), |error| Err(anyhow::anyhow!(error)));
            }
            phase
                .changed()
                .await
                .context("AirDrop session task stopped")?;
        }
    }
}
struct Sending {
    lease: Lease,
    ids: watch::Sender<std::collections::BTreeSet<String>>,
    id: String,
}
impl Drop for Sending {
    fn drop(&mut self) {
        self.ids.send_modify(|ids| {
            ids.remove(&self.id);
        });
    }
}
#[derive(Clone)]
struct Daemon {
    opts: Options,
    cancel: CancellationToken,
    active: Arc<Mutex<Option<Active>>>,
    history: Arc<Mutex<Vec<Transfer>>>,
    sessions: tokio_util::task::TaskTracker,
    visibility: Arc<visibility::Control>,
    ble: watch::Receiver<bool>,
    outgoing: Arc<Mutex<std::collections::BTreeMap<String, crate::progress::Progress>>>,
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
        if key == "timeouts" {
            merge_options(slot, value)?;
        } else {
            *slot = value.clone();
        }
    }
    Ok(())
}
impl Daemon {
    async fn bluetooth(&self, listening: watch::Sender<bool>) {
        let (wakes, mut requests) = tokio::sync::mpsc::channel(1);
        let scanner = tokio::spawn({
            let adapter = self.opts.bluetooth_adapter.clone();
            let timeouts = self.opts.timeouts;
            let mut policy = self.visibility.tx.subscribe();
            let cancel = self.cancel.clone();
            async move {
                loop {
                    if cancel.is_cancelled() {
                        break;
                    }
                    let result = crate::ble::listen(
                        adapter.as_deref(),
                        policy.clone(),
                        cancel.clone(),
                        wakes.clone(),
                        listening.clone(),
                        timeouts,
                    )
                    .await;
                    if let Err(error) = result {
                        tracing::warn!("BLE wake listener unavailable: {error:#}");
                    }
                    // Changes already handled by listen must not bypass backoff.
                    // Off returns to the listener's policy wait immediately.
                    if !policy.borrow_and_update().mode.enabled() {
                        continue;
                    }
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = visibility::changed(&mut policy) => (),
                        _ = tokio::time::sleep(timeouts.ble_retry) => (),
                    }
                }
            }
        });
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => break,
                Some(hint) = requests.recv() => {
                    if !self.visibility.tx.borrow().mode.enabled() { continue; }
                    let result = tokio::select! {
                        _ = self.cancel.cancelled() => break,
                        result = self.activate(&serde_json::Value::Null, Some(hint), false) => result,
                    };
                    if let Err(error) = result {
                        tracing::warn!("BLE activation: {error:#}");
                    }
                }
            }
        }
        let _ = scanner.await;
    }
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
            opts.owl_socket == self.opts.owl_socket,
            "session owld socket must match the daemon"
        );
        opts.validate()?;
        Ok(opts)
    }
    async fn live(&self) -> Result<State> {
        let active = self
            .active
            .lock()
            .await
            .clone()
            .context("no active AirDrop session; send or enable BLE discoverability")?;
        active
            .live
            .lock()
            .await
            .clone()
            .context("AirDrop session is starting")
    }
    async fn activate(
        &self,
        overrides: &serde_json::Value,
        wake: Option<crate::ble::WakeHint>,
        outgoing: bool,
    ) -> Result<(Active, Option<Lease>)> {
        loop {
            let revision = if let Some(hint) = wake {
                let policy = self.visibility.tx.borrow().clone();
                ensure!(
                    crate::ble::eligible(hint, policy.clone()).await,
                    "BLE wake does not match the current receiving policy"
                );
                Some(policy.revision)
            } else {
                None
            };
            let mut current = self.active.lock().await;
            if let Some(active) = current.as_ref() {
                if active.activity.closed() || active.cancel.is_cancelled() {
                    let active = active.clone();
                    drop(current);
                    active.stopped().await?;
                    continue;
                }
                let mut requested = serde_json::to_value(&active.opts)?;
                merge_options(&mut requested, overrides)?;
                requested["duration"] = serde_json::Value::Null;
                let requested: Options = serde_json::from_value(requested)?;
                ensure!(
                    serde_json::to_value(requested)? == serde_json::to_value(&active.opts)?,
                    "session settings differ from the active link; cancel it before changing settings"
                );
                let lease = if outgoing {
                    match active.activity.acquire() {
                        Ok(lease) => Some(lease),
                        Err(_) if active.activity.closed() => {
                            let active = active.clone();
                            drop(current);
                            active.stopped().await?;
                            continue;
                        }
                        Err(error) => return Err(error),
                    }
                } else {
                    None
                };
                let refreshed = revision.map(|revision| {
                    let policy = self.visibility.tx.borrow();
                    if policy.revision != revision {
                        return None;
                    }
                    Some(active.activity.wake())
                });
                if matches!(refreshed, Some(None)) {
                    drop(current);
                    continue;
                }
                if let Some(Some(Err(error))) = refreshed {
                    if active.activity.closed() {
                        let active = active.clone();
                        drop(current);
                        drop(lease);
                        active.stopped().await?;
                        continue;
                    }
                    return Err(error);
                }
                if wake.is_some() {
                    tracing::debug!("eligible BLE wake refreshed session deadline");
                }
                return Ok((active.clone(), lease));
            }
            ensure!(!self.cancel.is_cancelled(), "daemon is stopping");
            if wake.is_some() {
                ensure!(
                    self.visibility.tx.borrow().mode.enabled(),
                    "receiving is off"
                );
            }
            let mut opts = self.options(overrides)?;
            opts.duration = None;
            let timeouts = opts.timeouts;
            let active = Active {
                id: uuid::Uuid::new_v4().to_string(),
                opts,
                cancel: self.cancel.child_token(),
                live: Arc::default(),
                phase: watch::channel(Phase::Starting).0,
                policy: self.visibility.tx.subscribe(),
                activity: Activity::new(timeouts),
                sending: watch::channel(Default::default()).0,
            };
            let lease = if outgoing {
                Some(active.activity.acquire()?)
            } else {
                None
            };
            if let Some(revision) = revision {
                let policy = self.visibility.tx.borrow();
                if policy.revision != revision {
                    drop(policy);
                    drop(current);
                    continue;
                }
                active.activity.wake()?;
            }
            *current = Some(active.clone());
            if wake.is_some() {
                tracing::info!("eligible AirDrop BLE wake; starting radio session");
            }
            let daemon = self.clone();
            let worker = active.clone();
            self.sessions.spawn(async move {
                let result = session(&worker).await;
                worker.activity.close();
                if let Some(live) = worker.live.lock().await.take() {
                    let mut history = daemon.history.lock().await;
                    history.extend(live.receiver.transfers().await);
                    let extra = history.len().saturating_sub(256);
                    history.drain(..extra);
                }
                *daemon.active.lock().await = None;
                let error = result.err().map(|error| format!("{error:#}"));
                if let Some(error) = &error {
                    tracing::warn!(%error, "AirDrop session stopped");
                }
                worker.phase.send_replace(Phase::Stopped(error));
                worker.cancel.cancel();
            });
            return Ok((active, lease));
        }
    }
    async fn send(
        &self,
        command: Command,
        archive: Option<tempfile::NamedTempFile>,
        client_cancel: CancellationToken,
    ) -> Result<serde_json::Value> {
        let Command::Send {
            to, items, urls, ..
        } = &command
        else {
            unreachable!()
        };
        let names = if items.is_empty() {
            urls.clone()
        } else {
            items.iter().map(|item| item.name.clone()).collect()
        };
        let progress =
            crate::progress::Progress::new(to.clone(), names, client_cancel.child_token());
        let _guard = progress.guard();
        let id = progress.state.borrow().id.clone();
        {
            let mut outgoing = self.outgoing.lock().await;
            if outgoing.len() >= 256 {
                let key = outgoing
                    .iter()
                    .find(|(_, value)| crate::progress::terminal(&value.state.borrow().state))
                    .map(|(id, _)| id.clone())
                    .context("too many outgoing transfers")?;
                outgoing.remove(&key);
            }
            outgoing.insert(id, progress.clone());
        }
        let result = self.send_tracked(command, archive, &progress).await;
        progress.finish(result.as_ref().err().map(|error| format!("{error:#}")));
        result
    }
    async fn send_tracked(
        &self,
        command: Command,
        archive: Option<tempfile::NamedTempFile>,
        progress: &crate::progress::Progress,
    ) -> Result<serde_json::Value> {
        let Command::Send { options, .. } = &command else {
            unreachable!()
        };
        let deadline = self
            .options(options)?
            .duration
            .map(|seconds| tokio::time::Instant::now() + Duration::from_secs(seconds));
        let (active, lease) = tokio::select! {
            _ = progress.cancel.cancelled() => bail!("send cancelled"),
            _ = expires(deadline) => bail!("send duration expired"),
            result = self.activate(options, None, true) => result?,
        };
        let id = progress.state.borrow().id.clone();
        active.sending.send_modify(|ids| {
            ids.insert(id.clone());
        });
        let sending = Sending {
            lease: lease.context("missing send lifetime")?,
            ids: active.sending.clone(),
            id,
        };
        let mut wake = None;
        let result = tokio::select! {
            _ = progress.cancel.cancelled() => Err(anyhow::anyhow!("send cancelled")),
            _ = active.cancel.cancelled() => { progress.cancel.cancel(); Err(anyhow::anyhow!("AirDrop session cancelled")) },
            _ = expires(deadline) => Err(anyhow::anyhow!("send duration expired")),
            result = async {
                let mut state = active.ready().await?;
                if !active.opts.no_bluetooth && !active.opts.no_radio {
                    match Wake::start(active.opts.bluetooth_adapter.as_deref(), [0; 8], active.opts.timeouts).await {
                        Ok(advertisement) => { state.sender.tag = Some(advertisement.tag); wake = Some(advertisement); },
                        Err(error) => tracing::warn!("BLE wake unavailable: {error:#}"),
                    }
                }
                state.command_with_progress(command, archive, Some(progress.clone())).await
            } => result,
        };
        if let Some(wake) = &mut wake {
            wake.stop().await;
        }
        if result.is_ok() {
            sending.lease.complete();
        }
        drop(sending);
        result
    }
    async fn command(
        &self,
        command: Command,
        archive: Option<tempfile::NamedTempFile>,
        client_cancel: CancellationToken,
    ) -> Result<serde_json::Value> {
        match command {
            Command::Contact {
                action,
                contacts_file,
            } => {
                let path =
                    contacts_file.unwrap_or_else(|| self.visibility.tx.borrow().path.clone());
                ensure!(path.is_absolute(), "contacts path must be absolute");
                tokio::task::spawn_blocking(move || {
                    use crate::contact_book::{self, Book};
                    match action {
                        ContactAction::List => {
                            Ok(serde_json::to_value(contact_book::list(&path)?)?)
                        }
                        ContactAction::Add { identifiers } => {
                            Ok(serde_json::to_value(Book::new(path).add(&identifiers)?)?)
                        }
                        ContactAction::Remove { identifiers } => {
                            Ok(serde_json::to_value(Book::new(path).remove(&identifiers)?)?)
                        }
                    }
                })
                .await?
            }
            Command::SendPaths {
                to,
                direct,
                files,
                urls,
                timeout,
                options,
            } => {
                ensure!(!files.is_empty() ^ !urls.is_empty(), "choose files or URLs");
                ensure!(
                    files.iter().all(|path| path.is_absolute()),
                    "send paths must be absolute"
                );
                let opts = self.options(&options)?;
                let prepared = if files.is_empty() {
                    None
                } else {
                    let cancel = client_cancel.child_token();
                    let _guard = cancel.clone().drop_guard();
                    let prepare = tokio::task::spawn_blocking(move || {
                        archive::prepare_cancellable(&files, opts.max_bytes, &cancel)
                    });
                    Some(tokio::select! {
                        _ = client_cancel.cancelled() => bail!("send cancelled"),
                        result = tokio::time::timeout(opts.timeouts.control_archive, prepare) => result.context("archive preparation timed out")???,
                    })
                };
                let (items, bytes, icon, archive) = match prepared {
                    Some(prepared) => (
                        prepared.items,
                        prepared.bytes,
                        prepared.icon,
                        Some(prepared.file),
                    ),
                    None => (Vec::new(), 0, None, None),
                };
                ensure!(bytes <= opts.max_bytes, "archive exceeds size limit");
                self.send(
                    Command::Send {
                        to,
                        direct,
                        items,
                        urls,
                        bytes,
                        icon,
                        timeout,
                        options,
                    },
                    archive,
                    client_cancel,
                )
                .await
            }
            Command::Send { .. } => self.send(command, archive, client_cancel).await,
            Command::Peers { .. } => {
                let active = self
                    .active
                    .lock()
                    .await
                    .clone()
                    .context("no active AirDrop session")?;
                let _lease = active.activity.acquire()?;
                tokio::select! {
                    _ = client_cancel.cancelled() => bail!("peer discovery cancelled"),
                    _ = active.cancel.cancelled() => bail!("AirDrop session cancelled"),
                    result = async { active.ready().await?.command(command, None).await } => result,
                }
            }
            Command::Discoverable {
                mode,
                contacts_file,
            } => {
                self.visibility.set(mode, contacts_file).await?;
                Ok(serde_json::json!({"visibility": mode}))
            }
            Command::Accept { id: None } => loop {
                if let Ok(live) = self.live().await
                    && let Some(id) = live.receiver.accept_next().await?
                {
                    return Ok(serde_json::json!({"accepted": id}));
                }
                tokio::select! {
                    _ = client_cancel.cancelled() => bail!("accept cancelled"),
                    _ = tokio::time::sleep(Duration::from_millis(100)) => (),
                }
            },
            Command::Status => {
                let mode = self.visibility.tx.borrow().mode;
                let outgoing: Vec<_> = self
                    .outgoing
                    .lock()
                    .await
                    .values()
                    .map(|progress| progress.state.borrow().clone())
                    .collect();
                let listening = *self.ble.borrow();
                let active = self.active.lock().await.clone();
                if let Some(active) = active {
                    let live = active.live.lock().await.clone();
                    let mut value = if let Some(live) = live {
                        live.command(Command::Status, None).await?
                    } else {
                        serde_json::json!({"name":self.opts.name,"visibility":mode,"ble":{"listening":listening},"awdl":{},"sending":[],"transfers":[]})
                    };
                    value["ble"] = serde_json::json!({"listening":listening});
                    value["timeouts"] = serde_json::to_value(
                        crate::timeouts::AirDropTimeouts::from(active.opts.timeouts),
                    )?;
                    value["sending"] = serde_json::to_value(active.sending.borrow().clone())?;
                    value["outgoing"] = serde_json::to_value(outgoing)?;
                    let phase = match &*active.phase.borrow() {
                        Phase::Starting => "starting",
                        Phase::Ready => "active",
                        _ => "closing",
                    };
                    value["session"] = serde_json::json!({"id":active.id,"phase":phase});
                    Ok(value)
                } else {
                    Ok(
                        serde_json::json!({"name":self.opts.name,"visibility":mode,"ble":{"listening":listening},"session":null,"awdl":{},"sending":[],"outgoing":outgoing,"transfers":self.history.lock().await.clone(),"timeouts":crate::timeouts::AirDropTimeouts::from(self.opts.timeouts)}),
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
                if let Some(progress) = self.outgoing.lock().await.get(&id) {
                    ensure!(
                        !crate::progress::terminal(&progress.state.borrow().state),
                        "transfer has already ended"
                    );
                    progress.cancel.cancel();
                    return Ok(serde_json::json!({"cancelled":id}));
                }
                let active = self
                    .active
                    .lock()
                    .await
                    .clone()
                    .context("no active session")?;
                if active.id == id {
                    active.cancel.cancel();
                } else {
                    active.ready().await?.receiver.cancel(&id).await?;
                }
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
            &tokio::time::timeout(self.opts.timeouts.control_request, read_line(&mut reader))
                .await??,
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
                    self.opts.timeouts.control_archive,
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
pub async fn run(opts: Options) -> Result<()> {
    opts.validate()?;
    ensure!(
        !nix::unistd::geteuid().is_root(),
        "airdropd must run as a regular user; start owld separately as root"
    );
    let (uid, home) = current_user()?;
    std::fs::create_dir_all(&opts.run_dir)?;
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(&opts.run_dir)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == uid && metadata.mode() & 0o022 == 0,
        "AirDrop run directory must be owned by this user and not writable by others"
    );
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(opts.run_dir.join("daemon.lock"))?;
    fs2::FileExt::try_lock_exclusive(&lock).context("another daemon is running")?;
    let socket_path = opts.run_dir.join("control.sock");
    owl_ipc::remove_stale_socket(&socket_path)?;
    let listener = UnixListener::bind(&socket_path)?;
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
    let cancel = CancellationToken::new();
    let (listening, ble) = watch::channel(false);
    let daemon = Daemon {
        opts: opts.clone(),
        cancel: cancel.clone(),
        active: Arc::default(),
        history: Arc::default(),
        sessions: tokio_util::task::TaskTracker::new(),
        visibility: visibility::Control::new(crate::contact_book::default_path(&home)),
        ble,
        outgoing: Arc::default(),
    };
    let bluetooth = if !opts.no_bluetooth && !opts.no_radio {
        Some(tokio::spawn({
            let daemon = daemon.clone();
            async move {
                daemon.bluetooth(listening).await;
            }
        }))
    } else {
        None
    };
    let server = tokio::spawn({
        let daemon = daemon.clone();
        async move { daemon.serve_control(listener, uid).await }
    });
    let signal = tokio::spawn(signals(cancel.clone(), opts.duration));
    #[cfg(feature = "tray")]
    let desktop = tokio::spawn(desktop::run(daemon.clone()));
    #[cfg(feature = "tray")]
    let _tray = crate::tray::start(
        &opts.name,
        &opts.run_dir,
        daemon.visibility.clone(),
        cancel.clone(),
    );
    tracing::info!(control=%socket_path.display(), "AirDrop control ready; radio and HTTPS inactive");
    let result = tokio::select! {
        _ = cancel.cancelled() => Ok(()),
        _ = async { loop { if server.is_finished() {break;} tokio::time::sleep(Duration::from_millis(100)).await;} } => Err(anyhow::anyhow!("control server stopped")),
    };
    cancel.cancel();
    daemon.sessions.close();
    daemon.sessions.wait().await;
    if let Some(task) = bluetooth {
        let _ = task.await;
    }
    let cleanup = server
        .await
        .context("control server task")
        .and_then(|result| result);
    signal.abort();
    let _ = signal.await;
    #[cfg(feature = "tray")]
    {
        // A missing or unresponsive desktop service must not delay shutdown.
        let mut desktop = desktop;
        if tokio::time::timeout(Duration::from_secs(2), &mut desktop)
            .await
            .is_err()
        {
            desktop.abort();
            let _ = desktop.await;
        }
    }
    let _ = std::fs::remove_file(&socket_path);
    result.and(cleanup)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{timeouts::Timeouts, visibility::Visibility};
    use clap::Parser;
    use owl_ipc::Mac;
    #[derive(Parser)]
    struct TestArgs {
        #[command(flatten)]
        options: Options,
    }

    // One lifecycle regression covers reuse, both directions, policy changes,
    // independent cancellation and ordered cleanup.
    #[tokio::test]
    async fn shared_session_reuses_link_and_survives_independent_transfer_cancellation() {
        let temp = tempfile::tempdir().unwrap();
        let bind = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let address = bind.local_addr().unwrap();
        drop(bind);
        let mut opts =
            TestArgs::parse_from(["test", "--no-radio", "--no-bluetooth", "--auto-accept"]).options;
        opts.listen = address;
        opts.run_dir = temp.path().join("run");
        opts.keys = Some(temp.path().join("keys"));
        opts.output = Some(temp.path().join("received"));
        let (_, ble) = watch::channel(false);
        let daemon = Daemon {
            opts,
            cancel: CancellationToken::new(),
            active: Arc::default(),
            history: Arc::default(),
            sessions: tokio_util::task::TaskTracker::new(),
            visibility: visibility::Control::new(temp.path().join("contacts")),
            ble,
            outgoing: Arc::default(),
        };
        assert!(
            daemon
                .activate(
                    &serde_json::Value::Null,
                    Some(crate::ble::WakeHint { hashes: [0; 8] }),
                    false
                )
                .await
                .is_err()
        );
        assert!(!temp.path().join("keys").exists());
        daemon
            .visibility
            .set(Visibility::Everyone, None)
            .await
            .unwrap();
        assert!(
            daemon
                .options(&serde_json::json!({"duration":u64::MAX}))
                .is_err()
        );
        let (active, _) = daemon
            .activate(
                &serde_json::Value::Null,
                Some(crate::ble::WakeHint { hashes: [0; 8] }),
                false,
            )
            .await
            .unwrap();
        let state = tokio::time::timeout(Duration::from_secs(5), active.ready())
            .await
            .unwrap()
            .unwrap();
        let (again, _) = daemon
            .activate(
                &serde_json::Value::Null,
                Some(crate::ble::WakeHint { hashes: [0; 8] }),
                false,
            )
            .await
            .unwrap();
        assert_eq!(active.id, again.id);
        let contact_path = temp.path().join("contacts");
        std::fs::write(&contact_path, "friend@example.com\n").unwrap();
        daemon
            .visibility
            .set(Visibility::Contacts, None)
            .await
            .unwrap();
        let hash = openssl::sha::sha256(b"friend@example.com");
        let mut hashes = [0; 8];
        hashes[..2].copy_from_slice(&hash[..2]);
        let matched = crate::ble::WakeHint { hashes };
        let unmatched = crate::ble::WakeHint {
            hashes: [hash[0] ^ 255; 8],
        };
        assert!(
            daemon
                .activate(&serde_json::Value::Null, Some(unmatched), false)
                .await
                .is_err()
        );
        assert_eq!(
            daemon
                .activate(&serde_json::Value::Null, Some(matched), false)
                .await
                .unwrap()
                .0
                .id,
            active.id
        );
        std::fs::write(contact_path, "").unwrap();
        assert!(
            daemon
                .activate(&serde_json::Value::Null, Some(matched), false)
                .await
                .is_err()
        );
        daemon
            .visibility
            .set(Visibility::Everyone, None)
            .await
            .unwrap();
        assert_eq!(
            daemon
                .activate(&serde_json::Value::Null, Some(unmatched), false)
                .await
                .unwrap()
                .0
                .id,
            active.id
        );
        let bad = temp.path().join("invalid-contacts");
        std::fs::write(&bad, [255]).unwrap();
        assert!(
            daemon
                .visibility
                .set(Visibility::Contacts, Some(bad))
                .await
                .is_err()
        );
        assert_eq!(state.receiver.visibility(), Visibility::Everyone);
        assert!(
            daemon
                .activate(&serde_json::json!({"name":"different"}), None, true)
                .await
                .is_err()
        );
        let peer = crate::discovery::Peer::from_awdl(
            Mac([2, 0, 0, 0, 0, 2]),
            0,
            Timeouts::default().discovery_fallback,
        );
        state
            .discovery
            .peers
            .write()
            .await
            .insert(peer.id.clone(), peer.clone());
        let listed = daemon
            .command(
                Command::Peers { timeout: 1 },
                None,
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(listed[0]["id"], peer.id);
        assert!(listed[0]["name"].is_null());
        let remote_identity = Identity::load(&temp.path().join("remote-keys"), "fixture").unwrap();
        let remote = Receiver::new(
            "fixture".into(),
            remote_identity.clone(),
            temp.path().join("remote-received"),
            1024 * 1024,
            false,
        );
        let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let remote_address = match listener.local_addr().unwrap() {
            std::net::SocketAddr::V6(a) => a,
            _ => unreachable!(),
        };
        let remote_cancel = CancellationToken::new();
        let remote_task = tokio::spawn({
            let remote = remote.clone();
            let cancel = remote_cancel.clone();
            async move { remote.serve(listener, cancel).await }
        });
        let send_cancel = CancellationToken::new();
        let send = tokio::spawn({
            let daemon = daemon.clone();
            let cancel = send_cancel.clone();
            async move {
                daemon
                    .command(
                        Command::Send {
                            to: "fixture".into(),
                            direct: Some(remote_address),
                            items: vec![],
                            urls: vec!["https://example.com/outgoing".into()],
                            bytes: 0,
                            icon: None,
                            timeout: 1,
                            options: serde_json::Value::Null,
                        },
                        None,
                        cancel,
                    )
                    .await
            }
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if remote
                    .transfers()
                    .await
                    .iter()
                    .any(|t| t.state == "pending")
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(daemon.active.lock().await.as_ref().unwrap().id, active.id);
        assert_eq!(active.sending.borrow().len(), 1);
        let sending_status = daemon
            .command(Command::Status, None, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(sending_status["outgoing"][0]["state"], "pending");
        assert_eq!(active.activity.traffic().borrow().transfers, 0); // Pending approval stays on discovery.
        let incoming = Sender {
            name: "fixture".into(),
            id: "fixture".into(),
            identity: remote_identity,
            tag: None,
            timeouts: Timeouts {
                approval: Duration::from_secs(2),
                ..Timeouts::default()
            },
        };
        let address = match address {
            std::net::SocketAddr::V6(a) => a,
            _ => unreachable!(),
        };
        incoming.discover(address).await.unwrap();
        assert_eq!(active.activity.traffic().borrow().transfers, 0); // HTTPS discovery cannot select a transfer channel.
        incoming
            .send(
                address,
                vec![],
                vec!["https://example.com/incoming".into()],
                None,
                None,
            )
            .await
            .unwrap();
        assert!(
            state
                .receiver
                .transfers()
                .await
                .iter()
                .any(|t| t.state == "completed")
        );
        daemon.visibility.set(Visibility::Off, None).await.unwrap();
        assert_eq!(daemon.active.lock().await.as_ref().unwrap().id, active.id);
        send_cancel.cancel();
        assert!(send.await.unwrap().is_err());
        assert_eq!(
            daemon
                .command(Command::Status, None, CancellationToken::new())
                .await
                .unwrap()["outgoing"][0]["state"],
            "cancelled"
        );
        assert!(active.sending.borrow().is_empty());
        assert!(!active.activity.closed());
        tokio::time::timeout(Duration::from_secs(10), active.stopped())
            .await
            .unwrap()
            .unwrap();
        assert!(daemon.active.lock().await.is_none());
        assert!(tokio::net::TcpStream::connect(address).await.is_err());
        assert_eq!(
            daemon
                .history
                .lock()
                .await
                .iter()
                .filter(|t| t.state == "completed")
                .count(),
            1
        );
        daemon
            .visibility
            .set(Visibility::Everyone, None)
            .await
            .unwrap();
        let (next, _) = daemon
            .activate(
                &serde_json::Value::Null,
                Some(crate::ble::WakeHint { hashes: [0; 8] }),
                false,
            )
            .await
            .unwrap();
        next.ready().await.unwrap();
        assert_ne!(active.id, next.id);
        daemon.visibility.set(Visibility::Off, None).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), next.stopped())
            .await
            .unwrap()
            .unwrap();
        remote_cancel.cancel();
        remote_task.await.unwrap().unwrap();
    }
}
