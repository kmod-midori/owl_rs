// SPDX-License-Identifier: GPL-3.0-or-later
//! Privileged, single-owner radio leases. No user files, contacts, TLS or archives.
use crate::{
    link::Link,
    radio::RadioArgs,
    rate::{FecPolicy, Rate},
    timeouts::Timeouts,
};
use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use owl_ipc::{Event, LinkInfo, Mac, Request};
use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::{Semaphore, watch},
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Args)]
pub struct Options {
    #[command(flatten)]
    pub radio: RadioArgs,
    /// User allowed to acquire the radio; defaults to the sudo caller.
    #[arg(long)]
    pub user: Option<String>,
    #[arg(long, global = true, default_value = "/run/owld")]
    pub run_dir: PathBuf,
    /// Data transmit rate; VHT requests are capped at MCS8.
    #[arg(long, default_value = "auto")]
    pub rate: Rate,
    /// Data coding: BCC by default; auto/LDPC require a supported injection backend.
    #[arg(long, value_enum, default_value = "bcc")]
    pub fec: FecPolicy,
    #[arg(long, default_value_t = 60)]
    pub election_metric: u32,
    #[arg(long, default_value_t = 0)]
    pub election_counter: u32,
    /// Capture path prefix; each radio session adds its unique ID and .pcap.
    #[arg(long)]
    pub save: Option<String>,
    /// Use loopback instead of WLAN for local process-lifecycle testing.
    #[arg(long)]
    pub no_radio: bool,
}
async fn send(
    stream: &mut tokio::net::unix::OwnedWriteHalf,
    event: Event,
    timeout: Duration,
) -> Result<()> {
    tokio::time::timeout(timeout, owl_ipc::write(stream, &event))
        .await
        .context("link client stopped reading")?
}
async fn connection(
    socket: UnixStream,
    uid: u32,
    opts: Options,
    timeouts: Timeouts,
    mac: Mac,
    leases: Arc<Semaphore>,
    cancel: CancellationToken,
) -> Result<()> {
    ensure!(
        socket.peer_cred()?.uid() == uid,
        "link client is not the authorized user"
    );
    let (reader, mut writer) = socket.into_split();
    let mut reader = owl_ipc::reader(reader);
    let first = tokio::select! {
        _ = cancel.cancelled() => return Ok(()),
        request = tokio::time::timeout(timeouts.control_request, owl_ipc::read(&mut reader)) => request??,
    };
    let Request::Acquire { port } = first else {
        bail!("first link request must acquire a lease")
    };
    ensure!(port >= 1024, "service port must be unprivileged");
    let permit = match leases.try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            send(
                &mut writer,
                Event::Error {
                    message: "radio is already leased".into(),
                },
                timeouts.control_request,
            )
            .await?;
            return Ok(());
        }
    };
    let (policy, public) = watch::channel(false);
    let (traffic, transfers) = watch::channel(owl_ipc::TransferState::default());
    let generation = owl_ipc::generation();
    let save = opts
        .save
        .map(|prefix| format!("{prefix}.{generation}.pcap"));
    if let Some(path) = &save {
        tracing::info!(%path, "saving radio session capture");
    }
    let link_opts = crate::link::Options {
        radio: opts.radio,
        timeouts,
        run_dir: opts.run_dir,
        loopback: opts.no_radio.then_some(std::net::Ipv6Addr::LOCALHOST),
        service_port: port,
        save,
        rate: opts.rate,
        fec: opts.fec,
        election_metric: opts.election_metric,
        election_counter: opts.election_counter,
    };
    // Starting and restoring are owned by this task even if the peer disconnects.
    // Dropping a setup future midway could discard its WLAN recovery owner.
    let mut link = match Link::start(&link_opts, public, mac, transfers).await {
        Ok(link) => link,
        Err(error) => {
            send(
                &mut writer,
                Event::Error {
                    message: format!("{error:#}"),
                },
                timeouts.control_request,
            )
            .await?;
            return Ok(());
        }
    };
    let info = LinkInfo {
        generation: generation.clone(),
        mac: link.mac,
        address: link.address,
        scope: link.scope,
        interface: link.interface.clone(),
        lease_timeout: timeouts.control_request.as_secs_f64(),
    };
    let result = async {
        send(&mut writer, Event::Ready { link: info }, timeouts.control_request).await?;
        let mut snapshot = link.snapshot.clone();
        let mut channel_ready = link.channel_ready.clone();
        let mut monitor = tokio::time::interval(Duration::from_millis(250));
        // Only client control messages refresh this deadline, never snapshots.
        let mut last_request = tokio::time::Instant::now();
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep_until(last_request + timeouts.control_request) => bail!("link lease heartbeat expired"),
                _ = monitor.tick(), if !opts.no_radio => { ensure!(!link.stopped(), "AWDL runtime stopped"); }
                changed = snapshot.changed(), if !opts.no_radio => {
                    changed.context("AWDL snapshot stream ended")?;
                    let mut value = snapshot.borrow_and_update().clone();
                    value["timeouts"] = serde_json::to_value(crate::timeouts::RadioTimeouts::from(timeouts))?;
                    send(&mut writer, Event::Snapshot { value }, timeouts.control_request).await?;
                }
                ready = channel_ready.changed(), if !opts.no_radio => {
                    ready.context("AWDL channel readiness stream ended")?;
                    let applied = *channel_ready.borrow_and_update();
                    let state = *traffic.borrow();
                    if applied == Some(state.epoch) && state.transfers > 0 {
                        send(&mut writer, Event::ChannelReady {
                            generation: generation.clone(), transfer_epoch: state.epoch,
                        }, timeouts.control_request).await?;
                    }
                }
                request = owl_ipc::read::<_, Request>(&mut reader) => {
                    last_request = tokio::time::Instant::now();
                    match request? {
                        Request::State { generation: id, service_enabled, transfers, transfer_epoch } => {
                            ensure!(id == generation, "stale link generation");
                            ensure!(transfers <= 64, "too many active transfers");
                            let previous = *traffic.borrow();
                            ensure!(transfer_epoch > previous.epoch ||
                                (transfer_epoch == previous.epoch && transfers == previous.transfers),
                                "stale transfer activity revision");
                            policy.send_replace(service_enabled);
                            traffic.send_replace(owl_ipc::TransferState { epoch: transfer_epoch, transfers });
                            if opts.no_radio && transfers > 0 {
                                send(&mut writer, Event::ChannelReady {
                                    generation: generation.clone(), transfer_epoch,
                                }, timeouts.control_request).await?;
                            }
                        }
                        Request::Release { generation: id } => { ensure!(id == generation, "stale link generation"); break; }
                        Request::Acquire { .. } => bail!("link lease already acquired"),
                    }
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    policy.send_replace(false);
    traffic.send_modify(|state| state.transfers = 0);
    let cleanup = link.stop().await;
    // No subsequent acquire can overlap cleanup, including after a bad request.
    drop(permit);
    let error = match (result, cleanup) {
        (_, Err(error)) => Some(format!("link restoration failed: {error:#}")),
        (Err(error), Ok(())) => Some(format!("{error:#}")),
        _ => None,
    };
    send(
        &mut writer,
        Event::Closed { error },
        timeouts.control_request,
    )
    .await
}
pub async fn run(opts: Options, timeouts: Timeouts) -> Result<()> {
    timeouts.validate()?;
    opts.fec.validate_rate(opts.rate)?;
    ensure!(
        nix::unistd::geteuid().is_root() || opts.no_radio,
        "owld requires root for WLAN operations"
    );
    let user = if let Some(name) = &opts.user {
        nix::unistd::User::from_name(name)?.context("authorized user not found")?
    } else {
        let uid = std::env::var("SUDO_UID")
            .ok()
            .map(|s| s.parse())
            .transpose()?
            .unwrap_or(nix::unistd::getuid().as_raw());
        nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))?
            .context("authorized user not found")?
    };
    std::fs::create_dir_all(&opts.run_dir)?;
    let metadata = std::fs::symlink_metadata(&opts.run_dir)?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == nix::unistd::geteuid().as_raw()
            && metadata.mode() & 0o022 == 0,
        "owld run directory must be owned by the service and not writable by others"
    );
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(opts.run_dir.join("daemon.lock"))?;
    fs2::FileExt::try_lock_exclusive(&lock).context("another owld is running")?;
    if !opts.no_radio {
        crate::radio::recover(&opts.run_dir, &timeouts).await?;
    }
    let path = opts.run_dir.join("control.sock");
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    if nix::unistd::geteuid().is_root() {
        nix::unistd::chown(&path, Some(user.uid), Some(user.gid))?;
    } else {
        ensure!(
            user.uid == nix::unistd::getuid(),
            "only root can authorize another user"
        );
    }
    let leases = Arc::new(Semaphore::new(1));
    let cancel = CancellationToken::new();
    let mac = Mac::random();
    let mut clients = tokio::task::JoinSet::new();
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tracing::info!(socket=%path.display(), uid=user.uid.as_raw(), "owld ready; WLAN inactive");
    let result = async {
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => break,
                _ = term.recv() => break,
                done = clients.join_next(), if !clients.is_empty() => {
                    if let Some(Err(error)) = done { tracing::warn!(%error, "link connection task"); }
                }
                accepted = listener.accept() => {
                    let (socket, _) = accepted?;
                    if clients.len() >= 16 { continue; }
                    let (opts, leases, cancel) = (opts.clone(), leases.clone(), cancel.clone());
                    let uid = user.uid.as_raw();
                    clients.spawn(async move {
                        if let Err(error) = connection(socket, uid, opts, timeouts, mac, leases, cancel).await {
                            tracing::debug!("link client: {error:#}");
                        }
                    });
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    cancel.cancel();
    while clients.join_next().await.is_some() {}
    let _ = std::fs::remove_file(path);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[derive(Parser)]
    struct Fixture {
        #[command(flatten)]
        options: Options,
    }
    #[tokio::test]
    async fn leases_authenticate_generations_and_release_on_disconnect() {
        let temp = tempfile::tempdir().unwrap();
        let mut opts = Fixture::parse_from(["fixture", "--no-radio"]).options;
        opts.run_dir = temp.path().join("run");
        let timeouts = Timeouts {
            control_request: Duration::from_millis(100),
            ..Default::default()
        };
        let mac = Mac::random();
        let uid = nix::unistd::getuid().as_raw();
        let leases = Arc::new(Semaphore::new(1));
        let (client, server) = UnixStream::pair().unwrap();
        assert!(
            connection(
                server,
                uid + 1,
                opts.clone(),
                timeouts,
                mac,
                leases.clone(),
                CancellationToken::new()
            )
            .await
            .is_err()
        );
        drop(client);
        // An idle authorized connection must not delay service shutdown for
        // the configurable request timeout; no radio has been acquired yet.
        let (client, server) = UnixStream::pair().unwrap();
        let cancel = CancellationToken::new();
        let task = tokio::spawn(connection(
            server,
            uid,
            opts.clone(),
            timeouts,
            mac,
            leases.clone(),
            cancel.clone(),
        ));
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(leases.available_permits(), 1);
        drop(client);
        let mut previous = None;
        for invalid in [true, false] {
            let (client, server) = UnixStream::pair().unwrap();
            let task = tokio::spawn(connection(
                server,
                uid,
                opts.clone(),
                timeouts,
                mac,
                leases.clone(),
                CancellationToken::new(),
            ));
            let (read, mut write) = client.into_split();
            let mut read = owl_ipc::reader(read);
            owl_ipc::write(&mut write, &Request::Acquire { port: 8771 })
                .await
                .unwrap();
            let Event::Ready { link } = owl_ipc::read(&mut read).await.unwrap() else {
                panic!("ready")
            };
            assert_eq!(link.mac, mac);
            assert_eq!(mac.0[0] & 3, 2);
            assert_ne!(previous.as_ref(), Some(&link.generation));
            previous = Some(link.generation.clone());
            assert_eq!(leases.available_permits(), 0);
            if invalid {
                owl_ipc::write(
                    &mut write,
                    &Request::State {
                        generation: "stale".into(),
                        service_enabled: true,
                        transfers: 1,
                        transfer_epoch: 1,
                    },
                )
                .await
                .unwrap();
                let Event::Closed { error } = owl_ipc::read(&mut read).await.unwrap() else {
                    panic!("closed")
                };
                assert!(error.unwrap().contains("stale"));
                task.await.unwrap().unwrap();
            } else {
                owl_ipc::write(
                    &mut write,
                    &Request::State {
                        generation: link.generation.clone(),
                        service_enabled: false,
                        transfers: 1,
                        transfer_epoch: 1,
                    },
                )
                .await
                .unwrap();
                let Event::ChannelReady {
                    generation,
                    transfer_epoch,
                } = owl_ipc::read(&mut read).await.unwrap()
                else {
                    panic!("channel ready")
                };
                assert_eq!(generation, link.generation);
                assert_eq!(transfer_epoch, 1);
                // Lost transport clients must release their radio owner without an RPC.
                drop(read);
                drop(write);
                let _ = tokio::time::timeout(Duration::from_secs(1), task)
                    .await
                    .unwrap()
                    .unwrap();
            }
            assert_eq!(leases.available_permits(), 1);
        }
        assert!(!opts.run_dir.exists()); // Loopback leases never alter the radio.
    }
}
