// SPDX-License-Identifier: GPL-3.0-or-later
//! User-side link lease. WLAN setup and raw frame I/O stay in owld.
use crate::{timeouts::Timeouts, visibility::Policy};
use anyhow::{Context, Result, bail, ensure};
use owl_ipc::{Event, LinkInfo, Request};
use std::{net::Ipv6Addr, path::Path, time::Duration};
use tokio::{net::UnixStream, sync::watch};
use tokio_util::sync::CancellationToken;

pub(crate) struct Link {
    task: Option<tokio::task::JoinHandle<Result<()>>>,
    cancel: CancellationToken,
    public: watch::Sender<bool>,
    pub snapshot: watch::Receiver<serde_json::Value>,
    pub mac: owl_ipc::Mac,
    pub address: Ipv6Addr,
    pub scope: u32,
    pub interface: Option<String>,
}
impl Link {
    pub fn stopped(&self) -> bool {
        self.task.as_ref().is_some_and(|task| task.is_finished())
    }
    pub fn loopback(ip: Ipv6Addr) -> Result<Self> {
        ensure!(ip.is_loopback(), "--no-radio listener must be loopback");
        let (_, snapshot) = watch::channel(serde_json::json!({}));
        Ok(Self {
            task: None,
            cancel: CancellationToken::new(),
            public: watch::channel(false).0,
            snapshot,
            mac: owl_ipc::Mac([2, 0, 0, 0, 0, 1]),
            address: ip,
            scope: 0,
            interface: None,
        })
    }
    pub async fn start(
        socket: &Path,
        port: u16,
        timeouts: Timeouts,
        policy: watch::Receiver<Policy>,
        traffic: watch::Receiver<usize>,
    ) -> Result<Self> {
        Self::connect(socket, port, timeouts, policy, traffic, 0).await
    }
    async fn connect(
        socket: &Path,
        port: u16,
        timeouts: Timeouts,
        policy: watch::Receiver<Policy>,
        traffic: watch::Receiver<usize>,
        server_uid: u32,
    ) -> Result<Self> {
        let (mut reader, mut writer, info) = tokio::time::timeout(timeouts.link_startup, async {
            let stream = UnixStream::connect(socket).await.with_context(|| {
                format!(
                    "connect owld at {}; start the radio service first",
                    socket.display()
                )
            })?;
            ensure!(
                stream.peer_cred()?.uid() == server_uid,
                "owld socket is not owned by the expected service UID"
            );
            let (reader, mut writer) = stream.into_split();
            let mut reader = owl_ipc::reader(reader);
            owl_ipc::write(&mut writer, &Request::Acquire { port }).await?;
            let ready = owl_ipc::read(&mut reader).await?;
            let info: LinkInfo = match ready {
                Event::Ready { link } => link,
                Event::Error { message } => bail!("{message}"),
                _ => bail!("expected link readiness"),
            };
            ensure!(
                info.lease_timeout.is_finite()
                    && (0.0..=86400.0).contains(&info.lease_timeout)
                    && info.lease_timeout > 0.0,
                "invalid link deadlines"
            );
            ensure!(
                info.interface.is_some() && info.scope != 0 && info.address.is_unicast_link_local()
                    || info.interface.is_none() && info.scope == 0 && info.address.is_loopback(),
                "invalid link addressing"
            );
            Ok::<_, anyhow::Error>((reader, writer, info))
        })
        .await
        .context("owld link startup timed out")??;
        let cancel = CancellationToken::new();
        let (public, mut announced) = watch::channel(false);
        let (snapshots, snapshot) = watch::channel(serde_json::json!({}));
        let task = tokio::spawn({
            let cancel = cancel.clone();
            let generation = info.generation.clone();
            async move {
                let mut policy = policy;
                let mut traffic = traffic;
                let mut heartbeat = tokio::time::interval(
                    Duration::from_secs_f64(info.lease_timeout / 3.0).max(Duration::from_nanos(1)),
                );
                heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = heartbeat.tick() => (),
                        result = announced.changed() => { result.context("link publication stopped")?; },
                        result = policy.changed() => { result.context("receiving policy stopped")?; },
                        result = traffic.changed() => { result.context("link activity stopped")?; },
                        event = owl_ipc::read(&mut reader) => {
                            match event? {
                                Event::Snapshot { value } => { snapshots.send_replace(value); },
                                Event::Closed { error } => bail!("{}",error.as_deref().unwrap_or("owld closed the link")),
                                Event::Error { message } => bail!("{message}"),
                                Event::Ready { .. } => bail!("unexpected link readiness"),
                            }
                            continue;
                        }
                    }
                    let state = Request::State {
                        generation: generation.clone(),
                        service_enabled: *announced.borrow() && policy.borrow().mode.enabled(),
                        transfers: u32::try_from(*traffic.borrow())?,
                    };
                    tokio::time::timeout(
                        Duration::from_secs_f64(info.lease_timeout),
                        owl_ipc::write(&mut writer, &state),
                    )
                    .await??;
                }
                let shutdown = async {
                    owl_ipc::write(&mut writer, &Request::Release { generation }).await?;
                    loop {
                        match owl_ipc::read(&mut reader).await? {
                            Event::Closed { error } => {
                                return error.map_or(Ok(()), |error| Err(anyhow::anyhow!(error)));
                            }
                            Event::Snapshot { value } => {
                                snapshots.send_replace(value);
                            }
                            Event::Error { message } => bail!("{message}"),
                            _ => bail!("unexpected shutdown event"),
                        }
                    }
                };
                tokio::time::timeout(timeouts.link_shutdown, shutdown)
                    .await
                    .context("owld restoration timed out")?
            }
        });
        Ok(Self {
            task: Some(task),
            cancel,
            public,
            snapshot,
            mac: info.mac,
            address: info.address,
            scope: info.scope,
            interface: info.interface,
        })
    }
    pub fn announce(&self) {
        self.public.send_replace(true);
    }
    pub async fn stop(&mut self) -> Result<()> {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            task.await.context("link control task")??;
        }
        Ok(())
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn client_authenticates_server_and_orders_publication_activity_and_release() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("owld.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let policy = crate::visibility::Control::new(temp.path().join("contacts"));
        policy
            .set(crate::visibility::Visibility::Everyone, None)
            .await
            .unwrap();
        let (traffic, active) = watch::channel(0);
        let (idle, idle_seen) = tokio::sync::oneshot::channel();
        let (transmitting, transmitting_seen) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (rejected, _) = listener.accept().await.unwrap();
            drop(rejected);
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut read = owl_ipc::reader(read);
            assert!(matches!(
                owl_ipc::read::<_, Request>(&mut read).await.unwrap(),
                Request::Acquire { port: 8771 }
            ));
            owl_ipc::write(
                &mut write,
                &Event::Ready {
                    link: LinkInfo {
                        generation: "fixture".into(),
                        mac: owl_ipc::Mac([2, 0, 0, 0, 0, 1]),
                        address: Ipv6Addr::LOCALHOST,
                        scope: 0,
                        interface: None,
                        lease_timeout: 1.0,
                    },
                },
            )
            .await
            .unwrap();
            let Request::State {
                service_enabled,
                transfers,
                ..
            } = owl_ipc::read(&mut read).await.unwrap()
            else {
                panic!("state")
            };
            assert!(!service_enabled);
            assert_eq!(transfers, 0);
            idle.send(()).unwrap();
            loop {
                if let Request::State {
                    generation,
                    service_enabled: true,
                    transfers: 1,
                } = owl_ipc::read(&mut read).await.unwrap()
                {
                    assert_eq!(generation, "fixture");
                    break;
                }
            }
            owl_ipc::write(
                &mut write,
                &Event::Snapshot {
                    value: serde_json::json!({"fixture":true}),
                },
            )
            .await
            .unwrap();
            transmitting.send(()).unwrap();
            loop {
                if let Request::Release { generation } = owl_ipc::read(&mut read).await.unwrap() {
                    assert_eq!(generation, "fixture");
                    break;
                }
            }
            owl_ipc::write(&mut write, &Event::Closed { error: None })
                .await
                .unwrap();
        });
        let uid = nix::unistd::getuid().as_raw();
        assert!(
            Link::connect(
                &path,
                8771,
                Timeouts::default(),
                policy.tx.subscribe(),
                active.clone(),
                uid + 1
            )
            .await
            .is_err()
        );
        let mut link = Link::connect(
            &path,
            8771,
            Timeouts::default(),
            policy.tx.subscribe(),
            active,
            uid,
        )
        .await
        .unwrap();
        idle_seen.await.unwrap();
        link.announce();
        traffic.send_replace(1);
        transmitting_seen.await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while link.snapshot.borrow().get("fixture").is_none() {
                link.snapshot.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        link.stop().await.unwrap();
        server.await.unwrap();
    }
}
