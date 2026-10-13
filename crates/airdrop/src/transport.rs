// SPDX-License-Identifier: GPL-3.0-or-later
//! AirDrop HTTPS, mDNS and receiver BLE advertisement, over an existing link.
use crate::{
    discovery::Discovery,
    link::Link,
    transfer::{Receiver, Sender},
    visibility::Policy,
};
use anyhow::{Context, Result};
use tokio::{sync::watch, task::JoinSet};
use tokio_util::sync::CancellationToken;

pub(crate) struct Transport {
    pub receiver: Receiver,
    pub sender: Sender,
    pub discovery: Discovery,
    pub tasks: JoinSet<Result<()>>,
    cancel: CancellationToken,
    timeouts: crate::timeouts::Timeouts,
}
impl Transport {
    pub async fn start(
        receiver: Receiver,
        sender: Sender,
        link: &Link,
        policy: watch::Receiver<Policy>,
        port: u16,
        bluetooth: bool,
        adapter: Option<String>,
    ) -> Result<Self> {
        let timeouts = sender.timeouts;
        let cancel = CancellationToken::new();
        let listener = crate::transfer::listener(
            std::net::SocketAddrV6::new(link.address, port, 0, link.scope).into(),
            link.interface.as_deref(),
        )
        .await?;
        // Bind all sockets before publication; startup errors release the lease
        // without advertising a partially initialized service.
        let mdns = link
            .interface
            .as_deref()
            .map(|interface| crate::mdns::Socket::open(interface, link.scope, link.address))
            .transpose()?;
        let discovery = Discovery::default()
            .with_policy(policy.clone())
            .with_timeouts(timeouts);
        let mut tasks = JoinSet::new();
        tasks.spawn({
            let receiver = receiver.clone();
            let cancel = cancel.clone();
            async move {
                receiver
                    .serve(listener, cancel)
                    .await
                    .context("AirDrop HTTPS server")
            }
        });
        if bluetooth {
            let cancel = cancel.clone();
            let hashes = receiver.identity.hashes;
            tasks.spawn(async move {
                crate::ble::receiving(adapter.as_deref(), hashes, policy, cancel, timeouts).await
            });
        }
        if let Some(socket) = mdns {
            let discovery = discovery.clone();
            let cancel = cancel.clone();
            let id = sender.id.clone();
            let address = link.address;
            tasks.spawn(async move {
                discovery
                    .run(socket, &id, address, port, cancel)
                    .await
                    .context("mDNS discovery")
            });
        }
        Ok(Self {
            receiver,
            sender,
            discovery,
            tasks,
            cancel,
            timeouts,
        })
    }
    pub async fn stop(&mut self) {
        self.cancel.cancel();
        if tokio::time::timeout(self.timeouts.transport_shutdown, async {
            while self.tasks.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            self.tasks.abort_all();
            while self.tasks.join_next().await.is_some() {}
        }
    }
}
