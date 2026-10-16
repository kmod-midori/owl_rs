// SPDX-License-Identifier: GPL-3.0-or-later
//! Transfer notifications via zbus and org.freedesktop.Notifications.
//! The desktop notification service displays them and returns action clicks.
//! Enabled by the shared `tray` feature; independent of the KSNI/GTK tray backend.
use super::Daemon;
use crate::{
    progress::{self, Progress},
    transfer::Receiver,
};
use anyhow::{Result, bail, ensure};
use futures_util::StreamExt;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::Duration,
};
use zbus::{Proxy, zvariant::Value};

#[derive(Clone)]
enum Target {
    Incoming {
        session: String,
        receiver: Arc<Receiver>,
        id: String,
    },
    Outgoing(Progress),
}
impl Target {
    async fn act(&self, action: &str) -> Result<()> {
        match (self, action) {
            (Self::Incoming { receiver, id, .. }, "accept") => receiver.decide(id, true).await,
            (Self::Incoming { receiver, id, .. }, "decline") => receiver.decide(id, false).await,
            (Self::Incoming { receiver, id, .. }, "cancel") => receiver.cancel(id).await,
            (Self::Outgoing(progress), "cancel") => {
                ensure!(
                    !progress::terminal(&progress.state.borrow().state),
                    "transfer has already ended"
                );
                progress.cancel.cancel();
                Ok(())
            }
            _ => bail!("unsupported notification action"),
        }
    }
}
struct View {
    target: Target,
    incoming: bool,
    peer: String,
    items: Vec<String>,
    state: String,
    bytes: u64,
    total: Option<u64>,
    error: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Content {
    summary: String,
    body: String,
    actions: Vec<&'static str>,
    percent: Option<i32>,
    state: String,
}
fn text(value: &str, markup: bool) -> String {
    let value: String = value
        .chars()
        .take(180)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if markup {
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    } else {
        value
    }
}
impl View {
    fn content(&self, markup: bool) -> Content {
        let peer = text(&self.peer, false);
        let subject = match self.items.as_slice() {
            [] => "Transfer".into(),
            [item] => text(item, markup),
            [item, rest @ ..] => format!("{} and {} more", text(item, markup), rest.len()),
        };
        let terminal = progress::terminal(&self.state);
        let percent = self.total.filter(|total| *total > 0).map(|total| {
            if self.state == "completed" {
                100
            } else {
                ((u128::from(self.bytes) * 100 / u128::from(total)).min(99)) as i32
            }
        });
        let amount = match self.total {
            Some(total) => format!(
                "{:.1} / {:.1} MiB",
                self.bytes as f64 / 1048576.0,
                total as f64 / 1048576.0
            ),
            None => format!("{:.1} MiB", self.bytes as f64 / 1048576.0),
        };
        let (summary, detail) = match self.state.as_str() {
            "pending" if self.incoming => (
                format!("AirDrop from {peer}"),
                "Accept this transfer?".into(),
            ),
            "pending" => (
                format!("AirDrop to {peer}"),
                "Waiting for acceptance".into(),
            ),
            "connecting" => (format!("AirDrop to {peer}"), "Connecting…".into()),
            "accepted" => (
                format!("Receiving from {peer}"),
                "Waiting for the sender…".into(),
            ),
            "receiving" => (format!("Receiving from {peer}"), amount),
            "sending" => (
                format!("Sending to {peer}"),
                if self.total.is_some_and(|total| self.bytes >= total) {
                    format!("{amount} — waiting for confirmation")
                } else {
                    amount
                },
            ),
            "completed" => (
                if self.incoming {
                    "AirDrop received"
                } else {
                    "AirDrop sent"
                }
                .into(),
                amount,
            ),
            "rejected" => ("AirDrop declined".into(), String::new()),
            "cancelled" => ("AirDrop cancelled".into(), String::new()),
            _ => (
                "AirDrop failed".into(),
                text(self.error.as_deref().unwrap_or("Transfer ended"), markup),
            ),
        };
        Content {
            summary,
            body: format!("{subject}\n{detail}"),
            actions: if terminal {
                vec![]
            } else if self.incoming && self.state == "pending" {
                vec!["accept", "Accept", "decline", "Decline"]
            } else {
                vec!["cancel", "Cancel"]
            },
            percent,
            state: self.state.clone(),
        }
    }
}
struct Notice {
    target: Target,
    id: Option<u32>,
    content: Content,
    // Closing a popup is not declining or cancelling. Keep it dismissed until
    // the phase changes, rather than reopening it for every byte update.
    dismissed: bool,
    updated: tokio::time::Instant,
}
async fn views(daemon: &Daemon, notices: &BTreeMap<String, Notice>) -> BTreeMap<String, View> {
    let mut receivers = BTreeMap::new();
    for notice in notices.values() {
        if let Target::Incoming {
            session, receiver, ..
        } = &notice.target
            && (!progress::terminal(&notice.content.state)
                || notice.updated.elapsed() < Duration::from_secs(10))
        {
            receivers.insert(session.clone(), receiver.clone());
        }
    }
    if let Some(active) = daemon.active.lock().await.clone()
        && let Some(live) = active.live.lock().await.clone()
    {
        receivers.insert(active.id, Arc::new(live.receiver));
    }
    let mut views = BTreeMap::new();
    for (session, receiver) in receivers {
        for transfer in receiver.transfers().await {
            let id = transfer.offer.id;
            let items = if transfer.offer.items.is_empty() {
                transfer.offer.urls
            } else {
                transfer
                    .offer
                    .items
                    .into_iter()
                    .map(|item| item.name)
                    .collect()
            };
            views.insert(
                format!("in:{session}:{id}"),
                View {
                    target: Target::Incoming {
                        session: session.clone(),
                        receiver: receiver.clone(),
                        id,
                    },
                    incoming: true,
                    peer: transfer.offer.sender,
                    items,
                    state: transfer.state,
                    bytes: transfer.bytes,
                    total: transfer.total_bytes,
                    error: transfer.error,
                },
            );
        }
    }
    for (id, progress) in daemon.outgoing.lock().await.iter() {
        let status = progress.state.borrow().clone();
        views.insert(
            format!("out:{id}"),
            View {
                target: Target::Outgoing(progress.clone()),
                incoming: false,
                peer: status.target,
                items: status.items,
                state: status.state,
                bytes: status.bytes,
                total: status.total_bytes,
                error: status.error,
            },
        );
    }
    views
}
async fn notify(proxy: &Proxy<'_>, replaces: u32, content: &Content) -> Result<u32> {
    let terminal = progress::terminal(&content.state);
    let mut hints = HashMap::<&str, Value<'_>>::new();
    hints.insert("resident", Value::from(!terminal));
    hints.insert("suppress-sound", Value::from(replaces != 0));
    if let Some(percent) = content.percent {
        hints.insert("value", Value::from(percent));
    }
    Ok(proxy
        .call(
            "Notify",
            &(
                "AirDrop",
                replaces,
                "folder-download",
                &content.summary,
                &content.body,
                &content.actions,
                hints,
                if terminal { 5000i32 } else { 0i32 },
            ),
        )
        .await?)
}
async fn desktop(daemon: &Daemon) -> Result<()> {
    let connection = zbus::connection::Builder::session()?
        .method_timeout(Duration::from_secs(2))
        .build()
        .await?;
    let proxy = Proxy::new(
        &connection,
        "org.freedesktop.Notifications",
        "/org/freedesktop/Notifications",
        "org.freedesktop.Notifications",
    )
    .await?;
    let mut signals = proxy.receive_all_signals().await?;
    let capabilities: Vec<String> = proxy.call("GetCapabilities", &()).await?;
    let markup = capabilities.iter().any(|cap| cap == "body-markup");
    let mut notices: BTreeMap<String, Notice> = BTreeMap::new();
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let result = async {
        loop {
            tokio::select! {
                _ = daemon.cancel.cancelled() => break,
                signal = signals.next() => {
                    let Some(signal) = signal else { bail!("notification signal stream stopped") };
                    match signal.header().member().map(|member| member.as_str()) {
                        Some("ActionInvoked") => {
                            let (id, action): (u32, String) = signal.body().deserialize()?;
                            if let Some(notice) = notices.values().find(|notice| notice.id == Some(id))
                                && notice.content.actions.as_chunks::<2>().0.iter().any(|pair| pair[0] == action)
                                && let Err(error) = notice.target.act(&action).await
                            { tracing::debug!(%error, "notification action no longer applicable"); }
                        }
                        Some("NotificationClosed") => {
                            let (id, _reason): (u32, u32) = signal.body().deserialize()?;
                            if let Some(notice) = notices.values_mut().find(|notice| notice.id == Some(id)) {
                                notice.id = None;
                                notice.dismissed = true;
                            }
                        }
                        _ => (),
                    }
                }
                _ = tick.tick() => {
                    let current = views(daemon, &notices).await;
                    let removed: Vec<_> = notices.keys().filter(|key| !current.contains_key(*key)).cloned().collect();
                    for key in removed {
                        if let Some(id) = notices.remove(&key).and_then(|notice| notice.id) {
                            let _ = proxy.call_noreply("CloseNotification", &(id,)).await;
                        }
                    }
                    for (key, view) in current {
                        let content = view.content(markup);
                        let old = notices.get(&key);
                        if old.is_some_and(|old| old.content == content || (old.dismissed && old.content.state == content.state)) { continue; }
                        let id = notify(&proxy, old.and_then(|old| old.id).unwrap_or(0), &content).await?;
                        notices.insert(key, Notice { target: view.target, id: Some(id), content, dismissed: false, updated: tokio::time::Instant::now() });
                    }
                }
            }
        }
        Ok(())
    }.await;
    for notice in notices.values() {
        if let Some(id) = notice.id {
            let _ = proxy.call_noreply("CloseNotification", &(id,)).await;
        }
    }
    result
}
pub(super) async fn run(daemon: Daemon) {
    // Optional UI must never prevent service startup or take down a transfer.
    if let Err(error) = desktop(&daemon).await {
        tracing::warn!(%error, "desktop notifications unavailable; CLI controls remain active");
    }
}
