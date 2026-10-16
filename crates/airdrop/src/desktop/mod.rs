// SPDX-License-Identifier: GPL-3.0-or-later
//! Desktop transfer snapshots and actions shared by progress reporting backends.
//! Enabled by `tray`, independently of the KSNI/GTK tray backend.
mod job_view;
mod notifications;
mod reporter;

use super::Daemon;
use crate::{
    progress::{self, Progress},
    transfer::Receiver,
};
use anyhow::{Result, bail, ensure};
use futures_util::StreamExt;
use reporter::ProgressReporter;
use std::{collections::BTreeMap, sync::Arc, time::Duration};

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
struct Report {
    target: Target,
    state: String,
    updated: tokio::time::Instant,
    reporter: ProgressReporter,
}
async fn views(daemon: &Daemon, reports: &BTreeMap<String, Report>) -> BTreeMap<String, View> {
    let mut receivers = BTreeMap::new();
    for report in reports.values() {
        if let Target::Incoming {
            session, receiver, ..
        } = &report.target
            && (!progress::terminal(&report.state)
                || report.updated.elapsed() < Duration::from_secs(10))
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
async fn desktop(daemon: &Daemon) -> Result<()> {
    let connection = zbus::connection::Builder::session()?
        .method_timeout(Duration::from_secs(2))
        .build()
        .await?;
    let notifications = notifications::Service::new(&connection).await?;
    let mut signals = notifications.signals().await?;
    let mut reports: BTreeMap<String, Report> = BTreeMap::new();
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let result = async {
        loop {
            tokio::select! {
                _ = daemon.cancel.cancelled() => break,
                signal = signals.next() => {
                    let Some(signal) = signal else { bail!("notification signal stream stopped") };
                    if let Some(event) = notifications::Event::parse(&signal)? {
                        for report in reports.values_mut() {
                            report.reporter.event(&event, &report.target).await;
                        }
                    }
                }
                _ = tick.tick() => {
                    let current = views(daemon, &reports).await;
                    let removed: Vec<_> = reports.keys().filter(|key| !current.contains_key(*key)).cloned().collect();
                    for key in removed {
                        if let Some(mut report) = reports.remove(&key) {
                            report.reporter.close(&notifications, "Transfer ended").await;
                        }
                    }
                    for (key, view) in current {
                        let report = reports.entry(key).or_insert_with(|| Report {
                            target: view.target.clone(), state: view.state.clone(),
                            updated: tokio::time::Instant::now(), reporter: ProgressReporter::default(),
                        });
                        report.reporter.update(&connection, &notifications, &view).await;
                        if report.state != view.state {
                            report.state = view.state;
                            report.updated = tokio::time::Instant::now();
                        }
                    }
                }
            }
        }
        Ok(())
    }.await;
    for report in reports.values_mut() {
        report
            .reporter
            .close(&notifications, "AirDrop stopped")
            .await;
    }
    result
}
pub(super) async fn run(daemon: Daemon) {
    // Optional UI must never prevent service startup or take down a transfer.
    if let Err(error) = desktop(&daemon).await {
        tracing::warn!(%error, "desktop reporting unavailable; CLI controls remain active");
    }
}
