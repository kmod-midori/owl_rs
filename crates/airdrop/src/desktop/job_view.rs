// SPDX-License-Identifier: GPL-3.0-or-later
//! KDE JobView progress and cancellation.
use super::{Target, View};
use crate::progress;
use anyhow::Result;
use futures_util::StreamExt;
use std::time::Duration;
use tokio::time::Instant;
use zbus::Proxy;

// JobViewV2 is created through the original JobViewServer interface. The
// similarly named JobViewServerV2 instead creates JobViewV3 objects.
pub(super) struct Job {
    proxy: Proxy<'static>,
    actions: tokio::task::JoinHandle<()>,
    finished: bool,
    speed: Speed,
}
/// Sample over at least one second so the desktop polling rate does not
/// amplify the archive decoder's bursty writes.
#[derive(Default)]
struct Speed {
    previous: Option<(Instant, u64)>,
    bytes_per_second: u64,
}
impl Speed {
    fn update(&mut self, now: Instant, bytes: u64, active: bool) -> u64 {
        if !active {
            self.previous = None;
            self.bytes_per_second = 0;
            return 0;
        }
        match self.previous {
            Some((then, previous_bytes)) if bytes >= previous_bytes => {
                let elapsed = now.duration_since(then);
                if elapsed >= Duration::from_secs(1) {
                    self.bytes_per_second =
                        ((bytes - previous_bytes) as f64 / elapsed.as_secs_f64()) as u64;
                    self.previous = Some((now, bytes));
                }
            }
            _ => {
                self.previous = Some((now, bytes));
                self.bytes_per_second = 0;
            }
        }
        self.bytes_per_second
    }
}
impl Drop for Job {
    fn drop(&mut self) {
        self.actions.abort();
    }
}
impl Job {
    pub(super) async fn new(connection: &zbus::Connection, target: Target) -> Result<Self> {
        let bus = zbus::fdo::DBusProxy::new(connection).await?;
        // Resolve an existing owner: do not activate a desktop service merely
        // because it is installed, or send an old job to a replacement owner.
        let owner = bus
            .get_name_owner("org.kde.JobViewServer".try_into()?)
            .await?;
        let server = Proxy::new_owned(
            connection.clone(),
            owner.clone(),
            "/JobViewServer",
            "org.kde.JobViewServer",
        )
        .await?;
        let path: zbus::zvariant::OwnedObjectPath = server
            .call("requestView", &("AirDrop", "folder-download", 1i32))
            .await?;
        let proxy = Proxy::new_owned(connection.clone(), owner, path, "org.kde.JobViewV2").await?;
        let mut signals = match proxy.receive_signal("cancelRequested").await {
            Ok(signals) => signals,
            Err(error) => {
                let _ = proxy
                    .call_noreply("terminate", &("Progress controls unavailable",))
                    .await;
                return Err(error.into());
            }
        };
        let actions = tokio::spawn(async move {
            while signals.next().await.is_some() {
                if let Err(error) = target.act("cancel").await {
                    tracing::debug!(%error, "job cancellation no longer applicable");
                }
            }
        });
        Ok(Self {
            proxy,
            actions,
            finished: false,
            speed: Speed::default(),
        })
    }
    pub(super) async fn update(&mut self, view: &View) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        let content = view.content(false);
        // This method replies, so a disappeared or incompatible job service
        // can fall back to notifications; progress setters are no-reply calls.
        let _: bool = self
            .proxy
            .call("setDescriptionField", &(0u32, "Transfer", &content.body))
            .await?;
        self.proxy
            .call_noreply("setInfoMessage", &(&content.summary,))
            .await?;
        if let Some(total) = view.total {
            self.proxy
                .call_noreply("setTotalAmount", &(total, "bytes"))
                .await?;
        }
        self.proxy
            .call_noreply("setProcessedAmount", &(view.bytes, "bytes"))
            .await?;
        let speed = self.speed.update(
            Instant::now(),
            view.bytes,
            matches!(view.state.as_str(), "sending" | "receiving"),
        );
        self.proxy.call_noreply("setSpeed", &(speed,)).await?;
        if let Some(percent) = content.percent {
            self.proxy
                .call_noreply("setPercent", &(percent as u32,))
                .await?;
        }
        if progress::terminal(&view.state) {
            let error = match view.state.as_str() {
                "completed" => "",
                "cancelled" => "Transfer cancelled",
                "rejected" => "Transfer declined",
                _ => view.error.as_deref().unwrap_or("Transfer failed"),
            };
            self.close(error).await;
        }
        Ok(())
    }
    pub(super) async fn close(&mut self, error: &str) {
        if !self.finished {
            let _ = self.proxy.call_noreply("terminate", &(error,)).await;
            self.finished = true;
            self.actions.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn speed_uses_elapsed_time_and_clears_on_stalls_and_state_changes() {
        let start = Instant::now();
        let mut speed = Speed::default();
        assert_eq!(speed.update(start, 0, false), 0);
        assert_eq!(speed.update(start + Duration::from_secs(20), 0, true), 0);
        assert_eq!(
            speed.update(start + Duration::from_millis(20_250), 1000, true),
            0
        );
        assert_eq!(
            speed.update(start + Duration::from_secs(22), 4000, true),
            2000
        );
        assert_eq!(speed.update(start + Duration::from_secs(23), 4000, true), 0);
        assert_eq!(
            speed.update(start + Duration::from_secs(24), 8000, true),
            4000
        );
        assert_eq!(
            speed.update(start + Duration::from_secs(24), 8000, false),
            0
        );
        assert_eq!(speed.update(start + Duration::from_secs(30), 8000, true), 0);
        assert_eq!(
            speed.update(start + Duration::from_secs(31), 10_000, true),
            2000
        );
    }
}
