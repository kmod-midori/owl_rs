// SPDX-License-Identifier: GPL-3.0-or-later
//! KDE JobView progress and cancellation.
use super::{Target, View};
use crate::progress;
use anyhow::Result;
use futures_util::StreamExt;
use zbus::Proxy;

// JobViewV2 is created through the original JobViewServer interface. The
// similarly named JobViewServerV2 instead creates JobViewV3 objects.
pub(super) struct Job {
    proxy: Proxy<'static>,
    actions: tokio::task::JoinHandle<()>,
    finished: bool,
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
