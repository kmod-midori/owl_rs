// SPDX-License-Identifier: GPL-3.0-or-later
//! Outgoing operation state shared by CLI status and desktop notifications.
use serde::Serialize;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

pub(crate) fn terminal(state: &str) -> bool {
    matches!(state, "completed" | "failed" | "rejected" | "cancelled")
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Outgoing {
    pub id: String,
    pub target: String,
    pub items: Vec<String>,
    pub state: String,
    /// Compressed archive bytes handed to HTTP; completion requires its response.
    pub bytes: u64,
    pub total_bytes: Option<u64>,
    pub error: Option<String>,
}

#[derive(Clone)]
pub(crate) struct Progress {
    pub state: watch::Sender<Outgoing>,
    pub cancel: CancellationToken,
}
impl Progress {
    pub fn new(target: String, items: Vec<String>, cancel: CancellationToken) -> Self {
        Self {
            state: watch::channel(Outgoing {
                id: uuid::Uuid::new_v4().to_string(),
                target,
                items,
                state: "connecting".into(),
                bytes: 0,
                total_bytes: None,
                error: None,
            })
            .0,
            cancel,
        }
    }
    pub fn update(&self, state: &str, bytes: u64, total_bytes: Option<u64>) {
        self.state.send_modify(|value| {
            if !terminal(&value.state) {
                value.state = state.into();
                value.bytes = bytes;
                value.total_bytes = total_bytes;
            }
        });
    }
    pub fn finish(&self, error: Option<String>) {
        self.state.send_modify(|value| {
            if !terminal(&value.state) {
                value.state = if error.is_none() {
                    "completed"
                } else if self.cancel.is_cancelled() {
                    "cancelled"
                } else {
                    "failed"
                }
                .into();
                value.error = error;
            }
        });
    }
    pub fn guard(&self) -> Guard {
        Guard(self.clone())
    }
}
pub(crate) struct Guard(Progress);
impl Drop for Guard {
    fn drop(&mut self) {
        self.0.cancel.cancel();
        self.0.finish(Some("send cancelled".into()));
    }
}
