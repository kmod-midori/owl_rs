// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared operation lifetimes; registration and idle shutdown are atomic.
use crate::{
    timeouts::Timeouts,
    visibility::{self, Policy},
};
use anyhow::{Result, ensure};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{Notify, watch};
use tokio::time::Instant;

struct Usage {
    users: usize,
    last_activity: Instant,
    closed: bool,
}
pub(crate) struct Activity {
    // Guards protect bookkeeping only and never span an await.
    usage: Mutex<Usage>,
    timeouts: Timeouts,
    changed: Notify,
    traffic: watch::Sender<owl_ipc::TransferState>,
    channel_ready: Mutex<Option<watch::Receiver<Option<u64>>>>,
}
pub(crate) struct Lease {
    activity: Arc<Activity>,
    transmitting: Option<u64>,
}
impl Activity {
    pub fn new(timeouts: Timeouts) -> Arc<Self> {
        Arc::new(Self {
            timeouts,
            usage: Mutex::new(Usage {
                users: 0,
                last_activity: Instant::now(),
                closed: false,
            }),
            changed: Notify::new(),
            traffic: watch::channel(owl_ipc::TransferState::default()).0,
            channel_ready: Mutex::new(None),
        })
    }
    pub fn acquire(self: &Arc<Self>) -> Result<Lease> {
        let mut usage = self.usage.lock().unwrap();
        ensure!(!usage.closed, "AirDrop session is closing");
        usage.users += 1;
        Ok(Lease {
            activity: self.clone(),
            transmitting: None,
        })
    }
    pub fn traffic(&self) -> watch::Receiver<owl_ipc::TransferState> {
        self.traffic.subscribe()
    }
    pub fn set_channel_ready(&self, ready: watch::Receiver<Option<u64>>) {
        *self.channel_ready.lock().unwrap() = Some(ready);
    }
    async fn wait_channel_ready(&self, epoch: u64) -> Result<()> {
        let Some(mut ready) = self.channel_ready.lock().unwrap().clone() else {
            // In-process loopback sessions have no radio to tune.
            return Ok(());
        };
        tokio::time::timeout(self.timeouts.channel_ready, async {
            loop {
                ensure!(
                    ready.has_changed().is_ok(),
                    "radio link disconnected before channel readiness"
                );
                if ready
                    .borrow_and_update()
                    .is_some_and(|applied| applied >= epoch)
                {
                    return Ok(());
                }
                ready.changed().await.map_err(|_| {
                    anyhow::anyhow!("radio link disconnected before channel readiness")
                })?;
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("transfer channel readiness timed out"))?
    }
    pub fn wake(&self) -> Result<()> {
        let mut usage = self.usage.lock().unwrap();
        ensure!(!usage.closed, "AirDrop session is closing");
        usage.last_activity = Instant::now();
        self.changed.notify_one();
        Ok(())
    }
    pub fn close(&self) {
        self.usage.lock().unwrap().closed = true;
        self.changed.notify_one();
    }
    pub fn closed(&self) -> bool {
        self.usage.lock().unwrap().closed
    }
    pub async fn idle(&self, mut policy: watch::Receiver<Policy>) {
        loop {
            let (finished, deadline) = {
                let mut usage = self.usage.lock().unwrap();
                let delay = if policy.borrow().mode.enabled() {
                    self.timeouts.ble_idle
                } else {
                    Duration::ZERO
                };
                if usage.users == 0 && usage.last_activity.elapsed() >= delay {
                    usage.closed = true;
                    (true, None)
                } else {
                    (
                        false,
                        (usage.users == 0).then_some(usage.last_activity + delay),
                    )
                }
            };
            if finished {
                return;
            }
            tokio::select! {
                _ = self.changed.notified() => (),
                _ = visibility::changed(&mut policy) => (),
                _ = async { match deadline { Some(deadline) => tokio::time::sleep_until(deadline).await, None => std::future::pending().await } } => (),
            }
        }
    }
}
impl Lease {
    /// Hold the transfer channel after file approval, through TCP shutdown.
    pub fn transmitting(&mut self) {
        if self.transmitting.is_none() {
            self.activity.traffic.send_modify(|state| {
                state.epoch += 1;
                state.transfers += 1;
                self.transmitting = Some(state.epoch);
            });
        }
    }
    /// Channel selection remains in owld; wait for this activity revision to be applied.
    pub async fn channel_ready(&mut self) -> Result<()> {
        self.transmitting();
        self.activity
            .wait_channel_ready(self.transmitting.unwrap())
            .await
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if self.transmitting.is_some() {
            self.activity.traffic.send_modify(|state| {
                state.epoch += 1;
                state.transfers -= 1;
            });
        }
        let mut usage = self.activity.usage.lock().unwrap();
        usage.users -= 1;
        usage.last_activity = Instant::now();
        self.activity.changed.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::visibility::{Control, Visibility};
    use std::time::Duration;
    #[tokio::test(start_paused = true)]
    async fn channel_readiness_bounds_waits_and_rejects_old_revisions() {
        let activity = Activity::new(Timeouts {
            channel_ready: Duration::from_millis(20),
            ..Default::default()
        });
        let (ready, seen) = watch::channel(Some(0));
        activity.set_channel_ready(seen);
        let mut lease = activity.acquire().unwrap();
        assert!(
            lease
                .channel_ready()
                .await
                .unwrap_err()
                .to_string()
                .contains("timed out")
        );
        assert_eq!(activity.traffic.borrow().transfers, 1);
        ready.send_replace(Some(1));
        lease.channel_ready().await.unwrap();
        drop(lease);
        let mut next = activity.acquire().unwrap();
        assert!(
            next.channel_ready()
                .await
                .unwrap_err()
                .to_string()
                .contains("timed out")
        );
        assert_eq!(activity.traffic.borrow().epoch, 3);
        drop(ready);
        assert!(
            next.channel_ready()
                .await
                .unwrap_err()
                .to_string()
                .contains("disconnected")
        );
        drop(next);
        assert_eq!(activity.traffic.borrow().transfers, 0);
    }
    #[tokio::test(start_paused = true)]
    async fn activity_and_wakes_refresh_receive_idle_without_interrupting_users() {
        let policy = Control::new(std::path::PathBuf::new());
        policy.set(Visibility::Everyone, None).await.unwrap();
        let activity = Activity::new(Timeouts {
            ble_idle: Duration::from_secs(10),
            ..Default::default()
        });
        activity.wake().unwrap();
        let idle = tokio::spawn({
            let activity = activity.clone();
            let policy = policy.tx.subscribe();
            async move { activity.idle(policy).await }
        });
        tokio::time::advance(Duration::from_secs(9)).await;
        activity.wake().unwrap();
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(!idle.is_finished());
        let traffic = activity.traffic();
        let mut lease = activity.acquire().unwrap();
        assert_eq!(traffic.borrow().transfers, 0); // Session lifetime alone is not traffic.
        lease.transmitting();
        lease.transmitting(); // Marking the same exchange twice is harmless.
        assert_eq!(traffic.borrow().transfers, 1);
        let mut overlap = activity.acquire().unwrap();
        overlap.transmitting();
        assert_eq!(traffic.borrow().transfers, 2);
        drop(overlap);
        assert_eq!(traffic.borrow().transfers, 1);
        tokio::time::advance(Duration::from_secs(30)).await;
        assert!(!idle.is_finished());
        drop(lease);
        assert_eq!(traffic.borrow().transfers, 0);
        tokio::time::advance(Duration::from_secs(6)).await;
        assert!(!idle.is_finished());
        activity.wake().unwrap();
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(!idle.is_finished());
        tokio::time::advance(Duration::from_secs(9)).await;
        idle.await.unwrap();
        assert!(activity.closed());
        assert!(activity.wake().is_err());
    }
}
