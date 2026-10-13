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
    woken: bool,
    completed: bool,
    closed: bool,
}
pub(crate) struct Activity {
    // Guards protect bookkeeping only and never span an await.
    usage: Mutex<Usage>,
    timeouts: Timeouts,
    changed: Notify,
    traffic: watch::Sender<usize>,
}
pub(crate) struct Lease {
    activity: Arc<Activity>,
    transmitting: bool,
}
impl Activity {
    pub fn new(timeouts: Timeouts) -> Arc<Self> {
        Arc::new(Self {
            timeouts,
            usage: Mutex::new(Usage {
                users: 0,
                last_activity: Instant::now(),
                woken: false,
                completed: false,
                closed: false,
            }),
            changed: Notify::new(),
            traffic: watch::channel(0).0,
        })
    }
    pub fn acquire(self: &Arc<Self>) -> Result<Lease> {
        let mut usage = self.usage.lock().unwrap();
        ensure!(!usage.closed, "AirDrop session is closing");
        usage.users += 1;
        Ok(Lease {
            activity: self.clone(),
            transmitting: false,
        })
    }
    pub fn traffic(&self) -> watch::Receiver<usize> {
        self.traffic.subscribe()
    }
    pub fn wake(&self) -> Result<()> {
        let mut usage = self.usage.lock().unwrap();
        ensure!(!usage.closed, "AirDrop session is closing");
        usage.woken = true;
        usage.completed = false;
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
                let delay = if usage.completed {
                    self.timeouts.completion_grace
                } else if usage.woken && policy.borrow().mode.enabled() {
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
        if !self.transmitting {
            self.transmitting = true;
            self.activity.traffic.send_modify(|users| *users += 1);
        }
    }
    pub fn complete(&self) {
        self.activity.usage.lock().unwrap().completed = true;
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if self.transmitting {
            self.activity.traffic.send_modify(|users| *users -= 1);
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
    async fn repeated_wakes_refresh_idle_and_completion_grace_without_interrupting_users() {
        let policy = Control::new(std::path::PathBuf::new());
        policy.set(Visibility::Everyone, None).await.unwrap();
        let activity = Activity::new(Timeouts {
            ble_idle: Duration::from_secs(10),
            completion_grace: Duration::from_secs(2),
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
        assert_eq!(*traffic.borrow(), 0); // Session lifetime alone is not traffic.
        lease.transmitting();
        lease.transmitting(); // Marking the same exchange twice is harmless.
        assert_eq!(*traffic.borrow(), 1);
        let mut overlap = activity.acquire().unwrap();
        overlap.transmitting();
        assert_eq!(*traffic.borrow(), 2);
        drop(overlap);
        assert_eq!(*traffic.borrow(), 1);
        tokio::time::advance(Duration::from_secs(30)).await;
        assert!(!idle.is_finished());
        lease.complete();
        drop(lease);
        assert_eq!(*traffic.borrow(), 0);
        tokio::time::advance(Duration::from_secs(1)).await;
        activity.wake().unwrap(); // An eligible wake also refreshes completion grace.
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(!idle.is_finished());
        tokio::time::advance(Duration::from_secs(9)).await;
        idle.await.unwrap();
        assert!(activity.closed());
        assert!(activity.wake().is_err());
    }
}
