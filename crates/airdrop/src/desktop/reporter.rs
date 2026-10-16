// SPDX-License-Identifier: GPL-3.0-or-later
//! Per-transfer reporting lifecycle: approval, backend selection and fallback.
use super::{
    Target, View,
    job_view::Job,
    notifications::{Event, Notification, Service},
};
use crate::progress;

/// Presents transfer snapshots and routes desktop actions to their transfer.
/// Protocol code supplies state; backends own their display resources.
#[derive(Default)]
pub(super) struct ProgressReporter {
    notification: Notification,
    backend: Backend,
}
#[derive(Default)]
enum Backend {
    #[default]
    Pending,
    Job(Job),
    Notification,
}
impl ProgressReporter {
    pub(super) async fn update(
        &mut self,
        connection: &zbus::Connection,
        notifications: &Service,
        view: &View,
    ) {
        let approval = view.incoming && view.state == "pending";
        if matches!(self.backend, Backend::Pending) && !approval && !progress::terminal(&view.state)
        {
            self.backend = match Job::new(connection, view.target.clone()).await {
                Ok(job) => Backend::Job(job),
                Err(_) => Backend::Notification,
            };
        }
        if let Backend::Job(job) = &mut self.backend {
            match job.update(view).await {
                Ok(()) => {
                    self.notification.close(notifications).await;
                    return;
                }
                Err(error) => {
                    tracing::debug!(%error, "JobView unavailable; using notifications");
                    job.close("Progress service unavailable").await;
                    self.backend = Backend::Notification;
                    self.notification.close(notifications).await;
                }
            }
        }
        self.notification.update(notifications, view).await;
    }
    pub(super) async fn event(&mut self, event: &Event, target: &Target) {
        self.notification.event(event, target).await;
    }
    pub(super) async fn close(&mut self, notifications: &Service, reason: &str) {
        if let Backend::Job(job) = &mut self.backend {
            job.close(reason).await;
        }
        self.notification.close(notifications).await;
    }
}
