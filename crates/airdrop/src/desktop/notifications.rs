// SPDX-License-Identifier: GPL-3.0-or-later
//! Freedesktop approval prompts and fallback transfer notifications.
use super::{Content, Target, View};
use crate::progress;
use anyhow::Result;
use std::collections::HashMap;
use zbus::{Proxy, zvariant::Value};

pub(super) struct Service {
    proxy: Proxy<'static>,
    markup: bool,
}
impl Service {
    pub(super) async fn new(connection: &zbus::Connection) -> Result<Self> {
        let proxy = Proxy::new_owned(
            connection.clone(),
            "org.freedesktop.Notifications",
            "/org/freedesktop/Notifications",
            "org.freedesktop.Notifications",
        )
        .await?;
        let capabilities: Vec<String> =
            proxy.call("GetCapabilities", &()).await.unwrap_or_default();
        Ok(Self {
            proxy,
            markup: capabilities.iter().any(|cap| cap == "body-markup"),
        })
    }
    pub(super) async fn signals(&self) -> Result<zbus::proxy::SignalStream<'static>> {
        Ok(self.proxy.receive_all_signals().await?)
    }
}
pub(super) enum Event {
    Action(u32, String),
    Closed(u32),
}
impl Event {
    pub(super) fn parse(message: &zbus::Message) -> Result<Option<Self>> {
        Ok(
            match message.header().member().map(|member| member.as_str()) {
                Some("ActionInvoked") => {
                    let (id, action) = message.body().deserialize()?;
                    Some(Self::Action(id, action))
                }
                Some("NotificationClosed") => {
                    let (id, _reason): (u32, u32) = message.body().deserialize()?;
                    Some(Self::Closed(id))
                }
                _ => None,
            },
        )
    }
}
#[derive(Default)]
pub(super) struct Notification {
    id: Option<u32>,
    content: Option<Content>,
    // Dismissal lasts until the phase changes; byte updates must not reopen it.
    dismissed: bool,
}
impl Notification {
    pub(super) async fn update(&mut self, service: &Service, view: &View) {
        let content = view.content(service.markup);
        if self.content.as_ref().is_some_and(|old| {
            (self.id.is_some() && *old == content) || (self.dismissed && old.state == content.state)
        }) {
            return;
        }
        match notify(&service.proxy, self.id.unwrap_or(0), &content).await {
            Ok(id) => {
                self.id = Some(id);
                self.dismissed = false;
            }
            Err(error) => {
                tracing::debug!(%error, "notification unavailable");
                self.dismissed = true;
            }
        }
        self.content = Some(content);
    }
    pub(super) async fn event(&mut self, event: &Event, target: &Target) {
        match event {
            Event::Action(id, action) if self.id == Some(*id) => {
                if self.content.as_ref().is_some_and(|content| {
                    content
                        .actions
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .any(|pair| pair[0] == action)
                }) && let Err(error) = target.act(action).await
                {
                    tracing::debug!(%error, "notification action no longer applicable");
                }
            }
            Event::Closed(id) if self.id == Some(*id) => {
                self.id = None;
                self.dismissed = true;
            }
            _ => (),
        }
    }
    pub(super) async fn close(&mut self, service: &Service) {
        if let Some(id) = self.id.take() {
            let _ = service
                .proxy
                .call_noreply("CloseNotification", &(id,))
                .await;
        }
        self.content = None;
        self.dismissed = false;
    }
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
