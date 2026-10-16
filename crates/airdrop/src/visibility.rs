// SPDX-License-Identifier: GPL-3.0-or-later
//! Runtime receiving policy shared by HTTPS, discovery and BLE.
use crate::contacts::Contacts;
use anyhow::{Result, ensure};
use std::{path::PathBuf, sync::Arc};
use tokio::sync::{Mutex, watch};

pub use airdrop_client::visibility::Visibility;
#[derive(Clone)]
pub(crate) struct Policy {
    pub mode: Visibility,
    pub contacts: Option<Contacts>,
    pub path: PathBuf,
    pub revision: u64,
}
impl Policy {
    pub(crate) fn everyone() -> Self {
        Self {
            mode: Visibility::Everyone,
            contacts: None,
            path: PathBuf::new(),
            revision: 0,
        }
    }
}
pub(crate) struct Control {
    pub tx: watch::Sender<Policy>,
    change: Mutex<()>,
}
impl Control {
    pub fn new(path: PathBuf) -> Arc<Self> {
        let (tx, _) = watch::channel(Policy {
            mode: Visibility::Off,
            path,
            ..Policy::everyone()
        });
        Arc::new(Self {
            tx,
            change: Mutex::new(()),
        })
    }
    pub async fn set(&self, mode: Visibility, path: Option<PathBuf>) -> Result<()> {
        ensure!(
            path.is_none() || mode == Visibility::Contacts,
            "--contacts-file requires discoverable contacts"
        );
        let _guard = self.change.lock().await;
        let old = self.tx.borrow().clone();
        if old.mode == mode && path.is_none() && mode != Visibility::Contacts {
            return Ok(());
        }
        let path = path.unwrap_or(old.path);
        let contacts = if mode == Visibility::Contacts {
            let path = path.clone();
            Some(tokio::task::spawn_blocking(move || Contacts::new(path)).await??)
        } else {
            None
        };
        self.tx.send_replace(Policy {
            mode,
            contacts,
            path,
            revision: old.revision.wrapping_add(1),
        });
        Ok(())
    }
}
// Standalone library receivers have no controller; a dropped watch sender
// must not make their pending approval/discovery loops spin.
pub(crate) async fn changed(policy: &mut watch::Receiver<Policy>) {
    if policy.changed().await.is_err() {
        std::future::pending::<()>().await;
    }
}
