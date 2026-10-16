// SPDX-License-Identifier: GPL-3.0-or-later
//! Tray icon and menu controls via KSNI or GTK on a dedicated worker.
//! Transfer notifications use a separate D-Bus client in notifications.rs.
use crate::visibility::{Control, Visibility};
#[cfg(feature = "tray-gtk")]
use anyhow::Context;
use anyhow::Result;
use std::{path::Path, sync::Arc, thread, time::Duration};
use tokio_util::sync::CancellationToken;
use tray_icon::{
    Icon, TrayIconBuilder,
    menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem},
};

pub(crate) struct Tray {
    stop: CancellationToken,
    thread: Option<thread::JoinHandle<()>>,
}

pub(crate) fn start(
    name: &str,
    run_dir: &Path,
    visibility: Arc<Control>,
    cancel: CancellationToken,
) -> Option<Tray> {
    let stop = cancel.child_token();
    let worker_stop = stop.clone();
    let name = name.to_owned();
    let run_dir = run_dir.to_owned();
    let runtime = tokio::runtime::Handle::current();
    match thread::Builder::new()
        .name("airdrop-tray".into())
        .spawn(move || {
            if let Err(error) = run(&name, &run_dir, visibility, cancel, worker_stop, runtime) {
                tracing::warn!(%error, "tray unavailable; continuing without it");
            }
        }) {
        Ok(thread) => Some(Tray {
            stop,
            thread: Some(thread),
        }),
        Err(error) => {
            tracing::warn!(%error, "could not start tray thread; continuing without it");
            None
        }
    }
}

impl Drop for Tray {
    fn drop(&mut self) {
        // Also covers early returns: no detached tray loop survives the daemon.
        self.stop.cancel();
        // The tray worker never waits on Tokio, so joining cannot block its progress.
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            tracing::warn!("tray thread panicked");
        }
    }
}

fn run(
    name: &str,
    _run_dir: &Path,
    visibility: Arc<Control>,
    cancel: CancellationToken,
    stop: CancellationToken,
    runtime: tokio::runtime::Handle,
) -> Result<()> {
    #[cfg(feature = "tray-gtk")]
    gtk::init().context("initialize GTK (a graphical display is required)")?;
    let title = MenuItem::new(format!("AirDrop — {name}"), false, None);
    let modes = [
        (
            Visibility::Off,
            CheckMenuItem::new("Receiving off", true, true, None),
        ),
        (
            Visibility::Contacts,
            CheckMenuItem::new("Contacts only", true, false, None),
        ),
        (
            Visibility::Everyone,
            CheckMenuItem::new("Everyone", true, false, None),
        ),
    ];
    let status = MenuItem::new("Ready", false, None);
    let quit = MenuItem::new("Quit AirDrop", true, None);
    let menu = Menu::with_items(&[
        &title,
        &PredefinedMenuItem::separator(),
        &modes[0].1,
        &modes[1].1,
        &modes[2].1,
        &PredefinedMenuItem::separator(),
        &status,
        &quit,
    ])?;
    let builder = TrayIconBuilder::new()
        .with_tooltip(format!("AirDrop — {name}"))
        .with_icon(icon()?)
        .with_menu(Box::new(menu));
    // AppIndicator writes an icon file; KSNI sends its pixels over D-Bus.
    #[cfg(feature = "tray-gtk")]
    let icons = tempfile::Builder::new()
        .prefix("tray-")
        .tempdir_in(_run_dir)?;
    #[cfg(feature = "tray-gtk")]
    let builder = builder.with_temp_dir_path(icons.path());
    let _icon = builder.build()?;
    let (completed, results) = std::sync::mpsc::channel();
    let tick = move || {
        if stop.is_cancelled() {
            return false;
        }
        while let Ok(event) = MenuEvent::receiver().try_recv() {
            if event.id == *quit.id() {
                cancel.cancel();
            } else if let Some((mode, _)) = modes.iter().find(|(_, item)| event.id == *item.id()) {
                let mode = *mode;
                let visibility = visibility.clone();
                let completed = completed.clone();
                runtime.spawn(async move {
                    let result = visibility.set(mode, None).await.map_err(|error| {
                        tracing::warn!(%error, "could not change receiving mode from tray");
                        format!("Could not change receiving: {error}")
                    });
                    let _ = completed.send(result);
                });
            }
        }
        while let Ok(result) = results.try_recv() {
            status.set_text(result.err().unwrap_or_else(|| "Ready".into()));
        }
        let current = visibility.tx.borrow().mode;
        for (mode, item) in &modes {
            // The policy is authoritative, including changes made through the CLI
            // and failed contacts-file loads. Do not leave a speculative checkmark.
            if item.is_checked() != (*mode == current) {
                item.set_checked(*mode == current);
            }
        }
        true
    };
    #[cfg(feature = "tray-gtk")]
    {
        gtk::glib::timeout_add_local(Duration::from_millis(100), move || {
            if tick() {
                gtk::glib::ControlFlow::Continue
            } else {
                gtk::main_quit();
                gtk::glib::ControlFlow::Break
            }
        });
        gtk::main();
    }
    #[cfg(not(feature = "tray-gtk"))]
    while tick() {
        thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

fn icon() -> Result<Icon> {
    // A blue disc with white radio arcs and an incoming arrow, rendered at 32 px.
    let mut rgba = Vec::with_capacity(32 * 32 * 4);
    for y in 0..32 {
        for x in 0..32 {
            let dx = x as f32 - 15.5;
            let dy = y as f32 - 15.5;
            let radius = dx.hypot(dy);
            let arc = dy < -2.0 && ((radius - 10.0).abs() < 1.0 || (radius - 6.0).abs() < 1.0);
            let arrow = (dx.abs() < 1.5 && (13..23).contains(&y))
                || ((20..26).contains(&y) && dx.abs() < (26 - y) as f32);
            rgba.extend_from_slice(if radius > 15.0 {
                &[0, 0, 0, 0]
            } else if arc || arrow {
                &[255, 255, 255, 255]
            } else {
                &[36, 120, 220, 255]
            });
        }
    }
    Ok(Icon::from_rgba(rgba, 32, 32)?)
}
