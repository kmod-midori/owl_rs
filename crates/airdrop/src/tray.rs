// SPDX-License-Identifier: GPL-3.0-or-later
//! Optional desktop controls; GTK and the tray stay on their own OS thread.
use crate::visibility::{Control, Visibility};
use anyhow::{Context, Result};
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
        // Also covers early returns: no detached GTK loop survives the daemon.
        self.stop.cancel();
        // The GUI never waits on Tokio, so joining cannot depend on this worker.
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            tracing::warn!("tray thread panicked");
        }
    }
}

fn run(
    name: &str,
    run_dir: &Path,
    visibility: Arc<Control>,
    cancel: CancellationToken,
    stop: CancellationToken,
    runtime: tokio::runtime::Handle,
) -> Result<()> {
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
    // Private to this daemon, including custom --run-dir instances.
    let icons = tempfile::Builder::new()
        .prefix("tray-")
        .tempdir_in(run_dir)?;
    let _icon = TrayIconBuilder::new()
        .with_tooltip(format!("AirDrop — {name}"))
        .with_icon(icon()?)
        .with_menu(Box::new(menu))
        .with_temp_dir_path(icons.path())
        .build()?;
    let (completed, results) = std::sync::mpsc::channel();
    gtk::glib::timeout_add_local(Duration::from_millis(100), move || {
        if stop.is_cancelled() {
            gtk::main_quit();
            return gtk::glib::ControlFlow::Break;
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
            item.set_checked(*mode == current);
        }
        gtk::glib::ControlFlow::Continue
    });
    gtk::main();
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
