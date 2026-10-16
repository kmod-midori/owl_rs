// SPDX-License-Identifier: GPL-3.0-or-later
use airdrop_client::control::{self, Target};
use anyhow::{Result, bail, ensure};
use crossterm::{
    cursor::{Hide, MoveTo, Show},
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute, queue,
    terminal::{
        self, Clear, ClearType, DisableLineWrap, EnableLineWrap, EnterAlternateScreen,
        LeaveAlternateScreen,
    },
};
use std::{
    io::{self, IsTerminal, Write},
    path::Path,
    time::Duration,
};

pub fn interactive() -> bool {
    io::stdin().is_terminal()
        && io::stderr().is_terminal()
        && std::env::var("TERM").is_ok_and(|term| term != "dumb")
}

struct Terminal;
impl Terminal {
    fn enter() -> Result<Self> {
        terminal::enable_raw_mode()?;
        let guard = Self;
        execute!(io::stderr(), EnterAlternateScreen, Hide, DisableLineWrap)?;
        Ok(guard)
    }
}
impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = execute!(io::stderr(), EnableLineWrap, Show, LeaveAlternateScreen);
        let _ = terminal::disable_raw_mode();
    }
}

// Keep discovery alive while the send request acquires the same daemon session.
pub struct Discovery(tokio::task::JoinHandle<()>);
impl Drop for Discovery {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Default)]
struct Targets {
    items: Vec<Target>,
    selected: usize,
}
impl Targets {
    fn update(&mut self, items: Vec<Target>) {
        let selected = self.items.get(self.selected).map(|p| p.id.as_str());
        self.selected = selected
            .and_then(|id| items.iter().position(|p| p.id == id))
            .unwrap_or(self.selected.min(items.len().saturating_sub(1)));
        self.items = items;
    }
    fn draw(&self, ready: bool) -> Result<()> {
        let (width, height) = terminal::size()?;
        let mut out = io::stderr().lock();
        queue!(out, MoveTo(0, 0), Clear(ClearType::All))?;
        let mut line = |row: u16, text: &str| -> io::Result<()> {
            if row < height {
                queue!(out, MoveTo(0, row))?;
                // Peer names are untrusted; never print terminal control bytes.
                let text: String = text
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(width.saturating_sub(1) as usize)
                    .collect();
                write!(out, "{text}")?;
            }
            Ok(())
        };
        line(0, "Choose an AirDrop receiver")?;
        line(1, "Up/Down: select  Enter: send  Esc/q/Ctrl+C: cancel")?;
        let rows = height.saturating_sub(4) as usize;
        if self.items.is_empty() {
            line(
                3,
                if ready {
                    "Searching… Keep the receiver unlocked with AirDrop enabled."
                } else {
                    "Starting discovery…"
                },
            )?;
        } else {
            let start = self.selected.saturating_sub(rows.saturating_sub(1));
            for (index, peer) in self.items.iter().enumerate().skip(start).take(rows) {
                let name = peer.name.as_deref().unwrap_or("Unnamed receiver");
                line(
                    3 + (index - start) as u16,
                    &format!(
                        "{} {name}  [{}]",
                        if index == self.selected { ">" } else { " " },
                        peer.id
                    ),
                )?;
            }
        }
        out.flush()?;
        Ok(())
    }
}

pub async fn choose(
    dir: &Path,
    options: serde_json::Value,
    timeout: u64,
) -> Result<(Target, Discovery)> {
    ensure!(
        interactive(),
        "receiver required in a non-interactive console; use --to RECEIVER (or --direct ADDRESS)"
    );
    let _terminal = Terminal::enter()?;
    let mut targets = Targets::default();
    targets.draw(false)?;
    let (updates, mut receiver) = tokio::sync::watch::channel(None);
    let dir = dir.to_owned();
    let discovery = Discovery(tokio::spawn(async move {
        let result: Result<()> = async {
            let mut stream = control::watch_peers(&dir, options).await?;
            loop {
                let targets = control::peer_update(&mut stream).await?;
                updates.send_replace(Some(Ok(targets)));
            }
        }
        .await;
        if let Err(error) = result {
            let _ = updates.send(Some(Err(format!("{error:#}"))));
        }
    }));
    let mut tick = tokio::time::interval(Duration::from_millis(50));
    let deadline = tokio::time::sleep(Duration::from_secs(timeout));
    tokio::pin!(deadline);
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut ready = false;
    loop {
        tokio::select! {
            changed = receiver.changed() => {
                changed?;
                match receiver.borrow_and_update().as_ref() {
                    Some(Ok(items)) => targets.update(items.clone()),
                    Some(Err(error)) => bail!("{error}"),
                    None => continue,
                }
                ready = true;
                targets.draw(ready)?;
            }
            _ = tick.tick() => {
                if !event::poll(Duration::ZERO)? { continue; }
                match event::read()? {
                    Event::Key(key) if key.kind != KeyEventKind::Release => {
                        match key.code {
                            KeyCode::Esc | KeyCode::Char('q') => bail!("send cancelled"),
                            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => bail!("send cancelled"),
                            KeyCode::Up | KeyCode::Char('k') => targets.selected = targets.selected.saturating_sub(1),
                            KeyCode::Down | KeyCode::Char('j') => targets.selected = (targets.selected + 1).min(targets.items.len().saturating_sub(1)),
                            KeyCode::Enter => if let Some(peer) = targets.items.get(targets.selected) { return Ok((peer.clone(), discovery)); },
                            _ => (),
                        }
                        targets.draw(ready)?;
                    }
                    Event::Resize(..) => targets.draw(ready)?,
                    _ => (),
                }
            }
            _ = &mut deadline => bail!("receiver selection timed out"),
            _ = tokio::signal::ctrl_c() => bail!("send cancelled"),
            _ = term.recv() => bail!("send cancelled"),
        }
    }
}
