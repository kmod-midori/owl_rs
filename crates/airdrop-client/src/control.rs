// SPDX-License-Identifier: GPL-3.0-or-later
//! AirDrop daemon options, wire protocol and Unix control client.
use crate::{timeouts::Timeouts, visibility::Visibility};
use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddrV6,
    path::{Path, PathBuf},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader},
    net::UnixStream,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Item {
    pub name: String,
    pub size: u64,
    pub directory: bool,
}
#[derive(Clone, Debug, Args, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    #[arg(skip)]
    #[serde(default)]
    pub timeouts: Timeouts,
    #[arg(long, default_value = "owl-rs")]
    pub name: String,
    #[arg(long)]
    pub keys: Option<PathBuf>,
    #[arg(long)]
    pub output: Option<PathBuf>,
    #[arg(long, default_value_os_t = default_run_dir())]
    pub run_dir: PathBuf,
    /// Privileged radio service socket; owld is configured separately.
    #[arg(long, default_value = "/run/owld/control.sock")]
    pub owl_socket: PathBuf,
    /// Skip Wi-Fi setup for local IPv6 loopback HTTPS testing.
    #[arg(long)]
    pub no_radio: bool,
    /// Loopback listener; with radio setup, only its port is used.
    #[arg(long, default_value = "[::1]:8771")]
    pub listen: std::net::SocketAddr,
    #[arg(long)]
    pub no_bluetooth: bool,
    #[arg(long)]
    pub bluetooth_adapter: Option<String>,
    /// Accept all offers without prompting (default requires accept/reject commands).
    #[arg(long)]
    pub auto_accept: bool,
    #[arg(long,default_value_t=4*1024*1024*1024)]
    pub max_bytes: u64,
    /// Limit the daemon lifetime or one outgoing operation in seconds.
    #[arg(long, value_parser=clap::value_parser!(u64).range(1..=86400))]
    pub duration: Option<u64>,
}
impl Options {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.name.is_empty() && self.name.len() <= 64,
            "name must be 1..64 bytes"
        );
        ensure!(self.max_bytes > 0, "max-bytes must be positive");
        ensure!(
            self.duration.is_none_or(|s| (1..=86400).contains(&s)),
            "duration must be 1..86400 seconds"
        );
        self.timeouts.validate()
    }
}
pub fn default_run_dir() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", nix::unistd::getuid())))
        .join("owl_rs")
}
pub fn current_user() -> Result<(u32, PathBuf)> {
    let user = nix::unistd::User::from_uid(nix::unistd::getuid())?.context("user not found")?;
    Ok((user.uid.as_raw(), user.dir))
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Command {
    /// Prepare files in the daemon; paths must be absolute.
    SendPaths {
        to: String,
        direct: Option<SocketAddrV6>,
        files: Vec<PathBuf>,
        urls: Vec<String>,
        timeout: u64,
        #[serde(default)]
        options: serde_json::Value,
    },
    Contact {
        action: ContactAction,
        contacts_file: Option<PathBuf>,
    },
    Status,
    Discoverable {
        mode: Visibility,
        #[serde(default)]
        contacts_file: Option<PathBuf>,
    },
    Peers {
        timeout: u64,
    },
    Transfers,
    Accept {
        id: Option<String>,
    },
    Reject {
        id: String,
    },
    Cancel {
        id: String,
    },
    Stop,
    /// Send a prepared archive, streamed after the JSON request.
    Send {
        to: String,
        direct: Option<SocketAddrV6>,
        items: Vec<Item>,
        urls: Vec<String>,
        bytes: u64,
        #[serde(default)]
        icon: Option<Vec<u8>>,
        timeout: u64,
        #[serde(default)]
        options: serde_json::Value,
    },
}
pub async fn read_line<R: AsyncRead + Unpin>(reader: &mut BufReader<R>) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        let buf = reader.fill_buf().await?;
        ensure!(!buf.is_empty(), "control connection closed before request");
        let n = buf
            .iter()
            .position(|b| *b == b'\n')
            .map(|n| n + 1)
            .unwrap_or(buf.len());
        ensure!(
            line.len() + n <= 1024 * 1024,
            "control message exceeds 1 MiB"
        );
        line.extend_from_slice(&buf[..n]);
        reader.consume(n);
        if line.last() == Some(&b'\n') {
            return Ok(line);
        }
    }
}
pub async fn client(
    run_dir: &Path,
    command: Command,
    archive: Option<&Path>,
) -> Result<serde_json::Value> {
    let mut socket = UnixStream::connect(run_dir.join("control.sock"))
        .await
        .context("connect to airdropd (start `just daemon` first)")?;
    socket.write_all(&serde_json::to_vec(&command)?).await?;
    socket.write_all(b"\n").await?;
    if let Some(path) = archive {
        let mut file = tokio::fs::File::open(path).await?;
        tokio::io::copy(&mut file, &mut socket).await?;
    }
    let value: serde_json::Value =
        serde_json::from_slice(&read_line(&mut BufReader::new(socket)).await?)?;
    if let Some(error) = value.get("error") {
        bail!("{}", error.as_str().unwrap_or("daemon error"));
    }
    Ok(value.get("ok").context("invalid daemon response")?.clone())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ContactAction {
    List,
    Add { identifiers: Vec<String> },
    Remove { identifiers: Vec<String> },
}
