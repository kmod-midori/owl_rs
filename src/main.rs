// SPDX-License-Identifier: GPL-3.0-or-later
#![forbid(unsafe_code)]
mod awdl;
use anyhow::{Result, ensure};
use clap::{ArgAction, CommandFactory, FromArgMatches, Parser, Subcommand, parser::ValueSource};
use owl_rs::{
    archive, radio,
    service::{self, Command, Options},
};
use std::{net::SocketAddrV6, path::PathBuf};
#[derive(Parser)]
#[command(version, about = "Native AirDrop CLI and AWDL daemon")]
struct Cli {
    /// Increase logging detail; repeat for trace output. RUST_LOG overrides this.
    #[arg(long, global = true, action = ArgAction::Count)]
    verbose: u8,
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Run the idle control service; send/receive activate the radio and HTTPS.
    Daemon(Options),
    /// Receive transfers; inspect pending offers with transfers, then accept/reject.
    Receive {
        #[command(flatten)]
        options: Options,
        /// Exit after one successful file or link transfer.
        #[arg(long)]
        once: bool,
    },
    /// Send files, folders, or links; use a running daemon or start a temporary session.
    Send {
        #[command(flatten)]
        options: Options,
        /// AirDrop computer name or advertised service ID.
        to: String,
        files: Vec<PathBuf>,
        /// Send a link instead of files (can be repeated).
        #[arg(long, conflicts_with = "files")]
        url: Vec<String>,
        /// Bypass mDNS with an IPv6 socket address, including %scope for link-local.
        #[arg(long)]
        direct: Option<SocketAddrV6>,
        #[arg(long, default_value_t = 60)]
        timeout: u64,
    },
    /// List outgoing receivers during an active send session.
    Peers {
        #[arg(long, default_value = "/run/owl_rs")]
        run_dir: PathBuf,
        #[arg(long, default_value_t = 10)]
        timeout: u64,
    },
    /// Show AWDL statistics, active sends, and transfer state.
    Status {
        #[arg(long, default_value = "/run/owl_rs")]
        run_dir: PathBuf,
    },
    /// List incoming transfers and pending approvals.
    Transfers {
        #[arg(long, default_value = "/run/owl_rs")]
        run_dir: PathBuf,
    },
    Accept {
        id: String,
        #[arg(long, default_value = "/run/owl_rs")]
        run_dir: PathBuf,
    },
    Reject {
        id: String,
        #[arg(long, default_value = "/run/owl_rs")]
        run_dir: PathBuf,
    },
    /// Cancel the active session ID shown by status.
    Cancel {
        id: String,
        #[arg(long, default_value = "/run/owl_rs")]
        run_dir: PathBuf,
    },
    /// Stop the daemon and restore the radio.
    Stop {
        #[arg(long, default_value = "/run/owl_rs")]
        run_dir: PathBuf,
    },
    /// Inspect driver, TOML profile, and supported channels without changing the radio.
    Probe(#[command(flatten)] radio::RadioArgs),
    /// Restore radio state after an interrupted or killed process.
    Recover {
        #[arg(long, default_value = "/run/owl_rs")]
        run_dir: PathBuf,
    },
    /// AWDL diagnostics on a prepared monitor interface, or radiotap PCAP replay.
    Awdl(awdl::Arguments),
}
fn main() -> Result<()> {
    let matches = Cli::command().get_matches();
    let cli = Cli::from_arg_matches(&matches)?;
    let session_matches = matches.subcommand().map(|(_, args)| args);
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                match cli.verbose {
                    0 => "info",
                    1 => "debug",
                    _ => "trace",
                }
                .into()
            }),
        )
        .init();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let (dir, command) = match cli.command {
                Action::Daemon(options) => return service::run(options, None).await,
                Action::Receive { options, once } => {
                    let command = Command::Receive {
                        once,
                        options: overrides(&options, session_matches.unwrap())?,
                    };
                    if !service::control_available(&options.run_dir).await? {
                        return service::run(options, Some((command, None))).await;
                    }
                    (options.run_dir, command)
                }
                Action::Send {
                    options,
                    to,
                    files,
                    url,
                    direct,
                    timeout,
                } => {
                    ensure!(
                        !files.is_empty() || !url.is_empty(),
                        "choose files or --url"
                    );
                    let prepared = if files.is_empty() {
                        None
                    } else {
                        Some(
                            tokio::task::spawn_blocking({
                                let limit = options.max_bytes;
                                move || archive::prepare(&files, limit)
                            })
                            .await??,
                        )
                    };
                    let command = Command::Send {
                        to,
                        direct,
                        items: prepared
                            .as_ref()
                            .map(|p| p.items.clone())
                            .unwrap_or_default(),
                        urls: url,
                        bytes: prepared.as_ref().map(|p| p.bytes).unwrap_or(0),
                        icon: prepared.as_ref().and_then(|p| p.icon.clone()),
                        timeout,
                        options: overrides(&options, session_matches.unwrap())?,
                    };
                    if !service::control_available(&options.run_dir).await? {
                        return service::run(options, Some((command, prepared.map(|p| p.file))))
                            .await;
                    }
                    let value = foreground_client(
                        &options.run_dir,
                        command,
                        prepared.as_ref().map(|p| p.file.path()),
                    )
                    .await?;
                    println!("{}", serde_json::to_string_pretty(&value)?);
                    return Ok(());
                }
                Action::Peers { run_dir, timeout } => (run_dir, Command::Peers { timeout }),
                Action::Status { run_dir } => (run_dir, Command::Status),
                Action::Transfers { run_dir } => (run_dir, Command::Transfers),
                Action::Accept { id, run_dir } => (run_dir, Command::Accept { id }),
                Action::Reject { id, run_dir } => (run_dir, Command::Reject { id }),
                Action::Cancel { id, run_dir } => (run_dir, Command::Cancel { id }),
                Action::Stop { run_dir } => (run_dir, Command::Stop),
                Action::Probe(args) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&radio::probe(&args).await?)?
                    );
                    return Ok(());
                }
                Action::Recover { run_dir } => return radio::recover(&run_dir).await,
                Action::Awdl(args) => return awdl::run(args).await,
            };
            let value = if matches!(command, Command::Receive { .. }) {
                foreground_client(&dir, command, None).await?
            } else {
                service::client(&dir, command, None).await?
            };
            println!("{}", serde_json::to_string_pretty(&value)?);
            Ok(())
        })
}

// Only explicit CLI arguments override the idle daemon's session defaults.
fn overrides(options: &Options, matches: &clap::ArgMatches) -> Result<serde_json::Value> {
    fn explicit(value: &mut serde_json::Value, matches: &clap::ArgMatches) {
        if let Some(object) = value.as_object_mut() {
            object.retain(|key, value| {
                if key == "radio" {
                    explicit(value, matches);
                    !value.as_object().unwrap().is_empty()
                } else {
                    matches.value_source(key) == Some(ValueSource::CommandLine)
                }
            });
        }
    }
    let mut value = serde_json::to_value(options)?;
    explicit(&mut value, matches);
    Ok(value)
}

async fn foreground_client(
    dir: &std::path::Path,
    command: Command,
    archive: Option<&std::path::Path>,
) -> Result<serde_json::Value> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    {
        let request = service::client(dir, command, archive);
        tokio::pin!(request);
        tokio::select! {
            result = &mut request => return result,
            _ = tokio::signal::ctrl_c() => (),
            _ = term.recv() => (),
        }
        // Dropping the request closes IPC; the daemon then cancels this session.
    }
    tracing::info!("cancelling session; waiting for WLAN restoration");
    tokio::time::timeout(std::time::Duration::from_secs(90), async {
        loop {
            match service::client(dir, Command::Status, None).await {
                Ok(status) if !status["session"].is_null() => (),
                _ => break,
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!("session restoration is still running; inspect status or recover")
    })?;
    anyhow::bail!("session cancelled")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn awdl_requires_one_input_and_accepts_global_logging() {
        Cli::command().debug_assert();
        let cli =
            Cli::try_parse_from(["owl_rs", "awdl", "--read", "capture.pcap", "--verbose"]).unwrap();
        assert!(matches!(cli.command, Action::Awdl(_)));
        assert_eq!(cli.verbose, 1);
        assert!(
            Cli::try_parse_from(["owl_rs", "awdl", "--interface", "owlmon0", "--listen-only"])
                .is_ok()
        );
        for args in [
            vec!["owl_rs", "awdl"],
            vec![
                "owl_rs",
                "awdl",
                "--read",
                "capture.pcap",
                "--interface",
                "owlmon0",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
    }
}
