// SPDX-License-Identifier: GPL-3.0-or-later
#![forbid(unsafe_code)]
mod awdl;
use anyhow::{Result, ensure};
use clap::{
    ArgAction, Args, CommandFactory, FromArgMatches, Parser, Subcommand, parser::ValueSource,
};
use owl_rs::{
    archive, contact_book, radio,
    service::{self, Command, Options},
    timeouts::Timeouts,
    visibility::Visibility,
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
    #[command(flatten)]
    timeouts: Timeouts,
}
#[derive(Args)]
struct ContactArgs {
    /// Use a different Contacts Only receiving list.
    #[arg(long, global = true)]
    contacts_file: Option<PathBuf>,
    /// Select the user's list; under sudo, defaults to the invoking user.
    #[arg(long, global = true)]
    owner: Option<String>,
    #[command(subcommand)]
    command: ContactAction,
}
#[derive(Subcommand)]
enum ContactAction {
    /// Add Apple ID emails or international phone numbers; duplicates are ignored.
    Add {
        #[arg(required = true, num_args = 1..)]
        identifiers: Vec<String>,
    },
    /// Show normalized identifiers, one per line.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Remove matching emails or phone numbers, including alternate formatting.
    Remove {
        #[arg(required = true, num_args = 1..)]
        identifiers: Vec<String>,
    },
}
impl ContactArgs {
    fn run(self) -> Result<()> {
        let (uid, gid, home) = service::owner(self.owner.as_deref())?;
        let path = self
            .contacts_file
            .unwrap_or_else(|| contact_book::default_path(&home));
        match self.command {
            ContactAction::List { json } => {
                let entries = contact_book::list(&path)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&entries)?);
                } else {
                    for entry in entries {
                        println!("{entry}");
                    }
                }
            }
            ContactAction::Add { identifiers } => {
                let count = contact_book::Book::new(path, Some((uid, gid))).add(&identifiers)?;
                println!("Added {count} contact(s).");
            }
            ContactAction::Remove { identifiers } => {
                let count = contact_book::Book::new(path, Some((uid, gid))).remove(&identifiers)?;
                println!("Removed {count} contact(s).");
            }
        }
        Ok(())
    }
}
#[derive(Subcommand)]
enum Action {
    /// Manage the local contact list used for Contacts Only receiving.
    Contact(ContactArgs),
    /// Run the control daemon; enabled BLE wake requests start receiving sessions.
    Daemon(Options),
    /// Set runtime receiving visibility and BLE wake-up on the running daemon.
    Discoverable {
        #[arg(value_enum)]
        mode: Visibility,
        #[arg(long, default_value = "/run/owl_rs")]
        run_dir: PathBuf,
        /// Select the list for contacts mode; otherwise reuse the current list.
        #[arg(long)]
        contacts_file: Option<PathBuf>,
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
        #[arg(long, default_value_t = 60, value_parser=clap::value_parser!(u64).range(1..=86400))]
        timeout: u64,
    },
    /// List observed AirDrop receivers during an active session.
    Peers {
        #[arg(long, default_value = "/run/owl_rs")]
        run_dir: PathBuf,
        #[arg(long, default_value_t = 10, value_parser=clap::value_parser!(u64).range(1..=86400))]
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
    /// Accept a specific offer, or wait for and accept the next pending offer.
    Accept {
        id: Option<String>,
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
    ensure!(
        matches!(
            &cli.command,
            Action::Daemon(_)
                | Action::Send { .. }
                | Action::Probe(_)
                | Action::Recover { .. }
                | Action::Awdl(_)
        ) || !Timeouts::explicit(&matches),
        "timeout flags configure daemon/send or radio diagnostics; configure the running daemon at startup"
    );
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
                Action::Daemon(mut options) => {
                    options.timeouts = cli.timeouts;
                    return service::run(options, None).await;
                }
                Action::Discoverable {
                    mode,
                    run_dir,
                    contacts_file,
                } => (
                    run_dir,
                    Command::Discoverable {
                        mode,
                        contacts_file: contacts_file.map(std::path::absolute).transpose()?,
                    },
                ),
                Action::Send {
                    mut options,
                    to,
                    files,
                    url,
                    direct,
                    timeout,
                } => {
                    options.timeouts = cli.timeouts;
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
                        serde_json::to_string_pretty(&radio::probe(&args, &cli.timeouts).await?)?
                    );
                    return Ok(());
                }
                Action::Recover { run_dir } => {
                    return radio::recover(&run_dir, &cli.timeouts).await;
                }
                Action::Awdl(args) => return awdl::run(args, cli.timeouts).await,
                Action::Contact(args) => {
                    return tokio::task::spawn_blocking(move || args.run()).await?;
                }
            };
            let value = if matches!(command, Command::Accept { id: None }) {
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
                if key == "radio" || key == "timeouts" {
                    explicit(value, matches);
                    !value.as_object().unwrap().is_empty()
                } else {
                    matches.try_contains_id(key).unwrap_or(false)
                        && matches.value_source(key) == Some(ValueSource::CommandLine)
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
        // Dropping the request closes IPC; the daemon then cancels this operation.
    }
    // The daemon cancels this operation and retains any other session users.
    anyhow::bail!("operation cancelled")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cli_overrides_preserve_explicit_values() {
        Cli::command().debug_assert();
        for value in ["0", "-1", "NaN", "inf", "90000"] {
            assert!(
                Cli::try_parse_from(["owl_rs", "daemon", "--ble-idle-timeout", value]).is_err()
            );
        }
        assert!(
            Cli::try_parse_from(["owl_rs", "daemon", "--duration", "18446744073709551615"])
                .is_err()
        );
        let matches = Cli::command()
            .try_get_matches_from([
                "owl_rs",
                "--ble-idle-timeout",
                "12.5",
                "send",
                "fixture",
                "--url",
                "https://example.com/",
                "--approval-timeout",
                "0.5",
                "--completion-grace",
                "0",
            ])
            .unwrap();
        let parsed = Cli::from_arg_matches(&matches).unwrap();
        let Action::Send { mut options, .. } = parsed.command else {
            unreachable!()
        };
        options.timeouts = parsed.timeouts;
        let changed = overrides(&options, matches.subcommand().unwrap().1).unwrap();
        assert_eq!(options.rate, owl_rs::rate::Rate::Auto);
        assert!(changed.get("rate").is_none());
        for rate in ["12", "mcs7-sgi", "vht4-nss2-bw40-sgi", "auto"] {
            let matches = Cli::command()
                .try_get_matches_from([
                    "owl_rs",
                    "send",
                    "fixture",
                    "--url",
                    "https://example.com/",
                    "--rate",
                    rate,
                ])
                .unwrap();
            let Action::Send { options, .. } = Cli::from_arg_matches(&matches).unwrap().command
            else {
                unreachable!()
            };
            assert_eq!(
                overrides(&options, matches.subcommand().unwrap().1).unwrap()["rate"],
                rate
            );
        }
        assert_eq!(
            changed["timeouts"],
            serde_json::json!({"ble_idle":12.5,"approval":0.5,"completion_grace":0.0})
        );
    }
}
