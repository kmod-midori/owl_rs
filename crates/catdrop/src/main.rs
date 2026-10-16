// SPDX-License-Identifier: GPL-3.0-or-later
#![forbid(unsafe_code)]
mod picker;
use airdrop_client::{
    control::{self, Command, ContactAction as ContactCommand, Options},
    timeouts::{AirDropTimeouts, Timeouts},
    visibility::Visibility,
};
use anyhow::{Result, ensure};
use clap::{
    ArgAction, Args, CommandFactory, FromArgMatches, Parser, Subcommand, parser::ValueSource,
};
use std::{net::SocketAddrV6, path::PathBuf};
#[derive(Parser)]
#[command(version, about = "AirDrop CLI for the user-owned airdropd service")]
struct Cli {
    /// Increase logging detail; repeat for trace output. RUST_LOG overrides this.
    #[arg(long, global = true, action = ArgAction::Count)]
    verbose: u8,
    #[command(subcommand)]
    command: Action,
    #[command(flatten)]
    timeouts: AirDropTimeouts,
}
#[derive(Args)]
struct ContactArgs {
    #[arg(long, global = true, default_value_os_t = control::default_run_dir())]
    run_dir: PathBuf,
    /// Use a different Contacts Only receiving list.
    #[arg(long, global = true)]
    contacts_file: Option<PathBuf>,
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
    async fn run(self) -> Result<()> {
        enum Output {
            Json,
            Lines,
            Count(&'static str),
        }
        let (action, output) = match self.command {
            ContactAction::List { json } => (
                ContactCommand::List,
                if json { Output::Json } else { Output::Lines },
            ),
            ContactAction::Add { identifiers } => {
                (ContactCommand::Add { identifiers }, Output::Count("Added"))
            }
            ContactAction::Remove { identifiers } => (
                ContactCommand::Remove { identifiers },
                Output::Count("Removed"),
            ),
        };
        let result = control::client(
            &self.run_dir,
            Command::Contact {
                action,
                contacts_file: self.contacts_file.map(std::path::absolute).transpose()?,
            },
            None,
        )
        .await?;
        match output {
            Output::Json => println!("{}", serde_json::to_string_pretty(&result)?),
            Output::Lines => {
                for entry in serde_json::from_value::<Vec<String>>(result)? {
                    println!("{entry}");
                }
            }
            Output::Count(verb) => println!(
                "{verb} {} contact(s).",
                serde_json::from_value::<usize>(result)?
            ),
        }
        Ok(())
    }
}
#[derive(Subcommand)]
enum Action {
    /// Ask the daemon to manage its Contacts Only receiving list.
    Contact(ContactArgs),
    /// Set runtime receiving visibility and BLE wake-up on the running daemon.
    Discoverable {
        #[arg(value_enum)]
        mode: Visibility,
        #[arg(long, default_value_os_t = control::default_run_dir())]
        run_dir: PathBuf,
        /// Select the list for contacts mode; otherwise reuse the current list.
        #[arg(long)]
        contacts_file: Option<PathBuf>,
    },
    /// Send files, folders, or links through the running user daemon.
    Send {
        #[command(flatten)]
        options: Box<Options>,
        /// AirDrop name or service ID; omit to choose interactively.
        #[arg(long)]
        to: Option<String>,
        files: Vec<PathBuf>,
        /// Send a link instead of files (can be repeated).
        #[arg(long, conflicts_with = "files")]
        url: Vec<String>,
        /// Bypass mDNS with an IPv6 socket address, including %scope for link-local.
        #[arg(long)]
        direct: Option<SocketAddrV6>,
        /// Maximum seconds to discover or interactively select a receiver.
        #[arg(long, default_value_t = 60, value_parser=clap::value_parser!(u64).range(1..=86400))]
        timeout: u64,
    },
    /// List observed AirDrop receivers during an active session.
    Peers {
        #[arg(long, default_value_os_t = control::default_run_dir())]
        run_dir: PathBuf,
        #[arg(long, default_value_t = 10, value_parser=clap::value_parser!(u64).range(1..=86400))]
        timeout: u64,
    },
    /// Show AWDL statistics, active sends, and transfer state.
    Status {
        #[arg(long, default_value_os_t = control::default_run_dir())]
        run_dir: PathBuf,
    },
    /// List incoming transfers and pending approvals.
    Transfers {
        #[arg(long, default_value_os_t = control::default_run_dir())]
        run_dir: PathBuf,
    },
    /// Accept a specific offer, or wait for and accept the next pending offer.
    Accept {
        id: Option<String>,
        #[arg(long, default_value_os_t = control::default_run_dir())]
        run_dir: PathBuf,
    },
    Reject {
        id: String,
        #[arg(long, default_value_os_t = control::default_run_dir())]
        run_dir: PathBuf,
    },
    /// Cancel a session or individual incoming/outgoing transfer ID shown by status.
    Cancel {
        id: String,
        #[arg(long, default_value_os_t = control::default_run_dir())]
        run_dir: PathBuf,
    },
    /// Stop the daemon and restore the radio.
    Stop {
        #[arg(long, default_value_os_t = control::default_run_dir())]
        run_dir: PathBuf,
    },
}
fn main() -> Result<()> {
    let matches = Cli::command().get_matches();
    let cli = Cli::from_arg_matches(&matches)?;
    ensure!(
        matches!(&cli.command, Action::Send { .. }) || !Timeouts::explicit(&matches),
        "timeout overrides apply to sends; configure airdropd at startup for other operations"
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
                    mut direct,
                    timeout,
                } => {
                    options.timeouts = cli.timeouts.into();
                    ensure!(
                        !files.is_empty() || !url.is_empty(),
                        "choose files or --url"
                    );
                    let overrides = overrides(&options, session_matches.unwrap())?;
                    let mut discovery = None;
                    let to = match to {
                        Some(to) => to,
                        None if direct.is_some() => direct.unwrap().to_string(),
                        None => {
                            let (target, session) =
                                picker::choose(&options.run_dir, overrides.clone(), timeout)
                                    .await?;
                            direct = Some(target.address);
                            discovery = Some(session);
                            target.name.unwrap_or(target.id)
                        }
                    };
                    let command = Command::SendPaths {
                        to,
                        direct,
                        files: files
                            .into_iter()
                            .map(std::path::absolute)
                            .collect::<std::io::Result<_>>()?,
                        urls: url,
                        timeout,
                        options: overrides,
                    };
                    let value = foreground_client(&options.run_dir, command).await?;
                    drop(discovery);
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
                Action::Contact(args) => {
                    return args.run().await;
                }
            };
            let value = if matches!(command, Command::Accept { id: None }) {
                foreground_client(&dir, command).await?
            } else {
                control::client(&dir, command, None).await?
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
                if key == "timeouts" {
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

async fn foreground_client(dir: &std::path::Path, command: Command) -> Result<serde_json::Value> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    {
        let request = control::client(dir, command, None);
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
                Cli::try_parse_from([
                    "catdrop",
                    "send",
                    "--to",
                    "fixture",
                    "--url",
                    "https://example.com",
                    "--ble-idle-timeout",
                    value
                ])
                .is_err()
            );
        }
        let matches = Cli::command()
            .try_get_matches_from([
                "catdrop",
                "--ble-idle-timeout",
                "12.5",
                "send",
                "--to",
                "fixture",
                "--url",
                "https://example.com/",
                "--approval-timeout",
                "0.5",
            ])
            .unwrap();
        let parsed = Cli::from_arg_matches(&matches).unwrap();
        let Action::Send { mut options, .. } = parsed.command else {
            unreachable!()
        };
        options.timeouts = parsed.timeouts.into();
        let changed = overrides(&options, matches.subcommand().unwrap().1).unwrap();
        assert_eq!(
            changed["timeouts"],
            serde_json::json!({"ble_idle":12.5,"approval":0.5})
        );
    }
}
