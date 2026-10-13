// SPDX-License-Identifier: GPL-3.0-or-later
#![forbid(unsafe_code)]
mod awdl;
use anyhow::Result;
use clap::{ArgAction, Parser, Subcommand};
#[derive(Parser)]
#[command(version, about = "Privileged AWDL radio service")]
struct Cli {
    #[arg(long, global=true, action=ArgAction::Count)]
    verbose: u8,
    #[command(flatten)]
    options: owl::daemon::Options,
    #[command(flatten)]
    timeouts: owl::timeouts::RadioTimeouts,
    #[command(subcommand)]
    command: Option<Action>,
}
#[derive(Subcommand)]
enum Action {
    /// Inspect hardware and profiles without changing the radio.
    Probe(owl::radio::RadioArgs),
    /// Restore WLAN state left by a killed radio service.
    Recover,
    /// Live monitor diagnostics or offline PCAP replay.
    Awdl(awdl::Arguments),
}
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| if cli.verbose > 0 { "debug" } else { "info" }.into()),
        )
        .init();
    let timeouts = cli.timeouts.into();
    match cli.command {
        Some(Action::Probe(args)) => println!(
            "{}",
            serde_json::to_string_pretty(&owl::radio::probe(&args, &timeouts).await?)?
        ),
        Some(Action::Recover) => owl::radio::recover(&cli.options.run_dir, &timeouts).await?,
        Some(Action::Awdl(args)) => awdl::run(args, timeouts).await?,
        None => owl::daemon::run(cli.options, timeouts).await?,
    }
    Ok(())
}
