// SPDX-License-Identifier: GPL-3.0-or-later
#![forbid(unsafe_code)]
use anyhow::Result;
use clap::{ArgAction, Parser};
#[derive(Parser)]
#[command(
    version,
    about = "User AirDrop service; uses the privileged owld radio service"
)]
struct Cli {
    #[command(flatten)]
    options: airdrop::service::Options,
    #[command(flatten)]
    timeouts: airdrop::timeouts::AirDropTimeouts,
    #[arg(long, action=ArgAction::Count)]
    verbose: u8,
}
#[tokio::main]
async fn main() -> Result<()> {
    let mut cli = Cli::parse();
    cli.options.timeouts = cli.timeouts.into();
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| if cli.verbose > 0 { "debug" } else { "info" }.into()),
        )
        .init();
    airdrop::service::run(cli.options).await
}
