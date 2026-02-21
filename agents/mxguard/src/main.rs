//! MxGuard -- Endpoint Detection & Response agent for the MxTac platform.
//!
//! Collects process, file, and network telemetry from Linux hosts, converts
//! them to OCSF events, and ships them to the MxTac ingest API.

mod agent;
mod attack;
mod collectors;
mod config;
mod events;
mod health;
mod resource_limits;
mod transport;

use clap::Parser;
use tracing_subscriber::EnvFilter;

/// MxGuard EDR agent.
#[derive(Parser, Debug)]
#[command(name = "mxguard", version, about = "MxGuard EDR Agent for MxTac")]
struct Cli {
    /// Path to TOML configuration file.
    #[arg(short, long, default_value = "/etc/mxguard/mxguard.toml")]
    config: String,

    /// Override log level (trace, debug, info, warn, error).
    #[arg(short, long)]
    log_level: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Load configuration (TOML file first, then MXGUARD_* env var overrides).
    let cfg = if std::path::Path::new(&cli.config).exists() {
        config::Config::from_file(&cli.config)?
    } else {
        tracing::warn!(
            "Config file not found at {}, using defaults",
            cli.config
        );
        config::Config::default_config()?
    };

    // Initialise tracing / logging.
    let log_level = cli
        .log_level
        .as_deref()
        .unwrap_or(&cfg.agent.log_level);

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(log_level)),
        )
        .with_target(true)
        .with_thread_ids(true)
        .init();

    tracing::info!("MxGuard v{} starting", env!("CARGO_PKG_VERSION"));

    // Build and run the agent.
    let agent = agent::Agent::new(cfg);
    agent.run().await?;

    Ok(())
}
