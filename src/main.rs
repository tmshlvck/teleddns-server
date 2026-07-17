//! teleddns-server — co-located DNS management + Dynamic DNS server for a Knot DNS master.
//! See PRD.md for the product spec and RUSTREWRITE.md for the implementation plan.

mod app;
mod authz;
mod config;
mod db;
mod keys;
mod model;
mod principal;
mod sync;
mod web;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(name = "teleddns-server", version = VERSION, about = "Co-located DNS + DDNS server for Knot")]
struct Cli {
    /// Path to the config file (else $TELEDDNS_CONFIG, ./teleddns-server.yaml, /etc/teleddns/…).
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the server (default).
    Serve,
    /// Administrative subcommands.
    #[command(subcommand)]
    Admin(AdminCommand),
}

#[derive(Subcommand)]
enum AdminCommand {
    /// Reset a user's password (prompts are avoided; a new random password is printed).
    ResetPassword { username: String },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let cfg = config::Config::load(cli.config.as_deref())?;
    init_tracing(cfg.debug);

    match cli.command {
        None | Some(Command::Serve) => app::serve(cfg).await,
        Some(Command::Admin(AdminCommand::ResetPassword { username })) => {
            app::reset_password(cfg, &username).await
        }
    }
}

fn init_tracing(debug: bool) {
    use tracing_subscriber::EnvFilter;
    // Quiet sqlx's per-statement logging by default; the app's own logs stay at info/debug.
    let default = if debug {
        "debug,sqlx::query=warn"
    } else {
        "info,sqlx::query=warn"
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
