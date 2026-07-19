//! teleddns-server — co-located DNS management + Dynamic DNS server for a Knot DNS master.
//! See PRD.md for the product spec and RUSTREWRITE.md for the implementation plan.

mod api;
mod app;
mod authz;
mod backend;
mod cfapi;
mod config;
mod db;
mod ddns;
mod dns;
mod keys;
mod metrics;
mod migration;
mod model;
mod net;
mod ops;
mod principal;
mod ratelimit;
mod sso;
mod sync;
mod web;
mod zoneimport;

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
    /// Bulk-load a BIND zone file into the DB (use `-` to read stdin).
    Import {
        /// Path to the zone file, or `-` for stdin.
        file: String,
        /// Clear the zone's existing records first (default merges).
        #[arg(long)]
        replace: bool,
        /// Override the origin (else taken from $ORIGIN / SOA).
        #[arg(long)]
        origin: Option<String>,
    },
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
        Some(Command::Admin(AdminCommand::Import { file, replace, origin })) => {
            zoneimport::import(cfg, &file, replace, origin.as_deref()).await
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
