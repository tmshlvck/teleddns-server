//! Application bootstrap: wire config → DB → migrations → router → server. (M0: a minimal router
//! with `/healthcheck`; later milestones merge the DDNS, API, CF facade, admin UI, and worker.)

use crate::config::Config;
use axum::routing::get;
use axum::Router;
use relativelylight::auth::{self, Auth};
use sea_orm::DatabaseConnection;
use std::sync::Arc;

/// Shared, cheaply-cloneable application state.
#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub cfg: Arc<Config>,
    pub auth: Auth,
}

/// Run the HTTP server.
pub async fn serve(cfg: Config) -> Result<(), Box<dyn std::error::Error>> {
    let db = crate::db::connect(&cfg.db_dsn).await?;
    auth::migrate(&db).await?;

    let secure = cfg.public_url.starts_with("https://");
    let auth = Auth::new(db.clone()).secure_cookies(secure).admin_group("admin");

    let state = AppState { db, cfg: Arc::new(cfg), auth };

    let app = Router::new()
        .route("/healthcheck", get(healthcheck))
        .with_state(state.clone());

    let addr = state.cfg.bind_addr();
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "teleddns-server listening");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Minimal healthcheck placeholder (full implementation in the ops milestone).
async fn healthcheck() -> &'static str {
    "OK\n"
}

/// `admin reset-password` — set a new random password for a user and print it.
pub async fn reset_password(cfg: Config, username: &str) -> Result<(), Box<dyn std::error::Error>> {
    use rand::Rng;
    let db = crate::db::connect(&cfg.db_dsn).await?;
    auth::migrate(&db).await?;
    let pw: String = {
        let mut rng = rand::thread_rng();
        (0..16).map(|_| rng.sample(rand::distributions::Alphanumeric) as char).collect()
    };
    auth::set_password(&db, username, &pw).await?;
    println!("password for {username} set to: {pw}");
    Ok(())
}
