//! Application bootstrap: wire config → DB → migrations → engine → router → server.

use crate::config::Config;
use axum::routing::get;
use axum::Router;
use relativelylight::auth::{self, Auth};
use relativelylight::crud::engine::Engine;
use sea_orm::{DatabaseConnection, EntityTrait, PaginatorTrait};
use std::sync::Arc;

/// Shared, cheaply-cloneable application state.
#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub cfg: Arc<Config>,
    pub auth: Auth,
    pub engine: Arc<Engine>,
    pub openapi: String,
    pub backend: Arc<dyn crate::backend::Backend>,
    pub worker: crate::backend::worker::WorkerHandle,
    pub metrics: Arc<crate::metrics::Metrics>,
    pub ratelimit: Arc<crate::ratelimit::RateLimiter>,
}

/// Run the HTTP server.
pub async fn serve(cfg: Config) -> Result<(), Box<dyn std::error::Error>> {
    let db = crate::db::connect(&cfg.db_dsn).await?;
    auth::migrate(&db).await?;
    crate::model::migrate(&db).await?;
    seed_admin(&db).await?;

    let secure = cfg.public_url.starts_with("https://");
    let auth = Auth::new(db.clone())
        .secure_cookies(secure)
        .admin_group("admin")
        .totp_issuer("teleddns")
        .login_shell(crate::web::login_shell)
        .profile_shell(crate::web::profile_shell);

    let engine = Arc::new(crate::web::build_engine(db.clone(), &auth));

    // The app owns the OpenAPI root; the admin CRUD entity endpoints + schemas are merged in.
    let app_doc = utoipa::openapi::OpenApiBuilder::new()
        .info(
            utoipa::openapi::InfoBuilder::new()
                .title("teleddns-server API")
                .version(env!("CARGO_PKG_VERSION"))
                .build(),
        )
        .build();
    let openapi = relativelylight::crud::openapi::merge_into(app_doc, &engine)
        .to_pretty_json()
        .unwrap_or_default();

    let cfg = Arc::new(cfg);
    let backend = crate::backend::make(&cfg);
    let worker = crate::backend::worker::spawn(db.clone(), cfg.clone(), backend.clone());
    tracing::info!(backend = backend.name(), "backend sync worker started");

    let state = AppState {
        db,
        cfg,
        auth: auth.clone(),
        engine: engine.clone(),
        openapi,
        backend,
        worker,
        metrics: Arc::new(crate::metrics::Metrics::new()),
        ratelimit: Arc::new(crate::ratelimit::RateLimiter::new()),
    };

    let ddns = get(crate::ddns::update).fallback(crate::ddns::reject_non_get);
    let app = Router::new()
        .route("/", get(crate::web::home))
        .route("/keys", get(crate::keys::page).post(crate::keys::mint))
        .route("/keys/{id}/revoke", axum::routing::post(crate::keys::revoke))
        .route("/nic/update", ddns.clone())
        .route("/ddns/update", ddns.clone())
        .route("/update", ddns)
        .route("/openapi.json", get(crate::web::openapi_json))
        .route("/docs", get(crate::web::docs))
        .route("/healthcheck", get(healthcheck))
        .merge(crate::api::router())
        .merge(crate::cfapi::router())
        .with_state(state.clone())
        .merge(auth.routes())
        .merge(engine.router());

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

/// On first start (no users yet), seed an `admin` user in the `admin` group and log the generated
/// password once.
async fn seed_admin(db: &DatabaseConnection) -> Result<(), Box<dyn std::error::Error>> {
    let count = relativelylight::auth::user::Entity::find().count(db).await?;
    if count > 0 {
        return Ok(());
    }
    let pw = random_password();
    auth::make_admin(db, "admin", "admin", &pw).await?;
    tracing::warn!(username = "admin", password = %pw, "seeded initial admin user");
    Ok(())
}

fn random_password() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..16).map(|_| rng.sample(rand::distributions::Alphanumeric) as char).collect()
}

/// `admin reset-password` — set a new random password for a user and print it.
pub async fn reset_password(cfg: Config, username: &str) -> Result<(), Box<dyn std::error::Error>> {
    let db = crate::db::connect(&cfg.db_dsn).await?;
    auth::migrate(&db).await?;
    let pw = random_password();
    auth::set_password(&db, username, &pw).await?;
    println!("password for {username} set to: {pw}");
    Ok(())
}
