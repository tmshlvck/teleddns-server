//! Application bootstrap: wire config → DB → migrations → engine → router → server.

use crate::config::Config;
use axum::routing::get;
use axum::Router;
use crate::migration::Migrator;
use relativelylight::auth::{self, Auth};
use relativelylight::crud::engine::Engine;
use sea_orm::{DatabaseConnection, EntityTrait, PaginatorTrait};
use sea_orm_migration::MigratorTrait;
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
    pub started_at: i64,
    pub allowed_nets: Arc<Vec<ipnet::IpNet>>,
    pub ops_nets: Arc<Vec<ipnet::IpNet>>,
}

/// Run the HTTP server.
pub async fn serve(cfg: Config) -> Result<(), Box<dyn std::error::Error>> {
    let db = crate::db::connect(&cfg.db_dsn).await?;
    Migrator::up(&db, None).await?; // versioned schema (auth + app tables), applied once
    seed_admin(&db).await?;

    let secure = cfg.public_url.starts_with("https://");
    // SSO login buttons for the login page (empty when no providers are configured).
    let sso_buttons = crate::sso::buttons_html(&cfg);
    // The profile page (password + 2FA) is owned by relativelylight; teleddns composes its
    // API-key/bearer-token component in below it via `profile_extra`.
    let extra_db = db.clone();
    let auth = Auth::new(db.clone())
        .secure_cookies(secure)
        .admin_group("admin")
        .cookie_name("teleddns_session")
        .totp_issuer("teleddns")
        .login_shell(move |form| crate::web::login_shell(form, &sso_buttons))
        .profile_shell(crate::web::profile_shell)
        .profile_extra(move |who| {
            let db = extra_db.clone();
            async move {
                let uid = who.id.parse::<i32>().unwrap_or(0);
                crate::keys::section(&db, uid).await
            }
        });

    // OIDC single sign-on (optional): built from config, routes merged below.
    let sso = crate::sso::build(&cfg, &auth);
    if let Some(s) = &sso {
        tracing::info!(providers = s.buttons().len(), "OIDC SSO enabled");
    }

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
    let merged = relativelylight::crud::openapi::merge_into(app_doc, &engine)
        .to_pretty_json()
        .unwrap_or_default();
    // Fold in the hand-written native-API + CF-facade paths (their handlers aren't introspected).
    let openapi = match serde_json::from_str::<serde_json::Value>(&merged) {
        Ok(mut doc) => {
            crate::api::openapi::merge(&mut doc);
            serde_json::to_string_pretty(&doc).unwrap_or(merged)
        }
        Err(_) => merged,
    };

    let cfg = Arc::new(cfg);
    let metrics = Arc::new(crate::metrics::Metrics::new());
    let backend = crate::backend::make(&cfg);
    let worker =
        crate::backend::worker::spawn(db.clone(), cfg.clone(), backend.clone(), metrics.clone());
    tracing::info!(backend = backend.name(), "backend sync worker started");

    let allowed_nets = Arc::new(crate::net::parse_nets(&cfg.allowed_ips));
    let ops_nets = Arc::new(crate::net::parse_nets(&cfg.ops_allowed_ips));
    let state = AppState {
        db,
        cfg,
        auth: auth.clone(),
        engine: engine.clone(),
        openapi,
        backend,
        worker,
        metrics,
        ratelimit: Arc::new(crate::ratelimit::RateLimiter::new()),
        started_at: crate::model::now(),
        allowed_nets,
        ops_nets,
    };

    let ddns = get(crate::ddns::update).fallback(crate::ddns::reject_non_get);
    let app = Router::new()
        .route("/", get(crate::web::home))
        .route("/keys", axum::routing::post(crate::keys::mint))
        .route("/keys/{id}/revoke", axum::routing::post(crate::keys::revoke))
        .route("/nic/update", ddns.clone())
        .route("/ddns/update", ddns.clone())
        .route("/update", ddns)
        .route("/openapi.json", get(crate::web::openapi_json))
        .route("/docs", get(crate::web::docs))
        .route("/healthcheck", get(crate::ops::healthcheck))
        .route("/metrics", get(crate::ops::metrics))
        .merge(crate::api::router())
        .merge(crate::cfapi::router())
        .with_state(state.clone())
        .merge(auth.routes())
        .merge(engine.router());
    // Merge the SSO login/callback routes (their own state) when configured.
    let app = match &sso {
        Some(s) => app.merge(s.routes()),
        None => app,
    };
    let app =
        app.layer(axum::middleware::from_fn_with_state(state.clone(), crate::net::allow_list));

    let addr = state.cfg.bind_addr();
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "teleddns-server listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
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
    Migrator::up(&db, None).await?;
    let pw = random_password();
    auth::set_password(&db, username, &pw).await?;
    println!("password for {username} set to: {pw}");
    Ok(())
}
