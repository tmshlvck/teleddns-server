//! Application bootstrap: wire config → DB → migrations → engine → router → server.

use crate::config::Config;
use axum::routing::get;
use axum::Router;
use crate::migration::Migrator;
use relativelylight::auth::lockout::{IpLockout, Lockout, UsernameLockout};
use relativelylight::auth::{self, Auth};
use relativelylight::crud::engine::Engine;
use sea_orm::{DatabaseConnection, EntityTrait, PaginatorTrait};
use sea_orm_migration::MigratorTrait;
use std::sync::Arc;

/// The group whose members hold L3 (global authority). **One name for all of it**: the library's
/// `Auth::admin_group` (which drives the profile-manager default), the console's `GroupReadWrite` gate
/// (`web.rs`), the L3 decision in `authz::user_groups`, the first-start seed, and `admin
/// reset-password --break-glass`. If those ever disagree, an "admin" ends up outside the group the gate
/// checks — able to log in, able to administer nothing. Not configurable on purpose: it is baked into
/// the grants (PRD §3.2), so renaming it would need a migration, not a config edit.
pub const ADMIN_GROUP: &str = "admin";

/// The session-cookie name (shared by `Auth` and the audit sink's session resolution).
const SESSION_COOKIE: &str = "teleddns_session";

/// The double-submit CSRF token cookie (relativelylight `csrf`). Named per app — a co-hosted app on
/// the same host would otherwise fight us for the default `rl_csrf` name. `keys.rs` reads it from the
/// browser to put the token on its own forms.
pub const CSRF_COOKIE: &str = "teleddns_csrf";

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
    /// Brute-force brake on the credential checks *we* make (DDNS Basic, bearer tokens) — the very same
    /// DB-backed counters relativelylight brakes the console login with, so an account has one budget
    /// across every surface and deleting one row in the admin panel unlocks all of them.
    pub usernames: UsernameLockout,
    pub ips: IpLockout,
    pub audit: Arc<crate::audit::Audit>,
    pub started_at: i64,
    pub ip_whitelist: Arc<Vec<ipnet::IpNet>>,
    pub ops_ip_whitelist: Arc<Vec<ipnet::IpNet>>,
}

/// Run the HTTP server.
pub async fn serve(cfg: Config) -> Result<(), Box<dyn std::error::Error>> {
    crate::web::init_ui_title(&cfg.ui_title); // navbar brand
    let db = crate::db::connect(&cfg.db_dsn).await?;
    Migrator::up(&db, None).await?; // versioned schema (auth + app tables), applied once
    seed_admin(&db).await?;
    crate::audit::prune(&db, cfg.audit_retention_days).await; // drop rows past the retention window
    // Hygiene for rows written before an empty admin-form input on a nullable column meant NULL: a
    // blank `sso_provider` used to read as "this is an SSO account" (no password login) and a blank
    // `totp_secret` as "2FA on" (demanding a code no authenticator can produce). relativelylight's
    // readers now tolerate both, this makes the column consistent. Cheap and idempotent.
    match auth::normalize_blank_user_columns(&db).await {
        Ok(0) => {}
        Ok(n) => tracing::info!(rows = n, "normalized blank sso_provider/totp columns to NULL"),
        Err(e) => tracing::warn!(error = %e, "could not normalize blank auth_user columns"),
    }

    let secure = cfg.public_url.starts_with("https://");
    // The audit sink persists a row per write; shared as the WriteObserver for the admin auto-CRUD
    // and the auth handlers, and used directly by the DDNS/API/CF handlers.
    let audit: Arc<crate::audit::Audit> =
        Arc::new(crate::audit::Audit::new(db.clone(), SESSION_COOKIE, cfg.trust_proxy));
    // SSO login buttons for the login page (empty when no providers are configured).
    let sso_buttons = crate::sso::buttons_html(&cfg);
    // The profile page (password + 2FA) is owned by relativelylight; teleddns composes its
    // API-key/bearer-token component in below it via `profile_extra`.
    let extra_db = db.clone();
    // The brute-force brake (PRD §3.6) — mandatory, so it is a constructor argument. Counters live in
    // `auth_username_lockout` / `auth_ip_lockout`; a locked key is refused before its secret is read.
    let lockout = Lockout {
        username_after: cfg.username_lockout_after,
        username_duration_secs: cfg.username_lockout_duration.as_secs() as i64,
        ip_after: cfg.ip_lockout_after,
        ip_duration_secs: cfg.ip_lockout_duration.as_secs() as i64,
        // The login route resolves the client with `relativelylight::net::client_ip`, which is what our
        // own surfaces call too — one client's failures land on one row whichever surface they came
        // from, and proxy trust is decided in exactly one place: this config flag.
        trust_proxy: cfg.trust_proxy,
        // Never locked out (empty by default): the office range, a monitoring probe, the NAT a fleet
        // shares — a locked address turns away the valid callers behind it too.
        ip_whitelist: relativelylight::net::parse_nets(&cfg.ip_lockout_whitelist),
    };
    let auth = Auth::new(db.clone(), lockout.clone())
        .secure_cookies(secure)
        .admin_group(ADMIN_GROUP)
        .cookie_name(SESSION_COOKIE)
        .csrf_cookie_name(CSRF_COOKIE)
        .totp_issuer("teleddns")
        .on_write(audit.clone()) // audit auth-table changes (password change, manager reset)
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

    let engine =
        Arc::new(crate::web::build_engine(db.clone(), &auth, audit.clone(), cfg.default_ttl));

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

    // Handles on those same counters for the DDNS/API/CF credential checks (see `principal`): one
    // account has one budget whether it is guessed at on the console or on the DDNS endpoint.
    let usernames = auth.username_lockout();
    let ips = auth.ip_lockout();
    tracing::info!(
        username_after = lockout.username_after,
        username_duration = lockout.username_duration_secs,
        ip_after = lockout.ip_after,
        ip_duration = lockout.ip_duration_secs,
        trust_proxy = lockout.trust_proxy,
        "credential lockout"
    );

    let cfg = Arc::new(cfg);
    let metrics = Arc::new(crate::metrics::Metrics::new());
    let backend = crate::backend::make(&cfg);
    let worker = crate::backend::worker::spawn(
        db.clone(),
        cfg.clone(),
        backend.clone(),
        metrics.clone(),
        lockout, // the worker also runs the auth housekeeping (sessions + lockout rows)
    );
    tracing::info!(backend = backend.name(), "backend sync worker started");

    let ip_whitelist = Arc::new(relativelylight::net::parse_nets(&cfg.ip_whitelist));
    let ops_ip_whitelist = Arc::new(relativelylight::net::parse_nets(&cfg.ops_ip_whitelist));
    let state = AppState {
        db,
        cfg,
        auth: auth.clone(),
        engine: engine.clone(),
        openapi,
        backend,
        worker,
        metrics,
        usernames,
        ips,
        audit,
        started_at: crate::model::now(),
        ip_whitelist,
        ops_ip_whitelist,
    };

    // dyndns2 documents the parameters in the query string and prefers GET, but permits POST; any
    // other method falls through to `badagent`.
    let ddns = get(crate::ddns::update)
        .post(crate::ddns::update)
        .fallback(crate::ddns::reject_method);
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
        app.layer(axum::middleware::from_fn_with_state(state.clone(), crate::net::whitelist));
    // Outermost: one access-log line per request (logs allow-list denials too).
    let app =
        app.layer(axum::middleware::from_fn_with_state(state.clone(), crate::net::access_log));

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
    auth::make_admin(db, ADMIN_GROUP, "admin", &pw).await?;
    tracing::warn!(username = "admin", password = %pw, "seeded initial admin user");
    Ok(())
}

fn random_password() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..16).map(|_| rng.sample(rand::distributions::Alphanumeric) as char).collect()
}

/// `admin reset-password` — set a new random password for an **existing** user and print it. Nothing
/// else about the account changes: a disabled account stays disabled, 2FA stays enrolled, and an SSO
/// account still refuses password login — so a reset can never quietly re-open a closed account. An
/// unknown username is an error, not a new account.
///
/// `break_glass` is the recovery path for a locked-out administrator: it additionally re-activates the
/// account, **discards its TOTP enrolment** (the admin must re-enrol from `/profile`) and ensures
/// admin-group membership, creating the user if missing. It refuses an SSO account.
pub async fn reset_password(
    cfg: Config,
    username: &str,
    break_glass: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let db = crate::db::connect(&cfg.db_dsn).await?;
    Migrator::up(&db, None).await?;
    let pw = random_password();
    if break_glass {
        auth::reset_admin_access(&db, ADMIN_GROUP, username, &pw).await?;
        println!("admin access for {username} restored (2FA cleared); password set to: {pw}");
    } else {
        auth::set_password(&db, username, &pw).await?;
        println!("password for {username} set to: {pw}");
    }
    Ok(())
}
