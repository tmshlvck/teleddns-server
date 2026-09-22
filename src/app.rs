//! Application bootstrap: wire config → DB → migrations → engine → router → server.

use crate::config::Config;
use axum::response::Redirect;
use axum::routing::get;
use axum::Router;
use crate::migration::Migrator;
use relativelylight::auth::lockout::{IpLockout, Lockout, UsernameLockout};
use relativelylight::auth::{self, Auth};
use relativelylight::crud::engine::Engine;
use sea_orm::{DatabaseConnection, EntityTrait, PaginatorTrait};
use sea_orm_migration::MigratorTrait;
use std::sync::Arc;

/// The group whose members hold the **Superadmin** role (global authority). **One name for all of
/// it**: the library's
/// `Auth::admin_group` (which drives the profile-manager default), the console's `GroupReadWrite` gate
/// (`web::entities`), the Superadmin decision in `authz::user_groups`, the first-start seed, and `admin
/// reset-password --break-glass`. If those ever disagree, an "admin" ends up outside the group the gate
/// checks — able to log in, able to administer nothing. Not configurable on purpose: it is baked into
/// the grants (PRD §3.2), so renaming it would need a migration, not a config edit.
pub const ADMIN_GROUP: &str = "admin";

/// The session-cookie name (shared by `Auth` and the audit sink's session resolution — the CLI paths
/// build their own sink, hence `pub`).
pub const SESSION_COOKIE: &str = "teleddns_session";

/// The double-submit CSRF token cookie (relativelylight `csrf`). Named per app — a co-hosted app on
/// the same host would otherwise fight us for the default `rl_csrf` name. Every cookie-authenticated
/// form echoes the token in a hidden `_csrf` field, rendered server-side.
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
    pub ip_src_allowed: Arc<Vec<ipnet::IpNet>>,
    pub ops_ip_src_allowed: Arc<Vec<ipnet::IpNet>>,
}

/// Run the HTTP server.
pub async fn serve(cfg: Config) -> Result<(), Box<dyn std::error::Error>> {
    crate::web::init(&cfg); // navbar brand + the timezones the picker offers
    let db = crate::db::connect(&cfg.db_dsn).await?;
    Migrator::up(&db, None).await?; // versioned schema (auth + app tables), applied once
    // The audit sink persists a row per write; shared as the WriteObserver for the admin auto-CRUD
    // and the auth handlers, and used directly by the DDNS/API/CF/keys handlers. Built first because
    // the seed and the retention pass below both write state, and both are audited like anything else.
    // The address arrives on the event, already resolved by the `resolve_real_ip` layer, so the sink
    // needs nothing but the DB and the session-cookie name to resolve the actor.
    let audit: Arc<crate::audit::Audit> = Arc::new(crate::audit::Audit::new(db.clone(), SESSION_COOKIE));
    seed_admin(&db, &audit).await?;
    crate::audit::prune(&db, cfg.audit_retention_days, &audit).await; // drop rows past the retention window
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
    // SSO login buttons for the login page (empty when no providers are configured).
    let sso_buttons = crate::sso::buttons_html(&cfg);
    // The profile page (password + 2FA) is owned by relativelylight; teleddns composes its
    // API-key/bearer-token component in below it via `profile_extra`.
    let extra_db = db.clone();
    // The brute-force brake (PRD §3.6) — mandatory, so it is a constructor argument. Counters live in
    // `auth_username_lockout` / `auth_ip_lockout`; a locked key is refused before its secret is read.
    // Built from `Lockout::default()` and the two setters, not a struct literal — the type is
    // `#[non_exhaustive]` precisely so a knob added upstream is not a compile break here (one has
    // already *left* it: proxy trust moved to the `resolve_real_ip` layer below, where a request-level
    // concern belongs). The login route counts the very address that layer resolved, which is what our
    // own surfaces pass too — so one client's failures land on one row whichever surface they came from.
    let lockout = Lockout::default()
        .accounts(cfg.username_lockout_after, cfg.username_lockout_duration.as_secs() as i64)
        .addresses(cfg.ip_lockout_after, cfg.ip_lockout_duration.as_secs() as i64)
        // Never locked out (empty by default): the office range, a monitoring probe, the NAT a fleet
        // shares — a locked address turns away the valid callers behind it too.
        .whitelist(relativelylight::net::parse_nets(&cfg.ip_lockout_whitelist));
    let auth = Auth::new(db.clone(), lockout.clone())
        .secure_cookies(secure)
        .admin_group(ADMIN_GROUP)
        .cookie_name(SESSION_COOKIE)
        .csrf_cookie_name(CSRF_COOKIE)
        .totp_issuer("teleddns")
        // Idle sessions expire inside the (unchanged) 7-day absolute lifetime: a console left open on
        // an unattended desk stops being a live credential. `0` in the config turns the clock off.
        .session_idle_secs(cfg.session_idle_timeout.as_secs() as i64)
        // Screen a *typed* password on the profile + manager pages. The admin user form is a separate
        // wiring off the same config value (`web::build_engine`) — skip either and it becomes the way
        // around the other. `admin reset-password` is deliberately unaffected.
        .password_policy(cfg.password_policy())
        // Render the CSRF refusal in our own page shell rather than the library's bare page — an
        // operator who left a login form open overnight should land somewhere that looks like teleddns.
        .csrf_rejection(crate::web::csrf_rejected)
        .on_write(audit.clone()) // audit auth-table changes (password change, manager reset)
        .login_shell(move |form| crate::web::login_shell(form, &sso_buttons))
        .profile_shell(crate::web::profile_shell)
        // Our own section on the profile page: the caller's API keys. 0.3 hands the hook the
        // request's CSRF token alongside the identity, which is what lets the section hold real
        // forms rendered complete — no script fills them in afterwards.
        .profile_extra(move |s| {
            let db = extra_db.clone();
            async move { crate::keys::section(&db, &s).await }
        });
    // OIDC single sign-on (optional): built from config, routes merged below.
    let sso = crate::sso::build(&cfg, &auth);
    if let Some(s) = &sso {
        tracing::info!(providers = s.buttons().len(), "OIDC SSO enabled");
    }

    let engine = Arc::new(crate::web::build_engine(
        db.clone(),
        &auth,
        audit.clone(),
        cfg.default_ttl,
        cfg.password_policy(),
    ));

    // The OpenAPI document describes the three APIs this app publishes — the native JSON API, the
    // Cloudflare facade and DDNS — and nothing else. There used to be a fourth, auto-generated from
    // the crud engine, that existed only to feed the console's JavaScript; the console is
    // server-rendered now, so that surface and its generator are both gone.
    let openapi = crate::api::openapi::document(env!("CARGO_PKG_VERSION"));

    // Handles on those same counters for the DDNS/API/CF credential checks (see `principal`): one
    // account has one budget whether it is guessed at on the console or on the DDNS endpoint.
    let usernames = auth.username_lockout();
    let ips = auth.ip_lockout();
    tracing::info!(
        username_after = lockout.username_after,
        username_duration = lockout.username_duration_secs,
        ip_after = lockout.ip_after,
        ip_duration = lockout.ip_duration_secs,
        trust_proxy = cfg.trust_proxy,
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
        auth.clone(), // the worker also runs the auth housekeeping (sessions + lockout rows)
    );
    tracing::info!(backend = backend.name(), "backend sync worker started");

    let ip_src_allowed = Arc::new(relativelylight::net::parse_nets(&cfg.ip_src_allowed));
    let ops_ip_src_allowed = Arc::new(relativelylight::net::parse_nets(&cfg.ops_ip_src_allowed));
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
        ip_src_allowed,
        ops_ip_src_allowed,
    };

    // dyndns2 documents the parameters in the query string and prefers GET, but permits POST; any
    // other method falls through to `badagent`.
    let ddns = get(crate::ddns::update)
        .post(crate::ddns::update)
        .fallback(crate::ddns::reject_method);
    let app = Router::new()
        // The dashboard, and the console: one pair of handlers for every entity, the path saying
        // which one (`Admin::base("/admin")`). A GET renders, a POST on the same path writes.
        .route("/", get(crate::web::dashboard::page))
        .route("/admin", get(|| async { Redirect::permanent(crate::web::FIRST_ENTITY) }))
        .route(
            "/admin/{entity}",
            get(crate::web::admin_show).post(crate::web::admin_save),
        )
        // Where the navbar's timezone picker posts: sets the cookie the server formats with.
        .route("/tz", axum::routing::post(crate::web::set_tz))
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
        .merge(auth.routes());
    // Merge the SSO login/callback routes (their own state) when configured.
    let app = match &sso {
        Some(s) => app.merge(s.routes()),
        None => app,
    };
    let app =
        app.layer(axum::middleware::from_fn_with_state(state.clone(), crate::net::allow_from));
    // One access-log line per request (denials from the admission list included), so it wraps it.
    let app = app.layer(axum::middleware::from_fn(crate::net::access_log));
    // **Outermost, and mandatory**: resolve who is calling, once, into a `RealIp` extension. Everything
    // downstream reads that one value — the admission list, the access log, relativelylight's login
    // lockout, our own credential checks, the audit rows — so a log line and the event it describes can
    // never name different clients. This is also the single place proxy trust is decided; a request
    // whose address cannot be established at all gets a `500` here, never a guess. `Router::layer`
    // wraps, so the layer added last runs first.
    let app = app.layer(axum::middleware::from_fn_with_state(
        relativelylight::middleware::TrustProxy(state.cfg.trust_proxy),
        relativelylight::middleware::resolve_real_ip,
    ));

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
/// password once. Audited (`source: startup`) like every other account creation — the very first
/// administrator is exactly the one whose provenance an auditor will ask about.
async fn seed_admin(
    db: &DatabaseConnection,
    audit: &crate::audit::Audit,
) -> Result<(), Box<dyn std::error::Error>> {
    let count = relativelylight::auth::user::Entity::find().count(db).await?;
    if count > 0 {
        return Ok(());
    }
    let pw = random_password();
    auth::make_admin(db, ADMIN_GROUP, "admin", &pw).await?;
    tracing::warn!(username = "admin", password = %pw, "seeded initial admin user");
    audit
        .record_local(
            "startup",
            "create",
            user_target(db, "admin").await,
            None,
            Some(serde_json::json!({ "username": "admin", "group": ADMIN_GROUP, "seeded": true })),
        )
        .await;
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
    // Audited only on success: an unknown username (or an SSO account refusing the reset) returns
    // above and changed nothing. Break-glass in particular is the one command that can hand somebody
    // the console past 2FA — the log is where that shows up afterwards. Never the password itself.
    let audit = crate::audit::Audit::new(db.clone(), SESSION_COOKIE);
    audit
        .record_local(
            "cli",
            "update",
            user_target(&db, username).await,
            None,
            Some(serde_json::json!({
                "username": username,
                "password_reset": true,
                "break_glass": break_glass,
                // What --break-glass additionally did, spelled out: these are the account states an
                // auditor would otherwise have to infer from the flag.
                "totp_cleared": break_glass,
                "reactivated": break_glass,
                "admin_group": break_glass,
            })),
        )
        .await;
    Ok(())
}

/// `auth_user/{id}` for a username, so a CLI row addresses the account the same way an admin-console
/// row does. Falls back to the name when the id can't be read — a target that is slightly off beats an
/// audit row that isn't written.
async fn user_target(db: &DatabaseConnection, username: &str) -> String {
    use sea_orm::{ColumnTrait, QueryFilter};
    let found = relativelylight::auth::user::Entity::find()
        .filter(relativelylight::auth::user::Column::Username.eq(username))
        .one(db)
        .await;
    match found {
        Ok(Some(u)) => format!("auth_user/{}", u.id),
        _ => format!("auth_user/{username}"),
    }
}
