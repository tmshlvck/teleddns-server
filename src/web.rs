//! The operator web console: a relativelylight `crud::ui::Admin` panel over our entities, plus the
//! app-owned page shell, login/profile styling, and the home/docs handlers. The full console is
//! L3-gated (admin group); non-admin users act through the DDNS/API surfaces and the profile page.

use crate::app::AppState;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use relativelylight::auth::{AdminOnly, Auth, Identity};
use relativelylight::crud::engine::Engine;
use relativelylight::crud::seaorm::{Crud, MetaModel};
use relativelylight::crud::ui::Admin;
use sea_orm::DatabaseConnection;
use std::sync::Arc;

/// Build the CRUD engine over every managed entity, all gated admin-only (L3).
pub fn build_engine(db: DatabaseConnection, auth: &Auth) -> Engine {
    let gate = Arc::new(AdminOnly::new(auth, ["admin"]));
    let mut crud = Crud::new(db, "/admin/api");

    // Zone.
    let mut z = MetaModel::new(crate::model::zone::Entity);
    z.field("origin").label = Some("Origin".into());
    z.field("origin").description = Some("FQDN with trailing dot, e.g. example.com.".into());
    z.row_label = Box::new(|row| row["origin"].as_str().unwrap_or_default().to_string());
    crud.register(z, gate.clone());

    // One RR table per type. Slug defaults from the table name (`rr_a`, `rr_aaaa`, …).
    use crate::model::rr;
    macro_rules! reg_rr {
        ($ent:path) => {{
            let mm = MetaModel::new($ent);
            crud.register(mm, gate.clone());
        }};
    }
    reg_rr!(rr::a::Entity);
    reg_rr!(rr::aaaa::Entity);
    reg_rr!(rr::ns::Entity);
    reg_rr!(rr::ptr::Entity);
    reg_rr!(rr::cname::Entity);
    reg_rr!(rr::txt::Entity);
    reg_rr!(rr::mx::Entity);
    reg_rr!(rr::srv::Entity);
    reg_rr!(rr::caa::Entity);
    reg_rr!(rr::sshfp::Entity);
    reg_rr!(rr::tlsa::Entity);
    reg_rr!(rr::dnskey::Entity);
    reg_rr!(rr::ds::Entity);
    reg_rr!(rr::naptr::Entity);

    // API keys: minted from the profile page; here shown read-mostly (never expose the hash).
    let mut apikey = MetaModel::new(crate::model::api_key::Entity);
    apikey.field("hashed_key").hidden = true;
    crud.register(apikey, gate.clone());

    crud.register(MetaModel::new(crate::model::zone_role::Entity), gate.clone());
    crud.register(MetaModel::new(crate::model::rr_role::Entity), gate.clone());

    // Auth accounts + groups (admin-only, read included).
    let mut user = MetaModel::new(relativelylight::auth::user::Entity);
    user.field("password_hash").password();
    user.field("totp_secret").hidden = true;
    user.field("totp_pending").hidden = true;
    user.field("is_active").default = Some(serde_json::json!(true));
    crud.register(user, gate.clone());
    crud.register(MetaModel::new(relativelylight::auth::group::Entity), gate.clone());

    crud.into_engine()
}

/// Build the admin panel fragment structure (grouped side-panel). Rendered per-request via
/// `render_for` so write controls hide for non-writers.
pub fn build_admin(engine: &Engine) -> Admin<'_> {
    let mut admin = Admin::new(engine).title("teleddns").group("DNS").entity("zone");
    for slug in [
        "rr_a", "rr_aaaa", "rr_ns", "rr_ptr", "rr_cname", "rr_txt", "rr_mx", "rr_srv", "rr_caa",
        "rr_sshfp", "rr_tlsa", "rr_dnskey", "rr_ds", "rr_naptr",
    ] {
        admin = admin.entity(slug);
    }
    admin
        .separator()
        .group("Access")
        .entity("api_key")
        .entity("zone_role")
        .entity("rr_role")
        .separator()
        .group("Accounts")
        .entity_with("rl_user", |t| t.title("Users"))
        .entity_with("rl_group", |t| t.title("Groups"))
        .separator()
        .group("Reference")
        .link("API docs", "/docs")
        .link("Profile", "/profile")
        .link("Log out", "/logout")
}

/// The app's HTML page shell (Bootstrap + Alpine — required by the crud::ui fragments).
pub fn shell(title: &str, user: &str, body: &str) -> String {
    let nav_user = if user.is_empty() {
        String::new()
    } else {
        format!(
            r#"<span class="navbar-text ms-auto">{user} · <a href="/logout">log out</a></span>"#
        )
    };
    format!(
        r#"<!doctype html><html lang="en" data-bs-theme="light"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{title}</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</head><body class="bg-body-tertiary">
<nav class="navbar bg-body border-bottom px-3"><span class="navbar-brand">teleddns</span>{nav_user}</nav>
<main class="container-fluid py-3">{body}</main></body></html>"#
    )
}

/// Home = the admin console, login-gated. Anonymous → redirect to login.
pub async fn home(headers: HeaderMap, State(app): State<AppState>) -> Response {
    let Some(who) = app.auth.identify(&headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    let body = match build_admin(&app.engine).render_for(&headers).await {
        Ok(html) => html,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    Html(shell("teleddns admin", &who.username, &body)).into_response()
}

pub async fn openapi_json(State(app): State<AppState>) -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "application/json")], app.openapi.clone())
}

pub async fn docs() -> Html<&'static str> {
    Html(
        r#"<!doctype html><html><head><meta charset="utf-8"><title>teleddns API docs</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css"></head>
<body><div id="swagger-ui"></div>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>window.onload=()=>{SwaggerUIBundle({url:'/openapi.json',dom_id:'#swagger-ui'});};</script>
</body></html>"#,
    )
}

/// App chrome around the library's login form.
pub fn login_shell(form: &str) -> String {
    let body = format!(
        r#"<div class="card shadow-sm mx-auto mt-5" style="max-width:24rem"><div class="card-body">
<h1 class="h5 mb-3">Log in</h1>{form}</div></div>"#
    );
    shell("Log in — teleddns", "", &body)
}

/// App chrome around the library's profile/password/2FA page.
pub fn profile_shell(fragment: &str, who: &Identity) -> String {
    let body = format!(
        r#"<div class="card shadow-sm mx-auto mt-4" style="max-width:36rem"><div class="card-body">{fragment}
<hr><a href="/">&larr; Back to admin</a></div></div>"#
    );
    shell("Profile — teleddns", &who.username, &body)
}
