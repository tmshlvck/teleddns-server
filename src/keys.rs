//! Self-service API-key (bearer token) management on the operator profile. A logged-in user lists,
//! mints, and revokes their **own** keys; the level picker is capped at their max level (L3 for
//! admins, else the highest role level they hold) and re-capped server-side. Only the SHA-256 hash is
//! stored; the raw key is shown once on mint. Plain MPA forms, no JS.

use crate::app::AppState;
use crate::authz::Level;
use crate::model::{api_key, now};
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use rand::Rng;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct PageQuery {
    /// A freshly minted raw key, shown once immediately after mint.
    pub new: Option<String>,
}

/// GET /keys — the key list + mint form. `?new=<raw>` shows a freshly minted key once.
pub async fn page(headers: HeaderMap, State(app): State<AppState>, Query(q): Query<PageQuery>) -> Response {
    let Some(who) = signed_in(&app, &headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    let max = crate::authz::user_max_level(&app.db, &who.group_ids, who.is_admin)
        .await
        .unwrap_or(Level::None);

    let keys = api_key::Entity::find()
        .filter(api_key::Column::UserId.eq(who.user_id))
        .order_by_desc(api_key::Column::Id)
        .all(&app.db)
        .await
        .unwrap_or_default();

    Html(render(&who.username, max, &keys, q.new.as_deref())).into_response()
}

#[derive(Deserialize)]
pub struct MintForm {
    pub name: String,
    pub level: i32,
    #[serde(default)]
    pub expires_days: Option<i64>,
}

/// POST /keys — mint a key. The raw value is returned once via a redirect query param.
pub async fn mint(headers: HeaderMap, State(app): State<AppState>, Form(f): Form<MintForm>) -> Response {
    let Some(who) = signed_in(&app, &headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    let max = crate::authz::user_max_level(&app.db, &who.group_ids, who.is_admin)
        .await
        .unwrap_or(Level::None);
    // Re-cap the requested level server-side.
    let level = Level::from_i32(f.level).cap(max);
    if level == Level::None {
        return (axum::http::StatusCode::FORBIDDEN, "no access level available").into_response();
    }

    let raw = gen_token();
    let hashed = crate::principal::hash_key(&raw);
    let prefix = raw.chars().take(12).collect::<String>();
    let expires_at = f.expires_days.filter(|d| *d > 0).map(|d| now() + d * 86400);

    let am = api_key::ActiveModel {
        id: sea_orm::ActiveValue::NotSet,
        user_id: sea_orm::ActiveValue::Set(who.user_id),
        name: sea_orm::ActiveValue::Set(if f.name.trim().is_empty() { "key".into() } else { f.name }),
        hashed_key: sea_orm::ActiveValue::Set(hashed),
        prefix: sea_orm::ActiveValue::Set(prefix),
        level: sea_orm::ActiveValue::Set(level.as_i32()),
        expires_at: sea_orm::ActiveValue::Set(expires_at),
        last_used_at: sea_orm::ActiveValue::Set(None),
        disabled: sea_orm::ActiveValue::Set(false),
    };
    if am.insert(&app.db).await.is_err() {
        return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "could not mint key").into_response();
    }
    tracing::info!(actor = %who.username, level = level.as_i32(), "minted API key");
    Redirect::to(&format!("/keys?new={raw}")).into_response()
}

/// POST /keys/{id}/revoke — delete one of the caller's own keys.
pub async fn revoke(headers: HeaderMap, State(app): State<AppState>, Path(id): Path<i32>) -> Response {
    let Some(who) = signed_in(&app, &headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    // Only delete a key the caller owns.
    let _ = api_key::Entity::delete_many()
        .filter(api_key::Column::Id.eq(id))
        .filter(api_key::Column::UserId.eq(who.user_id))
        .exec(&app.db)
        .await;
    Redirect::to("/keys").into_response()
}

async fn signed_in(app: &AppState, headers: &HeaderMap) -> Option<crate::principal::Principal> {
    crate::principal::from_session(&app.auth, &app.db, headers).await.ok().flatten()
}

fn gen_token() -> String {
    let mut rng = rand::thread_rng();
    let body: String = (0..40).map(|_| rng.sample(rand::distributions::Alphanumeric) as char).collect();
    format!("tddns_{body}")
}

fn render(username: &str, max: Level, keys: &[api_key::Model], newly: Option<&str>) -> String {
    let banner = match newly {
        Some(raw) => format!(
            r#"<div class="alert alert-success"><strong>New key (shown once — copy it now):</strong>
<pre class="mb-0 mt-2"><code>{}</code></pre></div>"#,
            html_escape(raw)
        ),
        None => String::new(),
    };
    let mut rows = String::new();
    for k in keys {
        let exp = k.expires_at.map(|e| e.to_string()).unwrap_or_else(|| "never".into());
        let used = k.last_used_at.map(|e| e.to_string()).unwrap_or_else(|| "never".into());
        rows.push_str(&format!(
            r#"<tr><td>{name}</td><td><code>{prefix}…</code></td><td>L{level}</td><td>{exp}</td><td>{used}</td>
<td><form method="post" action="/keys/{id}/revoke" onsubmit="return confirm('Revoke this key?')">
<button class="btn btn-sm btn-outline-danger">Revoke</button></form></td></tr>"#,
            name = html_escape(&k.name),
            prefix = html_escape(&k.prefix),
            level = k.level,
            id = k.id,
        ));
    }
    if rows.is_empty() {
        rows = r#"<tr><td colspan="6" class="text-muted">No keys yet.</td></tr>"#.into();
    }

    let level_opts: String = (1..=max.as_i32())
        .rev()
        .map(|l| format!(r#"<option value="{l}">Level {l}</option>"#))
        .collect();
    let mint_form = if max == Level::None {
        r#"<p class="text-muted">You hold no DNS access level, so you cannot mint keys.</p>"#.into()
    } else {
        format!(
            r#"<form method="post" action="/keys" class="row g-2 align-items-end">
<div class="col-auto"><label class="form-label">Name</label>
<input class="form-control" name="name" placeholder="router at home"></div>
<div class="col-auto"><label class="form-label">Level</label>
<select class="form-select" name="level">{level_opts}</select></div>
<div class="col-auto"><label class="form-label">Expires (days, blank = never)</label>
<input class="form-control" name="expires_days" type="number" min="1"></div>
<div class="col-auto"><button class="btn btn-primary">Mint key</button></div>
</form>"#
        )
    };

    let body = format!(
        r#"<div class="card shadow-sm"><div class="card-body">
<h1 class="h5">API keys</h1>
<p class="text-muted">Bearer tokens for the DDNS endpoint and the management APIs. The raw key is shown once.</p>
{banner}
{mint_form}
<hr>
<table class="table table-sm align-middle"><thead><tr>
<th>Name</th><th>Prefix</th><th>Level</th><th>Expires</th><th>Last used</th><th></th></tr></thead>
<tbody>{rows}</tbody></table>
<a href="/">&larr; Back to admin</a></div></div>"#
    );
    crate::web::shell("API keys — teleddns", username, &body)
}

/// Minimal HTML escaping for user-controlled strings rendered into the page.
pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}
