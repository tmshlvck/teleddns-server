//! Self-service API-key (bearer token) management. This is the teleddns-owned component that
//! `relativelylight`'s profile page composes in below password + 2FA (via `Auth::profile_extra`):
//! [`section`] renders the card, and the mint/revoke form posts land on `/keys` + `/keys/{id}/revoke`
//! and return to `/profile`. A user lists/mints/revokes their **own** keys. Only the SHA-256 hash is
//! stored; the raw key is shown once, on the mint confirmation page.
//!
//! **A key carries no rights of its own** — it is its owner (`authz`): the same grants, resolved on
//! every request, so deleting a grant or deactivating the account disarms it at once. There is nothing
//! to choose at mint time beyond a label and an optional expiry. To give a device *narrower* access than
//! its human owner, give the device its own account with the grant it needs and let it hold a key of
//! that account — the scope then lives in the grants table, where it is visible and revocable on its
//! own, and the audit log names the device rather than a person.
//!
//! Both posts are **cookie-authenticated**, so both carry relativelylight's double-submit CSRF token
//! (`relativelylight::csrf`), exactly as the library's own password/2FA forms do. Since 0.3 the token
//! is handed to us with the identity (`ProfileSection::csrf`), so the forms are rendered complete,
//! server-side — the script that used to copy the cookie into them on load is gone.

use crate::app::AppState;
use crate::model::{api_key, now};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use rand::Rng;
use relativelylight::auth::ProfileSection;
use relativelylight::crud::ui::esc_str;
use relativelylight::csrf::Csrf;
use relativelylight::middleware::RealIp;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder};
use serde::Deserialize;
use serde_json::json;

/// Render the API-keys card (mint form + list + revoke buttons) for the caller. Returned as an HTML
/// fragment so the profile page (relativelylight) can append it below password/2FA.
pub async fn section(db: &DatabaseConnection, s: &ProfileSection) -> String {
    let user_id = s.who.id.parse::<i32>().unwrap_or(0);
    let keys = api_key::Entity::find()
        .filter(api_key::Column::UserId.eq(user_id))
        .order_by_desc(api_key::Column::Id)
        .all(db)
        .await
        .unwrap_or_default();
    render_card(&keys, &s.csrf)
}

#[derive(Deserialize)]
pub struct MintForm {
    pub name: String,
    /// Days until the key expires; blank (the form's default) means never. Kept as a string because
    /// an empty `<input type=number>` posts `expires_days=`, which is not an integer.
    #[serde(default)]
    pub expires_days: Option<String>,
    #[serde(default, rename = "_csrf")]
    pub csrf: Option<String>,
}

/// A post that carries nothing but the CSRF token (the revoke buttons).
#[derive(Deserialize)]
pub struct CsrfForm {
    #[serde(default, rename = "_csrf")]
    pub csrf: Option<String>,
}

/// POST /keys — mint a key, then show a one-time confirmation page with the raw value.
pub async fn mint(
    headers: HeaderMap,
    State(app): State<AppState>,
    RealIp(ip): RealIp,
    Form(f): Form<MintForm>,
) -> Response {
    let who = match signed_in(&app, &headers, f.csrf.as_deref()).await {
        Ok(who) => who,
        Err(r) => return r,
    };
    // Bound the label (own key, HTML-escaped on display, but keep it sane). Empty → a default below.
    let name = f.name.trim();
    if name.chars().count() > 128 {
        return (StatusCode::BAD_REQUEST, "key label too long (max 128 characters)").into_response();
    }
    let name = if name.is_empty() { "key".to_string() } else { name.to_string() };

    let expires_at = match f.expires_days.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => None, // blank = never
        Some(s) => match s.parse::<i64>() {
            Ok(d) if d > 0 => Some(now() + d * 86400),
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    "expiry must be a positive number of days (or blank for never)",
                )
                    .into_response()
            }
        },
    };

    let raw = gen_token();
    let am = api_key::ActiveModel {
        id: sea_orm::ActiveValue::NotSet,
        user_id: sea_orm::ActiveValue::Set(who.user_id),
        name: sea_orm::ActiveValue::Set(name),
        hashed_key: sea_orm::ActiveValue::Set(crate::principal::hash_key(&raw)),
        prefix: sea_orm::ActiveValue::Set(raw.chars().take(12).collect()),
        expires_at: sea_orm::ActiveValue::Set(expires_at),
        last_used_at: sea_orm::ActiveValue::Set(None),
        disabled: sea_orm::ActiveValue::Set(false),
    };
    let key = match am.insert(&app.db).await {
        Ok(k) => k,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "could not mint key").into_response(),
    };
    tracing::info!(actor = %who.username, "minted API key");
    // A minted key is a new credential for the account — audited like any other write. The `after`
    // carries the label, the display prefix and the expiry, never the key or its hash: the audit table
    // is readable in the console, and a credential in it would be a credential leak.
    app.audit
        .record(
            "keys",
            "create",
            format!("api_key/{}", key.id),
            &who,
            "session",
            ip,
            None,
            Some(json!({ "name": key.name, "prefix": key.prefix, "expires_at": key.expires_at })),
        )
        .await;

    // Show the raw key once, then send the user back to their profile.
    crate::web::notice(
        "API key created — teleddns",
        &who.username,
        &format!(
            r#"<h1 class="h5">API key created</h1>
<div class="alert alert-success mt-3"><strong>Copy it now — it is shown only once:</strong>
<pre class="mb-0 mt-2"><code>{}</code></pre></div>
<a class="btn btn-primary" href="/profile">Back to profile</a>"#,
            esc_str(&raw)
        ),
    )
}

/// POST /keys/{id}/revoke — delete one of the caller's own keys, then return to the profile.
pub async fn revoke(
    headers: HeaderMap,
    State(app): State<AppState>,
    Path(id): Path<i32>,
    RealIp(ip): RealIp,
    Form(f): Form<CsrfForm>,
) -> Response {
    let who = match signed_in(&app, &headers, f.csrf.as_deref()).await {
        Ok(who) => who,
        Err(r) => return r,
    };
    // Read the row first, so the audit `before` can describe what was revoked (a delete_many reports a
    // count, not a row) — and so a request naming somebody else's key audits nothing at all.
    let existing = api_key::Entity::find_by_id(id)
        .filter(api_key::Column::UserId.eq(who.user_id))
        .one(&app.db)
        .await
        .ok()
        .flatten();
    // Only delete a key the caller owns.
    let _ = api_key::Entity::delete_many()
        .filter(api_key::Column::Id.eq(id))
        .filter(api_key::Column::UserId.eq(who.user_id))
        .exec(&app.db)
        .await;
    if let Some(k) = existing {
        app.audit
            .record(
                "keys",
                "delete",
                format!("api_key/{}", k.id),
                &who,
                "session",
                ip,
                Some(json!({ "name": k.name, "prefix": k.prefix, "expires_at": k.expires_at })),
                None,
            )
            .await;
    }
    Redirect::to("/profile").into_response()
}

/// Resolve the caller from their session **and** verify the double-submit CSRF token, which every
/// cookie-authenticated post must carry. A stale token renders the same refusal relativelylight
/// shows for its own forms, so an operator meets one page for it wherever it happens.
async fn signed_in(
    app: &AppState,
    headers: &HeaderMap,
    token: Option<&str>,
) -> Result<crate::principal::Principal, Response> {
    let Ok(Some(who)) = crate::principal::from_session(&app.auth, &app.db, headers).await else {
        return Err(Redirect::to(app.auth.login_path()).into_response());
    };
    if !app.auth.csrf().verify(headers, token) {
        tracing::warn!("rejected an API-key form post with a missing or invalid CSRF token");
        return Err(crate::web::csrf_rejected());
    }
    Ok(who)
}

fn gen_token() -> String {
    let mut rng = rand::thread_rng();
    let body: String = (0..40).map(|_| rng.sample(rand::distributions::Alphanumeric) as char).collect();
    format!("tddns_{body}")
}

/// The card fragment (no page shell) — embedded on the profile page. `csrf` is *this request's*
/// token: the hook is handed it precisely so the section can contain real forms.
fn render_card(keys: &[api_key::Model], csrf: &str) -> String {
    let token = Csrf::hidden_input(csrf);
    let rows: String = keys
        .iter()
        .map(|k| {
            format!(
                r#"<tr><td>{name}</td><td><code>{prefix}…</code></td><td>{exp}</td><td>{used}</td>
<td><form method="post" action="/keys/{id}/revoke" onsubmit="return confirm('Revoke this key?')">
{token}<button class="btn btn-sm btn-outline-danger">Revoke</button></form></td></tr>"#,
                name = esc_str(&k.name),
                prefix = esc_str(&k.prefix),
                exp = k.expires_at.map(|e| e.to_string()).unwrap_or_else(|| "never".into()),
                used = k.last_used_at.map(|e| e.to_string()).unwrap_or_else(|| "never".into()),
                id = k.id,
            )
        })
        .collect();
    let rows = if rows.is_empty() {
        r#"<tr><td colspan="5" class="text-muted">No keys yet.</td></tr>"#.to_string()
    } else {
        rows
    };

    format!(
        r#"<hr class="my-4">
<h2 class="h5">API keys</h2>
<p class="text-muted">Bearer tokens for the DDNS endpoint and the management APIs. A key acts as
<em>you</em> — the same zones and records you may manage, checked on every request — so revoke it here if
a device is lost. The raw key is shown once, when created.</p>
<form method="post" action="/keys" class="row g-2 align-items-end">
{token}
<div class="col-auto"><label class="form-label">Name</label>
<input class="form-control" name="name" placeholder="router at home"></div>
<div class="col-auto"><label class="form-label">Expires (days, blank = never)</label>
<input class="form-control" name="expires_days" type="number" min="1"></div>
<div class="col-auto"><button class="btn btn-primary">Mint key</button></div>
</form>
<table class="table table-sm align-middle mt-3"><thead><tr>
<th>Name</th><th>Prefix</th><th>Expires</th><th>Last used</th><th></th></tr></thead>
<tbody>{rows}</tbody></table>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: i32) -> api_key::Model {
        api_key::Model {
            id,
            user_id: 1,
            name: "router".into(),
            hashed_key: "deadbeef".into(),
            prefix: "tddns_abcdef".into(),
            expires_at: None,
            last_used_at: None,
            disabled: false,
        }
    }

    /// Every form in the card must carry the request's CSRF token, rendered *into* it — the posts
    /// are refused without one, and since 0.3 there is no script to fill it in afterwards.
    #[test]
    fn every_form_carries_the_request_s_csrf_token() {
        let html = render_card(&[key(1), key(2)], "tok3n");
        assert_eq!(html.matches(r#"<form method="post""#).count(), 3); // 1 mint + 2 revoke
        assert_eq!(html.matches(r#"name="_csrf" value="tok3n""#).count(), 3);
        assert!(!html.contains("<script"), "the card ships no JavaScript: {html}");
    }

    /// Every user can mint: a key is only ever its owner, so one held by a user with no grants can do
    /// nothing — and starts working by itself if they are later granted something.
    #[test]
    fn the_card_offers_a_mint_form_and_a_revoke_form_per_key() {
        let html = render_card(&[key(1)], "t");
        assert!(html.contains(r#"action="/keys""#), "mint form");
        assert!(html.contains(r#"action="/keys/1/revoke""#));
        assert!(!html.to_lowercase().contains("level"), "no level anywhere: {html}");
    }
}
