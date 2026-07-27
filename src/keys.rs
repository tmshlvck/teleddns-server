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
//! (`relativelylight::csrf`), exactly as the library's own password/2FA forms do. The token can't be
//! rendered server-side here — `Auth::profile_extra` hands us the identity, not the request — so the
//! forms declare `data-csrf` and [`CSRF_SCRIPT`] copies the (deliberately JS-readable) token cookie
//! into their hidden `_csrf` field on load. The handlers verify it before doing anything.

use crate::app::AppState;
use crate::model::{api_key, now};
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use rand::Rng;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder};
use serde::Deserialize;

/// Render the API-keys card (mint form + list + revoke buttons) for one user. Returned as an HTML
/// fragment so the profile page (relativelylight) can append it below password/2FA.
pub async fn section(db: &DatabaseConnection, user_id: i32) -> String {
    let keys = api_key::Entity::find()
        .filter(api_key::Column::UserId.eq(user_id))
        .order_by_desc(api_key::Column::Id)
        .all(db)
        .await
        .unwrap_or_default();
    render_card(&keys)
}

#[derive(Deserialize)]
pub struct MintForm {
    pub name: String,
    /// Days until the key expires; blank (the form's default) means never. Kept as a string because
    /// an empty `<input type=number>` posts `expires_days=`, which is not an integer.
    #[serde(default)]
    pub expires_days: Option<String>,
    /// The double-submit CSRF token (filled in by [`CSRF_SCRIPT`]).
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
pub async fn mint(headers: HeaderMap, State(app): State<AppState>, Form(f): Form<MintForm>) -> Response {
    let Some(who) = signed_in(&app, &headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    if let Some(r) = csrf_rejected(&app, &headers, f.csrf.as_deref()) {
        return r;
    }
    // Bound the label (own key, HTML-escaped on display, but keep it sane). Empty → a default below.
    let name = f.name.trim();
    if name.chars().count() > 128 {
        return (axum::http::StatusCode::BAD_REQUEST, "key label too long (max 128 characters)")
            .into_response();
    }
    let name = if name.is_empty() { "key".to_string() } else { name.to_string() };

    let raw = gen_token();
    let hashed = crate::principal::hash_key(&raw);
    let prefix = raw.chars().take(12).collect::<String>();
    let expires_at = match f.expires_days.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => None, // blank = never
        Some(s) => match s.parse::<i64>() {
            Ok(d) if d > 0 => Some(now() + d * 86400),
            _ => {
                return (
                    axum::http::StatusCode::BAD_REQUEST,
                    "expiry must be a positive number of days (or blank for never)",
                )
                    .into_response()
            }
        },
    };

    let am = api_key::ActiveModel {
        id: sea_orm::ActiveValue::NotSet,
        user_id: sea_orm::ActiveValue::Set(who.user_id),
        name: sea_orm::ActiveValue::Set(name),
        hashed_key: sea_orm::ActiveValue::Set(hashed),
        prefix: sea_orm::ActiveValue::Set(prefix),
        expires_at: sea_orm::ActiveValue::Set(expires_at),
        last_used_at: sea_orm::ActiveValue::Set(None),
        disabled: sea_orm::ActiveValue::Set(false),
    };
    if am.insert(&app.db).await.is_err() {
        return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "could not mint key").into_response();
    }
    tracing::info!(actor = %who.username, "minted API key");

    // Show the raw key once, then send the user back to their profile.
    let body = format!(
        r#"<div class="card shadow-sm mx-auto mt-4" style="max-width:36rem"><div class="card-body">
<h1 class="h5">API key created</h1>
<div class="alert alert-success mt-3"><strong>Copy it now — it is shown only once:</strong>
<pre class="mb-0 mt-2"><code>{}</code></pre></div>
<a class="btn btn-primary" href="/profile">Back to profile</a></div></div>"#,
        html_escape(&raw)
    );
    Html(crate::web::shell("API key created — teleddns", &who.username, &body)).into_response()
}

/// POST /keys/{id}/revoke — delete one of the caller's own keys, then return to the profile.
pub async fn revoke(
    headers: HeaderMap,
    State(app): State<AppState>,
    Path(id): Path<i32>,
    Form(f): Form<CsrfForm>,
) -> Response {
    let Some(who) = signed_in(&app, &headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    if let Some(r) = csrf_rejected(&app, &headers, f.csrf.as_deref()) {
        return r;
    }
    // Only delete a key the caller owns.
    let _ = api_key::Entity::delete_many()
        .filter(api_key::Column::Id.eq(id))
        .filter(api_key::Column::UserId.eq(who.user_id))
        .exec(&app.db)
        .await;
    Redirect::to("/profile").into_response()
}

async fn signed_in(app: &AppState, headers: &HeaderMap) -> Option<crate::principal::Principal> {
    crate::principal::from_session(&app.auth, &app.db, headers).await.ok().flatten()
}

/// Verify the double-submit CSRF token on a cookie-authenticated post; `Some(response)` is the 403 to
/// return when it doesn't check out.
fn csrf_rejected(app: &AppState, headers: &HeaderMap, token: Option<&str>) -> Option<Response> {
    if app.auth.csrf().verify(headers, token) {
        return None;
    }
    tracing::warn!("rejected an API-key form post with a missing or invalid CSRF token");
    Some(
        (axum::http::StatusCode::FORBIDDEN, "CSRF token missing or invalid — reload /profile")
            .into_response(),
    )
}

/// Copies the CSRF token cookie into the hidden `_csrf` field of every `form[data-csrf]` in the
/// fragment. The cookie is not `HttpOnly` by design (it is not a credential — the point is that only
/// a same-origin page can read it); relativelylight's `crud::ui` tables do the same for their fetches.
const CSRF_SCRIPT: &str = r#"<script>
(function(){var n='{cookie}=',v='';
document.cookie.split('; ').forEach(function(c){if(c.indexOf(n)===0){v=decodeURIComponent(c.slice(n.length));}});
document.querySelectorAll('form[data-csrf] input[name="_csrf"]').forEach(function(i){i.value=v;});})();
</script>"#;

/// The hidden field `CSRF_SCRIPT` fills in.
const CSRF_INPUT: &str = r#"<input type="hidden" name="_csrf">"#;

fn gen_token() -> String {
    let mut rng = rand::thread_rng();
    let body: String = (0..40).map(|_| rng.sample(rand::distributions::Alphanumeric) as char).collect();
    format!("tddns_{body}")
}

/// The card fragment (no page shell) — embedded on the profile page.
fn render_card(keys: &[api_key::Model]) -> String {
    let mut rows = String::new();
    for k in keys {
        let exp = k.expires_at.map(|e| e.to_string()).unwrap_or_else(|| "never".into());
        let used = k.last_used_at.map(|e| e.to_string()).unwrap_or_else(|| "never".into());
        rows.push_str(&format!(
            r#"<tr><td>{name}</td><td><code>{prefix}…</code></td><td>{exp}</td><td>{used}</td>
<td><form method="post" action="/keys/{id}/revoke" data-csrf onsubmit="return confirm('Revoke this key?')">
{CSRF_INPUT}<button class="btn btn-sm btn-outline-danger">Revoke</button></form></td></tr>"#,
            name = html_escape(&k.name),
            prefix = html_escape(&k.prefix),
            id = k.id,
        ));
    }
    if rows.is_empty() {
        rows = r#"<tr><td colspan="5" class="text-muted">No keys yet.</td></tr>"#.into();
    }

    let mint_form = format!(
        r#"<form method="post" action="/keys" data-csrf class="row g-2 align-items-end">
{CSRF_INPUT}
<div class="col-auto"><label class="form-label">Name</label>
<input class="form-control" name="name" placeholder="router at home"></div>
<div class="col-auto"><label class="form-label">Expires (days, blank = never)</label>
<input class="form-control" name="expires_days" type="number" min="1"></div>
<div class="col-auto"><button class="btn btn-primary">Mint key</button></div>
</form>"#
    );

    let csrf_script = CSRF_SCRIPT.replace("{cookie}", crate::app::CSRF_COOKIE);
    format!(
        r#"<hr class="my-4">
<h2 class="h5">API keys</h2>
<p class="text-muted">Bearer tokens for the DDNS endpoint and the management APIs. A key acts as
<em>you</em> — the same zones and records you may manage, checked on every request — so revoke it here if
a device is lost. The raw key is shown once, when created.</p>
{mint_form}
<table class="table table-sm align-middle mt-3"><thead><tr>
<th>Name</th><th>Prefix</th><th>Expires</th><th>Last used</th><th></th></tr></thead>
<tbody>{rows}</tbody></table>
{csrf_script}"#
    )
}

/// Minimal HTML escaping for user-controlled strings rendered into the page.
pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
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

    /// Every form in the card must carry the hidden `_csrf` field the script fills, and the script
    /// must know the *app's* cookie name (the placeholder substituted) — else the posts 403.
    #[test]
    fn every_form_carries_the_csrf_field_and_the_script_knows_the_cookie() {
        let html = render_card(&[key(1), key(2)]);
        // 1 mint form + 2 revoke forms, each with the hidden input.
        assert_eq!(html.matches(r#"<form method="post""#).count(), 3);
        assert_eq!(html.matches(CSRF_INPUT).count(), 3);
        assert_eq!(html.matches("data-csrf").count(), 4); // the 3 forms + the script's selector
        assert!(html.contains(&format!("'{}='", crate::app::CSRF_COOKIE)), "cookie name: {html}");
        assert!(!html.contains("{cookie}"), "the placeholder must be substituted");
    }

    /// Every user can mint: a key is only ever its owner, so one held by a user with no grants can do
    /// nothing — and starts working by itself if they are later granted something.
    #[test]
    fn the_card_offers_a_mint_form_and_a_revoke_form_per_key() {
        let html = render_card(&[key(1)]);
        assert!(html.contains(r#"action="/keys""#), "mint form");
        assert!(html.contains(r#"action="/keys/1/revoke""#));
        assert!(!html.to_lowercase().contains("level"), "no level anywhere: {html}");
    }
}
