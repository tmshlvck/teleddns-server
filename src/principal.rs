//! Resolve a request to an authenticated `Principal` with an effective *token level*. Three sources:
//! the operator session cookie (via relativelylight `auth`), HTTP Basic (DDNS only), and a Bearer API
//! key. The token level caps what the principal can do (§3); the per-target `effective_level` lookup
//! (see `authz`) does the rest.
//!
//! **Every credential check here goes through the brute-force brake** — `AppState::{usernames, ips}`,
//! which are relativelylight's own lockout counters (`auth::lockout`), not a second implementation: a
//! DDNS Basic failure and a console login failure spend the *same* account budget, and deleting that
//! one row in the admin panel unlocks both. A locked account or source address is refused with
//! [`AuthError::Locked`] *before* the secret is looked at; a checked-and-rejected credential is recorded
//! here and only here (with its metric) — don't re-count at the call site.

use crate::app::AppState;
use crate::authz::Level;
use crate::model::{api_key, now};
use axum::http::HeaderMap;
use relativelylight::auth::{self, Auth};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter,
};
use sha2::{Digest, Sha256};
use std::net::IpAddr;

/// Where the request came from (for audit + metrics labels).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Ddns,
    Api,
    Cfapi,
    Ui,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Ddns => "ddns",
            Source::Api => "api",
            Source::Cfapi => "cfapi",
            Source::Ui => "ui",
        }
    }
}

/// An authenticated caller and the level their credential carries.
#[derive(Clone, Debug)]
pub struct Principal {
    pub user_id: i32,
    pub username: String,
    pub group_ids: Vec<i32>,
    /// Group names the caller belongs to (kept for audit/diagnostics; admin status is `is_admin`).
    #[allow(dead_code)]
    pub group_names: Vec<String>,
    pub is_admin: bool,
    /// The credential's own level cap: L3 for a session/Basic login, the key's level for a token.
    pub token_level: Level,
    pub source: Source,
    /// The API-key id, when authenticated by a token (for audit).
    pub key_id: Option<i32>,
}

/// Why an authentication attempt failed (maps to the surface's error vocabulary).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthError {
    /// No/invalid credentials.
    BadAuth,
    /// A 2FA/SSO user tried HTTP Basic (must use a token).
    BasicNotAllowed,
    /// Too many recent failures for this account or source address; retry after N seconds. The
    /// credential was **not** checked.
    Locked(i64),
    /// The credential could not be checked (database error) — never a statement about the credential.
    Internal,
}

/// SHA-256 hex of a raw API key.
pub fn hash_key(raw: &str) -> String {
    let mut h = Sha256::new();
    h.update(raw.as_bytes());
    hex::encode(h.finalize())
}

/// Resolve from the operator session cookie (token level = L3, capped by effective access).
pub async fn from_session(
    auth: &Auth,
    db: &DatabaseConnection,
    headers: &HeaderMap,
) -> Result<Option<Principal>, DbErr> {
    let Some(id) = auth.identify(headers).await else {
        return Ok(None);
    };
    let user_id: i32 = id.id.parse().unwrap_or(0);
    let (group_ids, group_names, is_admin) = crate::authz::user_groups(db, user_id).await?;
    Ok(Some(Principal {
        user_id,
        username: id.username,
        group_ids,
        group_names,
        is_admin,
        token_level: Level::L3,
        source: Source::Ui,
        key_id: None,
    }))
}

/// Resolve from an `Authorization` header (Bearer only), for a given source surface. A request with
/// no bearer token at all is `BadAuth` **without** being recorded as a failed attempt — there was no
/// credential to check, and counting anonymous traffic would let a bot lock out everyone sharing its
/// address.
pub async fn from_bearer(
    app: &AppState,
    ip: Option<IpAddr>,
    headers: &HeaderMap,
    source: Source,
) -> Result<Principal, AuthError> {
    let Some(token) = bearer_token(headers) else {
        return Err(AuthError::BadAuth);
    };
    from_token(app, ip, &token, source).await
}

/// Resolve a raw token string (used by Bearer and the CF `X-Auth-Key` header), rate-limited per
/// source address: a bearer token carries no account name, so the source is the only thing a failure
/// can be counted against.
pub async fn from_token(
    app: &AppState,
    ip: Option<IpAddr>,
    token: &str,
    source: Source,
) -> Result<Principal, AuthError> {
    // A token names no account, so the source address is the only thing to key on.
    if let Some(retry) = app.ips.locked(ip).await {
        return Err(locked(app, source, retry));
    }
    match principal_for_token(&app.db, token, source).await {
        Ok(Some(p)) => Ok(p),
        Ok(None) => Err(rejected(app, source, ip, None, "bad_token").await),
        Err(e) => {
            tracing::error!(surface = source.as_str(), error = %e, "could not check the API key");
            app.metrics.auth_failure(source.as_str(), "error");
            Err(AuthError::Internal)
        }
    }
}

/// Look a raw token up, ignoring the attempt limiter — the plain DB lookup behind [`from_token`].
async fn principal_for_token(
    db: &DatabaseConnection,
    token: &str,
    source: Source,
) -> Result<Option<Principal>, DbErr> {
    let hashed = hash_key(token);
    let Some(key) = api_key::Entity::find()
        .filter(api_key::Column::HashedKey.eq(hashed))
        .one(db)
        .await?
    else {
        return Ok(None);
    };
    if key.disabled {
        return Ok(None);
    }
    if let Some(exp) = key.expires_at {
        if exp <= now() {
            return Ok(None);
        }
    }
    // Bump last_used_at (best-effort).
    let mut am: api_key::ActiveModel = key.clone().into();
    am.last_used_at = sea_orm::ActiveValue::Set(Some(now()));
    let _ = am.update(db).await;

    let user = match auth::user::Entity::find_by_id(key.user_id).one(db).await? {
        Some(u) if u.is_active => u,
        _ => return Ok(None),
    };
    let (group_ids, group_names, is_admin) = crate::authz::user_groups(db, key.user_id).await?;
    Ok(Some(Principal {
        user_id: key.user_id,
        username: user.username,
        group_ids,
        group_names,
        is_admin,
        token_level: Level::from_i32(key.level),
        source,
        key_id: Some(key.id),
    }))
}

/// Resolve from HTTP Basic credentials (DDNS only). Rejects users with any strong factor (TOTP or
/// SSO) — they must use a token. Token level = L3, capped by effective access.
///
/// This is the one surface where a *password* is guessable, so it is limited per account as well as
/// per source address: while either is locked the argon2 verification is never run.
pub async fn from_basic(
    app: &AppState,
    ip: Option<IpAddr>,
    username: &str,
    password: &str,
) -> Result<Principal, AuthError> {
    if let Some(retry) = locked_for(app, username, ip).await {
        return Err(locked(app, Source::Ddns, retry));
    }
    let user = match auth::user::Entity::find()
        .filter(auth::user::Column::Username.eq(username))
        .one(&app.db)
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            return Err(rejected(app, Source::Ddns, ip, Some(username), "no_such_user").await)
        }
        Err(e) => {
            tracing::error!(error = %e, "could not check Basic credentials");
            app.metrics.auth_failure("ddns", "error");
            return Err(AuthError::Internal);
        }
    };
    if !user.is_active {
        return Err(rejected(app, Source::Ddns, ip, Some(username), "inactive").await);
    }
    // A user with 2FA enrolled or an external (SSO) account may not use Basic — the password either
    // isn't the whole credential or isn't ours to check. A *blank* TOTP secret is no second factor
    // (`has_totp`), so it must not lock the account out of DDNS either.
    if user.has_totp() || user.is_sso() {
        return Err(AuthError::BasicNotAllowed);
    }
    if !auth::verify_password(&user.password_hash, password) {
        return Err(rejected(app, Source::Ddns, ip, Some(username), "bad_password").await);
    }
    let (group_ids, group_names, is_admin) = crate::authz::user_groups(&app.db, user.id)
        .await
        .map_err(|_| AuthError::Internal)?;
    // A good password clears the account's failures — including any it collected on the console login
    // form (one row). The source's are deliberately kept: one valid credential shouldn't refund a
    // spraying address's budget.
    app.usernames.clear(username).await;
    Ok(Principal {
        user_id: user.id,
        username: user.username,
        group_ids,
        group_names,
        is_admin,
        token_level: Level::L3,
        source: Source::Ddns,
        key_id: None,
    })
}

/// The longer of the account's and the address's remaining lockout, if either is locked.
async fn locked_for(app: &AppState, username: &str, ip: Option<IpAddr>) -> Option<i64> {
    match (app.usernames.locked(username).await, app.ips.locked(ip).await) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    }
}

/// Record a checked-and-rejected credential: count it, meter it, and warn once if that failure is what
/// locked the account/source out. Returns the error to hand back.
async fn rejected(
    app: &AppState,
    source: Source,
    ip: Option<IpAddr>,
    username: Option<&str>,
    reason: &str,
) -> AuthError {
    let by_user = match username {
        Some(u) => app.usernames.record_failure(u).await,
        None => false,
    };
    if app.ips.record_failure(ip).await || by_user {
        tracing::warn!(
            surface = source.as_str(),
            user = username.unwrap_or("-"),
            src = %ip.map(|i| i.to_string()).unwrap_or_else(|| "-".into()),
            "too many failed credential checks — locked out for now"
        );
    }
    app.metrics.auth_failure(source.as_str(), reason);
    AuthError::BadAuth
}

/// A credential refused without being checked, because its account or source is locked out.
fn locked(app: &AppState, source: Source, retry: i64) -> AuthError {
    tracing::debug!(surface = source.as_str(), retry, "credential check refused: locked out");
    app.metrics.auth_failure(source.as_str(), "locked");
    AuthError::Locked(retry)
}

/// Extract a Bearer token from the `Authorization` header.
pub fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let v = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    v.strip_prefix("Bearer ").map(|s| s.trim().to_string())
}

/// Extract HTTP Basic credentials from the `Authorization` header.
pub fn basic_creds(headers: &HeaderMap) -> Option<(String, String)> {
    use base64::Engine;
    let v = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    let b64 = v.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(b64.trim()).ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let (u, p) = s.split_once(':')?;
    Some((u.to_string(), p.to_string()))
}
