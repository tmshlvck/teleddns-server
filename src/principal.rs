//! Resolve a machine request to an authenticated `Principal`. Two sources: HTTP Basic (DDNS only) and
//! an API key (relativelylight's `Auth::identify_key` since 0.5 — the keys live in its `auth_api_key`
//! table and are minted on `/profile`). The console resolves its session with `Auth::identify`.
//!
//! **A credential carries no rights of its own** — least of all a bearer token. Whichever source
//! authenticated, the `Principal` is built from the *user*: their group memberships and their Superadmin
//! flag, read from the database on this request. What they may then do is `authz`'s two predicates over
//! the grant tables.
//!
//! **Every credential check here goes through the brute-force brake** — `AppState::{usernames, ips}`,
//! which are relativelylight's own lockout counters (`auth::lockout`), not a second implementation: a
//! DDNS Basic failure and a console login failure spend the *same* account budget, and deleting that
//! one row in the admin panel unlocks both. A locked account or source address is refused with
//! [`AuthError::Locked`] *before* the secret is looked at; a checked-and-rejected credential is recorded
//! here and only here (with its metric) — don't re-count at the call site. An API key is the one
//! credential the library brakes itself: `identify_key` checks and counts the source address on the
//! same `IpLockout`, so here it is only metered.

use crate::app::AppState;
use axum::http::HeaderMap;
use relativelylight::auth::{self, api_key::KeyError};
use sea_orm::{ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter};
use std::net::IpAddr;

/// Where the request came from (for audit + metrics labels).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Ddns,
    Api,
    Cfapi,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Ddns => "ddns",
            Source::Api => "api",
            Source::Cfapi => "cfapi",
        }
    }
}

/// An authenticated caller: who they are and what groups they hold. Nothing about *how* they
/// authenticated changes what they may do.
#[derive(Clone, Debug)]
pub struct Principal {
    pub user_id: i32,
    pub username: String,
    pub group_ids: Vec<i32>,
    /// Group names the caller belongs to (kept for audit/diagnostics; the role flag is `is_superadmin`).
    #[allow(dead_code)]
    pub group_names: Vec<String>,
    /// Membership of the `admin` group — the Superadmin role (see `authz`).
    pub is_superadmin: bool,
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

impl Principal {
    /// The principal for user `user_id`, with their groups and Superadmin flag read **now** — whatever
    /// credential proved who they are carries no rights of its own.
    async fn of_user(
        db: &DatabaseConnection,
        user_id: i32,
        username: String,
        source: Source,
        key_id: Option<i32>,
    ) -> Result<Principal, DbErr> {
        let (group_ids, group_names, is_superadmin) = crate::authz::user_groups(db, user_id).await?;
        Ok(Principal { user_id, username, group_ids, group_names, is_superadmin, source, key_id })
    }
}

/// Resolve from an `Authorization` header (Bearer only), for a given source surface. A request with
/// no bearer token at all is `BadAuth` **without** being recorded as a failed attempt — there was no
/// credential to check, and counting anonymous traffic would let a bot lock out everyone sharing its
/// address.
pub async fn from_bearer(
    app: &AppState,
    ip: IpAddr,
    headers: &HeaderMap,
    source: Source,
) -> Result<Principal, AuthError> {
    let Some(token) = bearer_token(headers) else {
        return Err(AuthError::BadAuth);
    };
    from_token(app, ip, token, source).await
}

/// Resolve a raw token string (used by Bearer and the CF `X-Auth-Key` header). The library does the
/// lookup, the expiry/disabled/inactive-owner checks, the `last_used_at` stamp and the per-address
/// brake; what is left here is the metric and the principal.
pub async fn from_token(
    app: &AppState,
    ip: IpAddr,
    token: &str,
    source: Source,
) -> Result<Principal, AuthError> {
    let surface = source.as_str();
    let key = match app.auth.identify_key(token, ip).await {
        Ok(k) => k,
        Err(KeyError::Invalid) => {
            app.metrics.auth_failure(surface, "bad_token");
            return Err(AuthError::BadAuth);
        }
        Err(KeyError::Locked(retry)) => return Err(locked(app, source, retry)),
        Err(KeyError::Internal) => return Err(internal(app, source, "could not check the API key")),
    };
    let owner = key.identity;
    Principal::of_user(&app.db, owner.id.parse().unwrap_or(0), owner.username, source, Some(key.key_id))
        .await
        .map_err(|e| internal(app, source, &format!("could not read the key owner's groups: {e}")))
}

/// Resolve from HTTP Basic credentials (DDNS only). Rejects users with any strong factor (TOTP or
/// SSO) — they must use a token.
///
/// This is the one surface where a *password* is guessable, so it is limited per account as well as
/// per source address: while either is locked the argon2 verification is never run.
pub async fn from_basic(
    app: &AppState,
    ip: IpAddr,
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
            return Err(internal(app, Source::Ddns, &format!("could not check Basic credentials: {e}")))
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
    let principal = Principal::of_user(&app.db, user.id, user.username, Source::Ddns, None)
        .await
        .map_err(|e| internal(app, Source::Ddns, &format!("could not read the user's groups: {e}")))?;
    // A good password clears the account's failures — including any it collected on the console login
    // form (one row). The source's are deliberately kept: one valid credential shouldn't refund a
    // spraying address's budget.
    app.usernames.clear(username).await;
    Ok(principal)
}

/// The longer of the account's and the address's remaining lockout, if either is locked.
async fn locked_for(app: &AppState, username: &str, ip: IpAddr) -> Option<i64> {
    match (app.usernames.locked(username).await, app.ips.locked(Some(ip)).await) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    }
}

/// Record a checked-and-rejected credential: count it, meter it, and warn once if that failure is what
/// locked the account/source out. Returns the error to hand back.
async fn rejected(
    app: &AppState,
    source: Source,
    ip: IpAddr,
    username: Option<&str>,
    reason: &str,
) -> AuthError {
    let by_user = match username {
        Some(u) => app.usernames.record_failure(u).await,
        None => false,
    };
    if app.ips.record_failure(Some(ip)).await || by_user {
        tracing::warn!(
            surface = source.as_str(),
            user = username.unwrap_or("-"),
            src = %ip,
            "too many failed credential checks — locked out for now"
        );
    }
    app.metrics.auth_failure(source.as_str(), reason);
    AuthError::BadAuth
}

/// A credential that could not be checked at all — never a statement about the credential.
fn internal(app: &AppState, source: Source, what: &str) -> AuthError {
    tracing::error!(surface = source.as_str(), "{what}");
    app.metrics.auth_failure(source.as_str(), "error");
    AuthError::Internal
}

/// A credential refused without being checked, because its account or source is locked out.
fn locked(app: &AppState, source: Source, retry: i64) -> AuthError {
    tracing::debug!(surface = source.as_str(), retry, "credential check refused: locked out");
    app.metrics.auth_failure(source.as_str(), "locked");
    AuthError::Locked(retry)
}

/// Extract a Bearer token from the `Authorization` header (the scheme case-insensitively, RFC 7235).
pub use relativelylight::auth::bearer_token;

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
