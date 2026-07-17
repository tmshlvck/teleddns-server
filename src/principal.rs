//! Resolve a request to an authenticated `Principal` with an effective *token level*. Three sources:
//! the operator session cookie (via relativelylight `auth`), HTTP Basic (DDNS only), and a Bearer API
//! key. The token level caps what the principal can do (§3); the per-target `effective_level` lookup
//! (see `authz`) does the rest.

use crate::authz::Level;
use crate::model::{api_key, now};
use axum::http::HeaderMap;
use relativelylight::auth::{self, Auth};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter,
};
use sha2::{Digest, Sha256};

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

/// Resolve from an `Authorization` header (Bearer only), for a given source surface.
pub async fn from_bearer(
    db: &DatabaseConnection,
    headers: &HeaderMap,
    source: Source,
) -> Result<Option<Principal>, DbErr> {
    let Some(token) = bearer_token(headers) else {
        return Ok(None);
    };
    principal_for_token(db, &token, source).await
}

/// Resolve a raw token string (used by Bearer and the CF `X-Auth-Key` header).
pub async fn principal_for_token(
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

/// Resolve from HTTP Basic credentials (DDNS only). Rejects users with any strong factor (TOTP/SSO/
/// passkey) — they must use a token. Token level = L3, capped by effective access.
pub async fn from_basic(
    db: &DatabaseConnection,
    username: &str,
    password: &str,
) -> Result<Principal, AuthError> {
    let user = match auth::user::Entity::find()
        .filter(auth::user::Column::Username.eq(username))
        .one(db)
        .await
    {
        Ok(Some(u)) => u,
        _ => return Err(AuthError::BadAuth),
    };
    if !user.is_active {
        return Err(AuthError::BadAuth);
    }
    // A user with TOTP enabled (or a future SSO/passkey marker) may not use Basic.
    if user.totp_secret.is_some() {
        return Err(AuthError::BasicNotAllowed);
    }
    if !auth::verify_password(&user.password_hash, password) {
        return Err(AuthError::BadAuth);
    }
    let (group_ids, group_names, is_admin) = crate::authz::user_groups(db, user.id)
        .await
        .map_err(|_| AuthError::BadAuth)?;
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
