//! The native JSON management API (PRD §6.1): bearer-only, level-scoped, unified type-discriminated
//! records with opaque ids, DB pagination, and Idempotency-Key replay. The app owns the OpenAPI
//! document; these routes are described there via utoipa paths merged in `app.rs` (kept minimal here).

pub mod idempotency;
pub mod openapi;
pub mod record_view;
pub mod records;
pub mod zones;

use crate::app::AppState;
use crate::principal::{self, Principal, Source};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Json;
use serde_json::json;

/// Mount the native API under `/api`.
pub fn router() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/api/zones", get(zones::list).post(zones::create))
        .route(
            "/api/zones/{id}",
            get(zones::get_one).put(zones::update).delete(zones::delete),
        )
        .route("/api/zones/{id}/rr", get(records::list).post(records::create))
        .route(
            "/api/zones/{id}/rr/{rrid}",
            get(records::get_one).put(records::update).delete(records::delete),
        )
}

/// Require a valid Bearer token; on failure returns the JSON error response to short-circuit. Token
/// checks are rate-limited per client IP (`principal`), so a caller that keeps guessing gets `429` +
/// `Retry-After` instead of another `401` — hence `ip`, the handler's `RealIp`.
pub async fn require_bearer(
    app: &AppState,
    headers: &HeaderMap,
    ip: std::net::IpAddr,
) -> Result<Principal, Response> {
    // Basic is rejected on the API (bearer-only).
    if principal::basic_creds(headers).is_some() && principal::bearer_token(headers).is_none() {
        return Err(err(StatusCode::UNAUTHORIZED, "bearer token required (HTTP Basic not accepted)"));
    }
    match principal::from_bearer(app, ip, headers, Source::Api).await {
        Ok(p) => Ok(p),
        Err(principal::AuthError::Locked(retry)) => Err(too_many(retry)),
        Err(principal::AuthError::Internal) => {
            Err(err(StatusCode::INTERNAL_SERVER_ERROR, "auth error"))
        }
        Err(_) => Err(err(StatusCode::UNAUTHORIZED, "invalid or missing bearer token")),
    }
}

/// `429` with a `Retry-After`, for a credential refused because its source is locked out.
fn too_many(retry: i64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(axum::http::header::RETRY_AFTER, retry.to_string())],
        Json(json!({ "error": "too many failed authentication attempts" })),
    )
        .into_response()
}

/// A JSON error response `{ "error": msg }`.
pub fn err(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

/// Map a record_view::ApiError to an HTTP response.
pub fn map_api_error(e: record_view::ApiError) -> Response {
    use record_view::ApiError::*;
    match e {
        NotFound => err(StatusCode::NOT_FOUND, "not found"),
        BadType(t) => err(StatusCode::BAD_REQUEST, &format!("unknown record type: {t}")),
        Validation(m) => (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({ "error": m }))).into_response(),
        Db(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db error: {e}")),
    }
}

/// Pagination parsed from `?page`/`?per_page` (default 50, max 500).
pub struct Page {
    pub page: u64,
    pub per_page: u64,
}

impl Page {
    pub fn from_query(q: &std::collections::HashMap<String, String>) -> Page {
        let page = q.get("page").and_then(|s| s.parse().ok()).filter(|p| *p >= 1).unwrap_or(1);
        let per_page = q
            .get("per_page")
            .and_then(|s| s.parse().ok())
            .filter(|p| *p >= 1)
            .unwrap_or(50)
            .min(500);
        Page { page, per_page }
    }
    pub fn offset(&self) -> usize {
        ((self.page - 1) * self.per_page) as usize
    }
}
