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

/// Require a valid Bearer token; on failure returns the JSON 401 response to short-circuit.
pub async fn require_bearer(app: &AppState, headers: &HeaderMap) -> Result<Principal, Response> {
    // Basic is rejected on the API (bearer-only).
    if principal::basic_creds(headers).is_some() && principal::bearer_token(headers).is_none() {
        return Err(err(StatusCode::UNAUTHORIZED, "bearer token required (HTTP Basic not accepted)"));
    }
    match principal::from_bearer(&app.db, headers, Source::Api).await {
        Ok(Some(p)) => Ok(p),
        Ok(None) => {
            app.metrics.auth_failure("api", "bad_token");
            Err(err(StatusCode::UNAUTHORIZED, "invalid or missing bearer token"))
        }
        Err(_) => Err(err(StatusCode::INTERNAL_SERVER_ERROR, "auth error")),
    }
}

/// A JSON error response `{ "error": msg }`.
pub fn err(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

/// Resolve the client IP for an API/CF request (peer + trust_proxy/XFF), for the audit log.
pub fn req_ip(
    app: &AppState,
    headers: &HeaderMap,
    peer: std::net::SocketAddr,
) -> Option<std::net::IpAddr> {
    crate::net::resolve_ip(app.cfg.trust_proxy, headers, Some(peer.ip()))
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
