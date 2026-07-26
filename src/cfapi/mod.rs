//! Cloudflare-compatible API facade (PRD §6.2) under `/client/v4`, for tooling that only speaks
//! Cloudflare's DNS API (cert-manager's ACME DNS01 solver, external-dns' `cloudflare` provider). It
//! mirrors CF's envelope + record shape closely enough for those clients and reuses the native
//! validation + write path. Supported types: A, AAAA, CNAME, TXT, NS, MX. Auth: Bearer or X-Auth-Key.

pub mod records;
pub mod zones;

use crate::app::AppState;
use crate::principal::{self, Principal, Source};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Json;
use serde_json::{json, Value};

/// Mount the CF facade under `/client/v4`.
pub fn router() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/client/v4/user/tokens/verify", get(verify_token))
        .route("/client/v4/zones", get(zones::list))
        .route(
            "/client/v4/zones/{id}/dns_records",
            get(records::list).post(records::create),
        )
        .route(
            "/client/v4/zones/{id}/dns_records/{rid}",
            get(records::get_one)
                .put(records::update)
                .patch(records::update)
                .delete(records::delete),
        )
}

/// Resolve the caller from `Authorization: Bearer` or `X-Auth-Key`. `Err` is the ready-to-return CF
/// error envelope: `401` for a bad/absent token, `429` + `Retry-After` when the source has failed too
/// many checks recently (the token isn't looked at then — see `principal`), `500` if we couldn't check.
pub async fn authenticate(
    app: &AppState,
    headers: &HeaderMap,
    peer: std::net::SocketAddr,
) -> Result<Principal, Response> {
    let ip = crate::api::req_ip(app, headers, peer);
    // `X-Auth-Key` is CF's own carrier for the same token; `Authorization: Bearer` wins when both are
    // present (as on DDNS and the native API), so one request is never two credential checks.
    let token = principal::bearer_token(headers)
        .or_else(|| headers.get("X-Auth-Key").and_then(|v| v.to_str().ok()).map(str::to_string));
    let Some(token) = token else {
        return Err(cf_err(StatusCode::UNAUTHORIZED, 1000, "invalid token"));
    };
    match principal::from_token(app, ip, &token, Source::Cfapi).await {
        Ok(p) => Ok(p),
        Err(principal::AuthError::Locked(retry)) => Err((
            StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::RETRY_AFTER, retry.to_string())],
            Json(json!({
                "success": false,
                "errors": [{ "code": 10000, "message": "too many failed authentication attempts" }],
                "messages": [],
                "result": null,
            })),
        )
            .into_response()),
        Err(principal::AuthError::Internal) => {
            Err(cf_err(StatusCode::INTERNAL_SERVER_ERROR, 1001, "auth error"))
        }
        Err(_) => Err(cf_err(StatusCode::UNAUTHORIZED, 1000, "invalid token")),
    }
}

/// A CF success envelope wrapping `result`.
pub fn ok(result: Value) -> Response {
    Json(json!({
        "success": true,
        "errors": [],
        "messages": [],
        "result": result,
    }))
    .into_response()
}

/// A CF success envelope with `result_info` (for lists).
pub fn ok_list(result: Value, count: usize, page: u64, per_page: u64, total: usize) -> Response {
    Json(json!({
        "success": true,
        "errors": [],
        "messages": [],
        "result": result,
        "result_info": {
            "page": page,
            "per_page": per_page,
            "count": count,
            "total_count": total,
        },
    }))
    .into_response()
}

/// A CF error envelope.
pub fn cf_err(status: StatusCode, code: i64, message: &str) -> Response {
    (
        status,
        Json(json!({
            "success": false,
            "errors": [{ "code": code, "message": message }],
            "messages": [],
            "result": null,
        })),
    )
        .into_response()
}

/// GET /client/v4/user/tokens/verify — confirms a token is valid/active.
async fn verify_token(
    axum::extract::State(app): axum::extract::State<AppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Response {
    match authenticate(&app, &headers, peer).await {
        Ok(p) => ok(json!({
            "id": p.key_id.map(|k| k.to_string()).unwrap_or_default(),
            "status": "active",
        })),
        Err(r) => r,
    }
}
