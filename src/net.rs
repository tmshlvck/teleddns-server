//! CIDR allow-lists and the request log. `allowed_ips` gates every request; `ops_allowed_ips`
//! additionally gates `/healthcheck` and `/metrics` (on top of `allowed_ips`).
//!
//! Nothing about addresses is implemented here — `relativelylight::net` owns it: `client_ip`
//! (socket peer, or the left-most `X-Forwarded-For` / `X-Real-IP` hop when `trust_proxy`, IPv4-mapped
//! collapsed to IPv4), `parse_nets` and `in_nets` (CIDR rules, matching across families and the mapped
//! form). Everything that needs an address calls those directly — `ddns`, `api::req_ip`, `audit`, the
//! two middlewares below, the lockout's allow-list, and relativelylight's own login route — so there is
//! one implementation and one place where proxy trust is decided: our config.

use crate::app::AppState;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use relativelylight::net::{canonical, client_ip, in_nets};
use std::net::SocketAddr;

pub async fn access_log(
    State(app): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let target = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let ip = client_ip(app.cfg.trust_proxy, req.headers(), Some(peer.ip()))
        .unwrap_or_else(|| canonical(peer.ip())); // `None` needs no peer, and we have one
    let ua = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();
    let start = std::time::Instant::now();
    let res = next.run(req).await;
    tracing::info!(
        %method,
        target = %target,
        status = res.status().as_u16(),
        ip = %ip,
        ua = %ua,
        latency_ms = start.elapsed().as_millis() as u64,
        "http"
    );
    res
}

/// Middleware: enforce `allowed_ips` globally and `ops_allowed_ips` on the operability endpoints.
pub async fn allow_list(
    State(app): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let ip = client_ip(app.cfg.trust_proxy, req.headers(), Some(peer.ip()))
        .unwrap_or_else(|| canonical(peer.ip())); // `None` needs no peer, and we have one

    if !app.allowed_nets.is_empty() && !in_nets(&app.allowed_nets, ip) {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    let path = req.uri().path();
    if (path == "/healthcheck" || path == "/metrics")
        && !app.ops_nets.is_empty()
        && !in_nets(&app.ops_nets, ip)
    {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    next.run(req).await
}
