//! The two network middlewares: source admission and the access log. `ip_src_allowed` says which
//! source networks may reach the server at all; `ops_ip_src_allowed` narrows `/healthcheck` and
//! `/metrics` further (both must pass). Either empty means "no restriction" — this is an admission
//! policy, not a set of exceptions, which is why neither is called a whitelist (the lockout's
//! `ip_lockout_whitelist` is: it exempts addresses from automatic blocking).
//!
//! Both lists are matched against the *resolved* client address with the same canonicalization the
//! lockout and the audit log use, so a rule cannot mean one thing here and another there.
//!
//! Nothing about addresses is implemented here — `relativelylight::net` owns it: `client_ip`
//! (socket peer, or the right-most `X-Forwarded-For` hop — the one the proxy appended — when
//! `trust_proxy`, else `X-Real-IP`; IPv4-mapped
//! collapsed to IPv4), `parse_nets` and `in_nets` (CIDR rules, matching across families and the mapped
//! form). Everything that needs an address calls those directly — `ddns`, `api::req_ip`, `audit`, the
//! two middlewares below, the lockout's whitelist, and relativelylight's own login route — so there is
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

/// Middleware: enforce `ip_src_allowed` globally and `ops_ip_src_allowed` on the operability
/// endpoints.
pub async fn allow_from(
    State(app): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let ip = client_ip(app.cfg.trust_proxy, req.headers(), Some(peer.ip()))
        .unwrap_or_else(|| canonical(peer.ip())); // `None` needs no peer, and we have one

    if !app.ip_src_allowed.is_empty() && !in_nets(&app.ip_src_allowed, ip) {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    let path = req.uri().path();
    if (path == "/healthcheck" || path == "/metrics")
        && !app.ops_ip_src_allowed.is_empty()
        && !in_nets(&app.ops_ip_src_allowed, ip)
    {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    next.run(req).await
}
