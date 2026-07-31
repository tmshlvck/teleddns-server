//! The two app-owned network middlewares: source admission and the access log. `ip_src_allowed` says
//! which source networks may reach the server at all; `ops_ip_src_allowed` narrows `/healthcheck` and
//! `/metrics` further (both must pass). Either empty means "no restriction" — this is an admission
//! policy, not a set of exceptions, which is why neither is called a whitelist (the lockout's
//! `ip_lockout_whitelist` is: it exempts addresses from automatic blocking).
//!
//! **Neither resolves an address.** Both read [`RealIp`], the request extension
//! `relativelylight::middleware::resolve_real_ip` fills in at the outermost layer (`app.rs`) — the same
//! value the lockout counts, the audit row records and every handler sees, already canonicalized
//! (IPv4-mapped IPv6 folded to IPv4). One resolution, one policy decision about proxy trust
//! (`config.trust_proxy`, passed to that layer as `TrustProxy`), so a CIDR rule cannot mean one thing
//! here and another there. Extraction is strict: without the layer these answer `500` naming it, rather
//! than admitting a request whose source they could not establish.
//!
//! `relativelylight::net` still owns the address *vocabulary* — `parse_nets` / `in_nets` (CIDR rules
//! matching across both families and the mapped form) — which is what the two lists below are built
//! from.
//!
//! The access log is ours because **relativelylight ships none** — the crate writes nothing to stdout
//! or stderr, deliberately, and leaves the request log to the app (its `examples/access_log` is the
//! worked version of what this file does). Which suits us: this emits a `tracing` event carrying the
//! query string — for `/nic/update` the query *is* the request — plus the User-Agent, so a
//! misbehaving DDNS client can be identified. It honours `config.debug` and lands in journald with the
//! rest of our structured logs, none of which a fixed `eprintln!` line could do.

use crate::app::AppState;
use axum::extract::State;
use axum::http::{header, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use relativelylight::middleware::RealIp;
use relativelylight::net::in_nets;

pub async fn access_log(
    RealIp(ip): RealIp,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let target = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
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
    RealIp(ip): RealIp,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
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
