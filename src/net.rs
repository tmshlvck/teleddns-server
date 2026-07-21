//! Client-IP resolution and CIDR allow-lists. `allowed_ips` gates every request; `ops_allowed_ips`
//! additionally gates `/healthcheck` and `/metrics` (on top of `allowed_ips`). The real client IP is
//! the socket peer unless `trust_proxy` is set, in which case the left-most `X-Forwarded-For` (or
//! `X-Real-IP`) hop is used.

use crate::app::AppState;
use axum::extract::{ConnectInfo, State};
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};

/// Parse a list of CIDR strings (bare IPs are accepted as /32 or /128).
pub fn parse_nets(cidrs: &[String]) -> Vec<IpNet> {
    cidrs
        .iter()
        .filter_map(|s| {
            s.parse::<IpNet>()
                .ok()
                .or_else(|| s.parse::<IpAddr>().ok().map(IpNet::from))
        })
        .collect()
}

fn in_any(nets: &[IpNet], ip: IpAddr) -> bool {
    nets.iter().any(|n| n.contains(&ip))
}

/// Resolve the real client IP for a request.
pub fn client_ip(app: &AppState, headers: &axum::http::HeaderMap, peer: IpAddr) -> IpAddr {
    resolve_ip(app.cfg.trust_proxy, headers, Some(peer)).unwrap_or(peer)
}

/// Resolve the real client IP without needing `AppState` (used by the audit sink, which must not hold
/// a back-reference to it): the left-most `X-Forwarded-For`/`X-Real-IP` hop when `trust_proxy`, else
/// the socket `peer`. `None` only when there is neither a trusted header nor a peer.
pub fn resolve_ip(
    trust_proxy: bool,
    headers: &axum::http::HeaderMap,
    peer: Option<IpAddr>,
) -> Option<IpAddr> {
    if trust_proxy {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = xff.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
        if let Some(xr) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            if let Ok(ip) = xr.trim().parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }
    peer
}

/// Middleware: enforce `allowed_ips` globally and `ops_allowed_ips` on the operability endpoints.
pub async fn allow_list(
    State(app): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let ip = client_ip(&app, req.headers(), peer.ip());

    if !app.allowed_nets.is_empty() && !in_any(&app.allowed_nets, ip) {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    let path = req.uri().path();
    if (path == "/healthcheck" || path == "/metrics")
        && !app.ops_nets.is_empty()
        && !in_any(&app.ops_nets, ip)
    {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_membership() {
        let nets = parse_nets(&["10.0.0.0/8".into(), "127.0.0.1".into()]);
        assert!(in_any(&nets, "10.9.9.9".parse().unwrap()));
        assert!(in_any(&nets, "127.0.0.1".parse().unwrap()));
        assert!(!in_any(&nets, "192.168.1.1".parse().unwrap()));
    }
}
