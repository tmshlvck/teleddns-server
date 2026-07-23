//! Client-IP resolution and CIDR allow-lists. `allowed_ips` gates every request; `ops_allowed_ips`
//! additionally gates `/healthcheck` and `/metrics` (on top of `allowed_ips`). The real client IP is
//! the socket peer unless `trust_proxy` is set, in which case the left-most `X-Forwarded-For` (or
//! `X-Real-IP`) hop is used.

use crate::app::AppState;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use ipnet::{IpNet, Ipv4Net};
use std::net::{IpAddr, SocketAddr};

/// Parse a list of CIDR strings (bare IPs are accepted as /32 or /128). IPv4-mapped IPv6 entries are
/// canonicalized to IPv4 so they match unmapped IPv4 clients (matching the same normalization applied
/// to the source IP — see [`canonical`]).
pub fn parse_nets(cidrs: &[String]) -> Vec<IpNet> {
    cidrs
        .iter()
        .filter_map(|s| {
            s.parse::<IpNet>()
                .ok()
                .or_else(|| s.parse::<IpAddr>().ok().map(IpNet::from))
                .map(canonical_net)
        })
        .collect()
}

fn in_any(nets: &[IpNet], ip: IpAddr) -> bool {
    nets.iter().any(|n| n.contains(&ip))
}

/// Canonicalize an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) back to plain IPv4. A dual-stack
/// (`::`-bound) listener reports IPv4 clients in this mapped form, which would otherwise not match an
/// IPv4 CIDR in the allow-lists (and would read oddly in logs/audit).
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// The rule-side counterpart of [`canonical`]: an IPv4-mapped IPv6 network (`::ffff:a.b.c.d/N`, N≥96)
/// becomes the equivalent IPv4 network (`/N-96`), so a rule written in mapped form still matches an
/// unmapped IPv4 client. Genuine IPv6 networks are left untouched.
fn canonical_net(net: IpNet) -> IpNet {
    if let IpNet::V6(v6) = net {
        if let Some(v4) = v6.addr().to_ipv4_mapped() {
            if v6.prefix_len() >= 96 {
                if let Ok(n) = Ipv4Net::new(v4, v6.prefix_len() - 96) {
                    return IpNet::V4(n);
                }
            }
        }
    }
    net
}

/// Resolve the real client IP for a request (canonicalized — IPv4-mapped IPv6 → IPv4).
pub fn client_ip(app: &AppState, headers: &axum::http::HeaderMap, peer: IpAddr) -> IpAddr {
    resolve_ip(app.cfg.trust_proxy, headers, Some(peer)).unwrap_or_else(|| canonical(peer))
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
                    return Some(canonical(ip));
                }
            }
        }
        if let Some(xr) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            if let Ok(ip) = xr.trim().parse::<IpAddr>() {
                return Some(canonical(ip));
            }
        }
    }
    peer.map(canonical)
}

/// Middleware: one INFO access-log line per HTTP request, to stderr (no standalone access.log). Covers
/// every surface — DDNS, native API, CF facade, UI, `/metrics`, `/healthcheck`. Fields: method, the
/// path+query, response status, the resolved client IP (proxy-aware when `trust_proxy`), the
/// User-Agent, and the latency. Placed outermost, so even allow-list-denied (403) requests are logged.
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
    let ip = client_ip(&app, req.headers(), peer.ip());
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

    #[test]
    fn ipv4_mapped_is_canonicalized() {
        // A dual-stack (::)-bound listener reports an IPv4 client as ::ffff:a.b.c.d; it must match an
        // IPv4 CIDR after canonicalization.
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert_eq!(canonical(mapped), "127.0.0.1".parse::<IpAddr>().unwrap());
        let nets = parse_nets(&["127.0.0.1".into()]);
        assert!(in_any(&nets, canonical(mapped)));
        assert!(!in_any(&nets, mapped)); // (unmapped it would not match)
        // A genuine IPv6 address is left alone.
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(canonical(v6), v6);
    }

    #[test]
    fn mapped_rules_are_canonicalized_symmetrically() {
        // A rule written in IPv4-mapped form matches an (unmapped) IPv4 client.
        let nets = parse_nets(&["::ffff:127.0.0.1".into()]);
        assert_eq!(nets, parse_nets(&["127.0.0.1".into()])); // both → 127.0.0.1/32
        assert!(in_any(&nets, "127.0.0.1".parse().unwrap()));

        // A mapped CIDR (prefix ≥ 96) converts to the equivalent IPv4 CIDR (prefix − 96).
        let nets = parse_nets(&["::ffff:10.0.0.0/104".into()]);
        assert_eq!(nets, parse_nets(&["10.0.0.0/8".into()]));
        assert!(in_any(&nets, "10.9.9.9".parse().unwrap()));
        assert!(!in_any(&nets, "11.0.0.1".parse().unwrap()));

        // Genuine IPv6 rules are untouched and still match IPv6 clients with the right prefix.
        let nets = parse_nets(&["2001:db8::/32".into()]);
        assert!(in_any(&nets, "2001:db8::5".parse().unwrap()));
        assert!(!in_any(&nets, "2001:dead::5".parse().unwrap()));
    }
}
