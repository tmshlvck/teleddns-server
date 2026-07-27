//! The dyndns2 DDNS endpoint (PRD §2, wire protocol in `DYNDNS2.md`). Three paths behave
//! identically and take `GET` or `POST`; any other method is `405 badagent`. Auth is HTTP Basic or
//! Bearer; per-record authorization is L1; the path only ever creates/updates A and AAAA (never
//! deletes). On any data change it bumps the SOA serial and enqueues a push (via the RR after_save
//! hook).
//!
//! Request shape follows the original dyn API: `hostname` is a comma-separated list of up to 20
//! names, `myip` a comma-separated address list of either family, and every listed host gets the
//! same address set (`myipv6` is the common extension for an explicit IPv6). With no address at all
//! the client's source address is used. The response body is dyndns2 vocabulary with **one line per
//! hostname, in request order** — a whole-request failure (auth, malformed query) is a single line
//! instead. The HTTP status is the worst of the lines.

use crate::app::AppState;
use crate::authz::{self, Level};
use crate::dns;
use crate::model::rr;
use crate::principal::{self, AuthError, Principal, Source};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter};
use std::collections::HashMap;

/// dyndns2's hostname-per-request cap (the dyn API's documented limit); more → `numhost`.
const MAX_HOSTNAMES: usize = 20;

/// An update result in dyndns2 vocabulary — per address family internally, then merged to one per
/// hostname for the response.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    /// Created or changed; carries the address(es) now on record.
    Good(String),
    /// Already at the requested value; carries the same.
    Nochg(String),
    NotFqdn,
    BadAuth,
    NotYours,
    NoHost,
    /// More than [`MAX_HOSTNAMES`] names in one request.
    NumHost,
    Abuse,
    /// The client did not follow the update-client requirements — here: a non-GET method.
    BadAgent,
    Error,
}

impl Outcome {
    fn status(&self) -> StatusCode {
        match self {
            Outcome::Good(_) | Outcome::Nochg(_) => StatusCode::OK,
            Outcome::NotFqdn | Outcome::NumHost => StatusCode::BAD_REQUEST,
            Outcome::BadAuth => StatusCode::UNAUTHORIZED,
            Outcome::NotYours => StatusCode::FORBIDDEN,
            Outcome::NoHost => StatusCode::NOT_FOUND,
            Outcome::Abuse => StatusCode::TOO_MANY_REQUESTS,
            Outcome::BadAgent => StatusCode::METHOD_NOT_ALLOWED,
            Outcome::Error => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
    fn body(&self) -> String {
        match self {
            Outcome::Good(ip) => format!("good {ip}"),
            Outcome::Nochg(ip) => format!("nochg {ip}"),
            Outcome::NotFqdn => "notfqdn".into(),
            Outcome::BadAuth => "badauth".into(),
            Outcome::NotYours => "!yours".into(),
            Outcome::NoHost => "nohost".into(),
            Outcome::NumHost => "numhost".into(),
            Outcome::Abuse => "abuse".into(),
            Outcome::BadAgent => "badagent".into(),
            Outcome::Error => "911".into(),
        }
    }
    /// Metric result label.
    fn label(&self) -> &'static str {
        match self {
            Outcome::Good(_) => "good",
            Outcome::Nochg(_) => "nochg",
            Outcome::NotFqdn => "notfqdn",
            Outcome::BadAuth => "badauth",
            Outcome::NotYours => "notyours",
            Outcome::NoHost => "nohost",
            Outcome::NumHost => "numhost",
            Outcome::Abuse => "abuse",
            Outcome::BadAgent => "badagent",
            Outcome::Error => "error",
        }
    }
    /// Ranking used to merge one hostname's per-family outcomes into the single line dyndns2 wants:
    /// any failure outranks a success (the client must see it), and a change outranks a no-change.
    /// The dyn spec is silent on partial failures — a client that needs per-family detail should send
    /// one family per request.
    fn severity(&self) -> u8 {
        match self {
            Outcome::Nochg(_) => 0,
            Outcome::Good(_) => 1,
            Outcome::NoHost => 2,
            Outcome::NotYours => 3,
            Outcome::Abuse => 4,
            Outcome::NotFqdn => 5,
            Outcome::NumHost => 6,
            Outcome::BadAgent => 7,
            Outcome::BadAuth => 8,
            Outcome::Error => 9,
        }
    }
}

/// GET|POST /nic/update | /ddns/update | /update
pub async fn update(
    State(app): State<AppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Query(query): Query<HashMap<String, String>>,
    // Body last (it is consumed): empty for GET, the form payload for a POST that sends one.
    body: String,
) -> Response {
    let params = request_params(query, &headers, &body);
    // Real client IP (post proxy rewrite) for the audit log, the request log line, and — when the
    // request carries no address at all — the address to publish.
    let ip = relativelylight::net::client_ip(app.cfg.trust_proxy, &headers, Some(peer.ip()));
    let ip_s = ip.map(|i| i.to_string()).unwrap_or_else(|| "-".into());
    let ua = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();

    // --- authenticate ---
    let principal = match authenticate(&app, &headers, ip).await {
        Ok(p) => p,
        Err(o) => return finish(&app, &[o], "-", &ua),
    };

    // --- parse the hostname list (dyndns2: comma-separated, up to MAX_HOSTNAMES names) ---
    let hostnames: Vec<&str> = csv(&params, "hostname");
    if hostnames.is_empty() {
        return finish(&app, &[Outcome::NotFqdn], &principal.username, &ua);
    }
    if hostnames.len() > MAX_HOSTNAMES {
        return finish(&app, &[Outcome::NumHost], &principal.username, &ua);
    }
    // A syntactically invalid name is `notfqdn`, never `nohost`. One bad name fails the whole
    // request: the alternative — a per-host `notfqdn` line — would imply the name was looked up.
    if hostnames.iter().any(|h| dns::check::ddns_hostname(h).is_err()) {
        return finish(&app, &[Outcome::NotFqdn], &principal.username, &ua);
    }

    // --- parse the address set, shared by every listed hostname ---
    let addrs = match Addrs::parse(&params) {
        Ok(a) if !a.is_empty() => a,
        // No address given at all: fall back to the address the request came from, as the dyn API
        // does ("the best IP address the server can determine"). Only that one family is touched —
        // publishing a second address the client never mentioned would be a surprise. With
        // `trust_proxy` the resolved IP is the left-most forwarded hop, so this works behind a proxy.
        Ok(_) => match ip {
            Some(detected) => {
                tracing::debug!(actor = %principal.username, src = %ip_s, "ddns: no address given, using the client address");
                Addrs::from_client_ip(detected)
            }
            None => return finish(&app, &[Outcome::NotFqdn], &principal.username, &ua),
        },
        Err(o) => return finish(&app, &[o], &principal.username, &ua),
    };

    // --- one outcome line per hostname, in request order ---
    let auth_type = if principal.key_id.is_some() { "bearer" } else { "basic" };
    let mut outcomes = Vec::with_capacity(hostnames.len());
    for hostname in &hostnames {
        outcomes.push(
            update_host(&app, &principal, hostname, &addrs, ip, &ip_s, &ua, auth_type).await,
        );
    }
    finish(&app, &outcomes, &principal.username, &ua)
}

/// The request's parameters. dyn puts them in the query string for both GET and POST; a POST that
/// instead form-encodes them in the body is accepted too (some embedded clients do that). A name
/// present in both places is taken from the query string.
fn request_params(
    mut query: HashMap<String, String>,
    headers: &HeaderMap,
    body: &str,
) -> HashMap<String, String> {
    let form = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.trim_start().starts_with("application/x-www-form-urlencoded"))
        .unwrap_or(false);
    if form && !body.is_empty() {
        for (k, v) in form_urlencoded::parse(body.as_bytes()) {
            query.entry(k.into_owned()).or_insert_with(|| v.into_owned());
        }
    }
    query
}

/// Split a comma-separated query parameter into trimmed, non-empty entries (dyndns2 uses this form
/// for both `hostname` and `myip`). A missing parameter yields no entries.
fn csv<'a>(params: &'a HashMap<String, String>, key: &str) -> Vec<&'a str> {
    params
        .get(key)
        .map(|v| v.split(',').map(str::trim).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

/// The address set of one request: at most one address per family. dyndns2 puts both families in
/// `myip` as a comma-separated list (`myip=192.0.2.1,2001:db8::1`); `myipv6` is the widely-used
/// extension for an explicit IPv6. Two *different* addresses of the same family contradict each
/// other — the request is malformed (`notfqdn`) rather than silently last-one-wins.
#[derive(Default, Debug, PartialEq, Eq)]
struct Addrs {
    v4: Option<String>,
    v6: Option<String>,
}

impl Addrs {
    fn parse(params: &HashMap<String, String>) -> Result<Self, Outcome> {
        let mut a = Self::default();
        for entry in csv(params, "myip") {
            if dns::is_ipv4(entry) {
                a.set(Family::V4, entry)?;
            } else if dns::is_ipv6(entry) {
                a.set(Family::V6, entry)?;
            } else {
                return Err(Outcome::NotFqdn); // not an address literal
            }
        }
        // `myipv6` is IPv6-only; a v4 there is a client bug worth reporting, not silently accepting.
        for entry in csv(params, "myipv6") {
            if !dns::is_ipv6(entry) {
                return Err(Outcome::NotFqdn);
            }
            a.set(Family::V6, entry)?;
        }
        Ok(a)
    }

    /// The set implied by the address a request arrived from (used when it names none): that one
    /// family only. `IpAddr`'s display form is the canonical literal, and `net::client_ip` has
    /// already unwrapped an IPv4-mapped IPv6 peer, so a dual-stack listener yields plain IPv4 here.
    fn from_client_ip(ip: std::net::IpAddr) -> Self {
        match ip {
            std::net::IpAddr::V4(v4) => Self { v4: Some(v4.to_string()), v6: None },
            std::net::IpAddr::V6(v6) => Self { v4: None, v6: Some(v6.to_string()) },
        }
    }

    /// Record one address, rejecting a conflicting second one for the same family. Repeating the
    /// same address (e.g. in both `myip` and `myipv6`) is accepted as a no-op.
    fn set(&mut self, family: Family, addr: &str) -> Result<(), Outcome> {
        let slot = match family {
            Family::V4 => &mut self.v4,
            Family::V6 => &mut self.v6,
        };
        match slot {
            Some(existing) if existing != addr => Err(Outcome::NotFqdn),
            _ => {
                *slot = Some(addr.to_string());
                Ok(())
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.v4.is_none() && self.v6.is_none()
    }

    /// The requested `(family, address)` pairs, IPv4 first (the order the response line lists them).
    fn iter(&self) -> impl Iterator<Item = (Family, &str)> {
        [(Family::V4, self.v4.as_deref()), (Family::V6, self.v6.as_deref())]
            .into_iter()
            .filter_map(|(f, a)| a.map(|a| (f, a)))
    }
}

/// Apply the address set to one hostname and collapse the per-family results into the single line
/// dyndns2 expects for that name: the most severe failure if any family failed, else
/// `good`/`nochg` with the addresses now on record.
#[allow(clippy::too_many_arguments)]
async fn update_host(
    app: &AppState,
    principal: &Principal,
    hostname: &str,
    addrs: &Addrs,
    ip: Option<std::net::IpAddr>,
    ip_s: &str,
    ua: &str,
    auth_type: &str,
) -> Outcome {
    let (zone, label) = match dns::resolve_zone(&app.db, hostname).await {
        Ok(Some(zl)) => zl,
        Ok(None) => return Outcome::NoHost,
        Err(_) => return Outcome::Error,
    };

    let mut worst: Option<Outcome> = None;
    let mut changed = false;
    let mut applied: Vec<&str> = Vec::new();
    for (family, addr) in addrs.iter() {
        let o = update_one(app, principal, &zone, &label, family, addr, ip, auth_type).await;
        tracing::info!(
            actor = %principal.username, source = principal.source.as_str(), src = %ip_s, ua = %ua,
            zone = %zone.origin, label = %label, family = ?family, addr = %addr,
            result = o.label(), "ddns update"
        );
        match o {
            Outcome::Good(_) => {
                changed = true;
                applied.push(addr);
            }
            Outcome::Nochg(_) => applied.push(addr),
            failure => {
                if worst.as_ref().map(|w| failure.severity() > w.severity()).unwrap_or(true) {
                    worst = Some(failure);
                }
            }
        }
    }
    match worst {
        Some(w) => w,
        None if changed => Outcome::Good(applied.join(",")),
        None => Outcome::Nochg(applied.join(",")),
    }
}

/// Authenticate a DDNS request (Bearer wins over Basic).
/// Authenticate a DDNS request: Bearer first, then HTTP Basic. `ip` is the resolved client address —
/// the brute-force brake counts failures against it (and, for Basic, against the account). A locked
/// account/source is `abuse` (429), which is exactly what dyndns2 says about a blocked username; it is
/// deliberately distinct from `badauth` so a client can tell "wrong password" from "stop hammering".
async fn authenticate(
    app: &AppState,
    headers: &HeaderMap,
    ip: Option<std::net::IpAddr>,
) -> Result<Principal, Outcome> {
    if principal::bearer_token(headers).is_some() {
        return principal::from_bearer(app, ip, headers, Source::Ddns).await.map_err(auth_outcome);
    }
    if let Some((u, p)) = principal::basic_creds(headers) {
        return principal::from_basic(app, ip, &u, &p).await.map_err(auth_outcome);
    }
    Err(Outcome::BadAuth)
}

/// A failed credential check in dyndns2 vocabulary. "Basic not allowed" is deliberately `badauth`
/// too — telling a caller *why* would say which accounts have 2FA/SSO.
fn auth_outcome(e: AuthError) -> Outcome {
    match e {
        AuthError::Locked(_) => Outcome::Abuse,
        AuthError::Internal => Outcome::Error,
        AuthError::BadAuth | AuthError::BasicNotAllowed => Outcome::BadAuth,
    }
}

/// Update one address family for `(zone, label)`.
#[allow(clippy::too_many_arguments)]
async fn update_one(
    app: &AppState,
    principal: &Principal,
    zone: &crate::model::zone::Model,
    label: &str,
    family: Family,
    addr: &str,
    ip: Option<std::net::IpAddr>,
    auth_type: &str,
) -> Outcome {
    // Authorize: L1 on this exact (zone, label).
    let eff = match authz::effective_level(
        &app.db,
        &principal.group_ids,
        principal.is_admin,
        zone.id,
        Some(label),
    )
    .await
    {
        Ok(l) => l,
        Err(_) => return Outcome::Error,
    };
    if !authz::allowed(principal.token_level, eff, Level::L1) {
        return Outcome::NotYours;
    }

    let ttl = app.cfg.ddns_rr_ttl as i32;
    let res = match family {
        Family::V4 => set_a(&app.db, zone.id, label, addr, ttl).await,
        Family::V6 => set_aaaa(&app.db, zone.id, label, addr, ttl).await,
    };
    match res {
        Ok((true, old)) => {
            let typ = match family {
                Family::V4 => "A",
                Family::V6 => "AAAA",
            };
            app.audit
                .record(
                    "ddns",
                    if old.is_none() { "create" } else { "update" },
                    format!("{} {}", typ, dns::fqdn_of(label, &zone.origin)),
                    principal,
                    auth_type,
                    ip,
                    old.map(|v| serde_json::json!({ "value": v })),
                    Some(serde_json::json!({ "value": addr })),
                )
                .await;
            Outcome::Good(addr.to_string())
        }
        Ok((false, _)) => Outcome::Nochg(addr.to_string()),
        Err(_) => Outcome::Error,
    }
}

/// Set the A set at `(zone,label)` to exactly `[addr]`. Returns `(changed, old_value)` — `changed` is
/// false if already at the requested value; `old_value` is the prior single value (for the audit
/// before-state). Updates the existing row **in place** (preserving `created_at`) rather than
/// delete+recreate, so a router refreshing its IP doesn't reset the record's creation time. Both the
/// insert and the update fire the after_save hook (serial bump + enqueue).
async fn set_a(
    db: &sea_orm::DatabaseConnection,
    zone_id: i32,
    label: &str,
    addr: &str,
    ttl: i32,
) -> Result<(bool, Option<String>), sea_orm::DbErr> {
    let existing = rr::a::Entity::find()
        .filter(rr::a::Column::ZoneId.eq(zone_id))
        .filter(rr::a::Column::Label.eq(label))
        .all(db)
        .await?;
    let old = existing.first().map(|e| e.value.clone());
    if existing.len() == 1 && existing[0].value == addr {
        return Ok((false, old));
    }
    match existing.split_first() {
        // Keep the first row (update in place → preserves created_at); drop any extras.
        Some((first, rest)) => {
            for e in rest {
                rr::a::Entity::delete_by_id(e.id).exec(db).await?;
            }
            let mut am: rr::a::ActiveModel = first.clone().into();
            am.value = Set(addr.to_string());
            am.ttl = Set(ttl);
            am.update(db).await?;
        }
        // No existing record → create one.
        None => {
            rr::a::ActiveModel {
                id: NotSet,
                zone_id: Set(zone_id),
                label: Set(label.to_string()),
                ttl: Set(ttl),
                value: Set(addr.to_string()),
                ..Default::default() // created_at/updated_at stamped by before_save
            }
            .insert(db)
            .await?;
        }
    }
    Ok((true, old))
}

async fn set_aaaa(
    db: &sea_orm::DatabaseConnection,
    zone_id: i32,
    label: &str,
    addr: &str,
    ttl: i32,
) -> Result<(bool, Option<String>), sea_orm::DbErr> {
    let existing = rr::aaaa::Entity::find()
        .filter(rr::aaaa::Column::ZoneId.eq(zone_id))
        .filter(rr::aaaa::Column::Label.eq(label))
        .all(db)
        .await?;
    let old = existing.first().map(|e| e.value.clone());
    if existing.len() == 1 && existing[0].value == addr {
        return Ok((false, old));
    }
    match existing.split_first() {
        Some((first, rest)) => {
            for e in rest {
                rr::aaaa::Entity::delete_by_id(e.id).exec(db).await?;
            }
            let mut am: rr::aaaa::ActiveModel = first.clone().into();
            am.value = Set(addr.to_string());
            am.ttl = Set(ttl);
            am.update(db).await?;
        }
        None => {
            rr::aaaa::ActiveModel {
                id: NotSet,
                zone_id: Set(zone_id),
                label: Set(label.to_string()),
                ttl: Set(ttl),
                value: Set(addr.to_string()),
                ..Default::default() // created_at/updated_at stamped by before_save
            }
            .insert(db)
            .await?;
        }
    }
    Ok((true, old))
}

/// Build the response: one `\n`-joined line per outcome (per hostname, in request order — or a
/// single line for a whole-request failure) and the worst HTTP status of them.
fn finish(app: &AppState, outcomes: &[Outcome], _actor: &str, _ua: &str) -> Response {
    for o in outcomes {
        app.metrics.ddns_update(o.label());
    }
    let status = outcomes.iter().map(|o| o.status()).max_by_key(|s| s.as_u16()).unwrap_or(StatusCode::OK);
    let body = outcomes.iter().map(|o| o.body()).collect::<Vec<_>>().join("\n");
    (status, [(axum::http::header::CONTENT_TYPE, "text/plain")], body).into_response()
}

/// Anything other than GET/POST is rejected — dyndns2 folds "used an unsupported HTTP method" into
/// `badagent`, so the body stays in the protocol's vocabulary (a client that parses the body sees a
/// permanent failure instead of an unknown keyword); the 405 status carries the same signal.
pub async fn reject_method(State(app): State<AppState>) -> Response {
    finish(&app, &[Outcome::BadAgent], "-", "-")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every outcome renders a keyword from the dyndns2 vocabulary, paired with the documented status
    /// (PRD §2). `good`/`nochg` carry the address; the rest are bare keywords.
    #[test]
    fn dyndns2_keywords_and_statuses() {
        let cases = [
            (Outcome::Good("1.2.3.4".into()), "good 1.2.3.4", 200),
            (Outcome::Nochg("2001:db8::1".into()), "nochg 2001:db8::1", 200),
            (Outcome::NotFqdn, "notfqdn", 400),
            (Outcome::BadAuth, "badauth", 401),
            (Outcome::NotYours, "!yours", 403),
            (Outcome::NoHost, "nohost", 404),
            (Outcome::NumHost, "numhost", 400),
            (Outcome::BadAgent, "badagent", 405),
            (Outcome::Abuse, "abuse", 429),
            (Outcome::Error, "911", 500),
        ];
        for (o, body, status) in cases {
            assert_eq!(o.body(), body);
            assert_eq!(o.status().as_u16(), status);
        }
    }

    /// A failed credential check keeps to the vocabulary: a lockout is `abuse` (the client must back
    /// off), everything else a client could fix is `badauth`, and only our own failure is `911`.
    #[test]
    fn credential_failures_map_to_the_dyndns2_vocabulary() {
        assert_eq!(auth_outcome(AuthError::Locked(42)), Outcome::Abuse);
        assert_eq!(auth_outcome(AuthError::BadAuth), Outcome::BadAuth);
        // Never leak *why* Basic was refused — that would enumerate the 2FA/SSO accounts.
        assert_eq!(auth_outcome(AuthError::BasicNotAllowed), Outcome::BadAuth);
        assert_eq!(auth_outcome(AuthError::Internal), Outcome::Error);
    }

    /// The response is one line per hostname in request order, and the HTTP status is the worst.
    #[test]
    fn one_line_per_hostname_worst_status() {
        let hosts = [
            Outcome::Good("192.0.2.1,2001:db8::1".into()),
            Outcome::Nochg("192.0.2.2".into()),
            Outcome::NotYours,
        ];
        let body = hosts.iter().map(|o| o.body()).collect::<Vec<_>>().join("\n");
        assert_eq!(body, "good 192.0.2.1,2001:db8::1\nnochg 192.0.2.2\n!yours");
        assert_eq!(
            hosts.iter().map(|o| o.status()).max_by_key(|s| s.as_u16()).unwrap(),
            StatusCode::FORBIDDEN
        );
    }

    /// Merging a hostname's per-family results: a failure wins over a success, a change over a
    /// no-change (the ranking `update_host` applies).
    #[test]
    fn severity_ranking() {
        assert!(Outcome::Good("x".into()).severity() > Outcome::Nochg("x".into()).severity());
        for failure in [Outcome::NoHost, Outcome::NotYours, Outcome::Abuse, Outcome::Error] {
            assert!(failure.severity() > Outcome::Good("x".into()).severity(), "{failure:?}");
        }
        assert!(Outcome::Error.severity() > Outcome::NotYours.severity());
    }

    fn q(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// `hostname` and `myip` are comma-separated lists; entries are trimmed and empties dropped.
    #[test]
    fn csv_parsing() {
        let p = q(&[("hostname", " a.example.com , b.example.com ,")]);
        assert_eq!(csv(&p, "hostname"), ["a.example.com", "b.example.com"]);
        assert_eq!(csv(&p, "myip"), Vec::<&str>::new()); // absent
        assert_eq!(csv(&q(&[("myip", ",")]), "myip"), Vec::<&str>::new());
    }

    /// The address set: `myip` carries either family (dyn's own form), `myipv6` is IPv6-only, and a
    /// contradictory second address of one family makes the request malformed.
    #[test]
    fn address_set_parsing() {
        let dual = Addrs::parse(&q(&[("myip", "192.0.2.1,2001:db8::1")])).unwrap();
        assert_eq!(dual, Addrs { v4: Some("192.0.2.1".into()), v6: Some("2001:db8::1".into()) });
        assert_eq!(
            dual.iter().collect::<Vec<_>>(),
            [(Family::V4, "192.0.2.1"), (Family::V6, "2001:db8::1")] // IPv4 first
        );
        // The teleddns/extension form, and the two mixed.
        let ext = Addrs::parse(&q(&[("myip", "192.0.2.1"), ("myipv6", "2001:db8::1")])).unwrap();
        assert_eq!(ext, dual);
        // v6 in myip alone (what ddclient sends for a v6-only host) → AAAA only.
        let v6_only = Addrs::parse(&q(&[("myip", "2001:db8::1")])).unwrap();
        assert_eq!(v6_only, Addrs { v4: None, v6: Some("2001:db8::1".into()) });
        // Repeating the same address is a no-op; a different one for the same family is not.
        assert!(Addrs::parse(&q(&[("myip", "2001:db8::1"), ("myipv6", "2001:db8::1")])).is_ok());
        assert_eq!(
            Addrs::parse(&q(&[("myip", "2001:db8::1"), ("myipv6", "2001:db8::2")])),
            Err(Outcome::NotFqdn)
        );
        assert_eq!(Addrs::parse(&q(&[("myip", "192.0.2.1,192.0.2.2")])), Err(Outcome::NotFqdn));
        // Junk, and a v4 in the v6-only parameter.
        assert_eq!(Addrs::parse(&q(&[("myip", "not-an-ip")])), Err(Outcome::NotFqdn));
        assert_eq!(Addrs::parse(&q(&[("myipv6", "192.0.2.1")])), Err(Outcome::NotFqdn));
        // No address at all is empty, not an error (the handler maps it to notfqdn).
        assert!(Addrs::parse(&q(&[("hostname", "a.example.com")])).unwrap().is_empty());
    }

    /// With no address parameter the client's own address is published — that family only.
    #[test]
    fn autodetected_address_set() {
        let v4 = Addrs::from_client_ip("192.0.2.7".parse().unwrap());
        assert_eq!(v4, Addrs { v4: Some("192.0.2.7".into()), v6: None });
        let v6 = Addrs::from_client_ip("2001:db8::7".parse().unwrap());
        assert_eq!(v6, Addrs { v4: None, v6: Some("2001:db8::7".into()) });
        assert_eq!(v6.iter().collect::<Vec<_>>(), [(Family::V6, "2001:db8::7")]);
        // Only used when the request names no address at all — an explicit one is never extended.
        assert!(Addrs::parse(&q(&[("myip", "192.0.2.1")])).unwrap().v6.is_none());
    }

    /// Parameters come from the query string; a form-encoded POST body is merged under it.
    #[test]
    fn params_from_query_and_form_body() {
        let mut form = HeaderMap::new();
        form.insert(
            axum::http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse().unwrap(),
        );

        // GET: no body, query only.
        let p = request_params(q(&[("hostname", "a.example.com")]), &HeaderMap::new(), "");
        assert_eq!(csv(&p, "hostname"), ["a.example.com"]);

        // POST with a form body — percent- and plus-decoded, comma lists intact.
        let p = request_params(HashMap::new(), &form, "hostname=a.example.com%2Cb.example.com&myip=192.0.2.1");
        assert_eq!(csv(&p, "hostname"), ["a.example.com", "b.example.com"]);
        assert_eq!(Addrs::parse(&p).unwrap().v4.as_deref(), Some("192.0.2.1"));

        // Both: the query string wins for a name in both places, body-only names still apply.
        let p = request_params(q(&[("myip", "192.0.2.1")]), &form, "myip=198.51.100.1&hostname=a.example.com");
        assert_eq!(p.get("myip").map(String::as_str), Some("192.0.2.1"));
        assert_eq!(csv(&p, "hostname"), ["a.example.com"]);

        // A body without the form content-type is ignored (it isn't dyndns2's transport).
        let p = request_params(HashMap::new(), &HeaderMap::new(), "hostname=a.example.com");
        assert!(csv(&p, "hostname").is_empty());
    }

    /// The `hostname` parameter must be a syntactic DNS name — junk is `notfqdn`, never a record.
    #[test]
    fn hostname_syntax() {
        assert!(dns::check::ddns_hostname("host.example.com").is_ok());
        assert!(dns::check::ddns_hostname("host.example.com.").is_ok());
        assert!(dns::check::ddns_hostname("host .example.com").is_err());
        // A comma-separated list is split before validation, so each name is checked on its own.
        let p = q(&[("hostname", "a.example.com,b .example.com")]);
        let hosts = csv(&p, "hostname");
        assert!(hosts.iter().any(|h| dns::check::ddns_hostname(h).is_err()));
    }
}
