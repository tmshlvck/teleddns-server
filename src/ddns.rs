//! The dyndns2 DDNS endpoint (PRD §2). Three GET paths behave identically; a non-GET is 405. Auth is
//! HTTP Basic or Bearer; per-record authorization is L1; the path only ever creates/updates A and
//! AAAA (never deletes). On any data change it bumps the SOA serial and enqueues a push (via the RR
//! after_save hook). The response body uses dyndns2 vocabulary; the HTTP status is authoritative.

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

/// A single-family update result in dyndns2 vocabulary.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    Good(String),
    Nochg(String),
    NotFqdn,
    BadAuth,
    NotYours,
    NoHost,
    Abuse,
    Error,
}

impl Outcome {
    fn status(&self) -> StatusCode {
        match self {
            Outcome::Good(_) | Outcome::Nochg(_) => StatusCode::OK,
            Outcome::NotFqdn => StatusCode::BAD_REQUEST,
            Outcome::BadAuth => StatusCode::UNAUTHORIZED,
            Outcome::NotYours => StatusCode::FORBIDDEN,
            Outcome::NoHost => StatusCode::NOT_FOUND,
            Outcome::Abuse => StatusCode::TOO_MANY_REQUESTS,
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
            Outcome::Abuse => "abuse".into(),
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
            Outcome::Abuse => "abuse",
            Outcome::Error => "error",
        }
    }
}

/// GET /nic/update | /ddns/update | /update
pub async fn update(
    State(app): State<AppState>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    // Real client IP (post proxy rewrite) for the audit log + the request log line.
    let ip = crate::net::resolve_ip(app.cfg.trust_proxy, &headers, Some(peer.ip()));
    let ip_s = ip.map(|i| i.to_string()).unwrap_or_else(|| "-".into());
    let ua = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();

    // --- authenticate ---
    let principal = match authenticate(&app, &headers).await {
        Ok(p) => p,
        Err(o) => return finish(&app, &[o], "-", &ua),
    };

    // --- parse hostname ---
    let Some(hostname) = params.get("hostname").map(|s| s.trim()).filter(|s| !s.is_empty()) else {
        return finish(&app, &[Outcome::NotFqdn], &principal.username, &ua);
    };

    // Collect requested (family, address) pairs.
    let mut families: Vec<(Family, String)> = Vec::new();
    if let Some(myip) = params.get("myip").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if dns::is_ipv4(myip) {
            families.push((Family::V4, myip.to_string()));
        } else if dns::is_ipv6(myip) {
            families.push((Family::V6, myip.to_string()));
        } else {
            return finish(&app, &[Outcome::NotFqdn], &principal.username, &ua);
        }
    }
    if let Some(v6) = params.get("myipv6").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if dns::is_ipv6(v6) {
            families.push((Family::V6, v6.to_string()));
        } else {
            return finish(&app, &[Outcome::NotFqdn], &principal.username, &ua);
        }
    }
    if families.is_empty() {
        return finish(&app, &[Outcome::NotFqdn], &principal.username, &ua);
    }

    // --- resolve zone/label ---
    let (zone, label) = match dns::resolve_zone(&app.db, hostname).await {
        Ok(Some(zl)) => zl,
        Ok(None) => return finish(&app, &[Outcome::NoHost], &principal.username, &ua),
        Err(_) => return finish(&app, &[Outcome::Error], &principal.username, &ua),
    };

    let auth_type = if principal.key_id.is_some() { "bearer" } else { "basic" };
    let mut outcomes = Vec::new();
    for (family, addr) in families {
        let o = update_one(&app, &principal, &zone, &label, family, &addr, ip, auth_type).await;
        tracing::info!(
            actor = %principal.username, source = principal.source.as_str(), src = %ip_s, ua = %ua,
            zone = %zone.origin, label = %label, family = ?family, addr = %addr,
            result = o.label(), "ddns update"
        );
        outcomes.push(o);
    }
    finish(&app, &outcomes, &principal.username, &ua)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

/// Authenticate a DDNS request (Bearer wins over Basic).
async fn authenticate(app: &AppState, headers: &HeaderMap) -> Result<Principal, Outcome> {
    if principal::bearer_token(headers).is_some() {
        return match principal::from_bearer(&app.db, headers, Source::Ddns).await {
            Ok(Some(p)) => Ok(p),
            _ => Err(Outcome::BadAuth),
        };
    }
    if let Some((u, p)) = principal::basic_creds(headers) {
        return match principal::from_basic(&app.db, &u, &p).await {
            Ok(pr) => Ok(pr),
            Err(AuthError::BasicNotAllowed) | Err(AuthError::BadAuth) => Err(Outcome::BadAuth),
        };
    }
    Err(Outcome::BadAuth)
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

    // Rate limit (per record + per token).
    let token_key = format!("tok:{}", principal.key_id.map(|k| k.to_string()).unwrap_or_else(|| format!("u{}", principal.user_id)));
    let record_key = format!("rec:{}:{}:{:?}", zone.id, label, family);
    if !app.ratelimit.allow_update(&token_key, &record_key) {
        app.metrics.ratelimit_hit("ddns");
        return Outcome::Abuse;
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

/// Combine per-family outcomes into a response: worst HTTP status, `\n`-joined body.
fn finish(app: &AppState, outcomes: &[Outcome], _actor: &str, _ua: &str) -> Response {
    for o in outcomes {
        app.metrics.ddns_update(o.label());
    }
    let status = outcomes.iter().map(|o| o.status()).max_by_key(|s| s.as_u16()).unwrap_or(StatusCode::OK);
    let body = outcomes.iter().map(|o| o.body()).collect::<Vec<_>>().join("\n");
    (status, [(axum::http::header::CONTENT_TYPE, "text/plain")], body).into_response()
}

/// POST etc. are rejected.
pub async fn reject_non_get() -> Response {
    (StatusCode::METHOD_NOT_ALLOWED, "method not allowed").into_response()
}
