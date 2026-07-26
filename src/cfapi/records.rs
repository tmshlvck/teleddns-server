//! CF facade: DNS record CRUD, mapping CF's `{type, name(FQDN), content, ttl, priority}` onto the
//! native `(zone, label, value)` and reusing the native validation + write path (record_view).
//! Supported types: A, AAAA, CNAME, TXT, NS, MX. Level scoping mirrors the native API.

use super::{authenticate, cf_err, ok, ok_list};
use crate::app::AppState;
use crate::api::record_view;
use crate::api::req_ip;
use crate::api::zones::zone_allowed;
use crate::authz::{self, Level};
use crate::dns;
use crate::model::zone;
use crate::principal::Principal;
use axum::extract::{ConnectInfo, Path, Query, State};
use std::net::SocketAddr;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use sea_orm::EntityTrait;
use serde_json::{json, Value};
use std::collections::HashMap;

const SUPPORTED: &[&str] = &["A", "AAAA", "CNAME", "TXT", "NS", "MX"];

async fn zone_or_err(app: &AppState, id: i32) -> Result<zone::Model, Response> {
    zone::Entity::find_by_id(id)
        .one(&app.db)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| cf_err(StatusCode::NOT_FOUND, 1003, "zone not found"))
}

/// GET /client/v4/zones/{id}/dns_records — list (CF shape), `?type`/`?name`/`?content` filters.
pub async fn list(
    State(app): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(zid): Path<i32>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let who = match authenticate(&app, &headers, peer).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let zone = match zone_or_err(&app, zid).await {
        Ok(z) => z,
        Err(r) => return r,
    };
    if !zone_allowed(&app, &who, zid, Level::L1).await && !zone_allowed(&app, &who, zid, Level::L2).await {
        // A reader needs at least some zone-wide access to list; keep it simple (L1 zone-wide/L2).
        return cf_err(StatusCode::FORBIDDEN, 1002, "insufficient access");
    }
    let type_filter = q.get("type").cloned();
    let views = match record_view::collect_views(&app.db, zid, type_filter.as_deref(), None).await {
        Ok(v) => v,
        Err(e) => return map_err(e),
    };
    // CF `name` filter is a full FQDN; translate to a label match.
    let name_label = q.get("name").map(|n| dns::label_in_zone(n, &zone.origin));
    let mut result: Vec<Value> = Vec::new();
    for v in &views {
        let t = v["type"].as_str().unwrap_or("");
        if !SUPPORTED.contains(&t) {
            continue;
        }
        if let Some(nl) = &name_label {
            if v["name"].as_str().unwrap_or("") != nl {
                continue;
            }
        }
        if let Some(c) = q.get("content") {
            if content_of(v) != *c {
                continue;
            }
        }
        result.push(cf_record(v, &zone));
    }
    let n = result.len();
    ok_list(json!(result), n, 1, n as u64, n)
}

/// GET /client/v4/zones/{id}/dns_records/{rid}
pub async fn get_one(
    State(app): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path((zid, rid)): Path<(i32, String)>,
) -> Response {
    let who = match authenticate(&app, &headers, peer).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let zone = match zone_or_err(&app, zid).await {
        Ok(z) => z,
        Err(r) => return r,
    };
    let view = match record_view::get_record(&app.db, zid, &rid).await {
        Ok(v) => v,
        Err(e) => return map_err(e),
    };
    let label = view["name"].as_str().unwrap_or("@");
    let typ = view["type"].as_str().unwrap_or("");
    if !read_ok(&app, &who, zid, typ, label).await {
        return cf_err(StatusCode::FORBIDDEN, 1002, "insufficient access");
    }
    ok(cf_record(&view, &zone))
}

/// POST /client/v4/zones/{id}/dns_records
pub async fn create(
    State(app): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(zid): Path<i32>,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    let who = match authenticate(&app, &headers, peer).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let zone = match zone_or_err(&app, zid).await {
        Ok(z) => z,
        Err(r) => return r,
    };
    if !zone_allowed(&app, &who, zid, Level::L2).await {
        return cf_err(StatusCode::FORBIDDEN, 1002, "record create requires L2 on the zone");
    }
    let native = match cf_to_native(&body, &zone) {
        Ok(n) => n,
        Err(m) => return cf_err(StatusCode::BAD_REQUEST, 1004, &m),
    };
    match record_view::create_record(&app.db, zid, ttl_of(&body, &app), &native).await {
        Ok(v) => {
            tracing::info!(actor = %who.username, source = "cfapi", zone = %zone.origin, "cf record created");
            let target = format!("rr/{}", v.get("id").and_then(|x| x.as_str()).unwrap_or(""));
            app.audit
                .record("cfapi", "create", target, &who, cf_auth_type(&headers),
                        req_ip(&app, &headers, peer), None, Some(v.clone()))
                .await;
            ok(cf_record(&v, &zone))
        }
        Err(e) => map_err(e),
    }
}

/// CF auth type: `X-Auth-Key` header vs `Authorization: Bearer`.
fn cf_auth_type(headers: &HeaderMap) -> &'static str {
    if headers.contains_key("x-auth-key") {
        "x-auth-key"
    } else {
        "bearer"
    }
}

/// PUT/PATCH /client/v4/zones/{id}/dns_records/{rid}
pub async fn update(
    State(app): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path((zid, rid)): Path<(i32, String)>,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    let who = match authenticate(&app, &headers, peer).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let zone = match zone_or_err(&app, zid).await {
        Ok(z) => z,
        Err(r) => return r,
    };
    // Existing record → check level on its label.
    let existing = match record_view::get_record(&app.db, zid, &rid).await {
        Ok(v) => v,
        Err(e) => return map_err(e),
    };
    let typ = existing["type"].as_str().unwrap_or("");
    let label = existing["name"].as_str().unwrap_or("@");
    if !write_ok(&app, &who, zid, typ, label).await {
        return cf_err(StatusCode::FORBIDDEN, 1002, "insufficient access");
    }
    let native = match cf_to_native(&body, &zone) {
        Ok(n) => n,
        Err(m) => return cf_err(StatusCode::BAD_REQUEST, 1004, &m),
    };
    match record_view::update_record(&app.db, zid, &rid, ttl_of(&body, &app), &native).await {
        Ok(v) => {
            app.audit
                .record("cfapi", "update", format!("rr/{rid}"), &who, cf_auth_type(&headers),
                        req_ip(&app, &headers, peer), Some(existing), Some(v.clone()))
                .await;
            ok(cf_record(&v, &zone))
        }
        Err(e) => map_err(e),
    }
}

/// DELETE /client/v4/zones/{id}/dns_records/{rid}
pub async fn delete(
    State(app): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path((zid, rid)): Path<(i32, String)>,
) -> Response {
    let who = match authenticate(&app, &headers, peer).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    if zone_or_err(&app, zid).await.is_err() {
        return cf_err(StatusCode::NOT_FOUND, 1003, "zone not found");
    }
    if !zone_allowed(&app, &who, zid, Level::L2).await {
        return cf_err(StatusCode::FORBIDDEN, 1002, "record delete requires L2 on the zone");
    }
    match record_view::delete_record(&app.db, zid, &rid).await {
        // CF returns { id } on delete.
        Ok(v) => {
            app.audit
                .record("cfapi", "delete", format!("rr/{rid}"), &who, cf_auth_type(&headers),
                        req_ip(&app, &headers, peer), Some(v), None)
                .await;
            ok(json!({ "id": rid }))
        }
        Err(e) => map_err(e),
    }
}

// --- CF <-> native mapping ---

/// CF record shape from a native view + its zone.
fn cf_record(v: &Value, zone: &zone::Model) -> Value {
    let label = v["name"].as_str().unwrap_or("@");
    let typ = v["type"].as_str().unwrap_or("");
    let mut o = json!({
        "id": v["id"],
        "type": typ,
        "name": dns::fqdn_of(label, &zone.origin).trim_end_matches('.'),
        "content": content_of(v),
        "ttl": v["ttl"],
        "proxied": false,
        "zone_id": zone.id.to_string(),
        "zone_name": zone.origin.trim_end_matches('.'),
    });
    if typ == "MX" {
        o["priority"] = v.get("priority").cloned().unwrap_or(json!(0));
    }
    o
}

/// The CF `content` string for a native view.
fn content_of(v: &Value) -> String {
    v.get("value").and_then(|x| x.as_str()).unwrap_or("").to_string()
}

/// Translate a CF create/update body into a native record body.
fn cf_to_native(body: &Value, zone: &zone::Model) -> Result<Value, String> {
    let typ = body.get("type").and_then(|v| v.as_str()).ok_or("type is required")?.to_ascii_uppercase();
    if !SUPPORTED.contains(&typ.as_str()) {
        return Err(format!("unsupported record type: {typ}"));
    }
    let name = body.get("name").and_then(|v| v.as_str()).ok_or("name is required")?;
    // CF `name` is a full FQDN and must live inside this zone. Without the check, a name from
    // another zone (or plain junk) would be taken as a *relative* label and stored as
    // `<name>.<origin>` — a record nobody asked for. The label itself is then validated by the
    // native write path (`dns::check::record_label`).
    let fqdn = dns::normalize_fqdn(name);
    if fqdn != zone.origin && !fqdn.ends_with(&format!(".{}", zone.origin)) {
        return Err(format!(
            "name {name:?} is not inside zone {}",
            zone.origin.trim_end_matches('.')
        ));
    }
    let label = dns::label_in_zone(name, &zone.origin);
    let content = body.get("content").and_then(|v| v.as_str()).ok_or("content is required")?;
    let mut native = json!({ "type": typ, "name": label, "value": content });
    if let Some(ttl) = body.get("ttl").and_then(|v| v.as_i64()) {
        if ttl > 1 {
            native["ttl"] = json!(ttl);
        }
    }
    if typ == "MX" {
        let prio = body.get("priority").and_then(|v| v.as_i64()).unwrap_or(10);
        native["priority"] = json!(prio);
    }
    Ok(native)
}

/// Effective TTL for a CF write (`1` = automatic → default_ttl).
fn ttl_of(body: &Value, app: &AppState) -> i32 {
    match body.get("ttl").and_then(|v| v.as_i64()) {
        Some(t) if t > 1 => t as i32,
        _ => app.cfg.default_ttl as i32,
    }
}

fn map_err(e: record_view::ApiError) -> Response {
    use record_view::ApiError::*;
    match e {
        NotFound => cf_err(StatusCode::NOT_FOUND, 1003, "record not found"),
        BadType(t) => cf_err(StatusCode::BAD_REQUEST, 1004, &format!("unknown record type: {t}")),
        Validation(m) => cf_err(StatusCode::BAD_REQUEST, 1004, &m),
        Db(e) => cf_err(StatusCode::INTERNAL_SERVER_ERROR, 1001, &format!("db: {e}")),
    }
}

async fn read_ok(app: &AppState, who: &Principal, zid: i32, typ: &str, label: &str) -> bool {
    if record_view::is_addr_type(typ) {
        let eff = authz::effective_level(&app.db, &who.group_ids, who.is_admin, zid, Some(label))
            .await
            .unwrap_or(Level::None);
        authz::allowed(who.token_level, eff, Level::L1)
    } else {
        zone_allowed(app, who, zid, Level::L2).await
    }
}

async fn write_ok(app: &AppState, who: &Principal, zid: i32, typ: &str, label: &str) -> bool {
    read_ok(app, who, zid, typ, label).await
}
