//! Native API zone endpoints. Reading/updating a zone needs Zone Manager on it; creating or deleting
//! one needs Superadmin. Create
//! auto-generates the SOA + apex NS; delete removes the zone, its records, and enqueues a Knot removal.

use super::{err, req_ip, require_bearer, Page};
use crate::app::AppState;
use crate::authz;
use crate::dns;
use crate::model::{now, rr, zone};
use crate::principal::Principal;
use axum::extract::{ConnectInfo, Path, Query, State};
use std::net::SocketAddr;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect,
};
use serde_json::{json, Value};
use std::collections::HashMap;

/// GET /api/zones — zones the caller can see (admins: all; others: zones they hold a grant on).
pub async fn list(
    State(app): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let who = match require_bearer(&app, &headers, peer).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let page = Page::from_query(&q);

    let visible = match visible_zone_ids(&app, &who).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mut query = zone::Entity::find().order_by_asc(zone::Column::Origin);
    if let Some(ids) = &visible {
        query = query.filter(zone::Column::Id.is_in(ids.clone()));
    }
    let total = match query.clone().count(&app.db).await {
        Ok(t) => t,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
    };
    let rows = match query
        .offset(page.offset() as u64)
        .limit(page.per_page)
        .all(&app.db)
        .await
    {
        Ok(r) => r,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
    };
    let data: Vec<Value> = rows.iter().map(zone_view).collect();
    (
        [("X-Total-Count", total.to_string())],
        Json(json!({ "data": data, "page": page.page, "per_page": page.per_page, "total": total })),
    )
        .into_response()
}

/// GET /api/zones/{id} — needs Zone Manager on it.
pub async fn get_one(
    State(app): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(id): Path<i32>,
) -> Response {
    let who = match require_bearer(&app, &headers, peer).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let Some(z) = load_zone(&app, id).await else {
        return err(StatusCode::NOT_FOUND, "zone not found");
    };
    if !zone_allowed(&app, &who, id).await {
        return err(StatusCode::FORBIDDEN, "insufficient access");
    }
    Json(zone_view(&z)).into_response()
}

/// POST /api/zones — needs Superadmin. Auto SOA + apex NS. Honors Idempotency-Key.
pub async fn create(
    State(app): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<Value>,
) -> Response {
    let who = match require_bearer(&app, &headers, peer).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    if !who.is_superadmin {
        return err(StatusCode::FORBIDDEN, "creating a zone requires Superadmin");
    }
    // Idempotency.
    let idem = super::idempotency::begin(&app, &who, &headers, &body).await;
    if let super::idempotency::Outcome::Replay(resp) = &idem {
        return resp.to_response();
    }
    if let super::idempotency::Outcome::Conflict = idem {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "Idempotency-Key reused with a different body");
    }

    let origin = match body.get("origin").and_then(|v| v.as_str()) {
        Some(o) if !o.is_empty() => dns::normalize_fqdn(o),
        _ => return err(StatusCode::BAD_REQUEST, "origin is required"),
    };
    if let Err(e) = dns::check::zone_origin(&origin) {
        return err(StatusCode::BAD_REQUEST, &e);
    }
    // Reject a duplicate origin.
    if zone::Entity::find().filter(zone::Column::Origin.eq(&origin)).one(&app.db).await.ok().flatten().is_some()
    {
        return err(StatusCode::CONFLICT, "zone already exists");
    }

    let am = zone::Model::new_defaults(&origin, app.cfg.default_ttl as i32);
    let z = match am.insert(&app.db).await {
        Ok(z) => z,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
    };
    // Default apex NS (fires the RR hook → serial bump + push).
    let ns = rr::ns::ActiveModel {
        id: NotSet,
        zone_id: Set(z.id),
        label: Set("@".into()),
        ttl: Set(z.ttl),
        value: Set(z.mname.clone()),
        ..Default::default()
    };
    let _ = ns.insert(&app.db).await;

    tracing::info!(actor = %who.username, source = "api", origin = %origin, "zone created");
    let view = zone_view(&z);
    app.audit
        .record("api", "create", format!("zone/{}", z.id), &who, "bearer",
                req_ip(&app, &headers, peer), None, Some(view.clone()))
        .await;
    let resp = super::idempotency::Stored { status: 201, body: view.clone() };
    super::idempotency::finish(&app, &who, &headers, &body, &resp).await;
    (StatusCode::CREATED, Json(view)).into_response()
}

/// PUT /api/zones/{id} — needs Zone Manager. Updates SOA fields; bumps the serial + enqueues a push.
pub async fn update(
    State(app): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(id): Path<i32>,
    Json(body): Json<Value>,
) -> Response {
    let who = match require_bearer(&app, &headers, peer).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let Some(z) = load_zone(&app, id).await else {
        return err(StatusCode::NOT_FOUND, "zone not found");
    };
    if !zone_allowed(&app, &who, id).await {
        return err(StatusCode::FORBIDDEN, "insufficient access");
    }
    let mut am: zone::ActiveModel = z.clone().into();
    // SOA name fields (MNAME/RNAME): validate as DNS names before storing.
    if let Some(v) = body.get("mname").and_then(|v| v.as_str()) {
        if let Err(e) = dns::check::target_name(v) {
            return err(StatusCode::UNPROCESSABLE_ENTITY, &format!("mname {e}"));
        }
        am.mname = Set(v.to_string());
    }
    if let Some(v) = body.get("rname").and_then(|v| v.as_str()) {
        if let Err(e) = dns::check::target_name(v) {
            return err(StatusCode::UNPROCESSABLE_ENTITY, &format!("rname {e}"));
        }
        am.rname = Set(v.to_string());
    }
    // SOA intervals + default TTL: range-check to their column width (TTL is the RFC 2181 form).
    for k in ["refresh", "retry", "expire", "minimum", "ttl"] {
        if let Some(v) = body.get(k).and_then(|v| v.as_i64()) {
            let check: fn(i64) -> Result<(), String> =
                if k == "ttl" { dns::check::ttl } else { dns::check::soa_interval };
            if let Err(e) = check(v) {
                return err(StatusCode::UNPROCESSABLE_ENTITY, &format!("{k} {e}"));
            }
            match k {
                "refresh" => am.refresh = Set(v as i32),
                "retry" => am.retry = Set(v as i32),
                "expire" => am.expire = Set(v as i32),
                "minimum" => am.minimum = Set(v as i32),
                "ttl" => am.ttl = Set(v as i32),
                _ => {}
            }
        }
    }
    // A zone SOA edit bumps the serial (content changed); the zone after_save hook enqueues a push.
    am.serial = Set(z.serial + 1);
    let before = zone_view(&z);
    let updated = match am.update(&app.db).await {
        Ok(z) => z,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")),
    };
    let view = zone_view(&updated);
    app.audit
        .record("api", "update", format!("zone/{id}"), &who, "bearer",
                req_ip(&app, &headers, peer), Some(before), Some(view.clone()))
        .await;
    Json(view).into_response()
}

/// DELETE /api/zones/{id} — needs Superadmin. Removes the zone + all its records and enqueues a Knot removal.
pub async fn delete(
    State(app): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(id): Path<i32>,
) -> Response {
    let who = match require_bearer(&app, &headers, peer).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    // Deleting a zone takes every record in it, so it stays with the Superadmin.
    if !who.is_superadmin {
        return err(StatusCode::FORBIDDEN, "deleting a zone requires Superadmin");
    }
    let Some(z) = load_zone(&app, id).await else {
        return err(StatusCode::NOT_FOUND, "zone not found");
    };
    // Delete all RRs of the zone across types, then the zone, then enqueue a removal.
    if let Err(e) = delete_all_rrs(&app, id).await {
        return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}"));
    }
    let _ = zone::Entity::delete_by_id(id).exec(&app.db).await;
    let _ = crate::sync::enqueue_remove(&app.db, &z.origin).await;
    tracing::info!(actor = %who.username, source = "api", origin = %z.origin, "zone deleted");
    let view = zone_view(&z);
    app.audit
        .record("api", "delete", format!("zone/{id}"), &who, "bearer",
                req_ip(&app, &headers, peer), Some(view.clone()), None)
        .await;
    Json(view).into_response()
}

// --- helpers ---

fn zone_view(z: &zone::Model) -> Value {
    json!({
        "id": z.id,
        "origin": z.origin,
        "mname": z.mname,
        "rname": z.rname,
        "serial": z.serial,
        "refresh": z.refresh,
        "retry": z.retry,
        "expire": z.expire,
        "minimum": z.minimum,
        "ttl": z.ttl,
    })
}

async fn load_zone(app: &AppState, id: i32) -> Option<zone::Model> {
    zone::Entity::find_by_id(id).one(&app.db).await.ok().flatten()
}

/// The set of zone ids visible to the caller; `None` means "all" (a Superadmin).
async fn visible_zone_ids(app: &AppState, who: &Principal) -> Result<Option<Vec<i32>>, Response> {
    if who.is_superadmin {
        return Ok(None);
    }
    if who.group_ids.is_empty() {
        return Ok(Some(vec![]));
    }
    let mut ids: Vec<i32> = crate::model::zone_role::Entity::find()
        .filter(crate::model::zone_role::Column::GroupId.is_in(who.group_ids.clone()))
        .all(&app.db)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")))?
        .into_iter()
        .map(|r| r.zone_id)
        .collect();
    let rr_ids: Vec<i32> = crate::model::rr_role::Entity::find()
        .filter(crate::model::rr_role::Column::GroupId.is_in(who.group_ids.clone()))
        .all(&app.db)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}")))?
        .into_iter()
        .map(|r| r.zone_id)
        .collect();
    ids.extend(rr_ids);
    ids.sort_unstable();
    ids.dedup();
    Ok(Some(ids))
}

/// Whether the caller manages this whole zone (Zone Manager grant, or Superadmin).
pub async fn zone_allowed(app: &AppState, who: &Principal, zone_id: i32) -> bool {
    authz::zone_manager(&app.db, &who.group_ids, who.is_superadmin, zone_id).await.unwrap_or(false)
}

async fn delete_all_rrs(app: &AppState, zone_id: i32) -> Result<(), sea_orm::DbErr> {
    macro_rules! d {
        ($ent:path, $col:path) => {
            <$ent>::delete_many().filter($col.eq(zone_id)).exec(&app.db).await?;
        };
    }
    d!(rr::a::Entity, rr::a::Column::ZoneId);
    d!(rr::aaaa::Entity, rr::aaaa::Column::ZoneId);
    d!(rr::ns::Entity, rr::ns::Column::ZoneId);
    d!(rr::ptr::Entity, rr::ptr::Column::ZoneId);
    d!(rr::cname::Entity, rr::cname::Column::ZoneId);
    d!(rr::txt::Entity, rr::txt::Column::ZoneId);
    d!(rr::mx::Entity, rr::mx::Column::ZoneId);
    d!(rr::srv::Entity, rr::srv::Column::ZoneId);
    d!(rr::caa::Entity, rr::caa::Column::ZoneId);
    d!(rr::sshfp::Entity, rr::sshfp::Column::ZoneId);
    d!(rr::tlsa::Entity, rr::tlsa::Column::ZoneId);
    d!(rr::dnskey::Entity, rr::dnskey::Column::ZoneId);
    d!(rr::ds::Entity, rr::ds::Column::ZoneId);
    d!(rr::naptr::Entity, rr::naptr::Column::ZoneId);
    let _ = now();
    Ok(())
}
