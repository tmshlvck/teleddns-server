//! Native API record endpoints over the unified view. List needs L2; A/AAAA read+update need L1 (on
//! the record's label); other reads/updates and any create/delete need L2. Pagination + `?type`/
//! `?name` filters + `X-Total-Count`; POST honors Idempotency-Key.

use super::record_view;
use super::zones::zone_allowed;
use super::{err, map_api_error, req_ip, require_bearer, Page};
use crate::app::AppState;
use crate::authz::{self, Level};
use crate::model::zone;
use crate::principal::Principal;
use axum::extract::{ConnectInfo, Path, Query, State};
use std::net::SocketAddr;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use sea_orm::EntityTrait;
use serde_json::{json, Value};
use std::collections::HashMap;

async fn zone_or_404(app: &AppState, id: i32) -> Result<zone::Model, Response> {
    zone::Entity::find_by_id(id)
        .one(&app.db)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "zone not found"))
}

/// GET /api/zones/{id}/rr — list (L2), paginated, `?type`/`?name` filters, `X-Total-Count`.
pub async fn list(
    State(app): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(id): Path<i32>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let who = match require_bearer(&app, &headers, peer).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(r) = zone_or_404(&app, id).await {
        return r;
    }
    if !zone_allowed(&app, &who, id, Level::L2).await {
        return err(StatusCode::FORBIDDEN, "insufficient access");
    }
    let page = Page::from_query(&q);
    let all = match record_view::collect_views(&app.db, id, q.get("type").map(String::as_str), q.get("name").map(String::as_str)).await {
        Ok(v) => v,
        Err(e) => return map_api_error(e),
    };
    let total = all.len();
    let window: Vec<Value> = all.into_iter().skip(page.offset()).take(page.per_page as usize).collect();
    (
        [("X-Total-Count", total.to_string())],
        Json(json!({ "data": window, "page": page.page, "per_page": page.per_page, "total": total })),
    )
        .into_response()
}

/// GET /api/zones/{id}/rr/{rrid} — A/AAAA need L1 on the label; else L2.
pub async fn get_one(
    State(app): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path((id, rrid)): Path<(i32, String)>,
) -> Response {
    let who = match require_bearer(&app, &headers, peer).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(r) = zone_or_404(&app, id).await {
        return r;
    }
    let view = match record_view::get_record(&app.db, id, &rrid).await {
        Ok(v) => v,
        Err(e) => return map_api_error(e),
    };
    let typ = record_view::type_of_id(&rrid).unwrap_or("");
    let label = view.get("name").and_then(|n| n.as_str()).unwrap_or("@");
    if !read_allowed(&app, &who, id, typ, label).await {
        return err(StatusCode::FORBIDDEN, "insufficient access");
    }
    Json(view).into_response()
}

/// POST /api/zones/{id}/rr — create (L2). Honors Idempotency-Key.
pub async fn create(
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
    if let Err(r) = zone_or_404(&app, id).await {
        return r;
    }
    // Create of any type needs L2 on the zone.
    if !zone_allowed(&app, &who, id, Level::L2).await {
        return err(StatusCode::FORBIDDEN, "record create requires L2 on the zone");
    }
    match super::idempotency::begin(&app, &who, &headers, &body).await {
        super::idempotency::Outcome::Replay(s) => return s.to_response(),
        super::idempotency::Outcome::Conflict => {
            return err(StatusCode::UNPROCESSABLE_ENTITY, "Idempotency-Key reused with a different body")
        }
        super::idempotency::Outcome::Proceed => {}
    }
    let view = match record_view::create_record(&app.db, id, app.cfg.default_ttl as i32, &body).await {
        Ok(v) => v,
        Err(e) => return map_api_error(e),
    };
    tracing::info!(actor = %who.username, source = "api", zone_id = id, "record created");
    let target = format!("rr/{}", view.get("id").and_then(|v| v.as_str()).unwrap_or(""));
    app.audit
        .record("api", "create", target, &who, "bearer",
                req_ip(&app, &headers, peer), None, Some(view.clone()))
        .await;
    let stored = super::idempotency::Stored { status: 201, body: view.clone() };
    super::idempotency::finish(&app, &who, &headers, &body, &stored).await;
    (StatusCode::CREATED, Json(view)).into_response()
}

/// PUT /api/zones/{id}/rr/{rrid} — A/AAAA need L1 on the label; else L2.
pub async fn update(
    State(app): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path((id, rrid)): Path<(i32, String)>,
    Json(body): Json<Value>,
) -> Response {
    let who = match require_bearer(&app, &headers, peer).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(r) = zone_or_404(&app, id).await {
        return r;
    }
    // Determine the record's current label for the L1 check.
    let existing = match record_view::get_record(&app.db, id, &rrid).await {
        Ok(v) => v,
        Err(e) => return map_api_error(e),
    };
    let typ = record_view::type_of_id(&rrid).unwrap_or("");
    let label = existing.get("name").and_then(|n| n.as_str()).unwrap_or("@");
    if !write_allowed(&app, &who, id, typ, label).await {
        return err(StatusCode::FORBIDDEN, "insufficient access");
    }
    let view = match record_view::update_record(&app.db, id, &rrid, app.cfg.default_ttl as i32, &body).await {
        Ok(v) => v,
        Err(e) => return map_api_error(e),
    };
    app.audit
        .record("api", "update", format!("rr/{rrid}"), &who, "bearer",
                req_ip(&app, &headers, peer), Some(existing), Some(view.clone()))
        .await;
    Json(view).into_response()
}

/// DELETE /api/zones/{id}/rr/{rrid} — needs L2.
pub async fn delete(
    State(app): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path((id, rrid)): Path<(i32, String)>,
) -> Response {
    let who = match require_bearer(&app, &headers, peer).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(r) = zone_or_404(&app, id).await {
        return r;
    }
    if !zone_allowed(&app, &who, id, Level::L2).await {
        return err(StatusCode::FORBIDDEN, "record delete requires L2 on the zone");
    }
    match record_view::delete_record(&app.db, id, &rrid).await {
        Ok(v) => {
            app.audit
                .record("api", "delete", format!("rr/{rrid}"), &who, "bearer",
                        req_ip(&app, &headers, peer), Some(v.clone()), None)
                .await;
            Json(v).into_response()
        }
        Err(e) => map_api_error(e),
    }
}

/// Read gate: A/AAAA → L1 on the label; other types → L2 on the zone.
async fn read_allowed(app: &AppState, who: &Principal, zone_id: i32, typ: &str, label: &str) -> bool {
    if record_view::is_addr_type(typ) {
        let eff = authz::effective_level(&app.db, &who.group_ids, who.is_admin, zone_id, Some(label))
            .await
            .unwrap_or(Level::None);
        authz::allowed(who.token_level, eff, Level::L1)
    } else {
        zone_allowed(app, who, zone_id, Level::L2).await
    }
}

/// Update gate: same shape as read (A/AAAA → L1, else L2).
async fn write_allowed(app: &AppState, who: &Principal, zone_id: i32, typ: &str, label: &str) -> bool {
    read_allowed(app, who, zone_id, typ, label).await
}
