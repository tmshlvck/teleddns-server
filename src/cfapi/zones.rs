//! CF facade: zone listing. Returns zones the caller can see in CF shape (`id` as string,
//! `name` without the trailing dot, `status: active`). Supports `?name=` exact match.

use super::{authenticate, cf_err, ok_list};
use crate::app::AppState;
use crate::model::zone;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;

/// GET /client/v4/zones[?name=]
pub async fn list(
    State(app): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let who = match authenticate(&app, &headers, peer).await {
        Ok(p) => p,
        Err(r) => return r,
    };

    let rows = match zone::Entity::find().order_by_asc(zone::Column::Origin).all(&app.db).await {
        Ok(r) => r,
        Err(e) => return cf_err(StatusCode::INTERNAL_SERVER_ERROR, 1001, &format!("db: {e}")),
    };

    // CF `name` filter (given without trailing dot).
    let name_filter = q.get("name").map(|n| crate::dns::normalize_fqdn(n));

    let mut result: Vec<Value> = Vec::new();
    for z in rows {
        if let Some(nf) = &name_filter {
            if &z.origin != nf {
                continue;
            }
        }
        // Visibility: admins see all; others only zones they hold a grant on.
        if !who.is_superadmin && !has_any_grant(&app, &who, z.id).await {
            continue;
        }
        result.push(cf_zone(&z));
    }
    let n = result.len();
    ok_list(json!(result), n, 1, n as u64, n)
}

fn cf_zone(z: &zone::Model) -> Value {
    json!({
        "id": z.id.to_string(),
        "name": z.origin.trim_end_matches('.'),
        "status": "active",
    })
}

/// True if the caller holds any zone/rr grant on the zone (for CF zone visibility).
async fn has_any_grant(app: &AppState, who: &crate::principal::Principal, zone_id: i32) -> bool {
    if who.group_ids.is_empty() {
        return false;
    }
    let zr = crate::model::zone_role::Entity::find()
        .filter(crate::model::zone_role::Column::GroupId.is_in(who.group_ids.clone()))
        .filter(crate::model::zone_role::Column::ZoneId.eq(zone_id))
        .one(&app.db)
        .await
        .ok()
        .flatten()
        .is_some();
    if zr {
        return true;
    }
    crate::model::rr_role::Entity::find()
        .filter(crate::model::rr_role::Column::GroupId.is_in(who.group_ids.clone()))
        .filter(crate::model::rr_role::Column::ZoneId.eq(zone_id))
        .one(&app.db)
        .await
        .ok()
        .flatten()
        .is_some()
}
