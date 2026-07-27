//! Operability endpoints: `/healthcheck` (always 200; OK/WARN first token) and `/metrics`
//! (Prometheus text). Both refresh DB-derived state on demand. IP gating is applied by the
//! whitelist middleware (see `net.rs`).

use crate::app::AppState;
use crate::backend::Probe;
use crate::model::{now, rr, sync_task, zone};
use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};
use std::sync::atomic::Ordering;

/// GET /healthcheck — always HTTP 200; body first token is OK or WARN.
pub async fn healthcheck(State(app): State<AppState>) -> Response {
    let uptime = now() - app.started_at;
    let zones = zone::Entity::find().count(&app.db).await.unwrap_or(0);
    let records = count_records(&app).await;
    let pending = sync_task::Entity::find()
        .filter(sync_task::Column::State.is_in([sync_task::STATE_PENDING, sync_task::STATE_IN_FLIGHT]))
        .count(&app.db)
        .await
        .unwrap_or(0);
    let failed = sync_task::Entity::find()
        .filter(sync_task::Column::State.eq(sync_task::STATE_FAILED))
        .count(&app.db)
        .await
        .unwrap_or(0);

    let probe = app.backend.probe().await;
    let knot = match probe {
        Probe::Up => "up",
        Probe::Down => "down",
        Probe::Na => "na",
    };
    let last_push = app.worker.last_push.load(Ordering::Relaxed);
    let last_tick = app.worker.last_tick.load(Ordering::Relaxed);
    // Zones Knot isn't serving at the DB serial (periodic reconcile); -1 = not yet computed / log backend.
    let out_of_sync = app.worker.out_of_sync.load(Ordering::Relaxed);

    // WARN conditions (past a short startup grace).
    let grace = 30;
    let mut warn = false;
    if uptime > grace {
        let period = app.cfg.backend_sync_period.as_secs() as i64;
        if last_tick > 0 && now() - last_tick > 2 * period {
            warn = true; // worker stalled
        }
        if failed > 0 {
            warn = true; // dead-lettered push
        }
        if matches!(probe, Probe::Down) {
            warn = true; // knot unreachable
        }
        if out_of_sync > 0 {
            warn = true; // Knot not serving the current serial for some zone(s)
        }
        if let Some(oldest) = oldest_unfinished(&app).await {
            if now() - oldest > app.cfg.warn_on_nopush.as_secs() as i64 {
                warn = true; // backlog stuck
            }
        }
    }

    let first = if warn { "WARN" } else { "OK" };
    let body = format!(
        "{first} uptime={uptime} zones={zones} records={records} pending={pending} failed={failed} outofsync={oos} knot={knot} last_push={last_push}\n",
        oos = out_of_sync.max(0),
    );
    ([(header::CONTENT_TYPE, "text/plain")], body).into_response()
}

/// GET /metrics — refresh gauges from the DB, then render the Prometheus registry.
pub async fn metrics(State(app): State<AppState>) -> Response {
    let m = &app.metrics;
    m.zones.set(zone::Entity::find().count(&app.db).await.unwrap_or(0) as i64);

    let mut total = 0i64;
    for (typ, n) in count_by_type(&app).await {
        m.records_by_type.with_label_values(&[typ]).set(n as i64);
        total += n as i64;
    }
    m.records.set(total);

    for state in [
        sync_task::STATE_PENDING,
        sync_task::STATE_IN_FLIGHT,
        sync_task::STATE_FAILED,
    ] {
        let n = sync_task::Entity::find()
            .filter(sync_task::Column::State.eq(state))
            .count(&app.db)
            .await
            .unwrap_or(0);
        m.pending_pushes.with_label_values(&[state]).set(n as i64);
    }

    let up = matches!(app.backend.probe().await, Probe::Up) as i64;
    m.knot_up.set(up);
    m.worker_last_tick.set(app.worker.last_tick.load(Ordering::Relaxed));

    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], m.render()).into_response()
}

async fn count_records(app: &AppState) -> u64 {
    count_by_type(app).await.iter().map(|(_, n)| n).sum()
}

/// Per-type record counts, in a stable order.
async fn count_by_type(app: &AppState) -> Vec<(&'static str, u64)> {
    macro_rules! c {
        ($ent:path, $typ:literal) => {
            ($typ, <$ent>::find().count(&app.db).await.unwrap_or(0))
        };
    }
    vec![
        c!(rr::a::Entity, "A"),
        c!(rr::aaaa::Entity, "AAAA"),
        c!(rr::ns::Entity, "NS"),
        c!(rr::ptr::Entity, "PTR"),
        c!(rr::cname::Entity, "CNAME"),
        c!(rr::txt::Entity, "TXT"),
        c!(rr::mx::Entity, "MX"),
        c!(rr::srv::Entity, "SRV"),
        c!(rr::caa::Entity, "CAA"),
        c!(rr::sshfp::Entity, "SSHFP"),
        c!(rr::tlsa::Entity, "TLSA"),
        c!(rr::dnskey::Entity, "DNSKEY"),
        c!(rr::ds::Entity, "DS"),
        c!(rr::naptr::Entity, "NAPTR"),
    ]
}

/// Created-at of the oldest unfinished (pending/in_flight) sync task.
async fn oldest_unfinished(app: &AppState) -> Option<i64> {
    use sea_orm::QueryOrder;
    sync_task::Entity::find()
        .filter(sync_task::Column::State.is_in([sync_task::STATE_PENDING, sync_task::STATE_IN_FLIGHT]))
        .order_by_asc(sync_task::Column::CreatedAt)
        .one(&app.db)
        .await
        .ok()
        .flatten()
        .map(|t| t.created_at)
}
