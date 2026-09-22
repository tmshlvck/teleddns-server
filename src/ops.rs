//! Operability endpoints: `/healthcheck` (always 200; OK/WARN first token) and `/metrics`
//! (Prometheus text). Both read [`crate::stats::Stats`] — the same numbers the dashboard renders, so
//! a WARN here and a red banner there can never disagree. Source admission is applied by the
//! `allow_from` middleware — `ops_ip_src_allowed` on top of `ip_src_allowed` (see `net.rs`).

use crate::app::AppState;
use crate::backend::Probe;
use crate::stats::Stats;
use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};

/// GET /healthcheck — always HTTP 200; body first token is OK or WARN.
pub async fn healthcheck(State(app): State<AppState>) -> Response {
    let s = Stats::gather(&app).await;
    let first = if s.warnings(&app.cfg).is_empty() { "OK" } else { "WARN" };
    let knot = match s.status.probe {
        Probe::Up => "up",
        Probe::Down => "down",
        Probe::Na => "na",
    };
    let body = format!(
        "{first} uptime={uptime} zones={zones} records={records} pending={pending} failed={failed} \
         outofsync={oos} knot={knot} last_push={last_push}\n",
        uptime = s.uptime,
        zones = s.zones,
        records = s.records(),
        pending = s.unfinished(),
        failed = s.failed,
        oos = s.out_of_sync.max(0),
        last_push = s.last_push,
    );
    ([(header::CONTENT_TYPE, "text/plain")], body).into_response()
}

/// GET /metrics — refresh gauges from the DB, then render the Prometheus registry.
pub async fn metrics(State(app): State<AppState>) -> Response {
    let s = Stats::gather(&app).await;
    let m = &app.metrics;
    m.zones.set(s.zones as i64);
    for (typ, n) in &s.by_type {
        m.records_by_type.with_label_values(&[typ]).set(*n as i64);
    }
    m.records.set(s.records() as i64);
    for (state, n) in [
        (crate::model::sync_task::STATE_PENDING, s.pending),
        (crate::model::sync_task::STATE_IN_FLIGHT, s.in_flight),
        (crate::model::sync_task::STATE_FAILED, s.failed),
    ] {
        m.pending_pushes.with_label_values(&[state]).set(n as i64);
    }
    m.knot_up.set((s.status.probe == Probe::Up) as i64);
    m.worker_last_tick.set(s.last_tick);
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], m.render()).into_response()
}
