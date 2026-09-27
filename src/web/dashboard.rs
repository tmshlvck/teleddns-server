//! The landing page: what this server is currently doing, for a person. Three panels, each a
//! question an operator actually asks — *is anything changing?* (update activity), *is every zone
//! live?* (zones), *is the machinery healthy?* (backend & sync) — over the numbers `/healthcheck`
//! and `/metrics` publish ([`crate::stats`]) plus the serial each zone is really answered with.
//!
//! Read-only by construction: nothing here posts. Changes happen in the console at `/admin`, and
//! every number links to the table it came from. The page refreshes itself on a `<meta>` timer, so
//! it can be left open on a wall display without a line of JavaScript.

use crate::app::AppState;
use crate::model::{now, sync_task, zone};
use crate::stats::{ago, Stats};
use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, Uri};
use axum::response::{Html, IntoResponse, Redirect, Response};
use relativelylight::time::Tz;
use sea_orm::{EntityTrait, QueryOrder};
use std::collections::HashMap;

/// How many zones the sync table lists before deferring to the console. Anything needing attention
/// sorts first, so the cap only ever hides healthy rows.
const ZONE_ROWS: usize = 25;

/// Dead-lettered origins named individually before it becomes a number.
const DEAD_LETTERS: usize = 5;

/// How often the page reloads itself, in seconds.
const REFRESH_SECS: u32 = 30;

/// A timestamp rendered both ways: absolute (in the viewer's zone, for correlating with Knot's logs
/// or syslog) and relative (for "is this fresh?"). Neither answers the other's question.
///
/// The timers this renders live in [`crate::backend::worker::WorkerHandle`] — three atomics, held
/// in memory and reset on every start. The *work* is durable (the `sync_task` journal survives a
/// restart, retry schedule and all); these are observation only. So a zero means "not since this
/// process started", **not** "never happened", and it says so rather than implying a history it
/// cannot see.
struct Stamp {
    absolute: String,
    relative: String,
}

impl Stamp {
    fn new(epoch: i64, tz: &Tz) -> Stamp {
        if epoch <= 0 {
            return Stamp { absolute: "none since restart".into(), relative: String::new() };
        }
        // `Tz::format` stops at minutes; every IANA offset is a whole number of minutes, so the
        // seconds are the same in any zone and can be appended from the epoch directly.
        Stamp {
            absolute: format!("{}:{:02} {}", tz.format(epoch), epoch.rem_euclid(60), tz.name()),
            relative: ago(epoch),
        }
    }
}

struct ZoneRow {
    id: i32,
    origin: String,
    db_serial: i64,
    live_serial: String,
    records: u64,
    queued: u64,
    badge: &'static str,
    badge_class: &'static str,
    /// Why it is in that state, when there is more to say (attempts, when it retries).
    note: String,
    /// Trouble first; not rendered.
    rank: u8,
}

struct TypeCount {
    name: &'static str,
    slug: String,
    count: u64,
}

struct Window {
    label: &'static str,
    counts: Vec<u64>,
    total: u64,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct Dashboard {
    refresh: u32,
    warnings: Vec<String>,
    // --- update activity ---
    /// The chart's `data` object, already JSON. Baked into the page rather than fetched: the server
    /// has the numbers, so a round trip to collect them again would be a JSON API existing purely to
    /// feed the browser — the thing 0.3 removed.
    chart_json: String,
    chart_span_hours: i64,
    surfaces: Vec<&'static str>,
    windows: Vec<Window>,
    // --- zones ---
    zones: Vec<ZoneRow>,
    zone_total: usize,
    more_zones: usize,
    records: u64,
    by_type: Vec<TypeCount>,
    // --- backend & sync ---
    backend_name: &'static str,
    backend_state: &'static str,
    backend_class: &'static str,
    backend_detail: Option<String>,
    backend_error: Option<String>,
    zones_served: Option<usize>,
    last_push: Stamp,
    last_tick: Stamp,
    pending: u64,
    in_flight: u64,
    failed: u64,
    retrying: u64,
    dead_letters: Vec<String>,
}

/// `GET /` — the dashboard, for a Superadmin. Everyone else is sent to their profile: this page and
/// the console are both Superadmin-only, and `/profile` (password, 2FA, API keys) is what a device
/// owner actually came for.
pub async fn page(headers: HeaderMap, uri: Uri, State(app): State<AppState>) -> Response {
    let Some(who) = app.auth.identify(&headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    if !app.auth.can_manage_others(&who) {
        return Redirect::to("/profile").into_response();
    }
    let tz = Tz::from_headers(&headers);
    let s = Stats::gather(&app).await;
    let journal = Journal::load(&app).await;
    let (zones, zone_total, served) = zone_rows(&app, &s, &journal).await;
    let chart_json = chart(&app, &tz).await;

    let page = Dashboard {
        refresh: REFRESH_SECS,
        warnings: s.warnings(&app.cfg),
        chart_json,
        chart_span_hours: crate::stats::CHART_SPAN / 3600,
        surfaces: crate::stats::SURFACES.iter().map(|(n, _)| *n).chain(["Console"]).collect(),
        windows: crate::stats::activity(&app)
            .await
            .into_iter()
            .map(|w| Window { label: w.label, counts: w.counts, total: w.total })
            .collect(),
        more_zones: zone_total.saturating_sub(zones.len()),
        zones,
        zone_total,
        records: s.records(),
        by_type: s
            .type_totals()
            .into_iter()
            .map(|(name, count)| TypeCount { name, slug: name.to_lowercase(), count })
            .collect(),
        backend_name: app.backend.name(),
        backend_state: match s.status.probe {
            crate::backend::Probe::Up => "up",
            crate::backend::Probe::Down => "down",
            crate::backend::Probe::Na => "n/a",
        },
        backend_class: match s.status.probe {
            crate::backend::Probe::Up => "text-bg-success",
            crate::backend::Probe::Down => "text-bg-danger",
            crate::backend::Probe::Na => "text-bg-secondary",
        },
        backend_detail: s.status.detail.clone(),
        backend_error: s.status.error.clone(),
        zones_served: served,
        last_push: Stamp::new(s.last_push, &tz),
        last_tick: Stamp::new(s.last_tick, &tz),
        pending: s.pending,
        in_flight: s.in_flight,
        failed: s.failed,
        retrying: journal.retrying,
        dead_letters: journal.dead_letters.clone(),
    };
    match page.render() {
        Ok(body) => Html(
            super::Shell::page("Dashboard — teleddns", &who, &uri, &headers, body)
                .refresh_every(REFRESH_SECS)
                .html(),
        )
        .into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ===================== the push journal, read once =====================

/// The state of every outstanding push, keyed by origin — so the zones panel can say *why* a zone
/// is behind instead of only that it is. One query, not one per zone.
struct Journal {
    by_origin: HashMap<String, Vec<sync_task::Model>>,
    retrying: u64,
    dead_letters: Vec<String>,
}

impl Journal {
    async fn load(app: &AppState) -> Journal {
        let tasks = sync_task::Entity::find()
            .order_by_asc(sync_task::Column::CreatedAt)
            .all(&app.db)
            .await
            .unwrap_or_default();
        let mut by_origin: HashMap<String, Vec<sync_task::Model>> = HashMap::new();
        let mut retrying = 0;
        let mut dead_letters = Vec::new();
        for t in tasks {
            // "Retrying" is a pending row that has already failed at least once and is waiting out
            // its backoff — worth separating from a fresh enqueue, which is waiting out the debounce.
            if t.state == sync_task::STATE_PENDING && t.attempts > 0 {
                retrying += 1;
            }
            if t.state == sync_task::STATE_FAILED && dead_letters.len() < DEAD_LETTERS {
                dead_letters.push(t.origin.clone());
            }
            by_origin.entry(t.origin.clone()).or_default().push(t);
        }
        Journal { by_origin, retrying, dead_letters }
    }

    /// The most alarming thing outstanding for this origin.
    fn status_of(&self, origin: &str) -> Option<(&'static str, &'static str, String, u8)> {
        let tasks = self.by_origin.get(origin)?;
        if let Some(t) = tasks.iter().find(|t| t.state == sync_task::STATE_FAILED) {
            return Some((
                "failed",
                "text-bg-danger",
                format!("gave up after {} attempts", t.attempts),
                0,
            ));
        }
        if tasks.iter().any(|t| t.state == sync_task::STATE_IN_FLIGHT) {
            return Some(("pushing", "text-bg-info", "being pushed now".into(), 1));
        }
        let pending = tasks.iter().find(|t| t.state == sync_task::STATE_PENDING)?;
        let wait = pending.available_at - now();
        Some(if pending.attempts > 0 {
            (
                "retrying",
                "text-bg-warning",
                format!(
                    "attempt {} of {}{}",
                    pending.attempts + 1,
                    crate::backend::worker::MAX_ATTEMPTS,
                    if wait > 0 { format!(", in {wait}s") } else { String::new() }
                ),
                1,
            )
        } else if wait > 0 {
            ("queued", "text-bg-info", format!("debouncing, due in {wait}s"), 2)
        } else {
            ("queued", "text-bg-info", "due now".into(), 2)
        })
    }
}

// ===================== zones =====================

/// One row per zone: its serial against the backend's, what it holds, and what it is waiting on.
async fn zone_rows(
    app: &AppState,
    s: &Stats,
    journal: &Journal,
) -> (Vec<ZoneRow>, usize, Option<usize>) {
    let zones = zone::Entity::find()
        .order_by_asc(zone::Column::Origin)
        .all(&app.db)
        .await
        .unwrap_or_default();
    // `Ok(None)` = a backend that cannot report serials (the `log` one); an `Err` is a backend that
    // is down, which the backend panel already says. Both render as "unknown", never as a drift.
    let served: Option<HashMap<String, i64>> = app.backend.zone_serials().await.ok().flatten();
    let per_zone = s.per_zone();

    let mut rows: Vec<ZoneRow> = zones
        .into_iter()
        .map(|z| {
            let live = served.as_ref().map(|m| m.get(&z.origin).copied());
            let queued = journal.by_origin.get(&z.origin).map(|v| v.len()).unwrap_or(0) as u64;
            // What the journal is doing wins: a zone with a push outstanding is not "behind", it is
            // mid-flight, and saying so is the difference between "normal" and "go and look".
            let (badge, badge_class, note, rank) = journal.status_of(&z.origin).unwrap_or_else(|| {
                match live {
                    None => ("unknown", "text-bg-secondary", "backend cannot report".into(), 3),
                    Some(None) => ("not served", "text-bg-danger", "missing from the backend".into(), 0),
                    Some(Some(n)) if n == z.serial => ("in sync", "text-bg-success", String::new(), 4),
                    Some(Some(n)) if n < z.serial => (
                        "behind",
                        "text-bg-warning",
                        "no push queued — re-save the zone".into(),
                        0,
                    ),
                    Some(Some(_)) => ("ahead", "text-bg-secondary", "backend is newer".into(), 0),
                }
            });
            ZoneRow {
                id: z.id,
                origin: z.origin,
                db_serial: z.serial,
                live_serial: live.flatten().map(|n| n.to_string()).unwrap_or_else(|| "—".into()),
                records: per_zone.get(&z.id).copied().unwrap_or(0),
                queued,
                badge,
                badge_class,
                note,
                rank,
            }
        })
        .collect();
    rows.sort_by_key(|r| r.rank); // stable: origin order survives inside a rank

    let total = rows.len();
    rows.truncate(ZONE_ROWS);
    (rows, total, served.map(|m| m.len()))
}

// ===================== the activity chart =====================

/// One colour per surface, in `SURFACES` order then Console. Fixed hex rather than Bootstrap's
/// variables, which flip with the colour mode; these stay legible in both.
const COLOURS: [&str; 4] = ["#0d6efd", "#198754", "#fd7e14", "#6f42c1"];

/// The chart's `data`, as JSON for Chart.js.
///
/// The x labels are formatted **here**, in the zone the picker chose, so the chart agrees with every
/// other timestamp on the page and the browser needs no date library or timezone of its own — which
/// is also why this is a category axis rather than a time axis.
async fn chart(app: &AppState, tz: &Tz) -> String {
    let (series, first_bucket) = crate::stats::activity_series(app).await;

    let labels: Vec<String> = (0..crate::stats::CHART_POINTS)
        .map(|i| {
            let at = first_bucket + i as i64 * crate::stats::CHART_BUCKET;
            // `Tz::format` is "YYYY-MM-DD HH:MM"; an axis wants the clock.
            let stamp = tz.format(at);
            stamp.split_once(' ').map(|(_, t)| t.to_string()).unwrap_or(stamp)
        })
        .collect();

    let datasets: Vec<serde_json::Value> = series
        .iter()
        .enumerate()
        .map(|(i, (name, values))| {
            let colour = COLOURS[i % COLOURS.len()];
            serde_json::json!({
                "label": name,
                "data": values,
                "borderColor": colour,
                // The same colour at ~18% alpha, for the area under the line.
                "backgroundColor": format!("{colour}2e"),
                "borderWidth": 1.5,
                "pointRadius": 0,
                "pointHoverRadius": 3,
                "fill": true,
                "tension": 0.25,
            })
        })
        .collect();

    let json = serde_json::json!({ "labels": labels, "datasets": datasets }).to_string();
    // The payload sits in a `<script type="application/json">`, which ends at the first `</script`
    // *whatever* the content type. A label can only be a time and a series name is a constant, so
    // this cannot bite today — but it is one escaping rule away from being an injection if either
    // ever becomes data, and the fix is cheaper than the audit.
    json.replace('<', "\\u003c")
}
