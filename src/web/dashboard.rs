//! The landing page: what this server is currently doing, for a person. It renders the numbers
//! `/healthcheck` and `/metrics` publish ([`crate::stats`]) plus the one thing neither can show in a
//! line of text — the serial each zone is *actually* being answered with, beside the serial in the
//! database.
//!
//! Read-only by construction: nothing here posts. Changes happen in the console at `/admin`, and
//! every number on this page links to the table it came from.

use crate::app::AppState;
use crate::model::{sync_task, zone};
use crate::stats::{ago, Stats, Window, SURFACES};
use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, Uri};
use axum::response::{Html, IntoResponse, Redirect, Response};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use std::collections::{HashMap, HashSet};

/// How many zones the sync table lists before deferring to the console. Drifted zones sort first,
/// so the cap hides in-sync rows, never a problem.
const ZONE_ROWS: usize = 20;

/// Dead-lettered origins named individually before it becomes a number.
const DEAD_LETTERS: usize = 5;

struct Card {
    label: &'static str,
    value: String,
    note: String,
    /// A Bootstrap text colour, or empty for the default.
    tone: &'static str,
}

struct ZoneRow {
    origin: String,
    db_serial: i64,
    /// The serial the backend answers with, or `—` when it has none / can't report.
    live_serial: String,
    badge: &'static str,
    badge_class: &'static str,
    /// Drifted rows sort to the top; not rendered.
    rank: u8,
}

/// What the DNS backend says about itself, for its own panel.
struct BackendPanel {
    name: &'static str,
    state: &'static str,
    state_class: &'static str,
    /// The backend's own status line (`knotc status`), when it has one.
    detail: Option<String>,
    /// Why the probe failed, when it did.
    error: Option<String>,
    last_push: String,
    zones_db: u64,
    /// Zones the backend is actually serving — `None` when it can't report (the `log` backend) or
    /// the ask failed. Not the same number as `zones_db`, and the difference is the point.
    zones_served: Option<usize>,
}

/// The zone-sync table plus the two numbers derived from the same backend answer.
struct ZoneSync {
    rows: Vec<ZoneRow>,
    hidden: usize,
    served: Option<usize>,
}

struct TypeCount {
    name: &'static str,
    /// The entity slug, so the count links to its table: `A` → `/admin/rr_a`.
    slug: String,
    count: u64,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct Dashboard {
    warnings: Vec<String>,
    cards: Vec<Card>,
    backend: BackendPanel,
    /// Column headings for the activity table: the named surfaces, then "Console".
    surfaces: Vec<&'static str>,
    windows: Vec<Window>,
    zones: Vec<ZoneRow>,
    more_zones: usize,
    pending: u64,
    in_flight: u64,
    failed: u64,
    dead_letters: Vec<String>,
    by_type: Vec<TypeCount>,
}

/// `GET /` — the dashboard, for a Superadmin. Everyone else is sent to their profile: the console
/// and this page are both Superadmin-only, and `/profile` (password, 2FA, API keys) is what a
/// device owner actually came for.
pub async fn page(headers: HeaderMap, uri: Uri, State(app): State<AppState>) -> Response {
    let Some(who) = app.auth.identify(&headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    if !app.auth.can_manage_others(&who) {
        return Redirect::to("/profile").into_response();
    }

    let s = Stats::gather(&app).await;
    let sync = zone_rows(&app).await;
    let page = Dashboard {
        warnings: s.warnings(&app.cfg),
        cards: cards(&app, &s),
        backend: backend_panel(&app, &s, sync.served),
        surfaces: SURFACES.iter().map(|(name, _)| *name).chain(["Console"]).collect(),
        windows: crate::stats::activity(&app).await,
        zones: sync.rows,
        more_zones: sync.hidden,
        pending: s.pending,
        in_flight: s.in_flight,
        failed: s.failed,
        dead_letters: dead_letters(&app).await,
        by_type: s
            .by_type
            .iter()
            .map(|(name, count)| TypeCount { name, slug: name.to_lowercase(), count: *count })
            .collect(),
    };
    match page.render() {
        Ok(body) => Html(super::Shell::page("Dashboard — teleddns", &who, &uri, &headers, body).html())
            .into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// The DNS backend's own panel: is it answering, what does it say about itself, and is it serving
/// the zones we think it is. `served` comes from the [`zone_rows`] call so the backend is asked for
/// its serials once, not twice.
fn backend_panel(app: &AppState, s: &Stats, served: Option<usize>) -> BackendPanel {
    use crate::backend::Probe;
    let (state, state_class) = match s.status.probe {
        Probe::Up => ("up", "text-bg-success"),
        Probe::Down => ("down", "text-bg-danger"),
        Probe::Na => ("n/a", "text-bg-secondary"),
    };
    BackendPanel {
        name: app.backend.name(),
        state,
        state_class,
        detail: s.status.detail.clone(),
        error: s.status.error.clone(),
        last_push: ago(s.last_push),
        zones_db: s.zones,
        zones_served: served,
    }
}

/// The five numbers at the top. Each is one of the healthcheck's fields, worded for a reader.
fn cards(app: &AppState, s: &Stats) -> Vec<Card> {
    use crate::backend::Probe;
    let (backend, backend_tone) = match s.status.probe {
        Probe::Up => ("up".to_string(), "text-success"),
        Probe::Down => ("down".to_string(), "text-danger"),
        // The `log` backend pushes nowhere, so there is nothing to be up or down.
        Probe::Na => ("n/a".to_string(), "text-muted"),
    };
    let (drift, drift_tone) = match s.out_of_sync {
        -1 => ("—".to_string(), "text-muted"),
        0 => ("0".to_string(), "text-success"),
        n => (n.to_string(), "text-danger"),
    };
    vec![
        Card { label: "Zones", value: s.zones.to_string(), note: "served from this database".into(), tone: "" },
        Card {
            label: "Records",
            value: s.records().to_string(),
            note: format!("across {} types", s.by_type.iter().filter(|(_, n)| *n > 0).count()),
            tone: "",
        },
        Card {
            label: "Backend",
            value: backend,
            note: format!("{}, last push {}", app.backend.name(), ago(s.last_push)),
            tone: backend_tone,
        },
        Card {
            label: "Sync worker",
            value: ago(s.last_tick),
            note: format!("{} push(es) queued", s.unfinished()),
            tone: if s.last_tick == 0 { "text-muted" } else { "" },
        },
        Card {
            label: "Out of sync",
            value: drift,
            note: "zones behind their serial".into(),
            tone: drift_tone,
        },
    ]
}

/// One row per zone: the database serial beside the one the backend is answering with.
async fn zone_rows(app: &AppState) -> ZoneSync {
    let zones = zone::Entity::find()
        .order_by_asc(zone::Column::Origin)
        .all(&app.db)
        .await
        .unwrap_or_default();
    // `Ok(None)` = a backend that can't report serials (the `log` one); an `Err` is a backend that
    // is down, which the Backend card already says. Both render as "unknown", not as a drift.
    let served: Option<HashMap<String, i64>> = app.backend.zone_serials().await.ok().flatten();
    let queued = unfinished_origins(app).await;

    let mut rows: Vec<ZoneRow> = zones
        .into_iter()
        .map(|z| {
            let live = served.as_ref().map(|m| m.get(&z.origin).copied());
            // rank orders the table: trouble first, then the merely pending, then the quiet ones.
            let (badge, badge_class, rank) = match (live, queued.contains(&z.origin)) {
                (None, _) => ("unknown", "text-bg-secondary", 2),
                (Some(None), _) => ("not served", "text-bg-danger", 0),
                (Some(Some(n)), _) if n == z.serial => ("in sync", "text-bg-success", 3),
                // Behind with a push still owed is the normal state a second after an edit.
                (Some(Some(_)), true) => ("syncing", "text-bg-info", 1),
                (Some(Some(n)), false) if n < z.serial => ("behind", "text-bg-warning", 0),
                (Some(Some(_)), false) => ("ahead", "text-bg-secondary", 0),
            };
            ZoneRow {
                origin: z.origin,
                db_serial: z.serial,
                live_serial: live.flatten().map(|n| n.to_string()).unwrap_or_else(|| "—".into()),
                badge,
                badge_class,
                rank,
            }
        })
        .collect();
    rows.sort_by_key(|r| r.rank); // stable: origin order survives inside a rank

    let hidden = rows.len().saturating_sub(ZONE_ROWS);
    rows.truncate(ZONE_ROWS);
    ZoneSync { rows, hidden, served: served.map(|m| m.len()) }
}

/// Origins with a push still owed (pending or in flight) — what turns "behind" into "syncing".
async fn unfinished_origins(app: &AppState) -> HashSet<String> {
    sync_task::Entity::find()
        .filter(sync_task::Column::State.is_in([sync_task::STATE_PENDING, sync_task::STATE_IN_FLIGHT]))
        .all(&app.db)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|t| t.origin)
        .collect()
}

/// Origins the worker gave up on — the one queue state an operator has to act on.
async fn dead_letters(app: &AppState) -> Vec<String> {
    sync_task::Entity::find()
        .filter(sync_task::Column::State.eq(sync_task::STATE_FAILED))
        .order_by_asc(sync_task::Column::CreatedAt)
        .limit(DEAD_LETTERS as u64)
        .all(&app.db)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|t| t.origin)
        .collect()
}
