//! The numbers three surfaces report about this server: `/healthcheck` (one line of text),
//! `/metrics` (Prometheus) and the dashboard (HTML). One set of queries, so the three can't drift
//! apart — a WARN on the healthcheck and a red badge on the dashboard mean the same thing because
//! they read the same value.

use crate::app::AppState;
use crate::model::{audit, now, rr, sync_task, zone};
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect};
use std::collections::HashMap;
use std::sync::atomic::Ordering;

/// Everything derived from the DB + the worker + the backend probe, gathered once.
pub struct Stats {
    pub uptime: i64,
    pub zones: u64,
    /// Per-type record counts keyed by zone, in the canonical RR order. Sum = [`Stats::records`];
    /// [`Stats::per_zone`] collapses it the other way, for the zones panel.
    pub by_type: Vec<(&'static str, HashMap<i32, u64>)>,
    pub pending: u64,
    pub in_flight: u64,
    pub failed: u64,
    /// What the backend says about itself — asked **once** here, so the dashboard's panel, the
    /// healthcheck's `knot=` field and the `knot_up` gauge are all the same observation.
    pub status: crate::backend::Status,
    pub last_push: i64,
    pub last_tick: i64,
    /// Zones whose live serial is behind the DB, from the worker's periodic reconcile. `-1` = not
    /// computed yet (or the `log` backend, which can't report serials).
    pub out_of_sync: i64,
    /// `created_at` of the oldest unfinished (pending/in-flight) push, if any.
    pub oldest_unfinished: Option<i64>,
}

impl Stats {
    /// Collect the lot. Every query degrades to `0` rather than failing the page: these are
    /// observability numbers, and a dashboard that 500s because one count timed out is worse than
    /// one that shows a zero.
    pub async fn gather(app: &AppState) -> Stats {
        let count_state = |state: &'static str| async move {
            sync_task::Entity::find()
                .filter(sync_task::Column::State.eq(state))
                .count(&app.db)
                .await
                .unwrap_or(0)
        };
        Stats {
            uptime: now() - app.started_at,
            zones: zone::Entity::find().count(&app.db).await.unwrap_or(0),
            by_type: count_by_type(app).await,
            pending: count_state(sync_task::STATE_PENDING).await,
            in_flight: count_state(sync_task::STATE_IN_FLIGHT).await,
            failed: count_state(sync_task::STATE_FAILED).await,
            status: app.backend.status().await,
            last_push: app.worker.last_push.load(Ordering::Relaxed),
            last_tick: app.worker.last_tick.load(Ordering::Relaxed),
            out_of_sync: app.worker.out_of_sync.load(Ordering::Relaxed),
            oldest_unfinished: oldest_unfinished(app).await,
        }
    }

    /// Total record count across every RR type.
    pub fn records(&self) -> u64 {
        self.by_type.iter().flat_map(|(_, per_zone)| per_zone.values()).sum()
    }

    /// Per-type totals across all zones — what `/metrics` labels and the by-type chips show.
    pub fn type_totals(&self) -> Vec<(&'static str, u64)> {
        self.by_type.iter().map(|(t, z)| (*t, z.values().sum())).collect()
    }

    /// Records per zone id, summed across every RR type.
    pub fn per_zone(&self) -> HashMap<i32, u64> {
        let mut out: HashMap<i32, u64> = HashMap::new();
        for (_, per_zone) in &self.by_type {
            for (zone, n) in per_zone {
                *out.entry(*zone).or_default() += n;
            }
        }
        out
    }

    /// Pushes the worker still owes the backend.
    pub fn unfinished(&self) -> u64 {
        self.pending + self.in_flight
    }

    /// Is anything wrong enough that an operator should look? This is the healthcheck's `WARN`
    /// **and** the dashboard's red banner — one predicate, so they always agree.
    ///
    /// `grace` seconds after startup nothing warns: the worker hasn't ticked yet and the backlog a
    /// restart inherits is expected.
    pub fn warnings(&self, cfg: &crate::config::Config) -> Vec<String> {
        let mut w = Vec::new();
        if self.uptime <= 30 {
            return w;
        }
        let period = cfg.backend_sync_period.as_secs() as i64;
        if self.last_tick > 0 && now() - self.last_tick > 2 * period {
            w.push(format!("the sync worker has not ticked for {}", since(self.last_tick)));
        }
        if self.failed > 0 {
            w.push(format!("{} push(es) dead-lettered after repeated failures", self.failed));
        }
        if self.status.probe == crate::backend::Probe::Down {
            w.push(match &self.status.error {
                Some(e) => format!("the DNS backend is not answering: {e}"),
                None => "the DNS backend is not answering".into(),
            });
        }
        if self.out_of_sync > 0 {
            w.push(format!("{} zone(s) are not being served at their current serial", self.out_of_sync));
        }
        if let Some(oldest) = self.oldest_unfinished {
            if now() - oldest > cfg.warn_on_nopush.as_secs() as i64 {
                w.push(format!("the oldest queued push has been waiting {}", since(oldest)));
            }
        }
        w
    }
}

/// Per-type record counts **broken down by zone**, in a stable type order.
///
/// One `GROUP BY zone_id` per RR table rather than one `COUNT(*)` — the same fourteen queries and
/// the same scan, but the result answers both "how many A records are there" (sum the map) and "how
/// many does *this* zone have", which the zones panel needs. `zone_id` carries no index, so either
/// form scans; if this ever becomes the dashboard's cost, an index is the fix and it is a migration,
/// not a model change.
async fn count_by_type(app: &AppState) -> Vec<(&'static str, HashMap<i32, u64>)> {
    macro_rules! c {
        ($ent:path, $col:path, $typ:literal) => {{
            let rows: Vec<(i32, i64)> = <$ent>::find()
                .select_only()
                .column($col)
                .column_as(sea_orm::prelude::Expr::val(1).count(), "n")
                .group_by($col)
                .into_tuple()
                .all(&app.db)
                .await
                .unwrap_or_default();
            ($typ, rows.into_iter().map(|(z, n)| (z, n.max(0) as u64)).collect())
        }};
    }
    vec![
        c!(rr::a::Entity, rr::a::Column::ZoneId, "A"),
        c!(rr::aaaa::Entity, rr::aaaa::Column::ZoneId, "AAAA"),
        c!(rr::ns::Entity, rr::ns::Column::ZoneId, "NS"),
        c!(rr::ptr::Entity, rr::ptr::Column::ZoneId, "PTR"),
        c!(rr::cname::Entity, rr::cname::Column::ZoneId, "CNAME"),
        c!(rr::txt::Entity, rr::txt::Column::ZoneId, "TXT"),
        c!(rr::mx::Entity, rr::mx::Column::ZoneId, "MX"),
        c!(rr::srv::Entity, rr::srv::Column::ZoneId, "SRV"),
        c!(rr::caa::Entity, rr::caa::Column::ZoneId, "CAA"),
        c!(rr::sshfp::Entity, rr::sshfp::Column::ZoneId, "SSHFP"),
        c!(rr::tlsa::Entity, rr::tlsa::Column::ZoneId, "TLSA"),
        c!(rr::dnskey::Entity, rr::dnskey::Column::ZoneId, "DNSKEY"),
        c!(rr::ds::Entity, rr::ds::Column::ZoneId, "DS"),
        c!(rr::naptr::Entity, rr::naptr::Column::ZoneId, "NAPTR"),
    ]
}

/// Created-at of the oldest unfinished (pending/in_flight) sync task.
async fn oldest_unfinished(app: &AppState) -> Option<i64> {
    sync_task::Entity::find()
        .filter(sync_task::Column::State.is_in([sync_task::STATE_PENDING, sync_task::STATE_IN_FLIGHT]))
        .order_by_asc(sync_task::Column::CreatedAt)
        .one(&app.db)
        .await
        .ok()
        .flatten()
        .map(|t| t.created_at)
}

// ===================== write activity =====================

/// The windows the activity panel reports over. Short ones answer "is it working *now*" (a DDNS
/// fleet updates every few minutes, so an empty 5-minute row on a live deployment is a symptom);
/// the long ones give the short ones a baseline to be judged against.
pub const WINDOWS: [(&str, i64); 6] = [
    ("5 min", 300),
    ("15 min", 900),
    ("1 hour", 3600),
    ("6 hours", 6 * 3600),
    ("12 hours", 12 * 3600),
    ("24 hours", 24 * 3600),
];

/// The surfaces a write can arrive on, as a column heading and the `audit.source` values it covers.
/// Anything not matched here — the console's auto-CRUD (`crud`) and the auth handlers
/// (`auth-profile`, `auth-admin`) — falls into **Console**, which is where all of it is done.
pub const SURFACES: [(&str, &[&str]); 3] =
    [("DDNS", &["ddns"]), ("API", &["api"]), ("CF", &["cfapi"])];

/// One row of the activity panel: writes in the last `label` window, split by surface.
pub struct Window {
    pub label: &'static str,
    /// One count per [`SURFACES`] entry, in order, then **Console** (everything else).
    pub counts: Vec<u64>,
    pub total: u64,
}

/// Writes per surface over each of [`WINDOWS`], read from the audit log — the only place that
/// records *every* state-changing request across all four surfaces, which is exactly what makes it
/// the right source for "how much is happening".
///
/// Six grouped counts, not one scan: `WHERE ts >= ? GROUP BY source` is covered end to end by
/// `ix_audit_ts_source` (migration `m0006`), so each window reads index entries and never a row.
/// Counting in Rust instead would mean pulling a day of DDNS updates into memory to add them up.
///
/// Bounded by retention: `audit_retention_days` must be at least 1 for the 24-hour row to mean
/// anything. At the default (365) every window is well inside it.
pub async fn activity(app: &AppState) -> Vec<Window> {
    let now = now();
    let mut out = Vec::with_capacity(WINDOWS.len());
    for (label, secs) in WINDOWS {
        let rows: Vec<(String, i64)> = audit::Entity::find()
            .select_only()
            .column(audit::Column::Source)
            .column_as(audit::Column::Id.count(), "n")
            .filter(audit::Column::Ts.gte(now - secs))
            .group_by(audit::Column::Source)
            .into_tuple()
            .all(&app.db)
            .await
            .unwrap_or_default();

        // One bucket per named surface, plus a trailing "Console" for everything else.
        let mut counts = vec![0u64; SURFACES.len() + 1];
        for (source, n) in rows {
            let n = n.max(0) as u64;
            let slot = SURFACES
                .iter()
                .position(|(_, keys)| keys.contains(&source.as_str()))
                .unwrap_or(SURFACES.len());
            counts[slot] += n;
        }
        out.push(Window { label, total: counts.iter().sum(), counts });
    }
    out
}

/// The chart's span and bucket, in seconds: **six hours at five-minute granularity** — 72 points,
/// enough to show a DDNS fleet's rhythm and an operator's burst of edits without the line becoming
/// noise. Both are compile-time constants because the SVG's geometry is derived from them.
pub const CHART_SPAN: i64 = 6 * 3600;
pub const CHART_BUCKET: i64 = 300;
pub const CHART_POINTS: usize = (CHART_SPAN / CHART_BUCKET) as usize;

/// Writes per surface per five-minute bucket over the last six hours: one series per [`SURFACES`]
/// entry plus Console, each `CHART_POINTS` long and oldest-first.
///
/// **One query.** `ts / 300` is integer division on both SQLite and PostgreSQL, so the grouping is
/// the database's work rather than a day of rows dragged into memory, and `WHERE ts >= ?` is served
/// by `ix_audit_ts_source` (migration `m0006`) — the same index the window totals use.
pub async fn activity_series(app: &AppState) -> Vec<(&'static str, Vec<u64>)> {
    let now = now();
    // Align to the bucket so the rightmost point is the one in progress, not a sliver.
    let newest = now / CHART_BUCKET;
    let oldest = newest - CHART_POINTS as i64 + 1;

    let mut series: Vec<(&'static str, Vec<u64>)> = SURFACES
        .iter()
        .map(|(name, _)| *name)
        .chain(["Console"])
        .map(|name| (name, vec![0u64; CHART_POINTS]))
        .collect();

    let rows: Vec<(i64, String, i64)> = audit::Entity::find()
        .select_only()
        .column_as(Expr::col(audit::Column::Ts).div(CHART_BUCKET), "bucket")
        .column(audit::Column::Source)
        .column_as(audit::Column::Id.count(), "n")
        .filter(audit::Column::Ts.gte(oldest * CHART_BUCKET))
        .group_by(Expr::col(audit::Column::Ts).div(CHART_BUCKET))
        .group_by(audit::Column::Source)
        .into_tuple()
        .all(&app.db)
        .await
        .unwrap_or_default();

    for (bucket, source, n) in rows {
        let Ok(idx) = usize::try_from(bucket - oldest) else { continue };
        if idx >= CHART_POINTS {
            continue;
        }
        let slot = SURFACES
            .iter()
            .position(|(_, keys)| keys.contains(&source.as_str()))
            .unwrap_or(SURFACES.len());
        series[slot].1[idx] += n.max(0) as u64;
    }
    series
}

/// How long ago, as a phrase with no "ago" — `"21 seconds"`, `"2 hours"`. For sentences that supply
/// their own preposition ("has not ticked for …"), where appending "ago" would be wrong.
pub fn since(epoch: i64) -> String {
    let d = (now() - epoch).max(0);
    let (n, unit) = match d {
        0..=59 => (d, "second"),
        60..=3599 => (d / 60, "minute"),
        3600..=86399 => (d / 3600, "hour"),
        _ => (d / 86400, "day"),
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

/// A coarse "21 seconds ago" for a Unix timestamp; `never` for a zero/absent one. Deliberately not
/// an absolute time — that is the other half of a [`Stamp`](crate::web::dashboard) and answers a
/// different question ("when exactly", for lining up against Knot's log); this one answers "is it
/// fresh?", which needs no timezone at all.
pub fn ago(epoch: i64) -> String {
    if epoch <= 0 {
        return "never".into();
    }
    format!("{} ago", since(epoch))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The panel's columns are `SURFACES` plus one for everything else; a row that didn't reserve
    /// that trailing slot would drop every console write on the floor (or panic).
    #[test]
    fn every_audit_source_lands_in_a_column() {
        let mut counts = vec![0u64; SURFACES.len() + 1];
        for source in ["ddns", "api", "cfapi", "crud", "auth-profile", "auth-admin", "something-new"] {
            let slot = SURFACES
                .iter()
                .position(|(_, keys)| keys.contains(&source))
                .unwrap_or(SURFACES.len());
            counts[slot] += 1;
        }
        assert_eq!(counts, vec![1, 1, 1, 4], "ddns/api/cf get one each; the other four are Console");
    }

    /// `since` supplies the duration, `ago` the relative phrase. They are separate because a
    /// sentence that brings its own preposition — "has not ticked for …" — reads as nonsense with
    /// "ago" stuck on the end, which is exactly what the warnings used to say.
    #[test]
    fn ago_scales_its_unit_and_names_the_absent() {
        assert_eq!(ago(0), "never");
        assert_eq!(ago(-1), "never");
        assert_eq!(ago(now()), "0 seconds ago");
        assert_eq!(ago(now() - 1), "1 second ago", "singular, not '1 seconds'");
        assert_eq!(ago(now() - 90), "1 minute ago");
        assert_eq!(ago(now() - 7200), "2 hours ago");
        assert_eq!(ago(now() - 3 * 86400), "3 days ago");

        assert_eq!(since(now() - 90), "1 minute", "no 'ago' — the sentence supplies its own");
    }
}
