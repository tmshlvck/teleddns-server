//! The numbers three surfaces report about this server: `/healthcheck` (one line of text),
//! `/metrics` (Prometheus) and the dashboard (HTML). One set of queries, so the three can't drift
//! apart — a WARN on the healthcheck and a red badge on the dashboard mean the same thing because
//! they read the same value.

use crate::app::AppState;
use crate::model::{audit, now, rr, sync_task, zone};
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect};
use std::sync::atomic::Ordering;

/// Everything derived from the DB + the worker + the backend probe, gathered once.
pub struct Stats {
    pub uptime: i64,
    pub zones: u64,
    /// Per-type record counts, in the canonical RR order. Sum = [`Stats::records`].
    pub by_type: Vec<(&'static str, u64)>,
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
        self.by_type.iter().map(|(_, n)| n).sum()
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
            w.push(format!("the sync worker has not ticked for {}", ago(self.last_tick)));
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
                w.push(format!("the oldest queued push has been waiting {}", ago(oldest)));
            }
        }
        w
    }
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

/// A coarse "3m ago" for a Unix timestamp; `never` for a zero/absent one. Deliberately not a
/// timezone-aware absolute time — an operator reading a dashboard wants the *age*, and an age needs
/// no zone.
pub fn ago(epoch: i64) -> String {
    if epoch <= 0 {
        return "never".into();
    }
    let d = (now() - epoch).max(0);
    match d {
        0..=59 => format!("{d}s ago"),
        60..=3599 => format!("{}m ago", d / 60),
        3600..=86399 => format!("{}h ago", d / 3600),
        _ => format!("{}d ago", d / 86400),
    }
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

    #[test]
    fn ago_scales_its_unit_and_names_the_absent() {
        assert_eq!(ago(0), "never");
        assert_eq!(ago(-1), "never");
        assert_eq!(ago(now()), "0s ago");
        assert_eq!(ago(now() - 90), "1m ago");
        assert_eq!(ago(now() - 7200), "2h ago");
        assert_eq!(ago(now() - 3 * 86400), "3d ago");
    }
}
