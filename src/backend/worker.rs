//! The backend-sync worker: a single background task draining the `sync_task` journal. Coalesces per
//! origin, is at-least-once (in-flight reset on boot + stuck-reclaim), idempotent (full regen each
//! push), retries with exponential backoff + jitter, and dead-letters after MAX_ATTEMPTS.

use super::Backend;
use crate::config::Config;
use crate::model::sync_task::{
    self, KIND_ZONE_REMOVE, STATE_FAILED, STATE_IN_FLIGHT, STATE_PENDING,
};
use crate::model::{now, zone};
use sea_orm::ActiveValue::Set;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect,
};
use std::collections::HashSet;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

const MAX_ATTEMPTS: i32 = 20;
const BACKOFF_CAP_SECS: i64 = 3600;

/// Liveness handles the healthcheck reads.
#[derive(Clone)]
pub struct WorkerHandle {
    pub last_tick: Arc<AtomicI64>,
    pub last_push: Arc<AtomicI64>,
    /// Zones whose live Knot serial is behind the DB (or missing), with nothing pending — refreshed
    /// by the periodic reconcile. `-1` = not yet computed / not applicable (log backend).
    pub out_of_sync: Arc<AtomicI64>,
}

/// How often the worker runs the auth housekeeping (expired sessions on **both** clocks + expired
/// lockout rows). relativelylight schedules nothing itself — this loop is the app's answer to that.
const AUTH_PRUNE_PERIOD_SECS: i64 = 3600;

/// Spawn the worker; returns handles the healthcheck reads.
pub fn spawn(
    db: DatabaseConnection,
    cfg: Arc<Config>,
    backend: Arc<dyn Backend>,
    metrics: Arc<crate::metrics::Metrics>,
    auth: relativelylight::auth::Auth,
) -> WorkerHandle {
    let last_tick = Arc::new(AtomicI64::new(0));
    let last_push = Arc::new(AtomicI64::new(0));
    let out_of_sync = Arc::new(AtomicI64::new(-1));
    let handle = WorkerHandle {
        last_tick: last_tick.clone(),
        last_push: last_push.clone(),
        out_of_sync: out_of_sync.clone(),
    };

    let delay = cfg.backend_sync_delay.max(Duration::from_secs(1));
    let period = cfg.backend_sync_period.as_secs() as i64;
    let full_resync_period = cfg.full_resync_period.as_secs() as i64;
    let delete_zones = cfg.knot_delete_zones;

    tokio::spawn(async move {
        // At-least-once: anything left in_flight from a previous run goes back to pending.
        let _ = reset_in_flight(&db).await;

        let mut ticker = tokio::time::interval(delay);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_reconcile = 0i64;
        // 0 so the sweep also runs once on the first tick after startup.
        let mut last_full_resync = 0i64;
        let mut last_auth_prune = 0i64;
        loop {
            ticker.tick().await;
            if let Err(e) = tick(&db, &*backend, period, &last_push, &metrics).await {
                tracing::warn!(error = %e, "sync worker tick failed");
            }
            last_tick.store(now(), Ordering::Relaxed);
            // Periodic drift check: is Knot actually serving every zone's current serial?
            if now() - last_reconcile >= period.max(1) {
                reconcile(&db, &*backend, &metrics, &out_of_sync).await;
                last_reconcile = now();
            }
            // Full sweep: re-push every zone, and (if enabled) prune backend zones we don't own.
            if now() - last_full_resync >= full_resync_period.max(1) {
                full_resync(&db, &*backend, delete_zones).await;
                last_full_resync = now();
            }
            // Auth housekeeping: drop expired sessions and expired lockout rows. Purely cosmetic for
            // correctness (an expired row reads as unlocked, an expired session never authenticates),
            // so failures are logged and forgotten. Runs once on the first tick, then hourly. This is
            // `Auth`'s own prune rather than the free `auth::prune`, because only the handle knows our
            // `session_idle_secs` — the free function would leave idle-dead rows until their absolute
            // deadline.
            if now() - last_auth_prune >= AUTH_PRUNE_PERIOD_SECS {
                match auth.prune().await {
                    Ok(0) => {}
                    Ok(n) => tracing::debug!(rows = n, "pruned expired sessions/lockout rows"),
                    Err(e) => tracing::warn!(error = %e, "auth prune failed"),
                }
                last_auth_prune = now();
            }
        }
    });

    handle
}

/// Unconditionally re-push every zone in the DB (covers RRs transitively — a push is a full
/// render), then, if `delete_zones`, prune backend zones declared under our template that aren't
/// in the DB. Runs on startup (first tick) and every `full_resync_period` after.
async fn full_resync(db: &DatabaseConnection, backend: &dyn Backend, delete_zones: bool) {
    let zones = match zone::Entity::find().all(db).await {
        Ok(z) => z,
        Err(e) => {
            tracing::warn!(error = %e, "full resync: could not load zones");
            return;
        }
    };
    let mut origins = HashSet::new();
    for z in &zones {
        if let Err(e) = crate::sync::enqueue(db, &z.origin).await {
            tracing::warn!(origin = %z.origin, error = %e, "full resync: could not enqueue push");
        }
        origins.insert(z.origin.clone());
    }
    tracing::info!(zones = origins.len(), "full resync: enqueued push for all zones");

    if !delete_zones {
        return;
    }
    match backend.managed_zones().await {
        Ok(Some(declared)) => {
            for orphan in declared.difference(&origins) {
                tracing::warn!(origin = %orphan, "full resync: pruning zone not in DB");
                if let Err(e) = crate::sync::enqueue_remove(db, orphan).await {
                    tracing::warn!(origin = %orphan, error = %e, "full resync: could not enqueue removal");
                }
            }
        }
        Ok(None) => {} // backend can't enumerate (log backend)
        Err(e) => tracing::warn!(error = %e, "full resync: could not list backend zones"),
    }
}

/// Compare each zone's DB serial to what Knot is serving (`zone_serials`), ignoring zones with a
/// push still pending/in-flight (those are expected to be transiently behind). Publishes the count to
/// the `out_of_sync` handle + the gauge, and logs each drifted zone at WARN. No-op for the `log`
/// backend (which can't report serials).
async fn reconcile(
    db: &DatabaseConnection,
    backend: &dyn Backend,
    metrics: &crate::metrics::Metrics,
    out_of_sync: &AtomicI64,
) {
    let served = match backend.zone_serials().await {
        Ok(Some(m)) => m,
        Ok(None) => return, // log backend: nothing to reconcile against
        Err(e) => {
            tracing::debug!(error = %e, "reconcile: could not read Knot serials");
            return;
        }
    };
    let zones = match zone::Entity::find().all(db).await {
        Ok(z) => z,
        Err(e) => {
            tracing::warn!(error = %e, "reconcile: could not load zones");
            return;
        }
    };
    // Origins with an outstanding push are allowed to be behind.
    let pending: HashSet<String> = sync_task::Entity::find()
        .filter(sync_task::Column::State.is_in([STATE_PENDING, STATE_IN_FLIGHT]))
        .all(db)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|t| t.origin)
        .collect();

    let mut count = 0i64;
    for z in &zones {
        if pending.contains(&z.origin) {
            continue;
        }
        match served.get(&z.origin) {
            Some(&live) if live >= z.serial => {} // in sync (≥: DNSSEC signing may bump it)
            Some(&live) => {
                count += 1;
                tracing::warn!(origin = %z.origin, db_serial = z.serial, knot_serial = live, "zone out of sync");
            }
            None => {
                count += 1;
                tracing::warn!(origin = %z.origin, db_serial = z.serial, "zone not served by Knot");
            }
        }
    }
    out_of_sync.store(count, Ordering::Relaxed);
    metrics.zones_out_of_sync.set(count);
}

async fn reset_in_flight(db: &DatabaseConnection) -> Result<(), sea_orm::DbErr> {
    sync_task::Entity::update_many()
        .col_expr(sync_task::Column::State, sea_orm::sea_query::Expr::value(STATE_PENDING))
        .filter(sync_task::Column::State.eq(STATE_IN_FLIGHT))
        .exec(db)
        .await?;
    Ok(())
}

async fn tick(
    db: &DatabaseConnection,
    backend: &dyn Backend,
    period: i64,
    last_push: &AtomicI64,
    metrics: &crate::metrics::Metrics,
) -> Result<(), sea_orm::DbErr> {
    // Reclaim stuck in-flight rows (older than 2× the period).
    let cutoff = now() - 2 * period.max(1);
    sync_task::Entity::update_many()
        .col_expr(sync_task::Column::State, sea_orm::sea_query::Expr::value(STATE_PENDING))
        .filter(sync_task::Column::State.eq(STATE_IN_FLIGHT))
        .filter(sync_task::Column::UpdatedAt.lt(cutoff))
        .exec(db)
        .await?;

    // Due pending tasks, coalesced to one per origin (newest wins).
    let due = sync_task::Entity::find()
        .filter(sync_task::Column::State.eq(STATE_PENDING))
        .filter(sync_task::Column::AvailableAt.lte(now()))
        .order_by_asc(sync_task::Column::AvailableAt)
        .limit(200)
        .all(db)
        .await?;

    let mut seen: HashSet<String> = HashSet::new();
    for task in due {
        if !seen.insert(task.origin.clone()) {
            // A newer/older duplicate for the same origin is already being handled this tick.
            continue;
        }
        process(db, backend, task, last_push, metrics).await?;
    }
    Ok(())
}

async fn process(
    db: &DatabaseConnection,
    backend: &dyn Backend,
    task: sync_task::Model,
    last_push: &AtomicI64,
    metrics: &crate::metrics::Metrics,
) -> Result<(), sea_orm::DbErr> {
    // Claim it.
    let id = task.id;
    let mut am: sync_task::ActiveModel = task.clone().into();
    am.state = Set(STATE_IN_FLIGHT.to_string());
    am.updated_at = Set(now());
    am.update(db).await?;

    let started = std::time::Instant::now();
    let result: Result<(), String> = if task.kind == KIND_ZONE_REMOVE {
        backend.remove_zone(&task.origin).await
    } else {
        match zone::Entity::find()
            .filter(zone::Column::Origin.eq(&task.origin))
            .one(db)
            .await?
        {
            Some(z) => match super::zonefile::render_zone(db, &z).await {
                Ok(text) => backend.push_zone(&task.origin, &text, z.serial).await,
                Err(e) => Err(format!("render: {e}")),
            },
            // The zone was deleted; treat a stale `zone` task as a removal.
            None => backend.remove_zone(&task.origin).await,
        }
    };
    metrics
        .backend_push_seconds
        .with_label_values(&[&task.kind])
        .observe(started.elapsed().as_secs_f64());

    match result {
        Ok(()) => {
            // Success: drop the journal row.
            sync_task::Entity::delete_by_id(id).exec(db).await?;
            last_push.store(now(), Ordering::Relaxed);
            metrics.backend_push.with_label_values(&[&task.kind, "ok"]).inc();
            tracing::info!(origin = %task.origin, kind = %task.kind, "pushed to backend");
        }
        Err(e) => {
            metrics.backend_push.with_label_values(&[&task.kind, "error"]).inc();
            let attempts = task.attempts + 1;
            let mut am: sync_task::ActiveModel = sync_task::Entity::find_by_id(id)
                .one(db)
                .await?
                .map(Into::into)
                .unwrap_or_default();
            am.attempts = Set(attempts);
            am.updated_at = Set(now());
            if attempts >= MAX_ATTEMPTS {
                am.state = Set(STATE_FAILED.to_string());
                tracing::error!(origin = %task.origin, attempts, error = %e, "push dead-lettered");
            } else {
                am.state = Set(STATE_PENDING.to_string());
                am.available_at = Set(now() + backoff_secs(attempts));
                tracing::warn!(origin = %task.origin, attempts, error = %e, "push failed; will retry");
            }
            am.update(db).await?;
        }
    }
    Ok(())
}

/// Exponential backoff with a tiny deterministic jitter, capped.
fn backoff_secs(attempts: i32) -> i64 {
    let base = 2i64.saturating_pow(attempts.min(12) as u32);
    let jitter = (attempts as i64 * 7) % 5;
    (base + jitter).min(BACKOFF_CAP_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_caps() {
        assert!(backoff_secs(1) < backoff_secs(5));
        assert_eq!(backoff_secs(20), BACKOFF_CAP_SECS);
    }
}
