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
}

/// Spawn the worker; returns handles the healthcheck reads.
pub fn spawn(
    db: DatabaseConnection,
    cfg: Arc<Config>,
    backend: Arc<dyn Backend>,
) -> WorkerHandle {
    let last_tick = Arc::new(AtomicI64::new(0));
    let last_push = Arc::new(AtomicI64::new(0));
    let handle = WorkerHandle { last_tick: last_tick.clone(), last_push: last_push.clone() };

    let delay = cfg.backend_sync_delay.max(Duration::from_secs(1));
    let period = cfg.backend_sync_period.as_secs() as i64;

    tokio::spawn(async move {
        // At-least-once: anything left in_flight from a previous run goes back to pending.
        let _ = reset_in_flight(&db).await;

        let mut ticker = tokio::time::interval(delay);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(e) = tick(&db, &*backend, period, &last_push).await {
                tracing::warn!(error = %e, "sync worker tick failed");
            }
            last_tick.store(now(), Ordering::Relaxed);
        }
    });

    handle
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
        process(db, backend, task, last_push).await?;
    }
    Ok(())
}

async fn process(
    db: &DatabaseConnection,
    backend: &dyn Backend,
    task: sync_task::Model,
    last_push: &AtomicI64,
) -> Result<(), sea_orm::DbErr> {
    // Claim it.
    let id = task.id;
    let mut am: sync_task::ActiveModel = task.clone().into();
    am.state = Set(STATE_IN_FLIGHT.to_string());
    am.updated_at = Set(now());
    am.update(db).await?;

    let result: Result<(), String> = if task.kind == KIND_ZONE_REMOVE {
        backend.remove_zone(&task.origin).await
    } else {
        match zone::Entity::find()
            .filter(zone::Column::Origin.eq(&task.origin))
            .one(db)
            .await?
        {
            Some(z) => match super::zonefile::render_zone(db, &z).await {
                Ok(text) => backend.push_zone(&task.origin, &text).await,
                Err(e) => Err(format!("render: {e}")),
            },
            // The zone was deleted; treat a stale `zone` task as a removal.
            None => backend.remove_zone(&task.origin).await,
        }
    };

    match result {
        Ok(()) => {
            // Success: drop the journal row.
            sync_task::Entity::delete_by_id(id).exec(db).await?;
            last_push.store(now(), Ordering::Relaxed);
            tracing::debug!(origin = %task.origin, kind = %task.kind, "pushed");
        }
        Err(e) => {
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
