//! Backend-push enqueueing + SOA-serial bumping. These run from three places: the SeaORM
//! `after_save` hooks on the zone/RR entities (so console create/edit are synced too), directly from
//! the DDNS / native-API / CF write paths, and — for **console deletes**, which fire no per-row hook
//! — the [`DeleteSync`] write observer. All are transaction-safe (they take whatever connection the
//! caller holds).

use crate::model::sync_task::{self, KIND_ZONE, KIND_ZONE_REMOVE, STATE_PENDING};
use crate::model::{now, zone};
use sea_orm::sea_query::Expr;
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::{ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter};

/// Called after an RR row is created/updated: bump the parent zone's serial and enqueue a push.
pub async fn on_rr_saved<C: ConnectionTrait>(db: &C, zone_id: i32) -> Result<(), DbErr> {
    bump_serial(db, zone_id).await?;
    if let Some(z) = zone::Entity::find_by_id(zone_id).one(db).await? {
        enqueue(db, &z.origin).await?;
    }
    Ok(())
}

/// Bump a zone's SOA serial by one (set-based, so it does not re-trigger the zone hook).
pub async fn bump_serial<C: ConnectionTrait>(db: &C, zone_id: i32) -> Result<(), DbErr> {
    zone::Entity::update_many()
        .col_expr(zone::Column::Serial, Expr::col(zone::Column::Serial).add(1))
        .filter(zone::Column::Id.eq(zone_id))
        .exec(db)
        .await?;
    Ok(())
}

/// Enqueue a full-zone regen+reload for `origin` (idempotent: skips if one is already outstanding).
pub async fn enqueue<C: ConnectionTrait>(db: &C, origin: &str) -> Result<(), DbErr> {
    enqueue_kind(db, origin, KIND_ZONE).await
}

/// Enqueue a zone removal (conf-unset + delete file).
pub async fn enqueue_remove<C: ConnectionTrait>(db: &C, origin: &str) -> Result<(), DbErr> {
    enqueue_kind(db, origin, KIND_ZONE_REMOVE).await
}

async fn enqueue_kind<C: ConnectionTrait>(db: &C, origin: &str, kind: &str) -> Result<(), DbErr> {
    // Coalesce on the *pending* state only: an edit while a push is in-flight enqueues a fresh
    // pending row, so the just-committed change gets its own follow-up push.
    let outstanding = sync_task::Entity::find()
        .filter(sync_task::Column::Origin.eq(origin))
        .filter(sync_task::Column::Kind.eq(kind))
        .filter(sync_task::Column::State.eq(STATE_PENDING))
        .one(db)
        .await?;
    if outstanding.is_some() {
        return Ok(());
    }
    let t = now();
    sync_task::ActiveModel {
        id: NotSet,
        origin: Set(origin.to_string()),
        kind: Set(kind.to_string()),
        state: Set(STATE_PENDING.to_string()),
        attempts: Set(0),
        available_at: Set(t),
        created_at: Set(t),
        updated_at: Set(t),
    }
    .insert(db)
    .await?;
    Ok(())
}

// ===================== console deletes =====================

/// Keeps DNS in step with deletes made through the **console**.
///
/// Create and update need nothing here: every surface writes through
/// `ActiveModel::insert/update`, so the SeaORM `after_save` hook on the zone/RR entities already
/// bumps and enqueues. Deletes have no equivalent — every delete path is a set-based
/// `DELETE … WHERE`, which fires no per-row hook — so the API and CF paths call `sync::*` for
/// themselves (`api::record_view`, `api::zones`) and this observer covers the one path that cannot:
/// the crud engine's, which does the delete inside the library.
///
/// It reads `WriteEvent::before_rows` — every row the delete removed, which relativelylight 0.3.1
/// added for exactly this. Without it a bulk delete announced only that *something* had gone from
/// `rr_a`, so the record vanished from the database and the console while the backend went on
/// serving it; and with no serial bump, even a later re-push would have left every secondary on the
/// old copy.
pub struct DeleteSync {
    db: sea_orm::DatabaseConnection,
}

impl DeleteSync {
    pub fn new(db: sea_orm::DatabaseConnection) -> Self {
        DeleteSync { db }
    }
}

#[async_trait::async_trait]
impl relativelylight::observe::WriteObserver for DeleteSync {
    async fn on_write(&self, ev: &relativelylight::observe::WriteEvent<'_>) {
        use relativelylight::authz::Operation;
        if ev.op != Operation::Delete || ev.before_rows.is_empty() {
            return;
        }
        // Errors are logged, never propagated: the rows are already gone, and an observer cannot
        // fail the write that called it. A missed enqueue is picked up by the next full resync; a
        // missed *serial bump* is not, which is why it is the half worth shouting about.
        if ev.entity == "zone" {
            for origin in ev.before_rows.iter().filter_map(|r| r["origin"].as_str()) {
                log(enqueue_remove(&self.db, origin).await, origin, "enqueue removal");
                tracing::info!(%origin, "console delete: queued a zone removal");
            }
            return;
        }
        if !ev.entity.starts_with("rr_") {
            return; // an account, a grant, an API key, a lockout row: nothing to do with DNS
        }
        let mut ids: Vec<i32> = ev.before_rows.iter().filter_map(zone_id_of).collect();
        ids.sort_unstable();
        ids.dedup();
        for id in ids {
            let Ok(Some(z)) = zone::Entity::find_by_id(id).one(&self.db).await else { continue };
            // Both, and in this order: a push carrying an unchanged serial leaves every secondary
            // on the old copy, so the bump is the half that must not be skipped.
            log(bump_serial(&self.db, id).await, &z.origin, "bump serial");
            log(enqueue(&self.db, &z.origin).await, &z.origin, "enqueue push");
            tracing::info!(origin = %z.origin, "console delete: bumped serial and queued a push");
        }
    }
}

fn log(r: Result<(), DbErr>, origin: &str, what: &str) {
    if let Err(e) = r {
        tracing::error!(%origin, error = %e, "console delete: could not {what}");
    }
}

/// The zone a record row belongs to, from a row as the crud engine renders it.
///
/// The engine **embeds a to-one relation under the relation's name**, not the foreign key's:
/// `{"label": "www", "zone": {"id": 7, "label": "example.com."}}`. Reading `zone_id` finds nothing,
/// silently — which is exactly the shape of bug this function exists to stop, so both spellings are
/// accepted and a row that has neither is skipped rather than guessed at.
fn zone_id_of(row: &serde_json::Value) -> Option<i32> {
    let v = &row["zone"];
    v["id"].as_i64().or_else(|| v.as_i64()).or_else(|| row["zone_id"].as_i64()).map(|n| n as i32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Pinning the row shape, because getting it wrong fails **silently**: `capture` resolves no
    /// zones, falls back to re-pushing everything, and the only symptom is a warning in a log
    /// nobody reads. The embedded form is what the engine actually renders (verified against a
    /// running server); the other two are accepted so a library change can't quietly break this.
    #[test]
    fn a_records_zone_is_read_from_whichever_shape_the_row_uses() {
        let embedded = json!({"label": "www", "zone": {"id": 7, "label": "example.com."}});
        assert_eq!(zone_id_of(&embedded), Some(7), "the shape the engine really emits");
        assert_eq!(zone_id_of(&json!({"zone": 7})), Some(7), "a bare relation id");
        assert_eq!(zone_id_of(&json!({"zone_id": 7})), Some(7), "the raw foreign key");
        assert_eq!(zone_id_of(&json!({"label": "www"})), None, "no zone: skipped, not guessed");
    }
}
