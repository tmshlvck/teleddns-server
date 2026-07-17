//! Backend-push enqueueing + SOA-serial bumping. These run from two places: the SeaORM
//! `after_save` hooks on the zone/RR entities (so admin-UI create/edit are synced too) and directly
//! from the DDNS / native-API / CF write paths (which also cover deletes, since bulk deletes bypass
//! the per-row hooks). All are transaction-safe (they take whatever connection the caller holds).

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
