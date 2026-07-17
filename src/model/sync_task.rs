//! `sync_task` — the backend-push journal. A row is appended inside a mutation's transaction; the
//! worker drains it (coalesce per origin, at-least-once, retry with backoff, dead-letter).

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
#[sea_orm(table_name = "sync_task")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    /// Zone origin this push targets.
    pub origin: String,
    /// `zone` (regenerate + reload) or `zone-remove` (unset + delete).
    pub kind: String,
    /// `pending` | `in_flight` | `done` | `failed`.
    pub state: String,
    pub attempts: i32,
    /// Earliest unix time this row may be claimed (backoff/debounce).
    pub available_at: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

pub const KIND_ZONE: &str = "zone";
pub const KIND_ZONE_REMOVE: &str = "zone-remove";
pub const STATE_PENDING: &str = "pending";
pub const STATE_IN_FLIGHT: &str = "in_flight";
pub const STATE_DONE: &str = "done";
pub const STATE_FAILED: &str = "failed";
