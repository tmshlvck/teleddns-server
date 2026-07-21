//! `audit` — an append-only log of state-changing (write) requests across every surface (DDNS, the
//! native API, the Cloudflare facade, and the admin/auth UI). Written by the [`crate::audit`] sink;
//! **read-only** in the admin. All timestamps are UTC Unix seconds. Retention is the app's
//! responsibility (teleddns prunes at `audit_retention_days`).

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
#[sea_orm(table_name = "audit")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    /// When it happened (UTC Unix seconds).
    pub ts: i64,
    /// Surface: `ddns` | `api` | `cfapi` | `crud` (admin auto-CRUD) | `auth-profile` | `auth-admin`.
    pub source: String,
    /// `create` | `update` | `delete`.
    pub operation: String,
    /// The affected target — `entity[/key]`, e.g. `zone/3`, `rr_a/12`, `auth_user/1`.
    pub target: String,
    /// Authenticated user id, if known.
    pub actor_user_id: Option<i32>,
    /// Authenticated username (or `-`).
    pub actor_username: String,
    /// How the caller authenticated: `session` | `basic` | `bearer` | `x-auth-key` | `none`.
    pub auth_type: String,
    /// Resolved client IP (post reverse-proxy rewrite).
    pub client_ip: String,
    /// Prior state (JSON), when captured. `NULL` on create or when not available.
    #[sea_orm(column_type = "Text", nullable)]
    pub before: Option<String>,
    /// New state (JSON), when captured. `NULL` on delete.
    #[sea_orm(column_type = "Text", nullable)]
    pub after: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
