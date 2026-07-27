//! `api_key` — a bearer token belonging to a user. Only the SHA-256 hash is stored; the raw key is
//! shown once on mint. A key has **no rights of its own**: it authenticates as its owner, and what that
//! owner may do is decided by the grant tables on every request (see `authz`). Only `disabled` and
//! `expires_at` limit it here.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
#[sea_orm(table_name = "api_key")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    /// Owner (FK → relativelylight auth `auth_user`).
    pub user_id: i32,
    /// Human-readable label.
    pub name: String,
    /// SHA-256 hex of the raw key.
    #[sea_orm(unique)]
    pub hashed_key: String,
    /// Short visible prefix of the raw key (for identification in listings).
    pub prefix: String,
    /// Optional expiry (unix seconds).
    pub expires_at: Option<i64>,
    /// Last time the key authenticated a request (unix seconds).
    pub last_used_at: Option<i64>,
    /// Administratively disabled.
    pub disabled: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "relativelylight::auth::user::Entity",
        from = "Column::UserId",
        to = "relativelylight::auth::user::Column::Id"
    )]
    User,
}

impl Related<relativelylight::auth::user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
