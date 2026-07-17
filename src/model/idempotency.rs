//! `api_idempotency` — stored responses for `Idempotency-Key` replay on native-API POSTs. A retry
//! within 24h with the same key + body replays the original response; a different body → 422.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
#[sea_orm(table_name = "api_idempotency")]
pub struct Model {
    /// The client-supplied Idempotency-Key (scoped per user).
    #[sea_orm(primary_key, auto_increment = false)]
    pub key: String,
    pub user_id: i32,
    /// Hash of the original request body, to detect key reuse with a different payload.
    pub request_hash: String,
    pub status: i32,
    #[sea_orm(column_type = "Text")]
    pub response_body: String,
    pub created_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
