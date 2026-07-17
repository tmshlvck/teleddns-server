//! The `zone` entity. A zone carries its SOA inline (not as a separate record row). The serial is
//! bumped on every mutating change; zone creation auto-generates the SOA + a default apex NS.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
#[sea_orm(table_name = "zone")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    /// Fully-qualified origin with trailing dot, e.g. `example.com.`.
    #[sea_orm(unique)]
    pub origin: String,
    // --- SOA fields ---
    pub mname: String,
    pub rname: String,
    pub serial: i64,
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum: i32,
    pub ttl: i32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    /// Default SOA/NS-bearing zone for a freshly created origin. `serial` starts at 1; MNAME defaults
    /// to `ns.<origin>` and RNAME to `hostmaster.<origin>`.
    pub fn new_defaults(origin: &str, default_ttl: i32) -> ActiveModel {
        use sea_orm::ActiveValue::Set;
        ActiveModel {
            id: sea_orm::ActiveValue::NotSet,
            origin: Set(origin.to_string()),
            mname: Set(format!("ns.{origin}")),
            rname: Set(format!("hostmaster.{origin}")),
            serial: Set(1),
            refresh: Set(10800),
            retry: Set(3600),
            expire: Set(604800),
            minimum: Set(3600),
            ttl: Set(default_ttl),
        }
    }
}
