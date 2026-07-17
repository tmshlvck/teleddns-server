//! The DNS + supporting data model (SeaORM entities) and the schema migrator.

pub mod api_key;
pub mod idempotency;
pub mod roles;
pub mod rr;
pub mod sync_task;
pub mod zone;

pub use roles::{rr_role, zone_role};

use sea_orm::{ConnectionTrait, DatabaseConnection, DbErr, EntityTrait, Schema};

/// Current unix time in seconds.
pub fn now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Create every app-owned table if it does not yet exist. The relativelylight `auth` tables are
/// created separately by `auth::migrate`. This is an idempotent create-if-absent migrator; versioned
/// migrations can layer on later without changing the fresh-build path.
pub async fn migrate(db: &DatabaseConnection) -> Result<(), DbErr> {
    create_table(db, zone::Entity).await?;
    // RR tables (one per type).
    create_table(db, rr::a::Entity).await?;
    create_table(db, rr::aaaa::Entity).await?;
    create_table(db, rr::ns::Entity).await?;
    create_table(db, rr::ptr::Entity).await?;
    create_table(db, rr::cname::Entity).await?;
    create_table(db, rr::txt::Entity).await?;
    create_table(db, rr::mx::Entity).await?;
    create_table(db, rr::srv::Entity).await?;
    create_table(db, rr::caa::Entity).await?;
    create_table(db, rr::sshfp::Entity).await?;
    create_table(db, rr::tlsa::Entity).await?;
    create_table(db, rr::dnskey::Entity).await?;
    create_table(db, rr::ds::Entity).await?;
    create_table(db, rr::naptr::Entity).await?;
    // Supporting tables.
    create_table(db, api_key::Entity).await?;
    create_table(db, zone_role::Entity).await?;
    create_table(db, rr_role::Entity).await?;
    create_table(db, sync_task::Entity).await?;
    create_table(db, idempotency::Entity).await?;
    Ok(())
}

async fn create_table<E: EntityTrait>(db: &DatabaseConnection, e: E) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    let mut stmt = Schema::new(backend).create_table_from_entity(e);
    stmt.if_not_exists();
    db.execute(backend.build(&stmt)).await?;
    Ok(())
}
