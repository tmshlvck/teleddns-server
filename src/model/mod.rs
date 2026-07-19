//! The DNS + supporting data model (SeaORM entities). The schema is created by the versioned
//! migrator in [`crate::migration`], run at startup.

pub mod api_key;
pub mod idempotency;
pub mod roles;
pub mod rr;
pub mod sync_task;
pub mod zone;

pub use roles::{rr_role, zone_role};

/// Current unix time in seconds.
pub fn now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}
