//! Versioned schema migrations (`sea-orm-migration`), embedded in the binary and run at startup via
//! [`Migrator::up`]. This replaces the old create-if-absent bootstrap: migrations are applied once and
//! recorded in a `seaql_migrations` table, so restarts and upgrades are safe.
//!
//! The initial migration creates the relativelylight `auth` tables (via
//! `relativelylight::auth::table_create_statements`) plus every app-owned table, in FK-safe order
//! (referenced tables first). Later schema changes go in *new* migration structs added to
//! [`Migrator::migrations`] — never edit a migration that has shipped.

use sea_orm_migration::prelude::*;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(m0001_init::Migration)]
    }
}

mod m0001_init {
    use sea_orm::Schema;
    use sea_orm_migration::prelude::*;

    pub struct Migration;

    // Explicit, stable name (DeriveMigrationName picks up "mod" from mod.rs).
    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m0001_init"
        }
    }

    #[async_trait::async_trait]
    impl MigrationTrait for Migration {
        async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
            let backend = m.get_database_backend();

            // relativelylight auth tables: rl_user, rl_group, rl_user_group, rl_session.
            for stmt in relativelylight::auth::table_create_statements(backend) {
                m.create_table(stmt).await?;
            }

            // App tables, referenced-first: zone before rr_*; auth (above) before roles/api_key.
            let schema = Schema::new(backend);
            use crate::model::{api_key, idempotency, rr, rr_role, sync_task, zone, zone_role};
            macro_rules! create {
                ($($ent:expr),* $(,)?) => {{
                    $( m.create_table(schema.create_table_from_entity($ent)).await?; )*
                }};
            }
            create!(zone::Entity);
            create!(
                rr::a::Entity, rr::aaaa::Entity, rr::ns::Entity, rr::ptr::Entity, rr::cname::Entity,
                rr::txt::Entity, rr::mx::Entity, rr::srv::Entity, rr::caa::Entity, rr::sshfp::Entity,
                rr::tlsa::Entity, rr::dnskey::Entity, rr::ds::Entity, rr::naptr::Entity,
            );
            create!(
                api_key::Entity,
                zone_role::Entity,
                rr_role::Entity,
                sync_task::Entity,
                idempotency::Entity,
            );
            Ok(())
        }

        async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
            // Drop dependents before their targets (reverse of `up`).
            for table in [
                "api_idempotency",
                "sync_task",
                "rr_role",
                "zone_role",
                "api_key",
                "rr_naptr",
                "rr_ds",
                "rr_dnskey",
                "rr_tlsa",
                "rr_sshfp",
                "rr_caa",
                "rr_srv",
                "rr_mx",
                "rr_txt",
                "rr_cname",
                "rr_ptr",
                "rr_ns",
                "rr_aaaa",
                "rr_a",
                "zone",
                "rl_session",
                "rl_user_group",
                "rl_group",
                "rl_user",
            ] {
                m.drop_table(Table::drop().table(Alias::new(table)).if_exists().to_owned()).await?;
            }
            Ok(())
        }
    }
}
