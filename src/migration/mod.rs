//! Versioned schema migrations (`sea-orm-migration`), embedded in the binary and run at startup via
//! [`Migrator::up`]. Migrations are applied once and recorded in a `seaql_migrations` table, so
//! restarts and upgrades are safe.
//!
//! A single migration creates the relativelylight `auth` tables (via
//! `relativelylight::auth::table_create_statements`) plus every app-owned table, in FK-safe order
//! (referenced tables first) — all from the *current* entity definitions, so a fresh DB always gets
//! the full column set (lifecycle timestamps included) in one shot. This is schema v1: no deployed
//! DB predates it, so there's nothing to preserve compatibility with. Later schema changes go in
//! *new* migration structs appended to [`Migrator::migrations`] — never edit a migration that has
//! shipped.

use sea_orm_migration::prelude::*;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(m0001_init::Migration), Box::new(m0002_lockout::Migration)]
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

            // relativelylight auth tables: auth_user, auth_group, auth_user_group, auth_session.
            for stmt in relativelylight::auth::table_create_statements(backend) {
                m.create_table(stmt).await?;
            }

            // App tables, referenced-first: zone before rr_*; auth (above) before roles/api_key.
            let schema = Schema::new(backend);
            use crate::model::{api_key, audit, idempotency, rr, rr_role, sync_task, zone, zone_role};
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
                audit::Entity,
            );

            // Uniqueness for the access grants (enforced in the DB, not just app code):
            // one zone grant per (group, zone); one record grant per (group, zone, label).
            m.create_index(
                Index::create()
                    .name("ux_zone_role_group_zone")
                    .table(Alias::new("zone_role"))
                    .col(Alias::new("group_id"))
                    .col(Alias::new("zone_id"))
                    .unique()
                    .to_owned(),
            )
            .await?;
            m.create_index(
                Index::create()
                    .name("ux_rr_role_group_zone_label")
                    .table(Alias::new("rr_role"))
                    .col(Alias::new("group_id"))
                    .col(Alias::new("zone_id"))
                    .col(Alias::new("label"))
                    .unique()
                    .to_owned(),
            )
            .await?;
            Ok(())
        }

        async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
            // Drop dependents before their targets (reverse of `up`).
            for table in [
                "audit",
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
                "auth_session",
                "auth_user_group",
                "auth_group",
                "auth_user",
            ] {
                m.drop_table(Table::drop().table(Alias::new(table)).if_exists().to_owned()).await?;
            }
            Ok(())
        }
    }
}

/// The relativelylight lockout tables (`auth_username_lockout`, `auth_ip_lockout`), added when the
/// brute-force brake moved from a process-local map into the database (PRD §3.6). A *fresh* database
/// already has them — `m0001` builds every table `auth::table_create_statements` reports, and that list
/// grew — so this step is `IF NOT EXISTS` and only does work on a DB created before the change.
mod m0002_lockout {
    use sea_orm_migration::prelude::*;

    pub struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m0002_lockout"
        }
    }

    #[async_trait::async_trait]
    impl MigrationTrait for Migration {
        async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
            let backend = m.get_database_backend();
            let schema = sea_orm::Schema::new(backend);
            for mut entity_stmt in [
                schema.create_table_from_entity(
                    relativelylight::auth::lockout::username_entity::Entity,
                ),
                schema.create_table_from_entity(relativelylight::auth::lockout::ip_entity::Entity),
            ] {
                m.create_table(entity_stmt.if_not_exists().to_owned()).await?;
            }
            Ok(())
        }

        async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
            for table in ["auth_ip_lockout", "auth_username_lockout"] {
                m.drop_table(Table::drop().table(Alias::new(table)).if_exists().to_owned()).await?;
            }
            Ok(())
        }
    }
}
