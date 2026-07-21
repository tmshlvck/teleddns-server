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
        vec![
            Box::new(m0001_init::Migration),
            Box::new(m0002_audit::Migration),
            Box::new(m0003_row_timestamps::Migration),
        ]
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

mod m0002_audit {
    use sea_orm::{ConnectionTrait, Schema};
    use sea_orm_migration::prelude::*;

    pub struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m0002_audit"
        }
    }

    #[async_trait::async_trait]
    impl MigrationTrait for Migration {
        async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
            // The audit log table (new for every deployment).
            let schema = Schema::new(m.get_database_backend());
            let mut stmt = schema.create_table_from_entity(crate::model::audit::Entity);
            stmt.if_not_exists();
            m.create_table(stmt).await?;

            // Auth lifecycle timestamps (added to relativelylight alongside the audit hook). On a DB
            // whose auth tables were created *before* those columns existed (an upgrade), add them; on
            // a fresh DB the columns already exist (created by m0001's table_create_statements), so the
            // "duplicate column" error is expected and ignored.
            let db = m.get_connection();
            for sql in [
                "ALTER TABLE auth_user ADD COLUMN created_at bigint NOT NULL DEFAULT 0",
                "ALTER TABLE auth_user ADD COLUMN updated_at bigint NOT NULL DEFAULT 0",
                "ALTER TABLE auth_user ADD COLUMN last_login_at bigint",
                "ALTER TABLE auth_group ADD COLUMN created_at bigint NOT NULL DEFAULT 0",
                "ALTER TABLE auth_group ADD COLUMN updated_at bigint NOT NULL DEFAULT 0",
            ] {
                let _ = db.execute_unprepared(sql).await;
            }
            Ok(())
        }

        async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
            m.drop_table(Table::drop().table(Alias::new("audit")).if_exists().to_owned()).await?;
            // The auth columns are left in place (per-engine column drops aren't worth it).
            Ok(())
        }
    }
}

mod m0003_row_timestamps {
    use sea_orm::ConnectionTrait;
    use sea_orm_migration::prelude::*;

    pub struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m0003_row_timestamps"
        }
    }

    #[async_trait::async_trait]
    impl MigrationTrait for Migration {
        async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
            // Add created_at/updated_at (UTC Unix seconds) to the zone + every RR table. As with
            // m0002's auth columns: an upgrade adds them; a fresh DB already has them (from m0001's
            // create_table_from_entity), so the "duplicate column" error is expected and ignored.
            let db = m.get_connection();
            let tables = [
                "zone", "rr_a", "rr_aaaa", "rr_ns", "rr_ptr", "rr_cname", "rr_txt", "rr_mx",
                "rr_srv", "rr_caa", "rr_sshfp", "rr_tlsa", "rr_dnskey", "rr_ds", "rr_naptr",
            ];
            for t in tables {
                let _ = db
                    .execute_unprepared(&format!(
                        "ALTER TABLE {t} ADD COLUMN created_at bigint NOT NULL DEFAULT 0"
                    ))
                    .await;
                let _ = db
                    .execute_unprepared(&format!(
                        "ALTER TABLE {t} ADD COLUMN updated_at bigint NOT NULL DEFAULT 0"
                    ))
                    .await;
            }
            Ok(())
        }

        async fn down(&self, _m: &SchemaManager) -> Result<(), DbErr> {
            Ok(()) // columns left in place
        }
    }
}
