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
        vec![
            Box::new(m0001_init::Migration),
            Box::new(m0002_lockout::Migration),
            Box::new(m0003_drop_api_key_level::Migration),
            Box::new(m0004_lowercase_names::Migration),
            Box::new(m0005_session_clocks_and_recovery::Migration),
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
                "auth_totp_recovery",
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

/// Drop `api_key.level`. The level was a *ceiling* on what a key could do relative to its owner, and
/// it went away with the L1/L2/L3 ladder, now the named roles of PRD §3: a key simply authenticates
/// as its owner, and
/// narrowing a device means giving the device its own account with its own grant. A fresh database
/// never had the column — `m0001` builds `api_key` from the current entity — so this only does work on
/// a database created before the change.
mod m0003_drop_api_key_level {
    use sea_orm_migration::prelude::*;

    pub struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m0003_drop_api_key_level"
        }
    }

    #[async_trait::async_trait]
    impl MigrationTrait for Migration {
        async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
            if !m.has_column("api_key", "level").await? {
                return Ok(());
            }
            m.alter_table(
                Table::alter().table(Alias::new("api_key")).drop_column(Alias::new("level")).to_owned(),
            )
            .await
        }

        async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
            if m.has_column("api_key", "level").await? {
                return Ok(());
            }
            m.alter_table(
                Table::alter()
                    .table(Alias::new("api_key"))
                    .add_column(ColumnDef::new(Alias::new("level")).integer().not_null().default(3))
                    .to_owned(),
            )
            .await
        }
    }
}

/// Canonicalize stored names to lower case. DNS is case-insensitive (RFC 4343), but our lookups are
/// exact string matches and a request always resolves to a lower-cased name — so a zone `Example.com.`
/// was never found, a `WWW` record was a second row beside `www`, and a `Thermostat` record grant
/// silently authorized nothing. Every write path now canonicalizes (`dns::normalize_label`); this
/// fixes what is already stored.
///
/// The two tables with a uniqueness constraint (`zone.origin`, `rr_role`) are updated only where the
/// lower-cased value is still free, and the step then **fails loudly** if any mixed-case row is left:
/// that means a genuine duplicate pair (`Example.com.` *and* `example.com.`), which only an operator
/// can resolve — silently dropping one would take records with it.
mod m0004_lowercase_names {
    use sea_orm::ConnectionTrait;
    use sea_orm_migration::prelude::*;

    /// Every table with a record `label` column (no uniqueness constraint on them).
    const RR_TABLES: [&str; 14] = [
        "rr_a", "rr_aaaa", "rr_ns", "rr_ptr", "rr_cname", "rr_txt", "rr_mx", "rr_srv", "rr_caa",
        "rr_sshfp", "rr_tlsa", "rr_dnskey", "rr_ds", "rr_naptr",
    ];

    pub struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m0004_lowercase_names"
        }
    }

    #[async_trait::async_trait]
    impl MigrationTrait for Migration {
        async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
            let db = m.get_connection();
            for t in RR_TABLES {
                db.execute_unprepared(&format!(
                    "UPDATE {t} SET label = lower(label) WHERE label <> lower(label)"
                ))
                .await?;
            }
            // Unique on `origin`: skip a row whose lower-cased origin is already taken.
            db.execute_unprepared(
                "UPDATE zone SET origin = lower(origin) WHERE origin <> lower(origin) \
                 AND NOT EXISTS (SELECT 1 FROM zone z2 WHERE z2.origin = lower(zone.origin))",
            )
            .await?;
            // Unique on (group_id, zone_id, label): same treatment.
            db.execute_unprepared(
                "UPDATE rr_role SET label = lower(label) WHERE label <> lower(label) \
                 AND NOT EXISTS (SELECT 1 FROM rr_role r2 WHERE r2.group_id = rr_role.group_id \
                 AND r2.zone_id = rr_role.zone_id AND r2.label = lower(rr_role.label))",
            )
            .await?;
            for (table, column) in [("zone", "origin"), ("rr_role", "label")] {
                let sql = format!("SELECT count(*) AS n FROM {table} WHERE {column} <> lower({column})");
                let left = db
                    .query_one(sea_orm::Statement::from_string(db.get_database_backend(), sql))
                    .await?
                    .map(|r| r.try_get::<i64>("", "n").unwrap_or(0))
                    .unwrap_or(0);
                if left > 0 {
                    return Err(DbErr::Custom(format!(
                        "{left} row(s) in `{table}` differ from their lower-cased `{column}` only by \
                         case, and the lower-cased value is already taken — DNS treats them as the \
                         same name. Merge or delete the duplicates in the admin console, then restart."
                    )));
                }
            }
            Ok(())
        }

        /// Case cannot be restored, and restoring it would only bring the bug back.
        async fn down(&self, _m: &SchemaManager) -> Result<(), DbErr> {
            Ok(())
        }
    }
}

/// The three schema additions relativelylight 0.2.0 makes to the auth tables: the `auth_totp_recovery`
/// table (single-use 2FA recovery codes), `auth_session.last_seen_at` (the idle-session clock) and
/// `auth_user.totp_last_step` (the TOTP replay guard). A *fresh* database already has all three —
/// `m0001` creates every table `auth::table_create_statements` reports, and the columns come from the
/// current entities — so each step here is conditional and does work only on a database created before
/// the upgrade.
///
/// `last_seen_at` is backfilled to **now**, not left at `0`: a zero reads as idle-expired, which would
/// sign every operator out the moment the new binary starts. The safe direction is arguably the other
/// one, but this is a fleet's own console and an upgrade is not a breach — losing every session on a
/// deploy is a worse surprise than carrying a session through it. `totp_last_step` is nullable and
/// means "no code spent yet", which is correct for every existing enrolment.
///
/// **Recovery codes are not backfilled** (deliberately, and there is nothing to backfill them from):
/// an account that enrolled 2FA under an earlier version has none until it generates a set from
/// `/profile`, where the page says so.
mod m0005_session_clocks_and_recovery {
    use sea_orm_migration::prelude::*;

    pub struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m0005_session_clocks_and_recovery"
        }
    }

    #[async_trait::async_trait]
    impl MigrationTrait for Migration {
        async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
            let backend = m.get_database_backend();
            let schema = sea_orm::Schema::new(backend);
            let mut stmt = schema
                .create_table_from_entity(relativelylight::auth::recovery::entity::Entity);
            m.create_table(stmt.if_not_exists().to_owned()).await?;

            if !m.has_column("auth_session", "last_seen_at").await? {
                m.alter_table(
                    Table::alter()
                        .table(Alias::new("auth_session"))
                        .add_column(
                            ColumnDef::new(Alias::new("last_seen_at"))
                                .big_integer()
                                .not_null()
                                .default(0),
                        )
                        .to_owned(),
                )
                .await?;
                // Existing sessions are live, not idle — see the module note above.
                sea_orm::ConnectionTrait::execute_unprepared(
                    m.get_connection(),
                    &format!(
                        "UPDATE auth_session SET last_seen_at = {} WHERE last_seen_at = 0",
                        crate::model::now()
                    ),
                )
                .await?;
            }
            if !m.has_column("auth_user", "totp_last_step").await? {
                m.alter_table(
                    Table::alter()
                        .table(Alias::new("auth_user"))
                        .add_column(ColumnDef::new(Alias::new("totp_last_step")).big_integer().null())
                        .to_owned(),
                )
                .await?;
            }
            Ok(())
        }

        async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
            m.drop_table(
                Table::drop().table(Alias::new("auth_totp_recovery")).if_exists().to_owned(),
            )
            .await?;
            for (table, column) in
                [("auth_session", "last_seen_at"), ("auth_user", "totp_last_step")]
            {
                if m.has_column(table, column).await? {
                    m.alter_table(
                        Table::alter()
                            .table(Alias::new(table))
                            .drop_column(Alias::new(column))
                            .to_owned(),
                    )
                    .await?;
                }
            }
            Ok(())
        }
    }
}
