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
            Box::new(m0006_audit_ts_index::Migration),
            Box::new(m0007_zone_template::Migration),
            Box::new(m0008_auth_cascades::Migration),
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

/// An index on `audit (ts, source)`. Not a model change — no column, no data rewrite.
///
/// The audit log is append-only and retained a year by default, so it is the biggest table in a
/// busy deployment (a fleet of DDNS clients writes a row per update). Two things scan it by time:
/// `audit::prune` (`DELETE … WHERE ts < ?`) at startup, and the dashboard's activity panel, which
/// asks "how many writes, per surface, since T" six times per page load. Unindexed, each of those
/// is a full scan. `(ts, source)` is leading-column-usable for the plain range, and **covering**
/// for the panel's `WHERE ts >= ? GROUP BY source` — it never touches the row.
mod m0006_audit_ts_index {
    use sea_orm_migration::prelude::*;

    pub struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m0006_audit_ts_index"
        }
    }

    #[async_trait::async_trait]
    impl MigrationTrait for Migration {
        async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
            m.create_index(
                Index::create()
                    .name("ix_audit_ts_source")
                    .table(Alias::new("audit"))
                    .col(Alias::new("ts"))
                    .col(Alias::new("source"))
                    .to_owned(),
            )
            .await
        }

        async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
            m.drop_index(Index::drop().name("ix_audit_ts_source").table(Alias::new("audit")).to_owned())
                .await
        }
    }
}

/// `zone.template` — the knot.conf template this zone is declared under, `NULL` meaning "use
/// `default_knot_template`".
///
/// Nullable on purpose: `NULL` is not a missing value here, it is the *answer* "whatever the server
/// says", so a deployment that never sets it keeps behaving exactly as it did when there was one
/// global template. A zone that names a template pins itself to it — which is how a signed zone
/// (under a `dnssec-signing` policy) lives beside unsigned ones on the same Knot.
///
/// **Guarded by `has_column`, and it must be.** `m0001_init` builds its tables from the *live*
/// entity definitions, so the day `zone::Model` gained this field `m0001` started creating it too:
/// on a fresh database the column already exists by the time this step runs, while an existing one
/// still needs it. The same reason `m0003` is guarded — see its note.
mod m0007_zone_template {
    use sea_orm_migration::prelude::*;

    pub struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m0007_zone_template"
        }
    }

    #[async_trait::async_trait]
    impl MigrationTrait for Migration {
        async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
            if m.has_column("zone", "template").await? {
                return Ok(()); // fresh database: m0001_init already built it from the entity
            }
            m.alter_table(
                Table::alter()
                    .table(Alias::new("zone"))
                    .add_column(ColumnDef::new(Alias::new("template")).text().null())
                    .to_owned(),
            )
            .await
        }

        async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
            if !m.has_column("zone", "template").await? {
                return Ok(());
            }
            m.alter_table(
                Table::alter()
                    .table(Alias::new("zone"))
                    .drop_column(Alias::new("template"))
                    .to_owned(),
            )
            .await
        }
    }
}

/// Give the auth foreign keys `ON DELETE CASCADE`, so deleting a user takes their sessions,
/// recovery codes and group memberships with them.
///
/// **And teleddns's own tables have the same defect**, which the library release does not touch:
/// `api_key.user_id`, and the `group_id` / `zone_id` of both grant tables, were all `NO ACTION`. An
/// API key is its owner and must die with them; a grant naming a deleted group or zone grants
/// nothing. In every case the rows also *blocked* the deletion, so this is one fix, not two.
///
/// relativelylight 0.3.2 fixed the schema: `auth_session.user_id` and `auth_totp_recovery.user_id`
/// had **no foreign key at all**, so a deleted account left credential-shaped rows owned by nobody,
/// and `auth_user_group` declared its keys with no `ON DELETE` action, so deleting a user who
/// belonged to any group failed outright — surfacing in the console as a `409` with no way forward.
///
/// **Guarded, and it must be** (see `m0007`'s note): `m0001_init` builds the auth tables from the
/// *live* `auth::table_create_statements`, so a database created on 0.3.2 already has the cascades
/// and this step must do nothing. Only one upgraded from an earlier release needs the work.
///
/// **SQLite cannot add a constraint in place** — `ALTER TABLE` only renames and adds columns — so
/// each table is rebuilt: create the new shape under a temporary name, copy every row by explicit
/// column name, drop the original, rename the new one in
/// ([SQLite's own procedure](https://sqlite.org/lang_altertable.html#otheralter)). Two details make
/// that safe here. `sea-orm-migration` runs SQLite migrations **outside** a transaction — it opens
/// one only for PostgreSQL — so `PRAGMA foreign_keys=OFF` actually takes effect, and this step can
/// open a transaction of its own. And the whole thing is one `execute_unprepared` because the pool
/// hands out any connection it likes: `BEGIN` and `COMMIT` issued as separate calls could land on
/// different connections.
///
/// PostgreSQL needs no rebuild, just `ALTER TABLE`, and gets the migrator's own transaction.
mod m0008_auth_cascades {
    use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
    use sea_orm_migration::prelude::*;

    pub struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m0008_auth_cascades"
        }
    }

    /// One table's worth of the change.
    struct Table {
        name: &'static str,
        /// How many of its foreign keys cascade once it is correct — the guard compares against this.
        cascades: i64,
        /// The target shape, as a fresh install gets it. Taken verbatim from a database created by
        /// `auth::table_create_statements` on 0.3.2, with the table renamed; regenerate after a
        /// library upgrade with `sqlite3 fresh.sqlite '.schema auth_session'`.
        sqlite_ddl: &'static str,
        /// Copied by **name**, never `SELECT *`: a difference in column order between the old table
        /// and the new one would otherwise shift values quietly into the wrong columns.
        columns: &'static str,
        /// A row that cannot satisfy the new key — its owner was deleted before the upgrade, when
        /// nothing stopped that. It must go first or the copy fails.
        orphans: &'static str,
        /// `(column, referenced table)` per foreign key, for the PostgreSQL path.
        keys: &'static [(&'static str, &'static str)],
        /// Explicit indexes to recreate: `DROP TABLE` takes them with it, and losing a **unique**
        /// index would quietly re-permit the duplicate grants it exists to forbid. Indexes SQLite
        /// creates itself for `PRIMARY KEY` / `UNIQUE` columns come back with the new DDL and are
        /// not listed here.
        indexes: &'static [&'static str],
    }

    const TABLES: [Table; 6] = [
        Table {
            name: "auth_session",
            cascades: 1,
            sqlite_ddl: r#"CREATE TABLE "auth_session__new" ( "id" varchar NOT NULL PRIMARY KEY, "user_id" integer NOT NULL, "expires_at" bigint NOT NULL, "last_seen_at" bigint NOT NULL, "awaiting_totp" boolean NOT NULL, FOREIGN KEY ("user_id") REFERENCES "auth_user" ("id") ON DELETE CASCADE )"#,
            columns: r#""id", "user_id", "expires_at", "last_seen_at", "awaiting_totp""#,
            orphans: "user_id NOT IN (SELECT id FROM auth_user)",
            keys: &[("user_id", "auth_user")],
            indexes: &[],
        },
        Table {
            name: "auth_totp_recovery",
            cascades: 1,
            sqlite_ddl: r#"CREATE TABLE "auth_totp_recovery__new" ( "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "user_id" integer NOT NULL, "code_hash" varchar NOT NULL, "created_at" bigint NOT NULL, "used_at" bigint, FOREIGN KEY ("user_id") REFERENCES "auth_user" ("id") ON DELETE CASCADE )"#,
            columns: r#""id", "user_id", "code_hash", "created_at", "used_at""#,
            orphans: "user_id NOT IN (SELECT id FROM auth_user)",
            keys: &[("user_id", "auth_user")],
            indexes: &[],
        },
        Table {
            name: "auth_user_group",
            cascades: 2,
            sqlite_ddl: r#"CREATE TABLE "auth_user_group__new" ( "user_id" integer NOT NULL, "group_id" integer NOT NULL, CONSTRAINT "pk-auth_user_group" PRIMARY KEY ("user_id", "group_id"), FOREIGN KEY ("user_id") REFERENCES "auth_user" ("id") ON DELETE CASCADE, FOREIGN KEY ("group_id") REFERENCES "auth_group" ("id") ON DELETE CASCADE )"#,
            columns: r#""user_id", "group_id""#,
            orphans: "user_id NOT IN (SELECT id FROM auth_user) OR group_id NOT IN (SELECT id FROM auth_group)",
            keys: &[("user_id", "auth_user"), ("group_id", "auth_group")],
            indexes: &[],
        },
        // --- teleddns's own tables, the same defect in our schema ---
        Table {
            name: "api_key",
            cascades: 1,
            sqlite_ddl: r#"CREATE TABLE "api_key__new" ( "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "user_id" integer NOT NULL, "name" varchar NOT NULL, "hashed_key" varchar NOT NULL UNIQUE, "prefix" varchar NOT NULL, "expires_at" bigint, "last_used_at" bigint, "disabled" boolean NOT NULL, FOREIGN KEY ("user_id") REFERENCES "auth_user" ("id") ON DELETE CASCADE )"#,
            columns: r#""id", "user_id", "name", "hashed_key", "prefix", "expires_at", "last_used_at", "disabled""#,
            orphans: "user_id NOT IN (SELECT id FROM auth_user)",
            keys: &[("user_id", "auth_user")],
            indexes: &[],
        },
        Table {
            name: "zone_role",
            cascades: 2,
            sqlite_ddl: r#"CREATE TABLE "zone_role__new" ( "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "group_id" integer NOT NULL, "zone_id" integer NOT NULL, FOREIGN KEY ("group_id") REFERENCES "auth_group" ("id") ON DELETE CASCADE, FOREIGN KEY ("zone_id") REFERENCES "zone" ("id") ON DELETE CASCADE )"#,
            columns: r#""id", "group_id", "zone_id""#,
            orphans: "group_id NOT IN (SELECT id FROM auth_group) OR zone_id NOT IN (SELECT id FROM zone)",
            keys: &[("group_id", "auth_group"), ("zone_id", "zone")],
            indexes: &[
                r#"CREATE UNIQUE INDEX "ux_zone_role_group_zone" ON "zone_role" ("group_id", "zone_id")"#,
            ],
        },
        Table {
            name: "rr_role",
            cascades: 2,
            sqlite_ddl: r#"CREATE TABLE "rr_role__new" ( "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "group_id" integer NOT NULL, "zone_id" integer NOT NULL, "label" varchar NOT NULL, FOREIGN KEY ("group_id") REFERENCES "auth_group" ("id") ON DELETE CASCADE, FOREIGN KEY ("zone_id") REFERENCES "zone" ("id") ON DELETE CASCADE )"#,
            columns: r#""id", "group_id", "zone_id", "label""#,
            orphans: "group_id NOT IN (SELECT id FROM auth_group) OR zone_id NOT IN (SELECT id FROM zone)",
            keys: &[("group_id", "auth_group"), ("zone_id", "zone")],
            indexes: &[
                r#"CREATE UNIQUE INDEX "ux_rr_role_group_zone_label" ON "rr_role" ("group_id", "zone_id", "label")"#,
            ],
        },
    ];

    #[async_trait::async_trait]
    impl MigrationTrait for Migration {
        async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
            match m.get_database_backend() {
                DatabaseBackend::Sqlite => sqlite_up(m).await,
                DatabaseBackend::Postgres => postgres_up(m).await,
                // The app builds with sqlx-sqlite + sqlx-postgres only; nothing else can get here.
                DatabaseBackend::MySql => Ok(()),
            }
        }

        /// **Deliberately empty.** Reversing this would put back foreign keys that permit
        /// credential-shaped rows to outlive their owner, and the orphans the `up` deleted are gone
        /// either way — a `down` that restored the constraint but not the data would be a worse lie
        /// than no `down` at all. `m0004` (lower-casing names) is irreversible for the same reason.
        async fn down(&self, _m: &SchemaManager) -> Result<(), DbErr> {
            Ok(())
        }
    }

    /// How many of `table`'s foreign keys already cascade on delete.
    async fn cascading(m: &SchemaManager<'_>, table: &str) -> Result<i64, DbErr> {
        let db = m.get_connection();
        let sql = match m.get_database_backend() {
            DatabaseBackend::Sqlite => format!(
                r#"SELECT count(*) AS n FROM pragma_foreign_key_list('{table}') WHERE "on_delete" = 'CASCADE'"#
            ),
            // confdeltype 'c' is ON DELETE CASCADE.
            _ => format!(
                "SELECT count(*)::bigint AS n FROM pg_constraint \
                 WHERE conrelid = '{table}'::regclass AND contype = 'f' AND confdeltype = 'c'"
            ),
        };
        let row = db
            .query_one(Statement::from_string(m.get_database_backend(), sql))
            .await?
            .ok_or_else(|| DbErr::Custom(format!("{table}: could not read its foreign keys")))?;
        row.try_get("", "n")
    }

    /// Rows that would violate the new key — counted so the deletion is announced, not silent.
    async fn orphan_count(m: &SchemaManager<'_>, t: &Table) -> Result<i64, DbErr> {
        let db = m.get_connection();
        let sql = format!(
            r#"SELECT count(*) AS n FROM "{}" WHERE {}"#,
            t.name, t.orphans
        );
        let row = db
            .query_one(Statement::from_string(m.get_database_backend(), sql))
            .await?
            .ok_or_else(|| DbErr::Custom(format!("{}: could not count orphans", t.name)))?;
        row.try_get::<i64>("", "n")
    }

    /// Which tables still need the work, skipping any this database already has right.
    async fn todo(m: &SchemaManager<'_>) -> Result<Vec<&'static Table>, DbErr> {
        let mut out = Vec::new();
        for t in TABLES.iter() {
            if !m.has_table(t.name).await? {
                continue; // an earlier migration creates them all; belt and braces
            }
            if cascading(m, t.name).await? != t.cascades {
                out.push(t);
            }
        }
        Ok(out)
    }

    async fn sqlite_up(m: &SchemaManager<'_>) -> Result<(), DbErr> {
        let work = todo(m).await?;
        if work.is_empty() {
            return Ok(()); // a fresh database: m0001_init already built the cascading shape
        }

        // One string, one `execute_unprepared`, therefore one connection: the pool would happily
        // hand `BEGIN` and `COMMIT` to different ones. `PRAGMA foreign_keys` is a no-op inside a
        // transaction, so it sits outside — which only works because sea-orm-migration does not
        // wrap SQLite migrations in one.
        let mut sql = String::from("PRAGMA foreign_keys=OFF;\nBEGIN;\n");
        for t in &work {
            let n = orphan_count(m, t).await?;
            if n > 0 {
                tracing::warn!(
                    table = t.name,
                    rows = n,
                    "m0008: deleting rows whose owner was deleted before the upgrade — they cannot \
                     satisfy the new foreign key"
                );
                sql.push_str(&format!("DELETE FROM \"{}\" WHERE {};\n", t.name, t.orphans));
            }
            sql.push_str(&format!("DROP TABLE IF EXISTS \"{}__new\";\n", t.name));
            sql.push_str(t.sqlite_ddl);
            sql.push_str(";\n");
            sql.push_str(&format!(
                "INSERT INTO \"{0}__new\" ({1}) SELECT {1} FROM \"{0}\";\n",
                t.name, t.columns
            ));
            sql.push_str(&format!("DROP TABLE \"{0}\";\n", t.name));
            sql.push_str(&format!("ALTER TABLE \"{0}__new\" RENAME TO \"{0}\";\n", t.name));
            // The DROP took the table's explicit indexes with it. A missing unique index would not
            // fail anything here — it would quietly start permitting the duplicates it forbids.
            for idx in t.indexes {
                sql.push_str(idx);
                sql.push_str(";\n");
            }
        }
        sql.push_str("COMMIT;\nPRAGMA foreign_keys=ON;\n");

        m.get_connection().execute_unprepared(&sql).await?;

        // Prove it, rather than assume the DDL said what was meant.
        for t in &work {
            let got = cascading(m, t.name).await?;
            if got != t.cascades {
                return Err(DbErr::Custom(format!(
                    "{}: rebuilt but has {got} cascading foreign keys, expected {}",
                    t.name, t.cascades
                )));
            }
            for idx in t.indexes {
                // `CREATE UNIQUE INDEX "name" ON …` — the name is the second quoted token.
                let name = idx.split('"').nth(1).unwrap_or_default();
                if !m.has_index(t.name, name).await? {
                    return Err(DbErr::Custom(format!(
                        "{}: index {name} did not survive the rebuild",
                        t.name
                    )));
                }
            }
            tracing::info!(table = t.name, cascades = got, "m0008: rebuilt with cascading keys");
        }
        Ok(())
    }

    async fn postgres_up(m: &SchemaManager<'_>) -> Result<(), DbErr> {
        let work = todo(m).await?;
        if work.is_empty() {
            return Ok(());
        }
        let db = m.get_connection();
        let backend = m.get_database_backend();
        for t in &work {
            let n = orphan_count(m, t).await?;
            if n > 0 {
                tracing::warn!(table = t.name, rows = n, "m0008: deleting pre-upgrade orphans");
                db.execute_unprepared(&format!("DELETE FROM \"{}\" WHERE {}", t.name, t.orphans))
                    .await?;
            }
            // Drop whatever foreign keys the table has — 0.3.1 gave `auth_user_group` two without
            // an ON DELETE action and the other two tables none — then add them back cascading.
            // Dropping by looked-up name rather than a guessed one: the originals are generated.
            let existing = db
                .query_all(Statement::from_string(
                    backend,
                    format!(
                        "SELECT conname FROM pg_constraint \
                         WHERE conrelid = '{}'::regclass AND contype = 'f'",
                        t.name
                    ),
                ))
                .await?;
            for row in existing {
                let name: String = row.try_get("", "conname")?;
                db.execute_unprepared(&format!(
                    "ALTER TABLE \"{}\" DROP CONSTRAINT \"{name}\"",
                    t.name
                ))
                .await?;
            }
            for (column, target) in t.keys {
                db.execute_unprepared(&format!(
                    "ALTER TABLE \"{0}\" ADD CONSTRAINT \"fk-{0}-{column}\" \
                     FOREIGN KEY (\"{column}\") REFERENCES \"{target}\" (\"id\") ON DELETE CASCADE",
                    t.name
                ))
                .await?;
            }
            tracing::info!(table = t.name, "m0008: foreign keys replaced with cascading ones");
        }
        Ok(())
    }
}
