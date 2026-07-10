package model

import (
	"log/slog"
	"time"

	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// Schema migrations (gormigrate).
//
// Two paths reach the same schema:
//
//   - Fresh database — the migrations table is empty, so InitSchema runs once,
//     builds the whole schema from appModels() (the current structs), and
//     stamps SCHEMA_INIT plus every migration ID below as already applied. No
//     migration body runs; a new install starts at the latest version.
//
//   - Existing database — InitSchema is skipped and every not-yet-recorded
//     migration runs in order. A database that predates this tool (no
//     migrations table) must be adopted once by hand — see docs/DEPLOY — by
//     seeding the version table so InitSchema does NOT fire (it only checks that
//     the table is empty, never whether the app tables already exist; letting it
//     fire would stamp the drop below as done without running it).
//
// Rules for adding a migration:
//   - Append; never edit or reorder an ID that may have run somewhere.
//   - Anything destructive (drop/rename) uses a frozen struct copy declared
//     next to the migration, never a live model that can change under it.
//   - Keep InitSchema == replaying every migration in order. migrate_test.go
//     asserts this, so the fresh-install shortcut can never drift from history.

// migrationTable is gormigrate's default version table (DefaultOptions). The
// adoption step in DEPLOY seeds rows here, so the name is part of the contract.
const migrationTable = "migrations"

// groupZoneRoleV1 is the frozen group_zone_roles as it existed before migration
// 0002: it still carries the dead `level` column. Kept as a local snapshot so
// migration 0001/0002 mean the same thing no matter how model.GroupZoneRole
// later changes. No association fields — the FK constraints are created by the
// live AutoMigrate in 0001; this type only adds the extra column.
type groupZoneRoleV1 struct {
	ID        uint `gorm:"primaryKey"`
	GroupID   uint `gorm:"not null;uniqueIndex:idx_gzr_group_zone"`
	ZoneID    uint `gorm:"not null;uniqueIndex:idx_gzr_group_zone"`
	Level     int  `gorm:"not null;default:2"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (groupZoneRoleV1) TableName() string { return "group_zone_roles" }

// migrations returns the ordered migration list. Bodies log through log so the
// journal shows exactly which step ran and what it did.
func migrations(log *slog.Logger) []*gormigrate.Migration {
	return []*gormigrate.Migration{
		{
			// The schema as it was when migrations were introduced: the full
			// app schema plus the legacy group_zone_roles.level column. In
			// practice this body never executes (fresh DBs stamp it via
			// InitSchema; adopted DBs seed it), but replaying it must still
			// reproduce the pre-0002 state so the chain stays coherent.
			ID: "0001_initial_schema",
			Migrate: func(tx *gorm.DB) error {
				log.Info("migrate: applying", "id", "0001_initial_schema",
					"detail", "create base schema incl. legacy group_zone_roles.level")
				if err := tx.AutoMigrate(appModels()...); err != nil {
					return err
				}
				return tx.AutoMigrate(&groupZoneRoleV1{}) // adds the level column
			},
			Rollback: func(tx *gorm.DB) error {
				return tx.Migrator().DropTable(appModels()...)
			},
		},
		{
			// Retire group_zone_roles.level. The grant is the row's existence;
			// a per-zone level can't express L3 (which is global), so the
			// column was never read and is removed. On SQLite DropColumn
			// rebuilds the table and drops idx_gzr_group_zone with it, so a
			// follow-up AutoMigrate restores the unique index.
			ID: "0002_drop_gzr_level",
			Migrate: func(tx *gorm.DB) error {
				m := tx.Migrator()
				if !m.HasColumn(&groupZoneRoleV1{}, "level") {
					log.Info("migrate: skipping", "id", "0002_drop_gzr_level",
						"detail", "group_zone_roles.level already absent")
					return nil
				}
				log.Info("migrate: applying", "id", "0002_drop_gzr_level",
					"detail", "drop group_zone_roles.level, restore idx_gzr_group_zone")
				if err := m.DropColumn(&groupZoneRoleV1{}, "level"); err != nil {
					return err
				}
				return tx.AutoMigrate(&GroupZoneRole{})
			},
			Rollback: func(tx *gorm.DB) error {
				return tx.AutoMigrate(&groupZoneRoleV1{})
			},
		},
	}
}

// Migrate brings db to the current schema, logging the path taken and every
// step. Call after the gone auth tables exist (NewAuthGORM): the role-grant
// tables carry FKs into auth_groups.
func Migrate(db *gorm.DB, log *slog.Logger) error {
	before := appliedVersions(db)
	if len(before) == 0 {
		log.Info("migrate: no version table yet — fresh database or first-time adoption")
	} else {
		log.Info("migrate: current schema version", "applied", before, "count", len(before))
	}

	opts := *gormigrate.DefaultOptions
	opts.UseTransaction = true // wrap each step so a failure can't leave a half-applied table
	m := gormigrate.New(db, &opts, migrations(log))

	// Fresh-database shortcut: build the whole schema from the current models
	// in one shot. gormigrate then records SCHEMA_INIT and every migration ID
	// as applied, so the incremental bodies above are skipped.
	m.InitSchema(func(tx *gorm.DB) error {
		log.Info("migrate: fresh database — initializing schema at current version",
			"tables", len(appModels()))
		return tx.AutoMigrate(appModels()...)
	})

	if err := m.Migrate(); err != nil {
		log.Error("migrate: failed", "err", err, "applied_before", before)
		return err
	}

	after := appliedVersions(db)
	switch {
	case len(before) == 0 && len(after) > 0:
		log.Info("migrate: done", "result", "schema initialized", "version", after)
	case len(after) > len(before):
		log.Info("migrate: done", "result", "applied", "new", diffVersions(before, after), "version", after)
	default:
		log.Info("migrate: done", "result", "already up to date", "version", after)
	}
	return nil
}

// appliedVersions returns the migration IDs recorded as applied, or nil when the
// version table does not exist yet. Best-effort: logging/diagnostics only.
func appliedVersions(db *gorm.DB) []string {
	if !db.Migrator().HasTable(migrationTable) {
		return nil
	}
	var ids []string
	db.Table(migrationTable).Order("id").Pluck("id", &ids)
	return ids
}

// diffVersions returns the IDs in after that were not in before.
func diffVersions(before, after []string) []string {
	seen := make(map[string]bool, len(before))
	for _, id := range before {
		seen[id] = true
	}
	var added []string
	for _, id := range after {
		if !seen[id] {
			added = append(added, id)
		}
	}
	return added
}
