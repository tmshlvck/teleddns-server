package model

import (
	"sort"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/tmshlvck/gone/auth"
	"github.com/tmshlvck/gone/site"
	"gorm.io/gorm"
)

// freshDB opens an in-memory SQLite with only the gone auth tables migrated —
// the state Migrate expects to find (FKs into auth_groups).
func freshDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := site.ForceUTC(db); err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&auth.UserGORM{}, &auth.GroupGORM{}); err != nil {
		t.Fatal(err)
	}
	return db
}

func columns(t *testing.T, db *gorm.DB, table string) []string {
	t.Helper()
	cts, err := db.Migrator().ColumnTypes(table)
	if err != nil {
		t.Fatalf("ColumnTypes(%s): %v", table, err)
	}
	var names []string
	for _, c := range cts {
		names = append(names, c.Name())
	}
	sort.Strings(names)
	return names
}

// TestMigrateFreshUsesInitSchema: a blank DB is built by InitSchema in one shot
// and every migration is recorded as applied, so nothing is left pending.
func TestMigrateFreshUsesInitSchema(t *testing.T) {
	db := freshDB(t)
	if err := Migrate(db, discardLog()); err != nil {
		t.Fatal(err)
	}
	applied := appliedVersions(db)
	// SCHEMA_INIT + the two migrations.
	if len(applied) != 3 {
		t.Fatalf("applied versions = %v, want SCHEMA_INIT + 0001 + 0002", applied)
	}
	// Fresh schema must not carry the retired column.
	if db.Migrator().HasColumn(&GroupZoneRole{}, "level") {
		t.Fatal("fresh DB still has group_zone_roles.level")
	}
	// Re-running is a no-op (idempotent).
	if err := Migrate(db, discardLog()); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
}

// TestMigrateLegacyDropsLevel simulates slon: a pre-tool DB whose
// group_zone_roles still has the level column, adopted by seeding the version
// table with SCHEMA_INIT + 0001 so InitSchema is skipped and only 0002 runs.
func TestMigrateLegacyDropsLevel(t *testing.T) {
	db := freshDB(t)

	// Build the pre-0002 schema (with level) exactly as migration 0001 does.
	if err := db.AutoMigrate(appModels()...); err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&groupZoneRoleV1{}); err != nil {
		t.Fatal(err)
	}
	if !db.Migrator().HasColumn(&groupZoneRoleV1{}, "level") {
		t.Fatal("setup: legacy DB should have level column")
	}
	// A real row must survive the drop.
	g := auth.GroupGORM{Name: "g1"}
	if err := db.Create(&g).Error; err != nil {
		t.Fatal(err)
	}
	z := Zone{Origin: "example.com."}
	if err := db.Create(&z).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO group_zone_roles (group_id, zone_id, level) VALUES (?, ?, 2)", g.ID, z.ID).Error; err != nil {
		t.Fatal(err)
	}

	// Adopt: seed the version table so InitSchema does NOT fire.
	if err := db.Exec("CREATE TABLE migrations (id VARCHAR(255) PRIMARY KEY)").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO migrations (id) VALUES ('SCHEMA_INIT'), ('0001_initial_schema')").Error; err != nil {
		t.Fatal(err)
	}

	if err := Migrate(db, discardLog()); err != nil {
		t.Fatal(err)
	}

	if db.Migrator().HasColumn(&GroupZoneRole{}, "level") {
		t.Fatal("legacy DB still has group_zone_roles.level after migrate")
	}
	// The unique index that SQLite's table-rebuild drops must be restored.
	if !db.Migrator().HasIndex(&GroupZoneRole{}, "idx_gzr_group_zone") {
		t.Fatal("idx_gzr_group_zone not restored after DropColumn rebuild")
	}
	var n int64
	db.Model(&GroupZoneRole{}).Count(&n)
	if n != 1 {
		t.Fatalf("role row count = %d, want 1 (row lost in migration)", n)
	}
	// Uniqueness must still bite.
	err := db.Exec("INSERT INTO group_zone_roles (group_id, zone_id) VALUES (?, ?)", g.ID, z.ID).Error
	if err == nil {
		t.Fatal("duplicate (group_id, zone_id) accepted — unique index missing")
	}
}

// TestMigrateNoDriftInitVsReplay is the guard that keeps the fresh-install
// shortcut honest: the schema built by InitSchema must be identical, table by
// table, to the schema produced by replaying every migration in order.
func TestMigrateNoDriftInitVsReplay(t *testing.T) {
	// Path A: InitSchema (the fresh-DB shortcut).
	initDB := freshDB(t)
	if err := Migrate(initDB, discardLog()); err != nil {
		t.Fatalf("init path: %v", err)
	}

	// Path B: replay migrations by hand, skipping InitSchema entirely.
	replayDB := freshDB(t)
	for _, m := range migrations(discardLog()) {
		if err := m.Migrate(replayDB); err != nil {
			t.Fatalf("replay %s: %v", m.ID, err)
		}
	}

	for _, model := range appModels() {
		stmt := &gorm.Statement{DB: initDB}
		if err := stmt.Parse(model); err != nil {
			t.Fatalf("parse model: %v", err)
		}
		name := stmt.Schema.Table
		a := columns(t, initDB, name)
		b := columns(t, replayDB, name)
		if len(a) != len(b) {
			t.Errorf("%s: column count init=%v replay=%v", name, a, b)
			continue
		}
		for i := range a {
			if a[i] != b[i] {
				t.Errorf("%s: columns differ init=%v replay=%v", name, a, b)
				break
			}
		}
	}
}
