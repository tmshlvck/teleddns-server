package zoneimport

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/tmshlvck/gone/site"
	"gorm.io/gorm"

	"github.com/tmshlvck/teleddns-server/model"
)

const zoneText = `$ORIGIN example.com.
$TTL 3600
@   IN SOA ns1.example.com. hostmaster.example.com. ( 2024010101 7200 3600 1209600 3600 )
    IN NS ns1.example.com.
    IN NS ns2.example.com.
    IN MX 10 mail.example.com.
    IN A 93.184.216.34
www IN CNAME @
_acme-challenge IN TXT "tok"
bad IN HINFO "cpu" "os"
`

func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := site.ForceUTC(db); err != nil {
		t.Fatal(err)
	}
	if err := model.Migrate(db, discard()); err != nil {
		t.Fatal(err)
	}
	return db
}

func count[T any](db *gorm.DB) int64 {
	var n int64
	db.Model(new(T)).Count(&n)
	return n
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestImportNewZone(t *testing.T) {
	db := testDB(t)
	sum, err := Import(db, strings.NewReader(zoneText), "test", "", false, discard())
	if err != nil {
		t.Fatal(err)
	}
	if !sum.Created {
		t.Error("want Created=true")
	}
	if sum.Skipped != 1 { // HINFO is unsupported
		t.Errorf("skipped = %d, want 1", sum.Skipped)
	}
	if sum.Total() != 6 { // 2 NS + 1 MX + 1 A + 1 CNAME + 1 TXT
		t.Errorf("total = %d, want 6", sum.Total())
	}

	var z model.Zone
	if err := db.Where("origin = ?", "example.com.").First(&z).Error; err != nil {
		t.Fatal(err)
	}
	if z.SOASerial != 2024010101 {
		t.Errorf("SOA serial = %d, want 2024010101", z.SOASerial)
	}
	if z.SOAMName != "ns1.example.com." {
		t.Errorf("SOA mname = %q", z.SOAMName)
	}
	// The auto-created apex NS was dropped — exactly the file's 2 NS remain.
	if n := count[model.RRNS](db); n != 2 {
		t.Errorf("NS count = %d, want 2", n)
	}
	if n := count[model.RRTXT](db); n != 1 {
		t.Errorf("TXT count = %d, want 1", n)
	}
}

func TestImportReplaceVsMerge(t *testing.T) {
	db := testDB(t)
	mustImport(t, db, false)
	mustImport(t, db, false) // merge → duplicates
	if n := count[model.RRA](db); n != 2 {
		t.Errorf("after merge, A count = %d, want 2", n)
	}
	mustImport(t, db, true) // replace → back to the file's single A
	if n := count[model.RRA](db); n != 1 {
		t.Errorf("after replace, A count = %d, want 1", n)
	}
}

func mustImport(t *testing.T, db *gorm.DB, replace bool) {
	t.Helper()
	if _, err := Import(db, strings.NewReader(zoneText), "t", "", replace, discard()); err != nil {
		t.Fatal(err)
	}
}
