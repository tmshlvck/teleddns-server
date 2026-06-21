package knot

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/tmshlvck/gone/auth"
	"github.com/tmshlvck/gone/site"
	"gorm.io/gorm"

	"github.com/tmshlvck/teleddns-server/model"
)

func testDB(t *testing.T) *gorm.DB {
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
	if err := model.MigrateDNS(db); err != nil {
		t.Fatal(err)
	}
	return db
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestRenderZone(t *testing.T) {
	db := testDB(t)
	z := model.Zone{Origin: "example.com."}
	if err := db.Create(&z).Error; err != nil { // auto apex NS to ns1.example.com.
		t.Fatal(err)
	}
	mk := func(v any) {
		if err := db.Create(v).Error; err != nil {
			t.Fatal(err)
		}
	}
	mk(&model.RRA{ZoneID: z.ID, Label: "host", TTL: 60, Value: "1.2.3.4"})
	mk(&model.RRAAAA{ZoneID: z.ID, Label: "host", TTL: 60, Value: "2001:db8::1"})
	mk(&model.RRMX{ZoneID: z.ID, Label: "@", TTL: 3600, Priority: 10, Value: "mail.example.com."})
	mk(&model.RRTXT{ZoneID: z.ID, Label: "@", TTL: 3600, Value: "hello world"})
	mk(&model.RRCAA{ZoneID: z.ID, Label: "@", TTL: 3600, Flag: 0, Tag: "issue", Value: "letsencrypt.org"})

	out, err := RenderZone(db, "example.com.", 3600)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"$ORIGIN example.com.",
		"$TTL 3600",
		"@ 3600 IN SOA ns1.example.com. hostmaster.example.com. (",
		"@ 3600 IN NS ns1.example.com.",
		"host 60 IN A 1.2.3.4",
		"host 60 IN AAAA 2001:db8::1",
		"@ 3600 IN MX 10 mail.example.com.",
		`@ 3600 IN TXT "hello world"`,
		`@ 3600 IN CAA 0 issue "letsencrypt.org"`,
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("zone file missing line %q\n--- got ---\n%s", w, out)
		}
	}
}

// captureBackend records pushes and can be told to fail the first failN calls.
type captureBackend struct {
	mu     sync.Mutex
	pushes map[string]string
	failN  int
}

func (b *captureBackend) PushZone(_ context.Context, origin, content string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failN > 0 {
		b.failN--
		return errors.New("boom")
	}
	if b.pushes == nil {
		b.pushes = map[string]string{}
	}
	b.pushes[origin] = content
	return nil
}

func countTasks(db *gorm.DB, state string) int64 {
	var n int64
	db.Model(&model.SyncTask{}).Where("state = ?", state).Count(&n)
	return n
}

func TestWorkerSyncsAndCoalesces(t *testing.T) {
	db := testDB(t)
	z := model.Zone{Origin: "example.com."}
	db.Create(&z)                                                               // enqueues task #1 (via auto-NS hook)
	db.Create(&model.RRA{ZoneID: z.ID, Label: "host", Value: "1.2.3.4"})        // coalesced
	db.Create(&model.RRAAAA{ZoneID: z.ID, Label: "host", Value: "2001:db8::1"}) // coalesced

	if got := countTasks(db, model.SyncPending); got != 1 {
		t.Fatalf("coalescing: want 1 pending task, got %d", got)
	}

	be := &captureBackend{}
	w := &Worker{DB: db, Backend: be, Log: discardLog(), Interval: time.Hour, DefaultTTL: 3600}
	w.tick(context.Background())

	if got := countTasks(db, model.SyncDone); got != 1 {
		t.Fatalf("want 1 done task, got %d", got)
	}
	if got := countTasks(db, model.SyncPending); got != 0 {
		t.Fatalf("want 0 pending, got %d", got)
	}
	content := be.pushes["example.com."]
	if !strings.Contains(content, "host 3600 IN A 1.2.3.4") || !strings.Contains(content, "host 3600 IN AAAA 2001:db8::1") {
		t.Fatalf("pushed zone missing records:\n%s", content)
	}
}

func TestWorkerRetriesOnFailure(t *testing.T) {
	db := testDB(t)
	z := model.Zone{Origin: "example.com."}
	db.Create(&z)

	be := &captureBackend{failN: 1} // first push fails
	w := &Worker{DB: db, Backend: be, Log: discardLog(), Interval: time.Hour, DefaultTTL: 3600}
	w.tick(context.Background())

	var task model.SyncTask
	if err := db.First(&task).Error; err != nil {
		t.Fatal(err)
	}
	if task.State != model.SyncPending {
		t.Fatalf("after failure want pending, got %q", task.State)
	}
	if task.Attempts != 1 {
		t.Fatalf("want attempts=1, got %d", task.Attempts)
	}
	if !task.AvailableAt.After(time.Now()) {
		t.Fatalf("want backoff (available_at in future), got %v", task.AvailableAt)
	}
	if task.LastError == "" {
		t.Fatal("want last_error recorded")
	}
}
