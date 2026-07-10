package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/tmshlvck/gone/site"
	"gorm.io/gorm"

	"github.com/tmshlvck/teleddns-server/knot"
	"github.com/tmshlvck/teleddns-server/model"
)

func hcTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := site.ForceUTC(db); err != nil {
		t.Fatal(err)
	}
	if err := model.Migrate(db, discardLog()); err != nil {
		t.Fatal(err)
	}
	return db
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// runHealthcheck invokes the handler and returns the body's first token (OK or
// WARN) plus the full body.
func runHealthcheck(cfg model.Config, db *gorm.DB, w *knot.Worker, started time.Time) (string, string) {
	rr := httptest.NewRecorder()
	healthcheck(cfg, db, w, started)(rr, httptest.NewRequest(http.MethodGet, "/healthcheck", nil))
	body := rr.Body.String()
	return strings.Fields(body)[0], body
}

func TestHealthcheckOK(t *testing.T) {
	db := hcTestDB(t)
	cfg := model.Defaults()
	cfg.Backend = "log"
	w := &knot.Worker{DB: db, Backend: knot.NewBackend(cfg, discardLog()), Log: discardLog(), Interval: time.Hour}

	// Fresh start (uptime within grace), no tasks, log backend ⇒ knot=na.
	status, body := runHealthcheck(cfg, db, w, time.Now())
	if status != "OK" {
		t.Fatalf("want OK, got %q (body %q)", status, body)
	}
	if !strings.Contains(body, "knot=na") {
		t.Errorf("log backend should report knot=na: %q", body)
	}
	// HTTP status is always 200; only the body conveys OK/WARN.
	rr := httptest.NewRecorder()
	healthcheck(cfg, db, w, time.Now())(rr, httptest.NewRequest(http.MethodGet, "/healthcheck", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("want HTTP 200, got %d", rr.Code)
	}
}

func TestHealthcheckWarnDeadLetter(t *testing.T) {
	db := hcTestDB(t)
	cfg := model.Defaults()
	cfg.Backend = "log"
	w := &knot.Worker{DB: db, Backend: knot.NewBackend(cfg, discardLog()), Log: discardLog(), Interval: time.Hour}

	now := time.Now()
	db.Create(&model.SyncTask{Kind: model.SyncKindZone, Origin: "x.", State: model.SyncFailed,
		EnqueuedAt: now, AvailableAt: now})

	status, body := runHealthcheck(cfg, db, w, now)
	if status != "WARN" {
		t.Fatalf("dead-lettered task should WARN, got %q (body %q)", status, body)
	}
	if !strings.Contains(body, "failed=1") {
		t.Errorf("want failed=1 in body: %q", body)
	}
}

func TestHealthcheckWarnKnotDown(t *testing.T) {
	db := hcTestDB(t)
	cfg := model.Defaults()
	cfg.Backend = "knot"
	cfg.KnotcPath = "/nonexistent/knotc" // Status probe will fail
	cfg.BackendSyncPeriod = time.Minute  // grace = 2m
	w := &knot.Worker{DB: db, Backend: knot.NewBackend(cfg, discardLog()), Log: discardLog(), Interval: 5 * time.Millisecond}

	ctx, cancel := context.WithCancel(context.Background())
	go w.Run(ctx)
	defer cancel()
	// Wait for at least one tick to record the failed knot-status probe.
	deadline := time.Now().Add(2 * time.Second)
	for w.LastTick().IsZero() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	// Pretend the server has been up well past the grace window.
	status, body := runHealthcheck(cfg, db, w, time.Now().Add(-time.Hour))
	if status != "WARN" {
		t.Fatalf("unreachable knot should WARN, got %q (body %q)", status, body)
	}
	if !strings.Contains(body, "knot=down") {
		t.Errorf("want knot=down in body: %q", body)
	}
}
