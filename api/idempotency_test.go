package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alexedwards/scs/v2"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/glebarez/sqlite"
	"github.com/go-chi/chi/v5"
	"github.com/tmshlvck/gone/auth"
	"github.com/tmshlvck/gone/site"
	"gorm.io/gorm"

	"github.com/tmshlvck/teleddns-server/model"
)

// idemHarness wires the real stack — chi + the idempotency middleware + humachi
// + the API — behind an httptest server, since the humatest adapter bypasses
// chi middleware.
type idemHarness struct {
	srv *httptest.Server
	db  *gorm.DB
	key string
}

func setupIdem(t *testing.T) *idemHarness {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	mustNil(t, err)
	mustNil(t, site.ForceUTC(db))
	ag, err := auth.NewAuthGORM(scs.New(), db)
	mustNil(t, err)
	mustNil(t, model.MigrateDNS(db))
	ks, err := model.NewKeyStore(db)
	mustNil(t, err)
	mustNil(t, ag.GroupAdd(model.AdminGroup))
	mustNil(t, ag.UserAdd("admin", "admin@x", "pw"))
	mustNil(t, ag.UserMod("admin", []string{model.AdminGroup}))
	mustNil(t, db.Create(&model.Zone{Origin: "example.com."}).Error) // id 1

	var u auth.UserGORM
	mustNil(t, db.Where("username = ?", "admin").First(&u).Error)
	raw, err := ks.Issue(u.ID, "idem", 3, nil)
	mustNil(t, err)

	cfg := huma.DefaultConfig("test", "1.0.0")
	cfg.Components.SecuritySchemes = map[string]*huma.SecurityScheme{"bearer": {Type: "http", Scheme: "bearer"}}

	r := chi.NewRouter()
	idem, err := NewIdempotencyStore(db)
	mustNil(t, err)
	r.Use(idem.Middleware)
	humaAPI := humachi.New(r, cfg)
	Register(humaAPI, &Deps{DB: db, Keys: ks, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DefaultTTL: 3600})

	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return &idemHarness{srv: srv, db: db, key: raw}
}

func (h *idemHarness) post(t *testing.T, path, idemKey, body string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+h.key)
	req.Header.Set("Content-Type", "application/json")
	if idemKey != "" {
		req.Header.Set("Idempotency-Key", idemKey)
	}
	resp, err := http.DefaultClient.Do(req)
	mustNil(t, err)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func (h *idemHarness) countA(t *testing.T) int64 {
	t.Helper()
	var n int64
	mustNil(t, h.db.Model(&model.RRA{}).Count(&n).Error)
	return n
}

func recID(t *testing.T, body string) string {
	t.Helper()
	var rec APIRecord
	mustNil(t, json.Unmarshal([]byte(body), &rec))
	return rec.ID
}

func TestIdempotencyReplay(t *testing.T) {
	h := setupIdem(t)
	payload := `{"type":"A","name":"host","value":"1.2.3.4"}`

	// first create
	resp1, body1 := h.post(t, "/api/zones/1/rr", "key-1", payload)
	if resp1.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %s", resp1.StatusCode, body1)
	}
	if h.countA(t) != 1 {
		t.Fatalf("want 1 A record after create, got %d", h.countA(t))
	}

	// retry with the same key + body → replayed, NO new record
	resp2, body2 := h.post(t, "/api/zones/1/rr", "key-1", payload)
	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("replay status: %d", resp2.StatusCode)
	}
	if resp2.Header.Get("Idempotency-Replayed") != "true" {
		t.Errorf("missing Idempotency-Replayed header")
	}
	if body2 != body1 || recID(t, body2) != recID(t, body1) {
		t.Errorf("replay body differs:\n%s\n%s", body1, body2)
	}
	if n := h.countA(t); n != 1 {
		t.Fatalf("replay must not create a duplicate; got %d A records", n)
	}
}

func TestIdempotencyKeyReuseWithDifferentBody(t *testing.T) {
	h := setupIdem(t)
	if resp, _ := h.post(t, "/api/zones/1/rr", "key-2", `{"type":"A","name":"host","value":"1.2.3.4"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d", resp.StatusCode)
	}
	// same key, different body → 422
	resp, _ := h.post(t, "/api/zones/1/rr", "key-2", `{"type":"A","name":"other","value":"9.9.9.9"}`)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("key reuse with different body: want 422, got %d", resp.StatusCode)
	}
}

func TestNoIdempotencyKeyDoesNotDedup(t *testing.T) {
	h := setupIdem(t)
	payload := `{"type":"A","name":"host","value":"1.2.3.4"}`
	h.post(t, "/api/zones/1/rr", "", payload)
	h.post(t, "/api/zones/1/rr", "", payload)
	if n := h.countA(t); n != 2 {
		t.Fatalf("without a key, both POSTs should create; got %d", n)
	}
}
