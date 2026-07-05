package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alexedwards/scs/v2"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/glebarez/sqlite"
	"github.com/tmshlvck/gone/auth"
	"github.com/tmshlvck/gone/site"
	"gorm.io/gorm"

	"github.com/tmshlvck/teleddns-server/model"
)

type harness struct {
	api  humatest.TestAPI
	db   *gorm.DB
	ks   *model.KeyStore
	logs *bytes.Buffer
}

func setup(t *testing.T) *harness {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := site.ForceUTC(db); err != nil {
		t.Fatal(err)
	}
	ag, err := auth.NewAuthGORM(scs.New(), db)
	if err != nil {
		t.Fatal(err)
	}
	if err := model.MigrateDNS(db); err != nil {
		t.Fatal(err)
	}
	ks, err := model.NewKeyStore(db)
	if err != nil {
		t.Fatal(err)
	}

	// admin (L3) + a regular user "bob" with no roles.
	mustNil(t, ag.GroupAdd(model.AdminGroup))
	mustNil(t, ag.UserAdd("admin", "admin@x", "pw"))
	mustNil(t, ag.UserMod("admin", []string{model.AdminGroup}))
	mustNil(t, ag.UserAdd("bob", "bob@x", "pw"))

	cfg := huma.DefaultConfig("test", "1.0.0")
	cfg.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		"bearer": {Type: "http", Scheme: "bearer"},
	}
	logs := &bytes.Buffer{}
	_, tapi := humatest.New(t, cfg)
	Register(tapi, &Deps{DB: db, Keys: ks, Log: slog.New(slog.NewTextHandler(logs, nil)), DefaultTTL: 3600})

	return &harness{api: tapi, db: db, ks: ks, logs: logs}
}

func (h *harness) key(t *testing.T, username string, level int) string {
	t.Helper()
	var u auth.UserGORM
	mustNil(t, h.db.Where("username = ?", username).First(&u).Error)
	raw, err := h.ks.Issue(u.ID, "test", level, nil)
	mustNil(t, err)
	return "Authorization: Bearer " + raw
}

func mustNil(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// grantZoneRole gives username's (new) group an L2 role on zoneID.
func (h *harness) grantZoneRole(t *testing.T, username, group string, zoneID uint) {
	t.Helper()
	var g auth.GroupGORM
	mustNil(t, h.db.Where("name = ?", group).First(&g).Error)
	mustNil(t, h.db.Create(&model.GroupZoneRole{GroupID: g.ID, ZoneID: zoneID, Level: 2}).Error)
}

func TestRequiresBearer(t *testing.T) {
	h := setup(t)
	if r := h.api.Get("/api/zones"); r.Code != http.StatusUnauthorized {
		t.Fatalf("no auth: want 401, got %d", r.Code)
	}
	if r := h.api.Get("/api/zones", "Authorization: Bearer teleddns_bogus"); r.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: want 401, got %d", r.Code)
	}
}

func TestZoneAndRecordLifecycle(t *testing.T) {
	h := setup(t)
	admin := h.key(t, "admin", 3)

	// create zone
	r := h.api.Post("/api/zones", admin, map[string]any{"origin": "example.com."})
	if r.Code != http.StatusCreated {
		t.Fatalf("create zone: %d %s", r.Code, r.Body.String())
	}
	var z struct {
		ID  uint `json:"id"`
		SOA struct {
			Serial uint32 `json:"serial"`
		} `json:"soa"`
	}
	decode(t, r, &z)
	if z.ID == 0 {
		t.Fatal("zone id not returned")
	}

	// list zones (admin sees it)
	r = h.api.Get("/api/zones", admin)
	if r.Code != 200 || r.Header().Get("X-Total-Count") != "1" {
		t.Fatalf("list zones: %d total=%q", r.Code, r.Header().Get("X-Total-Count"))
	}

	// create an A record
	r = h.api.Post("/api/zones/1/rr", admin, map[string]any{"type": "A", "name": "host", "value": "1.2.3.4"})
	if r.Code != http.StatusCreated {
		t.Fatalf("create A: %d %s", r.Code, r.Body.String())
	}
	var rec APIRecord
	decode(t, r, &rec)
	if rec.ID == "" || rec.Type != "A" || rec.Value != "1.2.3.4" {
		t.Fatalf("unexpected record: %+v", rec)
	}

	// list records includes the auto apex NS + the A
	r = h.api.Get("/api/zones/1/rr", admin)
	if r.Code != 200 {
		t.Fatalf("list rr: %d", r.Code)
	}
	if tot := r.Header().Get("X-Total-Count"); tot != "2" {
		t.Fatalf("want 2 records (NS+A), got %s\n%s", tot, r.Body.String())
	}

	// get by id
	r = h.api.Get("/api/zones/1/rr/"+rec.ID, admin)
	if r.Code != 200 {
		t.Fatalf("get rr: %d %s", r.Code, r.Body.String())
	}

	// update the A value → serial bumps
	r = h.api.Put("/api/zones/1/rr/"+rec.ID, admin, map[string]any{"type": "A", "name": "host", "value": "5.6.7.8"})
	if r.Code != 200 {
		t.Fatalf("update A: %d %s", r.Code, r.Body.String())
	}
	var updated APIRecord
	decode(t, r, &updated)
	if updated.Value != "5.6.7.8" {
		t.Fatalf("update did not take: %+v", updated)
	}

	// delete
	r = h.api.Delete("/api/zones/1/rr/"+rec.ID, admin)
	if r.Code != http.StatusNoContent {
		t.Fatalf("delete A: %d %s", r.Code, r.Body.String())
	}

	// serial advanced from the initial create
	var zr model.Zone
	h.db.First(&zr, z.ID)
	if zr.SOASerial <= z.SOA.Serial {
		t.Fatalf("serial did not advance: %d <= %d", zr.SOASerial, z.SOA.Serial)
	}
}

func TestAuditTagging(t *testing.T) {
	h := setup(t)
	admin := h.key(t, "admin", 3)

	if r := h.api.Post("/api/zones", admin, map[string]any{"origin": "audit.test."}); r.Code != http.StatusCreated {
		t.Fatalf("create zone: %d", r.Code)
	}
	logs := h.logs.String()
	for _, want := range []string{"source=api", "action=create", "type=Zone", "actor=admin"} {
		if !strings.Contains(logs, want) {
			t.Errorf("audit log missing %q in:\n%s", want, logs)
		}
	}
}

func TestValidationRejectsBadIP(t *testing.T) {
	h := setup(t)
	admin := h.key(t, "admin", 3)
	mustNil(t, h.db.Create(&model.Zone{Origin: "example.com."}).Error)

	r := h.api.Post("/api/zones/1/rr", admin, map[string]any{"type": "A", "name": "host", "value": "not-an-ip"})
	if r.Code != http.StatusUnprocessableEntity {
		t.Fatalf("bad IP: want 422, got %d %s", r.Code, r.Body.String())
	}
}

func TestRecordPaginationAcrossTypes(t *testing.T) {
	h := setup(t)
	admin := h.key(t, "admin", 3)
	z := model.Zone{Origin: "page.test."}
	mustNil(t, h.db.Create(&z).Error) // auto apex NS (1)
	for i := 0; i < 3; i++ {
		mustNil(t, h.db.Create(&model.RRA{ZoneID: z.ID, Label: fmt.Sprintf("a%d", i), TTL: 60, Value: fmt.Sprintf("10.0.0.%d", i+1)}).Error)
	}
	for i := 0; i < 2; i++ {
		mustNil(t, h.db.Create(&model.RRAAAA{ZoneID: z.ID, Label: fmt.Sprintf("b%d", i), TTL: 60, Value: fmt.Sprintf("2001:db8::%d", i+1)}).Error)
	}
	mustNil(t, h.db.Create(&model.RRMX{ZoneID: z.ID, Label: "@", TTL: 60, Priority: 10, Value: "mail.page.test."}).Error)
	// Global order (listOrder): NS(1), A(3), AAAA(2), MX(1) = 7.

	base := fmt.Sprintf("/api/zones/%d/rr", z.ID)
	p1 := listRR(t, h, base+"?per_page=3&page=1", admin)
	p2 := listRR(t, h, base+"?per_page=3&page=2", admin)
	p3 := listRR(t, h, base+"?per_page=3&page=3", admin)
	if len(p1) != 3 || len(p2) != 3 || len(p3) != 1 {
		t.Fatalf("page sizes: %d %d %d, want 3 3 1", len(p1), len(p2), len(p3))
	}
	if p1[0].Type != "NS" || p1[1].Type != "A" || p1[2].Type != "A" {
		t.Errorf("page1 types = %s %s %s, want NS A A", p1[0].Type, p1[1].Type, p1[2].Type)
	}
	if p2[0].Type != "A" || p2[1].Type != "AAAA" || p2[2].Type != "AAAA" {
		t.Errorf("page2 types = %s %s %s, want A AAAA AAAA (window spans a type boundary)", p2[0].Type, p2[1].Type, p2[2].Type)
	}
	if p3[0].Type != "MX" {
		t.Errorf("page3 type = %s, want MX", p3[0].Type)
	}
	seen := map[string]bool{}
	for _, r := range append(append(append([]APIRecord{}, p1...), p2...), p3...) {
		if seen[r.ID] {
			t.Errorf("record %s appears on more than one page", r.ID)
		}
		seen[r.ID] = true
	}
	if len(seen) != 7 {
		t.Errorf("distinct records across pages = %d, want 7", len(seen))
	}
}

// listRR fetches a record page and asserts the DB-computed X-Total-Count is 7.
func listRR(t *testing.T, h *harness, path, auth string) []APIRecord {
	t.Helper()
	r := h.api.Get(path, auth)
	if r.Code != 200 {
		t.Fatalf("list %s: %d", path, r.Code)
	}
	if got := r.Header().Get("X-Total-Count"); got != "7" {
		t.Fatalf("X-Total-Count for %s = %s, want 7", path, got)
	}
	var body []APIRecord
	mustNil(t, json.Unmarshal(r.Body.Bytes(), &body))
	return body
}

func TestAuthz(t *testing.T) {
	h := setup(t)
	mustNil(t, h.db.Create(&model.Zone{Origin: "example.com."}).Error)

	// bob has no roles → can't create a zone (L3) and sees no zones.
	bob := h.key(t, "bob", 3) // token level 3, but effective user level is 0
	if r := h.api.Post("/api/zones", bob, map[string]any{"origin": "other.com."}); r.Code != http.StatusForbidden {
		t.Fatalf("bob create zone: want 403, got %d", r.Code)
	}
	if r := h.api.Get("/api/zones", bob); r.Header().Get("X-Total-Count") != "0" {
		t.Fatalf("bob should see 0 zones, got %s", r.Header().Get("X-Total-Count"))
	}

	// Grant bob's group an L2 role on the zone → he can now create a record but
	// still not create a zone.
	mustNil(t, h.db.Create(&auth.GroupGORM{Name: "zoneadmins"}).Error)
	mustNil(t, addUserToGroup(h.db, "bob", "zoneadmins"))
	h.grantZoneRole(t, "bob", "zoneadmins", 1)

	if r := h.api.Post("/api/zones/1/rr", bob, map[string]any{"type": "TXT", "name": "x", "value": "hi"}); r.Code != http.StatusCreated {
		t.Fatalf("L2 bob create record: want 201, got %d %s", r.Code, r.Body.String())
	}
	if r := h.api.Post("/api/zones", bob, map[string]any{"origin": "other.com."}); r.Code != http.StatusForbidden {
		t.Fatalf("L2 bob create zone: want 403, got %d", r.Code)
	}
}

// addUserToGroup attaches an existing user to an existing group by name.
func addUserToGroup(db *gorm.DB, username, group string) error {
	var u auth.UserGORM
	if err := db.Where("username = ?", username).First(&u).Error; err != nil {
		return err
	}
	var g auth.GroupGORM
	if err := db.Where("name = ?", group).First(&g).Error; err != nil {
		return err
	}
	return db.Model(&u).Association("Groups").Append(&g)
}

// decode unmarshals a JSON response body into v.
func decode(t *testing.T, r *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(r.Body.Bytes(), v); err != nil {
		t.Fatalf("decode %q: %v", r.Body.String(), err)
	}
}
