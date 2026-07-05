package cfapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alexedwards/scs/v2"
	"github.com/glebarez/sqlite"
	"github.com/go-chi/chi/v5"
	"github.com/tmshlvck/gone/auth"
	"github.com/tmshlvck/gone/site"
	"gorm.io/gorm"

	"github.com/tmshlvck/teleddns-server/model"
)

type harness struct {
	srv  *httptest.Server
	db   *gorm.DB
	key  string
	logs *bytes.Buffer
}

func setup(t *testing.T) *harness {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	must(t, err)
	must(t, site.ForceUTC(db))
	ag, err := auth.NewAuthGORM(scs.New(), db)
	must(t, err)
	must(t, model.MigrateDNS(db))
	ks, err := model.NewKeyStore(db)
	must(t, err)

	must(t, ag.GroupAdd(model.AdminGroup))
	must(t, ag.UserAdd("admin", "admin@x", "pw"))
	must(t, ag.UserMod("admin", []string{model.AdminGroup}))
	must(t, db.Create(&model.Zone{Origin: "example.com."}).Error) // id 1, auto apex NS

	var u auth.UserGORM
	must(t, db.Where("username = ?", "admin").First(&u).Error)
	raw, err := ks.Issue(u.ID, "cf", 3, nil)
	must(t, err)

	logs := &bytes.Buffer{}
	r := chi.NewRouter()
	(&Deps{DB: db, Keys: ks, Log: slog.New(slog.NewTextHandler(logs, nil)), DefaultTTL: 3600}).RegisterRoutes(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return &harness{srv: srv, db: db, key: raw, logs: logs}
}

type env struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo *struct {
		Count      int `json:"count"`
		TotalCount int `json:"total_count"`
	} `json:"result_info"`
}

func (h *harness) do(t *testing.T, method, path, body string, auth bool) (int, env) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, h.srv.URL+path, r)
	if auth {
		req.Header.Set("Authorization", "Bearer "+h.key)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	must(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var e env
	if len(raw) > 0 {
		must(t, json.Unmarshal(raw, &e))
	}
	return resp.StatusCode, e
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAndAuth(t *testing.T) {
	h := setup(t)

	st, e := h.do(t, "GET", "/client/v4/user/tokens/verify", "", true)
	if st != 200 || !e.Success {
		t.Fatalf("verify: %d success=%v", st, e.Success)
	}
	// No token → 401, envelope success:false.
	st, e = h.do(t, "GET", "/client/v4/zones", "", false)
	if st != 401 || e.Success {
		t.Fatalf("no auth: want 401 success=false, got %d %v", st, e.Success)
	}
}

// TestCertManagerFlow mirrors cert-manager's DNS01 solver: verify token →
// resolve zone by name → check existing TXT → create → list → delete.
func TestCertManagerFlow(t *testing.T) {
	h := setup(t)

	// resolve zone by name
	st, e := h.do(t, "GET", "/client/v4/zones?name=example.com", "", true)
	if st != 200 {
		t.Fatalf("zones: %d", st)
	}
	var zones []cfZone
	must(t, json.Unmarshal(e.Result, &zones))
	if len(zones) != 1 || zones[0].Name != "example.com" {
		t.Fatalf("zone lookup: %+v", zones)
	}
	zid := zones[0].ID

	// no existing challenge record
	st, e = h.do(t, "GET", "/client/v4/zones/"+zid+"/dns_records?type=TXT&name=_acme-challenge.example.com", "", true)
	if st != 200 || e.ResultInfo.TotalCount != 0 {
		t.Fatalf("pre-create list: %d total=%v", st, e.ResultInfo)
	}

	// create the TXT
	st, e = h.do(t, "POST", "/client/v4/zones/"+zid+"/dns_records",
		`{"type":"TXT","name":"_acme-challenge.example.com","content":"tok123","ttl":60}`, true)
	if st != 200 || !e.Success {
		t.Fatalf("create TXT: %d %+v", st, e.Errors)
	}
	var rec cfRecord
	must(t, json.Unmarshal(e.Result, &rec))
	if rec.Type != "TXT" || rec.Name != "_acme-challenge.example.com" || rec.Content != "tok123" {
		t.Fatalf("created record: %+v", rec)
	}

	// list finds it (by name+content, as cert-manager filters)
	st, e = h.do(t, "GET", "/client/v4/zones/"+zid+"/dns_records?type=TXT&name=_acme-challenge.example.com&content=tok123", "", true)
	if st != 200 || e.ResultInfo.TotalCount != 1 {
		t.Fatalf("post-create list: %d total=%v", st, e.ResultInfo)
	}

	// delete by id
	st, e = h.do(t, "DELETE", "/client/v4/zones/"+zid+"/dns_records/"+rec.ID, "", true)
	if st != 200 || !e.Success {
		t.Fatalf("delete: %d %+v", st, e.Errors)
	}
	st, e = h.do(t, "GET", "/client/v4/zones/"+zid+"/dns_records?type=TXT", "", true)
	if st != 200 || e.ResultInfo.TotalCount != 0 {
		t.Fatalf("post-delete list: %d total=%v", st, e.ResultInfo)
	}
}

// TestExternalDNSFlow mirrors external-dns' cloudflare provider: list zones →
// create an A → PATCH its content.
func TestExternalDNSFlow(t *testing.T) {
	h := setup(t)

	st, e := h.do(t, "GET", "/client/v4/zones", "", true)
	if st != 200 || e.ResultInfo.TotalCount != 1 {
		t.Fatalf("list zones: %d total=%v", st, e.ResultInfo)
	}

	// create A with ttl=1 (automatic) → defaults to 3600
	st, e = h.do(t, "POST", "/client/v4/zones/1/dns_records",
		`{"type":"A","name":"host.example.com","content":"1.2.3.4","ttl":1}`, true)
	if st != 200 || !e.Success {
		t.Fatalf("create A: %d %+v", st, e.Errors)
	}
	var rec cfRecord
	must(t, json.Unmarshal(e.Result, &rec))
	if rec.Content != "1.2.3.4" || rec.TTL != 3600 || rec.Proxied {
		t.Fatalf("created A: %+v", rec)
	}

	// PATCH content
	st, e = h.do(t, "PATCH", "/client/v4/zones/1/dns_records/"+rec.ID, `{"content":"5.6.7.8"}`, true)
	if st != 200 || !e.Success {
		t.Fatalf("patch A: %d %+v", st, e.Errors)
	}
	var upd cfRecord
	must(t, json.Unmarshal(e.Result, &upd))
	if upd.Content != "5.6.7.8" {
		t.Fatalf("patched A: %+v", upd)
	}
}

func TestAuditTagging(t *testing.T) {
	h := setup(t)
	st, e := h.do(t, "POST", "/client/v4/zones/1/dns_records",
		`{"type":"A","name":"host.example.com","content":"1.2.3.4","ttl":1}`, true)
	if st != 200 || !e.Success {
		t.Fatalf("create A: %d", st)
	}
	logs := h.logs.String()
	for _, want := range []string{"source=cfapi", "action=create", "type=A", "actor=admin"} {
		if !strings.Contains(logs, want) {
			t.Errorf("audit log missing %q in:\n%s", want, logs)
		}
	}
}

func TestRecordListPagination(t *testing.T) {
	h := setup(t)
	for i := 0; i < 5; i++ {
		st, e := h.do(t, "POST", "/client/v4/zones/1/dns_records",
			fmt.Sprintf(`{"type":"A","name":"h%d.example.com","content":"10.0.0.%d","ttl":1}`, i, i+1), true)
		if st != 200 || !e.Success {
			t.Fatalf("create %d: %d", i, st)
		}
	}
	// page 2 of per_page 2 → the 3rd and 4th of 5, total_count 5, DB-paginated
	st, e := h.do(t, "GET", "/client/v4/zones/1/dns_records?type=A&per_page=2&page=2", "", true)
	if st != 200 || e.ResultInfo.TotalCount != 5 || e.ResultInfo.Count != 2 {
		t.Fatalf("page 2: %d total=%v", st, e.ResultInfo)
	}
	var recs []cfRecord
	must(t, json.Unmarshal(e.Result, &recs))
	if len(recs) != 2 {
		t.Fatalf("page 2 len = %d, want 2", len(recs))
	}
	// last page has the remainder
	_, e = h.do(t, "GET", "/client/v4/zones/1/dns_records?type=A&per_page=2&page=3", "", true)
	if e.ResultInfo.Count != 1 {
		t.Fatalf("page 3 count = %d, want 1", e.ResultInfo.Count)
	}
}

func TestRejectsBadInput(t *testing.T) {
	h := setup(t)
	// name outside the zone → 400 code 1004
	st, e := h.do(t, "POST", "/client/v4/zones/1/dns_records",
		`{"type":"A","name":"host.other.com","content":"1.2.3.4","ttl":1}`, true)
	if st != 400 || e.Success || e.Errors[0].Code != 1004 {
		t.Fatalf("out-of-zone: %d %+v", st, e.Errors)
	}
	// bad IPv4 → 400 (validation from the shared registry)
	st, e = h.do(t, "POST", "/client/v4/zones/1/dns_records",
		`{"type":"A","name":"host.example.com","content":"nope","ttl":1}`, true)
	if st != 400 || e.Success {
		t.Fatalf("bad ip: %d %+v", st, e.Errors)
	}
}
