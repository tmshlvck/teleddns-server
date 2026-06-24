package ddns

import (
	"encoding/base64"
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
	srv *httptest.Server
	db  *gorm.DB
	ks  *model.KeyStore
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

	// admin user in the admin group (L3), plus a powerless user "bob".
	mustNil(t, ag.GroupAdd(model.AdminGroup))
	mustNil(t, ag.UserAdd("admin", "admin@x", "adminpw"))
	mustNil(t, ag.UserMod("admin", []string{model.AdminGroup}))
	mustNil(t, ag.UserAdd("bob", "bob@x", "bobpw"))

	// a zone (auto-NS) with host.example.com A + AAAA.
	z := model.Zone{Origin: "example.com."}
	mustNil(t, db.Create(&z).Error)
	mustNil(t, db.Create(&model.RRA{ZoneID: z.ID, Label: "host", TTL: 60, Value: "1.2.3.4"}).Error)
	mustNil(t, db.Create(&model.RRAAAA{ZoneID: z.ID, Label: "host", TTL: 60, Value: "2001:db8::1"}).Error)

	h := New(db, ag, ks, slog.New(slog.NewTextHandler(io.Discard, nil)), model.Defaults())
	r := chiRouter(h)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return &harness{srv: srv, db: db, ks: ks}
}

func (h *harness) issueKey(t *testing.T, username string, level int) string {
	t.Helper()
	var u auth.UserGORM
	mustNil(t, h.db.Where("username = ?", username).First(&u).Error)
	raw, err := h.ks.Issue(u.ID, "test", level, nil)
	mustNil(t, err)
	return raw
}

// get issues a GET with an optional Authorization header; returns status+body.
func (h *harness) get(t *testing.T, path, authz string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+path, nil)
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	resp, err := http.DefaultClient.Do(req)
	mustNil(t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b))
}

func bearer(raw string) string { return "Bearer " + raw }
func basic(u, p string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+p))
}

func TestDDNS_BearerUpdateAndNochg(t *testing.T) {
	h := setup(t)
	key := h.issueKey(t, "admin", 3)

	st, body := h.get(t, "/update?hostname=host.example.com&myip=5.6.7.8", bearer(key))
	if st != 200 || body != "good 5.6.7.8" {
		t.Fatalf("update: %d %q", st, body)
	}
	st, body = h.get(t, "/update?hostname=host.example.com&myip=5.6.7.8", bearer(key))
	if st != 200 || body != "nochg 5.6.7.8" {
		t.Fatalf("nochg: %d %q", st, body)
	}
	// serial bumped at least once for the change.
	var z model.Zone
	h.db.First(&z, "origin = ?", "example.com.")
	if z.SOASerial == 0 {
		t.Fatal("serial not bumped")
	}
}

func TestDDNS_BasicAuth(t *testing.T) {
	h := setup(t)
	st, body := h.get(t, "/update?hostname=host.example.com&myip=5.6.7.8", basic("admin", "adminpw"))
	if st != 200 || !strings.HasPrefix(body, "good") {
		t.Fatalf("basic update: %d %q", st, body)
	}
}

func TestDDNS_NoCreds(t *testing.T) {
	h := setup(t)
	st, body := h.get(t, "/update?hostname=host.example.com&myip=5.6.7.8", "")
	if st != 401 || body != "badauth" {
		t.Fatalf("want 401 badauth, got %d %q", st, body)
	}
}

func TestDDNS_AutoCreateAndNoZone(t *testing.T) {
	h := setup(t)
	key := h.issueKey(t, "admin", 3)
	// resolved zone but no record at label → auto-created → good.
	if st, b := h.get(t, "/update?hostname=missing.example.com&myip=1.1.1.1", bearer(key)); st != 200 || b != "good 1.1.1.1" {
		t.Fatalf("auto-create: %d %q", st, b)
	}
	// a second update of the now-existing record converges → nochg.
	if st, b := h.get(t, "/update?hostname=missing.example.com&myip=1.1.1.1", bearer(key)); st != 200 || b != "nochg 1.1.1.1" {
		t.Fatalf("converge created: %d %q", st, b)
	}
	// no zone matches → nohost.
	if st, b := h.get(t, "/update?hostname=host.other.tld&myip=1.1.1.1", bearer(key)); st != 404 || b != "nohost" {
		t.Fatalf("no zone: %d %q", st, b)
	}
}

func TestDDNS_BadIP(t *testing.T) {
	h := setup(t)
	key := h.issueKey(t, "admin", 3)
	if st, b := h.get(t, "/update?hostname=host.example.com&myip=not-an-ip", bearer(key)); st != 400 || b != "notfqdn" {
		t.Fatalf("want 400 notfqdn, got %d %q", st, b)
	}
}

func TestDDNS_NotYours(t *testing.T) {
	h := setup(t)
	key := h.issueKey(t, "bob", 1) // bob has no roles
	if st, b := h.get(t, "/update?hostname=host.example.com&myip=5.6.7.8", bearer(key)); st != 403 || !strings.HasPrefix(b, "!yours") {
		t.Fatalf("want 403 !yours, got %d %q", st, b)
	}
}

func TestDDNS_BothFamilies(t *testing.T) {
	h := setup(t)
	key := h.issueKey(t, "admin", 3)
	st, body := h.get(t, "/update?hostname=host.example.com&myip=9.9.9.9&myipv6=2001:db8::2", bearer(key))
	if st != 200 {
		t.Fatalf("status %d", st)
	}
	if !strings.Contains(body, "good 9.9.9.9") || !strings.Contains(body, "good 2001:db8::2") {
		t.Fatalf("both lines expected, got %q", body)
	}
}

func TestDDNS_PostNotAllowed(t *testing.T) {
	h := setup(t)
	resp, err := http.Post(h.srv.URL+"/update?hostname=host.example.com&myip=1.2.3.4", "text/plain", nil)
	mustNil(t, err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", resp.StatusCode)
	}
}

func TestDDNS_RateLimit(t *testing.T) {
	h := setup(t)
	// Force a tiny budget.
	cfg := model.Defaults()
	cfg.DDNSRatePerRecord = 2
	hd := New(h.db, mustAuth(t, h.db), h.ks, slog.New(slog.NewTextHandler(io.Discard, nil)), cfg)
	srv := httptest.NewServer(chiRouter(hd))
	defer srv.Close()
	key := h.issueKey(t, "admin", 3)

	url := srv.URL + "/update?hostname=host.example.com&myip=5.6.7.8"
	codeFor := func() int {
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		req.Header.Set("Authorization", bearer(key))
		resp, err := http.DefaultClient.Do(req)
		mustNil(t, err)
		resp.Body.Close()
		return resp.StatusCode
	}
	codeFor()
	codeFor()
	if st := codeFor(); st != http.StatusTooManyRequests {
		t.Fatalf("3rd request want 429, got %d", st)
	}
}

func TestDDNS_BasicRejectedForTOTP(t *testing.T) {
	h := setup(t)
	// enrol a fake TOTP secret on bob, then try basic.
	mustNil(t, h.db.Model(&auth.UserGORM{}).Where("username = ?", "bob").Update("totp_secret", "SECRET").Error)
	st, body := h.get(t, "/update?hostname=host.example.com&myip=5.6.7.8", basic("bob", "bobpw"))
	if st != 401 || body != "badauth" {
		t.Fatalf("want 401 badauth for TOTP user on basic, got %d %q", st, body)
	}
}

// helpers ----------------------------------------------------------------

func mustNil(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustAuth(t *testing.T, db *gorm.DB) *auth.AuthGORM {
	t.Helper()
	ag, err := auth.NewAuthGORM(scs.New(), db)
	mustNil(t, err)
	return ag
}

func chiRouter(h *Handler) http.Handler {
	r := chi.NewRouter()
	h.RegisterRoutes(r)
	return r
}
