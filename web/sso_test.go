package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alexedwards/scs/v2"
	"github.com/glebarez/sqlite"
	"github.com/tmshlvck/gone/auth"
	"gorm.io/gorm"

	"github.com/tmshlvck/teleddns-server/model"
)

func testAG(t *testing.T) *auth.AuthGORM {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ag, err := auth.NewAuthGORM(scs.New(), db)
	if err != nil {
		t.Fatal(err)
	}
	return ag
}

// fakeOIDC serves a minimal OIDC discovery document whose issuer is its own URL,
// enough for oidc.NewProvider (called by AddOIDCProvider) to succeed.
func fakeOIDC(t *testing.T) string {
	t.Helper()
	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                base,
			"authorization_endpoint":                base + "/auth",
			"token_endpoint":                        base + "/token",
			"jwks_uri":                              base + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	base = srv.URL
	return base
}

func TestToSSORules(t *testing.T) {
	in := []model.SSOGroupRule{
		{Regex: "@example\\.com$", Groups: []string{"users"}},
		{Claim: "groups", Equals: "dns-admins", Groups: []string{"admin"}},
	}
	out := toSSORules(in)
	if len(out) != 2 {
		t.Fatalf("len = %d", len(out))
	}
	if out[0].Regex != "@example\\.com$" || out[0].Groups[0] != "users" {
		t.Errorf("rule 0 = %+v", out[0])
	}
	if out[1].Claim != "groups" || out[1].Equals != "dns-admins" || out[1].Groups[0] != "admin" {
		t.Errorf("rule 1 = %+v", out[1])
	}
	if toSSORules(nil) != nil {
		t.Error("nil rules should map to nil")
	}
}

func TestRegisterSSO_NoProviders(t *testing.T) {
	if err := RegisterSSO(testAG(t), model.Config{}, quietLog()); err != nil {
		t.Fatalf("no providers should be a no-op: %v", err)
	}
}

func TestRegisterSSO_MissingPublicURL(t *testing.T) {
	cfg := model.Config{SSOProviders: []model.SSOProvider{{Name: "x", Issuer: "https://x", ClientID: "c"}}}
	if err := RegisterSSO(testAG(t), cfg, quietLog()); err == nil {
		t.Fatal("want error when public_url is empty")
	}
}

func TestRegisterSSO_MissingRequiredFields(t *testing.T) {
	cfg := model.Config{
		PublicURL:    "https://ddns.example.com",
		SSOProviders: []model.SSOProvider{{Name: "okta"}}, // no issuer / client_id
	}
	if err := RegisterSSO(testAG(t), cfg, quietLog()); err == nil {
		t.Fatal("want error when issuer/client_id are missing")
	}
}

func TestRegisterSSO_HappyPath(t *testing.T) {
	issuer := fakeOIDC(t)
	cfg := model.Config{
		PublicURL: "https://ddns.example.com/",
		SSOProviders: []model.SSOProvider{{
			Name: "corp", DisplayName: "Corp", Issuer: issuer, ClientID: "cid", ClientSecret: "sec",
			GroupRules: []model.SSOGroupRule{{Regex: ".*", Groups: []string{"guest"}}},
		}},
	}
	ag := testAG(t)
	if err := RegisterSSO(ag, cfg, quietLog()); err != nil {
		t.Fatalf("RegisterSSO: %v", err)
	}
	// Registering the same provider name again must be rejected by gone.
	if err := RegisterSSO(ag, cfg, quietLog()); err == nil {
		t.Fatal("re-registering the same provider name should error")
	}
}
