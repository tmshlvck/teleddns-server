package web

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5/middleware"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// chain wires RealIP (as it runs behind trust_proxy) ahead of IPAllowlist, then
// a 200 handler — mirroring the operability-endpoint mount.
func chain(allowed []string) http.Handler {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return middleware.RealIP(IPAllowlist(allowed, quietLog())(ok))
}

func TestIPAllowlistEmptyAllowsAll(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	chain(nil).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("empty allowlist should allow all, got %d", rr.Code)
	}
}

func TestIPAllowlistBehindProxy(t *testing.T) {
	allowed := []string{"10.0.0.0/8"}

	// Real client (via X-Real-IP) inside the allowed range → 200, even though
	// the TCP peer (the proxy) is 127.0.0.1.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	req.Header.Set("X-Real-IP", "10.1.2.3")
	chain(allowed).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("forwarded client in range should be allowed, got %d", rr.Code)
	}

	// Forwarded client outside the range → 403.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	req.Header.Set("X-Real-IP", "203.0.113.7")
	chain(allowed).ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("forwarded client out of range should be 403, got %d", rr.Code)
	}
}
