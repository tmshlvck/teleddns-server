package web

import (
	"net"
	"net/http"
)

// IPAllowlist rejects requests whose client IP is outside every CIDR in
// allowed. An empty allowed list permits everything (PRD: "all if empty").
//
// The client IP is taken from r.RemoteAddr; mount chi's middleware.RealIP
// (gated on TrustProxy) ahead of this when behind a reverse proxy so the
// proxy's X-Forwarded-For / X-Real-IP is honored.
func IPAllowlist(allowed []string) func(http.Handler) http.Handler {
	nets := make([]*net.IPNet, 0, len(allowed))
	for _, c := range allowed {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(nets) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}
			ip := net.ParseIP(host)
			for _, n := range nets {
				if ip != nil && n.Contains(ip) {
					next.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, "forbidden", http.StatusForbidden)
		})
	}
}
