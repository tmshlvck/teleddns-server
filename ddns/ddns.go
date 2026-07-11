// Package ddns implements the dyndns2-style DDNS update endpoint (PRD §8 /
// legacy Part A): a drop-in for generic dyndns2 clients. The HTTP status code
// is the authoritative success/failure signal; the text/plain body carries the
// dyndns2 vocabulary (good / nochg / nohost / badauth / !yours / notfqdn /
// abuse / 911).
package ddns

import (
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/tmshlvck/gone/auth"
	"gorm.io/gorm"

	"github.com/tmshlvck/teleddns-server/metrics"
	"github.com/tmshlvck/teleddns-server/model"
)

// Handler serves the DDNS endpoints.
type Handler struct {
	DB   *gorm.DB
	Auth *auth.AuthGORM
	Keys *model.KeyStore
	Log  *slog.Logger
	ttl  uint32
	lim  *limiter
}

// New builds a DDNS handler from app config.
func New(db *gorm.DB, ag *auth.AuthGORM, keys *model.KeyStore, log *slog.Logger, cfg model.Config) *Handler {
	return &Handler{
		DB:   db,
		Auth: ag,
		Keys: keys,
		Log:  log,
		ttl:  cfg.DDNSRRTTL,
		lim:  newLimiter(int(cfg.DDNSRatePerRecord), int(cfg.DDNSRatePerToken)),
	}
}

// RegisterRoutes mounts the three GET endpoints. POST yields 405 (chi default).
func (h *Handler) RegisterRoutes(r chi.Router) {
	r.Get("/nic/update", h.handle)  // dyndns2 canonical
	r.Get("/ddns/update", h.handle) // legacy
	r.Get("/update", h.handle)      // legacy
}

// line is one result row in the response body.
type line struct {
	code   string
	ip     string // for good/nochg
	status int
}

func (h *Handler) handle(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	hostname := strings.TrimSpace(q.Get("hostname"))
	myip := strings.TrimSpace(q.Get("myip"))
	myipv6 := strings.TrimSpace(q.Get("myipv6"))
	src := clientIP(r)
	ua := r.UserAgent()

	c, ok, fail := h.resolveCaller(r)
	if !ok {
		metrics.AuthFailures.WithLabelValues("ddns", authReason(fail)).Inc()
		h.Log.Warn("ddns auth rejected", "reason", fail.reason, "user", fail.user,
			"src", src, "hostname", hostname, "ua", ua)
		h.write(w, http.StatusUnauthorized, []line{{code: "badauth", status: 401}}, fail.www)
		return
	}
	if hostname == "" || (myip == "" && myipv6 == "") {
		h.write(w, http.StatusBadRequest, []line{{code: "notfqdn", status: 400}}, "")
		return
	}
	if !h.lim.allow(c, hostname) {
		metrics.RateLimited.WithLabelValues("ddns").Inc()
		h.Log.Warn("ddns rate limited", "user", c.user.Username(), "hostname", hostname, "src", src, "ua", ua)
		h.write(w, http.StatusTooManyRequests, []line{{code: "abuse", status: 429}}, "")
		return
	}

	var lines []line
	if myip != "" {
		lines = append(lines, h.one(c, hostname, myip, src, ua))
	}
	if myipv6 != "" {
		lines = append(lines, h.one(c, hostname, myipv6, src, ua))
	}
	h.write(w, worstStatus(lines), lines, "")
}

// one processes a single address against the resolved (zone, label).
func (h *Handler) one(c caller, hostname, addrStr, src, ua string) line {
	addr, err := netip.ParseAddr(addrStr)
	if err != nil {
		return line{code: "notfqdn", status: 400}
	}
	ip := addr.String()

	zone, label, ok := h.resolveZoneLabel(hostname)
	if !ok {
		return line{code: "nohost", status: 404}
	}

	// Authorization (PRD §9.6): a DDNS update is read/update of an A/AAAA set
	// → needs L1; the token caps the user's effective level. Auto-create of the
	// set at the (already authorized) label is permitted on this path — an L1
	// grant is scoped to the exact (zone, label), so creating the record there
	// is within the caller's explicit designation.
	need := model.RequiredLevel(model.Update, model.TargetAddrRecord)
	eff := model.EffectiveLevel(h.DB, c.user, zone.ID, label)
	if !model.Authorized(c.tokenLevel, eff, need) {
		h.Log.Warn("ddns authz denied", "user", c.user.Username(), "src", src,
			"zone", zone.Origin, "label", label, "tokenLevel", c.tokenLevel,
			"effective", eff, "need", need, "ua", ua)
		return line{code: "!yours", ip: ip, status: 403}
	}

	var code string
	var status int
	if addr.Is4() {
		code, status = h.convergeA(zone.ID, label, ip)
	} else {
		code, status = h.convergeAAAA(zone.ID, label, ip)
	}
	if status == http.StatusOK {
		h.Log.Info("ddns", "result", code, "label", label, "zone", zone.Origin, "ip", ip,
			"user", c.user.Username(), "src", src, "ua", ua)
	}
	return line{code: code, ip: ip, status: status}
}

// resolveZoneLabel finds the longest-suffix zone for hostname and the
// remaining left-hand label ("@" for the apex). Match is case-insensitive.
func (h *Handler) resolveZoneLabel(hostname string) (model.Zone, string, bool) {
	parts := strings.Split(strings.ToLower(strings.TrimSuffix(hostname, ".")), ".")
	for i := 0; i < len(parts); i++ {
		origin := strings.Join(parts[i:], ".") + "."
		var z model.Zone
		if err := h.DB.Where("lower(origin) = ?", origin).First(&z).Error; err == nil {
			label := "@"
			if i > 0 {
				label = strings.Join(parts[:i], ".")
			}
			return z, label, true
		}
	}
	return model.Zone{}, "", false
}

// convergeA brings the A set at (zone, label) to the single value ip. An empty
// set is auto-created (the caller is already authorized for this exact label).
func (h *Handler) convergeA(zoneID uint, label, ip string) (string, int) {
	var rrs []model.RRA
	h.DB.Where("zone_id = ? AND label = ?", zoneID, label).Find(&rrs)
	if len(rrs) == 0 {
		rr := model.RRA{ZoneID: zoneID, Label: label, TTL: h.ttl, Value: ip}
		if err := h.DB.Create(&rr).Error; err != nil {
			h.Log.Error("ddns create A", "zone_id", zoneID, "label", label, "err", err)
			return "911", 500
		}
		return "good", 200
	}
	deletedExtras := false
	for i := 1; i < len(rrs); i++ {
		h.DB.Delete(&rrs[i])
		deletedExtras = true
	}
	keep := &rrs[0]
	if keep.Value == ip {
		if deletedExtras {
			return "good", 200
		}
		return "nochg", 200
	}
	keep.Value, keep.TTL = ip, h.ttl
	h.DB.Save(keep)
	return "good", 200
}

// convergeAAAA is convergeA for the AAAA set.
func (h *Handler) convergeAAAA(zoneID uint, label, ip string) (string, int) {
	var rrs []model.RRAAAA
	h.DB.Where("zone_id = ? AND label = ?", zoneID, label).Find(&rrs)
	if len(rrs) == 0 {
		rr := model.RRAAAA{ZoneID: zoneID, Label: label, TTL: h.ttl, Value: ip}
		if err := h.DB.Create(&rr).Error; err != nil {
			h.Log.Error("ddns create AAAA", "zone_id", zoneID, "label", label, "err", err)
			return "911", 500
		}
		return "good", 200
	}
	deletedExtras := false
	for i := 1; i < len(rrs); i++ {
		h.DB.Delete(&rrs[i])
		deletedExtras = true
	}
	keep := &rrs[0]
	if keep.Value == ip {
		if deletedExtras {
			return "good", 200
		}
		return "nochg", 200
	}
	keep.Value, keep.TTL = ip, h.ttl
	h.DB.Save(keep)
	return "good", 200
}

// write emits the dyndns2 response: text/plain body, one line per result.
func (h *Handler) write(w http.ResponseWriter, status int, lines []line, www string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if www != "" {
		w.Header().Set("WWW-Authenticate", www)
	}
	w.WriteHeader(status)
	var b strings.Builder
	for _, l := range lines {
		metrics.DDNSUpdates.WithLabelValues(metricResult(l.code)).Inc()
		b.WriteString(l.code)
		if l.ip != "" && (l.code == "good" || l.code == "nochg") {
			b.WriteString(" ")
			b.WriteString(l.ip)
		}
		b.WriteString("\n")
	}
	if _, err := w.Write([]byte(b.String())); err != nil {
		h.Log.Error("ddns write", "err", err)
	}
}

// worstStatus returns the most severe (highest) status among the lines.
func worstStatus(lines []line) int {
	worst := http.StatusOK
	for _, l := range lines {
		if l.status > worst {
			worst = l.status
		}
	}
	return worst
}

// metricResult maps a dyndns2 body code to the bounded label set used by
// teleddns_ddns_updates_total (PRD §11.5): "!yours"→"notyours", "911"→"error".
func metricResult(code string) string {
	switch code {
	case "!yours":
		return "notyours"
	case "911":
		return "error"
	default:
		return code // good, nochg, nohost, badauth, notfqdn, abuse
	}
}

// authReason maps an auth rejection to a bounded reason label for
// teleddns_auth_failures_total. Keeps cardinality fixed (the human detail stays
// in the log).
func authReason(f authFail) string {
	switch f.reason {
	case "invalid bearer token":
		return "bad_token"
	case "bad username or password":
		return "bad_password"
	case "2FA/SSO user must use a bearer token":
		return "needs_bearer"
	case "malformed Basic credentials":
		return "malformed"
	default:
		return "no_auth"
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
