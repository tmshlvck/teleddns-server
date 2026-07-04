// Package cfapi is a Cloudflare-DNS-API-compatible facade over the same zone/RR
// models, scoped to the tools that only speak Cloudflare's API: cert-manager's
// DNS01 solver and external-dns' cloudflare provider. It mirrors Cloudflare's
// /client/v4 surface (envelope, record shape, /user/tokens/verify) closely
// enough for those clients, translating Cloudflare's FQDN `name` + `content`
// into our (zone,label,value) model and reusing the api package's per-type
// validation + CRUD. Bearer-only (or X-Auth-Key) auth via the shared KeyStore.
package cfapi

import (
	"encoding/json"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/tmshlvck/gone/auth"
	"gorm.io/gorm"

	"github.com/tmshlvck/teleddns-server/metrics"
	"github.com/tmshlvck/teleddns-server/model"
)

// Deps are the facade's dependencies.
type Deps struct {
	DB         *gorm.DB
	Keys       *model.KeyStore
	Log        *slog.Logger
	DefaultTTL uint32
}

// supportedTypes are the RR types the facade maps (covers cert-manager: TXT, and
// external-dns: A/AAAA/CNAME/TXT/NS/MX). Other types in a zone are simply not
// surfaced through this Cloudflare view.
var supportedTypes = []string{"A", "AAAA", "CNAME", "TXT", "NS", "MX"}

func isSupported(typ string) bool {
	for _, t := range supportedTypes {
		if t == typ {
			return true
		}
	}
	return false
}

// RegisterRoutes mounts the Cloudflare-compatible endpoints under /client/v4.
func (d *Deps) RegisterRoutes(r chi.Router) {
	r.Route("/client/v4", func(r chi.Router) {
		r.Get("/user/tokens/verify", d.verifyToken)
		r.Get("/zones", d.listZones)
		r.Route("/zones/{zoneID}/dns_records", func(r chi.Router) {
			r.Get("/", d.listRecords)
			r.Post("/", d.createRecord)
			r.Get("/{recordID}", d.getRecord)
			r.Put("/{recordID}", d.updateRecord)
			r.Patch("/{recordID}", d.updateRecord)
			r.Delete("/{recordID}", d.deleteRecord)
		})
	})
}

// ── Cloudflare envelope ──

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfEnvelope struct {
	Success    bool          `json:"success"`
	Errors     []cfError     `json:"errors"`
	Messages   []cfError     `json:"messages"`
	Result     any           `json:"result"`
	ResultInfo *cfResultInfo `json:"result_info,omitempty"`
}

type cfResultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
	TotalPages int `json:"total_pages"`
}

func writeJSON(w http.ResponseWriter, status int, env cfEnvelope) {
	if env.Errors == nil {
		env.Errors = []cfError{}
	}
	if env.Messages == nil {
		env.Messages = []cfError{}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(env)
}

func writeResult(w http.ResponseWriter, result any) {
	writeJSON(w, http.StatusOK, cfEnvelope{Success: true, Result: result})
}

func writeResultList(w http.ResponseWriter, result any, info cfResultInfo) {
	writeJSON(w, http.StatusOK, cfEnvelope{Success: true, Result: result, ResultInfo: &info})
}

// fail writes a Cloudflare-style error envelope with the given HTTP status and
// CF error code (see https://developers.cloudflare.com/api → error codes).
func fail(w http.ResponseWriter, status, code int, msg string) {
	writeJSON(w, status, cfEnvelope{Success: false, Errors: []cfError{{Code: code, Message: msg}}, Result: nil})
}

// ── auth ──

type caller struct {
	user       auth.User
	tokenLevel int
}

// authenticate accepts a Cloudflare API token via `Authorization: Bearer <key>`
// or the legacy `X-Auth-Key` header (email is ignored — our keys are the
// principal). Both resolve through the shared KeyStore.
func (d *Deps) authenticate(r *http.Request) (caller, bool) {
	var raw string
	if b, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		raw = strings.TrimSpace(b)
	} else if k := r.Header.Get("X-Auth-Key"); k != "" {
		raw = strings.TrimSpace(k)
	}
	if raw == "" {
		metrics.AuthFailures.WithLabelValues("cfapi", "no_token").Inc()
		return caller{}, false
	}
	u, k, err := d.Keys.Validate(raw)
	if err != nil {
		metrics.AuthFailures.WithLabelValues("cfapi", "bad_token").Inc()
		return caller{}, false
	}
	return caller{user: u, tokenLevel: k.Level}, true
}

// authz applies min(token, effective) ≥ required for (zone,label).
func (d *Deps) authz(c caller, zoneID uint, label string, a model.Action, k model.TargetKind) bool {
	need := model.RequiredLevel(a, k)
	eff := model.EffectiveLevel(d.DB, c.user, zoneID, label)
	return model.Authorized(c.tokenLevel, eff, need)
}

// ── shared helpers ──

// loadZone resolves the {zoneID} path segment (our numeric id, stringified) to
// a Zone. Returns false (and writes the error) if missing.
func (d *Deps) loadZone(w http.ResponseWriter, r *http.Request) (model.Zone, bool) {
	id, err := strconv.ParseUint(chi.URLParam(r, "zoneID"), 10, 64)
	if err != nil {
		fail(w, http.StatusNotFound, 7003, "could not route to zone: invalid zone identifier")
		return model.Zone{}, false
	}
	var z model.Zone
	res := d.DB.Where("id = ?", uint(id)).Limit(1).Find(&z)
	if res.Error != nil {
		fail(w, http.StatusInternalServerError, 1000, "database error")
		return model.Zone{}, false
	}
	if res.RowsAffected == 0 {
		fail(w, http.StatusNotFound, 1049, "zone not found")
		return model.Zone{}, false
	}
	return z, true
}

// labelToFQDN renders a stored label as a Cloudflare-style FQDN (no trailing
// dot); "@" becomes the bare origin.
func labelToFQDN(label, origin string) string {
	o := strings.TrimSuffix(origin, ".")
	if label == "@" || label == "" {
		return o
	}
	return label + "." + o
}

// fqdnToLabel is the inverse: an in-zone FQDN → the stored label ("@" for the
// apex). Returns false if name is not within origin.
func fqdnToLabel(name, origin string) (string, bool) {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	o := strings.TrimSuffix(strings.ToLower(origin), ".")
	if n == o {
		return "@", true
	}
	if strings.HasSuffix(n, "."+o) {
		return n[:len(n)-len(o)-1], true
	}
	return "", false
}

// paginate parses ?page/?per_page (CF defaults: page 1, per_page 100) and
// returns the [lo:hi) window over n plus the result_info to report.
func paginate(r *http.Request, n int) (lo, hi int, info cfResultInfo) {
	page := atoiDefault(r.URL.Query().Get("page"), 1)
	per := atoiDefault(r.URL.Query().Get("per_page"), 100)
	if per < 1 {
		per = 100
	}
	if page < 1 {
		page = 1
	}
	lo = (page - 1) * per
	if lo > n {
		lo = n
	}
	hi = lo + per
	if hi > n {
		hi = n
	}
	total := int(math.Ceil(float64(n) / float64(per)))
	return lo, hi, cfResultInfo{Page: page, PerPage: per, Count: hi - lo, TotalCount: n, TotalPages: total}
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	if v, err := strconv.Atoi(s); err == nil {
		return v
	}
	return def
}
