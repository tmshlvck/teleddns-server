package cfapi

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/tmshlvck/teleddns-server/model"
)

// cfZone is the Cloudflare zone representation (only the fields the clients
// read: id, name, status).
type cfZone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// ── GET /client/v4/zones[?name=] ──
//
// external-dns enumerates zones here (paginated) to build its zone map;
// cert-manager walks the domain with ?name=<candidate> to find the hosting
// zone. We return only zones the caller can read (≥ L2), so a scoped token maps
// to its own zones.
func (d *Deps) listZones(w http.ResponseWriter, r *http.Request) {
	c, ok := d.authenticate(r)
	if !ok {
		fail(w, http.StatusUnauthorized, 9109, "Invalid access token")
		return
	}

	q := d.DB.Model(&model.Zone{}).Order("origin")
	if name := q2origin(r.URL.Query().Get("name")); name != "" {
		// Cloudflare's `name` filter is exact on the zone apex here.
		q = q.Where("lower(origin) = ? OR lower(origin) = ?", name, name+".")
	}
	var zones []model.Zone
	if err := q.Find(&zones).Error; err != nil {
		fail(w, http.StatusInternalServerError, 1000, "database error")
		return
	}

	visible := make([]cfZone, 0, len(zones))
	for _, z := range zones {
		if d.authz(c, z.ID, "@", model.Read, model.TargetZoneData) {
			visible = append(visible, cfZone{
				ID:     strconv.FormatUint(uint64(z.ID), 10),
				Name:   strings.TrimSuffix(z.Origin, "."),
				Status: "active",
			})
		}
	}

	lo, hi, info := paginate(r, len(visible))
	page := visible[lo:hi]
	if page == nil {
		page = []cfZone{}
	}
	writeResultList(w, page, info)
}

// q2origin normalizes a ?name= query value for comparison (lowercased, no
// trailing dot).
func q2origin(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// ── GET /client/v4/user/tokens/verify ──
//
// cert-manager calls this to validate an API token before use and surfaces a
// clear error if it fails, so the facade must answer it.
func (d *Deps) verifyToken(w http.ResponseWriter, r *http.Request) {
	c, ok := d.authenticate(r)
	if !ok {
		fail(w, http.StatusUnauthorized, 1000, "Invalid API Token")
		return
	}
	_ = c
	writeJSON(w, http.StatusOK, cfEnvelope{
		Success:  true,
		Result:   map[string]string{"id": "teleddns", "status": "active"},
		Messages: []cfError{{Code: 10000, Message: "This API Token is valid and active"}},
	})
}
