package cfapi

import (
	"net/http"
	"strconv"
	"strings"

	"gorm.io/gorm"

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
	page, per := cfPageParams(r)

	scope, ok := model.ZoneReadScope(d.DB, c.user, c.tokenLevel)
	if !ok {
		writeResultList(w, []cfZone{}, cfInfo(page, per, 0, 0))
		return
	}
	nameScope := func(tx *gorm.DB) *gorm.DB {
		if name := q2origin(r.URL.Query().Get("name")); name != "" {
			return tx.Where("lower(origin) = ? OR lower(origin) = ?", name, name+".")
		}
		return tx
	}

	var total int64
	if err := d.DB.Model(&model.Zone{}).Scopes(scope, nameScope).Count(&total).Error; err != nil {
		fail(w, http.StatusInternalServerError, 1000, "database error")
		return
	}
	var zones []model.Zone
	if err := d.DB.Model(&model.Zone{}).Scopes(scope, nameScope).
		Order("origin").Limit(per).Offset((page - 1) * per).Find(&zones).Error; err != nil {
		fail(w, http.StatusInternalServerError, 1000, "database error")
		return
	}

	out := make([]cfZone, len(zones))
	for i, z := range zones {
		out[i] = cfZone{
			ID:     strconv.FormatUint(uint64(z.ID), 10),
			Name:   strings.TrimSuffix(z.Origin, "."),
			Status: "active",
		}
	}
	writeResultList(w, out, cfInfo(page, per, int(total), len(out)))
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
