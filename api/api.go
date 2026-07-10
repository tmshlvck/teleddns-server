// Package api implements the native management JSON API (docs/DESIGN.md §6):
// a Huma-served, Bearer-only surface for zones and resource records, for
// clients/tooling (external-dns, cert-manager, libdns, …). Authorization reuses
// the model's RequiredLevel/EffectiveLevel/Authorized helpers; every mutation
// funnels through the same GORM hooks as the admin + DDNS paths (SOA bump,
// last-NS guard, SyncTask enqueue). It covers zones + RR only —
// users/groups/roles are managed via the operator UI + the IdP (see docs/DESIGN.md §4).
package api

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/tmshlvck/gone/auth"
	"gorm.io/gorm"

	"github.com/tmshlvck/teleddns-server/metrics"
	"github.com/tmshlvck/teleddns-server/model"
)

// Deps are the dependencies the API operations need.
type Deps struct {
	DB         *gorm.DB
	Keys       *model.KeyStore
	Log        *slog.Logger
	DefaultTTL uint32
}

// bearerSec marks an operation as requiring the "bearer" security scheme.
var bearerSec = []map[string][]string{{"bearer": {}}}

// Register mounts every management operation on the Huma API.
func Register(api huma.API, d *Deps) {
	huma.Register(api, op("list-zones", http.MethodGet, "/api/zones", "List zones"), d.listZones)
	huma.Register(api, op("get-zone", http.MethodGet, "/api/zones/{id}", "Get a zone"), d.getZone)
	huma.Register(api, opStatus("create-zone", http.MethodPost, "/api/zones", "Create a zone", 201), d.createZone)
	huma.Register(api, op("update-zone", http.MethodPut, "/api/zones/{id}", "Update a zone's SOA"), d.updateZone)
	huma.Register(api, opStatus("delete-zone", http.MethodDelete, "/api/zones/{id}", "Delete a zone", 204), d.deleteZone)

	huma.Register(api, op("list-records", http.MethodGet, "/api/zones/{zone_id}/rr", "List records in a zone"), d.listRecords)
	huma.Register(api, op("get-record", http.MethodGet, "/api/zones/{zone_id}/rr/{rrid}", "Get a record"), d.getRecord)
	huma.Register(api, opStatus("create-record", http.MethodPost, "/api/zones/{zone_id}/rr", "Create a record", 201), d.createRecord)
	huma.Register(api, op("update-record", http.MethodPut, "/api/zones/{zone_id}/rr/{rrid}", "Update a record"), d.updateRecord)
	huma.Register(api, opStatus("delete-record", http.MethodDelete, "/api/zones/{zone_id}/rr/{rrid}", "Delete a record", 204), d.deleteRecord)
}

func op(id, method, path, summary string) huma.Operation {
	return huma.Operation{OperationID: id, Method: method, Path: path,
		Summary: summary, Tags: []string{tagFor(path)}, Security: bearerSec}
}

func opStatus(id, method, path, summary string, status int) huma.Operation {
	o := op(id, method, path, summary)
	o.DefaultStatus = status
	return o
}

func tagFor(path string) string {
	if strings.Contains(path, "/rr") {
		return "records"
	}
	return "zones"
}

// ── auth ──

type caller struct {
	user       auth.User
	userID     uint
	tokenLevel int
}

// AuthIn carries the Bearer credential. It is embedded in every operation
// input; the type must be exported so Huma's reflection can populate the
// promoted Authorization field.
type AuthIn struct {
	Authorization string `header:"Authorization" doc:"Bearer <api-key>"`
}

// authenticate resolves the Bearer credential. Basic is rejected — the API is
// Bearer-only (PRD §11.1).
func (d *Deps) authenticate(header string) (caller, error) {
	raw, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		metrics.AuthFailures.WithLabelValues("api", "no_bearer").Inc()
		return caller{}, huma.Error401Unauthorized("Bearer token required")
	}
	u, k, err := d.Keys.Validate(strings.TrimSpace(raw))
	if err != nil {
		metrics.AuthFailures.WithLabelValues("api", "bad_token").Inc()
		return caller{}, huma.Error401Unauthorized("invalid bearer token")
	}
	return caller{user: u, userID: userIDOf(u), tokenLevel: k.Level}, nil
}

func userIDOf(u auth.User) uint {
	if a, ok := u.(auth.UserGORMAdapter); ok && a.U != nil {
		return a.U.ID
	}
	return 0
}

// authz checks min(token, effective) ≥ required for the action on (zone,label).
func (d *Deps) authz(c caller, zoneID uint, label string, a model.Action, k model.TargetKind) error {
	need := model.RequiredLevel(a, k)
	eff := model.EffectiveLevel(d.DB, c.user, zoneID, label)
	if !model.Authorized(c.tokenLevel, eff, need) {
		return huma.Error403Forbidden("insufficient permission for this resource")
	}
	return nil
}

// requireAdmin gates zone create/delete on effective L3 (admin group), capped by
// the token level. A new origin has no GroupZoneRole yet, so zone lifecycle is
// L3 in practice (PRD §11.2).
func (d *Deps) requireAdmin(c caller) error {
	if model.Authorized(c.tokenLevel, model.UserMaxLevel(d.DB, c.user), model.L3) {
		return nil
	}
	return huma.Error403Forbidden("requires L3 (admin) access")
}

// ── shared helpers ──

func (d *Deps) loadZone(id uint) (model.Zone, error) {
	var z model.Zone
	res := d.DB.Where("id = ?", id).Limit(1).Find(&z)
	if res.Error != nil {
		return z, huma.Error500InternalServerError("database error")
	}
	if res.RowsAffected == 0 {
		return z, huma.Error404NotFound("zone not found")
	}
	return z, nil
}

// pageBounds clamps pagination params (PRD §11.1: default 50, max 500) into a
// SQL LIMIT/OFFSET.
func pageBounds(pageNum, perPage int) (limit, offset int) {
	if perPage <= 0 {
		perPage = 50
	}
	if perPage > 500 {
		perPage = 500
	}
	if pageNum < 1 {
		pageNum = 1
	}
	return perPage, (pageNum - 1) * perPage
}

// mapWriteErr turns model/validation errors into HTTP errors.
func mapWriteErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errRRNotFound):
		return huma.Error404NotFound("record not found")
	case errors.Is(err, model.ErrLastNSRecord):
		return huma.Error409Conflict(err.Error())
	default:
		return huma.Error422UnprocessableEntity(err.Error())
	}
}
