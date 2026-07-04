package cfapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/tmshlvck/teleddns-server/api"
	"github.com/tmshlvck/teleddns-server/model"
)

// cfRecord is the Cloudflare DNS record representation.
type cfRecord struct {
	ID         string  `json:"id"`
	ZoneID     string  `json:"zone_id,omitempty"`
	ZoneName   string  `json:"zone_name,omitempty"`
	Type       string  `json:"type"`
	Name       string  `json:"name"`
	Content    string  `json:"content"`
	TTL        int     `json:"ttl"`
	Proxied    bool    `json:"proxied"`
	Priority   *uint16 `json:"priority,omitempty"`
	CreatedOn  string  `json:"created_on,omitempty"`
	ModifiedOn string  `json:"modified_on,omitempty"`
}

// cfRecordInput is the create/update request body.
type cfRecordInput struct {
	Type     string  `json:"type"`
	Name     string  `json:"name"`
	Content  string  `json:"content"`
	TTL      int     `json:"ttl"`
	Priority *uint16 `json:"priority"`
	Proxied  *bool   `json:"proxied"`
}

// toCF renders an api.APIRecord (our model view) as a Cloudflare record.
func toCF(rec api.APIRecord, z model.Zone, zoneIDStr string) cfRecord {
	now := time.Now().UTC().Format(time.RFC3339)
	out := cfRecord{
		ID:         rec.ID,
		ZoneID:     zoneIDStr,
		ZoneName:   strings.TrimSuffix(z.Origin, "."),
		Type:       rec.Type,
		Name:       labelToFQDN(rec.Name, z.Origin),
		Content:    rec.Value,
		TTL:        int(rec.TTL),
		Proxied:    false, // authoritative DNS — never proxied
		CreatedOn:  now,
		ModifiedOn: now,
	}
	if rec.Type == "MX" {
		out.Priority = rec.Priority
	}
	return out
}

// fromCF maps a Cloudflare create/update body to (type, api.APIRecord). It
// resolves the FQDN to a label within z and moves `content`/`priority` into the
// model's value/priority. Per-type value validation is left to api.RR*.
func (d *Deps) fromCF(in cfRecordInput, z model.Zone) (string, api.APIRecord, *cfError) {
	typ := strings.ToUpper(strings.TrimSpace(in.Type))
	if !isSupported(typ) {
		return "", api.APIRecord{}, &cfError{Code: 9004, Message: "record type " + in.Type + " is not supported by this endpoint"}
	}
	label, ok := fqdnToLabel(in.Name, z.Origin)
	if !ok {
		return "", api.APIRecord{}, &cfError{Code: 1004, Message: "DNS name " + in.Name + " is not within zone " + z.Origin}
	}
	ttl := uint32(in.TTL)
	if in.TTL <= 1 { // Cloudflare "automatic"
		ttl = d.DefaultTTL
	}
	rec := api.APIRecord{Type: typ, Name: label, TTL: ttl, Value: in.Content}
	if typ == "MX" {
		if in.Priority == nil {
			return "", api.APIRecord{}, &cfError{Code: 9004, Message: "priority is required for MX records"}
		}
		rec.Priority = in.Priority
	}
	return typ, rec, nil
}

// gatherRecords returns every supported record in the zone as CF records.
func (d *Deps) gatherRecords(z model.Zone, zoneIDStr string) ([]cfRecord, error) {
	var out []cfRecord
	for _, typ := range supportedTypes {
		recs, err := api.RRList(d.DB, typ, z.ID)
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			out = append(out, toCF(r, z, zoneIDStr))
		}
	}
	return out, nil
}

// ── GET /zones/{id}/dns_records ──

func (d *Deps) listRecords(w http.ResponseWriter, r *http.Request) {
	c, ok := d.authenticate(r)
	if !ok {
		fail(w, http.StatusUnauthorized, 9109, "Invalid access token")
		return
	}
	z, ok := d.loadZone(w, r)
	if !ok {
		return
	}
	if !d.authz(c, z.ID, "@", model.Read, model.TargetZoneData) {
		fail(w, http.StatusForbidden, 9109, "insufficient permissions for this zone")
		return
	}

	all, err := d.gatherRecords(z, chi.URLParam(r, "zoneID"))
	if err != nil {
		fail(w, http.StatusInternalServerError, 1000, "database error")
		return
	}

	// Cloudflare list filters used by the clients: type, name (exact FQDN),
	// content (exact).
	q := r.URL.Query()
	fType := strings.ToUpper(q.Get("type"))
	fName := strings.TrimSuffix(strings.ToLower(q.Get("name")), ".")
	fContent := q.Get("content")
	filtered := all[:0:0]
	for _, rec := range all {
		if fType != "" && rec.Type != fType {
			continue
		}
		if fName != "" && strings.ToLower(rec.Name) != fName {
			continue
		}
		if fContent != "" && rec.Content != fContent {
			continue
		}
		filtered = append(filtered, rec)
	}

	lo, hi, info := paginate(r, len(filtered))
	page := filtered[lo:hi]
	if page == nil {
		page = []cfRecord{}
	}
	writeResultList(w, page, info)
}

// ── POST /zones/{id}/dns_records ──

func (d *Deps) createRecord(w http.ResponseWriter, r *http.Request) {
	c, ok := d.authenticate(r)
	if !ok {
		fail(w, http.StatusUnauthorized, 9109, "Invalid access token")
		return
	}
	z, ok := d.loadZone(w, r)
	if !ok {
		return
	}
	var in cfRecordInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, 6003, "invalid JSON in request body")
		return
	}
	typ, rec, cerr := d.fromCF(in, z)
	if cerr != nil {
		fail(w, http.StatusBadRequest, cerr.Code, cerr.Message)
		return
	}
	if !d.authz(c, z.ID, rec.Name, model.Create, targetOf(typ)) {
		fail(w, http.StatusForbidden, 9109, "insufficient permissions for this record")
		return
	}
	created, err := api.RRCreate(d.DB, typ, z.ID, rec)
	if err != nil {
		writeRRErr(w, err)
		return
	}
	writeResult(w, toCF(created, z, chi.URLParam(r, "zoneID")))
}

// ── GET /zones/{id}/dns_records/{rid} ──

func (d *Deps) getRecord(w http.ResponseWriter, r *http.Request) {
	c, ok := d.authenticate(r)
	if !ok {
		fail(w, http.StatusUnauthorized, 9109, "Invalid access token")
		return
	}
	z, ok := d.loadZone(w, r)
	if !ok {
		return
	}
	typ, pk, rec, found := d.resolve(w, r, z)
	if !found {
		return
	}
	if !d.authz(c, z.ID, rec.Name, model.Read, targetOf(typ)) {
		fail(w, http.StatusForbidden, 9109, "insufficient permissions for this record")
		return
	}
	_ = pk
	writeResult(w, toCF(rec, z, chi.URLParam(r, "zoneID")))
}

// ── PUT / PATCH /zones/{id}/dns_records/{rid} ──

func (d *Deps) updateRecord(w http.ResponseWriter, r *http.Request) {
	c, ok := d.authenticate(r)
	if !ok {
		fail(w, http.StatusUnauthorized, 9109, "Invalid access token")
		return
	}
	z, ok := d.loadZone(w, r)
	if !ok {
		return
	}
	typ, pk, existing, found := d.resolve(w, r, z)
	if !found {
		return
	}
	var in cfRecordInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, 6003, "invalid JSON in request body")
		return
	}
	// The id pins the type; PATCH omits unchanged fields, so default from the
	// existing record.
	in.Type = typ
	if in.Name == "" {
		in.Name = labelToFQDN(existing.Name, z.Origin)
	}
	if in.Content == "" {
		in.Content = existing.Value
	}
	if in.TTL == 0 {
		in.TTL = int(existing.TTL)
	}
	if typ == "MX" && in.Priority == nil {
		in.Priority = existing.Priority
	}
	_, rec, cerr := d.fromCF(in, z)
	if cerr != nil {
		fail(w, http.StatusBadRequest, cerr.Code, cerr.Message)
		return
	}
	if !d.authz(c, z.ID, existing.Name, model.Update, targetOf(typ)) ||
		!d.authz(c, z.ID, rec.Name, model.Update, targetOf(typ)) {
		fail(w, http.StatusForbidden, 9109, "insufficient permissions for this record")
		return
	}
	updated, err := api.RRUpdate(d.DB, typ, z.ID, pk, rec)
	if err != nil {
		writeRRErr(w, err)
		return
	}
	writeResult(w, toCF(updated, z, chi.URLParam(r, "zoneID")))
}

// ── DELETE /zones/{id}/dns_records/{rid} ──

func (d *Deps) deleteRecord(w http.ResponseWriter, r *http.Request) {
	c, ok := d.authenticate(r)
	if !ok {
		fail(w, http.StatusUnauthorized, 9109, "Invalid access token")
		return
	}
	z, ok := d.loadZone(w, r)
	if !ok {
		return
	}
	typ, pk, existing, found := d.resolve(w, r, z)
	if !found {
		return
	}
	if !d.authz(c, z.ID, existing.Name, model.Delete, targetOf(typ)) {
		fail(w, http.StatusForbidden, 9109, "insufficient permissions for this record")
		return
	}
	if err := api.RRDelete(d.DB, typ, z.ID, pk); err != nil {
		writeRRErr(w, err)
		return
	}
	// Cloudflare's delete returns just the id.
	writeResult(w, map[string]string{"id": chi.URLParam(r, "recordID")})
}

// resolve decodes the {recordID} path param and loads the record within z.
// Writes the 404/400 envelope and returns found=false on any miss.
func (d *Deps) resolve(w http.ResponseWriter, r *http.Request, z model.Zone) (typ string, pk uint, rec api.APIRecord, found bool) {
	id := chi.URLParam(r, "recordID")
	t, k, ok := api.RRDecodeID(id)
	if !ok || !isSupported(strings.ToUpper(t)) {
		fail(w, http.StatusNotFound, 81044, "record does not exist")
		return "", 0, api.APIRecord{}, false
	}
	typ = strings.ToUpper(t)
	rec, ok, err := api.RRGet(d.DB, typ, z.ID, k)
	if err != nil {
		fail(w, http.StatusInternalServerError, 1000, "database error")
		return "", 0, api.APIRecord{}, false
	}
	if !ok {
		fail(w, http.StatusNotFound, 81044, "record does not exist")
		return "", 0, api.APIRecord{}, false
	}
	return typ, k, rec, true
}

func targetOf(typ string) model.TargetKind {
	t, _ := api.RRTarget(typ)
	return t
}

// writeRRErr maps a registry/model write error to a Cloudflare error envelope.
func writeRRErr(w http.ResponseWriter, err error) {
	switch {
	case api.IsRRNotFound(err):
		fail(w, http.StatusNotFound, 81044, "record does not exist")
	case errors.Is(err, model.ErrLastNSRecord):
		fail(w, http.StatusBadRequest, 1004, err.Error())
	default:
		fail(w, http.StatusBadRequest, 9004, err.Error())
	}
}
