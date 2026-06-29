package api

import (
	"context"

	"github.com/danielgtaylor/huma/v2"

	"github.com/tmshlvck/teleddns-server/model"
)

// listOrder fixes the type iteration order for unified listing (apex authority
// first, then by type — same spirit as the zone-file render).
var listOrder = []string{"NS", "A", "AAAA", "CNAME", "MX", "TXT", "PTR", "SRV",
	"CAA", "SSHFP", "TLSA", "DNSKEY", "DS", "NAPTR"}

// ── list ──

type ListRecordsInput struct {
	AuthIn
	ZoneID  uint   `path:"zone_id"`
	Page    int    `query:"page"`
	PerPage int    `query:"per_page"`
	Type    string `query:"type" doc:"Filter: only this RR type."`
	Name    string `query:"name" doc:"Filter: exact label match."`
}

type ListRecordsOutput struct {
	Total int         `header:"X-Total-Count"`
	Body  []APIRecord `json:"-"`
}

func (d *Deps) listRecords(_ context.Context, in *ListRecordsInput) (*ListRecordsOutput, error) {
	c, err := d.authenticate(in.Authorization)
	if err != nil {
		return nil, err
	}
	z, err := d.loadZone(in.ZoneID)
	if err != nil {
		return nil, err
	}
	// Listing a whole zone is a zone-wide read → L2.
	if err := d.authz(c, z.ID, "@", model.Read, model.TargetZoneData); err != nil {
		return nil, err
	}

	types := listOrder
	if in.Type != "" {
		if _, ok := kindByType(in.Type); !ok {
			return nil, huma.Error422UnprocessableEntity("unknown record type: " + in.Type)
		}
		types = []string{in.Type}
	}

	var all []APIRecord
	for _, t := range types {
		k, _ := kindByType(t)
		recs, err := k.list(d.DB, z.ID)
		if err != nil {
			return nil, huma.Error500InternalServerError("database error")
		}
		for _, r := range recs {
			if in.Name == "" || r.Name == in.Name {
				all = append(all, r)
			}
		}
	}

	lo, hi := page(in.Page, in.PerPage, len(all))
	return &ListRecordsOutput{Total: len(all), Body: all[lo:hi]}, nil
}

// ── get ──

type GetRecordInput struct {
	AuthIn
	ZoneID uint   `path:"zone_id"`
	RRID   string `path:"rrid" doc:"Opaque record id, e.g. \"a-12\"."`
}

type RecordOutput struct {
	Body APIRecord
}

func (d *Deps) getRecord(_ context.Context, in *GetRecordInput) (*RecordOutput, error) {
	c, err := d.authenticate(in.Authorization)
	if err != nil {
		return nil, err
	}
	z, err := d.loadZone(in.ZoneID)
	if err != nil {
		return nil, err
	}
	k, pk, ok := d.resolveRR(in.RRID)
	if !ok {
		return nil, huma.Error404NotFound("record not found")
	}
	r, found, err := k.get(d.DB, z.ID, pk)
	if err != nil {
		return nil, huma.Error500InternalServerError("database error")
	}
	if !found {
		return nil, huma.Error404NotFound("record not found")
	}
	if err := d.authz(c, z.ID, r.Name, model.Read, k.target); err != nil {
		return nil, err
	}
	return &RecordOutput{Body: r}, nil
}

// ── create ──

type CreateRecordInput struct {
	AuthIn
	ZoneID uint `path:"zone_id"`
	Body   APIRecord
}

func (d *Deps) createRecord(_ context.Context, in *CreateRecordInput) (*RecordOutput, error) {
	c, err := d.authenticate(in.Authorization)
	if err != nil {
		return nil, err
	}
	z, err := d.loadZone(in.ZoneID)
	if err != nil {
		return nil, err
	}
	k, ok := kindByType(in.Body.Type)
	if !ok {
		return nil, huma.Error422UnprocessableEntity("unknown record type: " + in.Body.Type)
	}
	if err := d.authz(c, z.ID, in.Body.Name, model.Create, k.target); err != nil {
		return nil, err
	}
	body := d.withDefaultTTL(in.Body)
	r, err := k.create(d.DB, z.ID, body)
	if err != nil {
		return nil, mapWriteErr(err)
	}
	return &RecordOutput{Body: r}, nil
}

// ── update ──

type UpdateRecordInput struct {
	AuthIn
	ZoneID uint   `path:"zone_id"`
	RRID   string `path:"rrid"`
	Body   APIRecord
}

func (d *Deps) updateRecord(_ context.Context, in *UpdateRecordInput) (*RecordOutput, error) {
	c, err := d.authenticate(in.Authorization)
	if err != nil {
		return nil, err
	}
	z, err := d.loadZone(in.ZoneID)
	if err != nil {
		return nil, err
	}
	k, pk, ok := d.resolveRR(in.RRID)
	if !ok {
		return nil, huma.Error404NotFound("record not found")
	}
	existing, found, err := k.get(d.DB, z.ID, pk)
	if err != nil {
		return nil, huma.Error500InternalServerError("database error")
	}
	if !found {
		return nil, huma.Error404NotFound("record not found")
	}
	// The id pins the type; the body cannot change it.
	body := d.withDefaultTTL(in.Body)
	body.Type = k.name
	// Need write access to both the current label and the (possibly new) target.
	if err := d.authz(c, z.ID, existing.Name, model.Update, k.target); err != nil {
		return nil, err
	}
	if body.Name != existing.Name {
		if err := d.authz(c, z.ID, body.Name, model.Update, k.target); err != nil {
			return nil, err
		}
	}
	r, err := k.update(d.DB, z.ID, pk, body)
	if err != nil {
		return nil, mapWriteErr(err)
	}
	return &RecordOutput{Body: r}, nil
}

// ── delete ──

type DeleteRecordInput struct {
	AuthIn
	ZoneID uint   `path:"zone_id"`
	RRID   string `path:"rrid"`
}

func (d *Deps) deleteRecord(_ context.Context, in *DeleteRecordInput) (*EmptyOutput, error) {
	c, err := d.authenticate(in.Authorization)
	if err != nil {
		return nil, err
	}
	z, err := d.loadZone(in.ZoneID)
	if err != nil {
		return nil, err
	}
	k, pk, ok := d.resolveRR(in.RRID)
	if !ok {
		return nil, huma.Error404NotFound("record not found")
	}
	existing, found, err := k.get(d.DB, z.ID, pk)
	if err != nil {
		return nil, huma.Error500InternalServerError("database error")
	}
	if !found {
		return nil, huma.Error404NotFound("record not found")
	}
	if err := d.authz(c, z.ID, existing.Name, model.Delete, k.target); err != nil {
		return nil, err
	}
	if err := k.del(d.DB, z.ID, pk); err != nil {
		return nil, mapWriteErr(err)
	}
	return &EmptyOutput{}, nil
}

// resolveRR decodes an opaque record id into its kind + primary key.
func (d *Deps) resolveRR(id string) (rrKind, uint, bool) {
	typ, pk, ok := ridDecode(id)
	if !ok {
		return rrKind{}, 0, false
	}
	k, ok := kindByType(typ)
	if !ok {
		return rrKind{}, 0, false
	}
	return k, pk, true
}

// withDefaultTTL fills a zero TTL with the server default (PRD §5).
func (d *Deps) withDefaultTTL(in APIRecord) APIRecord {
	if in.TTL == 0 {
		in.TTL = d.DefaultTTL
	}
	return in
}
