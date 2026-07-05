package api

import (
	"context"
	"strconv"

	"github.com/danielgtaylor/huma/v2"
	"gorm.io/gorm"

	"github.com/tmshlvck/teleddns-server/model"
)

// zoneIDStr renders a zone id for audit lines.
func zoneIDStr(id uint) string { return strconv.FormatUint(uint64(id), 10) }

// APIZone is the JSON representation of a zone (origin + inline SOA).
type APIZone struct {
	ID     uint   `json:"id"`
	Origin string `json:"origin"`
	SOA    APISOA `json:"soa"`
}

// APISOA mirrors the zone's inline SOA fields (PRD §4.1).
type APISOA struct {
	TTL     uint32 `json:"ttl"`
	MName   string `json:"mname"`
	RName   string `json:"rname"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minimum uint32 `json:"minimum"`
}

func toAPIZone(z model.Zone) APIZone {
	return APIZone{
		ID:     z.ID,
		Origin: z.Origin,
		SOA: APISOA{
			TTL: z.SOATTL, MName: z.SOAMName, RName: z.SOARName, Serial: z.SOASerial,
			Refresh: z.SOARefresh, Retry: z.SOARetry, Expire: z.SOAExpire, Minimum: z.SOAMinimum,
		},
	}
}

// ── list ──

type ListZonesInput struct {
	AuthIn
	Page    int    `query:"page" doc:"1-based page number."`
	PerPage int    `query:"per_page" doc:"Page size (default 50, max 500)."`
	Origin  string `query:"origin" doc:"Filter: substring match on origin."`
}

type ListZonesOutput struct {
	Total int       `header:"X-Total-Count" doc:"Total zones visible to the caller."`
	Body  []APIZone `json:"-"`
}

func (d *Deps) listZones(_ context.Context, in *ListZonesInput) (*ListZonesOutput, error) {
	c, err := d.authenticate(in.Authorization)
	if err != nil {
		return nil, err
	}

	// Restrict to readable zones (≥ L2) in SQL, so pagination happens in the DB.
	scope, ok := model.ZoneReadScope(d.DB, c.user, c.tokenLevel)
	if !ok {
		return &ListZonesOutput{Total: 0, Body: []APIZone{}}, nil
	}
	originScope := func(tx *gorm.DB) *gorm.DB {
		if in.Origin != "" {
			return tx.Where("origin LIKE ?", "%"+in.Origin+"%")
		}
		return tx
	}

	var total int64
	if err := d.DB.Model(&model.Zone{}).Scopes(scope, originScope).Count(&total).Error; err != nil {
		return nil, huma.Error500InternalServerError("database error")
	}
	limit, offset := pageBounds(in.Page, in.PerPage)
	var zones []model.Zone
	if err := d.DB.Model(&model.Zone{}).Scopes(scope, originScope).
		Order("origin").Limit(limit).Offset(offset).Find(&zones).Error; err != nil {
		return nil, huma.Error500InternalServerError("database error")
	}

	body := make([]APIZone, len(zones))
	for i := range zones {
		body[i] = toAPIZone(zones[i])
	}
	return &ListZonesOutput{Total: int(total), Body: body}, nil
}

// ── get ──

type GetZoneInput struct {
	AuthIn
	ID uint `path:"id"`
}

type ZoneOutput struct {
	Body APIZone
}

func (d *Deps) getZone(_ context.Context, in *GetZoneInput) (*ZoneOutput, error) {
	c, err := d.authenticate(in.Authorization)
	if err != nil {
		return nil, err
	}
	z, err := d.loadZone(in.ID)
	if err != nil {
		return nil, err
	}
	if err := d.authz(c, z.ID, "@", model.Read, model.TargetZoneData); err != nil {
		return nil, err
	}
	return &ZoneOutput{Body: toAPIZone(z)}, nil
}

// ── create ──

type ZoneCreateBody struct {
	Origin string `json:"origin" doc:"Zone origin FQDN with a trailing dot, e.g. \"example.com.\""`
	MName  string `json:"mname,omitempty" doc:"SOA primary NS; defaults to ns1.<origin>."`
	RName  string `json:"rname,omitempty" doc:"SOA responsible party; defaults to hostmaster.<origin>."`
}

type CreateZoneInput struct {
	AuthIn
	Body ZoneCreateBody
}

func (d *Deps) createZone(_ context.Context, in *CreateZoneInput) (*ZoneOutput, error) {
	c, err := d.authenticate(in.Authorization)
	if err != nil {
		return nil, err
	}
	if err := d.requireAdmin(c); err != nil {
		return nil, err
	}
	if err := model.ValFQDN(in.Body.Origin); err != nil {
		return nil, huma.Error422UnprocessableEntity("origin: " + err.Error())
	}
	z := model.Zone{Origin: in.Body.Origin, SOAMName: in.Body.MName, SOARName: in.Body.RName}
	// BeforeCreate fills SOA defaults; AfterCreate adds the apex NS + enqueues sync.
	if err := d.DB.Create(&z).Error; err != nil {
		return nil, huma.Error422UnprocessableEntity("create zone: " + err.Error())
	}
	Audit(d.Log, "api", "create", "Zone", zoneIDStr(z.ID), c.user.Username())
	return &ZoneOutput{Body: toAPIZone(z)}, nil
}

// ── update (SOA) ──

type ZoneUpdateBody struct {
	TTL     *uint32 `json:"ttl,omitempty"`
	MName   *string `json:"mname,omitempty"`
	RName   *string `json:"rname,omitempty"`
	Refresh *uint32 `json:"refresh,omitempty"`
	Retry   *uint32 `json:"retry,omitempty"`
	Expire  *uint32 `json:"expire,omitempty"`
	Minimum *uint32 `json:"minimum,omitempty"`
}

type UpdateZoneInput struct {
	AuthIn
	ID   uint `path:"id"`
	Body ZoneUpdateBody
}

func (d *Deps) updateZone(_ context.Context, in *UpdateZoneInput) (*ZoneOutput, error) {
	c, err := d.authenticate(in.Authorization)
	if err != nil {
		return nil, err
	}
	z, err := d.loadZone(in.ID)
	if err != nil {
		return nil, err
	}
	if err := d.authz(c, z.ID, "@", model.Update, model.TargetZoneData); err != nil {
		return nil, err
	}

	b := in.Body
	if b.TTL != nil {
		z.SOATTL = *b.TTL
	}
	if b.MName != nil {
		if err := model.ValDNSName(*b.MName); err != nil {
			return nil, huma.Error422UnprocessableEntity("mname: " + err.Error())
		}
		z.SOAMName = *b.MName
	}
	if b.RName != nil {
		z.SOARName = *b.RName
	}
	if b.Refresh != nil {
		z.SOARefresh = *b.Refresh
	}
	if b.Retry != nil {
		z.SOARetry = *b.Retry
	}
	if b.Expire != nil {
		z.SOAExpire = *b.Expire
	}
	if b.Minimum != nil {
		z.SOAMinimum = *b.Minimum
	}
	// A direct SOA edit is a content change → bump the serial so secondaries
	// refresh (RR edits bump via their hooks; the zone row itself does not).
	z.SOASerial++
	if err := d.DB.Save(&z).Error; err != nil { // AfterUpdate enqueues the sync
		return nil, huma.Error422UnprocessableEntity("update zone: " + err.Error())
	}
	Audit(d.Log, "api", "update", "Zone", zoneIDStr(z.ID), c.user.Username())
	return &ZoneOutput{Body: toAPIZone(z)}, nil
}

// ── delete ──

type DeleteZoneInput struct {
	AuthIn
	ID uint `path:"id"`
}

type EmptyOutput struct{}

func (d *Deps) deleteZone(_ context.Context, in *DeleteZoneInput) (*EmptyOutput, error) {
	c, err := d.authenticate(in.Authorization)
	if err != nil {
		return nil, err
	}
	z, err := d.loadZone(in.ID)
	if err != nil {
		return nil, err
	}
	if err := d.requireAdmin(c); err != nil {
		return nil, err
	}
	// BeforeDelete cascades RRs + roles; AfterDelete enqueues the zone-remove.
	if err := d.DB.Delete(&z).Error; err != nil {
		return nil, huma.Error500InternalServerError("delete zone: " + err.Error())
	}
	Audit(d.Log, "api", "delete", "Zone", zoneIDStr(z.ID), c.user.Username())
	return &EmptyOutput{}, nil
}
