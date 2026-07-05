package api

import (
	"errors"

	"gorm.io/gorm"

	"github.com/tmshlvck/teleddns-server/model"
)

// This file exposes the record registry + APIRecord marshalling for the
// Cloudflare-compat facade (cfapi), so that package reuses this one's per-type
// validation and CRUD (mapping to/from the 14 GORM tables) instead of
// re-deriving it. cfapi handles only the CF envelope + field translation.

// ErrUnknownType is returned by the RR* helpers for an unregistered type name.
var ErrUnknownType = errors.New("unknown record type")

// IsRRNotFound reports whether err is the registry's not-found sentinel.
func IsRRNotFound(err error) bool { return errors.Is(err, errRRNotFound) }

// RRDecodeID splits an opaque record id ("a-12") into its type + primary key.
func RRDecodeID(id string) (typ string, pk uint, ok bool) { return ridDecode(id) }

// RRTarget returns a type's authorization target kind (A/AAAA are address sets).
func RRTarget(typ string) (model.TargetKind, bool) {
	k, ok := kindByType(typ)
	if !ok {
		return 0, false
	}
	return k.target, true
}

// RRList returns all records of one type in a zone.
func RRList(db *gorm.DB, typ string, zoneID uint) ([]APIRecord, error) {
	k, ok := kindByType(typ)
	if !ok {
		return nil, ErrUnknownType
	}
	return k.list(db, zoneID)
}

// RRPageAcross paginates a global window across the given types (in order),
// applying optional exact label/value filters, and returns the page rows plus
// the total across all the types. Only the page's rows are fetched from the DB —
// the rest is len(types) cheap COUNT(*) queries. value must be empty unless
// every listed type has a value column (true for all cfapi types).
func RRPageAcross(db *gorm.DB, types []string, zoneID uint, label, value string, limit, offset int) ([]APIRecord, int, error) {
	counts := make([]int, len(types))
	total := 0
	for i, t := range types {
		k, ok := kindByType(t)
		if !ok {
			return nil, 0, ErrUnknownType
		}
		n, err := k.count(db, zoneID, label, value)
		if err != nil {
			return nil, 0, err
		}
		counts[i] = int(n)
		total += int(n)
	}
	var out []APIRecord
	start := 0
	for i, t := range types {
		typeStart, typeEnd := start, start+counts[i]
		start = typeEnd
		lo, hi := max(offset, typeStart), min(offset+limit, typeEnd)
		if lo >= hi {
			continue
		}
		k, _ := kindByType(t)
		recs, err := k.page(db, zoneID, label, value, hi-lo, lo-typeStart)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, recs...)
	}
	return out, total, nil
}

// RRGet returns one record by (type, zone, pk).
func RRGet(db *gorm.DB, typ string, zoneID, pk uint) (APIRecord, bool, error) {
	k, ok := kindByType(typ)
	if !ok {
		return APIRecord{}, false, ErrUnknownType
	}
	return k.get(db, zoneID, pk)
}

// RRCreate validates + inserts a record (firing the model hooks).
func RRCreate(db *gorm.DB, typ string, zoneID uint, in APIRecord) (APIRecord, error) {
	k, ok := kindByType(typ)
	if !ok {
		return APIRecord{}, ErrUnknownType
	}
	return k.create(db, zoneID, in)
}

// RRUpdate validates + saves a record by pk (firing the model hooks).
func RRUpdate(db *gorm.DB, typ string, zoneID, pk uint, in APIRecord) (APIRecord, error) {
	k, ok := kindByType(typ)
	if !ok {
		return APIRecord{}, ErrUnknownType
	}
	return k.update(db, zoneID, pk, in)
}

// RRDelete removes a record by pk (firing the model hooks; may return
// model.ErrLastNSRecord).
func RRDelete(db *gorm.DB, typ string, zoneID, pk uint) error {
	k, ok := kindByType(typ)
	if !ok {
		return ErrUnknownType
	}
	return k.del(db, zoneID, pk)
}
