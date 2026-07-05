package api

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"gorm.io/gorm"

	"github.com/tmshlvck/teleddns-server/model"
)

// APIRecord is the unified, type-discriminated representation of a resource
// record over the management API (PLAN.md M6). One JSON shape covers all 14 RR
// types: `type` selects the record kind, and only the rdata fields relevant to
// that type are populated (the rest are omitted). It maps to/from the
// one-table-per-type GORM models. `id` is an opaque, type-prefixed handle
// ("a-12", "mx-7") so a single id unambiguously identifies a row across tables.
type APIRecord struct {
	ID   string `json:"id,omitempty" doc:"Opaque record id (e.g. \"a-12\"); ignored on create." readOnly:"true"`
	Type string `json:"type" enum:"A,AAAA,NS,PTR,CNAME,TXT,MX,SRV,CAA,SSHFP,TLSA,DNSKEY,DS,NAPTR" doc:"RR type."`
	Name string `json:"name" doc:"Label within the zone; \"@\" for the apex."`
	TTL  uint32 `json:"ttl,omitempty" doc:"Record TTL in seconds; defaults to the server default when omitted."`

	// rdata — union over all types; only the type-relevant fields are set.
	Value        string  `json:"value,omitempty" doc:"A/AAAA address, NS/PTR/CNAME/MX target, TXT text, or CAA value."`
	Priority     *uint16 `json:"priority,omitempty" doc:"MX/SRV priority."`
	Weight       *uint16 `json:"weight,omitempty" doc:"SRV weight."`
	Port         *uint16 `json:"port,omitempty" doc:"SRV port."`
	Flag         *uint8  `json:"flag,omitempty" doc:"CAA flag."`
	Tag          string  `json:"tag,omitempty" doc:"CAA tag (issue|issuewild|iodef|contactemail|contactphone)."`
	Algorithm    *uint8  `json:"algorithm,omitempty" doc:"SSHFP/DNSKEY/DS algorithm."`
	HashType     *uint8  `json:"hash_type,omitempty" doc:"SSHFP hash type."`
	Fingerprint  string  `json:"fingerprint,omitempty" doc:"SSHFP fingerprint."`
	CertUsage    *uint8  `json:"cert_usage,omitempty" doc:"TLSA certificate usage."`
	Selector     *uint8  `json:"selector,omitempty" doc:"TLSA selector."`
	MatchingType *uint8  `json:"matching_type,omitempty" doc:"TLSA matching type."`
	CertData     string  `json:"cert_data,omitempty" doc:"TLSA certificate association data."`
	Flags        *uint16 `json:"flags,omitempty" doc:"DNSKEY flags."`
	Protocol     *uint8  `json:"protocol,omitempty" doc:"DNSKEY protocol (default 3)."`
	PublicKey    string  `json:"public_key,omitempty" doc:"DNSKEY public key."`
	KeyTag       *uint16 `json:"key_tag,omitempty" doc:"DS key tag."`
	DigestType   *uint8  `json:"digest_type,omitempty" doc:"DS digest type."`
	Digest       string  `json:"digest,omitempty" doc:"DS digest."`
	Order        *uint16 `json:"order,omitempty" doc:"NAPTR order."`
	Preference   *uint16 `json:"preference,omitempty" doc:"NAPTR preference."`
	NAPTRFlags   string  `json:"naptr_flags,omitempty" doc:"NAPTR flags (e.g. \"U\", \"S\")."`
	Service      string  `json:"service,omitempty" doc:"NAPTR service."`
	Regexp       string  `json:"regexp,omitempty" doc:"NAPTR regexp."`
	Replacement  string  `json:"replacement,omitempty" doc:"NAPTR replacement (DNS name)."`
}

// errRRNotFound signals a missing record (mapped to 404 by the handler).
var errRRNotFound = errors.New("record not found")

// rrKind is the per-type CRUD surface over one RR table, type-erased so all 14
// live in one registry. target drives the authorization level (A/AAAA address
// sets are L1; everything else is L2).
type rrKind struct {
	name   string
	target model.TargetKind
	list   func(db *gorm.DB, zoneID uint) ([]APIRecord, error)
	// count / page support DB-level pagination with optional exact filters on
	// label and value ("" = no filter). value must only be passed for
	// value-bearing types (all cfapi types have a value column).
	count  func(db *gorm.DB, zoneID uint, label, value string) (int64, error)
	page   func(db *gorm.DB, zoneID uint, label, value string, limit, offset int) ([]APIRecord, error)
	get    func(db *gorm.DB, zoneID, pk uint) (APIRecord, bool, error)
	create func(db *gorm.DB, zoneID uint, in APIRecord) (APIRecord, error)
	update func(db *gorm.DB, zoneID, pk uint, in APIRecord) (APIRecord, error)
	del    func(db *gorm.DB, zoneID, pk uint) error
}

// mkKind builds an rrKind for table type T from two concrete closures: toAPI
// (row → APIRecord) and apply (APIRecord → row, with validation). The generic
// CRUD plumbing — scoped queries, hooks via Save/Delete — is shared.
func mkKind[T any](name string, target model.TargetKind,
	toAPI func(*T) APIRecord,
	apply func(in APIRecord, zoneID uint, row *T) error,
) rrKind {
	return rrKind{
		name:   name,
		target: target,
		list: func(db *gorm.DB, zoneID uint) ([]APIRecord, error) {
			var rows []T
			if err := db.Where("zone_id = ?", zoneID).Order("id").Find(&rows).Error; err != nil {
				return nil, err
			}
			out := make([]APIRecord, len(rows))
			for i := range rows {
				out[i] = toAPI(&rows[i])
			}
			return out, nil
		},
		count: func(db *gorm.DB, zoneID uint, label, value string) (int64, error) {
			var n int64
			err := rrFilter(db.Model(new(T)), zoneID, label, value).Count(&n).Error
			return n, err
		},
		page: func(db *gorm.DB, zoneID uint, label, value string, limit, offset int) ([]APIRecord, error) {
			var rows []T
			q := rrFilter(db, zoneID, label, value).Order("id").Limit(limit).Offset(offset)
			if err := q.Find(&rows).Error; err != nil {
				return nil, err
			}
			out := make([]APIRecord, len(rows))
			for i := range rows {
				out[i] = toAPI(&rows[i])
			}
			return out, nil
		},
		get: func(db *gorm.DB, zoneID, pk uint) (APIRecord, bool, error) {
			var row T
			res := db.Where("zone_id = ? AND id = ?", zoneID, pk).Limit(1).Find(&row)
			if res.Error != nil {
				return APIRecord{}, false, res.Error
			}
			if res.RowsAffected == 0 {
				return APIRecord{}, false, nil
			}
			return toAPI(&row), true, nil
		},
		create: func(db *gorm.DB, zoneID uint, in APIRecord) (APIRecord, error) {
			var row T
			if err := apply(in, zoneID, &row); err != nil {
				return APIRecord{}, err
			}
			if err := db.Create(&row).Error; err != nil {
				return APIRecord{}, err
			}
			return toAPI(&row), nil
		},
		update: func(db *gorm.DB, zoneID, pk uint, in APIRecord) (APIRecord, error) {
			var row T
			res := db.Where("zone_id = ? AND id = ?", zoneID, pk).Limit(1).Find(&row)
			if res.Error != nil {
				return APIRecord{}, res.Error
			}
			if res.RowsAffected == 0 {
				return APIRecord{}, errRRNotFound
			}
			if err := apply(in, zoneID, &row); err != nil {
				return APIRecord{}, err
			}
			if err := db.Save(&row).Error; err != nil {
				return APIRecord{}, err
			}
			return toAPI(&row), nil
		},
		del: func(db *gorm.DB, zoneID, pk uint) error {
			var row T
			res := db.Where("zone_id = ? AND id = ?", zoneID, pk).Limit(1).Find(&row)
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected == 0 {
				return errRRNotFound
			}
			return db.Delete(&row).Error
		},
	}
}

// rrFilter applies the common (zone, optional label, optional value) predicates.
func rrFilter(q *gorm.DB, zoneID uint, label, value string) *gorm.DB {
	q = q.Where("zone_id = ?", zoneID)
	if label != "" {
		q = q.Where("label = ?", label)
	}
	if value != "" {
		q = q.Where("value = ?", value)
	}
	return q
}

// rrKinds is the registry keyed by lowercase type name (matching the id prefix).
var rrKinds = buildKinds()

func kindByType(typ string) (rrKind, bool) {
	k, ok := rrKinds[strings.ToLower(typ)]
	return k, ok
}

// ridEncode / ridDecode map between an APIRecord id and (type, pk).
func ridEncode(typ string, pk uint) string {
	return strings.ToLower(typ) + "-" + strconv.FormatUint(uint64(pk), 10)
}

func ridDecode(id string) (typ string, pk uint, ok bool) {
	t, n, found := strings.Cut(id, "-")
	if !found {
		return "", 0, false
	}
	v, err := strconv.ParseUint(n, 10, 64)
	if err != nil {
		return "", 0, false
	}
	return strings.ToLower(t), uint(v), true
}

// ── small validation + conversion helpers ──

func rec(typ string, pk uint, label string, ttl uint32) APIRecord {
	return APIRecord{ID: ridEncode(typ, pk), Type: typ, Name: label, TTL: ttl}
}

func p8(v uint8) *uint8    { return &v }
func p16(v uint16) *uint16 { return &v }

func vName(s string) error {
	if s == "" {
		return errors.New("name is required")
	}
	return model.ValLabel(s)
}

func vDNSName(s string) error {
	if s == "" {
		return errors.New("value is required (a DNS name)")
	}
	return model.ValDNSName(s)
}

func nonEmpty(s, field string) error {
	if s == "" {
		return fmt.Errorf("%s is required", field)
	}
	return nil
}

func req8(p *uint8, field string) (uint8, error) {
	if p == nil {
		return 0, fmt.Errorf("%s is required", field)
	}
	return *p, nil
}

func req16(p *uint16, field string) (uint16, error) {
	if p == nil {
		return 0, fmt.Errorf("%s is required", field)
	}
	return *p, nil
}

func inRange8(v, lo, hi uint8, field string) error {
	if v < lo || v > hi {
		return fmt.Errorf("%s must be between %d and %d", field, lo, hi)
	}
	return nil
}

// buildKinds wires every RR type. Each entry is (toAPI, apply) — apply sets
// zone/label/ttl + rdata and validates per PRD Part A §4.2.
func buildKinds() map[string]rrKind {
	m := map[string]rrKind{}
	add := func(k rrKind) { m[strings.ToLower(k.name)] = k }

	add(mkKind[model.RRA]("A", model.TargetAddrRecord,
		func(r *model.RRA) APIRecord { a := rec("A", r.ID, r.Label, r.TTL); a.Value = r.Value; return a },
		func(in APIRecord, z uint, r *model.RRA) error {
			if err := vName(in.Name); err != nil {
				return err
			}
			ip, err := netip.ParseAddr(in.Value)
			if err != nil || !ip.Is4() {
				return errors.New("value must be an IPv4 address")
			}
			r.ZoneID, r.Label, r.TTL, r.Value = z, in.Name, in.TTL, ip.String()
			return nil
		}))

	add(mkKind[model.RRAAAA]("AAAA", model.TargetAddrRecord,
		func(r *model.RRAAAA) APIRecord { a := rec("AAAA", r.ID, r.Label, r.TTL); a.Value = r.Value; return a },
		func(in APIRecord, z uint, r *model.RRAAAA) error {
			if err := vName(in.Name); err != nil {
				return err
			}
			ip, err := netip.ParseAddr(in.Value)
			if err != nil || ip.Is4() || !ip.Is6() {
				return errors.New("value must be an IPv6 address")
			}
			r.ZoneID, r.Label, r.TTL, r.Value = z, in.Name, in.TTL, ip.String()
			return nil
		}))

	add(mkKind[model.RRNS]("NS", model.TargetZoneData,
		func(r *model.RRNS) APIRecord { a := rec("NS", r.ID, r.Label, r.TTL); a.Value = r.Value; return a },
		func(in APIRecord, z uint, r *model.RRNS) error {
			if err := vName(in.Name); err != nil {
				return err
			}
			if err := vDNSName(in.Value); err != nil {
				return err
			}
			r.ZoneID, r.Label, r.TTL, r.Value = z, in.Name, in.TTL, in.Value
			return nil
		}))

	add(mkKind[model.RRPTR]("PTR", model.TargetZoneData,
		func(r *model.RRPTR) APIRecord { a := rec("PTR", r.ID, r.Label, r.TTL); a.Value = r.Value; return a },
		func(in APIRecord, z uint, r *model.RRPTR) error {
			if err := vName(in.Name); err != nil {
				return err
			}
			if err := vDNSName(in.Value); err != nil {
				return err
			}
			r.ZoneID, r.Label, r.TTL, r.Value = z, in.Name, in.TTL, in.Value
			return nil
		}))

	add(mkKind[model.RRCNAME]("CNAME", model.TargetZoneData,
		func(r *model.RRCNAME) APIRecord { a := rec("CNAME", r.ID, r.Label, r.TTL); a.Value = r.Value; return a },
		func(in APIRecord, z uint, r *model.RRCNAME) error {
			if err := vName(in.Name); err != nil {
				return err
			}
			if err := vDNSName(in.Value); err != nil {
				return err
			}
			r.ZoneID, r.Label, r.TTL, r.Value = z, in.Name, in.TTL, in.Value
			return nil
		}))

	add(mkKind[model.RRTXT]("TXT", model.TargetZoneData,
		func(r *model.RRTXT) APIRecord { a := rec("TXT", r.ID, r.Label, r.TTL); a.Value = r.Value; return a },
		func(in APIRecord, z uint, r *model.RRTXT) error {
			if err := vName(in.Name); err != nil {
				return err
			}
			if err := nonEmpty(in.Value, "value"); err != nil {
				return err
			}
			r.ZoneID, r.Label, r.TTL, r.Value = z, in.Name, in.TTL, in.Value
			return nil
		}))

	add(mkKind[model.RRMX]("MX", model.TargetZoneData,
		func(r *model.RRMX) APIRecord {
			a := rec("MX", r.ID, r.Label, r.TTL)
			a.Priority, a.Value = p16(r.Priority), r.Value
			return a
		},
		func(in APIRecord, z uint, r *model.RRMX) error {
			if err := vName(in.Name); err != nil {
				return err
			}
			prio, err := req16(in.Priority, "priority")
			if err != nil {
				return err
			}
			if err := vDNSName(in.Value); err != nil {
				return err
			}
			r.ZoneID, r.Label, r.TTL = z, in.Name, in.TTL
			r.Priority, r.Value = prio, in.Value
			return nil
		}))

	add(mkKind[model.RRSRV]("SRV", model.TargetZoneData,
		func(r *model.RRSRV) APIRecord {
			a := rec("SRV", r.ID, r.Label, r.TTL)
			a.Priority, a.Weight, a.Port, a.Value = p16(r.Priority), p16(r.Weight), p16(r.Port), r.Value
			return a
		},
		func(in APIRecord, z uint, r *model.RRSRV) error {
			if err := vName(in.Name); err != nil {
				return err
			}
			prio, err := req16(in.Priority, "priority")
			if err != nil {
				return err
			}
			weight, err := req16(in.Weight, "weight")
			if err != nil {
				return err
			}
			port, err := req16(in.Port, "port")
			if err != nil {
				return err
			}
			if err := vDNSName(in.Value); err != nil {
				return err
			}
			r.ZoneID, r.Label, r.TTL = z, in.Name, in.TTL
			r.Priority, r.Weight, r.Port, r.Value = prio, weight, port, in.Value
			return nil
		}))

	add(mkKind[model.RRCAA]("CAA", model.TargetZoneData,
		func(r *model.RRCAA) APIRecord {
			a := rec("CAA", r.ID, r.Label, r.TTL)
			a.Flag, a.Tag, a.Value = p8(r.Flag), r.Tag, r.Value
			return a
		},
		func(in APIRecord, z uint, r *model.RRCAA) error {
			if err := vName(in.Name); err != nil {
				return err
			}
			flag, err := req8(in.Flag, "flag")
			if err != nil {
				return err
			}
			if err := model.OneOfString("issue", "issuewild", "iodef", "contactemail", "contactphone")(in.Tag); err != nil {
				return err
			}
			if err := nonEmpty(in.Tag, "tag"); err != nil {
				return err
			}
			if err := nonEmpty(in.Value, "value"); err != nil {
				return err
			}
			r.ZoneID, r.Label, r.TTL = z, in.Name, in.TTL
			r.Flag, r.Tag, r.Value = flag, in.Tag, in.Value
			return nil
		}))

	add(mkKind[model.RRSSHFP]("SSHFP", model.TargetZoneData,
		func(r *model.RRSSHFP) APIRecord {
			a := rec("SSHFP", r.ID, r.Label, r.TTL)
			a.Algorithm, a.HashType, a.Fingerprint = p8(r.Algorithm), p8(r.HashType), r.Fingerprint
			return a
		},
		func(in APIRecord, z uint, r *model.RRSSHFP) error {
			if err := vName(in.Name); err != nil {
				return err
			}
			alg, err := req8(in.Algorithm, "algorithm")
			if err != nil {
				return err
			}
			if err := inRange8(alg, 1, 4, "algorithm"); err != nil {
				return err
			}
			ht, err := req8(in.HashType, "hash_type")
			if err != nil {
				return err
			}
			if err := inRange8(ht, 1, 2, "hash_type"); err != nil {
				return err
			}
			if err := nonEmpty(in.Fingerprint, "fingerprint"); err != nil {
				return err
			}
			r.ZoneID, r.Label, r.TTL = z, in.Name, in.TTL
			r.Algorithm, r.HashType, r.Fingerprint = alg, ht, in.Fingerprint
			return nil
		}))

	add(mkKind[model.RRTLSA]("TLSA", model.TargetZoneData,
		func(r *model.RRTLSA) APIRecord {
			a := rec("TLSA", r.ID, r.Label, r.TTL)
			a.CertUsage, a.Selector, a.MatchingType, a.CertData = p8(r.CertUsage), p8(r.Selector), p8(r.MatchingType), r.CertData
			return a
		},
		func(in APIRecord, z uint, r *model.RRTLSA) error {
			if err := vName(in.Name); err != nil {
				return err
			}
			cu, err := req8(in.CertUsage, "cert_usage")
			if err != nil {
				return err
			}
			if err := inRange8(cu, 0, 3, "cert_usage"); err != nil {
				return err
			}
			sel, err := req8(in.Selector, "selector")
			if err != nil {
				return err
			}
			if err := inRange8(sel, 0, 1, "selector"); err != nil {
				return err
			}
			mt, err := req8(in.MatchingType, "matching_type")
			if err != nil {
				return err
			}
			if err := inRange8(mt, 0, 2, "matching_type"); err != nil {
				return err
			}
			if err := nonEmpty(in.CertData, "cert_data"); err != nil {
				return err
			}
			r.ZoneID, r.Label, r.TTL = z, in.Name, in.TTL
			r.CertUsage, r.Selector, r.MatchingType, r.CertData = cu, sel, mt, in.CertData
			return nil
		}))

	add(mkKind[model.RRDNSKEY]("DNSKEY", model.TargetZoneData,
		func(r *model.RRDNSKEY) APIRecord {
			a := rec("DNSKEY", r.ID, r.Label, r.TTL)
			a.Flags, a.Protocol, a.Algorithm, a.PublicKey = p16(r.Flags), p8(r.Protocol), p8(r.Algorithm), r.PublicKey
			return a
		},
		func(in APIRecord, z uint, r *model.RRDNSKEY) error {
			if err := vName(in.Name); err != nil {
				return err
			}
			flags, err := req16(in.Flags, "flags")
			if err != nil {
				return err
			}
			alg, err := req8(in.Algorithm, "algorithm")
			if err != nil {
				return err
			}
			if err := nonEmpty(in.PublicKey, "public_key"); err != nil {
				return err
			}
			proto := uint8(3)
			if in.Protocol != nil {
				proto = *in.Protocol
			}
			r.ZoneID, r.Label, r.TTL = z, in.Name, in.TTL
			r.Flags, r.Protocol, r.Algorithm, r.PublicKey = flags, proto, alg, in.PublicKey
			return nil
		}))

	add(mkKind[model.RRDS]("DS", model.TargetZoneData,
		func(r *model.RRDS) APIRecord {
			a := rec("DS", r.ID, r.Label, r.TTL)
			a.KeyTag, a.Algorithm, a.DigestType, a.Digest = p16(r.KeyTag), p8(r.Algorithm), p8(r.DigestType), r.Digest
			return a
		},
		func(in APIRecord, z uint, r *model.RRDS) error {
			if err := vName(in.Name); err != nil {
				return err
			}
			kt, err := req16(in.KeyTag, "key_tag")
			if err != nil {
				return err
			}
			alg, err := req8(in.Algorithm, "algorithm")
			if err != nil {
				return err
			}
			dt, err := req8(in.DigestType, "digest_type")
			if err != nil {
				return err
			}
			if err := nonEmpty(in.Digest, "digest"); err != nil {
				return err
			}
			r.ZoneID, r.Label, r.TTL = z, in.Name, in.TTL
			r.KeyTag, r.Algorithm, r.DigestType, r.Digest = kt, alg, dt, in.Digest
			return nil
		}))

	add(mkKind[model.RRNAPTR]("NAPTR", model.TargetZoneData,
		func(r *model.RRNAPTR) APIRecord {
			a := rec("NAPTR", r.ID, r.Label, r.TTL)
			a.Order, a.Preference = p16(r.Order), p16(r.Preference)
			a.NAPTRFlags, a.Service, a.Regexp, a.Replacement = r.Flags, r.Service, r.Regexp, r.Replacement
			return a
		},
		func(in APIRecord, z uint, r *model.RRNAPTR) error {
			if err := vName(in.Name); err != nil {
				return err
			}
			order, err := req16(in.Order, "order")
			if err != nil {
				return err
			}
			pref, err := req16(in.Preference, "preference")
			if err != nil {
				return err
			}
			if in.Replacement != "" && in.Replacement != "." {
				if err := model.ValDNSName(in.Replacement); err != nil {
					return err
				}
			}
			r.ZoneID, r.Label, r.TTL = z, in.Name, in.TTL
			r.Order, r.Preference = order, pref
			r.Flags, r.Service, r.Regexp, r.Replacement = in.NAPTRFlags, in.Service, in.Regexp, in.Replacement
			return nil
		}))

	return m
}
