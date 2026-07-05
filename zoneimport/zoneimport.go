// Package zoneimport bulk-loads a BIND zone file into teleddns via the same
// model write path the JSON API uses (api.RRCreate — per-type validation, SOA
// serial bump, SyncTask enqueue). It backs the `admin import` CLI subcommand:
// an operator quality-of-life tool that needs no running server, network, or API
// key. Parsing is delegated to github.com/miekg/dns (handles $ORIGIN/$TTL and
// every RR type).
package zoneimport

import (
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/miekg/dns"
	"gorm.io/gorm"

	"github.com/tmshlvck/teleddns-server/api"
	"github.com/tmshlvck/teleddns-server/model"
)

// Summary reports what an import did.
type Summary struct {
	Origin   string
	Created  bool           // the zone was created by this import
	Replaced bool           // existing records were cleared first
	Imported map[string]int // RR type → count inserted
	Skipped  int            // unsupported RR types
	Errors   int            // records rejected by validation
}

// Total returns the number of records inserted.
func (s *Summary) Total() int {
	n := 0
	for _, c := range s.Imported {
		n += c
	}
	return n
}

// Import parses a zone from r and loads it. origin may be empty when the file
// carries an SOA or $ORIGIN. With replace, an existing zone's records are
// cleared (and its SOA reset from the file) before loading; otherwise records
// are added on top of what's there.
func Import(db *gorm.DB, r io.Reader, filename, origin string, replace bool, log *slog.Logger) (*Summary, error) {
	parserOrigin := ""
	if origin != "" {
		parserOrigin = dns.Fqdn(origin)
	}
	zp := dns.NewZoneParser(r, parserOrigin, filename)
	zp.SetIncludeAllowed(false) // don't follow $INCLUDE out of an operator-supplied file

	var (
		rrs []dns.RR
		soa *dns.SOA
	)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if s, isSOA := rr.(*dns.SOA); isSOA {
			soa = s
			continue
		}
		rrs = append(rrs, rr)
	}
	if err := zp.Err(); err != nil {
		return nil, fmt.Errorf("parse zone file: %w", err)
	}

	orig := dns.Fqdn(origin)
	if soa != nil {
		orig = soa.Hdr.Name
	}
	if orig == "" || orig == "." {
		return nil, fmt.Errorf("no zone origin: pass --origin or include an SOA / $ORIGIN in the file")
	}
	sum := &Summary{Origin: orig, Replaced: replace, Imported: map[string]int{}}

	// Locate or create the zone.
	var z model.Zone
	res := db.Where("origin = ?", orig).Limit(1).Find(&z)
	if res.Error != nil {
		return nil, res.Error
	}
	switch {
	case res.RowsAffected == 0:
		z = model.Zone{Origin: orig}
		applySOA(&z, soa)
		if err := db.Create(&z).Error; err != nil { // BeforeCreate fills any blank SOA fields; AfterCreate adds an apex NS
			return nil, fmt.Errorf("create zone %s: %w", orig, err)
		}
		sum.Created = true
		// The file is authoritative for NS — drop the auto-created apex NS so the
		// import doesn't duplicate it.
		db.Session(&gorm.Session{SkipHooks: true}).Where("zone_id = ?", z.ID).Delete(&model.RRNS{})
	case replace:
		deleteAllRRs(db, z.ID)
		applySOA(&z, soa)
		if err := db.Save(&z).Error; err != nil {
			return nil, fmt.Errorf("update zone %s: %w", orig, err)
		}
	}

	for _, rr := range rrs {
		typ, rec, ok := toAPIRecord(rr, orig)
		if !ok {
			sum.Skipped++
			if log != nil {
				log.Warn("import: unsupported record skipped", "rr", strings.TrimSpace(rr.String()))
			}
			continue
		}
		if _, err := api.RRCreate(db, typ, z.ID, rec); err != nil {
			sum.Errors++
			if log != nil {
				log.Warn("import: record rejected", "rr", strings.TrimSpace(rr.String()), "err", err)
			}
			continue
		}
		sum.Imported[typ]++
	}

	// Pin the serial to the file's SOA so the imported zone matches it exactly
	// (the per-record hooks bumped it during insert). Skips hooks — no extra push.
	if soa != nil {
		db.Model(&model.Zone{}).Where("id = ?", z.ID).UpdateColumn("soa_serial", soa.Serial)
	}
	return sum, nil
}

// applySOA copies SOA fields off the parsed record; a nil soa leaves the zone's
// defaults (BeforeCreate fills blanks on create).
func applySOA(z *model.Zone, soa *dns.SOA) {
	if soa == nil {
		return
	}
	z.SOATTL = soa.Hdr.Ttl
	z.SOAMName = soa.Ns
	z.SOARName = soa.Mbox
	z.SOASerial = soa.Serial
	z.SOARefresh = soa.Refresh
	z.SOARetry = soa.Retry
	z.SOAExpire = soa.Expire
	z.SOAMinimum = soa.Minttl
}

// deleteAllRRs clears every RR of a zone (hooks skipped, so no serial churn or
// last-NS guard during a full replace). Role grants are left intact.
func deleteAllRRs(db *gorm.DB, zoneID uint) {
	tx := db.Session(&gorm.Session{SkipHooks: true}).Where("zone_id = ?", zoneID)
	for _, m := range []any{
		&model.RRA{}, &model.RRAAAA{}, &model.RRNS{}, &model.RRPTR{}, &model.RRCNAME{}, &model.RRTXT{},
		&model.RRMX{}, &model.RRSRV{}, &model.RRCAA{}, &model.RRSSHFP{}, &model.RRTLSA{},
		&model.RRDNSKEY{}, &model.RRDS{}, &model.RRNAPTR{},
	} {
		tx.Delete(m)
	}
}

// toAPIRecord maps a parsed dns.RR to (type, api.APIRecord). Returns ok=false
// for RR types teleddns does not model.
func toAPIRecord(rr dns.RR, origin string) (string, api.APIRecord, bool) {
	h := rr.Header()
	base := api.APIRecord{Name: fqdnToLabel(h.Name, origin), TTL: h.Ttl}
	set := func(typ string) api.APIRecord { base.Type = typ; return base }

	switch v := rr.(type) {
	case *dns.A:
		r := set("A")
		r.Value = v.A.String()
		return "A", r, true
	case *dns.AAAA:
		r := set("AAAA")
		r.Value = v.AAAA.String()
		return "AAAA", r, true
	case *dns.NS:
		r := set("NS")
		r.Value = v.Ns
		return "NS", r, true
	case *dns.PTR:
		r := set("PTR")
		r.Value = v.Ptr
		return "PTR", r, true
	case *dns.CNAME:
		r := set("CNAME")
		r.Value = v.Target
		return "CNAME", r, true
	case *dns.TXT:
		r := set("TXT")
		r.Value = strings.Join(v.Txt, "")
		return "TXT", r, true
	case *dns.MX:
		r := set("MX")
		r.Priority, r.Value = p16(v.Preference), v.Mx
		return "MX", r, true
	case *dns.SRV:
		r := set("SRV")
		r.Priority, r.Weight, r.Port, r.Value = p16(v.Priority), p16(v.Weight), p16(v.Port), v.Target
		return "SRV", r, true
	case *dns.CAA:
		r := set("CAA")
		r.Flag, r.Tag, r.Value = p8(v.Flag), v.Tag, v.Value
		return "CAA", r, true
	case *dns.SSHFP:
		r := set("SSHFP")
		r.Algorithm, r.HashType, r.Fingerprint = p8(v.Algorithm), p8(v.Type), v.FingerPrint
		return "SSHFP", r, true
	case *dns.TLSA:
		r := set("TLSA")
		r.CertUsage, r.Selector, r.MatchingType, r.CertData = p8(v.Usage), p8(v.Selector), p8(v.MatchingType), v.Certificate
		return "TLSA", r, true
	case *dns.DNSKEY:
		r := set("DNSKEY")
		r.Flags, r.Protocol, r.Algorithm, r.PublicKey = p16(v.Flags), p8(v.Protocol), p8(v.Algorithm), v.PublicKey
		return "DNSKEY", r, true
	case *dns.DS:
		r := set("DS")
		r.KeyTag, r.Algorithm, r.DigestType, r.Digest = p16(v.KeyTag), p8(v.Algorithm), p8(v.DigestType), v.Digest
		return "DS", r, true
	case *dns.NAPTR:
		r := set("NAPTR")
		r.Order, r.Preference = p16(v.Order), p16(v.Preference)
		r.NAPTRFlags, r.Service, r.Regexp, r.Replacement = v.Flags, v.Service, v.Regexp, v.Replacement
		return "NAPTR", r, true
	default:
		return "", api.APIRecord{}, false
	}
}

// fqdnToLabel converts an absolute record name to the label stored in the zone
// ("@" for the apex).
func fqdnToLabel(name, origin string) string {
	n := strings.TrimSuffix(strings.ToLower(name), ".")
	o := strings.TrimSuffix(strings.ToLower(origin), ".")
	if n == o {
		return "@"
	}
	if strings.HasSuffix(n, "."+o) {
		return n[:len(n)-len(o)-1]
	}
	return name // out-of-zone; api.RRCreate will validate/reject
}

func p8(v uint8) *uint8    { return &v }
func p16(v uint16) *uint16 { return &v }
