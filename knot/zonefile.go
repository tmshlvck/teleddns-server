// Package knot renders zone files for the local Knot DNS server and pushes
// them via the backend-sync worker. Scoped to the co-located, master-only,
// Knot-only design (see docs/DESIGN.md §7).
package knot

import (
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/tmshlvck/teleddns-server/model"
)

// RenderZone regenerates the full BIND-format zone file for origin from current
// DB state — the idempotent payload the worker pushes to Knot. Serialization
// follows PRD Part A §4.2 so kzonecheck accepts the output. Returns ErrNoZone-
// like gorm.ErrRecordNotFound if the origin is gone (e.g. zone deleted).
func RenderZone(db *gorm.DB, origin string, defaultTTL uint32) (string, error) {
	var z model.Zone
	if err := db.Where("origin = ?", origin).First(&z).Error; err != nil {
		return "", err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "$ORIGIN %s\n", z.Origin)
	fmt.Fprintf(&b, "$TTL %d\n", defaultTTL)
	// SOA (inline on the zone row; NAME=@ and CLASS=IN are implicit).
	fmt.Fprintf(&b, "@ %d IN SOA %s %s ( %d %d %d %d %d )\n",
		z.SOATTL, z.SOAMName, z.SOARName, z.SOASerial, z.SOARefresh, z.SOARetry, z.SOAExpire, z.SOAMinimum)

	emit := func(lines []string) {
		for _, l := range lines {
			b.WriteString(l)
			b.WriteString("\n")
		}
	}

	// Order: NS first (apex authority), then the rest by type. Within a type,
	// DB order (id) is stable.
	emit(renderNS(db, z.ID))
	emit(renderA(db, z.ID))
	emit(renderAAAA(db, z.ID))
	emit(renderCNAME(db, z.ID))
	emit(renderMX(db, z.ID))
	emit(renderTXT(db, z.ID))
	emit(renderPTR(db, z.ID))
	emit(renderSRV(db, z.ID))
	emit(renderCAA(db, z.ID))
	emit(renderSSHFP(db, z.ID))
	emit(renderTLSA(db, z.ID))
	emit(renderDNSKEY(db, z.ID))
	emit(renderDS(db, z.ID))
	emit(renderNAPTR(db, z.ID))

	return b.String(), nil
}

func renderNS(db *gorm.DB, zoneID uint) []string {
	var rs []model.RRNS
	db.Where("zone_id = ?", zoneID).Order("id").Find(&rs)
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = fmt.Sprintf("%s %d IN NS %s", r.Label, r.TTL, r.Value)
	}
	return out
}

func renderA(db *gorm.DB, zoneID uint) []string {
	var rs []model.RRA
	db.Where("zone_id = ?", zoneID).Order("id").Find(&rs)
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = fmt.Sprintf("%s %d IN A %s", r.Label, r.TTL, r.Value)
	}
	return out
}

func renderAAAA(db *gorm.DB, zoneID uint) []string {
	var rs []model.RRAAAA
	db.Where("zone_id = ?", zoneID).Order("id").Find(&rs)
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = fmt.Sprintf("%s %d IN AAAA %s", r.Label, r.TTL, r.Value)
	}
	return out
}

func renderCNAME(db *gorm.DB, zoneID uint) []string {
	var rs []model.RRCNAME
	db.Where("zone_id = ?", zoneID).Order("id").Find(&rs)
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = fmt.Sprintf("%s %d IN CNAME %s", r.Label, r.TTL, r.Value)
	}
	return out
}

func renderMX(db *gorm.DB, zoneID uint) []string {
	var rs []model.RRMX
	db.Where("zone_id = ?", zoneID).Order("id").Find(&rs)
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = fmt.Sprintf("%s %d IN MX %d %s", r.Label, r.TTL, r.Priority, r.Value)
	}
	return out
}

func renderTXT(db *gorm.DB, zoneID uint) []string {
	var rs []model.RRTXT
	db.Where("zone_id = ?", zoneID).Order("id").Find(&rs)
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = fmt.Sprintf("%s %d IN TXT %q", r.Label, r.TTL, r.Value)
	}
	return out
}

func renderPTR(db *gorm.DB, zoneID uint) []string {
	var rs []model.RRPTR
	db.Where("zone_id = ?", zoneID).Order("id").Find(&rs)
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = fmt.Sprintf("%s %d IN PTR %s", r.Label, r.TTL, r.Value)
	}
	return out
}

func renderSRV(db *gorm.DB, zoneID uint) []string {
	var rs []model.RRSRV
	db.Where("zone_id = ?", zoneID).Order("id").Find(&rs)
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = fmt.Sprintf("%s %d IN SRV %d %d %d %s", r.Label, r.TTL, r.Priority, r.Weight, r.Port, r.Value)
	}
	return out
}

func renderCAA(db *gorm.DB, zoneID uint) []string {
	var rs []model.RRCAA
	db.Where("zone_id = ?", zoneID).Order("id").Find(&rs)
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = fmt.Sprintf("%s %d IN CAA %d %s %q", r.Label, r.TTL, r.Flag, r.Tag, r.Value)
	}
	return out
}

func renderSSHFP(db *gorm.DB, zoneID uint) []string {
	var rs []model.RRSSHFP
	db.Where("zone_id = ?", zoneID).Order("id").Find(&rs)
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = fmt.Sprintf("%s %d IN SSHFP %d %d %s", r.Label, r.TTL, r.Algorithm, r.HashType, r.Fingerprint)
	}
	return out
}

func renderTLSA(db *gorm.DB, zoneID uint) []string {
	var rs []model.RRTLSA
	db.Where("zone_id = ?", zoneID).Order("id").Find(&rs)
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = fmt.Sprintf("%s %d IN TLSA %d %d %d %s", r.Label, r.TTL, r.CertUsage, r.Selector, r.MatchingType, r.CertData)
	}
	return out
}

func renderDNSKEY(db *gorm.DB, zoneID uint) []string {
	var rs []model.RRDNSKEY
	db.Where("zone_id = ?", zoneID).Order("id").Find(&rs)
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = fmt.Sprintf("%s %d IN DNSKEY %d %d %d %s", r.Label, r.TTL, r.Flags, r.Protocol, r.Algorithm, r.PublicKey)
	}
	return out
}

func renderDS(db *gorm.DB, zoneID uint) []string {
	var rs []model.RRDS
	db.Where("zone_id = ?", zoneID).Order("id").Find(&rs)
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = fmt.Sprintf("%s %d IN DS %d %d %d %s", r.Label, r.TTL, r.KeyTag, r.Algorithm, r.DigestType, r.Digest)
	}
	return out
}

func renderNAPTR(db *gorm.DB, zoneID uint) []string {
	var rs []model.RRNAPTR
	db.Where("zone_id = ?", zoneID).Order("id").Find(&rs)
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = fmt.Sprintf("%s %d IN NAPTR %d %d %q %q %q %s",
			r.Label, r.TTL, r.Order, r.Preference, r.Flags, r.Service, r.Regexp, r.Replacement)
	}
	return out
}
