package model

import (
	"errors"
	"time"

	"github.com/tmshlvck/gone/auth"
	"gorm.io/gorm"
)

// ErrLastNSRecord rejects deleting a zone's only NS record (PRD §11.3 — a
// delete must not orphan a zone's SOA or all its NS records).
var ErrLastNSRecord = errors.New("cannot delete the last NS record of a zone")

// This file defines the DNS data model (PRD §10.3 + Part A §4), scoped to the
// co-located, master-only, Knot-only design (see PLAN.md):
//
//   - Zone      — a master origin with inline SOA fields + sync tracking.
//   - RR*        — one GORM table per RR type (PRD §4.2). Structs are flat (no
//     embedding) because gone's CRUD reflection only walks top-level fields.
//   - TSIGKey    — a shared secret for authenticating zone transfers.
//   - ZoneSlave  — a per-zone transfer ACL: an allowed slave address + key.
//   - GroupZoneRole / GroupRRRole — L2 / L1 grants (PRD §9.3).
//
// There is no Server table: the backend is the local Knot daemon (configured
// from app Config). Slaves are not managed here — they auto-provision from the
// catalog zone the backend generates (RFC 9432) and pull data via AXFR/TSIG.
//
// Invariants enforced by GORM hooks (so they hold on every write path —
// admin, API, DDNS): a new Zone gets SOA defaults + a default apex NS, and any
// RR mutation bumps the owning zone's SOA serial and marks it dirty for the
// backend push.

// Zone is a master DNS zone: an origin (FQDN with trailing dot), its owner,
// the inline SOA fields (PRD §4.1; NAME=@ and CLASS=IN are implicit), and
// content-sync tracking. It is always served by the local Knot as master.
type Zone struct {
	ID      uint          `gorm:"primaryKey"`
	Origin  string        `gorm:"uniqueIndex;size:255;not null"`
	OwnerID uint          `gorm:"index"`
	Owner   auth.UserGORM `gorm:"foreignKey:OwnerID"`

	SOATTL     uint32 `gorm:"not null;default:3600"`
	SOAMName   string `gorm:"size:255"` // primary nameserver (SOA MNAME)
	SOARName   string `gorm:"size:255"` // responsible party (SOA RNAME)
	SOASerial  uint32 `gorm:"not null"`
	SOARefresh uint32 `gorm:"not null;default:10800"`
	SOARetry   uint32 `gorm:"not null;default:3600"`
	SOAExpire  uint32 `gorm:"not null;default:1209600"`
	SOAMinimum uint32 `gorm:"not null;default:3600"`

	ContentDirty    bool `gorm:"not null;default:false"`
	LastContentSync *time.Time

	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastUpdateInfo string `gorm:"size:255"`
}

func (Zone) TableName() string { return "zones" }

// BeforeCreate fills SOA defaults so a freshly-created zone is already valid.
func (z *Zone) BeforeCreate(*gorm.DB) error {
	if z.SOATTL == 0 {
		z.SOATTL = 3600
	}
	if z.SOAMName == "" {
		z.SOAMName = "ns1." + z.Origin
	}
	if z.SOARName == "" {
		z.SOARName = "hostmaster." + z.Origin
	}
	if z.SOASerial == 0 {
		z.SOASerial = todaySerial()
	}
	if z.SOARefresh == 0 {
		z.SOARefresh = 10800
	}
	if z.SOARetry == 0 {
		z.SOARetry = 3600
	}
	if z.SOAExpire == 0 {
		z.SOAExpire = 1209600
	}
	if z.SOAMinimum == 0 {
		z.SOAMinimum = 3600
	}
	return nil
}

// AfterCreate auto-generates the default apex NS record (PRD §4.1). Creating
// it bumps the serial once via the NS hook, which is the desired "zone changed
// → needs push" signal.
func (z *Zone) AfterCreate(tx *gorm.DB) error {
	ns := RRNS{ZoneID: z.ID, Label: "@", TTL: z.SOATTL, Value: z.SOAMName}
	return tx.Session(&gorm.Session{NewDB: true}).Create(&ns).Error
}

// todaySerial returns a YYYYMMDD00 SOA serial seed.
func todaySerial() uint32 {
	t := time.Now().UTC()
	return uint32(t.Year()*1000000 + int(t.Month())*10000 + t.Day()*100)
}

// bumpZoneOnChange increments the owning zone's SOA serial and flags it dirty
// for the backend push. Called from every RR type's AfterSave/AfterDelete so
// the invariant holds regardless of write path. UpdateColumns skips hooks and
// auto-timestamps, so there's no recursion.
func bumpZoneOnChange(tx *gorm.DB, zoneID uint) error {
	if zoneID == 0 {
		return nil
	}
	return tx.Session(&gorm.Session{NewDB: true}).
		Model(&Zone{}).Where("id = ?", zoneID).
		UpdateColumns(map[string]any{
			"soa_serial":    gorm.Expr("soa_serial + 1"),
			"content_dirty": true,
		}).Error
}

// ── RR tables (one per type, PRD §4.2). Common columns are repeated on each
// struct because gone's reflection does not descend into embedded structs. ──

type RRA struct {
	ID             uint   `gorm:"primaryKey"`
	ZoneID         uint   `gorm:"index;not null"`
	Zone           Zone   `gorm:"foreignKey:ZoneID"`
	Label          string `gorm:"size:63;not null"`
	TTL            uint32 `gorm:"not null;default:3600"`
	Value          string `gorm:"size:45;not null"` // IPv4 literal
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastUpdateInfo string `gorm:"size:255"`
}

type RRAAAA struct {
	ID             uint   `gorm:"primaryKey"`
	ZoneID         uint   `gorm:"index;not null"`
	Zone           Zone   `gorm:"foreignKey:ZoneID"`
	Label          string `gorm:"size:63;not null"`
	TTL            uint32 `gorm:"not null;default:3600"`
	Value          string `gorm:"size:45;not null"` // IPv6 literal
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastUpdateInfo string `gorm:"size:255"`
}

type RRNS struct {
	ID             uint   `gorm:"primaryKey"`
	ZoneID         uint   `gorm:"index;not null"`
	Zone           Zone   `gorm:"foreignKey:ZoneID"`
	Label          string `gorm:"size:63;not null"`
	TTL            uint32 `gorm:"not null;default:3600"`
	Value          string `gorm:"size:255;not null"` // DNS name
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastUpdateInfo string `gorm:"size:255"`
}

type RRPTR struct {
	ID             uint   `gorm:"primaryKey"`
	ZoneID         uint   `gorm:"index;not null"`
	Zone           Zone   `gorm:"foreignKey:ZoneID"`
	Label          string `gorm:"size:63;not null"`
	TTL            uint32 `gorm:"not null;default:3600"`
	Value          string `gorm:"size:255;not null"` // DNS name
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastUpdateInfo string `gorm:"size:255"`
}

type RRCNAME struct {
	ID             uint   `gorm:"primaryKey"`
	ZoneID         uint   `gorm:"index;not null"`
	Zone           Zone   `gorm:"foreignKey:ZoneID"`
	Label          string `gorm:"size:63;not null"`
	TTL            uint32 `gorm:"not null;default:3600"`
	Value          string `gorm:"size:255;not null"` // DNS name
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastUpdateInfo string `gorm:"size:255"`
}

type RRTXT struct {
	ID             uint   `gorm:"primaryKey"`
	ZoneID         uint   `gorm:"index;not null"`
	Zone           Zone   `gorm:"foreignKey:ZoneID"`
	Label          string `gorm:"size:63;not null"`
	TTL            uint32 `gorm:"not null;default:3600"`
	Value          string `gorm:"size:65535;not null"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastUpdateInfo string `gorm:"size:255"`
}

type RRMX struct {
	ID             uint   `gorm:"primaryKey"`
	ZoneID         uint   `gorm:"index;not null"`
	Zone           Zone   `gorm:"foreignKey:ZoneID"`
	Label          string `gorm:"size:63;not null"`
	TTL            uint32 `gorm:"not null;default:3600"`
	Priority       uint16 `gorm:"not null"`
	Value          string `gorm:"size:255;not null"` // DNS name
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastUpdateInfo string `gorm:"size:255"`
}

type RRSRV struct {
	ID             uint   `gorm:"primaryKey"`
	ZoneID         uint   `gorm:"index;not null"`
	Zone           Zone   `gorm:"foreignKey:ZoneID"`
	Label          string `gorm:"size:63;not null"`
	TTL            uint32 `gorm:"not null;default:3600"`
	Priority       uint16 `gorm:"not null"`
	Weight         uint16 `gorm:"not null"`
	Port           uint16 `gorm:"not null"`
	Value          string `gorm:"size:255;not null"` // DNS name (target)
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastUpdateInfo string `gorm:"size:255"`
}

type RRCAA struct {
	ID             uint   `gorm:"primaryKey"`
	ZoneID         uint   `gorm:"index;not null"`
	Zone           Zone   `gorm:"foreignKey:ZoneID"`
	Label          string `gorm:"size:63;not null"`
	TTL            uint32 `gorm:"not null;default:3600"`
	Flag           uint8  `gorm:"not null"`
	Tag            string `gorm:"size:16;not null"` // issue|issuewild|iodef|contactemail|contactphone
	Value          string `gorm:"size:255;not null"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastUpdateInfo string `gorm:"size:255"`
}

type RRSSHFP struct {
	ID             uint   `gorm:"primaryKey"`
	ZoneID         uint   `gorm:"index;not null"`
	Zone           Zone   `gorm:"foreignKey:ZoneID"`
	Label          string `gorm:"size:63;not null"`
	TTL            uint32 `gorm:"not null;default:3600"`
	Algorithm      uint8  `gorm:"not null"` // 1..4
	HashType       uint8  `gorm:"not null"` // 1..2
	Fingerprint    string `gorm:"size:255;not null"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastUpdateInfo string `gorm:"size:255"`
}

type RRTLSA struct {
	ID             uint   `gorm:"primaryKey"`
	ZoneID         uint   `gorm:"index;not null"`
	Zone           Zone   `gorm:"foreignKey:ZoneID"`
	Label          string `gorm:"size:63;not null"`
	TTL            uint32 `gorm:"not null;default:3600"`
	CertUsage      uint8  `gorm:"not null"` // 0..3
	Selector       uint8  `gorm:"not null"` // 0..1
	MatchingType   uint8  `gorm:"not null"` // 0..2
	CertData       string `gorm:"size:1024;not null"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastUpdateInfo string `gorm:"size:255"`
}

type RRDNSKEY struct {
	ID             uint   `gorm:"primaryKey"`
	ZoneID         uint   `gorm:"index;not null"`
	Zone           Zone   `gorm:"foreignKey:ZoneID"`
	Label          string `gorm:"size:63;not null"`
	TTL            uint32 `gorm:"not null;default:3600"`
	Flags          uint16 `gorm:"not null"`
	Protocol       uint8  `gorm:"not null;default:3"`
	Algorithm      uint8  `gorm:"not null"`
	PublicKey      string `gorm:"size:1024;not null"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastUpdateInfo string `gorm:"size:255"`
}

type RRDS struct {
	ID             uint   `gorm:"primaryKey"`
	ZoneID         uint   `gorm:"index;not null"`
	Zone           Zone   `gorm:"foreignKey:ZoneID"`
	Label          string `gorm:"size:63;not null"`
	TTL            uint32 `gorm:"not null;default:3600"`
	KeyTag         uint16 `gorm:"not null"`
	Algorithm      uint8  `gorm:"not null"`
	DigestType     uint8  `gorm:"not null"`
	Digest         string `gorm:"size:512;not null"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastUpdateInfo string `gorm:"size:255"`
}

type RRNAPTR struct {
	ID             uint   `gorm:"primaryKey"`
	ZoneID         uint   `gorm:"index;not null"`
	Zone           Zone   `gorm:"foreignKey:ZoneID"`
	Label          string `gorm:"size:63;not null"`
	TTL            uint32 `gorm:"not null;default:3600"`
	Order          uint16 `gorm:"not null"`
	Preference     uint16 `gorm:"not null"`
	Flags          string `gorm:"size:16"`
	Service        string `gorm:"size:255"`
	Regexp         string `gorm:"size:255"`
	Replacement    string `gorm:"size:255"` // DNS name
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastUpdateInfo string `gorm:"size:255"`
}

func (RRA) TableName() string      { return "rr_a" }
func (RRAAAA) TableName() string   { return "rr_aaaa" }
func (RRNS) TableName() string     { return "rr_ns" }
func (RRPTR) TableName() string    { return "rr_ptr" }
func (RRCNAME) TableName() string  { return "rr_cname" }
func (RRTXT) TableName() string    { return "rr_txt" }
func (RRMX) TableName() string     { return "rr_mx" }
func (RRSRV) TableName() string    { return "rr_srv" }
func (RRCAA) TableName() string    { return "rr_caa" }
func (RRSSHFP) TableName() string  { return "rr_sshfp" }
func (RRTLSA) TableName() string   { return "rr_tlsa" }
func (RRDNSKEY) TableName() string { return "rr_dnskey" }
func (RRDS) TableName() string     { return "rr_ds" }
func (RRNAPTR) TableName() string  { return "rr_naptr" }

// AfterSave / AfterDelete on every RR type bump the owning zone's serial.
func (r *RRA) AfterSave(tx *gorm.DB) error      { return bumpZoneOnChange(tx, r.ZoneID) }
func (r *RRA) AfterDelete(tx *gorm.DB) error    { return bumpZoneOnChange(tx, r.ZoneID) }
func (r *RRAAAA) AfterSave(tx *gorm.DB) error   { return bumpZoneOnChange(tx, r.ZoneID) }
func (r *RRAAAA) AfterDelete(tx *gorm.DB) error { return bumpZoneOnChange(tx, r.ZoneID) }
func (r *RRNS) AfterSave(tx *gorm.DB) error     { return bumpZoneOnChange(tx, r.ZoneID) }
func (r *RRNS) AfterDelete(tx *gorm.DB) error   { return bumpZoneOnChange(tx, r.ZoneID) }

// BeforeDelete rejects removing a zone's last NS record (PRD §11.3).
func (r *RRNS) BeforeDelete(tx *gorm.DB) error {
	var n int64
	if err := tx.Session(&gorm.Session{NewDB: true}).
		Model(&RRNS{}).Where("zone_id = ?", r.ZoneID).Count(&n).Error; err != nil {
		return err
	}
	if n <= 1 {
		return ErrLastNSRecord
	}
	return nil
}
func (r *RRPTR) AfterSave(tx *gorm.DB) error      { return bumpZoneOnChange(tx, r.ZoneID) }
func (r *RRPTR) AfterDelete(tx *gorm.DB) error    { return bumpZoneOnChange(tx, r.ZoneID) }
func (r *RRCNAME) AfterSave(tx *gorm.DB) error    { return bumpZoneOnChange(tx, r.ZoneID) }
func (r *RRCNAME) AfterDelete(tx *gorm.DB) error  { return bumpZoneOnChange(tx, r.ZoneID) }
func (r *RRTXT) AfterSave(tx *gorm.DB) error      { return bumpZoneOnChange(tx, r.ZoneID) }
func (r *RRTXT) AfterDelete(tx *gorm.DB) error    { return bumpZoneOnChange(tx, r.ZoneID) }
func (r *RRMX) AfterSave(tx *gorm.DB) error       { return bumpZoneOnChange(tx, r.ZoneID) }
func (r *RRMX) AfterDelete(tx *gorm.DB) error     { return bumpZoneOnChange(tx, r.ZoneID) }
func (r *RRSRV) AfterSave(tx *gorm.DB) error      { return bumpZoneOnChange(tx, r.ZoneID) }
func (r *RRSRV) AfterDelete(tx *gorm.DB) error    { return bumpZoneOnChange(tx, r.ZoneID) }
func (r *RRCAA) AfterSave(tx *gorm.DB) error      { return bumpZoneOnChange(tx, r.ZoneID) }
func (r *RRCAA) AfterDelete(tx *gorm.DB) error    { return bumpZoneOnChange(tx, r.ZoneID) }
func (r *RRSSHFP) AfterSave(tx *gorm.DB) error    { return bumpZoneOnChange(tx, r.ZoneID) }
func (r *RRSSHFP) AfterDelete(tx *gorm.DB) error  { return bumpZoneOnChange(tx, r.ZoneID) }
func (r *RRTLSA) AfterSave(tx *gorm.DB) error     { return bumpZoneOnChange(tx, r.ZoneID) }
func (r *RRTLSA) AfterDelete(tx *gorm.DB) error   { return bumpZoneOnChange(tx, r.ZoneID) }
func (r *RRDNSKEY) AfterSave(tx *gorm.DB) error   { return bumpZoneOnChange(tx, r.ZoneID) }
func (r *RRDNSKEY) AfterDelete(tx *gorm.DB) error { return bumpZoneOnChange(tx, r.ZoneID) }
func (r *RRDS) AfterSave(tx *gorm.DB) error       { return bumpZoneOnChange(tx, r.ZoneID) }
func (r *RRDS) AfterDelete(tx *gorm.DB) error     { return bumpZoneOnChange(tx, r.ZoneID) }
func (r *RRNAPTR) AfterSave(tx *gorm.DB) error    { return bumpZoneOnChange(tx, r.ZoneID) }
func (r *RRNAPTR) AfterDelete(tx *gorm.DB) error  { return bumpZoneOnChange(tx, r.ZoneID) }

// ── Zone transfer (AXFR/TSIG) — master side. ──

// TSIGKey is a shared secret authenticating zone transfers (RFC 8945).
// Referenced by ZoneSlave ACL rows and emitted into the Knot config.
type TSIGKey struct {
	ID        uint   `gorm:"primaryKey"`
	Name      string `gorm:"uniqueIndex;size:255;not null"` // key name, e.g. "slave1."
	Algorithm string `gorm:"size:32;not null;default:hmac-sha256"`
	Secret    string `gorm:"size:255;not null"` // base64 HMAC secret
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (TSIGKey) TableName() string { return "tsig_keys" }

// ZoneSlave is one entry in a zone's transfer ACL: a slave permitted to AXFR
// the zone (and receive NOTIFY), optionally authenticated with a TSIGKey. The
// backend turns these into Knot ACL rules + the catalog membership, so the
// listed slaves auto-provision and transfer the zone.
type ZoneSlave struct {
	ID        uint     `gorm:"primaryKey"`
	ZoneID    uint     `gorm:"index;not null"`
	Zone      Zone     `gorm:"foreignKey:ZoneID"`
	Address   string   `gorm:"size:64;not null"` // slave IP or CIDR
	TSIGKeyID *uint    `gorm:"index"`            // nil = IP-only ACL
	TSIGKey   *TSIGKey `gorm:"foreignKey:TSIGKeyID"`
	Notify    bool     `gorm:"not null;default:true"` // send NOTIFY to this slave
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (ZoneSlave) TableName() string { return "zone_slaves" }

// ── Authorization grants (PRD §9.3). ──

// GroupZoneRole grants L2 (full zone CRUD) to a group on a whole zone.
type GroupZoneRole struct {
	ID        uint           `gorm:"primaryKey"`
	GroupID   uint           `gorm:"not null;uniqueIndex:idx_gzr_group_zone"`
	Group     auth.GroupGORM `gorm:"foreignKey:GroupID"`
	ZoneID    uint           `gorm:"not null;uniqueIndex:idx_gzr_group_zone"`
	Zone      Zone           `gorm:"foreignKey:ZoneID"`
	Level     int            `gorm:"not null;default:2"` // 2 in v1
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (GroupZoneRole) TableName() string { return "group_zone_roles" }

// GroupRRRole grants L1 (read/update the A/AAAA set) to a group on a
// (zone, label). Level is implicitly 1.
type GroupRRRole struct {
	ID        uint           `gorm:"primaryKey"`
	GroupID   uint           `gorm:"not null;uniqueIndex:idx_grr_group_zone_label"`
	Group     auth.GroupGORM `gorm:"foreignKey:GroupID"`
	ZoneID    uint           `gorm:"not null;uniqueIndex:idx_grr_group_zone_label"`
	Zone      Zone           `gorm:"foreignKey:ZoneID"`
	Label     string         `gorm:"size:63;uniqueIndex:idx_grr_group_zone_label"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (GroupRRRole) TableName() string { return "group_rr_roles" }

// MigrateDNS auto-migrates the DNS schema. Call after the auth tables exist
// (NewAuthGORM) since Zone/roles carry FKs into auth_users / auth_groups.
func MigrateDNS(db *gorm.DB) error {
	return db.AutoMigrate(
		&Zone{}, &TSIGKey{}, &ZoneSlave{},
		&RRA{}, &RRAAAA{}, &RRNS{}, &RRPTR{}, &RRCNAME{}, &RRTXT{},
		&RRMX{}, &RRSRV{}, &RRCAA{}, &RRSSHFP{}, &RRTLSA{}, &RRDNSKEY{}, &RRDS{}, &RRNAPTR{},
		&GroupZoneRole{}, &GroupRRRole{},
	)
}
