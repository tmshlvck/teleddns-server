package web

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"strings"

	"github.com/tmshlvck/gone/auth"
	"github.com/tmshlvck/gone/crud"
	"github.com/tmshlvck/gone/site"
	"gorm.io/gorm"

	"github.com/tmshlvck/teleddns-server/model"
)

// dnsTables builds the admin CRUDTables for the DNS data model (Server, Zone,
// the per-type RR tables, and the role grants). Each table's accessor is
// wrapped with an audit observer; relations (Zone.Owner, Zone.MasterServer,
// RR.Zone, role.Group/Zone) are auto-wired by DeriveAdmin against the other
// registered tables.
func dnsTables(db *gorm.DB, settings site.Settings, gate auth.Authz, log *slog.Logger, ag *auth.AuthGORM) []crud.CRUDTableInterface {
	tables := []crud.CRUDTableInterface{
		dnsTable[model.Server](db, settings, gate, log, ag, "Servers", "servers", []crud.MetaField{
			{Name: "APIKey", DisplayName: "API key", DisplayValue: crud.Redact,
				GenFormElement: crud.PasswordInput, BindStrings: keepSecretOnBlank, NoExport: true},
		}),
		dnsTable[model.Zone](db, settings, gate, log, ag, "Zones", "zones", []crud.MetaField{
			{Name: "Origin", FieldValidate: crud.All(crud.NotEmpty, model.ValFQDN),
				FormHelp: "FQDN with trailing dot, e.g. example.com."},
			{Name: "SOAMName", DisplayName: "SOA MNAME", FieldValidate: model.ValDNSName},
			{Name: "SOARName", DisplayName: "SOA RNAME", FieldValidate: model.ValDNSName},
			{Name: "ContentDirty", ReadOnly: true},
			{Name: "LastContentSync", ReadOnly: true},
			{Name: "LastUpdateInfo", Hidden: true},
		}),

		dnsTable[model.RRA](db, settings, gate, log, ag, "A", "rr-a",
			rrFields(crud.MetaField{Name: "Value", FieldValidate: crud.All(crud.NotEmpty, crud.IPv4Addr), FormHelp: "IPv4 address"})),
		dnsTable[model.RRAAAA](db, settings, gate, log, ag, "AAAA", "rr-aaaa",
			rrFields(crud.MetaField{Name: "Value", FieldValidate: crud.All(crud.NotEmpty, crud.IPv6Addr), FormHelp: "IPv6 address"})),
		dnsTable[model.RRNS](db, settings, gate, log, ag, "NS", "rr-ns",
			rrFields(crud.MetaField{Name: "Value", FieldValidate: crud.All(crud.NotEmpty, model.ValDNSName), FormHelp: "nameserver hostname"})),
		dnsTable[model.RRPTR](db, settings, gate, log, ag, "PTR", "rr-ptr",
			rrFields(crud.MetaField{Name: "Value", FieldValidate: crud.All(crud.NotEmpty, model.ValDNSName)})),
		dnsTable[model.RRCNAME](db, settings, gate, log, ag, "CNAME", "rr-cname",
			rrFields(crud.MetaField{Name: "Value", FieldValidate: crud.All(crud.NotEmpty, model.ValDNSName), FormHelp: "canonical hostname"})),
		dnsTable[model.RRTXT](db, settings, gate, log, ag, "TXT", "rr-txt",
			rrFields(crud.MetaField{Name: "Value", FieldValidate: crud.NotEmpty})),

		dnsTable[model.RRMX](db, settings, gate, log, ag, "MX", "rr-mx",
			rrFields(
				crud.MetaField{Name: "Priority", FieldValidate: crud.IntRange(0, 65535)},
				crud.MetaField{Name: "Value", FieldValidate: crud.All(crud.NotEmpty, model.ValDNSName), FormHelp: "mail exchanger hostname"})),
		dnsTable[model.RRSRV](db, settings, gate, log, ag, "SRV", "rr-srv",
			rrFields(
				crud.MetaField{Name: "Priority", FieldValidate: crud.IntRange(0, 65535)},
				crud.MetaField{Name: "Weight", FieldValidate: crud.IntRange(0, 65535)},
				crud.MetaField{Name: "Port", FieldValidate: crud.IntRange(0, 65535)},
				crud.MetaField{Name: "Value", FieldValidate: crud.All(crud.NotEmpty, model.ValDNSName), FormHelp: "target hostname"})),
		dnsTable[model.RRCAA](db, settings, gate, log, ag, "CAA", "rr-caa",
			rrFields(
				crud.MetaField{Name: "Flag", FieldValidate: crud.IntRange(0, 255)},
				crud.MetaField{Name: "Tag", FieldValidate: crud.All(crud.NotEmpty,
					model.OneOfString("issue", "issuewild", "iodef", "contactemail", "contactphone"))},
				crud.MetaField{Name: "Value", FieldValidate: crud.NotEmpty})),
		dnsTable[model.RRSSHFP](db, settings, gate, log, ag, "SSHFP", "rr-sshfp",
			rrFields(
				crud.MetaField{Name: "Algorithm", FieldValidate: crud.IntRange(1, 4)},
				crud.MetaField{Name: "HashType", FieldValidate: crud.IntRange(1, 2)},
				crud.MetaField{Name: "Fingerprint", FieldValidate: crud.NotEmpty})),
		dnsTable[model.RRTLSA](db, settings, gate, log, ag, "TLSA", "rr-tlsa",
			rrFields(
				crud.MetaField{Name: "CertUsage", FieldValidate: crud.IntRange(0, 3)},
				crud.MetaField{Name: "Selector", FieldValidate: crud.IntRange(0, 1)},
				crud.MetaField{Name: "MatchingType", FieldValidate: crud.IntRange(0, 2)},
				crud.MetaField{Name: "CertData", FieldValidate: crud.NotEmpty})),
		dnsTable[model.RRDNSKEY](db, settings, gate, log, ag, "DNSKEY", "rr-dnskey",
			rrFields(
				crud.MetaField{Name: "Flags", FieldValidate: crud.IntRange(0, 65535)},
				crud.MetaField{Name: "Protocol", FieldValidate: crud.IntRange(0, 255)},
				crud.MetaField{Name: "Algorithm", FieldValidate: crud.IntRange(0, 255)},
				crud.MetaField{Name: "PublicKey", FieldValidate: crud.NotEmpty})),
		dnsTable[model.RRDS](db, settings, gate, log, ag, "DS", "rr-ds",
			rrFields(
				crud.MetaField{Name: "KeyTag", FieldValidate: crud.IntRange(0, 65535)},
				crud.MetaField{Name: "Algorithm", FieldValidate: crud.IntRange(0, 255)},
				crud.MetaField{Name: "DigestType", FieldValidate: crud.IntRange(0, 255)},
				crud.MetaField{Name: "Digest", FieldValidate: crud.NotEmpty})),
		dnsTable[model.RRNAPTR](db, settings, gate, log, ag, "NAPTR", "rr-naptr",
			rrFields(
				crud.MetaField{Name: "Order", FieldValidate: crud.IntRange(0, 65535)},
				crud.MetaField{Name: "Preference", FieldValidate: crud.IntRange(0, 65535)},
				crud.MetaField{Name: "Replacement", FieldValidate: model.ValDNSName})),

		dnsTable[model.GroupZoneRole](db, settings, gate, log, ag, "Zone roles (L2)", "group-zone-roles", nil),
		dnsTable[model.GroupRRRole](db, settings, gate, log, ag, "RR roles (L1)", "group-rr-roles", []crud.MetaField{
			{Name: "Label", FieldValidate: model.ValLabel},
		}),
	}
	return tables
}

// rrFields returns the common RR field presets (Label validation + TTL help +
// hidden audit field) with the type-specific extra fields appended.
func rrFields(extra ...crud.MetaField) []crud.MetaField {
	out := []crud.MetaField{
		{Name: "Label", FieldValidate: crud.All(crud.NotEmpty, model.ValLabel), FormHelp: "@ for apex, or a hostname label"},
		{Name: "TTL", FormHelp: "seconds"},
	}
	out = append(out, extra...)
	out = append(out, crud.MetaField{Name: "LastUpdateInfo", Hidden: true})
	return out
}

// dnsTable builds one observe-wrapped admin CRUDTable[T].
func dnsTable[T any](db *gorm.DB, settings site.Settings, gate auth.Authz, log *slog.Logger, ag *auth.AuthGORM, display, segment string, fields []crud.MetaField) crud.CRUDTableInterface {
	mm := crud.DeriveMetaModel[T](crud.MetaModel[T]{DisplayName: display, Fields: fields})
	data := crud.ObserveAccessor(crud.GORMAccessor(mm, db), auditObserver[T](log, ag, mm.Name))
	tbl := crud.NewTable(mm, data, settings, gate)
	if segment != "" {
		tbl.Segment = segment
	}
	return &tbl
}

// auditObserver logs a structured audit line (source=ui) for each create/
// update/delete through the admin. Push scheduling (enqueue PendingPush) is
// added in M5.
func auditObserver[T any](log *slog.Logger, ag *auth.AuthGORM, typeName string) func(context.Context, crud.ChangeEvent[T]) {
	return func(ctx context.Context, e crud.ChangeEvent[T]) {
		log.Info("audit",
			"source", "ui",
			"action", e.Kind.String(),
			"type", typeName,
			"id", e.ID,
			"actor", ag.CurrentUsername(ctx),
		)
	}
}

// keepSecretOnBlank is a BindStrings hook for plaintext secrets (e.g. a
// backend API key): a blank submission leaves the stored value unchanged,
// a non-blank one overwrites it. Mirrors gone's HashWith keep-on-blank
// behaviour without hashing.
func keepSecretOnBlank(mf crud.MetaField, strs []string, instance any) error {
	var v string
	if len(strs) > 0 {
		v = strings.TrimSpace(strs[0])
	}
	if v == "" {
		return nil // leave unchanged
	}
	rv := reflect.ValueOf(instance)
	for rv.Kind() == reflect.Pointer {
		rv = rv.Elem()
	}
	f := rv.FieldByName(mf.Name)
	if !f.IsValid() || !f.CanSet() || f.Kind() != reflect.String {
		return fmt.Errorf("cannot set field %s", mf.Name)
	}
	f.SetString(strs[0])
	return nil
}
