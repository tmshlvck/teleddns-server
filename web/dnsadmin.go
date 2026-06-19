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

// dnsTables builds the DNS portion of the admin sidebar (gone 0.1.1: one
// ordered list of elements). It returns the Zone/TSIG/ACL tables, the 14
// per-type RR tables, and the role grants, grouped under Headers. Each table's
// accessor is wrapped with an audit observer; relations (RR.Zone,
// ZoneSlave.Zone/TSIGKey, role.Group/Zone, Zone.Owner) are auto-wired by
// DeriveAdmin against the other registered tables.
func dnsTables(db *gorm.DB, settings site.Settings, gate auth.Authz, log *slog.Logger, ag *auth.AuthGORM) []crud.SidebarElementInterface {
	t := func(table crud.CRUDTableInterface) crud.SidebarElementInterface { return table }

	return []crud.SidebarElementInterface{
		crud.Separator(), crud.Header("DNS"),
		t(dnsTable[model.Zone](db, settings, gate, log, ag, "Zones", []crud.MetaField{
			{Name: "Origin", FieldValidate: crud.All(crud.NotEmpty, model.ValFQDN),
				FormHelp: "FQDN with trailing dot, e.g. example.com."},
			{Name: "SOAMName", DisplayName: "SOA MNAME", FieldValidate: model.ValDNSName},
			{Name: "SOARName", DisplayName: "SOA RNAME", FieldValidate: model.ValDNSName},
			{Name: "ContentDirty", ReadOnly: true},
			{Name: "LastContentSync", ReadOnly: true},
			{Name: "LastUpdateInfo", Hidden: true},
		})),
		t(dnsTable[model.TSIGKey](db, settings, gate, log, ag, "TSIG keys", []crud.MetaField{
			{Name: "Name", FieldValidate: crud.NotEmpty, FormHelp: "key name, e.g. slave1."},
			{Name: "Secret", DisplayValue: crud.Redact, GenFormElement: crud.PasswordInput,
				BindStrings: keepSecretOnBlank, NoExport: true, FormHelp: "base64 HMAC secret"},
		})),
		t(dnsTable[model.ZoneSlave](db, settings, gate, log, ag, "Slave ACLs", []crud.MetaField{
			{Name: "Address", FieldValidate: crud.NotEmpty, FormHelp: "slave IP or CIDR"},
		})),

		crud.Separator(), crud.Header("Records"),
		t(dnsTable[model.RRA](db, settings, gate, log, ag, "A",
			rrFields(crud.MetaField{Name: "Value", FieldValidate: crud.All(crud.NotEmpty, crud.IPv4Addr), FormHelp: "IPv4 address"}))),
		t(dnsTable[model.RRAAAA](db, settings, gate, log, ag, "AAAA",
			rrFields(crud.MetaField{Name: "Value", FieldValidate: crud.All(crud.NotEmpty, crud.IPv6Addr), FormHelp: "IPv6 address"}))),
		t(dnsTable[model.RRNS](db, settings, gate, log, ag, "NS",
			rrFields(crud.MetaField{Name: "Value", FieldValidate: crud.All(crud.NotEmpty, model.ValDNSName), FormHelp: "nameserver hostname"}))),
		t(dnsTable[model.RRPTR](db, settings, gate, log, ag, "PTR",
			rrFields(crud.MetaField{Name: "Value", FieldValidate: crud.All(crud.NotEmpty, model.ValDNSName)}))),
		t(dnsTable[model.RRCNAME](db, settings, gate, log, ag, "CNAME",
			rrFields(crud.MetaField{Name: "Value", FieldValidate: crud.All(crud.NotEmpty, model.ValDNSName), FormHelp: "canonical hostname"}))),
		t(dnsTable[model.RRTXT](db, settings, gate, log, ag, "TXT",
			rrFields(crud.MetaField{Name: "Value", FieldValidate: crud.NotEmpty}))),
		t(dnsTable[model.RRMX](db, settings, gate, log, ag, "MX",
			rrFields(
				crud.MetaField{Name: "Priority", FieldValidate: crud.IntRange(0, 65535)},
				crud.MetaField{Name: "Value", FieldValidate: crud.All(crud.NotEmpty, model.ValDNSName), FormHelp: "mail exchanger hostname"}))),
		t(dnsTable[model.RRSRV](db, settings, gate, log, ag, "SRV",
			rrFields(
				crud.MetaField{Name: "Priority", FieldValidate: crud.IntRange(0, 65535)},
				crud.MetaField{Name: "Weight", FieldValidate: crud.IntRange(0, 65535)},
				crud.MetaField{Name: "Port", FieldValidate: crud.IntRange(0, 65535)},
				crud.MetaField{Name: "Value", FieldValidate: crud.All(crud.NotEmpty, model.ValDNSName), FormHelp: "target hostname"}))),
		t(dnsTable[model.RRCAA](db, settings, gate, log, ag, "CAA",
			rrFields(
				crud.MetaField{Name: "Flag", FieldValidate: crud.IntRange(0, 255)},
				crud.MetaField{Name: "Tag", FieldValidate: crud.All(crud.NotEmpty,
					model.OneOfString("issue", "issuewild", "iodef", "contactemail", "contactphone"))},
				crud.MetaField{Name: "Value", FieldValidate: crud.NotEmpty}))),
		t(dnsTable[model.RRSSHFP](db, settings, gate, log, ag, "SSHFP",
			rrFields(
				crud.MetaField{Name: "Algorithm", FieldValidate: crud.IntRange(1, 4)},
				crud.MetaField{Name: "HashType", FieldValidate: crud.IntRange(1, 2)},
				crud.MetaField{Name: "Fingerprint", FieldValidate: crud.NotEmpty}))),
		t(dnsTable[model.RRTLSA](db, settings, gate, log, ag, "TLSA",
			rrFields(
				crud.MetaField{Name: "CertUsage", FieldValidate: crud.IntRange(0, 3)},
				crud.MetaField{Name: "Selector", FieldValidate: crud.IntRange(0, 1)},
				crud.MetaField{Name: "MatchingType", FieldValidate: crud.IntRange(0, 2)},
				crud.MetaField{Name: "CertData", FieldValidate: crud.NotEmpty}))),
		t(dnsTable[model.RRDNSKEY](db, settings, gate, log, ag, "DNSKEY",
			rrFields(
				crud.MetaField{Name: "Flags", FieldValidate: crud.IntRange(0, 65535)},
				crud.MetaField{Name: "Protocol", FieldValidate: crud.IntRange(0, 255)},
				crud.MetaField{Name: "Algorithm", FieldValidate: crud.IntRange(0, 255)},
				crud.MetaField{Name: "PublicKey", FieldValidate: crud.NotEmpty}))),
		t(dnsTable[model.RRDS](db, settings, gate, log, ag, "DS",
			rrFields(
				crud.MetaField{Name: "KeyTag", FieldValidate: crud.IntRange(0, 65535)},
				crud.MetaField{Name: "Algorithm", FieldValidate: crud.IntRange(0, 255)},
				crud.MetaField{Name: "DigestType", FieldValidate: crud.IntRange(0, 255)},
				crud.MetaField{Name: "Digest", FieldValidate: crud.NotEmpty}))),
		t(dnsTable[model.RRNAPTR](db, settings, gate, log, ag, "NAPTR",
			rrFields(
				crud.MetaField{Name: "Order", FieldValidate: crud.IntRange(0, 65535)},
				crud.MetaField{Name: "Preference", FieldValidate: crud.IntRange(0, 65535)},
				crud.MetaField{Name: "Replacement", FieldValidate: model.ValDNSName}))),

		crud.Separator(), crud.Header("Access"),
		t(dnsTable[model.GroupZoneRole](db, settings, gate, log, ag, "Zone roles (L2)", nil)),
		t(dnsTable[model.GroupRRRole](db, settings, gate, log, ag, "RR roles (L1)", []crud.MetaField{
			{Name: "Label", FieldValidate: model.ValLabel},
		})),
	}
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

// dnsTable builds one observe-wrapped admin CRUDTable[T]. The URL slug is
// derived by gone from the Go type name (lowercase+"s"); the sidebar label is
// the DisplayName passed here.
func dnsTable[T any](db *gorm.DB, settings site.Settings, gate auth.Authz, log *slog.Logger, ag *auth.AuthGORM, display string, fields []crud.MetaField) crud.CRUDTableInterface {
	mm := crud.DeriveMetaModel[T](crud.MetaModel[T]{DisplayName: display, Fields: fields})
	data := crud.ObserveAccessor(crud.GORMAccessor(mm, db), auditObserver[T](log, ag, mm.Name))
	tbl := crud.NewTable(mm, data, settings, gate)
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

// keepSecretOnBlank is a BindStrings hook for plaintext secrets (e.g. a TSIG
// key secret): a blank submission leaves the stored value unchanged, a
// non-blank one overwrites it. Mirrors gone's HashWith keep-on-blank
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
