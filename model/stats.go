package model

import "gorm.io/gorm"

// Stats is a point-in-time count snapshot for the /metrics gauges (PRD §11.5).
// Counts are cheap COUNT(*) queries run per scrape, so the gauges never go
// stale.
type Stats struct {
	Zones          int64
	RecordsByType  map[string]int64 // RR type name → row count
	PendingByState map[string]int64 // sync-task state → row count
}

// rrTypeTables maps each RR type's metric label to its table, for per-type
// record counts. Mirrors the tables in appModels (see migrate.go).
var rrTypeTables = []struct{ name, table string }{
	{"A", "rr_a"}, {"AAAA", "rr_aaaa"}, {"NS", "rr_ns"}, {"PTR", "rr_ptr"},
	{"CNAME", "rr_cname"}, {"TXT", "rr_txt"}, {"MX", "rr_mx"}, {"SRV", "rr_srv"},
	{"CAA", "rr_caa"}, {"SSHFP", "rr_sshfp"}, {"TLSA", "rr_tlsa"},
	{"DNSKEY", "rr_dnskey"}, {"DS", "rr_ds"}, {"NAPTR", "rr_naptr"},
}

// CountStats returns the zone count, per-type record counts, and the
// outstanding sync-task counts by state. Only the live sync states are reported
// (done rows are journal history, not a gauge); the three are always present so
// the series exist even at zero.
func CountStats(db *gorm.DB) Stats {
	s := Stats{
		RecordsByType:  make(map[string]int64, len(rrTypeTables)),
		PendingByState: map[string]int64{SyncPending: 0, SyncInFlight: 0, SyncFailed: 0},
	}
	db.Model(&Zone{}).Count(&s.Zones)
	for _, rt := range rrTypeTables {
		var n int64
		db.Table(rt.table).Count(&n)
		s.RecordsByType[rt.name] = n
	}
	var rows []struct {
		State string
		N     int64
	}
	db.Model(&SyncTask{}).
		Select("state, count(*) as n").
		Where("state IN ?", []string{SyncPending, SyncInFlight, SyncFailed}).
		Group("state").Scan(&rows)
	for _, r := range rows {
		s.PendingByState[r.State] = r.N
	}
	return s
}
