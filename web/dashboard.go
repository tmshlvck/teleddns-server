package web

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"time"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/tmshlvck/gone/auth"
	"github.com/tmshlvck/gone/site"
	"gorm.io/gorm"

	"github.com/tmshlvck/teleddns-server/model"
)

// RegisterDashboard mounts the landing page at /dashboard: a server-state card
// (up + uptime) plus a few counts (zones, records, pending syncs). It is a
// placeholder for richer stats to land in a later milestone — for now it just
// confirms the server is alive and summarizes what's in the database.
func RegisterDashboard(mux chi.Router, ag *auth.AuthGORM, db *gorm.DB, shell site.Shell, started time.Time) {
	mux.Get("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		if ag.CurrentUser(r.Context()) == nil {
			http.Redirect(w, r, ag.LoginURL(r.URL.Path), http.StatusSeeOther)
			return
		}
		shell(w, r, "Dashboard", dashboardPage(collectStats(db, started)))
	})
}

// dashboardStats is the snapshot rendered on the dashboard.
type dashboardStats struct {
	Uptime  time.Duration
	Zones   int64
	Records int64
	Pending int64 // SyncTasks not yet completed
}

// collectStats gathers the dashboard snapshot. Count errors are swallowed —
// the dashboard is best-effort status, not an authoritative report.
func collectStats(db *gorm.DB, started time.Time) dashboardStats {
	s := dashboardStats{Uptime: time.Since(started)}
	db.Model(&model.Zone{}).Count(&s.Zones)
	for _, tbl := range []string{
		"rr_a", "rr_aaaa", "rr_ns", "rr_ptr", "rr_cname", "rr_txt",
		"rr_mx", "rr_srv", "rr_caa", "rr_sshfp", "rr_tlsa", "rr_dnskey", "rr_ds", "rr_naptr",
	} {
		var n int64
		db.Table(tbl).Count(&n)
		s.Records += n
	}
	db.Model(&model.SyncTask{}).Where("state <> ?", model.SyncDone).Count(&s.Pending)
	return s
}

func dashboardPage(s dashboardStats) templ.Component {
	return templ.ComponentFunc(func(_ context.Context, w io.Writer) error {
		fmt.Fprint(w, `<div class="max-w-6xl mx-auto flex flex-col gap-8">`)
		fmt.Fprint(w, `<section class="card bg-base-100 shadow-xl"><div class="card-body gap-3">`)
		fmt.Fprint(w, `<h2 class="card-title flex items-center gap-2">`+
			`<span class="inline-block w-3 h-3 rounded-full bg-success"></span>Server is up</h2>`)
		fmt.Fprintf(w, `<p class="text-sm opacity-70">Uptime: %s</p>`, html.EscapeString(fmtUptime(s.Uptime)))
		fmt.Fprint(w, `</div></section>`)

		fmt.Fprint(w, `<section class="flex flex-col gap-3">`)
		fmt.Fprint(w, `<h2 class="text-lg font-medium opacity-80">Statistics</h2>`)
		fmt.Fprint(w, `<div class="stats stats-vertical sm:stats-horizontal shadow bg-base-100">`)
		statBox(w, "Zones", s.Zones)
		statBox(w, "Records", s.Records)
		statBox(w, "Pending syncs", s.Pending)
		fmt.Fprint(w, `</div>`)
		fmt.Fprint(w, `<p class="text-xs opacity-50">More detailed statistics arrive in a later milestone.</p>`)
		fmt.Fprint(w, `</section></div>`)
		return nil
	})
}

func statBox(w io.Writer, title string, value int64) {
	fmt.Fprintf(w, `<div class="stat"><div class="stat-title">%s</div><div class="stat-value">%d</div></div>`,
		html.EscapeString(title), value)
}

// fmtUptime renders a duration as e.g. "3d 4h 12m" (or "5m 9s" when short),
// trimming leading zero units.
func fmtUptime(d time.Duration) string {
	d = d.Round(time.Second)
	days := int(d / (24 * time.Hour))
	d -= time.Duration(days) * 24 * time.Hour
	h := int(d / time.Hour)
	d -= time.Duration(h) * time.Hour
	m := int(d / time.Minute)
	sec := int((d - time.Duration(m)*time.Minute) / time.Second)
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh %dm", days, h, m)
	case h > 0:
		return fmt.Sprintf("%dh %dm", h, m)
	case m > 0:
		return fmt.Sprintf("%dm %ds", m, sec)
	default:
		return fmt.Sprintf("%ds", sec)
	}
}
