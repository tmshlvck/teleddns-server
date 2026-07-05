// Command teleddns-server is the DNS management + DDNS server (Go rewrite).
//
// Usage:
//
//	teleddns-server [-config FILE] [-debug]                 # run the server
//	teleddns-server [-config FILE] admin reset-password USER [PASSWORD]
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	flag "github.com/spf13/pflag"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"

	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httplog/v3"
	"github.com/tmshlvck/gone/auth"
	"gorm.io/gorm"

	"github.com/tmshlvck/teleddns-server/api"
	"github.com/tmshlvck/teleddns-server/cfapi"
	"github.com/tmshlvck/teleddns-server/ddns"
	"github.com/tmshlvck/teleddns-server/knot"
	"github.com/tmshlvck/teleddns-server/metrics"
	"github.com/tmshlvck/teleddns-server/model"
	"github.com/tmshlvck/teleddns-server/web"
	"github.com/tmshlvck/teleddns-server/zoneimport"
)

func main() {
	var cfgPath string
	var debug bool
	flag.StringVarP(&cfgPath, "config", "c", "", "path to YAML config file")
	flag.BoolVarP(&debug, "debug", "d", false, "enable debug logging")
	// Stop global flag parsing at the first positional so subcommand flags
	// (e.g. `admin import --replace`) pass through to the subcommand's flagset.
	flag.CommandLine.SetInterspersed(false)
	flag.Parse()

	path := resolveConfigPath(cfgPath)
	cfg, err := model.Load(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}
	if debug {
		cfg.Debug = true
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}

	log := newLogger(cfg.Debug)
	if path != "" {
		log.Debug("loaded config file", "path", path)
	} else {
		log.Debug("no config file found, using built-in defaults")
	}

	if err := run(cfg, log, flag.Args()); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// run dispatches to a CLI subcommand or, with no args, serves.
func run(cfg model.Config, log *slog.Logger, args []string) error {
	db, err := model.OpenDB(cfg, log)
	if err != nil {
		return err
	}
	sm := scs.New()
	sm.Lifetime = 24 * time.Hour
	sm.Cookie.HttpOnly = true
	sm.Cookie.SameSite = http.SameSiteLaxMode

	ag, err := auth.NewAuthGORM(sm, db) // auto-migrates UserGORM + GroupGORM
	if err != nil {
		return fmt.Errorf("auth init: %w", err)
	}

	if len(args) > 0 {
		return runCLI(db, ag, log, args)
	}
	return serve(cfg, log, db, sm, ag)
}

func runCLI(db *gorm.DB, ag *auth.AuthGORM, log *slog.Logger, args []string) error {
	switch {
	case args[0] == "admin" && len(args) >= 3 && args[1] == "reset-password":
		username := args[2]
		var pw string
		if len(args) >= 4 {
			pw = args[3]
		} else {
			pw = randomPassword()
		}
		if err := ag.Passwd(username, pw); err != nil {
			return fmt.Errorf("reset-password %q: %w", username, err)
		}
		if len(args) < 4 {
			fmt.Printf("New password for %q: %s\n", username, pw)
		} else {
			fmt.Printf("Password for %q updated.\n", username)
		}
		return nil
	case args[0] == "admin" && len(args) >= 2 && args[1] == "import":
		return runImport(db, log, args[2:])
	default:
		return fmt.Errorf("unknown command: %v", args)
	}
}

// runImport implements `admin import [--origin FQDN] [--replace] <zonefile|->`:
// bulk-load a BIND zone file into the DB via the shared model write path.
func runImport(db *gorm.DB, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	origin := fs.String("origin", "", "zone origin FQDN (optional when the file has an SOA or $ORIGIN)")
	replace := fs.Bool("replace", false, "clear the zone's existing records before loading")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: admin import [--origin FQDN] [--replace] <zonefile|->")
	}
	if err := model.MigrateDNS(db); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	path := fs.Arg(0)
	r := io.Reader(os.Stdin)
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}

	sum, err := zoneimport.Import(db, r, path, *origin, *replace, log)
	if err != nil {
		return err
	}
	where := "into existing zone"
	switch {
	case sum.Created:
		where = "into new zone"
	case sum.Replaced:
		where = "replacing contents of zone"
	}
	fmt.Printf("Imported %d records %s %s (skipped %d unsupported, %d errors).\n",
		sum.Total(), where, sum.Origin, sum.Skipped, sum.Errors)
	for _, t := range []string{"NS", "A", "AAAA", "CNAME", "MX", "TXT", "PTR", "SRV", "CAA", "SSHFP", "TLSA", "DNSKEY", "DS", "NAPTR"} {
		if n := sum.Imported[t]; n > 0 {
			fmt.Printf("  %-7s %d\n", t, n)
		}
	}
	return nil
}

func serve(cfg model.Config, log *slog.Logger, db *gorm.DB, sm *scs.SessionManager, ag *auth.AuthGORM) error {
	if err := ensureAdmin(ag, log); err != nil {
		return err
	}

	shell := web.Shell{Auth: ag, Log: log}.Func()

	ks, err := model.NewKeyStore(db)
	if err != nil {
		return fmt.Errorf("api keys init: %w", err)
	}
	if err := model.MigrateDNS(db); err != nil {
		return fmt.Errorf("dns migrate: %w", err)
	}

	// Backend + sync worker. Created here so /healthcheck can read worker
	// liveness + the knot-status probe; started (go worker.Run) once the signal
	// ctx exists below.
	worker := &knot.Worker{
		DB:         db,
		Backend:    knot.NewBackend(cfg, log),
		Log:        log,
		Interval:   cfg.BackendSyncDelay,
		DefaultTTL: cfg.DefaultTTL,
	}
	// DB-derived /metrics gauges (zones, records, pending pushes), per scrape.
	metrics.RegisterStats(func() metrics.Snapshot {
		s := model.CountStats(db)
		rec := make(map[string]float64, len(s.RecordsByType))
		for t, n := range s.RecordsByType {
			rec[t] = float64(n)
		}
		pend := make(map[string]float64, len(s.PendingByState))
		for st, n := range s.PendingByState {
			pend[st] = float64(n)
		}
		return metrics.Snapshot{Zones: float64(s.Zones), RecordsByType: rec, PendingByState: pend}
	})

	root := chi.NewRouter()
	// Log every request (success at INFO, 4xx/5xx at WARN). ECS-concise trims
	// the field wall but also drops the client IP — re-add it under "src" so
	// auth failures and DDNS calls are always traceable to a source. The
	// monitoring polls (/healthcheck, /metrics) are skipped to keep them from
	// flooding the log.
	reqSchema := httplog.SchemaECS.Concise(true)
	reqSchema.RequestRemoteIP = "src"
	root.Use(httplog.RequestLogger(log, &httplog.Options{
		Level:         slog.LevelInfo,
		Schema:        reqSchema,
		RecoverPanics: true,
		Skip: func(r *http.Request, _ int) bool {
			return r.URL.Path == "/healthcheck" || r.URL.Path == "/metrics"
		},
	}))
	if cfg.TrustProxy {
		root.Use(middleware.RealIP)
	}
	root.Use(web.IPAllowlist(cfg.AllowedIPs, log))

	// Idempotency-Key replay for /api POSTs (PRD §11.1). Guarded internally, so
	// it no-ops for every other route. Registered before routes (chi requires
	// middleware to precede route registration).
	idem, err := api.NewIdempotencyStore(db)
	if err != nil {
		return fmt.Errorf("idempotency store: %w", err)
	}
	root.Use(idem.Middleware)

	// Operability endpoints — additionally gated by ops_allowed_ips (evaluated
	// after RealIP, so it works behind Caddy). Empty list = no extra restriction
	// beyond the global allowlist.
	root.Group(func(r chi.Router) {
		r.Use(web.IPAllowlist(cfg.OpsAllowedIPs, log))
		r.Get("/healthcheck", healthcheck(cfg, db, worker, startedAt))
		r.Handle("/metrics", metrics.Handler())
	})

	// Token/credential surfaces — no cookie session, so no CSRF. The DDNS
	// endpoints carry their own Basic/Bearer auth.
	ddns.New(db, ag, ks, log, cfg).RegisterRoutes(root)

	// Cloudflare-compatible record facade (/client/v4), for cert-manager +
	// external-dns. Bearer/X-Auth-Key auth via the shared KeyStore.
	(&cfapi.Deps{DB: db, Keys: ks, Log: log, DefaultTTL: cfg.DefaultTTL}).RegisterRoutes(root)

	// Huma API: serves /openapi.json + /docs, the chi-served DDNS endpoints'
	// documentation, and the M6 management/record operations (zones + RR).
	hcfg := huma.DefaultConfig("teleddns-server", "0.1.0")
	hcfg.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		"basic":  {Type: "http", Scheme: "basic"},
		"bearer": {Type: "http", Scheme: "bearer"},
	}
	humaAPI := humachi.New(root, hcfg)
	ddns.DocumentOpenAPI(humaAPI)
	api.Register(humaAPI, &api.Deps{DB: db, Keys: ks, Log: log, DefaultTTL: cfg.DefaultTTL})
	root.Get("/swagger", web.SwaggerHandler("/openapi.json")) // public, like the spec

	// Browser surfaces — cookie sessions + CSRF on mutating requests.
	var regErr error
	root.Group(func(r chi.Router) {
		r.Use(auth.CSRFWrap(sm))
		if regErr = web.RegisterAdmin(r, ag, db, cfg, log, shell); regErr != nil {
			return
		}
		web.RegisterPreferences(r, ag, ks, shell)
		web.RegisterDashboard(r, ag, db, shell, startedAt)
		r.Get("/", func(w http.ResponseWriter, req *http.Request) {
			http.Redirect(w, req, "/dashboard", http.StatusSeeOther)
		})
	})
	if regErr != nil {
		return regErr
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Backend-sync worker: drains the SyncTask journal → renders + pushes zones,
	// and stamps liveness + the knot-status probe each tick (for /healthcheck).
	go worker.Run(ctx)

	srv := &http.Server{Addr: cfg.ListenAddr, Handler: sm.LoadAndSave(root)}
	return listenAndServe(ctx, srv, log)
}

var startedAt = time.Now()

// healthcheck implements PRD §11.5. It always returns HTTP 200; OK vs WARN is
// the body's first token. Health means "can we serve + replicate", not "did
// clients send updates" — zero updates is healthy. Past a startup grace
// (2×BackendSyncPeriod), it WARNs when the sync worker has stalled, any sync
// task is dead-lettered, the push backlog is stuck (oldest unfinished task
// older than WarnOnNoPush), or the knot backend's status probe fails.
func healthcheck(cfg model.Config, db *gorm.DB, worker *knot.Worker, started time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		uptime := now.Sub(started)
		grace := 2 * cfg.BackendSyncPeriod

		s := model.CountStats(db)
		var records int64
		for _, n := range s.RecordsByType {
			records += n
		}
		pending := s.PendingByState[model.SyncPending] + s.PendingByState[model.SyncInFlight]
		failed := s.PendingByState[model.SyncFailed]

		// Worker liveness: no tick within the grace window ⇒ stalled/dead.
		lastTick := worker.LastTick()
		workerStalled := uptime > grace && (lastTick.IsZero() || now.Sub(lastTick) > grace)

		// Push backlog stuck: the oldest unfinished task is older than the bound.
		backlogStuck := false
		if cfg.WarnOnNoPush > 0 {
			var oldest []time.Time
			db.Model(&model.SyncTask{}).
				Where("state IN ?", []string{model.SyncPending, model.SyncInFlight}).
				Order("enqueued_at").Limit(1).Pluck("enqueued_at", &oldest)
			if len(oldest) > 0 {
				backlogStuck = now.Sub(oldest[0]) > cfg.WarnOnNoPush
			}
		}

		// Knot reachability (only meaningful for the knot backend).
		knot := "na"
		knotDown := false
		if cfg.Backend == "knot" {
			if worker.KnotUp() {
				knot = "up"
			} else {
				knot = "down"
				knotDown = uptime > grace // give Knot time to come up after boot
			}
		}

		// last_push: the most recent successfully-drained task.
		var lastPush int64
		var done []time.Time
		db.Model(&model.SyncTask{}).Where("state = ?", model.SyncDone).
			Order("last_attempt DESC").Limit(1).Pluck("last_attempt", &done)
		if len(done) > 0 && !done[0].IsZero() {
			lastPush = done[0].Unix()
		}

		status := "OK"
		if workerStalled || failed > 0 || backlogStuck || knotDown {
			status = "WARN"
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "%s uptime=%d zones=%d records=%d pending=%d failed=%d knot=%s last_push=%d\n",
			status, int(uptime.Seconds()), s.Zones, records, pending, failed, knot, lastPush)
	}
}

// resolveConfigPath picks the config file to load when -config/-c is not
// given: $TELEDDNS_CONFIG, then ./config.yaml, then the system path. Returns
// "" when none exists (built-in defaults apply).
func resolveConfigPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if v := os.Getenv("TELEDDNS_CONFIG"); v != "" {
		return v
	}
	for _, p := range []string{"config.yaml", "/etc/teleddns-server/config.yaml"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// ensureAdmin seeds an "admin" group and an admin user on first run so the
// operator can log in. It first checks whether any user exists: if so, the
// database is already set up and seeding is skipped silently (no failing
// INSERTs, no constraint-error log noise). The generated password is printed
// once, via the logger, at WARN.
func ensureAdmin(ag *auth.AuthGORM, log *slog.Logger) error {
	var n int64
	if err := ag.DB.Model(&auth.UserGORM{}).Count(&n).Error; err != nil {
		return fmt.Errorf("count users: %w", err)
	}
	if n > 0 {
		log.Debug("users already present, admin seed skipped", "count", n)
		return nil
	}
	if err := ag.GroupAdd("admin"); err != nil {
		return fmt.Errorf("create admin group: %w", err)
	}
	pw := randomPassword()
	if err := ag.UserAdd("admin", "admin@localhost", pw); err != nil {
		return fmt.Errorf("create admin user: %w", err)
	}
	if err := ag.UserMod("admin", []string{"admin"}); err != nil {
		return err
	}
	log.Warn("seeded initial admin user", "username", "admin", "password", pw)
	return nil
}

func listenAndServe(ctx context.Context, srv *http.Server, log *slog.Logger) error {
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(sctx)
	}
}

func newLogger(debug bool) *slog.Logger {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}
	// Under systemd, journald already timestamps every captured line, so the
	// slog time attr is redundant noise in `journalctl`. systemd sets
	// JOURNAL_STREAM when stdout/stderr is wired to the journal — detect that
	// and drop the top-level time attr.
	if os.Getenv("JOURNAL_STREAM") != "" {
		opts.ReplaceAttr = func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		}
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

func randomPassword() string {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
