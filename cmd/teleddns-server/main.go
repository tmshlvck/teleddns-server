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
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httplog/v3"
	"github.com/tmshlvck/gone/auth"
	"github.com/tmshlvck/gone/site"
	"gorm.io/gorm"

	"github.com/tmshlvck/teleddns-server/model"
	"github.com/tmshlvck/teleddns-server/web"
)

func main() {
	var cfgPath string
	var debug bool
	flag.StringVar(&cfgPath, "config", "", "path to YAML config file")
	flag.StringVar(&cfgPath, "c", "", "path to YAML config file (shorthand)")
	flag.BoolVar(&debug, "debug", false, "enable debug logging")
	flag.BoolVar(&debug, "d", false, "enable debug logging (shorthand)")
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
		return runCLI(ag, log, args)
	}
	return serve(cfg, log, db, sm, ag)
}

func runCLI(ag *auth.AuthGORM, log *slog.Logger, args []string) error {
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
	default:
		return fmt.Errorf("unknown command: %v", args)
	}
}

func serve(cfg model.Config, log *slog.Logger, db *gorm.DB, sm *scs.SessionManager, ag *auth.AuthGORM) error {
	if err := ensureAdmin(ag, log); err != nil {
		return err
	}

	shell := web.Shell{Auth: ag, Log: log}.Func()

	mux := chi.NewRouter()
	mux.Use(httplog.RequestLogger(log, &httplog.Options{
		Level:         slog.LevelInfo,
		Schema:        httplog.SchemaECS.Concise(true), // trim the ECS field wall
		RecoverPanics: true,
		Skip:          func(_ *http.Request, status int) bool { return status == http.StatusNotFound },
	}))
	if cfg.TrustProxy {
		mux.Use(middleware.RealIP)
	}
	mux.Use(web.IPAllowlist(cfg.AllowedIPs))

	mux.Get("/healthcheck", healthcheck(cfg, startedAt))

	if err := web.RegisterAdmin(mux, ag, db, cfg, shell); err != nil {
		return err
	}
	registerPreferences(mux, ag, shell)
	mux.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
	})

	handler := sm.LoadAndSave(auth.CSRFWrap(sm)(mux))
	srv := &http.Server{Addr: cfg.ListenAddr, Handler: handler}

	return listenAndServe(srv, log)
}

// registerPreferences mounts the self-service account page composing gone's
// account-security cards. The API-keys card is added in a later milestone.
func registerPreferences(mux chi.Router, ag *auth.AuthGORM, shell site.Shell) {
	mux.Get("/preferences", func(w http.ResponseWriter, r *http.Request) {
		cards, target, res := ag.AccountSection(r)
		switch res {
		case auth.AccountAnonymous:
			http.Redirect(w, r, ag.LoginURL(r.URL.Path), http.StatusSeeOther)
			return
		case auth.AccountForbidden:
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		case auth.AccountNotFound:
			http.NotFound(w, r)
			return
		}
		shell(w, r, "Preferences — "+target.Username, cards)
	})
}

var startedAt = time.Now()

// healthcheck implements PRD §11.5 (OK/WARN with uptime + thresholds). The
// last_update / last_push timestamps are zero until the sync loop lands (M5).
func healthcheck(cfg model.Config, started time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uptime := time.Since(started)
		status := "OK"
		// WARN logic activates once the sync loop reports real timestamps.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "%s uptime=%d last_update=0 last_push=0\n", status, int(uptime.Seconds()))
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

func listenAndServe(srv *http.Server, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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
