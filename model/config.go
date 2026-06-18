package model

import (
	"fmt"
	"os"
	"time"

	"github.com/tmshlvck/gone/site"
	"gopkg.in/yaml.v3"
)

// SlaveServer is a peer teleddns-server we replicate every zone to. Slaves
// are configured globally (not per-zone) — see PLAN.md §1. The peer is driven
// through its own management/record API with a bearer token.
type SlaveServer struct {
	Name    string `yaml:"name"`
	BaseURL string `yaml:"base_url"`
	Token   string `yaml:"token"`
}

// Config is the app-global configuration. It also satisfies gone's
// site.Settings interface (TimeFormatter + PaginationSettings) by embedding
// site.DefaultSettings and overriding the page-size default, so the same
// object can be handed to gone CRUD tables.
//
// Load order (lowest → highest precedence): Defaults() → YAML file → env →
// flags (applied by the caller in cmd/).
type Config struct {
	// DBDSN selects engine + location: "sqlite:///var/lib/teleddns/db.sqlite"
	// or "postgres://user:pass@host/db?sslmode=disable". Engine is inferred
	// from the scheme (see OpenDB).
	DBDSN string `yaml:"db_dsn"`

	ListenAddr string   `yaml:"listen_addr"` // e.g. ":8080"
	AllowedIPs []string `yaml:"allowed_ips"` // CIDRs allowed to connect; empty = all
	TrustProxy bool     `yaml:"trust_proxy"` // honor X-Forwarded-For / X-Real-IP / X-Forwarded-Proto

	SlaveServers []SlaveServer `yaml:"slave_servers"`

	DefaultTTL uint32 `yaml:"default_ttl"` // TTL for $TTL + API-created RRs (PRD §5)
	DDNSRRTTL  uint32 `yaml:"ddns_rr_ttl"` // TTL for A/AAAA touched via DDNS (PRD §5)

	BackendSyncDelay  time.Duration `yaml:"backend_sync_delay"`  // debounce window
	BackendSyncPeriod time.Duration `yaml:"backend_sync_period"` // safety-net sweep
	WarnOnNoUpdate    time.Duration `yaml:"warn_on_noupdate"`    // healthcheck WARN threshold
	WarnOnNoPush      time.Duration `yaml:"warn_on_nopush"`      // healthcheck WARN threshold

	Debug bool `yaml:"debug"`

	// Presentation defaults for gone components. Embedding gives a free
	// TimeFormatter; PaginationSizeDefault is overridden below to 50 (PRD §11.1).
	site.DefaultSettings `yaml:"-"`
}

// PaginationSizeDefault overrides gone's 20-row default to the PRD §11.1
// default page size of 50.
func (Config) PaginationSizeDefault() uint16 { return 50 }

// Defaults returns a Config populated with the PRD's operational defaults.
func Defaults() Config {
	return Config{
		DBDSN:             "sqlite://teleddns.sqlite",
		ListenAddr:        ":8080",
		TrustProxy:        false,
		DefaultTTL:        3600,
		DDNSRRTTL:         60,
		BackendSyncDelay:  10 * time.Second,
		BackendSyncPeriod: 300 * time.Second,
		WarnOnNoUpdate:    7200 * time.Second,
		WarnOnNoPush:      3600 * time.Second,
	}
}

// Load returns Defaults() merged with the YAML file at path (if path != "")
// and then with environment overrides. Flags are applied by the caller after
// Load so they win.
func Load(path string) (Config, error) {
	cfg := Defaults()
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("read config %q: %w", path, err)
		}
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			return cfg, fmt.Errorf("parse config %q: %w", path, err)
		}
	}
	applyEnv(&cfg)
	return cfg, nil
}

// applyEnv overrides selected fields from TELEDDNS_* environment variables.
// Kept deliberately small — the YAML file is the primary config surface.
func applyEnv(cfg *Config) {
	if v := os.Getenv("TELEDDNS_DB_DSN"); v != "" {
		cfg.DBDSN = v
	}
	if v := os.Getenv("TELEDDNS_LISTEN_ADDR"); v != "" {
		cfg.ListenAddr = v
	}
	if _, ok := os.LookupEnv("TELEDDNS_DEBUG"); ok {
		cfg.Debug = true
	}
}

// Validate checks that required fields are coherent before the server boots.
func (c Config) Validate() error {
	if c.DBDSN == "" {
		return fmt.Errorf("db_dsn is required")
	}
	if c.ListenAddr == "" {
		return fmt.Errorf("listen_addr is required")
	}
	return nil
}
