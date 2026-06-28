package model

import (
	"fmt"
	"os"
	"time"

	"github.com/tmshlvck/gone/site"
	"gopkg.in/yaml.v3"
)

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
	// OpsAllowedIPs additionally restricts /healthcheck + /metrics to these
	// CIDRs (PRD §11.5). Empty = no extra restriction beyond AllowedIPs.
	// Evaluated after the proxy real-IP rewrite, so it works behind Caddy.
	OpsAllowedIPs []string `yaml:"ops_allowed_ips"`
	TrustProxy    bool     `yaml:"trust_proxy"` // honor X-Forwarded-For / X-Real-IP / X-Forwarded-Proto

	// Backend. The local Knot serves master zones; slaves AXFR a Knot-generated
	// catalog zone (RFC 9432) authenticated with TSIG. The catalog, the
	// transfer ACL and the TSIG keys live in the operator's base knot.conf (in
	// a template); teleddns only declares zones as members of that template via
	// `knotc conf-set` and pushes zone content. So no slave/TSIG config here.
	Backend      string `yaml:"backend"`       // "log" (default, no-op) | "knot"
	KnotZoneDir  string `yaml:"knot_zone_dir"` // dir for generated .zone files (knot backend)
	KnotcPath    string `yaml:"knotc_path"`    // knotc binary (default "knotc")
	KnotTemplate string `yaml:"knot_template"` // knot.conf template assigned to managed zones (default "master")

	DefaultTTL uint32 `yaml:"default_ttl"` // TTL for $TTL + API-created RRs (PRD §5)
	DDNSRRTTL  uint32 `yaml:"ddns_rr_ttl"` // TTL for A/AAAA touched via DDNS (PRD §5)

	DDNSRatePerRecord uint `yaml:"ddns_rate_per_record"` // updates/hour per (user,hostname) (PRD §8.8)
	DDNSRatePerToken  uint `yaml:"ddns_rate_per_token"`  // updates/hour per token (PRD §8.8)

	BackendSyncDelay  time.Duration `yaml:"backend_sync_delay"`  // worker tick / debounce window
	BackendSyncPeriod time.Duration `yaml:"backend_sync_period"` // worker-liveness reference for healthcheck
	// WarnOnNoPush is the healthcheck WARN threshold for a stuck push backlog:
	// WARN when the oldest unfinished sync task is older than this. Absence of
	// updates is NOT a fault, so there is no no-update threshold (PRD §11.5).
	WarnOnNoPush time.Duration `yaml:"warn_on_nopush"`

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
		Backend:           "log",
		KnotcPath:         "knotc",
		KnotTemplate:      "master",
		DefaultTTL:        3600,
		DDNSRRTTL:         60,
		DDNSRatePerRecord: 60,
		DDNSRatePerToken:  600,
		BackendSyncDelay:  10 * time.Second,
		BackendSyncPeriod: 300 * time.Second,
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
