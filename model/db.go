package model

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/glebarez/sqlite"
	"github.com/tmshlvck/gone/site"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// OpenDB opens the GORM database selected by cfg.DBDSN. The scheme picks the
// engine:
//
//	sqlite://<path>      → pure-Go SQLite (glebarez)
//	postgres://<dsn...>  → Postgres (dsn passed through verbatim)
//
// time.Time is forced to UTC storage on every backend via site.ForceUTC so
// SQL sort/range filters operate on the instant (PRD audit + gone CRUD rely
// on this).
func OpenDB(cfg Config, log *slog.Logger) (*gorm.DB, error) {
	gcfg := &gorm.Config{Logger: newGormLogger(log, cfg.Debug)}

	var (
		db  *gorm.DB
		err error
	)
	switch {
	case strings.HasPrefix(cfg.DBDSN, "sqlite://"):
		path := strings.TrimPrefix(cfg.DBDSN, "sqlite://")
		db, err = gorm.Open(sqlite.Open(path), gcfg)
	case strings.HasPrefix(cfg.DBDSN, "postgres://") || strings.HasPrefix(cfg.DBDSN, "postgresql://"):
		db, err = gorm.Open(postgres.Open(cfg.DBDSN), gcfg)
	default:
		return nil, fmt.Errorf("unsupported db_dsn scheme in %q (want sqlite:// or postgres://)", cfg.DBDSN)
	}
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := site.ForceUTC(db); err != nil {
		return nil, fmt.Errorf("force utc: %w", err)
	}
	return db, nil
}
