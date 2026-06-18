package model

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// gormSlog routes GORM's logging through the application's *slog.Logger, so DB
// logs share the app's format and respect the journald time-stripping. Every
// line carries component=gorm. SQL traces are emitted at slog DEBUG (visible
// only with --debug), slow queries at WARN, and real errors at ERROR
// (record-not-found is ignored — it's a normal control-flow signal).
type gormSlog struct {
	log           *slog.Logger
	level         logger.LogLevel
	slowThreshold time.Duration
}

// newGormLogger builds a GORM logger backed by log. With debug it logs at GORM
// Info (every statement); otherwise Warn (slow queries + errors only).
func newGormLogger(log *slog.Logger, debug bool) logger.Interface {
	lvl := logger.Warn
	if debug {
		lvl = logger.Info
	}
	return gormSlog{
		log:           log.With("component", "gorm"),
		level:         lvl,
		slowThreshold: 200 * time.Millisecond,
	}
}

func (g gormSlog) LogMode(l logger.LogLevel) logger.Interface {
	g.level = l
	return g
}

func (g gormSlog) Info(ctx context.Context, msg string, data ...any) {
	if g.level >= logger.Info {
		g.log.InfoContext(ctx, fmt.Sprintf(msg, data...))
	}
}

func (g gormSlog) Warn(ctx context.Context, msg string, data ...any) {
	if g.level >= logger.Warn {
		g.log.WarnContext(ctx, fmt.Sprintf(msg, data...))
	}
}

func (g gormSlog) Error(ctx context.Context, msg string, data ...any) {
	if g.level >= logger.Error {
		g.log.ErrorContext(ctx, fmt.Sprintf(msg, data...))
	}
}

func (g gormSlog) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	if g.level <= logger.Silent {
		return
	}
	elapsed := time.Since(begin)
	switch {
	case err != nil && g.level >= logger.Error && !errors.Is(err, gorm.ErrRecordNotFound):
		sql, rows := fc()
		g.log.ErrorContext(ctx, "query failed", "err", err, "elapsed", elapsed, "rows", rows, "sql", sql)
	case elapsed > g.slowThreshold && g.level >= logger.Warn:
		sql, rows := fc()
		g.log.WarnContext(ctx, "slow query", "elapsed", elapsed, "rows", rows, "sql", sql)
	case g.level >= logger.Info:
		sql, rows := fc()
		g.log.DebugContext(ctx, "query", "elapsed", elapsed, "rows", rows, "sql", sql)
	}
}
