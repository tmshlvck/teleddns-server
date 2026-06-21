package knot

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/tmshlvck/teleddns-server/model"
)

// Backend applies a rendered zone to the DNS server. PushZone must be
// idempotent (the worker always passes the full, current zone).
type Backend interface {
	PushZone(ctx context.Context, origin, content string) error
}

// NewBackend selects the backend from config. Default ("log") is a no-op that
// logs what it would push — safe for dev/tests and for a first boot before
// Knot is wired up.
func NewBackend(cfg model.Config, log *slog.Logger) Backend {
	switch cfg.Backend {
	case "knot":
		knotc := cfg.KnotcPath
		if knotc == "" {
			knotc = "knotc"
		}
		return &KnotBackend{ZoneDir: cfg.KnotZoneDir, Knotc: knotc, Log: log}
	default:
		return &LogBackend{Log: log}
	}
}

// LogBackend logs each push instead of touching a real server.
type LogBackend struct{ Log *slog.Logger }

func (b *LogBackend) PushZone(_ context.Context, origin, content string) error {
	b.Log.Info("backend(log) would push zone", "origin", origin, "bytes", len(content))
	return nil
}

// KnotBackend writes the zone file under ZoneDir and reloads it via knotc.
// (knot.conf / catalog / ACL generation is a follow-up; this assumes the zone
// is already declared in Knot's config.)
type KnotBackend struct {
	ZoneDir string
	Knotc   string
	Log     *slog.Logger
}

func (b *KnotBackend) PushZone(ctx context.Context, origin, content string) error {
	name := strings.TrimSuffix(origin, ".")
	path := filepath.Join(b.ZoneDir, name+".zone")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	out, err := exec.CommandContext(ctx, b.Knotc, "zone-reload", origin).CombinedOutput()
	if err != nil {
		return fmt.Errorf("knotc zone-reload %s: %w: %s", origin, err, strings.TrimSpace(string(out)))
	}
	b.Log.Info("backend(knot) reloaded zone", "origin", origin, "path", path)
	return nil
}
