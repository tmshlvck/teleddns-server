package knot

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/tmshlvck/teleddns-server/model"
)

// Backend applies zone changes to the DNS server. PushZone must be idempotent
// (the worker always passes the full, current zone); RemoveZone undeclares a
// zone. Both must tolerate being called repeatedly.
type Backend interface {
	PushZone(ctx context.Context, origin, content string) error
	RemoveZone(ctx context.Context, origin string) error
}

// NewBackend selects the backend from config. Default ("log") is a no-op that
// logs what it would do — safe for dev/tests and for a first boot before Knot
// is wired up.
func NewBackend(cfg model.Config, log *slog.Logger) Backend {
	switch cfg.Backend {
	case "knot":
		knotc := cfg.KnotcPath
		if knotc == "" {
			knotc = "knotc"
		}
		return &KnotBackend{
			ZoneDir:  cfg.KnotZoneDir,
			Knotc:    knotc,
			Template: cfg.KnotTemplate,
			Log:      log,
			declared: map[string]bool{},
		}
	default:
		return &LogBackend{Log: log}
	}
}

// LogBackend logs each operation instead of touching a real server.
type LogBackend struct{ Log *slog.Logger }

func (b *LogBackend) PushZone(_ context.Context, origin, content string) error {
	b.Log.Info("backend(log) would push zone", "origin", origin, "bytes", len(content))
	return nil
}

func (b *LogBackend) RemoveZone(_ context.Context, origin string) error {
	b.Log.Info("backend(log) would remove zone", "origin", origin)
	return nil
}

// KnotBackend drives the local Knot daemon via knotc. Zone content is a
// regenerated zone file + `knotc zone-reload` (Knot diffs it against the
// loaded zone — with `zonefile-load: difference` that propagates as an
// incremental IXFR). Zones are declared in Knot's config DB once, as members
// of the operator's Template, via a `knotc conf-*` transaction; the template
// (in the operator's base knot.conf) carries the ACL, TSIG and catalog
// membership, so Knot generates the catalog and slaves auto-provision.
type KnotBackend struct {
	ZoneDir  string
	Knotc    string
	Template string // knot.conf template assigned to managed zones
	Log      *slog.Logger

	mu       sync.Mutex
	declared map[string]bool // origins declared this process lifetime
}

func (b *KnotBackend) PushZone(ctx context.Context, origin, content string) error {
	name := strings.TrimSuffix(origin, ".")
	path := filepath.Join(b.ZoneDir, name+".zone")
	// Write the file first so the first-time declaration's conf-commit loads
	// real content; later pushes rely on zone-reload to re-read it.
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := b.ensureDeclared(ctx, origin); err != nil {
		return err
	}
	if err := b.knotc(ctx, "zone-reload", origin); err != nil {
		return err
	}
	b.Log.Info("backend(knot) reloaded zone", "origin", origin, "path", path)
	return nil
}

func (b *KnotBackend) RemoveZone(ctx context.Context, origin string) error {
	name := strings.TrimSuffix(origin, ".")
	if err := b.confTxn(ctx, [][]string{{"conf-unset", "zone[" + name + "]"}}); err != nil {
		return err
	}
	b.setDeclared(origin, false)
	_ = os.Remove(filepath.Join(b.ZoneDir, name+".zone")) // best-effort
	b.Log.Info("backend(knot) removed zone", "origin", origin)
	return nil
}

// ensureDeclared declares origin as a member of Template in Knot's config DB,
// once per process. If the declaring transaction fails (e.g. a no-op commit
// because the zone is already configured after a restart), it confirms the
// zone exists via conf-read and treats that as success.
func (b *KnotBackend) ensureDeclared(ctx context.Context, origin string) error {
	if b.isDeclared(origin) {
		return nil
	}
	name := strings.TrimSuffix(origin, ".")
	cmds := [][]string{{"conf-set", "zone[" + name + "]"}}
	if b.Template != "" {
		cmds = append(cmds, []string{"conf-set", "zone[" + name + "].template", b.Template})
	}
	if err := b.confTxn(ctx, cmds); err != nil {
		if b.knotcOK(ctx, "conf-read", "zone["+name+"].domain") {
			b.setDeclared(origin, true)
			return nil
		}
		return fmt.Errorf("declare zone %s: %w", origin, err)
	}
	b.setDeclared(origin, true)
	return nil
}

// confTxn runs cmds inside a single conf-begin/…/conf-commit transaction,
// aborting on any error.
func (b *KnotBackend) confTxn(ctx context.Context, cmds [][]string) error {
	if err := b.knotc(ctx, "conf-begin"); err != nil {
		return err
	}
	for _, c := range cmds {
		if err := b.knotc(ctx, c...); err != nil {
			_ = b.knotc(ctx, "conf-abort")
			return err
		}
	}
	if err := b.knotc(ctx, "conf-commit"); err != nil {
		_ = b.knotc(ctx, "conf-abort")
		return err
	}
	return nil
}

func (b *KnotBackend) knotc(ctx context.Context, args ...string) error {
	out, err := exec.CommandContext(ctx, b.Knotc, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("knotc %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (b *KnotBackend) knotcOK(ctx context.Context, args ...string) bool {
	return b.knotc(ctx, args...) == nil
}

func (b *KnotBackend) isDeclared(origin string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.declared[origin]
}

func (b *KnotBackend) setDeclared(origin string, v bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if v {
		b.declared[origin] = true
	} else {
		delete(b.declared, origin)
	}
}
