package knot

import (
	"context"
	"errors"
	"log/slog"
	"math/rand"
	"time"

	"gorm.io/gorm"

	"github.com/tmshlvck/teleddns-server/model"
)

// maxAttempts is the dead-letter threshold (PRD §12.2): after this many failed
// attempts a task moves to state=failed and is no longer retried.
const maxAttempts = 20

// Worker is the single in-process executor that drains the SyncTask journal:
// every tick it claims due pending tasks, coalesces them per origin,
// regenerates the full zone, and pushes it via the backend. Success marks the
// tasks done; failure applies exponential backoff (capped at 1h) and
// dead-letters after maxAttempts. Single-instance only — a multi-process
// deployment would need SELECT … FOR UPDATE SKIP LOCKED.
type Worker struct {
	DB         *gorm.DB
	Backend    Backend
	Log        *slog.Logger
	Interval   time.Duration // tick / debounce (BackendSyncDelay)
	DefaultTTL uint32
}

// Run drains the journal until ctx is cancelled. It first re-queues any tasks
// left in_flight by a previous crash.
func (w *Worker) Run(ctx context.Context) {
	w.DB.Model(&model.SyncTask{}).
		Where("state = ?", model.SyncInFlight).
		Update("state", model.SyncPending)

	t := time.NewTicker(w.Interval)
	defer t.Stop()
	w.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			w.Log.Info("sync worker stopped")
			return
		case <-t.C:
			w.tick(ctx)
		}
	}
}

func (w *Worker) tick(ctx context.Context) {
	now := time.Now()
	var tasks []model.SyncTask
	if err := w.DB.Where("state = ? AND available_at <= ?", model.SyncPending, now).
		Order("id").Find(&tasks).Error; err != nil {
		w.Log.Error("sync claim", "err", err)
		return
	}
	if len(tasks) == 0 {
		return
	}

	// Claim, then coalesce by origin.
	byOrigin := map[string][]model.SyncTask{}
	var ids []uint
	for _, t := range tasks {
		byOrigin[t.Origin] = append(byOrigin[t.Origin], t)
		ids = append(ids, t.ID)
	}
	w.DB.Model(&model.SyncTask{}).Where("id IN ?", ids).
		Updates(map[string]any{"state": model.SyncInFlight, "last_attempt": &now})

	for origin, grp := range byOrigin {
		w.process(ctx, origin, grp)
	}
}

func (w *Worker) process(ctx context.Context, origin string, grp []model.SyncTask) {
	grpIDs := make([]uint, len(grp))
	maxAtt := 0
	for i, t := range grp {
		grpIDs[i] = t.ID
		if t.Attempts > maxAtt {
			maxAtt = t.Attempts
		}
	}

	err := w.pushZone(ctx, origin)
	if err == nil {
		w.DB.Model(&model.SyncTask{}).Where("id IN ?", grpIDs).
			Updates(map[string]any{"state": model.SyncDone, "last_error": ""})
		w.Log.Info("synced zone", "origin", origin, "tasks", len(grp))
		return
	}

	attempts := maxAtt + 1
	upd := map[string]any{"attempts": attempts, "last_error": err.Error()}
	if attempts >= maxAttempts {
		upd["state"] = model.SyncFailed
		w.Log.Error("sync dead-lettered", "origin", origin, "attempts", attempts, "err", err)
	} else {
		upd["state"] = model.SyncPending
		upd["available_at"] = time.Now().Add(backoff(attempts))
		w.Log.Warn("sync failed, will retry", "origin", origin, "attempts", attempts, "err", err)
	}
	w.DB.Model(&model.SyncTask{}).Where("id IN ?", grpIDs).Updates(upd)
}

// pushZone regenerates origin's zone and hands it to the backend. A deleted
// zone (no row) is treated as success — there's nothing to push, and the
// task should not retry forever.
func (w *Worker) pushZone(ctx context.Context, origin string) error {
	content, err := RenderZone(w.DB, origin, w.DefaultTTL)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return w.Backend.PushZone(ctx, origin, content)
}

// backoff returns an exponential delay (base 1s, doubling) capped at 1h, with
// up to 25% jitter.
func backoff(attempts int) time.Duration {
	shift := attempts
	if shift > 12 {
		shift = 12 // 2^12 s ≈ 68 min, already past the cap
	}
	d := time.Duration(1<<shift) * time.Second
	if d > time.Hour {
		d = time.Hour
	}
	jitter := time.Duration(rand.Int63n(int64(d)/4 + 1))
	return d + jitter
}
