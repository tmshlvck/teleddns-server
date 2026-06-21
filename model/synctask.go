package model

import (
	"time"

	"gorm.io/gorm"
)

// SyncTask is one entry in the backend-push journal (PRD §10.4 / §12). A
// zone/RR mutation enqueues a task in the same transaction; an executor
// goroutine (see knot.Worker) claims due tasks, regenerates the full zone, and
// pushes it to the local Knot. done/failed rows are kept as a journal.
type SyncTask struct {
	ID          uint      `gorm:"primaryKey"`
	Kind        string    `gorm:"size:16;not null;index:idx_synctask_scan,priority:1"` // "zone" (catalog later)
	Origin      string    `gorm:"size:255;not null;index"`
	State       string    `gorm:"size:16;not null;default:pending;index:idx_synctask_scan,priority:2"`
	Attempts    int       `gorm:"not null;default:0"`
	LastError   string    `gorm:"size:1024"`
	EnqueuedAt  time.Time `gorm:"not null"`
	AvailableAt time.Time `gorm:"not null;index:idx_synctask_scan,priority:3"`
	LastAttempt *time.Time
}

func (SyncTask) TableName() string { return "sync_tasks" }

// SyncTask states + kinds.
const (
	SyncPending  = "pending"
	SyncInFlight = "in_flight"
	SyncDone     = "done"
	SyncFailed   = "failed"

	SyncKindZone       = "zone"        // regenerate + reload the zone content
	SyncKindZoneRemove = "zone-remove" // undeclare the zone from Knot
)

// EnqueueZoneSync appends a pending "zone" task for the zone identified by
// zoneID, unless one is already pending for that origin (coalescing keeps at
// most one pending row per zone; the executor always regenerates from current
// state, so a single pending task captures every change since). Runs in the
// caller's transaction (tx) so the task commits atomically with the change.
func EnqueueZoneSync(tx *gorm.DB, zoneID uint) error {
	db := tx.Session(&gorm.Session{NewDB: true})

	var origins []string
	if err := db.Model(&Zone{}).Where("id = ?", zoneID).Limit(1).Pluck("origin", &origins).Error; err != nil {
		return err
	}
	if len(origins) == 0 || origins[0] == "" {
		return nil
	}
	origin := origins[0]

	var n int64
	if err := db.Model(&SyncTask{}).Where("origin = ? AND state = ?", origin, SyncPending).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	now := time.Now()
	return db.Create(&SyncTask{
		Kind:        SyncKindZone,
		Origin:      origin,
		State:       SyncPending,
		EnqueuedAt:  now,
		AvailableAt: now,
	}).Error
}
