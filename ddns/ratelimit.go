package ddns

import (
	"fmt"
	"sync"
	"time"
)

// limiter is an in-process fixed-window rate limiter (PRD §8.8): a per-token
// budget and a per-(user, hostname) budget, both per hour. Single-instance is
// fine for v1; a shared store would be needed for multi-process deployments.
type limiter struct {
	mu          sync.Mutex
	perToken    map[uint]*window
	perRecord   map[string]*window
	tokenLimit  int
	recordLimit int
	window      time.Duration
}

type window struct {
	start time.Time
	count int
}

func newLimiter(perRecord, perToken int) *limiter {
	return &limiter{
		perToken:    map[uint]*window{},
		perRecord:   map[string]*window{},
		tokenLimit:  perToken,
		recordLimit: perRecord,
		window:      time.Hour,
	}
}

// allow records one update attempt and reports whether both budgets still hold.
func (l *limiter) allow(c caller, hostname string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()

	recordOK := l.tick(l.perRecord, fmt.Sprintf("%d|%s", c.userID, hostname), l.recordLimit, now)
	tokenOK := true
	if c.tokenID != 0 {
		tokenOK = l.tickToken(c.tokenID, l.tokenLimit, now)
	}
	return recordOK && tokenOK
}

func (l *limiter) tick(m map[string]*window, key string, limit int, now time.Time) bool {
	w := m[key]
	if w == nil || now.Sub(w.start) >= l.window {
		w = &window{start: now}
		m[key] = w
	}
	w.count++
	return w.count <= limit
}

func (l *limiter) tickToken(key uint, limit int, now time.Time) bool {
	w := l.perToken[key]
	if w == nil || now.Sub(w.start) >= l.window {
		w = &window{start: now}
		l.perToken[key] = w
	}
	w.count++
	return w.count <= limit
}
