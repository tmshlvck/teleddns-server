package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"
)

// idempotencyWindow is how long a stored response is replayable (PRD §11.1).
const idempotencyWindow = 24 * time.Hour

// IdempotencyRecord stores a successful POST's response keyed by the client's
// Idempotency-Key, scoped to the presenting credential, so a retry within the
// window replays the original response instead of creating a duplicate.
type IdempotencyRecord struct {
	ID           uint      `gorm:"primaryKey"`
	IdemKey      string    `gorm:"size:255;not null;uniqueIndex:idx_idem,priority:1"`
	Scope        string    `gorm:"size:64;not null;uniqueIndex:idx_idem,priority:2"` // sha256(Authorization)
	RequestHash  string    `gorm:"size:64;not null"`                                 // sha256(method+path+body)
	StatusCode   int       `gorm:"not null"`
	ContentType  string    `gorm:"size:128"`
	ResponseBody []byte    `gorm:"type:blob"`
	CreatedAt    time.Time `gorm:"index"`
}

func (IdempotencyRecord) TableName() string { return "api_idempotency" }

// IdempotencyStore backs the Idempotency-Key middleware.
type IdempotencyStore struct{ DB *gorm.DB }

// NewIdempotencyStore migrates the table and returns a store.
func NewIdempotencyStore(db *gorm.DB) (*IdempotencyStore, error) {
	if err := db.AutoMigrate(&IdempotencyRecord{}); err != nil {
		return nil, err
	}
	return &IdempotencyStore{DB: db}, nil
}

// Middleware implements Idempotency-Key replay for POST /api/… requests that
// carry the header (PRD §11.1); everything else passes through untouched. On a
// first request it runs the handler and stores a 2xx response; a later request
// with the same key + credential replays it (or 422 if the key is reused with
// different request parameters). Replay is scoped by a hash of the Authorization
// header, so only the same credential can trigger it. Sequential retries — the
// case this protects (a create whose response was lost) — are fully handled;
// concurrent same-key requests rely on the unique index and may both execute,
// which is acceptable for the single-instance deployment.
func (s *IdempotencyStore) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Idempotency-Key")
		if key == "" || r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}

		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))

		scope := sha256hex(r.Header.Get("Authorization"))
		reqHash := sha256hex(r.Method + " " + r.URL.Path + "\n" + string(body))

		var rec IdempotencyRecord
		res := s.DB.
			Where("idem_key = ? AND scope = ? AND created_at > ?", key, scope, time.Now().Add(-idempotencyWindow)).
			Limit(1).Find(&rec)
		if res.Error == nil && res.RowsAffected > 0 {
			if rec.RequestHash != reqHash {
				writeIdemConflict(w)
				return
			}
			replay(w, rec)
			return
		}

		cw := &captureWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(cw, r)

		// Only successful creates are replayable; a failed attempt should be
		// retryable afresh.
		if cw.status >= 200 && cw.status < 300 {
			// Ignore a unique-index conflict from a concurrent first request.
			_ = s.DB.Create(&IdempotencyRecord{
				IdemKey:      key,
				Scope:        scope,
				RequestHash:  reqHash,
				StatusCode:   cw.status,
				ContentType:  cw.Header().Get("Content-Type"),
				ResponseBody: cw.buf.Bytes(),
			}).Error
			s.gc()
		}
	})
}

// gc drops expired rows opportunistically (no separate sweeper needed).
func (s *IdempotencyStore) gc() {
	s.DB.Where("created_at < ?", time.Now().Add(-idempotencyWindow)).Delete(&IdempotencyRecord{})
}

func replay(w http.ResponseWriter, rec IdempotencyRecord) {
	if rec.ContentType != "" {
		w.Header().Set("Content-Type", rec.ContentType)
	}
	w.Header().Set("Idempotency-Replayed", "true")
	w.WriteHeader(rec.StatusCode)
	_, _ = w.Write(rec.ResponseBody)
}

func writeIdemConflict(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusUnprocessableEntity)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"title":  "Unprocessable Entity",
		"status": http.StatusUnprocessableEntity,
		"detail": "Idempotency-Key already used with different request parameters",
	})
}

// captureWriter tees the handler's response into a buffer while forwarding it to
// the client, so a successful response can be stored for replay.
type captureWriter struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
	wrote  bool
}

func (c *captureWriter) WriteHeader(code int) {
	if !c.wrote {
		c.status = code
		c.wrote = true
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *captureWriter) Write(b []byte) (int, error) {
	c.buf.Write(b)
	return c.ResponseWriter.Write(b)
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
