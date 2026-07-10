package model

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/tmshlvck/gone/auth"
	"gorm.io/gorm"
)

// apiKeyPrefix tags every raw key so Validate can reject obviously-foreign
// tokens before hashing, and so users recognize the credential.
const apiKeyPrefix = "teleddns_"

// ErrInvalidAPIKey is returned for any key that is malformed, unknown,
// disabled, expired, or whose owner is disabled — deliberately one error so
// callers can't distinguish the reasons.
var ErrInvalidAPIKey = errors.New("invalid api key")

// APIKey is a per-user bearer credential for the JSON + DDNS APIs (the Token
// entity of PRD §10.1). Only the SHA-256 hash of the raw key is stored — a key
// is high-entropy, so a fast hash is sufficient and there's nothing to brute-
// force. The raw key is shown to the user exactly once, at creation.
//
// Level mirrors PRD §9.2 (L1/L2/L3). Capping a key's level to the owning
// user's maximum, and enforcing min(token.level, user.level), lands with the
// authorization model in M3; for now new keys default to L1.
type APIKey struct {
	ID         uint       `gorm:"primaryKey"`
	UserID     uint       `gorm:"index;not null"`      // owning user (effective principal)
	HashedKey  string     `gorm:"uniqueIndex;size:64"` // hex sha256(raw); never the raw key
	Prefix     string     `gorm:"index;size:12"`       // shown in the UI to identify a key
	Name       string     `gorm:"size:128"`            // user-supplied label
	Level      int        `gorm:"not null;default:1"`  // 1|2|3 (PRD §9.2)
	LastUsedAt *time.Time //
	ExpiresAt  *time.Time // nil = never expires
	Disabled   bool       //
	CreatedAt  time.Time  //
}

func (APIKey) TableName() string { return "api_keys" }

// KeyStore mints, validates, and manages APIKeys. It shares the *gorm.DB the
// rest of the app uses, so keys live alongside users in one database.
type KeyStore struct{ DB *gorm.DB }

// NewKeyStore returns a store over db. The api_keys table is created by
// Migrate (it is in appModels), which must have run first.
func NewKeyStore(db *gorm.DB) (*KeyStore, error) {
	return &KeyStore{DB: db}, nil
}

// Issue mints a new key for userID and returns the RAW key — the only time it
// is ever available. Only its hash is persisted. level < 1 is clamped to 1.
func (s *KeyStore) Issue(userID uint, name string, level int, expires *time.Time) (raw string, err error) {
	buf := make([]byte, 24)
	if _, err = rand.Read(buf); err != nil {
		return "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(buf)
	prefix := secret[:8]
	raw = apiKeyPrefix + prefix + "_" + secret[8:]

	if level < 1 {
		level = 1
	}
	sum := sha256.Sum256([]byte(raw))
	return raw, s.DB.Create(&APIKey{
		UserID:    userID,
		HashedKey: hex.EncodeToString(sum[:]),
		Prefix:    prefix,
		Name:      name,
		Level:     level,
		ExpiresAt: expires,
	}).Error
}

// Validate resolves a presented raw key to its owning user (as an auth.User,
// so the app's existing Authz applies unchanged) and the key record. It checks
// the key is known, not disabled, not expired, and the owner is not disabled,
// then best-effort bumps LastUsedAt.
func (s *KeyStore) Validate(raw string) (auth.User, *APIKey, error) {
	if !strings.HasPrefix(raw, apiKeyPrefix) {
		return nil, nil, ErrInvalidAPIKey
	}
	sum := sha256.Sum256([]byte(raw))
	hashed := hex.EncodeToString(sum[:])

	var k APIKey
	if err := s.DB.Where("hashed_key = ? AND disabled = ?", hashed, false).First(&k).Error; err != nil {
		return nil, nil, ErrInvalidAPIKey
	}
	if k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt) {
		return nil, nil, ErrInvalidAPIKey
	}

	var u auth.UserGORM
	if err := s.DB.Preload("Groups").First(&u, k.UserID).Error; err != nil {
		return nil, nil, ErrInvalidAPIKey
	}
	if u.Disabled {
		return nil, nil, ErrInvalidAPIKey
	}

	now := time.Now()
	s.DB.Model(&k).Update("last_used_at", &now) // best-effort
	return auth.UserGORMAdapter{U: &u}, &k, nil
}

// List returns userID's keys, newest first.
func (s *KeyStore) List(userID uint) ([]APIKey, error) {
	var keys []APIKey
	err := s.DB.Where("user_id = ?", userID).Order("created_at DESC").Find(&keys).Error
	return keys, err
}

// Revoke disables key id, scoped to userID so a user can only revoke their own
// keys. Idempotent (PRD: DELETE-like operations).
func (s *KeyStore) Revoke(userID, id uint) error {
	return s.DB.Model(&APIKey{}).
		Where("id = ? AND user_id = ?", id, userID).
		Update("disabled", true).Error
}
