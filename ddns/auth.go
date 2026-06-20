package ddns

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/tmshlvck/gone/auth"
)

// caller is an authenticated DDNS principal.
type caller struct {
	user       auth.User
	userID     uint
	tokenID    uint // APIKey.ID for bearer; 0 for basic (no per-token rate key)
	tokenLevel int  // bearer: APIKey.Level; basic: 3 (no token cap)
}

// resolveCaller authenticates the request. Bearer wins over Basic. On success
// returns (caller, true, ""); on any failure returns (zero, false, www) where
// www is the WWW-Authenticate value to send with the 401 badauth.
func (h *Handler) resolveCaller(r *http.Request) (caller, bool, string) {
	hdr := r.Header.Get("Authorization")

	if raw, ok := strings.CutPrefix(hdr, "Bearer "); ok {
		u, k, err := h.Keys.Validate(strings.TrimSpace(raw))
		if err != nil {
			return caller{}, false, "Bearer"
		}
		return caller{user: u, userID: userID(u), tokenID: k.ID, tokenLevel: k.Level}, true, ""
	}

	if enc, ok := strings.CutPrefix(hdr, "Basic "); ok {
		username, password, ok := decodeBasic(enc)
		if !ok {
			return caller{}, false, "Basic, Bearer"
		}
		u, err := h.Auth.Authenticate(username, password)
		if err != nil || u == nil {
			return caller{}, false, "Basic, Bearer"
		}
		// 2FA / SSO / passkey users must use a bearer token (PRD §3.6/§8.7).
		if h.twoFactorUser(u) {
			return caller{}, false, "Bearer"
		}
		return caller{user: u, userID: userID(u), tokenLevel: 3}, true, ""
	}

	return caller{}, false, "Basic, Bearer"
}

// twoFactorUser reports whether the user has TOTP, SSO, or a passkey enrolled
// (or is SSO-only) — any of which forbids Basic auth on the DDNS endpoint.
func (h *Handler) twoFactorUser(u auth.User) bool {
	a, ok := u.(auth.UserGORMAdapter)
	if !ok {
		return false
	}
	var ug auth.UserGORM
	if err := h.DB.Preload("Passkeys").Preload("SSOIdentities").First(&ug, a.U.ID).Error; err != nil {
		return false
	}
	return ug.TOTPSecret != "" || len(ug.Passkeys) > 0 || len(ug.SSOIdentities) > 0 || ug.SSOOnly
}

func decodeBasic(enc string) (user, pass string, ok bool) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(enc))
	if err != nil {
		return "", "", false
	}
	user, pass, ok = strings.Cut(string(raw), ":")
	return user, pass, ok
}

// userID extracts the numeric id from a gone GORM-backed user.
func userID(u auth.User) uint {
	if a, ok := u.(auth.UserGORMAdapter); ok {
		return a.U.ID
	}
	return 0
}
