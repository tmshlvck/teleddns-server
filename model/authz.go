package model

import (
	"github.com/tmshlvck/gone/auth"
	"gorm.io/gorm"
)

// Authorization model (PRD §9). Three levels:
//
//	L1 — read/update the A/AAAA record set at a (zone, label); no create/delete.
//	L2 — full CRUD on a whole zone's records; manage scoped users/groups.
//	L3 — superuser: anything, plus the operator UI.
//
// A request is allowed iff min(token level, the user's effective level for the
// target) ≥ the level the action requires. The min() is the key safety rule: a
// leaked low-level token never escalates past its own level even if the owner
// is more privileged.
const (
	LevelNone = 0
	L1        = 1
	L2        = 2
	L3        = 3
)

// AdminGroup is the group whose members are L3 / superusers. gone's UserGORM
// has no is_superuser column, so admin status is group membership (the same
// "admin" group the CRUD admin write-gate checks).
const AdminGroup = "admin"

// Action is a CRUD-ish verb for an authorization check.
type Action int

const (
	Read Action = iota
	Update
	Create
	Delete
)

// TargetKind classifies what is being acted on.
type TargetKind int

const (
	// TargetAddrRecord is an A/AAAA record set at a (zone, label).
	TargetAddrRecord TargetKind = iota
	// TargetZoneData is any other RR type, or the zone / SOA / NS.
	TargetZoneData
	// TargetAdmin is users, groups, servers, or another user's tokens.
	TargetAdmin
)

// RequiredLevel implements PRD §9.6: read/update of an A/AAAA set needs L1; any
// other zone/RR action needs L2; admin objects need L3.
func RequiredLevel(a Action, k TargetKind) int {
	switch k {
	case TargetAddrRecord:
		if a == Read || a == Update {
			return L1
		}
		return L2 // create/delete an address record (no L1 auto-create)
	case TargetZoneData:
		return L2
	default:
		return L3
	}
}

// Authorized applies the cap rule: allowed iff min(tokenLevel, userEffective)
// ≥ required.
func Authorized(tokenLevel, userEffective, required int) bool {
	have := tokenLevel
	if userEffective < have {
		have = userEffective
	}
	return have >= required
}

// EffectiveLevel returns a user's authorization level for the record set at
// (zoneID, label), without the token cap (apply Authorized at the call site):
//
//	L3  superuser (member of AdminGroup)
//	L2  a GroupZoneRole on the zone via one of the user's groups
//	L1  a GroupRRRole on (zone, label) via one of the user's groups
//	0   no access
func EffectiveLevel(db *gorm.DB, u auth.User, zoneID uint, label string) int {
	gids, isAdmin := userGroups(db, u)
	if isAdmin {
		return L3
	}
	if len(gids) == 0 {
		return LevelNone
	}
	var n int64
	if db.Model(&GroupZoneRole{}).Where("zone_id = ? AND group_id IN ?", zoneID, gids).Count(&n); n > 0 {
		return L2
	}
	if db.Model(&GroupRRRole{}).Where("zone_id = ? AND label = ? AND group_id IN ?", zoneID, label, gids).Count(&n); n > 0 {
		return L1
	}
	return LevelNone
}

// UserMaxLevel returns the highest level a user can be granted anywhere — the
// cap for minting tokens (PRD §9.2): L3 for admins, else the highest role level
// the user holds in any zone (L2 via a GroupZoneRole, L1 via a GroupRRRole).
func UserMaxLevel(db *gorm.DB, u auth.User) int {
	gids, isAdmin := userGroups(db, u)
	if isAdmin {
		return L3
	}
	if len(gids) == 0 {
		return LevelNone
	}
	var n int64
	if db.Model(&GroupZoneRole{}).Where("group_id IN ?", gids).Count(&n); n > 0 {
		return L2
	}
	if db.Model(&GroupRRRole{}).Where("group_id IN ?", gids).Count(&n); n > 0 {
		return L1
	}
	return LevelNone
}

// userGroups returns the user's group ids and whether one of them is the admin
// group. Queried directly so callers needn't preload Groups onto the user.
func userGroups(db *gorm.DB, u auth.User) (gids []uint, isAdmin bool) {
	a, ok := u.(auth.UserGORMAdapter)
	if !ok || a.U == nil {
		return nil, false
	}
	db.Table("auth_user_groups").Where("user_gorm_id = ?", a.U.ID).Pluck("group_gorm_id", &gids)
	if len(gids) == 0 {
		return nil, false
	}
	var admin auth.GroupGORM
	if err := db.Where("name = ?", AdminGroup).First(&admin).Error; err == nil {
		for _, g := range gids {
			if g == admin.ID {
				return gids, true
			}
		}
	}
	return gids, false
}
