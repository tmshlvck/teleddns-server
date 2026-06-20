package model

import (
	"github.com/tmshlvck/gone/auth"
	"gorm.io/gorm"
)

// AdminGroup is the group whose members are L3 / superusers. gone's UserGORM
// has no is_superuser column, so admin status is group membership (the same
// "admin" group the CRUD admin write-gate checks).
const AdminGroup = "admin"

// EffectiveLevel returns a user's authorization level for the record set at
// (zoneID, label), per PRD §9 — without the token cap (apply min(token.level,
// EffectiveLevel) at the call site):
//
//	3  superuser (member of AdminGroup)
//	2  L2 — a GroupZoneRole on the zone via one of the user's groups
//	1  L1 — a GroupRRRole on (zone, label) via one of the user's groups
//	0  no access
//
// This is the shared core the DDNS path (M4) and the full authz model (M3)
// both build on.
func EffectiveLevel(db *gorm.DB, u auth.User, zoneID uint, label string) int {
	a, ok := u.(auth.UserGORMAdapter)
	if !ok || a.U == nil {
		return 0
	}
	// The user's group ids — queried directly so this doesn't depend on
	// whether the caller preloaded Groups onto the user.
	var gids []uint
	db.Table("auth_user_groups").Where("user_gorm_id = ?", a.U.ID).Pluck("group_gorm_id", &gids)
	if len(gids) == 0 {
		return 0
	}
	// L3: member of the admin group.
	var admin auth.GroupGORM
	if err := db.Where("name = ?", AdminGroup).First(&admin).Error; err == nil {
		for _, g := range gids {
			if g == admin.ID {
				return 3
			}
		}
	}
	var n int64
	if db.Model(&GroupZoneRole{}).Where("zone_id = ? AND group_id IN ?", zoneID, gids).Count(&n); n > 0 {
		return 2
	}
	if db.Model(&GroupRRRole{}).Where("zone_id = ? AND label = ? AND group_id IN ?", zoneID, label, gids).Count(&n); n > 0 {
		return 1
	}
	return 0
}
