package model

import (
	"testing"

	"github.com/tmshlvck/gone/auth"
	"gorm.io/gorm"
)

// authzFixture builds an admin/L2/L1/none user against one zone+label and
// returns them as auth.User values.
func authzFixture(t *testing.T, db *gorm.DB) (zoneID uint, admin, l2, l1, none auth.User) {
	t.Helper()
	adminG := auth.GroupGORM{Name: AdminGroup}
	zoneG := auth.GroupGORM{Name: "zoneops"}
	rrG := auth.GroupGORM{Name: "rrops"}
	for _, g := range []*auth.GroupGORM{&adminG, &zoneG, &rrG} {
		if err := db.Create(g).Error; err != nil {
			t.Fatal(err)
		}
	}
	z := Zone{Origin: "example.com."}
	if err := db.Create(&z).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&GroupZoneRole{GroupID: zoneG.ID, ZoneID: z.ID, Level: L2}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&GroupRRRole{GroupID: rrG.ID, ZoneID: z.ID, Label: "host"}).Error; err != nil {
		t.Fatal(err)
	}
	mk := func(name string, groups ...*auth.GroupGORM) auth.User {
		u := auth.UserGORM{Username: name, Email: name + "@example.test"}
		if err := db.Create(&u).Error; err != nil {
			t.Fatal(err)
		}
		for _, g := range groups {
			if err := db.Model(&u).Association("Groups").Append(g); err != nil {
				t.Fatal(err)
			}
		}
		return auth.UserGORMAdapter{U: &u}
	}
	return z.ID, mk("admin", &adminG), mk("l2", &zoneG), mk("l1", &rrG), mk("none")
}

func TestEffectiveLevel(t *testing.T) {
	db := testDB(t)
	zid, admin, l2, l1, none := authzFixture(t, db)

	cases := []struct {
		name  string
		u     auth.User
		label string
		want  int
	}{
		{"admin anywhere", admin, "host", L3},
		{"admin other label", admin, "other", L3},
		{"l2 on zone", l2, "host", L2},
		{"l2 other label", l2, "other", L2}, // zone role covers any label
		{"l1 on its label", l1, "host", L1},
		{"l1 other label", l1, "other", LevelNone}, // rr role is label-scoped
		{"none", none, "host", LevelNone},
	}
	for _, c := range cases {
		if got := EffectiveLevel(db, c.u, zid, c.label); got != c.want {
			t.Errorf("%s: EffectiveLevel=%d, want %d", c.name, got, c.want)
		}
	}
}

func TestUserMaxLevel(t *testing.T) {
	db := testDB(t)
	_, admin, l2, l1, none := authzFixture(t, db)
	for _, c := range []struct {
		name string
		u    auth.User
		want int
	}{
		{"admin", admin, L3},
		{"l2", l2, L2},
		{"l1", l1, L1},
		{"none", none, LevelNone},
	} {
		if got := UserMaxLevel(db, c.u); got != c.want {
			t.Errorf("%s: UserMaxLevel=%d, want %d", c.name, got, c.want)
		}
	}
}

func TestRequiredLevel(t *testing.T) {
	cases := []struct {
		a    Action
		k    TargetKind
		want int
	}{
		{Read, TargetAddrRecord, L1},
		{Update, TargetAddrRecord, L1},
		{Create, TargetAddrRecord, L2}, // no L1 auto-create
		{Delete, TargetAddrRecord, L2},
		{Read, TargetZoneData, L2},
		{Update, TargetZoneData, L2},
		{Read, TargetAdmin, L3},
		{Delete, TargetAdmin, L3},
	}
	for _, c := range cases {
		if got := RequiredLevel(c.a, c.k); got != c.want {
			t.Errorf("RequiredLevel(%v,%v)=%d, want %d", c.a, c.k, got, c.want)
		}
	}
}

func TestAuthorizedCapRule(t *testing.T) {
	cases := []struct {
		name             string
		token, eff, need int
		want             bool
	}{
		{"L1 token, L1 user, need L1", L1, L1, L1, true},
		{"leaked L1 token of admin can't reach L2", L1, L3, L2, false},
		{"L2 token but user only L1 is capped", L2, L1, L2, false},
		{"L3 token, admin, need L3", L3, L3, L3, true},
		{"no access", L1, LevelNone, L1, false},
	}
	for _, c := range cases {
		if got := Authorized(c.token, c.eff, c.need); got != c.want {
			t.Errorf("%s: Authorized(%d,%d,%d)=%v, want %v", c.name, c.token, c.eff, c.need, got, c.want)
		}
	}
}
