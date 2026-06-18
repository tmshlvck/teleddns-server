package web

import (
	"fmt"

	"github.com/go-chi/chi/v5"
	"github.com/tmshlvck/gone/auth"
	"github.com/tmshlvck/gone/crud"
	"github.com/tmshlvck/gone/site"
	"gorm.io/gorm"
)

// RegisterAdmin mounts gone's auth routes (login/logout/account) and a CRUD
// Admin over the User and Group tables under /admin. Any logged-in user may
// read; only the "admin" group may write (AuthzLoggedInReadAdminWrite).
//
// Mirrors gone's auth_gorm example. Zone/RR tables get added here as the data
// model lands (M2).
func RegisterAdmin(mux chi.Router, ag *auth.AuthGORM, db *gorm.DB, settings site.Settings, shell site.Shell) error {
	gate := auth.AuthzLoggedInReadAdminWrite{Auth: ag}

	userMM := crud.DeriveMetaModel[auth.UserGORM](crud.MetaModel[auth.UserGORM]{
		DisplayName: "Users",
		Fields: []crud.MetaField{
			// Write-only password box: a non-blank entry is re-hashed, a blank
			// one keeps the current hash. Never display the hash.
			{Name: "PasswordHash", DisplayName: "Password", FormInputType: "password",
				DisplayValue:   crud.Redact,
				GenFormElement: crud.PasswordInput,
				BindStrings:    crud.HashWith(auth.HashPassword)},
			// Secrets / passkeys are managed from the account page — hide here.
			{Name: "TOTPSecret", Hidden: true},
			{Name: "WebAuthnHandle", Hidden: true},
			{Name: "Passkeys", Hidden: true},
		},
	})
	userTable := crud.NewTable(userMM, crud.GORMAccessor(userMM, db), settings, gate)
	userTable.Segment = "users" // irregular plural of "UserGORM"

	groupMM := crud.DeriveMetaModel[auth.GroupGORM](crud.MetaModel[auth.GroupGORM]{DisplayName: "Groups"})
	groupTable := crud.NewTable(groupMM, crud.GORMAccessor(groupMM, db), settings, gate)
	groupTable.Segment = "groups"

	admin := crud.DeriveAdmin([]crud.CRUDTableInterface{&userTable, &groupTable}, nil)

	if err := ag.RegisterRoutes(mux, "", shell); err != nil {
		return fmt.Errorf("auth routes: %w", err)
	}
	if err := admin.RegisterRoutes(mux, "", "/admin", shell); err != nil {
		return fmt.Errorf("admin routes: %w", err)
	}
	return nil
}
