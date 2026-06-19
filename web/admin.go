package web

import (
	"fmt"
	"log/slog"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/tmshlvck/gone/auth"
	"github.com/tmshlvck/gone/crud"
	"github.com/tmshlvck/gone/site"
	"gorm.io/gorm"
)

// RegisterAdmin mounts gone's auth routes (login/logout/account) and a CRUD
// Admin under /admin over the User and Group tables plus the DNS data model
// (Server, Zone, the per-type RR tables, and the role grants). Any logged-in
// user may read; only the "admin" group may write
// (AuthzLoggedInReadAdminWrite).
func RegisterAdmin(mux chi.Router, ag *auth.AuthGORM, db *gorm.DB, settings site.Settings, log *slog.Logger, shell site.Shell) error {
	gate := auth.AuthzLoggedInReadAdminWrite{Auth: ag}

	userMM := crud.DeriveMetaModel[auth.UserGORM](crud.MetaModel[auth.UserGORM]{
		DisplayName: "Users",
		Fields: []crud.MetaField{
			// Clickable ID cell → opens the password-change modal for that
			// user (HTMX GET /account/{id} into the table's L1 modal body).
			{Name: "ID", DisplayValue: func(_ crud.MetaField, value any) templ.Component {
				return userIDLink(fmt.Sprintf("%v", value), "admin-usergorms-modal-l1-body")
			}},
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

	groupMM := crud.DeriveMetaModel[auth.GroupGORM](crud.MetaModel[auth.GroupGORM]{DisplayName: "Groups"})
	groupTable := crud.NewTable(groupMM, crud.GORMAccessor(groupMM, db), settings, gate)

	// One ordered sidebar (gone 0.1.1): tables interleaved with group headers.
	elements := []crud.SidebarElementInterface{
		crud.Header("Accounts"), &userTable, &groupTable,
	}
	elements = append(elements, dnsTables(db, settings, gate, log, ag)...)
	admin := crud.DeriveAdmin(elements, nil)

	if err := ag.RegisterRoutes(mux, "", shell); err != nil {
		return fmt.Errorf("auth routes: %w", err)
	}
	if err := admin.RegisterRoutes(mux, "", "/admin", shell); err != nil {
		return fmt.Errorf("admin routes: %w", err)
	}
	return nil
}
