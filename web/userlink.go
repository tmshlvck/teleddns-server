package web

import (
	"context"
	"fmt"
	"html"
	"io"

	"github.com/a-h/templ"
)

// userIDLink renders a user row's ID cell as a button that opens the
// password-change modal for that user: an HTMX GET of /account/{id} swapped
// into the users table's L1 modal body. Mirrors gone's auth_gorm example
// (the library mounts the GET/POST /account/{ref} handlers that serve the
// password form). modalBodyID is the table's L1 body element id, derived from
// the component path "/admin/usergorms" → "admin-usergorms-modal-l1-body"
// (gone derives the slug as lowercase(typeName)+"s"; UserGORM → usergorms).
func userIDLink(id, modalBodyID string) templ.Component {
	return templ.ComponentFunc(func(_ context.Context, w io.Writer) error {
		_, err := fmt.Fprintf(w,
			`<button type="button" class="link link-primary" hx-get="/account/%s" hx-target="#%s" hx-swap="innerHTML" title="Change password">%s</button>`,
			html.EscapeString(id), html.EscapeString(modalBodyID), html.EscapeString(id))
		return err
	})
}
