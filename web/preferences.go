package web

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"
	"github.com/tmshlvck/gone/auth"
	"github.com/tmshlvck/gone/site"

	"github.com/tmshlvck/teleddns-server/model"
)

// RegisterPreferences mounts the self-service account page. It composes gone's
// account-security cards (password / TOTP / passkeys / SSO, via
// AccountSection) with an app-owned API-keys card, plus the issue/revoke POST
// routes. These are browser, cookie-session routes — they go through CSRF like
// any other form; only the consuming JSON API bypasses CSRF.
func RegisterPreferences(mux chi.Router, ag *auth.AuthGORM, ks *model.KeyStore, shell site.Shell) {
	mux.Get("/preferences", func(w http.ResponseWriter, r *http.Request) {
		renderPreferences(w, r, ag, ks, shell, "")
	})

	mux.Post("/preferences/apikey", func(w http.ResponseWriter, r *http.Request) {
		uid, ok := currentUserID(ag, r.Context())
		if !ok {
			http.Redirect(w, r, ag.LoginURL(r.URL.Path), http.StatusSeeOther)
			return
		}
		name := r.PostFormValue("name")
		var expires *time.Time
		if d, err := strconv.Atoi(r.PostFormValue("expires_days")); err == nil && d > 0 {
			t := time.Now().Add(time.Duration(d) * 24 * time.Hour)
			expires = &t
		}
		// Level: requested, capped at the user's maximum (PRD §9.2) and floored
		// at L1 so every key is at least usable for DDNS.
		level := model.L1
		if v, err := strconv.Atoi(r.PostFormValue("level")); err == nil {
			level = v
		}
		if maxLvl := model.UserMaxLevel(ks.DB, ag.CurrentUser(r.Context())); level > maxLvl {
			level = maxLvl
		}
		if level < model.L1 {
			level = model.L1
		}
		raw, err := ks.Issue(uid, name, level, expires)
		if err != nil {
			http.Error(w, "could not create key", http.StatusInternalServerError)
			return
		}
		// Show the raw key once, inline (a redirect can't carry the secret).
		renderPreferences(w, r, ag, ks, shell, raw)
	})

	mux.Post("/preferences/apikey/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		uid, ok := currentUserID(ag, r.Context())
		if !ok {
			http.Redirect(w, r, ag.LoginURL(r.URL.Path), http.StatusSeeOther)
			return
		}
		if id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64); err == nil {
			_ = ks.Revoke(uid, uint(id)) // idempotent; ignore "not found"
		}
		http.Redirect(w, r, "/preferences", http.StatusSeeOther)
	})
}

// renderPreferences renders the preferences page; newRawKey, when non-empty,
// is shown once in a banner.
func renderPreferences(w http.ResponseWriter, r *http.Request, ag *auth.AuthGORM, ks *model.KeyStore, shell site.Shell, newRawKey string) {
	cards, target, res := ag.AccountSection(r)
	switch res {
	case auth.AccountAnonymous:
		http.Redirect(w, r, ag.LoginURL(r.URL.Path), http.StatusSeeOther)
		return
	case auth.AccountForbidden:
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	case auth.AccountNotFound:
		http.NotFound(w, r)
		return
	}
	keys, _ := ks.List(target.ID)
	maxLvl := model.UserMaxLevel(ks.DB, ag.CurrentUser(r.Context()))
	page := preferencesPage(target.Username, cards, keys, newRawKey, auth.CSRFToken(r.Context()), maxLvl)
	shell(w, r, "Preferences — "+target.Username, page)
}

// currentUserID extracts the signed-in user's numeric ID by type-asserting the
// gone GORM adapter that AuthGORM.CurrentUser returns.
func currentUserID(ag *auth.AuthGORM, ctx context.Context) (uint, bool) {
	if a, ok := ag.CurrentUser(ctx).(auth.UserGORMAdapter); ok {
		return a.U.ID, true
	}
	return 0, false
}

// preferencesPage composes the library's account-security cards above an
// app-owned API-keys card (the "bundled auth block + app block" pattern).
func preferencesPage(username string, accountCards templ.Component, keys []model.APIKey, newRawKey, csrf string, maxLevel int) templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		fmt.Fprintf(w, `<div class="max-w-6xl mx-auto flex flex-col gap-8">`)
		fmt.Fprintf(w, `<h1 class="text-2xl font-semibold">Preferences — %s</h1>`, html.EscapeString(username))

		fmt.Fprint(w, `<section class="flex flex-col gap-3"><h2 class="text-lg font-medium opacity-80">Account security</h2>`)
		if accountCards != nil {
			if err := accountCards.Render(ctx, w); err != nil {
				return err
			}
		}
		fmt.Fprint(w, `</section>`)

		fmt.Fprint(w, `<section class="flex flex-col gap-3"><h2 class="text-lg font-medium opacity-80">API keys</h2>`)
		writeAPIKeysCard(w, keys, newRawKey, csrf, maxLevel)
		fmt.Fprint(w, `</section></div>`)
		return nil
	})
}

func writeAPIKeysCard(w io.Writer, keys []model.APIKey, newRawKey, csrf string, maxLevel int) {
	fmt.Fprint(w, `<div class="card w-full bg-base-100 shadow-xl"><div class="card-body gap-4">`)

	if newRawKey != "" {
		fmt.Fprintf(w, `<div role="alert" class="alert alert-success flex-col items-start gap-1">
<span class="font-medium">New API key — copy it now, it won't be shown again:</span>
<code class="text-sm break-all select-all">%s</code></div>`, html.EscapeString(newRawKey))
	}

	if len(keys) == 0 {
		fmt.Fprint(w, `<p class="text-sm opacity-70">No API keys yet.</p>`)
	} else {
		fmt.Fprint(w, `<div class="overflow-x-auto"><table class="table table-sm">
<thead><tr><th>Key</th><th>Name</th><th>Level</th><th>Last used</th><th>Expires</th><th></th></tr></thead><tbody>`)
		for _, k := range keys {
			fmt.Fprint(w, `<tr>`)
			fmt.Fprintf(w, `<td><code>%s…</code></td>`, html.EscapeString(k.Prefix))
			fmt.Fprintf(w, `<td>%s</td>`, html.EscapeString(k.Name))
			fmt.Fprintf(w, `<td>L%d</td>`, k.Level)
			fmt.Fprintf(w, `<td>%s</td>`, html.EscapeString(fmtKeyTime(k.LastUsedAt, "never")))
			fmt.Fprintf(w, `<td>%s</td>`, html.EscapeString(fmtKeyTime(k.ExpiresAt, "never")))
			if k.Disabled {
				fmt.Fprint(w, `<td><span class="badge badge-ghost">revoked</span></td>`)
			} else {
				fmt.Fprintf(w, `<td><form method="post" action="/preferences/apikey/%d/revoke">
<input type="hidden" name="csrf_token" value="%s"/>
<button type="submit" class="btn btn-xs btn-error btn-outline">Revoke</button></form></td>`,
					k.ID, html.EscapeString(csrf))
			}
			fmt.Fprint(w, `</tr>`)
		}
		fmt.Fprint(w, `</tbody></table></div>`)
	}

	// New-key form. The level selector is capped at the user's maximum (PRD
	// §9.2); a leaked low-level key can't escalate (min rule in Authorized).
	if maxLevel < model.L1 {
		maxLevel = model.L1
	}
	fmt.Fprintf(w, `<form method="post" action="/preferences/apikey" class="flex flex-wrap items-end gap-3 pt-2 border-t border-base-300">
<input type="hidden" name="csrf_token" value="%s"/>
<label class="form-control"><span class="label-text text-xs opacity-70">Name</span>
<input name="name" required class="input input-bordered input-sm" placeholder="my-router"/></label>
<label class="form-control"><span class="label-text text-xs opacity-70">Level</span>
<select name="level" class="select select-bordered select-sm">`, html.EscapeString(csrf))
	for lvl := model.L1; lvl <= maxLevel; lvl++ {
		fmt.Fprintf(w, `<option value="%d">L%d</option>`, lvl, lvl)
	}
	fmt.Fprint(w, `</select></label>
<label class="form-control"><span class="label-text text-xs opacity-70">Expires in days (blank = never)</span>
<input name="expires_days" type="number" min="1" class="input input-bordered input-sm" placeholder="—"/></label>
<button type="submit" class="btn btn-primary btn-sm">Create key</button>
</form>`)

	fmt.Fprint(w, `</div></div>`)
}

func fmtKeyTime(t *time.Time, zero string) string {
	if t == nil {
		return zero
	}
	return t.UTC().Format("2006-01-02 15:04 MST")
}
