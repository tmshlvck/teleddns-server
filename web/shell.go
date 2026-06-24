// Package web holds the application's page chrome (the HTML document gone's
// HTMX fragments render inside) plus the wiring of gone's auth + CRUD admin.
package web

import (
	"context"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"strings"

	"github.com/a-h/templ"
	"github.com/tmshlvck/gone/auth"
	"github.com/tmshlvck/gone/site"
)

// Shell builds the app's page-chrome function (a site.Shell). It wraps gone's
// fragment components in a full HTML document — DaisyUI + Tailwind + HTMX from
// CDNs, the focus-outline/font polish from gone's admin_gorm example, a CSRF
// meta tag wired to every htmx request, a light/dark theme toggle, and a
// "signed in as …" header with a logout form. Anonymous requests to non-auth
// paths bounce to the login page, matching gone's auth_gorm example.
type Shell struct {
	Auth *auth.AuthGORM
	Log  *slog.Logger
}

// Func returns the site.Shell closure to hand to gone (auth/admin RegisterRoutes).
func (s Shell) Func() site.Shell {
	return func(w http.ResponseWriter, r *http.Request, title string, content templ.Component) {
		u := s.Auth.CurrentUser(r.Context())
		if u == nil && !s.Auth.IsAuthPath(r.URL.Path) {
			http.Redirect(w, r, s.Auth.LoginURL(r.URL.Path), http.StatusSeeOther)
			return
		}
		username := ""
		if u != nil {
			username = u.Username()
		}
		csrf := auth.CSRFToken(r.Context())
		theme := site.Theme(r, "light")

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		s.writeHead(w, title, csrf, theme)
		s.writeHeader(r.Context(), w, title, username, csrf, r.URL.Path)
		if err := content.Render(r.Context(), w); err != nil {
			s.Log.Error("shell render", "err", err)
		}
		s.write(w, "</main></body></html>")
	}
}

func (s Shell) writeHead(w http.ResponseWriter, title, csrf, theme string) {
	const headFmt = `<!doctype html>
<html lang="en" data-theme="%s">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<meta name="csrf-token" content="%s"/>
<title>%s</title>
<link href="https://cdn.jsdelivr.net/npm/daisyui@5" rel="stylesheet" type="text/css"/>
<script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
<script src="https://unpkg.com/htmx.org@2"></script>
<style>
html { -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; }
.input:focus, .input:focus-within,
.select:focus, .textarea:focus {
  outline: none;
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px color-mix(in oklab, var(--color-primary) 28%%, transparent);
}
.btn:focus-visible, .checkbox:focus-visible, .join > :focus-visible {
  outline: 2px solid color-mix(in oklab, var(--color-primary) 65%%, transparent);
  outline-offset: 1px;
  position: relative;
  z-index: 1;
}
</style>
<script>
document.addEventListener('htmx:configRequest', (event) => {
  const meta = document.querySelector('meta[name="csrf-token"]');
  if (meta) event.detail.headers['X-CSRF-Token'] = meta.getAttribute('content');
});
</script>
</head>
<body class="bg-base-200 min-h-screen">
`
	s.write(w, headFmt, html.EscapeString(theme), html.EscapeString(csrf), html.EscapeString(title))
}

// writeHeader renders the top bar: a title plus (when signed in) the primary
// nav on the left, and on the right the theme toggle plus the user link +
// logout form.
func (s Shell) writeHeader(ctx context.Context, w http.ResponseWriter, title, username, csrf, path string) {
	s.write(w, `<header class="p-4 flex flex-wrap items-center justify-between gap-3">
<div class="flex items-center gap-4">
<h1 class="text-xl font-bold">%s</h1>`, html.EscapeString(title))

	if username != "" {
		s.writeNav(w, path)
	}
	s.write(w, `</div><div class="flex items-center gap-3">`)

	if username != "" {
		const userFmt = `<a href="/preferences" class="text-sm opacity-80 link link-hover">Signed in as <b>%s</b></a>
<form method="post" action="%s">
<input type="hidden" name="csrf_token" value="%s"/>
<button type="submit" class="btn btn-sm btn-ghost">Sign out</button>
</form>`
		s.write(w, userFmt,
			html.EscapeString(username),
			html.EscapeString(s.Auth.LogoutURL("")),
			html.EscapeString(csrf),
		)
	}
	if err := site.ThemeToggle("light", "dark").Render(ctx, w); err != nil {
		s.Log.Error("theme toggle render", "err", err)
	}
	s.write(w, `</div></header><main class="p-4">`)
}

// navLinks is the primary navigation, in display order.
var navLinks = []struct{ href, label string }{
	{"/dashboard", "Dashboard"},
	{"/admin", "Admin"},
	{"/preferences", "Preferences"},
}

// writeNav renders the horizontal DaisyUI menu, marking the link whose href
// prefixes the current path as active.
func (s Shell) writeNav(w http.ResponseWriter, path string) {
	s.write(w, `<nav><ul class="menu menu-horizontal gap-1 p-0">`)
	for _, l := range navLinks {
		active := ""
		if path == l.href || strings.HasPrefix(path, l.href+"/") {
			active = " menu-active"
		}
		s.write(w, `<li><a href="%s" class="font-medium%s">%s</a></li>`,
			html.EscapeString(l.href), active, html.EscapeString(l.label))
	}
	s.write(w, `</ul></nav>`)
}

func (s Shell) write(w http.ResponseWriter, format string, args ...any) {
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		s.Log.Error("shell write", "err", err)
	}
}
