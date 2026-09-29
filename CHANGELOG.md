# Changelog

Notable changes to `teleddns-server`, newest first. Releases before 0.4.4 predate this file — their
history is in `git log`, and each was tagged `vX.Y.Z`.

**On version numbers.** This is an application, not a library: nothing resolves it by version, so the
major/minor/patch split carries no mechanical meaning and is not used to encode compatibility.
Versions increment; **anything an operator must do is called out under "Upgrading" in the entry**,
whatever the number does. Read that section, not the digits.

## [0.4.4] — 2026-09-29

The console is rewritten as a plain server-rendered multi-page app, DNSSEC signing becomes a
per-zone decision, and a family of foreign keys that could block a delete — or leave rows behind —
are made to cascade.

### ⚠ Upgrading — one required edit, and one thing to know

**Rename one config key before starting 0.4.4**, or it will refuse to boot:

```yaml
knot_template: "master"           # ← up to 0.4.3
default_knot_template: "master"   # ← 0.4.4
```

A one-line edit, and a one-line change to a deployment script — which is why this is a patch release
and not a minor one. It is called out here rather than encoded in the version.

`Config` is `deny_unknown_fields`, so the old key is a hard startup error rather than a line that is
silently ignored — which is the point of renaming rather than aliasing it. A stale key that kept
working while doing nothing would put every zone on the wrong Knot template.

**The upgrade is one-way.** Migrations `m0006`–`m0009` run once at startup; afterwards the previous
binary will not start (`sea-orm-migration` reports "Migration file of version '…' is missing").
Rolling back means deleting that row from `seaql_migrations` by hand, and undoing what it did. This
has been true of every migration this project has shipped and is only now written down. **Back the
database up before the first start.**

Nothing else needs operator action. Existing config files are otherwise unchanged, every database
migrates in place with its rows intact, and sessions and API keys keep working.

### Breaking

- **`knot_template` → `default_knot_template`** (above), plus a new optional `knot_templates`
  allow-list.
- **`/` is now the dashboard**; the console moved to `/admin/{entity}` (`/admin` redirects). Update
  bookmarks and any runbook that links to it.
- **The console's JSON API under `/admin/api` is gone**, along with its entries in
  `/openapi.json`. It existed only to feed the JavaScript this release deletes and was never a
  documented contract. The three APIs teleddns actually publishes — native, Cloudflare facade,
  DDNS — are unchanged.

### Added

- **A dashboard at `/`**, Superadmin-only, refreshing itself every 30 s in place. Update activity as
  a Chart.js line chart (data baked into the page — no JSON endpoint) plus per-surface totals over
  six windows; a zones panel with each zone's database serial against the serial the backend is
  actually answering with, its record count, queued pushes and why it is waiting (`queued`,
  `retrying`, `pushing`, `failed`); and the backend and sync-worker state. Timestamps show both
  absolute (in the chosen timezone) and relative.
- **Per-zone Knot templates.** A zone's `template` field decides which `knot.conf` template it is
  declared under, `default_knot_template` applies when it names none, and `knot_templates` is an
  optional allow-list that turns the console field into a `<select>`, makes the API reject anything
  else, and defines which templates orphan-pruning treats as ours. **This is the mechanism behind
  per-zone DNSSEC signing** — see `DNSSEC.md`, rewritten around it.
- **Timezones.** A navbar picker (offered zones from the new `timezones` config key) sets a cookie
  and the *server* formats every timestamp with it — table cells, datetime inputs and CSV exports
  alike, so an export matches what is on screen.
- **`log_access: false`** drops the per-request log line, for a deployment behind a reverse proxy
  that already logs accesses. The middleware is then not installed at all.
- **The audit log names its own vocabulary** in the console, and every write path is covered
  including those with no request behind them (`admin import`, `admin reset-password`, the
  first-start seed, the retention prune).

### Fixed

- **Deleting records in the console did nothing to DNS.** No serial bump and no push, so the backend
  went on answering with records the console said were gone — and because the serial never moved,
  even a later re-push would have left every secondary on the old copy. All three delete controls
  were affected. The native API, CF facade and DDNS were never affected.
- **A bulk delete audited only that *something* had gone.** "Delete selected" and "delete all
  matching" wrote a single row naming the table, with no key and no prior state. Each removed record
  now gets its own row, carrying what it was.
- **Deleting a user could fail outright**, with a `409` and no way forward, if they belonged to any
  group or held any API key; the same for deleting a group or zone named in a grant. And a deleted
  account left its sessions and recovery-code hashes behind — credential-shaped rows owned by
  nobody. Every dependent foreign key now cascades (`m0008`).
- **Deleting a zone now takes its records** (`m0009`). The API always meant this and deleted them by
  hand; the console could not delete a zone at all while it held any. Both surfaces now agree, and
  the deletion audits every record it destroyed rather than only the zone.
- **A warning read "the sync worker has not ticked for 21s ago."**
- **The audit `source` column's help rendered nowhere** — a field description only appears on a
  form, and that table is read-only.

### Changed

- **Built on `relativelylight` 0.3.2** (from 0.2.0). The console is now server-rendered HTML: a
  `GET` renders and a `POST` on the same path writes, answering `303`. The whole view — page, sort,
  search, zone filter, the open create/edit dialog — lives in the URL, so every screen is a
  bookmarkable link and a chosen zone follows you across all fifteen record tables. Reads are gated
  at the handler rather than by hiding buttons.
- **No JavaScript framework and no build step.** Alpine and Bootstrap's JS bundle are gone; what
  remains is a light/dark toggle and Chart.js on the dashboard, pinned and integrity-checked.
  An admin page went from ~520 KB to ~15 KB.
- **`utoipa` dropped**; `/openapi.json` is hand-written and describes exactly the three published
  APIs.
- **Logs go to stdout** (they always did; the README said stderr).
