# AGENTS.md — working on teleddns-server

Orientation for developing **on** this codebase. Read this, then the docs it
points to. The design + requirements (behavioral contracts, high-level decisions,
status) are in [`PRD.md`](PRD.md); operator usage and the deployment runbook are in
[`README.md`](README.md); the DDNS wire protocol as clients see it (and where it
deviates from the dyn API) is [`DYNDNS2.md`](DYNDNS2.md) — keep it in step with
`src/ddns.rs`, it is what client authors implement against.

## What this is

A Rust rewrite of a co-located DNS + Dynamic-DNS control-plane for a Knot DNS
master, built on the [`relativelylight`](https://github.com/tmshlvck/relativelylight)
back-office library (a **crates.io dependency**, `version = "0.3"` in `Cargo.toml`). The library
provides the SeaORM CRUD engine + metadata, the server-rendered admin UI
(`crud::ui::Admin` — plain HTML fragments, no JavaScript framework), and `auth`
(users/groups/sessions/login/profile, argon2id, TOTP, the `Authz` gate). Everything
DNS-specific is app code, and so is every route: the library contributes none.

## Before you start — fetch first

**`git fetch` before branching, and before changing anything on `master`.** The
authoritative history is `origin/master` on GitHub, and this repository is worked on
from more than one machine, so a local `master` is only ever a claim about the past.

```sh
git fetch origin
git log --oneline master..origin/master     # empty = you are at the tip
git status -sb                              # "[behind N]" = stop and pull
```

Not a formality. It has already cost real work once: a branch was started from a local
`master` that was **seven weeks and seven commits stale** — including two releases
(`v0.4.2`, `v0.4.3`) — and the divergence only surfaced at the next `pull`, as a
five-file conflict in the middle of a rebase of a 1,700-line change. Everything was
recoverable, and an hour went into recovering it. Thirty seconds of `git fetch` at the
start would have avoided all of it.

Two related habits, for the same reason:

- **`pull` here rebases** (`pull.rebase` is on), so a pull onto unpushed local commits
  *replays* them and can stop mid-way. `git config pull.ff only` makes a diverged pull
  refuse instead, which is the safer default when work is in flight.
- **Push a branch when you finish it**, rather than letting local commits accumulate
  across sessions — an unpushed commit is invisible to every other machine, including
  the one that will make the next conflicting change.

## Build / test / run

```sh
cargo build
cargo test                 # unit tests live next to the code (mod tests)
cargo clippy
cargo run -- serve         # http://127.0.0.1:8080/  (logs the seeded admin password once)
```

`db_dsn: sqlite://…` for single-node, `postgres://…` for larger. The default
`backend: log` is a no-op that logs the rendered zone — safe for dev with no
Knot. Quick manual loop: `TELEDDNS_DB_DSN=sqlite::memory:
TELEDDNS_LISTEN_ADDR=127.0.0.1:8080 cargo run -- serve`, grab the logged admin
password, log in at `/`, mint a key on `/profile` (the API-keys card below
password + 2FA), then exercise `/api/...`.

## Module map (`src/`)

| File | Role |
|---|---|
| `main.rs` | CLI (`serve`, `--version`, `admin reset-password [--break-glass]`, `admin import`) |
| `config.rs` | layered YAML config (defaults → file → env → flags) |
| `db.rs` | connection; SQLite DSN normalization |
| `app.rs` | `AppState`, router composition, server bootstrap, admin seed |
| `model/` | SeaORM entities: `zone` (SOA inline), `rr` (one table per type, macro), `api_key`, `roles` (zone_role/rr_role), `sync_task`, `idempotency`, `audit` |
| `migration/` | versioned `sea-orm-migration` steps (auth tables via the library + app tables + audit) |
| `authz.rs` | `Level` algebra, the `min()` cap, `effective_level`, `user_groups` |
| `principal.rs` | resolve session / HTTP Basic / bearer → `Principal` (with a token level); the one place credential failures are counted + metered |
| `keys.rs` | self-service API-key component (`section()` composed onto `/profile` via `Auth::profile_extra`; CSRF-checked mint/revoke of the caller's own keys) |
| `stats.rs` | the numbers `/healthcheck`, `/metrics` and the dashboard all report — one `Stats::gather`, one `warnings()` predicate, so the three can't disagree |
| `sync.rs` | serial bump + push enqueue (called from RR/zone `after_save` hooks and write paths) |
| `audit.rs` | audit sink: `WriteObserver` for admin/auth writes + `record()` for DDNS/API/CF; writes the `audit` table |
| `ddns.rs` | dyndns2 endpoint |
| `api/` | native JSON API: `record_view` (unified type-discriminated mapping), `zones`, `records`, `idempotency`, `openapi` (the **whole** OpenAPI document — native + CF + DDNS, hand-written) |
| `cfapi/` | Cloudflare facade (`/client/v4`) |
| `backend/` | `Backend` trait, `log` + `knot` impls, `worker` (journal drain), `zonefile` (BIND render) |
| `ops.rs` | `/healthcheck` + `/metrics` |
| `net.rs` | just two middlewares (source admission via `ip_src_allowed`/`ops_ip_src_allowed`, access log — the library ships no logging, so the request log is ours). Neither resolves an address — both read the `RealIp` extension `relativelylight::middleware::resolve_real_ip` fills at the outermost layer. CIDR rules are `relativelylight::net`'s `parse_nets`/`in_nets` (both families and the `::ffff:` form) |
| `metrics.rs` | Prometheus registry + instruments |
| `sso.rs` | build relativelylight `Sso` (OIDC) from config; login-page buttons |
| `web/` | the console, a plain MPA: `mod.rs` (page shell + the `get`/`post` handler pair behind `/admin/{entity}` + the login/profile/CSRF chrome + `/tz`), `entities.rs` (the CRUD engine: every managed entity's labels, help and validators), `dashboard.rs` (the landing page) |
| `templates/` | the two askama templates the app owns: `shell.html` (the only `<html>` in the tree) and `dashboard.html` |
| `zoneimport.rs` | BIND zone-file parser for `admin import` |

## Design invariants — keep these

- **The app owns the roots.** Since library 0.3 `relativelylight` contributes **no routes at all** —
  only HTML fragments and a write path. `app.rs` owns the axum router, `web/mod.rs` owns the page
  shell (Bootstrap 5's *stylesheet* plus `crud::ui::CSS`, and nothing else), and `api/openapi.rs`
  owns the whole OpenAPI document.
- **One name for the admin group.** `app::ADMIN_GROUP` drives `Auth::admin_group`, the
  console gate in `web/entities.rs`, the Superadmin decision in `authz::user_groups`, the first-start seed,
  and `--break-glass`. Never write the literal `"admin"` again — a mismatch mints an
  "admin" outside the group the gate checks.
- **A credential is its owner — nothing more.** `principal.rs` fills `Principal` from the *user*
  (groups + the Superadmin flag, read live from the DB); a bearer token contributes no rights and
  carries no level. To narrow a device, give the device its own account and grant, never a weaker
  key. If you find yourself adding a per-credential capability field, that is the L1/L2/L3 ladder
  growing back.
- **One authorization model, three surfaces, two predicates.** DDNS, the native API and the CF
  facade all resolve a `Principal` and then call `authz::zone_manager` (the whole zone: any type,
  any operation) or `authz::rr_manager` (create/update the A/AAAA at one name). Roles are nested
  scopes, not numbers — there is no arithmetic and no level column. The console is
  Superadmin-only via the library's `GroupReadWrite` gate. Never add a second authz path.
- **Successful writes are not rate-limited on any surface** — DDNS, the native API and the CF
  facade all trust an authenticated, authorized caller (this is a fleet's own server, not a public
  service), and the backend is protected structurally by the journal's per-zone coalescing. The one
  thing braked is *failed* credentials; `abuse`/`429` means a lockout, nothing else. Don't reintroduce
  a per-request budget without an operator-visible store and an whitelist — see the lockout tables
  for the shape that would take.
- **Credential checks go through `principal.rs`, which brakes them with the library's own
  counters.** `from_basic` / `from_bearer` / `from_token` consult `AppState::{usernames, ips}`
  (relativelylight's `auth::lockout`, from `Auth::username_lockout()` / `ip_lockout()`) *before*
  touching the secret, and record a rejection afterwards — that's also the only place the
  `auth_failures` metric is incremented, so don't re-count at the call site. **Never add a second
  limiter:** account failures share one DB row with the console login, which is what makes a
  lockout mean the same thing everywhere and makes "delete the row in the console" the unlock. A
  lockout is `AuthError::Locked(retry)`; each surface renders it in its own vocabulary (429 +
  `Retry-After`, `abuse` on DDNS). A request with no credential at all is *not* counted, and an
  *authenticated* check (the profile password) is not limited at all. If you add a credential
  source, route it through here.
- **The console is a multi-page app; keep it that way.** One `get` renders (`render_for`), one
  `post` on the *same path* writes (`submit`), and a write answers `303`. The view — page, sort,
  filters, search, which entity, which dialog is open — lives in the **query string** and nowhere
  else, so every screen is a link. There is no JSON between browser and server, no client-side
  state, and no script file: the only JavaScript the app ships is the shell's light/dark toggle
  (enhancement — without it the page is light) and Swagger UI on `/docs`, which is a viewer for the
  *machine* API, not part of the console. If you reach for `fetch`, you are rebuilding the thing
  0.3 deleted.
- **Both handlers must build the same panel.** `web::panel()` is a *function* for that reason: a
  link the read side renders has to be a write the post side accepts, and `submit` refuses an
  entity the panel doesn't list before it consults any gate. Never inline one of them.
- **Cookie-authenticated writes need the CSRF token.** relativelylight's own forms and
  the `crud` engine (`crud.csrf(auth.csrf())` in `web/entities.rs`) render and enforce it; app-owned
  cookie-auth posts must too — `keys.rs` is the worked example (`Csrf::hidden_input` from the token
  `Auth::profile_extra` hands it, verified with `Csrf::verify`).
  Bearer-authenticated surfaces are exempt by design, so `/api` and `/client/v4` stay
  header-only.
- **The library schedules nothing; the worker does.** `relativelylight` spawns no tasks, so
  `Auth::prune` (expired sessions on *both* clocks + expired lockout rows) is called hourly from
  `backend::worker`, next to the reconcile and full-resync passes. It is the **method**, not the free
  `auth::prune` — only the handle knows our `session_idle_secs`. Missing a prune is harmless
  — expired rows read as absent — so it stays best-effort.
- **One address, resolved once, at the edge.** `relativelylight::middleware::resolve_real_ip` is the
  **outermost** layer in `app.rs` (`Router::layer` wraps, so it is the last one added) and is
  *mandatory*: it puts the caller's canonical address in the request as `RealIp`, and the login
  lockout, `net.rs`'s two middlewares, every handler and every audit row read that one value. Never
  re-derive an address from headers — that is how a log line and the event it described came to name
  different clients. `config.trust_proxy` reaches exactly one place, the `TrustProxy` state on that
  layer; the server must serve with `into_make_service_with_connect_info::<SocketAddr>()`. A handler
  takes `RealIp(ip): RealIp` and gets an `IpAddr`, never an `Option` — a request whose source cannot be
  established is a `500` at the edge, not a guess downstream. A stranger topology (a CDN header) means
  writing a middleware that inserts `RealIp` itself, not a config knob.
- **Logging is ours, all of it.** relativelylight writes nothing to stdout or stderr and ships no access
  log — deliberately, so the app picks the shape. `net.rs` owns the request line: a `tracing` event, so it
  carries the query string (for `/nic/update` the query *is* the request), the User-Agent, and a level
  `config.debug` can move. Upstream's `examples/access_log` is the same fifteen lines if you need a
  reference. Don't reach for a library layer that isn't there.
- **Both password surfaces or neither.** `config.password_level` feeds `Auth::password_policy` (the
  profile + manager pages) **and** the `password_hash` field validator on the admin user form
  (`web/entities.rs`). Wire a new one and you have created the documented way around the other. It governs typed
  input only — `admin reset-password` and the first-start seed must always be able to set a password.
- **Every mutation bumps the serial + enqueues a push.** RR/zone create+update go
  through SeaORM `ActiveModel::insert/update`, whose `after_save` hooks call
  `sync::*`. **Deletes fire no hook at all** — every delete path is a set-based
  `DELETE … WHERE` — so each one enqueues explicitly: the native API and CF through
  `record_view`, zone-delete in `api::zones`, and the console through
  `sync::Deletion::capture` + `apply` in `web::admin_save`. If you add a write path,
  keep this contract; a delete that skips it leaves the backend serving records the
  console says are gone, with no serial change to make any secondary notice.
- **Console deletes are handled by a write observer, not by the handler.** A delete
  through the crud engine fires no SeaORM hook, so `sync::DeleteSync` reads
  `WriteEvent::before_rows` — every row the delete removed, which relativelylight
  **0.3.1** added for this — and bumps + enqueues the zones they belonged to. Two
  details that fail **silently** if got wrong: the engine embeds a relation under its
  own name (`"zone": {"id": 7, …}`, never `zone_id` — hence `sync::zone_id_of` and its
  test), and the serial bump matters more than the push, because a re-push carrying an
  unchanged serial leaves every secondary on the old copy.
- **Two sinks, one hook.** `Crud::on_write` takes a single observer, so `web::entities`
  fans out to `audit` (records the write) and `sync::DeleteSync` (reacts to it). Keep
  them separate: recording and reacting are different jobs, and a failure in one must
  not swallow the other.
- **A delete audits one row per record.** `before_rows` is what makes that possible —
  before it, "delete selected" and "delete all matching" wrote a single row naming the
  *table* and nothing else, because a bulk delete has no `key` and no `before`. A log
  that cannot say what was deleted is not an audit log, and a record removed by mistake
  is exactly what someone comes to it to reconstruct.
- **The published APIs are ours, and they are the only ones.** The native API, the CF facade and
  DDNS are hand-written (unified type-discriminated records, opaque ids), and `api/openapi.rs`
  describes exactly those three — it is the whole document. The console has **no** API behind it;
  0.3 removed the generated CRUD wire that existed only to feed the old JavaScript. Don't publish a
  new surface to make a page work: a page is a handler.
- **Three surfaces, one set of numbers.** `/healthcheck`, `/metrics` and the dashboard all read
  `stats::Stats`, and "is anything wrong" is `Stats::warnings` — one predicate, so a WARN on the
  healthcheck and a red banner on the dashboard always mean the same thing. Add a number there, not
  in a handler. **The backend is asked once**: `Backend::status()` returns liveness *and* its own
  status line in one call, because on knot that call is a `knotc` subprocess and three consumers
  wanting a piece of it must not mean three spawns.
- **Counting is the database's job.** `stats::activity` asks the audit log for six windows with
  `WHERE ts >= ? GROUP BY source` — covered end to end by `ix_audit_ts_source` (`m0006`). Never
  fetch a day of rows to add them up in Rust: on a DDNS fleet that is the largest table in the
  deployment. If you add a window or a column, check `EXPLAIN QUERY PLAN` still says
  `COVERING INDEX`.
- **The Knot template is per zone, resolved in one place.** `zone.template` (nullable) wins, else
  `config.default_knot_template`; the **worker** does that fallback, because it is the one place
  holding both the zone row and the config, and `Backend::push_zone` takes an already-resolved name
  so no backend ever reads `Config`. Two consequences worth keeping: `ensure_declared` caches
  `(origin, template)` and **re-sets a zone whose template changed** — moving a zone onto a
  `dnssec-signing` template *is* how signing is switched on, so an origin-keyed cache would silently
  make the feature a no-op; and "ours" for orphan pruning is `default_knot_template` ∪
  `knot_templates`, so a zone under an unlisted template is never deleted and never recognised.
- **Both template surfaces or neither.** `config.knot_templates` gates the console's zone form
  (`MetaField::options` in `web/entities.rs` — a `<select>` *and* a membership check) **and**
  `api::zones::parse_template`. Same shape as the password-policy invariant above: wire one and you
  have built the documented way around the other. Empty list = unrestricted on both, with
  `dns::check::template_name` as the syntactic floor on both.
- **A migration that adds a column must be guarded by `has_column`.** `m0001_init` builds its tables
  from the **live** entity definitions, so the moment a model gains a field, `m0001` starts creating
  it too — a fresh database then has the column before the `ALTER` step runs, and an unguarded
  `add_column` is a `duplicate column name` at boot. `m0003` and `m0007` are the worked examples.
- **A shipped migration is never renumbered.** `Migrator::migrations()` is the truth; the two
  `TODO-*.md` plans carry *proposed* numbers that go stale the moment anything else ships. Check the
  vec before picking one, and renumber the plan, not the code.
- **Records are one table per RR type**, generated by the `rr_entity!` macro. Add
  a type by adding a macro line + arms in `record_view`, `zonefile`, `zoneimport`,
  and the admin panel list.
- **Integers must match the column width.** The library's SeaORM backend was
  patched to coerce JSON integers to the column's actual width (i64 serials/
  timestamps). Keep timestamps `i64` (Y2038).

## Known gaps / deferred

- **SSO** is wired via relativelylight's `sso` module (`src/sso.rs` builds
  `relativelylight::auth::sso::Sso` from config; routes merged in `app.rs`). The
  config→library group-rule mapping is a subset: username-claim rules become
  global regex/equals username rules; other claims become exact-value rules
  (regex on a non-username claim is ignored). See `src/sso.rs`.
- **Native list pagination** reads the zone's rows then paginates in memory
  (correct; a DB-level cross-table optimization is deferred).
- **CORS** is still not added; the only network filter is the CIDR source-admission list
  (`ip_src_allowed`). Everything else on the old list of gaps has landed: real-ip resolution is the
  library's `resolve_real_ip` layer (see the invariant above), CSRF covers every cookie-authenticated
  write, and 0.2.0 brought re-auth before a password/2FA change, session invalidation after a password
  change, and TOTP recovery codes. Still missing, library-side: passkeys/WebAuthn, and re-auth through
  the IdP for SSO accounts (an SSO account has no local factor, so it passes the re-auth gate
  unchallenged — relativelylight `docs/AUTH.md` §5h states the limit).
- **Timezones are done** (this was the long-standing TODO). The DB and the APIs stay UTC; the
  console's navbar picker (`time::TzPicker`, offered zones from `config.timezones`) posts to `/tz`,
  which sets a cookie, and the **server** formats every timestamp with it — table cells, datetime
  inputs and the CSV export alike, so an export matches what is on screen. The picker only appears
  on pages rendered from a request: `login_shell` / `profile_shell` are handed a fragment and an
  identity, never the request, so those two pages are UTC.
- `relativelylight` is a **crates.io dependency** (`version = "0.3"`), which for a `0.x` crate is one
  compatible range: a patch release is picked up, a behaviour break bumps the minor and is not, and
  `Cargo.lock` pins the exact version regardless. We are on **0.3.0**, which re-homed the web UI in
  Rust: `Crud::new(db)` lost its mount path, `render()` became `async render_for(&headers, &state)`,
  writes need a `post` route calling `submit(&headers, ip, &body, &state)` (raw `Bytes` — a CSV
  import is a real file upload), `Table::format` takes a Rust closure instead of a string of
  JavaScript, `Auth::profile_extra` is handed a `ProfileSection` (identity **and** this request's
  CSRF token), `time::JS` is gone in favour of a server-side `Tz`, and the `openapi` feature, the
  JSON/metadata API and `Crud::into_router` no longer exist. **Reads are gated now** — `render_for`
  answers 401/403 itself rather than rendering rows a caller may not read. The 0.2.0 defaults it
  inherits are still in force: CSRF on the auth forms, the DB-backed login lockout, the mandatory
  `resolve_real_ip` layer, `set_password` as a reset plus `reset_admin_access` for break-glass, an
  empty input on a *nullable* column stored as `NULL`, `NOT NULL` columns enforced as `required` (a
  hook-stamped column must be `read_only`), and `#[non_exhaustive]` public types (build them from
  `Default` + setters, never a struct literal). Moving to `0.4` will be a read of the library's
  `CHANGELOG.md` §Upgrading and `docs/MIGRATION-*.md`, not a version bump.
- **Audit** is written by `audit.rs`, and **every path that writes or deletes app state goes through
  it** — there are exactly three ways in: the `WriteObserver` relativelylight fires for the admin
  auto-CRUD + auth handlers; `Audit::record` (DDNS/API/CF/`keys.rs`, principal + `RealIp` already
  resolved); and `Audit::record_local` for the paths with no request behind them (`admin import`,
  `admin reset-password`, the first-start seed, the retention pass), actored by the shell user with
  `auth_type: local`. `audit::SOURCES` is the vocabulary — add a surface, add it there, and it shows
  up in the console's column help. Rows land in the read-only `audit` table; retention is app-side
  (`audit_retention_days`, pruned at startup — and the prune audits itself, since it is the one thing
  that removes rows). What is *not* audited is machinery, not action: `sync_task`, the idempotency
  store, `last_used_at`, sessions, lockout counters. A future `admin` CLI to dump/clear the log is
  anticipated but not implemented.
- **There is no generic "audit every DB write" hook, on purpose.** SeaORM offers no connection-level
  write interceptor, and the per-entity `ActiveModelBehavior` hooks that do exist (`after_save`, used
  by `sync.rs`) see the row and nothing else — not the actor, not the auth type, not the client
  address, which is most of an audit row. They also don't fire for the bulk deletes every delete path
  uses. So auditing stays at the call site, where the principal is in scope, and the *contract* rather
  than a hook is what keeps it complete: a new write path calls `record`/`record_local` before it
  returns. **The `source` on a library-emitted event is stored verbatim** — the library names its own
  emitters (`observe::WriteEvent::source`, a `&'static str` at each emission site), teleddns names its
  own at the `record`/`record_local` call site, and nothing is translated in between. The `crud` →
  **`autocrud`** rename is relativelylight's own and **landed in 0.3**, so new rows say `autocrud`
  while rows written under 0.2.x keep `crud` — nothing rewrites them, which is why `audit::SOURCES`
  lists both and must go on doing so.
- **Input validation** lives in `dns::check` — typed field predicates built on
  `relativelylight::validate`, shared by the DDNS/native API/CF write paths, `admin import`, **and**
  the admin CRUD forms (wired via `MetaField::validate_str`/`validate_int` in `web/entities.rs`). Every
  name-shaped field composes the two primitives `check::dns_label` (one label) and
  `check::fqdn_hostname` (absolute name) — `record_label`, `ddns_hostname`, `target_name`,
  `hostname`, `zone_origin` are all thin wrappers, so all surfaces reject exactly the same junk. The
  bar is the **rendered zone file**: whitespace, newlines, commas, over-long labels or control
  characters must never reach the DB, or Knot rejects the zone on reload. The bar is *not* "must be
  a hostname" — `dns_label` takes the LDH set plus `_` **and `/`**, which is exactly what libknot
  renders unescaped, so **RFC 2317** classless reverse delegation (`0/27` as an owner, in a CNAME/NS
  target, and as a child zone's origin) is an ordinary name here. Knot writes that slash literally
  into the zone-file name too, so `backend::knot` creates the directory such an origin implies.
  Quoted rdata (CAA value, NAPTR flags/service/regexp) is capped at one 255-octet character-string by
  `check::char_string`; TXT is the exception — long values are legal and `backend::zonefile`
  splits them into 255-octet strings. Add a new RR field or type? Add its `check::*` validator
  (built on the primitives) and wire it on every surface: the `reg_rr!` macro in `web/entities.rs`, the
  `write_record` arm in `api/record_view.rs`, and the OpenAPI body doc in `api/openapi.rs`.

## Next release

The version in `Cargo.toml` is deliberately **not** bumped as features land; it is
set at release time in its own commit (see `Release 0.4.1`). What is queued:

- **`0.5.0`, and it must be a minor bump**: `knot_template` was renamed to
  `default_knot_template`, and `Config` is `deny_unknown_fields`, so an existing
  config file is a **hard startup error** until the operator edits it. That is the
  one genuine break in the queue — the relativelylight 0.3 / MPA work before it
  broke neither config nor database (only the console moved from `/` to
  `/admin/{entity}`, and the undocumented `/admin/api` CRUD wire was removed).
- Also worth saying out loud in the release notes: **the upgrade is one-way.** Once
  a migration has run, the previous binary refuses to start — `sea-orm-migration`
  errors with "Migration file of version '…' is missing, this migration has been
  applied but its file is missing". Rolling back means deleting that
  `seaql_migrations` row (and undoing whatever it did) by hand. True of every
  migration this project has ever shipped; it has just never been written down.

There is no `CHANGELOG.md`; the release commit message is the changelog.

## Conventions

SeaORM 1.1, axum 0.8, askama 0.13 (matching the library). `utoipa` is gone with the
OpenAPI generator — the document is `serde_json` in `api/openapi.rs`. Match the
surrounding terse, well-commented style; keep doc comments current (they carry
the contract). Errors on the API are `{ "error": … }` with the right status
(400/401/403/404/422/500); the CF facade uses the CF envelope. HTML the app
writes itself goes through `crud::ui::esc_str` (or an askama template, which
escapes for you) — never `format!` a database value straight into a page.
