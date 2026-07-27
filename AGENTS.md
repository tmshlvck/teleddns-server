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
back-office library (a **git dependency pinned to a release tag** in `Cargo.toml`; move
to a `version = "…"` crates.io pin once it's published). The library
provides the SeaORM CRUD engine + metadata, the auto-generated admin UI
(`crud::ui::Admin`), OpenAPI generation, and `auth` (users/groups/sessions/login/
profile, argon2id, TOTP, the `Authz` gate). Everything DNS-specific is app code.

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
| `keys.rs` | self-service API-key component (`section()` composed onto `/profile` via `Auth::profile_extra`; level-capped mint/revoke) |
| `sync.rs` | serial bump + push enqueue (called from RR/zone `after_save` hooks and write paths) |
| `audit.rs` | audit sink: `WriteObserver` for admin/auth writes + `record()` for DDNS/API/CF; writes the `audit` table |
| `ddns.rs` | dyndns2 endpoint |
| `api/` | native JSON API: `record_view` (unified type-discriminated mapping), `zones`, `records`, `idempotency`, `openapi` (paths supplement) |
| `cfapi/` | Cloudflare facade (`/client/v4`) |
| `backend/` | `Backend` trait, `log` + `knot` impls, `worker` (journal drain), `zonefile` (BIND render) |
| `ops.rs` | `/healthcheck` + `/metrics` |
| `net.rs` | just two middlewares (source admission via `allowed_networks`/`ops_allowed_networks`, access log). Addresses are `relativelylight::net`'s: `client_ip` (peer vs `X-Forwarded-For`, per `trust_proxy`), `parse_nets`/`in_nets` (CIDRs across both families and the `::ffff:` form) |
| `metrics.rs` | Prometheus registry + instruments |
| `sso.rs` | build relativelylight `Sso` (OIDC) from config; login-page buttons |
| `web.rs` | admin console (crud::ui::Admin), page shell (header username→`/profile`, footer docs/GitHub/copyright), login/profile styling |
| `zoneimport.rs` | BIND zone-file parser for `admin import` |

## Design invariants — keep these

- **The app owns the roots.** `relativelylight` contributes routes, HTML
  fragments, and OpenAPI schemas; `app.rs` owns the axum router, the page shell
  (Bootstrap + Alpine, required by the crud fragments), and the OpenAPI document.
- **One name for the admin group.** `app::ADMIN_GROUP` drives `Auth::admin_group`, the
  console gate in `web.rs`, the L3 decision in `authz::user_groups`, the first-start seed,
  and `--break-glass`. Never write the literal `"admin"` again — a mismatch mints an
  "admin" outside the group the gate checks.
- **One authorization model, three surfaces.** DDNS, the native API, and the CF
  facade all resolve a `Principal` (session/Basic/bearer) and check
  `authz::allowed(token_level, effective, need)`. The operator console is L3-only
  via the library's `GroupReadWrite` gate. Never add a second authz path.
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
- **Cookie-authenticated writes need the CSRF token.** relativelylight's own forms and
  the `crud` engine (`crud.csrf(auth.csrf())` in `web.rs`) enforce it; app-owned
  cookie-auth posts must too — `keys.rs` is the worked example (hidden `_csrf` field
  filled from the token cookie by `CSRF_SCRIPT`, verified with `Csrf::verify`).
  Bearer-authenticated surfaces are exempt by design, so `/api` and `/client/v4` stay
  header-only.
- **The library schedules nothing; the worker does.** `relativelylight` spawns no tasks, so
  `auth::prune` (expired sessions + expired lockout rows) is called hourly from
  `backend::worker`, next to the reconcile and full-resync passes. Missing a prune is harmless
  — expired rows read as absent — so it stays best-effort.
- **Every mutation bumps the serial + enqueues a push.** RR/zone create+update go
  through SeaORM `ActiveModel::insert/update`, whose `after_save` hooks call
  `sync::*`. Bulk deletes bypass per-row hooks, so delete paths (native API, CF,
  DDNS, zone-delete) enqueue **explicitly**. If you add a write path, keep this
  contract.
- **The native API is hand-written** (unified type-discriminated records, opaque
  ids), not `relativelylight::crud` — that's the one place we don't auto-generate.
  The admin UI *does* use the library's per-entity CRUD (one table per RR type).
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
- **Admin-UI record/zone *deletes*** go through the library's bulk delete, which
  bypasses the `after_save` hook — a UI delete does not auto-enqueue a push
  (create/edit do). Delete via the API/DDNS, or re-save the zone, to force a push.
- **Native list pagination** reads the zone's rows then paginates in memory
  (correct; a DB-level cross-table optimization is deferred).
- **CORS + a trusted-proxy real-ip layer** are still not added; client-IP resolution
  is ours (`net.rs`, gated on `trust_proxy`) and the only network filter is the CIDR
  source-admission list (`allowed_networks`). CSRF *is* in place for every cookie-authenticated write (see the
  invariant above). Not yet (library-side): re-auth before a password/2FA change,
  session invalidation after a password change, TOTP recovery codes.
- **Admin timezone display (TODO, low priority).** The DB/API are UTC and the admin
  renders timestamps in UTC (relativelylight's `crud::ui::TIME_JS` + `TZ_PICKER_HTML`
  support UTC/browser-local/named zones — see relativelylight `docs/TIME.md`, not yet
  wired here). Consider a **server-timezone** option so the admin shows times in the
  host's zone, matching the Knot logs / syslog. Would mean: expose the server TZ (config
  or the host's `/etc/localtime`) via a tiny endpoint and set `$store.tz` from it on load.
- `relativelylight` is a **git dependency pinned to an exact commit** (`Cargo.toml`) —
  currently the **0.2.0 pre-release**, which turns the security defaults on: CSRF on
  the auth forms, the DB-backed login lockout (`Auth::new(db, Lockout {..})`),
  `set_password` as a reset (not an upsert) plus `reset_admin_access` for break-glass,
  and an empty input on a *nullable* column stored as `NULL`. Move the pin to
  `tag = "v0.2.0"` when it's cut, and to a crates.io `version` once published. See the
  library's `CHANGELOG.md` (§Upgrading) and `docs/AUTH.md` §5e/§7.
- **Audit** is written by `audit.rs`: it's the `WriteObserver` relativelylight
  fires for the admin auto-CRUD + auth handlers, and the DDNS/API/CF handlers call
  `Audit::record` directly. Rows land in the read-only `audit` table; retention is
  app-side (`audit_retention_days`, pruned at startup). A future `admin` CLI to
  dump/clear the log is anticipated but not implemented.
- **Input validation** lives in `dns::check` — typed field predicates built on
  `relativelylight::validate`, shared by the DDNS/native API/CF write paths, `admin import`, **and**
  the admin CRUD forms (wired via `MetaField::validate_str`/`validate_int` in `web.rs`). Every
  name-shaped field composes the two primitives `check::dns_label` (one label) and
  `check::fqdn_hostname` (absolute name) — `record_label`, `ddns_hostname`, `target_name`,
  `hostname`, `zone_origin` are all thin wrappers, so all surfaces reject exactly the same junk. The
  bar is the **rendered zone file**: whitespace, newlines, commas, over-long labels or control
  characters must never reach the DB, or Knot rejects the zone on reload. Quoted rdata
  (CAA value, NAPTR flags/service/regexp) is capped at one 255-octet character-string by
  `check::char_string`; TXT is the exception — long values are legal and `backend::zonefile`
  splits them into 255-octet strings. Add a new RR field or type? Add its `check::*` validator
  (built on the primitives) and wire it on every surface: the `reg_rr!` macro in `web.rs`, the
  `write_record` arm in `api/record_view.rs`, and the OpenAPI body doc in `api/openapi.rs`.

## Conventions

SeaORM 1.1, axum 0.8, askama 0.13, utoipa 5 (matching the library). Match the
surrounding terse, well-commented style; keep doc comments current (they carry
the contract). Errors on the API are `{ "error": … }` with the right status
(400/401/403/404/422/500); the CF facade uses the CF envelope.
