# teleddns-server — Rust rewrite plan

Re-implement [`PRD.md`](PRD.md) in **Rust**, built on the
[`relativelylight`](../relativelylight) back-office library (path dependency to the
in-tree development copy). This document is the working plan: architecture,
module layout, what the library gives us vs. what we build, and the milestone
sequence. It supersedes the Go implementation, which is removed on this branch.

**Status:** M0–M8 are **done** (scaffold, model + admin UI, authz + API keys,
backend + worker + zonefile, DDNS, native API, CF facade, operability, docs) and
verified end-to-end against the `log` backend; the `knot` backend is implemented
and documented in [`DEPLOY.md`](DEPLOY.md). M9 (OIDC SSO login) is deferred — its
config is parsed today. See §11 for the per-milestone detail and §12 for gaps.

## 1. Goals & constraints

- **Faithful to the PRD.** Same wire contracts (dyndns2 vocabulary, native API
  shapes, Cloudflare facade, Knot `knotc` protocol, `/healthcheck` + `/metrics`).
  A dyndns2 client, cert-manager, or external-dns pointed at the Rust server must
  not notice the reimplementation.
- **Lean on `relativelylight`** for everything it already does: the SeaORM CRUD
  engine + metadata, the auto-generated admin UI (`crud::ui::Admin`), OpenAPI
  generation, and `auth` (users/groups/sessions/login/profile, argon2id, TOTP,
  the `Authz` gate).
- **Build the DNS-specific parts ourselves** on top of the same axum + SeaORM
  stack: the DDNS endpoint, the native + CF management APIs, the L1/L2/L3
  authorization, bearer API keys, and the Knot backend + sync worker.
- **The app owns the roots** (router, page shell, OpenAPI document), per the
  library's composition contract. The library contributes routes, HTML fragments,
  and schemas.
- Single static-ish binary; SQLite for single-node, PostgreSQL for larger installs.

## 2. Stack

| Concern | Choice |
|---|---|
| Language / async | Rust 2021, `tokio` multi-thread |
| HTTP | `axum` 0.8 (matches the library) |
| ORM | `SeaORM` 1.1 (`sqlx-sqlite` + `sqlx-postgres`, `runtime-tokio-rustls`) |
| Back-office | `relativelylight` (path `../relativelylight/relativelylight`), features `crud, axum, ui, openapi, csv, auth` |
| OpenAPI | `utoipa` 5 (our own paths + `crud::openapi::merge_into`) |
| Templates (shell only) | `askama` 0.13 |
| Config | `serde` + `serde_yaml`, layered defaults→file→env→flags (`clap` for flags/subcommands) |
| DNS parsing/validation | `hickory-proto` (name grammar, zone-file parse for import) or hand-rolled per-type validators; decide in M1 |
| Metrics | `prometheus` (or `metrics` + exporter) — text exposition |
| Passwords / tokens | argon2id via `relativelylight::auth`; SHA-256 (`sha2`) for API-key hashing |
| Logging | `tracing` + `tracing-subscriber` (structured lines, one per request + audit) |
| OIDC (SSO) | `openidconnect` crate — **deferred** to a later milestone (see §11) |

## 3. What the library gives us vs. what we build

**From `relativelylight` (reuse, no per-model code):**

- `auth`: `rl_user` / `rl_group` / `rl_user_group` / `rl_session` tables, argon2id
  hashing, `Auth::identify(&headers) -> Option<Identity>`, login/logout/profile
  routes (incl. TOTP 2FA), `admin_group`, the `Authz` gate trait + presets.
- `crud`: `MetaModel::new(entity)` introspection, JSON CRUD engine, metadata,
  OpenAPI, CSV — used to drive the **operator admin console** over our SeaORM
  entities.
- `crud::ui::Admin` / `Table`: the server-rendered admin fragments (Bootstrap +
  Alpine), rendered per-request with `render_for`.

**We build (app code):**

1. **DNS domain model** — `zone` + one SeaORM entity per RR type (§5). These
   register into `relativelylight` for the admin UI for free.
2. **Bearer API keys** — an `api_key` entity + a resolver that turns
   `Authorization: Bearer <key>` into an authenticated principal *with a level*
   (the library's session identity has no level/token concept).
3. **The L1/L2/L3 authorization module** (§6) — row/scope-aware, beyond the
   library's header-only per-model gate. Shared by DDNS, native API, CF API.
4. **The DDNS endpoint** (dyndns2) — custom handlers (§7.1).
5. **The native management API** — unified, type-discriminated records with opaque
   ids, pagination, idempotency (§7.2). Custom handlers + `utoipa` paths (this
   shape is intentionally *not* the library's per-entity CRUD).
6. **The Cloudflare facade** (§7.3).
7. **The Knot backend + sync worker + push journal** (§8).
8. **Config, migrations, metrics, healthcheck, CLI, zone-file import** (§9).

> **Why the native API is not `relativelylight::crud`:** the library serves one
> endpoint set per entity (`/api/v1/{entity}`) with a flat per-table row. The
> native API deliberately presents a *single* record resource keyed by an opaque
> `type`-prefixed id over the many per-type tables, with `Idempotency-Key` replay
> and DB-level `?type`/`?name` filters. We hand-write it. The **admin UI** uses the
> library's per-entity CRUD (one table per RR type), which is the natural fit there.

## 4. Crate & module layout

Single binary crate (workspace-friendly). Proposed layout:

```
Cargo.toml
src/
  main.rs            CLI dispatch (serve | version | admin reset-password | admin import)
  config.rs          Config struct, layered load, defaults
  app.rs             AppState, router composition, server bootstrap
  db.rs              connection, migrations runner
  model/
    mod.rs
    zone.rs          zone entity (SOA inline)
    rr/              one module per RR type (a, aaaa, ns, ... ) + a shared trait
    api_key.rs
    zone_role.rs     L2 grant (group ↔ zone)
    rr_role.rs       L1 grant (group ↔ zone,label)
    sync_task.rs     push journal
    idempotency.rs
    audit.rs         structured audit emit helper
  authz.rs           Level, effective(), required(), the min() cap, gates for the admin UI
  principal.rs       identify a request: session (library) OR bearer API key → Principal{ user, groups, level, source }
  ddns.rs            dyndns2 endpoint
  api/
    mod.rs           native API router + utoipa paths
    zones.rs  records.rs  idempotency.rs
    record_view.rs   the unified type-discriminated record <-> per-type row mapping
  cfapi/
    mod.rs zones.rs records.rs   Cloudflare facade
  backend/
    mod.rs           Backend trait, selector (log | knot)
    log.rs           no-op backend
    knot.rs          zone-file render + knotc driver
    worker.rs        journal drain, coalesce, retry, sweep
    zonefile.rs      BIND zone-file rendering (byte-faithful)
  admin_ui.rs        build the crud::ui::Admin panel over our entities
  ops.rs             /healthcheck + /metrics
  metrics.rs         counters/gauges/histograms
  ratelimit.rs       per-token / per-(user,hostname) limiter
  sso.rs             OIDC (deferred; stub + config parsing first)
  ratelimit.rs
migrations/          SeaORM migration crate or inline migrator
```

## 5. Data model (SeaORM entities)

All entities use a single-column integer PK and single-column FKs, per the
library's requirement, so each registers for the admin UI with `MetaModel::new`.

- **`zone`** — `id`, `origin` (unique, trailing dot) + SOA columns (`mname`,
  `rname`, `serial`, `refresh`, `retry`, `expire`, `minimum`, `ttl`). No owner
  column, no sync columns.
- **RR tables** — one per type in the PRD §5.2 table. Common columns `id`,
  `zone_id` (FK), `label`, `ttl`; then the type-specific rdata columns. A shared
  Rust trait `Rr` provides `type_tag()`, `render_bind(origin)`, `validate()`, and
  conversion to/from the unified API view. The DDNS path only touches `a` / `aaaa`.
- **`api_key`** — `id`, `user_id` (FK → `rl_user`), `name`, `hashed_key`
  (sha256 hex), `prefix`, `level` (1–3), `expires_at` (nullable), `last_used_at`
  (nullable), `disabled`.
- **`zone_role`** — `id`, `group_id` (FK → `rl_group`), `zone_id` (FK → `zone`);
  unique `(group_id, zone_id)`. L2.
- **`rr_role`** — `id`, `group_id` (FK → `rl_group`), `zone_id` (FK → `zone`),
  `label`; unique `(group_id, zone_id, label)`. L1.
- **`sync_task`** — `id`, `origin`, `kind` (`zone` | `zone-remove`), `state`
  (`pending` | `in_flight` | `done` | `failed`), `attempts`, `available_at`,
  `created_at`, `updated_at`. Index on `(state, available_at)`.
- **`api_idempotency`** — `key`, `user_id`, `request_hash`, `status`,
  `response_body`, `created_at`. TTL-swept at 24 h.

Auth tables (`rl_user`, `rl_group`, `rl_user_group`, `rl_session`) are owned by
`relativelylight::auth` — we run its migrator and never redefine them. The
`rl_user` model already carries `totp_secret` / `totp_pending` (2FA) and
`is_active`. Cross-entity SeaORM relations (`api_key` → `rl_user`, `zone_role` →
`rl_group`, etc.) are declared so the admin UI shows group/user pickers.

**Migrations.** A startup migrator: run `auth::migrate` for the library tables,
then our own migrations (SeaORM `migration` crate or `create_table_from_entity`
for a fresh DB + explicit versioned steps thereafter). Append-only. Seed an
`admin` user + `admin` group on first run and log the generated password once.

## 6. Authorization (`authz.rs` + `principal.rs`)

The heart of the port. Two layers:

**Principal resolution (`principal.rs`).** Given request headers, produce a
`Principal`:

```rust
struct Principal {
    user_id: i32,
    username: String,
    groups: Vec<String>,   // group *names* (for admin check) + ids (for grant lookup)
    token_level: Level,    // L3 for a session/Basic login; the key's level for a bearer token
    source: Source,        // Ddns | Api | Cfapi | Ui
}
```

- **Session** (operator UI): reuse `Auth::identify(&headers)` → `Identity`; a
  session principal has `token_level = L3` (its effective level still caps it).
- **HTTP Basic** (DDNS only): verify username+password via
  `auth::verify_password`; **reject** users with TOTP/SSO/passkey (they must use a
  token) → `badauth`. `token_level = L3` (capped by effective).
- **HTTP Bearer** (DDNS, native API, CF): sha256 the key, look up `api_key`,
  check enabled + not expired, load the owner + groups, `token_level = key.level`,
  bump `last_used_at`.

**Access decision (`authz.rs`).** Pure functions over the principal + target:

```rust
enum Level { L0, L1, L2, L3 }   // ordered

fn required(action, target) -> Level { … }          // PRD §3.3
async fn effective(db, principal, zone, label) -> Level {
    if principal.in_group(admin_group) { return L3 }
    if zone_role_exists(group_ids, zone) { return L2 }
    if rr_role_exists(group_ids, zone, label) { return L1 }
    L0
}
fn authorized(principal, effective, required) -> bool {
    min(principal.token_level, effective) >= required
}
```

`UserMaxLevel` (for the token-mint level cap in the profile UI) = L3 for admins,
else the highest role level the user holds anywhere. Computed on demand.

**Admin console gating.** The `crud::ui::Admin` panel and its per-entity API are
registered with a library gate = `AdminOnly::new(&auth, ["admin"])` (L3). This
matches the PRD: the full admin console is L3; non-admin users act through the
DDNS/API surfaces and the self-service profile. (Per-zone UI editing for L1/L2
users is via the API, not the console — same as the original.)

## 7. Request surfaces

### 7.1 DDNS (`ddns.rs`)
Three GET routes (`/nic/update`, `/ddns/update`, `/update`); 405 on other methods.
Parse `hostname`/`myip`/`myipv6`; longest-origin zone match → `(zone, label)`;
per-family update semantics (PRD §2). Auth = Basic or Bearer via `principal.rs`.
Rate-limit per token and per `(user, hostname)`. Emit dyndns2 body + status,
combine two families with the worst code. Bump SOA + enqueue `sync_task` in the
mutation transaction. Audit line with `source=ddns` + User-Agent.

### 7.2 Native API (`api/`)
Bearer-only (Basic → 401). `utoipa`-annotated handlers, merged into the app's
OpenAPI document alongside the library's admin-entity schemas.

- Zones: `GET/POST /api/zones`, `GET/PUT/DELETE /api/zones/{id}` (L2 read/update,
  L3 create/delete; create auto-SOA + apex NS).
- Records: unified view `{id, type, name, ttl, …rdata}`, opaque `type`-prefixed id
  (`a-12`). `record_view.rs` maps the view ↔ the correct per-type table. A/AAAA
  read+update L1; else L2. Pagination (`X-Total-Count`, `page`/`per_page`,
  `type`/`name` filters pushed to SQL). `Idempotency-Key` replay (24 h; different
  body → 422). Mutations share the SOA-bump + journal-enqueue + last-apex-NS-guard
  path with the UI.

### 7.3 Cloudflare facade (`cfapi/`)
`/client/v4` with the CF envelope + record shape; `GET /zones[?name=]`,
`GET/POST /zones/{id}/dns_records`, `GET/PUT/PATCH/DELETE
/zones/{id}/dns_records/{rid}`, `GET /user/tokens/verify`. Auth via `Bearer` or
`X-Auth-Key`. Types A/AAAA/CNAME/TXT/NS/MX. Reuses the native validation + write
path. `source=cfapi`.

### 7.4 Operator UI (`admin_ui.rs`)
Compose `crud::ui::Admin` over: `zone`, each RR type, `api_key`, `zone_role`,
`rr_role`, and (manager-only) `rl_user` / `rl_group`. Gate L3. The app owns the
shell (askama) + navbar + login/profile wrapping (`login_shell` / `profile_shell`)
exactly as the adminpanel example does. API-key minting lives on the profile page
(self-service, level-capped) — implemented as an app page since the library's
profile page doesn't manage app tokens.

### 7.5 Operability (`ops.rs`)
`/healthcheck` (always 200; `OK`/`WARN` first token; PRD §8.1) and `/metrics`
(Prometheus text; PRD §8.2), both behind `ops_allowed_ips` on top of `allowed_ips`,
after the real-IP rewrite.

## 8. Knot backend (`backend/`)

- `Backend` trait: `push_zone(origin)`, `remove_zone(origin)`, `probe()`.
- `log` backend: logs the rendered zone; `probe` → `na`.
- `knot` backend: render full BIND file to `<knot_zone_dir>/<origin>.zone`; on
  first push declare the zone (`knotc conf-begin/conf-set …/conf-commit`, cached);
  `knotc zone-reload`; `remove_zone` → `conf-unset` + unlink; `probe` → `knotc
  status`. Shell out to `knotc_path` via `tokio::process`.
- `worker.rs`: single task draining `sync_task` — coalesce per origin (debounce
  `backend_sync_delay`), at-least-once (reset in-flight on boot), idempotent full
  regen, exponential backoff + jitter (cap ~1 h), dead-letter after ~20 attempts,
  safety-net sweep every `backend_sync_period`. Feed metrics + `last_tick`.
- `zonefile.rs`: byte-faithful BIND rendering (SOA header from the zone row, then
  every RR via its `render_bind`). Must pass `kzonecheck`.

## 9. Config, CLI, migrations

- `config.rs`: the PRD §9 keys; layered defaults→file→env→flags; file lookup
  `-c` → `$TELEDDNS_CONFIG` → `./teleddns-server.yaml` → `/etc/teleddns/…`.
- `main.rs` subcommands: `serve` (default), `--version`, `admin reset-password
  <user>`, `admin import [--replace] [--origin O] <file|->`.
- Migrations run on startup; fresh DB stamped at latest.

## 10. Testing

- **Unit:** per-type RR validation + BIND render (golden strings from the Go
  `docs/DESIGN.md` table); zone/label longest-match; `authz` decision table
  (min-cap matrix); dyndns2 status mapping; CF ↔ native mapping; zone-file import.
- **Integration (axum `oneshot`):** DDNS create/nochg/update/!yours/nohost/abuse;
  native API CRUD + pagination + idempotency; CF facade happy paths + `verify`;
  admin console gating (401/403); healthcheck/metrics.
- **Backend:** `log` backend end-to-end; `knot` backend behind a fake `knotc`
  script asserting the exact `conf-set`/`zone-reload` calls; worker
  coalesce/retry/dead-letter with a controllable clock.
- **Manual/verify:** run against a real Knot 3.x in `DEPLOY.md` (kdig serves the
  records), like the Go version's verification.

## 11. Milestones (commit after each)

1. **M0 — scaffold.** Remove Go code; `Cargo.toml` with the path dep; `main.rs`
   that loads config, connects the DB, runs `auth::migrate`, serves an empty
   router + `/healthcheck`. Builds and runs. ✅ commit.
2. **M1 — model + migrations + admin UI.** All SeaORM entities; migrator; seed
   admin; wire `crud::ui::Admin` (L3) + login/profile. Zones + records editable in
   the browser. ✅ commit.
3. **M2 — authz + principal + API keys.** `Level`/`effective`/`required`/min-cap;
   session + Basic + Bearer principal resolution; `api_key` minting on the profile
   page (level-capped). Unit tests for the decision table. ✅ commit.
4. **M3 — backend + worker + zonefile.** `log` + `knot` backends, journal, worker,
   BIND render; SOA bump + enqueue wired into model mutations. Fake-`knotc` tests.
   ✅ commit.
5. **M4 — DDNS endpoint.** Full dyndns2 semantics + rate limiting + audit; drives
   the backend. Integration tests. ✅ commit.
6. **M5 — native API.** Zones + unified records, pagination, idempotency, OpenAPI
   merged, docs page. ✅ commit.
7. **M6 — Cloudflare facade.** `/client/v4` + `verify`; cert-manager/external-dns
   shapes. ✅ commit.
8. **M7 — operability + polish.** `/metrics`, full `/healthcheck`, `allowed_ips` /
   `ops_allowed_ips` / `trust_proxy`, zone-file import CLI, `--version`. ✅ commit.
9. **M8 — docs.** README.md, AGENTS.md/CLAUDE.md, then DEPLOY.md once verified
   against Knot. ✅ commit.
10. **M9 (deferred) — OIDC SSO.** `public_url` + `sso_providers`, rule-based group
    provisioning. Config parsing lands earlier (M1) as inert; the callback + rule
    engine land here. Depends on `relativelylight` OIDC support or an app-local
    `openidconnect` integration.

## 12. Known gaps & risks

- **OIDC SSO** is not yet in `relativelylight` (planned there). We parse its config
  from the start but implement the flow app-side (M9) or wait for library support.
  Until then, local login + tokens cover all surfaces.
- **Row-level authz** is explicitly out of scope in the library's gate; our L1/L2
  checks live in app code on each surface, not in the library gate (the admin
  console stays L3-only, as in the original).
- **The native API is hand-written**, not generated — the one place we duplicate
  CRUD-ish plumbing, justified by the unified type-discriminated shape.
- **`relativelylight` is v0.0.0** (in-tree dev copy). We pin the path dependency and
  adapt if its API shifts; the composition surface we depend on (`Auth`, `Crud`,
  `Engine`, `crud::ui::Admin`, `crud::openapi`) is documented and stable enough.
- **2FA/passkey** enforcement on DDNS Basic auth depends on reading the library's
  `rl_user` 2FA columns; passkeys aren't in the library yet, so "has passkey" is a
  future check (TOTP is present today).
