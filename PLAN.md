# TeleDDNS Server — Go Rewrite Implementation Plan

Status: **draft / prototype phase**. Source of truth for *behavior* is
[`PRD.md`](PRD.md). This document is the source of truth for *how we build it*
in Go: tech stack, module layout, and a phased milestone plan.

The legacy Python implementation lives in `obsolete/` (gitignored, kept on
disk for reference only).

---

## 1. Tech stack

| Concern | Choice | Notes |
|---|---|---|
| Language / toolchain | Go 1.26 | matches `gone` (`go 1.26.3`). |
| Building blocks | **`github.com/tmshlvck/gone@v0.1.0`** | chi + GORM + HTMX CRUD admin + auth stack. Local checkout at `../gone`. |
| HTTP router | **chi v5** | what `gone` registers routes onto; everything mounts here. |
| ORM | **GORM v2** | `gone` derives its CRUD admin from GORM models via reflection. |
| DB engines | **SQLite + Postgres** | SQLite via pure-Go `glebarez/sqlite` (already a `gone` dep); Postgres via `gorm.io/driver/postgres`. Engine chosen from the configured DB DSN. |
| Templates / UI | **templ + DaisyUI/Tailwind + HTMX 2** | `gone` emits HTML *fragments*; the app owns the page shell (`site.Shell` / `PageShellFunc`). |
| Auth | **`gone/auth` (`AuthGORM`)** | reuse `UserGORM`/`GroupGORM`, password (argon2id) + TOTP + passkeys + SSO already implemented. Sessions via `scs`, CSRF via `auth.CSRFWrap`. |
| API framework | **Huma v2** (`humachi` adapter) | auto-OpenAPI 3 + JSON Schema for the DDNS + management/record APIs. Bearer + Basic security schemes. |
| Logging | **`log/slog` + `github.com/go-chi/httplog/v3`** | one `*slog.Logger`; level driven by the `--debug` flag. `httplog.RequestLogger` auto-maps status→level (5xx ERROR, 4xx WARN, 429/normal INFO, OPTIONS DEBUG). Use `httplog.SetAttrs` to attach actor/source-IP to request logs. |
| Migrations | **GORM `AutoMigrate`** for v1 | revisit a versioned tool (e.g. `goose`/`atlas`) before first real deployment; legacy used Alembic. |
| Config | hand-rolled `Config` struct | see §3. Loaded from file + env + flags. |

### gone integration notes (current `main`, ≥ 0.1.1)
- gone uses a single shared **`site.Shell`** page-chrome type everywhere
  (`auth.PageShellFunc` was removed) — auth + admin `RegisterRoutes` both take
  `site.Shell`.
- **Admin sidebar is one ordered `[]crud.SidebarElementInterface`** (0.1.1):
  interleave `*CRUDTable`s with `crud.SidebarHeader` / `crud.SidebarSeparator`
  / `crud.SidebarLink`.
  `CRUDTable.Segment` is **gone** — a table's URL slug is derived from the Go
  type name (`lowercase(name)+"s"`, e.g. `UserGORM`→`usergorms`, `RRA`→`rras`,
  `Zone`→`zones`). The sidebar *label* is the `DisplayName`. So slugs are ugly
  but stable; the password-modal target id is `admin-usergorms-modal-l1-body`.
- The app owns all CSS. Our `web` shell adopts gone's `admin_gorm` example
  polish: the focus-outline/font-smoothing `<style>` block and
  `site.ThemeToggle("light","dark")` in the header.
- `crud.ObserveAccessor` is the hook for scheduling backend pushes, not just
  audit — see M2.

### Decisions locked in
- **Deployment: co-located, master-only, Knot-only.** teleddns-server runs on
  the DNS host and manages the **local Knot** as **master**. There is no
  remote-backend `Server` table; the local Knot connection is app `Config`.
- **Replication: native DNS, not app-to-app.** Master→slave is **AXFR/IXFR +
  NOTIFY**, authenticated with **TSIG** (RFC 8945). The backend generates a
  **catalog zone (RFC 9432)** so slaves **auto-provision** member zones — no
  teleddns↔teleddns API, no slave-zone table here. Slaves are plain Knot
  instances consuming the catalog.
- **Slaves + TSIG: global, in `Config`.** A uniform slave list + TSIG keys live
  in `Config` (no DB tables) — the catalog zone applies them to every zone.
- **Sync: task-log journal.** A zone/RR change enqueues a `SyncTask` in the
  same DB transaction; an executor goroutine coalesces per zone, regenerates
  the full zone + reloads Knot, marks `done`, and keeps rows as a journal
  (retry + backoff + dead-letter). Replaces any per-zone dirty flag (M5).
- **RR storage: one GORM table per RR type** — maps 1:1 to `crud.CRUDTable[T]`
  reflection; flat structs (gone reflection ignores embedded fields).
- **CLI: `spf13/pflag`** — GNU `-c, --config` / `-d, --debug` (combined help,
  `--config=x`); single-dash long names are intentionally not accepted.

### Decision still to confirm
- **Record/management API blueprint.** Recommended split plane — native REST
  (PRD §11) for management (zones, users, groups, tokens, roles) + a
  **Cloudflare-compatible record-CRUD facade** (`cfapi/`) for third-party
  tooling (external-dns, cert-manager, acme.sh/lego, libdns, OctoDNS). This API
  is for *clients/tooling only* — no peer replication. Not yet final.

---

## 2. Module layout (proposed)

Flat, intentionally small — grow it only when a concern actually needs its
own package.

```
teleddns-server/
  go.mod                module github.com/tmshlvck/teleddns-server
  cmd/teleddns-server/  entrypoint, CLI subcommands, slog/httplog setup, server wiring
  model/                everything data-shaped:
                          • DB models — User ext/APIKey, Zone + SOA fields,
                            one table per RR type, TSIGKey, ZoneSlave (ACL),
                            GroupZoneRole/GroupRRRole, PendingPush
                          • config model — Config struct + loader (satisfies
                            gone's site.Settings)
                          • temporal model — the scheduler / update loop +
                            PendingPush worker
                          • authz level logic (PRD §9.6) + BIND zonefile render
  web/                  page shell + gone CRUD admin wiring + auth (AuthGORM,
                        sessions, CSRF, login, preferences + API-key management)
  ddns/                 DDNS update endpoint (Huma): auth, zone/label resolve, semantics
  knot/                 Knot backend: render zone files + knot.conf (zones,
                        templates, ACLs, TSIG, catalog zone), reload via knotc
  api/                  native management JSON API (Huma, bearer)
  cfapi/                Cloudflare-compatible record facade (for client tooling)
```

**Build order:** start with `model/`, `web/`, `ddns/`, `knot/`; add `api/`,
`cfapi/` (and split anything out of `model/`) as we reach them. No `bind/` and
no peer/secondary package — Knot-only, and slaves replicate via DNS, not us.

Local sibling references (not vendored): `../gone` (library), `../teleddns`
(existing Rust DDNS client — compatibility target), `obsolete/` (old Python).

---

## 3. Config struct (first concrete step)

A single app-owned `Config` that also satisfies `gone`'s `site.Settings`
interface (= `TimeFormatter` + `PaginationSettings`):

```go
type Config struct {
    DBDsn        string   // "sqlite:///path/teleddns.db" or "postgres://…"; engine inferred
    ListenAddr   string   // e.g. ":8080"
    AllowedIPs   []string // CIDRs allowed to reach the server; empty = all
    TrustProxy   bool     // honor X-Forwarded-For / X-Real-IP / X-Forwarded-Proto (PRD §3.10)
    // (M5) local Knot backend connection: knotc path / control socket, catalog
    // zone name, etc. No slave/peer list — slaves replicate via DNS.
    DefaultTTL   uint32   // 3600 (PRD §5)
    DDNSRRTTL    uint32   // 60   (PRD §5)
    BackendSyncDelay   time.Duration // 10s  (debounce)
    BackendSyncPeriod  time.Duration // 300s (safety-net sweep)
    WarnOnNoUpdate     time.Duration // 7200s
    WarnOnNoPush       time.Duration // 3600s
    Debug        bool
    // embeds site.DefaultSettings → free TimeFormatter + PaginationSizeDefault();
    // override PaginationSizeDefault() to return 50 (PRD §11.1 default page size).
    site.DefaultSettings
}
```

- Loader precedence: defaults → config file (YAML) → env → flags.
- `AllowedIPs` enforced by a chi middleware mounted before everything else
  (using the real client IP per `TrustProxy`).

---

## 4. Milestones

Ordered to match the build sequence. Each milestone is independently runnable.

### M0 — Scaffolding
- `go mod init`, wire `../gone` (replace directive to local checkout during
  dev), chi router, `slog` + `httplog/v3`, graceful shutdown.
- `Config` (§3) load + validate; `AllowedIPs` middleware; `TrustProxy` real-IP.
- Boot an empty server with `/healthcheck` returning `OK uptime=…`.

### M1 — Auth + admin shell
- Wire `AuthGORM`: `UserGORM`/`GroupGORM`, sessions, CSRF, login (password +
  TOTP + passkey + SSO already in `gone`).
- App page shell (`site.Shell`): head/theme/nav (DaisyUI), HTMX, theme +
  timezone pickers from `gone/site`.
- Mount `gone` CRUD **Admin** over users/groups (L3 only).
- **API keys** extending the user model (done): `model.APIKey` table +
  `KeyStore` (SHA-256 hash, prefix, `Level`, expiry, disabled; `Issue` /
  `Validate` / `List` / `Revoke`) — per `gone/docs/HOWTO-BEARER-TOKENS.md`.
  Managed on the `/preferences` page (app-owned card below gone's
  `AccountSection` cards): list, issue with one-time raw-key banner, revoke,
  all CSRF-protected. New keys are L1 until the authz model (M3) adds the
  user-max cap + level picker. The `BearerAuth` middleware + `apiAuth` wrapper
  from the HOWTO are deferred to their consumers — DDNS (M4) and the JSON API
  (M6) — as thin callers of `KeyStore.Validate`.
- **CLI subcommands** (`cmd/teleddns-server`):
  - `serve` (default) — run the server.
  - `admin reset-password <username>` — reset/seed the admin password.
  - `--debug` global flag → slog level Debug + httplog verbose.
  - (later) `import-legacy` one-shot from old SQLite (PRD §13.5).

### M2 — DNS data model + admin
- GORM models: `Zone` (origin + 10 SOA fields + `master`/sync-tracking
  columns), one table **per RR type** (PRD §4.2 fields + validators), `Server`
  (backend host). Roles: `GroupZoneRole` (L2), `GroupRRRole` (L1).
- Per-type field validation (PRD §4.2) as `gone/crud` validators.
- Zone creation auto-generates SOA + default NS (PRD §4.1/§11.3); SOA serial
  auto-increment on mutation; reject deletes orphaning SOA/all-NS.
- Wire each model into the `gone` Admin as a `CRUDTable`.
- **Audit + push scheduling via one chokepoint.** Wrap the Zone/RR accessors
  with `crud.ObserveAccessor` (covers the admin UI, the management API, *and*
  CSV import — every mutation funnels through `Accessor.Data`). The callback
  emits the structured slog audit record (actor, source IP, verb, target,
  before/after; tagged `source=ui`/`api`/`ddns`) **and** schedules the backend
  push (bump SOA + enqueue `PendingPush`) — see M5. The DDNS handler doesn't
  go through the CRUD accessor, so it enqueues explicitly. Callback must not
  block: send to a buffered channel with a `default` drop.

  M2 status: audit logging is wired (`source=ui`); the **push-scheduling**
  half of the callback is a TODO until `PendingPush` lands in M5.
- **Done in M2:** all 14 RR tables + Zone + role grants with validators, wired
  into one grouped admin sidebar (Accounts / DNS / Records / Access); SOA
  defaults + auto apex-NS on zone create; SOA-serial bump on every RR change
  (path-independent GORM hooks); last-NS delete guard; audit observer. Model
  trimmed to essentials — no Server table, no owner / dirty / sync / per-row
  audit columns; slaves + TSIG moved to `Config`; sync state will live in the
  `SyncTask` journal (M5). Unit + HTTP e2e tested.
- **Deferred:** zone-delete cascade (deleting a Zone currently orphans its RR
  rows — add FK `OnDelete` or a `BeforeDelete` sweep); per-zone RR editor UX
  (the 14 per-type admin tables are functional but clunky — a nicer per-zone
  view is operator-UI scope).

### M3 — Authorization model (PRD §9)
- `required_level(action, target)` + `user_effective_level(user, target)` +
  `authorized = min(token.level, user_level) >= need`.
- Token carries its own `level` (cap = user max). Effective scopes from
  `GroupZoneRole`/`GroupRRRole` unions; L3 = `is_superuser`.
- Expose as an `auth.Authz` impl so both the CRUD UI and the APIs reuse it.
- Port legacy `tests/test_ddns_auth.py` as the conformance harness.

### M4 — DDNS endpoint (PRD §8, legacy Part A)
- Plain chi handlers (not Huma) on `GET /nic/update`, `/ddns/update`,
  `/update` (POST→405) — dyndns2 is a plain-text, status-code protocol where
  Huma's JSON-schema/OpenAPI value doesn't apply; Huma is reserved for the
  JSON management/record API (M6).
- Basic **or** Bearer auth (Bearer wins); Basic rejected for TOTP/SSO/passkey
  users → `badauth`. Reuse `KeyStore.Validate` for bearer.
- Longest-suffix zone match → `(zone,label)`; `myip`/`myipv6` family detect;
  update semantics (no-op/update/converge-to-one); **no auto-create on DDNS**
  for L1 (`nohost`). SOA bump + enqueue push on change.
- dyndns2 `text/plain` body (`good`/`nochg`/`nohost`/`badauth`/`!yours`/
  `notfqdn`/`abuse`/`911`); transitional JSON `{detail}` mode behind a flag.
- Rate limiting (PRD §8.8): 60/h per record, 600/h per token → `429 abuse`.
- Port `tests/test_ddns_http_integration.py`.
- **Done in M4** (`ddns/`): the three GET endpoints (POST→405), Bearer-wins
  auth with Basic rejected for 2FA/SSO/passkey users, longest-suffix zone
  resolution, A/AAAA converge-to-one semantics with **no auto-create**
  (`nohost`), `myip`+`myipv6` combined (worst status), dyndns2 text responses,
  per-token + per-(user,hostname) rate limiting, and authorization via
  `model.EffectiveLevel` (`min(token.level, effective) ≥ 1`; L3 = admin-group
  membership since gone's `UserGORM` has no `is_superuser`). Mounted **outside
  CSRF**; the browser routes moved under a CSRF-wrapped chi group. Go unit
  tests + live e2e. The SOA serial bump rides the existing RR hooks.
  - **OpenAPI:** a Huma API is bootstrapped now (serves `/openapi.json`,
    `/openapi.yaml`, `/docs`, and an app-owned `/swagger` Swagger-UI page — all
    public). The chi-served DDNS endpoints are documented in the spec via
    `ddns.DocumentOpenAPI` (path-item injection, not Huma-handled). M6 registers
    the real JSON operations on the same API.
  - **Deferred:** transitional JSON `{detail}` response mode; wiring
    `last_update` into `/healthcheck`; the SyncTask enqueue (M5). The
    `EffectiveLevel` helper is the seed for M3's full model.

### M5 — Local Knot backend (PRD §12, Knot-only)
- `knot/`: render, from current DB state —
  - **zone files** in BIND format **byte-faithful to PRD §4.2** (must pass
    `kzonecheck`);
  - **`knot.conf`** fragments: zone blocks, templates, **ACLs + TSIG keys**
    (from `TSIGKey`/`ZoneSlave`), NOTIFY targets, and a **catalog zone**
    (RFC 9432) advertising the master zones so slaves auto-provision.
  - apply + reload via `knotc` (or the existing TeleAPI on localhost if kept).
- `SyncTask` journal appended **in the same transaction** as the mutation
  (via the RR `bumpZoneOnChange` hook + `Zone.AfterUpdate`); coalesced to one
  pending row per origin. In-process worker goroutine (single instance): ticks
  every `BackendSyncDelay`, claims due pending tasks, groups by origin,
  full-zone idempotent regen → `Backend.PushZone`, exponential backoff+jitter
  (cap 1h), dead-letter after 20 attempts; resets `in_flight` on startup.
- **Done in M5** (`knot/`): byte-faithful BIND zone rendering for SOA + all 14
  RR types (`RenderZone`); the `Backend` interface with a `log` default and a
  `knotc` impl (`<dir>/<zone>.zone` + `knotc zone-reload`); the `SyncTask`
  model + enqueue (coalescing) + `Worker` executor, wired into `serve` and
  stopped with the server. Config gains `backend`/`knot_zone_dir`/`knotc_path`.
  Unit tests (render, sync+coalesce, retry/backoff) + live e2e (admin edit →
  worker drains the task). Single-instance only — multi-process would need
  `SELECT … FOR UPDATE SKIP LOCKED`.
- **Deferred:** `knot.conf` / template / ACL / TSIG generation and the
  **catalog zone** (RFC 9432) — the *content* push works; the *config* push
  (declaring zones + transfer ACLs to Knot, catalog membership) is the
  follow-up. Also: `last_push` from the journal into `/healthcheck`.

### M6 — Management + record API (PRD §11, clients only)
- Huma JSON API, **Bearer only** (Basic rejected), token level scopes access.
- Native management resources (PRD §11.2): zones, RR-in-zone, users, groups,
  group-zone-roles, group-rr-roles, self tokens, user tokens, TSIG keys, slave
  ACLs. Pagination (default 50, max 500), filtering, `{detail,code}` errors,
  `Idempotency-Key` on POST.
- **`cfapi/` — Cloudflare-compatible record facade** (pending §1 confirmation):
  per-record id CRUD over the same models for third-party tooling. This is the
  only "external API" surface — there is **no teleddns↔teleddns** peer API
  (slaves replicate via DNS).
- `/healthcheck` (always public, OK/WARN per PRD §11.5) + `/metrics`
  (Prometheus series in §11.5; auth configurable).

*(Former M7 "secondary replication" is removed — replaced by the catalog zone
+ AXFR/TSIG handled in M5.)*

---

## 5. Open questions carried from PRD §13
1. Whole-zone push vs JSON sidecar on Knot hosts — moot; we configure the
   **local** Knot directly (co-located).
2. Slave config sync — **resolved: native DNS** (catalog zone + AXFR/TSIG); no
   app-to-app sync.
3. TeleDDNS client `User-Agent` opt-in — not required for v1.
4. L1 client provisioning UX (pre-create row + mint L1 token) — operator-UI task.
5. Legacy SQLite import — `admin import-legacy` once schema is final.

## 6. Testing strategy
- Port legacy `test_ddns_auth.py` + `test_ddns_http_integration.py` as the
  DDNS conformance harness (PRD §6 acceptance criteria).
- Knot `kzonecheck` golden-file tests for `zonefile/` output.
- Worker tests for at-least-once + idempotent push + backoff.
- `httptest` + Huma's test API for management/record endpoints.
```
