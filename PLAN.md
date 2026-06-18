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

### gone integration notes (current `main`)
- gone uses a single shared **`site.Shell`** page-chrome type everywhere
  (`auth.PageShellFunc` was removed) — auth + admin `RegisterRoutes` both take
  `site.Shell`.
- The app owns all CSS. Our `web` shell adopts gone's `admin_gorm` example
  polish: the focus-outline/font-smoothing `<style>` block and
  `site.ThemeToggle("light","dark")` in the header. `site.TimezonePicker` can
  be added to the navbar later (UTC-stored, per-session display zone).
- `crud.ObserveAccessor` is the hook for scheduling backend pushes, not just
  audit — see M2.

### Decisions locked in
- **Secondary (slave) servers: global config.** Slaves are defined once in
  `Config`; every zone replicates to all of them. (Not per-zone — simplifies
  the uniform fleet we run. Revisit if mixed topologies appear.)
- **RR storage: one GORM table per RR type** (`A`, `AAAA`, `NS`, … like the
  legacy schema). Maps 1:1 to `gone`'s `crud.CRUDTable[T]` reflection so each
  type gets a clean admin form with typed, per-type-validated fields.

### Decision still to confirm
- **Management/record API blueprint.** Recommended: **split plane** — native
  REST (PRD §11) for the *management* surface (zones, users, groups, tokens,
  servers, roles), plus a **Cloudflare-compatible record-CRUD facade**
  (`…/zones/{id}/dns_records`, per-record id CRUD, `Authorization: Bearer`)
  over the same model for third-party tooling (external-dns, cert-manager,
  acme.sh/lego, libdns, OctoDNS). See PLAN review notes; not yet final.

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
                            one table per RR type, Server,
                            GroupZoneRole/GroupRRRole, PendingPush
                          • config model — Config struct + loader (satisfies
                            gone's site.Settings)
                          • temporal model — the scheduler / update loop +
                            PendingPush worker
                          • authz level logic (PRD §9.6) + BIND zonefile render
  web/                  page shell + gone CRUD admin wiring + auth (AuthGORM,
                        sessions, CSRF, login, preferences + API-key management)
  ddns/                 DDNS update endpoint (Huma): auth, zone/label resolve, semantics
  knot/                 Knot / TeleAPI backend (push zone+config, reload)
  bind/                 Bind backend
  api/                  native management JSON API (Huma, bearer)
  cfapi/                Cloudflare-compatible record facade
```

**Build order:** start with `model/`, `web/`, `ddns/`, `knot/`; add `bind/`,
`api/`, `cfapi/` (and split anything out of `model/`) as we reach them.

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
    SlaveServers []SlaveServer // global secondary teleddns-servers (peers)
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
- `SlaveServers` carries peer base URL + bearer token (see §10).

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
- **API keys** extending the user model: app-side `APIKey` table + `KeyStore`
  (SHA-256 hash, prefix, expiry, disabled) + `BearerAuth` middleware +
  `apiAuth` wrapper — straight from `gone/docs/HOWTO-BEARER-TOKENS.md`.
  Manage on the preferences page (issue/revoke, raw key shown once).
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

### M3 — Authorization model (PRD §9)
- `required_level(action, target)` + `user_effective_level(user, target)` +
  `authorized = min(token.level, user_level) >= need`.
- Token carries its own `level` (cap = user max). Effective scopes from
  `GroupZoneRole`/`GroupRRRole` unions; L3 = `is_superuser`.
- Expose as an `auth.Authz` impl so both the CRUD UI and the APIs reuse it.
- Port legacy `tests/test_ddns_auth.py` as the conformance harness.

### M4 — DDNS endpoint (PRD §8, legacy Part A)
- Huma operations on `GET /nic/update`, `/ddns/update`, `/update` (POST→405).
- Basic **or** Bearer auth (Bearer wins); Basic rejected for TOTP/SSO/passkey
  users → `badauth`. Reuse `KeyStore.Validate` for bearer.
- Longest-suffix zone match → `(zone,label)`; `myip`/`myipv6` family detect;
  update semantics (no-op/update/converge-to-one); **no auto-create on DDNS**
  for L1 (`nohost`). SOA bump + enqueue push on change.
- dyndns2 `text/plain` body (`good`/`nochg`/`nohost`/`badauth`/`!yours`/
  `notfqdn`/`abuse`/`911`); transitional JSON `{detail}` mode behind a flag.
- Rate limiting (PRD §8.8): 60/h per record, 600/h per token → `429 abuse`.
- Port `tests/test_ddns_http_integration.py`.

### M5 — Backend sync (PRD §12)
- `zonefile/`: BIND zone serialization **byte-faithful to PRD §4.2** (must pass
  Knot `kzonecheck`) + Knot template config (per legacy SPECS).
- `Backend` interface with two impls:
  - **Knot/TeleAPI**: `/zonewrite`, `/zonecheck`, `/zonereload`, `/configwrite`,
    `/configreload` (existing contract, unchanged for v1).
  - **Bind**: write zone file + reload (`rndc reload` / equivalent). Details
    TBD; same interface.
- `PendingPush` journal (PRD §10.4) appended **in the same transaction** as the
  mutation. In-process worker goroutine (single-instance deploy for v1):
  claim under row lock (`FOR UPDATE SKIP LOCKED` on PG; single-worker serialize
  on SQLite), full-zone idempotent regen, exponential backoff+jitter (cap 1h),
  dead-letter after 20 attempts, debounce `BackendSyncDelay`, safety sweep
  `BackendSyncPeriod`. Sync-inline mode for dev/tests only.

### M6 — Management + record API (PRD §11)
- Huma JSON API, **Bearer only** (Basic rejected), token level scopes access.
- Native management resources (PRD §11.2): zones, RR-in-zone, users, groups,
  group-zone-roles, group-rr-roles, self tokens, user tokens, servers.
  Pagination (default 50, max 500), filtering, `{detail,code}` errors,
  `Idempotency-Key` on POST.
- **Cloudflare-compatible record facade** (pending §1 confirmation): per-record
  id CRUD over the same models for third-party tooling.
- `/healthcheck` (always public, OK/WARN per PRD §11.5) + `/metrics`
  (Prometheus series in §11.5; auth configurable).

### M7 — Secondary replication (global slaves)
- `secondary/` client pushes zone state to each peer teleddns-server defined in
  `Config.SlaveServers`, authenticating with the peer's bearer token over the
  **same management/record API** (server-to-server). Triggered off the same
  `PendingPush`/update loop as backend sync (a slave is just another push
  target kind).
- Resolves PRD §13.2; keep the Knot/Bind backend push and the peer replication
  as two `Backend`-like target kinds behind one worker.

---

## 5. Open questions carried from PRD §13
1. Whole-zone push vs JSON sidecar on Knot hosts — keep whole-zone for v1.
2. Slave config sync representation — **resolved: global config** (§1).
3. TeleDDNS client `User-Agent` opt-in — not required for v1.
4. L1 client provisioning UX (pre-create row + mint L1 token) — operator-UI task.
5. Legacy SQLite import — `admin import-legacy` once schema is final (M1/M8).

## 6. Testing strategy
- Port legacy `test_ddns_auth.py` + `test_ddns_http_integration.py` as the
  DDNS conformance harness (PRD §6 acceptance criteria).
- Knot `kzonecheck` golden-file tests for `zonefile/` output.
- Worker tests for at-least-once + idempotent push + backoff.
- `httptest` + Huma's test API for management/record endpoints.
```
