# teleddns-server — Design

How the server is built and behaves. Operator usage is in
[`../README.md`](../README.md); the production runbook is in
[`../DEPLOY.md`](../DEPLOY.md); the forward-looking roadmap is in
[`TODO.md`](TODO.md).

teleddns-server is a co-located DNS manager: it owns the zone data in its own
database and runs **next to a Knot DNS master**, pushing changes into it via
`knotc`. Secondaries replicate over native DNS (catalog zone + AXFR/TSIG) and
never talk to teleddns.

## 1. Surfaces

The server exposes three request surfaces plus one internal channel:

1. **DDNS endpoint** (§2) — dyndns2 over HTTP for DDNS clients in the field.
2. **APIs** (§6) — a native JSON management API for zones and records, plus a
   Cloudflare-compatible facade for cert-manager / external-dns. Bearer-token
   auth.
3. **Operator web UI** — server-rendered admin (gone's HTMX CRUD) for zones,
   records, users, groups and role grants; the only place users/groups/roles are
   managed.
4. **Backend push channel** (§7) — internal. Regenerates the zone file and
   reloads the local Knot.

Non-goals: DNSSEC signing inside the server (Knot produces `RRSIG`); UI/API
feature parity (the API is deliberately narrower — §6).

## 2. DDNS API

A drop-in dyndns2 server: any generic dyndns2 client (`ddclient`, MikroTik
RouterOS, OPNsense/pfSense, UniFi, the TeleDDNS Rust client) works with only a
base-URL change.

### Endpoints

Three GET paths behave identically; POST is rejected with `405`:

| Path           | Notes |
|----------------|-------|
| `/nic/update`  | dyndns2 canonical path. |
| `/ddns/update` | preserved from the legacy server. |
| `/update`      | preserved from the legacy server. |

### Query parameters

| Name       | Required | Notes |
|------------|----------|-------|
| `hostname` | yes      | FQDN to update; trailing dot tolerated. |
| `myip`     | one of   | IPv4 *or* IPv6 literal; family auto-detected. |
| `myipv6`   | one of   | Explicit IPv6. If both `myip` and `myipv6` are present they are processed independently (one A update, one AAAA update). |

At least one of `myip` / `myipv6` is required. The DDNS path never deletes
records — deletions go through the management API or UI.

### Zone & label resolution

`hostname` is matched against configured zones by walking labels right-to-left
and selecting the **longest matching origin**; the remaining left-hand labels
become the record `label`. With zones `example.com.` and `sub.example.com.`, a
request for `host.sub.example.com` updates label `host` in `sub.example.com.`.
No match → `nohost` (404).

### Update semantics

For each `(family, address)`:

1. Resolve `(zone, label)`; resolve the record set (A for v4, AAAA for v6).
2. Authorize (§4). Insufficient role → `!yours` (403).
3. Empty set → **create** the record (`good`). Auto-create is allowed because an
   L1 grant is scoped to the exact `(zone, label)`.
4. One record, same value → no-op (`nochg`).
5. One record, different value → update in place (`good`).
6. Multiple records → keep the first, delete the rest, update if needed (`good`).
7. On any data change: bump the zone SOA serial and enqueue a backend push (§7).

TTL of records touched via DDNS is `ddns_rr_ttl` (default 60 s); records created
through the management API use `default_ttl` (default 3600 s).

### Response codes & body

Body is `text/plain` in dyndns2 vocabulary; the HTTP status is the authoritative
signal.

| HTTP | Body        | Condition |
|------|-------------|-----------|
| 200  | `good <ip>` | created or updated. |
| 200  | `nochg <ip>`| already at the requested value. |
| 400  | `notfqdn`   | bad `hostname`, or `myip`/`myipv6` not parseable. |
| 401  | `badauth`   | missing/wrong credentials, or Basic auth by a 2FA/SSO/passkey user. |
| 403  | `!yours`    | authenticated but not authorized for the resolved record. |
| 404  | `nohost`    | no configured zone matches `hostname`. |
| 429  | `abuse`     | rate limit tripped. |
| 500  | `911`       | internal error. |

With both `myip` and `myipv6`, the body carries both status lines (`\n`
separated) and the response takes the **worst** HTTP code.

### Authentication

- **HTTP Basic** — username + password (argon2id). Rejected with `badauth` for
  any user who has TOTP, SSO, or a passkey enabled; those users must use a token.
- **HTTP Bearer** — an API key (§5). Bearer wins if both headers are present.

The DDNS endpoint accepts tokens of any level; the per-record check (§4) gates
what a token can actually touch.

### Rate limiting

Per-token and per-`(user, hostname)` limits: **60 updates/hour per record**,
**600 updates/hour per token**. Exceeding either returns `429 abuse`. Because
regular updates are not expected, update *volume* is itself the abuse signal
(§8).

## 3. Resource records

Every record has class `IN` and belongs to one zone, carrying a `label`, integer
`ttl` (seconds), and type-specific fields. `label` is a DNS label (or `@`);
underscored names (`_acme-challenge`, `_dmarc`, `_sip._tcp`) are permitted.

Each RR type is its own GORM table (one table per type maps 1:1 to gone's CRUD
reflection). The DDNS path only ever touches A and AAAA; every other type is
managed through the API or UI.

### SOA

A zone carries its SOA inline as fields on the zone row (not an RR table row):
`MNAME`, `RNAME`, `SERIAL`, `REFRESH`, `RETRY`, `EXPIRE`, `MINIMUM`, plus TTL.
Zone creation auto-generates the SOA and a default apex `NS`. The serial
auto-increments on every mutating change (including DDNS) via a model hook.

### RR types and BIND serialization

| Type     | Fields beyond `(label, ttl)`                        | BIND output (per record) |
|----------|-----------------------------------------------------|--------------------------|
| `A`      | `value` (IPv4)                                      | `<label> <ttl> IN A <value>` |
| `AAAA`   | `value` (IPv6)                                      | `<label> <ttl> IN AAAA <value>` |
| `NS`     | `value` (name)                                      | `<label> <ttl> IN NS <value>` |
| `PTR`    | `value` (name)                                      | `<label> <ttl> IN PTR <value>` |
| `CNAME`  | `value` (name)                                      | `<label> <ttl> IN CNAME <value>` |
| `TXT`    | `value`                                             | `<label> <ttl> IN TXT "<value>"` |
| `MX`     | `priority`, `value` (name)                          | `<label> <ttl> IN MX <priority> <value>` |
| `SRV`    | `priority`, `weight`, `port`, `value` (name)        | `<label> <ttl> IN SRV <priority> <weight> <port> <value>` |
| `CAA`    | `flag`, `tag`, `value`                              | `<label> <ttl> IN CAA <flag> <tag> "<value>"` |
| `SSHFP`  | `algorithm`, `hash_type`, `fingerprint`             | `<label> <ttl> IN SSHFP <algorithm> <hash_type> <fingerprint>` |
| `TLSA`   | `cert_usage`, `selector`, `matching_type`, `cert_data` | `<label> <ttl> IN TLSA <cert_usage> <selector> <matching_type> <cert_data>` |
| `DNSKEY` | `flags`, `protocol`, `algorithm`, `public_key`      | `<label> <ttl> IN DNSKEY <flags> <protocol> <algorithm> <public_key>` |
| `DS`     | `key_tag`, `algorithm`, `digest_type`, `digest`     | `<label> <ttl> IN DS <key_tag> <algorithm> <digest_type> <digest>` |
| `NAPTR`  | `order`, `preference`, `flags`, `service`, `regexp`, `replacement` | `<label> <ttl> IN NAPTR <order> <preference> "<flags>" "<service>" "<regexp>" <replacement>` |

Validation is per-type (address literals for A/AAAA, enum sets for
CAA `tag` / SSHFP / TLSA, `[0,65535]` bounds for the 16-bit fields, DNS-name
grammar for name-valued rdata). The render is byte-faithful and passes Knot's
`kzonecheck`. `DNSKEY`/`DS` are stored as static data; signing is Knot's job.

Types not modelled (`HINFO`, `LOC`, `SVCB`, `HTTPS`, `NSEC*`, `RRSIG`, `URI`, …)
are out of scope.

## 4. Authorization

### Levels

Three levels, combined by a `min()` cap so a leaked low-level token never
escalates past its own level even if its owner is more privileged:

| Level | Scope | Powers |
|-------|-------|--------|
| L1 | a record set at `(zone, label)` | read & update the A/AAAA set; no create/delete. |
| L2 | a whole zone | full CRUD on every RR in the zone (SOA, NS, …). |
| L3 | global | anything: any zone, any user, group, server; grants the operator UI. |

### How a level is held

- **L3** = membership in the **admin group** (the group literally named `admin`).
  It is not a column on the user; it is group membership, the same gate gone's
  CRUD admin uses.
- **L2** = a **`GroupZoneRole`** row for one of the user's groups on the zone.
  The grant is the row's existence — there is no level column on the row.
- **L1** = a **`GroupRRRole`** row for one of the user's groups on the
  `(zone, label)`.

A user in several groups gets the union of their grants.

### Permission check

```
required(action, target):
    read/update of an A/AAAA set   -> L1
    any other RR or zone action    -> L2
    zone create/delete, admin objs -> L3

effective(user, zone, label):
    admin group        -> L3
    GroupZoneRole(zone) -> L2
    GroupRRRole(zone,label) -> L1
    else 0

authorized = min(token.level, effective) >= required
```

The same path serves DDNS, the native API, and the Cloudflare facade. Operator
CRUD admin is L3-gated at the table level (gone's `auth.Authz`).

### API keys and the token cap

A **token** (API key) belongs to a user and carries its own `level` (1–3). The
key form on `/preferences` caps the picker at the user's `UserMaxLevel` (L3 for
admins, else the highest role level they hold anywhere) and re-caps server-side.
This lets an L2 user mint an L1 key for a router so a compromised router can't
escalate. Only the SHA-256 hash is stored; the raw key is shown once on mint.

### SSO group provisioning

Group membership is the join between the IdP and DNS access, so for SSO users the
IdP controls it via declarative **group rules**. On **every** login gone
evaluates each provider's rules and reconciles membership:

- A rule matches one claim (`claim`, default `email`) by `equals` or `regex`
  (RE2, against a scalar or any element of an array claim like `groups`) and
  names local `groups`.
- The desired set for a login is the union of every matching rule's groups; the
  union of *all* a provider's rule targets is its **managed set**.
- Membership within the managed set is reconciled to the match on each login
  (deprovision included); groups outside it (manual grants) are untouched.
  Rule-named groups are auto-created only when `create_groups` is set.
- No admin special-casing: a rule that names the admin group grants L3 — scope
  rules accordingly.

This is provider config (`public_url` + `sso_providers`); none of it is on the
API. The reconcile logic lives in gone `auth`.

## 5. Data model

App-owned tables (the gone auth tables — `auth_users`, `auth_groups`,
passkeys, SSO identities — are owned by gone). All schema changes run through the
migrator (§9).

- **APIKey** — N:1 to user; `hashed_key` (sha256), `prefix`, `name`, `level`
  ∈ {1,2,3} (capped per §4), `expires_at`, `last_used_at`, `disabled`.
- **Zone** — `origin` (unique FQDN with trailing dot) + the SOA fields. Zone
  authority is the role model; there is no `owner` column and no per-zone sync
  columns (sync state lives in `SyncTask`).
- **RR** — one table per type (§3), each a flat struct of common
  `(zone, label, ttl)` + type-specific rdata.
- **GroupZoneRole** — L2 grant; unique on `(group, zone)`.
- **GroupRRRole** — L1 grant; unique on `(group, zone, label)`.
- **SyncTask** — the backend-push journal (§7).
- **api_idempotency** — stored responses for `Idempotency-Key` replay (§6).

There is **no `Server` table**: the deployment is co-located and master-only, so
the single local Knot is app config (`backend` / `knot_zone_dir` / `knotc_path`
/ `knot_template`), and secondaries replicate via native DNS.

Every mutating action emits a structured **audit** log line — actor (user +
token), source IP (post reverse-proxy rewrite), action, target, and `source`
∈ {`ddns`, `api`, `cfapi`, `ui`}.

## 6. Management APIs

### Native JSON API (`/api`)

Huma-generated (OpenAPI 3 at `/openapi.json`, docs at `/docs`, Swagger at
`/swagger`). **Bearer only** — HTTP Basic is rejected; the token level scopes
access via the §4 check.

- **Zones:** `GET/POST /api/zones`, `GET/PUT/DELETE /api/zones/{id}`. Read/update
  need L2 in-scope; create/delete need L3. Create auto-generates SOA + apex NS;
  SOA edits bump the serial.
- **Records:** one unified, type-discriminated object over the per-type tables —
  `{id, type, name, ttl, …rdata}` with an opaque type-prefixed `id` (`a-12`,
  `mx-7`). `GET/POST /api/zones/{id}/rr`, `GET/PUT/DELETE
  /api/zones/{id}/rr/{rrid}`. A/AAAA read+update need L1; other types and any
  create/delete need L2.
- Lists paginate at the DB level (default 50, max 500; `X-Total-Count` header)
  with `?type` / `?name` filters pushed into SQL — only the page's rows are read,
  never the whole zone.
- `POST` honors an `Idempotency-Key` header: the original 2xx response is
  replayed (`Idempotency-Replayed: true`) for a retry within 24 h; a key reused
  with a different body → 422.

Mutations funnel through the same model hooks as the UI (SOA bump, last-NS
guard, `SyncTask` enqueue). Users, groups, role grants, and other users' tokens
are **not** on the API — they are provisioned via the operator UI and SSO
(§4), so the API needn't manage them.

### Cloudflare-compatible facade (`/client/v4`)

For tooling that only speaks Cloudflare's DNS API (cert-manager's ACME DNS01
solver, external-dns' `cloudflare` provider). It mirrors CF closely enough for
those clients:

- the `{success, errors, messages, result, result_info}` envelope and CF record
  shape (`name` as FQDN, `content`, `ttl` with `1`=automatic, `proxied:false`,
  `priority` for MX);
- `GET /zones[?name=]`, `GET/POST /zones/{id}/dns_records`,
  `GET/PUT/PATCH/DELETE /zones/{id}/dns_records/{rid}`, `GET /user/tokens/verify`;
- auth via `Authorization: Bearer <key>` or `X-Auth-Key`.

It maps CF `name`/`content` onto `(zone, label, value)` and reuses the native
validation + write path. Supported types: A, AAAA, CNAME, TXT, NS, MX. This is
the only *external* API surface; there is no teleddns↔teleddns peer API.

## 7. Backend sync

### Journal + worker

Any zone mutation (DDNS, API, or UI) appends a **`SyncTask`** row **inside the
mutation's transaction**; the request returns as soon as that commits, never
waiting on `knotc`. An in-process worker goroutine (single instance) drains the
journal:

- **Coalesced** to one outstanding row per origin (debounce `backend_sync_delay`,
  default 10 s), so consecutive edits collapse into one regen+reload.
- **At-least-once** — `in_flight` is reset on startup; a row is marked `done`
  only after `knotc` succeeds.
- **Idempotent** — each push regenerates the *full* zone file from current DB
  state, never a delta, so retries are safe.
- **Retry** with exponential backoff + jitter, capped at 1 h; **dead-letter** to
  `state=failed` after 20 attempts (surfaces in `/metrics` and the audit log).
- **Safety-net sweep** every `backend_sync_period` (default 300 s) re-enqueues
  stale-but-unclaimed rows.

`SyncTask` states: `pending`, `in_flight`, `done`, `failed`; kinds: `zone`,
`zone-remove`. Indexed by `(state, available_at)` for the worker scan. A
multi-process deployment would need `SELECT … FOR UPDATE SKIP LOCKED`; not
needed for the single co-located instance.

### Knot contract

The worker drives the local Knot via `knotc`. On each push it:

1. regenerates the **full BIND zone file** to `knot_zone_dir/<origin>.zone`;
2. on a zone's first push this process, **declares it** in Knot's config DB —
   `knotc conf-begin; conf-set 'zone[<o>]'; conf-set 'zone[<o>].template'
   <knot_template>; conf-commit` (cached, idempotent);
3. `knotc zone-reload <origin>`.

With `zonefile-load: difference` in the operator's template, Knot diffs the
regenerated file and emits an **incremental IXFR** to secondaries — so full-file
regen on the master still yields incremental replication (the per-change SOA bump
makes the IXFR valid). Secondaries **auto-provision** from a Knot-generated
**catalog zone (RFC 9432)** over AXFR/TSIG. The transfer ACL, TSIG keys, and
catalog membership live in the operator's base `knot.conf`, not in teleddns. A
`zone-remove` task runs `conf-unset` + deletes the file.

The `backend` config selects the implementation: `log` (default, no-op — logs
what it would push) or `knot`. See [`../README.md`](../README.md) "How teleddns
drives Knot" and [`../DEPLOY.md`](../DEPLOY.md).

## 8. Operability

Both endpoints serve `text/plain` and honor **`ops_allowed_ips`** — a CIDR
allow-list applied *on top of* the global `allowed_ips`, evaluated after the
reverse-proxy real-IP rewrite (so a monitoring host works behind Caddy).

### `GET /healthcheck`

Reports whether the server can **serve and replicate DNS** — not whether clients
sent traffic (zero updates is healthy). Always HTTP **200**; `OK`/`WARN` is the
body's first token:

```
OK uptime=<s> zones=<n> records=<n> pending=<n> failed=<n> knot=<up|down|na> last_push=<unixts|0>
```

`WARN` (past a short startup grace) when any of: the sync worker has stalled (no
tick within 2 × `backend_sync_period`); a `SyncTask` is dead-lettered
(`failed>0`); the oldest unfinished task is older than `warn_on_nopush` (default
3600 s); or `backend=knot` and a `knotc status` probe fails (`knot=na` for the
`log` backend).

### `GET /metrics`

Prometheus exposition:

| Series | Type | Labels |
|---|---|---|
| `teleddns_zones` / `teleddns_records` | gauge | — |
| `teleddns_records_by_type` | gauge | `type` |
| `teleddns_ddns_updates_total` | counter | `result` (`good`/`nochg`/`nohost`/`notyours`/`badauth`/`notfqdn`/`abuse`/`error`) |
| `teleddns_auth_failures_total` | counter | `surface`,`reason` |
| `teleddns_ratelimited_total` | counter | `surface` |
| `teleddns_backend_push_seconds` | histogram | `kind` |
| `teleddns_backend_push_total` | counter | `kind`,`result` |
| `teleddns_pending_pushes` | gauge | `state` |
| `teleddns_worker_last_tick_seconds` | gauge | — |
| `teleddns_knot_up` | gauge | — |

Metrics carry no user/token labels (cardinality); the audit log identifies the
actor once an alert fires. Alert on `rate(teleddns_ddns_updates_total[5m])` (a
stolen credential driving excessive successful updates) and on the auth-failure /
rate-limit counters (brute force or a revoked-but-retried credential).

## 9. Configuration & migrations

Config is a single YAML file (`teleddns-server.yaml`), loaded defaults → file →
env → flags; every key is optional. Engine is inferred from `db_dsn`
(`sqlite://…` pure-Go glebarez, or `postgres://…`). See
[`../README.md`](../README.md) and the sample config for the full key list.

Schema changes run through a **gormigrate** migrator at startup: a fresh DB is
built in one shot from the current models and stamped at the latest version; an
existing DB has pending migrations applied in order. The migrator logs the path
taken. Migrations are append-only; destructive steps use frozen struct snapshots
so history can't drift from the current models (a test asserts the fresh-build
schema equals a full replay).
