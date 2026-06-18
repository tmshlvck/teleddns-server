# TeleDDNS Server — Product Requirements

This document has two parts:

- **Part A — Legacy Compatibility Surface (§1–§6).** What the *current* Python
  server exposes to DDNS clients; the rewrite must keep this wire contract.
- **Part B — New Server Design (§7–§13).** What the *new* server is being
  built to. Framework-agnostic — describes the required behavior, contracts,
  and data shapes without prescribing a language, web framework, ORM, or
  task system. Source of truth for the spec going forward.

---

# Part A — Legacy Compatibility Surface

## 1. Purpose & Scope

This document captures the **externally observable contract** of the existing
TeleDDNS server that must be preserved by any rewrite (regardless of language
or framework). It covers:

1. The HTTP DDNS update API consumed by Dynamic DNS clients.
2. Authentication, authorization and error semantics of that API.
3. The full list of DNS Resource Record types the server stores, their field
   shapes and validation rules.

**Out of scope** (intentionally not specified here):

- The backend integration with Knot/TeleAPI (`/zonewrite`, `/zonereload`,
  `/configwrite`, `/configreload`, `/zonecheck`) and the dirty-flag /
  sync-loop machinery (`BACKEND_SYNC_PERIOD`, `BACKEND_SYNC_DELAY`).
- The legacy admin interface (Starlette-Admin in the current
  implementation), any planned operator UI, and the data-model REST API
  (User/Group/Token/Server management) — these are specified in Part B.
- Audit logging, Prometheus, `/healthcheck`.
- Database schema and migrations.

These remain free to be redesigned in the rewrite.

## 2. Compatibility Goals

The rewrite **must** be a drop-in replacement for existing DDNS clients
without requiring any client-side configuration change beyond the base URL.
In particular:

- The wire-level URL paths, query-parameter names, authentication schemes and
  HTTP status codes documented here are normative.
- The response **body format** of the existing server is a JSON object of the
  form `{"detail": "..."}`. Clients in the wild (notably the `teleddns`
  reference client and routers/scripts using basic-auth dyndns) treat any 2xx
  as success and any 4xx/5xx as failure, so the body itself is informational.
  The rewrite may keep the JSON shape or move to a traditional dyndns2
  plain-text body (`good <ip>` / `nochg <ip>`), but if it changes, the change
  must be documented and a transitional mode SHOULD be available.

## 3. DDNS Update API

### 3.1 Endpoints

Two endpoint paths are exposed and MUST behave identically:

| Method | Path             |
|--------|------------------|
| GET    | `/ddns/update`   |
| GET    | `/update`        |

Both paths exist for compatibility with clients that hard-code one or the
other (the dyndns2-style `/nic/update` is *not* implemented; the deployed
NGINX layer typically rewrites `/ddns/*` → upstream `/*`, so depending on
deployment one or both will be reachable).

Only `GET` is supported. `POST` is not accepted on these paths.

### 3.2 Query Parameters

| Name       | Required | Description |
|------------|----------|-------------|
| `hostname` | yes      | Fully-qualified domain name to update, e.g. `host.example.com`. A trailing dot is tolerated. |
| `myip`     | yes      | The IPv4 or IPv6 address to set. Address family is auto-detected from the literal. |

Both parameters are passed as URL query parameters. The server does **not**
implement the legacy multi-value `myip,myipv6` form; clients that need to
update both A and AAAA must issue two separate requests.

### 3.3 Zone & Label Resolution

The server resolves `hostname` against the set of configured zones by
walking labels right-to-left and selecting the **longest matching zone
origin**. The remaining left-hand labels become the RR `label`.

Example: with zones `example.com.` and `sub.example.com.` configured, a
request for `host.sub.example.com` updates label `host` inside zone
`sub.example.com.`.

If no zone matches, the server returns **404**.

### 3.4 Update Semantics

For the resolved `(zone, label)` pair:

- If `myip` parses as an **IPv4** address, the operation targets the **A**
  record set.
- If `myip` parses as an **IPv6** address, the operation targets the **AAAA**
  record set.
- The address family of `myip` does not affect records of the other family;
  e.g. updating with an IPv4 address leaves existing AAAA records untouched.

Within the targeted record set:

- If no record exists at `(zone, label)`, a new RR is created with TTL
  `DDNS_RR_TTL` (default **60 seconds**) and `IN` class.
- If exactly one record exists and its value equals `myip` (after
  normalization via Python's `ipaddress` module), the operation is a **no-op**
  — no data change, no SOA serial bump.
- If exactly one record exists with a different value, the value is updated
  in place.
- If multiple records exist, the first is kept (and updated if needed) and
  all extras are deleted, so the set converges to a single RR.

On any change:

- The owning zone's `SOA SERIAL` is incremented by 1.
- The zone is flagged for backend sync (out of scope for this PRD).
- The record and the zone record the request's source IP in an audit field.

### 3.5 Deletion

The published spec describes deletion via an empty `myip`. **The current
implementation does not support this**: an empty `myip` fails IP-address
parsing and returns 400. Clients in the wild do not rely on this behavior.

The rewrite **SHOULD NOT** introduce empty-`myip` deletion silently; if
deletion is desired it should be added as a clearly documented separate
endpoint or parameter. Preserving the current "empty myip → 400" behavior is
acceptable.

### 3.6 Authentication

The endpoint accepts **either** HTTP Basic auth **or** HTTP Bearer auth,
chosen by the client via the `Authorization` header.

- **Basic auth** — credentials are validated against the user's stored
  password (Argon2 hash). Basic auth is **rejected with 401** for any user
  who has TOTP, SSO or any active PassKey enabled; such users MUST use a
  bearer token.
- **Bearer auth** — the bearer token string is SHA-256 hashed and compared
  against the `UserToken` table. A token is accepted only if it is
  `is_active`, not expired (`expires_at` is null or in the future), and the
  owning user is `is_active`. Last-used timestamps are updated on success.

If both headers are provided, **Bearer takes precedence**.

If neither is provided, the server returns 401 with
`WWW-Authenticate: Basic, Bearer`.

### 3.7 Authorization (per-update)

After authentication, the resolved user must have write access to the
specific `(zone, label)`. Access is granted if any of these hold:

1. The user is `is_admin`.
2. The user is the zone's `owner`.
3. The zone has a `group` and the user is a member of that group.
4. There is a `UserLabelAuthorization` row for `(user, zone)` whose
   `label_pattern` (Python `re.match`) matches the requested label. An empty
   pattern matches every label.
5. There is a `GroupLabelAuthorization` row for any of the user's groups on
   that zone whose `label_pattern` matches.

Otherwise the server returns 401.

### 3.8 HTTP Response Codes

| Code | Condition |
|------|-----------|
| 200  | Update succeeded (created, updated, or no-op). |
| 400  | `myip` is not a valid IPv4 or IPv6 literal. |
| 401  | No credentials; bad credentials; basic auth used by a 2FA/PassKey/SSO user; authenticated user lacks authorization for the resolved `(zone, label)`. |
| 404  | No configured zone matches the supplied `hostname`. |
| 500  | Unexpected server error. |

On 401 the response carries an appropriate `WWW-Authenticate` header
(`Basic`, `Bearer`, or `Basic, Bearer`).

### 3.9 Response Body

Current implementation returns `application/json`:

```json
{ "detail": "DDNS updated A label='host' zone.origin='example.com.' -> 1.2.3.4" }
```

Distinct human-readable detail strings exist for created/updated, no-op,
and error cases. **Clients must not parse the detail string**; success is
indicated by the HTTP status code.

### 3.10 Transport Security

The DDNS endpoint accepts plain-text Basic credentials. The deployment model
assumes HTTPS termination at a reverse proxy (NGINX + LetsEncrypt) in front
of the app; the rewrite MUST continue to assume the same and SHOULD
trust `X-Forwarded-For` / `X-Real-IP` / `X-Forwarded-Proto` headers from the
proxy for audit-log source-IP recording.

## 4. Supported Resource Record Types

All records are stored with class `IN` (the `RRClass` enum currently has no
other member). Each record belongs to exactly one `MasterZone` and carries a
`label`, an integer `ttl` (seconds; default 3600), and type-specific fields.

`label` validation: matches `^(?![0-9]+$)(?!-)[a-zA-Z0-9.-]{,63}(?<!-)$` or
the literal `@`. Trailing/leading whitespace is stripped.

A "DNS name" field below is validated against `[a-zA-Z0-9.-]+` (currently
permissive; the rewrite SHOULD tighten this to true hostname grammar).

### 4.1 SOA (implicit per zone)

Each zone carries its SOA inline as fields on the zone row (not a row in the
RR tables): `soa_NAME`, `soa_CLASS`, `soa_TTL`, `soa_MNAME`, `soa_RNAME`,
`soa_SERIAL`, `soa_REFRESH`, `soa_RETRY`, `soa_EXPIRE`, `soa_MINIMUM`. The
serial is auto-incremented on every change.

The rewrite must preserve the fact that zone creation auto-generates SOA and
default NS records, and that the serial bumps on every mutating change
(including DDNS updates) unless explicitly suppressed by an admin API.

### 4.2 RR table

The following RR types are first-class tables and MUST be supported by the
rewrite. The "Fields" column lists fields beyond the common `(label, ttl,
class, zone)` tuple.

| Type     | Fields                                              | Value validation                       | BIND output (per record)                                  |
|----------|-----------------------------------------------------|----------------------------------------|-----------------------------------------------------------|
| `A`      | `value`                                             | IPv4 literal                           | `<label> <ttl> IN A <value>`                              |
| `AAAA`   | `value`                                             | IPv6 literal                           | `<label> <ttl> IN AAAA <value>`                           |
| `NS`     | `value`                                             | DNS name                               | `<label> <ttl> IN NS <value>`                             |
| `PTR`    | `value`                                             | DNS name                               | `<label> <ttl> IN PTR <value>`                            |
| `CNAME`  | `value`                                             | DNS name                               | `<label> <ttl> IN CNAME <value>`                          |
| `TXT`    | `value`                                             | (none beyond text)                     | `<label> <ttl> IN TXT "<value>"`                          |
| `MX`     | `priority`, `value`                                 | `value` is DNS name                    | `<label> <ttl> IN MX <priority> <value>`                  |
| `SRV`    | `priority`, `weight`, `port`, `value`               | `value` is DNS name; label SRV-shaped  | `<label> <ttl> IN SRV <priority> <weight> <port> <value>` |
| `CAA`    | `flag` (int), `tag` (enum), `value`                 | `tag` ∈ {`issue`,`issuewild`,`iodef`,`contactemail`,`contactphone`} | `<label> <ttl> IN CAA <flag> <tag> "<value>"`             |
| `SSHFP`  | `algorithm` (int), `hash_type` (int), `fingerprint` | `algorithm` ∈ {1,2,3,4}; `hash_type` ∈ {1,2} | `<label> <ttl> IN SSHFP <algorithm> <hash_type> <fingerprint>` |
| `TLSA`   | `cert_usage`, `selector`, `matching_type`, `cert_data` | `cert_usage` ∈ {0,1,2,3}; `selector` ∈ {0,1}; `matching_type` ∈ {0,1,2} | `<label> <ttl> IN TLSA <cert_usage> <selector> <matching_type> <cert_data>` |
| `DNSKEY` | `flags`, `protocol` (default 3), `algorithm`, `public_key` | `flags` ∈ [0, 65535]                | `<label> <ttl> IN DNSKEY <flags> <protocol> <algorithm> <public_key>` |
| `DS`     | `key_tag`, `algorithm`, `digest_type`, `digest`     | `key_tag` ∈ [0, 65535]                 | `<label> <ttl> IN DS <key_tag> <algorithm> <digest_type> <digest>` |
| `NAPTR`  | `order`, `preference`, `flags` (str), `service`, `regexp`, `replacement` | `order`/`preference` ∈ [0, 65535]; `replacement` is DNS name | `<label> <ttl> IN NAPTR <order> <preference> "<flags>" "<service>" "<regexp>" <replacement>` |

The DDNS update endpoint only ever touches `A` and `AAAA`. All other RR
types are managed through the admin / data-model API (out of scope of this
PRD) but the rewrite must persist and emit them with the field set and BIND
serialization shown above so that the generated zone files remain
byte-compatible enough for Knot to accept them.

### 4.3 Record types intentionally NOT supported

Other RR types in common use (e.g. `HINFO`, `LOC`, `SVCB`, `HTTPS`,
`NSEC`/`NSEC3`/`RRSIG`, `SMIMEA`, `OPENPGPKEY`, `URI`) are not modelled by
the current server and the rewrite has no compatibility obligation for them.
DNSSEC records that *are* modelled (`DNSKEY`, `DS`) are stored as static
data; signing/`RRSIG` generation is delegated to the backend Knot servers.

## 5. Operational Defaults

| Setting             | Default | Notes |
|---------------------|---------|-------|
| `DEFAULT_TTL`       | 3600    | Used in the `$TTL` directive of generated zone files. |
| `DDNS_RR_TTL`       | 60      | TTL assigned to A/AAAA records created or updated via the DDNS endpoint. |

The rewrite SHOULD expose both as configurable, with the same defaults.

## 6. Acceptance Criteria for the Rewrite

The rewrite is considered API-compatible for DDNS clients when:

1. `GET /ddns/update?hostname=...&myip=...` and `GET /update?...` are both
   served and behave per §3.
2. Both Basic and Bearer auth schemes work as in §3.6, including the
   2FA/PassKey/SSO → Bearer-only enforcement.
3. Authorization decisions match the rules in §3.7 byte-for-byte against the
   existing test suite in `tests/test_ddns_auth.py` and
   `tests/test_ddns_http_integration.py` (these tests should be ported and
   pass against the new implementation).
4. The status codes in §3.8 are produced for the listed conditions.
5. Zone files generated for Knot continue to contain RRs in the exact
   per-type format of §4.2 (Knot's `kzonecheck` MUST still accept the
   output).

---

# Part B — New Server Design

## 7. Architecture Overview

The rewrite exposes three distinct on-the-wire surfaces and one internal
channel:

1. **DDNS endpoint** (§8) — preserves the legacy contract from Part A and
   reshapes responses into the de-facto dyndns2 vocabulary. Targets DDNS
   clients in the field.
2. **Management API** (§11) — JSON over HTTP, Bearer-token authenticated.
   CRUD for zones, RRs, users, groups, entitlements, tokens, and DNS-server
   records.
3. **Operator interface** — a web-rendered UI for human L3/L2 operators,
   covering everything the Management API does plus user/group/token
   administration. Specified at the resource level only; visual design is
   out of scope for this PRD.
4. **Backend push channel** (§12) — internal-only. Pushes generated zone
   files and DNS-server config to one or more Knot/TeleAPI hosts.

### 7.1 Implementation freedom

This document specifies *behavior and contracts*, not a language or
framework. The following are explicitly left to the implementer:

- Programming language (e.g. Python, Go, Rust).
- HTTP / web framework.
- Persistence layer and ORM (or direct SQL).
- Background-job mechanism (see §12 for the required properties).
- Operator-interface technology (server-rendered, SPA, mixed).
- Database engine, provided it supports transactional updates and either
  row-level locking with skip-locked semantics or advisory locks (§12.2).

The implementer MUST honor:

- Every wire-level contract documented in Part A §3 and in §8 below (DDNS).
- The authorization model in §9 (the legacy test suite ports as the
  conformance harness for DDNS authz).
- The Management API resource map and error semantics in §11.
- The at-least-once + idempotent push semantics in §12.

### 7.2 Non-goals for v1

- DNSSEC signing inside the server (Knot still produces `RRSIG`).
- Feature parity between the operator UI and the Management API — the UI
  may lag.
- Live dual-running with the legacy server. A one-shot import from the
  legacy SQLite is acceptable; concurrent operation is not required.

## 8. DDNS API (new)

### 8.1 Goal

Be a drop-in dyndns2 server. Any generic dyndns2 client (`ddclient`, MikroTik
RouterOS, OPNsense/pfSense, UniFi, the existing TeleDDNS Rust client) MUST
work without modification beyond setting the base URL.

### 8.2 Endpoints

Three GET paths are exposed and behave identically:

| Method | Path           | Notes |
|--------|----------------|-------|
| GET    | `/nic/update`  | dyndns2 canonical path — added for ecosystem compat. |
| GET    | `/ddns/update` | Preserved from the legacy server. |
| GET    | `/update`      | Preserved from the legacy server. |

POST is rejected with `405`.

### 8.3 Query parameters

| Name       | Required | Notes |
|------------|----------|-------|
| `hostname` | yes      | FQDN to update; trailing dot tolerated. |
| `myip`     | one of   | IPv4 *or* IPv6 literal. Address family auto-detected. |
| `myipv6`   | one of   | dyndns2-style explicit IPv6 parameter. If both `myip` and `myipv6` are present they are processed independently (one A update, one AAAA update). |

At least one of `myip` / `myipv6` MUST be present. Empty values yield
`notfqdn`-class errors (see §8.6); the server does **not** delete records via
the DDNS path — deletions go through the management API.

### 8.4 Zone & label resolution

Identical to §3.3 (legacy): longest-suffix match against configured zones, no
match → `nohost`.

### 8.5 Update semantics

For each `(family, address)` derived from `myip` / `myipv6`:

1. Resolve `(zone, label)` per §8.4.
2. Resolve the matching record set (A for v4, AAAA for v6).
3. Apply authorization (§9.6). If the user lacks the required role on the
   *existing* record, reject — **no auto-create on the DDNS path** (see §8.7).
4. If exactly one record exists with the same value → no-op (`nochg`).
5. If exactly one record exists with a different value → update in place
   (`good`).
6. If multiple records exist → keep the first, delete the rest, update value
   if needed (`good`).
7. On any data change: bump zone SOA SERIAL and enqueue a backend push (§12).

TTL on records touched via DDNS = `DDNS_RR_TTL` (default 60 s); TTL on records
created by the management API = `DEFAULT_TTL` (default 3600 s).

### 8.6 Response codes & body

Response body is **`text/plain`** in the dyndns2 vocabulary. The HTTP status
code is the authoritative success/failure signal; the body is the dyndns2 code.

| HTTP | Body          | Condition |
|------|---------------|-----------|
| 200  | `good <ip>`   | Record created or updated. |
| 200  | `nochg <ip>`  | Already at requested value. |
| 400  | `notfqdn`     | `hostname` invalid or `myip`/`myipv6` cannot be parsed as an address. |
| 401  | `badauth`     | Missing credentials, wrong credentials, or Basic auth attempted by a 2FA/SSO/PassKey user. |
| 403  | `!yours`      | Authenticated, but caller's roles do not grant access to the resolved record. |
| 404  | `nohost`      | No configured zone matches `hostname`; *or* (for L1 callers) no pre-existing A/AAAA record at the resolved label. |
| 429  | `abuse`       | Rate limit tripped (see §8.8). |
| 500  | `911`         | Internal error. |

When both `myip` and `myipv6` are sent, the response body contains both
status lines separated by `\n`, with the **worst** HTTP code as the response
status:

```
good 1.2.3.4
nochg 2001:db8::1
```

### 8.7 Authentication

Identical mechanisms to the legacy server (§3.6):

- **HTTP Basic** — username + password against the `User` table. Rejected
  with `badauth` for any user with TOTP, SSO or PassKey enabled.
- **HTTP Bearer** — token from the `Token` table (§10). Bearer wins if both
  headers present.

The DDNS endpoint accepts tokens of **any** level (L1, L2, L3) since L2 and
L3 supersede L1's update power; the per-record check (§9.6) gates what the
token can actually touch.

### 8.8 Rate limiting & abuse

The server MUST enforce per-token and per-`(user, hostname)` request rate
limits. Defaults: **60 updates/hour per record**, **600 updates/hour per
token**. Exceeding a limit returns `429 abuse`. The counter store
(in-process, shared cache, datastore) is implementer-chosen, but limits
MUST be honored across worker processes/instances in a multi-process
deployment.

### 8.9 Existing TeleDDNS Rust client

The existing client at `../teleddns/`:

- Sends `?myip=&hostname=` only (no `myipv6`); auto-detects address family.
- Uses HTTP Basic via URL-embedded credentials.
- Inspects only the HTTP status code.

The new server is **fully compatible** without any client change. We do *not*
need to recognize the TeleDDNS client by User-Agent (the current binary uses
reqwest's default UA). A future TeleDDNS release SHOULD set
`User-Agent: teleddns/<version>` so we can opt-in to client-specific
behaviors later (e.g., richer responses), but this is not required for v1.

## 9. Authorization Model

### 9.1 Levels

Three permission levels, encoded as the integer `level` on roles (§9.3):

| Level | Constant | Scope object | Powers |
|-------|----------|--------------|--------|
| L1    | `1`      | A record set at `(zone, label)` | Read & update the A/AAAA record set; cannot create or delete. Targets the DDNS API and read/update on the management API. |
| L2    | `2`      | A whole zone | Full CRUD on every RR in the zone (incl. SOA serial, NS, etc.); manage Users (L1/L2) and Groups scoped to that zone. |
| L3    | `3`      | global | Anything: any zone, any user, any group, any server. Marked by an `is_superuser` flag on the User entity; also grants access to the operator interface. |

L3 is intentionally outside the group machinery: L3 = `User.is_superuser =
True`. L1 and L2 are *only* expressible through group memberships.

### 9.2 Users & tokens

- The **User** entity carries the conventional account columns
  (`username`, `email`, `password_hash`, `is_active`, `is_superuser`,
  `last_login`) plus:
  - 2FA: `totp_enabled`, `totp_secret`, `totp_backup_codes`
  - SSO: `sso_provider`, `sso_subject_id`, `sso_enabled`
  - PassKeys via a related **PassKey** entity (one-to-many)
- **Bearer tokens** (the `Token` entity):
  - Belong to a user.
  - Carry their **own** `level` field (1, 2, or 3). A token's level MUST be
    `<=` to the maximum level the user is capable of (`L3` if superuser, else
    `max(role.level for role in user's roles)`).
  - Distinct purpose: an L2 user can issue an L1 token for their router so
    that a compromised router can't escalate to zone-wide CRUD.
  - Token plaintext is shown once on creation; storage is the SHA-256 hash.
  - Optional `expires_at`, `description`, `last_used`, `is_active`.

### 9.3 Groups & roles

A `Group` is a named, otherwise property-less container of users. Permissions
flow from per-group **roles**:

```
GroupZoneRole  { id, group, zone, level (1|2) }     # L2 on a whole zone
GroupRRRole    { id, group, zone, label, level=1 }  # L1 on (zone, label)
UserGroup      { user, group }                      # N:M
```

Notes:

- `GroupZoneRole.level` is restricted to `2` in v1. (L3 is not group-bound;
  L1 is record-bound and uses `GroupRRRole`.)
- `GroupRRRole` targets the *record set at a label*, not a specific RR type.
  Granting `(zone=example.com., label=host)` covers both A and AAAA. This
  matches DDNS reality where a single host needs both families.
- A user can be in multiple groups; effective rights are the union.
- A user's "max level" = `max(role.level for role in roles_via_groups)` (or
  3 if `is_superuser`).

### 9.4 L2 user/group management

An L2 user MAY:

- Create new users and assign them to groups whose zone-scopes are a subset
  of the L2's own zone-scopes.
- Mint Tokens for themselves at level ≤ 2.
- Create/edit/delete `GroupRRRole` rows for groups within their zone-scopes
  (i.e. delegate L1 access on labels in their zones).
- Create new groups, but only attached to their zones.

An L2 user MAY NOT:

- Modify `User.is_superuser`.
- Create `GroupZoneRole` rows (that would grant additional L2 access);
  scoping new L2 groups is L3-only in v1 to avoid privilege-laundering.
- Touch users or groups whose scope reaches outside their zones.

### 9.5 L1 user actions

An L1 user MAY:

- Read the record set at any `(zone, label)` they have a `GroupRRRole` for.
- Update the value of an *existing* A or AAAA in that record set, via DDNS or
  the management API.

An L1 user MAY NOT:

- Create records (including A/AAAA at a new label). On the DDNS path this is
  the `nohost` case in §8.6.
- Delete records.
- Touch any RR type other than A and AAAA.
- See or manage users, groups, tokens (except their own tokens — list, mint,
  revoke).

### 9.6 Permission check algorithm

For an authenticated request acting on a target object:

```
def required_level(action, target) -> int:
    # 'read'/'update' on A/AAAA at (zone, label)  -> L1
    # any other action on a RR or zone           -> L2
    # any action on users/groups/servers (except self-token mgmt) -> L3
    ...

def user_effective_level(user, target) -> int:
    if user.is_superuser: return 3
    scopes = collect_via_groups(user)  # {(zone,label): 1, (zone): 2}
    if isinstance(target, RR):
        if (target.zone, target.label) in scopes[L1]: return 1
        if target.zone in scopes[L2]: return 2
    if isinstance(target, Zone) and target in scopes[L2]: return 2
    return 0  # no access

def authorized(token, user, action, target) -> bool:
    need = required_level(action, target)
    have = min(token.level, user_effective_level(user, target))
    return have >= need
```

The `min(token.level, user_level)` rule is the key: a leaked L1 token never
escalates to L2/L3 even if the owning user is more privileged.

## 10. Data Model

Logical entities required for v1. Names, exact column types, indexing
strategy and storage shape are implementer-chosen; what follows is the
*required* information set and the relationships between entities. All
entities carry `created_at`, `updated_at`, and an optional
`last_update_info` free-text audit string unless noted.

### 10.1 Account & auth

- **User** — `id`, `username` (unique), `email`, `password_hash` (Argon2id;
  never stored or transmitted in plaintext), `is_active`, `is_superuser`
  (L3 marker), `last_login`, plus the 2FA / SSO columns from §9.2.
- **PassKey** — N:1 to User; `credential_id` (unique), `public_key`,
  `sign_count`, `name`, `last_used`, `is_active`.
- **Token** — N:1 to User; `token_hash` (SHA-256 of plaintext; plaintext
  shown once on mint), `level` ∈ {1,2,3} subject to the cap rule in §9.2,
  `description`, `expires_at`, `last_used`, `is_active`.

### 10.2 Authorization

- **Group** — `name` (unique), `description`. N:M with User via
  **UserGroup**.
- **GroupZoneRole** — grants L2 on an entire zone. Fields: `group`, `zone`,
  `level` (`2` in v1). Unique on `(group, zone)`.
- **GroupRRRole** — grants L1 on a `(zone, label)` record set. Fields:
  `group`, `zone`, `label`. Implicit `level=1`. Unique on `(group, zone,
  label)`.

### 10.3 DNS data

- **Server** — backend Knot/TeleAPI host. `name`, `api_url`, `api_key`,
  `master_template`, `slave_template`, `is_active`.
- **Zone** — `origin` (unique; FQDN with trailing dot), `owner` → User
  (creator; bootstrap L3 of the zone), the 10 SOA fields from Part A §4.1,
  `master_server` → Server, `slave_servers` (N:M → Server), and
  backend-sync tracking columns `content_dirty`, `last_content_sync`.
- **RR** — one record per resource record. Common fields: `zone`, `label`,
  `ttl`, `rrclass` (always `IN` in v1), `type`. Type-specific fields per
  Part A §4.2 (e.g. `value` for A/AAAA, `priority` for MX, `flag`/`tag`
  for CAA, etc.).

  Whether RRs live in one discriminated table (with the type-specific
  fields stored in a structured rdata column) or in one table per RR type
  is left to the implementer; both shapes are acceptable so long as Part A
  §4.2 validation rules and BIND serialization are faithful.

### 10.4 Backend-push journal

- **PendingPush** (or any equivalent durable queue representation)
  - `id`, `zone` (nullable; null = server-config push), `server`, `kind`
    ∈ {`zone`, `config`}, `state` ∈ {`pending`, `in_flight`, `done`,
    `failed`}
  - `enqueued_at`, `last_attempt_at`, `attempts`, `last_error`,
    `available_at` (for backoff)
  - Indexed by `(state, available_at)` for the worker scan.

Whether this lives in the primary datastore or in a separate broker is a
deployment choice; the **contract** between the producer (web tier) and
the consumer (worker, §12) is the row shape above.

### 10.5 Audit

Every mutating action against any of the above MUST produce a structured
audit record carrying: actor (user id + token id), source IP (honoring the
configured reverse-proxy header), action verb, target entity, and a
before/after diff or snapshot sufficient to reconstruct the change. The
transport (log file, table, external sink) is implementer-chosen; the
information set is normative.

## 11. Management API

### 11.1 Style

- JSON over HTTP. Request bodies `application/json`; responses
  `application/json` (or `text/plain` for `/healthcheck` and `/metrics`).
- Authentication: **Bearer token only** (the same Token entity as DDNS).
  HTTP Basic is rejected on these paths.
- The token's `level` scopes what endpoints and objects the request can
  reach (§9.6).
- **Pagination** is REQUIRED on every list endpoint. Cursor-based is
  preferred, offset-based is acceptable. Default page size 50, max 500.
- **Filtering** via `?field=value` querystring on the documented filterable
  fields per resource.
- **Errors**: structured JSON body `{ "detail": "<human message>", "code":
  "<machine-readable>" }` plus the appropriate HTTP status. Validation
  errors additionally carry a `fields` map of per-field error lists.
- **Idempotency**: `PUT` and `DELETE` MUST be idempotent. `POST` SHOULD
  honor an `Idempotency-Key` request header — when present, the original
  response MUST be replayed for retries within a 24-hour window.

### 11.2 Resource map

| Resource         | URL prefix              | L1                 | L2 (in scope)            | L3 |
|------------------|-------------------------|--------------------|--------------------------|----|
| Zone             | `/api/zones/`           | —                  | RU (only own zones)      | CRUD |
| RR (in zone)     | `/api/zones/{id}/rr/`   | R/U on scoped sets | CRUD                     | CRUD |
| User             | `/api/users/`           | self only          | CR in scope (L1, L2)     | CRUD |
| Group            | `/api/groups/`          | —                  | CRUD in scope            | CRUD |
| GroupZoneRole    | `/api/group-zone-roles/`| —                  | R (in scope)             | CRUD |
| GroupRRRole     | `/api/group-rr-roles/`  | —                  | CRUD in scope            | CRUD |
| Token (self)     | `/api/me/tokens/`       | self CRD           | self CRD                 | self CRD |
| Token (any user) | `/api/users/{id}/tokens/`| —                 | —                        | CRUD |
| Server           | `/api/servers/`         | —                  | —                        | CRUD |
| Healthcheck      | `/healthcheck`          | public             | public                   | public |
| Metrics          | `/metrics`              | restricted (token) | —                        | configured |

Legend: C=create, R=read, U=update, D=delete.

### 11.3 Validation rules

- Zone creation auto-generates SOA + default NS records.
- SOA serial auto-increments on any zone mutation unless the request carries
  `?bump_serial=false` (L3 only).
- RR validation matches the per-type rules of §4.2.
- Deletes that would orphan a zone's SOA or all NS records are rejected.
- An L2 user cannot create a `GroupZoneRole` (per §9.4).

### 11.4 Audit

Every mutating Management API request and every DDNS-driven mutation MUST
produce an audit record per §10.5. Records from DDNS are tagged
`source=ddns`; records from the Management API are tagged
`source=api`; records from the operator UI are tagged `source=ui`.

### 11.5 Operability endpoints

- `GET /healthcheck` → `text/plain`:
  `OK uptime=<seconds> last_update=<ts> last_push=<ts>`. Returns `WARN`
  instead of `OK` when `last_update` exceeds `WARN_ON_NOUPDATE`
  (default 7200 s) or `last_push` exceeds `WARN_ON_NOPUSH` (default
  3600 s), provided `uptime` is also past the same threshold (so a
  freshly-started instance is not flagged).
- `GET /metrics` → Prometheus exposition. Minimum required series:
  - `teleddns_zones` (gauge)
  - `teleddns_records{zone,type}` (gauge)
  - `teleddns_ddns_updates_total{result}` (counter)
  - `teleddns_backend_push_seconds{server,kind}` (histogram)
  - `teleddns_pending_pushes{state}` (gauge)

Authentication on `/metrics` is configurable (public on a private network,
or Bearer-restricted on a public deployment); `/healthcheck` is always
unauthenticated.

## 12. Backend Sync

### 12.1 Trigger

Any zone or server-config mutation — whether arriving via DDNS, the
Management API, or the operator UI — MUST append a `PendingPush` row
(§10.4) **inside the same transaction** as the mutation that caused it.
The user-facing request returns as soon as that transaction commits. The
upstream Knot/TeleAPI call MUST NOT block the request.

### 12.2 Worker requirements

The implementation MUST provide a worker (separate process, OS thread,
async loop — language-dependent) with these properties:

- **Decoupled lifecycle** — web tier and worker(s) can be deployed and
  restarted independently.
- **At-least-once delivery** — a crashed worker does not lose pending
  pushes. Achieved by claiming `PendingPush` rows under a row-level lock
  (`SELECT … FOR UPDATE SKIP LOCKED` or equivalent advisory-locking
  scheme) and only marking `state=done` after the upstream call returns
  success.
- **Idempotent push payload** — each push regenerates the *full* zone
  file (or *full* server config) from current DB state, never a delta.
  Retries are therefore safe.
- **Retry with exponential backoff and jitter** — capped at 1 hour
  between attempts. Per-row `attempts` and `last_error` columns record
  progress.
- **Dead-letter** — after a configurable max attempts (default 20) the
  row moves to `state=failed`; this MUST surface as a non-zero
  `teleddns_pending_pushes{state="failed"}` metric and in the audit log.
- **Safety-net sweep** — a periodic pass (configurable, default every
  `BACKEND_SYNC_PERIOD = 300 s`) re-enqueues any row whose
  `available_at` has passed but which is not currently claimed.
- **Batch coalescing** — before claiming, the worker MAY collapse
  multiple consecutive `PendingPush` rows for the same `(zone, server)`
  or `(config, server)` pair into a single upstream call. Default
  debounce window `BACKEND_SYNC_DELAY = 10 s`.
- **Observability** — emit the metrics in §11.5 and a structured audit
  record per push attempt (zone name, SOA serial pushed, server name,
  outcome, duration).

### 12.3 Knot / TeleAPI contract (v1)

For v1, the worker uses the existing TeleAPI shape unchanged: it generates
the full BIND-format zone file (per Part A §4.2) and the Knot template
config (per legacy `SPECS.md`), then calls `/zonewrite`, `/zonecheck`,
`/zonereload`, `/configwrite`, `/configreload` on the relevant Server.

Whether to keep this whole-zone push model or move to a JSON-emitting
sidecar on the Knot host is **deferred — see §13**.

### 12.4 Local development

A "synchronous" mode in which the push happens inline in the request is
acceptable for development and integration tests, but MUST NOT be the
production default.

## 13. Open Questions (deferred)

These are explicitly out of scope for this PRD pass but tracked so they
don't get lost:

1. **Whole-zone push vs. JSON-emitting sidecar** — the current model
   regenerates a full BIND zone per push. Alternative: emit JSON over an
   API and run a small sidecar (Rust, Python, anything) on each Knot host
   that converts JSON to a zone file locally. Tradeoff: less coupling and
   stronger server-side validation vs. more moving parts to operate.
2. **Slave-server config sync** — each Server currently has its own
   master/slave templates; how do we cleanly represent secondaries
   (NOTIFY/AXFR direction, hidden masters) in the new model?
3. **Identifying the TeleDDNS client** — would a stable, distinctive
   `User-Agent: teleddns/<version>` header pay off (richer responses,
   per-client diagnostics, behavioral opt-ins)? Today the binary uses
   its HTTP library's default UA.
4. **L1 client provisioning UX** — given §9.5, a brand-new dyndns client
   needs *someone* (L2/L3 operator, or self-service onboarding tooling)
   to pre-create the `(zone, label)` A/AAAA row and mint an L1 token.
   Worth a dedicated onboarding flow in the operator UI.
5. **Migration from the legacy SQLite** — likely a one-shot import
   command; details once the new schema is final.
