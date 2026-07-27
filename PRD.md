# teleddns-server — design & requirements

**teleddns-server** is a co-located DNS management and Dynamic DNS server. It runs
**next to a Knot DNS master**, owns the zone data in its own small database, and
pushes changes into the local Knot. It exposes:

- a **dyndns2 DDNS endpoint** for clients in the field (routers, hosts),
- a **native JSON management API** and a **Cloudflare-compatible API facade** for
  tooling (cert-manager, external-dns, libdns, …),
- an **operator web UI** for zones, records, users, groups and access grants.

Secondary/authoritative DNS servers replicate **natively** (catalog zone + AXFR/
TSIG) directly from Knot — teleddns never talks to another teleddns instance and
is not in the DNS query path itself.

This is the **developer-facing** document: the behavioral contracts the server
must honor (§1–§10) plus the high-level implementation decisions (§11) and current
status (§12). Operator usage and the deployment runbook are in
[`README.md`](README.md); a file-by-file module map and working conventions are in
[`AGENTS.md`](AGENTS.md). Sections §1–§10 are written as contracts (exact status
codes, wire shapes, invariants) and are language-agnostic; the current
implementation is Rust on the [`relativelylight`](https://github.com/tmshlvck/relativelylight)
back-office library (§11).

> **Status:** all surfaces are **implemented and verified** (§12). The DDNS
> endpoint, native + CF APIs, operator UI, per-type validation, Knot backend +
> sync worker, operability endpoints, and OIDC SSO are done against both the `log`
> and `knot` backends. Open items: passkeys, and the SSO group-mapping subset.

---

## 1. Surfaces

The server exposes three request surfaces plus one internal channel:

1. **DDNS endpoint** (§2) — dyndns2 over HTTP for DDNS clients.
2. **Management APIs** (§6) — a native JSON API for zones and records, plus a
   Cloudflare-compatible facade for cert-manager / external-dns. Bearer-token auth.
3. **Operator web UI** (§4, §6) — server-rendered admin for zones, records, users,
   groups and access grants; the **only** place users/groups/grants are managed.
4. **Backend push channel** (§7) — internal. Regenerates the zone file and reloads
   the local Knot.

**Non-goals.** DNSSEC signing inside the server (Knot produces `RRSIG`/`NSEC`);
serving DNS queries (Knot does); teleddns↔teleddns peer replication (native DNS
does); full UI/API feature parity (the API is deliberately narrower — §6); acting
as a recursive resolver or a registrar.

---

## 2. DDNS API

A drop-in **dyndns2** server: any generic dyndns2 client (`ddclient`, MikroTik
RouterOS, OPNsense/pfSense, UniFi, the TeleDDNS client) works with only a
base-URL change.

### Endpoints

Three paths behave identically and accept `GET` (preferred) or `POST`; any other
method is rejected with `405 badagent` (dyndns2 folds an unsupported HTTP method into
`badagent`). Parameters travel in the query string; a `POST` may instead
form-encode them in the body (query wins on a clash):

| Path           | Notes |
|----------------|-------|
| `/nic/update`  | dyndns2 canonical path. |
| `/ddns/update` | preserved from the legacy server. |
| `/update`      | preserved from the legacy server. |

### Query parameters

| Name       | Required | Notes |
|------------|----------|-------|
| `hostname` | yes      | Comma-separated list of **1–20** FQDNs (dyn's cap); trailing dot tolerated, case-insensitive. More than 20 → `numhost`; a syntactically invalid name fails the whole request with `notfqdn`. |
| `myip`     | no       | Comma-separated address list of **either family** (dyn's own dual-stack form), family auto-detected per entry. |
| `myipv6`   | no       | Comma-separated IPv6 (a widely-used extension; dyn itself carries v6 in `myip`). IPv4 here → `notfqdn`. |

With **no** address parameter the request's own source address is published — the
family it connected over, and only that family (an explicit `myip` is never extended
with a detected address of the other family). The address is the one
`relativelylight::net::client_ip` yields, so behind a proxy it is the
right-most forwarded hop **only when `trust_proxy` is set**; without a resolvable address the
request is `notfqdn`.

At most **one address per family** per request: the same address repeated is fine,
two different addresses of one family contradict each other → `notfqdn`. The address
set is applied to **every** listed hostname (dyn: each hostname "receives the same
information"); the two lists are *not* paired positionally.

The DDNS path **never deletes** records — deletions go through the management API or
UI. The deprecated dyn flags (`wildcard`, `mx`, `backmx`, `offline`) and
`system`/`url` are ignored.

The full client-facing wire contract — including the parse/retry algorithm a client
should implement and the per-client compatibility matrix — is
[`DYNDNS2.md`](DYNDNS2.md).

### Zone & label resolution

`hostname` is matched against configured zones by walking labels right-to-left
and selecting the **longest matching origin**; the remaining left-hand labels
become the record `label`. With zones `example.com.` and `sub.example.com.`, a
request for `host.sub.example.com` updates label `host` in `sub.example.com.`.
No matching zone → `nohost` (404).

### Update semantics

For each hostname, and within it for each `(family, address)`:

1. Resolve `(zone, label)`; resolve the record set (A for v4, AAAA for v6).
2. Authorize (§3). Insufficient access → `!yours` (403).
3. Empty set → **create** the record (`good`). Auto-create is allowed because an
   L1 grant is scoped to the exact `(zone, label)`.
4. One record, same value → no-op (`nochg`).
5. One record, different value → update in place (`good`).
6. Multiple records → keep the first, delete the rest, update if needed (`good`).
7. On any data change: bump the zone SOA serial and enqueue a backend push (§7).

Each hostname resolves independently (so one `nohost` among 20 names doesn't sink the
others), and authorization is decided per `(zone, label, family)`.

TTL of records touched via DDNS is `ddns_rr_ttl` (default 60 s); records created
through the management API use `default_ttl` (default 3600 s).

### Response codes & body

Body is `text/plain` in dyndns2 vocabulary: **one line per hostname, in request
order** — except a whole-request failure (auth, malformed query, `numhost`), which is
a single line whatever the hostname count. The HTTP status is the most severe of the
lines and always agrees with the body.

| HTTP | Body        | Condition |
|------|-------------|-----------|
| 200  | `good <addrs>` | created or updated; addresses comma-separated, IPv4 first. |
| 200  | `nochg <addrs>`| already at the requested value(s). |
| 400  | `notfqdn`   | missing/syntactically invalid `hostname`, or an unparseable/contradictory address, or no address and none detectable (dyndns2 has no keyword for a malformed address; `notfqdn` classifies as a permanent client-side error, which is the right signal). |
| 400  | `numhost`   | more than 20 hostnames in one request. |
| 401  | `badauth`   | missing/wrong credentials, or Basic auth by a 2FA/SSO user. |
| 403  | `!yours`    | authenticated but not authorized for the resolved record. |
| 404  | `nohost`    | no configured zone matches `hostname`. |
| 405  | `badagent`  | non-GET method (dyndns2's catch-all for a client that does not follow the update-client requirements). |
| 429  | `abuse`     | the account or the source address is locked out after too many failed credential checks (§3.6). |
| 500  | `911`       | internal error. |

A dual-stack request reports **one** line for the hostname: the most severe failure
if either family failed, else `good` (something changed) or `nochg` (nothing did),
ranked `nochg` < `good` < `nohost` < `!yours` < `abuse` < `notfqdn` < `numhost` <
`badagent` < `badauth` < `911`. A family that succeeded alongside a failing one is
still applied — the client's retry then sees `nochg` for it. Clients that want
per-family resolution send one family per request.

### Authentication

- **HTTP Basic** — username + password (argon2id-verified). Rejected with
  `badauth` for any user who has TOTP, SSO, or a passkey enabled; those users must
  use a token.
- **HTTP Bearer** — an API key (§3.4). Bearer wins if both headers are present.

The DDNS endpoint accepts tokens of any level; the per-record check (§3) gates
what a token can actually touch.

### Limits

**Successful updates are not rate-limited.** The caller is authenticated and
authorized for the exact record it is touching, which is the same reason the native
API and the CF facade carry no budget either: this server is run for a known fleet,
not as a public service. The expensive resource is protected structurally instead —
the push journal coalesces to one pending task per zone and the worker does at most
one render+reload per zone per `backend_sync_delay` (§7.1), however many updates
arrive, and an unchanged address is a `nochg` that writes nothing.

Credential *failures* are limited (§3.6), and that is the only thing that returns
`429 abuse`: once an account or a source address is locked out the submitted secret
is never checked, so guessing a DDNS password costs the attacker the lockout window
rather than an argon2 verification per try, and the account's budget is the same one
the console login spends.

---

## 3. Authorization model

The core of the product. One authorization decision serves the DDNS endpoint, the
native API, and the Cloudflare facade; the operator UI uses the same model at the
table/global level.

### 3.1 Levels

Three levels, combined by a `min()` cap so a leaked low-level token never
escalates past its own level even if its owner is more privileged:

| Level | Scope | Powers |
|-------|-------|--------|
| **L1** | a record set at `(zone, label)` | read & update the A/AAAA set; no create/delete. |
| **L2** | a whole zone | full CRUD on every RR in the zone (SOA, NS, …). |
| **L3** | global | anything: any zone, any user, group, grant; grants the operator UI. |

### 3.2 How a level is held

Access is **group-based**, never a column on the user:

- **L3** = membership in the **admin group** (a group literally named `admin`).
  It is not a user flag; it is group membership — the same gate the operator UI's
  admin uses.
- **L2** = a **zone-role grant** joining one of the user's groups to a zone. The
  grant is the row's existence — there is no level column on it.
- **L1** = a **record-role grant** joining one of the user's groups to a
  `(zone, label)`.

A user in several groups gets the **union** of their grants.

### 3.3 Permission check

```
required(action, target):
    read/update of an A/AAAA set   -> L1
    any other RR or zone action    -> L2
    zone create/delete, admin objs -> L3

effective(user, zone, label):
    admin group        -> L3
    zone-role(zone)    -> L2
    record-role(zone,label) -> L1
    else 0

authorized = min(token.level, effective) >= required
```

### 3.4 API keys (bearer tokens) and the token cap

A **token** (API key) **is its owner**: every authorization decision it takes uses the
owner's identity — user id, group memberships, admin flag — read from the database at
*verify* time, not baked into the key. A key grants nothing by itself; the grants come
from the owner's groups (§3.2), so revoking a group membership or deactivating the
account disarms every key that user holds, immediately.

What the key adds is its own `level` (1–3), which acts as a **ceiling, never a grant**:
`min(token_level, effective_level)` (§3.3). Tokens are **self-service** — a user mints
and revokes their own in the profile page — and the picker is capped at the owner's
maximum level (L3 for admins, else the highest role level they hold anywhere) and
re-capped server-side. So an L2 user can mint an L1 key for a router, and a compromised
router cannot escalate; an admin can mint an L1 key that cannot create or delete zones.
Because the cap is a `min()`, editing a key's level in the console cannot escalate it
either: a level 3 on a user who holds only an L1 grant is still L1 in effect.

The ceiling is a **capability limit, not a scope**. An L1 key of an admin may update
A/AAAA at *any* name in *any* zone — what it cannot do is anything needing L2 or L3. To
tie a device to one record, give the device its own account with an rr-role grant on
that `(zone, label)` and let it hold a key of that account; the scoping then comes from
the grant, and the key's level is defence in depth on top.

- Only a one-way hash of the key is stored; the raw key is shown **once** on mint.
- A key carries: a display name, its level, an optional expiry, a last-used
  timestamp, and a disabled flag.
- Tokens authenticate the API surfaces and the DDNS endpoint (§2, §6); they never
  grant the interactive operator UI (that requires an interactive login session).
- Every authorization decision — including the global ones with no zone to scope
  against, zone create and zone delete — goes through the `min()` cap. Reading the
  owner's admin flag directly would silently exempt those from the ceiling.

### 3.5 Identity providers

- **Local users** — username + argon2id password; optional TOTP 2FA and passkeys.
- **Single sign-on (OIDC)** — optional; see §4.2. SSO controls group membership,
  and group membership is what carries L1/L2/L3.

### 3.6 Credential lockout (brute-force brake)

Every **unauthenticated** credential check is behind a lockout: the console login and its TOTP step,
DDNS HTTP Basic, and every bearer token on the DDNS/native/CF surfaces. A locked subject is refused
*before* the submitted secret is looked at, with `429` + `Retry-After` (`abuse` on the DDNS endpoint) —
so a locked account costs no argon2 work and the answer says nothing about whether it exists. Two
counters, each with its own limit and window:

- **per account** (default 10 failures, 15 min) — the account being guessed at. Cleared by a successful
  check.
- **per client IP** (default 100 failures, 15 min) — the only thing that brakes *bearer tokens*, which
  name no account, and the only thing that catches username spraying. Deliberately far looser: a locked
  address turns away valid callers too, which matters on a shared one (CGNAT, an office NAT). Not
  cleared by a success.

An **whitelist** (`ip_lockout_whitelist`, CIDRs across both families and the IPv4-mapped form) exempts
addresses that must never be locked — an office range, a probe, a shared NAT — on every surface at
once, since they all go through the same counter. There is no username equivalent by design.

A failure records `failures += 1, last_failure_at = now` **unless the subject is already locked** — a
locked key records nothing, so an attacker cannot push the expiry out by continuing. The lock lifts
`duration` after the last counted failure, at which point the row reads as absent and the pruner
deletes it. So: *N failures, each within `duration` of the previous, lock the subject for `duration`
after the last one.* A request presenting **no** credential is a plain `401` and is not counted — an
anonymous scanner must not be able to lock out everyone sharing its address.

**Authenticated checks are deliberately not limited**: the password confirmation on `/profile` and 2FA
enrolment. Whoever posts those already holds a session, which is a session-theft problem with its own
mitigations — and counting them would let a stolen session lock the real user out of logging in.

**One set of counters, in the database.** They are relativelylight's own (`auth::lockout`), so DDNS
Basic and the console login spend the *same* account budget — there is no way for one account to have
two budgets. The rows live in `auth_username_lockout` / `auth_ip_lockout`, so they survive a restart (a
deploy must not hand every attacker a fresh budget), and — the point — **the operator unlock is
deleting a row in the admin console**: gated at L3, CSRF-checked and written to the audit log like any
other change, with no bespoke endpoint and no shell access. The console shows both tables ("Locked
accounts", "Locked addresses"), which is also the only place the fact of an attack is visible.

Expired rows are cleared by `relativelylight::auth::prune` (which also drops expired sessions), called
hourly from the sync worker — the library schedules nothing itself. Skipping a prune is harmless: an
expired row reads as unlocked and resets itself on the next failure.

**One answer to "who is the client".** `trust_proxy` selects it — the **right-most** forwarded hop when
set (the one the proxy appended; everything left of it is caller-supplied, so reading the left-most
entry would let a caller choose its own identity), the socket peer otherwise, IPv4-mapped addresses
collapsed either way — and there is a single
implementation: `relativelylight::net::client_ip`, called directly by the library's login route and by
every surface of ours (DDNS, the APIs, the access log, the audit sink). So proxy trust is decided in
exactly one place, our config, and one client's failures always land on one row.
Without a proxy the forwarded headers are ignored, so a caller cannot choose whose address gets locked
out; behind one, `trust_proxy` must be set or every user is bucketed under the proxy's address.

---

## 4. Operator web UI & login

A server-rendered operator console. It is the **only** place users, groups, and
access grants (zone-role / record-role) are managed — none of that is on the API.

### 4.1 Login & profile

- **Interactive login** with username + password, establishing a server-side
  session (opaque, revocable cookie).
- **TOTP 2FA** and **passkeys** as optional second factors; a user who enables any
  strong factor can no longer use HTTP Basic on the DDNS endpoint (must use a
  token).
- **Self-service profile:** change own password, manage own TOTP/passkeys, and
  **mint/revoke API keys** (§3.4). Admins can reset another user's password — a reset
  changes *only* the password: a disabled account stays disabled and 2FA stays
  enrolled, so it can never quietly re-open a closed account. Recovering a locked-out
  administrator is a separate, deliberately destructive CLI action (§9).
- **Failed logins are locked out** per account (and per source address where the peer
  is the real client) — see §3.6. An operator clears one by deleting its row in the
  console; nothing else is needed.
- **CSRF:** every cookie-authenticated write — the login/profile forms, the API-key
  card, and the admin console's JSON API — carries a double-submit token
  (`X-CSRF-Token` header or a `_csrf` field) and is `403` without it. Bearer-
  authenticated requests are exempt: an `Authorization` header is not ambient, so a
  cross-site request cannot borrow it. A script that posts to `/login` must read the
  token cookie and echo it.

### 4.2 Single sign-on (OIDC)

Optional OpenID Connect login (Google, Okta, Keycloak, Entra, …). Configured with
a `public_url` (external HTTPS base) and one entry per IdP.

- **Redirect URL** is derived, not configured: `<public_url>/login/sso/<name>/
  callback`, where `<name>` is the provider's configured name. That exact URL is
  registered as the authorized redirect URI at the IdP.
- **Group provisioning by rule.** On **every** login, declarative rules map an IdP
  claim (`equals` or `regex`; `claim` defaults to `email`, and may match any
  element of an array claim such as `groups`) to local groups. The desired set is
  the union of every matching rule's groups; membership within the union of all a
  provider's rule targets (its *managed set*) is **reconciled** on each login
  (deprovision included), while groups no rule names (manual grants) are left
  untouched. Rule-named groups are auto-created only when `create_groups` is set.
- **No admin special-casing** — a rule that names the admin group grants L3, so
  rules must be scoped carefully.

This is provider config only; **none of it is on the API**. The local groups it
maintains are what carry L1/L2/L3 via zone-role / record-role grants.

### 4.3 Admin console

Server-rendered CRUD over zones, records (per type), users, groups, and grants,
gated at L3 (admin group). Write controls are hidden from callers who lack write
access, but the API/handler remains the actual enforcement point (hiding is
cosmetic).

---

## 5. DNS data model

### 5.1 Zones

A zone is identified by its `origin` (a unique, fully-qualified name with trailing
dot). The zone carries its **SOA inline** (not as a separate record row):
`MNAME`, `RNAME`, `SERIAL`, `REFRESH`, `RETRY`, `EXPIRE`, `MINIMUM`, plus TTL.

- Zone creation **auto-generates** the SOA and a default apex `NS`.
- The SOA serial **auto-increments** on every mutating change (including DDNS).
- Zone authority is expressed purely through the role model (§3) — there is **no
  owner column** and no per-zone sync columns on the zone (sync state lives in the
  push journal, §7).

### 5.2 Resource records

Every record has class `IN`, belongs to one zone, and carries a `label` (a DNS
label or `@`; underscored names like `_acme-challenge`, `_dmarc`, `_sip._tcp` are
permitted), an integer `ttl` (seconds), and type-specific rdata. The DDNS path
only ever touches **A** and **AAAA**; every other type is managed through the API
or UI.

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

**Validation is per type and enforced on every write surface** (DDNS, native API,
CF facade, `admin import`, and the admin forms) from one shared set of predicates
(`dns::check`, built on `relativelylight::validate`): IP literals for A/AAAA;
DNS-name grammar for owner names and name-valued rdata; the CAA `tag` enum; hex
(SSHFP/TLSA/DS) and base64 (DNSKEY) rdata; TTL to the RFC 2181 `0..2³¹−1`; and
numeric fields range-checked to their wire width (octet vs 16-bit). It is
RFC-reasonable with a few corners cut for uncommon cases (numeric enums are
range-checked to their width, not to the exact IANA-registered set).

Every **name-shaped** field is composed from two primitives — `dns_label` (one
label: 1–63 chars, LDH plus `_` service labels) and `fqdn_hostname` (an absolute
name, trailing dot required) — so no surface can accept a name another rejects:

| Field | Rule |
|---|---|
| record owner (`label`), DDNS `hostname`, record-grant scope | label sequence; `@`/empty = apex; leftmost `*` wildcard allowed |
| rdata targets (NS/PTR/CNAME/MX/SRV `value`, NAPTR `replacement`), SOA MNAME/RNAME | label sequence, absolute or zone-relative, **no** wildcard; a lone `.` allowed where "no target" is meaningful |
| zone `origin` | `fqdn_hostname` — trailing dot required |
| quoted rdata (CAA `value`, NAPTR `flags`/`service`/`regexp`) | one character-string: ≤ 255 octets, no control characters |
| TXT `value` | ≤ 65535 bytes, any byte (see the render rule below) |

The reason the bar is set here is the **rendered zone file**: a stored value
carrying whitespace, a newline, a comma or an over-long label breaks the
`<owner> <ttl> IN <TYPE> <rdata>` line and Knot then refuses the whole zone on
reload, so such a value must never reach the DB in the first place.

The zone-file render must be byte-faithful and pass Knot's `kzonecheck`: quoted
rdata escapes `"`/`\` and writes any non-printable byte as `\DDD`, and a TXT value
longer than one character-string is emitted as **adjacent 255-octet strings**
(`"part1" "part2"` — what a long DKIM key needs; a single over-long string would be
rejected). `DNSKEY`/`DS` are stored as static data; **signing is Knot's job**.

Types not modelled (`HINFO`, `LOC`, `SVCB`, `HTTPS`, `NSEC*`, `RRSIG`, `URI`, …)
are out of scope.

### 5.3 Supporting data

- **API keys** — belong to a user; hash, prefix, name, level ∈ {1,2,3}, expiry,
  last-used, disabled (§3.4).
- **Zone-role grant** — L2; unique on `(group, zone)`.
- **Record-role grant** — L1; unique on `(group, zone, label)`.
- **Users / groups / group membership / sessions** — the auth model (§3.5, §4).
- **Push journal** — the backend-push work queue (§7).
- **Idempotency store** — saved responses for `Idempotency-Key` replay (§6).

There is **no server registry table**: the deployment is co-located and
master-only, so the single local Knot is app configuration (§9) and secondaries
replicate via native DNS.

### 5.4 Audit

Every mutating action emits a structured **audit** log line — actor (user +
token), source IP (post reverse-proxy rewrite), action, target, and `source` ∈
{`ddns`, `api`, `cfapi`, `ui`}.

---

## 6. Management APIs

### 6.1 Native JSON API (`/api`)

An OpenAPI-described JSON API (spec at `/openapi.json`, human docs served).
**Bearer only** — HTTP Basic is rejected; the token level scopes access via the §3
check.

- **Zones:** `GET/POST /api/zones`, `GET/PUT/DELETE /api/zones/{id}`. Read/update
  need L2 in-scope; create/delete need L3. Create auto-generates SOA + apex NS;
  SOA edits bump the serial.
- **Records:** one **unified, type-discriminated** object over the per-type
  storage — `{id, type, name, ttl, …rdata}` with an **opaque, type-prefixed** id
  (`a-12`, `mx-7`); `type` selects the kind and only its rdata fields apply.
  `GET/POST /api/zones/{id}/rr`, `GET/PUT/DELETE /api/zones/{id}/rr/{rrid}`.
  A/AAAA read+update need L1; other types and any create/delete need L2.
- **Pagination:** lists paginate at the storage level (default 50, max 500; a
  `X-Total-Count` header) with `?type` / `?name` filters pushed into the query —
  only the page's rows are read, never the whole zone. `?page` / `?per_page`.
- **Idempotency:** a `POST` may carry an `Idempotency-Key` header — the original
  2xx response is replayed (`Idempotency-Replayed: true`) for a retry within 24 h;
  the same key reused with a **different** body → 422.

Mutations funnel through the same path as the UI (SOA bump, last-apex-NS guard,
push-journal enqueue). **Users, groups, role grants, and other users' tokens are
not on the API** — they are provisioned via the operator UI and SSO (§4).

### 6.2 Cloudflare-compatible facade (`/client/v4`)

For tooling that only speaks Cloudflare's DNS API (cert-manager's ACME DNS01
solver, external-dns' `cloudflare` provider). Point the tool at teleddns as if it
were Cloudflare, using a teleddns API key as the API token. It mirrors CF closely
enough for those clients:

- the `{success, errors, messages, result, result_info}` envelope and CF record
  shape (`name` as FQDN, `content`, `ttl` with `1` = automatic, `proxied: false`,
  `priority` for MX);
- `GET /zones[?name=]`, `GET/POST /zones/{id}/dns_records`,
  `GET/PUT/PATCH/DELETE /zones/{id}/dns_records/{rid}`, `GET /user/tokens/verify`;
- auth via `Authorization: Bearer <key>` or `X-Auth-Key`.

It maps CF `name`/`content` onto `(zone, label, value)` and reuses the native
validation + write path. The FQDN in `name` must be **inside the addressed zone**
(`400` otherwise) — as a relative label it would otherwise be stored under the
zone's origin, creating a record the caller never asked for. Supported record
types: **A, AAAA, CNAME, TXT, NS, MX**
(what those tools use). The key's level scopes which zones it can touch, same as
the native API. This is the only *external* API surface; there is no teleddns↔
teleddns peer API.

---

## 7. Backend sync (Knot integration)

teleddns owns the zone data and pushes it into the co-located Knot master. It
keeps **no Knot config of its own** beyond assigning a template.

### 7.1 Journal + worker

Any zone mutation (DDNS, API, or UI) appends a **push-journal** entry **inside the
mutation's transaction**; the request returns as soon as that commits, never
waiting on `knotc`. A single in-process worker drains the journal:

- **Coalesced** to one outstanding entry per origin (debounce `backend_sync_delay`,
  default 10 s), so consecutive edits collapse into one regen + reload.
- **At-least-once** — in-flight state is reset on startup; an entry is marked done
  only after `knotc` succeeds.
- **Idempotent** — each push regenerates the **full** zone file from current state,
  never a delta, so retries are safe.
- **Retry** with exponential backoff + jitter, capped at ~1 h; **dead-letter** to a
  failed state after ~20 attempts (surfaced in `/metrics` and the audit log).
- **Safety-net sweep** every `backend_sync_period` (default 300 s) re-enqueues
  stale-but-unclaimed entries.
- **Full resync** on startup and every `full_resync_period` (default 24 h)
  unconditionally re-enqueues a push for **every** zone (a push regenerates the
  full zone from current state, so this also covers RRs). If `knot_delete_zones`
  (default on), the same pass lists zones the backend has declared under
  `knot_template` and enqueues a `zone-remove` for any that aren't in the DB —
  teleddns takes ownership of everything under its template and prunes the rest.
  A backend that can't enumerate its zones (the `log` backend) skips the prune
  half silently.

Journal states: `pending`, `in_flight`, `done`, `failed`; kinds: `zone`,
`zone-remove`. A multi-process deployment would need row-level locking
(`SELECT … FOR UPDATE SKIP LOCKED`); not needed for the single co-located instance.

### 7.2 Knot contract

The worker drives the local Knot via `knotc`. On each push it:

1. regenerates the **full BIND zone file** to `<knot_zone_dir>/<origin>.zone`;
2. on a zone's first push this process, **declares it** in Knot's config DB —
   `knotc conf-begin; conf-set 'zone[<o>]'; conf-set 'zone[<o>].template'
   <knot_template>; conf-commit` (cached, idempotent);
3. `knotc zone-reload <origin>`;
4. **confirms the reload took** — a `zone-reload` returns as soon as it is
   *accepted*, so the worker then polls `knotc zone-status <origin> +serial` until
   Knot serves a serial ≥ the pushed one (up to `knot_confirm_timeout`, default 5 s).
   If Knot rejects the zone it keeps the old, lower serial, so this **fails the
   push** → it retries, logs WARN/ERROR, and (past `MAX_ATTEMPTS`) dead-letters —
   rather than silently reporting success.

With `zonefile-load: difference` in the operator's template, Knot diffs the
regenerated file and emits an **incremental IXFR** to secondaries — so full-file
regen on the master still yields incremental replication (the per-change SOA bump
makes the IXFR valid). Secondaries **auto-provision** from a Knot-generated
**catalog zone (RFC 9432)** over AXFR/TSIG. The transfer ACL, TSIG keys, and
catalog membership live in the operator's **base `knot.conf`**, not in teleddns; a
`zone-remove` runs `conf-unset` + deletes the file.

The **template name is global config** (`knot_template`), applied to every managed
zone. A backend selector chooses the implementation: a no-op **`log`** backend
(default; logs what it would push — safe for first boot and dev) or the **`knot`**
backend.

### 7.3 Bulk import

An admin can bulk-load records from a BIND zone file (origin from the file's SOA /
`$ORIGIN`, or an override). Imported records go through the same validation + push
path as the API. A replace mode clears the zone's existing records first; the
default merges.

---

## 8. Operability

Two operability endpoints, both `text/plain`, both honoring **`ops_ip_src_allowed`**
— the source networks allowed to reach them, narrowing the global `ip_src_allowed`
(both must pass), evaluated after
the reverse-proxy real-IP rewrite (so a monitoring host works behind a proxy).

### 8.1 `GET /healthcheck`

Reports whether the server can **serve and replicate DNS** — not whether clients
sent traffic (zero updates is healthy). Always HTTP **200**; `OK`/`WARN` is the
body's first token:

```
OK uptime=<s> zones=<n> records=<n> pending=<n> failed=<n> outofsync=<n> knot=<up|down|na> last_push=<unixts|0>
```

`WARN` (past a short startup grace) when any of: the sync worker has stalled (no
tick within 2 × `backend_sync_period`); a push is dead-lettered (`failed>0`); a
zone has drifted out of sync (`outofsync>0` — a periodic reconcile finds Knot
serving a serial behind the DB, or not serving the zone, with nothing pending to
fix it); the oldest unfinished push is older than `warn_on_nopush` (default 3600 s);
or `backend=knot` and a `knotc status` probe fails (`knot=na` for the `log`
backend).

### 8.2 `GET /metrics`

Prometheus exposition:

| Series | Type | Labels |
|---|---|---|
| `teleddns_zones` / `teleddns_records` | gauge | — |
| `teleddns_records_by_type` | gauge | `type` |
| `teleddns_ddns_updates_total` | counter | `result` (`good`/`nochg`/`nohost`/`notyours`/`badauth`/`notfqdn`/`numhost`/`abuse`/`badagent`/`error`) — one count per response line, i.e. per hostname |
| `teleddns_auth_failures_total` | counter | `surface`,`reason` (`bad_token`/`bad_password`/`no_such_user`/`inactive`/`locked`/`error`; `locked` = refused by the §3.6 lockout) |
| `teleddns_backend_push_seconds` | histogram | `kind` |
| `teleddns_backend_push_total` | counter | `kind`,`result` |
| `teleddns_pending_pushes` | gauge | `state` |
| `teleddns_zones_out_of_sync` | gauge | — |
| `teleddns_worker_last_tick_seconds` | gauge | — |
| `teleddns_knot_up` | gauge | — |

Metrics carry **no** per-user/token labels (cardinality); the audit log identifies
the actor once an alert fires. Because regular updates are not expected, update
*volume* is the abuse signal — alert on `rate(teleddns_ddns_updates_total[5m])`
and on the auth-failure / rate-limit counters (a stolen or brute-forced
credential).

### 8.3 Logging

Structured `tracing` to **stderr** (captured by the journal under systemd) — no
standalone log files. Three concerns, deliberately distinct:

- **Access log** — one INFO line per HTTP request on every surface (DDNS, native
  API, CF facade, UI, `/metrics`, `/healthcheck`), emitted by an outer middleware:
  method, path+query, status, the resolved client IP (proxy-aware after the real-IP
  rewrite), User-Agent, and latency. Denied (403 by source admission) requests are logged
  too.
- **State changes / backend** — INFO for zone-file writes, zone declarations, and
  successful pushes; **WARN/ERROR** when a push fails or a reload is accepted but
  Knot doesn't serve the pushed serial (§7.2). This is what makes a rejected zone
  visible without reading Knot's own journal.
- **Audit** (§5.4) — the persisted, retrospective DNS-change record (who/what/where),
  surfaced in the operator UI; **not** the same as the operational stderr log above.

`debug: true` raises the level (and dumps rendered zones from the `log` backend).

---

## 9. Configuration

Configuration is a single YAML file, layered **defaults → file → env → flags**;
every key is optional. The file is located via an explicit flag, an environment
variable, the working directory, then a system path (`/etc/teleddns/…`).

Key groups:

- **Storage** — a DSN whose scheme selects the engine (SQLite for single-node,
  PostgreSQL for larger installs). Schema changes are applied by a **startup
  migrator**: a fresh database is built to the latest schema in one shot; an
  existing one has pending migrations applied in order. Migrations are
  append-only.
- **HTTP** — listen address; `ip_src_allowed` (source networks admitted at all);
  `trust_proxy`
  (parse `X-Forwarded-For`/`X-Real-IP`/`X-Forwarded-Proto` from a trusted proxy);
  `ops_ip_src_allowed`; `ui_title` (navbar brand, default "TeleDDNS Server Manager").
- **TTLs** — `default_ttl` (API-created records, default 3600), `ddns_rr_ttl`
  (DDNS-touched A/AAAA, default 60).
- **Backend sync** — `backend` (`log` | `knot`), `knot_zone_dir`, `knotc_path`,
  `knot_template`, `knot_confirm_timeout` (default 5 s; post-reload serial
  confirmation, §7.2), `backend_sync_delay` (default 10 s), `backend_sync_period`
  (default 300 s; also the reconcile cadence), `warn_on_nopush` (default 3600 s),
  `full_resync_period` (default 24 h; §7.1 full resync), `knot_delete_zones`
  (default true; prune backend zones under `knot_template` not in the DB).
- **Credential lockout** (§3.6) — `username_lockout_after` (default 10) +
  `username_lockout_duration` (15 m), `ip_lockout_after` (100) + `ip_lockout_duration`
  (15 m), `ip_lockout_whitelist` (never-locked CIDRs); `0` disables either counter, and the
  two windows are independent.
  `trust_proxy` decides whether the library's login route may count the socket peer, so
  there is no separate setting for that.
- **SSO** — `public_url` and `sso_providers[]` (§4.2).

On first start the server **seeds an `admin` user** and logs the generated
password once. It ships a CLI for at least: run the server, print the version,
reset a user's password, and bulk-import a zone file (§7.3). Password reset has a
`--break-glass` mode for a locked-out administrator: it re-activates the account,
**clears its TOTP enrolment** and restores admin-group membership (refusing an SSO
account), which the plain reset deliberately does not do.

---

## 10. Deployment shape

- teleddns runs as a service **co-located** with the Knot master, reachable by
  `knotc` and able to write into `knot_zone_dir`.
- A reverse proxy terminates TLS and forwards the real client IP (`trust_proxy`).
- The operator's base `knot.conf` provides the control socket, a `master`
  template (AXFR ACL + TSIG keys + catalog membership), and a catalog zone
  (generate) that secondaries consume; secondaries (Knot or BIND 9) are configured
  once to read that catalog and thereafter auto-provision every zone teleddns
  creates.
- teleddns is **not** in the DNS query path and holds no DNSSEC keys; it is a
  control-plane component that feeds the authoritative master.

The full production runbook (systemd unit, TLS/reverse proxy, Knot base config for
the master and secondaries) is in [`README.md`](README.md#production-deployment).

---

## 11. Implementation (Rust on `relativelylight`)

§1–§10 are the contract; this section records the **decisions** behind the current
implementation. The file-by-file map lives in [`AGENTS.md`](AGENTS.md) — not
repeated here.

### 11.1 Stack

Rust 2021 / `tokio`; `axum` 0.8; `SeaORM` 1.1 (`sqlx-sqlite` + `sqlx-postgres`,
`runtime-tokio-rustls`); `utoipa` 5 for OpenAPI; `askama` 0.13 for the page shell;
`serde`/`serde_yaml` + `clap` for layered config; `prometheus` for metrics;
`tracing` for structured logs. Passwords are argon2id (via the library); API keys
are SHA-256-hashed. Built on
[`relativelylight`](https://github.com/tmshlvck/relativelylight) — a git dependency
pinned to a release tag (currently `v0.1.2`; move to a crates.io `version` once
published), features `crud, axum, ui, openapi, csv, auth, sso, validate-base64`.

### 11.2 Library boundary — reuse vs. build

**From `relativelylight` (no per-model code):** the `auth` stack (`auth_user` /
`auth_group` / `auth_user_group` / `auth_session`, argon2id, `Auth::identify`,
login/logout/profile incl. TOTP, the OIDC `sso` module, the `Authz` gate + presets);
the `crud` engine + `MetaModel` introspection driving the **operator admin console**
over our entities; `crud::ui::Admin`/`Table` fragments; OpenAPI + CSV; and
`validate` (the shared field-validator predicates — §5.2).

**We build (app code):** the DNS domain model (`zone` + one entity per RR type); the
bearer **API-key** entity + a principal resolver that attaches a *level* (the
library's session identity has no level/token concept); the **L1/L2/L3
authorization** module (row/scope-aware, beyond the library's header-only per-model
gate), shared by all three request surfaces; the **DDNS** endpoint; the **native**
and **Cloudflare** management APIs; the **Knot backend + sync worker + push
journal**; and config, migrations, metrics, healthcheck, CLI, and zone-file import.

### 11.3 Key decisions

- **The app owns the roots.** Per the library's composition contract, the app owns
  the axum router, the page shell (Bootstrap + Alpine, required by the crud
  fragments), and the OpenAPI document; the library only contributes routes, HTML
  fragments, and schemas.
- **One authorization model, three surfaces.** DDNS, the native API, and the CF
  facade all resolve a `Principal` (session / HTTP Basic / bearer) and run the same
  `min(token_level, effective) ≥ required` check (§3). The operator console is
  L3-only via the library's admin gate. There is never a second authz path.
- **The native API is hand-written, not `crud`.** The library serves one flat
  endpoint set per entity; the native API deliberately presents a *single* record
  resource keyed by an opaque `type`-prefixed id over the many per-type tables,
  with `Idempotency-Key` replay and DB-level `?type`/`?name` filters — so it is
  hand-written. The **admin UI** does use the library's per-entity CRUD (one table
  per RR type), the natural fit there.
- **Every mutation bumps the serial + enqueues a push**, inside the mutation's
  transaction; the request never waits on `knotc`. Bulk deletes bypass per-row ORM
  hooks, so delete paths enqueue explicitly (§7.1).
- **Records are one table per RR type** (a macro-generated entity each); a new type
  means a new table plus arms in the unified record view, the zone-file renderer,
  the importer, `dns::check`, and the admin panel.

---

## 12. Status & known gaps

**Implemented and verified** end-to-end (admin UI, native API, CF facade, DDNS,
`admin import`, `/metrics` + `/healthcheck`, the sync worker) against both the
`log` and `knot` backends: §2 DDNS, §3 authorization + API keys, §4 operator UI +
login + **OIDC SSO**, §5 data model + per-type validation, §6 management APIs, §7
Knot backend + worker, §8 operability, §9 config + CLI.

**Open items / TODO:**

- **Passkeys** (§3.5, §4.1) are not implemented — TOTP 2FA is. "Has a strong
  factor" (which disables DDNS HTTP Basic) currently means TOTP or SSO.
- **SSO group mapping is a subset** of §4.2: the library matches the *username*
  claim by regex/equals (global) and *other* claims by exact value only; a regex on
  a non-username claim is ignored (logged). Scope rules accordingly.
- **Row-level authz lives in app code**, not the library gate (which is
  header-only by design); the admin console stays L3-only.
- **Multi-process deployments** would need row-level locking on the push journal
  (`SELECT … FOR UPDATE SKIP LOCKED`); the single co-located instance doesn't. (The
  lockout counters are DB-backed, so those *are* replica-safe — §3.6.)
- **No *username* whitelist on the lockout** (§3.6) — addresses can be exempted,
  accounts cannot, deliberately: an account that can never lock is an account whose
  password can be guessed at forever.
- **Re-authentication is not required** before changing a password or disabling 2FA,
  a password change does not invalidate the user's other sessions, and there are no
  TOTP recovery codes — all in relativelylight's auth module, tracked there.
- **CORS and trusted-proxy real-IP parsing** are not middleware yet: client-IP
  resolution is ours (`net.rs`, gated on `trust_proxy`), and the only network filter
  is source admission (`ip_src_allowed`). CSRF *is* in place for cookie-authenticated
  writes (§4.1).
- **Admin timezone display** — the DB/API are UTC and the admin renders UTC; a
  server-timezone option (to match Knot/syslog) is deferred (see `AGENTS.md`).
