# teleddns-server

DNS management + Dynamic DNS server (Rust). It runs **co-located with a Knot DNS
master**: it owns the zone data in a small database, serves a dyndns2 DDNS
endpoint, a JSON management API (plus a Cloudflare-compatible facade for
cert-manager / external-dns), and an operator web UI, and pushes changes into the
local Knot via `knotc`. Secondaries replicate natively over **AXFR/TSIG** and
auto-provision from a **catalog zone (RFC 9432)** — teleddns never talks to other
teleddns instances and is never in the DNS query path.

```
             ┌───────────────────── master host ─────────────────────┐
 operators → │  proxy (TLS) → teleddns-server → knotc → Knot master    │ ─AXFR/IXFR+catalog─┐
 DDNS/API  → │      :8080     (owns DB + zone files)   (authoritative)  │                    │
             └─────────────────────────────────────────────────────────┘                    ▼
                                                                          secondaries (Knot / BIND 9)
                                                                          auto-provision from catalog
```

It is a Rust rewrite built on the [`relativelylight`](https://github.com/tmshlvck/relativelylight)
back-office library (SeaORM CRUD engine, auto-generated admin UI, auth). The
design + product spec is in [`PRD.md`](PRD.md); contributor orientation is in
[`AGENTS.md`](AGENTS.md).

---

## Contents

- [Quick start](#quick-start) — build, configure, run on `:8080`
- [The four surfaces](#the-four-surfaces) — UI, DDNS, native API, Cloudflare facade
- [Authorization model](#authorization-model) — the three roles, API keys, SSO
- [Monitoring](#monitoring) — `/healthcheck`, `/metrics`
- [Production deployment](#production-deployment) — Knot, systemd, TLS proxy, secondaries

---

## Quick start

```sh
cargo build --release      # → target/release/teleddns-server
```

Copy [`teleddns-server.sample.yaml`](teleddns-server.sample.yaml) and edit. The
essentials (every key is optional — built-in defaults apply):

```yaml
db_dsn: "sqlite:///var/lib/teleddns/db.sqlite"   # or postgres://…
listen_addr: "0.0.0.0:8080"                       # loopback + a proxy in production (below)

backend: "log"                        # "log" (default, no-op: logs the rendered zone) or "knot"
# backend: "knot"                     # drive a co-located Knot master (see Production deployment)
# knot_zone_dir: "/var/lib/knot/zones"
# knotc_path: "/usr/sbin/knotc"
# knot_template: "master"
```

Durations are quoted strings (`"10s"`). The config file is found via `-c/--config`,
`$TELEDDNS_CONFIG`, `./teleddns-server.yaml`, or `/etc/teleddns/teleddns-server.yaml`.

Run it — with the default `log` backend it needs no Knot, so it's ready to evaluate
immediately:

```sh
teleddns-server                                       # default config path
teleddns-server -c /etc/teleddns/teleddns-server.yaml # or point at one explicitly
teleddns-server --version
```

On first start it seeds an `admin` user and logs the generated password once
(`WARN … seeded initial admin user … password=…`). Reset it any time:

```sh
teleddns-server admin reset-password admin
# locked out for real (2FA device gone, account disabled, dropped from the admin group)?
teleddns-server admin reset-password admin --break-glass
```

A plain reset changes **only** the password: a disabled account stays disabled and 2FA
stays enrolled, so it can't be used to quietly re-open a closed account (an unknown
username is an error, not a new account). `--break-glass` is the recovery path — it
also re-activates the account, **discards its TOTP enrolment** and restores admin-group
membership; it refuses an SSO account.

Then open **`http://127.0.0.1:8080/`**, log in, and you have:

- **Web UI / admin** — zones, records, users, groups, grants, audit log
- **API docs** — `/docs` (Swagger UI); spec at `/openapi.json`
- **Profile** — password, 2FA, and self-service API keys at `/profile` (or click your name in the header)
- **Health / metrics** — `/healthcheck` · `/metrics`
- **DDNS** — `GET|POST /nic/update|/ddns/update|/update?hostname=…[&myip=…]`
- **Management API** — `/api/zones` + `/api/zones/{id}/rr`
- **Cloudflare facade** — `/client/v4/…`

Bulk-load records from a BIND zone file (origin from the file's SOA / `$ORIGIN`, or
`--origin`; `-` reads stdin). Imports go through the same validation + Knot-sync
path as the API; `--replace` clears the zone's records first, the default merges:

```sh
teleddns-server admin import example.com.zone
teleddns-server admin import --replace example.com.zone
```

---

## The four surfaces

All four share one authorization model (below). Only the operator UI manages
users, groups and grants; the APIs manage only zones and records.

### Web UI / admin

A server-rendered console (login required) for zones, records (one editor per RR
type), users, groups, access grants, API keys, and a read-only audit log. Every
field is validated on input and carries inline help. The whole console is
**Superadmin**-only (the `admin` group); everyone else works through the DDNS/API
surfaces and the self-service profile page.

**Working inside one zone.** Each record table carries a **zone picker** beside its
search box, and the choice follows you from one RR type to the next — pick the zone
once rather than on every editor you open. It is remembered between visits and travels
in the URL (`#filter.zone=7`), so a link to one zone's records can be bookmarked or
sent to a colleague. Every column header sorts, **Zone** included: that one orders by
the zone name shown in the cell, not the row id behind it.

Cookie-authenticated writes (the login/profile forms, the API-key card, the console's
own JSON API under `/admin/api`) require a **double-submit CSRF token** and answer
`403` without it. Browsers handle this by themselves; a *script* that posts to
`/login` or `/admin/api/…` must read the `teleddns_csrf` cookie and echo it in the
`X-CSRF-Token` header (or a `_csrf` form field) — or just use a bearer token on the
native API instead, which is exempt (an `Authorization` header is not ambient).

### DDNS endpoint

A drop-in **dyndns2** server — any generic dyndns2 client (`ddclient`, MikroTik,
OPNsense/pfSense, UniFi, …) works with only a base-URL change. `GET
/nic/update|/ddns/update|/update` with `hostname` + `myip`/`myipv6`. Auth is HTTP
Basic or `Authorization: Bearer <key>`. The path only creates/updates A/AAAA (never
deletes); the per-record check gates what a token can touch.

> **Accounts with 2FA or SSO must use a bearer token — HTTP Basic will not work for
> them.** If the account has TOTP enrolled, its password is only half the credential;
> if it is an SSO account, the password isn't ours to check at all. Either way the
> server answers `badauth` (401) and never even verifies the password, so it looks
> exactly like wrong credentials. Mint a key on `/profile` and point the client at
> `Authorization: Bearer <key>` instead. Password-only accounts may keep using Basic.

`hostname` takes up to 20 comma-separated names and `myip` a comma-separated address
list of either family (`myip=192.0.2.1,2001:db8::1` — dyn's dual-stack form; the
`myipv6` extension is equivalent), with the address set applied to every listed name.
Omit the address entirely and the request's source address is used (its family only;
behind a proxy that needs `trust_proxy`). `POST` is accepted as well as `GET`, with
the parameters in the query string or a form-encoded body. Responses are `text/plain`
in dyndns2 vocabulary (`good`/`nochg`/`nohost`/`!yours`/`notfqdn`/`numhost`/`badauth`/
`abuse`/`badagent`/`911`), **one line per hostname in request order**; the HTTP status
is the worst of them. Successful updates are not rate-limited — a valid credential is
authorized for the record it touches, and the backend is protected by coalescing
instead (one Knot reload per zone per `backend_sync_delay`, however many updates
arrive). `429 abuse` means a credential lockout (below): a client that retries wrong
credentials on a timer locks itself out. Full client-facing contract:
[`DYNDNS2.md`](DYNDNS2.md).

### Management API (native)

A JSON API for zones and resource records, for tooling. **Bearer only** —
`Authorization: Bearer <api-key>`; the key's level scopes access. Browse it at
`/docs`. Records use one **unified, type-discriminated** shape — `type` selects
the kind and only its rdata fields apply; the `id` is opaque and type-prefixed
(`a-12`):

```sh
# create a zone (auto-generates SOA + apex NS)
curl -X POST $URL/api/zones -H "Authorization: Bearer $KEY" \
     -H 'Content-Type: application/json' -d '{"origin":"example.com."}'

# add an A record
curl -X POST $URL/api/zones/1/rr -H "Authorization: Bearer $KEY" \
     -H 'Content-Type: application/json' \
     -d '{"type":"A","name":"host","value":"1.2.3.4"}'

# list / delete
curl $URL/api/zones/1/rr -H "Authorization: Bearer $KEY"          # X-Total-Count header
curl -X DELETE $URL/api/zones/1/rr/a-1 -H "Authorization: Bearer $KEY"
```

Zones: reading/updating needs Zone Manager, creating/deleting needs Superadmin.
Records: an A/AAAA needs RR Manager on its name, everything else needs Zone
Manager. Input is validated per type (IP literals, DNS names,
hex/base64 rdata, numeric ranges) — a bad value returns `400`/`422` with
`{ "error": … }`. The same shared validators guard every write surface (DDNS, this
API, the CF facade, `admin import`, the admin forms), so nothing that would break
the rendered zone file — a name with whitespace or an over-long label, a control
character in quoted rdata — can be stored at all. Mutations bump the SOA serial and push to Knot. Lists paginate
(`?page`/`?per_page`, default 50 / max 500) with an `X-Total-Count` header and
`?type`/`?name` filters. A `POST` may carry an `Idempotency-Key` — a retry within
24 h replays the original response (`Idempotency-Replayed: true`); the same key
with a different body → `422`. User/group/grant management is **not** on the API.

### Cloudflare-compatible facade (cert-manager, external-dns)

For tooling that only speaks Cloudflare's API, teleddns exposes a compatible
facade under `/client/v4` (envelope, record shape, `/user/tokens/verify`). Point
the tool at teleddns as if it were Cloudflare, using a teleddns API key as the
**API token**:

- **cert-manager** (ACME DNS01): set the solver's `apiTokenSecretRef` to a
  teleddns key and override the API base URL to `https://<host>/client/v4`.
- **external-dns**: `--provider=cloudflare` with `CF_API_TOKEN=<teleddns-key>` and
  the base URL pointed at `https://<host>/client/v4`.

Supported types: A, AAAA, CNAME, TXT, NS, MX. The key's level scopes which zones
it can touch, same as the native API.

---

## Authorization model

Access is group-based with three levels, combined by a `min()` cap so a leaked
low-level token never escalates past its own level:

| Role | Held by | May |
|------|---------|-----|
| **RR Manager** | a **record grant** (group ↔ zone + name) | create & update the A/AAAA set at that one name — what a DDNS client needs |
| **Zone Manager** | a **zone grant** (group ↔ zone) | everything inside that zone: any record type, create, update, delete |
| **Superadmin** | membership of the `admin` group | everything, including the console and creating/deleting zones |

They are nested **scopes**, not numbered levels: a Zone Manager is an RR Manager
everywhere in their zone, and a Superadmin is both everywhere. It does not nest the
other way — an RR Manager cannot delete records or touch other record types, because
the DDNS client it exists for never needs to. A user gets the union of their groups'
grants; users, groups and grants are managed **only** in the operator console (or via
SSO), never on the API.

**API keys (bearer tokens)** are self-service on the profile page (`/profile`,
below password + 2FA): a user mints/revokes their own keys. Only the key's hash is
stored; the raw key is shown once.

A key **is its owner** — it carries no rights of its own, and there is nothing to
choose at mint time but a label and an optional expiry. Every check uses the owner's
groups and grants, looked up at request time, so removing a grant or deactivating the
account disarms that user's keys at once.

Which means: **to give a device narrow access, give the device its own account.** Create
a user for the thermostat, put it in a group with one record grant on
`thermostat.example.com`, and let it hold a key of that account. The scope then lives in
the grants table where you can see and revoke it on its own, and the audit log says
`thermostat` rather than your name. Handing a device a key of your own admin account
gives it your authority — no key setting can take that back.

A key is the **only** credential that works on the management APIs (they are
bearer-only), and the only one that works on DDNS for an account with **2FA or SSO**
— see the DDNS section above. A password-only account can use HTTP Basic on DDNS, but
a token is still preferable: it can be revoked on its own, without changing anyone's
password or disturbing that account's other devices.

### Brute-force protection

Every **unauthenticated** credential check — the login form, the TOTP step at login, DDNS HTTP Basic,
and every bearer token on the DDNS/native/CF surfaces — is behind a lockout. All of them share one set
of counters, so an account can't be given two budgets: burn it on DDNS and the console login is locked
too, and vice versa. A locked subject is refused with `429` + `Retry-After` (`abuse` on DDNS)
**without the submitted secret being checked**, so it costs no password verification and leaks nothing:

| Key | Defaults | Covers |
|---|---|---|
| per account | `username_lockout_after: 10`, `username_lockout_duration: "15m"` | password + TOTP checks; cleared by a success |
| per client IP | `ip_lockout_after: 100`, `ip_lockout_duration: "15m"` | bearer-token guessing (a token names no account) and username spraying |

`ip_lockout_whitelist` exempts addresses that must never be locked out — your office range,
a monitoring probe, the NAT a fleet shares — as CIDRs or bare addresses, IPv4 and IPv6
(a rule in either form matches a client arriving in the other). There is no username
equivalent on purpose: an account that can never lock is an account whose password can
be guessed at forever.

`0` turns either counter off, and the two windows are independent. Requests carrying **no** credential
are a plain `401` and are not counted, so an anonymous scanner can't lock out everyone sharing its
address. Checks made by an *already authenticated* caller (the password confirmation on `/profile`, 2FA
enrolment) are deliberately not counted — that's session theft, not brute force.

**Unlocking is a row delete in the console.** The counters live in the database
(`auth_username_lockout`, `auth_ip_lockout`), and the admin console shows them as **Locked accounts**
and **Locked addresses**. Delete a row and that account or address is free immediately; leave it and it
clears itself when the lockout expires. The delete is Superadmin-gated and lands in the audit log like any
other change. Because the rows are durable, a restart no longer resets anyone's budget.

The client address is resolved (and CIDR-matched) the same way everywhere — the forwarded hop when `trust_proxy: true`,
the socket peer otherwise — so the login form, the DDNS endpoint, the APIs and the audit log all agree
on who a caller is. One operational note: while an address is locked, *valid* callers from it are
refused too, so keep `ip_lockout_after` well above what a broken client produces if your users share an
address (CGNAT, an office NAT). Watch `teleddns_auth_failures_total{reason="locked"}`.

### Passwords, 2FA and sessions

These apply to the **console** (the login form and `/profile`); the DDNS/API surfaces
authenticate per request and hold no session.

**Password strength.** A password *typed* into the profile page, a manager's reset form, or
the admin console's user form is screened against `password_level` (`0` off, `1` ≥ 8
characters, `2` ≥ 12 — the default, `3` ≥ 12 plus the classic character mix). Above `0` it
also rejects common values and keyboard walks, one repeated character, a run of six
consecutive characters, and a password containing the account's own username. Length first,
per NIST SP 800-63B. All three surfaces are covered by the one setting, because whichever is
left unscreened becomes the way around the others — and `admin reset-password` is covered by
none of them, so a recovery path can always set a password.

**Sessions expire on two clocks.** A session dies 7 days after it was created, and after
`session_idle_timeout` (default `8h`, `0` to disable) with no requests — so a console left
open on an unattended desk stops being a live credential well before the week is out. The
session id is reissued when the second factor completes, so a session planted in someone's
browser before they log in cannot be inherited afterwards.

**Changing a password signs the other sessions out** — the account's own, everywhere else,
and *all* of a target's when a manager resets it. `/profile` also has a **Sign out other
sessions** button for evicting an intruder without a password change.

**Sensitive profile changes ask for a factor again**, in the same request: enrolling 2FA or
turning it off, and a manager's reset or 2FA-disable (which take the *manager's* own factor,
not the target's). A current password or a fresh TOTP code satisfies it; a code spent this
way cannot then be used to log in. An SSO account has no local factor to ask for and passes
unchallenged.

**TOTP recovery codes.** Enrolling 2FA now issues ten single-use codes, shown once. Submit
one in place of the authenticator code at login when the phone isn't available; `/profile`
reports how many are left and regenerates the set (which invalidates the old one). An account
that enrolled **before this version has none** — nothing backfills them — until it generates
a set from `/profile`, which says so on the page.

### Single sign-on (SSO)

Optional OpenID Connect login (Authorization Code + PKCE), via relativelylight's
`sso` module. Configure a `public_url` and one entry per IdP under
`sso_providers`; a **"Sign in with …"** button then appears on the login page and
the callback URL is `<public_url>/login/sso/<name>/callback` (register that at the
IdP). On first login an SSO user is created (`auto_register: true` by default) as
an external account — no local password/2FA.

Because such an account has no local password, **an SSO user cannot use HTTP Basic on
the DDNS endpoint** (the attempt is refused with `badauth`); they mint an API key on
`/profile` after signing in and use `Authorization: Bearer <key>`. The same applies to
any account with TOTP enrolled.

**Group mapping.** Declarative `group_rules` run on **every** login and their
result is *reconciled* onto the user (groups added/removed to match), and those
groups carry the roles above via the zone/record grants. Each rule keys off a `claim`
(default `email`):

- a rule whose `claim` is the provider's **`username_claim`** (default `email`) is
  matched against the username by `regex` (or `equals`, anchored) — the fallback
  for IdPs with no group claim (e.g. plain Google);
- any other `claim` (e.g. `groups` from Okta/a corporate IdP, requiring that
  scope) contributes groups when the claim **exactly equals** the rule's `equals`
  value. (Regex on a non-username claim isn't supported and is ignored.)

Rule-named groups are created automatically. There is no admin special-casing — a
rule that names the `admin` group makes that user a Superadmin, so scope rules carefully.

```yaml
public_url: "https://ddns.example.com"
sso_providers:
  - name: google                       # → /login/sso/google/callback
    display_name: "Google"
    issuer: "https://accounts.google.com"
    client_id: "…"
    client_secret: "…"
    group_rules:
      - regex: "@example\\.com$"        # claim defaults to email (= username_claim)
        groups: ["example-users"]
  - name: okta
    display_name: "Okta"
    issuer: "https://dev-123.okta.com"
    client_id: "…"
    client_secret: "…"
    scopes: ["email", "profile", "groups"]   # request the groups claim
    group_rules:
      - {claim: "groups", equals: "dns-operators", groups: ["example-ops"]}
```

---

## Monitoring

**Logging.** teleddns logs to stderr (structured `tracing`; captured by the
journal under systemd) — no standalone access.log. It emits **one INFO line per
HTTP request** across every surface (DDNS, native API, CF facade, UI, `/metrics`,
`/healthcheck`) with the method, path, status, the real client IP (proxy-aware),
User-Agent, and latency; INFO lines for each zone-file write and `knotc`
interaction; and **WARN/ERROR when a push fails** — including when Knot *accepts* a
reload but doesn't end up serving the pushed serial (a bad zone), which retries and
then dead-letters. Set `debug: true` for verbose logs. (The in-DB **audit log** —
who changed which record, visible in the admin UI — is separate and covers DNS
changes; this is the operational log.)

Restrict the operability endpoints with `ops_ip_src_allowed` — the source networks
allowed to reach them, narrowing `ip_src_allowed` further (both must pass),
evaluated after the reverse-proxy real-IP rewrite.

- **`GET /healthcheck`** — always HTTP 200; the body's first token is `OK` or
  `WARN`:

  ```
  OK uptime=<s> zones=<n> records=<n> pending=<n> failed=<n> outofsync=<n> knot=<up|down|na> last_push=<unixts>
  ```

  It flips to `WARN` when the sync worker stalls, a push is dead-lettered
  (`failed>0`), a zone drifts out of sync (`outofsync>0` — Knot isn't serving the
  DB's serial, checked periodically), the backlog is stuck (`warn_on_nopush`), or
  `backend=knot` and `knotc` is unreachable (`knot=na` for the no-op `log`
  backend).

- **`GET /metrics`** — Prometheus exposition: `teleddns_zones`,
  `teleddns_records`(+`_by_type`), `teleddns_ddns_updates_total{result}`,
  `teleddns_auth_failures_total{surface,reason}` (`reason="locked"` = refused by the
  brute-force brake),
  `teleddns_backend_push_total`, `teleddns_backend_push_seconds` (reconcile
  latency), `teleddns_pending_pushes{state}`, `teleddns_zones_out_of_sync`,
  `teleddns_worker_last_tick_seconds`, `teleddns_knot_up`. Since regular updates
  aren't expected, alert on `rate(teleddns_ddns_updates_total[5m])`, the
  auth-failure counter, `teleddns_pending_pushes{state="failed"} > 0`,
  `teleddns_zones_out_of_sync > 0`, and `teleddns_knot_up == 0`.

---

## Production deployment

Install teleddns co-located with a **Knot DNS master**, put it behind TLS, and
let secondaries auto-provision from a catalog zone. teleddns is **control-plane
only** — not in the query path, holds no DNSSEC keys: it writes zone files and
calls `knotc`; Knot serves and (optionally) signs.

### 1. Install Knot + teleddns

Knot DNS 3.x, from the distro (all ship a recent 3.x):

```sh
# Debian / Ubuntu
sudo apt install knot
# Fedora / RHEL
sudo dnf install knot
```

Build teleddns and install the binary + state dirs. teleddns runs **as the `knot`
user** so it can write Knot's zone files and reach the control socket without any
permission juggling:

```sh
cargo build --release
sudo install -m0755 target/release/teleddns-server /usr/local/bin/
sudo install -d -o knot -g knot /var/lib/teleddns /etc/teleddns
```

### 2. Knot master — base config

teleddns keeps **no Knot config of its own** beyond assigning a template per zone.
Everything cluster-static — the control socket, TSIG key(s), transfer ACL, a
`master` template that makes each zone a catalog member, and the catalog zone —
lives in `/etc/knot/knot.conf`:

```yaml
server:
    listen: 0.0.0.0@53
    listen: ::@53

control:
    listen: /run/knot/knot.sock       # teleddns runs knotc against this (as the knot user)

key:
  - id: xfr.example.com.
    algorithm: hmac-sha256
    secret: "REPLACE"                 # keymgr -t xfr.example.com. hmac-sha256

acl:
  - { id: acl_secondary, key: xfr.example.com., action: transfer }

remote:
  - { id: secondary1, address: 203.0.113.10, key: xfr.example.com. }

template:
  - id: master                         # teleddns assigns THIS to every zone it manages
    storage: /var/lib/knot/zones       # MUST equal teleddns knot_zone_dir
    file: "%s.zone"                     # Knot reads <storage>/<zonename>.zone
    zonefile-load: difference           # diff our regenerated file → incremental IXFR
    zonefile-sync: -1                   # teleddns owns the file; Knot never overwrites it
    catalog-role: member
    catalog-zone: catalog.example.
    acl: acl_secondary
    notify: secondary1
    # dnssec-signing: on                # optional: let Knot sign

zone:
  - { domain: catalog.example., catalog-role: generate, acl: acl_secondary, notify: secondary1 }
```

`catalog-role: generate` sits **on the catalog zone**, not on a template — Knot builds that
zone's contents in memory from every zone whose template says `catalog-role: member`, so it
has no zone file and needs no storage. Pick a catalog name that is not below any zone this
server actually serves, or it shadows part of that subtree.

`zonefile-load: difference` + `zonefile-sync: -1` is what turns full-file
regeneration on the master into **incremental IXFR** to secondaries while keeping
teleddns the sole writer.

**Run Knot from the configuration database (required).** teleddns declares each
zone at runtime with `knotc conf-set zone[<origin>]`, which operates on Knot's
config *database* (confdb), not the text file. So import the base config and start
`knotd` with `-C`:

```sh
sudo install -d -o knot -g knot /var/lib/knot/zones
sudo systemctl stop knot
sudo knotc conf-import /etc/knot/knot.conf          # load templates/keys/acl/catalog into the confdb
# Point knotd at the confdb (env var name differs by distro: KNOTD_ARGS on Fedora/RHEL,
# KNOTD_OPTS on Debian/Ubuntu):
sudo mkdir -p /etc/systemd/system/knot.service.d
printf '[Service]\nEnvironment=KNOTD_ARGS=-C /var/lib/knot/confdb\n' \
    | sudo tee /etc/systemd/system/knot.service.d/confdb.conf
sudo systemctl daemon-reload && sudo systemctl start knot
knotc conf-read 'zone[catalog.example.]'            # sanity: reads the committed confdb
```

Keep the base config's `zone:` block to just the catalog zone — teleddns adds and
removes per-domain `zone[...]` entries itself, idempotently (a restart is safe).
teleddns treats every zone declared under `knot_template` as its own: a daily
sweep (also run once at startup) prunes any such zone that isn't in its database.
Set `knot_delete_zones: false` if you want to declare zones under that template by
hand as well. To change templates/keys later, edit `knot.conf` and re-run `knotc
conf-import`.

### 3. teleddns config + systemd

`/etc/teleddns/teleddns-server.yaml`:

```yaml
db_dsn: "sqlite:///var/lib/teleddns/teleddns.sqlite"   # or postgres://…
listen_addr: "127.0.0.1:8080"                     # loopback, behind the proxy
trust_proxy: true                                 # honor X-Forwarded-For from the proxy

backend: "knot"
knot_zone_dir: "/var/lib/knot/zones"              # == the master template's storage
knotc_path: "/usr/sbin/knotc"
knot_template: "master"

public_url: "https://ddns.example.com"            # external HTTPS base (SSO + cookies)
ops_ip_src_allowed: ["10.9.0.0/24"]                  # Prometheus / uptime host
```

`/etc/systemd/system/teleddns-server.service`:

```ini
[Unit]
Description=teleddns-server (DNS + DDNS control plane)
After=network-online.target knot.service
Wants=network-online.target

[Service]
User=knot
Group=knot
ExecStart=/usr/local/bin/teleddns-server -c /etc/teleddns/teleddns-server.yaml
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/teleddns /var/lib/knot /run/knot
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload && sudo systemctl enable --now teleddns-server
sudo journalctl -u teleddns-server | grep "seeded initial admin user"   # one-time password
```

### 4. TLS reverse proxy

teleddns speaks plain HTTP on loopback; a proxy terminates TLS and forwards the
real client IP (teleddns reads it because `trust_proxy: true` — needed for the
lockout, the audit log, `ip_src_allowed` and the DDNS "use my source address"
behaviour). Pick one. (For an internal/eval box you can skip the proxy and bind
`listen_addr: "0.0.0.0:8080"` directly, leaving `trust_proxy: false`.)

All three configurations below **append** to `X-Forwarded-For`, which is what you
want: teleddns reads the **right-most** entry — the hop your proxy added — so a
caller that sends its own `X-Forwarded-For` cannot choose which address it appears
to come from. Two things follow. Set `trust_proxy: true` **only** when nothing can
reach teleddns except the proxy (otherwise a direct caller supplies the whole
header, and with it its own identity). And if you put a second hop in front — a
CDN ahead of your proxy — the right-most entry becomes your proxy's view of the
CDN, not the end user; teleddns has no trusted-proxy list to unwind that yet.

**Caddy** — automatic certificates:

```
ddns.example.com {
    reverse_proxy 127.0.0.1:8080     # appends X-Forwarded-For and sets -Proto by default
}
```

**nginx** (with a certbot cert):

```nginx
server {
    listen 443 ssl;
    server_name ddns.example.com;
    ssl_certificate     /etc/letsencrypt/live/ddns.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ddns.example.com/privkey.pem;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;   # appends; we read the last hop
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**HAProxy**:

```
frontend https
    bind :443 ssl crt /etc/haproxy/ddns.example.com.pem
    default_backend teleddns
backend teleddns
    http-request set-header X-Forwarded-Proto https
    option forwardfor            # appends X-Forwarded-For; teleddns reads the entry HAProxy added
    server t1 127.0.0.1:8080
```

Then confirm `public_url` matches the proxy's hostname (the SSO callback base).

### 5. Secondaries (auto-provision)

Configure each secondary **once**; it then provisions every zone teleddns creates
via the catalog zone.

**Knot secondary** — `/etc/knot/knot.conf`:

```yaml
key:
  - { id: xfr.example.com., algorithm: hmac-sha256, secret: "SAME_SECRET_AS_MASTER" }
remote:
  - { id: primary, address: 198.51.100.5, key: xfr.example.com. }
  # IPv6 and a non-default port: address: "2001:db8::5@5353"
acl:
  - { id: acl_primary, key: xfr.example.com., action: notify }

# Applied to every zone learned FROM the catalog — this is what makes a member zone
# transfer. Plain secondary config: where to pull from, and whose NOTIFY to accept.
template:
  - { id: catalog_member, master: primary, acl: acl_primary }

# The catalog zone itself, which is also an ordinary secondary zone.
zone:
  - domain: catalog.example.
    master: primary
    acl: acl_primary
    catalog-role: interpret
    catalog-template: catalog_member    # ← REQUIRED: without it nothing is provisioned
```

**`catalog-template` is the whole mechanism** and the easiest line to leave out. It names
the template Knot applies to each zone it learns from the catalog; a member zone otherwise
has no primary to transfer from and no ACL to accept a NOTIFY, so the catalog arrives and
nothing happens. Note it belongs on the **catalog zone**, and `catalog-role` belongs
*only* there too — putting `catalog-role: interpret` on `catalog_member` would hand it to
every member zone, telling Knot to interpret each of them as a catalog as well.

**BIND 9 secondary** — `named.conf`:

```
key "xfr.example.com." { algorithm hmac-sha256; secret "SAME_SECRET"; };
options {
    catalog-zones { zone "catalog.example." default-primaries { 198.51.100.5 key "xfr.example.com."; }; };
};
zone "catalog.example." {
    type secondary;
    primaries { 198.51.100.5 key "xfr.example.com."; };
    file "catalog.example.db";
};
```

### 6. Verify end to end

```sh
# Log in at https://ddns.example.com/ as a Superadmin, mint an API key on /profile, then:
KEY=…; URL=https://ddns.example.com
curl -X POST $URL/api/zones -H "Authorization: Bearer $KEY" \
     -H 'Content-Type: application/json' -d '{"origin":"example.com."}'
curl -X POST $URL/api/zones/1/rr -H "Authorization: Bearer $KEY" \
     -H 'Content-Type: application/json' -d '{"type":"A","name":"www","value":"1.2.3.4"}'

knotc zone-status example.com.                      # declared + served on the master
kdig @127.0.0.1 www.example.com. A +short           # → 1.2.3.4

# On the secondary: the member zone should appear by itself, from the catalog.
knotc zone-status example.com.                      # if only catalog.example. is listed,
                                                    # catalog-template is missing (step 5)
kdig @<secondary> www.example.com. A +short         # → 1.2.3.4 (auto-provisioned)
```

`/healthcheck` should report `knot=up` and a recent `last_push`.

### 7. Backups, upgrades, troubleshooting

- **Back up `db_dsn`** (the SQLite file or Postgres DB) — it is the source of
  truth; zone files under `knot_zone_dir` are regenerated from it.
- **Upgrade:** replace the binary and `systemctl restart teleddns-server`. The
  startup migrator applies pending schema changes; the worker re-pushes as needed.
  Live console sessions survive an upgrade; DDNS clients and API tokens are untouched.
  One thing an upgrade does **not** do is issue TOTP recovery codes to accounts that
  enrolled 2FA before this version — they have none until they generate a set from
  `/profile` (see [Passwords, 2FA and sessions](#passwords-2fa-and-sessions)).

| Symptom | Check |
|---|---|
| `knot=down` in `/healthcheck` | teleddns can run `knotc status` (`knotc_path`; it runs as `knot`, so the socket is reachable). |
| Pushes fail / dead-letter | `journalctl -u teleddns-server` (the error includes the knotc command, exit code, stderr/stdout); `knot_zone_dir` writable. |
| `conf-set zone[...]` fails | Knot must run from the **confdb** (step 2) — `conf-set` on a file-configured `knotd` fails. |
| Secondary has the catalog but no member zones | the catalog zone on the secondary is missing `catalog-template` (step 5) — the catalog transfers, and Knot then has no configuration to apply to what it learned. `knotc zone-status` lists only the catalog. |
| Zone served but secondary empty | catalog wiring: `knotc zone-status catalog.example.`; TSIG secret matches; ACL/notify. |
| DDNS `!yours` for a valid user | the zone/record grant on one of the account's groups — a key carries no rights of its own (see [Authorization model](#authorization-model)). |
| Signed out sooner than expected | `session_idle_timeout` (default `8h`); a password change also evicts that account's other sessions. |
| A form posts back "Request rejected" | a stale CSRF token — the page sat open past its session. Reload and retry. |
| Real client IP wrong | `trust_proxy: true`, and the proxy sets `X-Forwarded-For` (we read its right-most entry). Two proxies in front? The inner one's view wins — not supported yet. |

---

## Status

Working and verified end-to-end: zone + record CRUD via the admin UI, the native
JSON API, and the Cloudflare facade; per-type input validation on every surface;
the DDNS endpoint; SSO login; `admin import`; Prometheus `/metrics` +
`/healthcheck`; and the sync worker rendering zones + draining the journal against
both the `log` and `knot` backends. Remaining gaps (passkeys, the SSO
group-mapping subset) are tracked in [`PRD.md`](PRD.md).

## License

GPL-3.0-or-later. See [`LICENSE`](LICENSE). Copyright © 2026 Tomas Hlavacek.
