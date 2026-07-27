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
- [Authorization model](#authorization-model) — L1/L2/L3, API keys, SSO
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
field is validated on input and carries inline help. The full console is L3
(admin group); non-admin users work through the DDNS/API surfaces and the
self-service profile page.

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
Basic (rejected for 2FA/SSO users — use a token) or `Authorization: Bearer <key>`.
The path only creates/updates A/AAAA (never deletes); the per-record check gates
what a token can touch.

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

Zones: read/update need L2, create/delete need L3. Records: A/AAAA read+update
need L1, everything else L2. Input is validated per type (IP literals, DNS names,
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

| Level | Scope | Powers |
|-------|-------|--------|
| **L1** | a record set at `(zone, label)` | read & update the A/AAAA set |
| **L2** | a whole zone | full CRUD on every RR in the zone |
| **L3** | global (the `admin` group) | anything, incl. the operator console |

L3 = membership in the `admin` group; L2 = a **zone-role** grant (group ↔ zone);
L1 = an **rr-role** grant (group ↔ zone+label). A user gets the union of their
groups' grants. Users, groups, and grants are managed **only** in the operator
console (or via SSO), never on the API.

**API keys (bearer tokens)** are self-service on the profile page (`/profile`,
below password + 2FA): a user mints/revokes their own keys, with the level picker
capped at their max level and re-capped server-side (so an L2 user can mint an L1
key for a router). Only the key's hash is stored; the raw key is shown once.

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

`0` turns either counter off, and the two windows are independent. Requests carrying **no** credential
are a plain `401` and are not counted, so an anonymous scanner can't lock out everyone sharing its
address. Checks made by an *already authenticated* caller (the password confirmation on `/profile`, 2FA
enrolment) are deliberately not counted — that's session theft, not brute force.

**Unlocking is a row delete in the console.** The counters live in the database
(`auth_username_lockout`, `auth_ip_lockout`), and the admin console shows them as **Locked accounts**
and **Locked addresses**. Delete a row and that account or address is free immediately; leave it and it
clears itself when the lockout expires. The delete is L3-gated and lands in the audit log like any
other change. Because the rows are durable, a restart no longer resets anyone's budget.

The client address is resolved the same way everywhere — the forwarded hop when `trust_proxy: true`,
the socket peer otherwise — so the login form, the DDNS endpoint, the APIs and the audit log all agree
on who a caller is. One operational note: while an address is locked, *valid* callers from it are
refused too, so keep `ip_lockout_after` well above what a broken client produces if your users share an
address (CGNAT, an office NAT). Watch `teleddns_auth_failures_total{reason="locked"}`.

### Single sign-on (SSO)

Optional OpenID Connect login (Authorization Code + PKCE), via relativelylight's
`sso` module. Configure a `public_url` and one entry per IdP under
`sso_providers`; a **"Sign in with …"** button then appears on the login page and
the callback URL is `<public_url>/login/sso/<name>/callback` (register that at the
IdP). On first login an SSO user is created (`auto_register: true` by default) as
an external account — no local password/2FA.

**Group mapping.** Declarative `group_rules` run on **every** login and their
result is *reconciled* onto the user (groups added/removed to match), and those
groups carry L1/L2/L3 via the zone/rr grants. Each rule keys off a `claim`
(default `email`):

- a rule whose `claim` is the provider's **`username_claim`** (default `email`) is
  matched against the username by `regex` (or `equals`, anchored) — the fallback
  for IdPs with no group claim (e.g. plain Google);
- any other `claim` (e.g. `groups` from Okta/a corporate IdP, requiring that
  scope) contributes groups when the claim **exactly equals** the rule's `equals`
  value. (Regex on a non-username claim isn't supported and is ignored.)

Rule-named groups are created automatically. There is no admin special-casing — a
rule that names the `admin` group grants L3, so scope rules carefully.

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

Restrict the operability endpoints with `ops_allowed_ips` (a CIDR allow-list
applied on top of `allowed_ips`, after the reverse-proxy real-IP rewrite).

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
  - id: catalog                        # Knot GENERATES the catalog from member zones
    catalog-role: generate
    catalog-zone: catalog.example.
    storage: /var/lib/knot/catalog
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

`zonefile-load: difference` + `zonefile-sync: -1` is what turns full-file
regeneration on the master into **incremental IXFR** to secondaries while keeping
teleddns the sole writer.

**Run Knot from the configuration database (required).** teleddns declares each
zone at runtime with `knotc conf-set zone[<origin>]`, which operates on Knot's
config *database* (confdb), not the text file. So import the base config and start
`knotd` with `-C`:

```sh
sudo install -d -o knot -g knot /var/lib/knot/zones /var/lib/knot/catalog
sudo systemctl stop knot
sudo knotc conf-import /etc/knot/knot.conf          # load templates/keys/acl/catalog into the confdb
# Point knotd at the confdb (env var name differs by distro: KNOTD_ARGS on Fedora/RHEL,
# KNOTD_OPTS on Debian/Ubuntu):
sudo mkdir -p /etc/systemd/system/knot.service.d
printf '[Service]\nEnvironment=KNOTD_ARGS=-C /var/lib/knot/confdb\n' \
    | sudo tee /etc/systemd/system/knot.service.d/confdb.conf
sudo systemctl daemon-reload && sudo systemctl start knot
knotc conf-read 'zone[catalog.]'                    # sanity: reads the committed confdb
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
ops_allowed_ips: ["10.9.0.0/24"]                  # Prometheus / uptime host
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
real client IP (teleddns reads it because `trust_proxy: true` — needed for rate
limiting, audit, and `ops_allowed_ips`). Pick one. (For an internal/eval box you
can skip the proxy and bind `listen_addr: "0.0.0.0:8080"` directly.)

**Caddy** — automatic certificates:

```
ddns.example.com {
    reverse_proxy 127.0.0.1:8080     # sets X-Forwarded-For / -Proto by default
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
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
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
    server t1 127.0.0.1:8080     # HAProxy appends X-Forwarded-For with `option forwardfor`
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
  - { id: master, address: 198.51.100.5, key: xfr.example.com. }
acl:
  - { id: acl_master, key: xfr.example.com., action: notify }
template:
  - { id: catalog, catalog-role: interpret, master: master, acl: acl_master }
zone:
  - { domain: catalog.example., catalog-role: interpret, master: master, acl: acl_master }
```

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
# Log in at https://ddns.example.com/, mint an L3 API key on /profile, then:
KEY=…; URL=https://ddns.example.com
curl -X POST $URL/api/zones -H "Authorization: Bearer $KEY" \
     -H 'Content-Type: application/json' -d '{"origin":"example.com."}'
curl -X POST $URL/api/zones/1/rr -H "Authorization: Bearer $KEY" \
     -H 'Content-Type: application/json' -d '{"type":"A","name":"www","value":"1.2.3.4"}'

knotc zone-status example.com.                      # declared + served on the master
kdig @127.0.0.1 www.example.com. A +short           # → 1.2.3.4
kdig @<secondary> www.example.com. A +short         # → 1.2.3.4 (auto-provisioned)
```

`/healthcheck` should report `knot=up` and a recent `last_push`.

### 7. Backups, upgrades, troubleshooting

- **Back up `db_dsn`** (the SQLite file or Postgres DB) — it is the source of
  truth; zone files under `knot_zone_dir` are regenerated from it.
- **Upgrade:** replace the binary and `systemctl restart teleddns-server`. The
  startup migrator applies pending schema changes; the worker re-pushes as needed.

| Symptom | Check |
|---|---|
| `knot=down` in `/healthcheck` | teleddns can run `knotc status` (`knotc_path`; it runs as `knot`, so the socket is reachable). |
| Pushes fail / dead-letter | `journalctl -u teleddns-server` (the error includes the knotc command, exit code, stderr/stdout); `knot_zone_dir` writable. |
| `conf-set zone[...]` fails | Knot must run from the **confdb** (step 2) — `conf-set` on a file-configured `knotd` fails. |
| Zone served but secondary empty | catalog wiring: `knotc zone-status catalog.example.`; TSIG secret matches; ACL/notify. |
| DDNS `!yours` for a valid user | the token's level + the group's zone/rr grant (see [Authorization model](#authorization-model)). |
| Real client IP wrong | `trust_proxy: true` and the proxy sets `X-Forwarded-For`. |

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
