# teleddns-server

DNS management + Dynamic DNS server (Rust). It runs **co-located with a Knot DNS
master**: it owns the zone data in a small database, serves a dyndns2 DDNS
endpoint, a JSON management API (plus a Cloudflare-compatible facade for
cert-manager / external-dns), and an operator web UI, and pushes changes into the
local Knot via `knotc`. Secondaries replicate natively over **AXFR/TSIG** and
auto-provision from a **catalog zone (RFC 9432)** — teleddns never talks to other
teleddns instances.

It is a Rust rewrite built on the [`relativelylight`](../relativelylight)
back-office library (SeaORM CRUD engine, auto-generated admin UI, auth). The
product spec is in [`PRD.md`](PRD.md); the rewrite plan and architecture are in
[`RUSTREWRITE.md`](RUSTREWRITE.md); the production runbook is in
[`DEPLOY.md`](DEPLOY.md); contributor orientation is in [`AGENTS.md`](AGENTS.md).

## Build

```sh
cargo build --release      # target/release/teleddns-server
```

## Configure

Copy [`teleddns-server.sample.yaml`](teleddns-server.sample.yaml) and edit. The
essentials:

```yaml
db_dsn: "sqlite:///var/lib/teleddns/db.sqlite"   # or postgres://…
listen_addr: ":8080"

backend: "knot"                       # "log" (default, no-op) or "knot"
knot_zone_dir: "/var/lib/knot/zones"  # where zone files are written (must match the Knot template's storage)
knotc_path: "/usr/sbin/knotc"
knot_template: "master"               # the knot.conf template teleddns assigns to each managed zone
```

Every key is optional (built-in defaults apply); durations are quoted strings
(`"10s"`). The config file is found via `-c/--config`, `$TELEDDNS_CONFIG`,
`./teleddns-server.yaml`, or `/etc/teleddns/teleddns-server.yaml`.

## Run

```sh
teleddns-server                                       # uses the default config path
teleddns-server -c /etc/teleddns/teleddns-server.yaml # or point at one explicitly
teleddns-server --version
```

On first start it seeds an `admin` user and logs the generated password once
(`WARN … seeded initial admin user … password=…`). Reset it any time:

```sh
teleddns-server admin reset-password admin
```

Bulk-load records from a BIND zone file (origin from the file's SOA / `$ORIGIN`,
or `--origin`). Records go through the same validation + Knot-sync path as the
API. `--replace` clears the zone's existing records first; the default merges.
Reads stdin with `-`:

```sh
teleddns-server admin import example.com.zone
teleddns-server admin import --replace example.com.zone
```

Then:

- Web UI / admin: `http://127.0.0.1:8080/` (login required)
- API docs: `/docs` (Swagger UI), spec at `/openapi.json`
- Management API: `/api/zones` + `/api/zones/{id}/rr` (see below)
- Profile — password, 2FA, and self-service API keys: `/profile` (also reached by clicking your username in the header)
- Health: `/healthcheck` · Metrics: `/metrics`
- DDNS: `GET /nic/update|/ddns/update|/update?hostname=…&myip=…` (HTTP Basic or `Authorization: Bearer <api-key>`)

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
below password + 2FA): a user mints/revokes
their own keys, with the level picker capped at their max level and re-capped
server-side (so an L2 user can mint an L1 key for a router). Only the key's hash
is stored; the raw key is shown once.

## DDNS endpoint

A drop-in dyndns2 server — any generic dyndns2 client (`ddclient`, MikroTik,
OPNsense/pfSense, UniFi, …) works with only a base-URL change. `GET
/nic/update|/ddns/update|/update` with `hostname` + `myip`/`myipv6`. Auth is HTTP
Basic (rejected for 2FA users — use a token) or `Authorization: Bearer <key>`.
The path only creates/updates A/AAAA (never deletes); the per-record check gates
what a token can touch. Responses use dyndns2 vocabulary (`good`/`nochg`/
`nohost`/`!yours`/`notfqdn`/`badauth`/`abuse`); the HTTP status is authoritative.
Per-record (60/h) and per-token (600/h) rate limits return `429 abuse`.

## Management API

A JSON API for zones and resource records, for tooling. **Bearer only** —
`Authorization: Bearer <api-key>`; the key's level scopes access. Browse it at
`/docs`.

Records use one **unified, type-discriminated** shape — `type` selects the kind
and only its rdata fields apply; the `id` is opaque and type-prefixed (`a-12`):

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
need L1, everything else L2. Mutations bump the SOA serial and push to Knot.
Lists paginate (`?page`/`?per_page`, default 50 / max 500) with an
`X-Total-Count` header and `?type`/`?name` filters. A `POST` may carry an
`Idempotency-Key` — a retry within 24h replays the original response
(`Idempotency-Replayed: true`); the same key with a different body → 422.
User/group/grant management is **not** on the API — use the operator UI.

### Cloudflare-compatible API (cert-manager, external-dns)

For tooling that only speaks Cloudflare's API, teleddns exposes a compatible
facade under `/client/v4` (envelope, record shape, `/user/tokens/verify`). Point
the tool at teleddns as if it were Cloudflare, using a teleddns API key as the
**API token**:

- **cert-manager** (ACME DNS01): set the solver's `apiTokenSecretRef` to a
  teleddns key and override the API base URL to `https://<host>/client/v4`.
- **external-dns**: `--provider=cloudflare` with `CF_API_TOKEN=<teleddns-key>`
  and the base URL pointed at `https://<host>/client/v4`.

Supported types: A, AAAA, CNAME, TXT, NS, MX. The key's level scopes which zones
it can touch, same as the native API.

## Single sign-on (SSO)

Optional OpenID Connect login (Authorization Code + PKCE), via relativelylight's
`sso` module. Configure a `public_url` and one entry per IdP under
`sso_providers`; a **"Sign in with …"** button then appears on the login page and
the callback URL is `<public_url>/login/sso/<name>/callback` (register that at the
IdP). On first login an SSO user is created (`auto_register: true` by default;
turn it off to require an admin to pre-create the account) as an external account
— no local password/2FA.

**Group mapping.** Declarative `group_rules` run on **every** login and their
result is *reconciled* onto the user (groups added/removed to match), and those
groups carry L1/L2/L3 via the zone/rr grants. Each rule keys off a `claim`
(default `email`):

- a rule whose `claim` is the provider's **`username_claim`** (default `email`) is
  matched against the username by `regex` (or `equals`, anchored) — the fallback
  for IdPs with no group claim (e.g. plain Google);
- any other `claim` (e.g. `groups` from Okta/a corporate IdP, requiring that scope)
  contributes groups when the claim **exactly equals** the rule's `equals` value.
  (Regex on a non-username claim isn't supported and is ignored with a warning.)

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

## Monitoring

Restrict both endpoints with `ops_allowed_ips` (a CIDR allow-list applied on top
of `allowed_ips`, after the reverse-proxy real-IP rewrite).

- **`GET /healthcheck`** — always HTTP 200; the body's first token is `OK` or
  `WARN`:

  ```
  OK uptime=<s> zones=<n> records=<n> pending=<n> failed=<n> knot=<up|down|na> last_push=<unixts>
  ```

  It flips to `WARN` when the sync worker stalls, a push is dead-lettered
  (`failed>0`), the backlog is stuck (`warn_on_nopush`), or `backend=knot` and
  `knotc` is unreachable (`knot=na` for the no-op `log` backend).

- **`GET /metrics`** — Prometheus exposition: `teleddns_zones`,
  `teleddns_records`(+`_by_type`), `teleddns_ddns_updates_total{result}`,
  `teleddns_ratelimited_total`, `teleddns_backend_push_total`,
  `teleddns_pending_pushes{state}`, `teleddns_worker_last_tick_seconds`,
  `teleddns_knot_up`. Since regular updates aren't expected, alert on
  `rate(teleddns_ddns_updates_total[5m])` and the rate-limit counter.

## How teleddns drives Knot

On a change the backend regenerates the **full zone file** to
`knot_zone_dir/<origin>.zone`, declares the zone in Knot's config DB on its first
push (`knotc conf-set … zone[<z>].template <knot_template>`, cached), and runs
`knotc zone-reload`. With `zonefile-load: difference` in the template, Knot diffs
the file and emits an **incremental IXFR** to secondaries. Everything
cluster-static (transfer ACL, TSIG keys, catalog membership) lives in the
operator's base `knot.conf`. See [`DEPLOY.md`](DEPLOY.md) for the full setup.

## Status

Working and verified with the `log` backend end-to-end: zone + record CRUD via
the admin UI, the native JSON API, and the Cloudflare facade; the DDNS endpoint;
`admin import`; Prometheus `/metrics` + the health/replication `/healthcheck`;
and the sync worker rendering zones + draining the journal. The `knot` backend
(`knotc` driver) is implemented; wire it up per [`DEPLOY.md`](DEPLOY.md). SSO
login is the main deferred item (see [`RUSTREWRITE.md`](RUSTREWRITE.md) §12).

## License

GPL-3.0-or-later. See [`LICENSE`](LICENSE). Copyright © 2026 Tomas Hlavacek.
