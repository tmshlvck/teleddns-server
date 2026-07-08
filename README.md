# teleddns-server

DNS management + Dynamic DNS server (Go rewrite). It runs **co-located with a
Knot DNS master**: it owns the zone data (a small DB), serves a dyndns2 DDNS
endpoint, a JSON management API (plus a Cloudflare-compatible facade for
cert-manager / external-dns), and an operator web UI, and pushes changes into the
local Knot via `knotc`. Secondary servers replicate natively over **AXFR/TSIG**
and auto-provision from a **catalog zone (RFC 9432)** — teleddns never talks to
other teleddns instances.

Design/roadmap live in [`PLAN.md`](PLAN.md); the wire contract for DDNS clients
is in [`PRD.md`](PRD.md). For a full production runbook — systemd service,
Caddy/TLS with correct client-IP forwarding, and secondary **Knot or BIND9**
via the catalog zone — see [`DEPLOY.md`](DEPLOY.md).

## Build

Pure-Go (no cgo); produces a static binary.

```sh
CGO_ENABLED=0 go build -o teleddns-server ./cmd/teleddns-server
```

## Configure

Copy [`config.sample.yaml`](config.sample.yaml) and edit. The essentials:

```yaml
db_dsn: "sqlite:///var/lib/teleddns/db.sqlite"   # or postgres://…
listen_addr: "127.0.0.1:8080"

backend: "knot"                 # "log" (default, no-op) or "knot"
knot_zone_dir: "/var/lib/knot"  # where zone files are written (must match the Knot template's storage)
knotc_path: "/usr/sbin/knotc"
knot_template: "master"         # the knot.conf template teleddns assigns to each managed zone
```

All keys are optional (built-in defaults apply); durations are quoted strings
(`"10s"`). Config file is found via `-c/--config`, `$TELEDDNS_CONFIG`,
`./config.yaml`, or `/etc/teleddns-server/config.yaml`.

## Run

```sh
teleddns-server -c /etc/teleddns.yaml
```

On first start it seeds an `admin` user and logs the generated password once
(`level=WARN msg="seeded initial admin user"`). Reset it any time:

```sh
teleddns-server -c /etc/teleddns.yaml admin reset-password admin
```

Bulk-load records from a BIND zone file (parsed with `miekg/dns`; the origin
comes from the file's SOA / `$ORIGIN`, or pass `--origin`). Records go through
the same validation + Knot-sync path as the API. `--replace` clears the zone's
existing records first; the default merges. Reads stdin with `-`:

```sh
teleddns-server -c /etc/teleddns.yaml admin import example.com.zone
teleddns-server -c /etc/teleddns.yaml admin import --replace example.com.zone
```

Then:

- Web UI / admin: `http://127.0.0.1:8080/admin`
- API docs: `/swagger` (Swagger UI) and `/docs` (built-in), spec at `/openapi.json`
- Management API: `/api/zones` + `/api/zones/{id}/rr` (see Management API)
- Health: `/healthcheck` · Metrics: `/metrics` (see Monitoring)
- DDNS: `GET /nic/update|/ddns/update|/update?hostname=…&myip=…` (HTTP Basic or `Authorization: Bearer <api-key>`)

## Management API

A JSON API for zones and resource records, for tooling (external-dns,
cert-manager, libdns, …). **Bearer only** — `Authorization: Bearer <api-key>`
(mint a key on `/preferences`); the key's level scopes access
(`min(token, your-effective-level)`). Browse it at `/docs`.

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

# list / get / update / delete
curl $URL/api/zones/1/rr -H "Authorization: Bearer $KEY"          # X-Total-Count header
curl -X DELETE $URL/api/zones/1/rr/a-1 -H "Authorization: Bearer $KEY"
```

Zones: read/update need L2 on the zone, create/delete need L3 (admin). Records:
A/AAAA read+update need L1, everything else L2. Mutations bump the SOA serial and
push to Knot exactly like the admin UI. User/group/role management is **not** on
the API — use the operator UI or your IdP (see [`PLAN.md`](PLAN.md)).

Lists are paginated (`?page`/`?per_page`, default 50 / max 500) with an
`X-Total-Count` header and `?type`/`?name` filters. A `POST` may carry an
`Idempotency-Key` header — a retry within 24h replays the original response
(`Idempotency-Replayed: true`) instead of creating a duplicate.

### Cloudflare-compatible API (cert-manager, external-dns)

For tooling that only speaks Cloudflare's API, teleddns exposes a compatible
facade under `/client/v4` (envelope, record shape, `/user/tokens/verify`). Point
the tool at teleddns as if it were Cloudflare, using a teleddns API key as the
**API token**:

- **cert-manager** (ACME DNS01): set the solver's `apiTokenSecretRef` to a
  teleddns key and override the API base URL to `https://<host>/client/v4`.
- **external-dns**: `--provider=cloudflare` with `CF_API_TOKEN=<teleddns-key>`
  and the base URL pointed at `https://<host>/client/v4`.

Supported record types: A, AAAA, CNAME, TXT, NS, MX (what those tools use). The
key's level scopes which zones it can touch, same as the native API.

## Single sign-on (SSO)

Optional OpenID Connect login (Google, Okta, Keycloak, Entra, …), configured
under `sso_providers` with a `public_url` base for the redirect. **Groups are
provisioned from rules on every login:** each rule matches a claim (`equals` or
`regex`; `claim` defaults to `email`) and contributes its `groups`; the union is
reconciled — so removing a user from an IdP group deprovisions them here, while
groups no rule names (manual grants) are left untouched. Those local groups are
what carry L1/L2/L3 via `GroupZoneRole` / `GroupRRRole`.

```yaml
public_url: "https://ddns.example.com"
sso_providers:
  - name: google                     # no groups claim → match on email
    issuer: "https://accounts.google.com"
    client_id: "…"
    client_secret: "…"
    group_rules:
      - regex: "@example\\.com$"
        groups: ["example-users"]
  - name: okta                       # groups array claim
    issuer: "https://dev-123.okta.com"
    client_id: "…"
    client_secret: "…"
    group_rules:
      - {claim: "groups", equals: "dns-operators", groups: ["example-ops"]}
```

There is no admin special-casing — a rule that assigns your admin group grants
L3, so scope rules carefully. See [`config.sample.yaml`](config.sample.yaml) for
the full commented example.

## Monitoring

Two operability endpoints. Restrict them with `ops_allowed_ips` (a CIDR
allow-list applied *on top of* `allowed_ips`); empty = no extra restriction. The
check runs after the reverse-proxy real-IP rewrite, so list the monitoring
host's real IP even behind Caddy (`trust_proxy: true`).

- **`GET /healthcheck`** — always HTTP 200; the body's first token is `OK` or
  `WARN`. Health means *can we serve and replicate DNS*, not *did clients send
  updates* — a server with zero DDNS/API/UI traffic is healthy. It reports

  ```
  OK uptime=<s> zones=<n> records=<n> pending=<n> failed=<n> knot=<up|down|na> last_push=<unixts>
  ```

  and flips to `WARN` when the sync worker has stalled, a push is dead-lettered
  (`failed>0`), the push backlog is stuck (oldest unfinished task older than
  `warn_on_nopush`), or the `knot` backend is unreachable (`knot=down`).
  `knot=na` means the no-op `log` backend.

- **`GET /metrics`** — Prometheus exposition: `teleddns_zones`,
  `teleddns_records`(+`_by_type`), `teleddns_ddns_updates_total{result}`,
  `teleddns_auth_failures_total{surface,reason}`, `teleddns_ratelimited_total`,
  `teleddns_backend_push_seconds`/`_total`, `teleddns_pending_pushes{state}`,
  `teleddns_worker_last_tick_seconds`, `teleddns_knot_up`. Since regular updates
  aren't expected, update *volume* is the abuse signal — alert on
  `rate(teleddns_ddns_updates_total[5m])` and on the auth-failure / rate-limit
  counters (a stolen or brute-forced credential). Metrics carry no per-user
  labels; the structured log identifies the actor.

## How teleddns drives Knot

The backend keeps **no** Knot config of its own. On a change it:

1. regenerates the **full zone file** to `knot_zone_dir/<zone>.zone`;
2. on a zone's first push, **declares it** in Knot's config DB —
   `knotc conf-begin; conf-set 'zone[<z>]'; conf-set 'zone[<z>].template'
   <knot_template>; conf-commit` (idempotent, cached);
3. `knotc zone-reload <zone>`.

With `zonefile-load: difference` in the template, Knot diffs the regenerated
file and propagates an **incremental IXFR** to secondaries — so full-file
regeneration on the master still yields incremental replication. Deleting a
zone runs `conf-unset` + removes the file.

The **template name is global config** (`knot_template`), applied to every
managed zone. Everything cluster-static — the transfer ACL, TSIG keys, catalog
membership — lives in the operator's base `knot.conf` template, so teleddns
only has to assign that template per zone.

## Operator base `knot.conf` (master with catalog generation)

teleddns assigns the `master` template to each zone; the template makes the
zone a catalog member, and Knot generates the catalog the secondaries consume.
This config is `knotc conf-check`-valid on Knot 3.4 and loads the catalog zone
as `role: master | catalog: generate`:

```yaml
server:
    rundir: "/run/knot"
    listen: [ 127.0.0.1@53 ]
    automatic-acl: on

database:
    storage: "/var/lib/knot"

key:
  - id: xfrkey
    algorithm: hmac-sha256
    secret: "<base64 secret>"        # head -c 32 /dev/urandom | base64

remote:
  - id: slave
    address: 192.0.2.2@53            # the secondary
    key: xfrkey

acl:
  - id: slave_acl
    address: 192.0.2.2
    key: xfrkey
    action: transfer

template:
  - id: master
    storage: "/var/lib/knot"         # must equal teleddns knot_zone_dir
    file: "%s.zone"
    zonefile-load: difference        # → incremental IXFR to secondaries
    catalog-role: member
    catalog-zone: catalog.
    acl: slave_acl
    notify: slave

zone:
  - domain: catalog.
    catalog-role: generate
    acl: slave_acl
    notify: slave
```

Set teleddns `knot_zone_dir: /var/lib/knot` and `knot_template: master`.
Create a zone in teleddns → it is declared as a `master`-template member →
Knot adds it to `catalog.` (check with `knotc zone-read catalog.`).

## Secondary (consumes the catalog)

A plain Knot instance, configured once to interpret the catalog and AXFR from
the master with the shared TSIG key — it then auto-provisions every member
zone (no per-zone config):

```yaml
key:
  - id: xfrkey
    algorithm: hmac-sha256
    secret: "<same base64 secret>"

remote:
  - id: master
    address: 192.0.2.1@53
    key: xfrkey

acl:
  - id: master_acl
    address: 192.0.2.1
    key: xfrkey
    action: notify

template:
  - id: catalog-member
    master: master
    acl: master_acl

zone:
  - domain: catalog.
    master: master
    acl: master_acl
    catalog-role: interpret
    catalog-template: catalog-member
```

## Status

Working and tested against Knot DNS 3.4.6. Complete and verified: zone + record
CRUD via the admin UI, the **JSON management API** and the **Cloudflare-compatible
facade**, the DDNS endpoint, `admin import` for BIND zone files, Prometheus
`/metrics` + the health/replication `/healthcheck`, and the sync worker driving
`knotc` (declare zone, write file, reload) so `kdig` serves the records. Catalog
generation on the master is verified; full secondary auto-provisioning is the
documented setup above. Milestones M0–M6 are done; see [`PLAN.md`](PLAN.md) §7
for the optional/deferred items that remain.
