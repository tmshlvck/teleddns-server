# teleddns-server

DNS management + Dynamic DNS server (Go rewrite). It runs **co-located with a
Knot DNS master**: it owns the zone data (a small DB), serves a dyndns2 DDNS
endpoint and an operator web UI, and pushes changes into the local Knot via
`knotc`. Secondary servers replicate natively over **AXFR/TSIG** and
auto-provision from a **catalog zone (RFC 9432)** — teleddns never talks to
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

Then:

- Web UI / admin: `http://127.0.0.1:8080/admin`
- API docs: `/swagger` (Swagger UI) and `/docs` (built-in), spec at `/openapi.json`
- Health: `/healthcheck`
- DDNS: `GET /nic/update|/ddns/update|/update?hostname=…&myip=…` (HTTP Basic or `Authorization: Bearer <api-key>`)

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

Working and tested against Knot DNS 3.4.6: zone + record CRUD via the admin,
the DDNS endpoint, and the sync worker driving `knotc` (declare zone, write
file, reload) so `kdig` serves the records. Catalog generation on the master
is verified; full secondary auto-provisioning is the documented setup above.
See [`PLAN.md`](PLAN.md) for the milestone status and what's still deferred.
