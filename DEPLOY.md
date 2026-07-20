# Deploying teleddns-server with Knot DNS

A production runbook: install teleddns co-located with a **Knot DNS master**, put
it behind TLS, wire it into Knot, and auto-provision **secondaries** (Knot or
BIND 9) from a catalog zone. Operator usage is in [`README.md`](README.md); the
design is in [`PRD.md`](PRD.md).

```
              ┌────────────────────── master host ──────────────────────┐
  operators → │  Caddy/nginx (TLS) → teleddns-server → knotc → Knot master│ ──AXFR/IXFR+catalog──┐
  DDNS/API  → │        (owns the DB + zone files)      (authoritative)     │                     │
              └───────────────────────────────────────────────────────────┘                     ▼
                                                                            secondaries (Knot / BIND 9)
                                                                            auto-provision from catalog.
```

teleddns is **control-plane only** — it is not in the DNS query path and holds no
DNSSEC keys. It writes zone files and calls `knotc`; Knot serves and signs.

## 0. Prerequisites

- A Linux host running **Knot DNS 3.x** (the master), with `knotc` and a control
  socket teleddns can reach.
- A dedicated system user, e.g. `teleddns`, that can run `knotc` and write into
  Knot's zone storage directory.
- A reverse proxy for TLS (examples use Caddy).

## 1. Knot master — base configuration

teleddns keeps **no Knot config of its own** beyond assigning a template per
zone. Everything cluster-static lives in the operator's `knot.conf`: the control
socket, the TSIG key(s), the transfer ACL, a **`master` template** that makes each
zone a catalog member, and the **catalog zone** that generates membership for the
secondaries.

`/etc/knot/knot.conf` on the master:

```yaml
server:
    listen: 0.0.0.0@53
    listen: ::@53

control:
    # teleddns runs knotc against this socket; the teleddns user needs access.
    listen: /run/knot/knot.sock

key:
  - id: xfr.example.com.
    algorithm: hmac-sha256
    secret: "REPLACE_WITH_BASE64_SECRET"     # keymgr -t xfr.example.com.

acl:
  - id: acl_secondary
    key: xfr.example.com.
    action: transfer

remote:
  - id: secondary1
    address: 203.0.113.10                     # a secondary's IP
    key: xfr.example.com.

# The catalog zone: Knot GENERATES its contents from every zone that is a member
# (see the `master` template below) and serves it to the secondaries by AXFR.
template:
  - id: catalog
    catalog-role: generate
    catalog-zone: catalog.example.          # the catalog zone name
    storage: /var/lib/knot/catalog

  # teleddns assigns THIS template to every zone it manages.
  - id: master
    storage: /var/lib/knot/zones            # MUST equal teleddns `knot_zone_dir`
    file: "%s.zone"                          # Knot reads <storage>/<zonename>.zone
    zonefile-load: difference                # diff our regenerated file → incremental IXFR
    zonefile-sync: -1                        # never let Knot overwrite our file (teleddns owns it)
    catalog-role: member                     # each managed zone joins the catalog…
    catalog-zone: catalog.example.          # …this one
    acl: acl_secondary
    notify: secondary1
    # dnssec-signing: on                     # optional: let Knot sign

zone:
  - domain: catalog.example.
    catalog-role: generate
    acl: acl_secondary
    notify: secondary1
```

Notes:

- **`storage` must equal teleddns `knot_zone_dir`** and the default `file: "%s.zone"`
  matches the file teleddns writes (`<origin>.zone`, e.g. `example.com.zone`).
- `zonefile-load: difference` + `zonefile-sync: -1` is what makes full-file
  regeneration on the master yield **incremental IXFR** to secondaries while
  keeping teleddns the sole writer of the file.
- Generate a TSIG key with `keymgr -t xfr.example.com. hmac-sha256`.
- Validate before starting: `knotc conf-check`.

Create the directories and start Knot:

```sh
install -d -o knot -g knot /var/lib/knot/zones /var/lib/knot/catalog
systemctl enable --now knot
knotc conf-check && knotc status
```

### 1a. Run Knot from the configuration database (required)

teleddns declares each managed zone at runtime with `knotc conf-begin / conf-set
zone[<origin>] / conf-commit`. **That transactional API operates on Knot's
configuration *database* (confdb), not the text file** — so `knotd` must run from
the confdb, with the base config above (templates, keys, ACL, catalog zone)
imported into it. If `knotd` runs from the plain `knot.conf`, every `conf-set`
fails and no zones get declared.

Import the base config and point `knotd` at the confdb:

```sh
systemctl stop knot
knotc conf-import /etc/knot/knot.conf          # load templates/keys/acl/catalog into the confdb
# Start knotd against the confdb. Distro units read a drop-in env var (KNOTD_ARGS
# on RHEL/Fedora, KNOTD_OPTS/knot.conf on Debian); set it to include -C:
mkdir -p /etc/systemd/system/knot.service.d
printf '[Service]\nEnvironment=KNOTD_ARGS=-C /var/lib/knot/confdb\n' \
    > /etc/systemd/system/knot.service.d/confdb.conf
systemctl daemon-reload && systemctl start knot
knotc conf-read 'zone[catalog.]'               # sanity: reads the committed confdb
```

Keep the base config's `zone:` blocks to just the **catalog zone** — teleddns
adds and removes the per-domain `zone[...]` entries itself, idempotently (it skips
re-declaring a zone that already exists, so a teleddns restart is safe). To change
the templates/keys later, edit `knot.conf` and re-run `knotc conf-import` (or use
`knotc conf-set` directly).

## 2. Install teleddns-server

```sh
cargo build --release
install -m0755 target/release/teleddns-server /usr/local/bin/teleddns-server

useradd --system --home /var/lib/teleddns --shell /usr/sbin/nologin teleddns
install -d -o teleddns -g teleddns /var/lib/teleddns /etc/teleddns

# Let teleddns reach the Knot control socket and write zone files.
usermod -aG knot teleddns
# Ensure the zone dir is group-writable by knot's group:
chmod 0775 /var/lib/knot/zones
```

`/etc/teleddns/teleddns-server.yaml`:

```yaml
db_dsn: "sqlite:///var/lib/teleddns/db.sqlite"   # or postgres://…
listen_addr: "127.0.0.1:8080"                     # behind the reverse proxy
trust_proxy: true                                 # honor X-Forwarded-For from Caddy

backend: "knot"
knot_zone_dir: "/var/lib/knot/zones"              # == the master template's storage
knotc_path: "/usr/sbin/knotc"
knot_template: "master"                           # the template above

public_url: "https://ddns.example.com"            # external HTTPS base (SSO + cookies)
ops_allowed_ips:
  - "10.9.0.0/24"                                  # Prometheus / uptime host
```

## 3. systemd unit

`/etc/systemd/system/teleddns-server.service`:

```ini
[Unit]
Description=teleddns-server (DNS + DDNS control plane)
After=network-online.target knot.service
Wants=network-online.target

[Service]
User=teleddns
Group=teleddns
SupplementaryGroups=knot
ExecStart=/usr/local/bin/teleddns-server -c /etc/teleddns/teleddns-server.yaml
Restart=on-failure
RestartSec=2
# Hardening (relax if it blocks the knot socket / zone dir):
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/teleddns /var/lib/knot/zones /run/knot
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```sh
systemctl daemon-reload
systemctl enable --now teleddns-server
journalctl -u teleddns-server | grep "seeded initial admin user"   # note the one-time password
```

Reset the admin password whenever you like:

```sh
sudo -u teleddns teleddns-server -c /etc/teleddns/teleddns-server.yaml admin reset-password admin
```

## 4. Reverse proxy + TLS (Caddy)

teleddns listens on plain HTTP on loopback; the proxy terminates TLS and forwards
the real client IP (teleddns reads it because `trust_proxy: true`). The DDNS +
API surfaces need the real IP for rate limiting, audit, and `ops_allowed_ips`.

`/etc/caddy/Caddyfile`:

```
ddns.example.com {
    reverse_proxy 127.0.0.1:8080
    # Caddy sets X-Forwarded-For / X-Forwarded-Proto by default.
}
```

`reload caddy`, then confirm the SSO callback base (`public_url`) matches this
hostname.

## 5. Secondaries

Secondaries **auto-provision** every zone teleddns creates, via the catalog zone
— you configure each secondary once and never touch it per zone.

### Knot secondary

`/etc/knot/knot.conf` on the secondary:

```yaml
key:
  - id: xfr.example.com.
    algorithm: hmac-sha256
    secret: "SAME_BASE64_SECRET_AS_THE_MASTER"

remote:
  - id: master
    address: 198.51.100.5                    # the master's IP
    key: xfr.example.com.

acl:
  - id: acl_master
    key: xfr.example.com.
    action: notify

template:
  - id: catalog
    catalog-role: interpret                   # consume the catalog from the master
    master: master
    acl: acl_master

zone:
  - domain: catalog.example.
    catalog-role: interpret
    master: master
    acl: acl_master
```

`knotc conf-check && systemctl restart knot`. As teleddns creates zones on the
master, they appear in `catalog.example.` and the secondary provisions + transfers
them automatically.

### BIND 9 secondary (catalog zone)

```
# named.conf
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

## 6. Verify end to end

```sh
# 1. Log in at https://ddns.example.com/ (admin + the seeded password), mint an
#    L3 API key on /profile (the API-keys card below password + 2FA), then:
KEY=…; URL=https://ddns.example.com
curl -X POST $URL/api/zones -H "Authorization: Bearer $KEY" \
     -H 'Content-Type: application/json' -d '{"origin":"example.com."}'
curl -X POST $URL/api/zones/1/rr -H "Authorization: Bearer $KEY" \
     -H 'Content-Type: application/json' -d '{"type":"A","name":"www","value":"1.2.3.4"}'

# 2. On the master, the zone is declared and served:
knotc zone-status example.com.
kdig @127.0.0.1 www.example.com. A +short          # → 1.2.3.4

# 3. On a secondary, it auto-provisioned from the catalog:
kdig @<secondary> www.example.com. A +short         # → 1.2.3.4

# 4. A DDNS client:
curl "$URL/nic/update?hostname=www.example.com&myip=5.6.7.8" -H "Authorization: Bearer $KEY"
```

`/healthcheck` should report `knot=up` and a recent `last_push`; if a push
dead-letters it shows `WARN … failed>0`.

## 7. Monitoring

Scrape `https://ddns.example.com/metrics` (from a host in `ops_allowed_ips`).
Alert on:

- `rate(teleddns_ddns_updates_total[5m])` — unusual update volume (a stolen
  credential); regular updates are not expected.
- `teleddns_ratelimited_total` and `teleddns_auth_failures_total` — brute force /
  a revoked-but-retried credential.
- `teleddns_pending_pushes{state="failed"} > 0` — a dead-lettered push.
- `teleddns_knot_up == 0` — Knot unreachable from teleddns.

Also poll `/healthcheck` (HTTP 200 always; alert on a `WARN` first token).

## 8. Backups & upgrades

- **Back up** `db_dsn` (the SQLite file or the Postgres database) — it is the
  source of truth. The zone files under `knot_zone_dir` are regenerated from it.
- **Upgrade:** replace the binary and `systemctl restart teleddns-server`. The
  startup migrator applies any pending schema changes; the sync worker resets
  in-flight pushes and re-pushes as needed.
- **Rebuild a zone file** (e.g. after a manual edit): any record change re-renders
  it; or `admin import --replace` to reload from a BIND file.

## 9. Troubleshooting

| Symptom | Check |
|---|---|
| `knot=down` in `/healthcheck` | teleddns can run `knotc status` (socket perms, `knotc_path`, `SupplementaryGroups=knot`). |
| Pushes fail / dead-letter | `journalctl -u teleddns-server` (the error now includes the knotc command, exit code, and stderr+stdout); `knot_zone_dir` writable; `knotc conf-check` on the master. |
| `conf-set zone[...]` fails | Knot must run from the **confdb** (§1a) — `conf-set` on a file-configured `knotd` fails. Confirm `knotd` was started with `-C …/confdb` and the base config was `conf-import`ed. |
| Zone served but secondary empty | catalog wiring: `knotc zone-status catalog.example.`; TSIG secret matches; ACL/notify. |
| DDNS `!yours` for a valid user | the token's level + the group's zone/rr grant (see README "Authorization model"). |
| Real client IP wrong in logs/limits | `trust_proxy: true` and the proxy sets `X-Forwarded-For`. |
