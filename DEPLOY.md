# Deployment

A primary **runs teleddns-server next to a Knot master**. Secondaries are
plain Knot or BIND instances that **auto-provision from a catalog zone**
(RFC 9432) and pull zones over **AXFR/IXFR authenticated with TSIG**.
teleddns-server never talks to the secondaries — DNS does.

```
            teleddns-server ──knotc──▶ Knot (primary/master)
                  │                        │  catalog zone "catalog."
              web UI / DDNS / API          │  + member zones
                                           ▼  AXFR/IXFR + NOTIFY (TSIG)
                              ┌────────────┴────────────┐
                        Knot (secondary)          BIND9 (secondary)
```

The only shared secret between primary and secondaries is the **TSIG key** —
same name, algorithm and secret on every host.

```sh
# generate a TSIG secret once; use the same value everywhere
head -c 32 /dev/urandom | base64
```

---

## 1. Primary — Knot master

Edit `/etc/knot/knot.conf`. teleddns assigns the `master` template to each
zone; the template makes the zone a catalog member, and Knot generates the
`catalog.` zone the secondaries consume.

```yaml
server:
    rundir: "/run/knot"
    listen: [ 0.0.0.0@53, ::@53 ]     # must be reachable by the secondaries
    automatic-acl: on

database:
    storage: "/var/lib/knot"

key:
  - id: xfrkey                         # TSIG key name — identical on all hosts
    algorithm: hmac-sha256
    secret: "<base64 secret>"

remote:
  - id: sec1
    address: 192.0.2.2@53             # a secondary
    key: xfrkey
  - id: sec2
    address: 192.0.2.3@53
    key: xfrkey

acl:
  - id: xfr_acl
    key: xfrkey
    action: transfer

template:
  - id: master
    storage: "/var/lib/knot/zones"    # MUST equal teleddns knot_zone_dir
    file: "%s.zone"
    zonefile-load: difference         # → incremental IXFR to secondaries
    catalog-role: member
    catalog-zone: catalog.
    acl: xfr_acl
    notify: [ sec1, sec2 ]

zone:
  - domain: catalog.
    catalog-role: generate
    acl: xfr_acl
    notify: [ sec1, sec2 ]
```

`database.storage` is where Knot keeps its own state (`confdb/`, `journal/`,
`timers/`, `keys/`, `catalog/`); the template's `storage` is where *zone files*
live. They default to the same `/var/lib/knot`, but keeping the zone files in
their own subdirectory — as Knot's own examples do — means teleddns writes into
a directory that holds nothing but zones:

```sh
mkdir -p /var/lib/knot/zones
chown knot:knot /var/lib/knot/zones
knotc conf-check       # validate the file
```

**Run Knot from its configuration database, not the file.** teleddns declares
each managed zone at runtime with `knotc conf-set` (assigning the `master`
template). Knot keeps those dynamic changes in its *configuration database*
(confdb). In plain file mode (`knotd -c knot.conf`, the default) the file is
re-read on **every restart**, silently discarding all dynamically-declared
zones — and with them their catalog membership; only zones written into
`knot.conf` itself (here, just `catalog.`) survive. Seed the confdb from the
file once, then point knotd at the confdb:

```sh
# import the base config into the confdb (default dir: /var/lib/knot/confdb)
knotc conf-import /etc/knot/knot.conf

# conf-import as root creates a root-owned confdb that knotd (user "knot")
# can't open ("failed to open configuration database … operation not
# permitted"); hand it to the knot user.
chown -R knot:knot /var/lib/knot/confdb

# tell knotd to use the confdb instead of the file:
#   Fedora/RHEL: /etc/sysconfig/knot     Debian/Ubuntu: /etc/default/knot
echo 'KNOTD_ARGS="-C /var/lib/knot/confdb"' >> /etc/default/knot

systemctl restart knot
```

After this, `knotc conf-*` changes — including teleddns's zone declarations —
persist across restarts. The text `knot.conf` is now just a one-time seed: to
change the static parts later (keys, remotes, template, the catalog zone),
prefer a live `knotc conf-set`. A fresh `knotc conf-import` is also fine but
**replaces** the whole confdb, dropping the managed zones until teleddns
re-declares each one on its next push (so re-save the affected zones in the UI,
or expect them to reappear as records change).

`automatic-acl: on` already lets the `notify` remotes transfer, so `xfr_acl`
is belt-and-braces; keep it if you also serve other clients.

## 2. Primary — teleddns-server

Build a static binary (on a build host with Go) and copy it over:

```sh
CGO_ENABLED=0 go build -o teleddns-server ./cmd/teleddns-server
scp teleddns-server root@primary:/usr/local/bin/
```

`/etc/teleddns/teleddns-server.yaml` (the default path — `-c` only needed
elsewhere):

```yaml
db_dsn: "sqlite:///var/lib/teleddns-server/db.sqlite"
listen_addr: "127.0.0.1:8080"        # plaintext; front with Caddy for TLS (§3)
trust_proxy: true                     # read the real client IP from the proxy (§3)

backend: "knot"
knot_zone_dir: "/var/lib/knot/zones"  # == the template's storage
knotc_path: "/usr/sbin/knotc"
knot_template: "master"               # the template from §1
backend_sync_delay: "5s"
```

Run it as the **`knot` user** so it can use the control socket
(`/run/knot/knot.sock`) and write zone files into `/var/lib/knot/zones`.
`/etc/systemd/system/teleddns-server.service`:

```ini
[Unit]
Description=teleddns-server
After=network-online.target knot.service
Wants=network-online.target knot.service

[Service]
User=knot
Group=knot
ExecStart=/usr/local/bin/teleddns-server -c /etc/teleddns/teleddns-server.yaml
StateDirectory=teleddns-server         # creates /var/lib/teleddns-server (knot:knot)
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```sh
systemctl daemon-reload && systemctl enable --now teleddns-server
journalctl -u teleddns-server | grep 'seeded initial admin'   # one-time admin password
# or: teleddns-server -c /etc/teleddns/teleddns-server.yaml admin reset-password admin
```

Open the UI at `http://127.0.0.1:8080/admin` (tunnel or reverse-proxy it),
create a zone and records, and confirm the primary serves them:

```sh
kdig @127.0.0.1 host.example.com A
knotc zone-read catalog.            # the new zone appears as a catalog member
```

---

## 3. TLS and client IP — Caddy

teleddns-server listens on `127.0.0.1:8080` in plaintext; put **Caddy** in
front for HTTPS. Caddy auto-provisions a Let's Encrypt certificate and forwards
the real client IP so the request log, DDNS audit, the rate limiter and the
`allowed_ips` filter all see the actual client instead of `127.0.0.1`.

`/etc/caddy/Caddyfile`:

```caddyfile
ddns.example.com {
    reverse_proxy 127.0.0.1:8080 {
        header_up X-Real-IP {remote_host}
    }
}
```

`header_up X-Real-IP {remote_host}` makes Caddy **set** (overwrite) the header
to the real TCP client. With `trust_proxy: true` (see §2), teleddns runs chi's
`RealIP` middleware, which prefers `X-Real-IP` and rewrites `RemoteAddr` — so
every downstream consumer (logs, audit, rate limit, IP allow-list) gets the
real client, and a client-supplied header can't spoof it. (`X-Forwarded-For` is
*appended* to by proxies, so its first entry is spoofable — prefer the explicit
`X-Real-IP` above. Caddy still sets `X-Forwarded-For`/`-Proto` too.)

Reload Caddy, then confirm the real IP shows up (under systemd the logs go to
journald; the request line is concise and `time=` is dropped):

```sh
systemctl reload caddy
journalctl -u teleddns-server -f
# level=INFO msg="GET /ddns/update => HTTP 200 (1.2ms)" ... client.ip=203.0.113.7 ...
# level=INFO msg=ddns result=good label=host zone=example.com. ip=203.0.113.7 src=203.0.113.7 user=router1
```

DDNS clients then point at `https://ddns.example.com/nic/update?...`.

> If Caddy itself sits behind a CDN/another proxy, configure its global
> `servers { trusted_proxies static <cidrs> }` and use `{client_ip}` instead of
> `{remote_host}` so the *originating* client is forwarded.

**SSO note.** If you enable OpenID Connect login, set `public_url` to this same
external HTTPS origin (`https://ddns.example.com`) — teleddns builds each
provider's OIDC redirect as `<public_url>/login/sso/<name>/callback`, and you
must register **that exact URL** as the authorized redirect URI at the IdP. The
callback must be reachable over HTTPS (i.e. through Caddy), so keep the `/login/`
paths proxied (the default `reverse_proxy` above already forwards everything).
Provider setup + `group_rules` are in [`README.md`](README.md).

---

## 4. Secondary — Knot

A stock Knot that interprets the catalog and transfers from the primary. No
per-zone config — members appear automatically.

```yaml
server:
    listen: [ 0.0.0.0@53, ::@53 ]
    automatic-acl: on

database:
    storage: "/var/lib/knot"

key:
  - id: xfrkey
    algorithm: hmac-sha256
    secret: "<same base64 secret>"

remote:
  - id: primary
    address: 192.0.2.1@53
    key: xfrkey

acl:
  - id: notify_acl
    address: 192.0.2.1
    key: xfrkey
    action: notify

template:
  - id: catalog-member
    master: primary
    acl: notify_acl

zone:
  - domain: catalog.
    master: primary
    acl: notify_acl
    catalog-role: interpret
    catalog-template: catalog-member
```

```sh
knotc conf-check && systemctl restart knot
knotc zone-status                    # catalog. + each member, role: slave
```

---

## 5. Secondary — BIND 9

BIND ≥ 9.18 (for RFC 9432 catalog zones). Define the TSIG key, the catalog
zone as a secondary, and a `catalog-zones` clause that auto-creates members.

```
key "xfrkey" {
    algorithm hmac-sha256;
    secret "<same base64 secret>";
};

options {
    directory "/var/cache/bind";
    recursion no;

    catalog-zones {
        zone "catalog."
            default-primaries { 192.0.2.1 key "xfrkey"; }
            zone-directory "catalog-members"     # writable by named
            in-memory no;
    };
};

zone "catalog." {
    type secondary;
    primaries { 192.0.2.1 key "xfrkey"; };
    file "catalog.db";
};
```

```sh
mkdir -p /var/cache/bind/catalog-members && chown bind:bind /var/cache/bind/catalog-members
named-checkconf && rndc reload
rndc zonestatus example.com.         # a member auto-added from the catalog
dig @127.0.0.1 host.example.com A
```

> **Interop note.** Knot generates version-2 (RFC 9432) catalogs. Use a recent
> BIND (≥ 9.18) and Knot (≥ 3.1). If a member isn't created, check
> `rndc catz status` / the BIND log and confirm the catalog zone transferred
> (`dig @127.0.0.1 catalog. AXFR -y hmac-sha256:xfrkey:<secret>`).

---

## 6. Operational notes

- **Firewall:** secondaries need TCP/UDP 53 to the primary (AXFR is TCP);
  the primary sends NOTIFY to the secondaries' port 53.
- **Serials:** teleddns bumps the SOA serial on every change, which is what
  makes Knot's `difference` IXFR (and the secondaries' refresh) work.
- **Adding/removing zones:** creating a zone in teleddns declares it as a
  catalog member (it appears on secondaries within a NOTIFY/refresh); deleting
  it undeclares it and removes it from the catalog.
- **Bootstrapping / API:** bulk-load existing zones with
  `teleddns-server admin import <zonefile>` (offline, no server needed), or drive
  the JSON API / Cloudflare-compatible facade (`/api`, `/client/v4`) — see
  [`README.md`](README.md). All paths funnel through the same validation +
  Knot-sync, so the catalog/IXFR behaviour above applies identically.
- **TLS / client IP:** terminate HTTPS at Caddy (§3) and set `trust_proxy:
  true` so source IPs come from `X-Real-IP` — used for DDNS audit, rate limits,
  `allowed_ips`, and the request log.
- **Monitoring:** `/healthcheck` (always 200; `OK`/`WARN` in the body — `WARN`
  on a stalled worker, dead-lettered push, stuck backlog, or an unreachable
  Knot) and `/metrics` (Prometheus). Lock both down with `ops_allowed_ips`, a
  CIDR allow-list applied on top of `allowed_ips`; it honours the proxy real-IP,
  so list the monitoring host's actual address even when scraping through Caddy.
  Because regular DDNS updates aren't expected, alert on the *rate* of
  `teleddns_ddns_updates_total` / `teleddns_auth_failures_total` to catch a
  stolen or brute-forced credential.
- **Backup:** the teleddns SQLite/Postgres DB is the source of truth; Knot
  state (zone files, journal) is regenerated from it on the next push.
- **Schema migrations:** the server runs its migrations at startup and logs the
  path taken (`msg="migrate: ..."`). A brand-new database is built in one shot;
  an existing one has any pending migrations applied in order. Neither needs
  operator action.

See [`README.md`](README.md) for the app itself and [`PLAN.md`](PLAN.md) for
design/status.
