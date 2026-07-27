# The teleddns-server DDNS protocol (dyndns2)

**Normative wire contract** for the Dynamic-DNS endpoint of
[teleddns-server](https://github.com/tmshlvck/teleddns-server) — written for people
implementing or testing a client against it. It follows the dyndns2 pseudo-standard
(Dyn's *Remote Access API*): [request
parameters](http://help.dyn.com/perform-update.html), [return
codes](http://help.dyn.com/return-codes.html). Where teleddns-server deviates, §11
says so explicitly.

Applies to teleddns-server **0.4.0+**. Behaviour that changed relative to earlier
builds is listed in §14 — check it if you wrote a client against 0.3.x.

---

## 1. Endpoint

| | |
|---|---|
| Methods | `GET` (preferred) or `POST` |
| Paths | `/nic/update` (canonical), `/ddns/update`, `/update` — identical behaviour |
| Parameters | in the query string; a `POST` may instead send them as an `application/x-www-form-urlencoded` body (§4) |
| Response | `text/plain`, dyndns2 keywords (§7) |

Any other method returns **`405 badagent`**. Requests are also subject to the
operator's IP whitelist, which answers `403` with the body `forbidden` — that is
*not* a dyndns2 keyword, treat an unparseable body per §12.2.

## 2. Authentication

Required on every request. Two mechanisms:

- **HTTP Basic** — `Authorization: Basic base64(user:password)`. Rejected with
  `badauth` for accounts that have TOTP/SSO enabled; those must use a token.
- **Bearer token** — `Authorization: Bearer <api-key>`. Any key level is accepted
  here; what the key may touch is decided per record (§3).

If both headers are somehow present, **Bearer wins**. Missing or invalid
credentials → `badauth` + HTTP 401.

## 3. Authorization

Each `(hostname, address-family)` needs the **RR Manager** role on the resolved
`(zone, record-name)` — granted for that record set, or inherited by a Zone Manager of
the zone or a Superadmin. A credential is its owner, so a bearer token has exactly the
access the account it belongs to has. Insufficient access →
`!yours` for that hostname. A caller that may write the name may also **create** it
if it does not exist yet.

## 4. Request parameters

| Name | Required | Form |
|---|---|---|
| `hostname` | **yes** | comma-separated list of **1–20** FQDNs. Trailing dot tolerated, case-insensitive. More than 20 → `numhost`. |
| `myip` | no | comma-separated list of IP addresses, **either family** — the family of each entry is auto-detected. |
| `myipv6` | no | comma-separated IPv6 addresses. A teleddns extension (common in the wild); IPv4 here is an error. |

Empty list entries are ignored (`myip=192.0.2.1,` is fine).

**If neither `myip` nor `myipv6` names an address, the address the request came from
is published** — as the dyn API does. That covers only the family the client
connected over: an IPv4 client gets an A record, an IPv6 client an AAAA. An
*explicit* address is never extended this way: `myip=192.0.2.1` from an IPv6 client
updates the A record only and leaves AAAA alone. If the server is behind a reverse
proxy the operator must have `trust_proxy` enabled for the forwarded address to be
used; otherwise detection sees the proxy. Prefer sending the address explicitly if
you know it.

For a `POST`, parameters may be sent either in the query string (what the dyn API
documents) or as an `application/x-www-form-urlencoded` body; a name present in both
is taken from the query string. Any other body content type is ignored — there is no
JSON form of this protocol.

Accepted name syntax: dot-separated labels of 1–63 characters (letters, digits,
`-`, and `_` for service labels), optionally a leading `*` wildcard label.
Anything else — including whitespace or a comma inside a name — is `notfqdn`.

**Ignored parameters:** the deprecated dyn flags `wildcard`, `mx`, `backmx`,
`offline`, plus `system` and `url`. Unknown parameters are ignored too. Sending
them is harmless; none of them change behaviour.

## 5. Address-set semantics

The address list is a **set applied to every listed hostname** — it is *not*
positionally paired with the hostname list. `hostname=a.example.com,b.example.com`
with `myip=192.0.2.1,2001:db8::1` gives **both** names the address pair (one A, one
AAAA). There is no way to give different addresses to different hostnames in one
request; use one request per address set.

At most **one address per family** per request. Two *different* addresses of the
same family contradict each other and make the request malformed (`notfqdn`); the
*same* address repeated (e.g. in both `myip` and `myipv6`) is accepted.

```
myip=192.0.2.1,2001:db8::1          → A 192.0.2.1  + AAAA 2001:db8::1
myip=192.0.2.1&myipv6=2001:db8::1   → the same (extension form)
myip=2001:db8::1                    → AAAA only
myip=2001:db8::1&myipv6=2001:db8::1 → AAAA only (same address twice is fine)
(neither given)                     → the source address, its family only
myip=192.0.2.1,192.0.2.2            → notfqdn (contradictory)
myip=2001:db8::1&myipv6=2001:db8::2 → notfqdn (contradictory)
myipv6=192.0.2.1                    → notfqdn (wrong family)
```

## 6. Effect on the zone

For each `(hostname, family)`:

1. `hostname` is matched against the served zones by longest matching origin; the
   remaining left-hand labels become the record name. With zones `example.com.` and
   `sub.example.com.`, `host.sub.example.com` updates `host` in `sub.example.com.`.
   No matching zone → `nohost`.
2. The **A** (IPv4) or **AAAA** (IPv6) record set at that name is replaced by
   exactly the requested address: created if absent, updated in place if different,
   left alone if already equal (`nochg`). If several records exist, one is kept and
   updated and the extras are removed.
3. The TTL of a record written here is the server's `ddns_rr_ttl` (default **60 s**).
4. Any change bumps the zone's SOA serial and queues a push to the DNS server.

The DDNS endpoint **never deletes** a record set and never touches any other record
type. Removing records is a management-API/UI operation.

## 7. Response format

```
Content-Type: text/plain

<keyword>[ <address>[,<address>]]
```

- **One line per hostname, in request order.** A 3-hostname request yields 3 lines.
- A failure that concerns the **whole request** (authentication, a malformed query,
  `numhost`) is reported as a **single line**, whatever the hostname count.
- `good`/`nochg` carry the addresses now on record for that hostname, IPv4 first,
  comma-separated. All other keywords appear bare.
- The **HTTP status** is the most severe of the lines (§8). It always agrees with the
  body; the body is the finer-grained signal.

```http
GET /nic/update?hostname=a.example.com,b.example.com&myip=192.0.2.5,2001:db8::5

200 OK
good 192.0.2.5,2001:db8::5
good 192.0.2.5,2001:db8::5
```

```http
GET /nic/update?hostname=a.example.com,x.unknown.test&myip=192.0.2.6

404 Not Found
good 192.0.2.6
nohost
```

## 8. Keywords

| Keyword | HTTP | Meaning | Client action |
|---|---|---|---|
| `good <addrs>` | 200 | created or changed | success — adopt as current |
| `nochg <addrs>` | 200 | already at that value | success — adopt as current; **do not** re-send |
| `notfqdn` | 400 | `hostname` missing/invalid, or an address is unparseable/contradictory | permanent — fix the request |
| `numhost` | 400 | more than 20 hostnames | permanent — split the request |
| `badauth` | 401 | bad credentials, or Basic used by a 2FA/SSO account | permanent — fix credentials |
| `!yours` | 403 | authenticated, but not authorized for that name | permanent — fix the grant |
| `nohost` | 404 | no served zone matches the name | permanent — fix the name |
| `badagent` | 405 | request did not follow the client requirements (here: non-GET) | permanent — fix the client |
| `abuse` | 429 | too many failed credential checks — the account or your address is locked out (§10) | fix the credentials, then retry after the lockout |
| `911` | 500 | server-side failure | transient — retry with backoff |

Not implemented (never returned): `dnserr`, `!donator`, `!active`.

## 9. Per-hostname merge rules

When a request carries both families, the two updates run independently and their
results are merged into that hostname's single line:

| Families | Line |
|---|---|
| all succeeded, at least one changed | `good` + all addresses |
| all succeeded, none changed | `nochg` + all addresses |
| any failed | the **most severe** failure keyword, bare |

Severity order: `nochg` < `good` < `nohost` < `!yours` < `abuse` < `notfqdn` <
`numhost` < `badagent` < `badauth` < `911`.

A partial failure reports the failure, **but the family that succeeded has still
been applied** — the retry will simply report `nochg` for it. A client that needs
per-family resolution should send one family per request (both forms are supported).

## 10. Limits

**Successful updates are not rate-limited.** A client holding a valid credential is
authorized for exactly the records its grant covers, and this is a server you run for
your own fleet — so there is no update budget and no `abuse` for updating too often.
That is not licence to poll: dyndns2 asks a client to update **when its address
actually changes, not on a timer**, and re-sending an unchanged address just earns
`nochg` (§8).

**Failed credentials are limited**, and that is what `abuse` now means. Repeated
`badauth` answers lock the account (by default 10 failures in 15 minutes) and the
source address (100 in 15 minutes); while locked, the request is answered `abuse`
(429) without the credentials being checked at all — including a *correct* one, so a
client that keeps retrying wrong credentials locks itself out until the window passes.
Treat `badauth` as permanent (§8): fix the credentials, don't retry them on a timer.

## 11. Deviations from the dyn API

| Topic | Dyn | teleddns-server |
|---|---|---|
| `myipv6` | does not exist | **accepted** as an explicit-IPv6 alternative to `myip` |
| POST body | parameters in the query string | query string **or** a form-encoded body |
| User-Agent | must be descriptive; may be answered with `badagent` | logged, never enforced — a missing UA is fine |
| `!yours` | not in the published code list | returned (as most dyndns2 implementations do) |
| offline/MX/wildcard flags | act on the account | ignored |
| `dnserr` | internal DNS failure | not used; server-side failures are `911` |
| non-globally-routable addresses | rejected by most public providers | accepted — teleddns is typically run for private/split-horizon zones too |

Everything else in §4–§9 follows the dyn API: `GET` and `POST`, the comma-separated
`hostname` and `myip` lists, the 20-name cap and `numhost`, the address set applied
to every name, source-address detection when no address is given, one return code per
hostname in request order, and a single line for request-level failures.

## 12. Writing a client

### 12.1 Request

- Send one `GET` per address set. The compact dual-stack form is
  `?hostname=<fqdn>&myip=<v4>,<v6>`; `?hostname=<fqdn>&myip=<v4>&myipv6=<v6>` is
  equivalent. Sending one family per request is also fine and gives you per-family
  status directly. `POST` works if your platform makes GET awkward, with the
  parameters in the query string or a form-encoded body.
- Send the address explicitly whenever you know it; omit it only when you *want* the
  server to use the connection's source address (behind CGNAT, for instance). A
  client that detects its own address can also verify what it published, which
  source-address detection cannot give you.
- Batch names that share an address set (up to 20) — one request, one line back per
  name, in the order you sent them.
- Send a stable, descriptive `User-Agent` (e.g. `myclient/1.2`). teleddns-server does
  not require it, but other dyndns2 services reject requests without one, and it is
  what shows up in the server's logs when someone debugs your client.
- Use a request timeout (~30 s) and keep connections alive if you update often.

### 12.2 Parsing

Parse the **body first**, fall back to the HTTP status:

1. Split the body on `\n`. If the line count equals the hostname count, line *i* is
   the result for hostname *i*; if there is exactly one line, it applies to the whole
   request (typically an error). Any other count: treat the first line as the overall
   result, and any name without a line as failed.
2. On each line, the first whitespace-separated token is the keyword; the rest is
   informational (the addresses). Match keywords case-insensitively.
3. Unknown or empty body → classify by HTTP status: 2xx = success, 429/5xx =
   transient, other 4xx = permanent.

### 12.3 Retrying

- `good`/`nochg` — done. Record the address as current and do not send again until it
  changes. Re-sending an unchanged address is the classic abuse pattern.
- `abuse`, `911`, a network error, or any 5xx — retry with exponential backoff.
- Everything else is permanent: log it and stop retrying until the configuration or
  the address changes. Retrying `badauth` in a loop is how clients get blocked.

## 13. Known clients

| Client | Request it sends | Works |
|---|---|---|
| `ddclient` (`protocol=dyndns2`) | groups hosts: `?hostname=h1,h2&myip=<v4>[,<v6>]` | ✅ including dual-stack and multi-host |
| teleddns client | one request per family, `myip` / `myipv6` | ✅ |
| MikroTik RouterOS, OPNsense/pfSense, UniFi, generic routers | single hostname, single `myip` | ✅ |
| Clients that omit `myip` and rely on source-address detection | `?hostname=<fqdn>` | ✅ |
| Clients that `POST` the parameters | query string or form body | ✅ |

## 14. Changes from teleddns-server 0.3.x

- **Response granularity changed**: the body used to carry one line per *address
  family*; it now carries one line per *hostname* (§7). A single-hostname dual-stack
  request that previously returned two lines (`good <v4>\ngood <v6>`) now returns one
  (`good <v4>,<v6>`). Clients that read only the first line are unaffected.
- `hostname` accepts a list (was: a single name, and a comma-separated value was
  silently mangled into a bogus record name).
- `myip` accepts a list, so dyn's native dual-stack form works (was: `notfqdn`).
- `numhost` and `badagent` are now returned (`badagent` replaces the old
  non-protocol `405 method not allowed` body).
- Contradictory addresses for one family are now `notfqdn` (was: last one silently
  won).
- A request with no address now publishes the source address (was: `notfqdn`).
- `POST` is accepted, with the parameters in the query string or a form-encoded body
  (was: `405`). Methods other than GET/POST are still `badagent`.

## 15. Test recipes

Verified against 0.4.0; `$U` is the base URL, `$K` an API key.

```sh
A="Authorization: Bearer $K"      # or: curl -u user:password

# dual-stack, dyn's native form
curl -s -H "$A" "$U/nic/update?hostname=host.example.com&myip=192.0.2.1,2001:db8::1"
# -> good 192.0.2.1,2001:db8::1        (200)
# repeat:
# -> nochg 192.0.2.1,2001:db8::1       (200)

# extension form, one family per request
curl -s -H "$A" "$U/nic/update?hostname=host.example.com&myipv6=2001:db8::1"
# -> nochg 2001:db8::1                 (200)

# batch: 3 names, one address set
curl -s -H "$A" "$U/nic/update?hostname=a.example.com,b.example.com,c.example.com&myip=192.0.2.5"
# -> good 192.0.2.5
#    good 192.0.2.5
#    good 192.0.2.5                    (200)

# mixed results keep their order; status is the worst
curl -s -H "$A" "$U/nic/update?hostname=a.example.com,x.unknown.test&myip=192.0.2.6"
# -> good 192.0.2.6
#    nohost                            (404)

# no address given: the source address is published (A for an IPv4 client)
curl -s -H "$A" "$U/nic/update?hostname=auto.example.com"
# -> good 198.51.100.9                 (200)   (whatever address you connected from)

# POST, parameters in the query string, then in a form body
curl -s -H "$A" -X POST "$U/nic/update?hostname=host.example.com&myip=192.0.2.60"
# -> good 192.0.2.60                   (200)
curl -s -H "$A" -X POST -d 'hostname=host.example.com&myip=192.0.2.61' "$U/nic/update"
# -> good 192.0.2.61                   (200)

# limits and malformed requests
curl -s -H "$A" "$U/nic/update?hostname=$(seq -s, -f 'h%g.example.com' 21)&myip=192.0.2.1"
# -> numhost                           (400)
curl -s -H "$A" "$U/nic/update?hostname=a.example.com&myip=192.0.2.1,192.0.2.2"
# -> notfqdn                           (400)
curl -s -H "$A" "$U/nic/update?hostname=a.example.com&myipv6=192.0.2.1"
# -> notfqdn                           (400)
curl -s -H "$A" "$U/nic/update?hostname=a.example.com&myip=2001:db8::1&myipv6=2001:db8::2"
# -> notfqdn                           (400)   (two different IPv6 addresses)
curl -s -H "$A" -X PUT "$U/nic/update?hostname=a.example.com&myip=192.0.2.1"
# -> badagent                          (405)   (GET and POST only)

# auth
curl -s -H "Authorization: Bearer wrong" "$U/nic/update?hostname=a.example.com&myip=192.0.2.1"
# -> badauth                           (401)

# a token scoped to one record set, two names requested
curl -s -H "Authorization: Bearer $KEY" "$U/nic/update?hostname=mine.example.com,other.example.com&myip=192.0.2.20"
# -> good 192.0.2.20
#    !yours                            (403)
```
