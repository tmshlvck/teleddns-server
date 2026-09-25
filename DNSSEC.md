# DNSSEC on the Knot primary: auto-signing, always-on CDS/CDNSKEY, coordinated KSK rollover

Operator runbook. Almost all of it is Knot config: per `AGENTS.md` this is
"cluster-static config" living in the operator's base `knot.conf` and the templates
it defines, while teleddns-server writes zone files and calls `zone-reload`. Knot
does the signing, the key timers and the rollover on its own.

The one teleddns-side control is **which template a zone is declared under**
(`zone.template` in the console and on the native API, falling back to
`default_knot_template`). That is what makes signing a *per-zone* decision rather
than a server-wide one — §4.

This document covers the **child** side: a zone hosted here that wants to be signed
and to get its DS to whatever its parent is. The **parent** side — teleddns-server
consuming a child's CDS/CDNSKEY for delegations inside zones it manages — is
`TODO-RFC7344.md`, not yet implemented; §6c is the forward reference.

## What this config achieves

- Zones under the template sign themselves and stay signed (new records, key
  timers, everything) with no manual `keymgr` babysitting.
- CDS/CDNSKEY are published **continuously**, not just during a rollover — so a
  registry that scans for them (CZ.NIC/FRED does; `.eu`/EURid, per the research
  behind `TODO-RFC7344.md`, apparently does not) can pick up the initial DS or a
  rollover on its own, and so teleddns-server's own future CDS consumer
  (`TODO-RFC7344.md`) has something to observe for delegations parented here.
- A KSK rollover's submission phase is **checked against the real parent**, not
  timed blindly: Knot queries the parent's own authoritative servers for the new
  DS and only retires the old key once it actually sees it there.

## 1. Define the parent's nameservers as a `remote`

This is who Knot asks "has the new DS shown up yet" during a rollover — the
parent zone's *authoritative* servers, not a random resolver (the answer needs to
be authoritative, not eventually-consistent-from-a-cache).

```yaml
remote:
  - id: parent-ns1
    address: 192.0.2.53         # the parent's authoritative server, IP not hostname
  - id: parent-ns2
    address: 198.51.100.53

remotes:
  - id: parent-servers
    remote: [parent-ns1, parent-ns2]
```

If the parent zone is itself hosted by another teleddns-server/Knot pair you
control, this is just that pair's own addresses. If the parent is a registrar's
DNS (webglobe, in the `telephant.eu`/`d.telephant.eu` case this follows on from),
use *their* authoritative servers for the zone the delegation lives in — `dig
telephant.eu NS +short` finds them.

## 2. The submission check

```yaml
submission:
  - id: parent-check
    parent: [parent-servers]     # the remote(s)/remotes group from step 1
    check-interval: 1h
    timeout: 0                    # wait indefinitely — never retire the old key on a guess
```

`timeout: 0` is deliberate, not a placeholder: any nonzero timeout means Knot
retires the old KSK on a **clock** once it elapses, whether or not the new DS
actually made it to the parent. `0` means Knot only ever proceeds on a confirmed
observation — slower in the worst case (if you forget to publish the new DS
somewhere), never wrong.

## 3. The signing policy

```yaml
policy:
  - id: auto-signed
    algorithm: ECDSAP256SHA256
    zsk-lifetime: 30d             # rolls itself, no registrar involvement — ZSK isn't in the DS
    ksk-lifetime: 3y              # see note below — don't pin this at 0 forever
    rrsig-lifetime: 10d
    rrsig-refresh: 3d
    nsec3: off                    # on only if zone-walking privacy specifically matters here
    cds-cdnskey-publish: double-ds
    ksk-submission: parent-check
```

**`cds-cdnskey-publish: double-ds`, not the more obvious `always`.** Knot's
default is `rollover` (publishes nothing outside an active rollover — useless for
a registry that scans continuously, and useless for `TODO-RFC7344.md`'s consumer).
`always` publishes only the *current* (active) KSK's CDS/CDNSKEY — fine for
steady-state discovery, but during a rollover's submission phase the new key is
`ready`, not yet `active`, so `always` alone doesn't expose the one CDS record a
parent actually needs to pick up next. `double-ds` is documented as "publish up to
two CDS and two CDNSKEY records for ready and/or active KSKs" — it's `always` and
`rollover` at once: something is published all the time (satisfies "always
distribute"), and the new key's CDS shows up the moment a rollover starts
(satisfies "coordinate the rollover"). One setting, both requirements.

**On `ksk-lifetime: 3y` rather than `0`**: a KSK rollover means one DS update at
the parent, and — with the submission check above — Knot does everything else
(generate, double-sign, publish CDS, detect confirmation, retire the old key) on
its own. Pinning the KSK forever avoids that touch entirely, but for a zone held
for years, a periodic rollover you've rehearsed is worth more than one you've
never done and hope works under pressure if the key is ever suspected compromised.
Pick whatever cadence you're actually willing to revisit; `3y` is a reasonable
default, not a requirement.

## 4. Apply it to the zone(s)

Define **two** templates — one signing, one not — identical in every other respect:

```yaml
template:
  - id: master                  # the default: unsigned
    storage: /var/lib/knot/zones
    zonefile-load: difference
    catalog-role: member
    catalog-zone: catalog.example.
    acl: [secondary-xfr]

  - id: dnssec-signing          # same again, plus signing
    storage: /var/lib/knot/zones
    zonefile-load: difference
    catalog-role: member
    catalog-zone: catalog.example.
    acl: [secondary-xfr]
    dnssec-signing: on
    dnssec-policy: auto-signed
```

The duplication is deliberate and worth keeping: the two templates must agree on
storage, catalog membership and ACLs, because a zone moves *between* them and
anything that differs would silently change when it does.

Then tell teleddns which templates exist, so it renders them as a choice and
recognises both as its own:

```yaml
# teleddns-server.yaml
default_knot_template: "master"
knot_templates: ["master", "dnssec-signing"]
```

`knot_templates` is doing two jobs. It turns the zone form's **Knot template**
field into a `<select>` (and makes the native API 422 anything else), and it
defines which templates the orphan sweep treats as ours — a zone under a template
named in neither this list nor `default_knot_template` is never deleted, but is
never recognised either. **List every template you declare zones under**, or the
day you remove a signed zone from the database its Knot declaration outlives it.

## 5. Bring a zone up under it

Set the zone's **Knot template** to `dnssec-signing` — in the console
(`/admin/zone` → edit the zone) or on the API:

```sh
curl -X PUT -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
     -d '{"template":"dnssec-signing"}' https://ddns.example.com/api/zones/7
```

That is the whole teleddns-side action. The edit enqueues a push; the worker
re-declares the zone under the new template (`conf-set zone[…].template`) and
reloads it. Setting it back to empty returns the zone to `default_knot_template`.

No `keymgr` step is required to get started — the moment the signing template
applies, Knot generates the zone's first KSK+ZSK pair and signs on that reload.
Confirm it:

```sh
knotc zone-status telephant.eu. +signing
kdig @<primary> telephant.eu DNSKEY +dnssec
kdig @<primary> telephant.eu CDS +short
kdig @<primary> telephant.eu CDNSKEY +short
```

The last two should already be non-empty — that's `double-ds` doing its job even
with no rollover in progress.

### Do not put DNSKEY records in a signed zone

teleddns has an **RR DNSKEY** table, and the rendered zone file includes whatever
is in it. For a zone under a signing template that is a trap: Knot generates the
apex DNSKEY RRset itself from its own keys, and an apex DNSKEY fed to it in the
zone file is at best ignored and at worst a load error. **Leave the DNSKEY table
empty for any zone Knot signs.** It exists for zones signed elsewhere and served
here as ordinary data.

**DS records are the opposite** — those you *do* manage here. A DS belongs at a
delegation point inside your zone (`sub.example.com. DS …` in `example.com.`),
pointing at a signed child, and it is exactly what the RFC 7344 parent role (§6c)
will one day write for you. Nothing about a zone being signed changes that.

The secondary needs **no** DNSSEC-specific config at all: it AXFRs whatever the
primary now signs, same as every other record type, through the same catalog
zone. The one thing worth *checking*, not changing, is that the secondary's own
template does **not** carry `dnssec-signing: on` — only the primary (the
authoritative signer) should ever be told to sign; a slave-role zone signing on
top of an already-signed transfer is a misconfiguration, not a second layer of
protection. And leave the catalog zone itself out of this template entirely — it
must never be signed.

## 6. Getting the key material to the parent

Signing a zone is the easy half. The zone is only *validated* once the parent
publishes a DS for it, and how that happens depends entirely on what the parent is.
Three cases, in increasing order of manual work.

### 6a. The parent scans CDS/CDNSKEY (RFC 7344) — nothing to do

If the parent operator watches for CDS/CDNSKEY, `double-ds` (§3) has already been
publishing them since the zone's first signing, and the parent will pick the DS up
on its own polling schedule — for the initial bootstrap *and* for every subsequent
KSK rollover. There is no submission step, ever.

Check that you are actually offering something:

```sh
kdig @<primary> example.com CDS +short
kdig @<primary> example.com CDNSKEY +short
```

Then just watch the parent until the DS appears, and validate end to end:

```sh
dig +short example.com DS @<a parent nameserver>     # authoritative, not a resolver
delv @<resolver> example.com SOA                     # "fully validated" once the chain is live
```

Nothing else is required, and nothing should be submitted by hand — a DS you add
manually alongside one the parent derived from your CDS is how you end up with a
stale DS nobody remembers owning.

**This is the case §6c makes available for delegations parented on another
teleddns-server**, and it is why `TODO-RFC7344.md` exists.

### 6b. The parent needs the key submitted by hand

This is the common case for a TLD registry reached through a registrar. Two things
vary and you must know both **before** you start a rollover:

**1. Which form the parent wants.** RFC 5910 gives EPP two interfaces, and
registries pick one:

| Interface | What you submit | Fields |
|---|---|---|
| **DS data** (`dsData`) | the digest — the DS record itself | key tag, algorithm, digest type, digest |
| **Key data** (`keyData`) | the key — the registry computes the DS | flags, protocol, algorithm, public key |

Produce whichever is asked for:

```sh
keymgr example.com. ds                        # DS form:     12345 13 2 A1B2...
keymgr example.com. dnskey                    # DNSKEY form: 257 3 13 mdsswUy...
kdig @<primary> example.com DNSKEY +short     # same, read off the live zone
keymgr example.com. list                      # key ids, states; flags 257 = KSK, 256 = ZSK
```

Note it is always the **KSK** (flags 257) — the DS chains to the key-signing key.
A ZSK (256) is rolled entirely inside the zone and never appears at the parent,
which is why `zsk-lifetime: 30d` in §3 needs no registrar involvement at all while
`ksk-lifetime: 3y` does.

**2. Which registry does which.** This genuinely differs per TLD — `.cz`, `.eu`,
`.com` and `.sk` do not all behave the same way, and a registrar's web form may
also differ from what the registry's EPP accepts. **Confirm with your own
registrar before relying on it**; the cost of guessing is a delegation that fails
validation for everyone.

<!-- TODO(operator): fill this table in from confirmed experience, one row per TLD
     you actually operate under. Left deliberately empty rather than populated from
     memory — a wrong row here breaks a delegation. -->

| TLD | Registry | Interface it wants | CDS/CDNSKEY scanning? | Notes |
|---|---|---|---|---|
| `.cz` | CZ.NIC (FRED) | ? | yes | |
| `.eu` | EURid | ? | ? | |
| `.com` / `.net` | Verisign | ? | no | |

The quickest way to find out for a TLD you already hold: look at what the
registrar's DNSSEC form asks for. Four fields including a *digest* → DS data. Four
fields including a *public key* → key data.

**The safe ordering for a manual rollover is add-then-remove**, never replace:
publish the new DS/DNSKEY alongside the old one, wait for Knot's submission check
(§2) to confirm and retire the old key, and only then remove the old DS. §7 walks
through it.

### 6c. The parent is another teleddns-server — not yet

When `TODO-RFC7344.md` lands, a delegation *inside a zone this server manages* will
be picked up automatically: the child publishes CDS/CDNSKEY exactly as §6a
describes, and the parent turns it into DS records here with no submission step.
The child side needs no extra configuration — a zone set up per §§3–5 is already
publishing everything the parent will look for.

Two limits worth stating now, because they decide whether this helps you:

- It only ever acts where **teleddns-server itself is the parent** — an NS-only cut
  like `sub.example.com` inside `example.com`. It does nothing for a zone whose
  parent is a registry or another operator; that stays §6b forever.
- Bootstrap (no DS yet) and rollover (DS already present) have different guarantees
  and will be separately opt-in. A rollover's new CDS can be validated against the
  DNSKEY the existing DS already trusts; a bootstrap has no anchor and is
  trust-on-first-use, mitigated only by a stability window.

## 7. How a rollover actually unfolds

With the config above, a KSK rollover — whether Knot starts it on its own at the
`ksk-lifetime` boundary, or you start it early — goes:

1. Knot generates a new KSK and publishes **both** DNSKEYs (double signature —
   the standard, safe KSK rollover method: never a moment where a validator holds
   a DS that matches nothing published).
2. `double-ds` immediately starts publishing the new key's CDS/CDNSKEY alongside
   the old one's.
3. If the parent supports CDS scanning (§6a), it picks up the new DS on its own
   within its own polling window — nothing to do here.
4. If not (§6b): pull the new DS/DNSKEY in whichever form the parent wants and
   submit it, **adding** it alongside the still-present old one — don't remove the
   old DS yet.
5. Knot's submission check (§2) polls `parent-servers` every `check-interval`
   until it sees the new DS there, then completes the rollover on its own —
   retires the old key over the policy's normal timers. Nothing to trigger
   manually.
6. Once Knot has retired the old key (`knotc zone-status telephant.eu. +signing`
   stops listing it), remove the now-unused old DS from the parent. This is the
   second and last manual touch, same as the two-edit rollover procedure this
   whole plan traces back to.

**To force a rollover on demand** (compromise, or just deliberately exercising
the procedure rather than waiting for the timer):

```sh
knotc zone-key-rollover telephant.eu. ksk
```

**To short-circuit the submission wait** — if you've confirmed by hand that the
new DS is live at the parent and don't want to wait for the next `check-interval`
poll (or the parent genuinely can't be queried the way `remote` expects, e.g. it
answers only over an authenticated channel):

```sh
knotc zone-ksk-submitted telephant.eu.
```

This tells Knot to trust that confirmation immediately and proceed to retire the
old key — it's a manual override of exactly the check §2 configures, so only use
it once the new DS is *actually* live; it does no verification of its own.

## Quick reference

| Command | What it shows/does |
|---|---|
| `knotc zone-status <zone> +signing` | Current signing state, key ages, rollover phase |
| `kdig @<ns> <zone> DNSKEY +dnssec` | Published keys |
| `kdig @<ns> <zone> CDS +short` / `CDNSKEY +short` | What's being offered to a parent right now |
| `keymgr <zone> list` | Key IDs, flags (256=ZSK, 257=KSK), states |
| `keymgr <zone> ds` | DS form of the KSK(s) — for a registry wanting `dsData` (§6b) |
| `keymgr <zone> dnskey` | DNSKEY form — for a registry wanting `keyData` (§6b) |
| `knotc zone-key-rollover <zone> ksk` | Force-start a KSK rollover now |
| `knotc zone-ksk-submitted <zone>` | Manually confirm the new DS is live at the parent |
| `delv @<resolver> <zone> SOA` | End-to-end chain-of-trust validation check |
| `dig +short <zone> DS @<parent-ns>` | What the parent is actually publishing for you |

## Where this is going

| Piece | State |
|---|---|
| Per-zone Knot templates (`zone.template`, §4–5) | **done** |
| This runbook: signing, always-on CDS/CDNSKEY, coordinated rollover | **done** |
| teleddns-server as RFC 7344 **parent** (§6c) | planned — `TODO-RFC7344.md` |
