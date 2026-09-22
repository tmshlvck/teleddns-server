# Plan: RFC 7344 CDS/CDNSKEY consumer (Parental Agent role)

teleddns-server acting as the *parent* — watching a delegation it hosts (an
NS-only cut inside a zone it manages, e.g. `sub.x.tld` inside `x.tld`) for CDS/
CDNSKEY published by the child's own operator, and turning that into DS records
here, automatically. This is the same role CZ.NIC/FRED and SWITCH implement for
their TLDs; here it's scoped to delegations *within zones teleddns-server itself
manages*, not the TLD registry problem — it does not help a zone whose parent is
someone else's registrar (that was this conversation's original `d.telephant.eu`/
webglobe question, and is genuinely out of reach of this codebase).

Two sub-features, opt-in, with **different risk profiles** — this distinction
should stay visible in the implementation, not just this doc:

1. **Rollover**: a DS already exists at the delegation. The new CDS/CDNSKEY can be
   cryptographically validated against the DNSKEY that DS already trusts. Sound,
   bounded, build first.
2. **Bootstrap**: no DS exists yet (insecure delegation). There is no anchor to
   validate against — this is trust-on-first-use, mitigated only by a stability
   window (default **3 days**, per the discussion this plan follows from).
   Weaker guarantee, must be opted into explicitly and stay visibly weaker in the
   UI/audit trail than rollover.

Building this does **not** retroactively help the `.eu`/webglobe situation — flagging
that again here since it's the reason this plan exists, so it doesn't get lost:
this only ever acts where teleddns-server itself is the parent.

## 1. New capability: outbound DNS queries + DNSSEC validation

Nothing in this codebase today queries a third party's DNS server — everything is
either serving authoritative answers or talking to the local `knotc` socket
(`AGENTS.md`'s module map is entirely "serve" or "control-plane", no "resolve").
This plan adds the first resolver-shaped code in the app.

- New dependency: `hickory-resolver`/`hickory-client` (the trust-dns successor),
  not a hand-rolled RRSIG/DNSKEY verifier. This is the one place in the codebase
  where "wrote it myself" is the wrong call — a subtly wrong RRSIG check (wrong
  covered RRset, an unchecked expiration, an algorithm downgrade not rejected)
  fails open and silently defeats DNSSEC for exactly the zones this feature
  touches. Flagging as a dependency decision worth a second look before merging,
  not just a `cargo add`.
- New module `src/cds.rs`: given a delegation `(zone_id, label)`, look up its NS
  RRset (`rr::ns` rows at that `(zone_id, label)`), query **each NS server
  directly** for CDS and CDNSKEY (not full recursive/validating resolution — the
  NS names in the delegation are definitionally who to ask, exactly what a
  Parental Agent does per RFC 7344). A per-query timeout (`cds_query_timeout`,
  default 5s) so one unreachable child server can't stall a poll tick.
- For the rollover path only: fetch the child's current DNSKEY RRset + RRSIG,
  verify one of the delegation's *currently published* DS rows (key_tag,
  algorithm, digest) matches a DNSKEY in that set, then verify the CDS/CDNSKEY
  RRset's RRSIG against that specific, already-trusted DNSKEY. This is a bounded
  "verify against a known anchor" check, not general-purpose validating
  resolution — much smaller surface than embedding a full validator.

## 2. Data model: a `cds_watch` entity, not a bare flag

An NS delegation isn't a first-class row today (`rr::ns` is one row per server,
no natural "this is one delegation" grouping), and the poller needs somewhere to
keep state between ticks (what was last observed, since when, current status).
Reuse the shape `zone_role`/`rr_role` already establish — a scope-defining table
(FK to `zone` + a label) that's admin-managed via relativelylight CRUD like every
other entity:

```
cds_watch
  id                  pk
  zone_id             FK → zone
  label               text            -- delegation owner name, relative to zone
  mode                text            -- "rollover" | "bootstrap" | "both"
  grace_period_secs   int, nullable   -- overrides cds_bootstrap_grace_period
  allow_ds_removal    bool            -- honor an RFC 7344 "delete" CDS (see §4)
  status              text            -- "watching" | "stable_pending" | "applied" | "error"
  last_seen_fingerprint text, nullable -- hash of the last-observed CDS/CDNSKEY RRset
  first_seen_at       bigint, nullable
  last_checked_at     bigint, nullable
  last_error          text, nullable
  created_at / updated_at
  UNIQUE (zone_id, label)
```

Registered in `web::build_engine` like `zone_role`: Superadmin-managed for v1 (this
is new security-relevant automation — narrower delegation to a Zone Manager, if it
turns out to matter, is a follow-up, not a v1 requirement). The observed-state
columns (`status`, `last_seen_fingerprint`, `first_seen_at`, `last_checked_at`,
`last_error`) are `read_only` in the admin form — they're the poller's bookkeeping,
an operator reads them, doesn't edit them, same treatment as `api_key.last_used_at`
today.

## 3. Config

- `cds_scan_enabled: bool` (default `false`) — master switch. No queries happen at
  all unless this is `true` **and** at least one `cds_watch` row exists.
- `cds_check_interval` (default `1h`, mirrors Knot's own `ksk-submission`
  `check-interval` default from the earlier discussion — same cadence idea).
- `cds_bootstrap_grace_period` (default **`3d`**, per your ask) — the global
  default; a `cds_watch` row's `grace_period_secs` overrides it per-delegation.
- `cds_query_timeout` (default `5s`).
- `cds_max_concurrent` (default e.g. `4`) — this is now a DNS client hitting
  third-party servers; a large delegation count shouldn't turn into a self-inflicted
  flood against however many child operators exist.

## 4. The rollover path (DS already present)

On each due tick for a `mode ∈ {rollover, both}` watch with an existing DS:

1. Query CDS + CDNSKEY at the child's NS servers.
2. If present: validate per §1 (RRSIG against the DNSKEY the current DS already
   trusts).
3. **Light consistency check even though it's cryptographically valid**: require
   the same content on two consecutive polls before acting (cheap — at most one
   `cds_check_interval` of latency — and guards against a transient/malformed
   single response without the cost of a multi-day window a rollover doesn't need).
4. If it differs from the current DS row(s): upsert `rr::ds::Entity` to match —
   this rides the *existing* write path exactly (`ActiveModel::insert/update` →
   `after_save` → `sync::on_rr_saved` → serial bump + push enqueue), so nothing
   about the sync pipeline needs to change. Run the new DS values through the
   *same* `dns::check::{u16,octet,hex}` predicates `web.rs`'s `reg_rr!` already
   uses for the DS entity — defense in depth even though the values came from a
   validated chain.
5. **The RFC 7344 "delete" signal** (a CDS with algorithm/digest-type 0, or the
   equivalent CDNSKEY form) means "remove DNSSEC for this delegation." Recognize
   it, but only act on it when the watch row's `allow_ds_removal` is set — this is
   a security-*lowering* action, categorically different from a routine key
   rollover, and shouldn't share a single opt-in checkbox with it.
6. Audit every automated write via `Audit::record` with a new `source` value
   (e.g. `"cds"`), distinguishing it from human/API-originated changes in the log —
   `audit.rs`'s `source` field already discriminates `ddns`/`api`/`cf`/admin, this
   is one more.

## 5. The bootstrap path (no DS yet) — the TOFU case

For a `mode ∈ {bootstrap, both}` watch with no existing DS:

1. Query CDS + CDNSKEY at the child's NS servers each tick.
2. No cryptographic anchor exists to validate against — accept this at face value,
   same as CZ.NIC/SWITCH's own bootstrap mechanism, and say so plainly in the code
   comment and README, not just imply it.
3. State machine on `first_seen_at`/`last_seen_fingerprint`: a **different**
   observed CDS/CDNSKEY content resets `first_seen_at` to now (an attacker or a
   flapping child shouldn't get a shorter effective window than a stable one would).
   A **failed** query (timeout, SERVFAIL, no NS reachable) neither advances nor
   resets — it's just a missed observation, not a signal.
4. Once the same content has held continuously since `first_seen_at` for
   `grace_period_secs` (default 3d): create the DS row(s) — same write path as §4
   step 4.
5. Audit the bootstrap event with enough detail to review after the fact: which NS
   servers answered, the resulting key tag(s), how long it was stable for. This is
   the one write in the whole app where "why did this happen" needs to be
   reconstructable without re-deriving it from a poll history that may have moved
   on.
6. **Residual risk, stated explicitly rather than left implicit**: an attacker
   sitting on-path between teleddns-server and the child's authoritative servers
   for the *entire* grace window can forge this. That's the same risk model every
   TOFU-based CDS registry accepts (RFC 8078 §2's whole premise) — proportionate
   here specifically because it's opt-in per delegation, logged loudly, and scoped
   to zones/delegations an operator explicitly chose to watch, not silently on by
   default.

## 6. New periodic worker

`src/backend/cds_worker.rs` (parallel to `backend::worker`, not merged into it —
different failure domain, different cadence, and it should be possible to disable
independently via `cds_scan_enabled`). Spawned from `app.rs::serve()` only when
enabled. Loop shape:

- Every tick, load `cds_watch` rows where `last_checked_at + check_interval <=
  now()` (or `NULL`, for a never-checked row).
- For each: run §4 or §5 depending on `mode`, update `status`/
  `last_seen_fingerprint`/`first_seen_at`/`last_checked_at`/`last_error`.
- No journal/retry-with-backoff needed the way `sync_task` has one — a failed
  check just tries again next tick, and §4/§5's "failure doesn't reset progress"
  rule already absorbs transient trouble.

## 7. Surfacing status

- `cds_watch` is a normal relativelylight entity in the admin console (create/
  edit/delete a watch; the observed-state columns are read-only), per §2.
- The Dashboard page (now landed — `src/web/dashboard.rs`) gets a small panel: counts of
  watching / stable-pending / applied / error, with anything in `error`
  prominently flagged — the one state that actually needs an operator's attention,
  same spirit as the sync worker's dead-letter count today.
- No native `/api` surface for `cds_watch` in v1 — the admin console already
  covers create/edit/read, and there's no evident programmatic use case yet.
  Explicit non-goal, revisit if one shows up.

## 8. Sequencing

- **Phase 1**: rollover only (§4). Cryptographically bounded, the higher-value
  half, and it's the piece that actually makes a future KSK rollover painless for
  any delegation teleddns-server parents.
- **Phase 2**: bootstrap (§5), gated behind its own `mode`/opt-in as described
  throughout — ship once Phase 1 has some real mileage, since it's the half with
  the weaker guarantee.
- This plan's migration (`cds_watch` table) should land *after*
  `TODO-templates.md`'s `zone_template` one — sequence as `m0008_cds_watch`, or
  bundle both into one release. Not a hard technical dependency, just avoids two
  migration-numbering races if both are being worked on close together.
  **Numbers have shifted since this was written:** `m0006_audit_ts_index` shipped
  with the dashboard, so `zone_template` is now `m0007` and this one `m0008`.
  Re-check `Migrator::migrations()` before picking a number — a shipped migration
  is never renumbered, so the unshipped plans move instead.

## 9. Testing

- Pure-logic unit tests (no network): the stability-window state machine (content
  change resets, failure doesn't, exact boundary at `grace_period_secs`), CDS
  "delete" signal detection, fingerprint comparison.
- The RRSIG/DNSKEY validation path in §1 is the highest-risk code in this plan —
  test against real RFC 8078/DNSSEC test vectors, not just hand-built fixtures,
  before it's trusted to gate a DS write.
- Integration-test the full rollover path against a local Knot instance signing a
  throwaway child zone (mirrors the manual verification loop already documented in
  `AGENTS.md`'s "Build / test / run" section — a `TELEDDNS_DB_DSN=sqlite::memory:`
  instance plus a local Knot playing "child").

## 10. Rollout checklist

- [ ] `hickory-resolver`/`hickory-client` dependency added, feature-scoped if
      possible to keep default builds lean.
- [ ] `src/cds.rs`: query + validation logic (Phase 1 first).
- [ ] Migration `m0008_cds_watch` + `model/cds_watch.rs`.
- [ ] Config: `cds_scan_enabled`, `cds_check_interval`, `cds_bootstrap_grace_period`
      (default `3d`), `cds_query_timeout`, `cds_max_concurrent`.
- [ ] `cds_watch` registered in `web::build_engine` (Superadmin-gated).
- [ ] `src/backend/cds_worker.rs`, spawned conditionally in `app.rs::serve()`.
- [ ] Audit wiring: new `source = "cds"` rows for both bootstrap and rollover
      writes.
- [ ] Dashboard panel. *(The dashboard itself has landed — `src/web/dashboard.rs`
      + `templates/dashboard.html`; add a `cds_watch` panel beside the others.)*
- [ ] README: document the feature, the opt-in model, and the residual TOFU risk
      in §5 in plain operator-facing language — this is the one feature in the
      app where under-explaining the trust model to an operator is itself a risk.
- [ ] `AGENTS.md`: add a module-map entry for `cds.rs`/`cds_worker.rs`, and a
      design-invariant note alongside "the library schedules nothing; the worker
      does" — now there are two workers, worth being explicit about which does
      what.
