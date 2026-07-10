# teleddns-server — Roadmap / TODO

Forward-looking work only. What the server *does* today is in
[`DESIGN.md`](DESIGN.md) (design) and [`../README.md`](../README.md) (usage).
The core is complete and deployed; nothing below blocks a release.

## Planned features

### Change log / record history
Record *who and what* changed each record, beyond the transient audit log line.
A persistent change-log table (or at minimum the last source IP that touched a
given record) so operators can answer "what happened to this record, and from
where". Feeds the two items below.

- **Dashboard: recent activity.** Surface the latest change-log entries on the
  dashboard so the last edits are visible at a glance.
- **Change-log search.** Optionally, let operators search/filter the change log
  (by zone, label, actor, source IP, time range).

### Operator UI — per-zone record editor
The 14 per-type admin tables work but are clunky for editing a single zone. A
per-zone record view (all RR types for one origin on one page) is nicer UX than
jumping between the type tables.

### L1 client onboarding flow
A brand-new dyndns client needs an operator to grant the `(zone, label)` L1 role
and mint an L1 token; the A/AAAA row itself is auto-created on first update. A
dedicated onboarding flow in the operator UI would make this self-service.

## Smaller niceties

- **DDNS transitional JSON `{detail}` mode** behind a flag, for any legacy client
  that parsed the old JSON body (clients should key off the HTTP status; this is
  belt-and-braces).
- **Management-API error shape.** The API currently emits Huma's
  `{title, status, detail}`. A `{detail, code}` body with a per-field `fields`
  map, plus a `?bump_serial=false` (L3-only) override on mutations, are specced
  but not implemented.

## Won't do

- **Legacy Python-SQLite import.** The BIND zone-file `admin import` covers
  migration needs.
- **`knotc zone-set` content plane.** `zonefile-load: difference` already yields
  incremental IXFR, so pushing content through `knotc` buys nothing.
- **teleddns↔teleddns peer replication.** Secondaries replicate via native DNS
  (catalog zone + AXFR/TSIG); there is no app-to-app sync.
