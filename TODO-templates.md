# Plan: per-zone Knot templates + a Dashboard landing page

> **Status: implemented** (branch `dnssec`). §5 landed with the relativelylight 0.3
> migration; §§1–4 landed after it. Deviations from the plan as written are noted
> inline. What remains open is the *documentation* row of §6 and the version bump,
> both deliberately left for release time.

Two related pieces of work, bundled because both touch `web.rs`'s nav/shell and both
are natural companions to the DNSSEC work in `TODO-RFC7344.md` (that plan needs a
`dnssec-signing`/`dnssec-policy` template to exist for the zones it acts on, and its
progress belongs on the Dashboard). This plan is written to land first.

**Breaking changes, so this ships as a minor version bump (0.4.1 → 0.5.0).**

## 1. Config: one default template + an optional allow-list

Today (`src/config.rs:55`, `src/backend/knot.rs`) there is exactly one
`knot_template: String`, applied to every zone `KnotBackend` declares. This plan
makes it a default with an optional per-zone override.

- **Rename** `knot_template` → `default_knot_template`. `Config` derives
  `#[serde(deny_unknown_fields)]`, so an old config file's `knot_template:` key
  becomes a hard startup error, not a silent no-op — which is the point (a renamed
  key that's silently ignored is exactly the failure mode the `deny_unknown_fields`
  comment on `Config` already exists to prevent). Document the rename prominently in
  the CHANGELOG and README.
- **Add** `knot_templates: Vec<String>` — the allow-list of template names an
  operator is willing to have zones assigned to. Empty (the default) means
  "unrestricted," matching today's behavior exactly for anyone who doesn't set it.
  Populating it is what turns the per-zone `template` field into a `<select>` with
  server-side enforcement (§3).
- Startup: if `backend == "knot"` and `knot_templates` is empty, log a one-time
  `tracing::warn!` — not an error, but worth nudging an operator who's about to add
  a second template (e.g. a signed one) toward listing it.

## 2. Schema: nullable per-zone template

- New migration `m0007_zone_template` (append to `Migrator::migrations()`,
  following the existing pattern in `src/migration/mod.rs` — never edit a shipped
  migration): `ALTER TABLE zone ADD COLUMN template TEXT NULL`.
- `zone::Model` / `zone::ActiveModel` gain `pub template: Option<String>`.
  `Model::new_defaults` leaves it `NotSet` → `NULL`, i.e. "use the default" — no
  behavior change for a zone that never sets it.

## 3. Admin UI + native API

This is exactly what `relativelylight::crud::seaorm::MetaField::options` is for
(`relativelylight/src/crud/seaorm.rs:54-67`): setting `.options` on a **text**
column (no SQLite enum type needed) turns it into a `<select>` in the admin form
*and* a membership check on write — a value outside the list is a `422`. That is
the "gate it only on change" behavior for free, no hand-written validator needed:

```rust
// web.rs, build_engine — only when the operator has populated an allow-list
if !cfg.knot_templates.is_empty() {
    z.field("template").options = cfg.knot_templates.clone();
} else {
    z.field("template").validate_str(crate::dns::check::template_name); // new predicate: non-empty, no whitespace/control chars
}
z.field("template").label = Some("Knot template".into());
z.field("template").description = Some(
    "Which knot.conf template this zone is declared under. Leave empty to use the \
     server's default template.".into(),
);
```

- `template_name` is a new `dns::check` predicate — cheap syntactic sanity (Knot's
  own `conf-set` will reject a template that doesn't actually exist in `knot.conf`;
  this is just "not obviously garbage", the same spirit as every other `check::*`
  predicate).
- Native API (`src/api/zones.rs`): add `template: Option<String>` to the
  create/update JSON payload, with the *same* allow-list check server-side when
  `knot_templates` is non-empty — the admin form and the API must agree, per the
  "both password surfaces or neither" style of invariant already in `AGENTS.md`.
- `src/api/openapi.rs`: document the new field on the zone schema.

## 4. `KnotBackend`: resolve the template per push

- Rename the field `template: String` → `default_template: String` (matches the
  config rename) and add `templates: Vec<String>` (from `cfg.knot_templates`).
- `Backend::push_zone`'s signature gains the resolved template:
  `push_zone(&self, origin: &str, zonefile: &str, serial: i64, template: &str)`.
  This is an internal trait (no external implementors), so the break is contained
  to `backend/{knot,log}.rs` and `backend/worker.rs::process`, which already loads
  the `zone::Model` before calling the backend — it just needs to pass
  `z.template.as_deref().unwrap_or(&cfg.default_knot_template)` through.
- `ensure_declared` uses that resolved string instead of `self.template`.
- **`list_managed_zones` needs a real design change, not just a rename.** Today it
  decides "is this zone ours" by `tmpl == self.template` (single string). With
  per-zone templates, "ours" has to mean "declared under one of the templates we
  know about" — i.e. `tmpl ∈ {default_template} ∪ templates`. This is exactly why
  §1 recommends operators populate `knot_templates`: a zone pushed under a template
  that's in neither the default nor the allow-list is invisible to orphan-pruning
  (`knot_delete_zones`) — not wrongly deleted, just not recognized as ours either
  way. Worth a code comment at the call site spelling this out, since it's the one
  subtle correctness edge in this whole plan.

## 5. Dashboard page + nav restructure — **DONE** (landed with the relativelylight 0.3 / MPA migration)

Delivered as described below, with these deviations:

- `/admin` is a redirect to `/admin/zone`; the console is `/admin/{entity}` (one
  route, one handler pair, `Admin::base("/admin")` from library 0.3) rather than a
  single `/admin` page with `?entity=`.
- The shared helpers went to a new **`src/stats.rs`** (`Stats::gather` +
  `Stats::warnings`), which `ops::healthcheck`, `ops::metrics` and
  `web::dashboard` all read — the WARN predicate is now literally one function.
- The nav lives in `templates/shell.html` (askama) rather than a `shell()`
  signature change; `Shell::page` computes the active item from the request URI.
- Visibility: Superadmin-only, as recommended. A non-Superadmin hitting `/` is
  **redirected to `/profile`** rather than shown a 403 — that page (password, 2FA,
  API keys) is what a device owner came for.
- §2's per-zone table also distinguishes **`syncing`** (behind, but a push is still
  queued) from **`behind`** (behind with nothing owed), which is the difference
  between "normal, one second after an edit" and "something is wrong".
- §4 (the `cds_watch` panel) is still open — see `TODO-RFC7344.md`.

The original plan, for reference:

Currently `/` **is** the admin console (`web::home` → `build_admin(...)`). This
splits that:

- `/` becomes a new **Dashboard** page — the post-login landing page.
- `/admin` becomes the admin console (what `/` renders today, moved verbatim —
  `web::home`'s body becomes `web::admin_console`, routed at `/admin` in
  `app.rs`).
- `web::shell()` gains two nav links next to the brand: "Dashboard" (`/`) and
  "Admin" (`/admin`), with the active one highlighted. Small signature change:
  `shell(title, active_nav, user, body)` (or thread an `enum Nav { Dashboard,
  Admin }` — cheaper than string comparison and it's the same shape as everything
  else in this file).
- New module `src/dashboard.rs`, handler `pub async fn dashboard(headers,
  State(app)) -> Response` — same anonymous→redirect-to-login pattern as
  `web::home` today.

**Content** — this is almost entirely already computed, just not rendered as HTML:
`ops.rs` already queries zone count, per-type record counts (`count_by_type`),
pending/in-flight/failed `sync_task` counts, the Knot `probe()` (up/down/n/a),
`worker.last_push`/`last_tick`, and `out_of_sync` (from the periodic reconcile).
Pull the shared query helpers (`count_records`, `count_by_type`,
`oldest_unfinished`) out of `ops.rs` into a small `pub(crate)` home (either make
them `pub(crate)` in place, or a new `src/stats.rs`) so `ops::healthcheck`,
`ops::metrics`, and `dashboard::dashboard` all call the same code instead of three
copies drifting apart.

Proposed dashboard sections:
1. **At a glance**: zone count, total record count, Knot up/down, worker last-tick
   age, out-of-sync count — the same numbers `/healthcheck`'s WARN logic already
   flags, just human-readable.
2. **Sync status table**: per-zone origin, DB serial, Knot-served serial (from
   `backend.zone_serials()` — already a `HashMap<origin, i64>`, the same call
   `worker::reconcile` makes), and a derived in-sync/behind/unknown badge. Cap it
   (reuse the `Page`/`per_page` convention from the native API) with a link to
   `/admin` for the full zone list on a large deployment.
3. **Sync queue**: pending / in-flight / failed counts, and — if failed > 0 — the
   oldest dead-lettered origin(s), since that's the one condition an operator needs
   to *act* on rather than just observe.
4. Once `TODO-RFC7344.md` lands: a small panel summarizing `cds_watch` state
   (watching / stable-pending / applied / error counts) — noted here so the two
   pages are designed to fit together, not built as an afterthought.

**Open question — who can see it?** The admin console is Superadmin-only
(`AGENTS.md`: "The console is Superadmin-only via the library's `GroupReadWrite`
gate"). The dashboard is read-only and arguably fine for any authenticated user
(a Zone Manager might reasonably want to see sync status for zones they manage),
but that's a new authz shape (relativelylight's `GroupReadWrite` gate is
all-or-nothing per entity, and the dashboard isn't a CRUD entity at all — it's a
hand-rolled page). **Recommend Superadmin-only for v1** (reuse the same
`GroupReadWrite` check `home()` already implies via the engine's gate, or just
check `who` is in `ADMIN_GROUP` directly), and leave "narrower visibility" as a
follow-up if it turns out to matter.

## 6. Rollout checklist

- [x] `default_knot_template` rename + `knot_templates` allow-list in `config.rs`
      (+ `Config::default()`, + the `deny_unknown_fields` test coverage already in
      `config.rs`'s test module — add a case asserting the *old* key name now
      errors).
- [x] Migration `m0007_zone_template` — **guarded by `has_column`**, which the plan
      did not anticipate: `m0001_init` builds its tables from the live entity, so a
      fresh DB already has the column by the time the ALTER runs. `m0006` was taken
      by `m0006_audit_ts_index` (the dashboard's activity panel).
- [x] `zone::Model`/`ActiveModel` + admin form + native API + OpenAPI. The API
      distinguishes an absent `template` key (leave alone) from an explicit
      `null`/`""` (clear the override) — `api::zones::parse_template`.
- [x] `Backend` trait + `KnotBackend`/`LogBackend` + `worker::process` threading.
      `KnotBackend` grew no `default_template`: the worker resolves the fallback, so
      a backend never reads `Config`. `ensure_declared` now caches `(origin,
      template)` and **re-sets a zone whose template changed** — an origin-only cache
      would have made "move a zone onto the signing template" a silent no-op, i.e.
      the whole feature.
- [x] `list_managed_zones` ownership-set fix (§4) — `default_knot_template` ∪
      `knot_templates`, with a startup warning when the allow-list is empty under the
      knot backend.
- [x] Dashboard page, nav restructure, shared stats helpers. **Done** — see §5.
- [ ] README: update the example config (`knot_template` → `default_knot_template`,
      document `knot_templates`). *(The "first page after login" description and the
      admin-console URL were already updated with §5.)*
- [x] `AGENTS.md`: two new invariants (per-zone template resolved in one place;
      both template surfaces or neither) plus one on `has_column`-guarded migrations.
      `PRD.md` §7.1–7.2 rewritten. `DNSSEC.md` §§4–6 rewritten around the feature.
- [ ] CHANGELOG entry calling out the config key rename. *(`/` no longer being the
      admin console already shipped with §5.)* — **release-time**
- [ ] Bump `Cargo.toml` version to `0.5.0`. — **release-time**. Note this *is* now
      a genuine config break (`knot_template` is a hard startup error under
      `deny_unknown_fields`), unlike the 0.3/MPA work which broke neither config nor DB.
