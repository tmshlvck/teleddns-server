//! The operator web console: a relativelylight `crud::ui::Admin` panel over our entities, plus the
//! app-owned page shell, login/profile styling, and the home/docs handlers. The full console is
//! Superadmin-gated (the `admin` group); everyone else acts through the DDNS/API surfaces and the
//! profile page.

use crate::app::AppState;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use relativelylight::auth::{Auth, GroupReadWrite, Identity};
use relativelylight::crud::engine::Engine;
use relativelylight::crud::seaorm::{Crud, MetaModel};
use relativelylight::crud::ui::Admin;
use sea_orm::DatabaseConnection;
use std::sync::Arc;

/// Canonicalize a name as it is written: DNS is case-insensitive but our lookups are exact string
/// matches, so a label or origin typed `WWW` here would never meet the lower-cased `www` a DDNS or API
/// request resolves to (`dns::normalize_label`). Applied to every record label, every zone origin, and
/// the label on a record grant.
fn lowercase() -> relativelylight::crud::seaorm::WriteTransform {
    Box::new(|v| match v.as_str() {
        Some(s) => serde_json::Value::String(crate::dns::normalize_label(s)),
        None => v,
    })
}

/// Shared per-RR field metadata: the common Name / TTL / Zone columns every record type carries.
/// `default_ttl` pre-fills the TTL field on the create form (`config.default_ttl` — the same value
/// the native API applies when a caller omits it).
fn rr_common<E: sea_orm::EntityTrait + sea_orm::EntityName>(mm: &mut MetaModel<E>, default_ttl: u32) {
    mm.field("label").label = Some("Name".into());
    mm.field("label").description = Some(
        "Record name relative to the zone origin — use @ for the zone apex, or a subdomain like \
         www (not the full FQDN)."
            .into(),
    );
    mm.field("label").validate_str(crate::dns::check::record_label);
    mm.field("label").on_write = Some(lowercase());
    mm.field("ttl").label = Some("TTL (seconds)".into());
    mm.field("ttl").description = Some(
        "How long resolvers may cache this record, e.g. 3600 (=1h); use 300 (=5m) for records that \
         change often."
            .into(),
    );
    mm.field("ttl").validate_int(crate::dns::check::ttl);
    mm.field("ttl").default = Some(serde_json::json!(default_ttl));
    mm.relation("zone").label = Some("Zone".into());
    mm.relation("zone").description = Some("The zone this record belongs to.".into());
    mm.field("created_at").label = Some("Created".into());
    mm.field("created_at").read_only = true;
    mm.field("created_at").datetime();
    mm.field("updated_at").label = Some("Last changed".into());
    mm.field("updated_at").read_only = true;
    mm.field("updated_at").datetime();
}

/// Build the CRUD engine over every managed entity, all gated Superadmin-only. `audit` is registered
/// as the write observer so admin-UI edits are recorded.
pub fn build_engine(
    db: DatabaseConnection,
    auth: &Auth,
    audit: Arc<crate::audit::Audit>,
    default_ttl: u32,
    password_policy: Option<relativelylight::validate::PasswordPolicy>,
) -> Engine {
    let gate = Arc::new(GroupReadWrite::new(auth, [crate::app::ADMIN_GROUP]));
    let mut crud = Crud::new(db, "/admin/api");
    crud.on_write(audit);
    // The console's API is cookie-authenticated, so every write must echo the double-submit CSRF token
    // (`auth.csrf()` shares one token cookie with the login/profile forms). The crud::ui tables add the
    // `X-CSRF-Token` header to their own fetches; a bearer-authenticated caller is exempt (nothing
    // ambient to abuse) — but that's the native API's job anyway, not this engine's.
    crud.csrf(auth.csrf());

    // Zone (+ inline SOA). The SOA fields get plain-language labels + example values.
    let mut z = MetaModel::new(crate::model::zone::Entity);
    z.field("origin").label = Some("Origin".into());
    z.field("origin").description =
        Some("Fully-qualified zone name with a trailing dot, e.g. example.com.".into());
    z.field("mname").label = Some("Primary nameserver (MNAME)".into());
    z.field("mname").description =
        Some("The zone's primary/master nameserver — the SOA MNAME, e.g. ns1.example.com.".into());
    z.field("rname").label = Some("Admin email (RNAME)".into());
    z.field("rname").description = Some(
        "Zone contact as a DNS name: the @ becomes a dot, so hostmaster.example.com. means \
         hostmaster@example.com."
            .into(),
    );
    z.field("serial").label = Some("Serial".into());
    z.field("serial").description = Some(
        "Zone version; secondaries re-transfer when it increases. Often YYYYMMDDnn, e.g. \
         2026011501. Record changes bump it automatically."
            .into(),
    );
    z.field("refresh").label = Some("Refresh (seconds)".into());
    z.field("refresh").description =
        Some("How often a secondary checks the primary for changes, e.g. 10800 (=3h).".into());
    z.field("retry").label = Some("Retry (seconds)".into());
    z.field("retry").description = Some(
        "How long a secondary waits before retrying a failed refresh, e.g. 3600 (=1h).".into(),
    );
    z.field("expire").label = Some("Expire (seconds)".into());
    z.field("expire").description = Some(
        "A secondary stops answering for the zone if it can't refresh for this long, e.g. \
         604800 (=7 days)."
            .into(),
    );
    z.field("minimum").label = Some("Minimum TTL (seconds)".into());
    z.field("minimum").description =
        Some("TTL for negative (NXDOMAIN) answers, e.g. 3600 (=1h).".into());
    z.field("ttl").label = Some("Default TTL (seconds)".into());
    z.field("ttl").description =
        Some("Default cache lifetime for the zone's records, e.g. 3600 (=1h).".into());
    z.field("created_at").label = Some("Created".into());
    z.field("created_at").read_only = true;
    z.field("created_at").datetime();
    z.field("updated_at").label = Some("Last changed".into());
    z.field("updated_at").read_only = true;
    z.field("updated_at").datetime();
    // Pre-fill the create form with the same SOA the API's auto-generated zone gets
    // (`zone::Model::new_defaults`): every one of these is `NOT NULL` with no database default, so the
    // engine now refuses a create that omits it — better a form that arrives filled in with sane
    // numbers than eight red `*`s an operator has to look up. A `default` is a *form* value, never
    // applied server-side, so an API caller still has to say what it means.
    z.field("serial").default = Some(serde_json::json!(1));
    z.field("refresh").default = Some(serde_json::json!(10800));
    z.field("retry").default = Some(serde_json::json!(3600));
    z.field("expire").default = Some(serde_json::json!(604800));
    z.field("minimum").default = Some(serde_json::json!(3600));
    z.field("ttl").default = Some(serde_json::json!(default_ttl));
    z.field("origin").validate_str(crate::dns::check::zone_origin);
    z.field("origin").on_write = Some(lowercase());
    z.field("mname").validate_str(crate::dns::check::target_name);
    z.field("rname").validate_str(crate::dns::check::target_name);
    z.field("serial").validate_int(crate::dns::check::serial);
    z.field("refresh").validate_int(crate::dns::check::soa_interval);
    z.field("retry").validate_int(crate::dns::check::soa_interval);
    z.field("expire").validate_int(crate::dns::check::soa_interval);
    z.field("minimum").validate_int(crate::dns::check::soa_interval);
    z.field("ttl").validate_int(crate::dns::check::ttl);
    z.row_label = Box::new(|row| row["origin"].as_str().unwrap_or_default().to_string());
    crud.register(z, gate.clone());

    // One RR table per type. `reg_rr!` applies the shared Name/TTL/Zone metadata, then the listed
    // per-type rdata fields as `"col" => ("Label", "help / example")`.
    use crate::dns::check;
    use crate::model::rr;
    // Each RR field carries a label + help string and an input validator: `str <pred>` (a
    // `fn(&str) -> Result<(), String>`) or `int <pred>` (a `fn(i64) -> …`) from `dns::check` — the
    // *same* predicates the native API/DDNS/CF paths enforce, so the admin can't create a record the
    // API would reject (nor one that would break the rendered zone). Every rdata field of every type
    // is validated; if you add a field here without a predicate, junk reaches the zone file.
    macro_rules! reg_rr {
        ($ent:path $(, $field:literal => ($label:literal, $fdesc:literal $(, $kind:ident $pred:path)? ) )* $(,)?) => {{
            let mut mm = MetaModel::new($ent);
            rr_common(&mut mm, default_ttl);
            $(
                mm.field($field).label = Some($label.into());
                mm.field($field).description = Some($fdesc.into());
                $( reg_rr!(@apply mm, $field, $kind $pred); )?
            )*
            crud.register(mm, gate.clone());
        }};
        (@apply $mm:ident, $field:literal, str $pred:path) => { $mm.field($field).validate_str($pred); };
        (@apply $mm:ident, $field:literal, int $pred:path) => { $mm.field($field).validate_int($pred); };
    }
    reg_rr!(rr::a::Entity, "value" => ("IPv4 address", "Dotted-quad, e.g. 192.0.2.1", str check::ipv4));
    reg_rr!(rr::aaaa::Entity, "value" => ("IPv6 address", "e.g. 2001:db8::1 (compressed form allowed)", str check::ipv6));
    reg_rr!(rr::ns::Entity, "value" => ("Nameserver (FQDN)", "Authoritative nameserver hostname with a trailing dot, e.g. ns1.example.com.", str check::target_name));
    reg_rr!(rr::ptr::Entity, "value" => ("Target (FQDN)", "The name this address maps back to, e.g. host.example.com.", str check::target_name));
    reg_rr!(rr::cname::Entity, "value" => ("Canonical name (FQDN)", "Alias target with a trailing dot, e.g. example.com. A CNAME can't coexist with other records at the same name.", str check::target_name));
    reg_rr!(rr::txt::Entity, "value" => ("Text", "Free-form text, e.g. an SPF record: v=spf1 include:_spf.example.com -all", str check::txt));
    reg_rr!(rr::mx::Entity,
        "priority" => ("Priority", "Lower is preferred, e.g. 10. Mail is tried lowest-first.", int check::u16),
        "value" => ("Mail server (FQDN)", "Mail exchanger hostname with a trailing dot, e.g. mail.example.com.", str check::target_name));
    reg_rr!(rr::srv::Entity,
        "priority" => ("Priority", "Lower is preferred, e.g. 10.", int check::u16),
        "weight" => ("Weight", "Relative share among equal-priority targets, e.g. 5 (0 = no preference).", int check::u16),
        "port" => ("Port", "TCP/UDP port of the service, e.g. 443.", int check::u16),
        "value" => ("Target (FQDN)", "Host providing the service, e.g. sip.example.com. Use a single . for 'service not available'.", str check::target_name));
    reg_rr!(rr::caa::Entity,
        "flag" => ("Flags", "0 normally; 128 marks the tag critical (issuers must understand it).", int check::octet),
        "tag" => ("Tag", "issue, issuewild, or iodef.", str check::caa_tag),
        "value" => ("Value", "For issue/issuewild: the allowed CA, e.g. letsencrypt.org. For iodef: a mailto: or URL.", str check::caa_value));
    reg_rr!(rr::sshfp::Entity,
        "algorithm" => ("Algorithm", "Key type: 1=RSA, 2=DSA, 3=ECDSA, 4=Ed25519.", int check::octet),
        "hash_type" => ("Hash type", "1=SHA-1, 2=SHA-256 (recommended).", int check::octet),
        "fingerprint" => ("Fingerprint (hex)", "Hex-encoded host-key fingerprint.", str check::hex));
    reg_rr!(rr::tlsa::Entity,
        "cert_usage" => ("Certificate usage", "0=PKIX-TA, 1=PKIX-EE, 2=DANE-TA, 3=DANE-EE (most common).", int check::octet),
        "selector" => ("Selector", "0=full certificate, 1=subject public key (common).", int check::octet),
        "matching_type" => ("Matching type", "0=exact, 1=SHA-256 (common), 2=SHA-512.", int check::octet),
        "cert_data" => ("Certificate data (hex)", "Hex of the certificate/public key or its hash.", str check::hex));
    reg_rr!(rr::dnskey::Entity,
        "flags" => ("Flags", "256=ZSK (zone-signing), 257=KSK (key-signing / secure entry point).", int check::u16),
        "protocol" => ("Protocol", "Always 3.", int check::dnskey_protocol),
        "algorithm" => ("Algorithm", "DNSSEC algorithm, e.g. 13 (ECDSA P-256/SHA-256) or 8 (RSA/SHA-256).", int check::octet),
        "public_key" => ("Public key (base64)", "Base64-encoded public key.", str check::base64));
    reg_rr!(rr::ds::Entity,
        "key_tag" => ("Key tag", "Identifies the referenced DNSKEY, e.g. 12345.", int check::u16),
        "algorithm" => ("Algorithm", "DNSSEC algorithm of that DNSKEY, e.g. 13.", int check::octet),
        "digest_type" => ("Digest type", "1=SHA-1, 2=SHA-256 (recommended).", int check::octet),
        "digest" => ("Digest (hex)", "Hex digest of the referenced DNSKEY.", str check::hex));
    reg_rr!(rr::naptr::Entity,
        "order" => ("Order", "Rules are processed low→high, e.g. 100.", int check::u16),
        "preference" => ("Preference", "Tie-break within equal order, lower first, e.g. 10.", int check::u16),
        "flags" => ("Flags", "e.g. U, S, A, P — empty for a non-terminal rule.", str check::naptr_flags),
        "service" => ("Service", "e.g. E2U+sip.", str check::naptr_service),
        "regexp" => ("Regexp", "Substitution expression, e.g. !^.*$!sip:info@example.com!", str check::naptr_regexp),
        "replacement" => ("Replacement (FQDN)", "Next name to look up, or a single . when using Regexp.", str check::target_name));

    // API keys: minted from the profile page; here shown read-mostly (never expose the hash).
    let mut apikey = MetaModel::new(crate::model::api_key::Entity);
    apikey.field("hashed_key").hidden = true;
    apikey.field("name").label = Some("Label".into());
    apikey.field("name").description = Some("A human-readable name for this key.".into());
    apikey.field("name").validate_str(check::non_empty_value);
    apikey.field("prefix").label = Some("Prefix".into());
    apikey.field("prefix").description =
        Some("Short visible start of the key, shown to help identify it.".into());
    apikey.field("expires_at").label = Some("Expires at".into());
    apikey.field("expires_at").description = Some("Optional expiry (UTC). Empty = never.".into());
    apikey.field("expires_at").datetime();
    apikey.field("last_used_at").label = Some("Last used".into());
    apikey.field("last_used_at").read_only = true; // maintained by the principal resolver, not admins
    apikey.field("last_used_at").datetime();
    apikey.field("disabled").label = Some("Disabled".into());
    apikey.relation("user").label = Some("Owner".into());
    crud.register(apikey, gate.clone());

    // Access grants (group → scope).
    let mut zr = MetaModel::new(crate::model::zone_role::Entity);
    zr.relation("group").label = Some("Group".into());
    zr.relation("group").description = Some("The group being granted access.".into());
    zr.relation("zone").label = Some("Zone".into());
    zr.relation("zone").description = Some("The zone the group may fully manage (Zone Manager).".into());
    crud.register(zr, gate.clone());

    let mut rrr = MetaModel::new(crate::model::rr_role::Entity);
    rrr.relation("group").label = Some("Group".into());
    rrr.relation("zone").label = Some("Zone".into());
    rrr.field("label").label = Some("Record name".into());
    rrr.field("label").description = Some(
        "The record label this grant is scoped to (@ = the zone apex); the grant covers its A/AAAA \
         records only."
            .into(),
    );
    rrr.field("label").validate_str(check::record_label);
    rrr.field("label").on_write = Some(lowercase());
    crud.register(rrr, gate.clone());

    // Auth accounts + groups (admin-only, read included).
    let mut user = MetaModel::new(relativelylight::auth::user::Entity);
    user.field("username").validate_str(relativelylight::auth::valid_username);
    user.field("password_hash").password();
    // The *other half* of `config.password_level`: relativelylight screens a password typed on
    // `/profile`, this screens one typed here. Skip either and it becomes the documented way around the
    // other — an admin could set `hunter2` on an account the profile page would have refused. The crud
    // pipeline is coerce → validate → transform, so the validator sees the plaintext before
    // `password()`'s argon2 hook hashes it. `optional` because blank has a meaning on this column
    // (blank on create = no password / login disabled, blank on edit = keep the current one), and
    // without it "leave blank" would become a validation error.
    if let Some(policy) = password_policy {
        user.field("password_hash").validate_str(relativelylight::validate::optional(Box::new(
            relativelylight::validate::password(policy),
        )));
    }
    user.field("totp_secret").hidden = true;
    user.field("totp_pending").hidden = true;
    // The TOTP replay guard's bookkeeping (the last step number a code was spent at). Not a secret,
    // but not an operator's business either, and editing it would either replay-enable a code or lock
    // the account out of its own authenticator until the clock caught up.
    user.field("totp_last_step").hidden = true;
    user.field("is_active").default = Some(serde_json::json!(true));
    user.field("sso_provider").label = Some("SSO provider".into());
    user.field("sso_provider").description = Some(
        "Set to an SSO provider key (e.g. google) to make this an external account — no local \
         password or 2FA. Leave empty for a local password account."
            .into(),
    );
    // Lifecycle timestamps are maintained by relativelylight (hook / login flow) — show, don't edit.
    for f in ["created_at", "updated_at", "last_login_at"] {
        user.field(f).read_only = true;
        user.field(f).datetime();
    }
    let mut group = MetaModel::new(relativelylight::auth::group::Entity);
    group.field("name").validate_str(relativelylight::auth::valid_group_name);
    for f in ["created_at", "updated_at"] {
        group.field(f).read_only = true;
        group.field(f).datetime();
    }
    // Expose the user↔group membership (N:M) on both forms so admins can assign groups from either
    // the user or the group. (SSO users' groups are reconciled on login — see sso.rs — so manual
    // edits to an SSO account's groups are overwritten on their next login.)
    user.relate(&group);
    group.relate(&user);
    // The relation's name is the target model's slug (auth_group / auth_user).
    user.relation("auth_group").label = Some("Groups".into());
    user.relation("auth_group").description =
        Some("Group memberships — the zone/record grants hang off these, and `admin` means Superadmin.".into());
    group.relation("auth_user").label = Some("Members".into());
    crud.register(user, gate.clone());
    crud.register(group, gate.clone());

    // Lockout rows (relativelylight `auth::lockout`): who is currently locked out of the login form /
    // DDNS Basic / the token surfaces, and the operator's unlock — **deleting the row**. Everything is
    // maintained by the limiter, so nothing here is editable; the delete is gated (Superadmin), CSRF-checked
    // and audited like any other write, which is exactly why the counters live in the DB (PRD §3.6).
    let mut ul = MetaModel::new(relativelylight::auth::lockout::username_entity::Entity);
    ul.field("username").label = Some("Account".into());
    ul.field("username").description =
        Some("The submitted account name (lower-cased). Unknown names are counted too.".into());
    ul.field("failures").label = Some("Failures".into());
    ul.field("failures").read_only = true;
    ul.field("last_failure_at").label = Some("Last failure".into());
    ul.field("last_failure_at").read_only = true;
    ul.field("last_failure_at").datetime();
    ul.row_label = Box::new(|row| row["username"].as_str().unwrap_or_default().to_string());
    crud.register(ul, gate.clone());

    let mut il = MetaModel::new(relativelylight::auth::lockout::ip_entity::Entity);
    il.field("ip").label = Some("Client address".into());
    il.field("ip").description =
        Some("Source address as resolved for the request (honours trust_proxy).".into());
    il.field("failures").label = Some("Failures".into());
    il.field("failures").read_only = true;
    il.field("last_failure_at").label = Some("Last failure".into());
    il.field("last_failure_at").read_only = true;
    il.field("last_failure_at").datetime();
    il.row_label = Box::new(|row| row["ip"].as_str().unwrap_or_default().to_string());
    crud.register(il, gate.clone());

    // Audit log: read-only view (rows are written by the audit sink, never the CRUD API).
    let mut a = MetaModel::new(crate::model::audit::Entity);
    for f in ["id", "ts", "source", "operation", "target", "actor_user_id", "actor_username",
              "auth_type", "client_ip", "before", "after"] {
        a.field(f).read_only = true;
    }
    a.field("ts").datetime();
    a.row_label = Box::new(|row| {
        format!(
            "{} {} {}",
            row["ts"].as_i64().unwrap_or(0),
            row["operation"].as_str().unwrap_or(""),
            row["target"].as_str().unwrap_or("")
        )
    });
    crud.register(a, gate.clone());

    crud.into_engine()
}

/// Build the admin panel fragment structure (grouped side-panel). Rendered per-request via
/// `render_for` so write controls hide for non-writers.
pub fn build_admin(engine: &Engine) -> Admin<'_> {
    // No component title (the navbar brand `ui_title` is the single app heading) — omitting
    // `.title(...)` leaves `has_title = false`, so no empty heading element is rendered.
    let mut admin = Admin::new(engine).group("DNS").entity_with("zone", |t| {
        t.title("Zones").description(
            "DNS zones and their SOA. Creating a zone auto-generates the SOA and a default apex NS; \
             record changes bump the serial and trigger a backend sync.",
        )
    });
    // (slug, RR type, description). Title shown as "RR <type>".
    let rrs: [(&str, &str, &str); 14] = [
        ("rr_a", "A", "Address — maps a name to an IPv4 address."),
        ("rr_aaaa", "AAAA", "IPv6 address — maps a name to an IPv6 address."),
        ("rr_ns", "NS", "Nameserver — delegates a name to authoritative nameservers."),
        ("rr_ptr", "PTR", "Pointer — reverse DNS: maps an address back to a name."),
        ("rr_cname", "CNAME", "Canonical name — aliases one name to another (can't coexist with other records at the same name)."),
        ("rr_txt", "TXT", "Text — arbitrary text; used for SPF, DKIM, domain verification, etc."),
        ("rr_mx", "MX", "Mail exchange — where email for the zone is delivered."),
        ("rr_srv", "SRV", "Service — advertises the host and port of a service (SIP, XMPP, …)."),
        ("rr_caa", "CAA", "Certification Authority Authorization — which CAs may issue certificates."),
        ("rr_sshfp", "SSHFP", "SSH fingerprint — publishes SSH host-key fingerprints for verification."),
        ("rr_tlsa", "TLSA", "TLSA / DANE — binds a certificate or key to a name for TLS."),
        ("rr_dnskey", "DNSKEY", "DNSSEC public keys for the zone."),
        ("rr_ds", "DS", "Delegation Signer — the DNSSEC link placed in the parent zone."),
        ("rr_naptr", "NAPTR", "Naming Authority Pointer — regexp-based rewriting (ENUM, SIP discovery)."),
    ];
    for (slug, ty, desc) in rrs {
        let title = format!("RR {ty}");
        admin = admin.entity_with(slug, move |t| t.title(title).description(desc));
    }
    admin
        .separator()
        .group("Access")
        .entity_with("api_key", |t| {
            t.title("API keys").description(
                "Bearer tokens for the HTTP API and DDNS. A key has no rights of its own — it acts as \
                 its owner, so what it may touch is whatever that account's grants allow. Only the \
                 hash is stored; the raw key is shown once at mint.",
            )
        })
        .entity_with("zone_role", |t| {
            t.title("Zone grants").description(
                "Zone Manager: the group may manage every record in the zone, of any type, including \
                 deletes.",
            )
        })
        .entity_with("rr_role", |t| {
            t.title("Record grants").description(
                "RR Manager: the group may create and update the A/AAAA set at one (zone, name) — what \
                 a DDNS client needs, and nothing else.",
            )
        })
        .separator()
        .group("Accounts")
        .entity_with("auth_user", |t| {
            t.title("Users").description(
                "Login accounts — for people, and for devices that need their own narrow grant. Set an \
                 SSO provider on an account to make it external (no local password / 2FA).",
            )
        })
        .entity_with("auth_group", |t| {
            t.title("Groups").description(
                "Groups carry the grants below; membership of `admin` is the Superadmin role.",
            )
        })
        .entity_with("auth_username_lockout", |t| {
            t.title("Locked accounts").description(
                "Accounts with recent failed logins (console, DDNS HTTP Basic). Delete a row to \
                 unlock one immediately; otherwise it clears itself when the lockout expires.",
            )
        })
        .entity_with("auth_ip_lockout", |t| {
            t.title("Locked addresses").description(
                "Client addresses with recent failed credential checks — this is what brakes bearer- \
                 token guessing, which names no account. Delete a row to unlock.",
            )
        })
        .separator()
        .group("Audit")
        .entity_with("audit", |t| {
            t.read_only(true).per_page(50).title("Audit log").description(
                "Append-only record of every state-changing request (DDNS, API, CF facade, admin, \
                 auth). Read-only.",
            )
        })
    // (API docs, profile, and log out now live in the page header/footer — see `shell`.)
}

/// The repository, shown in the footer.
const REPO_URL: &str = "https://github.com/tmshlvck/teleddns-server";

/// The server version, shown in the footer.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The navbar brand (`ui_title`), set once at startup; defaults to "TeleDDNS" until then.
static UI_TITLE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Set the navbar brand from config (call once at startup).
pub fn init_ui_title(title: &str) {
    let _ = UI_TITLE.set(title.to_string());
}

fn ui_title() -> &'static str {
    UI_TITLE.get().map(String::as_str).unwrap_or("TeleDDNS Server Manager")
}

/// Sets the initial Bootstrap color mode before first paint (so there's no flash): a remembered
/// choice from `localStorage`, else the browser's `prefers-color-scheme`. Runs first in `<head>`.
const THEME_HEAD: &str = r#"<script>(function(){try{var s=localStorage.getItem('theme');}catch(e){}var t=s||((window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches)?'dark':'light');document.documentElement.setAttribute('data-bs-theme',t);})();</script>"#;

/// The light/dark toggle behavior: the top-right button shows a sun in dark mode (→ switch to light)
/// and a moon in light mode (→ switch to dark); the choice is remembered in `localStorage`.
const THEME_JS: &str = r#"<script>
function ruTheme(){return document.documentElement.getAttribute('data-bs-theme')||'light';}
function ruThemeIcon(){var b=document.getElementById('theme-toggle');if(b){var d=ruTheme()==='dark';b.textContent=d?'☀':'☾';b.title=d?'Switch to light mode':'Switch to dark mode';}}
function ruToggleTheme(){var n=ruTheme()==='dark'?'light':'dark';document.documentElement.setAttribute('data-bs-theme',n);try{localStorage.setItem('theme',n);}catch(e){}ruThemeIcon();}
document.addEventListener('DOMContentLoaded',ruThemeIcon);
</script>"#;

/// The app's HTML page shell (Bootstrap + Alpine — required by the crud::ui fragments). The header
/// shows the configurable brand (`ui_title`) and the signed-in username as a link to their profile
/// (+ log out) and a light/dark toggle; the footer carries the server name + version, the API docs
/// and source links, and the copyright.
pub fn shell(title: &str, user: &str, body: &str) -> String {
    let brand = crate::keys::html_escape(ui_title());
    let nav_user = if user.is_empty() {
        String::new()
    } else {
        // Clicking the username opens the profile page.
        format!(
            r#"<span class="navbar-text">
<a href="/profile" class="link-body-emphasis text-decoration-none fw-medium">{user}</a>
 · <a href="/logout" class="link-secondary text-decoration-none">log out</a></span>"#,
            user = crate::keys::html_escape(user)
        )
    };
    format!(
        r#"<!doctype html><html lang="en"><head>{THEME_HEAD}<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{title}</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<!-- Required by the relativelylight crud::ui fragments: hides x-cloak'd elements (the admin panels
     and the create/edit modal) until Alpine initializes, so no incomplete markup flashes on load. -->
<style>[x-cloak] {{ display: none !important; }}</style>
<script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</head><body class="bg-body-tertiary d-flex flex-column min-vh-100">
<nav class="navbar bg-body border-bottom px-3"><a class="navbar-brand" href="/">{brand}</a>
<div class="d-flex align-items-center gap-3 ms-auto">{nav_user}<button id="theme-toggle" type="button"
 class="btn btn-sm btn-outline-secondary border-0 px-2" onclick="ruToggleTheme()"
 aria-label="Toggle light / dark mode">&#9790;</button></div></nav>
<main class="container-fluid py-3 flex-grow-1">{body}</main>
<footer class="border-top py-3 mt-auto"><div class="container-fluid text-center small text-muted">
<span>teleddns-server v{VERSION}</span>
 · <a href="/docs" class="link-secondary text-decoration-none">API docs</a>
 · <a href="{REPO_URL}" class="link-secondary text-decoration-none" target="_blank" rel="noopener">GitHub</a>
 · © 2026 Tomas Hlavacek · <span>GPL-3.0-or-later</span></div></footer>
{THEME_JS}</body></html>"#
    )
}

/// Home = the admin console, login-gated. Anonymous → redirect to login.
pub async fn home(headers: HeaderMap, State(app): State<AppState>) -> Response {
    let Some(who) = app.auth.identify(&headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    let body = match build_admin(&app.engine).render_for(&headers).await {
        Ok(html) => html,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    Html(shell("teleddns admin", &who.username, &body)).into_response()
}

pub async fn openapi_json(State(app): State<AppState>) -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "application/json")], app.openapi.clone())
}

pub async fn docs() -> Html<&'static str> {
    Html(
        r#"<!doctype html><html><head><meta charset="utf-8"><title>teleddns API docs</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css"></head>
<body><div id="swagger-ui"></div>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>window.onload=()=>{SwaggerUIBundle({url:'/openapi.json',dom_id:'#swagger-ui'});};</script>
</body></html>"#,
    )
}

/// App chrome around the library's login form, with any configured SSO buttons appended below it.
pub fn login_shell(form: &str, sso_buttons: &str) -> String {
    let body = format!(
        r#"<div class="card shadow-sm mx-auto mt-5" style="max-width:24rem"><div class="card-body">
<h1 class="h5 mb-3">Log in</h1>{form}{sso_buttons}</div></div>"#
    );
    shell("Log in — teleddns", "", &body)
}

/// The CSRF refusal, in our page shell instead of relativelylight's bare one (`Auth::csrf_rejection`,
/// which also covers `csrf::enforce` on our own routes). Same discipline as the default: the request
/// never proved it came from this site, so it names no user and sets no cookie, and it stays a `403`.
pub fn csrf_rejected() -> Response {
    (
        StatusCode::FORBIDDEN,
        Html(shell(
            "Request rejected — teleddns",
            "",
            r#"<div class="card shadow-sm mx-auto mt-5" style="max-width:32rem"><div class="card-body">
<h1 class="h5 mb-3">Request rejected</h1>
<p class="mb-1">This form's security token was missing or stale — usually a page left open too long, or
one reloaded after signing out.</p>
<p class="mb-0"><a href="/">Reload the console</a> and try again.</p></div></div>"#,
        )),
    )
        .into_response()
}

/// App chrome around the library's profile/password/2FA page.
pub fn profile_shell(fragment: &str, who: &Identity) -> String {
    let body = format!(
        r#"<div class="card shadow-sm mx-auto mt-4" style="max-width:36rem"><div class="card-body">{fragment}
<hr><a href="/">&larr; Back to admin</a></div></div>"#
    );
    shell("Profile — teleddns", &who.username, &body)
}
