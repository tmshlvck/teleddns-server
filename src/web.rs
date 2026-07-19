//! The operator web console: a relativelylight `crud::ui::Admin` panel over our entities, plus the
//! app-owned page shell, login/profile styling, and the home/docs handlers. The full console is
//! L3-gated (admin group); non-admin users act through the DDNS/API surfaces and the profile page.

use crate::app::AppState;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use relativelylight::auth::{AdminOnly, Auth, Identity};
use relativelylight::crud::engine::Engine;
use relativelylight::crud::seaorm::{Crud, MetaModel};
use relativelylight::crud::ui::Admin;
use sea_orm::DatabaseConnection;
use std::sync::Arc;

/// Shared per-RR field metadata: the common Name / TTL / Zone columns every record type carries.
fn rr_common<E: sea_orm::EntityTrait + sea_orm::EntityName>(mm: &mut MetaModel<E>) {
    mm.field("label").label = Some("Name".into());
    mm.field("label").description = Some(
        "Record name relative to the zone origin — use @ for the zone apex, or a subdomain like \
         www (not the full FQDN)."
            .into(),
    );
    mm.field("ttl").label = Some("TTL (seconds)".into());
    mm.field("ttl").description = Some(
        "How long resolvers may cache this record, e.g. 3600 (=1h); use 300 (=5m) for records that \
         change often."
            .into(),
    );
    mm.relation("zone").label = Some("Zone".into());
    mm.relation("zone").description = Some("The zone this record belongs to.".into());
}

/// Build the CRUD engine over every managed entity, all gated admin-only (L3).
pub fn build_engine(db: DatabaseConnection, auth: &Auth) -> Engine {
    let gate = Arc::new(AdminOnly::new(auth, ["admin"]));
    let mut crud = Crud::new(db, "/admin/api");

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
    z.row_label = Box::new(|row| row["origin"].as_str().unwrap_or_default().to_string());
    crud.register(z, gate.clone());

    // One RR table per type. `reg_rr!` applies the shared Name/TTL/Zone metadata, then the listed
    // per-type rdata fields as `"col" => ("Label", "help / example")`.
    use crate::model::rr;
    macro_rules! reg_rr {
        ($ent:path $(, $field:literal => ($label:literal, $fdesc:literal) )* $(,)?) => {{
            let mut mm = MetaModel::new($ent);
            rr_common(&mut mm);
            $(
                mm.field($field).label = Some($label.into());
                mm.field($field).description = Some($fdesc.into());
            )*
            crud.register(mm, gate.clone());
        }};
    }
    reg_rr!(rr::a::Entity, "value" => ("IPv4 address", "Dotted-quad, e.g. 192.0.2.1"));
    reg_rr!(rr::aaaa::Entity, "value" => ("IPv6 address", "e.g. 2001:db8::1 (compressed form allowed)"));
    reg_rr!(rr::ns::Entity, "value" => ("Nameserver (FQDN)", "Authoritative nameserver hostname with a trailing dot, e.g. ns1.example.com."));
    reg_rr!(rr::ptr::Entity, "value" => ("Target (FQDN)", "The name this address maps back to, e.g. host.example.com."));
    reg_rr!(rr::cname::Entity, "value" => ("Canonical name (FQDN)", "Alias target with a trailing dot, e.g. example.com. A CNAME can't coexist with other records at the same name."));
    reg_rr!(rr::txt::Entity, "value" => ("Text", "Free-form text, e.g. an SPF record: v=spf1 include:_spf.example.com -all"));
    reg_rr!(rr::mx::Entity,
        "priority" => ("Priority", "Lower is preferred, e.g. 10. Mail is tried lowest-first."),
        "value" => ("Mail server (FQDN)", "Mail exchanger hostname with a trailing dot, e.g. mail.example.com."));
    reg_rr!(rr::srv::Entity,
        "priority" => ("Priority", "Lower is preferred, e.g. 10."),
        "weight" => ("Weight", "Relative share among equal-priority targets, e.g. 5 (0 = no preference)."),
        "port" => ("Port", "TCP/UDP port of the service, e.g. 443."),
        "value" => ("Target (FQDN)", "Host providing the service, e.g. sip.example.com. Use a single . for 'service not available'."));
    reg_rr!(rr::caa::Entity,
        "flag" => ("Flags", "0 normally; 128 marks the tag critical (issuers must understand it)."),
        "tag" => ("Tag", "issue, issuewild, or iodef."),
        "value" => ("Value", "For issue/issuewild: the allowed CA, e.g. letsencrypt.org. For iodef: a mailto: or URL."));
    reg_rr!(rr::sshfp::Entity,
        "algorithm" => ("Algorithm", "Key type: 1=RSA, 2=DSA, 3=ECDSA, 4=Ed25519."),
        "hash_type" => ("Hash type", "1=SHA-1, 2=SHA-256 (recommended)."),
        "fingerprint" => ("Fingerprint (hex)", "Hex-encoded host-key fingerprint."));
    reg_rr!(rr::tlsa::Entity,
        "cert_usage" => ("Certificate usage", "0=PKIX-TA, 1=PKIX-EE, 2=DANE-TA, 3=DANE-EE (most common)."),
        "selector" => ("Selector", "0=full certificate, 1=subject public key (common)."),
        "matching_type" => ("Matching type", "0=exact, 1=SHA-256 (common), 2=SHA-512."),
        "cert_data" => ("Certificate data (hex)", "Hex of the certificate/public key or its hash."));
    reg_rr!(rr::dnskey::Entity,
        "flags" => ("Flags", "256=ZSK (zone-signing), 257=KSK (key-signing / secure entry point)."),
        "protocol" => ("Protocol", "Always 3."),
        "algorithm" => ("Algorithm", "DNSSEC algorithm, e.g. 13 (ECDSA P-256/SHA-256) or 8 (RSA/SHA-256)."),
        "public_key" => ("Public key (base64)", "Base64-encoded public key."));
    reg_rr!(rr::ds::Entity,
        "key_tag" => ("Key tag", "Identifies the referenced DNSKEY, e.g. 12345."),
        "algorithm" => ("Algorithm", "DNSSEC algorithm of that DNSKEY, e.g. 13."),
        "digest_type" => ("Digest type", "1=SHA-1, 2=SHA-256 (recommended)."),
        "digest" => ("Digest (hex)", "Hex digest of the referenced DNSKEY."));
    reg_rr!(rr::naptr::Entity,
        "order" => ("Order", "Rules are processed low→high, e.g. 100."),
        "preference" => ("Preference", "Tie-break within equal order, lower first, e.g. 10."),
        "flags" => ("Flags", "e.g. U, S, A, P — empty for a non-terminal rule."),
        "service" => ("Service", "e.g. E2U+sip."),
        "regexp" => ("Regexp", "Substitution expression, e.g. !^.*$!sip:info@example.com!"),
        "replacement" => ("Replacement (FQDN)", "Next name to look up, or a single . when using Regexp."));

    // API keys: minted from the profile page; here shown read-mostly (never expose the hash).
    let mut apikey = MetaModel::new(crate::model::api_key::Entity);
    apikey.field("hashed_key").hidden = true;
    apikey.field("name").label = Some("Label".into());
    apikey.field("name").description = Some("A human-readable name for this key.".into());
    apikey.field("prefix").label = Some("Prefix".into());
    apikey.field("prefix").description =
        Some("Short visible start of the key, shown to help identify it.".into());
    apikey.field("level").label = Some("Access level".into());
    apikey.field("level").description = Some(
        "1 = one record set, 2 = a whole zone, 3 = admin. Capped by the owner's level.".into(),
    );
    apikey.field("expires_at").label = Some("Expires at".into());
    apikey.field("expires_at").description =
        Some("Optional expiry, unix seconds. Empty = never.".into());
    apikey.field("last_used_at").label = Some("Last used".into());
    apikey.field("disabled").label = Some("Disabled".into());
    apikey.relation("user").label = Some("Owner".into());
    crud.register(apikey, gate.clone());

    // Access grants (group → scope).
    let mut zr = MetaModel::new(crate::model::zone_role::Entity);
    zr.relation("group").label = Some("Group".into());
    zr.relation("group").description = Some("The group being granted access.".into());
    zr.relation("zone").label = Some("Zone".into());
    zr.relation("zone").description = Some("The zone the group may fully manage.".into());
    crud.register(zr, gate.clone());

    let mut rrr = MetaModel::new(crate::model::rr_role::Entity);
    rrr.relation("group").label = Some("Group".into());
    rrr.relation("zone").label = Some("Zone".into());
    rrr.field("label").label = Some("Record name".into());
    rrr.field("label").description =
        Some("The record label this grant is scoped to (@ = the zone apex).".into());
    crud.register(rrr, gate.clone());

    // Auth accounts + groups (admin-only, read included).
    let mut user = MetaModel::new(relativelylight::auth::user::Entity);
    user.field("password_hash").password();
    user.field("totp_secret").hidden = true;
    user.field("totp_pending").hidden = true;
    user.field("is_active").default = Some(serde_json::json!(true));
    user.field("sso_provider").label = Some("SSO provider".into());
    user.field("sso_provider").description = Some(
        "Set to an SSO provider key (e.g. google) to make this an external account — no local \
         password or 2FA. Leave empty for a local password account."
            .into(),
    );
    crud.register(user, gate.clone());
    crud.register(MetaModel::new(relativelylight::auth::group::Entity), gate.clone());

    crud.into_engine()
}

/// Build the admin panel fragment structure (grouped side-panel). Rendered per-request via
/// `render_for` so write controls hide for non-writers.
pub fn build_admin(engine: &Engine) -> Admin<'_> {
    let mut admin = Admin::new(engine).title("teleddns").group("DNS").entity_with("zone", |t| {
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
                "Bearer tokens for the HTTP API and DDNS. Only the hash is stored; the raw key is \
                 shown once at mint.",
            )
        })
        .entity_with("zone_role", |t| {
            t.title("Zone grants").description("Give a group full control of a whole zone (L2).")
        })
        .entity_with("rr_role", |t| {
            t.title("Record grants")
                .description("Give a group control of a single record set — a (zone, name) pair (L1).")
        })
        .separator()
        .group("Accounts")
        .entity_with("auth_user", |t| {
            t.title("Users").description(
                "Login accounts. Set an SSO provider on an account to make it external (no local \
                 password / 2FA).",
            )
        })
        .entity_with("auth_group", |t| {
            t.title("Groups").description("Groups drive access grants and the admin gate.")
        })
    // (API docs, profile, and log out now live in the page header/footer — see `shell`.)
}

/// The repository, shown in the footer.
const REPO_URL: &str = "https://github.com/tmshlvck/teleddns-server";

/// The app's HTML page shell (Bootstrap + Alpine — required by the crud::ui fragments). The header
/// shows the signed-in username as a link to their profile (+ log out); the footer carries the API
/// docs link, the source link, and the copyright.
pub fn shell(title: &str, user: &str, body: &str) -> String {
    let nav_user = if user.is_empty() {
        String::new()
    } else {
        // Clicking the username opens the profile page.
        format!(
            r#"<span class="navbar-text ms-auto">
<a href="/profile" class="link-body-emphasis text-decoration-none fw-medium">{user}</a>
 · <a href="/logout" class="link-secondary text-decoration-none">log out</a></span>"#,
            user = crate::keys::html_escape(user)
        )
    };
    format!(
        r#"<!doctype html><html lang="en" data-bs-theme="light"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{title}</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</head><body class="bg-body-tertiary d-flex flex-column min-vh-100">
<nav class="navbar bg-body border-bottom px-3"><a class="navbar-brand" href="/">teleddns</a>{nav_user}</nav>
<main class="container-fluid py-3 flex-grow-1">{body}</main>
<footer class="border-top py-3 mt-auto"><div class="container-fluid text-center small text-muted">
<a href="/docs" class="link-secondary text-decoration-none">API docs</a>
 · <a href="{REPO_URL}" class="link-secondary text-decoration-none" target="_blank" rel="noopener">GitHub</a>
 · © 2026 Tomas Hlavacek · <span>GPL-3.0-or-later</span></div></footer>
</body></html>"#
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

/// App chrome around the library's login form.
pub fn login_shell(form: &str) -> String {
    let body = format!(
        r#"<div class="card shadow-sm mx-auto mt-5" style="max-width:24rem"><div class="card-body">
<h1 class="h5 mb-3">Log in</h1>{form}</div></div>"#
    );
    shell("Log in — teleddns", "", &body)
}

/// App chrome around the library's profile/password/2FA page.
pub fn profile_shell(fragment: &str, who: &Identity) -> String {
    let body = format!(
        r#"<div class="card shadow-sm mx-auto mt-4" style="max-width:36rem"><div class="card-body">{fragment}
<hr><a href="/">&larr; Back to admin</a></div></div>"#
    );
    shell("Profile — teleddns", &who.username, &body)
}
