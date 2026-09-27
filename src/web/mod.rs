//! The operator web console — a plain multi-page app. Every page is rendered server-side: the
//! library hands us HTML *fragments* ([`relativelylight::crud::ui`]) and this module owns the
//! `<html>`, the navbar, the login/profile chrome and the two handlers behind each surface.
//!
//! The shape is the one [`relativelylight`]'s `docs/APP.md` describes, and it is the whole of it:
//!
//! * a `GET` renders (`render_for`), a `POST` on the **same path** writes (`submit`), and a write
//!   answers `303` back to the list it came from — so back, forward, refresh and a bookmarked
//!   filtered view all behave;
//! * the **URL is the view**: page, sort, filters, search, which entity is showing and which row's
//!   dialog is open are all query parameters, parsed once into a [`ViewState`];
//! * there is no JSON between the browser and the server, no framework, and no script file. The
//!   only JavaScript the shell ships is the light/dark toggle, which is pure enhancement.
//!
//! [`dashboard`] is the landing page; [`entities`] configures what the console can manage.

pub mod dashboard;
mod entities;

pub use entities::build_engine;

use crate::app::AppState;
use askama::Template;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Redirect, Response};
use relativelylight::auth::Identity;
use relativelylight::crud::engine::Engine;
use relativelylight::crud::ui::{Admin, Outcome, ViewState, CSS};
use relativelylight::middleware::RealIp;
use relativelylight::time::{Tz, TzPicker};
use std::collections::HashMap;

/// The repository, shown in the footer.
const REPO_URL: &str = "https://github.com/tmshlvck/teleddns-server";

/// The server version, shown in the footer.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The entity the console opens on — the console's own `/` in effect.
pub const FIRST_ENTITY: &str = "/admin/zone";

// ===================== the page shell =====================

/// The navbar brand and the offered timezones, both from config, set once at startup.
static UI: std::sync::OnceLock<(String, TzPicker)> = std::sync::OnceLock::new();

/// Wire the shell to the configuration (call once at startup). Timezone names the host's database
/// doesn't know are dropped here and reported, rather than offered as options that silently mean UTC.
pub fn init(cfg: &crate::config::Config) {
    let picker = match cfg.timezones.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        [] => TzPicker::new(),
        ["all"] => TzPicker::new().all_zones(),
        ref list => TzPicker::new().zones(list.iter().copied()),
    };
    if !picker.unknown_zones().is_empty() {
        tracing::warn!(ignored = ?picker.unknown_zones(), "config `timezones` names zones this host doesn't know");
    }
    let _ = UI.set((cfg.ui_title.clone(), picker));
}

fn ui() -> &'static (String, TzPicker) {
    UI.get_or_init(|| ("TeleDDNS Server Manager".into(), TzPicker::new()))
}

struct NavItem {
    label: &'static str,
    href: &'static str,
    active: bool,
}

/// The app's HTML page — the only place a `<html>` element is written.
#[derive(Template)]
#[template(path = "shell.html")]
struct Shell {
    title: String,
    brand: &'static str,
    user: String,
    nav: Vec<NavItem>,
    body: String,
    /// The navbar timezone form, or empty on the pages rendered without a request in hand.
    tz_picker: String,
    css: &'static str,
    version: &'static str,
    repo: &'static str,
}

impl Shell {
    /// A page rendered from a request: the nav highlights where we are and the timezone picker
    /// returns here, so setting a zone doesn't lose the table the operator was looking at.
    fn page(title: &str, who: &Identity, uri: &Uri, headers: &HeaderMap, body: String) -> Shell {
        let here = uri.path();
        let (brand, picker) = ui();
        Shell {
            title: title.into(),
            brand,
            user: who.username.clone(),
            nav: vec![
                NavItem { label: "Dashboard", href: "/", active: here == "/" },
                NavItem { label: "Console", href: FIRST_ENTITY, active: here.starts_with("/admin") },
            ],
            body,
            tz_picker: picker.render(&Tz::from_headers(headers), full_path(uri)),
            css: CSS,
            version: VERSION,
            repo: REPO_URL,
        }
    }

    /// A page rendered *for* us by the library — the login form, the profile page, the CSRF
    /// refusal. Those handlers hand us a fragment and an identity, never the request, so there is no
    /// URL to highlight and no headers to read a timezone cookie from.
    fn plain(title: &str, user: &str, body: String) -> Shell {
        Shell {
            title: title.into(),
            brand: &ui().0,
            user: user.into(),
            nav: Vec::new(),
            body,
            tz_picker: String::new(),
            css: CSS,
            version: VERSION,
            repo: REPO_URL,
        }
    }

    fn html(self) -> String {
        self.render().unwrap_or_else(|e| format!("<pre>template error: {e}</pre>"))
    }
}

fn full_path(uri: &Uri) -> &str {
    uri.path_and_query().map(|p| p.as_str()).unwrap_or("/")
}

/// Wrap a fragment in a centred card — the shape of every page that is one form (login, profile,
/// a one-off confirmation) rather than a table.
fn card(width_rem: u32, body: &str) -> String {
    format!(
        r#"<div class="card shadow-sm mx-auto mt-4" style="max-width:{width_rem}rem"><div class="card-body">{body}</div></div>"#
    )
}

// ===================== the admin console =====================

/// The console's structure: the side panel's groups, and each table's title and help. **Built by a
/// function, not stored**, because the read and the write handler must describe the same panel — a
/// link one renders has to be a write the other accepts, and `submit` refuses an entity this panel
/// doesn't list before it consults any gate.
fn panel(engine: &Engine) -> Admin<'_> {
    // No component title: the navbar brand is the page's one heading.
    Admin::new(engine)
        // A path per model — /admin/zone, /admin/rr_a — so a deep link says what it is.
        .base("/admin")
        // One zone control in the side panel, applied to every table that has a zone: an operator
        // works inside one zone at a time, picks it once, and it follows them across all fifteen
        // record tables. Tables without the column (users, groups, the audit log) ignore it.
        .filter("zone")
        .group("DNS")
        .entity_with("zone", |t| {
            t.title("Zones").description(
                "DNS zones and their SOA. Creating a zone auto-generates the SOA and a default apex NS; \
                 record changes bump the serial and trigger a backend sync.",
            )
        })
        .rr_tables()
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
                "Groups carry the grants above; membership of `admin` is the Superadmin role.",
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
            // The `source` vocabulary belongs in the *table's* description, not the column's: a
            // field description renders under a form input, and this table is `read_only`, so it has
            // no form and the help would never be seen. `source` is the column an operator reads the
            // log by, and "cli" or "autocrud" mean nothing without the list.
            t.read_only(true).per_page(50).title("Audit log").description(format!(
                "Append-only record of every state-changing request (DDNS, API, CF facade, admin, \
                 auth). Read-only. The `source` column is one of: {}.",
                crate::audit::SOURCES.join(", ")
            ))
        })
}

/// The fourteen per-type record tables, added in one go. `(slug, type, description)`; the title is
/// `RR <type>`. Each carries the zone in its own column, so `panel`'s shared filter reaches them all.
trait RrTables<'a> {
    fn rr_tables(self) -> Admin<'a>;
}

impl<'a> RrTables<'a> for Admin<'a> {
    fn rr_tables(mut self) -> Admin<'a> {
        const RRS: [(&str, &str, &str); 14] = [
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
        for (slug, ty, desc) in RRS {
            let title = format!("RR {ty}");
            self = self.entity_with(slug, move |t| t.title(title).description(desc));
        }
        self
    }
}

/// `GET /admin/{entity}` — render one table, or export the view on screen as CSV.
pub async fn admin_show(
    headers: HeaderMap,
    uri: Uri,
    Path(entity): Path<String>,
    State(app): State<AppState>,
) -> Response {
    let Some(who) = app.auth.identify(&headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    // The path names the model; the query carries the view of it.
    let mut state = ViewState::from_uri(&uri);
    state.entity = Some(entity);

    // The toolbar's Export link is `?format=csv` on this very page, so the export is this handler's
    // other answer — and it exports what is on screen: filter, search, sort and timezone included.
    if state.csv {
        return match panel(&app.engine).csv(&headers, &state).await {
            Ok(csv) => (
                [
                    (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
                    (header::CONTENT_DISPOSITION, "attachment; filename=\"export.csv\"".into()),
                ],
                csv,
            )
                .into_response(),
            Err(e) => e.into_response(),
        };
    }

    match panel(&app.engine).render_for(&headers, &state).await {
        // `render_for` is the read enforcement point: a caller the gate refuses gets 401/403 here,
        // not a page with the rows in it.
        Ok(body) => Html(Shell::page("Console — teleddns", &who, &uri, &headers, body).html()).into_response(),
        Err(e) => e.into_response(),
    }
}

/// `POST /admin/{entity}` — hand the posted body to the library, then redirect; or, if it was
/// refused, re-render the same dialog with the messages **and** the operator's input still in it.
pub async fn admin_save(
    headers: HeaderMap,
    uri: Uri,
    Path(entity): Path<String>,
    RealIp(ip): RealIp,
    State(app): State<AppState>,
    // Raw bytes, not a String: the CSV import dialog uploads a real multipart file.
    body: Bytes,
) -> Response {
    let Some(who) = app.auth.identify(&headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    let mut state = ViewState::from_uri(&uri);
    state.entity = Some(entity);
    // Deletes need no special handling here: they fire no SeaORM hook, but the engine hands every
    // removed row to the write observers, where `audit` records them and `sync::DeleteSync` bumps
    // the affected zones' serials and queues a push.
    match panel(&app.engine).submit(&headers, ip, &body, &state).await {
        Ok(Outcome::Done(to)) => Redirect::to(&to).into_response(),
        Ok(Outcome::Invalid(state)) => match panel(&app.engine).render_for(&headers, &state).await {
            Ok(body) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Html(Shell::page("Console — teleddns", &who, &uri, &headers, body).html()),
            )
                .into_response(),
            Err(e) => e.into_response(),
        },
        Err(e) => e.into_response(),
    }
}

/// `POST /tz` — the timezone picker's four lines. Set the cookie, come back to the page it was set
/// from; every timestamp the server renders after that is in the chosen zone.
pub async fn set_tz(axum::Form(f): axum::Form<HashMap<String, String>>) -> Response {
    let tz = Tz::named(f.get("tz").map(String::as_str).unwrap_or("UTC"));
    // Only ever back to a path on this site — `back` arrives in a form body, so it is caller input.
    let back = match f.get("back") {
        Some(b) if b.starts_with('/') && !b.starts_with("//") => b.clone(),
        _ => "/".into(),
    };
    ([(header::SET_COOKIE, tz.cookie())], Redirect::to(&back)).into_response()
}

// ===================== API documentation =====================

pub async fn openapi_json(State(app): State<AppState>) -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "application/json")], app.openapi.clone())
}

/// Swagger UI over `/openapi.json`. The one page in the app that is a JavaScript application —
/// it is a third-party document viewer for the *machine* API, not part of the console.
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

// ===================== the pages relativelylight renders =====================

/// App chrome around the library's login form, with any configured SSO buttons appended below it.
pub fn login_shell(form: &str, sso_buttons: &str) -> String {
    Shell::plain("Log in — teleddns", "", card(24, &format!(r#"<h1 class="h5 mb-3">Log in</h1>{form}{sso_buttons}"#)))
        .html()
}

/// App chrome around the library's profile/password/2FA page (and, below it, [`crate::keys`]'s
/// API-key card — composed in via `Auth::profile_extra`).
pub fn profile_shell(fragment: &str, who: &Identity) -> String {
    let body = card(36, &format!(r#"{fragment}<hr><a href="/">&larr; Back to the dashboard</a>"#));
    Shell::plain("Profile — teleddns", &who.username, body).html()
}

/// The CSRF refusal, in our page shell instead of relativelylight's bare one. Same discipline as the
/// default: the request never proved it came from this site, so it names no user and sets no cookie,
/// and it stays a `403`.
pub fn csrf_rejected() -> Response {
    let body = card(
        32,
        r#"<h1 class="h5 mb-3">Request rejected</h1>
<p class="mb-1">This form's security token was missing or stale — usually a page left open too long, or
one reloaded after signing out.</p>
<p class="mb-0"><a href="/">Reload the console</a> and try again.</p>"#,
    );
    (StatusCode::FORBIDDEN, Html(Shell::plain("Request rejected — teleddns", "", body).html()))
        .into_response()
}

/// A one-off page carrying one message in a card — used by [`crate::keys`] to show a freshly
/// minted key once.
pub fn notice(title: &str, user: &str, body: &str) -> Response {
    Html(Shell::plain(title, user, card(36, body)).html()).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shell is the one place `<html>` is written, and it must carry Bootstrap's stylesheet and
    /// the library's own CSS — without the latter the create/edit `<dialog>` renders unstyled.
    /// It must **not** carry Alpine or Bootstrap's JavaScript bundle: 0.3 needs neither, and a page
    /// that still loads them is a page someone will write client-side state into again.
    #[test]
    fn the_shell_loads_the_stylesheets_and_no_framework() {
        let html = Shell::plain("t", "someone", "<p>body</p>".into()).html();
        assert!(html.contains("bootstrap@5.3.3/dist/css/bootstrap.min.css"));
        assert!(html.contains(CSS), "crud::ui::CSS must be inlined");
        assert!(!html.contains("alpinejs"), "no Alpine: {html}");
        assert!(!html.contains("bootstrap.bundle"), "no Bootstrap JS bundle");
        assert!(!html.contains("x-cloak"));
    }

    /// `back` comes out of a posted form, so it is caller input: it must never be able to send the
    /// browser off-site after setting the cookie.
    #[tokio::test]
    async fn the_timezone_form_only_returns_to_a_local_path() {
        let go = |back: &str| {
            let f = HashMap::from([("tz".to_string(), "UTC".to_string()), ("back".into(), back.into())]);
            async move {
                let r = set_tz(axum::Form(f)).await;
                r.headers().get(header::LOCATION).unwrap().to_str().unwrap().to_string()
            }
        };
        assert_eq!(go("/admin/rr_a?page=2").await, "/admin/rr_a?page=2");
        assert_eq!(go("https://evil.example/").await, "/");
        assert_eq!(go("//evil.example/").await, "/");
    }
}
