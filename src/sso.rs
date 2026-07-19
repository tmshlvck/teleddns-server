//! OIDC single sign-on: build the relativelylight `Sso` (feature `sso`) from teleddns config and
//! render the login-page buttons. relativelylight owns the Authorization-Code+PKCE flow, ID-token
//! verification, user resolution/auto-registration, and on-login group reconciliation; teleddns only
//! translates its config into the library's two group-mapping tables.
//!
//! **Config → library mapping.** The callback URL is `<public_url>/login/sso/<name>/callback`. Each
//! provider's `group_rules` split by their `claim`:
//! - a rule whose `claim` equals the provider's `username_claim` (default `email`) becomes a **global
//!   username-pattern rule** (`regex`, or `equals` anchored as `^…$`) matched against the username;
//! - any other `claim` sets the provider's **groups claim** and contributes **exact-value** rules
//!   (`equals`). relativelylight matches claim values by equality only, so `regex` on a non-username
//!   claim is unsupported (logged + ignored).

use crate::config::{Config, GroupRule};
use relativelylight::auth::sso::{Sso, SsoProvider};
use relativelylight::auth::Auth;

const BASE_PATH: &str = "/login/sso";

/// Build the SSO configuration from `cfg`, or `None` when there are no providers (or no `public_url`
/// to derive redirect URLs from).
pub fn build(cfg: &Config, auth: &Auth) -> Option<Sso> {
    if cfg.sso_providers.is_empty() {
        return None;
    }
    if cfg.public_url.is_empty() {
        tracing::warn!("sso_providers configured but public_url is empty — SSO disabled");
        return None;
    }
    let public = cfg.public_url.trim_end_matches('/');
    let mut sso = Sso::new(auth).base_path(BASE_PATH);

    for pc in &cfg.sso_providers {
        // Username-pattern rules are global on the Sso.
        for r in &pc.group_rules {
            if rule_claim(r) == pc.username_claim {
                if let Some(pat) = rule_pattern(r) {
                    sso = sso.username_group_rule(&pat, r.groups.clone());
                }
            }
        }

        let label =
            if pc.display_name.is_empty() { pc.name.clone() } else { pc.display_name.clone() };
        let redirect = format!("{public}{BASE_PATH}/{}/callback", pc.name);
        let mut p = SsoProvider::new(
            pc.name.clone(),
            label,
            pc.issuer.clone(),
            pc.client_id.clone(),
            pc.client_secret.clone(),
            redirect,
        )
        .scopes(pc.scopes.clone())
        .username_claim(pc.username_claim.clone())
        .auto_register(pc.auto_register);

        // Non-username claims → per-provider exact-value rules on that groups claim.
        for r in &pc.group_rules {
            let claim = rule_claim(r);
            if claim == pc.username_claim {
                continue;
            }
            p = p.groups_claim(claim.clone());
            if let Some(eq) = &r.equals {
                p = p.claim_group_rule(eq.clone(), r.groups.clone());
            } else if r.regex.is_some() {
                tracing::warn!(
                    provider = %pc.name, claim = %claim,
                    "SSO group rule uses regex on a non-username claim; relativelylight matches claim \
                     values by exact equality only — rule ignored"
                );
            }
        }
        sso = sso.provider(p);
    }
    Some(sso)
}

/// The claim a rule matches (defaulting to `email`).
fn rule_claim(r: &GroupRule) -> String {
    if r.claim.is_empty() {
        "email".into()
    } else {
        r.claim.clone()
    }
}

/// A username-rule regex from a `GroupRule`: `regex` verbatim, or `equals` anchored (`^…$`, escaped).
fn rule_pattern(r: &GroupRule) -> Option<String> {
    if let Some(rx) = &r.regex {
        Some(rx.clone())
    } else {
        r.equals.as_ref().map(|eq| format!("^{}$", regex::escape(eq)))
    }
}

/// The login-page SSO buttons (empty when no providers) — appended to the login form.
pub fn buttons_html(cfg: &Config) -> String {
    if cfg.sso_providers.is_empty() || cfg.public_url.is_empty() {
        return String::new();
    }
    let mut out = String::from(r#"<hr class="my-3"><div class="d-grid gap-2">"#);
    for p in &cfg.sso_providers {
        let label = if p.display_name.is_empty() { &p.name } else { &p.display_name };
        out.push_str(&format!(
            r#"<a class="btn btn-outline-primary" href="{BASE_PATH}/{key}/login">Sign in with {label}</a>"#,
            key = crate::keys::html_escape(&p.name),
            label = crate::keys::html_escape(label),
        ));
    }
    out.push_str("</div>");
    out
}
