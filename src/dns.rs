//! Shared DNS helpers: FQDN normalization, longest-origin zone/label resolution, and value
//! validation used by the DDNS endpoint, the native API, and the Cloudflare facade.

use crate::model::zone;
use sea_orm::{ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Lowercase and ensure a single trailing dot.
pub fn normalize_fqdn(s: &str) -> String {
    let mut n = s.trim().to_ascii_lowercase();
    if !n.ends_with('.') {
        n.push('.');
    }
    n
}

/// Resolve an FQDN to `(zone, label)` by longest matching origin. `label` is `@` for the apex.
pub async fn resolve_zone<C: ConnectionTrait>(
    db: &C,
    fqdn: &str,
) -> Result<Option<(zone::Model, String)>, DbErr> {
    let fqdn = normalize_fqdn(fqdn);
    // Candidate origins: every right-hand suffix of the name.
    let labels: Vec<&str> = fqdn.trim_end_matches('.').split('.').collect();
    let mut candidates: Vec<String> = Vec::new();
    for i in 0..labels.len() {
        candidates.push(format!("{}.", labels[i..].join(".")));
    }
    if candidates.is_empty() {
        return Ok(None);
    }
    let zones = zone::Entity::find()
        .filter(zone::Column::Origin.is_in(candidates))
        .all(db)
        .await?;
    // Longest origin wins.
    let Some(z) = zones.into_iter().max_by_key(|z| z.origin.len()) else {
        return Ok(None);
    };
    let label = label_in_zone(&fqdn, &z.origin);
    Ok(Some((z, label)))
}

/// The record label of `fqdn` within `origin` (`@` at the apex).
pub fn label_in_zone(fqdn: &str, origin: &str) -> String {
    let fqdn = normalize_fqdn(fqdn);
    if fqdn == origin {
        return "@".to_string();
    }
    match fqdn.strip_suffix(&format!(".{origin}")) {
        Some(l) => l.to_string(),
        None => fqdn.trim_end_matches('.').to_string(),
    }
}

/// Build the FQDN of a `(label, origin)` pair.
pub fn fqdn_of(label: &str, origin: &str) -> String {
    if label == "@" || label.is_empty() {
        origin.to_string()
    } else {
        format!("{label}.{origin}")
    }
}

/// Is this a syntactically valid IPv4 literal?
pub fn is_ipv4(s: &str) -> bool {
    s.parse::<Ipv4Addr>().is_ok()
}

/// Is this a syntactically valid IPv6 literal?
pub fn is_ipv6(s: &str) -> bool {
    s.parse::<Ipv6Addr>().is_ok()
}

/// A permissive DNS label/name check for rdata (allows `@`, underscores, trailing dot).
pub fn is_valid_name(s: &str) -> bool {
    if s == "@" {
        return true;
    }
    let s = s.trim_end_matches('.');
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fqdn_norm() {
        assert_eq!(normalize_fqdn("Host.Example.COM"), "host.example.com.");
        assert_eq!(normalize_fqdn("example.com."), "example.com.");
    }

    #[test]
    fn label_extraction() {
        assert_eq!(label_in_zone("host.sub.example.com.", "sub.example.com."), "host");
        assert_eq!(label_in_zone("sub.example.com.", "sub.example.com."), "@");
        assert_eq!(label_in_zone("a.b.example.com", "example.com."), "a.b");
    }

    #[test]
    fn ip_checks() {
        assert!(is_ipv4("1.2.3.4"));
        assert!(!is_ipv4("::1"));
        assert!(is_ipv6("2001:db8::1"));
        assert!(!is_ipv6("1.2.3.4"));
    }

    #[test]
    fn name_checks() {
        assert!(is_valid_name("_acme-challenge"));
        assert!(is_valid_name("mail.example.com."));
        assert!(is_valid_name("@"));
        assert!(!is_valid_name("bad space"));
    }
}
