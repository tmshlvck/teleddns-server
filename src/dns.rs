//! Shared DNS helpers: FQDN normalization, longest-origin zone/label resolution, and value
//! validation used by the DDNS endpoint, the native API, and the Cloudflare facade.

use crate::model::zone;
use relativelylight::validate;
use sea_orm::{ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter};

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

/// Is this a syntactically valid IPv4 literal? (thin wrapper over the shared validator, used by the
/// DDNS endpoint to pick the address family.)
pub fn is_ipv4(s: &str) -> bool {
    validate::ipv4(s).is_ok()
}

/// Is this a syntactically valid IPv6 literal?
pub fn is_ipv6(s: &str) -> bool {
    validate::ipv6(s).is_ok()
}

/// DNS field validators — typed predicates (`Result<(), String>`) shared by **every** write surface:
/// the native API, the Cloudflare facade (via the native path), and the admin CRUD forms (wired with
/// [`MetaField::validate_str`/`validate_int`](relativelylight::crud::seaorm::MetaField)). Built on
/// [`relativelylight::validate`]; the messages are user-facing (the API wraps them in
/// `{ "error": … }`, the admin renders them under the field).
///
/// RFC-reasonable, with a few corners cut for uncommon cases — numeric enums are range-checked to
/// their wire width (octet / 16-bit) rather than to the exact IANA-registered set, so a
/// not-yet-known-here algorithm number is still accepted.
pub mod check {
    use relativelylight::validate as rl;

    /// A dotted-quad IPv4 address (A record).
    pub fn ipv4(s: &str) -> Result<(), String> {
        rl::ipv4(s).map_err(|_| "must be an IPv4 address, e.g. 192.0.2.1".into())
    }

    /// An IPv6 address (AAAA record).
    pub fn ipv6(s: &str) -> Result<(), String> {
        rl::ipv6(s).map_err(|_| "must be an IPv6 address, e.g. 2001:db8::1".into())
    }

    /// A non-empty rdata string (e.g. the CAA value: a CA domain or an iodef URL).
    pub fn non_empty_value(s: &str) -> Result<(), String> {
        rl::non_empty(s).map_err(|_| "must not be empty".into())
    }

    /// A record TTL: RFC 2181 §8 — a 32-bit value with the top bit clear, i.e. `0..=2147483647`.
    pub fn ttl(n: i64) -> Result<(), String> {
        rl::int_range(0, 2_147_483_647)(n).map_err(|_| "TTL must be 0..2147483647 seconds".into())
    }

    /// An SOA interval (refresh / retry / expire / minimum): a non-negative 32-bit seconds count.
    pub fn soa_interval(n: i64) -> Result<(), String> {
        rl::int_range(0, 2_147_483_647)(n).map_err(|_| "must be 0..2147483647 seconds".into())
    }

    /// An SOA serial: a 32-bit unsigned integer (RFC 1982 serial-number arithmetic).
    pub fn serial(n: i64) -> Result<(), String> {
        rl::int_range(0, 4_294_967_295)(n).map_err(|_| "serial must be 0..4294967295".into())
    }

    /// A single-octet numeric field (`0..=255`) — CAA flag, SSHFP algorithm/hash-type, TLSA
    /// usage/selector/matching-type, DS/DNSKEY algorithm, DS digest-type.
    pub fn octet(n: i64) -> Result<(), String> {
        rl::int_range(0, 255)(n).map_err(|_| "must be 0..255".into())
    }

    /// A 16-bit numeric field (`0..=65535`) — MX/SRV/NAPTR priorities and friends, SRV port, DS key
    /// tag, DNSKEY flags.
    pub fn u16(n: i64) -> Result<(), String> {
        rl::int_range(0, 65535)(n).map_err(|_| "must be 0..65535".into())
    }

    /// The DNSKEY protocol octet — RFC 4034 fixes it at 3.
    pub fn dnskey_protocol(n: i64) -> Result<(), String> {
        if n == 3 {
            Ok(())
        } else {
            Err("must be 3 (RFC 4034)".into())
        }
    }

    /// An owner name *relative to the zone*: the apex `@` (or empty), otherwise a DNS name — LDH +
    /// underscore labels, an optional leading `*` wildcard, an optional trailing dot.
    pub fn record_label(s: &str) -> Result<(), String> {
        if s.is_empty() || s == "@" {
            return Ok(());
        }
        rl::dns_name(s).map_err(|_| format!("invalid record name: {s:?}"))
    }

    /// An rdata *target* hostname (NS / PTR / CNAME / MX / SRV target, NAPTR replacement). Accepts a
    /// lone `.` (the root — SRV/NAPTR "no service"); otherwise a DNS name (absolute or relative).
    pub fn target_name(s: &str) -> Result<(), String> {
        if s == "." {
            return Ok(());
        }
        rl::dns_name(s).map_err(|_| format!("must be a valid hostname: {s:?}"))
    }

    /// A zone origin — a DNS name (normalized to an absolute FQDN before storage).
    pub fn zone_origin(s: &str) -> Result<(), String> {
        rl::dns_name(s).map_err(|_| format!("invalid zone origin: {s:?}"))
    }

    /// A CAA property tag: `issue`, `issuewild`, or `iodef` (case-insensitive).
    pub fn caa_tag(s: &str) -> Result<(), String> {
        rl::one_of_ci(&["issue", "issuewild", "iodef"])(s)
            .map_err(|_| "must be issue, issuewild, or iodef".into())
    }

    /// Hex-encoded rdata (SSHFP fingerprint, TLSA certificate data, DS digest).
    pub fn hex(s: &str) -> Result<(), String> {
        rl::hex(s).map_err(|_| "must be a hex string (an even number of hex digits)".into())
    }

    /// Base64-encoded rdata (DNSKEY public key).
    pub fn base64(s: &str) -> Result<(), String> {
        rl::base64(s).map_err(|_| "must be base64-encoded".into())
    }

    /// A TXT value — free-form, but bounded to a sane maximum.
    pub fn txt(s: &str) -> Result<(), String> {
        rl::length_bytes(0, 65535)(s).map_err(|_| "TXT value is too long".into())
    }
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
    fn field_checks() {
        // Names / labels.
        assert!(check::record_label("@").is_ok());
        assert!(check::record_label("_acme-challenge").is_ok());
        assert!(check::record_label("*").is_ok());
        assert!(check::record_label("bad space").is_err());
        assert!(check::target_name("mail.example.com.").is_ok());
        assert!(check::target_name(".").is_ok()); // SRV "no service"
        assert!(check::target_name("bad space").is_err());

        // Numeric ranges.
        assert!(check::ttl(3600).is_ok() && check::ttl(-1).is_err() && check::ttl(1 << 31).is_err());
        assert!(check::octet(255).is_ok() && check::octet(256).is_err());
        assert!(check::u16(65535).is_ok() && check::u16(70000).is_err());
        assert!(check::dnskey_protocol(3).is_ok() && check::dnskey_protocol(2).is_err());

        // Encodings / enums.
        assert!(check::caa_tag("ISSUE").is_ok() && check::caa_tag("bogus").is_err());
        assert!(check::hex("deadbeef").is_ok() && check::hex("xyz").is_err());
        assert!(check::base64("aGVsbG8=").is_ok() && check::base64("not b64!!").is_err());
    }
}
