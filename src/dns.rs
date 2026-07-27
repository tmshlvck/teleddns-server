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

/// The stored form of a record label. DNS names are case-insensitive (RFC 4343) but our lookups are
/// exact string matches — a request always arrives lower-cased (via [`normalize_fqdn`]), so anything
/// written in another case would simply never match: a `Thermostat` grant silently authorizes nothing,
/// and a `WWW` record is a second row beside the `www` a DDNS client writes, rendering two records at
/// one name. So every write path canonicalizes here instead of every read path guessing.
pub fn normalize_label(s: &str) -> String {
    s.trim().to_ascii_lowercase()
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
/// the DDNS endpoint, the native API, the Cloudflare facade (via the native path), `admin import`,
/// and the admin CRUD forms (wired with
/// [`MetaField::validate_str`/`validate_int`](relativelylight::crud::seaorm::MetaField)). Built on
/// [`relativelylight::validate`]; the messages are user-facing (the API wraps them in
/// `{ "error": … }`, the admin renders them under the field).
///
/// The bar every name/string predicate has to clear is the **rendered zone file**: a value carrying
/// whitespace, a newline, a comma, an over-long label or a control character breaks the
/// `<owner> <ttl> IN <TYPE> <rdata>` line, and Knot then rejects the whole zone on reload. So no
/// write path may store one — which is why all of them funnel through the two primitives below
/// ([`dns_label`] and [`fqdn_hostname`]) instead of validating names ad-hoc.
///
/// RFC-reasonable, with a few corners cut for uncommon cases — numeric enums are range-checked to
/// their wire width (octet / 16-bit) rather than to the exact IANA-registered set, so a
/// not-yet-known-here algorithm number is still accepted.
pub mod check {
    use relativelylight::validate as rl;

    // --- name primitives: every name-shaped field below is composed from these two ---

    /// **One DNS label** — 1–63 octets of letters, digits and `-` (never first or last), plus `_`
    /// for service labels (`_dmarc`, `_acme-challenge`). No dot and no `*`: a dotted sequence and
    /// the wildcard are name-level concerns, handled by the callers below.
    pub fn dns_label(s: &str) -> Result<(), String> {
        if s == "*" || s.contains('.') || rl::dns_name(s).is_err() {
            return Err(format!(
                "invalid DNS label {s:?} (1–63 characters: letters, digits, '-', '_')"
            ));
        }
        Ok(())
    }

    /// **A fully-qualified hostname** — `label(.label)*` with the trailing dot **required** and at
    /// most 253 octets without it. Neither the bare root (`.`) nor a wildcard qualifies; every
    /// label must pass [`dns_label`].
    pub fn fqdn_hostname(s: &str) -> Result<(), String> {
        let Some(rest) = s.strip_suffix('.') else {
            return Err(format!("must be fully-qualified (end it with a dot): {s:?}"));
        };
        labels(rest, false)
    }

    /// The shared label-sequence walk behind every name check: split on dots and validate each
    /// label, optionally allowing a lone `*` as the left-most one. `s` must have any trailing dot
    /// already stripped.
    fn labels(s: &str, wildcard: bool) -> Result<(), String> {
        if s.is_empty() || s.len() > 253 {
            return Err(format!("must be 1–253 characters: {s:?}"));
        }
        for (i, l) in s.split('.').enumerate() {
            if wildcard && i == 0 && l == "*" {
                continue; // *.example.com — a wildcard owner name
            }
            dns_label(l)?;
        }
        Ok(())
    }

    /// A hostname that may be written relative to the zone or fully-qualified (trailing dot
    /// optional) — no wildcard. The form that rdata targets and the SOA MNAME/RNAME take.
    pub fn hostname(s: &str) -> Result<(), String> {
        labels(s.strip_suffix('.').unwrap_or(s), false)
    }

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

    /// An owner name *relative to the zone*: the apex `@` (or empty), otherwise a label sequence
    /// with an optional leading `*` wildcard and an optional trailing dot. Used for the `label`
    /// column of every RR table (and the record-grant scope).
    pub fn record_label(s: &str) -> Result<(), String> {
        if s.is_empty() || s == "@" {
            return Ok(());
        }
        labels(s.strip_suffix('.').unwrap_or(s), true).map_err(|e| format!("invalid record name: {e}"))
    }

    /// A DDNS `hostname` query parameter — the same grammar as a [`record_label`] (a wildcard owner
    /// is legal), but the name is absolute-ish and never `@`. Whether it maps to a served zone is
    /// decided later by [`resolve_zone`](super::resolve_zone); this only rejects syntactic junk,
    /// notably the comma-separated multi-host form of the original dyn API (which teleddns does not
    /// implement) — without it, `a.example.com,b.example.com` would resolve to the nonsense label
    /// `a.example.com,b` and silently create a record there.
    pub fn ddns_hostname(s: &str) -> Result<(), String> {
        labels(s.strip_suffix('.').unwrap_or(s), true).map_err(|e| format!("invalid hostname: {e}"))
    }

    /// An rdata *target* hostname (NS / PTR / CNAME / MX / SRV target, NAPTR replacement, SOA
    /// MNAME/RNAME). Accepts a lone `.` (the root — SRV/NAPTR "no service"); otherwise a
    /// [`hostname`], absolute or relative to the zone. A wildcard is *not* accepted: it means
    /// nothing in rdata.
    pub fn target_name(s: &str) -> Result<(), String> {
        if s == "." {
            return Ok(());
        }
        hostname(s).map_err(|e| format!("must be a valid hostname: {e}"))
    }

    /// A zone origin — a [`fqdn_hostname`] (trailing dot required). The native API/zoneimport paths
    /// also call `normalize_fqdn` before this runs, so a missing dot never reaches them; the admin
    /// CRUD form validates the raw field with only this, so it must enforce the dot itself.
    pub fn zone_origin(s: &str) -> Result<(), String> {
        fqdn_hostname(s).map_err(|e| format!("invalid zone origin (e.g. example.com.): {e}"))
    }

    /// A zone-file **character-string** — the unit the renderer emits inside quotes (the CAA value,
    /// the NAPTR text fields): at most 255 octets (the wire limit for one string; the renderer does
    /// not split these) and free of control characters. Empty is allowed here; fields that also
    /// require content pair it with [`non_empty_value`].
    pub fn char_string(s: &str) -> Result<(), String> {
        if s.len() > 255 {
            return Err("must be at most 255 characters".into());
        }
        if s.chars().any(char::is_control) {
            return Err("must not contain control characters (newlines, tabs, …)".into());
        }
        Ok(())
    }

    /// The CAA value — a non-empty character-string (a CA domain for `issue`/`issuewild`, a
    /// `mailto:`/URL for `iodef`).
    pub fn caa_value(s: &str) -> Result<(), String> {
        non_empty_value(s)?;
        char_string(s)
    }

    /// NAPTR flags (RFC 3403) — letters/digits only, e.g. `U`, `S`, `A`, `P`; empty for a
    /// non-terminal rule.
    pub fn naptr_flags(s: &str) -> Result<(), String> {
        if s.len() > 15 || !s.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err("must be letters/digits only, e.g. U, S, A or P (empty for a non-terminal rule)".into());
        }
        Ok(())
    }

    /// The NAPTR service field (RFC 3403), e.g. `E2U+sip` — a character-string with no spaces (a
    /// service tag never has any, and a stray space would split the rendered rdata).
    pub fn naptr_service(s: &str) -> Result<(), String> {
        char_string(s)?;
        if s.chars().any(char::is_whitespace) {
            return Err("must not contain spaces, e.g. E2U+sip".into());
        }
        Ok(())
    }

    /// The NAPTR substitution expression, e.g. `!^.*$!sip:info@example.com!` — a character-string
    /// (empty when `replacement` is used instead). Quoted by the renderer, so punctuation is fine.
    pub fn naptr_regexp(s: &str) -> Result<(), String> {
        char_string(s)
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

    /// A TXT value — free-form (any byte: the renderer escapes what needs escaping) and bounded to
    /// a sane maximum. Unlike the other quoted fields it is *not* capped at 255: long values (a DKIM
    /// key) are legal and the renderer splits them into 255-octet character-strings.
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

    /// The two primitives every name-shaped field is built from.
    #[test]
    fn name_primitives() {
        // dns_label: one label, nothing dotted, no wildcard.
        assert!(check::dns_label("www").is_ok());
        assert!(check::dns_label("_dmarc").is_ok());
        assert!(check::dns_label("xn--bcher-kva").is_ok());
        assert!(check::dns_label("a".repeat(63).as_str()).is_ok());
        for bad in ["", "a".repeat(64).as_str(), "-lead", "trail-", "a.b", "*", "sp ace", "a,b", "a\nb", "hé"] {
            assert!(check::dns_label(bad).is_err(), "{bad:?} must be rejected");
        }
        // fqdn_hostname: trailing dot required, no root, no wildcard, labels as above.
        assert!(check::fqdn_hostname("mail.example.com.").is_ok());
        assert!(check::fqdn_hostname("_acme-challenge.example.com.").is_ok());
        for bad in ["mail.example.com", ".", "*.example.com.", "a..b.", "a b.example.com."] {
            assert!(check::fqdn_hostname(bad).is_err(), "{bad:?} must be rejected");
        }
        // hostname: relative or absolute, still no wildcard.
        assert!(check::hostname("mail.example.com.").is_ok());
        assert!(check::hostname("mail").is_ok());
        assert!(check::hostname("*.example.com.").is_err());
    }

    #[test]
    fn field_checks() {
        // Names / labels — all composed from dns_label / fqdn_hostname.
        assert!(check::record_label("@").is_ok());
        assert!(check::record_label("").is_ok());
        assert!(check::record_label("_acme-challenge").is_ok());
        assert!(check::record_label("*").is_ok());
        assert!(check::record_label("*.dyn").is_ok());
        assert!(check::record_label("a.b.c").is_ok());
        assert!(check::record_label("bad space").is_err());
        assert!(check::record_label("a.*.b").is_err()); // wildcard only left-most
        assert!(check::target_name("mail.example.com.").is_ok());
        assert!(check::target_name(".").is_ok()); // SRV "no service"
        assert!(check::target_name("bad space").is_err());
        assert!(check::target_name("*.example.com.").is_err()); // meaningless in rdata
        assert!(check::zone_origin("example.com.").is_ok());
        assert!(check::zone_origin("example.com").is_err()); // missing trailing dot
        assert!(check::zone_origin("exa mple.com.").is_err());
        assert!(check::ddns_hostname("host.example.com").is_ok());
        assert!(check::ddns_hostname("a.example.com,b.example.com").is_err());

        // Character-strings: bounded to one wire string, no control characters.
        assert!(check::char_string("letsencrypt.org").is_ok());
        assert!(check::char_string("").is_ok());
        assert!(check::char_string(&"x".repeat(255)).is_ok());
        assert!(check::char_string(&"x".repeat(256)).is_err());
        assert!(check::char_string("line\nbreak").is_err());
        assert!(check::caa_value("letsencrypt.org").is_ok() && check::caa_value("").is_err());
        // A long TXT is allowed (the renderer splits it); a long CAA value is not.
        assert!(check::txt(&"x".repeat(1024)).is_ok());

        // NAPTR text fields.
        assert!(check::naptr_flags("U").is_ok() && check::naptr_flags("").is_ok());
        assert!(check::naptr_flags("U S").is_err() && check::naptr_flags("!").is_err());
        assert!(check::naptr_service("E2U+sip").is_ok() && check::naptr_service("E2U sip").is_err());
        assert!(check::naptr_regexp("!^.*$!sip:info@example.com!").is_ok());
        assert!(check::naptr_regexp("bad\tregexp").is_err());

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
