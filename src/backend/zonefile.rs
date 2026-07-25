//! Byte-faithful BIND zone-file rendering from the DB. The output must pass Knot's `kzonecheck`. The
//! SOA header comes from the zone row; every RR is rendered from its per-type table.

use crate::model::{rr, zone};
use sea_orm::{ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter, QueryOrder};

/// Render the full zone file for `zone` (SOA + $ORIGIN/$TTL header, then every RR).
pub async fn render_zone<C: ConnectionTrait>(db: &C, zone: &zone::Model) -> Result<String, DbErr> {
    let mut out = String::new();
    out.push_str(&format!("$ORIGIN {}\n", zone.origin));
    out.push_str(&format!("$TTL {}\n", zone.ttl));
    out.push_str(&format!(
        "@ {ttl} IN SOA {mname} {rname} ( {serial} {refresh} {retry} {expire} {minimum} )\n",
        ttl = zone.ttl,
        mname = zone.mname,
        rname = zone.rname,
        serial = zone.serial,
        refresh = zone.refresh,
        retry = zone.retry,
        expire = zone.expire,
        minimum = zone.minimum,
    ));

    let zid = zone.id;
    // For each RR type: fetch the zone's rows (label-ordered for stable output) and render each via
    // `$body`, with the row bound to the caller-named ident `$r` (so macro hygiene lets the body see
    // it).
    macro_rules! each {
        ($ent:path, $zonecol:path, $labelcol:path, $r:ident, $body:block) => {{
            let rows = <$ent>::find()
                .filter($zonecol.eq(zid))
                .order_by_asc($labelcol)
                .all(db)
                .await?;
            for $r in &rows $body
        }};
    }

    each!(rr::a::Entity, rr::a::Column::ZoneId, rr::a::Column::Label, r, {
        out.push_str(&line(&r.label, r.ttl, "A", &r.value));
    });
    each!(rr::aaaa::Entity, rr::aaaa::Column::ZoneId, rr::aaaa::Column::Label, r, {
        out.push_str(&line(&r.label, r.ttl, "AAAA", &r.value));
    });
    each!(rr::ns::Entity, rr::ns::Column::ZoneId, rr::ns::Column::Label, r, {
        out.push_str(&line(&r.label, r.ttl, "NS", &r.value));
    });
    each!(rr::ptr::Entity, rr::ptr::Column::ZoneId, rr::ptr::Column::Label, r, {
        out.push_str(&line(&r.label, r.ttl, "PTR", &r.value));
    });
    each!(rr::cname::Entity, rr::cname::Column::ZoneId, rr::cname::Column::Label, r, {
        out.push_str(&line(&r.label, r.ttl, "CNAME", &r.value));
    });
    each!(rr::txt::Entity, rr::txt::Column::ZoneId, rr::txt::Column::Label, r, {
        out.push_str(&line(&r.label, r.ttl, "TXT", &char_strings(&r.value)));
    });
    each!(rr::mx::Entity, rr::mx::Column::ZoneId, rr::mx::Column::Label, r, {
        out.push_str(&line(&r.label, r.ttl, "MX", &format!("{} {}", r.priority, r.value)));
    });
    each!(rr::srv::Entity, rr::srv::Column::ZoneId, rr::srv::Column::Label, r, {
        out.push_str(&line(
            &r.label,
            r.ttl,
            "SRV",
            &format!("{} {} {} {}", r.priority, r.weight, r.port, r.value),
        ));
    });
    each!(rr::caa::Entity, rr::caa::Column::ZoneId, rr::caa::Column::Label, r, {
        out.push_str(&line(&r.label, r.ttl, "CAA", &format!("{} {} {}", r.flag, r.tag, quote(&r.value))));
    });
    each!(rr::sshfp::Entity, rr::sshfp::Column::ZoneId, rr::sshfp::Column::Label, r, {
        out.push_str(&line(
            &r.label,
            r.ttl,
            "SSHFP",
            &format!("{} {} {}", r.algorithm, r.hash_type, r.fingerprint),
        ));
    });
    each!(rr::tlsa::Entity, rr::tlsa::Column::ZoneId, rr::tlsa::Column::Label, r, {
        out.push_str(&line(
            &r.label,
            r.ttl,
            "TLSA",
            &format!("{} {} {} {}", r.cert_usage, r.selector, r.matching_type, r.cert_data),
        ));
    });
    each!(rr::dnskey::Entity, rr::dnskey::Column::ZoneId, rr::dnskey::Column::Label, r, {
        out.push_str(&line(
            &r.label,
            r.ttl,
            "DNSKEY",
            &format!("{} {} {} {}", r.flags, r.protocol, r.algorithm, r.public_key),
        ));
    });
    each!(rr::ds::Entity, rr::ds::Column::ZoneId, rr::ds::Column::Label, r, {
        out.push_str(&line(
            &r.label,
            r.ttl,
            "DS",
            &format!("{} {} {} {}", r.key_tag, r.algorithm, r.digest_type, r.digest),
        ));
    });
    each!(rr::naptr::Entity, rr::naptr::Column::ZoneId, rr::naptr::Column::Label, r, {
        out.push_str(&line(
            &r.label,
            r.ttl,
            "NAPTR",
            &format!(
                "{} {} {} {} {} {}",
                r.order,
                r.preference,
                quote(&r.flags),
                quote(&r.service),
                quote(&r.regexp),
                r.replacement
            ),
        ));
    });

    Ok(out)
}

/// One RR line: `<label> <ttl> IN <TYPE> <rdata>`.
fn line(label: &str, ttl: i32, rtype: &str, rdata: &str) -> String {
    format!("{label} {ttl} IN {rtype} {rdata}\n")
}

/// Quote one character-string for zone-file rdata (CAA value, NAPTR text fields — `dns::check`
/// bounds those to the 255-octet wire limit). `"` and `\` are escaped and every non-printable byte
/// becomes a `\DDD` decimal escape, so no stored byte can break out of the line.
fn quote(s: &str) -> String {
    quote_bytes(s.as_bytes())
}

fn quote_bytes(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len() + 2);
    out.push('"');
    for &c in b {
        match c {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(c as char),
            _ => out.push_str(&format!("\\{c:03}")), // control / non-ASCII → \DDD
        }
    }
    out.push('"');
    out
}

/// Render a TXT value as one or more character-strings. A single string may carry at most 255
/// octets, so a longer value (a DKIM key, typically) is split into adjacent quoted strings —
/// `"part1" "part2"`, which resolvers concatenate. Emitting one 300-octet string instead would make
/// Knot reject the zone.
fn char_strings(s: &str) -> String {
    let b = s.as_bytes();
    if b.len() <= 255 {
        return quote_bytes(b);
    }
    b.chunks(255).map(quote_bytes).collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(quote("hello"), "\"hello\"");
        assert_eq!(quote(r#"a"b"#), "\"a\\\"b\"");
        assert_eq!(quote(r"a\b"), r#""a\\b""#);
        // Anything non-printable becomes a \DDD escape rather than a literal byte in the line.
        assert_eq!(quote("a\nb"), r#""a\010b""#);
        assert_eq!(quote("é"), r#""\195\169""#);
    }

    /// A TXT value longer than one wire string is split into adjacent 255-octet strings (DKIM keys).
    #[test]
    fn long_txt_is_split() {
        let short = "v=spf1 -all";
        assert_eq!(char_strings(short), format!("\"{short}\""));
        let long = "x".repeat(600);
        let rendered = char_strings(&long);
        let parts: Vec<&str> = rendered.split(' ').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].len(), 255 + 2); // 255 payload + the two quotes
        assert_eq!(parts[2], format!("\"{}\"", "x".repeat(90)));
        // The payload survives the round trip unchanged.
        let payload: String = parts.iter().map(|p| p.trim_matches('"')).collect();
        assert_eq!(payload, long);
    }

    #[test]
    fn rr_line_format() {
        assert_eq!(line("www", 60, "A", "1.2.3.4"), "www 60 IN A 1.2.3.4\n");
        assert_eq!(line("@", 3600, "MX", "10 mail.example.com."), "@ 3600 IN MX 10 mail.example.com.\n");
    }
}
