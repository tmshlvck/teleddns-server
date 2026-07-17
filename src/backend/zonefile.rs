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
        out.push_str(&line(&r.label, r.ttl, "TXT", &quote(&r.value)));
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

/// Quote a character string for zone-file rdata (TXT, CAA value, NAPTR text fields).
fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(quote("hello"), "\"hello\"");
        assert_eq!(quote(r#"a"b"#), "\"a\\\"b\"");
    }

    #[test]
    fn rr_line_format() {
        assert_eq!(line("www", 60, "A", "1.2.3.4"), "www 60 IN A 1.2.3.4\n");
        assert_eq!(line("@", 3600, "MX", "10 mail.example.com."), "@ 3600 IN MX 10 mail.example.com.\n");
    }
}
