//! `admin import`: bulk-load a BIND zone file into the DB. A pragmatic line-based parser handling
//! `$ORIGIN`/`$TTL`, `@`, relative/absolute owners, owner inheritance, comments, and the SOA paren
//! block (skipped — we own the SOA). Records go through the same validation + push path as the API.

use crate::api::record_view;
use crate::config::Config;
use crate::dns;
use crate::model::{now, rr, zone};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter};
use serde_json::json;

/// Import records from a BIND zone file (or stdin when `path == "-"`).
pub async fn import(
    cfg: Config,
    path: &str,
    replace: bool,
    origin_override: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let text = if path == "-" {
        use std::io::Read;
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        s
    } else {
        std::fs::read_to_string(path)?
    };

    let db = crate::db::connect(&cfg.db_dsn).await?;
    relativelylight::auth::migrate(&db).await?;
    crate::model::migrate(&db).await?;

    let parsed = parse(&text, origin_override)?;
    let origin = parsed.origin;
    println!("importing {} records into {origin}", parsed.records.len());

    // Ensure the zone exists.
    let z = match zone::Entity::find().filter(zone::Column::Origin.eq(&origin)).one(&db).await? {
        Some(z) => z,
        None => zone::Model::new_defaults(&origin, cfg.default_ttl as i32).insert(&db).await?,
    };

    if replace {
        // Remove every RR of the zone first.
        macro_rules! d {
            ($ent:path, $col:path) => {
                <$ent>::delete_many().filter($col.eq(z.id)).exec(&db).await?;
            };
        }
        d!(rr::a::Entity, rr::a::Column::ZoneId);
        d!(rr::aaaa::Entity, rr::aaaa::Column::ZoneId);
        d!(rr::ns::Entity, rr::ns::Column::ZoneId);
        d!(rr::ptr::Entity, rr::ptr::Column::ZoneId);
        d!(rr::cname::Entity, rr::cname::Column::ZoneId);
        d!(rr::txt::Entity, rr::txt::Column::ZoneId);
        d!(rr::mx::Entity, rr::mx::Column::ZoneId);
        d!(rr::srv::Entity, rr::srv::Column::ZoneId);
        d!(rr::caa::Entity, rr::caa::Column::ZoneId);
    }

    let mut ok = 0usize;
    let mut skipped = 0usize;
    for (i, rec) in parsed.records.iter().enumerate() {
        match record_view::create_record(&db, z.id, cfg.default_ttl as i32, rec).await {
            Ok(_) => ok += 1,
            Err(e) => {
                skipped += 1;
                eprintln!("record {}: skipped ({:?})", i + 1, e);
            }
        }
    }
    // Ensure at least the push is enqueued even if create hooks coalesced.
    crate::sync::enqueue(&db, &origin).await.ok();
    let _ = now();
    println!("imported {ok} records, skipped {skipped}");
    Ok(())
}

struct Parsed {
    origin: String,
    records: Vec<serde_json::Value>,
}

/// Parse a zone file into native record bodies.
fn parse(text: &str, origin_override: Option<&str>) -> Result<Parsed, String> {
    let mut origin = origin_override.map(dns::normalize_fqdn);
    let mut default_ttl: Option<i32> = None;
    let mut last_owner: Option<String> = None;
    let mut records: Vec<serde_json::Value> = Vec::new();
    let mut paren_depth = 0i32;

    for raw in text.lines() {
        // Strip comments (naive; does not handle ';' inside quoted strings).
        let line = match raw.find(';') {
            Some(i) => &raw[..i],
            None => raw,
        };
        if paren_depth > 0 {
            paren_depth += count(line, '(') - count(line, ')');
            continue; // inside a multi-line block (SOA); skip
        }
        let trimmed = line.trim_end();
        if trimmed.trim().is_empty() {
            continue;
        }

        if let Some(rest) = trimmed.trim().strip_prefix("$ORIGIN") {
            origin = Some(dns::normalize_fqdn(rest.trim()));
            continue;
        }
        if let Some(rest) = trimmed.trim().strip_prefix("$TTL") {
            default_ttl = rest.trim().parse().ok();
            continue;
        }

        // Owner: present if the line does not start with whitespace.
        let starts_indented = line.starts_with(char::is_whitespace);
        let mut toks: Vec<&str> = trimmed.split_whitespace().collect();
        if toks.is_empty() {
            continue;
        }
        let owner = if starts_indented {
            last_owner.clone().ok_or("record without an owner and no previous owner")?
        } else {
            let o = toks.remove(0).to_string();
            last_owner = Some(o.clone());
            o
        };

        // Optional TTL and class, then the type.
        let mut ttl = default_ttl;
        while let Some(first) = toks.first() {
            if let Ok(n) = first.parse::<i32>() {
                ttl = Some(n);
                toks.remove(0);
            } else if first.eq_ignore_ascii_case("IN") {
                toks.remove(0);
            } else {
                break;
            }
        }
        let Some(rtype) = toks.first().map(|s| s.to_ascii_uppercase()) else {
            continue;
        };
        toks.remove(0);

        let org = origin.clone().ok_or("no $ORIGIN and no --origin given")?;
        if rtype == "SOA" {
            // Enter paren-block skipping if the SOA spans lines.
            paren_depth += count(line, '(') - count(line, ')');
            continue;
        }
        let label = owner_to_label(&owner, &org);
        let rdata = &toks;
        if let Some(rec) = record_body(&rtype, &label, ttl, rdata) {
            records.push(rec);
        }
    }

    let origin = origin.ok_or("could not determine origin (no $ORIGIN, SOA, or --origin)")?;
    Ok(Parsed { origin, records })
}

/// Map an owner token to a zone-relative label.
fn owner_to_label(owner: &str, origin: &str) -> String {
    if owner == "@" {
        "@".into()
    } else if owner.ends_with('.') {
        dns::label_in_zone(owner, origin)
    } else {
        owner.to_string() // already relative to $ORIGIN
    }
}

/// Build a native record body for a supported type (None → unsupported, skip).
fn record_body(
    rtype: &str,
    label: &str,
    ttl: Option<i32>,
    rdata: &[&str],
) -> Option<serde_json::Value> {
    let mut o = json!({ "type": rtype, "name": label });
    if let Some(t) = ttl {
        o["ttl"] = json!(t);
    }
    match rtype {
        "A" | "AAAA" | "NS" | "CNAME" | "PTR" => {
            o["value"] = json!(rdata.first()?.to_string());
        }
        "TXT" => {
            o["value"] = json!(unquote(&rdata.join(" ")));
        }
        "MX" => {
            o["priority"] = json!(rdata.first()?.parse::<i64>().ok()?);
            o["value"] = json!(rdata.get(1)?.to_string());
        }
        "SRV" => {
            o["priority"] = json!(rdata.first()?.parse::<i64>().ok()?);
            o["weight"] = json!(rdata.get(1)?.parse::<i64>().ok()?);
            o["port"] = json!(rdata.get(2)?.parse::<i64>().ok()?);
            o["value"] = json!(rdata.get(3)?.to_string());
        }
        "CAA" => {
            o["flag"] = json!(rdata.first()?.parse::<i64>().ok()?);
            o["tag"] = json!(rdata.get(1)?.to_string());
            o["value"] = json!(unquote(&rdata[2..].join(" ")));
        }
        other => {
            eprintln!("skipping unsupported type {other} at {label}");
            return None;
        }
    }
    Some(o)
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    s.strip_prefix('"').and_then(|s| s.strip_suffix('"')).unwrap_or(s).to_string()
}

fn count(s: &str, c: char) -> i32 {
    s.chars().filter(|x| *x == c).count() as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_records() {
        let z = "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns hostmaster 1 2 3 4 5\n\
                 www IN A 1.2.3.4\n    IN AAAA 2001:db8::1\n@ IN MX 10 mail.example.com.\n";
        let p = parse(z, None).unwrap();
        assert_eq!(p.origin, "example.com.");
        assert_eq!(p.records.len(), 3);
        assert_eq!(p.records[0]["type"], "A");
        assert_eq!(p.records[0]["name"], "www");
        assert_eq!(p.records[1]["type"], "AAAA");
        assert_eq!(p.records[1]["name"], "www"); // inherited owner
        assert_eq!(p.records[2]["type"], "MX");
        assert_eq!(p.records[2]["priority"], 10);
    }

    #[test]
    fn skips_multiline_soa() {
        let z = "$ORIGIN example.com.\n@ IN SOA ns hostmaster (\n 1 ; serial\n 2 3 4 5 )\nwww IN A 1.1.1.1\n";
        let p = parse(z, None).unwrap();
        assert_eq!(p.records.len(), 1);
        assert_eq!(p.records[0]["type"], "A");
    }
}
