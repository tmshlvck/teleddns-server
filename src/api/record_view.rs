//! The unified, type-discriminated record view over the per-type RR tables. A record is
//! `{id, type, name, ttl, …rdata}` with an opaque, type-prefixed id (`a-12`, `mx-7`). Reads are
//! uniform (serialize the row, rename `label`→`name`, prefix the id); writes dispatch on `type` and
//! build the right per-type row, with per-type validation. Every write goes through SeaORM
//! ActiveModels, so the after_save hook bumps the serial + enqueues a push.

use crate::dns;
use crate::model::rr;
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::{ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter};
use serde_json::{json, Map, Value};

/// A write/lookup error, mapped to HTTP by the handlers.
#[derive(Debug)]
pub enum ApiError {
    NotFound,
    BadType(String),
    Validation(String),
    Db(DbErr),
}

impl From<DbErr> for ApiError {
    fn from(e: DbErr) -> Self {
        ApiError::Db(e)
    }
}

/// Map a type tag (`"A"`) to its id prefix (`"a"`), and back.
fn type_to_prefix(t: &str) -> Option<&'static str> {
    Some(match t.to_ascii_uppercase().as_str() {
        "A" => "a",
        "AAAA" => "aaaa",
        "NS" => "ns",
        "PTR" => "ptr",
        "CNAME" => "cname",
        "TXT" => "txt",
        "MX" => "mx",
        "SRV" => "srv",
        "CAA" => "caa",
        "SSHFP" => "sshfp",
        "TLSA" => "tlsa",
        "DNSKEY" => "dnskey",
        "DS" => "ds",
        "NAPTR" => "naptr",
        _ => return None,
    })
}

fn prefix_to_type(p: &str) -> Option<&'static str> {
    Some(match p {
        "a" => "A",
        "aaaa" => "AAAA",
        "ns" => "NS",
        "ptr" => "PTR",
        "cname" => "CNAME",
        "txt" => "TXT",
        "mx" => "MX",
        "srv" => "SRV",
        "caa" => "CAA",
        "sshfp" => "SSHFP",
        "tlsa" => "TLSA",
        "dnskey" => "DNSKEY",
        "ds" => "DS",
        "naptr" => "NAPTR",
        _ => return None,
    })
}

/// Split an opaque record id `"mx-7"` into `("mx", 7)`.
fn split_id(rrid: &str) -> Option<(String, i32)> {
    let (p, n) = rrid.rsplit_once('-')?;
    let id: i32 = n.parse().ok()?;
    Some((p.to_string(), id))
}

/// Whether A/AAAA (the DDNS-touchable set); used by the handler to pick the required level.
pub fn is_addr_type(t: &str) -> bool {
    matches!(t.to_ascii_uppercase().as_str(), "A" | "AAAA")
}

/// The type tag of an opaque id (for the level check on get/update/delete).
pub fn type_of_id(rrid: &str) -> Option<&'static str> {
    let (p, _) = split_id(rrid)?;
    prefix_to_type(&p)
}

/// Convert a serialized row into the unified view (`label`→`name`, prefixed id, `type` added).
fn to_view(row: Value, prefix: &str, typ: &str) -> Value {
    let mut o: Map<String, Value> = row.as_object().cloned().unwrap_or_default();
    let id = o.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    o.remove("zone_id");
    let name = o.remove("label").unwrap_or(Value::Null);
    o.insert("id".into(), json!(format!("{prefix}-{id}")));
    o.insert("type".into(), json!(typ));
    o.insert("name".into(), name);
    Value::Object(o)
}

// --- read side (uniform across all types) ---

/// Collect all views for a zone, optionally filtered by type and name, sorted by (type, name).
pub async fn collect_views(
    db: &DatabaseConnection,
    zone_id: i32,
    type_filter: Option<&str>,
    name_filter: Option<&str>,
) -> Result<Vec<Value>, ApiError> {
    let want = |t: &str| type_filter.map(|f| f.eq_ignore_ascii_case(t)).unwrap_or(true);
    let mut out: Vec<Value> = Vec::new();

    macro_rules! collect {
        ($ent:path, $col:path, $prefix:literal, $typ:literal) => {
            if want($typ) {
                for m in <$ent>::find().filter($col.eq(zone_id)).all(db).await? {
                    out.push(to_view(serde_json::to_value(&m).unwrap(), $prefix, $typ));
                }
            }
        };
    }
    collect!(rr::a::Entity, rr::a::Column::ZoneId, "a", "A");
    collect!(rr::aaaa::Entity, rr::aaaa::Column::ZoneId, "aaaa", "AAAA");
    collect!(rr::ns::Entity, rr::ns::Column::ZoneId, "ns", "NS");
    collect!(rr::ptr::Entity, rr::ptr::Column::ZoneId, "ptr", "PTR");
    collect!(rr::cname::Entity, rr::cname::Column::ZoneId, "cname", "CNAME");
    collect!(rr::txt::Entity, rr::txt::Column::ZoneId, "txt", "TXT");
    collect!(rr::mx::Entity, rr::mx::Column::ZoneId, "mx", "MX");
    collect!(rr::srv::Entity, rr::srv::Column::ZoneId, "srv", "SRV");
    collect!(rr::caa::Entity, rr::caa::Column::ZoneId, "caa", "CAA");
    collect!(rr::sshfp::Entity, rr::sshfp::Column::ZoneId, "sshfp", "SSHFP");
    collect!(rr::tlsa::Entity, rr::tlsa::Column::ZoneId, "tlsa", "TLSA");
    collect!(rr::dnskey::Entity, rr::dnskey::Column::ZoneId, "dnskey", "DNSKEY");
    collect!(rr::ds::Entity, rr::ds::Column::ZoneId, "ds", "DS");
    collect!(rr::naptr::Entity, rr::naptr::Column::ZoneId, "naptr", "NAPTR");

    if let Some(nf) = name_filter {
        out.retain(|v| v.get("name").and_then(|n| n.as_str()).map(|n| n.contains(nf)).unwrap_or(false));
    }
    out.sort_by(|a, b| {
        let ka = (a["type"].as_str().unwrap_or(""), a["name"].as_str().unwrap_or(""));
        let kb = (b["type"].as_str().unwrap_or(""), b["name"].as_str().unwrap_or(""));
        ka.cmp(&kb)
    });
    Ok(out)
}

/// Fetch one record by opaque id within a zone.
pub async fn get_record(
    db: &DatabaseConnection,
    zone_id: i32,
    rrid: &str,
) -> Result<Value, ApiError> {
    let (prefix, id) = split_id(rrid).ok_or(ApiError::NotFound)?;
    let typ = prefix_to_type(&prefix).ok_or(ApiError::NotFound)?;
    dispatch_fetch(db, &prefix, id, zone_id, typ).await
}

// --- write side (dispatch on type) ---

/// Create a record from a unified body `{type, name, ttl?, …rdata}` in `zone_id`.
pub async fn create_record(
    db: &DatabaseConnection,
    zone_id: i32,
    default_ttl: i32,
    body: &Value,
) -> Result<Value, ApiError> {
    write_record(db, zone_id, default_ttl, body, None).await
}

/// Create (`update = None`) or update-in-place (`update = Some(pk)`) a record from a unified body.
/// The same per-type parsing/validation drives both; an update sets the PK so it UPDATEs the existing
/// row (preserving `created_at`) rather than inserting.
async fn write_record(
    db: &DatabaseConnection,
    zone_id: i32,
    default_ttl: i32,
    body: &Value,
    update: Option<i32>,
) -> Result<Value, ApiError> {
    let obj = body.as_object().ok_or_else(|| ApiError::Validation("body must be an object".into()))?;
    let typ = rstr(obj, "type")?;
    let prefix = type_to_prefix(&typ).ok_or_else(|| ApiError::BadType(typ.clone()))?;
    let label = name_of(obj)?;
    let ttl = match obj.get("ttl").and_then(|v| v.as_i64()) {
        Some(n) => {
            dns::check::ttl(n).map_err(ApiError::Validation)?;
            n as i32
        }
        None => default_ttl,
    };

    macro_rules! ins {
        ($m:path, { $($f:ident : $val:expr),* $(,)? }) => {{
            use $m as _m;
            let am = _m::ActiveModel {
                id: match update { Some(i) => Set(i), None => NotSet },
                zone_id: Set(zone_id),
                label: Set(label.clone()),
                ttl: Set(ttl),
                $( $f: Set($val), )*
                ..Default::default() // created_at/updated_at stamped by before_save (created_at kept on update)
            };
            // insert/update both fire the after_save hook (serial bump + enqueue).
            let m = if update.is_some() {
                sea_orm::ActiveModelTrait::update(am, db).await?
            } else {
                sea_orm::ActiveModelTrait::insert(am, db).await?
            };
            to_view(serde_json::to_value(&m).unwrap(), prefix, prefix_to_type(prefix).unwrap())
        }};
    }

    let view = match prefix {
        "a" => { let value = strv(obj, "value", dns::check::ipv4)?; ins!(rr::a, { value: value }) }
        "aaaa" => { let value = strv(obj, "value", dns::check::ipv6)?; ins!(rr::aaaa, { value: value }) }
        "ns" => { let value = name_val(obj, "value")?; ins!(rr::ns, { value: value }) }
        "ptr" => { let value = name_val(obj, "value")?; ins!(rr::ptr, { value: value }) }
        "cname" => { let value = name_val(obj, "value")?; ins!(rr::cname, { value: value }) }
        "txt" => { let value = strv(obj, "value", dns::check::txt)?; ins!(rr::txt, { value: value }) }
        "mx" => {
            let priority = u16v(obj, "priority")?;
            let value = name_val(obj, "value")?;
            ins!(rr::mx, { priority: priority, value: value })
        }
        "srv" => {
            let priority = u16v(obj, "priority")?;
            let weight = u16v(obj, "weight")?;
            let port = u16v(obj, "port")?;
            let value = name_val(obj, "value")?;
            ins!(rr::srv, { priority: priority, weight: weight, port: port, value: value })
        }
        "caa" => {
            let flag = octv(obj, "flag")?;
            let tag = strv(obj, "tag", dns::check::caa_tag)?;
            let value = strv(obj, "value", dns::check::non_empty_value)?;
            ins!(rr::caa, { flag: flag, tag: tag, value: value })
        }
        "sshfp" => {
            let algorithm = octv(obj, "algorithm")?;
            let hash_type = octv(obj, "hash_type")?;
            let fingerprint = strv(obj, "fingerprint", dns::check::hex)?;
            ins!(rr::sshfp, { algorithm: algorithm, hash_type: hash_type, fingerprint: fingerprint })
        }
        "tlsa" => {
            let cert_usage = octv(obj, "cert_usage")?;
            let selector = octv(obj, "selector")?;
            let matching_type = octv(obj, "matching_type")?;
            let cert_data = strv(obj, "cert_data", dns::check::hex)?;
            ins!(rr::tlsa, { cert_usage: cert_usage, selector: selector, matching_type: matching_type, cert_data: cert_data })
        }
        "dnskey" => {
            let flags = u16v(obj, "flags")?;
            let protocol = intv(obj, "protocol", dns::check::dnskey_protocol)?;
            let algorithm = octv(obj, "algorithm")?;
            let public_key = strv(obj, "public_key", dns::check::base64)?;
            ins!(rr::dnskey, { flags: flags, protocol: protocol, algorithm: algorithm, public_key: public_key })
        }
        "ds" => {
            let key_tag = u16v(obj, "key_tag")?;
            let algorithm = octv(obj, "algorithm")?;
            let digest_type = octv(obj, "digest_type")?;
            let digest = strv(obj, "digest", dns::check::hex)?;
            ins!(rr::ds, { key_tag: key_tag, algorithm: algorithm, digest_type: digest_type, digest: digest })
        }
        "naptr" => {
            let order = u16v(obj, "order")?;
            let preference = u16v(obj, "preference")?;
            let flags = rstr(obj, "flags")?;
            let service = rstr(obj, "service")?;
            let regexp = rstr(obj, "regexp").unwrap_or_default();
            let replacement = rstr(obj, "replacement")?;
            ins!(rr::naptr, { order: order, preference: preference, flags: flags, service: service, regexp: regexp, replacement: replacement })
        }
        _ => return Err(ApiError::BadType(typ)),
    };
    Ok(view)
}

/// Delete a record by opaque id; returns the deleted view. Enqueues a push explicitly (bulk deletes
/// bypass the per-row hook).
pub async fn delete_record(
    db: &DatabaseConnection,
    zone_id: i32,
    rrid: &str,
) -> Result<Value, ApiError> {
    let existing = get_record(db, zone_id, rrid).await?;
    let (prefix, id) = split_id(rrid).ok_or(ApiError::NotFound)?;
    let affected = dispatch_delete(db, &prefix, id, zone_id).await?;
    if affected == 0 {
        return Err(ApiError::NotFound);
    }
    // Enqueue a push for the zone (deletes bypass the after_save hook).
    if let Some(z) = crate::model::zone::Entity::find_by_id(zone_id).one(db).await? {
        crate::sync::bump_serial(db, zone_id).await?;
        crate::sync::enqueue(db, &z.origin).await?;
    }
    Ok(existing)
}

/// Update a record by opaque id (replace ttl + rdata; `name` may be changed). Type is immutable.
pub async fn update_record(
    db: &DatabaseConnection,
    zone_id: i32,
    rrid: &str,
    default_ttl: i32,
    body: &Value,
) -> Result<Value, ApiError> {
    let (prefix, id) = split_id(rrid).ok_or(ApiError::NotFound)?;
    let typ = prefix_to_type(&prefix).ok_or(ApiError::NotFound)?;
    // Confirm it exists in this zone first (also guards the id against a foreign zone).
    let _ = get_record(db, zone_id, rrid).await?;
    // Update the existing row in place: the id stays stable, `created_at` is preserved (only
    // `updated_at` bumps), and the after_save hook still fires the serial bump + push. Type is
    // immutable, so we pin it to the id's type regardless of the body.
    let mut merged = body.as_object().cloned().unwrap_or_default();
    merged.insert("type".into(), json!(typ));
    write_record(db, zone_id, default_ttl, &Value::Object(merged), Some(id)).await
}

// --- per-type dispatch for fetch/delete (find_by_id needs the concrete entity) ---

async fn dispatch_fetch(
    db: &DatabaseConnection,
    prefix: &str,
    id: i32,
    zone_id: i32,
    typ: &str,
) -> Result<Value, ApiError> {
    macro_rules! f {
        ($ent:path, $col:path) => {{
            match <$ent>::find_by_id(id).filter($col.eq(zone_id)).one(db).await? {
                Some(m) => Ok(to_view(serde_json::to_value(&m).unwrap(), prefix, typ)),
                None => Err(ApiError::NotFound),
            }
        }};
    }
    match prefix {
        "a" => f!(rr::a::Entity, rr::a::Column::ZoneId),
        "aaaa" => f!(rr::aaaa::Entity, rr::aaaa::Column::ZoneId),
        "ns" => f!(rr::ns::Entity, rr::ns::Column::ZoneId),
        "ptr" => f!(rr::ptr::Entity, rr::ptr::Column::ZoneId),
        "cname" => f!(rr::cname::Entity, rr::cname::Column::ZoneId),
        "txt" => f!(rr::txt::Entity, rr::txt::Column::ZoneId),
        "mx" => f!(rr::mx::Entity, rr::mx::Column::ZoneId),
        "srv" => f!(rr::srv::Entity, rr::srv::Column::ZoneId),
        "caa" => f!(rr::caa::Entity, rr::caa::Column::ZoneId),
        "sshfp" => f!(rr::sshfp::Entity, rr::sshfp::Column::ZoneId),
        "tlsa" => f!(rr::tlsa::Entity, rr::tlsa::Column::ZoneId),
        "dnskey" => f!(rr::dnskey::Entity, rr::dnskey::Column::ZoneId),
        "ds" => f!(rr::ds::Entity, rr::ds::Column::ZoneId),
        "naptr" => f!(rr::naptr::Entity, rr::naptr::Column::ZoneId),
        _ => Err(ApiError::NotFound),
    }
}

async fn dispatch_delete(
    db: &DatabaseConnection,
    prefix: &str,
    id: i32,
    zone_id: i32,
) -> Result<u64, ApiError> {
    macro_rules! d {
        ($ent:path, $idcol:path, $zcol:path) => {{
            let r = <$ent>::delete_many().filter($idcol.eq(id)).filter($zcol.eq(zone_id)).exec(db).await?;
            r.rows_affected
        }};
    }
    let n = match prefix {
        "a" => d!(rr::a::Entity, rr::a::Column::Id, rr::a::Column::ZoneId),
        "aaaa" => d!(rr::aaaa::Entity, rr::aaaa::Column::Id, rr::aaaa::Column::ZoneId),
        "ns" => d!(rr::ns::Entity, rr::ns::Column::Id, rr::ns::Column::ZoneId),
        "ptr" => d!(rr::ptr::Entity, rr::ptr::Column::Id, rr::ptr::Column::ZoneId),
        "cname" => d!(rr::cname::Entity, rr::cname::Column::Id, rr::cname::Column::ZoneId),
        "txt" => d!(rr::txt::Entity, rr::txt::Column::Id, rr::txt::Column::ZoneId),
        "mx" => d!(rr::mx::Entity, rr::mx::Column::Id, rr::mx::Column::ZoneId),
        "srv" => d!(rr::srv::Entity, rr::srv::Column::Id, rr::srv::Column::ZoneId),
        "caa" => d!(rr::caa::Entity, rr::caa::Column::Id, rr::caa::Column::ZoneId),
        "sshfp" => d!(rr::sshfp::Entity, rr::sshfp::Column::Id, rr::sshfp::Column::ZoneId),
        "tlsa" => d!(rr::tlsa::Entity, rr::tlsa::Column::Id, rr::tlsa::Column::ZoneId),
        "dnskey" => d!(rr::dnskey::Entity, rr::dnskey::Column::Id, rr::dnskey::Column::ZoneId),
        "ds" => d!(rr::ds::Entity, rr::ds::Column::Id, rr::ds::Column::ZoneId),
        "naptr" => d!(rr::naptr::Entity, rr::naptr::Column::Id, rr::naptr::Column::ZoneId),
        _ => return Err(ApiError::NotFound),
    };
    Ok(n)
}

// --- field readers ---

fn name_of(obj: &Map<String, Value>) -> Result<String, ApiError> {
    let n = obj
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::Validation("name is required".into()))?;
    let n = if n.is_empty() { "@" } else { n };
    dns::check::record_label(n).map_err(ApiError::Validation)?;
    Ok(n.to_string())
}

fn rstr(obj: &Map<String, Value>, key: &str) -> Result<String, ApiError> {
    obj.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| ApiError::Validation(format!("{key} is required")))
}

fn name_val(obj: &Map<String, Value>, key: &str) -> Result<String, ApiError> {
    let v = rstr(obj, key)?;
    dns::check::target_name(&v).map_err(|e| ApiError::Validation(format!("{key} {e}")))?;
    Ok(v)
}

/// Read a required integer field and validate it with `check` (e.g. `dns::check::u16`), prefixing the
/// message with the field name. Returns it as `i32` (the column width).
fn intv(
    obj: &Map<String, Value>,
    key: &str,
    check: impl Fn(i64) -> Result<(), String>,
) -> Result<i32, ApiError> {
    let n = obj
        .get(key)
        .and_then(|v| v.as_i64())
        .ok_or_else(|| ApiError::Validation(format!("{key} is required (integer)")))?;
    check(n).map_err(|e| ApiError::Validation(format!("{key} {e}")))?;
    Ok(n as i32)
}

/// A 16-bit unsigned field in `[0,65535]`, stored as i32.
fn u16v(obj: &Map<String, Value>, key: &str) -> Result<i32, ApiError> {
    intv(obj, key, dns::check::u16)
}

/// A single-octet field in `[0,255]`, stored as i32.
fn octv(obj: &Map<String, Value>, key: &str) -> Result<i32, ApiError> {
    intv(obj, key, dns::check::octet)
}

/// Read a required string field and validate it with `check` (e.g. `dns::check::hex`), prefixing the
/// message with the field name.
fn strv(
    obj: &Map<String, Value>,
    key: &str,
    check: impl Fn(&str) -> Result<(), String>,
) -> Result<String, ApiError> {
    let v = rstr(obj, key)?;
    check(&v).map_err(|e| ApiError::Validation(format!("{key} {e}")))?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_roundtrip() {
        assert_eq!(split_id("mx-7"), Some(("mx".into(), 7)));
        assert_eq!(type_to_prefix("MX"), Some("mx"));
        assert_eq!(prefix_to_type("mx"), Some("MX"));
        assert_eq!(type_of_id("aaaa-3"), Some("AAAA"));
    }

    #[test]
    fn view_shape() {
        let row = json!({"id": 12, "zone_id": 1, "label": "www", "ttl": 60, "value": "1.2.3.4"});
        let v = to_view(row, "a", "A");
        assert_eq!(v["id"], "a-12");
        assert_eq!(v["type"], "A");
        assert_eq!(v["name"], "www");
        assert_eq!(v["value"], "1.2.3.4");
        assert!(v.get("zone_id").is_none());
    }
}
