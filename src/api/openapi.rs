//! A hand-authored OpenAPI paths supplement for the native API and the Cloudflare facade (their
//! handlers are hand-written, so they aren't introspected like the admin CRUD entities). We merge
//! these path entries into the app's OpenAPI JSON so `/docs` documents every surface.

use serde_json::{json, Value};

/// Merge the native-API + CF-facade paths into an OpenAPI document (a serialized JSON value).
pub fn merge(doc: &mut Value) {
    let paths = doc
        .as_object_mut()
        .and_then(|o| o.entry("paths").or_insert_with(|| json!({})).as_object_mut());
    let Some(paths) = paths else { return };

    let bearer = json!([{ "bearerAuth": [] }]);

    for (path, item) in native_paths(&bearer) {
        paths.insert(path, item);
    }

    // Advertise the bearer security scheme.
    if let Some(comp) = doc
        .as_object_mut()
        .and_then(|o| o.entry("components").or_insert_with(|| json!({})).as_object_mut())
    {
        comp.entry("securitySchemes").or_insert_with(|| {
            json!({ "bearerAuth": { "type": "http", "scheme": "bearer" } })
        });
    }
}

fn op(summary: &str, security: &Value, tag: &str) -> Value {
    json!({
        "summary": summary,
        "tags": [tag],
        "security": security,
        "responses": { "200": { "description": "OK" } }
    })
}

/// Like [`op`] but with a longer description and the standard validation-failure response advertised
/// (the native API rejects malformed input with 400/422 and `{ "error": … }`).
fn op_doc(summary: &str, description: &str, security: &Value, tag: &str) -> Value {
    json!({
        "summary": summary,
        "description": description,
        "tags": [tag],
        "security": security,
        "responses": {
            "200": { "description": "OK" },
            "400": { "description": "Malformed request (bad type, missing/invalid field): { \"error\": … }" },
            "422": { "description": "Validation failed (value out of range / wrong format): { \"error\": … }" }
        }
    })
}

/// Human-readable summary of the per-type record body + the field constraints the server enforces
/// (kept in sync with `dns::check` and the admin help). Shown on the record create/update operations.
fn record_body_doc() -> &'static str {
    "Unified, type-discriminated record body: `{ type, name, ttl?, …rdata }`.\n\
     `name` is relative to the zone (`@` = apex; `*` wildcard and `_underscore` labels allowed). \
     `ttl` is optional (defaults to the zone TTL) and must be 0..2147483647 (RFC 2181).\n\n\
     rdata by type — all validated on write:\n\
     - **A**: `value` = IPv4 (e.g. 192.0.2.1); **AAAA**: `value` = IPv6.\n\
     - **NS/PTR/CNAME**: `value` = hostname (trailing dot ok).\n\
     - **TXT**: `value` = free text (≤ 65535 bytes).\n\
     - **MX**: `priority` 0..65535, `value` = hostname.\n\
     - **SRV**: `priority`/`weight`/`port` 0..65535, `value` = host (`.` = no service).\n\
     - **CAA**: `flag` 0..255, `tag` = issue|issuewild|iodef, `value` non-empty.\n\
     - **SSHFP**: `algorithm`/`hash_type` 0..255, `fingerprint` = hex.\n\
     - **TLSA**: `cert_usage`/`selector`/`matching_type` 0..255, `cert_data` = hex.\n\
     - **DNSKEY**: `flags` 0..65535, `protocol` = 3, `algorithm` 0..255, `public_key` = base64.\n\
     - **DS**: `key_tag` 0..65535, `algorithm`/`digest_type` 0..255, `digest` = hex.\n\
     - **NAPTR**: `order`/`preference` 0..65535, `flags`/`service`/`regexp` free, `replacement` = name."
}

fn native_paths(sec: &Value) -> Vec<(String, Value)> {
    vec![
        (
            "/api/zones".into(),
            json!({
                "get": op("List zones (paginated; X-Total-Count)", sec, "native-api"),
                "post": op_doc(
                    "Create a zone (L3; auto SOA + apex NS; Idempotency-Key)",
                    "Body: `{ \"origin\": \"example.com.\" }`. `origin` must be a valid DNS name; it \
                     is normalized to an absolute FQDN. The SOA (with MNAME `ns.<origin>`, RNAME \
                     `hostmaster.<origin>`) and a default apex NS are generated automatically.",
                    sec, "native-api"),
            }),
        ),
        (
            "/api/zones/{id}".into(),
            json!({
                "get": op("Get a zone (L2)", sec, "native-api"),
                "put": op_doc(
                    "Update a zone's SOA (L2; bumps serial)",
                    "Body may set any of `mname`/`rname` (DNS names) and `refresh`/`retry`/`expire`/\
                     `minimum`/`ttl` (0..2147483647 seconds). The serial is bumped automatically.",
                    sec, "native-api"),
                "delete": op("Delete a zone (L3)", sec, "native-api"),
            }),
        ),
        (
            "/api/zones/{id}/rr".into(),
            json!({
                "get": op("List records (L2; ?type/?name; paginated)", sec, "native-api"),
                "post": op_doc(
                    "Create a record (L2; unified type-discriminated body; Idempotency-Key)",
                    record_body_doc(), sec, "native-api"),
            }),
        ),
        (
            "/api/zones/{id}/rr/{rrid}".into(),
            json!({
                "get": op("Get a record (A/AAAA L1, else L2)", sec, "native-api"),
                "put": op_doc(
                    "Update a record (A/AAAA L1, else L2)",
                    record_body_doc(), sec, "native-api"),
                "delete": op("Delete a record (L2)", sec, "native-api"),
            }),
        ),
        (
            "/client/v4/user/tokens/verify".into(),
            json!({ "get": op("Cloudflare-compatible: verify token", sec, "cloudflare-facade") }),
        ),
        (
            "/client/v4/zones".into(),
            json!({ "get": op("Cloudflare-compatible: list zones", sec, "cloudflare-facade") }),
        ),
        (
            "/client/v4/zones/{id}/dns_records".into(),
            json!({
                "get": op("Cloudflare-compatible: list DNS records", sec, "cloudflare-facade"),
                "post": op("Cloudflare-compatible: create a DNS record", sec, "cloudflare-facade"),
            }),
        ),
        (
            "/client/v4/zones/{id}/dns_records/{rid}".into(),
            json!({
                "get": op("Cloudflare-compatible: get a DNS record", sec, "cloudflare-facade"),
                "put": op("Cloudflare-compatible: update a DNS record", sec, "cloudflare-facade"),
                "patch": op("Cloudflare-compatible: update a DNS record", sec, "cloudflare-facade"),
                "delete": op("Cloudflare-compatible: delete a DNS record", sec, "cloudflare-facade"),
            }),
        ),
        (
            "/nic/update".into(),
            json!({ "get": op("dyndns2 DDNS update (Basic or Bearer; hostname, myip, myipv6)", sec, "ddns") }),
        ),
    ]
}
