//! The OpenAPI document for the three APIs this server publishes: the native JSON management API,
//! the Cloudflare-compatible facade, and the dyndns2 DDNS endpoint. All three are hand-written
//! handlers, so this description is hand-written too — and it is the *whole* document now:
//! relativelylight 0.3 removed the generator that used to describe the console's own CRUD wire,
//! along with that wire (the console is server-rendered HTML; it has no API behind it).
//!
//! Keep this in step with `api/`, `cfapi/` and `ddns.rs` — it is what `/docs` renders.

use serde_json::{json, Value};

/// The complete document, as pretty JSON — what `/openapi.json` serves.
pub fn document(version: &str) -> String {
    let doc = json!({
        "openapi": "3.0.3",
        "info": {
            "title": "teleddns-server API",
            "version": version,
            "description": "Three surfaces, one authorization model: every call resolves a principal \
                            from a bearer token (or HTTP Basic, on DDNS only) and is then allowed by a \
                            *zone* grant or a *record* grant. A credential carries no rights of its \
                            own — it acts as its owner.",
        },
        "paths": Value::Object(paths(&json!([{ "bearerAuth": [] }])).into_iter().collect()),
        "components": {
            "securitySchemes": {
                "bearerAuth": { "type": "http", "scheme": "bearer" },
                "basicAuth": { "type": "http", "scheme": "basic" },
            }
        },
    });
    serde_json::to_string_pretty(&doc).unwrap_or_default()
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
     `name` is relative to the zone (`@` = apex; `*` wildcard, `_underscore` and RFC 2317 \
     classless-reverse labels such as `0/27` are all allowed). \
     `ttl` is optional (defaults to the zone TTL) and must be 0..2147483647 (RFC 2181).\n\n\
     rdata by type — all validated on write:\n\
     - **A**: `value` = IPv4 (e.g. 192.0.2.1); **AAAA**: `value` = IPv6.\n\
     - **NS/PTR/CNAME**: `value` = hostname (trailing dot ok).\n\
     - **TXT**: `value` = free text (≤ 65535 bytes; split into 255-byte strings when rendered).\n\
     - **MX**: `priority` 0..65535, `value` = hostname.\n\
     - **SRV**: `priority`/`weight`/`port` 0..65535, `value` = host (`.` = no service).\n\
     - **CAA**: `flag` 0..255, `tag` = issue|issuewild|iodef, `value` non-empty (≤ 255 bytes).\n\
     - **SSHFP**: `algorithm`/`hash_type` 0..255, `fingerprint` = hex.\n\
     - **TLSA**: `cert_usage`/`selector`/`matching_type` 0..255, `cert_data` = hex.\n\
     - **DNSKEY**: `flags` 0..65535, `protocol` = 3, `algorithm` 0..255, `public_key` = base64.\n\
     - **DS**: `key_tag` 0..65535, `algorithm`/`digest_type` 0..255, `digest` = hex.\n\
     - **NAPTR**: `order`/`preference` 0..65535, `flags` = letters/digits (may be empty), \
     `service` = text without spaces (e.g. E2U+sip), `regexp` = text (≤ 255 bytes, optional), \
     `replacement` = hostname (`.` = none)."
}

/// One entry per published path, in the order `/docs` lists them.
fn paths(sec: &Value) -> Vec<(String, Value)> {
    vec![
        (
            "/api/zones".into(),
            json!({
                "get": op("List zones (paginated; X-Total-Count)", sec, "native-api"),
                "post": op_doc(
                    "Create a zone (Superadmin; auto SOA + apex NS; Idempotency-Key)",
                    "Body: `{ \"origin\": \"example.com.\" }`. `origin` must be a valid DNS name; it \
                     is normalized to an absolute FQDN. The SOA (with MNAME `ns.<origin>`, RNAME \
                     `hostmaster.<origin>`) and a default apex NS are generated automatically.",
                    sec, "native-api"),
            }),
        ),
        (
            "/api/zones/{id}".into(),
            json!({
                "get": op("Get a zone (Zone Manager)", sec, "native-api"),
                "put": op_doc(
                    "Update a zone's SOA (Zone Manager; bumps serial)",
                    "Body may set any of `mname`/`rname` (DNS names) and `refresh`/`retry`/`expire`/\
                     `minimum`/`ttl` (0..2147483647 seconds). The serial is bumped automatically.",
                    sec, "native-api"),
                "delete": op("Delete a zone (Superadmin)", sec, "native-api"),
            }),
        ),
        (
            "/api/zones/{id}/rr".into(),
            json!({
                "get": op("List records (Zone Manager; ?type/?name; paginated)", sec, "native-api"),
                "post": op_doc(
                    "Create a record (Zone Manager; unified type-discriminated body; Idempotency-Key)",
                    record_body_doc(), sec, "native-api"),
            }),
        ),
        (
            "/api/zones/{id}/rr/{rrid}".into(),
            json!({
                "get": op("Get a record (A/AAAA: RR Manager, else Zone Manager)", sec, "native-api"),
                "put": op_doc(
                    "Update a record (A/AAAA: RR Manager, else Zone Manager)",
                    record_body_doc(), sec, "native-api"),
                "delete": op("Delete a record (Zone Manager)", sec, "native-api"),
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
            json!({
                // The one surface that also accepts HTTP Basic: a dyndns2 client is usually a router
                // firmware that only knows how to send a username and a password.
                "get": op_doc(
                    "dyndns2 DDNS update",
                    "Query: `hostname` (the FQDN to update, required), `myip` / `myipv6` (the \
                     addresses; omitted means \"use the address this request came from\"). Answers in \
                     dyndns2's vocabulary — `good <ip>`, `nochg <ip>`, `nohost`, `badauth`, `abuse`, \
                     `badagent` — not with HTTP status codes. `/ddns/update` and `/update` are \
                     aliases. See DYNDNS2.md.",
                    &json!([{ "bearerAuth": [] }, { "basicAuth": [] }]), "ddns"),
            }),
        ),
    ]
}

#[cfg(test)]
mod tests {
    /// The document must parse, name a version, and describe every surface we publish — and none we
    /// don't. A console CRUD path reappearing here would mean the engine's wire had come back.
    #[test]
    fn the_document_covers_the_three_published_surfaces_and_nothing_else() {
        let doc: serde_json::Value = serde_json::from_str(&super::document("9.9.9")).unwrap();
        assert_eq!(doc["info"]["version"], "9.9.9");
        let paths = doc["paths"].as_object().unwrap();
        for expected in ["/api/zones", "/client/v4/zones", "/nic/update"] {
            assert!(paths.contains_key(expected), "missing {expected}");
        }
        for p in paths.keys() {
            assert!(
                p.starts_with("/api/") || p.starts_with("/client/v4/") || p == "/nic/update",
                "unexpected path in the document: {p}"
            );
        }
        assert!(doc["components"]["securitySchemes"]["bearerAuth"].is_object());
    }
}
