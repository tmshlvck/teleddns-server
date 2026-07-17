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

fn native_paths(sec: &Value) -> Vec<(String, Value)> {
    vec![
        (
            "/api/zones".into(),
            json!({
                "get": op("List zones (paginated; X-Total-Count)", sec, "native-api"),
                "post": op("Create a zone (L3; auto SOA + apex NS; Idempotency-Key)", sec, "native-api"),
            }),
        ),
        (
            "/api/zones/{id}".into(),
            json!({
                "get": op("Get a zone (L2)", sec, "native-api"),
                "put": op("Update a zone's SOA (L2; bumps serial)", sec, "native-api"),
                "delete": op("Delete a zone (L3)", sec, "native-api"),
            }),
        ),
        (
            "/api/zones/{id}/rr".into(),
            json!({
                "get": op("List records (L2; ?type/?name; paginated)", sec, "native-api"),
                "post": op("Create a record (L2; unified type-discriminated body; Idempotency-Key)", sec, "native-api"),
            }),
        ),
        (
            "/api/zones/{id}/rr/{rrid}".into(),
            json!({
                "get": op("Get a record (A/AAAA L1, else L2)", sec, "native-api"),
                "put": op("Update a record (A/AAAA L1, else L2)", sec, "native-api"),
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
