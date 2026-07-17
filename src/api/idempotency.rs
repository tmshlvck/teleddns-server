//! Idempotency-Key replay for native-API POSTs (PRD §6.1). A key is scoped per user. A retry within
//! 24h with the same key + body replays the original 2xx response (`Idempotency-Replayed: true`); the
//! same key with a *different* body is a conflict (422).

use crate::app::AppState;
use crate::model::{idempotency, now};
use crate::principal::Principal;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use sea_orm::ActiveValue::Set;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde_json::Value;
use sha2::{Digest, Sha256};

const TTL_SECS: i64 = 24 * 3600;

/// A stored 2xx response for replay.
#[derive(Clone)]
pub struct Stored {
    pub status: u16,
    pub body: Value,
}

impl Stored {
    pub fn to_response(&self) -> Response {
        let code = StatusCode::from_u16(self.status).unwrap_or(StatusCode::OK);
        (code, [("Idempotency-Replayed", "true")], Json(self.body.clone())).into_response()
    }
}

/// The result of checking a key before doing the work.
pub enum Outcome {
    /// No key present, or a fresh key — proceed and then call `finish`.
    Proceed,
    /// The same key + body was seen — replay this response.
    Replay(Stored),
    /// The key was reused with a different body.
    Conflict,
}

fn key_of(headers: &HeaderMap) -> Option<String> {
    headers.get("Idempotency-Key").and_then(|v| v.to_str().ok()).map(|s| s.to_string())
}

fn body_hash(body: &Value) -> String {
    let mut h = Sha256::new();
    h.update(serde_json::to_vec(body).unwrap_or_default());
    hex::encode(h.finalize())
}

/// Look up a key before doing the work.
pub async fn begin(app: &AppState, who: &Principal, headers: &HeaderMap, body: &Value) -> Outcome {
    let Some(key) = key_of(headers) else {
        return Outcome::Proceed;
    };
    let scoped = format!("{}:{}", who.user_id, key);
    match idempotency::Entity::find_by_id(scoped).one(&app.db).await {
        Ok(Some(row)) => {
            if now() - row.created_at > TTL_SECS {
                return Outcome::Proceed; // expired; a fresh use overwrites in `finish`
            }
            if row.request_hash != body_hash(body) {
                return Outcome::Conflict;
            }
            let body: Value = serde_json::from_str(&row.response_body).unwrap_or(Value::Null);
            Outcome::Replay(Stored { status: row.status as u16, body })
        }
        _ => Outcome::Proceed,
    }
}

/// Store the response for a keyed POST after success.
pub async fn finish(app: &AppState, who: &Principal, headers: &HeaderMap, body: &Value, resp: &Stored) {
    let Some(key) = key_of(headers) else {
        return;
    };
    let scoped = format!("{}:{}", who.user_id, key);
    // Upsert: delete any expired/old row for this key first, then insert.
    let _ = idempotency::Entity::delete_by_id(scoped.clone()).exec(&app.db).await;
    let row = idempotency::ActiveModel {
        key: Set(scoped),
        user_id: Set(who.user_id),
        request_hash: Set(body_hash(body)),
        status: Set(resp.status as i32),
        response_body: Set(serde_json::to_string(&resp.body).unwrap_or_default()),
        created_at: Set(now()),
    };
    let _ = idempotency::Entity::insert(row).exec(&app.db).await;
}
