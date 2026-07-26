//! The audit sink: persists a row per state-changing request into the `audit` table (PRD §5.4). It is
//! the app-side [`WriteObserver`] relativelylight fires for the admin auto-CRUD and the auth handlers,
//! and it also exposes [`Audit::record`] for teleddns's own surfaces (DDNS, native API, CF facade).
//!
//! It deliberately holds only `db` + a little config (cookie name, `trust_proxy`) — **not** `AppState`
//! or `Auth` — so there's no reference cycle (AppState/Auth own the sink `Arc`). For observer events it
//! resolves the acting session user straight from the DB; direct callers pass the resolved principal.

use crate::model::{audit, now};
use crate::principal::Principal;
use axum_extra::extract::cookie::CookieJar;
use relativelylight::authz::Operation;
use relativelylight::observe::{WriteEvent, WriteObserver};
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use serde_json::Value;
use std::net::IpAddr;

pub struct Audit {
    db: DatabaseConnection,
    cookie_name: String,
    trust_proxy: bool,
}

impl Audit {
    pub fn new(db: DatabaseConnection, cookie_name: impl Into<String>, trust_proxy: bool) -> Self {
        Audit { db, cookie_name: cookie_name.into(), trust_proxy }
    }

    /// Insert one audit row (best-effort — a failed audit write must never break the request).
    #[allow(clippy::too_many_arguments)]
    async fn insert(
        &self,
        source: &str,
        operation: &str,
        target: String,
        actor_user_id: Option<i32>,
        actor_username: String,
        auth_type: &str,
        client_ip: String,
        before: Option<Value>,
        after: Option<Value>,
    ) {
        let row = audit::ActiveModel {
            id: sea_orm::ActiveValue::NotSet,
            ts: Set(now()),
            source: Set(source.to_string()),
            operation: Set(operation.to_string()),
            target: Set(target),
            actor_user_id: Set(actor_user_id),
            actor_username: Set(actor_username),
            auth_type: Set(auth_type.to_string()),
            client_ip: Set(client_ip),
            before: Set(before.map(|v| v.to_string())),
            after: Set(after.map(|v| v.to_string())),
        };
        if let Err(e) = row.insert(&self.db).await {
            tracing::warn!(error = %e, "failed to write audit row");
        }
    }

    /// Record an event from one of teleddns's own handlers (DDNS / native API / CF facade), where the
    /// principal + client IP are already resolved.
    #[allow(clippy::too_many_arguments)]
    pub async fn record(
        &self,
        source: &str,
        operation: &str,
        target: String,
        principal: &Principal,
        auth_type: &str,
        ip: Option<IpAddr>,
        before: Option<Value>,
        after: Option<Value>,
    ) {
        self.insert(
            source,
            operation,
            target,
            Some(principal.user_id),
            principal.username.clone(),
            auth_type,
            ip.map(|i| i.to_string()).unwrap_or_else(|| "-".into()),
            before,
            after,
        )
        .await;
    }

    /// Resolve the acting session user from the request cookie (the admin auto-CRUD and auth handlers
    /// are session-authenticated). Returns `(user_id, username, auth_type)`.
    async fn session_actor(&self, headers: &axum::http::HeaderMap) -> (Option<i32>, String, &'static str) {
        let jar = CookieJar::from_headers(headers);
        if let Some(cookie) = jar.get(&self.cookie_name) {
            if let Ok(Some(s)) = relativelylight::auth::session::Entity::find_by_id(cookie.value().to_string())
                .one(&self.db)
                .await
            {
                if let Ok(Some(u)) =
                    relativelylight::auth::user::Entity::find_by_id(s.user_id).one(&self.db).await
                {
                    return (Some(u.id), u.username, "session");
                }
            }
        }
        (None, "-".into(), "none")
    }
}

fn op_str(op: Operation) -> &'static str {
    match op {
        Operation::Create => "create",
        Operation::Update => "update",
        Operation::Delete => "delete",
        Operation::List => "list",
        Operation::Read => "read",
    }
}

#[async_trait::async_trait]
impl WriteObserver for Audit {
    async fn on_write(&self, ev: &WriteEvent<'_>) {
        let (uid, uname, auth_type) = self.session_actor(ev.headers).await;
        let ip = relativelylight::net::client_ip(self.trust_proxy, ev.headers, ev.peer.map(|p| p.ip()))
            .map(|i| i.to_string())
            .unwrap_or_else(|| "-".into());
        let target = match &ev.key {
            Some(k) => format!("{}/{}", ev.entity, k),
            None => ev.entity.to_string(),
        };
        self.insert(
            ev.source,
            op_str(ev.op),
            target,
            uid,
            uname,
            auth_type,
            ip,
            ev.before.clone(),
            ev.after.clone(),
        )
        .await;
    }
}

/// Delete audit rows older than `retention_days` (best-effort). Called at startup.
pub async fn prune(db: &DatabaseConnection, retention_days: u32) {
    if retention_days == 0 {
        return; // 0 = keep forever
    }
    let cutoff = now() - (retention_days as i64) * 86400;
    match audit::Entity::delete_many().filter(audit::Column::Ts.lt(cutoff)).exec(db).await {
        Ok(r) if r.rows_affected > 0 => {
            tracing::info!(pruned = r.rows_affected, "pruned old audit rows");
        }
        Err(e) => tracing::warn!(error = %e, "audit prune failed"),
        _ => {}
    }
}
