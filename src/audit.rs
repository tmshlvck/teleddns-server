//! The audit sink: persists a row per state-changing request into the `audit` table (PRD §5.4). It is
//! the app-side [`WriteObserver`] relativelylight fires for the admin auto-CRUD and the auth handlers,
//! and it also exposes [`Audit::record`] for teleddns's own surfaces (DDNS, native API, CF facade,
//! the API-key card) and [`Audit::record_local`] for the ones with no request behind them at all (the
//! `admin` CLI subcommands, the first-start seed).
//!
//! **Every path that writes or deletes app state lands here.** There are exactly three ways in — the
//! observer (library-driven), `record` (a handler, principal already resolved), `record_local` (an
//! operator at a shell) — and the [`SOURCES`] list names every surface that uses one of them. A
//! library-emitted event names *itself* (`crud` / `auth-*`); teleddns names its own surfaces at the
//! call site. Nothing is rewritten in between — see the observer impl below. What is
//! deliberately *not* audited is machinery rather than action: the push journal (`sync_task`), the
//! `Idempotency-Key` store, a key's `last_used_at` stamp, sessions and the lockout counters. Each of
//! those is either a side effect of a write that is already audited, or a counter the admin console
//! shows live; a row per hit would bury the log without adding a fact. Add a *user-visible* write path
//! and it audits, no exceptions — see the invariant in AGENTS.md.
//!
//! It deliberately holds only `db` + the session-cookie name — **not** `AppState` or `Auth` — so
//! there's no reference cycle (AppState/Auth own the sink `Arc`). For observer events it resolves the
//! acting session user straight from the DB; direct callers pass the resolved principal.
//!
//! The client address is never derived here: an observer event carries the one
//! `middleware::resolve_real_ip` resolved at the edge, and our own handlers pass the `RealIp` they were
//! given — so an audit row names exactly the client the lockout counted and the access log printed.

use crate::model::{audit, now};
use crate::principal::Principal;
use axum_extra::extract::cookie::CookieJar;
use relativelylight::authz::Operation;
use relativelylight::observe::{WriteEvent, WriteObserver};
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use serde_json::Value;
use std::net::IpAddr;

/// Every `source` value that can appear in the log, for the admin column's docs and as the one place
/// to look when adding a surface. The `autocrud` / `auth-*` rows come from relativelylight, which names
/// its own emitters (`observe::WriteEvent::source`); the rest are teleddns's, named at the `record` /
/// `record_local` call site.
///
/// `crud` is the older spelling of `autocrud` — relativelylight renamed it (cosmetic; a bare "crud"
/// says little in an app with CRUD screens of its own), and it is still what our pinned 0.2.1 writes.
/// Both stay listed because the rename isn't retroactive: a stored row keeps whichever spelling was
/// current when it was written, until it ages out of `audit_retention_days`.
pub const SOURCES: &[&str] = &[
    "ddns", "api", "cfapi", "keys", "autocrud", "crud", "auth-profile", "auth-admin", "cli", "startup",
];

pub struct Audit {
    db: DatabaseConnection,
    cookie_name: String,
}

impl Audit {
    pub fn new(db: DatabaseConnection, cookie_name: impl Into<String>) -> Self {
        Audit { db, cookie_name: cookie_name.into() }
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
        ip: IpAddr,
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
            ip.to_string(),
            before,
            after,
        )
        .await;
    }

    /// Record an event with **no request behind it**: an `admin` CLI subcommand, or the first-start
    /// seed. There is no session to resolve and no client to name, so the actor is the operator at the
    /// shell — read from the environment — and the address is the literal `local`.
    ///
    /// `actor_user_id` stays `NULL` on purpose: a shell account is not an app account, and mapping the
    /// two by name would put an identity in the log that nothing ever authenticated. What the row does
    /// prove is that the change came from the host, not the network — which is the distinction that
    /// matters when a zone changes and no API call explains it.
    pub async fn record_local(
        &self,
        source: &str,
        operation: &str,
        target: String,
        before: Option<Value>,
        after: Option<Value>,
    ) {
        self.insert(source, operation, target, None, local_actor(), "local", "local".into(), before, after)
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

/// Name the operator running a CLI subcommand. `SUDO_USER` first — under `sudo` the interesting name
/// is the human, not `root`. `-` when the process has no environment to speak of (a systemd unit).
fn local_actor() -> String {
    for var in ["SUDO_USER", "USER", "LOGNAME"] {
        match std::env::var(var) {
            Ok(v) if !v.is_empty() => return v,
            _ => {}
        }
    }
    "-".into()
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
        let ip = ev.client_ip.to_string(); // already resolved at the edge — see the module docs
        let target = match &ev.key {
            Some(k) => format!("{}/{}", ev.entity, k),
            None => ev.entity.to_string(),
        };
        // The event's `source` is stored verbatim: the library names its own emitters, and translating
        // its vocabulary here would only hide which version wrote a row. `crud` → `autocrud` is
        // relativelylight's own rename, landing in its next release.
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
///
/// Retention is the one thing that removes rows from the log, so it records *itself* — otherwise the
/// only trace of a gap in the history would be the gap. The row survives the pass that wrote it (it is
/// newer than the cutoff), and is in turn pruned by a later one.
pub async fn prune(db: &DatabaseConnection, retention_days: u32, sink: &Audit) {
    if retention_days == 0 {
        return; // 0 = keep forever
    }
    let cutoff = now() - (retention_days as i64) * 86400;
    match audit::Entity::delete_many().filter(audit::Column::Ts.lt(cutoff)).exec(db).await {
        Ok(r) if r.rows_affected > 0 => {
            tracing::info!(pruned = r.rows_affected, "pruned old audit rows");
            sink.record_local(
                "startup",
                "delete",
                "audit".into(),
                Some(serde_json::json!({ "pruned": r.rows_affected, "older_than": cutoff })),
                None,
            )
            .await;
        }
        Err(e) => tracing::warn!(error = %e, "audit prune failed"),
        _ => {}
    }
}
