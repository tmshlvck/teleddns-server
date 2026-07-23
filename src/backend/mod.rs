//! The backend-push abstraction: turn a rendered zone into a live Knot zone (or just log it). The
//! worker (`worker.rs`) drains the `sync_task` journal and calls a `Backend`.

pub mod knot;
pub mod log;
pub mod worker;
pub mod zonefile;

use crate::config::Config;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

/// Liveness of the underlying DNS server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Probe {
    /// Reachable (knot backend, `knotc status` ok).
    Up,
    /// Unreachable (knot backend, probe failed).
    Down,
    /// Not applicable (the no-op `log` backend).
    Na,
}

/// A push target. Implementations receive the *already-rendered* zone file.
#[async_trait]
pub trait Backend: Send + Sync {
    /// Write/declare/reload a zone, then **confirm the server is serving `serial`** (a bare reload
    /// only means the request was accepted). `origin` has a trailing dot; `zonefile` is the full
    /// BIND text; `serial` is the SOA serial rendered into it. Returns `Err` if the confirmation
    /// times out — so a zone the server rejects becomes a real, retried, logged failure.
    async fn push_zone(&self, origin: &str, zonefile: &str, serial: i64) -> Result<(), String>;
    /// Remove a zone (undeclare + delete its file).
    async fn remove_zone(&self, origin: &str) -> Result<(), String>;
    /// Liveness probe for the healthcheck.
    async fn probe(&self) -> Probe;
    /// The serial the server is currently serving for each zone it holds, for reconciliation.
    /// `Ok(None)` = the backend can't report (the `log` backend) — reconciliation is skipped.
    async fn zone_serials(&self) -> Result<Option<HashMap<String, i64>>, String>;
    /// Short name for logs/metrics.
    fn name(&self) -> &'static str;
}

/// Build the configured backend.
pub fn make(cfg: &Config) -> Arc<dyn Backend> {
    match cfg.backend.as_str() {
        "knot" => Arc::new(knot::KnotBackend::new(cfg)),
        _ => Arc::new(log::LogBackend),
    }
}
