//! The backend-push abstraction: turn a rendered zone into a live Knot zone (or just log it). The
//! worker (`worker.rs`) drains the `sync_task` journal and calls a `Backend`.

pub mod knot;
pub mod log;
pub mod worker;
pub mod zonefile;

use crate::config::Config;
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// What the backend says about itself: liveness, plus whatever detail it can produce cheaply.
///
/// One call, because the dashboard, `/healthcheck` and `/metrics` all want a piece of it and the
/// knot implementation is a subprocess — three separate probes per page load would be three
/// `knotc` spawns. [`crate::stats::Stats`] makes the call once and hands the parts out.
#[derive(Clone, Debug, Default)]
pub struct Status {
    pub probe: Probe,
    /// The server's own one-line answer, for an operator to read: `knotc status` on the knot
    /// backend, `None` where there is nothing to ask (the `log` backend) or the ask failed.
    pub detail: Option<String>,
    /// Why the probe failed, when it did — the message an operator needs to fix it.
    pub error: Option<String>,
}

/// Liveness of the underlying DNS server.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Probe {
    /// Reachable (knot backend, `knotc status` ok).
    Up,
    /// Unreachable (knot backend, probe failed).
    Down,
    /// Not applicable (the no-op `log` backend).
    #[default]
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
    /// Liveness, plus any cheap self-description. Called **once** per request that needs any of
    /// it — see [`Status`].
    async fn status(&self) -> Status;
    /// The serial the server is currently serving for each zone it holds, for reconciliation.
    /// `Ok(None)` = the backend can't report (the `log` backend) — reconciliation is skipped.
    async fn zone_serials(&self) -> Result<Option<HashMap<String, i64>>, String>;
    /// Origins currently declared in the backend under the configured template, for orphan
    /// pruning. `Ok(None)` = not applicable (the `log` backend has nothing to enumerate).
    async fn managed_zones(&self) -> Result<Option<HashSet<String>>, String>;
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
