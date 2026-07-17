//! Prometheus metrics (PRD §8.2). A single `Metrics` holds the registry + instruments; handlers call
//! the typed helpers. The `/metrics` endpoint (see `ops.rs`) renders the registry, refreshing the
//! DB-derived gauges first. No per-user/token labels (cardinality); the audit log carries the actor.

use prometheus::{
    IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry, TextEncoder,
};

pub struct Metrics {
    pub registry: Registry,
    pub ddns_updates: IntCounterVec,
    pub auth_failures: IntCounterVec,
    pub ratelimited: IntCounterVec,
    pub backend_push: IntCounterVec,
    pub zones: IntGauge,
    pub records: IntGauge,
    pub records_by_type: IntGaugeVec,
    pub pending_pushes: IntGaugeVec,
    pub knot_up: IntGauge,
    pub worker_last_tick: IntGauge,
}

impl Metrics {
    pub fn new() -> Self {
        let registry = Registry::new();
        let ddns_updates = IntCounterVec::new(
            Opts::new("teleddns_ddns_updates_total", "DDNS update results"),
            &["result"],
        )
        .unwrap();
        let auth_failures = IntCounterVec::new(
            Opts::new("teleddns_auth_failures_total", "authentication failures"),
            &["surface", "reason"],
        )
        .unwrap();
        let ratelimited = IntCounterVec::new(
            Opts::new("teleddns_ratelimited_total", "rate-limited requests"),
            &["surface"],
        )
        .unwrap();
        let backend_push = IntCounterVec::new(
            Opts::new("teleddns_backend_push_total", "backend pushes"),
            &["kind", "result"],
        )
        .unwrap();
        let zones = IntGauge::new("teleddns_zones", "number of zones").unwrap();
        let records = IntGauge::new("teleddns_records", "number of records").unwrap();
        let records_by_type = IntGaugeVec::new(
            Opts::new("teleddns_records_by_type", "records by type"),
            &["type"],
        )
        .unwrap();
        let pending_pushes = IntGaugeVec::new(
            Opts::new("teleddns_pending_pushes", "pushes by state"),
            &["state"],
        )
        .unwrap();
        let knot_up = IntGauge::new("teleddns_knot_up", "1 if the knot backend is reachable").unwrap();
        let worker_last_tick =
            IntGauge::new("teleddns_worker_last_tick_seconds", "unix time of the last worker tick")
                .unwrap();

        registry.register(Box::new(ddns_updates.clone())).ok();
        registry.register(Box::new(auth_failures.clone())).ok();
        registry.register(Box::new(ratelimited.clone())).ok();
        registry.register(Box::new(backend_push.clone())).ok();
        registry.register(Box::new(zones.clone())).ok();
        registry.register(Box::new(records.clone())).ok();
        registry.register(Box::new(records_by_type.clone())).ok();
        registry.register(Box::new(pending_pushes.clone())).ok();
        registry.register(Box::new(knot_up.clone())).ok();
        registry.register(Box::new(worker_last_tick.clone())).ok();

        Metrics {
            registry,
            ddns_updates,
            auth_failures,
            ratelimited,
            backend_push,
            zones,
            records,
            records_by_type,
            pending_pushes,
            knot_up,
            worker_last_tick,
        }
    }

    pub fn ddns_update(&self, result: &str) {
        self.ddns_updates.with_label_values(&[result]).inc();
    }
    pub fn auth_failure(&self, surface: &str, reason: &str) {
        self.auth_failures.with_label_values(&[surface, reason]).inc();
    }
    pub fn ratelimit_hit(&self, surface: &str) {
        self.ratelimited.with_label_values(&[surface]).inc();
    }

    /// Render the registry to the Prometheus text exposition format.
    pub fn render(&self) -> String {
        let mut buf = String::new();
        let mf = self.registry.gather();
        let _ = TextEncoder::new().encode_utf8(&mf, &mut buf);
        buf
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}
