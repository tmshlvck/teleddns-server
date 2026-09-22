//! The no-op `log` backend (default): logs what it would push. Safe for first boot and development.

use super::{Backend, Probe, Status};
use async_trait::async_trait;

pub struct LogBackend;

#[async_trait]
impl Backend for LogBackend {
    async fn push_zone(
        &self,
        origin: &str,
        zonefile: &str,
        serial: i64,
        template: &str,
    ) -> Result<(), String> {
        tracing::info!(%origin, serial, %template, bytes = zonefile.len(), "log backend: would push zone");
        tracing::debug!(%origin, "\n{zonefile}");
        Ok(())
    }

    async fn remove_zone(&self, origin: &str) -> Result<(), String> {
        tracing::info!(%origin, "log backend: would remove zone");
        Ok(())
    }

    async fn status(&self) -> Status {
        // Nothing to be up or down: this backend pushes nowhere.
        Status { probe: Probe::Na, ..Default::default() }
    }

    async fn zone_serials(&self) -> Result<Option<std::collections::HashMap<String, i64>>, String> {
        Ok(None) // no live server to reconcile against
    }

    async fn managed_zones(&self) -> Result<Option<std::collections::HashSet<String>>, String> {
        Ok(None) // no live server to enumerate
    }

    fn name(&self) -> &'static str {
        "log"
    }
}
