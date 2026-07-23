//! The no-op `log` backend (default): logs what it would push. Safe for first boot and development.

use super::{Backend, Probe};
use async_trait::async_trait;

pub struct LogBackend;

#[async_trait]
impl Backend for LogBackend {
    async fn push_zone(&self, origin: &str, zonefile: &str, serial: i64) -> Result<(), String> {
        tracing::info!(%origin, serial, bytes = zonefile.len(), "log backend: would push zone");
        tracing::debug!(%origin, "\n{zonefile}");
        Ok(())
    }

    async fn remove_zone(&self, origin: &str) -> Result<(), String> {
        tracing::info!(%origin, "log backend: would remove zone");
        Ok(())
    }

    async fn probe(&self) -> Probe {
        Probe::Na
    }

    async fn zone_serials(&self) -> Result<Option<std::collections::HashMap<String, i64>>, String> {
        Ok(None) // no live server to reconcile against
    }

    fn name(&self) -> &'static str {
        "log"
    }
}
