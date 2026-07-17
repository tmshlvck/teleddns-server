//! The `knot` backend: write the full zone file, declare the zone in Knot's config DB on its first
//! push (idempotent, cached), and `knotc zone-reload`. Everything cluster-static (ACLs, TSIG, catalog
//! membership) lives in the operator's base knot.conf template — this backend only assigns it.

use super::{Backend, Probe};
use async_trait::async_trait;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Mutex;
use tokio::process::Command;

pub struct KnotBackend {
    zone_dir: PathBuf,
    knotc: String,
    template: String,
    /// Origins already declared in Knot's config DB this process (avoids repeat conf-set).
    declared: Mutex<HashSet<String>>,
}

impl KnotBackend {
    pub fn new(cfg: &crate::config::Config) -> Self {
        KnotBackend {
            zone_dir: PathBuf::from(&cfg.knot_zone_dir),
            knotc: cfg.knotc_path.clone(),
            template: cfg.knot_template.clone(),
            declared: Mutex::new(HashSet::new()),
        }
    }

    /// Run `knotc` with args; error carries stderr on non-zero exit.
    async fn knotc(&self, args: &[&str]) -> Result<String, String> {
        let out = Command::new(&self.knotc)
            .args(args)
            .output()
            .await
            .map_err(|e| format!("spawn {}: {e}", self.knotc))?;
        if !out.status.success() {
            return Err(format!(
                "knotc {:?} failed: {}",
                args,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }

    /// Declare the zone as a member of the configured template (once per process).
    async fn ensure_declared(&self, origin: &str) -> Result<(), String> {
        if self.declared.lock().unwrap().contains(origin) {
            return Ok(());
        }
        // conf-begin; conf-set zone[o]; conf-set zone[o].template T; conf-commit
        self.knotc(&["conf-begin"]).await?;
        let set_zone = format!("zone[{origin}]");
        let set_tmpl = format!("zone[{origin}].template");
        if let Err(e) = self.knotc(&["conf-set", &set_zone]).await {
            let _ = self.knotc(&["conf-abort"]).await;
            return Err(e);
        }
        if let Err(e) = self.knotc(&["conf-set", &set_tmpl, &self.template]).await {
            let _ = self.knotc(&["conf-abort"]).await;
            return Err(e);
        }
        self.knotc(&["conf-commit"]).await?;
        self.declared.lock().unwrap().insert(origin.to_string());
        Ok(())
    }

    fn zone_path(&self, origin: &str) -> PathBuf {
        self.zone_dir.join(format!("{origin}zone"))
    }
}

#[async_trait]
impl Backend for KnotBackend {
    async fn push_zone(&self, origin: &str, zonefile: &str) -> Result<(), String> {
        let path = self.zone_path(origin);
        tokio::fs::write(&path, zonefile)
            .await
            .map_err(|e| format!("writing {}: {e}", path.display()))?;
        self.ensure_declared(origin).await?;
        self.knotc(&["zone-reload", origin]).await?;
        Ok(())
    }

    async fn remove_zone(&self, origin: &str) -> Result<(), String> {
        let unset = format!("zone[{origin}]");
        self.knotc(&["conf-begin"]).await?;
        if let Err(e) = self.knotc(&["conf-unset", &unset]).await {
            let _ = self.knotc(&["conf-abort"]).await;
            return Err(e);
        }
        self.knotc(&["conf-commit"]).await?;
        self.declared.lock().unwrap().remove(origin);
        let _ = tokio::fs::remove_file(self.zone_path(origin)).await;
        Ok(())
    }

    async fn probe(&self) -> Probe {
        match self.knotc(&["status"]).await {
            Ok(_) => Probe::Up,
            Err(_) => Probe::Down,
        }
    }

    fn name(&self) -> &'static str {
        "knot"
    }
}
