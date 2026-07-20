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

    /// Run `knotc` with args. On failure the error carries the command, the exit code, and both
    /// stderr and stdout (knotc prints some errors to stdout, e.g. `error: (duplicate identifier)`).
    async fn knotc(&self, args: &[&str]) -> Result<String, String> {
        let out = Command::new(&self.knotc)
            .args(args)
            .output()
            .await
            .map_err(|e| format!("spawn {} {:?}: {e}", self.knotc, args))?;
        if !out.status.success() {
            let code = out
                .status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".into());
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            let detail = format!("{} {}", stderr.trim(), stdout.trim());
            return Err(format!("knotc {:?} exited {code}: {}", args, detail.trim()));
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }

    /// Whether the zone is already declared in Knot's committed configuration. `conf-read` reads the
    /// committed config (no transaction), unlike `conf-get` which needs an open transaction.
    async fn already_declared(&self, origin: &str) -> bool {
        self.knotc(&["conf-read", &format!("zone[{origin}]")]).await.is_ok()
    }

    /// Ensure the zone is declared as a member of the configured template. Idempotent across process
    /// restarts: if the zone is already in Knot's config we do nothing (Knot rejects re-declaring an
    /// existing `zone[...]` with a "duplicate identifier" error), so a restart doesn't wedge pushes.
    async fn ensure_declared(&self, origin: &str) -> Result<(), String> {
        if self.declared.lock().unwrap().contains(origin) {
            return Ok(());
        }
        // Already in the running config (e.g. declared before a restart) → just cache and move on.
        if self.already_declared(origin).await {
            self.declared.lock().unwrap().insert(origin.to_string());
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
