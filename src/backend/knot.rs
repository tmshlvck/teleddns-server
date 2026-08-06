//! The `knot` backend: write the full zone file, declare the zone in Knot's config DB on its first
//! push (idempotent, cached), and `knotc zone-reload`. Everything cluster-static (ACLs, TSIG, catalog
//! membership) lives in the operator's base knot.conf template — this backend only assigns it.

use super::{Backend, Probe};
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;
use tokio::process::Command;

pub struct KnotBackend {
    zone_dir: PathBuf,
    knotc: String,
    template: String,
    /// How long to wait for Knot to serve a pushed serial before failing the push.
    confirm_timeout: Duration,
    /// Origins already declared in Knot's config DB this process (avoids repeat conf-set).
    declared: Mutex<HashSet<String>>,
}

impl KnotBackend {
    pub fn new(cfg: &crate::config::Config) -> Self {
        KnotBackend {
            zone_dir: PathBuf::from(&cfg.knot_zone_dir),
            knotc: cfg.knotc_path.clone(),
            template: cfg.knot_template.clone(),
            confirm_timeout: cfg.knot_confirm_timeout,
            declared: Mutex::new(HashSet::new()),
        }
    }

    /// Run `knotc` with args. On failure the error carries the command, the exit code, and both
    /// stderr and stdout (knotc prints some errors to stdout, e.g. `error: (duplicate identifier)`).
    async fn knotc(&self, args: &[&str]) -> Result<String, String> {
        tracing::debug!(?args, "knotc");
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

    /// Poll `knotc zone-status <origin> +serial` until Knot serves a serial ≥ `want`, or the confirm
    /// timeout elapses. A `zone-reload` returns as soon as it's *accepted*; this is what actually
    /// proves Knot loaded the file (a rejected zone keeps the old, lower serial → this errors).
    async fn confirm_serial(&self, origin: &str, want: i64) -> Result<(), String> {
        if self.confirm_timeout.is_zero() {
            return Ok(());
        }
        let deadline = tokio::time::Instant::now() + self.confirm_timeout;
        let mut last: Option<i64> = None;
        loop {
            // Ignore transient probe errors; keep polling until the serial appears or we time out.
            if let Ok(out) = self.knotc(&["zone-status", origin, "+serial"]).await {
                if let Some(cur) = parse_one_serial(&out) {
                    last = Some(cur);
                    if cur >= want {
                        return Ok(());
                    }
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "reloaded but Knot is not serving serial {want} within {:?} (last seen {})",
                    self.confirm_timeout,
                    last.map(|s| s.to_string()).unwrap_or_else(|| "none".into()),
                ));
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }

    /// Whether the zone is already declared in Knot's committed configuration. `conf-read` reads the
    /// committed config (no transaction), unlike `conf-get` which needs an open transaction.
    async fn already_declared(&self, origin: &str) -> bool {
        self.knotc(&["conf-read", &format!("zone[{origin}]")]).await.is_ok()
    }

    /// All origins declared in Knot's committed config under `self.template`, for orphan pruning.
    /// Best-effort: an origin whose template can't be determined is left out rather than risking a
    /// wrong deletion; a single per-origin `knotc` failure only skips that origin.
    async fn list_managed_zones(&self) -> Result<HashSet<String>, String> {
        let out = self.knotc(&["conf-read", "zone"]).await?;
        let mut result = HashSet::new();
        for origin in parse_zone_list(&out) {
            let tmpl = self
                .knotc(&["conf-read", &format!("zone[{origin}].template")])
                .await
                .unwrap_or_default();
            if tmpl.trim() == self.template {
                result.insert(origin);
            }
        }
        Ok(result)
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
        tracing::info!(%origin, template = %self.template, "declared zone in Knot config");
        Ok(())
    }

    fn zone_path(&self, origin: &str) -> PathBuf {
        self.zone_dir.join(format!("{origin}zone"))
    }

    /// An RFC 2317 origin (`0/27.62.185.83.in-addr.arpa.`) carries a slash, and Knot's `%s` file
    /// formatter writes it out literally (libknot escapes everything *except* alphanumerics, `-`,
    /// `_`, `*` and `/`), so the path it expects has a directory component we have to create — or
    /// every push of that zone fails with ENOENT. A no-op for every ordinary origin.
    async fn ensure_zone_dir(&self, path: &std::path::Path) -> Result<(), String> {
        let Some(dir) = path.parent().filter(|d| *d != self.zone_dir) else {
            return Ok(());
        };
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|e| format!("creating {}: {e}", dir.display()))
    }
}

/// Extract the first parseable serial from `knotc zone-status … +serial` output (a line like
/// `[example.com.] serial: 2024010101`). `serial: none` / `-` → `None`.
fn parse_one_serial(out: &str) -> Option<i64> {
    for line in out.lines() {
        if let Some(rest) = line.split("serial:").nth(1) {
            let tok = rest.trim().split(|c: char| c.is_whitespace() || c == '|').next().unwrap_or("");
            if let Ok(n) = tok.parse::<i64>() {
                return Some(n);
            }
        }
    }
    None
}

/// Parse `knotc conf-read zone` (all declared zones): one `zone[origin]` line per zone.
fn parse_zone_list(out: &str) -> Vec<String> {
    out.lines()
        .filter_map(|line| line.split('[').nth(1).and_then(|s| s.split(']').next()))
        .map(|s| s.trim().to_string())
        .collect()
}

/// Parse `knotc zone-status +serial` (all zones): one `[origin] … serial: N` line per zone.
fn parse_serial_map(out: &str) -> HashMap<String, i64> {
    let mut m = HashMap::new();
    for line in out.lines() {
        let origin = line.split('[').nth(1).and_then(|s| s.split(']').next());
        let serial = line.split("serial:").nth(1).and_then(|rest| {
            rest.trim().split(|c: char| c.is_whitespace() || c == '|').next().and_then(|t| t.parse::<i64>().ok())
        });
        if let (Some(o), Some(s)) = (origin, serial) {
            m.insert(o.trim().to_string(), s);
        }
    }
    m
}

#[async_trait]
impl Backend for KnotBackend {
    async fn push_zone(&self, origin: &str, zonefile: &str, serial: i64) -> Result<(), String> {
        let path = self.zone_path(origin);
        self.ensure_zone_dir(&path).await?;
        tokio::fs::write(&path, zonefile)
            .await
            .map_err(|e| format!("writing {}: {e}", path.display()))?;
        tracing::info!(%origin, serial, bytes = zonefile.len(), path = %path.display(), "wrote zone file");
        self.ensure_declared(origin).await?;
        self.knotc(&["zone-reload", origin]).await?;
        // A reload only means "accepted" — confirm Knot actually loaded it and serves the serial.
        self.confirm_serial(origin, serial).await?;
        tracing::info!(%origin, serial, "zone reloaded and serving");
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

    async fn zone_serials(&self) -> Result<Option<HashMap<String, i64>>, String> {
        let out = self.knotc(&["zone-status", "+serial"]).await?;
        Ok(Some(parse_serial_map(&out)))
    }

    async fn managed_zones(&self) -> Result<Option<HashSet<String>>, String> {
        self.list_managed_zones().await.map(Some)
    }

    fn name(&self) -> &'static str {
        "knot"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_and_map_serials() {
        assert_eq!(parse_one_serial("[example.com.] serial: 2024010101"), Some(2024010101));
        assert_eq!(parse_one_serial("[ns1.example.com.] serial: 42 | role: master"), Some(42));
        assert_eq!(parse_one_serial("[example.com.] serial: none"), None);

        let m = parse_serial_map("[a.com.] serial: 5\n[b.com.] serial: 9\n[bad.com.] serial: none\n");
        assert_eq!(m.get("a.com."), Some(&5));
        assert_eq!(m.get("b.com."), Some(&9));
        assert_eq!(m.get("bad.com."), None);
    }

    #[test]
    fn parses_zone_list() {
        let out = "zone[a.com.]\nzone[b.com.]\n";
        assert_eq!(parse_zone_list(out), vec!["a.com.".to_string(), "b.com.".to_string()]);
        assert!(parse_zone_list("").is_empty());
    }
}
