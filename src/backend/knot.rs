//! The `knot` backend: write the full zone file, declare the zone in Knot's config DB on its first
//! push (idempotent, cached), and `knotc zone-reload`. Everything cluster-static (ACLs, TSIG, catalog
//! membership) lives in the operator's base knot.conf template — this backend only assigns it.

use super::{Backend, Probe, Status};
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;
use tokio::process::Command;

pub struct KnotBackend {
    zone_dir: PathBuf,
    knotc: String,
    /// Every template this server considers **ours**, for orphan pruning — the default plus the
    /// configured allow-list. See [`KnotBackend::list_managed_zones`]. There is deliberately no
    /// `default_template` here: the worker resolves a zone's template before calling `push_zone`,
    /// so a backend never has to decide what a zone with no template of its own means.
    owned_templates: HashSet<String>,
    /// How long to wait for Knot to serve a pushed serial before failing the push.
    confirm_timeout: Duration,
    /// `origin → template` already declared in Knot's config DB this process, so a repeat push is
    /// not a repeat `conf-set`. Keyed by *both*, because a zone whose template changed needs
    /// re-declaring and an origin-only cache would silently skip it.
    declared: Mutex<HashMap<String, String>>,
}

impl KnotBackend {
    pub fn new(cfg: &crate::config::Config) -> Self {
        let mut owned_templates: HashSet<String> = cfg.knot_templates.iter().cloned().collect();
        owned_templates.insert(cfg.default_knot_template.clone());
        KnotBackend {
            zone_dir: PathBuf::from(&cfg.knot_zone_dir),
            knotc: cfg.knotc_path.clone(),
            owned_templates,
            confirm_timeout: cfg.knot_confirm_timeout,
            declared: Mutex::new(HashMap::new()),
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

    /// The template Knot currently has this zone under, if the zone is declared at all. `conf-read`
    /// reads the committed config (no transaction), unlike `conf-get` which needs an open one.
    ///
    /// `Some("")` is a declared zone with no template — possible if an operator declared it by hand.
    /// `None` means not declared.
    async fn declared_template(&self, origin: &str) -> Option<String> {
        self.knotc(&["conf-read", &format!("zone[{origin}]")]).await.ok()?;
        let out = self
            .knotc(&["conf-read", &format!("zone[{origin}].template")])
            .await
            .unwrap_or_default();
        Some(parse_conf_value(&out))
    }

    /// All origins declared in Knot's committed config under a template we own, for orphan pruning.
    ///
    /// "Ours" is `default_knot_template` ∪ `knot_templates`, and that set is the whole reason the
    /// allow-list is worth configuring: a zone pushed under a template named in *neither* is
    /// invisible here. It is never wrongly deleted — the answer is "not ours" and pruning leaves it
    /// alone — but it is also never recognised, so an orphan under a forgotten template lingers
    /// forever. Populate `knot_templates` the day a second template exists.
    ///
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
            if self.owned_templates.contains(parse_conf_value(&tmpl).as_str()) {
                result.insert(origin);
            }
        }
        Ok(result)
    }

    /// Ensure the zone is declared in Knot under `template`. Idempotent across process restarts: a
    /// zone already declared under the same template is left alone (Knot rejects re-declaring an
    /// existing `zone[...]` with a "duplicate identifier" error), so a restart doesn't wedge pushes.
    ///
    /// A zone whose template has **changed** — an operator moving it onto a signing policy — is the
    /// case an origin-keyed cache would get wrong, so the cache holds the template too and a
    /// mismatch re-sets it. Moving a zone under a `dnssec-signing` template is how signing is turned
    /// on, so this path is the feature, not an edge case.
    async fn ensure_declared(&self, origin: &str, template: &str) -> Result<(), String> {
        if self.declared.lock().unwrap().get(origin).is_some_and(|t| t == template) {
            return Ok(());
        }
        let current = self.declared_template(origin).await;
        if current.as_deref() == Some(template) {
            // Already right in the committed config (e.g. declared before a restart) → cache it.
            self.declared.lock().unwrap().insert(origin.to_string(), template.to_string());
            return Ok(());
        }
        let declared = current.is_some();
        // conf-begin; [conf-set zone[o];] conf-set zone[o].template T; conf-commit
        self.knotc(&["conf-begin"]).await?;
        let set_zone = format!("zone[{origin}]");
        let set_tmpl = format!("zone[{origin}].template");
        let apply = async || -> Result<(), String> {
            if !declared {
                self.knotc(&["conf-set", &set_zone]).await?;
            }
            self.knotc(&["conf-set", &set_tmpl, template]).await?;
            Ok(())
        };
        if let Err(e) = apply().await {
            let _ = self.knotc(&["conf-abort"]).await;
            return Err(e);
        }
        self.knotc(&["conf-commit"]).await?;
        self.declared.lock().unwrap().insert(origin.to_string(), template.to_string());
        match current {
            Some(was) => tracing::warn!(%origin, %was, now = %template, "moved zone to another Knot template"),
            None => tracing::info!(%origin, %template, "declared zone in Knot config"),
        }
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

/// The value out of a `knotc conf-read <item>` line. knotc answers `zone[example.com.].template = \
/// master`, but an older/terser build just prints the value, so take what follows the last `=` and
/// fall back to the whole line. Empty when the item is unset.
fn parse_conf_value(out: &str) -> String {
    let line = out.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    line.rsplit_once('=').map(|(_, v)| v).unwrap_or(line).trim().to_string()
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
    async fn push_zone(
        &self,
        origin: &str,
        zonefile: &str,
        serial: i64,
        template: &str,
    ) -> Result<(), String> {
        let path = self.zone_path(origin);
        self.ensure_zone_dir(&path).await?;
        tokio::fs::write(&path, zonefile)
            .await
            .map_err(|e| format!("writing {}: {e}", path.display()))?;
        tracing::info!(%origin, serial, bytes = zonefile.len(), path = %path.display(), "wrote zone file");
        self.ensure_declared(origin, template).await?;
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

    async fn status(&self) -> Status {
        // `knotc status` is both the liveness probe and the one line worth showing an operator
        // (knotd's version and configuration summary), so it is one spawn, not two.
        match self.knotc(&["status"]).await {
            Ok(out) => Status {
                probe: Probe::Up,
                detail: Some(out.split('\n').next().unwrap_or("").trim().to_string())
                    .filter(|s| !s.is_empty()),
                error: None,
            },
            Err(e) => Status { probe: Probe::Down, detail: None, error: Some(e) },
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

    /// Which template a zone is under decides whether orphan-pruning may delete it, so misreading
    /// `conf-read` output is a way to delete someone else's zone. Both output shapes knotc produces
    /// must give the bare value, and an unset item must give the empty string, not the whole line.
    #[test]
    fn parses_a_conf_value_in_either_knotc_output_shape() {
        assert_eq!(parse_conf_value("zone[example.com.].template = master"), "master");
        assert_eq!(parse_conf_value("master\n"), "master");
        assert_eq!(parse_conf_value("  dnssec-signing  "), "dnssec-signing");
        assert_eq!(parse_conf_value(""), "");
        assert_eq!(parse_conf_value("\n\n"), "");
        // An item that exists but is unset prints the key with nothing after the `=`.
        assert_eq!(parse_conf_value("zone[example.com.].template ="), "");
    }

    /// "Ours" for orphan pruning is the default template **plus** the allow-list. A zone under a
    /// template in neither is not ours — left alone, never deleted — which is the whole reason
    /// `knot_templates` is worth configuring once a second template exists.
    #[test]
    fn owned_templates_is_the_default_plus_the_allow_list() {
        let mut cfg = crate::config::Config {
            default_knot_template: "master".into(),
            knot_templates: vec!["signed".into(), "master".into()],
            ..Default::default()
        };
        let b = KnotBackend::new(&cfg);
        assert!(b.owned_templates.contains("master"));
        assert!(b.owned_templates.contains("signed"));
        assert!(!b.owned_templates.contains("someone-elses"));

        // The default is always ours, even when the operator forgot to list it.
        cfg.knot_templates = vec!["signed".into()];
        assert!(KnotBackend::new(&cfg).owned_templates.contains("master"));
    }
}
