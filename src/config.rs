//! Configuration: a single YAML file layered defaults → file → env → flags. Every key is optional;
//! omitted keys fall back to the built-in defaults. Durations are strings ("10s", "5m").

use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The full server configuration. All fields have defaults, so an empty file (or none) is valid.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Database DSN; scheme selects the engine (`sqlite://…` or `postgres://…`).
    pub db_dsn: String,
    /// Address the HTTP server binds.
    pub listen_addr: String,
    /// CIDRs allowed to connect; empty = allow all.
    pub allowed_ips: Vec<String>,
    /// Extra CIDR allow-list for `/healthcheck` + `/metrics`, on top of `allowed_ips`.
    pub ops_allowed_ips: Vec<String>,
    /// Trust reverse-proxy headers (X-Forwarded-For / X-Real-IP / X-Forwarded-Proto).
    pub trust_proxy: bool,
    /// Verbose (debug-level) logging.
    pub debug: bool,
    /// Brand shown in the web UI navbar (top-left). Default "TeleDDNS Server Manager".
    pub ui_title: String,

    /// $TTL + records created via the management API.
    pub default_ttl: u32,
    /// A/AAAA records touched via the DDNS endpoint.
    pub ddns_rr_ttl: u32,

    /// Worker tick / debounce before a push.
    #[serde(with = "humantime_serde_opt")]
    pub backend_sync_delay: Duration,
    /// Worker-liveness window for the healthcheck.
    #[serde(with = "humantime_serde_opt")]
    pub backend_sync_period: Duration,
    /// WARN if the oldest unfinished push is older than this.
    #[serde(with = "humantime_serde_opt")]
    pub warn_on_nopush: Duration,

    /// Backend: "log" (no-op) or "knot".
    pub backend: String,
    /// Directory Knot reads zone files from (must match the Knot template's storage).
    pub knot_zone_dir: String,
    /// Path to the `knotc` binary.
    pub knotc_path: String,
    /// The knot.conf template assigned to each managed zone.
    pub knot_template: String,
    /// After `knotc zone-reload`, how long to wait for Knot to actually serve the pushed SOA serial
    /// before treating the push as failed (a `zone-reload` returns as soon as it's *accepted*, so
    /// without this a zone Knot then rejects would look pushed). `0` disables the confirmation.
    #[serde(with = "humantime_serde_opt")]
    pub knot_confirm_timeout: Duration,
    /// How often to run the full sweep: re-push every zone (covers RRs transitively) and, if
    /// `knot_delete_zones`, prune backend zones under `knot_template` that aren't in the DB. Also
    /// runs once shortly after startup (the first worker tick).
    #[serde(with = "humantime_serde_opt")]
    pub full_resync_period: Duration,
    /// During the full sweep, delete backend zones declared under `knot_template` that are not in
    /// our DB (conf-unset + delete the zone file). Default on; set false to only get the
    /// push-everything half of the sweep.
    pub knot_delete_zones: bool,

    /// Days to keep audit-log rows; older rows are pruned at startup. `0` = keep forever.
    pub audit_retention_days: u32,

    /// Failed credential checks against one **account** before it is locked out (`429`). Covers the
    /// console login + TOTP step and DDNS HTTP Basic — one budget per account, whichever surface it is
    /// spent on. `0` disables.
    pub username_lockout_after: u32,
    /// How long a locked account stays locked (and how much silence resets its counter).
    #[serde(with = "humantime_serde_opt")]
    pub username_lockout_duration: Duration,
    /// Failed credential checks from one **client IP** before it is locked out — the brake on
    /// bearer-token guessing (a token names no account) and on username spraying. Keep it well above
    /// what a broken client produces: a locked address is refused *before* its credential is looked at,
    /// so a shared address (CGNAT, an office NAT) also stops valid callers. `0` disables.
    pub ip_lockout_after: u32,
    /// How long a locked address stays locked. Separate from the account window on purpose — an
    /// address is a coarser subject, so it is usually worth a shorter (or longer) lock than an account.
    #[serde(with = "humantime_serde_opt")]
    pub ip_lockout_duration: Duration,
    /// CIDRs (or bare addresses) that are **never** locked out — your office range, a monitoring probe,
    /// the NAT a device fleet shares. IPv4 and IPv6 both, and a rule written in either form matches a
    /// client that arrives in the other. Empty = no exemptions. There is no username equivalent: an
    /// account that can never lock is an account whose password can be guessed at forever.
    pub ip_lockout_allow: Vec<String>,

    /// Externally reachable base URL (scheme + host), used to derive SSO redirect URLs.
    pub public_url: String,
    /// OIDC single sign-on providers.
    pub sso_providers: Vec<SsoProvider>,
}

/// One OpenID Connect provider.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct SsoProvider {
    /// URL-safe key: the `/login/sso/<name>/…` segment and the account's `sso_provider` value.
    pub name: String,
    /// Button label on the login page.
    pub display_name: String,
    /// OIDC issuer URL (metadata is discovered at `<issuer>/.well-known/openid-configuration`).
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    /// Extra scopes (besides `openid`, which is always requested). Default `email profile`.
    pub scopes: Vec<String>,
    /// ID-token claim used as the local username. Default `email`; a corporate IdP may use
    /// `preferred_username`. `group_rules` whose `claim` equals this become username-pattern rules.
    pub username_claim: String,
    /// Create unknown users on first login (default true). Off → an admin must pre-create the account
    /// and set its `sso_provider` to this name first.
    pub auto_register: bool,
    /// Whether to auto-create rule-named groups. (Groups are always ensured on reconcile, so this is
    /// accepted for compatibility but has no effect.)
    pub create_groups: bool,
    pub group_rules: Vec<GroupRule>,
}

/// A rule mapping an IdP claim to local groups on every login.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct GroupRule {
    /// Claim to match; defaults to "email".
    pub claim: String,
    /// Exact-match value (set exactly one of equals/regex).
    pub equals: Option<String>,
    /// RE2 regex value.
    pub regex: Option<String>,
    /// Local groups this rule contributes.
    pub groups: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            db_dsn: "sqlite://teleddns.sqlite".into(),
            listen_addr: ":8080".into(),
            allowed_ips: vec![],
            ops_allowed_ips: vec![],
            trust_proxy: false,
            debug: false,
            ui_title: "TeleDDNS Server Manager".into(),
            default_ttl: 3600,
            ddns_rr_ttl: 60,
            backend_sync_delay: Duration::from_secs(10),
            backend_sync_period: Duration::from_secs(300),
            warn_on_nopush: Duration::from_secs(3600),
            backend: "log".into(),
            knot_zone_dir: "/var/lib/knot/zones".into(),
            knotc_path: "knotc".into(),
            knot_template: "master".into(),
            knot_confirm_timeout: Duration::from_secs(5),
            full_resync_period: Duration::from_secs(24 * 3600),
            knot_delete_zones: true,
            audit_retention_days: 365,
            username_lockout_after: 10,
            username_lockout_duration: Duration::from_secs(900),
            ip_lockout_after: 100,
            ip_lockout_duration: Duration::from_secs(900),
            ip_lockout_allow: vec![],
            public_url: String::new(),
            sso_providers: vec![],
        }
    }
}

impl Default for SsoProvider {
    fn default() -> Self {
        SsoProvider {
            name: String::new(),
            display_name: String::new(),
            issuer: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            scopes: vec!["openid".into(), "email".into(), "profile".into()],
            username_claim: "email".into(),
            auto_register: true,
            create_groups: false,
            group_rules: vec![],
        }
    }
}

impl Default for GroupRule {
    fn default() -> Self {
        GroupRule { claim: "email".into(), equals: None, regex: None, groups: vec![] }
    }
}

impl Config {
    /// Load config: explicit path if given, else the lookup chain
    /// `$TELEDDNS_CONFIG` → `./teleddns-server.yaml` → `/etc/teleddns/teleddns-server.yaml`.
    /// A missing file (with no explicit path) yields defaults.
    pub fn load(explicit: Option<&Path>) -> Result<Config, String> {
        let path = match explicit {
            Some(p) => Some(p.to_path_buf()),
            None => Self::lookup(),
        };
        let mut cfg = match path {
            Some(p) => {
                let text = std::fs::read_to_string(&p)
                    .map_err(|e| format!("reading config {}: {e}", p.display()))?;
                serde_yaml::from_str(&text).map_err(|e| format!("parsing config {}: {e}", p.display()))?
            }
            None => Config::default(),
        };
        cfg.apply_env();
        Ok(cfg)
    }

    fn lookup() -> Option<PathBuf> {
        if let Ok(p) = std::env::var("TELEDDNS_CONFIG") {
            if !p.is_empty() {
                return Some(PathBuf::from(p));
            }
        }
        for cand in ["./teleddns-server.yaml", "/etc/teleddns/teleddns-server.yaml"] {
            let p = PathBuf::from(cand);
            if p.exists() {
                return Some(p);
            }
        }
        None
    }

    /// A few high-value env overrides (env layer over file).
    fn apply_env(&mut self) {
        if let Ok(v) = std::env::var("TELEDDNS_DB_DSN") {
            self.db_dsn = v;
        }
        if let Ok(v) = std::env::var("TELEDDNS_LISTEN_ADDR") {
            self.listen_addr = v;
        }
        if std::env::var("TELEDDNS_DEBUG").map(|v| v == "1" || v == "true").unwrap_or(false) {
            self.debug = true;
        }
    }

    /// Normalize `listen_addr` — a leading ":" means all interfaces.
    pub fn bind_addr(&self) -> String {
        if let Some(rest) = self.listen_addr.strip_prefix(':') {
            format!("0.0.0.0:{rest}")
        } else {
            self.listen_addr.clone()
        }
    }
}

/// serde helper: (de)serialize a Duration from a humantime-ish string like "10s"/"5m"/"2h".
mod humantime_serde_opt {
    use serde::{Deserialize, Deserializer};
    use std::time::Duration;

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let s = String::deserialize(d)?;
        parse(&s).map_err(serde::de::Error::custom)
    }

    /// Parse "<n><unit>" where unit ∈ {s,m,h,d}; a bare number is seconds.
    pub fn parse(s: &str) -> Result<Duration, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("empty duration".into());
        }
        let (num, unit): (&str, &str) = match s.find(|c: char| c.is_alphabetic()) {
            Some(i) => (&s[..i], &s[i..]),
            None => (s, "s"),
        };
        let n: u64 = num.trim().parse().map_err(|_| format!("bad duration number in {s:?}"))?;
        let secs = match unit {
            "s" => n,
            "m" => n * 60,
            "h" => n * 3600,
            "d" => n * 86400,
            other => return Err(format!("unknown duration unit {other:?}")),
        };
        Ok(Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_parse() {
        let cfg = Config::default();
        assert_eq!(cfg.default_ttl, 3600);
        assert_eq!(cfg.bind_addr(), "0.0.0.0:8080");
    }

    #[test]
    fn duration_parsing() {
        assert_eq!(humantime_serde_opt::parse("10s").unwrap(), Duration::from_secs(10));
        assert_eq!(humantime_serde_opt::parse("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(humantime_serde_opt::parse("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(humantime_serde_opt::parse("42").unwrap(), Duration::from_secs(42));
        assert!(humantime_serde_opt::parse("nope").is_err());
    }

    #[test]
    fn yaml_partial_overrides_defaults() {
        let cfg: Config = serde_yaml::from_str("default_ttl: 120\nbackend: knot\n").unwrap();
        assert_eq!(cfg.default_ttl, 120);
        assert_eq!(cfg.backend, "knot");
        assert_eq!(cfg.ddns_rr_ttl, 60); // untouched default
    }
}
