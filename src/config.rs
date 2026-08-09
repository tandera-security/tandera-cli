//! Config file (`api_url` + PAT `token`) load/save, plus the env-var
//! override rules and the never-print-the-full-token redaction helper.
//!
//! SECURITY: the config file holds a credential (the PAT). It is written
//! with `0600` permissions on unix (owner read/write only) — see
//! `restrict_permissions` below — and the token is never logged or printed
//! anywhere in full by this crate, only via `redact_token`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Used when neither `--api-url`, `TANDERA_API_URL`, nor the config file's
/// `api_url` is set.
pub const DEFAULT_API_URL: &str = "https://api.tandera.io";

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_url: Option<String>,
    /// Optional override for the console (web app) base URL used by
    /// `:portal` / `tandera portal`. Absent → derived from `api_url` by
    /// swapping the `api.` subdomain for `console.` (see `commands::portal`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assessment: Option<String>,
    /// Opt-in sync of the local testing-log to the assessment's activity
    /// timeline (see `logbook::sync_entry`). `None`/absent means OFF — the
    /// same as `Some(false)` — so a config file written before this field
    /// existed, or one that never mentions it, keeps the safe default of
    /// "local log only, no network sync". Toggled by the REPL's `:sync
    /// on|off` verb.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_testing_log: Option<bool>,
}

// SECURITY: `Config` holds a PAT. The derived `Debug` would print it in full
// if any future `{:?}` (a verbose/debug flag, a `dbg!`, a panic message) ever
// touched a `Config` — so `Debug` is implemented by hand to redact the token,
// making the never-print-the-full-token invariant compiler-enforced rather
// than convention-enforced (mirrors the API's `MintedPat`).
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("api_url", &self.api_url)
            .field(
                "token",
                &self.token.as_deref().map(redact_token).unwrap_or_default(),
            )
            .field("assessment", &self.assessment)
            .field("sync_testing_log", &self.sync_testing_log)
            .finish()
    }
}

/// `<platform config dir>/tandera/config.toml` — e.g.
/// `~/.config/tandera/config.toml` on Linux,
/// `~/Library/Application Support/tandera/config.toml` on macOS.
pub fn config_path() -> Result<PathBuf> {
    let dir = dirs::config_dir().context("could not determine the platform config directory")?;
    Ok(dir.join("tandera").join("config.toml"))
}

impl Config {
    /// Load the config file at `path`. A missing file is not an error — it
    /// just means nothing is configured yet (`Config::default()`).
    pub fn load_from(path: &Path) -> Result<Config> {
        if !path.exists() {
            return Ok(Config::default());
        }
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file at {}", path.display()))?;
        let cfg: Config = toml::from_str(&raw)
            .with_context(|| format!("failed to parse config file at {}", path.display()))?;
        Ok(cfg)
    }

    pub fn load() -> Result<Config> {
        Self::load_from(&config_path()?)
    }

    /// Write the config file at `path`, then chmod it `0600` (unix only —
    /// see `restrict_permissions`). Creates the parent directory if needed.
    pub fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create config directory {}", parent.display())
            })?;
        }
        let raw = toml::to_string_pretty(self).context("failed to serialize config")?;
        fs::write(path, raw)
            .with_context(|| format!("failed to write config file at {}", path.display()))?;
        restrict_permissions(path)?;
        Ok(())
    }

    pub fn save(&self) -> Result<()> {
        self.save_to(&config_path()?)
    }

    /// Resolution order: an explicit `--api-url` override, then
    /// `TANDERA_API_URL`, then the config file's `api_url`, then the
    /// built-in default.
    pub fn effective_api_url(&self, cli_override: Option<&str>) -> String {
        if let Some(u) = cli_override {
            if !u.is_empty() {
                return u.to_string();
            }
        }
        if let Ok(env) = std::env::var("TANDERA_API_URL") {
            if !env.is_empty() {
                return env;
            }
        }
        self.api_url
            .clone()
            .unwrap_or_else(|| DEFAULT_API_URL.to_string())
    }

    /// `TANDERA_TOKEN` takes precedence over the config file's stored
    /// token (so CI can pass a token without ever writing a config file).
    pub fn effective_token(&self) -> Option<String> {
        if let Ok(env) = std::env::var("TANDERA_TOKEN") {
            if !env.is_empty() {
                return Some(env);
            }
        }
        self.token.clone()
    }

    /// The active assessment slug/id: `--assessment` override, then
    /// `TANDERA_ASSESSMENT`, then the config file. `None` if unset.
    pub fn effective_assessment(&self, cli_override: Option<&str>) -> Option<String> {
        if let Some(a) = cli_override {
            if !a.is_empty() {
                return Some(a.to_string());
            }
        }
        if let Ok(env) = std::env::var("TANDERA_ASSESSMENT") {
            if !env.is_empty() {
                return Some(env);
            }
        }
        self.assessment.clone()
    }

    /// Whether opt-in testing-log sync is enabled. Absent/`None` (a config
    /// file that predates this field, or one that was never toggled on) is
    /// treated as OFF — the single place that default lives, so callers
    /// never repeat `.unwrap_or(false)` themselves.
    pub fn sync_testing_log_enabled(&self) -> bool {
        self.sync_testing_log.unwrap_or(false)
    }

    /// Persist the `:sync on|off` toggle to the config file at `path`.
    pub fn set_sync_testing_log(path: &Path, on: bool) -> Result<()> {
        let mut cfg = Config::load_from(path)?;
        cfg.sync_testing_log = Some(on);
        cfg.save_to(path)
    }
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)
        .with_context(|| format!("failed to stat {}", path.display()))?
        .permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)
        .with_context(|| format!("failed to chmod 0600 {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    // No portable equivalent of unix file-mode bits; non-unix platforms
    // rely on their own user-profile ACLs for this file.
    Ok(())
}

/// How many leading characters of a token are safe to display. The server
/// mints PATs with a public, indexable `token_prefix` of exactly
/// `PAT_PREFIX` (`tandera_pat_`, 12 chars) + 8 base64url characters of the
/// random body = 20 chars total (see the API's `shared::pat` module) — so
/// showing the first 20 characters of a token here shows exactly (and only)
/// that already-public prefix, never any of the secret body.
const REDACT_VISIBLE_CHARS: usize = 20;

/// The FULL token must never be printed anywhere by this CLI (not in `auth
/// status`, not in errors, not in verbose output) — every call site that
/// wants to show a token to a human must go through this function.
pub fn redact_token(token: &str) -> String {
    let visible: String = token.chars().take(REDACT_VISIBLE_CHARS).collect();
    format!("{visible}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `TANDERA_API_URL`/`TANDERA_TOKEN` are process-global state, and
    /// `cargo test` runs tests in parallel within one process by default —
    /// so any test that reads or writes them must hold this lock for its
    /// whole body, and the RAII guard below clears both vars on drop
    /// (including on a panicking assertion) so a failing test can't leave
    /// dirty env state for whichever test acquires the lock next.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvGuard(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: exclusive access to these env vars is guaranteed
            // by `ENV_LOCK`, held for this guard's entire lifetime.
            unsafe {
                std::env::remove_var("TANDERA_API_URL");
                std::env::remove_var("TANDERA_TOKEN");
                std::env::remove_var("TANDERA_ASSESSMENT");
            }
        }
    }

    fn lock_env() -> EnvGuard {
        EnvGuard(ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner()))
    }

    #[test]
    fn round_trips_and_sets_0600_permissions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");

        let cfg = Config {
            api_url: Some("https://api.example.com".to_string()),
            app_url: None,
            token: Some("tandera_pat_abcdefghijklmnopqrstuvwxyz".to_string()),
            assessment: None,
            sync_testing_log: None,
        };
        cfg.save_to(&path).expect("save");

        let loaded = Config::load_from(&path).expect("load");
        assert_eq!(loaded, cfg);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "config file must be chmod 0600");
        }
    }

    #[test]
    fn missing_file_loads_as_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nope.toml");
        let cfg = Config::load_from(&path).expect("load");
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn redact_token_never_exposes_the_secret_body() {
        let full = "tandera_pat_thisIsASecretRandomBodyThatMustNeverAppearInOutput1234567890";
        let redacted = redact_token(full);
        assert!(redacted.starts_with("tandera_pat_"));
        assert!(redacted.ends_with('…'));
        assert!(!redacted.contains("SecretRandomBody"));
        assert_eq!(redacted.chars().count(), REDACT_VISIBLE_CHARS + 1);
        assert_ne!(redacted.trim_end_matches('…'), full);
    }

    #[test]
    fn debug_never_exposes_the_full_token() {
        let cfg = Config {
            api_url: Some("https://api.example.com".to_string()),
            app_url: None,
            token: Some(
                "tandera_pat_thisIsASecretRandomBodyThatMustNeverAppearInDebug1234".to_string(),
            ),
            assessment: None,
            sync_testing_log: None,
        };
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("SecretRandomBody"), "debug output: {dbg}");
        assert!(dbg.contains("tandera_pat_"), "prefix should still show");
        assert!(dbg.contains('…'), "token should be redacted");
    }

    #[test]
    fn redact_token_handles_short_strings_without_panicking() {
        // A malformed/short token must not panic (e.g. a byte-boundary
        // slice panic) — `chars().take(n)` is a safe, boundary-aware
        // operation, unlike a raw `&token[..20]`.
        assert_eq!(redact_token("short"), "short…");
        assert_eq!(redact_token(""), "…");
    }

    #[test]
    fn effective_api_url_precedence() {
        let _guard = lock_env();
        let cfg = Config {
            api_url: Some("https://from-config.example.com".to_string()),
            app_url: None,
            token: None,
            assessment: None,
            sync_testing_log: None,
        };
        assert_eq!(
            cfg.effective_api_url(Some("https://from-flag.example.com")),
            "https://from-flag.example.com",
            "--api-url must win over everything else"
        );
        assert_eq!(
            cfg.effective_api_url(None),
            "https://from-config.example.com",
            "config file value used when no override/env is set"
        );
        let empty = Config::default();
        assert_eq!(empty.effective_api_url(None), DEFAULT_API_URL);
    }

    #[test]
    fn env_vars_override_the_config_file_but_not_a_cli_flag() {
        let _guard = lock_env();
        let cfg = Config {
            api_url: Some("https://from-config-file.example.com".to_string()),
            app_url: None,
            token: Some("tandera_pat_fromconfigfile".to_string()),
            assessment: None,
            sync_testing_log: None,
        };
        // SAFETY: exclusive access to these two var names is guaranteed by
        // `ENV_LOCK` (see `lock_env`'s doc comment above).
        unsafe {
            std::env::set_var("TANDERA_API_URL", "https://from-env.example.com");
            std::env::set_var("TANDERA_TOKEN", "tandera_pat_fromenv");
        }

        assert_eq!(cfg.effective_api_url(None), "https://from-env.example.com");
        assert_eq!(
            cfg.effective_token(),
            Some("tandera_pat_fromenv".to_string())
        );
        assert_eq!(
            cfg.effective_api_url(Some("https://from-flag.example.com")),
            "https://from-flag.example.com",
            "--api-url must still win over TANDERA_API_URL"
        );

        unsafe {
            std::env::remove_var("TANDERA_API_URL");
            std::env::remove_var("TANDERA_TOKEN");
        }

        assert_eq!(
            cfg.effective_api_url(None),
            "https://from-config-file.example.com"
        );
        assert_eq!(
            cfg.effective_token(),
            Some("tandera_pat_fromconfigfile".to_string())
        );
    }

    #[test]
    fn effective_assessment_precedence() {
        let _guard = lock_env();
        let cfg = Config {
            api_url: None,
            app_url: None,
            token: None,
            assessment: Some("from-config".to_string()),
            sync_testing_log: None,
        };
        assert_eq!(
            cfg.effective_assessment(Some("from-flag")).as_deref(),
            Some("from-flag")
        );
        assert_eq!(
            cfg.effective_assessment(None).as_deref(),
            Some("from-config")
        );
        unsafe {
            std::env::set_var("TANDERA_ASSESSMENT", "from-env");
        }
        assert_eq!(cfg.effective_assessment(None).as_deref(), Some("from-env"));
        unsafe {
            std::env::remove_var("TANDERA_ASSESSMENT");
        }
        assert_eq!(Config::default().effective_assessment(None), None);
    }

    #[test]
    fn sync_testing_log_defaults_off_and_round_trips() {
        // Default (never toggled, e.g. `Config::default()` or a config file
        // predating this field) must be OFF — sync is strictly opt-in.
        assert!(!Config::default().sync_testing_log_enabled());
        assert_eq!(Config::default().sync_testing_log, None);

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");

        Config::set_sync_testing_log(&path, true).expect("set on");
        let loaded = Config::load_from(&path).expect("load");
        assert!(loaded.sync_testing_log_enabled());
        assert_eq!(loaded.sync_testing_log, Some(true));

        Config::set_sync_testing_log(&path, false).expect("set off");
        let loaded = Config::load_from(&path).expect("load");
        assert!(!loaded.sync_testing_log_enabled());
        assert_eq!(loaded.sync_testing_log, Some(false));
    }
}
