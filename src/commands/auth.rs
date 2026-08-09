//! `tandera auth login|status|logout`. Every function here returns a plain
//! outcome enum rather than printing/exiting directly, so the
//! login-does-not-store-an-invalid-token behavior (and everything else) is
//! unit/integration-testable without spawning a subprocess.

use std::path::Path;

use anyhow::Result;

use crate::api::{ApiClient, ApiError};
use crate::config::{redact_token, Config};

pub enum LoginOutcome {
    Success { redacted_token: String },
    InvalidToken,
}

/// Verifies `token` against `{api_url}/v1/assessments` BEFORE writing
/// anything to disk. Only a 200 response causes `cfg_path` to be written
/// (with `api_url` + `token`, `0600` permissions via `Config::save_to`); a
/// 401 returns `InvalidToken` and touches the config file not at all —
/// this is what `auth_login_does_not_store_an_invalid_token` in
/// `tests/http_stub.rs` locks in.
pub fn login(cfg_path: &Path, api_url: &str, token: &str) -> Result<LoginOutcome> {
    let client = ApiClient::new(api_url, Some(token.to_string()))?;
    match client.probe_auth() {
        Ok(()) => {
            let mut cfg = Config::load_from(cfg_path)?;
            cfg.api_url = Some(api_url.to_string());
            cfg.token = Some(token.to_string());
            cfg.save_to(cfg_path)?;
            Ok(LoginOutcome::Success {
                redacted_token: redact_token(token),
            })
        }
        Err(ApiError::Unauthorized(_)) => Ok(LoginOutcome::InvalidToken),
        Err(e) => Err(anyhow::anyhow!("failed to verify token: {e}")),
    }
}

pub enum StatusOutcome {
    NotConfigured,
    Authenticated { prefix: String, api_url: String },
    Expired { prefix: String, api_url: String },
}

/// Reads whatever token is configured (env override wins, same rule as
/// every other command) and makes a lightweight authed call to confirm it
/// still works. Never returns/prints the full token — only its prefix.
pub fn status(cfg_path: &Path, api_url_override: Option<&str>) -> Result<StatusOutcome> {
    let cfg = Config::load_from(cfg_path)?;
    let token = match cfg.effective_token() {
        Some(t) => t,
        None => return Ok(StatusOutcome::NotConfigured),
    };
    let api_url = cfg.effective_api_url(api_url_override);
    let client = ApiClient::new(api_url.clone(), Some(token.clone()))?;
    let prefix = redact_token(&token);
    match client.probe_auth() {
        Ok(()) => Ok(StatusOutcome::Authenticated { prefix, api_url }),
        Err(ApiError::Unauthorized(_)) => Ok(StatusOutcome::Expired { prefix, api_url }),
        Err(e) => Err(anyhow::anyhow!("failed to check token status: {e}")),
    }
}

/// Clears the stored token from the config file (leaves `api_url` intact).
/// Returns `true` if a token was actually cleared, `false` if there was
/// nothing to clear (no file, or a file with no token).
pub fn logout(cfg_path: &Path) -> Result<bool> {
    if !cfg_path.exists() {
        return Ok(false);
    }
    let mut cfg = Config::load_from(cfg_path)?;
    let had_token = cfg.token.is_some();
    cfg.token = None;
    cfg.save_to(cfg_path)?;
    Ok(had_token)
}
