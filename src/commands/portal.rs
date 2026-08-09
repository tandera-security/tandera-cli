//! `:portal` / `tandera portal` — open the Tandera console in the browser,
//! deep-linked to the active assessment when there is one.
//!
//! The console lives on a `console.<stage>.tandera.io` subdomain, derived
//! from the configured API URL by swapping `api.` → `console.`. The URL
//! derivation is pure (and unit-tested); actually opening the browser shells
//! out to the platform opener and always prints the URL as a fallback for
//! headless/SSH sessions.

/// Used when the API URL isn't a recognizable `api.<...>` host (e.g. a
/// local/custom endpoint) and no `app_url` override is configured.
pub const DEFAULT_CONSOLE_URL: &str = "https://console.tandera.io";

/// Derive the console base URL. An explicit `app_url_override` wins; else the
/// `api.` subdomain of `api_url` is swapped for `console.`; else the default.
pub fn console_base(api_url: &str, app_url_override: Option<&str>) -> String {
    if let Some(o) = app_url_override {
        let o = o.trim();
        if !o.is_empty() {
            return o.trim_end_matches('/').to_string();
        }
    }
    if let Some((scheme, rest)) = api_url.split_once("://") {
        let host = rest.split('/').next().unwrap_or(rest);
        if let Some(after) = host.strip_prefix("api.") {
            return format!("{scheme}://console.{after}");
        }
    }
    DEFAULT_CONSOLE_URL.to_string()
}

/// The full URL to open: the console base, deep-linked to
/// `/assessments/<id>` when an assessment is active.
pub fn portal_url(
    api_url: &str,
    app_url_override: Option<&str>,
    assessment_id: Option<&str>,
) -> String {
    let base = console_base(api_url, app_url_override);
    match assessment_id {
        Some(id) if !id.is_empty() => format!("{base}/assessments/{id}"),
        _ => base,
    }
}

/// The platform browser-opener command + its fixed leading args (the URL is
/// appended by the caller). `None` on an unrecognized platform.
pub fn open_command() -> Option<(&'static str, Vec<&'static str>)> {
    if cfg!(target_os = "macos") {
        Some(("open", vec![]))
    } else if cfg!(target_os = "linux") {
        Some(("xdg-open", vec![]))
    } else if cfg!(target_os = "windows") {
        // `cmd /C start "" <url>` — the empty "" is the (required) window title.
        Some(("cmd", vec!["/C", "start", ""]))
    } else {
        None
    }
}

/// Print `url` (always — the fallback for when the browser can't launch) and
/// best-effort spawn the platform opener. Never blocks or panics.
pub fn open_url(url: &str) {
    println!("Opening {url}");
    if let Some((cmd, args)) = open_command() {
        let _ = std::process::Command::new(cmd).args(&args).arg(url).spawn();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_base_swaps_api_subdomain() {
        assert_eq!(
            console_base("https://api.tandera.io", None),
            "https://console.tandera.io"
        );
        assert_eq!(
            console_base("https://api.dev.tandera.io", None),
            "https://console.dev.tandera.io"
        );
    }

    #[test]
    fn console_base_ignores_path_and_falls_back_for_non_api_host() {
        assert_eq!(
            console_base("https://api.tandera.io/v1", None),
            "https://console.tandera.io"
        );
        assert_eq!(
            console_base("http://localhost:3000", None),
            DEFAULT_CONSOLE_URL
        );
    }

    #[test]
    fn app_url_override_wins_and_trims_trailing_slash() {
        assert_eq!(
            console_base("https://api.tandera.io", Some("https://console.local/")),
            "https://console.local"
        );
    }

    #[test]
    fn portal_url_deep_links_when_assessment_active() {
        assert_eq!(
            portal_url("https://api.tandera.io", None, Some("acme-external")),
            "https://console.tandera.io/assessments/acme-external"
        );
        assert_eq!(
            portal_url("https://api.tandera.io", None, None),
            "https://console.tandera.io"
        );
        // An empty id is treated as "no active assessment".
        assert_eq!(
            portal_url("https://api.tandera.io", None, Some("")),
            "https://console.tandera.io"
        );
    }

    #[test]
    fn open_command_is_total() {
        // Must compile + not panic on this platform.
        let _ = open_command();
    }
}
