//! Local testing-log: one JSONL line per executed command (attestation of
//! what ran, when, and which IPs were involved), plus (P6, opt-in) a
//! redacted sync of each entry to the assessment's activity timeline.
//!
//! SECURITY: the local `testing-log.jsonl` intentionally keeps the raw,
//! unredacted command (that's the point of a local attestation log — it's
//! evidence of exactly what ran). `redact_cmd` applies ONLY to what's ever
//! sent over the network via `sync_entry`; the two are never conflated.

use std::fs;
use std::io::Write;
use std::net::ToSocketAddrs;
use std::path::Path;

use serde::Serialize;
use uuid::Uuid;

use crate::api::{ApiClient, ApiError};

#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub ts: String,
    pub cmd: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub egress_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dur_s: Option<f64>,
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Resolve a hostname to its first IP via DNS. `host` may be a bare host or
/// `host:port`; we append `:0` if no port. Returns `None` on failure.
pub fn resolve_target_ip(host: &str) -> Option<String> {
    let hostport = if host.contains(':') {
        host.to_string()
    } else {
        format!("{host}:0")
    };
    hostport
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
        .map(|sa| sa.ip().to_string())
}

/// The literal mask substituted for anything that looks like a secret.
const MASK: &str = "*****";

/// `KEY=VALUE` keys (lowercased, leading `-`/`--` stripped) whose value is
/// always masked — covers every common password-flag spelling, not just
/// `token=`/`key=`.
const SECRET_KEYS: &[&str] = &[
    "password",
    "pass",
    "pwd",
    "secret",
    "token",
    "key",
    "apikey",
    "api_key",
    "authorization",
];

/// Mask values that look like secrets in a command line before it's ever
/// sent to the API (`sync_entry`). This is a token-walk over
/// whitespace-separated words, not a pile of regexes:
///
/// - `-p`/`--password`/`--pass` followed by another token masks that next
///   token as the value, ONLY when that next token plausibly IS a secret
///   value (see `looks_like_secret_value`) — a token that starts with `-`
///   is a flag, not a value (`mysql -u root -p --host=db` leaves
///   `--host=db` alone), and a token that's "port-like" (digits plus
///   `,`/`-`/`:`, e.g. `80,443` or `1-65535`) is nmap/masscan's `-p` port
///   spec, not a password (`nmap -p 80,443 10.0.0.5` is untouched). This
///   matches ONLY the exact flag spelling — e.g. `-p-` (nmap's port-range
///   flag, an attached suffix, not a separate value) does NOT match `-p`,
///   so `nmap -p- 10.0.0.5` passes through unchanged. The rule is
///   deliberately "next whitespace-separated token after an exact `-p`
///   word", never "starts with `-p`".
/// - An ATTACHED short-flag password, `-p<rest>` (more than the bare `-p`),
///   masks to `-p*****` — the very common `mysql -phunter2` shape — UNLESS
///   `<rest>` looks like an nmap/masscan port spec (`-p80,443`,
///   `-p1-1000`) or starts with `-` (`-p-`, nmap's "all ports" flag): those
///   pass through unchanged, same port-like guard as the space-separated
///   form.
/// - `Authorization:` (case-insensitive, quote-tolerant) masks everything
///   up to the end of its (optionally quoted) value, collapsing it to one
///   `*****`, while the header name itself is kept.
/// - `KEY=<v>` where `KEY` (lowercased, leading `-`/`--` stripped) is one of
///   `SECRET_KEYS` — `password`, `pass`, `pwd`, `secret`, `token`, `key`,
///   `apikey`, `api_key`, `authorization` — becomes `key=*****`, keeping the
///   key and masking only the value.
/// - A standalone token that looks like a long random secret (mixed
///   letters+digits, no path/URL punctuation, long enough that it's very
///   unlikely to be an ordinary word) is masked outright.
///
/// Pure — no I/O, no network — so it's unit-testable on its own.
pub fn redact_cmd(cmd: &str) -> String {
    let tokens: Vec<&str> = cmd.split_whitespace().collect();
    let mut out: Vec<String> = Vec::with_capacity(tokens.len());
    let mut i = 0;

    while i < tokens.len() {
        let tok = tokens[i];

        // `-p`/`--password`/`--pass VALUE` — exact-word match only, so
        // nmap's attached `-p-`/`-p1-100` never trips this. The next token
        // is only masked when it plausibly IS a secret value: a flag
        // (`--host=db`) or a port spec (`80,443`, `1-65535`) is left alone.
        if matches!(tok, "-p" | "--password" | "--pass") {
            out.push(tok.to_string());
            i += 1;
            if i < tokens.len() {
                let next = tokens[i];
                if looks_like_secret_value(next) {
                    out.push(MASK.to_string());
                } else {
                    out.push(next.to_string());
                }
                i += 1;
            }
            continue;
        }

        // `KEY=<v>` where `KEY` (lowercased, leading `-`/`--` stripped) is a
        // known secret-value key — e.g. `password=`, `pwd=`, `secret=`,
        // `token=`, `key=`, `apikey=`, `api_key=`, `authorization=`, and
        // their `-`/`--`-prefixed flag spellings (`--password=hunter2`).
        if let Some(eq) = tok.find('=') {
            let key = &tok[..eq];
            let normalized = key.trim_start_matches('-').to_ascii_lowercase();
            if SECRET_KEYS.contains(&normalized.as_str()) {
                out.push(format!("{}=*****", key.to_lowercase()));
                i += 1;
                continue;
            }
        }

        // Attached short-flag password: `-p<rest>` where `<rest>` is NOT
        // port-like and doesn't itself start with `-` (nmap's `-p-`,
        // `-p1-1000`, `-p80,443` are port specs, not passwords). This is
        // the very common `mysql -phunter2` shape.
        if tok.len() > 2 && tok.starts_with("-p") {
            let rest = &tok[2..];
            if !rest.starts_with('-') && !is_port_like(rest) {
                out.push(format!("-p{MASK}"));
                i += 1;
                continue;
            }
        }

        // `Authorization: <value...>` — tolerate a leading quote char
        // (`'Authorization:` / `"Authorization:`) since the header is
        // typically passed as one shell-quoted argument to `-H`.
        let bare = tok.trim_start_matches(['\'', '"']);
        if bare.eq_ignore_ascii_case("authorization:") {
            out.push(tok.to_string());
            i += 1;
            let quote_char = tok.chars().find(|c| *c == '\'' || *c == '"');
            let mut masked = false;
            while i < tokens.len() {
                let t = tokens[i];
                if !masked {
                    out.push(MASK.to_string());
                    masked = true;
                }
                i += 1;
                if let Some(qc) = quote_char {
                    if t.ends_with(qc) {
                        break;
                    }
                } else {
                    // No opening quote: the value is a single bare token.
                    break;
                }
            }
            continue;
        }

        if looks_like_secret_token(tok) {
            out.push(MASK.to_string());
            i += 1;
            continue;
        }

        out.push(tok.to_string());
        i += 1;
    }

    out.join(" ")
}

/// Disambiguates the token immediately following `-p`/`--password`/`--pass`:
/// is it plausibly the secret value, or something else entirely?
///
/// - A token starting with `-` is a flag (e.g. `--host=db`), never a value
///   for the flag before it — the value slot was skipped, not filled.
/// - A "port-like" token (starts with a digit, and every char is a digit
///   or one of `,`/`-`/`:`) is nmap/masscan's port-spec shape for `-p`
///   (`80,443`, `1-65535`, `22`), not a password.
///
/// Everything else is treated as a plausible secret and masked.
fn looks_like_secret_value(tok: &str) -> bool {
    if tok.starts_with('-') {
        return false; // a flag, not a secret
    }
    !is_port_like(tok)
}

/// "Port-like": first char is a digit and every char is a digit or one of
/// `,`/`-`/`:` — nmap/masscan's port-spec shape (`80,443`, `1-65535`, `22`),
/// shared by both the space-separated (`-p 80,443`) and attached
/// (`-p80,443`) `-p` forms so a port spec is never mistaken for a password.
fn is_port_like(tok: &str) -> bool {
    tok.chars().next().is_some_and(|c| c.is_ascii_digit())
        && tok
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, ',' | '-' | ':'))
}

/// Heuristic for "this standalone word is probably a secret", not "this
/// is definitely a secret": long, no path/URL/email punctuation, and a mix
/// of letters and digits (plain English words and hostnames rarely have
/// both). Deliberately conservative — a false negative just means a token
/// wasn't masked, but a false positive would corrupt a legitimate argument
/// in the synced summary, so length and character-set checks lean strict.
fn looks_like_secret_token(tok: &str) -> bool {
    const MIN_LEN: usize = 20;
    if tok.len() < MIN_LEN {
        return false;
    }
    let allowed = tok
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !allowed {
        return false;
    }
    let has_digit = tok.chars().any(|c| c.is_ascii_digit());
    let has_alpha = tok.chars().any(|c| c.is_ascii_alphabetic());
    has_digit && has_alpha
}

/// POST a redacted summary of `entry` to the assessment's activity
/// timeline. Called ONLY when the operator opted in
/// (`Config.sync_testing_log == Some(true)`) — see `Session::log_command`.
///
/// SECURITY: the payload's `cmd` field is always `redact_cmd(&entry.cmd)`,
/// never `entry.cmd` itself — the raw command (which may contain
/// passwords/tokens) is never sent over the network, only what stays in
/// the local `testing-log.jsonl`.
pub fn sync_entry(client: &ApiClient, aid: Uuid, entry: &LogEntry) -> Result<(), ApiError> {
    #[derive(Serialize)]
    struct ActivityPayload<'a> {
        ts: &'a str,
        cmd: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        target: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        exit: Option<i32>,
    }
    let payload = ActivityPayload {
        ts: &entry.ts,
        cmd: redact_cmd(&entry.cmd),
        target: entry.target.as_deref(),
        exit: entry.exit,
    };
    let path = format!("/v1/assessments/{aid}/activity");
    client.post_json::<_, serde_json::Value>(&path, &payload)?;
    Ok(())
}

/// Append one JSONL entry; create the parent dir and chmod the file 0600.
pub fn append(path: &Path, entry: &LogEntry) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let line = serde_json::to_string(entry).map_err(std::io::Error::other)?;
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = f.metadata()?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    writeln!(f, "{line}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_writes_one_jsonl_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".tandera/testing-log.jsonl");
        let e = LogEntry {
            ts: "2026-07-11T14:02:09Z".into(),
            cmd: "nmap -p- 10.0.0.5".into(),
            kind: "wrapped".into(),
            egress_ip: None,
            target: Some("10.0.0.5".into()),
            target_ip: Some("10.0.0.5".into()),
            exit: Some(0),
            dur_s: Some(412.0),
        };
        append(&path, &e).unwrap();
        append(&path, &e).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body.lines().count(), 2);
        assert!(body.lines().next().unwrap().starts_with('{'));
    }

    #[test]
    fn resolve_localhost() {
        let ip = resolve_target_ip("localhost");
        assert!(ip == Some("127.0.0.1".into()) || ip == Some("::1".into()) || ip.is_some());
    }

    #[test]
    fn resolve_bad_host_is_none() {
        assert!(resolve_target_ip("nonexistent.invalid.").is_none());
    }

    #[test]
    fn redact_masks_password_flags_and_tokens() {
        assert_eq!(
            redact_cmd("mysql -u root -p hunter2 db"),
            "mysql -u root -p ***** db"
        );
        let out = redact_cmd("curl -H 'Authorization: Bearer abc.def.ghi' http://x");
        assert!(out.contains("Authorization: *****"));
        assert!(!out.contains("abc.def.ghi"));
    }

    #[test]
    fn redact_leaves_nmap_port_range_flag_alone() {
        // `-p-` is nmap's "all ports" flag, an attached suffix — not the
        // `-p <value>` password-flag shape (a bare `-p` word followed by a
        // separate token). Must pass through byte-for-byte unchanged.
        assert_eq!(redact_cmd("nmap -p- 10.0.0.5"), "nmap -p- 10.0.0.5");
        assert_eq!(
            redact_cmd("nmap -p1-1000 10.0.0.5"),
            "nmap -p1-1000 10.0.0.5"
        );
    }

    #[test]
    fn redact_masks_long_options_and_key_value_pairs() {
        assert_eq!(
            redact_cmd("mysql -u root --password hunter2verylong db"),
            "mysql -u root --password ***** db"
        );
        assert_eq!(
            redact_cmd("curl -H token=abc123 http://x"),
            "curl -H token=***** http://x"
        );
        assert_eq!(
            redact_cmd("curl -H KEY=abc123 http://x"),
            "curl -H key=***** http://x"
        );
    }

    #[test]
    fn redact_masks_standalone_long_random_looking_tokens() {
        let out = redact_cmd("curl -H x-api-key9f3a7c21e8b4d6f0a5c2 http://x");
        assert!(!out.contains("x-api-key9f3a7c21e8b4d6f0a5c2"));
        assert!(out.contains("*****"));
    }

    #[test]
    fn redact_leaves_p_followed_by_flag_alone() {
        // `-p` followed by ANOTHER FLAG must not be treated as a password —
        // the value slot was skipped, not filled.
        assert_eq!(
            redact_cmd("mysql -u root -p --host=db"),
            "mysql -u root -p --host=db"
        );
    }

    #[test]
    fn redact_leaves_nmap_space_separated_ports_alone() {
        // nmap/masscan's `-p <ports>` — space-separated, not the attached
        // `-p-`/`-p1-1000` suffix form — must not be masked as a password.
        assert_eq!(
            redact_cmd("nmap -p 80,443 10.0.0.5"),
            "nmap -p 80,443 10.0.0.5"
        );
    }

    #[test]
    fn redact_masks_password_arg() {
        assert_eq!(
            redact_cmd("mysql -u root -p hunter2 db"),
            "mysql -u root -p ***** db"
        );
    }

    #[test]
    fn redact_masks_long_password_flag() {
        let out = redact_cmd("app --password s3cr3tPass");
        assert!(!out.contains("s3cr3tPass"));
        assert!(out.contains("*****"));
    }

    #[test]
    fn redact_does_not_mangle_ordinary_commands() {
        assert_eq!(
            redact_cmd("httpx -u example.com -json"),
            "httpx -u example.com -json"
        );
        assert_eq!(
            redact_cmd("nmap -sV -oX out.xml 10.0.0.5"),
            "nmap -sV -oX out.xml 10.0.0.5"
        );
    }

    #[test]
    fn redact_masks_equals_joined_password_flag() {
        assert_eq!(
            redact_cmd("mysql --password=hunter2"),
            "mysql --password=*****"
        );
    }

    #[test]
    fn redact_masks_attached_short_flag_password() {
        assert_eq!(redact_cmd("mysql -phunter2"), "mysql -p*****");
    }

    #[test]
    fn redact_masks_bare_key_value_password() {
        assert_eq!(redact_cmd("password=hunter2"), "password=*****");
    }

    #[test]
    fn redact_masks_other_common_secret_key_spellings() {
        assert_eq!(redact_cmd("pwd=hunter2"), "pwd=*****");
        assert_eq!(redact_cmd("secret=hunter2"), "secret=*****");
        assert_eq!(redact_cmd("apikey=abc123def456"), "apikey=*****");
        assert_eq!(redact_cmd("api_key=abc123def456"), "api_key=*****");
        assert_eq!(redact_cmd("pass=hunter2"), "pass=*****");
    }

    #[test]
    fn redact_leaves_attached_nmap_port_specs_alone() {
        assert_eq!(
            redact_cmd("nmap -p80,443 10.0.0.5"),
            "nmap -p80,443 10.0.0.5"
        );
        assert_eq!(redact_cmd("nmap -p- 10.0.0.5"), "nmap -p- 10.0.0.5");
    }

    #[test]
    fn redact_leaves_nmap_space_separated_port_flag_alone_again() {
        assert_eq!(redact_cmd("nmap -p 80,443 host"), "nmap -p 80,443 host");
    }

    #[test]
    fn redact_masks_password_value_in_space_separated_p_flag() {
        assert_eq!(
            redact_cmd("mysql -u root -p hunter2 db"),
            "mysql -u root -p ***** db"
        );
    }
}
