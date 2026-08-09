//! Natural language phrase parser for `:finding` in the interactive shell,
//! plus the `:finding`/`:paste` API-hitting flow itself: `create_from_phrase`
//! (natural-language phrase -> AI draft finding, optionally with a clipboard
//! screenshot attached) and `attach_image` (the presigned
//! upload-url -> S3 PUT -> confirm sequence, reused by `:paste`).
//!
//! The presigned-upload shape mirrors `capture::import::upload_file`'s
//! upload-url -> PUT -> confirm pipeline (same reasoning, same
//! `ApiClient::put_bytes_to_url` no-auth-header guarantee — see that
//! module's doc) but isn't literally the same code: an attachment's
//! upload-url request/response and its dedicated `.../confirm` route are a
//! distinct resource from an import, so the shapes (and endpoints) differ
//! enough that sharing more than the tolerant-response-parsing helper
//! (`models::first_present`, used by both `UploadUrlResponse` and
//! `AttachmentUploadUrlResponse`) would be a false abstraction.

use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use crate::api::{ApiClient, ApiError};
use crate::models::{AiDraftRequest, AttachmentUploadUrlResponse};

/// Parsed finding from natural language input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedFinding {
    /// The finding's title (the phrase without the trailing ` in <url>` clause).
    pub title: String,
    /// The inferred category: one of the 15 API `FindingCategory` wire values
    /// (`injection`, `client_side`, `ssrf`, etc.), or `other` if unrecognized.
    pub category: String,
    /// The optional URL extracted from a trailing ` in <url>` clause.
    pub url: Option<String>,
}

/// Parse a natural-language finding phrase into title, category, and optional URL.
///
/// # Behavior
/// - Splits off a trailing ` in <url>` clause (the last ` in ` whose tail looks like
///   a URL/host: starts with `http`, contains `://`, or looks like a hostname/path).
/// - Scans the phrase (lowercased) against a keyword→category map. Recognized keywords:
///   - `sql` → `injection`
///   - `xss` → `client_side`
///   - `ssrf` → `ssrf`
///   - `xxe` → `xxe`
///   - `idor`, `access control` → `access_control`
///   - `rce`, `command inj` → `injection`
///   - Anything else defaults to `other`.
/// - Returns the phase minus the URL clause (trimmed) as the title.
pub fn parse_finding_phrase(input: &str) -> ParsedFinding {
    let (title, url) = split_url_clause(input);
    let category = infer_category(title);

    ParsedFinding {
        title: title.to_string(),
        category,
        url,
    }
}

/// Split a phrase into (title, url) by detecting and removing a trailing
/// ` in <url>` clause. Only treats the tail as a URL if it looks URL-shaped
/// (starts with `http`, contains `://`, or looks like a host/path).
fn split_url_clause(phrase: &str) -> (&str, Option<String>) {
    // Find the last occurrence of " in " in the phrase.
    let phrase_lower = phrase.to_lowercase();
    let delimiter = " in ";

    // Search for the last ` in ` in the lowercased version to find the index.
    if let Some(last_in_pos) = phrase_lower.rfind(delimiter) {
        // Extract the tail after the last ` in `.
        let tail_start = last_in_pos + delimiter.len();
        let tail = &phrase[tail_start..];

        // Check if the tail looks URL-shaped.
        if is_url_like(tail) {
            // The title is everything before the ` in `, trimmed.
            let title = phrase[..last_in_pos].trim();
            return (title, Some(tail.to_string()));
        }
    }

    // No URL clause detected; the whole phrase is the title.
    (phrase.trim(), None)
}

/// Check if a string looks like a URL or hostname.
fn is_url_like(s: &str) -> bool {
    let trimmed = s.trim();
    // Looks like a URL if it starts with http, contains ://, or contains a dot (likely a domain).
    trimmed.starts_with("http") || trimmed.contains("://") || trimmed.contains('.')
}

/// Infer the finding category from a phrase by keyword scanning.
fn infer_category(phrase: &str) -> String {
    let lower = phrase.to_lowercase();

    // Keyword map: a vec of (keyword, category) tuples.
    // Order matters: more specific keywords should come before broader ones.
    let keyword_map = vec![
        // SQL injection variants
        ("sql", "injection"),
        // XSS variants
        ("xss", "client_side"),
        ("cross-site scripting", "client_side"),
        // SSRF
        ("ssrf", "ssrf"),
        // XXE
        ("xxe", "xxe"),
        ("xml external entity", "xxe"),
        // IDOR / access control
        ("idor", "access_control"),
        ("access control", "access_control"),
        // RCE / command injection
        ("rce", "injection"),
        ("remote code execution", "injection"),
        ("command injection", "injection"),
        ("command inj", "injection"),
    ];

    // Scan for keywords in the lowercased phrase.
    for (keyword, category) in keyword_map {
        if lower.contains(keyword) {
            return category.to_string();
        }
    }

    // Default to `other` if no keywords matched.
    "other".to_string()
}

/// The finding just created by `create_from_phrase` — only what a receipt
/// line needs to print (`display_code` if the response had one, else the
/// caller falls back to `id`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedFinding {
    pub id: Uuid,
    pub display_code: Option<String>,
}

#[derive(Serialize)]
struct AttachmentUploadUrlRequest<'a> {
    file_name: &'a str,
    content_type: &'a str,
}

/// Build an `AiDraftRequest` from a parsed phrase + operator-chosen
/// `severity`, call the existing `findings::ai_draft`, parse the created
/// finding's id (+ display code) out of the response, and — if `image` is
/// `Some` — attach it via `attach_image`. `severity` and `parsed.category`
/// are entirely operator-owned inputs; `note` (the raw phrase) is the only
/// thing handed to the model, matching `ai_draft`'s existing contract that
/// severity/category are never model-set.
pub fn create_from_phrase(
    client: &ApiClient,
    aid: Uuid,
    parsed: &ParsedFinding,
    severity: &str,
    note: &str,
    image: Option<Vec<u8>>,
) -> Result<CreatedFinding, ApiError> {
    let req = AiDraftRequest {
        category: parsed.category.clone(),
        severity: severity.to_string(),
        cwes: Vec::new(),
        cvss_vector: None,
        asset_id: None,
        note: Some(note.to_string()),
        language: "en".to_string(),
        artifacts: Vec::new(),
    };
    let raw = super::findings::ai_draft(client, aid, &req)?;
    let id = extract_finding_id(&raw).ok_or_else(|| {
        ApiError::Transport(
            "ai-draft response did not include a recognizable finding id (tried a top-level \
             `id`/`finding_id`, and the same under a nested `finding` object)"
                .to_string(),
        )
    })?;
    let display_code = extract_display_code(&raw);

    if let Some(png) = image {
        attach_image(client, aid, id, png)?;
    }

    Ok(CreatedFinding { id, display_code })
}

/// Attach a PNG screenshot to an existing finding: request a presigned
/// upload URL, PUT the bytes to it (no Tandera auth header — see
/// `ApiClient::put_bytes_to_url`'s doc), then confirm the upload. Reused by
/// both `create_from_phrase` (when `:finding` captured a screenshot at
/// creation time) and `:paste` (attaching to the last-created finding
/// after the fact).
pub fn attach_image(
    client: &ApiClient,
    aid: Uuid,
    finding_id: Uuid,
    png: Vec<u8>,
) -> Result<(), ApiError> {
    let resp: AttachmentUploadUrlResponse = client.post_json(
        &format!("/v1/assessments/{aid}/findings/{finding_id}/attachments"),
        &AttachmentUploadUrlRequest {
            file_name: "screenshot.png",
            content_type: "image/png",
        },
    )?;
    let upload_url = resp
        .resolved_upload_url()
        .ok_or_else(|| {
            ApiError::Transport(
                "attachment upload-url response did not include an upload URL".to_string(),
            )
        })?
        .to_string();
    let attachment_id = resp
        .resolved_attachment_id()
        .ok_or_else(|| {
            ApiError::Transport(
                "attachment upload-url response did not include an attachment id".to_string(),
            )
        })?
        .to_string();

    client.put_bytes_to_url(&upload_url, png, "image/png")?;

    let _: Value = client.post_json(
        &format!("/v1/assessments/{aid}/findings/{finding_id}/attachments/{attachment_id}/confirm"),
        &serde_json::json!({}),
    )?;
    Ok(())
}

/// Defensively pulls a finding id out of the `ai-draft` response. The exact
/// shape wasn't confirmed against a schema when this was written, so this
/// tries, in order: a top-level `id`, a top-level `finding_id`, then the
/// same two keys nested under a `finding` object (in case the response
/// wraps the created finding rather than returning it bare).
fn extract_finding_id(raw: &Value) -> Option<Uuid> {
    for key in ["id", "finding_id"] {
        if let Some(s) = raw.get(key).and_then(Value::as_str) {
            if let Ok(id) = Uuid::parse_str(s) {
                return Some(id);
            }
        }
    }
    raw.get("finding").and_then(extract_finding_id)
}

/// Same defensive strategy as `extract_finding_id`, for the human-facing
/// `display_code` (e.g. `FIND-123`). Absent entirely is not an error here —
/// `create_from_phrase`'s caller falls back to the raw id.
fn extract_display_code(raw: &Value) -> Option<String> {
    for key in ["display_code", "code"] {
        if let Some(s) = raw.get(key).and_then(Value::as_str) {
            return Some(s.to_string());
        }
    }
    raw.get("finding").and_then(extract_display_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqli_maps_to_injection_with_url() {
        let p = parse_finding_phrase("SQL Injection in https://t.com/?id=");
        assert_eq!(p.category, "injection");
        assert_eq!(p.title, "SQL Injection");
        assert_eq!(p.url.as_deref(), Some("https://t.com/?id="));
    }

    #[test]
    fn xss_maps_to_client_side() {
        assert_eq!(
            parse_finding_phrase("Reflected XSS").category,
            "client_side"
        );
    }

    #[test]
    fn unknown_maps_to_other_no_url() {
        let p = parse_finding_phrase("Weird thing");
        assert_eq!(p.category, "other");
        assert!(p.url.is_none());
    }

    #[test]
    fn extract_finding_id_reads_a_top_level_id() {
        let raw = serde_json::json!({"id": "00000000-0000-0000-0000-0000000000ab", "display_code": "FIND-1"});
        assert_eq!(
            extract_finding_id(&raw),
            Uuid::parse_str("00000000-0000-0000-0000-0000000000ab").ok()
        );
        assert_eq!(extract_display_code(&raw).as_deref(), Some("FIND-1"));
    }

    #[test]
    fn extract_finding_id_falls_back_to_finding_id_key() {
        let raw = serde_json::json!({"finding_id": "00000000-0000-0000-0000-0000000000cd"});
        assert_eq!(
            extract_finding_id(&raw),
            Uuid::parse_str("00000000-0000-0000-0000-0000000000cd").ok()
        );
        assert!(extract_display_code(&raw).is_none());
    }

    #[test]
    fn extract_finding_id_falls_back_to_a_nested_finding_object() {
        let raw = serde_json::json!({
            "finding": {"id": "00000000-0000-0000-0000-0000000000ef", "code": "FIND-2"}
        });
        assert_eq!(
            extract_finding_id(&raw),
            Uuid::parse_str("00000000-0000-0000-0000-0000000000ef").ok()
        );
        assert_eq!(extract_display_code(&raw).as_deref(), Some("FIND-2"));
    }

    #[test]
    fn extract_finding_id_is_none_when_nothing_matches() {
        let raw = serde_json::json!({"unrelated": "value"});
        assert!(extract_finding_id(&raw).is_none());
        assert!(extract_display_code(&raw).is_none());
    }
}
