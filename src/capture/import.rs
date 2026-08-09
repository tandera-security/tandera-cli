//! Import pipeline client: hand a scan output file to Tandera and walk it
//! through the assessment-scoped import flow — `upload-url` (mint a
//! presigned S3 URL) -> PUT the file to S3 -> `parse` -> `preview` (counts +
//! sample) -> `confirm`.
//!
//! Step 2 (the S3 PUT) is routed through `ApiClient::put_bytes_to_url`,
//! which deliberately bypasses the bearer-token-injecting
//! `ApiClient::request` path — the presigned URL points at a third party
//! (S3), and attaching the Tandera personal access token to that request
//! would leak the credential to it. See `tests/import_pipeline.rs` for the
//! functional proof that the PUT carries no `Authorization` header.

use std::fs;
use std::io::Read;
use std::path::Path;

use anyhow::Context;
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use crate::api::{ApiClient, ApiError};
use crate::models::{PreviewResponse, UploadUrlResponse};

/// Counts reported once the pipeline completes. Deliberately not the raw
/// wire shape (`PreviewResponse`) — just the two numbers a caller (the
/// `import` command, once it exists) needs to print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportResult {
    pub asset_count: i64,
    pub finding_count: i64,
}

#[derive(Serialize)]
struct UploadUrlRequest<'a> {
    file_name: &'a str,
    scan_type: &'a str,
}

/// Runs the 5-step import pipeline for `path` against assessment `aid`,
/// tagging the upload with `scan_type` (e.g. `"nmap"`, `"httpx"` — see
/// `sniff_scan_type`). Reads the whole file into memory before the PUT;
/// fine for v1's expected file sizes, streaming is a later optimization.
pub fn upload_file(
    client: &ApiClient,
    aid: Uuid,
    path: &Path,
    scan_type: &str,
) -> Result<ImportResult, ApiError> {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("scan.out")
        .to_string();
    let bytes = fs::read(path)
        .map_err(|e| ApiError::Transport(format!("failed to read {}: {e}", path.display())))?;

    // Step 1: mint a presigned upload URL + import id.
    let upload_url_resp: UploadUrlResponse = client.post_json(
        &format!("/v1/assessments/{aid}/imports/upload-url"),
        &UploadUrlRequest {
            file_name: &file_name,
            scan_type,
        },
    )?;
    let upload_url = upload_url_resp
        .resolved_upload_url()
        .ok_or_else(|| {
            ApiError::Transport("upload-url response did not include an upload URL".to_string())
        })?
        .to_string();
    let import_id = upload_url_resp
        .resolved_import_id()
        .ok_or_else(|| {
            ApiError::Transport("upload-url response did not include an import id".to_string())
        })?
        .to_string();

    // Step 2: PUT the file bytes straight to S3 — no Tandera auth header.
    client.put_bytes_to_url(&upload_url, bytes, "application/octet-stream")?;

    // Step 3: tell Tandera to parse what was just uploaded.
    let _: Value = client.post_json(
        &format!("/v1/assessments/{aid}/imports/{import_id}/parse"),
        &serde_json::json!({}),
    )?;

    // Step 4: preview — counts + sample of what parsing found.
    let preview: PreviewResponse = client.post_json(
        &format!("/v1/assessments/{aid}/imports/{import_id}/preview"),
        &serde_json::json!({}),
    )?;

    // Step 5: confirm the import. Assumed to echo the same counts as
    // preview; if preview didn't report a nonzero count for a field, fall
    // back to whatever confirm reports for it.
    let confirm: PreviewResponse = client.post_json(
        &format!("/v1/assessments/{aid}/imports/{import_id}/confirm"),
        &serde_json::json!({}),
    )?;

    let asset_count = non_zero_or(
        preview.resolved_asset_count(),
        confirm.resolved_asset_count(),
    );
    let finding_count = non_zero_or(
        preview.resolved_finding_count(),
        confirm.resolved_finding_count(),
    );

    Ok(ImportResult {
        asset_count,
        finding_count,
    })
}

/// Like `upload_file`, but for bytes that aren't already sitting at a file
/// path (the piped-stdin case in `tandera import`). Rather than duplicate
/// the 5-step pipeline for an in-memory body, this writes `bytes` to a
/// uniquely-named file under the OS temp dir and delegates straight to
/// `upload_file`, cleaning the temp file up afterwards regardless of
/// outcome. `file_name` is cosmetic — it's what's sent as the upload's
/// `file_name` and is folded into the temp file's name for readability
/// during debugging, not for uniqueness (the pid does that).
pub fn upload_bytes(
    client: &ApiClient,
    aid: Uuid,
    file_name: &str,
    bytes: &[u8],
    scan_type: &str,
) -> Result<ImportResult, ApiError> {
    let safe_name: String = file_name
        .chars()
        .map(|c| if c == '/' || c == '\\' { '_' } else { c })
        .collect();
    let tmp_path =
        std::env::temp_dir().join(format!("tandera-import-{}-{safe_name}", std::process::id()));
    fs::write(&tmp_path, bytes).map_err(|e| {
        ApiError::Transport(format!(
            "failed to write temp file {}: {e}",
            tmp_path.display()
        ))
    })?;

    let result = upload_file(client, aid, &tmp_path, scan_type);
    let _ = fs::remove_file(&tmp_path);
    result
}

/// Reads all of stdin into memory. An empty stdin is returned as `Ok(vec![])`
/// rather than an error here — the caller (the `import` command) is in a
/// better position to phrase "nothing was piped in" clearly; this function
/// only reports genuine I/O failures.
pub fn read_all_stdin() -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();
    std::io::stdin()
        .read_to_end(&mut buf)
        .context("failed to read from stdin")?;
    Ok(buf)
}

fn non_zero_or(primary: i64, fallback: i64) -> i64 {
    if primary != 0 {
        primary
    } else {
        fallback
    }
}

/// Best-effort scan-format detection from a leading sample of a file's
/// bytes (a few KB is plenty — this never needs the whole file). Returns
/// the `scan_type` string the import API expects, or `None` if nothing
/// recognizable matched.
pub fn sniff_scan_type(sample: &[u8]) -> Option<&'static str> {
    let text = String::from_utf8_lossy(sample);
    let trimmed = text.trim_start();

    if trimmed.starts_with('<') {
        // Skip an optional `<?xml ...?>` declaration to reach the root
        // element.
        let root = trimmed
            .find("?>")
            .map(|i| trimmed[i + 2..].trim_start())
            .unwrap_or(trimmed);
        let root_lower = root.to_ascii_lowercase();
        if root_lower.starts_with("<nmaprun") {
            return Some("nmap");
        }
        if root_lower.starts_with("<niktoscan") {
            return Some("nikto");
        }
        return None;
    }

    // JSON / JSONL: sniff the first non-blank line as a standalone JSON
    // object and look for tool-shaped keys.
    let first_line = text.lines().find(|l| !l.trim().is_empty())?;
    let value: Value = serde_json::from_str(first_line).ok()?;
    if value.get("url").is_some() && value.get("status_code").is_some() {
        return Some("httpx");
    }
    if value.get("template-id").is_some() || value.get("templateID").is_some() {
        return Some("nuclei");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniff_detects_nmap_xml_and_httpx_jsonl() {
        assert_eq!(
            sniff_scan_type(b"<?xml version=\"1.0\"?><nmaprun>"),
            Some("nmap")
        );
        assert_eq!(
            sniff_scan_type(b"{\"url\":\"https://x\",\"status_code\":200}\n"),
            Some("httpx")
        );
        assert_eq!(sniff_scan_type(b"not a scan"), None);
    }

    #[test]
    fn sniff_detects_nmap_without_xml_declaration() {
        assert_eq!(sniff_scan_type(b"<nmaprun scanner=\"nmap\">"), Some("nmap"));
    }

    #[test]
    fn sniff_detects_nuclei_jsonl() {
        assert_eq!(
            sniff_scan_type(b"{\"template-id\":\"CVE-2021-1234\",\"host\":\"x\"}\n"),
            Some("nuclei")
        );
    }

    #[test]
    fn sniff_returns_none_for_unrelated_xml() {
        assert_eq!(sniff_scan_type(b"<?xml version=\"1.0\"?><rss></rss>"), None);
    }

    #[test]
    fn non_zero_or_prefers_primary_unless_it_is_zero() {
        assert_eq!(non_zero_or(5, 9), 5);
        assert_eq!(non_zero_or(0, 9), 9);
        assert_eq!(non_zero_or(0, 0), 0);
    }
}
