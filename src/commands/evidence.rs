//! `tandera evidence add|list` — thin wrappers over the evidence locker API
//! (`POST`/`GET /v1/assessments/{assessment_id}/evidence`). Mirrors the style
//! of `findings.rs`: no shared model here, since both routes' response
//! shapes (a full `Evidence` row on create, a `{ data, next_cursor, has_more
//! }` envelope on list) are rendered as raw JSON by the caller rather than
//! deserialized into a CLI-side struct.

use serde_json::Value;
use uuid::Uuid;

use crate::api::{ApiClient, ApiError};

/// `POST /v1/assessments/{assessment_id}/evidence` — captures a text
/// evidence item (`kind` one of the text kinds: http_request, http_response,
/// terminal, log, note, scanner_record). Binary kinds (screenshot/file) go
/// through the upload-url flow instead, which isn't exposed by this
/// subcommand.
pub fn add(
    client: &ApiClient,
    assessment_id: Uuid,
    kind: &str,
    content: Option<&str>,
    target: Option<&str>,
    source: &str,
) -> Result<Value, ApiError> {
    let body = serde_json::json!({
        "kind": kind,
        "content": content,
        "target_raw": target,
        "source": source,
    });
    client.post_json(&format!("/v1/assessments/{assessment_id}/evidence"), &body)
}

/// `GET /v1/assessments/{assessment_id}/evidence` — lists the locker,
/// optionally filtered to a single `status` (captured/resolved/promoted/
/// discarded) via the CEL `query` param the list endpoint accepts.
pub fn list(
    client: &ApiClient,
    assessment_id: Uuid,
    status: Option<&str>,
) -> Result<Value, ApiError> {
    let query = status.map(|s| format!("status == \"{s}\""));
    let params: Vec<(&str, &str)> = query
        .as_deref()
        .map(|q| vec![("query", q)])
        .unwrap_or_default();
    client.get_json_query(
        &format!("/v1/assessments/{assessment_id}/evidence"),
        &params,
    )
}
