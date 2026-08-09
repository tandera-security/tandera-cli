//! `tandera findings list|ai-draft|ai-rewrite`.

use serde_json::Value;
use uuid::Uuid;

use crate::api::{ApiClient, ApiError};
use crate::models::{AiDraftRequest, AiRewriteRequest, Artifact};

/// `GET /v1/assessments/{assessment_id}/findings` — returns a bare JSON
/// array (no envelope). Returned as raw `Value` for the same reason
/// `assessments::list` is: `--json` prints it verbatim, the table renderer
/// deserializes it into `Vec<models::FindingSummary>` itself.
pub fn list(client: &ApiClient, assessment_id: Uuid) -> Result<Value, ApiError> {
    client.get_json(&format!("/v1/assessments/{assessment_id}/findings"))
}

/// `POST /v1/assessments/{assessment_id}/findings/ai-draft` (R-6
/// normalized route). Returns the raw JSON body — the created `Finding` has
/// far too many fields for a table, so callers pretty-print it directly
/// rather than round-tripping through a partial struct.
pub fn ai_draft(
    client: &ApiClient,
    assessment_id: Uuid,
    req: &AiDraftRequest,
) -> Result<Value, ApiError> {
    client.post_json(
        &format!("/v1/assessments/{assessment_id}/findings/ai-draft"),
        req,
    )
}

/// `POST /v1/assessments/{assessment_id}/findings/{finding_id}/ai-rewrite`.
pub fn ai_rewrite(
    client: &ApiClient,
    assessment_id: Uuid,
    finding_id: Uuid,
    req: &AiRewriteRequest,
) -> Result<Value, ApiError> {
    client.post_json(
        &format!("/v1/assessments/{assessment_id}/findings/{finding_id}/ai-rewrite"),
        req,
    )
}

/// Parses a `--artifact <kind>=<content>` CLI argument into an
/// `Artifact`. `kind` must be one of the four wire values
/// (`http_request`/`http_response`/`log`/`scanner_output`); a bare value
/// with no `kind=` prefix defaults to `log`. Pure — no I/O — so it's
/// directly unit-tested below rather than only exercised via clap parsing.
pub fn parse_artifact(raw: &str) -> Result<Artifact, String> {
    match raw.split_once('=') {
        Some((kind, content)) => {
            let parsed = crate::models::ArtifactKind::parse_wire(kind).ok_or_else(|| {
                format!(
                    "'{kind}' is not a valid artifact kind (expected one of: http_request, http_response, log, scanner_output)"
                )
            })?;
            Ok(Artifact {
                kind: parsed.as_wire().to_string(),
                content: content.to_string(),
            })
        }
        None => Ok(Artifact {
            kind: crate::models::ArtifactKind::Log.as_wire().to_string(),
            content: raw.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_artifact_with_explicit_kind() {
        let a = parse_artifact("http_request=GET / HTTP/1.1").expect("parses");
        assert_eq!(a.kind, "http_request");
        assert_eq!(a.content, "GET / HTTP/1.1");
    }

    #[test]
    fn parse_artifact_defaults_to_log_with_no_kind_prefix() {
        let a = parse_artifact("some raw log line").expect("parses");
        assert_eq!(a.kind, "log");
        assert_eq!(a.content, "some raw log line");
    }

    #[test]
    fn parse_artifact_rejects_unknown_kind() {
        assert!(parse_artifact("not_a_kind=content").is_err());
    }

    #[test]
    fn parse_artifact_preserves_equals_signs_in_content() {
        // A content value that itself contains '=' must not be truncated —
        // split_once takes only the FIRST '=' as the separator.
        let a = parse_artifact("log=key=value&other=thing").expect("parses");
        assert_eq!(a.kind, "log");
        assert_eq!(a.content, "key=value&other=thing");
    }
}
