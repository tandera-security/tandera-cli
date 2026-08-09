//! `tandera assessments list`.

use serde_json::Value;

use crate::api::{ApiClient, ApiError};

/// Returns the raw JSON response body (`{"items": [...], "total": N}`) —
/// `--json` prints it verbatim; the table renderer deserializes it into
/// `models::AssessmentListResponse` itself, so a raw request/response round
/// trip is tested here without committing this function to one output
/// shape.
pub fn list(client: &ApiClient) -> Result<Value, ApiError> {
    client.get_json("/v1/assessments")
}
