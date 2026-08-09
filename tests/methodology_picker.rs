//! `new assessment` wizard's "what are you testing?" step (Task 8 —
//! checklist packs as the front door). Two contracts, mirroring the
//! console's Task 7 reframe (`AssessmentForm.svelte`) against the identical
//! `GET /v1/methodologies` endpoint:
//!
//! - The primary picker calls the category-filtered list (`?category=`),
//!   which the server (`ListQuery`/`service::list`, D-M5) forces to
//!   published-only — i.e. just the 5 curated packs, never an archived
//!   framework.
//! - The 13 archived frameworks are reachable ONLY via a separate, explicit
//!   `?status=archived` call — `list_packs` never sends `status=archived`,
//!   and `list_reference_frameworks` never sends `category=`.
//!
//! `pack_prompt_words` (the pure word-list builder behind the wizard's
//! Tab-completion) is covered by its own `#[cfg(test)]` unit tests inside
//! `commands::methodologies`, alongside every other pure formatting helper
//! in this crate (`read.rs::format_assets_table`, etc.) — not duplicated
//! here.
//!
//! - `apply_to_assessment` (the wizard's post-create follow-up, Task 9) PUTs
//!   `{"methodology_id": ...}` to `/v1/assessments/{id}/methodology` and
//!   never tries to parse a response body — the real endpoint replies
//!   `200`/empty, which is exactly the gap `put_json` would fall into.

mod common;

use common::{http_response, spawn_stub_server};
use tandera_cli::api::ApiClient;
use tandera_cli::commands::methodologies::{
    apply_to_assessment, list_packs, list_reference_frameworks,
};
use uuid::Uuid;

#[test]
fn list_packs_filters_by_category_only_never_status() {
    let body = r#"{
        "data": [
            {"id":"00000000-0000-0000-0000-000000000001","slug":"pack_web","name":"Web Application"}
        ],
        "has_more": false
    }"#;
    let (url, rx) = spawn_stub_server(http_response("200 OK", body));
    let client = ApiClient::new(url, Some("tandera_pat_test".to_string())).unwrap();

    let packs = list_packs(&client, "external").unwrap();
    assert_eq!(packs.len(), 1);
    assert_eq!(packs[0].slug, "pack_web");
    assert_eq!(packs[0].name, "Web Application");

    let recorded = rx.recv().unwrap();
    assert!(
        recorded.path.contains("category=external"),
        "path was {}",
        recorded.path
    );
    assert!(
        !recorded.path.contains("status="),
        "the primary pack list must never filter by status — path was {}",
        recorded.path
    );
}

#[test]
fn list_reference_frameworks_filters_by_status_archived_only_never_category() {
    let body = r#"{
        "data": [
            {"id":"00000000-0000-0000-0000-000000000002","slug":"owasp_wstg","name":"OWASP WSTG"}
        ],
        "has_more": false
    }"#;
    let (url, rx) = spawn_stub_server(http_response("200 OK", body));
    let client = ApiClient::new(url, Some("tandera_pat_test".to_string())).unwrap();

    let frameworks = list_reference_frameworks(&client).unwrap();
    assert_eq!(frameworks.len(), 1);
    assert_eq!(frameworks[0].slug, "owasp_wstg");

    let recorded = rx.recv().unwrap();
    assert!(
        recorded.path.contains("status=archived"),
        "path was {}",
        recorded.path
    );
    assert!(
        !recorded.path.contains("category="),
        "the reference-framework list must never filter by category — path was {}",
        recorded.path
    );
}

#[test]
fn apply_to_assessment_puts_the_methodology_id_to_the_right_path() {
    // The real endpoint replies 200 with an empty body — `put_json` would
    // fail trying to parse that as JSON, which is exactly why
    // `apply_to_assessment` goes through `put_json_no_content` instead.
    let (url, rx) = spawn_stub_server(http_response("200 OK", ""));
    let client = ApiClient::new(url, Some("tandera_pat_test".to_string())).unwrap();

    let assessment_id = Uuid::parse_str("00000000-0000-0000-0000-0000000000aa").unwrap();
    let methodology_id = Uuid::parse_str("00000000-0000-0000-0000-0000000000bb").unwrap();

    apply_to_assessment(&client, assessment_id, methodology_id).unwrap();

    let recorded = rx.recv().unwrap();
    assert_eq!(recorded.method, "PUT");
    assert!(
        recorded
            .path
            .ends_with(&format!("/v1/assessments/{assessment_id}/methodology")),
        "path was {}",
        recorded.path
    );
    assert_eq!(
        recorded.header("authorization"),
        Some("Bearer tandera_pat_test")
    );

    let body: serde_json::Value = serde_json::from_str(&recorded.body).unwrap();
    assert_eq!(body["methodology_id"], methodology_id.to_string());
}
