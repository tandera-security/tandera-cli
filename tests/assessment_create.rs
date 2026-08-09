//! `POST /v1/assessments` wire contract for the `:pentest` / `new assessment`
//! wizard: the created body carries only the answered fields, hits the right
//! path, and is authenticated.

mod common;

use std::time::Duration;

use common::{http_response, spawn_stub, spawn_stub_server};
use tandera_cli::api::ApiClient;
use tandera_cli::commands::assessment_new::create_assessment;
use tandera_cli::commands::methodologies::apply_to_assessment;
use tandera_cli::models::CreateAssessmentRequest;
use uuid::Uuid;

#[test]
fn create_assessment_posts_only_answered_fields_to_v1_assessments() {
    let resp = http_response(
        "201 Created",
        r#"{"id":"00000000-0000-0000-0000-000000000001","name":"Acme External","slug":"acme-external"}"#,
    );
    let (url, rx) = spawn_stub_server(resp);
    let client = ApiClient::new(url, Some("tandera_pat_test".to_string())).unwrap();

    let req = CreateAssessmentRequest {
        name: "Acme External".to_string(),
        category: Some("external".to_string()),
        assessment_type: Some("black_box".to_string()),
        ..Default::default()
    };
    let created: serde_json::Value = create_assessment(&client, &req).unwrap();
    assert_eq!(created["slug"], "acme-external");

    let recorded = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(recorded.method, "POST");
    assert!(
        recorded.path.ends_with("/v1/assessments"),
        "path was {}",
        recorded.path
    );
    assert_eq!(
        recorded.header("authorization"),
        Some("Bearer tandera_pat_test")
    );

    let body: serde_json::Value = serde_json::from_str(&recorded.body).unwrap();
    assert_eq!(body["name"], "Acme External");
    assert_eq!(body["category"], "external");
    assert_eq!(body["assessment_type"], "black_box");
    // The unanswered optionals must be omitted from the wire body, not sent as null.
    assert!(body.get("description").is_none());
    assert!(body.get("start_date").is_none());
    assert!(body.get("testing_days").is_none());
}

/// The wizard's post-create follow-up: once the operator has picked a
/// checklist pack/framework, `run_wizard` applies it to the just-created
/// assessment right after the `POST /v1/assessments` succeeds. This drives
/// the same two calls in the same order — create, then apply, using the id
/// the create response handed back — against a two-request stub, since
/// `run_wizard` itself needs a TTY and isn't unit-tested.
#[test]
fn wizard_applies_the_picked_methodology_right_after_create_succeeds() {
    let methodology_id = Uuid::parse_str("00000000-0000-0000-0000-0000000000cc").unwrap();

    let (url, rx) = spawn_stub(2, move |req, _base| {
        if req.method == "POST" {
            http_response(
                "201 Created",
                r#"{"id":"00000000-0000-0000-0000-000000000001","name":"Acme External","slug":"acme-external"}"#,
            )
        } else {
            assert_eq!(req.method, "PUT");
            http_response("200 OK", "")
        }
    });
    let client = ApiClient::new(url, Some("tandera_pat_test".to_string())).unwrap();

    let req = CreateAssessmentRequest {
        name: "Acme External".to_string(),
        category: Some("external".to_string()),
        assessment_type: Some("black_box".to_string()),
        ..Default::default()
    };
    let created: serde_json::Value = create_assessment(&client, &req).unwrap();
    let assessment_id = Uuid::parse_str(created["id"].as_str().unwrap()).unwrap();

    apply_to_assessment(&client, assessment_id, methodology_id).unwrap();

    let first = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(first.method, "POST");
    assert!(first.path.ends_with("/v1/assessments"));

    let second = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(second.method, "PUT");
    assert!(second
        .path
        .ends_with(&format!("/v1/assessments/{assessment_id}/methodology")));
    let body: serde_json::Value = serde_json::from_str(&second.body).unwrap();
    assert_eq!(body["methodology_id"], methodology_id.to_string());
}
