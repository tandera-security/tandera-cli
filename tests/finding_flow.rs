//! Integration tests for `commands::finding::{create_from_phrase,
//! attach_image}`: the `:finding`/`:paste` API-hitting flow — ai-draft ->
//! (optionally) attachment upload-url -> S3 PUT -> confirm — driven against
//! a raw `TcpListener` stub answering a sequence of requests, same
//! technique as `tests/import_pipeline.rs`.
//!
//! What this locks in: the request ORDER and paths for the full sequence,
//! that the finding id + display_code are parsed out of the (stubbed)
//! ai-draft response, that the confirm call targets the exact
//! `attachment_id` the upload-url response handed back, and — the single
//! most security-relevant behavior — that the attachment PUT (like the
//! import PUT) carries NO `Authorization` header while every other call in
//! the sequence (ai-draft, the attachments POST, confirm) does.
//!
//! The interactive `:finding`/`:paste` prompt wiring in `repl::mod` is not
//! exercised here (it needs a TTY) — only the two functions
//! `dispatch_finding`/`dispatch_paste` call directly:
//! `create_from_phrase` and `attach_image`.

use std::time::Duration;

use tandera_cli::api::ApiClient;
use tandera_cli::commands::finding::{attach_image, create_from_phrase, parse_finding_phrase};
use uuid::Uuid;

mod common;
use common::{http_response, spawn_stub, RecordedRequest};

const FINDING_ID: &str = "11111111-1111-1111-1111-111111111111";
const ATTACHMENT_ID: &str = "att-abc123";
const TOKEN: &str = "tandera_pat_finding_flow_secret";

/// Full `:finding <phrase>` sequence with a clipboard screenshot attached:
/// ai-draft -> attachments upload-url -> S3 PUT -> confirm, asserting order,
/// paths, the parsed `CreatedFinding`, and the no-auth PUT.
#[test]
fn create_from_phrase_with_image_runs_ai_draft_then_the_attachment_sequence() {
    let (base_url, rx) = spawn_stub(4, |req, base| {
        if req.method == "POST" && req.path.ends_with("/findings/ai-draft") {
            http_response(
                "201 Created",
                &format!(r#"{{"id":"{FINDING_ID}","display_code":"FIND-42"}}"#),
            )
        } else if req.method == "POST" && req.path.ends_with("/attachments") {
            http_response(
                "200 OK",
                &format!(
                    r#"{{"upload_url":"{base}/s3/put-target","attachment_id":"{ATTACHMENT_ID}"}}"#
                ),
            )
        } else if req.method == "PUT" && req.path == "/s3/put-target" {
            http_response("200 OK", "")
        } else if req.method == "POST" && req.path.ends_with("/confirm") {
            http_response("200 OK", "{}")
        } else {
            http_response("404 Not Found", "{}")
        }
    });

    let client = ApiClient::new(base_url, Some(TOKEN.to_string())).expect("build client");
    let aid = Uuid::nil();
    let parsed = parse_finding_phrase("SQL Injection in https://example.com/login");
    // Ascii-only fake PNG payload — the stub records the request body as a
    // `String` (via `from_utf8_lossy`), so real PNG magic bytes (which
    // aren't valid UTF-8) would get mangled before the byte-for-byte
    // comparison below; the actual bytes sent over the wire by
    // `put_bytes_to_url` are untouched regardless (see
    // `put_bytes_to_url_carries_no_authorization_header` in
    // `tests/import_pipeline.rs` for the binary-safety proof on that path).
    let png = b"FAKE-PNG-fake-bytes".to_vec();

    let created = create_from_phrase(
        &client,
        aid,
        &parsed,
        "high",
        "SQL Injection in https://example.com/login",
        Some(png.clone()),
    )
    .expect("create_from_phrase should succeed end to end");

    assert_eq!(created.id, Uuid::parse_str(FINDING_ID).unwrap());
    assert_eq!(created.display_code.as_deref(), Some("FIND-42"));

    let recorded: Vec<RecordedRequest> = (0..4)
        .map(|_| {
            rx.recv_timeout(Duration::from_secs(5))
                .expect("stub saw all 4 requests")
        })
        .collect();

    // Step 1: ai-draft, authed, with the operator-owned category/severity
    // and the raw phrase as the note.
    assert_eq!(recorded[0].method, "POST");
    assert!(recorded[0]
        .path
        .ends_with(&format!("/assessments/{aid}/findings/ai-draft")));
    assert_eq!(
        recorded[0].header("authorization"),
        Some(format!("Bearer {TOKEN}").as_str())
    );
    let draft_body: serde_json::Value =
        serde_json::from_str(&recorded[0].body).expect("valid JSON body");
    assert_eq!(draft_body["category"], "injection");
    assert_eq!(draft_body["severity"], "high");
    assert_eq!(
        draft_body["note"],
        "SQL Injection in https://example.com/login"
    );

    // Step 2: request the presigned attachment upload URL, authed, scoped
    // under the finding id parsed out of step 1's response.
    assert_eq!(recorded[1].method, "POST");
    assert!(recorded[1]
        .path
        .ends_with(&format!("/findings/{FINDING_ID}/attachments")));
    assert_eq!(
        recorded[1].header("authorization"),
        Some(format!("Bearer {TOKEN}").as_str())
    );

    // Step 3: the presigned S3 PUT — no auth, and it carries the exact PNG
    // bytes. This is the security-critical assertion.
    assert_eq!(recorded[2].method, "PUT");
    assert_eq!(recorded[2].path, "/s3/put-target");
    assert!(
        recorded[2].header("authorization").is_none(),
        "the presigned screenshot PUT must never carry the Tandera bearer token, but got: {:?}",
        recorded[2].header("authorization")
    );
    assert_eq!(recorded[2].body.as_bytes(), png.as_slice());

    // Step 4: confirm, authed, targeting the EXACT attachment id the
    // upload-url response returned.
    assert_eq!(recorded[3].method, "POST");
    assert!(recorded[3].path.ends_with(&format!(
        "/findings/{FINDING_ID}/attachments/{ATTACHMENT_ID}/confirm"
    )));
    assert_eq!(
        recorded[3].header("authorization"),
        Some(format!("Bearer {TOKEN}").as_str())
    );
}

/// Without a screenshot (`image: None`), only the ai-draft call happens —
/// no attachment sequence at all.
#[test]
fn create_from_phrase_without_image_only_calls_ai_draft() {
    let (base_url, rx) = spawn_stub(1, |req, _base| {
        if req.method == "POST" && req.path.ends_with("/findings/ai-draft") {
            http_response("201 Created", &format!(r#"{{"id":"{FINDING_ID}"}}"#))
        } else {
            http_response("404 Not Found", "{}")
        }
    });
    let client = ApiClient::new(base_url, Some(TOKEN.to_string())).expect("build client");
    let aid = Uuid::nil();
    let parsed = parse_finding_phrase("Reflected XSS");

    let created = create_from_phrase(&client, aid, &parsed, "medium", "Reflected XSS", None)
        .expect("should succeed with no image");
    assert_eq!(created.id, Uuid::parse_str(FINDING_ID).unwrap());
    assert!(created.display_code.is_none());

    let recorded = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("stub saw exactly one request");
    assert_eq!(recorded.method, "POST");
    assert!(recorded.path.ends_with("/findings/ai-draft"));
}

/// `attach_image` alone (the `:paste` path) — request upload-url -> PUT ->
/// confirm, against a finding id that was NOT just created by ai-draft
/// (proving it's independently reusable, not entangled with
/// `create_from_phrase`).
#[test]
fn attach_image_runs_the_upload_url_put_confirm_sequence() {
    let (base_url, rx) = spawn_stub(3, |req, base| {
        if req.method == "POST" && req.path.ends_with("/attachments") {
            http_response(
                "200 OK",
                &format!(
                    r#"{{"upload_url":"{base}/s3/paste-target","attachment_id":"{ATTACHMENT_ID}"}}"#
                ),
            )
        } else if req.method == "PUT" && req.path == "/s3/paste-target" {
            http_response("200 OK", "")
        } else if req.method == "POST" && req.path.ends_with("/confirm") {
            http_response("200 OK", "{}")
        } else {
            http_response("404 Not Found", "{}")
        }
    });

    let client = ApiClient::new(base_url, Some(TOKEN.to_string())).expect("build client");
    let aid = Uuid::nil();
    let finding_id = Uuid::parse_str(FINDING_ID).unwrap();
    let png = b"paste-png-bytes".to_vec();

    attach_image(&client, aid, finding_id, png.clone()).expect("attach_image should succeed");

    let recorded: Vec<RecordedRequest> = (0..3)
        .map(|_| {
            rx.recv_timeout(Duration::from_secs(5))
                .expect("stub saw all 3 requests")
        })
        .collect();

    assert!(recorded[0]
        .path
        .ends_with(&format!("/findings/{FINDING_ID}/attachments")));
    assert_eq!(
        recorded[0].header("authorization"),
        Some(format!("Bearer {TOKEN}").as_str())
    );

    assert_eq!(recorded[1].method, "PUT");
    assert_eq!(recorded[1].path, "/s3/paste-target");
    assert!(
        recorded[1].header("authorization").is_none(),
        ":paste's screenshot PUT must never carry the Tandera bearer token"
    );
    assert_eq!(recorded[1].body.as_bytes(), png.as_slice());

    assert!(recorded[2].path.ends_with(&format!(
        "/findings/{FINDING_ID}/attachments/{ATTACHMENT_ID}/confirm"
    )));
    assert_eq!(
        recorded[2].header("authorization"),
        Some(format!("Bearer {TOKEN}").as_str())
    );
}

/// A response missing both upload-url field variants must be a clean
/// `ApiError`, not a panic.
#[test]
fn attach_image_errors_when_upload_url_response_is_missing_fields() {
    let (base_url, _rx) = spawn_stub(1, |_req, _base| http_response("200 OK", "{}"));
    let client = ApiClient::new(base_url, Some(TOKEN.to_string())).expect("build client");

    let err = attach_image(&client, Uuid::nil(), Uuid::nil(), b"x".to_vec())
        .expect_err("a response missing upload_url/attachment_id must error, not panic");
    assert!(format!("{err}").to_lowercase().contains("upload"));
}

/// An ai-draft response with no recognizable id shape must be a clean
/// `ApiError`, not a panic — proves the defensive parsing fails safely.
#[test]
fn create_from_phrase_errors_when_ai_draft_response_has_no_recognizable_id() {
    let (base_url, _rx) = spawn_stub(1, |_req, _base| {
        http_response("201 Created", r#"{"unexpected":"shape"}"#)
    });
    let client = ApiClient::new(base_url, Some(TOKEN.to_string())).expect("build client");
    let parsed = parse_finding_phrase("Weird thing");

    let err = create_from_phrase(&client, Uuid::nil(), &parsed, "low", "Weird thing", None)
        .expect_err("a response with no id-shaped field must error, not panic");
    assert!(format!("{err}").to_lowercase().contains("finding id"));
}
