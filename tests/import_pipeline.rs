//! Integration tests for `capture::import`: the pure `sniff_scan_type`
//! detector, a direct proof that `ApiClient::put_bytes_to_url` never sends
//! the Tandera bearer token, and the full 5-step `upload_file` pipeline
//! (upload-url -> S3 PUT -> parse -> preview -> confirm) driven against a
//! raw `TcpListener` stub — same technique as `tests/http_stub.rs`, extended
//! here to answer a *sequence* of requests on one listener rather than just
//! one, since `upload_file` makes 5 calls in order and the presigned
//! `upload_url` the stub hands back in step 1 points at itself for step 2.

use std::fs;
use std::time::Duration;

use tandera_cli::api::ApiClient;
use tandera_cli::capture::import::{sniff_scan_type, upload_bytes, upload_file, ImportResult};
use uuid::Uuid;

mod common;
use common::{http_response, spawn_stub, RecordedRequest};

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

/// The single most security-relevant behavior in this module: even though
/// the `ApiClient` is configured with a real-looking PAT, a
/// `put_bytes_to_url` call against a URL that is NOT the client's
/// configured `api_url` (exactly the presigned-S3-URL scenario) must not
/// carry an `Authorization` header.
#[test]
fn put_bytes_to_url_carries_no_authorization_header() {
    let (base_url, rx) = spawn_stub(1, |_req, _base| http_response("200 OK", ""));
    // Deliberately a different host than the stub — mirrors the real
    // shape, where `api_url` is the Tandera API and the presigned URL is
    // S3, a different origin entirely.
    let client = ApiClient::new(
        "http://tandera-api.invalid",
        Some("tandera_pat_super_secret".to_string()),
    )
    .expect("build client");

    client
        .put_bytes_to_url(
            &format!("{base_url}/s3/put-target"),
            b"raw-file-bytes".to_vec(),
            "application/octet-stream",
        )
        .expect("PUT should succeed on 200");

    let recorded = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("stub saw the PUT");
    assert_eq!(recorded.method, "PUT");
    assert_eq!(recorded.path, "/s3/put-target");
    assert!(
        recorded.header("authorization").is_none(),
        "the presigned PUT must never carry the Tandera bearer token, but got: {:?}",
        recorded.header("authorization")
    );
    assert_eq!(recorded.body, "raw-file-bytes");
}

#[test]
fn put_bytes_to_url_returns_an_api_error_on_a_non_2xx_response() {
    let (base_url, _rx) = spawn_stub(1, |_req, _base| {
        http_response("500 Internal Server Error", "S3 is down")
    });
    let client = ApiClient::new("http://tandera-api.invalid", None).expect("build client");

    let err = client
        .put_bytes_to_url(
            &format!("{base_url}/s3/put-target"),
            b"x".to_vec(),
            "text/plain",
        )
        .expect_err("a 500 from S3 must surface as an error");
    assert!(format!("{err}").contains("500"));
}

fn ok_scan_file(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let path = dir.path().join("scan.xml");
    fs::write(&path, b"<?xml version=\"1.0\"?><nmaprun></nmaprun>").expect("write scan file");
    path
}

/// Drives the full `upload_file` pipeline against a stub that answers all
/// 5 requests (upload-url, the S3 PUT it points back at, parse, preview,
/// confirm), and asserts both the request ORDER/paths and the no-auth PUT.
#[test]
fn upload_file_runs_the_five_step_pipeline_in_order() {
    let (base_url, rx) = spawn_stub(5, |req, base| {
        if req.method == "POST" && req.path.ends_with("/imports/upload-url") {
            http_response(
                "200 OK",
                &format!(r#"{{"upload_url":"{base}/s3/put-target","import_id":"import-abc123"}}"#),
            )
        } else if req.method == "PUT" && req.path == "/s3/put-target" {
            http_response("200 OK", "")
        } else if req.method == "POST" && req.path.ends_with("/parse") {
            http_response("200 OK", "{}")
        } else if req.method == "POST"
            && (req.path.ends_with("/preview") || req.path.ends_with("/confirm"))
        {
            http_response("200 OK", r#"{"asset_count":5,"finding_count":3}"#)
        } else {
            http_response("404 Not Found", "{}")
        }
    });

    let client = ApiClient::new(base_url, Some("tandera_pat_pipeline_secret".to_string()))
        .expect("build client");
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = ok_scan_file(&dir);
    let aid = Uuid::nil();

    let result =
        upload_file(&client, aid, &file_path, "nmap").expect("pipeline should succeed end to end");
    assert_eq!(
        result,
        ImportResult {
            asset_count: 5,
            finding_count: 3,
        }
    );

    let recorded: Vec<RecordedRequest> = (0..5)
        .map(|_| {
            rx.recv_timeout(Duration::from_secs(5))
                .expect("stub saw all 5 requests")
        })
        .collect();

    // Step 1: upload-url, authed.
    assert_eq!(recorded[0].method, "POST");
    assert!(recorded[0].path.ends_with("/imports/upload-url"));
    assert_eq!(
        recorded[0].header("authorization"),
        Some("Bearer tandera_pat_pipeline_secret")
    );

    // Step 2: the presigned S3 PUT — no auth, and it carries the file body.
    assert_eq!(recorded[1].method, "PUT");
    assert_eq!(recorded[1].path, "/s3/put-target");
    assert!(
        recorded[1].header("authorization").is_none(),
        "the presigned S3 PUT must never carry the Tandera bearer token"
    );
    assert_eq!(
        recorded[1].body,
        "<?xml version=\"1.0\"?><nmaprun></nmaprun>"
    );

    // Step 3: parse, authed.
    assert_eq!(recorded[2].method, "POST");
    assert!(recorded[2].path.ends_with("/imports/import-abc123/parse"));
    assert_eq!(
        recorded[2].header("authorization"),
        Some("Bearer tandera_pat_pipeline_secret")
    );

    // Step 4: preview, authed.
    assert_eq!(recorded[3].method, "POST");
    assert!(recorded[3].path.ends_with("/imports/import-abc123/preview"));
    assert_eq!(
        recorded[3].header("authorization"),
        Some("Bearer tandera_pat_pipeline_secret")
    );

    // Step 5: confirm, authed.
    assert_eq!(recorded[4].method, "POST");
    assert!(recorded[4].path.ends_with("/imports/import-abc123/confirm"));
    assert_eq!(
        recorded[4].header("authorization"),
        Some("Bearer tandera_pat_pipeline_secret")
    );
}

/// Same 5-step pipeline as `upload_file_runs_the_five_step_pipeline_in_order`,
/// but driven through `upload_bytes` — the entry point the non-interactive
/// `tandera import` command (and bare `tandera` with piped stdin) uses when
/// there's no pre-existing file path, only an in-memory body and an explicit
/// `--type`. Proves `upload_bytes` reuses the exact same pipeline (temp-file
/// plumbing aside) rather than duplicating it.
#[test]
fn upload_bytes_runs_the_five_step_pipeline_with_an_explicit_scan_type() {
    let (base_url, rx) = spawn_stub(5, |req, base| {
        if req.method == "POST" && req.path.ends_with("/imports/upload-url") {
            http_response(
                "200 OK",
                &format!(r#"{{"upload_url":"{base}/s3/put-target","import_id":"import-xyz789"}}"#),
            )
        } else if req.method == "PUT" && req.path == "/s3/put-target" {
            http_response("200 OK", "")
        } else if req.method == "POST" && req.path.ends_with("/parse") {
            http_response("200 OK", "{}")
        } else if req.method == "POST"
            && (req.path.ends_with("/preview") || req.path.ends_with("/confirm"))
        {
            http_response("200 OK", r#"{"asset_count":2,"finding_count":7}"#)
        } else {
            http_response("404 Not Found", "{}")
        }
    });

    let client = ApiClient::new(base_url, Some("tandera_pat_bytes_secret".to_string()))
        .expect("build client");
    let bytes = b"{\"url\":\"https://x\",\"status_code\":200}\n".to_vec();
    let aid = Uuid::nil();

    let result = upload_bytes(&client, aid, "stdin.jsonl", &bytes, "httpx")
        .expect("bytes pipeline should succeed end to end");
    assert_eq!(
        result,
        ImportResult {
            asset_count: 2,
            finding_count: 7,
        }
    );

    let recorded: Vec<RecordedRequest> = (0..5)
        .map(|_| {
            rx.recv_timeout(Duration::from_secs(5))
                .expect("stub saw all 5 requests")
        })
        .collect();

    assert_eq!(recorded[0].method, "POST");
    assert!(recorded[0].path.ends_with("/imports/upload-url"));
    assert_eq!(recorded[1].method, "PUT");
    assert_eq!(
        recorded[1].body,
        "{\"url\":\"https://x\",\"status_code\":200}\n"
    );
    assert!(
        recorded[1].header("authorization").is_none(),
        "the presigned S3 PUT must never carry the Tandera bearer token"
    );
    assert!(recorded[2].path.ends_with("/imports/import-xyz789/parse"));
    assert!(recorded[3].path.ends_with("/imports/import-xyz789/preview"));
    assert!(recorded[4].path.ends_with("/imports/import-xyz789/confirm"));
}

#[test]
fn upload_file_errors_when_upload_url_response_is_missing_fields() {
    let (base_url, _rx) = spawn_stub(1, |_req, _base| http_response("200 OK", "{}"));
    let client = ApiClient::new(base_url, Some("tandera_pat_x".to_string())).expect("build client");
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = ok_scan_file(&dir);

    let err = upload_file(&client, Uuid::nil(), &file_path, "nmap")
        .expect_err("a response missing upload_url/import_id must error, not panic");
    assert!(format!("{err}").to_lowercase().contains("upload"));
}
