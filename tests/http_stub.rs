//! Integration tests driving `ApiClient`/`commands::auth` against a raw
//! `std::net::TcpListener` stub server — no HTTP-mocking crate is a
//! dev-dependency of this crate, mirroring the API's own established
//! technique for testing outbound HTTP calls without a live network
//! dependency (`tandera-api/src/domains/integrations/jira.rs`'s
//! `with_bases` tests, `tandera-api/tests/notifications_chat.rs`'s
//! `HttpChatPoster` tests) — the blocking-`reqwest` equivalent of that
//! `tokio::net::TcpListener` pattern.
//!
//! What this file locks in, per the task brief: the `Authorization: Bearer
//! <token>` header actually carries the configured PAT, the request method
//! and path are correct, a POST body matches the exact `AiDraftRequest`
//! shape, `auth login` does NOT write a token to disk when the verification
//! call returns 401, and — a wire-level regression guard for
//! `Session::log_command`'s sync path — a command containing a secret is
//! NEVER sent to the API unredacted (only `logbook::redact_cmd`'s output
//! ever leaves the process; see `sync_testing_log_only_sends_redacted_cmd`).

use std::time::Duration;

use tandera_cli::api::ApiClient;
use tandera_cli::commands::auth;
use tandera_cli::config::Config;
use tandera_cli::repl::Session;

mod common;
use common::{http_response, spawn_stub_server};

fn ok_empty_json() -> String {
    http_response("200 OK", "{\"items\":[],\"total\":0}")
}

fn unauthorized_json() -> String {
    http_response(
        "401 Unauthorized",
        "{\"error\":{\"code\":\"UNAUTHORIZED\",\"message\":\"no\"}}",
    )
}

#[test]
fn probe_auth_sends_the_bearer_token_to_the_correct_path() {
    let (base_url, rx) = spawn_stub_server(ok_empty_json());
    let client = ApiClient::new(base_url, Some("tandera_pat_test_secret_body".to_string()))
        .expect("build client");

    client
        .probe_auth()
        .expect("probe_auth should succeed on 200");

    let req = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("stub saw a request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/v1/assessments");
    assert_eq!(
        req.header("authorization"),
        Some("Bearer tandera_pat_test_secret_body")
    );
}

#[test]
fn post_json_sends_the_exact_ai_draft_request_shape() {
    let response = http_response("201 Created", "{\"id\":\"draft\"}");
    let (base_url, rx) = spawn_stub_server(response);
    let client =
        ApiClient::new(base_url, Some("tandera_pat_abc".to_string())).expect("build client");

    let req = tandera_cli::models::AiDraftRequest {
        category: "injection".to_string(),
        severity: "high".to_string(),
        cwes: vec![89],
        cvss_vector: None,
        asset_id: None,
        note: Some("a note".to_string()),
        language: "en".to_string(),
        artifacts: vec![tandera_cli::models::Artifact {
            kind: "log".to_string(),
            content: "log content".to_string(),
        }],
    };

    let assessment_id = uuid::Uuid::nil();
    let _: serde_json::Value = client
        .post_json(
            &format!("/v1/assessments/{assessment_id}/findings/ai-draft"),
            &req,
        )
        .expect("post_json should succeed on 201");

    let recorded = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("stub saw a request");
    assert_eq!(recorded.method, "POST");
    assert_eq!(
        recorded.path,
        format!("/v1/assessments/{assessment_id}/findings/ai-draft")
    );
    assert_eq!(
        recorded.header("authorization"),
        Some("Bearer tandera_pat_abc")
    );

    let body: serde_json::Value = serde_json::from_str(&recorded.body).expect("valid JSON body");
    assert_eq!(body["category"], "injection");
    assert_eq!(body["severity"], "high");
    assert_eq!(body["cwes"], serde_json::json!([89]));
    assert_eq!(body["note"], "a note");
    assert_eq!(body["language"], "en");
    assert_eq!(body["artifacts"][0]["kind"], "log");
    assert_eq!(body["artifacts"][0]["content"], "log content");
    // Fields that were `None` on the Rust side must be OMITTED from the
    // wire body, not sent as `null` — `AiDraftRequest`'s own fields
    // (`cvss_vector`, `asset_id`) have no `#[serde(default)]` marker on the
    // API side that would tolerate an explicit `null` any differently, so
    // omission is the correct, verified wire shape.
    assert!(body.get("cvss_vector").is_none());
    assert!(body.get("asset_id").is_none());
}

#[test]
fn auth_login_stores_the_token_on_a_200_verification() {
    let (base_url, _rx) = spawn_stub_server(ok_empty_json());
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg_path = dir.path().join("config.toml");

    let outcome =
        auth::login(&cfg_path, &base_url, "tandera_pat_realsecret1234567890").expect("login");
    match outcome {
        auth::LoginOutcome::Success { redacted_token } => {
            assert!(redacted_token.starts_with("tandera_pat_"));
            assert!(!redacted_token.contains("realsecret1234567890"));
        }
        auth::LoginOutcome::InvalidToken => panic!("expected a successful login on 200"),
    }

    assert!(cfg_path.exists(), "config file must be written on success");
    let cfg = Config::load_from(&cfg_path).expect("load saved config");
    assert_eq!(
        cfg.token.as_deref(),
        Some("tandera_pat_realsecret1234567890")
    );
    assert_eq!(cfg.api_url.as_deref(), Some(base_url.as_str()));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&cfg_path)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn auth_login_does_not_store_an_invalid_token() {
    let (base_url, _rx) = spawn_stub_server(unauthorized_json());
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg_path = dir.path().join("config.toml");

    let outcome = auth::login(&cfg_path, &base_url, "tandera_pat_totally_bogus")
        .expect("login call itself should not error out on a 401 — it's a normal outcome");

    assert!(
        matches!(outcome, auth::LoginOutcome::InvalidToken),
        "a 401 verification must be reported as InvalidToken"
    );
    assert!(
        !cfg_path.exists(),
        "an invalid token must NEVER be written to the config file"
    );
}

#[test]
fn auth_login_does_not_overwrite_an_existing_valid_token_when_the_new_one_is_invalid() {
    let (base_url, _rx) = spawn_stub_server(unauthorized_json());
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg_path = dir.path().join("config.toml");

    // Seed a config file with an already-valid, previously-stored token.
    let existing = Config {
        api_url: Some(base_url.clone()),
        app_url: None,
        token: Some("tandera_pat_previously_valid_token".to_string()),
        assessment: None,
        sync_testing_log: None,
    };
    existing.save_to(&cfg_path).expect("seed config");

    let outcome = auth::login(&cfg_path, &base_url, "tandera_pat_new_but_bad").expect("login");
    assert!(matches!(outcome, auth::LoginOutcome::InvalidToken));

    let cfg_after = Config::load_from(&cfg_path).expect("reload config");
    assert_eq!(
        cfg_after.token.as_deref(),
        Some("tandera_pat_previously_valid_token"),
        "a failed login attempt must not clobber a previously-stored good token"
    );
}

/// Wire-level regression guard for `Session::log_command`'s sync path: the
/// security property "only the redacted command ever leaves the process" is
/// otherwise unit-tested only on the pure `logbook::redact_cmd` function
/// (see `src/logbook.rs`'s tests), which a future refactor passing
/// `entry.cmd` instead of `redact_cmd(&entry.cmd)` into the sync payload
/// would not catch. This test drives the real enqueue-and-upload path
/// (`Session::log_command` -> the background `uploads` queue ->
/// `logbook::sync_entry` -> `ApiClient::post_json`) against the same
/// `TcpListener` stub every other test in this file uses, and inspects the
/// exact bytes the stub received on the wire.
///
/// `Session::for_test` always starts with `sync_testing_log` off and no
/// stub-driven way to flip it or to invoke the private `log_command`, so
/// this reuses two minimal `#[doc(hidden)] pub` test seams added alongside
/// it on `Session` (`enable_sync_testing_log_for_test`,
/// `log_command_for_test`) — same pattern as the existing
/// `bump_generation_for_test`/`snapshot_for_test` seams.
#[test]
fn sync_testing_log_only_sends_redacted_cmd_over_the_wire() {
    let (base_url, rx) = spawn_stub_server(http_response("200 OK", "{}"));
    let client =
        ApiClient::new(base_url, Some("tandera_pat_sync_test".to_string())).expect("build client");

    let dir = tempfile::tempdir().expect("tempdir");
    let log_path = dir.path().join(".tandera/testing-log.jsonl");
    let aid = uuid::Uuid::new_v4();

    let mut session = Session::for_test(
        client,
        dir.path().join("unused-config.toml"),
        Some(aid),
        "test-project",
        log_path,
    );
    session.enable_sync_testing_log_for_test();

    // A command with an obvious secret in it.
    session.log_command_for_test(
        "curl -H 'Authorization: Bearer SUPERSECRET' http://x",
        "wrapped",
        None,
        Some(0),
        0.5,
    );

    // Block until the background sync job (enqueued by log_command_for_test
    // above) has actually run and hit the stub.
    session.drain_uploads_on_exit();

    let recorded = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("stub saw the sync request");
    assert_eq!(recorded.method, "POST");
    assert_eq!(recorded.path, format!("/v1/assessments/{aid}/activity"));

    let body: serde_json::Value = serde_json::from_str(&recorded.body).expect("valid JSON body");
    let cmd = body["cmd"].as_str().expect("cmd field present");
    assert!(
        !cmd.contains("SUPERSECRET"),
        "raw secret must never reach the wire, got: {cmd}"
    );
    assert!(
        cmd.contains("*****"),
        "redacted command must contain the mask, got: {cmd}"
    );
}
