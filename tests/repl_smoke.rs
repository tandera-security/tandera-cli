//! Smoke tests for the REPL's pure `handle_line` entry point (not the
//! rustyline wrapper, which needs a TTY and is intentionally untested here).
//!
//! Both tests use `Session::for_test`, which skips every network call
//! `Session::new` makes (assessment resolution + the background
//! status-fetch thread) — so unlike `tests/read_surface.rs`/`http_stub.rs`,
//! no stub `TcpListener` server is needed: neither `:exit` nor a
//! passthrough command ever touches `session.client`. The `ApiClient` below
//! points at a loopback address that is never actually connected to.

use std::path::PathBuf;

use tandera_cli::api::ApiClient;
use tandera_cli::config::Config;
use tandera_cli::models::{Credits, Scope, TestingStatus};
use tandera_cli::repl::{handle_line, Control, Session};
use uuid::Uuid;

fn test_session(log_path: PathBuf) -> Session {
    let client = ApiClient::new("http://127.0.0.1:0", None).expect("build client");
    Session::for_test(
        client,
        PathBuf::from("unused-config.toml"),
        None,
        "test-project",
        log_path,
    )
}

#[test]
fn exit_verb_returns_exit_control() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log_path = dir.path().join(".tandera/testing-log.jsonl");
    let mut session = test_session(log_path);

    let control = handle_line(&mut session, ":exit").expect("handle_line should not error");
    assert_eq!(control, Control::Exit);
}

#[test]
fn quit_verb_also_returns_exit_control() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log_path = dir.path().join(".tandera/testing-log.jsonl");
    let mut session = test_session(log_path);

    let control = handle_line(&mut session, ":quit").expect("handle_line should not error");
    assert_eq!(control, Control::Exit);
}

#[test]
fn passthrough_line_runs_and_logs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log_path = dir.path().join(".tandera/testing-log.jsonl");
    let mut session = test_session(log_path.clone());

    let control = handle_line(&mut session, "echo hi").expect("handle_line should not error");
    assert_eq!(control, Control::Continue);

    let body = std::fs::read_to_string(&log_path).expect("log file should have been written");
    let last_line = body.lines().last().expect("at least one log line");
    let entry: serde_json::Value =
        serde_json::from_str(last_line).expect("log line should be valid JSON");
    assert_eq!(entry["kind"], "passthrough");
    assert_eq!(entry["cmd"], "echo hi");
}

#[test]
fn blank_line_is_a_no_op() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log_path = dir.path().join(".tandera/testing-log.jsonl");
    let mut session = test_session(log_path.clone());

    let control = handle_line(&mut session, "   ").expect("handle_line should not error");
    assert_eq!(control, Control::Continue);
    assert!(
        !log_path.exists(),
        "a blank line must not write a log entry"
    );
}

#[test]
fn unknown_meta_verb_is_reported_but_does_not_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log_path = dir.path().join(".tandera/testing-log.jsonl");
    let mut session = test_session(log_path);

    let control = handle_line(&mut session, ":bogus").expect("unknown verb should not error");
    assert_eq!(control, Control::Continue);
}

/// Fix 1 (Critical): `Session::new` must make zero synchronous network
/// calls, so the prompt/banner can render immediately. Prove it against a
/// *slow* endpoint rather than a merely-refused one — a refused connection
/// fails (and would return) fast on its own and wouldn't distinguish
/// "blocks on the network" from "doesn't". This listener accepts the
/// connection `Session::new`'s background thread opens and then holds it
/// open indefinitely, replying to nothing; if `Session::new` were still
/// doing the old synchronous `resolve_active_assessment` call before
/// returning, this test would hang until the test harness's own timeout —
/// observably failing instead of quietly passing.
#[test]
fn session_new_does_not_block_on_a_slow_assessment_endpoint() {
    use std::net::TcpListener;
    use std::time::{Duration, Instant};

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub listener");
    let addr = listener.local_addr().expect("listener addr");
    std::thread::spawn(move || {
        // Accept and then just sit on the connection — never write a byte
        // back. A real HTTP client sitting on this hangs until it times out
        // (far longer than this test's budget) or the process exits.
        if let Ok((stream, _)) = listener.accept() {
            std::thread::sleep(Duration::from_secs(30));
            drop(stream);
        }
    });

    let base_url = format!("http://{addr}");
    let client = ApiClient::new(base_url.clone(), None).expect("build client");

    let dir = tempfile::tempdir().expect("tempdir");
    let cfg_path = dir.path().join("config.toml");
    Config {
        api_url: Some(base_url),
        app_url: None,
        token: None,
        assessment: Some("slow-project".to_string()),
        sync_testing_log: None,
    }
    .save_to(&cfg_path)
    .expect("seed config");

    let started = Instant::now();
    let _session = Session::new(client, cfg_path, None).expect("Session::new must not error");
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(500),
        "Session::new took {elapsed:?} — it must never block on the network"
    );
}

/// Deterministic regression test for the check-then-lock TOCTOU a prior fix
/// left open: the generation guard used to be a plain `load()` on an atomic
/// followed by a *separate* mutex write, so a background thread could pass
/// the check, get preempted, let `:use` bump the generation and reset
/// state, and then resume and write its now-stale data anyway. The fix
/// consolidates the guarded fields behind one mutex and does the
/// compare-and-write (`Session::apply_if_current`, backed by the crate's
/// private `gated_apply`) while holding that single lock.
///
/// This test exercises the guard directly — no threads, no sleeps, no
/// scheduling — by calling `apply_if_current` once at the current
/// generation (proving the write lands) and once at a now-stale generation
/// after `bump_generation_for_test` simulates what `:use` does (proving the
/// write is silently discarded instead of overwriting the fresher state).
#[test]
fn stale_generation_write_is_discarded_after_a_use_style_generation_bump() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log_path = dir.path().join(".tandera/testing-log.jsonl");
    let session = test_session(log_path);

    let fresh_status = TestingStatus {
        is_within_window: true,
        is_allowed_day: true,
        is_blackout: false,
        is_testing_allowed: true,
        message: String::new(),
    };
    let fresh_credits = Credits {
        plan_credits: 100,
        purchased_credits: 20,
        total: 120,
        low: false,
    };
    let fresh_aid =
        Uuid::parse_str("00000000-0000-0000-0000-000000000042").expect("valid uuid literal");
    let fresh_scopes = vec![Scope {
        scope_type: "domain".to_string(),
        value: "acme.example".to_string(),
    }];

    // Write at the CURRENT generation (0, seeded by `for_test`): the data
    // must be applied.
    session.apply_if_current(0, &fresh_status, &fresh_credits, fresh_aid, fresh_scopes);
    assert_eq!(
        session
            .resolve_assessment_id()
            .expect("assessment id cached"),
        fresh_aid,
        "a write at the current generation must be applied"
    );
    let snap = session.snapshot_for_test();
    assert_eq!(snap.credits, Some(120));
    assert_eq!(snap.window_open, Some(true));

    // Simulate `:use` switching assessments: it bumps the generation under
    // the SAME lock the compare-and-write uses, so from this point on
    // generation 0 is stale.
    let new_gen = session.bump_generation_for_test();
    assert_eq!(
        new_gen, 1,
        "the simulated `:use` must have bumped the generation"
    );

    // A write still carrying the OLD generation (0) — as a background
    // thread spawned before the `:use` would — must be a no-op: this is
    // exactly the stale write the prior check-then-lock gap let through.
    let stale_aid =
        Uuid::parse_str("00000000-0000-0000-0000-0000000000ff").expect("valid uuid literal");
    let stale_status = TestingStatus {
        is_within_window: false,
        is_allowed_day: false,
        is_blackout: true,
        is_testing_allowed: false,
        message: "stale blackout".to_string(),
    };
    let stale_credits = Credits {
        plan_credits: 1,
        purchased_credits: 0,
        total: 1,
        low: true,
    };
    session.apply_if_current(0, &stale_status, &stale_credits, stale_aid, Vec::new());

    assert_eq!(
        session
            .resolve_assessment_id()
            .expect("assessment id cached"),
        fresh_aid,
        "a stale-generation write must not overwrite the assessment id"
    );
    let snap_after = session.snapshot_for_test();
    assert_eq!(
        snap_after.credits,
        Some(120),
        "a stale-generation write must not overwrite credits"
    );
    assert_eq!(
        snap_after.window_open,
        Some(true),
        "a stale-generation write must not overwrite the testing-window status"
    );
}
