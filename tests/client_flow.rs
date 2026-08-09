//! `client add` wire flow: `add_and_bind` must POST the company name to
//! `/v1/clients`, then PUT the returned `client_id` to the active
//! assessment (a partial update), authenticated on both calls.

mod common;

use std::time::Duration;

use common::{http_response, spawn_stub};
use tandera_cli::api::ApiClient;
use tandera_cli::commands::client::add_and_bind;
use uuid::Uuid;

#[test]
fn add_and_bind_creates_then_binds_client_to_the_assessment() {
    let client_id = "00000000-0000-0000-0000-0000000000c1";
    let (url, rx) = spawn_stub(2, move |req, _base| {
        if req.method == "POST" && req.path.ends_with("/v1/clients") {
            http_response(
                "201 Created",
                &format!(r#"{{"id":"{client_id}","company_name":"Acme Corp"}}"#),
            )
        } else {
            http_response("200 OK", "{}")
        }
    });

    let api = ApiClient::new(url, Some("tandera_pat_test".to_string())).unwrap();
    let aid = Uuid::parse_str("00000000-0000-0000-0000-0000000000a1").unwrap();

    let new_id = add_and_bind(&api, aid, "Acme Corp").unwrap();
    assert_eq!(new_id.to_string(), client_id);

    // 1) POST /v1/clients { company_name }
    let r1 = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(r1.method, "POST");
    assert!(r1.path.ends_with("/v1/clients"), "path was {}", r1.path);
    assert_eq!(r1.header("authorization"), Some("Bearer tandera_pat_test"));
    let b1: serde_json::Value = serde_json::from_str(&r1.body).unwrap();
    assert_eq!(b1["company_name"], "Acme Corp");

    // 2) PUT /v1/assessments/{aid} { client_id } — the bind
    let r2 = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(r2.method, "PUT");
    assert!(
        r2.path.ends_with(&format!("/v1/assessments/{aid}")),
        "path was {}",
        r2.path
    );
    assert_eq!(r2.header("authorization"), Some("Bearer tandera_pat_test"));
    let b2: serde_json::Value = serde_json::from_str(&r2.body).unwrap();
    assert_eq!(b2["client_id"], client_id);
}
