use tandera_cli::api::ApiClient;

mod common;
use common::serve_once;

#[test]
fn get_json_query_encodes_the_query_string() {
    let (addr, rx) = serve_once(r#"{"items":[],"total":0}"#);
    let client = ApiClient::new(addr, Some("tandera_pat_test".to_string())).unwrap();
    let _: serde_json::Value = client
        .get_json_query("/v1/assessments/AID/assets", &[("asset_type", "host")])
        .unwrap();
    let req = rx.recv().unwrap();
    assert!(req.contains("asset_type=host"), "request was: {req}");
}
