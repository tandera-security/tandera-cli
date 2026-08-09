//! Wire types for the Tandera API. This CLI shares no code with the API
//! crate (`code/src/tandera-api`), so every shape here is copied by hand
//! from the real request/response types it must match byte-for-byte:
//!
//! - `Category`/`Severity`/`ArtifactKind` mirror
//!   `domains::findings::model::{FindingCategory, FindingSeverity}` and
//!   `shared::ai::prompt_guard::ArtifactKind` (`#[serde(rename_all =
//!   "snake_case")]` on every one of them).
//! - `AiDraftRequest`/`AiRewriteRequest`/`Artifact` mirror
//!   `domains::findings::ai_authoring::{AiDraftRequest, AiRewriteRequest}`
//!   and `shared::ai::prompt_guard::Artifact` field-for-field.
//! - `Assessment`/`AssessmentListResponse`/`FindingSummary` are read-only
//!   response shapes: only the fields this CLI actually displays are
//!   declared, and every response deserialization here is `serde`'s default
//!   "ignore unknown fields" mode, so the real (much larger) API response
//!   objects deserialize into these subsets without error.
//! - `ApiErrorBody` mirrors `shared::error::AppError`'s
//!   `{"error": {"code", "message"}}` response body shape.

use chrono::{NaiveDate, NaiveTime};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// `domains::findings::model::FindingCategory` (15 variants, `as_str()`).
#[derive(Debug, Clone, Copy, ValueEnum)]
#[value(rename_all = "snake_case")]
pub enum Category {
    Injection,
    AccessControl,
    Cryptography,
    AuthnAuthz,
    Misconfiguration,
    InfoDisclosure,
    DataValidation,
    Ssrf,
    Xxe,
    Deserialization,
    BusinessLogic,
    DenialOfService,
    ClientSide,
    SupplyChain,
    Other,
}

impl Category {
    pub fn as_wire(self) -> &'static str {
        match self {
            Category::Injection => "injection",
            Category::AccessControl => "access_control",
            Category::Cryptography => "cryptography",
            Category::AuthnAuthz => "authn_authz",
            Category::Misconfiguration => "misconfiguration",
            Category::InfoDisclosure => "info_disclosure",
            Category::DataValidation => "data_validation",
            Category::Ssrf => "ssrf",
            Category::Xxe => "xxe",
            Category::Deserialization => "deserialization",
            Category::BusinessLogic => "business_logic",
            Category::DenialOfService => "denial_of_service",
            Category::ClientSide => "client_side",
            Category::SupplyChain => "supply_chain",
            Category::Other => "other",
        }
    }
}

/// `domains::findings::model::FindingSeverity` (5 variants, `as_str()`).
#[derive(Debug, Clone, Copy, ValueEnum)]
#[value(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_wire(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// `shared::ai::prompt_guard::ArtifactKind` (4 variants).
#[derive(Debug, Clone, Copy, ValueEnum)]
#[value(rename_all = "snake_case")]
pub enum ArtifactKind {
    HttpRequest,
    HttpResponse,
    Log,
    ScannerOutput,
}

impl ArtifactKind {
    pub fn as_wire(self) -> &'static str {
        match self {
            ArtifactKind::HttpRequest => "http_request",
            ArtifactKind::HttpResponse => "http_response",
            ArtifactKind::Log => "log",
            ArtifactKind::ScannerOutput => "scanner_output",
        }
    }

    /// Parses a CLI-facing token (`"log"`, `"http_request"`, ...) back into
    /// the enum, for `--artifact <kind>=<content>` parsing. Kept separate
    /// from clap's own `ValueEnum::from_str` so `--artifact` parsing (a
    /// hand-rolled `key=value` split, not a plain enum arg) doesn't need to
    /// reach into clap's derive machinery.
    pub fn parse_wire(s: &str) -> Option<ArtifactKind> {
        match s {
            "http_request" => Some(ArtifactKind::HttpRequest),
            "http_response" => Some(ArtifactKind::HttpResponse),
            "log" => Some(ArtifactKind::Log),
            "scanner_output" => Some(ArtifactKind::ScannerOutput),
            _ => None,
        }
    }
}

/// `shared::ai::prompt_guard::Artifact { kind: ArtifactKind, content: String }`.
#[derive(Debug, Clone, Serialize)]
pub struct Artifact {
    pub kind: String,
    pub content: String,
}

/// `domains::findings::ai_authoring::AiDraftRequest` — field names and
/// optionality copied verbatim (`cwes`/`artifacts` are required arrays,
/// possibly empty; everything else marked `#[serde(default)]` there is
/// `Option`/skip-if-none here).
#[derive(Debug, Clone, Serialize)]
pub struct AiDraftRequest {
    pub category: String,
    pub severity: String,
    pub cwes: Vec<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_vector: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub language: String,
    pub artifacts: Vec<Artifact>,
}

/// `domains::findings::ai_authoring::AiRewriteRequest`.
#[derive(Debug, Clone, Serialize)]
pub struct AiRewriteRequest {
    pub fields: Vec<String>,
    pub artifacts: Vec<Artifact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    pub language: String,
}

/// Mirrors `domains::assessments::model::CreateAssessmentRequest`
/// (`POST /v1/assessments`) field-for-field. Only `name` is required; every
/// optional field is skipped from the JSON body when unset, so the wizard
/// sends exactly what the operator answered. `assessment_type`/`category`
/// are free-form strings here (the server 422s an unknown enum value); the
/// wizard restricts them to the valid set (`commands::assessment_new`).
#[derive(Debug, Clone, Default, Serialize)]
pub struct CreateAssessmentRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assessment_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_date: Option<NaiveDate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_date: Option<NaiveDate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_hours: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules_of_engagement: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub testing_window_start: Option<NaiveTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub testing_window_end: Option<NaiveTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub testing_window_timezone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub testing_days: Option<i16>,
}

/// `domains::clients::model::CreateClientRequest` — `POST /v1/clients`. Only
/// the company name is required (the server owns everything else).
#[derive(Debug, Clone, Serialize)]
pub struct CreateClientRequest {
    pub company_name: String,
}

/// The subset of `UpdateAssessmentRequest` the CLI sends to bind a client to
/// an existing assessment (`PUT /v1/assessments/{id}`). The update is partial
/// — every field it omits is left untouched — so this one-field body only
/// changes the client link.
#[derive(Debug, Clone, Serialize)]
pub struct BindClientRequest {
    pub client_id: Uuid,
}

/// Read-only subset of `domains::clients::model::Client`.
#[derive(Debug, Clone, Deserialize)]
pub struct Client {
    pub id: Uuid,
    pub company_name: String,
    #[serde(default)]
    pub created_at: Option<String>,
}

/// Read-only subset of `domains::assessments::model::Assessment`.
#[derive(Debug, Clone, Deserialize)]
pub struct Assessment {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub assessment_type: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub slug: Option<String>,
}

/// `domains::assessments::model::AssessmentListResponse`.
#[derive(Debug, Clone, Deserialize)]
pub struct AssessmentListResponse {
    pub items: Vec<Assessment>,
    #[serde(default)]
    pub total: i64,
}

/// Read-only subset of asset data.
#[derive(Debug, Clone, Deserialize)]
pub struct Asset {
    pub id: Uuid,
    pub asset_type: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub criticality: Option<String>,
}

/// Asset list response envelope.
#[derive(Debug, Clone, Deserialize)]
pub struct AssetListResponse {
    pub items: Vec<Asset>,
    #[serde(default)]
    pub total: i64,
}

/// Read-only subset of `domains::findings::model::Finding` — `GET
/// /v1/assessments/{id}/findings` returns a bare `Vec<Finding>` (no
/// envelope), so this deserializes directly against that array.
#[derive(Debug, Clone, Deserialize)]
pub struct FindingSummary {
    pub id: Uuid,
    #[serde(default)]
    pub display_code: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub status: String,
}

/// `GET /v1/methodologies` list-summary shape
/// (`domains::methodologies::model::MethodologyResponse`) — only the fields
/// the `new assessment` wizard's checklist-pack step needs: `slug`/`name`
/// to display and Tab-complete the pick, `id` to apply it to the just-
/// created assessment via `PUT /v1/assessments/{id}/methodology`.
#[derive(Debug, Clone, Deserialize)]
pub struct Methodology {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
}

/// `shared::pagination::PaginatedResponse<MethodologyResponse>` — the
/// envelope `GET /v1/methodologies` responds with. Keyed `data`, unlike
/// `AssessmentListResponse`/`AssetListResponse`'s `items` — the two domains
/// use different list-envelope shapes on the Rust side, confirmed against
/// `code/src/tandera-api/tests/checklist_packs.rs`'s own
/// `listed["data"].as_array()` assertion.
#[derive(Debug, Clone, Deserialize)]
pub struct MethodologyListResponse {
    pub data: Vec<Methodology>,
}

/// `shared::error::AppError`'s `IntoResponse` body shape:
/// `{"error": {"code": "...", "message": "..."}}`.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorBody {
    pub error: ApiErrorDetail,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorDetail {
    #[serde(default)]
    pub code: String,
    pub message: String,
}

/// Read-only subset of testing window/blackout status.
#[derive(Debug, Clone, Deserialize)]
pub struct TestingStatus {
    pub is_within_window: bool,
    pub is_allowed_day: bool,
    pub is_blackout: bool,
    pub is_testing_allowed: bool,
    #[serde(default)]
    pub message: String,
}

/// Org credits: plan-allocated, user-purchased, and low-balance flag.
#[derive(Debug, Clone, Deserialize)]
pub struct Credits {
    pub plan_credits: i32,
    pub purchased_credits: i32,
    pub total: i32,
    #[serde(default)]
    pub low: bool,
}

/// A single scope entry: `scope_type` and `value` (IP, CIDR, domain, etc.).
#[derive(Debug, Clone, Deserialize)]
pub struct Scope {
    pub scope_type: String,
    pub value: String,
}

/// List of scopes (envelope — may be absent, in which case `fetch_scopes` handles both this and a bare array).
#[derive(Debug, Clone, Deserialize)]
pub struct ScopeListResponse {
    #[serde(default)]
    pub items: Vec<Scope>,
}

/// `POST /v1/assessments/{id}/imports/upload-url` response. The real API's
/// exact field names weren't confirmed at the time this client was written,
/// so both a `upload_url`/`url` and an `import_id`/`id` variant are accepted
/// — `resolved_upload_url`/`resolved_import_id` pick whichever was present.
/// Everything else in the response is ignored (serde's default behavior).
#[derive(Debug, Clone, Deserialize)]
pub struct UploadUrlResponse {
    #[serde(default)]
    pub upload_url: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub import_id: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
}

impl UploadUrlResponse {
    pub fn resolved_upload_url(&self) -> Option<&str> {
        first_present(self.upload_url.as_deref(), self.url.as_deref())
    }

    pub fn resolved_import_id(&self) -> Option<&str> {
        first_present(self.import_id.as_deref(), self.id.as_deref())
    }
}

/// Picks whichever of two field-name variants for the same logical value
/// was actually present in a tolerantly-parsed response — shared by
/// `UploadUrlResponse` and `AttachmentUploadUrlResponse`, which both accept
/// an `upload_url`/`url` pair (and their own separately-named id field).
fn first_present<'a>(primary: Option<&'a str>, fallback: Option<&'a str>) -> Option<&'a str> {
    primary.or(fallback)
}

/// `POST /v1/assessments/{aid}/findings/{fid}/attachments` response — mints
/// a presigned upload URL + attachment id for a screenshot/evidence upload
/// (used by `:finding`'s clipboard-screenshot flow and `:paste`). The real
/// API's exact field names weren't confirmed at the time this client was
/// written (no schema available), so both an `upload_url`/`url` and an
/// `attachment_id`/`id` variant are accepted, same tolerance strategy as
/// `UploadUrlResponse`.
#[derive(Debug, Clone, Deserialize)]
pub struct AttachmentUploadUrlResponse {
    #[serde(default)]
    pub upload_url: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub attachment_id: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
}

impl AttachmentUploadUrlResponse {
    pub fn resolved_upload_url(&self) -> Option<&str> {
        first_present(self.upload_url.as_deref(), self.url.as_deref())
    }

    pub fn resolved_attachment_id(&self) -> Option<&str> {
        first_present(self.attachment_id.as_deref(), self.id.as_deref())
    }
}

/// `POST /v1/assessments/{id}/imports/{import}/preview` (and reused for the
/// `/confirm` response, which is assumed to carry the same counts): asset
/// and finding counts detected in the uploaded file. Same field-name
/// uncertainty as `UploadUrlResponse` — a flat `asset_count`/`finding_count`,
/// a pluralized `assets_count`/`findings_count`, and a nested
/// `counts: { assets, findings }` shape are all tolerated; an absent count
/// resolves to `0` rather than failing the whole response.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PreviewResponse {
    #[serde(default)]
    pub asset_count: Option<i64>,
    #[serde(default)]
    pub assets_count: Option<i64>,
    #[serde(default)]
    pub finding_count: Option<i64>,
    #[serde(default)]
    pub findings_count: Option<i64>,
    #[serde(default)]
    pub counts: Option<PreviewCounts>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PreviewCounts {
    #[serde(default)]
    pub assets: Option<i64>,
    #[serde(default)]
    pub findings: Option<i64>,
}

impl PreviewResponse {
    pub fn resolved_asset_count(&self) -> i64 {
        self.asset_count
            .or(self.assets_count)
            .or_else(|| self.counts.as_ref().and_then(|c| c.assets))
            .unwrap_or(0)
    }

    pub fn resolved_finding_count(&self) -> i64 {
        self.finding_count
            .or(self.findings_count)
            .or_else(|| self.counts.as_ref().and_then(|c| c.findings))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_wire_values_match_the_api_enum_exactly() {
        assert_eq!(Category::Injection.as_wire(), "injection");
        assert_eq!(Category::AccessControl.as_wire(), "access_control");
        assert_eq!(Category::AuthnAuthz.as_wire(), "authn_authz");
        assert_eq!(Category::InfoDisclosure.as_wire(), "info_disclosure");
        assert_eq!(Category::DataValidation.as_wire(), "data_validation");
        assert_eq!(Category::DenialOfService.as_wire(), "denial_of_service");
        assert_eq!(Category::ClientSide.as_wire(), "client_side");
        assert_eq!(Category::SupplyChain.as_wire(), "supply_chain");
    }

    #[test]
    fn severity_wire_values_match_the_api_enum_exactly() {
        assert_eq!(Severity::Info.as_wire(), "info");
        assert_eq!(Severity::Critical.as_wire(), "critical");
    }

    #[test]
    fn artifact_kind_round_trips_through_parse_wire() {
        for kind in [
            ArtifactKind::HttpRequest,
            ArtifactKind::HttpResponse,
            ArtifactKind::Log,
            ArtifactKind::ScannerOutput,
        ] {
            let wire = kind.as_wire();
            let parsed = ArtifactKind::parse_wire(wire).expect("round trip");
            assert_eq!(parsed.as_wire(), wire);
        }
        assert!(ArtifactKind::parse_wire("not_a_kind").is_none());
    }

    #[test]
    fn ai_draft_request_serializes_with_exact_field_names() {
        let req = AiDraftRequest {
            category: Category::Injection.as_wire().to_string(),
            severity: Severity::High.as_wire().to_string(),
            cwes: vec![89],
            cvss_vector: None,
            asset_id: None,
            note: Some("note text".to_string()),
            language: "en".to_string(),
            artifacts: vec![Artifact {
                kind: ArtifactKind::Log.as_wire().to_string(),
                content: "log line".to_string(),
            }],
        };
        let json = serde_json::to_value(&req).expect("serialize");
        assert_eq!(json["category"], "injection");
        assert_eq!(json["severity"], "high");
        assert_eq!(json["cwes"], serde_json::json!([89]));
        assert!(json.get("cvss_vector").is_none(), "None must be omitted");
        assert!(json.get("asset_id").is_none(), "None must be omitted");
        assert_eq!(json["note"], "note text");
        assert_eq!(json["language"], "en");
        assert_eq!(json["artifacts"][0]["kind"], "log");
        assert_eq!(json["artifacts"][0]["content"], "log line");
    }

    #[test]
    fn assessment_list_response_ignores_unknown_fields() {
        let raw = serde_json::json!({
            "items": [
                {"id": "00000000-0000-0000-0000-000000000001", "name": "A", "status": "draft", "org_id": "should-be-ignored", "extra_future_field": 42}
            ],
            "total": 1
        });
        let parsed: AssessmentListResponse =
            serde_json::from_value(raw).expect("deserializes despite extra/unknown fields");
        assert_eq!(parsed.items.len(), 1);
        assert_eq!(parsed.items[0].name, "A");
    }

    #[test]
    fn api_error_body_parses_the_app_error_shape() {
        let raw = serde_json::json!({"error": {"code": "PLAN_GATED_AI_AUTHORING", "message": "AI finding authoring is not available on your plan"}});
        let parsed: ApiErrorBody = serde_json::from_value(raw).expect("parse");
        assert_eq!(
            parsed.error.message,
            "AI finding authoring is not available on your plan"
        );
    }

    #[test]
    fn asset_list_response_deserializes_and_tolerates_missing_fields() {
        let raw = r#"{"items":[{"id":"00000000-0000-0000-0000-000000000001","asset_type":"host","value":"10.0.0.5"}],"total":1}"#;
        let resp: crate::models::AssetListResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(resp.total, 1);
        assert_eq!(resp.items[0].asset_type, "host");
        assert_eq!(resp.items[0].value.as_deref(), Some("10.0.0.5"));
        assert!(resp.items[0].criticality.is_none());
    }

    #[test]
    fn upload_url_response_resolves_either_field_name_variant() {
        let a: UploadUrlResponse =
            serde_json::from_str(r#"{"upload_url":"https://s3/1","import_id":"imp-1"}"#).unwrap();
        assert_eq!(a.resolved_upload_url(), Some("https://s3/1"));
        assert_eq!(a.resolved_import_id(), Some("imp-1"));

        let b: UploadUrlResponse =
            serde_json::from_str(r#"{"url":"https://s3/2","id":"imp-2"}"#).unwrap();
        assert_eq!(b.resolved_upload_url(), Some("https://s3/2"));
        assert_eq!(b.resolved_import_id(), Some("imp-2"));
    }

    #[test]
    fn attachment_upload_url_response_resolves_either_field_name_variant() {
        let a: AttachmentUploadUrlResponse =
            serde_json::from_str(r#"{"upload_url":"https://s3/att-1","attachment_id":"att-1"}"#)
                .unwrap();
        assert_eq!(a.resolved_upload_url(), Some("https://s3/att-1"));
        assert_eq!(a.resolved_attachment_id(), Some("att-1"));

        let b: AttachmentUploadUrlResponse =
            serde_json::from_str(r#"{"url":"https://s3/att-2","id":"att-2"}"#).unwrap();
        assert_eq!(b.resolved_upload_url(), Some("https://s3/att-2"));
        assert_eq!(b.resolved_attachment_id(), Some("att-2"));
    }

    #[test]
    fn preview_response_resolves_flat_pluralized_and_nested_counts() {
        let flat: PreviewResponse =
            serde_json::from_str(r#"{"asset_count":5,"finding_count":3}"#).unwrap();
        assert_eq!(flat.resolved_asset_count(), 5);
        assert_eq!(flat.resolved_finding_count(), 3);

        let pluralized: PreviewResponse =
            serde_json::from_str(r#"{"assets_count":7,"findings_count":2}"#).unwrap();
        assert_eq!(pluralized.resolved_asset_count(), 7);
        assert_eq!(pluralized.resolved_finding_count(), 2);

        let nested: PreviewResponse =
            serde_json::from_str(r#"{"counts":{"assets":9,"findings":4}}"#).unwrap();
        assert_eq!(nested.resolved_asset_count(), 9);
        assert_eq!(nested.resolved_finding_count(), 4);

        let absent: PreviewResponse = serde_json::from_str(r#"{}"#).unwrap();
        assert_eq!(absent.resolved_asset_count(), 0);
        assert_eq!(absent.resolved_finding_count(), 0);
    }
}
