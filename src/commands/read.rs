//! `:findings`, `:asset list [TYPE]`, `:report` — read-only review of the
//! active assessment. All over existing endpoints; honors `--json` at the
//! call site (mod.rs), which passes the raw JSON through.

use serde_json::Value;
use uuid::Uuid;

use crate::api::{ApiClient, ApiError};
use crate::commands::truncate;
use crate::models::Asset;

/// `GET /v1/assessments/{id}/assets`, optionally filtered to one asset_type.
pub fn list_assets(
    client: &ApiClient,
    assessment: Uuid,
    asset_type: Option<&str>,
) -> Result<Value, ApiError> {
    let path = format!("/v1/assessments/{assessment}/assets");
    match asset_type {
        Some(t) => client.get_json_query(&path, &[("asset_type", t)]),
        None => client.get_json(&path),
    }
}

pub fn format_assets_table(items: &[Asset]) -> String {
    if items.is_empty() {
        return "No assets found.".to_string();
    }
    let mut out = format!("{:<14} {:<40} CRITICALITY\n", "TYPE", "VALUE");
    for a in items {
        let value = a.value.as_deref().or(a.name.as_deref()).unwrap_or("-");
        out.push_str(&format!(
            "{:<14} {:<40} {}\n",
            truncate(&a.asset_type, 14),
            truncate(value, 40),
            a.criticality.as_deref().unwrap_or("-")
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Asset;
    use uuid::Uuid;

    #[test]
    fn format_assets_table_has_header_and_rows() {
        let a = Asset {
            id: Uuid::nil(),
            asset_type: "host".into(),
            value: Some("10.0.0.5".into()),
            name: None,
            criticality: Some("high".into()),
        };
        let out = format_assets_table(&[a]);
        assert!(out.contains("TYPE"));
        assert!(out.contains("host"));
        assert!(out.contains("10.0.0.5"));
    }

    #[test]
    fn format_assets_table_empty_is_friendly() {
        assert!(format_assets_table(&[]).contains("No assets"));
    }
}
