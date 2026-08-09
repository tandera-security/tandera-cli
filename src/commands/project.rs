//! `:project` / `:use` — pick and persist the active assessment.

use std::path::Path;

use anyhow::Result;
use serde_json::Value;
use uuid::Uuid;

use crate::api::{ApiClient, ApiError};
use crate::config::Config;
use crate::models::Assessment;

pub fn list(client: &ApiClient) -> Result<Value, ApiError> {
    client.get_json("/v1/assessments")
}

/// Resolve a user-typed needle to an assessment id: exact id, then slug,
/// then case-insensitive name.
pub fn resolve_assessment(items: &[Assessment], needle: &str) -> Option<Uuid> {
    if let Ok(id) = Uuid::parse_str(needle) {
        if items.iter().any(|a| a.id == id) {
            return Some(id);
        }
    }
    if let Some(a) = items.iter().find(|a| a.slug.as_deref() == Some(needle)) {
        return Some(a.id);
    }
    items
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case(needle))
        .map(|a| a.id)
}

/// Persist the active assessment (store the slug if we have one, else the id
/// string) to the config file.
pub fn set_active(cfg_path: &Path, value: &str) -> Result<()> {
    let mut cfg = Config::load_from(cfg_path)?;
    cfg.assessment = Some(value.to_string());
    cfg.save_to(cfg_path)?;
    Ok(())
}

pub fn clear_active(cfg_path: &Path) -> Result<()> {
    let mut cfg = Config::load_from(cfg_path)?;
    cfg.assessment = None;
    cfg.save_to(cfg_path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Assessment;
    use uuid::Uuid;

    fn a(id: &str, slug: &str, name: &str) -> Assessment {
        Assessment {
            id: Uuid::parse_str(id).unwrap(),
            name: name.to_string(),
            slug: Some(slug.to_string()),
            status: "active".into(),
            assessment_type: None,
            category: None,
        }
    }

    #[test]
    fn resolve_by_slug_then_name_then_id() {
        let items = vec![
            a(
                "00000000-0000-0000-0000-000000000001",
                "acme-web",
                "Acme Web",
            ),
            a(
                "00000000-0000-0000-0000-000000000002",
                "acme-api",
                "Acme API",
            ),
        ];
        assert_eq!(resolve_assessment(&items, "acme-api"), Some(items[1].id));
        assert_eq!(resolve_assessment(&items, "Acme Web"), Some(items[0].id));
        assert_eq!(
            resolve_assessment(&items, "00000000-0000-0000-0000-000000000002"),
            Some(items[1].id)
        );
        assert_eq!(resolve_assessment(&items, "nope"), None);
    }
}
