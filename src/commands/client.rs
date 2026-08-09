//! `:client` / `tandera client` — add a client and bind it to the active
//! assessment, list clients, or bind an existing one.
//!
//! The headline is low-friction: `client add "<company>"` creates the client
//! *and* binds it to the active assessment in one step. Binding uses the
//! assessment's partial update (`PUT /v1/assessments/{id}` with just
//! `client_id`), so nothing else on the assessment changes.

use serde_json::Value;
use uuid::Uuid;

use crate::api::{ApiClient, ApiError};
use crate::models::{BindClientRequest, Client, CreateClientRequest};

/// `POST /v1/clients` — create a client from its company name.
pub fn create_client(client: &ApiClient, company_name: &str) -> Result<Value, ApiError> {
    let req = CreateClientRequest {
        company_name: company_name.to_string(),
    };
    client.post_json("/v1/clients", &req)
}

/// `GET /v1/clients` — the org's clients (raw, for `--json` or the table).
pub fn list_clients(client: &ApiClient) -> Result<Value, ApiError> {
    client.get_json("/v1/clients")
}

/// `PUT /v1/assessments/{assessment_id}` with only `client_id` — a partial
/// update that binds the client and leaves every other field untouched.
pub fn bind_client(
    client: &ApiClient,
    assessment_id: Uuid,
    client_id: Uuid,
) -> Result<(), ApiError> {
    let req = BindClientRequest { client_id };
    let _: Value = client.put_json(&format!("/v1/assessments/{assessment_id}"), &req)?;
    Ok(())
}

/// Create a client and bind it to `assessment_id` in one step. Returns the
/// new client's id.
pub fn add_and_bind(
    client: &ApiClient,
    assessment_id: Uuid,
    company_name: &str,
) -> Result<Uuid, ApiError> {
    let created = create_client(client, company_name)?;
    let id = extract_client_id(&created).ok_or_else(|| {
        ApiError::Transport("client created but its id was missing from the response".to_string())
    })?;
    bind_client(client, assessment_id, id)?;
    Ok(id)
}

/// Bind an *existing* client (resolved by id or company name) to
/// `assessment_id`. `Ok(None)` means no client matched `needle`.
pub fn bind_existing(
    client: &ApiClient,
    assessment_id: Uuid,
    needle: &str,
) -> Result<Option<String>, ApiError> {
    let items = parse_clients(list_clients(client)?);
    match resolve_client(&items, needle) {
        Some(found) => {
            bind_client(client, assessment_id, found.id)?;
            Ok(Some(found.company_name.clone()))
        }
        None => Ok(None),
    }
}

/// Resolve a user-typed needle to a client: exact id first, then
/// case-insensitive company name.
pub fn resolve_client<'a>(items: &'a [Client], needle: &str) -> Option<&'a Client> {
    if let Ok(id) = Uuid::parse_str(needle) {
        if let Some(found) = items.iter().find(|c| c.id == id) {
            return Some(found);
        }
    }
    items
        .iter()
        .find(|c| c.company_name.eq_ignore_ascii_case(needle))
}

/// Pull the created client's id out of the `POST /v1/clients` response.
pub fn extract_client_id(v: &Value) -> Option<Uuid> {
    v.get("id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
}

/// Deserialize the clients-list response, tolerating both a bare array and an
/// `{ "items": [...] }` envelope.
pub fn parse_clients(raw: Value) -> Vec<Client> {
    if let Some(items) = raw.get("items") {
        serde_json::from_value(items.clone()).unwrap_or_default()
    } else {
        serde_json::from_value(raw).unwrap_or_default()
    }
}

pub fn format_clients_table(items: &[Client]) -> String {
    if items.is_empty() {
        return "No clients found.".to_string();
    }
    let mut out = format!("{:<40} ID\n", "COMPANY");
    for c in items {
        out.push_str(&format!("{:<40} {}\n", c.company_name, c.id));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(id: &str, name: &str) -> Client {
        Client {
            id: Uuid::parse_str(id).unwrap(),
            company_name: name.to_string(),
            created_at: None,
        }
    }

    #[test]
    fn resolve_by_id_then_case_insensitive_name() {
        let items = vec![
            client("00000000-0000-0000-0000-000000000001", "Acme Corp"),
            client("00000000-0000-0000-0000-000000000002", "Beta LLC"),
        ];
        assert_eq!(
            resolve_client(&items, "beta llc").map(|c| c.id),
            Some(items[1].id)
        );
        assert_eq!(
            resolve_client(&items, "00000000-0000-0000-0000-000000000001").map(|c| c.id),
            Some(items[0].id)
        );
        assert!(resolve_client(&items, "nobody").is_none());
    }

    #[test]
    fn extract_client_id_reads_id_field() {
        let v = serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000009",
            "company_name": "X",
        });
        assert_eq!(
            extract_client_id(&v),
            Uuid::parse_str("00000000-0000-0000-0000-000000000009").ok()
        );
        assert!(extract_client_id(&serde_json::json!({})).is_none());
    }

    #[test]
    fn parse_clients_tolerates_array_and_envelope() {
        let arr = serde_json::json!([{"id":"00000000-0000-0000-0000-000000000001","company_name":"Acme"}]);
        assert_eq!(parse_clients(arr).len(), 1);
        let env = serde_json::json!({"items":[{"id":"00000000-0000-0000-0000-000000000001","company_name":"Acme"}],"total":1});
        assert_eq!(parse_clients(env).len(), 1);
    }

    #[test]
    fn table_shows_rows_and_friendly_empty() {
        let out =
            format_clients_table(&[client("00000000-0000-0000-0000-000000000001", "Acme Corp")]);
        assert!(out.contains("COMPANY"));
        assert!(out.contains("Acme Corp"));
        assert!(format_clients_table(&[]).contains("No clients"));
    }
}
