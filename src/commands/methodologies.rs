//! `GET /v1/methodologies` — backs the `new assessment` wizard's "what are
//! you testing?" step (Task 8). Mirrors the console's Task 7 reframe
//! (`apps/console/.../AssessmentForm.svelte`) against the identical
//! endpoint: the front door offers the 5 published checklist packs
//! suggested for the assessment's scope category, and the 13 now-archived
//! framework methodologies (WSTG, PTES, …) are reachable only via an
//! explicit, separate call — never mixed into the default list.
//!
//! `list_packs`/`list_reference_frameworks` return the read-only
//! `Methodology` subset (`id`/`slug`/`name`) the wizard displays and
//! Tab-completes on. There's no `CreateAssessmentRequest` field for a
//! methodology — `apply_to_assessment` below applies a pick via the
//! separate `PUT /v1/assessments/{assessment_id}/methodology` endpoint,
//! called by the wizard right after a successful create (see
//! `assessment_new::run_wizard`'s doc comment).

use serde::Serialize;
use uuid::Uuid;

use crate::api::{ApiClient, ApiError};
use crate::models::{Methodology, MethodologyListResponse};

/// The literal answer that switches the wizard from the primary pack list
/// to the archived reference-framework sub-prompt (`ask_reference_
/// framework` in `assessment_new.rs`). Never a methodology slug itself —
/// system methodology slugs are namespaced `pack_*`/framework-specific, so
/// this can't collide with a real one.
pub const REFERENCE_FRAMEWORKS_TOKEN: &str = "advanced";

/// The checklist packs suggested for `category` (the assessment's flat
/// scope category — `external`/`internal`/`cloud`/`mobile`/`advanced`).
/// The server forces a published-only read whenever `category` is present
/// (`domains::methodologies::service::list`'s D-M5 rule), so this can never
/// return an archived framework — no `status` filter is sent here.
pub fn list_packs(client: &ApiClient, category: &str) -> Result<Vec<Methodology>, ApiError> {
    let resp: MethodologyListResponse =
        client.get_json_query("/v1/methodologies", &[("category", category)])?;
    Ok(resp.data)
}

/// The 13 archived framework methodologies — reachable only by this
/// explicit `status=archived` call, never bundled into `list_packs`'s
/// result and never queried unless the operator explicitly opts in via
/// `REFERENCE_FRAMEWORKS_TOKEN`.
pub fn list_reference_frameworks(client: &ApiClient) -> Result<Vec<Methodology>, ApiError> {
    let resp: MethodologyListResponse =
        client.get_json_query("/v1/methodologies", &[("status", "archived")])?;
    Ok(resp.data)
}

/// `PUT /v1/assessments/{assessment_id}/methodology` — applies a published
/// checklist pack/framework to an assessment
/// (`domains::methodologies::handler::apply`; mounted alongside the catalog
/// reads above for the same reason the server-side doc comment gives: it's
/// about an assessment's applied methodology, not the catalog itself).
/// Admin/manager, not plan-gated. The wizard calls this right after a
/// successful create, when the operator picked a pack/framework — a
/// failure here is never fatal (the assessment already exists by then), so
/// this returns a plain `Result` and lets the caller decide how to report
/// it.
pub fn apply_to_assessment(
    client: &ApiClient,
    assessment_id: Uuid,
    methodology_id: Uuid,
) -> Result<(), ApiError> {
    #[derive(Serialize)]
    struct ApplyMethodologyRequest {
        methodology_id: Uuid,
    }
    client.put_json_no_content(
        &format!("/v1/assessments/{assessment_id}/methodology"),
        &ApplyMethodologyRequest { methodology_id },
    )
}

/// The Tab-completion word list for the primary "what are you testing?"
/// prompt: every pack's slug, plus the `advanced` escape hatch. Frameworks
/// are deliberately never included — they only become reachable after the
/// operator answers `advanced`, which drives a second, separate prompt
/// built from `list_reference_frameworks`'s own result.
pub fn pack_prompt_words(packs: &[Methodology]) -> Vec<String> {
    let mut words: Vec<String> = packs.iter().map(|p| p.slug.clone()).collect();
    words.push(REFERENCE_FRAMEWORKS_TOKEN.to_string());
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack(slug: &str, name: &str) -> Methodology {
        Methodology {
            id: uuid::Uuid::nil(),
            slug: slug.to_string(),
            name: name.to_string(),
        }
    }

    #[test]
    fn pack_prompt_words_offers_every_pack_plus_the_advanced_escape() {
        let packs = vec![
            pack("pack_web", "Web Application"),
            pack("pack_api", "API"),
            pack("pack_mobile", "Mobile"),
            pack("pack_internal", "Internal Network"),
            pack("pack_red_team", "Red Team"),
        ];
        let words = pack_prompt_words(&packs);
        assert_eq!(
            words,
            vec![
                "pack_web",
                "pack_api",
                "pack_mobile",
                "pack_internal",
                "pack_red_team",
                "advanced",
            ]
        );
    }

    #[test]
    fn pack_prompt_words_never_includes_a_framework_slug() {
        // Frameworks are only ever reachable through the `advanced` token,
        // never mixed into the primary word list itself.
        let packs = vec![pack("pack_web", "Web Application")];
        let words = pack_prompt_words(&packs);
        assert!(!words.iter().any(|w| w == "owasp_wstg" || w == "ptes"));
        assert!(words.contains(&REFERENCE_FRAMEWORKS_TOKEN.to_string()));
    }

    #[test]
    fn pack_prompt_words_on_empty_packs_is_just_the_advanced_escape() {
        assert_eq!(pack_prompt_words(&[]), vec!["advanced".to_string()]);
    }
}
