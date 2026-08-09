//! `:new assessment` / `:pentest` (and `tandera pentest`) — an interactive
//! wizard that creates an assessment via `POST /v1/assessments`.
//!
//! The wizard itself (`run_wizard`) is interactive (rustyline prompts with
//! per-field Tab-completion) and needs a TTY, so it isn't unit-tested. The
//! pure pieces it's built from — input validation, the `testing_days`
//! bitmask, request serialization, and the `create_assessment` POST plus
//! the follow-up `apply_checklist_methodology` PUT — are exercised against
//! stubs in `tests/`.

use anyhow::Result;
use chrono::{NaiveDate, NaiveTime};
use rustyline::completion::{Completer, Pair};
use rustyline::history::DefaultHistory;
use rustyline::{Editor, Helper};
use serde_json::Value;
use uuid::Uuid;

use crate::api::{ApiClient, ApiError};
use crate::commands::methodologies;
use crate::models::{CreateAssessmentRequest, Methodology};

/// A short curated set of IANA timezones offered for Tab-completion on the
/// testing-window timezone prompt. Any other value is still accepted (typed
/// in full) — this list is a convenience, not a whitelist.
const COMMON_TIMEZONES: &[&str] = &[
    "UTC",
    "America/Sao_Paulo",
    "America/New_York",
    "America/Chicago",
    "America/Los_Angeles",
    "Europe/London",
    "Europe/Lisbon",
    "Europe/Berlin",
    "Asia/Tokyo",
    "Australia/Sydney",
];

const DAY_NAMES: &[&str] = &["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

/// The `category` Postgres enum (`0005_assessments.sql`) — the *kind* of
/// pentest. The server 422s anything outside this set.
pub const CATEGORIES: &[&str] = &["external", "internal", "cloud", "mobile", "advanced"];

/// The `assessment_type` Postgres enum — the testing *methodology*.
pub const METHODOLOGIES: &[&str] = &["black_box", "gray_box", "white_box", "red_team"];

/// `POST /v1/assessments` — create an assessment. Returns the raw created
/// record (the wizard extracts the id/slug to make it active).
pub fn create_assessment(
    client: &ApiClient,
    req: &CreateAssessmentRequest,
) -> Result<Value, ApiError> {
    client.post_json("/v1/assessments", req)
}

/// Trim + length-check a name (server rule: 1–500 chars).
pub fn validate_name(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 500 {
        return Err("name must be 1–500 characters".to_string());
    }
    Ok(trimmed.to_string())
}

pub fn is_valid_category(s: &str) -> bool {
    CATEGORIES.contains(&s)
}

pub fn is_valid_methodology(s: &str) -> bool {
    METHODOLOGIES.contains(&s)
}

/// Parse a `YYYY-MM-DD` date, or a clear error.
pub fn parse_date(s: &str) -> Result<NaiveDate, String> {
    NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d")
        .map_err(|_| format!("`{}` is not a YYYY-MM-DD date", s.trim()))
}

/// End must be on or after start (server rule). `None`s pass.
pub fn validate_date_order(start: Option<NaiveDate>, end: Option<NaiveDate>) -> Result<(), String> {
    if let (Some(s), Some(e)) = (start, end) {
        if e < s {
            return Err("end date must be on or after start date".to_string());
        }
    }
    Ok(())
}

/// Server rule: 1..=100_000.
pub fn validate_hours(h: i32) -> Result<(), String> {
    if (1..=100_000).contains(&h) {
        Ok(())
    } else {
        Err("estimated hours must be between 1 and 100000".to_string())
    }
}

/// Parse `HH:MM` or `HH:MM:SS`.
pub fn parse_time(s: &str) -> Result<NaiveTime, String> {
    let s = s.trim();
    NaiveTime::parse_from_str(s, "%H:%M:%S")
        .or_else(|_| NaiveTime::parse_from_str(s, "%H:%M"))
        .map_err(|_| format!("`{s}` is not an HH:MM time"))
}

/// Build the `testing_days` bitmask from day names (bit0=Mon … bit6=Sun, to
/// match the server's `is_allowed_weekday`). Accepts `mon`/`monday` etc.,
/// case-insensitive; unknown names are ignored.
pub fn testing_days_bitmask(days: &[&str]) -> i16 {
    let mut mask = 0i16;
    for day in days {
        let bit = match day.trim().to_ascii_lowercase().as_str() {
            "mon" | "monday" => 0,
            "tue" | "tuesday" => 1,
            "wed" | "wednesday" => 2,
            "thu" | "thursday" => 3,
            "fri" | "friday" => 4,
            "sat" | "saturday" => 5,
            "sun" | "sunday" => 6,
            _ => continue,
        };
        mask |= 1 << bit;
    }
    mask
}

/// The created assessment the wizard hands back so the caller can make it the
/// active project (the REPL updates its live session; the subcommand persists
/// to config).
pub struct CreatedAssessment {
    pub id: Uuid,
    pub slug: Option<String>,
    pub name: String,
}

impl CreatedAssessment {
    /// The best handle to activate by: prefer the slug, fall back to the id.
    pub fn active_ref(&self) -> String {
        self.slug.clone().unwrap_or_else(|| self.id.to_string())
    }
}

/// A rustyline completer over a fixed word list — completes the current word
/// (the whole line, since wizard answers are single values) from `words`.
/// Non-matching input is left untouched (the prompt still accepts free text).
struct WordCompleter {
    words: Vec<String>,
}

impl Completer for WordCompleter {
    type Candidate = Pair;
    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let prefix = &line[..pos];
        let matches = self
            .words
            .iter()
            .filter(|w| w.starts_with(prefix))
            .map(|w| Pair {
                display: w.clone(),
                replacement: w.clone(),
            })
            .collect();
        Ok((0, matches))
    }
}

impl rustyline::hint::Hinter for WordCompleter {
    type Hint = String;
}
impl rustyline::highlight::Highlighter for WordCompleter {}
impl rustyline::validate::Validator for WordCompleter {}
impl Helper for WordCompleter {}

/// Read one line for `label`, offering `words` for Tab-completion. Returns
/// the trimmed input, or `None` on EOF/interrupt (Ctrl-D / Ctrl-C) so the
/// wizard can abort cleanly instead of hanging or panicking.
fn ask(
    rl: &mut Editor<WordCompleter, DefaultHistory>,
    label: &str,
    words: &[&str],
) -> Option<String> {
    rl.set_helper(Some(WordCompleter {
        words: words.iter().map(|w| (*w).to_string()).collect(),
    }));
    match rl.readline(&format!("{label}> ")) {
        Ok(line) => Some(line.trim().to_string()),
        Err(_) => None, // Eof / Interrupted / io error → abort the field
    }
}

/// Required free-text field: re-prompt until `validate` accepts, or abort on EOF.
fn ask_required<F>(
    rl: &mut Editor<WordCompleter, DefaultHistory>,
    label: &str,
    words: &[&str],
    validate: F,
) -> Option<String>
where
    F: Fn(&str) -> Result<String, String>,
{
    loop {
        let raw = ask(rl, label, words)?;
        match validate(&raw) {
            Ok(v) => return Some(v),
            Err(e) => println!("  {e}"),
        }
    }
}

/// Optional free-text field: empty input → `None` (skipped).
fn ask_optional(rl: &mut Editor<WordCompleter, DefaultHistory>, label: &str) -> Option<String> {
    let v = ask(rl, label, &[])?;
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// A `[y/N]` prompt: only an explicit yes is true; EOF/empty/anything else is no.
fn ask_yes(rl: &mut Editor<WordCompleter, DefaultHistory>, label: &str) -> bool {
    match ask(rl, &format!("{label} [y/N]"), &["yes"]) {
        Some(v) => matches!(v.to_ascii_lowercase().as_str(), "y" | "yes"),
        None => false,
    }
}

/// Optional field that must parse: empty → `None`; a bad value re-prompts.
fn ask_optional_parsed<T, F>(
    rl: &mut Editor<WordCompleter, DefaultHistory>,
    label: &str,
    parse: F,
) -> Option<T>
where
    F: Fn(&str) -> Result<T, String>,
{
    loop {
        let raw = ask(rl, label, &[])?;
        if raw.is_empty() {
            return None;
        }
        match parse(&raw) {
            Ok(v) => return Some(v),
            Err(e) => println!("  {e}"),
        }
    }
}

/// Collect the optional testing window (start/end time, timezone, days).
fn ask_testing_window(
    rl: &mut Editor<WordCompleter, DefaultHistory>,
) -> (
    Option<NaiveTime>,
    Option<NaiveTime>,
    Option<String>,
    Option<i16>,
) {
    let start = ask_optional_parsed(rl, "  window start HH:MM (enter to skip)", parse_time);
    let end = ask_optional_parsed(rl, "  window end HH:MM (enter to skip)", parse_time);
    let tz = ask(
        rl,
        "  timezone (Tab to complete, enter to skip)",
        COMMON_TIMEZONES,
    )
    .filter(|s| !s.is_empty());
    let days_line = ask(
        rl,
        "  testing days e.g. `mon,tue,wed` (enter to skip)",
        DAY_NAMES,
    );
    let days = days_line.and_then(|line| {
        if line.is_empty() {
            return None;
        }
        let names: Vec<&str> = line.split([',', ' ']).filter(|s| !s.is_empty()).collect();
        let mask = testing_days_bitmask(&names);
        (mask != 0).then_some(mask)
    });
    (start, end, tz, days)
}

/// Shared mechanics behind both methodology pickers below: print `header`,
/// list `items` (slug + name, Tab-completed via `words`), prompt
/// `prompt_label`, and resolve the answer against `items` by slug.
///
/// Returns `None` on EOF/interrupt or an empty (skip) answer — same as
/// `ask`. Otherwise returns `(answer, resolved)`: `resolved` is the
/// matching item, or `None` if the answer didn't match any `items` slug.
/// Callers that offer an answer outside `items` (the checklist prompt's
/// `advanced` escape to the reference-framework sub-prompt) inspect the raw
/// `answer`; callers that don't need to tell "skipped" apart from
/// "unmatched" just use `.1`. Fetching `items` (a different endpoint/error
/// message per caller) and what to do on an empty list or a `None` result
/// are both left to the caller — only the print/prompt/resolve steps that
/// were byte-for-byte identical are shared here.
fn pick_from_list(
    rl: &mut Editor<WordCompleter, DefaultHistory>,
    items: &[Methodology],
    header: &str,
    prompt_label: &str,
    words: &[&str],
) -> Option<(String, Option<Methodology>)> {
    println!("{header}");
    for item in items {
        println!("  {:<16} {}", item.slug, item.name);
    }
    let answer = ask(rl, prompt_label, words)?;
    if answer.is_empty() {
        return None;
    }
    let resolved = items.iter().find(|i| i.slug == answer).cloned();
    Some((answer, resolved))
}

/// The optional "what are you testing?" checklist-pack step (Task 8 — the
/// same front-door reframe Task 7 built for the console picker, against the
/// identical `GET /v1/methodologies` endpoint). Lists the packs suggested
/// for `category` and lets the operator Tab-complete one, or answer
/// `methodologies::REFERENCE_FRAMEWORKS_TOKEN` to browse the archived
/// reference frameworks instead — those are never offered by default.
///
/// A pick here is applied to the assessment right after it's created
/// (`run_wizard`'s `methodologies::apply_to_assessment` call) — that's a
/// separate `PUT`, not a `CreateAssessmentRequest` field, so the id
/// returned here is what makes that possible. A fetch failure or an empty
/// pack list (e.g. no packs cover `category`) silently skips the step —
/// this guidance must never block assessment creation.
fn ask_checklist_methodology(
    rl: &mut Editor<WordCompleter, DefaultHistory>,
    client: &ApiClient,
    category: &str,
) -> Option<Methodology> {
    let packs = match methodologies::list_packs(client, category) {
        Ok(p) => p,
        Err(e) => {
            crate::commands::print_api_error(&e);
            return None;
        }
    };
    if packs.is_empty() {
        return None;
    }

    let header = format!("What are you testing? (suggested checklists for {category})");
    let words = methodologies::pack_prompt_words(&packs);
    let word_refs: Vec<&str> = words.iter().map(String::as_str).collect();
    let (answer, resolved) = pick_from_list(
        rl,
        &packs,
        &header,
        "checklist (Tab-complete, `advanced` for reference frameworks, enter to skip)",
        &word_refs,
    )?;
    if answer == methodologies::REFERENCE_FRAMEWORKS_TOKEN {
        return ask_reference_framework(rl, client);
    }
    resolved
}

/// The archived reference-framework sub-prompt `ask_checklist_methodology`
/// falls into when the operator explicitly asks for it. Only ever reached
/// via that one path — never queried, let alone shown, by default.
fn ask_reference_framework(
    rl: &mut Editor<WordCompleter, DefaultHistory>,
    client: &ApiClient,
) -> Option<Methodology> {
    let frameworks = match methodologies::list_reference_frameworks(client) {
        Ok(f) => f,
        Err(e) => {
            crate::commands::print_api_error(&e);
            return None;
        }
    };
    if frameworks.is_empty() {
        println!("  no reference frameworks available.");
        return None;
    }

    let words: Vec<&str> = frameworks.iter().map(|f| f.slug.as_str()).collect();
    let (_, resolved) = pick_from_list(
        rl,
        &frameworks,
        "Reference frameworks (advanced, read-only):",
        "reference framework (Tab-complete, enter to skip)",
        &words,
    )?;
    resolved
}

/// Run the interactive create-assessment wizard. Prompts for the required
/// name + kind + methodology (Tab-completed) and the common optionals, POSTs
/// the assessment, and returns the created record. `Ok(None)` means the
/// operator aborted (Ctrl-D) or the API rejected the request (the error is
/// printed) — the caller simply continues.
///
/// If the operator also picked a checklist pack/reference framework
/// (`ask_checklist_methodology`), it's applied to the freshly created
/// assessment via `apply_checklist_methodology` right after the create
/// succeeds. That apply call is never allowed to turn a successful create
/// into a failure — the assessment already exists by that point, so a
/// failed apply is reported as a warning, not an error, and `run_wizard`
/// still returns `Ok(Some(..))`.
pub fn run_wizard(client: &ApiClient) -> Result<Option<CreatedAssessment>> {
    let mut rl: Editor<WordCompleter, DefaultHistory> = Editor::new()?;

    println!("New assessment — answer the prompts (Ctrl-D to cancel).");

    let name = match ask_required(&mut rl, "name", &[], validate_name) {
        Some(n) => n,
        None => return Ok(None),
    };
    let category = match ask_required(&mut rl, "kind of pentest", CATEGORIES, |s| {
        if is_valid_category(s) {
            Ok(s.to_string())
        } else {
            Err(format!("pick one of: {}", CATEGORIES.join(", ")))
        }
    }) {
        Some(c) => c,
        None => return Ok(None),
    };
    let assessment_type = match ask_required(&mut rl, "methodology", METHODOLOGIES, |s| {
        if is_valid_methodology(s) {
            Ok(s.to_string())
        } else {
            Err(format!("pick one of: {}", METHODOLOGIES.join(", ")))
        }
    }) {
        Some(m) => m,
        None => return Ok(None),
    };
    let checklist_methodology = ask_checklist_methodology(&mut rl, client, &category);

    let description = ask_optional(&mut rl, "description (enter to skip)");
    let start_date =
        ask_optional_parsed(&mut rl, "start date YYYY-MM-DD (enter to skip)", parse_date);
    let end_date = loop {
        let e = ask_optional_parsed(&mut rl, "end date YYYY-MM-DD (enter to skip)", parse_date);
        match validate_date_order(start_date, e) {
            Ok(()) => break e,
            Err(msg) => println!("  {msg}"),
        }
    };
    let estimated_hours = ask_optional_parsed(&mut rl, "estimated hours (enter to skip)", |s| {
        let h: i32 = s.parse().map_err(|_| "enter a whole number".to_string())?;
        validate_hours(h).map(|()| h)
    });
    let rules_of_engagement = ask_optional(&mut rl, "rules of engagement (enter to skip)");

    let (testing_window_start, testing_window_end, testing_window_timezone, testing_days) =
        if ask_yes(&mut rl, "add a testing window?") {
            ask_testing_window(&mut rl)
        } else {
            (None, None, None, None)
        };

    let req = CreateAssessmentRequest {
        name: name.clone(),
        description,
        assessment_type: Some(assessment_type),
        category: Some(category),
        start_date,
        end_date,
        estimated_hours,
        rules_of_engagement,
        testing_window_start,
        testing_window_end,
        testing_window_timezone,
        testing_days,
    };

    match create_assessment(client, &req) {
        Ok(v) => {
            let id = extract_id(&v);
            let slug = v.get("slug").and_then(Value::as_str).map(str::to_string);
            match id {
                Some(id) => {
                    let display = slug.clone().unwrap_or_else(|| id.to_string());
                    println!("✓ created assessment {display}");
                    if let Some(methodology) = &checklist_methodology {
                        apply_checklist_methodology(client, id, methodology);
                    }
                    Ok(Some(CreatedAssessment { id, slug, name }))
                }
                None => {
                    // Created, but we couldn't find the id to activate it.
                    println!("✓ assessment created (couldn't read its id from the response).");
                    Ok(None)
                }
            }
        }
        Err(e) => {
            crate::commands::print_api_error(&e);
            Ok(None)
        }
    }
}

/// Applies `methodology` to the just-created assessment `assessment_id` via
/// `PUT /v1/assessments/{assessment_id}/methodology`. Non-fatal by design:
/// called only after `create_assessment` already succeeded, so a failure
/// here must never read as "the assessment wasn't created" — it prints a
/// clearly-labeled warning (reusing `print_api_error` for the underlying
/// detail) and lets the wizard finish reporting the create as a success.
fn apply_checklist_methodology(client: &ApiClient, assessment_id: Uuid, methodology: &Methodology) {
    match methodologies::apply_to_assessment(client, assessment_id, methodology.id) {
        Ok(()) => println!("  checklist applied: {}", methodology.name),
        Err(e) => {
            println!(
                "  warning: assessment created, but applying \"{}\" failed — apply it later from the console.",
                methodology.name
            );
            crate::commands::print_api_error(&e);
        }
    }
}

/// Pull the created assessment's id out of the response, tolerating `id` or
/// `finding`-style nesting variants without ever panicking.
fn extract_id(v: &Value) -> Option<Uuid> {
    v.get("id")
        .or_else(|| v.get("assessment_id"))
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_trimmed_and_rejects_empty_or_too_long() {
        assert_eq!(validate_name("  Acme External  ").unwrap(), "Acme External");
        assert!(validate_name("   ").is_err());
        assert!(validate_name(&"x".repeat(501)).is_err());
        assert!(validate_name(&"x".repeat(500)).is_ok());
    }

    #[test]
    fn category_and_methodology_membership() {
        assert!(is_valid_category("external"));
        assert!(is_valid_category("advanced"));
        assert!(!is_valid_category("web"));
        assert!(is_valid_methodology("black_box"));
        assert!(is_valid_methodology("red_team"));
        assert!(!is_valid_methodology("greybox"));
    }

    #[test]
    fn parse_date_accepts_iso_rejects_other() {
        assert!(parse_date("2026-07-20").is_ok());
        assert!(parse_date("07/20/2026").is_err());
        assert!(parse_date("not-a-date").is_err());
    }

    #[test]
    fn date_order_requires_end_on_or_after_start() {
        let start = parse_date("2026-07-20").ok();
        let earlier = parse_date("2026-07-10").ok();
        assert!(validate_date_order(start, earlier).is_err());
        assert!(validate_date_order(start, start).is_ok());
        assert!(validate_date_order(start, None).is_ok());
        assert!(validate_date_order(None, None).is_ok());
    }

    #[test]
    fn hours_range_is_1_to_100000() {
        assert!(validate_hours(1).is_ok());
        assert!(validate_hours(100_000).is_ok());
        assert!(validate_hours(0).is_err());
        assert!(validate_hours(100_001).is_err());
    }

    #[test]
    fn parse_time_accepts_hh_mm_and_hh_mm_ss() {
        assert!(parse_time("09:00").is_ok());
        assert!(parse_time("17:30:00").is_ok());
        assert!(parse_time("25:00").is_err());
        assert!(parse_time("abc").is_err());
    }

    #[test]
    fn bitmask_maps_days_mon0_to_sun6() {
        assert_eq!(testing_days_bitmask(&["mon"]), 0b000_0001);
        assert_eq!(testing_days_bitmask(&["sun"]), 0b100_0000); // bit 6 = 64
                                                                // Mon(0) + Wed(2) + Fri(4) = 1 + 4 + 16 = 21
        assert_eq!(testing_days_bitmask(&["mon", "wed", "fri"]), 21);
        assert_eq!(testing_days_bitmask(&["Monday", "tuesday"]), 0b000_0011);
        assert_eq!(testing_days_bitmask(&["bogus"]), 0);
        assert_eq!(testing_days_bitmask(&[]), 0);
    }

    #[test]
    fn request_serializes_only_answered_fields() {
        let req = CreateAssessmentRequest {
            name: "Acme External".to_string(),
            category: Some("external".to_string()),
            assessment_type: Some("black_box".to_string()),
            ..Default::default()
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["name"], "Acme External");
        assert_eq!(v["category"], "external");
        assert_eq!(v["assessment_type"], "black_box");
        // Unanswered optionals are omitted entirely, not sent as null.
        assert!(v.get("description").is_none());
        assert!(v.get("start_date").is_none());
        assert!(v.get("testing_days").is_none());
    }
}
