//! Tab-completion + `:help` for the `tandera>` prompt.
//!
//! `META_VERBS` is the single source of truth for the `:`-prefixed verb
//! list: `complete_meta` (Tab-completion) and `help_text` (`:help`) both
//! derive from it, so a verb added/renamed here shows up in both places
//! without a second list to keep in sync. `dispatch_meta` in `repl::mod` is
//! the actual dispatcher and must accept the same verbs — see its module
//! doc for the one place that list is authoritative for *behavior*; this
//! module is authoritative for what the shell *advertises*.
//!
//! v1 only completes meta verbs (a bare `:` word). Tool-name/slug
//! completion is a later nicety, not built here (YAGNI).

/// Every `:`-prefixed verb the shell understands, in the order `:help`
/// prints them. Keep in sync with `dispatch_meta`'s `match` (in
/// `repl::mod`) — `:exit`/`:quit` are handled a step earlier, in
/// `handle_line`, but are still verbs a user can type/complete.
pub const META_VERBS: &[&str] = &[
    ":login",
    ":logout",
    ":auth",
    ":project",
    ":use",
    ":status",
    ":findings",
    ":finding",
    ":asset",
    ":pentest",
    ":new",
    ":portal",
    ":client",
    ":report",
    ":pause",
    ":resume",
    ":log",
    ":sync",
    ":paste",
    ":undo",
    ":help",
    ":exit",
    ":quit",
];

/// One-line summary for a verb in `META_VERBS`, used only by `help_text`.
/// A `match` rather than a second array, so `META_VERBS` stays the only
/// place the verb *names* are listed — this only supplies the description
/// text for a name `help_text` already got from `META_VERBS`.
fn summary(verb: &str) -> &'static str {
    match verb {
        ":login" => "sign in with a personal access token (prompts; verifies before saving)",
        ":logout" => "clear the stored token and sign out",
        ":auth" => "sign in/out or check status (`:auth login|logout|status`)",
        ":project" => "list assessments, or `:project current|clear|use <slug>`",
        ":use" => "set the active assessment (`:use <slug>`)",
        ":status" => "reprint the banner and refresh testing status/credits",
        ":findings" => "list findings for the active assessment",
        ":finding" => {
            "draft an AI finding from a phrase + clipboard screenshot (`:finding <phrase>`)"
        }
        ":asset" => "list discovered assets (`:asset list [TYPE]`)",
        ":pentest" => "create a new assessment via an interactive wizard",
        ":new" => "create something new (`:new assessment` — alias of `:pentest`)",
        ":portal" => "open the Tandera console in your browser (deep-links to the active assessment)",
        ":client" => "add/list/bind clients (`:client add <name>` creates + binds to the assessment)",
        ":report" => "preview the report (coming in a later phase)",
        ":pause" => "pause auto-upload of captured tool output",
        ":resume" => "resume auto-upload of captured tool output",
        ":log" => "print the local testing-log transcript",
        ":sync" => {
            "opt in/out of syncing the testing-log to the assessment activity timeline (`:sync on|off`)"
        }
        ":paste" => "attach a clipboard screenshot to the last-created finding",
        ":undo" => "undo the last capture/paste (Phase 4)",
        ":help" => "show this help",
        ":exit" | ":quit" => "leave the shell",
        _ => "",
    }
}

/// Render the full `:help` text: every verb in `META_VERBS` with its
/// one-line summary.
pub fn help_text() -> String {
    let mut out = String::from("Meta commands:\n");
    for v in META_VERBS {
        out.push_str(&format!("  {v:<10} {}\n", summary(v)));
    }
    out
}

/// Verbs in `META_VERBS` starting with `prefix`. Empty (never panics/errors)
/// when nothing matches, including when `prefix` doesn't start with `:` —
/// callers that only want `:`-completions should check that themselves
/// (see `ReplHelper::complete`).
pub fn complete_meta(prefix: &str) -> Vec<String> {
    META_VERBS
        .iter()
        .filter(|v| v.starts_with(prefix))
        .map(|v| (*v).to_string())
        .collect()
}

/// Rustyline helper wired into `run_shell`'s `Editor`. Only implements
/// `Completer` with real behavior — `Hinter`/`Highlighter`/`Validator` are
/// left at their no-op defaults, and `Helper` is the marker trait rustyline
/// requires to accept this as a combined helper type.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReplHelper;

impl rustyline::completion::Completer for ReplHelper {
    type Candidate = String;

    /// Complete a `:`-prefixed word at the cursor from `META_VERBS`. Any
    /// other line (no current word, or a word not starting with `:`) yields
    /// no completions rather than erroring — tool-name/slug completion is
    /// out of scope for v1.
    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let start = line[..pos].rfind(char::is_whitespace).map_or(0, |i| i + 1);
        let word = &line[start..pos];
        if !word.starts_with(':') {
            return Ok((pos, Vec::new()));
        }
        Ok((start, complete_meta(word)))
    }
}

impl rustyline::hint::Hinter for ReplHelper {
    type Hint = String;
}

impl rustyline::highlight::Highlighter for ReplHelper {}
impl rustyline::validate::Validator for ReplHelper {}
impl rustyline::Helper for ReplHelper {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_meta_matches_prefix() {
        let out = complete_meta(":fi");
        assert!(out.iter().any(|c| c == ":finding" || c == ":findings"));
        assert!(!out.iter().any(|c| c == ":project"));
    }

    #[test]
    fn help_lists_core_verbs() {
        let h = help_text();
        for v in [":project", ":finding", ":status", ":log", ":exit"] {
            assert!(h.contains(v), "help missing {v}");
        }
    }

    #[test]
    fn auth_verbs_are_advertised_and_completable() {
        // The shell now opens unauthenticated, so `:login`/`:logout` must be
        // discoverable both in `:help` and via Tab-completion.
        let h = help_text();
        assert!(h.contains(":login"), "help missing :login");
        assert!(h.contains(":logout"), "help missing :logout");
        assert!(h.contains(":auth"), "help missing :auth");

        let out = complete_meta(":lo");
        assert!(out.iter().any(|c| c == ":login"), "no :login completion");
        assert!(out.iter().any(|c| c == ":logout"), "no :logout completion");
        assert!(
            complete_meta(":au").iter().any(|c| c == ":auth"),
            "no :auth completion"
        );
    }
}
