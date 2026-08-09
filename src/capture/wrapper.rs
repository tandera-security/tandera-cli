//! The tool wrapper: the integration point for every line `classify`
//! recognizes as a known recon tool (`registry::is_known_tool`).
//!
//! The flow, in order:
//! 1. Look the tool up in the registry and try to extract its target
//!    (host/URL) from argv.
//! 2. Advisory gates (`confirm_gates`): if the testing window is closed, or
//!    the target is determinable and not in scope, warn and ask
//!    `[y/N]` — never a hard block, since both the window and the scope
//!    list are cached API state that can be stale, and target extraction is
//!    a heuristic that can miss.
//! 3. Per-session upload consent (`confirm_upload`): `Paused` never
//!    uploads, `Always` always does, `Ask` prompts once and (on `always`)
//!    upgrades the session to `Always` so later captures stop asking.
//! 4. Build the capture output path and inject the tool's output flag
//!    (unless the user already passed one), then run the tool directly
//!    (`Command`, not a shell) with stdio inherited and the session's
//!    cwd/env, logging the result to the testing log.
//! 5. If upload consent was given and the output file exists and is
//!    non-empty, enqueue an upload job on the session's background queue
//!    and print its `bgN` handle; otherwise leave the file on disk.
//!
//! Never panics and never hard-blocks: a gate warning, a missing active
//! assessment, or a failed enqueue all degrade to "skip the network part,
//! still let the user keep working" rather than propagating an `Err` that
//! would abort the shell.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;

use crate::capture::import;
use crate::capture::registry::{self, ToolSpec};
use crate::gates;
use crate::logbook;
use crate::repl::exec::ShellEnv;
use crate::repl::{AutoUpload, Session};

/// Build `<cwd>/output/<assessment>/recon/<tool>-<ts>.<ext>` — the same
/// `output/<assessment>/...` layout `repl::default_log_path` uses for the
/// testing log, so captured scan output and the log that references it live
/// under one assessment-scoped tree. `assessment` is sanitized the same way
/// (`/`/`\` -> `_`) in case a label ever contains one.
pub fn default_out_path(cwd: &Path, assessment: &str, tool: &str, ext: &str, ts: &str) -> PathBuf {
    let dir = assessment.replace(['/', '\\'], "_");
    cwd.join("output")
        .join(dir)
        .join("recon")
        .join(format!("{tool}-{ts}.{ext}"))
}

/// Inject `spec`'s output flag(s) pointed at `out_path`, unless `argv`
/// already carries an output flag — in which case the user's explicit
/// choice wins and argv is returned unchanged. The `bool` reports whether
/// injection happened.
pub fn build_capture_argv(spec: &ToolSpec, argv: &[String], out_path: &str) -> (Vec<String>, bool) {
    if (spec.has_output_flag)(argv) {
        return (argv.to_vec(), false);
    }
    let mut out = argv.to_vec();
    out.extend((spec.out_flags)(out_path));
    (out, true)
}

/// Print `text` and read one line of stdin, trimmed and lowercased. EOF or a
/// read/flush error both degrade to `""` rather than blocking or panicking —
/// every caller treats an empty answer as the safe default ("no" for the
/// gate prompt, "yes" for the upload-consent prompt, matching `[y/N]` vs
/// `[Y/n/always]`).
fn prompt(text: &str) -> String {
    print!("{text}");
    if io::stdout().flush().is_err() {
        return String::new();
    }
    let mut line = String::new();
    match io::stdin().read_line(&mut line) {
        Ok(0) | Err(_) => String::new(),
        Ok(_) => line.trim().to_lowercase(),
    }
}

fn is_yes(answer: &str) -> bool {
    matches!(answer, "y" | "yes")
}

/// Advisory scope/window check. Reads `window_open` + `scopes` out of the
/// session under one lock (via `Session::gate_inputs`), then drops the lock
/// before ever printing or prompting — the gate warning and the `[y/N]`
/// read must never hold it. Returns `true` if the capture should proceed.
fn confirm_gates(session: &Session, target: Option<&str>) -> bool {
    let (window_open, scopes) = session.gate_inputs();

    let mut warnings = Vec::new();
    if window_open == Some(false) {
        warnings.push("testing window is CLOSED".to_string());
    }
    match target {
        Some(t) if !gates::scope_contains(&scopes, t) => {
            warnings.push(format!("target `{t}` is not in the recorded scope"));
        }
        None => {
            println!(
                "tandera: \u{26a0} scope check skipped — target not determinable from this command"
            );
        }
        _ => {}
    }

    if warnings.is_empty() {
        return true;
    }
    for w in &warnings {
        println!("tandera: \u{26a0} {w}");
    }
    is_yes(&prompt("Run anyway? [y/N] "))
}

/// Per-session upload consent. Doesn't touch the network — it only decides
/// intent; the actual upload happens later, only if the tool produced
/// output.
fn confirm_upload(session: &mut Session, label: &str) -> bool {
    match session.auto_upload_mode() {
        AutoUpload::Paused => false,
        AutoUpload::Always => true,
        AutoUpload::Ask => {
            let answer = prompt(&format!("auto-upload results to {label}? [Y/n/always] "));
            match answer.as_str() {
                "" | "y" | "yes" => true,
                "always" => {
                    session.set_auto_upload_mode(AutoUpload::Always);
                    true
                }
                _ => false,
            }
        }
    }
}

/// Run `argv` directly — no shell — with stdio inherited and cwd/env taken
/// from the session's shell state. Deliberately `Command::new(argv[0])`
/// rather than joining argv into a `$SHELL -c` line: there's no
/// pipe/redirect to preserve (`classify::has_shell_metachar` already routed
/// those to plain passthrough before a line is ever classified as a known
/// tool), and running the vector directly sidesteps shell-quoting the
/// injected output path entirely.
fn run_capture(argv: &[String], env: &ShellEnv) -> io::Result<Option<i32>> {
    let Some((prog, rest)) = argv.split_first() else {
        return Ok(None);
    };
    let status = Command::new(prog)
        .args(rest)
        .current_dir(&env.cwd)
        .envs(&env.vars)
        .status()?;
    Ok(status.code())
}

/// Sanitize an RFC3339 timestamp into something safe as a filename
/// fragment: `2026-07-11T14:02:09Z` -> `20260711T140209Z`.
fn ts_for_filename(ts: &str) -> String {
    ts.replace(['-', ':'], "")
}

/// The full inject/gate/run/capture/enqueue flow for one known-tool line.
pub fn handle(session: &mut Session, tool: &str, argv: &[String], raw_line: &str) -> Result<()> {
    let Some(spec) = registry::lookup(tool) else {
        // Unreachable given `is_known_tool` gated the classification, but
        // never worth a panic over a registry/classify drift.
        println!("tandera: `{tool}` is not a recognized capture tool");
        return Ok(());
    };
    let target = registry::extract_target(spec, argv);

    if !confirm_gates(session, target.as_deref()) {
        println!("tandera: skipped");
        return Ok(());
    }

    let label = session.assessment_label().to_string();
    let upload_intent = confirm_upload(session, &label);

    let ts = ts_for_filename(&logbook::now_rfc3339());
    let out_path = default_out_path(&session.shell_env().cwd, &label, tool, spec.ext, &ts);
    if let Some(parent) = out_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!(
                "tandera: failed to create output directory {}: {e}",
                parent.display()
            );
        }
    }
    let out_path_str = out_path.to_string_lossy().to_string();
    let (capture_argv, injected) = build_capture_argv(spec, argv, &out_path_str);
    if injected {
        println!("tandera: capturing output to {out_path_str}");
    }

    let started = std::time::Instant::now();
    let exit_code = match run_capture(&capture_argv, session.shell_env()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("tandera: failed to run `{tool}`: {e}");
            None
        }
    };
    let dur_s = started.elapsed().as_secs_f64();
    session.log_command(raw_line, "wrapped", target.as_deref(), exit_code, dur_s);
    if let Some(code) = exit_code {
        if code != 0 {
            eprintln!("[exit {code}]");
        }
    }

    let has_output = std::fs::metadata(&out_path)
        .map(|m| m.len() > 0)
        .unwrap_or(false);
    if !has_output {
        println!("tandera: no output captured (expected at {out_path_str})");
        return Ok(());
    }
    if !upload_intent {
        println!("tandera: output saved to {out_path_str} (not uploaded)");
        return Ok(());
    }

    let aid = match session.resolve_assessment_id() {
        Ok(id) => id,
        Err(e) => {
            eprintln!(
                "tandera: no active assessment — output saved to {out_path_str}, not uploaded ({e})"
            );
            return Ok(());
        }
    };

    let client = session.client().clone();
    let scan_type = spec.scan_type;
    let job_label = format!("{tool} -> {out_path_str}");
    let job_path = out_path.clone();
    let bg_handle = session.uploads_queue().enqueue(
        job_label,
        Box::new(move || {
            let res = import::upload_file(&client, aid, &job_path, scan_type)?;
            Ok(format!(
                "{}: {} assets, {} findings imported",
                job_path.display(),
                res.asset_count,
                res.finding_count
            ))
        }),
    );
    println!("tandera: queued upload as {bg_handle} (see `:status`/next prompt for the receipt)");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::registry::lookup;
    use std::path::Path;

    #[test]
    fn injects_output_flag_when_absent() {
        let spec = lookup("httpx").unwrap();
        let argv: Vec<String> = ["httpx", "-u", "t.com"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (out, injected) = build_capture_argv(spec, &argv, "/tmp/httpx.jsonl");
        assert!(injected);
        assert!(out.contains(&"-json".to_string()));
        assert!(out.contains(&"/tmp/httpx.jsonl".to_string()));
    }

    #[test]
    fn skips_injection_when_output_flag_present() {
        let spec = lookup("nmap").unwrap();
        let argv: Vec<String> = ["nmap", "-oX", "mine.xml", "10.0.0.5"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (out, injected) = build_capture_argv(spec, &argv, "/tmp/x.xml");
        assert!(!injected);
        assert_eq!(out, argv);
    }

    #[test]
    fn default_out_path_has_tool_and_ext() {
        let p = default_out_path(
            Path::new("/w"),
            "acme-web",
            "httpx",
            "jsonl",
            "20260711T140209Z",
        );
        let s = p.to_string_lossy();
        assert!(s.contains("acme-web"));
        assert!(s.contains("httpx"));
        assert!(s.ends_with(".jsonl"));
    }
}
