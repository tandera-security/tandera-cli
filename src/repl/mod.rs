//! The interactive shell: the read-loop, the `Session` it drives, and
//! `:meta`-command dispatch. This is Phase 2's integration point — it wires
//! together `classify` (line classification), `exec` (builtins +
//! passthrough), `status`/`gates` (the banner + advisory checks), and
//! `logbook` (the local testing-log attestation) into one command loop.
//!
//! `handle_line` classifies with `capture::registry::is_known_tool`; a line
//! recognized as a known recon tool is dispatched to `capture::wrapper::handle`,
//! which injects an output flag, runs the advisory scope/window gates,
//! executes the tool, and (per the session's upload consent) enqueues the
//! captured output on `Session::uploads` for background import.

pub mod classify;
pub mod complete;
pub mod exec;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

use anyhow::{Context, Result};
use clap::ValueEnum;
use uuid::Uuid;

use crate::api::ApiClient;
use crate::capture::uploads::Queue;
use crate::commands::{self, findings, project, read};
use crate::config::Config;
use crate::gates;
use crate::logbook;
use crate::models::{
    AssessmentListResponse, AssetListResponse, Category, Credits, FindingSummary, Scope, Severity,
    TestingStatus,
};
use crate::status::{self, StatusSnapshot};
use crate::util::lock;

/// The label shown (in the banner and `:project current`) when no
/// assessment is active.
const NO_PROJECT_LABEL: &str = "— no project —";

#[derive(Debug, PartialEq, Eq)]
pub enum Control {
    Continue,
    Exit,
}

/// Whether captured tool output should be queued for upload without asking,
/// queued but held for confirmation, or not queued at all. Phase 2 never
/// captures anything, so this only affects `:pause`/`:resume` bookkeeping
/// and the banner's dot; Phase 3 (Task 18) is where it actually gates an
/// upload decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoUpload {
    Ask,
    Always,
    Paused,
}

/// Everything a background refresh thread writes, consolidated behind ONE
/// mutex so the generation compare-and-write is atomic.
///
/// Before this struct existed, `generation` was a free-standing
/// `Arc<AtomicU64>` and `assessment`/`snap`/`scopes` were each their own
/// `Arc<Mutex<_>>`. A background thread did `if generation.load() ==
/// my_gen { ... }` and then, as a *separate* operation, locked `assessment`
/// (and `snap`, `scopes`) to write. Because the atomic load and the mutex
/// writes were independent operations, a thread could be preempted right
/// between them: it passes the generation check, `:use` runs on the main
/// thread (bumps the generation, resets `assessment`/`snap`/`scopes`), and
/// then the preempted thread resumes and writes its stale data anyway —
/// wrong window/credits, and worse, a stale assessment id that a later
/// `:findings`/`:asset` would query. Putting every field the guard cares
/// about behind one lock and doing the compare-and-write while holding it
/// (`gated_apply`) closes that gap: the check and the write can no longer
/// be separated by anything, including a preemption.
#[derive(Debug, Default)]
struct SharedState {
    generation: u64,
    assessment: Option<Uuid>,
    snap: StatusSnapshot,
    /// In-scope entries for the active assessment, fetched in the background
    /// (`gates::fetch_scopes`, via `apply_refresh`) and read by
    /// `Session::gate_inputs`, which `capture::wrapper::confirm_gates`
    /// consults before letting a capture proceed.
    scopes: Vec<Scope>,
}

/// All state a REPL turn needs. Deliberately minimal for Phase 2 — Task 18
/// adds the capture/upload-queue fields on top of this.
///
/// `state` is `Arc<Mutex<SharedState>>` because it's written by a
/// background thread (`spawn_resolve_and_refresh` / `spawn_refresh_for`) as
/// well as read/written from the foreground command-dispatch path — never
/// from `Session::new` or `run_shell`'s banner print, which must stay
/// network-free (see the module-level Fix 1 note on `new`). Consolidating
/// the generation counter and the fields it guards into one mutex (rather
/// than a separate atomic plus separate mutexes) is what makes the
/// compare-and-write in `gated_apply` atomic — see `SharedState`'s doc.
pub struct Session {
    client: ApiClient,
    cfg_path: PathBuf,
    /// The `--assessment` override (if any) the process started with.
    /// Retained (rather than only consulted once in `new`) so an on-demand
    /// resolution in `resolve_assessment_id` — triggered by a command
    /// running before the background thread finishes — resolves the same
    /// candidate the thread would have.
    assessment_override: Option<String>,
    assessment_label: String,
    auto_upload: AutoUpload,
    env: exec::ShellEnv,
    state: Arc<Mutex<SharedState>>,
    log_path: PathBuf,
    egress_ip: Option<String>,
    last_finding: Option<Uuid>,
    /// Background upload queue (`capture::wrapper::handle` enqueues jobs
    /// here after a capture; `run_shell` prints `poll_receipts()` between
    /// prompts; `:exit`/`:quit` calls `drain_uploads_on_exit` so the process
    /// never disappears mid-upload). Small fixed concurrency — a REPL is
    /// used interactively, not for a fleet of parallel scans.
    uploads: Queue,
    /// Cached mirror of `Config.sync_testing_log_enabled()` — read on every
    /// `log_command` call, so it's kept as a plain `bool` on `Session`
    /// rather than re-loading the config file from disk per command.
    /// Seeded from config at `Session::new` and updated in lockstep by
    /// `:sync on|off` (`dispatch_sync`), which also persists the change.
    sync_testing_log: bool,
}

impl Session {
    /// Build a live session. **Makes no synchronous network call** — the
    /// prompt/banner must render immediately. `assessment_label` is seeded
    /// from local config only (`Config::effective_assessment`, which never
    /// touches the network); the actual assessment id, testing-status,
    /// credits, and scopes are all resolved/fetched on a background thread
    /// (`spawn_resolve_and_refresh`) that `run_shell` does not wait on.
    pub fn new(
        client: ApiClient,
        cfg_path: PathBuf,
        assessment_override: Option<&str>,
    ) -> Result<Session> {
        let cfg = Config::load_from(&cfg_path)?;
        let assessment_label = cfg
            .effective_assessment(assessment_override)
            .unwrap_or_else(|| NO_PROJECT_LABEL.to_string());
        let sync_testing_log = cfg.sync_testing_log_enabled();
        let log_path = default_log_path(&assessment_label);
        let egress_ip = fetch_egress_ip(&client);
        let assessment_override = assessment_override.map(str::to_string);

        let state = Arc::new(Mutex::new(SharedState::default()));
        let expected_gen = lock(&state).generation;

        spawn_resolve_and_refresh(
            client.clone(),
            cfg,
            assessment_override.clone(),
            Arc::clone(&state),
            expected_gen,
        );

        Ok(Session {
            client,
            cfg_path,
            assessment_override,
            assessment_label,
            auto_upload: AutoUpload::Ask,
            env: exec::ShellEnv::default(),
            state,
            log_path,
            egress_ip,
            last_finding: None,
            uploads: Queue::new(2),
            sync_testing_log,
        })
    }

    /// Return the background-resolved assessment id if one is already
    /// cached; otherwise resolve it synchronously — one blocking network
    /// call — and cache it. Blocking here is acceptable: every caller is a
    /// command the user explicitly typed (`:findings`, `:asset`, the
    /// synchronous half of `:status`), never the prompt-render path.
    pub fn resolve_assessment_id(&self) -> Result<Uuid> {
        if let Some(id) = lock(&self.state).assessment {
            return Ok(id);
        }
        let cfg = Config::load_from(&self.cfg_path)?;
        let id = commands::resolve_active_assessment(
            &self.client,
            &cfg,
            self.assessment_override.as_deref(),
        )?;
        lock(&self.state).assessment = Some(id);
        Ok(id)
    }

    /// Rebuild the API client from the current on-disk config — used after
    /// an in-shell `:login` stores a fresh token (or `:logout` clears it) —
    /// and kick off a background resolve/refresh so the banner's window /
    /// credits repopulate for the new auth state, the same startup path
    /// `Session::new` runs. The API base URL is preserved from the live
    /// client so a `--api-url` the shell was started with survives the swap
    /// (it is not stored anywhere else on `Session`).
    fn reauthenticate(&mut self) -> Result<()> {
        let cfg = Config::load_from(&self.cfg_path)?;
        let api_url = self.client.base_url().to_string();
        self.client = ApiClient::new(api_url, cfg.effective_token())?;

        // Invalidate any in-flight refresh from the previous auth state and
        // drop its cached snapshot/scopes/id under one lock (the same
        // generation discipline `set_active_assessment` / `:project clear`
        // use), then spawn a fresh resolve on the new client.
        let expected_gen = {
            let mut state = lock(&self.state);
            state.generation += 1;
            state.assessment = None;
            state.snap = StatusSnapshot::default();
            state.scopes = Vec::new();
            state.generation
        };
        spawn_resolve_and_refresh(
            self.client.clone(),
            cfg,
            self.assessment_override.clone(),
            Arc::clone(&self.state),
            expected_gen,
        );
        Ok(())
    }

    /// Block until every queued/in-flight upload finishes. Called by
    /// `handle_line`'s `:exit`/`:quit` arm so the process never disappears
    /// mid-upload.
    pub fn drain_uploads_on_exit(&self) {
        self.uploads.drain();
    }

    // --- Accessors for `capture::wrapper::handle` -------------------------
    //
    // `wrapper::handle` lives in a different module (`capture::wrapper`) and
    // needs a narrow, read-mostly slice of `Session`'s otherwise-private
    // state: the API client (to build an upload job), the shell env (cwd +
    // vars the wrapped tool should inherit), the assessment label (for
    // prompts and the output path), the auto-upload mode (consent), and one
    // locked read of the gate inputs. These are `pub(crate)` rather than
    // `pub` — they're an internal seam, not part of the crate's published
    // surface (`for_test`/`apply_if_current` above use the same
    // `#[doc(hidden)] pub` pattern for the cross-crate test seam instead,
    // since `tests/repl_smoke.rs` is a separate crate; `capture::wrapper` is
    // not, so `pub(crate)` suffices and stays out of any external API).

    pub(crate) fn client(&self) -> &ApiClient {
        &self.client
    }

    pub(crate) fn shell_env(&self) -> &exec::ShellEnv {
        &self.env
    }

    pub(crate) fn assessment_label(&self) -> &str {
        &self.assessment_label
    }

    pub(crate) fn auto_upload_mode(&self) -> AutoUpload {
        self.auto_upload
    }

    pub(crate) fn set_auto_upload_mode(&mut self, mode: AutoUpload) {
        self.auto_upload = mode;
    }

    /// One locked read of `window_open` + `scopes`, cloned out so the
    /// gate check (`capture::wrapper::confirm_gates`) never holds `state`'s
    /// lock across a print or a `[y/N]` prompt.
    pub(crate) fn gate_inputs(&self) -> (Option<bool>, Vec<Scope>) {
        let state = lock(&self.state);
        (state.snap.window_open, state.scopes.clone())
    }

    pub(crate) fn uploads_queue(&self) -> &Queue {
        &self.uploads
    }

    /// The background-resolved assessment id, if one is already cached —
    /// never triggers a network call (unlike `resolve_assessment_id`). Used
    /// by `log_command`'s sync check: "an assessment is active" means
    /// already-known, not "block this command to go find out".
    fn cached_assessment_id(&self) -> Option<Uuid> {
        lock(&self.state).assessment
    }

    /// Test-only hook onto the single-lock generation compare-and-write
    /// (`gated_apply`) so `tests/repl_smoke.rs` can prove the TOCTOU guard
    /// deterministically, without spawning or scheduling any thread: call
    /// with the CURRENT generation and the write lands; bump the
    /// generation (`bump_generation_for_test`, simulating `:use`) and call
    /// again with the OLD generation and it's silently discarded. `pub`
    /// (not `#[cfg(test)]`) for the same cross-crate-visibility reason as
    /// `for_test`; `#[doc(hidden)]` keeps it out of the published surface.
    #[doc(hidden)]
    pub fn apply_if_current(
        &self,
        gen: u64,
        status: &TestingStatus,
        credits: &Credits,
        aid: Uuid,
        scopes: Vec<Scope>,
    ) {
        gated_apply(
            &self.state,
            gen,
            Some(aid),
            Some(status),
            Some(credits),
            Some(scopes),
        );
    }

    /// Test-only: bump the generation the way `:use`/`:project clear` do,
    /// returning the new value. Lets a test simulate an assessment switch
    /// without going through the network-backed `dispatch_meta` path.
    #[doc(hidden)]
    pub fn bump_generation_for_test(&self) -> u64 {
        let mut state = lock(&self.state);
        state.generation += 1;
        state.generation
    }

    /// Test-only: read back the cached snapshot so a test can assert what
    /// `apply_if_current`/`bump_generation_for_test` did (or didn't) apply.
    #[doc(hidden)]
    pub fn snapshot_for_test(&self) -> StatusSnapshot {
        lock(&self.state).snap.clone()
    }

    /// Test-only constructor that skips every network call `Session::new`
    /// makes (assessment resolution, the background status-fetch thread).
    /// Used by `tests/repl_smoke.rs` to build a deterministic `Session`
    /// directly, without a stub API — neither test in that file exercises a
    /// path that touches `client`, so there's nothing to stub. `pub` (not
    /// `#[cfg(test)]`) because `tests/repl_smoke.rs` is a separate crate and
    /// can only see public items; `#[doc(hidden)]` keeps it out of the
    /// crate's published API surface.
    #[doc(hidden)]
    pub fn for_test(
        client: ApiClient,
        cfg_path: PathBuf,
        assessment: Option<Uuid>,
        assessment_label: impl Into<String>,
        log_path: PathBuf,
    ) -> Session {
        Session {
            client,
            cfg_path,
            assessment_override: None,
            assessment_label: assessment_label.into(),
            auto_upload: AutoUpload::Ask,
            env: exec::ShellEnv::default(),
            state: Arc::new(Mutex::new(SharedState {
                assessment,
                ..SharedState::default()
            })),
            log_path,
            egress_ip: None,
            last_finding: None,
            uploads: Queue::new(2),
            sync_testing_log: false,
        }
    }

    /// Test-only: flip `sync_testing_log` on for a `for_test`-built session
    /// (which always starts with it `false`), so an integration test can
    /// exercise `log_command`'s sync-enqueue path against a stub server.
    /// `pub` (not `#[cfg(test)]`) because integration tests under `tests/`
    /// are a separate crate and can only see public items; `#[doc(hidden)]`
    /// keeps it out of the crate's published surface, same pattern as
    /// `for_test`/`bump_generation_for_test` above.
    #[doc(hidden)]
    pub fn enable_sync_testing_log_for_test(&mut self) {
        self.sync_testing_log = true;
    }

    /// Test-only passthrough to the private `log_command`, for the same
    /// cross-crate-visibility reason as `enable_sync_testing_log_for_test`.
    /// Lets an integration test drive the exact enqueue path `log_command`
    /// wires up (local append +, if opted in, a background redacted sync)
    /// without needing `capture::wrapper`'s full shell-out machinery.
    #[doc(hidden)]
    pub fn log_command_for_test(
        &mut self,
        cmd: &str,
        kind: &str,
        target: Option<&str>,
        exit: Option<i32>,
        dur_s: f64,
    ) {
        self.log_command(cmd, kind, target, exit, dur_s);
    }

    /// Append one entry to the local testing-log. A write failure (disk
    /// full, permissions) is reported but never crashes the shell — the log
    /// is an attestation aid, not something worth losing a session over.
    ///
    /// If the operator opted in (`:sync on`) AND an assessment id is already
    /// cached (never triggers a resolve — see `cached_assessment_id`), the
    /// entry is ALSO queued for a best-effort, REDACTED sync to the
    /// assessment's activity timeline on the background upload queue
    /// (`logbook::sync_entry`, which applies `logbook::redact_cmd` before
    /// anything leaves the process). This never blocks the prompt — the
    /// network call runs on a worker thread — and a sync failure is
    /// swallowed to a one-line background-receipt note (surfaced later via
    /// `poll_receipts`), never propagated into the REPL loop. The raw,
    /// unredacted `cmd` is only ever passed to the LOCAL `logbook::append`
    /// call above; it never crosses into the sync path.
    pub(crate) fn log_command(
        &mut self,
        cmd: &str,
        kind: &str,
        target: Option<&str>,
        exit: Option<i32>,
        dur_s: f64,
    ) {
        let entry = logbook::LogEntry {
            ts: logbook::now_rfc3339(),
            cmd: cmd.to_string(),
            kind: kind.to_string(),
            egress_ip: self.egress_ip.clone(),
            target: target.map(str::to_string),
            target_ip: target.and_then(logbook::resolve_target_ip),
            exit,
            dur_s: Some(dur_s),
        };
        if let Err(e) = logbook::append(&self.log_path, &entry) {
            eprintln!("tandera: failed to write testing log: {e}");
        }

        if self.sync_testing_log {
            if let Some(aid) = self.cached_assessment_id() {
                let client = self.client.clone();
                let entry_for_job = entry.clone();
                let label = format!("sync activity: {}", logbook::redact_cmd(&entry.cmd));
                self.uploads.enqueue(
                    label,
                    Box::new(move || {
                        logbook::sync_entry(&client, aid, &entry_for_job)
                            .map(|()| "activity synced".to_string())
                            .map_err(anyhow::Error::new)
                    }),
                );
            }
        }
    }
}

/// GETs a caller-IP field from the API if/when it exposes one (open
/// question Q7). No such endpoint exists yet, and this deliberately does
/// NOT call an external echo-IP service — so for now it's always `None`.
fn fetch_egress_ip(_client: &ApiClient) -> Option<String> {
    None
}

/// The single critical section every generation-gated write goes through:
/// lock `state` ONCE, compare `my_gen` against the generation stored
/// inside that same lock, and — only if they still match — apply every
/// write in that one locked scope before releasing it. This is what makes
/// the compare-and-write atomic with respect to `:use`/`:project clear`
/// (see `SharedState`'s doc for the race this closes): the check and the
/// writes can no longer be separated by a preemption, because both happen
/// while holding the one mutex `:use` also locks to bump the generation
/// and reset state — the two are fully serialized.
///
/// `aid`/`status`/`credits`/`scopes` are each `Option` so a caller can
/// apply a subset (a background fetch tolerates one of several network
/// calls failing independently — see `refresh_snapshot`/`apply_refresh`);
/// `None` simply leaves that field untouched rather than overwriting good
/// data with nothing.
fn gated_apply(
    state: &Mutex<SharedState>,
    my_gen: u64,
    aid: Option<Uuid>,
    status: Option<&TestingStatus>,
    credits: Option<&Credits>,
    scopes: Option<Vec<Scope>>,
) {
    let mut state = lock(state);
    if state.generation != my_gen {
        return;
    }
    if let Some(aid) = aid {
        state.assessment = Some(aid);
    }
    if let Some(s) = status {
        state.snap.apply_status(s);
    }
    if let Some(c) = credits {
        state.snap.apply_credits(c);
    }
    if let Some(sc) = scopes {
        state.scopes = sc;
    }
}

/// Fetch testing-status and credits for `aid` — the slow network calls
/// happen with NO lock held — then apply whichever succeeded in one
/// `gated_apply` call gated on `my_gen`. Shared by the synchronous
/// `:status` path (`dispatch_status`, which passes the generation it just
/// read — always current, since foreground dispatch is single-threaded)
/// and every background refresh thread.
fn refresh_snapshot(client: &ApiClient, aid: Uuid, state: &Mutex<SharedState>, my_gen: u64) {
    let status = gates::fetch_testing_status(client, aid).ok();
    let credits = gates::fetch_credits(client).ok();
    gated_apply(state, my_gen, None, status.as_ref(), credits.as_ref(), None);
}

/// The fetch phase shared by every background refresh thread: testing
/// status + credits + scopes, all fetched without holding `state`'s lock,
/// then written in one `gated_apply` call.
fn apply_refresh(client: &ApiClient, aid: Uuid, state: &Mutex<SharedState>, my_gen: u64) {
    let status = gates::fetch_testing_status(client, aid).ok();
    let credits = gates::fetch_credits(client).ok();
    let scopes = gates::fetch_scopes(client, aid).ok();
    gated_apply(
        state,
        my_gen,
        None,
        status.as_ref(),
        credits.as_ref(),
        scopes,
    );
}

/// Spawn the one-time startup background thread: resolve the active
/// assessment (the blocking `GET /v1/assessments` that Fix 1 moves off the
/// prompt-render path) then fetch its snapshot + scopes. Every write —
/// including the resolved id itself — goes through `gated_apply`, gated on
/// `state`'s generation still matching `expected_gen`, so a `:use` that
/// runs before this thread finishes (bumping the generation under the same
/// lock) makes this thread's writes no-ops instead of clobbering the newer
/// assessment's state (Fix 2, now race-free — see `SharedState`).
fn spawn_resolve_and_refresh(
    client: ApiClient,
    cfg: Config,
    assessment_override: Option<String>,
    state: Arc<Mutex<SharedState>>,
    expected_gen: u64,
) {
    thread::spawn(move || {
        let Ok(aid) =
            commands::resolve_active_assessment(&client, &cfg, assessment_override.as_deref())
        else {
            return;
        };
        // Best-effort early-out: skip the fetches entirely if a `:use` has
        // already moved on. Purely an optimization — `gated_apply` below
        // re-checks the generation under the lock before writing anything,
        // so correctness never depends on this check firing.
        if lock(&state).generation != expected_gen {
            return;
        }
        gated_apply(&state, expected_gen, Some(aid), None, None, None);

        apply_refresh(&client, aid, &state, expected_gen);
    });
}

/// Spawn a refresh thread for an assessment id that's already resolved
/// (used by `:use`, which must confirm the id synchronously before
/// persisting it). Same generation-guarded write discipline as
/// `spawn_resolve_and_refresh`.
fn spawn_refresh_for(
    client: ApiClient,
    aid: Uuid,
    state: Arc<Mutex<SharedState>>,
    expected_gen: u64,
) {
    thread::spawn(move || {
        apply_refresh(&client, aid, &state, expected_gen);
    });
}

fn default_log_path(assessment_label: &str) -> PathBuf {
    let dir_name = if assessment_label == NO_PROJECT_LABEL || assessment_label.is_empty() {
        "no-project".to_string()
    } else {
        assessment_label.replace(['/', '\\'], "_")
    };
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("output")
        .join(dir_name)
        .join(".tandera")
        .join("testing-log.jsonl")
}

/// Classify and dispatch one line of input. A known recon tool
/// (`capture::registry::is_known_tool`) is wrapped by
/// `capture::wrapper::handle`; everything else is either a meta-command or
/// plain passthrough.
pub fn handle_line(session: &mut Session, input: &str) -> anyhow::Result<Control> {
    let line = match classify::classify(input, crate::capture::registry::is_known_tool) {
        None => return Ok(Control::Continue),
        Some(l) => l,
    };
    match line {
        classify::Line::Meta { verb, rest } => {
            if matches!(verb.as_str(), "exit" | "quit") {
                session.drain_uploads_on_exit();
                return Ok(Control::Exit);
            }
            dispatch_meta(session, &verb, &rest)?;
            Ok(Control::Continue)
        }
        classify::Line::KnownTool { tool, argv } => {
            crate::capture::wrapper::handle(session, &tool, &argv, input)?;
            Ok(Control::Continue)
        }
        classify::Line::Passthrough(cmd) => {
            let started = std::time::Instant::now();
            if let Some(res) = exec::try_builtin(&cmd, &mut session.env) {
                if let Err(e) = res {
                    eprintln!("tandera: {e}");
                }
            } else {
                let status = exec::run_passthrough(&cmd, &session.env);
                let code = status.as_ref().ok().and_then(|s| s.code());
                session.log_command(
                    &cmd,
                    "passthrough",
                    None,
                    code,
                    started.elapsed().as_secs_f64(),
                );
                if let Ok(s) = status {
                    if !s.success() {
                        if let Some(c) = s.code() {
                            eprintln!("[exit {c}]");
                        }
                    }
                }
            }
            Ok(Control::Continue)
        }
    }
}

/// Route a `:verb [rest]` meta-command. Unexpected failures (a parse error,
/// a config write failure) propagate as `Err` — the caller (`run_shell`)
/// prints them and keeps the loop going; "the user typed something we don't
/// understand" or "the API said no" are handled inline here instead, so
/// they never abort the session.
pub fn dispatch_meta(session: &mut Session, verb: &str, rest: &str) -> Result<()> {
    match verb {
        "login" => dispatch_login(session)?,
        "logout" => dispatch_logout(session)?,
        "auth" => dispatch_auth(session, rest)?,
        "project" => dispatch_project(session, rest)?,
        "use" => set_active_assessment(session, rest)?,
        "status" => dispatch_status(session),
        "findings" => dispatch_findings(session)?,
        "asset" => dispatch_asset(session, rest)?,
        "report" => println!("tandera: report preview coming in a later phase"),
        "pause" => {
            session.auto_upload = AutoUpload::Paused;
            println!("Auto-upload paused.");
        }
        "resume" => {
            session.auto_upload = AutoUpload::Ask;
            println!("Auto-upload resumed.");
        }
        "log" => dispatch_log(session),
        "sync" => dispatch_sync(session, rest)?,
        "help" => print_help(),
        "finding" => dispatch_finding(session, rest)?,
        "pentest" => dispatch_pentest(session)?,
        "new" => dispatch_new(session, rest)?,
        "portal" => dispatch_portal(session),
        "client" => dispatch_client(session, rest)?,
        "paste" => dispatch_paste(session, rest)?,
        "undo" => println!("tandera: `:undo` available in Phase 4"),
        other => eprintln!("tandera: unknown command `:{other}` — try `:help`"),
    }
    Ok(())
}

fn dispatch_project(session: &mut Session, rest: &str) -> Result<()> {
    let rest = rest.trim();
    let (sub, arg) = match rest.split_once(char::is_whitespace) {
        Some((s, a)) => (s, a.trim()),
        None => (rest, ""),
    };
    match sub {
        "" => list_projects(session)?,
        "current" => {
            if session.assessment_label == NO_PROJECT_LABEL {
                println!("No active assessment. Run `:project` or `:use <slug>`.");
            } else {
                match session.resolve_assessment_id() {
                    Ok(id) => println!("Active assessment: {} ({id})", session.assessment_label),
                    Err(e) => eprintln!("tandera: {e}"),
                }
            }
        }
        "clear" => {
            project::clear_active(&session.cfg_path)?;
            session.assessment_override = None;
            session.assessment_label = NO_PROJECT_LABEL.to_string();
            // Invalidate any in-flight refresh thread from a prior
            // assessment (Fix 2) and drop all cached state for it — bump
            // and reset happen under ONE lock acquisition, the same lock
            // `gated_apply` takes, so a stale thread's write can never
            // land between the bump and the reset.
            let mut state = lock(&session.state);
            state.generation += 1;
            state.assessment = None;
            state.snap = StatusSnapshot::default();
            state.scopes = Vec::new();
            drop(state);
            println!("Active assessment cleared.");
        }
        "use" => set_active_assessment(session, arg)?,
        other => eprintln!(
            "tandera: unknown `:project {other}` — try `:project`, `:project current`, `:project clear`, `:project use <slug>`"
        ),
    }
    Ok(())
}

fn list_projects(session: &Session) -> Result<()> {
    match project::list(&session.client) {
        Ok(raw) => {
            let resp: AssessmentListResponse =
                serde_json::from_value(raw).context("failed to parse assessments response")?;
            commands::print_assessments_table(&resp.items);
            println!("\nUse `:use <slug>` to set the active assessment.");
        }
        Err(e) => commands::print_api_error(&e),
    }
    Ok(())
}

/// Shared by `:use <x>` and `:project use <x>`. Reuses
/// `commands::resolve_active_assessment` (an explicit override always wins
/// its precedence order) rather than re-implementing list+resolve here.
/// This blocking resolve is fine — `:use` is a command the user explicitly
/// typed, not the prompt-render path Fix 1 protects.
///
/// Switches assessment: bumps `generation` and resets the shared
/// snapshot/scopes/id under ONE lock acquisition (Fix 2, now race-free —
/// see `SharedState`'s doc) before spawning the new refresh thread. Because
/// `gated_apply` takes that same lock to compare-and-write, a thread
/// spawned for the previous assessment either writes before this reset
/// (and the reset correctly wins, running after) or observes the bumped
/// generation while holding the lock itself (and skips its write) — there
/// is no window where a stale write can land after the reset.
/// `:portal` — open the console in the browser, deep-linked to the active
/// assessment when one is set. Always prints the URL as a fallback.
fn dispatch_portal(session: &Session) {
    let app_url = Config::load_from(&session.cfg_path)
        .ok()
        .and_then(|c| c.app_url);
    let aid = session
        .resolve_assessment_id()
        .ok()
        .map(|id| id.to_string());
    let url = crate::commands::portal::portal_url(
        session.client.base_url(),
        app_url.as_deref(),
        aid.as_deref(),
    );
    crate::commands::portal::open_url(&url);
}

/// `:client add <name>` / `:client list` / `:client bind <name|id>` — manage
/// clients and bind to the active assessment.
fn dispatch_client(session: &Session, rest: &str) -> Result<()> {
    use crate::commands::client;
    let rest = rest.trim();
    let (sub, arg) = match rest.split_once(char::is_whitespace) {
        Some((s, a)) => (s, a.trim()),
        None => (rest, ""),
    };
    let active_aid = |session: &Session| match session.resolve_assessment_id() {
        Ok(id) => Some(id),
        Err(e) => {
            eprintln!("tandera: {e}");
            None
        }
    };
    match sub {
        "" | "list" => match client::list_clients(&session.client) {
            Ok(raw) => print!(
                "{}",
                client::format_clients_table(&client::parse_clients(raw))
            ),
            Err(e) => crate::commands::print_api_error(&e),
        },
        "add" => {
            if arg.is_empty() {
                eprintln!("tandera: usage: `:client add <company name>`");
                return Ok(());
            }
            if let Some(aid) = active_aid(session) {
                match client::add_and_bind(&session.client, aid, arg) {
                    Ok(_) => println!(
                        "✓ created client \"{arg}\" and bound it to {}.",
                        session.assessment_label
                    ),
                    Err(e) => crate::commands::print_api_error(&e),
                }
            }
        }
        "bind" => {
            if arg.is_empty() {
                eprintln!("tandera: usage: `:client bind <company name or id>`");
                return Ok(());
            }
            if let Some(aid) = active_aid(session) {
                match client::bind_existing(&session.client, aid, arg) {
                    Ok(Some(name)) => println!(
                        "✓ bound client \"{name}\" to {}.",
                        session.assessment_label
                    ),
                    Ok(None) => eprintln!(
                        "tandera: no client matching \"{arg}\" — try `:client list` or `:client add {arg}`"
                    ),
                    Err(e) => crate::commands::print_api_error(&e),
                }
            }
        }
        other => eprintln!(
            "tandera: unknown `:client {other}` — try `:client add <name>`, `:client list`, `:client bind <name>`"
        ),
    }
    Ok(())
}

/// `:pentest` / `:new assessment` — run the create-assessment wizard, then
/// make the new assessment the active project for this session.
fn dispatch_pentest(session: &mut Session) -> Result<()> {
    if let Some(created) = crate::commands::assessment_new::run_wizard(&session.client)? {
        set_active_assessment(session, &created.active_ref())?;
    }
    Ok(())
}

/// `:new <thing>` — currently only `:new assessment` (an alias for
/// `:pentest`). A bare `:new` also opens the assessment wizard since it's the
/// only thing you can create here.
fn dispatch_new(session: &mut Session, rest: &str) -> Result<()> {
    match rest.trim().to_ascii_lowercase().as_str() {
        "" | "assessment" | "pentest" => dispatch_pentest(session),
        "finding" => {
            println!("tandera: use `:finding <phrase>` to draft a finding.");
            Ok(())
        }
        other => {
            eprintln!("tandera: unknown `:new {other}` — try `:new assessment` (or `:pentest`)");
            Ok(())
        }
    }
}

fn set_active_assessment(session: &mut Session, needle: &str) -> Result<()> {
    let needle = needle.trim();
    if needle.is_empty() {
        eprintln!("tandera: usage: `:use <id-or-slug>` or `:project use <id-or-slug>`");
        return Ok(());
    }
    match commands::resolve_active_assessment(&session.client, &Config::default(), Some(needle)) {
        Ok(id) => {
            project::set_active(&session.cfg_path, needle)?;
            session.assessment_override = Some(needle.to_string());
            session.assessment_label = needle.to_string();
            session.log_path = default_log_path(&session.assessment_label);

            let gen = {
                let mut state = lock(&session.state);
                state.generation += 1;
                state.assessment = Some(id);
                state.snap = StatusSnapshot::default();
                state.scopes = Vec::new();
                state.generation
            };

            spawn_refresh_for(session.client.clone(), id, Arc::clone(&session.state), gen);
            println!("Active assessment set to {needle}");
        }
        Err(e) => eprintln!("tandera: {e}"),
    }
    Ok(())
}

/// `:login` — prompt for a personal access token, verify it against the API
/// (via `auth::login`, which only persists a token that actually works), and
/// on success swap the freshly-authenticated client into the running session
/// so the very next command — and the banner — act as the logged-in user,
/// with no restart. Deliberately prompt-only (no `:login <token>` form):
/// echoing a secret on the prompt line would land it in the shell's in-memory
/// history. Scripted/non-interactive login stays `tandera auth login --token`.
fn dispatch_login(session: &mut Session) -> Result<()> {
    let api_url = session.client.base_url().to_string();
    let token = commands::prompt_for_token()?;
    let token = token.trim();
    if token.is_empty() {
        eprintln!("tandera: no token provided");
        return Ok(());
    }
    match commands::auth::login(&session.cfg_path, &api_url, token)? {
        commands::auth::LoginOutcome::Success { redacted_token } => {
            session.reauthenticate()?;
            println!("✓ signed in as {redacted_token}");
        }
        commands::auth::LoginOutcome::InvalidToken => {
            eprintln!("tandera: invalid token — not saved");
        }
    }
    Ok(())
}

/// `:logout` — clear the stored token and drop back to an unauthenticated
/// client in place (the banner reverts to `…`), without leaving the shell.
fn dispatch_logout(session: &mut Session) -> Result<()> {
    if commands::auth::logout(&session.cfg_path)? {
        session.reauthenticate()?;
        println!("Signed out.");
    } else {
        println!("No token was configured.");
    }
    Ok(())
}

/// `:auth <login|logout|status>` — the same actions as the `:login`/`:logout`
/// shortcuts, under the `auth` verb for anyone who reaches for `tandera auth
/// login`'s shape from inside the shell. Bare `:auth` reports sign-in state.
fn dispatch_auth(session: &mut Session, rest: &str) -> Result<()> {
    match rest.trim() {
        "" | "status" => dispatch_auth_status(session),
        "login" => dispatch_login(session)?,
        "logout" => dispatch_logout(session)?,
        other => eprintln!(
            "tandera: unknown `:auth {other}` — try `:auth login`, `:auth logout`, `:auth status`"
        ),
    }
    Ok(())
}

/// `:auth status` (and bare `:auth`) — report whether a token is configured
/// and still valid, reusing the same probe `tandera auth status` runs. Never
/// prints the full token — only its already-public prefix.
fn dispatch_auth_status(session: &Session) {
    match commands::auth::status(&session.cfg_path, None) {
        Ok(commands::auth::StatusOutcome::NotConfigured) => {
            println!("Not signed in. Run `:login`.");
        }
        Ok(commands::auth::StatusOutcome::Authenticated { prefix, api_url }) => {
            println!("Signed in as {prefix} against {api_url}");
        }
        Ok(commands::auth::StatusOutcome::Expired { prefix, api_url }) => {
            println!("Token {prefix} for {api_url} is expired or revoked — run `:login`.");
        }
        Err(e) => eprintln!("tandera: {e:#}"),
    }
}

fn dispatch_status(session: &Session) {
    match session.resolve_assessment_id() {
        Ok(aid) => {
            let my_gen = lock(&session.state).generation;
            refresh_snapshot(&session.client, aid, &session.state, my_gen);
        }
        Err(e) => eprintln!("tandera: {e}"),
    }
    let snap = lock(&session.state).snap.clone();
    let active = !matches!(session.auto_upload, AutoUpload::Paused);
    println!(
        "{}",
        status::format_banner(&session.assessment_label, active, &snap)
    );
}

fn dispatch_findings(session: &Session) -> Result<()> {
    let aid = match session.resolve_assessment_id() {
        Ok(id) => id,
        Err(e) => {
            eprintln!("tandera: {e}");
            return Ok(());
        }
    };
    match findings::list(&session.client, aid) {
        Ok(raw) => {
            let items: Vec<FindingSummary> =
                serde_json::from_value(raw).context("failed to parse findings response")?;
            commands::print_findings_table(&items);
        }
        Err(e) => commands::print_api_error(&e),
    }
    Ok(())
}

fn dispatch_asset(session: &Session, rest: &str) -> Result<()> {
    let rest = rest.trim();
    let mut parts = rest.split_whitespace();
    let sub = parts.next().unwrap_or("");
    if !sub.is_empty() && sub != "list" {
        eprintln!("tandera: unknown `:asset {sub}` — try `:asset list [TYPE]`");
        return Ok(());
    }
    let asset_type = parts.next();
    let aid = match session.resolve_assessment_id() {
        Ok(id) => id,
        Err(e) => {
            eprintln!("tandera: {e}");
            return Ok(());
        }
    };
    match read::list_assets(&session.client, aid, asset_type) {
        Ok(raw) => {
            let resp: AssetListResponse =
                serde_json::from_value(raw).context("failed to parse assets response")?;
            print!("{}", read::format_assets_table(&resp.items));
        }
        Err(e) => commands::print_api_error(&e),
    }
    Ok(())
}

/// `:finding <phrase>` — parse the phrase, try to grab a clipboard
/// screenshot, show one editable confirm line for the operator-owned
/// category/severity, then create the draft via
/// `commands::finding::create_from_phrase`. Bare `:finding` (no phrase)
/// keeps the old "show the last-touched finding" behavior rather than
/// erroring, since that's still useful and costs nothing to keep.
///
/// The confirm prompt reads from stdin directly (not through `rustyline` —
/// this is a sub-prompt inside one command, not the main read loop) via
/// `read_stdin_line`, which returns `None` on EOF/a closed/non-tty stdin
/// instead of blocking forever or panicking; every prompt in this function
/// treats `None` as "accept whatever is currently staged" and moves on, so
/// a non-interactive invocation degrades to the defaults rather than
/// hanging.
fn dispatch_finding(session: &mut Session, rest: &str) -> Result<()> {
    let phrase = rest.trim();
    if phrase.is_empty() {
        match session.last_finding {
            Some(id) => {
                println!("tandera: last finding {id} — use `:finding <phrase>` to draft a new one")
            }
            None => println!(
                "tandera: usage: `:finding <phrase>` e.g. `:finding SQL Injection in https://example.com`"
            ),
        }
        return Ok(());
    }

    // Resolve the active assessment FIRST, before the clipboard grab + the
    // interactive confirm loop below: a user with no active assessment
    // fails fast instead of only discovering that after all the
    // interactive work is already done.
    let aid = match session.resolve_assessment_id() {
        Ok(id) => id,
        Err(e) => {
            eprintln!("tandera: {e}");
            return Ok(());
        }
    };

    let mut parsed = commands::finding::parse_finding_phrase(phrase);

    let image = match crate::clipboard::grab_png() {
        Ok(bytes) => {
            println!("📎 screenshot attached (png, {} bytes)", bytes.len());
            Some(bytes)
        }
        Err(e) => {
            println!("tandera: no screenshot attached ({e})");
            None
        }
    };
    let had_image = image.is_some();

    let mut severity = "medium".to_string();
    let url_display = parsed.url.clone().unwrap_or_else(|| "-".to_string());

    'confirm: loop {
        println!(
            "category: {}  severity: [{severity}]  url: {url_display}",
            parsed.category
        );
        print!("[Enter=accept, s=severity, c=category, e=edit all] > ");
        flush_stdout();
        let Some(choice) = read_stdin_line() else {
            break 'confirm;
        };
        match choice.trim() {
            "" => break 'confirm,
            "s" => {
                if let Some(v) = prompt_severity(&severity) {
                    severity = v;
                }
            }
            "c" => {
                if let Some(v) = prompt_category(&parsed.category) {
                    parsed.category = v;
                }
            }
            "e" => {
                if let Some(v) = prompt_category(&parsed.category) {
                    parsed.category = v;
                }
                if let Some(v) = prompt_severity(&severity) {
                    severity = v;
                }
            }
            other => eprintln!("tandera: unrecognized option `{other}` — try Enter, s, c, or e"),
        }
    }

    match commands::finding::create_from_phrase(
        session.client(),
        aid,
        &parsed,
        &severity,
        phrase,
        image,
    ) {
        Ok(created) => {
            let label = created
                .display_code
                .unwrap_or_else(|| created.id.to_string());
            if had_image {
                println!("✓ draft {label} created + screenshot attached — finish in web app");
            } else {
                println!("✓ draft {label} created — finish in web app");
            }
            session.last_finding = Some(created.id);
        }
        Err(e) => commands::print_api_error(&e),
    }
    Ok(())
}

/// `:paste [<finding-code>]` — attach a clipboard screenshot to a finding.
/// Only the last-created finding (`session.last_finding`, set by
/// `dispatch_finding`) is supported as a target; resolving an explicit
/// display code to an id is out of scope for this task (YAGNI — no
/// display-code lookup service exists yet), so that case prints a clear
/// message instead of guessing.
fn dispatch_paste(session: &mut Session, rest: &str) -> Result<()> {
    let code = rest.trim();
    let finding_id = if code.is_empty() {
        match session.last_finding {
            Some(id) => id,
            None => {
                eprintln!(
                    "tandera: no finding to paste into — run `:finding <phrase>` first, then `:paste`"
                );
                return Ok(());
            }
        }
    } else {
        eprintln!(
            "tandera: `:paste {code}` isn't supported yet — looking up a finding by its display \
             code isn't wired up; run `:paste` with no argument right after `:finding` instead"
        );
        return Ok(());
    };

    let png = match crate::clipboard::grab_png() {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("tandera: {e}");
            return Ok(());
        }
    };

    let aid = match session.resolve_assessment_id() {
        Ok(id) => id,
        Err(e) => {
            eprintln!("tandera: {e}");
            return Ok(());
        }
    };

    match commands::finding::attach_image(session.client(), aid, finding_id, png) {
        Ok(()) => println!("📎 screenshot attached to finding {finding_id}"),
        Err(e) => commands::print_api_error(&e),
    }
    Ok(())
}

/// Prompt once for a severity override; `None` means "leave it unchanged"
/// (an empty line, an unrecognized value, or EOF — the caller keeps
/// `current` in all three cases, this only signals whether a NEW value was
/// accepted).
fn prompt_severity(current: &str) -> Option<String> {
    print!("severity ({current}) > ");
    flush_stdout();
    let input = read_stdin_line()?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    match Severity::value_variants()
        .iter()
        .map(|s| s.as_wire())
        .find(|w| w.eq_ignore_ascii_case(trimmed))
    {
        Some(w) => Some(w.to_string()),
        None => {
            eprintln!("tandera: unknown severity `{trimmed}` — keeping `{current}`");
            None
        }
    }
}

/// Same shape as `prompt_severity`, for category.
fn prompt_category(current: &str) -> Option<String> {
    print!("category ({current}) > ");
    flush_stdout();
    let input = read_stdin_line()?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    match Category::value_variants()
        .iter()
        .map(|c| c.as_wire())
        .find(|w| w.eq_ignore_ascii_case(trimmed))
    {
        Some(w) => Some(w.to_string()),
        None => {
            eprintln!("tandera: unknown category `{trimmed}` — keeping `{current}`");
            None
        }
    }
}

/// Read one line from stdin for an interactive sub-prompt. Returns `None`
/// on EOF (`Ok(0)`) or any read error — a closed/non-tty stdin degrades to
/// "no input" instead of panicking or blocking forever, so every caller can
/// treat `None` as "accept the current default and move on".
fn read_stdin_line() -> Option<String> {
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(0) => None,
        Ok(_) => Some(line),
        Err(_) => None,
    }
}

fn flush_stdout() {
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

/// `:sync [on|off]` — toggle (and persist) whether the local testing-log
/// also gets a redacted, best-effort sync to the assessment's activity
/// timeline (see `Session::log_command`). No argument just reports the
/// current setting rather than erroring — a quiet way to check state
/// without risking flipping it by fat-fingering a bare `:sync`.
fn dispatch_sync(session: &mut Session, rest: &str) -> Result<()> {
    let arg = rest.trim().to_ascii_lowercase();
    let on = match arg.as_str() {
        "on" => true,
        "off" => false,
        "" => {
            println!(
                "tandera: testing-log sync to activity timeline is {}",
                if session.sync_testing_log {
                    "on"
                } else {
                    "off"
                }
            );
            return Ok(());
        }
        other => {
            eprintln!("tandera: unknown `:sync {other}` — try `:sync on` or `:sync off`");
            return Ok(());
        }
    };
    Config::set_sync_testing_log(&session.cfg_path, on)?;
    session.sync_testing_log = on;
    println!(
        "tandera: testing-log sync to activity timeline is now {}",
        if on { "on" } else { "off" }
    );
    Ok(())
}

fn dispatch_log(session: &Session) {
    match std::fs::read_to_string(&session.log_path) {
        Ok(body) if !body.trim().is_empty() => print!("{body}"),
        _ => println!("No log entries yet."),
    }
}

fn print_help() {
    print!("{}", complete::help_text());
}

/// Print one line per upload that finished since the last check — called at
/// the top of every prompt cycle so a background import's outcome (success
/// with counts, or an error) surfaces without blocking the shell.
fn print_upload_receipts(session: &Session) {
    for r in session.uploads.poll_receipts() {
        match &r.result {
            Ok(msg) => println!("tandera: [{}] {} — {msg}", r.handle, r.label),
            Err(e) => println!("tandera: [{}] {} — failed: {e}", r.handle, r.label),
        }
    }
}

/// Build the `Session`, print the initial banner, then loop reading lines
/// from the user until `:exit`/`:quit`/Ctrl-D. Not unit-tested (rustyline
/// needs a TTY) — `handle_line` carries all the logic this drives.
pub fn run_shell(
    cfg_path: &Path,
    api_url_override: Option<&str>,
    assessment_override: Option<&str>,
) -> Result<i32> {
    // The shell opens even without a token: `build_client_optional_auth`
    // never errors on a missing credential, so bare `tandera` (or `tandera
    // shell`) always reaches the banner. Authentication is prompted for
    // lazily — from inside, via `:login` — rather than being a hard gate on
    // ever seeing the console.
    let (client, authenticated) = commands::build_client_optional_auth(cfg_path, api_url_override)?;
    let mut session = Session::new(client, cfg_path.to_path_buf(), assessment_override)?;

    let snap = lock(&session.state).snap.clone();
    let active = !matches!(session.auto_upload, AutoUpload::Paused);
    println!(
        "{}",
        status::format_banner(&session.assessment_label, active, &snap)
    );
    if !authenticated {
        println!("Not signed in — run `:login` to authenticate (or `:help` for commands).");
    }

    let mut rl: rustyline::Editor<complete::ReplHelper, rustyline::history::DefaultHistory> =
        rustyline::Editor::new().context("failed to initialize the line editor")?;
    rl.set_helper(Some(complete::ReplHelper));
    loop {
        print_upload_receipts(&session);
        match rl.readline("tandera> ") {
            Ok(line) => {
                let _ = rl.add_history_entry(line.as_str());
                match handle_line(&mut session, &line) {
                    Ok(Control::Continue) => {}
                    Ok(Control::Exit) => break,
                    Err(e) => eprintln!("tandera: {e:#}"),
                }
            }
            Err(rustyline::error::ReadlineError::Interrupted) => {
                // Ctrl-C: mirror bash — cancel the current line, re-prompt.
            }
            Err(rustyline::error::ReadlineError::Eof) => break, // Ctrl-D
            Err(e) => {
                eprintln!("tandera: readline error: {e}");
                break;
            }
        }
    }
    Ok(0)
}
