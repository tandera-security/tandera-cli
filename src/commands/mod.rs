//! CLI surface (clap derive) + dispatch. Each subcommand's actual logic
//! lives in a sibling module (`auth`, `assessments`, `findings`) as plain
//! functions over `&ApiClient` / `&Path`, so it's testable without going
//! through `clap` parsing or `std::process::exit`; this module is the thin
//! glue that parses args, resolves config, calls those functions, and
//! renders the result (table or `--json`).

pub mod assessment_new;
pub mod assessments;
pub mod auth;
pub mod client;
pub mod evidence;
pub mod finding;
pub mod findings;
pub mod methodologies;
pub mod portal;
pub mod project;
pub mod read;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use uuid::Uuid;

use crate::api::{ApiClient, ApiError};
use crate::capture::import;
use crate::config::Config;
use crate::models::{
    AiDraftRequest, AiRewriteRequest, Artifact, Assessment, Category, FindingSummary, Severity,
};

#[derive(Parser)]
#[command(
    name = "tandera",
    version,
    about = "Command-line client for the Tandera security platform API"
)]
pub struct Cli {
    /// Override the configured API URL for this invocation only.
    #[arg(long, global = true, hide = true)]
    pub api_url: Option<String>,

    /// Override the active assessment for this invocation only (must
    /// precede the subcommand, e.g. `tandera --assessment foo asset list`).
    //
    // Deliberately NOT `global = true` (unlike the brief's literal snippet):
    // `FindingsCommand::{List,AiDraft,AiRewrite}` already each declare their
    // own required `--assessment <UUID>` flag. clap merges global args into
    // every subcommand's arg set *by id*, and both fields share the id
    // `assessment` — with `global = true` here, clap collapses them into one
    // Arg definition and the Findings subcommands panic at parse time
    // (`Mismatch between definition and access of "assessment" ... need to
    // downcast to uuid::Uuid`) because the merged Arg ends up using this
    // field's `String` value-parser. Keeping this one non-global avoids the
    // collision: it's still parsed into `Cli::assessment` when given before
    // the subcommand, which is all `resolve_active_assessment` needs.
    #[arg(long)]
    pub assessment: Option<String>,

    /// Print raw API JSON instead of a table.
    #[arg(long, global = true)]
    pub json: bool,

    /// Absent when `tandera` is invoked with no subcommand: `run()` then
    /// picks import mode (piped stdin) or the interactive shell (a TTY)
    /// based on `std::io::IsTerminal`. This is the only reason this field
    /// is optional — every other subcommand still parses exactly as before.
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Manage the stored personal access token (PAT).
    Auth {
        #[command(subcommand)]
        action: AuthCommand,
    },
    /// Work with assessments.
    Assessments {
        #[command(subcommand)]
        action: AssessmentsCommand,
    },
    /// Work with findings, including AI-assisted authoring.
    Findings {
        #[command(subcommand)]
        action: FindingsCommand,
    },
    /// Pick / set the active assessment.
    Project {
        #[command(subcommand)]
        action: ProjectCommand,
    },
    /// Set the active assessment directly (alias for `project use`).
    Use { id_or_slug: String },
    /// List assets on the active assessment.
    Asset {
        #[command(subcommand)]
        action: AssetCommand,
    },
    /// Launch the interactive shell.
    Shell,
    /// Create a new assessment through an interactive wizard (needs a
    /// terminal). Also reachable as `tandera new-assessment`.
    #[command(alias = "new-assessment")]
    Pentest,
    /// Open the Tandera console in your browser — deep-linked to the active
    /// assessment when one is set.
    Portal,
    /// Manage clients: add one (and bind it to the active assessment), list
    /// them, or bind an existing one.
    Client {
        #[command(subcommand)]
        action: ClientCommand,
    },
    /// Capture and list evidence in the active assessment's locker.
    Evidence {
        #[command(subcommand)]
        action: EvidenceCommand,
    },
    /// Non-interactive import: upload a scan file (or piped stdin) to the
    /// active assessment. Equivalent to piping into bare `tandera`, but
    /// explicit and scriptable.
    Import {
        /// The scan_type to tag the upload with (e.g. nmap, nuclei, httpx,
        /// nikto). If omitted, it's sniffed from the input; an ambiguous or
        /// unrecognized sniff is a hard error asking for this flag.
        #[arg(long = "type")]
        scan_type: Option<String>,
        /// Read the scan output from this file instead of stdin.
        #[arg(long, short = 'f')]
        file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub enum ProjectCommand {
    /// Interactive picker.
    Pick,
    /// Print the active assessment.
    Current,
    /// Unset the active assessment.
    Clear,
    /// Set directly by id or slug.
    Use { id_or_slug: String },
}

#[derive(Subcommand)]
pub enum AssetCommand {
    List {
        /// Optional asset_type filter (e.g. host, domain, url).
        asset_type: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum EvidenceCommand {
    /// Capture a text evidence item on the active assessment's locker
    /// (asset/finding resolution happens server-side).
    Add {
        /// The evidence kind (e.g. http_request, http_response, terminal,
        /// log, note, scanner_record). Binary kinds aren't supported here.
        #[arg(long)]
        kind: String,
        /// The text body to capture.
        #[arg(long)]
        content: Option<String>,
        /// A raw host/url/ip hint for later asset resolution.
        #[arg(long)]
        target: Option<String>,
        /// Who/what captured this evidence.
        #[arg(long, default_value = "cli")]
        source: String,
    },
    /// List the locker, optionally filtered by status.
    List {
        /// One of captured/resolved/promoted/discarded.
        #[arg(long)]
        status: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum ClientCommand {
    /// Create a client and bind it to the active assessment in one step.
    Add {
        /// The company name (no quotes needed — trailing words are joined).
        #[arg(required = true)]
        company: Vec<String>,
    },
    /// List the org's clients.
    List,
    /// Bind an existing client (company name or id) to the active assessment.
    Bind {
        /// Company name or client id (trailing words are joined).
        #[arg(required = true)]
        needle: Vec<String>,
    },
}

#[derive(Subcommand)]
pub enum AuthCommand {
    /// Log in with a personal access token (verified before it is stored).
    Login {
        /// The PAT to store (tandera_pat_...). If omitted, you're prompted
        /// on stdin (plain text — not hidden; see the README for why).
        #[arg(long)]
        token: Option<String>,
    },
    /// Show whether a token is configured, its prefix, and whether it's
    /// still valid.
    Status,
    /// Remove the stored token.
    Logout,
}

#[derive(Subcommand)]
pub enum AssessmentsCommand {
    /// List assessments.
    List,
}

#[derive(Subcommand)]
pub enum FindingsCommand {
    /// List findings on an assessment.
    List {
        /// The assessment id.
        #[arg(long)]
        assessment: Uuid,
    },
    /// Generate a new DRAFT finding from operator inputs + artifacts via AI
    /// (`POST /v1/assessments/{assessment}/findings/ai-draft`). Requires
    /// the org's `AiAuthoring` plan entitlement (a 402 otherwise).
    AiDraft {
        /// The assessment to create the finding on.
        #[arg(long)]
        assessment: Uuid,
        /// The finding's category — human-owned, never set by the model.
        #[arg(long)]
        category: Category,
        /// The finding's severity — human-owned, never set by the model.
        #[arg(long)]
        severity: Severity,
        /// A CWE id (bare number, e.g. `89`). Repeatable.
        #[arg(long = "cwe")]
        cwes: Vec<u32>,
        /// A CVSS vector string.
        #[arg(long)]
        cvss_vector: Option<String>,
        /// An asset id to associate the finding with.
        #[arg(long)]
        asset_id: Option<Uuid>,
        /// A free-text note for the model (treated as untrusted input).
        #[arg(long)]
        note: Option<String>,
        /// Report language.
        #[arg(long, default_value = "en")]
        language: String,
        /// `<kind>=<content>` (kind: http_request, http_response, log,
        /// scanner_output; a bare value with no `kind=` defaults to
        /// `log`). Repeatable.
        #[arg(long = "artifact", value_parser = findings::parse_artifact)]
        artifacts: Vec<Artifact>,
    },
    /// Regenerate the prose of one or more fields on an EXISTING finding
    /// via AI (`POST
    /// /v1/assessments/{assessment}/findings/{finding}/ai-rewrite`).
    /// Requires the org's `AiAuthoring` plan entitlement.
    AiRewrite {
        /// The finding's assessment id (the route is nested under it).
        #[arg(long)]
        assessment: Uuid,
        /// The finding to rewrite.
        #[arg(long)]
        finding: Uuid,
        /// A prose field to regenerate (e.g. `description`,
        /// `recommendation`). Repeatable, at least one required.
        #[arg(long = "field")]
        fields: Vec<String>,
        /// Free-text guidance for the rewrite (treated as untrusted input).
        #[arg(long)]
        instructions: Option<String>,
        /// Report language.
        #[arg(long, default_value = "en")]
        language: String,
        /// `<kind>=<content>`, same shape as `ai-draft --artifact`.
        #[arg(long = "artifact", value_parser = findings::parse_artifact)]
        artifacts: Vec<Artifact>,
    },
}

/// Parses argv and runs the selected command, returning the process exit
/// code (0 success, non-zero on any failure — an API error, an invalid
/// token, etc.). Only genuinely unexpected failures (a malformed config
/// file, a broken HTTP client) come back as `Err`; ordinary "the API said
/// no" outcomes are handled inline and reflected in the returned code.
pub fn run(cli: Cli) -> Result<i32> {
    let cfg_path = crate::config::config_path()?;
    let Some(command) = cli.command else {
        return run_bare(&cfg_path, cli.api_url.as_deref(), cli.assessment.as_deref());
    };
    match command {
        Commands::Auth { action } => run_auth(action, &cfg_path, cli.api_url.as_deref()),
        Commands::Assessments { action } => {
            run_assessments(action, &cfg_path, cli.api_url.as_deref(), cli.json)
        }
        Commands::Findings { action } => {
            run_findings(action, &cfg_path, cli.api_url.as_deref(), cli.json)
        }
        Commands::Project { action } => {
            run_project(action, &cfg_path, cli.api_url.as_deref(), cli.json)
        }
        Commands::Use { id_or_slug } => use_assessment(&cfg_path, &id_or_slug),
        Commands::Asset { action } => run_asset(
            action,
            &cfg_path,
            cli.api_url.as_deref(),
            cli.assessment.as_deref(),
            cli.json,
        ),
        Commands::Shell => {
            crate::repl::run_shell(&cfg_path, cli.api_url.as_deref(), cli.assessment.as_deref())
        }
        Commands::Pentest => run_pentest(&cfg_path, cli.api_url.as_deref()),
        Commands::Portal => {
            run_portal(&cfg_path, cli.api_url.as_deref(), cli.assessment.as_deref())
        }
        Commands::Client { action } => run_client(
            action,
            &cfg_path,
            cli.api_url.as_deref(),
            cli.assessment.as_deref(),
            cli.json,
        ),
        Commands::Evidence { action } => run_evidence(
            action,
            &cfg_path,
            cli.api_url.as_deref(),
            cli.assessment.as_deref(),
        ),
        Commands::Import { scan_type, file } => run_import(
            &cfg_path,
            cli.api_url.as_deref(),
            cli.assessment.as_deref(),
            scan_type,
            file,
        ),
    }
}

/// `tandera pentest` / `tandera new-assessment`: run the create-assessment
/// wizard, then persist the created assessment as the active one so
/// subsequent commands target it.
fn run_pentest(cfg_path: &Path, api_url_override: Option<&str>) -> Result<i32> {
    let client = build_client(cfg_path, api_url_override)?;
    match assessment_new::run_wizard(&client)? {
        Some(created) => {
            let handle = created.active_ref();
            project::set_active(cfg_path, &handle)?;
            println!("Active assessment set to {handle}.");
            Ok(0)
        }
        // Aborted (Ctrl-D) or the API rejected it — the wizard already said why.
        None => Ok(0),
    }
}

/// `tandera portal` — open the console in the browser, deep-linked to the
/// active assessment when one can be resolved. Works even without a token
/// (falls back to the console home) so it's always useful.
fn run_portal(
    cfg_path: &Path,
    api_url_override: Option<&str>,
    assessment_override: Option<&str>,
) -> Result<i32> {
    let cfg = Config::load_from(cfg_path)?;
    let api_url = cfg.effective_api_url(api_url_override);
    let aid = build_client(cfg_path, api_url_override)
        .ok()
        .and_then(|client| resolve_active_assessment(&client, &cfg, assessment_override).ok())
        .map(|id| id.to_string());
    let url = portal::portal_url(&api_url, cfg.app_url.as_deref(), aid.as_deref());
    portal::open_url(&url);
    Ok(0)
}

/// `tandera client add|list|bind` — manage clients and bind them to the
/// active assessment.
fn run_client(
    action: ClientCommand,
    cfg_path: &Path,
    api_url_override: Option<&str>,
    assessment_override: Option<&str>,
    json: bool,
) -> Result<i32> {
    let api = build_client(cfg_path, api_url_override)?;
    let cfg = Config::load_from(cfg_path)?;
    match action {
        ClientCommand::List => match client::list_clients(&api) {
            Ok(raw) => {
                if json {
                    println!("{}", serde_json::to_string_pretty(&raw)?);
                } else {
                    print!(
                        "{}",
                        client::format_clients_table(&client::parse_clients(raw))
                    );
                }
                Ok(0)
            }
            Err(e) => {
                print_api_error(&e);
                Ok(1)
            }
        },
        ClientCommand::Add { company } => {
            let name = company.join(" ");
            let aid = resolve_active_assessment(&api, &cfg, assessment_override)?;
            match client::add_and_bind(&api, aid, &name) {
                Ok(_) => {
                    println!("✓ created client \"{name}\" and bound it to the active assessment.");
                    Ok(0)
                }
                Err(e) => {
                    print_api_error(&e);
                    Ok(1)
                }
            }
        }
        ClientCommand::Bind { needle } => {
            let needle = needle.join(" ");
            let aid = resolve_active_assessment(&api, &cfg, assessment_override)?;
            match client::bind_existing(&api, aid, &needle) {
                Ok(Some(name)) => {
                    println!("✓ bound client \"{name}\" to the active assessment.");
                    Ok(0)
                }
                Ok(None) => {
                    eprintln!(
                        "no client matching \"{needle}\" — try `tandera client list`, or `tandera client add \"{needle}\"` to create it."
                    );
                    Ok(1)
                }
                Err(e) => {
                    print_api_error(&e);
                    Ok(1)
                }
            }
        }
    }
}

/// Routing for bare `tandera` (no subcommand at all): a piped/redirected
/// stdin means "import this", an interactive terminal means "launch the
/// shell". The decision itself is `wants_shell` (unit-tested below) so this
/// function is just wiring `std::io::IsTerminal` to it.
fn run_bare(
    cfg_path: &Path,
    api_url_override: Option<&str>,
    assessment_override: Option<&str>,
) -> Result<i32> {
    use std::io::IsTerminal;

    if wants_shell(std::io::stdin().is_terminal(), false) {
        crate::repl::run_shell(cfg_path, api_url_override, assessment_override)
    } else {
        run_import(cfg_path, api_url_override, assessment_override, None, None)
    }
}

/// Bare `tandera` routes to the shell only when stdin is an interactive
/// terminal AND no subcommand was given — piped/redirected stdin (or any
/// explicit subcommand, which never reaches this helper) means import mode
/// instead. Factored out so the TTY-detection wiring in `run_bare` can stay
/// untested while this decision is covered directly.
fn wants_shell(is_tty: bool, has_command: bool) -> bool {
    is_tty && !has_command
}

/// Turn the stored slug/id into a concrete assessment `Uuid` by listing the
/// caller's assessments and resolving. Errors clearly if none is active or
/// the stored value no longer matches a membership.
pub fn resolve_active_assessment(
    client: &ApiClient,
    cfg: &Config,
    assessment_override: Option<&str>,
) -> Result<Uuid> {
    let needle = cfg
        .effective_assessment(assessment_override)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no active assessment — run `tandera project` (or `:project` in the shell)"
            )
        })?;
    let raw = crate::commands::project::list(client)
        .map_err(|e| anyhow::anyhow!("failed to list assessments: {e}"))?;
    let resp: crate::models::AssessmentListResponse =
        serde_json::from_value(raw).context("failed to parse assessments response")?;
    crate::commands::project::resolve_assessment(&resp.items, &needle).ok_or_else(|| {
        anyhow::anyhow!("active assessment `{needle}` not found among your memberships")
    })
}

/// Shared by both `tandera use <id_or_slug>` and `tandera project use
/// <id_or_slug>`.
fn use_assessment(cfg_path: &Path, id_or_slug: &str) -> Result<i32> {
    project::set_active(cfg_path, id_or_slug)?;
    println!("Active assessment set to {id_or_slug}");
    Ok(0)
}

fn run_project(
    action: ProjectCommand,
    cfg_path: &Path,
    api_url_override: Option<&str>,
    json: bool,
) -> Result<i32> {
    match action {
        ProjectCommand::Pick => {
            let client = build_client(cfg_path, api_url_override)?;
            match project::list(&client) {
                Ok(raw) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&raw)?);
                    } else {
                        let resp: crate::models::AssessmentListResponse =
                            serde_json::from_value(raw)
                                .context("failed to parse assessments response")?;
                        print_assessments_table(&resp.items);
                        println!("\nRun `tandera use <id-or-slug>` to set the active assessment.");
                    }
                    Ok(0)
                }
                Err(e) => {
                    print_api_error(&e);
                    Ok(1)
                }
            }
        }
        ProjectCommand::Current => {
            let cfg = Config::load_from(cfg_path)?;
            match cfg.effective_assessment(None) {
                Some(a) => println!("{a}"),
                None => println!(
                    "No active assessment. Run `tandera project` or `tandera use <id-or-slug>`."
                ),
            }
            Ok(0)
        }
        ProjectCommand::Clear => {
            project::clear_active(cfg_path)?;
            println!("Active assessment cleared.");
            Ok(0)
        }
        ProjectCommand::Use { id_or_slug } => use_assessment(cfg_path, &id_or_slug),
    }
}

fn run_asset(
    action: AssetCommand,
    cfg_path: &Path,
    api_url_override: Option<&str>,
    assessment_override: Option<&str>,
    json: bool,
) -> Result<i32> {
    let client = build_client(cfg_path, api_url_override)?;
    match action {
        AssetCommand::List { asset_type } => {
            let cfg = Config::load_from(cfg_path)?;
            let assessment_id = match resolve_active_assessment(&client, &cfg, assessment_override)
            {
                Ok(id) => id,
                Err(e) => {
                    eprintln!("error: {e:#}");
                    return Ok(1);
                }
            };
            match read::list_assets(&client, assessment_id, asset_type.as_deref()) {
                Ok(raw) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&raw)?);
                    } else {
                        let resp: crate::models::AssetListResponse = serde_json::from_value(raw)
                            .context("failed to parse assets response")?;
                        print!("{}", read::format_assets_table(&resp.items));
                    }
                    Ok(0)
                }
                Err(e) => {
                    print_api_error(&e);
                    Ok(1)
                }
            }
        }
    }
}

/// `tandera evidence add|list` — captures/lists evidence on the active
/// assessment. Both routes' response shapes (a full `Evidence` row on
/// create, a paginated `{ data, next_cursor, has_more }` envelope on list)
/// are rendered as raw pretty-printed JSON rather than a table, the same way
/// `run_findings` handles `AiDraft`/`AiRewrite` — there's no CLI-side model
/// for either shape (yet), so there's nothing to build a table out of.
fn run_evidence(
    action: EvidenceCommand,
    cfg_path: &Path,
    api_url_override: Option<&str>,
    assessment_override: Option<&str>,
) -> Result<i32> {
    let client = build_client(cfg_path, api_url_override)?;
    let cfg = Config::load_from(cfg_path)?;
    let assessment_id = match resolve_active_assessment(&client, &cfg, assessment_override) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("error: {e:#}");
            return Ok(1);
        }
    };
    let result = match action {
        EvidenceCommand::Add {
            kind,
            content,
            target,
            source,
        } => evidence::add(
            &client,
            assessment_id,
            &kind,
            content.as_deref(),
            target.as_deref(),
            &source,
        ),
        EvidenceCommand::List { status } => {
            evidence::list(&client, assessment_id, status.as_deref())
        }
    };
    match result {
        Ok(v) => {
            println!("{}", serde_json::to_string_pretty(&v)?);
            Ok(0)
        }
        Err(e) => {
            print_api_error(&e);
            Ok(1)
        }
    }
}

/// Non-interactive import: resolves the active assessment, gets the bytes
/// from `--file` if given (else stdin), determines `scan_type` from `--type`
/// if given (else sniffs it), and uploads. Reused verbatim by bare `tandera`
/// with piped stdin (`run_bare` calls this with `scan_type: None, file:
/// None`).
fn run_import(
    cfg_path: &Path,
    api_url_override: Option<&str>,
    assessment_override: Option<&str>,
    scan_type: Option<String>,
    file: Option<PathBuf>,
) -> Result<i32> {
    let client = build_client(cfg_path, api_url_override)?;
    let cfg = Config::load_from(cfg_path)?;
    let assessment_id = match resolve_active_assessment(&client, &cfg, assessment_override) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("error: {e:#}");
            return Ok(1);
        }
    };

    if let Some(path) = file {
        let bytes = match std::fs::read(&path)
            .with_context(|| format!("failed to read {}", path.display()))
        {
            Ok(b) => b,
            Err(e) => {
                eprintln!("error: {e:#}");
                return Ok(1);
            }
        };
        if bytes.is_empty() {
            eprintln!("error: {} is empty — nothing to import", path.display());
            return Ok(1);
        }
        let Some(resolved_type) =
            resolve_scan_type_or_report(scan_type, &bytes, &path.display().to_string())
        else {
            return Ok(1);
        };
        let result = import::upload_file(&client, assessment_id, &path, &resolved_type);
        return report_import(result);
    }

    let bytes = import::read_all_stdin()?;
    if bytes.is_empty() {
        eprintln!("error: no input on stdin — pipe a scan file or pass --file <path>");
        return Ok(1);
    }
    let Some(resolved_type) = resolve_scan_type_or_report(scan_type, &bytes, "stdin") else {
        return Ok(1);
    };
    let ext = crate::capture::registry::lookup(&resolved_type)
        .map(|spec| spec.ext)
        .unwrap_or("dat");
    let file_name = format!("stdin.{ext}");
    let result = import::upload_bytes(&client, assessment_id, &file_name, &bytes, &resolved_type);
    report_import(result)
}

/// `--type` wins outright; otherwise sniffs `bytes` and, on an
/// unrecognized/ambiguous result, returns a user-facing error message that
/// names the flag to pass instead.
fn resolve_scan_type(
    explicit: Option<String>,
    bytes: &[u8],
    source: &str,
) -> std::result::Result<String, String> {
    if let Some(t) = explicit {
        return Ok(t);
    }
    import::sniff_scan_type(bytes).map(str::to_string).ok_or_else(|| {
        format!(
            "error: could not determine the scan type from {source} — pass `--type <scan_type>` (e.g. nmap, nikto, nuclei, httpx)"
        )
    })
}

/// `resolve_scan_type`, plus the "print the message and report the caller's
/// exit-1 outcome" arm shared by both the `--file` and stdin branches of
/// `run_import` — collapses what used to be two identical `match` blocks.
fn resolve_scan_type_or_report(
    explicit: Option<String>,
    bytes: &[u8],
    source: &str,
) -> Option<String> {
    match resolve_scan_type(explicit, bytes, source) {
        Ok(t) => Some(t),
        Err(msg) => {
            eprintln!("{msg}");
            None
        }
    }
}

fn report_import(result: std::result::Result<import::ImportResult, ApiError>) -> Result<i32> {
    match result {
        Ok(r) => {
            println!(
                "Imported {} asset(s), {} finding(s)",
                r.asset_count, r.finding_count
            );
            Ok(0)
        }
        Err(e) => {
            print_api_error(&e);
            Ok(1)
        }
    }
}

fn run_auth(action: AuthCommand, cfg_path: &Path, api_url_override: Option<&str>) -> Result<i32> {
    match action {
        AuthCommand::Login { token } => {
            let cfg = Config::load_from(cfg_path)?;
            let api_url = cfg.effective_api_url(api_url_override);
            let token = match token {
                Some(t) => t,
                None => prompt_for_token()?,
            };
            let token = token.trim();
            if token.is_empty() {
                eprintln!("error: no token provided");
                return Ok(1);
            }
            match auth::login(cfg_path, &api_url, token)? {
                auth::LoginOutcome::Success { redacted_token } => {
                    println!("Logged in as {redacted_token} against {api_url}");
                    Ok(0)
                }
                auth::LoginOutcome::InvalidToken => {
                    eprintln!("invalid token");
                    Ok(1)
                }
            }
        }
        AuthCommand::Status => match auth::status(cfg_path, api_url_override)? {
            auth::StatusOutcome::NotConfigured => {
                println!("Not logged in. Run `tandera auth login`.");
                Ok(1)
            }
            auth::StatusOutcome::Authenticated { prefix, api_url } => {
                println!("Token:    {prefix}");
                println!("API URL:  {api_url}");
                println!("Status:   authenticated");
                Ok(0)
            }
            auth::StatusOutcome::Expired { prefix, api_url } => {
                println!("Token:    {prefix}");
                println!("API URL:  {api_url}");
                println!("Status:   token expired or revoked");
                Ok(1)
            }
        },
        AuthCommand::Logout => {
            if auth::logout(cfg_path)? {
                println!("Logged out.");
            } else {
                println!("No token was configured.");
            }
            Ok(0)
        }
    }
}

/// Prompts for a token on stdin. Deliberately a PLAIN prompt, not an
/// echo-suppressed one: suppressing terminal echo portably needs either a
/// raw-mode terminal crate or shelling out to `stty`, and the task brief
/// explicitly allows "a plain prompt" as the fallback — adding a dependency
/// solely for this one, non-security-critical UX nicety (the token is still
/// verified before storage either way, and typing it is no less safe than
/// e.g. `git` prompting for a token in plain text) isn't worth it here.
///
/// `pub(crate)` so the shell's `:login` (`repl::dispatch_login`) prompts for
/// a token exactly the way `tandera auth login` does, instead of hand-rolling
/// a second prompt.
pub(crate) fn prompt_for_token() -> Result<String> {
    use std::io::Write;
    eprint!("Enter Tandera personal access token: ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("failed to read token from stdin")?;
    Ok(line)
}

/// `pub(crate)` so `repl::run_shell` can build the shell's `ApiClient` the
/// same way every other subcommand does, instead of duplicating config
/// resolution + error messaging.
pub(crate) fn build_client(cfg_path: &Path, api_url_override: Option<&str>) -> Result<ApiClient> {
    let cfg = Config::load_from(cfg_path)?;
    let api_url = cfg.effective_api_url(api_url_override);
    let token = cfg.effective_token().ok_or_else(|| {
        anyhow::anyhow!(
            "no token configured — run `tandera auth login` first (or set TANDERA_TOKEN)"
        )
    })?;
    ApiClient::new(api_url, Some(token))
}

/// Like `build_client`, but tolerates a missing token instead of erroring:
/// the returned client simply sends no `Authorization` header, so an
/// unauthenticated call comes back as a `401` (rendered by `print_api_error`)
/// rather than failing before the request is ever made. Used only by the
/// interactive shell (`repl::run_shell`), which must open — and print its
/// banner — even when the user hasn't logged in yet; auth is then handled
/// lazily from inside via `:login`. The returned `bool` is whether a token
/// was present, so the caller can show a "not signed in" hint.
pub(crate) fn build_client_optional_auth(
    cfg_path: &Path,
    api_url_override: Option<&str>,
) -> Result<(ApiClient, bool)> {
    let cfg = Config::load_from(cfg_path)?;
    let api_url = cfg.effective_api_url(api_url_override);
    let token = cfg.effective_token();
    let authenticated = token.is_some();
    let client = ApiClient::new(api_url, token)?;
    Ok((client, authenticated))
}

fn run_assessments(
    action: AssessmentsCommand,
    cfg_path: &Path,
    api_url_override: Option<&str>,
    json: bool,
) -> Result<i32> {
    let client = build_client(cfg_path, api_url_override)?;
    match action {
        AssessmentsCommand::List => match assessments::list(&client) {
            Ok(raw) => {
                if json {
                    println!("{}", serde_json::to_string_pretty(&raw)?);
                } else {
                    let resp: crate::models::AssessmentListResponse =
                        serde_json::from_value(raw)
                            .context("failed to parse assessments response")?;
                    print_assessments_table(&resp.items);
                }
                Ok(0)
            }
            Err(e) => {
                print_api_error(&e);
                Ok(1)
            }
        },
    }
}

fn run_findings(
    action: FindingsCommand,
    cfg_path: &Path,
    api_url_override: Option<&str>,
    json: bool,
) -> Result<i32> {
    let client = build_client(cfg_path, api_url_override)?;
    match action {
        FindingsCommand::List { assessment } => match findings::list(&client, assessment) {
            Ok(raw) => {
                if json {
                    println!("{}", serde_json::to_string_pretty(&raw)?);
                } else {
                    let items: Vec<FindingSummary> =
                        serde_json::from_value(raw).context("failed to parse findings response")?;
                    print_findings_table(&items);
                }
                Ok(0)
            }
            Err(e) => {
                print_api_error(&e);
                Ok(1)
            }
        },
        FindingsCommand::AiDraft {
            assessment,
            category,
            severity,
            cwes,
            cvss_vector,
            asset_id,
            note,
            language,
            artifacts,
        } => {
            let req = AiDraftRequest {
                category: category.as_wire().to_string(),
                severity: severity.as_wire().to_string(),
                cwes,
                cvss_vector,
                asset_id,
                note,
                language,
                artifacts,
            };
            match findings::ai_draft(&client, assessment, &req) {
                Ok(raw) => {
                    println!("{}", serde_json::to_string_pretty(&raw)?);
                    Ok(0)
                }
                Err(e) => {
                    print_api_error(&e);
                    Ok(1)
                }
            }
        }
        FindingsCommand::AiRewrite {
            assessment,
            finding,
            fields,
            instructions,
            language,
            artifacts,
        } => {
            let req = AiRewriteRequest {
                fields,
                artifacts,
                instructions,
                language,
            };
            match findings::ai_rewrite(&client, assessment, finding, &req) {
                Ok(raw) => {
                    println!("{}", serde_json::to_string_pretty(&raw)?);
                    Ok(0)
                }
                Err(e) => {
                    print_api_error(&e);
                    Ok(1)
                }
            }
        }
    }
}

/// `pub(crate)` so `repl::dispatch_meta` renders API errors identically to
/// the non-interactive subcommands, instead of duplicating the match.
pub(crate) fn print_api_error(e: &ApiError) {
    match e {
        ApiError::Unauthorized(msg) => eprintln!("error: unauthorized — {msg}"),
        ApiError::PaymentRequired(msg) => {
            eprintln!("error: plan entitlement required — {msg}");
        }
        ApiError::Http { status, message } => {
            eprintln!("error: API returned {status} — {message}")
        }
        ApiError::Transport(msg) => eprintln!("error: {msg}"),
    }
}

/// `pub(crate)` so `:project` in the shell renders the same table as
/// `tandera project pick` / `tandera assessments list`.
pub(crate) fn print_assessments_table(items: &[Assessment]) {
    if items.is_empty() {
        println!("No assessments found.");
        return;
    }
    println!("{:<38} {:<30} {:<16} TYPE", "ID", "NAME", "STATUS");
    for a in items {
        println!(
            "{:<38} {:<30} {:<16} {}",
            a.id,
            truncate(&a.name, 30),
            a.status,
            a.assessment_type.as_deref().unwrap_or("-")
        );
    }
}

/// `pub(crate)` so `:findings` in the shell renders the same table as
/// `tandera findings list`.
pub(crate) fn print_findings_table(items: &[FindingSummary]) {
    if items.is_empty() {
        println!("No findings found.");
        return;
    }
    println!("{:<14} {:<40} {:<10} STATUS", "CODE", "TITLE", "SEVERITY");
    for f in items {
        let code = if f.display_code.is_empty() {
            f.id.to_string()
        } else {
            f.display_code.clone()
        };
        println!(
            "{:<14} {:<40} {:<10} {}",
            code,
            truncate(&f.title, 40),
            f.severity,
            f.status
        );
    }
}

/// `pub(crate)` so `commands::read::format_assets_table` reuses this instead
/// of carrying an identical copy.
pub(crate) fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{t}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_is_char_boundary_safe_and_no_op_under_the_limit() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("exactly10c", 10), "exactly10c");
        let long = "a".repeat(50);
        let t = truncate(&long, 10);
        assert_eq!(t.chars().count(), 10);
        assert!(t.ends_with('…'));
    }

    #[test]
    fn cli_parses_ai_draft_with_repeated_flags() {
        let cli = Cli::parse_from([
            "tandera",
            "findings",
            "ai-draft",
            "--assessment",
            "00000000-0000-0000-0000-000000000001",
            "--category",
            "injection",
            "--severity",
            "high",
            "--cwe",
            "89",
            "--cwe",
            "20",
            "--artifact",
            "log=some log line",
            "--artifact",
            "http_request=GET / HTTP/1.1",
        ]);
        match cli.command {
            Some(Commands::Findings {
                action:
                    FindingsCommand::AiDraft {
                        cwes, artifacts, ..
                    },
            }) => {
                assert_eq!(cwes, vec![89, 20]);
                assert_eq!(artifacts.len(), 2);
                assert_eq!(artifacts[0].kind, "log");
                assert_eq!(artifacts[1].kind, "http_request");
            }
            _ => panic!("expected Findings::AiDraft"),
        }
    }

    #[test]
    fn cli_parses_asset_list_with_type() {
        let cli = Cli::parse_from(["tandera", "asset", "list", "host"]);
        match cli.command {
            Some(Commands::Asset {
                action: AssetCommand::List { asset_type },
            }) => {
                assert_eq!(asset_type.as_deref(), Some("host"));
            }
            _ => panic!("expected Asset::List"),
        }
    }

    #[test]
    fn cli_parses_with_no_subcommand_as_none() {
        let cli = Cli::parse_from(["tandera"]);
        assert!(cli.command.is_none());
    }

    #[test]
    fn cli_parses_import_with_type_and_file() {
        let cli = Cli::parse_from([
            "tandera",
            "import",
            "--type",
            "nmap",
            "--file",
            "/tmp/scan.xml",
        ]);
        match cli.command {
            Some(Commands::Import { scan_type, file }) => {
                assert_eq!(scan_type.as_deref(), Some("nmap"));
                assert_eq!(file, Some(std::path::PathBuf::from("/tmp/scan.xml")));
            }
            _ => panic!("expected Import"),
        }
    }

    #[test]
    fn cli_parses_import_with_no_flags() {
        let cli = Cli::parse_from(["tandera", "import"]);
        match cli.command {
            Some(Commands::Import { scan_type, file }) => {
                assert!(scan_type.is_none());
                assert!(file.is_none());
            }
            _ => panic!("expected Import"),
        }
    }

    #[test]
    fn wants_shell_only_when_tty_and_no_subcommand() {
        assert!(wants_shell(true, false));
        assert!(!wants_shell(false, false));
        assert!(!wants_shell(true, true));
        assert!(!wants_shell(false, true));
    }

    #[test]
    fn api_url_flag_is_hidden() {
        // `--api-url` still parses, but is hidden from help.
        let cli = Cli::parse_from(["tandera", "--api-url", "http://x", "assessments", "list"]);
        assert_eq!(cli.api_url.as_deref(), Some("http://x"));
    }

    #[test]
    fn optional_auth_client_builds_and_reports_a_configured_token() {
        // The shell's client builder must SUCCEED (never the hard "no token
        // configured" error `build_client` raises) and, when a token is
        // present, report `authenticated == true`. A stored token makes
        // `effective_token()` `Some` regardless of any `TANDERA_TOKEN` in the
        // environment (env only overrides the value, never its presence), so
        // this positive case is deterministic without touching process env.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        Config {
            api_url: Some("https://api.example.com".to_string()),
            app_url: None,
            token: Some("tandera_pat_configuredtoken".to_string()),
            assessment: None,
            sync_testing_log: None,
        }
        .save_to(&path)
        .expect("save config");

        let (client, authenticated) =
            build_client_optional_auth(&path, None).expect("client should build");
        assert!(authenticated, "a stored token means authenticated");
        assert_eq!(client.base_url(), "https://api.example.com");
    }
}
