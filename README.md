# tandera

The `tandera` command-line client for the Tandera security platform API.

## Standalone project

This is a self-contained Rust project. It depends on nothing else in the
Tandera codebase — no shared crates, no path dependencies. Its only
integration point with the rest of the product is the Tandera HTTP API,
authenticated with a personal access token, which it talks to exactly like
any external client would.

Build and test it:

```bash
cargo build
cargo test
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
```

## Install / run

```bash
cargo build --release
./target/release/tandera --help
```

## Authentication

`tandera` authenticates with a Tandera **personal access token (PAT)**
(`tandera_pat_...`), minted via `POST /v1/cli/tokens` on the API (or the
console UI, once that surface exists).

```bash
tandera auth login --token tandera_pat_...
# or, to be prompted / read from stdin:
tandera auth login

tandera auth status
tandera auth logout
```

The token is verified against the API (`GET /v1/assessments`) before it is
ever stored — an invalid token is never written to disk.

### Config file

Config lives at your platform's config directory, e.g.
`~/.config/tandera/config.toml` on Linux, or
`~/Library/Application Support/tandera/config.toml` on macOS
(`dirs::config_dir()`), and holds:

```toml
api_url = "https://api.tandera.io"
token = "tandera_pat_..."
```

The file is written with `0600` permissions (owner read/write only) on unix,
since it holds a credential. The full token is **never** printed anywhere by
this tool (not in `auth status`, not in errors, not in verbose output) — only
its first ~20 characters (`tandera_pat_` + a few), followed by `…`.

### Environment overrides

`TANDERA_API_URL` and `TANDERA_TOKEN` take precedence over the config file
(useful in CI, where you don't want to write a config file to disk).

## Commands

```bash
tandera assessments list [--json]

tandera findings list --assessment <assessment_id> [--json]

tandera findings ai-draft \
  --assessment <assessment_id> \
  --category <category> \
  --severity <severity> \
  [--cwe <n>]... \
  [--cvss-vector <vector>] \
  [--asset-id <uuid>] \
  [--note <text>] \
  [--language <lang>] \
  [--artifact <kind>=<content>]...

tandera findings ai-rewrite \
  --assessment <assessment_id> \
  --finding <finding_id> \
  --field <field_name>... \
  [--instructions <text>] \
  [--language <lang>] \
  [--artifact <kind>=<content>]...
```

`--category`/`--severity` must be one of the API's validated enum values
(see `tandera findings ai-draft --help`); `--artifact` takes a
`kind=content` pair where `kind` is one of `http_request`, `http_response`,
`log`, `scanner_output` (bare `content` with no `kind=` prefix defaults to
`log`).

A `402` response from `ai-draft`/`ai-rewrite` means your org lacks the
`AiAuthoring` plan entitlement — the CLI surfaces that message verbatim.

Global flags: `--api-url <url>` (overrides config/env for one invocation),
`--json` (print raw API JSON instead of a table).
