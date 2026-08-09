//! `$SHELL -c` delegation and the minimal builtins (`cd`, `export`,
//! `NAME=VALUE`) needed so a command-at-a-time dispatcher feels like a shell.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};

use anyhow::{Context, Result};

pub struct ShellEnv {
    pub cwd: PathBuf,
    pub vars: BTreeMap<String, String>,
}

impl Default for ShellEnv {
    fn default() -> Self {
        Self {
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            vars: BTreeMap::new(),
        }
    }
}

fn assignment(s: &str) -> Option<(String, String)> {
    let (k, v) = s.split_once('=')?;
    if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some((k.to_string(), v.trim_matches(['"', '\'']).to_string()))
}

/// Handle `cd`, `export`, and a bare leading `NAME=VALUE`. Returns `None`
/// when the line is not a builtin (caller should pass it to the shell).
pub fn try_builtin(line: &str, env: &mut ShellEnv) -> Option<Result<()>> {
    let line = line.trim();
    if let Some(arg) = line.strip_prefix("cd ").map(str::trim) {
        let target = if arg.is_empty() {
            dirs::home_dir().unwrap_or_else(|| env.cwd.clone())
        } else {
            let p = PathBuf::from(arg);
            if p.is_absolute() {
                p
            } else {
                env.cwd.join(p)
            }
        };
        return Some(
            std::fs::canonicalize(&target)
                .with_context(|| format!("cd: {}", target.display()))
                .map(|c| env.cwd = c),
        );
    }
    if let Some(rest) = line.strip_prefix("export ") {
        return match assignment(rest.trim()) {
            Some((k, v)) => {
                env.vars.insert(k, v);
                Some(Ok(()))
            }
            None => Some(Err(anyhow::anyhow!("export: expected NAME=VALUE"))),
        };
    }
    if !line.contains(char::is_whitespace) {
        if let Some((k, v)) = assignment(line) {
            env.vars.insert(k, v);
            return Some(Ok(()));
        }
    }
    None
}

fn shell() -> String {
    std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())
}

/// Run `line` via `$SHELL -c`, inheriting stdio + cwd + the REPL's env vars.
pub fn run_passthrough(line: &str, env: &ShellEnv) -> std::io::Result<ExitStatus> {
    Command::new(shell())
        .arg("-c")
        .arg(line)
        .current_dir(&env.cwd)
        .envs(&env.vars)
        .status()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cd_updates_cwd() {
        let mut env = ShellEnv::default();
        let tmp = std::env::temp_dir();
        let r = try_builtin(&format!("cd {}", tmp.display()), &mut env);
        assert!(r.is_some() && r.unwrap().is_ok());
        assert_eq!(env.cwd.canonicalize().unwrap(), tmp.canonicalize().unwrap());
    }

    #[test]
    fn export_sets_var() {
        let mut env = ShellEnv::default();
        try_builtin("export FOO=bar", &mut env).unwrap().unwrap();
        assert_eq!(env.vars.get("FOO").map(String::as_str), Some("bar"));
    }

    #[test]
    fn bare_assignment_sets_var() {
        let mut env = ShellEnv::default();
        try_builtin("TOKEN=abc", &mut env).unwrap().unwrap();
        assert_eq!(env.vars.get("TOKEN").map(String::as_str), Some("abc"));
    }

    #[test]
    fn non_builtin_returns_none() {
        let mut env = ShellEnv::default();
        assert!(try_builtin("nmap -p-", &mut env).is_none());
    }

    #[test]
    fn passthrough_runs_and_preserves_exit_code() {
        let env = ShellEnv::default();
        let status = run_passthrough("exit 3", &env).unwrap();
        assert_eq!(status.code(), Some(3));
    }
}
