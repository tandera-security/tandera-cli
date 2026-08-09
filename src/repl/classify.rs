//! Pure classification of a REPL input line. The first character decides the
//! top-level split: `:` → tandera meta-command; otherwise a shell/tool line,
//! sub-split into a wrappable known-tool invocation vs raw passthrough.

#[derive(Debug, PartialEq, Eq)]
pub enum Line {
    Meta { verb: String, rest: String },
    KnownTool { tool: String, argv: Vec<String> },
    Passthrough(String),
}

const METACHARS: &[&str] = &["|", ">", "<", "&", ";", "`", "$(", "&&", "||"];

pub fn has_shell_metachar(s: &str) -> bool {
    if s.contains('\n') {
        return true;
    }
    METACHARS.iter().any(|m| s.contains(m))
}

/// Classify a line. `is_known_tool` decides whether a bare first token is a
/// wrappable recon/GUI tool. Returns `None` for blank input.
pub fn classify(input: &str, is_known_tool: impl Fn(&str) -> bool) -> Option<Line> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix(':') {
        let rest = rest.trim_start();
        let (verb, args) = match rest.split_once(char::is_whitespace) {
            Some((v, a)) => (v.to_string(), a.trim().to_string()),
            None => (rest.to_string(), String::new()),
        };
        return Some(Line::Meta { verb, rest: args });
    }
    if !has_shell_metachar(trimmed) {
        if let Some(argv) = shlex::split(trimmed) {
            if let Some(first) = argv.first() {
                if is_known_tool(first) {
                    return Some(Line::KnownTool {
                        tool: first.clone(),
                        argv,
                    });
                }
            }
        }
    }
    Some(Line::Passthrough(trimmed.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known(t: &str) -> bool {
        matches!(t, "httpx" | "nmap" | "burp")
    }

    #[test]
    fn colon_prefix_is_meta() {
        match classify(":finding SQLi in http://x", known).unwrap() {
            Line::Meta { verb, rest } => {
                assert_eq!(verb, "finding");
                assert_eq!(rest, "SQLi in http://x");
            }
            _ => panic!("expected meta"),
        }
    }

    #[test]
    fn known_tool_without_metachars_is_wrapped() {
        match classify("httpx -u t.com", known).unwrap() {
            Line::KnownTool { tool, argv } => {
                assert_eq!(tool, "httpx");
                assert_eq!(argv, vec!["httpx", "-u", "t.com"]);
            }
            _ => panic!("expected known tool"),
        }
    }

    #[test]
    fn known_tool_with_pipe_is_passthrough() {
        match classify("cat h.txt | httpx | tee out", known).unwrap() {
            Line::Passthrough(l) => assert_eq!(l, "cat h.txt | httpx | tee out"),
            _ => panic!("expected passthrough"),
        }
    }

    #[test]
    fn unknown_tool_is_passthrough() {
        assert!(matches!(
            classify("ls -la", known).unwrap(),
            Line::Passthrough(_)
        ));
    }

    #[test]
    fn blank_is_none() {
        assert!(classify("   ", known).is_none());
    }

    #[test]
    fn metachar_detection() {
        assert!(has_shell_metachar("a | b"));
        assert!(has_shell_metachar("a > b"));
        assert!(has_shell_metachar("a && b"));
        assert!(!has_shell_metachar("nmap -p- 10.0.0.5"));
    }
}
