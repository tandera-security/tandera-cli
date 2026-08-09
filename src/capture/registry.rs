//! CLI-side tool registry: which tools tandera can wrap, the output flag to
//! inject, the import scan_type, and where the target argument sits (for the
//! scope gate + testing log). Mirrors the import parser catalog; grows as
//! parsers are covered.

pub struct ToolSpec {
    pub name: &'static str,
    pub scan_type: &'static str,
    pub ext: &'static str,
    /// Flags that write output to `path`.
    pub out_flags: fn(path: &str) -> Vec<String>,
    /// True if the argv already carries an output flag (skip injection).
    pub has_output_flag: fn(argv: &[String]) -> bool,
    /// Extract the scan target (host/url) from argv, if determinable.
    pub extract_target: fn(argv: &[String]) -> Option<String>,
}

fn last_positional(argv: &[String]) -> Option<String> {
    argv.iter()
        .skip(1)
        .rev()
        .find(|a| !a.starts_with('-'))
        .cloned()
}

fn value_after(argv: &[String], flag: &str) -> Option<String> {
    argv.iter()
        .position(|a| a == flag)
        .and_then(|i| argv.get(i + 1))
        .cloned()
}

static TOOLS: &[ToolSpec] = &[
    ToolSpec {
        name: "nmap",
        scan_type: "nmap",
        ext: "xml",
        out_flags: |p| vec!["-oX".into(), p.into()],
        has_output_flag: |a| {
            a.iter()
                .any(|x| x == "-oX" || x == "-oA" || x == "-oG" || x == "-oN")
        },
        extract_target: last_positional,
    },
    ToolSpec {
        name: "nuclei",
        scan_type: "nuclei",
        ext: "jsonl",
        out_flags: |p| vec!["-jsonl".into(), "-o".into(), p.into()],
        has_output_flag: |a| a.iter().any(|x| x == "-o" || x == "-output"),
        extract_target: |a| value_after(a, "-u").or_else(|| value_after(a, "-target")),
    },
    ToolSpec {
        name: "httpx",
        scan_type: "httpx",
        ext: "jsonl",
        out_flags: |p| vec!["-json".into(), "-o".into(), p.into()],
        has_output_flag: |a| a.iter().any(|x| x == "-o" || x == "-output"),
        extract_target: |a| value_after(a, "-u").or_else(|| value_after(a, "-target")),
    },
    ToolSpec {
        name: "nikto",
        scan_type: "nikto",
        ext: "xml",
        out_flags: |p| vec!["-o".into(), p.into(), "-Format".into(), "xml".into()],
        has_output_flag: |a| a.iter().any(|x| x == "-o" || x == "-output"),
        extract_target: |a| value_after(a, "-h").or_else(|| value_after(a, "-host")),
    },
];

pub fn lookup(tool: &str) -> Option<&'static ToolSpec> {
    TOOLS.iter().find(|t| t.name == tool)
}

pub fn is_known_tool(tool: &str) -> bool {
    lookup(tool).is_some()
}

/// NOTE: this extracts exactly ONE representative target (e.g. nmap's
/// trailing positional) — a multi-host/CIDR invocation is only ever gated
/// by that one host, so this is an advisory heuristic, not a guarantee that
/// every target in the invocation was scope-checked.
pub fn extract_target(spec: &ToolSpec, argv: &[String]) -> Option<String> {
    (spec.extract_target)(argv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_tools_present() {
        assert!(is_known_tool("httpx"));
        assert!(is_known_tool("nmap"));
        assert!(is_known_tool("nuclei"));
        assert!(!is_known_tool("ls"));
    }

    #[test]
    fn httpx_target_is_the_u_value() {
        let spec = lookup("httpx").unwrap();
        let argv: Vec<String> = ["httpx", "-u", "t.com"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(extract_target(spec, &argv).as_deref(), Some("t.com"));
    }

    #[test]
    fn nmap_target_is_the_trailing_positional() {
        let spec = lookup("nmap").unwrap();
        let argv: Vec<String> = ["nmap", "-p-", "10.0.0.5"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(extract_target(spec, &argv).as_deref(), Some("10.0.0.5"));
    }

    #[test]
    fn detects_existing_output_flag() {
        let spec = lookup("nmap").unwrap();
        let argv: Vec<String> = ["nmap", "-oX", "out.xml", "10.0.0.5"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!((spec.has_output_flag)(&argv));
    }
}
