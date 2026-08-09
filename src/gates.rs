//! Advisory gates: is the target in scope, and is the testing window open.
//! Matching is pure and unit-tested; fetches wrap the existing endpoints.

use std::net::IpAddr;
use std::str::FromStr;

use ipnetwork::IpNetwork;
use uuid::Uuid;

use crate::api::{ApiClient, ApiError};
use crate::models::{Credits, Scope, ScopeListResponse, TestingStatus};

/// Reduce a target argument to a bare, lowercased host for scope matching.
/// Handles `scheme://user:pass@host:port/path?query#frag`, bracketed IPv6
/// (`[::1]:8080`), and bare hosts. Only strips a trailing `:port` when it is
/// genuinely a numeric port, so bare IPv6 literals (many colons) survive.
fn host_of(target: &str) -> String {
    let t = target.trim();
    // 1. Strip the scheme: everything after the FIRST "://".
    let t = match t.find("://") {
        Some(i) => &t[i + 3..],
        None => t,
    };
    // 2. Strip path / query / fragment.
    let t = t.split(['/', '\\', '?', '#']).next().unwrap_or(t);
    // 3. Strip userinfo: authority is `[user[:pass]@]host[:port]`.
    let t = match t.rsplit_once('@') {
        Some((_, host)) => host,
        None => t,
    };
    // 4. Host + optional port. Bracketed IPv6 first, then host:port only when
    //    the port is numeric; bare IPv6 (many colons) is left untouched.
    let host = if let Some(rest) = t.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else if t.matches(':').count() == 1 {
        match t.rsplit_once(':') {
            Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
            _ => t,
        }
    } else {
        t
    };
    host.trim_matches('.').to_lowercase()
}

fn domain_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim_matches('.').to_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host == suffix || host.ends_with(&format!(".{suffix}"))
    } else {
        host == pattern
    }
}

/// Is `target` covered by any in-scope entry? IPs test CIDR/ip membership;
/// hostnames test domain/wildcard entries; URLs reduce to their host first.
pub fn scope_contains(scopes: &[Scope], target: &str) -> bool {
    let host = host_of(target);
    let as_ip = IpAddr::from_str(&host).ok();
    for sc in scopes {
        match sc.scope_type.as_str() {
            "cidr" => {
                if let (Some(ip), Ok(net)) = (as_ip, IpNetwork::from_str(&sc.value)) {
                    if net.contains(ip) {
                        return true;
                    }
                }
            }
            "ip" => {
                if host == sc.value.trim().to_lowercase() {
                    return true;
                }
            }
            "domain" | "subdomain" | "url" => {
                if domain_matches(&host_of(&sc.value), &host) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

pub fn fetch_testing_status(client: &ApiClient, aid: Uuid) -> Result<TestingStatus, ApiError> {
    client.get_json(&format!("/v1/assessments/{aid}/testing-status"))
}

pub fn fetch_credits(client: &ApiClient) -> Result<Credits, ApiError> {
    client.get_json("/v1/billing/credits")
}

pub fn fetch_scopes(client: &ApiClient, aid: Uuid) -> Result<Vec<Scope>, ApiError> {
    // Tolerate both `{"items":[…]}` and a bare array.
    let raw: serde_json::Value = client.get_json(&format!("/v1/assessments/{aid}/scopes"))?;
    if let Ok(list) = serde_json::from_value::<ScopeListResponse>(raw.clone()) {
        return Ok(list.items);
    }
    serde_json::from_value::<Vec<Scope>>(raw)
        .map_err(|e| ApiError::Transport(format!("failed to parse scopes: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Scope;

    fn s(t: &str, v: &str) -> Scope {
        Scope {
            scope_type: t.into(),
            value: v.into(),
        }
    }

    #[test]
    fn ip_in_cidr() {
        let scopes = vec![s("cidr", "203.0.113.0/24")];
        assert!(scope_contains(&scopes, "203.0.113.9"));
        assert!(!scope_contains(&scopes, "10.0.0.5"));
    }

    #[test]
    fn host_matches_exact_and_wildcard_domain() {
        let scopes = vec![s("domain", "acme.com"), s("domain", "*.acme.com")];
        assert!(scope_contains(&scopes, "acme.com"));
        assert!(scope_contains(&scopes, "api.acme.com"));
        assert!(!scope_contains(&scopes, "evil.com"));
    }

    #[test]
    fn url_is_reduced_to_host() {
        let scopes = vec![s("domain", "*.acme.com")];
        assert!(scope_contains(&scopes, "https://api.acme.com/login?x=1"));
    }

    #[test]
    fn exact_ip_scope() {
        assert!(scope_contains(&[s("ip", "10.0.0.5")], "10.0.0.5"));
    }

    #[test]
    fn host_of_uses_first_scheme_not_last() {
        // A second "://" embedded in a query must not hijack the host.
        assert!(!scope_contains(
            &[s("domain", "acme.com")],
            "http://evil.com/path?x=http://acme.com"
        ));
    }

    #[test]
    fn host_of_strips_userinfo() {
        // `user@host` — the real host is after the `@`.
        assert!(!scope_contains(
            &[s("domain", "acme.com")],
            "acme.com:x@evil.com"
        ));
    }

    #[test]
    fn ipv6_targets_match_ip_and_cidr_scopes() {
        assert!(scope_contains(&[s("ip", "2001:db8::1")], "2001:db8::1"));
        assert!(scope_contains(&[s("cidr", "2001:db8::/32")], "2001:db8::1"));
        assert!(scope_contains(&[s("ip", "::1")], "[::1]:8080"));
    }

    #[test]
    fn host_of_treats_backslash_as_authority_terminator() {
        // WHATWG/reqwest treat `\` like `/`; the real host is `evil.com`.
        assert!(!scope_contains(
            &[s("domain", "acme.com")],
            "http://evil.com\\@acme.com"
        ));
    }
}
