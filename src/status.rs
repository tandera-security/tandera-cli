//! The status banner (`● tandera · acme-web · window: OPEN · credits: 320`)
//! and the cached snapshot behind it. Fetches are done off the prompt path
//! (§2.1) by the REPL; this module only formats and holds the snapshot.

use crate::models::{Credits, TestingStatus};

#[derive(Debug, Clone, Default)]
pub struct StatusSnapshot {
    pub window_open: Option<bool>,
    pub window_msg: Option<String>,
    pub credits: Option<i32>,
    pub credits_low: bool,
}

impl StatusSnapshot {
    pub fn apply_status(&mut self, s: &TestingStatus) {
        self.window_open = Some(s.is_testing_allowed);
        self.window_msg = if s.is_testing_allowed || s.message.is_empty() {
            None
        } else {
            Some(s.message.clone())
        };
    }
    pub fn apply_credits(&mut self, c: &Credits) {
        self.credits = Some(c.total);
        self.credits_low = c.low;
    }
}

pub fn format_banner(assessment: &str, auto_upload: bool, snap: &StatusSnapshot) -> String {
    let dot = if auto_upload { '●' } else { '○' };
    let window = match (snap.window_open, &snap.window_msg) {
        (Some(true), _) => "OPEN".to_string(),
        (Some(false), Some(m)) => format!("CLOSED — {m}"),
        (Some(false), None) => "CLOSED".to_string(),
        (None, _) => "…".to_string(),
    };
    let credits = match snap.credits {
        Some(c) if snap.credits_low => format!("{c} (low)"),
        Some(c) => c.to_string(),
        None => "…".to_string(),
    };
    format!("{dot} tandera  ·  {assessment}  ·  window: {window}  ·  credits: {credits}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_shows_assessment_window_credits() {
        let snap = StatusSnapshot {
            window_open: Some(true),
            window_msg: None,
            credits: Some(320),
            credits_low: false,
        };
        let b = format_banner("acme-web", true, &snap);
        assert!(b.contains("tandera"));
        assert!(b.contains("acme-web"));
        assert!(b.contains("OPEN"));
        assert!(b.contains("320"));
    }

    #[test]
    fn banner_shows_closed_with_message() {
        let snap = StatusSnapshot {
            window_open: Some(false),
            window_msg: Some("blackout date".into()),
            credits: None,
            credits_low: false,
        };
        let b = format_banner("acme-web", false, &snap);
        assert!(b.contains("CLOSED"));
        assert!(b.contains("blackout date"));
    }

    #[test]
    fn banner_pending_when_unknown() {
        let snap = StatusSnapshot {
            window_open: None,
            window_msg: None,
            credits: None,
            credits_low: false,
        };
        let b = format_banner("acme-web", false, &snap);
        assert!(b.contains('…'));
    }
}
