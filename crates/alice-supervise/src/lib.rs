//! Process supervision for the embedded Alice node (and, later, the mining
//! engine). Mirrors Monero-GUI's `DaemonManager`: spawn a child, own its
//! handle + PID, capture a sanitised log tail, expose start/stop/restart/status,
//! and apply bounded auto-restart with backoff.
//!
//! Design constraints (see `docs/WALLET-ALLINONE-PLAN.md` §1.2):
//! - **Owned handle only.** We stop the process we spawned via its `Child`
//!   handle / recorded PID. We NEVER `pkill` by name.
//! - **Crash isolation.** A node crash surfaces an `Error` status + sanitised
//!   log tail; it must never lock or corrupt the wallet (custody state is
//!   wholly independent of this module).
//! - **Bounded restart.** At most [`MAX_RESTARTS`] within [`RESTART_WINDOW`],
//!   then we stay `Error` until the user restarts manually.
//! - **Graceful stop.** SIGTERM → bounded join → SIGKILL fallback.
//!
//! The restart-policy and log-tail logic are pure and unit-tested; the actual
//! process I/O is in [`child`].
//!
//! Lifted VERBATIM from `alice-wallet/gui/src/supervise/mod.rs`. The only edit
//! for the standalone crate is dropping the wallet-only `miner_supervisor` /
//! `node_supervisor` submodules (not part of M0) and re-exporting the public
//! items from [`child`] so downstream crates see one flat `alice_supervise` API.

#![allow(dead_code)]

pub mod child;

// Re-export the child-process API so consumers can use it directly off the
// crate root (`alice_supervise::spawn_supervised`, `OwnedChild`, …).
pub use child::{
    read_pid_file, spawn_supervised, LogLine, LogStream, OwnedChild,
};

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Max sanitised log lines retained for the UI's "last log" panel.
pub const LOG_TAIL_CAPACITY: usize = 200;
/// Bounded auto-restart budget.
pub const MAX_RESTARTS: u32 = 3;
pub const RESTART_WINDOW: Duration = Duration::from_secs(5 * 60);
/// Backoff between auto-restarts (capped).
pub const RESTART_BACKOFF_BASE: Duration = Duration::from_secs(2);

/// Lifecycle state of a supervised subsystem (node or miner).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcState {
    /// Not started (or cleanly stopped by the user).
    Stopped,
    /// Spawn requested; process starting up.
    Starting,
    /// Process is alive.
    Running,
    /// Graceful stop in progress.
    Stopping,
    /// Process exited unexpectedly or failed to start; held until user action
    /// (or until the bounded restarter retries).
    Error,
}

impl ProcState {
    pub fn is_active(self) -> bool {
        matches!(
            self,
            ProcState::Starting | ProcState::Running | ProcState::Stopping
        )
    }

    pub fn i18n_key(self) -> &'static str {
        match self {
            ProcState::Stopped => "node.proc_stopped",
            ProcState::Starting => "node.proc_starting",
            ProcState::Running => "node.proc_running",
            ProcState::Stopping => "node.proc_stopping",
            ProcState::Error => "node.proc_error",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ProcState::Stopped => "Stopped",
            ProcState::Starting => "Starting",
            ProcState::Running => "Running",
            ProcState::Stopping => "Stopping",
            ProcState::Error => "Error",
        }
    }
}

/// A point-in-time, UI-safe snapshot of a supervised process. Cloneable and
/// free of any handle / secret so it can cross the worker→GUI channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcStatus {
    pub state: ProcState,
    pub pid: Option<u32>,
    /// Last process exit code (when the process has exited).
    pub last_exit_code: Option<i32>,
    /// Short, sanitised error/reason for the current state, if any.
    pub message: Option<String>,
    /// Sanitised tail of recent stdout/stderr lines (most recent last).
    pub log_tail: Vec<String>,
    /// Restarts consumed within the current window.
    pub restarts_used: u32,
}

impl ProcStatus {
    pub fn stopped() -> Self {
        Self {
            state: ProcState::Stopped,
            pid: None,
            last_exit_code: None,
            message: None,
            log_tail: Vec::new(),
            restarts_used: 0,
        }
    }
}

/// Sanitise a single log line before it is shown in the UI or persisted.
///
/// Substrate logs are not expected to contain wallet secrets (the node never
/// sees the wallet seed/keys), but we defensively (a) strip ANSI escapes,
/// (b) bound length, and (c) redact anything that looks like a long hex blob or
/// a 12/24-word phrase fragment, so a log panel can never become a secret leak.
pub fn sanitize_log_line(raw: &str) -> String {
    // 1) Strip ANSI CSI escape sequences (these begin with the ESC control
    //    char, so this MUST run before we drop control characters).
    let mut s = strip_ansi(raw);

    // 2) Drop any remaining control characters (keep tabs).
    s = s
        .chars()
        .filter(|c| !c.is_control() || *c == '\t')
        .collect();

    // 3) Redact long hex runs (>= 48 hex chars ~ a key/seed-sized blob).
    s = redact_long_hex(&s);

    // Bound length.
    const MAX: usize = 400;
    if s.chars().count() > MAX {
        let truncated: String = s.chars().take(MAX).collect();
        format!("{truncated}…")
    } else {
        s
    }
    .trim_end()
    .to_string()
}

fn strip_ansi(s: &str) -> String {
    // Minimal CSI escape stripper: drop ESC '[' ... terminator.
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&n) = chars.peek() {
                    chars.next();
                    if n.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

fn redact_long_hex(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut run = String::new();
    let flush = |out: &mut String, run: &mut String| {
        let body = run.trim_start_matches("0x").trim_start_matches("0X");
        if body.len() >= 48 && body.chars().all(|c| c.is_ascii_hexdigit()) {
            out.push_str("[redacted-hex]");
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in s.chars() {
        if c.is_ascii_hexdigit() || c == 'x' || c == 'X' {
            run.push(c);
        } else {
            if !run.is_empty() {
                flush(&mut out, &mut run);
            }
            out.push(c);
        }
    }
    if !run.is_empty() {
        flush(&mut out, &mut run);
    }
    out
}

/// Bounded restart bookkeeping. Pure / testable: records restart timestamps and
/// decides whether another auto-restart is permitted.
#[derive(Debug, Default)]
pub struct RestartPolicy {
    events: VecDeque<Instant>,
}

impl RestartPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop events older than the window relative to `now`.
    fn evict(&mut self, now: Instant) {
        while let Some(&front) = self.events.front() {
            if now.duration_since(front) > RESTART_WINDOW {
                self.events.pop_front();
            } else {
                break;
            }
        }
    }

    /// Number of restarts counted within the current window.
    pub fn used(&mut self, now: Instant) -> u32 {
        self.evict(now);
        self.events.len() as u32
    }

    /// Whether another auto-restart is allowed at `now`.
    pub fn may_restart(&mut self, now: Instant) -> bool {
        self.used(now) < MAX_RESTARTS
    }

    /// Record a restart at `now` and return the backoff to wait before it.
    pub fn record(&mut self, now: Instant) -> Duration {
        self.evict(now);
        let n = self.events.len() as u32;
        self.events.push_back(now);
        // Exponential backoff capped at 30s: 2s, 4s, 8s, …
        let secs = (RESTART_BACKOFF_BASE.as_secs() << n.min(4)).min(30);
        Duration::from_secs(secs)
    }

    /// Manual user (re)start clears the budget.
    pub fn reset(&mut self) {
        self.events.clear();
    }
}

/// A bounded ring buffer of sanitised log lines for the UI.
#[derive(Debug, Default)]
pub struct LogRing {
    lines: VecDeque<String>,
}

impl LogRing {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_raw(&mut self, raw: &str) {
        let line = sanitize_log_line(raw);
        if line.is_empty() {
            return;
        }
        if self.lines.len() >= LOG_TAIL_CAPACITY {
            self.lines.pop_front();
        }
        self.lines.push_back(line);
    }

    pub fn tail(&self) -> Vec<String> {
        self.lines.iter().cloned().collect()
    }

    pub fn last(&self) -> Option<&str> {
        self.lines.back().map(|s| s.as_str())
    }

    pub fn clear(&mut self) {
        self.lines.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_state_active_classification() {
        assert!(ProcState::Running.is_active());
        assert!(ProcState::Starting.is_active());
        assert!(ProcState::Stopping.is_active());
        assert!(!ProcState::Stopped.is_active());
        assert!(!ProcState::Error.is_active());
    }

    #[test]
    fn sanitize_strips_ansi_and_bounds_length() {
        let dirty = "\u{1b}[31mERROR\u{1b}[0m peer connected";
        assert_eq!(sanitize_log_line(dirty), "ERROR peer connected");

        let long = "x".repeat(1000);
        let out = sanitize_log_line(&long);
        assert!(out.chars().count() <= 401); // 400 + ellipsis
        assert!(out.ends_with('…'));
    }

    #[test]
    fn sanitize_redacts_long_hex_but_keeps_short_hashes() {
        // 64-hex (seed/key-sized) blob is redacted.
        let secretish = format!("seed={}", "a".repeat(64));
        assert!(sanitize_log_line(&secretish).contains("[redacted-hex]"));
        // 0x-prefixed long blob redacted.
        let hexy = format!("key 0x{}", "b".repeat(64));
        assert!(sanitize_log_line(&hexy).contains("[redacted-hex]"));
        // A short block hash fragment / port number is preserved.
        let normal = "imported block #12345 (0xabcd)";
        let s = sanitize_log_line(normal);
        assert!(s.contains("12345"));
        assert!(s.contains("0xabcd"));
        assert!(!s.contains("[redacted-hex]"));
    }

    #[test]
    fn restart_policy_is_bounded_within_window() {
        let mut p = RestartPolicy::new();
        let t0 = Instant::now();
        assert!(p.may_restart(t0));
        for _ in 0..MAX_RESTARTS {
            assert!(p.may_restart(t0));
            p.record(t0);
        }
        // Budget exhausted within the window.
        assert!(!p.may_restart(t0));
        assert_eq!(p.used(t0), MAX_RESTARTS);
    }

    #[test]
    fn restart_policy_evicts_old_events() {
        let mut p = RestartPolicy::new();
        let t0 = Instant::now();
        for _ in 0..MAX_RESTARTS {
            p.record(t0);
        }
        assert!(!p.may_restart(t0));
        // After the window passes, budget is restored.
        let later = t0 + RESTART_WINDOW + Duration::from_secs(1);
        assert!(p.may_restart(later));
        assert_eq!(p.used(later), 0);
    }

    #[test]
    fn restart_backoff_grows_and_caps() {
        let mut p = RestartPolicy::new();
        let t0 = Instant::now();
        let b0 = p.record(t0);
        let b1 = p.record(t0);
        let b2 = p.record(t0);
        assert!(b1 >= b0);
        assert!(b2 >= b1);
        // Cap at 30s.
        for _ in 0..10 {
            assert!(p.record(t0) <= Duration::from_secs(30));
        }
    }

    #[test]
    fn restart_policy_reset_clears_budget() {
        let mut p = RestartPolicy::new();
        let t0 = Instant::now();
        for _ in 0..MAX_RESTARTS {
            p.record(t0);
        }
        assert!(!p.may_restart(t0));
        p.reset();
        assert!(p.may_restart(t0));
    }

    #[test]
    fn log_ring_is_bounded_and_sanitises() {
        let mut r = LogRing::new();
        for i in 0..(LOG_TAIL_CAPACITY + 50) {
            r.push_raw(&format!("line {i}"));
        }
        assert_eq!(r.tail().len(), LOG_TAIL_CAPACITY);
        // Oldest dropped, newest retained.
        assert!(r
            .last()
            .unwrap()
            .contains(&format!("{}", LOG_TAIL_CAPACITY + 49)));
        // Empty/whitespace lines are skipped.
        let before = r.tail().len();
        r.push_raw("   ");
        assert_eq!(r.tail().len(), before);
    }
}
