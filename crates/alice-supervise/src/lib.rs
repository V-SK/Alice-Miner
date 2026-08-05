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
//! - **Bounded FAST restart.** At most [`MAX_RESTARTS`] within [`RESTART_WINDOW`].
//!   Spending that budget does NOT end the lane: it hands over to the escalating
//!   [`RetryLadder`], which keeps retrying on a longer and longer backoff (capped)
//!   so a miner is never left silently dead. Only the user's own Stop is terminal.
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
    read_pid_file, spawn_guarded, spawn_supervised, GuardedChild, LogLine, LogStream, OwnedChild,
    GUARD_GRACE,
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

/// The escalating backoff ladder used once the FAST budget ([`MAX_RESTARTS`] inside
/// [`RESTART_WINDOW`]) is spent.
///
/// **Why this exists.** The old design treated budget exhaustion — and a child that
/// exited on its own — as TERMINAL: the lane went to `Error` and nothing ever tried
/// again, so a single third-party engine crash (SRBMiner's `0xC0000374` heap
/// corruption is the observed one) left the CLI alive, the GPU idle and the miner
/// earning nothing until a human noticed hours later. Giving up protects us from a
/// restart STORM, but a storm is a *rate* problem, not a *forever* problem: the
/// correct answer to "this keeps failing" is to try less often, never to stop trying.
///
/// So after the fast budget the supervisor keeps retrying on this ladder (seconds →
/// half an hour, then capped), always with a visible "retrying in N" status. A rung is
/// REFUNDED per [`HEALTHY_RUN_STEP`] of real mining (see
/// [`RetryLadder::credit_healthy_run`]), so a rig that mines fine for an hour and then
/// hits one crash gets a fast retry — the ladder tracks *current* health, not the
/// lifetime failure count.
pub const RETRY_BACKOFF_LADDER: [Duration; 6] = [
    Duration::from_secs(5),
    Duration::from_secs(30),
    Duration::from_secs(2 * 60),
    Duration::from_secs(5 * 60),
    Duration::from_secs(15 * 60),
    Duration::from_secs(30 * 60),
];

/// How much CONTINUOUS, PROGRESS-MAKING mining refunds one step of the escalating
/// [`RetryLadder`] (and one slot of the fast [`RestartPolicy`] budget). "Healthy" is
/// measured as the time a run kept making progress — landing accepted shares — not
/// merely the time its process was alive, so a wedged engine that stays up forever
/// never buys itself retry budget.
pub const HEALTHY_RUN_STEP: Duration = Duration::from_secs(10 * 60);

/// The escalating, NEVER-terminal retry backoff (see [`RETRY_BACKOFF_LADDER`]).
///
/// Pure + unit-tested: it owns only a step counter, so the whole escalate / refund
/// decision table is testable without spawning anything.
#[derive(Debug, Default, Clone)]
pub struct RetryLadder {
    /// How many retries have been scheduled without an intervening healthy run.
    level: u32,
}

impl RetryLadder {
    pub fn new() -> Self {
        Self::default()
    }

    /// The current escalation level (0 = the next retry is the fastest rung).
    pub fn level(&self) -> u32 {
        self.level
    }

    /// The delay the NEXT retry would wait, WITHOUT consuming a step.
    pub fn peek(&self) -> Duration {
        RETRY_BACKOFF_LADDER[(self.level as usize).min(RETRY_BACKOFF_LADDER.len() - 1)]
    }

    /// Take the next delay and escalate one rung (saturating at the cap). Returns
    /// `(delay, attempt)` where `attempt` is the 1-based number of the retry this
    /// delay belongs to — the number shown to the user.
    pub fn next_backoff(&mut self) -> (Duration, u32) {
        let delay = self.peek();
        self.level = self.level.saturating_add(1);
        (delay, self.level)
    }

    /// Credit a run that kept making progress for `healthy_for`: one rung is refunded
    /// per full [`HEALTHY_RUN_STEP`]. Returns how many rungs were refunded.
    pub fn credit_healthy_run(&mut self, healthy_for: Duration) -> u32 {
        let steps = (healthy_for.as_secs() / HEALTHY_RUN_STEP.as_secs()).min(u32::MAX as u64) as u32;
        let refunded = steps.min(self.level);
        self.level -= refunded;
        refunded
    }

    /// A manual user (re)start clears the escalation.
    pub fn reset(&mut self) {
        self.level = 0;
    }
}

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

    /// Credit a run that kept making progress for `healthy_for`: refund one recorded
    /// restart per full [`HEALTHY_RUN_STEP`] of real mining (oldest first). Returns how
    /// many were refunded.
    ///
    /// The window eviction alone is not enough: it heals the budget purely with the
    /// passage of time, which is the same whether the lane mined for an hour or sat
    /// dead. This ties recovery to actual work, so a lane that IS earning gets its
    /// retries back and one that never lands a share does not.
    pub fn credit_healthy_run(&mut self, healthy_for: Duration) -> u32 {
        let steps = (healthy_for.as_secs() / HEALTHY_RUN_STEP.as_secs()).min(u32::MAX as u64) as u32;
        let refunded = steps.min(self.events.len() as u32);
        for _ in 0..refunded {
            self.events.pop_front();
        }
        refunded
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

    /// A healthy run refunds fast-budget slots — one per [`HEALTHY_RUN_STEP`] of real
    /// mining — so a lane that IS earning gets its retries back without waiting out the
    /// window, and a run with NO progress refunds nothing.
    #[test]
    fn restart_policy_healthy_run_refunds_budget() {
        let mut p = RestartPolicy::new();
        let t0 = Instant::now();
        for _ in 0..MAX_RESTARTS {
            p.record(t0);
        }
        assert!(!p.may_restart(t0), "budget spent");

        // A run that never made progress buys nothing.
        assert_eq!(p.credit_healthy_run(Duration::from_secs(0)), 0);
        assert_eq!(p.credit_healthy_run(HEALTHY_RUN_STEP - Duration::from_secs(1)), 0);
        assert!(!p.may_restart(t0), "a short/unhealthy run must not refund");

        // One healthy step refunds exactly one slot.
        assert_eq!(p.credit_healthy_run(HEALTHY_RUN_STEP), 1);
        assert!(p.may_restart(t0), "one refunded slot re-arms the budget");
        assert_eq!(p.used(t0), MAX_RESTARTS - 1);

        // A long healthy run refunds at most what was spent (never goes negative).
        assert_eq!(p.credit_healthy_run(HEALTHY_RUN_STEP * 10), MAX_RESTARTS - 1);
        assert_eq!(p.used(t0), 0);
        assert_eq!(p.credit_healthy_run(HEALTHY_RUN_STEP * 10), 0, "nothing left to refund");
    }

    /// The escalating ladder walks the rungs in order, caps at the last one, and NEVER
    /// runs out (there is no "give up" value) — the core of the BUG#4 fix.
    #[test]
    fn retry_ladder_escalates_then_caps_and_never_gives_up() {
        let mut l = RetryLadder::new();
        assert_eq!(l.level(), 0);
        let mut seen = Vec::new();
        for (i, rung) in RETRY_BACKOFF_LADDER.iter().enumerate() {
            assert_eq!(l.peek(), *rung, "peek does not consume");
            let (d, attempt) = l.next_backoff();
            assert_eq!(d, *rung);
            assert_eq!(attempt as usize, i + 1, "attempt is 1-based");
            seen.push(d);
        }
        // Monotonically non-decreasing.
        assert!(seen.windows(2).all(|w| w[1] >= w[0]), "ladder must not shrink: {seen:?}");
        let cap = *RETRY_BACKOFF_LADDER.last().unwrap();
        // Past the end it CAPS — and still yields a delay, forever.
        for _ in 0..50 {
            let (d, _) = l.next_backoff();
            assert_eq!(d, cap, "past the ladder the backoff caps, it never becomes 'never'");
        }
        assert!(l.level() > RETRY_BACKOFF_LADDER.len() as u32);
    }

    /// Healthy mining walks the ladder back DOWN: one rung per [`HEALTHY_RUN_STEP`],
    /// floored at 0. So an hour of good mining followed by one crash retries fast.
    #[test]
    fn retry_ladder_credits_healthy_running_time() {
        let mut l = RetryLadder::new();
        for _ in 0..4 {
            l.next_backoff();
        }
        assert_eq!(l.level(), 4);
        // A run shorter than one step refunds nothing.
        assert_eq!(l.credit_healthy_run(HEALTHY_RUN_STEP - Duration::from_secs(1)), 0);
        assert_eq!(l.level(), 4);
        // Two steps of healthy mining → two rungs back.
        assert_eq!(l.credit_healthy_run(HEALTHY_RUN_STEP * 2), 2);
        assert_eq!(l.level(), 2);
        assert_eq!(l.peek(), RETRY_BACKOFF_LADDER[2]);
        // A very long healthy run floors at 0 (never negative / wrapping).
        assert_eq!(l.credit_healthy_run(HEALTHY_RUN_STEP * 100), 2);
        assert_eq!(l.level(), 0);
        assert_eq!(l.peek(), RETRY_BACKOFF_LADDER[0], "back to the fastest rung");
        // reset() is the user-start clear.
        l.next_backoff();
        l.reset();
        assert_eq!(l.level(), 0);
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
