//! The `start` ⇄ `stop` rendezvous: a tiny pid file under `~/.alice/` so a
//! separately-launched `alice-miner stop` can find a running `alice-miner start`
//! and tear it down **gracefully, with no orphan** (PLAN §5 M6).
//!
//! This is NOT a daemon and NOT IPC into the engine — each `start` owns its
//! engine in-process and already handles Ctrl-C/SIGTERM as a graceful
//! `Command::Stop` (SIGTERM→SIGKILL on the owned child via `kill_on_drop`). So
//! `stop` simply signals the recorded process:
//!   * **unix:** `SIGTERM` (the `start` process traps it via `ctrlc`'s
//!     `termination` feature → graceful `Command::Stop`), escalating to `SIGKILL`
//!     after a timeout if it hasn't exited. Killing the `start` process drops its
//!     engine + owned child (no orphan).
//!   * **windows:** a best-effort `taskkill /PID` (graceful), then `/F` (force).
//!
//! The pid file holds only this process's own pid (a public integer) — no secret.

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// The pid file path: `$ALICE_IDENTITY_DIR/miner-cli.pid` (tests) or
/// `~/.alice/miner-cli.pid`. Co-located with the identity pointer so it shares
/// the same per-user dir + override knob.
pub fn pid_path() -> PathBuf {
    dir().join("miner-cli.pid")
}

fn dir() -> PathBuf {
    // Reuse the engine's identity-dir resolution (honors `$ALICE_IDENTITY_DIR`,
    // else `~/.alice`) so the pid file sits beside `identity.json` with the SAME
    // override knob — no separate `dirs` dependency, no drift.
    alice_miner_core::identity::identity_path()
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".alice"))
}

/// Read the recorded pid, if the file exists + parses.
pub fn read_pid() -> Option<u32> {
    let s = fs::read_to_string(pid_path()).ok()?;
    s.trim().parse::<u32>().ok()
}

/// Remove the pid file (best-effort; a missing file is fine).
pub fn remove() {
    let _ = fs::remove_file(pid_path());
}

/// Write this process's pid into the pid file (best-effort). Creates the dir if
/// needed. A failure (e.g. read-only home) is non-fatal: mining proceeds; only
/// `stop` would be unable to find us (Ctrl-C still works).
fn write_self() -> bool {
    let path = pid_path();
    if let Some(parent) = path.parent() {
        if fs::create_dir_all(parent).is_err() {
            return false;
        }
    }
    fs::write(&path, std::process::id().to_string()).is_ok()
}

/// An RAII guard that records this process's pid on construction and removes the
/// pid file on drop — so a clean exit never leaves a stale pid. If another live
/// `start` already holds the pid file, we DON'T clobber it (so the original owner
/// keeps the rendezvous) — but we still run; `stop` would just target the first.
pub struct PidGuard {
    /// Whether THIS guard wrote the file (only then do we remove it on drop, so
    /// we never delete another live instance's pid).
    owns: bool,
}

impl PidGuard {
    /// Acquire the rendezvous: record our pid unless a *live* one is already
    /// recorded. Always returns a guard (mining proceeds regardless).
    pub fn acquire() -> Self {
        let existing_live = read_pid().map(is_alive).unwrap_or(false);
        let owns = if existing_live {
            // Respect an existing live owner; don't steal the rendezvous.
            false
        } else {
            // No file, or a stale pid → take ownership.
            write_self()
        };
        Self { owns }
    }
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        if self.owns {
            // Only remove if the file still names US (avoid racing a newer start).
            if read_pid() == Some(std::process::id()) {
                remove();
            }
        }
    }
}

/// Whether process `pid` is currently alive.
#[cfg(unix)]
pub fn is_alive(pid: u32) -> bool {
    // `kill(pid, 0)` performs error checking without sending a signal: Ok = alive
    // (or a zombie we can still signal), `ESRCH` = no such process.
    unsafe { libc_kill(pid as i32, 0) == 0 }
}

#[cfg(not(unix))]
pub fn is_alive(_pid: u32) -> bool {
    // On non-unix we can't cheaply probe; assume alive and let `stop`'s taskkill
    // report if it's already gone.
    true
}

/// The result of a `stop` request.
pub enum StopOutcome {
    /// The process exited after SIGTERM within the grace window.
    Graceful,
    /// The process did not exit in time and was SIGKILL'd (no orphan).
    Killed,
    /// We could not signal the process (e.g. not permitted).
    Error(String),
}

/// Gracefully stop process `pid`: SIGTERM, wait up to `timeout` for it to exit,
/// then SIGKILL if still alive (unix). On windows: `taskkill` then `taskkill /F`.
#[cfg(unix)]
pub fn stop_pid(pid: u32, timeout: Duration) -> StopOutcome {
    // 1) SIGTERM — the `start` process traps it → graceful Command::Stop.
    let rc = unsafe { libc_kill(pid as i32, SIGTERM) };
    if rc != 0 {
        // ESRCH (already gone) counts as success; anything else is an error.
        if !is_alive(pid) {
            return StopOutcome::Graceful;
        }
        return StopOutcome::Error(format!("failed to signal pid {pid} (rc={rc})"));
    }

    // 2) Poll for graceful exit.
    let start = Instant::now();
    while start.elapsed() < timeout {
        if !is_alive(pid) {
            return StopOutcome::Graceful;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // 3) Still alive → SIGKILL. The kernel reaps it; its engine + owned child die
    // with it (kill_on_drop), so no orphan is left.
    unsafe { libc_kill(pid as i32, SIGKILL) };
    // Give the kernel a moment to reap.
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(2) {
        if !is_alive(pid) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    StopOutcome::Killed
}

#[cfg(not(unix))]
pub fn stop_pid(pid: u32, timeout: Duration) -> StopOutcome {
    use std::process::Command;
    // Graceful close request.
    let _ = Command::new("taskkill").args(["/PID", &pid.to_string()]).output();
    let start = Instant::now();
    while start.elapsed() < timeout {
        // taskkill without /F may not stop a console app reliably; re-check by
        // attempting a no-op query.
        let alive = Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}")])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()))
            .unwrap_or(false);
        if !alive {
            return StopOutcome::Graceful;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    // Force.
    let out = Command::new("taskkill").args(["/F", "/PID", &pid.to_string()]).output();
    match out {
        Ok(_) => StopOutcome::Killed,
        Err(e) => StopOutcome::Error(format!("taskkill failed: {e}")),
    }
}

// ── Minimal libc bindings (unix) ──────────────────────────────────────────────
// We only need `kill(2)`; binding it directly avoids adding a `libc`/`nix`
// dependency to this dep-light crate (keeping the no-egui tree minimal).
#[cfg(unix)]
const SIGTERM: i32 = 15;
#[cfg(unix)]
const SIGKILL: i32 = 9;

#[cfg(unix)]
extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ALICE_IDENTITY_DIR` is process-global; the tests that mutate it must NOT
    /// run concurrently (Rust runs a crate's tests in parallel) — INCLUDING with
    /// the `setup` module's tests, which also set this var. Serialize them ALL
    /// through the ONE crate-wide lock (a module-local lock couldn't coordinate
    /// across modules). (`is_alive`/`stop_pid` tests don't touch the env, so
    /// they're free.)
    use crate::TEST_ENV_LOCK as ENV_LOCK;

    /// The pid file lives under the identity dir (honoring the override) so tests
    /// never touch the real `~/.alice`.
    #[test]
    fn pid_path_honors_override() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("alice-pid-test-{}", std::process::id()));
        std::env::set_var("ALICE_IDENTITY_DIR", &tmp);
        assert_eq!(pid_path(), tmp.join("miner-cli.pid"));
        std::env::remove_var("ALICE_IDENTITY_DIR");
    }

    /// is_alive: this very process is alive; a very high unused pid is not (unix).
    #[cfg(unix)]
    #[test]
    fn is_alive_detects_self_and_missing() {
        assert!(is_alive(std::process::id()));
        // PID 0x7FFF_FFFE is extremely unlikely to exist.
        assert!(!is_alive(0x7FFF_FFFE));
    }

    /// The guard writes our pid then removes it on drop (no stale pid left).
    #[test]
    fn pid_guard_writes_and_cleans_up() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!(
            "alice-pid-guard-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        std::env::set_var("ALICE_IDENTITY_DIR", &tmp);

        {
            let _g = PidGuard::acquire();
            assert_eq!(read_pid(), Some(std::process::id()));
        }
        // Dropped → file removed.
        assert!(read_pid().is_none());

        std::env::remove_var("ALICE_IDENTITY_DIR");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// stop_pid on a definitely-dead pid returns Graceful (ESRCH path), not an
    /// error — so `stop` after a crash cleans up rather than failing.
    #[cfg(unix)]
    #[test]
    fn stop_pid_on_dead_pid_is_graceful() {
        match stop_pid(0x7FFF_FFFE, Duration::from_millis(200)) {
            StopOutcome::Graceful => {}
            other => panic!("expected Graceful for a dead pid, got {:?}", match other {
                StopOutcome::Killed => "Killed",
                StopOutcome::Error(_) => "Error",
                StopOutcome::Graceful => "Graceful",
            }),
        }
    }
}
