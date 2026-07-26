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
//!   * **windows:** a best-effort `taskkill /PID /T` (graceful — usually a no-op for
//!     a windowless console app), then `taskkill /F /T` (force the whole TREE). The
//!     engine child is additionally bound to a kill-on-close Job Object at spawn
//!     (`alice-supervise::child`), which is what actually guarantees it cannot
//!     outlive a force-killed parent.
//!
//! **Every outcome here is verified, never assumed.** `Graceful`/`Killed` are only
//! returned after re-probing the pid and finding it gone; anything we could not
//! confirm becomes `Error` so the caller can tell the user the truth instead of
//! printing "stopped cleanly" over a still-running miner.
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
    ///
    /// **Stale-file takeover (bug fix).** The decision now turns on a POSITIVE
    /// [`Liveness::Dead`], not on "not alive". The old code asked `is_alive`, which
    /// on Windows was hard-coded to `true` — so after ANY crash / power loss / closed
    /// window the leftover pid file looked like a live owner forever, we declined to
    /// record our own pid, and every later `stop` aimed at the dead pid and reported
    /// a clean stop while the real miner kept running. A pid we can PROVE is gone is
    /// safe to take over; an `Unknown` (we could not probe) still yields to the
    /// recorded owner, because stealing the rendezvous from a live miner would be the
    /// worse failure.
    pub fn acquire() -> Self {
        let owns = match read_pid() {
            // Someone is (or may be) there → don't steal the rendezvous.
            Some(pid) if liveness_settled(pid) != Liveness::Dead => false,
            // No file, or a pid we positively know is gone → take ownership.
            _ => write_self(),
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

/// What we could establish about a pid. The three-way answer matters: "I could not
/// tell" must NEVER be collapsed into either "alive" or "dead", because each
/// collapse produces a different lie (a phantom owner that blocks the rendezvous,
/// or a false "stopped cleanly" while the miner runs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    /// The process exists.
    Alive,
    /// The process positively does not exist.
    Dead,
    /// We could not probe (no tooling / permission / OS error) — assume nothing.
    Unknown,
}

/// Probe whether process `pid` exists.
#[cfg(unix)]
pub fn liveness(pid: u32) -> Liveness {
    // `kill(pid, 0)` performs error checking without sending a signal: Ok = alive
    // (or a zombie we can still signal), `ESRCH` = no such process, `EPERM` = it
    // exists but belongs to someone else (still ALIVE for our purposes).
    if unsafe { libc_kill(pid as i32, 0) } == 0 {
        return Liveness::Alive;
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(ESRCH) => Liveness::Dead,
        Some(EPERM) => Liveness::Alive,
        _ => Liveness::Unknown,
    }
}

/// Probe whether process `pid` exists (Windows).
///
/// **Bug fix.** This used to be a hard-coded `true` ("we can't cheaply probe"),
/// which made every stale pid file immortal — see [`PidGuard::acquire`]. `tasklist`
/// ships on every supported Windows (unlike `wmic`, which Microsoft removed in
/// recent Windows 11 builds) and the very same filter is already used by
/// [`stop_pid`], so this is a real probe with no new dependency: we ask for a
/// headerless CSV row for exactly this pid and read the PID column back.
#[cfg(not(unix))]
pub fn liveness(pid: u32) -> Liveness {
    use std::process::Command;
    match Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
        .output()
    {
        // A row for this pid → alive. A run that succeeded but listed nothing
        // ("INFO: No tasks are running which match…") → positively dead.
        Ok(out) => {
            if tasklist_csv_has_pid(&String::from_utf8_lossy(&out.stdout), pid) {
                Liveness::Alive
            } else {
                Liveness::Dead
            }
        }
        // tasklist itself could not be run → we know nothing. NOT "dead".
        Err(_) => Liveness::Unknown,
    }
}

/// Whether process `pid` may be running. Conservative by design: an `Unknown`
/// counts as alive, so we never *act* as if a process we failed to probe is gone.
/// Callers that must distinguish "proven gone" (stale-file takeover, stop
/// verification) use [`liveness_settled`].
pub fn is_alive(pid: u32) -> bool {
    liveness(pid) != Liveness::Dead
}

/// [`liveness`], but a **zombie counts as Dead** — the answer to use at decision
/// points ("may I take over this pid file?", "did it really stop?").
///
/// A process that has been killed but not yet reaped by its parent still answers
/// `kill(pid, 0)`, so the cheap probe reports it Alive. It is NOT running: it holds
/// no CPU or GPU and cannot mine. Treating it as alive would produce the two lies
/// this fix exists to prevent, in mirror image — a "could not confirm it stopped"
/// warning for a miner that certainly stopped, and a stale pid file that blocks the
/// rendezvous forever (this is reachable in normal use: the GUI spawns the CLI and
/// may not `wait()` on it promptly).
///
/// Kept separate from [`liveness`] because it costs a `ps` fork: polling loops use
/// the cheap probe and consult this only when they are about to decide.
#[cfg(unix)]
pub fn liveness_settled(pid: u32) -> Liveness {
    match liveness(pid) {
        Liveness::Alive if is_zombie(pid) => Liveness::Dead,
        other => other,
    }
}

/// Windows has no zombie state (a terminated process disappears from `tasklist`
/// once its handles close), so the settled answer is the plain probe.
#[cfg(not(unix))]
pub fn liveness_settled(pid: u32) -> Liveness {
    liveness(pid)
}

/// Is `pid` a zombie (terminated, awaiting reap)? `ps -o stat=` reports `Z` for it on
/// both Linux and macOS. Any failure to read the state answers `false` (we do not
/// claim a process is finished on a guess).
#[cfg(unix)]
fn is_zombie(pid: u32) -> bool {
    std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "stat="])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim_start()
                .starts_with('Z')
        })
        .unwrap_or(false)
}

/// Does this `tasklist /FO CSV /NH` output contain a row for `pid`?
///
/// Parsed as CSV rather than by substring: the raw row also carries the memory
/// column (`"12,345 K"`) and the session id, so a naive `stdout.contains(pid)` can
/// match those digits and report a dead pid as alive. Pure + compiled on every OS
/// so the parser is covered by the macOS/Linux CI runs too, not only Windows.
#[allow(dead_code)] // used by `liveness` on Windows only; always tested.
fn tasklist_csv_has_pid(stdout: &str, pid: u32) -> bool {
    stdout.lines().any(|line| {
        // `"image.exe","1234","Console","1","12,345 K"` → field 1 is the PID.
        line.split("\",\"")
            .nth(1)
            .map(|f| f.trim_matches('"').trim() == pid.to_string())
            .unwrap_or(false)
    })
}

/// The result of a `stop` request.
///
/// `Graceful` and `Killed` are both CONFIRMED terminations — each is only returned
/// after re-probing the pid and finding it gone. Anything we could not confirm is an
/// `Error` carrying the reason, so the caller can tell the user the truth instead of
/// printing "stopped cleanly" over a still-running miner.
#[derive(Debug)]
pub enum StopOutcome {
    /// The process exited after the termination request within the grace window.
    Graceful,
    /// The process did not exit in time, was force-killed, and is CONFIRMED gone.
    Killed,
    /// We could not signal the process, or could not confirm that it died.
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
    // Give the kernel a moment to reap — and then VERIFY. `Killed` is a claim that
    // the process is gone, so we only make it after seeing the pid disappear.
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(2) {
        if liveness(pid) == Liveness::Dead {
            return StopOutcome::Killed;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // Still answering `kill(pid, 0)`. A zombie awaiting reap is finished — that IS a
    // confirmed stop. Anything else, we genuinely could not confirm.
    match liveness_settled(pid) {
        Liveness::Dead => StopOutcome::Killed,
        _ => StopOutcome::Error(format!(
            "pid {pid} is still present after SIGKILL — could not confirm it stopped"
        )),
    }
}

/// Windows stop. Three corrections over the previous version, all of them about
/// not lying:
///   * the force path now passes **`/T`** (kill the whole process TREE). Without it
///     `taskkill /F` killed only the recorded process and left every helper it had
///     spawned — the engine — running.
///   * the outcome is decided by **re-probing the pid**, not by "did `taskkill`
///     launch". `Command::output()` returning `Ok` only means the *tool* ran; a
///     taskkill that printed "Access is denied" or "process not found" exits
///     non-zero and used to be reported as `Killed`.
///   * a pid we cannot confirm dead yields `Error`, never `Killed`.
///
/// The graceful phase stays best-effort: `taskkill` without `/F` posts `WM_CLOSE`,
/// which a windowless console miner does not process, so it is expected to fail —
/// the real graceful path is the CLI's own Ctrl-C handling, and the real no-orphan
/// guarantee is the Job Object the engine child is bound to (see
/// `alice-supervise::child`).
#[cfg(not(unix))]
pub fn stop_pid(pid: u32, timeout: Duration) -> StopOutcome {
    use std::process::Command;
    // Already gone?
    if liveness(pid) == Liveness::Dead {
        return StopOutcome::Graceful;
    }
    // 1) Graceful close request (best-effort; see the doc comment).
    let _ = Command::new("taskkill")
        .args(["/T", "/PID", &pid.to_string()])
        .output();
    // 2) Poll for a confirmed exit.
    let start = Instant::now();
    while start.elapsed() < timeout {
        if liveness(pid) == Liveness::Dead {
            return StopOutcome::Graceful;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    // 3) Force-kill the whole tree.
    if let Err(e) = Command::new("taskkill")
        .args(["/F", "/T", "/PID", &pid.to_string()])
        .output()
    {
        return StopOutcome::Error(format!("taskkill could not be run: {e}"));
    }
    // 4) VERIFY. Only a pid we watched disappear counts as killed.
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(3) {
        match liveness(pid) {
            Liveness::Dead => return StopOutcome::Killed,
            _ => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    StopOutcome::Error(match liveness(pid) {
        Liveness::Unknown => format!(
            "could not verify whether pid {pid} stopped (tasklist unavailable) — \
             please check Task Manager for xmrig / SRBMiner"
        ),
        _ => format!(
            "pid {pid} is still running after taskkill /F /T — \
             please check Task Manager for xmrig / SRBMiner"
        ),
    })
}

// ── Minimal libc bindings (unix) ──────────────────────────────────────────────
// We only need `kill(2)`; binding it directly avoids adding a `libc`/`nix`
// dependency to this dep-light crate (keeping the no-egui tree minimal).
#[cfg(unix)]
const SIGTERM: i32 = 15;
#[cfg(unix)]
const SIGKILL: i32 = 9;
/// `errno` values we interpret from `kill(pid, 0)` (identical on Linux + macOS).
#[cfg(unix)]
const EPERM: i32 = 1;
#[cfg(unix)]
const ESRCH: i32 = 3;

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

    /// A pid that certainly does not exist. (Windows pids are multiples of 4 and
    /// nowhere near this range; unix pids are bounded well below it.)
    const DEAD_PID: u32 = 0x7FFF_FFFE;

    /// liveness/is_alive: this very process is alive; a very high unused pid is
    /// positively dead. Runs on **every** OS — on Windows this exercises the real
    /// `tasklist` probe that replaced the hard-coded `true` (Bug 2), so the fix is
    /// actually covered by CI rather than assumed.
    #[test]
    fn liveness_detects_self_and_missing() {
        assert_eq!(liveness(std::process::id()), Liveness::Alive);
        assert!(is_alive(std::process::id()));
        assert_eq!(
            liveness(DEAD_PID),
            Liveness::Dead,
            "a non-existent pid must be positively Dead, never assumed alive"
        );
        assert!(!is_alive(DEAD_PID));
    }

    /// The `tasklist /FO CSV /NH` row parser (Bug 2). Pure, so it runs on every OS.
    /// The memory column contains digits too — a substring match would report the
    /// dead pid 345 as alive off `"12,345 K"`.
    #[test]
    fn tasklist_csv_row_is_parsed_by_column_not_substring() {
        let row = "\"xmrig.exe\",\"1234\",\"Console\",\"1\",\"12,345 K\"\r\n";
        assert!(tasklist_csv_has_pid(row, 1234));
        assert!(!tasklist_csv_has_pid(row, 345), "must not match the memory column");
        assert!(!tasklist_csv_has_pid(row, 1), "must not match the session column");
        assert!(!tasklist_csv_has_pid(row, 12));
        // The "no match" output tasklist prints for a dead pid.
        let none = "INFO: No tasks are running which match the specified criteria.\r\n";
        assert!(!tasklist_csv_has_pid(none, 1234));
        assert!(!tasklist_csv_has_pid("", 1234));
        // Several rows: find the right one.
        let rows = "\"a.exe\",\"10\",\"Console\",\"1\",\"1 K\"\r\n\"b.exe\",\"20\",\"Console\",\"1\",\"2 K\"\r\n";
        assert!(tasklist_csv_has_pid(rows, 20));
        assert!(!tasklist_csv_has_pid(rows, 30));
    }

    /// REGRESSION (Bug 2): a STALE pid file left by a crash / power loss must be
    /// taken over by the next `start`, so the running miner's pid is the one on
    /// record and a later `stop` aims at a real process. On Windows this used to be
    /// impossible (`is_alive` was always `true` → we never wrote our pid → `stop`
    /// targeted a dead pid and falsely reported success). Runs on every OS.
    #[test]
    fn acquire_takes_over_a_stale_pid_file() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!(
            "alice-pid-stale-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        std::env::set_var("ALICE_IDENTITY_DIR", &tmp);

        // A crash left a pid file naming a process that no longer exists.
        std::fs::write(pid_path(), DEAD_PID.to_string()).unwrap();
        {
            let _guard = PidGuard::acquire();
            assert_eq!(
                read_pid(),
                Some(std::process::id()),
                "a stale pid file must be taken over, not treated as a live owner"
            );
        }
        // We owned it → dropped → cleaned up.
        assert!(read_pid().is_none());

        std::env::remove_var("ALICE_IDENTITY_DIR");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// The other side of the takeover rule: a pid file naming a LIVE process (here,
    /// ourselves) is respected — we neither steal it nor delete it on drop.
    #[test]
    fn acquire_yields_to_a_live_owner() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!(
            "alice-pid-live-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        std::env::set_var("ALICE_IDENTITY_DIR", &tmp);

        // A live pid that is NOT us would be ideal, but our own pid proves the same
        // branch (`liveness != Dead` → don't take ownership) without spawning.
        std::fs::write(pid_path(), std::process::id().to_string()).unwrap();
        {
            let _guard = PidGuard::acquire();
            assert_eq!(read_pid(), Some(std::process::id()));
        }
        // NOTE: the file still names our pid, and `Drop` only removes it when the
        // guard OWNED it. It didn't (a live owner was recorded), but the recorded pid
        // happens to equal ours, so the drop check cannot distinguish the two here.
        // The takeover behaviour is what this test pins; ownership-on-drop is covered
        // by `pid_guard_writes_and_cleans_up`.
        std::env::remove_var("ALICE_IDENTITY_DIR");
        let _ = std::fs::remove_dir_all(&tmp);
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

    /// stop_pid on a definitely-dead pid returns Graceful (ESRCH / "no such task"),
    /// not an error — so `stop` after a crash cleans up rather than failing. Now runs
    /// on Windows too, where it must return promptly instead of burning the whole
    /// grace window on a pid that is already gone.
    #[test]
    fn stop_pid_on_dead_pid_is_graceful() {
        let t0 = Instant::now();
        match stop_pid(DEAD_PID, Duration::from_millis(200)) {
            StopOutcome::Graceful => {}
            other => panic!("expected Graceful for a dead pid, got {other:?}"),
        }
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "a dead pid must be resolved without waiting out the force/verify path"
        );
    }
}
