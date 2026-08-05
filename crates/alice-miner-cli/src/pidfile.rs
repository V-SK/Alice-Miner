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

/// Read the recorded pid, if the file exists + parses. The pid is the FIRST line,
/// so a file written by an older build (pid only) still reads correctly.
pub fn read_pid() -> Option<u32> {
    let s = fs::read_to_string(pid_path()).ok()?;
    s.lines().next()?.trim().parse::<u32>().ok()
}

/// Who holds the rendezvous: the recorded pid plus (since v0.6.8) the data directory
/// that instance is using. The directory is recorded so the refusal message can name
/// it — "another miner is running" is not actionable; "pid 4242, data dir
/// /Users/x/.alice" is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    pub pid: u32,
    pub data_dir: Option<PathBuf>,
}

/// Parse the pid-file body. Pure, so both the legacy (pid-only) and current
/// (pid + data dir) shapes are pinned by tests.
pub fn parse_owner(body: &str) -> Option<Owner> {
    let mut lines = body.lines();
    let pid = lines.next()?.trim().parse::<u32>().ok()?;
    let data_dir = lines
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    Some(Owner { pid, data_dir })
}

/// Read the full owner record, if the file exists + parses.
pub fn read_owner() -> Option<Owner> {
    parse_owner(&fs::read_to_string(pid_path()).ok()?)
}

/// Remove the pid file (best-effort; a missing file is fine).
pub fn remove() {
    let _ = fs::remove_file(pid_path());
}

/// The record this process writes: its pid, then the data directory it is using.
fn self_record() -> String {
    format!("{}\n{}\n", std::process::id(), dir().display())
}

/// Claim the rendezvous ATOMICALLY, or report who already holds it.
///
/// `create_new` maps to `O_EXCL` / `CREATE_NEW`, so between two `alice-miner start`
/// processes racing at the same instant exactly ONE can win — the check-then-write
/// the old `acquire` did had a window in which both could decide the file was free.
///
/// A file left by a process we can PROVE is gone is removed and the claim retried
/// once (the stale-file takeover); a claim we cannot make for any other reason
/// (read-only home) yields `Unavailable` rather than pretending to have the lock.
fn claim_atomic() -> Claim {
    use std::io::Write as _;
    let path = pid_path();
    if let Some(parent) = path.parent() {
        if fs::create_dir_all(parent).is_err() {
            return Claim::Unavailable;
        }
    }
    for _ in 0..2 {
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                return match f.write_all(self_record().as_bytes()) {
                    Ok(()) => Claim::Won,
                    // We created the file but could not fill it — remove it rather
                    // than leave an unparseable record that blocks the next start.
                    Err(_) => {
                        let _ = fs::remove_file(&path);
                        Claim::Unavailable
                    }
                };
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let owner = read_owner();
                let Some(owner) = owner else {
                    // Present but unparseable (a truncated write, a stray file): it
                    // names nobody, so it can be replaced.
                    let _ = fs::remove_file(&path);
                    continue;
                };
                match liveness_settled(owner.pid) {
                    // Provably gone → stale-file takeover.
                    Liveness::Dead => {
                        let _ = fs::remove_file(&path);
                        continue;
                    }
                    Liveness::Alive => return Claim::Held(owner, Liveness::Alive),
                    Liveness::Unknown => return Claim::Held(owner, Liveness::Unknown),
                }
            }
            Err(_) => return Claim::Unavailable,
        }
    }
    // Two takeover attempts both lost the race to someone else: whoever is there now
    // is live enough to keep winning. Report it rather than loop.
    match read_owner() {
        Some(o) => {
            let l = liveness_settled(o.pid);
            Claim::Held(o, l)
        }
        None => Claim::Unavailable,
    }
}

/// The outcome of one atomic claim attempt.
#[derive(Debug)]
enum Claim {
    /// We hold the rendezvous.
    Won,
    /// Someone else holds it; with what we could establish about their liveness.
    Held(Owner, Liveness),
    /// We could not use the rendezvous at all (read-only home). Mining still works;
    /// `stop` just cannot find us.
    Unavailable,
}

/// Why a start was refused, with everything needed to act on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceConflict {
    pub pid: u32,
    pub data_dir: Option<PathBuf>,
}

/// An RAII guard that records this process's pid on construction and removes the
/// pid file on drop — so a clean exit never leaves a stale pid.
pub struct PidGuard {
    /// Whether THIS guard wrote the file (only then do we remove it on drop, so
    /// we never delete another live instance's pid).
    owns: bool,
    /// Set when we are running ALONGSIDE another instance: either the user passed
    /// `--allow-multiple`, or we could not verify the recorded pid's liveness.
    /// Rendered as a warning by the caller.
    sharing: Option<SharingReason>,
}

/// Why this process is running without owning the rendezvous.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharingReason {
    /// The user explicitly opted in with `--allow-multiple` over a LIVE owner.
    UserOverride { pid: u32, data_dir: Option<PathBuf> },
    /// A pid is recorded and we could NOT determine whether it is alive. We do not
    /// know, so we neither steal the rendezvous nor refuse to mine — and we say
    /// exactly that instead of picking a story.
    Unverifiable { pid: u32 },
    /// The rendezvous file could not be used at all (read-only home).
    RendezvousUnavailable,
}

impl PidGuard {
    /// Acquire the rendezvous, or REFUSE to start.
    ///
    /// **AM-REL-007.** Until v0.6.7 a second `alice-miner start` printed a warning
    /// and mined anyway. That warning was not enough, because the failure it warns
    /// about is silent and expensive: both instances drive the same engine directory,
    /// each overwrites the other's telemetry snapshot, and `alice-miner stop` can only
    /// reach the recorded one — so the survivor keeps the GPU busy while the UI, the
    /// dashboard and the exit code all agree that mining stopped. A warning printed
    /// once, minutes ago, above a live dashboard, is not a control.
    ///
    /// So a PROVABLY live owner is now a refusal. The two honest exceptions:
    ///   * `allow_multiple` — the user's explicit override (pids DO get recycled, so
    ///     "alive" can be a false positive and the user must be able to say so);
    ///   * [`Liveness::Unknown`] — we could not probe. Refusing there would mean
    ///     guessing that another miner exists and blocking a legitimate start on that
    ///     guess; we run, and say we could not verify.
    pub fn try_acquire(allow_multiple: bool) -> Result<Self, InstanceConflict> {
        match claim_atomic() {
            Claim::Won => Ok(Self {
                owns: true,
                sharing: None,
            }),
            Claim::Unavailable => Ok(Self {
                owns: false,
                sharing: Some(SharingReason::RendezvousUnavailable),
            }),
            Claim::Held(owner, Liveness::Unknown) => Ok(Self {
                owns: false,
                sharing: Some(SharingReason::Unverifiable { pid: owner.pid }),
            }),
            Claim::Held(owner, _) => {
                if allow_multiple {
                    Ok(Self {
                        owns: false,
                        sharing: Some(SharingReason::UserOverride {
                            pid: owner.pid,
                            data_dir: owner.data_dir,
                        }),
                    })
                } else {
                    Err(InstanceConflict {
                        pid: owner.pid,
                        data_dir: owner.data_dir,
                    })
                }
            }
        }
    }

    /// Why this process is running without the rendezvous, if it is. `None` on the
    /// normal single-instance path.
    pub fn sharing(&self) -> Option<&SharingReason> {
        self.sharing.as_ref()
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

// ── Liveness: ONE probe, shared with the GUI/core side. ──────────────────────
// Round 1 fixed this module's Windows stub but left `core::terminal::pid_is_alive`
// as a SECOND stub (always-alive off unix). Round 2 moves the probe into
// `alice_miner_core::proc` and both sides now call it, so the two can never drift
// apart again — and the Windows decision table is one pure, always-compiled
// function that the macOS/Linux CI legs execute too.
pub use alice_miner_core::proc::{is_alive, liveness, liveness_settled, Liveness};

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

    /// The probe itself (including the Windows `tasklist` decision table and the
    /// round-2 "ran but failed → Unknown" rule) is tested at its new home,
    /// `alice_miner_core::proc` — this module now re-exports it. What stays here is
    /// what this module still OWNS: the rendezvous file and `stop_pid`.
    ///
    /// The one probe fact the rendezvous depends on, asserted where it is used:
    /// a very high pid must be POSITIVELY dead, or the stale-file takeover below
    /// silently stops working.
    #[test]
    fn probe_is_wired_to_the_shared_implementation() {
        assert_eq!(liveness(std::process::id()), Liveness::Alive);
        assert!(is_alive(std::process::id()));
        assert_eq!(liveness(DEAD_PID), Liveness::Dead);
        assert!(!is_alive(DEAD_PID));
    }

    /// A temp `$ALICE_IDENTITY_DIR` for a rendezvous test.
    fn temp_dir(tag: &str) -> PathBuf {
        let tmp = std::env::temp_dir().join(format!(
            "alice-pid-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        std::env::set_var("ALICE_IDENTITY_DIR", &tmp);
        tmp
    }

    /// REGRESSION (Bug 2): a STALE pid file left by a crash / power loss must be
    /// taken over by the next `start`, so the running miner's pid is the one on
    /// record and a later `stop` aims at a real process. On Windows this used to be
    /// impossible (`is_alive` was always `true` -> we never wrote our pid -> `stop`
    /// targeted a dead pid and falsely reported success). Runs on every OS.
    #[test]
    fn acquire_takes_over_a_stale_pid_file() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = temp_dir("stale");

        // A crash left a pid file naming a process that no longer exists.
        std::fs::write(pid_path(), DEAD_PID.to_string()).unwrap();
        {
            let _guard = PidGuard::try_acquire(false).expect("a stale file must not block a start");
            assert_eq!(
                read_pid(),
                Some(std::process::id()),
                "a stale pid file must be taken over, not treated as a live owner"
            );
        }
        // We owned it -> dropped -> cleaned up.
        assert!(read_pid().is_none());

        std::env::remove_var("ALICE_IDENTITY_DIR");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// A pid file that exists but names NOBODY (truncated / stray) must not wedge
    /// every future start: it is replaced, not obeyed.
    #[test]
    fn acquire_replaces_an_unparseable_pid_file() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = temp_dir("junk");
        std::fs::write(pid_path(), b"").unwrap();
        {
            let _guard = PidGuard::try_acquire(false).expect("an empty pid file must not block");
            assert_eq!(read_pid(), Some(std::process::id()));
        }
        std::fs::write(pid_path(), b"not-a-pid\n").unwrap();
        {
            let _guard = PidGuard::try_acquire(false).expect("a junk pid file must not block");
            assert_eq!(read_pid(), Some(std::process::id()));
        }
        std::env::remove_var("ALICE_IDENTITY_DIR");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// AM-REL-007, the headline change: a pid file naming a PROVABLY LIVE process is
    /// now a REFUSAL, not a warning. (Our own pid is a live process we can create
    /// without spawning anything.) The refusal must carry the pid AND the data dir —
    /// "another miner is running" alone is not actionable.
    #[test]
    fn try_acquire_refuses_when_a_live_instance_holds_the_rendezvous() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = temp_dir("live");

        std::fs::write(
            pid_path(),
            format!("{}\n/some/other/alice\n", std::process::id()),
        )
        .unwrap();
        let conflict = PidGuard::try_acquire(false)
            .err()
            .expect("a live owner must REFUSE the start, not merely warn");
        assert_eq!(conflict.pid, std::process::id());
        assert_eq!(conflict.data_dir, Some(PathBuf::from("/some/other/alice")));
        // The refusal must not have clobbered the owner's record.
        assert_eq!(read_pid(), Some(std::process::id()));

        std::env::remove_var("ALICE_IDENTITY_DIR");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// The escape hatch: `--allow-multiple` runs anyway, does NOT take the
    /// rendezvous (so `stop` still reaches the original), and reports WHY.
    #[test]
    fn allow_multiple_runs_without_taking_the_rendezvous() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = temp_dir("override");

        let owner_record = format!("{}\n/some/other/alice\n", std::process::id());
        std::fs::write(pid_path(), &owner_record).unwrap();
        {
            let guard = PidGuard::try_acquire(true).expect("--allow-multiple must start");
            match guard.sharing() {
                Some(SharingReason::UserOverride { pid, data_dir }) => {
                    assert_eq!(*pid, std::process::id());
                    assert_eq!(data_dir.as_deref(), Some(std::path::Path::new("/some/other/alice")));
                }
                other => panic!("expected a UserOverride sharing reason, got {other:?}"),
            }
            // The ORIGINAL owner's record is untouched: `stop` must still reach it.
            assert_eq!(
                std::fs::read_to_string(pid_path()).unwrap(),
                owner_record,
                "--allow-multiple must not steal the rendezvous"
            );
        }
        // Dropping a non-owning guard must not delete someone else's record either.
        assert_eq!(std::fs::read_to_string(pid_path()).unwrap(), owner_record);

        std::env::remove_var("ALICE_IDENTITY_DIR");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// The pid-file body parser: the current two-line form AND the legacy pid-only
    /// form written by <= v0.6.7 (an upgrade must not orphan the running miner's
    /// record). Pure - runs on every OS.
    #[test]
    fn parse_owner_reads_both_the_legacy_and_current_records() {
        // Legacy: pid only.
        assert_eq!(
            parse_owner("4242"),
            Some(Owner { pid: 4242, data_dir: None })
        );
        assert_eq!(
            parse_owner("4242\n"),
            Some(Owner { pid: 4242, data_dir: None })
        );
        // Current: pid + data dir.
        assert_eq!(
            parse_owner("4242\n/Users/x/.alice\n"),
            Some(Owner {
                pid: 4242,
                data_dir: Some(PathBuf::from("/Users/x/.alice")),
            })
        );
        // A blank second line is "not recorded", not an empty path.
        assert_eq!(
            parse_owner("4242\n\n"),
            Some(Owner { pid: 4242, data_dir: None })
        );
        // Junk names nobody.
        assert_eq!(parse_owner(""), None);
        assert_eq!(parse_owner("not-a-pid\n/x"), None);
        // `read_pid` still sees the pid in the two-line form (the compatibility that
        // keeps `stop` working across the upgrade).
        assert_eq!(
            parse_owner("4242\n/Users/x/.alice").map(|o| o.pid),
            Some(4242)
        );
    }

    /// The guard writes our pid then removes it on drop (no stale pid left).
    #[test]
    fn pid_guard_writes_and_cleans_up() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = temp_dir("guard");

        {
            let _g = PidGuard::try_acquire(false).expect("free rendezvous");
            assert_eq!(read_pid(), Some(std::process::id()));
            // The record also carries the data dir, so a later conflict can name it.
            let body = std::fs::read_to_string(pid_path()).unwrap();
            assert_eq!(
                parse_owner(&body).and_then(|o| o.data_dir),
                Some(tmp.clone()),
                "the rendezvous must record which data dir this miner is using"
            );
        }
        // Dropped -> file removed.
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
