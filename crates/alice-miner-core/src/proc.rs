//! `core/proc` — the ONE process-liveness probe the whole workspace shares.
//!
//! There used to be three answers to "is pid N alive?": the CLI's `pidfile`
//! (a real probe), `terminal::pid_is_alive` (a `#[cfg(not(unix))]` stub that
//! answered `true` forever), and a test-local helper in `alice-supervise`. Two of
//! them were wrong on Windows in OPPOSITE directions, which is exactly how a stop
//! can both "succeed" over a running miner and strand the GUI at `Stopping…`.
//! This module is the single source of truth; the others delegate here.
//!
//! ── THE HONESTY CONTRACT ────────────────────────────────────────────────────
//! Liveness is a THREE-way answer ([`Liveness`]). "I could not tell" is never
//! folded into `Alive` or `Dead`, because each fold produces its own lie:
//!   * `Unknown → Dead` lets `stop` report "stopped cleanly" over a live miner and
//!     lets a fresh `start` steal a live instance's pid file.
//!   * `Unknown → Alive` makes every stale pid file immortal (the pre-fix Windows
//!     behaviour) and leaves the GUI convinced a crashed miner is still mining.
//!
//! Callers pick the fold that is SAFE for their decision, and say which they used.

/// What we could establish about a pid.
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
///
/// `pid == 0` is never a single miner process (on unix `kill(0, 0)` addresses the
/// caller's whole process GROUP — a false "alive"; on Windows it is not a valid
/// target either), so it is answered `Dead` before either platform probe.
#[cfg(unix)]
pub fn liveness(pid: u32) -> Liveness {
    if pid == 0 {
        return Liveness::Dead;
    }
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

/// Probe whether process `pid` exists (Windows) via `tasklist`.
///
/// `tasklist` ships on every supported Windows (unlike `wmic`, which Microsoft
/// removed in recent Windows 11 builds) and needs no elevation for the current
/// session. We ask for a headerless CSV row for exactly this pid and read the PID
/// column back — see [`classify_tasklist`] for how the answer is derived, and why
/// a `tasklist` that RAN BUT FAILED is `Unknown` rather than `Dead`.
#[cfg(not(unix))]
pub fn liveness(pid: u32) -> Liveness {
    use std::process::Command;
    if pid == 0 {
        return Liveness::Dead;
    }
    match Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
        .output()
    {
        Ok(out) => classify_tasklist(
            &String::from_utf8_lossy(&out.stdout),
            out.status.success(),
            pid,
        ),
        // tasklist itself could not be run → we know nothing. NOT "dead".
        Err(_) => Liveness::Unknown,
    }
}

/// Turn one `tasklist /FI "PID eq N" /FO CSV /NH` run into a [`Liveness`].
///
/// Pure + compiled on every OS, so the Windows decision table is covered by the
/// macOS/Linux CI legs too (the report's root cause was `cfg(windows)` code that
/// no test ever executed).
///
/// The rules, and why:
///   * a CSV row whose PID column is `pid` → **Alive**.
///   * `ok == false` (tasklist ran but exited non-zero: access denied, a restricted
///     / service session, a broken image) → **Unknown**. This is the fix for the
///     last false-success path: the previous version looked only at whether the
///     COMMAND could be spawned, so a tasklist that started and then failed printed
///     nothing, and "nothing" was read as a POSITIVE "dead" — `stop` then reported
///     `Graceful` over a live miner and `PidGuard::acquire` stole its pid file. The
///     module's two PowerShell probes already checked their exit status; this one
///     now agrees with them.
///   * `ok == true` and no matching row → **Dead**. This is the ordinary "no such
///     pid" answer: tasklist exits 0 and prints `INFO: No tasks are running which
///     match the specified criteria.` The `Dead` here is load-bearing (stale pid
///     files are only taken over on a POSITIVE dead), so it must stay reachable.
///   * `ok == true` but stdout is COMPLETELY empty → **Unknown**. A successful
///     tasklist always says something (a row, or the INFO line). Silence means we
///     do not actually understand what happened, and a guess would be a lie.
///
/// Localisation is a non-issue: only the INFO sentence is translated, and we key
/// off the CSV column layout (which `/FO CSV /NH` fixes) rather than any message.
pub fn classify_tasklist(stdout: &str, ok: bool, pid: u32) -> Liveness {
    if tasklist_csv_has_pid(stdout, pid) {
        return Liveness::Alive;
    }
    if !ok {
        return Liveness::Unknown;
    }
    if stdout.trim().is_empty() {
        return Liveness::Unknown;
    }
    Liveness::Dead
}

/// Does this `tasklist /FO CSV /NH` output contain a row for `pid`?
///
/// Parsed as CSV rather than by substring: the raw row also carries the memory
/// column (`"12,345 K"`) and the session id, so a naive `stdout.contains(pid)` can
/// match those digits and report a dead pid as alive.
pub fn tasklist_csv_has_pid(stdout: &str, pid: u32) -> bool {
    let want = pid.to_string();
    stdout.lines().any(|line| {
        // `"image.exe","1234","Console","1","12,345 K"` → field 1 is the PID.
        line.split("\",\"")
            .nth(1)
            .map(|f| f.trim_matches('"').trim() == want)
            .unwrap_or(false)
    })
}

/// What one `pgrep -f <needle>` run established — the **unix twin of
/// [`classify_tasklist`]**, and it exists for the same reason.
///
/// `pgrep` puts its answer in the EXIT STATUS, and the `stop` orphan sweep used to
/// ignore it completely: it read stdout and nothing else. A `pgrep` that ran and
/// FAILED (a hardened/containerised environment with no readable `/proc`, a
/// restricted session, a `pgrep` that rejects the invocation) prints nothing, and
/// "nothing" parsed as an empty pid list — i.e. a POSITIVE "there are no orphans",
/// after which `stop` printed *"No orphan left."* over a possibly still-mining
/// engine. That is exactly the false success round 2 closed on the Windows side;
/// unix was left asymmetric, and this closes it.
///
/// The trap in the OTHER direction is exit **1**. For `pgrep` (BSD and procps
/// alike) `1` means "no process matched" — the ordinary, correct "there are no
/// orphans" — so folding `1` into a failure would turn every clean stop on every
/// unix into a permanent, cry-wolf scan gap. Both folds are lies. The status is a
/// three-way answer and is kept as one.
///
/// Pure + compiled on every OS, so the Windows CI leg covers this table too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgrepScan {
    /// Exit 0 — at least one process matched; stdout carries the candidate pids.
    Matched,
    /// Exit 1 — the scan RAN and matched nothing. A real, usable answer.
    NoMatch,
    /// Exit ≥ 2 (2 = usage/syntax error, 3 = fatal error, 126/127 = could not
    /// execute) or killed by a signal — `pgrep` did not answer. We know NOTHING
    /// about leftover engines and must not claim otherwise.
    Failed,
}

impl PgrepScan {
    /// Did the scan actually RUN? (`Matched` or `NoMatch`.) The only question the
    /// caller asks: a scan that ran may back a "no orphan left" claim — including
    /// when it found none — and one that did not, may not.
    pub fn ran(self) -> bool {
        !matches!(self, Self::Failed)
    }
}

/// Classify a finished `pgrep` by its exit status (`None` = killed by a signal).
/// See [`PgrepScan`] for why `1` is an answer and `2` is not.
pub fn classify_pgrep(code: Option<i32>) -> PgrepScan {
    match code {
        Some(0) => PgrepScan::Matched,
        Some(1) => PgrepScan::NoMatch,
        _ => PgrepScan::Failed,
    }
}

/// [`liveness`], but a **zombie counts as Dead** — the answer to use at decision
/// points ("may I take over this pid file?", "did it really stop?").
///
/// A process that has been killed but not yet reaped by its parent still answers
/// `kill(pid, 0)`, so the cheap probe reports it Alive. It is NOT running: it holds
/// no CPU or GPU and cannot mine. Treating it as alive produces the two lies this
/// module exists to prevent, in mirror image — a "could not confirm it stopped"
/// warning for a miner that certainly stopped, and a stale pid file that blocks the
/// rendezvous forever (reachable in normal use: the GUI spawns the CLI and may not
/// `wait()` on it promptly).
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

/// Whether process `pid` MAY be running — the fail-SAFE fold: an `Unknown` counts as
/// alive, so we never *act* as if a process we failed to probe is gone. Callers that
/// must distinguish "proven gone" (stale-file takeover, stop verification) use
/// [`liveness_settled`] and compare against [`Liveness::Dead`] explicitly.
pub fn is_alive(pid: u32) -> bool {
    liveness(pid) != Liveness::Dead
}

// ── Minimal libc binding (unix) ───────────────────────────────────────────────
// We only need `kill(2)`; binding it directly avoids adding a `libc`/`nix`
// dependency to this dep-light crate.
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

    /// A pid that certainly does not exist. (Windows pids are multiples of 4 and
    /// nowhere near this range; unix pids are bounded well below it.)
    const DEAD_PID: u32 = 0x7FFF_FFFE;

    /// The real probe, on EVERY OS — on Windows this exercises the `tasklist` path
    /// that replaced the hard-coded `true`.
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
        assert_eq!(liveness(0), Liveness::Dead, "pid 0 is not a miner process");
    }

    /// The `tasklist /FO CSV /NH` row parser. Pure, so it runs on every OS. The
    /// memory column contains digits too — a substring match would report the dead
    /// pid 345 as alive off `"12,345 K"`.
    #[test]
    fn tasklist_csv_row_is_parsed_by_column_not_substring() {
        let row = "\"xmrig.exe\",\"1234\",\"Console\",\"1\",\"12,345 K\"\r\n";
        assert!(tasklist_csv_has_pid(row, 1234));
        assert!(!tasklist_csv_has_pid(row, 345), "must not match the memory column");
        assert!(!tasklist_csv_has_pid(row, 1), "must not match the session column");
        assert!(!tasklist_csv_has_pid(row, 12));
        let none = "INFO: No tasks are running which match the specified criteria.\r\n";
        assert!(!tasklist_csv_has_pid(none, 1234));
        assert!(!tasklist_csv_has_pid("", 1234));
        // Several rows: find the right one.
        let rows = "\"a.exe\",\"10\",\"Console\",\"1\",\"1 K\"\r\n\"b.exe\",\"20\",\"Console\",\"1\",\"2 K\"\r\n";
        assert!(tasklist_csv_has_pid(rows, 20));
        assert!(!tasklist_csv_has_pid(rows, 30));
    }

    /// ROUND-2 REGRESSION: a `tasklist` that RAN BUT FAILED (non-zero exit, empty
    /// stdout — a restricted session, access denied) must be `Unknown`, NEVER a
    /// positive `Dead`. A `Dead` here is the last false-success path: `stop` would
    /// return `Graceful` over a live miner and `acquire` would steal its pid file.
    #[test]
    fn tasklist_that_ran_but_failed_is_unknown_not_dead() {
        // Non-zero exit, nothing on stdout (the access-denied shape).
        assert_eq!(classify_tasklist("", false, 1234), Liveness::Unknown);
        // Non-zero exit WITH some output that isn't our row — still unknown.
        assert_eq!(
            classify_tasklist("ERROR: Access denied\r\n", false, 1234),
            Liveness::Unknown
        );
        // Exit 0 but total silence: a successful tasklist always says something.
        assert_eq!(classify_tasklist("", true, 1234), Liveness::Unknown);
        assert_eq!(classify_tasklist("   \r\n", true, 1234), Liveness::Unknown);
    }

    /// The other half of the table: the ORDINARY answers must stay decisive, or the
    /// stale-pid takeover (which needs a POSITIVE dead) silently stops working.
    #[test]
    fn tasklist_ordinary_answers_stay_decisive() {
        let row = "\"xmrig.exe\",\"1234\",\"Console\",\"1\",\"12,345 K\"\r\n";
        assert_eq!(classify_tasklist(row, true, 1234), Liveness::Alive);
        // A row for a live pid outranks a non-zero exit: we SAW the process.
        assert_eq!(classify_tasklist(row, false, 1234), Liveness::Alive);
        // The localised "no tasks" INFO line (here, a Chinese Windows) → Dead.
        assert_eq!(
            classify_tasklist("信息: 没有运行的任务匹配指定标准。\r\n", true, 1234),
            Liveness::Dead
        );
        assert_eq!(
            classify_tasklist(
                "INFO: No tasks are running which match the specified criteria.\r\n",
                true,
                1234
            ),
            Liveness::Dead
        );
        // A row for a DIFFERENT pid (impossible with the filter, but be strict).
        assert_eq!(
            classify_tasklist("\"a.exe\",\"999\",\"Console\",\"1\",\"1 K\"\r\n", true, 1234),
            Liveness::Dead
        );
    }

    /// ROUND-3 REGRESSION — the UNIX TWIN of the tasklist false success. The orphan
    /// sweep read `pgrep`'s stdout and ignored its exit status, so a `pgrep` that ran
    /// and failed (empty stdout) was indistinguishable from "scanned, found nothing"
    /// and `stop` went on to claim "No orphan left." over a possibly live engine.
    ///
    /// The test pins BOTH directions, because over-correcting is its own bug: exit 1
    /// is `pgrep`'s ordinary "no match" and must stay a usable answer, or every clean
    /// stop on every unix reports a scan gap nobody would read twice.
    #[test]
    fn pgrep_failure_is_not_an_empty_result_and_no_match_is_not_a_failure() {
        // The table.
        assert_eq!(classify_pgrep(Some(0)), PgrepScan::Matched);
        assert_eq!(classify_pgrep(Some(1)), PgrepScan::NoMatch);
        assert_eq!(classify_pgrep(Some(2)), PgrepScan::Failed); // usage / syntax
        assert_eq!(classify_pgrep(Some(3)), PgrepScan::Failed); // fatal
        assert_eq!(classify_pgrep(Some(126)), PgrepScan::Failed); // not executable
        assert_eq!(classify_pgrep(Some(127)), PgrepScan::Failed); // not found
        assert_eq!(classify_pgrep(None), PgrepScan::Failed); // killed by a signal
        // The load-bearing split: "we looked and found none" backs the claim;
        // "we could not look" does not.
        assert!(classify_pgrep(Some(0)).ran());
        assert!(
            classify_pgrep(Some(1)).ran(),
            "exit 1 is pgrep's NORMAL 'no match' — treating it as a failure would \
             make every clean unix stop cry scan-gap"
        );
        assert!(!classify_pgrep(Some(2)).ran());
        assert!(!classify_pgrep(Some(3)).ran());
        assert!(!classify_pgrep(None).ran());
    }

    /// `liveness_settled` never claims a live process is finished.
    #[test]
    fn settled_agrees_with_the_plain_probe_for_a_live_process() {
        assert_eq!(liveness_settled(std::process::id()), Liveness::Alive);
        assert_eq!(liveness_settled(DEAD_PID), Liveness::Dead);
    }
}
