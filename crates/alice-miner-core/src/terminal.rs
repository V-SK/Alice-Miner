//! `core/terminal` — pop a **visible OS terminal** running the headless miner CLI.
//!
//! The operator's chosen GUI model: clicking Start in the desktop app launches the
//! headless `alice-miner-cli` in a REAL terminal window, so (a) mining persists in
//! a process the user can see and Ctrl-C, and (b) the user watches the live engine
//! output directly. This is the **GPU-persistence path** — distinct from the
//! launchd background service (`service.rs`), which stays XMR-only and headless.
//!
//! ── HONESTY / SECURITY INVARIANTS ───────────────────────────────────────────
//!   * The argv is **SECRET-FREE**: it is only `start --lane <lane> [--gpus <ids>]`.
//!     The CLI prompts for the GPU-PRL/Alpha wallet-unlock password *interactively*
//!     in its own terminal (`rpassword`), so no password is ever stored or passed
//!     on a command line / through the process table.
//!   * No address, endpoint, collection address, or pool ever appears here — the
//!     reward address comes from the on-disk `~/.alice` identity the CLI reads at
//!     runtime, exactly as the foreground/engine path does.
//!   * **Never panics.** A missing terminal program / missing CLI binary returns a
//!     clear `Err(String)` the GUI surfaces inline.
//!
//! The command-BUILDING (escaping + the per-OS argv) is factored into pure,
//! unit-tested functions ([`build_macos_osascript`], [`build_windows_argv`],
//! [`build_unix_terminal_argv`]); [`spawn_in_terminal`] is the thin spawn wrapper.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The headless miner CLI binary name (sibling of the GUI executable). `.exe` on
/// Windows.
pub const CLI_BIN_NAME: &str = if cfg!(windows) {
    "alice-miner-cli.exe"
} else {
    "alice-miner-cli"
};

/// Resolve the headless CLI binary that sits next to the CURRENT executable
/// (`Contents/MacOS/alice-miner-cli` on macOS; the install dir elsewhere). Returns
/// a clear `Err` when the current exe / its dir can't be resolved or the CLI isn't
/// found there (a broken install) so the GUI can tell the user to reinstall.
pub fn resolve_cli_path() -> Result<std::path::PathBuf, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("cannot locate this app's executable: {e}"))?;
    let dir = exe
        .parent()
        .ok_or("this app's executable has no parent directory")?;
    let cli = dir.join(CLI_BIN_NAME);
    if cli.is_file() {
        Ok(cli)
    } else {
        Err(format!(
            "the bundled miner CLI ({CLI_BIN_NAME}) wasn't found next to the app — reinstall Alice Miner."
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI → GUI telemetry file + engine-child pid backstop
//
// When the GUI launches the headless CLI in a visible terminal, the CLI writes its
// latest `Snapshot` to a small JSON file the GUI polls, so the GUI Dashboard mirrors
// the CLI's live hashrate/shares. Separately, the engine child (xmrig / SRBMiner —
// the process that actually eats CPU) records its pid AND the exact engine binary path
// to a second file so `stop` can find, IDENTITY-VERIFY, and kill it even when the CLI
// PARENT pid file is stale (the "stopped but xmrig still at 1200% CPU" report). Both
// files hold PUBLIC data only (the credit-only `Snapshot`, whose wire form carries no
// secret — a core test asserts it; and the child's pid + on-disk engine path). Co-located
// with the identity pointer under the same per-user dir.
// ─────────────────────────────────────────────────────────────────────────────

/// The CLI→GUI telemetry file basename (latest `Snapshot`, atomically overwritten).
pub const TELEMETRY_FILE_NAME: &str = "miner-cli.snapshot.json";

/// The engine-child pid file basename (the real xmrig/SRBMiner pid — NOT the CLI
/// parent's `miner-cli.pid`).
pub const CHILD_PID_FILE_NAME: &str = "miner-child.pid";

/// The CLI **parent** pid file basename — the `alice-miner-cli start` process itself
/// (written by the CLI's `pidfile` module, removed on its graceful exit). Kept HERE as
/// a shared constant so the GUI can probe its presence for stop-convergence WITHOUT
/// depending on the CLI crate. MUST stay in lock-step with `alice-miner-cli`'s
/// `pidfile::pid_path` basename.
pub const CLI_PID_FILE_NAME: &str = "miner-cli.pid";

/// A LEGACY pid file basename from pre-terminal builds (`miner.pid`). Newer builds
/// never write it, but a residual one from an old install can linger; we sweep it on
/// stop-convergence so it can't confuse a future `stop` / a stale-pid probe.
pub const LEGACY_PID_FILE_NAME: &str = "miner.pid";

/// Resolve the per-user Alice dir (`$ALICE_IDENTITY_DIR`, else `~/.alice`, else the
/// relative `.alice`) — the SAME location [`crate::identity::identity_path`] and the
/// CLI `miner-cli.pid` resolve to, so all four files share one dir + override knob.
///
/// We intentionally do NOT delegate to [`crate::identity::identity_path`] here: under
/// `cfg(test)` that resolver PANICS when `$ALICE_IDENTITY_DIR` is unset (its keystore
/// safety net), and these helpers are called from `supervise::spawn_run` which the
/// core's OWN child-spawn tests exercise WITHOUT that env — a delegation would turn
/// every such test into a panic. Instead we replicate its precedence and, under
/// `cfg(test)` with no override, resolve to a process-scoped TEMP dir (never the real
/// `~/.alice`) — honoring the exact same "tests never touch real home" invariant.
fn alice_dir() -> PathBuf {
    if let Some(over) = std::env::var_os("ALICE_IDENTITY_DIR") {
        let s = over.to_string_lossy().trim().to_string();
        if !s.is_empty() {
            return PathBuf::from(s);
        }
    }
    #[cfg(test)]
    {
        // A test that forgot `$ALICE_IDENTITY_DIR` must still never write real home;
        // route it to a temp dir instead (the identity resolver's protection intent).
        std::env::temp_dir().join(format!("alice-miner-terminal-test-{}", std::process::id()))
    }
    #[cfg(not(test))]
    {
        dirs::home_dir()
            .map(|h| h.join(".alice"))
            .unwrap_or_else(|| PathBuf::from(".alice"))
    }
}

/// The telemetry file path (`<alice-dir>/miner-cli.snapshot.json`).
pub fn telemetry_path() -> PathBuf {
    alice_dir().join(TELEMETRY_FILE_NAME)
}

/// The engine-child pid file path (`<alice-dir>/miner-child.pid`).
pub fn child_pid_path() -> PathBuf {
    alice_dir().join(CHILD_PID_FILE_NAME)
}

/// The CLI-parent pid file path (`<alice-dir>/miner-cli.pid`) — the SAME path the
/// `alice-miner-cli` `pidfile` module resolves to (both honor `$ALICE_IDENTITY_DIR`,
/// else `~/.alice`). Used by the GUI's stop-convergence to tell that the external CLI
/// has fully exited (it drops this file on graceful shutdown).
pub fn cli_pid_path() -> PathBuf {
    alice_dir().join(CLI_PID_FILE_NAME)
}

/// The legacy pid file path (`<alice-dir>/miner.pid`) — see [`LEGACY_PID_FILE_NAME`].
pub fn legacy_pid_path() -> PathBuf {
    alice_dir().join(LEGACY_PID_FILE_NAME)
}

/// Whether BOTH the CLI-parent pid file (`miner-cli.pid`) and the engine-child pid file
/// (`miner-child.pid`) are ABSENT — the DEFINITIVE "the external terminal miner is fully
/// down" signal used by the GUI's stop-convergence. Independent of telemetry, so a final
/// idle `Snapshot` the CLI writes on its way out (which would otherwise keep telemetry
/// "fresh") can never strand the UI at `Stopping…`. Best-effort + fail-safe: a path that
/// can't be probed is treated as absent (the staleness sweep remains the backstop).
pub fn terminal_pids_absent() -> bool {
    !cli_pid_path().exists() && !child_pid_path().exists()
}

/// Read the CLI **parent** pid (`miner-cli.pid`, line 1), if the file exists + parses.
/// The counterpart of [`read_child_pid`] for the CLI-parent rendezvous.
pub fn read_cli_pid() -> Option<u32> {
    let body = fs::read_to_string(cli_pid_path()).ok()?;
    body.lines().next()?.trim().parse::<u32>().ok()
}

/// Whether the external terminal miner has a **LIVE process**: either the CLI parent
/// (`miner-cli.pid`) or the engine child (`miner-child.pid`) names a pid that is CURRENTLY
/// running. This is stronger than [`terminal_pids_absent`] (which only checks that the pid
/// *files* exist): it also rejects a STALE pid file a crashed / SIGKILL'd process left
/// behind. Path-independent — it NEVER looks at the process's on-disk bundle path, so a
/// miner running from a macOS AppTranslocation mount (a `.app` launched straight from
/// `~/Downloads`) is recognised exactly like one under `/Applications`. Best-effort +
/// fail-SAFE: an indeterminate liveness probe reports ALIVE, so a running miner is never
/// falsely declared dead.
pub fn terminal_pids_alive() -> bool {
    if let Some(pid) = read_cli_pid() {
        if pid_is_alive(pid) {
            return true;
        }
    }
    if let Some(pid) = read_child_pid() {
        if pid_is_alive(pid) {
            return true;
        }
    }
    false
}

/// Whether process `pid` is currently alive. Uses `kill(pid, 0)` on unix (Ok / `EPERM` =
/// the process exists; `ESRCH` = no such process) — the same primitive the CLI's `pidfile`
/// module uses, bound directly to avoid a `libc` dependency on this crate. On non-unix we
/// can't cheaply probe, so we fail-SAFE to ALIVE (never falsely declare a miner dead).
pub fn pid_is_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // A pid of 0 addresses the whole process group on unix — never a single miner
        // process — so treat it as "not a live miner" rather than probing it.
        if pid == 0 {
            return false;
        }
        unsafe { libc_kill(pid as i32, 0) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

/// Age (`now − mtime`) of the CLI→GUI telemetry snapshot file at `path`, or `None` when the
/// file is absent / its mtime can't be read. Lets the GUI judge freshness by the CLI's OWN
/// write clock (the file's mtime) rather than the GUI's poll clock — so a GUI-side stall
/// (macOS App Nap, an occluded window, repaint starvation, a stretch of failed reads) can
/// never make a still-updating miner look stale. Fail-SAFE toward "fresh": a future / equal
/// mtime (clock jitter around a just-written file) reports `Duration::ZERO`, not an error.
pub fn snapshot_age_at(path: &Path) -> Option<std::time::Duration> {
    let mtime = fs::metadata(path).ok()?.modified().ok()?;
    Some(
        std::time::SystemTime::now()
            .duration_since(mtime)
            .unwrap_or(std::time::Duration::ZERO),
    )
}

/// Age of the CANONICAL telemetry snapshot (`<alice-dir>/miner-cli.snapshot.json`).
/// See [`snapshot_age_at`].
pub fn snapshot_age() -> Option<std::time::Duration> {
    snapshot_age_at(&telemetry_path())
}

/// Best-effort remove of a residual legacy `miner.pid` (see [`LEGACY_PID_FILE_NAME`]).
/// Called on stop-convergence so an old-build leftover can't linger. A missing file is
/// fine; any error is ignored (this is pure hygiene, never load-bearing).
pub fn remove_legacy_pid() {
    let _ = fs::remove_file(legacy_pid_path());
}

/// Record the engine child's pid (line 1) AND the exact engine binary path it was
/// spawned from (line 2) — the real xmrig / SRBMiner / kawpowminer / AlphaMiner (the
/// process that eats CPU) — so `stop` can (a) reach it when the CLI parent's pid file
/// is stale AND (b) RE-VERIFY the pid still runs OUR engine before signalling it (never
/// an unrelated process the OS reused that pid for after a parent SIGKILL / reboot).
/// Best-effort: creates the dir if needed; a write failure is non-fatal (mining proceeds
/// — only the child-pid backstop is lost). The file holds ONLY public data: the pid
/// integer + the on-disk engine path — never an address / password / endpoint.
pub fn write_child_pid(pid: u32, engine_path: &Path) {
    let path = child_pid_path();
    if let Some(parent) = path.parent() {
        if fs::create_dir_all(parent).is_err() {
            return;
        }
    }
    let _ = fs::write(&path, format!("{pid}\n{}\n", engine_path.display()));
}

/// Read the recorded engine-child pid (line 1), if the file exists + parses. Tolerates
/// both the current two-line record and a legacy single-line (pid-only) file.
pub fn read_child_pid() -> Option<u32> {
    let body = fs::read_to_string(child_pid_path()).ok()?;
    body.lines().next()?.trim().parse::<u32>().ok()
}

/// Read the engine binary path (line 2) the child was spawned from, if the file carries
/// it (a legacy pid-only file returns `None`). Used by `stop` to verify a live child pid
/// actually runs OUR engine — engine-agnostic — before it is ever signalled.
pub fn read_child_engine_path() -> Option<PathBuf> {
    let body = fs::read_to_string(child_pid_path()).ok()?;
    let line = body.lines().nth(1)?.trim();
    (!line.is_empty()).then(|| PathBuf::from(line))
}

/// Remove the child-pid file, but ONLY if it still names `pid` — so a stale removal
/// can't delete a NEWER child's rendezvous (the same race guard `PidGuard` uses).
/// Best-effort; a missing file is fine.
pub fn remove_child_pid(pid: u32) {
    if read_child_pid() == Some(pid) {
        let _ = fs::remove_file(child_pid_path());
    }
}

/// Run the bundled CLI's `stop --timeout-s <timeout_s>` as a DETACHED background
/// process (NOT a visible terminal — this is a one-shot control command). It signals
/// the terminal miner via its pid file (SIGTERM→SIGKILL) plus the child-pid / orphan
/// backstops, so the GUI's Stop tears down the external miner without a window. Stdio
/// is nulled and the handle dropped immediately (fire-and-forget). Maps a spawn error
/// to a clear `Err` (never panics).
pub fn spawn_cli_stop(cli_path: &Path, timeout_s: u64) -> Result<(), String> {
    Command::new(cli_path)
        .arg("stop")
        .arg("--timeout-s")
        .arg(timeout_s.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_child| ())
        .map_err(|e| format!("failed to run the bundled CLI stop: {e}"))
}

/// The **bundled** engine binary that sits next to the CURRENT executable
/// (`Contents/MacOS/xmrig` on macOS; the install dir elsewhere), if it exists. This
/// is the ONLY xmrig path the `stop` last-resort `pgrep` fallback is ever allowed to
/// match — so it can never kill an unrelated `xmrig` the user runs from elsewhere.
/// `None` when the current exe / its dir can't be resolved or no sibling xmrig exists.
pub fn bundled_xmrig_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let cand = dir.join(crate::binaries::XMRIG_BINARY_NAME);
    cand.is_file().then_some(cand)
}

/// Build the **secret-free** `start` argv the terminal launcher runs: always
/// `start --lane <lane_arg>`, plus `--gpus <ids>` when a specific GPU subset was
/// chosen (`gpus_csv = Some("0,1")`). `lane_arg` is [`crate::lane::Lane::cli_lane_arg`]
/// (e.g. `prl`/`alpha`/`xmr`/`rvn`). NEVER carries a password / address — the CLI
/// prompts for the wallet-unlock password interactively in its own terminal.
pub fn terminal_start_args(lane_arg: &str, gpus_csv: Option<&str>) -> Vec<String> {
    let mut args = vec!["start".to_string(), "--lane".to_string(), lane_arg.to_string()];
    if let Some(csv) = gpus_csv {
        if !csv.is_empty() {
            args.push("--gpus".to_string());
            args.push(csv.to_string());
        }
    }
    args
}

/// Shell-escape a single argument for a POSIX `/bin/sh -c` command line by wrapping
/// it in single quotes and escaping any embedded single quote as the standard
/// `'\''` sequence. Safe for arbitrary paths/values (spaces, `"`, `$`, `;`, …).
pub fn sh_single_quote(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for c in arg.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Escape a string for embedding inside an AppleScript double-quoted string literal
/// (the `do script "<cmd>"` payload): backslash and double-quote are the only
/// metacharacters inside an AppleScript `"..."` literal.
pub fn applescript_quote_inner(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(c),
        }
    }
    out
}

/// Build the POSIX `/bin/sh` command STRING that runs `<cli> <args...>` with every
/// token single-quote-escaped (so a path with spaces / a value with shell
/// metacharacters is safe). Shared by the macOS (AppleScript) + Linux paths.
fn build_sh_command(cli_path: &Path, args: &[String]) -> String {
    let mut cmd = sh_single_quote(&cli_path.to_string_lossy());
    for a in args {
        cmd.push(' ');
        cmd.push_str(&sh_single_quote(a));
    }
    cmd
}

/// Build the `osascript -e <script>` argv for macOS: open Terminal.app and run the
/// (sh-escaped, then AppleScript-escaped) miner command in a new window. Returns
/// `(program, args)` ready for `Command::new(program).args(args)`.
pub fn build_macos_osascript(cli_path: &Path, args: &[String]) -> (String, Vec<String>) {
    let sh_cmd = build_sh_command(cli_path, args);
    let inner = applescript_quote_inner(&sh_cmd);
    let script = format!("tell application \"Terminal\" to do script \"{inner}\"");
    ("osascript".to_string(), vec!["-e".to_string(), script])
}

/// Build the `cmd /C start …` argv for Windows: open a NEW console window
/// (`conhost`) titled "Alice Miner" running the CLI; `cmd /K` keeps the window open
/// after the miner exits so the user can read the final output. Returns
/// `(program, args)`.
///
/// The first quoted token after `start` is the window TITLE (a `start` quirk — an
/// unquoted path with spaces would otherwise be mis-parsed as the title), so we
/// pass an explicit "Alice Miner" title, then `cmd /K`, then the CLI + args. We do
/// NOT shell-escape the individual args into one string (cmd quoting is a minefield);
/// instead each is a distinct argv element so `Command` quotes them correctly.
pub fn build_windows_argv(cli_path: &Path, args: &[String]) -> (String, Vec<String>) {
    let mut argv: Vec<String> = vec![
        "/C".to_string(),
        "start".to_string(),
        "Alice Miner".to_string(), // window title (the quoted first token)
        "cmd".to_string(),
        "/K".to_string(),
        cli_path.to_string_lossy().to_string(),
    ];
    argv.extend(args.iter().cloned());
    ("cmd".to_string(), argv)
}

/// The ordered list of Linux terminal emulators to try, each with the flag that
/// precedes the command to run. `x-terminal-emulator` (the Debian alternatives
/// symlink) first, then GNOME Terminal, then xterm — the first that exists wins.
/// All three accept "everything after the flag is the program + its args" so the
/// CLI + args are passed as DISTINCT argv elements (no shell-escaping needed).
pub const LINUX_TERMINALS: &[(&str, &str)] = &[
    ("x-terminal-emulator", "-e"),
    ("gnome-terminal", "--"),
    ("xterm", "-e"),
];

/// Build the argv for a specific Linux terminal `(program, flag)` running
/// `<cli> <args…>`. The CLI path + each arg are distinct argv elements after the
/// flag (so spaces are safe without shell quoting). Returns `(program, args)`.
pub fn build_unix_terminal_argv(
    program: &str,
    flag: &str,
    cli_path: &Path,
    args: &[String],
) -> (String, Vec<String>) {
    let mut argv = vec![flag.to_string(), cli_path.to_string_lossy().to_string()];
    argv.extend(args.iter().cloned());
    (program.to_string(), argv)
}

/// Whether `program` exists on `PATH` (Unix): scan `$PATH` for an executable file.
/// Used to pick the first available Linux terminal. Best-effort + fail-safe (a
/// missing/empty PATH simply yields `false`).
#[cfg(all(unix, not(target_os = "macos")))]
fn program_on_path(program: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        let candidate = dir.join(program);
        candidate.is_file()
    })
}

/// Open the platform terminal running `<cli_path> <args…>` in a NEW visible window.
/// `args` MUST be secret-free (the brief: only `start --lane <lane> [--gpus <ids>]`).
///
/// * **macOS** — `osascript` drives Terminal.app's `do script`.
/// * **Windows** — `cmd /C start "Alice Miner" cmd /K <cli> <args>` (a new conhost).
/// * **Linux** — the first of `x-terminal-emulator -e` / `gnome-terminal --` /
///   `xterm -e` found on `PATH`.
///
/// Returns `Ok(())` once the window-spawn command was launched; `Err(String)` (never
/// a panic) when no terminal program is available or the spawn failed. NOTE: success
/// means the terminal launcher process started — the miner's own success/failure is
/// then visible IN that terminal (the whole point of this path).
pub fn spawn_in_terminal(cli_path: &Path, args: &[String]) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let (program, argv) = build_macos_osascript(cli_path, args);
        spawn_detached(&program, &argv)
    }
    #[cfg(target_os = "windows")]
    {
        let (program, argv) = build_windows_argv(cli_path, args);
        spawn_detached(&program, &argv)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        // Try each known terminal in order; use the first that's on PATH.
        for (prog, flag) in LINUX_TERMINALS {
            if program_on_path(prog) {
                let (program, argv) = build_unix_terminal_argv(prog, flag, cli_path, args);
                return spawn_detached(&program, &argv);
            }
        }
        Err(
            "no terminal program found (tried x-terminal-emulator, gnome-terminal, xterm) — \
             install one, or run `alice-miner-cli start` yourself in a terminal."
                .to_string(),
        )
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", all(unix, not(target_os = "macos")))))]
    {
        let _ = (cli_path, args);
        Err("opening a terminal isn't supported on this platform".to_string())
    }
}

/// Spawn `program` with `argv` detached (stdio nulled — the spawned terminal owns
/// its own console). The handle is dropped immediately; the terminal window
/// outlives this process. Maps any spawn error to a clear `Err` (never panics).
#[allow(dead_code)]
fn spawn_detached(program: &str, argv: &[String]) -> Result<(), String> {
    Command::new(program)
        .args(argv)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_child| ())
        .map_err(|e| format!("failed to open a terminal via `{program}`: {e}"))
}

// ── Minimal libc binding (unix) ───────────────────────────────────────────────
// [`pid_is_alive`] needs only `kill(2)`; binding it directly avoids adding a `libc` /
// `nix` dependency (mirrors the CLI's `pidfile` module, which does the same).
#[cfg(unix)]
extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn cli() -> PathBuf {
        PathBuf::from("/Applications/Alice Miner.app/Contents/MacOS/alice-miner-cli")
    }

    #[test]
    fn sh_single_quote_wraps_and_escapes() {
        assert_eq!(sh_single_quote("plain"), "'plain'");
        // A space-bearing path stays inside ONE quoted token.
        assert_eq!(sh_single_quote("/a b/c"), "'/a b/c'");
        // An embedded single quote becomes the '\'' sequence.
        assert_eq!(sh_single_quote("a'b"), "'a'\\''b'");
        // Shell metacharacters are inert inside single quotes.
        assert_eq!(sh_single_quote("$(rm -rf /)"), "'$(rm -rf /)'");
        assert_eq!(sh_single_quote("a;b|c&d"), "'a;b|c&d'");
    }

    #[test]
    fn applescript_quote_escapes_backslash_and_quote() {
        assert_eq!(applescript_quote_inner("plain"), "plain");
        assert_eq!(applescript_quote_inner("a\"b"), "a\\\"b");
        assert_eq!(applescript_quote_inner("a\\b"), "a\\\\b");
    }

    #[test]
    fn macos_osascript_argv_is_escaped_and_secret_free() {
        let args = vec![
            "start".to_string(),
            "--lane".to_string(),
            "prl".to_string(),
            "--gpus".to_string(),
            "0,1".to_string(),
        ];
        let (program, argv) = build_macos_osascript(&cli(), &args);
        assert_eq!(program, "osascript");
        assert_eq!(argv.len(), 2);
        assert_eq!(argv[0], "-e");
        let script = &argv[1];
        // Drives Terminal.app's `do script`.
        assert!(script.starts_with("tell application \"Terminal\" to do script \""));
        // The CLI path (with its space) is single-quoted inside the sh command, and
        // the surrounding AppleScript quotes are escaped.
        assert!(script.contains("'/Applications/Alice Miner.app/Contents/MacOS/alice-miner-cli'"));
        // The full secret-free argv is present, in order.
        assert!(script.contains("start"));
        assert!(script.contains("--lane"));
        assert!(script.contains("prl"));
        assert!(script.contains("--gpus"));
        assert!(script.contains("0,1"));
        // SECRET-FREE: no password / address vocabulary ever appears.
        let lower = script.to_lowercase();
        for forbidden in ["--password", "password", "prl1p", "seed", "mnemonic"] {
            assert!(!lower.contains(forbidden), "argv leaked `{forbidden}`: {script}");
        }
    }

    #[test]
    fn macos_osascript_handles_quote_in_path() {
        // A pathological path containing a single quote stays one sh token AND its
        // AppleScript quoting is intact (no panic, no broken script).
        let weird = PathBuf::from("/od'd/alice-miner-cli");
        let args = vec!["start".to_string(), "--lane".to_string(), "xmr".to_string()];
        let (_p, argv) = build_macos_osascript(&weird, &args);
        let script = &argv[1];
        // The sh single-quote escape (the 4-char sequence  '\''  ) survives into the
        // AppleScript literal with its backslash DOUBLED by AppleScript escaping, so
        // the on-screen sh command reads back as  '/od'\''d/alice-miner-cli'  . The
        // Rust literal below encodes  '/od'\\''d/alice-miner-cli'  (two backslashes).
        assert!(
            script.contains("'/od'\\\\''d/alice-miner-cli'"),
            "quote-in-path not escaped as expected: {script}"
        );
    }

    #[test]
    fn windows_argv_titles_window_and_keeps_open() {
        let win_cli = PathBuf::from("C:\\Program Files\\Alice Miner\\alice-miner-cli.exe");
        let args = vec!["start".to_string(), "--lane".to_string(), "prl".to_string()];
        let (program, argv) = build_windows_argv(&win_cli, &args);
        assert_eq!(program, "cmd");
        // /C start "Alice Miner" cmd /K <cli> start --lane prl
        assert_eq!(argv[0], "/C");
        assert_eq!(argv[1], "start");
        assert_eq!(argv[2], "Alice Miner"); // window title (Command quotes it)
        assert_eq!(argv[3], "cmd");
        assert_eq!(argv[4], "/K");
        assert_eq!(argv[5], "C:\\Program Files\\Alice Miner\\alice-miner-cli.exe");
        assert_eq!(&argv[6..], &["start", "--lane", "prl"]);
        // SECRET-FREE.
        for tok in &argv {
            let l = tok.to_lowercase();
            assert!(!l.contains("password") && !l.contains("prl1p"), "leaked secret: {tok}");
        }
    }

    #[test]
    fn unix_terminal_argv_passes_cli_and_args_after_flag() {
        let lin_cli = PathBuf::from("/opt/alice/alice-miner-cli");
        let args = vec!["start".to_string(), "--lane".to_string(), "alpha".to_string()];
        let (program, argv) = build_unix_terminal_argv("gnome-terminal", "--", &lin_cli, &args);
        assert_eq!(program, "gnome-terminal");
        // The flag precedes the program + its args (distinct argv elements).
        assert_eq!(argv[0], "--");
        assert_eq!(argv[1], "/opt/alice/alice-miner-cli");
        assert_eq!(&argv[2..], &["start", "--lane", "alpha"]);
        // xterm/x-terminal-emulator use -e the same way.
        let (_p, argv2) = build_unix_terminal_argv("xterm", "-e", &lin_cli, &args);
        assert_eq!(argv2[0], "-e");
        assert_eq!(argv2[1], "/opt/alice/alice-miner-cli");
    }

    #[test]
    fn linux_terminal_table_is_in_priority_order() {
        // The documented fallback order: x-terminal-emulator → gnome-terminal → xterm.
        let names: Vec<&str> = LINUX_TERMINALS.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, vec!["x-terminal-emulator", "gnome-terminal", "xterm"]);
        // GNOME uses `--`; the others use `-e`.
        for (name, flag) in LINUX_TERMINALS {
            if *name == "gnome-terminal" {
                assert_eq!(*flag, "--");
            } else {
                assert_eq!(*flag, "-e");
            }
        }
    }

    #[test]
    fn terminal_start_args_is_secret_free_and_omits_gpus_by_default() {
        // No subset → just `start --lane <lane>` (every card; argv unchanged).
        assert_eq!(
            terminal_start_args("prl", None),
            vec!["start", "--lane", "prl"]
        );
        // An empty CSV is treated as "all cards" (no --gpus appended).
        assert_eq!(
            terminal_start_args("xmr", Some("")),
            vec!["start", "--lane", "xmr"]
        );
        // A real subset appends --gpus <ids>.
        assert_eq!(
            terminal_start_args("alpha", Some("0,2")),
            vec!["start", "--lane", "alpha", "--gpus", "0,2"]
        );
        // SECRET-FREE under every shape.
        for args in [
            terminal_start_args("prl", Some("1")),
            terminal_start_args("rvn", None),
        ] {
            for tok in &args {
                let l = tok.to_lowercase();
                assert!(
                    !l.contains("password") && !l.contains("prl1p") && !l.contains("seed"),
                    "leaked secret token: {tok}"
                );
            }
        }
    }

    #[test]
    fn cli_bin_name_matches_platform() {
        if cfg!(windows) {
            assert_eq!(CLI_BIN_NAME, "alice-miner-cli.exe");
        } else {
            assert_eq!(CLI_BIN_NAME, "alice-miner-cli");
        }
    }

    /// A unique temp dir for one env-scoped test (`$ALICE_IDENTITY_DIR` is
    /// process-global, so these tests take the crate env lock and never run
    /// concurrently — see `crate::IDENTITY_ENV_LOCK`).
    fn temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "alice-terminal-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    /// The telemetry + child-pid paths sit under `$ALICE_IDENTITY_DIR` (honoring the
    /// override), co-located with the identity pointer — never the real `~/.alice`.
    #[test]
    fn telemetry_and_child_pid_paths_honor_override() {
        let _g = crate::IDENTITY_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = temp_dir("paths");
        std::env::set_var("ALICE_IDENTITY_DIR", &tmp);
        assert_eq!(telemetry_path(), tmp.join(TELEMETRY_FILE_NAME));
        assert_eq!(child_pid_path(), tmp.join(CHILD_PID_FILE_NAME));
        // The two basenames are distinct + stable.
        assert_eq!(TELEMETRY_FILE_NAME, "miner-cli.snapshot.json");
        assert_eq!(CHILD_PID_FILE_NAME, "miner-child.pid");
        std::env::remove_var("ALICE_IDENTITY_DIR");
    }

    /// write_child_pid → read_child_pid/read_child_engine_path round-trips the pid AND
    /// the exact engine path (engine-agnostic), tolerates a legacy pid-only file, and
    /// remove_child_pid clears it — but ONLY when the file still names that pid.
    #[test]
    fn child_pid_write_read_remove_round_trip() {
        let _g = crate::IDENTITY_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = temp_dir("childpid");
        std::env::set_var("ALICE_IDENTITY_DIR", &tmp);

        assert_eq!(read_child_pid(), None); // nothing yet
        assert_eq!(read_child_engine_path(), None);

        // Records BOTH the pid (line 1) and the exact engine path (line 2) — here
        // SRBMiner, to prove the backstop is engine-agnostic (not xmrig-only).
        let engine = std::path::Path::new("/opt/AliceMiner/Contents/MacOS/SRBMiner-MULTI");
        write_child_pid(4242, engine);
        assert_eq!(read_child_pid(), Some(4242));
        assert_eq!(read_child_engine_path().as_deref(), Some(engine));

        // The file carries ONLY public data: the pid integer + on-disk engine path.
        let body = std::fs::read_to_string(child_pid_path()).unwrap();
        assert_eq!(body.lines().next(), Some("4242"));
        assert!(body.contains("SRBMiner-MULTI"));
        assert!(!body.to_lowercase().contains("password"));

        // A LEGACY single-line (pid-only) file written by a pre-fix binary still reads
        // back its pid (upgrade tolerance); it simply carries no engine path.
        std::fs::write(child_pid_path(), "777").unwrap();
        assert_eq!(read_child_pid(), Some(777));
        assert_eq!(read_child_engine_path(), None);

        // Re-establish the two-line record for the remove-race assertions.
        write_child_pid(4242, engine);
        // remove_child_pid(other) is a no-op — it must not delete a DIFFERENT child's
        // rendezvous (the race guard).
        remove_child_pid(9999);
        assert_eq!(read_child_pid(), Some(4242));
        // remove_child_pid(matching) clears it.
        remove_child_pid(4242);
        assert_eq!(read_child_pid(), None);

        std::env::remove_var("ALICE_IDENTITY_DIR");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// The CLI-parent + legacy pid paths sit under `$ALICE_IDENTITY_DIR`, co-located
    /// with the identity pointer + the other rendezvous files, with stable basenames
    /// matching the CLI's own `pidfile` module.
    #[test]
    fn cli_and_legacy_pid_paths_honor_override() {
        let _g = crate::IDENTITY_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = temp_dir("cli-legacy");
        std::env::set_var("ALICE_IDENTITY_DIR", &tmp);
        assert_eq!(cli_pid_path(), tmp.join(CLI_PID_FILE_NAME));
        assert_eq!(legacy_pid_path(), tmp.join(LEGACY_PID_FILE_NAME));
        assert_eq!(CLI_PID_FILE_NAME, "miner-cli.pid");
        assert_eq!(LEGACY_PID_FILE_NAME, "miner.pid");
        std::env::remove_var("ALICE_IDENTITY_DIR");
    }

    /// `pid_is_alive` detects THIS process as alive and a very high unused pid as dead
    /// (unix); pid 0 (a process-group address, never a single miner) reports not-alive.
    #[test]
    fn pid_is_alive_detects_self_and_missing() {
        assert!(pid_is_alive(std::process::id()), "our own pid is alive");
        assert!(!pid_is_alive(0), "pid 0 is a group address, not a live miner");
        #[cfg(unix)]
        {
            // A pid near the top of the space is (essentially certainly) unused.
            assert!(!pid_is_alive(0x7FFF_FFFE), "a very high pid is not alive");
        }
    }

    /// `terminal_pids_alive` is TRUE iff the CLI-parent OR engine-child pid file names a
    /// LIVE process — stronger than `terminal_pids_absent` (file existence only): a STALE
    /// pid file from a dead process reads as NOT alive. It never inspects a bundle path,
    /// so an AppTranslocation-mounted engine is recognised the same as any other.
    /// Unix-only: the "dead pid → not alive" leg relies on `kill(pid, 0)`; on non-unix the
    /// probe fail-safes to always-alive (a different, intentionally weaker contract).
    #[cfg(unix)]
    #[test]
    fn terminal_pids_alive_requires_a_live_process_not_just_a_file() {
        let _g = crate::IDENTITY_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = temp_dir("pids-alive");
        std::fs::create_dir_all(&tmp).unwrap();
        std::env::set_var("ALICE_IDENTITY_DIR", &tmp);

        // No files → not alive.
        assert!(!terminal_pids_alive(), "no pid files → not alive");

        // A STALE cli-pid file naming a dead process → still NOT alive (the crash/kill
        // case: the file lingers but nothing runs). 2147483646 (0x7FFF_FFFE) is unused.
        std::fs::write(cli_pid_path(), "2147483646\n").unwrap();
        assert!(!terminal_pids_alive(), "a dead pid in the file → not alive");

        // Our OWN pid in the CLI-parent file → alive (a live parent counts). The child-pid
        // path also records an engine binary path we DON'T inspect for liveness.
        std::fs::write(cli_pid_path(), format!("{}\n", std::process::id())).unwrap();
        assert!(terminal_pids_alive(), "a live cli-parent pid → alive");

        // Only a live CHILD (engine) pid, no cli-parent file → alive via the child path.
        std::fs::remove_file(cli_pid_path()).unwrap();
        write_child_pid(
            std::process::id(),
            std::path::Path::new(
                "/private/var/folders/xx/AppTranslocation/ABC/d/AliceMiner.app/Contents/MacOS/xmrig",
            ),
        );
        assert!(
            terminal_pids_alive(),
            "a live engine-child pid at an AppTranslocation path → alive (path never inspected)"
        );

        std::env::remove_var("ALICE_IDENTITY_DIR");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// `snapshot_age_at` reports `None` for a missing file and a small, non-None age for a
    /// just-written one — the CLI's own write clock (the file mtime) the GUI reads instead
    /// of its own poll clock. `snapshot_age` resolves the canonical path under the override.
    #[test]
    fn snapshot_age_tracks_file_mtime() {
        let _g = crate::IDENTITY_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = temp_dir("snap-age");
        std::fs::create_dir_all(&tmp).unwrap();
        let f = tmp.join("miner-cli.snapshot.json");

        // Missing file → None (nothing to attach to).
        assert!(snapshot_age_at(&f).is_none(), "missing file → None");

        // Just written → a small, non-None age (well under any staleness window).
        std::fs::write(&f, b"{}").unwrap();
        let age = snapshot_age_at(&f).expect("a written file has an age");
        assert!(age < std::time::Duration::from_secs(5), "a fresh file reads fresh: {age:?}");

        // The canonical `snapshot_age()` resolves through `$ALICE_IDENTITY_DIR` (never real
        // `~/.alice`): with the override set to our temp dir and the file present there, it
        // returns the same fresh age.
        std::env::set_var("ALICE_IDENTITY_DIR", &tmp);
        assert_eq!(telemetry_path(), f);
        assert!(snapshot_age().is_some(), "canonical age resolves under the override");
        std::env::remove_var("ALICE_IDENTITY_DIR");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// `terminal_pids_absent` is the stop-convergence signal: TRUE only when NEITHER the
    /// CLI-parent nor the engine-child pid file exists. A lingering final telemetry file
    /// is irrelevant to it (it probes pid files only). `remove_legacy_pid` sweeps the old
    /// `miner.pid` and is a no-op when none exists.
    #[test]
    fn terminal_pids_absent_tracks_both_pid_files_and_legacy_sweep() {
        let _g = crate::IDENTITY_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = temp_dir("pids-absent");
        std::fs::create_dir_all(&tmp).unwrap();
        std::env::set_var("ALICE_IDENTITY_DIR", &tmp);

        // Nothing written yet → absent.
        assert!(terminal_pids_absent(), "no pid files → absent");

        // The CLI-parent pid alone → NOT absent (the CLI is still winding down).
        std::fs::write(cli_pid_path(), "12345").unwrap();
        assert!(!terminal_pids_absent(), "cli-pid present → not converged");

        // Add the engine-child pid → still not absent.
        write_child_pid(12346, std::path::Path::new("/x/xmrig"));
        assert!(!terminal_pids_absent());

        // Remove the CLI-parent pid but keep the child → still not absent (the belt).
        std::fs::remove_file(cli_pid_path()).unwrap();
        assert!(!terminal_pids_absent(), "child-pid alone → not converged");

        // Remove the child too → BOTH gone → converged.
        std::fs::remove_file(child_pid_path()).unwrap();
        assert!(terminal_pids_absent(), "both pid files gone → converged");

        // remove_legacy_pid: a no-op when absent, and clears a residual one.
        remove_legacy_pid(); // no legacy file — must not panic
        std::fs::write(legacy_pid_path(), "999").unwrap();
        assert!(legacy_pid_path().exists());
        remove_legacy_pid();
        assert!(!legacy_pid_path().exists(), "legacy miner.pid swept");

        std::env::remove_var("ALICE_IDENTITY_DIR");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
