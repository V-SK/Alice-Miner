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

use std::path::Path;
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
}
