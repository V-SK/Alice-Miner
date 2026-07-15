//! Force the Windows console to UTF-8 at process start so the CLI's UTF-8 text —
//! especially 中文 — renders correctly in `cmd.exe` / PowerShell regardless of the
//! machine's legacy OEM code page.
//!
//! ## Why this is needed (the root cause)
//!
//! Every user-facing string in the headless `alice-miner-cli` is emitted through
//! `print!` / `println!` / `eprintln!` — i.e. std's `Stdout` / `Stderr`. There is
//! NO raw-handle / `termcolor` / custom-writer path in this workspace that bypasses
//! std (verified by audit; the `--plain` line renderer is pure `print!`, and the
//! interactive TUI uses crossterm). When stdout is a *genuine* console handle,
//! Rust std converts UTF-8 → UTF-16 and calls `WriteConsoleW`, so 中文 renders no
//! matter the console code page.
//!
//! But whenever the *byte* path is taken instead — output redirected to a file or
//! pipe, run under a host that presents stdout as a pipe (MSYS2 / Git-Bash /
//! mintty, VS Code's integrated terminal, ConEmu, …), or console detection
//! otherwise declines — std writes the raw UTF-8 *bytes*, and the console decodes
//! them with its **active output code page**. On a 繁體中文 Windows that page is
//! cp950 (Big5), so the UTF-8 bytes for e.g. "启动" surface as mojibake like
//! "撖摨隞?". Running `chcp 65001` by hand fixes it — exactly what the external
//! tester observed (garbage without it, "明显改善" after it). That the tester's
//! `chcp 65001` changed anything is itself the proof the bytes were reaching the
//! console via the code-page path, not `WriteConsoleW`.
//!
//! [`init_utf8_console`] performs that `chcp 65001` programmatically (via
//! `SetConsoleOutputCP` / `SetConsoleCP`) at the very first instant of `main`,
//! before any output. It is a belt-and-braces guarantee: it makes the byte path
//! render correctly, and is a harmless no-op on the `WriteConsoleW` path, on every
//! non-Windows OS, and whenever no console is attached.

/// UTF-8 code page id (`CP_UTF8`) — the same value `chcp 65001` selects.
#[cfg(windows)]
const CP_UTF8: u32 = 65001;

/// On Windows, set this process's console input + output code pages to UTF-8 so
/// UTF-8 text (incl. 中文) is decoded correctly by the console even on the raw
/// byte path (redirection, pipe-backed hosts, or when std declines
/// `WriteConsoleW`).
///
/// MUST be called before any output — put it first in `main`. Cheap and safe to
/// call more than once.
///
/// Failures are ignored on purpose: with no console attached (a background
/// service), output redirected to a file, or a locked-down environment, there is
/// simply nothing to configure and the byte stream is consumed by a file/pipe that
/// applies no code page. The GUI (egui) never writes 中文 to a console, so it does
/// not call this.
///
/// The original code page is **not** restored on exit, by design:
///
/// * `cmd.exe` does not restore a child's code-page change either, so this only
///   matches native tool behavior (and the user's own `chcp 65001` workaround).
/// * Leaving the console at UTF-8 is benign — UTF-8 is an ASCII superset and this
///   is precisely the state a user reaches by typing `chcp 65001`.
/// * Reliable restoration would need an exit / `Ctrl-C` hook that a hard kill
///   (`taskkill /F`, `SIGKILL`) skips anyway — buying unreliability for no real
///   benefit. Keeping this minimal and reentrancy-free is the better trade.
#[cfg(windows)]
pub fn init_utf8_console() {
    use windows_sys::Win32::System::Console::{SetConsoleCP, SetConsoleOutputCP};
    // SAFETY: both are plain FFI calls into `kernel32` that take a single code-page
    // id and only affect THIS process's attached console. They read/write no memory
    // we own, and a `0` (failure) return — e.g. no console attached, or stdout
    // redirected — is expected and intentionally ignored.
    unsafe {
        // Output CP governs how the bytes we WRITE are decoded to glyphs (the fix
        // for the mojibake). Input CP keeps interactive prompts (identity / setup)
        // that READ 中文 consistent with what is echoed.
        let _ = SetConsoleOutputCP(CP_UTF8);
        let _ = SetConsoleCP(CP_UTF8);
    }
}

/// Non-Windows: nothing to do — POSIX terminals are UTF-8 and std writes UTF-8
/// bytes straight through. Present so call sites need no `#[cfg]` of their own.
#[cfg(not(windows))]
#[inline]
pub fn init_utf8_console() {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Never panics; on non-Windows it is a no-op, and on Windows it best-effort
    /// sets the console code page (itself a no-op when no console is attached, e.g.
    /// in CI). Idempotent — calling it twice is safe.
    #[test]
    fn init_utf8_console_is_safe_and_idempotent() {
        init_utf8_console();
        init_utf8_console();
    }
}
