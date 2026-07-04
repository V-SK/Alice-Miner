//! `alice-miner service --logs [--follow] [--lines N]` — show the background miner log.
//!
//! Backgrounding (via `service --install`) swallows the live dashboard: the launchd /
//! systemd / Task-Scheduler agent runs `start --json` detached and its stdout/stderr go
//! to a single fixed file (macOS: launchd `StandardOutPath`; the path is
//! [`alice_miner_core::service::background_log_path`]). Before this, `--status` only ever
//! said "running" and the log path was never surfaced — so a user had no way to SEE what
//! the background miner was doing. `--logs` prints the last N lines; `--follow` tails it.
//!
//! std-only (no new deps): the follow loop polls the file for growth on a short sleep and
//! prints appended bytes, exiting cleanly on Ctrl-C via the repo's stop-flag pattern
//! (mirrors `fleet.rs` / `serve.rs`). Missing file is handled honestly (a bilingual "no
//! background log yet at <path>"), never a panic. Credit-only: it just relays the log the
//! miner already wrote — it prints no reward figure of its own.

use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use alice_miner_core::tr;

use crate::EXIT_OK;

/// The last `n` lines of `lines` (all of them when `n >= lines.len()`; empty when
/// `n == 0`). Pure + testable — the tail-slicing rule, factored out of the IO so it can
/// be unit-tested over a plain `&[&str]`.
pub fn tail_lines<'a>(lines: &'a [&'a str], n: usize) -> &'a [&'a str] {
    let start = lines.len().saturating_sub(n);
    &lines[start..]
}

/// Print the last `n` lines of the background log, then (when `follow`) tail it until
/// Ctrl-C. Returns a process exit code. Never panics; a missing / unreadable file is an
/// honest bilingual note (not an error exit — an absent log just means "nothing has run
/// in the background yet", which is a normal state).
pub fn run(follow: bool, lines: usize) -> i32 {
    let path = alice_miner_core::service::background_log_path();
    print_tail(&path, lines);
    if follow {
        follow_tail(&path);
    }
    EXIT_OK
}

/// Print the trailing `n` lines of the file at `path`, or the honest "no log yet" note
/// when it is absent / unreadable. Returns the byte length printed up to (the follow
/// loop resumes from there so it never reprints what we just showed).
fn print_tail(path: &Path, n: usize) -> u64 {
    match std::fs::read(path) {
        Ok(bytes) => {
            let text = String::from_utf8_lossy(&bytes);
            // Split into lines WITHOUT a trailing empty element (a file ending in '\n'
            // otherwise yields a phantom blank last line).
            let all: Vec<&str> = if text.is_empty() {
                Vec::new()
            } else {
                text.strip_suffix('\n').unwrap_or(&text).split('\n').collect()
            };
            if all.is_empty() {
                println!(
                    "{} {}",
                    tr!("the background log is empty at", "后台日志为空:"),
                    path.display()
                );
            } else {
                for line in tail_lines(&all, n) {
                    println!("{line}");
                }
            }
            bytes.len() as u64
        }
        Err(_) => {
            // Absent / unreadable: honest "no background log yet" — an absent file is the
            // normal "nothing has been backgrounded" state, not a failure.
            println!(
                "{} {}",
                tr!("no background log yet at", "尚无后台日志:"),
                path.display()
            );
            println!(
                "  {}",
                tr!(
                    "(start the background service first: `alice-miner service --install`)",
                    "(请先启动后台服务: `alice-miner service --install`)"
                )
            );
            0
        }
    }
}

/// Tail `path`, printing appended bytes as they arrive, until Ctrl-C. std-only: poll the
/// file length on a short sleep; when it grows, read + print the new tail; when it
/// SHRINKS (a rotation truncated it in place — see `rotate_background_log_if_oversized`),
/// resume from 0 so we don't miss post-rotation lines. Ctrl-C flips the stop flag (the
/// repo's shared pattern) and we exit clean.
fn follow_tail(path: &Path) {
    let stop = Arc::new(AtomicBool::new(false));
    {
        let f = Arc::clone(&stop);
        // Best-effort: if a handler is already installed (e.g. in a test), just skip —
        // the loop still exits on the natural EOF-less poll when the process is killed.
        let _ = ctrlc::set_handler(move || f.store(true, Ordering::SeqCst));
    }
    println!(
        "{}",
        tr!("— following (Ctrl-C to stop) —", "— 正在跟踪(Ctrl-C 停止)—")
    );
    // Resume from the current EOF so we only print NEW lines from here on.
    let mut offset = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    while !stop.load(Ordering::SeqCst) {
        match std::fs::metadata(path).map(|m| m.len()) {
            Ok(len) if len > offset => {
                offset = print_new_bytes(path, offset).unwrap_or(len);
            }
            Ok(len) if len < offset => {
                // The file was truncated in place (rotation) — resume from the top.
                offset = print_new_bytes(path, 0).unwrap_or(len);
            }
            _ => {}
        }
        // Poll in a short slice so Ctrl-C is responsive without a busy-spin.
        for _ in 0..5 {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// Read `path` from byte `offset` to EOF and print it verbatim (no re-lineation — the
/// bytes already carry their own newlines). Returns the new EOF offset, or an error the
/// caller falls back on. Best-effort flush so a piped consumer sees lines promptly.
fn print_new_bytes(path: &Path, offset: u64) -> std::io::Result<u64> {
    use std::io::{Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut buf = Vec::new();
    let read = f.read_to_end(&mut buf)?;
    if read > 0 {
        let mut out = std::io::stdout();
        let _ = out.write_all(&buf);
        let _ = out.flush();
    }
    Ok(offset + read as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pure tail-slicing rule: last N lines, all when N ≥ len, empty when N == 0.
    #[test]
    fn tail_lines_slices_the_trailing_n() {
        let lines = ["a", "b", "c", "d", "e"];
        assert_eq!(tail_lines(&lines, 2), &["d", "e"]);
        assert_eq!(tail_lines(&lines, 3), &["c", "d", "e"]);
        // N larger than the input → the whole thing (never panics on over-request).
        assert_eq!(tail_lines(&lines, 99), &["a", "b", "c", "d", "e"]);
        assert_eq!(tail_lines(&lines, 5), &["a", "b", "c", "d", "e"]);
        // N == 0 → empty.
        assert_eq!(tail_lines(&lines, 0), &[] as &[&str]);
        // Empty input → empty for any N.
        let empty: [&str; 0] = [];
        assert_eq!(tail_lines(&empty, 3), &[] as &[&str]);
    }

    /// A missing log file prints the honest "no background log yet" note and returns 0
    /// bytes (never a panic / error exit). Uses a path guaranteed not to exist.
    #[test]
    fn print_tail_missing_file_is_honest() {
        let path = std::env::temp_dir().join(format!(
            "alice-no-such-log-{}-{}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        assert!(!path.exists());
        // The function prints to stdout; we only assert it returns 0 and does not panic.
        assert_eq!(print_tail(&path, 50), 0);
    }

    /// `print_tail` over a real file returns the file's byte length and does not panic on
    /// a file that both does and does not end in a newline.
    #[test]
    fn print_tail_reads_a_real_file() {
        let dir = std::env::temp_dir().join(format!("alice-log-tail-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bg.log");
        // Trailing newline → no phantom blank last line.
        std::fs::write(&path, b"line1\nline2\nline3\n").unwrap();
        assert_eq!(print_tail(&path, 2), 18);
        // No trailing newline → still fine.
        std::fs::write(&path, b"only").unwrap();
        assert_eq!(print_tail(&path, 5), 4);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
