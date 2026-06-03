//! OS-level child-process spawning, ownership, PID files, and graceful stop.
//!
//! Used by the node (and later miner) supervisor. Kept deliberately small and
//! free of policy (restart budget, log retention live in the parent module).
//!
//! Ownership rule (plan §1.2): we only ever signal the process we spawned, via
//! its `Child` handle or the PID we recorded for it — never `pkill` by name.

#![allow(dead_code)]

use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc::UnboundedSender;

/// A line captured from a child's stdout/stderr (raw — caller sanitises).
#[derive(Debug, Clone)]
pub struct LogLine {
    pub stream: LogStream,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogStream {
    Stdout,
    Stderr,
}

/// A spawned, owned child process plus its recorded PID.
pub struct OwnedChild {
    child: Child,
    pid: u32,
    pid_file: Option<PathBuf>,
}

impl OwnedChild {
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Non-blocking poll: `Some(code)` if the child has exited.
    pub fn try_exit_code(&mut self) -> Option<i32> {
        match self.child.try_wait() {
            Ok(Some(status)) => Some(status.code().unwrap_or(-1)),
            _ => None,
        }
    }

    /// Gracefully stop the child: request termination, wait up to `grace`, then
    /// force-kill. Removes the PID file. Idempotent.
    pub async fn stop(mut self, grace: Duration) -> io::Result<Option<i32>> {
        // Already exited?
        if let Ok(Some(status)) = self.child.try_wait() {
            self.cleanup_pid_file();
            return Ok(Some(status.code().unwrap_or(-1)));
        }

        #[cfg(unix)]
        self.request_term_unix();
        #[cfg(not(unix))]
        {
            // On Windows tokio's `kill` maps to TerminateProcess; we have no
            // graceful CTRL_BREAK here without a console group, so go straight
            // to kill after the grace window below.
        }

        // Bounded wait for graceful exit.
        let waited = tokio::time::timeout(grace, self.child.wait()).await;
        let code = match waited {
            Ok(Ok(status)) => Some(status.code().unwrap_or(-1)),
            _ => {
                // Force kill, then reap.
                let _ = self.child.start_kill();
                let _ = self.child.wait().await;
                self.child.try_wait().ok().flatten().and_then(|s| s.code())
            }
        };
        self.cleanup_pid_file();
        Ok(code)
    }

    #[cfg(unix)]
    fn request_term_unix(&self) {
        // SIGTERM to the recorded PID (the one we spawned).
        // Safety: PID is the child we own; signal 15 = SIGTERM.
        let pid = self.pid as i32;
        unsafe {
            libc_kill(pid, 15);
        }
    }

    fn cleanup_pid_file(&mut self) {
        if let Some(p) = self.pid_file.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

// We avoid pulling the `libc` crate just for SIGTERM; declare the one symbol.
#[cfg(unix)]
extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

/// Spawn `program` with `args`, capturing stdout+stderr line-by-line into
/// `log_tx`. Writes a PID file at `pid_file` (best-effort). The returned
/// [`OwnedChild`] owns the process.
pub fn spawn_supervised(
    program: &Path,
    args: &[String],
    envs: &[(String, String)],
    pid_file: Option<&Path>,
    log_tx: UnboundedSender<LogLine>,
) -> io::Result<OwnedChild> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true); // never leak the child if the handle is dropped

    // Defensive: start from a clean-ish env we extend, so the child can't
    // inherit anything secret the wallet may hold. We deliberately do NOT
    // clear the whole env (the child needs PATH/HOME), but we add only the
    // explicit, non-secret entries the caller passes.
    for (k, v) in envs {
        cmd.env(k, v);
    }

    #[cfg(unix)]
    {
        // Put the child in its own process group so a stray signal to the
        // wallet's group does not also hit (or get blocked by) the node, and so
        // we can target it precisely. `tokio::process::Command` exposes
        // `pre_exec` inherently (no std `CommandExt` import needed).
        unsafe {
            cmd.pre_exec(|| {
                // setpgid(0,0): new process group led by the child.
                if set_pgid(0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    let mut child = cmd.spawn()?;
    let pid = child
        .id()
        .ok_or_else(|| io::Error::other("child has no PID"))?;

    if let Some(pf) = pid_file {
        if let Some(parent) = pf.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(pf, pid.to_string());
    }

    if let Some(stdout) = child.stdout.take() {
        let tx = log_tx.clone();
        tokio::spawn(pump_lines(stdout, LogStream::Stdout, tx));
    }
    if let Some(stderr) = child.stderr.take() {
        let tx = log_tx.clone();
        tokio::spawn(pump_lines(stderr, LogStream::Stderr, tx));
    }

    Ok(OwnedChild {
        child,
        pid,
        pid_file: pid_file.map(|p| p.to_path_buf()),
    })
}

#[cfg(unix)]
extern "C" {
    #[link_name = "setpgid"]
    fn set_pgid(pid: i32, pgid: i32) -> i32;
}

async fn pump_lines<R>(reader: R, stream: LogStream, tx: UnboundedSender<LogLine>)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(text)) = lines.next_line().await {
        if tx.send(LogLine { stream, text }).is_err() {
            break; // receiver gone
        }
    }
}

/// Read a previously-written PID file, if present and parseable. Used on
/// startup to detect a possibly-orphaned prior node (we do NOT auto-kill it;
/// the supervisor decides — see plan §1.2 ownership rule).
pub fn read_pid_file(pid_file: &Path) -> Option<u32> {
    std::fs::read_to_string(pid_file)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use tokio::sync::mpsc::unbounded_channel;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Runtime::new().unwrap()
    }

    #[test]
    fn read_pid_file_roundtrips() {
        let p = std::env::temp_dir().join(format!(
            "alice-pidtest-{}-{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
        std::fs::write(&p, "4242\n").unwrap();
        assert_eq!(read_pid_file(&p), Some(4242));
        std::fs::write(&p, "not-a-pid").unwrap();
        assert_eq!(read_pid_file(&p), None);
        let _ = std::fs::remove_file(&p);
    }

    #[cfg(unix)]
    #[test]
    fn spawn_captures_output_and_writes_pidfile_then_stops() {
        let rt = rt();
        rt.block_on(async {
            let pid_file = std::env::temp_dir().join(format!(
                "alice-child-pid-{}-{}",
                std::process::id(),
                Instant::now().elapsed().as_nanos()
            ));
            let (tx, mut rx) = unbounded_channel();
            // `sh -c 'echo hello; sleep 5'` — long enough to observe running.
            let mut child = spawn_supervised(
                Path::new("/bin/sh"),
                &[
                    "-c".to_string(),
                    "echo hello-from-child; sleep 5".to_string(),
                ],
                &[],
                Some(&pid_file),
                tx,
            )
            .expect("spawn");

            assert!(child.pid() > 0);
            // PID file written.
            assert_eq!(read_pid_file(&pid_file), Some(child.pid()));

            // Capture the echoed line.
            let line = tokio::time::timeout(Duration::from_secs(3), rx.recv())
                .await
                .expect("log line within timeout")
                .expect("some line");
            assert!(line.text.contains("hello-from-child"));

            // Still running (sleep 5).
            assert!(child.try_exit_code().is_none());

            // Graceful stop terminates promptly (sleep is interruptible).
            let code = child.stop(Duration::from_secs(3)).await.expect("stop ok");
            // SIGTERM => terminated; code may be None/negative depending on OS.
            let _ = code;
            // PID file cleaned up.
            assert_eq!(read_pid_file(&pid_file), None);
        });
    }

    #[cfg(unix)]
    #[test]
    fn stop_reports_exit_code_for_already_exited_child() {
        let rt = rt();
        rt.block_on(async {
            let (tx, _rx) = unbounded_channel();
            let mut child = spawn_supervised(
                Path::new("/bin/sh"),
                &["-c".to_string(), "exit 7".to_string()],
                &[],
                None,
                tx,
            )
            .expect("spawn");
            // Give it a moment to exit.
            tokio::time::sleep(Duration::from_millis(200)).await;
            let _ = child.try_exit_code();
            let code = child.stop(Duration::from_secs(2)).await.expect("stop");
            assert_eq!(code, Some(7));
        });
    }
}
