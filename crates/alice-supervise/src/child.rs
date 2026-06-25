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

/// The minimal, non-secret environment variables the spawned miner child is
/// allowed to inherit (audit S-1). Everything else is cleared. These let the
/// engine find shared libraries + a scratch/cache dir on each OS; none carries a
/// secret. The list is intentionally small and OS-conditional.
#[cfg(unix)]
const ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    // GPU/driver discovery for the (Linux) RVN lane; harmless/absent elsewhere.
    "LD_LIBRARY_PATH",
    "DISPLAY",
    "XAUTHORITY",
    "CUDA_VISIBLE_DEVICES",
    "NVIDIA_VISIBLE_DEVICES",
];
#[cfg(windows)]
const ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "SystemRoot",
    "SystemDrive",
    "WINDIR",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "LOCALAPPDATA",
    "APPDATA",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
];
#[cfg(not(any(unix, windows)))]
const ENV_ALLOWLIST: &[&str] = &["PATH"];

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
            // On Windows there is no process group / graceful CTRL_BREAK without a
            // console group, so the graceful phase is just the grace window; the
            // force path below terminates the whole process TREE.
        }

        // Bounded wait for graceful exit.
        let waited = tokio::time::timeout(grace, self.child.wait()).await;
        let code = match waited {
            Ok(Ok(status)) => Some(status.code().unwrap_or(-1)),
            _ => {
                // Force-kill the whole process TREE (not just the recorded PID), so
                // a miner that spawned helper processes can't leave them orphaned
                // (consuming the GPU) after Stop.
                #[cfg(unix)]
                self.force_kill_group_unix();
                #[cfg(windows)]
                self.force_kill_tree_windows();
                #[cfg(not(any(unix, windows)))]
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
        // SIGTERM to the child's PROCESS GROUP (negative pid). The child is its own
        // group leader (pgid==pid, set via setpgid(0,0) at spawn), so this reaches
        // the miner AND any helper it spawned — signaling only the PID would orphan
        // grandchildren. Safety: the group is exclusively our spawned subtree.
        let pid = self.pid as i32;
        unsafe {
            libc_kill(-pid, 15);
        }
    }

    /// SIGKILL the child's whole process group (force path).
    #[cfg(unix)]
    fn force_kill_group_unix(&self) {
        let pid = self.pid as i32;
        unsafe {
            libc_kill(-pid, 9);
        }
    }

    /// Terminate the child + its entire process tree on Windows (no process groups
    /// there; `taskkill /T` walks and kills descendants, so helper miners can't be
    /// orphaned). A blunt but reliable teardown that needs no Win32 FFI.
    #[cfg(windows)]
    fn force_kill_tree_windows(&self) {
        let _ = std::process::Command::new("taskkill")
            .args(["/T", "/F", "/PID", &self.pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
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

    // Audit S-1: scrub the child's environment. We `env_clear()` first, then
    // re-add ONLY a minimal, non-secret allowlist (the few vars a miner actually
    // needs to find libs / a scratch dir), plus the explicit entries the caller
    // passes. This guarantees the miner child inherits NONE of this process's
    // environment — so a future change that ever placed a secret in our env can't
    // leak it to the engine. Today nothing secret is ever in our env, so this is
    // pure hardening (no behaviour change for the proven argv-only launch).
    cmd.env_clear();
    for key in ENV_ALLOWLIST {
        if let Some(val) = std::env::var_os(key) {
            cmd.env(key, val);
        }
    }
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
    // Only the `#[cfg(unix)]` spawn tests below use this (Windows skips them → the
    // import would be unused there under `-D warnings`).
    #[cfg(unix)]
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

    /// Audit S-1: the spawned child must NOT inherit this process's environment.
    /// We set a fake "secret" in the parent env, spawn a child that echoes it,
    /// and confirm the child sees it EMPTY (env was cleared) while an allowlisted
    /// var (PATH) is still present.
    #[cfg(unix)]
    #[test]
    fn child_env_is_scrubbed_to_allowlist() {
        let rt = rt();
        rt.block_on(async {
            // A secret that must NOT cross into the child.
            std::env::set_var("ALICE_TEST_FAKE_SECRET", "do-not-leak");
            let (tx, mut rx) = unbounded_channel();
            let child = spawn_supervised(
                Path::new("/bin/sh"),
                &[
                    "-c".to_string(),
                    // Print the secret (should be empty) and whether PATH is set.
                    "echo \"SECRET=[${ALICE_TEST_FAKE_SECRET}]\"; \
                     if [ -n \"$PATH\" ]; then echo PATH_PRESENT; else echo PATH_MISSING; fi"
                        .to_string(),
                ],
                &[],
                None,
                tx,
            )
            .expect("spawn");

            let mut saw_secret_empty = false;
            let mut saw_path_present = false;
            // Drain the few lines the child prints.
            for _ in 0..4 {
                match tokio::time::timeout(Duration::from_secs(3), rx.recv()).await {
                    Ok(Some(line)) => {
                        if line.text.contains("SECRET=[]") {
                            saw_secret_empty = true;
                        }
                        if line.text.contains("PATH_PRESENT") {
                            saw_path_present = true;
                        }
                    }
                    _ => break,
                }
            }
            let _ = child.stop(Duration::from_secs(2)).await;
            std::env::remove_var("ALICE_TEST_FAKE_SECRET");

            assert!(
                saw_secret_empty,
                "child must NOT inherit the parent's ALICE_TEST_FAKE_SECRET (env_clear)"
            );
            assert!(
                saw_path_present,
                "PATH (allowlisted) must still be available to the child"
            );
        });
    }

    /// An explicit env entry passed by the caller IS applied to the child (the
    /// allowlist scrub doesn't drop caller-supplied vars).
    #[cfg(unix)]
    #[test]
    fn caller_supplied_env_reaches_child() {
        let rt = rt();
        rt.block_on(async {
            let (tx, mut rx) = unbounded_channel();
            let child = spawn_supervised(
                Path::new("/bin/sh"),
                &["-c".to_string(), "echo \"GOT=[${ALICE_EXPLICIT}]\"".to_string()],
                &[("ALICE_EXPLICIT".to_string(), "passed-through".to_string())],
                None,
                tx,
            )
            .expect("spawn");
            let mut ok = false;
            for _ in 0..3 {
                match tokio::time::timeout(Duration::from_secs(3), rx.recv()).await {
                    Ok(Some(line)) if line.text.contains("GOT=[passed-through]") => {
                        ok = true;
                        break;
                    }
                    Ok(Some(_)) => continue,
                    _ => break,
                }
            }
            let _ = child.stop(Duration::from_secs(2)).await;
            assert!(ok, "caller-supplied env var must reach the child");
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
