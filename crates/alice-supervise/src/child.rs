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
    /// Windows: the kill-on-close Job Object this child (and everything it spawns)
    /// is bound to. Dropping it — including via process death, when the OS closes
    /// our handles — terminates the whole job. `None` if the OS refused to create
    /// or assign the job (we then fall back to the taskkill tree walk).
    #[cfg(windows)]
    job: Option<job::JobHandle>,
}

impl OwnedChild {
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Windows: whether this child is bound to a kill-on-close Job Object (i.e.
    /// whether "parent dies → engine dies" is guaranteed by the OS for this child).
    /// Exposed for tests / diagnostics.
    #[cfg(windows)]
    pub fn job_bound(&self) -> bool {
        self.job.is_some()
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
            // force path below terminates the whole process TREE, and the Job Object
            // (dropped with `self` at the end of this fn) is the kernel-enforced
            // backstop if even that fails.
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

/// Windows Job Objects — the OS-enforced "parent dies → engine dies" bond.
///
/// **Why this exists (orphan bug).** On unix the engine is a process-group leader
/// and `kill_on_drop` gives us a Rust-level backstop. Neither helps on Windows:
///   * `kill_on_drop` runs in `Drop`, and `taskkill /F` (which is how the CLI parent
///     is actually terminated, because the graceful path cannot stop a windowless
///     console app) calls `TerminateProcess` — no unwinding, no destructors. So the
///     engine (xmrig / SRBMiner) survived its parent and kept mining on the user's
///     GPU while `stop` printed "no orphan left".
///   * the taskkill tree walk only helps when someone is alive to run it.
///
/// A Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` moves the guarantee into
/// the kernel: when the last handle to the job closes — which the OS does for us
/// when this process dies, however it dies — every process in the job is terminated.
/// Processes the engine itself spawns are in the job too, so helper miners cannot
/// escape either.
///
/// Fail-soft: any failure returns `None` and leaves the previous behaviour intact.
#[cfg(windows)]
mod job {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE};

    /// An owned job handle. Stored as `usize` (not the raw `HANDLE` pointer) so
    /// `OwnedChild` stays `Send`/`Sync`; a Windows handle is a process-wide token,
    /// not a thread-affine pointer, so this is sound.
    pub struct JobHandle(usize);

    impl Drop for JobHandle {
        fn drop(&mut self) {
            // Closing the LAST handle to a kill-on-close job terminates every process
            // still in it — this is the teardown, not just a cleanup.
            unsafe { CloseHandle(self.0 as HANDLE) };
        }
    }

    /// Create a kill-on-close job and put process `pid` in it. Returns the owning
    /// handle, which must be kept alive for as long as the child should live.
    ///
    /// Safe to call right after spawn: we still hold the child's process handle, so
    /// the OS cannot recycle `pid` onto a different process in between.
    pub fn bind(pid: u32) -> Option<JobHandle> {
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() || job == INVALID_HANDLE_VALUE {
                return None;
            }
            let guard = JobHandle(job as usize);

            // Ask for kill-on-close.
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) == 0
            {
                return None; // `guard` drops → handle closed, nothing was assigned yet
            }

            // Assigning needs SET_QUOTA + TERMINATE on the target process.
            let proc = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid);
            if proc.is_null() {
                return None;
            }
            let assigned = AssignProcessToJobObject(job, proc) != 0;
            CloseHandle(proc);
            if !assigned {
                return None;
            }
            Some(guard)
        }
    }
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
                // macOS: take the child OUT of any inherited "background" CPU band
                // before exec, so the miner runs on the PERFORMANCE cores.
                //
                // On Apple Silicon the scheduler parks a background-QoS thread on the
                // EFFICIENCY cores, which runs RandomX/xmrig ~10x slower. A child
                // INHERITS the parent's Darwin background clamp — so when the miner UI
                // is App-Napped / occluded / launched at a reduced QoS, the spawned
                // engine lands on the E-cores and hashrate collapses even though it is
                // still in fast (dataset) mode. Measured on an M2 Max via a mock pool:
                // xmrig 318 H/s under a `taskpolicy -b` clamp vs 3818 H/s once this
                // clear is applied — a full 12x restoration (cf. the ~10x
                // Background-LaunchAgent note in alice-miner-core::service, which is why
                // the launch agent already uses ProcessType=Standard; this covers the
                // INTERACTIVE path, which sets no explicit QoS).
                //
                // `setpriority(PRIO_DARWIN_PROCESS, 0, 0)` clears the background band on
                // THIS process (`who = 0` = current; `prio = 0` = not throttled — the
                // inverse of `PRIO_DARWIN_BG`). Best-effort: a failure must never block
                // mining, so the result is ignored (the engine still runs, just possibly
                // throttled). `setpriority` is a single syscall → async-signal-safe, so
                // it is safe to call here in the post-fork / pre-exec context.
                #[cfg(target_os = "macos")]
                {
                    let _ = set_darwin_priority(PRIO_DARWIN_PROCESS, 0, 0);
                }
                Ok(())
            });
        }
    }

    let mut child = cmd.spawn()?;
    let pid = child
        .id()
        .ok_or_else(|| io::Error::other("child has no PID"))?;

    // Windows: bind the child (and everything it spawns) to a kill-on-close Job
    // Object, so it cannot outlive us even when we are TerminateProcess'd — which is
    // exactly how `alice-miner stop` ends up terminating the CLI parent. See `mod job`.
    // We still hold `child`, so `pid` cannot have been recycled here.
    #[cfg(windows)]
    let job = job::bind(pid);

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
        #[cfg(windows)]
        job,
    })
}

#[cfg(unix)]
extern "C" {
    #[link_name = "setpgid"]
    fn set_pgid(pid: i32, pgid: i32) -> i32;
}

/// macOS `setpriority(2)` "which" selector for the Darwin per-PROCESS CPU band
/// (`<sys/resource.h>`: `PRIO_DARWIN_PROCESS = 4`). Paired with a `prio` of `0`
/// it CLEARS the background clamp (the inverse of `PRIO_DARWIN_BG = 0x1000`),
/// pulling a spawned miner back onto the performance cores.
#[cfg(target_os = "macos")]
const PRIO_DARWIN_PROCESS: i32 = 4;

// Raw `setpriority(2)`. `who` is a `u32` (`id_t`); `who = 0` targets the calling
// process. Declared locally (no `libc` dep) to mirror the `setpgid` binding above.
#[cfg(target_os = "macos")]
extern "C" {
    #[link_name = "setpriority"]
    fn set_darwin_priority(which: i32, who: u32, prio: i32) -> i32;
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

// ════════════════════════════════════════════════════════════════════════════
// Synchronous guarded spawn — the SAME kill-the-whole-tree guarantee, for the
// blocking (non-tokio) call sites.
//
// Audit AM-REL-006: the `ai` and `train` roles spawned their python engine with
// a bare `std::process::Command` and stopped it with `child.kill()`. `kill()` is
// `TerminateProcess` / `SIGKILL` on the DIRECT child only, so every descendant
// the engine forked (torch dataloader workers, an NCCL helper, a `python -c`
// shell-out) was orphaned and kept the GPU memory and the relay socket. The
// mining lanes have not had that bug since the Job Object / process-group work
// landed — but that machinery lived behind an ASYNC API (`spawn_supervised`
// returns a tokio-driven `OwnedChild`), so the blocking roles could not reuse it
// and grew their own weaker copy.
//
// [`spawn_guarded`] closes that gap WITHOUT duplicating any OS code: it applies
// the same `setpgid(0,0)` pre-exec on unix and binds the same kill-on-close
// [`job`] object on Windows, then hands back a blocking handle whose teardown
// signals the whole GROUP / TREE.
//
// DELIBERATELY NOT DONE HERE: the caller's environment is passed through
// untouched (unlike `spawn_supervised`, which `env_clear`s to an allowlist).
// Scrubbing the AI/Train child's env is audit AM-SEC-003/004 — a real finding,
// but one that needs a python-side compatibility pass (HF_HOME, VIRTUAL_ENV,
// CUDA paths…) and is tracked as its own project. Silently `env_clear`ing here
// would look like a reliability fix while changing what the engine can load.
// ════════════════════════════════════════════════════════════════════════════

/// How long a guarded child gets to exit after the polite signal before the
/// force path runs. Short: this is a teardown, not a shutdown negotiation.
pub const GUARD_GRACE: Duration = Duration::from_millis(1500);

/// A spawned `std::process::Child` whose ENTIRE descendant tree is owned:
///
///   * **unix** — the child leads its own process group (`setpgid(0, 0)` in
///     `pre_exec`), so [`GuardedChild::kill_tree`] signals `-pid` and reaches
///     every descendant, not just the direct child.
///   * **Windows** — the child is bound to a `KILL_ON_JOB_CLOSE` Job Object (the
///     same [`job`] module the mining lanes use), so the kernel terminates the
///     whole job when the last handle closes — including when THIS process is
///     `TerminateProcess`d and no destructor ever runs. `taskkill /T /F` is the
///     belt to that suspender.
///
/// `Drop` tears the tree down, so an early return / panic on the supervising
/// thread can never leave a GPU-holding orphan behind.
pub struct GuardedChild {
    child: std::process::Child,
    pid: u32,
    /// Set once the child has been reaped (so `Drop` doesn't signal a pid the OS
    /// may already have recycled).
    reaped: bool,
    #[cfg(windows)]
    job: Option<job::JobHandle>,
}

impl GuardedChild {
    /// The direct child's pid (the process-group leader / job root).
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Windows: whether the kill-on-close Job Object binding succeeded (i.e.
    /// whether "we die → the engine dies" is kernel-enforced for this child).
    /// Exposed for tests + honest diagnostics.
    #[cfg(windows)]
    pub fn job_bound(&self) -> bool {
        self.job.is_some()
    }

    /// Take the child's piped stdout (once).
    pub fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.child.stdout.take()
    }

    /// Take the child's piped stderr (once).
    pub fn take_stderr(&mut self) -> Option<std::process::ChildStderr> {
        self.child.stderr.take()
    }

    /// Take the child's piped stdin (once).
    pub fn take_stdin(&mut self) -> Option<std::process::ChildStdin> {
        self.child.stdin.take()
    }

    /// Non-blocking exit poll. `Ok(Some(status))` once the child has exited (and
    /// been reaped); `Ok(None)` while it is still running.
    pub fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        if self.reaped {
            return Ok(None);
        }
        let r = self.child.try_wait();
        if let Ok(Some(_)) = r {
            self.reaped = true;
        }
        r
    }

    /// Block until the child exits.
    pub fn wait(&mut self) -> io::Result<std::process::ExitStatus> {
        let r = self.child.wait();
        if r.is_ok() {
            self.reaped = true;
        }
        r
    }

    /// Terminate the child AND every descendant, then reap. Polite signal first
    /// (SIGTERM to the group / `taskkill /T`), `grace` to comply, then the force
    /// path (SIGKILL to the group / `taskkill /T /F` + `Child::kill`).
    ///
    /// Idempotent: a child that has already been reaped is a no-op.
    pub fn kill_tree(&mut self, grace: Duration) {
        if self.reaped {
            return;
        }
        if let Ok(Some(_)) = self.child.try_wait() {
            self.reaped = true;
            return;
        }

        #[cfg(unix)]
        unsafe {
            // Negative pid = the whole process group the child leads.
            libc_kill(-(self.pid as i32), 15);
        }
        #[cfg(windows)]
        {
            let _ = std::process::Command::new("taskkill")
                .args(["/T", "/PID", &self.pid.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }

        let deadline = std::time::Instant::now() + grace;
        while std::time::Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                self.reaped = true;
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        // Force path: the whole tree, not just the recorded pid.
        #[cfg(unix)]
        unsafe {
            libc_kill(-(self.pid as i32), 9);
        }
        #[cfg(windows)]
        {
            let _ = std::process::Command::new("taskkill")
                .args(["/F", "/T", "/PID", &self.pid.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = self.child.kill();
        // Reap so we never leave a zombie (and never signal a recycled pid).
        let _ = self.child.wait();
        self.reaped = true;
    }
}

impl Drop for GuardedChild {
    fn drop(&mut self) {
        // An early return / `?` / panic on the supervising thread must not leave
        // the engine running. (On Windows the Job Object is the backstop even for
        // a `TerminateProcess`d parent, where this never runs.)
        self.kill_tree(GUARD_GRACE);
    }
}

/// Spawn `cmd` as a [`GuardedChild`]. The caller configures the command fully
/// (program, args, cwd, stdio, env); this only adds the OS ownership bond.
///
/// On unix the child is made a process-group leader via `pre_exec`; on Windows it
/// is bound to a kill-on-close Job Object right after spawn (we still hold the
/// process handle, so the pid cannot have been recycled in between). A Job
/// binding failure is FAIL-SOFT — the child still runs and `kill_tree` still walks
/// the tree with `taskkill /T` — and is observable via
/// [`GuardedChild::job_bound`], never silently reported as guarded.
pub fn spawn_guarded(cmd: &mut std::process::Command) -> io::Result<GuardedChild> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        unsafe {
            cmd.pre_exec(|| {
                if set_pgid(0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    let child = cmd.spawn()?;
    let pid = child.id();

    #[cfg(windows)]
    let job = job::bind(pid);

    Ok(GuardedChild {
        child,
        pid,
        reaped: false,
        #[cfg(windows)]
        job,
    })
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
    // Used by the spawn tests: the `#[cfg(unix)]` ones and the Windows job-binding
    // one. On a hypothetical third OS neither runs, so the import would be unused
    // there under `-D warnings`.
    #[cfg(any(unix, windows))]
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

    /// Windows: is this pid present according to `tasklist`? (Local to the test —
    /// the CLI has its own copy for the stop path.)
    #[cfg(windows)]
    fn win_pid_present(pid: u32) -> bool {
        std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout).lines().any(|l| {
                    l.split("\",\"")
                        .nth(1)
                        .map(|f| f.trim_matches('"').trim() == pid.to_string())
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    }

    /// REGRESSION (Bug 1, Windows-only): every spawned engine child must be bound to
    /// a kill-on-close Job Object. That binding is what makes the engine die when the
    /// CLI parent is `taskkill /F`'d (TerminateProcess runs no destructors, so
    /// `kill_on_drop` never fires) — the mechanism behind "stop said no orphan while
    /// xmrig kept mining". If `bind` ever silently starts returning `None` (wrong
    /// access rights, API misuse), this fails instead of regressing in the field.
    ///
    /// Windows CI is the ONLY place this executes; it cannot be validated on macOS.
    #[cfg(windows)]
    #[test]
    fn spawned_child_is_bound_to_a_kill_on_close_job() {
        let rt = rt();
        rt.block_on(async {
            let (tx, _rx) = unbounded_channel();
            let mut child = spawn_supervised(
                Path::new("cmd.exe"),
                &["/C".to_string(), "ping -n 30 127.0.0.1 > nul".to_string()],
                &[],
                None,
                tx,
            )
            .expect("spawn");
            let pid = child.pid();
            assert!(pid > 0);
            assert!(
                child.job_bound(),
                "the engine child MUST be in a kill-on-close job — without it a \
                 force-killed parent leaves the miner orphaned"
            );
            assert!(child.try_exit_code().is_none(), "child should still be running");

            let _ = child.stop(Duration::from_secs(3)).await.expect("stop ok");
            // The whole point: after stop the process is really gone.
            let mut gone = false;
            for _ in 0..20 {
                if !win_pid_present(pid) {
                    gone = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(150));
            }
            assert!(gone, "pid {pid} still present after stop() — orphan left behind");
        });
    }

    // ── Synchronous guarded spawn (AM-REL-006) ────────────────────────────────
    //
    // These run on EVERY OS: the platform difference is a RUNTIME `cfg!(windows)`
    // branch that picks the shell + probe, not a `#[cfg]` that would compile the
    // test out of existence on the platform it matters most for. (2026-07-26
    // lesson: a `#[cfg(unix)]` test suite is a coverage illusion on Windows.)

    /// Is `pid` present? Same shape as the CLI's probe, local to the test.
    fn probe_pid_alive(pid: u32) -> bool {
        if cfg!(windows) {
            std::process::Command::new("tasklist")
                .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
                .output()
                .map(|o| {
                    String::from_utf8_lossy(&o.stdout).lines().any(|l| {
                        l.split("\",\"")
                            .nth(1)
                            .map(|f| f.trim_matches('"').trim() == pid.to_string())
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false)
        } else {
            std::process::Command::new("kill")
                .args(["-0", &pid.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }
    }

    /// A command whose DIRECT child spawns a long-lived GRANDCHILD and prints the
    /// grandchild's pid on stdout, then keeps running. This is the exact shape the
    /// AI/Train roles have in the field (python → dataloader/NCCL helpers) and the
    /// exact shape `child.kill()` used to orphan.
    fn grandchild_spawner() -> std::process::Command {
        let mut cmd = if cfg!(windows) {
            let mut c = std::process::Command::new("powershell");
            c.args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$p = Start-Process -PassThru -WindowStyle Hidden ping \
                 -ArgumentList '-n','120','127.0.0.1'; \
                 Write-Output $p.Id; Start-Sleep -Seconds 120",
            ]);
            c
        } else {
            let mut c = std::process::Command::new("/bin/sh");
            c.args(["-c", "sleep 120 & echo $!; wait"]);
            c
        };
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        cmd
    }

    /// Read the first line the child prints, within a bounded wall clock.
    fn first_line(out: std::process::ChildStdout) -> Option<String> {
        use std::io::{BufRead, BufReader};
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut r = BufReader::new(out);
            let mut line = String::new();
            if r.read_line(&mut line).is_ok() {
                let _ = tx.send(line);
            }
        });
        rx.recv_timeout(Duration::from_secs(20))
            .ok()
            .map(|l| l.trim().to_string())
    }

    /// THE regression this API exists for: `kill_tree` must take the DESCENDANTS
    /// down too. A plain `Child::kill()` reaps only the direct child and leaves the
    /// grandchild holding VRAM / a relay socket forever.
    #[test]
    fn guarded_kill_tree_takes_descendants_with_it() {
        let mut cmd = grandchild_spawner();
        let mut child = spawn_guarded(&mut cmd).expect("spawn guarded child");
        let direct = child.pid();
        assert!(direct > 0);

        let out = child.take_stdout().expect("piped stdout");
        let grand: u32 = first_line(out)
            .and_then(|l| l.trim().parse().ok())
            .expect("the child must report its grandchild's pid (test setup)");
        assert_ne!(grand, direct, "the grandchild must be a distinct process");

        // Both alive before the teardown.
        assert!(child.try_wait().unwrap().is_none(), "direct child still running");
        let mut saw_grand = false;
        for _ in 0..40 {
            if probe_pid_alive(grand) {
                saw_grand = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(saw_grand, "grandchild pid {grand} should be observable before the kill");

        child.kill_tree(Duration::from_secs(2));

        // The direct child is gone…
        let mut direct_gone = false;
        for _ in 0..40 {
            if !probe_pid_alive(direct) {
                direct_gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(direct_gone, "direct pid {direct} survived kill_tree");

        // …and so is the grandchild. THIS is the assertion `child.kill()` fails.
        let mut grand_gone = false;
        for _ in 0..60 {
            if !probe_pid_alive(grand) {
                grand_gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            grand_gone,
            "grandchild pid {grand} outlived kill_tree — the engine's helpers would keep the GPU"
        );
    }

    /// `Drop` must tear the tree down too: a supervising thread that returns early
    /// (or panics) can never leave the engine mining in the background.
    #[test]
    fn guarded_drop_kills_the_child() {
        let mut cmd = grandchild_spawner();
        let pid = {
            let child = spawn_guarded(&mut cmd).expect("spawn");
            child.pid()
            // dropped here
        };
        let mut gone = false;
        for _ in 0..60 {
            if !probe_pid_alive(pid) {
                gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(gone, "pid {pid} survived the GuardedChild drop");
    }

    /// `kill_tree` is idempotent and never signals a reaped pid twice (a reaped pid
    /// can be recycled by the OS onto an unrelated process).
    #[test]
    fn guarded_kill_tree_is_idempotent() {
        let mut cmd = if cfg!(windows) {
            let mut c = std::process::Command::new("cmd");
            c.args(["/C", "exit 7"]);
            c
        } else {
            let mut c = std::process::Command::new("/bin/sh");
            c.args(["-c", "exit 7"]);
            c
        };
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        let mut child = spawn_guarded(&mut cmd).expect("spawn");
        // Let it exit on its own, then reap through the normal path.
        let status = child.wait().expect("wait");
        assert_eq!(status.code(), Some(7));
        // Already reaped → both calls are no-ops, and neither panics.
        child.kill_tree(Duration::from_millis(100));
        child.kill_tree(Duration::from_millis(100));
    }

    /// Windows-only: the guarded child must be inside a kill-on-close Job Object,
    /// the only mechanism that survives our own `TerminateProcess`.
    #[cfg(windows)]
    #[test]
    fn guarded_child_is_bound_to_a_kill_on_close_job() {
        let mut cmd = std::process::Command::new("cmd");
        cmd.args(["/C", "ping -n 30 127.0.0.1 > nul"])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = spawn_guarded(&mut cmd).expect("spawn");
        assert!(
            child.job_bound(),
            "a guarded AI/Train engine child MUST be in a kill-on-close job"
        );
        child.kill_tree(Duration::from_secs(2));
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
