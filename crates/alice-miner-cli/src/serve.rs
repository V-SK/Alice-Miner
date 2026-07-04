//! `alice-miner serve` — the **consumer single-GPU serving** role.
//!
//! A miner runs `alice-miner serve` (usually after picking a tier in the
//! `alice-miner ai --menu` wizard) and this box becomes a CONSUMER serving worker:
//! it spawns the vendored Python acp worker_client pull-serve loop
//! (`python -m alice_acp.worker_client …`), which registers to the acp gateway,
//! long-polls `/v1/worker/pull`, serves chat completions on the LOCAL GPU, and
//! submits them. Unlike the shard-stage `ai` role there is NO public port — the
//! worker is OUTBOUND-only (it dials the gateway; nothing dials it), so there is
//! nothing to port-forward.
//!
//! The CLI's whole job here is ORCHESTRATION — it NEVER reimplements any model /
//! backend logic in Rust:
//!
//!   1. resolve  — merge flags > env > saved config > default, https-only + a
//!      fail-closed check that the worker dir really holds the worker_client entry;
//!   2. preflight — doctor-style, fail-closed: python ≥ 3.11, the worker package
//!      imports, the llama-cpp backend is present (else print the known-good source
//!      build recipe and STOP — we never auto-run a CUDA pip build from a CLI);
//!   3. spawn + supervise — run the worker with the tier (or `--auto-vram`
//!      self-provisioning), line-pump its stdout/stderr to a per-run log AND echo it
//!      (the worker's own JSON-ish logs ARE the dashboard for v1 — no ratatui), and
//!      bounded-restart it on a crash so bad deps / OOM can't spin forever;
//!   4. Ctrl-C — kill the child + wait, print a clean bilingual stop line, exit 0.
//!
//! CREDIT-ONLY (paid_acu=0) + honest: no hashrate, no earnings. Fail-closed: a
//! missing worker dir / python / backend is a doctor-grade error, never a pretend
//! "serving".
//!
//! ── On the PoP signer (honest note) ──────────────────────────────────────────
//! The worker's proof-of-possession signer is read by the PYTHON side from ONE env
//! var, `ALICE_WORKER_POP_SECRET_URI`; it is never a CLI flag (a flag would leak the
//! key into the process table). We PASS THAT ENV THROUGH if it is set in our own
//! environment, but we NEVER set it ourselves and it never touches argv. Unset =>
//! best-effort PoP: the live edge currently runs with `REQUIRE_POP` OFF, so
//! registering + pulling + serving works WITHOUT the signer. When PoP flips on, the
//! serving worker will need that env exported before `serve` starts — otherwise a
//! gated gateway will (honestly) refuse to dispatch jobs. Because register/submit
//! need no wallet SIGNATURE from the Rust side today, `serve` takes no password
//! flags in v1 and never unlocks the keystore.

use std::io::{BufRead, BufReader, Write as _};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use alice_miner_core::serve_config::{self, ServeConfig};
use alice_miner_core::tr;

use crate::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE};

/// The production acp gateway base URL the other lanes' control-plane already uses.
/// Used as the `--gateway-url` default (via `--center-url`) when nothing else supplies it.
const DEFAULT_CENTER_URL: &str = "https://api.aliceprotocol.org";

/// The worker_client entry that MUST exist under `<worker_dir>/`. Its presence is the
/// signal the dir is a real `alice-acp-minerai` checkout (the worker is invoked as
/// `python -m alice_acp.worker_client` with `<worker_dir>/src` on PYTHONPATH).
const WORKER_MAIN_REL: &str = "src/alice_acp/worker_client/__main__.py";

/// The `src` subdir prepended to PYTHONPATH so `-m alice_acp.worker_client` resolves.
const WORKER_SRC_REL: &str = "src";

/// Env var the worker dir can be supplied through (parity with the flag).
const ENV_WORKER_DIR: &str = "ALICE_ACP_WORKER_PATH";

/// The env var the PYTHON worker reads its PoP signer from. NEVER set by us — only
/// passed THROUGH when present in our environment (see the module doc). Kept as a
/// constant so the passthrough site and the doc stay in lock-step.
const ENV_POP_SECRET_URI: &str = "ALICE_WORKER_POP_SECRET_URI";

/// The minimum python the worker needs (`from datetime import UTC` lands in 3.11).
const MIN_PYTHON_MINOR: u32 = 11;

/// Max consecutive worker crash-restarts before `serve` gives up (bounded so a
/// hard-failing worker — bad deps, OOM — can't spin forever; the give-up error
/// points at the log file).
const MAX_WORKER_RESTARTS: u32 = 5;

/// Linear backoff between worker restarts after a crash.
const RESTART_BACKOFF: Duration = Duration::from_secs(5);

/// A worker that stayed up at least this long before crashing is NOT in a
/// crash-loop, so the restart counter resets — the `MAX_WORKER_RESTARTS` bound
/// counts CONSECUTIVE rapid crashes (bad deps / instant OOM), never a handful of
/// temporally-unrelated transient exits spread across a long healthy run.
const HEALTHY_UPTIME_RESET: Duration = Duration::from_secs(300);

// ─────────────────────────────────────────────────────────────────────────────
// flags + resolved settings (kept UI-agnostic so resolve_config is unit-testable)
// ─────────────────────────────────────────────────────────────────────────────

/// The raw flags from clap (kept UI-agnostic so [`resolve_config`] is unit-testable).
#[derive(Debug, Clone, Default)]
pub struct ServeFlags {
    pub center_url: Option<String>,
    pub worker_dir: Option<String>,
    pub python: Option<String>,
    pub tier: Option<String>,
    pub runtime: Option<String>,
    pub free_memory_gb: Option<u32>,
    pub vram_gb: Option<f64>,
    pub cache_root: Option<String>,
    /// Force `--auto-vram` self-provisioning even if a tier is saved/flagged.
    pub auto: bool,
    pub max_output_tokens: Option<u32>,
}

/// The tier mode the worker runs in, resolved from flags + saved config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TierMode {
    /// Serve exactly this saved/flagged tier on the given runtime (`--tiers <t>
    /// --runtime <r>`). The model must already be present (or the worker downloads
    /// the pinned artifact on first job — that is INSIDE the child).
    Fixed { tier: String, runtime: String },
    /// Self-provision: `--auto-vram` — the worker probes GPU class + VRAM, picks the
    /// largest fitting tier, DOWNLOADS the pinned model, and advertises every fitting
    /// tier. Used when no tier is resolved, or `--auto` forces it.
    AutoVram,
}

/// The resolved, validated `serve` invocation (flags + config merged). Built by
/// [`resolve_config`]; consumed by [`run`].
#[derive(Debug, Clone, PartialEq)]
pub struct ServeSettings {
    pub center_url: String,
    pub worker_dir: PathBuf,
    pub python: String,
    pub tier_mode: TierMode,
    pub free_memory_gb: u32,
    /// Free-VRAM hint (GB, integer) passed to `--free-vram-gb` in AUTO mode only.
    /// `None` => omit it and let the python probe decide.
    pub free_vram_gb: Option<u32>,
    /// Weights cache root (`--cache-root`); `None` => the worker's own default
    /// (`~/.cache/alice/local-models`).
    pub cache_root: Option<String>,
    pub max_output_tokens: u32,
}

/// The default `--max-output-tokens` (matches the worker_client's own default so a
/// bare `serve` behaves exactly like a bare `python -m alice_acp.worker_client`).
const DEFAULT_MAX_OUTPUT_TOKENS: u32 = 256;

/// Merge flags over the persisted config, validate, and (on success) persist the
/// resolved PUBLIC settings back so a bare `alice-miner serve` re-run replays them.
///
/// `address` is the active identity's reward address (passed to the worker's
/// `--alice-address`). `saved` is the serve config the M2 wizard writes.
/// `detected_mem_gb` is the detected system RAM (always resolvable) and
/// `detected_free_vram_gb` the nvidia-smi hint (both injected so this is pure +
/// testable without probing hardware).
///
/// Fails (usage error) when the center is non-https, when the worker dir is missing /
/// lacks the worker_client entry.
pub fn resolve_config(
    flags: ServeFlags,
    saved: &ServeConfig,
    ai_center_url: Option<&str>,
    detected_mem_gb: u32,
    detected_free_vram_gb: Option<f64>,
) -> Result<ServeSettings, String> {
    // center: flag > serve_config > ai_config > default. https-only (a PoP signature /
    // completion must never cross the wire in the clear).
    let center_url = flags
        .center_url
        .or_else(|| saved.center_url.clone())
        .or_else(|| ai_center_url.map(str::to_string))
        .unwrap_or_else(|| DEFAULT_CENTER_URL.to_string());
    if !center_url.starts_with("https://") {
        return Err(format!(
            "--center-url must be an https:// URL (a PoP signature / completion must never cross \
             the wire in the clear): {center_url}"
        ));
    }

    // worker dir: flag > env > saved. REQUIRED, and must contain the worker_client entry.
    let worker_dir = flags
        .worker_dir
        .or_else(|| std::env::var(ENV_WORKER_DIR).ok().filter(|s| !s.is_empty()))
        .or_else(|| saved.worker_dir.clone())
        .ok_or(
            "--worker-dir <alice-acp-minerai checkout> is required (or set \
             ALICE_ACP_WORKER_PATH) — it must contain src/alice_acp/worker_client/__main__.py",
        )?;
    let worker_dir = PathBuf::from(worker_dir);
    let worker_main = worker_dir.join(WORKER_MAIN_REL);
    if !worker_main.is_file() {
        return Err(format!(
            "worker dir {} does not contain {WORKER_MAIN_REL} — point --worker-dir at your \
             alice-acp-minerai checkout",
            worker_dir.display()
        ));
    }

    let python = flags
        .python
        .filter(|s| !s.trim().is_empty())
        .or_else(|| saved.python.clone())
        .unwrap_or_else(|| "python3".to_string());

    // Tier mode. --auto forces self-provisioning; otherwise a resolved tier (flag >
    // saved) runs Fixed, and NO tier => AutoVram (the honest self-provision path).
    let tier = flags
        .tier
        .filter(|s| !s.trim().is_empty())
        .or_else(|| saved.tier.clone().filter(|s| !s.trim().is_empty()));
    let runtime = flags
        .runtime
        .filter(|s| !s.trim().is_empty())
        .or_else(|| saved.runtime.clone().filter(|s| !s.trim().is_empty()))
        .unwrap_or_else(|| "cuda".to_string());
    let tier_mode = match (flags.auto, tier) {
        (false, Some(tier)) => TierMode::Fixed { tier, runtime },
        // --auto forced, OR no tier resolved => let the worker self-provision.
        _ => TierMode::AutoVram,
    };

    // free system memory (the route memory gate): flag > detected (always resolvable).
    let free_memory_gb = flags.free_memory_gb.unwrap_or(detected_mem_gb).max(1);

    // free-VRAM hint (auto mode only): flag > nvidia-smi hint, floored to int.
    // 0 / None => omit and let the python probe decide.
    let free_vram_gb = flags
        .vram_gb
        .or(detected_free_vram_gb)
        .map(|v| v.floor() as i64)
        .filter(|v| *v > 0)
        .map(|v| v as u32);

    let cache_root = flags.cache_root.filter(|s| !s.trim().is_empty());

    let max_output_tokens = flags.max_output_tokens.unwrap_or(DEFAULT_MAX_OUTPUT_TOKENS).max(1);

    Ok(ServeSettings {
        center_url,
        worker_dir,
        python,
        tier_mode,
        free_memory_gb,
        free_vram_gb,
        cache_root,
        max_output_tokens,
    })
}

/// Persist the resolved settings' PUBLIC fields so a bare `alice-miner serve` re-run
/// replays them (never a secret). Only the fields `serve` owns are written; the model
/// coordinates the wizard saved (repo/revision/subpath) are left untouched by loading
/// them first and folding our fields on top.
fn persist(settings: &ServeSettings) {
    let mut cfg = serve_config::load();
    cfg.center_url = Some(settings.center_url.clone());
    cfg.worker_dir = Some(settings.worker_dir.to_string_lossy().to_string());
    cfg.python = Some(settings.python.clone());
    if let TierMode::Fixed { tier, runtime } = &settings.tier_mode {
        cfg.tier = Some(tier.clone());
        cfg.runtime = Some(runtime.clone());
    }
    // Best-effort: a write failure (read-only home) never blocks serving.
    let _ = serve_config::save(&cfg);
}

// ─────────────────────────────────────────────────────────────────────────────
// argv construction (pure + testable — asserts no secret ever lands in argv)
// ─────────────────────────────────────────────────────────────────────────────

/// The ordered argv (after the python executable) the worker is spawned with. Pure
/// so a test can assert the EXACT vec for both tier modes without spawning a process.
/// `-m alice_acp.worker_client` + the always-present flags, then the tier-mode tail.
/// The PoP secret is NEVER here (it rides one env var only) — the test asserts that.
pub fn worker_argv(settings: &ServeSettings, address: &str) -> Vec<String> {
    let mut argv = vec![
        "-m".to_string(),
        "alice_acp.worker_client".to_string(),
        "--gateway-url".to_string(),
        settings.center_url.clone(),
        "--alice-address".to_string(),
        address.to_string(),
        "--free-memory-gb".to_string(),
        settings.free_memory_gb.to_string(),
        "--backend".to_string(),
        "llama-cpp".to_string(),
        "--max-output-tokens".to_string(),
        settings.max_output_tokens.to_string(),
    ];
    if let Some(cache) = &settings.cache_root {
        argv.push("--cache-root".to_string());
        argv.push(cache.clone());
    }
    match &settings.tier_mode {
        TierMode::Fixed { tier, runtime } => {
            argv.push("--tiers".to_string());
            argv.push(tier.clone());
            argv.push("--runtime".to_string());
            argv.push(runtime.clone());
        }
        TierMode::AutoVram => {
            argv.push("--auto-vram".to_string());
            if let Some(v) = settings.free_vram_gb {
                argv.push("--free-vram-gb".to_string());
                argv.push(v.to_string());
            }
        }
    }
    argv
}

/// The PYTHONPATH value to hand the child: `<worker_dir>/src`, with any inherited
/// PYTHONPATH appended (prepend ours so the worker checkout wins). Pure + testable.
fn worker_pythonpath(worker_dir: &std::path::Path, inherited: Option<&str>) -> std::ffi::OsString {
    let src = worker_dir.join(WORKER_SRC_REL);
    match inherited.filter(|s| !s.is_empty()) {
        Some(rest) => {
            let mut joined = src.into_os_string();
            joined.push(if cfg!(windows) { ";" } else { ":" });
            joined.push(rest);
            joined
        }
        None => src.into_os_string(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// preflight (doctor-style, fail-closed, BEFORE spawning the loop)
// ─────────────────────────────────────────────────────────────────────────────

/// Parse the `<major> <minor>` line our python-version probe prints (e.g. `3 11`).
/// Returns `(major, minor)` or an error naming the raw string. Pure + testable.
pub fn parse_python_version(raw: &str) -> Result<(u32, u32), String> {
    let mut it = raw.split_whitespace();
    let major = it
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| format!("could not parse the python version from {raw:?}"))?;
    let minor = it
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| format!("could not parse the python version from {raw:?}"))?;
    Ok((major, minor))
}

/// True iff `(major, minor)` is at least `3.MIN_PYTHON_MINOR`. Pure + testable.
pub fn python_version_ok(major: u32, minor: u32) -> bool {
    major > 3 || (major == 3 && minor >= MIN_PYTHON_MINOR)
}

/// The bilingual error for a too-old python (the acp worker does `from datetime import
/// UTC`, which is a 3.11 feature; a 3.10 dies at import). Pure so it's the same string
/// the test asserts.
fn python_too_old_error(major: u32, minor: u32, python: &str) -> String {
    // Build the version-bearing middle clause first (a `tr!` over `format!().as_str()`
    // would drop the temporary at statement end — bind it to a `let`).
    let en_mid = format!(
        "is {major}.{minor}; the acp worker needs python 3.11+ (it uses `from datetime import UTC`)"
    );
    let zh_mid = format!(
        "为 {major}.{minor};acp 工作节点需要 python 3.11+(它使用 `from datetime import UTC`)"
    );
    format!(
        "{}: {python} {}. {}",
        tr!("python too old", "python 版本过低"),
        tr!(en_mid.as_str(), zh_mid.as_str()),
        tr!(
            "install python 3.11+ and pass --python <path/to/python3.11>",
            "请安装 python 3.11+ 并通过 --python <python3.11 的路径> 指定"
        )
    )
}

/// The known-good llama-cpp source-build recipe (bilingual HINT). We print it and
/// FAIL CLOSED — we never auto-run a CUDA source build from a CLI (a support minefield:
/// it needs a matching CUDA toolkit + the card's SM arch, and prebuilt cu-wheels SIGILL
/// on some CPUs — EPYC seen in prod). Pure so the doctor hint is one auditable string.
fn llama_cpp_missing_hint() -> String {
    format!(
        "{}\n  CMAKE_ARGS=\"-DGGML_CUDA=on -DGGML_NATIVE=on -DCMAKE_CUDA_ARCHITECTURES=<your sm>\" \\\n    pip install --no-binary :all: llama-cpp-python==0.3.32\n  {}",
        tr!(
            "the llama-cpp backend is not importable — build it FROM SOURCE with CUDA (a prebuilt \
             cu-wheel SIGILLs on some CPUs, e.g. EPYC):",
            "llama-cpp 后端无法导入 — 请带 CUDA 从源码构建(预编译的 cu-wheel 在部分 CPU 上会 \
             SIGILL,例如 EPYC):"
        ),
        tr!(
            "(set <your sm> to your GPU's compute capability, e.g. 89 for a 4090; then re-run \
             alice-miner serve)",
            "(将 <your sm> 设为你 GPU 的算力号,例如 4090 为 89;然后重新运行 alice-miner serve)"
        )
    )
}

/// Run `<python> -c "<code>"` with `PYTHONPATH=<worker_dir>/src`, returning
/// `Ok(stdout)` on a clean (exit-0) run, `Err(<stderr tail>)` on a non-zero exit /
/// spawn failure. Used by the import preflights so a missing dep surfaces honestly.
fn python_probe(settings: &ServeSettings, code: &str) -> Result<String, String> {
    let pythonpath = worker_pythonpath(&settings.worker_dir, None);
    let out = std::process::Command::new(&settings.python)
        .arg("-c")
        .arg(code)
        .env("PYTHONPATH", &pythonpath)
        .current_dir(&settings.worker_dir)
        .output()
        .map_err(|e| format!("failed to run {} -c: {e}", settings.python))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        // Surface the tail of stderr (the real import error) — bounded so a flood
        // can't make an unwieldy message.
        let err = String::from_utf8_lossy(&out.stderr);
        let tail: String = err.lines().rev().take(6).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n");
        Err(tail)
    }
}

/// Doctor-style preflight, fail-closed, BEFORE spawning the loop. Each failure is an
/// actionable bilingual `Err(String)` (mapped to EXIT_USAGE by the caller):
///   1. python runs and is ≥ 3.11;
///   2. the worker package imports (`import alice_acp.worker_client`);
///   3. the llama-cpp backend imports (`import llama_cpp`) — else the source-build hint.
fn preflight(settings: &ServeSettings) -> Result<(), String> {
    // 1. python ≥ 3.11.
    let ver = python_probe(settings, "import sys; print(sys.version_info[0], sys.version_info[1])")
        .map_err(|tail| {
            format!(
                "{} ({}): {tail}",
                tr!(
                    "could not run the configured python",
                    "无法运行所配置的 python"
                ),
                settings.python
            )
        })?;
    let (major, minor) = parse_python_version(&ver)?;
    if !python_version_ok(major, minor) {
        return Err(python_too_old_error(major, minor, &settings.python));
    }

    // 2. the worker package imports (surfaces missing deps honestly).
    python_probe(settings, "import alice_acp.worker_client").map_err(|tail| {
        format!(
            "{}\n{tail}\n  {}",
            tr!(
                "the alice_acp.worker_client package does not import",
                "alice_acp.worker_client 包无法导入"
            ),
            tr!(
                "install the worker's dependencies in this python, then re-run: alice-miner serve",
                "请在此 python 中安装 worker 的依赖,然后重新运行: alice-miner serve"
            )
        )
    })?;

    // 3. the llama-cpp backend imports (the serve backend is llama-cpp). On failure,
    // print the known-good source-build recipe and FAIL CLOSED (never auto-pip).
    python_probe(settings, "import llama_cpp").map_err(|_tail| llama_cpp_missing_hint())?;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// spawn + supervise
// ─────────────────────────────────────────────────────────────────────────────

/// A running worker child + the log path its stdout/stderr are mirrored to.
struct WorkerChild {
    child: std::process::Child,
    log_path: PathBuf,
}

impl WorkerChild {
    /// Best-effort kill + reap (used on shutdown + before a restart).
    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn `<python> -m alice_acp.worker_client <argv>` with `PYTHONPATH=<worker_dir>/src`
/// (any inherited PYTHONPATH appended), passing THROUGH `ALICE_WORKER_POP_SECRET_URI`
/// only when it is already in our env (never set by us, never in argv). stdout+stderr
/// are line-pumped to a per-run log file AND echoed to our stdout prefixed. cwd =
/// worker_dir. Returns the running child + its log path.
fn spawn_worker(settings: &ServeSettings, address: &str) -> Result<WorkerChild, String> {
    use std::process::{Command, Stdio};

    let log_dir = serve_config::serve_log_dir();
    std::fs::create_dir_all(&log_dir)
        .map_err(|e| format!("failed to create serve log dir {}: {e}", log_dir.display()))?;
    let log_path = log_dir.join(format!("serve-{}.log", now_unix()));
    let log_file = std::fs::File::create(&log_path)
        .map_err(|e| format!("failed to create serve log {}: {e}", log_path.display()))?;

    let inherited = std::env::var("PYTHONPATH").ok();
    let pythonpath = worker_pythonpath(&settings.worker_dir, inherited.as_deref());

    let mut cmd = Command::new(&settings.python);
    cmd.args(worker_argv(settings, address))
        .current_dir(&settings.worker_dir)
        .env("PYTHONPATH", &pythonpath)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Pass THROUGH the PoP signer env only if present — never set it ourselves, never
    // argv. Command inherits our environment by default, so an unset var stays unset;
    // this is a no-op when it isn't set (documented so the intent is unmistakable).
    if let Ok(uri) = std::env::var(ENV_POP_SECRET_URI) {
        if !uri.is_empty() {
            cmd.env(ENV_POP_SECRET_URI, uri);
        }
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn the acp worker ({}): {e}", settings.python))?;

    // Drain stdout + stderr on their own threads: mirror every line to the log file
    // AND echo to our stdout prefixed (the worker's own JSON logs are the v1
    // dashboard). Both streams share one Mutex<File> so their interleaving is faithful.
    let log = Arc::new(Mutex::new(log_file));
    if let Some(out) = child.stdout.take() {
        spawn_line_pump(out, Arc::clone(&log), "worker");
    }
    if let Some(err) = child.stderr.take() {
        spawn_line_pump(err, Arc::clone(&log), "worker!");
    }

    Ok(WorkerChild { child, log_path })
}

/// Mirror a child stream to the shared log file line-by-line AND echo it to our stdout
/// with a short prefix. Runs until the stream closes.
fn spawn_line_pump<R: std::io::Read + Send + 'static>(
    stream: R,
    log: Arc<Mutex<std::fs::File>>,
    prefix: &'static str,
) {
    std::thread::spawn(move || {
        let reader = BufReader::new(stream);
        for line in reader.lines().map_while(Result::ok) {
            if let Ok(mut f) = log.lock() {
                let _ = writeln!(f, "{line}");
            }
            println!("[{prefix}] {line}");
        }
    });
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Sleep `dur` in short slices so Ctrl-C tears down promptly (mirrors the ai role).
/// Returns early if the stop flag flips.
fn sleep_interruptible(dur: Duration, stop: &Arc<AtomicBool>) {
    let slices = (dur.as_millis() / 200).max(1);
    for _ in 0..slices {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// run
// ─────────────────────────────────────────────────────────────────────────────

/// Run the `serve` role: resolve the reward identity (READ-ONLY — watch-only is fine,
/// serve needs no keystore unlock in v1), resolve + validate config, preflight
/// (fail-closed), then spawn + supervise the worker until Ctrl-C. Returns the exit code.
pub fn run(flags: ServeFlags) -> i32 {
    // Resolve the reward identity (READ-ONLY — we never create/overwrite it here).
    // A watch-only (pasted) address is FINE for serve v1: the worker's register/submit
    // need no wallet SIGNATURE from us today (PoP is env-driven + currently off), so we
    // only need the address string, not a signing key.
    let Some(pointer) = alice_miner_core::identity::load_pointer() else {
        eprintln!(
            "error: {}",
            tr!(
                "no reward identity yet — create, import, or paste one first:\n  \
                 alice-miner identity --create   (or --import \"<24 words>\" / --paste <alice1…>)\n\
                 (serve registers this worker under your reward address; a watch-only pasted \
                 address is fine — serve needs no keystore unlock today)",
                "尚无奖励身份 — 请先创建、导入或粘贴一个:\n  \
                 alice-miner identity --create   (或 --import \"<24 个词>\" / --paste <alice1…>)\n\
                 (serve 会以你的奖励地址注册此工作节点;仅粘贴的观察地址即可 — \
                 serve 当前无需解锁密钥库)"
            )
        );
        return EXIT_USAGE;
    };
    let address = pointer.address.clone();

    let saved = serve_config::load();
    let ai_center = alice_miner_core::ai_config::load().center_url;
    let detected_mem_gb = alice_miner_core::detect::DeviceProfile::detect().memory_gb;
    let detected_free_vram_gb = crate::ai::detect_free_vram_gb("python3");

    let settings = match resolve_config(
        flags,
        &saved,
        ai_center.as_deref(),
        detected_mem_gb,
        detected_free_vram_gb,
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            // On an interactive terminal, hint at the participation menu (it detects
            // the hardware + lets the user pick a tier, which SAVES the config serve
            // reads). PRINT only — never auto-launch — so `run` stays testable.
            use std::io::IsTerminal;
            if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
                eprintln!(
                    "{}",
                    tr!(
                        "run `alice-miner ai --menu` to pick a serving tier for this machine",
                        "运行 `alice-miner ai --menu` 为这台机器选择一个服务档位"
                    )
                );
            }
            return EXIT_USAGE;
        }
    };

    // Preflight (fail-closed) BEFORE spawning: python ≥ 3.11, the worker imports, the
    // llama-cpp backend is present. Each failure is an actionable usage error.
    if let Err(e) = preflight(&settings) {
        eprintln!("error: {e}");
        return EXIT_USAGE;
    }

    // Persist the resolved public settings for a bare re-run (best-effort).
    persist(&settings);

    let tier_line = match &settings.tier_mode {
        TierMode::Fixed { tier, runtime } => format!("{tier} ({runtime})"),
        TierMode::AutoVram => tr!("auto-vram (self-provision)", "auto-vram (自动适配)").to_string(),
    };
    println!(
        "{}\n  {}: {}\n  {}: {}\n  {}: {}\n  {}: {} GB\n",
        tr!(
            "Alice Miner serve — single-GPU serving worker (credit-only, 积分)",
            "Alice Miner serve — 单卡服务工作节点 (credit-only, 积分)"
        ),
        tr!("center", "调度中心"),
        settings.center_url,
        tr!("worker", "工作节点"),
        settings.worker_dir.join(WORKER_MAIN_REL).display(),
        tr!("tier", "档位"),
        tier_line,
        tr!("advertised memory", "声明内存"),
        settings.free_memory_gb,
    );

    // Ctrl-C / SIGTERM → graceful stop (kill the child, exit clean). Same pattern as ai.
    let stop = Arc::new(AtomicBool::new(false));
    {
        let f = Arc::clone(&stop);
        let _ = ctrlc::set_handler(move || f.store(true, Ordering::SeqCst));
    }

    supervise(&settings, &address, &stop)
}

/// Spawn + supervise the worker: the worker IS the register→pull→serve→submit loop, so
/// we only own crash-restart + clean shutdown. Bounded restarts (a worker that keeps
/// dying — bad deps, OOM — must NOT spin forever). Returns the exit code.
///
/// NOTE: the first-run model download (auto-vram) happens INSIDE the child and can take
/// many minutes; there is no readiness timeout on our side — we just supervise.
fn supervise(settings: &ServeSettings, address: &str, stop: &Arc<AtomicBool>) -> i32 {
    let mut restarts: u32 = 0;
    let mut worker = match spawn_worker(settings, address) {
        Ok(w) => {
            println!(
                "{}: {}",
                tr!("worker log", "工作节点日志"),
                w.log_path.display()
            );
            w
        }
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_RUNTIME;
        }
    };
    let mut spawned_at = Instant::now();

    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        match worker.child.try_wait() {
            Ok(Some(_exit)) => {
                // The worker exited. Bounded restart with linear backoff. A run
                // that stayed healthy past the reset window is not a crash-loop:
                // the bound counts CONSECUTIVE rapid crashes, so earlier isolated
                // exits stop counting against a long-running worker.
                if spawned_at.elapsed() >= HEALTHY_UPTIME_RESET {
                    restarts = 0;
                }
                restarts += 1;
                if restarts > MAX_WORKER_RESTARTS {
                    eprintln!(
                        "error: {}",
                        tr!(
                            "the acp worker exited repeatedly (>5 restarts) — giving up. Check the \
                             worker log for the reason (bad deps / OOM / gateway):",
                            "acp 工作节点反复退出(>5 次重启)— 放弃。请查看工作节点日志了解原因\
                             (依赖问题 / OOM / 网关):"
                        )
                    );
                    eprintln!("  {}", worker.log_path.display());
                    return EXIT_RUNTIME;
                }
                // Build both localized strings first (a `tr!` over `format!().as_str()`
                // would drop the temporary at statement end — bind them to `let`s).
                let backoff_s = RESTART_BACKOFF.as_secs();
                let en_msg = format!(
                    "the acp worker exited (restart {restarts}/{MAX_WORKER_RESTARTS}); backing off {backoff_s}s"
                );
                let zh_msg = format!(
                    "acp 工作节点已退出(重启 {restarts}/{MAX_WORKER_RESTARTS});退避 {backoff_s}s"
                );
                eprintln!("{}", tr!(en_msg.as_str(), zh_msg.as_str()));
                sleep_interruptible(RESTART_BACKOFF, stop);
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                match spawn_worker(settings, address) {
                    Ok(w) => {
                        println!(
                            "{}: {}",
                            tr!("worker log", "工作节点日志"),
                            w.log_path.display()
                        );
                        worker = w;
                        spawned_at = Instant::now();
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        return EXIT_RUNTIME;
                    }
                }
            }
            Ok(None) => {
                // Still running — nothing to do; the line pumps carry the worker's logs.
                sleep_interruptible(Duration::from_secs(2), stop);
            }
            Err(e) => {
                eprintln!(
                    "error: {}: {e}",
                    tr!(
                        "could not poll the acp worker",
                        "无法轮询 acp 工作节点"
                    )
                );
                // A try_wait Err (EINTR/ECHILD) does NOT mean the child died —
                // kill+reap before bailing so we never orphan a live worker that
                // would keep pulling jobs with no supervisor.
                worker.kill();
                return EXIT_RUNTIME;
            }
        }
    }

    // Graceful shutdown: kill the child, exit clean.
    worker.kill();
    println!(
        "\n{}",
        tr!(
            "serve role stopped. (credit-only — no rewards were paid.)",
            "serve 角色已停止。(credit-only — 未发放任何奖励。)"
        )
    );
    EXIT_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR: &str = "a2uJXaVk7Zx4fgk9aRLnhiD2RdpAP4usJxKXpN4vh4hDNoP1C";

    /// A temp worker dir with a stub `src/alice_acp/worker_client/__main__.py` so
    /// resolve_config's existence check passes without a real checkout. Nanosecond +
    /// atomic-counter name so parallel tests never collide (mirrors ai.rs).
    fn temp_worker_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "alice-serve-worker-{}-{}-{}",
            std::process::id(),
            nanos,
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(dir.join("src/alice_acp/worker_client")).unwrap();
        std::fs::write(dir.join(WORKER_MAIN_REL), b"# stub\n").unwrap();
        dir
    }

    fn base_flags(worker: &std::path::Path) -> ServeFlags {
        ServeFlags {
            worker_dir: Some(worker.to_string_lossy().to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn resolve_config_requires_worker_dir() {
        // No worker dir anywhere → error naming --worker-dir.
        let e = resolve_config(ServeFlags::default(), &ServeConfig::default(), None, 16, None)
            .unwrap_err();
        assert!(e.contains("--worker-dir"), "names --worker-dir: {e}");
    }

    #[test]
    fn resolve_config_rejects_worker_dir_without_main() {
        // A dir that exists but lacks the worker_client entry → fail-closed.
        let dir = std::env::temp_dir().join(format!(
            "alice-serve-empty-{}-{}",
            std::process::id(),
            now_unix()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let f = base_flags(&dir);
        let e = resolve_config(f, &ServeConfig::default(), None, 16, None).unwrap_err();
        assert!(e.contains(WORKER_MAIN_REL), "names the missing entry: {e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_config_rejects_non_https_center() {
        let dir = temp_worker_dir();
        let f = ServeFlags {
            center_url: Some("http://insecure.example".into()),
            ..base_flags(&dir)
        };
        let e = resolve_config(f, &ServeConfig::default(), None, 16, None).unwrap_err();
        assert!(e.contains("https"), "non-https center refused: {e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_config_center_precedence_flag_over_serve_over_ai() {
        let dir = temp_worker_dir();
        // serve_config center is used over the ai center.
        let saved = ServeConfig {
            center_url: Some("https://serve.example".into()),
            ..Default::default()
        };
        let s = resolve_config(base_flags(&dir), &saved, Some("https://ai.example"), 16, None)
            .expect("resolve");
        assert_eq!(s.center_url, "https://serve.example");
        // A flag wins over both.
        let f = ServeFlags {
            center_url: Some("https://flag.example".into()),
            ..base_flags(&dir)
        };
        let s = resolve_config(f, &saved, Some("https://ai.example"), 16, None).expect("resolve");
        assert_eq!(s.center_url, "https://flag.example");
        // Only ai center set → it is used.
        let s = resolve_config(
            base_flags(&dir),
            &ServeConfig::default(),
            Some("https://ai.example"),
            16,
            None,
        )
        .expect("resolve");
        assert_eq!(s.center_url, "https://ai.example");
        // Nothing set → the production default.
        let s = resolve_config(base_flags(&dir), &ServeConfig::default(), None, 16, None)
            .expect("resolve");
        assert_eq!(s.center_url, DEFAULT_CENTER_URL);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_config_fixed_tier_mode_from_saved() {
        let dir = temp_worker_dir();
        // A saved tier + runtime (what the M2 wizard writes) → Fixed mode.
        let saved = ServeConfig {
            tier: Some("alice_lite_4b".into()),
            runtime: Some("cuda".into()),
            ..Default::default()
        };
        let s = resolve_config(base_flags(&dir), &saved, None, 16, None).expect("resolve");
        assert_eq!(
            s.tier_mode,
            TierMode::Fixed { tier: "alice_lite_4b".into(), runtime: "cuda".into() }
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_config_no_tier_is_auto_vram() {
        let dir = temp_worker_dir();
        // No tier anywhere → the honest self-provision path.
        let s = resolve_config(base_flags(&dir), &ServeConfig::default(), None, 16, None)
            .expect("resolve");
        assert_eq!(s.tier_mode, TierMode::AutoVram);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_config_auto_flag_forces_auto_over_saved_tier() {
        let dir = temp_worker_dir();
        let saved = ServeConfig {
            tier: Some("alice_lite_4b".into()),
            runtime: Some("cuda".into()),
            ..Default::default()
        };
        let f = ServeFlags { auto: true, ..base_flags(&dir) };
        let s = resolve_config(f, &saved, None, 16, None).expect("resolve");
        assert_eq!(s.tier_mode, TierMode::AutoVram, "--auto forces self-provision");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_config_free_memory_flag_over_detected() {
        let dir = temp_worker_dir();
        let f = ServeFlags { free_memory_gb: Some(48), ..base_flags(&dir) };
        let s = resolve_config(f, &ServeConfig::default(), None, 16, None).expect("resolve");
        assert_eq!(s.free_memory_gb, 48);
        // No flag → detected is used.
        let s = resolve_config(base_flags(&dir), &ServeConfig::default(), None, 24, None)
            .expect("resolve");
        assert_eq!(s.free_memory_gb, 24);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_config_vram_hint_floors_and_drops_zero() {
        let dir = temp_worker_dir();
        // A detected fractional VRAM floors to an int.
        let s = resolve_config(base_flags(&dir), &ServeConfig::default(), None, 16, Some(23.6))
            .expect("resolve");
        assert_eq!(s.free_vram_gb, Some(23));
        // A flag wins.
        let f = ServeFlags { vram_gb: Some(10.0), ..base_flags(&dir) };
        let s = resolve_config(f, &ServeConfig::default(), None, 16, Some(23.6)).expect("resolve");
        assert_eq!(s.free_vram_gb, Some(10));
        // Zero / none → omitted (let the python probe decide).
        let s = resolve_config(base_flags(&dir), &ServeConfig::default(), None, 16, Some(0.0))
            .expect("resolve");
        assert_eq!(s.free_vram_gb, None);
        let s = resolve_config(base_flags(&dir), &ServeConfig::default(), None, 16, None)
            .expect("resolve");
        assert_eq!(s.free_vram_gb, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn worker_argv_fixed_mode_exact_and_no_secret() {
        let dir = temp_worker_dir();
        let saved = ServeConfig {
            tier: Some("alice_lite_4b".into()),
            runtime: Some("cuda".into()),
            ..Default::default()
        };
        let s = resolve_config(base_flags(&dir), &saved, None, 16, None).expect("resolve");
        let argv = worker_argv(&s, ADDR);
        assert_eq!(
            argv,
            vec![
                "-m",
                "alice_acp.worker_client",
                "--gateway-url",
                DEFAULT_CENTER_URL,
                "--alice-address",
                ADDR,
                "--free-memory-gb",
                "16",
                "--backend",
                "llama-cpp",
                "--max-output-tokens",
                "256",
                "--tiers",
                "alice_lite_4b",
                "--runtime",
                "cuda",
            ]
        );
        // No secret token ever lands in argv (the PoP secret rides one env var only).
        // NB: the gateway url legitimately contains `//`, so we scan for the secret
        // markers themselves — the exact-argv assertion above is the strongest proof.
        let joined = argv.join(" ");
        for bad in ["POP", "SECRET", "mnemonic", "password", "//derivation"] {
            assert!(!joined.contains(bad), "argv must not contain {bad:?}: {joined}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn worker_argv_auto_mode_with_and_without_vram_hint() {
        let dir = temp_worker_dir();
        // Auto mode with a VRAM hint → --auto-vram --free-vram-gb <n>, no --tiers.
        let s = resolve_config(base_flags(&dir), &ServeConfig::default(), None, 16, Some(24.0))
            .expect("resolve");
        let argv = worker_argv(&s, ADDR);
        assert_eq!(
            argv,
            vec![
                "-m",
                "alice_acp.worker_client",
                "--gateway-url",
                DEFAULT_CENTER_URL,
                "--alice-address",
                ADDR,
                "--free-memory-gb",
                "16",
                "--backend",
                "llama-cpp",
                "--max-output-tokens",
                "256",
                "--auto-vram",
                "--free-vram-gb",
                "24",
            ]
        );
        assert!(!argv.iter().any(|a| a == "--tiers"), "auto mode has no --tiers");
        // Auto mode with NO VRAM hint → --auto-vram with no --free-vram-gb.
        let s = resolve_config(base_flags(&dir), &ServeConfig::default(), None, 16, None)
            .expect("resolve");
        let argv = worker_argv(&s, ADDR);
        assert!(argv.iter().any(|a| a == "--auto-vram"), "auto-vram present");
        assert!(
            !argv.iter().any(|a| a == "--free-vram-gb"),
            "no vram hint → --free-vram-gb omitted: {argv:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn worker_argv_includes_cache_root_when_set() {
        let dir = temp_worker_dir();
        let f = ServeFlags {
            cache_root: Some("/data/alice-cache".into()),
            ..base_flags(&dir)
        };
        let s = resolve_config(f, &ServeConfig::default(), None, 16, None).expect("resolve");
        let argv = worker_argv(&s, ADDR);
        let i = argv.iter().position(|a| a == "--cache-root").expect("cache-root present");
        assert_eq!(argv.get(i + 1).map(String::as_str), Some("/data/alice-cache"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pythonpath_prepends_worker_src_and_appends_inherited() {
        let dir = std::path::Path::new("/opt/alice-acp-minerai");
        let sep = if cfg!(windows) { ";" } else { ":" };
        // No inherited PYTHONPATH → just <worker_dir>/src.
        let pp = worker_pythonpath(dir, None);
        assert_eq!(pp.to_string_lossy(), format!("/opt/alice-acp-minerai/src"));
        // Inherited PYTHONPATH → ours first, then the inherited (so the checkout wins).
        let pp = worker_pythonpath(dir, Some("/existing/path"));
        assert_eq!(
            pp.to_string_lossy(),
            format!("/opt/alice-acp-minerai/src{sep}/existing/path")
        );
        // An empty inherited value is treated as absent.
        let pp = worker_pythonpath(dir, Some(""));
        assert_eq!(pp.to_string_lossy(), format!("/opt/alice-acp-minerai/src"));
    }

    #[test]
    fn python_version_parse_and_gate() {
        assert_eq!(parse_python_version("3 11").unwrap(), (3, 11));
        assert_eq!(parse_python_version("  3   12  ").unwrap(), (3, 12));
        assert!(parse_python_version("3").is_err());
        assert!(parse_python_version("").is_err());
        assert!(parse_python_version("x y").is_err());
        // The gate: 3.11+ ok; 3.10 and older not.
        assert!(python_version_ok(3, 11));
        assert!(python_version_ok(3, 12));
        assert!(python_version_ok(4, 0));
        assert!(!python_version_ok(3, 10));
        assert!(!python_version_ok(3, 9));
        assert!(!python_version_ok(2, 7));
    }

    #[test]
    fn python_too_old_error_names_311() {
        use alice_miner_core::i18n::{self, Lang};
        i18n::set_lang(Lang::En);
        let e = python_too_old_error(3, 10, "python3");
        assert!(e.contains("3.10"), "names the found version: {e}");
        assert!(e.contains("3.11"), "names the required version: {e}");
        i18n::set_lang(Lang::En);
    }

    #[test]
    fn llama_cpp_hint_names_the_source_build_recipe() {
        use alice_miner_core::i18n::{self, Lang};
        i18n::set_lang(Lang::En);
        let h = llama_cpp_missing_hint();
        assert!(h.contains("llama-cpp-python==0.3.32"), "pins the version: {h}");
        assert!(h.contains("GGML_CUDA=on"), "CUDA source build flag: {h}");
        assert!(h.contains("CMAKE_CUDA_ARCHITECTURES"), "the SM arch flag: {h}");
        i18n::set_lang(Lang::En);
    }
}
