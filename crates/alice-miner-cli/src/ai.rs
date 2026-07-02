//! `alice-miner ai` — the shard-stage INFERENCE worker role.
//!
//! A GPU miner runs `alice-miner ai --center-url <acp-gateway> --endpoint
//! <public-host:port> --engine-dir <alice-shard-engine>` and becomes a
//! pipeline-parallel inference STAGE coordinated by the Alice scheduling center:
//!
//!   1. register  — PoP-prove it owns the reward address + bind its public endpoint
//!      into the stake-gated swarm registry (core `shard::register`);
//!   2. loop       — heartbeat (carrying the live status) + pull;
//!   3. on a pull assignment — spawn + supervise the vendored shard engine
//!      (`python3 <engine-dir>/phase0/pipeline.py <argv from the spec>`), with the
//!      swarm `SHARD_PSK` passed through the ENV only (never argv); mark `ready`
//!      when the engine's listening line appears (or the local port accepts TCP),
//!      `error` on a crash with bounded-retry backoff.
//!
//! Ctrl-C stops gracefully (the child is killed). CREDIT-ONLY + honest: no
//! hashrate, no earnings — only the pipeline state, the assigned layer range, and
//! engine uptime/restarts. Fail-closed: a missing engine / python / PSK is a
//! doctor-grade error, never a pretend "serving".

use std::io::{BufRead, BufReader, Write as _};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use alice_miner_core::ai_config::{self, AiConfig};
use alice_miner_core::shard::{self, PullAssignment, PullOutcome, SHARD_PSK_ENV};

use crate::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE};

/// The production acp gateway base URL the other lanes' control-plane already uses
/// (see `alice_miner_core::pop::CENTRAL_HOST`). Used as the `--center-url` default.
const DEFAULT_CENTER_URL: &str = "https://api.aliceprotocol.org";

/// The engine entrypoint relative to the engine checkout dir.
const PIPELINE_REL: &str = "phase0/pipeline.py";

/// Env var the engine dir can be supplied through (parity with the flag).
const ENV_ENGINE_DIR: &str = "ALICE_SHARD_ENGINE_PATH";

/// How often the register→heartbeat→pull loop wakes. The server stage TTL is 90s;
/// a 20s cadence keeps the seat comfortably fresh with headroom for a missed tick.
const LOOP_TICK: Duration = Duration::from_secs(20);

/// Max consecutive engine crash-restarts before the loop gives up on the current
/// assignment (bounded so a hard-failing model can't spin forever).
const MAX_ENGINE_RESTARTS: u32 = 5;

/// Backoff between engine restarts (linear, capped) after a crash.
const RESTART_BACKOFF: Duration = Duration::from_secs(5);

/// The role's live state machine (drives the dashboard + the heartbeat `status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiState {
    /// Proving possession + binding the endpoint into the registry.
    Registering,
    /// Registered; polling for a swarm placement (`pull` → no_assignment).
    WaitingAssignment,
    /// Placed; the engine subprocess is starting (loading layers).
    Launching,
    /// The engine is listening / the local port accepts TCP — serving its stage.
    ServingReady,
    /// The engine crashed; backing off before a bounded restart.
    Error,
}

impl AiState {
    /// The human word for the dashboard.
    pub fn label(self) -> &'static str {
        match self {
            AiState::Registering => "registering",
            AiState::WaitingAssignment => "waiting-assignment",
            AiState::Launching => "launching",
            AiState::ServingReady => "serving-ready",
            AiState::Error => "error",
        }
    }

    /// The `status` string sent on the heartbeat (the additive server field). Only
    /// the launching/ready/error phases map to a status; the pre-placement phases
    /// send `None` (nothing to report about an engine that isn't running yet).
    pub fn heartbeat_status(self) -> Option<&'static str> {
        match self {
            AiState::Launching => Some("launching"),
            AiState::ServingReady => Some("ready"),
            AiState::Error => Some("error"),
            AiState::Registering | AiState::WaitingAssignment => None,
        }
    }
}

/// The resolved, validated `ai` invocation (flags + config merged). Built by
/// [`resolve_config`]; consumed by [`run`].
#[derive(Debug, Clone, PartialEq)]
pub struct AiSettings {
    pub center_url: String,
    pub endpoint: String,
    pub engine_dir: PathBuf,
    pub python: String,
    pub vram_gb: f64,
    pub region: String,
    pub stake_ref: String,
    pub allow_cpu: bool,
}

/// The raw flags from clap (kept UI-agnostic so `resolve_config` is unit-testable).
#[derive(Debug, Clone, Default)]
pub struct AiFlags {
    pub center_url: Option<String>,
    pub endpoint: Option<String>,
    pub engine_dir: Option<String>,
    pub python: Option<String>,
    pub vram_gb: Option<f64>,
    pub region: Option<String>,
    pub stake_ref: Option<String>,
    pub allow_cpu: bool,
}

/// Validate a `host:port` endpoint: a non-empty host, a `:`, and a numeric port in
/// 1..=65535. Accepts a bracketed IPv6 host (`[::1]:29501`). Returns the parsed port
/// (used for the local readiness probe) on success.
pub fn validate_endpoint(endpoint: &str) -> Result<u16, String> {
    let ep = endpoint.trim();
    if ep.is_empty() {
        return Err("endpoint must not be empty (expected host:port)".into());
    }
    let (host, port_str) = ep
        .rsplit_once(':')
        .ok_or("endpoint must be host:port (missing ':')")?;
    // Strip IPv6 brackets for the host-empty check only.
    let host_bare = host.trim_start_matches('[').trim_end_matches(']');
    if host_bare.is_empty() {
        return Err("endpoint host must not be empty".into());
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("endpoint port is not a valid 1..=65535 number: {port_str:?}"))?;
    if port == 0 {
        return Err("endpoint port must be 1..=65535 (not 0)".into());
    }
    Ok(port)
}

/// The local `127.0.0.1:<port>` the readiness probe dials. The advertised endpoint
/// is a PUBLIC host:port, but the engine listens locally on that port, so readiness
/// is probed against loopback (works behind NAT/port-forward where the public host
/// isn't locally routable).
fn local_probe_addr(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

/// Auto-detect free VRAM (GB) via `nvidia-smi`, summing the largest single GPU's
/// free memory. Returns `None` when nvidia-smi is absent / returns nothing (the
/// caller then requires an explicit `--vram-gb` or `--allow-cpu`).
pub fn detect_free_vram_gb(python_unused: &str) -> Option<f64> {
    let _ = python_unused;
    let out = std::process::Command::new("nvidia-smi")
        .args(["--query-gpu=memory.free", "--format=csv,noheader,nounits"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    parse_nvidia_free_vram_gb(&text)
}

/// Parse `nvidia-smi --query-gpu=memory.free --format=csv,noheader,nounits` output
/// (one MiB integer per GPU line) into the LARGEST single-GPU free VRAM in GB. Pure
/// + testable. Returns `None` when no numeric line is present.
pub fn parse_nvidia_free_vram_gb(text: &str) -> Option<f64> {
    let max_mib = text
        .lines()
        .filter_map(|l| l.trim().parse::<f64>().ok())
        .fold(None, |acc: Option<f64>, v| Some(acc.map_or(v, |a| a.max(v))))?;
    // MiB → GB (binary MiB to decimal GB is close enough for an advertised hint;
    // the server only needs a positive number, not a precise figure).
    Some((max_mib / 1024.0 * 100.0).round() / 100.0)
}

/// The default stake reference: `enroll:<address>`. The server only requires a
/// non-empty stake_ref (day-1 sybil gate); this is an honest, address-scoped
/// default that a future on-chain stake pallet can supersede.
pub fn default_stake_ref(address: &str) -> String {
    format!("enroll:{address}")
}

/// Merge flags over the persisted config, validate, and (on success) persist the
/// resolved public settings back so a bare re-run replays them. `address` is the
/// active identity's reward address (for the stake-ref default + VRAM messaging).
///
/// Fails (usage error) when a required value is still missing after the merge, when
/// the endpoint is malformed, when the engine dir lacks `phase0/pipeline.py`, or
/// when no VRAM could be resolved and `--allow-cpu` was not given.
pub fn resolve_config(flags: AiFlags, address: &str, saved: &AiConfig) -> Result<AiSettings, String> {
    let center_url = flags
        .center_url
        .or_else(|| saved.center_url.clone())
        .unwrap_or_else(|| DEFAULT_CENTER_URL.to_string());
    if !center_url.starts_with("https://") {
        return Err(format!(
            "--center-url must be an https:// URL (a PoP signature must never cross the wire in \
             the clear): {center_url}"
        ));
    }

    let endpoint = flags
        .endpoint
        .or_else(|| saved.endpoint.clone())
        .ok_or("--endpoint <public host:port> is required (the address the swarm dials this stage)")?;
    validate_endpoint(&endpoint)?;

    let engine_dir = flags
        .engine_dir
        .or_else(|| std::env::var(ENV_ENGINE_DIR).ok().filter(|s| !s.is_empty()))
        .or_else(|| saved.engine_dir.clone())
        .ok_or(
            "--engine-dir <alice-shard-engine checkout> is required (or set \
             ALICE_SHARD_ENGINE_PATH) — it must contain phase0/pipeline.py",
        )?;
    let engine_dir = PathBuf::from(engine_dir);
    let pipeline = engine_dir.join(PIPELINE_REL);
    if !pipeline.is_file() {
        return Err(format!(
            "engine dir {} does not contain {PIPELINE_REL} — point --engine-dir at your \
             alice-shard-engine checkout",
            engine_dir.display()
        ));
    }

    let python = flags
        .python
        .or_else(|| saved.python.clone())
        .unwrap_or_else(|| "python3".to_string());

    // VRAM: explicit flag > saved > auto-detect. With none of those, require
    // --allow-cpu (an honest opt-in for a no-NVIDIA test box) and advertise a small
    // positive hint so the server accepts the registration.
    let vram_gb = match flags.vram_gb.or(saved.vram_gb) {
        Some(v) if v > 0.0 => v,
        _ => match detect_free_vram_gb(&python) {
            Some(v) if v > 0.0 => v,
            _ => {
                if flags.allow_cpu {
                    1.0 // honest minimal hint for a CPU/test box (server needs > 0)
                } else {
                    return Err(format!(
                        "could not detect GPU VRAM via nvidia-smi for {address}. Pass --vram-gb \
                         <GB> to advertise it explicitly, or --allow-cpu to run without an NVIDIA \
                         GPU (for testing — a real inference stage needs a GPU)."
                    ));
                }
            }
        },
    };

    let region = flags
        .region
        .or_else(|| saved.region.clone())
        .unwrap_or_else(|| "unknown".to_string());

    let stake_ref = flags
        .stake_ref
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| default_stake_ref(address));

    Ok(AiSettings {
        center_url,
        endpoint,
        engine_dir,
        python,
        vram_gb,
        region,
        stake_ref,
        allow_cpu: flags.allow_cpu,
    })
}

/// Persist the resolved settings' PUBLIC fields so a bare `alice-miner ai` re-run
/// replays them (never a secret — no PSK, no key).
fn persist(settings: &AiSettings) {
    let cfg = AiConfig {
        schema: 0, // save() stamps the current schema
        center_url: Some(settings.center_url.clone()),
        endpoint: Some(settings.endpoint.clone()),
        engine_dir: Some(settings.engine_dir.to_string_lossy().to_string()),
        python: Some(settings.python.clone()),
        vram_gb: Some(settings.vram_gb),
        region: (settings.region != "unknown").then(|| settings.region.clone()),
    };
    // Best-effort: a write failure (read-only home) never blocks mining.
    let _ = ai_config::save(&cfg);
}

/// A running engine child + the reader thread that mirrors its stdout/stderr to a
/// log file AND watches for the "listening" line to flip readiness.
struct EngineChild {
    child: std::process::Child,
    /// Set true once the engine prints its `listening on :<port>` line.
    saw_listening: Arc<AtomicBool>,
    log_path: PathBuf,
    started: Instant,
}

impl EngineChild {
    /// Best-effort kill + reap (used on shutdown + before a restart).
    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn `python3 <engine-dir>/phase0/pipeline.py <argv>` with `SHARD_PSK` from the
/// current env passed through, capturing stdout+stderr into a per-assignment log
/// file under the ai log dir. Returns the running child + a shared "saw listening"
/// flag the loop polls for readiness. The PSK is NEVER placed in argv.
fn spawn_engine(
    settings: &AiSettings,
    assignment: &PullAssignment,
    psk: &str,
) -> Result<EngineChild, String> {
    use std::process::{Command, Stdio};

    let pipeline = settings.engine_dir.join(PIPELINE_REL);
    let mut argv = vec![pipeline.to_string_lossy().to_string()];
    argv.extend(shard::engine_argv(assignment));

    let log_dir = ai_config::ai_log_dir();
    std::fs::create_dir_all(&log_dir)
        .map_err(|e| format!("failed to create engine log dir {}: {e}", log_dir.display()))?;
    let log_path = log_dir.join(format!(
        "stage-{}-{}.log",
        assignment.spec.stage_index,
        now_unix()
    ));
    let log_file = std::fs::File::create(&log_path)
        .map_err(|e| format!("failed to create engine log {}: {e}", log_path.display()))?;

    let mut cmd = Command::new(&settings.python);
    cmd.args(&argv)
        .current_dir(&settings.engine_dir)
        // SHARD_PSK rides the ENV only (the engine's wire.key_from_env reads it);
        // it is NEVER in argv, so it can't leak into the process table / logs.
        .env(SHARD_PSK_ENV, psk)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn the shard engine ({}): {e}", settings.python))?;

    let saw_listening = Arc::new(AtomicBool::new(false));

    // Drain stdout + stderr on their own threads: mirror every line to the log
    // file and flip `saw_listening` when the engine reports it is listening. Both
    // streams share one Mutex<File> so their interleaving is a faithful transcript.
    let log = Arc::new(Mutex::new(log_file));
    if let Some(out) = child.stdout.take() {
        spawn_line_pump(out, Arc::clone(&log), Some(Arc::clone(&saw_listening)));
    }
    if let Some(err) = child.stderr.take() {
        spawn_line_pump(err, Arc::clone(&log), None);
    }

    Ok(EngineChild {
        child,
        saw_listening,
        log_path,
        started: Instant::now(),
    })
}

/// Mirror a child stream to the shared log file line-by-line; when `watch` is set,
/// flip it true on the engine's listening line. Runs until the stream closes.
fn spawn_line_pump<R: std::io::Read + Send + 'static>(
    stream: R,
    log: Arc<Mutex<std::fs::File>>,
    watch: Option<Arc<AtomicBool>>,
) {
    std::thread::spawn(move || {
        let reader = BufReader::new(stream);
        for line in reader.lines().map_while(Result::ok) {
            if let Some(flag) = &watch {
                if is_listening_line(&line) {
                    flag.store(true, Ordering::SeqCst);
                }
            }
            if let Ok(mut f) = log.lock() {
                let _ = writeln!(f, "{line}");
            }
        }
    });
}

/// True for the engine's readiness line — `phase0/pipeline.py` prints
/// `[s<stage>] listening on :<port> ...`. Matched loosely (contains "listening on")
/// so a minor engine wording change still flips readiness; the TCP probe is the
/// backstop either way.
pub fn is_listening_line(line: &str) -> bool {
    let l = line.to_ascii_lowercase();
    l.contains("listening on")
}

/// TCP-probe the local listen port to confirm the stage accepts connections
/// (readiness backstop when the log line is missed, e.g. a head stage that only
/// connects forward). Short timeout; never blocks the loop meaningfully.
fn port_accepts(port: u16) -> bool {
    let addr = local_probe_addr(port);
    addr.parse()
        .ok()
        .and_then(|a| TcpStream::connect_timeout(&a, Duration::from_millis(300)).ok())
        .is_some()
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A snapshot of the live role for the dashboard renderer (no secret, credit-only).
#[derive(Debug, Clone)]
pub struct AiStatus {
    pub state: AiState,
    pub endpoint: String,
    pub center_url: String,
    /// The current assignment's model + stage/layer range, when placed.
    pub assignment: Option<AssignmentView>,
    /// The server's whole-swarm readiness flag, when it reports one.
    pub session_ready: Option<bool>,
    pub engine_uptime_s: u64,
    pub restarts: u32,
    /// Whether the last heartbeat round-trip succeeded (None before the first).
    pub last_heartbeat_ok: Option<bool>,
    /// The last non-fatal message (a heartbeat error, a restart reason).
    pub last_message: Option<String>,
}

/// The placement view the dashboard shows (stage index + layer range + role).
#[derive(Debug, Clone, PartialEq)]
pub struct AssignmentView {
    pub model_id: String,
    pub stage_index: u32,
    pub n_stages: u32,
    pub layer_lo: u32,
    pub layer_hi: u32,
    pub role: String,
}

impl AssignmentView {
    fn from(a: &PullAssignment) -> Self {
        AssignmentView {
            model_id: a.model_id.clone(),
            stage_index: a.spec.stage_index,
            n_stages: a.spec.n_stages,
            layer_lo: a.spec.layer_lo,
            layer_hi: a.spec.layer_hi,
            role: a.spec.role.clone(),
        }
    }
}

/// Render one dashboard frame (plain, greppable — the ai role uses the line
/// renderer). CREDIT-ONLY: no hashrate, no earnings; the credit-only label mirrors
/// the rest of the CLI. Pure over its input so a test can assert the honest surface.
pub fn render_status(s: &AiStatus) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "ai · shard-stage inference · credit-only (积分)\n  state: {}\n",
        s.state.label()
    ));
    out.push_str(&format!("  endpoint: {}\n", s.endpoint));
    out.push_str(&format!("  center: {}\n", s.center_url));
    match &s.assignment {
        Some(a) => {
            out.push_str(&format!(
                "  assignment: model {} · stage {}/{} ({}) · layers [{}:{}]\n",
                a.model_id, a.stage_index, a.n_stages, a.role, a.layer_lo, a.layer_hi
            ));
        }
        None => out.push_str("  assignment: none yet (waiting for the center to place this stage)\n"),
    }
    if let Some(sr) = s.session_ready {
        out.push_str(&format!("  session_ready: {sr}\n"));
    }
    if s.engine_uptime_s > 0 {
        out.push_str(&format!("  engine uptime: {}s\n", s.engine_uptime_s));
    }
    if s.restarts > 0 {
        out.push_str(&format!("  engine restarts: {}\n", s.restarts));
    }
    match s.last_heartbeat_ok {
        Some(true) => out.push_str("  last heartbeat: ok\n"),
        Some(false) => out.push_str("  last heartbeat: FAILED\n"),
        None => {}
    }
    if let Some(m) = &s.last_message {
        out.push_str(&format!("  note: {m}\n"));
    }
    out
}

/// Run the `ai` role: resolve config, load the signing key, register, then loop
/// heartbeat+pull, supervising the engine when placed. Blocks until Ctrl-C.
pub fn run(flags: AiFlags, unlock_password: Option<Zeroizing<String>>) -> i32 {
    // Resolve the reward identity (READ-ONLY — we never create/overwrite it here).
    let Some(pointer) = alice_miner_core::identity::load_pointer() else {
        eprintln!(
            "error: no reward identity yet — create or import one first:\n  \
             alice-miner identity --create   (or --import \"<24 words>\")\n\
             (the ai role must prove it owns the reward address to register a stage; a \
             watch-only pasted address has no signing key and cannot register)"
        );
        return EXIT_USAGE;
    };
    let address = pointer.address.clone();

    let saved = ai_config::load();
    let settings = match resolve_config(flags, &address, &saved) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_USAGE;
        }
    };

    // SHARD_PSK is REQUIRED (the engine fails fast without it). Read it from the env
    // ONCE up front and fail closed with a clear message rather than spawning an
    // engine that will immediately die. It is never persisted / logged / argv'd.
    let psk = match std::env::var(SHARD_PSK_ENV) {
        Ok(v) if !v.is_empty() => Zeroizing::new(v),
        _ => {
            eprintln!(
                "error: {SHARD_PSK_ENV} is not set. The shard swarm needs a shared pre-shared key \
                 to authenticate stage-to-stage frames; the coordinator distributes it out of band. \
                 Set it in the environment (never on the command line) before starting:\n  \
                 export {SHARD_PSK_ENV}=<the swarm key>   # then: alice-miner ai ..."
            );
            return EXIT_USAGE;
        }
    };

    // The sr25519 signing key for the register/heartbeat PoP. A watch-only identity
    // fails here with the same shape the PRL lane uses (no fabricated signature).
    let secrets = match alice_miner_core::engine::resolve_prl_secrets(
        unlock_password.as_ref().map(|p| p.as_str()),
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_USAGE;
        }
    };

    // Persist the resolved public settings for a bare re-run.
    persist(&settings);

    let port = match validate_endpoint(&settings.endpoint) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_USAGE;
        }
    };

    println!(
        "Alice Miner ai — shard-stage inference worker (credit-only, 积分)\n  \
         center: {}\n  endpoint: {}\n  engine: {}\n  advertised VRAM: {:.1} GB · region: {}\n",
        settings.center_url,
        settings.endpoint,
        settings.engine_dir.join(PIPELINE_REL).display(),
        settings.vram_gb,
        settings.region,
    );

    // Ctrl-C / SIGTERM → graceful stop (kill the child, exit clean).
    let stop = Arc::new(AtomicBool::new(false));
    {
        let f = Arc::clone(&stop);
        let _ = ctrlc::set_handler(move || f.store(true, Ordering::SeqCst));
    }

    run_loop(&settings, &address, port, &secrets, &psk, &stop)
}

/// The register→loop{heartbeat,pull,supervise} core. Split from [`run`] so the
/// I/O-free parts (config, key resolution) are done and this is the long-lived
/// loop. Returns the process exit code.
fn run_loop(
    settings: &AiSettings,
    address: &str,
    port: u16,
    secrets: &alice_miner_core::alice_crypto::WalletSecrets,
    psk: &str,
    stop: &Arc<AtomicBool>,
) -> i32 {
    let mut status = AiStatus {
        state: AiState::Registering,
        endpoint: settings.endpoint.clone(),
        center_url: settings.center_url.clone(),
        assignment: None,
        session_ready: None,
        engine_uptime_s: 0,
        restarts: 0,
        last_heartbeat_ok: None,
        last_message: None,
    };

    // Register (PoP-gated). A hard failure here (bad address / no stake / PoP
    // rejected / unreachable center) is fatal — there's nothing to serve.
    print!("{}", render_status(&status));
    if let Err(e) = shard::register(
        &settings.center_url,
        address,
        &settings.endpoint,
        settings.vram_gb,
        &settings.stake_ref,
        &settings.region,
        secrets,
    ) {
        eprintln!("error: could not register this stage with the center: {e}");
        return EXIT_RUNTIME;
    }
    status.state = AiState::WaitingAssignment;
    status.last_message = Some("registered; waiting for a swarm placement".into());
    print!("{}", render_status(&status));

    let mut engine: Option<EngineChild> = None;
    // The FULL current placement (not just the view), so a crash can respawn the
    // SAME stage in place. Cleared when displaced / given up on.
    let mut current: Option<PullAssignment> = None;
    let mut restarts: u32 = 0;

    // The main loop: on each tick, heartbeat (with the live status), pull, and
    // supervise the engine if placed.
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }

        // Heartbeat (carries the live status; a server that ignores it is fine).
        match shard::heartbeat(
            &settings.center_url,
            address,
            &settings.endpoint,
            status.state.heartbeat_status(),
            secrets,
        ) {
            Ok(()) => status.last_heartbeat_ok = Some(true),
            Err(e) => {
                status.last_heartbeat_ok = Some(false);
                // A heartbeat miss is non-fatal (a transient blip / the seat was
                // pruned → re-register on the next placement). Surface + continue.
                status.last_message = Some(format!("heartbeat failed: {e}"));
            }
        }

        // Pull the current placement.
        match shard::pull(&settings.center_url, address) {
            Ok(PullOutcome::Assigned(a)) => {
                let a = *a;
                let view = AssignmentView::from(&a);
                let new_placement = status.assignment.as_ref() != Some(&view);
                status.assignment = Some(view);
                status.session_ready = a.session_ready;
                if new_placement || engine.is_none() {
                    // A fresh placement (or first) — (re)launch the engine for it.
                    if let Some(mut old) = engine.take() {
                        old.kill();
                    }
                    restarts = 0;
                    status.restarts = 0;
                    status.state = AiState::Launching;
                    print!("{}", render_status(&status));
                    match spawn_engine(settings, &a, psk) {
                        Ok(child) => {
                            status.last_message =
                                Some(format!("engine log: {}", child.log_path.display()));
                            engine = Some(child);
                        }
                        Err(e) => {
                            status.state = AiState::Error;
                            status.last_message = Some(e);
                            print!("{}", render_status(&status));
                        }
                    }
                }
                current = Some(a);
            }
            Ok(PullOutcome::NoAssignment) => {
                if engine.is_some() {
                    // Displaced (a re-form dropped this node) — stop the engine.
                    if let Some(mut old) = engine.take() {
                        old.kill();
                    }
                    status.assignment = None;
                    status.session_ready = None;
                }
                current = None;
                if status.state != AiState::WaitingAssignment {
                    status.state = AiState::WaitingAssignment;
                }
            }
            Err(e) => {
                status.last_message = Some(format!("pull failed: {e}"));
            }
        }

        // Supervise the engine child: readiness + crash detection + bounded restart.
        if let Some(child) = engine.as_mut() {
            match child.child.try_wait() {
                Ok(Some(exit)) => {
                    // The engine exited. Bounded restart with backoff.
                    let _ = exit;
                    restarts += 1;
                    status.restarts = restarts;
                    status.engine_uptime_s = 0;
                    engine = None;
                    if restarts > MAX_ENGINE_RESTARTS {
                        // Give up on THIS assignment; drop to waiting so the center
                        // can re-place it (a fresh placement resets the counter).
                        status.state = AiState::WaitingAssignment;
                        status.assignment = None;
                        status.last_message = Some(format!(
                            "engine crashed {restarts} times (>{MAX_ENGINE_RESTARTS}); giving up on \
                             this assignment — check the engine log ({}); it re-tries on the next \
                             placement",
                            child_log_hint(&status)
                        ));
                        current = None;
                    } else if let Some(a) = current.clone() {
                        status.state = AiState::Error;
                        status.last_message = Some(format!(
                            "engine exited (restart {restarts}/{MAX_ENGINE_RESTARTS}); backing off {}s",
                            RESTART_BACKOFF.as_secs()
                        ));
                        print!("{}", render_status(&status));
                        // Re-spawn after backoff, for the SAME assignment.
                        sleep_interruptible(RESTART_BACKOFF, stop);
                        if stop.load(Ordering::SeqCst) {
                            break;
                        }
                        match spawn_engine(settings, &a, psk) {
                            Ok(c) => {
                                status.state = AiState::Launching;
                                engine = Some(c);
                            }
                            Err(e) => {
                                status.state = AiState::Error;
                                status.last_message = Some(format!("respawn failed: {e}"));
                            }
                        }
                    } else {
                        status.state = AiState::WaitingAssignment;
                    }
                }
                Ok(None) => {
                    // Still running — update uptime + readiness.
                    status.engine_uptime_s = child.started.elapsed().as_secs();
                    let ready = child.saw_listening.load(Ordering::SeqCst) || port_accepts(port);
                    let new_state = if ready {
                        AiState::ServingReady
                    } else {
                        AiState::Launching
                    };
                    if new_state != status.state {
                        status.state = new_state;
                        print!("{}", render_status(&status));
                    }
                }
                Err(e) => {
                    status.last_message = Some(format!("could not poll the engine: {e}"));
                }
            }
        }

        print!("{}", render_status(&status));
        sleep_interruptible(LOOP_TICK, stop);
    }

    // Graceful shutdown: kill the child, exit clean.
    if let Some(mut child) = engine.take() {
        child.kill();
    }
    println!("\nai role stopped. (credit-only — no rewards were paid.)");
    EXIT_OK
}

/// A short pointer to the ai log dir for a give-up message (the exact per-run log
/// file is already surfaced on the launching message; this names the dir).
fn child_log_hint(_status: &AiStatus) -> String {
    engine_log_dir_display()
}

/// Sleep `dur` in short slices so Ctrl-C tears down promptly (mirrors the credit
/// poller in `start`). Returns early if the stop flag flips.
fn sleep_interruptible(dur: Duration, stop: &Arc<AtomicBool>) {
    let slices = (dur.as_millis() / 200).max(1);
    for _ in 0..slices {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// The ai log dir path (the ai role writes engine stdout/stderr here). Exposed for
/// the give-up message so the user knows where to look.
pub fn engine_log_dir_display() -> String {
    ai_config::ai_log_dir().display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alice_miner_core::ai_config::AiConfig;

    const ADDR: &str = "a2uJXaVk7Zx4fgk9aRLnhiD2RdpAP4usJxKXpN4vh4hDNoP1C";

    #[test]
    fn endpoint_validation_accepts_ipv4_ipv6_and_rejects_garbage() {
        assert_eq!(validate_endpoint("203.0.113.7:29501").unwrap(), 29501);
        assert_eq!(validate_endpoint("[2001:db8::1]:29600").unwrap(), 29600);
        assert_eq!(validate_endpoint("host.example.org:8080").unwrap(), 8080);
        assert!(validate_endpoint("").is_err());
        assert!(validate_endpoint("noport").is_err());
        assert!(validate_endpoint("host:").is_err());
        assert!(validate_endpoint(":29501").is_err());
        assert!(validate_endpoint("host:0").is_err());
        assert!(validate_endpoint("host:99999").is_err());
    }

    #[test]
    fn vram_parse_takes_largest_gpu() {
        // Two GPUs; the larger free block wins. 24576 MiB → 24.0 GB.
        assert_eq!(parse_nvidia_free_vram_gb("12288\n24576\n"), Some(24.0));
        assert_eq!(parse_nvidia_free_vram_gb("  8192  "), Some(8.0));
        assert_eq!(parse_nvidia_free_vram_gb(""), None);
        assert_eq!(parse_nvidia_free_vram_gb("garbage\n"), None);
    }

    #[test]
    fn default_stake_ref_is_address_scoped() {
        assert_eq!(default_stake_ref(ADDR), format!("enroll:{ADDR}"));
    }

    #[test]
    fn state_labels_and_heartbeat_status_map() {
        assert_eq!(AiState::Registering.heartbeat_status(), None);
        assert_eq!(AiState::WaitingAssignment.heartbeat_status(), None);
        assert_eq!(AiState::Launching.heartbeat_status(), Some("launching"));
        assert_eq!(AiState::ServingReady.heartbeat_status(), Some("ready"));
        assert_eq!(AiState::Error.heartbeat_status(), Some("error"));
        assert_eq!(AiState::ServingReady.label(), "serving-ready");
    }

    #[test]
    fn listening_line_detection() {
        assert!(is_listening_line("[s2] listening on :29501 (edge timeout 30s)"));
        assert!(is_listening_line("LISTENING ON :29501"));
        assert!(!is_listening_line("[s0] loading layers [0:12] of M ..."));
    }

    /// A temp engine dir with a stub `phase0/pipeline.py` so resolve_config's
    /// existence check passes without a real checkout.
    fn temp_engine_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "alice-ai-engine-{}-{}",
            std::process::id(),
            now_unix()
        ));
        std::fs::create_dir_all(dir.join("phase0")).unwrap();
        std::fs::write(dir.join(PIPELINE_REL), b"# stub\n").unwrap();
        dir
    }

    #[test]
    fn resolve_config_requires_endpoint_and_engine() {
        let engine = temp_engine_dir();
        // Missing endpoint → error.
        let f = AiFlags {
            engine_dir: Some(engine.to_string_lossy().to_string()),
            vram_gb: Some(24.0),
            ..Default::default()
        };
        assert!(resolve_config(f, ADDR, &AiConfig::default())
            .unwrap_err()
            .contains("--endpoint"));

        // Missing engine dir → error.
        let f = AiFlags {
            endpoint: Some("203.0.113.7:29501".into()),
            vram_gb: Some(24.0),
            ..Default::default()
        };
        assert!(resolve_config(f, ADDR, &AiConfig::default())
            .unwrap_err()
            .contains("engine-dir"));

        let _ = std::fs::remove_dir_all(&engine);
    }

    #[test]
    fn resolve_config_full_flags_and_stake_default() {
        let engine = temp_engine_dir();
        let f = AiFlags {
            center_url: Some("https://api.aliceprotocol.org".into()),
            endpoint: Some("203.0.113.7:29501".into()),
            engine_dir: Some(engine.to_string_lossy().to_string()),
            vram_gb: Some(24.0),
            region: Some("us".into()),
            ..Default::default()
        };
        let s = resolve_config(f, ADDR, &AiConfig::default()).expect("resolve");
        assert_eq!(s.center_url, "https://api.aliceprotocol.org");
        assert_eq!(s.endpoint, "203.0.113.7:29501");
        assert_eq!(s.vram_gb, 24.0);
        assert_eq!(s.region, "us");
        // Unset stake_ref → the address-scoped default.
        assert_eq!(s.stake_ref, format!("enroll:{ADDR}"));
        assert_eq!(s.python, "python3");
        let _ = std::fs::remove_dir_all(&engine);
    }

    #[test]
    fn resolve_config_rejects_non_https_center() {
        let engine = temp_engine_dir();
        let f = AiFlags {
            center_url: Some("http://insecure.example".into()),
            endpoint: Some("h:1".into()),
            engine_dir: Some(engine.to_string_lossy().to_string()),
            vram_gb: Some(8.0),
            ..Default::default()
        };
        assert!(resolve_config(f, ADDR, &AiConfig::default())
            .unwrap_err()
            .contains("https"));
        let _ = std::fs::remove_dir_all(&engine);
    }

    #[test]
    fn resolve_config_no_vram_without_allow_cpu_is_error() {
        // On a box with no nvidia-smi (CI), no --vram-gb + no --allow-cpu → error.
        // (If the test box HAS nvidia-smi this still passes: it resolves a VRAM and
        // the branch isn't reached — so assert only the allow-cpu fallback below.)
        let engine = temp_engine_dir();
        let f = AiFlags {
            endpoint: Some("h:1".into()),
            engine_dir: Some(engine.to_string_lossy().to_string()),
            allow_cpu: true,
            ..Default::default()
        };
        let s = resolve_config(f, ADDR, &AiConfig::default()).expect("allow-cpu resolves");
        assert!(s.vram_gb > 0.0, "allow-cpu advertises a positive hint");
        assert!(s.allow_cpu);
        let _ = std::fs::remove_dir_all(&engine);
    }

    #[test]
    fn render_status_is_credit_only_and_has_no_reward_tokens() {
        let s = AiStatus {
            state: AiState::ServingReady,
            endpoint: "203.0.113.7:29501".into(),
            center_url: "https://api.aliceprotocol.org".into(),
            assignment: Some(AssignmentView {
                model_id: "Qwen/Qwen2.5-3B-Instruct".into(),
                stage_index: 1,
                n_stages: 3,
                layer_lo: 12,
                layer_hi: 24,
                role: "middle".into(),
            }),
            session_ready: Some(true),
            engine_uptime_s: 42,
            restarts: 0,
            last_heartbeat_ok: Some(true),
            last_message: None,
        };
        let out = render_status(&s);
        // The honest, credit-only surface.
        assert!(out.contains("credit-only"));
        assert!(out.contains("serving-ready"));
        assert!(out.contains("stage 1/3"));
        assert!(out.contains("layers [12:24]"));
        assert!(out.contains("session_ready: true"));
        // NO fabricated reward / rate tokens.
        let low = out.to_ascii_lowercase();
        for bad in ["hashrate", "h/s", "earned", "paid", "payout", "$", "reward"] {
            assert!(!low.contains(bad), "must not contain {bad:?}: {out}");
        }
    }
}
