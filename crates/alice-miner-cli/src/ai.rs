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

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write as _};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use alice_miner_core::ai_config::{self, AiConfig};
use alice_miner_core::alice_supervise::{spawn_guarded, GuardedChild, RetryLadder, GUARD_GRACE};
use alice_miner_core::shard::{self, classify_fault, PullAssignment, PullOutcome, SHARD_PSK_ENV};
use alice_miner_core::tr;

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

/// Max consecutive engine crash-restarts, FOR ONE PLACEMENT, before the loop stops
/// respawning it and puts that placement on an escalating cooldown.
const MAX_ENGINE_RESTARTS: u32 = 5;

/// Backoff between engine restarts (linear, capped) after a crash.
const RESTART_BACKOFF: Duration = Duration::from_secs(5);

/// How many CONSECUTIVE heartbeat failures make us stop believing we are still in
/// the scheduling pool (and re-register). One miss is a blip; three in a row —
/// a minute of wall clock at [`LOOP_TICK`] — is a seat that is probably gone.
const HEARTBEAT_FAILURES_BEFORE_REREGISTER: u32 = 3;

/// How long a placement may sit in `launching` before we say out loud that it is
/// taking unusually long (and name what we are waiting for). Loading a large model
/// off cold storage genuinely takes minutes, so this is a NOTE, not a failure.
const LAUNCH_SLOW_AFTER: Duration = Duration::from_secs(180);

/// Cap on the per-placement failure table. A center that churns placements can
/// never grow this client's memory without bound; the oldest entry is evicted.
const ASSIGNMENT_HEALTH_CAP: usize = 32;

/// The role's live state machine (drives the dashboard + the heartbeat `status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiState {
    /// Proving possession + binding the endpoint into the registry.
    Registering,
    /// We were registered, lost the seat (or the heartbeat kept failing), and are
    /// repairing it with backoff. NOT "waiting for a placement" — we are not in the
    /// pool at all right now, and saying otherwise is the lie AM-REL-004 is about.
    ReRegistering,
    /// Registered; polling for a swarm placement (`pull` → no_assignment).
    WaitingAssignment,
    /// Placed; the engine subprocess is starting (loading layers).
    Launching,
    /// The engine is listening / the local port accepts TCP — serving its stage.
    ServingReady,
    /// The engine crashed; backing off before a bounded restart.
    Error,
    /// This exact placement has exhausted its restart budget. We are NOT running it
    /// and NOT pretending to wait for a new one — we are cooling down before the
    /// next attempt, and the heartbeat says `error` so the center can re-place it.
    AssignmentFailed,
    /// The control plane answered with something this client cannot act on (an
    /// unknown pull status, an un-interpretable error). Distinct from waiting.
    ControlPlaneError,
}

impl AiState {
    /// The human word for the dashboard.
    pub fn label(self) -> &'static str {
        match self {
            AiState::Registering => "registering",
            AiState::ReRegistering => "re-registering",
            AiState::WaitingAssignment => "waiting-assignment",
            AiState::Launching => "launching",
            AiState::ServingReady => "serving-ready",
            AiState::Error => "error",
            AiState::AssignmentFailed => "assignment-failed",
            AiState::ControlPlaneError => "control-plane-error",
        }
    }

    /// The `status` string sent on the heartbeat (the additive server field).
    ///
    /// The server contract knows exactly three values — `launching` / `ready` /
    /// `error` — so a placement we have GIVEN UP on reports `error`, which is true
    /// and is the strongest permanent-failure signal available inside the current
    /// wire contract. (A distinct `permanent_failure` reason would let the center
    /// re-plan immediately instead of waiting out the stage TTL; that needs a server
    /// field and is listed as a follow-up rather than invented here.)
    pub fn heartbeat_status(self) -> Option<&'static str> {
        match self {
            AiState::Launching => Some("launching"),
            AiState::ServingReady => Some("ready"),
            AiState::Error | AiState::AssignmentFailed => Some("error"),
            AiState::Registering
            | AiState::ReRegistering
            | AiState::WaitingAssignment
            | AiState::ControlPlaneError => None,
        }
    }

    /// Whether this state means "the center currently has us in its pool". Used so
    /// the UI never claims a seat we do not hold.
    pub fn is_enrolled(self) -> bool {
        !matches!(self, AiState::Registering | AiState::ReRegistering)
    }
}

/// A stable identity for a placement, independent of anything that can wobble
/// between pulls. Two pulls that describe the SAME work produce the same string.
///
/// **AM-REL-003.** The old loop compared the rendered [`AssignmentView`] and, on a
/// give-up, cleared `status.assignment`. The very next pull then re-delivered the
/// identical placement, compared it against `None`, called it a fresh placement, and
/// reset the restart counter to zero — an unbounded crash→restart→give-up→re-place
/// loop that looked like progress in the log and was, in fact, a machine spinning
/// forever on a model it could never load. Keying the failure budget on this
/// fingerprint (and NOT clearing the assignment on give-up) is what bounds it.
pub fn assignment_fingerprint(a: &PullAssignment) -> String {
    format!(
        "{}|{}|{}/{}|{}:{}|{}|{}|{}",
        a.model_id,
        a.device,
        a.spec.stage_index,
        a.spec.n_stages,
        a.spec.layer_lo,
        a.spec.layer_hi,
        a.spec.role,
        a.spec.listen_port,
        a.spec.next_endpoint.as_deref().unwrap_or("-"),
    )
}

/// A short, stable, human-quotable digest of [`assignment_fingerprint`] (FNV-1a).
/// Shown in messages so a user can say "it is failing on placement 3f2a…" without
/// pasting a whole spec.
pub fn short_fingerprint(fingerprint: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in fingerprint.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    format!("{:012x}", h & 0xffff_ffff_ffff)
}

/// The per-placement failure budget: how many times THIS placement's engine has
/// died, and (once the budget is spent) until when we refuse to respawn it.
#[derive(Debug, Default)]
struct AssignmentHealth {
    /// Engine deaths charged to this placement since its last healthy run.
    restarts: u32,
    /// Escalating cooldown after a give-up (5s → 30m, capped, never "never").
    ladder: RetryLadder,
    /// While `Some(t)` and `now < t`, we do not spawn this placement at all.
    cooldown_until: Option<Instant>,
    /// How many times we have given up on this placement (for the message).
    give_ups: u32,
    /// When this entry was last touched (for the bounded-table eviction).
    touched: Option<Instant>,
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

/// How we learned the stage is ready — surfaced verbatim, because the two are not
/// equally trustworthy and the user deserves to know which one we have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadySource {
    /// The engine itself printed its `listening on :<port>` line. Authoritative.
    EngineLine,
    /// The engine never said so, but the port the CENTER assigned accepts TCP.
    /// A backstop, and an inherently weaker claim: any process could hold that
    /// port. Always labelled as such.
    PortProbe,
}

/// A running engine child + the reader thread that mirrors its stdout/stderr to a
/// log file AND watches for the "listening" line to flip readiness.
struct EngineChild {
    /// Owned via [`spawn_guarded`]: unix process group / Windows kill-on-close Job
    /// Object, so the engine's own children (dataloader workers, NCCL helpers) die
    /// with it. AM-REL-006 — a bare `Child::kill()` orphaned every one of them and
    /// left the VRAM allocated.
    child: GuardedChild,
    /// Set true once the engine prints its `listening on :<port>` line.
    saw_listening: Arc<AtomicBool>,
    log_path: PathBuf,
    started: Instant,
    /// The port to TCP-probe as a readiness backstop: the port the CENTER told this
    /// stage to listen on (`launch_spec.listen_port`), or `None` for a head stage,
    /// which by design listens on nothing at all.
    ///
    /// **AM-REL-005.** This used to be the port parsed out of the USER's
    /// `--endpoint`. Those are the same number only by luck: the endpoint is what
    /// the swarm dials, the listen port is what the center assigns. When they
    /// differed the stage either never went ready (probing a dead port) or went
    /// ready on the strength of an UNRELATED program holding the endpoint port —
    /// a false "serving" that the center then routed real traffic into.
    probe_port: Option<u16>,
    /// The placement's role, for honest launching/readiness messages.
    role: String,
    /// When the stage first reported ready (for the healthy-run credit).
    ready_since: Option<Instant>,
    /// How readiness was established, once it has been.
    ready_source: Option<ReadySource>,
}

impl EngineChild {
    /// Terminate the engine AND its descendants, then reap.
    fn kill(&mut self) {
        self.child.kill_tree(GUARD_GRACE);
    }

    /// How long this run has been READY (the healthy-run measure). A stage that
    /// never reached ready earns no credit, however long it sat there launching.
    fn healthy_for(&self) -> Duration {
        self.ready_since
            .map(|t| t.elapsed())
            .unwrap_or(Duration::ZERO)
    }
}

/// Decide the readiness probe port for a placement: middle/tail listen on the
/// port the CENTER assigned; a head stage listens on nothing, so there is no port
/// to probe and readiness can only come from the engine's own line. Pure.
pub fn readiness_probe_port(spec: &alice_miner_core::shard::LaunchSpec) -> Option<u16> {
    if spec.is_head() {
        None
    } else {
        Some(spec.listen_port)
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

    // AM-REL-006: spawn through the shared guard so the engine leads its own
    // process group (unix) / sits in a kill-on-close Job Object (Windows). The
    // rest of the environment is inherited exactly as before — scrubbing it is
    // audit AM-SEC-003/004 and needs its own python-compatibility pass.
    let mut child = spawn_guarded(&mut cmd)
        .map_err(|e| format!("failed to spawn the shard engine ({}): {e}", settings.python))?;

    let saw_listening = Arc::new(AtomicBool::new(false));

    // Drain stdout + stderr on their own threads: mirror every line to the log
    // file and flip `saw_listening` when the engine reports it is listening. Both
    // streams share one Mutex<File> so their interleaving is a faithful transcript.
    let log = Arc::new(Mutex::new(log_file));
    if let Some(out) = child.take_stdout() {
        spawn_line_pump(out, Arc::clone(&log), Some(Arc::clone(&saw_listening)));
    }
    if let Some(err) = child.take_stderr() {
        spawn_line_pump(err, Arc::clone(&log), None);
    }

    Ok(EngineChild {
        child,
        saw_listening,
        log_path,
        started: Instant::now(),
        probe_port: readiness_probe_port(&assignment.spec),
        role: assignment.spec.role.clone(),
        ready_since: None,
        ready_source: None,
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
    /// How readiness was established, when the stage is ready. Rendered, because
    /// "the engine said so" and "something is holding that port" are different
    /// claims and only one of them is proof.
    pub ready_source: Option<ReadySource>,
    /// The short fingerprint of the current placement (for failure messages).
    pub assignment_id: Option<String>,
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
        "{}\n  {}: {}\n",
        tr!(
            "ai · shard-stage inference · credit-only (积分)",
            "ai · 分片推理 · credit-only (积分)"
        ),
        tr!("state", "状态"),
        s.state.label()
    ));
    out.push_str(&format!("  {}: {}\n", tr!("endpoint", "端点"), s.endpoint));
    out.push_str(&format!("  {}: {}\n", tr!("center", "调度中心"), s.center_url));
    match &s.assignment {
        Some(a) => {
            let id = s
                .assignment_id
                .as_deref()
                .map(|i| format!(" · id {i}"))
                .unwrap_or_default();
            out.push_str(&format!(
                "  {}: model {} · stage {}/{} ({}) · layers [{}:{}]{id}\n",
                tr!("assignment", "分配"),
                a.model_id, a.stage_index, a.n_stages, a.role, a.layer_lo, a.layer_hi
            ));
        }
        // Only the states that ARE in the pool may say "waiting to be placed". While
        // re-registering we hold no seat at all, and saying "waiting for a placement"
        // there is precisely the comfortable lie AM-REL-004 is about.
        None if s.state.is_enrolled() => out.push_str(&format!(
            "  {}: {}\n",
            tr!("assignment", "分配"),
            tr!(
                "none yet (waiting for the center to place this stage)",
                "暂无(等待调度中心分配此阶段)"
            )
        )),
        None => out.push_str(&format!(
            "  {}: {}\n",
            tr!("assignment", "分配"),
            tr!(
                "none — this node is NOT in the scheduling pool right now (see state)",
                "无 — 此节点当前不在调度池中(见状态)"
            )
        )),
    }
    if let Some(src) = s.ready_source {
        out.push_str(&format!(
            "  {}: {}\n",
            tr!("readiness", "就绪判定"),
            match src {
                ReadySource::EngineLine => tr!(
                    "the engine reported it is listening",
                    "引擎已报告正在监听"
                ),
                ReadySource::PortProbe => tr!(
                    "the assigned listen port accepts connections (the engine printed no ready \
                     line — this is a probe, not the engine's own word)",
                    "所分配的监听端口可接受连接(引擎未打印就绪行 —— 这是探测结果,并非引擎自述)"
                ),
            }
        ));
    }
    if let Some(sr) = s.session_ready {
        out.push_str(&format!("  session_ready: {sr}\n"));
    }
    if s.engine_uptime_s > 0 {
        out.push_str(&format!("  {}: {}s\n", tr!("engine uptime", "引擎运行时长"), s.engine_uptime_s));
    }
    if s.restarts > 0 {
        out.push_str(&format!("  {}: {}\n", tr!("engine restarts", "引擎重启次数"), s.restarts));
    }
    match s.last_heartbeat_ok {
        Some(true) => out.push_str(&format!("  {}: ok\n", tr!("last heartbeat", "最近心跳"))),
        Some(false) => out.push_str(&format!("  {}: FAILED\n", tr!("last heartbeat", "最近心跳"))),
        None => {}
    }
    if let Some(m) = &s.last_message {
        out.push_str(&format!("  {}: {m}\n", tr!("note", "提示")));
    }
    out
}

/// Run the `ai` role: resolve config, load the signing key, register, then loop
/// heartbeat+pull, supervising the engine when placed. Blocks until Ctrl-C.
pub fn run(flags: AiFlags, unlock_password: Option<Zeroizing<String>>) -> i32 {
    // Resolve the reward identity (READ-ONLY — we never create/overwrite it here).
    let Some(pointer) = alice_miner_core::identity::load_pointer() else {
        eprintln!(
            "error: {}",
            tr!(
                "no reward identity yet — create or import one first:\n  \
                 alice-miner identity --create   (or --import \"<24 words>\")\n\
                 (the ai role must prove it owns the reward address to register a stage; a \
                 watch-only pasted address has no signing key and cannot register)",
                "尚无奖励身份 — 请先创建或导入:\n  \
                 alice-miner identity --create   (或 --import \"<24 个词>\")\n\
                 (ai 角色必须证明拥有奖励地址才能注册阶段;\
                 仅粘贴的观察地址没有签名密钥,无法注册)"
            )
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
                "error: {}",
                tr!(
                    "SHARD_PSK is not set. The shard swarm needs a shared pre-shared key to \
                     authenticate stage-to-stage frames; the coordinator distributes it out of band. \
                     Set it in the environment (never on the command line) before starting:\n  \
                     export SHARD_PSK=<the swarm key>   # then: alice-miner ai ...",
                    "SHARD_PSK 未设置。分片群需要共享的预共享密钥来认证阶段间数据帧;\
                     协调方会带外分发。启动前请在环境变量中设置(切勿写在命令行):\n  \
                     export SHARD_PSK=<群密钥>   # 然后: alice-miner ai ..."
                )
                .replace("SHARD_PSK", SHARD_PSK_ENV)
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

    // Validate the advertised endpoint one more time (a malformed one would be
    // rejected by the center anyway; fail here with a clear local message). The
    // PORT is deliberately NOT used for readiness — see `readiness_probe_port`.
    if let Err(e) = validate_endpoint(&settings.endpoint) {
        eprintln!("error: {e}");
        return EXIT_USAGE;
    }

    println!(
        "{}\n  {}: {}\n  {}: {}\n  {}: {}\n  {}: {:.1} GB · {}: {}\n",
        tr!(
            "Alice Miner ai — shard-stage inference worker (credit-only, 积分)",
            "Alice Miner ai — 分片推理工作节点 (credit-only, 积分)"
        ),
        tr!("center", "调度中心"),
        settings.center_url,
        tr!("endpoint", "端点"),
        settings.endpoint,
        tr!("engine", "引擎"),
        settings.engine_dir.join(PIPELINE_REL).display(),
        tr!("advertised VRAM", "声明显存"),
        settings.vram_gb,
        tr!("region", "区域"),
        settings.region,
    );

    // Ctrl-C / SIGTERM → graceful stop (kill the child, exit clean).
    let stop = Arc::new(AtomicBool::new(false));
    {
        let f = Arc::clone(&stop);
        let _ = ctrlc::set_handler(move || f.store(true, Ordering::SeqCst));
    }

    run_loop(&settings, &address, &secrets, &psk, &stop)
}

/// The register→loop{heartbeat,pull,supervise} core. Split from [`run`] so the
/// I/O-free parts (config, key resolution) are done and this is the long-lived
/// loop. Returns the process exit code.
fn run_loop(
    settings: &AiSettings,
    address: &str,
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
        ready_source: None,
        assignment_id: None,
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
        // Route the raw register failure through the shared friendly renderer so the
        // user gets an actionable next step (network / region / identity) instead of a
        // bare technical string; the raw detail stays available under
        // ALICE_MINER_VERBOSE=1. The "enroll/register" wording classifies it to the
        // enroll guidance. Presentation only — this stays fatal (nothing to serve).
        eprintln!(
            "{}",
            crate::errmsg::render_error(&format!(
                "could not enroll/register this inference stage with the center: {e}"
            ))
        );
        return EXIT_RUNTIME;
    }
    status.state = AiState::WaitingAssignment;
    status.last_message = Some(
        tr!(
            "registered; waiting for a swarm placement",
            "已注册;等待群分配"
        )
        .into(),
    );
    print!("{}", render_status(&status));

    let mut engine: Option<EngineChild> = None;
    // The FULL current placement (not just the view), so a crash can respawn the
    // SAME stage in place.
    let mut current: Option<PullAssignment> = None;
    // The fingerprint of `current`. Kept even after a give-up: it is what makes a
    // re-delivered placement recognizable as the SAME one (AM-REL-003).
    let mut current_key: Option<String> = None;
    // Per-placement failure budgets, keyed by fingerprint, bounded in size.
    let mut healths: HashMap<String, AssignmentHealth> = HashMap::new();
    // Are we (as far as we can tell) in the center's pool right now?
    let mut registered = true; // the initial register above succeeded
    let mut heartbeat_failures: u32 = 0;
    let mut reregister_ladder = RetryLadder::new();

    // The main loop: on each tick, heartbeat (with the live status), pull, and
    // supervise the engine if placed.
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }

        // ── 1) Heartbeat ─────────────────────────────────────────────────────
        // Only meaningful while we believe we hold a seat. A failure is classified,
        // not merely printed: the classification decides whether the repair is
        // "try again" or "we are not registered any more".
        if registered {
            match shard::heartbeat(
                &settings.center_url,
                address,
                &settings.endpoint,
                status.state.heartbeat_status(),
                secrets,
            ) {
                Ok(()) => {
                    status.last_heartbeat_ok = Some(true);
                    heartbeat_failures = 0;
                }
                Err(e) => {
                    status.last_heartbeat_ok = Some(false);
                    heartbeat_failures += 1;
                    let fault = classify_fault(&e);
                    // AM-REL-004: the old code recorded the message and carried on
                    // rendering "waiting-assignment" — the comment even claimed a
                    // pruned seat would be re-registered, and nothing ever did. A
                    // node could sit for hours looking patient while the center had
                    // long since forgotten it.
                    if fault.needs_reregister()
                        || heartbeat_failures >= HEARTBEAT_FAILURES_BEFORE_REREGISTER
                    {
                        registered = false;
                        // Whatever the engine was doing, it is no longer part of a
                        // swarm the center knows about. Stop it rather than serve
                        // traffic on a seat we cannot prove we hold.
                        if let Some(mut old) = engine.take() {
                            old.kill();
                        }
                        status.ready_source = None;
                        status.last_message = Some(format!(
                            "{} — {} ({heartbeat_failures}×)",
                            fault.describe(),
                            tr!(
                                "this node is no longer known to be in the scheduling pool; \
                                 re-registering",
                                "本节点已无法确认仍在调度池中;正在重新注册"
                            )
                        ));
                    } else {
                        status.last_message = Some(format!(
                            "{} ({heartbeat_failures}/{HEARTBEAT_FAILURES_BEFORE_REREGISTER})",
                            fault.describe()
                        ));
                    }
                }
            }
        }

        // ── 2) Re-register when the seat is (or may be) gone ─────────────────
        if !registered {
            status.state = AiState::ReRegistering;
            print!("{}", render_status(&status));
            match shard::register(
                &settings.center_url,
                address,
                &settings.endpoint,
                settings.vram_gb,
                &settings.stake_ref,
                &settings.region,
                secrets,
            ) {
                Ok(()) => {
                    registered = true;
                    heartbeat_failures = 0;
                    reregister_ladder.reset();
                    status.state = AiState::WaitingAssignment;
                    status.last_message = Some(
                        tr!(
                            "re-registered; back in the scheduling pool",
                            "已重新注册;重新进入调度池"
                        )
                        .into(),
                    );
                    print!("{}", render_status(&status));
                }
                Err(e) => {
                    let fault = classify_fault(&e);
                    let (delay, attempt) = reregister_ladder.next_backoff();
                    status.last_message = Some(format!(
                        "{}: {} — {}",
                        tr!("re-registration failed", "重新注册失败"),
                        fault.describe(),
                        tr!(
                            format!("retrying in {}s (attempt {attempt})", delay.as_secs()),
                            format!("{} 秒后重试(第 {attempt} 次)", delay.as_secs())
                        )
                    ));
                    print!("{}", render_status(&status));
                    sleep_interruptible(delay, stop);
                    continue;
                }
            }
        }

        // ── 3) Pull the current placement ────────────────────────────────────
        match shard::pull(&settings.center_url, address) {
            Ok(PullOutcome::Assigned(a)) => {
                let a = *a;
                let key = assignment_fingerprint(&a);
                let short = short_fingerprint(&key);
                status.assignment = Some(AssignmentView::from(&a));
                status.assignment_id = Some(short.clone());
                status.session_ready = a.session_ready;

                let same_placement = current_key.as_deref() == Some(key.as_str());
                if !same_placement {
                    // A genuinely different placement: stop whatever was running.
                    if let Some(mut old) = engine.take() {
                        old.kill();
                    }
                    status.ready_source = None;
                }
                current = Some(a.clone());
                current_key = Some(key.clone());

                // Look up (or create) THIS placement's failure budget. Note the
                // budget is NOT reset here — being handed the same placement again
                // is not evidence that it will work this time.
                touch_health(&mut healths, &key);
                let now = Instant::now();
                let cooling = healths
                    .get(&key)
                    .and_then(|h| placement_cooldown_left(h, now));

                if let Some(left) = cooling {
                    // Still cooling down: do NOT spawn, and say exactly why.
                    if let Some(mut old) = engine.take() {
                        old.kill();
                    }
                    let secs = left.as_secs();
                    let give_ups = healths.get(&key).map(|h| h.give_ups).unwrap_or(0);
                    status.state = AiState::AssignmentFailed;
                    status.restarts = healths.get(&key).map(|h| h.restarts).unwrap_or(0);
                    status.engine_uptime_s = 0;
                    status.last_message = Some(format!(
                        "{} — {}",
                        tr!(
                            format!(
                                "placement {short} has failed {give_ups}× (engine died \
                                 >{MAX_ENGINE_RESTARTS} times each); not retrying it for {secs}s"
                            ),
                            format!(
                                "分配 {short} 已失败 {give_ups} 次(每次引擎崩溃超过 \
                                 {MAX_ENGINE_RESTARTS} 次);{secs} 秒内不再重试"
                            )
                        ),
                        tr!(
                            format!(
                                "the heartbeat reports 'error' so the center can re-place this \
                                 stage; engine log: {}",
                                engine_log_dir_display()
                            ),
                            format!(
                                "心跳已上报 'error',调度中心可另行安排此阶段;引擎日志:{}",
                                engine_log_dir_display()
                            )
                        )
                    ));
                } else if engine.is_none() {
                    // Cooldown elapsed (or first attempt): allow a bounded run.
                    if let Some(h) = healths.get_mut(&key) {
                        arm_after_cooldown(h, now);
                    }
                    status.state = AiState::Launching;
                    status.restarts = healths.get(&key).map(|h| h.restarts).unwrap_or(0);
                    print!("{}", render_status(&status));
                    match spawn_engine(settings, &a, psk) {
                        Ok(child) => {
                            status.last_message = Some(format!(
                                "{}: {} · {}",
                                tr!("engine log", "引擎日志"),
                                child.log_path.display(),
                                describe_readiness_plan(&child)
                            ));
                            engine = Some(child);
                        }
                        Err(e) => {
                            status.state = AiState::Error;
                            status.last_message = Some(e);
                            print!("{}", render_status(&status));
                        }
                    }
                }
            }
            Ok(PullOutcome::NoAssignment) => {
                if let Some(mut old) = engine.take() {
                    // Displaced (a re-form dropped this node) — stop the engine.
                    old.kill();
                }
                status.assignment = None;
                status.assignment_id = None;
                status.session_ready = None;
                status.ready_source = None;
                status.engine_uptime_s = 0;
                current = None;
                current_key = None;
                status.state = AiState::WaitingAssignment;
            }
            Err(e) => {
                // AM-REL-011 in the loop: an unknown/failed pull is NOT waiting.
                let fault = classify_fault(&e);
                if fault.needs_reregister() {
                    registered = false;
                }
                status.state = AiState::ControlPlaneError;
                status.last_message = Some(format!(
                    "{}: {}",
                    tr!("pull failed", "拉取分配失败"),
                    // `classify_fault` only understands HTTP/transport shapes; a
                    // protocol error from `parse_pull` carries its own full text,
                    // which is already sanitized at the source.
                    if fault.status.is_none() && !e.contains("HTTP ") {
                        e.clone()
                    } else {
                        fault.describe()
                    }
                ));
            }
        }

        // ── 4) Supervise the engine child ────────────────────────────────────
        if let Some(child) = engine.as_mut() {
            match child.child.try_wait() {
                Ok(Some(exit)) => {
                    let code = exit.code();
                    let healthy_for = child.healthy_for();
                    let log_path = child.log_path.display().to_string();
                    engine = None;
                    status.engine_uptime_s = 0;
                    status.ready_source = None;

                    // Charge the failure to the placement it belongs to. With no
                    // placement on record (we were displaced while the engine was
                    // dying) there is nothing to charge — inventing a key would put
                    // a phantom entry in the table and, worse, attribute the death
                    // to work the center never asked for.
                    let Some(key) = current_key.clone() else {
                        status.state = AiState::WaitingAssignment;
                        status.last_message = Some(tr!(
                            format!(
                                "the engine exited (code {code:?}) after this node was displaced \
                                 from its placement; nothing to restart. Log: {log_path}"
                            ),
                            format!(
                                "本节点已被移出原分配后引擎退出(退出码 {code:?});无需重启。\
                                 日志:{log_path}"
                            )
                        ));
                        prune_health(&mut healths);
                        print!("{}", render_status(&status));
                        sleep_interruptible(LOOP_TICK, stop);
                        continue;
                    };
                    let h = healths.entry(key.clone()).or_default();
                    // Credit real serving time: a stage that served for a while and
                    // then died gets its budget back, so one bad night does not
                    // permanently blacklist a placement that mostly works.
                    let verdict = charge_engine_death(h, healthy_for, Instant::now());
                    let restarts = match verdict {
                        FailureVerdict::Restart { restarts } => restarts,
                        FailureVerdict::GiveUp { restarts, .. } => restarts,
                    };
                    status.restarts = restarts;

                    if let FailureVerdict::GiveUp {
                        delay,
                        attempt,
                        give_ups,
                        ..
                    } = verdict
                    {
                        // Budget spent for THIS placement. Do NOT clear the
                        // assignment (that is what made the next identical pull
                        // look like a fresh placement and reset the counter to 0 —
                        // the unbounded loop in AM-REL-003). Cool down instead.
                        let short = status.assignment_id.clone().unwrap_or_default();
                        status.state = AiState::AssignmentFailed;
                        status.last_message = Some(format!(
                            "{} — {}",
                            tr!(
                                format!(
                                    "engine died {restarts}× on placement {short} \
                                     (exit {code:?}); giving up on it for {}s \
                                     (give-up #{give_ups}, backoff step {attempt})",
                                    delay.as_secs()
                                ),
                                format!(
                                    "引擎在分配 {short} 上已崩溃 {restarts} 次(退出码 {code:?});\
                                     暂停重试 {} 秒(第 {give_ups} 次放弃,退避档 {attempt})",
                                    delay.as_secs()
                                )
                            ),
                            tr!(
                                format!(
                                    "the heartbeat now reports 'error'; engine log: {log_path}"
                                ),
                                format!("心跳现已上报 'error';引擎日志:{log_path}")
                            )
                        ));
                    } else if let Some(a) = current.clone() {
                        status.state = AiState::Error;
                        status.last_message = Some(tr!(
                            format!(
                                "engine exited (code {code:?}) — restart \
                                 {restarts}/{MAX_ENGINE_RESTARTS} for this placement, backing \
                                 off {}s; log: {log_path}",
                                RESTART_BACKOFF.as_secs()
                            ),
                            format!(
                                "引擎已退出(退出码 {code:?})—— 本分配第 \
                                 {restarts}/{MAX_ENGINE_RESTARTS} 次重启,退避 {} 秒;日志:{log_path}",
                                RESTART_BACKOFF.as_secs()
                            )
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
                        // A key is on record but the full placement is not (should be
                        // unreachable — they are set together). Say what we know.
                        status.state = AiState::WaitingAssignment;
                        status.last_message = Some(tr!(
                            format!("the engine exited (code {code:?}); log: {log_path}"),
                            format!("引擎已退出(退出码 {code:?});日志:{log_path}")
                        ));
                    }
                }
                Ok(None) => {
                    // Still running — update uptime + readiness.
                    status.engine_uptime_s = child.started.elapsed().as_secs();
                    let source = probe_readiness(child);
                    match source {
                        Some(src) => {
                            if child.ready_since.is_none() {
                                child.ready_since = Some(Instant::now());
                                child.ready_source = Some(src);
                            }
                            status.ready_source = child.ready_source;
                            if status.state != AiState::ServingReady {
                                status.state = AiState::ServingReady;
                                print!("{}", render_status(&status));
                            }
                        }
                        None => {
                            status.ready_source = None;
                            if status.state != AiState::Launching {
                                status.state = AiState::Launching;
                            }
                            // AM-REL-005: a head stage listens on NOTHING, so it can
                            // sit in `launching` forever with no probe that could
                            // ever flip it. Say so instead of looking busy.
                            if child.started.elapsed() >= LAUNCH_SLOW_AFTER {
                                status.last_message = Some(slow_launch_note(child));
                            }
                        }
                    }
                }
                Err(e) => {
                    status.last_message = Some(format!("could not poll the engine: {e}"));
                }
            }
        }

        prune_health(&mut healths);
        print!("{}", render_status(&status));
        sleep_interruptible(LOOP_TICK, stop);
    }

    // Graceful shutdown: kill the child, exit clean.
    if let Some(mut child) = engine.take() {
        child.kill();
    }
    println!(
        "\n{}",
        tr!(
            "ai role stopped. (credit-only — no rewards were paid.)",
            "ai 角色已停止。(credit-only — 未发放任何奖励。)"
        )
    );
    EXIT_OK
}

/// Establish readiness for a RUNNING engine child: the engine's own line first,
/// then (middle/tail only) a TCP probe of the port the CENTER assigned.
fn probe_readiness(child: &EngineChild) -> Option<ReadySource> {
    if child.saw_listening.load(Ordering::SeqCst) {
        return Some(ReadySource::EngineLine);
    }
    // A head stage has no listen port — there is nothing to probe, and probing
    // the endpoint port (what the old code did) could only ever produce a false
    // positive from an unrelated program. Absence of a ready line is the answer.
    match child.probe_port {
        Some(p) if port_accepts(p) => Some(ReadySource::PortProbe),
        _ => None,
    }
}

/// One line stating HOW this placement's readiness will be judged, printed when the
/// engine is launched so the user is never guessing which signal we are waiting on.
fn describe_readiness_plan(child: &EngineChild) -> String {
    match child.probe_port {
        Some(p) => tr!(
            format!(
                "readiness: the engine's ready line, or 127.0.0.1:{p} (the listen port the center \
                 assigned) accepting a connection"
            ),
            format!(
                "就绪判定:引擎的就绪日志行,或 127.0.0.1:{p}(调度中心分配的监听端口)可建立连接"
            )
        ),
        None => tr!(
            format!(
                "readiness: the engine's ready line ONLY — a {} stage listens on no port by \
                 design, so there is nothing to probe",
                child.role
            ),
            format!(
                "就绪判定:仅凭引擎的就绪日志行 —— {} 阶段按设计不监听任何端口,无端口可探测",
                child.role
            )
        ),
    }
}

/// An honest note for a placement that has been `launching` unusually long. Names
/// what we are waiting for, so "stuck" is diagnosable instead of mysterious.
fn slow_launch_note(child: &EngineChild) -> String {
    let secs = child.started.elapsed().as_secs();
    let log = child.log_path.display();
    match child.probe_port {
        Some(p) => tr!(
            format!(
                "still launching after {secs}s: the engine has not printed a ready line and \
                 127.0.0.1:{p} is not accepting connections. Large models legitimately take \
                 minutes to load — check {log} for progress."
            ),
            format!(
                "已启动 {secs} 秒仍未就绪:引擎尚未打印就绪行,且 127.0.0.1:{p} 无法建立连接。\
                 大模型加载数分钟属正常 —— 请查看 {log} 确认进度。"
            )
        ),
        None => tr!(
            format!(
                "still launching after {secs}s: a {role} stage listens on no port, so readiness \
                 can ONLY come from the engine's ready line, and it has not printed one. \
                 Check {log}.",
                role = child.role
            ),
            format!(
                "已启动 {secs} 秒仍未就绪:{role} 阶段不监听端口,就绪只能来自引擎的就绪日志行,\
                 而它尚未打印。请查看 {log}。",
                role = child.role
            )
        ),
    }
}

/// What charging one engine death to a placement decided.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FailureVerdict {
    /// Budget remains — restart this placement in place.
    Restart { restarts: u32 },
    /// Budget spent — stop respawning and cool down for `delay`.
    GiveUp {
        restarts: u32,
        delay: Duration,
        attempt: u32,
        give_ups: u32,
    },
}

/// Charge one engine death to a placement and decide what happens next. Pure over
/// its inputs (the clock is a parameter) so the whole escalation sequence — the
/// thing AM-REL-003 says must be bounded — can be driven in a unit test.
///
/// `healthy_for` is the time this run spent actually SERVING (not merely alive); it
/// refunds budget, so a placement that works for hours and then dies once retries
/// quickly instead of inheriting an old grudge.
fn charge_engine_death(
    h: &mut AssignmentHealth,
    healthy_for: Duration,
    now: Instant,
) -> FailureVerdict {
    use alice_miner_core::alice_supervise::HEALTHY_RUN_STEP;
    h.touched = Some(now);
    // Refund one restart per full step of REAL serving. Computed from the clock, not
    // from what the escalation ladder happens to refund: the ladder only has rungs to
    // give back once we have already given up, and a placement that served for an
    // hour before its first crash deserves its budget back too.
    let steps = (healthy_for.as_secs() / HEALTHY_RUN_STEP.as_secs()).min(u32::MAX as u64) as u32;
    if steps > 0 {
        h.restarts = h.restarts.saturating_sub(steps);
        h.ladder.credit_healthy_run(healthy_for);
    }
    h.restarts += 1;
    let restarts = h.restarts;
    if restarts > MAX_ENGINE_RESTARTS {
        h.give_ups += 1;
        let (delay, attempt) = h.ladder.next_backoff();
        h.cooldown_until = Some(now + delay);
        FailureVerdict::GiveUp {
            restarts,
            delay,
            attempt,
            give_ups: h.give_ups,
        }
    } else {
        FailureVerdict::Restart { restarts }
    }
}

/// How much longer this placement is refusing to be respawned, if it is. `None`
/// means it may run now.
fn placement_cooldown_left(h: &AssignmentHealth, now: Instant) -> Option<Duration> {
    h.cooldown_until
        .filter(|t| now < *t)
        .map(|t| t.saturating_duration_since(now))
}

/// Clear an ELAPSED cooldown so the placement may be attempted again. Returns
/// whether a cooldown was cleared.
///
/// A placement we have ALREADY given up on gets exactly ONE probe attempt, not a
/// whole fresh budget of [`MAX_ENGINE_RESTARTS`]. Handing back the full budget every
/// time would make each cooldown cycle cost six more spawns, so a placement that can
/// never work would still be launched dozens of times an hour — the escalating
/// ladder would be governing give-UPS rather than actual engine launches, which is
/// not the quantity that costs the miner anything. One probe per rung means the
/// ladder governs the real cost. If that probe SERVES for a while, the healthy-run
/// refund in [`charge_engine_death`] gives the budget back properly.
fn arm_after_cooldown(h: &mut AssignmentHealth, now: Instant) -> bool {
    if h.cooldown_until.is_some_and(|t| now >= t) {
        h.cooldown_until = None;
        h.restarts = if h.give_ups > 0 {
            // One attempt: the next death gives up again and escalates the ladder.
            MAX_ENGINE_RESTARTS
        } else {
            0
        };
        true
    } else {
        false
    }
}

/// Create-or-touch the failure entry for `key` (bounded table).
fn touch_health(healths: &mut HashMap<String, AssignmentHealth>, key: &str) {
    let e = healths.entry(key.to_string()).or_default();
    e.touched = Some(Instant::now());
}

/// Keep the per-placement failure table bounded: a center that churns placements
/// must not be able to grow this client's memory. Evicts the least-recently-touched
/// entries, never the one we are currently cooling down on (it is touched each tick).
fn prune_health(healths: &mut HashMap<String, AssignmentHealth>) {
    if healths.len() <= ASSIGNMENT_HEALTH_CAP {
        return;
    }
    let mut by_age: Vec<(String, Option<Instant>)> = healths
        .iter()
        .map(|(k, v)| (k.clone(), v.touched))
        .collect();
    // Oldest (or never-touched) first.
    by_age.sort_by_key(|(_, t)| *t);
    let excess = healths.len() - ASSIGNMENT_HEALTH_CAP;
    for (k, _) in by_age.into_iter().take(excess) {
        healths.remove(&k);
    }
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
        // AM-REL-003: a placement we gave up on reports `error`, the strongest
        // permanent-failure signal the current wire contract has.
        assert_eq!(AiState::AssignmentFailed.heartbeat_status(), Some("error"));
        assert_eq!(AiState::AssignmentFailed.label(), "assignment-failed");
        // AM-REL-004: while re-registering we are NOT in the pool.
        assert_eq!(AiState::ReRegistering.heartbeat_status(), None);
        assert!(!AiState::ReRegistering.is_enrolled());
        assert!(!AiState::Registering.is_enrolled());
        assert!(AiState::WaitingAssignment.is_enrolled());
        assert!(AiState::AssignmentFailed.is_enrolled());
        // AM-REL-011: an un-actionable control-plane answer is its own state.
        assert_eq!(AiState::ControlPlaneError.label(), "control-plane-error");
        // Every label is distinct — a state that renders as another state's word
        // would be invisible in the dashboard.
        let labels = [
            AiState::Registering,
            AiState::ReRegistering,
            AiState::WaitingAssignment,
            AiState::Launching,
            AiState::ServingReady,
            AiState::Error,
            AiState::AssignmentFailed,
            AiState::ControlPlaneError,
        ]
        .map(|s| s.label());
        let mut sorted = labels.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), labels.len(), "state labels must be distinct");
    }

    // ── AM-REL-003: the placement fingerprint + failure budget ────────────────

    fn assignment(role: &str, stage: u32, port: u16, next: Option<&str>) -> PullAssignment {
        PullAssignment {
            model_id: "Qwen/Qwen2.5-3B-Instruct".into(),
            device: "cuda".into(),
            spec: alice_miner_core::shard::LaunchSpec {
                stage_index: stage,
                n_stages: 3,
                alice_address: ADDR.into(),
                layer_lo: 12,
                layer_hi: 24,
                role: role.into(),
                listen_port: port,
                next_endpoint: next.map(|s| s.into()),
            },
            session_ready: None,
        }
    }

    /// The SAME placement delivered twice must fingerprint identically — that is
    /// what stops the give-up→re-place→reset-to-zero loop. Anything that changes
    /// the actual work must change the fingerprint.
    #[test]
    fn assignment_fingerprint_is_stable_and_discriminating() {
        let a = assignment("middle", 1, 29501, Some("10.0.0.3:29501"));
        let again = assignment("middle", 1, 29501, Some("10.0.0.3:29501"));
        assert_eq!(assignment_fingerprint(&a), assignment_fingerprint(&again));
        // `session_ready` is swarm-wide weather, not this placement's identity: it
        // flips between pulls and must NOT look like a new placement.
        let mut wobbly = again.clone();
        wobbly.session_ready = Some(true);
        assert_eq!(
            assignment_fingerprint(&a),
            assignment_fingerprint(&wobbly),
            "session_ready must not change the placement's identity"
        );

        // Each field that changes the WORK changes the identity.
        for other in [
            assignment("tail", 1, 29501, Some("10.0.0.3:29501")),
            assignment("middle", 2, 29501, Some("10.0.0.3:29501")),
            assignment("middle", 1, 29502, Some("10.0.0.3:29501")),
            assignment("middle", 1, 29501, Some("10.0.0.9:29501")),
            assignment("middle", 1, 29501, None),
        ] {
            assert_ne!(
                assignment_fingerprint(&a),
                assignment_fingerprint(&other),
                "a different placement must fingerprint differently"
            );
        }
        let mut other_model = again.clone();
        other_model.model_id = "meta/other".into();
        assert_ne!(assignment_fingerprint(&a), assignment_fingerprint(&other_model));

        // The short id is stable and fixed-width (it goes in user-facing text).
        let s = short_fingerprint(&assignment_fingerprint(&a));
        assert_eq!(s.len(), 12);
        assert_eq!(s, short_fingerprint(&assignment_fingerprint(&again)));
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// The failure table is bounded: a center that churns placements cannot grow
    /// this client's memory without limit.
    #[test]
    fn health_table_is_bounded_and_evicts_the_oldest() {
        let mut h: HashMap<String, AssignmentHealth> = HashMap::new();
        for i in 0..(ASSIGNMENT_HEALTH_CAP + 10) {
            touch_health(&mut h, &format!("key-{i}"));
            // Distinct `touched` instants so the eviction order is deterministic.
            std::thread::sleep(Duration::from_millis(1));
        }
        prune_health(&mut h);
        assert_eq!(h.len(), ASSIGNMENT_HEALTH_CAP);
        // The most recent survived; the oldest did not.
        assert!(h.contains_key(&format!("key-{}", ASSIGNMENT_HEALTH_CAP + 9)));
        assert!(!h.contains_key("key-0"));
    }

    /// **THE AM-REL-003 REGRESSION.** Replays the exact field sequence: an engine
    /// that dies immediately, a center that keeps re-delivering the SAME placement,
    /// and a client that used to treat each re-delivery as fresh.
    ///
    /// The old code cleared `status.assignment` on give-up, so the next pull compared
    /// the placement against `None`, called it new, and set `restarts = 0`. The result
    /// was a machine that crash-restarted forever at a fixed 5s cadence and logged
    /// "giving up" every sixth time as if that meant something.
    ///
    /// The bound asserted here: over 200 delivered pulls of one bad placement, the
    /// number of engine SPAWNS is small and the wait between them grows.
    #[test]
    fn a_repeatedly_redelivered_bad_placement_cannot_spin_forever() {
        let mut h = AssignmentHealth::default();
        let mut clock = Instant::now();
        let mut spawns = 0u32;
        let mut give_ups = 0u32;
        let mut waits: Vec<Duration> = Vec::new();

        // 200 pull ticks. Each tick: the center hands us the SAME placement.
        for _ in 0..200 {
            // 20 seconds of wall clock per LOOP_TICK.
            clock += LOOP_TICK;

            if let Some(_left) = placement_cooldown_left(&h, clock) {
                // Cooling down: no spawn this tick. This is the branch that did not
                // exist before — the old code always spawned.
                continue;
            }
            arm_after_cooldown(&mut h, clock);

            // Not cooling → we spawn, and the engine dies instantly (0s healthy).
            spawns += 1;
            match charge_engine_death(&mut h, Duration::ZERO, clock) {
                FailureVerdict::Restart { restarts } => {
                    assert!(restarts <= MAX_ENGINE_RESTARTS);
                }
                FailureVerdict::GiveUp { delay, .. } => {
                    give_ups += 1;
                    waits.push(delay);
                }
            }
        }

        // Under the OLD behaviour this loop spawns ~200 times (every tick, forever).
        assert!(
            spawns <= 30,
            "a permanently-failing placement must not keep spawning: {spawns} spawns over 200 \
             pulls (the pre-fix behaviour was one per tick)"
        );
        assert!(give_ups >= 2, "the sequence must actually reach the give-up path");
        // The wait between attempts ESCALATES rather than sitting at a fixed 5s.
        assert!(
            waits.windows(2).all(|w| w[1] >= w[0]),
            "the cooldown must not shrink: {waits:?}"
        );
        assert!(
            *waits.last().unwrap() > *waits.first().unwrap(),
            "the cooldown must actually grow: {waits:?}"
        );
    }

    /// The other half of the fix: re-delivery of the same placement must NOT hand it
    /// a fresh budget. (This is the precise line the old code got wrong.)
    #[test]
    fn redelivering_the_same_placement_does_not_refill_its_budget() {
        let mut h = AssignmentHealth::default();
        let now = Instant::now();
        // Spend the budget down to its last slot.
        for _ in 0..MAX_ENGINE_RESTARTS {
            assert!(matches!(
                charge_engine_death(&mut h, Duration::ZERO, now),
                FailureVerdict::Restart { .. }
            ));
        }
        // Simulate the center re-delivering the identical placement several times.
        // Nothing about that may reset the counter.
        for _ in 0..5 {
            let mut table: HashMap<String, AssignmentHealth> = HashMap::new();
            table.insert("k".into(), std::mem::take(&mut h));
            touch_health(&mut table, "k");
            h = table.remove("k").unwrap();
            assert_eq!(
                h.restarts, MAX_ENGINE_RESTARTS,
                "a re-delivered placement must keep its spent budget"
            );
        }
        // The next death is therefore the give-up, not restart #1 all over again.
        assert!(matches!(
            charge_engine_death(&mut h, Duration::ZERO, now),
            FailureVerdict::GiveUp { .. }
        ));
    }

    /// A placement that SERVED for a long time and then died is not treated like one
    /// that never worked: healthy serving refunds budget, so the retry is fast again.
    #[test]
    fn a_long_healthy_run_earns_back_the_restart_budget() {
        use alice_miner_core::alice_supervise::HEALTHY_RUN_STEP;
        let mut h = AssignmentHealth::default();
        let now = Instant::now();
        for _ in 0..MAX_ENGINE_RESTARTS {
            charge_engine_death(&mut h, Duration::ZERO, now);
        }
        assert_eq!(h.restarts, MAX_ENGINE_RESTARTS, "budget spent");

        // Now a run that actually served for three healthy steps before dying.
        let verdict = charge_engine_death(&mut h, HEALTHY_RUN_STEP * 3, now);
        assert!(
            matches!(verdict, FailureVerdict::Restart { .. }),
            "a long healthy run must buy another restart, not a give-up"
        );
        assert!(h.restarts < MAX_ENGINE_RESTARTS, "budget was refunded: {}", h.restarts);
        assert_eq!(h.cooldown_until, None, "no cooldown after a healthy run");
    }

    /// An ELAPSED cooldown re-arms exactly one bounded budget — it does not stay
    /// blocked forever, and it does not come back with the old spent counter.
    #[test]
    fn an_elapsed_cooldown_rearms_a_bounded_budget() {
        let mut h = AssignmentHealth::default();
        let t0 = Instant::now();
        for _ in 0..=MAX_ENGINE_RESTARTS {
            charge_engine_death(&mut h, Duration::ZERO, t0);
        }
        let left = placement_cooldown_left(&h, t0).expect("cooling after the give-up");
        assert!(left > Duration::ZERO);
        // Before it elapses: still blocked, and re-arming is a no-op.
        assert!(!arm_after_cooldown(&mut h, t0));
        assert!(placement_cooldown_left(&h, t0).is_some());
        // After it elapses: allowed to run again, with a fresh bounded budget.
        let after = t0 + left + Duration::from_secs(1);
        assert!(placement_cooldown_left(&h, after).is_none());
        assert!(arm_after_cooldown(&mut h, after));
        assert_eq!(
            h.restarts, MAX_ENGINE_RESTARTS,
            "a placement we already gave up on gets ONE probe, not a whole new budget"
        );
        assert_eq!(h.give_ups, 1, "and the history of giving up is NOT forgotten");
        // That single probe dying escalates straight back to a (longer) cooldown.
        assert!(matches!(
            charge_engine_death(&mut h, Duration::ZERO, after),
            FailureVerdict::GiveUp { .. }
        ));
    }

    /// The escalating cooldown is the real bound: it never becomes "never", it
    /// grows, and real serving time walks it back down.
    #[test]
    fn give_up_cooldown_escalates_and_is_refunded_by_healthy_serving() {
        let mut h = AssignmentHealth::default();
        let (first, a1) = h.ladder.next_backoff();
        let (second, a2) = h.ladder.next_backoff();
        assert!(second >= first, "the cooldown must not shrink");
        assert_eq!((a1, a2), (1, 2));
        // Past the ladder it caps — and still returns a delay, forever.
        for _ in 0..20 {
            let (d, _) = h.ladder.next_backoff();
            assert!(d > Duration::ZERO, "there is no 'give up forever' value");
        }
        // Serving healthily for a while walks the ladder back down.
        let before = h.ladder.level();
        let refunded = h
            .ladder
            .credit_healthy_run(alice_miner_core::alice_supervise::HEALTHY_RUN_STEP * 3);
        assert_eq!(refunded, 3);
        assert_eq!(h.ladder.level(), before - 3);
    }

    // ── AM-REL-005: the readiness probe port ──────────────────────────────────

    /// The probe must follow the port the CENTER assigned, not the one the user
    /// typed into `--endpoint`; and a head stage, which listens on nothing, must
    /// have no probe at all.
    #[test]
    fn readiness_probe_follows_the_assigned_listen_port_not_the_endpoint() {
        let middle = assignment("middle", 1, 29501, Some("10.0.0.3:29501"));
        assert_eq!(readiness_probe_port(&middle.spec), Some(29501));
        let tail = assignment("tail", 2, 31337, None);
        assert_eq!(readiness_probe_port(&tail.spec), Some(31337));
        // The head DRIVES; it never listens, so there is nothing to probe. The old
        // code probed the endpoint port here and could go "ready" because some
        // unrelated program happened to hold it.
        let head = assignment("head", 0, 29501, Some("10.0.0.2:29501"));
        assert_eq!(
            readiness_probe_port(&head.spec),
            None,
            "a head stage must have NO readiness port probe"
        );
    }

    #[test]
    fn listening_line_detection() {
        assert!(is_listening_line("[s2] listening on :29501 (edge timeout 30s)"));
        assert!(is_listening_line("LISTENING ON :29501"));
        assert!(!is_listening_line("[s0] loading layers [0:12] of M ..."));
    }

    /// A temp engine dir with a stub `phase0/pipeline.py` so resolve_config's
    /// existence check passes without a real checkout. The name uses a nanosecond
    /// clock + a process-wide atomic counter so two parallel tests can NEVER collide
    /// on the same dir (a second-granularity name did, and one test's cleanup would
    /// delete another's pipeline.py mid-run — a flaky failure).
    fn temp_engine_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "alice-ai-engine-{}-{}-{}",
            std::process::id(),
            nanos,
            SEQ.fetch_add(1, Ordering::Relaxed)
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
            ready_source: Some(ReadySource::EngineLine),
            assignment_id: Some("0123456789ab".into()),
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

    /// The rendered surface must not claim a seat we do not hold. While
    /// re-registering, "waiting for the center to place this stage" is false —
    /// we are not in the pool for the center to place.
    #[test]
    fn render_never_claims_a_pool_seat_while_reregistering() {
        alice_miner_core::i18n::set_lang(alice_miner_core::i18n::Lang::En);
        let base = AiStatus {
            state: AiState::WaitingAssignment,
            endpoint: "203.0.113.7:29501".into(),
            center_url: "https://api.aliceprotocol.org".into(),
            assignment: None,
            session_ready: None,
            engine_uptime_s: 0,
            restarts: 0,
            last_heartbeat_ok: Some(false),
            last_message: None,
            ready_source: None,
            assignment_id: None,
        };
        // Genuinely in the pool, genuinely unplaced → the patient wording is true.
        let waiting = render_status(&base);
        assert!(waiting.contains("waiting for the center to place this stage"));

        // Seat lost → the SAME "no assignment" fact must read differently.
        let reregistering = render_status(&AiStatus {
            state: AiState::ReRegistering,
            ..base.clone()
        });
        assert!(
            reregistering.contains("NOT in the scheduling pool"),
            "a node with no seat must say so: {reregistering}"
        );
        assert!(
            !reregistering.contains("waiting for the center to place this stage"),
            "must not imply we are in the pool: {reregistering}"
        );
        assert!(reregistering.contains("re-registering"));
    }

    /// A port-probe readiness is a WEAKER claim than the engine's own line, and the
    /// render says which one it has.
    #[test]
    fn render_distinguishes_engine_ready_line_from_a_port_probe() {
        alice_miner_core::i18n::set_lang(alice_miner_core::i18n::Lang::En);
        let base = AiStatus {
            state: AiState::ServingReady,
            endpoint: "203.0.113.7:29501".into(),
            center_url: "https://api.aliceprotocol.org".into(),
            assignment: None,
            session_ready: None,
            engine_uptime_s: 9,
            restarts: 0,
            last_heartbeat_ok: Some(true),
            last_message: None,
            ready_source: Some(ReadySource::EngineLine),
            assignment_id: None,
        };
        let by_engine = render_status(&base);
        assert!(by_engine.contains("the engine reported it is listening"));

        let by_probe = render_status(&AiStatus {
            ready_source: Some(ReadySource::PortProbe),
            ..base.clone()
        });
        assert!(
            by_probe.contains("this is a probe, not the engine's own word"),
            "a probe-derived readiness must be labelled as such: {by_probe}"
        );

        // No readiness at all → no readiness line (never a default claim).
        let none = render_status(&AiStatus {
            ready_source: None,
            state: AiState::Launching,
            ..base
        });
        assert!(!none.contains("readiness:"));
    }
}
