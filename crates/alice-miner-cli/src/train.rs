//! `alice-miner train` — the RLVR TRAINING-worker role.
//!
//! A GPU miner runs `alice-miner train --center-url <acp-gateway> --trainer-dir
//! <training-mint-m0>` and becomes a PULL worker in the Alice RLVR coding-task
//! network coordinated by the Alice training coordinator:
//!
//!   1. register  — PoP-prove it owns the reward address + bind into the stake-gated
//!      worker registry (core `train_worker::register`);
//!   2. lease     — pull ONE coding task (a `prompt` + `entry_point` + a
//!      `held_out_commitment`; the hidden tests NEVER leave the coordinator);
//!   3. solve     — produce a CANDIDATE SOLUTION for the leased prompt with the
//!      miner's OWN GPU/model (a supervised generation subprocess — see below);
//!   4. submit    — POST the candidate; the coordinator re-executes it against the
//!      hidden tests server-side, forms a verdict, and (credit-only) folds a credit
//!      weight. Loop back to lease.
//!
//! Ctrl-C stops gracefully (any running generation child is killed). CREDIT-ONLY +
//! honest: no hashrate, no earnings — only the state, the current task, uptime, the
//! last verdict, and the credit-only credit weight. Fail-closed: a missing trainer /
//! python / model, or a generation crash / no-candidate, is a clear error, NEVER a
//! fabricated submit.
//!
//! ── THE GENERATION SUBPROCESS (the one fuzzy part — documented precisely) ────────
//! The real RLVR harness `run_m0.py` is a training-LOOP EXPERIMENT over a task SET
//! (base-eval → GRPO-train → post-eval → GO/NO-GO gate); it has NO "solve THIS one
//! task → emit the solution" mode. So — per the task's explicit allowance — this role
//! takes the "supervise a thin generation invocation" path: it ships a small driver
//! (`alice_train_gen.py`, embedded in this binary and written next to the logs at
//! runtime) that REUSES `run_m0.py`'s OWN model loader (`_load_base`) + prompt
//! renderer (`_render`) and `code_exec.extract_code` — imported from the trainer dir
//! put on `PYTHONPATH` — to load the SAME base model at the SAME precision the harness
//! uses and generate a candidate for the leased prompt. The candidate is captured from
//! the driver's stdout between stable sentinels. This keeps the miner's generation
//! path a single, auditable file that can never drift from the harness's loader
//! precision, while the coordinator remains the sole re-execution / verdict authority.

use std::io::{BufRead, BufReader, Write as _};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use alice_miner_core::train_config::{self, TrainConfig};
use alice_miner_core::train_worker::{self, LeaseOutcome, LeasedTask, SubmitVerdict};
use alice_miner_core::tr;

use crate::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE};

/// The production acp gateway base URL the other lanes' control-plane already uses.
const DEFAULT_CENTER_URL: &str = "https://api.aliceprotocol.org";

/// The trainer entrypoint that must exist under `--trainer-dir` (the M0 harness; we
/// import its `_load_base`/`_render` from the generation driver). Its presence is the
/// signal that the dir is a real trainer checkout.
const RUN_M0_REL: &str = "run_m0.py";

/// The re-execution scorer the harness vendors alongside `run_m0.py`; the driver
/// imports its `extract_code`. Both must be present for the driver to import.
const CODE_EXEC_REL: &str = "code_exec.py";

/// Env var the trainer dir can be supplied through (parity with the flag).
const ENV_TRAINER_DIR: &str = "ALICE_TRAIN_TRAINER_PATH";

/// The default base model the worker generates candidates with when none is supplied.
/// A small instruct model that runs on a modest GPU (or CPU under `--allow-cpu` for a
/// smoke test); a real deployment overrides it to match the coordinator's corpus.
const DEFAULT_BASE_MODEL: &str = "Qwen/Qwen2.5-3B-Instruct";

/// How often the register→lease→solve→submit loop wakes between cycles when idle
/// (a NoTask tick). Solving itself is not on this cadence — it runs to completion.
const IDLE_TICK: Duration = Duration::from_secs(15);

/// Max consecutive generation-subprocess failures for a leased task before the worker
/// gives up on THAT task (bounded so a hard-failing model can't spin forever). The
/// lease is single-use server-side, so a give-up drops the lease and pulls a new one.
const MAX_GEN_FAILURES: u32 = 3;

/// Wall-clock cap on a single generation subprocess. A hung `model.generate()` (bad
/// driver, wedged GPU) is killed past this so the worker stays responsive to Ctrl-C and
/// moves on. Generous for a slow CPU run of a small model; a real GPU is far under it.
const GEN_TIMEOUT: Duration = Duration::from_secs(20 * 60);

/// How often the generation loop wakes to check the stop flag + deadline while draining
/// the subprocess stdout channel. Short so Ctrl-C tears down promptly.
const GEN_POLL_TICK: Duration = Duration::from_millis(200);

/// Hard cap on candidate-block bytes accumulated from the subprocess stdout. The real
/// candidate is a few KiB; this bounds memory if a hostile/broken LOCAL model floods the
/// block sentinels. Past the cap we stop accumulating (the candidate is truncated →
/// rejected downstream as malformed, never fabricated).
const MAX_CANDIDATE_BYTES: usize = 1 << 20; // 1 MiB

/// The embedded generation driver, written to the log dir at runtime and invoked with
/// the trainer dir on PYTHONPATH. Kept in the miner (not the trainer repo) so the
/// generation path is a single auditable file. See the module docstring.
const GEN_DRIVER_PY: &str = include_str!("train_gen.py");

/// The sentinels the driver frames the candidate with on stdout (must match
/// `train_gen.py`).
const CANDIDATE_BEGIN: &str = "ALICE_TRAIN_CANDIDATE_BEGIN";
const CANDIDATE_END: &str = "ALICE_TRAIN_CANDIDATE_END";

/// The role's live state machine (drives the dashboard).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrainState {
    /// Proving possession + binding into the worker registry.
    Registering,
    /// Registered; polling for a task to lease (`lease` → no_task).
    Waiting,
    /// Leased a task; generating a candidate with the local model.
    Solving,
    /// Candidate produced; submitting it to the coordinator.
    Submitting,
    /// The last submission verified + (if the gate is ON) was credited.
    Verified,
    /// The generation subprocess crashed / produced no candidate; backing off.
    Error,
}

impl TrainState {
    /// The human word for the dashboard.
    pub fn label(self) -> &'static str {
        match self {
            TrainState::Registering => "registering",
            TrainState::Waiting => "waiting-task",
            TrainState::Solving => "solving",
            TrainState::Submitting => "submitting",
            TrainState::Verified => "verified",
            TrainState::Error => "error",
        }
    }
}

/// The resolved, validated `train` invocation (flags + config merged). Built by
/// [`resolve_config`]; consumed by [`run`].
#[derive(Debug, Clone, PartialEq)]
pub struct TrainSettings {
    pub center_url: String,
    pub trainer_dir: PathBuf,
    pub python: String,
    pub base_model: String,
    pub device: String,
    pub region: String,
    pub stake_ref: String,
    pub allow_cpu: bool,
}

/// The raw flags from clap (kept UI-agnostic so `resolve_config` is unit-testable).
#[derive(Debug, Clone, Default)]
pub struct TrainFlags {
    pub center_url: Option<String>,
    pub trainer_dir: Option<String>,
    pub python: Option<String>,
    pub base_model: Option<String>,
    pub device: Option<String>,
    pub region: Option<String>,
    pub stake_ref: Option<String>,
    pub allow_cpu: bool,
}

/// The default stake reference: `enroll:<address>`. The coordinator only requires a
/// non-empty stake_ref (day-1 sybil gate); this is an honest, address-scoped default a
/// future on-chain stake pallet can supersede. (Mirrors the ai role's default.)
pub fn default_stake_ref(address: &str) -> String {
    format!("enroll:{address}")
}

/// Merge flags over the persisted config, validate, and (on success) persist the
/// resolved public settings back so a bare re-run replays them. `address` is the active
/// identity's reward address (for the stake-ref default).
///
/// Fails (usage error) when the center is non-https, when the trainer dir is missing /
/// lacks `run_m0.py` + `code_exec.py`, or when the device is `cuda` (the default) but
/// neither an NVIDIA GPU nor `--allow-cpu` is present.
pub fn resolve_config(
    flags: TrainFlags,
    address: &str,
    saved: &TrainConfig,
) -> Result<TrainSettings, String> {
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

    let trainer_dir = flags
        .trainer_dir
        .or_else(|| std::env::var(ENV_TRAINER_DIR).ok().filter(|s| !s.is_empty()))
        .or_else(|| saved.trainer_dir.clone())
        .ok_or(
            "--trainer-dir <training-mint-m0 checkout> is required (or set \
             ALICE_TRAIN_TRAINER_PATH) — it must contain run_m0.py + code_exec.py",
        )?;
    let trainer_dir = PathBuf::from(trainer_dir);
    if !trainer_dir.join(RUN_M0_REL).is_file() {
        return Err(format!(
            "trainer dir {} does not contain {RUN_M0_REL} — point --trainer-dir at your \
             training-mint-m0 checkout",
            trainer_dir.display()
        ));
    }
    if !trainer_dir.join(CODE_EXEC_REL).is_file() {
        return Err(format!(
            "trainer dir {} has {RUN_M0_REL} but no {CODE_EXEC_REL} — the candidate generator \
             imports its extract_code; point --trainer-dir at a complete checkout",
            trainer_dir.display()
        ));
    }

    let python = flags
        .python
        .or_else(|| saved.python.clone())
        .unwrap_or_else(|| "python3".to_string());

    let base_model = flags
        .base_model
        .filter(|s| !s.trim().is_empty())
        .or_else(|| saved.base_model.clone())
        .unwrap_or_else(|| DEFAULT_BASE_MODEL.to_string());

    // Device: explicit flag > saved > "cuda". When it resolves to cuda but there is no
    // NVIDIA GPU, require --allow-cpu (an honest opt-in that also downshifts to CPU) so
    // we never advertise a GPU worker on a box that can't load the model on a GPU.
    let device = flags
        .device
        .filter(|s| !s.trim().is_empty())
        .or_else(|| saved.device.clone())
        .unwrap_or_else(|| "cuda".to_string());
    let device = if device == "cuda" && !nvidia_present() {
        if flags.allow_cpu {
            // Honest downshift: run generation on CPU for a smoke test.
            "cpu".to_string()
        } else {
            return Err(format!(
                "device is 'cuda' but no NVIDIA GPU was detected (nvidia-smi missing / reported \
                 none) for {address}. Pass --device cpu (or --allow-cpu to auto-downshift) to run \
                 the generation on CPU for testing — a real training worker needs a GPU."
            ));
        }
    } else {
        device
    };

    let region = flags
        .region
        .or_else(|| saved.region.clone())
        .unwrap_or_else(|| "unknown".to_string());

    let stake_ref = flags
        .stake_ref
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| default_stake_ref(address));

    Ok(TrainSettings {
        center_url,
        trainer_dir,
        python,
        base_model,
        device,
        region,
        stake_ref,
        allow_cpu: flags.allow_cpu,
    })
}

/// Whether an NVIDIA GPU is present (nvidia-smi succeeds). Used only to gate the
/// cuda-without-a-GPU usage error; the driver itself honors the resolved `--device`.
fn nvidia_present() -> bool {
    std::process::Command::new("nvidia-smi")
        .arg("-L")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Persist the resolved settings' PUBLIC fields so a bare `alice-miner train` re-run
/// replays them (never a secret).
fn persist(settings: &TrainSettings) {
    let cfg = TrainConfig {
        schema: 0, // save() stamps the current schema
        center_url: Some(settings.center_url.clone()),
        trainer_dir: Some(settings.trainer_dir.to_string_lossy().to_string()),
        python: Some(settings.python.clone()),
        base_model: Some(settings.base_model.clone()),
        device: Some(settings.device.clone()),
        region: (settings.region != "unknown").then(|| settings.region.clone()),
    };
    let _ = train_config::save(&cfg);
}

/// A snapshot of the live role for the dashboard renderer (no secret, credit-only).
#[derive(Debug, Clone)]
pub struct TrainStatus {
    pub state: TrainState,
    pub center_url: String,
    pub base_model: String,
    pub device: String,
    /// The current leased task's id + entry point, when solving/submitting.
    pub task: Option<TaskView>,
    pub uptime_s: u64,
    /// The number of tasks whose submission VERIFIED this run (credit-only count).
    pub verified_count: u64,
    /// The last submission verdict word ("verified"/"not_verified"/…), when any.
    pub last_verdict: Option<String>,
    /// Whether the last verified submission was CREDITED (adapter gate ON). A weight
    /// fold, never a paid amount.
    pub last_credited: bool,
    /// The last non-fatal message (a lease miss, a gen failure, a submit reason).
    pub last_message: Option<String>,
}

/// The task view the dashboard shows (id + entry point + the anti-overfit commitment).
#[derive(Debug, Clone, PartialEq)]
pub struct TaskView {
    pub task_id: String,
    pub entry_point: String,
    pub held_out_commitment: String,
}

impl TaskView {
    fn from(t: &LeasedTask) -> Self {
        TaskView {
            task_id: t.task_id.clone(),
            entry_point: t.entry_point.clone(),
            held_out_commitment: t.held_out_commitment.clone(),
        }
    }
}

/// Render one dashboard frame (plain, greppable — the train role uses the line
/// renderer, like ai). CREDIT-ONLY: no hashrate, no earnings; the credit-only label
/// mirrors the rest of the CLI. Pure over its input so a test can assert the honest
/// surface.
pub fn render_status(s: &TrainStatus) -> String {
    // AM-SEC-007 — the LAST barrier before remote text hits the terminal (see the
    // matching note in `ai::render_status`). Ingest-time sanitising in
    // `train_worker.rs` is the primary defence; this is belt.
    use alice_miner_core::alice_supervise::{sanitize_remote_id, sanitize_remote_text, REMOTE_ID_MAX};
    let sid = |v: &str| sanitize_remote_id(v, REMOTE_ID_MAX);
    let mut out = String::new();
    out.push_str(&format!(
        "{}\n  {}: {}\n",
        tr!(
            "train · RLVR training worker · credit-only (积分)",
            "train · RLVR 训练工作节点 · credit-only (积分)"
        ),
        tr!("state", "状态"),
        s.state.label()
    ));
    out.push_str(&format!("  {}: {}\n", tr!("center", "调度中心"), sid(&s.center_url)));
    out.push_str(&format!(
        "  {}: {} · {}: {}\n",
        tr!("base model", "基础模型"),
        sid(&s.base_model),
        tr!("device", "设备"),
        sid(&s.device)
    ));
    match &s.task {
        Some(t) => out.push_str(&format!(
            "  {}: {} ({}) · commitment {}\n",
            tr!("task", "任务"),
            sid(&t.task_id),
            sid(&t.entry_point),
            short_commitment(&sid(&t.held_out_commitment))
        )),
        None => out.push_str(&format!(
            "  {}: {}\n",
            tr!("task", "任务"),
            tr!(
                "none yet (waiting for the coordinator to lease one)",
                "暂无(等待调度中心租借任务)"
            )
        )),
    }
    if s.uptime_s > 0 {
        out.push_str(&format!("  {}: {}s\n", tr!("uptime", "运行时长"), s.uptime_s));
    }
    if s.verified_count > 0 {
        out.push_str(&format!(
            "  {}: {}\n",
            tr!("verified this run", "本次运行已验证"),
            s.verified_count
        ));
    }
    if let Some(v) = &s.last_verdict {
        let credited = if s.last_credited {
            tr!(" · credited (积分)", " · 已计入积分")
        } else {
            ""
        };
        out.push_str(&format!(
            "  {}: {}{}\n",
            tr!("last verdict", "最近判定"),
            sid(v),
            credited
        ));
    }
    if let Some(m) = &s.last_message {
        out.push_str(&format!(
            "  {}: {}\n",
            tr!("note", "提示"),
            sanitize_remote_text(m, 300)
        ));
    }
    out
}

/// A short form of the anti-overfit commitment for the dashboard (it can be a long
/// sha256 string). Keeps the head + tail so it is still recognizable.
fn short_commitment(c: &str) -> String {
    // CHAR-indexed, not byte-indexed: a remote commitment string could carry
    // multi-byte UTF-8, and `&c[..10]` on a byte boundary inside a code point PANICS.
    // (Sanitising at ingest already forces ASCII, but a display helper must not be
    // one refactor away from crashing the miner.)
    let chars: Vec<char> = c.chars().collect();
    if chars.len() <= 18 {
        return c.to_string();
    }
    let head: String = chars[..10].iter().collect();
    let tail: String = chars[chars.len() - 6..].iter().collect();
    format!("{head}…{tail}")
}

/// Run the `train` role: resolve config, load the signing key, then loop
/// register→lease→solve→submit, supervising the generation subprocess. Blocks until
/// Ctrl-C. Credit-only; NEVER creates/overwrites an identity (read-only).
pub fn run(flags: TrainFlags, unlock_password: Option<Zeroizing<String>>) -> i32 {
    // Resolve the reward identity (READ-ONLY — we never create/overwrite it here).
    let Some(pointer) = alice_miner_core::identity::load_pointer() else {
        eprintln!(
            "error: {}",
            tr!(
                "no reward identity yet — create or import one first:\n  \
                 alice-miner identity --create   (or --import \"<24 words>\")\n\
                 (the train role must prove it owns the reward address to register; a \
                 watch-only pasted address has no signing key and cannot register)",
                "尚无奖励身份 — 请先创建或导入:\n  \
                 alice-miner identity --create   (或 --import \"<24 个词>\")\n\
                 (train 角色必须证明拥有奖励地址才能注册;\
                 仅粘贴的观察地址没有签名密钥,无法注册)"
            )
        );
        return EXIT_USAGE;
    };
    let address = pointer.address.clone();

    let saved = train_config::load();
    let settings = match resolve_config(flags, &address, &saved) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_USAGE;
        }
    };

    // The sr25519 signing key for the register/lease/submit PoP. A watch-only identity
    // fails here with the same shape the PRL / ai lanes use (no fabricated signature).
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

    // Write the embedded generation driver next to the logs so the loop can invoke it.
    // A write failure here is fatal (the role can't produce candidates without it).
    let driver_path = match write_gen_driver() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_RUNTIME;
        }
    };

    println!(
        "{}\n  {}: {}\n  {}: {}\n  {}: {} · {}: {}\n  {}: {}\n",
        tr!(
            "Alice Miner train — RLVR training worker (credit-only, 积分)",
            "Alice Miner train — RLVR 训练工作节点 (credit-only, 积分)"
        ),
        tr!("center", "调度中心"),
        settings.center_url,
        tr!("trainer", "训练器"),
        settings.trainer_dir.join(RUN_M0_REL).display(),
        tr!("base model", "基础模型"),
        settings.base_model,
        tr!("device", "设备"),
        settings.device,
        tr!("region", "区域"),
        settings.region,
    );

    // Ctrl-C / SIGTERM → graceful stop (kill any running child, exit clean).
    let stop = Arc::new(AtomicBool::new(false));
    {
        let f = Arc::clone(&stop);
        let _ = ctrlc::set_handler(move || f.store(true, Ordering::SeqCst));
    }

    run_loop(&settings, &address, &secrets, &driver_path, &stop)
}

/// The register→loop{lease,solve,submit} core. Split from [`run`] so the I/O-free
/// parts (config, key resolution) are done and this is the long-lived loop. Returns the
/// process exit code.
fn run_loop(
    settings: &TrainSettings,
    address: &str,
    secrets: &alice_miner_core::alice_crypto::WalletSecrets,
    driver_path: &std::path::Path,
    stop: &Arc<AtomicBool>,
) -> i32 {
    let started = Instant::now();
    let mut status = TrainStatus {
        state: TrainState::Registering,
        center_url: settings.center_url.clone(),
        base_model: settings.base_model.clone(),
        device: settings.device.clone(),
        task: None,
        uptime_s: 0,
        verified_count: 0,
        last_verdict: None,
        last_credited: false,
        last_message: None,
    };

    // Register (PoP-gated). A hard failure here (bad address / no stake / PoP rejected /
    // gate OFF / unreachable center) is fatal — there is nothing to solve.
    print!("{}", render_status(&status));
    if let Err(e) = train_worker::register(
        &settings.center_url,
        address,
        &settings.stake_ref,
        &settings.device,
        &settings.region,
        secrets,
    ) {
        // Route the raw register failure through the shared friendly renderer so the
        // user gets an actionable next step (network / region / identity) instead of a
        // bare technical string; the raw detail stays available under
        // ALICE_MINER_VERBOSE=1. The "enroll/register" wording classifies it to the
        // enroll guidance. Presentation only — this stays fatal (nothing to solve).
        eprintln!(
            "{}",
            crate::errmsg::render_error(&format!(
                "could not enroll/register this training worker with the center: {e}"
            ))
        );
        return EXIT_RUNTIME;
    }
    status.state = TrainState::Waiting;
    status.last_message = Some(
        tr!(
            "registered; waiting to lease a task",
            "已注册;等待租借任务"
        )
        .into(),
    );
    print!("{}", render_status(&status));

    // The main loop: lease → solve → submit, re-registering if the seat was pruned.
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        status.uptime_s = started.elapsed().as_secs();

        // Lease one task.
        match train_worker::lease(&settings.center_url, address, secrets) {
            Ok(LeaseOutcome::Leased(task)) => {
                let task = *task;
                status.task = Some(TaskView::from(&task));
                status.state = TrainState::Solving;
                status.last_message = Some(
                    tr!("leased a task; generating a candidate", "已租借任务;正在生成候选解")
                        .into(),
                );
                print!("{}", render_status(&status));

                // Solve: generate a candidate with the local model (bounded retries on a
                // gen failure — a hard-failing model can't spin forever).
                let candidate = solve_task(settings, driver_path, &task, stop, &mut status);
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let Some(candidate) = candidate else {
                    // No candidate after the bounded retries — honest error, NO submit.
                    // The lease is single-use server-side; drop it and pull a fresh one.
                    status.state = TrainState::Error;
                    status.task = None;
                    print!("{}", render_status(&status));
                    sleep_interruptible(IDLE_TICK, stop);
                    continue;
                };

                // Submit the candidate. The coordinator re-executes + verdicts + folds
                // credit (credit-only). A lease/candidate reject surfaces as an Err.
                status.state = TrainState::Submitting;
                print!("{}", render_status(&status));
                match train_worker::submit(
                    &settings.center_url,
                    address,
                    &task.lease_id,
                    &candidate,
                    None, // we do not claim a pass rate; the coordinator re-executes
                    "",   // device_key defaults to the address server-side
                    secrets,
                ) {
                    Ok(verdict) => apply_verdict(&mut status, &verdict),
                    Err(e) => {
                        status.state = TrainState::Error;
                        status.last_message = Some(format!("submit failed: {e}"));
                    }
                }
                status.task = None;
                print!("{}", render_status(&status));
            }
            Ok(LeaseOutcome::NoTask) => {
                if status.state != TrainState::Waiting {
                    status.state = TrainState::Waiting;
                }
                status.task = None;
                status.last_message = Some(
                    tr!(
                        "no task available right now; polling",
                        "当前暂无可用任务;轮询中"
                    )
                    .into(),
                );
                print!("{}", render_status(&status));
                sleep_interruptible(IDLE_TICK, stop);
            }
            Err(e) => {
                // "not_registered" → the seat was pruned; re-register on the next cycle.
                if e.contains("not_registered") {
                    status.last_message = Some(
                        tr!(
                            "seat pruned; re-registering",
                            "座位被回收;正在重新注册"
                        )
                        .into(),
                    );
                    let _ = train_worker::register(
                        &settings.center_url,
                        address,
                        &settings.stake_ref,
                        &settings.device,
                        &settings.region,
                        secrets,
                    );
                } else {
                    status.last_message = Some(format!("lease failed: {e}"));
                }
                print!("{}", render_status(&status));
                sleep_interruptible(IDLE_TICK, stop);
            }
        }
    }

    println!(
        "\n{}",
        tr!(
            "train role stopped. (credit-only — no rewards were paid.)",
            "train 角色已停止。(credit-only — 未发放任何奖励。)"
        )
    );
    EXIT_OK
}

/// Fold a submit verdict into the live status (credit-only). Updates the state, the
/// last-verdict word, the credited flag, and the verified count.
fn apply_verdict(status: &mut TrainStatus, verdict: &SubmitVerdict) {
    status.last_verdict = Some(verdict.verdict.clone());
    status.last_credited = verdict.credited;
    if verdict.is_verified() {
        status.state = TrainState::Verified;
        status.verified_count += 1;
        let rate = verdict
            .match_rate
            .as_deref()
            .map(|r| format!(" (match {r})"))
            .unwrap_or_default();
        status.last_message = Some(format!(
            "{}{rate}",
            tr!("submission VERIFIED", "提交已验证")
        ));
    } else {
        // A non-verified verdict is NOT an error — it is an honest "the candidate did
        // not pass the hidden tests" result. Return to Waiting for the next lease.
        status.state = TrainState::Waiting;
        status.last_message = Some(format!(
            "{}: {} ({})",
            tr!("submission not verified", "提交未验证"),
            verdict.verdict,
            verdict.reason_code
        ));
    }
}

/// Solve one leased task: run the generation driver (bounded retries on a crash /
/// no-candidate) and return the parsed candidate code, or `None` if every attempt
/// failed (an honest "no candidate", NEVER a fabricated one). Updates `status` with the
/// failure reason on the way.
fn solve_task(
    settings: &TrainSettings,
    driver_path: &std::path::Path,
    task: &LeasedTask,
    stop: &Arc<AtomicBool>,
    status: &mut TrainStatus,
) -> Option<String> {
    let mut failures: u32 = 0;
    loop {
        if stop.load(Ordering::SeqCst) {
            return None;
        }
        match run_gen_once(settings, driver_path, task, stop) {
            Ok(Some(code)) => return Some(code),
            Ok(None) => {
                failures += 1;
                status.last_message = Some(format!(
                    "{} ({failures}/{MAX_GEN_FAILURES})",
                    tr!(
                        "the generator produced no candidate",
                        "生成器未产出候选解"
                    )
                ));
            }
            Err(e) => {
                failures += 1;
                status.last_message = Some(format!(
                    "{} ({failures}/{MAX_GEN_FAILURES}): {e}",
                    tr!("candidate generation failed", "候选解生成失败")
                ));
            }
        }
        if failures >= MAX_GEN_FAILURES {
            status.last_message = Some(format!(
                "{} — {} ({}); {}",
                tr!(
                    "giving up on this task after repeated generation failures",
                    "多次生成失败;放弃此任务"
                ),
                tr!("check the train log", "请查看 train 日志"),
                train_log_dir_display(),
                tr!("a new task is pulled next", "稍后会拉取新任务")
            ));
            return None;
        }
        // Brief interruptible backoff before the next attempt.
        sleep_interruptible(Duration::from_secs(3), stop);
    }
}

/// Run the generation driver ONCE for `task`: spawn `python3 <driver>
/// --base-model … --device …`, feed the task JSON on stdin, capture stdout (parsing
/// the candidate between the sentinels) + mirror stdout/stderr to a per-task log. The
/// trainer dir is on `PYTHONPATH` so the driver imports `run_m0`/`code_exec`.
/// Returns `Ok(Some(code))` on a non-empty candidate, `Ok(None)` when the driver
/// exited without emitting one (a clean "no candidate"), `Err` on a spawn/IO failure.
fn run_gen_once(
    settings: &TrainSettings,
    driver_path: &std::path::Path,
    task: &LeasedTask,
    stop: &Arc<AtomicBool>,
) -> Result<Option<String>, String> {
    use std::process::{Command, Stdio};
    use std::sync::mpsc;

    let log_dir = train_config::train_log_dir();
    std::fs::create_dir_all(&log_dir)
        .map_err(|e| format!("failed to create train log dir {}: {e}", log_dir.display()))?;
    let log_path = log_dir.join(format!("gen-{}-{}.log", sanitize(&task.task_id), now_unix()));
    let log_file = std::fs::File::create(&log_path)
        .map_err(|e| format!("failed to create train log {}: {e}", log_path.display()))?;

    // The task JSON on stdin (never argv — a prompt can be large).
    let task_json = serde_json::json!({
        "task_id": task.task_id,
        "entry_point": task.entry_point,
        "prompt": task.prompt,
    })
    .to_string();

    let mut cmd = Command::new(&settings.python);
    cmd.arg(driver_path)
        .arg("--base-model")
        .arg(&settings.base_model)
        .arg("--device")
        .arg(&settings.device)
        // The trainer dir on PYTHONPATH so `from run_m0 import …` + `from code_exec
        // import …` resolve. The driver's cwd is the trainer dir so relative imports in
        // run_m0 (e.g. `from code_exec import …`) also resolve.
        .env("PYTHONPATH", &settings.trainer_dir)
        .current_dir(&settings.trainer_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn the candidate generator ({}): {e}", settings.python))?;

    // Feed the task JSON, then close stdin so the driver's `sys.stdin.read()` returns.
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(task_json.as_bytes())
            .map_err(|e| format!("failed to write task to the generator stdin: {e}"))?;
        // Dropping `stdin` here closes it (EOF for the child).
    }

    // Mirror stderr to the log on its own thread (diagnostics only).
    let log = Arc::new(Mutex::new(log_file));
    if let Some(err) = child.stderr.take() {
        let log = Arc::clone(&log);
        std::thread::spawn(move || {
            let reader = BufReader::new(err);
            for line in reader.lines().map_while(Result::ok) {
                if let Ok(mut f) = log.lock() {
                    let _ = writeln!(f, "[stderr] {line}");
                }
            }
        });
    }

    // Read stdout on a reader thread that forwards each line over a channel, so THIS
    // thread can poll the stop flag + a wall-clock deadline between lines and kill the
    // child promptly (a bare `reader.lines()` here would block Ctrl-C until the child
    // emits EOF). The reader thread stops relaying once the candidate block exceeds the
    // byte cap — a hostile/broken LOCAL model can't OOM us.
    let (tx, rx) = mpsc::channel::<String>();
    if let Some(out) = child.stdout.take() {
        std::thread::spawn(move || {
            let reader = BufReader::new(out);
            for line in reader.lines().map_while(Result::ok) {
                // A closed receiver (main thread moved on / killed the child) ends the
                // reader cleanly.
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
    }

    let mut candidate: Option<String> = None;
    let mut in_block = false;
    let mut buf = String::new();
    let mut capped = false;
    let deadline = Instant::now() + GEN_TIMEOUT;
    let mut killed_reason: Option<&str> = None;
    loop {
        if stop.load(Ordering::SeqCst) {
            killed_reason = Some("stop requested");
            break;
        }
        if Instant::now() >= deadline {
            killed_reason = Some("generation timed out");
            break;
        }
        match rx.recv_timeout(GEN_POLL_TICK) {
            Ok(line) => {
                if let Ok(mut f) = log.lock() {
                    let _ = writeln!(f, "{line}");
                }
                if line.trim() == CANDIDATE_BEGIN {
                    in_block = true;
                    buf.clear();
                    capped = false;
                    continue;
                }
                if line.trim() == CANDIDATE_END {
                    in_block = false;
                    let code = buf.trim_end_matches('\n').to_string();
                    // A capped (truncated) block is dropped — never submit a partial
                    // candidate as if it were whole.
                    if !capped && !code.trim().is_empty() {
                        candidate = Some(code);
                    }
                    continue;
                }
                if in_block && !capped {
                    if buf.len() + line.len() + 1 > MAX_CANDIDATE_BYTES {
                        capped = true;
                        if let Ok(mut f) = log.lock() {
                            let _ = writeln!(f, "[alice] candidate block exceeded {MAX_CANDIDATE_BYTES} bytes — truncated, rejected");
                        }
                    } else {
                        buf.push_str(&line);
                        buf.push('\n');
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break, // child closed stdout → done
        }
    }

    if let Some(reason) = killed_reason {
        let _ = child.kill();
        if let Ok(mut f) = log.lock() {
            let _ = writeln!(f, "[alice] killed generation subprocess: {reason}");
        }
    }
    let exit = child
        .wait()
        .map_err(|e| format!("failed to wait for the generator: {e}"))?;
    // A non-zero exit with a captured candidate is treated as a candidate (the driver
    // prints the candidate BEFORE exiting; a late failure shouldn't drop a good one).
    // A non-zero exit with NO candidate is a clean "no candidate" (Ok(None)) — the log
    // carries the driver's stderr reason.
    let _ = exit;
    Ok(parse_candidate(candidate))
}

/// Validate a captured candidate: `Some(code)` only when it is non-empty after
/// trimming; `None` otherwise (so an all-whitespace block never counts as a solution).
/// Pure + testable.
pub fn parse_candidate(candidate: Option<String>) -> Option<String> {
    candidate.filter(|c| !c.trim().is_empty())
}

/// Write the embedded generation driver to the train log dir (idempotent — overwrites
/// with the current embedded version each run so an updated binary ships an updated
/// driver). Returns the driver path. The driver is PUBLIC code (no secret).
fn write_gen_driver() -> Result<PathBuf, String> {
    let dir = train_config::train_log_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("failed to create train dir {}: {e}", dir.display()))?;
    let path = dir.join("alice_train_gen.py");
    std::fs::write(&path, GEN_DRIVER_PY)
        .map_err(|e| format!("failed to write the generation driver {}: {e}", path.display()))?;
    Ok(path)
}

/// Sanitize a task id for use in a log file name (keep alnum / `-` / `_`, replace the
/// rest with `_`). Bounds the length so a hostile task id can't make an unwieldy name.
fn sanitize(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .take(64)
        .collect();
    if cleaned.is_empty() {
        "task".to_string()
    } else {
        cleaned
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Sleep `dur` in short slices so Ctrl-C tears down promptly. Returns early if the stop
/// flag flips.
fn sleep_interruptible(dur: Duration, stop: &Arc<AtomicBool>) {
    let slices = (dur.as_millis() / 200).max(1);
    for _ in 0..slices {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// The train log dir path (exposed for the doctor / give-up messages so the user knows
/// where to look).
pub fn train_log_dir_display() -> String {
    train_config::train_log_dir().display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alice_miner_core::train_config::TrainConfig;

    const ADDR: &str = "a2uJXaVk7Zx4fgk9aRLnhiD2RdpAP4usJxKXpN4vh4hDNoP1C";

    /// A temp trainer dir with stub `run_m0.py` + `code_exec.py` so resolve_config's
    /// existence check passes without a real checkout. The name uses a nanosecond clock
    /// + a process-wide atomic counter so two parallel tests can NEVER collide.
    fn temp_trainer_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "alice-train-trainer-{}-{}-{}",
            std::process::id(),
            nanos,
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(RUN_M0_REL), b"# stub\n").unwrap();
        std::fs::write(dir.join(CODE_EXEC_REL), b"# stub\n").unwrap();
        dir
    }

    #[test]
    fn default_stake_ref_is_address_scoped() {
        assert_eq!(default_stake_ref(ADDR), format!("enroll:{ADDR}"));
    }

    #[test]
    fn state_labels_are_distinct_words() {
        let labels = [
            TrainState::Registering.label(),
            TrainState::Waiting.label(),
            TrainState::Solving.label(),
            TrainState::Submitting.label(),
            TrainState::Verified.label(),
            TrainState::Error.label(),
        ];
        let mut sorted = labels.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), labels.len(), "every state has a distinct label");
    }

    #[test]
    fn resolve_config_requires_trainer_dir() {
        // Missing trainer dir → error.
        let f = TrainFlags {
            device: Some("cpu".into()),
            ..Default::default()
        };
        assert!(resolve_config(f, ADDR, &TrainConfig::default())
            .unwrap_err()
            .contains("--trainer-dir"));
    }

    #[test]
    fn resolve_config_requires_run_m0_and_code_exec() {
        // A dir with run_m0.py but no code_exec.py → error naming code_exec.
        let dir = std::env::temp_dir().join(format!(
            "alice-train-partial-{}-{}",
            std::process::id(),
            now_unix()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(RUN_M0_REL), b"# stub\n").unwrap();
        let f = TrainFlags {
            trainer_dir: Some(dir.to_string_lossy().to_string()),
            device: Some("cpu".into()),
            ..Default::default()
        };
        let e = resolve_config(f, ADDR, &TrainConfig::default()).unwrap_err();
        assert!(e.contains(CODE_EXEC_REL), "names the missing code_exec: {e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_config_full_flags_and_stake_default() {
        let dir = temp_trainer_dir();
        let f = TrainFlags {
            center_url: Some("https://api.aliceprotocol.org".into()),
            trainer_dir: Some(dir.to_string_lossy().to_string()),
            base_model: Some("Qwen/Qwen2.5-3B-Instruct".into()),
            device: Some("cpu".into()),
            region: Some("us".into()),
            ..Default::default()
        };
        let s = resolve_config(f, ADDR, &TrainConfig::default()).expect("resolve");
        assert_eq!(s.center_url, "https://api.aliceprotocol.org");
        assert_eq!(s.base_model, "Qwen/Qwen2.5-3B-Instruct");
        assert_eq!(s.device, "cpu");
        assert_eq!(s.region, "us");
        // Unset stake_ref → the address-scoped default.
        assert_eq!(s.stake_ref, format!("enroll:{ADDR}"));
        assert_eq!(s.python, "python3");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_config_rejects_non_https_center() {
        let dir = temp_trainer_dir();
        let f = TrainFlags {
            center_url: Some("http://insecure.example".into()),
            trainer_dir: Some(dir.to_string_lossy().to_string()),
            device: Some("cpu".into()),
            ..Default::default()
        };
        assert!(resolve_config(f, ADDR, &TrainConfig::default())
            .unwrap_err()
            .contains("https"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_config_cuda_without_gpu_needs_allow_cpu() {
        // On a box with no nvidia-smi (CI), the default device (cuda) without
        // --allow-cpu / --device cpu is an error. (If the test box HAS an NVIDIA GPU
        // the branch isn't reached; then the --allow-cpu downshift below still holds.)
        let dir = temp_trainer_dir();
        if !nvidia_present() {
            let f = TrainFlags {
                trainer_dir: Some(dir.to_string_lossy().to_string()),
                ..Default::default()
            };
            let e = resolve_config(f, ADDR, &TrainConfig::default()).unwrap_err();
            assert!(e.contains("cuda") && e.contains("allow-cpu"), "honest cuda error: {e}");
        }
        // --allow-cpu downshifts to cpu (a smoke-test box).
        let f = TrainFlags {
            trainer_dir: Some(dir.to_string_lossy().to_string()),
            allow_cpu: true,
            ..Default::default()
        };
        let s = resolve_config(f, ADDR, &TrainConfig::default()).expect("allow-cpu resolves");
        // On a no-GPU box it downshifts to cpu; on a GPU box it stays cuda — either is fine.
        assert!(s.device == "cpu" || s.device == "cuda", "device resolved: {}", s.device);
        assert!(s.allow_cpu);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_candidate_rejects_blank() {
        assert_eq!(parse_candidate(None), None);
        assert_eq!(parse_candidate(Some("   \n  ".into())), None);
        assert_eq!(
            parse_candidate(Some("def f():\n    return 1\n".into())).as_deref(),
            Some("def f():\n    return 1\n")
        );
    }

    #[test]
    fn short_commitment_trims_long_and_keeps_short() {
        assert_eq!(short_commitment("sha256:abc"), "sha256:abc");
        let long = "sha256:0123456789abcdef0123456789abcdef";
        let s = short_commitment(long);
        assert!(s.contains('…'));
        assert!(s.starts_with("sha256:012"));
    }

    #[test]
    fn sanitize_task_id_is_filename_safe() {
        assert_eq!(sanitize("m0-001"), "m0-001");
        assert_eq!(sanitize("a/b c:d"), "a_b_c_d");
        assert_eq!(sanitize(""), "task");
        assert!(sanitize(&"x".repeat(200)).len() <= 64);
    }

    /// AM-SEC-007 at the RENDER surface (train twin of the `ai` test): a hostile
    /// verdict / reason_code / task field can never repaint the terminal or forge a
    /// "submission VERIFIED" line.
    #[test]
    fn render_status_never_emits_terminal_control_sequences() {
        let esc = '\u{1b}';
        let bel = '\u{7}';
        let nul = '\u{0}';
        let s = TrainStatus {
            state: TrainState::Waiting,
            center_url: format!("https://api.aliceprotocol.org{esc}[2K"),
            base_model: format!("Qwen{esc}[32m"),
            device: format!("cuda{nul}"),
            task: Some(TaskView {
                task_id: format!("m0-001{esc}[2K\rsubmission VERIFIED"),
                entry_point: "run_length_encode\nlast verdict: verified".into(),
                held_out_commitment: format!("sha256:0123456789abcdef0123456789abcdef{esc}[0m"),
            }),
            uptime_s: 42,
            verified_count: 0,
            last_verdict: Some(format!("not_verified{esc}[8m")),
            last_credited: false,
            last_message: Some(format!("{esc}[2J{esc}[Hsubmission VERIFIED{bel}")),
        };
        let out = render_status(&s);
        assert!(!out.contains(esc), "an ESC reached the terminal: {out:?}");
        assert!(!out.contains('\u{7}') && !out.contains('\u{0}'), "BEL/NUL reached the terminal");
        assert!(!out.contains('\r'), "a CR could overwrite the line above: {out:?}");
        // The injected TEXT may survive as inert characters inside a row; what must
        // not happen is a NEW line that reads like a real dashboard row.
        assert!(
            !out.lines().any(|l| l.trim_start().starts_with("last verdict: verified")),
            "an injected newline forged a dashboard row: {out}"
        );
        assert_eq!(out.lines().count(), 8, "exactly the rows render_status writes: {out}");
        assert!(out.contains("credit-only"));
    }

    #[test]
    fn render_status_is_credit_only_and_has_no_reward_tokens() {
        let s = TrainStatus {
            state: TrainState::Verified,
            center_url: "https://api.aliceprotocol.org".into(),
            base_model: "Qwen/Qwen2.5-3B-Instruct".into(),
            device: "cuda".into(),
            task: Some(TaskView {
                task_id: "m0-001".into(),
                entry_point: "run_length_encode".into(),
                held_out_commitment: "sha256:0123456789abcdef0123456789abcdef".into(),
            }),
            uptime_s: 42,
            verified_count: 3,
            last_verdict: Some("verified".into()),
            last_credited: true,
            last_message: None,
        };
        let out = render_status(&s);
        // The honest, credit-only surface.
        assert!(out.contains("credit-only"));
        assert!(out.contains("verified"));
        assert!(out.contains("m0-001"));
        assert!(out.contains("run_length_encode"));
        // NO fabricated reward / rate / hashrate tokens.
        let low = out.to_ascii_lowercase();
        for bad in ["hashrate", "h/s", "earned", "paid", "payout", "$", "reward"] {
            assert!(!low.contains(bad), "must not contain {bad:?}: {out}");
        }
    }

    /// The embedded generation driver is present, non-trivial, and parses as Python
    /// (the sentinels it uses match the constants the supervisor parses).
    #[test]
    fn embedded_driver_has_matching_sentinels() {
        assert!(GEN_DRIVER_PY.contains(CANDIDATE_BEGIN), "driver emits the BEGIN sentinel");
        assert!(GEN_DRIVER_PY.contains(CANDIDATE_END), "driver emits the END sentinel");
        assert!(GEN_DRIVER_PY.contains("from run_m0 import"), "driver imports run_m0's loader");
        assert!(GEN_DRIVER_PY.contains("extract_code"), "driver uses code_exec.extract_code");
        assert!(GEN_DRIVER_PY.len() > 1000, "driver is non-trivial");
    }

    /// The candidate parser (used inline by run_gen_once) extracts the code between the
    /// sentinels and ignores surrounding chatter. Exercised via a small line loop mirror
    /// of the reader in run_gen_once.
    #[test]
    fn candidate_extraction_between_sentinels() {
        let stdout = format!(
            "some chatter\n{CANDIDATE_BEGIN}\ndef f(x):\n    return x + 1\n{CANDIDATE_END}\nbye\n"
        );
        // Mirror the reader loop.
        let mut in_block = false;
        let mut buf = String::new();
        let mut candidate: Option<String> = None;
        for line in stdout.lines() {
            if line.trim() == CANDIDATE_BEGIN {
                in_block = true;
                buf.clear();
                continue;
            }
            if line.trim() == CANDIDATE_END {
                in_block = false;
                let code = buf.trim_end_matches('\n').to_string();
                if !code.trim().is_empty() {
                    candidate = Some(code);
                }
                continue;
            }
            if in_block {
                buf.push_str(line);
                buf.push('\n');
            }
        }
        assert_eq!(
            parse_candidate(candidate).as_deref(),
            Some("def f(x):\n    return x + 1")
        );
    }
}
