//! `alice-miner doctor` — a preflight + on-stuck self-diagnostic (Theme 2 #7).
//!
//! Runs a fixed battery of checks and prints, per check, a PASS / WARN / FAIL
//! line plus an EXACT fix when something is wrong. It collapses the recurring
//! field bugs (Win/PRL 0-share, V100 spins-to-0, Mac App-Nap stall, headless GPU
//! keyring) into ONE self-serve screen so a non-developer can unstick themselves.
//!
//! Every check REUSES an existing core primitive — the capability matrix
//! ([`alice_miner_core::CapabilityProfile`]), the engine resolver
//! ([`alice_miner_core::binaries`]), the keyring gate
//! ([`alice_miner_core::keyring`]), the endpoint plan
//! ([`alice_miner_core::EndpointPlan`]), and the SS58-300 address validator
//! ([`alice_miner_core::lane::xmr::validate_alice_address`]) — so `doctor` can
//! never drift from what `start` actually does.
//!
//! ── HONESTY / CREDIT-ONLY ───────────────────────────────────────────────────
//! `doctor` prints only diagnostic activity: hardware support, engine presence,
//! reachability, address shape. It NEVER prints a secret, a reward amount, a
//! `$`/`paid`/`earned`/`payout` figure, or the collection address / upstream pool
//! / core IP (it only ever names the PUBLIC relay endpoint). A unit test scans the
//! rendered report for forbidden tokens.

use std::io::Write as _;
use std::net::ToSocketAddrs;
use std::time::Duration;

use alice_miner_core::binaries::{self, MinerKind};
use alice_miner_core::tr;
use alice_miner_core::{CapabilityProfile, EndpointPlan, Lane};

/// The outcome of one diagnostic check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// All good.
    Pass,
    /// Not fatal, but worth knowing / acting on.
    Warn,
    /// This will block mining on the relevant lane until fixed.
    Fail,
    /// Not applicable on this platform / for this lane (shown dim, never a fix).
    Skip,
}

impl Status {
    /// The fixed-width status word for the human report.
    fn word(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
            Status::Skip => "SKIP",
        }
    }

    /// The machine token for `--json`.
    fn json_token(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Warn => "warn",
            Status::Fail => "fail",
            Status::Skip => "skip",
        }
    }
}

/// What `doctor --fix` may safely DO for a failing check, if anything. The SAFE
/// variants are applied non-interactively; `PromptService` asks first on a TTY (and is
/// skipped in a non-interactive run); everything not covered here has NO auto-fix
/// (the identity / keyring / wallet class is INTENTIONALLY absent — a fix that could
/// create or overwrite an identity is only ever PRINTED, never applied). See
/// [`apply_fixes`] for the safe/prompt/never matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixAction {
    /// Re-download (SHA-verify per miners.json) this lane's missing/corrupt engine.
    /// Fully safe + idempotent — reuses the same pinned fetch `start` uses.
    RedownloadEngine(MinerKind),
    /// Recreate a malformed settings/config file (backing the old one up first). Safe:
    /// it never touches identity/keystore/wallet, only the non-secret settings file.
    RecreateConfig,
    /// (Re)install / repair the background service — a bigger action, so PROMPT on a
    /// TTY before doing it, and SKIP entirely in a non-interactive `--fix` run.
    PromptService,
}

/// One diagnostic line: a short `name`, the `status`, a one-line `detail`, an EXACT
/// `fix` string (a command or step) when the status is not Pass/Skip, and an OPTIONAL
/// machine-applicable [`FixAction`] that `doctor --fix` can carry out.
#[derive(Debug, Clone)]
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
    /// The exact fix to apply (empty for Pass/Skip).
    pub fix: String,
    /// A safe/prompt fix `doctor --fix` can apply, if any (`None` = print-only).
    pub fix_action: Option<FixAction>,
}

impl Check {
    fn pass(name: &'static str, detail: impl Into<String>) -> Self {
        Check {
            name,
            status: Status::Pass,
            detail: detail.into(),
            fix: String::new(),
            fix_action: None,
        }
    }
    fn warn(name: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Check {
            name,
            status: Status::Warn,
            detail: detail.into(),
            fix: fix.into(),
            fix_action: None,
        }
    }
    fn fail(name: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Check {
            name,
            status: Status::Fail,
            detail: detail.into(),
            fix: fix.into(),
            fix_action: None,
        }
    }
    fn skip(name: &'static str, detail: impl Into<String>) -> Self {
        Check {
            name,
            status: Status::Skip,
            detail: detail.into(),
            fix: String::new(),
            fix_action: None,
        }
    }

    /// Attach a machine-applicable [`FixAction`] to a check (builder style).
    fn with_action(mut self, action: FixAction) -> Self {
        self.fix_action = Some(action);
        self
    }
}

/// Map a lane to the engine kind whose binary it runs (for the engine-presence
/// check). RVN runs kawpowminer; XMR runs xmrig; the pearlhash lanes run
/// SRBMiner / alpha-miner.
fn kind_for_lane(lane: Lane) -> MinerKind {
    match lane {
        Lane::Xmr => MinerKind::CpuXmr,
        Lane::GpuPrl => MinerKind::GpuPrl,
        Lane::GpuAlpha => MinerKind::GpuAlpha,
        Lane::GpuRvn => MinerKind::GpuRvn,
    }
}

/// Run the full battery for `lane` against the detected `cap`. Pure over its
/// inputs except for the engine-resolve + reachability probes (which touch disk /
/// network). Returns the checks in display order.
pub fn run_checks(lane: Lane, cap: &CapabilityProfile) -> Vec<Check> {
    let mut checks = vec![
        check_identity(),
        check_config(),
        check_lane_support(lane, cap),
        check_gpu_compute_capability(lane, cap),
        check_engine(lane),
        check_keyring(lane),
        check_relay(lane),
    ];
    checks.extend(platform_guardrails());
    checks
}

/// Config file integrity: the non-secret `settings.json` (language / lane prefs) must
/// parse. A malformed file is a WARN (the app falls back to defaults, so it's not
/// blocking) that `doctor --fix` can safely recreate — it backs the old file up first
/// and NEVER touches identity / keystore / wallet (those live in separate files).
fn check_config() -> Check {
    const NAME: &str = "config";
    let path = alice_miner_core::settings::settings_path();
    match std::fs::read_to_string(&path) {
        // Absent → nothing wrong (defaults apply); PASS.
        Err(_) => Check::pass(
            NAME,
            tr!(
                "no settings file yet (defaults apply)",
                "尚无设置文件(使用默认值)"
            ),
        ),
        Ok(s) => {
            if serde_json::from_str::<serde_json::Value>(&s).is_ok() {
                Check::pass(
                    NAME,
                    tr!("settings file is valid JSON", "设置文件是有效的 JSON"),
                )
            } else {
                Check::warn(
                    NAME,
                    tr!(
                        "the settings file is malformed (not valid JSON)",
                        "设置文件已损坏(不是有效的 JSON)"
                    ),
                    tr!(
                        "run `alice-miner doctor --fix` to recreate it (the old file is backed up first); or delete it — the app falls back to defaults",
                        "运行 `alice-miner doctor --fix` 重建它(会先备份旧文件);或删除它 — 应用会回退到默认值"
                    ),
                )
                .with_action(FixAction::RecreateConfig)
            }
        }
    }
}

/// Identity / address validity: a valid SS58-300 Alice reward address must exist
/// (else mining has nowhere to send credit).
fn check_identity() -> Check {
    const NAME: &str = "identity";
    match alice_miner_core::identity::load_pointer() {
        Some(p) => {
            if alice_miner_core::lane::xmr::validate_alice_address(&p.address).is_some() {
                let watch = if p.keystore_path.is_none() {
                    tr!(" (watch-only)", " (仅观察)")
                } else {
                    ""
                };
                Check::pass(
                    NAME,
                    format!(
                        "{}{watch}",
                        tr!(
                            "reward address is a valid Alice SS58-300 address",
                            "奖励地址是有效的 Alice SS58-300 地址"
                        )
                    ),
                )
            } else {
                Check::fail(
                    NAME,
                    tr!(
                        "the stored reward address is not a valid Alice SS58-300 address",
                        "存储的奖励地址不是有效的 Alice SS58-300 地址"
                    ),
                    tr!(
                        "re-create or re-paste your identity: `alice-miner identity --create` (or `--paste <address>`)",
                        "重新创建或重新粘贴身份: `alice-miner identity --create` (或 `--paste <地址>`)"
                    ),
                )
            }
        }
        None => Check::fail(
            NAME,
            tr!("no reward identity yet", "尚无奖励身份"),
            tr!(
                "create one: `alice-miner identity --create` (or `--paste <address>` for watch-only)",
                "请创建一个: `alice-miner identity --create` (或 `--paste <地址>` 用于仅观察)"
            ),
        ),
    }
}

/// Lane viability: the selected lane must be runnable on this device per the
/// capability matrix (the honest gate the engine uses before spawn).
fn check_lane_support(lane: Lane, cap: &CapabilityProfile) -> Check {
    const NAME: &str = "lane support";
    if cap.support(lane).is_runnable() {
        Check::pass(
            NAME,
            format!(
                "{} {}",
                lane.label(),
                tr!("is runnable on this device", "可在此设备上运行")
            ),
        )
    } else {
        let reason = cap
            .viability
            .reason(lane)
            .unwrap_or(tr!("not viable on this device", "在此设备上不可用"));
        Check::fail(
            NAME,
            format!(
                "{} {} {} ({reason})",
                lane.label(),
                tr!("is", "为"),
                cap.support(lane).label()
            ),
            format!(
                "{}: `alice-miner start --lane {}`",
                tr!("use the recommended lane instead", "改用推荐的通道"),
                cap.recommended_lane().id()
            ),
        )
    }
}

/// GPU compute-capability floor for the SRBMiner PRL lane (CC ≥ 7.5 / Turing+).
/// Honest about a Volta/V100 card: it CANNOT run SRBMiner pearlhash and must use
/// the Alpha lane instead — never a false promise that spins to 0. Only meaningful
/// for the GpuPrl lane; Skip otherwise.
fn check_gpu_compute_capability(lane: Lane, cap: &CapabilityProfile) -> Check {
    const NAME: &str = "gpu compute capability";
    if lane != Lane::GpuPrl {
        return Check::skip(
            NAME,
            tr!(
                "only applies to the GPU-PRL (SRBMiner) lane",
                "仅适用于 GPU-PRL (SRBMiner) 通道"
            ),
        );
    }
    match cap.profile.gpu.max_compute_cap_x10 {
        Some(cc) if cc >= 75 => Check::pass(
            NAME,
            format!(
                "CC {}.{} {}",
                cc / 10,
                cc % 10,
                tr!("≥ 7.5 — SRBMiner pearlhash is supported", "≥ 7.5 — 支持 SRBMiner pearlhash")
            ),
        ),
        Some(cc) => Check::fail(
            NAME,
            format!(
                "CC {}.{} {}",
                cc / 10,
                cc % 10,
                tr!(
                    "is below 7.5 — SRBMiner pearlhash is unsupported on this card",
                    "低于 7.5 — 此显卡不支持 SRBMiner pearlhash"
                )
            ),
            tr!(
                "use the Alpha lane (AlphaMiner covers Volta/V100): `alice-miner start --lane alpha`",
                "改用 Alpha 通道(AlphaMiner 覆盖 Volta/V100): `alice-miner start --lane alpha`"
            ),
        ),
        None => Check::warn(
            NAME,
            tr!(
                "no NVIDIA compute capability reported (non-NVIDIA card or nvidia-smi missing)",
                "未报告 NVIDIA 计算能力(非 NVIDIA 显卡或缺少 nvidia-smi)"
            ),
            tr!(
                "if this is an NVIDIA card, install the NVIDIA driver so `nvidia-smi` reports its compute capability; SRBMiner pearlhash needs CC 7.5+",
                "如果这是 NVIDIA 显卡,请安装 NVIDIA 驱动以便 `nvidia-smi` 报告其计算能力;SRBMiner pearlhash 需要 CC 7.5+"
            ),
        ),
    }
}

/// Engine present or downloadable: the lane's miner binary must resolve (a bundled
/// sibling, a cached download, or a fetchable pinned release). Reuses the SAME
/// resolver `start` uses, so a PASS here means `start` will find the engine.
fn check_engine(lane: Lane) -> Check {
    const NAME: &str = "engine";
    let kind = kind_for_lane(lane);
    // The resolver does the real work (override → sibling → dev → auto-download),
    // verifying the SHA pin throughout. A no-network fetchable lane still PASSES
    // (the download will run at start); a present binary PASSES immediately.
    match binaries::resolve_miner_binary(kind) {
        Ok(path) => Check::pass(
            NAME,
            format!(
                "{} {} {}",
                kind.binary_name(),
                tr!("resolved at", "已解析于"),
                path.display()
            ),
        ),
        Err(e) => {
            if binaries::is_fetchable(kind) {
                // A real pin + URL exist, but the resolve failed (e.g. offline). The
                // download will run at start; surface the transient reason as a WARN.
                // `doctor --fix` can fetch it now (SHA-verified) — a fully-safe action.
                Check::warn(
                    NAME,
                    format!("{} {}: {e}", kind.binary_name(), tr!("not yet cached", "尚未缓存")),
                    tr!(
                        "it will auto-download (sha-pinned) on the next `alice-miner start` when the network is reachable, or run `alice-miner doctor --fix` to fetch it now",
                        "网络可达时,下次 `alice-miner start` 会自动下载(sha 校验);或运行 `alice-miner doctor --fix` 立即获取"
                    ),
                )
                .with_action(FixAction::RedownloadEngine(kind))
            } else {
                Check::fail(
                    NAME,
                    format!("{} {}: {e}", kind.binary_name(), tr!("is not available", "不可用")),
                    format!(
                        "{}: {}",
                        tr!(
                            "install a packaged release that bundles the engine",
                            "请安装内置引擎的打包版"
                        ),
                        binaries::RELEASES_URL
                    ),
                )
            }
        }
    }
}

/// Keyring availability — only matters for BACKGROUNDING a GPU pearlhash lane (its
/// wallet unlock must live in the OS keyring). For XMR / RVN it is irrelevant
/// (Skip). A pearlhash lane on a box with no keyring can still mine in the
/// foreground, so a missing keyring is a WARN (background-only), not a FAIL.
fn check_keyring(lane: Lane) -> Check {
    const NAME: &str = "keyring (background GPU)";
    if !lane.is_prl_lane() {
        return Check::skip(
            NAME,
            tr!(
                "only needed to BACKGROUND a GPU pearlhash lane",
                "仅在后台运行 GPU pearlhash 通道时需要"
            ),
        );
    }
    if alice_miner_core::keyring::is_available() {
        Check::pass(
            NAME,
            tr!(
                "an OS keyring is available to hold the background wallet unlock",
                "系统密钥环可用,可保存后台钱包解锁凭据"
            ),
        )
    } else {
        Check::warn(
            NAME,
            tr!(
                "no OS keyring on this box (e.g. a headless Linux rig)",
                "此机器没有系统密钥环(例如无头 Linux 矿机)"
            ),
            tr!(
                "foreground mining works without it; for BACKGROUND GPU mining, run on a box with a keyring (macOS Keychain / Windows Credential Manager / Linux Secret Service) or background the CPU-XMR lane instead",
                "前台挖矿无需它;若要后台 GPU 挖矿,请在有密钥环的机器上运行(macOS 钥匙串 / Windows 凭据管理器 / Linux Secret Service),或改为后台运行 CPU-XMR 通道"
            ),
        )
    }
}

/// Relay reachability: a TCP connect (3 s timeout) to the lane's default PUBLIC
/// relay endpoint. Only ever names the public relay (never the upstream pool / core
/// IP). A failure is the classic "never reached Running" cause.
fn check_relay(lane: Lane) -> Check {
    const NAME: &str = "relay reachability";
    let plan = EndpointPlan::default_for_lane(lane);
    let ep = plan.current();
    let host_port = ep.host_port();
    match tcp_reachable(&ep.host, ep.port, Duration::from_secs(3)) {
        Ok(()) => Check::pass(
            NAME,
            format!("{} {host_port}", tr!("connected to the relay", "已连接到中继")),
        ),
        Err(e) => Check::fail(
            NAME,
            format!("{} {host_port}: {e}", tr!("cannot reach the relay", "无法连接到中继")),
            tr!(
                "check your network / firewall (the stratum port must be reachable outbound); a VPN or captive portal can block it",
                "请检查网络 / 防火墙(stratum 端口必须可出站访问);VPN 或强制门户网络可能会拦截它"
            ),
        ),
    }
}

/// TCP-connect reachability to `host:port` with a timeout. Resolves DNS first
/// (a DNS failure is itself a reachability failure). Never panics.
fn tcp_reachable(host: &str, port: u16, timeout: Duration) -> Result<(), String> {
    let mut addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed: {e}"))?;
    let addr = addrs.next().ok_or_else(|| "no address resolved".to_string())?;
    std::net::TcpStream::connect_timeout(&addr, timeout)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Platform guardrails — the known per-OS root causes of the field bugs. Each is a
/// WARN (informational, with the exact fix) because they are environment hygiene,
/// not hard blockers detectable here.
fn platform_guardrails() -> Vec<Check> {
    let mut out = Vec::new();
    let cache = binaries::engine_cache_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<engine cache dir>".to_string());

    if cfg!(target_os = "windows") {
        out.push(Check::warn(
            "windows defender (PUA)",
            tr!(
                "Windows Defender flags mining engines as a \"potentially unwanted application\" (a known false positive) and may quarantine the engine",
                "Windows Defender 会把挖矿引擎标记为\"潜在有害应用\"(已知误报)并可能隔离它"
            ),
            format!(
                "{} Add-MpPreference -ExclusionPath '{cache}'",
                tr!(
                    "if mining won't start, allow the engine cache in Defender — in an elevated PowerShell run:",
                    "如果挖矿无法启动,请在 Defender 中放行引擎缓存 — 在管理员 PowerShell 中运行:"
                )
            ),
        ));
    }
    if cfg!(target_os = "macos") {
        out.push(Check::warn(
            "macos gatekeeper / app-nap",
            tr!(
                "macOS App Nap can throttle a backgrounded miner to ~0 H/s, and Gatekeeper can block a freshly-downloaded engine",
                "macOS App Nap 会把后台矿工限速到 ~0 H/s,Gatekeeper 可能拦截刚下载的引擎"
            ),
            tr!(
                "the packaged app sets NSAppSleepDisabled + uses caffeinate to defeat App Nap; if you launched a raw binary and hashrate drops to 0 when the window is hidden, run it under `caffeinate -dimsu alice-miner start …` and keep the engine in the packaged app so Gatekeeper trusts it",
                "打包版会设置 NSAppSleepDisabled 并使用 caffeinate 来对抗 App Nap;如果你直接运行裸二进制且窗口隐藏时算力掉到 0,请用 `caffeinate -dimsu alice-miner start …` 运行,并把引擎保留在打包版内以便 Gatekeeper 信任它"
            ),
        ));
    }
    out
}

/// Render the full report to a String (human form). Each non-Pass/Skip line gets
/// its exact fix indented underneath. Credit-only by construction (diagnostics
/// only — a unit test scans for forbidden reward/secret tokens).
pub fn render_report(checks: &[Check], lane: Lane) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "{} {}\n",
        tr!("Alice Miner doctor — lane", "Alice Miner doctor — 通道"),
        lane.cli_lane_arg()
    ));
    s.push_str("─────────────────────────────────────────────\n");
    for c in checks {
        s.push_str(&format!("  [{}] {} — {}\n", c.status.word(), c.name, c.detail));
        if !c.fix.is_empty() {
            s.push_str(&format!("        {}: {}\n", tr!("fix", "修复"), c.fix));
        }
    }
    let fails = checks.iter().filter(|c| c.status == Status::Fail).count();
    let warns = checks.iter().filter(|c| c.status == Status::Warn).count();
    s.push_str("─────────────────────────────────────────────\n");
    if fails == 0 {
        s.push_str(&format!(
            "{}\n",
            tr!("Ready to mine.", "已就绪,可以开始挖矿。")
                .to_string()
                + &format!(" ({warns} {})", tr!("warning(s).", "个警告。"))
        ));
    } else {
        s.push_str(&format!(
            "{fails} {}, {warns} {}\n",
            tr!("blocking issue(s)", "个阻塞问题"),
            tr!(
                "warning(s). Fix the FAIL lines above, then re-run `alice-miner doctor`.",
                "个警告。请修复上面的 FAIL 行,然后重新运行 `alice-miner doctor`。"
            )
        ));
    }
    s
}

/// Render the report as a single JSON object (machine-readable). Credit-only: only
/// the check name / status / detail / fix appear — no reward or secret field.
pub fn render_json(checks: &[Check], lane: Lane) -> String {
    let arr: Vec<serde_json::Value> = checks
        .iter()
        .map(|c| {
            serde_json::json!({
                "name": c.name,
                "status": c.status.json_token(),
                "detail": c.detail,
                "fix": if c.fix.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(c.fix.clone()) },
            })
        })
        .collect();
    let fails = checks.iter().filter(|c| c.status == Status::Fail).count();
    serde_json::json!({
        "lane": lane.cli_lane_arg(),
        "ready": fails == 0,
        "checks": arr,
    })
    .to_string()
}

/// Whether the report has any blocking FAIL (drives the exit code: a clean
/// preflight exits 0; any FAIL exits non-zero so a harness/script can branch).
pub fn has_blocking_failure(checks: &[Check]) -> bool {
    checks.iter().any(|c| c.status == Status::Fail)
}

// ─────────────────────────────────────────────────────────────────────────────
// `doctor --fix` — safe/prompt/never auto-repair
// ─────────────────────────────────────────────────────────────────────────────
//
// The SAFE/PROMPT/NEVER matrix (the brief):
//   * SAFE (auto-applied, even non-interactively):
//       - RedownloadEngine → re-fetch the SHA-pinned engine via binaries::ensure_cached_engine
//       - RecreateConfig    → back up the malformed settings.json, then write a fresh default
//   * PROMPT (TTY only): PromptService → (re)install/repair the background service; SKIPPED
//       (with a note) in a non-interactive `--fix` run.
//   * NEVER: identity / keyring / wallet — a fix that could create/overwrite an identity is
//       ONLY printed as a manual step, never applied. (Those checks carry no FixAction.)

/// The result of attempting one check's fix. Presentation-only wording is localized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixOutcome {
    /// A safe fix was applied successfully; the string is a short what-was-done note.
    Applied(String),
    /// A prompt-required fix was SKIPPED (non-interactive run, or the user declined).
    Skipped(String),
    /// The fix failed; the string is the reason (never a secret).
    Failed(String),
}

/// Apply the safe (and, when `interactive`, prompt-gated) fixes for `checks`, returning
/// a human report of what was done. `prompt` is asked before a [`FixAction::PromptService`]
/// (only when `interactive`); in a non-interactive run those are SKIPPED with a note.
/// Never touches identity/keystore/wallet (those checks carry no [`FixAction`]).
///
/// The actual side-effecting fix appliers are the small pure-ish functions below; this
/// only orchestrates + formats, so it stays testable via [`apply_one_fix`].
pub fn apply_fixes(
    checks: &[Check],
    interactive: bool,
    prompt: &mut dyn FnMut(&str) -> bool,
) -> String {
    let mut out = String::new();
    out.push_str(tr!("Applying safe fixes…\n", "正在应用安全修复…\n"));
    out.push_str("─────────────────────────────────────────────\n");
    let mut any = false;
    for c in checks {
        let Some(action) = c.fix_action else { continue };
        // The service fix PROMPTS on a TTY and is SKIPPED non-interactively.
        if action == FixAction::PromptService {
            if !interactive {
                any = true;
                out.push_str(&format!(
                    "  [{}] {} — {}\n",
                    tr!("SKIP", "跳过"),
                    c.name,
                    tr!(
                        "needs a prompt; re-run `doctor --fix` in a terminal to (re)install the service",
                        "需要确认;请在终端中重新运行 `doctor --fix` 以(重新)安装服务"
                    ),
                ));
                continue;
            }
            let q = tr!(
                "(Re)install/repair the background service now? [y/N]: ",
                "现在(重新)安装/修复后台服务吗? [y/N]: "
            );
            if !prompt(q) {
                any = true;
                out.push_str(&format!(
                    "  [{}] {} — {}\n",
                    tr!("SKIP", "跳过"),
                    c.name,
                    tr!("declined", "已跳过")
                ));
                continue;
            }
        }
        any = true;
        let outcome = apply_one_fix(action);
        let (tag, msg) = match outcome {
            FixOutcome::Applied(m) => (tr!("FIXED", "已修复"), m),
            FixOutcome::Skipped(m) => (tr!("SKIP", "跳过"), m),
            FixOutcome::Failed(m) => (tr!("FAILED", "失败"), m),
        };
        out.push_str(&format!("  [{tag}] {} — {msg}\n", c.name));
    }
    // Print the manual-only steps for any non-Pass check WITHOUT a fix action (the
    // identity/keyring/wallet "never auto-touch" class) so the user still sees them.
    let manual: Vec<&Check> = checks
        .iter()
        .filter(|c| {
            c.fix_action.is_none()
                && matches!(c.status, Status::Fail | Status::Warn)
                && !c.fix.is_empty()
        })
        .collect();
    let had_manual = !manual.is_empty();
    if had_manual {
        out.push_str(&format!(
            "\n{}\n",
            tr!(
                "Manual steps (not auto-applied — identity/keyring/wallet are never auto-touched):",
                "手动步骤(不会自动应用 — 身份/密钥环/钱包绝不自动修改):"
            )
        ));
        for c in manual {
            out.push_str(&format!("  • {} — {}\n", c.name, c.fix));
        }
    }
    if !any && !had_manual {
        out.push_str(tr!("Nothing to fix.\n", "无需修复。\n"));
    }
    out
}

/// Apply ONE [`FixAction`] (the safe/prompt appliers). Pure w.r.t. its input action;
/// touches disk/network only for the specific safe repair. Never handles identity.
pub fn apply_one_fix(action: FixAction) -> FixOutcome {
    match action {
        FixAction::RedownloadEngine(kind) => fix_redownload_engine(kind),
        FixAction::RecreateConfig => fix_recreate_config(),
        // Reaching here means the caller already prompted (interactive). The concrete
        // service install/repair lives in the service module; we surface a clear
        // "not yet wired" rather than silently claiming success. (Kept explicit so the
        // matrix is complete even before the service repair path lands.)
        FixAction::PromptService => FixOutcome::Skipped(
            tr!(
                "service (re)install is not available from doctor yet — use `alice-miner service …`",
                "doctor 暂不支持(重新)安装服务 — 请使用 `alice-miner service …`"
            )
            .to_string(),
        ),
    }
}

/// SAFE fix: re-fetch the SHA-pinned engine for `kind` (reuses the same verified fetch
/// `start` uses). Idempotent — a fetch of an already-cached, verified engine is a no-op
/// resolve. Fail-soft: a network/verify error is reported, never a panic.
fn fix_redownload_engine(kind: MinerKind) -> FixOutcome {
    if !binaries::is_fetchable(kind) {
        return FixOutcome::Failed(
            tr!(
                "no verifiable download source for this engine on this platform (install a packaged release)",
                "此平台没有此引擎的可验证下载源(请安装打包版)"
            )
            .to_string(),
        );
    }
    match binaries::ensure_cached_engine(kind) {
        Ok(path) => FixOutcome::Applied(format!(
            "{} {} → {}",
            tr!("re-downloaded (sha-verified)", "已重新下载(校验通过)"),
            kind.binary_name(),
            path.display()
        )),
        Err(e) => FixOutcome::Failed(format!(
            "{}: {e}",
            tr!("engine re-download failed", "引擎重新下载失败")
        )),
    }
}

/// SAFE fix: recreate a malformed settings/config file. Backs up the old file to
/// `settings.json.bak` FIRST (best-effort), then writes a fresh default via the core
/// settings writer. Never touches identity/keystore/wallet (separate files). Fail-soft.
fn fix_recreate_config() -> FixOutcome {
    let path = alice_miner_core::settings::settings_path();
    // Only act if the file exists AND is malformed (defensive re-check so `--fix` never
    // clobbers a VALID config, even if the check list is stale).
    match std::fs::read_to_string(&path) {
        Ok(s) if serde_json::from_str::<serde_json::Value>(&s).is_ok() => {
            return FixOutcome::Skipped(
                tr!("config is already valid — nothing to do", "配置已有效 — 无需操作").to_string(),
            );
        }
        Err(_) => {
            // Absent: writing a default is harmless but not a "repair" — treat as nothing.
            return FixOutcome::Skipped(
                tr!("no config file to repair", "没有需要修复的配置文件").to_string(),
            );
        }
        Ok(_) => { /* malformed → proceed to back up + recreate */ }
    }
    // Back up the malformed file BEFORE overwriting it. If the backup can't be written
    // (read-only dir, ENOSPC, …), abort rather than destroy the original with no copy —
    // the user may want to recover a hand-edit. Never proceed unbacked-up.
    let backup = path.with_extension("json.bak");
    if let Err(e) = std::fs::copy(&path, &backup) {
        return FixOutcome::Failed(format!(
            "{} {}: {e}",
            tr!(
                "could not back up the malformed config before recreating it; left it untouched —",
                "重建前无法备份损坏的配置文件,已保持原样未改动 —"
            ),
            backup.display()
        ));
    }
    match alice_miner_core::settings::save(&alice_miner_core::settings::Settings::default()) {
        Ok(_) => {
            let note = format!(
                " ({} {})",
                tr!("old file backed up to", "旧文件已备份至"),
                backup.display()
            );
            FixOutcome::Applied(format!(
                "{}{note}",
                tr!("recreated a fresh default settings file", "已重建一份全新的默认设置文件")
            ))
        }
        Err(e) => FixOutcome::Failed(format!(
            "{}: {e}",
            tr!("could not write a fresh settings file", "无法写入新的设置文件")
        )),
    }
}

/// Print a one-line summary to stderr that a `start` pre-flight can show (a light
/// version of doctor inside `start` — the spec's "run a light version inside
/// start"). Best-effort; never blocks mining.
pub fn print_preflight_summary(lane: Lane, cap: &CapabilityProfile) {
    let checks = run_checks(lane, cap);
    if let Some(first_fail) = checks.iter().find(|c| c.status == Status::Fail) {
        let mut err = std::io::stderr();
        let _ = writeln!(
            err,
            "{}: {} — {}\n  {}: {}\n  {}",
            tr!("preflight", "预检"),
            first_fail.name,
            first_fail.detail,
            tr!("fix", "修复"),
            first_fail.fix,
            tr!(
                "(run `alice-miner doctor` for the full report)",
                "(运行 `alice-miner doctor` 查看完整报告)"
            )
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ai (shard-stage inference worker) doctor section
// ─────────────────────────────────────────────────────────────────────────────

/// The inputs the ai doctor battery probes (a subset of the resolved `ai`
/// settings). All optional so `doctor --ai` can run before the user has supplied
/// everything and still report exactly what is missing.
#[derive(Debug, Clone, Default)]
pub struct AiDoctorInput {
    pub center_url: Option<String>,
    pub endpoint: Option<String>,
    pub engine_dir: Option<std::path::PathBuf>,
    pub python: String,
    pub allow_cpu: bool,
}

/// Run the ai-role diagnostic battery: identity, python3, engine dir + pipeline.py,
/// torch importable, NVIDIA (or --allow-cpu), endpoint port bindable, center URL
/// reachable. Reuses the same [`Check`] primitives + honest FAIL/WARN/OK style as
/// the mining doctor. Network/subprocess probes are bounded; never panics.
pub fn run_ai_checks(input: &AiDoctorInput) -> Vec<Check> {
    vec![
        check_identity(),
        check_ai_python(&input.python),
        check_ai_engine_dir(input.engine_dir.as_deref()),
        check_ai_torch(&input.python),
        check_ai_nvidia(input.allow_cpu),
        check_ai_endpoint(input.endpoint.as_deref()),
        check_ai_center(input.center_url.as_deref()),
    ]
}

/// python3 present + its version (the interpreter that runs the engine).
fn check_ai_python(python: &str) -> Check {
    const NAME: &str = "python3";
    let mut cmd = std::process::Command::new(python);
    cmd.arg("--version");
    match run_with_timeout(&mut cmd, PROBE_TIMEOUT) {
        Ok(Some(out)) if out.status.success() => {
            let v = String::from_utf8_lossy(&out.stdout);
            let v = if v.trim().is_empty() {
                String::from_utf8_lossy(&out.stderr).trim().to_string()
            } else {
                v.trim().to_string()
            };
            Check::pass(NAME, format!("{python} {} ({v})", tr!("present", "已安装")))
        }
        _ => Check::fail(
            NAME,
            format!("{} {python:?}", tr!("python3 not found / not runnable at", "在此处找不到 / 无法运行 python3:")),
            tr!(
                "install Python 3 (the shard engine runs on it) or pass --python <path-to-python3>",
                "请安装 Python 3(分片引擎在其上运行),或传入 --python <python3 路径>"
            ),
        ),
    }
}

/// The engine checkout exists and contains phase0/pipeline.py.
fn check_ai_engine_dir(engine_dir: Option<&std::path::Path>) -> Check {
    const NAME: &str = "shard engine";
    match engine_dir {
        None => Check::fail(
            NAME,
            tr!("no engine dir set", "未设置引擎目录"),
            tr!(
                "pass --engine-dir <alice-shard-engine checkout> (or set ALICE_SHARD_ENGINE_PATH); it must contain phase0/pipeline.py",
                "请传入 --engine-dir <alice-shard-engine 检出目录>(或设置 ALICE_SHARD_ENGINE_PATH);它必须包含 phase0/pipeline.py"
            ),
        ),
        Some(dir) if dir.join("phase0/pipeline.py").is_file() => Check::pass(
            NAME,
            format!("{} {}", tr!("phase0/pipeline.py found under", "在此处找到 phase0/pipeline.py:"), dir.display()),
        ),
        Some(dir) => Check::fail(
            NAME,
            format!("{} {}", tr!("phase0/pipeline.py is missing under", "此处缺少 phase0/pipeline.py:"), dir.display()),
            tr!(
                "point --engine-dir at your alice-shard-engine checkout (the dir that has phase0/)",
                "请把 --engine-dir 指向你的 alice-shard-engine 检出目录(含 phase0/ 的目录)"
            ),
        ),
    }
}

/// torch importable in the engine's python (a hard prerequisite for loading model
/// layers). Bounded by a timeout so a wedged import can't hang the doctor.
fn check_ai_torch(python: &str) -> Check {
    const NAME: &str = "torch";
    match run_with_timeout(
        std::process::Command::new(python)
            .args(["-c", "import torch; print(torch.__version__)"]),
        Duration::from_secs(30),
    ) {
        Ok(Some(out)) if out.status.success() => Check::pass(
            NAME,
            format!("torch {} {}", String::from_utf8_lossy(&out.stdout).trim(), tr!("importable", "可导入")),
        ),
        Ok(Some(_)) => Check::fail(
            NAME,
            tr!("python3 could not import torch", "python3 无法导入 torch"),
            tr!(
                "install the engine's deps into this python: `pip install torch` (and the rest of phase0/requirements*.txt) — the stage cannot load model layers without torch",
                "请把引擎依赖安装到此 python: `pip install torch`(以及 phase0/requirements*.txt 的其余部分)— 没有 torch 该阶段无法加载模型层"
            ),
        ),
        Ok(None) => Check::warn(
            NAME,
            tr!(
                "torch import check timed out (a slow first import / large environment)",
                "torch 导入检查超时(首次导入较慢 / 环境较大)"
            ),
            tr!(
                "run `python3 -c \"import torch\"` by hand to confirm it imports before starting",
                "启动前请手动运行 `python3 -c \"import torch\"` 确认可导入"
            ),
        ),
        Err(e) => Check::fail(
            NAME,
            format!("{}: {e}", tr!("could not run the torch import check", "无法运行 torch 导入检查")),
            tr!("confirm --python points at a working python3", "请确认 --python 指向一个可用的 python3"),
        ),
    }
}

/// NVIDIA present (nvidia-smi), else a WARN unless --allow-cpu (then Skip-like OK).
fn check_ai_nvidia(allow_cpu: bool) -> Check {
    const NAME: &str = "nvidia gpu";
    let mut cmd = std::process::Command::new("nvidia-smi");
    cmd.arg("-L");
    let smi_ok = matches!(run_with_timeout(&mut cmd, PROBE_TIMEOUT), Ok(Some(o)) if o.status.success());
    if smi_ok {
        Check::pass(
            NAME,
            tr!("nvidia-smi reports at least one NVIDIA GPU", "nvidia-smi 报告至少一块 NVIDIA GPU"),
        )
    } else if allow_cpu {
        Check::warn(
            NAME,
            tr!(
                "no NVIDIA GPU detected, but --allow-cpu was given (testing only)",
                "未检测到 NVIDIA GPU,但已指定 --allow-cpu(仅供测试)"
            ),
            tr!(
                "a real inference stage needs a GPU; --allow-cpu only lets a no-NVIDIA box register",
                "真正的推理阶段需要 GPU;--allow-cpu 只是让无 NVIDIA 的机器能注册"
            ),
        )
    } else {
        Check::fail(
            NAME,
            tr!(
                "no NVIDIA GPU detected (nvidia-smi missing or reported none)",
                "未检测到 NVIDIA GPU(缺少 nvidia-smi 或其未报告任何 GPU)"
            ),
            tr!(
                "install the NVIDIA driver so nvidia-smi works, or pass --allow-cpu to run without a GPU for testing (a real stage needs a GPU)",
                "请安装 NVIDIA 驱动使 nvidia-smi 可用,或传入 --allow-cpu 以在无 GPU 情况下测试运行(真正的阶段需要 GPU)"
            ),
        )
    }
}

/// The listen port parses and is bindable locally (nothing else already holds it).
fn check_ai_endpoint(endpoint: Option<&str>) -> Check {
    const NAME: &str = "endpoint port";
    let Some(ep) = endpoint else {
        return Check::fail(
            NAME,
            tr!("no endpoint set", "未设置端点"),
            tr!(
                "pass --endpoint <public host:port> (the address the swarm dials this stage)",
                "请传入 --endpoint <公网 host:port>(集群拨号到此阶段的地址)"
            ),
        );
    };
    let port = match ep.trim().rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()) {
        Some(p) if p > 0 => p,
        _ => {
            return Check::fail(
                NAME,
                format!(
                    "{} {ep:?}",
                    tr!(
                        "not host:port with a valid 1..=65535 port:",
                        "不是带有效 1..=65535 端口的 host:port:"
                    )
                ),
                tr!("use host:port, e.g. --endpoint 203.0.113.7:29501", "请使用 host:port,例如 --endpoint 203.0.113.7:29501"),
            )
        }
    };
    // Try to bind loopback:port — if it binds, nothing else holds it (the engine
    // will listen there). We immediately drop the listener.
    match std::net::TcpListener::bind(("127.0.0.1", port)) {
        Ok(_l) => Check::pass(
            NAME,
            format!("{} {port} {}", tr!("port", "端口"), tr!("is free to bind locally", "可在本地绑定")),
        ),
        Err(e) => Check::warn(
            NAME,
            format!("{} {port} {}: {e}", tr!("port", "端口"), tr!("is not bindable locally right now", "当前无法在本地绑定")),
            tr!(
                "another process may hold it (a previous stage?); free it, or advertise a different port. NOTE: the PUBLIC reachability of the endpoint still depends on your NAT / port-forwarding — doctor only checks the LOCAL bind",
                "可能有其他进程占用它(上一个阶段?);请释放它,或改用其他端口。注意:端点的公网可达性仍取决于你的 NAT / 端口转发 — doctor 只检查本地绑定"
            ),
        ),
    }
}

/// Center URL reachable: a GET /health probe (the acp gateway serves it). https-only.
/// Delegates to the core's `shard::probe_center_health` (which owns the ureq client).
fn check_ai_center(center_url: Option<&str>) -> Check {
    const NAME: &str = "center reachability";
    let url = center_url.unwrap_or("https://api.aliceprotocol.org");
    if !url.starts_with("https://") {
        return Check::fail(
            NAME,
            format!("{}: {url}", tr!("center url is not https://", "center url 不是 https://")),
            tr!(
                "use an https:// --center-url (a PoP signature must never cross the wire in the clear)",
                "请使用 https:// 的 --center-url(PoP 签名绝不能明文传输)"
            ),
        );
    }
    match alice_miner_core::shard::probe_center_health(url) {
        Ok(desc) => Check::pass(NAME, desc),
        Err(e) => Check::fail(
            NAME,
            e,
            tr!(
                "check the --center-url and your network / firewall (outbound https must be reachable)",
                "请检查 --center-url 和你的网络 / 防火墙(出站 https 必须可达)"
            ),
        ),
    }
}

/// Wall-clock cap on the quick version/GPU probes (`python3 --version`, `nvidia-smi`).
/// A wedged driver can hang `nvidia-smi` indefinitely; past this the child is killed so
/// `doctor` can never stall. Ample for a healthy binary.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Run a command with a wall-clock timeout. Returns `Ok(Some(output))` on
/// completion, `Ok(None)` on timeout (child killed), `Err` on spawn failure. Used
/// for the torch import probe (which can be slow on a fresh env).
fn run_with_timeout(
    cmd: &mut std::process::Command,
    timeout: Duration,
) -> Result<Option<std::process::Output>, String> {
    use std::process::Stdio;
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let start = std::time::Instant::now();
    loop {
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(_status) => {
                return child.wait_with_output().map(Some).map_err(|e| e.to_string());
            }
            None => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Ok(None);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// Render the ai doctor report (human form) — same layout as [`render_report`] but
/// headed for the ai role.
pub fn render_ai_report(checks: &[Check]) -> String {
    let mut s = String::new();
    s.push_str(tr!(
        "Alice Miner doctor — ai (shard-stage inference)\n",
        "Alice Miner doctor — ai (分片推理)\n"
    ));
    s.push_str("─────────────────────────────────────────────\n");
    for c in checks {
        s.push_str(&format!("  [{}] {} — {}\n", c.status.word(), c.name, c.detail));
        if !c.fix.is_empty() {
            s.push_str(&format!("        {}: {}\n", tr!("fix", "修复"), c.fix));
        }
    }
    let fails = checks.iter().filter(|c| c.status == Status::Fail).count();
    let warns = checks.iter().filter(|c| c.status == Status::Warn).count();
    s.push_str("─────────────────────────────────────────────\n");
    if fails == 0 {
        s.push_str(&format!(
            "{} ({warns} {})\n",
            tr!("Ready to run the ai role.", "ai 角色已就绪。"),
            tr!("warning(s).", "个警告。")
        ));
    } else {
        s.push_str(&format!(
            "{fails} {}, {warns} {}\n",
            tr!("blocking issue(s)", "个阻塞问题"),
            tr!(
                "warning(s). Fix the FAIL lines above, then re-run `alice-miner doctor --ai`.",
                "个警告。请修复上面的 FAIL 行,然后重新运行 `alice-miner doctor --ai`。"
            )
        ));
    }
    s
}

/// Render the ai doctor report as JSON (machine-readable).
pub fn render_ai_json(checks: &[Check]) -> String {
    let arr: Vec<serde_json::Value> = checks
        .iter()
        .map(|c| {
            serde_json::json!({
                "name": c.name,
                "status": c.status.json_token(),
                "detail": c.detail,
                "fix": if c.fix.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(c.fix.clone()) },
            })
        })
        .collect();
    let fails = checks.iter().filter(|c| c.status == Status::Fail).count();
    serde_json::json!({ "role": "ai", "ready": fails == 0, "checks": arr }).to_string()
}

// ─────────────────────────────────────────────────────────────────────────────
// train (RLVR training worker) doctor section
// ─────────────────────────────────────────────────────────────────────────────

/// The inputs the train doctor battery probes (a subset of the resolved `train`
/// settings). All optional so `doctor --train` can run before the user has supplied
/// everything and still report exactly what is missing.
#[derive(Debug, Clone)]
pub struct TrainDoctorInput {
    pub center_url: Option<String>,
    pub trainer_dir: Option<std::path::PathBuf>,
    pub python: String,
    pub base_model: Option<String>,
    pub device: String,
    pub allow_cpu: bool,
}

impl Default for TrainDoctorInput {
    fn default() -> Self {
        TrainDoctorInput {
            center_url: None,
            trainer_dir: None,
            python: "python3".to_string(),
            base_model: None,
            device: "cuda".to_string(),
            allow_cpu: false,
        }
    }
}

/// Run the train-role diagnostic battery: identity, python3, torch importable, the
/// trainer dir (run_m0.py + code_exec.py), a base model resolvable, NVIDIA (or the
/// cpu/allow-cpu path), and the center URL reachable. Reuses the same [`Check`]
/// primitives + honest FAIL/WARN/OK style as the mining + ai doctors.
pub fn run_train_checks(input: &TrainDoctorInput) -> Vec<Check> {
    vec![
        check_identity(),
        check_ai_python(&input.python),
        check_ai_torch(&input.python),
        check_train_trainer_dir(input.trainer_dir.as_deref()),
        check_train_base_model(input.base_model.as_deref()),
        check_train_device(&input.device, input.allow_cpu),
        check_ai_center(input.center_url.as_deref()),
    ]
}

/// The trainer dir exists and contains run_m0.py + code_exec.py (the candidate
/// generator imports `_load_base`/`_render` from run_m0 and `extract_code` from
/// code_exec).
fn check_train_trainer_dir(trainer_dir: Option<&std::path::Path>) -> Check {
    const NAME: &str = "trainer dir";
    match trainer_dir {
        None => Check::fail(
            NAME,
            tr!("no trainer dir set", "未设置训练器目录"),
            tr!(
                "pass --trainer-dir <training-mint-m0 checkout> (or set ALICE_TRAIN_TRAINER_PATH); it must contain run_m0.py + code_exec.py",
                "请传入 --trainer-dir <training-mint-m0 检出目录>(或设置 ALICE_TRAIN_TRAINER_PATH);它必须包含 run_m0.py + code_exec.py"
            ),
        ),
        Some(dir) => {
            let has_run = dir.join("run_m0.py").is_file();
            let has_exec = dir.join("code_exec.py").is_file();
            if has_run && has_exec {
                Check::pass(
                    NAME,
                    format!(
                        "{} {}",
                        tr!("run_m0.py + code_exec.py found under", "在此处找到 run_m0.py + code_exec.py:"),
                        dir.display()
                    ),
                )
            } else {
                let missing = if !has_run { "run_m0.py" } else { "code_exec.py" };
                Check::fail(
                    NAME,
                    format!("{missing} {} {}", tr!("is missing under", "缺失于"), dir.display()),
                    tr!(
                        "point --trainer-dir at a COMPLETE training-mint-m0 checkout (the dir with both run_m0.py and code_exec.py)",
                        "请把 --trainer-dir 指向一个完整的 training-mint-m0 检出目录(同时包含 run_m0.py 与 code_exec.py)"
                    ),
                )
            }
        }
    }
}

/// The base model id is set (a HF id or a local path). We do NOT download it here (a
/// multi-GB pull is not a doctor action); a local path is checked for existence, an HF
/// id is accepted as-is with a note that the first `train` run downloads it.
fn check_train_base_model(base_model: Option<&str>) -> Check {
    const NAME: &str = "base model";
    let Some(model) = base_model.filter(|m| !m.trim().is_empty()) else {
        // Unset → the train role falls back to its built-in default; a WARN naming that.
        return Check::warn(
            NAME,
            tr!(
                "no base model set (the train role uses its built-in default)",
                "未设置基础模型(train 角色将使用内置默认模型)"
            ),
            tr!(
                "pass --base-model <hf-id-or-path> to match the coordinator's corpus; the default is the 30B-A3B MoE (Qwen3-30B-A3B-Instruct-2507), which needs --four-bit on a 24GB GPU or --multi-gpu shard across cards",
                "请传入 --base-model <hf-id-或路径> 以匹配调度中心的语料;默认是 30B-A3B MoE(Qwen3-30B-A3B-Instruct-2507),在 24GB 显卡上需配 --four-bit,或用 --multi-gpu shard 跨卡"
            ),
        );
    };
    // A path-like value that exists locally → PASS (a local checkout). Otherwise treat
    // it as an HF id (resolvable at run time; the first run downloads it).
    let looks_local = model.contains('/') && std::path::Path::new(model).exists();
    if looks_local {
        Check::pass(
            NAME,
            format!("{} {model}", tr!("local base model path exists:", "本地基础模型路径存在:")),
        )
    } else {
        Check::pass(
            NAME,
            format!(
                "{model} — {}",
                tr!(
                    "treated as a Hugging Face id (downloaded on the first train run)",
                    "视为 Hugging Face id(首次 train 运行时下载)"
                )
            ),
        )
    }
}

/// The device is one of cuda/cpu/mps, and if cuda, an NVIDIA GPU is present (else FAIL
/// unless --allow-cpu, then WARN). A cpu/mps device is accepted with a testing note.
fn check_train_device(device: &str, allow_cpu: bool) -> Check {
    const NAME: &str = "device";
    match device {
        "cpu" => Check::warn(
            NAME,
            tr!("device is cpu (testing only — slow)", "设备为 cpu(仅供测试 — 很慢)"),
            tr!(
                "a real training worker needs a GPU; use --device cuda on an NVIDIA box for real throughput",
                "真正的训练工作节点需要 GPU;请在 NVIDIA 机器上使用 --device cuda 以获得真实吞吐"
            ),
        ),
        "mps" => Check::warn(
            NAME,
            tr!("device is mps (Apple Metal — testing)", "设备为 mps(Apple Metal — 测试)"),
            tr!(
                "mps works for a smoke test; the coordinator's corpus expects a CUDA GPU for real throughput",
                "mps 可用于冒烟测试;调度中心的语料在真实吞吐下需要 CUDA GPU"
            ),
        ),
        "cuda" => {
            let mut cmd = std::process::Command::new("nvidia-smi");
            cmd.arg("-L");
            let smi_ok = matches!(run_with_timeout(&mut cmd, PROBE_TIMEOUT), Ok(Some(o)) if o.status.success());
            if smi_ok {
                Check::pass(
                    NAME,
                    tr!("cuda — nvidia-smi reports at least one NVIDIA GPU", "cuda — nvidia-smi 报告至少一块 NVIDIA GPU"),
                )
            } else if allow_cpu {
                Check::warn(
                    NAME,
                    tr!(
                        "device is cuda but no NVIDIA GPU was detected; --allow-cpu will downshift to CPU (testing)",
                        "设备为 cuda 但未检测到 NVIDIA GPU;--allow-cpu 将降级到 CPU(测试)"
                    ),
                    tr!(
                        "a real training worker needs a GPU; --allow-cpu only lets a no-NVIDIA box generate on CPU",
                        "真正的训练工作节点需要 GPU;--allow-cpu 仅让无 NVIDIA 的机器在 CPU 上生成"
                    ),
                )
            } else {
                Check::fail(
                    NAME,
                    tr!(
                        "device is cuda but no NVIDIA GPU was detected (nvidia-smi missing or reported none)",
                        "设备为 cuda 但未检测到 NVIDIA GPU(缺少 nvidia-smi 或其未报告任何 GPU)"
                    ),
                    tr!(
                        "install the NVIDIA driver so nvidia-smi works, or pass --device cpu (or --allow-cpu) to generate on CPU for testing (a real worker needs a GPU)",
                        "请安装 NVIDIA 驱动使 nvidia-smi 可用,或传入 --device cpu(或 --allow-cpu)以在 CPU 上生成用于测试(真正的工作节点需要 GPU)"
                    ),
                )
            }
        }
        other => Check::fail(
            NAME,
            format!("{} {other:?}", tr!("unknown device", "未知设备")),
            tr!("use --device cuda | cpu | mps", "请使用 --device cuda | cpu | mps"),
        ),
    }
}

/// Render the train doctor report (human form) — same layout as [`render_report`] but
/// headed for the train role.
pub fn render_train_report(checks: &[Check]) -> String {
    let mut s = String::new();
    s.push_str(tr!(
        "Alice Miner doctor — train (RLVR training worker)\n",
        "Alice Miner doctor — train (RLVR 训练工作节点)\n"
    ));
    s.push_str("─────────────────────────────────────────────\n");
    for c in checks {
        s.push_str(&format!("  [{}] {} — {}\n", c.status.word(), c.name, c.detail));
        if !c.fix.is_empty() {
            s.push_str(&format!("        {}: {}\n", tr!("fix", "修复"), c.fix));
        }
    }
    let fails = checks.iter().filter(|c| c.status == Status::Fail).count();
    let warns = checks.iter().filter(|c| c.status == Status::Warn).count();
    s.push_str("─────────────────────────────────────────────\n");
    if fails == 0 {
        s.push_str(&format!(
            "{} ({warns} {})\n",
            tr!("Ready to run the train role.", "train 角色已就绪。"),
            tr!("warning(s).", "个警告。")
        ));
    } else {
        s.push_str(&format!(
            "{fails} {}, {warns} {}\n",
            tr!("blocking issue(s)", "个阻塞问题"),
            tr!(
                "warning(s). Fix the FAIL lines above, then re-run `alice-miner doctor --train`.",
                "个警告。请修复上面的 FAIL 行,然后重新运行 `alice-miner doctor --train`。"
            )
        ));
    }
    s
}

/// Render the train doctor report as JSON (machine-readable).
pub fn render_train_json(checks: &[Check]) -> String {
    let arr: Vec<serde_json::Value> = checks
        .iter()
        .map(|c| {
            serde_json::json!({
                "name": c.name,
                "status": c.status.json_token(),
                "detail": c.detail,
                "fix": if c.fix.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(c.fix.clone()) },
            })
        })
        .collect();
    let fails = checks.iter().filter(|c| c.status == Status::Fail).count();
    serde_json::json!({ "role": "train", "ready": fails == 0, "checks": arr }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap() -> CapabilityProfile {
        CapabilityProfile::detect()
    }

    /// The battery runs end-to-end without panicking on the dev box and produces a
    /// check for each diagnostic area (identity, lane, gpu cc, engine, keyring,
    /// relay, + at least one platform guardrail on mac/windows).
    #[test]
    fn run_checks_produces_a_full_battery() {
        let checks = run_checks(Lane::Xmr, &cap());
        let names: Vec<&str> = checks.iter().map(|c| c.name).collect();
        assert!(names.contains(&"identity"));
        assert!(names.contains(&"lane support"));
        assert!(names.contains(&"gpu compute capability"));
        assert!(names.contains(&"engine"));
        assert!(names.contains(&"keyring (background GPU)"));
        assert!(names.contains(&"relay reachability"));
        // Every check has a non-empty detail, and any non-Pass/Skip carries a fix.
        for c in &checks {
            assert!(!c.detail.is_empty(), "{} has no detail", c.name);
            if matches!(c.status, Status::Fail | Status::Warn) {
                assert!(!c.fix.is_empty(), "{} ({:?}) must carry a fix", c.name, c.status);
            }
        }
    }

    /// The CC check is honest about a Volta/V100 card: it FAILS for the PRL lane
    /// with CC < 7.5 and the fix routes to the Alpha lane (never a false promise).
    #[test]
    fn gpu_cc_check_is_honest_about_volta() {
        use alice_miner_core::detect::{GpuInfo, GpuVendor};
        // A synthetic Volta profile (CC 7.0).
        let mut c = cap();
        c.profile.gpu = GpuInfo {
            vendor: GpuVendor::Nvidia,
            model: "Tesla V100-PCIE-16GB".into(),
            vram_gb: 16,
            gpus: Vec::new(),
            max_compute_cap_x10: Some(70),
        };
        let check = check_gpu_compute_capability(Lane::GpuPrl, &c);
        assert_eq!(check.status, Status::Fail);
        assert!(check.detail.contains("below 7.5"), "honest detail: {}", check.detail);
        assert!(check.fix.contains("--lane alpha"), "routes to Alpha: {}", check.fix);

        // A Turing+ card (CC 7.5) passes.
        c.profile.gpu.max_compute_cap_x10 = Some(75);
        assert_eq!(check_gpu_compute_capability(Lane::GpuPrl, &c).status, Status::Pass);

        // The check is Skip for non-PRL lanes.
        assert_eq!(check_gpu_compute_capability(Lane::Xmr, &c).status, Status::Skip);
    }

    /// The keyring check is Skip for XMR/RVN (it only gates background GPU), and a
    /// pearlhash lane on a no-keyring box WARNs (foreground still works), never FAILs.
    #[test]
    fn keyring_check_scopes_to_gpu_background() {
        assert_eq!(check_keyring(Lane::Xmr).status, Status::Skip);
        assert_eq!(check_keyring(Lane::GpuRvn).status, Status::Skip);
        // PRL lane: Pass or Warn depending on the box, but NEVER Fail (foreground ok).
        let k = check_keyring(Lane::GpuPrl);
        assert!(matches!(k.status, Status::Pass | Status::Warn), "got {:?}", k.status);
    }

    /// The rendered report (human + json) is CREDIT-ONLY and secret-free: no
    /// fiat/paid/earned/payout token, and it never prints a seed/mnemonic/password.
    #[test]
    fn report_is_credit_only_and_secret_free() {
        // Build a battery that hits every render branch, including a synthetic FAIL.
        let mut checks = run_checks(Lane::GpuPrl, &cap());
        checks.push(Check::fail("synthetic", "a forced failure", "do the fix"));
        let human = render_report(&checks, Lane::GpuPrl);
        let json = render_json(&checks, Lane::GpuPrl);
        for blob in [&human, &json] {
            let lower = blob.to_ascii_lowercase();
            for forbidden in [
                "$", "usd", "fiat", "paid", "earned", "payout", "待发放", "已发放",
                "mnemonic", "seed", "password", "private key",
            ] {
                assert!(!lower.contains(forbidden), "report leaked `{forbidden}`: {blob}");
            }
        }
        // The human report names the relay endpoint host (public) — and ONLY that
        // public host, never an upstream pool / core IP.
        assert!(human.contains("doctor"), "header present");
    }

    /// `has_blocking_failure` mirrors the presence of a FAIL (drives the exit code).
    #[test]
    fn blocking_failure_reflects_a_fail() {
        let ok = vec![Check::pass("a", "fine"), Check::warn("b", "meh", "fix")];
        assert!(!has_blocking_failure(&ok));
        let bad = vec![Check::pass("a", "fine"), Check::fail("c", "broken", "fix")];
        assert!(has_blocking_failure(&bad));
    }

    // ── doctor --fix (safe / prompt / never matrix) ────────────────────────────

    /// The identity check carries NO [`FixAction`] — a fix that could create/overwrite
    /// an identity must only be PRINTED, never auto-applied (the hard rule). This locks
    /// the "NEVER auto-touch identity/keyring/wallet" invariant.
    #[test]
    fn identity_and_keyring_checks_have_no_fix_action() {
        // Identity is never auto-fixable regardless of state.
        assert!(check_identity().fix_action.is_none(), "identity must never auto-fix");
        // The keyring / relay checks likewise carry no auto-fix (relay may PASS or FAIL
        // depending on the box, but never carries a machine fix action either way).
        assert!(check_keyring(Lane::GpuPrl).fix_action.is_none());
        assert!(check_relay(Lane::Xmr).fix_action.is_none());
    }

    /// The engine check attaches a safe RedownloadEngine action ONLY when the engine is
    /// missing-but-fetchable (a WARN); a resolved engine (PASS) carries no action.
    #[test]
    fn engine_check_action_matches_fetchability() {
        let c = check_engine(Lane::Xmr);
        match c.status {
            Status::Pass => assert!(c.fix_action.is_none(), "resolved engine → no fix action"),
            Status::Warn => assert!(
                matches!(c.fix_action, Some(FixAction::RedownloadEngine(_))),
                "fetchable-but-uncached → RedownloadEngine action"
            ),
            _ => {}
        }
    }

    /// `apply_fixes` in a NON-interactive run SKIPS a prompt-required service fix with a
    /// note (never silently applies it) and reports the manual-only steps.
    #[test]
    fn apply_fixes_skips_prompt_fix_when_non_interactive() {
        let checks = vec![
            Check::fail("background service", "not installed", "install it")
                .with_action(FixAction::PromptService),
            // A manual-only (no-action) failing check → surfaced under "Manual steps".
            Check::fail("identity", "no reward identity yet", "create one"),
        ];
        // A prompt that would PANIC if called — proving the non-interactive path never asks.
        let mut never = |_: &str| panic!("must not prompt when non-interactive");
        let report = apply_fixes(&checks, /*interactive=*/ false, &mut never);
        assert!(report.contains("background service"), "service line present: {report}");
        assert!(report.to_lowercase().contains("skip") || report.contains("跳过"), "skipped: {report}");
        assert!(report.contains("Manual steps"), "manual steps surfaced: {report}");
        assert!(report.contains("identity"), "identity is a manual step: {report}");
    }

    /// `apply_fixes` PROMPTS for a service fix on a TTY and honors a "no" answer.
    #[test]
    fn apply_fixes_prompts_and_respects_decline() {
        let checks = vec![Check::fail("background service", "not installed", "install it")
            .with_action(FixAction::PromptService)];
        let mut asked = false;
        let mut decline = |_: &str| {
            asked = true;
            false // decline
        };
        let report = apply_fixes(&checks, /*interactive=*/ true, &mut decline);
        assert!(asked, "the service fix must prompt on a TTY");
        assert!(report.to_lowercase().contains("declined") || report.contains("已跳过"), "{report}");
    }

    /// The safe RecreateConfig fix backs up a MALFORMED settings file and writes a fresh
    /// default; it is a no-op (Skipped) on a VALID or absent file (never clobbers a good
    /// config). Isolated via a temp ALICE_IDENTITY_DIR.
    #[test]
    fn recreate_config_backs_up_and_rewrites_only_when_malformed() {
        let _g = crate::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "alice-doctor-cfg-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("ALICE_IDENTITY_DIR", &dir);
        let path = alice_miner_core::settings::settings_path();

        // (a) No file → Skipped (nothing to repair).
        assert!(matches!(fix_recreate_config(), FixOutcome::Skipped(_)));

        // (b) Malformed file → Applied; a backup exists and the file now parses.
        std::fs::write(&path, b"{ this is not json").unwrap();
        assert!(matches!(fix_recreate_config(), FixOutcome::Applied(_)), "malformed → applied");
        let repaired = std::fs::read_to_string(&path).unwrap();
        assert!(serde_json::from_str::<serde_json::Value>(&repaired).is_ok(), "repaired to valid JSON");
        assert!(path.with_extension("json.bak").exists(), "old file backed up");

        // (c) A now-valid file → Skipped (never clobbers a good config).
        assert!(matches!(fix_recreate_config(), FixOutcome::Skipped(_)), "valid → no-op");

        std::env::remove_var("ALICE_IDENTITY_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The json form is valid JSON with the expected shape (lane, ready, checks[]).
    #[test]
    fn json_report_has_expected_shape() {
        let checks = run_checks(Lane::Xmr, &cap());
        let json = render_json(&checks, Lane::Xmr);
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["lane"].as_str(), Some("xmr"));
        assert!(v["ready"].is_boolean());
        let arr = v["checks"].as_array().expect("checks array");
        assert!(!arr.is_empty());
        for c in arr {
            assert!(c["name"].is_string());
            assert!(["pass", "warn", "fail", "skip"].contains(&c["status"].as_str().unwrap()));
        }
    }

    // ── ai (shard-stage inference) doctor ─────────────────────────────────────

    /// The ai engine-dir check FAILs when the dir is missing / lacks pipeline.py,
    /// and PASSes when it is present — honest, with a fix on the fail path.
    #[test]
    fn ai_engine_dir_check_is_honest() {
        // No dir → fail with a fix.
        let none = check_ai_engine_dir(None);
        assert_eq!(none.status, Status::Fail);
        assert!(none.fix.contains("--engine-dir"));

        // A dir missing pipeline.py → fail.
        let tmp = std::env::temp_dir().join(format!("ai-doctor-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        assert_eq!(check_ai_engine_dir(Some(&tmp)).status, Status::Fail);

        // With phase0/pipeline.py → pass.
        std::fs::create_dir_all(tmp.join("phase0")).unwrap();
        std::fs::write(tmp.join("phase0/pipeline.py"), b"# stub").unwrap();
        assert_eq!(check_ai_engine_dir(Some(&tmp)).status, Status::Pass);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// The nvidia check FAILs without a GPU + no --allow-cpu, WARNs with --allow-cpu.
    #[test]
    fn ai_nvidia_check_respects_allow_cpu() {
        let c = check_ai_nvidia(true);
        // With allow_cpu the worst case is a WARN (never a FAIL) — on a box that
        // HAS a GPU it PASSes; either way it is not a blocking failure.
        assert_ne!(c.status, Status::Fail);
    }

    /// The endpoint check FAILs for a missing / malformed endpoint.
    #[test]
    fn ai_endpoint_check_validates() {
        assert_eq!(check_ai_endpoint(None).status, Status::Fail);
        assert_eq!(check_ai_endpoint(Some("noport")).status, Status::Fail);
        assert_eq!(check_ai_endpoint(Some("h:0")).status, Status::Fail);
        // A high, likely-free port PASSes the local-bind probe (or WARNs if held).
        let c = check_ai_endpoint(Some("127.0.0.1:52987"));
        assert_ne!(c.status, Status::Fail, "a valid port is not a hard fail: {c:?}");
    }

    /// The ai battery runs end-to-end (no panic) and renders valid JSON.
    #[test]
    fn ai_battery_and_json_shape() {
        let input = AiDoctorInput {
            allow_cpu: true,
            python: "definitely-not-a-real-python-xyz".into(),
            ..Default::default()
        };
        let checks = run_ai_checks(&input);
        let names: Vec<&str> = checks.iter().map(|c| c.name).collect();
        assert!(names.contains(&"python3"));
        assert!(names.contains(&"shard engine"));
        assert!(names.contains(&"torch"));
        assert!(names.contains(&"nvidia gpu"));
        assert!(names.contains(&"endpoint port"));
        assert!(names.contains(&"center reachability"));
        for c in &checks {
            assert!(!c.detail.is_empty(), "{} has no detail", c.name);
            if matches!(c.status, Status::Fail | Status::Warn) {
                assert!(!c.fix.is_empty(), "{} ({:?}) must carry a fix", c.name, c.status);
            }
        }
        let json = render_ai_json(&checks);
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["role"].as_str(), Some("ai"));
        assert!(v["checks"].as_array().unwrap().len() >= 6);
        // The human report is credit-only diagnostics — no reward tokens.
        let human = render_ai_report(&checks);
        let low = human.to_ascii_lowercase();
        for bad in ["hashrate", "earned", "payout", "$"] {
            assert!(!low.contains(bad), "ai report must not contain {bad:?}");
        }
    }

    // ── train (RLVR training) doctor ──────────────────────────────────────────

    /// The train trainer-dir check FAILs when the dir is missing / lacks run_m0.py or
    /// code_exec.py, and PASSes when both are present — honest, with a fix on the fail.
    #[test]
    fn train_trainer_dir_check_is_honest() {
        // No dir → fail with a fix.
        let none = check_train_trainer_dir(None);
        assert_eq!(none.status, Status::Fail);
        assert!(none.fix.contains("--trainer-dir"));

        let tmp = std::env::temp_dir().join(format!("train-doctor-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        // Only run_m0.py → still fail (code_exec.py missing).
        std::fs::write(tmp.join("run_m0.py"), b"# stub").unwrap();
        assert_eq!(check_train_trainer_dir(Some(&tmp)).status, Status::Fail);
        // Both present → pass.
        std::fs::write(tmp.join("code_exec.py"), b"# stub").unwrap();
        assert_eq!(check_train_trainer_dir(Some(&tmp)).status, Status::Pass);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// The train device check: cpu/mps WARN (testing), cuda without a GPU FAILs unless
    /// --allow-cpu (then WARN), an unknown device FAILs.
    #[test]
    fn train_device_check_is_honest() {
        assert_eq!(check_train_device("cpu", false).status, Status::Warn);
        assert_eq!(check_train_device("mps", false).status, Status::Warn);
        assert_eq!(check_train_device("bogus", false).status, Status::Fail);
        // cuda: PASS on a GPU box, else FAIL (no --allow-cpu) / WARN (--allow-cpu).
        let cuda = check_train_device("cuda", false);
        assert!(matches!(cuda.status, Status::Pass | Status::Fail), "got {:?}", cuda.status);
        let cuda_allow = check_train_device("cuda", true);
        assert_ne!(cuda_allow.status, Status::Fail, "allow-cpu is never a hard fail");
    }

    /// The base-model check WARNs when unset (built-in default) and PASSes for a
    /// HF-id-like value (treated as downloadable).
    #[test]
    fn train_base_model_check() {
        assert_eq!(check_train_base_model(None).status, Status::Warn);
        assert_eq!(check_train_base_model(Some("")).status, Status::Warn);
        assert_eq!(
            check_train_base_model(Some("Qwen/Qwen2.5-3B-Instruct")).status,
            Status::Pass
        );
    }

    /// The train battery runs end-to-end (no panic), renders valid JSON, and stays
    /// credit-only.
    #[test]
    fn train_battery_and_json_shape() {
        let input = TrainDoctorInput {
            allow_cpu: true,
            python: "definitely-not-a-real-python-xyz".into(),
            device: "cpu".into(),
            ..Default::default()
        };
        let checks = run_train_checks(&input);
        let names: Vec<&str> = checks.iter().map(|c| c.name).collect();
        assert!(names.contains(&"python3"));
        assert!(names.contains(&"torch"));
        assert!(names.contains(&"trainer dir"));
        assert!(names.contains(&"base model"));
        assert!(names.contains(&"device"));
        assert!(names.contains(&"center reachability"));
        for c in &checks {
            assert!(!c.detail.is_empty(), "{} has no detail", c.name);
            if matches!(c.status, Status::Fail | Status::Warn) {
                assert!(!c.fix.is_empty(), "{} ({:?}) must carry a fix", c.name, c.status);
            }
        }
        let json = render_train_json(&checks);
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["role"].as_str(), Some("train"));
        assert!(v["checks"].as_array().unwrap().len() >= 6);
        let human = render_train_report(&checks);
        let low = human.to_ascii_lowercase();
        for bad in ["hashrate", "earned", "payout", "$"] {
            assert!(!low.contains(bad), "train report must not contain {bad:?}");
        }
    }
}
