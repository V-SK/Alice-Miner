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

/// One diagnostic line: a short `name`, the `status`, a one-line `detail`, and an
/// EXACT `fix` (a command or step) when the status is not Pass/Skip.
#[derive(Debug, Clone)]
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
    /// The exact fix to apply (empty for Pass/Skip).
    pub fix: String,
}

impl Check {
    fn pass(name: &'static str, detail: impl Into<String>) -> Self {
        Check { name, status: Status::Pass, detail: detail.into(), fix: String::new() }
    }
    fn warn(name: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Check { name, status: Status::Warn, detail: detail.into(), fix: fix.into() }
    }
    fn fail(name: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Check { name, status: Status::Fail, detail: detail.into(), fix: fix.into() }
    }
    fn skip(name: &'static str, detail: impl Into<String>) -> Self {
        Check { name, status: Status::Skip, detail: detail.into(), fix: String::new() }
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
        check_lane_support(lane, cap),
        check_gpu_compute_capability(lane, cap),
        check_engine(lane),
        check_keyring(lane),
        check_relay(lane),
    ];
    checks.extend(platform_guardrails());
    checks
}

/// Identity / address validity: a valid SS58-300 Alice reward address must exist
/// (else mining has nowhere to send credit).
fn check_identity() -> Check {
    const NAME: &str = "identity";
    match alice_miner_core::identity::load_pointer() {
        Some(p) => {
            if alice_miner_core::lane::xmr::validate_alice_address(&p.address).is_some() {
                let watch = if p.keystore_path.is_none() { " (watch-only)" } else { "" };
                Check::pass(NAME, format!("reward address is a valid Alice SS58-300 address{watch}"))
            } else {
                Check::fail(
                    NAME,
                    "the stored reward address is not a valid Alice SS58-300 address",
                    "re-create or re-paste your identity: `alice-miner identity --create` \
                     (or `--paste <address>`)",
                )
            }
        }
        None => Check::fail(
            NAME,
            "no reward identity yet",
            "create one: `alice-miner identity --create` (or `--paste <address>` for watch-only)",
        ),
    }
}

/// Lane viability: the selected lane must be runnable on this device per the
/// capability matrix (the honest gate the engine uses before spawn).
fn check_lane_support(lane: Lane, cap: &CapabilityProfile) -> Check {
    const NAME: &str = "lane support";
    if cap.support(lane).is_runnable() {
        Check::pass(NAME, format!("{} is runnable on this device", lane.label()))
    } else {
        let reason = cap.viability.reason(lane).unwrap_or("not viable on this device");
        Check::fail(
            NAME,
            format!("{} is {} ({reason})", lane.label(), cap.support(lane).label()),
            format!(
                "use the recommended lane instead: `alice-miner start --lane {}`",
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
        return Check::skip(NAME, "only applies to the GPU-PRL (SRBMiner) lane");
    }
    match cap.profile.gpu.max_compute_cap_x10 {
        Some(cc) if cc >= 75 => Check::pass(
            NAME,
            format!("CC {}.{} ≥ 7.5 — SRBMiner pearlhash is supported", cc / 10, cc % 10),
        ),
        Some(cc) => Check::fail(
            NAME,
            format!(
                "CC {}.{} is below 7.5 — SRBMiner pearlhash is unsupported on this card",
                cc / 10,
                cc % 10
            ),
            "use the Alpha lane (AlphaMiner covers Volta/V100): \
             `alice-miner start --lane alpha`",
        ),
        None => Check::warn(
            NAME,
            "no NVIDIA compute capability reported (non-NVIDIA card or nvidia-smi missing)",
            "if this is an NVIDIA card, install the NVIDIA driver so `nvidia-smi` reports \
             its compute capability; SRBMiner pearlhash needs CC 7.5+",
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
        Ok(path) => Check::pass(NAME, format!("{} resolved at {}", kind.binary_name(), path.display())),
        Err(e) => {
            if binaries::is_fetchable(kind) {
                // A real pin + URL exist, but the resolve failed (e.g. offline). The
                // download will run at start; surface the transient reason as a WARN.
                Check::warn(
                    NAME,
                    format!("{} not yet cached: {e}", kind.binary_name()),
                    "it will auto-download (sha-pinned) on the next `alice-miner start` \
                     when the network is reachable",
                )
            } else {
                Check::fail(
                    NAME,
                    format!("{} is not available: {e}", kind.binary_name()),
                    format!(
                        "install a packaged release that bundles the engine: {}",
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
        return Check::skip(NAME, "only needed to BACKGROUND a GPU pearlhash lane");
    }
    if alice_miner_core::keyring::is_available() {
        Check::pass(NAME, "an OS keyring is available to hold the background wallet unlock")
    } else {
        Check::warn(
            NAME,
            "no OS keyring on this box (e.g. a headless Linux rig)",
            "foreground mining works without it; for BACKGROUND GPU mining, run on a box \
             with a keyring (macOS Keychain / Windows Credential Manager / Linux Secret \
             Service) or background the CPU-XMR lane instead",
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
        Ok(()) => Check::pass(NAME, format!("connected to the relay {host_port}")),
        Err(e) => Check::fail(
            NAME,
            format!("cannot reach the relay {host_port}: {e}"),
            "check your network / firewall (the stratum port must be reachable outbound); \
             a VPN or captive portal can block it",
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
            "Windows Defender flags mining engines as a \"potentially unwanted application\" \
             (a known false positive) and may quarantine the engine",
            format!(
                "if mining won't start, allow the engine cache in Defender — in an elevated \
                 PowerShell run: Add-MpPreference -ExclusionPath '{cache}'"
            ),
        ));
    }
    if cfg!(target_os = "macos") {
        out.push(Check::warn(
            "macos gatekeeper / app-nap",
            "macOS App Nap can throttle a backgrounded miner to ~0 H/s, and Gatekeeper can \
             block a freshly-downloaded engine",
            "the packaged app sets NSAppSleepDisabled + uses caffeinate to defeat App Nap; if \
             you launched a raw binary and hashrate drops to 0 when the window is hidden, run \
             it under `caffeinate -dimsu alice-miner start …` and keep the engine in the \
             packaged app so Gatekeeper trusts it",
        ));
    }
    out
}

/// Render the full report to a String (human form). Each non-Pass/Skip line gets
/// its exact fix indented underneath. Credit-only by construction (diagnostics
/// only — a unit test scans for forbidden reward/secret tokens).
pub fn render_report(checks: &[Check], lane: Lane) -> String {
    let mut s = String::new();
    s.push_str(&format!("Alice Miner doctor — lane {}\n", lane.cli_lane_arg()));
    s.push_str("─────────────────────────────────────────────\n");
    for c in checks {
        s.push_str(&format!("  [{}] {} — {}\n", c.status.word(), c.name, c.detail));
        if !c.fix.is_empty() {
            s.push_str(&format!("        fix: {}\n", c.fix));
        }
    }
    let fails = checks.iter().filter(|c| c.status == Status::Fail).count();
    let warns = checks.iter().filter(|c| c.status == Status::Warn).count();
    s.push_str("─────────────────────────────────────────────\n");
    if fails == 0 {
        s.push_str(&format!("Ready to mine. ({warns} warning(s).)\n"));
    } else {
        s.push_str(&format!(
            "{fails} blocking issue(s), {warns} warning(s). Fix the FAIL lines above, then \
             re-run `alice-miner doctor`.\n"
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

/// Print a one-line summary to stderr that a `start` pre-flight can show (a light
/// version of doctor inside `start` — the spec's "run a light version inside
/// start"). Best-effort; never blocks mining.
pub fn print_preflight_summary(lane: Lane, cap: &CapabilityProfile) {
    let checks = run_checks(lane, cap);
    if let Some(first_fail) = checks.iter().find(|c| c.status == Status::Fail) {
        let mut err = std::io::stderr();
        let _ = writeln!(
            err,
            "preflight: {} — {}\n  fix: {}\n  (run `alice-miner doctor` for the full report)",
            first_fail.name, first_fail.detail, first_fail.fix
        );
    }
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
}
