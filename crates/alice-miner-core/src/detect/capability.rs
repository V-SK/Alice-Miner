//! `core/detect/capability` — the **lane-viability matrix** + the full
//! [`CapabilityProfile`] auto-detection bundle.
//!
//! Ported from the SHAPE of `hardware_probe.py`'s `LaneViability` /
//! `derive_lane_viability` / `apply_lane_override` / `CapabilityProfile`, with
//! the **deliberate Alice-Miner divergences** from the Python reference (PLAN
//! §6 D-lanes):
//!
//!   * **Only two client lanes exist** — CPU→XMR and NVIDIA-GPU→RVN. The Python
//!     reference also models PRL / LTC / AI; **PRL is NOT a client lane** (ruled
//!     fake-AI per MEMORY), LTC is upstream-only (not a client lane), and the
//!     AI-earn lane is M8 (hidden until then). So this module's universe is
//!     exactly `{Xmr, GpuRvn}` — the [`crate::lane::Lane`] enum.
//!   * Each lane is classified into a [`LaneSupport`] level: **`Viable`**
//!     (runnable on this device now), **`ComingSoon`** (the hardware is present
//!     but the client can't run it yet — e.g. an AMD/Intel GPU for RVN), or
//!     **`Unavailable`** (the device can't do it at all — e.g. RVN on Apple).
//!     The UI uses this directly: a `ComingSoon` lane shows a muted
//!     "coming soon" chip and is NOT selectable; an `Unavailable` lane is hidden
//!     or shown only as a dim "not supported" row.
//!
//! The viability rules (the M3 matrix, from the brief / PLAN §5 M3):
//!
//! | device                  | XMR      | RVN                         |
//! |-------------------------|----------|-----------------------------|
//! | CPU (any)               | Viable   | (per-GPU below)             |
//! | NVIDIA GPU              | Viable   | **Viable**                  |
//! | AMD / Intel GPU         | Viable   | **ComingSoon** (not runnable yet) |
//! | Apple Silicon           | Viable   | **Unavailable** (XMR only)  |
//! | no GPU / all-probes-fail| Viable   | Unavailable                 |
//!
//! **CREDIT-ONLY / pure derivation.** This module reads the profile and computes
//! a lane set; it touches no reward / payout / chain surface and no key.

#![allow(dead_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{DeviceProfile, GpuVendor};
use crate::lane::Lane;

/// How well the client supports a given lane on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneSupport {
    /// Runnable on this device right now (the lane can be Started).
    Viable,
    /// The hardware is present but the client can't run this lane yet (e.g. an
    /// AMD/Intel GPU for RVN — no confirmed/bundled KawPoW path). Surfaced to the
    /// UI as a muted "coming soon" chip; NOT selectable.
    ComingSoon,
    /// The device cannot do this lane at all (e.g. RVN on Apple Silicon, or RVN
    /// with no GPU). Hidden or shown as a dim "not supported" row.
    Unavailable,
}

impl LaneSupport {
    /// Whether the lane can actually be Started on this device.
    pub fn is_runnable(self) -> bool {
        matches!(self, LaneSupport::Viable)
    }

    /// A short, honest UI label for the support level.
    pub fn label(self) -> &'static str {
        match self {
            LaneSupport::Viable => "available",
            LaneSupport::ComingSoon => "coming soon",
            LaneSupport::Unavailable => "not supported",
        }
    }
}

/// The viable-lane subset derived from a [`DeviceProfile`] — the M3 lane-viability
/// matrix. `support` carries the [`LaneSupport`] level for EVERY lane; `reasons`
/// records, per lane, WHY (a machine-readable token, surfaced in the CLI + handy
/// in tests). `recommended` is the lane the UI defaults to (the best runnable
/// one). Mirrors the Python `LaneViability`, restricted to the two client lanes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneViability {
    /// Support level for each lane (always covers all of [`Lane`]).
    pub support: BTreeMap<Lane, LaneSupport>,
    /// Machine-readable reason per lane (e.g. `cpu_always_viable`,
    /// `rvn_requires_nvidia_apple_excluded`).
    pub reasons: BTreeMap<Lane, String>,
    /// The lane the UI recommends / defaults to (the best RUNNABLE lane). On a
    /// device with no runnable GPU lane this is always [`Lane::Xmr`].
    pub recommended: Lane,
    /// Operator-facing hints (e.g. an AMD "coming soon" note).
    pub notes: Vec<String>,
}

impl LaneViability {
    /// The support level for `lane` (defaults to `Unavailable` if somehow
    /// missing — never panics).
    pub fn support(&self, lane: Lane) -> LaneSupport {
        self.support
            .get(&lane)
            .copied()
            .unwrap_or(LaneSupport::Unavailable)
    }

    /// Whether `lane` is runnable on this device right now.
    pub fn is_runnable(&self, lane: Lane) -> bool {
        self.support(lane).is_runnable()
    }

    /// The reason token for `lane`, if recorded.
    pub fn reason(&self, lane: Lane) -> Option<&str> {
        self.reasons.get(&lane).map(String::as_str)
    }

    /// The ordered list of RUNNABLE lanes (recommended first), for the CLI /
    /// "change lane" affordance.
    pub fn runnable_lanes(&self) -> Vec<Lane> {
        let mut lanes: Vec<Lane> = ALL_LANES
            .iter()
            .copied()
            .filter(|&l| self.is_runnable(l))
            .collect();
        // Recommended lane first.
        lanes.sort_by_key(|&l| if l == self.recommended { 0 } else { 1 });
        lanes
    }
}

/// The full universe of client lanes. Declared here so every derivation covers
/// exactly this set: CPU-XMR, the GPU-PRL **mainline** (SRBMiner pearlhash), and
/// the earlier GPU-RVN path. LTC/AI are intentionally absent.
pub const ALL_LANES: [Lane; 3] = [Lane::Xmr, Lane::GpuPrl, Lane::GpuRvn];

/// Derive the lane-viability matrix from a detected [`DeviceProfile`].
///
/// Rules (PLAN §5 M3 / the brief):
///   * **XMR** = any CPU → always [`LaneSupport::Viable`] (every device has a
///     CPU; the proven RandomX lane runs everywhere).
///   * **RVN** = NVIDIA → `Viable`; AMD/Intel GPU → `ComingSoon` (detected but no
///     bundled KawPoW path yet); Apple Silicon → `Unavailable` (XMR-only);
///     no GPU / all-probes-failed → `Unavailable`.
///   * **recommended** = the best runnable lane: RVN when it's viable (a real
///     NVIDIA GPU outruns the CPU), else XMR.
pub fn derive_lane_viability(profile: &DeviceProfile) -> LaneViability {
    let mut support = BTreeMap::new();
    let mut reasons = BTreeMap::new();
    let mut notes = Vec::new();

    // ── XMR: any CPU is viable, always ──────────────────────────────────────
    support.insert(Lane::Xmr, LaneSupport::Viable);
    reasons.insert(Lane::Xmr, "cpu_always_viable".to_string());

    // ── RVN: depends on the GPU vendor ──────────────────────────────────────
    let (rvn_support, rvn_reason) = match profile.gpu.vendor {
        GpuVendor::Nvidia => (LaneSupport::Viable, "nvidia_present"),
        GpuVendor::Amd => {
            notes.push(
                "AMD GPU detected — the RVN (KawPoW) lane for AMD is coming soon."
                    .to_string(),
            );
            (LaneSupport::ComingSoon, "rvn_amd_coming_soon")
        }
        GpuVendor::Apple => (LaneSupport::Unavailable, "rvn_requires_nvidia_apple_excluded"),
        GpuVendor::None => {
            // Distinguish "an Intel/integrated GPU might be present but we can't
            // run RVN on it" from "truly no GPU". We can't reliably tell Intel
            // iGPU apart cheaply, so we treat the non-Apple no-NVIDIA case as
            // CPU-only RVN-unavailable (the honest, conservative result).
            (LaneSupport::Unavailable, "rvn_requires_nvidia_cpu_only")
        }
    };
    support.insert(Lane::GpuRvn, rvn_support);
    reasons.insert(Lane::GpuRvn, rvn_reason.to_string());

    // ── PRL (SRBMiner pearlhash): NVIDIA + AMD viable (SRBMiner supports both);
    //    Apple/none unavailable (SRBMiner ships no macOS build). ────────────────
    let (prl_support, prl_reason) = match profile.gpu.vendor {
        GpuVendor::Nvidia => (LaneSupport::Viable, "nvidia_present"),
        GpuVendor::Amd => (LaneSupport::Viable, "amd_srbminer_supported"),
        GpuVendor::Apple => (
            LaneSupport::Unavailable,
            "prl_requires_nvidia_or_amd_apple_excluded",
        ),
        GpuVendor::None => (LaneSupport::Unavailable, "prl_requires_gpu_cpu_only"),
    };
    support.insert(Lane::GpuPrl, prl_support);
    reasons.insert(Lane::GpuPrl, prl_reason.to_string());

    // ── recommended: best runnable lane (RVN if viable, else XMR) ───────────
    let recommended = if support
        .get(&Lane::GpuRvn)
        .copied()
        .unwrap_or(LaneSupport::Unavailable)
        .is_runnable()
    {
        Lane::GpuRvn
    } else {
        Lane::Xmr
    };

    LaneViability {
        support,
        reasons,
        recommended,
        notes,
    }
}

// ── Operator lane override (env): force / restrict the runnable lanes ─────────

/// Env var that overrides the runnable lane set (e.g. `xmr` or `xmr,gpu`).
/// Mirrors the Python `LANE_OVERRIDE_ENV`.
pub const LANE_OVERRIDE_ENV: &str = "ALICE_MINER_LANES";
/// Env var that, when truthy, makes the override FORCE lanes the probe deemed
/// non-viable (an operator escape hatch). Mirrors the Python force flag.
pub const LANE_FORCE_ENV: &str = "ALICE_MINER_LANES_FORCE";

/// Parse a lane-override string (e.g. `"xmr"`, `"gpu,xmr"`, `"rvn"`) into the
/// requested lane set. Tokens are case-insensitive (`xmr`/`cpu` → XMR;
/// `gpu`/`rvn` → GpuRvn). Unknown tokens are ignored (fail-open to "no override"
/// rather than crashing). Returns `None` when unset/empty.
pub fn parse_lane_override(value: Option<&str>) -> Option<Vec<Lane>> {
    let raw = value?.trim();
    if raw.is_empty() {
        return None;
    }
    let mut out: Vec<Lane> = Vec::new();
    for token in raw.split(|c: char| c == ',' || c.is_whitespace()) {
        let key = token.trim().to_ascii_lowercase();
        let lane = match key.as_str() {
            "" => continue,
            "xmr" | "cpu" => Lane::Xmr,
            "prl" => Lane::GpuPrl,
            "gpu" | "rvn" => Lane::GpuRvn,
            _ => continue, // unknown token → ignore (fail-open)
        };
        if !out.contains(&lane) {
            out.push(lane);
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Apply an operator lane override to a derived [`LaneViability`].
///
/// Default (`force=false`): the override RESTRICTS — only lanes in BOTH the
/// override AND the hardware-runnable set stay `Viable`; runnable lanes the
/// operator excluded are demoted to `Unavailable` (reason `override_excluded`).
/// `force=true`: lanes in the override are FORCED to `Viable` even when the
/// probe deemed them non-viable (reason `forced_override`) — the escape hatch.
/// Mirrors the Python `apply_lane_override` semantics (restrict vs replace),
/// then recomputes `recommended` against the post-override runnable set.
pub fn apply_lane_override(
    mut viability: LaneViability,
    override_lanes: Option<&[Lane]>,
    force: bool,
) -> LaneViability {
    let Some(over) = override_lanes else {
        return viability;
    };
    let over_set: std::collections::BTreeSet<Lane> = over.iter().copied().collect();

    for &lane in &ALL_LANES {
        let in_override = over_set.contains(&lane);
        let cur = viability.support(lane);
        if force {
            if in_override {
                if !cur.is_runnable() {
                    viability.support.insert(lane, LaneSupport::Viable);
                    viability
                        .reasons
                        .insert(lane, "forced_override".to_string());
                }
            } else {
                // Forced override REPLACES the set: lanes not requested are off.
                viability.support.insert(lane, LaneSupport::Unavailable);
                viability
                    .reasons
                    .insert(lane, "override_excluded".to_string());
            }
        } else {
            // Restrict: a runnable lane the operator did not request is demoted.
            if cur.is_runnable() && !in_override {
                viability.support.insert(lane, LaneSupport::Unavailable);
                viability
                    .reasons
                    .insert(lane, "override_excluded".to_string());
            }
            // A non-runnable lane the operator requested STAYS non-runnable in
            // restrict mode (cannot conjure hardware) — keep its original reason.
        }
    }

    // Recompute recommended against the new runnable set (RVN > XMR > whatever's
    // left). Prefer the previously-recommended lane if it's still runnable.
    viability.recommended = recompute_recommended(&viability);
    if force {
        viability.notes.push("lane_override_forced".to_string());
    } else {
        viability.notes.push("lane_override_restrict".to_string());
    }
    viability
}

/// Pick the recommended lane: the prior recommendation if still runnable, else
/// RVN if runnable, else XMR if runnable, else XMR (fail-safe default).
fn recompute_recommended(v: &LaneViability) -> Lane {
    if v.is_runnable(v.recommended) {
        return v.recommended;
    }
    if v.is_runnable(Lane::GpuRvn) {
        return Lane::GpuRvn;
    }
    Lane::Xmr
}

/// The full auto-detection bundle the front-ends consume: the raw
/// [`DeviceProfile`], the (override-applied) [`LaneViability`], and the
/// `recommended_lane`. Mirrors the Python `CapabilityProfile` (minus the
/// server-side device-record / heartbeat fields, which aren't a client concern).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityProfile {
    /// The detected hardware profile.
    pub profile: DeviceProfile,
    /// The derived (override-applied) lane-viability matrix.
    pub viability: LaneViability,
}

impl CapabilityProfile {
    /// Derive the capability bundle from a detected profile, applying the
    /// `ALICE_MINER_LANES` / `ALICE_MINER_LANES_FORCE` env overrides.
    pub fn from_profile(profile: DeviceProfile) -> Self {
        let base = derive_lane_viability(&profile);
        let over = parse_lane_override(std::env::var(LANE_OVERRIDE_ENV).ok().as_deref());
        let force = std::env::var(LANE_FORCE_ENV)
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);
        let viability = apply_lane_override(base, over.as_deref(), force);
        Self { profile, viability }
    }

    /// Detect the current device + derive the bundle (the one-call entry point).
    pub fn detect() -> Self {
        Self::from_profile(DeviceProfile::detect())
    }

    /// The recommended lane for this device.
    pub fn recommended_lane(&self) -> Lane {
        self.viability.recommended
    }

    /// Support level for a lane.
    pub fn support(&self, lane: Lane) -> LaneSupport {
        self.viability.support(lane)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{GpuInfo, OsFamily};

    /// Build a synthetic profile with a given GPU, so the viability matrix can be
    /// exercised for every device class regardless of the host running the test.
    fn profile_with(os: OsFamily, apple_silicon: bool, gpu: GpuInfo) -> DeviceProfile {
        DeviceProfile {
            os,
            arch: if apple_silicon { "aarch64".into() } else { "x86_64".into() },
            apple_silicon,
            logical_cores: 8,
            cpu_model: "Test CPU".into(),
            gpu,
            memory_gb: 32,
            display: "Test CPU · 8 cores".into(),
            warnings: vec![],
        }
    }

    fn apple() -> DeviceProfile {
        profile_with(
            OsFamily::Macos,
            true,
            GpuInfo { vendor: GpuVendor::Apple, model: "Apple M2 Max".into(), vram_gb: 0 },
        )
    }

    fn nvidia() -> DeviceProfile {
        profile_with(
            OsFamily::Linux,
            false,
            GpuInfo {
                vendor: GpuVendor::Nvidia,
                model: "NVIDIA GeForce RTX 3070 Ti".into(),
                vram_gb: 8,
            },
        )
    }

    fn amd() -> DeviceProfile {
        profile_with(
            OsFamily::Linux,
            false,
            GpuInfo { vendor: GpuVendor::Amd, model: "AMD GPU".into(), vram_gb: 0 },
        )
    }

    fn cpu_only() -> DeviceProfile {
        profile_with(OsFamily::Linux, false, GpuInfo::none())
    }

    /// THE M3 VIABILITY MATRIX (the gate, test (c)): Apple → {XMR viable, RVN
    /// not}; simulated-NVIDIA → {RVN viable + recommended}.
    #[test]
    fn viability_matrix_apple_xmr_only_nvidia_rvn() {
        // Apple: XMR viable, RVN NOT runnable (Unavailable), recommended = XMR.
        let v = derive_lane_viability(&apple());
        assert_eq!(v.support(Lane::Xmr), LaneSupport::Viable);
        assert!(!v.is_runnable(Lane::GpuRvn));
        assert_eq!(v.support(Lane::GpuRvn), LaneSupport::Unavailable);
        // PRL (SRBMiner) is also unavailable on Apple (no macOS SRBMiner build).
        assert_eq!(v.support(Lane::GpuPrl), LaneSupport::Unavailable);
        assert!(!v.is_runnable(Lane::GpuPrl));
        assert_eq!(v.recommended, Lane::Xmr);
        assert_eq!(v.reason(Lane::GpuRvn), Some("rvn_requires_nvidia_apple_excluded"));

        // Simulated NVIDIA: RVN + PRL viable; XMR still viable.
        let v = derive_lane_viability(&nvidia());
        assert_eq!(v.support(Lane::Xmr), LaneSupport::Viable);
        assert_eq!(v.support(Lane::GpuRvn), LaneSupport::Viable);
        assert_eq!(v.support(Lane::GpuPrl), LaneSupport::Viable);
        assert!(v.is_runnable(Lane::GpuRvn));
        assert!(v.is_runnable(Lane::GpuPrl));
        // recommended is still RVN at T2 (PRL becomes the mainline default once PoP
        // earning is wired); runnable set = recommended-first, then ALL_LANES order.
        assert_eq!(v.recommended, Lane::GpuRvn);
        assert_eq!(
            v.runnable_lanes(),
            vec![Lane::GpuRvn, Lane::Xmr, Lane::GpuPrl]
        );
    }

    /// AMD → RVN "coming soon" (NOT runnable), XMR viable, recommended XMR.
    #[test]
    fn viability_matrix_amd_rvn_coming_soon() {
        let v = derive_lane_viability(&amd());
        assert_eq!(v.support(Lane::Xmr), LaneSupport::Viable);
        assert_eq!(v.support(Lane::GpuRvn), LaneSupport::ComingSoon);
        assert!(!v.is_runnable(Lane::GpuRvn)); // coming-soon is NOT runnable
        assert_eq!(v.recommended, Lane::Xmr);
        assert_eq!(v.reason(Lane::GpuRvn), Some("rvn_amd_coming_soon"));
        assert!(v.notes.iter().any(|n| n.contains("AMD")));
    }

    /// CPU-only / all-probes-failed → XMR viable everywhere, RVN unavailable.
    #[test]
    fn viability_matrix_cpu_only_xmr_viable_rvn_unavailable() {
        let v = derive_lane_viability(&cpu_only());
        assert_eq!(v.support(Lane::Xmr), LaneSupport::Viable);
        assert_eq!(v.support(Lane::GpuRvn), LaneSupport::Unavailable);
        assert_eq!(v.recommended, Lane::Xmr);
        assert_eq!(v.runnable_lanes(), vec![Lane::Xmr]);
    }

    #[test]
    fn parse_lane_override_aliases() {
        assert_eq!(parse_lane_override(Some("xmr")), Some(vec![Lane::Xmr]));
        assert_eq!(parse_lane_override(Some("cpu")), Some(vec![Lane::Xmr]));
        assert_eq!(parse_lane_override(Some("gpu")), Some(vec![Lane::GpuRvn]));
        assert_eq!(parse_lane_override(Some("rvn")), Some(vec![Lane::GpuRvn]));
        assert_eq!(
            parse_lane_override(Some("gpu, xmr")),
            Some(vec![Lane::GpuRvn, Lane::Xmr])
        );
        // `prl` is now the GPU-PRL mainline lane.
        assert_eq!(
            parse_lane_override(Some("prl,xmr")),
            Some(vec![Lane::GpuPrl, Lane::Xmr])
        );
        assert_eq!(parse_lane_override(Some("prl")), Some(vec![Lane::GpuPrl]));
        // Genuinely-unknown tokens are still ignored (fail-open).
        assert_eq!(parse_lane_override(Some("ltc,xmr")), Some(vec![Lane::Xmr]));
        assert_eq!(parse_lane_override(Some("ltc")), None);
        assert_eq!(parse_lane_override(Some("")), None);
        assert_eq!(parse_lane_override(None), None);
    }

    /// Restrict override: on an NVIDIA box, `ALICE_MINER_LANES=xmr` demotes the
    /// runnable RVN lane and re-points the recommendation to XMR.
    #[test]
    fn restrict_override_demotes_unrequested_runnable_lane() {
        let base = derive_lane_viability(&nvidia());
        assert_eq!(base.recommended, Lane::GpuRvn);
        let v = apply_lane_override(base, Some(&[Lane::Xmr]), false);
        assert_eq!(v.support(Lane::Xmr), LaneSupport::Viable);
        assert!(!v.is_runnable(Lane::GpuRvn));
        assert_eq!(v.recommended, Lane::Xmr);
        assert_eq!(v.reason(Lane::GpuRvn), Some("override_excluded"));
    }

    /// Restrict override CANNOT conjure hardware: forcing `gpu` on an Apple box
    /// without `force` leaves RVN non-runnable.
    #[test]
    fn restrict_override_cannot_enable_unsupported_lane() {
        let base = derive_lane_viability(&apple());
        let v = apply_lane_override(base, Some(&[Lane::GpuRvn]), false);
        assert!(!v.is_runnable(Lane::GpuRvn));
        // With RVN unavailable and XMR not in the override, recommended falls
        // back to XMR (fail-safe default).
        assert_eq!(v.recommended, Lane::Xmr);
    }

    /// Force override IS the escape hatch: `force=true` makes a non-viable lane
    /// runnable (operator-known-better path).
    #[test]
    fn force_override_enables_nonviable_lane() {
        let base = derive_lane_viability(&apple());
        let v = apply_lane_override(base, Some(&[Lane::GpuRvn]), true);
        assert!(v.is_runnable(Lane::GpuRvn));
        assert_eq!(v.reason(Lane::GpuRvn), Some("forced_override"));
        // Forced set REPLACES: XMR (not requested) is turned off.
        assert!(!v.is_runnable(Lane::Xmr));
        assert_eq!(v.recommended, Lane::GpuRvn);
    }

    #[test]
    fn capability_round_trips_through_json() {
        let cap = CapabilityProfile {
            profile: nvidia(),
            viability: derive_lane_viability(&nvidia()),
        };
        let json = serde_json::to_string(&cap).expect("serialize");
        let back: CapabilityProfile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cap, back);
    }
}
