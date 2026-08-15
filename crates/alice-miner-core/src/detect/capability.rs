//! `core/detect/capability` — the **lane-viability matrix** + the full
//! [`CapabilityProfile`] auto-detection bundle.
//!
//! Ported from the SHAPE of `hardware_probe.py`'s `LaneViability` /
//! `derive_lane_viability` / `apply_lane_override` / `CapabilityProfile`, with
//! the **deliberate Alice-Miner divergences** from the Python reference (PLAN
//! §6 D-lanes):
//!
//!   * **Three client lanes exist** — CPU→XMR, GPU→PRL (the SRBMiner `pearlhash`
//!     **mainline**, the V-decided GPU mainline, PoP-gated), and GPU→RVN (the
//!     earlier KawPoW relay path). LTC is upstream-only (not a client lane), and
//!     the AI-earn lane is later (hidden until then). So this module's universe is
//!     exactly `{Xmr, GpuPrl, GpuRvn}` — the [`crate::lane::Lane`] enum.
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
//! | device                    | XMR      | PRL (mainline)                  | RVN          |
//! |---------------------------|----------|---------------------------------|--------------|
//! | CPU only / no GPU         | Viable   | Unavailable                     | Unavailable  |
//! | NVIDIA GPU (CC ≥ 7.5)     | Viable   | **Viable**                      | ComingSoon   |
//! | NVIDIA Volta (CC 7.0)     | Viable   | Unavailable (→ Alpha)           | ComingSoon   |
//! | AMD **RDNA3 or newer**    | Viable   | **Viable** (SRBMiner)           | ComingSoon   |
//! | AMD **RDNA2** (RX 6xxx)   | Viable   | **Unavailable** (dropped ≥3.5.0)| ComingSoon   |
//! | AMD, arch unidentified    | Viable   | Viable but **never auto-picked**| ComingSoon   |
//! | Apple Silicon             | Viable   | Unavailable (no macOS SRBMiner) | Unavailable  |
//!
//! ## The AMD split, and why "unknown" is its own answer
//!
//! SRBMiner **removed AMD RDNA2 (RX 6000-series) pearlhash support upstream in
//! 3.5.0**, and v0.6.8 pins 3.5.4. The v0.6.8 release notes promise RDNA2 owners
//! that the lane "simply becomes unavailable" rather than mining wrongly. This
//! module is where that promise is kept — using the per-card PCI device ids the
//! probe now carries ([`super::DeviceProfile::amd_gpu_pci_ids`] → [`super::amd`]).
//!
//! Three inputs, three different answers:
//!
//!   * **Positively RDNA2** → [`LaneSupport::Unavailable`]. `start`, `setup` and
//!     the GUI all refuse it, `doctor` FAILs it, and every one of them prints
//!     [`PRL_REASON_AMD_RDNA2`], which names the upstream removal.
//!   * **Positively RDNA3 or newer** → [`LaneSupport::Viable`] and eligible to be
//!     the recommended one-click default, exactly as before.
//!   * **Unidentified** → [`LaneSupport::Viable`] (so `--lane prl` still works)
//!     but **never** the auto-selected `recommended` lane, with reason
//!     [`PRL_REASON_AMD_UNIDENTIFIED`] and an operator note.
//!
//! That last rule is the one judgement call here, so the reasoning, explicitly:
//! the two errors are not symmetric. **Offering** the lane to a card that cannot
//! mine reproduces the exact failure this release exists to fix, and it does so
//! *silently* — the miner sees an engine that idles. **Withholding** it from a
//! card that could mine costs real earnings — but only if it is truly withheld.
//! "Runnable but never auto-picked" withholds nothing except the default: the
//! lane stays selectable by name, so a card we failed to identify costs its owner
//! one explicit `--lane prl`, not their hashrate. Meanwhile nobody is ever
//! *routed* into an unidentified card by `--lane auto`, `setup`, or the GUI's
//! pre-selection. Making unknown mean `Unavailable` would have been the stricter
//! reading, but it would rot: the id table can only ever be complete for
//! hardware that already exists, so every future AMD card would be denied by
//! default until someone shipped a new client.
//!
//! The unidentified bucket is also, in practice, dominated by cards that
//! genuinely cannot mine this lane — every pre-RDNA2 AMD part (Polaris, Vega,
//! GCN, RDNA1), for which we hold no evidence the pinned engine works either.
//! Not auto-picking it is right for that population too.
//!
//! **CREDIT-ONLY / pure derivation.** This module reads the profile and computes
//! a lane set; it touches no reward / payout / chain surface and no key.

#![allow(dead_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::amd::AmdArch;
use super::{DeviceProfile, GpuVendor};
use crate::lane::Lane;

// ── The AMD / GPU-PRL reason tokens ──────────────────────────────────────────
//
// These are the machine-readable strings `LaneViability::reasons` carries for
// the GPU-PRL lane on an AMD box. They are `pub const` (not inline literals)
// because `recompute_recommended` matches on one of them — an inline typo there
// would silently re-promote a lane we deliberately demoted.

/// GPU-PRL on a positively-identified **RDNA2** card: SRBMiner removed
/// pearlhash support for RDNA2 upstream in 3.5.0 and v0.6.8 pins 3.5.4, so the
/// lane cannot run at all. Surfaced by `start` / `setup` / `doctor`.
pub const PRL_REASON_AMD_RDNA2: &str = "prl_amd_rdna2_removed_upstream_in_srbminer_3_5_0";
/// GPU-PRL on a positively-identified **RDNA3-or-newer** card — the only AMD
/// generation the pinned engine is documented to still support.
pub const PRL_REASON_AMD_RDNA3_PLUS: &str = "prl_amd_rdna3_or_newer_supported";
/// GPU-PRL on an AMD card whose architecture we could **not** identify. The lane
/// stays runnable (an explicit `--lane prl` works) but is never auto-selected —
/// see the module docs for why this is neither "yes" nor "no".
pub const PRL_REASON_AMD_UNIDENTIFIED: &str = "prl_amd_arch_unidentified_not_auto_selected";

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
            LaneSupport::Viable => crate::tr!("available", "可用"),
            LaneSupport::ComingSoon => crate::tr!("coming soon", "即将支持"),
            LaneSupport::Unavailable => crate::tr!("not supported", "不支持"),
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
    /// The lane the UI recommends / defaults to (the best RUNNABLE lane,
    /// GPU-PRL-first as the GPU mainline). On a device with no runnable GPU lane
    /// this is always [`Lane::Xmr`].
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
pub const ALL_LANES: [Lane; 4] = [Lane::Xmr, Lane::GpuPrl, Lane::GpuAlpha, Lane::GpuRvn];

/// Derive the lane-viability matrix from a detected [`DeviceProfile`].
///
/// Rules (PLAN §5 M3 / the brief):
///   * **XMR** = any CPU → always [`LaneSupport::Viable`] (every device has a
///     CPU; the proven RandomX lane runs everywhere).
///   * **RVN** = NVIDIA → `Viable`; AMD/Intel GPU → `ComingSoon` (detected but no
///     bundled KawPoW path yet); Apple Silicon → `Unavailable` (XMR-only);
///     no GPU / all-probes-failed → `Unavailable`.
///   * **recommended** = the best runnable lane, GPU-PRL first (the V-decided
///     GPU mainline): GpuPrl when runnable, else GpuRvn when runnable, else XMR.
pub fn derive_lane_viability(profile: &DeviceProfile) -> LaneViability {
    let mut support = BTreeMap::new();
    let mut reasons = BTreeMap::new();
    let mut notes = Vec::new();

    // ── XMR: any CPU is viable, always ──────────────────────────────────────
    support.insert(Lane::Xmr, LaneSupport::Viable);
    reasons.insert(Lane::Xmr, "cpu_always_viable".to_string());

    // ── RVN: depends on the GPU vendor ──────────────────────────────────────
    let (rvn_support, rvn_reason) = match profile.gpu.vendor {
        GpuVendor::Nvidia => {
            // RVN (KawPoW) needs a pinned kawpowminer engine, which is NOT yet bundled
            // or fetchable (the miners.json entry is an all-zero placeholder, refused by
            // binaries.rs). Advertising it Viable made the UI offer a lane that always
            // failed with "GPU miner not installed"; ComingSoon is the honest state
            // until the engine is pinned (PRL/Alpha are the live NVIDIA pearlhash lanes).
            notes.push(
                "NVIDIA GPU detected — the RVN (KawPoW) lane is coming soon; mine the \
                 PRL or Alpha pearlhash lane today."
                    .to_string(),
            );
            (LaneSupport::ComingSoon, "rvn_nvidia_coming_soon_engine_unpinned")
        }
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

    // SRBMiner (GPU-PRL) pearlhash needs CUDA compute capability ≥ 7.5 (Turing+);
    // a KNOWN Volta card (CC 7.0) CANNOT run it — those route to AlphaMiner (Alpha).
    // Unknown CC (probe missing) does NOT exclude PRL (fail-open to the vendor rule).
    const SRBMINER_CC_FLOOR_X10: u32 = 75;
    let nvidia_below_srbminer_floor = profile.gpu.vendor == GpuVendor::Nvidia
        && profile
            .gpu
            .max_compute_cap_x10
            .map(|cc| cc < SRBMINER_CC_FLOOR_X10)
            .unwrap_or(false);

    // ── PRL (SRBMiner pearlhash): NVIDIA (CC≥7.5) + AMD viable; a Volta NVIDIA card
    //    (CC<7.5) is Unavailable here (→ Alpha); Apple/none unavailable. ──────────
    let (prl_support, prl_reason) = match profile.gpu.vendor {
        GpuVendor::Nvidia if nvidia_below_srbminer_floor => {
            notes.push(
                "Volta-class NVIDIA GPU (CC 7.0) detected — SRBMiner can't mine \
                 pearlhash on it; using the AlphaMiner (Alpha) lane instead."
                    .to_string(),
            );
            (LaneSupport::Unavailable, "prl_srbminer_needs_cc_7_5_use_alpha")
        }
        GpuVendor::Nvidia => (LaneSupport::Viable, "nvidia_present"),
        // AMD splits three ways on the card's ARCHITECTURE, not just the vendor:
        // SRBMiner dropped RDNA2 pearlhash in 3.5.0 (and v0.6.8 pins 3.5.4), so a
        // vendor-only rule handed the lane — as the RECOMMENDED one — to cards
        // that cannot mine it. See the module docs for the unknown-case reasoning.
        GpuVendor::Amd => match profile.amd_arch() {
            AmdArch::Rdna3OrNewer => (LaneSupport::Viable, PRL_REASON_AMD_RDNA3_PLUS),
            AmdArch::Rdna2 => {
                notes.push(format!(
                    "{} detected (RDNA2) — SRBMiner removed RDNA2 pearlhash support \
                     upstream in 3.5.0, so the GPU-PRL lane is permanently unavailable \
                     on this card. There is no version of the client that keeps it. \
                     The CPU (XMR) lane still runs.",
                    if profile.gpu.model.is_empty() {
                        "AMD GPU".to_string()
                    } else {
                        profile.gpu.model.clone()
                    }
                ));
                (LaneSupport::Unavailable, PRL_REASON_AMD_RDNA2)
            }
            AmdArch::Unknown => {
                notes.push(
                    "AMD GPU detected but its architecture could not be identified, so \
                     GPU-PRL is NOT selected automatically. SRBMiner dropped RDNA2 \
                     (RX 6000-series) pearlhash support in 3.5.0: if this is an RX 6xxx \
                     card the lane will not mine. You can still start it explicitly with \
                     `--lane prl` if you know the card is RDNA3 or newer."
                        .to_string(),
                );
                (LaneSupport::Viable, PRL_REASON_AMD_UNIDENTIFIED)
            }
        },
        GpuVendor::Apple => (
            LaneSupport::Unavailable,
            "prl_requires_nvidia_or_amd_apple_excluded",
        ),
        GpuVendor::None => (LaneSupport::Unavailable, "prl_requires_gpu_cpu_only"),
    };
    support.insert(Lane::GpuPrl, prl_support);
    reasons.insert(Lane::GpuPrl, prl_reason.to_string());

    // ── Alpha (alpha-miner pearl/v1, V100/Volta): NVIDIA-only (alpha-miner is
    //    CUDA, backends volta/turing/ampere/ada/hopper/blackwell). This is the lane
    //    that COVERS Volta (CC 7.0), where SRBMiner/GPU-PRL cannot run. AMD/Apple/none
    //    → Unavailable. NOTE: auto-recommending it for a Volta card (vs GPU-PRL) needs
    //    compute-capability detection — a follow-up; today it is viable + selectable
    //    (`--lane alpha` / the GUI lane list), and GPU-PRL stays the auto-default. ───
    let (alpha_support, alpha_reason) = match profile.gpu.vendor {
        GpuVendor::Nvidia => (LaneSupport::Viable, "nvidia_present"),
        GpuVendor::Amd => (LaneSupport::Unavailable, "alpha_requires_nvidia_cuda"),
        GpuVendor::Apple => (LaneSupport::Unavailable, "alpha_requires_nvidia_apple_excluded"),
        GpuVendor::None => (LaneSupport::Unavailable, "alpha_requires_nvidia_cpu_only"),
    };
    support.insert(Lane::GpuAlpha, alpha_support);
    reasons.insert(Lane::GpuAlpha, alpha_reason.to_string());

    // ── recommended: GPU-PRL is the mainline (V: "GPU 主线 = PRL"). Prefer PRL
    //    when runnable (one-click default mines PRL on any GPU box), else fall
    //    back to the GPU-RVN path, else CPU-XMR. ──────────────────────────────
    let is_runnable = |lane: Lane| {
        support
            .get(&lane)
            .copied()
            .unwrap_or(LaneSupport::Unavailable)
            .is_runnable()
    };
    // GPU-PRL is runnable on an AMD card we could not identify, but it must never
    // be the lane we pick FOR the user — `--lane auto`, `setup`'s default and the
    // GUI's pre-selection all read `recommended`. See the module docs.
    let recommended = if is_runnable(Lane::GpuPrl) && prl_reason != PRL_REASON_AMD_UNIDENTIFIED {
        Lane::GpuPrl
    } else if is_runnable(Lane::GpuAlpha) {
        // GPU-PRL not runnable but Alpha is = a Volta/V100 NVIDIA box (SRBMiner can't
        // run there): AlphaMiner IS the GPU mainline for this card → one-click default.
        Lane::GpuAlpha
    } else if is_runnable(Lane::GpuRvn) {
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

    // Recompute recommended against the new runnable set (PRL > RVN > XMR).
    // Prefer the previously-recommended lane if it's still runnable.
    viability.recommended = recompute_recommended(&viability);
    if force {
        viability.notes.push("lane_override_forced".to_string());
    } else {
        viability.notes.push("lane_override_restrict".to_string());
    }
    viability
}

/// Pick the recommended lane: the prior recommendation if still runnable, else
/// GPU-PRL (the mainline) if runnable, else GPU-RVN if runnable, else XMR
/// (fail-safe default).
///
/// GPU-PRL on an **unidentified AMD card** is skipped here for the same reason
/// [`derive_lane_viability`] skips it: it is runnable but must never be chosen
/// *for* the user. The one path that can still land on it is an operator who
/// excluded every other lane by hand (`ALICE_MINER_LANES=prl`) — at which point
/// they have asked for it by name, which is exactly the bar we set.
fn recompute_recommended(v: &LaneViability) -> Lane {
    if v.is_runnable(v.recommended) {
        return v.recommended;
    }
    if prl_eligible_for_auto_default(v) {
        return Lane::GpuPrl;
    }
    if v.is_runnable(Lane::GpuRvn) {
        return Lane::GpuRvn;
    }
    if v.is_runnable(Lane::Xmr) {
        return Lane::Xmr;
    }
    // Last resort: an operator override left ONLY the unidentified-AMD GPU-PRL
    // lane runnable. They named it, so point at it rather than at a lane that is
    // not runnable either.
    if v.is_runnable(Lane::GpuPrl) {
        return Lane::GpuPrl;
    }
    Lane::Xmr
}

/// Whether GPU-PRL may be chosen as the AUTO default (`--lane auto`, `setup`'s
/// default, the GUI's pre-selection). Runnable is necessary but not sufficient:
/// on an AMD card whose architecture we could not identify the lane is runnable
/// **on request only**, never by default.
fn prl_eligible_for_auto_default(v: &LaneViability) -> bool {
    v.is_runnable(Lane::GpuPrl) && v.reason(Lane::GpuPrl) != Some(PRL_REASON_AMD_UNIDENTIFIED)
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
            amd_gpu_pci_ids: Vec::new(),
        }
    }

    fn apple() -> DeviceProfile {
        profile_with(
            OsFamily::Macos,
            true,
            GpuInfo { vendor: GpuVendor::Apple, model: "Apple M2 Max".into(), vram_gb: 0, gpus: Vec::new(), max_compute_cap_x10: None },
        )
    }

    fn nvidia() -> DeviceProfile {
        // An Ampere card (CC 8.6 → SRBMiner-capable, GPU-PRL the mainline).
        profile_with(
            OsFamily::Linux,
            false,
            GpuInfo {
                vendor: GpuVendor::Nvidia,
                model: "NVIDIA GeForce RTX 3070 Ti".into(),
                vram_gb: 8,
                gpus: Vec::new(),
                max_compute_cap_x10: Some(86),
            },
        )
    }

    fn nvidia_volta() -> DeviceProfile {
        // A Volta card (CC 7.0 → SRBMiner CANNOT run; GPU-Alpha is the path).
        profile_with(
            OsFamily::Linux,
            false,
            GpuInfo {
                vendor: GpuVendor::Nvidia,
                model: "Tesla V100-PCIE-16GB".into(),
                vram_gb: 16,
                gpus: Vec::new(),
                max_compute_cap_x10: Some(70),
            },
        )
    }

    /// An AMD box with the given PCI device ids (the input the RDNA2 split needs).
    fn amd_with_ids(model: &str, ids: &[u16]) -> DeviceProfile {
        let mut p = profile_with(
            OsFamily::Linux,
            false,
            GpuInfo {
                vendor: GpuVendor::Amd,
                model: model.into(),
                vram_gb: 0,
                gpus: Vec::new(),
                max_compute_cap_x10: None,
            },
        );
        p.amd_gpu_pci_ids = ids.to_vec();
        p
    }

    /// An RX 6800 XT — Navi 21, **RDNA2**: the card the v0.6.8 notes name.
    fn amd_rdna2() -> DeviceProfile {
        amd_with_ids("AMD Navi 21", &[0x73BF])
    }

    /// An RX 7900 XTX — Navi 31, **RDNA3**: still supported by the pinned engine.
    fn amd_rdna3() -> DeviceProfile {
        amd_with_ids("AMD Navi 31", &[0x744C])
    }

    /// An AMD card we cannot place (here: an RX 580 / Polaris 10, which the id
    /// table deliberately does not enumerate). Also the shape of an AMD box whose
    /// device ids could not be read at all.
    fn amd_unidentified() -> DeviceProfile {
        amd_with_ids("AMD GPU [1002:67df]", &[0x67DF])
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
        // PRL (SRBMiner) + Alpha (alpha-miner CUDA) are also unavailable on Apple.
        assert_eq!(v.support(Lane::GpuPrl), LaneSupport::Unavailable);
        assert!(!v.is_runnable(Lane::GpuPrl));
        assert_eq!(v.support(Lane::GpuAlpha), LaneSupport::Unavailable);
        assert!(!v.is_runnable(Lane::GpuAlpha));
        assert_eq!(v.recommended, Lane::Xmr);
        assert_eq!(v.reason(Lane::GpuRvn), Some("rvn_requires_nvidia_apple_excluded"));

        // Simulated NVIDIA: PRL + Alpha viable; RVN is ComingSoon (engine unpinned,
        // honest — not runnable); XMR still viable.
        let v = derive_lane_viability(&nvidia());
        assert_eq!(v.support(Lane::Xmr), LaneSupport::Viable);
        assert_eq!(v.support(Lane::GpuRvn), LaneSupport::ComingSoon);
        assert_eq!(v.support(Lane::GpuPrl), LaneSupport::Viable);
        assert_eq!(v.support(Lane::GpuAlpha), LaneSupport::Viable); // V100/Volta path, selectable
        assert!(!v.is_runnable(Lane::GpuRvn)); // coming-soon is NOT runnable
        assert!(v.is_runnable(Lane::GpuPrl));
        assert!(v.is_runnable(Lane::GpuAlpha));
        // GPU-PRL is the mainline default (V: "GPU 主线 = PRL") — a GPU box
        // one-click-defaults to PRL. runnable set = recommended-first, then
        // ALL_LANES order; RVN is excluded (ComingSoon, not runnable).
        assert_eq!(v.recommended, Lane::GpuPrl);
        assert_eq!(
            v.runnable_lanes(),
            vec![Lane::GpuPrl, Lane::Xmr, Lane::GpuAlpha]
        );
    }

    /// Volta/V100 (CC 7.0): SRBMiner CANNOT run → GPU-PRL Unavailable; AlphaMiner
    /// (GPU-Alpha) IS runnable and becomes the recommended one-click GPU lane.
    #[test]
    fn viability_matrix_volta_routes_prl_to_alpha() {
        let v = derive_lane_viability(&nvidia_volta());
        // GPU-PRL (SRBMiner) is excluded on Volta...
        assert_eq!(v.support(Lane::GpuPrl), LaneSupport::Unavailable);
        assert!(!v.is_runnable(Lane::GpuPrl));
        assert_eq!(v.reason(Lane::GpuPrl), Some("prl_srbminer_needs_cc_7_5_use_alpha"));
        // ...and GPU-Alpha is the runnable GPU mainline → recommended (one-click V100).
        assert_eq!(v.support(Lane::GpuAlpha), LaneSupport::Viable);
        assert!(v.is_runnable(Lane::GpuAlpha));
        assert_eq!(v.recommended, Lane::GpuAlpha);
        assert!(v.notes.iter().any(|n| n.contains("Volta")));
        // RVN is ComingSoon on NVIDIA (engine unpinned, not runnable) → excluded; the
        // runnable set is Alpha-led then XMR.
        assert_eq!(v.runnable_lanes(), vec![Lane::GpuAlpha, Lane::Xmr]);
    }

    /// AMD **RDNA3** → RVN "coming soon" (NOT runnable), PRL viable (the pinned
    /// SRBMiner still supports this generation) and the recommended GPU mainline.
    ///
    /// ASSERTION CHANGED (was `viability_matrix_amd_rvn_coming_soon`): that test
    /// built a vendor-only "AMD GPU" profile and pinned `recommended == GpuPrl`
    /// for it — i.e. it actively locked in the bug, because that same profile is
    /// what an RX 6800 produced. The AMD cases are now split by architecture; this
    /// is the half where the old expectation is still correct.
    #[test]
    fn viability_matrix_amd_rdna3_prl_viable_and_recommended() {
        let v = derive_lane_viability(&amd_rdna3());
        assert_eq!(v.support(Lane::Xmr), LaneSupport::Viable);
        assert_eq!(v.support(Lane::GpuRvn), LaneSupport::ComingSoon);
        assert!(!v.is_runnable(Lane::GpuRvn)); // coming-soon is NOT runnable
        // PRL is runnable on RDNA3+ → it's the recommended mainline lane.
        assert_eq!(v.support(Lane::GpuPrl), LaneSupport::Viable);
        assert!(v.is_runnable(Lane::GpuPrl));
        assert_eq!(v.recommended, Lane::GpuPrl);
        assert_eq!(v.reason(Lane::GpuPrl), Some(PRL_REASON_AMD_RDNA3_PLUS));
        assert_eq!(v.reason(Lane::GpuRvn), Some("rvn_amd_coming_soon"));
        assert!(v.notes.iter().any(|n| n.contains("AMD")));
        // runnable set = PRL (recommended) first, then XMR; RVN is coming-soon.
        assert_eq!(v.runnable_lanes(), vec![Lane::GpuPrl, Lane::Xmr]);
    }

    /// THE REGRESSION GATE for this fix: an **RDNA2** card (RX 6800 XT / Navi 21)
    /// must NOT be offered GPU-PRL at all. SRBMiner removed RDNA2 pearlhash
    /// support in 3.5.0 and v0.6.8 pins 3.5.4, so the lane cannot work — and the
    /// release notes promise these owners it "simply becomes unavailable".
    /// Before this fix the same device produced `Viable` + `recommended`.
    #[test]
    fn viability_matrix_amd_rdna2_prl_unavailable_and_never_recommended() {
        let v = derive_lane_viability(&amd_rdna2());
        // The lane is UNAVAILABLE — not "coming soon", which would imply it might
        // arrive. It will not.
        assert_eq!(v.support(Lane::GpuPrl), LaneSupport::Unavailable);
        assert!(!v.is_runnable(Lane::GpuPrl));
        assert_eq!(v.reason(Lane::GpuPrl), Some(PRL_REASON_AMD_RDNA2));
        // ...so it can never be recommended, and the CPU lane is what's left
        // (alpha-miner is NVIDIA-CUDA only, RVN is unpinned).
        assert_eq!(v.recommended, Lane::Xmr);
        assert_eq!(v.runnable_lanes(), vec![Lane::Xmr]);
        assert_eq!(v.support(Lane::Xmr), LaneSupport::Viable);
        // The operator-facing note names the card and says it is permanent.
        assert!(v
            .notes
            .iter()
            .any(|n| n.contains("RDNA2") && n.contains("3.5.0")));
    }

    /// A whole rig of RDNA2 cards is still RDNA2 (no card can mine), while a rig
    /// with even one RDNA3 card runs — the RDNA2 card simply cannot participate.
    #[test]
    fn viability_matrix_amd_multi_gpu_rigs() {
        let all_rdna2 = derive_lane_viability(&amd_with_ids("AMD Navi 21", &[0x73BF, 0x73BF]));
        assert_eq!(all_rdna2.support(Lane::GpuPrl), LaneSupport::Unavailable);
        assert_eq!(all_rdna2.recommended, Lane::Xmr);

        let mixed = derive_lane_viability(&amd_with_ids("AMD Navi 21 + Navi 31", &[0x73BF, 0x744C]));
        assert_eq!(mixed.support(Lane::GpuPrl), LaneSupport::Viable);
        assert_eq!(mixed.recommended, Lane::GpuPrl);
    }

    /// THE THIRD STATE: an AMD card we could not identify is treated as neither.
    /// The lane stays runnable (an explicit `--lane prl` works, so a card we
    /// simply don't know about is not stripped of its hashrate) but it is NEVER
    /// the auto-selected default — `--lane auto`, `setup` and the GUI all land on
    /// XMR, and the reason + note say why.
    #[test]
    fn viability_matrix_amd_unidentified_is_runnable_but_never_auto_selected() {
        let v = derive_lane_viability(&amd_unidentified());
        assert_eq!(v.support(Lane::GpuPrl), LaneSupport::Viable);
        assert!(v.is_runnable(Lane::GpuPrl)); // `--lane prl` still works
        assert_eq!(v.reason(Lane::GpuPrl), Some(PRL_REASON_AMD_UNIDENTIFIED));
        // ...but it is NOT what we pick for the user.
        assert_eq!(v.recommended, Lane::Xmr);
        // It is still listed as runnable (so the UI offers it), just not first.
        assert_eq!(v.runnable_lanes(), vec![Lane::Xmr, Lane::GpuPrl]);
        // And the note names RDNA2 explicitly, so this is never silent.
        assert!(v
            .notes
            .iter()
            .any(|n| n.contains("could not be identified") && n.contains("RDNA2")));
    }

    /// An AMD box whose PCI device ids could not be read at all (empty list) is
    /// the same "unknown" case — it must NOT fall back to the old vendor-only
    /// "AMD is supported" answer.
    #[test]
    fn viability_matrix_amd_with_no_readable_ids_is_unidentified_not_supported() {
        let v = derive_lane_viability(&amd_with_ids("AMD GPU", &[]));
        assert_eq!(v.reason(Lane::GpuPrl), Some(PRL_REASON_AMD_UNIDENTIFIED));
        assert_eq!(v.recommended, Lane::Xmr);
    }

    /// An operator who names the lane by hand still gets it on an unidentified
    /// card — the demotion withholds the DEFAULT, not the lane.
    #[test]
    fn unidentified_amd_prl_is_still_reachable_by_explicit_override() {
        let base = derive_lane_viability(&amd_unidentified());
        assert_eq!(base.recommended, Lane::Xmr);
        let v = apply_lane_override(base, Some(&[Lane::GpuPrl]), false);
        assert!(v.is_runnable(Lane::GpuPrl));
        assert_eq!(v.recommended, Lane::GpuPrl);
    }

    /// ...but an override that merely narrows AWAY from PRL must not accidentally
    /// re-promote it: with XMR requested, XMR stays the recommendation.
    #[test]
    fn unidentified_amd_prl_is_not_repromoted_by_an_unrelated_override() {
        let base = derive_lane_viability(&amd_unidentified());
        let v = apply_lane_override(base, Some(&[Lane::Xmr]), false);
        assert_eq!(v.recommended, Lane::Xmr);
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
    /// runnable GPU lanes (PRL/Alpha) and re-points the recommendation to XMR. (RVN is
    /// already ComingSoon/not-runnable, so it keeps its own reason, not override_excluded.)
    #[test]
    fn restrict_override_demotes_unrequested_runnable_lane() {
        let base = derive_lane_viability(&nvidia());
        assert_eq!(base.recommended, Lane::GpuPrl);
        let v = apply_lane_override(base, Some(&[Lane::Xmr]), false);
        assert_eq!(v.support(Lane::Xmr), LaneSupport::Viable);
        assert!(!v.is_runnable(Lane::GpuRvn));
        assert!(!v.is_runnable(Lane::GpuPrl));
        assert_eq!(v.recommended, Lane::Xmr);
        // GPU-PRL was runnable and the operator excluded it → override_excluded.
        assert_eq!(v.reason(Lane::GpuPrl), Some("override_excluded"));
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
