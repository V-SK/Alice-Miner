//! `core/detect/amd` — **which AMD GPU is this, really?**
//!
//! The GPU-PRL lane runs SRBMiner-MULTI. Upstream **removed AMD RDNA2 (RX 6000
//! series) pearlhash support in 3.5.0**, and v0.6.8 pins 3.5.4 — so on an RDNA2
//! card that lane cannot work at all. The v0.6.8 release notes promise those
//! owners that the lane "simply becomes unavailable" rather than silently mining
//! nothing. Keeping that promise needs something the probe never used to
//! produce: the card's **architecture**.
//!
//! This module is the pure half of that. It maps a **PCI device id** (vendor
//! `0x1002`) to an [`AmdArch`] and a codename, and summarises a whole rig's worth
//! of cards into one verdict. It performs no IO, so the *decision* is fully
//! unit-testable from a synthetic device description even though the *probe*
//! that feeds it (see [`super::probe_amd_from_drm_root`]) needs a real machine.
//!
//! ## Three states, not two
//!
//! [`AmdArch`] is deliberately three-valued:
//!
//!   * [`AmdArch::Rdna2`] — positively identified as gfx103x. SRBMiner ≥ 3.5.0
//!     dropped it; the lane must be **Unavailable**.
//!   * [`AmdArch::Rdna3OrNewer`] — positively identified as gfx11xx (RDNA3) or
//!     gfx12xx (RDNA4). This is the only AMD class our pinned engine is
//!     documented to still support, so the lane is **Viable**.
//!   * [`AmdArch::Unknown`] — vendor is AMD but the device id is not in the
//!     table (a card newer than this table, an obscure OEM SKU, or any
//!     pre-RDNA2 part: Polaris / Vega / GCN / RDNA1, which this table
//!     deliberately does **not** enumerate because we have no documentation that
//!     the pinned engine supports them either). Callers must treat this as
//!     *neither* — see [`super::capability`], which keeps the lane runnable but
//!     never lets it be the auto-selected default.
//!
//! ## Provenance of the table (read this before editing it)
//!
//! The **discrete** entries are transcribed from two authoritative sources that
//! were fetched and cross-checked, not from memory:
//!
//!   * the Linux kernel's `drivers/gpu/drm/amd/amdgpu/amdgpu_drv.c` `pciidlist[]`
//!     (`CHIP_SIENNA_CICHLID` / `CHIP_NAVY_FLOUNDER` / `CHIP_DIMGREY_CAVEFISH` /
//!     `CHIP_BEIGE_GOBY` are Navi 21/22/23/24 = RDNA2), and
//!   * the `pciutils` `pci.ids` database (which additionally names the RDNA3 /
//!     RDNA4 parts the kernel now binds via IP discovery rather than by id).
//!
//! `drivers/gpu/drm/amd/amdkfd/kfd_device.c` corroborates the generation split:
//! GC **10.3.x** is RDNA2 (10.3.0 Sienna Cichlid, 10.3.1 Van Gogh, 10.3.2 Navy
//! Flounder, 10.3.3 Yellow Carp/Rembrandt, 10.3.4 Dimgrey Cavefish, 10.3.5 Beige
//! Goby, 10.3.6 Raphael, 10.3.7 Mendocino), GC **11.x** is RDNA3 and GC **12.x**
//! is RDNA4.
//!
//! Two traps this table exists to avoid, both of which a range check gets wrong:
//!
//!   * `0x73F0` is **Navi 33 (RDNA3)** sitting in the middle of the Navi 23
//!     (RDNA2) `0x73Ex`/`0x73FF` block. Exact ids only — never ranges.
//!   * AMD *integrated* GPUs are AMD-vendor DRM devices too, so every Ryzen box
//!     with no discrete card lands here. Several of those iGPUs (Raphael,
//!     Rembrandt, Mendocino, Van Gogh) are RDNA2.
//!
//! The **integrated / APU** entries carry the same generation split, but their
//! id→codename mapping comes from vendor documentation rather than a fetched
//! table; they are marked in the table below. Getting one of those wrong can
//! only *withhold* the auto-default from a 2-CU integrated GPU that cannot
//! meaningfully mine anyway, so the blast radius is nil.
//!
//! **NOT VERIFIED AGAINST HARDWARE.** No AMD GPU of any generation was available
//! when this was written. Every id below is transcription; the classification
//! logic is unit-tested, the transcription is not.
//!
//! **CREDIT-ONLY / pure.** No IO, no reward / payout / chain surface, no key.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// AMD GPU architecture generation, to the extent we can identify it from a PCI
/// device id. See the module docs for why this is three-valued and what the
/// caller owes the `Unknown` case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AmdArch {
    /// gfx103x — Navi 21/22/23/24 and the RDNA2 APUs. **SRBMiner removed
    /// pearlhash support for these in 3.5.0**, so the GPU-PRL lane cannot run.
    Rdna2,
    /// gfx11xx (RDNA3) or gfx12xx (RDNA4) — the AMD class the pinned engine is
    /// documented to still support.
    Rdna3OrNewer,
    /// An AMD device we could not place: newer than this table, an obscure SKU,
    /// a pre-RDNA2 part, or an unreadable/absent device id.
    Unknown,
}

impl AmdArch {
    /// A short, honest label (bilingual) for the UI / CLI.
    pub fn label(self) -> &'static str {
        match self {
            AmdArch::Rdna2 => crate::tr!("RDNA2", "RDNA2"),
            AmdArch::Rdna3OrNewer => crate::tr!("RDNA3 or newer", "RDNA3 或更新"),
            AmdArch::Unknown => crate::tr!("architecture unidentified", "架构无法识别"),
        }
    }

    /// Whether this is a generation the pinned SRBMiner is documented to support
    /// for pearlhash. `Unknown` is deliberately **false** — "we don't know" is
    /// not "yes" (the caller still decides what to do with that; see
    /// [`super::capability`]).
    pub fn srbminer_pearlhash_documented(self) -> bool {
        matches!(self, AmdArch::Rdna3OrNewer)
    }
}

/// One row of the id table: PCI device id, chip codename, generation.
type Row = (u16, &'static str, AmdArch);

use AmdArch::{Rdna2, Rdna3OrNewer};

/// AMD GPU PCI device ids we can place, **sorted by id** (see
/// `table_is_sorted_and_unique`, which is the guard that keeps the binary search
/// honest). Only actual GPU functions are listed — the sibling USB-C (`0x73A4`,
/// `0x73C4`, `0x73E4`, `0x7446`) and HDMI-audio functions of the same cards are
/// deliberately absent, because they never appear as a DRM `card*` node.
///
/// `[APU]` marks the integrated parts whose generation comes from vendor
/// documentation rather than a fetched table (see the module docs).
const AMD_DEVICES: &[Row] = &[
    // ── Integrated (APU) ────────────────────────────────────────────────────
    (0x1114, "Krackan", Rdna3OrNewer),        // [APU] gfx1152
    (0x13C0, "Granite Ridge", Rdna2),         // [APU] gfx1036-class desktop iGPU
    (0x1506, "Mendocino", Rdna2),             // [APU] GC 10.3.7
    (0x150E, "Strix", Rdna3OrNewer),          // [APU] gfx1150
    (0x1586, "Strix Halo", Rdna3OrNewer),     // [APU] gfx1151
    (0x15BF, "Phoenix1", Rdna3OrNewer),       // [APU] GC 11.0.1
    (0x15C8, "Phoenix2", Rdna3OrNewer),       // [APU] GC 11.0.4
    (0x163F, "Van Gogh", Rdna2),              // [APU] GC 10.3.1 (Steam Deck)
    (0x164D, "Rembrandt", Rdna2),             // [APU] GC 10.3.3 (Yellow Carp)
    (0x164E, "Raphael", Rdna2),               // [APU] GC 10.3.6
    (0x164F, "Phoenix", Rdna3OrNewer),        // [APU] GC 11.0.1
    (0x1681, "Rembrandt", Rdna2),             // [APU] GC 10.3.3 (Radeon 680M)
    (0x1900, "HawkPoint1", Rdna3OrNewer),     // [APU] GC 11.0.1
    (0x1901, "HawkPoint2", Rdna3OrNewer),     // [APU] GC 11.0.4
    (0x1902, "Krackan2", Rdna3OrNewer),       // [APU] gfx1152
    // ── Navi 21 / Sienna Cichlid — RDNA2, gfx1030 (RX 6800/6900, PRO W6800) ──
    (0x73A0, "Navi 21", Rdna2),
    (0x73A1, "Navi 21", Rdna2),
    (0x73A2, "Navi 21", Rdna2),
    (0x73A3, "Navi 21", Rdna2),
    (0x73A5, "Navi 21", Rdna2),
    (0x73A8, "Navi 21", Rdna2),
    (0x73A9, "Navi 21", Rdna2),
    (0x73AB, "Navi 21", Rdna2),
    (0x73AC, "Navi 21", Rdna2),
    (0x73AD, "Navi 21", Rdna2),
    (0x73AE, "Navi 21", Rdna2),
    (0x73AF, "Navi 21", Rdna2),
    (0x73BF, "Navi 21", Rdna2), // RX 6800 / 6800 XT / 6900 XT
    // ── Navi 22 / Navy Flounder — RDNA2, gfx1031 (RX 6700 XT / 6750 XT) ──────
    (0x73C0, "Navi 22", Rdna2),
    (0x73C1, "Navi 22", Rdna2),
    (0x73C3, "Navi 22", Rdna2),
    (0x73CE, "Navi 22", Rdna2),
    (0x73DA, "Navi 22", Rdna2),
    (0x73DB, "Navi 22", Rdna2),
    (0x73DC, "Navi 22", Rdna2),
    (0x73DD, "Navi 22", Rdna2),
    (0x73DE, "Navi 22", Rdna2),
    (0x73DF, "Navi 22", Rdna2), // RX 6700 / 6700 XT / 6750 XT / 6800M
    // ── Navi 23 / Dimgrey Cavefish — RDNA2, gfx1032 (RX 6600 / 6650 XT) ──────
    (0x73E0, "Navi 23", Rdna2),
    (0x73E1, "Navi 23", Rdna2),
    (0x73E2, "Navi 23", Rdna2),
    (0x73E3, "Navi 23", Rdna2),
    (0x73E8, "Navi 23", Rdna2),
    (0x73E9, "Navi 23", Rdna2),
    (0x73EA, "Navi 23", Rdna2),
    (0x73EB, "Navi 23", Rdna2),
    (0x73EC, "Navi 23", Rdna2),
    (0x73ED, "Navi 23", Rdna2),
    (0x73EF, "Navi 23", Rdna2), // RX 6650 XT / 6700S / 6800S
    // THE TRAP: 0x73F0 is RDNA3, wedged between two RDNA2 ids. Ranges lie here.
    (0x73F0, "Navi 33", Rdna3OrNewer), // RX 7600M XT
    (0x73FF, "Navi 23", Rdna2),        // RX 6600 / 6600 XT / 6600M
    // ── Navi 24 / Beige Goby — RDNA2, gfx1034 (RX 6400 / 6500 XT) ────────────
    (0x7420, "Navi 24", Rdna2),
    (0x7421, "Navi 24", Rdna2),
    (0x7422, "Navi 24", Rdna2),
    (0x7423, "Navi 24", Rdna2),
    (0x7424, "Navi 24", Rdna2),
    (0x743F, "Navi 24", Rdna2), // RX 6400 / 6500 XT / 6500M
    // ── Navi 31 — RDNA3, gfx1100 (RX 7900 XT/XTX, PRO W7900) ────────────────
    (0x7448, "Navi 31", Rdna3OrNewer),
    (0x7449, "Navi 31", Rdna3OrNewer),
    (0x744A, "Navi 31", Rdna3OrNewer),
    (0x744B, "Navi 31", Rdna3OrNewer),
    (0x744C, "Navi 31", Rdna3OrNewer), // RX 7900 XT / 7900 XTX / 7900 GRE
    (0x745E, "Navi 31", Rdna3OrNewer),
    // ── Navi 32 — RDNA3, gfx1101 (RX 7700 XT / 7800 XT) ─────────────────────
    (0x7460, "Navi 32", Rdna3OrNewer),
    (0x7461, "Navi 32", Rdna3OrNewer),
    (0x7470, "Navi 32", Rdna3OrNewer),
    (0x747E, "Navi 32", Rdna3OrNewer), // RX 7700 XT / 7800 XT
    // ── Navi 33 — RDNA3, gfx1102 (RX 7600 / 7500) ───────────────────────────
    (0x7480, "Navi 33", Rdna3OrNewer), // RX 7600 / 7600 XT / PRO W7600
    (0x7481, "Navi 33", Rdna3OrNewer),
    (0x7483, "Navi 33", Rdna3OrNewer),
    (0x7487, "Navi 33", Rdna3OrNewer),
    (0x7489, "Navi 33", Rdna3OrNewer),
    (0x748B, "Navi 33", Rdna3OrNewer),
    (0x7499, "Navi 33", Rdna3OrNewer),
    (0x749F, "Navi 33", Rdna3OrNewer),
    // ── Navi 48 / Navi 44 — RDNA4, gfx120x (RX 9070 / 9060 XT) ──────────────
    (0x7550, "Navi 48", Rdna3OrNewer), // RX 9070 / 9070 XT / 9070 GRE
    (0x7551, "Navi 48", Rdna3OrNewer),
    (0x7590, "Navi 44", Rdna3OrNewer), // RX 9050 / 9060 XT
];

/// Look up one AMD PCI device id. Returns the codename + generation, or `None`
/// when the id is not in the table. Pure; binary search over [`AMD_DEVICES`].
pub fn lookup(device_id: u16) -> Option<(&'static str, AmdArch)> {
    AMD_DEVICES
        .binary_search_by_key(&device_id, |&(id, _, _)| id)
        .ok()
        .map(|i| {
            let (_, name, arch) = AMD_DEVICES[i];
            (name, arch)
        })
}

/// The generation of a single AMD PCI device id ([`AmdArch::Unknown`] when the
/// id is not in the table).
pub fn classify(device_id: u16) -> AmdArch {
    lookup(device_id).map_or(AmdArch::Unknown, |(_, arch)| arch)
}

/// The **rig-level** verdict over every AMD card the probe enumerated.
///
/// Rules, in order:
///   1. any card positively RDNA3-or-newer → [`AmdArch::Rdna3OrNewer`]. One
///      supported card is enough for the lane to run (SRBMiner is told which
///      GPUs to use, and a mixed rig's RDNA2 card simply cannot participate).
///   2. else any card positively RDNA2 → [`AmdArch::Rdna2`]. Every card we could
///      place is one the engine dropped, so the lane cannot work.
///   3. else [`AmdArch::Unknown`] — including the **empty** id list, which is
///      what an AMD box whose device ids could not be read looks like. That is
///      the fail-safe direction: unknown, never "supported".
pub fn fleet_arch(device_ids: &[u16]) -> AmdArch {
    let mut saw_rdna2 = false;
    for &id in device_ids {
        match classify(id) {
            AmdArch::Rdna3OrNewer => return AmdArch::Rdna3OrNewer,
            AmdArch::Rdna2 => saw_rdna2 = true,
            AmdArch::Unknown => {}
        }
    }
    if saw_rdna2 {
        AmdArch::Rdna2
    } else {
        AmdArch::Unknown
    }
}

/// A human model label for a set of AMD device ids, e.g.
/// `AMD Navi 21 (RDNA2)`, `AMD Navi 21 + Navi 31`, or — when nothing is
/// placeable — `AMD GPU [1002:6798]`, which at least hands a support ticket the
/// exact id we failed on instead of the useless constant `"AMD GPU"` this used
/// to return. Never empty.
pub fn model_label(device_ids: &[u16]) -> String {
    if device_ids.is_empty() {
        return "AMD GPU".to_string();
    }
    // Distinct codenames in probe order (a 2×RX 6800 rig reads "Navi 21", not
    // "Navi 21 + Navi 21").
    let mut names: Vec<&str> = Vec::new();
    let mut unplaced: Vec<u16> = Vec::new();
    for &id in device_ids {
        match lookup(id) {
            Some((name, _)) => {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
            None => {
                if !unplaced.contains(&id) {
                    unplaced.push(id);
                }
            }
        }
    }
    let mut parts: Vec<String> = names.iter().map(|n| (*n).to_string()).collect();
    parts.extend(unplaced.iter().map(|id| format!("[1002:{id:04x}]")));
    // With no codename at all the label still has to read as a GPU, not as a bare
    // id: "AMD GPU [1002:67df]", not "AMD [1002:67df]".
    let head = if names.is_empty() { "AMD GPU" } else { "AMD" };
    format!("{head} {}", parts.join(" + "))
}

/// Parse a Linux sysfs PCI id file body (`"0x1002\n"`, `"0x73bf\n"`, and
/// tolerating a bare `73bf`) into a `u16`. Pure + fail-safe: any malformed /
/// out-of-range body → `None`.
pub fn parse_pci_id_hex(raw: &str) -> Option<u16> {
    let t = raw.trim();
    let hex = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    if hex.is_empty() || hex.len() > 4 {
        return None;
    }
    u16::from_str_radix(hex, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The binary search in [`lookup`] is only correct if the table is sorted;
    /// duplicate ids would also silently shadow one another. Guard both.
    #[test]
    fn table_is_sorted_and_unique() {
        for w in AMD_DEVICES.windows(2) {
            assert!(
                w[0].0 < w[1].0,
                "AMD_DEVICES must be sorted + unique by device id: 0x{:04x} then 0x{:04x}",
                w[0].0,
                w[1].0
            );
        }
    }

    /// The headline case the v0.6.8 notes promise: an RX 6800 / 6800 XT / 6900 XT
    /// (Navi 21, 0x73BF) is positively RDNA2.
    #[test]
    fn rx_6800_is_rdna2() {
        assert_eq!(classify(0x73BF), AmdArch::Rdna2);
        assert_eq!(lookup(0x73BF).unwrap().0, "Navi 21");
        assert!(!AmdArch::Rdna2.srbminer_pearlhash_documented());
    }

    /// Every RDNA2 discrete family classifies as RDNA2 — spot-checked at the
    /// edges of each block (these are the cards the release notes name).
    #[test]
    fn every_rdna2_discrete_family_classifies_as_rdna2() {
        for id in [
            0x73A0, 0x73AF, 0x73BF, // Navi 21
            0x73C0, 0x73DF, // Navi 22
            0x73E0, 0x73EF, 0x73FF, // Navi 23
            0x7420, 0x743F, // Navi 24
        ] {
            assert_eq!(classify(id), AmdArch::Rdna2, "0x{id:04x} must be RDNA2");
        }
    }

    /// THE RANGE TRAP: 0x73F0 is Navi 33 (RDNA3) sitting between 0x73EF and
    /// 0x73FF, which are both Navi 23 (RDNA2). Any range-based classifier gets
    /// this backwards — which would deny the lane to an RX 7600M XT owner.
    #[test]
    fn navi33_id_wedged_in_the_navi23_block_is_not_rdna2() {
        assert_eq!(classify(0x73EF), AmdArch::Rdna2);
        assert_eq!(classify(0x73F0), AmdArch::Rdna3OrNewer);
        assert_eq!(classify(0x73FF), AmdArch::Rdna2);
        assert_eq!(lookup(0x73F0).unwrap().0, "Navi 33");
    }

    /// RDNA3 / RDNA4 discrete cards are positively supported.
    #[test]
    fn rdna3_and_rdna4_are_supported() {
        for id in [0x744C, 0x747E, 0x7480, 0x7550, 0x7590] {
            assert_eq!(classify(id), AmdArch::Rdna3OrNewer, "0x{id:04x}");
            assert!(classify(id).srbminer_pearlhash_documented());
        }
    }

    /// AMD **integrated** GPUs are AMD-vendor DRM devices too, so a Ryzen box
    /// with no discrete card lands in this classifier. The RDNA2 iGPUs (Raphael
    /// on Ryzen 7000 desktop, Rembrandt, Mendocino, Van Gogh) must read RDNA2 —
    /// before this table they were indistinguishable from a discrete card and
    /// got GPU-PRL recommended.
    #[test]
    fn rdna2_integrated_gpus_are_not_mistaken_for_supported_cards() {
        for id in [0x164E, 0x164D, 0x1681, 0x1506, 0x163F, 0x13C0] {
            assert_eq!(classify(id), AmdArch::Rdna2, "0x{id:04x} iGPU must be RDNA2");
        }
        // ...while the RDNA3 iGPUs are (correctly) the newer generation.
        for id in [0x15BF, 0x164F, 0x150E, 0x1586] {
            assert_eq!(classify(id), AmdArch::Rdna3OrNewer, "0x{id:04x}");
        }
    }

    /// Pre-RDNA2 parts are deliberately absent from the table, so they land in
    /// `Unknown` — NOT in "supported". RX 580 (Polaris 10, 0x67DF), Vega 64
    /// (0x687F) and RX 5700 XT (Navi 10, 0x731F) are the classic AMD mining
    /// cards; we have no documentation that the pinned engine runs pearlhash on
    /// any of them, and `Unknown` is the honest answer.
    #[test]
    fn pre_rdna2_cards_are_unknown_not_supported() {
        for id in [0x67DF, 0x687F, 0x731F, 0x7340] {
            assert_eq!(classify(id), AmdArch::Unknown, "0x{id:04x}");
            assert!(!classify(id).srbminer_pearlhash_documented());
        }
    }

    /// A device id newer than this table is `Unknown`, never "supported".
    #[test]
    fn unrecognised_id_is_unknown() {
        assert_eq!(classify(0xFFFF), AmdArch::Unknown);
        assert_eq!(classify(0x0000), AmdArch::Unknown);
        assert!(lookup(0xFFFF).is_none());
    }

    /// Rig-level rules: one supported card wins; an all-RDNA2 rig is RDNA2; an
    /// empty / unplaceable list is Unknown (the fail-safe direction).
    #[test]
    fn fleet_arch_summarises_a_whole_rig() {
        // Single cards.
        assert_eq!(fleet_arch(&[0x73BF]), AmdArch::Rdna2);
        assert_eq!(fleet_arch(&[0x744C]), AmdArch::Rdna3OrNewer);
        // All-RDNA2 rig (4× RX 6800) → RDNA2.
        assert_eq!(fleet_arch(&[0x73BF, 0x73BF, 0x73BF, 0x73BF]), AmdArch::Rdna2);
        // Mixed rig: the RDNA3 card can mine, so the lane runs.
        assert_eq!(fleet_arch(&[0x73BF, 0x744C]), AmdArch::Rdna3OrNewer);
        assert_eq!(fleet_arch(&[0x744C, 0x73BF]), AmdArch::Rdna3OrNewer);
        // Unknown alongside RDNA2 does not upgrade the verdict.
        assert_eq!(fleet_arch(&[0x73BF, 0xFFFF]), AmdArch::Rdna2);
        // Nothing placeable → Unknown, NOT supported.
        assert_eq!(fleet_arch(&[0xFFFF, 0x67DF]), AmdArch::Unknown);
        // THE EMPTY CASE: an AMD box whose ids could not be read.
        assert_eq!(fleet_arch(&[]), AmdArch::Unknown);
    }

    #[test]
    fn model_label_names_what_it_can_and_prints_the_id_it_cannot() {
        assert_eq!(model_label(&[0x73BF]), "AMD Navi 21");
        // Two identical cards collapse to one name.
        assert_eq!(model_label(&[0x73BF, 0x73BF]), "AMD Navi 21");
        assert_eq!(model_label(&[0x73BF, 0x744C]), "AMD Navi 21 + Navi 31");
        // An unplaceable id is surfaced verbatim (a support ticket can act on it)
        // instead of the old constant "AMD GPU".
        assert_eq!(model_label(&[0x67DF]), "AMD GPU [1002:67df]");
        assert_eq!(model_label(&[0x73BF, 0x67DF]), "AMD Navi 21 + [1002:67df]");
        // No ids at all → the honest generic label (never empty).
        assert_eq!(model_label(&[]), "AMD GPU");
    }

    #[test]
    fn parse_pci_id_hex_is_fail_safe() {
        assert_eq!(parse_pci_id_hex("0x1002\n"), Some(0x1002));
        assert_eq!(parse_pci_id_hex("0X73BF"), Some(0x73BF));
        assert_eq!(parse_pci_id_hex("  73bf  "), Some(0x73BF));
        assert_eq!(parse_pci_id_hex("0x0000"), Some(0));
        // Malformed / oversized / empty → None, never a panic.
        assert_eq!(parse_pci_id_hex(""), None);
        assert_eq!(parse_pci_id_hex("0x"), None);
        assert_eq!(parse_pci_id_hex("zzzz"), None);
        assert_eq!(parse_pci_id_hex("0x173bf"), None);
        assert_eq!(parse_pci_id_hex("not an id"), None);
    }
}
