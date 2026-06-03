//! `core/detect` — fail-safe device detection → a [`DeviceProfile`].
//!
//! Ported from the SHAPE of
//! `Alice-Protocol/miner/mining_internal/hardware_probe.py` (`HardwareProfile` /
//! `_probe_cpu` / `_probe_cpu_model` / `_sysctl`), kept **minimal** for M1:
//! CPU + Apple-Silicon only (NVIDIA/AMD GPU breadth is M3). The two design
//! constraints from the Python probe are honoured verbatim:
//!
//!   * **FAIL-SAFE.** Every probe is wrapped so any failure degrades to a
//!     conservative result — a probe failure must NEVER panic the miner. On
//!     macOS a failed `sysctl` falls back to an arch string; an unknown OS falls
//!     back to `std::env::consts::ARCH` + a logical-core count of at least 1.
//!   * **CREDIT-ONLY / pure detection.** This module only reads hardware; it
//!     touches no reward / payout / chain surface and no key.
//!
//! On macOS the friendly model string mirrors the Python probe's
//! `_sysctl("machdep.cpu.brand_string")` (e.g. "Apple M2 Max"), falling back to
//! `hw.model` (e.g. "Mac14,6"); the assembled label adds the logical core count
//! (e.g. `Apple M2 Max · 12 cores`), per PLAN §6 (model string only, no emoji).

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// OS family, classified the same way the Python probe's `device_registry`
/// platform constants are (`macos` / `linux` / `windows` / `unknown`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsFamily {
    Macos,
    Linux,
    Windows,
    Unknown,
}

impl OsFamily {
    /// Classify the compile-time target OS (fail-safe: anything else → Unknown).
    pub fn current() -> Self {
        match std::env::consts::OS {
            "macos" => OsFamily::Macos,
            "linux" => OsFamily::Linux,
            "windows" => OsFamily::Windows,
            _ => OsFamily::Unknown,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            OsFamily::Macos => "macOS",
            OsFamily::Linux => "Linux",
            OsFamily::Windows => "Windows",
            OsFamily::Unknown => "Unknown",
        }
    }
}

/// A minimal, UI-safe device profile (CPU / Apple only for M1). Cloneable and
/// serialisable so it can cross the engine `Command`/`Event` channel and be
/// printed by the CLI. Mirrors the relevant subset of the Python
/// `HardwareProfile` (`os/arch`, `apple_silicon`, `cpu_model`, `cpu_cores`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceProfile {
    /// OS family of the running machine.
    pub os: OsFamily,
    /// CPU architecture string (`std::env::consts::ARCH`, e.g. `aarch64`).
    pub arch: String,
    /// True on Apple Silicon (macOS + arm64/aarch64) — same rule as the Python
    /// probe's `apple_silicon = plat == MACOS and arch in {arm64, aarch64}`.
    pub apple_silicon: bool,
    /// Logical (thread) core count, ≥ 1 (fail-safe floor).
    pub logical_cores: usize,
    /// Raw CPU model string if a probe succeeded (e.g. `Apple M2 Max`), else
    /// empty — exactly like the Python `cpu_model` (empty on probe failure).
    pub cpu_model: String,
    /// A human-friendly one-line label for the UI / CLI, e.g.
    /// `Apple M2 Max · 12 cores`. Never an emoji or vendor glyph (PLAN §6-i).
    pub display: String,
    /// Any probe that fell back (never fatal) — mirrors `probe_warnings`.
    pub warnings: Vec<String>,
}

impl DeviceProfile {
    /// Detect the current device. **Never panics** — every probe is fail-safe
    /// and degrades to a conservative result.
    pub fn detect() -> Self {
        let os = OsFamily::current();
        let arch = std::env::consts::ARCH.to_string();
        let apple_silicon = os == OsFamily::Macos && matches!(arch.as_str(), "arm64" | "aarch64");
        let logical_cores = probe_logical_cores();

        let mut warnings = Vec::new();
        let cpu_model = probe_cpu_model(os, &mut warnings);
        let display = assemble_display(os, &arch, &cpu_model, logical_cores);

        DeviceProfile {
            os,
            arch,
            apple_silicon,
            logical_cores,
            cpu_model,
            display,
            warnings,
        }
    }
}

/// Logical core count, ≥ 1. Mirrors the Python `_probe_cpu_cores` floor of
/// `os.cpu_count() or 1`. Uses `std::thread::available_parallelism` (the same
/// primitive `miner::miner_thread_count` uses) so the two agree.
fn probe_logical_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .max(1)
}

/// Probe the CPU model string. Fail-safe: on any failure, push a warning and
/// return empty (exactly like the Python `_probe_cpu_model`, which appends
/// `cpu_model_probe_failed` and returns `""`).
///
/// macOS  → `sysctl -n machdep.cpu.brand_string`, falling back to `hw.model`.
/// Linux  → first `model name` line of `/proc/cpuinfo`.
/// other  → empty (Windows model breadth is a later milestone).
fn probe_cpu_model(os: OsFamily, warnings: &mut Vec<String>) -> String {
    match os {
        OsFamily::Macos => {
            let brand = sysctl("machdep.cpu.brand_string");
            if !brand.is_empty() {
                return brand;
            }
            let model = sysctl("hw.model");
            if !model.is_empty() {
                return model;
            }
            warnings.push("cpu_model_probe_failed".into());
            String::new()
        }
        OsFamily::Linux => {
            let model = read_proc_cpuinfo_model();
            if model.is_empty() {
                warnings.push("cpu_model_probe_failed".into());
            }
            model
        }
        _ => String::new(),
    }
}

/// Run `sysctl -n <key>` and return its trimmed stdout, or empty on ANY error.
/// Verbatim shape of the Python `_sysctl` helper (which `check=False` and
/// swallows every exception into `""`).
fn sysctl(key: &str) -> String {
    use std::process::Command;
    Command::new("sysctl")
        .arg("-n")
        .arg(key)
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// First `model name` line of `/proc/cpuinfo`, or empty. Mirrors the Python
/// `_read_proc_cpuinfo_model`.
fn read_proc_cpuinfo_model() -> String {
    let Ok(contents) = std::fs::read_to_string("/proc/cpuinfo") else {
        return String::new();
    };
    for line in contents.lines() {
        if line.contains("model name") {
            if let Some((_, value)) = line.split_once(':') {
                let value = value.trim();
                if !value.is_empty() {
                    return value.to_string();
                }
            }
        }
    }
    String::new()
}

/// Build the friendly one-line label. Prefers the probed model (e.g.
/// `Apple M2 Max · 12 cores`); when the model is unknown, falls back to an
/// honest OS+arch string (e.g. `macOS aarch64 · 12 cores`) so the UI always has
/// something truthful to show and never an empty field. The middot separator
/// matches the PLAN's example (`Apple M2 Max · 12 cores`).
fn assemble_display(os: OsFamily, arch: &str, cpu_model: &str, cores: usize) -> String {
    let core_word = if cores == 1 { "core" } else { "cores" };
    let head = if !cpu_model.is_empty() {
        cpu_model.to_string()
    } else {
        format!("{} {}", os.label(), arch)
    };
    format!("{head} · {cores} {core_word}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_never_panics_and_has_sane_fallbacks() {
        let p = DeviceProfile::detect();
        // Core count is always at least 1 (the fail-safe floor).
        assert!(p.logical_cores >= 1);
        // Arch is the compile-time arch and non-empty.
        assert_eq!(p.arch, std::env::consts::ARCH);
        assert!(!p.arch.is_empty());
        // Display is always populated (model or OS+arch fallback) + carries the
        // core count.
        assert!(!p.display.is_empty());
        assert!(p.display.contains(&p.logical_cores.to_string()));
    }

    #[test]
    fn os_family_classifies_current_target() {
        // Whatever we compile for, `current()` agrees with the runtime check and
        // never panics.
        let os = OsFamily::current();
        match std::env::consts::OS {
            "macos" => assert_eq!(os, OsFamily::Macos),
            "linux" => assert_eq!(os, OsFamily::Linux),
            "windows" => assert_eq!(os, OsFamily::Windows),
            _ => assert_eq!(os, OsFamily::Unknown),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_reports_apple_silicon_on_arm_and_a_model() {
        let p = DeviceProfile::detect();
        assert_eq!(p.os, OsFamily::Macos);
        if matches!(p.arch.as_str(), "arm64" | "aarch64") {
            assert!(p.apple_silicon);
        }
        // On a real Mac the brand-string probe should succeed (no warning).
        // (We don't hard-assert the exact string — it varies per machine — but
        // a successful probe means the model field is non-empty.)
        if p.warnings.is_empty() {
            assert!(!p.cpu_model.is_empty());
        }
    }

    #[test]
    fn assemble_display_uses_model_then_falls_back() {
        // With a model: "<model> · N cores".
        assert_eq!(
            assemble_display(OsFamily::Macos, "aarch64", "Apple M2 Max", 12),
            "Apple M2 Max · 12 cores"
        );
        // Singular core word.
        assert_eq!(
            assemble_display(OsFamily::Linux, "x86_64", "Some CPU", 1),
            "Some CPU · 1 core"
        );
        // No model → honest OS+arch fallback, still carries the core count.
        let fallback = assemble_display(OsFamily::Unknown, "riscv64", "", 4);
        assert_eq!(fallback, "Unknown riscv64 · 4 cores");
    }

    #[test]
    fn detect_profile_round_trips_through_json() {
        // The profile must cross the engine channel + be CLI-printable.
        let p = DeviceProfile::detect();
        let json = serde_json::to_string(&p).expect("serialize");
        let back: DeviceProfile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(p, back);
    }
}
