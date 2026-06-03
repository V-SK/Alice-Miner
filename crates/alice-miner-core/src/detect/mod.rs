//! `core/detect` — fail-safe device detection → a [`DeviceProfile`] +
//! [`capability::CapabilityProfile`] (the M3 full-breadth probe).
//!
//! Ported from the SHAPE of
//! `Alice-Protocol/miner/mining_internal/hardware_probe.py` (`HardwareProfile` /
//! `LaneViability` / `_probe_*` / `_sysctl` / `derive_lane_viability` /
//! `apply_lane_override`). The design constraints from the Python probe are
//! honoured verbatim:
//!
//!   * **FAIL-SAFE.** Every probe is wrapped so any failure degrades to a
//!     conservative result — a probe failure must NEVER panic the miner. On
//!     macOS a failed `sysctl` falls back to an arch string; an unknown OS falls
//!     back to `std::env::consts::ARCH` + a logical-core count of at least 1;
//!     a hung/absent `nvidia-smi` (bounded by a timeout) degrades to "no GPU".
//!   * **CREDIT-ONLY / pure detection.** This module only reads hardware; it
//!     touches no reward / payout / chain surface and no key.
//!
//! On macOS the friendly model string mirrors the Python probe's
//! `_sysctl("machdep.cpu.brand_string")` (e.g. "Apple M2 Max"), falling back to
//! `hw.model` (e.g. "Mac14,6"); the assembled label adds the logical core count
//! (e.g. `Apple M2 Max · 12 cores`), per PLAN §6 (model string only, no emoji).
//!
//! M3 adds GPU-vendor detection ([`GpuVendor`] / [`GpuInfo`]) via `nvidia-smi`
//! (NVIDIA name + VRAM) — AMD is **label-only** ("detected, lane coming soon")
//! and Apple Silicon's GPU shares unified memory (so `vram_gb` stays 0). The
//! [`capability`] submodule derives the **lane-viability matrix** from the
//! profile. PRL is deliberately NOT a client lane (ruled fake-AI per MEMORY /
//! PLAN §6 D-lanes), so this Rust port omits it from the viable set entirely.

#![allow(dead_code)]

pub mod capability;

pub use capability::{CapabilityProfile, LaneSupport, LaneViability};

use std::time::Duration;

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

/// GPU vendor classification — mirrors the Python probe's
/// `GPU_VENDOR_{NVIDIA,AMD,APPLE,NONE}`. Drives the lane-viability matrix:
/// NVIDIA → RVN runnable; AMD → RVN "coming soon" (detected but not yet
/// runnable in this client); Apple → unified-memory GPU, XMR-only lane; None →
/// CPU-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuVendor {
    Nvidia,
    Amd,
    Apple,
    None,
}

impl GpuVendor {
    pub fn label(self) -> &'static str {
        match self {
            GpuVendor::Nvidia => "NVIDIA",
            GpuVendor::Amd => "AMD",
            GpuVendor::Apple => "Apple",
            GpuVendor::None => "none",
        }
    }
}

/// The detected GPU. For NVIDIA we read the model + VRAM from `nvidia-smi`; for
/// AMD we record the vendor as **label-only** (no confirmed KawPoW path bundled
/// yet, so `vram_gb` stays 0 and the lane is "coming soon"); for Apple Silicon
/// the GPU shares unified memory so `vram_gb` is 0 and the system RAM is the
/// real budget. Mirrors the relevant subset of the Python `HardwareProfile`
/// GPU fields (`gpu_vendor`, `gpu_model`, `vram_gb`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuInfo {
    /// Vendor classification.
    pub vendor: GpuVendor,
    /// Model string when a probe succeeded (e.g. `NVIDIA GeForce RTX 3070 Ti`),
    /// else empty.
    pub model: String,
    /// Dedicated GPU VRAM in whole GB (NVIDIA only; 0 for Apple/AMD/none).
    pub vram_gb: u32,
}

impl GpuInfo {
    fn none() -> Self {
        Self {
            vendor: GpuVendor::None,
            model: String::new(),
            vram_gb: 0,
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
    /// The detected GPU (vendor / model / VRAM). M3 breadth: NVIDIA via
    /// `nvidia-smi`, AMD label-only, Apple unified-memory, else none.
    pub gpu: GpuInfo,
    /// System RAM in whole GB (≥ 1 fail-safe floor; conservative
    /// [`FALLBACK_MEMORY_GB`] when every memory probe fails). Mirrors the Python
    /// `memory_gb`.
    pub memory_gb: u32,
    /// A human-friendly one-line label for the UI / CLI, e.g.
    /// `Apple M2 Max · 12 cores`. Never an emoji or vendor glyph (PLAN §6-i).
    pub display: String,
    /// Any probe that fell back (never fatal) — mirrors `probe_warnings`.
    pub warnings: Vec<String>,
}

impl DeviceProfile {
    /// Detect the current device. **Never panics** — every probe is fail-safe
    /// and degrades to a conservative result. Uses the real subprocess runner;
    /// tests use [`DeviceProfile::detect_with`] with an injected runner so they
    /// never shell out (the same INJECTABLE-probe contract as the Python probe).
    pub fn detect() -> Self {
        Self::detect_with(&RealRunner)
    }

    /// Detect using an injectable subprocess [`Runner`] (so the GPU probe can be
    /// faked in tests / `--offline-smoke`, exactly like the Python probe's
    /// injectable `SubprocessRunner`). **Never panics.**
    pub fn detect_with(runner: &dyn Runner) -> Self {
        let os = OsFamily::current();
        let arch = std::env::consts::ARCH.to_string();
        let apple_silicon = os == OsFamily::Macos && matches!(arch.as_str(), "arm64" | "aarch64");
        let logical_cores = probe_logical_cores();

        let mut warnings = Vec::new();
        let cpu_model = probe_cpu_model(os, &mut warnings);
        let gpu = probe_gpu(os, apple_silicon, &cpu_model, runner, &mut warnings);
        let memory_gb = probe_memory_gb(os, &mut warnings);
        let display = assemble_display(os, &arch, &cpu_model, logical_cores);

        DeviceProfile {
            os,
            arch,
            apple_silicon,
            logical_cores,
            cpu_model,
            gpu,
            memory_gb,
            display,
            warnings,
        }
    }

    /// The viable mining lanes for this device (the M3 lane-viability matrix).
    /// Convenience wrapper over [`capability::derive_lane_viability`].
    pub fn lane_viability(&self) -> LaneViability {
        capability::derive_lane_viability(self)
    }

    /// Full auto-detection bundle: profile + viability + recommended lane, with
    /// the `ALICE_MINER_LANES` / `ALICE_MINER_LANES_FORCE` env overrides applied.
    pub fn capability(&self) -> CapabilityProfile {
        capability::CapabilityProfile::from_profile(self.clone())
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

// ── GPU + memory probes (M3 breadth) ────────────────────────────────────────

/// A conservative default RAM assumption when every memory probe fails — the
/// same 8 GB floor the Python probe uses (`_FALLBACK_MEMORY_GB`). Safe: keeps
/// the CPU/XMR lane viable, and (correctly) gates AI below the inference floor.
pub const FALLBACK_MEMORY_GB: u32 = 8;

/// Subprocess timeout for the GPU probe (seconds). A hung `nvidia-smi` must
/// never stall detection — mirrors the Python `_NVIDIA_SMI_TIMEOUT_SECONDS`.
const GPU_PROBE_TIMEOUT_SECS: u64 = 5;

/// An injectable subprocess runner: `(program, args) -> Ok(stdout)` on a clean
/// (zero) exit, `Err(())` on any failure (absent binary / non-zero exit / hung /
/// timeout). Mirrors the Python probe's `SubprocessRunner` so the GPU probe is
/// testable without shelling out. **Fail-safe:** the unit error is deliberate —
/// callers treat any `Err` as "probe unavailable" and degrade; there is no error
/// detail to act on (so a richer error type would be noise).
#[allow(clippy::result_unit_err)]
pub trait Runner {
    fn run(&self, program: &str, args: &[&str]) -> Result<String, ()>;
}

/// The production runner: actually shells out, bounded by a timeout so a hung
/// child cannot stall startup. The timeout is enforced by spawning + polling
/// (no external `timeout(1)` dependency, which is not portable to Windows).
pub struct RealRunner;

impl Runner for RealRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<String, ()> {
        run_bounded(program, args, Duration::from_secs(GPU_PROBE_TIMEOUT_SECS))
    }
}

/// Spawn `program args`, capture stdout, and wait up to `timeout`; on timeout
/// the child is killed and we return `Err(())`. Fail-safe: ANY error (spawn
/// failure, non-zero exit, non-UTF8, timeout) → `Err(())`.
fn run_bounded(program: &str, args: &[&str], timeout: Duration) -> Result<String, ()> {
    use std::process::{Command, Stdio};
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ())?;

    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Collect stdout from the finished child.
                use std::io::Read;
                let mut out = String::new();
                if let Some(mut so) = child.stdout.take() {
                    let _ = so.read_to_string(&mut out);
                }
                return if status.success() { Ok(out) } else { Err(()) };
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return Err(()),
        }
    }
}

/// Probe the GPU vendor + (for NVIDIA) model + VRAM. **Fail-safe.**
///
/// Apple Silicon → `apple` (unified memory; VRAM reported 0, model = the chip
/// brand string). Otherwise we ask `nvidia-smi`; absent/error → we then look for
/// an AMD signal (label-only, no VRAM). Mirrors the Python `_probe_gpu`, except
/// AMD is *detected and labelled* (so the UI can say "coming soon") rather than
/// silently folded into `none`.
fn probe_gpu(
    os: OsFamily,
    apple_silicon: bool,
    cpu_model: &str,
    runner: &dyn Runner,
    warnings: &mut Vec<String>,
) -> GpuInfo {
    if apple_silicon {
        // The Apple GPU label is the chip brand (e.g. "Apple M2 Max"); fall back
        // to a generic Apple-Silicon string if the CPU model probe came up empty.
        let model = if cpu_model.is_empty() {
            format!("Apple Silicon ({})", std::env::consts::ARCH)
        } else {
            cpu_model.to_string()
        };
        return GpuInfo {
            vendor: GpuVendor::Apple,
            model,
            vram_gb: 0,
        };
    }

    // NVIDIA via nvidia-smi (the only GPU we can both detect AND run a lane on).
    if let Some(info) = probe_nvidia(runner, warnings) {
        return info;
    }

    // No NVIDIA — look for an AMD signal so the UI can say "detected · coming
    // soon" (label-only; no confirmed KawPoW path bundled for AMD yet).
    if let Some(model) = probe_amd_label(os, runner) {
        return GpuInfo {
            vendor: GpuVendor::Amd,
            model,
            vram_gb: 0,
        };
    }

    GpuInfo::none()
}

/// Query `nvidia-smi` for the first GPU's name + total memory; `None` when the
/// driver/tool is absent or output is unparseable (fail-safe). Mirrors the
/// Python `_probe_nvidia` (same query + CSV parse → whole-GB VRAM).
fn probe_nvidia(runner: &dyn Runner, warnings: &mut Vec<String>) -> Option<GpuInfo> {
    let stdout = runner
        .run(
            "nvidia-smi",
            &[
                "--query-gpu=name,memory.total",
                "--format=csv,noheader",
            ],
        )
        .ok()?;
    let first = stdout.lines().map(str::trim).find(|l| !l.is_empty())?;
    let (name, mem) = match first.split_once(',') {
        Some((n, m)) => (n.trim(), m.trim()),
        None => (first, ""),
    };
    let vram_gb = parse_mib_to_gb(mem);
    if vram_gb == 0 {
        warnings.push("nvidia_vram_parse_failed".into());
    }
    let model = if name.is_empty() {
        "NVIDIA GPU".to_string()
    } else {
        name.to_string()
    };
    Some(GpuInfo {
        vendor: GpuVendor::Nvidia,
        model,
        vram_gb,
    })
}

/// Parse an `nvidia-smi` memory cell (e.g. `"8192 MiB"`) → whole GB (rounded).
/// Mirrors the Python `_parse_mib_to_gb`.
fn parse_mib_to_gb(value: &str) -> u32 {
    let digits: String = value.chars().take_while(|c| c.is_ascii_digit()).collect();
    // The leading number may be preceded by spaces; find the first run of digits.
    let mib: u64 = if digits.is_empty() {
        value
            .split_whitespace()
            .find_map(|tok| tok.parse::<u64>().ok())
            .unwrap_or(0)
    } else {
        digits.parse().unwrap_or(0)
    };
    // nvidia-smi reports MiB; round to the nearest GB (1 GB == 1024 MiB).
    ((mib as f64) / 1024.0).round() as u32
}

/// Best-effort AMD detection (label-only). On Linux we look for an `amdgpu`
/// device via a couple of cheap, optional signals; on Windows/other we don't
/// guess (returns `None`). This NEVER enables a lane — it only lets the UI show
/// "AMD detected · lane coming soon". Fail-safe (any error → `None`).
fn probe_amd_label(os: OsFamily, _runner: &dyn Runner) -> Option<String> {
    if os != OsFamily::Linux {
        return None;
    }
    // /sys/class/drm/card*/device/vendor == 0x1002 (PCI vendor id for AMD/ATI).
    let entries = std::fs::read_dir("/sys/class/drm").ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("card") || name.contains('-') {
            continue; // skip connectors like card0-DP-1
        }
        let vendor_path = entry.path().join("device").join("vendor");
        if let Ok(v) = std::fs::read_to_string(&vendor_path) {
            if v.trim().eq_ignore_ascii_case("0x1002") {
                return Some("AMD GPU".to_string());
            }
        }
    }
    None
}

/// System RAM in whole GB. **Fail-safe** to [`FALLBACK_MEMORY_GB`]. Mirrors the
/// Python `_probe_memory` stdlib path (macOS `hw.memsize`, Linux
/// `/proc/meminfo`); on other OSes we degrade to the floor (no `psutil` dep).
fn probe_memory_gb(os: OsFamily, warnings: &mut Vec<String>) -> u32 {
    let bytes = match os {
        OsFamily::Macos => sysctl("hw.memsize").parse::<u64>().ok(),
        OsFamily::Linux => read_proc_meminfo_total_bytes(),
        _ => None,
    };
    match bytes {
        Some(b) if b > 0 => bytes_to_gb(b),
        _ => {
            warnings.push("memory_probe_fell_back".into());
            FALLBACK_MEMORY_GB
        }
    }
}

/// Whole GB from bytes (≥ 1), rounded. Mirrors the Python `_bytes_to_gb`.
fn bytes_to_gb(total_bytes: u64) -> u32 {
    let gb = ((total_bytes as f64) / (1024.0 * 1024.0 * 1024.0)).round() as u32;
    gb.max(1)
}

/// `MemTotal` (kB) from `/proc/meminfo` → bytes, or `None`. Mirrors the Python
/// `_read_proc_meminfo_total_bytes`.
fn read_proc_meminfo_total_bytes() -> Option<u64> {
    let contents = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb: String = rest
                .trim()
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(kb) = kb.parse::<u64>() {
                return Some(kb * 1024);
            }
        }
    }
    None
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

    /// A fake subprocess runner driven by a fixed `nvidia-smi` reply, so the GPU
    /// probe is exercised deterministically without a real driver (the same
    /// INJECTABLE contract the Python probe uses).
    struct FakeRunner {
        /// `Some(stdout)` → `nvidia-smi` succeeds with this output; `None` → it
        /// "fails" (absent driver), so the probe sees no NVIDIA.
        nvidia: Option<String>,
    }

    impl FakeRunner {
        fn nvidia(out: &str) -> Self {
            Self { nvidia: Some(out.to_string()) }
        }
        fn no_gpu() -> Self {
            Self { nvidia: None }
        }
    }

    impl Runner for FakeRunner {
        fn run(&self, program: &str, _args: &[&str]) -> Result<String, ()> {
            if program == "nvidia-smi" {
                self.nvidia.clone().ok_or(())
            } else {
                Err(())
            }
        }
    }

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
        // Memory is always at least the floor.
        assert!(p.memory_gb >= 1);
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
            // Apple Silicon → the GPU is classified Apple (unified memory, 0 VRAM)
            // and NEVER NVIDIA — so the RVN lane is correctly excluded here.
            assert_eq!(p.gpu.vendor, GpuVendor::Apple);
            assert_eq!(p.gpu.vram_gb, 0);
        }
        // On a real Mac the brand-string probe should succeed (no warning).
        // (We don't hard-assert the exact string — it varies per machine — but
        // a successful probe means the model field is non-empty.)
        let only_mem_warn = p.warnings.iter().all(|w| w == "memory_probe_fell_back");
        if only_mem_warn {
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

    #[test]
    fn parse_mib_to_gb_rounds_to_whole_gb() {
        assert_eq!(parse_mib_to_gb("8192 MiB"), 8);
        assert_eq!(parse_mib_to_gb("8192"), 8);
        assert_eq!(parse_mib_to_gb("12288 MiB"), 12);
        // RTX 3070 Ti reports 8192; a 24 GB card reports 24576.
        assert_eq!(parse_mib_to_gb("24576 MiB"), 24);
        // Rounds (e.g. 16376 MiB ≈ 16 GB).
        assert_eq!(parse_mib_to_gb("16376 MiB"), 16);
        // Unparseable → 0 (caller records a warning).
        assert_eq!(parse_mib_to_gb("n/a"), 0);
        assert_eq!(parse_mib_to_gb(""), 0);
    }

    #[test]
    fn probe_nvidia_parses_smi_csv_line() {
        // A simulated NVIDIA box: nvidia-smi returns one CSV row.
        let runner = FakeRunner::nvidia("NVIDIA GeForce RTX 3070 Ti, 8192 MiB\n");
        let mut warnings = Vec::new();
        let info = probe_nvidia(&runner, &mut warnings).expect("nvidia detected");
        assert_eq!(info.vendor, GpuVendor::Nvidia);
        assert_eq!(info.model, "NVIDIA GeForce RTX 3070 Ti");
        assert_eq!(info.vram_gb, 8);
        assert!(warnings.is_empty());
    }

    #[test]
    fn probe_nvidia_absent_is_none_not_panic() {
        let runner = FakeRunner::no_gpu();
        let mut warnings = Vec::new();
        assert!(probe_nvidia(&runner, &mut warnings).is_none());
    }

    #[test]
    fn probe_gpu_simulated_nvidia_on_a_linux_box() {
        // Force the non-Apple branch (apple_silicon=false) so the nvidia path runs
        // regardless of the host this test compiles on.
        let runner = FakeRunner::nvidia("NVIDIA GeForce RTX 4090, 24564 MiB\n");
        let mut warnings = Vec::new();
        let gpu = probe_gpu(OsFamily::Linux, false, "Intel Core i9", &runner, &mut warnings);
        assert_eq!(gpu.vendor, GpuVendor::Nvidia);
        assert_eq!(gpu.vram_gb, 24);
        assert!(gpu.model.contains("4090"));
    }

    #[test]
    fn probe_gpu_apple_silicon_is_apple_unified_memory() {
        // On the apple_silicon branch the runner is never consulted; the GPU is
        // Apple with 0 dedicated VRAM and the chip brand as its label.
        let runner = FakeRunner::no_gpu();
        let mut warnings = Vec::new();
        let gpu = probe_gpu(OsFamily::Macos, true, "Apple M2 Max", &runner, &mut warnings);
        assert_eq!(gpu.vendor, GpuVendor::Apple);
        assert_eq!(gpu.vram_gb, 0);
        assert_eq!(gpu.model, "Apple M2 Max");
    }

    #[test]
    fn probe_gpu_non_apple_no_nvidia_is_none() {
        // A non-Apple box with no NVIDIA and no AMD signal → none (CPU-only).
        let runner = FakeRunner::no_gpu();
        let mut warnings = Vec::new();
        // OsFamily::Windows so the AMD /sys probe (Linux-only) is skipped too.
        let gpu = probe_gpu(OsFamily::Windows, false, "AMD Ryzen 9", &runner, &mut warnings);
        assert_eq!(gpu.vendor, GpuVendor::None);
        assert_eq!(gpu.vram_gb, 0);
    }

    #[test]
    fn bytes_to_gb_rounds_and_floors_at_one() {
        assert_eq!(bytes_to_gb(16 * 1024 * 1024 * 1024), 16);
        assert_eq!(bytes_to_gb(1), 1); // floor
        assert_eq!(bytes_to_gb(0), 1); // floor (never 0)
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_memory_probe_succeeds_on_a_real_mac() {
        // On a real Mac hw.memsize should resolve to a positive GB count.
        let mut warnings = Vec::new();
        let gb = probe_memory_gb(OsFamily::Macos, &mut warnings);
        assert!(gb >= 1);
    }
}
