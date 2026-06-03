//! `core/binaries` — resolve the bundled miner engine on disk.
//!
//! Generalizes `alice-wallet/gui/src/node.rs::resolve_miner_binary` over a
//! [`MinerKind`] (M1 = `CpuXmr`; `GpuRvn` is M3). Resolution order mirrors the
//! Wallet:
//!   1. an explicit `ALICE_MINER_<KIND>_BIN` env override (tests / advanced);
//!   2. a **sibling of this executable** (the packaged layout: the engine ships
//!      next to the binary — `…/MacOS/xmrig`, `…/AliceMiner/xmrig`, …);
//!   3. **dev fallback** (debug builds only): the committed asset under
//!      `release-assets/<target-triple>/<filename>` relative to this crate's
//!      `CARGO_MANIFEST_DIR`, so `cargo run`/`cargo test` works in a checkout
//!      without packaging.
//! Returns `Ok(path)` only when the file actually exists.

#![allow(dead_code)]

use std::path::PathBuf;

/// The bundled engine kinds. M1 builds only [`MinerKind::CpuXmr`]; the GPU lane
/// is declared for forward-compatibility (M3) but has no bundled binary yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinerKind {
    CpuXmr,
    GpuRvn,
}

impl MinerKind {
    /// The on-disk filename of the engine for the current OS (xmrig / xmrig.exe).
    pub fn binary_name(self) -> &'static str {
        match self {
            MinerKind::CpuXmr => XMRIG_BINARY_NAME,
            MinerKind::GpuRvn => KAWPOW_BINARY_NAME,
        }
    }

    /// The `ALICE_MINER_*_BIN` env var that overrides the resolved path.
    pub fn env_override(self) -> &'static str {
        match self {
            MinerKind::CpuXmr => "ALICE_MINER_XMR_BIN",
            MinerKind::GpuRvn => "ALICE_MINER_GPU_BIN",
        }
    }
}

#[cfg(target_os = "windows")]
pub const XMRIG_BINARY_NAME: &str = "xmrig.exe";
#[cfg(not(target_os = "windows"))]
pub const XMRIG_BINARY_NAME: &str = "xmrig";

#[cfg(target_os = "windows")]
pub const KAWPOW_BINARY_NAME: &str = "kawpowminer.exe";
#[cfg(not(target_os = "windows"))]
pub const KAWPOW_BINARY_NAME: &str = "kawpowminer";

/// The committed release-asset target-triple directory for the current build,
/// used by the dev fallback (matches the `release-assets/<triple>/` layout the
/// Wallet ships and the M1 brief specifies). Mirrors the platform strings the
/// release pipeline emits.
pub fn current_target_triple() -> &'static str {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "aarch64-apple-darwin"
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        "x86_64-apple-darwin"
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "x86_64-unknown-linux-gnu"
    } else if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        "x86_64-pc-windows-msvc"
    } else {
        // Unknown target: the dev fallback simply won't find a committed asset,
        // and resolution falls through to the explicit error.
        "unknown"
    }
}

/// Resolve the bundled engine binary for `kind`. See the module docs for the
/// resolution order. Returns `Ok(path)` only when the file exists.
pub fn resolve_miner_binary(kind: MinerKind) -> Result<PathBuf, String> {
    // 1) explicit override.
    if let Some(over) = std::env::var_os(kind.env_override()) {
        let p = PathBuf::from(over);
        return if p.is_file() {
            Ok(p)
        } else {
            Err(format!(
                "{} does not point to a file: {}",
                kind.env_override(),
                p.display()
            ))
        };
    }

    // 2) sibling of this executable (the packaged layout).
    let exe =
        std::env::current_exe().map_err(|e| format!("cannot locate miner executable: {e}"))?;
    let dir = exe
        .parent()
        .ok_or_else(|| "miner executable has no parent directory".to_string())?;
    let candidate = dir.join(kind.binary_name());
    if candidate.is_file() {
        return Ok(candidate);
    }

    // 3) dev fallback: the committed asset in the source tree (debug only), so
    //    `cargo run`/`cargo test` works before packaging.
    #[cfg(debug_assertions)]
    {
        let dev = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("release-assets")
            .join(current_target_triple())
            .join(kind.binary_name());
        if dev.is_file() {
            return Ok(dev);
        }
    }

    Err(format!(
        "miner binary not bundled (expected `{}` beside the executable at {}).",
        kind.binary_name(),
        candidate.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // `resolve_miner_binary` reads a process-global env var, so these tests must
    // not run concurrently (one setting the override would leak into another's
    // dev-fallback path). Serialize them and always clear the var on entry.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn env_override_to_existing_file_is_honored() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Point the override at a file we know exists (this test binary's own
        // path is not stable, so use a temp file).
        let tmp = std::env::temp_dir().join(format!("alice-miner-binstub-{}", std::process::id()));
        std::fs::write(&tmp, b"#!/bin/sh\n").unwrap();
        std::env::set_var(MinerKind::CpuXmr.env_override(), &tmp);
        let resolved = resolve_miner_binary(MinerKind::CpuXmr).expect("override resolves");
        assert_eq!(resolved, tmp);
        std::env::remove_var(MinerKind::CpuXmr.env_override());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn env_override_to_missing_file_errors() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(
            MinerKind::CpuXmr.env_override(),
            "/no/such/alice/miner/binary",
        );
        let err = resolve_miner_binary(MinerKind::CpuXmr).expect_err("missing override errors");
        assert!(err.contains("does not point to a file"));
        std::env::remove_var(MinerKind::CpuXmr.env_override());
    }

    #[cfg(all(debug_assertions, target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn dev_fallback_finds_committed_macos_xmrig() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // With no override and (normally) no sibling under cargo test, the dev
        // fallback should find the committed macOS arm64 xmrig asset.
        std::env::remove_var(MinerKind::CpuXmr.env_override());
        let resolved = resolve_miner_binary(MinerKind::CpuXmr).expect("dev fallback resolves");
        assert!(resolved.is_file());
        assert_eq!(resolved.file_name().unwrap(), "xmrig");
        assert!(resolved.to_string_lossy().contains("aarch64-apple-darwin"));
    }
}
