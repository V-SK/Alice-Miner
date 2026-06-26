//! `core/binaries` — resolve AND integrity-verify the bundled miner engine.
//!
//! Generalizes `alice-wallet/gui/src/node.rs::resolve_miner_binary` over a
//! [`MinerKind`] (`CpuXmr` = xmrig; `GpuRvn` = kawpowminer, M3). Resolution order
//! mirrors the Wallet:
//!   1. an explicit `ALICE_MINER_<KIND>_BIN` env override (tests / advanced;
//!      `ALICE_MINER_GPU_BIN` also selects T-Rex over the bundled kawpowminer);
//!   2. a **sibling of this executable** (the packaged layout: the engine ships
//!      next to the binary — `…/MacOS/xmrig`, `…/AliceMiner/kawpowminer`, …);
//!   3. **dev fallback** (debug builds only): the committed asset under
//!      `release-assets/<target-triple>/<filename>` relative to this crate's
//!      `CARGO_MANIFEST_DIR`, so `cargo run`/`cargo test` works in a checkout
//!      without packaging.
//!
//! Returns `Ok(path)` only when the file exists **and its SHA-256 matches the
//! pin baked into the binary from `release-assets/miners.json`** (audit MED-2/3:
//! never exec an unverified engine). The pinned-binary manifest is embedded at
//! compile time via [`MINERS_MANIFEST`], so the integrity check needs no file on
//! disk at runtime. A bundled (sibling/dev) binary whose hash doesn't match, or
//! for which no real pin exists yet (the kawpowminer placeholder), is **refused**
//! with a clear error — no exec. The `ALICE_MINER_<KIND>_BIN` override is the one
//! escape hatch and it requires an explicit `ALICE_MINER_ALLOW_UNVERIFIED_BIN=1`
//! opt-in (and logs a loud warning) — it never silently runs an unpinned binary.
//!
//! Otherwise a clear, kind-specific "not installed" / "integrity" error (the GPU
//! lane uses this to stay gracefully unavailable). **Never panics.**

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The pinned-engine manifest, embedded at compile time so the SHA-256 pins
/// travel inside the binary (no `release-assets/miners.json` needed at runtime).
/// This is the SAME file the offline packaging step reads; baking it in is what
/// turns the "SHA-pinned engine" promise from a packaging-time note into a
/// runtime guarantee (audit B-1).
const MINERS_MANIFEST: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../release-assets/miners.json"));

/// The env var that, set to `1`/`true`, permits the `ALICE_MINER_<KIND>_BIN`
/// override to run a binary whose SHA-256 is NOT pinned (or doesn't match). This
/// is an explicit, loud opt-in for advanced users supplying their own engine
/// (e.g. T-Rex); without it, an override to an unverified binary is refused.
pub const ALLOW_UNVERIFIED_ENV: &str = "ALICE_MINER_ALLOW_UNVERIFIED_BIN";

/// A single entry in `release-assets/miners.json`.
#[derive(Debug, Clone, Deserialize)]
struct MinerPin {
    kind: String,
    target: String,
    filename: String,
    sha256: String,
    #[serde(default)]
    #[serde(rename = "_placeholder")]
    placeholder: bool,
    /// Auto-download: a direct URL to the engine BINARY (e.g. a frozen xmrig).
    /// The fetched bytes are verified against `sha256` before install.
    #[serde(default)]
    binary_url: Option<String>,
    /// Auto-download (archive form): a URL to an archive (`.tar.gz` / `.zip`)
    /// containing the engine at `binary_path_in_archive`. The archive bytes are
    /// verified against `archive_sha256`, then the extracted binary against
    /// `sha256`. Used for SRBMiner-MULTI (GPU-PRL).
    #[serde(default)]
    archive_url: Option<String>,
    #[serde(default)]
    archive_sha256: Option<String>,
    #[serde(default)]
    binary_path_in_archive: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct MinersManifest {
    engines: Vec<MinerPin>,
}

/// The bundled engine kinds. [`MinerKind::CpuXmr`] = xmrig (the proven CPU lane);
/// [`MinerKind::GpuRvn`] = kawpowminer (the M3 GPU lane). The kawpowminer binary
/// is obtained at packaging (M7) — until then `resolve_miner_binary` fails
/// gracefully with a "GPU miner not installed" status (no panic).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinerKind {
    CpuXmr,
    GpuRvn,
    /// SRBMiner-MULTI on the `pearlhash` algorithm — the GPU-PRL mainline lane.
    GpuPrl,
    /// alpha-miner (pearl/v1) — the GPU-Alpha (V100/Volta) lane.
    GpuAlpha,
}

impl MinerKind {
    /// The on-disk filename of the engine for the current OS (xmrig / xmrig.exe).
    pub fn binary_name(self) -> &'static str {
        match self {
            MinerKind::CpuXmr => XMRIG_BINARY_NAME,
            MinerKind::GpuRvn => KAWPOW_BINARY_NAME,
            MinerKind::GpuPrl => SRBMINER_BINARY_NAME,
            MinerKind::GpuAlpha => ALPHA_BINARY_NAME,
        }
    }

    /// The `ALICE_MINER_*_BIN` env var that overrides the resolved path.
    pub fn env_override(self) -> &'static str {
        match self {
            MinerKind::CpuXmr => "ALICE_MINER_XMR_BIN",
            MinerKind::GpuRvn => "ALICE_MINER_GPU_BIN",
            MinerKind::GpuPrl => "ALICE_MINER_PRL_BIN",
            MinerKind::GpuAlpha => "ALICE_MINER_ALPHA_BIN",
        }
    }

    /// The `kind` string this engine carries in `release-assets/miners.json`.
    fn manifest_kind(self) -> &'static str {
        match self {
            MinerKind::CpuXmr => "cpu-xmr",
            MinerKind::GpuRvn => "gpu-rvn",
            MinerKind::GpuPrl => "gpu-prl",
            MinerKind::GpuAlpha => "gpu-alpha",
        }
    }
}

/// A non-placeholder SHA-256 pin for `kind` on the current target triple, parsed
/// from the embedded [`MINERS_MANIFEST`]. `None` when no entry matches OR the
/// entry is an all-zero placeholder (e.g. kawpowminer until M7) — i.e. "there is
/// no real pin to verify against", which the resolver treats as not-installable
/// for a bundled binary (it must not exec something it can't verify).
fn pinned_sha256_for(kind: MinerKind) -> Option<String> {
    let triple = current_target_triple();
    let manifest: MinersManifest = serde_json::from_str(MINERS_MANIFEST).ok()?;
    manifest.engines.into_iter().find_map(|e| {
        let matches = e.kind == kind.manifest_kind()
            && e.target == triple
            && e.filename == kind.binary_name();
        if !matches {
            return None;
        }
        let sha = e.sha256.trim().to_ascii_lowercase();
        // Reject the all-zero placeholder: it is NOT a usable pin.
        if e.placeholder || sha.chars().all(|c| c == '0') || sha.len() != 64 {
            None
        } else {
            Some(sha)
        }
    })
}

/// The full embedded manifest entry for `kind` on the current target triple
/// (filename-matched), or `None` if absent. Unlike [`pinned_sha256_for`], this
/// returns the WHOLE entry so the auto-download path can read the fetch URLs.
fn manifest_entry_for(kind: MinerKind) -> Option<MinerPin> {
    let triple = current_target_triple();
    let manifest: MinersManifest = serde_json::from_str(MINERS_MANIFEST).ok()?;
    manifest.engines.into_iter().find(|e| {
        e.kind == kind.manifest_kind()
            && e.target == triple
            && e.filename == kind.binary_name()
    })
}

// ────────────────────────────────────────────────────────────────────────────
// Engine auto-download (v0.3.2): a MISSING engine self-provisions into a
// per-user cache, fetched over TLS and verified against the SAME embedded
// SHA-256 pin the bundled path checks. The URL is only a CDN — the embedded
// `miners.json` is the sole trust root. Fetched bytes are ALWAYS verified before
// install; a mismatch is deleted and NEVER run (fail-closed-but-recoverable).
// ────────────────────────────────────────────────────────────────────────────

/// Generous ceiling for an engine download (binary or archive). Real engines are
/// ~5–20 MiB; this only guards against an unbounded body, the SHA pin does the
/// real integrity work.
const ENGINE_DOWNLOAD_CAP: u64 = 256 * 1024 * 1024;

/// A phase of the auto-download, for optional progress reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchPhase {
    Downloading,
    Verifying,
    Extracting,
    Installing,
}

impl FetchPhase {
    pub fn label(self) -> &'static str {
        match self {
            FetchPhase::Downloading => "Downloading",
            FetchPhase::Verifying => "Verifying",
            FetchPhase::Extracting => "Extracting",
            FetchPhase::Installing => "Installing",
        }
    }
}

/// The per-user engine cache directory for the current triple:
/// `<data_local_dir>/AliceMiner/engines/<triple>/`. This is DELIBERATELY outside
/// the `~/.alice` keystore root (asserted in tests) — a downloaded engine binary
/// must never share a directory tree with wallet secrets. Returns an error if no
/// data-local dir can be resolved (the auto-download then simply doesn't run).
pub fn engine_cache_dir() -> Result<PathBuf, String> {
    let base = dirs::data_local_dir()
        .ok_or_else(|| "no per-user data directory available for the engine cache".to_string())?;
    Ok(base.join("AliceMiner").join("engines").join(current_target_triple()))
}

/// How to obtain a missing engine, parsed from its manifest entry.
enum FetchSpec {
    /// Download a single binary directly; verify it against `sha256`.
    Direct { url: String, sha256: String },
    /// Download an archive (`.tar.gz`/`.zip`), verify it against `archive_sha256`,
    /// extract `member`, and verify the extracted binary against `sha256`.
    Archive {
        url: String,
        archive_sha256: String,
        member: String,
        binary_sha256: String,
    },
}

/// Build a [`FetchSpec`] for `kind` from the embedded manifest, or `None` if the
/// entry is a placeholder / has no real pin / has no download URL configured.
/// A direct `binary_url` wins over an `archive_url` if both are present.
fn fetch_spec_for(kind: MinerKind) -> Option<FetchSpec> {
    let pin = pinned_sha256_for(kind)?; // refuses placeholders / non-64-hex
    let e = manifest_entry_for(kind)?;
    if let Some(url) = e.binary_url.filter(|u| u.starts_with("https://")) {
        return Some(FetchSpec::Direct { url, sha256: pin });
    }
    let url = e.archive_url.filter(|u| u.starts_with("https://"))?;
    let archive_sha256 = e.archive_sha256.filter(|s| s.len() == 64)?;
    let member = e.binary_path_in_archive.filter(|m| !m.is_empty())?;
    Some(FetchSpec::Archive { url, archive_sha256, member, binary_sha256: pin })
}

/// Whether a missing `kind` COULD be auto-downloaded on this platform (a real
/// pin AND a usable fetch URL both exist). Used by capability honesty so a
/// fetchable lane is surfaced as viable even before the engine is on disk.
pub fn is_fetchable(kind: MinerKind) -> bool {
    fetch_spec_for(kind).is_some()
}

/// Ensure the engine for `kind` is present in the per-user cache and matches its
/// embedded SHA-256 pin, downloading + verifying it if absent. Returns the cached
/// path. Cache hit (already-pinned bytes on disk) does NO network. A fetched
/// binary whose hash != the pin is deleted and an error returned — never run.
///
/// SECURITY: the only trust anchor is the embedded pin (`pinned_sha256_for`). The
/// URL, the archive hash, and the member path all come from the SAME embedded
/// manifest; nothing fetched is trusted until its bytes hash to the pin.
pub fn ensure_cached_engine(kind: MinerKind) -> Result<PathBuf, String> {
    ensure_cached_engine_with_progress(kind, &mut |_phase, _done, _total| {})
}

/// As [`ensure_cached_engine`], but reports progress via `cb(phase, done, total)`
/// (`total` is `None` when unknown). Bytes are downloaded fully into memory, then
/// verified, then atomically installed — so a partial/aborted download never
/// leaves a runnable file behind.
pub fn ensure_cached_engine_with_progress(
    kind: MinerKind,
    cb: &mut dyn FnMut(FetchPhase, u64, Option<u64>),
) -> Result<PathBuf, String> {
    let dir = engine_cache_dir()?;
    let dest = dir.join(kind.binary_name());

    // Cache hit: already present AND matches the pin → no network.
    if dest.is_file() && verify_pinned(kind, &dest).is_ok() {
        return Ok(dest);
    }

    let spec = fetch_spec_for(kind).ok_or_else(|| {
        format!(
            "the {} engine is not installed and no verified download is configured \
             for this platform (the lane stays unavailable).",
            kind.binary_name()
        )
    })?;

    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("cannot create engine cache {}: {e}", dir.display()))?;

    // Fetch + verify ENTIRELY before touching the destination path.
    let verified_bytes = match spec {
        FetchSpec::Direct { url, sha256 } => {
            cb(FetchPhase::Downloading, 0, None);
            let bytes = alice_release::https_get_capped(&url, ENGINE_DOWNLOAD_CAP)?;
            cb(FetchPhase::Verifying, bytes.len() as u64, None);
            verify_bytes_sha256(&bytes, &sha256, kind.binary_name())?;
            bytes
        }
        FetchSpec::Archive { url, archive_sha256, member, binary_sha256 } => {
            cb(FetchPhase::Downloading, 0, None);
            let archive = alice_release::https_get_capped(&url, ENGINE_DOWNLOAD_CAP)?;
            cb(FetchPhase::Verifying, archive.len() as u64, None);
            verify_bytes_sha256(&archive, &archive_sha256, "engine archive")?;
            cb(FetchPhase::Extracting, 0, None);
            let bytes = extract_member(&url, &archive, &member)?;
            verify_bytes_sha256(&bytes, &binary_sha256, kind.binary_name())?;
            bytes
        }
    };

    cb(FetchPhase::Installing, verified_bytes.len() as u64, None);
    cache_install_atomic(&dir, &dest, &verified_bytes)?;

    // Final defence: re-read from disk and re-verify the pin before we hand the
    // path back (catches a truncated write / racing writer).
    verify_pinned(kind, &dest).map_err(|e| {
        let _ = std::fs::remove_file(&dest);
        format!("{e}\n(the freshly-installed engine failed re-verification; removed)")
    })?;
    Ok(dest)
}

/// Verify `bytes` hash to the expected lowercase-hex SHA-256, or a clear error
/// naming `what`. The single chokepoint that enforces "fetched == pinned".
fn verify_bytes_sha256(bytes: &[u8], expected: &str, what: &str) -> Result<(), String> {
    let got = alice_release::sha256_hex(bytes);
    if got.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(format!(
            "refusing to install {what}: downloaded SHA-256 {got} does not match the \
             pinned {expected}. The download was tampered with or corrupted; nothing \
             was written."
        ))
    }
}

/// Extract one member from an in-memory archive, dispatching on the URL suffix
/// (`.tar.gz`/`.tgz` → tar+gzip, `.zip` → zip). The member path is matched
/// exactly (the manifest pins it); we never honour an archive-supplied absolute
/// or `..` path. Returns the member's bytes.
fn extract_member(url: &str, archive: &[u8], member: &str) -> Result<Vec<u8>, String> {
    let lower = url.to_ascii_lowercase();
    if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        extract_tar_gz_member(archive, member)
    } else if lower.ends_with(".zip") {
        extract_zip_member(archive, member)
    } else {
        Err(format!("unsupported engine archive format for {url} (expected .tar.gz or .zip)"))
    }
}

fn extract_tar_gz_member(archive: &[u8], member: &str) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let gz = flate2::read::GzDecoder::new(archive);
    let mut tar = tar::Archive::new(gz);
    let entries = tar.entries().map_err(|e| format!("reading tar: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("reading tar entry: {e}"))?;
        let path = entry.path().map_err(|e| format!("tar entry path: {e}"))?;
        if path.to_string_lossy() == member {
            let mut buf = Vec::new();
            // Bound decompression so a tar bomb can't exhaust memory; a truncated
            // read just fails the binary-pin check downstream (fail-closed).
            entry
                .take(ENGINE_DOWNLOAD_CAP)
                .read_to_end(&mut buf)
                .map_err(|e| format!("extracting {member}: {e}"))?;
            return Ok(buf);
        }
    }
    Err(format!("member {member:?} not found in the .tar.gz archive"))
}

fn extract_zip_member(archive: &[u8], member: &str) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let reader = std::io::Cursor::new(archive);
    let mut zip = zip::ZipArchive::new(reader).map_err(|e| format!("reading zip: {e}"))?;
    let file = zip
        .by_name(member)
        .map_err(|e| format!("member {member:?} not found in the .zip archive: {e}"))?;
    // Defence: never trust the entry's declared path for filesystem writes — we
    // only return the bytes; the caller installs to a fixed cache path. Bound
    // decompression (see extract_tar_gz_member) so a zip bomb is truncated at the
    // cap and then fails the binary-pin check.
    let mut buf = Vec::new();
    file.take(ENGINE_DOWNLOAD_CAP)
        .read_to_end(&mut buf)
        .map_err(|e| format!("extracting {member}: {e}"))?;
    Ok(buf)
}

/// Atomically install verified engine bytes at `dest`: write to a temp file in
/// the SAME directory (so `rename` is atomic on the same filesystem), make it
/// executable, strip macOS quarantine, then rename over `dest`. A failure leaves
/// no partially-written runnable file at `dest`.
fn cache_install_atomic(dir: &Path, dest: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    // Per-call-unique temp name (pid + a monotonic counter) so concurrent installs
    // never collide.
    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);
    let base = dest.file_name().and_then(|n| n.to_str()).unwrap_or("engine");
    let tmp = dir.join(format!(
        ".{base}.partial-{}-{}",
        std::process::id(),
        TMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    // O_EXCL create (create_new): if a symlink or file is pre-planted at this path
    // (the engine cache is per-user but defence-in-depth), fail CLOSED instead of
    // following/truncating it. Audit hardening — never write through a planted link.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| format!("creating {}: {e}", tmp.display()))?;
    f.write_all(bytes).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    drop(f);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = std::fs::metadata(&tmp)
            .map_err(|e| format!("stat {}: {e}", tmp.display()))?
            .permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&tmp, perm)
            .map_err(|e| format!("chmod {}: {e}", tmp.display()))?;
    }

    // Best-effort: clear the macOS quarantine xattr so Gatekeeper doesn't block a
    // freshly-downloaded helper binary. Non-fatal if it fails.
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("/usr/bin/xattr")
            .args(["-d", "com.apple.quarantine"])
            .arg(&tmp)
            .output();
    }

    std::fs::rename(&tmp, dest).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("installing engine to {}: {e}", dest.display())
    })?;
    Ok(())
}

/// Compute the lowercase-hex SHA-256 of a file on disk (streamed via the audited
/// `alice_release::sha256_hex`). Returns an `Err` string on a read failure.
fn file_sha256(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| read_error_message(path, &e))?;
    Ok(alice_release::sha256_hex(&bytes))
}

/// A clear, actionable message for a failed engine-binary read. On Windows a read
/// that fails with `ERROR_VIRUS_INFECTED` (225) means an antivirus — almost always
/// Windows Defender — quarantined the binary as a "potentially unwanted
/// application". That is a well-known FALSE POSITIVE for mining engines (SRBMiner /
/// xmrig / kawpowminer). Surface it plainly with the exact fix, instead of the raw
/// localized OS string (which renders as mojibake on non-UTF-8 system locales).
fn read_error_message(path: &Path, e: &std::io::Error) -> String {
    // winerror.h ERROR_VIRUS_INFECTED. Only ever set on Windows; harmless elsewhere.
    const ERROR_VIRUS_INFECTED: i32 = 225;
    if e.raw_os_error() == Some(ERROR_VIRUS_INFECTED) {
        let folder = path
            .parent()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| path.display().to_string());
        return format!(
            "the mining engine {} was blocked/quarantined by antivirus. Windows Defender flags \
             mining software as a \"potentially unwanted application\" — a known false positive. \
             To mine, allow this folder in Defender: open an elevated PowerShell (Run as \
             administrator) and run\n    Add-MpPreference -ExclusionPath '{}'\nthen start mining \
             again. (You can undo it later with Remove-MpPreference -ExclusionPath.)",
            path.display(),
            folder
        );
    }
    format!("cannot read {} for integrity check: {e}", path.display())
}

/// Verify the resolved bundled binary at `path` against the pinned SHA-256 for
/// `kind`. Refuses (clear `Err`, no exec) when there is no real pin to check
/// against, or when the on-disk hash does not match the pin.
fn verify_pinned(kind: MinerKind, path: &Path) -> Result<(), String> {
    let Some(pin) = pinned_sha256_for(kind) else {
        return Err(format!(
            "refusing to run the {} engine at {}: no pinned SHA-256 is available for this \
             platform yet (the bundled binary cannot be integrity-verified). The lane stays \
             unavailable until a pinned build ships.",
            kind.binary_name(),
            path.display()
        ));
    };
    let got = file_sha256(path)?;
    if got.eq_ignore_ascii_case(&pin) {
        Ok(())
    } else {
        Err(format!(
            "refusing to run the {} engine at {}: SHA-256 integrity check FAILED \
             (got {got}, pinned {pin}). The on-disk binary does not match the signed \
             release; it may have been tampered with or replaced.",
            kind.binary_name(),
            path.display()
        ))
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

#[cfg(target_os = "windows")]
pub const SRBMINER_BINARY_NAME: &str = "SRBMiner-MULTI.exe";
#[cfg(not(target_os = "windows"))]
pub const SRBMINER_BINARY_NAME: &str = "SRBMiner-MULTI";

#[cfg(target_os = "windows")]
pub const ALPHA_BINARY_NAME: &str = "alpha-miner.exe";
#[cfg(not(target_os = "windows"))]
pub const ALPHA_BINARY_NAME: &str = "alpha-miner";

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

/// Resolve AND integrity-verify the bundled engine binary for `kind`. See the
/// module docs for the resolution order + the trust model. Returns `Ok(path)`
/// only when the file exists AND (for a bundled binary) its SHA-256 matches the
/// pin baked in from `release-assets/miners.json`; the env override is the one
/// path that may skip verification, and only behind the explicit
/// `ALICE_MINER_ALLOW_UNVERIFIED_BIN=1` opt-in (with a loud warning).
pub fn resolve_miner_binary(kind: MinerKind) -> Result<PathBuf, String> {
    // 1) explicit override. This is an advanced/test escape hatch (e.g. T-Rex),
    //    so we verify it against the pin IF one exists, and otherwise refuse —
    //    UNLESS the user has explicitly opted out of verification, in which case
    //    we run it but log a loud warning. Never silently exec an unpinned path.
    if let Some(over) = std::env::var_os(kind.env_override()) {
        let p = PathBuf::from(over);
        if !p.is_file() {
            return Err(format!(
                "{} does not point to a file: {}",
                kind.env_override(),
                p.display()
            ));
        }
        if allow_unverified() {
            eprintln!(
                "[alice-miner] WARNING: running an UNVERIFIED miner binary from {} ({}={}). \
                 Its SHA-256 is not checked against the signed release. Only do this with a \
                 binary you trust.",
                p.display(),
                ALLOW_UNVERIFIED_ENV,
                std::env::var(ALLOW_UNVERIFIED_ENV).unwrap_or_default(),
            );
            return Ok(p);
        }
        // No opt-out: the override must match a real pin, or we refuse.
        verify_pinned(kind, &p).map_err(|e| {
            format!(
                "{e}\n(the {} override binary must match the pinned SHA-256; to run an \
                 unpinned binary you trust, set {}=1.)",
                kind.env_override(),
                ALLOW_UNVERIFIED_ENV
            )
        })?;
        return Ok(p);
    }

    // 2) sibling of this executable (the packaged layout). Verified before exec.
    //    A sibling that EXISTS but fails the pin is NOT run — we fall through to
    //    the verified auto-download (the canonical pinned bytes win) instead of
    //    dead-ending, so a corrupted/drifted bundled engine self-heals.
    let exe =
        std::env::current_exe().map_err(|e| format!("cannot locate miner executable: {e}"))?;
    let dir = exe
        .parent()
        .ok_or_else(|| "miner executable has no parent directory".to_string())?;
    let candidate = dir.join(kind.binary_name());
    if candidate.is_file() {
        match verify_pinned(kind, &candidate) {
            Ok(()) => return Ok(candidate),
            Err(e) => eprintln!(
                "[alice-miner] bundled {} failed integrity ({e}); trying verified auto-download",
                kind.binary_name()
            ),
        }
    }

    // 3) dev fallback: the committed asset in the source tree (debug only), so
    //    `cargo run`/`cargo test` works before packaging. Verified before exec.
    #[cfg(debug_assertions)]
    {
        let dev = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("release-assets")
            .join(current_target_triple())
            .join(kind.binary_name());
        if dev.is_file() {
            match verify_pinned(kind, &dev) {
                Ok(()) => return Ok(dev),
                Err(e) => eprintln!(
                    "[alice-miner] dev-asset {} failed integrity ({e}); trying auto-download",
                    kind.binary_name()
                ),
            }
        }
    }

    // 4) auto-download into the per-user cache, verified against the embedded pin
    //    (the URL is just a CDN). Only engines with a real pin + a configured
    //    fetch URL are fetchable; the rest fall through to the not-installed error
    //    so a placeholder lane (kawpowminer / macOS-only xmrig) stays honest.
    if is_fetchable(kind) {
        return ensure_cached_engine(kind).map_err(|e| {
            format!("the {} engine is not installed and auto-download failed: {e}", kind.binary_name())
        });
    }

    // Graceful, kind-specific "not installed" status (NEVER a panic). The GPU
    // lane in particular ships no bundled binary on this dev machine, so the lane
    // must surface a clear, user-facing reason and stay unavailable.
    Err(match kind {
        MinerKind::CpuXmr => format!(
            "CPU miner not installed (expected `{}` beside the executable at {}).",
            kind.binary_name(),
            candidate.display()
        ),
        MinerKind::GpuRvn => format!(
            "GPU miner not installed: the KawPowMiner engine `{}` was not found \
             (set {} to a kawpowminer/T-Rex binary, or install the bundled engine). \
             The RVN lane stays unavailable.",
            kind.binary_name(),
            kind.env_override(),
        ),
        MinerKind::GpuPrl => format!(
            "GPU miner not installed: the SRBMiner-MULTI engine `{}` was not found \
             (set {} to an SRBMiner-MULTI binary, or install the bundled engine). \
             The GPU-PRL lane stays unavailable.",
            kind.binary_name(),
            kind.env_override(),
        ),
        MinerKind::GpuAlpha => format!(
            "GPU miner not installed: the AlphaMiner engine `{}` was not found \
             (set {} to an alpha-miner binary, or install the bundled engine). \
             The GPU-Alpha (V100/Volta) lane stays unavailable.",
            kind.binary_name(),
            kind.env_override(),
        ),
    })
}

/// `true` when `ALICE_MINER_ALLOW_UNVERIFIED_BIN` is set to an affirmative value
/// (`1` / `true` / `yes`, case-insensitive). Off (safe) by default.
fn allow_unverified() -> bool {
    std::env::var(ALLOW_UNVERIFIED_ENV)
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes"
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    // `resolve_miner_binary` reads process-global env vars, so these tests must
    // not run concurrently (one setting the override would leak into another's
    // dev-fallback path) — and they share the lock with the engine's dual-mine
    // test, which also sets `ALICE_MINER_*_BIN`. Serialize through the ONE
    // crate-level lock; always clear the var on entry.
    use crate::MINER_BIN_ENV_LOCK as ENV_LOCK;

    /// Clear both the kind override AND the allow-unverified gate, so a test
    /// starts from a clean, verifying-by-default environment.
    fn clear_env(kind: MinerKind) {
        std::env::remove_var(kind.env_override());
        std::env::remove_var(ALLOW_UNVERIFIED_ENV);
    }

    #[test]
    fn env_override_to_existing_file_is_honored_with_allow_gate() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env(MinerKind::CpuXmr);
        // An arbitrary stub binary won't match the pin, so the override now
        // requires the explicit allow-unverified opt-in to be honored.
        let tmp = std::env::temp_dir().join(format!("alice-miner-binstub-{}", std::process::id()));
        std::fs::write(&tmp, b"#!/bin/sh\n").unwrap();
        std::env::set_var(MinerKind::CpuXmr.env_override(), &tmp);
        std::env::set_var(ALLOW_UNVERIFIED_ENV, "1");
        let resolved = resolve_miner_binary(MinerKind::CpuXmr).expect("override resolves under opt-in");
        assert_eq!(resolved, tmp);
        clear_env(MinerKind::CpuXmr);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn env_override_to_unpinned_file_is_refused_without_allow_gate() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env(MinerKind::CpuXmr);
        // Same arbitrary stub, but WITHOUT the opt-in: it doesn't match the pin,
        // so resolution must REFUSE (no exec of an unverified binary).
        let tmp =
            std::env::temp_dir().join(format!("alice-miner-binstub-noallow-{}", std::process::id()));
        std::fs::write(&tmp, b"#!/bin/sh\n").unwrap();
        std::env::set_var(MinerKind::CpuXmr.env_override(), &tmp);
        let err = resolve_miner_binary(MinerKind::CpuXmr)
            .expect_err("unpinned override without opt-in must be refused");
        assert!(
            err.contains("integrity check FAILED") || err.contains("no pinned SHA-256"),
            "expected an integrity refusal, got: {err}"
        );
        assert!(err.contains(ALLOW_UNVERIFIED_ENV), "the error must name the opt-out knob");
        clear_env(MinerKind::CpuXmr);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn env_override_to_missing_file_errors() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env(MinerKind::CpuXmr);
        std::env::set_var(
            MinerKind::CpuXmr.env_override(),
            "/no/such/alice/miner/binary",
        );
        let err = resolve_miner_binary(MinerKind::CpuXmr).expect_err("missing override errors");
        assert!(err.contains("does not point to a file"));
        clear_env(MinerKind::CpuXmr);
    }

    #[cfg(all(debug_assertions, target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn dev_fallback_finds_and_verifies_committed_macos_xmrig() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env(MinerKind::CpuXmr);
        // With no override and no sibling under cargo test, the dev fallback finds
        // the committed macOS arm64 xmrig — and (the MED-2 fix) its SHA-256 MUST
        // match the pin in release-assets/miners.json, or this would error.
        let resolved = resolve_miner_binary(MinerKind::CpuXmr).expect("dev fallback resolves + verifies");
        assert!(resolved.is_file());
        assert_eq!(resolved.file_name().unwrap(), "xmrig");
        assert!(resolved.to_string_lossy().contains("aarch64-apple-darwin"));
        // The pin is real (non-placeholder) and matches the on-disk bytes.
        let pin = pinned_sha256_for(MinerKind::CpuXmr).expect("xmrig has a real pin");
        assert_eq!(file_sha256(&resolved).unwrap(), pin);
    }

    /// A bundled (dev-fallback) binary whose bytes have been corrupted must be
    /// REFUSED — the resolver verifies the SHA-256 before returning the path.
    #[cfg(all(debug_assertions, target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn dev_fallback_refuses_on_sha_mismatch() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env(MinerKind::CpuXmr);
        // We can't corrupt the committed asset, but we CAN prove the gate via the
        // verify helper directly on a wrong-bytes file (the same call the resolver
        // makes on the dev path).
        let tmp = std::env::temp_dir().join(format!("alice-miner-corrupt-{}", std::process::id()));
        std::fs::write(&tmp, b"NOT-the-real-xmrig").unwrap();
        let err = verify_pinned(MinerKind::CpuXmr, &tmp)
            .expect_err("a wrong-bytes binary must fail the pin check");
        assert!(err.contains("integrity check FAILED"), "got: {err}");
        let _ = std::fs::remove_file(&tmp);
    }

    /// The embedded miners.json parses, the real xmrig pin is present + non-zero,
    /// and the kawpowminer entries are (correctly) treated as no-pin placeholders.
    #[test]
    fn embedded_manifest_pins_xmrig_and_placeholders_kawpow() {
        // The CPU-XMR pin exists ONLY on the platform whose triple is in the
        // manifest (aarch64-apple-darwin); on other triples there's no entry.
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            let pin = pinned_sha256_for(MinerKind::CpuXmr).expect("xmrig pinned on this triple");
            assert_eq!(pin.len(), 64);
            assert!(!pin.chars().all(|c| c == '0'), "pin must not be all-zero");
        }
        // kawpowminer is a placeholder everywhere (no real binary yet) → no pin.
        assert!(
            pinned_sha256_for(MinerKind::GpuRvn).is_none(),
            "the kawpowminer placeholder must NOT be treated as a usable pin"
        );
    }

    /// The gpu-prl (SRBMiner-MULTI) entries are the only engines staged by a
    /// FETCH-at-packaging path (scripts/stage_gpu_prl.sh): archive_url ->
    /// archive_sha256 -> binary_path_in_archive -> sha256. Guard that BOTH the
    /// Linux and Windows entries carry a real (non-placeholder) 64-hex binary
    /// `sha256` plus a complete, well-formed fetch spec, so the packaging step
    /// can never silently ship an unverifiable PRL engine. macOS is asserted
    /// ABSENT (SRBMiner has no Apple build → GPU-PRL Unavailable).
    #[test]
    fn gpu_prl_manifest_entries_have_real_pin_and_fetch_spec() {
        let v: serde_json::Value = serde_json::from_str(MINERS_MANIFEST).unwrap();
        let engines = v["engines"].as_array().expect("engines array");
        let is_hex64 = |s: &str| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit());

        let prl: Vec<&serde_json::Value> = engines
            .iter()
            .filter(|e| e["kind"].as_str() == Some("gpu-prl"))
            .collect();
        assert_eq!(prl.len(), 2, "expected exactly 2 gpu-prl entries (linux + windows)");

        let mut targets = std::collections::BTreeSet::new();
        for e in &prl {
            let target = e["target"].as_str().expect("gpu-prl target");
            targets.insert(target.to_string());
            assert!(
                target != "aarch64-apple-darwin",
                "SRBMiner has no macOS build — gpu-prl must not list an Apple target"
            );
            // Not a placeholder, and a real 64-hex binary pin (the runtime gate).
            assert_ne!(e.get("_placeholder").and_then(|p| p.as_bool()), Some(true));
            let sha = e["sha256"].as_str().unwrap_or("");
            assert!(is_hex64(sha) && !sha.chars().all(|c| c == '0'),
                "gpu-prl {target}: sha256 must be a real 64-hex pin, got {sha:?}");
            // A complete, well-formed fetch spec for stage_gpu_prl.sh.
            let arc_sha = e["archive_sha256"].as_str().unwrap_or("");
            assert!(is_hex64(arc_sha) && !arc_sha.chars().all(|c| c == '0'),
                "gpu-prl {target}: archive_sha256 must be real 64-hex, got {arc_sha:?}");
            assert!(e["archive_url"].as_str().unwrap_or("").starts_with("https://"),
                "gpu-prl {target}: archive_url must be an https URL");
            assert!(!e["binary_path_in_archive"].as_str().unwrap_or("").is_empty(),
                "gpu-prl {target}: binary_path_in_archive must be set");
            let fname = e["filename"].as_str().unwrap_or("");
            assert!(fname == "SRBMiner-MULTI" || fname == "SRBMiner-MULTI.exe",
                "gpu-prl {target}: unexpected filename {fname:?}");
        }
        assert!(targets.contains("x86_64-unknown-linux-gnu"));
        assert!(targets.contains("x86_64-pc-windows-msvc"));
    }

    /// The GPU-Alpha (alpha-miner) entries: 2 (linux+windows), NO macOS (NVIDIA-CUDA
    /// only), each a real 64-hex pin + an https binary_url (bare binary, not archive).
    #[test]
    fn gpu_alpha_manifest_entries_have_real_pin_and_fetch_spec() {
        let v: serde_json::Value = serde_json::from_str(MINERS_MANIFEST).unwrap();
        let engines = v["engines"].as_array().expect("engines array");
        let is_hex64 = |s: &str| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit());

        let alpha: Vec<&serde_json::Value> = engines
            .iter()
            .filter(|e| e["kind"].as_str() == Some("gpu-alpha"))
            .collect();
        assert_eq!(alpha.len(), 2, "expected exactly 2 gpu-alpha entries (linux + windows)");

        let mut targets = std::collections::BTreeSet::new();
        for e in &alpha {
            let target = e["target"].as_str().expect("gpu-alpha target");
            targets.insert(target.to_string());
            assert!(
                target != "aarch64-apple-darwin",
                "alpha-miner is NVIDIA-CUDA only — gpu-alpha must not list an Apple target"
            );
            assert_ne!(e.get("_placeholder").and_then(|p| p.as_bool()), Some(true));
            let sha = e["sha256"].as_str().unwrap_or("");
            assert!(is_hex64(sha) && !sha.chars().all(|c| c == '0'),
                "gpu-alpha {target}: sha256 must be a real 64-hex pin, got {sha:?}");
            // Bare-binary fetch spec: an https binary_url (NO archive fields needed).
            assert!(e["binary_url"].as_str().unwrap_or("").starts_with("https://"),
                "gpu-alpha {target}: binary_url must be an https URL");
            let fname = e["filename"].as_str().unwrap_or("");
            assert!(fname == "alpha-miner" || fname == "alpha-miner.exe",
                "gpu-alpha {target}: unexpected filename {fname:?}");
        }
        assert!(targets.contains("x86_64-unknown-linux-gnu"));
        assert!(targets.contains("x86_64-pc-windows-msvc"));
    }

    /// The CPU-XMR (xmrig) lane must be deliverable on EVERY shipped platform so
    /// "any device one-click mines ALICE" holds: macOS arm64 BUNDLES xmrig (pin,
    /// no URL), Linux + Windows FETCH it (real pin + complete archive spec). This
    /// guards the regression where only Apple Silicon could mine (Linux/Windows
    /// had no xmrig pin → the only runnable lane never started).
    #[test]
    fn cpu_xmr_is_deliverable_on_all_shipped_platforms() {
        let v: serde_json::Value = serde_json::from_str(MINERS_MANIFEST).unwrap();
        let engines = v["engines"].as_array().expect("engines array");
        let is_hex64 = |s: &str| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit());
        let xmr: Vec<&serde_json::Value> = engines
            .iter()
            .filter(|e| e["kind"].as_str() == Some("cpu-xmr"))
            .collect();

        let mut by_target = std::collections::BTreeMap::new();
        for e in &xmr {
            let target = e["target"].as_str().expect("cpu-xmr target").to_string();
            // Every cpu-xmr entry carries a REAL (non-placeholder, non-zero) binary pin.
            assert_ne!(e.get("_placeholder").and_then(|p| p.as_bool()), Some(true));
            let sha = e["sha256"].as_str().unwrap_or("");
            assert!(is_hex64(sha) && !sha.chars().all(|c| c == '0'),
                "cpu-xmr {target}: sha256 must be a real 64-hex pin, got {sha:?}");
            by_target.insert(target, *e);
        }

        // macOS arm64: bundled (pin, NO fetch url).
        let mac = by_target.get("aarch64-apple-darwin").expect("macOS arm64 cpu-xmr present");
        assert!(mac.get("archive_url").is_none() && mac.get("binary_url").is_none(),
            "macOS xmrig is bundled, not fetched");

        // Linux + Windows: a COMPLETE fetch spec (archive_url + archive_sha256 +
        // binary_path_in_archive) so the runtime auto-download can deliver xmrig.
        for t in ["x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"] {
            let e = by_target.get(t).unwrap_or_else(|| panic!("cpu-xmr {t} must be fetchable"));
            let arc = e["archive_sha256"].as_str().unwrap_or("");
            assert!(is_hex64(arc) && !arc.chars().all(|c| c == '0'),
                "cpu-xmr {t}: archive_sha256 must be real 64-hex, got {arc:?}");
            assert!(e["archive_url"].as_str().unwrap_or("").starts_with("https://"),
                "cpu-xmr {t}: archive_url must be https");
            assert!(!e["binary_path_in_archive"].as_str().unwrap_or("").is_empty(),
                "cpu-xmr {t}: binary_path_in_archive must be set");
            let fname = e["filename"].as_str().unwrap_or("");
            assert!(fname == "xmrig" || fname == "xmrig.exe",
                "cpu-xmr {t}: unexpected filename {fname:?}");
        }
    }

    #[test]
    fn gpu_kind_has_distinct_binary_name_and_override() {
        // kawpowminer (not xmrig) + its own env override.
        assert_eq!(MinerKind::GpuRvn.binary_name(), KAWPOW_BINARY_NAME);
        assert!(MinerKind::GpuRvn.binary_name().starts_with("kawpowminer"));
        assert_eq!(MinerKind::GpuRvn.env_override(), "ALICE_MINER_GPU_BIN");
        assert_ne!(MinerKind::GpuRvn.binary_name(), MinerKind::CpuXmr.binary_name());
    }

    #[test]
    fn gpu_resolution_without_binary_fails_gracefully_not_panic() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // No override, and no bundled kawpowminer on this dev machine (none is
        // committed) → a clear "GPU miner not installed" error, NOT a panic.
        clear_env(MinerKind::GpuRvn);
        let err = resolve_miner_binary(MinerKind::GpuRvn).expect_err("no GPU binary on this box");
        assert!(
            err.contains("GPU miner not installed"),
            "expected a clear GPU-not-installed status, got: {err}"
        );
        // The message tells the user the override knob + that the lane stays off.
        assert!(err.contains("ALICE_MINER_GPU_BIN"));
        assert!(err.contains("unavailable"));
    }

    #[test]
    fn gpu_env_override_to_existing_file_is_honored_under_opt_in() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env(MinerKind::GpuRvn);
        // A user-supplied kawpowminer / T-Rex has no bundled pin, so the override
        // is honored only with the explicit allow-unverified opt-in (loud warn).
        let tmp =
            std::env::temp_dir().join(format!("alice-miner-gpustub-{}", std::process::id()));
        std::fs::write(&tmp, b"#!/bin/sh\n").unwrap();
        std::env::set_var(MinerKind::GpuRvn.env_override(), &tmp);
        std::env::set_var(ALLOW_UNVERIFIED_ENV, "1");
        let resolved = resolve_miner_binary(MinerKind::GpuRvn).expect("override resolves under opt-in");
        assert_eq!(resolved, tmp);
        clear_env(MinerKind::GpuRvn);
        let _ = std::fs::remove_file(&tmp);
    }

    // ── Auto-download (v0.3.2) ──────────────────────────────────────────────

    /// The engine cache dir is under the per-user data dir and DELIBERATELY NOT
    /// under the `~/.alice` keystore root — a downloaded engine must never share a
    /// tree with wallet secrets.
    #[test]
    fn engine_cache_dir_is_outside_keystore_root() {
        let dir = engine_cache_dir().expect("a data dir exists in test env");
        let s = dir.to_string_lossy();
        assert!(s.contains("AliceMiner"), "cache under an AliceMiner dir: {s}");
        assert!(s.contains(current_target_triple()), "cache is per-triple: {s}");
        // Must not be inside the keystore root.
        if let Some(home) = dirs::home_dir() {
            let keystore = home.join(".alice");
            assert!(!dir.starts_with(&keystore), "engine cache must not live under {}", keystore.display());
        }
    }

    /// The verify chokepoint accepts matching bytes and refuses any mismatch —
    /// this is the "fetched == pinned" gate the whole auto-download trusts.
    #[test]
    fn verify_bytes_sha256_accepts_match_refuses_mismatch() {
        let bytes = b"the real engine bytes";
        let good = alice_release::sha256_hex(bytes);
        assert!(verify_bytes_sha256(bytes, &good, "engine").is_ok());
        let bad = "0".repeat(64);
        let err = verify_bytes_sha256(bytes, &bad, "engine").expect_err("mismatch must refuse");
        assert!(err.contains("does not match the pinned"), "got: {err}");
        assert!(err.contains("nothing"), "must promise no write: {err}");
    }

    fn make_tar_gz(member: &str, content: &[u8]) -> Vec<u8> {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        {
            let mut b = tar::Builder::new(&mut gz);
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            b.append_data(&mut header, member, content).unwrap();
            b.finish().unwrap();
        }
        gz.finish().unwrap()
    }

    fn make_zip(member: &str, content: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut zw = zip::ZipWriter::new(&mut buf);
            let opts: zip::write::FileOptions<()> =
                zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            zw.start_file(member, opts).unwrap();
            zw.write_all(content).unwrap();
            zw.finish().unwrap();
        }
        buf.into_inner()
    }

    /// A `.tar.gz` member round-trips through the extractor; a missing member is a
    /// clear error (not a silent empty file).
    #[test]
    fn tar_gz_member_extracts_and_missing_errors() {
        let content = b"#!/bin/sh\necho SRBMiner\n";
        let arc = make_tar_gz("SRBMiner-Multi-3-4-1/SRBMiner-MULTI", content);
        let got = extract_member(
            "https://x/SRBMiner.tar.gz",
            &arc,
            "SRBMiner-Multi-3-4-1/SRBMiner-MULTI",
        )
        .expect("member extracts");
        assert_eq!(got, content);
        let err = extract_member("https://x/SRBMiner.tar.gz", &arc, "not/here")
            .expect_err("missing member errors");
        assert!(err.contains("not found"), "got: {err}");
    }

    /// A `.zip` member round-trips; the format is chosen by URL suffix.
    #[test]
    fn zip_member_extracts_by_url_suffix() {
        let content = b"MZ\x90\x00 fake exe bytes";
        let arc = make_zip("SRBMiner-Multi-3-4-1/SRBMiner-MULTI.exe", content);
        let got = extract_member(
            "https://x/SRBMiner-win64.zip",
            &arc,
            "SRBMiner-Multi-3-4-1/SRBMiner-MULTI.exe",
        )
        .expect("zip member extracts");
        assert_eq!(got, content);
        // An unknown suffix is refused, not guessed.
        let err = extract_member("https://x/engine.7z", &arc, "x").expect_err("unknown format refused");
        assert!(err.contains("unsupported"), "got: {err}");
    }

    /// `cache_install_atomic` writes the bytes, makes the file executable, and the
    /// install is observable at the destination (atomic rename).
    #[test]
    fn cache_install_atomic_writes_executable() {
        let dir = std::env::temp_dir().join(format!("alice-eng-inst-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("xmrig");
        let bytes = b"engine payload";
        cache_install_atomic(&dir, &dest, bytes).expect("install");
        assert_eq!(std::fs::read(&dest).unwrap(), bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dest).unwrap().permissions().mode();
            assert!(mode & 0o111 != 0, "installed engine must be executable, mode={mode:o}");
        }
        // No leftover .partial temp.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("partial"))
            .collect();
        assert!(leftovers.is_empty(), "no .partial temp must remain");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// On macOS-arm64 the committed xmrig matches the cpu-xmr pin, so pre-placing
    /// it in the cache makes `ensure_cached_engine` a CACHE HIT — it returns the
    /// path with NO network. Proves the cache-reuse path + the pin re-check.
    #[cfg(all(debug_assertions, target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn ensure_cached_engine_is_a_cache_hit_when_pinned_bytes_present() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env(MinerKind::CpuXmr);
        // The committed dev xmrig == the pin. Place a copy in the real cache dir.
        let dev = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../release-assets")
            .join(current_target_triple())
            .join("xmrig");
        let cache = engine_cache_dir().unwrap();
        std::fs::create_dir_all(&cache).unwrap();
        let dest = cache.join("xmrig");
        std::fs::copy(&dev, &dest).unwrap();
        // Cache hit: returns the cached path, verified against the pin, no fetch.
        let got = ensure_cached_engine(MinerKind::CpuXmr).expect("cache hit");
        assert_eq!(got, dest);
        let _ = std::fs::remove_file(&dest);
    }

    /// A non-placeholder gpu-prl entry yields an Archive fetch spec on the triples
    /// that carry one (linux/windows). On the dev mac there's no gpu-prl entry, so
    /// it's correctly NOT fetchable — assert the platform-appropriate result.
    #[test]
    fn gpu_prl_fetch_spec_matches_platform() {
        let fetchable = is_fetchable(MinerKind::GpuPrl);
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        assert!(!fetchable, "SRBMiner has no macOS build → GPU-PRL not fetchable on Apple");
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        assert!(fetchable, "GPU-PRL ships an archive fetch spec on linux/windows");
        let _ = fetchable;
    }

    #[test]
    fn allow_unverified_accepts_only_affirmative_values() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for (val, want) in [("1", true), ("true", true), ("YES", true), ("0", false), ("", false), ("no", false)] {
            std::env::set_var(ALLOW_UNVERIFIED_ENV, val);
            assert_eq!(allow_unverified(), want, "value {val:?}");
        }
        std::env::remove_var(ALLOW_UNVERIFIED_ENV);
        assert!(!allow_unverified(), "unset → off (safe default)");
    }

    #[test]
    fn defender_quarantine_read_error_is_clean_and_actionable() {
        let path = Path::new("C:\\Users\\Naris\\AppData\\Local\\AliceMiner\\engines\\x86_64-pc-windows-msvc\\SRBMiner-MULTI.exe");
        // ERROR_VIRUS_INFECTED (225) → a clear Defender message with the exact fix,
        // NOT the raw localized OS string (which renders as mojibake).
        let msg = read_error_message(path, &std::io::Error::from_raw_os_error(225));
        assert!(msg.contains("antivirus"), "names the cause: {msg}");
        assert!(msg.contains("Add-MpPreference -ExclusionPath"), "gives the fix: {msg}");
        assert!(msg.contains("SRBMiner-MULTI.exe"), "names the engine: {msg}");
        assert!(msg.contains("AliceMiner"), "names the folder to exclude: {msg}");
        // A normal IO error keeps the plain integrity-check wording.
        let plain = read_error_message(path, &std::io::Error::from_raw_os_error(2));
        assert!(plain.contains("for integrity check"), "plain path: {plain}");
        assert!(!plain.contains("Add-MpPreference"), "no AV noise for a normal error");
    }
}
