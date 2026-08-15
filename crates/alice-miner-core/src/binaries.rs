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

/// The env var that, set to `1`/`true`, permits the `ALICE_MINER_<KIND>_BIN`
/// override to run a binary whose SHA-256 is NOT pinned (or doesn't match). This
/// is an explicit, loud opt-in for advanced users supplying their own engine
/// (e.g. T-Rex); without it, an override to an unverified binary is refused.
pub const ALLOW_UNVERIFIED_ENV: &str = "ALICE_MINER_ALLOW_UNVERIFIED_BIN";

/// Machine-readable marker on every "we could not verify these engine bytes"
/// error. A lane that sees it must stop rather than degrade: there is no
/// "run the old engine anyway" path (that is exactly how you keep mining into a
/// hard fork, or run bytes someone swapped).
pub const ENGINE_UNVERIFIED: &str = "ENGINE_UNVERIFIED";

/// True when `err` came from an integrity/verification refusal (as opposed to a
/// merely-missing engine or a network hiccup).
pub fn is_engine_unverified(err: &str) -> bool {
    err.contains(ENGINE_UNVERIFIED)
}

/// One engine pin. Defined in [`crate::engine_pins`] because the pin table now
/// has two sources — the manifest compiled into this binary (the floor) and the
/// separately-signed, independently-publishable `engines.json` — and the
/// resolver must treat them as the same shape.
pub use crate::engine_pins::PinEntry;

/// The pin table compiled into this binary from `release-assets/miners.json` —
/// the FLOOR the resolver falls back to whenever no verified `engines.json` is
/// active. Baking it in is what makes "SHA-pinned engine" a runtime guarantee
/// rather than a packaging-time note (audit B-1); it now also guarantees that a
/// client with no network, no pin document, or a refused one still knows exactly
/// which bytes it is allowed to run.
pub use crate::engine_pins::EMBEDDED_MANIFEST as MINERS_MANIFEST;

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

    /// The `kind` string this engine carries in `release-assets/miners.json`
    /// (and in the signed `engines.json`).
    pub fn manifest_kind(self) -> &'static str {
        match self {
            MinerKind::CpuXmr => "cpu-xmr",
            MinerKind::GpuRvn => "gpu-rvn",
            MinerKind::GpuPrl => "gpu-prl",
            MinerKind::GpuAlpha => "gpu-alpha",
        }
    }
}

/// The SHA-256 pin in force for `kind` on the current target triple.
///
/// The pin comes from [`crate::engine_pins::effective_pin_for`]: a verified,
/// non-stale `engines.json` if one is active on this machine, otherwise the
/// manifest compiled into this binary (the floor). `None` when no entry matches
/// OR the entry is an all-zero placeholder (e.g. kawpowminer until M7) — i.e.
/// "there is no real pin to verify against", which the resolver treats as
/// not-installable for a bundled binary (it must not exec what it can't verify).
fn pinned_sha256_for(kind: MinerKind) -> Option<String> {
    crate::engine_pins::effective_pin_for(kind).and_then(|p| p.entry.real_sha256())
}

/// The whole pin entry in force for `kind` on the current target triple.
/// Unlike [`pinned_sha256_for`], this returns the download URLs too.
fn manifest_entry_for(kind: MinerKind) -> Option<PinEntry> {
    crate::engine_pins::effective_pin_for(kind).map(|p| p.entry)
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
    // The engines root (`…/AliceMiner/engines`) is shared with the pin store and
    // honours the same single relocation hook, so a test — or an operator moving
    // the cache off a small disk — never ends up with the pins in one place and
    // the binaries they pin in another.
    Ok(crate::engine_pins::engines_root()?.join(current_target_triple()))
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

/// Build a [`FetchSpec`] from a pin entry, or `None` if the entry is a
/// placeholder / has no real pin / has no usable download URL. A direct
/// `binary_url` wins over an `archive_url` if both are present.
///
/// Every URL must sit under one of [`crate::engine_pins::ALLOWED_URL_PREFIXES`]
/// — the upstream projects' official release hosts, compiled into this client.
/// The signed pin list is validated against the same list when it is accepted;
/// enforcing it again HERE means the download path itself has the property,
/// whichever source the entry came from.
fn fetch_spec_from(e: &PinEntry) -> Option<FetchSpec> {
    let pin = e.real_sha256()?; // refuses placeholders / non-64-hex
    let allowed = |u: &String| crate::engine_pins::url_is_allowed(u);
    if let Some(url) = e.binary_url.clone().filter(allowed) {
        return Some(FetchSpec::Direct { url, sha256: pin });
    }
    let url = e.archive_url.clone().filter(allowed)?;
    let archive_sha256 = e.archive_sha256.clone().filter(|s| s.len() == 64)?;
    let member = e.binary_path_in_archive.clone().filter(|m| !m.is_empty())?;
    Some(FetchSpec::Archive { url, archive_sha256, member, binary_sha256: pin })
}

/// Build a [`FetchSpec`] for the pin in force for `kind` on this platform.
fn fetch_spec_for(kind: MinerKind) -> Option<FetchSpec> {
    fetch_spec_from(&manifest_entry_for(kind)?)
}

/// Why an engine fetch did not produce verified bytes. The distinction is
/// load-bearing for the pin updater: a NETWORK failure must leave the current
/// engine (and the current pin) alone and be retried, while an INTEGRITY failure
/// means the bytes upstream do not match what was signed — that is a refusal, not
/// a retry, and it is never resolved by running something else.
#[derive(Debug, Clone)]
pub enum FetchFail {
    Network(String),
    Integrity(String),
    NotFetchable(String),
}

impl FetchFail {
    pub fn message(&self) -> &str {
        match self {
            FetchFail::Network(m) | FetchFail::Integrity(m) | FetchFail::NotFetchable(m) => m,
        }
    }
}

/// Download the engine bytes an entry names and verify them against that entry's
/// own SHA-256 (and, for an archive, the archive hash first). Returns the
/// verified bytes; NOTHING is written to disk here, so a failure cannot leave a
/// runnable file behind.
pub fn fetch_entry_bytes(e: &PinEntry) -> Result<Vec<u8>, FetchFail> {
    fetch_entry_bytes_with_progress(e, &mut |_p, _d, _t| {})
}

/// [`fetch_entry_bytes`] with progress reporting.
pub fn fetch_entry_bytes_with_progress(
    e: &PinEntry,
    cb: &mut dyn FnMut(FetchPhase, u64, Option<u64>),
) -> Result<Vec<u8>, FetchFail> {
    let spec = fetch_spec_from(e).ok_or_else(|| {
        FetchFail::NotFetchable(format!(
            "no verified download is configured for {}/{} ({})",
            e.kind, e.target, e.filename
        ))
    })?;
    match spec {
        FetchSpec::Direct { url, sha256 } => {
            cb(FetchPhase::Downloading, 0, None);
            let bytes = alice_release::https_get_capped(&url, ENGINE_DOWNLOAD_CAP)
                .map_err(FetchFail::Network)?;
            cb(FetchPhase::Verifying, bytes.len() as u64, None);
            verify_bytes_sha256(&bytes, &sha256, &e.filename).map_err(FetchFail::Integrity)?;
            Ok(bytes)
        }
        FetchSpec::Archive { url, archive_sha256, member, binary_sha256 } => {
            cb(FetchPhase::Downloading, 0, None);
            let archive = alice_release::https_get_capped(&url, ENGINE_DOWNLOAD_CAP)
                .map_err(FetchFail::Network)?;
            cb(FetchPhase::Verifying, archive.len() as u64, None);
            verify_bytes_sha256(&archive, &archive_sha256, "engine archive")
                .map_err(FetchFail::Integrity)?;
            cb(FetchPhase::Extracting, 0, None);
            // A malformed/unexpected archive is an integrity problem, not a
            // network one: retrying the same URL cannot fix it.
            let bytes = extract_member(&url, &archive, &member).map_err(FetchFail::Integrity)?;
            verify_bytes_sha256(&bytes, &binary_sha256, &e.filename)
                .map_err(FetchFail::Integrity)?;
            Ok(bytes)
        }
    }
}

/// Install ALREADY-VERIFIED engine bytes into the per-user engine cache under
/// `filename`, atomically. Used by the pin updater to stage a newly pinned engine
/// while the old one is still running.
///
/// The caller is responsible for having hashed `bytes` against the pin; this
/// function is the write half only, and it is deliberately not reachable from
/// anywhere that has not just done that check.
pub fn install_verified_engine(filename: &str, bytes: &[u8]) -> Result<(), String> {
    if filename.is_empty()
        || Path::new(filename).file_name().map(|n| n != filename).unwrap_or(true)
    {
        return Err(format!("refusing to install an engine under an unsafe name {filename:?}"));
    }
    let dir = engine_cache_dir()?;
    ensure_cache_dir(&dir)?;
    sweep_stale_installs(&dir);
    cache_install_atomic(&dir, &dir.join(filename), bytes)
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

    let entry = manifest_entry_for(kind).filter(|e| fetch_spec_from(e).is_some()).ok_or_else(|| {
        let name = kind.binary_name();
        match crate::i18n::lang() {
            crate::i18n::Lang::En => format!(
                "the {name} engine is not installed and no verified download is configured \
                 for this platform (the lane stays unavailable)."
            ),
            crate::i18n::Lang::Zh => format!(
                "{name} 引擎未安装,且此平台没有配置可验证的下载源(该通道保持不可用)。"
            ),
        }
    })?;

    ensure_cache_dir(&dir)?;
    // Opportunistically clear any stale rename-aside / partial files a previous
    // (esp. Windows, running-exe) install may have left behind.
    sweep_stale_installs(&dir);

    // Fetch + verify ENTIRELY before touching the destination path. An integrity
    // failure is tagged so a lane can tell "could not reach the CDN" (retry) from
    // "these are not the bytes we pinned" (stop, say so, never substitute).
    let verified_bytes = fetch_entry_bytes_with_progress(&entry, cb).map_err(|f| match f {
        FetchFail::Integrity(m) => format!("{ENGINE_UNVERIFIED}: {m}"),
        other => other.message().to_string(),
    })?;

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

/// Idempotently ensure the engine cache directory exists.
///
/// `std::fs::create_dir_all` is *supposed* to be a no-op when the directory is
/// already present, but on Windows it can still surface `ERROR_ALREADY_EXISTS`
/// (os error 183) — e.g. a benign race where a concurrent miner process created
/// the same tree between our existence check and the syscall, or a quirk of the
/// Win32 `CreateDirectory` path. A real Windows tester hit exactly this:
/// `cannot create engine cache C:\Users\...\AppData\Local\AliceMiner\engines\
/// x86_64-pc-windows-msvc` — even though the directory was already there. Treat
/// "it already exists as a directory" as success (which is what the caller
/// wanted), and only fail when the path is genuinely unusable: it exists as a
/// FILE (a component collision), or `create_dir_all` failed for another reason
/// AND the directory still isn't there afterwards.
fn ensure_cache_dir(dir: &Path) -> Result<(), String> {
    match std::fs::create_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Post-condition check: regardless of the error, if a directory now
            // exists at `dir` the goal is met. `metadata` follows symlinks, so a
            // symlink-to-directory also counts (the per-user cache is trusted; the
            // download path itself uses O_EXCL for defence-in-depth).
            match std::fs::metadata(dir) {
                Ok(meta) if meta.is_dir() => Ok(()),
                Ok(_) => Err(match crate::i18n::lang() {
                    // A non-directory (a file) sits where the cache dir must be.
                    // create_dir_all can't fix this; the user must remove it.
                    crate::i18n::Lang::En => format!(
                        "cannot create engine cache {}: a file already exists at that path \
                         (remove or rename it, then start mining again).",
                        dir.display()
                    ),
                    crate::i18n::Lang::Zh => format!(
                        "无法创建引擎缓存 {}:该路径上已存在一个同名文件\
                         (请删除或重命名后再开始挖矿)。",
                        dir.display()
                    ),
                }),
                Err(_) => Err(format!("cannot create engine cache {}: {e}", dir.display())),
            }
        }
    }
}

/// Verify `bytes` hash to the expected lowercase-hex SHA-256, or a clear error
/// naming `what`. The single chokepoint that enforces "fetched == pinned".
fn verify_bytes_sha256(bytes: &[u8], expected: &str, what: &str) -> Result<(), String> {
    let got = alice_release::sha256_hex(bytes);
    if got.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(match crate::i18n::lang() {
            crate::i18n::Lang::En => format!(
                "refusing to install {what}: downloaded SHA-256 {got} does not match the \
                 pinned {expected}. The download was tampered with or corrupted; nothing \
                 was written."
            ),
            crate::i18n::Lang::Zh => format!(
                "拒绝安装 {what}:下载的 SHA-256 {got} 与固定值 {expected} 不匹配。\
                 下载内容已被篡改或损坏;未写入任何文件。"
            ),
        })
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

    install_rename(dir, &tmp, dest).inspect_err(|_e| {
        let _ = std::fs::remove_file(&tmp);
    })?;
    Ok(())
}

/// Rename the verified temp file over `dest` atomically, tolerating the Windows
/// "the destination .exe is currently running" case.
///
/// On Unix `rename(2)` replaces an in-use binary transparently (the running
/// process keeps its open inode), so a single rename is enough. On Windows a
/// plain `MoveFileEx(REPLACE_EXISTING)` over a `.exe` that is currently executing
/// fails with `ERROR_ACCESS_DENIED` (5) or `ERROR_SHARING_VIOLATION` (32) — which
/// is exactly what happens if a previous mining run left the engine process alive
/// (or a scanner has the file open) while we try to refresh it. Windows *does*
/// allow renaming a running `.exe` to a NEW name, so we fall back to the classic
/// rename-aside dance: move the locked `dest` out of the way to a unique
/// `.old-*` name, then move our fresh binary into `dest`. The stale aside file is
/// deleted best-effort (it may still be locked by the running process; it will be
/// removable after that process exits, and `sweep_stale_installs` mops it up).
fn install_rename(dir: &Path, tmp: &Path, dest: &Path) -> Result<(), String> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static ASIDE_SEQ: AtomicU64 = AtomicU64::new(0);

    // Fast path: works when dest is absent, or present-and-not-locked (Unix
    // always; Windows when no process holds the old binary open).
    match std::fs::rename(tmp, dest) {
        Ok(()) => Ok(()),
        Err(_e) if dest.exists() => {
            // Move the (possibly running/locked) current binary aside, then retry.
            let base = dest.file_name().and_then(|n| n.to_str()).unwrap_or("engine");
            let aside = dir.join(format!(
                ".{base}.old-{}-{}",
                std::process::id(),
                ASIDE_SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::rename(dest, &aside).map_err(|e| {
                format!(
                    "installing engine to {}: could not move the existing binary aside \
                     (is it still running? stop mining and retry): {e}",
                    dest.display()
                )
            })?;
            // With dest now free, the fresh binary can take its place.
            if let Err(e) = std::fs::rename(tmp, dest) {
                // Roll back so we don't leave the lane with NO binary at all.
                let _ = std::fs::rename(&aside, dest);
                return Err(format!("installing engine to {}: {e}", dest.display()));
            }
            // Best-effort cleanup; a still-locked aside file is swept later.
            let _ = std::fs::remove_file(&aside);
            Ok(())
        }
        Err(e) => Err(format!("installing engine to {}: {e}", dest.display())),
    }
}

/// Best-effort removal of stale `.old-*` / `.partial-*` files left in the engine
/// cache dir by a previous install (e.g. a Windows rename-aside whose original
/// process was still running at cleanup time). Never fails the caller — a file we
/// still can't delete is simply left for the next sweep. Call opportunistically.
pub fn sweep_stale_installs(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // Our temp artifacts are always dot-prefixed with these infixes.
        if name.starts_with('.') && (name.contains(".old-") || name.contains(".partial-")) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
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
        let bin = path.display();
        return match crate::i18n::lang() {
            crate::i18n::Lang::En => format!(
                "the mining engine {bin} was blocked/quarantined by antivirus. Windows Defender flags \
                 mining software as a \"potentially unwanted application\" — a known false positive. \
                 To mine, allow this folder in Defender: open an elevated PowerShell (Run as \
                 administrator) and run\n    Add-MpPreference -ExclusionPath '{folder}'\nthen start mining \
                 again. (You can undo it later with Remove-MpPreference -ExclusionPath.)"
            ),
            crate::i18n::Lang::Zh => format!(
                "挖矿引擎 {bin} 被杀毒软件拦截/隔离。Windows Defender 会把挖矿软件标记为\
                 \"潜在有害应用\" — 这是已知的误报。要继续挖矿,请在 Defender 中放行该文件夹:\
                 以管理员身份打开 PowerShell(Run as administrator)并运行\n    \
                 Add-MpPreference -ExclusionPath '{folder}'\n然后重新开始挖矿。\
                 (之后可用 Remove-MpPreference -ExclusionPath 撤销。)"
            ),
        };
    }
    match crate::i18n::lang() {
        crate::i18n::Lang::En => format!("cannot read {} for integrity check: {e}", path.display()),
        crate::i18n::Lang::Zh => format!("无法读取 {} 进行完整性校验: {e}", path.display()),
    }
}

/// Verify the resolved bundled binary at `path` against the pinned SHA-256 for
/// `kind`. Refuses (clear `Err`, no exec) when there is no real pin to check
/// against, or when the on-disk hash does not match the pin.
fn verify_pinned(kind: MinerKind, path: &Path) -> Result<(), String> {
    let name = kind.binary_name();
    let Some(pin) = pinned_sha256_for(kind) else {
        let at = path.display();
        return Err(match crate::i18n::lang() {
            crate::i18n::Lang::En => format!(
                "{ENGINE_UNVERIFIED}: refusing to run the {name} engine at {at}: no pinned SHA-256 is available for this \
                 platform yet (the bundled binary cannot be integrity-verified). The lane stays \
                 unavailable until a pinned build ships."
            ),
            crate::i18n::Lang::Zh => format!(
                "{ENGINE_UNVERIFIED}: 拒绝运行位于 {at} 的 {name} 引擎:此平台尚无固定的 SHA-256 \
                 (无法对内置二进制做完整性校验)。在固定校验的构建发布前,该通道保持不可用。"
            ),
        });
    };
    let got = file_sha256(path)?;
    if got.eq_ignore_ascii_case(&pin) {
        Ok(())
    } else {
        let at = path.display();
        Err(match crate::i18n::lang() {
            crate::i18n::Lang::En => format!(
                "{ENGINE_UNVERIFIED}: refusing to run the {name} engine at {at}: SHA-256 integrity check FAILED \
                 (got {got}, pinned {pin}). The on-disk binary does not match the signed \
                 release; it may have been tampered with or replaced."
            ),
            crate::i18n::Lang::Zh => format!(
                "{ENGINE_UNVERIFIED}: 拒绝运行位于 {at} 的 {name} 引擎:SHA-256 完整性校验失败 \
                 (实际 {got},固定 {pin})。磁盘上的二进制与签名发布不匹配;\
                 可能已被篡改或替换。"
            ),
        })
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
    // 0) A BELT, not the primary trigger (F15). The refresher is started by each
    //    front-end at PROCESS start, because gating it on "a lane started an
    //    engine" means a client the acceptance guard has halted — which starts no
    //    engine, ever — can never receive the engine pin that would un-halt it.
    //    This call remains so that any future entry point which forgets the
    //    process-start hook still ends up with a running refresher; it is
    //    idempotent (see `background_refresh_starts`), runs OFF this thread, and
    //    never blocks mining.
    crate::engine_pins::start_background_refresh();

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
            let name = kind.binary_name();
            match crate::i18n::lang() {
                crate::i18n::Lang::En => {
                    format!("the {name} engine is not installed and auto-download failed: {e}")
                }
                crate::i18n::Lang::Zh => format!("{name} 引擎未安装,且自动下载失败: {e}"),
            }
        });
    }

    // Graceful, kind-specific "not installed" status (NEVER a panic). We reach
    // here only when the engine is NOT fetchable on this platform (no real pin +
    // configured download URL) — which, for a kind that DOES ship a packaged
    // release elsewhere, means this is an unpackaged DEV build (e.g. `target/release`
    // on macOS with no `.app` sibling). Lead with the actionable fix — install a
    // packaged release — instead of a bare "not installed" (#14).
    let name = kind.binary_name();
    let env = kind.env_override();
    let en = crate::i18n::lang() == crate::i18n::Lang::En;
    Err(match kind {
        MinerKind::CpuXmr => {
            let cand = candidate.display();
            if en {
                format!(
                    "CPU miner not bundled in this build: `{name}` was not found beside the \
                     executable at {cand} and no verified download is configured for this \
                     platform — this is an unpackaged dev build. Install a packaged release \
                     from {RELEASES_URL} (which bundles the engine), or set {env} to a pinned `{name}`."
                )
            } else {
                format!(
                    "此构建未内置 CPU 矿机:在可执行文件旁 {cand} 未找到 `{name}`,\
                     且此平台没有配置可验证的下载源 — 这是一个未打包的 dev 构建。\
                     请从 {RELEASES_URL} 安装打包版(其中内置引擎),或将 {env} 设为固定校验的 `{name}`。"
                )
            }
        }
        MinerKind::GpuRvn => {
            if en {
                format!(
                    "GPU miner not bundled in this build: the KawPowMiner engine `{name}` was not \
                     found and no verified download is configured for this platform. Install a \
                     packaged release from {RELEASES_URL}, or set {env} to a kawpowminer/T-Rex binary. The \
                     RVN lane stays unavailable."
                )
            } else {
                format!(
                    "此构建未内置 GPU 矿机:未找到 KawPowMiner 引擎 `{name}`,\
                     且此平台没有配置可验证的下载源。请从 {RELEASES_URL} 安装打包版,\
                     或将 {env} 设为 kawpowminer/T-Rex 二进制。RVN 通道保持不可用。"
                )
            }
        }
        MinerKind::GpuPrl => {
            if en {
                format!(
                    "GPU miner not bundled in this build: the SRBMiner-MULTI engine `{name}` was not \
                     found and no verified download is configured for this platform (SRBMiner \
                     ships no macOS build). Install a packaged release from {RELEASES_URL}, or set {env} to an \
                     SRBMiner-MULTI binary. The GPU-PRL lane stays unavailable."
                )
            } else {
                format!(
                    "此构建未内置 GPU 矿机:未找到 SRBMiner-MULTI 引擎 `{name}`,\
                     且此平台没有配置可验证的下载源(SRBMiner 无 macOS 版本)。\
                     请从 {RELEASES_URL} 安装打包版,或将 {env} 设为 SRBMiner-MULTI 二进制。\
                     GPU-PRL 通道保持不可用。"
                )
            }
        }
        MinerKind::GpuAlpha => {
            if en {
                format!(
                    "GPU miner not bundled in this build: the AlphaMiner engine `{name}` was not \
                     found and no verified download is configured for this platform (alpha-miner \
                     is NVIDIA-CUDA only). Install a packaged release from {RELEASES_URL}, or set {env} to an \
                     alpha-miner binary. The GPU-Alpha (V100/Volta) lane stays unavailable."
                )
            } else {
                format!(
                    "此构建未内置 GPU 矿机:未找到 AlphaMiner 引擎 `{name}`,\
                     且此平台没有配置可验证的下载源(alpha-miner 仅支持 NVIDIA-CUDA)。\
                     请从 {RELEASES_URL} 安装打包版,或将 {env} 设为 alpha-miner 二进制。\
                     GPU-Alpha (V100/Volta) 通道保持不可用。"
                )
            }
        }
    })
}

/// The canonical packaged-release home for the actionable "engine not bundled"
/// message (#14). A non-dev gets a one-stop place to download a real packaged
/// build (which bundles / auto-downloads the verified engine), instead of being
/// told the engine is merely "not installed". The releases page hosts the signed
/// per-OS artifacts.
pub const RELEASES_URL: &str = "https://github.com/V-SK/Alice-Miner/releases/latest";

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

    /// A gpu-prl entry's `version` must AGREE with the URL it fetches and the member
    /// it extracts.
    ///
    /// WHY THIS EXISTS (2026-08-11). Pearl hard-forked at height 99000 to the V3
    /// salted-seed certificate; the engine we pinned, SRBMiner-MULTI 3.4.1, predated
    /// that spec by seven weeks and so emitted invalid shares from the fork on — 78
    /// hours at zero accepted PRL shares. The fix is a pin bump, and a pin bump is
    /// FOUR fields that must move together: `version`, `archive_url`, the
    /// `binary_path_in_archive` prefix, and the two hashes. The structural test above
    /// would happily pass a half-done bump that declares 3.5.4 while still downloading
    /// the 3.4.1 archive — the hashes would still be "real 64-hex", and the failure
    /// would only surface as a mismatch on a miner's machine, or worse, as a silently
    /// stale engine. SRBMiner spells its version with dashes in paths (`3.5.4` ->
    /// `3-5-4`), so both spellings are checked.
    ///
    /// This asserts CONSISTENCY, never a specific version: bumping the pin correctly
    /// keeps it green, bumping it halfway does not.
    #[test]
    fn gpu_prl_pin_version_agrees_with_its_url_and_archive_member() {
        let v: serde_json::Value = serde_json::from_str(MINERS_MANIFEST).unwrap();
        for e in v["engines"].as_array().expect("engines array") {
            if e["kind"].as_str() != Some("gpu-prl") {
                continue;
            }
            let target = e["target"].as_str().expect("gpu-prl target");
            let version = e["version"].as_str().unwrap_or_else(|| {
                panic!("gpu-prl {target}: a fetched engine must declare its version")
            });
            let dashed = version.replace('.', "-");
            let url = e["archive_url"].as_str().unwrap_or("");
            let member = e["binary_path_in_archive"].as_str().unwrap_or("");
            assert!(
                url.contains(&format!("/download/{version}/")),
                "gpu-prl {target}: archive_url must fetch the DECLARED version {version}, got {url:?}"
            );
            assert!(
                url.contains(&dashed),
                "gpu-prl {target}: archive filename must carry {dashed}, got {url:?}"
            );
            assert!(
                member.starts_with(&format!("SRBMiner-Multi-{dashed}/")),
                "gpu-prl {target}: archive member must live under SRBMiner-Multi-{dashed}/, got {member:?}"
            );
        }
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

    /// #14 (the surviving HIGH-1 nugget): EVERY non-placeholder engine entry must
    /// be obtainable — it carries an https `binary_url` or `archive_url` for the
    /// runtime auto-download. The ONE intentional exception is the macOS arm64 xmrig,
    /// which is BUNDLED in the `.app` (pin, no URL by design). gpu-rvn entries are
    /// intentional all-zero placeholders (pinned at packaging) → excluded. This guards
    /// the "onboarding dead-end" regression: a real-user entry with a pin but no way
    /// to fetch it.
    #[test]
    fn every_non_placeholder_entry_is_fetchable_or_bundled() {
        let v: serde_json::Value = serde_json::from_str(MINERS_MANIFEST).unwrap();
        let engines = v["engines"].as_array().expect("engines array");
        let mut checked = 0;
        for e in engines {
            let kind = e["kind"].as_str().unwrap_or("");
            let target = e["target"].as_str().unwrap_or("");
            // Exclude intentional placeholders (gpu-rvn: pinned at packaging M7).
            if e.get("_placeholder").and_then(|p| p.as_bool()) == Some(true) {
                assert_eq!(kind, "gpu-rvn", "only gpu-rvn is a placeholder, not {kind}");
                continue;
            }
            // The bundled exception: macOS arm64 xmrig ships in the `.app` (no URL).
            let bundled_macos_xmrig = kind == "cpu-xmr" && target == "aarch64-apple-darwin";
            let has_binary_url =
                e["binary_url"].as_str().map(|u| u.starts_with("https://")).unwrap_or(false);
            let has_archive_url =
                e["archive_url"].as_str().map(|u| u.starts_with("https://")).unwrap_or(false);
            if bundled_macos_xmrig {
                assert!(
                    !has_binary_url && !has_archive_url,
                    "macOS arm64 xmrig is bundled — it must NOT carry a download URL"
                );
            } else {
                assert!(
                    has_binary_url || has_archive_url,
                    "non-placeholder {kind}/{target} must have an https binary_url or \
                     archive_url (onboarding dead-end guard)"
                );
            }
            checked += 1;
        }
        // Sanity: we actually exercised real entries (not an empty/garbled manifest).
        assert!(checked >= 5, "expected to check several real entries, got {checked}");
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
            err.contains("not bundled in this build"),
            "expected a clear not-bundled status, got: {err}"
        );
        // #14: the message is ACTIONABLE — it points at a packaged release, names the
        // override knob, and says the lane stays off (never a bare "not installed").
        assert!(err.contains(RELEASES_URL), "must point at a packaged release: {err}");
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

    // ── Fail-closed verification (engine-pin layer) ─────────────────────────

    /// A binary on disk that does not hash to the pin is REFUSED, and the refusal
    /// is machine-taggable so a lane can stop instead of "degrading" into mining
    /// with whatever bytes happen to be there.
    #[test]
    fn a_binary_that_misses_the_pin_is_refused_and_tagged() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = scratch("verify");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(MinerKind::CpuXmr.binary_name());
        std::fs::write(&path, b"not the pinned engine").unwrap();
        let err = verify_pinned(MinerKind::CpuXmr, &path).expect_err("must refuse");
        assert!(is_engine_unverified(&err), "tagged for the lane layer: {err}");
        assert!(
            err.contains("integrity check FAILED") || err.contains("no pinned SHA-256"),
            "and readable by a human: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `install_verified_engine` is the write half used by the pin stager: it
    /// refuses a name that is anything other than a bare filename, so a pin
    /// document can never write outside the engine cache.
    #[test]
    fn install_verified_engine_refuses_a_path_as_a_name() {
        for bad in ["../evil", "a/b", ""] {
            let err = install_verified_engine(bad, b"x").expect_err("must refuse {bad}");
            assert!(err.contains("unsafe name"), "got: {err}");
        }
    }

    /// The download path enforces the upstream allow-list itself, whichever pin
    /// source the entry came from — a pin naming a foreign host is simply not
    /// fetchable, so nothing is ever downloaded from it.
    #[test]
    fn a_pin_pointing_off_the_allowlist_is_not_fetchable() {
        let mut e = crate::engine_pins::embedded_entry(
            "gpu-prl",
            "x86_64-unknown-linux-gnu",
            "SRBMiner-MULTI",
        )
        .expect("floor entry");
        assert!(fetch_spec_from(&e).is_some(), "the real upstream URL is fetchable");
        e.archive_url = Some("https://cdn.attacker.example/SRBMiner.tar.gz".into());
        assert!(fetch_spec_from(&e).is_none(), "a foreign host must not be fetchable");
        let err = fetch_entry_bytes(&e).expect_err("and fetching it fails");
        assert!(matches!(err, FetchFail::NotFetchable(_)), "got: {err:?}");
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

    /// A unique scratch dir under the OS temp root (never the real cache).
    fn scratch(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "alice-eng-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ))
    }

    /// `ensure_cache_dir` creates the tree AND is idempotent — a second call on an
    /// already-existing directory succeeds (this is the os-error-183 case: on
    /// Windows `create_dir_all` can report ERROR_ALREADY_EXISTS even though the dir
    /// is right there; we must treat "already a directory" as success).
    #[test]
    fn ensure_cache_dir_is_idempotent() {
        let dir = scratch("mkidem").join("engines").join("x86_64-pc-windows-msvc");
        ensure_cache_dir(&dir).expect("first create");
        assert!(dir.is_dir());
        // Second call: the directory already exists → must still be Ok, never the
        // "cannot create engine cache" error the Windows tester saw.
        ensure_cache_dir(&dir).expect("idempotent second create");
        let root = dir.ancestors().nth(2).unwrap().to_path_buf();
        let _ = std::fs::remove_dir_all(root);
    }

    /// If a FILE sits where the cache directory must be, `ensure_cache_dir` returns
    /// a clear, actionable error (not a silent success, not a raw OS string).
    #[test]
    fn ensure_cache_dir_reports_file_collision() {
        let base = scratch("mkfile");
        std::fs::create_dir_all(&base).unwrap();
        let clash = base.join("engines");
        std::fs::write(&clash, b"not a dir").unwrap();
        let err = ensure_cache_dir(&clash).expect_err("a file where the dir must be must fail");
        assert!(
            err.contains("a file already exists") || err.contains("同名文件"),
            "clear file-collision message, got: {err}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// `install_rename` replaces an EXISTING destination binary — the core of the
    /// Windows running-exe fix. We can't lock a file the way a running .exe does on
    /// this (macOS) host, but we can prove the replace path installs the new bytes
    /// and leaves no stale `.old-*`/`.partial-*` behind on a normal filesystem.
    #[test]
    fn install_rename_replaces_existing_destination() {
        let dir = scratch("replace");
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("SRBMiner-MULTI");
        std::fs::write(&dest, b"OLD ENGINE").unwrap();

        let tmp = dir.join(".SRBMiner-MULTI.partial-test");
        std::fs::write(&tmp, b"NEW ENGINE").unwrap();

        install_rename(&dir, &tmp, &dest).expect("replace existing");
        assert_eq!(std::fs::read(&dest).unwrap(), b"NEW ENGINE", "dest holds the new bytes");
        assert!(!tmp.exists(), "temp consumed by the rename");

        // No stale artifacts left (the fast path handled it; even if it took the
        // aside path, cleanup + sweep would clear it).
        sweep_stale_installs(&dir);
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.contains(".old-") || n.contains(".partial-")
            })
            .collect();
        assert!(leftovers.is_empty(), "no stale .old-/.partial- files: {leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `sweep_stale_installs` removes dot-prefixed `.old-*` / `.partial-*` cruft but
    /// leaves the real engine binary and unrelated files untouched.
    #[test]
    fn sweep_stale_installs_only_removes_our_temps() {
        let dir = scratch("sweep");
        std::fs::create_dir_all(&dir).unwrap();
        let engine = dir.join("xmrig");
        let stale_old = dir.join(".xmrig.old-1234-0");
        let stale_partial = dir.join(".xmrig.partial-1234-0");
        let unrelated = dir.join("readme.txt");
        for (p, c) in [
            (&engine, b"real".as_slice()),
            (&stale_old, b"old"),
            (&stale_partial, b"part"),
            (&unrelated, b"keep"),
        ] {
            std::fs::write(p, c).unwrap();
        }
        sweep_stale_installs(&dir);
        assert!(engine.exists(), "real engine kept");
        assert!(unrelated.exists(), "unrelated file kept");
        assert!(!stale_old.exists(), ".old- swept");
        assert!(!stale_partial.exists(), ".partial- swept");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
