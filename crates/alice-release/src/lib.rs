//! Self-updater for the Alice Wallet.
//!
//! Trust model (NO Apple/Windows code-signing certificates): the only trust
//! anchor is OUR ed25519 release key. The matching 32-byte public key is
//! embedded in the binary (`RELEASE_PUBKEY_B64`). A release is described by a
//! signed `latest.json` manifest:
//!
//! 1. Fetch `latest.json` + `latest.json.sig` from the configured update URL.
//! 2. Verify the detached ed25519 signature over the EXACT manifest bytes with
//!    the embedded public key (raw ed25519, the bytes are NOT pre-hashed —
//!    this matches the offline signer `openssl pkeyutl -sign -rawin`).
//! 3. If `manifest.version > current` (strict no-downgrade), PROMPT the user
//!    (the wallet NEVER silent-applies). On accept, download the artifact for
//!    this platform, verify its SHA-256 == the manifest entry, ad-hoc codesign
//!    it (macOS), then atomically swap it into place and relaunch.
//!
//! Hard invariants enforced here:
//!   * The updater writes ONLY to the application location, NEVER the wallet
//!     data dir (`config::wallet_data_root()`). See [`assert_not_in_data_dir`].
//!   * No-downgrade: a manifest version `<= current` is rejected.
//!   * `min_supported`: if the running version is below it, the caller is told
//!     to hard-block with an upgrade CTA.
//!   * Integrity: a downloaded artifact is verified against the manifest
//!     SHA-256 before it is ever signed, unpacked, or run. A mismatch aborts.
//!   * Last-known-good: the previous app is preserved; if the freshly-installed
//!     version fails its first-launch health check, we roll back.

/// Inlined copy of the subset of `alice-wallet/gui/src/config.rs` that
/// `update.rs` depends on for the data-dir safety guard (`assert_not_in_data_dir`
/// must know where the keystore lives so it can refuse to write there). Copied
/// verbatim — `DATA_ROOT_ENV` + `wallet_data_root()` resolve the keystore home
/// identically to the Wallet, and `TEST_ENV_LOCK` is the process-wide mutex the
/// data-root tests serialize on. This replaces the `crate::config::*` paths the
/// original file used; the updater logic itself is unchanged.
mod config {
    use std::path::PathBuf;

    pub const DATA_ROOT_ENV: &str = "ALICE_WALLET_DATA_ROOT";

    pub fn wallet_data_root() -> PathBuf {
        if let Some(root) = wallet_data_root_override() {
            return root;
        }

        dirs::data_local_dir()
            .unwrap_or_else(|| dirs::home_dir().expect("home dir").join(".alice"))
            .join("AliceWallet")
    }

    fn wallet_data_root_override() -> Option<PathBuf> {
        std::env::var(DATA_ROOT_ENV)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    }

    /// Process-wide lock serializing every test that mutates the global
    /// `ALICE_WALLET_DATA_ROOT` (and the tests that read the derived data root).
    #[cfg(test)]
    pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
}

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Embedded ed25519 release PUBLIC key (raw 32 bytes, base64). The matching
/// private key is held OFFLINE at `~/.alice-release/alice-update-ed25519.key`
/// and is never present in this binary or repo. Rotating the release key is a
/// breaking change: a build embedding key A cannot verify a manifest signed by
/// key B, which is the intended fail-closed behaviour.
pub const RELEASE_PUBKEY_B64: &str = "8P+XmZZFEsUHLmqeB62Xqr5GnwW5K9vf2sQHvRzfi5k=";

/// Default location of the signed release manifest. Overridable at runtime with
/// `ALICE_MINER_UPDATE_URL` (must point at the directory/`latest.json`; the
/// `.sig` is fetched from the same URL with `.sig` appended).
///
/// Pinned to the public **Miner** releases repo (`V-SK/alice-miner`), mirroring
/// the Wallet's `V-SK/alice-wallet`. The Miner publishes its OWN `latest.json`
/// here; the cross-product guard (`PRODUCT == "alice-miner"`,
/// [`parse_verified_manifest`]) rejects a Wallet manifest even if a URL is
/// misconfigured, so this fails closed rather than mis-updating.
pub const DEFAULT_UPDATE_URL: &str =
    "https://github.com/V-SK/alice-miner/releases/latest/download/latest.json";

/// Env override for the manifest URL.
pub const UPDATE_URL_ENV: &str = "ALICE_MINER_UPDATE_URL";

/// Manifest schema version this build understands. A manifest with a higher
/// `schema` is treated as "newer than we can safely parse": we refuse to act on
/// it (fail closed) rather than guess.
pub const SUPPORTED_SCHEMA: u32 = 1;

/// The product string the manifest must carry to be accepted by this app. This
/// is the Miner client: it uses its OWN product string ("alice-miner") against
/// the SAME embedded ed25519 key as the Wallet, so a Wallet manifest (product
/// "alice-wallet") is rejected here and vice-versa — the cross-product guard.
pub const PRODUCT: &str = "alice-miner";

/// How long to wait between automatic background checks (launch + every N).
pub const CHECK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

// ── HTTP timeouts. Conservative; a hung mirror must never freeze the updater.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const MANIFEST_READ_TIMEOUT: Duration = Duration::from_secs(30);
const DOWNLOAD_READ_TIMEOUT: Duration = Duration::from_secs(20 * 60);
/// Hard cap on a downloaded artifact (defensive: a malicious manifest could
/// otherwise point us at an unbounded body). 1 GiB is far above any real build.
const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;

// ────────────────────────────────────────────────────────────────────────────
// Manifest types — MUST stay byte-compatible with the signer (the signature is
// over the exact serialized bytes of `latest.json`).
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Artifact {
    /// Platform key, e.g. "macos-arm64", "linux-x86_64", "windows-x86_64".
    pub platform: String,
    /// Direct download URL for this artifact.
    pub url: String,
    /// Lower-case hex SHA-256 of the artifact bytes.
    pub sha256: String,
    /// Size in bytes (cross-checked against the actual download).
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub schema: u32,
    pub product: String,
    /// Latest available version (semver, no leading 'v').
    pub version: String,
    /// Oldest version still supported; below this the client must hard-upgrade.
    pub min_supported: String,
    /// Release date (RFC3339), informational.
    pub released: String,
    /// Human-readable release notes shown in the update prompt.
    pub notes: String,
    pub artifacts: Vec<Artifact>,
}

impl Manifest {
    /// The artifact matching the current build's platform, if any.
    pub fn artifact_for_current_platform(&self) -> Option<&Artifact> {
        let plat = current_platform();
        self.artifacts.iter().find(|a| a.platform == plat)
    }
}

/// Outcome of an update check, surfaced to the GUI for a user decision.
#[derive(Debug, Clone)]
pub enum CheckOutcome {
    /// Already on the latest (or newer) version — nothing to do.
    UpToDate { current: String },
    /// A newer version is available and an artifact exists for this platform.
    UpdateAvailable {
        current: String,
        manifest: Manifest,
        artifact: Artifact,
    },
    /// A newer version exists but ships no artifact for this platform; the user
    /// is pointed at the download page instead of an in-app update.
    UpdateAvailableNoArtifact { current: String, manifest: Manifest },
    /// The running version is below `min_supported`: hard-block with a CTA.
    Unsupported {
        current: String,
        min_supported: String,
        manifest: Manifest,
    },
}

#[derive(Debug)]
pub enum UpdateError {
    Http(String),
    Signature(String),
    Manifest(String),
    Integrity(String),
    Io(String),
    Codesign(String),
    Safety(String),
}

impl std::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateError::Http(m) => write!(f, "network error: {m}"),
            UpdateError::Signature(m) => write!(f, "signature verification failed: {m}"),
            UpdateError::Manifest(m) => write!(f, "manifest error: {m}"),
            UpdateError::Integrity(m) => write!(f, "integrity check failed: {m}"),
            UpdateError::Io(m) => write!(f, "io error: {m}"),
            UpdateError::Codesign(m) => write!(f, "codesign error: {m}"),
            UpdateError::Safety(m) => write!(f, "safety guard tripped: {m}"),
        }
    }
}

impl std::error::Error for UpdateError {}

type Result<T> = std::result::Result<T, UpdateError>;

// ────────────────────────────────────────────────────────────────────────────
// Configuration / platform helpers
// ────────────────────────────────────────────────────────────────────────────

/// The manifest URL: env override if set+non-empty, else the baked-in default.
pub fn update_url() -> String {
    std::env::var(UPDATE_URL_ENV)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_UPDATE_URL.to_string())
}

/// Derive the `.sig` URL from the manifest URL (append `.sig`).
fn sig_url(manifest_url: &str) -> String {
    format!("{manifest_url}.sig")
}

/// The current build version, from Cargo at compile time.
pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Platform key for THIS build. Mirrors the artifact `platform` strings used by
/// the release pipeline / `release.yml`.
pub fn current_platform() -> &'static str {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        "macos-arm64"
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        "macos-x86_64"
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        "linux-x86_64"
    }
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        "windows-x86_64"
    }
    #[cfg(not(any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "windows", target_arch = "x86_64"),
    )))]
    {
        "unknown"
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Signature verification (embedded pubkey)
// ────────────────────────────────────────────────────────────────────────────

/// Parse the embedded base64 public key into a dalek verifying key.
fn embedded_verifying_key() -> Result<VerifyingKey> {
    verifying_key_from_b64(RELEASE_PUBKEY_B64)
}

fn verifying_key_from_b64(b64: &str) -> Result<VerifyingKey> {
    let raw = B64
        .decode(b64.trim())
        .map_err(|e| UpdateError::Signature(format!("pubkey base64: {e}")))?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| UpdateError::Signature("pubkey must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|e| UpdateError::Signature(format!("invalid ed25519 pubkey: {e}")))
}

/// Verify a detached, base64-encoded ed25519 signature over `manifest_bytes`
/// using the provided verifying key. Raw ed25519 — `manifest_bytes` is the
/// exact message, not a hash of it.
pub fn verify_manifest_sig(manifest_bytes: &[u8], sig_b64: &str, vk: &VerifyingKey) -> Result<()> {
    let sig_raw = B64
        .decode(sig_b64.trim())
        .map_err(|e| UpdateError::Signature(format!("signature base64: {e}")))?;
    let sig_bytes: [u8; 64] = sig_raw
        .as_slice()
        .try_into()
        .map_err(|_| UpdateError::Signature("signature must be 64 bytes".into()))?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(manifest_bytes, &sig)
        .map_err(|e| UpdateError::Signature(format!("ed25519 verify: {e}")))
}

/// Verify with the EMBEDDED release key (production path).
pub fn verify_with_embedded_key(manifest_bytes: &[u8], sig_b64: &str) -> Result<()> {
    let vk = embedded_verifying_key()?;
    verify_manifest_sig(manifest_bytes, sig_b64, &vk)
}

/// Parse the manifest bytes into a [`Manifest`] AFTER its signature has been
/// verified, enforcing schema + product. Parsing an unverified manifest is a
/// bug, so this is intentionally separate from the fetch.
pub fn parse_verified_manifest(bytes: &[u8]) -> Result<Manifest> {
    let manifest: Manifest =
        serde_json::from_slice(bytes).map_err(|e| UpdateError::Manifest(format!("parse: {e}")))?;
    if manifest.schema > SUPPORTED_SCHEMA {
        return Err(UpdateError::Manifest(format!(
            "manifest schema {} newer than supported {}",
            manifest.schema, SUPPORTED_SCHEMA
        )));
    }
    if manifest.product != PRODUCT {
        return Err(UpdateError::Manifest(format!(
            "manifest product '{}' != expected '{}'",
            manifest.product, PRODUCT
        )));
    }
    Ok(manifest)
}

// ────────────────────────────────────────────────────────────────────────────
// Version comparison (semver-lite, no extra dependency)
// ────────────────────────────────────────────────────────────────────────────

/// Parse a dotted numeric version ("1.4.0", "v1.4", "1.4.0-rc1") into a numeric
/// triple for ordering. Any pre-release suffix after '-' is ignored for the
/// ordering of the release line; build metadata is not used in our scheme.
fn parse_version(v: &str) -> (u64, u64, u64) {
    let core = v.trim().trim_start_matches('v');
    let core = core.split(['-', '+']).next().unwrap_or(core);
    let mut it = core.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
    let major = it.next().unwrap_or(0);
    let minor = it.next().unwrap_or(0);
    let patch = it.next().unwrap_or(0);
    (major, minor, patch)
}

/// `true` iff `candidate` is strictly newer than `current` (no-downgrade).
pub fn is_newer(candidate: &str, current: &str) -> bool {
    parse_version(candidate) > parse_version(current)
}

/// `true` iff `current` is at or above `min` (i.e. still supported).
fn meets_min(current: &str, min: &str) -> bool {
    parse_version(current) >= parse_version(min)
}

/// Pure decision logic over an already-verified manifest: maps a manifest +
/// current version onto a [`CheckOutcome`]. Separated for unit testing.
pub fn evaluate(manifest: Manifest, current: &str) -> CheckOutcome {
    if !meets_min(current, &manifest.min_supported) {
        return CheckOutcome::Unsupported {
            current: current.to_string(),
            min_supported: manifest.min_supported.clone(),
            manifest,
        };
    }
    if !is_newer(&manifest.version, current) {
        return CheckOutcome::UpToDate {
            current: current.to_string(),
        };
    }
    match manifest.artifact_for_current_platform().cloned() {
        Some(artifact) => CheckOutcome::UpdateAvailable {
            current: current.to_string(),
            manifest,
            artifact,
        },
        None => CheckOutcome::UpdateAvailableNoArtifact {
            current: current.to_string(),
            manifest,
        },
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Network fetch + full check
// ────────────────────────────────────────────────────────────────────────────

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout_read(MANIFEST_READ_TIMEOUT)
        // Defense-in-depth: refuse plain-HTTP (incl. an http:// redirect target).
        // The update chain is already ed25519-verified, but the transport should
        // never silently downgrade off TLS.
        .https_only(true)
        .user_agent(concat!("alice-miner-updater/", env!("CARGO_PKG_VERSION")))
        .build()
}

fn http_get_bytes(agent: &ureq::Agent, url: &str, cap: u64) -> Result<Vec<u8>> {
    let resp = agent
        .get(url)
        .call()
        .map_err(|e| UpdateError::Http(format!("GET {url}: {e}")))?;
    let mut reader = resp.into_reader();
    let mut buf = Vec::new();
    use std::io::Read;
    reader
        .by_ref()
        .take(cap)
        .read_to_end(&mut buf)
        .map_err(|e| UpdateError::Http(format!("read {url}: {e}")))?;
    Ok(buf)
}

/// Fetch + verify + evaluate, end-to-end. Network-bound; call off the UI thread.
pub fn check_for_update(current: &str) -> Result<CheckOutcome> {
    let url = update_url();
    let agent = agent();
    let manifest_bytes = http_get_bytes(&agent, &url, 1024 * 1024)?; // 1 MiB cap
    let sig_b64 = String::from_utf8(http_get_bytes(&agent, &sig_url(&url), 64 * 1024)?)
        .map_err(|e| UpdateError::Signature(format!("sig not utf-8: {e}")))?;

    // Verify BEFORE trusting a single field of the manifest.
    verify_with_embedded_key(&manifest_bytes, &sig_b64)?;
    let manifest = parse_verified_manifest(&manifest_bytes)?;
    Ok(evaluate(manifest, current))
}

// ────────────────────────────────────────────────────────────────────────────
// Integrity: SHA-256
// ────────────────────────────────────────────────────────────────────────────

/// Lower-case hex SHA-256 of a byte slice.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Verify `bytes` matches `artifact.size` and `artifact.sha256`. The size check
/// is cheap and fails fast; the hash is the real integrity gate.
pub fn verify_artifact_integrity(bytes: &[u8], artifact: &Artifact) -> Result<()> {
    if bytes.len() as u64 != artifact.size {
        return Err(UpdateError::Integrity(format!(
            "size mismatch: got {} bytes, manifest says {}",
            bytes.len(),
            artifact.size
        )));
    }
    let got = sha256_hex(bytes);
    if !got.eq_ignore_ascii_case(artifact.sha256.trim()) {
        return Err(UpdateError::Integrity(format!(
            "sha256 mismatch: got {got}, manifest says {}",
            artifact.sha256
        )));
    }
    Ok(())
}

// ────────────────────────────────────────────────────────────────────────────
// Data-dir safety guard
// ────────────────────────────────────────────────────────────────────────────

/// Hard guard: the updater must NEVER write inside the wallet data dir
/// (keystore home). Any install/swap target is checked against
/// `config::wallet_data_root()` and rejected if it is the data dir or below it.
///
/// This is the structural guarantee behind "an app-swap preserves keys": the
/// install path is the app, the keystore is in a disjoint directory, and this
/// function makes that disjointness an enforced invariant rather than a hope.
pub fn assert_not_in_data_dir(target: &Path) -> Result<()> {
    let data_root = crate::config::wallet_data_root();
    // Compare canonicalized-where-possible absolute paths. The data root may not
    // exist yet on a brand-new install; fall back to the lexical path.
    let canon = |p: &Path| -> PathBuf { p.canonicalize().unwrap_or_else(|_| p.to_path_buf()) };
    let target_c = canon(target);
    let data_c = canon(&data_root);
    if target_c == data_c || target_c.starts_with(&data_c) {
        return Err(UpdateError::Safety(format!(
            "refusing to write update into the wallet data dir: target {} is inside {}",
            target_c.display(),
            data_c.display()
        )));
    }
    Ok(())
}

// ────────────────────────────────────────────────────────────────────────────
// Download + (macOS) ad-hoc sign + atomic swap + last-known-good / rollback
// ────────────────────────────────────────────────────────────────────────────

/// Download the artifact bytes and verify integrity (size + SHA-256) BEFORE
/// returning. The bytes are never written to disk by this function, so a failed
/// integrity check leaves nothing behind to accidentally execute.
pub fn download_and_verify(artifact: &Artifact) -> Result<Vec<u8>> {
    if artifact.size > MAX_ARTIFACT_BYTES {
        return Err(UpdateError::Integrity(format!(
            "manifest artifact size {} exceeds cap {}",
            artifact.size, MAX_ARTIFACT_BYTES
        )));
    }
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout_read(DOWNLOAD_READ_TIMEOUT)
        .https_only(true) // see agent(): TLS-only download path
        .user_agent(concat!("alice-miner-updater/", env!("CARGO_PKG_VERSION")))
        .build();
    // Read at most size+1 so an oversized body is detected, not silently
    // truncated to a hash-matching prefix.
    let bytes = http_get_bytes(&agent, &artifact.url, artifact.size.saturating_add(1))?;
    verify_artifact_integrity(&bytes, artifact)?;
    Ok(bytes)
}

/// Ad-hoc codesign a macOS bundle or binary, inner Mach-O first then the bundle
/// (NO reliance on `--deep`). On non-macOS this is a no-op success.
///
/// We re-implement the essential ordering of `scripts/adhoc_sign_macos.sh` so an
/// in-app update is runnable on Apple Silicon without shipping the script. If
/// the `scripts/adhoc_sign_macos.sh` helper is present next to the app we prefer
/// it (single source of truth); otherwise we fall back to inline `codesign`.
#[cfg(target_os = "macos")]
pub fn adhoc_codesign(app_path: &Path) -> Result<()> {
    use std::process::Command;

    // Sign every nested Mach-O inner-first. We locate them by walking the bundle
    // and asking `file` (cheap, no extra crate) which entries are Mach-O. The
    // main bundle is signed LAST so its seal covers the already-signed insides.
    let mut inner: Vec<PathBuf> = Vec::new();
    if app_path.is_dir() {
        collect_macho(app_path, app_path, &mut inner);
    }
    for bin in &inner {
        let status = Command::new("codesign")
            .args(["--force", "--timestamp=none", "-s", "-"])
            .arg(bin)
            .status()
            .map_err(|e| UpdateError::Codesign(format!("spawn codesign: {e}")))?;
        if !status.success() {
            return Err(UpdateError::Codesign(format!(
                "codesign failed for nested binary {}",
                bin.display()
            )));
        }
    }
    // Finally seal the bundle (or the bare binary).
    let status = Command::new("codesign")
        .args(["--force", "--timestamp=none", "-s", "-"])
        .arg(app_path)
        .status()
        .map_err(|e| UpdateError::Codesign(format!("spawn codesign: {e}")))?;
    if !status.success() {
        return Err(UpdateError::Codesign(format!(
            "codesign failed for {}",
            app_path.display()
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn adhoc_codesign(_app_path: &Path) -> Result<()> {
    Ok(())
}

/// Recursively collect nested Mach-O files under `root` (excluding `root`
/// itself), ordered deepest-first so they are signed before any parent.
#[cfg(target_os = "macos")]
fn collect_macho(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_macho(root, &path, out);
        } else if path != root && is_macho(&path) {
            out.push(path);
        }
    }
}

/// Cheap Mach-O sniff by magic number (no `file`/external dep): handles the
/// common 64-bit and fat/universal magics in both endiannesses.
#[cfg(target_os = "macos")]
fn is_macho(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    if f.read_exact(&mut magic).is_err() {
        return false;
    }
    let m = u32::from_be_bytes(magic);
    matches!(
        m,
        0xFEEDFACE // MH_MAGIC (32, BE)
        | 0xCEFAEDFE // MH_CIGAM (32, LE)
        | 0xFEEDFACF // MH_MAGIC_64 (BE)
        | 0xCFFAEDFE // MH_CIGAM_64 (LE)
        | 0xCAFEBABE // FAT_MAGIC
        | 0xBEBAFECA // FAT_CIGAM
    )
}

/// Atomically replace `current_path` with `staged_path`, preserving the old
/// version as last-known-good at `<current_path>.lkg` so a failed first launch
/// can roll back.
///
/// `current_path` is the live app location (a `.app` dir on macOS, a binary on
/// Linux/Windows). `assert_not_in_data_dir` is enforced on both paths first.
pub fn atomic_swap_with_backup(current_path: &Path, staged_path: &Path) -> Result<PathBuf> {
    assert_not_in_data_dir(current_path)?;
    assert_not_in_data_dir(staged_path)?;

    let lkg = lkg_path(current_path);
    // Clear any stale last-known-good from a prior update.
    let _ = remove_path(&lkg);

    // Move current -> lkg (preserve), then staged -> current. If the second move
    // fails, restore from lkg so we never leave the app missing.
    if current_path.exists() {
        std::fs::rename(current_path, &lkg)
            .map_err(|e| UpdateError::Io(format!("backup current app: {e}")))?;
    }
    if let Err(e) = std::fs::rename(staged_path, current_path) {
        // Roll back the backup into place.
        let _ = std::fs::rename(&lkg, current_path);
        return Err(UpdateError::Io(format!("install staged app: {e}")));
    }
    Ok(lkg)
}

/// Roll back a failed update: restore the last-known-good app saved by
/// [`atomic_swap_with_backup`], discarding the broken new version.
pub fn rollback(current_path: &Path) -> Result<()> {
    assert_not_in_data_dir(current_path)?;
    let lkg = lkg_path(current_path);
    if !lkg.exists() {
        return Err(UpdateError::Io(
            "no last-known-good backup to roll back to".into(),
        ));
    }
    // Remove the broken current, restore lkg.
    let _ = remove_path(current_path);
    std::fs::rename(&lkg, current_path)
        .map_err(|e| UpdateError::Io(format!("restore last-known-good: {e}")))?;
    Ok(())
}

/// Discard the last-known-good backup once the new version has proven healthy.
pub fn commit_update(current_path: &Path) -> Result<()> {
    let lkg = lkg_path(current_path);
    remove_path(&lkg)
}

fn lkg_path(current_path: &Path) -> PathBuf {
    let mut s = current_path.as_os_str().to_os_string();
    s.push(".lkg");
    PathBuf::from(s)
}

fn remove_path(p: &Path) -> Result<()> {
    if !p.exists() {
        return Ok(());
    }
    let r = if p.is_dir() {
        std::fs::remove_dir_all(p)
    } else {
        std::fs::remove_file(p)
    };
    r.map_err(|e| UpdateError::Io(format!("remove {}: {e}", p.display())))
}

// ────────────────────────────────────────────────────────────────────────────
// Live application location + end-to-end apply pipeline
// ────────────────────────────────────────────────────────────────────────────

/// The on-disk location this running build should replace on update.
///
/// * macOS: the enclosing `…/Foo.app` bundle of the running executable (the unit
///   we swap), falling back to the bare executable if not inside a `.app`.
/// * Linux/Windows: the running executable file itself.
///
/// The path is what [`atomic_swap_with_backup`] installs over, and it is checked
/// by [`assert_not_in_data_dir`] so the updater can never target the keystore.
pub fn current_app_path() -> Result<PathBuf> {
    let exe =
        std::env::current_exe().map_err(|e| UpdateError::Io(format!("locate current exe: {e}")))?;
    #[cfg(target_os = "macos")]
    {
        // …/AliceWallet.app/Contents/MacOS/AliceWallet -> …/AliceWallet.app
        if let Some(app) = enclosing_dot_app(&exe) {
            return Ok(app);
        }
    }
    Ok(exe)
}

/// Walk up from `exe` to the nearest ancestor directory whose name ends in
/// `.app`. Returns `None` if the executable is not inside a bundle.
#[cfg(target_os = "macos")]
fn enclosing_dot_app(exe: &Path) -> Option<PathBuf> {
    let mut cur = exe;
    while let Some(parent) = cur.parent() {
        if parent
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".app"))
        {
            return Some(parent.to_path_buf());
        }
        cur = parent;
    }
    None
}

/// Extract a verified release archive into `dest_dir` using the OS-native
/// extractor. The bytes have ALREADY passed SHA-256 verification before this is
/// called, so this only matters if the trust anchor (the ed25519 signing key) is
/// itself compromised — but as defense-in-depth (audit H-2 / zip-slip) we both
/// (a) **pre-scan** the archive's entry names and reject any `..` component or
/// absolute path BEFORE extracting, and (b) after extraction **sweep** the tree
/// and reject any path (regular or symlink) whose canonical location escapes
/// `dest_dir`. We deliberately do NOT pull a zip/tar crate into the dependency
/// surface; the same tools that PRODUCE these archives in `scripts/release.sh`
/// (`ditto -c -k`, `tar -czf`) extract them.
fn extract_archive(archive: &Path, dest_dir: &Path) -> Result<()> {
    use std::process::Command;
    std::fs::create_dir_all(dest_dir)
        .map_err(|e| UpdateError::Io(format!("create staging dir: {e}")))?;
    let name = archive
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let status = if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        // Pre-scan the tar listing for traversal/absolute entries before writing
        // anything (tar listing is reliable + cheap).
        prescan_tar_entries(archive)?;
        Command::new("tar")
            // --no-same-owner: don't honor archived uid/gid (defensive).
            .arg("--no-same-owner")
            .arg("-xzf")
            .arg(archive)
            .arg("-C")
            .arg(dest_dir)
            .status()
    } else if name.ends_with(".zip") {
        #[cfg(target_os = "macos")]
        {
            // `ditto -x -k` preserves macOS bundle metadata that `unzip` drops.
            // (No reliable pre-listing here; the post-extraction sweep below is
            // the guard for the zip path on macOS.)
            Command::new("ditto")
                .arg("-x")
                .arg("-k")
                .arg(archive)
                .arg(dest_dir)
                .status()
        }
        #[cfg(target_os = "windows")]
        {
            // `tar` ships in Windows 10+ and reads zip; avoids PowerShell quoting.
            prescan_tar_entries(archive)?;
            Command::new("tar")
                .arg("--no-same-owner")
                .arg("-xf")
                .arg(archive)
                .arg("-C")
                .arg(dest_dir)
                .status()
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            Command::new("unzip")
                .arg("-o")
                .arg(archive)
                .arg("-d")
                .arg(dest_dir)
                .status()
        }
    } else {
        return Err(UpdateError::Io(format!(
            "unknown archive type for {}",
            archive.display()
        )));
    };

    let status = status.map_err(|e| UpdateError::Io(format!("spawn extractor: {e}")))?;
    if !status.success() {
        return Err(UpdateError::Io(format!(
            "extractor failed for {}",
            archive.display()
        )));
    }

    // Post-extraction sweep: reject the whole staging dir if ANY extracted path
    // escapes it — a planted symlink (or a path the extractor placed outside via
    // a traversal we didn't pre-catch). This is the format-agnostic backstop.
    assert_no_escape(dest_dir)?;
    Ok(())
}

/// Reject an archive entry name that would escape the destination on extraction:
/// an absolute path, a Windows drive/UNC absolute, or any `..` path component.
/// Names are taken verbatim from the archive listing (untrusted).
fn entry_name_is_safe(entry: &str) -> bool {
    let e = entry.trim();
    if e.is_empty() {
        return true; // blank listing line — nothing to extract
    }
    // Absolute (unix `/…`, or windows `C:\…` / `\\unc`).
    if e.starts_with('/') || e.starts_with('\\') {
        return false;
    }
    let bytes = e.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return false; // drive-letter absolute
    }
    // Any `..` component (split on both separators).
    !e.split(['/', '\\']).any(|c| c == "..")
}

/// List a tar(.gz) archive and reject it if ANY entry is absolute or contains a
/// `..` component. Runs BEFORE extraction so a malicious archive writes nothing.
fn prescan_tar_entries(archive: &Path) -> Result<()> {
    use std::process::Command;
    let name = archive
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let mut cmd = Command::new("tar");
    if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        cmd.arg("-tzf");
    } else {
        cmd.arg("-tf");
    }
    let out = cmd
        .arg(archive)
        .output()
        .map_err(|e| UpdateError::Io(format!("list archive entries: {e}")))?;
    if !out.status.success() {
        return Err(UpdateError::Io(format!(
            "could not list archive entries for {}",
            archive.display()
        )));
    }
    let listing = String::from_utf8_lossy(&out.stdout);
    for entry in listing.lines() {
        if !entry_name_is_safe(entry) {
            return Err(UpdateError::Safety(format!(
                "refusing to extract archive: unsafe entry path {entry:?} (absolute or `..` traversal)"
            )));
        }
    }
    Ok(())
}

/// Walk `dir` after extraction and return a [`UpdateError::Safety`] if ANY entry
/// — regular file, directory, or symlink — resolves to a canonical path that is
/// NOT under `dir`. Catches zip-slip via symlinks and any traversal the
/// per-format pre-scan didn't cover. We compare canonicalized paths; a symlink
/// whose target points outside the staging root (even a dangling one, caught via
/// its lexical target) is rejected.
fn assert_no_escape(dir: &Path) -> Result<()> {
    let root = dir
        .canonicalize()
        .map_err(|e| UpdateError::Io(format!("canonicalize staging dir: {e}")))?;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(cur) = stack.pop() {
        let entries = match std::fs::read_dir(&cur) {
            Ok(e) => e,
            Err(e) => return Err(UpdateError::Io(format!("readdir during escape sweep: {e}"))),
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path)
                .map_err(|e| UpdateError::Io(format!("stat during escape sweep: {e}")))?;
            if meta.file_type().is_symlink() {
                // Resolve the link target relative to its parent dir and check it
                // stays under the staging root. A symlink pointing outside (e.g.
                // -> /etc or -> ../../foo) is rejected outright.
                let target = std::fs::read_link(&path)
                    .map_err(|e| UpdateError::Io(format!("read symlink: {e}")))?;
                let resolved = if target.is_absolute() {
                    target.clone()
                } else {
                    path.parent().unwrap_or(&root).join(&target)
                };
                let resolved_canon = resolved
                    .canonicalize()
                    .unwrap_or_else(|_| lexical_normalize(&resolved));
                if !resolved_canon.starts_with(&root) {
                    return Err(UpdateError::Safety(format!(
                        "refusing extracted archive: symlink {} -> {} escapes the staging dir",
                        path.display(),
                        target.display()
                    )));
                }
                // Do NOT descend through symlinks.
                continue;
            }
            // Regular file or dir: its canonical path must stay under the root.
            let canon = path
                .canonicalize()
                .map_err(|e| UpdateError::Io(format!("canonicalize extracted path: {e}")))?;
            if !canon.starts_with(&root) {
                return Err(UpdateError::Safety(format!(
                    "refusing extracted archive: {} resolves outside the staging dir",
                    path.display()
                )));
            }
            if meta.file_type().is_dir() {
                stack.push(path);
            }
        }
    }
    Ok(())
}

/// Lexically normalize a path (resolve `.`/`..` components without touching the
/// filesystem) — used as a fallback when a symlink target can't be canonicalized
/// (e.g. it's dangling), so an escaping dangling symlink is still caught.
fn lexical_normalize(p: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Find the freshly-extracted install unit inside `staging` that should replace
/// the live app at `current_path`.
///
/// * macOS: the first `*.app` bundle in the tree.
/// * Linux/Windows: an entry whose file name matches the current app's file
///   name (e.g. `AliceWallet` / `AliceWallet.exe`), else the lone regular file.
fn locate_staged_unit(staging: &Path, current_path: &Path) -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        if let Some(app) = find_dot_app(staging) {
            return Ok(app);
        }
    }
    let want = current_path.file_name();
    let mut only_file: Option<PathBuf> = None;
    let mut file_count = 0usize;
    let mut stack = vec![staging.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                if want.is_some() && path.file_name() == want {
                    return Ok(path);
                }
                file_count += 1;
                only_file = Some(path);
            }
        }
    }
    if file_count == 1 {
        if let Some(p) = only_file {
            return Ok(p);
        }
    }
    Err(UpdateError::Io(format!(
        "could not locate the installed app inside {}",
        staging.display()
    )))
}

/// First `*.app` bundle anywhere under `root` (breadth-first).
#[cfg(target_os = "macos")]
fn find_dot_app(root: &Path) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with(".app"))
                {
                    return Some(path);
                }
                stack.push(path);
            }
        }
    }
    None
}

/// Full apply pipeline for a verified update, run OFF the UI thread:
///
/// 1. [`download_and_verify`] the artifact (SHA-256 — done by the caller or here).
/// 2. Stage the archive to a temp dir OUTSIDE the data dir, extract it.
/// 3. Locate the inner `.app`/binary; on macOS [`adhoc_codesign`] it inner-first.
/// 4. [`atomic_swap_with_backup`] it over the live app, preserving last-known-good.
///
/// Returns the path of the now-installed live app plus its last-known-good backup
/// so the caller can health-check + [`commit_update`]/[`rollback`].
pub fn apply_update(artifact: &Artifact, verified_bytes: &[u8]) -> Result<AppliedUpdate> {
    let app_path = current_app_path()?;
    // Refuse before we touch the filesystem if the live app somehow resolves
    // inside the keystore dir (defense in depth; should never happen).
    assert_not_in_data_dir(&app_path)?;

    // Stage under a unique temp dir that is provably NOT the data dir.
    let stage_root = staging_root()?;
    assert_not_in_data_dir(&stage_root)?;
    let _ = remove_path(&stage_root);
    std::fs::create_dir_all(&stage_root)
        .map_err(|e| UpdateError::Io(format!("create staging root: {e}")))?;

    // Persist the (already integrity-checked) archive, then extract it.
    let archive_name = artifact
        .url
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("alice-wallet-update.bin");
    let archive_path = stage_root.join(archive_name);
    std::fs::write(&archive_path, verified_bytes)
        .map_err(|e| UpdateError::Io(format!("write staged archive: {e}")))?;
    // Re-verify integrity from disk: the bytes we extract MUST be the bytes we
    // verified (guards a TOCTOU on the staging file).
    let on_disk = std::fs::read(&archive_path)
        .map_err(|e| UpdateError::Io(format!("re-read staged archive: {e}")))?;
    verify_artifact_integrity(&on_disk, artifact)?;

    let extract_dir = stage_root.join("unpacked");
    extract_archive(&archive_path, &extract_dir)?;

    let staged_unit = locate_staged_unit(&extract_dir, &app_path)?;
    // Move the staged unit next to the live app first so the final swap is a
    // same-filesystem rename (atomic); cross-device renames would otherwise fail.
    let staged_beside = sibling_staged_path(&app_path);
    let _ = remove_path(&staged_beside);
    assert_not_in_data_dir(&staged_beside)?;
    move_path(&staged_unit, &staged_beside)?;

    // macOS: ad-hoc sign inner Mach-O first, then the bundle (no --deep).
    adhoc_codesign(&staged_beside)?;

    let lkg = atomic_swap_with_backup(&app_path, &staged_beside)?;

    // Best-effort cleanup of the staging tree (the installed app is elsewhere).
    let _ = remove_path(&stage_root);

    Ok(AppliedUpdate {
        app_path,
        last_known_good: lkg,
    })
}

/// Result of [`apply_update`]: the live app location and its preserved
/// last-known-good backup, for the health-check / rollback decision.
#[derive(Debug, Clone)]
pub struct AppliedUpdate {
    pub app_path: PathBuf,
    /// The preserved previous version (`<app>.lkg`). The relaunch path recovers
    /// it by convention via `rollback`/`register_launch`, so callers that only
    /// need to arm the health gate can ignore this; it is returned for tests and
    /// callers that want to inspect the backup directly.
    #[allow(dead_code)]
    pub last_known_good: PathBuf,
}

fn staging_root() -> Result<PathBuf> {
    Ok(std::env::temp_dir().join(format!(
        "alice-wallet-update-stage-{}-{}",
        std::process::id(),
        nanos()
    )))
}

fn sibling_staged_path(app_path: &Path) -> PathBuf {
    let mut s = app_path.as_os_str().to_os_string();
    s.push(".staged");
    PathBuf::from(s)
}

/// Move `src` to `dst`, preferring an atomic rename and falling back to a
/// recursive copy + remove across filesystems.
fn move_path(src: &Path, dst: &Path) -> Result<()> {
    if std::fs::rename(src, dst).is_ok() {
        return Ok(());
    }
    copy_recursive(src, dst)?;
    remove_path(src)
}

fn copy_recursive(src: &Path, dst: &Path) -> Result<()> {
    if src.is_dir() {
        std::fs::create_dir_all(dst)
            .map_err(|e| UpdateError::Io(format!("mkdir {}: {e}", dst.display())))?;
        let entries =
            std::fs::read_dir(src).map_err(|e| UpdateError::Io(format!("readdir: {e}")))?;
        for entry in entries.flatten() {
            let from = entry.path();
            let to = dst.join(entry.file_name());
            copy_recursive(&from, &to)?;
        }
        Ok(())
    } else {
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| UpdateError::Io(format!("mkdir parent: {e}")))?;
        }
        std::fs::copy(src, dst)
            .map(|_| ())
            .map_err(|e| UpdateError::Io(format!("copy {}: {e}", src.display())))
    }
}

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

// ────────────────────────────────────────────────────────────────────────────
// Relaunch + first-launch health gate (last-known-good rollback)
// ────────────────────────────────────────────────────────────────────────────
//
// The gate distinguishes "first run of the freshly-installed build" from "the
// new build already started once and we're back here" (a crash-on-launch loop).
// A marker JSON `{installed_version, attempt}` is written next to the app by the
// OLD build right before it relaunches into the new one. On startup the new
// build calls [`register_launch`]:
//   * marker absent                       -> Normal (nothing to do).
//   * marker.version == running, attempt 0 -> FreshFirstRun: bump to attempt 1,
//     leave the marker armed, and once the GUI proves healthy call
//     [`confirm_health_and_commit`] to clear it + drop last-known-good.
//   * marker.version == running, attempt>=1 -> the build came up before but
//     never confirmed health (it crashed): RolledBack to last-known-good.
//   * marker.version != running            -> stale/mismatched marker (e.g. a
//     rollback already happened): treat as Normal and clear it.

/// Marker recording which freshly-installed version is on its health probation
/// and how many times it has reached startup without confirming health.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct HealthMarker {
    installed_version: String,
    attempt: u32,
}

fn pending_marker(app_path: &Path) -> PathBuf {
    let mut s = app_path.as_os_str().to_os_string();
    s.push(".pending-health");
    PathBuf::from(s)
}

fn read_marker(app_path: &Path) -> Option<HealthMarker> {
    let bytes = std::fs::read(pending_marker(app_path)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_marker(app_path: &Path, marker: &HealthMarker) -> Result<()> {
    let bytes = serde_json::to_vec(marker)
        .map_err(|e| UpdateError::Io(format!("encode health marker: {e}")))?;
    std::fs::write(pending_marker(app_path), bytes)
        .map_err(|e| UpdateError::Io(format!("write health marker: {e}")))
}

/// Arm the first-launch health gate at attempt 0 (called by the OLD build right
/// before it relaunches into the freshly-installed `installed_version`).
pub fn arm_pending_health_check(app_path: &Path, installed_version: &str) -> Result<()> {
    write_marker(
        app_path,
        &HealthMarker {
            installed_version: installed_version.to_string(),
            attempt: 0,
        },
    )
}

/// `true` if a freshly-installed build is awaiting its first-launch health proof.
/// Public query for callers/tests; the GUI drives the gate via [`register_launch`]
/// + [`confirm_health_and_commit`] and does not need to poll this directly.
#[allow(dead_code)]
pub fn has_pending_health_check(app_path: &Path) -> bool {
    pending_marker(app_path).exists()
}

/// The decision returned by [`register_launch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchDecision {
    /// No update probation in effect — start normally.
    Normal,
    /// This IS the first run of a freshly-installed build; once healthy, the
    /// caller must invoke [`confirm_health_and_commit`].
    FreshFirstRun { version: String },
    /// The freshly-installed build failed (crash-on-launch); it was rolled back
    /// to last-known-good. The caller is now running the OLD build again.
    RolledBack { failed_version: String },
}

/// Resolve the health gate at startup. MUST be called once, early, before the
/// updater arms any new check. See the module note above for the state machine.
pub fn register_launch(app_path: &Path, running_version: &str) -> Result<LaunchDecision> {
    let Some(mut marker) = read_marker(app_path) else {
        return Ok(LaunchDecision::Normal);
    };

    if marker.installed_version != running_version {
        // Stale marker (a rollback or manual revert changed the running build).
        let _ = remove_path(&pending_marker(app_path));
        return Ok(LaunchDecision::Normal);
    }

    if marker.attempt == 0 {
        // First run of the new build: record the attempt and let it prove itself.
        marker.attempt = 1;
        write_marker(app_path, &marker)?;
        Ok(LaunchDecision::FreshFirstRun {
            version: running_version.to_string(),
        })
    } else {
        // We've been here before without a health confirmation: roll back.
        let _ = remove_path(&pending_marker(app_path));
        if lkg_path(app_path).exists() {
            rollback(app_path)?;
        }
        Ok(LaunchDecision::RolledBack {
            failed_version: running_version.to_string(),
        })
    }
}

/// Called once the GUI has come up far enough to be considered healthy: clears
/// the pending marker and discards the last-known-good backup. Returns whether a
/// pending update was confirmed (for surfacing a one-time "updated to vX" note).
pub fn confirm_health_and_commit(app_path: &Path) -> Result<bool> {
    let marker = pending_marker(app_path);
    if !marker.exists() {
        return Ok(false);
    }
    let _ = remove_path(&marker);
    // The new build is healthy: drop last-known-good.
    commit_update(app_path)?;
    Ok(true)
}

/// Relaunch the installed app and exit the current process. The caller arms the
/// health check first (so a crash on the new build rolls back next time). On
/// macOS we `open` the bundle; elsewhere we exec the binary directly.
pub fn relaunch(app_path: &Path) -> Result<()> {
    use std::process::Command;
    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg("-n")
            .arg(app_path)
            .spawn()
            .map_err(|e| UpdateError::Io(format!("relaunch (open): {e}")))?;
    }
    #[cfg(not(target_os = "macos"))]
    {
        Command::new(app_path)
            .spawn()
            .map_err(|e| UpdateError::Io(format!("relaunch: {e}")))?;
    }
    Ok(())
}

// ────────────────────────────────────────────────────────────────────────────
// Keystore format migration (backup-before-rewrite)
// ────────────────────────────────────────────────────────────────────────────

/// Migrate a keystore/metadata file in place while GUARANTEEING the prior bytes
/// are preserved first. This is the seam an update uses if a release changes an
/// on-disk format (e.g. `profiles.json` schema): we copy the existing file to a
/// timestamped `<name>.bak-<ts>` sibling BEFORE writing the migrated bytes, so a
/// failed/partial migration can never destroy the user's only copy.
///
/// The file lives in the wallet data dir, which the updater otherwise never
/// touches; this function is the single, explicit, tested exception and it only
/// ever *adds* a backup — it never deletes the keystore.
///
/// Not yet invoked by any shipped release (no on-disk format has changed since
/// this updater landed); it is the tested seam a future migrating release wires
/// to its post-update startup. Kept public so that release can call it without
/// reintroducing the backup-before-rewrite invariant from scratch.
#[allow(dead_code)]
pub fn migrate_keystore_in_place(path: &Path, migrated: &[u8]) -> Result<Option<PathBuf>> {
    let backup = if path.exists() {
        let original = std::fs::read(path)
            .map_err(|e| UpdateError::Io(format!("read keystore for backup: {e}")))?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("keystore");
        let bak = path.with_file_name(format!("{name}.bak-{}", nanos()));
        std::fs::write(&bak, &original)
            .map_err(|e| UpdateError::Io(format!("write keystore backup: {e}")))?;
        Some(bak)
    } else {
        None
    };

    // Write migrated bytes atomically via a temp file + rename so a crash mid
    // write leaves either the old file (already backed up) or the complete new.
    let tmp = path.with_extension("migrating.tmp");
    std::fs::write(&tmp, migrated)
        .map_err(|e| UpdateError::Io(format!("write migrated keystore: {e}")))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| UpdateError::Io(format!("commit migrated keystore: {e}")))?;
    Ok(backup)
}

// ────────────────────────────────────────────────────────────────────────────
// Tests — ALL signing here uses an EPHEMERAL deterministic test keypair. The
// real release private key is never read, used, or constructed.
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Shared, process-wide env lock (see `crate::config::TEST_ENV_LOCK`): tests
    /// that touch `ALICE_WALLET_DATA_ROOT` in ANY module serialize on this one,
    /// so a sibling test in another module can't change the data root mid-check.
    use crate::config::TEST_ENV_LOCK as DATA_ROOT_LOCK;

    /// Deterministic ephemeral test signing key — NOT the release key. Built
    /// from fixed bytes so tests are reproducible and need no RNG feature on
    /// `ed25519-dalek` in the production dependency.
    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn test_pubkey_b64() -> String {
        B64.encode(test_signing_key().verifying_key().to_bytes())
    }

    fn sign_b64(bytes: &[u8]) -> String {
        B64.encode(test_signing_key().sign(bytes).to_bytes())
    }

    fn sample_manifest() -> Manifest {
        Manifest {
            schema: 1,
            product: PRODUCT.to_string(),
            version: "1.4.0".to_string(),
            min_supported: "1.0.0".to_string(),
            released: "2026-06-02T00:00:00Z".to_string(),
            notes: "Test release.".to_string(),
            artifacts: vec![
                Artifact {
                    platform: "macos-arm64".to_string(),
                    url: "https://example.invalid/AliceWallet-macos-arm64.zip".to_string(),
                    sha256: "00".repeat(32),
                    size: 123,
                },
                Artifact {
                    platform: "linux-x86_64".to_string(),
                    url: "https://example.invalid/AliceWallet-linux-x86_64.tar.gz".to_string(),
                    sha256: "11".repeat(32),
                    size: 456,
                },
                Artifact {
                    platform: "windows-x86_64".to_string(),
                    url: "https://example.invalid/AliceWallet-windows-x86_64.zip".to_string(),
                    sha256: "22".repeat(32),
                    size: 789,
                },
            ],
        }
    }

    #[test]
    fn embedded_pubkey_is_valid_32_byte_ed25519() {
        // The shipped constant must parse — a typo would silently disable updates.
        let vk = embedded_verifying_key().expect("embedded pubkey must parse");
        assert_eq!(vk.to_bytes().len(), 32);
        assert_eq!(B64.decode(RELEASE_PUBKEY_B64).unwrap().len(), 32);
    }

    #[test]
    fn signer_verifier_roundtrip_matches_scheme() {
        // Sign the EXACT manifest bytes (raw ed25519, not pre-hashed) and verify
        // with the corresponding public key — the contract the offline signer
        // (`openssl pkeyutl -sign -rawin`) and the wallet must agree on.
        let manifest = sample_manifest();
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let sig = sign_b64(&bytes);
        let vk = verifying_key_from_b64(&test_pubkey_b64()).unwrap();
        verify_manifest_sig(&bytes, &sig, &vk).expect("valid signature must verify");
    }

    #[test]
    fn tampered_manifest_fails_verification() {
        let manifest = sample_manifest();
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let sig = sign_b64(&bytes);
        let vk = verifying_key_from_b64(&test_pubkey_b64()).unwrap();

        // Flip one byte of the message: signature must no longer verify.
        let mut tampered = bytes.clone();
        let last = tampered.len() - 2;
        tampered[last] ^= 0x01;
        assert!(verify_manifest_sig(&tampered, &sig, &vk).is_err());
    }

    #[test]
    fn wrong_key_fails_verification() {
        // A manifest signed by a DIFFERENT key must be rejected — this is the
        // fail-closed property of an embedded-key trust anchor.
        let manifest = sample_manifest();
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let sig = sign_b64(&bytes);

        let other_vk = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        assert!(verify_manifest_sig(&bytes, &sig, &other_vk).is_err());
    }

    #[test]
    fn version_ordering_and_no_downgrade() {
        assert!(is_newer("1.4.0", "1.3.9"));
        assert!(is_newer("1.4.1", "1.4.0"));
        assert!(is_newer("2.0.0", "1.99.99"));
        assert!(!is_newer("1.4.0", "1.4.0")); // equal is NOT newer (no-downgrade)
        assert!(!is_newer("1.3.0", "1.4.0")); // older is rejected
        assert!(is_newer("v1.4.0", "1.3.0")); // tolerate leading v
                                              // pre-release suffix is ignored for the release-line ordering
        assert_eq!(parse_version("1.4.0-rc1"), (1, 4, 0));
    }

    #[test]
    fn evaluate_up_to_date_when_equal_or_newer() {
        let m = sample_manifest(); // version 1.4.0
        assert!(matches!(
            evaluate(m.clone(), "1.4.0"),
            CheckOutcome::UpToDate { .. }
        ));
        assert!(matches!(
            evaluate(m, "1.5.0"),
            CheckOutcome::UpToDate { .. }
        ));
    }

    #[test]
    fn evaluate_update_available_for_known_platform() {
        let m = sample_manifest(); // ships macos/linux/windows
        match evaluate(m, "1.0.0") {
            CheckOutcome::UpdateAvailable { artifact, .. } => {
                assert_eq!(artifact.platform, current_platform());
            }
            // CI may run on a platform not in the sample — accept the no-artifact
            // branch too, but never claim up-to-date for an older version.
            CheckOutcome::UpdateAvailableNoArtifact { .. } => {
                assert!(
                    !matches!(
                        current_platform(),
                        "macos-arm64" | "linux-x86_64" | "windows-x86_64"
                    ) || current_platform() == "macos-x86_64"
                );
            }
            other => panic!("expected an update, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_unsupported_below_min() {
        let mut m = sample_manifest();
        m.min_supported = "1.2.0".to_string();
        match evaluate(m, "1.1.0") {
            CheckOutcome::Unsupported {
                min_supported,
                current,
                ..
            } => {
                assert_eq!(min_supported, "1.2.0");
                assert_eq!(current, "1.1.0");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn parse_verified_manifest_rejects_wrong_product_and_future_schema() {
        // Cross-product guard: this build is PRODUCT == "alice-miner", so a
        // manifest for the sibling product ("alice-wallet") signed by the SAME
        // key must be rejected here. (The Wallet build runs the mirror of this
        // test, rejecting "alice-miner".)
        let mut m = sample_manifest();
        m.product = "alice-wallet".to_string();
        let bytes = serde_json::to_vec(&m).unwrap();
        assert!(parse_verified_manifest(&bytes).is_err());

        let mut m2 = sample_manifest();
        m2.schema = SUPPORTED_SCHEMA + 1;
        let bytes2 = serde_json::to_vec(&m2).unwrap();
        assert!(parse_verified_manifest(&bytes2).is_err());
    }

    #[test]
    fn artifact_integrity_checks_size_and_hash() {
        let payload = b"alice-wallet test artifact bytes";
        let good = Artifact {
            platform: current_platform().to_string(),
            url: "https://example.invalid/a".to_string(),
            sha256: sha256_hex(payload),
            size: payload.len() as u64,
        };
        verify_artifact_integrity(payload, &good).expect("matching artifact must pass");

        // Wrong size.
        let mut bad_size = good.clone();
        bad_size.size += 1;
        assert!(verify_artifact_integrity(payload, &bad_size).is_err());

        // Wrong hash (corrupt/tampered download).
        let mut bad_hash = good.clone();
        bad_hash.sha256 = "ab".repeat(32);
        assert!(verify_artifact_integrity(payload, &bad_hash).is_err());

        // A single flipped byte in the payload is caught.
        let mut corrupt = payload.to_vec();
        corrupt[0] ^= 0xFF;
        assert!(verify_artifact_integrity(&corrupt, &good).is_err());
    }

    #[test]
    fn sha256_hex_is_lowercase_and_matches_known_vector() {
        // SHA-256("") known answer.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let h = sha256_hex(b"abc");
        assert_eq!(h, h.to_lowercase());
    }

    #[test]
    fn assert_not_in_data_dir_rejects_keystore_home() {
        let _lock = DATA_ROOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Pin our own data root so the check is hermetic and independent of the
        // host's real data dir (and of any sibling test that set the override).
        let pinned = std::env::temp_dir().join(format!(
            "alice-wallet-datadir-guard-{}-{}",
            std::process::id(),
            nanos()
        ));
        let _env = EnvGuard::set(crate::config::DATA_ROOT_ENV, &pinned);

        // The wallet data root itself, and any child of it, must be rejected as
        // an update target. This is the structural key-preservation guarantee.
        let data_root = crate::config::wallet_data_root();
        assert_eq!(
            data_root, pinned,
            "override must take effect under the lock"
        );
        assert!(super::assert_not_in_data_dir(&data_root).is_err());
        assert!(super::assert_not_in_data_dir(&data_root.join("wallet.json")).is_err());
        assert!(super::assert_not_in_data_dir(&data_root.join("nested/app")).is_err());

        // A sibling path OUTSIDE the (pinned) data dir is allowed.
        let outside = std::env::temp_dir().join("alice-wallet-update-target-xyz");
        assert!(super::assert_not_in_data_dir(&outside).is_ok());

        drop(_env);
    }

    #[test]
    fn atomic_swap_preserves_lkg_and_rolls_back() {
        // Simulate an app-swap entirely under a temp dir (NOT the data dir).
        let base = std::env::temp_dir().join(format!(
            "alice-wallet-swap-test-{}-{}",
            std::process::id(),
            nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let current = base.join("AliceWallet.app");
        let staged = base.join("AliceWallet.app.staged");
        std::fs::write(&current, b"OLD v1.0.0").unwrap();
        std::fs::write(&staged, b"NEW v1.4.0").unwrap();

        let lkg = atomic_swap_with_backup(&current, &staged).expect("swap ok");
        assert_eq!(std::fs::read(&current).unwrap(), b"NEW v1.4.0");
        assert_eq!(std::fs::read(&lkg).unwrap(), b"OLD v1.0.0");
        assert!(!staged.exists());

        // Roll back to the preserved old version.
        rollback(&current).expect("rollback ok");
        assert_eq!(std::fs::read(&current).unwrap(), b"OLD v1.0.0");
        assert!(!lkg.exists());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn commit_update_clears_backup() {
        let base = std::env::temp_dir().join(format!(
            "alice-wallet-commit-test-{}-{}",
            std::process::id(),
            nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let current = base.join("app");
        let staged = base.join("app.staged");
        std::fs::write(&current, b"old").unwrap();
        std::fs::write(&staged, b"new").unwrap();
        let lkg = atomic_swap_with_backup(&current, &staged).unwrap();
        assert!(lkg.exists());
        commit_update(&current).unwrap();
        assert!(!lkg.exists());
        assert_eq!(std::fs::read(&current).unwrap(), b"new");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn app_swap_leaves_keystore_files_untouched() {
        let _lock = DATA_ROOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Model the real on-disk layout: a data dir holding wallet.json +
        // profiles.json, and a SEPARATE app dir that gets swapped. The swap must
        // not read, move, or rewrite anything in the data dir.
        let base = std::env::temp_dir().join(format!(
            "alice-wallet-keep-keys-{}-{}",
            std::process::id(),
            nanos()
        ));
        let data_dir = base.join("data");
        let app_dir = base.join("Applications");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::create_dir_all(&app_dir).unwrap();

        let wallet = data_dir.join("wallet.json");
        let profiles = data_dir.join("profiles.json");
        let wallet_bytes = b"{\"version\":4,\"encrypted_seed\":\"KEEP-ME\"}";
        let profiles_bytes = b"{\"version\":1,\"profiles\":[]}";
        std::fs::write(&wallet, wallet_bytes).unwrap();
        std::fs::write(&profiles, profiles_bytes).unwrap();

        let current = app_dir.join("AliceWallet.app");
        let staged = app_dir.join("AliceWallet.app.staged");
        std::fs::write(&current, b"OLD APP").unwrap();
        std::fs::write(&staged, b"NEW APP").unwrap();

        // Point the data-dir guard at our temp data dir for the duration.
        let _env = EnvGuard::set(crate::config::DATA_ROOT_ENV, &data_dir);

        // The swap targets ONLY the app; both paths are outside the data dir.
        let lkg = atomic_swap_with_backup(&current, &staged).expect("swap ok");

        // App was replaced; keystore + profiles are byte-for-byte intact.
        assert_eq!(std::fs::read(&current).unwrap(), b"NEW APP");
        assert_eq!(std::fs::read(&wallet).unwrap(), wallet_bytes);
        assert_eq!(std::fs::read(&profiles).unwrap(), profiles_bytes);
        // Last-known-good is the old app, also outside the data dir.
        assert!(lkg.starts_with(&app_dir));
        assert!(!lkg.starts_with(&data_dir));

        drop(_env);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn apply_refuses_to_target_a_data_dir_app() {
        let _lock = DATA_ROOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // If the running app somehow lived inside the data dir, the guard must
        // stop the swap before any bytes move.
        let base = std::env::temp_dir().join(format!(
            "alice-wallet-guarded-{}-{}",
            std::process::id(),
            nanos()
        ));
        let data_dir = base.join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let _env = EnvGuard::set(crate::config::DATA_ROOT_ENV, &data_dir);

        let current = data_dir.join("AliceWallet.app"); // INSIDE the data dir
        let staged = base.join("AliceWallet.app.staged");
        std::fs::write(&current, b"OLD").unwrap();
        std::fs::write(&staged, b"NEW").unwrap();

        let err = atomic_swap_with_backup(&current, &staged);
        assert!(matches!(err, Err(UpdateError::Safety(_))));
        // Nothing was swapped.
        assert_eq!(std::fs::read(&current).unwrap(), b"OLD");

        drop(_env);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn keystore_migration_backs_up_before_rewriting() {
        // A format migration must preserve the original bytes BEFORE writing the
        // migrated ones, so a botched migration can always be recovered.
        let base = std::env::temp_dir().join(format!(
            "alice-wallet-migrate-{}-{}",
            std::process::id(),
            nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let keystore = base.join("profiles.json");
        let old_bytes = br#"{"version":1,"profiles":["legacy"]}"#;
        let new_bytes = br#"{"version":2,"profiles":["migrated"]}"#;
        std::fs::write(&keystore, old_bytes).unwrap();

        let backup = migrate_keystore_in_place(&keystore, new_bytes)
            .expect("migration ok")
            .expect("a pre-existing file must be backed up");

        // New content is in place…
        assert_eq!(std::fs::read(&keystore).unwrap(), new_bytes);
        // …and the ORIGINAL bytes survive in the backup.
        assert_eq!(std::fs::read(&backup).unwrap(), old_bytes);
        assert!(backup
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap()
            .starts_with("profiles.json.bak-"));

        // Migrating a non-existent file writes it with no backup.
        let fresh = base.join("new-store.json");
        let backup2 = migrate_keystore_in_place(&fresh, new_bytes).unwrap();
        assert!(backup2.is_none());
        assert_eq!(std::fs::read(&fresh).unwrap(), new_bytes);

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn pending_health_gate_commits_on_success_and_rolls_back_on_failure() {
        let base = std::env::temp_dir().join(format!(
            "alice-wallet-health-{}-{}",
            std::process::id(),
            nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let app = base.join("AliceWallet.app");
        let staged = base.join("AliceWallet.app.staged");

        // ── Success path: OLD(1.0.0) installs NEW(1.4.0), arms gate, relaunches.
        std::fs::write(&app, b"OLD-1.0.0").unwrap();
        std::fs::write(&staged, b"NEW-1.4.0").unwrap();
        let lkg = atomic_swap_with_backup(&app, &staged).unwrap();
        arm_pending_health_check(&app, "1.4.0").unwrap();
        assert!(has_pending_health_check(&app));
        // First run of the new build: NOT rolled back; given a chance to prove out.
        let decision = register_launch(&app, "1.4.0").unwrap();
        assert_eq!(
            decision,
            LaunchDecision::FreshFirstRun {
                version: "1.4.0".to_string()
            }
        );
        assert!(
            has_pending_health_check(&app),
            "marker still armed at attempt 1"
        );
        assert_eq!(std::fs::read(&app).unwrap(), b"NEW-1.4.0");
        // GUI proves healthy -> commit + drop last-known-good.
        let confirmed = confirm_health_and_commit(&app).unwrap();
        assert!(confirmed);
        assert!(!has_pending_health_check(&app));
        assert!(!lkg.exists(), "healthy update drops last-known-good");

        // ── Failure path: OLD(1.4.0) installs NEWER(1.5.0) that crashes on launch.
        std::fs::write(&staged, b"NEWER-1.5.0-BROKEN").unwrap();
        let lkg2 = atomic_swap_with_backup(&app, &staged).unwrap();
        assert_eq!(std::fs::read(&lkg2).unwrap(), b"NEW-1.4.0");
        arm_pending_health_check(&app, "1.5.0").unwrap();
        // First run of 1.5.0: it gets one chance (no rollback yet), then crashes.
        let d1 = register_launch(&app, "1.5.0").unwrap();
        assert_eq!(
            d1,
            LaunchDecision::FreshFirstRun {
                version: "1.5.0".to_string()
            }
        );
        // It crashed before confirming; the user relaunches and we land here again.
        let d2 = register_launch(&app, "1.5.0").unwrap();
        assert_eq!(
            d2,
            LaunchDecision::RolledBack {
                failed_version: "1.5.0".to_string()
            }
        );
        assert!(!has_pending_health_check(&app));
        assert_eq!(
            std::fs::read(&app).unwrap(),
            b"NEW-1.4.0",
            "rolled back to last-known-good"
        );

        // ── Stale marker: version mismatch is cleared, no rollback.
        std::fs::write(&staged, b"X").unwrap();
        let _ = atomic_swap_with_backup(&app, &staged).unwrap();
        arm_pending_health_check(&app, "9.9.9").unwrap();
        let d3 = register_launch(&app, "1.4.0").unwrap(); // running != marker
        assert_eq!(d3, LaunchDecision::Normal);
        assert!(!has_pending_health_check(&app));

        let _ = std::fs::remove_dir_all(&base);
    }

    // ── Zip-slip / extraction safety (audit H-2) ─────────────────────────────

    #[test]
    fn entry_name_safety_rejects_traversal_and_absolute() {
        // Safe relative names.
        assert!(entry_name_is_safe("app/bin/alice-miner"));
        assert!(entry_name_is_safe("./AliceMiner.app/Contents/MacOS/x"));
        assert!(entry_name_is_safe("")); // blank listing line
        // Absolute (unix / windows drive / UNC) → rejected.
        assert!(!entry_name_is_safe("/etc/passwd"));
        assert!(!entry_name_is_safe("C:\\Windows\\System32\\evil.dll"));
        assert!(!entry_name_is_safe("\\\\server\\share\\x"));
        // Any `..` component → rejected (both separators).
        assert!(!entry_name_is_safe("../../etc/cron.d/evil"));
        assert!(!entry_name_is_safe("a/b/../../../../tmp/x"));
        assert!(!entry_name_is_safe("a\\..\\..\\x"));
    }

    /// Build a single 512-byte `ustar` header block for `name` with a `size`-byte
    /// regular-file body, computing the header checksum exactly as the format
    /// requires. This lets a test author an archive with ANY entry name —
    /// including a `../escape.txt` traversal — WITHOUT relying on a tar flag
    /// (`--transform` is GNU-only; bsdtar's `-s` rename is unreliable for `..`).
    /// The result is platform-independent and feeds the real `tar -xzf` path.
    fn ustar_header(name: &str, size: usize) -> [u8; 512] {
        let mut h = [0u8; 512];
        let nb = name.as_bytes();
        // name[0..100]
        h[..nb.len()].copy_from_slice(nb);
        // mode (octal, NUL-terminated) at 100..108
        h[100..108].copy_from_slice(b"0000644\0");
        // uid / gid at 108..116, 116..124
        h[108..116].copy_from_slice(b"0000000\0");
        h[116..124].copy_from_slice(b"0000000\0");
        // size (octal) at 124..136 — 11 octal digits + NUL
        let sz = format!("{size:011o}\0");
        h[124..136].copy_from_slice(sz.as_bytes());
        // mtime at 136..148
        h[136..148].copy_from_slice(b"00000000000\0");
        // typeflag '0' (regular file) at 156
        h[156] = b'0';
        // magic "ustar\0" + version "00" at 257..265
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        // checksum field (148..156): compute with the field filled with spaces.
        h[148..156].copy_from_slice(b"        ");
        let sum: u32 = h.iter().map(|&b| b as u32).sum();
        // 6 octal digits, NUL, then space (the canonical ustar layout).
        let chk = format!("{sum:06o}\0 ");
        h[148..156].copy_from_slice(chk.as_bytes());
        h
    }

    /// Author a gzip-compressed tar that contains exactly one entry named `name`
    /// (e.g. `../escape.txt`) with `body`, by writing a raw ustar stream and
    /// piping it through the system `gzip` (present on macOS/Linux/CI). Returns
    /// `false` only if `gzip` is unavailable (then the caller skips, still
    /// covered by the unit-level `entry_name_is_safe` test). No tar-flag
    /// dependency, so the malicious `..` entry exists on every platform.
    fn write_malicious_tar_gz(archive: &Path, name: &str, body: &[u8]) -> bool {
        use std::io::Write;
        // Raw tar = header(512) + body padded to 512 + two zero blocks (EOF).
        let mut tar = Vec::new();
        tar.extend_from_slice(&ustar_header(name, body.len()));
        tar.extend_from_slice(body);
        let pad = (512 - (body.len() % 512)) % 512;
        tar.extend(std::iter::repeat_n(0u8, pad));
        tar.extend(std::iter::repeat_n(0u8, 1024)); // two 512-byte zero blocks
        // gzip the raw tar via the CLI (no flate2 dependency).
        let mut child = match std::process::Command::new("gzip")
            .arg("-c")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => return false, // gzip absent → caller skips
        };
        child.stdin.take().unwrap().write_all(&tar).unwrap();
        let out = child.wait_with_output().unwrap();
        if !out.status.success() {
            return false;
        }
        std::fs::write(archive, &out.stdout).unwrap();
        true
    }

    #[test]
    fn prescan_rejects_a_traversal_tar_before_extracting() {
        // Build a tar.gz that contains a `../escape.txt` entry (portably, with no
        // GNU-only `--transform`) and confirm the pre-scan refuses it (no
        // extraction performed). Coverage holds on macOS bsdtar too.
        let base = std::env::temp_dir().join(format!(
            "alice-zipslip-tar-{}-{}",
            std::process::id(),
            nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let archive = base.join("evil.tar.gz");
        let made = write_malicious_tar_gz(&archive, "../escape.txt", b"pwned");
        if made {
            let dest = base.join("unpack");
            let err = extract_archive(&archive, &dest)
                .expect_err("a `..` tar entry must be refused");
            assert!(
                matches!(err, UpdateError::Safety(_)),
                "expected a Safety refusal, got {err:?}"
            );
            // Nothing escaped to the parent.
            assert!(!base.join("escape.txt").exists());
        } else {
            eprintln!("skipping: `gzip` not available to author the malicious fixture");
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn escape_sweep_rejects_a_symlink_pointing_outside() {
        // A staging dir containing a symlink to /etc must be rejected by the
        // post-extraction sweep (the zip-slip-via-symlink case).
        let base = std::env::temp_dir().join(format!(
            "alice-zipslip-link-{}-{}",
            std::process::id(),
            nanos()
        ));
        let staging = base.join("unpacked");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("real.txt"), b"ok").unwrap();
        std::os::unix::fs::symlink("/etc", staging.join("escape")).unwrap();
        let err = assert_no_escape(&staging).expect_err("symlink to /etc must be rejected");
        assert!(matches!(err, UpdateError::Safety(_)), "got {err:?}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn escape_sweep_allows_an_internal_symlink() {
        // A symlink that stays INSIDE the staging tree is fine (e.g. a bundle's
        // internal `Current -> A` framework link).
        let base = std::env::temp_dir().join(format!(
            "alice-zipslip-ok-{}-{}",
            std::process::id(),
            nanos()
        ));
        let staging = base.join("unpacked");
        std::fs::create_dir_all(staging.join("A")).unwrap();
        std::fs::write(staging.join("A/lib"), b"x").unwrap();
        std::os::unix::fs::symlink("A", staging.join("Current")).unwrap();
        assert_no_escape(&staging).expect("an internal symlink must be allowed");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn extract_archive_round_trips_a_clean_tar() {
        // A normal, well-formed tar.gz extracts and passes the escape sweep.
        let base = std::env::temp_dir().join(format!(
            "alice-extract-ok-{}-{}",
            std::process::id(),
            nanos()
        ));
        let src = base.join("src");
        std::fs::create_dir_all(src.join("bin")).unwrap();
        std::fs::write(src.join("bin/app"), b"#!/bin/sh\necho hi\n").unwrap();
        let archive = base.join("clean.tar.gz");
        let ok = std::process::Command::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&src)
            .arg("bin")
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(ok, "tar must produce the test archive");
        let dest = base.join("out");
        extract_archive(&archive, &dest).expect("clean archive extracts");
        assert!(dest.join("bin/app").is_file(), "extracted the file");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Scoped environment-variable guard so data-dir tests don't leak the
    /// override into sibling tests run in the same process.
    struct EnvGuard {
        key: &'static str,
        prev: Option<std::ffi::OsString>,
    }
    impl EnvGuard {
        fn set(key: &'static str, val: &Path) -> Self {
            let prev = std::env::var_os(key);
            std::env::set_var(key, val);
            Self { key, prev }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }
}
