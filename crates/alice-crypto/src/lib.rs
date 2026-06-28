//! Shared Alice keystore / sr25519 crypto.
//!
//! The body of this module is lifted **verbatim** from the reviewed/audited
//! `alice-wallet/gui/src/crypto.rs` (SS58_FORMAT=300, V4 keystore, Argon2id KDF,
//! AES-256-GCM with version+address AAD). The ONLY edits versus the Wallet are:
//!   * an inlined `config` module (below) providing the two data-root helpers
//!     the original referenced as `crate::config::*`, copied byte-identically
//!     from `alice-wallet/gui/src/config.rs` so the keystore path resolution
//!     (`$ALICE_WALLET_DATA_ROOT` or `data_local_dir()/AliceWallet`) is the
//!     same — this is what keeps the keystore parity the M0 gate proves; and
//!   * the net-new `generate_mnemonic()` helper at the bottom (24 words / 32-byte
//!     entropy, `Zeroizing`) lifted from `alice-wallet/gui/src/ui/create.rs`.
//!
//! The cryptographic logic is byte-for-byte the Wallet's. Do NOT rewrite it.

/// Inlined copy of the subset of `alice-wallet/gui/src/config.rs` that
/// `crypto.rs` depends on (`wallet_data_root`, `wallet_data_root_is_overridden`,
/// `DATA_ROOT_ENV`). Copied verbatim so the keystore lives at the identical path
/// in both apps.
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

    pub fn wallet_data_root_is_overridden() -> bool {
        wallet_data_root_override().is_some()
    }

    fn wallet_data_root_override() -> Option<PathBuf> {
        std::env::var(DATA_ROOT_ENV)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    }
}

// `config` below refers to the inlined module above (was `use crate::config;`
// in the Wallet, where it pointed at the external `gui::config` module).
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as b64, Engine};
use blake2::{Blake2b512, Digest};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use subxt_signer::sr25519::Keypair as Sr25519Keypair;
use zeroize::{Zeroize, Zeroizing};

pub const MIN_LEGACY_PBKDF2_ITERATIONS: u32 = 200_000;
// Argon2id time cost (t) for NEW wallets. Decryption uses the per-wallet KDF
// params stored in `WalletPayload` (see `derive_wallet_key`), so bumping this
// only strengthens newly created/upgraded wallets; existing wallets that were
// written with t=2 still unlock using their stored `kdf_iterations`.
pub const ARGON2_ITERATIONS: u32 = 3;
pub const ARGON2_MEMORY_KIB: u32 = 19_456;
pub const ARGON2_PARALLELISM: u32 = 1;
pub const SS58_FORMAT: u16 = 300;
pub const WALLET_VERSION_V2: u32 = 2;
pub const WALLET_VERSION_V3: u32 = 3;
// v4 binds AES-GCM associated data (wallet version + address) to every
// ciphertext. v2/v3 wallets were written without AAD and must keep decrypting
// without it; see `aad_for_payload` for the version gate.
pub const WALLET_VERSION_V4: u32 = 4;
pub const CURRENT_WALLET_VERSION: u32 = WALLET_VERSION_V4;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WalletPayload {
    pub version: u32,
    pub address: String,
    pub public_key: String,
    pub encrypted_seed: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_mnemonic: Option<String>,
    pub salt: String,
    pub nonce_seed: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_mnemonic: Option<String>,
    pub kdf: String,
    pub kdf_iterations: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_memory_kib: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_parallelism: Option<u32>,
}

struct SecretSeed {
    bytes: [u8; 32],
}

impl SecretSeed {
    fn from_slice(seed_bytes: &[u8]) -> Result<Self, String> {
        if seed_bytes.len() != 32 {
            return Err("Seed length mismatch".into());
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(seed_bytes);
        Ok(Self { bytes })
    }

    fn expose(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl Drop for SecretSeed {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[derive(Clone)]
pub struct WalletSecrets {
    pub address: String,
    seed: Option<Arc<SecretSeed>>,
}

impl Drop for WalletSecrets {
    fn drop(&mut self) {
        // The 32-byte secret seed lives behind `Arc<SecretSeed>` and is wiped by
        // `SecretSeed::drop` only when the last clone is released, so we must NOT
        // reach through the `Arc` here. We do zeroize the non-`Arc` `address`
        // string on every drop (defense-in-depth): each clone owns its own
        // `String` allocation, so wiping it cannot corrupt sibling clones.
        self.address.zeroize();
    }
}

impl WalletSecrets {
    pub fn display_only(address: impl Into<String>) -> Self {
        Self {
            address: address.into(),
            seed: None,
        }
    }

    pub fn to_keypair(&self) -> Result<Sr25519Keypair, String> {
        let Some(seed) = self.seed.as_ref() else {
            return Err("Signing is unavailable in display-only wallet preview.".into());
        };
        Sr25519Keypair::from_secret_key(*seed.expose()).map_err(|e| e.to_string())
    }

    pub fn can_export_private_key(&self) -> bool {
        self.seed.is_some()
    }

    pub fn export_private_key_hex(&self) -> Option<String> {
        self.seed
            .as_ref()
            .map(|seed| format!("0x{}", hex::encode(seed.expose())))
    }
}

pub struct UnlockOutcome {
    pub secrets: WalletSecrets,
    pub upgraded_payload: Option<WalletPayload>,
}

pub fn default_wallet_path() -> PathBuf {
    config::wallet_data_root().join("wallet.json")
}

pub fn detect_wallet_path() -> PathBuf {
    let primary = default_wallet_path();
    if primary.exists() {
        return primary;
    }

    if config::wallet_data_root_is_overridden() {
        return primary;
    }

    let legacy = legacy_wallet_path();
    if legacy.exists() {
        return legacy;
    }

    primary
}

/// How many `<name>.bak-<ts>` backups to keep per keystore. Every
/// create/import/re-key renames the live keystore to a fresh timestamped
/// `.bak-…` recovery copy; without a bound these pile up indefinitely (60+ were
/// observed in `~/.alice/` after a single day of identity churn). We keep the
/// N most recent and prune the rest. The backup-before-write safety net is
/// preserved — only the count is bounded.
const KEYSTORE_BACKUP_RETENTION: usize = 5;

/// Rename any existing wallet file to `wallet.json.bak-<timestamp>` so that an
/// import/overwrite can never destroy an old wallet silently.
///
/// After making the new backup we prune older `<name>.bak-*` siblings down to
/// [`KEYSTORE_BACKUP_RETENTION`] (best-effort: a prune failure is swallowed and
/// never fails the backup itself).
pub fn backup_existing_wallet(path: &Path) -> Result<Option<PathBuf>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("wallet.json");
    let backup = path.with_file_name(format!("{}.bak-{}", file_name, ts));
    fs::rename(path, &backup).map_err(|e| format!("Failed to back up existing wallet: {}", e))?;

    // Best-effort, fail-soft: bound the number of retained backups. A pruning
    // error must NEVER fail the write that just succeeded above.
    prune_old_backups(path, KEYSTORE_BACKUP_RETENTION);

    Ok(Some(backup))
}

/// Delete the oldest `<name>.bak-*` siblings of `keystore_path`, keeping the
/// `keep` most recent. Best-effort: any IO error (unreadable dir, undeletable
/// file) is silently ignored so this can never fail the keystore write.
///
/// SAFETY: only files whose name is EXACTLY `<live-name>.bak-<...>` are ever
/// considered — the live keystore itself and any unrelated file are never
/// touched. Ordering is by the numeric `<ts>` suffix (falling back to lexical
/// order for any non-numeric suffix), so the newest backups survive.
fn prune_old_backups(keystore_path: &Path, keep: usize) {
    let Some(dir) = keystore_path.parent() else {
        return;
    };
    let Some(live_name) = keystore_path.file_name().and_then(|n| n.to_str()) else {
        return;
    };
    let prefix = format!("{live_name}.bak-");

    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };

    // Collect (sort_key, path) for every matching backup. We sort by the numeric
    // timestamp suffix when it parses, else fall back to the raw suffix string so
    // ordering stays deterministic.
    let mut backups: Vec<(u64, String, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        // Match ONLY `<live-name>.bak-…` — never the live keystore or other files.
        let Some(suffix) = name.strip_prefix(&prefix) else {
            continue;
        };
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let ts = suffix.parse::<u64>().unwrap_or(0);
        backups.push((ts, suffix.to_string(), entry.path()));
    }

    if backups.len() <= keep {
        return;
    }

    // Newest first (higher ts first; tie-break on the raw suffix descending).
    backups.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));

    // Everything past the `keep` newest is pruned (fail-soft per file).
    for (_, _, stale) in backups.into_iter().skip(keep) {
        let _ = fs::remove_file(&stale);
    }
}

pub fn write_wallet_payload(path: &Path, payload: &WalletPayload) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create wallet directory: {}", e))?;
    }

    let encoded = serde_json::to_vec_pretty(payload)
        .map_err(|e| format!("Failed to serialize wallet payload: {}", e))?;
    let tmp_path = temporary_wallet_path(path);

    let mut file = create_wallet_file(&tmp_path)?;
    file.write_all(&encoded)
        .map_err(|e| format!("Failed to write wallet file: {}", e))?;
    file.flush()
        .map_err(|e| format!("Failed to flush wallet file: {}", e))?;
    file.sync_all()
        .map_err(|e| format!("Failed to sync wallet file: {}", e))?;
    drop(file);

    persist_wallet_file(&tmp_path, path)?;

    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if let Ok(dir) = OpenOptions::new().read(true).open(parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(())
}

pub fn unlock_wallet(payload: &WalletPayload, password: &str) -> Result<UnlockOutcome, String> {
    if !matches!(
        payload.version,
        WALLET_VERSION_V2 | WALLET_VERSION_V3 | WALLET_VERSION_V4
    ) {
        return Err(format!("Unsupported wallet version: {}", payload.version));
    }

    let salt = b64.decode(&payload.salt).map_err(|_| "Invalid salt")?;
    // AAD is derived from the stored version+address: empty for pre-v4 wallets
    // (so legacy ciphertexts still decrypt), bound for v4+.
    let aad = aad_for_payload(payload.version, &payload.address);
    let mut key = derive_wallet_key(payload, password, &salt)?;
    let seed_bytes = decrypt_blob(&payload.encrypted_seed, &payload.nonce_seed, &key, &aad)?;

    let seed = SecretSeed::from_slice(&seed_bytes)?;
    let keypair = Sr25519Keypair::from_secret_key(*seed.expose()).map_err(|e| e.to_string())?;
    verify_identity(payload, &keypair)?;

    if let (Some(enc_mnemonic), Some(nonce_mnemonic)) =
        (&payload.encrypted_mnemonic, &payload.nonce_mnemonic)
    {
        let mut decrypted = decrypt_blob(enc_mnemonic, nonce_mnemonic, &key, &aad)?;
        let mnemonic =
            std::str::from_utf8(&decrypted).map_err(|_| "Mnemonic is not valid UTF-8")?;
        let mnemonic_pair = keypair_from_phrase(mnemonic)?;
        decrypted.zeroize();
        if mnemonic_pair.public_key().0 != keypair.public_key().0 {
            return Err("Mnemonic does not match wallet seed".into());
        }
    }

    key.zeroize();

    let upgraded_payload = if payload_needs_upgrade(payload) {
        Some(create_wallet_payload_from_seed(seed.expose(), password)?)
    } else {
        None
    };

    Ok(UnlockOutcome {
        secrets: WalletSecrets {
            address: payload.address.clone(),
            seed: Some(Arc::new(seed)),
        },
        upgraded_payload,
    })
}

pub fn qa_display_address() -> String {
    account_id_to_ss58(&[0x42u8; 32], SS58_FORMAT)
}

pub fn qa_display_address_variant(byte: u8) -> String {
    account_id_to_ss58(&[byte; 32], SS58_FORMAT)
}

pub fn create_wallet_payload(mnemonic: &str, password: &str) -> Result<WalletPayload, String> {
    let seed_bytes = substrate_seed_from_phrase(mnemonic)?;
    let keypair = Sr25519Keypair::from_secret_key(seed_bytes).map_err(|e| e.to_string())?;
    create_wallet_payload_from_keypair(&keypair, &seed_bytes, password)
}

/// Build a wallet payload from a raw 32-byte sr25519 secret seed (hex,
/// optionally `0x` prefixed). Used for the "Import raw private key" path.
pub fn create_wallet_payload_from_seed_hex(
    seed_hex: &str,
    password: &str,
) -> Result<WalletPayload, String> {
    let trimmed = seed_hex
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    if trimmed.len() != 64 {
        return Err("Seed must be 0x + 64 hex characters (32 bytes)".into());
    }
    let mut bytes_vec =
        hex::decode(trimmed).map_err(|_| "Seed contains invalid hex characters".to_string())?;
    if bytes_vec.len() != 32 {
        bytes_vec.zeroize();
        return Err("Decoded seed length is not 32 bytes".into());
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes_vec);
    bytes_vec.zeroize();
    let result = create_wallet_payload_from_seed(&seed, password);
    seed.zeroize();
    result
}

fn create_wallet_payload_from_seed(
    seed_bytes: &[u8; 32],
    password: &str,
) -> Result<WalletPayload, String> {
    let keypair = Sr25519Keypair::from_secret_key(*seed_bytes).map_err(|e| e.to_string())?;
    create_wallet_payload_from_keypair(&keypair, seed_bytes, password)
}

fn create_wallet_payload_from_keypair(
    keypair: &Sr25519Keypair,
    seed_bytes: &[u8],
    password: &str,
) -> Result<WalletPayload, String> {
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);

    let mut key = derive_argon2id_key(
        password,
        &salt,
        ARGON2_ITERATIONS,
        ARGON2_MEMORY_KIB,
        ARGON2_PARALLELISM,
    )?;
    let address = account_id_to_ss58(&keypair.public_key().0, SS58_FORMAT);
    let aad = aad_for_payload(CURRENT_WALLET_VERSION, &address);
    let (encrypted_seed, nonce_seed) = encrypt_blob(seed_bytes, &key, &aad)?;
    key.zeroize();

    Ok(WalletPayload {
        version: CURRENT_WALLET_VERSION,
        address,
        public_key: format!("0x{}", hex::encode(keypair.public_key().0)),
        encrypted_seed,
        encrypted_mnemonic: None,
        salt: b64.encode(salt),
        nonce_seed,
        nonce_mnemonic: None,
        kdf: "argon2id".into(),
        kdf_iterations: ARGON2_ITERATIONS,
        kdf_memory_kib: Some(ARGON2_MEMORY_KIB),
        kdf_parallelism: Some(ARGON2_PARALLELISM),
    })
}

fn derive_wallet_key(
    payload: &WalletPayload,
    password: &str,
    salt: &[u8],
) -> Result<[u8; 32], String> {
    match payload.kdf.as_str() {
        "pbkdf2-sha256" => Ok(derive_pbkdf2_key(
            password,
            salt,
            payload.kdf_iterations.max(MIN_LEGACY_PBKDF2_ITERATIONS),
        )),
        "argon2id" => derive_argon2id_key(
            password,
            salt,
            payload.kdf_iterations.max(1),
            payload.kdf_memory_kib.unwrap_or(ARGON2_MEMORY_KIB),
            payload.kdf_parallelism.unwrap_or(ARGON2_PARALLELISM),
        ),
        other => Err(format!("Unsupported KDF: {}", other)),
    }
}

fn derive_pbkdf2_key(password: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut key);
    key
}

fn derive_argon2id_key(
    password: &str,
    salt: &[u8],
    iterations: u32,
    memory_kib: u32,
    parallelism: u32,
) -> Result<[u8; 32], String> {
    let params = Params::new(memory_kib, iterations, parallelism, Some(32))
        .map_err(|e| format!("Invalid Argon2 parameters: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Argon2 derivation failed: {}", e))?;
    Ok(key)
}

/// Build the AES-GCM associated data (AAD) for a wallet of the given version.
///
/// Backward-compat gate: wallets written before v4 were encrypted with no AAD,
/// so they must keep decrypting with an empty AAD (which is byte-identical to
/// "no AAD" in AES-GCM). From v4 onward we bind the wallet version and address
/// into the AAD so a ciphertext cannot be silently relocated onto a different
/// wallet identity or version without authentication failing.
fn aad_for_payload(version: u32, address: &str) -> Vec<u8> {
    if version >= WALLET_VERSION_V4 {
        format!("alice-wallet:v{}:{}", version, address).into_bytes()
    } else {
        Vec::new()
    }
}

fn encrypt_blob(plaintext: &[u8], key: &[u8; 32], aad: &[u8]) -> Result<(String, String), String> {
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new(key.into());
    let ciphertext = cipher
        .encrypt(
            &nonce_bytes.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| format!("encryption failure: {}", e))?;

    Ok((b64.encode(ciphertext), b64.encode(nonce_bytes)))
}

fn decrypt_blob(
    ciphertext_b64: &str,
    nonce_b64: &str,
    key: &[u8; 32],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let ciphertext = b64
        .decode(ciphertext_b64)
        .map_err(|_| "Invalid base64 in ciphertext")?;
    let nonce_bytes = b64
        .decode(nonce_b64)
        .map_err(|_| "Invalid base64 in nonce")?;
    if nonce_bytes.len() != 12 {
        return Err("Nonce length mismatch".into());
    }

    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(
            nonce_bytes.as_slice().into(),
            Payload {
                msg: ciphertext.as_ref(),
                aad,
            },
        )
        .map_err(|_| "Decryption failed (wrong password or corrupted)".into())
}

fn payload_needs_upgrade(payload: &WalletPayload) -> bool {
    payload.version != CURRENT_WALLET_VERSION
        || payload.kdf != "argon2id"
        || payload.kdf_iterations != ARGON2_ITERATIONS
        || payload.kdf_memory_kib != Some(ARGON2_MEMORY_KIB)
        || payload.kdf_parallelism != Some(ARGON2_PARALLELISM)
        || payload.encrypted_mnemonic.is_some()
        || payload.nonce_mnemonic.is_some()
}

fn verify_identity(payload: &WalletPayload, keypair: &Sr25519Keypair) -> Result<(), String> {
    let address = account_id_to_ss58(&keypair.public_key().0, SS58_FORMAT);
    if address != payload.address {
        return Err("Wallet address mismatch".into());
    }

    let public_key_hex = format!("0x{}", hex::encode(keypair.public_key().0));
    if payload.public_key != public_key_hex {
        return Err("Wallet public key mismatch".into());
    }

    Ok(())
}

fn legacy_wallet_path() -> PathBuf {
    legacy_data_dir().join("wallet.json")
}

fn legacy_data_dir() -> PathBuf {
    dirs::home_dir()
        .expect("Cannot find home directory")
        .join(".alice")
}

fn temporary_wallet_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("wallet.json");
    path.with_file_name(format!("{}.tmp-{}", file_name, std::process::id()))
}

fn create_wallet_file(path: &Path) -> Result<std::fs::File, String> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    options
        .open(path)
        .map_err(|e| format!("Failed to open wallet file {}: {}", path.display(), e))
}

fn persist_wallet_file(tmp_path: &Path, final_path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    if final_path.exists() {
        fs::remove_file(final_path)
            .map_err(|e| format!("Failed to replace existing wallet file: {}", e))?;
    }

    fs::rename(tmp_path, final_path).map_err(|e| {
        let _ = fs::remove_file(tmp_path);
        format!(
            "Failed to move wallet file into place ({} -> {}): {}",
            tmp_path.display(),
            final_path.display(),
            e
        )
    })
}

fn keypair_from_phrase(mnemonic: &str) -> Result<Sr25519Keypair, String> {
    let seed_bytes = substrate_seed_from_phrase(mnemonic)?;
    Sr25519Keypair::from_secret_key(seed_bytes).map_err(|e| e.to_string())
}

fn substrate_seed_from_phrase(mnemonic: &str) -> Result<[u8; 32], String> {
    let mnemonic = bip39::Mnemonic::parse(mnemonic).map_err(|e| e.to_string())?;
    let (entropy_array, len) = mnemonic.to_entropy_array();
    // The raw BIP-39 entropy and the full 64-byte derived seed are both highly
    // sensitive. Wrap them in `Zeroizing` so they are wiped on scope exit
    // (including on the early-return error path), not just the 32-byte slice.
    let entropy = Zeroizing::new(entropy_array);
    let seed64 = Zeroizing::new(
        substrate_bip39::seed_from_entropy(&entropy[..len], "")
            .map_err(|e| format!("Failed to derive seed from mnemonic entropy: {:?}", e))?,
    );
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&seed64[..32]);
    Ok(secret)
}

fn account_id_to_ss58(account_id: &[u8; 32], format: u16) -> String {
    let ident = format & 0b0011_1111_1111_1111;
    let mut payload = match ident {
        0..=63 => vec![ident as u8],
        64..=16_383 => {
            let first = ((ident & 0b0000_0000_1111_1100) as u8 >> 2) | 0b0100_0000;
            let second = ((ident >> 8) as u8) | (((ident & 0b0000_0000_0000_0011) as u8) << 6);
            vec![first, second]
        }
        _ => unreachable!("ss58 format is masked to 14 bits"),
    };
    payload.extend(account_id);

    let mut hasher = Blake2b512::new();
    hasher.update(b"SS58PRE");
    hasher.update(&payload);
    let checksum = hasher.finalize();
    payload.extend(&checksum[..2]);

    bs58::encode(payload).into_string()
}

/// Generate a fresh BIP-39 mnemonic (24 words, 32 bytes of entropy) for a new
/// wallet/identity. Lifted from `alice-wallet/gui/src/ui/create.rs` (the create
/// screen): hold the raw entropy in a `Zeroizing` buffer so it is wiped when the
/// scope exits rather than lingering on the stack, then return the assembled
/// phrase as a `Zeroizing<String>` so the caller's copy is wiped on drop too.
pub fn generate_mnemonic() -> Zeroizing<String> {
    use bip39::Mnemonic;
    let mut entropy = Zeroizing::new([0u8; 32]);
    rand::thread_rng().fill_bytes(entropy.as_mut());
    let mnemonic = Mnemonic::from_entropy(entropy.as_ref()).expect("32 bytes -> mnemonic");
    let phrase = mnemonic.words().collect::<Vec<&str>>().join(" ");
    Zeroizing::new(phrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEGACY_PBKDF2_ITERATIONS: u32 = 600_000;

    #[test]
    fn creates_v3_wallet_without_persisted_mnemonic() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let payload = create_wallet_payload(phrase, "correct horse battery staple").unwrap();

        assert_eq!(payload.version, CURRENT_WALLET_VERSION);
        assert_eq!(payload.kdf, "argon2id");
        assert!(payload.encrypted_mnemonic.is_none());
        assert!(payload.nonce_mnemonic.is_none());
    }

    #[test]
    fn imports_and_exports_raw_private_key_without_mnemonic_backup() {
        let seed_hex = "0x1111111111111111111111111111111111111111111111111111111111111111";
        let payload =
            create_wallet_payload_from_seed_hex(seed_hex, "correct horse battery staple").unwrap();

        assert_eq!(payload.version, CURRENT_WALLET_VERSION);
        assert!(payload.encrypted_mnemonic.is_none());
        assert!(payload.nonce_mnemonic.is_none());

        let unlocked = unlock_wallet(&payload, "correct horse battery staple").unwrap();
        assert_eq!(
            unlocked.secrets.export_private_key_hex().as_deref(),
            Some(seed_hex)
        );
        let keypair = unlocked.secrets.to_keypair().expect("unlocked keypair");
        assert_eq!(
            payload.public_key,
            format!("0x{}", hex::encode(keypair.public_key().0))
        );

        let display_only = WalletSecrets::display_only(payload.address);
        assert!(display_only.export_private_key_hex().is_none());
        assert!(display_only.to_keypair().is_err());
    }

    #[test]
    fn new_wallets_are_v4_and_bind_address_aad() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let payload = create_wallet_payload(phrase, "correct horse battery staple").unwrap();

        // New wallets are written at the AAD-binding version and round-trip.
        assert_eq!(payload.version, WALLET_VERSION_V4);
        let unlocked = unlock_wallet(&payload, "correct horse battery staple").unwrap();
        assert_eq!(unlocked.secrets.address, payload.address);
        // A correctly-formed v4 wallet does not need a further upgrade.
        assert!(unlock_wallet(&payload, "correct horse battery staple")
            .unwrap()
            .upgraded_payload
            .is_none());

        // The seed ciphertext is bound to (version, address) via AAD: relocating
        // it onto a different address must fail authentication even with the
        // correct password, instead of silently decrypting.
        let mut tampered = payload.clone();
        tampered.address = qa_display_address_variant(0xAB);
        match unlock_wallet(&tampered, "correct horse battery staple") {
            Ok(_) => panic!("AAD mismatch must reject decryption"),
            Err(err) => assert!(err.contains("Decryption failed"), "unexpected error: {err}"),
        }
    }

    #[test]
    fn aad_is_empty_for_legacy_versions_and_bound_for_v4() {
        assert!(aad_for_payload(WALLET_VERSION_V2, "addr").is_empty());
        assert!(aad_for_payload(WALLET_VERSION_V3, "addr").is_empty());
        assert!(!aad_for_payload(WALLET_VERSION_V4, "addr").is_empty());
        // The bound AAD distinguishes different addresses.
        assert_ne!(
            aad_for_payload(WALLET_VERSION_V4, "addr-a"),
            aad_for_payload(WALLET_VERSION_V4, "addr-b")
        );
    }

    #[test]
    fn unlocks_argon2_wallet_written_with_old_t2_iterations() {
        // Regression guard for the ARGON2_ITERATIONS 2 -> 3 bump: a v3 wallet
        // that was encrypted with the *old* t=2 cost must still decrypt, because
        // decryption derives the key from the per-wallet stored kdf_iterations,
        // not from the (now higher) ARGON2_ITERATIONS constant.
        const OLD_ARGON2_ITERATIONS: u32 = 2;
        assert_ne!(
            OLD_ARGON2_ITERATIONS, ARGON2_ITERATIONS,
            "test must use the pre-bump cost"
        );

        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed_bytes = substrate_seed_from_phrase(phrase).unwrap();
        let keypair = Sr25519Keypair::from_secret_key(seed_bytes).unwrap();

        let mut salt = [0u8; 32];
        salt.copy_from_slice(&[9u8; 32]);
        let mut key = derive_argon2id_key(
            "correct horse battery staple",
            &salt,
            OLD_ARGON2_ITERATIONS,
            ARGON2_MEMORY_KIB,
            ARGON2_PARALLELISM,
        )
        .unwrap();
        // v3 wallets predate AAD, so encrypt with an empty AAD to mirror real data.
        let (encrypted_seed, nonce_seed) = encrypt_blob(&seed_bytes, &key, &[]).unwrap();
        key.zeroize();

        let payload = WalletPayload {
            version: WALLET_VERSION_V3,
            address: account_id_to_ss58(&keypair.public_key().0, SS58_FORMAT),
            public_key: format!("0x{}", hex::encode(keypair.public_key().0)),
            encrypted_seed,
            encrypted_mnemonic: None,
            salt: b64.encode(salt),
            nonce_seed,
            nonce_mnemonic: None,
            kdf: "argon2id".into(),
            kdf_iterations: OLD_ARGON2_ITERATIONS,
            kdf_memory_kib: Some(ARGON2_MEMORY_KIB),
            kdf_parallelism: Some(ARGON2_PARALLELISM),
        };

        let unlocked = unlock_wallet(&payload, "correct horse battery staple").unwrap();
        assert_eq!(unlocked.secrets.address, payload.address);
        // The old t=2 params now differ from the bumped default, so the wallet
        // is transparently re-encrypted with the stronger cost on unlock.
        let upgraded = unlocked
            .upgraded_payload
            .expect("old t=2 wallet should request an upgrade to the new cost");
        assert_eq!(upgraded.kdf_iterations, ARGON2_ITERATIONS);
        // And the upgraded payload must itself still decrypt.
        assert!(unlock_wallet(&upgraded, "correct horse battery staple").is_ok());
    }

    #[test]
    fn unlocks_legacy_wallet_and_requests_upgrade() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed_bytes = substrate_seed_from_phrase(phrase).unwrap();
        let keypair = Sr25519Keypair::from_secret_key(seed_bytes).unwrap();
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&[7u8; 32]);
        let key = derive_pbkdf2_key("password123", &salt, LEGACY_PBKDF2_ITERATIONS);
        // Legacy v2 wallets were written without AAD.
        let (encrypted_seed, nonce_seed) = encrypt_blob(&seed_bytes, &key, &[]).unwrap();
        let (encrypted_mnemonic, nonce_mnemonic) =
            encrypt_blob(phrase.as_bytes(), &key, &[]).unwrap();

        let payload = WalletPayload {
            version: WALLET_VERSION_V2,
            address: account_id_to_ss58(&keypair.public_key().0, SS58_FORMAT),
            public_key: format!("0x{}", hex::encode(keypair.public_key().0)),
            encrypted_seed,
            encrypted_mnemonic: Some(encrypted_mnemonic),
            salt: b64.encode(salt),
            nonce_seed,
            nonce_mnemonic: Some(nonce_mnemonic),
            kdf: "pbkdf2-sha256".into(),
            kdf_iterations: LEGACY_PBKDF2_ITERATIONS,
            kdf_memory_kib: None,
            kdf_parallelism: None,
        };

        let unlocked = unlock_wallet(&payload, "password123").unwrap();
        assert_eq!(unlocked.secrets.address, payload.address);
        assert!(unlocked.upgraded_payload.is_some());
        assert!(unlocked
            .upgraded_payload
            .as_ref()
            .unwrap()
            .encrypted_mnemonic
            .is_none());
    }

    /// Unique scratch dir under the OS temp root (no `tempfile` dep needed). The
    /// returned guard removes the tree on drop so the test leaves nothing behind.
    struct ScratchDir(PathBuf);
    impl ScratchDir {
        fn new(tag: &str) -> Self {
            let uniq = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let dir = std::env::temp_dir().join(format!("alice-crypto-{tag}-{uniq}"));
            fs::create_dir_all(&dir).unwrap();
            ScratchDir(dir)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn backup_retention_keeps_only_n_newest_and_never_touches_live_keystore() {
        let scratch = ScratchDir::new("bak-retention");
        let keystore = scratch.path().join("miner-keystore.json");
        let live_name = "miner-keystore.json";

        // Seed MORE than the retention bound of pre-existing backups with known,
        // ordered timestamps. (Lower ts = older.)
        let total = KEYSTORE_BACKUP_RETENTION + 4;
        for ts in 1..=total as u64 {
            fs::write(
                scratch.path().join(format!("{live_name}.bak-{ts}")),
                format!("backup-{ts}"),
            )
            .unwrap();
        }
        // An unrelated sibling that merely starts similarly must SURVIVE — it is
        // not a `<live>.bak-<...>` file.
        let decoy = scratch.path().join("miner-keystore.json.notes.txt");
        fs::write(&decoy, b"keep me").unwrap();

        // The live keystore exists; backing it up renames it to a fresh `.bak-<now>`
        // and then prunes the tail down to the retention bound.
        fs::write(&keystore, b"live-keystore-bytes").unwrap();
        let made = backup_existing_wallet(&keystore).unwrap();
        assert!(made.is_some(), "an existing keystore must be backed up");

        // Exactly N backups remain.
        let mut remaining: Vec<String> = fs::read_dir(scratch.path())
            .unwrap()
            .flatten()
            .filter_map(|e| e.file_name().to_str().map(str::to_string))
            .filter(|n| n.starts_with(&format!("{live_name}.bak-")))
            .collect();
        remaining.sort();
        assert_eq!(
            remaining.len(),
            KEYSTORE_BACKUP_RETENTION,
            "exactly N backups must remain after pruning, got {remaining:?}"
        );

        // The survivors are the NEWEST: the just-created backup (ts == now, far
        // larger than our seeded 1..=total) plus the highest-numbered seeds. The
        // oldest seeds (ts = 1, 2, …) must be gone.
        assert!(
            !remaining.iter().any(|n| n == &format!("{live_name}.bak-1")),
            "the oldest backup must have been pruned"
        );

        // The live keystore is renamed-then-recreated only by the caller; here the
        // rename moved it away, so the ORIGINAL path no longer holds the live file
        // (backup_existing_wallet's contract). The unrelated decoy is untouched.
        assert!(decoy.exists(), "an unrelated sibling must never be deleted");
        assert_eq!(fs::read(&decoy).unwrap(), b"keep me");

        // And the backup we just made still contains the live bytes (safety net
        // preserved — the count is bounded, the recovery copy is intact).
        let made = made.unwrap();
        assert_eq!(fs::read(&made).unwrap(), b"live-keystore-bytes");
    }
}
