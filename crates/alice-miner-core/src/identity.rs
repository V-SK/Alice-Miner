//! `core/identity` — create / import / paste the Alice reward identity, and the
//! `~/.alice/identity.json` pointer contract (PLAN §2.5).
//!
//! Two layers (PLAN §2.5):
//!   * **Keystore (the secret)** stays at the Wallet's path
//!     (`data_local_dir()/AliceWallet/wallet.json`, honoring
//!     `$ALICE_WALLET_DATA_ROOT`) in the shared `WalletPayload` schema, written
//!     by `alice_crypto::write_wallet_payload`. One keystore, never two.
//!   * **Identity pointer (public only)** is `~/.alice/identity.json` — a tiny,
//!     unencrypted, world-public file naming the active `address`, `pubkey`,
//!     `keystore_path`, `label`, and `created` timestamp. Holds NO secret.
//!
//! ── Security invariant (PLAN §2.5 / the brief) ──────────────────────────────
//! `alice_crypto::unlock_wallet` runs **exactly once**, at create/import, to
//! derive + verify the address; the `WalletSecrets` is then dropped (zeroizing).
//! The mining path consumes ONLY the public `address` string returned here —
//! never a password, seed, or key. `paste` is watch-only (no keystore, no
//! unlock). Atomic `0o600` writes for `identity.json`; it is written only on
//! create/import/paste, never during mining.

#![allow(dead_code)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::lane::xmr::validate_alice_address;

/// The pointer file written to `~/.alice/identity.json`. Public-only: the
/// active address, its public key, where the keystore lives (None for a
/// watch-only paste), an optional label, and a creation timestamp. NO secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityPointer {
    /// The active Alice reward address (SS58-300).
    pub address: String,
    /// The sr25519 public key hex (`0x…`), or `None` for a watch-only paste
    /// (we only know the address, not the pubkey, without the keystore).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<String>,
    /// Absolute path to the keystore that owns this address, or `None` for a
    /// watch-only (paste) identity that has no keystore.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keystore_path: Option<String>,
    /// Optional user-facing label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Unix seconds at which this pointer was written.
    pub created: u64,
}

/// How an identity was established. The mining path treats all three identically
/// (it consumes only `address`); `watch_only` records whether a signing keystore
/// backs this identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub address: String,
    pub pubkey: Option<String>,
    pub keystore_path: Option<PathBuf>,
    pub watch_only: bool,
}

/// Resolve `~/.alice/identity.json`. Honors `$ALICE_IDENTITY_DIR` (tests) for the
/// directory, else `~/.alice`. Falls back to the current dir only if no home is
/// found (never panics).
pub fn identity_path() -> PathBuf {
    identity_dir().join("identity.json")
}

fn identity_dir() -> PathBuf {
    if let Some(over) = std::env::var_os("ALICE_IDENTITY_DIR") {
        let s = over.to_string_lossy().trim().to_string();
        if !s.is_empty() {
            return PathBuf::from(s);
        }
    }
    dirs::home_dir()
        .map(|h| h.join(".alice"))
        .unwrap_or_else(|| PathBuf::from(".alice"))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Create a brand-new identity: generate a 24-word mnemonic, build + write the
/// keystore (`WalletPayload`) at the Wallet path, unlock ONCE to derive+verify
/// the address (secrets drop here), and write the `~/.alice/identity.json`
/// pointer. Returns the new [`Identity`] **and** the freshly generated mnemonic
/// (so the caller can show it for the forced-backup step). The mnemonic is a
/// `Zeroizing<String>` — wiped on drop.
///
/// `password` is consumed only to encrypt the keystore + the single verifying
/// unlock; it never reaches the mining path.
pub fn create(label: Option<String>, password: &str) -> Result<(Identity, Zeroizing<String>), String> {
    let mnemonic = alice_crypto::generate_mnemonic();
    let payload = alice_crypto::create_wallet_payload(&mnemonic, password)?;

    let keystore_path = alice_crypto::default_wallet_path();
    // Never silently clobber an existing keystore (the two-keystore footgun):
    // back it up first, exactly like the Wallet's import path.
    alice_crypto::backup_existing_wallet(&keystore_path)?;
    alice_crypto::write_wallet_payload(&keystore_path, &payload)?;

    // Security invariant: unlock EXACTLY ONCE to derive+verify, then the
    // `WalletSecrets` drops at the end of this scope (zeroizing). Mining uses
    // only the public address below.
    let address = {
        let outcome = alice_crypto::unlock_wallet(&payload, password)?;
        outcome.secrets.address.clone()
        // `outcome` (and its `WalletSecrets`) dropped here.
    };

    let identity = Identity {
        address: address.clone(),
        pubkey: Some(payload.public_key.clone()),
        keystore_path: Some(keystore_path.clone()),
        watch_only: false,
    };
    write_pointer(&IdentityPointer {
        address,
        pubkey: Some(payload.public_key),
        keystore_path: Some(keystore_path.to_string_lossy().to_string()),
        label,
        created: now_unix(),
    })?;
    Ok((identity, mnemonic))
}

/// Import an identity from a 24-word mnemonic. Builds + writes the keystore,
/// unlocks ONCE to derive+verify, drops secrets, writes the pointer.
pub fn import_mnemonic(mnemonic: &str, label: Option<String>, password: &str) -> Result<Identity, String> {
    let payload = alice_crypto::create_wallet_payload(mnemonic, password)?;
    import_payload(payload, label, password)
}

/// Import an identity from a raw 32-byte sr25519 seed (hex, optional `0x`).
pub fn import_seed_hex(seed_hex: &str, label: Option<String>, password: &str) -> Result<Identity, String> {
    let payload = alice_crypto::create_wallet_payload_from_seed_hex(seed_hex, password)?;
    import_payload(payload, label, password)
}

/// Shared tail for the two import variants: back up any existing keystore, write
/// the new one, unlock ONCE (secrets drop), write the pointer.
fn import_payload(
    payload: alice_crypto::WalletPayload,
    label: Option<String>,
    password: &str,
) -> Result<Identity, String> {
    let keystore_path = alice_crypto::default_wallet_path();
    alice_crypto::backup_existing_wallet(&keystore_path)?;
    alice_crypto::write_wallet_payload(&keystore_path, &payload)?;

    let address = {
        let outcome = alice_crypto::unlock_wallet(&payload, password)?;
        outcome.secrets.address.clone()
    };

    let identity = Identity {
        address: address.clone(),
        pubkey: Some(payload.public_key.clone()),
        keystore_path: Some(keystore_path.clone()),
        watch_only: false,
    };
    write_pointer(&IdentityPointer {
        address,
        pubkey: Some(payload.public_key),
        keystore_path: Some(keystore_path.to_string_lossy().to_string()),
        label,
        created: now_unix(),
    })?;
    Ok(identity)
}

/// Paste an address-only (watch-only) identity. NO keystore, NO unlock — we only
/// validate that it is a checksum-valid SS58-300 Alice address (the same gate
/// the lane uses), then write the pointer with `keystore_path: None`.
pub fn paste(address: &str, label: Option<String>) -> Result<Identity, String> {
    let canonical =
        validate_alice_address(address.trim()).ok_or("invalid Alice address (not SS58-300)")?;
    let identity = Identity {
        address: canonical.clone(),
        pubkey: None,
        keystore_path: None,
        watch_only: true,
    };
    write_pointer(&IdentityPointer {
        address: canonical,
        pubkey: None,
        keystore_path: None,
        label,
        created: now_unix(),
    })?;
    Ok(identity)
}

/// Load the existing `~/.alice/identity.json` pointer, if present + parseable.
pub fn load_pointer() -> Option<IdentityPointer> {
    let path = identity_path();
    let contents = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&contents).ok()
}

/// Write the pointer atomically with `0o600` perms (write to a temp file in the
/// same dir, fsync, rename into place). Mirrors the Wallet keystore write.
fn write_pointer(pointer: &IdentityPointer) -> Result<(), String> {
    let path = identity_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create identity directory: {e}"))?;
    }
    let encoded = serde_json::to_vec_pretty(pointer)
        .map_err(|e| format!("failed to serialize identity pointer: {e}"))?;

    let tmp = tmp_path(&path);
    let mut file = open_0600(&tmp)?;
    file.write_all(&encoded)
        .map_err(|e| format!("failed to write identity pointer: {e}"))?;
    file.flush()
        .map_err(|e| format!("failed to flush identity pointer: {e}"))?;
    file.sync_all()
        .map_err(|e| format!("failed to sync identity pointer: {e}"))?;
    drop(file);

    persist(&tmp, &path)?;

    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if let Ok(dir) = OpenOptions::new().read(true).open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

fn tmp_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("identity.json");
    path.with_file_name(format!("{name}.tmp-{}", std::process::id()))
}

fn open_0600(path: &Path) -> Result<fs::File, String> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|e| format!("failed to open identity pointer {}: {e}", path.display()))
}

fn persist(tmp: &Path, final_path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    if final_path.exists() {
        fs::remove_file(final_path)
            .map_err(|e| format!("failed to replace identity pointer: {e}"))?;
    }
    fs::rename(tmp, final_path).map_err(|e| {
        let _ = fs::remove_file(tmp);
        format!("failed to move identity pointer into place: {e}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // create/import write the real keystore + the pointer; serialize these so
    // they don't race on the shared env vars / paths.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Run `f` with `$ALICE_WALLET_DATA_ROOT` and `$ALICE_IDENTITY_DIR` pointed
    /// at fresh temp dirs, so tests never touch the real `~/.alice` / keystore.
    fn with_temp_env<F: FnOnce()>(f: F) {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let base = std::env::temp_dir().join(format!(
            "alice-miner-id-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let wallet_root = base.join("wallet");
        let id_dir = base.join("dot-alice");
        std::fs::create_dir_all(&wallet_root).unwrap();
        std::fs::create_dir_all(&id_dir).unwrap();
        std::env::set_var("ALICE_WALLET_DATA_ROOT", &wallet_root);
        std::env::set_var("ALICE_IDENTITY_DIR", &id_dir);

        f();

        std::env::remove_var("ALICE_WALLET_DATA_ROOT");
        std::env::remove_var("ALICE_IDENTITY_DIR");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn create_round_trips_address_and_writes_pointer() {
        with_temp_env(|| {
            let (identity, mnemonic) =
                create(Some("test".into()), "correct horse battery staple").expect("create");

            // Address is a valid SS58-300 Alice address.
            assert!(validate_alice_address(&identity.address).is_some());
            assert!(!identity.watch_only);
            assert!(identity.keystore_path.is_some());
            assert!(identity.pubkey.is_some());
            // Mnemonic is 24 words.
            assert_eq!(mnemonic.split_whitespace().count(), 24);

            // The keystore exists at the Wallet path and decrypts back to the
            // SAME address (parity: the unlock the engine would refuse to repeat
            // still proves the address derivation).
            let ks = alice_crypto::default_wallet_path();
            assert!(ks.is_file());
            let payload: alice_crypto::WalletPayload =
                serde_json::from_slice(&std::fs::read(&ks).unwrap()).unwrap();
            let unlocked =
                alice_crypto::unlock_wallet(&payload, "correct horse battery staple").unwrap();
            assert_eq!(unlocked.secrets.address, identity.address);

            // identity.json was written and points at the same address + keystore.
            let pointer = load_pointer().expect("pointer written");
            assert_eq!(pointer.address, identity.address);
            assert_eq!(pointer.keystore_path.as_deref(), ks.to_str());
            assert_eq!(pointer.label.as_deref(), Some("test"));
            assert!(pointer.created > 0);

            // The pointer file is 0600 on unix (no secret, but defense-in-depth).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(identity_path())
                    .unwrap()
                    .permissions()
                    .mode();
                assert_eq!(mode & 0o777, 0o600);
            }
        });
    }

    #[test]
    fn import_mnemonic_matches_known_address() {
        with_temp_env(|| {
            // A fixed mnemonic must reproduce the same address create() would for
            // it (parity with the shared keystore).
            let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            let identity = import_mnemonic(phrase, None, "pw-123456").expect("import");
            let expected = alice_crypto::create_wallet_payload(phrase, "pw-123456")
                .unwrap()
                .address;
            assert_eq!(identity.address, expected);
            assert!(!identity.watch_only);
            assert_eq!(load_pointer().unwrap().address, expected);
        });
    }

    #[test]
    fn import_seed_hex_round_trips() {
        with_temp_env(|| {
            let seed = "0x1111111111111111111111111111111111111111111111111111111111111111";
            let identity = import_seed_hex(seed, None, "pw-123456").expect("import seed");
            let expected = alice_crypto::create_wallet_payload_from_seed_hex(seed, "pw-123456")
                .unwrap()
                .address;
            assert_eq!(identity.address, expected);
            assert!(!identity.watch_only);
        });
    }

    #[test]
    fn paste_is_watch_only_and_validates() {
        with_temp_env(|| {
            // Derive a real address to paste.
            let addr = alice_crypto::create_wallet_payload(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "pw-123456",
            )
            .unwrap()
            .address;

            let identity = paste(&addr, Some("watch".into())).expect("paste");
            assert_eq!(identity.address, addr);
            assert!(identity.watch_only);
            assert!(identity.keystore_path.is_none());
            assert!(identity.pubkey.is_none());

            // Pointer written, no keystore_path field.
            let pointer = load_pointer().unwrap();
            assert_eq!(pointer.address, addr);
            assert!(pointer.keystore_path.is_none());

            // A non-Alice address is rejected.
            assert!(paste("not-an-address", None).is_err());
            assert!(paste("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY", None).is_err());
        });
    }
}
