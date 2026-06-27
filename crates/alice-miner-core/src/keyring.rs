//! `core/keyring` — OS-native secret store for the **background-mining unlock password**.
//!
//! The background service (launchd / systemd `--user` / Windows Task Scheduler) runs the
//! CLI with **NO secret in its world-readable unit** (see [`crate::service`]). To run a
//! GPU **pearlhash** lane in the background — `GpuPrl`/`GpuAlpha`, which must unlock the
//! wallet keystore to sign the out-of-band M4 PoP — the unlock **password** is stored in
//! the OS keyring and read by the `--from-service` start. The keystore itself stays
//! encrypted on disk (`miner-keystore.json`); only the password lives in the keyring,
//! protected by the OS user account. CPU-XMR needs no secret, so it never uses this.
//!
//! Backends (via the `keyring` crate's native features):
//!   * macOS  → Keychain Services
//!   * Windows → Credential Manager
//!   * Linux  → Secret Service (libsecret/D-Bus)
//!
//! HONEST LIMITATION: a **headless Linux** box (a mining rig with no desktop session /
//! no running Secret Service) has no usable keyring — [`is_available`] returns `false`
//! there, so the service layer refuses GPU background with a clear message instead of
//! ever writing a plaintext secret. macOS/Windows keyrings are always available + survive
//! reboot.
//!
//! SECURITY INVARIANT: this module stores ONLY the unlock password (never the seed /
//! private key / mnemonic), keyed per Alice address, and zeroizes the retrieved copy
//! ([`Zeroizing`]). Nothing here mints/pays; it is a pure local secret store.

use zeroize::Zeroizing;

/// Keyring service name (the namespace under which the entry is stored).
const KEYRING_SERVICE: &str = "org.aliceprotocol.alice-miner";

/// Per-identity account key. Binding the entry to the Alice address means a stale
/// password from a PREVIOUS identity can never be used to (fail to) unlock a DIFFERENT
/// keystore — a re-key writes a new entry, and the old one is independently addressable.
fn account_for(address: &str) -> String {
    format!("background-unlock:{address}")
}

/// Build the keyring [`keyring::Entry`] for `address` (maps a backend-construction
/// failure — e.g. no Secret Service — to a human message).
fn entry(address: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new(KEYRING_SERVICE, &account_for(address))
        .map_err(|e| format!("OS keyring unavailable: {e}"))
}

/// Store (or overwrite) the background-unlock password for `address`. The caller MUST
/// have validated the password actually unlocks the keystore first — this only persists.
pub fn store_unlock_password(address: &str, password: &str) -> Result<(), String> {
    entry(address)?
        .set_password(password)
        .map_err(|e| format!("could not store the unlock password in the OS keyring: {e}"))
}

/// Retrieve the background-unlock password for `address`. `Ok(None)` when no entry
/// exists (so the caller can refuse GPU background cleanly); `Err` only on a real
/// keyring fault. The returned string is zeroized on drop.
pub fn get_unlock_password(address: &str) -> Result<Option<Zeroizing<String>>, String> {
    match entry(address)?.get_password() {
        Ok(pw) => Ok(Some(Zeroizing::new(pw))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!(
            "could not read the unlock password from the OS keyring: {e}"
        )),
    }
}

/// Delete the background-unlock password for `address`. Idempotent: a missing entry is
/// success (so an uninstall path never fails because nothing was stored).
pub fn delete_unlock_password(address: &str) -> Result<(), String> {
    match entry(address)?.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!(
            "could not delete the unlock password from the OS keyring: {e}"
        )),
    }
}

/// Whether a usable OS keyring exists on this box — a quick, side-effect-free probe
/// against a sentinel account. `NoEntry` (or a successful read) means the backend is
/// reachable and empty = available; any other error (e.g. a headless Linux without
/// Secret Service) means it is unusable. The service layer gates GPU background on this
/// so we never fall back to a plaintext secret.
pub fn is_available() -> bool {
    match keyring::Entry::new(KEYRING_SERVICE, "__availability_probe__") {
        Ok(e) => matches!(e.get_password(), Ok(_) | Err(keyring::Error::NoEntry)),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_is_address_scoped() {
        assert_eq!(account_for("a2abc"), "background-unlock:a2abc");
        assert_ne!(account_for("a2abc"), account_for("a2xyz"));
    }

    /// End-to-end against the REAL OS keyring — verifies the native backend round-trips
    /// store → get → delete. Skips cleanly where no keyring exists (headless Linux / CI)
    /// so it never fails the suite there; uses a throwaway, process-unique account and
    /// always cleans up. On macOS/Windows this exercises the real Keychain/Cred-Manager.
    #[test]
    fn round_trip_store_get_delete() {
        if !is_available() {
            eprintln!("OS keyring unavailable on this box — skipping round-trip");
            return;
        }
        let addr = format!("a2-selftest-{}", std::process::id());
        let secret = "correct-horse-battery-staple-9f3a";
        // Clean slate, then assert empty.
        let _ = delete_unlock_password(&addr);
        assert!(
            get_unlock_password(&addr).expect("get on empty").is_none(),
            "starts with no entry"
        );
        // Store → read back the exact secret.
        store_unlock_password(&addr, secret).expect("store");
        let got = get_unlock_password(&addr).expect("get").expect("present");
        assert_eq!(&*got, secret, "round-trips the stored secret");
        // Delete → gone, and a second delete is still Ok (idempotent).
        delete_unlock_password(&addr).expect("delete");
        assert!(
            get_unlock_password(&addr).expect("get after delete").is_none(),
            "deleted"
        );
        delete_unlock_password(&addr).expect("second delete is idempotent");
    }
}
