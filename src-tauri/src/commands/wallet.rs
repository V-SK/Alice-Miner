use serde::{Deserialize, Serialize};

const ALICE_SS58_PREFIX: u16 = 300;
const KEYRING_SERVICE: &str = "alice-miner";
const KEYRING_USER: &str = "wallet_address";

// SECURITY NOTE: This module only stores the wallet ADDRESS (public key derivative)
// in the system keychain. No private keys or mnemonics are ever persisted.
// The mnemonic is generated in-memory and returned to the frontend exactly once
// for the user to back up, then discarded. The address alone has no signing
// capability — this is by design since mining only requires an address to
// attribute rewards. Users must keep their mnemonic safe externally.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletInfo {
    pub address: String,
    pub mnemonic: Option<String>, // Only returned on generation, not stored
}

#[tauri::command]
pub fn generate_wallet() -> Result<WalletInfo, String> {
    use bip39::{Language, Mnemonic};
    use sp_core::{crypto::Ss58Codec, sr25519, Pair};

    // Generate 12-word mnemonic
    let mnemonic = Mnemonic::generate_in(Language::English, 12).map_err(|e| e.to_string())?;

    // Derive SR25519 keypair
    let (pair, _) =
        sr25519::Pair::from_phrase(&mnemonic.to_string(), None).map_err(|e| format!("{:?}", e))?;

    // Generate Alice Protocol address (SS58 prefix = 300)
    let address = pair
        .public()
        .to_ss58check_with_version(ALICE_SS58_PREFIX.into());

    Ok(WalletInfo {
        address,
        mnemonic: Some(mnemonic.to_string()),
    })
}

#[tauri::command]
pub fn import_wallet(mnemonic: String) -> Result<WalletInfo, String> {
    use sp_core::{crypto::Ss58Codec, sr25519, Pair};

    // Validate and derive keypair from mnemonic
    let (pair, _) =
        sr25519::Pair::from_phrase(&mnemonic.trim(), None).map_err(|_| "Invalid mnemonic phrase")?;

    let address = pair
        .public()
        .to_ss58check_with_version(ALICE_SS58_PREFIX.into());

    Ok(WalletInfo {
        address,
        mnemonic: None, // Don't return mnemonic on import
    })
}

#[tauri::command]
pub fn save_wallet_address(address: String) -> Result<(), String> {
    // Validate address format (should start with 'a' for Alice Protocol)
    if !address.starts_with('a') {
        return Err("Invalid Alice Protocol address (should start with 'a')".to_string());
    }

    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER).map_err(|e| e.to_string())?;

    entry.set_password(&address).map_err(|e| e.to_string())?;

    log::info!("Wallet address saved to system keychain");
    Ok(())
}

#[tauri::command]
pub fn get_wallet_address() -> Result<Option<String>, String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER).map_err(|e| e.to_string())?;

    match entry.get_password() {
        Ok(addr) => Ok(Some(addr)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
pub fn clear_wallet() -> Result<(), String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER).map_err(|e| e.to_string())?;

    match entry.delete_password() {
        Ok(_) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()), // Already cleared
        Err(e) => Err(e.to_string()),
    }
}
