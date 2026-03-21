use tauri::AppHandle;

pub async fn check_for_updates(_app: &AppHandle) -> Result<(), String> {
    // Auto-updater disabled for now — no pubkey configured yet.
    // Enable the "updater" feature in Cargo.toml and set a valid pubkey
    // in tauri.conf.json when ready to ship OTA updates.
    log::info!("Updater disabled; skipping update check");
    Ok(())
}
