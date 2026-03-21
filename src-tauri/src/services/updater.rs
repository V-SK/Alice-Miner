use tauri::AppHandle;

pub async fn check_for_updates(app: &AppHandle) -> Result<(), String> {
    // Use Tauri's built-in updater
    match tauri::updater::builder(app.clone()).check().await {
        Ok(update) => {
            if update.is_update_available() {
                log::info!(
                    "Update available: {} -> {}",
                    update.current_version(),
                    update.latest_version()
                );
                // The dialog will be shown automatically due to config
            } else {
                log::info!("No updates available");
            }
            Ok(())
        }
        Err(e) => {
            log::warn!("Update check failed: {}", e);
            Err(e.to_string())
        }
    }
}
