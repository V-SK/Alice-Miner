use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::io::AsyncWriteExt;

const DL_URL: &str = "https://dl.aliceprotocol.org";

/// Concurrency guard: only one download at a time
static DOWNLOADING: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ModelVariant {
    Int8,  // Quantized ~7GB, for quick start
    Fp16,  // Full ~13GB, for production training
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelStatus {
    pub int8_available: bool,
    pub fp16_available: bool,
    pub int8_size_gb: f64,
    pub fp16_size_gb: f64,
    pub active_variant: Option<ModelVariant>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadProgress {
    pub variant: ModelVariant,
    pub downloaded_bytes: u64,
    pub total_bytes: u64,
    pub percent: f64,
    pub speed_mbps: f64,
}

// Global download progress (thread-safe)
static DOWNLOAD_PROGRESS: AtomicU64 = AtomicU64::new(0);
static DOWNLOAD_TOTAL: AtomicU64 = AtomicU64::new(0);

fn get_model_dir() -> std::path::PathBuf {
    let home = dirs::home_dir().unwrap_or_default();
    let model_dir = home.join(".alice-miner").join("models");
    std::fs::create_dir_all(&model_dir).ok();
    model_dir
}

fn get_model_path(variant: ModelVariant) -> std::path::PathBuf {
    let filename = match variant {
        ModelVariant::Int8 => "model_int8.pt",
        ModelVariant::Fp16 => "model_fp16.pt",
    };
    get_model_dir().join(filename)
}

#[tauri::command]
pub fn check_model_status() -> Result<ModelStatus, String> {
    let model_dir = get_model_dir();

    let int8_path = model_dir.join("model_int8.pt");
    let fp16_path = model_dir.join("model_fp16.pt");

    let int8_available = int8_path.exists();
    let fp16_available = fp16_path.exists();

    let int8_size_gb = if int8_available {
        std::fs::metadata(&int8_path)
            .map(|m| m.len() as f64 / 1e9)
            .unwrap_or(0.0)
    } else {
        0.0
    };

    let fp16_size_gb = if fp16_available {
        std::fs::metadata(&fp16_path)
            .map(|m| m.len() as f64 / 1e9)
            .unwrap_or(0.0)
    } else {
        0.0
    };

    let active_variant = if fp16_available {
        Some(ModelVariant::Fp16)
    } else if int8_available {
        Some(ModelVariant::Int8)
    } else {
        None
    };

    Ok(ModelStatus {
        int8_available,
        fp16_available,
        int8_size_gb,
        fp16_size_gb,
        active_variant,
    })
}

#[tauri::command]
pub async fn download_model(variant: ModelVariant) -> Result<(), String> {
    // Concurrency guard: prevent multiple simultaneous downloads
    if DOWNLOADING.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        return Err("A download is already in progress".to_string());
    }

    // Ensure we clear the download flag on any exit path
    let result = download_model_inner(variant).await;
    DOWNLOADING.store(false, Ordering::SeqCst);
    result
}

async fn download_model_inner(variant: ModelVariant) -> Result<(), String> {
    let filename = match variant {
        ModelVariant::Int8 => "model_int8.pt",
        ModelVariant::Fp16 => "model_fp16.pt",
    };

    let url = format!("{}/{}", DL_URL, filename);
    let model_path = get_model_path(variant);
    let temp_path = model_path.with_extension("pt.tmp");

    log::info!("Starting download: {} -> {:?}", url, model_path);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3600)) // 1 hour timeout
        .build()
        .map_err(|e| e.to_string())?;

    // Check for existing partial download
    let existing_size = if temp_path.exists() {
        std::fs::metadata(&temp_path)
            .map(|m| m.len())
            .unwrap_or(0)
    } else {
        0
    };

    // Build request with Range header for resume
    let mut request = client.get(&url);
    if existing_size > 0 {
        request = request.header("Range", format!("bytes={}-", existing_size));
        log::info!("Resuming download from {} bytes", existing_size);
    }

    let response = request.send().await.map_err(|e| e.to_string())?;

    if !response.status().is_success() && response.status() != reqwest::StatusCode::PARTIAL_CONTENT
    {
        return Err(format!("Download failed: HTTP {}", response.status()));
    }

    let total_size = response.content_length().unwrap_or(0) + existing_size;
    DOWNLOAD_TOTAL.store(total_size, Ordering::SeqCst);
    DOWNLOAD_PROGRESS.store(existing_size, Ordering::SeqCst);

    // Open file for appending
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&temp_path)
        .await
        .map_err(|e| e.to_string())?;

    let mut stream = response.bytes_stream();
    let mut downloaded = existing_size;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| e.to_string())?;
        file.write_all(&chunk).await.map_err(|e| e.to_string())?;
        downloaded += chunk.len() as u64;
        DOWNLOAD_PROGRESS.store(downloaded, Ordering::SeqCst);
    }

    file.flush().await.map_err(|e| e.to_string())?;
    drop(file);

    // Verify checksum
    let checksum_url = format!("{}/{}.sha256", DL_URL, filename);
    log::info!("Fetching checksum from: {}", checksum_url);
    match client.get(&checksum_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let expected_hash = resp.text().await
                .map_err(|e| e.to_string())?
                .trim()
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_lowercase();

            if !expected_hash.is_empty() {
                // Compute SHA-256 of the downloaded file
                log::info!("Verifying checksum...");
                let file_bytes = std::fs::read(&temp_path).map_err(|e| e.to_string())?;
                let mut hasher = Sha256::new();
                hasher.update(&file_bytes);
                let actual_hash = format!("{:x}", hasher.finalize());

                if actual_hash != expected_hash {
                    // Delete corrupt file
                    let _ = std::fs::remove_file(&temp_path);
                    return Err(format!(
                        "Checksum mismatch: expected {}, got {}. File deleted.",
                        expected_hash, actual_hash
                    ));
                }
                log::info!("Checksum verified OK");
            }
        }
        Ok(resp) => {
            log::warn!("Checksum file not available (HTTP {}), skipping verification", resp.status());
        }
        Err(e) => {
            log::warn!("Could not fetch checksum: {}, skipping verification", e);
        }
    }

    std::fs::rename(&temp_path, &model_path).map_err(|e| e.to_string())?;

    log::info!("Download complete: {:?}", model_path);
    Ok(())
}

#[tauri::command]
pub fn get_download_progress() -> Result<Option<DownloadProgress>, String> {
    let downloaded = DOWNLOAD_PROGRESS.load(Ordering::SeqCst);
    let total = DOWNLOAD_TOTAL.load(Ordering::SeqCst);

    if total == 0 {
        return Ok(None);
    }

    let percent = (downloaded as f64 / total as f64) * 100.0;

    Ok(Some(DownloadProgress {
        variant: ModelVariant::Int8, // TODO: track actual variant
        downloaded_bytes: downloaded,
        total_bytes: total,
        percent,
        speed_mbps: 0.0, // TODO: calculate speed
    }))
}
