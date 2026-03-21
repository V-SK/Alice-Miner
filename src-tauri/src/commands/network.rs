use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkDiagResult {
    pub ps_reachable: bool,
    pub ps_latency_ms: u64,
    pub download_speed_mbps: f64,
    pub websocket_ok: bool,
    pub chain_epoch: Option<u64>,
    pub model_version: Option<u64>,
    pub issues: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PsStatus {
    pub chain_epoch: u64,
    pub model_version: u64,
    pub connected_miners: u64,
    pub aggregation_round: u64,
}

const PS_URL: &str = "https://ps.aliceprotocol.org";
const DL_URL: &str = "https://dl.aliceprotocol.org";

#[tauri::command]
pub async fn diagnose_network() -> Result<NetworkDiagResult, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    let mut result = NetworkDiagResult {
        ps_reachable: false,
        ps_latency_ms: 0,
        download_speed_mbps: 0.0,
        websocket_ok: false,
        chain_epoch: None,
        model_version: None,
        issues: Vec::new(),
    };

    // 1. Ping PS HTTP endpoint
    let start = Instant::now();
    match client.get(format!("{}/status", PS_URL)).send().await {
        Ok(resp) if resp.status().is_success() => {
            result.ps_reachable = true;
            result.ps_latency_ms = start.elapsed().as_millis() as u64;

            // Parse status
            if let Ok(status) = resp.json::<PsStatus>().await {
                result.chain_epoch = Some(status.chain_epoch);
                result.model_version = Some(status.model_version);
            }
        }
        Ok(resp) => {
            result.issues.push(format!("PS returned status {}", resp.status()));
        }
        Err(e) => {
            result.issues.push(format!("Cannot reach PS: {}", e));
        }
    }

    // 2. Test download speed (download a small test file)
    let start = Instant::now();
    match client.get(format!("{}/speedtest_1mb.bin", DL_URL)).send().await {
        Ok(resp) => {
            if let Ok(bytes) = resp.bytes().await {
                let elapsed = start.elapsed().as_secs_f64();
                if elapsed > 0.0 {
                    result.download_speed_mbps = (bytes.len() as f64 / 1_000_000.0) / elapsed * 8.0;
                }
            }
        }
        Err(e) => {
            result.issues.push(format!("Download test failed: {}", e));
        }
    }

    // 3. Test WebSocket connection
    match tokio_tungstenite::connect_async(format!("wss://ps.aliceprotocol.org/ws")).await {
        Ok(_) => result.websocket_ok = true,
        Err(e) => result.issues.push(format!("WebSocket failed: {}", e)),
    }

    // 4. Generate warnings
    if result.ps_latency_ms > 500 {
        result.issues.push("High latency to PS (>500ms)".to_string());
    }
    if result.download_speed_mbps > 0.0 && result.download_speed_mbps < 10.0 {
        result.issues.push(format!(
            "Slow connection ({:.1} Mbps), model download will be slow",
            result.download_speed_mbps
        ));
    }

    Ok(result)
}

#[tauri::command]
pub async fn check_ps_status() -> Result<PsStatus, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client
        .get(format!("{}/status", PS_URL))
        .send()
        .await
        .map_err(|e| format!("Failed to connect: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("PS returned status {}", resp.status()));
    }

    resp.json::<PsStatus>()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))
}
