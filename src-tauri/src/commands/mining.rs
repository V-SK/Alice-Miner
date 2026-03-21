use serde::{Deserialize, Serialize};
use std::io::BufRead;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use tauri::{Manager, State};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum MiningStatus {
    Idle,
    Starting,
    Running,
    Stopping,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningState {
    pub status: MiningStatus,
    pub wallet_address: Option<String>,
    pub gpu_index: u32,
    pub current_epoch: Option<u64>,
    pub current_shard: Option<u64>,
    pub current_loss: Option<f64>,
    pub shards_completed: u64,
    pub error_message: Option<String>,
}

pub struct MiningProcess {
    pub child: Option<Child>,
    pub state: MiningState,
}

impl Default for MiningProcess {
    fn default() -> Self {
        Self {
            child: None,
            state: MiningState {
                status: MiningStatus::Idle,
                wallet_address: None,
                gpu_index: 0,
                current_epoch: None,
                current_shard: None,
                current_loss: None,
                shards_completed: 0,
                error_message: None,
            },
        }
    }
}

pub type MiningProcessState = Mutex<MiningProcess>;

fn get_miner_binary_path() -> std::path::PathBuf {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_default();

    #[cfg(target_os = "windows")]
    let binary_name = "alice-miner-core.exe";

    #[cfg(not(target_os = "windows"))]
    let binary_name = "alice-miner-core";

    exe_dir.join(binary_name)
}

fn get_model_path() -> std::path::PathBuf {
    let home = dirs::home_dir().unwrap_or_default();
    home.join(".alice-miner").join("models")
}

#[tauri::command]
pub fn start_mining(
    wallet_address: String,
    gpu_index: u32,
    state: State<'_, MiningProcessState>,
    app_handle: tauri::AppHandle,
) -> Result<(), String> {
    let mut process = state.lock().map_err(|e| e.to_string())?;

    if process.state.status == MiningStatus::Running {
        return Err("Mining is already running".to_string());
    }

    let miner_path = get_miner_binary_path();
    if !miner_path.exists() {
        return Err(format!(
            "Miner binary not found at {:?}. Please download it first.",
            miner_path
        ));
    }

    let model_path = get_model_path();
    if !model_path.join("model_int8.pt").exists() && !model_path.join("model_fp16.pt").exists() {
        return Err("Model not found. Please download the model first.".to_string());
    }

    // Determine which model to use
    let model_file = if model_path.join("model_fp16.pt").exists() {
        model_path.join("model_fp16.pt")
    } else {
        model_path.join("model_int8.pt")
    };

    process.state.status = MiningStatus::Starting;
    process.state.wallet_address = Some(wallet_address.clone());
    process.state.gpu_index = gpu_index;

    let mut cmd = Command::new(&miner_path);
    cmd.arg("--ps-url")
        .arg("wss://ps.aliceprotocol.org")
        .arg("--wallet")
        .arg(&wallet_address)
        .arg("--gpu")
        .arg(gpu_index.to_string())
        .arg("--model-path")
        .arg(&model_file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    match cmd.spawn() {
        Ok(mut child) => {
            // Forward stdout to frontend via Tauri events
            if let Some(stdout) = child.stdout.take() {
                let handle = app_handle.clone();
                std::thread::spawn(move || {
                    let reader = std::io::BufReader::new(stdout);
                    for line in reader.lines() {
                        if let Ok(line) = line {
                            let _ = handle.emit_all("miner-log", serde_json::json!({
                                "type": "stdout",
                                "message": line
                            }));
                        }
                    }
                });
            }

            // Forward stderr to frontend via Tauri events
            if let Some(stderr) = child.stderr.take() {
                let handle = app_handle.clone();
                std::thread::spawn(move || {
                    let reader = std::io::BufReader::new(stderr);
                    for line in reader.lines() {
                        if let Ok(line) = line {
                            let _ = handle.emit_all("miner-log", serde_json::json!({
                                "type": "stderr",
                                "message": line
                            }));
                        }
                    }
                });
            }

            process.child = Some(child);
            process.state.status = MiningStatus::Running;
            log::info!("Mining started for wallet {} on GPU {}", wallet_address, gpu_index);
            Ok(())
        }
        Err(e) => {
            process.state.status = MiningStatus::Error;
            process.state.error_message = Some(e.to_string());
            Err(format!("Failed to start miner: {}", e))
        }
    }
}

#[tauri::command]
pub fn stop_mining(state: State<'_, MiningProcessState>) -> Result<(), String> {
    let mut process = state.lock().map_err(|e| e.to_string())?;

    if process.state.status != MiningStatus::Running {
        return Ok(()); // Already stopped
    }

    process.state.status = MiningStatus::Stopping;

    if let Some(ref mut child) = process.child {
        // Try graceful shutdown first
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // Send SIGTERM
            unsafe {
                libc::kill(child.id() as i32, libc::SIGTERM);
            }
            // Wait a bit for graceful shutdown
            std::thread::sleep(std::time::Duration::from_secs(2));
        }

        // Force kill if still running
        match child.try_wait() {
            Ok(Some(_)) => {} // Already exited
            _ => {
                let _ = child.kill();
            }
        }

        let _ = child.wait();
    }

    process.child = None;
    process.state.status = MiningStatus::Idle;
    process.state.current_epoch = None;
    process.state.current_shard = None;
    process.state.current_loss = None;

    log::info!("Mining stopped");
    Ok(())
}

#[tauri::command]
pub fn get_mining_status(state: State<'_, MiningProcessState>) -> Result<MiningState, String> {
    let mut process = state.lock().map_err(|e| e.to_string())?;

    // Check if child process is still running
    if let Some(ref mut child) = process.child {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Process exited
                if !status.success() {
                    process.state.status = MiningStatus::Error;
                    process.state.error_message =
                        Some(format!("Miner process exited with status: {}", status));
                } else {
                    process.state.status = MiningStatus::Idle;
                }
                process.child = None;
            }
            Ok(None) => {
                // Still running
                process.state.status = MiningStatus::Running;
            }
            Err(e) => {
                process.state.status = MiningStatus::Error;
                process.state.error_message = Some(e.to_string());
            }
        }
    }

    Ok(process.state.clone())
}
