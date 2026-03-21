use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuInfo {
    pub index: u32,
    pub name: String,
    pub vram_total_gb: f64,
    pub vram_free_gb: f64,
    pub driver_version: String,
    pub cuda_version: Option<String>,
    pub compute_capability: Option<String>,
    pub is_supported: bool,
    pub support_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuStats {
    pub index: u32,
    pub utilization_percent: u32,
    pub memory_used_gb: f64,
    pub memory_total_gb: f64,
    pub temperature_c: u32,
    pub power_watts: u32,
    pub power_limit_watts: u32,
}

// Minimum VRAM requirement for training
const MIN_VRAM_GB: f64 = 24.0;

#[cfg(any(target_os = "windows", target_os = "linux"))]
#[tauri::command]
pub fn detect_gpu() -> Result<Vec<GpuInfo>, String> {
    use nvml_wrapper::Nvml;

    let nvml = match Nvml::init() {
        Ok(n) => n,
        Err(_) => {
            // No NVIDIA driver
            return Ok(vec![GpuInfo {
                index: 0,
                name: "No NVIDIA GPU detected".to_string(),
                vram_total_gb: 0.0,
                vram_free_gb: 0.0,
                driver_version: "N/A".to_string(),
                cuda_version: None,
                compute_capability: None,
                is_supported: false,
                support_reason: "NVIDIA driver not found. Please install NVIDIA drivers.".to_string(),
            }]);
        }
    };

    let device_count = nvml.device_count().unwrap_or(0);
    let driver_version = nvml.sys_driver_version().unwrap_or_default();
    let cuda_version = nvml
        .sys_cuda_driver_version()
        .ok()
        .map(|v| {
            let major = nvml_wrapper::cuda_driver_version_major(v);
            let minor = nvml_wrapper::cuda_driver_version_minor(v);
            format!("{}.{}", major, minor)
        });

    let mut gpus = Vec::new();

    for i in 0..device_count {
        if let Ok(device) = nvml.device_by_index(i) {
            let name = device.name().unwrap_or_default();
            let memory = device.memory_info().ok();
            let vram_total_gb = memory.as_ref().map(|m| m.total as f64 / 1e9).unwrap_or(0.0);
            let vram_free_gb = memory.as_ref().map(|m| m.free as f64 / 1e9).unwrap_or(0.0);

            let compute_cap = device
                .cuda_compute_capability()
                .ok()
                .map(|c| format!("{}.{}", c.major, c.minor));

            let (is_supported, support_reason) = if vram_total_gb >= MIN_VRAM_GB {
                (true, format!("✓ {} GB VRAM meets requirement", vram_total_gb as u32))
            } else {
                (
                    false,
                    format!(
                        "✗ {} GB VRAM below {} GB minimum",
                        vram_total_gb as u32, MIN_VRAM_GB as u32
                    ),
                )
            };

            gpus.push(GpuInfo {
                index: i,
                name,
                vram_total_gb,
                vram_free_gb,
                driver_version: driver_version.clone(),
                cuda_version: cuda_version.clone(),
                compute_capability: compute_cap,
                is_supported,
                support_reason,
            });
        }
    }

    if gpus.is_empty() {
        gpus.push(GpuInfo {
            index: 0,
            name: "No GPU detected".to_string(),
            vram_total_gb: 0.0,
            vram_free_gb: 0.0,
            driver_version: driver_version,
            cuda_version: cuda_version,
            compute_capability: None,
            is_supported: false,
            support_reason: "No compatible GPU found".to_string(),
        });
    }

    Ok(gpus)
}

#[cfg(target_os = "macos")]
#[tauri::command]
pub fn detect_gpu() -> Result<Vec<GpuInfo>, String> {
    // On macOS, check for Apple Silicon
    let is_apple_silicon = std::env::consts::ARCH == "aarch64";

    if is_apple_silicon {
        // Get system memory as proxy for unified memory
        let sys_info = sys_info::mem_info().ok();
        let total_mem_gb = sys_info.map(|m| m.total as f64 / 1024.0 / 1024.0).unwrap_or(0.0);

        // Apple Silicon can use unified memory for MPS
        // Estimate available GPU memory as ~75% of system memory
        let estimated_vram = total_mem_gb * 0.75;
        let is_supported = estimated_vram >= 24.0;

        Ok(vec![GpuInfo {
            index: 0,
            name: "Apple Silicon (MPS)".to_string(),
            vram_total_gb: estimated_vram,
            vram_free_gb: estimated_vram * 0.8, // Estimate
            driver_version: "Metal".to_string(),
            cuda_version: None,
            compute_capability: None,
            is_supported,
            support_reason: if is_supported {
                format!("✓ {:.0} GB unified memory available for MPS", estimated_vram)
            } else {
                format!(
                    "✗ {:.0} GB unified memory below 24 GB recommended",
                    estimated_vram
                )
            },
        }])
    } else {
        // Intel Mac - no GPU acceleration
        Ok(vec![GpuInfo {
            index: 0,
            name: "Intel Mac (CPU only)".to_string(),
            vram_total_gb: 0.0,
            vram_free_gb: 0.0,
            driver_version: "N/A".to_string(),
            cuda_version: None,
            compute_capability: None,
            is_supported: false,
            support_reason: "✗ Intel Macs not supported. Apple Silicon required for MPS.".to_string(),
        }])
    }
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
#[tauri::command]
pub fn get_gpu_stats() -> Result<Vec<GpuStats>, String> {
    use nvml_wrapper::{enum_wrappers::device::TemperatureSensor, Nvml};

    let nvml = Nvml::init().map_err(|e| e.to_string())?;
    let device_count = nvml.device_count().unwrap_or(0);

    let mut stats = Vec::new();

    for i in 0..device_count {
        if let Ok(device) = nvml.device_by_index(i) {
            let utilization = device.utilization_rates().ok().map(|u| u.gpu).unwrap_or(0);
            let memory = device.memory_info().ok();
            let memory_used_gb = memory.as_ref().map(|m| m.used as f64 / 1e9).unwrap_or(0.0);
            let memory_total_gb = memory.as_ref().map(|m| m.total as f64 / 1e9).unwrap_or(0.0);
            let temperature = device
                .temperature(TemperatureSensor::Gpu)
                .ok()
                .unwrap_or(0);
            let power = device.power_usage().ok().unwrap_or(0) / 1000; // mW to W
            let power_limit = device.power_management_limit().ok().unwrap_or(0) / 1000;

            stats.push(GpuStats {
                index: i,
                utilization_percent: utilization,
                memory_used_gb,
                memory_total_gb,
                temperature_c: temperature,
                power_watts: power,
                power_limit_watts: power_limit,
            });
        }
    }

    Ok(stats)
}

#[cfg(target_os = "macos")]
#[tauri::command]
pub fn get_gpu_stats() -> Result<Vec<GpuStats>, String> {
    // macOS doesn't expose detailed GPU stats easily
    // Return placeholder data
    Ok(vec![GpuStats {
        index: 0,
        utilization_percent: 0,
        memory_used_gb: 0.0,
        memory_total_gb: 0.0,
        temperature_c: 0,
        power_watts: 0,
        power_limit_watts: 0,
    }])
}
