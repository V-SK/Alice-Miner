// Type definitions for Tauri commands

export interface NetworkDiagResult {
  ps_reachable: boolean;
  ps_latency_ms: number;
  download_speed_mbps: number;
  websocket_ok: boolean;
  chain_epoch?: number;
  model_version?: number;
  issues: string[];
}

export interface PsStatus {
  chain_epoch: number;
  model_version: number;
  connected_miners: number;
  aggregation_round: number;
}

export interface GpuInfo {
  index: number;
  name: string;
  vram_total_gb: number;
  vram_free_gb: number;
  driver_version: string;
  cuda_version?: string;
  compute_capability?: string;
  is_supported: boolean;
  support_reason: string;
}

export interface GpuStats {
  index: number;
  utilization_percent: number;
  memory_used_gb: number;
  memory_total_gb: number;
  temperature_c: number;
  power_watts: number;
  power_limit_watts: number;
}

export interface WalletInfo {
  address: string;
  mnemonic?: string;
}

export type MiningStatus = "Idle" | "Starting" | "Running" | "Stopping" | "Error";

export interface MiningState {
  status: MiningStatus;
  wallet_address?: string;
  gpu_index: number;
  current_epoch?: number;
  current_shard?: number;
  current_loss?: number;
  shards_completed: number;
  error_message?: string;
}

export type ModelVariant = "Int8" | "Fp16";

export interface ModelStatus {
  int8_available: boolean;
  fp16_available: boolean;
  int8_size_gb: number;
  fp16_size_gb: number;
  active_variant?: ModelVariant;
}

export interface DownloadProgress {
  variant: ModelVariant;
  downloaded_bytes: number;
  total_bytes: number;
  percent: number;
  speed_mbps: number;
}

// Tauri command declarations
declare module "@tauri-apps/api/tauri" {
  export function invoke(cmd: "diagnose_network"): Promise<NetworkDiagResult>;
  export function invoke(cmd: "check_ps_status"): Promise<PsStatus>;
  export function invoke(cmd: "detect_gpu"): Promise<GpuInfo[]>;
  export function invoke(cmd: "get_gpu_stats"): Promise<GpuStats[]>;
  export function invoke(cmd: "generate_wallet"): Promise<WalletInfo>;
  export function invoke(cmd: "import_wallet", args: { mnemonic: string }): Promise<WalletInfo>;
  export function invoke(cmd: "save_wallet_address", args: { address: string }): Promise<void>;
  export function invoke(cmd: "get_wallet_address"): Promise<string | null>;
  export function invoke(cmd: "clear_wallet"): Promise<void>;
  export function invoke(
    cmd: "start_mining",
    args: { walletAddress: string; gpuIndex: number }
  ): Promise<void>;
  export function invoke(cmd: "stop_mining"): Promise<void>;
  export function invoke(cmd: "get_mining_status"): Promise<MiningState>;
  export function invoke(cmd: "check_model_status"): Promise<ModelStatus>;
  export function invoke(cmd: "download_model", args: { variant: ModelVariant }): Promise<void>;
  export function invoke(cmd: "get_download_progress"): Promise<DownloadProgress | null>;
}
