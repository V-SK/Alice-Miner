import { create } from "zustand";
import { listen, UnlistenFn } from "@tauri-apps/api/event";

export interface NetworkStatus {
  ps_reachable: boolean;
  ps_latency_ms: number;
  download_speed_mbps: number;
  websocket_ok: boolean;
  chain_epoch?: number;
  model_version?: number;
  issues: string[];
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

export interface MiningState {
  status: "Idle" | "Starting" | "Running" | "Stopping" | "Error";
  wallet_address?: string;
  gpu_index: number;
  current_epoch?: number;
  current_shard?: number;
  current_loss?: number;
  shards_completed: number;
  error_message?: string;
}

export interface ModelStatus {
  int8_available: boolean;
  fp16_available: boolean;
  int8_size_gb: number;
  fp16_size_gb: number;
  active_variant?: "Int8" | "Fp16";
}

interface AppState {
  // Wallet
  walletAddress: string | null;
  setWalletAddress: (address: string | null) => void;

  // Network
  networkStatus: NetworkStatus | null;
  setNetworkStatus: (status: NetworkStatus | null) => void;

  // GPU
  gpuInfo: GpuInfo[];
  setGpuInfo: (info: GpuInfo[]) => void;

  // Mining
  miningState: MiningState;
  setMiningState: (state: MiningState) => void;

  // Model
  modelStatus: ModelStatus | null;
  setModelStatus: (status: ModelStatus | null) => void;

  // Download
  downloadProgress: {
    variant: "Int8" | "Fp16";
    downloaded_bytes: number;
    total_bytes: number;
    percent: number;
    speed_mbps: number;
  } | null;
  setDownloadProgress: (progress: any) => void;

  // Logs
  logs: { time: string; msg: string; type: string }[];
  addLog: (msg: string, type?: string) => void;
  clearLogs: () => void;

  // Earnings
  totalEarned: number;
  epochEarned: number;
  setEarnings: (total: number, epoch: number) => void;

  // Miner log listener
  startMinerLogListener: () => Promise<UnlistenFn>;
}

export const useAppStore = create<AppState>((set) => ({
  // Wallet
  walletAddress: null,
  setWalletAddress: (address) => set({ walletAddress: address }),

  // Network
  networkStatus: null,
  setNetworkStatus: (status) => set({ networkStatus: status }),

  // GPU
  gpuInfo: [],
  setGpuInfo: (info) => set({ gpuInfo: info }),

  // Mining
  miningState: {
    status: "Idle",
    gpu_index: 0,
    shards_completed: 0,
  },
  setMiningState: (state) => set({ miningState: state }),

  // Model
  modelStatus: null,
  setModelStatus: (status) => set({ modelStatus: status }),

  // Download
  downloadProgress: null,
  setDownloadProgress: (progress) => set({ downloadProgress: progress }),

  // Logs
  logs: [],
  addLog: (msg, type = "info") =>
    set((state) => ({
      logs: [
        ...state.logs.slice(-99), // Keep last 100 logs
        {
          time: new Date().toLocaleTimeString("en-US", { hour12: false }),
          msg,
          type,
        },
      ],
    })),
  clearLogs: () => set({ logs: [] }),

  // Earnings
  totalEarned: 0,
  epochEarned: 0,
  setEarnings: (total, epoch) => set({ totalEarned: total, epochEarned: epoch }),

  // Miner log listener: listens for "miner-log" events from the Rust backend
  startMinerLogListener: async () => {
    return listen<{ type: string; message: string }>("miner-log", (event) => {
      const { type, message } = event.payload;
      const logType = type === "stderr" ? "error" : "info";
      const store = useAppStore.getState();
      store.addLog(message, logType);
    });
  },
}));
