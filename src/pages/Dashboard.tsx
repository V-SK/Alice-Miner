import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/tauri";
import { useAppStore } from "../hooks/useAppStore";

export default function Dashboard() {
  const {
    walletAddress,
    miningState,
    setMiningState,
    networkStatus,
    gpuInfo,
    addLog,
  } = useAppStore();
  
  const [currentLoss, setCurrentLoss] = useState(11.5);
  const [epochProgress, setEpochProgress] = useState(0);

  // Polling for mining status
  useEffect(() => {
    const poll = async () => {
      try {
        const status = await invoke<any>("get_mining_status");
        setMiningState(status);
        
        // Update loss if available
        if (status.current_loss) {
          setCurrentLoss(status.current_loss);
        }
      } catch (e) {
        console.error("Failed to get mining status:", e);
      }
    };

    const interval = setInterval(poll, 2000);
    return () => clearInterval(interval);
  }, []);

  // Simulate epoch progress (TODO: get from PS API)
  useEffect(() => {
    if (miningState.status === "Running") {
      const interval = setInterval(() => {
        setEpochProgress((p) => (p >= 100 ? 0 : p + Math.random() * 2));
      }, 1000);
      return () => clearInterval(interval);
    }
  }, [miningState.status]);

  const startMining = async () => {
    if (!walletAddress) return;
    
    const gpu = gpuInfo.find((g) => g.is_supported);
    if (!gpu) {
      addLog("No supported GPU found", "error");
      return;
    }

    try {
      addLog("Starting mining...", "info");
      await invoke("start_mining", {
        walletAddress,
        gpuIndex: gpu.index,
      });
      addLog("Mining started successfully", "success");
    } catch (e: any) {
      addLog(`Failed to start mining: ${e}`, "error");
    }
  };

  const stopMining = async () => {
    try {
      addLog("Stopping mining...", "info");
      await invoke("stop_mining");
      addLog("Mining stopped", "info");
    } catch (e: any) {
      addLog(`Failed to stop mining: ${e}`, "error");
    }
  };

  const isRunning = miningState.status === "Running";
  const supportedGpu = gpuInfo.find((g) => g.is_supported);

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <div className="flex items-center gap-2">
          <div className={`status-dot ${isRunning ? "" : "idle"}`} />
          <span className="text-sm text-zinc-400">
            {miningState.status}
          </span>
        </div>
      </div>

      {/* Neural Core Card */}
      <div className="card">
        <div className="flex items-center gap-6">
          {/* Breathing Logo */}
          <div
            className={`w-20 h-20 rounded-2xl bg-gradient-to-br from-alice-500 to-alice-600 flex items-center justify-center ${
              isRunning ? "animate-breathe animate-glow" : "opacity-50"
            }`}
          >
            <svg viewBox="0 0 1024 1024" className="w-12 h-12 fill-white">
              <path d="M471.24 165.64 166.68 821.56c-10.92 23.76 6.24 50.84 32.24 50.84h116.96c12.48 0 23.92-7.28 29.12-18.64L512 520.32l166.96 333.44c5.24 11.36 16.68 18.64 29.12 18.64h116.96c26 0 43.2-27.08 32.28-50.84L552.76 165.64c-8.32-18.04-34.2-18.04-42.52 0l-39 84.88z" />
            </svg>
          </div>

          {/* Stats */}
          <div className="flex-1 grid grid-cols-4 gap-6">
            <div>
              <div className="text-xs text-zinc-500 mb-1">MODEL</div>
              <div className="font-semibold">7B Dense</div>
            </div>
            <div>
              <div className="text-xs text-zinc-500 mb-1">EPOCH</div>
              <div className="font-semibold">
                {networkStatus?.chain_epoch ?? "—"}
              </div>
            </div>
            <div>
              <div className="text-xs text-zinc-500 mb-1">GPU</div>
              <div className="font-semibold truncate">
                {supportedGpu?.name.replace("NVIDIA ", "") ?? "—"}
              </div>
            </div>
            <div>
              <div className="text-xs text-zinc-500 mb-1">SHARDS</div>
              <div className="font-semibold">
                {miningState.shards_completed}
              </div>
            </div>
          </div>
        </div>

        {/* Loss Display */}
        <div className="mt-6 flex items-end justify-between">
          <div>
            <div className="text-xs text-zinc-500 mb-1">CURRENT LOSS</div>
            <div className="text-4xl font-bold font-mono text-alice-500">
              {currentLoss.toFixed(4)}
            </div>
          </div>
          <div className="text-right">
            <div className="text-xs text-zinc-500 mb-1">TARGET</div>
            <div className="text-xl font-semibold text-green-500">3.0</div>
            <div className="text-xs text-zinc-500">(GPT-2 Level)</div>
          </div>
        </div>

        {/* Progress Bar */}
        <div className="mt-4">
          <div className="flex justify-between text-xs text-zinc-500 mb-2">
            <span>Training Progress</span>
            <span>{((11.8 - currentLoss) / (11.8 - 3.0) * 100).toFixed(1)}%</span>
          </div>
          <div className="flex gap-1">
            {Array.from({ length: 16 }).map((_, i) => (
              <div
                key={i}
                className={`flex-1 h-1.5 rounded ${
                  i < Math.floor(((11.8 - currentLoss) / (11.8 - 3.0)) * 16)
                    ? "bg-alice-500"
                    : "bg-zinc-800"
                }`}
              />
            ))}
          </div>
        </div>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-2 gap-4">
        <div className="stat-card">
          <div className="text-xs text-zinc-500 mb-1">Total Earned</div>
          <div className="text-2xl font-bold text-alice-500 font-mono">
            0.00
          </div>
          <div className="text-xs text-zinc-500">ALICE</div>
        </div>
        <div className="stat-card">
          <div className="text-xs text-zinc-500 mb-1">This Epoch</div>
          <div className="text-2xl font-bold text-green-500 font-mono">
            0.00
          </div>
          <div className="text-xs text-zinc-500">ALICE</div>
        </div>
      </div>

      {/* Current Task */}
      <div className="card">
        <div className="flex justify-between items-center mb-3">
          <span className="text-sm text-zinc-400">Current Task</span>
          <span className="text-sm font-mono text-alice-500">
            {epochProgress.toFixed(0)}%
          </span>
        </div>
        <div className="progress-bar">
          <div
            className="progress-fill"
            style={{ width: `${epochProgress}%` }}
          />
        </div>
        {miningState.current_shard && (
          <div className="text-xs text-zinc-500 mt-2">
            Processing shard #{miningState.current_shard}
          </div>
        )}
      </div>

      {/* Control Buttons */}
      <div className="flex gap-3">
        {isRunning ? (
          <button onClick={stopMining} className="btn btn-danger flex-1">
            <StopIcon />
            Stop Mining
          </button>
        ) : (
          <button
            onClick={startMining}
            disabled={!supportedGpu}
            className="btn btn-success flex-1 disabled:opacity-50"
          >
            <PlayIcon />
            Start Mining
          </button>
        )}
      </div>

      {/* Error message */}
      {miningState.error_message && (
        <div className="card border-red-500/50 text-red-500 text-sm">
          {miningState.error_message}
        </div>
      )}
    </div>
  );
}

function PlayIcon() {
  return (
    <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
      <path d="M8 5v14l11-7z" />
    </svg>
  );
}

function StopIcon() {
  return (
    <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
      <rect x="6" y="6" width="12" height="12" rx="2" />
    </svg>
  );
}
