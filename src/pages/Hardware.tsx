import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/tauri";
import { useAppStore } from "../hooks/useAppStore";

interface GpuStats {
  index: number;
  utilization_percent: number;
  memory_used_gb: number;
  memory_total_gb: number;
  temperature_c: number;
  power_watts: number;
  power_limit_watts: number;
}

export default function Hardware() {
  const { gpuInfo } = useAppStore();
  const [stats, setStats] = useState<GpuStats[]>([]);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const s = await invoke<GpuStats[]>("get_gpu_stats");
        setStats(s);
      } catch (e) {
        console.error("Failed to get GPU stats:", e);
      }
    };

    fetchStats();
    const interval = setInterval(fetchStats, 2000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold">Hardware</h1>

      {gpuInfo.map((gpu) => {
        const gpuStats = stats.find((s) => s.index === gpu.index);
        
        return (
          <div key={gpu.index} className="space-y-4">
            {/* GPU Card */}
            <div className="card flex items-center gap-4">
              <div className="w-12 h-12 rounded-lg bg-zinc-800 flex items-center justify-center">
                <GpuIcon />
              </div>
              <div className="flex-1">
                <div className="font-semibold">{gpu.name}</div>
                <div className="text-sm text-zinc-500">
                  {gpu.vram_total_gb.toFixed(1)} GB VRAM
                  {gpu.cuda_version && ` • CUDA ${gpu.cuda_version}`}
                  {gpu.driver_version && ` • Driver ${gpu.driver_version}`}
                </div>
              </div>
              <div className="flex items-center gap-2">
                <div className={`status-dot ${gpu.is_supported ? "" : "error"}`} />
                <span className="text-sm">{gpu.is_supported ? "Supported" : "Unsupported"}</span>
              </div>
            </div>

            {/* Usage Stats */}
            {gpuStats && (
              <>
                <div className="card">
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-sm text-zinc-400">GPU Usage</span>
                    <span className="font-mono text-alice-500">
                      {gpuStats.utilization_percent}%
                    </span>
                  </div>
                  <div className="progress-bar">
                    <div
                      className="progress-fill"
                      style={{ width: `${gpuStats.utilization_percent}%` }}
                    />
                  </div>
                </div>

                <div className="card">
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-sm text-zinc-400">VRAM Usage</span>
                    <span className="font-mono text-zinc-300">
                      {gpuStats.memory_used_gb.toFixed(1)} / {gpuStats.memory_total_gb.toFixed(1)} GB
                    </span>
                  </div>
                  <div className="progress-bar">
                    <div
                      className="progress-fill"
                      style={{
                        width: `${(gpuStats.memory_used_gb / gpuStats.memory_total_gb) * 100}%`,
                      }}
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div className="stat-card">
                    <div className="text-xs text-zinc-500 mb-1">Temperature</div>
                    <div className={`text-2xl font-bold font-mono ${
                      gpuStats.temperature_c > 80 ? "text-red-500" :
                      gpuStats.temperature_c > 70 ? "text-yellow-500" : "text-zinc-200"
                    }`}>
                      {gpuStats.temperature_c}
                    </div>
                    <div className="text-xs text-zinc-500">°C</div>
                  </div>
                  <div className="stat-card">
                    <div className="text-xs text-zinc-500 mb-1">Power Draw</div>
                    <div className="text-2xl font-bold font-mono text-zinc-200">
                      {gpuStats.power_watts}
                    </div>
                    <div className="text-xs text-zinc-500">
                      / {gpuStats.power_limit_watts} W
                    </div>
                  </div>
                </div>
              </>
            )}
          </div>
        );
      })}

      {gpuInfo.length === 0 && (
        <div className="card text-center py-8 text-zinc-500">
          No GPUs detected
        </div>
      )}
    </div>
  );
}

function GpuIcon() {
  return (
    <svg className="w-6 h-6 text-alice-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
      <rect x="4" y="4" width="16" height="16" rx="2" />
      <path d="M9 9h6v6H9z" />
    </svg>
  );
}
