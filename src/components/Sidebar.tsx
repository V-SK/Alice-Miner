import { useAppStore } from "../hooks/useAppStore";

interface SidebarProps {
  currentPage: string;
  onPageChange: (page: any) => void;
}

const navItems = [
  { id: "dashboard", label: "Dashboard", icon: DashboardIcon },
  { id: "wallet", label: "Wallet", icon: WalletIcon },
  { id: "hardware", label: "Hardware", icon: HardwareIcon },
  { id: "earnings", label: "Earnings", icon: EarningsIcon },
  { id: "logs", label: "Logs", icon: LogsIcon },
  { id: "settings", label: "Settings", icon: SettingsIcon },
];

export default function Sidebar({ currentPage, onPageChange }: SidebarProps) {
  const { miningState, networkStatus } = useAppStore();

  return (
    <div className="w-56 bg-zinc-950 border-r border-zinc-800 flex flex-col">
      {/* Logo */}
      <div className="p-4 border-b border-zinc-800">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-alice-500 to-alice-600 flex items-center justify-center">
            <svg viewBox="0 0 1024 1024" className="w-6 h-6 fill-white">
              <path d="M471.24 165.64 166.68 821.56c-10.92 23.76 6.24 50.84 32.24 50.84h116.96c12.48 0 23.92-7.28 29.12-18.64L512 520.32l166.96 333.44c5.24 11.36 16.68 18.64 29.12 18.64h116.96c26 0 43.2-27.08 32.28-50.84L552.76 165.64c-8.32-18.04-34.2-18.04-42.52 0l-39 84.88z" />
            </svg>
          </div>
          <div>
            <div className="font-semibold text-white">Alice Miner</div>
            <div className="text-xs text-zinc-500">v0.1.0</div>
          </div>
        </div>
      </div>

      {/* Status */}
      <div className="p-4 border-b border-zinc-800">
        <div className="flex items-center gap-2 mb-2">
          <div
            className={`status-dot ${
              miningState.status === "Running"
                ? ""
                : miningState.status === "Error"
                ? "error"
                : "idle"
            }`}
          />
          <span className="text-sm text-zinc-300">
            {miningState.status === "Running" ? "Mining" : miningState.status}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <div
            className={`status-dot ${
              networkStatus?.ps_reachable ? "" : "error"
            }`}
          />
          <span className="text-sm text-zinc-300">
            {networkStatus?.ps_reachable ? "Connected" : "Disconnected"}
          </span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-2">
        {navItems.map((item) => (
          <button
            key={item.id}
            onClick={() => onPageChange(item.id)}
            className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition-all ${
              currentPage === item.id
                ? "bg-alice-500/10 text-alice-500"
                : "text-zinc-400 hover:text-white hover:bg-zinc-800/50"
            }`}
          >
            <item.icon
              className={`w-5 h-5 ${
                currentPage === item.id ? "text-alice-500" : ""
              }`}
            />
            <span className="text-sm font-medium">{item.label}</span>
          </button>
        ))}
      </nav>

      {/* Footer */}
      <div className="p-4 border-t border-zinc-800">
        <div className="text-xs text-zinc-600">
          Epoch {networkStatus?.chain_epoch ?? "—"} • Model v
          {networkStatus?.model_version ?? "—"}
        </div>
      </div>
    </div>
  );
}

// Icons
function DashboardIcon({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      className={className}
    >
      <rect x="3" y="3" width="7" height="9" rx="1" />
      <rect x="14" y="3" width="7" height="5" rx="1" />
      <rect x="14" y="12" width="7" height="9" rx="1" />
      <rect x="3" y="16" width="7" height="5" rx="1" />
    </svg>
  );
}

function WalletIcon({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      className={className}
    >
      <path d="M21 12V7a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-5z" />
      <path d="M16 12h.01" />
    </svg>
  );
}

function HardwareIcon({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      className={className}
    >
      <rect x="4" y="4" width="16" height="16" rx="2" />
      <path d="M9 9h6v6H9z" />
      <path d="M9 1v3M15 1v3M9 20v3M15 20v3M1 9h3M1 15h3M20 9h3M20 15h3" />
    </svg>
  );
}

function EarningsIcon({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      className={className}
    >
      <path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6" />
    </svg>
  );
}

function LogsIcon({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      className={className}
    >
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <path d="M14 2v6h6M16 13H8M16 17H8M10 9H8" />
    </svg>
  );
}

function SettingsIcon({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      className={className}
    >
      <circle cx="12" cy="12" r="3" />
      <path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" />
    </svg>
  );
}
