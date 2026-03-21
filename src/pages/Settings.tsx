import { useState } from "react";
import { invoke } from "@tauri-apps/api/tauri";

export default function Settings() {
  const [autoStart, setAutoStart] = useState(false);
  const [notifications, setNotifications] = useState(true);
  const [language, setLanguage] = useState("en");

  const handleClearWallet = async () => {
    if (confirm("Are you sure you want to clear your wallet? This cannot be undone.")) {
      try {
        await invoke("clear_wallet");
        window.location.reload();
      } catch (e) {
        console.error("Failed to clear wallet:", e);
      }
    }
  };

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold">Settings</h1>

      {/* General */}
      <div className="card space-y-4">
        <h3 className="font-semibold text-zinc-300">General</h3>
        
        <div className="flex items-center justify-between py-2">
          <div>
            <div className="font-medium">Language</div>
            <div className="text-sm text-zinc-500">Choose your preferred language</div>
          </div>
          <select
            value={language}
            onChange={(e) => setLanguage(e.target.value)}
            className="bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm"
          >
            <option value="en">English</option>
            <option value="zh">中文</option>
          </select>
        </div>

        <div className="flex items-center justify-between py-2">
          <div>
            <div className="font-medium">Start on boot</div>
            <div className="text-sm text-zinc-500">Automatically start when computer starts</div>
          </div>
          <Toggle checked={autoStart} onChange={setAutoStart} />
        </div>

        <div className="flex items-center justify-between py-2">
          <div>
            <div className="font-medium">Notifications</div>
            <div className="text-sm text-zinc-500">Show desktop notifications</div>
          </div>
          <Toggle checked={notifications} onChange={setNotifications} />
        </div>
      </div>

      {/* Mining */}
      <div className="card space-y-4">
        <h3 className="font-semibold text-zinc-300">Mining</h3>
        
        <div className="flex items-center justify-between py-2">
          <div>
            <div className="font-medium">Power Limit</div>
            <div className="text-sm text-zinc-500">Limit GPU power consumption</div>
          </div>
          <select className="bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm">
            <option>100% (Default)</option>
            <option>90%</option>
            <option>80%</option>
            <option>70%</option>
          </select>
        </div>
      </div>

      {/* Danger Zone */}
      <div className="card border-red-500/30 space-y-4">
        <h3 className="font-semibold text-red-500">Danger Zone</h3>
        
        <div className="flex items-center justify-between py-2">
          <div>
            <div className="font-medium">Clear Wallet</div>
            <div className="text-sm text-zinc-500">Remove wallet from this device</div>
          </div>
          <button onClick={handleClearWallet} className="btn btn-danger text-sm">
            Clear Wallet
          </button>
        </div>
      </div>

      {/* About */}
      <div className="card">
        <h3 className="font-semibold text-zinc-300 mb-4">About</h3>
        <div className="space-y-2 text-sm text-zinc-400">
          <div className="flex justify-between">
            <span>Version</span>
            <span>0.1.0</span>
          </div>
          <div className="flex justify-between">
            <span>Website</span>
            <a href="https://aliceprotocol.org" className="text-alice-500 hover:underline">
              aliceprotocol.org
            </a>
          </div>
          <div className="flex justify-between">
            <span>Documentation</span>
            <a href="https://aliceprotocol.org/mine" className="text-alice-500 hover:underline">
              Mining Guide
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}

function Toggle({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      onClick={() => onChange(!checked)}
      className={`w-11 h-6 rounded-full transition-colors ${
        checked ? "bg-alice-500" : "bg-zinc-700"
      }`}
    >
      <div
        className={`w-5 h-5 bg-white rounded-full transition-transform ${
          checked ? "translate-x-5" : "translate-x-0.5"
        }`}
      />
    </button>
  );
}
