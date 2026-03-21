import { useAppStore } from "../hooks/useAppStore";

export default function Wallet() {
  const { walletAddress } = useAppStore();

  const copyAddress = () => {
    if (walletAddress) {
      navigator.clipboard.writeText(walletAddress);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold">Wallet</h1>

      {/* Address Card */}
      <div className="card">
        <div className="text-xs text-zinc-500 mb-2">Wallet Address</div>
        <div className="flex items-center gap-3">
          <div className="flex-1 font-mono text-sm bg-zinc-900 rounded-lg px-4 py-3 break-all">
            {walletAddress}
          </div>
          <button onClick={copyAddress} className="btn btn-secondary">
            <CopyIcon />
            Copy
          </button>
        </div>
      </div>

      {/* Balance */}
      <div className="card">
        <div className="text-center py-8">
          <div className="text-xs text-zinc-500 mb-2">Total Balance</div>
          <div className="text-5xl font-bold text-alice-500 font-mono">
            0.00
          </div>
          <div className="text-zinc-500 mt-1">ALICE</div>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="card">
        <h3 className="font-semibold mb-4">Recent Activity</h3>
        <div className="text-center py-8 text-zinc-500">
          No transactions yet
        </div>
      </div>
    </div>
  );
}

function CopyIcon() {
  return (
    <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
      <rect x="9" y="9" width="13" height="13" rx="2" />
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
    </svg>
  );
}
