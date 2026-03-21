export default function Earnings() {
  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold">Earnings</h1>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4">
        <div className="stat-card">
          <div className="text-xs text-zinc-500 mb-1">Total Earned</div>
          <div className="text-2xl font-bold text-alice-500 font-mono">0.00</div>
          <div className="text-xs text-zinc-500">ALICE</div>
        </div>
        <div className="stat-card">
          <div className="text-xs text-zinc-500 mb-1">Today</div>
          <div className="text-2xl font-bold text-green-500 font-mono">0.00</div>
          <div className="text-xs text-zinc-500">ALICE</div>
        </div>
      </div>

      {/* Chart Placeholder */}
      <div className="card">
        <h3 className="font-semibold mb-4">7-Day Earnings</h3>
        <div className="h-40 flex items-end justify-around gap-2">
          {[
            { day: "Mon", h: 0 },
            { day: "Tue", h: 0 },
            { day: "Wed", h: 0 },
            { day: "Thu", h: 0 },
            { day: "Fri", h: 0 },
            { day: "Sat", h: 0 },
            { day: "Sun", h: 0 },
          ].map(({ day, h }) => (
            <div key={day} className="flex-1 flex flex-col items-center gap-2">
              <div
                className="w-full bg-gradient-to-t from-alice-600 to-alice-500 rounded-t"
                style={{ height: `${h}%` }}
              />
              <span className="text-xs text-zinc-500">{day}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Epoch History */}
      <div className="card">
        <h3 className="font-semibold mb-4">Epoch History</h3>
        <div className="text-center py-8 text-zinc-500">
          No earnings yet. Start mining to earn ALICE!
        </div>
      </div>
    </div>
  );
}
