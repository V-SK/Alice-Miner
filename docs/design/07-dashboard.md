# 07 — Local Dashboard: Content + Data Plumbing

> **Scope of this dimension.** WHAT the Miner's own dashboard *shows* and WHERE
> every number *comes from*. The *visual* treatment (layout, components, colors,
> motion) is owned by the UI dimension (`08-ui.md`); this doc only specifies the
> **data model**, the **two data sources**, the **refresh model**, the
> **local-vs-server reconciliation**, and the honest **idle / disconnected /
> error** states. Credit-only is a hard invariant and is enforced in the data
> layer here, not just in copy.
>
> Status: design only. No product source is modified.

---

## 0. TL;DR (the load-bearing decisions)

1. **Two independent sources, never blended into one "truth" number.**
   - **Source A — LOCAL (live, instant):** parse each miner child's stdout via
     the per-lane supervisor (reuse the Wallet's `MinerSupervisor` parser
     verbatim). Gives *this machine's* hashrate + accepted/rejected shares +
     process state, sub-second, offline-capable. **This is "活" (activity), not
     credit.**
   - **Source B — SERVER (authoritative credit):** poll the proxy's **public,
     read-only** stats by the user's **Alice address**. Gives the *credited
     score* the relay actually attributed to the address. **This is the only
     thing the dashboard may call "credit / score earned."** Slow (30–60 s),
     network-dependent.
2. **The dashboard shows BOTH, side by side, clearly labelled** — "This device
   (live)" vs "Credited to your address (pool-confirmed)". It **never** reconciles
   them into a single figure and **never** silently substitutes one for the other.
   A small reconciliation badge explains drift ("pool confirming…", "in sync",
   "ahead of pool").
3. **Credit-only is enforced in the type system.** The credit figure is a
   `CreditScore` newtype with **no fiat/payout field and no `Display` that
   appends a currency**. `paid_acu` from the server is asserted `== "0"` and, if
   ever non-zero, the value is dropped and an error state shown — we never render
   a payout.
4. **OPEN QUESTION for V (the one real fork):** the proxy's *public* endpoints
   (`/shadow/window`, `/shadow/balance`) key credit by `passport_id|device_id`
   (C2/roster identity), **not** by the open-enrollment Alice address the Miner
   logs in with. So today there is **no address-keyed public read surface** that
   matches the Miner's open-enrollment credit key `(address|worker_label)`. See
   §6. Until V picks an option, Source B degrades gracefully to "credit confirmed
   on the relay; per-address breakdown not yet exposed" and the dashboard leans on
   Source A for the live experience. **This does not block the Miner shipping.**

---

## 1. What the dashboard shows (content inventory)

The dashboard is the Miner's home screen after the one-click Start. Everything
below is **credit-only**: no price, no fiat, no payout, no "claim".

### 1.1 Hero / status band (always visible)

| Element | Meaning | Source |
|---|---|---|
| **Overall state pill** | `Idle` / `Starting` / `Mining` / `Reconnecting` / `Error` (aggregate of all active lanes) | A (derived from per-lane `ProcState`) |
| **Active lane chips** | One chip per running lane: `CPU · XMR`, `GPU · RVN`, `AI` (lane label + algo); colored per brand lane colors | A |
| **Combined live hashrate** | Sum of per-lane live hashrate, human-formatted (H/s → kH/s → MH/s → GH/s) | A |
| **Uptime** | Wall-clock since the *current* mining session's first lane started; pauses to 0 when all lanes stop | local clock |
| **Relay connection dot** | `online` (green) / `checking` (amber) / `offline` (zinc) — relay reachability per lane, aggregated | A (per-child connection inference) + B (last successful poll) |

### 1.2 Per-device / per-lane table

One row per **active or recently-active lane** (a single machine may run CPU+GPU
dual-mine, so "per-device" here means *per-lane on this device*):

| Column | Source | Notes |
|---|---|---|
| Lane | A | `CPU · XMR (RandomX)`, `GPU · RVN (KawPoW)`, `AI` |
| Backend | A | `xmrig`, `kawpowminer`/`t-rex`, `inference-worker` (binary name) |
| State | A | per-lane `ProcState` → pill |
| Hashrate | A | live 10s figure (60s fallback), `None` → "—" until first speed line |
| Accepted / Rejected | A | cumulative `(A/R)` from stdout |
| Reject % | A (derived) | `rejected / (accepted+rejected)`; amber > 2%, red > 5% |
| Worker id | A (static) | `derive_worker_id(address)` — the on-wire rig id (PUBLIC, address-derived) |
| Last line | A | sanitized last stdout line ("what is it doing right now") |

For the **AI lane** the columns adapt: instead of hashrate/shares it shows
*jobs completed*, *tokens in/out (session)*, *last job latency*, and *ACU this
session (local estimate)* — all from the inference worker client's local return
values (`run_once` result), clearly tagged "local estimate, pool-confirmed below".

### 1.3 Credit panel (the "earnings" — credit-only)

This is the only place the word "earned" appears, and it is **always** qualified.

| Element | Meaning | Source |
|---|---|---|
| **Credited score (your address)** | The authoritative `simulated_alice_credit` / `rewardable_score` summed for the user's address over the chosen window | **B** |
| **Window** | the settlement window the figure covers (e.g. "last 4 h", with start/end ISO) | B |
| **`paid_acu`** | **always shown as `0`**, with a tooltip: "Payout is off (phase-J). You are accruing credit/score, not a payable balance." | B (asserted `=="0"`) |
| **Live (this device, unconfirmed)** | accepted shares × lane (a *local activity* readout, NOT a credit projection) | A |
| **Reconciliation badge** | `in sync` / `pool confirming…` / `ahead of pool` / `pool unreachable` | A vs B (see §5) |
| **Last pool sync** | "updated 18 s ago" relative timestamp | B (poll clock) |

**Hard rule:** the live accepted-share count is **never** multiplied by any rate
to produce a "you will earn N ALICE" number on the client. The Wallet's
`evaluate_reward_projection` / `estimated_rewards` / `confirmed_rewards` /
`held_rewards` machinery (`alice-wallet/gui/src/miner.rs:157-205`) is **explicitly
NOT reused** — it is a server-evidence projector the relay drives, and porting it
client-side would invite a fabricated-earnings figure. The Miner shows only
(a) raw local activity and (b) the server's own credited score. (See §7.)

### 1.4 History / sparkline (lightweight)

- A rolling in-memory ring buffer (last ~30 min, 1 sample / refresh tick) of
  combined hashrate → a sparkline. **Not persisted** in v1 (no on-disk metrics
  DB); resets on app restart. Optional v2: append to
  `~/.alice/miner/metrics.jsonl` (append-only, capped).
- Cumulative accepted/rejected since session start (from A).

### 1.5 Footer / honesty strip (always visible)

A persistent one-liner the UI renders muted: **"Credit-only · no payout ·
experimental"** plus the relay host (`hk.aliceprotocol.org`) and the active
address (truncated `a2…xyz`, click to copy). This mirrors the Wallet's
experimental badge posture (`MINING_EXPERIMENTAL = true`,
`alice-wallet/gui/src/miner.rs:16`).

---

## 2. Source A — local live (supervisor stdout parsing)

### 2.1 Reuse, don't rebuild

Reuse the Wallet's proven parser and process model **verbatim** (survey
"miner-reuse"). The dashboard consumes a cloneable snapshot per frame; the
supervisor owns the child and the parse.

- `MinerSupervisor` + `MinerStats` —
  `alice-wallet/gui/src/supervise/miner_supervisor.rs:38-133`
  (running, `state: ProcState`, `hashrate_hs: Option<f64>`, `accepted`,
  `rejected`, `last_exit_code`, `message`, `last_line`).
- `parse_hashrate_hs()` (10s→60s fallback) — `miner_supervisor.rs:273-295`.
- `parse_share_counts()` (`(A/R)` pair) — `miner_supervisor.rs:301-314`.
- `ProcState` (`Stopped/Starting/Running/Stopping/Error`, `is_active()`) —
  `alice-wallet/gui/src/supervise/mod.rs:38-76`.
- `spawn_supervised` + `OwnedChild` (SIGTERM→SIGKILL, `kill_on_drop`) —
  `alice-wallet/gui/src/supervise/child.rs`.

### 2.2 Multi-lane supervisor (the one extension needed)

The Wallet runs a single XMR lane. The Miner dual-mines, so the dashboard reads a
**registry of supervisors**, one per active lane. New, miner-only:

```
alice-miner/src/dashboard/lanes.rs
  pub enum LaneId { CpuXmr, GpuRvn, Ai }          // stable lane identity
  pub struct LaneSnapshot {                         // per-lane UI-safe snapshot
      pub lane: LaneId,
      pub backend: &'static str,                    // "xmrig" | "kawpowminer" | "trex" | "inference"
      pub stats: MinerStats,                        // REUSED type from the Wallet
      pub connection: ConnState,                    // derived, see §2.4
      pub started_at: Option<Instant>,
  }
  pub struct LaneRegistry {                         // owns N supervisors
      cpu_xmr: Option<MinerSupervisor>,
      gpu_rvn: Option<GpuMinerSupervisor>,          // T-Rex/KawPowMiner variant (own parser)
      ai:      Option<InferenceLaneState>,          // wraps inference_worker_client returns
  }
  impl LaneRegistry {
      pub fn snapshot(&self) -> DashboardModel { ... } // §3 — the single read the UI binds to
  }
```

- **GPU lane** needs a sibling supervisor with a T-Rex/KawPowMiner stdout parser
  (regexes already specified in survey "gpu-miners":
  `Alice-Protocol/miner/mining_internal/trex_logs.py`). Same `MinerStats` shape so
  the dashboard table is uniform. Implementation of that parser is the GPU/worker
  dimension's job; the dashboard only consumes `MinerStats`.
- **AI lane** has no stdout child of the same shape; its `MinerStats`-equivalent
  is synthesized from `inference_worker_client.run_once()` return values
  (`Alice-Protocol/miner/mining_internal/inference_worker_client.py`): jobs,
  tokens, latency, local ACU estimate. The dashboard treats it as a lane with
  `hashrate_hs = None` and AI-specific fields.

### 2.3 What A can and cannot tell us (honesty boundary)

- A **can** prove: the child is alive, it has a hashrate, the pool **accepted N
  shares from this connection**. That is real, local, instant.
- A **cannot** prove: how much *credit* the relay attributed (vardiff, lane budget
  split, dedup, anti-cheat recount all happen server-side). So A's accepted count
  is **activity**, never a credit figure. The UI copy reflects this.

### 2.4 Connection state inference (`ConnState`)

XMRig/T-Rex don't emit a clean machine-readable "connected" event, so infer from
the supervisor snapshot (no new IPC):

```
ConnState = Online    if state==Running AND (hashrate_hs.is_some()
                                             OR accepted increased in last window
                                             OR last_line matches /new job|use pool|connected/i)
          = Checking   if state==Starting OR (Running but no hashrate yet and < ~30s in)
          = Offline    if last_line matches /connect (error|failed|refused|timeout)|no active pools/i
          = Stopped    if !state.is_active()
          = Error      if state==Error
```

A tiny matcher `infer_conn_state(&MinerStats, since_start)` in
`alice-miner/src/dashboard/conn.rs`. This is best-effort and labelled as such
(the green dot means "looks connected", not a handshake guarantee).

---

## 3. The single UI-facing model

The UI binds to **one** struct, recomputed each refresh tick. No widget reads a
supervisor directly.

```
alice-miner/src/dashboard/model.rs

pub struct DashboardModel {
    // ---- aggregate (hero band) ----
    pub overall: OverallState,           // Idle|Starting|Mining|Reconnecting|Error
    pub combined_hashrate_hs: Option<f64>,
    pub uptime_secs: u64,
    pub relay: ConnState,                // aggregated connection
    pub active_lanes: Vec<LaneId>,

    // ---- per-lane (table) ----
    pub lanes: Vec<LaneSnapshot>,        // §2.2

    // ---- credit panel (Source B) ----
    pub credit: CreditView,              // §4

    // ---- reconciliation ----
    pub recon: ReconBadge,               // §5

    // ---- honesty ----
    pub address_display: String,         // truncated a2…xyz
    pub relay_host: &'static str,        // "hk.aliceprotocol.org"
    pub experimental: bool,              // true
    pub credit_only_note: &'static str,  // localized "credit-only · no payout"
}

pub enum OverallState { Idle, Starting, Mining, Reconnecting, Error }
```

`overall` derivation: `Error` if any lane is `Error`; else `Reconnecting` if any
active lane is `Offline`/`Checking`; else `Mining` if any lane `Running` with
hashrate; else `Starting` if any active; else `Idle`.

---

## 4. Source B — authoritative credited score (public read-only API)

### 4.1 The credit-only score type (enforcement)

```
alice-miner/src/dashboard/credit.rs

/// A pool-confirmed CREDIT score. Deliberately NOT a balance: no fiat, no payout,
/// no currency Display. Constructed only from a server response whose paid_acu=="0".
#[derive(Clone, PartialEq)]
pub struct CreditScore(Decimal);     // rust_decimal; never f64 for money-shaped values

impl CreditScore {
    pub fn render(&self) -> String { format!("{} credit", self.0) } // "credit", never a $ sign
}

pub struct CreditView {
    pub state: CreditState,          // Loading|Confirmed|Unavailable|NotExposed|Error
    pub score: Option<CreditScore>,  // Source B authoritative figure
    pub window_label: String,        // "last 4 h"
    pub window_start: Option<DateTime<Utc>>,
    pub window_end:   Option<DateTime<Utc>>,
    pub last_synced:  Option<Instant>,
    pub paid_acu_is_zero: bool,      // asserted; if false -> CreditState::Error
}

pub enum CreditState { Loading, Confirmed, Unavailable, NotExposed, Error }
```

`CreditState::NotExposed` is the graceful-degradation state for the §6 open
question (relay confirms credit exists but no per-address public breakdown yet).

### 4.2 The client + the exact server contract

```
alice-miner/src/dashboard/pool_stats.rs
  pub struct PoolStatsClient { base_url: String, http: reqwest::Client, addr: String }
  impl PoolStatsClient {
      pub async fn fetch_credit(&self, window: WindowSpec) -> Result<CreditView, PoolStatsError>;
  }
```

Server JSON contract (verified against
`alice-acp/src/alice_acp/shadow_server/http_app.py`):

- **`GET /shadow/window`** (persisting) / **`/shadow/window/preview`** (read-only,
  preferred for a polling client so it doesn't spam the audit log) —
  `http_app.py:780-794`, builder `_settlement_result_json` `http_app.py:1797-1815`.
  Returns:
  ```json
  {
    "window": { "window_id": "...", "starts_at": "...", "ends_at": "...",
                "total_window_emission": "..." },
    "pool_budgets": { "xmr_pool": "...", "main_pool_gpu_rvn": "...",
                      "scrypt_pool": "...", "main_pool_gpu_quai": "..." },
    "device_credits": {
      "<passport_id>|<device_id>": {
        "passport_id": "...", "device_id": "...",
        "simulated_alice_credit": "123.45", "paid_acu": "0"
      }
    },
    "reward_statements": [...], "reserve_roll_forward": "...", "paid_acu": "0"
  }
  ```
- **`GET /shadow/balance?passport_id=..&device_id=..&starts_at=..&hours=4`** —
  `http_app.py:796-814`. Returns a single `{simulated_alice_credit, paid_acu:"0",
  read_only_preview}`.
- Window query params: `starts_at` (ISO, required), `hours` (default `"4"`),
  `window_id`, `total_window_emission` — parser `_window_from_query`
  `http_app.py:1760-1770`.
- **Credit-only envelope on every response:** `live_reward_enabled=false`,
  `payout_executor_enabled=false`, `chain_writes_enabled=false`, `paid_acu="0"`
  (`_credit_only_envelope` `http_app.py:1683-1700`). The client **asserts**
  `paid_acu=="0"` and sets `CreditState::Error` if violated (defense in depth —
  we will not render a payout even if the server regresses).

### 4.3 The keying problem (why a default WindowSpec is not enough)

`device_credits` is keyed by **`passport_id|device_id`**, and `/shadow/balance`
*requires* `passport_id` + `device_id`. But the Miner uses the proxy's
**open-enrollment** path, where the credit key is **`(Alice address |
worker_label)`** → server-derived opaque `worker_name` `alc-w-<hex>`
(`alice-acp/src/alice_acp/transport_front/open_enrollment.py:224-239`), and the
miner **never** sends a passport/device id. **The open-enrollment Alice address is
not a key in the public `/shadow/*` responses.** This is the §6 fork.

The provider that *does* attribute by address is server-internal
(`alice-acp/src/alice_acp/shadow_server/pool_evidence_providers.py` — "server-read
per-worker shares, never client claims", keyed by `(pool_id, address,
worker_name, epoch_label)`), but it is **not exposed as a public read-only HTTP
endpoint today.** The tw-pool integration (memory) polls upstream
`api.tw-pool.com/api/worker_stats` *server-side*; the client has no equivalent.

**Therefore Source B, as specified against the *current* public API, can only
prove "credit accounting is live and payout is off" — it cannot yet return a
per-address number for an open-enrollment miner.** The dashboard handles this
honestly via `CreditState::NotExposed` (§5.3), and Source A carries the live
experience. See §6 for the three ways V can close this.

---

## 5. Refresh model + reconciliation

### 5.1 Two clocks

| Source | Cadence | Mechanism |
|---|---|---|
| **A (local)** | UI frame rate / ~250 ms repaint while mining | `LaneRegistry::snapshot()` reads the in-memory supervisor mutexes (already updated by the async log pump). No I/O on the UI thread. |
| **B (server)** | **30 s** default, **60 s** when backgrounded; jittered ±10% | a dedicated tokio task (`pool_stats_poller`) calls `fetch_credit`, writes the result into a shared `Arc<Mutex<CreditView>>` the model reads. Never on the UI thread. Single-flight (no overlapping requests); exponential backoff to 5 min on repeated failure. |

The provider cache upstream is ~one snapshot reused for a poll window
(`pool_evidence_providers.py:102`), so polling faster than ~30 s buys nothing.

### 5.2 Reconciliation (A vs B) — show drift, never fake agreement

`ReconBadge` is computed each tick from the two snapshots:

```
alice-miner/src/dashboard/recon.rs

pub enum ReconBadge {
    InSync,            // B confirmed AND B fresh (< 2 poll intervals) AND A has activity
    PoolConfirming,    // A shows accepted shares climbing but B hasn't caught up yet
    AheadOfPool,       // A accepted >> what B reflects (expected: vardiff/window lag)
    PoolUnreachable,   // B in backoff/error; A still local-authoritative
    Idle,              // nothing mining
    NotExposed,        // §6: B has no per-address figure to compare (open-enrollment)
}
```

Rules:
- We **never** compute "expected credit from A" to compare against B numerically.
  Reconciliation is **directional and qualitative**: does the pool's confirmed
  figure exist and is it moving in the same direction as local activity?
- `PoolConfirming` is the **normal** state for the first 1–4 min of a session
  (settlement windows are 4 h; credit lags shares). Copy: "Pool is confirming your
  shares — credit updates each window."
- `AheadOfPool` is also normal (a share submitted now lands in the *next* window).
  Copy: "Local activity ahead of the last pool snapshot — this is expected."
- If A says `accepted > 0` for a sustained period but B *persistently* shows zero
  for the address (and B is reachable + exposes the address), surface a **soft
  warning** ("shares accepted locally but not yet credited — check your address").
  This is the one place drift is treated as possibly-wrong, and it is worded as a
  prompt to verify, not an accusation.

### 5.3 The honest "credit panel" state machine

| `CreditState` | When | What the panel shows |
|---|---|---|
| `Loading` | first poll in flight | skeleton + "fetching pool-confirmed credit…" |
| `Confirmed` | B returned an address-keyed figure, `paid_acu=="0"` | the `CreditScore` + window + "updated Ns ago" |
| `NotExposed` | B reachable, healthy, credit-only confirmed, but no per-address breakdown (§6 today) | "Credit accounting is live (payout off). Per-address total isn't exposed yet — your local accepted shares are below." + link to address on explorer |
| `Unavailable` | B reachable but address genuinely has no credit this window | "No credit yet this window." |
| `Error` | B unreachable after backoff, OR `paid_acu != "0"` (invariant breach → drop value) | "Pool stats unreachable — showing local activity only." (never a number) |

---

## 6. OPEN QUESTION for V (the one real fork)

**There is no public, address-keyed read endpoint that matches the Miner's
open-enrollment credit key today.** The public `/shadow/window` + `/shadow/balance`
key by `passport_id|device_id`; the open-enrollment credit key is `(Alice address
| worker_label) → worker_name`. Pick one (all are server-side; none change the
client beyond the `PoolStatsClient` URL/parse):

- **Option 1 — Address-keyed public stats endpoint (recommended).** Add a
  read-only `GET /public/credit?address=<a2…>&hours=4` on the shadow/relay that
  sums the address's `rewardable_score` across its `worker_name`s for the window,
  returning the same credit-only envelope (`paid_acu:"0"`). This is the cleanest
  match to the survey's "public read-only stats API by the user's address" and
  makes `CreditState::Confirmed` reachable for the Miner. (The internal
  per-address attribution already exists in `pool_evidence_providers.py`; this is
  an exposure, not new accounting.)
- **Option 2 — Reuse `/shadow/balance` by mapping address→synthetic
  passport/device.** If open-enrollment miners are mirrored into the roster under
  a deterministic `passport_id/device_id` derived from the address, the existing
  endpoint works unchanged. More moving parts; couples open-enrollment to the C2
  roster.
- **Option 3 — Ship Source-B as "confirmation-only" for v1.** Dashboard uses
  `NotExposed`: it proves credit accounting is live + payout off (via the health/
  envelope), and leans entirely on Source A for the live number, with a deep link
  to the address on the public explorer/dashboard ("Alice聚合"). Zero server work;
  honest; defers the per-address figure to a later release.

**Recommendation: ship with Option 3 now (no server dependency, fully honest),
and adopt Option 1 as the fast-follow** so the credit panel can show a real
per-address confirmed score. The client code path is identical (`PoolStatsClient`
swaps URL + parse); only `CreditState` flips from `NotExposed` to `Confirmed`.

---

## 7. Explicitly NOT reused (and why)

- **`evaluate_reward_projection` / `WalletRewardProjection` / `estimated_rewards`
  / `confirmed_rewards` / `held_rewards` / `released_rewards`**
  (`alice-wallet/gui/src/miner.rs:100-205`). This is a *server-evidence
  projector* the relay feeds; reproducing it client-side would manufacture an
  "estimated earnings" figure from local shares — exactly the
  fabricated-earnings risk flagged in the #18 red-team. The Miner shows raw local
  activity (A) and the server's own credited score (B), nothing in between.
- **`AcceptedShareEvidence.estimated_rewards`** string fields — same reason.
- **Auto-restart loops** — inherited stance from `MinerSupervisor` (no restart on
  unexpected exit; land in `Error`), correct for a user-CPU/GPU tool.
- **Any payout / claim / settlement UI** — phase-J, OFF. `paid_acu` is rendered as
  a literal `0` with an explainer and asserted server-side.

---

## 8. Build manifest (files this dimension owns)

| File | Purpose |
|---|---|
| `alice-miner/src/dashboard/model.rs` | `DashboardModel`, `OverallState`, aggregation |
| `alice-miner/src/dashboard/lanes.rs` | `LaneId`, `LaneSnapshot`, `LaneRegistry` (N supervisors) |
| `alice-miner/src/dashboard/conn.rs` | `ConnState` + `infer_conn_state` heuristic |
| `alice-miner/src/dashboard/credit.rs` | `CreditScore` (credit-only newtype), `CreditView`, `CreditState` |
| `alice-miner/src/dashboard/pool_stats.rs` | `PoolStatsClient` + server JSON parse + `paid_acu=="0"` assert |
| `alice-miner/src/dashboard/recon.rs` | `ReconBadge` + reconciliation rules |
| `alice-miner/src/dashboard/poller.rs` | tokio `pool_stats_poller` (30/60 s, jitter, single-flight, backoff) |
| (reused) `…/supervise/miner_supervisor.rs`, `…/supervise/child.rs`, `…/supervise/mod.rs` | from the Wallet, verbatim |

**Crates:** `reqwest` (poll), `rust_decimal` (credit value), `tokio` (poller),
`chrono` (windows), `serde`/`serde_json` (parse). All already in the Wallet's
tree or trivially addable.

**Test hooks:** unit-test `infer_conn_state` (sample XMRig lines), `ReconBadge`
transitions (A-ahead-of-B, B-down), and a `paid_acu != "0"` → `CreditState::Error`
guard so the credit-only invariant fails the test (and ideally a `const`-asserted
compile guard mirroring `miner.rs:480-498`).
