# 02 — Device Detection · Lane Selection · One-Click · Dual-Mine

Status: design (research only — no product source touched).
Scope of this dimension: **detect the device → pick the lane → one button → mine**, including
**dual-mine** (CPU-XMR + GPU-RVN at once) and a **credit-only profit/auto-switch policy** with a
user override. Crypto/keystore, the XMR launch plan, and the process supervisor are designed in
sibling docs and **reused verbatim** here; this doc only wires them to hardware.

Grounding (cited inline):
- Reference detection impl (Python, to be ported to Rust): `/Users/v/Alice/Alice-Protocol/miner/mining_internal/hardware_probe.py`
- Proven XMR launch plan + Alice-address validation + worker-id derivation: `/Users/v/Alice/alice-wallet/gui/src/miner.rs`
- Single-child process supervisor (start/stop/stats, log pump, parsers): `/Users/v/Alice/alice-wallet/gui/src/supervise/miner_supervisor.rs`, `/Users/v/Alice/alice-wallet/gui/src/supervise/child.rs`
- Device-picker UI vocabulary + lane colors: `/Users/v/Alice/alice-website/mine.html` (lines 168–172, 199–202, 285–289)
- Relay endpoints/ports (XMR :3333, RVN :8888→core4444): MEMORY `alice-edge-node` + `mine.html:199-202`
- GPU miner selection (T-Rex now, KawPowMiner candidate): `/Users/v/Alice/Alice-Protocol/docs/rvn-kawpow-miner-selection.md`

---

## 0. Decisions up front (so the rest reads cleanly)

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | **Port `hardware_probe.py` to Rust** as `alice-miner/src/detect.rs`, keeping its struct shape, fail-safe contract, and override semantics. | It is the proven, dependency-light, fail-safe detector. A faithful port keeps client/server lane vocabulary aligned and is easy to diff-review. |
| D2 | **No heavy HW crates** (`sysinfo`/`wgpu`/`nvml`). Probe via stdlib + `std::process::Command` shelling `nvidia-smi` / `sysctl` / `wmic`/`wsl`, exactly like the Python. | Smaller binary, no driver linkage, fewer Windows-AV heuristics, identical behavior to the reference. |
| D3 | **Lane map: CPU→XMR (RandomX), GPU(NVIDIA)→RVN (KawPoW), Apple Silicon→XMR, ASIC→info-only.** **PRL is NOT a client lane** (fake-AI, ruled out — MEMORY). This is the one place the Rust matrix intentionally **diverges** from the Python (which defaults GPU→PRL). | Product brief + MEMORY GPU-LANE DIRECTION: client GPU lane = RVN, clean Alice-validated re-hash. |
| D4 | **Dual-mine = two independent `MinerSupervisor` instances** (one CPU-XMR, one GPU-RVN), not one merged child. | Reuses the existing single-child supervisor unchanged; isolates a crash/restart of one lane from the other. |
| D5 | **"Profit" = expected ALICE credit/hour. In credit-only mode all lanes pay the same ALICE and rates are unpublished (0)**, so the auto-policy reduces to a **static viability+capability ranking**, not a live $ optimizer. Fully overridable. | Brief: keep it simple + overridable; `mine.html:210` confirms rates are 0/pending. No payout math to get wrong. |
| D6 | **Auto picks ONE primary lane for one-click; dual-mine is an explicit toggle, default OFF.** | Safest default (heat/noise/laptop battery); power users opt into "拉满 both". |
| D7 | **GPU miner binary is on-demand, not bundled** initially (T-Rex/KawPowMiner), staged + sha256-verified. macOS/AMD GPU = no RVN miner → GPU lane shown as "not yet". | `rvn-kawpow-miner-selection.md` (operator-supplied, hash-gated); avoids shipping a closed miner. |

---

## 1. Device detection

### 1.1 Files / module layout

```
alice-miner/
└── src/
    └── detect/
        ├── mod.rs        // re-exports; detect_capability() one-call entry
        ├── profile.rs    // HardwareProfile + enums (GpuVendor, DeviceClass, Platform)
        ├── probe.rs      // fail-safe probes (gpu/cpu/mem/wsl), injectable runner
        ├── viability.rs  // HardwareProfile -> LaneViability matrix
        └── override.rs   // ALICE_MINER_LANES parse + apply (restrict / force)
```

Crates: stdlib only for probing (`std::process::Command`, `std::fs`, `std::env`,
`std::thread::available_parallelism`). Reuse the wallet's already-present `serde`/`serde_json`
for `to_dict()`/snapshots and `blake2`/`bs58`/`hex` for address/worker derivation (§4). **No new
crate** is required for detection.

### 1.2 Core types (Rust, mirrors `hardware_probe.py:117-209`)

```rust
// detect/profile.rs
#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Platform { MacOS, Linux, Windows, Unknown }

#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum GpuVendor { Nvidia, Amd, Apple, Intel, None }

/// What the user "sees" on the picker (mine.html vocabulary). Derived from profile.
#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum DeviceClass { Cpu, Gpu, Mac, Asic }   // Asic = info-only

#[derive(Clone, serde::Serialize)]
pub struct HardwareProfile {
    pub os_name: String,
    pub arch: String,                 // "x86_64" | "arm64" | ...
    pub platform: Platform,
    pub apple_silicon: bool,
    pub gpu_vendor: GpuVendor,
    pub gpu_model: String,            // "NVIDIA GeForce RTX 3070 Ti" | "Apple M2 Max" | ""
    pub vram_gb: u32,                 // dedicated VRAM; 0 for Apple unified / none
    pub cpu_model: String,
    pub cpu_cores: u32,               // LOGICAL cores (available_parallelism)
    pub memory_gb: u32,               // system RAM; 8 fallback
    pub wsl2_available: bool,         // Windows only; carried but unused by RVN/XMR
    pub probe_warnings: Vec<String>,  // every fallback recorded, never fatal
}
```

`HardwareProfile` helpers (ported from the Python `@property`s):
`is_windows/is_linux/is_macos`, `is_x86_64`, `has_nvidia`, and **`device_class()`** (new, for the UI):

```rust
impl HardwareProfile {
    pub fn device_class(&self) -> DeviceClass {
        if self.apple_silicon { DeviceClass::Mac }
        else if self.has_nvidia() { DeviceClass::Gpu }   // RVN-capable GPU
        else { DeviceClass::Cpu }                         // AMD/Intel/none GPU -> CPU lane
    }
    pub fn fallback() -> Self { /* cpu-only, warnings=["..._probe_failed"] */ }
}
```

> Note ASIC: an ASIC is **not auto-detected** (it is a separate box reached over the network).
> `DeviceClass::Asic` is selected **only** by the user choosing the ASIC card; detection never
> returns it. See §6.

### 1.3 The probes (each fail-safe — port of `hardware_probe.py:331-613`)

Injectable runner so tests/offline-smoke never shell out:
```rust
pub type SubprocessRunner = Box<dyn Fn(&[&str]) -> Result<String, ()> + Send + Sync>;
```

| Field | Source (in priority order) | Fallback | Python ref |
|-------|----------------------------|----------|------------|
| os/arch/platform | `std::env::consts::OS` / `ARCH` | `Unknown` | `_probe_os_arch` |
| apple_silicon | `platform == MacOS && arch ∈ {arm64,aarch64}` | false | `probe_hardware:285` |
| gpu (nvidia) | `nvidia-smi --query-gpu=name,memory.total --format=csv,noheader` → parse `name`, MiB→GB | `vendor=None` | `_probe_nvidia` |
| gpu (apple) | vendor=Apple, model=`sysctl -n machdep.cpu.brand_string`, vram=0 | `"Apple Silicon (arm64)"` | `_apple_gpu_label` |
| gpu (amd/intel) | **best-effort** (see §1.4) — default `None` if unconfirmed | `None` | new (Python returns None) |
| cpu_cores | `std::thread::available_parallelism()` | `1` | `_probe_cpu_cores` (we drop psutil) |
| cpu_model | macOS `sysctl machdep.cpu.brand_string`; Linux `/proc/cpuinfo` "model name"; Windows `wmic cpu get name` | `""` | `_probe_cpu_model` |
| memory_gb | macOS `sysctl -n hw.memsize`; Linux `/proc/meminfo MemTotal`; Windows `GlobalMemoryStatusEx` via `kernel32` (FFI) or `wmic ComputerSystem get TotalPhysicalMemory` | `8` | `_probe_memory` |
| wsl2 | Windows only: env `ALICE_MINER_WSL2_AVAILABLE` override → else `wsl --status` exit 0 | false | `_probe_wsl2` |

**Timeouts**: every shell-out is bounded (5 s) so a hung `nvidia-smi`/`wsl` cannot stall startup.
Implement via a spawn-and-`try_wait`-poll wrapper (no extra crate) or reuse the supervisor's
`OwnedChild` timed-wait helper from `supervise/child.rs`.

**Top-level entry** (port of `probe_hardware` + `detect_capability_profile`):
```rust
pub fn probe_hardware(runner: Option<SubprocessRunner>, env: &Env) -> HardwareProfile; // never panics
pub fn detect_capability(
    device_id: &str, device_label: &str,
    profile: Option<HardwareProfile>,   // injectable for tests/offline-smoke
    env: &Env,
) -> CapabilityProfile;                  // see §3
```

The whole thing is wrapped so **any** error degrades to `HardwareProfile::fallback()` with the
reason recorded in `probe_warnings` — matching the Python's "a probe failure must NEVER crash the
miner" contract (`hardware_probe.py:19-22, 312-328`).

### 1.4 AMD / Intel GPU (honest scope)

The reference impl does **not** guess AMD and neither do we for *lane viability* (no confirmed
RVN binary path for AMD/macOS in-tree — `rvn-kawpow-miner-selection.md` lists AMD as a
KawPowMiner *candidate*, not yet wired). We still **best-effort identify** an AMD/Intel GPU for
the **UI label** (so the picker can say "AMD Radeon detected — GPU mining coming soon") via:
- Linux: `lspci | grep -i vga` (string match `AMD/ATI`, `Intel`)
- Windows: `wmic path win32_VideoController get name`
- macOS Intel: `system_profiler SPDisplaysDataType` (rare; usually Apple anyway)

Result sets `gpu_vendor = Amd|Intel` + `gpu_model` but **does not** add the RVN lane (see §2).

---

## 2. Lane selection (the viability matrix)

### 2.1 Lane constants

```rust
// detect/viability.rs
pub enum Lane { Xmr, Rvn /*, Ai (sibling doc) */ }   // PRL intentionally absent
```
Only **XMR** and **RVN** are client mining lanes for this dimension. LTC/Quai/PRL are **not**
offered by the Miner client (LTC = ASIC manual-only; PRL = excluded; Quai = relay-side only).
AI is a separate lane owned by the ai-earn dimension and is merged into the same ranking (§5) if
that dimension marks it viable.

### 2.2 The matrix (diverges from Python only on PRL/RVN default)

| Device profile | XMR | RVN | Note |
|----------------|-----|-----|------|
| Any CPU (x86/ARM, any OS) | ✅ always | — | `cpu_always_viable` |
| NVIDIA present, miner binary available | ✅ | ✅ | `gpu→rvn` (the GPU default) |
| NVIDIA present, **no RVN binary staged** | ✅ | ⛔ `rvn_binary_not_staged` | offer on-demand download |
| AMD / Intel GPU | ✅ | ⛔ `rvn_requires_nvidia_amd_unconfirmed` | label only; force-override escape hatch |
| Apple Silicon | ✅ | ⛔ `rvn_requires_nvidia_apple_excluded` | Mac = XMR lane |
| ASIC (user-selected) | — | — | info-only, no local lane (§6) |

```rust
pub struct LaneViability {
    pub viable_lanes: Vec<Lane>,            // canonical order: [Xmr, Rvn]
    pub reasons: BTreeMap<Lane, String>,    // why viable / excluded (UI + tests)
    pub notes: Vec<String>,                 // operator hints
}
pub fn derive_lane_viability(p: &HardwareProfile, rvn_binary_ready: bool) -> LaneViability;
```

XMR is pushed first and unconditionally (`cpu_always_viable`), exactly like the Python
(`hardware_probe.py:636-640`). RVN is added iff `has_nvidia && rvn_binary_ready`. The reason
strings are kept verbatim where they exist in the Python so server/telemetry vocabulary lines up.

### 2.3 Override (`ALICE_MINER_LANES` — port of `hardware_probe.py:756-858`)

- `ALICE_MINER_LANES="xmr"` / `"rvn"` / `"xmr,rvn"` — restrict to the **intersection** of the
  request and the hardware-viable set (default; can narrow, can't conjure a lane).
- `ALICE_MINER_LANES_FORCE=1` — **replace** the viable set with exactly the requested lanes,
  even non-viable ones (escape hatch for an AMD KawPoW expert). Forced-but-non-viable lanes are
  tagged `forced_override` in `reasons`.
- Unknown token → `HardwareProbeError` (fail-closed parse).

Same `parse_lane_override` / `apply_lane_override` two-function shape as the Python.

---

## 3. CapabilityProfile (the one-call bundle the UI + one-click consume)

Port of `hardware_probe.py:864-931`:

```rust
#[derive(Clone, serde::Serialize)]
pub struct CapabilityProfile {
    pub profile: HardwareProfile,
    pub viability: LaneViability,
    pub device_class: DeviceClass,     // for the picker highlight
    pub recommended_lane: Option<Lane>,// the auto pick (§5); None only if nothing viable
    pub device_id: String,             // stable per-install id (sibling identity doc)
    pub device_label: String,          // human label e.g. "MacBook Pro (M2 Max)"
}
```

`detect_capability(...)` runs `probe_hardware → derive_lane_viability → apply_lane_override →
rank → recommended_lane`. It is the single function the UI calls on launch and the one-click flow
calls on Start. Injectable `profile` keeps it unit-testable with fixtures (no shell-out), matching
the Python's `--offline-smoke` discipline.

`device_id`/`device_label`: `device_id` is the stable per-install UUID written to `~/.alice/`
(owned by the identity/wallet dimension); **not** derived from hardware (privacy + matches the
existing `device_identity.py` pattern). The reward identity on the wire is the Alice **address**,
never `device_id` (§4).

---

## 4. One-click flow

The Miner's contract: **address present? → single Start button.** No lane question is ever put to
the casual user; auto picks it.

```
Launch
  └─ detect_capability()           // cached; re-run on "rescan"
  └─ load ~/.alice/identity.json   // active Alice address? (sibling identity doc)

State machine:
  NoAddress  --[create or import, force mnemonic backup]-->  Ready
  Ready      --[Start]-->  Mining(primary lane)            // one supervisor (§7)
  Mining     --[Stop]-->   Ready
```

- **Address gate.** If `identity.json` has a valid format-300 address → straight to Ready. If not,
  the create/import sheet appears first (reuses wallet crypto; force mnemonic backup on create).
  Mining needs only the **public address**; the key is never unlocked while mining
  (`miner.rs:354` — "the wallet seed/private key is NEVER passed").
- **The single button.** `Start` calls `detect_capability()`, takes `recommended_lane`, builds the
  launch plan for that lane (§4.1), and starts **one** supervisor. That is the entire one-click
  path. Dual-mine and lane choice live behind a disclosure (§5, §6), never on the critical path.
- **Worker id on the wire.** Reuse `miner.rs::derive_worker_id(address)` **verbatim** for the
  stratum `--rig-id` / `<addr>.<worker>` — it is the proven, fail-closed Alice-address validator +
  stable per-device rig id (`miner.rs:298-318`). One derivation feeds both lanes (rig ids may add a
  per-lane suffix, see §4.1).

### 4.1 Lane → launch plan

**XMR (reuse, do not redesign):** call `miner::build_miner_launch_plan(xmrig_path, address)`
verbatim (`miner.rs:355-396`): `-o hk.aliceprotocol.org:3333 -u <addr> -p x --rig-id <worker>
--coin monero --no-color --print-time 10 --donate-level 0 --cpu-priority 1 --threads <all-cores>`.

**RVN (new builder, same shape):** `build_rvn_launch_plan(miner_path, address) -> MinerLaunchPlan`:
```
-a kawpow
-o stratum+tcp://hk.aliceprotocol.org:8888
-u <addr>.<worker_id>           // open-enrollment: user's OWN Alice addr (mine.html:200)
-p x
--no-color                       // (T-Rex) or kawpowminer equivalent
```
- Host/port from a single `RelayConfig` (`hk.aliceprotocol.org`, RVN port **8888** →core4444 per
  MEMORY edge-node + `mine.html:200`). The **upstream RVN pool + our collection address are
  server-side on the relay** — the client never sends them (same contract as XMR; brief HARD
  CONSTRAINT). The Alice collection RVN address that appears in `real_pool_config.py` is for the
  **direct/legacy** path and must **not** be put in the client's `-u`.
- Reuse `validate_alice_address` + `derive_worker_id` for `-u`. Reject non-Alice addresses
  fail-closed (relay NACKs `stratum_login_open_bad_address` — `miner.rs:362-369`).
- **Per-lane worker suffix** for dual-mine so the two children are distinguishable to the relay
  without colliding: `--rig-id <worker_id>` for XMR and `-u <addr>.<worker_id>-gpu` for RVN
  (suffix stays inside the stratum-safe `[A-Za-z0-9_.-]` charset). Keep ≤64 chars (re-run the
  `derive_worker_id` tail-tag rule if a suffix overflows).

### 4.2 Windows XMR (brief HARD CONSTRAINT)

Do **not** bundle xmrig on Windows (Defender PUA). On Windows the one-click flow:
- If `device_class == Gpu` (NVIDIA): default to **RVN only** (no CPU lane offered) — Windows is
  effectively GPU-first.
- If CPU-only Windows: XMR via **on-demand download** of xmrig (sha256-gated, same staging policy
  as the GPU miner — `public-beta-supported-binaries.example.json`), surfaced as
  "Download CPU miner (~XMB)" before the first Start. Never silent.

---

## 5. Auto / profit-switch policy (credit-only)

### 5.1 What "profit" means here

Credit-only: every lane credits the **same ALICE** to the same address and per-unit rates are
**unpublished (0)** (`mine.html:210`). So a live $/coin profit switch is meaningless. "Profit" =
**expected ALICE credit per hour**, and since the rate is uniform, that collapses to **expected
accepted-share throughput on the viable lanes** — a *static* ranking, not a market optimizer.

### 5.2 The ranking (simple + deterministic + overridable)

```rust
pub fn rank_lanes(cap: &CapabilityProfile) -> Vec<Lane>; // best first
```
Rules (in order):
1. Honor any `ALICE_MINER_LANES` override / forced set first (§2.3).
2. Among viable lanes, prefer the lane that matches `device_class`:
   - `Gpu`  → **RVN** first (GPU does its strongest work), XMR second.
   - `Cpu`/`Mac` → **XMR** first (only CPU lane).
3. AI lane (if the ai-earn dimension marks it viable) ranks as an *idle-GPU* lane: below RVN on a
   GPU box (KawPoW is the GPU's primary credit substrate), and the ai-earn scheduler decides when
   to borrow idle GPU — out of scope here, but the ranking leaves a defined slot for it.

`recommended_lane = rank_lanes(cap).first()`. This is intentionally boring: no live polling, no
benchmarking on first run (which would delay the one-click Start). If/when ALICE rates publish,
this is the single function to upgrade to a real expected-credit comparison — the call sites don't
change.

### 5.3 Auto-switch at runtime (minimal)

The only runtime "switch" in credit-only mode is **failover**, not profit-chasing:
- If the primary lane's supervisor exits unexpectedly **and** a second viable lane exists, the
  orchestrator may fall back to it (opt-in setting `auto_failover`, default **on** for one-click,
  surfaced in the dashboard). This reuses the supervisor's exit signal (`miner_supervisor.rs`
  supervision loop) — no new mechanism.
- No periodic re-ranking, no "every N minutes try the other lane". Keeps heat/behavior predictable.
- A future rate-aware switch would live in a `SwitchPolicy` with a hysteresis window; stubbed but
  not built (credit-only).

### 5.4 User override (how the user beats the auto choice)

Three layers, increasing power, all credit-only:
1. **UI (primary).** The device picker (mine.html cards) lets the user click CPU/GPU/Mac and the
   "★ Best lane for this device" hint moves accordingly; choosing a card sets the lane manually and
   pins it (overrides `recommended_lane`). A "Use recommended" reset restores auto.
2. **Dual-mine toggle.** A single switch "Mine on CPU **and** GPU together" — when on, the
   orchestrator starts **both** viable lanes (§7). Default **off** (D6).
3. **Env (`ALICE_MINER_LANES` / `_FORCE`).** Power/headless override (§2.3); also drives CLI mode.

UI choice and env override compose: env restricts the menu of what the UI can pick; the UI picks
within it. Forced env wins outright.

---

## 6. ASIC (info-only)

We **cannot** drive an ASIC from the desktop client (it has its own firmware + miner). The ASIC
card therefore shows **connection info only** (mirrors `mine.html:194-202` "Manual / ASIC setup"):

```rust
pub struct AsicConnectionInfo {
    pub lane_label: &'static str,   // "LTC · Scrypt"
    pub pool: String,               // "hk.aliceprotocol.org:5555"  (LTC port, MEMORY)
    pub worker_template: String,    // "<your-alice-address>.rig1"
    pub password_hint: &'static str // "anything (e.g. x)"
}
pub fn asic_connection_info(address: &str) -> Result<AsicConnectionInfo, String>;
```
- Validates the address with the same `validate_alice_address`, then renders a **copy-paste card**
  (host, port, `worker = <addr>.rig1`, password) for the user to type into their miner's web UI.
- No supervisor, no binary, no detection — purely informational. A "Copy" button per field and a
  short "where do I paste this?" note. (LTC/Scrypt :5555 per MEMORY edge-node.)

---

## 7. Dual-mine orchestration

### 7.1 Two supervisors, one orchestrator

Reuse `MinerSupervisor` (single child) **unchanged**; run **two** instances:

```rust
// alice-miner/src/orchestrator.rs
pub struct MiningOrchestrator {
    xmr: MinerSupervisor,   // CPU lane
    rvn: MinerSupervisor,   // GPU lane
    mode: RunMode,          // Single(Lane) | Dual
}
pub enum RunMode { Single(Lane), Dual }

impl MiningOrchestrator {
    pub fn start(&self, cap: &CapabilityProfile, address: &str, mode: RunMode) -> Result<(), String>;
    pub fn stop_all(&self);
    pub fn snapshot(&self) -> OrchestratorSnapshot;  // merges both MinerStats
}
```
- `Single(lane)` → start only that supervisor with that lane's plan.
- `Dual` → start XMR with `build_miner_launch_plan` **and** RVN with `build_rvn_launch_plan`, each
  in its own supervisor. Both must be viable (else fall back to `Single` of whichever is viable,
  with a note).
- Stop tears down both via each supervisor's `request_stop()` (graceful SIGTERM→SIGKILL, 5 s grace
  — `miner_supervisor.rs`).

### 7.2 Resource sanity for dual-mine

- **Thread split.** XMRig at full cores while a GPU miner also runs can starve the GPU feeder /
  spike the box. In `Dual` mode, cap XMR threads at `max(1, logical_cores - 2)` (leave headroom for
  the GPU miner's host threads + UI). Single-mode XMR stays "拉满" (all cores, `miner.rs:329-341`).
  Implement as an optional `threads_override: Option<usize>` arg on the XMR plan builder so the
  proven full-power path is untouched in single mode.
- **GPU contention.** Only one GPU lane (RVN) runs at a time; AI-idle-GPU (other dimension) must
  coordinate via the same orchestrator to avoid double-claiming the GPU.
- **Laptop guard.** Default dual-mine **off**; show a one-line "this runs CPU+GPU hard; expect heat
  and fan" confirmation before first dual start.

### 7.3 Reused log parsing

- XMR: reuse the supervisor's `parse_hashrate_hs` + `parse_share_counts` (10s→60s fallback;
  `(A/R)` pair) verbatim — `miner_supervisor.rs:268-314`.
- RVN: add a `parse_kawpow_*` set modeled on T-Rex's regexes (hashrate `… MH/s`, shares `N/M`,
  reject `R: x%`) from `/Users/v/Alice/Alice-Protocol/miner/mining_internal/trex_logs.py`. If
  KawPowMiner is chosen instead, compare a sample log first (its format differs) — flagged in
  `rvn-kawpow-miner-selection.md` preconditions.

---

## 8. Test plan (mirrors the Python's fixture discipline)

- **Detection unit tests** inject fixture `HardwareProfile`s (no shell-out): NVIDIA+Linux,
  NVIDIA+Windows(no WSL2), Apple Silicon, AMD-only, Intel-iGPU, CPU-only, all-probes-failed →
  assert `device_class`, `viable_lanes`, `recommended_lane`, and the exact `reasons` strings.
- **Override tests**: `ALICE_MINER_LANES` restrict vs intersection vs `_FORCE`, unknown token →
  error (port the Python's override tests).
- **Launch-plan tests**: RVN plan targets `hk.aliceprotocol.org:8888`, `-u` = address, `-a kawpow`,
  no collection address / no seed in argv (mirror `miner.rs` test
  `miner_launch_plan_targets_relay_with_xmr_login_convention`).
- **Orchestrator tests**: `Dual` with one non-viable lane degrades to `Single`; `stop_all` stops
  both; dual XMR threads = `cores-2`.
- **Fail-safe**: a panicking/failing runner yields `HardwareProfile::fallback()` (XMR-only),
  never a panic.

---

## 9. Open questions for V

1. **RVN relay port = 8888?** MEMORY edge-node + `mine.html:200` say RVN :8888 → core 4444. The
   ACP proxy survey lists a generic RVN default of :4444. Confirm the **client-facing** port the
   friend's relay exposes for KawPoW (8888 vs 4444) — this is the one literal the RVN plan needs.
2. **GPU miner choice for v1: T-Rex (wired now, 1% fee, NVIDIA-only, closed) or KawPowMiner
   (open, 0%, needs log-format check)?** Affects the RVN log parser and the on-demand download
   manifest. Brief leans open-source; selection doc calls T-Rex the current integration.
3. **Dual-mine default** — confirm OFF (D6) and the CPU-thread headroom of `cores-2` in dual mode
   (vs your "拉满" instinct). One-click stays single-lane regardless.
4. **AMD/Intel GPU** — for v1, label-only "coming soon" (no RVN), or expose the `_FORCE` escape
   hatch in the UI? Default plan: env-only force, not a UI button.

---

Doc written to: `/Users/v/Alice/alice-miner/docs/design/02-device-lane.md`
