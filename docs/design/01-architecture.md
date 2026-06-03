# Alice Miner — Architecture & Core Engine Design

> **Doc 01 of the alice-miner design set.** Scope: GUI stack decision, core
> engine pipeline, repo layout, crate sharing with the Wallet, the `~/.alice/`
> shared-identity contract, and the async/process-supervision model.
>
> **Status:** design only. This document does NOT modify any product source.
> All "reuse" callouts cite the existing Wallet (`/Users/v/Alice/alice-wallet`)
> by file:line so a later build pass can lift code verbatim or factor it into a
> shared crate.
>
> **Hard constraints honoured throughout** (from the project brief & MEMORY):
> credit-only (no payout/claim/emission; `paid_acu` stays 0); the proven XMR
> stratum path is reused verbatim (login = user's Alice address, pass `x`,
> `--rig-id <worker-id>`, relay `hk.aliceprotocol.org:3333`; OUR collection
> address + upstream pool are server-side on the relay and the client NEVER
> sends them); Windows does NOT bundle xmrig; targets are macOS-arm64,
> linux-x86_64, windows-x86_64; the Wallet's ed25519 signed-update pipeline and
> crypto/keystore are reused, not rebuilt.

---

## 0. TL;DR of decisions

| # | Decision | Verdict |
|---|----------|---------|
| D1 | **GUI stack** | **egui/eframe 0.34** (same as Wallet) — NOT Tauri. |
| D2 | **Crate layout** | Cargo workspace: `alice-crypto` (shared lib, extracted from Wallet), `alice-miner-core` (engine lib), `alice-miner-gui` (eframe bin), `alice-miner-cli` (headless bin). |
| D3 | **GUI/CLI sharing** | Both bins depend on `alice-miner-core`; the engine is UI-agnostic, exposes an `EngineHandle` + snapshot stream. GUI renders snapshots; CLI prints them. |
| D4 | **Crypto reuse** | Factor Wallet `crypto.rs` into `alice-crypto`; both Wallet and Miner consume the same crate → same keystore file format, byte-for-byte. |
| D5 | **Shared identity** | `~/.alice/identity.json` (public active address) + `~/.alice/keystore.json` (encrypted, Wallet's v4 format). One mnemonic across all 3 apps; advisory file-lock on writes. |
| D6 | **Runtime model** | One worker `std::thread` owning an `Arc<tokio::Runtime>`; mpsc `Command`/`Event` channels; `ctx.request_repaint()` wakes the GUI. Lifted from Wallet `app.rs:1580` + `app.rs:312`. |
| D7 | **Supervision** | Reuse Wallet `supervise::child` (owned `Child`, SIGTERM→SIGKILL, own pgid, `kill_on_drop`) verbatim. Generalise `miner_supervisor` into a per-process `LaneSupervisor` so dual-mine = N supervisors. |

Open questions for V are in **§9**.

---

## 1. GUI stack decision: egui/eframe (NOT Tauri)

### 1.1 The choice

Build the GUI on **egui 0.34 / eframe 0.34**, exactly the stack the Wallet
already ships (`/Users/v/Alice/alice-wallet/gui/Cargo.toml`: `eframe = "0.34.1"`,
`egui_extras = "0.34.1"`). The headless CLI is a second binary over the same
core; it pulls in zero GUI deps.

### 1.2 Why egui over Tauri — specifically for a beautiful, animated, 3-OS GUI + CLI

This is the one decision the brief asks me to actively make and justify, so I
weigh it against the real alternative rather than defaulting.

**Reasons egui wins here:**

1. **The whole engine is Rust + a tokio process supervisor.** The Miner's job
   is to spawn/own/parse native miner binaries (xmrig, T-Rex/kawpowminer) and
   sign with sr25519. That is exactly what the Wallet already does in Rust
   (`supervise/child.rs`, `supervise/miner_supervisor.rs`, `crypto.rs`). With
   egui the UI is *in the same process and language* as that engine — the
   `MinerStats` snapshot (`miner_supervisor.rs:39`) is a plain Rust struct the
   UI reads directly. With Tauri we'd keep the identical Rust core but then add
   a JS/TS frontend and **marshal every stat across an IPC/serde boundary** —
   net new surface, net new bugs, for a dashboard that is fundamentally a few
   numbers + a sparkline.

2. **Maximum code reuse = faster path to "done + polished."** We lift, with
   near-zero change: the worker-thread/runtime bridge (`app.rs:312`,
   `app.rs:1580`), the supervisor (`miner_supervisor.rs`), the crypto
   (`crypto.rs`), the ed25519 signed-update pipeline (`update.rs`), the custom
   dark title-bar window (`main.rs:52`), and the existing **mining UI page**
   (`gui/src/ui/mining.rs`, 12.6 KB — already a styled hashrate/shares panel).
   A Tauri rewrite throws away the UI layer and the window/theme plumbing.

3. **The Wallet already proves egui can hit the "漂亮/流畅" bar.** The Wallet
   ships a polished dark theme: custom fonts (Inter + JetBrains Mono + Noto Sans
   SC) installed via `ui::theme::install_fonts` (`theme.rs:56`), a glass/orange
   brand system, and a custom fullsize-content title bar with the traffic
   lights preserved (`main.rs:52-63`). egui's **`Context::animate_value_with_time`
   / `animate_bool_with_time`** give frame-rate-independent eased transitions;
   `request_repaint_after` (already used at `app.rs:1163`, `2017`, `2269`)
   drives smooth live updates. We get fluid animation without a browser.

4. **3-OS story is a single static binary per target.** eframe builds one
   self-contained executable for macOS-arm64 / linux-x86_64 / windows-x86_64 —
   the **same three targets** the Wallet's update manifest already enumerates
   (`update.rs:190` `current_platform()`). No system WebView dependency
   (Tauri leans on WKWebView/WebView2/WebKitGTK, which adds a Linux runtime
   dependency and per-OS rendering drift). egui renders the *identical* pixels
   on all three via glow (`eframe` features `["glow","wayland","x11"]`).

5. **CLI is trivial and honest.** Because the engine is a pure Rust lib, the
   headless CLI is just a second `[[bin]]` linking `alice-miner-core` and
   printing snapshots — no Node, no webview, no duplicated logic. With Tauri the
   "core" tends to drift toward the JS side; here the core cannot drift because
   the GUI is also Rust.

**Where Tauri would have won (and why it doesn't here):** Tauri shines when you
want a web design team, CSS animation libraries, and rich HTML layout. Our UI is
a focused control surface (device card, one big Start button, live stats,
log tail) — not a content app. The animation we need (number tweening, glow
pulse, sparkline) is well within egui. The brief also forbids touching product
source and wants aggressive reuse; egui is the lower-risk path to a shippable,
*consistent-with-the-Wallet* product. **The "beautiful" bar is met by investing
in a strong egui theme/widget layer (§6), not by switching to HTML.**

> If V later wants a marketing-grade animated onboarding, that lives on the
> **website** (`alice-website/mine.html`, already the Tailwind/HTML brand
> surface) — the desktop client stays egui.

### 1.3 What we inherit by staying on egui 0.34

- `ui::theme` (fonts + style + backdrop) — `theme.rs:56,96,162`.
- `ui::widgets` (shared widget helpers) — `gui/src/ui/widgets.rs`.
- The whole `update_prompt` UX for signed auto-update — `ui/update_prompt.rs`.
- The custom OS window chrome — `main.rs:52-63`, `load_icon()` `main.rs:16`.

---

## 2. Repo layout — `alice-miner/`

A **Cargo workspace**. The shared crypto crate is created by *extracting* the
Wallet's `crypto.rs` (per the crypto survey's recommendation) so both products
read the identical keystore.

```
alice-miner/
├── Cargo.toml                      # [workspace] members = the 4 crates below
├── README.md
├── docs/
│   └── design/
│       ├── 01-architecture.md      # ← THIS doc
│       ├── 02-device-detect-and-lanes.md   (future)
│       ├── 03-ui-polish-system.md          (future)
│       └── 04-release-and-update.md        (future)
├── crates/
│   ├── alice-crypto/               # SHARED with the Wallet (see §4)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs              # re-exports: keystore, derive, sign, ss58
│   │       ├── keystore.rs         # WalletPayload + AES-256-GCM (from crypto.rs)
│   │       ├── derive.rs           # Argon2id + PBKDF2 KDF (from crypto.rs)
│   │       ├── sign.rs             # sr25519 keypair, WalletSecrets (from crypto.rs)
│   │       └── ss58.rs             # SS58 fmt-300 encode/validate (from crypto.rs)
│   │
│   ├── alice-miner-core/           # the engine library (UI-agnostic)
│   │   ├── Cargo.toml              # deps: tokio, serde, alice-crypto, supervise bits
│   │   └── src/
│   │       ├── lib.rs              # pub use: Engine, EngineHandle, Snapshot, Command, Event
│   │       ├── engine.rs           # orchestrator: state machine + command loop (§3,§5)
│   │       ├── identity/           # ~/.alice shared dir (§4)
│   │       │   ├── mod.rs
│   │       │   ├── shared_dir.rs   # path resolution + advisory lock
│   │       │   └── identity_file.rs# identity.json read/write
│   │       ├── device/             # device detection (§3 step 1)
│   │       │   ├── mod.rs
│   │       │   ├── cpu.rs          # logical cores, RandomX fitness, AES flag
│   │       │   ├── gpu.rs          # NVIDIA/AMD/Intel vendor + VRAM probe
│   │       │   ├── apple.rs        # Apple Silicon (unified mem, P/E cores)
│   │       │   └── asic.rs         # info-only (we never drive an ASIC)
│   │       ├── lane/               # lane selection + per-lane launch plans (§3 step 2)
│   │       │   ├── mod.rs          # Lane enum, LanePlan, select_lanes()
│   │       │   ├── xmr.rs          # REUSE Wallet miner.rs plan (verbatim)
│   │       │   ├── gpu_rvn.rs      # T-Rex/kawpowminer KawPoW plan
│   │       │   └── ai.rs           # idle-GPU inference lane (bridge; later)
│   │       ├── supervise/          # LIFTED from Wallet supervise/ (§7)
│   │       │   ├── mod.rs          # ProcState, sanitize_log_line, RestartPolicy, LogRing
│   │       │   ├── child.rs        # OwnedChild + spawn_supervised (verbatim)
│   │       │   └── lane_supervisor.rs # generalised miner_supervisor (one per lane)
│   │       ├── stats/
│   │       │   ├── mod.rs          # Snapshot, LaneStats, rolling hashrate ring
│   │       │   └── parse.rs        # hashrate/share parsers (xmrig + trex regexes)
│   │       ├── binaries/           # bundled-miner resolution + integrity (§3 step 3)
│   │       │   ├── mod.rs          # resolve_binary(lane, platform) -> PathBuf
│   │       │   └── manifest.rs     # sha256 gate (reuse update.rs verify_artifact_integrity)
│   │       ├── endpoint/
│   │       │   └── mod.rs          # multi-endpoint failover/obfuscation list (§3 step 2)
│   │       ├── update/             # REUSE Wallet update.rs (shared or copied) (§8)
│   │       │   └── mod.rs
│   │       └── config.rs           # MinerSettings (serde) + ~/.alice path glue
│   │
│   ├── alice-miner-gui/            # the eframe binary (the product)
│   │   ├── Cargo.toml              # deps: eframe 0.34, egui_extras, alice-miner-core
│   │   ├── assets/                 # COPY brand assets from Wallet (fonts, logo)
│   │   │   ├── brand/alice-logo.svg
│   │   │   └── fonts/{Inter,JetBrainsMono,NotoSansSC}…
│   │   └── src/
│   │       ├── main.rs             # window + runtime bring-up (mirror Wallet main.rs)
│   │       ├── app.rs              # MinerApp: holds EngineHandle, pumps Events
│   │       ├── bridge.rs           # Command/Event ↔ egui repaint plumbing (§5)
│   │       └── ui/
│   │           ├── theme.rs        # PORTED from Wallet theme.rs + miner accents
│   │           ├── widgets.rs      # ported widgets + animated stat/sparkline/gauge
│   │           ├── onboard.rs      # one-click flow: detect → address → Start
│   │           ├── dashboard.rs    # live hashrate/shares/lanes (the home screen)
│   │           ├── wallet_setup.rs # create/import minimal wallet (uses alice-crypto)
│   │           ├── lanes.rs        # per-lane cards (CPU/GPU/AI), dual-mine toggles
│   │           ├── log_view.rs     # sanitised log tail
│   │           └── update_prompt.rs# ported from Wallet
│   │
│   └── alice-miner-cli/            # headless binary
│       ├── Cargo.toml              # deps: alice-miner-core, clap (NO eframe)
│       └── src/
│           └── main.rs             # subcommands: detect | start | status | stop | identity
└── .github/workflows/             # release pipeline (mirror Wallet's)
```

**Why a workspace:** shared `target/`, one lockfile, and `alice-crypto` /
`alice-miner-core` compile once and link into both bins. The CLI never compiles
egui (it's not in its dep tree), so `cargo build -p alice-miner-cli` stays lean
for headless/server installs.

---

## 3. Core engine pipeline

The engine is the heart of the brief: **device-detect → lane-select →
spawn/supervise → collect stats → feed the dashboard.** It lives entirely in
`alice-miner-core` and is identical whether driven by GUI or CLI.

```
            ┌─────────────────────────────────────────────────────────────┐
            │                     alice-miner-core::Engine                  │
            │                                                               │
 Command ──►│  ┌──────────┐   ┌──────────┐   ┌──────────────┐   ┌────────┐ │
 (Start/    │  │ 1 device │──►│ 2 lane   │──►│ 3 spawn &     │──►│ 4 stats│ │──► Event
  Stop/     │  │  detect  │   │  select  │   │   supervise   │   │ collect│ │   (Snapshot)
  SetLane)  │  └──────────┘   └──────────┘   │  (N children) │   └────────┘ │
            │       │              │         └──────────────┘       │       │
            │       ▼              ▼                 ▲              ▼       │
            │   DeviceProfile   Vec<LanePlan>   LaneSupervisor   Snapshot   │
            └─────────────────────────────────────────────────────────────┘
                    binaries::resolve   endpoint::failover    stats::parse
```

### Step 1 — Device detect (`core/device/`)
`detect() -> DeviceProfile`. Pure, fast, no spawning.

```rust
pub struct DeviceProfile {
    pub cpu: CpuInfo,          // logical_cores, has_aes, randomx_fit: bool
    pub gpus: Vec<GpuInfo>,    // vendor: {Nvidia,Amd,Intel,Apple}, vram_mb, name
    pub apple_silicon: Option<AppleInfo>, // unified_mem_gb, p_cores, e_cores
    pub asic: Option<AsicInfo>,// info-only; never driven
    pub os: Platform,          // reuse update::current_platform() → "macos-arm64" …
}
```

- CPU cores: `std::thread::available_parallelism()` (Wallet uses exactly this at
  `miner.rs:336`), clamped `[1,256]` (`miner.rs:45`).
- GPU vendor: probe `nvidia-smi` / `rocm-smi` / sysfs (Linux), IOKit/Metal
  (macOS), WMI/`dxdiag`-class query (Windows). Vendor detection is enough to
  pick the lane; exact model is decoration.
- Apple Silicon: detected via `os = macos-arm64` + sysctl unified memory.
- ASIC: read-only — surfaced as guidance text + the manual stratum table from
  `alice-website/mine.html`. We never spawn or drive an ASIC.

### Step 2 — Lane select (`core/lane/`)
`select_lanes(&DeviceProfile, &MinerSettings) -> Vec<LanePlan>`.

```rust
pub enum Lane { XmrCpu, GpuRvn, Ai }   // (Quai/LTC/PRL exist server-side; client default RVN per MEMORY)

pub struct LanePlan {
    pub lane: Lane,
    pub program: std::path::PathBuf,    // from binaries::resolve_binary()
    pub args: Vec<String>,              // built per lane (see below)
    pub endpoints: Vec<Endpoint>,       // primary + failover/obfuscation (host:port)
    pub worker_id: String,              // derived from the Alice address
}
```

Auto-pick (the "极简一键" rule):
- **Apple Silicon / generic CPU** → `XmrCpu`.
- **Discrete NVIDIA/AMD GPU present** → `GpuRvn` (KawPoW; client GPU default is
  RVN per MEMORY's GPU-lane direction — clean Alice-validated re-hash).
- **CPU + GPU both present & dual-mine enabled** → BOTH `XmrCpu` + `GpuRvn`
  (one `LaneSupervisor` each — see §7).
- **AI lane** → opt-in / later; leases idle-GPU inference jobs (bridge to the
  AI app), credit-only via the shadow ledger. Designed, not wired in v1.
- **ASIC** → no lane; show manual config only.

**XMR lane args are reused VERBATIM** from the Wallet's proven, live-validated
builder — do NOT redesign:
- `build_miner_launch_plan()` → `/Users/v/Alice/alice-wallet/gui/src/miner.rs:355`
- Emits `-o hk.aliceprotocol.org:3333 -u <alice_addr> -p x --rig-id <worker_id>
  --coin monero --no-color --print-time 10 --donate-level 0 --cpu-priority 1
  --threads <n>` (`miner.rs:374`).
- `<alice_addr>` is the **user's own** Alice address (the reward identity);
  worker_id = `derive_worker_id(addr)` (`miner.rs:298`). The relay host/port are
  the only endpoint the client knows. **OUR collection address and the upstream
  pool live server-side on the relay — the client never sends or stores them.**
  This matches the open-enrollment, credit-only relay model in the proxy-lanes
  survey.

**GPU/RVN lane args** (`core/lane/gpu_rvn.rs`), modelled on the existing T-Rex
integration in `Alice-Protocol/miner/mining_internal/trex_runner.py`:
`-a kawpow -o stratum+tcp://<relay-rvn-endpoint> -u <alice_addr>.<worker> -p x`,
pointed at the Alice **relay** RVN port (`hk.aliceprotocol.org:8888` per MEMORY's
edge-node map; relay forwards to core:4444). Same credit-only contract: client
sends only its own Alice address; collection/upstream are server-side.

> **Endpoint failover/obfuscation** (`core/endpoint/`): each lane carries an
> ordered `Vec<Endpoint>` (the canonical `hk.aliceprotocol.org` plus any
> fallback hostnames/ports V configures). On connect-fail or sustained reject,
> the supervisor stops the child and the engine re-spawns against the next
> endpoint with backoff. **All endpoints are Alice relays** — never a direct
> pool — so the credit-only invariant holds regardless of which one is live.

### Step 3 — Spawn & supervise (`core/supervise/`)
For each `LanePlan`, the engine resolves the binary, then hands the plan to a
**`LaneSupervisor`** (one per lane → N concurrent children for dual-mine).

- **Binary resolution** (`core/binaries/`): `resolve_binary(lane, platform)`.
  - macOS/Linux: bundled, sidecar binary next to the app (xmrig for CPU;
    kawpowminer/T-Rex for GPU), verified by SHA-256 against an embedded manifest
    before exec — reuse `update::verify_artifact_integrity` (`update.rs:392`).
  - **Windows XMR: NOT bundled** (Defender/PUA false-positives per constraint).
    Windows XMR is **on-demand download** (signed manifest, sha256-gated, same
    pipeline) OR the device is treated as GPU-only. Decision flag in §9-Q1.
- Spawning uses the Wallet's `spawn_supervised()` verbatim
  (`/Users/v/Alice/alice-wallet/gui/src/supervise/child.rs:113`): piped
  stdout/stderr line pump, own process group (`setpgid`), `kill_on_drop(true)`,
  PID recorded, **never `pkill` by name**.

### Step 4 — Collect stats (`core/stats/`)
Each `LaneSupervisor` parses its child's log lines into a `LaneStats` snapshot,
reusing the Wallet's parsers:
- `parse_hashrate_hs()` — 10s→60s fallback (`miner_supervisor.rs:273`).
- `parse_share_counts()` — cumulative `(A/R)` pair (`miner_supervisor.rs:299`).
- For T-Rex/KawPoW, port the regexes from
  `Alice-Protocol/miner/mining_internal/trex_logs.py` (shares, reject %,
  hashrate units, temp/power) into `stats/parse.rs`.

The engine aggregates per-lane stats into one `Snapshot` (§5) and emits it as an
`Event`. A rolling ring of recent hashrate samples (in `stats/mod.rs`) feeds the
dashboard sparkline.

### Step 5 — Feed the dashboard
The engine emits `Event::Snapshot(Snapshot)` on every change (stat tick, state
change, log line). GUI renders it; CLI prints it. No business logic in either
front-end. **All numbers are credit/score; the engine never computes or shows
payout — `paid_acu` is structurally absent from `Snapshot`.**

---

## 4. Crypto reuse + `~/.alice/` shared-identity contract

### 4.1 `alice-crypto` shared crate

Per the crypto survey, extract the Wallet's `crypto.rs`
(`/Users/v/Alice/alice-wallet/gui/src/crypto.rs`, 737 LOC) into a standalone
`alice-crypto` crate consumed by **both** the Wallet and the Miner. This is the
only way to guarantee the keystore file is byte-for-byte compatible (same
sr25519 / BIP39 / SS58-300 / Argon2id+AES-256-GCM / v4 AAD).

Public API surface (unchanged from survey):
```rust
pub const SS58_FORMAT: u16 = 300;
pub const CURRENT_WALLET_VERSION: u32 = 4;
pub struct WalletPayload { /* version, address, encrypted_seed, salt, kdf… */ }
pub struct WalletSecrets { /* zeroizing */ }
pub fn create_wallet_payload(mnemonic: &str, password: &str) -> Result<WalletPayload, String>;
pub fn create_wallet_payload_from_seed_hex(seed_hex: &str, password: &str) -> Result<WalletPayload, String>;
pub fn unlock_wallet(payload: &WalletPayload, password: &str) -> Result<UnlockOutcome, String>;
pub fn generate_mnemonic() -> String; // for create + forced backup
```

The Miner uses: `create_wallet_payload` (create), `create_wallet_payload_from_seed_hex`
(import raw key) + a mnemonic-import path, and SS58-300 validation. **Mining
needs only the ADDRESS** — the engine reads the public address from
`identity.json` and never calls `unlock_wallet`. The private key is sealed at
create/import time and never unlocked during mining (matches the brief).

> **Migration note for the build pass:** extracting `crypto.rs` is the only
> change that touches the Wallet repo. It is a pure move-to-crate + `pub use`
> re-export so the Wallet keeps `crate::crypto::…` paths. This is explicitly a
> *future* step — this design document changes no source.

### 4.2 The `~/.alice/` directory contract

A single shared dir, used by Wallet, Miner, and the later AI app.

```
~/.alice/
├── identity.json      # PUBLIC: active address + metadata. Safe to read freely.
├── keystore.json      # ENCRYPTED: Wallet v4 WalletPayload. Secret at rest.
└── .lock              # advisory lock file for writer coordination
```

**Path resolution** (`core/identity/shared_dir.rs`):
```rust
// Override for tests/portable installs, else the real home.
pub fn alice_home() -> PathBuf {
    std::env::var("ALICE_HOME").ok().filter(|s| !s.is_empty()).map(PathBuf::from)
        .unwrap_or_else(|| dirs::home_dir().expect("home").join(".alice"))
}
```
> NOTE: the Wallet today stores its keystore under `…/AliceWallet/wallet.json`
> (`config.rs:67`), NOT under `~/.alice/`. The shared `~/.alice/` dir is the
> **new cross-app contract** introduced by this product line. Reconciling the
> Wallet onto `~/.alice/keystore.json` (or symlink/import) is **§9-Q2** for V.
> The Miner can ship `~/.alice/` first; the Wallet adopts it when convenient.

**`identity.json` schema** (public, the reward identity):
```json
{
  "version": 1,
  "active_address": "a2...",          // SS58 fmt-300, the credited address
  "label": "My Miner",
  "created_by": "alice-miner/0.1.0",  // which app first wrote it
  "keystore": "keystore.json",        // relative path to the encrypted store
  "updated_at": "2026-06-03T12:00:00Z"
}
```

**Contract rules:**
1. **Whoever creates, writes.** On first run, if `identity.json` is absent, the
   app that runs the create/import flow writes both `identity.json` and
   `keystore.json`. The others **read** them.
2. **The Miner only needs `active_address`.** It reads it from `identity.json`.
   No unlock, no key access during mining.
3. **Atomic + locked writes.** Reuse the Wallet's atomic write protocol
   (write `.tmp-<pid>`, fsync, rename — `crypto.rs:176`). Acquire an advisory
   lock on `~/.alice/.lock` (e.g. `fs2::FileExt::try_lock_exclusive`) for the
   brief write window so two apps can't race a create. Reads are lock-free.
4. **Keystore format is identical across apps** (guaranteed by `alice-crypto`),
   so a wallet created in any app unlocks in any other with the same mnemonic.
5. **Backup on overwrite.** Reuse `backup_existing_wallet` (`crypto.rs:153`)
   before any import that would replace an existing keystore.
6. **Permissions.** `keystore.json` written `0o600` on Unix (Wallet does this at
   `crypto.rs:491`); `identity.json` is public-readable (it holds no secret).

**AI-app bridge (forward-looking):** the AI app's "earn" entry detects the Miner
(installed? `identity.json` present?) and launches it — the approved bridge
approach. The Miner needs no AI-specific code for this; the AI app shells out.

---

## 5. GUI ⇄ CLI sharing — one core, two front-ends

`alice-miner-core` exposes a tiny, UI-agnostic handle. The engine runs on the
worker thread; front-ends send `Command`s and consume `Event`s.

```rust
// alice-miner-core/src/lib.rs
pub enum Command { Start, Stop, SetLane(Lane, bool), SetDualMine(bool),
                   RefreshDevice, SetAddress(String), CheckUpdate }

pub struct LaneStats { pub lane: Lane, pub state: ProcState, // from supervise::ProcState
    pub hashrate_hs: Option<f64>, pub accepted: u64, pub rejected: u64,
    pub last_line: Option<String> }

pub struct Snapshot {                 // the ONE thing the dashboard renders
    pub device: DeviceProfile,
    pub address: Option<String>,      // credited Alice address (public)
    pub lanes: Vec<LaneStats>,
    pub total_hashrate_hs: f64,
    pub recent_hashrate: Vec<f32>,    // ring for the sparkline
    pub log_tail: Vec<String>,        // sanitised (supervise::sanitize_log_line)
    // NOTE: no payout/paid_acu field — credit-only by construction.
}

pub enum Event { Snapshot(Snapshot), Toast{ ok: bool, title: String, body: String },
                 UpdateAvailable(/* from update::CheckOutcome */) }

pub struct EngineHandle { tx: Sender<Command>, rx: Receiver<Event> }
impl EngineHandle {
    pub fn spawn(rt: Arc<tokio::Runtime>, settings: MinerSettings) -> Self { /* §6 */ }
    pub fn send(&self, c: Command);
    pub fn try_recv(&self) -> Option<Event>;
}
```

- **GUI** (`alice-miner-gui/src/app.rs`): holds `EngineHandle`. Each
  `eframe::App::update` drains `try_recv()` into local render state, then draws.
  The worker calls `ctx.request_repaint()` when a new `Event` lands so the UI
  redraws immediately (exactly the Wallet pattern — `app.rs:1839`, `2015`), and
  `ctx.request_repaint_after(…ms)` keeps animations/live stats smooth
  (`app.rs:2017`).
- **CLI** (`alice-miner-cli/src/main.rs`): holds the same `EngineHandle`, loops
  on `try_recv()`, and prints. Subcommands:
  - `alice-miner detect` — print `DeviceProfile`.
  - `alice-miner identity [--create | --import <mnemonic|hex>]` — manage `~/.alice`.
  - `alice-miner start [--lane xmr|gpu|auto] [--dual]` — run; stream stats; Ctrl-C → `Command::Stop`.
  - `alice-miner status` / `stop` — for a detached/service run.

Because both front-ends speak only `Command`/`Event`, the engine is the single
source of truth and **cannot drift** between GUI and CLI.

---

## 6. Async runtime + process-supervision model

This mirrors the Wallet's proven threading model exactly (it already runs a
tokio runtime + supervised children behind an egui UI).

### 6.1 Runtime ownership
- `main.rs` creates `let rt = tokio::runtime::Runtime::new()` and wraps it in
  `Arc` (Wallet: `main.rs:50`, then `Arc<Runtime>` at `app.rs:1581`).
- `EngineHandle::spawn` launches **one** worker `std::thread` that owns the
  `Arc<Runtime>` and runs the command loop (Wallet: `spawn_worker`
  `app.rs:1580`). The egui UI thread never blocks on async or process I/O.
- Child-process I/O tasks (the stdout/stderr line pumps) are tokio tasks; the
  worker enters the runtime with `let _g = rt.enter();` before
  `supervisor.start(plan)` so those tasks have a reactor (Wallet does this at
  `app.rs:1595` / `app.rs:1618`).

### 6.2 The command loop (engine)
```
worker thread:
  loop {
    match command_rx.recv() {
      Start         => for plan in select_lanes(...) { lane_sups[plan.lane].start(plan) }
      Stop          => for s in lane_sups { s.request_stop() }
      SetDualMine(b)=> reconcile which lanes run
      ...
    }
    // a periodic ticker also pushes Event::Snapshot(...) every ~500ms
  }
```
Plus a lightweight ticker (tokio interval or a timed `recv_timeout`) that polls
each `LaneSupervisor::stats()` and emits a `Snapshot`, then
`ctx.request_repaint()` (Wallet polls stats the same way via
`AsyncAction::PollMinerStats` at `app.rs:1633`).

### 6.3 Process supervision (`core/supervise/`)
Lifted from the Wallet's `supervise/` module, which is already
miner-aware and battle-tested:

- **`child.rs` — verbatim.** `OwnedChild` + `spawn_supervised()`
  (`/Users/v/Alice/alice-wallet/gui/src/supervise/child.rs`): owned `Child`
  handle, recorded PID, own process group (`setpgid` `child.rs:142`),
  `kill_on_drop(true)` (`child.rs:125`), graceful **SIGTERM → bounded wait →
  SIGKILL** (`child.rs:55`), line-pump of stdout/stderr (`child.rs:186`). On
  Windows, `kill` maps to `TerminateProcess` (`child.rs:64`).
- **`mod.rs` — verbatim.** `ProcState`, `ProcStatus`, `sanitize_log_line`
  (ANSI strip + control-char drop + long-hex redaction — `mod.rs:116`),
  `RestartPolicy` (bounded auto-restart: 3 per 5 min, capped backoff —
  `mod.rs:195`), `LogRing` (200-line bounded tail — `mod.rs:244`).
- **`lane_supervisor.rs` — generalised from `miner_supervisor.rs`.** The
  Wallet's `MinerSupervisor` (`/Users/v/Alice/alice-wallet/gui/src/supervise/miner_supervisor.rs`)
  is already a single-XMRig supervisor with a `Clone` handle, a generation
  counter to defeat stale supervision loops (`miner_supervisor.rs` gen logic),
  a 400 ms supervision poll, a 5 s stop-grace, and the hashrate/share parsers.
  Generalise it so:
  1. it carries a `Lane` tag and an `endpoints` cursor (for failover),
  2. parsing dispatches by lane (xmrig parser vs T-Rex parser),
  3. the engine owns **N** instances (one per active lane) for dual-mine.
  Keep the Wallet's design choices: **no `pkill`**, owned-handle stop only, and
  bounded restart via `RestartPolicy`.

### 6.4 Why this model fits dual-mine + failover
- **Dual-mine** = two `LaneSupervisor`s (CPU-XMR + GPU-RVN) running concurrently
  under the same worker thread; each owns its own child and its own stats. The
  `Snapshot.lanes` vec naturally shows both.
- **Failover/obfuscation** = on a lane's child exiting with a connect/reject
  pattern, the supervisor reports `Error`; the engine advances that lane's
  endpoint cursor and re-`start`s the plan (within `RestartPolicy` budget).
- **Crash isolation** is inherited from the Wallet's design note
  (`supervise/mod.rs:8`): a miner crash surfaces an `Error` + sanitised tail and
  never touches custody/identity state.

---

## 7. Release & signed auto-update (reuse)

- Reuse the Wallet's `update.rs` end-to-end (`/Users/v/Alice/alice-wallet/gui/src/update.rs`):
  ed25519-signed `latest.json` manifest, raw-ed25519 detached-sig verify against
  an **embedded public key** (`update.rs:242`, `verify_with_embedded_key`
  `update.rs:256`), per-platform artifact selection
  (`artifact_for_current_platform` `update.rs:108`), SHA-256 integrity gate
  (`verify_artifact_integrity` `update.rs:392`), atomic swap + backup + rollback
  (`update.rs:562`/`586`), macOS ad-hoc re-codesign after swap (`update.rs:472`).
- `current_platform()` already enumerates exactly our three targets
  (`update.rs:190`): `macos-arm64`, `linux-x86_64`, `windows-x86_64`.
- The Miner ships its **own** `latest.json` (own GitHub releases URL, e.g.
  `alice-miner` repo), but the verifier/embedded-key mechanics are shared.
- **The same signed pipeline gates the on-demand miner binaries** (Windows XMR
  download, and GPU miner staging): each external binary entry carries a
  sha256/signature requirement, matching the binary-policy manifest in
  `Alice-Protocol/docs/public-beta-supported-binaries.example.json`.

> Open: factor `update.rs` into a shared `alice-update` crate vs. copy into
> `alice-miner-core::update`. Copying is lower-coupling for v1 (the embedded
> public key differs per product anyway). **§9-Q3.**

---

## 8. Beautiful-UI plan (egui), at a glance

Polish is a hard requirement, so the GUI crate carries a deliberate theme/widget
layer (detailed further in a future `03-ui-polish-system.md`):

- **Port the Wallet theme** (`theme.rs`): Inter + JetBrains Mono + Noto Sans SC
  fonts (`install_fonts` `theme.rs:56`), dark glass surfaces, brand orange
  `#F97316`, the lane accent colors from the brand survey (XMR orange, GPU blue,
  Apple cyan, AI violet).
- **Custom window chrome**: fullsize content view + hidden title + traffic
  lights, exactly as the Wallet (`main.rs:52-63`), so the Miner looks like a
  sibling of the Wallet.
- **Animated widgets** (new, in `ui/widgets.rs`): a number that tweens with
  `Context::animate_value_with_time`; a hashrate **sparkline** fed by
  `Snapshot.recent_hashrate`; a circular **hash gauge**; a pulsing live/offline
  status dot (the brand's `pulse-glow`); eased page transitions with
  `animate_bool_with_time`. `request_repaint_after` keeps it at a smooth tick.
- **The hero flow** (`ui/onboard.rs`): detect device → (create or import address,
  forced mnemonic backup on create) → **one big Start button** → dashboard. The
  Wallet's existing `ui/mining.rs` is the visual reference for the live panel.

---

## 9. Open questions for V

- **Q1 — Windows XMR:** on-demand signed download of xmrig, OR make Windows
  **GPU-only** (no CPU lane at all)? Both satisfy "don't bundle xmrig on
  Windows." Recommend: GPU-only default, with an explicit opt-in
  download for advanced users. Need V's call.
- **Q2 — `~/.alice/` adoption by the Wallet:** the Wallet currently keeps its
  keystore at `…/AliceWallet/wallet.json` (`config.rs:67`), not `~/.alice/`.
  Should the Wallet migrate/symlink onto the shared `~/.alice/keystore.json`,
  or should the Miner read the Wallet's existing path as a fallback? (Affects
  the "one mnemonic across 3 apps" UX timing.)
- **Q3 — share `update.rs` / `crypto.rs` as crates vs copy:** extracting both
  into `alice-crypto` / `alice-update` touches the Wallet repo (pure move +
  re-export). Approve the extraction, or keep the Miner on a vendored copy for
  v1 to avoid touching the Wallet now?
- **Q4 — GPU miner choice for bundling:** the gpu-miners survey recommends
  **kawpowminer** (GPL-3.0, 0% fee, auditable, cross-OS) over T-Rex
  (proprietary, 1%, NVIDIA-only) for the bundled GPU lane. Confirm kawpowminer
  as the bundled default (T-Rex stays an allowed external binary).
- **Q5 — RVN relay endpoint/port for the client:** confirm the client's GPU/RVN
  lane connects to `hk.aliceprotocol.org:8888` (per MEMORY edge-node map) with
  the same address-only, credit-only login as XMR.

---

## 10. Reuse ledger (what we lift, and from where)

| Engine concern | Reused from Wallet | Treatment |
|----------------|--------------------|-----------|
| sr25519 / BIP39 / SS58-300 / keystore | `gui/src/crypto.rs` | extract → `alice-crypto` crate (§4) |
| Child spawn/own/stop, log pump, pgid | `gui/src/supervise/child.rs` | verbatim into `core/supervise/child.rs` |
| ProcState, log sanitise, RestartPolicy, LogRing | `gui/src/supervise/mod.rs` | verbatim into `core/supervise/mod.rs` |
| Single-miner supervisor + stats parsers | `gui/src/supervise/miner_supervisor.rs` | generalise → `LaneSupervisor` (§6.3) |
| XMR stratum launch plan (proven path) | `gui/src/miner.rs:355` | verbatim into `core/lane/xmr.rs` |
| Worker-thread ⇄ UI bridge + runtime | `gui/src/app.rs:312, 1580` | pattern → `EngineHandle` + `gui/bridge.rs` |
| ed25519 signed auto-update pipeline | `gui/src/update.rs` | reuse (shared or copied) (§7) |
| Platform triple (3 targets) | `gui/src/update.rs:190` | reuse `current_platform()` |
| Theme: fonts, dark glass, brand orange | `gui/src/ui/theme.rs` | port into `gui/src/ui/theme.rs` |
| Custom window chrome (title bar) | `gui/src/main.rs:52` | mirror in `gui/src/main.rs` |
| Live mining panel visual reference | `gui/src/ui/mining.rs` | reference for `ui/dashboard.rs` |
| GPU/RVN T-Rex args + log regexes | `Alice-Protocol/miner/mining_internal/trex_*.py` | port into `core/lane/gpu_rvn.rs`, `stats/parse.rs` |

---

*End of doc 01. No product source was modified by this document.*
