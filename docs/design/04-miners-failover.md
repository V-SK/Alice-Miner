# 04 — Bundled Miners, Dual-Mine Plumbing, Failover & Obfuscation

Status: DESIGN (research only — no product source modified).
Scope owner: "Bundled miners + dual-mine plumbing + failover/obfuscation" dimension of Alice Miner.
Date: 2026-06-03.

This document specifies, concretely and buildably:

1. **Which miner binaries to bundle per-OS** (CPU-XMR via xmrig, GPU-RVN via a KawPoW miner), the bundling/no-bundling decision per OS, and the on-demand download path for Windows xmrig.
2. **Per-OS staging** that mirrors the Wallet's release-assets pattern (`gui/scripts/release.sh` + `resolve_*_binary` sibling resolution + signed `latest.json`).
3. **The supervisor** that manages 1–2 concurrent child miners and parses each one's hashrate/shares (reusing the Wallet's `MinerSupervisor` + `child.rs` design).
4. **Multi-endpoint failover** (primary relay + backups) and **obfuscation** (GFW-resistance / TLS / fallback hosts) — while keeping the client honest: it only ever sends the user's Alice address.

The non-negotiable invariant from the project brief and the proven XMR path holds throughout: **the client only ever transmits the user's OWN Alice address** as the stratum login; OUR collection address and the upstream pool are server-side on the relay. Credit-only — no payout/claim/settlement/mint. The private key is never passed to any miner child.

---

## 0. Grounding — what already exists (reuse targets)

These are the existing, proven implementations this design reuses. **Do not rebuild them.**

### 0.1 Wallet XMR launch plan (proven, do NOT redesign)
`/Users/v/Alice/alice-wallet/gui/src/miner.rs`
- `ALICE_POOL_HOST = "hk.aliceprotocol.org"`, `ALICE_POOL_PORT = 3333` (miner.rs:31,33).
- `build_miner_launch_plan(program, reward_identity)` → argv:
  `-o hk.aliceprotocol.org:3333 -u <alice_addr> -p x --rig-id <worker_id> --coin monero --no-color --print-time 10 --donate-level 0 --cpu-priority 1 --threads <N>` (miner.rs:355–396).
- `derive_worker_id(address)` — fail-closed SS58-format-300 validator + stable stratum-safe rig id (miner.rs:255–318). The login `-u` is the **user's own Alice address**; a non-Alice login is NACKed by the relay as `stratum_login_open_bad_address` (verified vs live relay 2026-06-03, miner.rs:362–369).
- `miner_thread_count()` = all logical cores, clamped `[1, 256]` (miner.rs:336–341).
- Capability gates: `MINING_EXECUTION_ALLOWED=true`, everything else (`CUSTOM_POOL_ALLOWED`, `LTC_DOGE_ALLOWED`, `AI_JOBS_ALLOWED`, `PAYOUT_RELEASE_ALLOWED`, `SETTLEMENT_ALLOWED`, `MINT_ALLOWED`) `=false` (miner.rs:18–24).

### 0.2 Supervisor + child process (reuse directly)
`/Users/v/Alice/alice-wallet/gui/src/supervise/`
- `miner_supervisor.rs` — `MinerSupervisor` owns ONE XMRig child, exposes a cloneable `MinerStats { running, state, hashrate_hs, accepted, rejected, last_exit_code, message, last_line }`. Generation counter prevents stale supervision loops clobbering newer state. **No auto-restart** in the miner variant (a miner that exits should stop, not restart-loop the user's CPU). `parse_hashrate_hs` (10s→60s fallback) + `parse_share_counts` (`(A/R)` pair). Stop = `request_stop()` → supervision loop polls every 400ms → `OwnedChild::stop(STOP_GRACE=5s)`.
- `child.rs` — `spawn_supervised(program, args, envs, pid_file, log_tx) -> OwnedChild`. Generic over program+args; pipes stdout+stderr line-by-line into an unbounded channel; `kill_on_drop(true)`; Unix `setpgid(0,0)` (own process group); SIGTERM→bounded-wait→SIGKILL. **Already generic enough to spawn ANY miner binary** — not XMRig-specific.
- `mod.rs` — `ProcState`, `sanitize_log_line()` (strips ANSI, drops control chars, redacts ≥48-char hex blobs, bounds to 400 chars), `RestartPolicy` (bounded backoff — available if we want a *bounded* GPU restart), `LogRing` (200-line ring).

### 0.3 Release / staging pattern (reuse + extend)
`/Users/v/Alice/alice-wallet/gui/scripts/release.sh`
- Per-OS package: macOS `.app` → `ditto -c -k` zip (ad-hoc signed inner-first, NO `--deep`); Linux dir → `tar -czf`; Windows dir → zip.
- **Sibling-binary bundling**: `resolve_xmrig_bin_for <triple> <want_exe>` and `resolve_node_bin_for` look first at committed `release-assets/<triple>/<name>`, then env override `ALICE_XMRIG_BIN[_<triple>]`. Optional — "when absent the artifact still ships" (release.sh:90–109, 220–229, 273–304). macOS arm64 xmrig is committed; **Linux/Windows xmrig are explicit TODOs**.
- Signed `latest.json` manifest (`gui/src/update.rs`): `{schema, product, version, min_supported, released, notes, artifacts:[{platform,url,sha256,size}]}`, raw-ed25519-signed with the OFFLINE release key; verified against the embedded `RELEASE_PUBKEY_B64` BEFORE any field is trusted. `product` string gates the manifest (`PRODUCT="alice-wallet"`; update.rs:1299 confirms `alice-miner` is already reserved as a distinct product).
- `resolve_miner_binary()` (node.rs:66–106) — sibling-of-exe resolution with `ALICE_WALLET_MINER_BIN` override + debug dev-fallback to `release-assets/aarch64-apple-darwin/xmrig`. **This is the exact pattern the Miner reuses, renamed.**

### 0.4 GPU miner integration (reference implementation)
`/Users/v/Alice/Alice-Protocol/miner/mining_internal/`
- `trex_runner.py` — `kawpow` argv: `-a kawpow -o stratum+tcp://<endpoint> -u <addr>.<worker> -p <pass>`.
- `trex_logs.py` — KawPoW log parser (shares `N/M`, reject rate `R:..%`, hashrate single/range with `KH/s|MH/s|GH/s` unit, GPU `[T:..C, P:..W, E:..H/W]`).
- `rvn-kawpow-miner-selection.md` — T-Rex selected as the integrated RVN runner (1% fee, NVIDIA, proprietary); **KawPowMiner = "best open-source audit candidate"** (GPL-3.0, 0% fee, NVIDIA+AMD, Windows/Linux/macOS, checksum artifacts).
- `public-beta-supported-binaries.example.json` — policy is `operator_supplied_external_binaries_only`; `forbidden` includes `embedded_miner_binary` and `client_auto_download`. **This policy is Alice-Protocol's CLI harness, NOT the consumer Miner** — the consumer Miner's whole point is "极简一键 / one-click", which requires bundling. See §1.6 for how we reconcile.

### 0.5 Edge / relay topology + GFW facts (reuse for failover/obfuscation)
`alice-edge-node` memory + `gfw-core-protection-research.md`:
- `hk.aliceprotocol.org` → friend's relay `203.0.113.20` (HK, nginx `stream{}`) → Finland core `203.0.113.10`.
- Port map (external → core): **LTC 5555→5555 · XMR 3333→3333 · RVN 8888→4444 (the "4"=死 taboo remap) · Quai 7777→7777.**
- Core is locked down (P0 done): stratum ports accept ONLY from the relay `203.0.113.20` + tailnet. Direct `203.0.113.10` is reachable externally and is the friend's proven fallback path.
- GFW: (1) FET dynamic block — **plaintext stratum JSON is EXEMPT**; (2) IP-level null-route — semi-permanent, killed the two raw HK boxes. Durable stealth = **VLESS+Reality+Vision (Xray)**; "C1 client baked-in Xray" is plan item P3/#30. Domain-fronting is dead; Cloudflare free can't proxy raw stratum.

---

## 1. Which miner binaries to bundle, per-OS

### 1.1 The two lanes the Miner runs
| Lane | Algo | Binary | Relay endpoint (host:port) | Backend |
|---|---|---|---|---|
| CPU-XMR | RandomX | **xmrig** | `hk.aliceprotocol.org:3333` | CPU |
| GPU-RVN | KawPoW | **kawpowminer** (primary bundle) / xmrig (CPU-KawPoW fallback only) | `hk.aliceprotocol.org:8888` | GPU (NVIDIA + AMD) |

Lane direction is per the memory: **client GPU lane = RVN** (clean Alice-validated re-hash, friend-recommended), NOT PRL. PRL is excluded from the official client GPU default (memory: "PRL NOT the GPU default/core"). The Miner therefore bundles/stages **two** miner kinds: xmrig (CPU) + a KawPoW GPU miner.

### 1.2 GPU miner choice: KawPowMiner (bundle) over T-Rex (operator-only)
**Decision: bundle KawPowMiner as the GPU lane miner; keep T-Rex as an optional operator-supplied alternative (env override).**

Rationale (from `rvn-kawpow-miner-selection.md` + the Windows-AV constraint):
- **License**: KawPowMiner is GPL-3.0 → we may *redistribute* it inside our installer (T-Rex is proprietary + a 1% dev fee that the smoke test showed fires even with donation set to zero → not redistributable/clean for a one-click consumer product).
- **0% fee** → no value leaks from the user; consistent with "earn ALICE credit, the work coin $/GPU≈0 is fine".
- **Cross-OS + cross-vendor**: NVIDIA (CUDA) + AMD (OpenCL); Windows + Linux builds published; macOS buildable. T-Rex is NVIDIA-only Windows/Linux.
- **Auditable + checksummed**: GPL-3.0 source + release checksum artifacts → we can pin a SHA-256 and (eventually) build from source for full provenance.
- **AV posture**: an open, source-verifiable binary is the least-bad option for Windows Defender/SmartScreen (still flagged as a PUA — see §1.4); a closed miner with a dev-fee is worse.

T-Rex stays reachable via `ALICE_MINER_GPU_BIN` override for power users who want its (often higher) NVIDIA hashrate, but it is never shipped in our artifact.

> **Open question for V (Q1):** Confirm bundling **KawPowMiner (GPL-3.0)** as the shipped GPU miner. The 0%-fee + redistributable-license combo is decisive for a one-click product, but T-Rex is faster on NVIDIA. Alternative: ship neither GPU binary and make the GPU lane an on-demand download (like Windows xmrig, §1.3) — slower first-run but zero GPU-miner AV surface in the base installer.

### 1.3 CPU-XMR: bundle on macOS + Linux, ON-DEMAND DOWNLOAD on Windows
Per the hard constraint ("Windows must NOT bundle xmrig — Defender/PUA false-positives"):

| OS | xmrig (CPU-XMR) | kawpowminer (GPU-RVN) |
|---|---|---|
| **macOS-arm64** | **Bundled** (committed `release-assets/aarch64-apple-darwin/xmrig`, ad-hoc signed in-bundle) | Bundled if a macOS build is staged; else on-demand. Apple Silicon GPU mining of KawPoW is weak → CPU-XMR is the macOS default lane anyway. |
| **linux-x86_64** | **Bundled** (`release-assets/x86_64-unknown-linux-gnu/xmrig`) | **Bundled** (`release-assets/x86_64-unknown-linux-gnu/kawpowminer`) |
| **windows-x86_64** | **NOT bundled** → on-demand download (§5), OR Windows is GPU-only | **NOT bundled** → on-demand download (§5). KawPoW GPU is also AV-flagged on Windows. |

So on Windows the base installer ships **no miner binary**; the Miner downloads the chosen miner on first Start (signed manifest + SHA-256, §5). This keeps the base `.exe` clean for SmartScreen reputation. (Wallet `release.sh` already documents Windows xmrig as a TODO — we formalize it as "download, don't bundle".)

> **Open question for V (Q2):** For Windows, pick the default: **(a)** on-demand download of xmrig+kawpowminer on first Start (keeps both lanes, adds a one-time download + an AV-unblock step the UI guides through), or **(b)** Windows is **GPU-only** (kawpowminer on-demand, no XMR lane on Windows at all — simplest AV story). Recommendation: (a), because CPU-XMR is the broadest "any device" lane and the on-demand flow is the same machinery either way.

### 1.4 Windows AV mitigations (carry over the Wallet's Gatekeeper playbook)
The Wallet has no code-signing certs; the trust anchor is the ed25519 release key (update.rs). Same here. For the on-demand Windows miner downloads:
- Download only from the **signed `miners.json` manifest** (§5) and verify SHA-256 before the binary is ever written executable.
- Stage downloaded miners under the Miner's **data dir** (NOT the app dir — mirrors `assert_not_in_data_dir`), then run from there.
- UI guides the user through the SmartScreen/Defender unblock exactly like the Wallet's `INSTALL.md` Gatekeeper steps (`xattr -dr com.apple.quarantine` on macOS; "Unblock" + folder exclusion on Windows). The Miner surfaces a clear "Windows Defender may flag the mining engine — here's why and how to allow it" panel.
- Never run a miner as a hidden service / background process without the user starting it (foreground, opt-in only — matches the Wallet's "nothing mines until Start").

### 1.5 Binary naming + resolution (reuse `resolve_miner_binary` pattern verbatim)
New crate module `alice-miner/src/miners/binaries.rs`:
```rust
// CPU-XMR (RandomX)
#[cfg(windows)]      pub const XMRIG_BIN: &str = "xmrig.exe";
#[cfg(not(windows))] pub const XMRIG_BIN: &str = "xmrig";

// GPU-RVN (KawPoW)
#[cfg(windows)]      pub const KAWPOW_BIN: &str = "kawpowminer.exe";
#[cfg(not(windows))] pub const KAWPOW_BIN: &str = "kawpowminer";

pub enum MinerKind { CpuXmr, GpuRvn }

/// Resolve a bundled/staged miner binary. Order:
///  1. env override  ALICE_MINER_CPU_BIN / ALICE_MINER_GPU_BIN (advanced/tests)
///  2. sibling of the Miner exe (bundled: macOS .app/Contents/MacOS, linux dir, windows dir)
///  3. on-demand staged copy under  <data_dir>/miners/<kind>/<bin>   (Windows path; §5)
///  4. (debug only) committed dev asset under release-assets/<triple>/<bin>
/// Returns Ok(path) only when the file exists + is executable.
pub fn resolve_miner_binary(kind: MinerKind) -> Result<PathBuf, MinerError>;
```
This is a near-verbatim copy of `gui/src/node.rs::resolve_miner_binary`, generalized over `MinerKind` and with the extra step (3) for the Windows on-demand case.

### 1.6 Reconciling with the "operator_supplied_external_binaries_only" policy
That policy (`public-beta-supported-binaries.example.json`, `forbidden: [embedded_miner_binary, client_auto_download]`) governs the **Alice-Protocol server-side test harness**, where embedding a miner would entangle Alice with miner provenance/liability during the internal-test phase. The **consumer Miner** is a different product with a different mandate ("一键", reuse the Wallet's release pipeline which ALREADY bundles xmrig for macOS). We therefore:
- Treat the consumer Miner's bundled/downloaded miners as **first-class release assets** with the same SHA-256 + signed-manifest discipline the Wallet uses for the node binary and chain spec.
- Keep a per-Miner `supported-miners.json` (shipped in-app, §5) recording kind/version/SHA for each lane — the consumer analogue of the harness manifest, satisfying the same "hash_required / signature_or_checksum_required" intent.

> **Open question for V (Q3):** Confirm the consumer Miner is allowed to **bundle/auto-download** miner binaries (overriding the harness's `embedded_miner_binary`/`client_auto_download` prohibition for THIS product). The brief and the Wallet's existing xmrig bundling imply yes; flagging because the harness manifest says the opposite for the test tooling.

---

## 2. Per-OS staging (mirror the Wallet's release pipeline)

The Miner gets its OWN `alice-miner/scripts/release.sh`, cloned from the Wallet's and extended for two miner kinds + the on-demand Windows split. It reuses the Wallet's `update.rs` machinery (the Miner crate depends on a shared `alice-release` crate factored out of `gui/src/update.rs`, or vendors it — see §2.4).

### 2.1 Committed release-assets layout
```
alice-miner/release-assets/
  aarch64-apple-darwin/
    xmrig                 # macOS arm64 CPU miner (committed; ad-hoc signed at package time)
    kawpowminer           # macOS arm64 GPU miner (if a mac build is staged)
  x86_64-unknown-linux-gnu/
    xmrig
    kawpowminer
  # NOTE: NO windows-x86_64 miner binaries committed — Windows downloads on demand (§5).
  miners.json             # signed on-demand-miner manifest (Windows + any lane not bundled)
```
Each committed binary's SHA-256 is pinned in `alice-miner/src/miners/pinned.rs` (the same fail-closed discipline as `node.rs::ALICE_MAINNET_SPEC_SHA256`), and `release.sh` refuses to bundle a binary whose hash ≠ the pin (copy of `stage_chain_spec`'s SHA gate).

### 2.2 Per-OS packaging (same shape as `release.sh`)
- **macOS-arm64**: build GUI → `AliceMiner.app/Contents/MacOS/`; copy `xmrig` (+ `kawpowminer` if staged) beside the exe; copy the icon + `Info.plist` (`CFBundleIdentifier org.aliceprotocol.miner`); `scripts/adhoc_sign_macos.sh AliceMiner.app` (sign inner Mach-O first — including each bundled miner — then the bundle); `ditto -c -k --keepParent` → `AliceMiner-macos-arm64.zip`.
- **linux-x86_64**: `AliceMiner/` dir with `AliceMiner` + `xmrig` + `kawpowminer` siblings; `tar -czf AliceMiner-linux-x86_64.tar.gz`.
- **windows-x86_64**: `AliceMiner\` dir with **only** `AliceMiner.exe` (no miner binaries); zip → `AliceMiner-windows-x86_64.zip`.

Artifact filenames + platform keys reuse the Wallet's `target_triple` / `artifact_name` maps verbatim (`macos-arm64`, `linux-x86_64`, `windows-x86_64`).

### 2.3 Signed `latest.json` (Miner product) + the separate signed `miners.json`
Two signed manifests, both raw-ed25519-signed with the OFFLINE release key, both verified against the embedded `RELEASE_PUBKEY_B64`:
1. **`latest.json`** — the Miner app auto-update manifest. Identical schema to the Wallet's; `product:"alice-miner"`. Drives in-app self-update (reuse `update.rs` end-to-end: fetch → verify sig → no-downgrade → prompt → download → SHA-256 → ad-hoc sign → atomic swap → health gate → rollback).
2. **`miners.json`** — the on-demand miner manifest (Windows + any unbundled lane), schema below (§5.1). Same signing key, separate file so a miner-binary refresh doesn't force an app version bump.

`release.sh` generates BOTH, prints the offline signing commands (never signs in CI — `CI` env guard copied from the Wallet), and `gh release create`s the app artifacts + `latest.json[.sig]` + `miners.json[.sig]` + `SHA256SUMS[.sig]`.

### 2.4 Shared release crate
Factor `gui/src/update.rs` into a workspace crate `alice-release` (manifest types, signature verify, version compare, download+verify, atomic swap, health gate). Both `alice-wallet/gui` and `alice-miner` depend on it. The embedded `RELEASE_PUBKEY_B64` is the SAME key for both products (one offline release key signs both `latest.json`s + the `miners.json`). The `PRODUCT` const is per-binary (`"alice-wallet"` vs `"alice-miner"`), so a wallet build refuses a miner manifest and vice-versa (the cross-product guard is already tested at update.rs:1296–1307).

> **Open question for V (Q4):** Use **one** offline ed25519 release key for both Wallet and Miner (simplest — one signing ceremony, one trust anchor; product-string isolation prevents cross-application), or a **separate** key per product (blast-radius isolation if one is ever compromised, at the cost of a second offline key + ceremony)? Recommendation: one key, product-string-isolated.

---

## 3. The supervisor — 1–2 concurrent child miners

The Wallet's `MinerSupervisor` owns exactly one child. The Miner needs to run **CPU-XMR and GPU-RVN simultaneously** (dual-mine). Design: a thin `DualMineSupervisor` that owns **two independent single-miner supervisors** plus per-lane log parsing. We reuse `child.rs::spawn_supervised` unchanged and reuse the single-lane supervision state machine (generation counter, stop, no-restart) per lane.

### 3.1 Module layout (`alice-miner/src/miners/`)
```
miners/
  mod.rs              # public surface: DualMineSupervisor, LaneId, MinerSnapshot
  binaries.rs         # §1.5 resolve_miner_binary(kind)
  pinned.rs           # §2.1 SHA-256 pins for committed binaries
  lane_supervisor.rs  # ONE child + parse; generalization of gui miner_supervisor.rs
  parse_xmr.rs        # reuse parse_hashrate_hs + parse_share_counts (from gui)
  parse_kawpow.rs     # port of trex_logs.py regexes, generalized for kawpowminer
  plan_xmr.rs         # reuse build_miner_launch_plan (XMR) + endpoint injection (§4)
  plan_kawpow.rs      # KawPoW argv builder (§3.4) + endpoint injection (§4)
  download.rs         # §5 on-demand miner fetch/verify/stage (Windows)
```
Reuse note: `lane_supervisor.rs` is `gui/src/supervise/miner_supervisor.rs` with (a) the launch plan abstracted behind a `LaneLaunch` trait so it isn't XMR-specific, and (b) a pluggable `LineParser` so KawPoW vs XMR parsing is per-lane. `child.rs` and `mod.rs` (`ProcState`, `sanitize_log_line`, `LogRing`) are reused **verbatim** via the shared `alice-supervise` crate (factor them out alongside `alice-release`).

### 3.2 `DualMineSupervisor`
```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LaneId { CpuXmr, GpuRvn }

/// Cloneable, UI-safe per-lane snapshot. Wraps the per-lane MinerStats plus the
/// lane id and the human label, so the dashboard reads one Vec<LaneSnapshot>.
#[derive(Clone, Debug)]
pub struct LaneSnapshot {
    pub lane: LaneId,
    pub label: &'static str,                 // "CPU · XMR (RandomX)" / "GPU · RVN (KawPoW)"
    pub stats: crate::supervise::MinerStats, // reused struct (hashrate_hs, accepted, rejected, state, last_line)
    pub endpoint: String,                    // active relay host:port (for the UI; §4)
}

#[derive(Clone)]
pub struct DualMineSupervisor {
    cpu: LaneSupervisor,   // owns the xmrig child  (or idle)
    gpu: LaneSupervisor,   // owns the kawpowminer child (or idle)
}

impl DualMineSupervisor {
    pub fn new() -> Self;

    /// Start the lanes the device + user settings select. `reward_identity` is the
    /// user's OWN Alice address (validated by derive_worker_id, fail-closed).
    /// `lanes` is chosen by device detection (CPU-only device => [CpuXmr]; NVIDIA/AMD
    /// GPU box => [CpuXmr, GpuRvn] or [GpuRvn] per user; Apple Silicon => [CpuXmr]).
    pub fn start(&self, reward_identity: &str, lanes: &[LaneId], net: &EndpointPlan) -> Result<(), MinerError>;

    /// Stop every running lane (graceful SIGTERM→SIGKILL via each OwnedChild).
    pub fn stop_all(&self);

    /// Stop one lane (e.g. user toggles off GPU but keeps CPU).
    pub fn stop_lane(&self, lane: LaneId);

    /// One snapshot Vec the dashboard renders each frame.
    pub fn snapshot(&self) -> Vec<LaneSnapshot>;

    /// Aggregate accepted/rejected across lanes (credit is per-share; both lanes
    /// credit the SAME Alice address on the relay, so the dashboard can show a
    /// combined "shares accepted" plus a per-lane breakdown).
    pub fn totals(&self) -> Totals;
}
```

### 3.3 Why two independent supervisors, not one multiplexed child
- **Crash isolation**: a GPU-driver crash (common) must not touch the CPU lane. Each lane is its own `OwnedChild` in its own process group (`child.rs` `setpgid`), so a SIGKILL to one never hits the other.
- **Independent log streams**: each child has its own unbounded `LogLine` channel + parse task (exactly as the Wallet does for one). No interleaving/disambiguation problem.
- **Independent lifecycle**: user can toggle GPU off while CPU keeps running; failover (§4) re-points one lane without disturbing the other.
- **Reuse**: each `LaneSupervisor` IS the Wallet's `MinerSupervisor` state machine (generation counter, `request_stop`, 400ms poll, no-restart). We change nothing in that proven core.

### 3.4 KawPoW launch plan (GPU lane) — honest, address-only
`plan_kawpow.rs::build_kawpow_launch_plan(program, reward_identity, endpoint) -> MinerLaunchPlan`:
- Validate `reward_identity` with the SAME `derive_worker_id()` fail-closed SS58-300 check (shared `alice-crypto`/address module). The login is `<alice_address>.<worker_id>` (KawPoW/stratum-v1 style; the relay's open-enrollment credits the Alice address — identical credit semantics to XMR, just the two-field bitcoin-family login from `transport_front` open-enrollment `<alice_address>.<worker_label>`).
- argv (kawpowminer; mirrors `trex_runner.py` shape but kawpowminer's flags):
  ```
  --pool stratum+tcp://hk.aliceprotocol.org:8888
  --user <alice_address>.<worker_id>
  --pass x
  --cuda            # NVIDIA
  --opencl          # AMD  (both flags safe; kawpowminer probes devices)
  --report-hashrate # ensure parseable speed lines
  ```
  > KawPoW relay port is **8888** externally (the "4"→死 remap), NOT 4444 (`alice-edge-node`). The client uses 8888 to reach the relay; the relay maps 8888→core 4444 server-side.
- **Honesty invariant (tested)**: the argv contains the user's Alice address as `--user` ONLY; it never contains OUR RVN collection address (`RWAp37…`), never a payout/override address, never the seed/key. A unit test asserts `!argv.iter().any(|a| a.contains("RWAp37") || a.contains("seed") || a.contains("priv"))` — the mirror of `miner.rs`'s `miner_launch_plan_targets_relay_with_xmr_login_convention` test.
- `--donate`/dev-fee: kawpowminer is 0% (no donate flag needed); if T-Rex is used via override, force `--no-watchdog` and accept the 1% (disclosed in UI).

### 3.5 Per-lane parsing
- **CPU-XMR**: reuse `parse_hashrate_hs` + `parse_share_counts` from `gui/src/supervise/miner_supervisor.rs` (XMRig format) verbatim (`parse_xmr.rs`).
- **GPU-RVN**: port `trex_logs.py` regexes to Rust (`parse_kawpow.rs`), generalized so they match BOTH kawpowminer and T-Rex output:
  - shares: `\b(\d+)\s*/\s*(\d+)\b` (accepted/submitted; reject = submitted − accepted, clamped ≥0).
  - reject rate: `\bR\s*:\s*([0-9.]+)\s*%`.
  - hashrate: range `([0-9.]+)\s*-\s*([0-9.]+)\s*([KMG]?H/s)` → use max; else single `([0-9.]+)\s*([KMG]?H/s)` near `GPU`/`[ OK ]`. Normalize the unit to H/s for the shared `MinerStats.hashrate_hs` (× 1e3 / 1e6 / 1e9).
  - GPU metrics (optional, for the dashboard): `\[T:(\d+)C, P:([0-9.]+)W, E:([0-9.]+)([KMG]?H/W)\]`.
  - All lines pass through the SHARED `sanitize_log_line()` first (ANSI strip + hex redaction), so the GPU lane inherits the same secret-leak protection.
- Both parsers feed the SAME `MinerStats` struct (so the dashboard is lane-agnostic), with `hashrate_hs` normalized to H/s (XMR is already H/s; KawPoW is MH/s → ×1e6).

### 3.6 Restart policy (deliberate difference from the node)
Like the Wallet's miner (not its node): **no unbounded auto-restart**. But because failover (§4) needs to *re-spawn a lane against the next endpoint*, the lane supervisor exposes a `restart_with(plan)` that the failover controller calls deliberately, gated by the reused `RestartPolicy` (bounded: ≤3 in 5min, exponential backoff capped 30s — `mod.rs`). This bounds an endpoint-flap loop while still letting failover work. A *clean* user-initiated stop bypasses the policy.

---

## 4. Multi-endpoint failover

### 4.1 Endpoint plan (per lane)
The client carries an ordered list of relay endpoints per lane, baked in + overridable, mirroring `bundled_bootnodes()` (node.rs:342). It NEVER carries OUR collection address or the upstream pool — only relay host:port (the relay handles upstream server-side).

```rust
pub struct Endpoint {
    pub host: String,     // "hk.aliceprotocol.org" | "203.0.113.10" | future Reality edge
    pub port: u16,        // XMR 3333 | RVN 8888
    pub transport: Transport,  // Plain | Tls { sni: String } | Reality { ... }  (§6)
    pub label: String,    // "HK relay" / "Core direct" — UI/log only
}

pub struct EndpointPlan {
    pub xmr: Vec<Endpoint>,   // ordered: primary first, then backups
    pub rvn: Vec<Endpoint>,
}

/// Baked-in defaults (overridable via ALICE_MINER_ENDPOINTS_JSON for staging/tests).
pub fn default_endpoint_plan() -> EndpointPlan {
    EndpointPlan {
        xmr: vec![
            Endpoint::plain("hk.aliceprotocol.org", 3333, "HK relay"),
            Endpoint::plain("203.0.113.10", 3333, "Core direct"),      // friend's proven fallback
        ],
        rvn: vec![
            Endpoint::plain("hk.aliceprotocol.org", 8888, "HK relay"),  // 8888→core 4444
            Endpoint::plain("203.0.113.10", 4444, "Core direct"),      // core internal RVN port
        ],
    }
}
```
> Note the asymmetry: via the HK relay the RVN external port is **8888**; direct-to-core the RVN port is **4444** (the relay does the 8888→4444 remap). The per-endpoint `port` captures this precisely.

> **Open question for V (Q5):** Should `203.0.113.10` (the Finland core) be a *baked-in public fallback* in the shipped client? It is the friend's proven path and is currently reachable, but the GFW research's whole point is **the core must never face China directly / never earn an IP blacklist**. Baking it into a public client publishes the core IP to everyone. Safer: ship ONLY `hk.aliceprotocol.org` (+ future Reality edges) and keep `203.0.113.10` as an *operator/tailnet-only* override (`ALICE_MINER_ENDPOINTS_JSON`). Recommendation: do NOT bake the core IP into the public client.

### 4.2 Failover mechanics
Two layers, because xmrig/kawpowminer already do stratum-level reconnect, and we add an *endpoint-rotation* layer on top:

**Layer A — miner-native reconnect (free):** pass MULTIPLE `-o`/`--pool` entries to the miner where supported (xmrig accepts repeated `-o ... -u ... -p ...` blocks and rotates on disconnect; kawpowminer accepts multiple `-P/--pool` URLs). So the FIRST line of defense is the miner's own failover across the endpoint list — zero supervisor logic, battle-tested. The launch-plan builders (`plan_xmr.rs`, `plan_kawpow.rs`) emit one `-o`/`--pool` block per `Endpoint` in order.

**Layer B — supervisor health watchdog (our code):** the `LaneSupervisor` already parses shares + hashrate. The failover controller watches the snapshot:
- **"No progress" detector**: if a lane is `Running` but produces **zero accepted shares AND zero hashrate readings for `STALL_WINDOW` (default 120s)**, treat the current endpoint as dead. (xmrig prints a speed line every 10s; kawpowminer with `--report-hashrate` similarly. Silence ⇒ stuck.)
- On stall: bump an endpoint cursor for that lane, call `lane.restart_with(plan_for(next_endpoint))` (bounded by `RestartPolicy`), and surface a UI note ("HK relay unreachable — trying Core direct"). The OTHER lane is untouched.
- Cursor wraps around the list; if ALL endpoints fail `RestartPolicy.may_restart()` budget is exhausted, the lane lands in `Error` with a clear "no relay reachable — check connection / VPN" message (no infinite loop, no CPU thrash).
- A successful share resets the cursor preference to the primary on the NEXT clean start (so a transient HK blip doesn't pin everyone to the fallback forever).

This gives: instant miner-native reconnect (Layer A) + a deterministic, bounded, observable endpoint rotation when an endpoint is *silently* black-holed (Layer B) — the exact GFW failure mode (SYN in, no SYN-ACK back; memory `alice-edge-node` "CHINA CONNECTIVITY").

### 4.3 The honesty guarantee under failover
Every endpoint in the plan is a relay host:port. The login on EVERY endpoint is the user's own Alice address (`build_*_launch_plan` validates it the same way per endpoint). Failover changes only the destination host:port, never the credential. A unit test asserts that for every endpoint in a generated plan, the `-u`/`--user` value equals the input Alice address and the argv contains no collection/payout/seed string.

---

## 5. On-demand miner download (Windows; any unbundled lane)

### 5.1 `miners.json` schema (signed, separate from `latest.json`)
```json
{
  "schema": 1,
  "product": "alice-miner-miners",
  "generated": "2026-06-03T00:00:00Z",
  "miners": [
    {
      "kind": "xmrig",
      "lane": "cpu-xmr",
      "version": "6.x.y",
      "upstream": "https://github.com/xmrig/xmrig/releases",
      "artifacts": [
        { "platform": "windows-x86_64", "url": "https://github.com/V-SK/alice-miner/releases/download/miners-1/xmrig-6xy-win64.zip",
          "sha256": "<hex>", "size": 1234567, "exe_in_zip": "xmrig.exe" }
      ]
    },
    {
      "kind": "kawpowminer",
      "lane": "gpu-rvn",
      "version": "1.2.4",
      "upstream": "https://github.com/RavenCommunity/kawpowminer/releases",
      "artifacts": [
        { "platform": "windows-x86_64", "url": "...", "sha256": "<hex>", "size": 9876543, "exe_in_zip": "kawpowminer.exe" }
      ]
    }
  ]
}
```
- Hosted on the SAME GitHub release as the Miner; the URL points at a copy WE re-host (so the SHA is stable and pinned, not subject to upstream re-tagging).
- Verified with the embedded release key (reuse `verify_with_embedded_key`), `product` gate = `"alice-miner-miners"`.

### 5.2 Download flow (`download.rs`, reuses `update.rs` primitives)
1. Fetch `miners.json` + `.sig`; `verify_with_embedded_key` BEFORE trusting any field (reuse).
2. Pick the artifact for `current_platform()` + the requested `kind`.
3. `download_and_verify`-style: stream with a size cap, SHA-256 must match BEFORE writing executable (reuse `verify_artifact_integrity`).
4. Extract the single `exe_in_zip` into `<data_dir>/miners/<kind>/<bin>` (NOT the app dir — `assert_not_in_data_dir` analogue; the staged miner lives with user data, never the signed app bundle).
5. `chmod +x` (Unix; Windows just needs the file). Record `{kind, version, sha256}` in `<data_dir>/miners/installed.json`.
6. `resolve_miner_binary(kind)` step (3) then finds it.

### 5.3 UI flow (one-click, honest about AV)
On Windows Start with a missing miner: a single modal — "Alice Miner needs the mining engine (xmrig, ~2 MB, verified). Windows Defender may flag it as a coin-miner; that's expected for any miner. [Download & verify] [Why?]". After download: if Defender quarantines it, a guided "Allow the file / add a folder exclusion" panel (same tone as the Wallet's Gatekeeper guide). No silent background download; no auto-run before the user has consented.

---

## 6. Obfuscation / GFW-resistance

The relay already fronts us (the client talks to `hk.aliceprotocol.org`, never the core). The client stays honest: even through any tunnel, the stratum login is the user's Alice address. Obfuscation is about *reaching the relay* from hostile networks, layered so the default install needs zero config.

### 6.1 What we DON'T do (rejected, per GFW research)
- No IP rotation / buying more raw HK IPs (whack-a-mole; both prior HK boxes got null-routed).
- No domain-fronting (dead). No Cloudflare-proxied stratum (L7-only; can't proxy raw TCP). No in-China infra (legal). No WireGuard/OpenVPN/Hysteria2/plain-SS as the China transport (flagged).

### 6.2 What we DO (layered, default-safe)
**Tier 0 — plaintext stratum to the relay (default, today).** Per the GFW research, plaintext stratum JSON is **exempt** from the FET dynamic block. So the simple `hk.aliceprotocol.org:3333/8888` path already works for most networks and survives FET. Failover (§4) handles a single endpoint being IP-null-routed by rotating to the next.

**Tier 1 — opportunistic TLS to the relay (`stratum+ssl`).** Add a `Transport::Tls { sni }` endpoint variant. Both xmrig (`--tls` / `stratum+ssl://`) and kawpowminer (`stratum+ssl://`) support TLS stratum natively. If/when the friend's relay exposes a TLS stratum port (e.g. :443 or :3334), the client lists a TLS endpoint AHEAD of the plaintext one in the plan. This raises the bar (encrypted), though it is FET-*detectable* — useful where the operator wants confidentiality, not the primary GFW answer.

**Tier 2 — bundled Xray (VLESS+Reality+Vision) client (the durable answer; plan P3/#30).** This is the real GFW-resistance and matches the memory's "C1 client = the superpower: bundle multi-endpoint failover + obfuscation (xray/VLESS+TLS)". Design:
- Ship an `xray` core binary as a sibling release asset (same staging as the miners; macOS/Linux committed, Windows on-demand to keep AV clean — Xray cores are also AV-flagged on Windows).
- A `Transport::Reality { server, sni, public_key, short_id, ... }` endpoint variant. When selected, the Miner:
  1. Spawns `xray` (via the SAME `child.rs::spawn_supervised` — it's just another supervised child, own process group, kill_on_drop) with a generated config that opens a **local SOCKS/`dokodemo-door` inbound on 127.0.0.1:<random_port>** and a VLESS+Reality+Vision outbound to the Reality edge.
  2. Points the miner's `-o`/`--pool` at `127.0.0.1:<that_port>` (xmrig/kawpowminer both speak stratum over a local plain port; Xray tunnels it out as Reality TLS that mimics a real foreign site).
  3. The Reality edge (a cheap clean-ASN box, plan P1) unwraps and forwards to the core over Tailscale — the client never learns the core IP.
- This keeps the miner binaries unchanged (they just connect to localhost), reuses our supervisor for the Xray child, and gives ~98% GFW resistance (per the research) with zero user config — the install ships the Reality params baked in (public key + short_id are not secrets).
- **Honesty preserved**: Xray only transports bytes; the stratum login inside is still the user's Alice address. Xray never sees or alters the credential.

**Endpoint selection order in a China-hostile build:** `[ Reality edge (Tier 2), TLS relay (Tier 1), plaintext relay (Tier 0) ]` — try the stealthiest first, fall back to plaintext (which FET won't block) if the Reality edge is down. Non-hostile networks get plaintext-first for lowest overhead. The order is data (`EndpointPlan`), so a future build/region can reorder without code changes.

### 6.3 Phasing
- **v1 (ship now):** Tier 0 plaintext + §4 failover across `hk.aliceprotocol.org` (+ operator-only core override). This already works and survives FET.
- **v1.1:** Tier 1 TLS endpoints once the relay exposes a TLS stratum port.
- **v2:** Tier 2 bundled Xray/Reality once plan P1 (Reality edge on a clean ASN) is stood up. The endpoint/transport abstraction (§4.1) is built v1 so v2 is additive (new `Transport` variant + an Xray child), not a refactor.

> **Open question for V (Q6):** For v2 Reality, confirm (a) a clean-ASN Reality edge will be provisioned (plan P1) so the client has something to point at, and (b) the Reality public-key/short_id/SNI to bake into the client. Also confirm Windows Xray is **on-demand download** (consistent with the miner-binary AV posture) rather than bundled.

---

## 7. Honesty / security invariants (enforced + tested)

Carried over from `miner.rs`'s test posture; every one is a unit test in the Miner:
1. **Address-only login**: every lane's argv, on every endpoint, has `-u`/`--user` == the user's input Alice address (validated fail-closed by `derive_worker_id`); never OUR XMR (`46knTV…`) or RVN (`RWAp37…`) collection address, never a payout/override address.
2. **No key material**: no argv/env passed to ANY child (miner or xray) contains `seed`/`priv`/the mnemonic/the keystore path. `spawn_supervised` is called with an explicit, minimal `envs` list (the Wallet passes `&[]` for the miner — we do the same; Xray gets only its config-file path).
3. **No collection address in the binary's reach**: the collection addresses live only as *documentation constants* server-side; the client crate does not even contain them (unlike the Wallet which keeps `ALICE_XMR_COLLECTION_ADDRESS` as a doc const — the Miner omits it entirely to make leakage impossible).
4. **Credit-only gates**: compile-time `const` assertions (copy of `miner.rs`'s `run_is_enabled_but_all_other_gates_remain_false`) — `PAYOUT_RELEASE_ALLOWED = SETTLEMENT_ALLOWED = MINT_ALLOWED = false`.
5. **Log sanitization**: all miner + xray output goes through the shared `sanitize_log_line` (ANSI strip + ≥48-hex redaction) before display/persist.
6. **Staged binaries verified**: every bundled binary matches its pinned SHA (`pinned.rs`); every downloaded binary matches its signed-manifest SHA before becoming executable.
7. **Writes never hit the app bundle**: downloaded miners/xray stage under `<data_dir>/miners/`, guarded by the `assert_not_in_data_dir` analogue (inverted: refuse to write a downloaded miner INTO the signed app dir).

---

## 8. Build order (concrete)

1. Factor shared crates from the Wallet: `alice-supervise` (`child.rs` + `mod.rs` `ProcState`/`sanitize_log_line`/`LogRing`/`RestartPolicy`) and `alice-release` (`update.rs`). Wallet keeps working (depends on the crates).
2. `alice-miner/src/miners/binaries.rs` + `pinned.rs` — resolution + SHA pins (reuse `resolve_miner_binary` pattern).
3. `plan_xmr.rs` (reuse `build_miner_launch_plan` + multi-`-o`) and `plan_kawpow.rs` (new KawPoW argv, §3.4) — both endpoint-list aware.
4. `parse_xmr.rs` (reuse) + `parse_kawpow.rs` (port `trex_logs.py`).
5. `lane_supervisor.rs` — generalize `MinerSupervisor` over `LaneLaunch` + `LineParser`.
6. `mod.rs` — `DualMineSupervisor` (two lanes) + `snapshot()`/`totals()`.
7. Failover controller (§4.2 Layer B watchdog) + `EndpointPlan` (§4.1).
8. `download.rs` + `miners.json` + Windows on-demand UI (§5).
9. `alice-miner/scripts/release.sh` (clone + extend the Wallet's) + committed `release-assets/` + `latest.json`/`miners.json` generation (§2).
10. v2 (later): `Transport::Reality` + Xray child (§6.2 Tier 2).

---

## 9. Summary of decisions + open questions

**Decisions:**
- Two lanes: CPU-XMR (xmrig) + GPU-RVN (kawpowminer). PRL excluded from the client GPU default (per memory).
- **Bundle**: xmrig + kawpowminer on **macOS-arm64 + linux-x86_64**. **Windows = no bundled miner**, on-demand download (clean SmartScreen reputation).
- GPU miner = **KawPowMiner** (GPL-3.0, 0% fee, NVIDIA+AMD, redistributable) over T-Rex (proprietary, 1% fee, NVIDIA-only); T-Rex reachable via `ALICE_MINER_GPU_BIN` override only.
- Supervisor = **two independent `LaneSupervisor`s** (each = the Wallet's proven `MinerSupervisor`), reusing `child.rs`/`mod.rs` verbatim; crash-isolated, per-lane parse, per-lane failover.
- Failover = **Layer A** (miner-native multi-`-o` reconnect) + **Layer B** (our bounded "no-progress" watchdog rotating an endpoint cursor; bounded by the reused `RestartPolicy`).
- Obfuscation = tiered: **T0 plaintext (FET-exempt, ship now)** → **T1 opportunistic `stratum+ssl`** → **T2 bundled Xray VLESS+Reality (durable, v2)**; abstracted behind `Transport` so v2 is additive.
- Staging/update = clone the Wallet's `release.sh` + signed `latest.json` (`product:"alice-miner"`) + a SECOND signed `miners.json` for on-demand binaries; ONE offline ed25519 key, product-string-isolated.
- Honesty = the client only ever sends the user's Alice address; collection/payout/key material are never in the client crate, enforced by unit tests.

**Open questions for V:** Q1 bundle KawPowMiner (GPL-3.0) as the shipped GPU miner? Q2 Windows = on-demand-both vs GPU-only? Q3 consumer Miner allowed to bundle/auto-download (overriding the harness's `embedded_miner_binary`/`client_auto_download` prohibition for THIS product)? Q4 one release key for both apps or one per app? Q5 bake the core IP `203.0.113.10` into the public client as a fallback (recommend NO — operator-only override)? Q6 v2 Reality: provision a clean-ASN edge + supply the Reality params; Windows Xray on-demand?

---

Document path: `/Users/v/Alice/alice-miner/docs/design/04-miners-failover.md`
