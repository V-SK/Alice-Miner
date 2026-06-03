# Alice Miner — Master Plan

> Single source of truth for the **Alice Miner** client. Synthesizes the eight
> dimension designs (`docs/design/01..08`) + the visual contract
> (`docs/design/mockup.html`) into one ordered build plan.
>
> **Status: design complete, awaiting V's go.** No product source has been
> written yet (the `alice-miner/` tree is docs-only). This plan modifies no code.
>
> **Hard constraints that hold in every milestone below** (from the brief +
> MEMORY): **credit-only** — no payout / claim / settlement / mint / on-chain
> emission (phase-J, OFF); any "earnings" shown are credit/score, `paid_acu`
> stays `0`. The **proven XMR stratum path is reused verbatim** — login = the
> user's OWN Alice address, pass `x`, `--rig-id <worker-id>`, relay
> `hk.aliceprotocol.org:3333`; OUR collection address + the upstream pool are
> **server-side on the relay** and the client NEVER sends or even contains them.
> **Windows does NOT bundle xmrig.** Targets: macOS-arm64, linux-x86_64,
> windows-x86_64. **Reuse aggressively** — do not rebuild the Wallet's crypto,
> keystore, XMR supervisor, or signed-update pipeline.

---

## 1. Vision + product shape

**Alice Miner** is a dead-simple, *beautiful* one-click desktop miner — the
sibling of the Alice **Wallet** (full, exists) and the future Alice **AI** app
(odysseus fork). It auto-detects the device (CPU / NVIDIA-GPU / Apple Silicon /
ASIC-info-only), auto-picks the mining lane, creates-or-imports a minimal Alice
address (the reward identity), and starts earning **ALICE credit** behind a
single Start button — with its own live local dashboard, bundled miner engines,
optional dual-mine (CPU+GPU), multi-endpoint failover/obfuscation, and a later
opt-in AI-earn lane. All three apps share one identity via `~/.alice/`, so one
mnemonic works everywhere and no user is ever blocked by "I have no address."
Polish (**漂亮 / 好看 / 流畅**) is a first-class requirement, not garnish.

---

## 2. Architecture

### 2.1 Stack decision — **egui/eframe 0.34, NOT Tauri** (resolved)

The Miner is a second **egui/eframe** Rust binary on the **same stack the Wallet
already ships** (`eframe 0.34.1`, verified in `alice-wallet/gui/Cargo.toml:20`).
Rationale (docs 01 §1, 06 §0, 08 §0, all concurring):

- The engine is already Rust + a tokio process supervisor; egui keeps the UI
  in-process and same-language, so the Wallet's `crypto.rs`, `miner.rs`,
  `supervise/*`, `update.rs`, theme, fonts, and window chrome **lift near-verbatim**
  with no JS/IPC marshalling boundary.
- One static binary per target, no WebView runtime dependency, no per-OS
  rendering drift; the **same three platform strings** `update.rs::current_platform()`
  already emits.
- One signing story: `update.rs` uses **raw-ed25519 over file bytes**; Tauri would
  force a *second* signing format (minisign) + a second toolchain.
- The "beautiful" bar is met with an egui theme/widget layer (animated value
  tween, conic hashrate gauge, glow pulse, sparkline) — the Wallet already proves
  the Alice look is achievable in egui; the mockup is the pixel target.

> Tauri would only win for CSS-grade marketing UI. That lives on the **website**
> (`mine.html` / new `miner.html`), not the desktop client.

### 2.2 Core engine

A single UI-agnostic engine library is the source of truth; **both** the GUI and
a headless CLI drive it over a `Command`/`Event` channel pair, so the two
front-ends **cannot drift**. Pipeline (doc 01 §3):

```
Command ─►  detect  ─►  lane-select  ─►  spawn & supervise (N children) ─►  collect stats ─► Event(Snapshot)
           DeviceProfile  Vec<LanePlan>     LaneSupervisor ×N                  Snapshot
```

- **Runtime:** one worker `std::thread` owning an `Arc<tokio::Runtime>`; mpsc
  `Command`/`Event`; `ctx.request_repaint()` wakes the GUI — the exact Wallet
  pattern (`app.rs:1580` worker, `app.rs:312` bridge).
- **Supervision:** lift `supervise/child.rs` (owned `Child`, own process group,
  `kill_on_drop`, SIGTERM→SIGKILL, line-pump) and `supervise/mod.rs` (`ProcState`,
  `sanitize_log_line`, `RestartPolicy`, `LogRing`) **verbatim**; generalize
  `miner_supervisor.rs` into a per-lane supervisor (canonical name **`LaneSupervisor`**,
  see §6 conflict C4). The engine owns **N** of them → dual-mine = 2 supervisors,
  failover = endpoint-cursor advance + bounded `restart_with`.
- **`Snapshot` has no `paid_acu` field** — credit-only by construction.

### 2.3 Repo layout — Cargo workspace (doc 01 §2 is canonical; see §6 conflict C1)

New repo **`V-SK/alice-miner`** (own release tags + binary mirror, no collision
with the Wallet). A **Cargo workspace** (shared `target/`, one lockfile):

```
alice-miner/
├─ Cargo.toml                       # [workspace]
├─ crates/
│  ├─ alice-crypto/                 # SHARED with the Wallet — extracted from crypto.rs (§2.4)
│  ├─ alice-supervise/              # SHARED — child.rs + mod.rs (ProcState/sanitize/RestartPolicy/LogRing)
│  ├─ alice-release/                # SHARED — update.rs kernel (verify/decide/apply)  [optional v1; copy ok]
│  ├─ alice-miner-core/             # the engine LIB (UI-agnostic): detect, lane, supervise, stats,
│  │                                #   identity, endpoint, binaries, dashboard data, config
│  ├─ alice-miner-gui/              # the eframe BIN (the product) — ui/, theme, widgets, screens
│  └─ alice-miner-cli/              # headless BIN (clap, NO egui in its dep tree)
├─ release-assets/                  # committed bundled engines (mac/linux xmrig + kawpowminer) + miners.json
├─ scripts/                         # release.sh + adhoc_sign_macos.sh (copied from Wallet)
├─ .github/workflows/release.yml    # CI build matrix (copied from Wallet, inner-first codesign)
└─ docs/                            # this plan + design set + mockup
```

> Mapping note: docs 02/03/05/06/07 wrote paths as a flat `alice-miner/src/…` or
> `gui/src/…`. Those modules land inside **`crates/alice-miner-core/src/…`**
> (engine logic: `detect/`, `identity.rs`, `lane/`, `dashboard/`, `ai_earn.rs`,
> `gpu_arbiter.rs`) or **`crates/alice-miner-gui/src/ui/…`** (screens/widgets).
> The workspace is the structure; the per-dimension module names are kept.

### 2.4 Shared crypto crate — `alice-crypto`

Extract the Wallet's `crypto.rs` (737 LOC, verified: `SS58_FORMAT=300`,
`CURRENT_WALLET_VERSION=V4`, `WalletPayload`, `create_wallet_payload`,
`create_wallet_payload_from_seed_hex`, `unlock_wallet`, `write_wallet_payload`,
`backup_existing_wallet`) into a standalone crate consumed by **both** apps, so
the keystore is **byte-for-byte identical** and one mnemonic unlocks everywhere.
Add one net-new helper `generate_mnemonic()` (24 words / 32-byte entropy,
`Zeroizing`) lifted from the Wallet's view layer (`ui/create.rs:56-64`).

> The Wallet→crate refactor is the **only** step that touches the Wallet repo (a
> mechanical move + `pub use` re-export). Deferred: until it lands, the Miner
> depends on a **path crate that physically copies the reviewed `crypto.rs`**; its
> test vectors (`crypto.rs:560-736`) move with it and guarantee parity.

### 2.5 The `~/.alice/` contract (doc 03 — pointer-only, recommended)

Two layers, resolving the brief-vs-shipped-Wallet reality (the shipped Wallet
keeps its keystore at `data_local_dir()/AliceWallet/wallet.json`, NOT `~/.alice/`):

- **Layer A — keystore (the secret):** stays at the Wallet's path
  (`AliceWallet/wallet.json`, env `ALICE_WALLET_DATA_ROOT`). `WalletPayload`
  schema. Owned by whichever app creates first; read by the others. **One keystore,
  never two** (two would desync into two addresses — the footgun).
- **Layer B — identity pointer (public only):** `~/.alice/identity.json` — a tiny,
  unencrypted, world-public file naming the **active address**, pubkey, and where
  the keystore lives. This is the cross-app rendezvous; it holds **no secret**.

Rules: whoever creates writes both; the Miner **adopts** an existing Wallet
keystore by reading its plaintext `address` (no unlock); on conflict the
**keystore wins** (it can sign; the pointer is a cache) and the pointer is
rewritten; atomic `0o600` writes; `identity.json` is written only on
create/import/adopt, **never during mining**.

**Security invariant:** `unlock_wallet` runs **exactly once**, at create/import,
to derive+verify the address; `WalletSecrets` is then dropped (zeroizing). The
mining path consumes only the **public address string** — no password, no key,
ever, to start or run mining.

---

## 3. Reuse map

| Wallet / proxy / Alice-Protocol asset | Verified location | How the Miner reuses it |
|---|---|---|
| sr25519 / BIP39 / SS58-300 / keystore | `alice-wallet/gui/src/crypto.rs` | extract → `alice-crypto` crate; byte-identical keystore |
| `generate_mnemonic` (24w/32B) | `…/ui/create.rs:56-64` | lift into `alice-crypto` |
| XMR launch plan (proven, live-validated) | `…/src/miner.rs:355` `build_miner_launch_plan` | **verbatim** in `core/lane/xmr.rs` (address-only login, server-side collection/upstream) |
| Alice-address validate + worker-id | `…/miner.rs:255-318` `validate_alice_address`/`derive_worker_id` | **verbatim**; feeds XMR + RVN + AI rig-ids |
| Thread count (all cores, clamped) | `…/miner.rs:336` `miner_thread_count` | reuse; add `threads_override` for dual-mine headroom |
| Credit-only gate consts | `…/miner.rs:12-24` (`PAYOUT_RELEASE_ALLOWED=false`…) | reuse + compile-time assert test |
| Child spawn/own/stop, log pump, pgid | `…/supervise/child.rs` | **verbatim** → `alice-supervise` crate |
| `ProcState`, `sanitize_log_line`, `RestartPolicy`, `LogRing` | `…/supervise/mod.rs` | **verbatim** → `alice-supervise` crate |
| Single-miner supervisor + parsers | `…/supervise/miner_supervisor.rs` | generalize → `LaneSupervisor` (per-lane parse + endpoints) |
| `parse_hashrate_hs` / `parse_share_counts` | `…/miner_supervisor.rs:273,299` | **verbatim** for XMR lane |
| Worker-thread ⇄ UI bridge + runtime | `…/app.rs:312,1580` | pattern → engine `EngineHandle` |
| ed25519 signed auto-update pipeline | `…/src/update.rs` (`RELEASE_PUBKEY_B64=8P+XmZZF…`, `PRODUCT`, `current_platform`) | copy verbatim, change `PRODUCT="alice-miner"` + URL; **cross-product guard already tested at `update.rs:1299`** |
| Sibling-binary resolution | `…/src/node.rs` `resolve_miner_binary` | generalize over `MinerKind {CpuXmr, GpuRvn}` |
| Committed xmrig bytes (mac+linux) | `…/release-assets/{aarch64-apple-darwin,x86_64-unknown-linux-gnu}/xmrig` (verified present) | copy bytes into Miner `release-assets/`, SHA-pin |
| Release packaging | `…/gui/scripts/release.sh` + `adhoc_sign_macos.sh` | copy; `PRODUCT=alice-miner`, stage engines (drop node logic) |
| CI matrix | `…/.github/workflows/release.yml` | copy; inner-first codesign (NOT `--deep`), engine-pin verify |
| Theme: fonts, dark glass, brand orange | `…/src/ui/theme.rs` + `assets/fonts/*.ttf` | port + extend with lane accents; reuse the TTFs |
| Custom window chrome (titlebar + lights) | `…/src/main.rs:52` | mirror |
| Live mining panel visual reference | `…/src/ui/mining.rs` | reference for dashboard |
| Device detection (fail-safe, dep-light) | `Alice-Protocol/miner/mining_internal/hardware_probe.py` | **port to Rust** `core/detect/`, keep shape/override semantics |
| KawPoW argv + log regexes | `…/mining_internal/trex_runner.py` + `trex_logs.py` | port → `core/lane/gpu_rvn.rs` + `stats/parse_kawpow.rs` |
| Inference worker (credit-only) | `…/mining_internal/inference_worker_client.py` `run_once()` | drive from a supervised sidecar (AI lane, later) |
| Public credit read API | `alice-acp/.../shadow_server/http_app.py:1683-1815` (`/shadow/window(/preview)`, `/shadow/balance`, `paid_acu="0"` envelope) | poll for Source-B credit; assert `paid_acu=="0"` |
| Download page pattern | `alice-website/wallet.html` (+ `mine.html`, `vercel.json`) | clone → `miner.html`; wire `mine.html` buttons; add `/miner` rewrite |

---

## 4. UI/UX direction

> **VISUAL LOCKED 2026-06-03 (V: "非常好看"):** Direction **B "focal / atmospheric"**
> with the **"Alice Core" hero** — a dark glassy orb with the **Alice mark glowing
> inside it** (orange = *emitted light*, not a flat fill); idle = dim ember + "START",
> mining = mark lights up + breathes, conic gauge ring wraps the orb, kH/s readout
> **below** the orb. Hero sized **170px (~43% of the card)**. Canonical contract =
> `docs/design/mockup.html` (the chosen B). `mockup-A.html` kept as the rejected
> calm-minimal alternative. egui mapping: orb = radial-gradient circle + layered
> shadows; mark = SVG/image with an additive glow; ring = epaint stroked arc;
> breathing/tween = `ctx.request_repaint()` time-lerps.

Design system in `docs/design/06-ui-ux.md`; **visual contract** in
`docs/design/mockup.html` (open in a browser). Tokens lifted **verbatim** from
`alice-website/assets/alice-theme.html` — no new brand invented.

- **North star:** one glance / one click; calm-premium-dark; **honest by
  construction** (rewards are *pending / 待发放*, never "credit"/"paid"/`$`).
- **Palette:** orange-500 `#F97316` spine, zinc glass surfaces
  (`rgba(24,24,27,.62)`), JetBrains-Mono on every numeral, bundled TTFs. Lane
  colors match `mine.html` exactly (XMR `#FB923C`, GPU `#3B82F6`, Mac `#22D3EE`,
  ASIC `#34D399`, AI `#A855F7`).
- **Window:** frameless 1040×720 (min 920×640), custom 56px titlebar = drag
  region + global mining-status pill, macOS traffic-lights preserved, 64px icon
  rail (Home / Dashboard / Settings).
- **Home (the product):** one tall centered card. The hero is a ~200px orange
  squircle Start button. **Signature interaction:** at "mining" it becomes a
  **live conic hashrate gauge** with the kH/s number inside + a `pulse-glow`
  breathing animation; numbers **tween** toward target each frame (the "流畅"
  feel). States fully specced: idle / connecting (indeterminate sweep) / mining /
  error / stopping + first-run.
- **Onboarding:** 3-step create (forced mnemonic backup — retype 3 random words,
  an intentional divergence from the Wallet) or 2-step import, or paste-address-only
  (watch-only). Auto-skips entirely if a shared `~/.alice/` identity already exists.
- **Dashboard:** header + 2×2 stat grid (Hashrate w/ 60s sparkline · Shares A/R ·
  Accepted % · **Est. rewards = "— pending"**) + per-lane breakdown + endpoint/worker
  KV + sanitized log console. **Never** renders the collection address or upstream
  pool (honored by absence).
- **Reward-wording contract (enforced, not stylistic):** a single `reward_label()`
  helper centralizes strings; a unit test asserts no key contains `$`, "credit",
  or an active "paid".

**Mockup polish verdict:** **genuinely polished and a faithful visual contract.**
The tokens are brand-accurate, the hero gauge + breathing pulse + JS hashrate
tween nail the "流畅" signature, and the Home/Dashboard screens read like a Wallet
sibling. **One pass still needed before/early-build:** the mockup draws only Home
+ Dashboard (happy path); it does **not** render the **onboarding create/import
wizard**, the **error / empty / first-run** states, or **Settings** — all specced
in doc 06 but not yet visualized. Recommend extending the mockup (or producing a
second frame set) for those states during M2/M3 so the build has a pixel target
for every screen, not just the two.

---

## 5. Ordered build milestones

Ordering principle: **a runnable, honest, end-to-end thing exists at M1**, then
layers outward. Each milestone is independently shippable; none after M1 blocks
the previous from running.

> Convention: "Reuses" = existing code lifted; "Accept" = the concrete check that
> proves the milestone done.

### M0 — Workspace skeleton + shared crates
- **Delivers:** the Cargo workspace (§2.3); `alice-crypto` (copied `crypto.rs` +
  `generate_mnemonic`, tests passing); `alice-supervise` (verbatim `child.rs` +
  `mod.rs`); `alice-release` (copied `update.rs`, `PRODUCT="alice-miner"`); empty
  `alice-miner-core` / `-gui` / `-cli` that compile.
- **Reuses:** `crypto.rs`, `supervise/*`, `update.rs` (all verbatim/copied).
- **Accept:** `cargo build` (all crates) + `cargo test -p alice-crypto` green
  (the moved KDF/AES/SS58 vectors pass → keystore parity proven); `cargo build -p
  alice-miner-cli` pulls **no** egui.

### M1 — One-click CPU-XMR on macOS, end-to-end to the relay ★ the spine
- **Delivers:** detect (CPU/Apple path) → create-or-import address (forced backup)
  → **one Start button** → xmrig spawned via `LaneSupervisor` → connects to
  `hk.aliceprotocol.org:3333` with address-only login → **minimal live dashboard**
  (hashrate + shares + state from stdout parse). The `~/.alice/identity.json`
  contract live; embedded minimal wallet (create/import/paste); engine
  `Command`/`Event` + GUI bridge; bundled macOS xmrig resolved as a sibling.
- **Reuses:** `build_miner_launch_plan` + `derive_worker_id` (verbatim), `xmrig`
  macOS bytes, `parse_hashrate_hs`/`parse_share_counts`, the worker/runtime
  pattern, theme/fonts/window chrome.
- **Accept:** on a real Mac, fresh `~/.alice/`, click Create → backup-confirm →
  Start → xmrig connects, dashboard shows a rising hashrate + accepted shares to
  the user's own address; Stop kills the child (SIGTERM→SIGKILL) cleanly; argv
  contains the user's address as `-u` and **no** collection/seed string (unit
  test). `paid_acu` absent from `Snapshot`.

### M2 — Beautiful Home (the visual contract) + onboarding polish
- **Delivers:** Home rebuilt to the mockup — hero squircle, **conic hashrate
  gauge**, idle/connecting/mining/error/stopping states, number tweening,
  pulse-glow, status pill; the full create/import/paste wizard styled; reduced-motion
  support; `reward_label()` guard + test. (Extend the mockup for wizard/error/empty
  states first — §4 verdict.)
- **Reuses:** Wallet `ui/theme.rs` + `widgets.rs` as the base; the mockup tokens
  (§11 egui mapping is a transcription table).
- **Accept:** side-by-side with `mockup.html`, Home matches at idle + mining; all
  five states reachable; no user-facing string contains `$`/"credit"/active-"paid"
  (test green); reduced-motion kills pulses but keeps color states.

### M3 — GPU-RVN lane (KawPoW) + device detection breadth
- **Delivers:** full `core/detect/` port (NVIDIA / AMD-label-only / Apple / CPU /
  all-probes-failed fallback) → `CapabilityProfile` + viability matrix;
  `core/lane/gpu_rvn.rs` KawPoW argv to `hk.aliceprotocol.org:8888`; kawpowminer
  resolution + `parse_kawpow` (ported `trex_logs.py`); RVN lane card on Home.
- **Reuses:** `hardware_probe.py` shape, `trex_runner.py`/`trex_logs.py` regexes,
  `validate_alice_address`.
- **Accept:** on an NVIDIA box, detect → recommended_lane = RVN → Start → kawpowminer
  connects to :8888, dashboard shows MH/s normalized to H/s + shares; AMD/Intel show
  "coming soon" label, no lane button; address-only login asserted per lane (test).

### M4 — Dual-mine + multi-endpoint failover
- **Delivers:** engine owns 2 `LaneSupervisor`s (CPU-XMR + GPU-RVN), default **OFF**,
  `cores-2` XMR headroom in dual mode (single mode stays "拉满"); dual-mine toggle +
  "heat/fan" confirm; failover = Layer A (miner-native multi-`-o`/`--pool`) + Layer B
  (bounded "no-progress 120s" watchdog rotating an endpoint cursor, gated by
  `RestartPolicy`); dashboard two-row lane stack + endpoint label.
- **Reuses:** the single-lane supervisor ×2, `RestartPolicy`, the `EndpointPlan`
  data shape.
- **Accept:** both lanes run crash-isolated (kill one, other survives); with the
  primary endpoint blackholed, the lane rotates to the next within the window and
  surfaces a UI note; budget exhaustion → clean `Error`, no thrash; **public client
  ships only `hk.aliceprotocol.org`** (core IP operator-only override — §6 D-Q5).

### M5 — Local dashboard depth + Source-B credit (confirmation-only)
- **Delivers:** `DashboardModel` with Source A (live, ~250ms) clearly labelled
  *activity*; Source B (`PoolStatsClient` → `/shadow/window/preview` + `/shadow/balance`,
  30–60s poll, jitter, single-flight, backoff) with the `CreditScore` newtype
  (no fiat/payout Display) asserting `paid_acu=="0"`; reconciliation badge
  (qualitative only); ships **Option 3 / `NotExposed`** for v1 (§6 D-Q-dash).
- **Reuses:** the supervisor snapshots; the verified server contract
  (`http_app.py:1683-1815`).
- **Accept:** dashboard shows live local activity + an honest "credit accounting
  live, payout off; per-address total not yet exposed" panel with an explorer deep
  link; **`evaluate_reward_projection` is NOT ported** (no fabricated earnings — the
  #18 red-team risk); a `paid_acu!="0"` response flips to `Error` and drops the value
  (test).

### M6 — CLI parity
- **Delivers:** `alice-miner-cli` subcommands `detect | identity [--create|--import]
  | start [--lane xmr|gpu|auto] [--dual] | status | stop` over the same engine;
  streams snapshots, Ctrl-C → `Stop`.
- **Reuses:** the whole `alice-miner-core` engine (zero new logic).
- **Accept:** `alice-miner detect` prints the profile; `alice-miner start --lane xmr`
  mines headlessly to the same address; no egui in the binary (`ldd`/`otool` clean).

### M7 — 3-OS packaging, signing, auto-update, download page
- **Delivers:** `scripts/release.sh` + `adhoc_sign_macos.sh` (copied), CI matrix
  (inner-first codesign, engine SHA-pin verify); committed mac+linux xmrig+kawpowminer;
  **Windows GPU-only** artifact (no xmrig.exe) + on-demand pinned `xmrig.exe` download
  (`miners.json`, signed); signed `latest.json` (`product:"alice-miner"`) self-update;
  `alice-website/miner.html` (cloned from `wallet.html`) + `mine.html` button wiring +
  `/miner` rewrite.
- **Reuses:** `release.sh`, `update.rs`, the one offline ed25519 key (product-isolated),
  `wallet.html` layout + `detectOS()`.
- **Accept:** all 3 artifacts build in CI unsigned; offline-signed `latest.json`
  verifies against the embedded key; a stale client self-updates with health-gate +
  rollback; Windows zip contains only `AliceMiner.exe`+`kawpowminer.exe`+svg; download
  page detects OS + shows verify block; credit-only/pending copy intact.

### M8 — AI-earn lane (opt-in, OFF by default, GPU-eligible only) — later
- **Delivers:** `core/ai_earn.rs` (validated sidecar launch plan + status parse),
  `core/gpu_arbiter.rs` (mutually-exclusive mine-OR-infer state machine),
  `ai_worker_supervisor`, the ~120-line Python sidecar driving
  `InferenceWorkerClient.run_once()`, one config toggle, one violet UI card.
  Hidden by `AI_EARN_ALLOWED=false` until go-live; renders only on eligible GPUs.
  Credit pegged to mining rate via Route 1; **resolve C5** (sidecar vs in-process)
  before building.
- **Model Manager (`core/model_manager.rs`) — NEW (V 2026-06-03):** on AI-earn
  opt-in (or an explicit "pre-fetch model" toggle, available earlier), detect
  device VRAM/RAM → pick a right-sized model (small quantized GGUF for ≤8 GB,
  mid for 12–24 GB, larger for ≥24 GB; CPU-only → tiny) → **background-download to
  `~/.alice/models/` with pinned SHA, resumable + checksum-verified** so inference
  loads instantly when a job arrives. Surfaced as a `model · downloading 40% / ready`
  chip on the AI card. Credit-only; the download **never** blocks or throttles mining
  (low-priority, pausable). Model catalog (name/size/SHA/url) ships pinned, signed.
- **Reuses:** `inference_worker_client.py` (verbatim), `LaneSupervisor`/`spawn_supervised`,
  `~/.alice/` address as `passport_id`.
- **Accept:** with the flag on, on a GPU box, toggling AI-earn runs inference **only
  while GPU mining is not running** (never starves mining), credit lands under
  `MAIN_POOL_AI` with `paid_acu=0`; seed/key never reaches the sidecar (test); the
  four credit-only guards hold.

### M9 — Obfuscation v2 (bundled Xray VLESS+Reality) — later, additive
- **Delivers:** `Transport::Reality` endpoint variant + an Xray child (same
  `child.rs` supervisor) opening a local SOCKS/dokodemo inbound; miner points at
  localhost; Reality params baked in. v1 already ships T0 plaintext (FET-exempt) +
  T1 opportunistic `stratum+ssl` so this is purely additive.
- **Reuses:** the `Transport` enum (built in M4), the child supervisor.
- **Accept:** on a hostile network the client reaches the relay via Reality, falls
  back to plaintext if the edge is down; the stratum login inside the tunnel is still
  the user's Alice address (Xray transports bytes only).

---

## 6. Key decisions (resolved) + open questions for V

### Resolved (do not relitigate)
- **D-stack:** egui/eframe 0.34, not Tauri (§2.1).
- **D-layout:** Cargo workspace with `alice-crypto`/`alice-supervise`/`alice-release`
  shared crates + `core`/`gui`/`cli` (§2.3) — this **reconciles C1**.
- **D-identity:** `~/.alice/identity.json` is **pointer-only**; the keystore stays
  at the Wallet's path; one keystore, never two (§2.5).
- **D-security:** key unlocked exactly once at create/import; mining uses only the
  public address.
- **D-lanes:** CPU→XMR, NVIDIA-GPU→RVN(KawPoW), Apple→XMR, ASIC→info-only. **PRL is
  NOT a client lane** (ruled fake-AI per MEMORY) — the one deliberate divergence
  from the Python reference.
- **D-GPU-miner:** bundle **KawPowMiner** (GPL-3.0, 0% fee, redistributable,
  NVIDIA+AMD, cross-OS) over T-Rex (proprietary, 1% fee, NVIDIA-only); T-Rex via
  `ALICE_MINER_GPU_BIN` override only.
- **D-dual:** default OFF; `cores-2` XMR headroom in dual; single mode "拉满".
- **D-credit-read:** ship **Option 3 (`NotExposed`)** v1 — honest, zero server
  dependency; fast-follow Option 1 (`GET /public/credit?address=`).
- **D-no-projection:** do **NOT** port `evaluate_reward_projection`/`estimated_rewards`
  (fabricated-earnings risk, #18 red-team).
- **D-signing:** one offline ed25519 key for both products (the `product` field
  isolates them; cross-product guard already tested at `update.rs:1299`).
- **D-Windows:** no bundled xmrig; GPU-first if NVIDIA, CPU lane = on-demand
  pinned-SHA download.
- **D-honesty:** the client crate never even contains the collection/payout
  addresses; enforced by unit tests on every lane's argv.

### Open questions — only V can decide

> **RESOLVED 2026-06-03 by V** ("剩下的按照你的推荐来"): **Q1 Windows CPU lane = on-demand pinned-SHA `xmrig.exe` download, GPU-first default.** All others accepted per recommendation — egui (D-stack), one ed25519 key (Q4), `crypto.rs` **vendored copy** for v1 / no Wallet-repo change yet (Q3), RVN client port **8888**→core4444 (Q2, confirmed from MEMORY edge-node), core IP **operator-only, never in the public client** (Q5), **KawPowMiner** (D-GPU-miner), single-mine 拉满 / dual `cores-2` (Q7), AI-earn = **sidecar, later (M8)** (Q6/C5), AI lane hidden until M8 (Q8). Tray = post-v1.
>
> **Two NEW V requirements (2026-06-03):**
> - **(i) NO emoji anywhere** — all iconography is monoline **SVG** or omitted; the auto-detected device shows **only its model string** (e.g. `Apple M2 Max · 12 cores`), never an emoji or vendor glyph. The v1 mockup was judged **"不够漂亮"** and is being re-cut to best-in-class premium-dark (Linear/Raycast tier) — see `docs/design/mockup-A.html` / `mockup-B.html`; pick replaces `mockup.html` as the contract.
> - **(ii) Auto-download a device-appropriate inference model** so AI-earn can load instantly when a job arrives — see **M8 + the new Model Manager**.

1. **Windows CPU lane:** on-demand xmrig download (keeps both lanes) **vs** Windows
   GPU-only (simplest AV story). *Recommend: on-demand download, GPU-first default.*
   (docs 01-Q1, 02-Q4-area, 04-Q2)
2. **RVN client-facing port: 8888** (MEMORY edge-node + `mine.html`) vs 4444 (ACP
   survey). All docs assume 8888→core4444; needs the one literal confirmed.
   (01-Q5, 02-Q1, 04 §4.1)
3. **Wallet repo touches:** approve extracting `crypto.rs` (+ optionally `update.rs`,
   `supervise/*`) into shared crates now, **vs** vendored copy for v1? (Also: file a
   follow-up so the Wallet writes `identity.json` for symmetry.) (01-Q3, 03-Q1/Q3)
4. **One ed25519 release key for both apps** (recommended) vs one per product? (04-Q4,
   08-O2)
5. **Core IP `203.0.113.10` in the public client?** *Recommend NO* — operator-only
   override; the GFW research says the core must never face China directly. (04-Q5)
6. **AI-earn shape (resolves C5):** Python **sidecar** (doc 05, recommended,
   matches Wallet pattern) **vs** in-process Rust worker_client (doc 08's bundle
   table)? Plus the AI-lane enrollment token (issue on open basis vs gated). (05-O1/O4,
   08 §2.1)
7. **Tray / menu-bar in v1?** and **default thread count** (true "拉满" vs leave 1-2
   cores free since it's left running)? (06-Q1/Q2)
8. **AI lane on Home v1** (third violet lane) **vs** Dashboard-only "coming soon"?
   (06-Q4) — plan assumes hidden until M8.

### Conflicts reconciled between dimension designs (flagged)
- **C1 — repo layout:** doc 01 (workspace, engine-as-lib + CLI) vs docs 02/03/05/06/07
  (flat `src/`) vs doc 08 (`gui/`). **Resolved:** adopt 01's workspace as canonical;
  map the others' modules into `core`/`gui` (§2.3). *No conflict in content, only in
  path prefix.*
- **C2 — CLI presence:** doc 01 mandates a headless CLI; doc 06's file list omits it.
  **Resolved:** keep the CLI (brief says GUI+CLI) — it's M6, free given the
  engine-as-lib design.
- **C3 — doc cross-refs:** doc 07 cites the UI dim as "08-ui.md" (it's `06-ui-ux.md`);
  doc 01's "future docs" are mis-numbered. **Cosmetic only** — no design impact.
- **C4 — supervisor naming:** `LaneSupervisor` (01) / `MiningOrchestrator` (02) /
  `DualMineSupervisor` owning `LaneSupervisor`s (04) / `ai_worker_supervisor` (05).
  **Resolved canonical:** **`LaneSupervisor`** = one child + parse + endpoints
  (generalized `miner_supervisor.rs`); the **engine** owns N of them (dual-mine = 2,
  +AI = 3). "DualMineSupervisor"/"MiningOrchestrator" are the same engine-owned set,
  not a separate type.
- **C5 — AI-earn binary:** doc 05 ships a supervised **Python sidecar**; doc 08's
  bundle matrix says the AI lane needs **no binary (in-process Rust)**. **Direct
  contradiction.** Flagged as **open question #6**; doc 05 (the AI-dimension owner) is
  more detailed and recommends the sidecar. Does not affect M0–M7. Must be settled
  before M8.
- **C6 — RVN port:** every doc converges on 8888 but flags 4444 (ACP survey) as
  needing confirmation. Surfaced as **open question #2** (consistent, just unconfirmed).

---

## 7. Risks + mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| **Windows Defender/SmartScreen flags the miner** (PUA) | High | No bundled xmrig on Windows; GPU-only default + on-demand pinned download; plain folder zip (no NSIS/MSI); honest Unblock docs + published checksums/sig; EV cert held as last-resort only (08 §7). |
| **Fabricated-earnings figure** (the #18 red-team trap) | Med | Type-system enforcement: `CreditScore` newtype, no fiat Display; `paid_acu=="0"` asserted; `evaluate_reward_projection` explicitly NOT ported; reward-wording unit test. |
| **No public address-keyed credit read endpoint today** | Certain (current) | Ship Option 3 (`NotExposed`) — honest, zero server dep; Source A carries the live UX; fast-follow Option 1 (client path identical, only `CreditState` flips). |
| **Two keystores desync into two addresses** (the 64× footgun) | Med if mis-built | `~/.alice/` is pointer-only; one keystore at the Wallet path; keystore-wins conflict rule; adopt-don't-create; backup-before-overwrite on import. |
| **Core IP leaked by baking it into the public client** | Med | Ship only `hk.aliceprotocol.org`; core IP is operator-only `ALICE_MINER_ENDPOINTS_JSON` (open question #5, recommend NO). |
| **GFW null-routes the relay endpoint** | Med | Layer A+B failover (v1, FET-exempt plaintext) → T1 TLS → T2 bundled Xray/Reality (M9); `Transport` enum built in M4 so v2 is additive. |
| **Wallet-repo refactor (crypto crate) destabilizes the shipping Wallet** | Low-Med | Defer: Miner uses a copied path-crate first (test vectors guarantee parity); the extraction is a pure move + `pub use` re-export, landed as its own reviewed change. |
| **GPU crash takes down the CPU lane in dual-mine** | Med | Two independent `LaneSupervisor`s, each its own process group; SIGKILL to one never hits the other (04 §3.3). |
| **macOS bundled-engine won't load after quarantine** | Med | Inner-first ad-hoc codesign (sign nested xmrig/kawpowminer Mach-Os before sealing the bundle), NOT `--deep`; `update::adhoc_codesign` mirrors it for self-update. |
| **KawPowMiner log format differs from T-Rex** | Low | `parse_kawpow` generalized to match both; compare a real kawpowminer sample before M3 sign-off (02 §7.3 precondition). |
| **AI-earn starves mining** | Low (by design) | Mutually-exclusive switch: AI runs only while GPU mining is NOT running (v1 rule); clean handoff, never killed mid-token unless stop-grace elapses. |

---

## 8. Build-workflow outline (for the follow-up build, after V approves)

Phased so a runnable artifact exists early; agents fan out **within** a phase only
where modules are independent (the workspace's crate boundaries make this clean).

- **Phase 0 — Foundation (serial, 1 agent).** M0: workspace + the three shared
  crates (`alice-crypto`, `alice-supervise`, `alice-release`). Gate: all green,
  keystore parity test passes. *Everything downstream depends on this; do it first,
  alone.*
- **Phase 1 — The spine (serial, 1 agent).** M1: detect(CPU)+identity+engine+GUI
  bridge+XMR lane+minimal dashboard, end-to-end on macOS. Gate: real mac mines to a
  user address. *This is the proof the architecture works; keep it one agent for a
  coherent first cut.*
- **Phase 2 — Breadth (fan-out, ~3 parallel agents).** Independent, all build on the
  M1 engine: **(a)** M2 beautiful Home + onboarding polish (+ extend mockup for
  wizard/error/Settings); **(b)** M3 GPU-RVN lane + full detection; **(c)** M5
  dashboard depth + Source-B poller. Light coordination on `Snapshot`/`DashboardModel`
  shape (freeze it at end of Phase 1).
- **Phase 3 — Resilience + reach (fan-out, ~2 agents).** **(a)** M4 dual-mine +
  failover + `Transport` enum + `EndpointPlan`; **(b)** M6 CLI parity. M4 owns the
  supervisor-set generalization; M6 only consumes the engine.
- **Phase 4 — Ship (serial, 1 agent).** M7 packaging/signing/CI/auto-update +
  `miner.html`. Gate: signed self-update round-trips with rollback; 3 artifacts build.
  *Touches release infra + the website; serialize to avoid signing/CI churn.*
- **Phase 5 — Later lanes (each its own task, after V settles its open question).**
  M8 AI-earn (blocked on open-question #6 = C5 resolution); M9 Xray/Reality v2
  (blocked on a provisioned clean-ASN edge + Reality params, open-question per 04-Q6).

**Cross-cutting gates every phase must hold:** the credit-only invariants
(no `paid_acu`, no payout flag, no projection), the honesty argv tests (address-only,
no collection/seed string), and the reward-wording test. Wire these as CI checks in
Phase 0 so they guard every later PR.

---

*End of master plan. This document modified no product source.*
