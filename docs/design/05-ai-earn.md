# 05 — AI-Earn Lane (idle-GPU inference)

**Status:** DESIGN (later milestone — not v1 core). Docs only; no product source changed.
**Owner:** Alice Miner.
**Hard posture:** OPT-IN, OFF by default, clearly SECONDARY to mining, **credit-only** (no claim/payout/emission; `paid_acu="0"`).

---

## 0. TL;DR

The Miner can let an **idle GPU** earn ALICE credit by running local LLM **inference jobs** instead of (never alongside) GPU mining. We do **not** rebuild the inference stack: we drive the already-built, credit-only `InferenceWorkerClient.run_once()` (Alice-Protocol) from a small Python **sidecar** that the Miner supervises exactly like it supervises XMRig. The GPU is shared by a **mutually-exclusive switch** (mine **or** infer, never split a single GPU) keyed on the inference stack's existing `current_mining_state` field; the server's existing `mining_throttle_signal` tells us when to yield. Credit for an inference completion is **pegged to that GPU's mining credit/hour** via the existing **Route 1** peg, so "AI earn" is fair against the RVN/PRL mining baseline, not a downgrade. The Miner shows it as one more credit source in the same dashboard the mining lanes feed; the headline number stays "credit / score", `paid_acu` stays `0`.

This lands as a **later milestone** with a **minimal integration surface**: one new Rust module (`ai_earn.rs`), one supervised sidecar entrypoint, one toggle in `config`, and ~four UI strings. None of it is on the v1 critical path, and nothing in the v1 mining core needs rework to add it.

---

## 1. What we reuse vs. what is new

### 1.1 Reused verbatim (do NOT rebuild)

| Concern | Reused component | Path |
| --- | --- | --- |
| Heartbeat → lease → execute → submit loop | `InferenceWorkerClient.run_once()` | `Alice-Protocol/miner/mining_internal/inference_worker_client.py:196` |
| Capacity heartbeat shape | `DemandDrivenInferenceWorker.worker_capacity_from_heartbeat` via `build_capacity_heartbeat` | `…/inference_worker_client.py:182`; `…/inference_worker.py` |
| Job execution (admit → backend → usage) | `DemandDrivenInferenceWorker.execute_job_envelope` | `…/inference_worker.py` |
| Mining-state field (the mutual-exclusion primitive) | `Q38InferenceAvailabilityHeartbeat.current_mining_state` (`idle`/`mining`/`preemptible`/`paused`) | `…/inference_availability.py:13-25,86` |
| Yield-to-mining / throttle signal | `mining_throttle_signal` on the scheduler admission | `…/inference_scheduler.py:79,142,176` |
| GPU-fair credit (peg to mining rate) | `Route1PegResolver` + `InferenceCompletionRequest.{model_tier,gpu_class,runtime}` | `alice-acp/.../shadow_server/route1_peg.py:317,399`; `.../types.py:256-258` |
| Credit ACU policy (fallback) | `calculate_verified_inference_acu` | `alice-acp/.../shadow_server/inference_acu.py:84` |
| Lane + session constants | `MAIN_POOL_AI`, `SESSION_KIND_INFERENCE` | `alice-acp/.../shadow_server/types.py:37,46` |
| Credit-only client guardrails | `_strip_forbidden_queue_fields` (drops `live_reward`/`payout` keys), `_validate_no_raw_prompt_response`, `config.validate()` rejecting `live_reward_enabled`/`payout_executor_enabled`/`direct_pool_mode_enabled` | `…/inference_worker_client.py:28-38,71-93,366-387` |
| Reference end-to-end credit loop | `ColocatedInferenceWorker` (Phase A, reward OFF, `paid_acu="0"`) | `alice-acp/.../api_chat_gateway/colocated_inference_worker.py` |
| Process supervision (spawn/SIGTERM→SIGKILL/log pump) | the Miner's miner-supervisor (mirrors `MinerSupervisor`) | `alice-wallet/gui/src/supervise/miner_supervisor.rs` |
| Shared identity (the Alice address) | `~/.alice/identity.json` (active address) | per `~/.alice/` shared-identity contract |
| Sidecar spawn pattern | `spawn_worker` + `supervise/` already used by the Wallet | `alice-wallet/gui/src/app.rs:339,1580`; `supervise/` |

### 1.2 New (this milestone)

| New artifact | Kind | Purpose |
| --- | --- | --- |
| `alice-miner/gui/src/ai_earn.rs` | Rust module | Build the validated sidecar launch plan + parse its status lines; the AI-earn analogue of the mining `miner.rs`. Pure/testable. |
| `alice-miner/gui/src/supervise/ai_worker_supervisor.rs` | Rust module | Supervise the Python inference sidecar (spawn/stop/log-pump), a near-copy of `miner_supervisor.rs`. |
| `alice-miner/sidecar/ai_earn_sidecar.py` | Python entrypoint | A thin wrapper around `InferenceWorkerClient.run_once()` that loops, reads config from argv/env, and prints **one JSON status line per cycle** to stdout. ~120 lines; **logic lives in the reused client**. |
| `alice-miner/gui/src/gpu_arbiter.rs` | Rust module | The single source of truth for "is the GPU mining or inferring right now". Owns the mutually-exclusive switch + the yield/resume policy. |
| `config` additions | Rust consts/struct fields | `AI_EARN_ALLOWED` compile-time gate (default `false` for v1) + a runtime `ai_earn_enabled` user toggle + sidecar/queue endpoint config. |
| UI: AI-earn card | egui widget | One card in the dashboard: toggle, status, last-cycle credit, "secondary to mining" note. |

> The Python sidecar is the same shape the Wallet already uses for its worker; we are not introducing a new IPC paradigm. If a future build prefers PyO3 over a subprocess, only `ai_worker_supervisor.rs` changes — `ai_earn.rs`, the arbiter, config, and UI are unaffected.

---

## 2. User experience (opt-in, secondary)

### 2.1 Visibility gate

* **The AI-earn card only renders when the device actually has an eligible GPU** (the detector's GPU lane is present and the GPU has enough free VRAM for at least the smallest pinned model tier). On CPU-only / Apple-Silicon-without-enough-RAM / ASIC devices the card is hidden entirely (no dead toggle).
* `AI_EARN_ALLOWED` is a **compile-time const, `false` for v1** — even on a GPU box the card is hidden in v1 builds. Flipping it to `true` is the milestone's go-live switch, mirroring the Wallet's `AI_JOBS_ALLOWED=false` precedent (`alice-wallet/gui/src/miner.rs:20`).

### 2.2 Opt-in flow (when the milestone is live)

1. The user is mining (or has set up mining) — AI-earn is presented **inside** the mining surface as "also earn when your GPU is idle", never as a competing primary action.
2. The card shows a single **"Earn with AI when idle"** toggle, default **OFF**. A one-line note: *"Secondary to mining. Your GPU mines first; it runs AI jobs only when there's no mining work for it. Credit-only — no payout."*
3. Turning it ON:
   * reuses the **same Alice address** already chosen for mining (read from `~/.alice/identity.json`); the user is **never** asked for an address again,
   * starts the supervised sidecar,
   * the card flips to a live state (status dot + "AI idle/serving", last-cycle credit).
4. Turning it OFF stops the sidecar (graceful SIGTERM→SIGKILL via the supervisor) and the GPU returns to mining-only.

### 2.3 No new wallet, no key use

AI-earn needs **only the public Alice address** (the credit/reward identity), exactly like mining. The private key / seed is **never** unlocked, read, or passed to the sidecar. The address is derived to the same `worker_id` the mining lane uses (`derive_worker_id`, `alice-wallet/gui/src/miner.rs:298`) so credit attributes to one identity across lanes.

---

## 3. Registration (the Alice address → credit identity)

The reused client speaks an **internal queue API** (`/internal/inference/workers/{heartbeat,lease}`, `/internal/inference/jobs/{complete,fail}` — `inference_worker_client.py:23-26`). Two registration facts the Miner must satisfy:

1. **Credit identity = the user's Alice address.** The capacity heartbeat carries `passport_id` + `device_id` (`inference_worker_client.py:233-234`). For the Miner's open-enrollment, credit-only posture we set:
   * `passport_id` = the user's Alice SS58-300 address (the same value mining logs in with),
   * `device_id` = the stable per-device id the Miner already computes for mining (the `derive_worker_id` output / device fingerprint),
   so an inference completion credits the **same address** as the device's mining shares. The server already keys `MAIN_POOL_AI` work to `(passport_id, device_id)` (`types.py:283-284`; `colocated_inference_worker.py:375-390`).
2. **Auth token.** The client requires a bearer token (`ALICE_ACP_INFERENCE_WORKER_AUTH_TOKEN`, `inference_worker_client.py:22,281`). For a public Miner this is the **AI-lane enrollment token** the relay/queue hands out on the same open-enrollment basis as the stratum lanes (server-side concern; see §7 open question O1). The Miner stores it next to its other endpoint config, never in the keystore.

`InferenceWorkerClientConfig.validate()` **fails closed** if `live_reward_enabled`, `payout_executor_enabled`, or `direct_pool_mode_enabled` are set (`inference_worker_client.py:87-92`) — the Miner constructs the config with all three `False` and never exposes them.

**No on-chain registration, no payout address.** `ShadowSessionIssueRequest.miner_provided_payout_address` is left `None` and `live_reward_enabled=False` end-to-end (`colocated_inference_worker.py:385-388`).

---

## 4. GPU sharing: mutually-exclusive switch (decision)

**Decision: a single GPU is either mining OR running inference at any instant — never both, never a fractional split.** Rationale:

* KawPoW/PRL mining saturates VRAM and SMs; co-resident LLM inference would thrash both and tank each workload's rate — the opposite of "fluid".
* The inference stack **already models this** as a state, not a fraction: `current_mining_state ∈ {idle, mining, preemptible, paused}` (`inference_availability.py:13-25`). We map the GPU's real state onto it; no new protocol.
* It keeps v1's promise that **mining is primary**: AI only consumes the GPU when mining isn't.

### 4.1 The `gpu_arbiter` state machine (`gpu_arbiter.rs`)

One arbiter per physical GPU (v1 milestone: assume the single primary GPU; multi-GPU is a trivial fan-out later — see O3). States:

```
                 ┌────────────── user toggles AI-earn OFF ──────────────┐
                 ▼                                                       │
        ┌───────────────┐  mining work available    ┌───────────────┐   │
        │  MINING_ONLY  │ ─────────────────────────► │  MINING_ONLY  │   │
        │ (GPU mines;   │ ◄───────────────────────── │   (steady)    │   │
        │  AI paused)   │                            └───────────────┘   │
        └──────┬────────┘                                                │
               │ AI-earn ON  &&  mining lane idle / no GPU work          │
               ▼            (mining throttle/yield window)               │
        ┌───────────────┐  mining work returns (demand/throttle clears)  │
        │ AI_SERVING     │ ───────────────────────────────────────────► (back to MINING_ONLY)
        │ (GPU infers;   │
        │  miner paused) │
        └───────────────┘
```

* **`current_mining_state` we report to the queue:**
  * GPU mining right now → `mining` (worker advertises it is busy; the scheduler will not lease it heavy work).
  * GPU mining but the Miner is willing to yield (AI-earn ON, mining is the low-priority filler) → `preemptible`.
  * GPU idle / mining lane has no work → `idle` (eligible to lease an inference job).
  * AI-earn OFF → `paused` (worker advertises unavailable; or the sidecar simply isn't running).
* **Yield trigger (mine → infer):** the arbiter moves to `AI_SERVING` only when mining is genuinely idle/yieldable. The single-GPU v1 rule is **the simplest correct one: AI-earn runs the sidecar only while the GPU mining supervisor is NOT in a running/hashing state** (e.g. user mines CPU-only, or GPU mining is paused/failed-over). This needs **zero new mining-side signal** and cannot starve mining. (A richer "yield during stratum idle gaps" mode is deferred — O2.)
* **Resume trigger (infer → mine):** when GPU mining is (re)started, the arbiter sends the sidecar a stop, waits for the in-flight job to finish or the supervisor's stop-grace to elapse, then mining takes the GPU. In-flight inference jobs are **never killed mid-token** unless stop-grace expires — a clean handoff is part of "流畅".
* The server's `mining_throttle_signal` (`inference_scheduler.py:79`) is the **complementary** server→client hint (server says "AI demand is high, throttle mining"); the Miner may honor it to move from `MINING_ONLY`→`AI_SERVING` faster, but the **local rule (mining-primary) always wins** in v1 — we never throttle paid-substrate mining below the user's intent. (Honoring the signal aggressively is O2.)

### 4.2 Why not a split?

A token-budget / time-slice split is explicitly **out of scope for v1 of this lane**: it complicates the arbiter, hurts both rates, and the credit peg (Route 1) already assumes a **full-load** GPU to be fair (§5). Mutually-exclusive keeps the math and the UX honest.

---

## 5. Credit: earned, fair, surfaced (credit-only)

### 5.1 How credit is earned

Each `run_once()` cycle that completes a job results in the sidecar submitting an `InferenceCompletionRequest` (built inside the reused client/worker) to `/internal/inference/jobs/complete`. The server records `verified_score` as a `ShadowWorkRecord` under `lane=MAIN_POOL_AI`, `score_kind="inference_acu"`, `paid_acu=0` (`types.py:280-294`; `colocated_inference_worker.py:531-595`).

### 5.2 Fair pricing via Route 1 (the key fairness decision)

To make "AI earn" **fair against mining** (not a quiet downgrade), the completion carries the **Route 1 peg inputs** — `model_tier`, `gpu_class`, `runtime` (`types.py:256-258`). When present and resolvable, the server prices credit as:

```
credit = recounted_total_tokens × (M_rate(GPU) / Throughput(model, GPU))
```

so a **full-load GPU running inference for an hour earns ≈ its mining (PRL/RVN) credit/hour** (`route1_peg.py:343-356`, `inference_acu.py:120-153`). The Miner's job is only to **supply accurate peg inputs**:

* `gpu_class` ← from the device detector (the same vendor/model probe the mining lane uses).
* `runtime` ← `cuda` (NVIDIA) / `gguf` / `mlx` (Apple) — from the sidecar's actual execution runtime.
* `model_tier` ← the fine catalog tier of the model the sidecar served (recovered from the leased job).

If any peg input is missing/unresolvable the server **safely falls back** to the legacy token/latency ACU (`inference_acu.py:128-153`) — correctness is never at risk, only fairness-precision. The Miner should always pass all three so the peg applies.

### 5.3 Surfacing (one dashboard, one headline)

* AI-earn credit is shown as **one more source in the same credit total** the mining lanes feed — not a separate "AI wallet". The dashboard already aggregates per-lane credit from the read-only stats API (`/shadow/window`, `/shadow/balance`); `MAIN_POOL_AI` work appears there alongside `xmr_pool` / `main_pool_gpu_*`.
* The AI-earn **card** shows, for the local session: status (idle/serving/paused), jobs completed this session, and **last-cycle credit** (parsed from the sidecar status line, §6.2). All amounts are labeled **"credit / score"**; `paid_acu` is shown as `0` and never as spendable.
* No "claim", no "withdraw", no payout CTA anywhere in this lane (matches the `.a-badge-paid` "gated OFF" treatment in the brand system).

### 5.4 Credit-only enforcement (belt and suspenders)

1. **Client config** rejects reward/payout/direct-pool flags at construction (`inference_worker_client.py:87-92`).
2. **Submission scrubber** drops any `live_reward*`/`payout*` key before it leaves the device (`inference_worker_client.py:366-373`).
3. **No raw prompt/response** ever leaves the device or is persisted — `_validate_no_raw_prompt_response` raises on `prompt`/`response`/`messages`/… keys (`inference_worker_client.py:32-38,376-387`); the durable plane carries only `prompt_hash` + usage counts (`colocated_inference_worker.py:18-33`).
4. **Server ledger** keeps its own `*_forbidden` rejections and `paid_acu="0"` invariant; the Miner relies on, and does not weaken, these.

---

## 6. Minimal integration surface (so it lands later without core rework)

### 6.1 Rust side — files, structs, functions

**`alice-miner/gui/src/ai_earn.rs`** (pure, testable — the AI analogue of `miner.rs`):

```rust
pub const AI_EARN_ALLOWED: bool = false;        // v1: hidden. Milestone go-live flips this.
pub const AI_QUEUE_HOST: &str = "hk.aliceprotocol.org"; // or the AI queue host (server-side; see O1)

/// Everything needed to spawn the inference sidecar, fully validated. No key/seed.
pub struct AiEarnLaunchPlan { pub program: PathBuf, pub args: Vec<String> }

/// Build the validated sidecar launch plan for the active reward identity.
/// `reward_identity` is the user's Alice address (validated via the SAME
/// `derive_worker_id`/`validate_alice_address` the mining lane uses). The seed/
/// key NEVER appears in argv (assert in tests, like miner.rs does).
pub fn build_ai_earn_launch_plan(
    sidecar: PathBuf,
    reward_identity: &str,
    gpu_class: &str,
    runtime: &str,
) -> Result<AiEarnLaunchPlan, String>;

/// Parse one sidecar status JSON line → a snapshot (mirrors miner_supervisor's
/// parse_* helpers). Fail-soft: unknown lines return None.
pub fn parse_ai_status_line(line: &str) -> Option<AiEarnCycleSnapshot>;

pub struct AiEarnCycleSnapshot {
    pub status: String,        // "idle" | "submitted" | "disabled" | "rejected"
    pub jobs_completed: u64,
    pub last_cycle_credit: Option<String>, // "credit / score" string; never paid_acu
    pub reason_code: String,
}
```

**`alice-miner/gui/src/gpu_arbiter.rs`** — the `GpuArbiter` state machine (§4.1). Its only inputs are (a) the GPU mining supervisor's running state and (b) the AI-earn user toggle; its only outputs are "start sidecar" / "stop sidecar" and the `current_mining_state` to advertise. **Pure decision logic** (the I/O lives in the supervisors), so it is unit-testable in isolation.

**`alice-miner/gui/src/supervise/ai_worker_supervisor.rs`** — a near-copy of `miner_supervisor.rs`: spawn the sidecar via the shared `spawn_supervised`, pump stdout lines through `parse_ai_status_line`, expose `start(plan)` / `request_stop()` with the same SIGTERM→SIGKILL grace. Reuses `supervise/child.rs` and `supervise/mod.rs::{spawn_supervised, sanitize_log_line}` unchanged.

**`config` additions:** `ai_earn_enabled: bool` (runtime toggle, persisted in the Miner's own settings, default `false`); the AI queue base URL + the auth-token source path; **no key material**.

### 6.2 Python side — the sidecar

**`alice-miner/sidecar/ai_earn_sidecar.py`** (~120 lines, all heavy lifting delegated):

```python
# Pseudocode — the LOGIC is the reused client; this is glue.
cfg = InferenceWorkerClientConfig(
    queue_base_url=os.environ["ALICE_MINER_AI_QUEUE_URL"],
    auth_token_env="ALICE_ACP_INFERENCE_WORKER_AUTH_TOKEN",
    internal_client_enabled=True,         # opt-in: only set when the user turned AI-earn ON
    live_reward_enabled=False,            # credit-only (validate() enforces this)
    payout_executor_enabled=False,
    direct_pool_mode_enabled=False,
)
worker = DemandDrivenInferenceWorker(...)            # reused
client = InferenceWorkerClient(config=cfg, worker=worker)
while not stop_requested:                            # parent sends SIGTERM to stop
    hb = build_shadow_heartbeat(passport_id=ADDR, device_id=DEV,
                                supported_lanes=("general",),
                                current_mining_state=arbiter_state)  # idle/preemptible/...
    result = client.run_once(hb, free_memory_gb=probe_free_vram(),
                             queue_depth=0)
    print(json.dumps({                               # ONE status line per cycle → stdout
        "status": result.status, "reason_code": result.reason_code,
        "jobs_completed": jobs_done, "last_cycle_credit": last_credit_str,
    }), flush=True)
    sleep(poll_interval)
```

* `internal_client_enabled` defaults `False`, so an accidentally-launched sidecar is a **safe no-op** (`run_once` returns `status="disabled"`, `inference_worker_client.py:205-212`).
* The sidecar **never** receives the seed/private key — only the public address (as `passport_id`/argv) and the queue URL + token.
* Bundling: the sidecar ships as part of the AI-earn milestone's bundle; until then it is absent and the lane is hidden by `AI_EARN_ALLOWED=false`.

### 6.3 What the v1 mining core must expose (and it's tiny)

The only thing the mining core needs to surface for this lane to attach later is a **read-only "is GPU mining running" status** the `GpuArbiter` can poll — which the mining supervisor already exposes for the dashboard. **No mining hot-path code changes.** Everything else (the sidecar, the arbiter, the AI card) is additive. This is why the lane can be a **clean later milestone**.

### 6.4 Test seams (parity with miner.rs)

* `ai_earn.rs`: `build_ai_earn_launch_plan` fails closed on a non-Alice address; the seed/`priv` string never appears in argv; `parse_ai_status_line` round-trips a known JSON line. (Direct mirrors of `miner.rs` tests.)
* `gpu_arbiter.rs`: never enters `AI_SERVING` while GPU mining runs; resumes mining within stop-grace; honors the AI-earn OFF toggle from any state.
* Sidecar: a dry-run mode (the repo already has `inference_worker_dry_run.py`) drives `run_once` against a fake transport to prove the status-line contract without a real model/network.

---

## 7. Milestone slicing

* **M-AI-0 (this doc):** design locked, credit-only posture confirmed against the reused client's guardrails.
* **M-AI-1:** `gpu_arbiter.rs` + `ai_earn.rs` + supervisor, **sidecar in dry-run mode** (fake backend), behind `AI_EARN_ALLOWED=false`. Proves the loop, the mutual-exclusion switch, and the status-line UI with no real model.
* **M-AI-2:** wire the real local model backend (Track A inference) into the sidecar; verify Route 1 peg inputs flow and credit lands under `MAIN_POOL_AI` end-to-end on a real GPU box.
* **M-AI-3:** flip `AI_EARN_ALLOWED=true` for GPU builds; ship the card. (Server-side AI open-enrollment token must be live — O1.)

Each milestone is shippable independently; none blocks v1 mining.

---

## 8. Open questions for V

* **O1 — AI-lane open enrollment token.** Mining uses address-only open enrollment (no token). The inference client **requires a bearer token**. Do we (a) issue an AI-lane enrollment token to any valid Alice address on the same open basis (server hands it out, Miner stores it), or (b) gate AI-earn behind the same friend-relay enrollment as a named device? (a) keeps the one-click promise; (b) is tighter. Recommend (a) for the public Miner.
* **O2 — Yield aggressiveness.** v1 rule = AI runs **only while GPU mining is not running** (simplest, cannot starve mining). Do you want the richer mode where AI also fills **stratum idle gaps** during active GPU mining (honoring the server `mining_throttle_signal`)? More credit, more complexity. Default: keep simple for v1 of the lane.
* **O3 — Multi-GPU.** v1 milestone assumes one primary GPU. Multi-GPU (mine on some, infer on others simultaneously) is a clean fan-out (one arbiter + sidecar per GPU) but adds UI/scheduling. Defer to a later milestone unless you want it day one.
* **O4 — Sidecar vs PyO3.** Subprocess sidecar (matches the Wallet pattern, lowest risk) vs in-process PyO3. Recommend subprocess; revisit only if process overhead shows up.
