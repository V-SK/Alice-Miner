//! `core/engine` — the UI-agnostic engine: a `Command`/`Event` channel pair
//! driven by a worker `std::thread` that owns an `Arc<tokio::Runtime>`.
//!
//! Both front-ends (the eframe GUI and the headless CLI) drive THIS, so they
//! cannot drift (PLAN §2.2). The worker-thread ⇄ front-end bridge + the
//! runtime-`enter()`-before-spawn pattern are ported from
//! `alice-wallet/gui/src/app.rs` (the bridge ~L312, the `spawn_worker` loop
//! ~L1580 — note `rt.enter()` before `supervisor.start(...)` because spawning
//! the child spawns tokio I/O tasks).
//!
//! ── Credit-only by construction (PLAN §2.2, the brief) ──────────────────────
//! [`Snapshot`] has **NO `paid_acu` field** (and no payout / claim / settlement
//! field of any kind). A unit test asserts the serialized JSON never contains
//! a `paid_acu` key.

#![allow(dead_code)]

use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::Duration;

use alice_supervise::ProcState;
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;

use crate::detect::DeviceProfile;
use crate::endpoint::{Endpoint, EndpointPlan};
use crate::identity::{self, Identity};
use crate::lane::Lane;
use crate::lane::{gpu_prl, gpu_rvn, xmr};
use crate::supervise::LaneSupervisor;

/// How a [`Command::Identity`] establishes the reward identity.
#[derive(Debug, Clone)]
pub enum IdentitySpec {
    /// Generate a fresh 24-word identity (returns the mnemonic in the event).
    Create { label: Option<String>, password: String },
    /// Import from a 24-word mnemonic.
    ImportMnemonic { mnemonic: String, label: Option<String>, password: String },
    /// Import from a raw 32-byte seed (hex, optional `0x`).
    ImportSeedHex { seed_hex: String, label: Option<String>, password: String },
    /// Paste an address only (watch-only — no keystore, no unlock).
    Paste { address: String, label: Option<String> },
}

/// Commands the front-end sends to the engine. (Mirrors the brief's
/// `Detect | Identity(Create/Import/Paste) | Start{lane} | Stop`.)
#[derive(Debug, Clone)]
pub enum Command {
    /// Probe the device → emits [`Event::Device`].
    Detect,
    /// Establish the reward identity → emits [`Event::Identity`].
    Identity(IdentitySpec),
    /// Start mining `lane` to `address` (defaults to the active identity's
    /// address when `address` is `None`). When `dual` is set, the engine runs
    /// BOTH lanes together (CPU-XMR + GPU-RVN), each in its own crash-isolated
    /// supervisor, with `cores-2` XMR thread headroom (PLAN §5 M4 / D-dual). The
    /// caller must only request dual when ≥2 lanes are viable (the GUI gates this
    /// on [`crate::CapabilityProfile`]); the engine still validates and falls back
    /// to single-lane if a lane can't start.
    Start {
        lane: Lane,
        address: Option<String>,
        #[doc(hidden)]
        dual: bool,
    },
    /// Stop the running lane (SIGTERM→SIGKILL on the owned child).
    Stop,
    /// Ask the engine to emit a fresh [`Event::Snapshot`] now.
    Poll,
    /// Tear the worker thread down (used by the CLI on Ctrl-C after Stop).
    Shutdown,
}

/// The current engine lifecycle, distilled for the UI/CLI. (Maps the
/// supervisor's [`ProcState`] plus an idle "not started" state.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineState {
    /// No lane started yet (or fully stopped).
    Idle,
    /// Spawn requested; engine starting.
    Starting,
    /// Mining.
    Running,
    /// Graceful stop in progress.
    Stopping,
    /// The engine child exited unexpectedly / failed to start.
    Error,
}

impl From<ProcState> for EngineState {
    fn from(p: ProcState) -> Self {
        match p {
            ProcState::Stopped => EngineState::Idle,
            ProcState::Starting => EngineState::Starting,
            ProcState::Running => EngineState::Running,
            ProcState::Stopping => EngineState::Stopping,
            ProcState::Error => EngineState::Error,
        }
    }
}

/// A point-in-time, UI-safe mining snapshot. Cloneable, serialisable, free of
/// any handle / secret.
///
/// **CREDIT-ONLY INVARIANT:** there is intentionally **NO `paid_acu`** field (or
/// any payout / claim / settlement field). Any "earnings" are credit/score and
/// live elsewhere (Source-B, M5); the mining snapshot only ever carries activity
/// (hashrate + shares). A unit test asserts the JSON has no `paid_acu` key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    /// Engine lifecycle state.
    pub state: EngineState,
    /// The detected device (once `Detect` has run), for the dashboard header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<DeviceProfile>,
    /// The active mining lane (once a `Start` has been issued).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lane: Option<Lane>,
    /// Live hashrate in H/s (`None` until the first speed line).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashrate_hs: Option<f64>,
    /// Cumulative accepted shares this run.
    pub shares_accepted: u64,
    /// Cumulative rejected shares this run.
    pub shares_rejected: u64,
    /// The stratum endpoint the lane targets (e.g. `hk.aliceprotocol.org:3333`).
    /// This is the ACTIVE endpoint — after a Layer-B failover it reflects the
    /// rotated-to endpoint (PLAN §5 M4). Only ever the PUBLIC relay (or, under an
    /// operator override, whatever the operator declared); never the upstream
    /// pool / collection address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// The on-wire worker/rig id (derived from the PUBLIC address).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
    /// Seconds since the current run started.
    pub uptime_s: u64,
    /// How many times Layer B has rotated the endpoint cursor this run (0 = never
    /// failed over). The dashboard shows a "failed over" note when > 0.
    pub failovers: u64,
    /// Whether dual-mine is active (both lanes running). Drives the dashboard's
    /// two-row lane stack.
    pub dual: bool,
    /// Per-lane breakdown (one entry per running supervisor). In single-lane mode
    /// this has one entry; in dual-mine it has two (CPU-XMR + GPU-RVN). The
    /// top-level `state`/`hashrate_hs`/shares mirror the PRIMARY lane for the
    /// existing single-lane UI; the dashboard reads `lanes` for the breakdown.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lanes: Vec<LaneSnapshot>,
    /// Last sanitised engine output line (an at-a-glance hint).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_line: Option<String>,
    /// Short, sanitised reason for an `Error`/`Stopping` state, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// One lane's live activity within a (possibly dual) run — the dashboard's
/// per-lane row. Credit-only (activity figures only); no payout field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LaneSnapshot {
    /// Which lane this row is.
    pub lane: Lane,
    /// This lane's lifecycle state.
    pub state: EngineState,
    /// This lane's live hashrate in H/s (`None` until the first speed line).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashrate_hs: Option<f64>,
    /// This lane's cumulative accepted shares.
    pub shares_accepted: u64,
    /// This lane's cumulative rejected shares.
    pub shares_rejected: u64,
    /// This lane's ACTIVE (post-failover) endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// This lane's Layer-B failover count this run.
    pub failovers: u64,
}

impl Snapshot {
    fn idle() -> Self {
        Self {
            state: EngineState::Idle,
            device: None,
            lane: None,
            hashrate_hs: None,
            shares_accepted: 0,
            shares_rejected: 0,
            endpoint: None,
            worker_id: None,
            uptime_s: 0,
            failovers: 0,
            dual: false,
            lanes: Vec::new(),
            last_line: None,
            message: None,
        }
    }
}

/// Events the engine emits back to the front-end.
#[derive(Debug, Clone)]
pub enum Event {
    /// Result of `Detect`.
    Device(DeviceProfile),
    /// Result of `Identity(..)`. On `Create`, `mnemonic` carries the freshly
    /// generated 24-word phrase for the forced-backup step (the front-end must
    /// surface it then drop it); for every other variant it is `None`.
    Identity { identity: Identity, mnemonic: Option<String> },
    /// A live mining snapshot (sent on Start, on Poll, and on Stop).
    Snapshot(Snapshot),
    /// A recoverable error string (bad address, spawn failure, …). The engine
    /// keeps running and awaits the next command.
    Error(String),
}

/// The front-end handle: send [`Command`]s, receive [`Event`]s. Dropping it
/// closes the command channel, which the worker treats as a shutdown.
pub struct EngineHandle {
    cmd_tx: Sender<Command>,
    evt_rx: Receiver<Event>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl EngineHandle {
    /// Spawn the engine worker thread (owns its own `tokio::Runtime`).
    pub fn spawn() -> Result<Self, String> {
        let rt = Runtime::new().map_err(|e| format!("failed to build tokio runtime: {e}"))?;
        let (cmd_tx, cmd_rx) = channel::<Command>();
        let (evt_tx, evt_rx) = channel::<Event>();
        let join = std::thread::Builder::new()
            .name("alice-miner-engine".into())
            .spawn(move || worker_loop(Arc::new(rt), cmd_rx, evt_tx))
            .map_err(|e| format!("failed to spawn engine thread: {e}"))?;
        Ok(Self {
            cmd_tx,
            evt_rx,
            join: Some(join),
        })
    }

    /// Send a command to the engine.
    pub fn send(&self, cmd: Command) -> Result<(), String> {
        self.cmd_tx
            .send(cmd)
            .map_err(|_| "engine worker is not running".to_string())
    }

    /// Try to receive the next event (non-blocking).
    pub fn try_recv(&self) -> Option<Event> {
        self.evt_rx.try_recv().ok()
    }

    /// Block until the next event (or the worker exits).
    pub fn recv(&self) -> Option<Event> {
        self.evt_rx.recv().ok()
    }

    /// Block up to `timeout` for the next event.
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Event, RecvTimeoutError> {
        self.evt_rx.recv_timeout(timeout)
    }

    /// Ask the worker to shut down and join it (best-effort).
    pub fn shutdown(mut self) {
        let _ = self.cmd_tx.send(Command::Shutdown);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for EngineHandle {
    fn drop(&mut self) {
        // Dropping the command sender closes the channel; the worker loop sees
        // `recv()` error out and tears down (stopping any child via
        // `kill_on_drop`). Join if we still hold the handle.
        let _ = self.cmd_tx.send(Command::Shutdown);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// The worker loop. Owns the runtime, the active supervisor, and the latest
/// device/identity so each `Snapshot` is fully populated. (Structure ported
/// from the Wallet's `spawn_worker`: enter the runtime before any
/// child-spawning supervisor call.)
fn worker_loop(rt: Arc<Runtime>, cmd_rx: Receiver<Command>, evt_tx: Sender<Event>) {
    let mut device: Option<DeviceProfile> = None;
    // The active identity address (the ONLY thing the mining path needs).
    let mut active_address: Option<String> = None;
    // The active run: the engine owns N `LaneSupervisor`s (M4) — one in
    // single-lane mode, two in dual-mine (CPU-XMR + GPU-RVN), each crash-isolated
    // in its own process group. Empty when idle.
    let mut run = RunSet::default();
    let mut active_worker_id: Option<String> = None;

    loop {
        // Poll for a command with a short timeout so we can push periodic
        // snapshots while a lane is running (the GUI/CLI also `Poll` explicitly,
        // but this keeps the stream live without a busy loop).
        let cmd = match cmd_rx.recv_timeout(Duration::from_millis(500)) {
            Ok(c) => Some(c),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => break, // front-end dropped
        };

        match cmd {
            Some(Command::Detect) => {
                let p = DeviceProfile::detect();
                device = Some(p.clone());
                let _ = evt_tx.send(Event::Device(p));
            }
            Some(Command::Identity(spec)) => {
                match run_identity(spec) {
                    Ok((identity, mnemonic)) => {
                        active_address = Some(identity.address.clone());
                        let _ = evt_tx.send(Event::Identity { identity, mnemonic });
                    }
                    Err(e) => {
                        let _ = evt_tx.send(Event::Error(e));
                    }
                }
            }
            Some(Command::Start { lane, address, dual }) => {
                // Resolve the reward address: the explicit one, else the active
                // identity's, else the on-disk pointer's.
                let addr = address
                    .or_else(|| active_address.clone())
                    .or_else(|| identity::load_pointer().map(|p| p.address));
                let Some(addr) = addr else {
                    let _ = evt_tx.send(Event::Error(
                        "no reward address: create/import/paste an identity first".into(),
                    ));
                    continue;
                };
                if run.is_active() {
                    let _ = evt_tx
                        .send(Event::Error("a lane is already running; Stop it first".into()));
                    continue;
                }

                match start_run(&rt, lane, dual, &addr) {
                    Ok((new_run, worker_id)) => {
                        run = new_run;
                        active_address = Some(addr);
                        active_worker_id = Some(worker_id);
                        let snap = build_snapshot(&device, &run, &active_worker_id);
                        let _ = evt_tx.send(Event::Snapshot(snap));
                    }
                    Err(e) => {
                        let _ = evt_tx.send(Event::Error(e));
                    }
                }
            }
            Some(Command::Stop) => {
                run.request_stop_all();
                let snap = build_snapshot(&device, &run, &active_worker_id);
                let _ = evt_tx.send(Event::Snapshot(snap));
            }
            Some(Command::Poll) | None => {
                // Periodic / explicit snapshot. Only emit while we have a run
                // (otherwise the front-end already knows we're idle).
                if !run.is_empty() {
                    let snap = build_snapshot(&device, &run, &active_worker_id);
                    let _ = evt_tx.send(Event::Snapshot(snap));
                }
            }
            Some(Command::Shutdown) => break,
        }
    }

    // Teardown: stop every child and let the runtime drop (kill_on_drop is the
    // backstop). Give the graceful stop a moment to complete.
    if run.is_active() {
        run.request_stop_all();
        // Let each supervision loop run its SIGTERM→SIGKILL on its owned child.
        std::thread::sleep(Duration::from_millis(700));
    }
    drop(run);
    // Dropping `rt` (the last Arc) shuts the runtime down, dropping any child
    // task and the `OwnedChild` (kill_on_drop ensures no orphan).
}

/// The set of lane supervisors the engine drives concurrently (PLAN §2.2: "the
/// engine owns N of them"). One in single-lane mode; two in dual-mine (CPU-XMR +
/// GPU-RVN), each crash-isolated in its own process group.
#[derive(Default)]
struct RunSet {
    /// The running supervisors, primary first (the primary drives the top-level
    /// Snapshot fields for the existing single-lane UI).
    supervisors: Vec<LaneSupervisor>,
    /// Whether this run is dual-mine (both lanes).
    dual: bool,
}

impl RunSet {
    fn is_empty(&self) -> bool {
        self.supervisors.is_empty()
    }

    /// Whether ANY supervisor in the set is still active.
    fn is_active(&self) -> bool {
        self.supervisors.iter().any(|s| s.is_active())
    }

    /// The primary supervisor (drives the top-level Snapshot).
    fn primary(&self) -> Option<&LaneSupervisor> {
        self.supervisors.first()
    }

    /// Request a graceful stop on every supervisor (each tears down its OWN child
    /// independently — crash-isolated).
    fn request_stop_all(&self) {
        for s in &self.supervisors {
            s.request_stop();
        }
    }
}

/// Establish the identity for an [`IdentitySpec`], zeroizing passwords as we go.
fn run_identity(spec: IdentitySpec) -> Result<(Identity, Option<String>), String> {
    use zeroize::Zeroize;
    match spec {
        IdentitySpec::Create { label, mut password } => {
            let (identity, mnemonic) = identity::create(label, &password)?;
            password.zeroize();
            // Hand the mnemonic out for the backup step (the front-end shows then
            // drops it); convert the Zeroizing<String> into a plain String here.
            Ok((identity, Some(mnemonic.to_string())))
        }
        IdentitySpec::ImportMnemonic { mut mnemonic, label, mut password } => {
            let identity = identity::import_mnemonic(&mnemonic, label, &password);
            mnemonic.zeroize();
            password.zeroize();
            Ok((identity?, None))
        }
        IdentitySpec::ImportSeedHex { mut seed_hex, label, mut password } => {
            let identity = identity::import_seed_hex(&seed_hex, label, &password);
            seed_hex.zeroize();
            password.zeroize();
            Ok((identity?, None))
        }
        IdentitySpec::Paste { address, label } => {
            let identity = identity::paste(&address, label)?;
            Ok((identity, None))
        }
    }
}

/// In dual-mine mode, leave this many cores free for the GPU lane's host
/// overhead (driver / DAG feeder threads): XMR runs at `cores - DUAL_XMR_HEADROOM`
/// (PLAN §5 M4 / §6 D-dual). Single-lane mode stays "拉满" (all cores).
const DUAL_XMR_HEADROOM: usize = 2;

/// The XMR thread count under dual-mine: `cores - 2` (GPU host headroom), floored
/// at 1 (a 1-2 core box still runs XMR on at least one thread). Single-lane mode
/// does NOT call this (it stays "拉满" / all cores). Pure + testable.
fn dual_xmr_threads(cores: usize) -> usize {
    cores.saturating_sub(DUAL_XMR_HEADROOM).max(1)
}

/// Start a run for `lane` (or BOTH lanes when `dual`), to `address`. Returns the
/// populated [`RunSet`] + the derived worker id. The reward `address` is the
/// user's PUBLIC Alice address — no secret crosses this boundary.
///
/// **Dual-mine** = a CPU-XMR supervisor (with `cores-2` thread headroom) AND a
/// GPU-RVN supervisor, each crash-isolated in its own process group. If a lane
/// fails to start (e.g. no GPU binary on this box), the whole start errors with
/// that lane's reason rather than silently running one lane (the GUI gates dual
/// on viability, so this is a defensive guard, not the normal path).
fn start_run(
    rt: &Arc<Runtime>,
    lane: Lane,
    dual: bool,
    address: &str,
) -> Result<(RunSet, String), String> {
    let worker_id = xmr::derive_worker_id(address)?; // one worker-id fn for both lanes
    // Enter the runtime ONCE for all the start()s — they spawn tokio child-I/O +
    // watchdog tasks (the Wallet pattern: `let _guard = rt.enter();`).
    let _guard = rt.enter();

    if dual {
        // Both lanes together. XMR gets `cores-2` headroom; RVN runs full.
        let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
        let xmr_threads = dual_xmr_threads(cores);
        let xmr_sup = start_one_lane(Lane::Xmr, address, Some(xmr_threads))?;
        let rvn_sup = match start_one_lane(Lane::GpuRvn, address, None) {
            Ok(s) => s,
            Err(e) => {
                // The XMR lane already started; tear it back down so we don't leave
                // a half-started dual run, then surface the GPU reason.
                xmr_sup.request_stop();
                return Err(format!("dual-mine: GPU lane could not start ({e})"));
            }
        };
        Ok((
            RunSet {
                supervisors: vec![xmr_sup, rvn_sup],
                dual: true,
            },
            worker_id,
        ))
    } else {
        let sup = start_one_lane(lane, address, None)?;
        Ok((
            RunSet {
                supervisors: vec![sup],
                dual: false,
            },
            worker_id,
        ))
    }
}

/// Build the per-lane [`EndpointPlan`] + Layer-A multi-endpoint launch plan,
/// create a [`LaneSupervisor`] bound to that plan, and start it with a rebuild
/// closure (so the supervisor's Layer-B watchdog can rotate endpoints). Must be
/// called inside a runtime context (the caller holds `rt.enter()`).
fn start_one_lane(
    lane: Lane,
    address: &str,
    threads_override: Option<usize>,
) -> Result<LaneSupervisor, String> {
    let plan = EndpointPlan::for_lane(lane);
    let address = address.to_string();

    // The engine-supplied rebuild closure: given an ordered endpoint list (the
    // EndpointPlan rotated to a new cursor), re-derive `(program, args)` for THIS
    // lane (Layer-A multi-endpoint argv). The supervisor's watchdog calls this on
    // a Layer-B failover. Resolves the binary each time so a freshly-installed
    // engine is picked up; the honesty invariant holds (relay-only endpoints).
    let addr_for_rebuild = address.clone();
    let rebuild: crate::supervise::RebuildFn = match lane {
        Lane::Xmr => Arc::new(move |eps: &[Endpoint]| {
            let program =
                crate::binaries::resolve_miner_binary(crate::binaries::MinerKind::CpuXmr)?;
            let p = xmr::build_miner_launch_plan_with_endpoints(
                program,
                &addr_for_rebuild,
                eps,
                threads_override,
            )?;
            Ok((p.program, p.args))
        }),
        Lane::GpuRvn => Arc::new(move |eps: &[Endpoint]| {
            let program =
                crate::binaries::resolve_miner_binary(crate::binaries::MinerKind::GpuRvn)?;
            let p = if is_trex_binary(&program) {
                // T-Rex (override path) takes a single endpoint; use the first.
                gpu_rvn::build_trex_launch_plan(program, &addr_for_rebuild)?
            } else {
                gpu_rvn::build_kawpowminer_launch_plan_with_endpoints(
                    program,
                    &addr_for_rebuild,
                    eps,
                )?
            };
            Ok((p.program, p.args))
        }),
        Lane::GpuPrl => Arc::new(move |eps: &[Endpoint]| {
            let program =
                crate::binaries::resolve_miner_binary(crate::binaries::MinerKind::GpuPrl)?;
            let Some(active) = eps.first() else {
                return Err("gpu-prl launch plan needs at least one endpoint".into());
            };
            let region = format!("{}:{}", active.host, active.port);
            // T2 skeleton: no-PoP SMOKE — placeholder password + a per-lane log
            // file. T4 replaces this with the region-bound PoP token (fetch →
            // sign → assemble) and the supervisor-owned log path; under the live
            // relay's REQUIRE_POP=1 the placeholder is rejected (no earning).
            let log_path = std::env::temp_dir().join("alice-gpu-prl.log");
            let p = gpu_prl::build_srbminer_pearl_launch_plan(
                program,
                &addr_for_rebuild,
                &region,
                "x",
                &log_path,
            )?;
            Ok((p.program, p.args))
        }),
    };

    // Build the initial launch plan (Layer A: all endpoints, primary first).
    let (program, args) = rebuild(&plan.ordered_from_cursor())?;

    let sup = LaneSupervisor::with_endpoints(lane, plan);
    sup.start(program, args, rebuild)?;
    Ok(sup)
}

/// Heuristic: does this resolved GPU-miner path look like T-Rex (so the engine
/// builds the T-Rex `-a kawpow -o -u -p -w` arg shape) rather than the bundled
/// kawpowminer (the ethminer-style `-P` URL)? Only reachable via the
/// `ALICE_MINER_GPU_BIN` override (the bundled binary is always kawpowminer).
fn is_trex_binary(program: &std::path::Path) -> bool {
    program
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| {
            let n = n.to_ascii_lowercase();
            n.contains("t-rex") || n.contains("trex")
        })
        .unwrap_or(false)
}

/// Assemble a [`Snapshot`] from the current engine state + the run set's live
/// stats. The top-level fields mirror the PRIMARY lane (so the existing
/// single-lane UI is unchanged); `lanes` carries the per-lane breakdown for the
/// dual-mine two-row stack. Never carries a `paid_acu` (credit-only — see
/// [`Snapshot`]).
fn build_snapshot(
    device: &Option<DeviceProfile>,
    run: &RunSet,
    worker_id: &Option<String>,
) -> Snapshot {
    let mut snap = Snapshot::idle();
    snap.device = device.clone();
    snap.worker_id = worker_id.clone();
    snap.dual = run.dual;

    // Per-lane breakdown (every supervisor in the set).
    for s in &run.supervisors {
        let st = s.stats();
        snap.lanes.push(LaneSnapshot {
            lane: st.lane,
            state: st.state.into(),
            hashrate_hs: st.hashrate_hs,
            shares_accepted: st.accepted,
            shares_rejected: st.rejected,
            endpoint: st.endpoint.clone(),
            failovers: st.failovers,
        });
    }

    // Top-level mirror = the primary lane (single-lane UI compatibility). For the
    // top-level lifecycle state in dual mode, prefer "Running" if ANY lane runs,
    // else the primary's state (so the hero reads "mining" while either lane is up).
    if let Some(p) = run.primary() {
        let st = p.stats();
        snap.lane = Some(st.lane);
        snap.hashrate_hs = st.hashrate_hs;
        snap.shares_accepted = st.accepted;
        snap.shares_rejected = st.rejected;
        snap.endpoint = st.endpoint.clone();
        snap.uptime_s = st.uptime_s;
        snap.failovers = st.failovers;
        snap.message = st.message.clone();
        if !st.last_line.is_empty() {
            snap.last_line = Some(st.last_line);
        }
        snap.state = if run.dual && run.is_active() {
            EngineState::Running
        } else {
            st.state.into()
        };
        // In dual mode, the top-level hashrate is the SUM of both lanes' rates
        // (the GUI's combined readout); shares too. Endpoint stays the primary's.
        if run.dual {
            let (mut hr, mut acc, mut rej, mut fo) = (None::<f64>, 0u64, 0u64, 0u64);
            for s in &run.supervisors {
                let st = s.stats();
                if let Some(h) = st.hashrate_hs {
                    hr = Some(hr.unwrap_or(0.0) + h);
                }
                acc += st.accepted;
                rej += st.rejected;
                fo += st.failovers;
            }
            snap.hashrate_hs = hr;
            snap.shares_accepted = acc;
            snap.shares_rejected = rej;
            snap.failovers = fo;
        }
    }
    snap
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CREDIT-ONLY: the serialized snapshot must never carry a `paid_acu` (or
    /// any payout/claim/settlement) field — by construction (PLAN §2.2).
    #[test]
    fn snapshot_has_no_paid_acu_field() {
        // A fully-populated snapshot (to catch any optional field too), incl. the
        // M4 dual-mine per-lane breakdown.
        let snap = Snapshot {
            state: EngineState::Running,
            device: Some(DeviceProfile::detect()),
            lane: Some(Lane::Xmr),
            hashrate_hs: Some(1234.5),
            shares_accepted: 7,
            shares_rejected: 1,
            endpoint: Some("hk.aliceprotocol.org:3333".into()),
            worker_id: Some("worker".into()),
            uptime_s: 42,
            failovers: 1,
            dual: true,
            lanes: vec![
                LaneSnapshot {
                    lane: Lane::Xmr,
                    state: EngineState::Running,
                    hashrate_hs: Some(1234.5),
                    shares_accepted: 7,
                    shares_rejected: 1,
                    endpoint: Some("hk.aliceprotocol.org:3333".into()),
                    failovers: 1,
                },
                LaneSnapshot {
                    lane: Lane::GpuRvn,
                    state: EngineState::Running,
                    hashrate_hs: Some(25_000_000.0),
                    shares_accepted: 3,
                    shares_rejected: 0,
                    endpoint: Some("hk.aliceprotocol.org:8888".into()),
                    failovers: 0,
                },
            ],
            last_line: Some("net accepted (7/1)".into()),
            message: None,
        };
        let json = serde_json::to_string(&snap).expect("serialize");
        assert!(
            !json.contains("paid_acu"),
            "Snapshot JSON must not contain a paid_acu field: {json}"
        );
        // Also assert none of the other forbidden payout fields leaked in.
        for forbidden in ["paid", "payout", "claim", "settle", "settlement", "mint"] {
            assert!(
                !json.contains(forbidden),
                "Snapshot JSON must not contain `{forbidden}`: {json}"
            );
        }
    }

    #[test]
    fn engine_state_maps_from_proc_state() {
        assert_eq!(EngineState::from(ProcState::Stopped), EngineState::Idle);
        assert_eq!(EngineState::from(ProcState::Starting), EngineState::Starting);
        assert_eq!(EngineState::from(ProcState::Running), EngineState::Running);
        assert_eq!(EngineState::from(ProcState::Stopping), EngineState::Stopping);
        assert_eq!(EngineState::from(ProcState::Error), EngineState::Error);
    }

    #[test]
    fn engine_spawns_and_detects() {
        let engine = EngineHandle::spawn().expect("spawn engine");
        engine.send(Command::Detect).expect("send detect");
        let evt = engine
            .recv_timeout(Duration::from_secs(5))
            .expect("device event");
        match evt {
            Event::Device(p) => {
                assert!(p.logical_cores >= 1);
                assert!(!p.display.is_empty());
            }
            other => panic!("expected Device, got {other:?}"),
        }
        engine.shutdown();
    }

    #[test]
    fn start_without_identity_errors() {
        let engine = EngineHandle::spawn().expect("spawn");
        // No identity, no pointer (the real ~/.alice may or may not exist; point
        // the identity dir at an empty temp dir to be deterministic).
        let empty = std::env::temp_dir().join(format!(
            "alice-miner-empty-id-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&empty).unwrap();
        std::env::set_var("ALICE_IDENTITY_DIR", &empty);

        engine
            .send(Command::Start { lane: Lane::Xmr, address: None, dual: false })
            .expect("send start");
        let evt = engine
            .recv_timeout(Duration::from_secs(5))
            .expect("error event");
        match evt {
            Event::Error(e) => assert!(e.contains("no reward address")),
            other => panic!("expected Error, got {other:?}"),
        }

        std::env::remove_var("ALICE_IDENTITY_DIR");
        let _ = std::fs::remove_dir_all(&empty);
        engine.shutdown();
    }

    /// DUAL gating math (the M4 gate): under dual-mine the XMR lane gets `cores-2`
    /// headroom, floored at 1; single-lane stays full power (not via this fn).
    #[test]
    fn dual_xmr_threads_applies_cores_minus_two_floored_at_one() {
        assert_eq!(dual_xmr_threads(16), 14);
        assert_eq!(dual_xmr_threads(12), 10);
        assert_eq!(dual_xmr_threads(4), 2);
        assert_eq!(dual_xmr_threads(3), 1);
        // A 1- or 2-core box still runs XMR on at least one thread.
        assert_eq!(dual_xmr_threads(2), 1);
        assert_eq!(dual_xmr_threads(1), 1);
    }

    /// DUAL-MINE end-to-end (engine-level): with BOTH lane binaries overridden to
    /// a long-lived stand-in (so no real GPU is needed), a `Start { dual: true }`
    /// brings up TWO crash-isolated supervisors; the snapshot reports `dual`, two
    /// per-lane rows (CPU-XMR + GPU-RVN), and the SUMMED hashrate. Then a clean
    /// Stop tears BOTH down. (The per-supervisor crash-isolation + failover gates
    /// are proven in `supervise::tests`; this proves the engine wires N of them.)
    #[cfg(unix)]
    #[test]
    fn dual_mine_runs_two_lanes_then_stops() {
        let _g = crate::MINER_BIN_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // A stand-in "miner" that ignores its args and emits one accepted-share +
        // speed line per lane, then idles — so BOTH lanes reach Running with stats.
        let stub = std::env::temp_dir().join(format!("alice-dual-stub-{}.sh", std::process::id()));
        std::fs::write(
            &stub,
            "#!/bin/sh\n\
             echo 'net      accepted (5/0) diff 100 (10 ms)'\n\
             echo 'miner    speed 10s/60s/15m 100.0 90.0 n/a H/s'\n\
             echo 'm kawpowminer Speed 20.00 Mh/s gpu0 [A5+0:R0+0:F0]'\n\
             sleep 30\n",
        )
        .unwrap();
        let mut perm = std::fs::metadata(&stub).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perm.set_mode(0o755);
        std::fs::set_permissions(&stub, perm).unwrap();

        // Point BOTH lane resolvers at the stub. The stub is unpinned, so this
        // test must opt into the allow-unverified gate (the same explicit knob a
        // user supplying their own engine would set) — proving the override path
        // still works under the new SHA-verify policy.
        std::env::set_var("ALICE_MINER_XMR_BIN", &stub);
        std::env::set_var("ALICE_MINER_GPU_BIN", &stub);
        std::env::set_var(crate::binaries::ALLOW_UNVERIFIED_ENV, "1");

        // A watch-only identity so no keystore is needed (a real SS58-300 address
        // derived through the shared keystore — mining only needs the address).
        let address = alice_crypto::create_wallet_payload(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "dual-test",
        )
        .unwrap()
        .address;

        let engine = EngineHandle::spawn().expect("spawn");
        engine
            .send(Command::Start {
                lane: Lane::Xmr,
                address: Some(address),
                dual: true,
            })
            .expect("send dual start");

        // Drain snapshots until BOTH lanes are Running (or a timeout).
        let mut saw_dual_both = false;
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        while std::time::Instant::now() < deadline {
            // Nudge a fresh snapshot.
            let _ = engine.send(Command::Poll);
            if let Ok(Event::Snapshot(s)) = engine.recv_timeout(Duration::from_millis(300)) {
                {
                    // Wait until BOTH lanes are running AND have parsed their
                    // hashrate (the log pump is async, so a fresh all-Running
                    // snapshot may not have the speed line parsed yet).
                    let xmr = s.lanes.iter().find(|l| l.lane == Lane::Xmr);
                    let rvn = s.lanes.iter().find(|l| l.lane == Lane::GpuRvn);
                    let ready = s.dual
                        && s.lanes.len() == 2
                        && s.lanes.iter().all(|l| l.state == EngineState::Running)
                        && xmr.and_then(|l| l.hashrate_hs).is_some()
                        && rvn.and_then(|l| l.hashrate_hs).is_some();
                    if ready {
                        let xmr = xmr.unwrap();
                        let rvn = rvn.unwrap();
                        assert_eq!(xmr.hashrate_hs, Some(100.0));
                        assert_eq!(rvn.hashrate_hs, Some(20_000_000.0));
                        // Top-level summed hashrate = xmr + rvn.
                        assert_eq!(s.hashrate_hs, Some(100.0 + 20_000_000.0));
                        // Each lane targets its OWN relay port (honesty: relay only).
                        assert_eq!(xmr.endpoint.as_deref(), Some("hk.aliceprotocol.org:3333"));
                        assert_eq!(rvn.endpoint.as_deref(), Some("hk.aliceprotocol.org:8888"));
                        saw_dual_both = true;
                        break;
                    }
                }
            }
        }
        assert!(saw_dual_both, "both lanes should reach Running under dual-mine");

        // Clean stop → both lanes torn down.
        engine.send(Command::Stop).expect("stop");
        let mut both_down = false;
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        while std::time::Instant::now() < deadline {
            let _ = engine.send(Command::Poll);
            if let Ok(Event::Snapshot(s)) = engine.recv_timeout(Duration::from_millis(300)) {
                if s.lanes.iter().all(|l| l.state == EngineState::Idle || l.state == EngineState::Error) {
                    both_down = true;
                    break;
                }
            }
        }
        assert!(both_down, "both lanes should tear down on Stop");

        engine.shutdown();
        std::env::remove_var("ALICE_MINER_XMR_BIN");
        std::env::remove_var("ALICE_MINER_GPU_BIN");
        std::env::remove_var(crate::binaries::ALLOW_UNVERIFIED_ENV);
        let _ = std::fs::remove_file(&stub);
    }
}
