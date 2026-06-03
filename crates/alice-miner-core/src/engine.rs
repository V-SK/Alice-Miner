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
use crate::identity::{self, Identity};
use crate::lane::xmr;
use crate::lane::Lane;
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
    /// address when `address` is `None`).
    Start { lane: Lane, address: Option<String> },
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// The on-wire worker/rig id (derived from the PUBLIC address).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
    /// Seconds since the current run started.
    pub uptime_s: u64,
    /// Last sanitised engine output line (an at-a-glance hint).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_line: Option<String>,
    /// Short, sanitised reason for an `Error`/`Stopping` state, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
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
    // The active lane supervisor (M1 owns at most one; the engine generalizes to
    // N in M4). Created lazily on the first Start.
    let mut supervisor: Option<LaneSupervisor> = None;
    let mut active_lane: Option<Lane> = None;
    let mut active_endpoint: Option<String> = None;
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
            Some(Command::Start { lane, address }) => {
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

                match start_lane(&rt, lane, &addr, &mut supervisor) {
                    Ok((endpoint, worker_id)) => {
                        active_address = Some(addr);
                        active_lane = Some(lane);
                        active_endpoint = Some(endpoint);
                        active_worker_id = Some(worker_id);
                        let snap = build_snapshot(
                            &device,
                            active_lane,
                            &active_endpoint,
                            &active_worker_id,
                            supervisor.as_ref(),
                        );
                        let _ = evt_tx.send(Event::Snapshot(snap));
                    }
                    Err(e) => {
                        let _ = evt_tx.send(Event::Error(e));
                    }
                }
            }
            Some(Command::Stop) => {
                if let Some(s) = supervisor.as_ref() {
                    s.request_stop();
                }
                let snap = build_snapshot(
                    &device,
                    active_lane,
                    &active_endpoint,
                    &active_worker_id,
                    supervisor.as_ref(),
                );
                let _ = evt_tx.send(Event::Snapshot(snap));
            }
            Some(Command::Poll) | None => {
                // Periodic / explicit snapshot. Only emit while we have a lane
                // (otherwise the front-end already knows we're idle).
                if supervisor.is_some() {
                    let snap = build_snapshot(
                        &device,
                        active_lane,
                        &active_endpoint,
                        &active_worker_id,
                        supervisor.as_ref(),
                    );
                    let _ = evt_tx.send(Event::Snapshot(snap));
                }
            }
            Some(Command::Shutdown) => break,
        }
    }

    // Teardown: stop the child and let the runtime drop (kill_on_drop is the
    // backstop). Give the graceful stop a moment to complete.
    if let Some(s) = supervisor.as_ref() {
        s.request_stop();
        // Let the supervision loop run its SIGTERM→SIGKILL on the owned child.
        std::thread::sleep(Duration::from_millis(700));
    }
    drop(supervisor);
    // Dropping `rt` (the last Arc) shuts the runtime down, dropping any child
    // task and the `OwnedChild` (kill_on_drop ensures no orphan).
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

/// Build the launch plan for `lane` to `address`, create-or-reuse the
/// supervisor, and start it inside the runtime context. Returns
/// `(endpoint, worker_id)` for the snapshot. The reward `address` is the user's
/// PUBLIC Alice address — no secret crosses this boundary.
fn start_lane(
    rt: &Arc<Runtime>,
    lane: Lane,
    address: &str,
    supervisor: &mut Option<LaneSupervisor>,
) -> Result<(String, String), String> {
    let (plan, endpoint, worker_id) = match lane {
        Lane::Xmr => {
            let program = crate::binaries::resolve_miner_binary(crate::binaries::MinerKind::CpuXmr)?;
            let plan = xmr::build_miner_launch_plan(program, address)?;
            let endpoint = format!("{}:{}", xmr::ALICE_POOL_HOST, xmr::ALICE_POOL_PORT);
            let worker_id = xmr::derive_worker_id(address)?;
            (plan, endpoint, worker_id)
        }
        Lane::GpuRvn => {
            return Err("GPU-RVN lane is not available in this build (M3)".into());
        }
    };

    // Reuse a stopped supervisor for the same lane, else make a fresh one.
    let sup = match supervisor.as_ref() {
        Some(s) if s.lane() == lane && !s.is_active() => s.clone(),
        Some(s) if s.is_active() => return Err("a lane is already running; Stop it first".into()),
        _ => {
            let s = LaneSupervisor::new(lane);
            *supervisor = Some(s.clone());
            s
        }
    };
    // If we reused an existing (stopped, same-lane) supervisor, ensure it's the
    // one stored.
    if supervisor.as_ref().map(|s| s.lane()) != Some(lane) {
        *supervisor = Some(sup.clone());
    }

    // Enter the runtime before start() — it spawns tokio child-I/O tasks (the
    // exact Wallet pattern: `let _guard = rt.enter();` before `sup.start(...)`).
    let _guard = rt.enter();
    sup.start(plan)?;
    Ok((endpoint, worker_id))
}

/// Assemble a [`Snapshot`] from the current engine state + the supervisor's
/// live stats. Never carries a `paid_acu` (credit-only — see [`Snapshot`]).
fn build_snapshot(
    device: &Option<DeviceProfile>,
    lane: Option<Lane>,
    endpoint: &Option<String>,
    worker_id: &Option<String>,
    supervisor: Option<&LaneSupervisor>,
) -> Snapshot {
    let mut snap = Snapshot::idle();
    snap.device = device.clone();
    snap.lane = lane;
    snap.endpoint = endpoint.clone();
    snap.worker_id = worker_id.clone();

    if let Some(s) = supervisor {
        let st = s.stats();
        snap.state = st.state.into();
        snap.hashrate_hs = st.hashrate_hs;
        snap.shares_accepted = st.accepted;
        snap.shares_rejected = st.rejected;
        snap.uptime_s = st.uptime_s;
        snap.message = st.message;
        if !st.last_line.is_empty() {
            snap.last_line = Some(st.last_line);
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
        // A fully-populated snapshot (to catch any optional field too).
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
            .send(Command::Start { lane: Lane::Xmr, address: None })
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
}
