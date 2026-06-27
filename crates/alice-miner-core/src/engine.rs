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

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::Duration;

use alice_supervise::ProcState;
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;

use crate::detect::DeviceProfile;
use crate::endpoint::{Endpoint, EndpointPlan};
use crate::identity::{self, Identity};
use crate::lane::{gpu_alpha, gpu_prl, gpu_rvn, xmr};
use crate::lane::{GpuSelection, Lane};

/// Lab bring-up escape hatch: `ALICE_ALPHA_REQUIRE_POP=0` skips the GPU-Alpha lane's
/// out-of-band M4 PoP (used ONLY for the initial e2e before the relay's alpha PoP
/// gate ships). Any other value (or unset) keeps PoP ON — V's decision.
fn alpha_pop_disabled() -> bool {
    std::env::var("ALICE_ALPHA_REQUIRE_POP")
        .map(|v| v.trim() == "0")
        .unwrap_or(false)
}
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
        /// Keystore unlock password — **required only for the GPU-PRL lane**,
        /// which must sign a Proof-of-Possession with the wallet sr25519 key
        /// (the relay's `REQUIRE_POP=1` credits no shares without it). The engine
        /// unlocks the on-disk keystore with this once at start to obtain the
        /// signing [`alice_crypto::WalletSecrets`], spawns the lane (+ its OOB
        /// refresh task), then drops the secrets/password. `None` is fine for
        /// XMR/RVN (address-only login); for GPU-PRL a `None` (or a watch-only
        /// identity) is rejected with a clear error. Held only for the brief
        /// unlock window, never persisted, never sent to the child.
        #[doc(hidden)]
        unlock_password: Option<String>,
        /// Which physical GPU(s) the GPU lane should run on (A5b). Defaults to
        /// [`GpuSelection::All`] (every detected card — the argv is unchanged vs.
        /// pre-A5b, so the existing multi-card behavior is preserved). Only the
        /// GPU lanes (PRL / RVN) consult it; the CPU-XMR lane ignores it.
        #[doc(hidden)]
        gpus: GpuSelection,
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
    /// GPU-PRL **15% PRL 返还** display block (A2c): a render-ready, **credit-only**
    /// status for the dashboard's "15% PRL 返还" panel — the enrolled flag, the
    /// user's MASKED `prl1p…` payout address, an honest "pending" text, and a
    /// `paid` field that is **hard-pinned 0.0**. `Some` only while the primary lane
    /// is [`Lane::GpuPrl`]; `None`/hidden for every other lane.
    ///
    /// **NOT serialized** (`#[serde(skip)]`): the credit-only JSON invariant forbids
    /// any `paid`/`payout` substring in a `Snapshot`'s wire form, and this is a pure
    /// UI render struct (it carries no minted / claimable / settleable value — see
    /// [`crate::prl_payout::PrlPayoutDisplay`]). It is rebuilt locally each snapshot
    /// from the (read-only) configured payout address + the enroll status flag.
    #[serde(skip)]
    pub prl_payout: Option<crate::prl_payout::PrlPayoutDisplay>,
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
            prl_payout: None,
        }
    }
}

/// The GPU-PRL **payout-enroll status**, shared between the async enroll task
/// (writer) and `build_snapshot` (reader) via an [`AtomicU8`]. Credit-only: this
/// is a binding/display status ONLY — it carries no amount, no claim, no payout
/// value. Maps 1:1 onto the enroll attempt's [`crate::prl_payout::EnrollOutcome`].
mod enroll_status {
    /// Enroll not yet attempted / in flight (the default).
    pub const PENDING: u8 = 0;
    /// The payout address was bound (enrolled) this session.
    pub const ENROLLED: u8 = 1;
    /// No payout address configured → nothing to bind (not an error).
    pub const NO_ADDRESS: u8 = 2;
    /// Watch-only identity → we refuse to fabricate a signature (skipped).
    pub const WATCH_ONLY: u8 = 3;
    /// A best-effort failure (network / server); can be retried next start.
    pub const FAILED: u8 = 4;
}

/// Events the engine emits back to the front-end.
// `Snapshot` is intentionally the largest variant — it's the hot-path payload sent
// on every poll; boxing it to satisfy `large_enum_variant` would add a heap alloc
// per snapshot for no real gain.
#[allow(clippy::large_enum_variant)]
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

/// Keeps the Mac awake for the lifetime of a mining session. On macOS, mining
/// must survive the user going idle: if the system idle-sleeps, xmrig stops; and
/// if the GUI is App-Napped, its stdout pump stalls, xmrig's pipe fills, and
/// xmrig blocks — both surface as a sudden drop to 0 H/s while the lane still
/// reads "Running". `caffeinate -i` (held for the session, killed on Stop / engine
/// exit via Drop) prevents idle sleep; the bundle's `NSAppSleepDisabled` handles
/// App Nap. A no-op on other platforms / if `caffeinate` is missing.
struct CaffeinateGuard {
    #[cfg(target_os = "macos")]
    child: Option<std::process::Child>,
}

impl CaffeinateGuard {
    fn new() -> Self {
        #[cfg(target_os = "macos")]
        {
            // -i = prevent idle system sleep while mining. Best-effort: a missing
            // /usr/bin/caffeinate just means no assertion (mining still works).
            let child = std::process::Command::new("/usr/bin/caffeinate")
                .arg("-i")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .ok();
            Self { child }
        }
        #[cfg(not(target_os = "macos"))]
        {
            Self {}
        }
    }
}

impl Drop for CaffeinateGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
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
    // single-lane mode, two in dual-mine (CPU-XMR + GPU-PRL), each crash-isolated
    // in its own process group. Empty when idle.
    let mut run = RunSet::default();
    let mut active_worker_id: Option<String> = None;
    // Held while ANY lane is running (macOS: prevents idle sleep stalling the
    // miner). Dropped (→ kills caffeinate) on Stop and on engine exit.
    let mut caffeinate: Option<CaffeinateGuard> = None;

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
            Some(Command::Start { lane, address, dual, mut unlock_password, gpus }) => {
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

                // GPU-PRL needs the wallet SIGNING key (PoP). Unlock the on-disk
                // keystore ONCE here to obtain the secrets; XMR/RVN don't need it
                // (address-only). A watch-only identity / missing password / wrong
                // password surfaces a clear error and the lane never starts (no
                // earning without PoP). The secrets/password drop at the end of
                // the start (the lane + refresh task own their own clone).
                // PRL needs the signing key. It is in play for a single pearlhash start
                // (GpuPrl OR GpuAlpha), and for a dual-mine whose GPU partner is a
                // pearlhash lane (anything but an explicit RVN selection). One shared
                // rule with the GUI modal + CLI prompt so the three can never drift.
                let prl_in_play = lane.start_needs_unlock(dual);
                let secrets = if prl_in_play {
                    match resolve_prl_secrets(unlock_password.as_deref()) {
                        Ok(s) => Some(s),
                        Err(e) => {
                            use zeroize::Zeroize;
                            if let Some(p) = unlock_password.as_mut() {
                                p.zeroize();
                            }
                            let _ = evt_tx.send(Event::Error(e));
                            continue;
                        }
                    }
                } else {
                    None
                };
                // Password no longer needed once the keystore is unlocked.
                {
                    use zeroize::Zeroize;
                    if let Some(p) = unlock_password.as_mut() {
                        p.zeroize();
                    }
                }

                match start_run(&rt, lane, dual, &addr, secrets, &gpus) {
                    Ok((new_run, worker_id)) => {
                        run = new_run;
                        // Keep the Mac awake for the session (no-op off macOS).
                        caffeinate.get_or_insert_with(CaffeinateGuard::new);
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
                caffeinate = None; // release the wake assertion (Drop kills caffeinate)
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
/// GPU-PRL), each crash-isolated in its own process group.
#[derive(Default)]
struct RunSet {
    /// The running supervisors, primary first (the primary drives the top-level
    /// Snapshot fields for the existing single-lane UI).
    supervisors: Vec<LaneSupervisor>,
    /// Whether this run is dual-mine (both lanes).
    dual: bool,
    /// GPU-PRL payout-enroll status (A2c), shared with the async enroll task.
    /// `Some` only on a GPU-PRL run; the task writes one of the [`enroll_status`]
    /// codes once it resolves, and `build_snapshot` reads it for the display block.
    /// Credit-only: a binding/display status, never an amount.
    prl_enroll: Option<Arc<AtomicU8>>,
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

/// Resolve the wallet [`alice_crypto::WalletSecrets`] (the sr25519 SIGNING key)
/// for the GPU-PRL lane's Proof-of-Possession. Loads the active identity pointer
/// to find the keystore, rejects a **watch-only** (pasted-address) identity with a
/// clear message (it has no keystore → it can never PoP — mirrors worker-v1's
/// keyless-identity error), then unlocks the on-disk keystore with `password`.
///
/// The returned `WalletSecrets` zeroizes its seed on the last clone's drop; the
/// caller hands ONE clone to the lane (+ its refresh task) and drops the rest.
pub fn resolve_prl_secrets(password: Option<&str>) -> Result<alice_crypto::WalletSecrets, String> {
    let pointer = identity::load_pointer().ok_or(
        "no reward identity: create/import an identity (the GPU-PRL lane needs a \
         wallet key to prove possession)",
    )?;

    // Watch-only / pasted address → no keystore → cannot sign a PoP. Fail closed
    // with the same shape worker-v1 uses for a keyless identity.
    let Some(keystore_path) = pointer.keystore_path.as_deref() else {
        return Err(
            "this reward identity is watch-only (address pasted, no signing key); the \
             GPU-PRL lane needs a wallet key to prove possession — import the mnemonic/seed \
             for this address instead"
                .into(),
        );
    };

    let password = password.ok_or(
        "the GPU-PRL lane needs your wallet password to unlock the signing key for \
         proof-of-possession",
    )?;

    let bytes = std::fs::read(keystore_path)
        .map_err(|e| format!("failed to read keystore {keystore_path}: {e}"))?;
    let payload: alice_crypto::WalletPayload = serde_json::from_slice(&bytes)
        .map_err(|e| format!("failed to parse keystore {keystore_path}: {e}"))?;
    let outcome = alice_crypto::unlock_wallet(&payload, password)
        .map_err(|e| format!("could not unlock the wallet key for proof-of-possession: {e}"))?;
    Ok(outcome.secrets)
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
    secrets: Option<alice_crypto::WalletSecrets>,
    gpus: &GpuSelection,
) -> Result<(RunSet, String), String> {
    let worker_id = xmr::derive_worker_id(address)?; // one worker-id fn for both lanes
    // Enter the runtime ONCE for all the start()s — they spawn tokio child-I/O +
    // watchdog tasks (the Wallet pattern: `let _guard = rt.enter();`).
    let _guard = rt.enter();

    if dual {
        // Both lanes together. XMR gets `cores-2` headroom; the GPU lane runs full.
        // The GPU partner is the user's explicitly-selected GPU lane (so a Volta/V100
        // box dual-mines via AlphaMiner, and an RVN selection stays RVN), defaulting to
        // the PRL **mainline** for a CPU-XMR selection. Pearlhash partners are PoP-gated
        // → `secrets` are threaded into the start; RVN is address-only.
        let gpu_lane = lane.dual_gpu_partner();
        let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
        let xmr_threads = dual_xmr_threads(cores);
        // CPU-XMR ignores GPU selection (pass All); the GPU partner (PRL mainline,
        // or RVN if explicitly selected) honors it and is threaded its PoP `secrets`.
        let (xmr_sup, _) =
            start_one_lane(Lane::Xmr, address, Some(xmr_threads), None, &GpuSelection::All)?;
        let (gpu_sup, prl_enroll) = match start_one_lane(gpu_lane, address, None, secrets, gpus) {
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
                supervisors: vec![xmr_sup, gpu_sup],
                dual: true,
                prl_enroll,
            },
            worker_id,
        ))
    } else {
        let (sup, prl_enroll) = start_one_lane(lane, address, None, secrets, gpus)?;
        Ok((
            RunSet {
                supervisors: vec![sup],
                dual: false,
                prl_enroll,
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
    secrets: Option<alice_crypto::WalletSecrets>,
    gpus: &GpuSelection,
) -> Result<(LaneSupervisor, Option<Arc<AtomicU8>>), String> {
    // A4 defensive CC guard: SRBMiner pearlhash needs CUDA compute capability ≥ 7.5
    // (Turing+). The CLI/GUI gate this advisorily, but a direct Start — the in-window
    // engine, a dual partner, or a misuse path — must NOT spawn SRBMiner on a Volta card
    // it physically cannot run on. `detect()` already folds in the operator override +
    // force (`ALICE_MINER_LANES[_FORCE]`), so a *forced* GpuPrl stays runnable and is NOT
    // refused here; we refuse only when the resolved viability says it can't run, and
    // redirect to the Alpha lane (which covers Volta/V100). Refuse BEFORE RTT probing.
    if lane == Lane::GpuPrl {
        let cap = crate::CapabilityProfile::detect();
        if !cap.support(Lane::GpuPrl).is_runnable() {
            return Err(format!(
                "GPU-PRL (SRBMiner) can't run on this GPU: {}. Use the Alpha lane \
                 (`--lane alpha`) — AlphaMiner covers Volta/V100.",
                cap.viability
                    .reason(Lane::GpuPrl)
                    .unwrap_or("compute capability below 7.5"),
            ));
        }
    }
    // GPU-PRL targets the region relays ordered by lowest RTT (operator override /
    // probe / US-first fallback); every other lane uses its compiled plan.
    let plan = if lane == Lane::GpuPrl {
        gpu_prl::region_plan_by_rtt()
    } else {
        EndpointPlan::for_lane(lane)
    };
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
        Lane::GpuRvn => {
            let gpus_rvn = gpus.clone();
            Arc::new(move |eps: &[Endpoint]| {
                let program =
                    crate::binaries::resolve_miner_binary(crate::binaries::MinerKind::GpuRvn)?;
                let p = if is_trex_binary(&program) {
                    // T-Rex (override path) takes a single endpoint; use the first.
                    gpu_rvn::build_trex_launch_plan(program, &addr_for_rebuild, &gpus_rvn)?
                } else {
                    gpu_rvn::build_kawpowminer_launch_plan_with_endpoints(
                        program,
                        &addr_for_rebuild,
                        eps,
                        &gpus_rvn,
                    )?
                };
                Ok((p.program, p.args))
            })
        }
        Lane::GpuPrl => {
            // GPU-PRL needs the wallet SIGNING key for the region-bound PoP. The
            // caller (worker_loop) already unlocked it + rejected watch-only; a
            // missing secret here is a programming error, so fail closed.
            let Some(secrets) = secrets.clone() else {
                return Err(
                    "internal: GPU-PRL lane started without an unlocked signing key".into(),
                );
            };
            // The supervisor-owned log file SRBMiner writes shares/hashrate to
            // (it does NOT print them to stdout). Unique per process so two runs
            // never collide. See the TODO at the bottom: the supervisor must tail
            // THIS file for the GPU-PRL lane (stdout-only capture misses shares).
            let log_path = prl_log_path();
            let addr_prl = addr_for_rebuild.clone();
            let gpus_prl = gpus.clone();
            Arc::new(move |eps: &[Endpoint]| {
                let program =
                    crate::binaries::resolve_miner_binary(crate::binaries::MinerKind::GpuPrl)?;
                let Some(active) = eps.first() else {
                    return Err("gpu-prl launch plan needs at least one endpoint".into());
                };
                let region_authority = format!("{}:{}", active.host, active.port);
                // ── T4: region-bound PoP. The token is minted+verified against
                // the ACTIVE region (a token for region A is rejected by region B),
                // so on EVERY (re)build — initial start AND a Layer-B failover to a
                // different region — we re-challenge → re-sign → re-OOB-verify for
                // the current region BEFORE building argv.
                let device_id = xmr::derive_worker_id(&addr_prl)?; // == stratum worker suffix
                let token = crate::pop::establish_pop(
                    &active.host, // control plane is `https://<host>/m4/challenge` (port-free)
                    &addr_prl,
                    &device_id,
                    &secrets,
                    None,
                )?;
                let p = gpu_prl::build_srbminer_pearl_launch_plan(
                    program,
                    &addr_prl,
                    &region_authority,
                    &token.password,
                    &log_path,
                    &gpus_prl,
                )?;
                Ok((p.program, p.args))
            })
        }
        Lane::GpuAlpha => {
            // GPU-Alpha (V100/Volta) also needs the wallet SIGNING key for its
            // out-of-band M4 PoP (require_pop=ON — V's decision); the caller already
            // unlocked it + rejected watch-only, so a missing secret is a bug.
            let Some(secrets) = secrets.clone() else {
                return Err(
                    "internal: GPU-Alpha lane started without an unlocked signing key".into(),
                );
            };
            let addr_alpha = addr_for_rebuild.clone();
            let gpus_alpha = gpus.clone();
            Arc::new(move |eps: &[Endpoint]| {
                let program =
                    crate::binaries::resolve_miner_binary(crate::binaries::MinerKind::GpuAlpha)?;
                let Some(active) = eps.first() else {
                    return Err("gpu-alpha launch plan needs at least one endpoint".into());
                };
                let authority = format!("{}:{}", active.host, active.port);
                // device_id == the relay worker-tail (`<alice>.<device_id>`) so the
                // OOB PoP allowlist key matches what the login presents (the device_id
                // contract that keeps a require_pop=ON relay from locking the miner out).
                let device_id = xmr::derive_worker_id(&addr_alpha)?;
                // OOB M4 PoP: prove possession of the Alice key so the relay credits
                // ONLY an owned address. The token rides the allowlist OUT-OF-BAND, NOT
                // argv — alpha-miner's stratum `--password` is AlphaPool's plain `x`
                // (the pool owns the pearl.challenge). Lab bring-up before the relay's
                // alpha PoP gate ships: ALICE_ALPHA_REQUIRE_POP=0 skips this step.
                if !alpha_pop_disabled() {
                    let _token = crate::pop::establish_pop(
                        &active.host,
                        &addr_alpha,
                        &device_id,
                        &secrets,
                        None,
                    )?;
                }
                let placeholder = gpu_alpha::alpha_placeholder_address();
                // backend=None → alpha-miner auto-selects (volta_sm70 on a V100, verified).
                let p = gpu_alpha::build_alphaminer_launch_plan(
                    program,
                    &addr_alpha,
                    &authority,
                    &placeholder,
                    None,
                    &gpus_alpha,
                )?;
                Ok((p.program, p.args))
            })
        }
    };

    // Build the initial launch plan (Layer A: all endpoints, primary first).
    let (program, args) = rebuild(&plan.ordered_from_cursor())?;

    let sup = LaneSupervisor::with_endpoints(lane, plan);
    sup.start(program, args, rebuild)?;

    // ── T4 item 5: OOB-allowlist refresh task (GPU-PRL only). The relay drops a
    // proven (address, device) from its PoP allowlist after OOB_ALLOWLIST_TTL
    // (~1800s) without a re-verify; without a refresh the lane silently stops
    // being credited after ~25min. Spawn a background task — tied to THIS lane's
    // lifecycle — that re-challenges → re-signs → re-OOB-verifies the CURRENT
    // region every ~60s once fewer than OOB_REFRESH_MARGIN (~300s) remain. It
    // stops as soon as the supervisor is no longer active (a user Stop, a crash,
    // or budget-exhaustion Error), so it shares the lane's lifecycle.
    let mut prl_enroll: Option<Arc<AtomicU8>> = None;
    if lane.is_prl_lane() {
        if let Some(secrets) = secrets {
            // T5: best-effort 15%-PRL payout enroll — bind the user's OWN prl1p…
            // payout address to their Alice address, ONCE, after PoP is up. Skips
            // cleanly (no error, no fake signature) when no payout address is set
            // or the identity is watch-only. Lane-independent (central HTTP keyed by
            // the Alice address), so BOTH GPU-PRL and GPU-Alpha enroll the same way.
            // A2c: the task reports its outcome into this shared status flag so the
            // dashboard's "15% PRL 返还" block can show the honest enrolled/skipped
            // state (credit-only — a status, never a value).
            let status = Arc::new(AtomicU8::new(enroll_status::PENDING));
            spawn_prl_enroll_task(sup.clone(), address.clone(), secrets.clone(), status.clone());
            // OOB-allowlist refresh: re-OOB-verify the (address, device) before the
            // relay's TTL (~1800s) lapses, or the lane silently stops being credited
            // after ~25min. The task is lane-agnostic (it targets the lane's CURRENT
            // region host via the same port-free `establish_pop` control plane), so it
            // serves BOTH the GPU-PRL (herominers :3340) and GPU-Alpha (AlphaPool :3341)
            // relays — the alpha PoP gate has shipped. Skip it only when the alpha lane
            // runs with PoP disabled (the lab escape hatch: no allowlist entry exists to
            // refresh). `secrets` is moved here, or dropped when skipped.
            let refresh_pop = match lane {
                Lane::GpuPrl => true,
                Lane::GpuAlpha => !alpha_pop_disabled(),
                _ => false,
            };
            if refresh_pop {
                spawn_pop_refresh_task(sup.clone(), address.clone(), secrets);
            }
            prl_enroll = Some(status);
        }
    }
    Ok((sup, prl_enroll))
}

/// A unique, supervisor-owned log path for the GPU-PRL SRBMiner child. SRBMiner
/// writes share/hashrate lines ONLY to its `--log-file` (never stdout), so the
/// path must be stable for the run and owned by us (the supervisor tails it).
fn prl_log_path() -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("alice-gpu-prl-{}-{}.log", std::process::id(), nanos))
}

/// Spawn the GPU-PRL OOB-allowlist refresh task (T4 item 5). MUST be called inside
/// a tokio runtime context (the caller holds `rt.enter()`). The task lives as long
/// as `sup` is active; it re-runs the region-bound PoP handshake for the lane's
/// CURRENT region when the TTL is within [`crate::pop::OOB_REFRESH_MARGIN`] of
/// expiring, so the miner never silently drops out of the allowlist. The wallet
/// `secrets` clone is owned by the task and zeroizes on the last clone's drop
/// (here, when the task ends). The token isn't fed to the child — the OOB verify
/// re-arms the relay's allowlist server-side; the child keeps mining under its
/// existing connection (a future change can also hot-swap the password via a child
/// restart, but the allowlist re-verify is what keeps crediting alive).
fn spawn_pop_refresh_task(
    sup: LaneSupervisor,
    address: String,
    secrets: alice_crypto::WalletSecrets,
) {
    use crate::pop::{OOB_ALLOWLIST_TTL, OOB_REFRESH_MARGIN, OOB_REFRESH_TICK};
    tokio::spawn(async move {
        // Track when the current region's allowlist entry was last (re)verified.
        // The initial establish_pop in the rebuild closure just verified, so the
        // first deadline is one TTL out.
        let mut verified_at = std::time::Instant::now();
        let mut last_region = sup.current_endpoint(); // host:port
        loop {
            tokio::time::sleep(OOB_REFRESH_TICK).await;
            // Stop when the lane is no longer active (Stop / crash / Error).
            if !sup.is_active() {
                return;
            }
            // A Layer-B failover rebuilt the token for a NEW region (the rebuild
            // closure re-verified there), so re-arm the deadline to that region.
            let region_now = sup.current_endpoint();
            if region_now != last_region {
                last_region = region_now;
                verified_at = std::time::Instant::now();
                continue;
            }
            // Re-verify only when within the margin of the TTL expiring.
            let remaining = OOB_ALLOWLIST_TTL.checked_sub(verified_at.elapsed());
            let due = match remaining {
                Some(r) => r <= OOB_REFRESH_MARGIN,
                None => true, // already past the TTL — re-verify now
            };
            if !due {
                continue;
            }
            // Re-run the handshake for the CURRENT region host (port-free control
            // plane). A failure is logged-and-retried next tick (the relay is the
            // authority; a transient verify hiccup must not kill the lane).
            let host = sup
                .current_endpoint()
                .split(':')
                .next()
                .unwrap_or_default()
                .to_string();
            let device_id = match crate::lane::xmr::derive_worker_id(&address) {
                Ok(d) => d,
                Err(_) => return, // address became invalid — nothing to refresh
            };
            // Run the blocking HTTPS handshake OFF the async worker (ureq is sync,
            // ~10s/call) so it can NEVER starve the tokio runtime — same as the
            // enroll task. A failure is SURFACED (stderr + a lane note the GUI/CLI
            // shows) instead of silently swallowed, then retried next tick; the
            // relay is the authority, a transient verify hiccup must not kill the
            // lane.
            let (h, a, d, s) = (
                host.clone(),
                address.clone(),
                device_id.clone(),
                secrets.clone(),
            );
            let res = tokio::task::spawn_blocking(move || {
                crate::pop::establish_pop(&h, &a, &d, &s, None)
            })
            .await;
            match res {
                Ok(Ok(_)) => {
                    verified_at = std::time::Instant::now();
                    sup.note_message(None); // recovered — clear any prior warning
                }
                Ok(Err(e)) => {
                    eprintln!(
                        "[pop-refresh] OOB re-verify failed for {host}: {e} — retrying; \
                         crediting may pause if the allowlist TTL lapses"
                    );
                    sup.note_message(Some(
                        "PoP re-verify failing — crediting may pause; retrying".into(),
                    ));
                    // Leave `verified_at` as-is so we retry on the next tick.
                }
                Err(join_err) => {
                    eprintln!("[pop-refresh] re-verify task panicked: {join_err}");
                }
            }
        }
    });
}

/// Map a relay host (`us.aliceprotocol.org`) to its short region tag (`us`) for the
/// enroll `region` field; falls back to the host itself if it isn't a known relay.
fn region_tag_for_host(host: &str) -> String {
    gpu_prl::REGION_HOSTS
        .iter()
        .find(|(_, h)| *h == host)
        .map(|(tag, _)| (*tag).to_string())
        .unwrap_or_else(|| host.to_string())
}

/// Spawn the T5 one-shot 15%-PRL **payout enroll** task (GPU-PRL only). MUST be
/// called inside a tokio runtime context. Best-effort: it binds the user's OWN
/// `prl1p…` payout address to their Alice address ONCE after the lane is up, then
/// exits. It NEVER fails the lane — a watch-only identity, an unset payout address,
/// or a transient server error is logged-as-outcome and dropped (the binding can be
/// retried on the next lane start). `secrets` is a dedicated clone owned by this
/// task and zeroizes when the task ends. The enroll endpoint is CENTRAL (one payout
/// authority), so the binding does not need to re-run per region failover.
fn spawn_prl_enroll_task(
    sup: LaneSupervisor,
    address: String,
    secrets: alice_crypto::WalletSecrets,
    status: Arc<AtomicU8>,
) {
    tokio::spawn(async move {
        // The lane may have been stopped before we even got scheduled; if so, skip.
        if !sup.is_active() {
            return;
        }
        let device_id = match crate::lane::xmr::derive_worker_id(&address) {
            Ok(d) => d,
            Err(_) => return, // invalid address → nothing to enroll
        };
        // The region tag of the lane's CURRENT (cursor) endpoint, for the binding's
        // `region` field. Enroll itself is central; the tag is informational.
        let host = sup
            .current_endpoint()
            .split(':')
            .next()
            .unwrap_or_default()
            .to_string();
        let region = region_tag_for_host(&host);
        // The HTTPS POSTs are blocking (ureq); run them off the async worker so they
        // can't stall the runtime. The outcome is best-effort — we don't surface it
        // as a lane Error (the lane keeps mining regardless of the payout binding).
        let outcome = tokio::task::spawn_blocking(move || {
            crate::prl_payout::run_enroll_best_effort(&address, &device_id, &region, &secrets)
        })
        .await;
        // A2c: record the outcome into the shared status flag so the dashboard's
        // "15% PRL 返还" block shows the honest enrolled/skipped state. The enroll
        // is still fail-open w.r.t. the lane (a Failed/JoinError never stops mining).
        use crate::prl_payout::EnrollOutcome;
        let code = match outcome {
            Ok(EnrollOutcome::Enrolled) => enroll_status::ENROLLED,
            Ok(EnrollOutcome::NoPayoutAddress) => enroll_status::NO_ADDRESS,
            Ok(EnrollOutcome::WatchOnly) => enroll_status::WATCH_ONLY,
            Ok(EnrollOutcome::Failed(_)) | Err(_) => enroll_status::FAILED,
        };
        status.store(code, Ordering::Relaxed);
    });
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

    // A2c: GPU "15% PRL 返还" display block. Built whenever a PRL-EARNING lane is
    // present — both pearlhash lanes (`GpuPrl` SRBMiner + `GpuAlpha` AlphaMiner/V100,
    // `lane.is_prl_lane()`), single-lane today and any future dual pairing that
    // includes one. Credit-only by construction — see
    // [`crate::prl_payout::PrlPayoutDisplay`] (`paid` is hard-pinned 0.0).
    if run.supervisors.iter().any(|s| s.lane().is_prl_lane()) {
        snap.prl_payout = Some(build_prl_payout_display(run.prl_enroll.as_ref()));
    }
    snap
}

/// Build the credit-only "15% PRL 返还" display block from the (read-only) configured
/// payout address + the shared enroll-status flag. NO network call (the GUI/CLI can
/// fold a best-effort `miner-lookup` in via
/// [`crate::prl_payout::PrlPayoutDisplay::with_pending_from_lookup`] if desired). The
/// returned struct's `paid` is hard-pinned 0.0 — there is no value path here.
fn build_prl_payout_display(
    enroll: Option<&Arc<AtomicU8>>,
) -> crate::prl_payout::PrlPayoutDisplay {
    // Best-effort, read-only: a configured (env/file) payout address, masked for the
    // panel. A shape error / unset address → None (the block shows the honest
    // "未设置返还地址" / "未绑定" text rather than a number).
    let payout = crate::prl_payout::load_payout_address().ok().flatten();
    // `enrolled` is true ONLY when the async enroll task reported ENROLLED; every
    // other state (pending / no-address / watch-only / failed) is honestly NOT
    // enrolled, so the panel never claims a binding that didn't happen.
    let enrolled = enroll
        .map(|s| s.load(Ordering::Relaxed) == enroll_status::ENROLLED)
        .unwrap_or(false);
    crate::prl_payout::PrlPayoutDisplay::new(enrolled, payout.as_deref())
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
            // A2c: a populated PRL display block must NOT leak any payout/paid
            // substring into the wire JSON (it is `#[serde(skip)]`). Set it here so
            // the credit-only JSON assertion below exercises the skip.
            prl_payout: Some(crate::prl_payout::PrlPayoutDisplay::new(
                true,
                Some("prl1pexamplewalletexamplewalletexamplewallet"),
            )),
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

    /// A2c / Piece 3: `build_snapshot` attaches the credit-only "15% PRL 返还"
    /// display block for ANY PRL-EARNING lane — both `GpuPrl` (SRBMiner) AND
    /// `GpuAlpha` (AlphaMiner/V100), via `lane.is_prl_lane()` — and never for the
    /// address-only lanes (`Xmr`/`GpuRvn`). Uses un-started supervisors (no child) so
    /// the test is pure: the gate keys off `supervisor.lane()`, not a live run.
    #[test]
    fn snapshot_attaches_prl_block_for_both_pearlhash_lanes() {
        fn has_block(lane: Lane) -> bool {
            let run = RunSet {
                supervisors: vec![LaneSupervisor::new(lane)],
                dual: false,
                prl_enroll: None,
            };
            build_snapshot(&None, &run, &None).prl_payout.is_some()
        }
        // Both pearlhash lanes get the block.
        assert!(has_block(Lane::GpuPrl), "GpuPrl (SRBMiner) → block");
        assert!(has_block(Lane::GpuAlpha), "GpuAlpha (AlphaMiner/V100) → block");
        // Address-only lanes never do.
        assert!(!has_block(Lane::Xmr), "XMR is address-only → no block");
        assert!(!has_block(Lane::GpuRvn), "RVN is address-only → no block");

        // And the credit-only JSON invariant still holds with the block attached on
        // the GpuAlpha path (the block is #[serde(skip)] → no payout substring).
        let run = RunSet {
            supervisors: vec![LaneSupervisor::new(Lane::GpuAlpha)],
            dual: false,
            prl_enroll: None,
        };
        let snap = build_snapshot(&None, &run, &None);
        assert!(snap.prl_payout.is_some());
        let json = serde_json::to_string(&snap).expect("serialize");
        for forbidden in ["paid", "payout", "prl_payout"] {
            assert!(!json.contains(forbidden), "GpuAlpha Snapshot JSON leaked `{forbidden}`: {json}");
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
            .send(Command::Start {
                lane: Lane::Xmr,
                address: None,
                dual: false,
                unlock_password: None,
                gpus: GpuSelection::All,
            })
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

    /// T4 item 4: the GPU-PRL lane needs the wallet SIGNING key, so a watch-only
    /// (pasted-address) identity must be REJECTED up front with a clear error —
    /// before any region probe / control-plane call. Mirrors worker-v1's keyless-
    /// identity refusal. Also asserts a keystore-backed identity with NO password
    /// is refused with the "needs your wallet password" message (no wrong-password
    /// unlock attempt). Pure: uses a temp identity dir, no network.
    #[test]
    fn resolve_prl_secrets_rejects_watch_only_and_missing_password() {
        // Shares the crate-wide identity-env lock with the `identity` tests so the
        // global `ALICE_WALLET_DATA_ROOT` / `ALICE_IDENTITY_DIR` can't race.
        let _g = crate::IDENTITY_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Isolate the identity pointer + keystore into fresh temp dirs.
        let base = std::env::temp_dir().join(format!(
            "alice-prl-secrets-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let wallet_root = base.join("wallet");
        let id_dir = base.join("dot-alice");
        std::fs::create_dir_all(&wallet_root).unwrap();
        std::fs::create_dir_all(&id_dir).unwrap();
        std::env::set_var("ALICE_WALLET_DATA_ROOT", &wallet_root);
        std::env::set_var("ALICE_IDENTITY_DIR", &id_dir);

        // `WalletSecrets` is intentionally not `Debug` (no secret in output), so we
        // extract the Err string without `unwrap_err` (which would need Ok: Debug).
        fn err_of(r: Result<alice_crypto::WalletSecrets, String>) -> String {
            match r {
                Ok(_) => panic!("expected an error, got Ok(secrets)"),
                Err(e) => e,
            }
        }

        // (a) No identity at all → clear "no reward identity" error.
        let err = err_of(resolve_prl_secrets(Some("pw")));
        assert!(err.contains("no reward identity"), "got: {err}");

        // (b) Watch-only (pasted) identity → rejected as keyless, regardless of pw.
        let addr = alice_crypto::create_wallet_payload(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "pw-123456",
        )
        .unwrap()
        .address;
        identity::paste(&addr, Some("watch".into())).expect("paste");
        let err = err_of(resolve_prl_secrets(Some("anything")));
        assert!(err.contains("watch-only"), "watch-only must be refused: {err}");

        // (c) A real keystore-backed identity, but NO password → asks for it
        // (does not attempt an unlock with a wrong/empty password).
        let (_id, _m) = identity::create(Some("real".into()), "correct horse battery staple")
            .expect("create");
        let err = err_of(resolve_prl_secrets(None));
        assert!(err.contains("wallet password"), "missing-pw message: {err}");

        // (d) The right password DOES unlock and yields a signing-capable secret.
        let secrets = resolve_prl_secrets(Some("correct horse battery staple"))
            .expect("unlock with the right password");
        assert!(secrets.can_export_private_key(), "secrets must hold a key");

        std::env::remove_var("ALICE_WALLET_DATA_ROOT");
        std::env::remove_var("ALICE_IDENTITY_DIR");
        let _ = std::fs::remove_dir_all(&base);
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

        // Exercise the **legacy RVN dual** (CPU-XMR + GPU-RVN): explicitly selecting
        // RVN keeps the GPU partner address-only, so no keystore/PoP secrets are
        // needed (the default PRL dual signs a PoP — covered by the single-PRL +
        // `prl_in_play` tests). `start_run` maps `lane == GpuRvn` → an RVN partner.
        let engine = EngineHandle::spawn().expect("spawn");
        engine
            .send(Command::Start {
                lane: Lane::GpuRvn,
                address: Some(address),
                dual: true,
                unlock_password: None,
                gpus: GpuSelection::All,
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
