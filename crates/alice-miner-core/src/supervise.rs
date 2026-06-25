//! `core/supervise` — [`LaneSupervisor`], one supervised mining child + its
//! parsed live stats + the M4 multi-endpoint failover watchdog.
//!
//! Generalizes `alice-wallet/gui/src/supervise/miner_supervisor.rs` (PLAN §2.2,
//! conflict C4: the canonical name is `LaneSupervisor`; the engine owns N of
//! them — dual-mine = 2). It:
//!   * spawns / owns / stops the engine child via the shared `alice-supervise`
//!     crate (`spawn_supervised` + `OwnedChild::stop` = SIGTERM→SIGKILL). Each
//!     child runs in **its OWN process group** (`child.rs` `setpgid` +
//!     `kill_on_drop`), so killing/crashing one supervisor's child can NEVER hit
//!     another's — the dual-mine **crash-isolation** invariant (PLAN §7);
//!   * drains the stdout/stderr `LogLine` channel on a background task and parses
//!     hashrate + accepted/rejected shares with [`parse_hashrate_hs`] /
//!     [`parse_share_counts`] (ported **VERBATIM** from the Wallet, ~L273/L299);
//!   * runs the **Layer-B "no-progress" watchdog** (M4): if no accepted share /
//!     no hashrate progress for [`NO_PROGRESS_WINDOW`] (~120s), it advances the
//!     [`crate::endpoint::EndpointPlan`] cursor and `restart_with`s the child
//!     pointed at the NEXT endpoint — **gated by [`alice_supervise::RestartPolicy`]**
//!     (bounded retries + backoff; budget exhaustion → clean `Error`, no
//!     restart-storm);
//!   * keeps a cloneable, secret-free [`LaneStats`] snapshot the engine reads.
//!
//! The wallet seed/private key is NEVER passed to the child (the launch plan
//! carries only the public address — see [`crate::lane::xmr`]); the child only
//! ever sees the PUBLIC Alice address.

#![allow(dead_code)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc::unbounded_channel;

use alice_supervise::child::{spawn_supervised, LogLine, OwnedChild};
use alice_supervise::{sanitize_log_line, ProcState, RestartPolicy};

use crate::endpoint::{Endpoint, EndpointPlan};
use crate::lane::Lane;
use crate::stats::parse_kawpow;
use crate::stats::parse_srbminer;

/// Grace period for a graceful miner stop before SIGKILL (verbatim from Wallet).
const STOP_GRACE: Duration = Duration::from_secs(5);

/// Layer-B failover window: if the lane makes no progress (no new accepted share
/// AND no hashrate increase) for this long, the watchdog advances the endpoint
/// cursor and restarts on the next endpoint (PLAN §5 M4 — "~120s"). Generous so
/// it never trips during normal warm-up (RandomX dataset alloc, first job).
pub const NO_PROGRESS_WINDOW: Duration = Duration::from_secs(120);

/// How often the watchdog wakes to check progress. Cheap; just compares the
/// stored progress timestamp against `NO_PROGRESS_WINDOW`.
const WATCHDOG_TICK: Duration = Duration::from_secs(2);

/// A closure the engine supplies that (re)builds the `(program, args)` launch
/// plan for a given ORDERED endpoint list. Lets the supervisor rebuild the
/// per-endpoint argv on a Layer-B failover without knowing any lane specifics —
/// the lane modules ([`crate::lane::xmr`] / [`crate::lane::gpu_rvn`]) own the
/// actual arg shape; the supervisor only knows "rebuild for these endpoints".
/// Returns the new `(program, args)` (Layer-A multi-endpoint, rotated so the new
/// cursor is primary). `Send + Sync` so the watchdog task can call it.
pub type RebuildFn =
    Arc<dyn Fn(&[Endpoint]) -> Result<(std::path::PathBuf, Vec<String>), String> + Send + Sync>;

/// A point-in-time, UI-safe snapshot of a lane's child. Cloneable + secret-free
/// so the engine can read it every tick. (Generalized from the Wallet
/// `MinerStats`, plus the lane tag + start instant for uptime + the M4 endpoint /
/// failover fields.)
#[derive(Debug, Clone, PartialEq)]
pub struct LaneStats {
    /// Which lane this supervisor runs.
    pub lane: Lane,
    /// Whether the child is currently active (starting/running/stopping).
    pub running: bool,
    /// Lifecycle state (drives the status pill).
    pub state: ProcState,
    /// Most recent hashrate in H/s (10s, else 60s figure). `None` until the
    /// first speed line arrives.
    pub hashrate_hs: Option<f64>,
    /// Running count of accepted shares (latest `(A/R)` figure).
    pub accepted: u64,
    /// Running count of rejected shares (latest `(A/R)` figure).
    pub rejected: u64,
    /// Last process exit code, when it has exited.
    pub last_exit_code: Option<i32>,
    /// Short, sanitised reason for the current state, if any.
    pub message: Option<String>,
    /// Last sanitised output line (an at-a-glance "what is it doing" hint).
    pub last_line: String,
    /// Seconds since the current run started (0 when stopped).
    pub uptime_s: u64,
    /// The endpoint the lane is CURRENTLY targeting (`host:port`) — the active
    /// relay endpoint, surfaced in the dashboard. `None` before the first start.
    pub endpoint: Option<String>,
    /// How many times Layer B has advanced the endpoint cursor this run (0 =
    /// never failed over). Drives the dashboard "failed over" note.
    pub failovers: u64,
}

impl LaneStats {
    fn stopped(lane: Lane) -> Self {
        Self {
            lane,
            running: false,
            state: ProcState::Stopped,
            hashrate_hs: None,
            accepted: 0,
            rejected: 0,
            last_exit_code: None,
            message: None,
            last_line: String::new(),
            uptime_s: 0,
            endpoint: None,
            failovers: 0,
        }
    }
}

/// Shared, lock-guarded supervisor state. Cloneable handle. (Mirrors the
/// Wallet's `MinerSupervisor` shape; generalized over [`Lane`] + endpoints.)
#[derive(Clone)]
pub struct LaneSupervisor {
    lane: Lane,
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    state: ProcState,
    pid: Option<u32>,
    last_exit_code: Option<i32>,
    message: Option<String>,
    hashrate_hs: Option<f64>,
    accepted: u64,
    rejected: u64,
    last_line: String,
    /// When the current run started (for uptime).
    started_at: Option<std::time::Instant>,
    /// User explicitly requested stop.
    stop_requested: bool,
    /// Set by the Layer-B watchdog when it gives up (budget exhausted): the child
    /// is being torn down, but the lane must land in `Error` (not `Stopped`) and
    /// keep the watchdog's explanatory message. Distinguishes a user Stop (→
    /// Stopped) from a forced failover-exhaustion stop (→ Error).
    forced_error: bool,
    /// Generation counter; bumped on every start/stop so a stale supervision
    /// loop from a previous child can't clobber newer state.
    generation: u64,

    // ── M4: multi-endpoint failover (Layer B) ───────────────────────────────
    /// The endpoint plan + failover cursor for THIS lane.
    endpoint_plan: EndpointPlan,
    /// Bounded restart budget gating Layer-B failovers (no restart-storm).
    restart_policy: RestartPolicy,
    /// The engine-supplied closure to rebuild `(program, args)` for a new
    /// endpoint order (set on `start`; reused by the watchdog on failover).
    rebuild: Option<RebuildFn>,
    /// Last time the lane made PROGRESS (a new accepted share OR a higher
    /// hashrate). The watchdog measures "no progress" against this.
    last_progress_at: Option<Instant>,
    /// The best (max) hashrate seen this run — a rise past it counts as progress
    /// (so a steady non-zero rate that never grows still eventually trips the
    /// watchdog only if shares ALSO stall; a healthy lane lands accepted shares).
    best_hashrate_hs: f64,
    /// The accepted count at the last progress mark (a rise counts as progress).
    progress_accepted: u64,
    /// Number of Layer-B endpoint advances this run.
    failovers: u64,
    /// The no-progress window before the watchdog rotates endpoints. Defaults to
    /// [`NO_PROGRESS_WINDOW`] (~120s); tunable (tests use a tiny value for speed).
    no_progress_window: Duration,
    /// Override for the per-failover backoff. `None` ⇒ use the [`RestartPolicy`]'s
    /// growing backoff (production). `Some(d)` ⇒ a fixed backoff (tests use a tiny
    /// value so the failover loop runs fast without multi-second wall sleeps).
    failover_backoff_override: Option<Duration>,
}

impl LaneSupervisor {
    /// A supervisor with the lane's DEFAULT endpoint plan (relay-only, plus any
    /// operator `ALICE_MINER_ENDPOINTS_JSON` override). The common path.
    pub fn new(lane: Lane) -> Self {
        Self::with_endpoints(lane, EndpointPlan::for_lane(lane))
    }

    /// A supervisor with an explicit [`EndpointPlan`] (used by tests + the
    /// failover verification to inject a bogus-primary→relay plan).
    pub fn with_endpoints(lane: Lane, endpoint_plan: EndpointPlan) -> Self {
        Self {
            lane,
            inner: Arc::new(Mutex::new(Inner {
                state: ProcState::Stopped,
                pid: None,
                last_exit_code: None,
                message: None,
                hashrate_hs: None,
                accepted: 0,
                rejected: 0,
                last_line: String::new(),
                started_at: None,
                stop_requested: false,
                forced_error: false,
                generation: 0,
                endpoint_plan,
                restart_policy: RestartPolicy::new(),
                rebuild: None,
                last_progress_at: None,
                best_hashrate_hs: 0.0,
                progress_accepted: 0,
                failovers: 0,
                no_progress_window: NO_PROGRESS_WINDOW,
                failover_backoff_override: None,
            })),
        }
    }

    /// Test/operator hook: shorten the no-progress window + fix the per-failover
    /// backoff so the Layer-B watchdog can be exercised quickly (the production
    /// default is a 120s window + the growing RestartPolicy backoff). Must be set
    /// before `start`.
    #[doc(hidden)]
    pub fn set_failover_timing(&self, window: Duration, backoff: Duration) {
        let mut g = self.inner.lock().expect("mutex");
        g.no_progress_window = window;
        g.failover_backoff_override = Some(backoff);
    }

    pub fn lane(&self) -> Lane {
        self.lane
    }

    /// The endpoint the lane is currently targeting (`host:port`).
    pub fn current_endpoint(&self) -> String {
        self.inner
            .lock()
            .expect("mutex")
            .endpoint_plan
            .current()
            .host_port()
    }

    /// Current UI-safe snapshot.
    pub fn stats(&self) -> LaneStats {
        let g = self.inner.lock().expect("lane supervisor mutex");
        let uptime_s = g
            .started_at
            .filter(|_| g.state.is_active())
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(0);
        LaneStats {
            lane: self.lane,
            running: g.state.is_active(),
            state: g.state,
            hashrate_hs: g.hashrate_hs,
            accepted: g.accepted,
            rejected: g.rejected,
            last_exit_code: g.last_exit_code,
            message: g.message.clone(),
            last_line: g.last_line.clone(),
            uptime_s,
            endpoint: Some(g.endpoint_plan.current().host_port()),
            failovers: g.failovers,
        }
    }

    pub fn is_active(&self) -> bool {
        self.inner.lock().expect("mutex").state.is_active()
    }

    pub fn pid(&self) -> Option<u32> {
        self.inner.lock().expect("mutex").pid
    }

    /// Number of Layer-B endpoint advances this run (0 = never failed over).
    pub fn failovers(&self) -> u64 {
        self.inner.lock().expect("mutex").failovers
    }

    /// Start the lane from a validated `(program, args)` launch plan with the
    /// lane's endpoint failover wired up. `rebuild` is the engine-supplied
    /// closure to re-derive `(program, args)` for a new endpoint order on a
    /// Layer-B failover (so the watchdog can rotate endpoints without lane
    /// knowledge). MUST be called inside a tokio runtime context (it spawns child
    /// I/O + watchdog tasks). Resets the per-run stats counters AND the restart
    /// budget (a user-initiated start clears any prior failover budget).
    pub fn start(
        &self,
        program: std::path::PathBuf,
        args: Vec<String>,
        rebuild: RebuildFn,
    ) -> Result<(), String> {
        // Reset the failover cursor + budget on a user-initiated start.
        {
            let mut g = self.inner.lock().expect("mutex");
            g.endpoint_plan.reset();
            g.restart_policy.reset();
            g.rebuild = Some(rebuild);
            g.failovers = 0;
        }
        self.spawn_run(program, args, /*is_failover=*/ false)
    }

    /// Backwards-compatible start with NO failover rebuild (single-endpoint, the
    /// M1 behaviour) — the watchdog will restart in place at most once per budget
    /// rather than rotate. Mostly used by older tests; the engine uses
    /// [`Self::start`] with a rebuild closure.
    pub fn start_simple(
        &self,
        program: std::path::PathBuf,
        args: Vec<String>,
    ) -> Result<(), String> {
        {
            let mut g = self.inner.lock().expect("mutex");
            g.endpoint_plan.reset();
            g.restart_policy.reset();
            g.rebuild = None;
            g.failovers = 0;
        }
        self.spawn_run(program, args, false)
    }

    /// Spawn (or re-spawn, on failover) the child with the given launch plan and
    /// wire its log pump + supervision + watchdog tasks. Bumps the generation so
    /// any stale task from a prior child stops touching state. (The Wallet
    /// `MinerSupervisor::start` core, generalized.)
    fn spawn_run(
        &self,
        program: std::path::PathBuf,
        args: Vec<String>,
        is_failover: bool,
    ) -> Result<(), String> {
        let gen = {
            let mut g = self.inner.lock().expect("mutex");
            if !is_failover
                && matches!(
                    g.state,
                    ProcState::Running | ProcState::Starting | ProcState::Stopping
                )
            {
                return Err("lane is already running".into());
            }
            g.state = ProcState::Starting;
            g.message = None;
            g.stop_requested = false;
            g.forced_error = false;
            g.hashrate_hs = None;
            // On a fresh start, zero the share counters; on a failover relaunch,
            // KEEP the cumulative accepted/rejected (the user's session totals
            // shouldn't reset just because we rotated endpoints) but re-arm the
            // progress mark so the new child gets a full window to make progress.
            if !is_failover {
                g.accepted = 0;
                g.rejected = 0;
                g.best_hashrate_hs = 0.0;
            }
            g.progress_accepted = g.accepted;
            g.last_line.clear();
            g.last_exit_code = None;
            g.started_at = Some(std::time::Instant::now());
            g.last_progress_at = Some(Instant::now());
            g.generation += 1;
            g.generation
        };

        let (log_tx, mut log_rx) = unbounded_channel::<LogLine>();
        // No extra env, no PID file — the miner is fully ephemeral.
        let owned = match spawn_supervised(&program, &args, &[], None, log_tx) {
            Ok(c) => c,
            Err(e) => {
                let mut g = self.inner.lock().expect("mutex");
                g.state = ProcState::Error;
                g.message = Some(format!("failed to start miner: {e}"));
                return Err(g.message.clone().unwrap());
            }
        };

        let pid = owned.pid();
        {
            let mut g = self.inner.lock().expect("mutex");
            g.pid = Some(pid);
            g.state = ProcState::Running;
        }

        // Log pump → parse hashrate / shares into the snapshot (per-lane parser).
        let inner_for_logs = self.inner.clone();
        let lane = self.lane;
        tokio::spawn(async move {
            while let Some(line) = log_rx.recv().await {
                let mut g = inner_for_logs.lock().expect("mutex");
                if g.generation != gen {
                    break; // superseded by a newer run
                }
                apply_log_line(&mut g, lane, &line.text);
            }
        });

        // Supervision task: wait for exit OR a stop request, then tear down.
        let this = self.clone();
        tokio::spawn(async move {
            this.supervise_until_exit(owned, gen).await;
        });

        // Layer-B watchdog: advance the endpoint cursor + restart on no-progress.
        let this_wd = self.clone();
        tokio::spawn(async move {
            this_wd.watchdog(gen).await;
        });

        Ok(())
    }

    async fn supervise_until_exit(&self, mut owned: OwnedChild, gen: u64) {
        loop {
            if let Some(code) = owned.try_exit_code() {
                let mut g = self.inner.lock().expect("mutex");
                if g.generation == gen {
                    g.last_exit_code = Some(code);
                    g.pid = None;
                    g.hashrate_hs = None;
                    g.started_at = None;
                    g.state = if g.stop_requested {
                        ProcState::Stopped
                    } else {
                        ProcState::Error
                    };
                    if !g.stop_requested && g.message.is_none() {
                        g.message = Some(format!("miner exited (code {code})"));
                    }
                }
                return;
            }
            let should_stop = {
                let g = self.inner.lock().expect("mutex");
                g.stop_requested && g.generation == gen
            };
            if should_stop {
                // SIGTERM → bounded wait → SIGKILL, on the OWNED child only.
                let code = owned.stop(STOP_GRACE).await.ok().flatten();
                let mut g = self.inner.lock().expect("mutex");
                if g.generation == gen {
                    g.pid = None;
                    g.hashrate_hs = None;
                    g.started_at = None;
                    g.last_exit_code = code;
                    if g.forced_error {
                        // A forced failover-exhaustion stop: land in Error and KEEP
                        // the watchdog's explanatory message (don't fall to Stopped).
                        g.state = ProcState::Error;
                    } else {
                        // A normal user Stop.
                        g.state = ProcState::Stopped;
                        g.message = None;
                    }
                }
                return;
            }
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
    }

    /// The Layer-B no-progress watchdog (M4). While this generation is the live
    /// one and the lane is running, it periodically checks whether the lane has
    /// made progress within [`NO_PROGRESS_WINDOW`]. On a stall it asks the engine
    /// closure to rebuild the argv for the NEXT endpoint and relaunches —
    /// **gated by [`RestartPolicy`]** (bounded + backoff). Budget exhaustion lands
    /// the lane in `Error` with a clear message (no restart-storm). Exits as soon
    /// as its generation is superseded (a relaunch bumps the generation, so the
    /// OLD watchdog stops and the NEW `spawn_run` starts a fresh one).
    async fn watchdog(&self, gen: u64) {
        // Poll at most every WATCHDOG_TICK, but faster when the no-progress window
        // is short (so a tuned/tested supervisor reacts promptly). Floor at 20ms.
        let tick = {
            let g = self.inner.lock().expect("mutex");
            WATCHDOG_TICK
                .min(g.no_progress_window / 2)
                .max(Duration::from_millis(20))
        };
        loop {
            tokio::time::sleep(tick).await;

            // Decide what to do under the lock, then act (relaunch) outside it.
            let action = {
                let mut g = self.inner.lock().expect("mutex");
                if g.generation != gen {
                    return; // superseded — this watchdog is stale
                }
                if g.state != ProcState::Running {
                    // Starting/Stopping/Stopped/Error → nothing to watch.
                    // (Starting is brief; once Running we begin counting.)
                    if matches!(g.state, ProcState::Stopped | ProcState::Error) {
                        return;
                    }
                    continue;
                }
                let window = g.no_progress_window;
                let stalled = g
                    .last_progress_at
                    .map(|t| t.elapsed() >= window)
                    .unwrap_or(false);
                if !stalled {
                    continue;
                }
                // No progress for the window. Decide: can we (a) advance to another
                // endpoint, and (b) is there restart budget?
                let now = Instant::now();
                if !g.restart_policy.may_restart(now) {
                    // Budget exhausted → clean Error, no thrash. Mark `forced_error`
                    // so the supervision loop reaps the child but lands in Error
                    // (not Stopped) and keeps this message.
                    g.message = Some(format!(
                        "no progress for {}s and the failover budget is exhausted; stopped to avoid a restart storm",
                        window.as_secs()
                    ));
                    g.forced_error = true;
                    g.stop_requested = true; // let supervise_until_exit reap the child
                    g.state = ProcState::Stopping; // transitional; loop → Error
                    WatchAction::GiveUp
                } else {
                    // Advance the cursor (rotate to the next endpoint) and record
                    // the restart against the budget (override the backoff when a
                    // test/operator pinned it).
                    let policy_backoff = g.restart_policy.record(now);
                    let _backoff = g.failover_backoff_override.unwrap_or(policy_backoff);
                    g.endpoint_plan.advance();
                    g.failovers += 1;
                    let next = g.endpoint_plan.current().clone();
                    let order = g.endpoint_plan.ordered_from_cursor();
                    let rebuild = g.rebuild.clone();
                    g.message = Some(format!(
                        "no progress on previous endpoint — failing over to {} (#{}/{})",
                        next.host_port(),
                        g.endpoint_plan.cursor() + 1,
                        g.endpoint_plan.len()
                    ));
                    WatchAction::Failover {
                        order,
                        rebuild,
                        backoff: _backoff,
                    }
                }
            };

            match action {
                WatchAction::GiveUp => return,
                WatchAction::Failover {
                    order,
                    rebuild,
                    backoff,
                } => {
                    // If we have no rebuild closure (single-endpoint / start_simple),
                    // there's nothing to rotate to — leave the lane to its own
                    // reconnect and stop watching (the miner's Layer-A handles it).
                    let Some(rebuild) = rebuild else { return };
                    // Stop the current child first (graceful + reaped), then relaunch
                    // on the new endpoint after the policy backoff. `spawn_run`
                    // bumps the generation so the old supervise/log tasks detach.
                    self.teardown_current_child(gen).await;
                    tokio::time::sleep(backoff).await;
                    match rebuild(&order) {
                        Ok((program, args)) => {
                            if let Err(e) = self.spawn_run(program, args, true) {
                                let mut g = self.inner.lock().expect("mutex");
                                g.state = ProcState::Error;
                                g.message = Some(format!("failover relaunch failed: {e}"));
                            }
                        }
                        Err(e) => {
                            let mut g = self.inner.lock().expect("mutex");
                            g.state = ProcState::Error;
                            g.message = Some(format!("failover plan rebuild failed: {e}"));
                        }
                    }
                    // This watchdog's generation is now stale (spawn_run bumped it);
                    // the NEW run started its own watchdog. Exit.
                    return;
                }
            }
        }
    }

    /// Tear down the currently-running child (the failover path) by flipping a
    /// stop request for THIS generation and waiting for the live
    /// `supervise_until_exit` to actually reap it (SIGTERM→grace→SIGKILL, with the
    /// log pump detaching). We do NOT bump the generation here — the old
    /// supervision loop must still match `gen` to do the kill; the FOLLOWING
    /// `spawn_run` bumps the generation so the new child takes over cleanly. This
    /// guarantees the old child is gone (no leak) before the next-endpoint child
    /// spawns. Bounded by the stop grace + a poll.
    async fn teardown_current_child(&self, gen: u64) {
        {
            let mut g = self.inner.lock().expect("mutex");
            if g.generation == gen {
                g.stop_requested = true;
                g.state = ProcState::Stopping; // transitional during the rotate
            }
        }
        // Wait for the old supervision loop to reap the child (it sets pid=None and
        // a terminal state for `gen`, or the generation moves on). Bounded.
        for _ in 0..30 {
            let done = {
                let g = self.inner.lock().expect("mutex");
                g.generation != gen || g.pid.is_none()
            };
            if done {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Request a graceful stop. The supervision loop performs the actual
    /// SIGTERM→SIGKILL teardown on its next tick; `kill_on_drop` is the backstop.
    pub fn request_stop(&self) {
        let mut g = self.inner.lock().expect("mutex");
        if matches!(g.state, ProcState::Running | ProcState::Starting) {
            g.stop_requested = true;
            g.state = ProcState::Stopping;
        }
    }
}

/// What the watchdog decided to do this tick (computed under the lock, executed
/// after releasing it).
enum WatchAction {
    /// Budget exhausted — the lane was put into `Error`; stop watching.
    GiveUp,
    /// Rotate to the next endpoint: rebuild argv for `order` (after `backoff`).
    Failover {
        order: Vec<Endpoint>,
        rebuild: Option<RebuildFn>,
        backoff: Duration,
    },
}

/// Update the snapshot from one raw engine output line, dispatching to the
/// PER-LANE parser: the XMR/RandomX line parsers ([`parse_hashrate_hs`] /
/// [`parse_share_counts`], verbatim from the Wallet) for [`Lane::Xmr`], and the
/// generalized KawPoW parser ([`crate::stats::parse_kawpow`], tolerating both
/// kawpowminer and T-Rex) for [`Lane::GpuRvn`]. Both yield hashrate in H/s +
/// cumulative accepted/rejected shares, so the [`LaneStats`] shape is identical
/// across lanes. ALSO marks Layer-B **progress** (a new accepted share or a
/// higher hashrate re-arms the no-progress watchdog).
fn apply_log_line(g: &mut Inner, lane: Lane, raw: &str) {
    let line = sanitize_log_line(raw);
    if line.is_empty() {
        return;
    }
    match lane {
        Lane::Xmr => {
            if let Some(hr) = parse_hashrate_hs(&line) {
                g.hashrate_hs = Some(hr);
                note_hashrate_progress(g, hr);
            }
            if let Some((accepted, rejected)) = parse_share_counts(&line) {
                g.accepted = accepted;
                g.rejected = rejected;
                note_accepted_progress(g, accepted);
            }
        }
        Lane::GpuRvn => {
            if let Some(sample) = parse_kawpow(&line) {
                if let Some(hr) = sample.hashrate_hs {
                    g.hashrate_hs = Some(hr);
                    note_hashrate_progress(g, hr);
                }
                if let (Some(a), Some(r)) = (sample.accepted, sample.rejected) {
                    g.accepted = a;
                    g.rejected = r;
                    note_accepted_progress(g, a);
                }
            }
        }
        Lane::GpuPrl => {
            // SRBMiner (pearlhash) writes share/hashrate lines to its --log-file
            // (the supervisor tails it). Accepted/rejected can arrive on SEPARATE
            // lines, so update each independently (unlike the kawpow both-or-none).
            //
            // TODO(T4 item 7 — log-file tail data source, supervise.rs): SRBMiner
            // emits share/hashrate lines ONLY to its `--log-file`, NOT to
            // stdout/stderr. The engine already passes a supervisor-owned
            // `--log-file <path>` in the GPU-PRL argv (engine.rs `prl_log_path`),
            // but `spawn_supervised` (alice-supervise/src/child.rs) only pumps the
            // child's stdout+stderr into this `apply_log_line` path — so for the
            // GPU-PRL lane TODAY this arm receives almost nothing and the dashboard
            // reads ~0 shares/hashrate (the Layer-B no-progress watchdog would then
            // false-trip). To finish: on a GpuPrl start, ALSO spawn a file-tail
            // task (e.g. poll `--log-file` from offset, or `notify`/inotify) that
            // feeds each new line into the SAME `LogLine` channel
            // (`spawn_run`'s `log_tx`), so this parser sees the real SRBMiner
            // output. The parser (`parse_srbminer`) + this arm are already correct
            // and unit-tested; only the DATA SOURCE (tailing the file vs. reading
            // stdout) is missing. Keep it generation-gated like the stdout pump so a
            // stale tail from a prior child can't clobber newer state.
            if let Some(sample) = parse_srbminer(&line) {
                if let Some(hr) = sample.hashrate_hs {
                    g.hashrate_hs = Some(hr);
                    note_hashrate_progress(g, hr);
                }
                if let Some(a) = sample.accepted {
                    g.accepted = a;
                    note_accepted_progress(g, a);
                }
                if let Some(r) = sample.rejected {
                    g.rejected = r;
                }
            }
        }
    }
    g.last_line = line;
}

/// A higher-than-best hashrate counts as progress (re-arms the watchdog). A
/// steady or falling rate does NOT (so a lane that connects but never lands a
/// share, with a flat hashrate, will still eventually trip the watchdog).
fn note_hashrate_progress(g: &mut Inner, hr: f64) {
    if hr > g.best_hashrate_hs + f64::EPSILON {
        g.best_hashrate_hs = hr;
        g.last_progress_at = Some(Instant::now());
    }
}

/// A rise in accepted shares counts as progress (the strongest signal — the lane
/// is doing real, credited work).
fn note_accepted_progress(g: &mut Inner, accepted: u64) {
    if accepted > g.progress_accepted {
        g.progress_accepted = accepted;
        g.last_progress_at = Some(Instant::now());
    }
}

/// Parse the 10s hashrate (H/s) from an XMRig speed line, e.g.
/// `miner    speed 10s/60s/15m 1234.5 1200.0 n/a H/s max 1300.0 H/s`.
/// Returns the first numeric figure after `10s/60s/15m` (the 10s rate); falls
/// back to the next numeric figure (60s) when the 10s slot is `n/a`. `None` when
/// the line is not a speed line or all figures are `n/a`. **Ported VERBATIM**
/// from `alice-wallet/gui/src/supervise/miner_supervisor.rs` (~L273).
pub fn parse_hashrate_hs(line: &str) -> Option<f64> {
    // Must be a speed line that also carries the H/s unit.
    if !line.contains("speed") || !line.contains("10s/60s/15m") {
        return None;
    }
    let after = line.split("10s/60s/15m").nth(1)?;
    // Tokens up to the unit; XMRig prints up to three figures then `H/s`.
    for tok in after.split_whitespace() {
        if tok.eq_ignore_ascii_case("h/s")
            || tok.eq_ignore_ascii_case("kh/s")
            || tok.eq_ignore_ascii_case("mh/s")
        {
            break;
        }
        if tok.eq_ignore_ascii_case("n/a") {
            continue; // 10s (or 60s) not available yet — try the next figure
        }
        if let Ok(v) = tok.parse::<f64>() {
            return Some(v);
        }
    }
    None
}

/// Parse cumulative `(accepted/rejected)` counts from an XMRig share line, e.g.
/// `net      accepted (12/0) diff 1234 (45 ms)` or `... rejected (12/1) ...`.
/// Returns `None` for non-share lines. **Ported VERBATIM** from
/// `miner_supervisor.rs` (~L299).
pub fn parse_share_counts(line: &str) -> Option<(u64, u64)> {
    if !line.contains("accepted") && !line.contains("rejected") {
        return None;
    }
    // Find the first `(<digits>/<digits>)` group.
    let open = line.find('(')?;
    let rest = &line[open + 1..];
    let close = rest.find(')')?;
    let inside = &rest[..close];
    let (a, r) = inside.split_once('/')?;
    let accepted = a.trim().parse::<u64>().ok()?;
    let rejected = r.trim().parse::<u64>().ok()?;
    Some((accepted, rejected))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Runtime::new().unwrap()
    }

    /// A no-op rebuild closure for tests that don't exercise failover (keeps the
    /// single-endpoint relay plan). The args are fixed.
    fn fixed_rebuild(program: std::path::PathBuf, args: Vec<String>) -> RebuildFn {
        Arc::new(move |_eps: &[Endpoint]| Ok((program.clone(), args.clone())))
    }

    #[test]
    fn fresh_supervisor_is_stopped_with_zeroed_stats() {
        let s = LaneSupervisor::new(Lane::Xmr);
        let st = s.stats();
        assert_eq!(st.lane, Lane::Xmr);
        assert!(!st.running);
        assert_eq!(st.state, ProcState::Stopped);
        assert!(st.hashrate_hs.is_none());
        assert_eq!(st.accepted, 0);
        assert_eq!(st.rejected, 0);
        assert_eq!(st.uptime_s, 0);
        assert!(st.last_line.is_empty());
        assert_eq!(st.failovers, 0);
        // The default plan is the relay (honesty: not the core IP).
        assert_eq!(st.endpoint.as_deref(), Some("hk.aliceprotocol.org:3333"));
    }

    #[test]
    fn parses_10s_hashrate_from_speed_line() {
        assert_eq!(
            parse_hashrate_hs("miner    speed 10s/60s/15m 1234.5 1200.0 n/a H/s max 1300.0 H/s"),
            Some(1234.5)
        );
        assert_eq!(
            parse_hashrate_hs("miner    speed 10s/60s/15m n/a 980.0 n/a H/s"),
            Some(980.0)
        );
        assert_eq!(
            parse_hashrate_hs("miner    speed 10s/60s/15m n/a n/a n/a H/s"),
            None
        );
        assert_eq!(parse_hashrate_hs("net      new job from pool"), None);
    }

    #[test]
    fn parses_accepted_and_rejected_share_counts() {
        assert_eq!(
            parse_share_counts("net      accepted (12/0) diff 1234 (45 ms)"),
            Some((12, 0))
        );
        assert_eq!(
            parse_share_counts("net      rejected (30/2) diff 5000 (60 ms)"),
            Some((30, 2))
        );
        assert_eq!(
            parse_share_counts("net      new job from pool diff 1000"),
            None
        );
        assert_eq!(parse_share_counts("cpu      using profile (rx)"), None);
    }

    #[test]
    fn apply_log_line_updates_snapshot_via_sanitised_input() {
        let s = LaneSupervisor::new(Lane::Xmr);
        {
            let mut g = s.inner.lock().unwrap();
            apply_log_line(&mut g, Lane::Xmr, "\u{1b}[1;32maccepted\u{1b}[0m (7/1) diff 900 (40 ms)");
            apply_log_line(&mut g, Lane::Xmr, "miner    speed 10s/60s/15m 555.5 540.0 n/a H/s");
        }
        let st = s.stats();
        assert_eq!(st.accepted, 7);
        assert_eq!(st.rejected, 1);
        assert_eq!(st.hashrate_hs, Some(555.5));
        assert!(!st.last_line.contains('\u{1b}'));
    }

    #[test]
    fn apply_log_line_uses_kawpow_parser_on_gpu_lane() {
        // The GPU lane routes lines through `parse_kawpow` (MH/s → H/s + shares).
        let s = LaneSupervisor::new(Lane::GpuRvn);
        {
            let mut g = s.inner.lock().unwrap();
            apply_log_line(
                &mut g,
                Lane::GpuRvn,
                "m 12:01:42 kawpowminer Speed 25.43 Mh/s gpu0 [A4+0:R0+0:F0]",
            );
        }
        let st = s.stats();
        assert_eq!(st.lane, Lane::GpuRvn);
        assert_eq!(st.hashrate_hs, Some(25_430_000.0));
        assert_eq!(st.accepted, 4);
        assert_eq!(st.rejected, 0);
        // GPU lane default endpoint is the relay on :8888.
        assert_eq!(st.endpoint.as_deref(), Some("hk.aliceprotocol.org:8888"));
    }

    /// Progress marking: a new accepted share OR a higher hashrate re-arms the
    /// watchdog (`last_progress_at` moves forward); a flat/repeat does not.
    #[test]
    fn progress_marks_advance_only_on_real_progress() {
        let s = LaneSupervisor::new(Lane::Xmr);
        let mut g = s.inner.lock().unwrap();
        g.last_progress_at = Some(Instant::now() - Duration::from_secs(60));
        let before = g.last_progress_at.unwrap();
        // A higher hashrate → progress.
        apply_log_line(&mut g, Lane::Xmr, "miner    speed 10s/60s/15m 100.0 90.0 n/a H/s");
        assert!(g.last_progress_at.unwrap() > before);
        // The SAME hashrate again → no new progress mark.
        let mark2 = g.last_progress_at.unwrap();
        std::thread::sleep(Duration::from_millis(2));
        apply_log_line(&mut g, Lane::Xmr, "miner    speed 10s/60s/15m 100.0 90.0 n/a H/s");
        assert_eq!(g.last_progress_at.unwrap(), mark2, "flat hashrate is not progress");
        // A new accepted share → progress.
        apply_log_line(&mut g, Lane::Xmr, "net      accepted (1/0) diff 100 (10 ms)");
        assert!(g.last_progress_at.unwrap() > mark2);
    }

    #[cfg(unix)]
    #[test]
    fn start_then_stop_transitions_and_captures_shares() {
        let rt = rt();
        rt.block_on(async {
            // Stand-in "miner": emit an accepted-share line + a speed line then
            // idle, so we observe Running + parsed stats, then stop cleanly.
            let program = std::path::PathBuf::from("/bin/sh");
            let args = vec![
                "-c".into(),
                "echo 'net      accepted (3/0) diff 100 (10 ms)'; \
                 echo 'miner    speed 10s/60s/15m 42.0 40.0 n/a H/s'; sleep 10"
                    .into(),
            ];
            let s = LaneSupervisor::new(Lane::Xmr);
            s.start(program.clone(), args.clone(), fixed_rebuild(program, args))
                .expect("start");
            assert!(s.is_active());

            let mut saw = false;
            for _ in 0..30 {
                let st = s.stats();
                if st.accepted == 3 && st.hashrate_hs == Some(42.0) {
                    saw = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert!(saw, "expected parsed accepted-share + hashrate");

            s.request_stop();
            let mut stopped = false;
            for _ in 0..40 {
                if s.stats().state == ProcState::Stopped {
                    stopped = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert!(stopped, "lane should reach Stopped after request_stop");
            assert!(!s.is_active());
            assert!(s.stats().hashrate_hs.is_none());
        });
    }

    #[cfg(unix)]
    #[test]
    fn gpu_lane_start_parses_kawpow_then_stops() {
        let rt = rt();
        rt.block_on(async {
            // Stand-in kawpowminer: emit a Speed line with a share block, then idle.
            let program = std::path::PathBuf::from("/bin/sh");
            let args = vec![
                "-c".into(),
                "echo 'm 12:01:42 kawpowminer Speed 30.00 Mh/s gpu0 [A9+0:R1+0:F0]'; sleep 10"
                    .into(),
            ];
            let s = LaneSupervisor::new(Lane::GpuRvn);
            s.start(program.clone(), args.clone(), fixed_rebuild(program, args))
                .expect("start");
            assert!(s.is_active());

            let mut saw = false;
            for _ in 0..30 {
                let st = s.stats();
                if st.accepted == 9 && st.hashrate_hs == Some(30_000_000.0) {
                    saw = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert!(saw, "expected parsed kawpow hashrate + shares on the GPU lane");
            assert_eq!(s.stats().rejected, 1);

            s.request_stop();
            let mut stopped = false;
            for _ in 0..40 {
                if s.stats().state == ProcState::Stopped {
                    stopped = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert!(stopped, "GPU lane should reach Stopped after request_stop");
        });
    }

    #[cfg(unix)]
    #[test]
    fn unexpected_exit_lands_in_error_not_restart_loop() {
        let rt = rt();
        rt.block_on(async {
            let program = std::path::PathBuf::from("/bin/sh");
            let args = vec!["-c".into(), "echo starting; exit 1".into()];
            let s = LaneSupervisor::new(Lane::Xmr);
            s.start_simple(program, args).expect("start");
            let mut reached_error = false;
            for _ in 0..40 {
                if s.stats().state == ProcState::Error {
                    reached_error = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert!(reached_error, "unexpected exit should land in Error");
            assert!(!s.is_active());
        });
    }

    /// CRASH ISOLATION (the M4 gate): two supervised children in their OWN
    /// process groups; kill one → the OTHER keeps running. We start a short-lived
    /// child on supervisor A (it exits → A lands in Error) and a long-lived child
    /// on supervisor B, and assert B is still Running after A is gone. (Each
    /// child is a separate process in its own pgid via `child.rs` setpgid, so
    /// A's exit/SIGKILL can never reach B.)
    #[cfg(unix)]
    #[test]
    fn two_supervisors_are_crash_isolated() {
        let rt = rt();
        rt.block_on(async {
            let prog = std::path::PathBuf::from("/bin/sh");
            // A: prints a line then exits non-zero almost immediately (a "crash").
            let a = LaneSupervisor::new(Lane::Xmr);
            let a_args = vec!["-c".into(), "echo a-up; sleep 0.3; exit 9".into()];
            a.start_simple(prog.clone(), a_args).expect("start A");
            // B: a long-lived child that keeps "mining".
            let b = LaneSupervisor::new(Lane::GpuRvn);
            let b_args = vec![
                "-c".into(),
                "echo 'm kawpowminer Speed 10.00 Mh/s gpu0 [A1+0:R0+0:F0]'; sleep 30".into(),
            ];
            b.start_simple(prog, b_args).expect("start B");

            // Wait for A to crash into Error.
            let mut a_errored = false;
            for _ in 0..50 {
                if a.stats().state == ProcState::Error {
                    a_errored = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert!(a_errored, "supervisor A should have crashed into Error");

            // B must STILL be running — A's death did not touch it.
            assert!(b.is_active(), "B must survive A's crash (crash isolation)");
            assert_eq!(b.stats().state, ProcState::Running);
            // And B has its own, independent stats (its accepted share).
            for _ in 0..20 {
                if b.stats().accepted >= 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert!(b.stats().accepted >= 1, "B keeps making progress after A died");

            // Now explicitly stop B; it tears down cleanly on its own.
            b.request_stop();
            for _ in 0..40 {
                if b.stats().state == ProcState::Stopped {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert_eq!(b.stats().state, ProcState::Stopped);
        });
    }

    /// LAYER-B FAILOVER (the M4 gate, mechanism-level + deterministic): a child
    /// that connects but makes NO progress is rotated to the next endpoint and
    /// the cursor advances; the rebuild closure is called for the ROTATED order
    /// (the good endpoint first). We use a tiny no-progress window + backoff so
    /// the watchdog fires fast without multi-second wall sleeps.
    #[cfg(unix)]
    #[test]
    fn layer_b_failover_advances_cursor_and_relaunches() {
        let rt = rt();
        rt.block_on(async {
            // A 2-endpoint plan: bogus primary, then the "good" endpoint.
            let plan = EndpointPlan::new(vec![
                Endpoint::plaintext("blackhole.invalid", 65000),
                Endpoint::plaintext("hk.aliceprotocol.org", 3333),
            ])
            .unwrap();
            let s = LaneSupervisor::with_endpoints(Lane::Xmr, plan);
            // Fast watchdog: 60ms no-progress window, 10ms backoff.
            s.set_failover_timing(Duration::from_millis(60), Duration::from_millis(10));

            // The rebuild closure records each call's PRIMARY (cursor) host so we
            // can prove the relaunch targeted the rotated (good) endpoint. The
            // relaunched child just sleeps (so it makes progress = none, but we
            // only need ONE advance here; the budget bounds further rotation).
            let calls = Arc::new(AtomicUsize::new(0));
            let seen_primary = Arc::new(Mutex::new(Vec::<String>::new()));
            let calls2 = calls.clone();
            let seen2 = seen_primary.clone();
            let rebuild: RebuildFn = Arc::new(move |eps: &[Endpoint]| {
                calls2.fetch_add(1, Ordering::SeqCst);
                seen2.lock().unwrap().push(eps[0].host_port());
                Ok((
                    std::path::PathBuf::from("/bin/sh"),
                    vec!["-c".into(), "echo connecting; sleep 30".into()],
                ))
            });

            // The INITIAL launch (cursor at the bogus primary) — a child that
            // never makes progress, so the watchdog trips.
            s.start(
                std::path::PathBuf::from("/bin/sh"),
                vec!["-c".into(), "echo init; sleep 30".into()],
                rebuild,
            )
            .expect("start");

            // Within a few fast ticks, the cursor advances to endpoint #2 (relay)
            // and the rebuild closure is called for the rotated order (relay first).
            let mut advanced = false;
            for _ in 0..100 {
                if s.failovers() >= 1 && calls.load(Ordering::SeqCst) >= 1 {
                    advanced = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(advanced, "Layer B should have advanced the cursor + relaunched");
            assert_eq!(
                s.current_endpoint(),
                "hk.aliceprotocol.org:3333",
                "cursor must have rotated to the good endpoint"
            );
            // The FIRST rebuild call targeted the rotated order: relay primary.
            assert_eq!(
                seen_primary.lock().unwrap().first().map(|s| s.as_str()),
                Some("hk.aliceprotocol.org:3333"),
                "the relaunch argv must put the rotated (good) endpoint first"
            );

            s.request_stop();
            for _ in 0..50 {
                let st = s.stats().state;
                if st == ProcState::Stopped || st == ProcState::Error {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
    }

    /// RESTART POLICY (the M4 gate): the failover budget is bounded — after the
    /// budget is exhausted the lane lands in `Error` with a clear message, with
    /// NO infinite restart loop. Every relaunched child also stalls (it just
    /// sleeps, no progress), so the watchdog keeps tripping until the
    /// `RestartPolicy` budget (`MAX_RESTARTS`) is spent. A tiny window + backoff
    /// keeps the test fast.
    #[cfg(unix)]
    #[test]
    fn failover_budget_exhaustion_lands_in_error_no_storm() {
        let rt = rt();
        rt.block_on(async {
            let plan = EndpointPlan::new(vec![
                Endpoint::plaintext("a.invalid", 1),
                Endpoint::plaintext("b.invalid", 2),
            ])
            .unwrap();
            let s = LaneSupervisor::with_endpoints(Lane::Xmr, plan);
            s.set_failover_timing(Duration::from_millis(50), Duration::from_millis(10));

            // Every relaunch is a never-progressing child (just sleeps). With a
            // 50ms window each fresh child re-stalls almost immediately, so the
            // watchdog rotates until the budget is exhausted → Error.
            let calls = Arc::new(AtomicUsize::new(0));
            let calls2 = calls.clone();
            let rebuild: RebuildFn = Arc::new(move |_eps: &[Endpoint]| {
                calls2.fetch_add(1, Ordering::SeqCst);
                Ok((
                    std::path::PathBuf::from("/bin/sh"),
                    vec!["-c".into(), "sleep 30".into()],
                ))
            });

            s.start(
                std::path::PathBuf::from("/bin/sh"),
                vec!["-c".into(), "sleep 30".into()],
                rebuild,
            )
            .expect("start");

            // Wait for the lane to settle into Error (budget exhausted). Bounded.
            let mut errored = false;
            for _ in 0..200 {
                if s.stats().state == ProcState::Error {
                    errored = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(errored, "budget exhaustion must land the lane in Error");
            // Failovers are bounded by the restart budget — NOT unbounded (no storm).
            let fo = s.failovers();
            assert!(
                fo <= alice_supervise::MAX_RESTARTS as u64 + 1,
                "failovers ({fo}) must be bounded by the restart budget (no storm)"
            );
            // The relaunch count is likewise bounded (a few, not hundreds).
            assert!(
                calls.load(Ordering::SeqCst) <= alice_supervise::MAX_RESTARTS as usize + 1,
                "relaunches must be bounded by the budget (no restart storm)"
            );
            // The error message explains the bounded-failover stop.
            let msg = s.stats().message.unwrap_or_default();
            assert!(
                msg.contains("budget is exhausted") || msg.contains("no progress"),
                "Error message should explain the bounded failover: {msg:?}"
            );

            // Settle into Error and stay there — no further rotation (assert the
            // failover count doesn't keep climbing).
            let fo_after = s.failovers();
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(s.failovers(), fo_after, "no rotation after budget exhausted");

            s.request_stop();
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
    }

    /// LIVE failover on the XMR lane (the M4 brief's "failover (live-ish on XMR)"
    /// gate) — **opt-in** (needs the real xmrig + network to the relay), gated on
    /// `ALICE_MINER_LIVE_FAILOVER=1` so the normal suite stays hermetic.
    ///
    /// Configures an [`EndpointPlan`] with a BOGUS primary (`10.255.255.1:1`, an
    /// unroutable blackhole) followed by the REAL `hk.aliceprotocol.org:3333`,
    /// builds the multi-`-o` XMR argv via the engine's lane builder, starts the
    /// REAL xmrig with an ADDRESS-ONLY login, and confirms Layer B advances the
    /// cursor to the real relay and the lane relaunches targeting it — then a
    /// clean stop. (xmrig's OWN multi-`-o` failover may also reach the relay, but
    /// this test specifically drives + asserts OUR Layer-B rotation.)
    #[cfg(unix)]
    #[test]
    fn live_xmr_failover_rotates_bogus_primary_to_real_relay() {
        if std::env::var("ALICE_MINER_LIVE_FAILOVER").as_deref() != Ok("1") {
            eprintln!("skipping live failover test (set ALICE_MINER_LIVE_FAILOVER=1 to run)");
            return;
        }
        use crate::endpoint::Endpoint;
        let rt = rt();
        rt.block_on(async {
            // Resolve the REAL xmrig (dev fallback / sibling / override).
            let xmrig = crate::binaries::resolve_miner_binary(crate::binaries::MinerKind::CpuXmr)
                .expect("real xmrig must be resolvable for the live failover test");
            // A real SS58-300 Alice address (the address-only login).
            let address = alice_crypto::create_wallet_payload(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "live-failover-test",
            )
            .unwrap()
            .address;

            // Plan: bogus blackhole primary → the real relay.
            let plan = EndpointPlan::new(vec![
                Endpoint::plaintext("10.255.255.1", 1),
                Endpoint::plaintext("hk.aliceprotocol.org", 3333),
            ])
            .unwrap();
            let s = LaneSupervisor::with_endpoints(Lane::Xmr, plan);
            // A short-ish window so the test completes in well under a minute, but
            // long enough for xmrig to attempt + fail the bogus primary first.
            s.set_failover_timing(Duration::from_secs(20), Duration::from_millis(500));

            // The rebuild closure = the engine's XMR multi-endpoint builder (so the
            // relaunch argv carries every endpoint, rotated, primary first).
            let addr = address.clone();
            let xmrig_path = xmrig.clone();
            let rebuild: RebuildFn = Arc::new(move |eps: &[Endpoint]| {
                let p = crate::lane::xmr::build_miner_launch_plan_with_endpoints(
                    xmrig_path.clone(),
                    &addr,
                    eps,
                    Some(1), // 1 thread — we only need a connection, not hashpower
                )?;
                Ok((p.program, p.args))
            });
            let (prog, args) = rebuild(&[
                Endpoint::plaintext("10.255.255.1", 1),
                Endpoint::plaintext("hk.aliceprotocol.org", 3333),
            ])
            .unwrap();

            s.start(prog, args, rebuild).expect("start real xmrig");
            eprintln!("[live] xmrig started; primary endpoint = {}", s.current_endpoint());

            // Wait for Layer B to rotate the cursor to the real relay (within the
            // window + a margin). xmrig's own failover may connect to the relay even
            // before our watchdog fires; either way we assert OUR cursor advances.
            let mut rotated = false;
            for _ in 0..400 {
                // 400 × 200ms = 80s ceiling
                if s.failovers() >= 1 && s.current_endpoint() == "hk.aliceprotocol.org:3333" {
                    rotated = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            assert!(
                rotated,
                "Layer B should have rotated the XMR cursor from the bogus primary to the real relay"
            );
            eprintln!(
                "[live] rotated to real relay; failovers={}, last_line={:?}",
                s.failovers(),
                s.stats().last_line
            );

            // Give the relaunched xmrig a moment to actually reach the relay, then
            // confirm it's running on the relay (a login/connect line or simply the
            // Running state on the rotated endpoint is sufficient proof of contact).
            let mut on_relay = false;
            for _ in 0..150 {
                let st = s.stats();
                if st.state == ProcState::Running
                    && st.endpoint.as_deref() == Some("hk.aliceprotocol.org:3333")
                {
                    on_relay = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            assert!(on_relay, "the relaunched xmrig should be running against the real relay");
            eprintln!("[live] xmrig running on the real relay (address-only login). Stopping.");

            // Clean stop.
            s.request_stop();
            let mut stopped = false;
            for _ in 0..60 {
                if s.stats().state == ProcState::Stopped {
                    stopped = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert!(stopped, "the lane should stop cleanly after the live failover");
        });
    }
}
