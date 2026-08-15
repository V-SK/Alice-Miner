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
//!     no hashrate progress for [`NO_PROGRESS_WINDOW`] (~600s), it advances the
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

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};

use alice_supervise::child::{spawn_supervised, LogLine, LogStream, OwnedChild};
use alice_supervise::{sanitize_log_line, ProcState, RestartPolicy, RetryLadder};

use crate::acceptance::{
    self, AcceptanceConfig, AcceptanceMonitor, Attribution, Collapse, LaneVerdict,
};
use crate::endpoint::{Endpoint, EndpointPlan};
use crate::lane::Lane;
use crate::stats::parse_kawpow;
use crate::stats::parse_srbminer;
use crate::stats::{parse_generic, ParserKind};

/// Grace period for a graceful miner stop before SIGKILL (verbatim from Wallet).
const STOP_GRACE: Duration = Duration::from_secs(5);

/// Layer-B failover window: if the lane makes no progress (no new accepted share
/// AND no hashrate increase) for this long, the watchdog advances the endpoint
/// cursor and restarts on the next endpoint.
///
/// Sized from a LIVE measurement (2026-06-26 — shipped v0.3.0 SRBMiner `pearlhash`
/// on an RTX A4000 vs `us.aliceprotocol.org:3340`, credit-only): the PRL pool is
/// low-traffic and after warm-up the hashrate plateaus, so ONLY new accepted
/// shares mark progress. Observed accepted-share gaps ranged 6–110s, with the max
/// (110s) sitting right at the old 120s window — on weaker GPUs / after a vardiff
/// difficulty bump, gaps routinely exceed 120s, which spuriously tripped this
/// watchdog and caused region churn (each failover costs a ~15s SRBMiner re-init
/// and the lane never settles). 600s gives comfortable headroom for a
/// healthy-but-slow lane (any device, weak GPUs included) while still catching a
/// genuinely dead endpoint within 10 min; a hard disconnect is caught sooner by
/// the engine's own connection handling. Generous so it never trips during normal
/// warm-up or slow-pool operation.
pub const NO_PROGRESS_WINDOW: Duration = Duration::from_secs(600);

/// How often the watchdog wakes to check progress. Cheap; just compares the
/// stored progress timestamp against `NO_PROGRESS_WINDOW`.
const WATCHDOG_TICK: Duration = Duration::from_secs(2);

/// Per-candidate TCP-connect timeout for the failover PRE-FLIGHT probe. Before Layer
/// B commits a failover it probes the candidate region(s) and rotates to the first
/// REACHABLE one — so it never switches into a dead region and immediately errors
/// (the exact symptom an external tester hit: auto-switching to an unavailable
/// region and stopping). Kept short so a genuinely dead lane still fails over
/// promptly; if NO candidate answers we fall back to the plain next endpoint (no
/// worse than the pre-probe behaviour).
const FAILOVER_PROBE_TIMEOUT: Duration = Duration::from_millis(1200);

/// How often the `nvidia-smi` telemetry fallback polls (throttled — not every frame).
/// One lightweight query every ~5s is plenty for a temp/power/fan readout and keeps the
/// subprocess overhead negligible even on a many-hour run.
const NVIDIA_TELEMETRY_POLL: Duration = Duration::from_secs(5);

/// Bound on the `nvidia-smi` query so a wedged driver can never stall the poll task.
const NVIDIA_TELEMETRY_TIMEOUT: Duration = Duration::from_secs(4);

/// A closure the engine supplies that (re)builds the `(program, args)` launch
/// plan for a given ORDERED endpoint list. Lets the supervisor rebuild the
/// per-endpoint argv on a Layer-B failover without knowing any lane specifics —
/// the lane modules ([`crate::lane::xmr`] / [`crate::lane::gpu_rvn`]) own the
/// actual arg shape; the supervisor only knows "rebuild for these endpoints".
/// Returns the new `(program, args)` (Layer-A multi-endpoint, rotated so the new
/// cursor is primary). `Send + Sync` so the watchdog task can call it.
pub type RebuildFn =
    Arc<dyn Fn(&[Endpoint]) -> Result<(std::path::PathBuf, Vec<String>), String> + Send + Sync>;

/// Structured arguments for a machine-keyed lane status ([`LaneStats::message_key`]
/// / [`crate::engine::Snapshot::message_key`]). Carried ALONGSIDE the human
/// `message` string so a front-end can (re)render the status in ITS OWN language at
/// draw time instead of being stuck with the locale the string was baked in — the
/// i18n boundary fix (a `zh` CLI must not force `zh` text into an `en` GUI). Every
/// field is optional + `skip`-when-`None`, so the wire JSON is additive and an older
/// stream (no key) deserializes cleanly to `None` (the GUI then falls back to
/// parsing the raw `message`). See [`status_short`] / [`status_tooltip`] /
/// [`status_from_legacy`].
// `Eq` was dropped when `accept_pct` (an `f64`) joined: a measured rate is a real
// number and rounding it to keep a marker trait would be the tail wagging the dog.
// Nothing compares `StatusArgs` for total equality — `Snapshot`, which embeds it, is
// itself only `PartialEq` (it has carried `f64` hashrates since day one).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct StatusArgs {
    /// The full active endpoint (`host:port`) — for the tooltip / diagnostics, never
    /// the crowded first status line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// A SHORT label for the (primary / stalled) region or pool — a region tag
    /// (`us` / `asia`) for a PRL region relay, else the endpoint's first host label
    /// upper-cased (`hk.aliceprotocol.org` → `HK`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// The SHORT label for the failover TARGET region (auto-failover only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_region: Option<String>,
    /// The no-progress window that tripped the watchdog, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stalled_s: Option<u64>,
    /// The engine child's RAW exit code for a crash status. Kept as the number (not a
    /// baked sentence) so a front-end can translate it in ITS OWN language via
    /// [`exit_code_explanation`] — same reason `message_key` exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Seconds until the PENDING automatic retry fires. Counts down while the lane
    /// waits, so "stopped" is never silent — the user always sees the next attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_in_s: Option<u64>,
    /// The 1-based number of the pending retry attempt (the escalating-backoff rung).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<u32>,
    /// How many times the ENGINE has exited on its own since this lane was started —
    /// the third-party-engine crash counter (SRBMiner's heap-corruption aborts are the
    /// observed case), so a support report / the telemetry snapshot carries a frequency
    /// and not just "it died once".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crashes: Option<u64>,
    /// LAYER 3: the run's accepted / rejected share totals behind an acceptance-halt
    /// status. Carried as the raw numbers (not a baked sentence) for the same reason
    /// every other field here is — a front-end renders them in its own language.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shares_accepted: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shares_rejected: Option<u64>,
    /// The MEASURED acceptance rate in percent. `None` means "not measured" and must
    /// render as "—"; it is never 0-as-a-placeholder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_pct: Option<f64>,
}

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
    /// The 60s + 15m hashrate windows (H/s) — populated ONLY for xmrig (its
    /// `speed 10s/60s/15m` line is the one engine that reports them); `None` for
    /// every GPU lane and for an xmrig window still printing `n/a`. Never fabricated.
    pub hashrate_60s_hs: Option<f64>,
    pub hashrate_15m_hs: Option<f64>,
    /// Running count of accepted shares (latest `(A/R)` figure).
    pub accepted: u64,
    /// Running count of rejected shares (latest `(A/R)` figure).
    pub rejected: u64,
    /// Last process exit code, when it has exited.
    pub last_exit_code: Option<i32>,
    /// Short, sanitised reason for the current state, if any (human, baked at the
    /// locale that produced it — use [`Self::message_key`] to re-localize).
    pub message: Option<String>,
    /// Machine key for a re-localizable status ([`status_short`] keys), when the
    /// current `message` is one of the Layer-B failover / endpoint-lock statuses;
    /// `None` for a free-form message. Lets a front-end render the status in ITS own
    /// language regardless of the locale that produced `message`.
    pub message_key: Option<String>,
    /// Structured arguments for [`Self::message_key`].
    pub message_args: Option<StatusArgs>,
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
    /// GPU core temperature in °C, if the engine reported it (parsed from stdout) OR
    /// a best-effort `nvidia-smi` fallback filled it. `None` when unavailable (a CPU
    /// lane, an engine that doesn't report it with no NVIDIA fallback, or Apple/AMD).
    /// On a multi-GPU rig this is the HOTTEST card's reading (the safety-relevant one).
    pub temp_c: Option<f64>,
    /// GPU board power draw in watts, same sourcing/semantics as [`Self::temp_c`].
    pub power_w: Option<f64>,
    /// GPU utilization percent (0..=100), same sourcing as [`Self::temp_c`].
    pub util_pct: Option<f64>,
    /// GPU fan speed percent (0..=100), same sourcing as [`Self::temp_c`].
    pub fan_pct: Option<f64>,
    /// How many times the ENGINE child exited on its own (crashed / self-exited)
    /// since this lane was started. Never reset by an automatic restart — it is the
    /// third-party-engine crash FREQUENCY, which is the number worth reporting.
    pub crashes: u64,
    /// Seconds until the pending automatic restart fires, when one is scheduled.
    /// `None` when the lane is not waiting to retry.
    pub retry_in_s: Option<u64>,
    /// The acceptance verdict's machine key ([`LaneVerdict::key`]): `warmup`,
    /// `unknown`, `gathering`, `healthy`, `degrading`, `collapsed`.
    pub acceptance: &'static str,
    /// The MEASURED share-acceptance rate in percent, or `None` when this machine has
    /// not measured one — during warm-up, before a period completes, or on a lane
    /// whose engine cannot report rejections at all. A front-end renders `None` as
    /// "—". It is NEVER 0-as-a-placeholder: on this project, an unknown that renders
    /// as a number is the bug.
    pub accept_pct: Option<f64>,
    /// The lane was stopped by the acceptance guard (not a crash, not a user stop).
    /// Nothing will restart it automatically.
    pub halted: bool,
}

impl LaneStats {
    fn stopped(lane: Lane) -> Self {
        Self {
            lane,
            running: false,
            state: ProcState::Stopped,
            hashrate_hs: None,
            hashrate_60s_hs: None,
            hashrate_15m_hs: None,
            accepted: 0,
            rejected: 0,
            last_exit_code: None,
            message: None,
            message_key: None,
            message_args: None,
            last_line: String::new(),
            uptime_s: 0,
            endpoint: None,
            failovers: 0,
            temp_c: None,
            power_w: None,
            util_pct: None,
            fan_pct: None,
            crashes: 0,
            retry_in_s: None,
            acceptance: "warmup",
            accept_pct: None,
            halted: false,
        }
    }
}

/// Shared, lock-guarded supervisor state. Cloneable handle. (Mirrors the
/// Wallet's `MinerSupervisor` shape; generalized over [`Lane`] + endpoints.)
#[derive(Clone)]
pub struct LaneSupervisor {
    lane: Lane,
    /// Which log parser drives this lane's stats. Derived from the lane for a
    /// BUNDLED engine ([`ParserKind::for_lane`]); a CUSTOM (bring-your-own) miner
    /// overrides it with its preset's parser (a lane no longer implies one format).
    parser: ParserKind,
    /// An explicit log-file path to TAIL for a miner that writes its share/hashrate
    /// stats ONLY to a file (SRBMiner + custom file-logging miners). `None` for a
    /// stdout miner. When `None` the bundled GPU-PRL lane still falls back to
    /// extracting `--log-file` from the argv (unchanged behavior).
    log_tail: Option<std::path::PathBuf>,
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    state: ProcState,
    pid: Option<u32>,
    last_exit_code: Option<i32>,
    message: Option<String>,
    /// Machine key + args mirroring `message` for a re-localizable Layer-B status
    /// (see [`LaneStats::message_key`]). Kept in lock-step with `message`: set together
    /// where a failover / lock status is produced, cleared together on recovery / restart.
    message_key: Option<String>,
    message_args: Option<StatusArgs>,
    hashrate_hs: Option<f64>,
    /// The 60s + 15m hashrate windows (H/s), populated ONLY for an engine that
    /// actually reports them — xmrig's `speed 10s/60s/15m` line. `None` for every
    /// GPU lane (SRBMiner / kawpow / alpha report a single instantaneous rate), and
    /// `None` while xmrig still prints `n/a` for that window during warm-up. NEVER
    /// fabricated from the 10s figure — a window we didn't measure stays `None`.
    hashrate_60s_hs: Option<f64>,
    hashrate_15m_hs: Option<f64>,
    /// Latest GPU hardware telemetry (hottest card), last-wins. Populated from the
    /// engine's own stdout when it reports it, else by the best-effort `nvidia-smi`
    /// fallback poller ([`spawn_nvidia_telemetry_poll`]). `None` when unavailable.
    /// The engine-parsed value always takes precedence over the fallback within a tick
    /// (a real reading beats a smi guess).
    telem_temp_c: Option<f64>,
    telem_power_w: Option<f64>,
    telem_util_pct: Option<f64>,
    telem_fan_pct: Option<f64>,
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

    // ── BUG#4: automatic, never-terminal recovery ───────────────────────────────
    /// The escalating backoff for AUTOMATIC restarts after a crash / stall. Unlike
    /// [`Self::restart_policy`] (a bounded budget that gates the FAST failover loop)
    /// this one never runs out — it only gets slower, and is walked back down by real
    /// mining. See [`alice_supervise::RetryLadder`].
    retry_ladder: RetryLadder,
    /// The launch plan of the CURRENT/last run, so an automatic restart can relaunch
    /// even without a `rebuild` closure (`start_simple`). When `rebuild` IS present it
    /// wins — a GPU-PRL argv carries a region-bound PoP token that must be re-minted,
    /// so replaying a stale argv would be rejected by the relay.
    last_launch: Option<(std::path::PathBuf, Vec<String>)>,
    /// The pid of the engine child of the run that just ended, so the retry task can
    /// VERIFY the process tree is really gone before spawning a replacement (never
    /// two engines on one GPU).
    last_child_pid: Option<u32>,
    /// Monotonic token identifying the CURRENTLY-pending automatic retry. Any new
    /// `spawn_run`, or a user `request_stop`, bumps it — which is how a pending retry
    /// is cancelled without racing (the retry task re-checks it under the lock).
    retry_token: u64,
    /// When the pending automatic retry is due (drives the visible countdown), and
    /// whether one is pending at all.
    retry_at: Option<Instant>,
    /// How many times the ENGINE child exited on its own since this lane was started.
    crashes: u64,
    /// Override for the automatic-restart backoff. `None` ⇒ use the [`RetryLadder`]
    /// (production). `Some(d)` ⇒ a fixed, tiny delay so the crash-recovery tests can
    /// exercise several restarts without waiting out the real 5s…30min ladder.
    retry_backoff_override: Option<Duration>,
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
    /// [`NO_PROGRESS_WINDOW`] (~600s); tunable (tests use a tiny value for speed).
    no_progress_window: Duration,
    /// Override for the per-failover backoff. `None` ⇒ use the [`RestartPolicy`]'s
    /// growing backoff (production). `Some(d)` ⇒ a fixed backoff (tests use a tiny
    /// value so the failover loop runs fast without multi-second wall sleeps).
    failover_backoff_override: Option<Duration>,
    /// The per-candidate TCP-connect timeout the watchdog uses to PRE-FLIGHT a
    /// failover target (so it never rotates into a dead region). Defaults to
    /// [`FAILOVER_PROBE_TIMEOUT`]; [`Self::set_failover_timing`] shrinks it so the
    /// failover tests stay fast.
    failover_probe_timeout: Duration,
    /// The region tag ([`crate::lane::gpu_prl::region_tag_for_host`]) most recently
    /// PERSISTED as last-good (an accepted share landed there). Kept in memory so we
    /// write `settings.last_good_region` only when the good region actually CHANGES,
    /// not on every accepted share. `None` until the first accepted share on a
    /// region relay this run.
    persisted_good_region: Option<String>,
    /// Set when an accepted share lands on a NEW region: the tag the log-pump task
    /// should persist to settings AFTER releasing the lock (disk I/O off the
    /// stats hot-path). Taken (cleared) by the pump each line.
    pending_good_region: Option<String>,

    /// The GENERIC parser's pending re-baseline candidates for the two cumulative
    /// share counters — see [`fold_cumulative`]. Only the `Generic` (bring-your-own
    /// miner) path uses them; the bundled parsers read a known format and assign
    /// directly.
    generic_accepted_pending: Option<u64>,
    generic_rejected_pending: Option<u64>,

    // ── Layer 3: acceptance-rate collapse self-protection ───────────────────────
    /// Watches the dimension nothing else watched: whether the pool is ACCEPTING
    /// what this lane submits. Fed the cumulative counters on every parsed line; see
    /// [`crate::acceptance`] for why a rejected-share storm is invisible to every
    /// other guard we have (TCP is up, jobs arrive, the hashrate is nominal, and a
    /// rejected share still moves the counters that mark Layer-B "progress").
    acceptance: AcceptanceMonitor,
    /// Set once the lane has been HALTED for acceptance collapse. This is the one
    /// self-protective stop that is deliberately terminal-until-the-user-acts: it
    /// suppresses failover, the crash ladder and the stall ladder, because all three
    /// would do exactly what the 2026-08-11 incident did — burn three days of power
    /// re-connecting to a pool that rejects every share.
    halted: bool,
}

/// Fold a new reading of a CUMULATIVE counter (accepted / rejected shares) coming
/// from the GENERIC parser, which reads an UNKNOWN third-party format and can
/// therefore mis-read a line in either direction.
///
/// **Why not last-wins, and why not plain `max`.** Round 1 replaced last-wins with
/// `max` because one mis-read (`cuda:0` → "accepted = 0") walked the user's session
/// totals backwards. But a high-water mark trades a transient lie for a PERMANENT
/// one: a single spurious HIGH reading then sticks for the whole session, with no
/// way back. Both are dishonest; the difference is only which direction and for how
/// long.
///
/// So: a RISE is always taken (cumulative counters rise — nothing to doubt), and a
/// FALL is taken only once CORROBORATED — the next generic reading must also be
/// below the current value and at or above the first low one, i.e. the miner is
/// visibly counting up from a new base. One stray line can never move the total
/// down; two consecutive, mutually consistent readings can, which is exactly the
/// shape of a real re-baseline (an engine that restarted its own counter) and also
/// how the session heals from a spurious high value instead of being stuck at it.
///
/// `pending` carries the candidate between lines; it is cleared whenever the value
/// is adopted, so an isolated low reading leaves no residue.
///
/// Pure + platform-independent, so the whole decision table is unit-tested.
fn fold_cumulative(current: u64, pending: &mut Option<u64>, new: u64) -> u64 {
    if new >= current {
        *pending = None;
        return new;
    }
    match *pending {
        // A second consecutive low reading, consistent with counting up from a new
        // base → the engine really did re-baseline; adopt it.
        Some(p) if new >= p => {
            *pending = None;
            new
        }
        // The first low reading (or one that contradicts the pending candidate):
        // hold the current value and remember this one.
        _ => {
            *pending = Some(new);
            current
        }
    }
}

impl Inner {
    /// Set the human `message` AND its structured, re-localizable `message_key` +
    /// `message_args` in ONE step, so the two never drift. Used for the Layer-B
    /// failover / endpoint-lock statuses a front-end may re-render in its own
    /// language (see [`status_short`]).
    fn set_status(&mut self, text: String, key: &str, args: StatusArgs) {
        self.message = Some(text);
        self.message_key = Some(key.to_string());
        self.message_args = Some(args);
    }

    /// Set (or clear, with `None`) a FREE-FORM message that carries no re-localizable
    /// key — always clears any prior `message_key` / `message_args` so a stale key can
    /// never outlive the message it described.
    fn set_freeform(&mut self, text: Option<String>) {
        self.message = text;
        self.message_key = None;
        self.message_args = None;
    }
}

impl LaneSupervisor {
    /// A supervisor with the lane's DEFAULT endpoint plan (relay-only, plus any
    /// operator `ALICE_MINER_ENDPOINTS_JSON` override). The common path.
    pub fn new(lane: Lane) -> Self {
        Self::with_endpoints(lane, EndpointPlan::for_lane(lane))
    }

    /// A supervisor with an explicit [`EndpointPlan`] (used by tests + the
    /// failover verification to inject a bogus-primary→relay plan). The parser is
    /// derived from the lane (the BUNDLED-engine mapping) and there is no explicit
    /// log-tail path (the GPU-PRL lane still tails its `--log-file` from argv).
    pub fn with_endpoints(lane: Lane, endpoint_plan: EndpointPlan) -> Self {
        Self::with_backend(lane, endpoint_plan, ParserKind::for_lane(lane), None)
    }

    /// A supervisor with an explicit parser + optional log-tail path — the CUSTOM
    /// (bring-your-own miner) constructor. `parser` decides how the child's output is
    /// read (the miner's preset, not the lane), and `log_tail` is the file the
    /// supervisor must tail for a file-logging miner (`None` = the miner prints stats
    /// to stdout). Everything else — PoP, failover, refresh — is identical to a
    /// bundled lane.
    pub fn with_backend(
        lane: Lane,
        endpoint_plan: EndpointPlan,
        parser: ParserKind,
        log_tail: Option<std::path::PathBuf>,
    ) -> Self {
        Self {
            lane,
            parser,
            log_tail,
            inner: Arc::new(Mutex::new(Inner {
                state: ProcState::Stopped,
                pid: None,
                last_exit_code: None,
                message: None,
                message_key: None,
                message_args: None,
                hashrate_hs: None,
                hashrate_60s_hs: None,
                hashrate_15m_hs: None,
                telem_temp_c: None,
                telem_power_w: None,
                telem_util_pct: None,
                telem_fan_pct: None,
                accepted: 0,
                rejected: 0,
                last_line: String::new(),
                started_at: None,
                stop_requested: false,
                forced_error: false,
                retry_ladder: RetryLadder::new(),
                last_launch: None,
                last_child_pid: None,
                retry_token: 0,
                retry_at: None,
                crashes: 0,
                retry_backoff_override: None,
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
                failover_probe_timeout: FAILOVER_PROBE_TIMEOUT,
                persisted_good_region: None,
                pending_good_region: None,
                generic_accepted_pending: None,
                generic_rejected_pending: None,
                // Keyed on the PARSER, not the lane: only the parser knows whether the
                // engine actually reports pool rejections (a custom miner breaks the
                // lane→format mapping, and alpha-miner reports submissions, not accepts).
                acceptance: AcceptanceMonitor::new(parser),
                halted: false,
            })),
        }
    }

    /// Test hook: run the acceptance monitor on compressed thresholds so the halt
    /// path can be exercised in milliseconds instead of the production 5 min warm-up
    /// + 10 min window. Must be set before `start`. Production never calls this — the
    /// real thresholds live in [`crate::acceptance`].
    #[doc(hidden)]
    pub fn set_acceptance_config(&self, cfg: AcceptanceConfig) {
        let mut g = self.inner.lock().expect("mutex");
        g.acceptance = AcceptanceMonitor::with_config(self.parser, cfg);
    }

    /// The lane's current acceptance verdict (what the pool is doing to our shares).
    pub fn acceptance_verdict(&self) -> LaneVerdict {
        self.inner.lock().expect("mutex").acceptance.verdict()
    }

    /// Whether the lane has been halted by the acceptance guard.
    pub fn is_halted(&self) -> bool {
        self.inner.lock().expect("mutex").halted
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
        // Keep the pre-flight probe from dominating a fast test failover: a
        // tuned/tested supervisor probes with a tiny timeout (an unresolvable
        // `*.invalid` host still returns fast; a real host that doesn't answer within
        // this is treated as unreachable → the plain fallback rotation kicks in).
        g.failover_probe_timeout = backoff.max(Duration::from_millis(50));
    }

    /// Test/operator hook: fix the AUTOMATIC-restart backoff to `delay` instead of
    /// walking the real [`alice_supervise::RetryLadder`] (5s … 30min). Lets the
    /// crash-recovery tests drive several restarts in milliseconds. The ladder itself
    /// still escalates, so the attempt counter and the healthy-run credit behave
    /// exactly as in production.
    #[doc(hidden)]
    pub fn set_retry_timing(&self, delay: Duration) {
        self.inner.lock().expect("mutex").retry_backoff_override = Some(delay);
    }

    pub fn lane(&self) -> Lane {
        self.lane
    }

    /// Surface a transient PoP-status note in the lane snapshot (e.g. an OOB
    /// re-verify failure) so the GUI/CLI shows it instead of the lane silently
    /// dropping out of the relay allowlist. `None` clears it. A FREE-FORM note (no
    /// re-localizable key) — clears any stale failover `message_key`/`args`; the
    /// watchdog's failover/error statuses still take over on a real failure.
    pub fn note_message(&self, msg: Option<String>) {
        self.inner.lock().expect("mutex").set_freeform(msg);
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
            hashrate_60s_hs: g.hashrate_60s_hs,
            hashrate_15m_hs: g.hashrate_15m_hs,
            accepted: g.accepted,
            rejected: g.rejected,
            last_exit_code: g.last_exit_code,
            message: g.message.clone(),
            message_key: g.message_key.clone(),
            message_args: g.message_args.clone(),
            last_line: g.last_line.clone(),
            uptime_s,
            endpoint: Some(g.endpoint_plan.current().host_port()),
            failovers: g.failovers,
            temp_c: g.telem_temp_c,
            power_w: g.telem_power_w,
            util_pct: g.telem_util_pct,
            fan_pct: g.telem_fan_pct,
            crashes: g.crashes,
            retry_in_s: g
                .retry_at
                .map(|t| t.saturating_duration_since(Instant::now()).as_secs()),
            acceptance: {
                let v = g.acceptance.verdict();
                v.key()
            },
            accept_pct: g.acceptance.verdict().accept_pct(),
            halted: g.halted,
        }
    }

    /// How many times the ENGINE child has exited on its own since this lane was
    /// started (the third-party-engine crash counter).
    pub fn engine_crashes(&self) -> u64 {
        self.inner.lock().expect("mutex").crashes
    }

    /// Seconds until the pending automatic restart, when one is scheduled.
    pub fn retry_in_s(&self) -> Option<u64> {
        let g = self.inner.lock().expect("mutex");
        g.retry_at
            .map(|t| t.saturating_duration_since(Instant::now()).as_secs())
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
            g.retry_ladder.reset();
            g.crashes = 0;
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
            g.retry_ladder.reset();
            g.crashes = 0;
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
            g.set_freeform(None);
            g.stop_requested = false;
            g.forced_error = false;
            // Any (re)spawn supersedes a pending automatic retry: bumping the token
            // makes the waiting task a no-op the moment it next checks, so a user Start
            // during a backoff can never race a second engine onto the same GPU.
            g.retry_token = g.retry_token.wrapping_add(1);
            g.retry_at = None;
            g.last_launch = Some((program.clone(), args.clone()));
            g.hashrate_hs = None;
            g.hashrate_60s_hs = None;
            g.hashrate_15m_hs = None;
            // Telemetry is INSTANTANEOUS (not cumulative), so clear it on EVERY (re)spawn
            // — a stale temp/power reading from a dead child is meaningless; the new child
            // (or the nvidia-smi fallback) re-populates it within a tick.
            g.telem_temp_c = None;
            g.telem_power_w = None;
            g.telem_util_pct = None;
            g.telem_fan_pct = None;
            // On a fresh start, zero the share counters; on a failover relaunch,
            // KEEP the cumulative accepted/rejected (the user's session totals
            // shouldn't reset just because we rotated endpoints) but re-arm the
            // progress mark so the new child gets a full window to make progress.
            if !is_failover {
                g.accepted = 0;
                g.rejected = 0;
                g.best_hashrate_hs = 0.0;
                // A fresh start is the user's explicit act (possibly after updating),
                // so it also clears an acceptance halt and every judgement behind it —
                // the share counters just went to zero, so keeping the old verdict
                // would be judging this run on the last one's evidence.
                g.acceptance.on_run_start(Instant::now());
                g.halted = false;
            } else {
                // A failover deliberately carries the evidence over — see
                // `AcceptanceMonitor::on_failover` for why resetting here would
                // reproduce the incident.
                g.acceptance.on_failover(Instant::now());
            }
            // Either way, drop any half-formed generic re-baseline candidate: it
            // belonged to the previous child's output stream (see `fold_cumulative`).
            g.generic_accepted_pending = None;
            g.generic_rejected_pending = None;
            g.progress_accepted = g.accepted;
            g.last_line.clear();
            g.last_exit_code = None;
            g.started_at = Some(std::time::Instant::now());
            g.last_progress_at = Some(Instant::now());
            g.generation += 1;
            g.generation
        };

        let (log_tx, mut log_rx) = unbounded_channel::<LogLine>();
        // A file-logging miner (SRBMiner, or a custom file-logging miner) writes
        // shares/hashrate ONLY to its log file (never stdout), so clone a sender for a
        // file-tail task that feeds those lines into the SAME channel the parser drains
        // (the tail task is spawned after the child is up, below). The path is the
        // explicit `log_tail` (custom backend), or — for the BUNDLED GPU-PRL lane with
        // no explicit path — the `--log-file` extracted from argv (unchanged behavior).
        let tail_path: Option<std::path::PathBuf> = self.log_tail.clone().or_else(|| {
            (self.lane == Lane::GpuPrl)
                .then(|| extract_log_file_arg(&args))
                .flatten()
        });
        let log_tx_tail = tail_path.as_ref().map(|_| log_tx.clone());
        // No extra env, no PID file — the miner is fully ephemeral.
        let owned = match spawn_supervised(&program, &args, &[], None, log_tx) {
            Ok(c) => c,
            Err(e) => {
                let mut g = self.inner.lock().expect("mutex");
                g.state = ProcState::Error;
                g.set_freeform(Some(format!("failed to start miner: {e}")));
                return Err(g.message.clone().unwrap());
            }
        };

        let pid = owned.pid();
        {
            let mut g = self.inner.lock().expect("mutex");
            g.pid = Some(pid);
            g.last_child_pid = Some(pid);
            g.state = ProcState::Running;
        }
        // Record the ENGINE CHILD's pid AND its exact engine path (the real
        // xmrig/SRBMiner/kawpowminer/AlphaMiner — the process that eats CPU) so
        // `alice-miner stop` can reach it even when the CLI PARENT pid file
        // (`miner-cli.pid`) is stale/missing (the "stopped but xmrig still at 1200%
        // CPU" orphan) — AND re-verify the pid still runs OUR engine before signalling
        // it, so a reused pid is never mis-killed. Best-effort + public (pid + on-disk
        // path). Cleared on exit/stop in `supervise_until_exit`.
        crate::terminal::write_child_pid(pid, &program);

        // GPU-PRL log-file tail (blocker fix): SRBMiner emits shares/hashrate ONLY
        // to its `--log-file`, so without tailing it the stdout-only log pump sees
        // ~0 shares and the Layer-B no-progress watchdog wrongly tears down a
        // HEALTHY lane. Feed the file's new lines into the SAME LogLine channel the
        // parser drains. Generation-gated so a stale tail can't clobber a newer run.
        if let (Some(tail_tx), Some(log_file)) = (log_tx_tail, tail_path) {
            let tail_inner = self.inner.clone();
            tokio::spawn(async move {
                tail_log_file_into(log_file, tail_tx, tail_inner, gen).await;
            });
        }

        // Log pump → parse hashrate / shares into the snapshot (per-PARSER, not
        // per-lane: a custom miner picks the parser its preset implies).
        let inner_for_logs = self.inner.clone();
        let parser = self.parser;
        tokio::spawn(async move {
            while let Some(line) = log_rx.recv().await {
                // Parse under the lock, then persist any new last-good region AFTER
                // releasing it (disk I/O off the stats hot-path).
                let persist_region = {
                    let mut g = inner_for_logs.lock().expect("mutex");
                    if g.generation != gen {
                        break; // superseded by a newer run
                    }
                    apply_log_line(&mut g, parser, &line.text);
                    g.pending_good_region.take()
                };
                if let Some(tag) = persist_region {
                    // Best-effort: remember the region that just landed an accepted
                    // share so the NEXT (unlocked) start resumes on it. Ignore errors
                    // (a read-only home is not worth failing a mining run over).
                    let _ = crate::settings::save_last_good_region(&tag);
                }
            }
        });

        // GPU telemetry fallback: for an NVIDIA GPU lane whose engine may not print
        // temp/power/util/fan on stdout, spawn a throttled `nvidia-smi` poller (tied to
        // THIS run's generation) that fills ONLY the fields the engine left blank. Never
        // spawned for the CPU-XMR lane, and it self-exits on any box without a working
        // `nvidia-smi` (Apple Silicon / AMD / no driver) — see `spawn_nvidia_telemetry_poll`.
        if self.lane.is_gpu_lane() {
            let inner_smi = self.inner.clone();
            tokio::spawn(async move {
                spawn_nvidia_telemetry_poll(inner_smi, gen).await;
            });
        }

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
        // The child pid we recorded in `spawn_run`; cleared on either teardown path
        // below (guarded so it never deletes a NEWER child's rendezvous).
        let child_pid = owned.pid();
        loop {
            if let Some(code) = owned.try_exit_code() {
                // The engine child exited on its own — clear its pid backstop file.
                crate::terminal::remove_child_pid(child_pid);
                // `Some((token, delay, attempt))` once the automatic retry is armed —
                // armed under the SAME lock that flips the state, so the lane is never
                // observable as a bare `Error` with no pending restart.
                let mut armed: Option<(u64, Duration, u32)> = None;
                {
                    let mut g = self.inner.lock().expect("mutex");
                    if g.generation == gen {
                        g.last_exit_code = Some(code);
                        g.pid = None;
                        g.hashrate_hs = None;
                        g.hashrate_60s_hs = None;
                        g.hashrate_15m_hs = None;
                        g.telem_temp_c = None;
                        g.telem_power_w = None;
                        g.telem_util_pct = None;
                        g.telem_fan_pct = None;
                        // How long this run actually MINED (kept landing progress) —
                        // the currency that buys back retry budget. Read before
                        // `started_at` is cleared below.
                        let healthy_for = g
                            .last_progress_at
                            .zip(g.started_at)
                            .map(|(p, s)| p.saturating_duration_since(s))
                            .unwrap_or_default();
                        g.started_at = None;
                        if g.stop_requested {
                            // A stop we asked for. `forced_error` distinguishes a USER
                            // stop (→ Stopped, message cleared elsewhere) from one WE
                            // forced — failover-budget exhaustion, or a Layer-3
                            // acceptance halt. A forced stop must land in `Error` and
                            // keep its explanation: a halt that renders as a plain
                            // "Stopped" is exactly the silence this layer exists to end.
                            g.state = if g.forced_error {
                                ProcState::Error
                            } else {
                                ProcState::Stopped
                            };
                        } else {
                            // ── BUG#4 ──────────────────────────────────────────────
                            // The engine died on its own. This used to be a TERMINAL
                            // `Error`: no restart, ever, so one SRBMiner heap-corruption
                            // abort (`0xC0000374`) left the CLI running, the GPU idle
                            // and the miner earning nothing until a human noticed. A
                            // crash is now a normal, recoverable event: count it, credit
                            // the healthy time this run earned, and schedule an automatic
                            // restart on the escalating (never-terminal) ladder. The
                            // state stays `Error` on the wire — but it is a WAITING error
                            // that always carries "retrying in N", never a dead end.
                            g.state = ProcState::Error;
                            g.crashes += 1;
                            g.restart_policy.credit_healthy_run(healthy_for);
                            g.retry_ladder.credit_healthy_run(healthy_for);
                            // `old_pid` stays `None` here on purpose: `try_exit_code`
                            // returning a code means the OS has already REAPED this
                            // child, so it is definitively gone — and probing a freed
                            // pid risks reading a REUSED one as "still alive" and
                            // blocking the restart for nothing. The liveness probe is
                            // reserved for the teardown path, where a stop can time out.
                            armed = Some(arm_retry_locked(&mut g, &RetryReason::EngineExit(code)));
                        }
                    }
                }
                if let Some((token, delay, attempt)) = armed {
                    // Drop the child handle FIRST: on Windows that closes the
                    // kill-on-close Job Object, which terminates anything the engine
                    // spawned. The retry additionally VERIFIES the pid is gone before
                    // it relaunches (`await_child_gone`), so a restart can never stack
                    // a second engine on top of a surviving tree.
                    drop(owned);
                    self.spawn_retry_task(
                        gen,
                        token,
                        delay,
                        attempt,
                        RetryReason::EngineExit(code),
                        // Already reaped by `try_exit_code` — nothing left to probe.
                        None,
                    );
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
                // The child is torn down — clear its pid backstop file.
                crate::terminal::remove_child_pid(child_pid);
                let mut g = self.inner.lock().expect("mutex");
                if g.generation == gen {
                    g.pid = None;
                    g.hashrate_hs = None;
                    g.hashrate_60s_hs = None;
                    g.hashrate_15m_hs = None;
                    g.telem_temp_c = None;
                    g.telem_power_w = None;
                    g.telem_util_pct = None;
                    g.telem_fan_pct = None;
                    g.started_at = None;
                    g.last_exit_code = code;
                    if g.forced_error {
                        // A forced failover-exhaustion stop: land in Error and KEEP
                        // the watchdog's explanatory message (don't fall to Stopped).
                        g.state = ProcState::Error;
                    } else {
                        // A normal user Stop.
                        g.state = ProcState::Stopped;
                        g.set_freeform(None);
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

                // ── PRIORITY 1: acceptance collapse ────────────────────────────────
                // Checked BEFORE the no-progress stall, and it wins outright. The two
                // guards answer different questions and only one of them can be right
                // at a time:
                //
                //   * Layer B asks "is this lane still moving?" and answers a stall by
                //     rotating regions and restarting.
                //   * This asks "is anything we submit being ACCEPTED?" — and when the
                //     answer is no, rotating and restarting is the WORST thing we can
                //     do. In the 2026-08-11 incident the lane was never stalled: shares
                //     kept flowing, so the counters kept moving, so Layer B kept seeing
                //     progress; the 69 failovers it did perform each burned a re-init
                //     and changed nothing, because every region rejects the same share.
                //
                // So a collapse halts the lane outright: no failover, no crash ladder,
                // no stall ladder. Ordering it first is what guarantees the two never
                // fight — once `halted` is set, every other automatic path checks it
                // and declines.
                if let LaneVerdict::Collapsed(collapse) = g.acceptance.verdict() {
                    g.halted = true;
                    // Cancel any retry a crash armed moments ago, and make sure nothing
                    // can arm a new one: `halted` is checked by `schedule_retry` and by
                    // the countdown task before it relaunches.
                    g.retry_token = g.retry_token.wrapping_add(1);
                    g.retry_at = None;
                    g.stop_requested = true; // let supervise_until_exit reap the child
                    g.forced_error = true; // land in Error, keep the explanation
                    g.state = ProcState::Stopping; // transitional; loop → Error
                    // Publish an immediate, attribution-free status so the lane is
                    // never a silent stop while we go ask the network whose fault it
                    // is. The wording is upgraded once that answer lands (or doesn't).
                    set_halt_status_locked(&mut g, &collapse, Attribution::Unknown);
                    WatchAction::Halt { collapse }
                } else {
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
                        // ── BUG#4 ──────────────────────────────────────────────────────
                        // The FAST failover budget is spent. That used to end the lane for
                        // good — `GiveUp`, a terminal `Error`, no further attempt ever. It
                        // is the right answer to a restart STORM and the wrong answer to a
                        // temporarily sick relay: the miner simply stopped earning, silently,
                        // until someone re-ran it by hand. Now we back OFF instead of giving
                        // up: tear the stalled child down and retry on the escalating ladder
                        // (5s → … → 30min, capped), with a visible countdown the whole time.
                        // Credit whatever healthy mining this run did before it stalled, so a
                        // rig that worked for hours retries quickly.
                        let healthy_for = g
                            .last_progress_at
                            .zip(g.started_at)
                            .map(|(p, s)| p.saturating_duration_since(s))
                            .unwrap_or_default();
                        g.restart_policy.credit_healthy_run(healthy_for);
                        g.retry_ladder.credit_healthy_run(healthy_for);
                        g.forced_error = true;
                        g.stop_requested = true; // let supervise_until_exit reap the child
                        g.state = ProcState::Stopping; // transitional; loop → Error
                        // ARM the retry here, under the same lock that condemns the child:
                        // the teardown below flips the lane to `Error`, and by then the
                        // pending restart + its countdown are already published.
                        let reason = RetryReason::Stalled(window.as_secs());
                        let (token, delay, attempt) = arm_retry_locked(&mut g, &reason);
                        WatchAction::GiveUp { reason, token, delay, attempt }
                    } else {
                        // A stall with budget remaining. Record the restart against the
                        // budget, then hand the CHOICE to the post-lock stage: it
                        // pre-flights the candidate region(s) OFF-lock (a TCP probe can't
                        // run under the mutex) and commits the rotation to the first
                        // REACHABLE one — or retries THIS region in place for a locked /
                        // single-region plan (empty candidates). We do NOT advance the
                        // cursor or set the failover message here — both depend on the
                        // probe outcome.
                        let policy_backoff = g.restart_policy.record(now);
                        let backoff = g.failover_backoff_override.unwrap_or(policy_backoff);
                        WatchAction::Failover {
                            from: g.endpoint_plan.current().clone(),
                            candidates: g.endpoint_plan.failover_candidates(),
                            rebuild: g.rebuild.clone(),
                            backoff,
                            probe_timeout: g.failover_probe_timeout,
                            window,
                            // The region that last landed an accepted share THIS run — the
                            // recovery order prefers it (so a restart-in-place resumes where
                            // mining was actually working, per `settings.last_good_region`).
                            last_good: g.persisted_good_region.clone(),
                        }
                    }
                }
            };

            match action {
                WatchAction::Halt { collapse } => {
                    // Stop the engine first — every second we spend deciding whose
                    // fault it is costs the user electricity for shares nobody will
                    // accept. The status was already published under the decision lock,
                    // so the lane is explained before it is even torn down.
                    self.teardown_current_child(gen).await;
                    // Only NOW do we ask the network whose problem this is. It changes
                    // the WORDING, never the halt: a slow, broken or hostile answer
                    // (or none at all) leaves the honest "we can't tell you yet" text
                    // in place. Bounded HTTP, so it runs on a blocking thread, off the
                    // async runtime — and after the child is dead, so a 10 s timeout
                    // can never delay the stop.
                    let lane = self.lane;
                    let attribution = tokio::task::spawn_blocking(move || fetch_attribution(lane))
                        .await
                        .unwrap_or(Attribution::Unknown);
                    let mut g = self.inner.lock().expect("mutex");
                    if g.generation == gen && g.halted {
                        set_halt_status_locked(&mut g, &collapse, attribution);
                    }
                    return;
                }
                WatchAction::GiveUp { reason, token, delay, attempt } => {
                    // Reap the stalled child (bounded) — the retry was already armed
                    // under the decision lock — then hand the countdown to its task.
                    // Tearing down first is what makes the restart safe: the replacement
                    // is only spawned once this engine is gone.
                    self.teardown_current_child(gen).await;
                    // The teardown is BOUNDED, so it can return with the child still
                    // recorded. Only then does the retry get a pid to probe — a reaped
                    // child needs no probe, and probing a freed pid could read a REUSED
                    // one as alive and stall the restart for no reason.
                    let unconfirmed = {
                        let g = self.inner.lock().expect("mutex");
                        if g.generation == gen { g.pid } else { None }
                    };
                    self.spawn_retry_task(gen, token, delay, attempt, reason, unconfirmed);
                    return;
                }
                WatchAction::Failover {
                    from,
                    candidates,
                    rebuild,
                    backoff,
                    probe_timeout,
                    window,
                    last_good,
                } => {
                    // If we have no rebuild closure (single-endpoint / start_simple),
                    // there's nothing to rotate to — leave the lane to its own
                    // reconnect and stop watching (the miner's Layer-A handles it).
                    let Some(rebuild) = rebuild else { return };
                    // A LOCKED / single-region plan (no failover candidates) can only
                    // retry THIS region in place; an AUTO / failover-capable plan rotates
                    // across regions. This is the explicit-lock vs auto-selected split:
                    // ONLY a lock (an empty candidate set = a single-endpoint plan built
                    // from `--region`) disables cross-region rotation. An auto-selected
                    // region NEVER becomes a lock — its plan keeps every region, so this
                    // set is non-empty and the recovery loop below rotates freely.
                    let locked = candidates.is_empty();
                    // Stop the current child first (graceful + reaped), then wait the
                    // backoff. `spawn_run` (below) bumps the generation so the old
                    // supervise/log tasks detach.
                    self.teardown_current_child(gen).await;
                    tokio::time::sleep(backoff).await;

                    // The ORDERED set of regions to (try to) relaunch on this round. For a
                    // locked plan that is just `from`; for an auto plan it is every other
                    // region (reachable-first, `last_good` first) plus a final in-place
                    // retry of `from` (a region that merely jittered can be resumed once it
                    // recovers). Crucially, if a region's rebuild — its region-bound PoP
                    // handshake — FAILS, we advance to the NEXT region instead of
                    // dead-ending in Error (THE bug: auto-switch to US, US relay unhealthy,
                    // then stuck on US with a "retrying other regions" status that never
                    // actually retried).
                    let targets: Vec<Endpoint> = if locked {
                        vec![from.clone()]
                    } else {
                        recovery_targets(&candidates, &from, last_good.as_deref(), probe_timeout)
                            .await
                    };

                    let mut launched = false;
                    for target in &targets {
                        // `changed` (target vs the STALLED region) drives the failover
                        // COUNT + status label — a real region switch vs an in-place
                        // resume. The cursor itself always follows `target`.
                        let changed = target.host != from.host || target.port != from.port;
                        // Commit the cursor to this target UNDER THE LOCK *before* the
                        // rebuild, so the snapshot endpoint always shows the region
                        // currently being attempted — it tracks the failover cursor and
                        // never freezes on a dead region.
                        let order = {
                            let mut g = self.inner.lock().expect("mutex");
                            if g.generation != gen {
                                return; // superseded while probing / retrying
                            }
                            if !g.endpoint_plan.advance_to(target) {
                                // Shouldn't happen (the target came from the plan) → a
                                // best-effort plain advance keeps the cursor moving.
                                g.endpoint_plan.advance();
                            }
                            g.endpoint_plan.ordered_from_cursor()
                        };

                        match rebuild(&order) {
                            Ok((program, args)) => match self.spawn_run(program, args, true) {
                                Ok(()) => {
                                    // `spawn_run` cleared `message` + bumped the generation
                                    // (the NEW child's watchdog now owns the lane). Restore
                                    // the LABELED, honest status; count a failover ONLY for a
                                    // real region change.
                                    let mut g = self.inner.lock().expect("mutex");
                                    if changed {
                                        g.failovers += 1;
                                    }
                                    let secs = window.as_secs();
                                    if changed {
                                        // auto-failover: <from> → <to>
                                        g.set_status(
                                            failover_status(&from, target, true, window),
                                            "auto_failover",
                                            StatusArgs {
                                                endpoint: Some(target.host_port()),
                                                region: Some(short_region_label(&from)),
                                                to_region: Some(short_region_label(target)),
                                                stalled_s: Some(secs),
                                                ..Default::default()
                                            },
                                        );
                                    } else if locked {
                                        // A LOCKED / single-endpoint plan retries in place. A PRL
                                        // REGION relay (us/asia) keeps the region-lock wording (it
                                        // has real region-failover semantics, merely disabled by
                                        // the lock); a FIXED pool endpoint (XMR/RVN, or an operator
                                        // override — NOT a region) gets a GENERIC "endpoint locked"
                                        // status, never PRL-style "region … no auto-failover".
                                        let (key, text) = if is_region_relay(&from) {
                                            (
                                                "region_locked_no_failover",
                                                failover_status(&from, target, false, window),
                                            )
                                        } else {
                                            ("endpoint_locked", endpoint_locked_status(&from, window))
                                        };
                                        g.set_status(
                                            text,
                                            key,
                                            StatusArgs {
                                                endpoint: Some(from.host_port()),
                                                region: Some(short_region_label(&from)),
                                                to_region: None,
                                                stalled_s: Some(secs),
                                                ..Default::default()
                                            },
                                        );
                                    } else {
                                        // auto plan resuming the (recovered) same region
                                        g.set_status(
                                            region_resumed_status(target, window),
                                            "region_recovered",
                                            StatusArgs {
                                                endpoint: Some(target.host_port()),
                                                region: Some(short_region_label(target)),
                                                to_region: None,
                                                stalled_s: Some(secs),
                                                ..Default::default()
                                            },
                                        );
                                    }
                                    launched = true;
                                    break;
                                }
                                Err(e) => {
                                    // A spawn/exec failure (the miner binary itself couldn't
                                    // launch) is region-independent — another region won't
                                    // help — and `spawn_run` already bumped the generation
                                    // (this watchdog is now stale) and set Error. Raw detail
                                    // stays in the verbose log. BUG#4: this is no longer the
                                    // end of the road — arm the escalating retry against the
                                    // CURRENT generation (`None`) so a transient exec failure
                                    // (an AV scanner holding the binary, a busy mount) heals
                                    // itself instead of parking the rig.
                                    log_verbose("failover relaunch failed", &e);
                                    self.schedule_retry(None, RetryReason::RelaunchFailed);
                                    return;
                                }
                            },
                            Err(e) => {
                                // The region answered the TCP pre-flight but its rebuild (the
                                // region-bound PoP challenge to `https://<host>/m4/challenge`)
                                // FAILED — the relay's control plane is unhealthy. THE FIX:
                                // do NOT dead-end. Record an honest "retrying other regions"
                                // status and advance to the NEXT region. The generation is
                                // unchanged (no child spawned), so the loop stays valid; the
                                // restart budget was charged ONCE for this stall (in the
                                // decision stage), so trying several regions is not a storm.
                                log_verbose("failover plan rebuild failed", &e);
                                let mut g = self.inner.lock().expect("mutex");
                                if g.generation != gen {
                                    return;
                                }
                                g.set_status(
                                    region_retry_message(),
                                    "region_retrying",
                                    StatusArgs {
                                        endpoint: Some(target.host_port()),
                                        region: Some(short_region_label(target)),
                                        to_region: None,
                                        stalled_s: Some(window.as_secs()),
                                        ..Default::default()
                                    },
                                );
                                // fall through to the next target
                            }
                        }
                    }

                    if !launched {
                        // Every region tried this round failed to (re)build/relaunch — all
                        // relays are currently unreachable/unhealthy. BUG#4: this used to be
                        // a TERMINAL Error ("restart to retry"), i.e. a relay outage longer
                        // than one round permanently parked the miner. Arm the escalating
                        // retry instead — it is still bounded (the delay only grows), but it
                        // comes back on its own when the relays do.
                        {
                            let g = self.inner.lock().expect("mutex");
                            if g.generation != gen {
                                return;
                            }
                        }
                        self.schedule_retry(
                            Some(gen),
                            if locked {
                                RetryReason::RelaunchFailed
                            } else {
                                RetryReason::AllRegionsDown
                            },
                        );
                    }
                    // On a successful relaunch this watchdog's generation is now stale
                    // (spawn_run bumped it) and the NEW run owns its own watchdog; on the
                    // all-failed path we've set a terminal Error. Either way, exit.
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
    ///
    /// A Stop issued while the lane is WAITING to auto-restart (BUG#4's backoff) also
    /// cancels that pending retry and lands the lane in `Stopped` — the user's Stop is
    /// the one thing that IS terminal, and it must not be silently undone a few minutes
    /// later by a timer nobody could see.
    pub fn request_stop(&self) {
        let mut g = self.inner.lock().expect("mutex");
        if matches!(g.state, ProcState::Running | ProcState::Starting) {
            g.stop_requested = true;
            g.state = ProcState::Stopping;
            // Also invalidate any retry armed by an earlier crash in this run.
            g.retry_token = g.retry_token.wrapping_add(1);
            g.retry_at = None;
        } else if g.retry_at.is_some() {
            g.retry_token = g.retry_token.wrapping_add(1);
            g.retry_at = None;
            g.stop_requested = true;
            g.forced_error = false;
            g.state = ProcState::Stopped;
            g.set_freeform(None);
        }
    }

    // ── BUG#4: the automatic, never-terminal restart ────────────────────────────

    /// Arm the automatic restart after a crash / stall / failed relaunch.
    ///
    /// `gen` is the generation the caller believes it owns; `None` binds to whatever
    /// the CURRENT generation is (used after `spawn_run` itself failed and already
    /// bumped it). Takes the next rung off the [`RetryLadder`], publishes the waiting
    /// status immediately (so the lane is never a silent `Error`), and spawns the task
    /// that counts down and relaunches.
    fn schedule_retry(&self, gen: Option<u64>, reason: RetryReason) {
        let (gen, token, delay, attempt, old_pid) = {
            let mut g = self.inner.lock().expect("mutex");
            // LAYER 3: a lane halted for acceptance collapse must not be restarted by
            // ANY automatic path. The crash ladder is normally the right answer to a
            // dead engine — but restarting into a pool that rejects every share is how
            // a miner burns three days, so the halt outranks it. Only a user Start
            // clears `halted`.
            if g.halted {
                return;
            }
            let gen = match gen {
                Some(want) if want != g.generation => return, // superseded
                Some(want) => want,
                None => g.generation,
            };
            let (token, delay, attempt) = arm_retry_locked(&mut g, &reason);
            g.state = ProcState::Error;
            g.pid = None;
            g.started_at = None;
            (gen, token, delay, attempt, g.last_child_pid)
        };
        self.spawn_retry_task(gen, token, delay, attempt, reason, old_pid);
    }

    /// Spawn the task that counts the armed retry down and relaunches. Split from
    /// [`Self::schedule_retry`] so a caller that ARMED the retry under its own lock
    /// (the crash + watchdog paths, where arming must be atomic with the state change)
    /// can still hand the waiting off here.
    fn spawn_retry_task(
        &self,
        gen: u64,
        token: u64,
        delay: Duration,
        attempt: u32,
        reason: RetryReason,
        old_pid: Option<u32>,
    ) {
        let this = self.clone();
        tokio::spawn(async move {
            this.retry_after(gen, token, delay, attempt, reason, old_pid).await;
        });
    }

    /// Refresh the "waiting to retry" status for `remaining`, unless this retry has been
    /// superseded (a newer generation / token). Returns `false` when superseded, so the
    /// countdown loop knows to stop.
    fn publish_retry_status(
        &self,
        gen: u64,
        token: u64,
        reason: &RetryReason,
        remaining: Duration,
        attempt: u32,
    ) -> bool {
        let mut g = self.inner.lock().expect("mutex");
        if g.generation != gen || g.retry_token != token {
            return false;
        }
        set_retry_status_locked(&mut g, reason, remaining, attempt);
        true
    }

    /// Wait out `delay` with a visible, second-by-second countdown, confirm the old
    /// engine's process tree is really gone, then relaunch. Never gives up: a relaunch
    /// that fails arms the NEXT (longer) rung instead of parking the lane.
    async fn retry_after(
        &self,
        gen: u64,
        token: u64,
        delay: Duration,
        attempt: u32,
        reason: RetryReason,
        old_pid: Option<u32>,
    ) {
        let deadline = Instant::now() + delay;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if !self.publish_retry_status(gen, token, &reason, remaining, attempt) {
                return; // superseded by a user Start / Stop, or a newer run
            }
            if remaining.is_zero() {
                break;
            }
            // Tick at most once a second so the countdown the user reads is real.
            tokio::time::sleep(remaining.min(Duration::from_secs(1))).await;
        }

        // ⑤ Job Object / process-group teardown is only half the contract — the other
        // half is not spawning until it has actually taken effect. Confirm the old
        // engine pid is gone before we put another one on the same GPU.
        if let Some(pid) = old_pid {
            if !await_child_gone(pid).await {
                log_verbose("retry deferred", &format!("engine pid {pid} still alive"));
                self.reschedule_retry(gen, token, RetryReason::EngineStillAlive);
                return;
            }
        }

        // Rebuild the argv when we can: a GPU-PRL launch plan carries a region-bound
        // PoP token, so replaying the old argv after a long backoff would be rejected
        // by the relay. Fall back to the last plan for a `start_simple` lane.
        let plan = {
            let g = self.inner.lock().expect("mutex");
            // `halted` is checked alongside the generation/token at every gate on this
            // path, not just once: the acceptance guard can fire while a countdown is
            // running, and a rebuild is a real network handshake that can take seconds.
            if g.generation != gen || g.retry_token != token || g.halted {
                return;
            }
            match g.rebuild.clone() {
                Some(rebuild) => Ok((rebuild, g.endpoint_plan.ordered_from_cursor())),
                None => Err(g.last_launch.clone()),
            }
        };
        let launch = match plan {
            Ok((rebuild, order)) => match rebuild(&order) {
                Ok(p) => Some(p),
                Err(e) => {
                    log_verbose("retry plan rebuild failed", &e);
                    None
                }
            },
            Err(last) => last,
        };
        let Some((program, args)) = launch else {
            self.reschedule_retry(gen, token, RetryReason::RelaunchFailed);
            return;
        };

        // FINAL gate, immediately before the spawn. The rebuild above performs a real
        // network handshake and can take seconds; a user Start landing in that window
        // would already have bumped the generation/token, and an automatic restart must
        // never stack a second engine on top of it.
        {
            let g = self.inner.lock().expect("mutex");
            if g.generation != gen || g.retry_token != token || g.state.is_active() || g.halted {
                return;
            }
        }
        // `is_failover = true`: keep the user's cumulative session shares across an
        // automatic restart (the rig kept mining; only the engine process is new) and
        // skip the "already running" guard — we know it is not.
        if let Err(e) = self.spawn_run(program, args, true) {
            log_verbose("retry spawn failed", &e);
            // `spawn_run` bumped the generation on its way out, so bind to the current
            // one and arm the next rung. Still never terminal.
            self.schedule_retry(None, RetryReason::RelaunchFailed);
        }
    }

    /// Arm the NEXT rung after a retry attempt could not even launch. Guarded on the
    /// same `(gen, token)` the attempt owned, so a user Start/Stop that landed while we
    /// were probing wins.
    fn reschedule_retry(&self, gen: u64, token: u64, reason: RetryReason) {
        {
            let g = self.inner.lock().expect("mutex");
            if g.generation != gen || g.retry_token != token {
                return;
            }
        }
        self.schedule_retry(Some(gen), reason);
    }
}

/// Arm the next automatic retry **under the caller's lock**, so the moment the lane
/// can be observed as `Error` it ALREADY carries "retrying in N". (Arming afterwards
/// left a window in which a poll saw a bare, hopeless-looking Error — exactly the
/// experience BUG#4 is about.) Consumes one rung of the ladder and publishes the
/// status. Returns `(token, delay, attempt)` for the waiting task.
fn arm_retry_locked(g: &mut Inner, reason: &RetryReason) -> (u64, Duration, u32) {
    let (ladder_delay, attempt) = g.retry_ladder.next_backoff();
    let delay = g.retry_backoff_override.unwrap_or(ladder_delay);
    g.retry_token = g.retry_token.wrapping_add(1);
    g.retry_at = Some(Instant::now() + delay);
    set_retry_status_locked(g, reason, delay, attempt);
    (g.retry_token, delay, attempt)
}

/// Write the retry status (message + machine key + args) into `g`. Caller holds the lock
/// and has already checked the generation/token.
fn set_retry_status_locked(g: &mut Inner, reason: &RetryReason, remaining: Duration, attempt: u32) {
    let crashes = g.crashes;
    let args = StatusArgs {
        endpoint: Some(g.endpoint_plan.current().host_port()),
        region: Some(short_region_label(g.endpoint_plan.current())),
        to_region: None,
        stalled_s: reason.stalled_s(),
        exit_code: reason.exit_code(),
        retry_in_s: Some(remaining.as_secs()),
        attempt: Some(attempt),
        crashes: (crashes > 0).then_some(crashes),
        ..Default::default()
    };
    g.set_status(retry_message(reason, remaining, attempt), reason.key(), args);
}

/// How long [`await_child_gone`] waits for the previous engine's process tree to
/// disappear before it stops holding the restart back.
const CHILD_GONE_BOUND: Duration = Duration::from_secs(10);
const CHILD_GONE_POLL: Duration = Duration::from_millis(250);

/// Wait (bounded) for the previous engine `pid` to be gone, so an automatic restart can
/// never stack a second engine on the same GPU. `true` ⇒ clear to relaunch.
///
/// The decision is asymmetric on purpose:
///   * `Dead` — clear immediately (the normal path: the child was reaped and, on
///     Windows, its kill-on-close Job Object went with the dropped handle);
///   * `Alive` — keep waiting, and if it is STILL provably alive when the bound
///     elapses, refuse: two engines is worse than a late restart;
///   * `Unknown` — wait out the full bound, then proceed. Refusing forever on a box
///     whose liveness probe never answers would recreate the exact "never recovers"
///     failure this whole fix exists to remove, and we would be blocking on a guess.
async fn await_child_gone(pid: u32) -> bool {
    let ticks = (CHILD_GONE_BOUND.as_millis() / CHILD_GONE_POLL.as_millis()).max(1);
    for _ in 0..ticks {
        if crate::proc::liveness_settled(pid) == crate::proc::Liveness::Dead {
            return true;
        }
        tokio::time::sleep(CHILD_GONE_POLL).await;
    }
    crate::proc::liveness_settled(pid) != crate::proc::Liveness::Alive
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 3 helpers: the halt status, and the one network call behind its wording.
// ─────────────────────────────────────────────────────────────────────────────

/// Publish the acceptance-halt status under an already-held lock.
///
/// Sets the short line, the machine key (so a GUI can re-render it in its own
/// language) and the [`StatusArgs`] carrying the raw numbers — the localizable
/// pieces, never a pre-baked foreign-language sentence. The full paragraph the user
/// reads lives in [`status_tooltip`] / [`acceptance::halt_explanation`].
fn set_halt_status_locked(g: &mut Inner, c: &Collapse, attribution: Attribution) {
    let key = match attribution {
        Attribution::NetworkWide => "acceptance_halt_network",
        Attribution::LocalOnly => "acceptance_halt_local",
        Attribution::Unknown => "acceptance_halt_unknown",
    };
    g.set_status(
        acceptance::halt_status_line(c),
        key,
        StatusArgs {
            endpoint: Some(g.endpoint_plan.current().host_port()),
            region: Some(short_region_label(g.endpoint_plan.current())),
            shares_accepted: Some(c.run_accepted),
            shares_rejected: Some(c.run_rejected),
            accept_pct: Some(c.period.accept_pct()),
            ..Default::default()
        },
    );
}

/// Ask the public read-API what the WHOLE NETWORK's acceptance rate is for `lane`.
///
/// The call itself lives in [`acceptance::fetch_attribution`] because the halt is no
/// longer its only reader: the auto-updater's health probation asks the same question
/// before it blames a client build for a lack of accepted shares (F4), and two copies
/// of "whose fault is this" is how the two layers would drift apart.
///
/// Blocking, bounded, unauthenticated, read-only, and called exactly once per halt —
/// after the engine is already stopped. Anything that goes wrong resolves to
/// [`Attribution::Unknown`], and the user is told we don't know rather than being
/// handed a guess. It CANNOT halt a healthy lane and CANNOT un-halt a collapsed one;
/// the worst a compromised endpoint achieves is pointing a stopped miner at the wrong
/// suspect.
fn fetch_attribution(lane: Lane) -> Attribution {
    acceptance::fetch_attribution(lane)
}

/// Why an automatic restart is pending. Drives the status key + wording, and carries
/// the one machine fact a front-end needs to explain it in its own language (the raw
/// engine exit code / the stall window) — never a pre-baked sentence.
#[derive(Debug, Clone, Copy)]
enum RetryReason {
    /// The engine child exited on its own with this code (a crash, or a self-exit).
    EngineExit(i32),
    /// The Layer-B watchdog saw no progress for N seconds and spent its fast budget.
    Stalled(u64),
    /// Every region failed to (re)build/relaunch in one failover round.
    AllRegionsDown,
    /// A relaunch attempt could not be built or spawned at all.
    RelaunchFailed,
    /// The previous engine's process tree was still alive at retry time, so the
    /// relaunch was deliberately deferred rather than risk two engines on one GPU.
    EngineStillAlive,
}

impl RetryReason {
    fn key(self) -> &'static str {
        match self {
            RetryReason::EngineExit(_) => "engine_crashed_retrying",
            RetryReason::Stalled(_) => "stall_retrying",
            RetryReason::AllRegionsDown => "all_regions_retrying",
            RetryReason::RelaunchFailed => "relaunch_retrying",
            RetryReason::EngineStillAlive => "engine_still_alive_retrying",
        }
    }
    fn exit_code(self) -> Option<i32> {
        match self {
            RetryReason::EngineExit(c) => Some(c),
            _ => None,
        }
    }
    fn stalled_s(self) -> Option<u64> {
        match self {
            RetryReason::Stalled(s) => Some(s),
            _ => None,
        }
    }
}

/// What the watchdog decided to do this tick (computed under the lock, executed
/// after releasing it).
enum WatchAction {
    /// LAYER 3: the pool is rejecting (nearly) everything this lane submits. Stop —
    /// and stay stopped. Outranks every other action; see the watchdog's PRIORITY 1
    /// comment for why failing over or restarting into a rejection storm is strictly
    /// worse than doing nothing.
    Halt { collapse: Collapse },
    /// The fast failover budget is spent. The child is torn down and the lane hands
    /// over to the escalating retry ladder — it does NOT stop for good (BUG#4). The
    /// retry is ARMED under the decision lock (so `Error` and "retrying in N" become
    /// visible together); these fields carry it to the waiting task.
    GiveUp {
        reason: RetryReason,
        token: u64,
        delay: Duration,
        attempt: u32,
    },
    /// A stall with budget remaining. The post-lock stage pre-flights `candidates`
    /// (after `backoff`), then tries to relaunch on them in a RECOVERY order —
    /// reachable-first, remembered `last_good` first — advancing to the NEXT region
    /// if a region's rebuild (its region-bound PoP handshake) fails, so an unhealthy
    /// region never dead-ends the lane. Empty `candidates` (a locked / single-region
    /// plan) ⇒ retry `from` in place. `window` feeds the status line's reason;
    /// `probe_timeout` bounds each reachability probe; `last_good` is the in-run
    /// last-good region tag (a recovery priority hint).
    Failover {
        from: Endpoint,
        candidates: Vec<Endpoint>,
        rebuild: Option<RebuildFn>,
        backoff: Duration,
        probe_timeout: Duration,
        window: Duration,
        last_good: Option<String>,
    },
}

/// The LABELED Layer-B status line (D-line requirement (c)/(b)). For a real region
/// change it reads `auto-failover: <from> → <to> (no progress for <N>s)`; for a
/// locked / single-region plan (nowhere to rotate — we retry the same region) it
/// reads `region <r> locked — retrying, no auto-failover (…)`. A region relay is
/// shown by its short tag (us/asia); any other host as `host:port`. Localized.
fn failover_status(from: &Endpoint, to: &Endpoint, changed: bool, window: Duration) -> String {
    let secs = window.as_secs();
    if changed {
        let f = region_label(from);
        let t = region_label(to);
        crate::tr!(
            format!("auto-failover: {f} → {t} (no progress for {secs}s)"),
            format!("自动切换区域: {f} → {t}(已 {secs}s 无进展)")
        )
    } else {
        let r = region_label(from);
        crate::tr!(
            format!("region {r} locked — retrying, no auto-failover (no progress for {secs}s)"),
            format!("区域 {r} 已锁定 — 仅重试该区域、不自动切换(已 {secs}s 无进展)")
        )
    }
}

/// A short, honest label for an endpoint: its region tag (us/asia) when the host
/// is a known region relay, else `host:port`.
fn region_label(ep: &Endpoint) -> String {
    match crate::lane::gpu_prl::region_tag_for_host(&ep.host) {
        Some(tag) => tag.to_string(),
        None => ep.host_port(),
    }
}

/// Push `ep` onto `list` only if no endpoint with the same host+port is already there
/// (de-dupe by identity, preserving first-seen order).
fn push_distinct(list: &mut Vec<Endpoint>, ep: &Endpoint) {
    if !list.iter().any(|e| e.host == ep.host && e.port == ep.port) {
        list.push(ep.clone());
    }
}

/// The ORDERED list of endpoints a failover-capable (auto) lane should try to
/// (re)launch on after a stall, most-preferred first:
///   1. the remembered `last_good` region — but ONLY if it is one of the failover
///      candidates AND is not the region that just stalled (resume where mining was
///      actually landing shares, per `settings.last_good_region`);
///   2. the remaining failover candidates, in the plan's rotation order;
///   3. the stalled `from` region itself, as a FINAL in-place retry (a region that
///      merely jittered can be resumed once it recovers).
///
/// The result is then STABLE-reordered reachable-first by a bounded TCP pre-flight
/// probe, so a region that answers is tried before one that doesn't — but an
/// unreachable region is still KEPT (tried last), because the rebuild's own
/// region-bound PoP handshake is the real health gate (a region can answer TCP yet
/// fail PoP, and vice-versa). Distinct by host+port; never empty (always `from`).
async fn recovery_targets(
    candidates: &[Endpoint],
    from: &Endpoint,
    last_good: Option<&str>,
    probe_timeout: Duration,
) -> Vec<Endpoint> {
    partition_reachable(recovery_order(candidates, from, last_good), probe_timeout).await
}

/// The PURE (network-free) recovery order — the priority ordering `recovery_targets`
/// then stable-reorders reachable-first. Testable without a probe. See
/// [`recovery_targets`] for the priority rationale.
fn recovery_order(candidates: &[Endpoint], from: &Endpoint, last_good: Option<&str>) -> Vec<Endpoint> {
    let mut base: Vec<Endpoint> = Vec::new();
    // 1. last_good first — only if it is a candidate and differs from the stalled region.
    if let Some(tag) = last_good {
        let from_tag = crate::lane::gpu_prl::region_tag_for_host(&from.host);
        if from_tag != Some(tag) {
            if let Some(ep) = candidates
                .iter()
                .find(|e| crate::lane::gpu_prl::region_tag_for_host(&e.host) == Some(tag))
            {
                push_distinct(&mut base, ep);
            }
        }
    }
    // 2. the remaining candidates, in rotation order.
    for ep in candidates {
        push_distinct(&mut base, ep);
    }
    // 3. the stalled region, as a final in-place retry.
    push_distinct(&mut base, from);
    base
}

/// Stable-reorder `order` so TCP-reachable endpoints come first (each group keeps its
/// input order), using a bounded connect probe per endpoint. The (blocking) probes run
/// on a blocking thread so a slow connect never stalls the runtime. On a join failure the
/// input order is returned unchanged (best-effort — the rebuild still guards health).
async fn partition_reachable(order: Vec<Endpoint>, timeout: Duration) -> Vec<Endpoint> {
    let fallback = order.clone();
    tokio::task::spawn_blocking(move || {
        let mut reachable: Vec<Endpoint> = Vec::new();
        let mut unreachable: Vec<Endpoint> = Vec::new();
        for ep in order {
            if endpoint_reachable(&ep.host, ep.port, timeout) {
                reachable.push(ep);
            } else {
                unreachable.push(ep);
            }
        }
        reachable.extend(unreachable);
        reachable
    })
    .await
    .unwrap_or(fallback)
}

/// A bounded reachability check to `host:port`: `true` when a TCP connection is
/// established within `timeout`. The whole check (DNS resolve + connect) runs on a
/// detached thread and is bounded by a `recv_timeout`, because `to_socket_addrs`
/// itself has no timeout — so a box with no DNS can't hang the failover path. Any
/// resolve/connect failure (or the bound elapsing) ⇒ `false` (unreachable). Never
/// panics.
fn endpoint_reachable(host: &str, port: u16, timeout: Duration) -> bool {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::sync::mpsc;
    let host = host.to_string();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let ok = (host.as_str(), port)
            .to_socket_addrs()
            .ok()
            .and_then(|mut it| it.next())
            .map(|addr| TcpStream::connect_timeout(&addr, timeout).is_ok())
            .unwrap_or(false);
        let _ = tx.send(ok); // receiver may be gone if we already timed out — fine
    });
    // Bound the whole resolve+connect: the detached thread finishes on its own; we
    // just stop waiting for it after `timeout` + a small scheduling margin.
    rx.recv_timeout(timeout + Duration::from_millis(250)).unwrap_or(false)
}

/// The user-facing status shown when a failover-plan rebuild / relaunch fails —
/// a clear, actionable, bilingual line. Replaces surfacing the RAW rebuild error
/// (which, on a pearlhash lane, can be a bare `POST https://…/m4/challenge: …`
/// leaking an internal PoP endpoint) in the primary status; the raw error is kept
/// only in the verbose debug log ([`log_verbose`]). Localized via [`crate::tr!`].
///
/// Scoped to THIS MACHINE on purpose. All the supervisor observed is that its own
/// rebuild/relaunch against that region failed; it has no way to know whether the
/// region itself is down. Saying "the region endpoint is unreachable" reads as a
/// statement about our relay, and on 2026-07-25 that exact reading sent a whole
/// investigation at a healthy HK relay when the real cause was a client-side zombie
/// socket. Same rule as `errmsg`: report the observation, not a guessed cause.
fn region_retry_message() -> String {
    crate::tr!(
        "Could not reach this region endpoint from this machine; retrying other regions",
        "本机暂时联系不上该区域节点,正在重试其他区域"
    )
    .to_string()
}

/// The status shown when an AUTO (failover-capable) lane relaunches on the SAME region
/// it was on (the stalled region recovered after other regions were unavailable). Unlike
/// the locked-retry label this does NOT claim the region is locked — auto-failover stays
/// available. Localized via [`crate::tr!`].
fn region_resumed_status(to: &Endpoint, window: Duration) -> String {
    let secs = window.as_secs();
    let r = region_label(to);
    crate::tr!(
        format!("region {r} recovered — resuming (no progress for {secs}s)"),
        format!("区域 {r} 已恢复 — 继续运行(此前 {secs}s 无进展)")
    )
}

/// The status shown when EVERY region failed to (re)build/relaunch in one failover round.
/// Honest + bilingual. It no longer says "restart to retry": since BUG#4 the lane retries
/// by itself, and the caller appends the countdown ([`retry_message`]), so telling the
/// user to intervene would be a lie in the other direction.
///
/// Also scoped to THIS MACHINE (see [`region_retry_message`]): "all relays are
/// unavailable" asserts a fact about our infrastructure that the client cannot observe.
/// One local cause — a captive portal, an HTTPS-inspecting firewall, a wedged socket —
/// makes every region fail at once and looks identical from here.
fn all_regions_unreachable_message() -> String {
    crate::tr!(
        "could not reach any region relay from this machine",
        "本机联系不上任何区域中继"
    )
    .to_string()
}

// ── BUG#4: the "waiting to restart" wording ─────────────────────────────────────

/// A short, localized delay ("45s" / "5m" / "1m 30s"). Used in the retry countdown, so
/// a waiting lane always answers the only question the user has: *when*.
fn human_delay(d: Duration) -> String {
    let s = d.as_secs();
    if s < 60 {
        return crate::tr!(format!("{s}s"), format!("{s} 秒"));
    }
    let (m, r) = (s / 60, s % 60);
    if r == 0 {
        crate::tr!(format!("{m}m"), format!("{m} 分钟"))
    } else {
        crate::tr!(format!("{m}m {r}s"), format!("{m} 分 {r} 秒"))
    }
}

/// Render an engine exit code the way the platform wrote it: a Windows NTSTATUS
/// (`0xC0000374`) in hex, an ordinary status in decimal. The hex form is what the
/// user will find in Event Viewer / a web search, so it must match.
fn fmt_exit_code(code: i32) -> String {
    let raw = code as u32;
    if raw >= 0x8000_0000 {
        format!("0x{raw:08X}")
    } else {
        code.to_string()
    }
}

/// Translate an engine exit code into a plain-language cause, when we know one.
///
/// **Why this is worth code.** The reported failure carried `state: error` and nothing
/// else; the miner had no way to tell "Alice broke" from "the third-party engine
/// aborted itself". `0xC0000374` is Windows' heap-corruption abort raised *inside*
/// SRBMiner — the user can neither cause nor fix it, and we should say so plainly
/// instead of showing a bare number. `None` for a code we have no honest explanation
/// for: we print the raw code rather than invent a story about it.
///
/// Covers the Windows NTSTATUS aborts a mining engine actually hits, plus the
/// `128 + signal` shell convention for the unix side.
pub fn exit_code_explanation(code: i32) -> Option<String> {
    let third_party = crate::tr!(
        " — a fault inside the third-party mining engine, not in Alice",
        "(第三方挖矿引擎自身的缺陷,不是 Alice 的问题)"
    );
    let s = match code as u32 {
        0xC000_0374 => crate::tr!(
            format!("heap corruption{third_party}"),
            format!("堆内存损坏{third_party}")
        ),
        0xC000_0005 => crate::tr!(
            format!("invalid memory access{third_party}"),
            format!("非法内存访问{third_party}")
        ),
        0xC000_0409 => crate::tr!(
            format!("stack buffer overrun{third_party}"),
            format!("栈缓冲区溢出{third_party}")
        ),
        0xC000_00FD => crate::tr!(
            format!("stack overflow{third_party}"),
            format!("栈溢出{third_party}")
        ),
        0xC000_001D => crate::tr!(
            "illegal instruction — the engine build may not match this CPU/GPU".to_string(),
            "非法指令 —— 该引擎版本可能与此 CPU/GPU 不匹配".to_string()
        ),
        0xC000_0094 => crate::tr!(
            format!("integer divide by zero{third_party}"),
            format!("整数除以零{third_party}")
        ),
        0xC000_0135 | 0xC000_0139 => crate::tr!(
            "a required system library is missing — reinstall the engine / the Visual C++ runtime"
                .to_string(),
            "缺少所需的系统库 —— 请重新安装引擎或 Visual C++ 运行库".to_string()
        ),
        0xC000_013A | 0x4001_0005 => crate::tr!(
            "terminated by Ctrl-C / a console close".to_string(),
            "被 Ctrl-C 或控制台关闭终止".to_string()
        ),
        _ => return unix_signal_explanation(code),
    };
    Some(s)
}

/// The unix side of [`exit_code_explanation`]: a shell reports a signal death as
/// `128 + signal`, and a child we could not read a code from at all comes back as `-1`.
fn unix_signal_explanation(code: i32) -> Option<String> {
    let s = match code {
        134 => crate::tr!("aborted (SIGABRT)".to_string(), "被中止(SIGABRT)".to_string()),
        139 => crate::tr!(
            "segmentation fault (SIGSEGV)".to_string(),
            "段错误(SIGSEGV)".to_string()
        ),
        137 => crate::tr!(
            "killed (SIGKILL) — often the OS out-of-memory killer".to_string(),
            "被强制杀死(SIGKILL)—— 常见于系统内存不足".to_string()
        ),
        136 => crate::tr!(
            "floating-point exception (SIGFPE)".to_string(),
            "浮点异常(SIGFPE)".to_string()
        ),
        132 => crate::tr!(
            "illegal instruction (SIGILL)".to_string(),
            "非法指令(SIGILL)".to_string()
        ),
        -1 => crate::tr!(
            "terminated by a signal (no exit code was reported)".to_string(),
            "被信号终止(没有退出码)".to_string()
        ),
        _ => return None,
    };
    Some(s)
}

/// The cause half of a crash retry status: what the engine did, in plain language.
fn engine_exit_cause(code: i32) -> String {
    let shown = fmt_exit_code(code);
    match exit_code_explanation(code) {
        Some(why) => crate::tr!(
            format!("the mining engine crashed: {why} (exit code {shown})"),
            format!("挖矿引擎崩溃:{why}(退出码 {shown})")
        ),
        None => crate::tr!(
            format!("the mining engine exited unexpectedly (exit code {shown})"),
            format!("挖矿引擎意外退出(退出码 {shown})")
        ),
    }
}

/// The FULL, localized status line for a pending automatic restart: what happened, and
/// when the next attempt is. Both halves are mandatory — the whole point of BUG#4's fix
/// is that a stopped lane can never again be silent about either.
fn retry_message(reason: &RetryReason, remaining: Duration, attempt: u32) -> String {
    let when = human_delay(remaining);
    let cause = match reason {
        RetryReason::EngineExit(code) => engine_exit_cause(*code),
        RetryReason::Stalled(secs) => crate::tr!(
            format!("no progress for {secs}s on this endpoint"),
            format!("该节点已 {secs}s 无进展")
        ),
        RetryReason::AllRegionsDown => all_regions_unreachable_message(),
        RetryReason::RelaunchFailed => crate::tr!(
            "the mining engine could not be relaunched".to_string(),
            "挖矿引擎无法重新启动".to_string()
        ),
        RetryReason::EngineStillAlive => crate::tr!(
            "the previous engine process has not exited yet".to_string(),
            "上一个引擎进程尚未退出".to_string()
        ),
    };
    crate::tr!(
        format!("{cause} — restarting automatically in {when} (attempt {attempt})"),
        format!("{cause} —— 将在 {when}后自动重启(第 {attempt} 次尝试)")
    )
}

/// The user-facing status for a LOCKED / single-endpoint plan that is NOT a PRL
/// region relay (a fixed pool endpoint — XMR/RVN, or an operator override). Generic
/// "endpoint locked" wording; it deliberately does NOT borrow the PRL region-failover
/// language ("no auto-failover") because a fixed pool has no region-failover concept
/// to disable. Localized via [`crate::tr!`].
fn endpoint_locked_status(ep: &Endpoint, window: Duration) -> String {
    let secs = window.as_secs();
    let e = ep.host_port();
    crate::tr!(
        format!("endpoint {e} locked — retrying this endpoint (no progress for {secs}s)"),
        format!("节点 {e} 已锁定 — 正在重试该节点(已 {secs}s 无进展)")
    )
}

/// Is this endpoint a PRL region relay (a known `us` / `asia` tag)? A fixed pool
/// endpoint (XMR/RVN) or operator override is NOT — it has no region-failover
/// semantics, so its lock status uses generic "endpoint locked" wording.
fn is_region_relay(ep: &Endpoint) -> bool {
    crate::lane::gpu_prl::region_tag_for_host(&ep.host).is_some()
}

/// A SHORT status-line label for an endpoint: the region tag (`US` / `ASIA`) for a
/// PRL region relay, else the endpoint host's first DNS label upper-cased
/// (`hk.aliceprotocol.org:3333` → `HK`). Never the full crowded `host:port`.
fn short_region_label(ep: &Endpoint) -> String {
    match crate::lane::gpu_prl::region_tag_for_host(&ep.host) {
        Some(tag) => tag.to_ascii_uppercase(),
        None => short_host_label(&ep.host),
    }
}

/// The first DNS label of a host, upper-cased (`hk.aliceprotocol.org` → `HK`). Accepts
/// a bare `host` or a `host:port` (the port is dropped).
fn short_host_label(host: &str) -> String {
    host.split(':')
        .next()
        .unwrap_or(host)
        .split('.')
        .next()
        .unwrap_or(host)
        .to_ascii_uppercase()
}

/// Render a SHORT, single-glance, LOCALIZED status line from a machine status key
/// ([`StatusArgs`]) produced by the Layer-B watchdog. Uses the PROCESS-GLOBAL
/// language ([`crate::i18n`]), so a front-end that mirrors its own language toggle
/// into [`crate::i18n::set_lang`] and calls this at DRAW time re-localizes the status
/// live — the fix for a `zh`-produced status bleeding through an `en` UI. An unknown
/// key returns an empty string so the caller can fall back to the raw `message`.
///
/// Keys: `region_locked_no_failover`, `endpoint_locked`, `auto_failover`,
/// `region_recovered`, `region_retrying`, `all_regions_unavailable`,
/// `budget_exhausted`.
pub fn status_short(key: &str, args: &StatusArgs) -> String {
    let region = args.region.clone().unwrap_or_default();
    let to = args.to_region.clone().unwrap_or_default();
    let secs = args.stalled_s.unwrap_or(0);
    match key {
        "region_locked_no_failover" => crate::tr!(
            format!("{region} locked · no failover · {secs}s stalled"),
            format!("区域已锁定:仅 {region} · {secs}s 无进展")
        ),
        "endpoint_locked" => crate::tr!(
            format!("Endpoint locked · {secs}s stalled"),
            format!("节点已锁定 · {secs}s 无进展")
        ),
        "auto_failover" => crate::tr!(
            format!("Failover: {region} → {to} · {secs}s stalled"),
            format!("切换区域:{region} → {to} · {secs}s 无进展")
        ),
        "region_recovered" => crate::tr!(
            format!("{region} recovered · resuming"),
            format!("{region} 已恢复 · 继续运行")
        ),
        // Both of these are what THIS MACHINE observed, not a verdict on our relays —
        // see `region_retry_message` for why the distinction is load-bearing.
        "region_retrying" => crate::tr!(
            "No reply from endpoint · retrying".to_string(),
            "节点无响应 · 正在重试".to_string()
        ),
        "all_regions_unavailable" => crate::tr!(
            "No relay reachable from here · stopped".to_string(),
            "本机连不上任何中继 · 已停止".to_string()
        ),
        // ── LAYER 3: the acceptance halt ────────────────────────────────────────
        // One line, and it must land the two facts that matter in the width of a
        // status pill: we stopped, and your shares were not being accepted. The
        // attribution and the full advice live in the tooltip.
        "acceptance_halt_network" | "acceptance_halt_local" | "acceptance_halt_unknown" => {
            let accepted = args.shares_accepted.unwrap_or(0);
            let rejected = args.shares_rejected.unwrap_or(0);
            let submitted = accepted.saturating_add(rejected);
            if accepted == 0 && submitted > 0 {
                crate::tr!(
                    format!("Stopped · {submitted} shares submitted, 0 accepted"),
                    format!("已停止 · 已提交 {submitted} 份额,0 个被接受")
                )
            } else {
                let pct = args.accept_pct.unwrap_or(0.0);
                crate::tr!(
                    format!("Stopped · only {pct:.0}% of shares accepted"),
                    format!("已停止 · 仅 {pct:.0}% 的份额被接受")
                )
            }
        }
        "budget_exhausted" => crate::tr!(
            "No progress · stopped to avoid a restart storm".to_string(),
            "长时间无进展 · 已停止以避免频繁重启".to_string()
        ),
        // ── BUG#4: a lane that is WAITING to restart itself ─────────────────────
        "engine_crashed_retrying" => {
            let when = human_delay(Duration::from_secs(args.retry_in_s.unwrap_or(0)));
            crate::tr!(
                format!("Engine crashed · retrying in {when}"),
                format!("引擎崩溃 · {when}后重试")
            )
        }
        "stall_retrying" => {
            let when = human_delay(Duration::from_secs(args.retry_in_s.unwrap_or(0)));
            crate::tr!(
                format!("No progress · retrying in {when}"),
                format!("无进展 · {when}后重试")
            )
        }
        "all_regions_retrying" => {
            let when = human_delay(Duration::from_secs(args.retry_in_s.unwrap_or(0)));
            crate::tr!(
                format!("No relay reachable from here · retrying in {when}"),
                format!("本机连不上任何中继 · {when}后重试")
            )
        }
        "relaunch_retrying" | "engine_still_alive_retrying" => {
            let when = human_delay(Duration::from_secs(args.retry_in_s.unwrap_or(0)));
            crate::tr!(
                format!("Could not relaunch · retrying in {when}"),
                format!("重启未成功 · {when}后重试")
            )
        }
        _ => String::new(),
    }
}

/// Is this status key one of the BUG#4 "an automatic restart is pending" family? A
/// front-end can use it to render a WAITING look (a countdown) rather than a dead
/// error, without hard-coding the key list.
pub fn status_is_retrying(key: &str) -> bool {
    matches!(
        key,
        "engine_crashed_retrying"
            | "stall_retrying"
            | "all_regions_retrying"
            | "relaunch_retrying"
            | "engine_still_alive_retrying"
    )
}

/// The FULL, localized tooltip for a status key — the complete endpoint + the honest
/// explanation the crowded one-line status omits (UI doc: full detail belongs in the
/// tooltip, not the status line). `None` when a key has nothing extra to add.
pub fn status_tooltip(key: &str, args: &StatusArgs) -> Option<String> {
    let ep = args.endpoint.clone().unwrap_or_default();
    let to = args.to_region.clone().unwrap_or_default();
    let secs = args.stalled_s.unwrap_or(0);
    match key {
        "region_locked_no_failover" | "endpoint_locked" if !ep.is_empty() => Some(crate::tr!(
            format!(
                "Locked to {ep}. The miner will retry this endpoint only and will not fail over automatically."
            ),
            format!("已锁定到 {ep}。矿工只会重试此节点,不会自动切换。")
        )),
        "auto_failover" => Some(crate::tr!(
            format!("No progress for {secs}s — switched to {to}."),
            format!("已 {secs}s 无进展 —— 已切换到 {to}。")
        )),
        // ── LAYER 3: the paragraph the 2026-08-11 miner never got ───────────────
        // Rebuilt from the raw numbers in `args`, so a GUI in a different language
        // than the CLI that produced them still reads it in its own.
        "acceptance_halt_network" | "acceptance_halt_local" | "acceptance_halt_unknown" => {
            let accepted = args.shares_accepted.unwrap_or(0);
            let rejected = args.shares_rejected.unwrap_or(0);
            let attribution = match key {
                "acceptance_halt_network" => Attribution::NetworkWide,
                "acceptance_halt_local" => Attribution::LocalOnly,
                _ => Attribution::Unknown,
            };
            let collapse = Collapse {
                period: crate::acceptance::PeriodStat {
                    accepted,
                    rejected,
                    elapsed: Duration::from_secs(secs),
                },
                run_accepted: accepted,
                run_rejected: rejected,
                shutout: accepted == 0,
            };
            Some(acceptance::halt_explanation(&collapse, attribution))
        }
        // ── BUG#4: the full story behind a pending automatic restart ────────────
        "engine_crashed_retrying" => {
            let code = args.exit_code.unwrap_or(0);
            let when = human_delay(Duration::from_secs(args.retry_in_s.unwrap_or(0)));
            let attempt = args.attempt.unwrap_or(1);
            let mut s = crate::tr!(
                format!("{}. Restarting automatically in {when} (attempt {attempt}).", engine_exit_cause(code)),
                format!("{}。将在 {when}后自动重启(第 {attempt} 次尝试)。", engine_exit_cause(code))
            );
            if let Some(n) = args.crashes.filter(|n| *n > 1) {
                s.push_str(&crate::tr!(
                    format!(" The engine has crashed {n} times since this run started."),
                    format!(" 本次运行以来引擎已崩溃 {n} 次。")
                ));
            }
            Some(s)
        }
        key if status_is_retrying(key) => {
            let when = human_delay(Duration::from_secs(args.retry_in_s.unwrap_or(0)));
            let attempt = args.attempt.unwrap_or(1);
            Some(crate::tr!(
                format!(
                    "Mining stopped on {ep}. The miner is retrying by itself in {when} (attempt {attempt}) — no action needed; use Stop if you want it to stay stopped."
                ),
                format!(
                    "{ep} 上的挖矿已停止。矿工会在 {when}后自动重试(第 {attempt} 次尝试)—— 无需手动操作;若希望保持停止,请点击停止。"
                )
            ))
        }
        _ => None,
    }
}

/// BACKWARD-COMPAT (fix "B"): recover a machine key + [`StatusArgs`] from a RAW
/// (already-localized) Layer-B lock `message` string — EN **or** ZH — so a NEW GUI
/// paired with an OLD CLI (whose snapshot carries only the baked `message`, no
/// `message_key`) can still re-localize + shorten it. Recognizes the region-lock /
/// endpoint-lock family (the reported case); returns `None` for anything else (the
/// caller then shows the raw string unchanged). Newer snapshots carry `message_key`
/// directly and never reach this path.
pub fn status_from_legacy(msg: &str) -> Option<(String, StatusArgs)> {
    let secs = extract_stalled_secs(msg);
    // Region / endpoint LOCK, both languages. The label sits between the lead-in
    // (`region ` / `区域 ` / `endpoint ` / `节点 `) and `locked` / `已锁定`.
    let lock_label = between(msg, "region ", " locked")
        .or_else(|| between(msg, "区域 ", " 已锁定"))
        .or_else(|| between(msg, "endpoint ", " locked"))
        .or_else(|| between(msg, "节点 ", " 已锁定"));
    if let Some(label) = lock_label {
        // A bare region tag (`us`/`asia`) → PRL region-lock wording; a `host:port`
        // fixed pool (e.g. the XMR relay) → generic endpoint-lock wording (checkpoint
        // ③: a fixed pool must not read like a PRL region failover).
        let looks_like_host = label.contains('.') || label.contains(':');
        let (key, region) = if looks_like_host {
            ("endpoint_locked", short_host_label(label))
        } else {
            ("region_locked_no_failover", label.to_ascii_uppercase())
        };
        return Some((
            key.to_string(),
            StatusArgs {
                endpoint: Some(label.to_string()),
                region: Some(region),
                to_region: None,
                stalled_s: secs,
                ..Default::default()
            },
        ));
    }
    None
}

/// The substring between the first `start` and the following `end` (trimmed); `None`
/// if either marker is absent.
fn between<'a>(s: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let i = s.find(start)? + start.len();
    let rest = &s[i..];
    let j = rest.find(end)?;
    Some(rest[..j].trim())
}

/// Extract the no-progress seconds from a raw status string: the first run of digits
/// immediately followed by an ASCII `s` (both the EN `…for 600s…` and ZH `…已 600s…`
/// shapes). A `host:port`'s digits are followed by `)`/space, not `s`, so they are
/// skipped. `None` if no such token exists.
fn extract_stalled_secs(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() {
            let start = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            if i < b.len() && b[i] == b's' {
                return s[start..i].parse().ok();
            }
        } else {
            i += 1;
        }
    }
    None
}

/// Echo a raw internal error to STDERR ONLY when the verbose env is set
/// (`ALICE_MINER_VERBOSE=1`), so the detail is available for debugging without
/// leaking an internal endpoint / path into the user's primary status line. A no-op
/// otherwise. NOT localized (a developer-facing debug line).
fn log_verbose(context: &str, err: &str) {
    if std::env::var("ALICE_MINER_VERBOSE").map(|v| v == "1").unwrap_or(false) {
        eprintln!("[verbose] {context}: {err}");
    }
}

/// Update the snapshot from one raw engine output line, dispatching to the
/// parser named by [`ParserKind`] (derived from the lane for a bundled engine, or
/// from the custom miner's preset): the XMR/RandomX line parsers
/// ([`parse_hashrate_hs`] / [`parse_share_counts`], verbatim from the Wallet) for
/// [`ParserKind::Xmr`], the KawPoW parser for [`ParserKind::Kawpow`], the SRBMiner
/// parser for [`ParserKind::Srbminer`], the AlphaMiner parser for
/// [`ParserKind::Alpha`], and the honest best-effort [`parse_generic`] for
/// [`ParserKind::Generic`] (an UNKNOWN custom miner). All yield hashrate in H/s +
/// cumulative accepted/rejected shares, so the [`LaneStats`] shape is identical.
/// ALSO marks Layer-B **progress** (a new accepted share or a higher hashrate
/// re-arms the no-progress watchdog). For a `Generic` miner whose format can't be
/// read, every field stays `None` — the lane shows "running, telemetry unavailable"
/// (the dashboard's honest degrade), NEVER a fabricated number.
fn apply_log_line(g: &mut Inner, parser: ParserKind, raw: &str) {
    let line = sanitize_log_line(raw);
    if line.is_empty() {
        return;
    }
    match parser {
        ParserKind::Xmr => {
            if let Some(hr) = parse_hashrate_hs(&line) {
                g.hashrate_hs = Some(hr);
                note_hashrate_progress(g, hr);
            }
            // Triple-window (10s/60s/15m): xmrig is the ONE engine that reports them.
            // Each window is set independently; a `n/a` slot leaves that window None
            // (we never backfill it from another window).
            if let Some((w10, w60, w15)) = parse_hashrate_windows(&line) {
                // The primary `hashrate_hs` already prefers 10s (else 60s) above; keep
                // the 60s/15m windows for the triple-window display only.
                let _ = w10;
                g.hashrate_60s_hs = w60;
                g.hashrate_15m_hs = w15;
            }
            if let Some((accepted, rejected)) = parse_share_counts(&line) {
                g.accepted = accepted;
                g.rejected = rejected;
                note_accepted_progress(g, accepted);
            }
        }
        ParserKind::Kawpow => {
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
                apply_telemetry(g, &sample);
            }
        }
        ParserKind::Srbminer => {
            // SRBMiner (pearlhash) writes share/hashrate lines to its --log-file
            // (the supervisor tails it). Accepted/rejected can arrive on SEPARATE
            // lines, so update each independently (unlike the kawpow both-or-none).
            //
            // SRBMiner emits share/hashrate lines ONLY to its `--log-file` (not
            // stdout/stderr). `spawn_run` spawns a generation-gated file-tail task
            // (`tail_log_file_into` on the engine's `--log-file`, engine.rs
            // `prl_log_path`) that feeds each new line into the SAME `LogLine`
            // channel as the stdout pump, so this arm sees the real SRBMiner output.
            // `parse_srbminer` is validated against a real pearlhash log: the TH/s
            // rate + the cumulative `[acc|rej|..]` bracket / `Shares acc./rej.`
            // summary (per-share event lines carry a latency, not a count → ignored).
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
                apply_telemetry(g, &sample);
            }
        }
        ParserKind::Alpha => {
            // alpha-miner (V100/Volta pearlhash) writes logfmt to STDOUT (the stdout
            // pump feeds this arm — no --log-file needed). `parse_alpha`, validated
            // against the real V100 capture, reads the periodic miner-status line:
            // `hashrate_th_s` (→ H/s) + the cumulative `hits` (submitted shares). The
            // client never sees a pool accept/reject (async submit; acceptance is the
            // relay's truth), so `rejected` stays None — only hashrate + accepted move.
            if let Some(sample) = crate::stats::parse_alpha(&line) {
                if let Some(hr) = sample.hashrate_hs {
                    g.hashrate_hs = Some(hr);
                    note_hashrate_progress(g, hr);
                }
                if let Some(a) = sample.accepted {
                    g.accepted = a;
                    note_accepted_progress(g, a);
                }
                apply_telemetry(g, &sample);
            }
        }
        ParserKind::Generic => {
            // An UNKNOWN custom miner: best-effort scan (`<num> <hash-unit>` +
            // accepted/rejected). Assign each field only when present. When a line
            // can't be read every field stays `None`, so the lane shows "running,
            // telemetry unavailable" — NEVER a fabricated number.
            //
            // The share counters are folded through [`fold_cumulative`], not
            // last-wins: the generic scanner reads an arbitrary third-party format,
            // so a single mis-read line must never walk the user's session totals
            // BACKWARDS (the `cuda:0 → accepted=0` bug — now also fixed at the
            // parser, this is the belt to those braces). It is NOT a plain high-water
            // mark either: a fall is adopted once a SECOND, consistent reading
            // confirms it, so a spurious high value heals instead of sticking for the
            // session. A hard reset happens exactly where it should — `spawn_run`
            // zeroes the counters on a fresh (non-failover) start.
            if let Some(sample) = parse_generic(&line) {
                if let Some(hr) = sample.hashrate_hs {
                    g.hashrate_hs = Some(hr);
                    note_hashrate_progress(g, hr);
                }
                if let Some(a) = sample.accepted {
                    let mut pending = g.generic_accepted_pending;
                    g.accepted = fold_cumulative(g.accepted, &mut pending, a);
                    g.generic_accepted_pending = pending;
                    note_accepted_progress(g, g.accepted);
                }
                if let Some(r) = sample.rejected {
                    let mut pending = g.generic_rejected_pending;
                    g.rejected = fold_cumulative(g.rejected, &mut pending, r);
                    g.generic_rejected_pending = pending;
                }
                apply_telemetry(g, &sample);
            }
        }
    }
    // Layer 3: after the counters have been folded, let the acceptance guard look at
    // them. This is the ONLY place the cumulative pair is known-consistent for every
    // parser, so it is the only correct place to observe from. Cheap by construction
    // (a few integer compares; at most one division per completed period) — it runs
    // under the same lock as the stats hot path.
    let (a, r) = (g.accepted, g.rejected);
    g.acceptance.observe(Instant::now(), a, r);
    g.last_line = line;
}

/// Fold a parsed sample's telemetry (temp/power/util/fan) into the supervisor state,
/// last-wins per field. Each field is assigned ONLY when the sample carried it, so a
/// line that reports the rate but no temperature leaves a prior temperature intact
/// (and a `nvidia-smi` fallback reading survives between engine speed lines). Fail-soft
/// by construction — a `None` field is simply not written.
fn apply_telemetry(g: &mut Inner, sample: &crate::stats::KawpowSample) {
    if let Some(t) = sample.temp_c {
        g.telem_temp_c = Some(t);
    }
    if let Some(p) = sample.power_w {
        g.telem_power_w = Some(p);
    }
    if let Some(u) = sample.util_pct {
        g.telem_util_pct = Some(u);
    }
    if let Some(f) = sample.fan_pct {
        g.telem_fan_pct = Some(f);
    }
}

/// Extract the value following `--log-file` in a child argv (the GPU-PRL SRBMiner
/// log path the supervisor must tail). `None` if the flag/value is absent.
fn extract_log_file_arg(args: &[String]) -> Option<std::path::PathBuf> {
    args.iter()
        .position(|a| a == "--log-file")
        .and_then(|i| args.get(i + 1))
        .map(std::path::PathBuf::from)
}

/// Tail a child's `--log-file`, feeding each COMPLETE new line into `tx` (the same
/// [`LogLine`] channel the per-lane parser drains). SRBMiner writes shares only
/// here, never stdout, so this is the data source that keeps the GPU-PRL lane's
/// stats + no-progress watchdog honest.
///
/// * **generation-gated**: returns as soon as `inner.generation` advances (a newer
///   child took over) — a stale tail can never clobber a newer run.
/// * polls ~1s; tolerates the file not existing yet (SRBMiner creates it on start)
///   and truncation/rotation (offset reset).
/// * only advances past the LAST newline, so a partially-written trailing line is
///   re-read whole next tick (never splits a share/hashrate line). Offset is tracked
///   in RAW bytes (not the lossy-decoded string) so multi-byte/invalid bytes can't
///   desync it. Bounded per-poll read so a runaway file can't stall the task.
async fn tail_log_file_into(
    path: std::path::PathBuf,
    tx: UnboundedSender<LogLine>,
    inner: Arc<Mutex<Inner>>,
    gen: u64,
) {
    use std::io::{Read, Seek, SeekFrom};
    const POLL: Duration = Duration::from_millis(1000);
    const MAX_READ: usize = 256 * 1024;
    let mut offset: u64 = 0;
    loop {
        tokio::time::sleep(POLL).await;
        if inner.lock().expect("mutex").generation != gen {
            return; // a newer run superseded this child
        }
        let mut f = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(_) => continue, // not created yet
        };
        let len = match f.metadata() {
            Ok(m) => m.len(),
            Err(_) => continue,
        };
        if len < offset {
            offset = 0; // truncated / rotated → restart from the top
        }
        if len <= offset {
            continue; // nothing new
        }
        if f.seek(SeekFrom::Start(offset)).is_err() {
            continue;
        }
        let want = ((len - offset) as usize).min(MAX_READ);
        let mut buf = vec![0u8; want];
        let n = match f.read(&mut buf) {
            Ok(0) => continue,
            Ok(n) => n,
            Err(_) => continue,
        };
        // Consume only up to the last complete line (raw-byte index).
        let consume = match buf[..n].iter().rposition(|&b| b == b'\n') {
            Some(i) => i + 1,
            None => continue, // no complete line yet — re-read next tick
        };
        offset += consume as u64;
        for line in String::from_utf8_lossy(&buf[..consume]).lines() {
            if tx
                .send(LogLine {
                    stream: LogStream::Stdout,
                    text: line.to_string(),
                })
                .is_err()
            {
                return; // receiver gone — channel closed
            }
        }
    }
}

/// One row of the `nvidia-smi` telemetry query (the hottest card is picked across rows).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct NvidiaTelemetry {
    temp_c: Option<f64>,
    power_w: Option<f64>,
    util_pct: Option<f64>,
    fan_pct: Option<f64>,
}

/// The best-effort **`nvidia-smi` telemetry fallback** (generation-gated). For an
/// NVIDIA GPU lane whose engine may not print temp/power/util/fan, this polls a single
/// lightweight `nvidia-smi --query-gpu=temperature.gpu,power.draw,utilization.gpu,fan.speed`
/// every [`NVIDIA_TELEMETRY_POLL`] (~5s), and fills ONLY the telemetry fields the engine
/// left `None` for this tick — a real engine reading always wins over an smi guess.
///
/// Non-blocking: the (synchronous, timeout-bounded) `nvidia-smi` call runs on a blocking
/// thread via `spawn_blocking` so it can never starve the tokio runtime. Best-effort +
/// self-terminating: the FIRST failed query (no `nvidia-smi` on Apple Silicon / AMD / a
/// box with no driver) ends the task cleanly — we never spawn it if the lane isn't a GPU
/// lane, and we never keep retrying on a box that plainly has no NVIDIA GPU. The task
/// also returns as soon as `generation` advances (a newer run / stop).
async fn spawn_nvidia_telemetry_poll(inner: Arc<Mutex<Inner>>, gen: u64) {
    loop {
        // Stop if a newer run took over (or the lane stopped and bumped generation).
        if inner.lock().expect("mutex").generation != gen {
            return;
        }
        // Run the sync, timeout-bounded query OFF the async worker so a wedged driver
        // can never stall the runtime.
        let telem = tokio::task::spawn_blocking(query_nvidia_telemetry)
            .await
            .unwrap_or(None);
        match telem {
            Some(t) => {
                let mut g = inner.lock().expect("mutex");
                if g.generation != gen {
                    return;
                }
                // Fill ONLY the fields the engine hasn't reported for this run — a real
                // engine-parsed reading (set by `apply_telemetry`) always takes precedence.
                if g.telem_temp_c.is_none() {
                    g.telem_temp_c = t.temp_c;
                }
                if g.telem_power_w.is_none() {
                    g.telem_power_w = t.power_w;
                }
                if g.telem_util_pct.is_none() {
                    g.telem_util_pct = t.util_pct;
                }
                if g.telem_fan_pct.is_none() {
                    g.telem_fan_pct = t.fan_pct;
                }
            }
            // A failed query on the FIRST poll = no usable nvidia-smi (Apple/AMD/no driver);
            // stop rather than spin. (Later transient failures also just end the task; the
            // engine-parsed telemetry, when present, keeps the readout alive.)
            None => return,
        }
        tokio::time::sleep(NVIDIA_TELEMETRY_POLL).await;
    }
}

/// Query `nvidia-smi` once for the current temp/power/util/fan, returning the HOTTEST
/// card across all rows (the safety-relevant reading on a multi-GPU rig). `None` when
/// `nvidia-smi` is absent / errors / times out (fail-soft — the caller then stops the
/// poll). Uses `nounits` so every cell is a bare number.
fn query_nvidia_telemetry() -> Option<NvidiaTelemetry> {
    let out = run_nvidia_smi_bounded(
        &[
            "--query-gpu=temperature.gpu,power.draw,utilization.gpu,fan.speed",
            "--format=csv,noheader,nounits",
        ],
        NVIDIA_TELEMETRY_TIMEOUT,
    )?;
    parse_nvidia_telemetry_csv(&out)
}

/// Spawn `nvidia-smi <args>`, capture stdout, wait up to `timeout` (kill on timeout).
/// `None` on ANY failure (missing binary / non-zero exit / non-UTF8 / timeout). Mirrors
/// the `detect::run_bounded` pattern (no external `timeout(1)` dependency, Windows-safe).
fn run_nvidia_smi_bounded(args: &[&str], timeout: Duration) -> Option<String> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    let mut child = Command::new("nvidia-smi")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut out = String::new();
                if let Some(mut so) = child.stdout.take() {
                    let _ = so.read_to_string(&mut out);
                }
                return status.success().then_some(out);
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return None,
        }
    }
}

/// Parse the `nvidia-smi` telemetry CSV (`temp, power, util, fan` per row, `nounits`) and
/// return the HOTTEST card's readings (max temperature). A cell that reads `[N/A]` /
/// non-numeric → `None` for that field (fail-soft). `None` when no row parsed.
fn parse_nvidia_telemetry_csv(csv: &str) -> Option<NvidiaTelemetry> {
    let cell = |s: &str| -> Option<f64> { s.trim().parse::<f64>().ok() };
    let mut best: Option<NvidiaTelemetry> = None;
    let mut best_temp = f64::NEG_INFINITY;
    for line in csv.lines() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        let mut it = l.split(',');
        let row = NvidiaTelemetry {
            temp_c: it.next().and_then(cell),
            power_w: it.next().and_then(cell),
            util_pct: it.next().and_then(cell),
            fan_pct: it.next().and_then(cell),
        };
        if row == NvidiaTelemetry::default() {
            continue; // a fully-unparseable row contributes nothing
        }
        // Pick the hottest card; a row without a temp still seeds `best` if none yet.
        let t = row.temp_c.unwrap_or(f64::NEG_INFINITY);
        if best.is_none() || t > best_temp {
            best_temp = t;
            best = Some(row);
        }
    }
    best
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
/// is doing real, credited work). A rise ALSO marks the CURRENT endpoint's region as
/// "last-good": if the active host maps to a region tag (us/asia) that differs
/// from the one already persisted this run, stage it in `pending_good_region` for the
/// log-pump task to write to `settings.last_good_region` off-lock. Lane-agnostic —
/// keyed purely by the endpoint host, so the XMR/RVN relay (`hk.aliceprotocol.org`,
/// not a region relay) never records anything.
fn note_accepted_progress(g: &mut Inner, accepted: u64) {
    if accepted > g.progress_accepted {
        g.progress_accepted = accepted;
        g.last_progress_at = Some(Instant::now());
        // Record the region that produced this accepted share (once per region change).
        let host = g.endpoint_plan.current().host.clone();
        if let Some(tag) = crate::lane::gpu_prl::region_tag_for_host(&host) {
            if g.persisted_good_region.as_deref() != Some(tag) {
                g.persisted_good_region = Some(tag.to_string());
                g.pending_good_region = Some(tag.to_string());
            }
        }
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

/// Parse ALL THREE hashrate windows (10s / 60s / 15m, each in H/s) from an XMRig
/// `speed 10s/60s/15m <a> <b> <c> H/s` line. Returns `(10s, 60s, 15m)`, each `None`
/// when that slot is `n/a` (warm-up) or absent. `None` (the whole tuple) only when
/// the line isn't an XMRig speed line. Positional: the three figures map 1:1 to the
/// three windows, so a window we didn't measure stays `None` — NEVER filled from
/// another window. Only XMRig prints this triple; the GPU engines have no such line,
/// so they never call this (the per-lane `apply_log_line` only invokes it for XMR).
pub fn parse_hashrate_windows(line: &str) -> Option<(Option<f64>, Option<f64>, Option<f64>)> {
    if !line.contains("speed") || !line.contains("10s/60s/15m") {
        return None;
    }
    let after = line.split("10s/60s/15m").nth(1)?;
    let mut windows: [Option<f64>; 3] = [None, None, None];
    let mut idx = 0usize;
    for tok in after.split_whitespace() {
        // Stop at the unit (the three figures all precede it; a trailing
        // `max <x> H/s` is past the unit and ignored).
        if tok.eq_ignore_ascii_case("h/s")
            || tok.eq_ignore_ascii_case("kh/s")
            || tok.eq_ignore_ascii_case("mh/s")
        {
            break;
        }
        if idx >= windows.len() {
            break;
        }
        if tok.eq_ignore_ascii_case("n/a") {
            windows[idx] = None; // this window genuinely not measured yet
            idx += 1;
            continue;
        }
        if let Ok(v) = tok.parse::<f64>() {
            windows[idx] = Some(v);
            idx += 1;
        }
        // A non-numeric, non-n/a, non-unit token (shouldn't happen) is skipped
        // without advancing — defensive against an unexpected log shape.
    }
    Some((windows[0], windows[1], windows[2]))
}

/// Parse cumulative `(accepted/rejected)` counts from an XMRig share line, e.g.
/// `net      accepted (12/0) diff 1234 (45 ms)` or `... rejected (12/1) ...`.
/// Returns `None` for non-share lines. **Ported VERBATIM** from
/// `miner_supervisor.rs` (~L299).
//
// HONESTY-DRIVEN DEFERRAL — the a/s/i (accepted / STALE / INVALID) share split, i.e.
// a per-reject CAUSE breakdown. xmrig's stdout `accepted (A/R)` line gives only TWO
// buckets: accepted + a single rejected count, and does NOT split that rejected count
// into a STALE (network/late) vs an INVALID (bad-result/verify) cause. The other GPU
// engines are the same or coarser for the *rejected* count: kawpow gives A/R, and
// AlphaMiner reports only SUBMITTED (the relay owns acceptance — no client-side reject
// at all). SRBMiner is the one partial exception: its per-GPU bracket is
// `[accepted|rejected|stale|eff]`, so it exposes a coarse CUMULATIVE *stale* counter
// (the third field) ALONGSIDE rejected — but `parse_srbminer` reads only the first two
// fields (`accepted|rejected`) and DISCARDS that stale column. So no lane currently
// surfaces a stale signal, and even SRBMiner's stale is a separate parallel counter,
// not a cause-split of `rejected`. Per the credit-only honesty rule we DO NOT fabricate
// a split: `rejected` stays a single bucket and no a/s/i field is added. Surfacing one
// would mean either capturing SRBMiner's stale column (a coarse start, SRBMiner-only)
// or a richer log mode / server-side reject-reason feed for a true per-engine cause
// split — a deliberate future change with its own measurement, not an invented guess.
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
    // Used by the failover tests (unix-only — they script `/bin/sh`) AND by the
    // crash-recovery tests, which run on EVERY OS, so this import is never unused.
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Runtime::new().unwrap()
    }

    /// Serialize any test that SPAWNS a child against the `terminal::tests` child-pid
    /// tests. `spawn_run` records the engine child via `terminal::write_child_pid`, whose
    /// path resolves under the process-global `$ALICE_IDENTITY_DIR`. A concurrent
    /// `terminal::tests` child-pid test sets that var (under this SAME lock) and asserts on
    /// the file, so an unguarded spawn here would write its own pid into that test's dir and
    /// flake its assertion. Holding `IDENTITY_ENV_LOCK` for the spawn test's duration keeps
    /// the two from ever overlapping. UN-gated: the crash-recovery tests spawn on Windows
    /// too — BUG#4 was reported on Windows, so its regression tests must actually RUN
    /// there. A unix-only suite is coverage theatre for a Windows bug.
    fn spawn_env_guard() -> std::sync::MutexGuard<'static, ()> {
        crate::IDENTITY_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A child that exits with `code` as soon as it starts — a "crashing engine" — on
    /// every OS. `/bin/sh` on unix, `cmd /C` on Windows (both resolve via PATH, which
    /// the spawned child's env allowlist keeps).
    /// `cfg!` (not `#[cfg]`) on purpose: BOTH arms are type-checked and compiled on
    /// EVERY platform, so the Windows path can never rot unnoticed behind a cfg the
    /// local build never sees — the coverage-theatre trap this fix is meant to avoid.
    fn crashing_child(code: i32) -> (std::path::PathBuf, Vec<String>) {
        if cfg!(windows) {
            (std::path::PathBuf::from("cmd"), vec!["/C".into(), format!("exit {code}")])
        } else {
            (std::path::PathBuf::from("/bin/sh"), vec!["-c".into(), format!("exit {code}")])
        }
    }

    /// A no-op rebuild closure for tests that don't exercise failover (keeps the
    /// single-endpoint relay plan). The args are fixed.
    fn fixed_rebuild(program: std::path::PathBuf, args: Vec<String>) -> RebuildFn {
        Arc::new(move |_eps: &[Endpoint]| Ok((program.clone(), args.clone())))
    }

    /// A child that stays alive for ~30 s doing nothing — a stand-in for a HEALTHY,
    /// connected engine, on every OS. Same `cfg!`-not-`#[cfg]` discipline as
    /// [`crashing_child`]: both arms compile everywhere so the Windows path cannot rot.
    fn idle_child() -> (std::path::PathBuf, Vec<String>) {
        if cfg!(windows) {
            // `ping -n 31 127.0.0.1` waits ~30 s and needs no console (unlike `timeout`).
            // Its stdout flows through the real log pump, which is the point: those lines
            // must NOT move any counter (they carry no `accepted`/`rejected` token), so
            // the Windows run also proves the parser ignores unrelated engine chatter.
            (
                std::path::PathBuf::from("cmd"),
                vec!["/C".into(), "ping -n 31 127.0.0.1".into()],
            )
        } else {
            (std::path::PathBuf::from("/bin/sh"), vec!["-c".into(), "sleep 30".into()])
        }
    }

    /// Compressed acceptance thresholds: the same state machine, in milliseconds.
    /// Production's 5 min warm-up + 10 min window are unchanged — only the test clock
    /// shrinks, so the LOGIC under test is the shipped logic.
    fn fast_acceptance() -> AcceptanceConfig {
        AcceptanceConfig {
            warmup: Duration::from_millis(30),
            min_window: Duration::from_millis(120),
            min_submissions: 20,
            collapse_pct: 20.0,
            strikes_to_halt: 2,
        }
    }

    /// Push one already-sanitised engine line through the SAME entry point the live
    /// log pump uses (`apply_log_line`, under the same lock), so these tests exercise
    /// the real path rather than poking the monitor directly.
    fn feed(s: &LaneSupervisor, line: &str) {
        let mut g = s.inner.lock().unwrap();
        apply_log_line(&mut g, ParserKind::Xmr, line);
    }

    /// Wait (bounded) for `pred` to hold of the lane's stats.
    async fn wait_for(s: &LaneSupervisor, secs: u64, pred: impl Fn(&LaneStats) -> bool) -> bool {
        for _ in 0..(secs * 10) {
            if pred(&s.stats()) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }

    // ── GPU telemetry (parse + fold) ───────────────────────────────────────────

    /// The `nvidia-smi` CSV parser picks the HOTTEST card and reads each cell, and an
    /// `[N/A]` cell becomes `None` (fail-soft) rather than corrupting the row.
    #[test]
    fn nvidia_telemetry_csv_picks_hottest_and_tolerates_na() {
        // Two cards; the second is hotter → its readings win.
        let csv = "61, 210.5, 97, 48\n74, 260.0, 99, 66\n";
        let t = parse_nvidia_telemetry_csv(csv).expect("parsed");
        assert_eq!(t.temp_c, Some(74.0), "hottest card");
        assert_eq!(t.power_w, Some(260.0));
        assert_eq!(t.util_pct, Some(99.0));
        assert_eq!(t.fan_pct, Some(66.0));

        // An `[N/A]` fan cell (a common laptop/passive-card case) → fan None, rest read.
        let na = parse_nvidia_telemetry_csv("65, 180, 90, [N/A]").expect("parsed");
        assert_eq!(na.temp_c, Some(65.0));
        assert_eq!(na.fan_pct, None);

        // Empty / all-junk input → None (fail-soft).
        assert!(parse_nvidia_telemetry_csv("").is_none());
        assert!(parse_nvidia_telemetry_csv("\n \n").is_none());
    }

    /// `apply_telemetry` folds a sample last-wins per field, leaving a field the sample
    /// didn't carry intact (so an engine speed line without a temp keeps a prior temp /
    /// an nvidia-smi reading).
    #[test]
    fn apply_telemetry_is_last_wins_per_field() {
        let sup = LaneSupervisor::new(Lane::GpuRvn);
        let mut g = sup.inner.lock().unwrap();
        apply_telemetry(
            &mut g,
            &crate::stats::KawpowSample {
                temp_c: Some(60.0),
                power_w: Some(140.0),
                ..Default::default()
            },
        );
        assert_eq!(g.telem_temp_c, Some(60.0));
        assert_eq!(g.telem_power_w, Some(140.0));
        // A later sample with only a new temp updates temp, KEEPS the prior power.
        apply_telemetry(
            &mut g,
            &crate::stats::KawpowSample { temp_c: Some(63.0), ..Default::default() },
        );
        assert_eq!(g.telem_temp_c, Some(63.0), "temp updated");
        assert_eq!(g.telem_power_w, Some(140.0), "power retained (sample carried none)");
    }

    /// `stats()` surfaces the folded telemetry into the UI-safe `LaneStats`.
    #[test]
    fn stats_surface_engine_parsed_telemetry() {
        let sup = LaneSupervisor::new(Lane::GpuPrl);
        {
            let mut g = sup.inner.lock().unwrap();
            g.telem_temp_c = Some(71.0);
            g.telem_fan_pct = Some(55.0);
        }
        let st = sup.stats();
        assert_eq!(st.temp_c, Some(71.0));
        assert_eq!(st.fan_pct, Some(55.0));
        assert_eq!(st.power_w, None, "unset field stays None");
    }

    #[test]
    fn extract_log_file_arg_finds_value_else_none() {
        let args = vec![
            "--algorithm".to_string(),
            "pearlhash".to_string(),
            "--log-file".to_string(),
            "/tmp/alice-prl.log".to_string(),
            "--disable-cpu".to_string(),
        ];
        assert_eq!(
            extract_log_file_arg(&args),
            Some(std::path::PathBuf::from("/tmp/alice-prl.log"))
        );
        // flag with no following value, or absent → None.
        assert_eq!(extract_log_file_arg(&["--log-file".to_string()]), None);
        assert_eq!(
            extract_log_file_arg(&["--foo".to_string(), "bar".to_string()]),
            None
        );
    }

    /// Blocker-1 fix: the GPU-PRL log-file tail must feed the file's lines into the
    /// LogLine channel (so the parser sees SRBMiner's shares), and must STOP as soon
    /// as the run generation advances (a stale tail can't clobber a newer child).
    #[test]
    fn tail_log_file_feeds_lines_then_stops_on_generation_bump() {
        let sup = LaneSupervisor::new(Lane::GpuPrl);
        let inner = sup.inner.clone();
        let gen = inner.lock().expect("mutex").generation;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("alice-tail-test-{}-{}.log", std::process::id(), nanos));
        std::fs::write(&path, "GPU0: pearlhash 31.21 Mh/s\nAccepted: 5 / Rejected: 0\n")
            .expect("seed log");

        rt().block_on(async {
            let (tx, mut rx) = unbounded_channel::<LogLine>();
            let h = tokio::spawn(tail_log_file_into(path.clone(), tx, inner.clone(), gen));

            // First poll fires after ~1s; give margin.
            tokio::time::sleep(Duration::from_millis(1400)).await;
            let mut got = Vec::new();
            while let Ok(l) = rx.try_recv() {
                got.push(l.text);
            }
            assert!(
                got.iter().any(|t| t.contains("Mh/s")),
                "hashrate line must be tailed: {got:?}"
            );
            assert!(
                got.iter().any(|t| t.contains("Accepted")),
                "shares line must be tailed: {got:?}"
            );

            // Bump the generation → the tail must exit on its next poll; lines
            // appended afterward must NOT arrive.
            inner.lock().expect("mutex").generation += 1;
            tokio::time::sleep(Duration::from_millis(1400)).await;
            assert!(
                h.is_finished(),
                "tail task must stop once the run generation advances"
            );
        });
        let _ = std::fs::remove_file(&path);
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

    /// The triple-window parser maps the three figures 1:1 to (10s, 60s, 15m); a
    /// `n/a` slot is `None` for THAT window only (never backfilled from another); a
    /// trailing `max <x>` is ignored; a non-speed line yields `None` for the tuple.
    #[test]
    fn parses_all_three_hashrate_windows() {
        // Full line: 10s + 60s present, 15m still n/a; the `max 1300.0` is ignored.
        assert_eq!(
            parse_hashrate_windows(
                "miner    speed 10s/60s/15m 1234.5 1200.0 n/a H/s max 1300.0 H/s"
            ),
            Some((Some(1234.5), Some(1200.0), None))
        );
        // 10s n/a but 60s + 15m present → only the 10s window is None.
        assert_eq!(
            parse_hashrate_windows("miner    speed 10s/60s/15m n/a 980.0 950.0 H/s"),
            Some((None, Some(980.0), Some(950.0)))
        );
        // All three measured.
        assert_eq!(
            parse_hashrate_windows("miner    speed 10s/60s/15m 100.0 90.0 80.0 H/s"),
            Some((Some(100.0), Some(90.0), Some(80.0)))
        );
        // All n/a (warm-up) → the tuple is present but every window is None (never
        // a fabricated figure).
        assert_eq!(
            parse_hashrate_windows("miner    speed 10s/60s/15m n/a n/a n/a H/s"),
            Some((None, None, None))
        );
        // Not a speed line → the whole tuple is None (nothing measured).
        assert_eq!(parse_hashrate_windows("net      new job from pool"), None);
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
            apply_log_line(&mut g, ParserKind::Xmr, "\u{1b}[1;32maccepted\u{1b}[0m (7/1) diff 900 (40 ms)");
            apply_log_line(&mut g, ParserKind::Xmr, "miner    speed 10s/60s/15m 555.5 540.0 n/a H/s");
        }
        let st = s.stats();
        assert_eq!(st.accepted, 7);
        assert_eq!(st.rejected, 1);
        assert_eq!(st.hashrate_hs, Some(555.5));
        // The triple-window is captured for XMR: 10s+60s measured, 15m still n/a.
        assert_eq!(st.hashrate_60s_hs, Some(540.0));
        assert_eq!(st.hashrate_15m_hs, None, "n/a window stays None, never backfilled");
        assert!(!st.last_line.contains('\u{1b}'));
    }

    /// A GPU lane (no `speed 10s/60s/15m` line) never gets the 60s/15m windows — they
    /// stay `None`, so the dashboard never shows a triple-window for a lane that
    /// didn't measure one (honesty rule).
    #[test]
    fn gpu_lane_has_no_triple_window() {
        let s = LaneSupervisor::new(Lane::GpuRvn);
        {
            let mut g = s.inner.lock().unwrap();
            // A kawpow speed line carries ONE instantaneous rate, no window triple.
            apply_log_line(&mut g, ParserKind::Kawpow, "m kawpowminer Speed 25.00 Mh/s gpu0 [A5+0:R0+0:F0]");
        }
        let st = s.stats();
        assert!(st.hashrate_hs.is_some(), "the single rate is still parsed");
        assert_eq!(st.hashrate_60s_hs, None, "no 60s window for a GPU lane");
        assert_eq!(st.hashrate_15m_hs, None, "no 15m window for a GPU lane");
    }

    #[test]
    fn apply_log_line_uses_kawpow_parser_on_gpu_lane() {
        // The GPU lane routes lines through `parse_kawpow` (MH/s → H/s + shares).
        let s = LaneSupervisor::new(Lane::GpuRvn);
        {
            let mut g = s.inner.lock().unwrap();
            apply_log_line(
                &mut g,
                ParserKind::Kawpow,
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

    /// T5: a CUSTOM miner with an unknown format routes through the GENERIC parser
    /// (chosen by preset, not lane). A recognisable `<num> <unit>` + accepted line is
    /// read; an UNREADABLE line leaves the stats untouched (no fabrication) — the lane
    /// stays "running, telemetry unavailable".
    #[test]
    fn apply_log_line_generic_parser_reads_known_and_degrades_on_unknown() {
        // Build a supervisor whose PARSER is Generic (as a custom miner would set).
        let s = LaneSupervisor::with_backend(
            Lane::GpuPrl,
            EndpointPlan::single(Endpoint::plaintext("us.aliceprotocol.org", 3340)),
            ParserKind::Generic,
            None,
        );
        {
            let mut g = s.inner.lock().unwrap();
            // A readable line: 30.5 MH/s + accepted 12.
            apply_log_line(&mut g, ParserKind::Generic, "[worker] 30.5 MH/s  accepted 12");
        }
        let st = s.stats();
        assert_eq!(st.hashrate_hs, Some(30_500_000.0));
        assert_eq!(st.accepted, 12);
        {
            // An UNreadable line must not zero or invent anything.
            let mut g = s.inner.lock().unwrap();
            apply_log_line(&mut g, ParserKind::Generic, "some proprietary status blob 0xdeadbeef");
        }
        let st2 = s.stats();
        assert_eq!(st2.hashrate_hs, Some(30_500_000.0), "unreadable line kept the last real rate");
        assert_eq!(st2.accepted, 12, "no fabricated share count");
    }

    /// The pure fold behind the generic parser's cumulative counters — the whole
    /// decision table, without spawning anything. ROUND 2: a plain `max` was replaced
    /// by "a fall needs a second, consistent reading", so neither direction can lie
    /// permanently.
    #[test]
    fn fold_cumulative_takes_rises_and_only_corroborated_falls() {
        // A rise is always taken, and clears any pending candidate.
        let mut p = Some(3);
        assert_eq!(fold_cumulative(100, &mut p, 101), 101);
        assert_eq!(p, None, "a rise clears the pending candidate");

        // ONE low reading never moves the total (the decoy / mis-parse case).
        let mut p = None;
        assert_eq!(fold_cumulative(100, &mut p, 0), 100);
        assert_eq!(p, Some(0));
        // …and a rise right after it still wins, leaving no residue.
        assert_eq!(fold_cumulative(100, &mut p, 100), 100);
        assert_eq!(p, None);

        // TWO consecutive, mutually consistent low readings DO re-baseline — this is
        // how a spurious high value heals instead of sticking for the session.
        let mut p = None;
        assert_eq!(fold_cumulative(999_999, &mut p, 101), 999_999, "hold on the first");
        assert_eq!(fold_cumulative(999_999, &mut p, 102), 102, "adopt on the second");
        assert_eq!(p, None);

        // Two low readings that CONTRADICT each other (falling) do not re-baseline;
        // the newest becomes the candidate.
        let mut p = None;
        assert_eq!(fold_cumulative(100, &mut p, 50), 100);
        assert_eq!(fold_cumulative(100, &mut p, 10), 100, "a falling pair is noise");
        assert_eq!(p, Some(10));
        assert_eq!(fold_cumulative(100, &mut p, 11), 11, "…then a consistent pair adopts");

        // Equal readings are "rises" (no change, nothing pending).
        let mut p = Some(7);
        assert_eq!(fold_cumulative(42, &mut p, 42), 42);
        assert_eq!(p, None);
    }

    /// REGRESSION (Bug 3): with the GENERIC parser, the cumulative share counters
    /// cannot be walked backwards by a single mis-read line. Combined with the
    /// parser-side word-boundary fix, an ordinary `cuda:0 power:120` device line
    /// leaves the totals untouched.
    #[test]
    fn generic_parser_share_counters_never_go_backwards() {
        let s = LaneSupervisor::with_backend(
            Lane::GpuPrl,
            EndpointPlan::single(Endpoint::plaintext("us.aliceprotocol.org", 3340)),
            ParserKind::Generic,
            None,
        );
        {
            let mut g = s.inner.lock().unwrap();
            apply_log_line(&mut g, ParserKind::Generic, "shares a:100 r:2 30.0 mh/s");
        }
        assert_eq!(s.stats().accepted, 100);
        assert_eq!(s.stats().rejected, 2);
        {
            // The exact real-world offenders: device/telemetry lines, including the
            // ROUND-2 hyphenated shape. The parser reads NO counts from either, and
            // even if some other format did yield a lower number, one line can never
            // move the totals down.
            let mut g = s.inner.lock().unwrap();
            apply_log_line(&mut g, ParserKind::Generic, "gpu0 cuda:0 power:120 30.0 mh/s");
            apply_log_line(&mut g, ParserKind::Generic, "gpu-a:0 core-r:120 30.0 mh/s");
            // A single lower cumulative reading is held, not adopted.
            apply_log_line(&mut g, ParserKind::Generic, "shares a:3 r:0 30.0 mh/s");
        }
        assert_eq!(s.stats().accepted, 100, "one low line must not regress the total");
        assert_eq!(s.stats().rejected, 2, "one low line must not regress the total");
        {
            // A genuine advance still moves it forward — and clears the candidate.
            let mut g = s.inner.lock().unwrap();
            apply_log_line(&mut g, ParserKind::Generic, "shares a:101 r:3 30.0 mh/s");
        }
        assert_eq!(s.stats().accepted, 101);
        assert_eq!(s.stats().rejected, 3);
    }

    /// The other half of the round-2 rule: the counters must also be able to HEAL.
    /// A spurious HIGH reading (the generic parser mis-reading an unknown format)
    /// used to stick for the entire session under a plain high-water mark; two
    /// consecutive, consistent real readings now re-baseline it.
    #[test]
    fn generic_parser_share_counters_heal_from_a_spurious_high_value() {
        let s = LaneSupervisor::with_backend(
            Lane::GpuPrl,
            EndpointPlan::single(Endpoint::plaintext("us.aliceprotocol.org", 3340)),
            ParserKind::Generic,
            None,
        );
        {
            let mut g = s.inner.lock().unwrap();
            // A mis-read line implants an absurd total.
            apply_log_line(&mut g, ParserKind::Generic, "shares a:999999 r:5000 30.0 mh/s");
        }
        assert_eq!(s.stats().accepted, 999_999);
        {
            let mut g = s.inner.lock().unwrap();
            // The engine's real, rising counters: held once, then adopted.
            apply_log_line(&mut g, ParserKind::Generic, "shares a:11 r:1 30.0 mh/s");
        }
        assert_eq!(s.stats().accepted, 999_999, "one reading is not enough to move down");
        {
            let mut g = s.inner.lock().unwrap();
            apply_log_line(&mut g, ParserKind::Generic, "shares a:12 r:2 30.0 mh/s");
        }
        assert_eq!(s.stats().accepted, 12, "a corroborated pair re-baselines");
        assert_eq!(s.stats().rejected, 2);
        {
            // And it keeps tracking normally afterwards.
            let mut g = s.inner.lock().unwrap();
            apply_log_line(&mut g, ParserKind::Generic, "shares a:13 r:2 30.0 mh/s");
        }
        assert_eq!(s.stats().accepted, 13);
    }

    /// T5: a supervisor built `with_backend` and an explicit `log_tail` path exposes
    /// that path to the tailer (rather than scanning argv), so a custom file-logging
    /// miner with a non-`--log-file` flag is still tailed.
    #[test]
    fn with_backend_carries_parser_and_log_tail() {
        let log = std::env::temp_dir().join("alice-custom-tail-test.log");
        let s = LaneSupervisor::with_backend(
            Lane::GpuPrl,
            EndpointPlan::single(Endpoint::plaintext("us.aliceprotocol.org", 3340)),
            ParserKind::Srbminer,
            Some(log.clone()),
        );
        assert_eq!(s.parser, ParserKind::Srbminer);
        assert_eq!(s.log_tail.as_deref(), Some(log.as_path()));
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
        apply_log_line(&mut g, ParserKind::Xmr, "miner    speed 10s/60s/15m 100.0 90.0 n/a H/s");
        assert!(g.last_progress_at.unwrap() > before);
        // The SAME hashrate again → no new progress mark.
        let mark2 = g.last_progress_at.unwrap();
        std::thread::sleep(Duration::from_millis(2));
        apply_log_line(&mut g, ParserKind::Xmr, "miner    speed 10s/60s/15m 100.0 90.0 n/a H/s");
        assert_eq!(g.last_progress_at.unwrap(), mark2, "flat hashrate is not progress");
        // A new accepted share → progress.
        apply_log_line(&mut g, ParserKind::Xmr, "net      accepted (1/0) diff 100 (10 ms)");
        assert!(g.last_progress_at.unwrap() > mark2);
    }

    #[cfg(unix)]
    #[test]
    fn start_then_stop_transitions_and_captures_shares() {
        let _env = spawn_env_guard();
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
        let _env = spawn_env_guard();
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

    /// An unexpected child exit lands in `Error` — but (BUG#4) an Error that is
    /// WAITING, not dead: the crash is counted, an automatic restart is armed with a
    /// visible countdown, and the status says so in words. It must NOT restart-storm
    /// (the first rung is seconds away, not instant).
    #[test]
    fn unexpected_exit_lands_in_error_and_arms_a_visible_retry() {
        let _env = spawn_env_guard();
        let rt = rt();
        rt.block_on(async {
            let (program, args) = crashing_child(1);
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

            // The crash is COUNTED and a retry is ARMED — the old behaviour was a
            // terminal Error with neither.
            let st = s.stats();
            assert_eq!(st.crashes, 1, "the engine crash must be counted");
            let retry_in = st.retry_in_s.expect("an automatic retry must be armed");
            assert!(
                retry_in <= alice_supervise::RETRY_BACKOFF_LADDER[0].as_secs(),
                "the first rung is the fastest one: {retry_in}s"
            );
            // …and it is VISIBLE: a machine key a front-end can render, plus words.
            assert_eq!(st.message_key.as_deref(), Some("engine_crashed_retrying"));
            assert!(status_is_retrying(st.message_key.as_deref().unwrap()));
            let msg = st.message.clone().unwrap_or_default();
            assert!(
                msg.contains("restarting automatically"),
                "the status must announce the pending restart: {msg:?}"
            );
            assert_eq!(st.message_args.as_ref().and_then(|a| a.attempt), Some(1));

            // A user Stop while WAITING cancels the retry and is honoured (the user's
            // Stop is the one terminal action).
            s.request_stop();
            let st = s.stats();
            assert_eq!(st.state, ProcState::Stopped, "Stop wins over a pending retry");
            assert_eq!(st.retry_in_s, None, "the pending retry is cancelled");
            // And it STAYS stopped — the timer must not resurrect the lane.
            tokio::time::sleep(Duration::from_secs(1)).await;
            assert_eq!(s.stats().state, ProcState::Stopped);
        });
    }

    /// THE BUG#4 REGRESSION: an engine that exits on its own is restarted
    /// automatically — the whole point. A child that dies immediately used to leave
    /// the lane in a permanent `Error` with SRBMiner gone and the CLI still polling.
    #[test]
    fn engine_crash_restarts_automatically() {
        let _env = spawn_env_guard();
        let rt = rt();
        rt.block_on(async {
            let s = LaneSupervisor::new(Lane::Xmr);
            // Shrink the ladder for the test: `set_retry_timing` fixes every rung.
            s.set_retry_timing(Duration::from_millis(60));

            // Every spawn dies immediately (a "crashing engine"); the rebuild closure
            // counts the relaunches nobody asked for.
            let calls = Arc::new(AtomicUsize::new(0));
            let calls2 = calls.clone();
            let rebuild: RebuildFn = Arc::new(move |_eps: &[Endpoint]| {
                calls2.fetch_add(1, Ordering::SeqCst);
                Ok(crashing_child(3))
            });
            let (program, args) = crashing_child(3);
            s.start(program, args, rebuild).expect("start");

            // It comes BACK by itself, more than once — no user action anywhere.
            let mut relaunches = 0;
            for _ in 0..200 {
                relaunches = calls.load(Ordering::SeqCst);
                if relaunches >= 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert!(
                relaunches >= 2,
                "the engine must be restarted automatically after it exits (got {relaunches})"
            );
            assert!(s.engine_crashes() >= 2, "every crash is counted");

            s.request_stop();
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
    }

    /// Repeated crashes ESCALATE the wait instead of giving up: the armed delay grows
    /// (and never becomes "never"). This is the "back off, don't stop" contract.
    #[test]
    fn repeated_crashes_back_off_instead_of_giving_up() {
        let _env = spawn_env_guard();
        let rt = rt();
        rt.block_on(async {
            let s = LaneSupervisor::new(Lane::Xmr);
            // The real ladder would take an hour to walk; the rung VALUES are asserted in
            // `alice_supervise`, so here we only prove the level keeps rising and that a
            // retry is always armed.
            s.set_retry_timing(Duration::from_millis(40));
            let rebuild: RebuildFn = Arc::new(move |_eps: &[Endpoint]| Ok(crashing_child(7)));
            let (program, args) = crashing_child(7);
            s.start(program, args, rebuild).expect("start");

            // Let it crash well past the OLD give-up point (MAX_RESTARTS = 3).
            let mut crashes = 0;
            for _ in 0..300 {
                crashes = s.engine_crashes();
                if crashes > alice_supervise::MAX_RESTARTS as u64 + 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
            assert!(
                crashes > alice_supervise::MAX_RESTARTS as u64,
                "retries must continue past the old fixed budget (got {crashes})"
            );
            // A retry is STILL armed — there is no terminal state without a next step.
            let st = s.stats();
            assert!(
                st.retry_in_s.is_some() || st.state == ProcState::Running || st.state == ProcState::Starting,
                "the lane is either mining or waiting to retry — never silently dead: {st:?}"
            );
            let attempt = st.message_args.as_ref().and_then(|a| a.attempt).unwrap_or(0);
            assert!(
                st.retry_in_s.is_none() || attempt > 1,
                "the attempt counter escalates with each retry"
            );

            s.request_stop();
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
    }

    /// The engine's process tree must be CONFIRMED gone before a restart puts another
    /// engine on the same GPU (the Job Object / process-group teardown is only half the
    /// contract). `await_child_gone` answers `true` only for a positively-dead pid.
    #[test]
    fn retry_waits_for_the_old_process_tree_to_be_gone() {
        let rt = rt();
        rt.block_on(async {
            // A pid that cannot exist → positively Dead → cleared to relaunch.
            assert!(
                await_child_gone(u32::MAX - 1).await,
                "a pid that is positively gone clears the relaunch"
            );
            // OUR OWN pid is alive → the probe must NOT clear a relaunch. (Bounded: the
            // helper polls for a few seconds, which is exactly the wait we want.)
            let me = std::process::id();
            let t0 = std::time::Instant::now();
            assert!(
                !await_child_gone(me).await,
                "a still-live engine must block the relaunch, not be assumed dead"
            );
            assert!(t0.elapsed() >= Duration::from_secs(1), "it actually waited");
        });
    }

    /// Exit codes become plain language (④): the reported SRBMiner heap-corruption
    /// abort names itself, is attributed to the third-party engine, and prints the hex
    /// form the user will see in Event Viewer. A code we have no honest explanation for
    /// stays a bare number — we never invent a cause.
    #[test]
    fn crash_exit_codes_are_translated_into_plain_language() {
        let _g = crate::i18n::LANG_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        crate::i18n::set_lang(crate::i18n::Lang::En);

        const HEAP_CORRUPTION: i32 = 0xC000_0374u32 as i32;
        let en = exit_code_explanation(HEAP_CORRUPTION).expect("0xC0000374 is explained");
        assert!(en.to_lowercase().contains("heap corruption"), "{en:?}");
        assert!(en.contains("third-party"), "attributed to the engine, not Alice: {en:?}");
        assert!(!has_cjk(&en));
        // The rendered code is the hex form (what a web search / Event Viewer shows).
        assert_eq!(fmt_exit_code(HEAP_CORRUPTION), "0xC0000374");
        assert!(engine_exit_cause(HEAP_CORRUPTION).contains("0xC0000374"));
        // An ordinary status stays decimal.
        assert_eq!(fmt_exit_code(1), "1");

        // Other engine-realistic aborts.
        assert!(exit_code_explanation(0xC000_0005u32 as i32).is_some(), "access violation");
        assert!(exit_code_explanation(0xC000_0409u32 as i32).is_some(), "stack overrun");
        assert!(exit_code_explanation(0xC000_0135u32 as i32).is_some(), "missing DLL");
        // The unix `128 + signal` convention.
        assert!(exit_code_explanation(139).unwrap().contains("SIGSEGV"));
        assert!(exit_code_explanation(134).unwrap().contains("SIGABRT"));
        assert!(exit_code_explanation(-1).is_some(), "signal death with no code");
        // No invention for a code we do not know.
        assert_eq!(exit_code_explanation(3), None);
        assert!(engine_exit_cause(3).contains("exited unexpectedly"));

        // ZH renders too, and carries no English cause text.
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        let zh = exit_code_explanation(HEAP_CORRUPTION).expect("zh");
        assert!(has_cjk(&zh), "{zh:?}");
        crate::i18n::set_lang(crate::i18n::Lang::En);
    }

    /// Healthy mining buys retry budget back (③): the elapsed-progress time of a run is
    /// credited to BOTH the fast budget and the escalating ladder, so a rig that mined
    /// for hours before one crash retries fast instead of inheriting an old escalation.
    #[test]
    fn healthy_mining_time_restores_the_retry_budget() {
        use alice_supervise::HEALTHY_RUN_STEP;
        let s = LaneSupervisor::new(Lane::Xmr);
        {
            let mut g = s.inner.lock().unwrap();
            // Escalate: three retries armed, fast budget spent.
            for _ in 0..3 {
                g.retry_ladder.next_backoff();
                g.restart_policy.record(Instant::now());
            }
            assert_eq!(g.retry_ladder.level(), 3);
            assert!(!g.restart_policy.may_restart(Instant::now()));

            // A run that made NO progress buys nothing…
            g.retry_ladder.credit_healthy_run(Duration::from_secs(0));
            g.restart_policy.credit_healthy_run(Duration::from_secs(0));
            assert_eq!(g.retry_ladder.level(), 3, "no progress, no refund");

            // …but 20 minutes of real mining walks both back by two steps.
            g.retry_ladder.credit_healthy_run(HEALTHY_RUN_STEP * 2);
            g.restart_policy.credit_healthy_run(HEALTHY_RUN_STEP * 2);
            assert_eq!(g.retry_ladder.level(), 1);
            assert!(g.restart_policy.may_restart(Instant::now()), "budget re-armed");
        }
    }

    /// The healthy-run credit is measured from real PROGRESS, not mere uptime: a lane
    /// whose process stayed up for hours without landing a single share earns nothing.
    #[test]
    fn healthy_credit_counts_progress_not_uptime() {
        let s = LaneSupervisor::new(Lane::Xmr);
        let mut g = s.inner.lock().unwrap();
        let start = Instant::now() - Duration::from_secs(3 * 3600);
        g.started_at = Some(start);
        // No progress since the run began → `last_progress_at` is still the start mark.
        g.last_progress_at = Some(start);
        let healthy = g
            .last_progress_at
            .zip(g.started_at)
            .map(|(p, s)| p.saturating_duration_since(s))
            .unwrap_or_default();
        assert_eq!(healthy, Duration::ZERO, "3h of dead uptime is 0 healthy time");
        // A share landed an hour in → one hour of healthy mining.
        g.last_progress_at = Some(start + Duration::from_secs(3600));
        let healthy = g
            .last_progress_at
            .zip(g.started_at)
            .map(|(p, s)| p.saturating_duration_since(s))
            .unwrap_or_default();
        assert_eq!(healthy, Duration::from_secs(3600));
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
        let _env = spawn_env_guard();
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
        let _env = spawn_env_guard();
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
        let _env = spawn_env_guard();
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
            let st = s.stats();
            let msg = st.message.clone().unwrap_or_default();
            assert!(
                msg.contains("no progress"),
                "Error message should explain the bounded failover: {msg:?}"
            );
            // BUG#4: exhausting the FAST budget backs off — it does not give up. The
            // lane is waiting on the escalating ladder with a visible countdown, and
            // says so, instead of the old silent terminal Error.
            assert_eq!(st.message_key.as_deref(), Some("stall_retrying"));
            assert!(st.retry_in_s.is_some(), "a long-backoff retry must be armed");
            assert!(
                msg.contains("restarting automatically"),
                "the status must announce the pending restart: {msg:?}"
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
        let _env = spawn_env_guard();
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

    // ── D-line: region persistence + lock + pre-flight probe ────────────────────

    /// (c)/(b): the labeled Layer-B status. A real region change reads as an explicit
    /// `auto-failover: <from> → <to>` with the no-progress reason; a locked /
    /// single-region retry reads as a locked retry and NEVER claims a failover.
    #[test]
    fn failover_status_labels_auto_change_and_locked_retry() {
        let us = Endpoint::plaintext("us.aliceprotocol.org", 3340);
        let asia = Endpoint::plaintext("asia.aliceprotocol.org", 3340);
        let msg = failover_status(&us, &asia, /*changed=*/ true, Duration::from_secs(600));
        assert!(msg.contains("auto-failover") || msg.contains("自动切换"), "{msg}");
        assert!(msg.contains("us"), "shows the from-region: {msg}");
        assert!(msg.contains("asia"), "shows the to-region: {msg}");
        assert!(msg.contains("600"), "shows the no-progress reason: {msg}");

        let locked = failover_status(&asia, &asia, /*changed=*/ false, Duration::from_secs(600));
        assert!(locked.contains("lock") || locked.contains("锁定"), "{locked}");
        // The labeled CHANGE form is `auto-failover: <from> → <to>` (note the colon).
        // The locked retry must never emit that labeled event (it may say "no
        // auto-failover", which is the opposite claim).
        assert!(
            !locked.contains("auto-failover:") && !locked.contains("自动切换区域:"),
            "a locked retry must NOT emit a failover event: {locked}"
        );
        assert!(locked.contains("asia"), "names the locked region: {locked}");
    }

    #[test]
    fn region_label_prefers_tag_else_host_port() {
        assert_eq!(region_label(&Endpoint::plaintext("asia.aliceprotocol.org", 3340)), "asia");
        // `fi` was removed in v0.6.1 → no longer a region relay, so it degrades to host:port.
        assert_eq!(
            region_label(&Endpoint::plaintext("fi.aliceprotocol.org", 3340)),
            "fi.aliceprotocol.org:3340"
        );
        // A non-region host (an operator override / the XMR relay) shows host:port.
        assert_eq!(
            region_label(&Endpoint::plaintext("hk.aliceprotocol.org", 3333)),
            "hk.aliceprotocol.org:3333"
        );
    }

    // ── i18n boundary: re-localizable Layer-B status (fix/region-lock-i18n) ──────

    /// True if `s` contains any CJK Unified Ideograph (the EN-status "no Chinese"
    /// guard the UI regression test asserts).
    fn has_cjk(s: &str) -> bool {
        s.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c))
    }

    /// `short_host_label` reduces a host / host:port to its first label, upper-cased.
    #[test]
    fn short_host_label_takes_first_label_uppercased() {
        assert_eq!(short_host_label("hk.aliceprotocol.org:3333"), "HK");
        assert_eq!(short_host_label("us.aliceprotocol.org"), "US");
        assert_eq!(short_host_label("localhost"), "LOCALHOST");
    }

    /// `extract_stalled_secs` finds the `<n>s` no-progress token, not a host's port
    /// digits (which are followed by `)`/space, not `s`).
    #[test]
    fn extract_stalled_secs_finds_progress_token_not_port() {
        assert_eq!(
            extract_stalled_secs("region us locked — no auto-failover (no progress for 600s)"),
            Some(600)
        );
        assert_eq!(
            extract_stalled_secs(
                "区域 hk.aliceprotocol.org:3333 已锁定 — 仅重试该区域、不自动切换(已 720s 无进展)"
            ),
            Some(720)
        );
        assert_eq!(extract_stalled_secs("no numbers-with-s here 3333)"), None);
    }

    /// THE reported bug: a Chinese-baked region-lock snapshot `message` must render as
    /// SHORT, Chinese-free ENGLISH when the UI language is EN, and as a short Chinese
    /// sentence when 中文 — regardless of the locale that produced the raw string.
    /// (checkpoint ③: the reported endpoint is a FIXED XMR pool → generic
    /// "Endpoint locked", never PRL-style "region … no auto-failover".)
    #[test]
    fn region_locked_message_relocalizes_even_when_snapshot_is_chinese() {
        let _g = crate::i18n::LANG_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let raw = "区域 hk.aliceprotocol.org:3333 已锁定 — 仅重试该区域、不自动切换(已 600s 无进展)";
        let (key, args) = status_from_legacy(raw).expect("parses the legacy region-lock string");
        // hk is a fixed pool (host:port), not a us/asia region → endpoint_locked.
        assert_eq!(key, "endpoint_locked");
        assert_eq!(args.stalled_s, Some(600));
        assert_eq!(args.endpoint.as_deref(), Some("hk.aliceprotocol.org:3333"));

        crate::i18n::set_lang(crate::i18n::Lang::En);
        let en = status_short(&key, &args);
        assert!(!has_cjk(&en), "EN status must contain no Chinese: {en:?}");
        assert!(en.contains("locked"), "EN status names the lock: {en:?}");
        assert!(en.len() <= 48, "EN status stays short (≤48 bytes): {en:?} = {}", en.len());

        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        let zh = status_short(&key, &args);
        assert!(zh.contains("已锁定"), "ZH status is a short lock sentence: {zh:?}");
        assert!(zh.chars().count() <= 24, "ZH status stays short: {zh:?}");

        crate::i18n::set_lang(crate::i18n::Lang::En);
    }

    /// A LOCKED PRL region relay (a bare `us`/`asia` tag) parses to the region-lock
    /// key (keeps the "no failover" semantics) — distinct from a fixed pool endpoint.
    #[test]
    fn legacy_parse_distinguishes_region_relay_from_fixed_pool() {
        let region = status_from_legacy(
            "region us locked — retrying, no auto-failover (no progress for 600s)",
        )
        .expect("parses region-lock");
        assert_eq!(region.0, "region_locked_no_failover");
        assert_eq!(region.1.region.as_deref(), Some("US"));

        let pool = status_from_legacy(
            "endpoint hk.aliceprotocol.org:3333 locked — retrying this endpoint (no progress for 600s)",
        )
        .expect("parses endpoint-lock");
        assert_eq!(pool.0, "endpoint_locked");
        assert_eq!(pool.1.region.as_deref(), Some("HK"));

        // A free-form message is not a lock status → no key (caller shows it raw).
        assert!(status_from_legacy("miner exited (code 1)").is_none());
    }

    /// Every `status_short` key renders a non-empty, Chinese-free EN line, and an
    /// unknown key returns empty (so the caller falls back to the raw message).
    #[test]
    fn status_short_covers_all_keys_and_localizes() {
        let _g = crate::i18n::LANG_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let args = StatusArgs {
            endpoint: Some("us.aliceprotocol.org:3340".into()),
            region: Some("US".into()),
            to_region: Some("ASIA".into()),
            stalled_s: Some(600),
            exit_code: Some(-1073740940), // 0xC0000374
            retry_in_s: Some(300),
            attempt: Some(4),
            crashes: Some(3),
            shares_accepted: Some(0),
            shares_rejected: Some(72),
            accept_pct: Some(0.0),
        };
        let keys = [
            "region_locked_no_failover",
            "endpoint_locked",
            "auto_failover",
            "region_recovered",
            "region_retrying",
            "all_regions_unavailable",
            "budget_exhausted",
            // BUG#4: the "an automatic restart is pending" family.
            "engine_crashed_retrying",
            "stall_retrying",
            "all_regions_retrying",
            "relaunch_retrying",
            "engine_still_alive_retrying",
        ];
        crate::i18n::set_lang(crate::i18n::Lang::En);
        for k in keys {
            let en = status_short(k, &args);
            assert!(!en.is_empty(), "EN {k} renders");
            assert!(!has_cjk(&en), "EN {k} has no Chinese: {en:?}");
        }
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        for k in keys {
            assert!(!status_short(k, &args).is_empty(), "ZH {k} renders");
        }
        assert!(status_short("totally_unknown_key", &args).is_empty());
        crate::i18n::set_lang(crate::i18n::Lang::En);
    }

    /// HONESTY GATE (same rule as `errmsg`): a reachability status reports what THIS
    /// MACHINE observed and must never assert a verdict about our relays. The client
    /// cannot distinguish "the relay is down" from "a captive portal / HTTPS-inspecting
    /// firewall / wedged socket on this box eats every region at once" — and on
    /// 2026-07-25 the old "All relays unavailable" wording sent a real investigation at
    /// a perfectly healthy HK relay.
    #[test]
    fn reachability_statuses_never_claim_our_relays_are_down() {
        let _g = crate::i18n::LANG_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let args = StatusArgs {
            endpoint: Some("us.aliceprotocol.org:3340".into()),
            region: Some("US".into()),
            stalled_s: Some(600),
            retry_in_s: Some(300),
            ..Default::default()
        };
        crate::i18n::set_lang(crate::i18n::Lang::En);
        for k in ["region_retrying", "all_regions_unavailable", "all_regions_retrying"] {
            let en = status_short(k, &args).to_lowercase();
            // The banned shapes: a bare claim that the relays / endpoint are down.
            for banned in [
                "all relays unavailable",
                "relays are unavailable",
                "endpoint unreachable",
                "relay is down",
            ] {
                assert!(!en.contains(banned), "EN {k} asserts a relay verdict: {en:?}");
            }
            // …and it must instead scope the observation to this machine.
            assert!(
                en.contains("from here") || en.contains("no reply"),
                "EN {k} must scope to this machine: {en:?}"
            );
            assert!(!has_cjk(&en), "EN {k} has no Chinese: {en:?}");
        }
        // The two free-form failover messages carry the same scoping.
        for msg in [region_retry_message(), all_regions_unreachable_message()] {
            let low = msg.to_lowercase();
            assert!(
                low.contains("from this machine"),
                "must scope to this machine: {msg:?}"
            );
            assert!(!has_cjk(&msg), "EN has no Chinese: {msg:?}");
        }
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        for msg in [region_retry_message(), all_regions_unreachable_message()] {
            assert!(msg.contains("本机"), "ZH must scope to this machine: {msg:?}");
        }
        crate::i18n::set_lang(crate::i18n::Lang::En);
    }

    #[test]
    fn endpoint_reachable_rejects_dead_accepts_live_local() {
        // An unresolvable `.invalid` host is unreachable — bounded + fast (no hang).
        assert!(!endpoint_reachable("blackhole.invalid", 65000, Duration::from_millis(200)));
        // A bound local listener accepts the connect (the handshake completes into the
        // backlog even without an `accept()`).
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = l.local_addr().unwrap().port();
        assert!(endpoint_reachable("127.0.0.1", port, Duration::from_millis(500)));
    }

    /// (a): an accepted share on a region relay stages that region as last-good
    /// (once per region — debounced), keyed purely by the endpoint host.
    #[test]
    fn note_accepted_progress_records_region_from_endpoint_host() {
        let s = LaneSupervisor::with_endpoints(
            Lane::GpuPrl,
            EndpointPlan::single(Endpoint::plaintext("asia.aliceprotocol.org", 3340)),
        );
        let mut g = s.inner.lock().unwrap();
        apply_log_line(&mut g, ParserKind::Srbminer, "Shares acc.  : 5");
        assert_eq!(g.accepted, 5, "the accepted count parsed");
        assert_eq!(g.pending_good_region.as_deref(), Some("asia"));
        assert_eq!(g.persisted_good_region.as_deref(), Some("asia"));
        // A further rise on the SAME region does not re-stage a write (debounced).
        g.pending_good_region = None;
        apply_log_line(&mut g, ParserKind::Srbminer, "Shares acc.  : 9");
        assert_eq!(g.accepted, 9);
        assert_eq!(g.pending_good_region, None, "same region → no duplicate persist");
    }

    /// The XMR/RVN relay host is NOT a region relay → nothing is recorded (a CPU-XMR
    /// run never writes a bogus last-good region).
    #[test]
    fn note_accepted_progress_ignores_non_region_relay() {
        let s = LaneSupervisor::new(Lane::Xmr); // default plan = hk.aliceprotocol.org:3333
        let mut g = s.inner.lock().unwrap();
        apply_log_line(&mut g, ParserKind::Xmr, "net      accepted (3/0) diff 100 (10 ms)");
        assert_eq!(g.accepted, 3);
        assert_eq!(g.pending_good_region, None);
        assert_eq!(g.persisted_good_region, None);
    }

    /// (d): PRE-FLIGHT PROBE. On a stall the watchdog probes the candidate regions and
    /// rotates to the first REACHABLE one, SKIPPING a dead candidate — instead of
    /// blindly advancing into it and erroring. Plan: stalled primary → DEAD candidate →
    /// LIVE (a local listener). The rotation must land on the LIVE endpoint.
    #[cfg(unix)]
    #[test]
    fn failover_preflight_skips_dead_candidate_for_live_one() {
        let _env = spawn_env_guard();
        let rt = rt();
        rt.block_on(async {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind live");
            let live_port = listener.local_addr().unwrap().port();
            let live = format!("127.0.0.1:{live_port}");

            let plan = EndpointPlan::new(vec![
                Endpoint::plaintext("blackhole-primary.invalid", 65001),
                Endpoint::plaintext("blackhole-dead.invalid", 65002),
                Endpoint::plaintext("127.0.0.1", live_port),
            ])
            .unwrap();
            let s = LaneSupervisor::with_endpoints(Lane::Xmr, plan);
            s.set_failover_timing(Duration::from_millis(60), Duration::from_millis(10));

            // The relaunched child PROGRESSES (rising accepted shares) only on the live
            // endpoint, so the lane settles there; on any other endpoint it stalls.
            let live_host = "127.0.0.1".to_string();
            let rebuild: RebuildFn = Arc::new(move |eps: &[Endpoint]| {
                let cmd = if eps[0].host == live_host {
                    "i=0; while true; do i=$((i+1)); \
                     echo \"net      accepted ($i/0) diff 100 (10 ms)\"; sleep 0.02; done"
                        .to_string()
                } else {
                    "echo connecting; sleep 30".to_string()
                };
                Ok((std::path::PathBuf::from("/bin/sh"), vec!["-c".into(), cmd]))
            });

            s.start(
                std::path::PathBuf::from("/bin/sh"),
                vec!["-c".into(), "echo init; sleep 30".into()],
                rebuild,
            )
            .expect("start");

            // Poll for BOTH landing conditions inside one bounded loop: the cursor +
            // failover counter advance BEFORE the relaunch path restores the labeled
            // status (`spawn_run` clears `message`; the watchdog re-sets it right
            // after — see the failover relaunch arm above). On a slow / contended
            // runner the gap between those two lock acquisitions is observable, so a
            // single read of `stats().message` right after `landed` can race a benign
            // transient `None`. Only a label that NEVER shows up within the budget is
            // a real failure.
            let mut landed = false;
            let mut labeled = false;
            for _ in 0..200 {
                landed = s.failovers() >= 1 && s.current_endpoint() == live;
                let msg = s.stats().message.unwrap_or_default();
                labeled = msg.contains("auto-failover") || msg.contains("自动切换");
                if landed && labeled {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(
                landed,
                "pre-flight must skip the dead candidate and land on the live region \
                 (current={}, failovers={})",
                s.current_endpoint(),
                s.failovers()
            );
            assert!(
                labeled,
                "status should label the auto-failover: {:?}",
                s.stats().message
            );

            s.request_stop();
            for _ in 0..50 {
                let st = s.stats().state;
                if st == ProcState::Stopped || st == ProcState::Error {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            drop(listener);
        });
    }

    /// (b): REGION LOCK. A locked / single-region plan never auto-fails-over to
    /// another region — the watchdog RETRIES the same region in place (bounded by the
    /// restart budget), labels the status as a locked retry, and once that budget is
    /// spent hands over to the escalating retry ladder — an `Error` that is still
    /// WAITING (BUG#4), never a dead end — all with the failover counter at 0.
    #[cfg(unix)]
    #[test]
    fn locked_region_retries_in_place_then_clear_error() {
        let _env = spawn_env_guard();
        let rt = rt();
        rt.block_on(async {
            // A single-region plan is exactly what `region_plan_from(lock,…)` builds.
            let plan = EndpointPlan::single(Endpoint::plaintext("asia.aliceprotocol.org", 3340));
            let s = LaneSupervisor::with_endpoints(Lane::Xmr, plan);
            s.set_failover_timing(Duration::from_millis(50), Duration::from_millis(10));

            let calls = Arc::new(AtomicUsize::new(0));
            let calls2 = calls.clone();
            let rebuild: RebuildFn = Arc::new(move |_eps: &[Endpoint]| {
                calls2.fetch_add(1, Ordering::SeqCst);
                Ok((std::path::PathBuf::from("/bin/sh"), vec!["-c".into(), "sleep 30".into()]))
            });

            s.start(
                std::path::PathBuf::from("/bin/sh"),
                vec!["-c".into(), "sleep 30".into()],
                rebuild,
            )
            .expect("start");

            let mut saw_locked = false;
            let mut errored = false;
            for _ in 0..700 {
                if let Some(m) = s.stats().message {
                    if m.contains("lock") || m.contains("锁定") {
                        saw_locked = true;
                    }
                }
                if s.stats().state == ProcState::Error {
                    errored = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert!(errored, "a locked region that stays dead must land in a clear Error");
            // …but an Error with a next step: a retry is armed and named.
            let st = s.stats();
            assert!(st.retry_in_s.is_some(), "a locked lane must still retry itself");
            assert!(
                status_is_retrying(st.message_key.as_deref().unwrap_or("")),
                "the status must be one of the retrying family: {:?}",
                st.message_key
            );
            assert_eq!(s.failovers(), 0, "a lock must NEVER count a region failover");
            assert!(saw_locked, "the status must label the locked retry at least once");
            assert!(
                calls.load(Ordering::SeqCst) >= 1,
                "the locked region must be retried in place (rebuild called)"
            );
        });
    }

    // ── fix/prl-failover-recover: recover past an unhealthy region, don't dead-end ──

    /// The PURE recovery order: `last_good` (when it is a candidate AND is not the
    /// stalled region) is tried FIRST; then the remaining candidates in rotation order;
    /// then the stalled `from` region as a final in-place retry. When `last_good`
    /// equals the stalled region it is NOT prioritised (retrying the just-failed region
    /// first is futile) — it stays the final in-place retry.
    #[test]
    fn recovery_order_prefers_last_good_then_rotation_then_from() {
        let us = Endpoint::plaintext("us.aliceprotocol.org", 3340);
        let asia = Endpoint::plaintext("asia.aliceprotocol.org", 3340);
        let eu = Endpoint::plaintext("eu.aliceprotocol.org", 3340);

        // Stalled on `us`; candidates (rotation after us) = [asia, eu]; last_good = eu.
        // Expected: eu (last_good) first, then asia (remaining candidate), then us (from).
        let order = recovery_order(&[asia.clone(), eu.clone()], &us, Some("eu"));
        let hosts: Vec<&str> = order.iter().map(|e| e.host.as_str()).collect();
        assert_eq!(
            hosts,
            [
                "eu.aliceprotocol.org",
                "asia.aliceprotocol.org",
                "us.aliceprotocol.org"
            ],
            "last_good (eu) must be tried first, then the rest, then the stalled from"
        );

        // last_good == the stalled region (us) → NOT prioritised; plain rotation + from.
        let order2 = recovery_order(&[asia.clone(), eu.clone()], &us, Some("us"));
        let hosts2: Vec<&str> = order2.iter().map(|e| e.host.as_str()).collect();
        assert_eq!(
            hosts2,
            [
                "asia.aliceprotocol.org",
                "eu.aliceprotocol.org",
                "us.aliceprotocol.org"
            ],
            "last_good == from must not jump ahead of other candidates"
        );

        // No last_good → rotation order, then the stalled from as the final retry.
        let order3 = recovery_order(&[asia.clone(), eu.clone()], &us, None);
        assert_eq!(order3.last().unwrap().host, "us.aliceprotocol.org");
        assert_eq!(order3.len(), 3, "distinct: asia, eu, us(from)");
    }

    /// THE FIX (the tester's exact bug): an AUTO / failover-capable lane whose auto-
    /// selected next region is UNHEALTHY (answers the TCP pre-flight but its rebuild —
    /// the region-bound PoP handshake — FAILS) must NOT dead-end on that region. It must
    /// advance to the NEXT region, relaunch there, update the snapshot endpoint, and land
    /// Running — never stuck in `error` on the unhealthy region with a lying "retrying"
    /// status. Plan: stalled primary → UNHEALTHY region (TCP-live, rebuild Err) → GOOD
    /// region (TCP-live, rebuild Ok + progressing child).
    #[cfg(unix)]
    #[test]
    fn auto_failover_recovers_past_unhealthy_region_no_dead_end() {
        let _env = spawn_env_guard();
        let rt = rt();
        rt.block_on(async {
            // Two local listeners: an "unhealthy relay" (TCP answers, PoP/rebuild fails)
            // and a "good relay" (TCP answers, rebuild succeeds → progressing child).
            let unhealthy = std::net::TcpListener::bind("127.0.0.1:0").expect("bind unhealthy");
            let unhealthy_port = unhealthy.local_addr().unwrap().port();
            let good = std::net::TcpListener::bind("127.0.0.1:0").expect("bind good");
            let good_port = good.local_addr().unwrap().port();
            let good_authority = format!("127.0.0.1:{good_port}");

            let plan = EndpointPlan::new(vec![
                Endpoint::plaintext("blackhole-primary.invalid", 65010), // stalled primary
                Endpoint::plaintext("127.0.0.1", unhealthy_port),        // reachable but PoP-dead
                Endpoint::plaintext("127.0.0.1", good_port),             // reachable + healthy
            ])
            .unwrap();
            let s = LaneSupervisor::with_endpoints(Lane::Xmr, plan);
            s.set_failover_timing(Duration::from_millis(60), Duration::from_millis(10));

            // rebuild: the UNHEALTHY region's control plane is down → Err (simulating a
            // failed region-bound PoP re-establish). The GOOD region rebuilds fine and
            // returns a PROGRESSING child so the lane settles there. Any other endpoint
            // (the blackhole primary) just sleeps.
            let rebuild: RebuildFn = Arc::new(move |eps: &[Endpoint]| {
                let primary = &eps[0];
                if primary.host == "127.0.0.1" && primary.port == unhealthy_port {
                    Err("region relay control plane unhealthy (simulated PoP failure)".into())
                } else if primary.host == "127.0.0.1" && primary.port == good_port {
                    Ok((
                        std::path::PathBuf::from("/bin/sh"),
                        vec![
                            "-c".into(),
                            "i=0; while true; do i=$((i+1)); \
                             echo \"net      accepted ($i/0) diff 100 (10 ms)\"; sleep 0.02; done"
                                .into(),
                        ],
                    ))
                } else {
                    Ok((
                        std::path::PathBuf::from("/bin/sh"),
                        vec!["-c".into(), "echo connecting; sleep 30".into()],
                    ))
                }
            });

            s.start(
                std::path::PathBuf::from("/bin/sh"),
                vec!["-c".into(), "echo init; sleep 30".into()],
                rebuild,
            )
            .expect("start");

            // The lane must recover onto the GOOD region — skipping the unhealthy one
            // whose rebuild failed — and be Running with rising shares. Bounded wait.
            let mut recovered = false;
            for _ in 0..300 {
                let st = s.stats();
                if s.current_endpoint() == good_authority
                    && st.state == ProcState::Running
                    && st.accepted >= 1
                {
                    recovered = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let st = s.stats();
            assert!(
                recovered,
                "auto lane must recover onto the good region, not dead-end on the \
                 unhealthy one (endpoint={:?}, state={:?}, failovers={})",
                st.endpoint, st.state, st.failovers
            );
            assert_ne!(st.state, ProcState::Error, "must NOT be stuck in error");
            assert!(st.failovers >= 1, "a real region change must be counted");
            // The snapshot endpoint tracked the cursor to the good region (never froze
            // on the unhealthy one).
            assert_eq!(st.endpoint.as_deref(), Some(good_authority.as_str()));

            s.request_stop();
            for _ in 0..50 {
                let stt = s.stats().state;
                if stt == ProcState::Stopped || stt == ProcState::Error {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            drop(unhealthy);
            drop(good);
        });
    }

    /// When EVERY region's rebuild fails in one round (all relays' control planes down),
    /// the auto lane lands in an Error carrying the honest "all regions unavailable"
    /// status — NOT the "retrying other regions" line (which would be a lie once there
    /// is nothing left to try in THIS round) — bounded (no restart storm), and (BUG#4)
    /// with an automatic retry armed so a relay outage no longer parks the rig forever.
    #[cfg(unix)]
    #[test]
    fn auto_failover_all_regions_unhealthy_lands_clear_error() {
        let _env = spawn_env_guard();
        let rt = rt();
        rt.block_on(async {
            // Two TCP-live listeners whose rebuild ALWAYS fails (control plane down).
            let a = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a");
            let a_port = a.local_addr().unwrap().port();
            let b = std::net::TcpListener::bind("127.0.0.1:0").expect("bind b");
            let b_port = b.local_addr().unwrap().port();

            let plan = EndpointPlan::new(vec![
                Endpoint::plaintext("127.0.0.1", a_port),
                Endpoint::plaintext("127.0.0.1", b_port),
            ])
            .unwrap();
            let s = LaneSupervisor::with_endpoints(Lane::Xmr, plan);
            s.set_failover_timing(Duration::from_millis(50), Duration::from_millis(10));

            // Every rebuild fails (both regions' control planes are down).
            let rebuild: RebuildFn =
                Arc::new(move |_eps: &[Endpoint]| Err("all region control planes down".into()));
            // Initial child stalls (sleeps) so the watchdog trips and enters recovery.
            s.start(
                std::path::PathBuf::from("/bin/sh"),
                vec!["-c".into(), "sleep 30".into()],
                rebuild,
            )
            .expect("start");

            let mut errored = false;
            for _ in 0..300 {
                if s.stats().state == ProcState::Error {
                    errored = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(errored, "all-regions-unhealthy must land in a clear Error");
            let st = s.stats();
            let msg = st.message.clone().unwrap_or_default();
            // The honest all-regions line, scoped to THIS MACHINE: the client only
            // observed that it could not reach them, so it must not claim our relays
            // are down (see `reachability_statuses_never_claim_our_relays_are_down`).
            assert!(
                msg.contains("could not reach any region relay from this machine")
                    || msg.contains("本机联系不上任何区域中继"),
                "the status must be the honest all-regions-unreachable line: {msg:?}"
            );
            assert!(
                !msg.contains("relays are unavailable") && !msg.contains("所有中继不可用"),
                "must not assert a verdict about our relays: {msg:?}"
            );
            // It must NOT tell the user to restart by hand — the lane retries itself.
            assert!(
                !msg.contains("restart to retry"),
                "the lane recovers on its own; the old 'restart to retry' line is a lie now: {msg:?}"
            );
            assert_eq!(st.message_key.as_deref(), Some("all_regions_retrying"));
            assert!(st.retry_in_s.is_some(), "an automatic retry must be armed");
            // Bounded — no restart storm (failovers never counted a phantom switch).
            assert_eq!(s.failovers(), 0, "no region ever actually switched");

            s.request_stop();
            drop(a);
            drop(b);
        });
    }

    // ── LAYER 3: acceptance-rate collapse self-protection ──────────────────────
    //
    // These run on EVERY OS (`cfg!`, never `#[cfg]`): the failure they guard against
    // hit a Windows rig, and a unix-only suite would be coverage theatre.

    /// THE 2026-08-11 SCENARIO, end to end through the real supervisor.
    ///
    /// The shape that fooled every existing guard: the engine is up and stays up, the
    /// connection is fine, jobs keep arriving, shares keep being submitted — and the
    /// pool rejects every single one. Layer B sees a lane whose counters keep moving
    /// and calls that progress. Nothing stops. The miner in the incident ran three
    /// days like this, 0 accepted / 72 rejected, and was never told.
    ///
    /// Now it stops, and it says why.
    #[test]
    fn all_shares_rejected_halts_the_lane_and_explains_it() {
        let _env = spawn_env_guard();
        let _lock = crate::i18n::LANG_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        crate::i18n::set_lang(crate::i18n::Lang::En);
        let rt = rt();
        rt.block_on(async {
            let s = LaneSupervisor::new(Lane::Xmr);
            s.set_acceptance_config(fast_acceptance());
            let (program, args) = idle_child();
            s.start_simple(program, args).expect("start");
            assert!(wait_for(&s, 5, |st| st.state == ProcState::Running).await, "child up");

            // Past the warm-up, then a full window of nothing but rejections — the
            // engine is healthy, the pool is not accepting anything.
            tokio::time::sleep(Duration::from_millis(60)).await;
            feed(&s, "net      rejected (0/0) diff 100 (10 ms)"); // warm baseline
            for i in 1..=25u64 {
                feed(&s, &format!("net      rejected (0/{i}) diff 100 (10 ms)"));
                tokio::time::sleep(Duration::from_millis(10)).await;
            }

            // The watchdog stops the lane by itself.
            assert!(
                wait_for(&s, 12, |st| st.halted).await,
                "a total rejection storm must halt the lane: {:?}",
                s.stats()
            );
            let st = s.stats();
            assert_eq!(st.acceptance, "collapsed");
            assert_eq!(st.accept_pct, Some(0.0), "0% measured is a real measurement");
            assert!(
                wait_for(&s, 8, |st| !st.running).await,
                "the engine must actually be stopped, not just flagged"
            );
            let st = s.stats();
            assert_eq!(st.state, ProcState::Error, "a halt is visible, never a silent Stopped");

            // It SAYS SO — the short line, the machine key, and the numbers.
            let key = st.message_key.clone().expect("a halt must carry a machine key");
            assert!(key.starts_with("acceptance_halt_"), "got {key}");
            let line = st.message.clone().unwrap_or_default();
            assert!(line.contains("0 accepted"), "the status must name the outcome: {line:?}");
            let args = st.message_args.clone().expect("args");
            assert_eq!(args.shares_accepted, Some(0));
            assert!(args.shares_rejected.unwrap_or(0) >= 20, "{args:?}");

            // And the full explanation says what it costs and where to go.
            let tip = status_tooltip(&key, &args).expect("a halt must explain itself");
            assert!(tip.contains("not one was accepted"), "{tip}");
            assert!(
                tip.contains("power bill"),
                "the user must be told why stopping is in his interest: {tip}"
            );
            assert!(tip.contains("https://"), "the user must be pointed somewhere: {tip}");

            // …and it STAYS stopped. No crash ladder, no failover, no silent resume.
            let before = s.stats().crashes;
            tokio::time::sleep(Duration::from_secs(2)).await;
            let st = s.stats();
            assert!(st.halted, "the halt must not decay");
            assert!(!st.running, "nothing may restart a halted lane");
            assert_eq!(st.retry_in_s, None, "no automatic retry may be armed");
            assert_eq!(st.crashes, before);
            assert_eq!(s.failovers(), 0, "a halt must never rotate regions");

            s.request_stop();
        });
    }

    /// **F4, end to end: a lane the acceptance guard halted must never produce a
    /// `StoppedEarning` rollback.**
    ///
    /// Layers 2 and 3 were built separately and this is where they meet. Layer 3
    /// halts on a rejection storm — and from that moment the accepted counter is
    /// frozen at zero *by design*. Layer 2 watches the same counter to decide
    /// whether the build it installed still earns, and its only guard was "this
    /// machine landed a share in the last 72 h", which is true of every normally
    /// mining rig. So layer 3 doing its job read, to layer 2, as "the new version
    /// does not earn" — and would roll back and permanently pin an innocent
    /// client during an upstream outage. Exactly the mistake this release exists
    /// to stop.
    ///
    /// This drives a REAL halt through the real supervisor, reads the evidence the
    /// front-ends read, and asserts the probation abstains.
    #[test]
    fn a_halted_lane_is_not_evidence_against_the_installed_build() {
        use alice_release::auto::{
            judge_session, Probation, SessionAction, SessionEvidence, SessionResult,
        };
        let _env = spawn_env_guard();
        let rt = rt();
        rt.block_on(async {
            // F15, in the same breath: the engine-pin refresher is armed by process
            // start, so it is already running on a client that is about to halt —
            // and it keeps running afterwards, when no lane will start an engine
            // ever again. That thread is the only way the fixed pin can reach this
            // machine without a human pressing Start.
            crate::engine_pins::start_background_refresh();
            assert_eq!(crate::engine_pins::background_refresh_starts(), 1);

            let s = LaneSupervisor::new(Lane::GpuPrl);
            s.set_acceptance_config(fast_acceptance());
            let (program, args) = idle_child();
            s.start_simple(program, args).expect("start");
            assert!(wait_for(&s, 5, |st| st.state == ProcState::Running).await, "child up");

            // The August shape: everything submitted is rejected.
            tokio::time::sleep(Duration::from_millis(60)).await;
            feed(&s, "net      rejected (0/0) diff 100 (10 ms)");
            for i in 1..=25u64 {
                feed(&s, &format!("net      rejected (0/{i}) diff 100 (10 ms)"));
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(wait_for(&s, 12, |st| st.halted).await, "the lane must halt");
            let st = s.stats();
            assert_eq!(st.accepted, 0, "a halted lane's accepted counter is frozen at 0");

            // What the front-ends now feed the updater, built from this lane.
            let mut snap = crate::engine::Snapshot::idle();
            snap.lane = Some(st.lane);
            snap.shares_accepted = st.accepted;
            snap.lanes = vec![crate::engine::LaneSnapshot {
                lane: st.lane,
                state: st.state.into(),
                hashrate_hs: st.hashrate_hs,
                hashrate_60s_hs: None,
                hashrate_15m_hs: None,
                shares_accepted: st.accepted,
                shares_rejected: st.rejected,
                uptime_s: st.uptime_s,
                endpoint: st.endpoint.clone(),
                failovers: st.failovers,
                temp_c: None,
                power_w: None,
                util_pct: None,
                fan_pct: None,
                acceptance: st.acceptance.to_string(),
                accept_pct: st.accept_pct,
                halted: st.halted,
            }];
            let mining = crate::autoupdate::MiningEvidence::from_snapshot(&snap);
            assert!(mining.halted, "the halt must reach layer 2");
            assert!(!mining.counts_as_earning());

            // A build that installed itself yesterday, on a machine that WAS
            // earning, with one long empty session already on the record: the next
            // report is the one that used to roll it back and pin it forever.
            let on_trial = Probation {
                version: "0.6.8".into(),
                previous: "0.6.7".into(),
                armed_at_unix: 0,
                launches: 1,
                started_ok: true,
                previous_productive: true,
                failed_sessions: alice_release::auto::FAILED_SESSIONS_TO_ROLLBACK - 1,
            };
            let ran = alice_release::auto::MIN_JUDGED_SESSION.as_secs();
            assert_eq!(
                judge_session(&on_trial, "0.6.8", &SessionResult::judgeable(ran, 0)),
                SessionAction::RollBack,
                "this is genuinely the tipping session — otherwise the test proves nothing"
            );
            assert_eq!(
                judge_session(
                    &on_trial,
                    "0.6.8",
                    &SessionResult {
                        ran_secs: ran,
                        accepted: mining.accepted,
                        evidence: SessionEvidence::MiningHalted,
                    }
                ),
                SessionAction::Abstain(SessionEvidence::MiningHalted),
                "layer 3 halting must never be read as 'the new version does not earn'"
            );

            // Still halted, still no engine — and the refresher is still the one
            // that was started with the process.
            assert!(s.stats().halted);
            assert_eq!(crate::engine_pins::background_refresh_starts(), 1);
            s.request_stop();
        });
    }

    /// A LOW-HASHRATE rig — one share every few seconds, all rejected, but never
    /// twenty inside a window — is NOT stopped. Stopping a small miner on three
    /// samples would be a worse bug than the one this layer fixes.
    #[test]
    fn a_trickle_of_rejects_below_the_sample_floor_never_halts() {
        let _env = spawn_env_guard();
        let rt = rt();
        rt.block_on(async {
            let s = LaneSupervisor::new(Lane::Xmr);
            s.set_acceptance_config(AcceptanceConfig {
                warmup: Duration::from_millis(30),
                min_window: Duration::from_millis(50),
                min_submissions: 50, // far more than this rig will ever produce
                ..fast_acceptance()
            });
            let (program, args) = idle_child();
            s.start_simple(program, args).expect("start");
            assert!(wait_for(&s, 5, |st| st.state == ProcState::Running).await);

            tokio::time::sleep(Duration::from_millis(60)).await;
            for i in 1..=12u64 {
                feed(&s, &format!("net      rejected (0/{i}) diff 100 (10 ms)"));
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
            tokio::time::sleep(Duration::from_secs(3)).await;

            let st = s.stats();
            assert!(!st.halted, "a thin sample must never stop a rig: {st:?}");
            assert_eq!(st.acceptance, "gathering");
            assert_eq!(st.accept_pct, None, "an unmeasured rate must render as '—', not 0");
            assert!(st.running);
            s.request_stop();
        });
    }

    /// COLD START: a burst of rejections in the first moments of a run — a
    /// re-handshake, a vardiff settle, a stale job at start-up — is discarded, and a
    /// run that is healthy thereafter is never touched.
    #[test]
    fn a_cold_start_reject_burst_never_halts_a_healthy_run() {
        let _env = spawn_env_guard();
        let rt = rt();
        rt.block_on(async {
            let s = LaneSupervisor::new(Lane::Xmr);
            s.set_acceptance_config(fast_acceptance());
            let (program, args) = idle_child();
            s.start_simple(program, args).expect("start");
            assert!(wait_for(&s, 5, |st| st.state == ProcState::Running).await);

            // 30 rejections while cold…
            for i in 1..=30u64 {
                feed(&s, &format!("net      rejected (0/{i}) diff 100 (10 ms)"));
            }
            // …then a normal lane: 3% rejects, sustained.
            tokio::time::sleep(Duration::from_millis(60)).await;
            let mut rej = 30u64;
            let mut ever_healthy = false;
            for i in 1..=120u64 {
                if i % 33 == 0 {
                    rej += 1;
                }
                feed(&s, &format!("net      accepted ({i}/{rej}) diff 100 (10 ms)"));
                let st = s.stats();
                // A period in progress reads `gathering`; a completed one reads
                // `healthy`. Neither a strike nor a halt may EVER appear here.
                assert!(
                    st.acceptance == "gathering" || st.acceptance == "healthy",
                    "a warm-up burst must not count against the run: {st:?}"
                );
                if st.acceptance == "healthy" {
                    ever_healthy = true;
                    assert!(st.accept_pct.unwrap_or(0.0) > 90.0, "{st:?}");
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert!(ever_healthy, "the run should have completed a healthy period");
            tokio::time::sleep(Duration::from_secs(2)).await;

            let st = s.stats();
            assert!(!st.halted, "a warm-up burst must not stop a healthy rig: {st:?}");
            assert!(st.running);
            s.request_stop();
        });
    }

    /// PRIORITY: the acceptance halt outranks the crash ladder. An engine that dies
    /// AFTER a collapse must not be resurrected — restarting into a pool that rejects
    /// everything is precisely the loop that burned three days.
    #[test]
    fn a_halted_lane_is_never_restarted_by_the_crash_ladder() {
        let _env = spawn_env_guard();
        let rt = rt();
        rt.block_on(async {
            let s = LaneSupervisor::new(Lane::Xmr);
            s.set_acceptance_config(fast_acceptance());
            s.set_retry_timing(Duration::from_millis(50));
            // A rebuild closure that would happily relaunch — if anything asked it to.
            let calls = Arc::new(AtomicUsize::new(0));
            let calls2 = calls.clone();
            let (program, args) = idle_child();
            let (p2, a2) = (program.clone(), args.clone());
            let rebuild: RebuildFn = Arc::new(move |_eps: &[Endpoint]| {
                calls2.fetch_add(1, Ordering::SeqCst);
                Ok((p2.clone(), a2.clone()))
            });
            s.start(program, args, rebuild).expect("start");
            assert!(wait_for(&s, 5, |st| st.state == ProcState::Running).await);

            tokio::time::sleep(Duration::from_millis(60)).await;
            feed(&s, "net      rejected (0/0) diff 100 (10 ms)");
            for i in 1..=25u64 {
                feed(&s, &format!("net      rejected (0/{i}) diff 100 (10 ms)"));
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(wait_for(&s, 12, |st| st.halted).await, "must halt: {:?}", s.stats());

            // Give every automatic path (crash ladder, stall ladder, failover) ample
            // time to misbehave.
            tokio::time::sleep(Duration::from_secs(3)).await;
            let st = s.stats();
            assert!(!st.running, "nothing may bring a halted lane back: {st:?}");
            assert_eq!(st.retry_in_s, None);
            assert_eq!(calls.load(Ordering::SeqCst), 0, "no relaunch may be attempted");
            s.request_stop();
        });
    }

    /// A user Start CLEARS the halt — it is the one action that means "I've dealt with
    /// it" (updated the client, fixed the address, stopped overclocking). The guard
    /// protects the user; it does not lock him out of his own rig.
    #[test]
    fn a_user_start_clears_the_halt_and_the_verdict() {
        let _env = spawn_env_guard();
        let rt = rt();
        rt.block_on(async {
            let s = LaneSupervisor::new(Lane::Xmr);
            s.set_acceptance_config(fast_acceptance());
            let (program, args) = idle_child();
            s.start_simple(program.clone(), args.clone()).expect("start");
            assert!(wait_for(&s, 5, |st| st.state == ProcState::Running).await);
            tokio::time::sleep(Duration::from_millis(60)).await;
            feed(&s, "net      rejected (0/0) diff 100 (10 ms)");
            for i in 1..=25u64 {
                feed(&s, &format!("net      rejected (0/{i}) diff 100 (10 ms)"));
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(wait_for(&s, 12, |st| st.halted).await, "must halt");
            assert!(wait_for(&s, 8, |st| !st.running).await, "must stop");

            s.start_simple(program, args).expect("the user may always start again");
            let st = s.stats();
            assert!(!st.halted, "a user Start clears the halt");
            assert_eq!(st.acceptance, "warmup", "and the evidence behind it");
            assert_eq!(st.accepted, 0, "a fresh run zeroes the counters");
            s.request_stop();
        });
    }

    /// HONESTY: the GPU-Alpha lane's engine reports SUBMISSIONS, not accepts. It must
    /// read `unknown` with no percentage — never a fabricated 100% (which would hide a
    /// real collapse) and never a fabricated 0% (which would stop a working rig).
    #[test]
    fn an_engine_that_cannot_see_rejections_reports_unknown_not_a_number() {
        let s = LaneSupervisor::with_backend(
            Lane::GpuAlpha,
            EndpointPlan::single(Endpoint::plaintext("us.aliceprotocol.org", 3340)),
            ParserKind::Alpha,
            None,
        );
        {
            let mut g = s.inner.lock().unwrap();
            for i in 1..=500u64 {
                apply_log_line(
                    &mut g,
                    ParserKind::Alpha,
                    &format!("level=info msg=miner-status hashrate_th_s=1.5 hits={i}"),
                );
            }
        }
        let st = s.stats();
        assert_eq!(st.acceptance, "unknown", "alpha cannot see the pool's verdict");
        assert_eq!(st.accept_pct, None, "and must not invent one");
        assert!(!st.halted, "an unknown lane is never halted on local evidence");
    }

    /// The two verdict messages must actually differ, and neither may claim what we
    /// did not measure. Sending a user on a two-day hardware hunt for OUR bug is the
    /// failure mode that matters here — he had already spent three days reinstalling.
    #[test]
    fn network_wide_and_local_only_halts_read_differently() {
        let _lock = crate::i18n::LANG_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        crate::i18n::set_lang(crate::i18n::Lang::En);
        let args = StatusArgs {
            shares_accepted: Some(0),
            shares_rejected: Some(72),
            accept_pct: Some(0.0),
            ..Default::default()
        };
        let net = status_tooltip("acceptance_halt_network", &args).unwrap();
        let loc = status_tooltip("acceptance_halt_local", &args).unwrap();
        let unk = status_tooltip("acceptance_halt_unknown", &args).unwrap();
        assert_ne!(net, loc);
        assert_ne!(net, unk);
        assert_ne!(loc, unk);
        // Everyone is down → hands off the rig.
        assert!(net.contains("not your machine"), "{net}");
        // Only you are down → look at the local end.
        assert!(loc.contains("this machine"), "{loc}");
        assert!(!loc.contains("not your machine"), "{loc}");
        // We couldn't check → say so, blame nobody.
        assert!(unk.contains("cannot yet tell"), "{unk}");
        // All three share the one-line status shape and stay short.
        for key in ["acceptance_halt_network", "acceptance_halt_local", "acceptance_halt_unknown"] {
            let short = status_short(key, &args);
            assert!(short.contains("0 accepted"), "{key}: {short}");
            assert!(short.chars().count() < 60, "a status pill must stay short: {short}");
            assert!(!status_is_retrying(key), "a halt must never render as 'retrying'");
        }
        crate::i18n::set_lang(crate::i18n::Lang::En);
    }

    /// The halt status re-localizes from its machine key + args, so a `zh` GUI paired
    /// with an `en` CLI reads it in Chinese (the i18n boundary rule).
    #[test]
    fn the_halt_relocalizes_from_the_key_not_the_baked_string() {
        let _lock = crate::i18n::LANG_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let args = StatusArgs {
            shares_accepted: Some(0),
            shares_rejected: Some(72),
            accept_pct: Some(0.0),
            ..Default::default()
        };
        crate::i18n::set_lang(crate::i18n::Lang::Zh);
        let zh = status_short("acceptance_halt_network", &args);
        let zh_tip = status_tooltip("acceptance_halt_network", &args).unwrap();
        assert!(has_cjk(&zh), "{zh}");
        assert!(zh_tip.contains("不是你的机器"), "{zh_tip}");
        crate::i18n::set_lang(crate::i18n::Lang::En);
        let en = status_short("acceptance_halt_network", &args);
        assert!(!has_cjk(&en), "{en}");
    }
}
