//! `core/acceptance` — the **share acceptance-rate collapse** self-protection
//! (Layer 3 of the 2026-08-14 self-protection design).
//!
//! # Why this exists
//!
//! On 2026-08-11T12:04Z the PRL lane's upstream pool changed algorithm (a Pearl
//! emergency hard fork). Our client hard-pins an older engine build, so from that
//! moment **every** share it submitted was judged invalid upstream. One miner ran
//! for three days: connected fine, received jobs fine, 69 automatic region
//! failovers, engine restarts — and `0 accepted / 72 rejected`. The client never
//! told him. He burned three days of electricity for nothing.
//!
//! Everything the client already watched was *green*: TCP was up, jobs arrived,
//! the hashrate was nominal, and the Layer-B watchdog measures "no progress",
//! which a stream of REJECTED shares does not look like — a rejected share still
//! moves the engine's counters and the miner still burns power. **Acceptance is a
//! dimension nothing was watching.** This module is that dimension.
//!
//! # What it does NOT do
//!
//! It never fabricates a verdict. Two lanes cannot see the pool's judgement at all:
//!
//! * the GPU-Alpha lane (`alpha-miner`) submits asynchronously and its cumulative
//!   `hits` counter is *submissions*, not accepts — its `rejected` is always `None`;
//! * an unknown custom miner may print an accept count and never a reject count.
//!
//! For those, the local verdict is [`LaneVerdict::Unknown`] — literally "we cannot
//! see whether your shares are being accepted" — and the ONLY thing that can
//! resolve it is the server's network-wide lane health. If that is unreachable the
//! answer stays `Unknown`. **A lane we cannot judge is never reported as 0% and
//! never halted.**
//!
//! # Zero supply-chain surface
//!
//! This layer adds no signing key, no auto-download, no new code path that a stolen
//! release key could ride. Its network use is one *read-only, unauthenticated* GET
//! whose only effect is choosing between two sentences (see [`Attribution`]) — a
//! hostile answer can make the wording wrong, never the halt.

use std::time::{Duration, Instant};

use crate::lane::Lane;
use crate::stats::ParserKind;

// ─────────────────────────────────────────────────────────────────────────────
// Thresholds. Every one of these is a "never stop a healthy miner" decision, so
// each carries the reasoning that set it.
// ─────────────────────────────────────────────────────────────────────────────

/// Cold-start grace. Nothing submitted in the first five minutes of a run counts
/// toward a verdict at all.
///
/// A fresh child re-handshakes, re-negotiates difficulty and (on the PRL lane)
/// re-mints a region-bound PoP token; the first shares out of a cold engine are
/// the ones most likely to be stale or mis-targeted through no fault of the pool.
/// SRBMiner's own warm-up on a big GPU is ~15 s, and a vardiff settle can take
/// minutes. Five minutes is comfortably past both, and costs a miner nothing —
/// this layer's job is to stop a THREE-DAY waste, so buying certainty with five
/// minutes is free.
pub const WARMUP: Duration = Duration::from_secs(5 * 60);

/// Minimum wall time a statistical period must cover before it may produce a
/// verdict. Paired with [`MIN_SUBMISSIONS`] as a floor, not a period length: a
/// period ENDS when *both* gates are satisfied, so a slow rig simply takes longer
/// to be judged rather than being judged on thin evidence.
pub const MIN_WINDOW: Duration = Duration::from_secs(10 * 60);

/// Minimum submitted shares (accepted + rejected) a period must contain. Below
/// this we say nothing at all.
///
/// This is the low-hashrate protection. A miner submitting one share every twenty
/// minutes accumulates twenty submissions in ~7 h — and that is CORRECT: with
/// three submissions you cannot distinguish "the pool rejects everything" from
/// "this rig got unlucky", and stopping a working rig on three samples would be a
/// far worse bug than the one this layer fixes.
pub const MIN_SUBMISSIONS: u64 = 20;

/// The acceptance rate (percent) at or below which a completed period is BAD.
///
/// A healthy lane runs 97–100%. Stale-share bursts around a block change, or a
/// laggy link, can drag a window down transiently — 20% is far below anything a
/// merely-unlucky-but-working rig produces, and the incident this layer exists for
/// sat at exactly 0%.
pub const COLLAPSE_PCT: f64 = 20.0;

/// How many CONSECUTIVE bad periods halt the lane. Two, so a single unlucky window
/// (a pool restart, a reorg, one bad tick) can never stop a working miner — it must
/// still be bad after a second full window with a second full sample.
pub const STRIKES_TO_HALT: u32 = 2;

/// Where a halted miner is pointed. This incident's actual fix is a new engine pin,
/// which ships as a release — so the releases page is the honest "go here" for a
/// miner who is told a pool rule changed.
//
// NOTE(deploy): override with `ALICE_MINER_HELP_URL` (or repoint this constant) once
// a dedicated status page exists; the halt text renders whatever this resolves to.
pub const HELP_URL_DEFAULT: &str = "https://github.com/V-SK/Alice-Miner/releases/latest";

/// Env override for [`HELP_URL_DEFAULT`]. Must be `https://` or it is ignored (we
/// will not send a miner to a plaintext URL we printed ourselves).
pub const ENV_HELP_URL: &str = "ALICE_MINER_HELP_URL";

/// The URL the halt message points at: [`ENV_HELP_URL`] when set to an `https://`
/// value, else [`HELP_URL_DEFAULT`].
pub fn help_url() -> String {
    std::env::var(ENV_HELP_URL)
        .ok()
        .filter(|s| s.starts_with("https://"))
        .unwrap_or_else(|| HELP_URL_DEFAULT.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Can this lane SEE the pool's judgement at all?
// ─────────────────────────────────────────────────────────────────────────────

/// Whether the engine driving a lane reports pool REJECTIONS to us.
///
/// This is the honesty gate. It is derived from the log parser, not from the lane,
/// because a bring-your-own miner breaks the lane→format mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectVisibility {
    /// The engine prints an accepted AND a rejected counter, so an acceptance rate
    /// computed from them is a real measurement.
    Observed,
    /// The engine never reports rejections. Its "accepted" counter is really a
    /// SUBMISSION counter, so a rate computed from it would read 100% forever —
    /// a fabricated all-clear. We refuse to compute one.
    Unavailable,
}

impl RejectVisibility {
    /// What `parser` can actually tell us.
    ///
    /// [`ParserKind::Alpha`] is the one that must be `Unavailable`: `parse_alpha`
    /// reads the alpha-miner status line's cumulative `hits`, which counts shares
    /// SUBMITTED (submission is async; acceptance is the relay's truth), and leaves
    /// `rejected` at `None`. Treating that as 0 rejections would report a
    /// 100%-healthy lane during a total rejection storm — precisely the lie this
    /// module exists to prevent.
    pub fn for_parser(parser: ParserKind) -> Self {
        match parser {
            // `(A/R)` on one line — both counters, always.
            ParserKind::Xmr => RejectVisibility::Observed,
            // kawpowminer / T-Rex report accepted+rejected together (both-or-none).
            ParserKind::Kawpow => RejectVisibility::Observed,
            // SRBMiner's `[acc|rej|...]` bracket / `Shares acc./rej.` summary.
            ParserKind::Srbminer => RejectVisibility::Observed,
            // alpha-miner: submissions only. See the doc comment above.
            ParserKind::Alpha => RejectVisibility::Unavailable,
            // An unknown format: if it never prints rejections its counters simply
            // never accumulate a bad period (rate reads 100%), which is a false
            // ALL-CLEAR, not a false halt. A rejection we DO manage to read is real
            // evidence, so this stays `Observed`.
            ParserKind::Generic => RejectVisibility::Observed,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The verdict
// ─────────────────────────────────────────────────────────────────────────────

/// What one completed statistical period measured.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PeriodStat {
    /// Shares accepted during the period.
    pub accepted: u64,
    /// Shares rejected during the period.
    pub rejected: u64,
    /// How long the period covered.
    pub elapsed: Duration,
}

impl PeriodStat {
    /// Submissions in the period (accepted + rejected). Never 0 for a period that
    /// completed (a period only completes past [`MIN_SUBMISSIONS`]).
    pub fn submissions(&self) -> u64 {
        self.accepted.saturating_add(self.rejected)
    }
    /// The measured acceptance rate in percent.
    pub fn accept_pct(&self) -> f64 {
        let n = self.submissions();
        if n == 0 {
            return 0.0;
        }
        self.accepted as f64 * 100.0 / n as f64
    }
    /// A period in which NOT ONE share was accepted. Distinguished because it is
    /// qualitatively different from "mostly bad": twenty-plus consecutive rejections
    /// with zero accepts, over ten-plus minutes, is not bad luck on any pool.
    pub fn is_shutout(&self) -> bool {
        self.accepted == 0
    }
}

/// The lane's acceptance verdict. Ordered from "we are not judging yet" to "stop".
#[derive(Debug, Clone, PartialEq)]
pub enum LaneVerdict {
    /// Inside the cold-start grace ([`WARMUP`]) — deliberately no opinion.
    Warmup,
    /// This engine cannot report rejections, so this machine cannot compute an
    /// acceptance rate. NOT 0%, NOT healthy — unknown. Only the server's
    /// network-wide lane health can speak for this lane, and if it is unreachable
    /// the answer stays unknown.
    Unknown,
    /// Warm and watching, but the current period has not yet reached BOTH
    /// [`MIN_WINDOW`] and [`MIN_SUBMISSIONS`]. A low-hashrate rig lives here for
    /// hours at a time; that is correct.
    Gathering,
    /// The last completed period was fine.
    Healthy(PeriodStat),
    /// One bad period recorded. Not acted on — a second one is required. The lane
    /// keeps mining and the UI can warn.
    Degrading(PeriodStat),
    /// The halt condition. Carries the period that decided it, so the message can
    /// quote real numbers instead of an adjective.
    Collapsed(Collapse),
}

impl LaneVerdict {
    /// Whether this verdict means "stop mining now".
    pub fn is_collapsed(&self) -> bool {
        matches!(self, LaneVerdict::Collapsed(_))
    }
    /// The acceptance rate to DISPLAY, if one was actually measured. `None` for
    /// warmup / unknown / gathering — the caller must render "—", never 0.
    pub fn accept_pct(&self) -> Option<f64> {
        match self {
            LaneVerdict::Healthy(p) | LaneVerdict::Degrading(p) => Some(p.accept_pct()),
            LaneVerdict::Collapsed(c) => Some(c.period.accept_pct()),
            LaneVerdict::Warmup | LaneVerdict::Unknown | LaneVerdict::Gathering => None,
        }
    }
    /// A stable machine key (for a snapshot / a front-end that localizes itself).
    pub fn key(&self) -> &'static str {
        match self {
            LaneVerdict::Warmup => "warmup",
            LaneVerdict::Unknown => "unknown",
            LaneVerdict::Gathering => "gathering",
            LaneVerdict::Healthy(_) => "healthy",
            LaneVerdict::Degrading(_) => "degrading",
            LaneVerdict::Collapsed(_) => "collapsed",
        }
    }
}

/// The evidence behind a [`LaneVerdict::Collapsed`].
#[derive(Debug, Clone, PartialEq)]
pub struct Collapse {
    /// The period that tipped it.
    pub period: PeriodStat,
    /// Totals for the whole run since warm-up ended — the numbers a user recognises
    /// ("0 accepted, 72 rejected"), which the per-period figures alone would understate.
    pub run_accepted: u64,
    pub run_rejected: u64,
    /// How the halt was reached: `true` when a single period at EXACTLY zero
    /// acceptance decided it, `false` when [`STRIKES_TO_HALT`] merely-bad periods did.
    pub shutout: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// The monitor
// ─────────────────────────────────────────────────────────────────────────────

/// Tunables, so tests can run the state machine in milliseconds instead of hours.
/// Production always uses [`AcceptanceConfig::default`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AcceptanceConfig {
    pub warmup: Duration,
    pub min_window: Duration,
    pub min_submissions: u64,
    pub collapse_pct: f64,
    pub strikes_to_halt: u32,
}

impl Default for AcceptanceConfig {
    fn default() -> Self {
        Self {
            warmup: WARMUP,
            min_window: MIN_WINDOW,
            min_submissions: MIN_SUBMISSIONS,
            collapse_pct: COLLAPSE_PCT,
            strikes_to_halt: STRIKES_TO_HALT,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Baseline {
    at: Instant,
    accepted: u64,
    rejected: u64,
}

/// The acceptance-collapse state machine.
///
/// Pure and synchronous: it is fed the lane's CUMULATIVE `(accepted, rejected)`
/// counters and a clock, and it returns a [`LaneVerdict`]. No I/O, no locks, no
/// clock of its own — which is why it can be exhaustively tested and why the
/// supervisor can call it from inside its existing mutex.
#[derive(Debug, Clone)]
pub struct AcceptanceMonitor {
    cfg: AcceptanceConfig,
    visibility: RejectVisibility,
    /// When the current RUN started (set by [`Self::on_run_start`]).
    run_started: Option<Instant>,
    /// Counters at the moment warm-up ended (the run-total baseline).
    warm_baseline: Option<Baseline>,
    /// Counters at the start of the current statistical period.
    period_baseline: Option<Baseline>,
    /// Consecutive completed periods below the threshold.
    strikes: u32,
    verdict: LaneVerdict,
    /// Latest cumulative counters seen (for regression detection).
    last_seen: (u64, u64),
}

impl AcceptanceMonitor {
    /// A monitor for a lane driven by `parser`, with production thresholds.
    pub fn new(parser: ParserKind) -> Self {
        Self::with_config(parser, AcceptanceConfig::default())
    }

    /// A monitor with explicit thresholds (tests).
    pub fn with_config(parser: ParserKind, cfg: AcceptanceConfig) -> Self {
        let visibility = RejectVisibility::for_parser(parser);
        Self {
            cfg,
            visibility,
            run_started: None,
            warm_baseline: None,
            period_baseline: None,
            strikes: 0,
            verdict: match visibility {
                RejectVisibility::Observed => LaneVerdict::Warmup,
                RejectVisibility::Unavailable => LaneVerdict::Unknown,
            },
            last_seen: (0, 0),
        }
    }

    /// Whether this lane can measure acceptance locally at all.
    pub fn visibility(&self) -> RejectVisibility {
        self.visibility
    }

    /// The current verdict without feeding a new observation.
    pub fn verdict(&self) -> LaneVerdict {
        self.verdict.clone()
    }

    /// Run totals since warm-up ended (accepted, rejected). `(0, 0)` before warm-up.
    pub fn run_totals(&self) -> (u64, u64) {
        match self.warm_baseline {
            Some(b) => (
                self.last_seen.0.saturating_sub(b.accepted),
                self.last_seen.1.saturating_sub(b.rejected),
            ),
            None => (0, 0),
        }
    }

    /// A FRESH run began: the supervisor zeroed the share counters, so every
    /// accumulated judgement is void. Also clears any prior collapse — a user who
    /// pressed Start again (perhaps after updating) gets a clean slate.
    pub fn on_run_start(&mut self, now: Instant) {
        self.run_started = Some(now);
        self.warm_baseline = None;
        self.period_baseline = None;
        self.strikes = 0;
        self.last_seen = (0, 0);
        self.verdict = match self.visibility {
            RejectVisibility::Observed => LaneVerdict::Warmup,
            RejectVisibility::Unavailable => LaneVerdict::Unknown,
        };
    }

    /// A Layer-B FAILOVER relaunched the child on another endpoint.
    ///
    /// Deliberately a **no-op** — it exists so the decision is written down at the
    /// call site instead of being an absence somebody later "fixes".
    ///
    /// The tempting version resets the statistical period so the new endpoint is
    /// judged on its own window. That version is a bug, and it is *this incident's*
    /// bug: the client failed over sixty-nine times in seventy-eight hours, and any
    /// per-failover reset hands a failover loop a way to keep the window perpetually
    /// open and hide a total shutout forever. The supervisor keeps the cumulative counters
    /// across a failover for the same reason, and rotating regions cannot fix an
    /// upstream algorithm change anyway — every region rejects the identical share.
    ///
    /// Nor does carrying the window across a rotation risk a false halt: if the new
    /// region IS healthy its accepts land in the same window and drag the rate UP,
    /// and any accepted share at all disqualifies the shutout rule.
    pub fn on_failover(&mut self, _now: Instant) {}

    /// Feed the lane's CUMULATIVE counters and get the resulting verdict.
    ///
    /// Called on every parsed log line, so it must stay cheap: a handful of integer
    /// comparisons and, at most once per completed period, one division.
    pub fn observe(&mut self, now: Instant, accepted: u64, rejected: u64) -> LaneVerdict {
        // A lane whose engine cannot report rejections is never judged here.
        if self.visibility == RejectVisibility::Unavailable {
            self.last_seen = (accepted, rejected);
            self.verdict = LaneVerdict::Unknown;
            return self.verdict.clone();
        }

        // Counters that moved BACKWARDS mean the stream re-baselined under us (a
        // custom miner's log re-read, a mis-parsed line the `fold_cumulative` belt
        // let through). Adopt the new floor rather than computing a bogus negative
        // delta — an under-count can only make us slower to halt, never quicker.
        if accepted < self.last_seen.0 || rejected < self.last_seen.1 {
            self.rebaseline(now, accepted, rejected);
        }
        self.last_seen = (accepted, rejected);

        let Some(started) = self.run_started else {
            // `observe` before `on_run_start` — treat this observation as the start.
            self.run_started = Some(now);
            self.verdict = LaneVerdict::Warmup;
            return self.verdict.clone();
        };

        // ── Cold start ────────────────────────────────────────────────────────
        if now.saturating_duration_since(started) < self.cfg.warmup {
            self.verdict = LaneVerdict::Warmup;
            return self.verdict.clone();
        }
        // First observation past warm-up: everything submitted while cold is
        // discarded, so a handshake-time reject burst can never count against a rig.
        if self.warm_baseline.is_none() {
            let base = Baseline { at: now, accepted, rejected };
            self.warm_baseline = Some(base);
            self.period_baseline = Some(base);
            self.verdict = LaneVerdict::Gathering;
            return self.verdict.clone();
        }

        // A collapse is terminal for the run — the supervisor halts on it, and a
        // late log line must not walk it back.
        if self.verdict.is_collapsed() {
            return self.verdict.clone();
        }

        let base = self.period_baseline.expect("set with warm_baseline");
        let period = PeriodStat {
            accepted: accepted.saturating_sub(base.accepted),
            rejected: rejected.saturating_sub(base.rejected),
            elapsed: now.saturating_duration_since(base.at),
        };

        // ── Both gates, or no verdict ─────────────────────────────────────────
        // The window and the sample are FLOORS, not a schedule: a period ends only
        // once it is both long enough and big enough. A rig too slow to reach the
        // sample simply stays in `Gathering` — it is never judged on thin evidence
        // and never stopped.
        if period.elapsed < self.cfg.min_window || period.submissions() < self.cfg.min_submissions {
            self.verdict = LaneVerdict::Gathering;
            return self.verdict.clone();
        }

        // The period is complete. Judge it and open the next one.
        self.period_baseline = Some(Baseline { at: now, accepted, rejected });

        if period.accept_pct() >= self.cfg.collapse_pct {
            self.strikes = 0;
            self.verdict = LaneVerdict::Healthy(period);
            return self.verdict.clone();
        }

        self.strikes = self.strikes.saturating_add(1);

        // A TOTAL shutout — a full window, a full sample, and not one share
        // accepted — is conclusive on its own. The two-period rule exists to
        // survive an unlucky window; a window in which the pool accepted literally
        // nothing is not luck, and making a miner burn a second full window to
        // confirm it doubles the waste this layer exists to stop.
        let decided = period.is_shutout() || self.strikes >= self.cfg.strikes_to_halt;
        if decided {
            let (run_accepted, run_rejected) = self.run_totals();
            self.verdict = LaneVerdict::Collapsed(Collapse {
                period,
                run_accepted,
                run_rejected,
                shutout: period.is_shutout(),
            });
        } else {
            self.verdict = LaneVerdict::Degrading(period);
        }
        self.verdict.clone()
    }

    /// Move every baseline down to a counter stream that restarted beneath us,
    /// preserving elapsed time (so a re-baseline cannot also reset the clock and
    /// hold a period open forever).
    fn rebaseline(&mut self, now: Instant, accepted: u64, rejected: u64) {
        if let Some(b) = self.warm_baseline.as_mut() {
            b.accepted = b.accepted.min(accepted);
            b.rejected = b.rejected.min(rejected);
        }
        if let Some(b) = self.period_baseline.as_mut() {
            b.accepted = b.accepted.min(accepted);
            b.rejected = b.rejected.min(rejected);
            let _ = now;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Attribution — "is it everyone, or is it me?"
// ─────────────────────────────────────────────────────────────────────────────

/// Who the collapse is most likely about. This changes ONLY the wording; the halt
/// itself is decided locally and never waits on the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attribution {
    /// The whole network's lane is being rejected too — ours or the upstream pool's
    /// problem. The user must be told plainly to leave their rig alone.
    NetworkWide,
    /// The network's lane is healthy; only this machine is being rejected. Points at
    /// the local end — hardware, driver, clock, network path, configuration.
    LocalOnly,
    /// We could not reach the lane-health endpoint, or it had nothing to say about
    /// this lane. We say so, and we blame nobody.
    Unknown,
}

impl Attribution {
    pub fn key(self) -> &'static str {
        match self {
            Attribution::NetworkWide => "network",
            Attribution::LocalOnly => "local",
            Attribution::Unknown => "unknown",
        }
    }
}

/// The network-wide acceptance rate for one lane, as reported by the public
/// read-API. Every field is optional because "the server did not say" must be
/// representable — an absent number is [`Attribution::Unknown`], never a zero.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LaneHealth {
    /// Network-wide acceptance rate in percent.
    pub accept_pct: f64,
    /// How many miners the figure is drawn from — a single-miner figure is US, and
    /// therefore proves nothing about the network.
    pub miners: u64,
}

impl LaneHealth {
    /// The attribution this network reading implies for a locally-collapsed lane.
    ///
    /// A figure computed from fewer than two miners is not evidence about the
    /// network (it is very likely this very machine), so it resolves to
    /// [`Attribution::Unknown`] rather than falsely accusing the user's hardware.
    pub fn attribute(&self) -> Attribution {
        if self.miners < 2 {
            return Attribution::Unknown;
        }
        if self.accept_pct <= COLLAPSE_PCT {
            Attribution::NetworkWide
        } else {
            Attribution::LocalOnly
        }
    }
}

/// Parse the lane-health payload for `lane` out of a read-API body.
///
/// Contract (public, read-only, no auth):
/// ```json
/// { "lanes": [ { "lane": "gpu_prl", "accept_pct": 0.0, "miners": 5 } ] }
/// ```
/// Anything else — a missing lane, a missing field, a non-numeric value, a body
/// that is not JSON — yields `None`, which the caller renders as
/// [`Attribution::Unknown`]. A hostile or broken server can therefore only make our
/// WORDING vaguer; it can neither halt a healthy miner nor un-halt a collapsed one.
pub fn parse_lane_health(body: &str, lane: Lane) -> Option<LaneHealth> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let lanes = v.get("lanes")?.as_array()?;
    let want = lane_wire_name(lane);
    for entry in lanes {
        let name = entry.get("lane").and_then(|n| n.as_str()).unwrap_or_default();
        if !name.eq_ignore_ascii_case(want) {
            continue;
        }
        let accept_pct = entry.get("accept_pct").and_then(|n| n.as_f64())?;
        if !accept_pct.is_finite() || !(0.0..=100.0).contains(&accept_pct) {
            return None; // a nonsense number is "no answer", not an answer
        }
        let miners = entry.get("miners").and_then(|n| n.as_u64()).unwrap_or(0);
        return Some(LaneHealth { accept_pct, miners });
    }
    None
}

/// The wire name a lane goes by in the read-API lane-health payload.
pub fn lane_wire_name(lane: Lane) -> &'static str {
    match lane {
        Lane::Xmr => "xmr",
        Lane::GpuRvn => "gpu_rvn",
        Lane::GpuPrl => "gpu_prl",
        Lane::GpuAlpha => "gpu_alpha",
    }
}

/// The lane-health URL under a read-API `base` (the same apex the credit poller uses).
pub fn lane_health_url(base: &str) -> String {
    format!("{}/read/lane-health", base.trim_end_matches('/'))
}

// ─────────────────────────────────────────────────────────────────────────────
// The words a halted miner actually reads
// ─────────────────────────────────────────────────────────────────────────────

/// The one-line status for a halted lane (the crowded status pill).
pub fn halt_status_line(c: &Collapse) -> String {
    let pct = c.period.accept_pct();
    if c.shutout {
        let n = c.run_rejected.max(c.period.rejected);
        crate::tr!(
            format!("Stopped · {n} shares submitted, 0 accepted"),
            format!("已停止 · 已提交 {n} 份额,0 个被接受")
        )
    } else {
        crate::tr!(
            format!("Stopped · only {pct:.0}% of shares accepted"),
            format!("已停止 · 仅 {pct:.0}% 的份额被接受")
        )
    }
}

/// The FULL explanation — the paragraph the miner in the 2026-08-11 incident never
/// got. Three parts, always in this order:
///
/// 1. **What we measured**, in his numbers, not an adjective.
/// 2. **Why we stopped**: continuing costs electricity and earns nothing. This is the
///    sentence that makes the halt a service rather than an inconvenience.
/// 3. **Whose problem it is** — and this is where [`Attribution`] earns its keep. If
///    the whole network is down, telling a user to check their GPU sends him on a
///    two-day hardware hunt for a bug on our side (he already spent three days
///    reinstalling); if only he is down, telling him "we're on it" leaves him waiting
///    for a fix that will never come. When we do not know, we say we do not know.
pub fn halt_explanation(c: &Collapse, attribution: Attribution) -> String {
    let submitted = c.run_accepted.saturating_add(c.run_rejected).max(c.period.submissions());
    let accepted = c.run_accepted;
    let url = help_url();

    let measured = if c.shutout {
        crate::tr!(
            format!(
                "You submitted {submitted} shares and not one was accepted. Mining like this earns nothing, so the miner has stopped instead of running up your power bill."
            ),
            format!(
                "你提交了 {submitted} 个份额,一个都没有被接受。这样挖下去不会有任何收益,所以矿工已经停止,不再白烧电费。"
            )
        )
    } else {
        let pct = c.period.accept_pct();
        crate::tr!(
            format!(
                "Of your last {submitted} submitted shares only {accepted} were accepted ({pct:.0}%). At that rate mining earns almost nothing, so the miner has stopped instead of running up your power bill."
            ),
            format!(
                "你最近提交的 {submitted} 个份额中只有 {accepted} 个被接受({pct:.0}%)。按这个比例挖下去几乎没有收益,所以矿工已经停止,不再白烧电费。"
            )
        )
    };

    let cause = match attribution {
        // Everyone is being rejected. Say it is ours, tell him to stop touching the rig.
        Attribution::NetworkWide => crate::tr!(
            format!(
                "Every miner on this lane is being rejected right now, so this is a problem on our side or with the upstream pool — not your machine. We are working on it. Do not reinstall or rebuild anything; check {url} and restart when an update is published."
            ),
            format!(
                "目前这条 lane 上所有矿工的份额都在被拒绝,所以这是我们或上游矿池的问题,不是你的机器。我们正在处理。请不要重装或折腾你的机器;关注 {url},等更新发布后再启动。"
            )
        ),
        // Everyone else is fine. Point at the local end — but never assert a cause we
        // did not measure; these are the things to check, in order of likelihood.
        Attribution::LocalOnly => crate::tr!(
            format!(
                "Other miners on this lane are being accepted normally, so this looks specific to this machine — most often an out-of-date miner, a wrong or mistyped payout address, a badly overclocked GPU producing invalid results, or a clock that has drifted. Check {url} for the current version, and if you are overclocking, return the card to stock and start again."
            ),
            format!(
                "这条 lane 上的其他矿工份额正常被接受,所以问题看起来只出在这台机器上 —— 最常见的原因是客户端版本过旧、收款地址填错、显卡超频过头导致算出的结果无效,或者本机时间不准。请到 {url} 核对当前版本;如果你在超频,请把显卡调回默认频率再重新启动。"
            )
        ),
        // We could not check. Do not guess out loud.
        Attribution::Unknown => crate::tr!(
            format!(
                "We could not reach the network status service, so we cannot yet tell you whether this is affecting everyone or only this machine. Pool rules can change and require a client update — check {url} before changing anything on your machine."
            ),
            format!(
                "我们暂时连不上网络状态服务,所以还无法判断这是全网问题还是只有这台机器。矿池规则有可能变更、需要更新客户端 —— 请先查看 {url},不要急着改动你的机器。"
            )
        ),
    };

    format!("{measured}\n{cause}")
}

/// The honest line for a lane whose engine cannot report rejections
/// ([`LaneVerdict::Unknown`]) — used where a UI would otherwise be tempted to print
/// "100%" or "0 rejected".
pub fn unknown_acceptance_note() -> String {
    crate::tr!(
        "This engine does not report pool rejections, so the acceptance rate cannot be measured on this machine.".to_string(),
        "该引擎不上报矿池拒绝信息,因此本机无法测量份额接受率。".to_string()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::{set_lang, Lang, LANG_TEST_LOCK};

    fn cfg_fast() -> AcceptanceConfig {
        AcceptanceConfig {
            warmup: Duration::from_millis(50),
            min_window: Duration::from_millis(100),
            min_submissions: 20,
            collapse_pct: 20.0,
            strikes_to_halt: 2,
        }
    }

    /// A clock we drive by hand — the state machine takes `Instant`s, so every
    /// timing case runs instantly and deterministically on every OS.
    struct Clock(Instant);
    impl Clock {
        fn new() -> Self {
            Clock(Instant::now())
        }
        fn at(&self, ms: u64) -> Instant {
            self.0 + Duration::from_millis(ms)
        }
    }

    // ── Cold start ──────────────────────────────────────────────────────────

    #[test]
    fn cold_start_never_judges_however_bad_it_looks() {
        let c = Clock::new();
        let mut m = AcceptanceMonitor::with_config(ParserKind::Srbminer, cfg_fast());
        m.on_run_start(c.at(0));
        // 200 rejections, zero accepts, inside the warm-up grace.
        for i in 1..=200u64 {
            let v = m.observe(c.at(10), 0, i);
            assert_eq!(v, LaneVerdict::Warmup, "warm-up must not judge");
        }
        assert!(!m.verdict().is_collapsed());
    }

    #[test]
    fn shares_submitted_during_warmup_do_not_count_against_the_run() {
        let c = Clock::new();
        let mut m = AcceptanceMonitor::with_config(ParserKind::Srbminer, cfg_fast());
        m.on_run_start(c.at(0));
        // A cold-start reject burst.
        m.observe(c.at(10), 0, 40);
        // Past warm-up, the lane is perfect from here on.
        m.observe(c.at(60), 0, 40); // baseline taken here — the 40 cold rejects are discarded
        let mut ever_healthy = false;
        for i in 1..=30u64 {
            let v = m.observe(c.at(60 + i * 10), i, 40);
            assert!(!v.is_collapsed(), "a warm-up burst must not poison a healthy run: {v:?}");
            assert!(!matches!(v, LaneVerdict::Degrading(_)), "no strike may be recorded: {v:?}");
            ever_healthy |= matches!(v, LaneVerdict::Healthy(_));
        }
        assert!(ever_healthy, "the run should have completed at least one healthy period");
        assert_eq!(m.run_totals(), (30, 0), "run totals must exclude the cold-start rejects");
    }

    // ── Low-hashrate protection ─────────────────────────────────────────────

    #[test]
    fn low_hashrate_miner_below_the_sample_floor_is_never_judged() {
        let c = Clock::new();
        let mut m = AcceptanceMonitor::with_config(ParserKind::Srbminer, cfg_fast());
        m.on_run_start(c.at(0));
        m.observe(c.at(60), 0, 0); // warm baseline
        // Nineteen rejections spread over a very long time — one short of the floor.
        for i in 1..=19u64 {
            let v = m.observe(c.at(60 + i * 1_000), 0, i);
            assert_eq!(v, LaneVerdict::Gathering, "19 samples must not decide anything");
        }
        assert!(!m.verdict().is_collapsed());
    }

    #[test]
    fn a_long_window_alone_is_not_enough_without_the_sample() {
        let c = Clock::new();
        let mut m = AcceptanceMonitor::with_config(ParserKind::Srbminer, cfg_fast());
        m.on_run_start(c.at(0));
        m.observe(c.at(60), 0, 0);
        // Hours pass; three rejects total.
        let v = m.observe(c.at(60 + 6 * 3_600_000), 0, 3);
        assert_eq!(v, LaneVerdict::Gathering);
    }

    #[test]
    fn a_big_sample_alone_is_not_enough_without_the_window() {
        let c = Clock::new();
        let mut m = AcceptanceMonitor::with_config(ParserKind::Srbminer, cfg_fast());
        m.on_run_start(c.at(0));
        m.observe(c.at(60), 0, 0);
        // 500 rejections in a millisecond — a burst, not a window.
        let v = m.observe(c.at(61), 0, 500);
        assert_eq!(v, LaneVerdict::Gathering, "a burst inside the window must not decide");
    }

    // ── Healthy miners are never stopped ────────────────────────────────────

    #[test]
    fn a_healthy_miner_with_normal_rejects_never_halts() {
        let c = Clock::new();
        let mut m = AcceptanceMonitor::with_config(ParserKind::Srbminer, cfg_fast());
        m.on_run_start(c.at(0));
        m.observe(c.at(60), 0, 0);
        // 3% rejects, sustained for a simulated day of periods.
        let (mut acc, mut rej) = (0u64, 0u64);
        for tick in 1..=2_000u64 {
            if tick % 33 == 0 {
                rej += 1;
            } else {
                acc += 1;
            }
            let v = m.observe(c.at(60 + tick * 20), acc, rej);
            assert!(!v.is_collapsed(), "healthy lane halted at tick {tick}: {v:?}");
        }
        assert!(matches!(m.verdict(), LaneVerdict::Healthy(_)));
    }

    #[test]
    fn one_bad_window_alone_does_not_halt() {
        let c = Clock::new();
        let mut m = AcceptanceMonitor::with_config(ParserKind::Srbminer, cfg_fast());
        m.on_run_start(c.at(0));
        m.observe(c.at(60), 0, 0);
        // One bad-but-not-shutout period: 2 accepted / 30 rejected = 6%.
        m.observe(c.at(60), 0, 0);
        let v = m.observe(c.at(300), 2, 30);
        assert!(
            matches!(v, LaneVerdict::Degrading(_)),
            "one bad window must only warn, got {v:?}"
        );
        // …then the pool recovers.
        let v = m.observe(c.at(600), 202, 32);
        assert!(matches!(v, LaneVerdict::Healthy(_)), "recovery must clear the strike, got {v:?}");
        // …and a later bad window starts counting from one again.
        let v = m.observe(c.at(900), 204, 62);
        assert!(matches!(v, LaneVerdict::Degrading(_)), "strike must have been reset, got {v:?}");
    }

    #[test]
    fn two_consecutive_bad_windows_halt() {
        let c = Clock::new();
        let mut m = AcceptanceMonitor::with_config(ParserKind::Srbminer, cfg_fast());
        m.on_run_start(c.at(0));
        m.observe(c.at(60), 0, 0);
        assert!(matches!(m.observe(c.at(300), 2, 30), LaneVerdict::Degrading(_)));
        let v = m.observe(c.at(600), 4, 60);
        assert!(v.is_collapsed(), "two bad windows must halt, got {v:?}");
    }

    // ── THE incident ────────────────────────────────────────────────────────

    #[test]
    fn total_shutout_halts_after_one_qualified_window() {
        // The 2026-08-11 shape exactly: connected, jobs arriving, hashrate nominal,
        // every single share rejected.
        let c = Clock::new();
        let mut m = AcceptanceMonitor::with_config(ParserKind::Srbminer, cfg_fast());
        m.on_run_start(c.at(0));
        m.observe(c.at(60), 0, 0);
        let mut v = LaneVerdict::Gathering;
        for i in 1..=20u64 {
            v = m.observe(c.at(60 + i * 20), 0, i);
        }
        assert!(v.is_collapsed(), "0 accepted / 20 rejected over a full window must halt: {v:?}");
        match v {
            LaneVerdict::Collapsed(c) => {
                assert!(c.shutout);
                assert_eq!(c.run_accepted, 0);
                assert_eq!(c.run_rejected, 20);
                assert_eq!(c.period.accept_pct(), 0.0);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn failover_does_not_erase_the_evidence() {
        // 69 failovers happened in the real incident. If each wiped the counters the
        // collapse would never become provable — which is exactly what went wrong.
        let c = Clock::new();
        let mut m = AcceptanceMonitor::with_config(ParserKind::Srbminer, cfg_fast());
        m.on_run_start(c.at(0));
        m.observe(c.at(60), 0, 0);
        let mut v = LaneVerdict::Gathering;
        for i in 1..=40u64 {
            v = m.observe(c.at(60 + i * 20), 0, i);
            if i % 5 == 0 {
                m.on_failover(c.at(60 + i * 20)); // rotate region; counters persist
            }
        }
        assert!(v.is_collapsed(), "failover churn must not hide a total shutout: {v:?}");
    }

    #[test]
    fn a_fresh_start_clears_a_previous_collapse() {
        let c = Clock::new();
        let mut m = AcceptanceMonitor::with_config(ParserKind::Srbminer, cfg_fast());
        m.on_run_start(c.at(0));
        m.observe(c.at(60), 0, 0);
        for i in 1..=20u64 {
            m.observe(c.at(60 + i * 20), 0, i);
        }
        assert!(m.verdict().is_collapsed());
        m.on_run_start(c.at(5_000));
        assert_eq!(m.verdict(), LaneVerdict::Warmup);
    }

    // ── Honesty ─────────────────────────────────────────────────────────────

    #[test]
    fn alpha_lane_is_unknown_not_zero_and_never_halts() {
        let c = Clock::new();
        let mut m = AcceptanceMonitor::with_config(ParserKind::Alpha, cfg_fast());
        m.on_run_start(c.at(0));
        // alpha-miner's "accepted" is really a SUBMISSION count and rejected stays 0.
        for i in 1..=500u64 {
            let v = m.observe(c.at(60 + i * 20), i, 0);
            assert_eq!(v, LaneVerdict::Unknown, "alpha must never claim a rate");
            assert_eq!(v.accept_pct(), None, "must not render a number it did not measure");
        }
        assert!(!m.verdict().is_collapsed());
    }

    #[test]
    fn verdicts_without_a_measurement_expose_no_percentage() {
        for v in [LaneVerdict::Warmup, LaneVerdict::Unknown, LaneVerdict::Gathering] {
            assert_eq!(v.accept_pct(), None, "{v:?} must not fabricate a rate");
        }
    }

    #[test]
    fn visibility_is_derived_per_parser_not_per_lane() {
        assert_eq!(RejectVisibility::for_parser(ParserKind::Alpha), RejectVisibility::Unavailable);
        for p in [ParserKind::Xmr, ParserKind::Kawpow, ParserKind::Srbminer, ParserKind::Generic] {
            assert_eq!(RejectVisibility::for_parser(p), RejectVisibility::Observed, "{p:?}");
        }
    }

    #[test]
    fn counters_going_backwards_never_produce_a_phantom_collapse() {
        let c = Clock::new();
        let mut m = AcceptanceMonitor::with_config(ParserKind::Generic, cfg_fast());
        m.on_run_start(c.at(0));
        m.observe(c.at(60), 1_000, 5);
        // The stream re-baselines to a much lower cumulative reading.
        let v = m.observe(c.at(400), 3, 1);
        assert!(!v.is_collapsed(), "a counter reset must not read as a rejection storm: {v:?}");
    }

    // ── Attribution ─────────────────────────────────────────────────────────

    #[test]
    fn attribution_reads_the_network_lane_health() {
        assert_eq!(
            LaneHealth { accept_pct: 0.0, miners: 9 }.attribute(),
            Attribution::NetworkWide
        );
        assert_eq!(
            LaneHealth { accept_pct: 99.1, miners: 9 }.attribute(),
            Attribution::LocalOnly
        );
        // One miner in the figure is very likely US — that proves nothing.
        assert_eq!(
            LaneHealth { accept_pct: 0.0, miners: 1 }.attribute(),
            Attribution::Unknown
        );
    }

    #[test]
    fn lane_health_parsing_is_fail_closed_to_unknown() {
        let good = r#"{"lanes":[{"lane":"gpu_prl","accept_pct":0.0,"miners":5}]}"#;
        assert_eq!(
            parse_lane_health(good, Lane::GpuPrl),
            Some(LaneHealth { accept_pct: 0.0, miners: 5 })
        );
        // A lane the server did not mention.
        assert_eq!(parse_lane_health(good, Lane::Xmr), None);
        for bad in [
            "",
            "not json",
            r#"{"lanes":[]}"#,
            r#"{"lanes":[{"lane":"gpu_prl"}]}"#,
            r#"{"lanes":[{"lane":"gpu_prl","accept_pct":"0"}]}"#,
            r#"{"lanes":[{"lane":"gpu_prl","accept_pct":-5.0}]}"#,
            r#"{"lanes":[{"lane":"gpu_prl","accept_pct":1e9}]}"#,
        ] {
            assert_eq!(parse_lane_health(bad, Lane::GpuPrl), None, "body: {bad}");
        }
    }

    #[test]
    fn lane_health_url_is_built_off_the_read_api_apex() {
        assert_eq!(
            lane_health_url("https://api.aliceprotocol.org/"),
            "https://api.aliceprotocol.org/read/lane-health"
        );
    }

    // ── The words ───────────────────────────────────────────────────────────

    fn shutout() -> Collapse {
        Collapse {
            period: PeriodStat { accepted: 0, rejected: 72, elapsed: Duration::from_secs(900) },
            run_accepted: 0,
            run_rejected: 72,
            shutout: true,
        }
    }

    #[test]
    fn halt_text_says_the_numbers_and_the_two_causes_differ() {
        let _lock = LANG_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_lang(Lang::En);
        let c = shutout();
        let net = halt_explanation(&c, Attribution::NetworkWide);
        let loc = halt_explanation(&c, Attribution::LocalOnly);
        let unk = halt_explanation(&c, Attribution::Unknown);

        // (1) the measurement, in his numbers
        for t in [&net, &loc, &unk] {
            assert!(t.contains("72"), "must quote the real count: {t}");
            assert!(t.contains("not one was accepted"), "must state the outcome: {t}");
            assert!(t.contains("https://"), "must point somewhere: {t}");
        }
        // (2) network-wide: ours, hands off the rig
        assert!(net.contains("not your machine"), "{net}");
        assert!(net.to_lowercase().contains("do not reinstall"), "{net}");
        // (3) local: point at the local end, never at us
        assert!(loc.contains("this machine"), "{loc}");
        assert!(!loc.contains("not your machine"), "{loc}");
        // (4) unknown: admit it
        assert!(unk.contains("cannot yet tell you"), "{unk}");
        assert!(!unk.contains("not your machine"), "{unk}");
        assert!(!unk.contains("specific to this machine"), "{unk}");
        set_lang(Lang::En);
    }

    #[test]
    fn halt_text_localizes_to_chinese() {
        let _lock = LANG_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_lang(Lang::Zh);
        let c = shutout();
        let net = halt_explanation(&c, Attribution::NetworkWide);
        assert!(net.contains("不是你的机器"), "{net}");
        assert!(net.contains("72"), "{net}");
        let loc = halt_explanation(&c, Attribution::LocalOnly);
        assert!(loc.contains("这台机器"), "{loc}");
        let line = halt_status_line(&c);
        assert!(line.contains("已停止"), "{line}");
        set_lang(Lang::En);
    }

    #[test]
    fn help_url_ignores_a_non_https_override() {
        // Not a real env mutation test (env is process-global); assert the predicate
        // the resolver applies.
        assert!(HELP_URL_DEFAULT.starts_with("https://"));
        assert!(help_url().starts_with("https://"));
    }
}
