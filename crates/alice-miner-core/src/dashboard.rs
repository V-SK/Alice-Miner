//! `core/dashboard` — the local dashboard DATA MODEL (M5), with **two clearly
//! separated sources** so the UI can never blur "what the miner is doing
//! locally" with "what the server has confirmed", and never fabricates an
//! earnings figure.
//!
//! ── The two sources (PLAN §5 M5, §6 D-credit-read / D-no-projection) ─────────
//!
//! * **Source A — live local *activity*** ([`LocalActivity`]): derived ~250ms
//!   from the [`crate::engine::Snapshot`] (which is itself the LaneSupervisor
//!   snapshots). Hashrate + sparkline + accepted/rejected + accepted% + per-lane
//!   rows + uptime + connection + failover. This is **what the miner is doing**,
//!   NOT earnings — every label says *activity*.
//! * **Source B — server-confirmed *credit*** ([`CreditState`]): a read-only,
//!   polled view of credit the SERVER has confirmed for this address. It is
//!   credit-only by type ([`CreditScore`] has **no fiat / payout `Display`**),
//!   and any response whose envelope's `paid_acu != "0"` is treated as a fault:
//!   the value is **dropped** and the state flips to [`CreditState::Error`] (the
//!   #18 red-team "fabricated / leaked payout" guard, enforced in code + tested).
//!
//! ── Source-B transport decision (investigated 2026-06-03) ────────────────────
//! There is **no reachable public, address-keyed credit endpoint today**:
//!
//! * `api.aliceprotocol.org` (the base the website's `miner-dashboard.html`
//!   targets) is **NXDOMAIN**; that page ships `USE_LIVE_API:false` ("keep false
//!   until the public /read API is deployed + DNS is live"); its read-model
//!   contract is `source: 'local_fixture_only' / placeholder_contract_only`.
//! * The ACP `/shadow/balance` endpoint is keyed by `passport_id`+`device_id`
//!   (device-enrollment identity, **not** the Alice address) and is gated
//!   `localhost_only` / operator-scope — an internal endpoint, not a clean
//!   public per-address one (PLAN §3 reuse-map row + §6 D-credit-read).
//!
//! So v1 ships **Option 3 / [`CreditState::NotExposed`]** — an honest "credit
//! accounting is live; payout is OFF (phase-J); your per-address total isn't
//! exposed here yet" panel with an explorer deep-link, **zero server dependency,
//! no fabricated number**. The [`PoolStatsClient`] parser ([`parse_credit_envelope`])
//! is implemented + tested against the website's documented `alice-read-model-v2`
//! envelope so the fast-follow (Option 1) is a *flip* of which `CreditState` the
//! poller yields, not a rewrite — and so the `paid_acu != "0"` drop is proven now.
//!
//! **`evaluate_reward_projection` is intentionally NOT ported** (no estimated /
//! fabricated earnings — the #18 red-team trap). Estimated rewards stays "pending".

#![allow(dead_code)]

use std::collections::VecDeque;
use std::io::Read as _;

use serde::{Deserialize, Serialize};

use crate::engine::{EngineState, Snapshot};
use crate::lane::Lane;

// ─────────────────────────────────────────────────────────────────────────────
// Source A — live local ACTIVITY (from the Snapshot / LaneSupervisor stats).
// ─────────────────────────────────────────────────────────────────────────────

/// One lane's local activity row (Source A). Activity figures only — there is no
/// reward/payout field here by construction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LaneActivity {
    pub lane: Lane,
    pub state: EngineState,
    /// Live hashrate in H/s (`None` until the first parsed speed line).
    pub hashrate_hs: Option<f64>,
    pub shares_accepted: u64,
    pub shares_rejected: u64,
    /// This lane's ACTIVE (post-failover) PUBLIC relay endpoint.
    pub endpoint: Option<String>,
    pub failovers: u64,
}

/// **Source A** — the live, local *activity* the miner is producing right now,
/// distilled from the engine [`Snapshot`] (the LaneSupervisor stats). Everything
/// here is "what the miner is doing locally", explicitly NOT earnings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocalActivity {
    pub state: EngineState,
    pub lane: Option<Lane>,
    /// Combined live hashrate in H/s (the snapshot's top-level / summed value).
    pub hashrate_hs: Option<f64>,
    pub shares_accepted: u64,
    pub shares_rejected: u64,
    /// The ACTIVE PUBLIC relay endpoint (post-failover). Never the upstream pool /
    /// collection address (those never reach the client).
    pub endpoint: Option<String>,
    pub worker_id: Option<String>,
    pub uptime_s: u64,
    pub failovers: u64,
    pub dual: bool,
    pub lanes: Vec<LaneActivity>,
}

impl LocalActivity {
    /// Build Source A from the latest engine [`Snapshot`]. Pure mapping — no
    /// network, no reward math.
    pub fn from_snapshot(s: &Snapshot) -> Self {
        Self {
            state: s.state,
            lane: s.lane,
            hashrate_hs: s.hashrate_hs,
            shares_accepted: s.shares_accepted,
            shares_rejected: s.shares_rejected,
            endpoint: s.endpoint.clone(),
            worker_id: s.worker_id.clone(),
            uptime_s: s.uptime_s,
            failovers: s.failovers,
            dual: s.dual,
            lanes: s
                .lanes
                .iter()
                .map(|l| LaneActivity {
                    lane: l.lane,
                    state: l.state,
                    hashrate_hs: l.hashrate_hs,
                    shares_accepted: l.shares_accepted,
                    shares_rejected: l.shares_rejected,
                    endpoint: l.endpoint.clone(),
                    failovers: l.failovers,
                })
                .collect(),
        }
    }

    /// An idle Source A (no run yet).
    pub fn idle() -> Self {
        Self {
            state: EngineState::Idle,
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
        }
    }

    /// Total shares submitted this run (accepted + rejected).
    pub fn shares_total(&self) -> u64 {
        self.shares_accepted + self.shares_rejected
    }

    /// Accepted ratio in `0..=1` (`None` until at least one share is submitted).
    pub fn accepted_ratio(&self) -> Option<f64> {
        let total = self.shares_total();
        if total == 0 {
            None
        } else {
            Some(self.shares_accepted as f64 / total as f64)
        }
    }

    /// Whether the miner is actively producing work locally (Running).
    pub fn is_active(&self) -> bool {
        self.state == EngineState::Running
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Source B — server-confirmed CREDIT (credit-only by type).
// ─────────────────────────────────────────────────────────────────────────────

/// A server-confirmed credit **score** — an opaque, credit-only quantity.
///
/// **HARD INVARIANT (type-enforced):** this newtype deliberately has **NO
/// `Display`** and exposes no fiat/payout conversion. It cannot be formatted as
/// money, "credit-as-cash", "paid", or "earned"; the only renderable form is the
/// honest, neutral [`Self::pending_label`] ("server-confirmed · pending"). The
/// raw magnitude is reachable only via [`Self::raw`] for tests / future
/// qualitative use — never wired to a `$`/fiat string (PLAN §7 fabricated-earnings
/// mitigation, the #18 red-team guard).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CreditScore(f64);

impl CreditScore {
    /// Wrap a raw confirmed-credit magnitude. Negative inputs are clamped to 0
    /// (a confirmed credit score is never negative).
    pub fn new(raw: f64) -> Self {
        Self(if raw.is_finite() && raw > 0.0 { raw } else { 0.0 })
    }

    /// The raw magnitude — for tests / qualitative reconciliation ONLY. NEVER
    /// render this through a fiat/`$`/"earned" string. (No `Display` impl exists
    /// precisely so a careless `format!("{score}")` cannot compile.)
    pub fn raw(self) -> f64 {
        self.0
    }

    /// Whether any credit has been confirmed (raw > 0).
    pub fn is_some_credit(self) -> bool {
        self.0 > 0.0
    }

    /// The ONLY honest way to label a confirmed score in the UI: it is credit,
    /// it is pending (payout OFF, phase-J), never a number/`$`. Bilingual.
    pub fn pending_label(self) -> &'static str {
        "server-confirmed · pending · 待发放"
    }
}

/// A per-lane cumulative accepted-share **COUNT** row (Source B), parsed from the
/// `miner-lookup` `lanes[]` breakdown. Credit-only by construction: it carries an
/// integer COUNT of accepted shares the SERVER has confirmed on this lane — never a
/// fiat / payout / `$` value (the `pending_alice`/`paid_alice` lane fields are NOT
/// read into this type). `label` is the server's display name (e.g. `"GPU · Alpha"`
/// / `"GPU · PRL"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneCredit {
    /// The server lane key (e.g. `"main_pool_gpu_alpha"`). Stable id for matching.
    pub key: String,
    /// The server display label (e.g. `"GPU · Alpha"`). Falls back to `key` if absent.
    pub label: String,
    /// Cumulative accepted-share COUNT on this lane (credit-only; never fiat).
    pub accepted: u64,
}

/// **Source B cumulative totals** — the server-confirmed accepted-share COUNTS for
/// this address, across all lanes plus the 24h window plus the per-lane breakdown.
///
/// **CREDIT-ONLY BY CONSTRUCTION:** every field is a non-negative integer COUNT of
/// accepted shares (or a per-lane breakdown of the same). There is deliberately NO
/// fiat / payout / `$` field here — the `pending_alice` / `paid_alice` summary
/// fields are intentionally NOT read into this type (they are guarded separately by
/// the envelope's `paid_acu`-zero check, and the credit-only `pending_alice` magnitude
/// is carried opaquely by [`CreditScore`], never rendered as a number). The UI renders
/// these counts directly ("N shares · GPU·Alpha M / GPU·PRL K"), which is honest:
/// they are SHARE COUNTS, not money.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CreditTotals {
    /// Cumulative accepted-share COUNT across all lanes (server-confirmed).
    pub accepted_total: u64,
    /// Accepted-share COUNT in the last 24h (server-confirmed).
    pub accepted_24h: u64,
    /// Per-lane cumulative accepted-share COUNT breakdown (display order from server).
    pub lanes: Vec<LaneCredit>,
}

impl CreditTotals {
    /// The cumulative accepted-share COUNT for a given server lane `key` (0 if the
    /// address has no confirmed shares on that lane). Used to surface the
    /// GPU·Alpha / GPU·PRL split.
    pub fn accepted_for_lane(&self, key: &str) -> u64 {
        self.lanes
            .iter()
            .find(|l| l.key == key)
            .map(|l| l.accepted)
            .unwrap_or(0)
    }

    /// Whether the server has confirmed any accepted shares at all for this address.
    pub fn has_any(&self) -> bool {
        self.accepted_total > 0 || self.lanes.iter().any(|l| l.accepted > 0)
    }
}

/// Why a [`CreditState::Error`] occurred (kept qualitative + honest; never leaks
/// a server number).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditError {
    /// The poll could not reach the endpoint (DNS / connect / timeout).
    Unreachable,
    /// The response did not parse / had no usable score field.
    Unparseable,
    /// **The envelope reported `paid_acu != "0"`.** This is a credit-only
    /// violation: the value is DROPPED and we surface an error rather than ever
    /// show a non-zero payout figure (the #18 red-team guard).
    PaidAcuNotZero,
}

impl CreditError {
    /// An honest, calm, NON-numeric UI message for this error.
    pub fn message(&self) -> &'static str {
        match self {
            CreditError::Unreachable => "couldn't reach the credit service · 待确认",
            CreditError::Unparseable => "credit response unavailable · 待确认",
            // Deliberately neutral — we never hint at the dropped number.
            CreditError::PaidAcuNotZero => "credit response withheld (payout is off) · 待确认",
        }
    }
}

/// **Source B** — the read-only, server-confirmed credit view for the active
/// address. Credit-only by construction. The [`Default`] is [`Self::NotExposed`]
/// — the investigated v1 reality (no reachable public per-address endpoint).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CreditState {
    /// **Option 3 (the v1 path, the default).** No reachable public per-address
    /// credit endpoint exists; we honestly state that credit accounting is live,
    /// payout is OFF (phase-J), and the per-address total isn't exposed to the
    /// client yet — pointing the user at the explorer. Zero server dependency, no
    /// fabricated number.
    #[default]
    NotExposed,
    /// We have an active Source-B poll in flight / no confirmation yet.
    Confirming,
    /// The server confirmed credit for this address (Option 1 — the live path now
    /// that a public per-address endpoint exists). The `score` is the credit-only
    /// `pending_alice` magnitude ([`CreditScore`] has no fiat Display); `totals`
    /// carries the server-confirmed cumulative accepted-share COUNTS (across lanes +
    /// 24h + per-lane breakdown). Reached only after the envelope's `paid_acu` was
    /// verified `"0"` and the payout/live-reward gates read off.
    Confirmed {
        score: CreditScore,
        totals: CreditTotals,
    },
    /// A poll failed (unreachable / unparseable / **paid_acu != "0"** → value
    /// dropped). The UI shows a calm, non-numeric note and keeps Source A as the
    /// live UX.
    Error { reason: CreditError },
}

impl CreditState {
    /// Whether this state carries a confirmed, non-zero credit score OR any
    /// server-confirmed accepted shares (the cumulative COUNT view). True whenever
    /// the server has confirmed *something* for this address.
    pub fn has_confirmed_credit(&self) -> bool {
        matches!(
            self,
            CreditState::Confirmed { score, totals }
                if score.is_some_credit() || totals.has_any()
        )
    }

    /// The server-confirmed cumulative accepted-share COUNTS, when in the `Confirmed`
    /// state (credit-only — counts, never fiat). `None` for every other state so the
    /// UI shows an honest "—"/"syncing" rather than a fabricated 0.
    pub fn totals(&self) -> Option<&CreditTotals> {
        match self {
            CreditState::Confirmed { totals, .. } => Some(totals),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The PUBLIC read-model envelope (alice-read-model-v2) + its credit-only parser.
//
// This is the EXACT field set the website's miner-dashboard.html documents the
// live `${API_BASE}/miner-lookup?address=` endpoint returns (the `paid_acu`,
// `live_reward_enabled`, `payout_executor_enabled`, `found` envelope). Wiring the
// parser now — even though the live `CreditState` ships `NotExposed` — means the
// fast-follow is a flip of which state the poller yields, and proves the
// `paid_acu != "0"` DROP today (the milestone's "parse test on a sample response").
// ─────────────────────────────────────────────────────────────────────────────

/// Server lane key for the GPU · PRL (pearlhash) pool. Mirrors the acp read_api's
/// `MAIN_POOL_GPU_PRL` so the client can pull the per-lane share split.
pub const LANE_KEY_GPU_PRL: &str = "main_pool_gpu_prl";
/// Server lane key for the GPU · Alpha (AlphaPool pearlhash) pool — the NEW lane the
/// read_api exposes alongside GPU · PRL. Mirrors `MAIN_POOL_GPU_ALPHA`.
pub const LANE_KEY_GPU_ALPHA: &str = "main_pool_gpu_alpha";

/// The credit-bearing part of an `alice-read-model-v2` `miner-lookup` response.
/// Only the fields Source B needs: the credit-only envelope guards + the
/// confirmed score (`summary.pending_alice`, carried opaquely) + the cumulative
/// accepted-share COUNTS (`summary.accepted_shares_total` / `_24h` + the per-lane
/// `lanes[]` breakdown). Unknown fields are ignored (the live payload carries much
/// more — timeseries, workers, payout_history, etc.).
#[derive(Debug, Clone, Deserialize)]
pub struct CreditEnvelope {
    /// `paid_acu` MUST be the string `"0"`; anything else is a credit-only
    /// violation handled by [`parse_credit_envelope`] (value dropped → error).
    #[serde(default)]
    pub paid_acu: Option<String>,
    /// Payout executor must stay disabled (phase-J). Defaults to `false` (absent =
    /// off) — a `true` is treated as a violation.
    #[serde(default)]
    pub payout_executor_enabled: bool,
    /// Live reward must stay disabled (phase-J). Same treatment as above.
    #[serde(default)]
    pub live_reward_enabled: bool,
    /// Whether the address was found at all.
    #[serde(default)]
    pub found: bool,
    /// The credit-side summary (pending credit total + cumulative COUNTS). Optional.
    #[serde(default)]
    pub summary: Option<CreditSummary>,
    /// The per-lane cumulative accepted-share COUNT breakdown. Optional / fail-closed
    /// (absent => no lane split, just the summary totals).
    #[serde(default)]
    pub lanes: Vec<LaneEnvelope>,
}

/// The credit-side summary fields of the read-model. `pending_alice` is the
/// credit accrued-but-not-paid total (phase-J keeps it as pending credit); the
/// `accepted_shares_*` are the cumulative server-confirmed COUNTS (credit-only).
#[derive(Debug, Clone, Deserialize)]
pub struct CreditSummary {
    /// Credit accrued and pending (NOT cash; never rendered as a number/`$`).
    #[serde(default)]
    pub pending_alice: Option<f64>,
    /// Cumulative accepted-share COUNT across all lanes (server-confirmed).
    #[serde(default)]
    pub accepted_shares_total: Option<u64>,
    /// Accepted-share COUNT in the last 24h (server-confirmed).
    #[serde(default)]
    pub accepted_shares_24h: Option<u64>,
}

/// One element of the read-model's `lanes[]` array — the credit-only fields the
/// client surfaces: the lane `key`, its display `label`, and the cumulative
/// `accepted` COUNT. The `pending_alice` / `paid_alice` lane fields are intentionally
/// NOT deserialized (credit-only: we surface COUNTS, never per-lane fiat).
#[derive(Debug, Clone, Deserialize)]
pub struct LaneEnvelope {
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub accepted: Option<u64>,
}

/// Parse a read-model `miner-lookup` JSON body into a [`CreditState`],
/// **enforcing the credit-only invariants in code**:
///
///   1. If the envelope's `paid_acu` is present and `!= "0"`, OR a payout/live
///      reward gate reads `true`, the response is a credit-only violation: the
///      score is **DROPPED** and we return [`CreditState::Error`] with
///      [`CreditError::PaidAcuNotZero`] — we NEVER surface the value.
///   2. A missing/`null` `paid_acu` is treated as the safe `"0"` (absence = off).
///   3. `found: false` → [`CreditState::Confirming`] (the address simply has no
///      confirmation yet — not an error).
///   4. Otherwise the credit-only `pending_alice` becomes a [`CreditScore`].
///
/// This is the function the fast-follow [`PoolStatsClient`] would call on each
/// poll; today it is exercised by tests + ready for the live flip.
pub fn parse_credit_envelope(body: &str) -> CreditState {
    let env: CreditEnvelope = match serde_json::from_str(body) {
        Ok(e) => e,
        Err(_) => return CreditState::Error { reason: CreditError::Unparseable },
    };
    // (1) Credit-only gate: paid_acu must read "0"; payout/live-reward must be off.
    // ANY of these failing → DROP the value, surface an error. This is the single
    // most important line of the milestone (the fabricated/leaked-payout guard).
    let paid_acu_ok = match env.paid_acu.as_deref() {
        // Absent → treated as "0" (fail-safe: absence = off).
        None => true,
        Some(s) => s.trim() == "0",
    };
    if !paid_acu_ok || env.payout_executor_enabled || env.live_reward_enabled {
        return CreditState::Error { reason: CreditError::PaidAcuNotZero };
    }
    // (3) Not found yet → just "confirming" (no error, no number). A MISSING/absent
    // address is "confirming", NOT a fabricated zero — the UI shows "syncing", never 0.
    if !env.found {
        return CreditState::Confirming;
    }
    // (4) The confirmed state. The credit-only score (pending credit magnitude) is
    // carried opaquely via CreditScore (no fiat Display); the cumulative accepted-share
    // COUNTS (total / 24h / per-lane) are surfaced directly as COUNTS. Absent summary
    // → 0 counts (a perfectly valid confirmed-but-zero state — a REAL server 0).
    let summary = env.summary;
    let raw = summary.as_ref().and_then(|s| s.pending_alice).unwrap_or(0.0);
    let accepted_total = summary
        .as_ref()
        .and_then(|s| s.accepted_shares_total)
        .unwrap_or(0);
    let accepted_24h = summary
        .as_ref()
        .and_then(|s| s.accepted_shares_24h)
        .unwrap_or(0);
    let lanes: Vec<LaneCredit> = env
        .lanes
        .into_iter()
        .filter_map(|l| {
            // Require a key (the stable id) and an accepted count; a lane row with no
            // key/accepted is dropped (we never fabricate a lane).
            let key = l.key?;
            let accepted = l.accepted.unwrap_or(0);
            let label = l.label.unwrap_or_else(|| key.clone());
            Some(LaneCredit { key, label, accepted })
        })
        .collect();
    CreditState::Confirmed {
        score: CreditScore::new(raw),
        totals: CreditTotals { accepted_total, accepted_24h, lanes },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PoolStatsClient — the Source-B poll *discipline* (30–60s, jitter, single-flight,
// backoff). v1 is configured `NotExposed` (no reachable public per-address
// endpoint), so it yields `NotExposed` WITHOUT any network call (zero server
// dependency). The discipline + parser are wired so the fast-follow to a live
// endpoint (Option 1) is a config flip, not a rewrite.
// ─────────────────────────────────────────────────────────────────────────────

/// The DEFAULT public read-API base for Source B. The acp central `read_api` serves
/// `GET {base}/read/miner-lookup?address=<alice>` (PUBLIC, read-only, no-auth,
/// credit-only — every payload asserts `paid_acu == "0"`). This is a clearly-marked
/// CONFIGURABLE DEFAULT: the EXACT production host is confirmed by the human at
/// deploy and is trivially overridden by [`ENV_READ_API_URL`] without a rebuild.
//
// NOTE(deploy): leave this as the public apex; the human confirms/wires the real
// production read-API URL at deploy time (env override or a one-line change here).
pub const READ_API_BASE_DEFAULT: &str = "https://api.aliceprotocol.org";

/// Env override for the read-API base (test/ops/deploy). When set & non-empty it
/// REPLACES [`READ_API_BASE_DEFAULT`]; still required to be `https://`.
pub const ENV_READ_API_URL: &str = "ALICE_READ_API_URL";

/// Connect + read timeout for the Source-B credit GET (~10 s, mirrors `pop.rs`).
const CREDIT_HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Upper bound on the read-API response body. A `miner-lookup` payload is a few KiB;
/// 256 KiB is generous (it carries timeseries/workers) yet caps a hostile response.
const CREDIT_MAX_RESPONSE_BYTES: u64 = 256 * 1024;

/// The base poll interval for Source B (PLAN §5 M5: "read-only poll, 30–60s").
pub const CREDIT_POLL_BASE_SECS: u64 = 30;
/// The jitter window added on top of the base so many clients don't poll in
/// lockstep (PLAN §5 M5: "with jitter").
pub const CREDIT_POLL_JITTER_SECS: u64 = 30;
/// The maximum backoff between polls after repeated failures (caps the
/// exponential backoff so a long outage settles to one poll/5 min, not silence).
pub const CREDIT_POLL_MAX_BACKOFF_SECS: u64 = 300;

/// How Source B is sourced. v1 is [`Self::NotExposed`] (the investigated reality);
/// [`Self::PublicReadModel`] is the fast-follow once a public, address-keyed
/// `miner-lookup` endpoint is actually deployed + reachable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreditSource {
    /// No reachable public per-address credit endpoint — ship the honest
    /// `NotExposed` panel, never poll the network.
    NotExposed,
    /// A reachable public read-model base (e.g. `https://api.aliceprotocol.org/read`);
    /// the client GETs `{base}/miner-lookup?address=<addr>` and parses the
    /// credit-only envelope via [`parse_credit_envelope`]. **Not used in v1** (the
    /// base is NXDOMAIN today); present so the flip is one line.
    PublicReadModel { base: String },
}

/// The Source-B credit poller. Holds the poll *discipline* (cadence + jitter +
/// single-flight + backoff) and the source config. It does NOT itself perform
/// network I/O here (the engine/GUI owns the actual transport when a live
/// endpoint exists); this type decides *whether* a poll is due and *what state*
/// to surface, so the policy is unit-testable without a network.
#[derive(Debug, Clone)]
pub struct PoolStatsClient {
    source: CreditSource,
    /// Single-flight guard: only one poll in flight at a time.
    in_flight: bool,
    /// Consecutive failures (drives exponential backoff).
    consecutive_failures: u32,
    /// The last state we resolved (so a transient miss keeps the last good view
    /// until the next success, rather than flickering).
    last_state: CreditState,
}

impl PoolStatsClient {
    /// A client in the v1 `NotExposed` configuration (no network, honest panel).
    pub fn not_exposed() -> Self {
        Self {
            source: CreditSource::NotExposed,
            in_flight: false,
            consecutive_failures: 0,
            last_state: CreditState::NotExposed,
        }
    }

    /// A client pointed at a live public read-model base (the live path). The `base`
    /// is the API apex (e.g. `https://api.aliceprotocol.org`); the client GETs
    /// `{base}/read/miner-lookup?address=<addr>`.
    pub fn public_read_model(base: impl Into<String>) -> Self {
        Self {
            source: CreditSource::PublicReadModel { base: base.into() },
            in_flight: false,
            consecutive_failures: 0,
            last_state: CreditState::Confirming,
        }
    }

    /// The production client: the read-API base from [`ENV_READ_API_URL`] (if set &
    /// non-empty) else [`READ_API_BASE_DEFAULT`]. This is what the front-ends use so
    /// the cumulative credit view is live; the exact host is a CONFIGURABLE DEFAULT
    /// the human confirms at deploy (env override needs no rebuild).
    pub fn public_default() -> Self {
        let base = std::env::var(ENV_READ_API_URL)
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| READ_API_BASE_DEFAULT.to_string());
        Self::public_read_model(base)
    }

    /// The URL this client GETs for `address`. Returns `None` in the `NotExposed`
    /// configuration (nothing to fetch). The path is the read-API contract path
    /// `/read/miner-lookup?address=` (percent-encoded address).
    pub fn lookup_url(&self, address: &str) -> Option<String> {
        match &self.source {
            CreditSource::NotExposed => None,
            CreditSource::PublicReadModel { base } => {
                let base = base.trim_end_matches('/');
                Some(format!(
                    "{base}/read/miner-lookup?address={}",
                    urlencode(address)
                ))
            }
        }
    }

    /// Whether this client ever polls the network (false for `NotExposed`).
    pub fn polls_network(&self) -> bool {
        matches!(self.source, CreditSource::PublicReadModel { .. })
    }

    /// The interval until the next poll, given `elapsed_since_last` and a `jitter`
    /// value in `0.0..=1.0` (the caller supplies the randomness so this stays
    /// pure/testable). Applies exponential backoff after failures, capped at
    /// [`CREDIT_POLL_MAX_BACKOFF_SECS`]. `NotExposed` never polls → returns `None`.
    pub fn next_poll_in_secs(&self, jitter: f64) -> Option<u64> {
        if !self.polls_network() {
            return None;
        }
        let jitter = jitter.clamp(0.0, 1.0);
        let base = CREDIT_POLL_BASE_SECS as f64 + jitter * CREDIT_POLL_JITTER_SECS as f64;
        // Exponential backoff: ×2 per consecutive failure, capped.
        let backoff_mult = 2f64.powi(self.consecutive_failures.min(8) as i32);
        let secs = (base * backoff_mult).min(CREDIT_POLL_MAX_BACKOFF_SECS as f64);
        Some(secs as u64)
    }

    /// Begin a poll (single-flight): returns `false` if one is already in flight
    /// (caller skips) or the source never polls. On `true` the caller performs the
    /// GET + calls [`Self::complete`] / [`Self::fail`].
    pub fn begin_poll(&mut self) -> bool {
        if self.in_flight || !self.polls_network() {
            return false;
        }
        self.in_flight = true;
        true
    }

    /// Complete a poll with a fetched body: parse it (credit-only guards apply),
    /// clear single-flight, reset backoff on success, and store the resolved state.
    pub fn complete(&mut self, body: &str) -> CreditState {
        self.in_flight = false;
        let state = parse_credit_envelope(body);
        match &state {
            // A credit-only violation or unparseable body counts as a failure for
            // backoff purposes (we keep trying, slower) but the surfaced state is
            // the honest error, not a stale value.
            CreditState::Error { .. } => self.consecutive_failures = self.consecutive_failures.saturating_add(1),
            _ => self.consecutive_failures = 0,
        }
        self.last_state = state.clone();
        state
    }

    /// Mark a poll as failed at the transport layer (DNS/connect/timeout): clear
    /// single-flight, bump backoff, surface `Error(Unreachable)`.
    pub fn fail(&mut self) -> CreditState {
        self.in_flight = false;
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let state = CreditState::Error { reason: CreditError::Unreachable };
        self.last_state = state.clone();
        state
    }

    /// Perform ONE real, best-effort, read-only credit poll for `address` (the live
    /// Source-B transport). Single-flight (returns the current state without a fetch
    /// if a poll is already in flight or the source never polls); off the mining hot
    /// path; ~10 s timeout; small read cap. A reachable, clean envelope is parsed via
    /// [`parse_credit_envelope`] (so the `paid_acu != "0"` DROP guard applies); a
    /// transport failure surfaces `Error(Unreachable)`. NEVER panics, never blocks
    /// the engine, never fabricates a value.
    ///
    /// Returns the resolved [`CreditState`] (also stored as `last_state`). A
    /// watch-only / pasted address is fine here: the read API only needs the public
    /// address to look up confirmed credit (no signing key required).
    pub fn poll(&mut self, address: &str) -> CreditState {
        if !self.begin_poll() {
            // Already in flight, or NotExposed — surface the current best-known view.
            return self.state();
        }
        let Some(url) = self.lookup_url(address) else {
            // Shouldn't happen (begin_poll gated on polls_network), but fail-closed.
            return self.fail();
        };
        match http_get_credit(&url) {
            Ok(body) => self.complete(&body),
            Err(_) => self.fail(),
        }
    }

    /// The current best-known credit state (for the UI between polls).
    pub fn state(&self) -> CreditState {
        self.last_state.clone()
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    pub fn is_in_flight(&self) -> bool {
        self.in_flight
    }
}

impl Default for PoolStatsClient {
    fn default() -> Self {
        // The investigated v1 reality: no public per-address endpoint.
        Self::not_exposed()
    }
}

/// Minimal percent-encoding for the address query param (alphanumerics + a few
/// safe chars pass through; everything else is `%XX`). Avoids a url crate dep for
/// the one query param Source B needs.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Read-only HTTPS GET of the public read-API `miner-lookup` URL, returning the
/// (capped) response body. Mirrors `pop.rs`'s ureq discipline: an https-only guard,
/// a ~10 s connect+read timeout, and a small read cap on the body. NO auth header,
/// NO secret, NO body — a plain public read. Any non-https URL, transport error, or
/// non-2xx status is an `Err` (the caller surfaces `Error(Unreachable)`); we never
/// panic and never block the mining hot path (the caller runs this off-thread).
fn http_get_credit(url: &str) -> Result<String, String> {
    // Fail closed on a non-https url (a credit lookup must never cross the wire in
    // the clear). A misconfigured ALICE_READ_API_URL can otherwise sneak http in.
    if !url.starts_with("https://") {
        return Err(format!("refusing non-https read-api url: {url}"));
    }
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(CREDIT_HTTP_TIMEOUT)
        .timeout_read(CREDIT_HTTP_TIMEOUT)
        .user_agent(concat!("alice-miner-credit/", env!("CARGO_PKG_VERSION")))
        .build();
    let resp = agent
        .get(url)
        .call()
        .map_err(|e| format!("GET {url}: {e}"))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .take(CREDIT_MAX_RESPONSE_BYTES)
        .read_to_end(&mut buf)
        .map_err(|e| format!("read {url}: {e}"))?;
    String::from_utf8(buf).map_err(|e| format!("utf8 {url}: {e}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Reconciliation — a QUALITATIVE badge (local activity vs server-confirmed).
// No fabricated numbers, no "X% confirmed" — only a small honest status word.
// ─────────────────────────────────────────────────────────────────────────────

/// A qualitative reconciliation badge between Source A (local activity) and
/// Source B (server-confirmed credit). Intentionally word-only — it NEVER claims
/// a number, a percentage, or an amount.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reconciliation {
    /// Not mining locally and nothing to reconcile.
    Idle,
    /// Mining locally; the per-address credit total isn't exposed to the client,
    /// so we can't reconcile a number — only state that activity is flowing and
    /// accounting is server-side ([`CreditState::NotExposed`]).
    ActivityOnly,
    /// Mining locally + waiting on the first server confirmation.
    Confirming,
    /// Mining locally AND the server has confirmed credit — they agree
    /// qualitatively ("in sync").
    InSync,
    /// The server confirmed credit but the miner isn't currently producing
    /// activity (e.g. just stopped) — confirmed credit persists.
    ConfirmedIdle,
    /// A Source-B fault — we keep showing Source A and note credit is unconfirmed.
    Unconfirmed,
}

impl Reconciliation {
    /// Derive the qualitative badge from the two sources.
    pub fn derive(activity: &LocalActivity, credit: &CreditState) -> Self {
        let active = activity.is_active();
        match (active, credit) {
            (false, CreditState::Confirmed { score, totals })
                if score.is_some_credit() || totals.has_any() =>
            {
                Reconciliation::ConfirmedIdle
            }
            (false, _) => Reconciliation::Idle,
            (true, CreditState::Confirmed { score, totals })
                if score.is_some_credit() || totals.has_any() =>
            {
                Reconciliation::InSync
            }
            (true, CreditState::Confirming) => Reconciliation::Confirming,
            (true, CreditState::Error { .. }) => Reconciliation::Unconfirmed,
            // Confirmed-but-zero, or NotExposed, while active → activity is flowing
            // but there's no server number to reconcile against.
            (true, _) => Reconciliation::ActivityOnly,
        }
    }

    /// A short, honest, bilingual badge label.
    pub fn label(self) -> &'static str {
        match self {
            Reconciliation::Idle => "idle · 空闲",
            Reconciliation::ActivityOnly => "activity flowing · 计入中",
            Reconciliation::Confirming => "confirming… · 确认中",
            Reconciliation::InSync => "in sync · 已同步",
            Reconciliation::ConfirmedIdle => "confirmed · 已确认",
            Reconciliation::Unconfirmed => "unconfirmed · 待确认",
        }
    }

    /// Whether this badge should read as "healthy/positive" (drives the UI tone:
    /// green for in-sync/confirmed, neutral otherwise — never red unless an error).
    pub fn is_positive(self) -> bool {
        matches!(self, Reconciliation::InSync | Reconciliation::ConfirmedIdle)
    }

    /// Whether this badge reflects a Source-B fault (drives a warn tone).
    pub fn is_warn(self) -> bool {
        matches!(self, Reconciliation::Unconfirmed)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The combined DashboardModel — Source A + Source B + reconciliation, plus the
// derived presentation helpers (sparkline, accepted%) the GUI reads.
// ─────────────────────────────────────────────────────────────────────────────

/// How many hashrate samples the 60s sparkline keeps (~1/s for ~60s; we keep a
/// few extra so a slightly faster cadence still spans a full minute on screen).
pub const SPARK_CAP: usize = 64;

/// The full local dashboard model (M5): the two clearly-separated sources + the
/// qualitative reconciliation badge. The GUI builds one of these per frame from
/// the latest [`Snapshot`] (Source A) + the poller's [`CreditState`] (Source B);
/// the headless CLI can build the same for `status`. No reward projection, ever.
#[derive(Debug, Clone, PartialEq)]
pub struct DashboardModel {
    /// Source A — live local activity (NOT earnings).
    pub activity: LocalActivity,
    /// Source B — server-confirmed credit (credit-only; may be `NotExposed`).
    pub credit: CreditState,
    /// The qualitative reconciliation badge (local vs server).
    pub reconciliation: Reconciliation,
}

impl DashboardModel {
    /// Build the model from Source A + Source B, deriving the reconciliation.
    pub fn new(activity: LocalActivity, credit: CreditState) -> Self {
        let reconciliation = Reconciliation::derive(&activity, &credit);
        Self { activity, credit, reconciliation }
    }

    /// Convenience: build from a [`Snapshot`] (Source A) + a [`CreditState`].
    pub fn from_snapshot(snapshot: &Snapshot, credit: CreditState) -> Self {
        Self::new(LocalActivity::from_snapshot(snapshot), credit)
    }

    /// An idle model (no run, default credit state).
    pub fn idle() -> Self {
        Self::new(LocalActivity::idle(), CreditState::default())
    }
}

/// A small, self-contained 60s hashrate sparkline buffer (kH/s), so the model
/// owns the activity sparkline rather than the GUI smuggling it in. (The GUI may
/// still keep its own smoothed display buffer; this is the model-level series.)
#[derive(Debug, Clone, Default)]
pub struct Sparkline {
    samples: VecDeque<f32>,
}

impl Sparkline {
    pub fn new() -> Self {
        Self { samples: VecDeque::with_capacity(SPARK_CAP) }
    }

    /// Push one sample (kH/s), evicting the oldest beyond [`SPARK_CAP`].
    pub fn push(&mut self, khs: f32) {
        self.samples.push_back(khs.max(0.0));
        while self.samples.len() > SPARK_CAP {
            self.samples.pop_front();
        }
    }

    pub fn as_slice_vec(&self) -> Vec<f32> {
        self.samples.iter().copied().collect()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{LaneSnapshot, Snapshot};

    fn running_snapshot() -> Snapshot {
        Snapshot {
            state: EngineState::Running,
            device: None,
            lane: Some(Lane::Xmr),
            hashrate_hs: Some(8_400.0),
            hashrate_60s_hs: None,
            hashrate_15m_hs: None,
            shares_accepted: 142,
            shares_rejected: 1,
            endpoint: Some("hk.aliceprotocol.org:3333".into()),
            worker_id: Some("rig-7f3a9c21".into()),
            uptime_s: 1234,
            failovers: 0,
            dual: false,
            lanes: vec![LaneSnapshot {
                lane: Lane::Xmr,
                state: EngineState::Running,
                hashrate_hs: Some(8_400.0),
                hashrate_60s_hs: None,
                hashrate_15m_hs: None,
                shares_accepted: 142,
                shares_rejected: 1,
                uptime_s: 1234,
                endpoint: Some("hk.aliceprotocol.org:3333".into()),
                failovers: 0,
            }],
            last_line: Some("accepted (142/1)".into()),
            message: None,
            prl_payout: None,
        }
    }

    // ── Source A ──────────────────────────────────────────────────────────────

    #[test]
    fn source_a_maps_snapshot_and_computes_accepted_ratio() {
        let a = LocalActivity::from_snapshot(&running_snapshot());
        assert!(a.is_active());
        assert_eq!(a.shares_total(), 143);
        let ratio = a.accepted_ratio().unwrap();
        assert!((ratio - 142.0 / 143.0).abs() < 1e-9);
        assert_eq!(a.lanes.len(), 1);
        assert_eq!(a.endpoint.as_deref(), Some("hk.aliceprotocol.org:3333"));
    }

    #[test]
    fn source_a_idle_has_no_ratio() {
        let a = LocalActivity::idle();
        assert!(!a.is_active());
        assert_eq!(a.shares_total(), 0);
        assert!(a.accepted_ratio().is_none());
    }

    // ── Source B — the credit-only guards (the heart of M5) ────────────────────

    /// THE #18 RED-TEAM GUARD: a response with `paid_acu != "0"` must flip to
    /// `Error(PaidAcuNotZero)` and the value must be DROPPED (never surfaced).
    #[test]
    fn source_b_paid_acu_not_zero_flips_to_error_and_drops_value() {
        // A response that "looks credited" but reports a non-zero payout. Even
        // though it carries a juicy pending_alice, we must NOT confirm it.
        let body = r#"{
            "ok": true,
            "found": true,
            "contract_version": "alice-read-model-v2",
            "paid_acu": "12.5",
            "live_reward_enabled": false,
            "payout_executor_enabled": false,
            "summary": { "pending_alice": 999.0 }
        }"#;
        let state = parse_credit_envelope(body);
        assert_eq!(state, CreditState::Error { reason: CreditError::PaidAcuNotZero });
        // And crucially: the dropped value is NOT reachable from the state.
        assert!(!state.has_confirmed_credit());
    }

    /// A `payout_executor_enabled:true` (or `live_reward_enabled:true`) envelope is
    /// equally a credit-only violation → drop + error.
    #[test]
    fn source_b_payout_executor_on_is_a_violation() {
        for body in [
            r#"{"found":true,"paid_acu":"0","payout_executor_enabled":true,"summary":{"pending_alice":5.0}}"#,
            r#"{"found":true,"paid_acu":"0","live_reward_enabled":true,"summary":{"pending_alice":5.0}}"#,
        ] {
            let state = parse_credit_envelope(body);
            assert_eq!(
                state,
                CreditState::Error { reason: CreditError::PaidAcuNotZero },
                "a live payout/reward gate must drop the value: {body}"
            );
        }
    }

    /// A clean `paid_acu:"0"`, found, phase-J envelope parses to a credit-only
    /// `Confirmed` score (this is the documented `alice-read-model-v2` shape from
    /// the website's miner-dashboard.html fixture).
    #[test]
    fn source_b_parses_clean_read_model_v2_envelope() {
        // The exact shape the website documents for the live miner-lookup endpoint.
        let body = r#"{
            "ok": true,
            "query_address": "a2x7Kf3mNqLpV9wBcD4hJ8sR2tY6uE1nG5kM0aZ7RtY2qWp",
            "found": true,
            "contract_version": "alice-read-model-v2",
            "paid_acu": "0",
            "live_reward_enabled": false,
            "payout_executor_enabled": false,
            "chain_writes_enabled": false,
            "summary": { "pending_alice": 0.0, "accepted_shares_total": 1284902 }
        }"#;
        match parse_credit_envelope(body) {
            CreditState::Confirmed { score, totals } => {
                // pending_alice was 0.0 (phase-J normal empty state) → a valid
                // confirmed-but-zero score.
                assert_eq!(score.raw(), 0.0);
                assert!(!score.is_some_credit());
                // The cumulative accepted-share COUNT is parsed from the summary.
                assert_eq!(totals.accepted_total, 1_284_902);
            }
            other => panic!("expected Confirmed, got {other:?}"),
        }
    }

    /// A found envelope WITH a positive credit total confirms a non-zero score
    /// (still credit-only, still no fiat Display).
    #[test]
    fn source_b_confirms_positive_credit_score() {
        let body = r#"{"found":true,"paid_acu":"0","summary":{"pending_alice":12.56}}"#;
        match parse_credit_envelope(body) {
            CreditState::Confirmed { score, .. } => {
                assert!(score.is_some_credit());
                assert!((score.raw() - 12.56).abs() < 1e-9);
            }
            other => panic!("expected Confirmed, got {other:?}"),
        }
    }

    /// A CAPTURED full `/read/miner-lookup` envelope (the EXACT shape the acp
    /// `read_api._build_miner_lookup` emits: `summary.accepted_shares_{total,24h}` +
    /// the per-lane `lanes[]` breakdown incl. the NEW `main_pool_gpu_alpha` lane
    /// alongside `main_pool_gpu_prl`) parses into the cumulative COUNT model. This is
    /// the milestone's "parse a captured JSON into the credit model" proof.
    #[test]
    fn source_b_parses_cumulative_counts_and_lane_split() {
        // Trimmed but field-faithful to read_api.py's miner-lookup payload.
        let body = r#"{
            "ok": true,
            "query_address": "a2x7Kf3mNqLpV9wBcD4hJ8sR2tY6uE1nG5kM0aZ7RtY2qWp",
            "normalized_address": "a2x7Kf3mNqLpV9wBcD4hJ8sR2tY6uE1nG5kM0aZ7RtY2qWp",
            "found": true,
            "contract_version": "alice-read-model-v2",
            "read_only": true,
            "paid_acu": "0",
            "live_reward_enabled": false,
            "payout_executor_enabled": false,
            "chain_writes_enabled": false,
            "summary": {
                "hashrate_eq": "unavailable",
                "accepted_shares_total": 873,
                "accepted_shares_24h": 142,
                "pending_alice": 0.0,
                "paid_alice": 0.0,
                "workers_online": 1,
                "workers_total": 2,
                "network_share_pct": 0.42
            },
            "lanes": [
                {"key": "main_pool_gpu_alpha", "label": "GPU · Alpha", "algo": "pearlhash",
                 "hashrate": "unavailable", "accepted": 500, "rejected": 0,
                 "pending_alice": 0.0, "paid_alice": 0.0, "evidence_status": "ok"},
                {"key": "main_pool_gpu_prl", "label": "GPU · PRL", "algo": "pearlhash",
                 "hashrate": "unavailable", "accepted": 373, "rejected": 0,
                 "pending_alice": 0.0, "paid_alice": 0.0, "evidence_status": "ok"}
            ],
            "payout_history": []
        }"#;
        match parse_credit_envelope(body) {
            CreditState::Confirmed { score, totals } => {
                // phase-J: pending_alice is 0 (a real server 0, not fabricated).
                assert_eq!(score.raw(), 0.0);
                // The cumulative + 24h COUNTS are parsed verbatim.
                assert_eq!(totals.accepted_total, 873);
                assert_eq!(totals.accepted_24h, 142);
                // The per-lane breakdown carries BOTH GPU lanes with their labels.
                assert_eq!(totals.lanes.len(), 2);
                assert_eq!(totals.accepted_for_lane(LANE_KEY_GPU_ALPHA), 500);
                assert_eq!(totals.accepted_for_lane(LANE_KEY_GPU_PRL), 373);
                // 500 + 373 == 873 (the split reconciles with the total).
                assert_eq!(
                    totals.accepted_for_lane(LANE_KEY_GPU_ALPHA)
                        + totals.accepted_for_lane(LANE_KEY_GPU_PRL),
                    totals.accepted_total
                );
                // The GPU·Alpha lane keeps its display label for the UI.
                let alpha = totals
                    .lanes
                    .iter()
                    .find(|l| l.key == LANE_KEY_GPU_ALPHA)
                    .unwrap();
                assert_eq!(alpha.label, "GPU · Alpha");
                assert!(totals.has_any());
            }
            other => panic!("expected Confirmed with totals, got {other:?}"),
        }
    }

    /// A confirmed-but-zero pending score with a NON-zero accepted-share COUNT is
    /// still "credit confirmed" (the COUNT view is what the cumulative display reads).
    #[test]
    fn source_b_zero_pending_but_nonzero_count_is_confirmed_credit() {
        let body = r#"{"found":true,"paid_acu":"0",
            "summary":{"pending_alice":0.0,"accepted_shares_total":42,"accepted_shares_24h":7}}"#;
        let state = parse_credit_envelope(body);
        assert!(state.has_confirmed_credit(), "nonzero count counts as confirmed");
        let totals = state.totals().expect("Confirmed carries totals");
        assert_eq!(totals.accepted_total, 42);
        assert_eq!(totals.accepted_24h, 7);
    }

    /// THE #18 GUARD over the FULL count model: a `paid_acu != "0"` envelope that ALSO
    /// carries cumulative counts + a lane split is dropped to `Error` — the COUNTS are
    /// NOT surfaced either (the whole confirmed value, counts included, is dropped).
    #[test]
    fn source_b_paid_acu_violation_drops_counts_too() {
        let body = r#"{"found":true,"paid_acu":"3.5",
            "summary":{"pending_alice":9.0,"accepted_shares_total":1000,"accepted_shares_24h":50},
            "lanes":[{"key":"main_pool_gpu_alpha","label":"GPU · Alpha","accepted":1000}]}"#;
        let state = parse_credit_envelope(body);
        assert_eq!(state, CreditState::Error { reason: CreditError::PaidAcuNotZero });
        // The dropped counts are NOT reachable from the state (no totals on Error).
        assert!(state.totals().is_none());
        assert!(!state.has_confirmed_credit());
    }

    /// The live-default client points at the read-API `/read/miner-lookup` path and is
    /// a real network poller (not the inert NotExposed stub). The env override swaps
    /// the base with no rebuild.
    #[test]
    fn public_default_client_targets_read_miner_lookup_path() {
        // Force a known base via the env override so the test is host-independent.
        let prev = std::env::var(ENV_READ_API_URL).ok();
        std::env::set_var(ENV_READ_API_URL, "https://read.example.test");
        let c = PoolStatsClient::public_default();
        assert!(c.polls_network(), "the live default is a real poller");
        let url = c.lookup_url("a2x7Kf3mNqLpV9wBcD4hJ8sR2tY6uE1nG5kM0aZ7RtY2qWp").unwrap();
        assert_eq!(
            url,
            "https://read.example.test/read/miner-lookup?address=a2x7Kf3mNqLpV9wBcD4hJ8sR2tY6uE1nG5kM0aZ7RtY2qWp"
        );
        match prev {
            Some(v) => std::env::set_var(ENV_READ_API_URL, v),
            None => std::env::remove_var(ENV_READ_API_URL),
        }
    }

    /// `found:false` is not an error — just "confirming" (no number).
    #[test]
    fn source_b_not_found_is_confirming_not_error() {
        let body = r#"{"found":false,"paid_acu":"0"}"#;
        assert_eq!(parse_credit_envelope(body), CreditState::Confirming);
    }

    /// A missing `paid_acu` is treated as the safe `"0"` (absence = off), so a
    /// found envelope without the field still confirms (does NOT error).
    #[test]
    fn source_b_missing_paid_acu_is_safe_zero() {
        let body = r#"{"found":true,"summary":{"pending_alice":1.0}}"#;
        assert!(matches!(parse_credit_envelope(body), CreditState::Confirmed { .. }));
    }

    /// Garbage / non-JSON fails closed to an unparseable error (never a panic,
    /// never a fabricated value).
    #[test]
    fn source_b_garbage_is_unparseable() {
        assert_eq!(
            parse_credit_envelope("not json at all"),
            CreditState::Error { reason: CreditError::Unparseable }
        );
    }

    /// CreditScore is credit-only by TYPE: the only public string form is the
    /// neutral pending label — there is no fiat/`$`/"earned"/"paid" rendering, and
    /// the label itself is honest. (A compile-time guard that no `Display` exists
    /// lives in the GUI strings honesty test; here we assert the label content.)
    #[test]
    fn credit_score_pending_label_is_honest() {
        let s = CreditScore::new(12.56);
        let label = s.pending_label();
        let lower = label.to_lowercase();
        for forbidden in ["$", "usd", "paid", "earned", "已发放"] {
            assert!(!lower.contains(forbidden), "credit label leaked `{forbidden}`: {label}");
        }
        assert!(lower.contains("pending") || label.contains("待发放"));
    }

    #[test]
    fn credit_score_clamps_negative_and_nonfinite() {
        assert_eq!(CreditScore::new(-5.0).raw(), 0.0);
        assert_eq!(CreditScore::new(f64::NAN).raw(), 0.0);
        assert_eq!(CreditScore::new(f64::INFINITY).raw(), 0.0);
        assert_eq!(CreditScore::new(3.0).raw(), 3.0);
    }

    #[test]
    fn credit_state_defaults_to_not_exposed() {
        assert_eq!(CreditState::default(), CreditState::NotExposed);
    }

    // ── Reconciliation (qualitative, no numbers) ───────────────────────────────

    #[test]
    fn reconciliation_states_are_derived_correctly() {
        let active = LocalActivity::from_snapshot(&running_snapshot());
        let idle = LocalActivity::idle();

        // Active + NotExposed → activity flowing, nothing to reconcile.
        assert_eq!(
            Reconciliation::derive(&active, &CreditState::NotExposed),
            Reconciliation::ActivityOnly
        );
        // Active + Confirming → confirming.
        assert_eq!(
            Reconciliation::derive(&active, &CreditState::Confirming),
            Reconciliation::Confirming
        );
        // Active + Confirmed(nonzero) → in sync.
        assert_eq!(
            Reconciliation::derive(
                &active,
                &CreditState::Confirmed {
                    score: CreditScore::new(5.0),
                    totals: CreditTotals::default(),
                }
            ),
            Reconciliation::InSync
        );
        // Active + Error → unconfirmed (warn).
        let r = Reconciliation::derive(
            &active,
            &CreditState::Error { reason: CreditError::Unreachable },
        );
        assert_eq!(r, Reconciliation::Unconfirmed);
        assert!(r.is_warn());
        // Idle + Confirmed(nonzero) → confirmed-idle (positive, persists).
        let r = Reconciliation::derive(
            &idle,
            &CreditState::Confirmed {
                score: CreditScore::new(5.0),
                totals: CreditTotals::default(),
            },
        );
        assert_eq!(r, Reconciliation::ConfirmedIdle);
        assert!(r.is_positive());
        // Idle + anything-else → idle.
        assert_eq!(
            Reconciliation::derive(&idle, &CreditState::NotExposed),
            Reconciliation::Idle
        );
    }

    #[test]
    fn reconciliation_labels_are_honest_and_nonnumeric() {
        for r in [
            Reconciliation::Idle,
            Reconciliation::ActivityOnly,
            Reconciliation::Confirming,
            Reconciliation::InSync,
            Reconciliation::ConfirmedIdle,
            Reconciliation::Unconfirmed,
        ] {
            let l = r.label().to_lowercase();
            for forbidden in ["$", "usd", "paid", "earned", "credit", "已发放"] {
                assert!(!l.contains(forbidden), "recon label leaked `{forbidden}`: {}", r.label());
            }
        }
    }

    // ── The combined model ─────────────────────────────────────────────────────

    #[test]
    fn dashboard_model_builds_and_reconciles() {
        let snap = running_snapshot();
        let model = DashboardModel::from_snapshot(&snap, CreditState::NotExposed);
        assert!(model.activity.is_active());
        assert_eq!(model.credit, CreditState::NotExposed);
        assert_eq!(model.reconciliation, Reconciliation::ActivityOnly);
    }

    #[test]
    fn dashboard_idle_model() {
        let m = DashboardModel::idle();
        assert!(!m.activity.is_active());
        assert_eq!(m.credit, CreditState::NotExposed);
        assert_eq!(m.reconciliation, Reconciliation::Idle);
    }

    // ── PoolStatsClient (poll discipline) ──────────────────────────────────────

    #[test]
    fn not_exposed_client_never_polls_and_stays_not_exposed() {
        let mut c = PoolStatsClient::not_exposed();
        assert!(!c.polls_network());
        assert!(c.lookup_url("addr").is_none());
        assert!(c.next_poll_in_secs(0.5).is_none());
        // begin_poll is a no-op for the NotExposed source (single-flight + no net).
        assert!(!c.begin_poll());
        assert_eq!(c.state(), CreditState::NotExposed);
    }

    #[test]
    fn public_read_model_client_builds_lookup_url_and_single_flights() {
        // The base is the API APEX; the client appends the `/read/miner-lookup` path.
        let mut c = PoolStatsClient::public_read_model("https://api.aliceprotocol.org/");
        assert!(c.polls_network());
        let url = c.lookup_url("a2x7Kf3+Lp/V9").unwrap();
        // The address is percent-encoded (the `+` and `/` must NOT pass through).
        assert_eq!(
            url,
            "https://api.aliceprotocol.org/read/miner-lookup?address=a2x7Kf3%2BLp%2FV9"
        );
        // Single-flight: first begin succeeds, a second (before complete/fail) is
        // rejected so the caller skips a concurrent poll.
        assert!(c.begin_poll());
        assert!(!c.begin_poll());
        // Completing clears it.
        c.complete(r#"{"found":false,"paid_acu":"0"}"#);
        assert!(c.begin_poll());
    }

    #[test]
    fn poll_backoff_grows_on_failure_and_resets_on_success() {
        let mut c = PoolStatsClient::public_read_model("https://x/read");
        // No failures yet: within [base, base+jitter].
        let s0 = c.next_poll_in_secs(0.0).unwrap();
        assert_eq!(s0, CREDIT_POLL_BASE_SECS);
        let s_full = c.next_poll_in_secs(1.0).unwrap();
        assert_eq!(s_full, CREDIT_POLL_BASE_SECS + CREDIT_POLL_JITTER_SECS);
        // Two transport failures → backoff ×4.
        c.begin_poll();
        c.fail();
        c.begin_poll();
        c.fail();
        assert_eq!(c.consecutive_failures(), 2);
        let s2 = c.next_poll_in_secs(0.0).unwrap();
        assert_eq!(s2, CREDIT_POLL_BASE_SECS * 4);
        // Backoff is capped.
        for _ in 0..20 {
            c.begin_poll();
            c.fail();
        }
        assert_eq!(c.next_poll_in_secs(1.0).unwrap(), CREDIT_POLL_MAX_BACKOFF_SECS);
        // A success resets backoff to base.
        c.begin_poll();
        c.complete(r#"{"found":true,"paid_acu":"0","summary":{"pending_alice":0.0}}"#);
        assert_eq!(c.consecutive_failures(), 0);
        assert_eq!(c.next_poll_in_secs(0.0).unwrap(), CREDIT_POLL_BASE_SECS);
    }

    /// A `paid_acu != "0"` body delivered through the client (not just the bare
    /// parser) still drops the value AND counts as a failure for backoff.
    #[test]
    fn client_complete_drops_nonzero_paid_acu_and_backs_off() {
        let mut c = PoolStatsClient::public_read_model("https://x/read");
        c.begin_poll();
        let state = c.complete(r#"{"found":true,"paid_acu":"7","summary":{"pending_alice":9.0}}"#);
        assert_eq!(state, CreditState::Error { reason: CreditError::PaidAcuNotZero });
        assert!(!state.has_confirmed_credit());
        assert_eq!(c.consecutive_failures(), 1);
    }

    #[test]
    fn default_client_is_not_exposed() {
        assert!(!PoolStatsClient::default().polls_network());
    }

    #[test]
    fn sparkline_caps_at_capacity() {
        let mut sp = Sparkline::new();
        for i in 0..(SPARK_CAP + 20) {
            sp.push(i as f32);
        }
        assert_eq!(sp.len(), SPARK_CAP);
        // Oldest evicted: the first sample present is sample #20.
        assert_eq!(sp.as_slice_vec()[0], 20.0);
    }
}
