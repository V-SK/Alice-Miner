//! The headless **dashboard renderer** — pure `&T -> String` formatters for the
//! CLI's human output. Kept separate from `main.rs` so the credit-only honesty
//! gate (no `$`/fiat/`paid`/`earned`, no collection address / upstream pool /
//! core IP) is auditable in one place and unit-testable without an engine.
//!
//! Parity with the GUI dashboard (PLAN §5 M6): the SAME fields — state, per-lane
//! hashrate (H/s + a human kH/MH), accepted/rejected shares, accepted %,
//! endpoint, failovers, uptime. The reward wording leads with credit
//! ("credit · 积分 (credit-only)") — the GUI (Beta) still shows the older
//! "pending · 待发放" and is intentionally not aligned yet. Every string here is
//! presentation only; no mining logic.

use alice_miner_core::detect::capability::ALL_LANES;
use alice_miner_core::detect::GpuDevice;
use alice_miner_core::engine::LaneSnapshot;
use alice_miner_core::{
    CapabilityProfile, CreditState, EngineState, GpuInfo, GpuVendor, Lane, Snapshot,
    LANE_KEY_GPU_ALPHA, LANE_KEY_GPU_PRL,
};

/// The ONLY way the CLI ever renders rewards: it is CREDIT (accruing now,
/// server-confirmable), credit-only (payout gated, phase-J), bilingual, never a
/// number / `$`. Leads with "credit" not "pending" — the credit is real and
/// accruing, whereas "待发放" wrongly implied a queued payout. (The GUI's
/// `strings::REWARD_PENDING` is the older wording, intentionally not aligned yet.)
const REWARD_CREDIT: &str = "credit · 积分 (credit-only)";

// ─────────────────────────────────────────────────────────────────────────────
// Lane semaphore + always-on lane table (the "make silent zeros LOUD" core).
//
// A strict green/amber/red per-lane health so the open field bugs (Win/PRL
// 0-share, V100/i9 0-hashrate, Mac App-Nap stall) become VISIBLE instead of
// silent zeros. SHARED by the line renderer (here) and the ratatui TUI so the two
// can never drift. Credit-only: it reads only activity (state + hashrate), never a
// reward number.
// ─────────────────────────────────────────────────────────────────────────────

/// A lane's at-a-glance health, the dashboard semaphore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneHealth {
    /// Running with a nonzero hashrate — the lane is doing real work.
    Green,
    /// Running but 0 H/s (a STALL — the loud "this lane is wedged" signal, e.g. Mac
    /// App-Nap), or a transitional Starting/Stopping (reconnecting).
    Amber,
    /// The lane errored / its child exited.
    Red,
    /// Not started / fully stopped.
    Idle,
}

impl LaneHealth {
    /// Classify a lane from its lifecycle state + live hashrate. A `Running` lane
    /// with a positive, finite hashrate is GREEN; a `Running` lane at 0 / no speed
    /// line yet is AMBER (the stall tell); `Starting`/`Stopping` are AMBER
    /// (reconnecting); `Error` is RED; `Idle` is IDLE.
    pub fn classify(state: EngineState, hashrate_hs: Option<f64>) -> Self {
        match state {
            EngineState::Running => match hashrate_hs {
                Some(h) if h.is_finite() && h > 0.0 => LaneHealth::Green,
                _ => LaneHealth::Amber, // running but 0 H/s = stalled (LOUD)
            },
            EngineState::Starting | EngineState::Stopping => LaneHealth::Amber,
            EngineState::Error => LaneHealth::Red,
            EngineState::Idle => LaneHealth::Idle,
        }
    }

    /// A short, color-independent chip so the semaphore survives NO_COLOR / a pipe /
    /// a journal (the green/amber/red is ALSO applied as a terminal color when color
    /// is enabled, but the word carries the signal on its own). ASCII-only.
    pub fn chip(self) -> &'static str {
        match self {
            LaneHealth::Green => "OK",
            LaneHealth::Amber => "STALL",
            LaneHealth::Red => "ERR",
            LaneHealth::Idle => "—",
        }
    }
}

/// One always-on lane row (LANE / STATE / SPEED / SHARES / ENDPOINT / FAILOVERS),
/// plus the computed [`LaneHealth`] semaphore. Pure presentation — built from the
/// snapshot, no engine handle. Credit-only (counts only).
#[derive(Debug, Clone, PartialEq)]
pub struct LaneRow {
    pub lane: Lane,
    pub health: LaneHealth,
    pub state: String,
    pub speed: String,
    pub shares: String,
    pub endpoint: String,
    pub failovers: u64,
}

impl LaneRow {
    fn from_lane_snapshot(l: &LaneSnapshot) -> Self {
        LaneRow {
            lane: l.lane,
            health: LaneHealth::classify(l.state, l.hashrate_hs),
            state: fmt_state(l.state).to_string(),
            speed: fmt_hashrate(l.hashrate_hs),
            shares: fmt_lane_shares(l.lane, l.shares_accepted, l.shares_rejected),
            endpoint: l.endpoint.clone().unwrap_or_else(|| "—".into()),
            failovers: l.failovers,
        }
    }
}

/// Honest per-lane share text: a GpuAlpha lane reports SUBMITTED shares (the relay
/// owns acceptance — AlphaMiner never logs a pool accept), so it reads "N sub"; every
/// other lane shows "A/R". Used by the lane table (both renderers).
fn fmt_lane_shares(lane: Lane, accepted: u64, rejected: u64) -> String {
    if lane == Lane::GpuAlpha {
        format!("{accepted} sub")
    } else {
        format!("{accepted}A/{rejected}R")
    }
}

/// The always-on lane table rows for a snapshot. When the engine populated `lanes`
/// (single OR dual run), use them; otherwise SYNTHESIZE one row from the top-level
/// mirror fields so the table renders even for an older single-lane stream that
/// predates the per-lane breakdown. Empty only when there is genuinely no lane (a
/// pre-start idle snapshot with no `lane`).
pub fn lane_table_rows(snap: &Snapshot) -> Vec<LaneRow> {
    if !snap.lanes.is_empty() {
        return snap.lanes.iter().map(LaneRow::from_lane_snapshot).collect();
    }
    // Synthesize a single row from the top-level fields (single-lane / older stream).
    match snap.lane {
        Some(lane) => vec![LaneRow {
            lane,
            health: LaneHealth::classify(snap.state, snap.hashrate_hs),
            state: fmt_state(snap.state).to_string(),
            speed: fmt_hashrate(snap.hashrate_hs),
            shares: fmt_lane_shares(lane, snap.shares_accepted, snap.shares_rejected),
            endpoint: snap.endpoint.clone().unwrap_or_else(|| "—".into()),
            failovers: snap.failovers,
        }],
        None => Vec::new(),
    }
}

/// Render the always-on lane table as a fixed-width text block (the line renderer's
/// table; the TUI builds a ratatui `Table` from the same [`lane_table_rows`]). The
/// per-row health chip is the LOUD signal — `STALL` for a running-but-0 lane, `ERR`
/// for a crashed one — visible even with color stripped. Returns `""` when there is
/// no lane to show.
pub fn render_lane_table(snap: &Snapshot, color: bool) -> String {
    let rows = lane_table_rows(snap);
    if rows.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    // Header. Columns: a 1-char health gutter, LANE / STATE / SPEED / SHARES /
    // ENDPOINT / FAILOVERS.
    out.push_str(&format!(
        "    {:<5} {:<18} {:<9} {:<22} {:<10} {:<26} {:>3}\n",
        "", "LANE", "STATE", "SPEED", "SHARES", "ENDPOINT", "F/O",
    ));
    for r in &rows {
        let line = format!(
            "    {:<5} {:<18} {:<9} {:<22} {:<10} {:<26} {:>3}\n",
            r.health.chip(),
            r.lane.label(),
            r.state,
            truncate_col(&r.speed, 22),
            truncate_col(&r.shares, 10),
            truncate_col(&r.endpoint, 26),
            r.failovers,
        );
        out.push_str(&paint_line(&line, r.health, color));
    }
    out
}

/// Apply the semaphore color to a whole row (green/amber/red) when color is enabled.
/// A no-op (returns the line unchanged) when `color` is false — so a pipe / journal /
/// NO_COLOR stays clean and greppable. Idle rows are left uncolored.
fn paint_line(line: &str, health: LaneHealth, color: bool) -> String {
    if !color {
        return line.to_string();
    }
    let code = match health {
        LaneHealth::Green => "\x1b[32m",
        LaneHealth::Amber => "\x1b[33m",
        LaneHealth::Red => "\x1b[31m",
        LaneHealth::Idle => return line.to_string(),
    };
    // Keep the trailing newline OUTSIDE the reset so the color spans exactly the row.
    let trimmed = line.strip_suffix('\n').unwrap_or(line);
    format!("{code}{trimmed}\x1b[0m\n")
}

/// Truncate a cell to `max` chars with a trailing `…` (char-counted, so the `·`
/// middot never splits) — keeps the lane table columns aligned.
fn truncate_col(s: &str, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        s.to_string()
    } else if max == 0 {
        String::new()
    } else {
        let kept: String = chars.into_iter().take(max.saturating_sub(1)).collect();
        format!("{kept}…")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// detect
// ─────────────────────────────────────────────────────────────────────────────

/// Render the full capability profile + lane-viability matrix (the `detect`
/// human output). Device model string only (no emoji, PLAN §6-i).
pub fn render_detect(cap: &CapabilityProfile) -> String {
    let p = &cap.profile;
    let mut out = String::new();
    out.push_str(&format!("Device:  {}\n", p.display));
    out.push_str(&format!("  os:            {}\n", p.os.label()));
    out.push_str(&format!("  arch:          {}\n", p.arch));
    out.push_str(&format!("  apple_silicon: {}\n", p.apple_silicon));
    out.push_str(&format!("  logical_cores: {}\n", p.logical_cores));
    if !p.cpu_model.is_empty() {
        out.push_str(&format!("  cpu_model:     {}\n", p.cpu_model));
    }
    out.push_str(&format!("  gpu:           {}\n", fmt_gpu(&p.gpu)));
    // Per-card enumeration (NVIDIA) so multi-GPU rigs can see each card + its
    // index — the token for `start --lane gpu --gpus 0,1,…`.
    out.push_str(&fmt_gpu_list(&p.gpu.gpus));
    out.push_str(&format!("  memory_gb:     {}\n", p.memory_gb));
    if !p.warnings.is_empty() {
        out.push_str(&format!("  warnings:      {}\n", p.warnings.join(", ")));
    }

    // The lane-viability matrix (which lanes this device can run + recommended).
    out.push_str("Lanes:\n");
    let recommended = cap.recommended_lane();
    // Pad to the WIDEST lane label so the STATE column always aligns. The longest
    // is "GPU · Alpha (V100)" (18 chars) — a fixed `{:<10}` truncated past it and
    // broke the column (polish #13). Compute the pad from the labels themselves so
    // it can never drift if a lane is renamed. `·` counts as one display column.
    let pad = ALL_LANES
        .iter()
        .map(|l| l.label().chars().count())
        .max()
        .unwrap_or(10);
    for &lane in ALL_LANES.iter() {
        let support = cap.support(lane);
        let marker = if lane == recommended { "  (recommended)" } else { "" };
        out.push_str(&format!(
            "  {:<pad$} {}{}\n",
            lane.label(),
            support.label(),
            marker
        ));
    }
    out
}

/// Human-friendly one-line GPU description (model + VRAM, the vendor when no
/// model was probed, or `none` when CPU-only). No emoji / vendor glyph.
/// The per-card enumeration block for `detect`. Lists every physical card with
/// its index (the `--gpus` token), name, and VRAM, plus a hint on restricting to
/// specific cards. Empty for a 0/1-card machine — the `gpu:` summary line above
/// already covers a single GPU, so this only adds value on a ≥2-GPU rig (where
/// per-card scheduling matters). NVIDIA-only (only `nvidia-smi` enumerates).
fn fmt_gpu_list(gpus: &[GpuDevice]) -> String {
    if gpus.len() < 2 {
        return String::new();
    }
    let mut s = String::new();
    for d in gpus {
        let vram = if d.vram_gb > 0 {
            format!(" · {} GB", d.vram_gb)
        } else {
            String::new()
        };
        s.push_str(&format!("    gpu[{}]:        {}{}\n", d.index, d.name, vram));
    }
    s.push_str(
        "    (--gpus selects by the MINER's device ids, which can differ from gpu[n]\n     above and may include an integrated GPU — run `gpu-devices` to list them.\n     Omit --gpus = every card.)\n",
    );
    s
}

/// The `gpu-devices` block: the GPUs as the SRBMiner engine enumerates them, i.e.
/// the exact ids `start --lane gpu --gpus <id>` selects. CUDA cards (NVIDIA) do
/// pearlhash; an OpenCL integrated GPU is flagged so it's never picked by mistake.
pub fn render_gpu_devices(devices: &[alice_miner_core::lane::gpu_prl::SrbGpuDevice]) -> String {
    if devices.is_empty() {
        return "No GPU devices reported by the miner (no usable GPU, or the engine \
                couldn't enumerate one).\n"
            .to_string();
    }
    let mut s = String::from("GPU devices (the ids `start --lane gpu --gpus <id>` selects):\n");
    for d in devices {
        let note = if d.backend != "CUDA" {
            "  (integrated/OpenCL — not for pearlhash)"
        } else {
            ""
        };
        let pci = if d.pci.is_empty() {
            String::new()
        } else {
            format!("  [{}]", d.pci)
        };
        s.push_str(&format!(
            "  --gpus {:<2}  {:<7} {}{}{}\n",
            d.id, d.backend, d.name, pci, note
        ));
    }
    s.push_str(
        "  Pick the id(s) above (NOT detect's gpu[n]); comma-separate for several, \
         e.g. --gpus 1,2.\n",
    );
    s
}

fn fmt_gpu(gpu: &GpuInfo) -> String {
    match gpu.vendor {
        GpuVendor::None => "none (CPU-only)".to_string(),
        GpuVendor::Nvidia => {
            if gpu.vram_gb > 0 {
                format!("{} · {} GB VRAM", gpu.model, gpu.vram_gb)
            } else {
                gpu.model.clone()
            }
        }
        GpuVendor::Amd => format!("{} (lane coming soon)", gpu.model),
        GpuVendor::Apple => format!("{} (unified memory)", gpu.model),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// identity
// ─────────────────────────────────────────────────────────────────────────────

/// Render a freshly-established identity. On create, `mnemonic` carries the
/// 24-word phrase to surface with a forced back-up warning; for import/paste it
/// is `None`. NEVER prints a password / seed / key.
pub fn render_identity(identity: &alice_miner_core::Identity, mnemonic: Option<&str>) -> String {
    let mut out = String::new();
    out.push_str("Identity established:\n");
    out.push_str(&format!("  address:    {}\n", identity.address));
    out.push_str(&format!("  watch_only: {}\n", identity.watch_only));
    if let Some(ks) = identity.keystore_path.as_ref() {
        out.push_str(&format!("  keystore:   {}\n", ks.display()));
    }
    out.push_str(&format!(
        "  pointer:    {}\n",
        alice_miner_core::identity::identity_path().display()
    ));
    if let Some(phrase) = mnemonic {
        out.push('\n');
        out.push_str("  ── BACK UP THIS RECOVERY PHRASE (24 words) ──\n");
        out.push_str("  This is the ONLY way to recover this identity. Anyone with these\n");
        out.push_str("  words controls the address. Store it offline — never paste it online.\n\n");
        out.push_str(&format!("  {phrase}\n"));
        out.push_str("  ─────────────────────────────────────────────\n");
    }
    out
}

/// Render `identity --show`: the active address from the pointer. Public only —
/// no secret is ever read or printed (the pointer holds none).
pub fn render_identity_show(p: &alice_miner_core::IdentityPointer) -> String {
    let mut out = String::new();
    out.push_str(&format!("address:    {}\n", p.address));
    out.push_str(&format!(
        "watch_only: {}\n",
        p.keystore_path.is_none()
    ));
    if let Some(label) = p.label.as_deref() {
        out.push_str(&format!("label:      {label}\n"));
    }
    out.push_str(&format!(
        "pointer:    {}\n",
        alice_miner_core::identity::identity_path().display()
    ));
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// start — banners + the live dashboard
// ─────────────────────────────────────────────────────────────────────────────

/// The one-line banner printed when a run starts.
pub fn render_start_banner(lane: Lane, dual: bool) -> String {
    if dual {
        // Dual's GPU partner is the PRL mainline unless RVN was explicitly selected
        // (mirrors `engine.rs` `start_run`'s `gpu_lane`).
        let gpu = if lane == Lane::GpuRvn { "RVN" } else { "PRL" };
        format!(
            "Starting dual-mine (CPU·XMR + GPU·{gpu}) — Ctrl-C or `alice-miner stop` to stop.\n"
        )
    } else {
        format!(
            "Starting {} lane — Ctrl-C or `alice-miner stop` to stop.\n",
            lane.label()
        )
    }
}

/// The transient banner printed when a stop is requested.
pub fn render_stopping_banner() -> String {
    "Stopping…\n".to_string()
}

/// Per-tick render context: an advancing heartbeat spinner frame + how stale the
/// stream is (seconds since the snapshot last ADVANCED). Lets the line renderer show
/// a visible, advancing heartbeat — so a wedged (App-Nap) miner whose process is
/// alive but stalled is obvious — and a "no update Ns" chip when the stream stops
/// advancing. The render-loop owns the state and passes it in each tick.
#[derive(Debug, Clone, Copy, Default)]
pub struct RenderCtx {
    /// A monotonically-increasing tick counter; `% SPINNER.len()` picks the frame.
    pub spinner_frame: u64,
    /// Seconds since the snapshot last advanced (a real tick changed). `None` =
    /// unknown / first tick; `Some(n)` drives the "no update Ns" amber chip when n is
    /// past [`STALE_AFTER_S`].
    pub stale_for_s: Option<u64>,
    /// Whether to emit terminal color (semaphore + chips). False under NO_COLOR /
    /// a pipe / a journal, so the output stays clean + greppable.
    pub color: bool,
}

/// The heartbeat spinner frames (ASCII-only so a journal / NO_COLOR stays clean and
/// no glyph trips the no-emoji gate). Advances on every real Snapshot tick.
pub const SPINNER: [char; 4] = ['|', '/', '-', '\\'];

/// After this many seconds without the stream advancing, the heartbeat dims to an
/// amber "no update Ns" — the loud "process alive but stalled" tell (App-Nap).
pub const STALE_AFTER_S: u64 = 5;

/// Render ONE live dashboard tick from a [`Snapshot`] with the default (no-context)
/// presentation — no spinner-staleness chip, no color. Kept for tests and any caller
/// that doesn't track per-tick state; the live loop uses [`render_snapshot_ctx`] with
/// a real [`RenderCtx`].
#[allow(dead_code)] // back-compat / test entry point; the live path uses *_ctx
pub fn render_snapshot(snap: &Snapshot) -> String {
    render_snapshot_ctx(snap, &RenderCtx::default())
}

/// Render ONE live dashboard tick from a [`Snapshot`] + a [`RenderCtx`]. A compact,
/// honest block: an advancing heartbeat · state · hashrate (H/s + human) · shares
/// A/R (+accepted%) · uptime · endpoint · failovers · rewards credit, followed by the
/// ALWAYS-ON per-lane table (LANE / STATE / SPEED / SHARES / ENDPOINT / FAILOVERS
/// with a green/amber/red semaphore per row).
///
/// Honest by construction: rewards are only ["credit · 积分 (credit-only)"](REWARD_CREDIT);
/// the endpoint shown is the PUBLIC relay carried in the snapshot — never the
/// collection address / upstream pool / core IP (those never reach the client).
pub fn render_snapshot_ctx(snap: &Snapshot, ctx: &RenderCtx) -> String {
    let mut out = String::new();

    let hr = fmt_hashrate(snap.hashrate_hs);
    let endpoint = snap.endpoint.as_deref().unwrap_or("—");
    let failover = if snap.failovers > 0 {
        format!(" · failed-over×{}", snap.failovers)
    } else {
        String::new()
    };
    let dual_tag = if snap.dual { " [dual]" } else { "" };

    // Heartbeat: an advancing spinner glyph (so an App-Nap stall — process alive but
    // the stream wedged — is visible), dimming to an amber "no update Ns" chip when
    // the stream stops advancing past STALE_AFTER_S.
    let beat = SPINNER[(ctx.spinner_frame as usize) % SPINNER.len()];
    let heartbeat = match ctx.stale_for_s {
        Some(n) if n >= STALE_AFTER_S => {
            let chip = format!("{beat} no update {n}s");
            // Amber when stale (color-gated; the word carries the signal regardless).
            if ctx.color { format!("\x1b[33m{chip}\x1b[0m ") } else { format!("{chip} ") }
        }
        _ => format!("{beat} "),
    };
    out.push_str(&heartbeat);

    // SHOULD-FIX B: AlphaMiner reports `hits` = SUBMITTED shares (it async-submits and
    // never logs a pool accept; acceptance is the relay's truth — see `parse_alpha`). So
    // on a single GpuAlpha lane the share segment reads "{N} submitted" with NO accepted%
    // (a 100% accept rate we can't know); every other lane keeps the "{A}A/{R}R (pct%)"
    // framing. (Dual mode mirrors the PRIMARY lane here; the per-lane rows below show each
    // lane's own counts, so we scope this to a single GpuAlpha primary.)
    let shares_seg = if snap.lane == Some(Lane::GpuAlpha) && !snap.dual {
        format!("shares {} submitted", snap.shares_accepted)
    } else {
        let accepted_pct = fmt_accepted_pct(snap.shares_accepted, snap.shares_rejected);
        format!(
            "shares {}A/{}R{}",
            snap.shares_accepted, snap.shares_rejected, accepted_pct
        )
    };

    out.push_str(&format!(
        "[{}]{dual_tag} {hr} · {shares_seg} · up {} · {}{} · rewards {}\n",
        fmt_state(snap.state),
        fmt_uptime(snap.uptime_s),
        endpoint,
        failover,
        REWARD_CREDIT,
    ));

    // Triple-window speed line (xmrig-grade): `speed 10s/60s/15m <a>/<b>/<c>`, shown
    // ONLY when the engine actually measures the windows (xmrig). A 0 in the 10s
    // column while Running is the instant stalled-lane tell; the 15m is the earnings
    // number. A window the engine reports as `n/a` (warm-up) renders `—`, never a
    // fabricated figure.
    if let Some(line) = fmt_speed_windows(snap) {
        out.push_str(&format!("    {line}\n"));
    }

    // Surface the engine's short reason whenever it set one: an Error/Stopping reason,
    // or a transient warning pushed while STILL running (e.g. the PoP-refresh "crediting
    // may pause" note — a full-hashrate lane can be earning nothing). The most actionable
    // field the engine computes every tick; previously dropped on the floor.
    if let Some(msg) = snap.message.as_deref() {
        if !msg.is_empty() {
            out.push_str(&format!("    ! {msg}\n"));
        }
    }
    // Reject-rate health note when elevated (rejected shares are wasted power that earns
    // nothing). Quiet under a noise floor; GPU-Alpha doesn't track rejects so it never trips.
    if let Some(note) = reject_health_note(snap.shares_accepted, snap.shares_rejected) {
        out.push_str(&format!("    ! {note}\n"));
    }

    // Crediting health for a pearlhash lane: it earns ONLY while the out-of-band PoP is
    // live, so a full-hashrate lane can otherwise be counting nothing. Positive
    // confirmation when healthy; the PAUSE case is already surfaced by the `message`
    // line above (so we suppress this line then to avoid a contradictory pair).
    if snap.lane.map(|l| l.is_prl_lane()).unwrap_or(false)
        && snap.state == alice_miner_core::EngineState::Running
        && snap.message.as_deref().map(str::is_empty).unwrap_or(true)
    {
        out.push_str("    rewards: counting (PoP active · credit-only)\n");
    }

    // The ALWAYS-ON per-lane table (was dual-only): one row per running lane (or a
    // single synthesized row for a single-lane / older stream), each with a strict
    // green/amber/red semaphore chip. One glance finds the dead / stalled lane.
    out.push_str(&render_lane_table(snap, ctx.color));

    // The GPU "15% PRL 返还 (credit-only)" line — present only on a PRL-earning lane
    // (the engine attaches the display block for `is_prl_lane()`). Credit-only by
    // construction: the masked return wallet + an honest enrolled/pending TEXT, never
    // a number / "$" / paid figure (the block's `paid` is hard-pinned 0.0 and is not
    // rendered here at all).
    if let Some(disp) = snap.prl_payout.as_ref() {
        out.push_str(&render_prl_return_line(disp));
    }

    // A sanitised hint line (the engine already sanitised it; we just surface
    // the last line as context). Only when present + non-empty.
    if let Some(line) = snap.last_line.as_deref() {
        if !line.is_empty() {
            out.push_str(&format!("    | {line}\n"));
        }
    }
    out
}

/// Render the **cumulative server-confirmed credit** line (Source B) for the human
/// dashboard. CREDIT-ONLY by construction: it surfaces only accepted-share COUNTS
/// (cumulative total, 24h, and the GPU·Alpha / GPU·PRL split) — never a `$`, a fiat
/// figure, or a "paid"/"earned" claim. The credit-only `pending_alice` magnitude on
/// `Confirmed` is deliberately NOT rendered (it stays "credit · 积分 (credit-only)").
///
/// Honest states (mirrors the read_api's fail-closed philosophy):
///   * `None` (no line at all) for `NotExposed` — the poller hasn't been wired to a
///     live endpoint, so there is nothing to claim.
///   * `Confirming` → "credited (cumulative): syncing…" (a MISSING fetch must NOT
///     show a fabricated 0).
///   * `Error` → "credited (cumulative): —" + a calm reason (network unreachable /
///     withheld); never a number, never the dropped value.
///   * `Confirmed` → the real COUNTS (a server 0 IS shown as 0 — a real measured
///     zero, distinct from "syncing"/"—").
pub fn render_credit_line(credit: &CreditState) -> Option<String> {
    match credit {
        // No live endpoint wired → no cumulative line (don't invent one).
        CreditState::NotExposed => None,
        CreditState::Confirming => {
            Some("    credited (cumulative): syncing… · 同步中 (credit-only)\n".to_string())
        }
        CreditState::Error { reason } => Some(format!(
            "    credited (cumulative): — · {} (credit-only)\n",
            reason.message()
        )),
        CreditState::Confirmed { totals, .. } => {
            let alpha = totals.accepted_for_lane(LANE_KEY_GPU_ALPHA);
            let prl = totals.accepted_for_lane(LANE_KEY_GPU_PRL);
            // The GPU·Alpha / GPU·PRL split is shown only when the server reports
            // those lanes (else just the headline count + 24h).
            let split = if alpha > 0 || prl > 0 {
                format!(" · GPU·Alpha {alpha} / GPU·PRL {prl}")
            } else {
                String::new()
            };
            Some(format!(
                "    credited (cumulative): {} shares (24h {}){} · {REWARD_CREDIT}\n",
                totals.accepted_total, totals.accepted_24h, split,
            ))
        }
    }
}

/// The warm-up an uptime must pass before a 0-credited / hashing-but-not-landing
/// divergence is treated as a real signal rather than normal start-up lag (the
/// server's read API + the first shares both take a moment). 120s ≈ a couple of
/// share intervals.
const CREDITED_RAW_WARMUP_S: u64 = 120;

/// The **credited-vs-raw** decision-grade note (Theme 1 #5). The local lane can be
/// producing a healthy RAW hashrate while the server confirms ZERO accepted shares —
/// exactly the Win/PRL "hashing but 0-share" field bug (a wedged PoP, a firewalled
/// stratum, a pool that isn't crediting). This surfaces that divergence at a glance:
/// the raw local rate next to the server's credited 24h count, with a "credited < raw
/// — shares may not be landing" note when they diverge.
///
/// HONEST + CREDIT-ONLY: counts and rates only, never a fiat figure. It fires ONLY on
/// a CONFIRMED server read (we never accuse the pool on a `syncing`/`error`/unexposed
/// state — that would be a false alarm from our own missing fetch) and only after a
/// warm-up, and only when the lane is genuinely producing raw work (nonzero, finite
/// hashrate while Running). `None` (no note) otherwise. The credited count being a
/// real measured 0 is the load-bearing signal — distinct from "syncing".
pub fn render_credited_vs_raw_note(snap: &Snapshot, credit: &CreditState) -> Option<String> {
    // Only a CONFIRMED server read can tell us the pool credited nothing; on
    // syncing/error/not-exposed we don't know, so we stay silent (no false alarm).
    let CreditState::Confirmed { totals, .. } = credit else {
        return None;
    };
    // The lane must be actually hashing (Running + a positive, finite raw rate) and
    // past warm-up — otherwise a 0 credited count is just normal start-up, not a bug.
    let raw = snap.hashrate_hs?;
    if snap.state != EngineState::Running || !raw.is_finite() || raw <= 0.0 {
        return None;
    }
    if snap.uptime_s < CREDITED_RAW_WARMUP_S {
        return None;
    }
    // Divergence: producing raw work for a while, but the server's recent (24h)
    // credited accepted-share count is still 0 → the shares aren't landing.
    if totals.accepted_24h == 0 {
        Some(format!(
            "    ! credited 0 < raw {} — shares may not be landing \
             (check PoP / pool / firewall)\n",
            fmt_hashrate_human(raw),
        ))
    } else {
        None
    }
}

/// Render the GPU **15% PRL 返还 (credit-only)** line for the human dashboard. Shows
/// the bind state (`已绑定 · bound` / `待绑定 · pending`), the user's MASKED return
/// wallet (`prl1p…XXXX`, only when one is configured — never the foundation
/// collection address), and the engine's honest pending TEXT. NEVER prints a "$" or
/// a number: the `PrlPayoutDisplay.paid` field (hard-pinned 0.0) is not read here.
fn render_prl_return_line(disp: &alice_miner_core::PrlPayoutDisplay) -> String {
    let state = if disp.enrolled { "已绑定 · bound" } else { "待绑定 · pending" };
    let wallet = match disp.payout_masked.as_deref() {
        Some(masked) => format!(" · {masked}"),
        None => String::new(),
    };
    // The engine's pending_text is already number-free + honest (see
    // `prl_payout::default_pending_text`); surface it verbatim.
    format!(
        "    └ 15% PRL 返还 (credit-only) [{state}]{wallet} · {}\n",
        disp.pending_text
    )
}

/// Map an engine state to a short, lower-case label for the dashboard.
fn fmt_state(state: alice_miner_core::EngineState) -> &'static str {
    use alice_miner_core::EngineState::*;
    match state {
        Idle => "idle",
        Starting => "starting",
        Running => "running",
        Stopping => "stopping",
        Error => "error",
    }
}

/// Format a hashrate as raw `H/s` plus a human-scaled unit (kH/s, MH/s, GH/s) so
/// both the precise figure (XMR ~ hundreds of H/s) and the big one (KawPoW ~ tens
/// of MH/s) read cleanly. `None` (no speed line yet) → `—`.
pub fn fmt_hashrate(hs: Option<f64>) -> String {
    match hs {
        None => "—".to_string(),
        Some(h) if !h.is_finite() || h < 0.0 => "—".to_string(),
        Some(h) => {
            let human = fmt_hashrate_human(h);
            // Avoid a redundant "(X H/s · X H/s)" when the value is already < 1 kH/s.
            if h < 1000.0 {
                format!("{h:.1} H/s")
            } else {
                format!("{h:.1} H/s ({human})")
            }
        }
    }
}

/// The xmrig-grade triple-window speed line `speed 10s/60s/15m <a>/<b>/<c>` — but
/// ONLY when the snapshot's lane actually measures the windows (i.e. at least one of
/// the 60s/15m figures is present, which is xmrig). `None` for every GPU lane (they
/// report a single instantaneous rate — no honest triple to show). The 10s figure is
/// the snapshot's primary `hashrate_hs`; each window renders `—` when not measured yet
/// (a `n/a` warm-up slot), and is NEVER backfilled from another window.
///
/// Honest-by-construction: a window we didn't measure stays `—`, not a copied value.
pub fn fmt_speed_windows(snap: &Snapshot) -> Option<String> {
    // Only show the triple when the engine reported a 60s OR 15m window — that's the
    // signal it actually measures them (xmrig). GPU lanes leave both None → no line.
    if snap.hashrate_60s_hs.is_none() && snap.hashrate_15m_hs.is_none() {
        return None;
    }
    let w = |h: Option<f64>| match h {
        Some(v) if v.is_finite() && v >= 0.0 => fmt_hashrate_human(v),
        _ => "—".to_string(),
    };
    Some(format!(
        "speed 10s/60s/15m {} / {} / {}",
        w(snap.hashrate_hs),
        w(snap.hashrate_60s_hs),
        w(snap.hashrate_15m_hs),
    ))
}

/// The human-scaled hashrate unit alone (kH/s, MH/s, GH/s) — no raw H/s. Used in
/// the combined form above; exposed for tests.
pub fn fmt_hashrate_human(h: f64) -> String {
    if !h.is_finite() || h < 0.0 {
        return "—".to_string();
    }
    const K: f64 = 1_000.0;
    const M: f64 = 1_000_000.0;
    const G: f64 = 1_000_000_000.0;
    const T: f64 = 1_000_000_000_000.0;
    if h >= T {
        // GPU-PRL pearlhash can exceed 1 TH/s on a strong card.
        format!("{:.2} TH/s", h / T)
    } else if h >= G {
        format!("{:.2} GH/s", h / G)
    } else if h >= M {
        format!("{:.2} MH/s", h / M)
    } else if h >= K {
        format!("{:.2} kH/s", h / K)
    } else {
        format!("{h:.0} H/s")
    }
}

/// A reject-rate health note when the rejected fraction is elevated — `None` under a
/// noise floor (don't alarm on a tiny sample) or when rejects are healthy. Rejected
/// shares are wasted power that earns nothing, so an elevated rate is a real earn-
/// correctness signal a miner should see. GPU-Alpha never tracks rejects (always 0), so
/// it never trips.
fn reject_health_note(accepted: u64, rejected: u64) -> Option<String> {
    let total = accepted + rejected;
    if total < 20 {
        return None; // noise floor: a few early rejects are normal vardiff churn
    }
    let pct = rejected as f64 / total as f64 * 100.0;
    if pct > 20.0 {
        Some(format!(
            "HIGH reject rate {pct:.0}% — wasted work; check GPU stability / overclock / pool"
        ))
    } else if pct > 5.0 {
        Some(format!("elevated reject rate {pct:.0}%"))
    } else {
        None
    }
}

/// Accepted-share percentage suffix, e.g. ` (99%)`. Empty until at least one
/// share is submitted (no "100%" of zero).
fn fmt_accepted_pct(accepted: u64, rejected: u64) -> String {
    let total = accepted + rejected;
    if total == 0 {
        String::new()
    } else {
        let pct = (accepted as f64 / total as f64) * 100.0;
        format!(" ({pct:.0}%)")
    }
}

/// `HH:MM:SS` uptime — same shape as the GUI's `fmt_uptime`.
pub fn fmt_uptime(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alice_miner_core::engine::{LaneSnapshot, Snapshot};
    use alice_miner_core::EngineState;

    fn gpu(index: u32, name: &str, vram: u32) -> GpuDevice {
        GpuDevice { index, name: name.into(), vram_gb: vram, uuid: String::new() }
    }

    /// A ≥2-GPU rig enumerates every card with its index (the `--gpus` token),
    /// name, and VRAM, plus the restrict-to-cards hint. 0/1-card → empty (the
    /// summary line covers a single GPU).
    #[test]
    fn multi_gpu_list_enumerates_cards_with_indices() {
        assert_eq!(fmt_gpu_list(&[]), "");
        assert_eq!(fmt_gpu_list(&[gpu(0, "RTX 3090", 24)]), "", "single card → summary only");
        let two = fmt_gpu_list(&[gpu(0, "RTX 3090", 24), gpu(1, "RTX 3070 Ti", 8)]);
        assert!(two.contains("gpu[0]:"), "lists index 0: {two}");
        assert!(two.contains("RTX 3090 · 24 GB"));
        assert!(two.contains("gpu[1]:"), "lists index 1");
        assert!(two.contains("RTX 3070 Ti · 8 GB"));
        assert!(two.contains("--gpus"), "hints the per-card flag");
        assert!(two.contains("gpu-devices"), "points to the authoritative id list");
        assert!(two.contains("integrated GPU"), "warns the ids can differ / include an iGPU");
    }

    fn running_snapshot() -> Snapshot {
        Snapshot {
            state: EngineState::Running,
            device: None,
            lane: Some(Lane::Xmr),
            hashrate_hs: Some(8_432.0),
            hashrate_60s_hs: None,
            hashrate_15m_hs: None,
            shares_accepted: 142,
            shares_rejected: 1,
            endpoint: Some("hk.aliceprotocol.org:3333".into()),
            worker_id: Some("rig-7f3a9c21".into()),
            uptime_s: 3_661,
            failovers: 0,
            dual: false,
            lanes: vec![LaneSnapshot {
                lane: Lane::Xmr,
                state: EngineState::Running,
                hashrate_hs: Some(8_432.0),
                hashrate_60s_hs: None,
                hashrate_15m_hs: None,
                shares_accepted: 142,
                shares_rejected: 1,
                endpoint: Some("hk.aliceprotocol.org:3333".into()),
                failovers: 0,
            }],
            last_line: Some("net accepted (142/1) diff 100".into()),
            message: None,
            prl_payout: None,
        }
    }

    fn dual_snapshot() -> Snapshot {
        Snapshot {
            state: EngineState::Running,
            device: None,
            lane: Some(Lane::Xmr),
            hashrate_hs: Some(8_432.0 + 25_000_000.0),
            hashrate_60s_hs: None,
            hashrate_15m_hs: None,
            shares_accepted: 145,
            shares_rejected: 1,
            endpoint: Some("hk.aliceprotocol.org:3333".into()),
            worker_id: Some("rig-7f3a9c21".into()),
            uptime_s: 65,
            failovers: 1,
            dual: true,
            lanes: vec![
                LaneSnapshot {
                    lane: Lane::Xmr,
                    state: EngineState::Running,
                    hashrate_hs: Some(8_432.0),
                    hashrate_60s_hs: None,
                    hashrate_15m_hs: None,
                    shares_accepted: 142,
                    shares_rejected: 1,
                    endpoint: Some("hk.aliceprotocol.org:3333".into()),
                    failovers: 1,
                },
                LaneSnapshot {
                    lane: Lane::GpuRvn,
                    state: EngineState::Running,
                    hashrate_hs: Some(25_000_000.0),
                    hashrate_60s_hs: None,
                    hashrate_15m_hs: None,
                    shares_accepted: 3,
                    shares_rejected: 0,
                    endpoint: Some("hk.aliceprotocol.org:8888".into()),
                    failovers: 0,
                },
            ],
            last_line: Some("Speed 25.00 Mh/s gpu0".into()),
            message: None,
            prl_payout: None,
        }
    }

    // ── Hashrate formatting ──────────────────────────────────────────────────

    #[test]
    fn hashrate_formats_h_k_m_g() {
        // Sub-kH XMR: precise H/s only (no redundant human unit).
        assert_eq!(fmt_hashrate(Some(842.0)), "842.0 H/s");
        // kH range: raw + kH/s.
        assert_eq!(fmt_hashrate(Some(8_432.0)), "8432.0 H/s (8.43 kH/s)");
        // MH range (KawPoW): raw + MH/s.
        assert_eq!(fmt_hashrate(Some(25_000_000.0)), "25000000.0 H/s (25.00 MH/s)");
        // None / non-finite / negative → em dash.
        assert_eq!(fmt_hashrate(None), "—");
        assert_eq!(fmt_hashrate(Some(f64::NAN)), "—");
        assert_eq!(fmt_hashrate(Some(-1.0)), "—");
        // Human-only scaler.
        assert_eq!(fmt_hashrate_human(1_500.0), "1.50 kH/s");
        assert_eq!(fmt_hashrate_human(2_000_000_000.0), "2.00 GH/s");
        assert_eq!(fmt_hashrate_human(500.0), "500 H/s");
    }

    #[test]
    fn uptime_is_hh_mm_ss() {
        assert_eq!(fmt_uptime(0), "00:00:00");
        assert_eq!(fmt_uptime(65), "00:01:05");
        assert_eq!(fmt_uptime(3_661), "01:01:01");
    }

    #[test]
    fn accepted_pct_empty_until_a_share() {
        assert_eq!(fmt_accepted_pct(0, 0), "");
        assert_eq!(fmt_accepted_pct(142, 1), " (99%)");
        assert_eq!(fmt_accepted_pct(1, 0), " (100%)");
    }

    // ── Snapshot rendering ───────────────────────────────────────────────────

    #[test]
    fn snapshot_renders_core_fields() {
        let s = render_snapshot(&running_snapshot());
        assert!(s.contains("running"));
        assert!(s.contains("8.43 kH/s"));
        assert!(s.contains("142A/1R"));
        assert!(s.contains("(99%)"));
        assert!(s.contains("01:01:01"));
        assert!(s.contains("hk.aliceprotocol.org:3333"));
        assert!(s.contains("net accepted (142/1)"));
    }

    // ── Triple-window speed line (xmrig-grade; STRETCH) ─────────────────────────

    /// XMR (the one engine that measures the windows) renders a `speed 10s/60s/15m`
    /// triple; a `n/a` window shows `—` (never a backfilled figure). A GPU lane (both
    /// windows None) shows NO triple line at all.
    #[test]
    fn triple_window_speed_only_when_measured() {
        // XMR with all three windows → the full triple.
        let mut xmr = running_snapshot();
        xmr.hashrate_hs = Some(8_432.0);
        xmr.hashrate_60s_hs = Some(8_100.0);
        xmr.hashrate_15m_hs = Some(7_900.0);
        let line = fmt_speed_windows(&xmr).expect("xmr measures windows");
        assert!(line.contains("speed 10s/60s/15m"), "{line}");
        assert!(line.contains("8.43 kH/s"), "10s: {line}");
        assert!(line.contains("8.10 kH/s"), "60s: {line}");
        assert!(line.contains("7.90 kH/s"), "15m: {line}");

        // A still-n/a 15m window → `—` for that slot, the rest measured.
        let mut warming = xmr.clone();
        warming.hashrate_15m_hs = None;
        let l2 = fmt_speed_windows(&warming).expect("60s present → triple shown");
        assert!(l2.contains("—"), "n/a window renders an em dash: {l2}");

        // A GPU lane (both windows None) → no triple line (honesty: nothing measured).
        let mut gpu = running_snapshot();
        gpu.lane = Some(Lane::GpuPrl);
        gpu.hashrate_hs = Some(870_000_000_000.0);
        gpu.hashrate_60s_hs = None;
        gpu.hashrate_15m_hs = None;
        assert!(fmt_speed_windows(&gpu).is_none(), "GPU lane has no honest triple");

        // The full snapshot render includes the triple line for XMR.
        let rendered = render_snapshot(&xmr);
        assert!(rendered.contains("speed 10s/60s/15m"), "triple in the block: {rendered}");
    }

    // ── Always-on lane table + semaphore (make silent zeros LOUD) ───────────────

    /// The lane semaphore: Running + nonzero = green; Running + 0/None = AMBER (the
    /// stall tell); Starting/Stopping = amber; Error = red; Idle = idle.
    #[test]
    fn lane_health_classify_amber_on_zero() {
        assert_eq!(LaneHealth::classify(EngineState::Running, Some(8_432.0)), LaneHealth::Green);
        // Running but 0 H/s = STALLED → amber (the loud signal).
        assert_eq!(LaneHealth::classify(EngineState::Running, Some(0.0)), LaneHealth::Amber);
        assert_eq!(LaneHealth::classify(EngineState::Running, None), LaneHealth::Amber);
        // A non-finite reading is treated as no-progress → amber, never green.
        assert_eq!(LaneHealth::classify(EngineState::Running, Some(f64::NAN)), LaneHealth::Amber);
        // Transitional = amber (reconnecting); error = red; idle = idle.
        assert_eq!(LaneHealth::classify(EngineState::Starting, None), LaneHealth::Amber);
        assert_eq!(LaneHealth::classify(EngineState::Stopping, Some(1.0)), LaneHealth::Amber);
        assert_eq!(LaneHealth::classify(EngineState::Error, None), LaneHealth::Red);
        assert_eq!(LaneHealth::classify(EngineState::Idle, None), LaneHealth::Idle);
    }

    /// The lane table renders ALWAYS (not just dual): a single-lane snapshot with no
    /// `lanes` breakdown still gets one synthesized row with the header + a semaphore
    /// chip. A running-but-0 row shows the loud "STALL" chip.
    #[test]
    fn lane_table_is_always_on_and_shows_stall() {
        // Single lane, no `lanes` breakdown → one synthesized row.
        let mut s = running_snapshot();
        s.lanes = vec![];
        let table = render_lane_table(&s, false);
        assert!(table.contains("LANE"), "header present: {table}");
        assert!(table.contains("CPU · XMR"), "synthesized row: {table}");
        assert!(table.contains("OK"), "green lane shows OK chip: {table}");
        assert!(table.contains("hk.aliceprotocol.org:3333"));

        // Running but 0 H/s → the STALL chip (silent zero made loud).
        let mut stalled = running_snapshot();
        stalled.hashrate_hs = Some(0.0);
        stalled.lanes[0].hashrate_hs = Some(0.0);
        let t2 = render_lane_table(&stalled, false);
        assert!(t2.contains("STALL"), "0 H/s while running = STALL chip: {t2}");

        // An idle snapshot with no lane → no table at all (nothing to show).
        let idle = Snapshot {
            state: EngineState::Idle,
            device: None,
            lane: None,
            hashrate_hs: None,
            hashrate_60s_hs: None,
            hashrate_15m_hs: None,
            shares_accepted: 0,
            shares_rejected: 0,
            endpoint: None,
            worker_id: None,
            uptime_s: 0,
            failovers: 0,
            dual: false,
            lanes: vec![],
            last_line: None,
            message: None,
            prl_payout: None,
        };
        assert_eq!(render_lane_table(&idle, false), "");
    }

    /// The lane table's GpuAlpha row is honest: SUBMITTED ("N sub"), never an A/R or
    /// a fabricated accept rate (the relay owns acceptance).
    #[test]
    fn lane_table_gpu_alpha_row_is_submitted() {
        let mut s = running_snapshot();
        s.lane = Some(Lane::GpuAlpha);
        s.lanes = vec![LaneSnapshot {
            lane: Lane::GpuAlpha,
            state: EngineState::Running,
            hashrate_hs: Some(9.58e12),
            hashrate_60s_hs: None,
            hashrate_15m_hs: None,
            shares_accepted: 42,
            shares_rejected: 0,
            endpoint: Some("us.aliceprotocol.org:3341".into()),
            failovers: 0,
        }];
        let t = render_lane_table(&s, false);
        assert!(t.contains("42 sub"), "submitted label: {t}");
        assert!(!t.contains("42A/0R"), "no A/R framing for alpha: {t}");
    }

    /// Color gating: with `color=false` the table carries no ANSI escape; with
    /// `color=true` a row is wrapped in a color code + reset (so a pipe / NO_COLOR
    /// journal stays clean, but a TTY gets the semaphore).
    #[test]
    fn lane_table_color_is_gated() {
        let s = running_snapshot();
        let plain = render_lane_table(&s, false);
        assert!(!plain.contains('\x1b'), "no ANSI when color off: {plain:?}");
        let colored = render_lane_table(&s, true);
        assert!(colored.contains('\x1b'), "ANSI present when color on");
        assert!(colored.contains("\x1b[0m"), "reset present");
    }

    /// The heartbeat advances with the spinner frame and, once the stream goes stale,
    /// dims to an amber "no update Ns" chip — the App-Nap "alive but wedged" tell.
    #[test]
    fn heartbeat_advances_and_goes_stale() {
        let s = running_snapshot();
        let fresh = render_snapshot_ctx(&s, &RenderCtx { spinner_frame: 0, stale_for_s: Some(1), color: false });
        // Fresh (under the stale threshold) → spinner glyph, no "no update".
        assert!(fresh.starts_with(SPINNER[0]), "leads with the heartbeat glyph: {fresh:?}");
        assert!(!fresh.contains("no update"), "fresh stream is not stale");
        // The frame advances.
        let f1 = render_snapshot_ctx(&s, &RenderCtx { spinner_frame: 1, stale_for_s: Some(0), color: false });
        assert!(f1.starts_with(SPINNER[1]), "spinner frame advanced: {f1:?}");
        // Past STALE_AFTER_S → the loud "no update Ns" chip.
        let stale = render_snapshot_ctx(&s, &RenderCtx { spinner_frame: 2, stale_for_s: Some(STALE_AFTER_S + 3), color: false });
        assert!(stale.contains("no update"), "stale shows the chip: {stale}");
        assert!(stale.contains(&format!("{}s", STALE_AFTER_S + 3)), "with the age: {stale}");
    }

    /// SHOULD-FIX B: a single GpuAlpha lane's count is SUBMITTED (the client never sees a
    /// pool accept — the relay owns acceptance). The line must read "{N} submitted" with
    /// NO "(100%)" accepted-rate (which would imply an accept rate we can't know).
    #[test]
    fn gpu_alpha_renders_submitted_not_accepted_pct() {
        let mut s = running_snapshot();
        s.lane = Some(Lane::GpuAlpha);
        s.shares_accepted = 42; // = AlphaMiner `hits` = submitted shares
        s.shares_rejected = 0; // the client never knows a pool reject
        s.lanes = vec![LaneSnapshot {
            lane: Lane::GpuAlpha,
            state: EngineState::Running,
            hashrate_hs: Some(9.58e12),
            hashrate_60s_hs: None,
            hashrate_15m_hs: None,
            shares_accepted: 42,
            shares_rejected: 0,
            endpoint: s.endpoint.clone(),
            failovers: 0,
        }];
        let out = render_snapshot(&s);
        assert!(out.contains("42 submitted"), "submitted label + count: {out}");
        assert!(!out.contains("42A/0R"), "no accepted/rejected framing: {out}");
        assert!(!out.contains("(100%)"), "no fabricated 100% accept rate: {out}");
    }

    #[test]
    fn reject_health_note_thresholds() {
        // Under the noise floor → no note regardless of ratio.
        assert_eq!(reject_health_note(5, 5), None);
        // Healthy (<=5%) → no note.
        assert_eq!(reject_health_note(1000, 30), None);
        // Elevated (>5%, <=20%).
        let n = reject_health_note(900, 100).expect("elevated");
        assert!(n.contains("elevated"), "{n}");
        // High (>20%) → loud note.
        let n = reject_health_note(700, 300).expect("high");
        assert!(n.contains("HIGH"), "{n}");
        // GPU-Alpha never tracks rejects (rejected stays 0) → never trips.
        assert_eq!(reject_health_note(10_000, 0), None);
    }

    #[test]
    fn dual_snapshot_renders_per_lane_rows_with_own_ports() {
        let s = render_snapshot(&dual_snapshot());
        assert!(s.contains("[dual]"));
        // Both lane rows present, each with its OWN relay port.
        assert!(s.contains("CPU · XMR"));
        assert!(s.contains("GPU · RVN"));
        assert!(s.contains("hk.aliceprotocol.org:3333"));
        assert!(s.contains("hk.aliceprotocol.org:8888"));
        // The failover note surfaces.
        assert!(s.contains("failed-over×1"));
    }

    // ── THE HONESTY GATE (credit-only): the rendered dashboard must never carry
    // a fiat/payout token, and must never carry the collection address / upstream
    // pool / core IP. Rewards appear ONLY as "credit · 积分 (credit-only)". ────────

    #[test]
    fn rendered_output_is_credit_only_and_leaks_no_secrets() {
        // Render every human surface and scan the combined text.
        let mut all = String::new();
        all.push_str(&render_snapshot(&running_snapshot()));
        all.push_str(&render_snapshot(&dual_snapshot()));
        all.push_str(&render_start_banner(Lane::Xmr, false));
        all.push_str(&render_start_banner(Lane::GpuRvn, true));
        all.push_str(&render_stopping_banner());

        // The reward line is present and is the ONLY reward wording.
        assert!(all.contains(REWARD_CREDIT));

        let lower = all.to_lowercase();
        // Fiat / positive-earnings claims can never appear.
        for forbidden in ["$", "usd", "fiat", "paid", "earned", "已发放"] {
            assert!(
                !lower.contains(forbidden),
                "dashboard leaked forbidden reward token `{forbidden}`: {all}"
            );
        }
        // The collection address + upstream pool + core IP must NEVER appear. We
        // assert the core IP (from MEMORY) and a couple of upstream markers are
        // absent; the client only ever shows the PUBLIC relay host.
        for secret in ["203.0.113.10", "tw-pool", "api.tw-pool", "supportxmr", "collection"] {
            assert!(
                !all.contains(secret),
                "dashboard leaked a server-side secret `{secret}`: {all}"
            );
        }
        // The only host that may appear is the public relay.
        assert!(all.contains("hk.aliceprotocol.org"));
    }

    // ── Source B: the cumulative server-confirmed credit line ──────────────────

    use alice_miner_core::{CreditError, CreditScore, CreditState, CreditTotals, LaneCredit};

    fn confirmed_totals() -> CreditState {
        CreditState::Confirmed {
            score: CreditScore::new(0.0),
            totals: CreditTotals {
                accepted_total: 873,
                accepted_24h: 142,
                lanes: vec![
                    LaneCredit {
                        key: alice_miner_core::LANE_KEY_GPU_ALPHA.into(),
                        label: "GPU · Alpha".into(),
                        accepted: 500,
                    },
                    LaneCredit {
                        key: alice_miner_core::LANE_KEY_GPU_PRL.into(),
                        label: "GPU · PRL".into(),
                        accepted: 373,
                    },
                ],
            },
        }
    }

    /// A `Confirmed` state renders the cumulative COUNTS + the GPU·Alpha / GPU·PRL
    /// split — and NOTHING else (no number that is a fiat figure).
    #[test]
    fn credit_line_renders_cumulative_counts_only() {
        let line = render_credit_line(&confirmed_totals()).expect("a confirmed state renders");
        assert!(line.contains("credited (cumulative): 873 shares"), "headline count: {line}");
        assert!(line.contains("24h 142"), "24h count: {line}");
        assert!(line.contains("GPU·Alpha 500"), "alpha split: {line}");
        assert!(line.contains("GPU·PRL 373"), "prl split: {line}");
        // Credit-only honesty: only counts + "credit · 积分 (credit-only)", never fiat/paid/earned.
        let lower = line.to_lowercase();
        for forbidden in ["$", "usd", "fiat", "paid", "earned", "已发放"] {
            assert!(!lower.contains(forbidden), "credit line leaked `{forbidden}`: {line}");
        }
        assert!(line.contains(REWARD_CREDIT));
    }

    // ── Piece 6: credited-vs-raw divergence note ────────────────────────────────

    /// A confirmed server read showing 0 credited (24h) while the lane is producing a
    /// healthy raw hashrate past warm-up = the "hashing but not landing" bug. The note
    /// fires with the raw rate + an actionable hint — counts/rates only, never fiat.
    #[test]
    fn credited_vs_raw_flags_hashing_but_zero_credited() {
        let mut s = running_snapshot();
        s.lane = Some(Lane::GpuPrl);
        s.hashrate_hs = Some(1_200_000_000_000.0); // ~1.2 TH/s of real work
        s.uptime_s = 600; // well past warm-up
        let zero_credited = CreditState::Confirmed {
            score: CreditScore::new(0.0),
            totals: CreditTotals::default(), // accepted_24h = 0
        };
        let note = render_credited_vs_raw_note(&s, &zero_credited).expect("divergence note");
        assert!(note.contains("credited 0 < raw"), "names the divergence: {note}");
        assert!(note.contains("TH/s"), "shows the raw rate: {note}");
        assert!(note.contains("shares may not be landing"), "actionable: {note}");
        // Credit-only: no fiat / paid token.
        let lower = note.to_lowercase();
        for forbidden in ["$", "usd", "paid", "earned", "已发放"] {
            assert!(!lower.contains(forbidden), "note leaked `{forbidden}`: {note}");
        }
    }

    /// The note is SILENT on every honest non-confirmed state (we never accuse the
    /// pool from our OWN missing/syncing fetch), during warm-up, and when the lane
    /// isn't actually hashing — so it never false-alarms.
    #[test]
    fn credited_vs_raw_is_silent_unless_truly_diverging() {
        let mut hashing = running_snapshot();
        hashing.hashrate_hs = Some(8_432.0);
        hashing.uptime_s = 600;

        // Non-confirmed states → silent (we don't know the server's truth).
        assert!(render_credited_vs_raw_note(&hashing, &CreditState::NotExposed).is_none());
        assert!(render_credited_vs_raw_note(&hashing, &CreditState::Confirming).is_none());
        assert!(render_credited_vs_raw_note(
            &hashing,
            &CreditState::Error { reason: CreditError::Unreachable }
        )
        .is_none());

        // Confirmed but credited > 0 → no divergence, no note.
        let credited = CreditState::Confirmed {
            score: CreditScore::new(0.0),
            totals: CreditTotals { accepted_total: 50, accepted_24h: 12, lanes: vec![] },
        };
        assert!(render_credited_vs_raw_note(&hashing, &credited).is_none(), "credited>0 → quiet");

        // Still within warm-up → silent (0 credited is just start-up lag).
        let mut warming = hashing.clone();
        warming.uptime_s = 5;
        let zero = CreditState::Confirmed {
            score: CreditScore::new(0.0),
            totals: CreditTotals::default(),
        };
        assert!(render_credited_vs_raw_note(&warming, &zero).is_none(), "warm-up → quiet");

        // Not hashing (0 / no raw rate) → silent (nothing to compare against).
        let mut idle_rate = hashing.clone();
        idle_rate.hashrate_hs = Some(0.0);
        assert!(render_credited_vs_raw_note(&idle_rate, &zero).is_none(), "0 raw → quiet");
        idle_rate.hashrate_hs = None;
        assert!(render_credited_vs_raw_note(&idle_rate, &zero).is_none(), "no raw line → quiet");
    }

    /// A real server ZERO is shown as 0 (a measured zero) — distinct from "syncing".
    #[test]
    fn credit_line_shows_a_real_server_zero() {
        let zero = CreditState::Confirmed {
            score: CreditScore::new(0.0),
            totals: CreditTotals::default(),
        };
        let line = render_credit_line(&zero).expect("confirmed-zero renders");
        assert!(line.contains("credited (cumulative): 0 shares"), "real 0: {line}");
        // No lane split when there are no lanes (don't fabricate one).
        assert!(!line.contains("GPU·Alpha"), "no split for an empty breakdown: {line}");
    }

    /// Honest non-confirmed states: NotExposed → no line at all; Confirming →
    /// "syncing" (NOT a fabricated 0); Error → "—" + a calm reason (no number).
    #[test]
    fn credit_line_honest_states() {
        // NotExposed: nothing to claim → no line.
        assert!(render_credit_line(&CreditState::NotExposed).is_none());
        // Confirming: an honest "syncing", never a 0.
        let confirming = render_credit_line(&CreditState::Confirming).unwrap();
        assert!(confirming.contains("syncing"), "confirming syncs: {confirming}");
        assert!(!confirming.contains(" 0 shares"), "no fabricated 0 while syncing: {confirming}");
        // Error (unreachable): an em-dash placeholder + a calm reason, never a 0/number.
        let err = render_credit_line(&CreditState::Error { reason: CreditError::Unreachable }).unwrap();
        assert!(err.contains("credited (cumulative): —"), "error shows —: {err}");
        assert!(!err.contains("shares"), "no count on an errored fetch: {err}");
    }

    /// The dropped-value guard at the RENDER layer: a `paid_acu != "0"` envelope
    /// parsed through the client lands as `Error` and the render shows NO number.
    #[test]
    fn credit_line_drops_paid_acu_violation() {
        let state = alice_miner_core::dashboard::parse_credit_envelope(
            r#"{"found":true,"paid_acu":"9.9","summary":{"pending_alice":5.0,"accepted_shares_total":1000}}"#,
        );
        let line = render_credit_line(&state).unwrap();
        // The withheld value is never rendered — no count, no magnitude.
        assert!(!line.contains("1000"), "dropped count must not render: {line}");
        assert!(!line.contains("shares"), "no count on a withheld response: {line}");
        let lower = line.to_lowercase();
        for forbidden in ["$", "paid", "earned", "9.9", "5.0"] {
            assert!(!lower.contains(forbidden), "withheld value leaked `{forbidden}`: {line}");
        }
    }

    // ── Piece 3: the 15% PRL 返还 (credit-only) dashboard line ──────────────────

    /// A legal-shaped masked return wallet for the display block.
    const PAYOUT_OK: &str = "prl1pexamplewalletexamplewalletexamplewallet";

    /// A snapshot carrying a populated PRL display block (the engine attaches this
    /// for a PRL-earning lane). `prl_payout` is `#[serde(skip)]` on `Snapshot`, so it
    /// only affects the HUMAN dashboard (never the JSON shape).
    fn prl_snapshot(disp: alice_miner_core::PrlPayoutDisplay) -> Snapshot {
        Snapshot {
            state: EngineState::Running,
            device: None,
            lane: Some(Lane::GpuPrl),
            hashrate_hs: Some(870_000_000_000.0), // ~0.87 TH/s pearlhash
            hashrate_60s_hs: None,
            hashrate_15m_hs: None,
            shares_accepted: 70,
            shares_rejected: 0,
            endpoint: Some("us.aliceprotocol.org:3340".into()),
            worker_id: Some("rig-7f3a9c21".into()),
            uptime_s: 120,
            failovers: 0,
            dual: false,
            lanes: vec![LaneSnapshot {
                lane: Lane::GpuPrl,
                state: EngineState::Running,
                hashrate_hs: Some(870_000_000_000.0),
                hashrate_60s_hs: None,
                hashrate_15m_hs: None,
                shares_accepted: 70,
                shares_rejected: 0,
                endpoint: Some("us.aliceprotocol.org:3340".into()),
                failovers: 0,
            }],
            last_line: None,
            message: None,
            prl_payout: Some(disp),
        }
    }

    /// The PRL-return line renders the bound state + the MASKED wallet + the honest
    /// pending text — and NEVER a number / "$".
    #[test]
    fn prl_return_line_renders_bound_masked_and_no_number() {
        // Bound, with a configured return wallet.
        let disp = alice_miner_core::PrlPayoutDisplay::new(true, Some(PAYOUT_OK));
        let s = render_snapshot(&prl_snapshot(disp));
        assert!(s.contains("15% PRL 返还 (credit-only)"), "renders the block: {s}");
        assert!(s.contains("已绑定 · bound"), "shows the bound state");
        // The wallet is MASKED (prefix + … + suffix), never the full address.
        assert!(s.contains("prl1p") && s.contains('…'), "masked wallet shown");
        assert!(!s.contains(PAYOUT_OK), "the FULL return wallet is never printed");
        // CREDIT-ONLY: no "$" and no paid figure on the PRL line.
        assert!(!s.contains('$'));
    }

    /// When no return wallet is configured the line still renders (pending), with no
    /// masked address and no number.
    #[test]
    fn prl_return_line_renders_unbound_no_address() {
        let disp = alice_miner_core::PrlPayoutDisplay::new(false, None);
        let s = render_snapshot(&prl_snapshot(disp));
        assert!(s.contains("15% PRL 返还 (credit-only)"));
        assert!(s.contains("待绑定 · pending"), "unbound → pending state");
        assert!(!s.contains('$'));
    }

    /// Crediting health: a pearlhash lane Running with no PoP warning shows the positive
    /// "rewards: counting" confirmation; a PoP-pause message suppresses it (the message
    /// line carries the detail, so the two never contradict); an XMR lane never shows it
    /// (XMR credits by address, no OOB PoP).
    #[test]
    fn crediting_line_counts_when_healthy_suppressed_when_paused() {
        // Healthy pearlhash → positive confirmation.
        let disp = alice_miner_core::PrlPayoutDisplay::new(true, Some(PAYOUT_OK));
        let s = render_snapshot(&prl_snapshot(disp));
        assert!(s.contains("rewards: counting"), "healthy pearlhash shows counting: {s}");

        // Paused → counting suppressed, the pause message surfaces.
        let disp2 = alice_miner_core::PrlPayoutDisplay::new(true, Some(PAYOUT_OK));
        let mut paused = prl_snapshot(disp2);
        paused.message = Some("PoP re-verify failing — crediting may pause; retrying".into());
        let s = render_snapshot(&paused);
        assert!(!s.contains("rewards: counting"), "paused suppresses the counting line: {s}");
        assert!(s.contains("crediting may pause"), "the pause message is surfaced: {s}");

        // XMR (address-only) never shows the crediting line.
        let s = render_snapshot(&running_snapshot());
        assert!(!s.contains("rewards: counting"), "XMR has no OOB-PoP crediting row: {s}");
    }

    /// Non-PRL snapshots carry NO display block → the line is absent (no regression
    /// to the XMR/RVN dashboard).
    #[test]
    fn prl_return_line_absent_for_non_prl_snapshot() {
        let s = render_snapshot(&running_snapshot()); // prl_payout: None
        assert!(!s.contains("15% PRL 返还"), "XMR dashboard has no PRL line");
    }

    /// CREDIT-ONLY: a PRL snapshot's rendered HUMAN output carries no forbidden
    /// reward token, and the serialized JSON keeps its no-`paid`/no-`payout` shape
    /// (the field is `#[serde(skip)]`).
    #[test]
    fn prl_snapshot_is_credit_only_in_human_and_json() {
        let disp = alice_miner_core::PrlPayoutDisplay::new(true, Some(PAYOUT_OK));
        let snap = prl_snapshot(disp);
        // Human render: no fiat / paid token (the masked wallet + honest text only).
        let human = render_snapshot(&snap);
        let lower = human.to_lowercase();
        for forbidden in ["$", "usd", "fiat", "paid", "earned", "已发放"] {
            assert!(!lower.contains(forbidden), "PRL human line leaked `{forbidden}`: {human}");
        }
        // JSON: prl_payout is skipped, so the wire shape carries no payout substring.
        let json = serde_json::to_string(&snap).expect("serialize");
        for forbidden in ["paid", "payout", "prl_payout", "masked"] {
            assert!(!json.contains(forbidden), "Snapshot JSON leaked `{forbidden}`: {json}");
        }
    }

    /// The detect render shows the model string, both lanes, and the recommended
    /// marker — and carries NO emoji (PLAN §6-i: model string only).
    #[test]
    fn detect_render_shows_matrix_no_emoji() {
        let cap = CapabilityProfile::detect();
        let s = render_detect(&cap);
        assert!(s.contains("Device:"));
        assert!(s.contains("Lanes:"));
        assert!(s.contains("CPU · XMR"));
        assert!(s.contains("GPU · RVN"));
        assert!(s.contains("(recommended)"));
        // No emoji: every char is ASCII or the few intentional non-ASCII glyphs
        // (the `·` middot, box-drawing). Assert there's no char in the emoji
        // ranges.
        for ch in s.chars() {
            let c = ch as u32;
            let is_emoji = (0x1F300..=0x1FAFF).contains(&c) || (0x2600..=0x27BF).contains(&c);
            assert!(!is_emoji, "detect output contains an emoji: {ch:?}");
        }
    }

    /// Polish #13: the lane-matrix support column must line up across rows even for
    /// the longest label "GPU · Alpha (V100)" — a fixed too-narrow pad truncated
    /// past it and broke the alignment. For each lane row we find the column where
    /// the support text starts (the char index past the label + its padding) and
    /// assert it's identical on every row.
    #[test]
    fn detect_matrix_columns_align_for_longest_label() {
        let cap = CapabilityProfile::detect();
        let s = render_detect(&cap);
        let mut starts = Vec::new();
        for line in s.lines() {
            for &lane in ALL_LANES.iter() {
                let prefix = format!("  {}", lane.label()); // "  " indent + label
                if line.starts_with(&prefix) {
                    // Char index of the first non-space AFTER the label = the column
                    // the support text starts at (must match across rows).
                    let chars: Vec<char> = line.chars().collect();
                    let label_len = prefix.chars().count();
                    let trailing_spaces =
                        chars[label_len..].iter().take_while(|c| **c == ' ').count();
                    starts.push(label_len + trailing_spaces);
                    break;
                }
            }
        }
        assert!(starts.len() >= 2, "expected ≥2 lane rows, got {}: {s}", starts.len());
        assert!(
            starts.iter().all(|c| *c == starts[0]),
            "support column must align across all lane rows, got {starts:?}: {s}"
        );
    }
}
