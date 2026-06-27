//! The headless **dashboard renderer** — pure `&T -> String` formatters for the
//! CLI's human output. Kept separate from `main.rs` so the credit-only honesty
//! gate (no `$`/fiat/`paid`/`earned`, no collection address / upstream pool /
//! core IP) is auditable in one place and unit-testable without an engine.
//!
//! Parity with the GUI dashboard (PLAN §5 M6): the SAME fields — state, per-lane
//! hashrate (H/s + a human kH/MH), accepted/rejected shares, accepted %,
//! endpoint, failovers, uptime — and the SAME honest reward wording ("pending ·
//! 待发放"). Every string here is presentation only; no mining logic.

use alice_miner_core::detect::capability::ALL_LANES;
use alice_miner_core::detect::GpuDevice;
use alice_miner_core::{CapabilityProfile, GpuInfo, GpuVendor, Lane, Snapshot};

/// The ONLY way the CLI ever renders rewards: pending, bilingual, never a
/// number / `$`. Mirrors the GUI's `strings::REWARD_PENDING`.
const REWARD_PENDING: &str = "pending · 待发放";

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
    for &lane in ALL_LANES.iter() {
        let support = cap.support(lane);
        let marker = if lane == recommended { "  (recommended)" } else { "" };
        out.push_str(&format!(
            "  {:<10} {}{}\n",
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

/// Render ONE live dashboard tick from a [`Snapshot`]. A compact, honest block:
/// state · hashrate (H/s + human) · shares A/R (+accepted%) · uptime · endpoint
/// · failovers · rewards pending. In dual-mine it appends a per-lane row each.
///
/// Honest by construction: rewards are only ["pending · 待发放"](REWARD_PENDING);
/// the endpoint shown is the PUBLIC relay carried in the snapshot — never the
/// collection address / upstream pool / core IP (those never reach the client).
pub fn render_snapshot(snap: &Snapshot) -> String {
    let mut out = String::new();

    let hr = fmt_hashrate(snap.hashrate_hs);
    let endpoint = snap.endpoint.as_deref().unwrap_or("—");
    let failover = if snap.failovers > 0 {
        format!(" · failed-over×{}", snap.failovers)
    } else {
        String::new()
    };
    let dual_tag = if snap.dual { " [dual]" } else { "" };
    let accepted_pct = fmt_accepted_pct(snap.shares_accepted, snap.shares_rejected);

    out.push_str(&format!(
        "[{}]{dual_tag} {hr} · shares {}A/{}R{} · up {} · {}{} · rewards {}\n",
        fmt_state(snap.state),
        snap.shares_accepted,
        snap.shares_rejected,
        accepted_pct,
        fmt_uptime(snap.uptime_s),
        endpoint,
        failover,
        REWARD_PENDING,
    ));

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

    // In dual mode, print each lane's own row so both lanes are visible.
    if snap.dual {
        for l in &snap.lanes {
            let lhr = fmt_hashrate(l.hashrate_hs);
            let lfo = if l.failovers > 0 {
                format!(" · failed-over×{}", l.failovers)
            } else {
                String::new()
            };
            out.push_str(&format!(
                "    └ {:<9} [{}] {lhr} · {}A/{}R · {}{}\n",
                l.lane.label(),
                fmt_state(l.state),
                l.shares_accepted,
                l.shares_rejected,
                l.endpoint.as_deref().unwrap_or("—"),
                lfo,
            ));
        }
    }

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
                    shares_accepted: 142,
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
    // pool / core IP. Rewards appear ONLY as "pending · 待发放". ──────────────────

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
        assert!(all.contains(REWARD_PENDING));

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
}
