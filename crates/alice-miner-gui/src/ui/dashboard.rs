//! Dashboard (mockup `03`) — live cards from the credit-only [`Snapshot`]:
//! hashrate, shares A/R, accepted %, est. rewards = **pending** (never a number
//! or `$`), the lane row, the connection (PUBLIC relay endpoint + derived
//! worker), and a small log tail. Honest by construction (rewards come only from
//! [`crate::ui::strings`]). Plus a minimal Settings view.

use eframe::egui::{self, RichText};

use super::change_addr;
use super::icons::Icon;
use super::strings;
use super::theme::THEME;
use super::widgets::{self, Tone};
use super::{lane_accent, lane_chip_label};
use crate::app::MinerApp;
use crate::update::UpdateUi;
use alice_miner_core::tr;
use alice_miner_core::{
    CreditState, CreditTotals, Lane, LaneSupport, Reconciliation, LANE_KEY_GPU_ALPHA,
    LANE_KEY_GPU_PRL,
};

/// One boxed stat-card painter, so the grid can lay the four cards out in either
/// one row of four or two rows of two without duplicating their bodies.
type CardFn<'a> = Box<dyn Fn(&mut egui::Ui) + 'a>;

pub fn render(ui: &mut egui::Ui, app: &mut MinerApp) {
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            // A 26px side inset (mockup `.dash` padding) + 22/28 top/bottom, applied
            // via a frame so the CONTENT width below is exact (no edge-to-edge spill
            // and no scrollbar-gutter ambiguity). Content is capped at 1000px and
            // left-indented to centre it so it never feels stretched on a wide
            // monitor; `dashboard_inner` computes the grid against `content_w`.
            egui::Frame::NONE
                .inner_margin(egui::Margin { left: 26, right: 26, top: 22, bottom: 28 })
                .show(ui, |ui| {
                    let avail = ui.available_width();
                    let content_w = avail.min(1000.0);
                    let indent = ((avail - content_w) * 0.5).max(0.0);
                    ui.horizontal(|ui| {
                        if indent > 0.0 {
                            ui.add_space(indent);
                        }
                        ui.allocate_ui_with_layout(
                            egui::vec2(content_w, ui.available_height()),
                            egui::Layout::top_down(egui::Align::Min),
                            |ui| {
                                ui.set_max_width(content_w);
                                dashboard_inner(ui, app);
                            },
                        );
                    });
                });
        });
}

fn dashboard_inner(ui: &mut egui::Ui, app: &mut MinerApp) {
    let snap = app.snapshot.clone();
    let mining = app.is_mining();
    // Cumulative accepted/rejected shares (used by several cards + the lane row).
    let (a, r) = snap
        .as_ref()
        .map(|s| (s.shares_accepted, s.shares_rejected))
        .unwrap_or((0, 0));

    // Header.
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(RichText::new(tr!("Dashboard", "仪表盘")).size(21.0).strong().color(THEME.text));
            let lane_label = lane_chip_label(app.active_lane());
            let sub = app
                .device
                .as_ref()
                .map(|d| format!("{} · {}", d.display, lane_label))
                .unwrap_or_else(|| lane_label.to_string());
            ui.label(RichText::new(sub).size(12.0).color(THEME.text3));
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let up = snap.as_ref().map(|s| fmt_uptime(s.uptime_s)).unwrap_or_else(|| "—".into());
            let (tone, blink) = if mining { (Tone::Live, app.motion_enabled()) } else { (Tone::Off, false) };
            egui::Frame::NONE
                .fill(egui::Color32::from_rgba_unmultiplied(tone.fg().r(), tone.fg().g(), tone.fg().b(), 22))
                .corner_radius(255)
                .inner_margin(egui::Margin::symmetric(12, 6))
                .stroke(egui::Stroke::new(1.0_f32, egui::Color32::from_rgba_unmultiplied(tone.fg().r(), tone.fg().g(), tone.fg().b(), 80)))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        widgets::status_dot(ui, tone.fg(), 8.0, blink);
                        ui.add_space(8.0);
                        let label = if mining { tr!("uptime", "运行时长") } else { tr!("idle", "空闲") };
                        ui.label(RichText::new(label).size(12.0).color(THEME.text2));
                        ui.add_space(4.0);
                        ui.label(widgets::mono(up, 12.0, THEME.text2));
                    });
                });
            // M5: the qualitative reconciliation badge (local activity vs
            // server-confirmed credit) — never a number, only an honest word.
            ui.add_space(8.0);
            reconciliation_badge(ui, app.reconciliation());
        });
    });

    ui.add_space(16.0);
    ui.painter().hline(
        ui.available_rect_before_wrap().x_range(),
        ui.cursor().top(),
        egui::Stroke::new(1.0_f32, THEME.line),
    );
    ui.add_space(18.0);

    // ── SOURCE A — local activity (what the miner is doing locally, NOT earnings).
    // Label it explicitly so the user (and the honesty audit) can never mistake
    // these live figures for confirmed earnings.
    source_label(ui, strings::activity_section(), strings::activity_caption(), Tone::Live);
    ui.add_space(12.0);

    // ── Stat grid (4 cards) ───────────────────────────────────────────────────
    // Reflows 1×4 → 2×2 when 4 cards would get too narrow (mockup
    // `@media(max-width:760px){repeat(2,1fr)}`), so all 4 — especially
    // "Est. rewards · pending" (honesty-critical) — are ALWAYS fully visible and
    // never spill past the right edge. The per-card frame inner margin (32px) is
    // subtracted so the CONTENT width passed to `stat_card` keeps the OUTER card
    // (content + margin) inside the available width.
    let total_w = ui.available_width();
    let gap = 13.0;
    // Per-card chrome eaten OUTSIDE the content width: 32px inner margin (16 each
    // side) + ~8px stroke/rounding/rounding-to-pixel slack measured empirically.
    // Subtracting the full budget keeps the OUTER card footprint inside `total_w`
    // so the row can never spill past the right edge (was clipping "Est. rewards").
    const CARD_CHROME_X: f32 = 40.0;
    /// Minimum comfortable CONTENT width before we wrap to two rows (enough for
    /// the "— pending" value + its "待发放 · rate pending" meta to read cleanly).
    const MIN_CARD_CONTENT: f32 = 172.0;
    let four_up_content = (total_w - gap * 3.0) / 4.0 - CARD_CHROME_X;
    let two_up = four_up_content < MIN_CARD_CONTENT;
    let cols = if two_up { 2.0 } else { 4.0 };
    // Floor so rounding never pushes the summed row past `total_w`.
    let card_w = (((total_w - gap * (cols - 1.0)) / cols - CARD_CHROME_X).floor()).max(96.0);
    // Shared minimum CONTENT height so all four cards are EQUAL height → the row has
    // one clean top AND bottom edge. Sized to the tallest card (Hashrate, which adds
    // a 26px sparkline under its value); the others pad up to match. Without this the
    // cards sized to their own content and read as a crooked descending staircase.
    const CARD_MIN_CONTENT_H: f32 = 84.0;

    let spark: Vec<f32> = app.spark.iter().cloned().collect();
    // The four card painters, in order. Boxed so we can lay them out in either
    // one row of four or two rows of two without duplicating the bodies.
    // Auto-scaled hashrate (kH/s for CPU-XMR … TH/s for GPU-PRL) — never a fixed
    // "kH/s" that turns a real ~0.87 TH/s pearlhash rate into a 9-digit number.
    let (hr_txt, hr_unit) = widgets::fmt_hashrate(app.hr_display_khs);
    let hr_val = if mining {
        widgets::mono(hr_txt.clone(), 25.0, THEME.text).strong()
    } else {
        widgets::mono("—", 25.0, THEME.text3)
    };
    let pct = if a + r > 0 {
        format!("{:.1}", a as f64 / (a + r) as f64 * 100.0)
    } else {
        "—".to_string()
    };
    // Reject-rate health for the "Accepted" card sub-label. Replaces the old
    // unconditional "rolling · healthy" (which read healthy at ANY reject ratio).
    // GPU-Alpha doesn't track rejects (parse_alpha → None, so r stays 0), so show an
    // honest "rejects n/a" there rather than a false 100%/healthy.
    //
    // SHOULD-FIX A: in dual-mine the summed `(a, r)` is XMR-dominated, so a high-reject
    // GPU lane is diluted to "healthy". `reject_health_sub` reads each lane's OWN
    // counters from the snapshot in dual mode and reports the WORST (highest-reject) GPU
    // lane. Single-lane reads the summed counters (sum == active lane), unchanged.
    let (rh_label, rh_tone) = reject_health_sub(snap.as_ref(), app.active_lane(), a, r);
    let (accepted_sub, accepted_sub_color): (String, egui::Color32) =
        (rh_label, rh_tone.color());
    // SHOULD-FIX B: AlphaMiner reports `hits` = SUBMITTED shares (it async-submits and
    // never logs a pool accept; acceptance is the relay's truth — see parse_alpha). So on
    // the GpuAlpha lane the third card is labelled "Submitted" with the COUNT (not an
    // "Accepted %" headline, which would imply a 100% accept rate we can't know). Every
    // other lane keeps the "Accepted" % headline. The reject-tone sub-label is already
    // suppressed to "rejects n/a" for GpuAlpha via `reject_health_sub`.
    let (accepted_title, accepted_headline) =
        accepted_card(mining, app.active_lane(), a, &pct);
    let cards: Vec<CardFn> = vec![
        // Hashrate (accent, with sparkline).
        Box::new({
            let spark = spark.clone();
            let hr_val = hr_val.clone();
            move |ui: &mut egui::Ui| {
                let spark_ref = &spark;
                widgets::stat_card(
                    ui,
                    card_w,
                    CARD_MIN_CONTENT_H,
                    tr!("Hashrate", "算力"),
                    hr_val.clone(),
                    None,
                    Some(THEME.lane_xmr),
                    Some(&move |ui: &mut egui::Ui| {
                        if spark_ref.is_empty() {
                            ui.label(RichText::new(hr_unit).size(11.0).color(THEME.text3));
                        } else {
                            widgets::sparkline(ui, spark_ref, ui.available_width().min(card_w - 4.0), 26.0);
                        }
                    }),
                );
            }
        }),
        // Shares A / R.
        Box::new(move |ui: &mut egui::Ui| {
            widgets::stat_card(
                ui,
                card_w,
                CARD_MIN_CONTENT_H,
                tr!("Shares A / R", "份额 接受/拒绝"),
                widgets::mono(format!("{a}"), 25.0, THEME.text).strong(),
                Some(widgets::mono(format!("/ {r} {}", tr!("rejected", "拒绝")), 11.5, THEME.text3)),
                None,
                None,
            );
        }),
        // Accepted % — or, on the GpuAlpha lane, the SUBMITTED count (SHOULD-FIX B).
        Box::new({
            let title = accepted_title;
            let headline = accepted_headline.clone();
            let sub = accepted_sub.clone();
            let sub_color = accepted_sub_color;
            move |ui: &mut egui::Ui| {
                widgets::stat_card(
                    ui,
                    card_w,
                    CARD_MIN_CONTENT_H,
                    title,
                    widgets::mono(headline.clone(), 25.0, THEME.text).strong(),
                    Some(RichText::new(sub.clone()).size(11.0).color(sub_color)),
                    None,
                    None,
                );
            }
        }),
        // Est. rewards — PENDING ONLY (never a number / $).
        Box::new(move |ui: &mut egui::Ui| {
            widgets::stat_card(
                ui,
                card_w,
                CARD_MIN_CONTENT_H,
                tr!("Est. rewards", "预计奖励"),
                RichText::new(strings::reward_pending_short()).size(20.0).strong().color(THEME.brand300),
                Some(RichText::new(strings::REWARD_RATE_PENDING).size(11.0).color(THEME.text3)),
                None,
                None,
            );
        }),
    ];

    let per_row = if two_up { 2 } else { 4 };
    // Each card lives in a FIXED-width cell so its Frame can't balloon to claim a
    // horizontal row's leftover space (egui's last-child-grabs-remainder trap).
    let cell_w = card_w + CARD_CHROME_X;
    for (row_i, row) in cards.chunks(per_row).enumerate() {
        if row_i > 0 {
            ui.add_space(gap);
        }
        // TOP-aligned row (cross-axis Align::Min): every card's top sits on the row
        // baseline. `ui.horizontal()` defaults to Align::Center, which — in egui's
        // single-pass immediate mode — centres each card against the *running* row
        // height and produces a descending staircase. Combined with the equal
        // `CARD_MIN_CONTENT_H` (one shared bottom edge), the four cards read as a
        // clean grid.
        ui.with_layout(egui::Layout::left_to_right(egui::Align::Min), |ui| {
            ui.spacing_mut().item_spacing.x = gap;
            for card in row {
                ui.allocate_ui_with_layout(
                    egui::vec2(cell_w, 0.0),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        ui.set_max_width(cell_w);
                        card(ui);
                    },
                );
            }
        });
    }

    // ── Lanes ─────────────────────────────────────────────────────────────────
    ui.add_space(22.0);
    widgets::section_label(ui, tr!("Lanes", "通道"));
    ui.add_space(10.0);
    // M4: in dual-mine BOTH lanes run, so read each lane's row from the snapshot's
    // per-lane breakdown (`snap.lanes`) when present. In single-lane mode only the
    // active lane is live (the existing behaviour).
    let dual = snap.as_ref().map(|s| s.dual).unwrap_or(false);
    let per_lane = |lane: Lane| -> Option<&alice_miner_core::engine::LaneSnapshot> {
        snap.as_ref().and_then(|s| s.lanes.iter().find(|l| l.lane == lane))
    };
    let xmr_ls = per_lane(Lane::Xmr);
    let prl_ls = per_lane(Lane::GpuPrl);
    // XMR row: live when dual (and it has a lane snapshot) OR single-XMR mining.
    let xmr_active = if dual {
        xmr_ls.map(|l| matches!(l.state, alice_miner_core::EngineState::Running | alice_miner_core::EngineState::Starting)).unwrap_or(false)
    } else {
        mining && app.active_lane() == Lane::Xmr
    };
    let (xmr_hr, xmr_sh) = lane_live_figures(app, dual, xmr_ls, xmr_active, (a, r));
    lane_row(
        ui,
        THEME.lane_xmr,
        "XMR · RandomX",
        &format!("· CPU · {} {}", app.device.as_ref().map(|d| d.logical_cores).unwrap_or(0), tr!("threads", "线程")),
        xmr_hr,
        xmr_sh,
        xmr_active,
    );
    // PRL row (the GPU mainline): live when dual (with a lane snapshot) OR
    // single-PRL mining. The role reflects the device's lane viability honestly:
    // "ready" on an NVIDIA/AMD box, "needs NVIDIA/AMD GPU" on Apple/CPU-only.
    let prl_active = if dual {
        prl_ls.map(|l| matches!(l.state, alice_miner_core::EngineState::Running | alice_miner_core::EngineState::Starting)).unwrap_or(false)
    } else {
        mining && app.active_lane() == Lane::GpuPrl
    };
    let prl_role = match app.lane_support(Lane::GpuPrl) {
        LaneSupport::Viable => tr!("· GPU · NVIDIA/AMD · ready", "· GPU · NVIDIA/AMD · 就绪"),
        LaneSupport::ComingSoon => tr!("· GPU · coming soon", "· GPU · 即将推出"),
        LaneSupport::Unavailable => tr!("· GPU · needs NVIDIA/AMD GPU", "· GPU · 需要 NVIDIA/AMD GPU"),
    };
    let (prl_hr, prl_sh) = lane_live_figures(app, dual, prl_ls, prl_active, (a, r));
    lane_row(
        ui,
        THEME.lane_gpu,
        "PRL · pearlhash",
        prl_role,
        prl_hr,
        prl_sh,
        prl_active,
    );

    // ── 15% PRL 返还 (A2c) — GPU-PRL mainline only. Rendered ONLY when the engine
    // attached a credit-only display block (primary lane == GPU-PRL). Shows the
    // bind status + the user's MASKED return wallet + an honest "pending" text;
    // never a number / "$" / paid figure (the block's `paid` is hard-pinned 0.0).
    if let Some(disp) = snap.as_ref().and_then(|s| s.prl_payout.clone()) {
        ui.add_space(24.0);
        source_label(ui, strings::PRL_RETURN_TITLE, strings::PRL_RETURN_CAPTION, Tone::Live);
        ui.add_space(10.0);
        prl_return_panel(ui, &disp);
    }

    // ── SOURCE B — server-confirmed credit (read-only). Clearly separated from
    // the live activity above; honest by construction (no fabricated number).
    ui.add_space(24.0);
    source_label(ui, strings::credit_section(), strings::credit_caption(), Tone::Off);
    ui.add_space(10.0);
    credit_panel(ui, app);

    // ── Connection ─────────────────────────────────────────────────────────────
    ui.add_space(22.0);
    widgets::section_label(ui, tr!("Connection", "连接"));
    ui.add_space(10.0);
    connection_panel(ui, app);

    // ── Log ─────────────────────────────────────────────────────────────────────
    ui.add_space(22.0);
    widgets::section_label(ui, tr!("Log", "日志"));
    ui.add_space(10.0);
    log_panel(ui, app);
}

/// The tone of the reject-health sub-label (mapped to a THEME colour at render).
/// A small enum (not a raw `Color32`) so [`reject_health_sub`] stays a pure,
/// testable function that doesn't depend on the egui theme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RejectTone {
    Neutral,
    Healthy,
    Elevated,
    High,
}

impl RejectTone {
    fn color(self) -> egui::Color32 {
        match self {
            RejectTone::Neutral => THEME.text3,
            RejectTone::Healthy => THEME.live,
            RejectTone::Elevated => THEME.warn,
            RejectTone::High => THEME.err,
        }
    }
}

/// The reject-health sub-label + tone for the "Accepted" card. Pure + testable.
///
/// SHOULD-FIX A: in **dual-mine** the summed `(sum_a, sum_r)` is XMR-dominated, so a
/// high-reject GPU lane would dilute to "healthy". So in dual mode this reads each
/// lane's OWN counters from the snapshot and reports the WORST (highest reject-rate)
/// GPU/PRL-earning lane — a degrading GPU lane is flagged even while XMR is clean. A
/// GpuAlpha lane reports "rejects n/a" (the client never sees a pool reject; the relay
/// owns acceptance). In **single-lane** mode the summed counters equal the active lane,
/// so it falls back to the prior summed behaviour (identical output).
fn reject_health_sub(
    snap: Option<&alice_miner_core::engine::Snapshot>,
    active_lane: Lane,
    sum_a: u64,
    sum_r: u64,
) -> (String, RejectTone) {
    let dual = snap.map(|s| s.dual).unwrap_or(false);
    if dual {
        // The PRL-earning GPU lanes that are actually producing (have shares). Pick the
        // worst reject-rate among them; if the only producing GPU lane is GpuAlpha (no
        // reject signal), say so honestly.
        let gpu_lanes: Vec<&alice_miner_core::engine::LaneSnapshot> = snap
            .map(|s| {
                s.lanes
                    .iter()
                    .filter(|l| l.lane.is_prl_lane() && l.shares_accepted + l.shares_rejected > 0)
                    .collect()
            })
            .unwrap_or_default();
        if gpu_lanes.is_empty() {
            return ("no shares yet".to_string(), RejectTone::Neutral);
        }
        // If EVERY producing GPU lane is GpuAlpha (rejects untracked), the reject signal
        // is genuinely n/a.
        if gpu_lanes.iter().all(|l| l.lane == Lane::GpuAlpha) {
            return ("rejects n/a".to_string(), RejectTone::Neutral);
        }
        // Worst reject-rate among the reject-tracking GPU lanes.
        let worst = gpu_lanes
            .iter()
            .filter(|l| l.lane != Lane::GpuAlpha)
            .map(|l| {
                let total = l.shares_accepted + l.shares_rejected;
                l.shares_rejected as f64 / total as f64 * 100.0
            })
            .fold(0.0_f64, f64::max);
        return classify_reject_pct(worst);
    }
    // Single-lane: the summed counters ARE the active lane's.
    if sum_a + sum_r == 0 {
        return ("no shares yet".to_string(), RejectTone::Neutral);
    }
    if active_lane == Lane::GpuAlpha {
        return ("rejects n/a".to_string(), RejectTone::Neutral);
    }
    classify_reject_pct(sum_r as f64 / (sum_a + sum_r) as f64 * 100.0)
}

/// The third stat card's (title, headline). Pure + testable.
///
/// SHOULD-FIX B: AlphaMiner's `hits` is a SUBMITTED-share count (the client never sees a
/// pool accept; the relay owns acceptance — see `stats::parse_alpha`). So on the GpuAlpha
/// lane the card is "Submitted" + the raw COUNT, suppressing the "Accepted %" headline
/// (which would imply a 100% accept rate we can't know). Every other lane keeps
/// "Accepted" + the `pct%` headline.
fn accepted_card(mining: bool, active_lane: Lane, accepted: u64, pct: &str) -> (&'static str, String) {
    if mining && active_lane == Lane::GpuAlpha {
        (tr!("Submitted", "已提交"), format!("{accepted}"))
    } else {
        (tr!("Accepted", "已接受"), format!("{pct}%"))
    }
}

/// Map a reject percentage to the (label, tone) the "Accepted" card shows.
fn classify_reject_pct(reject_pct: f64) -> (String, RejectTone) {
    if reject_pct <= 5.0 {
        ("rolling · healthy".to_string(), RejectTone::Healthy)
    } else if reject_pct <= 20.0 {
        (format!("{reject_pct:.0}% rejects · elevated"), RejectTone::Elevated)
    } else {
        (format!("{reject_pct:.0}% rejects · high"), RejectTone::High)
    }
}

/// The (hashrate kH/s, shares) to show for a lane row. In dual-mine each lane
/// shows its OWN per-lane figures from the snapshot (so the two rows are
/// independent); in single-lane mode the active lane uses the smoothed display
/// hashrate + the top-level shares (the existing behaviour).
fn lane_live_figures(
    app: &MinerApp,
    dual: bool,
    ls: Option<&alice_miner_core::engine::LaneSnapshot>,
    active: bool,
    single_shares: (u64, u64),
) -> (Option<f32>, (u64, u64)) {
    if dual {
        match ls {
            Some(l) if active => (
                l.hashrate_hs.map(|h| (h / 1000.0) as f32),
                (l.shares_accepted, l.shares_rejected),
            ),
            _ => (None, (0, 0)),
        }
    } else if active {
        (Some(app.hr_display_khs), single_shares)
    } else {
        (None, (0, 0))
    }
}

fn lane_row(
    ui: &mut egui::Ui,
    accent: egui::Color32,
    name: &str,
    role: &str,
    hr_khs: Option<f32>,
    shares: (u64, u64),
    live: bool,
) {
    let resp = egui::Frame::NONE
        .fill(THEME.surface)
        .corner_radius(14)
        .inner_margin(egui::Margin::symmetric(15, 13))
        .stroke(egui::Stroke::new(1.0_f32, THEME.line))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let dim = !live;
                let (rdot, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
                ui.painter().circle_filled(rdot.center(), 4.0, if dim { THEME.off } else { accent });
                ui.add_space(8.0);
                ui.label(RichText::new(name).size(13.0).strong().color(if dim { THEME.text3 } else { THEME.text }));
                ui.add_space(8.0);
                ui.label(RichText::new(role).size(12.0).color(THEME.text3));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if live {
                        ui.label(RichText::new(tr!("live", "实时")).size(11.0).color(THEME.text2));
                    } else {
                        ui.label(RichText::new(tr!("off", "关闭")).size(11.0).color(THEME.text4));
                    }
                    ui.add_space(12.0);
                    let sh = if live || shares.0 + shares.1 > 0 {
                        format!("{} / {}", shares.0, shares.1)
                    } else {
                        "— / —".into()
                    };
                    ui.label(widgets::mono(sh, 12.0, if dim { THEME.text4 } else { THEME.text2 }));
                    ui.add_space(16.0);
                    let hr = hr_khs
                        .map(|h| {
                            let (v, u) = widgets::fmt_hashrate(h);
                            format!("{v} {u}")
                        })
                        .unwrap_or_else(|| "—".into());
                    ui.label(widgets::mono(hr, 12.0, if dim { THEME.text4 } else { THEME.text }));
                });
            });
        });
    // Left accent bar.
    let r = resp.response.rect;
    ui.painter().rect_filled(
        egui::Rect::from_min_max(r.left_top(), egui::pos2(r.left() + 3.0, r.bottom())),
        0.0,
        if live { accent } else { THEME.off },
    );
    ui.add_space(9.0);
}

fn connection_panel(ui: &mut egui::Ui, app: &mut MinerApp) {
    let snap = app.snapshot.clone();
    // The PUBLIC relay endpoint only (never the upstream pool / collection addr).
    // M3 follow-up: while idle this reflects the SELECTED lane's port (:3333 XMR /
    // :8888 RVN) — not a hardcoded :3333 — via `display_endpoint()`.
    let endpoint = app.display_endpoint();
    let worker = snap.as_ref().and_then(|s| s.worker_id.clone());
    let connected = app.is_mining();
    let motion = app.motion_enabled();

    egui::Frame::NONE
        .fill(THEME.surface)
        .corner_radius(14)
        .inner_margin(egui::Margin::symmetric(16, 15))
        .stroke(egui::Stroke::new(1.0_f32, THEME.line))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            egui::Grid::new("conn-grid")
                .num_columns(2)
                .spacing(egui::vec2(20.0, 12.0))
                .show(ui, |ui| {
                    kv_key(ui, tr!("Endpoint", "节点"));
                    ui.horizontal(|ui| {
                        ui.label(widgets::mono(endpoint, 13.0, THEME.text));
                        // M4: a "failed over" note when Layer B has rotated the
                        // endpoint cursor this run (so the user knows the active
                        // endpoint differs from the primary).
                        let failovers = snap.as_ref().map(|s| s.failovers).unwrap_or(0);
                        if failovers > 0 {
                            ui.add_space(8.0);
                            egui::Frame::NONE
                                .fill(egui::Color32::from_rgba_unmultiplied(THEME.warn.r(), THEME.warn.g(), THEME.warn.b(), 26))
                                .corner_radius(6)
                                .inner_margin(egui::Margin::symmetric(7, 2))
                                .show(ui, |ui| {
                                    let label = if failovers == 1 {
                                        tr!("failed over", "已故障切换").to_string()
                                    } else {
                                        format!("{} ×{failovers}", tr!("failed over", "已故障切换"))
                                    };
                                    ui.label(RichText::new(label).size(10.5).color(THEME.warn));
                                });
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let (tone, label) = if connected {
                                (Tone::Live, tr!("connected", "已连接"))
                            } else {
                                (Tone::Off, tr!("not connected", "未连接"))
                            };
                            widgets::status_dot(ui, tone.fg(), 8.0, connected && motion);
                            ui.add_space(8.0);
                            ui.label(RichText::new(label).size(12.0).color(THEME.text2));
                        });
                    });
                    ui.end_row();

                    kv_key(ui, tr!("Worker", "矿工"));
                    ui.horizontal(|ui| {
                        let w = worker.clone().map(|w| widgets::shorten(&w)).unwrap_or_else(|| "—".into());
                        ui.label(widgets::mono(format!("rig-{w}"), 13.0, THEME.text));
                        ui.label(RichText::new(tr!("· rig-id derived", "· 由地址派生")).size(12.0).color(THEME.text4));
                        if let Some(addr) = app.reward_address() {
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                let copy = egui::Button::new(RichText::new(tr!("copy address", "复制地址")).size(11.0).color(THEME.text3))
                                    .fill(egui::Color32::TRANSPARENT)
                                    .stroke(egui::Stroke::new(1.0_f32, THEME.line))
                                    .corner_radius(8);
                                if ui.add(copy).clicked() {
                                    ui.ctx().copy_text(addr.clone());
                                    app.copied_at = Some(std::time::Instant::now());
                                }
                            });
                        }
                    });
                    ui.end_row();
                });
        });
}

fn kv_key(ui: &mut egui::Ui, key: &str) {
    ui.label(
        RichText::new(key.to_uppercase())
            .size(10.0)
            .extra_letter_spacing(1.2)
            .strong()
            .color(THEME.text3),
    );
}

/// A two-line SOURCE header (M5): a small dot + bold title + a caption underneath,
/// with a trailing rule. Used to clearly delineate **Source A (local activity)**
/// from **Source B (server-confirmed credit)** so the two are never blurred.
fn source_label(ui: &mut egui::Ui, title: &str, caption: &str, tone: Tone) {
    ui.horizontal(|ui| {
        let (dot, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
        ui.painter().circle_filled(dot.center(), 4.0, tone.fg());
        ui.add_space(8.0);
        ui.label(RichText::new(title).size(13.0).strong().color(THEME.text));
        ui.add_space(10.0);
        ui.label(RichText::new(caption).size(11.0).color(THEME.text3));
        // Trailing rule.
        let (rect, _) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 1.0), egui::Sense::hover());
        ui.painter().hline(rect.x_range(), rect.center().y, egui::Stroke::new(1.0_f32, THEME.line));
    });
}

/// The qualitative reconciliation badge (M5): a tinted pill reading a single
/// honest word ("in sync" / "confirming…" / "activity flowing" / "unconfirmed").
/// Never a number/percentage/amount. Tone: green when in-sync/confirmed, warn on
/// a Source-B fault, neutral otherwise.
fn reconciliation_badge(ui: &mut egui::Ui, recon: Reconciliation) {
    let tone = if recon.is_positive() {
        Tone::Live
    } else if recon.is_warn() {
        Tone::Warn
    } else {
        Tone::Off
    };
    let fg = tone.fg();
    egui::Frame::NONE
        .fill(egui::Color32::from_rgba_unmultiplied(fg.r(), fg.g(), fg.b(), 22))
        .corner_radius(255)
        .inner_margin(egui::Margin::symmetric(11, 6))
        .stroke(egui::Stroke::new(1.0_f32, egui::Color32::from_rgba_unmultiplied(fg.r(), fg.g(), fg.b(), 80)))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 7.0;
                ui.label(RichText::new(strings::reconcile_prefix()).size(10.0).color(THEME.text3));
                ui.label(RichText::new(recon.label()).size(11.0).strong().color(fg));
            });
        });
}

/// SOURCE B — the server-confirmed credit panel (M5). For v1 this renders the
/// honest [`CreditState::NotExposed`] panel (credit accounting is live, payout is
/// off, the per-address total isn't exposed here yet) with an explorer deep-link
/// and ZERO server dependency. The other variants are handled so the fast-follow
/// (a live public read-model endpoint) needs no UI change — and the value, when
/// present, is rendered ONLY as "pending" (never a number/`$`).
fn credit_panel(ui: &mut egui::Ui, app: &MinerApp) {
    let state = app.credit_state.clone();
    egui::Frame::NONE
        .fill(THEME.surface)
        .corner_radius(14)
        .inner_margin(egui::Margin::symmetric(16, 15))
        .stroke(egui::Stroke::new(1.0_f32, THEME.line))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            match &state {
                CreditState::NotExposed => {
                    // The honest Option-3 panel.
                    ui.horizontal(|ui| {
                        super::icons::show(ui, Icon::Globe, 14.0, THEME.brand300);
                        ui.add_space(9.0);
                        ui.label(
                            RichText::new(strings::credit_notexposed_title())
                                .size(13.5)
                                .strong()
                                .color(THEME.text),
                        );
                        // The pending tag on the right (no number).
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            pending_chip(ui);
                        });
                    });
                    ui.add_space(8.0);
                    ui.label(RichText::new(strings::credit_notexposed_body_1()).size(12.0).color(THEME.text2));
                    ui.add_space(3.0);
                    ui.label(RichText::new(strings::credit_notexposed_body_2()).size(12.0).color(THEME.text3));
                    ui.add_space(12.0);
                    explorer_link(ui);
                }
                CreditState::Confirming => {
                    credit_status_row(
                        ui,
                        Tone::Off,
                        strings::credit_section(),
                        strings::CREDIT_CONFIRMING,
                        app.motion_enabled(),
                    );
                    ui.add_space(10.0);
                    explorer_link(ui);
                }
                CreditState::Confirmed { score, totals, payout } => {
                    // CREDIT-ONLY: the `pending_alice` MAGNITUDE (`score`) is never
                    // rendered as a number ($-trap) — it stays "pending · 待发放". What
                    // we DO surface is the cumulative accepted-share COUNTS (counts are
                    // SHARE COUNTS, not money): the headline total, the 24h count, and
                    // the GPU·Alpha / GPU·PRL split.
                    let _ = score; // deliberately NOT rendered as a number
                    credit_cumulative_panel(ui, totals, app.motion_enabled());
                    // v0.6.0: once real-money payout is live, show the honest
                    // settled/paid figures below the counts. In the credit-only phase
                    // (`payout` is None) nothing extra renders.
                    if let Some(p) = payout {
                        ui.add_space(10.0);
                        credit_payout_panel(ui, p);
                    }
                    ui.add_space(10.0);
                    explorer_link(ui);
                }
                CreditState::UpgradeRequired { min_supported, download_url } => {
                    // v0.6.0 upgrade banner: the server requires a newer client.
                    upgrade_banner(ui, min_supported, download_url);
                }
                CreditState::Error { reason } => {
                    // A calm, NON-numeric fault note; Source A stays the live UX.
                    credit_status_row(
                        ui,
                        Tone::Warn,
                        strings::credit_section(),
                        strings::CREDIT_UNCONFIRMED,
                        false,
                    );
                    ui.add_space(6.0);
                    ui.label(RichText::new(reason.message()).size(11.5).color(THEME.text3));
                    ui.add_space(10.0);
                    explorer_link(ui);
                }
            }
        });
}

/// The GPU-PRL **15% PRL 返还** panel (A2c). Credit-only by construction: it shows
/// the bind STATUS (a pill, no number), the user's OWN return wallet **masked**
/// (`prl1p…`, never the foundation collection address), and an honest pending body
/// — never a number, never a "$", never a paid/earned claim. The display block's
/// `paid` field is hard-pinned 0.0 upstream and is NOT rendered here at all.
fn prl_return_panel(ui: &mut egui::Ui, disp: &alice_miner_core::PrlPayoutDisplay) {
    egui::Frame::NONE
        .fill(THEME.surface)
        .corner_radius(14)
        .inner_margin(egui::Margin::symmetric(16, 15))
        .stroke(egui::Stroke::new(1.0_f32, THEME.line))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            // Header row: a globe + the PRL currency label + a right-aligned status
            // pill (bound / pending). The status mirrors the engine's enroll flag.
            ui.horizontal(|ui| {
                super::icons::show(ui, Icon::Globe, 14.0, THEME.brand300);
                ui.add_space(9.0);
                ui.label(
                    RichText::new(format!("{} · 15% 返还", disp.currency))
                        .size(13.5)
                        .strong()
                        .color(THEME.text),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if disp.enrolled {
                        status_pill(ui, Tone::Live, strings::PRL_RETURN_ENROLLED);
                    } else {
                        pending_chip(ui);
                    }
                });
            });

            // The user's MASKED return wallet (only when one is configured). This is
            // THEIR wallet, masked — confirms "this is mine" without exposing the full
            // address in a screenshot. Never the collection address.
            if let Some(masked) = disp.payout_masked.as_deref() {
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(strings::PRL_RETURN_ADDR_LABEL).size(11.0).color(THEME.text3),
                    );
                    ui.add_space(8.0);
                    ui.label(widgets::mono(masked.to_string(), 12.0, THEME.text2));
                });
            }

            // The honest pending body — bound / unbound / no-address. No numbers.
            ui.add_space(8.0);
            let body = if disp.enrolled {
                strings::prl_return_body_bound()
            } else if disp.payout_masked.is_some() {
                strings::PRL_RETURN_BODY_UNBOUND
            } else {
                strings::PRL_RETURN_BODY_NOADDR
            };
            ui.label(RichText::new(body).size(12.0).color(THEME.text3));
        });
}

/// A small tinted status pill (a single honest word; never a number). Used by the
/// PRL-return header for the "bound · 已绑定" state.
fn status_pill(ui: &mut egui::Ui, tone: Tone, label: &str) {
    let fg = tone.fg();
    egui::Frame::NONE
        .fill(egui::Color32::from_rgba_unmultiplied(fg.r(), fg.g(), fg.b(), 22))
        .corner_radius(255)
        .inner_margin(egui::Margin::symmetric(10, 4))
        .stroke(egui::Stroke::new(1.0_f32, egui::Color32::from_rgba_unmultiplied(fg.r(), fg.g(), fg.b(), 70)))
        .show(ui, |ui| {
            ui.label(RichText::new(label).size(11.0).strong().color(fg));
        });
}

/// A small "pending · 待发放" chip (brand-tinted) — the ONLY way a credit value is
/// shown (never a number/`$`).
fn pending_chip(ui: &mut egui::Ui) {
    egui::Frame::NONE
        .fill(egui::Color32::from_rgba_unmultiplied(THEME.brand.r(), THEME.brand.g(), THEME.brand.b(), 22))
        .corner_radius(255)
        .inner_margin(egui::Margin::symmetric(10, 4))
        .stroke(egui::Stroke::new(1.0_f32, egui::Color32::from_rgba_unmultiplied(THEME.brand.r(), THEME.brand.g(), THEME.brand.b(), 70)))
        .show(ui, |ui| {
            ui.label(RichText::new(strings::CREDIT_PENDING_VALUE).size(11.0).strong().color(THEME.brand300));
        });
}

/// A one-line credit status row: a (optionally blinking) dot + a title + a
/// right-aligned status word.
fn credit_status_row(ui: &mut egui::Ui, tone: Tone, title: &str, status: &str, blink: bool) {
    ui.horizontal(|ui| {
        widgets::status_dot(ui, tone.fg(), 8.0, blink);
        ui.add_space(9.0);
        ui.label(RichText::new(title).size(13.0).strong().color(THEME.text));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(RichText::new(status).size(12.0).color(tone.fg()));
        });
    });
}

/// The cumulative server-confirmed credit panel (Source B, `Confirmed`). Renders
/// the accepted-share COUNTS — credit-only by construction (these are SHARE COUNTS,
/// not money): the headline total, the 24h count, and the GPU·Alpha / GPU·PRL split.
/// A real server 0 is shown as 0 (a measured zero); the `pending_alice` magnitude is
/// NEVER rendered (it stays "pending · 待发放" via the pending chip).
fn credit_cumulative_panel(ui: &mut egui::Ui, totals: &CreditTotals, motion: bool) {
    // Header: a live dot + the title + the pending chip (the ONLY "value" framing).
    ui.horizontal(|ui| {
        widgets::status_dot(ui, Tone::Live.fg(), 8.0, motion);
        ui.add_space(9.0);
        ui.label(
            RichText::new(strings::credit_cumulative_title())
                .size(13.0)
                .strong()
                .color(THEME.text),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            pending_chip(ui);
        });
    });
    ui.add_space(10.0);
    // The cumulative accepted-share COUNT (the headline number — a count, not money).
    credit_count_row(ui, strings::CREDIT_CUMULATIVE_TOTAL_LABEL, totals.accepted_total);
    ui.add_space(4.0);
    credit_count_row(ui, strings::CREDIT_CUMULATIVE_24H_LABEL, totals.accepted_24h);

    // The per-lane split (GPU·Alpha / GPU·PRL) — only when the server reports those
    // lanes (else just the headline; never fabricate a lane row).
    let alpha = totals.accepted_for_lane(LANE_KEY_GPU_ALPHA);
    let prl = totals.accepted_for_lane(LANE_KEY_GPU_PRL);
    if alpha > 0 || prl > 0 {
        ui.add_space(9.0);
        ui.label(
            RichText::new(strings::CREDIT_CUMULATIVE_LANES_LABEL)
                .size(10.5)
                .color(THEME.text3),
        );
        ui.add_space(4.0);
        credit_count_row(ui, "GPU · Alpha", alpha);
        ui.add_space(3.0);
        credit_count_row(ui, "GPU · PRL", prl);
    }
}

/// A single "label … N" count row (mono number, right-aligned). The number is an
/// accepted-share COUNT — never a fiat figure. Used by the cumulative-credit panel.
fn credit_count_row(ui: &mut egui::Ui, label: &str, count: u64) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(label).size(12.0).color(THEME.text2));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(widgets::mono(count.to_string(), 13.0, THEME.text));
        });
    });
}

/// The explorer deep-link (PUBLIC apex — never an internal/core host). A ghost
/// button that opens the explorer where the user can look up their address.
fn explorer_link(ui: &mut egui::Ui) {
    let btn = egui::Button::new(
        RichText::new(strings::CREDIT_EXPLORER_LABEL).size(12.0).color(THEME.text2),
    )
    .fill(THEME.well)
    .stroke(egui::Stroke::new(1.0_f32, THEME.line_strong))
    .corner_radius(9);
    if ui.add(btn).on_hover_text(strings::CREDIT_EXPLORER_URL).clicked() {
        ui.ctx().open_url(egui::OpenUrl::new_tab(strings::CREDIT_EXPLORER_URL));
    }
}

/// **v0.6.0 real-money payout sub-panel** (`Confirmed` with a live [`PayoutView`]).
/// Shows the HONEST settled / paid ALICE figures the server reports (`—` where a
/// figure is absent), with an explorer self-verify hint. Only ever rendered from a
/// self-consistent payout envelope (rails on, figures finite & non-negative). The
/// figures ARE real numbers here — that is the whole point of payout-awareness — but
/// they are ONLY the server's own settled/paid values, never a fabricated estimate.
fn credit_payout_panel(ui: &mut egui::Ui, p: &alice_miner_core::PayoutView) {
    let fmt = |v: Option<f64>| v.map(|x| format!("{x}")).unwrap_or_else(|| "—".to_string());
    egui::Frame::NONE
        .fill(THEME.well)
        .corner_radius(12)
        .inner_margin(egui::Margin::symmetric(14, 12))
        .stroke(egui::Stroke::new(1.0_f32, THEME.line_strong))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                widgets::status_dot(ui, Tone::Live.fg(), 8.0, false);
                ui.add_space(9.0);
                ui.label(
                    RichText::new(strings::CREDIT_PAYOUT_TITLE).size(13.0).strong().color(THEME.text),
                );
            });
            ui.add_space(8.0);
            // settled / paid ALICE — the server's own figures.
            credit_amount_row(ui, strings::CREDIT_PAYOUT_SETTLED_LABEL, &fmt(p.settled_alice));
            ui.add_space(4.0);
            credit_amount_row(ui, strings::CREDIT_PAYOUT_PAID_LABEL, &fmt(p.paid_alice));
            ui.add_space(9.0);
            ui.label(RichText::new(strings::CREDIT_PAYOUT_VERIFY_HINT).size(10.5).color(THEME.text3));
            ui.add_space(6.0);
            explorer_link(ui);
        });
}

/// A single "label … value ALICE" amount row (mono value, right-aligned). Used by the
/// payout sub-panel; the value is the server's own settled/paid figure (or `—`).
fn credit_amount_row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(label).size(12.0).color(THEME.text2));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(widgets::mono(format!("{value} ALICE"), 13.0, THEME.text));
        });
    });
}

/// **v0.6.0 upgrade banner** (`CreditState::UpgradeRequired`). The server advertised a
/// minimum client version this build does not meet; mining continues but the user must
/// update to keep participating once payout is live. A warn-toned card + a "get the
/// update" button that opens the download page.
fn upgrade_banner(ui: &mut egui::Ui, min_supported: &str, download_url: &str) {
    let fg = Tone::Warn.fg();
    ui.horizontal(|ui| {
        super::icons::show(ui, Icon::Globe, 14.0, fg);
        ui.add_space(9.0);
        ui.label(RichText::new(strings::CREDIT_UPGRADE_TITLE).size(13.5).strong().color(THEME.text));
    });
    ui.add_space(8.0);
    ui.label(
        RichText::new(format!("{} v{min_supported}+.", strings::CREDIT_UPGRADE_BODY))
            .size(12.0)
            .color(THEME.text2),
    );
    ui.add_space(12.0);
    let btn = egui::Button::new(RichText::new(strings::CREDIT_UPGRADE_CTA).size(12.0).color(THEME.text))
        .fill(THEME.well)
        .stroke(egui::Stroke::new(1.0_f32, egui::Color32::from_rgba_unmultiplied(fg.r(), fg.g(), fg.b(), 90)))
        .corner_radius(9);
    // AM-SEC-006 defense in depth: the URL originated with the read API, and this is
    // the exact moment it becomes an OS-level "open this site" action. Re-run the
    // host allowlist here rather than trusting that the producer already did — an
    // unallowlisted value silently becomes the built-in official releases page.
    let target = alice_miner_core::dashboard::download_url_allowed(download_url)
        .unwrap_or_else(|| alice_miner_core::dashboard::RELEASES_PAGE_DEFAULT.to_string());
    if ui.add(btn).on_hover_text(target.clone()).clicked() {
        ui.ctx().open_url(egui::OpenUrl::new_tab(target));
    }
}

fn log_panel(ui: &mut egui::Ui, app: &MinerApp) {
    egui::Frame::NONE
        .fill(THEME.well)
        .corner_radius(14)
        .inner_margin(egui::Margin::symmetric(16, 14))
        .stroke(egui::Stroke::new(1.0_f32, THEME.line_strong))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.set_min_height(60.0);
            if app.log.is_empty() {
                ui.label(widgets::mono(tr!("waiting for engine output…", "正在等待引擎输出…"), 11.5, THEME.text4));
            } else {
                egui::ScrollArea::vertical()
                    .max_height(166.0)
                    .auto_shrink([false, false])
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for (i, line) in app.log.iter().enumerate() {
                            let hot = i + 1 == app.log.len();
                            ui.label(widgets::mono(
                                line.clone(),
                                11.5,
                                if hot { THEME.text2 } else { THEME.text4 },
                            ));
                        }
                    });
            }
        });
}

fn fmt_uptime(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

// ── Settings (minimal, honest) ────────────────────────────────────────────────

pub fn render_settings(ui: &mut egui::Ui, app: &mut MinerApp) {
    // Lazily read the stored 15%-PRL return address (masked) once, so the Identity
    // panel can show it without a per-frame file read.
    if !app.prl_payout_loaded {
        app.load_prl_payout();
    }
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.add_space(22.0);
            ui.set_max_width(1000.0);
            ui.label(RichText::new(tr!("Settings", "设置")).size(21.0).strong().color(THEME.text));
            ui.label(RichText::new(tr!("The product resists knobs — only what matters.", "产品拒绝繁琐旋钮 —— 只保留真正重要的。")).size(12.0).color(THEME.text3));
            ui.add_space(16.0);

            // Mining panel.
            panel(ui, tr!("Mining", "挖矿"), Icon::Activity, |ui| {
                srow(ui, tr!("Worker threads", "工作线程"), tr!("Mining runs at full power (拉满) only while you've pressed Start.", "只有在你点击 Start 后,挖矿才会全力(拉满)运行。"), |ui| {
                    let n = app.device.as_ref().map(|d| d.logical_cores).unwrap_or(0);
                    ui.label(widgets::mono(format!("{n} {}", tr!("threads", "线程")), 13.0, THEME.text));
                });
                srow(ui, tr!("Lane", "通道"), tr!("Auto picks the best lane for your device. XMR uses the CPU (RandomX); PRL uses an NVIDIA/AMD GPU (pearlhash).", "Auto 会为你的设备自动选择最佳通道。XMR 使用 CPU(RandomX);PRL 使用 NVIDIA/AMD GPU(pearlhash)。"), |ui| {
                    let lane = app.active_lane();
                    widgets::chip(ui, Some(lane_accent(lane)), lane_chip_label(lane));
                });
            });

            // Network panel.
            panel(ui, tr!("Network", "网络"), Icon::Globe, |ui| {
                srow(ui, tr!("Endpoint", "节点"), tr!("Primary relay. The client handles failover automatically.", "主中继节点。客户端会自动处理故障切换。"), |ui| {
                    // Lane-aware while idle (:3333 XMR / :8888 RVN) — see
                    // `display_endpoint()` (the M3 follow-up fix).
                    let ep = app.display_endpoint();
                    ui.horizontal(|ui| {
                        ui.label(widgets::mono(ep, 12.5, THEME.text2));
                        ui.label(RichText::new(tr!("read-only", "只读")).size(10.0).extra_letter_spacing(0.8).color(THEME.text4));
                    });
                });
                // Region status (GPU-PRL only) — the effective region MODE: LOCKED to one
                // region (no auto-failover) vs preferred/nearest primary with failover on.
                // Read-only; the lock is set from the CLI (`start --region <tag>`).
                if app.active_lane() == Lane::GpuPrl {
                    let region = app.region_status_label();
                    srow(
                        ui,
                        tr!("Region", "区域"),
                        tr!(
                            "Auto picks the nearest region and fails over. Lock one with `start --region us|asia|eu`.",
                            "Auto 会选择最近的区域并自动故障切换。用 `start --region us|asia|eu` 锁定某个区域。"
                        ),
                        |ui| {
                            ui.horizontal(|ui| {
                                ui.label(widgets::mono(region, 12.5, THEME.text2));
                                ui.label(RichText::new(tr!("read-only", "只读")).size(10.0).extra_letter_spacing(0.8).color(THEME.text4));
                            });
                        },
                    );
                }
            });

            // Background-mining panel — keep mining after the window closes / at
            // login (macOS launchd backend today; the toggle is shown "coming
            // soon" off macOS). The CPU-XMR lane runs with no stored secret.
            render_background_panel(ui, app);

            // Software-update panel — the USER-INITIATED signed self-updater
            // (ed25519 manifest + SHA-256 artifact + atomic swap with rollback;
            // the keystore is never touched). v1 never silent-applies: a check
            // only surfaces a state, and the user presses "Update now" to apply.
            render_update_panel(ui, app);

            // Appearance panel (reduced motion, language).
            panel(ui, tr!("Appearance", "外观"), Icon::Activity, |ui| {
                let mut rm = app.reduce_motion;
                srow(
                    ui,
                    tr!("Reduce motion", "减少动效"),
                    tr!("Turns off the breathing glow, gauge sweep and number tween. Colours and states stay.", "关闭呼吸光晕、仪表扫描和数字渐变。颜色与状态保持不变。"),
                    |ui| {
                        if widgets::toggle(ui, rm).clicked() {
                            rm = !rm;
                        }
                    },
                );
                app.reduce_motion = rm;
                let mut zh = app.lang_zh;
                srow(ui, "Language · 语言", tr!("Interface language. Numbers stay mono in both.", "界面语言。两种语言下数字都保持等宽显示。"), |ui| {
                    ui.horizontal(|ui| {
                        if lang_seg(ui, "EN", !zh).clicked() {
                            zh = false;
                        }
                        ui.add_space(2.0);
                        if lang_seg(ui, "中文", zh).clicked() {
                            zh = true;
                        }
                    });
                });
                app.lang_zh = zh;
            });

            // Identity panel — the active reward address (with a copy affordance +
            // a keystore-backed / watch-only tag) and a "Change reward address"
            // action that opens the post-onboarding change flow. The action is
            // disabled while mining (the reward target can't be re-keyed under a
            // running lane); the hint says why.
            let mining = app.is_mining();
            panel(ui, tr!("Identity", "身份"), Icon::Eye, |ui| {
                srow(ui, tr!("Reward address", "奖励地址"), tr!("Your own Alice address. Rewards accrue to it as pending.", "你自己的 Alice 地址。奖励以待发放形式累积到此地址。"), |ui| {
                    if let Some(addr) = app.reward_address() {
                        let watch_only = app.reward_is_watch_only();
                        ui.horizontal(|ui| {
                            change_addr::identity_tag(ui, watch_only);
                            ui.add_space(8.0);
                            let copy = egui::Button::new(widgets::mono(widgets::shorten(&addr), 12.5, THEME.text))
                                .fill(THEME.well)
                                .stroke(egui::Stroke::new(1.0_f32, THEME.line_strong))
                                .corner_radius(9);
                            if ui.add(copy).on_hover_text(tr!("Click to copy", "点击复制")).clicked() {
                                ui.ctx().copy_text(addr.clone());
                                app.copied_at = Some(std::time::Instant::now());
                            }
                        });
                    } else {
                        ui.label(RichText::new(tr!("none", "无")).size(12.5).color(THEME.text4));
                    }
                });
                let hint = if mining {
                    strings::CHANGE_ADDR_MINING_BLOCK
                } else {
                    tr!("Create new, import a phrase/seed, or paste a different address. Your old keystore is backed up first.", "新建、导入助记词/种子,或粘贴另一个地址。你的旧密钥库会先被备份。")
                };
                srow(ui, tr!("Change reward address", "更换奖励地址"), hint, |ui| {
                    let btn = egui::Button::new(
                        RichText::new(tr!("Change reward address", "更换奖励地址"))
                            .size(12.5)
                            .strong()
                            .color(if mining { THEME.text4 } else { THEME.ink_on_brand }),
                    )
                    .fill(if mining { THEME.well } else { THEME.brand })
                    .stroke(egui::Stroke::new(1.0_f32, if mining { THEME.line_strong } else { THEME.brand }))
                    .corner_radius(9)
                    .min_size(egui::vec2(0.0, 32.0));
                    if ui.add_enabled(!mining, btn).clicked() {
                        app.open_change_addr();
                    }
                });
                // The 15%-PRL RETURN address input (A2c GUI parity with the CLI's
                // `identity --set-prl-payout`). A PUBLIC prl1p… address — stored +
                // shown masked, validated on save, watch-only-gated.
                prl_payout_row(ui, app);
            });

            ui.add_space(18.0);
            ui.label(
                RichText::new(format!("{} {}", strings::footer_line_1(), strings::footer_line_2()))
                    .size(11.0)
                    .color(THEME.text3),
            );
            ui.add_space(28.0);
        });
}

/// The Settings → Background mining panel. A "keep mining when the window is closed"
/// toggle that installs/removes the per-OS background agent (launchd / systemd `--user`
/// / Task Scheduler) via the (tested) `core::service` API. The reward address is read
/// from the keystore at runtime and never written into the service definition.
///
/// The background lane mirrors the SELECTED lane: a chosen GPU **pearlhash** lane is
/// backgrounded when the box has an OS keyring (to hold its wallet unlock for the
/// secret-free `--from-service` start); otherwise the secret-free CPU-XMR lane runs.
/// When a GPU lane is selected on a box WITHOUT a keyring, the toggle stays disabled
/// with the honest "needs an OS keyring" explainer (never a silent XMR fallback).
/// Enabling a GPU lane opens the background-unlock modal to capture + store the
/// password; XMR enables with no prompt.
fn render_background_panel(ui: &mut egui::Ui, app: &mut MinerApp) {
    use alice_miner_core::service::ServiceState;
    // Every platform now has a real background backend (launchd / systemd / Task
    // Scheduler) — the toggle is enabled wherever the SELECTED lane is backgroundable.
    let bg_lane = app.background_target_lane();
    let toggle_enabled = app.background_toggle_enabled();
    let disabled_reason = app.background_disabled_reason();
    // Lazily query the state once (spawns launchctl/systemctl/schtasks) and cache it.
    if app.bg_service.is_none() {
        app.refresh_bg_service();
    }
    let state = app.bg_service.unwrap_or(ServiceState::NotInstalled);
    let on = !matches!(state, ServiceState::NotInstalled);

    panel(ui, tr!("Background mining", "后台挖矿"), Icon::Activity, |ui| {
        let mut do_enable = false;
        let mut do_disable = false;
        srow(
            ui,
            tr!("Keep mining when closed", "关闭窗口后继续挖矿"),
            tr!(
                "Runs your selected lane in the background so mining continues after you close the \
                 window, and restarts at login. Your reward address stays in the keystore — it is \
                 never written into the background service.",
                "在后台运行你所选的通道,关闭窗口后仍继续挖矿,并在登录时重启。你的奖励地址\
                 保留在密钥库中 —— 绝不会写入后台服务。"
            ),
            |ui| {
                let (label, fill, ink, stroke) = if on {
                    (tr!("Turn off", "关闭"), THEME.well, THEME.text2, THEME.line_strong)
                } else {
                    (tr!("Turn on", "开启"), THEME.brand, THEME.ink_on_brand, THEME.brand)
                };
                let btn = egui::Button::new(RichText::new(label).size(12.5).strong().color(ink))
                    .fill(fill)
                    .stroke(egui::Stroke::new(1.0_f32, stroke))
                    .corner_radius(9)
                    .min_size(egui::vec2(0.0, 32.0));
                // Disable the "Turn on" affordance when the selected lane can't be
                // backgrounded here (GPU lane, no keyring); "Turn off" is always live.
                let clickable = on || toggle_enabled;
                if ui.add_enabled(clickable, btn).clicked() {
                    if on {
                        do_disable = true;
                    } else {
                        do_enable = true;
                    }
                }
            },
        );
        // The lane the background service will run, so the user knows what backgrounds.
        srow(
            ui,
            tr!("Lane", "通道"),
            tr!("The lane the background service will mine (mirrors your selection).", "后台服务将挖矿的通道(与你的选择一致)。"),
            |ui| {
                ui.label(RichText::new(bg_lane.label()).size(12.5).color(THEME.text2));
            },
        );
        let (word, tone) = match state {
            ServiceState::Running => (tr!("On — mining in the background", "已开启 —— 正在后台挖矿"), THEME.live),
            ServiceState::Loaded => (tr!("On — installed (the miner will keep retrying)", "已开启 —— 已安装(矿工将持续重试)"), THEME.warn),
            ServiceState::NotInstalled => (tr!("Off", "已关闭"), THEME.text3),
        };
        srow(ui, tr!("Status", "状态"), tr!("Background agent state.", "后台代理状态。"), |ui| {
            ui.label(RichText::new(word).size(12.5).color(tone));
        });
        // Honest explainer when a GPU lane is selected but no keyring is available —
        // we refuse rather than silently background XMR. Only shown while OFF.
        if !on {
            if let Some(reason) = &disabled_reason {
                srow(ui, tr!("Why disabled", "为何禁用"), tr!("This GPU lane needs an OS keyring.", "此 GPU 通道需要操作系统密钥环。"), |ui| {
                    ui.label(RichText::new(reason).size(11.5).color(THEME.text3));
                });
            }
        }
        if let Some(err) = app.bg_service_error.clone() {
            srow(ui, tr!("Last error", "最近错误"), tr!("The toggle action reported this.", "开关操作报告了此错误。"), |ui| {
                ui.label(RichText::new(err).size(11.5).color(THEME.err));
            });
        }
        if do_enable {
            app.enable_bg_service();
        }
        if do_disable {
            app.disable_bg_service();
        }
    });
}

/// The Settings → Software update panel. Renders the current updater state and
/// the "Check for updates" affordance; on a verified newer manifest it offers
/// "Update now". All work is user-initiated and runs on a background thread (see
/// [`crate::update`]); this only reads/sets `app.updater`.
/// The automatic-update mode selector: four buttons, the active one filled.
///
/// The description under it is deliberately blunt about the trade. Turning this
/// up is a decision about who is allowed to run code on this machine, and a UI
/// that presents it as a pure convenience setting would be lying by omission.
fn render_auto_update_mode(ui: &mut egui::Ui) {
    use alice_miner_core::alice_release::auto::Mode;
    use alice_miner_core::autoupdate;

    let active = autoupdate::mode();
    let mut pick: Option<Mode> = None;
    srow(
        ui,
        tr!("Install updates automatically", "自动安装更新"),
        tr!(
            "A new version is held for a day, rolled out in batches, and rolled back automatically if it fails to start or stops earning. Installing without being asked also means trusting our release key more — nothing is installed here that is not ed25519-signed and SHA-256-verified.",
            "新版本会先观察一天、分批放量,若无法启动或不再有收益会自动回滚。让它自动安装也意味着更依赖我们发布密钥的安全 —— 这里安装的任何内容都经过 ed25519 签名与 SHA-256 校验。"
        ),
        |ui| {
            for (m, label) in [
                (Mode::Off, tr!("Off", "关闭")),
                (Mode::Notify, tr!("Notify", "仅提示")),
                (Mode::SecurityOnly, tr!("Security", "仅安全")),
                (Mode::Full, tr!("All", "全部")),
            ] {
                let on = m == active;
                let btn = egui::Button::new(
                    RichText::new(label)
                        .size(12.0)
                        .strong()
                        .color(if on { THEME.ink_on_brand } else { THEME.text3 }),
                )
                .fill(if on { THEME.brand } else { THEME.well })
                .stroke(egui::Stroke::new(
                    1.0_f32,
                    if on { THEME.brand } else { THEME.line_strong },
                ))
                .corner_radius(9)
                .min_size(egui::vec2(0.0, 28.0));
                if ui.add(btn).clicked() && !on {
                    pick = Some(m);
                }
            }
        },
    );
    if let Some(m) = pick {
        // A failure to persist is surfaced, never swallowed: a setting the user
        // believes they changed and did not is worse than an error message.
        if let Err(e) = autoupdate::set_mode(m) {
            srow(
                ui,
                tr!("Could not save", "保存失败"),
                &e,
                |_ui| {},
            );
        }
    }
}

fn render_update_panel(ui: &mut egui::Ui, app: &mut MinerApp) {
    // The release channel link (PUBLIC apex; never an internal/core host). Shown
    // as the fallback for platforms without an in-app artifact.
    const RELEASES_PAGE: &str = "https://github.com/V-SK/alice-miner/releases/latest";

    panel(ui, tr!("Software update", "软件更新"), Icon::Globe, |ui| {
        // A one-time "updated to vX" confirmation, if the health gate committed a
        // freshly-applied build at startup. Cleared after it's shown once.
        if let Some(v) = app.update_committed_note.clone() {
            srow(
                ui,
                tr!("Updated", "已更新"),
                tr!("This build was just installed and verified.", "此版本刚刚安装并通过校验。"),
                |ui| {
                    ui.label(widgets::mono(format!("{} v{v}", tr!("now on", "当前")), 12.5, THEME.live));
                },
            );
            app.update_committed_note = None;
        }

        // What the AUTOMATIC updater last did, or last declined to do and why.
        // This row is the answer to the question the August 2026 incident left
        // us with: a miner should never have to wonder whether their client is
        // current, or guess why it is not.
        if let Some(note) = app.updater.auto_note.clone() {
            srow(
                ui,
                tr!("Automatic updates", "自动更新"),
                &note,
                |ui| {
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new(tr!("Dismiss", "知道了"))
                                    .size(12.0)
                                    .color(THEME.text3),
                            )
                            .fill(THEME.well)
                            .corner_radius(9)
                            .min_size(egui::vec2(0.0, 28.0)),
                        )
                        .clicked()
                    {
                        app.updater.auto_note = None;
                    }
                },
            );
        }

        // The mode switch. Four explicit choices, no hidden default: whichever
        // one is active is drawn as active even when the user has never chosen,
        // because "what will this machine do on its own" is not something to make
        // someone dig for.
        render_auto_update_mode(ui);

        let current = env!("CARGO_PKG_VERSION");
        let busy = app.updater.ui.is_busy();

        // The check row: current version + a "Check for updates" button. The
        // button disables (shows "Checking…") while a job is in flight.
        let mut do_check = false;
        srow(
            ui,
            tr!("Check for updates", "检查更新"),
            tr!("Updates are signed (ed25519) and integrity-checked (SHA-256). Your keystore is never touched.", "更新经过签名(ed25519)与完整性校验(SHA-256)。绝不会触碰你的密钥库。"),
            |ui| {
                let label = if busy { tr!("Checking…", "检查中…") } else { tr!("Check for updates", "检查更新") };
                let btn = egui::Button::new(
                    RichText::new(label)
                        .size(12.5)
                        .strong()
                        .color(if busy { THEME.text4 } else { THEME.ink_on_brand }),
                )
                .fill(if busy { THEME.well } else { THEME.brand })
                .stroke(egui::Stroke::new(1.0_f32, if busy { THEME.line_strong } else { THEME.brand }))
                .corner_radius(9)
                .min_size(egui::vec2(0.0, 32.0));
                if ui.add_enabled(!busy, btn).clicked() {
                    do_check = true;
                }
            },
        );
        if do_check {
            app.updater.check();
        }

        // The result/status row depends on the current updater state.
        match app.updater.ui.clone() {
            UpdateUi::Idle => {
                srow(ui, tr!("Status", "状态"), tr!("No check run yet this session.", "本次会话尚未检查。"), |ui| {
                    ui.label(widgets::mono(format!("v{current}"), 12.5, THEME.text3));
                });
            }
            UpdateUi::Checking | UpdateUi::Applying => {
                let what = if matches!(app.updater.ui, UpdateUi::Applying) {
                    tr!("Downloading and verifying the update…", "正在下载并校验更新…")
                } else {
                    tr!("Contacting the release channel…", "正在连接发布通道…")
                };
                srow(ui, tr!("Status", "状态"), what, |ui| {
                    ui.label(RichText::new(tr!("working…", "处理中…")).size(12.0).color(THEME.text3));
                });
            }
            UpdateUi::UpToDate { current } => {
                srow(ui, tr!("Status", "状态"), tr!("You're on the latest build.", "你已是最新版本。"), |ui| {
                    ui.horizontal(|ui| {
                        widgets::status_dot(ui, THEME.live, 8.0, false);
                        ui.add_space(6.0);
                        ui.label(widgets::mono(format!("v{current} · {}", tr!("up to date", "已是最新")), 12.5, THEME.text2));
                    });
                });
            }
            UpdateUi::Available { version, notes, .. } => {
                let hint = if notes.trim().is_empty() {
                    tr!("Version {v} is available.", "有可用版本 {v}。").replace("{v}", &version)
                } else {
                    tr!("Version {v} is available — {notes}", "有可用版本 {v} —— {notes}")
                        .replace("{v}", &version)
                        .replace("{notes}", &notes)
                };
                let mut do_apply = false;
                srow(ui, tr!("Update available", "有可用更新"), &hint, |ui| {
                    let btn = egui::Button::new(
                        RichText::new(tr!("Update now", "立即更新"))
                            .size(12.5)
                            .strong()
                            .color(THEME.ink_on_brand),
                    )
                    .fill(THEME.brand)
                    .stroke(egui::Stroke::new(1.0_f32, THEME.brand))
                    .corner_radius(9)
                    .min_size(egui::vec2(0.0, 32.0));
                    if ui.add(btn).clicked() {
                        do_apply = true;
                    }
                });
                if do_apply {
                    app.updater.apply();
                }
            }
            UpdateUi::AvailableNoArtifact { version, .. } => {
                srow(
                    ui,
                    tr!("Update available", "有可用更新"),
                    &tr!(
                        "Version {v} is available, but there's no in-app build for this platform — download it from the releases page.",
                        "有可用版本 {v},但本平台没有应用内构建 —— 请从发布页面下载。"
                    ).replace("{v}", &version),
                    |ui| {
                        let btn = egui::Button::new(
                            RichText::new(tr!("Open releases", "打开发布页")).size(12.5).strong().color(THEME.text),
                        )
                        .fill(THEME.well)
                        .stroke(egui::Stroke::new(1.0_f32, THEME.line_strong))
                        .corner_radius(9)
                        .min_size(egui::vec2(0.0, 32.0));
                        if ui.add(btn).on_hover_text(RELEASES_PAGE).clicked() {
                            ui.ctx().open_url(egui::OpenUrl::new_tab(RELEASES_PAGE));
                        }
                    },
                );
            }
            UpdateUi::Unsupported { min_supported, .. } => {
                srow(
                    ui,
                    tr!("Update required", "需要更新"),
                    &tr!(
                        "This build is older than the minimum supported (v{v}). Please update to keep mining.",
                        "此版本低于最低支持版本(v{v})。请更新以继续挖矿。"
                    ).replace("{v}", &min_supported),
                    |ui| {
                        let btn = egui::Button::new(
                            RichText::new(tr!("Open releases", "打开发布页")).size(12.5).strong().color(THEME.ink_on_brand),
                        )
                        .fill(THEME.warn)
                        .stroke(egui::Stroke::new(1.0_f32, THEME.warn))
                        .corner_radius(9)
                        .min_size(egui::vec2(0.0, 32.0));
                        if ui.add(btn).on_hover_text(RELEASES_PAGE).clicked() {
                            ui.ctx().open_url(egui::OpenUrl::new_tab(RELEASES_PAGE));
                        }
                    },
                );
            }
            UpdateUi::Applied { version } => {
                srow(
                    ui,
                    tr!("Update installed", "更新已安装"),
                    &tr!(
                        "Version {v} is installed and verified. Restart Alice Miner to run it.",
                        "版本 {v} 已安装并通过校验。重启 Alice Miner 以运行它。"
                    ).replace("{v}", &version),
                    |ui| {
                        ui.label(widgets::mono(tr!("restart to apply", "重启以生效"), 12.5, THEME.live));
                    },
                );
            }
            UpdateUi::Failed { message } => {
                srow(ui, tr!("Update check failed", "检查更新失败"), &message, |ui| {
                    ui.label(RichText::new(tr!("could not update", "无法更新")).size(12.0).color(THEME.err));
                });
            }
        }
    });
}

/// A zinc segmented-control button (language picker). `on` = selected.
fn lang_seg(ui: &mut egui::Ui, label: &str, on: bool) -> egui::Response {
    let btn = egui::Button::new(
        RichText::new(label).size(12.0).strong().color(if on { THEME.text } else { THEME.text3 }),
    )
    .fill(if on { THEME.surface3 } else { THEME.well })
    .stroke(egui::Stroke::new(1.0_f32, if on { THEME.line_strong } else { THEME.line }))
    .corner_radius(8)
    .min_size(egui::vec2(54.0, 30.0));
    ui.add(btn)
}

fn panel(ui: &mut egui::Ui, title: &str, icon: Icon, body: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::NONE
        .fill(THEME.surface)
        .corner_radius(14)
        .stroke(egui::Stroke::new(1.0_f32, THEME.line))
        .inner_margin(egui::Margin::ZERO)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            // Header.
            egui::Frame::NONE
                .inner_margin(egui::Margin::symmetric(17, 13))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        super::icons::show(ui, icon, 13.0, THEME.text4);
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new(title.to_uppercase())
                                .size(11.0)
                                .extra_letter_spacing(1.3)
                                .strong()
                                .color(THEME.text3),
                        );
                    });
                });
            ui.painter().hline(
                ui.available_rect_before_wrap().x_range(),
                ui.cursor().top(),
                egui::Stroke::new(1.0_f32, THEME.line),
            );
            egui::Frame::NONE
                .inner_margin(egui::Margin::symmetric(17, 4))
                .show(ui, |ui| body(ui));
        });
    ui.add_space(16.0);
}

/// The Settings → Identity **15%-PRL return-address** row (A2c GUI parity with the
/// CLI's `identity --set-prl-payout`). A labeled text field + Save button: on Save
/// the value is shape-validated (`prl_payout::validate_payout_shape`) — a typo shows
/// the red helper text inline and is NEVER written — else persisted
/// (`prl_payout::save_payout_address`). The currently-stored value is shown MASKED.
/// A watch-only identity (pasted address, no signing key) can't sign the PoP that
/// binds the 15% return, so the field is disabled with the gating note. The address
/// is PUBLIC (not a secret) — fine to store + show masked. No reward number ever.
fn prl_payout_row(ui: &mut egui::Ui, app: &mut MinerApp) {
    // Watch-only identities can't bind the 15% return (no signing key) — mirror the
    // start-PRL gating copy and disable the input.
    let watch_only = app.reward_is_watch_only();

    egui::Frame::NONE
        .inner_margin(egui::Margin::symmetric(0, 11))
        .show(ui, |ui| {
            ui.vertical(|ui| {
                // Title + the masked current value (or "not set") on the right.
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(strings::prl_payout_field_label())
                            .size(13.5)
                            .strong()
                            .color(THEME.text),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        match app.prl_payout_masked.as_deref() {
                            Some(masked) => {
                                ui.label(widgets::mono(masked.to_string(), 12.0, THEME.text2));
                                ui.add_space(6.0);
                                ui.label(RichText::new(strings::PRL_PAYOUT_CURRENT).size(10.5).color(THEME.text3));
                            }
                            None => {
                                ui.label(RichText::new(strings::PRL_PAYOUT_UNSET).size(11.5).color(THEME.text4));
                            }
                        }
                    });
                });
                ui.add_space(3.0);
                ui.label(RichText::new(strings::prl_payout_row_hint()).size(11.5).color(THEME.text3));
                ui.add_space(9.0);

                if watch_only {
                    // Gated: no input, just the honest reason (import the key first).
                    ui.horizontal_top(|ui| {
                        super::icons::show(ui, Icon::Eye, 13.0, THEME.text4);
                        ui.add_space(8.0);
                        ui.label(RichText::new(strings::prl_payout_watch_only()).size(11.0).color(THEME.text4));
                    });
                    return;
                }

                // The input + Save on one row. Enter in the field also saves.
                let mut do_save = false;
                ui.horizontal(|ui| {
                    let resp = widgets::text_input(
                        ui,
                        &mut app.form_prl_payout,
                        strings::prl_payout_field_hint(),
                        true,
                    );
                    if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        do_save = true;
                    }
                    ui.add_space(8.0);
                    let has_text = !app.form_prl_payout.trim().is_empty();
                    if widgets::primary_button(ui, strings::PRL_PAYOUT_SAVE, has_text, false).clicked() {
                        do_save = true;
                    }
                });
                if do_save {
                    app.save_prl_payout();
                }

                // AM-SEC-008 — the pre-save confirmation. `save_prl_payout` only
                // FULL-validates (shape + bech32m) and parks the value here; NOTHING
                // is written until the human confirms the address shown UNMASKED.
                if let Some(pending) = app.prl_payout_pending.clone() {
                    ui.add_space(10.0);
                    egui::Frame::NONE
                        .fill(THEME.well)
                        .corner_radius(11)
                        .inner_margin(egui::Margin::symmetric(14, 12))
                        .stroke(egui::Stroke::new(1.0_f32, THEME.line_strong))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(
                                RichText::new(strings::prl_payout_confirm_title())
                                    .size(12.5)
                                    .strong()
                                    .color(THEME.text),
                            );
                            ui.add_space(7.0);
                            // The WHOLE address, grouped — never the masked form here.
                            ui.label(widgets::mono(
                                alice_miner_core::prl_payout::format_for_confirm(&pending),
                                12.0,
                                THEME.text,
                            ));
                            ui.add_space(7.0);
                            ui.label(
                                RichText::new(strings::prl_payout_confirm_body())
                                    .size(11.0)
                                    .color(THEME.text3),
                            );
                            ui.add_space(10.0);
                            ui.horizontal(|ui| {
                                if widgets::primary_button(
                                    ui,
                                    strings::PRL_PAYOUT_CONFIRM_YES,
                                    true,
                                    false,
                                )
                                .clicked()
                                {
                                    app.confirm_prl_payout();
                                }
                                ui.add_space(8.0);
                                if widgets::ghost_button(ui, strings::PRL_PAYOUT_CONFIRM_NO, false)
                                    .clicked()
                                {
                                    app.cancel_prl_payout();
                                }
                            });
                        });
                }

                // Inline validation/save error (red), if any.
                if let Some(err) = app.prl_payout_error.clone() {
                    ui.add_space(7.0);
                    ui.label(RichText::new(err).size(11.0).color(THEME.err));
                }
            });
        });
    ui.painter().hline(
        ui.available_rect_before_wrap().x_range(),
        ui.cursor().top(),
        egui::Stroke::new(1.0_f32, THEME.line),
    );
}

fn srow(ui: &mut egui::Ui, title: &str, hint: &str, rhs: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::NONE
        .inner_margin(egui::Margin::symmetric(0, 11))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(RichText::new(title).size(13.5).strong().color(THEME.text));
                    ui.add_space(3.0);
                    ui.label(RichText::new(hint).size(11.5).color(THEME.text3));
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    rhs(ui);
                });
            });
        });
    ui.painter().hline(
        ui.available_rect_before_wrap().x_range(),
        ui.cursor().top(),
        egui::Stroke::new(1.0_f32, THEME.line),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use alice_miner_core::engine::{LaneSnapshot, Snapshot};
    use alice_miner_core::EngineState;

    fn lane(lane: Lane, accepted: u64, rejected: u64) -> LaneSnapshot {
        LaneSnapshot {
            lane,
            state: EngineState::Running,
            hashrate_hs: Some(1.0e6),
            hashrate_60s_hs: None,
            hashrate_15m_hs: None,
            shares_accepted: accepted,
            shares_rejected: rejected,
            uptime_s: 0,
            endpoint: None,
            failovers: 0,
            temp_c: None,
            power_w: None,
            util_pct: None,
            fan_pct: None,
        }
    }

    /// Build a minimal Snapshot carrying just the fields `reject_health_sub` reads
    /// (`dual` + `lanes`); the rest are honest zero/None defaults.
    fn snap(dual: bool, lanes: Vec<LaneSnapshot>) -> Snapshot {
        Snapshot {
            state: EngineState::Running,
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
            temp_c: None,
            power_w: None,
            util_pct: None,
            fan_pct: None,
            dual,
            lanes,
            last_line: None,
            message: None,
            message_key: None,
            message_args: None,
            prl_payout: None,
        }
    }

    // ── SHOULD-FIX A: reject-health is PER-LANE in dual-mine ───────────────────

    /// The core bug: in dual-mine a clean, high-volume XMR lane keeps the SUMMED reject
    /// denominator clean, so a high-reject GPU-PRL lane reads false-"healthy". Reading
    /// per-lane must flag the GPU lane's OWN reject rate even while XMR is healthy.
    #[test]
    fn dual_reject_health_flags_gpu_lane_not_summed() {
        // XMR: 10000 accepted / 1 rejected (~0% — healthy). GPU-PRL: 10 accepted / 10
        // rejected (50% — HIGH). Summed = 10010A / 11R ≈ 0.1% → would read "healthy".
        let s = snap(
            true,
            vec![lane(Lane::Xmr, 10_000, 1), lane(Lane::GpuPrl, 10, 10)],
        );
        let sum_a = 10_010;
        let sum_r = 11;
        // Summed view (the OLD behaviour) would be healthy …
        assert_eq!(
            classify_reject_pct(sum_r as f64 / (sum_a + sum_r) as f64 * 100.0).1,
            RejectTone::Healthy
        );
        // … the per-lane fix flags the GPU lane as HIGH.
        let (label, tone) = reject_health_sub(Some(&s), Lane::Xmr, sum_a, sum_r);
        assert_eq!(tone, RejectTone::High, "GPU lane's 50% reject must surface: {label}");
        assert!(label.contains("high"), "label: {label}");
    }

    /// A healthy GPU lane in dual-mine still reads healthy (no false alarm).
    #[test]
    fn dual_reject_health_healthy_gpu_stays_healthy() {
        let s = snap(true, vec![lane(Lane::Xmr, 5_000, 2), lane(Lane::GpuPrl, 100, 1)]);
        let (_, tone) = reject_health_sub(Some(&s), Lane::Xmr, 5_100, 3);
        assert_eq!(tone, RejectTone::Healthy);
    }

    /// A dual-mine GPU-Alpha partner (no pool-reject signal) reads "rejects n/a", not a
    /// fabricated 100%/healthy — even if XMR is producing.
    #[test]
    fn dual_gpu_alpha_reads_rejects_na() {
        let s = snap(true, vec![lane(Lane::Xmr, 5_000, 2), lane(Lane::GpuAlpha, 50, 0)]);
        let (label, tone) = reject_health_sub(Some(&s), Lane::Xmr, 5_050, 2);
        assert_eq!(tone, RejectTone::Neutral);
        assert_eq!(label, "rejects n/a");
    }

    // ── SHOULD-FIX B: GpuAlpha card shows SUBMITTED, not an accepted% ──────────

    /// On the GpuAlpha lane the third card is "Submitted" + the raw count (no "%"); every
    /// other lane keeps "Accepted" + the pct% headline. Idle (not mining) keeps "Accepted".
    #[test]
    fn accepted_card_alpha_shows_submitted_count_not_pct() {
        // GpuAlpha while mining → "Submitted" + count, NO percent sign.
        let (title, headline) = accepted_card(true, Lane::GpuAlpha, 42, "100.0");
        assert_eq!(title, "Submitted");
        assert_eq!(headline, "42");
        assert!(!headline.contains('%'), "alpha headline must not imply an accept rate");
        // Other lanes → "Accepted" + pct% (unchanged).
        let (title, headline) = accepted_card(true, Lane::Xmr, 142, "99.3");
        assert_eq!(title, "Accepted");
        assert_eq!(headline, "99.3%");
        // GpuPrl keeps the accepted% framing (it DOES have an accept signal).
        assert_eq!(accepted_card(true, Lane::GpuPrl, 10, "100.0").0, "Accepted");
        // Idle GpuAlpha (not mining) → still "Accepted" (the dash placeholder path).
        assert_eq!(accepted_card(false, Lane::GpuAlpha, 0, "—").0, "Accepted");
    }

    /// Single-lane behaviour is unchanged: the summed counters ARE the active lane, so
    /// the output matches the prior summed logic exactly.
    #[test]
    fn single_lane_reject_health_unchanged() {
        // Single XMR, 5% rejects → healthy boundary.
        let s = snap(false, vec![lane(Lane::Xmr, 95, 5)]);
        assert_eq!(reject_health_sub(Some(&s), Lane::Xmr, 95, 5).1, RejectTone::Healthy);
        // Single XMR, 30% rejects → high.
        let s = snap(false, vec![lane(Lane::Xmr, 70, 30)]);
        assert_eq!(reject_health_sub(Some(&s), Lane::Xmr, 70, 30).1, RejectTone::High);
        // Single GpuAlpha → rejects n/a.
        let s = snap(false, vec![lane(Lane::GpuAlpha, 40, 0)]);
        assert_eq!(reject_health_sub(Some(&s), Lane::GpuAlpha, 40, 0).0, "rejects n/a");
        // No shares yet.
        assert_eq!(reject_health_sub(Some(&s), Lane::Xmr, 0, 0).0, "no shares yet");
    }
}
