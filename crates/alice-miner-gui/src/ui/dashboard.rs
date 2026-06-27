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
use alice_miner_core::{CreditState, Lane, LaneSupport, Reconciliation};

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
            ui.label(RichText::new("Dashboard").size(21.0).strong().color(THEME.text));
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
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(tone.fg().r(), tone.fg().g(), tone.fg().b(), 80)))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        widgets::status_dot(ui, tone.fg(), 8.0, blink);
                        ui.add_space(8.0);
                        let label = if mining { "uptime" } else { "idle" };
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
        egui::Stroke::new(1.0, THEME.line),
    );
    ui.add_space(18.0);

    // ── SOURCE A — local activity (what the miner is doing locally, NOT earnings).
    // Label it explicitly so the user (and the honesty audit) can never mistake
    // these live figures for confirmed earnings.
    source_label(ui, strings::ACTIVITY_SECTION, strings::ACTIVITY_CAPTION, Tone::Live);
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
    let (accepted_sub, accepted_sub_color): (String, egui::Color32) = if a + r == 0 {
        ("no shares yet".to_string(), THEME.text3)
    } else if app.active_lane() == Lane::GpuAlpha {
        ("rejects n/a".to_string(), THEME.text3)
    } else {
        let reject_pct = r as f64 / (a + r) as f64 * 100.0;
        if reject_pct <= 5.0 {
            ("rolling · healthy".to_string(), THEME.live)
        } else if reject_pct <= 20.0 {
            (format!("{reject_pct:.0}% rejects · elevated"), THEME.warn)
        } else {
            (format!("{reject_pct:.0}% rejects · high"), THEME.err)
        }
    };
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
                    "Hashrate",
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
                "Shares A / R",
                widgets::mono(format!("{a}"), 25.0, THEME.text).strong(),
                Some(widgets::mono(format!("/ {r} rejected"), 11.5, THEME.text3)),
                None,
                None,
            );
        }),
        // Accepted %.
        Box::new({
            let pct = pct.clone();
            let sub = accepted_sub.clone();
            let sub_color = accepted_sub_color;
            move |ui: &mut egui::Ui| {
                widgets::stat_card(
                    ui,
                    card_w,
                    CARD_MIN_CONTENT_H,
                    "Accepted",
                    widgets::mono(format!("{pct}%"), 25.0, THEME.text).strong(),
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
                "Est. rewards",
                RichText::new(strings::REWARD_PENDING_SHORT).size(20.0).strong().color(THEME.brand300),
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
    widgets::section_label(ui, "Lanes");
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
        &format!("· CPU · {} threads", app.device.as_ref().map(|d| d.logical_cores).unwrap_or(0)),
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
        LaneSupport::Viable => "· GPU · NVIDIA/AMD · ready",
        LaneSupport::ComingSoon => "· GPU · coming soon",
        LaneSupport::Unavailable => "· GPU · needs NVIDIA/AMD GPU",
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
    source_label(ui, strings::CREDIT_SECTION, strings::CREDIT_CAPTION, Tone::Off);
    ui.add_space(10.0);
    credit_panel(ui, app);

    // ── Connection ─────────────────────────────────────────────────────────────
    ui.add_space(22.0);
    widgets::section_label(ui, "Connection");
    ui.add_space(10.0);
    connection_panel(ui, app);

    // ── Log ─────────────────────────────────────────────────────────────────────
    ui.add_space(22.0);
    widgets::section_label(ui, "Log");
    ui.add_space(10.0);
    log_panel(ui, app);
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
        .stroke(egui::Stroke::new(1.0, THEME.line))
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
                        ui.label(RichText::new("live").size(11.0).color(THEME.text2));
                    } else {
                        ui.label(RichText::new("off").size(11.0).color(THEME.text4));
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
        .stroke(egui::Stroke::new(1.0, THEME.line))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            egui::Grid::new("conn-grid")
                .num_columns(2)
                .spacing(egui::vec2(20.0, 12.0))
                .show(ui, |ui| {
                    kv_key(ui, "Endpoint");
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
                                        "failed over".to_string()
                                    } else {
                                        format!("failed over ×{failovers}")
                                    };
                                    ui.label(RichText::new(label).size(10.5).color(THEME.warn));
                                });
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let (tone, label) = if connected {
                                (Tone::Live, "connected")
                            } else {
                                (Tone::Off, "not connected")
                            };
                            widgets::status_dot(ui, tone.fg(), 8.0, connected && motion);
                            ui.add_space(8.0);
                            ui.label(RichText::new(label).size(12.0).color(THEME.text2));
                        });
                    });
                    ui.end_row();

                    kv_key(ui, "Worker");
                    ui.horizontal(|ui| {
                        let w = worker.clone().map(|w| widgets::shorten(&w)).unwrap_or_else(|| "—".into());
                        ui.label(widgets::mono(format!("rig-{w}"), 13.0, THEME.text));
                        ui.label(RichText::new("· rig-id derived").size(12.0).color(THEME.text4));
                        if let Some(addr) = app.reward_address() {
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                let copy = egui::Button::new(RichText::new("copy address").size(11.0).color(THEME.text3))
                                    .fill(egui::Color32::TRANSPARENT)
                                    .stroke(egui::Stroke::new(1.0, THEME.line))
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
        ui.painter().hline(rect.x_range(), rect.center().y, egui::Stroke::new(1.0, THEME.line));
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
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(fg.r(), fg.g(), fg.b(), 80)))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 7.0;
                ui.label(RichText::new(strings::RECONCILE_PREFIX).size(10.0).color(THEME.text3));
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
        .stroke(egui::Stroke::new(1.0, THEME.line))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            match &state {
                CreditState::NotExposed => {
                    // The honest Option-3 panel.
                    ui.horizontal(|ui| {
                        super::icons::show(ui, Icon::Globe, 14.0, THEME.brand300);
                        ui.add_space(9.0);
                        ui.label(
                            RichText::new(strings::CREDIT_NOTEXPOSED_TITLE)
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
                    ui.label(RichText::new(strings::CREDIT_NOTEXPOSED_BODY_1).size(12.0).color(THEME.text2));
                    ui.add_space(3.0);
                    ui.label(RichText::new(strings::CREDIT_NOTEXPOSED_BODY_2).size(12.0).color(THEME.text3));
                    ui.add_space(12.0);
                    explorer_link(ui);
                }
                CreditState::Confirming => {
                    credit_status_row(
                        ui,
                        Tone::Off,
                        strings::CREDIT_SECTION,
                        strings::CREDIT_CONFIRMING,
                        app.motion_enabled(),
                    );
                    ui.add_space(10.0);
                    explorer_link(ui);
                }
                CreditState::Confirmed { score } => {
                    // CREDIT-ONLY: render the confirmed score ONLY as its pending
                    // label — never the magnitude. The presence of confirmed credit
                    // is shown with a live dot; the amount stays "pending".
                    let _ = score; // intentionally NOT rendered as a number ($-trap)
                    credit_status_row(
                        ui,
                        Tone::Live,
                        "Confirmed by the network",
                        strings::CREDIT_PENDING_VALUE,
                        app.motion_enabled(),
                    );
                    ui.add_space(10.0);
                    explorer_link(ui);
                }
                CreditState::Error { reason } => {
                    // A calm, NON-numeric fault note; Source A stays the live UX.
                    credit_status_row(
                        ui,
                        Tone::Warn,
                        strings::CREDIT_SECTION,
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
        .stroke(egui::Stroke::new(1.0, THEME.line))
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
                strings::PRL_RETURN_BODY_BOUND
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
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(fg.r(), fg.g(), fg.b(), 70)))
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
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(THEME.brand.r(), THEME.brand.g(), THEME.brand.b(), 70)))
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

/// The explorer deep-link (PUBLIC apex — never an internal/core host). A ghost
/// button that opens the explorer where the user can look up their address.
fn explorer_link(ui: &mut egui::Ui) {
    let btn = egui::Button::new(
        RichText::new(strings::CREDIT_EXPLORER_LABEL).size(12.0).color(THEME.text2),
    )
    .fill(THEME.well)
    .stroke(egui::Stroke::new(1.0, THEME.line_strong))
    .corner_radius(9);
    if ui.add(btn).on_hover_text(strings::CREDIT_EXPLORER_URL).clicked() {
        ui.ctx().open_url(egui::OpenUrl::new_tab(strings::CREDIT_EXPLORER_URL));
    }
}

fn log_panel(ui: &mut egui::Ui, app: &MinerApp) {
    egui::Frame::NONE
        .fill(THEME.well)
        .corner_radius(14)
        .inner_margin(egui::Margin::symmetric(16, 14))
        .stroke(egui::Stroke::new(1.0, THEME.line_strong))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.set_min_height(60.0);
            if app.log.is_empty() {
                ui.label(widgets::mono("waiting for engine output…", 11.5, THEME.text4));
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
            ui.label(RichText::new("Settings").size(21.0).strong().color(THEME.text));
            ui.label(RichText::new("The product resists knobs — only what matters.").size(12.0).color(THEME.text3));
            ui.add_space(16.0);

            // Mining panel.
            panel(ui, "Mining", Icon::Activity, |ui| {
                srow(ui, "Worker threads", "Mining runs at full power (拉满) only while you've pressed Start.", |ui| {
                    let n = app.device.as_ref().map(|d| d.logical_cores).unwrap_or(0);
                    ui.label(widgets::mono(format!("{n} threads"), 13.0, THEME.text));
                });
                srow(ui, "Lane", "Auto picks the best lane for your device. XMR uses the CPU (RandomX); PRL uses an NVIDIA/AMD GPU (pearlhash).", |ui| {
                    let lane = app.active_lane();
                    widgets::chip(ui, Some(lane_accent(lane)), lane_chip_label(lane));
                });
            });

            // Network panel.
            panel(ui, "Network", Icon::Globe, |ui| {
                srow(ui, "Endpoint", "Primary relay. The client handles failover automatically.", |ui| {
                    // Lane-aware while idle (:3333 XMR / :8888 RVN) — see
                    // `display_endpoint()` (the M3 follow-up fix).
                    let ep = app.display_endpoint();
                    ui.horizontal(|ui| {
                        ui.label(widgets::mono(ep, 12.5, THEME.text2));
                        ui.label(RichText::new("read-only").size(10.0).extra_letter_spacing(0.8).color(THEME.text4));
                    });
                });
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
            panel(ui, "Appearance", Icon::Activity, |ui| {
                let mut rm = app.reduce_motion;
                srow(
                    ui,
                    "Reduce motion",
                    "Turns off the breathing glow, gauge sweep and number tween. Colours and states stay.",
                    |ui| {
                        if widgets::toggle(ui, rm).clicked() {
                            rm = !rm;
                        }
                    },
                );
                app.reduce_motion = rm;
                let mut zh = app.lang_zh;
                srow(ui, "Language · 语言", "Interface language. Numbers stay mono in both.", |ui| {
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
            panel(ui, "Identity", Icon::Eye, |ui| {
                srow(ui, "Reward address", "Your own Alice address. Rewards accrue to it as pending.", |ui| {
                    if let Some(addr) = app.reward_address() {
                        let watch_only = app.reward_is_watch_only();
                        ui.horizontal(|ui| {
                            change_addr::identity_tag(ui, watch_only);
                            ui.add_space(8.0);
                            let copy = egui::Button::new(widgets::mono(widgets::shorten(&addr), 12.5, THEME.text))
                                .fill(THEME.well)
                                .stroke(egui::Stroke::new(1.0, THEME.line_strong))
                                .corner_radius(9);
                            if ui.add(copy).on_hover_text("Click to copy").clicked() {
                                ui.ctx().copy_text(addr.clone());
                                app.copied_at = Some(std::time::Instant::now());
                            }
                        });
                    } else {
                        ui.label(RichText::new("none").size(12.5).color(THEME.text4));
                    }
                });
                let hint = if mining {
                    strings::CHANGE_ADDR_MINING_BLOCK
                } else {
                    "Create new, import a phrase/seed, or paste a different address. Your old keystore is backed up first."
                };
                srow(ui, "Change reward address", hint, |ui| {
                    let btn = egui::Button::new(
                        RichText::new(strings::CHANGE_ADDR_ACTION)
                            .size(12.5)
                            .strong()
                            .color(if mining { THEME.text4 } else { THEME.ink_on_brand }),
                    )
                    .fill(if mining { THEME.well } else { THEME.brand })
                    .stroke(egui::Stroke::new(1.0, if mining { THEME.line_strong } else { THEME.brand }))
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
                RichText::new(format!("{} {}", strings::FOOTER_LINE_1, strings::FOOTER_LINE_2))
                    .size(11.0)
                    .color(THEME.text3),
            );
            ui.add_space(28.0);
        });
}

/// The Settings → Background mining panel. A single "keep mining when the window
/// is closed" toggle that installs/removes the launchd LaunchAgent for the CPU-XMR
/// lane via the (tested) `core::service` API. The reward address is read from the
/// keystore at runtime and never written into the service definition. Rendered on
/// every platform (so the field/method references aren't dead code off macOS); the
/// toggle is enabled only where a backend exists (macOS today) and otherwise shows
/// an honest "coming soon".
fn render_background_panel(ui: &mut egui::Ui, app: &mut MinerApp) {
    use alice_miner_core::service::ServiceState;
    // macOS is the only platform with a background backend today; on Windows/Linux
    // the toggle is shown disabled with a "coming soon" note (service::install
    // would return a clear "not supported yet" error anyway).
    let supported = cfg!(target_os = "macos");
    // Lazily query the state once (spawns launchctl on macOS; a cheap stub
    // elsewhere) and cache it.
    if app.bg_service.is_none() {
        app.refresh_bg_service();
    }
    let state = app.bg_service.unwrap_or(ServiceState::NotInstalled);
    let on = !matches!(state, ServiceState::NotInstalled);

    panel(ui, "Background mining", Icon::Activity, |ui| {
        let mut do_enable = false;
        let mut do_disable = false;
        srow(
            ui,
            "Keep mining when closed",
            "Runs the CPU (XMR) lane in the background so mining continues after you close the \
             window, and restarts at login. Your reward address stays in the keystore — it is \
             never written into the background service.",
            |ui| {
                if !supported {
                    ui.label(RichText::new("macOS only for now").size(12.0).color(THEME.text3));
                    return;
                }
                let (label, fill, ink, stroke) = if on {
                    ("Turn off", THEME.well, THEME.text2, THEME.line_strong)
                } else {
                    ("Turn on", THEME.brand, THEME.ink_on_brand, THEME.brand)
                };
                let btn = egui::Button::new(RichText::new(label).size(12.5).strong().color(ink))
                    .fill(fill)
                    .stroke(egui::Stroke::new(1.0, stroke))
                    .corner_radius(9)
                    .min_size(egui::vec2(0.0, 32.0));
                if ui.add(btn).clicked() {
                    if on {
                        do_disable = true;
                    } else {
                        do_enable = true;
                    }
                }
            },
        );
        let (word, tone) = match (supported, state) {
            (false, _) => ("Windows/Linux background mining is on the way", THEME.text3),
            (true, ServiceState::Running) => ("On — mining in the background", THEME.live),
            (true, ServiceState::Loaded) => ("On — installed (the miner will keep retrying)", THEME.warn),
            (true, ServiceState::NotInstalled) => ("Off", THEME.text3),
        };
        srow(ui, "Status", "Background agent state.", |ui| {
            ui.label(RichText::new(word).size(12.5).color(tone));
        });
        if let Some(err) = app.bg_service_error.clone() {
            srow(ui, "Last error", "The toggle action reported this.", |ui| {
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
fn render_update_panel(ui: &mut egui::Ui, app: &mut MinerApp) {
    // The release channel link (PUBLIC apex; never an internal/core host). Shown
    // as the fallback for platforms without an in-app artifact.
    const RELEASES_PAGE: &str = "https://github.com/V-SK/alice-miner/releases/latest";

    panel(ui, "Software update", Icon::Globe, |ui| {
        // A one-time "updated to vX" confirmation, if the health gate committed a
        // freshly-applied build at startup. Cleared after it's shown once.
        if let Some(v) = app.update_committed_note.clone() {
            srow(
                ui,
                "Updated",
                "This build was just installed and verified.",
                |ui| {
                    ui.label(widgets::mono(format!("now on v{v}"), 12.5, THEME.live));
                },
            );
            app.update_committed_note = None;
        }

        let current = env!("CARGO_PKG_VERSION");
        let busy = app.updater.ui.is_busy();

        // The check row: current version + a "Check for updates" button. The
        // button disables (shows "Checking…") while a job is in flight.
        let mut do_check = false;
        srow(
            ui,
            "Check for updates",
            "Updates are signed (ed25519) and integrity-checked (SHA-256). Your keystore is never touched.",
            |ui| {
                let label = if busy { "Checking…" } else { "Check for updates" };
                let btn = egui::Button::new(
                    RichText::new(label)
                        .size(12.5)
                        .strong()
                        .color(if busy { THEME.text4 } else { THEME.ink_on_brand }),
                )
                .fill(if busy { THEME.well } else { THEME.brand })
                .stroke(egui::Stroke::new(1.0, if busy { THEME.line_strong } else { THEME.brand }))
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
                srow(ui, "Status", "No check run yet this session.", |ui| {
                    ui.label(widgets::mono(format!("v{current}"), 12.5, THEME.text3));
                });
            }
            UpdateUi::Checking | UpdateUi::Applying => {
                let what = if matches!(app.updater.ui, UpdateUi::Applying) {
                    "Downloading and verifying the update…"
                } else {
                    "Contacting the release channel…"
                };
                srow(ui, "Status", what, |ui| {
                    ui.label(RichText::new("working…").size(12.0).color(THEME.text3));
                });
            }
            UpdateUi::UpToDate { current } => {
                srow(ui, "Status", "You're on the latest build.", |ui| {
                    ui.horizontal(|ui| {
                        widgets::status_dot(ui, THEME.live, 8.0, false);
                        ui.add_space(6.0);
                        ui.label(widgets::mono(format!("v{current} · up to date"), 12.5, THEME.text2));
                    });
                });
            }
            UpdateUi::Available { version, notes, .. } => {
                let hint = if notes.trim().is_empty() {
                    format!("Version {version} is available.")
                } else {
                    format!("Version {version} is available — {notes}")
                };
                let mut do_apply = false;
                srow(ui, "Update available", &hint, |ui| {
                    let btn = egui::Button::new(
                        RichText::new("Update now")
                            .size(12.5)
                            .strong()
                            .color(THEME.ink_on_brand),
                    )
                    .fill(THEME.brand)
                    .stroke(egui::Stroke::new(1.0, THEME.brand))
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
                    "Update available",
                    &format!("Version {version} is available, but there's no in-app build for this platform — download it from the releases page."),
                    |ui| {
                        let btn = egui::Button::new(
                            RichText::new("Open releases").size(12.5).strong().color(THEME.text),
                        )
                        .fill(THEME.well)
                        .stroke(egui::Stroke::new(1.0, THEME.line_strong))
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
                    "Update required",
                    &format!("This build is older than the minimum supported (v{min_supported}). Please update to keep mining."),
                    |ui| {
                        let btn = egui::Button::new(
                            RichText::new("Open releases").size(12.5).strong().color(THEME.ink_on_brand),
                        )
                        .fill(THEME.warn)
                        .stroke(egui::Stroke::new(1.0, THEME.warn))
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
                    "Update installed",
                    &format!("Version {version} is installed and verified. Restart Alice Miner to run it."),
                    |ui| {
                        ui.label(widgets::mono("restart to apply", 12.5, THEME.live));
                    },
                );
            }
            UpdateUi::Failed { message } => {
                srow(ui, "Update check failed", &message, |ui| {
                    ui.label(RichText::new("could not update").size(12.0).color(THEME.err));
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
    .stroke(egui::Stroke::new(1.0, if on { THEME.line_strong } else { THEME.line }))
    .corner_radius(8)
    .min_size(egui::vec2(54.0, 30.0));
    ui.add(btn)
}

fn panel(ui: &mut egui::Ui, title: &str, icon: Icon, body: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::NONE
        .fill(THEME.surface)
        .corner_radius(14)
        .stroke(egui::Stroke::new(1.0, THEME.line))
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
                egui::Stroke::new(1.0, THEME.line),
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
                        RichText::new(strings::PRL_PAYOUT_FIELD_LABEL)
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
                ui.label(RichText::new(strings::PRL_PAYOUT_ROW_HINT).size(11.5).color(THEME.text3));
                ui.add_space(9.0);

                if watch_only {
                    // Gated: no input, just the honest reason (import the key first).
                    ui.horizontal_top(|ui| {
                        super::icons::show(ui, Icon::Eye, 13.0, THEME.text4);
                        ui.add_space(8.0);
                        ui.label(RichText::new(strings::PRL_PAYOUT_WATCH_ONLY).size(11.0).color(THEME.text4));
                    });
                    return;
                }

                // The input + Save on one row. Enter in the field also saves.
                let mut do_save = false;
                ui.horizontal(|ui| {
                    let resp = widgets::text_input(
                        ui,
                        &mut app.form_prl_payout,
                        strings::PRL_PAYOUT_FIELD_HINT,
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
        egui::Stroke::new(1.0, THEME.line),
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
        egui::Stroke::new(1.0, THEME.line),
    );
}
