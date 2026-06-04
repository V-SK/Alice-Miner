//! Home — the one-click screen (mockup `02a` idle / `02b` mining), plus the
//! `connecting` / `error` / `stopping` states (all specced in doc 06 §6.3).
//!
//! Device auto-detected line + lane chip, the Alice Core hero as the single
//! Start/Stop control, "Rewards to <addr>", a per-state status line, and the
//! honest credit-only footer. All reward copy comes from [`crate::ui::strings`].

use eframe::egui::{self, RichText};

use super::hero::{self, HeroMode};
use super::icons::Icon;
use super::strings;
use super::theme::THEME;
use super::widgets::{self, Tone};
use super::{lane_accent, lane_chip_label};
use crate::app::MinerApp;
use alice_miner_core::{EngineState, Lane, LaneSupport};

/// The Home hero card's fixed inner width (mockup `.card-hero` max-width 392px).
const HERO_CARD_W: f32 = 392.0;

pub fn render(ui: &mut egui::Ui, app: &mut MinerApp) {
    // The hero card is vertically centred when there's slack and top-anchored
    // (scrolls) when the window is short — so it never floats with a void beneath
    // it on a tall window, and nothing (incl. the error status line + footer) is
    // ever clipped on a short one. We balance with a TOP inset = half the leftover
    // height vs a per-state height estimate (errs a little high so the card never
    // pushes off the bottom; the inset is clamped to a small floor regardless).
    let avail_h = ui.available_height();
    let est_h = estimate_hero_height(app);
    let top = (((avail_h - est_h) * 0.5).floor()).clamp(8.0, 130.0);
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(top);
                widgets::card(ui, HERO_CARD_W, |ui| {
                    hero_card_body(ui, app);
                });
                ui.add_space(20.0);
            });
        });
}

/// A per-state height estimate (points) for the Home card — used only to balance
/// the centring inset. Tuned to the tightened `hero_card_body` rhythm; it errs a
/// touch high so the inset never pushes the card past the bottom. Off-by-a-little
/// is fine (the inset is clamped + the ScrollArea is the safety net).
fn estimate_hero_height(app: &MinerApp) -> f32 {
    use alice_miner_core::EngineState;
    // Tuned to the MEASURED card heights (≈510–540pt at zoom 1.0) so the centring
    // inset balances air above + below. A touch high so the card never overflows
    // the bottom; the ScrollArea is the final safety net regardless.
    match app.state() {
        EngineState::Idle => 576.0,
        EngineState::Error => 568.0,
        // Mid-run cards add the Stop button (+ dashboard link, except stopping).
        EngineState::Running | EngineState::Starting => 582.0,
        EngineState::Stopping => 538.0,
    }
}

fn hero_card_body(ui: &mut egui::Ui, app: &mut MinerApp) {
    // Drive ALL vertical rhythm via explicit `add_space` — zero the default
    // 10px inter-widget gap so the tall hero card fits the window cleanly.
    ui.spacing_mut().item_spacing.y = 0.0;
    let state = app.state();

    // Eyebrow reflects the state (live vs setup vs the calm fault label).
    let eyebrow = match state {
        EngineState::Running => "Mining · live",
        EngineState::Starting => "Connecting · 连接中",
        EngineState::Stopping => "Stopping · 停止中",
        EngineState::Error => "Lane stopped · 已停止",
        EngineState::Idle => "Device auto-detected",
    };
    centered(ui, |ui| widgets::eyebrow(ui, eyebrow));
    ui.add_space(11.0);

    // Device line: chip + model string (model only, e.g. "Apple M2 Max · 12 cores").
    let model = app
        .device
        .as_ref()
        .map(|d| d.display.clone())
        .unwrap_or_else(|| "Detecting device…".to_string());
    centered(ui, |ui| {
        // Chip-ic with a CPU glyph.
        egui::Frame::NONE
            .fill(THEME.surface2)
            .corner_radius(9)
            .inner_margin(egui::Margin::same(6))
            .stroke(egui::Stroke::new(1.0, THEME.line))
            .show(ui, |ui| {
                super::icons::show(ui, Icon::Cpu, 17.0, THEME.text2);
            });
        ui.add_space(11.0);
        ui.label(RichText::new(model.clone()).size(15.5).strong().color(THEME.text));
    });

    // Lane selector + dual-mine toggle are SETUP affordances — shown only while
    // idle/error (when the user can actually choose a lane). While mid-run the
    // lane is locked + already surfaced (titlebar pill + status line), so hiding
    // these rows keeps the running/connecting card compact enough to fit without
    // clipping the Stop button + footer. A dual-mine RUN still shows its "active"
    // indicator inside `dual_mine_row`.
    let mid_run = matches!(
        state,
        EngineState::Running | EngineState::Starting | EngineState::Stopping
    );
    if !mid_run {
        ui.add_space(9.0);
        // Lane row: the selected lane chip + (when the device supports it) a
        // selectable/"coming soon" chip for the other lane. Reflects viability:
        // on a non-NVIDIA box the RVN chip reads "coming soon" and is inert; XMR
        // stays the default.
        lane_selector(ui, app);
        // Dual-mine toggle: run BOTH lanes (CPU-XMR + GPU-RVN) together. Gated on
        // viability (≥2 runnable lanes) — DISABLED on this Mac. Default OFF.
        ui.add_space(8.0);
        dual_mine_row(ui, app);
    } else if app.snapshot.as_ref().map(|s| s.dual).unwrap_or(false) {
        // Dual-mine running → keep just the compact "active" indicator.
        ui.add_space(9.0);
        dual_mine_row(ui, app);
    }

    // ── The Alice Core hero ───────────────────────────────────────────────────
    ui.add_space(12.0);
    let mode = match state {
        EngineState::Running => HeroMode::Mining,
        EngineState::Starting => HeroMode::Connecting,
        EngineState::Stopping => HeroMode::Stopping,
        EngineState::Error => HeroMode::Error,
        EngineState::Idle => HeroMode::Idle,
    };
    let gauge = app.gauge();
    let motion = app.motion_enabled();
    let tex = app.mark_tex.clone().expect("mark texture loaded by chrome");
    let resp = ui
        .vertical_centered(|ui| hero::alice_core(ui, 118.0, mode, gauge, motion, &tex))
        .inner;
    if resp.clicked() {
        match state {
            EngineState::Running | EngineState::Starting => app.stop_mining(),
            // Idle OR Error OR (defensively) Stopping → (re)start.
            _ => app.start_mining(),
        }
    }

    // ── Readout BELOW the orb ─────────────────────────────────────────────────
    ui.add_space(10.0);
    readout(ui, app, mode);

    // ── Rewards-to line ───────────────────────────────────────────────────────
    ui.add_space(10.0);
    if let Some(addr) = app.reward_address() {
        // `center_row` runs its builder twice (a measure pass + the real pass),
        // so the click flag uses interior mutability (the sizing pass never
        // registers a real click, so this fires at most once).
        let do_copy = std::cell::Cell::new(false);
        centered(ui, |ui| {
            ui.label(RichText::new(strings::REWARDS_TO).size(12.5).color(THEME.text2));
            ui.add_space(6.0);
            ui.label(widgets::mono(widgets::shorten(&addr), 12.5, THEME.text));
            ui.add_space(4.0);
            if super::icons::show(ui, Icon::Copy, 13.0, THEME.text4)
                .interact(egui::Sense::click())
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .clicked()
            {
                do_copy.set(true);
            }
        });
        if do_copy.get() {
            ui.ctx().copy_text(addr.clone());
            app.copied_at = Some(std::time::Instant::now());
        }
    }

    // ── Status line ───────────────────────────────────────────────────────────
    ui.add_space(10.0);
    status_line(ui, app);

    // ── Stop button + dashboard link while mining/connecting/stopping ─────────
    if matches!(
        state,
        EngineState::Running | EngineState::Starting | EngineState::Stopping
    ) {
        ui.add_space(13.0);
        let stopping = matches!(state, EngineState::Stopping);
        let do_stop = std::cell::Cell::new(false);
        centered(ui, |ui| {
            let label = if stopping { "Stopping…" } else { "Stop mining" };
            let stop = egui::Button::new(RichText::new(label).size(12.5).color(THEME.text2))
                .fill(THEME.surface2)
                .stroke(egui::Stroke::new(1.0, THEME.line))
                .corner_radius(255)
                .min_size(egui::vec2(130.0, 34.0));
            // The button is inert during the stopping grace (non-interactive).
            if ui.add_enabled(!stopping, stop).clicked() {
                do_stop.set(true);
            }
        });
        if do_stop.get() {
            app.stop_mining();
        }
        if !stopping {
            ui.add_space(10.0);
            let go_dash = std::cell::Cell::new(false);
            centered(ui, |ui| {
                if ui
                    .add(
                        egui::Label::new(
                            RichText::new("Open dashboard →").size(12.0).strong().color(THEME.text_brand),
                        )
                        .sense(egui::Sense::click()),
                    )
                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                    .clicked()
                {
                    go_dash.set(true);
                }
            });
            if go_dash.get() {
                app.screen = crate::app::Screen::Dashboard;
            }
        }
    }

    // ── Honest footer ─────────────────────────────────────────────────────────
    ui.add_space(12.0);
    let r = ui.available_rect_before_wrap();
    ui.painter().hline(r.x_range(), r.top(), egui::Stroke::new(1.0, THEME.line));
    ui.add_space(10.0);
    footer(ui);
}

/// The readout beneath the orb — a different treatment per state, all centered.
fn readout(ui: &mut egui::Ui, app: &MinerApp, mode: HeroMode) {
    match mode {
        HeroMode::Mining => {
            // The live hashrate number (mono) + unit, then the hashing sub-line.
            let txt = format!("{:.2}", app.hr_display_khs);
            centered(ui, |ui| {
                ui.label(widgets::mono(txt.clone(), 31.0, THEME.text).strong());
                ui.add_space(5.0);
                ui.label(RichText::new("kH/s").size(13.0).strong().color(THEME.text3));
            });
            ui.add_space(4.0);
            centered(ui, |ui| {
                ui.label(
                    RichText::new(strings::HASHING_SUB)
                        .size(10.5)
                        .extra_letter_spacing(1.0)
                        .color(THEME.text4),
                );
            });
        }
        HeroMode::Connecting => {
            cta_readout(ui, strings::CTA_CONNECTING, strings::CTA_CONNECTING_SUB, THEME.warn, None);
        }
        HeroMode::Stopping => {
            cta_readout(ui, strings::CTA_STOPPING, strings::CTA_STOPPING_SUB, THEME.text2, None);
        }
        HeroMode::Error => {
            // Calm "start again" affordance — brand (inviting), never red.
            cta_readout(ui, strings::CTA_RETRY, strings::CTA_RETRY_SUB, THEME.text_brand, Some(Icon::Play));
        }
        HeroMode::Idle => {
            cta_readout(ui, strings::CTA_START, strings::CTA_START_SUB, THEME.text_brand, Some(Icon::Play));
        }
    }
}

/// A centered call-to-action readout: an optional leading glyph + a letter-spaced
/// label, then a small sub-line. Used by idle / connecting / stopping / error.
fn cta_readout(ui: &mut egui::Ui, label: &str, sub: &str, color: egui::Color32, glyph: Option<Icon>) {
    centered(ui, |ui| {
        if let Some(g) = glyph {
            super::icons::show(ui, g, 13.0, color);
            ui.add_space(8.0);
        }
        ui.label(
            RichText::new(label)
                .size(15.0)
                .strong()
                .extra_letter_spacing(3.0)
                .color(color),
        );
    });
    ui.add_space(6.0);
    centered(ui, |ui| {
        ui.label(
            RichText::new(sub)
                .size(10.5)
                .extra_letter_spacing(1.0)
                .color(THEME.text4),
        );
    });
}

fn status_line(ui: &mut egui::Ui, app: &MinerApp) {
    let blink = app.motion_enabled();
    let (tone, text) = match app.state() {
        EngineState::Running => {
            let a = app.snapshot.as_ref().map(|s| s.shares_accepted).unwrap_or(0);
            let r = app.snapshot.as_ref().map(|s| s.shares_rejected).unwrap_or(0);
            (Tone::Live, format!("Mining · {a}/{r} shares"))
        }
        EngineState::Starting => (Tone::Warn, strings::STATUS_CONNECTING.to_string()),
        EngineState::Stopping => (Tone::Warn, strings::STATUS_STOPPING.to_string()),
        EngineState::Error => (
            Tone::Danger,
            app.snapshot
                .as_ref()
                .and_then(|s| s.message.clone())
                .or_else(|| app.error.clone())
                .unwrap_or_else(|| strings::STATUS_ERROR_GENERIC.to_string()),
        ),
        EngineState::Idle => (Tone::Off, strings::STATUS_IDLE.to_string()),
    };
    let dot_blink = matches!(tone, Tone::Live | Tone::Warn) && blink;
    centered(ui, |ui| {
        widgets::status_dot(ui, tone.fg(), 8.0, dot_blink);
        ui.add_space(9.0);
        ui.label(RichText::new(text.clone()).size(12.5).color(THEME.text2));
    });
}

/// The lane row beneath the device line: the SELECTED lane as a filled chip,
/// plus the *other* lane as either a selectable chip (when runnable on this
/// device) or a muted "coming soon" / "Apple → XMR" chip (when not). On this
/// non-NVIDIA Mac the RVN chip reads "RVN · coming soon" and is inert, while XMR
/// stays selected — the honest M3 viability behaviour.
fn lane_selector(ui: &mut egui::Ui, app: &mut MinerApp) {
    let selected = app.active_lane();
    // While a run is in flight, the lane is locked (can't switch under a child).
    let locked = matches!(
        app.state(),
        EngineState::Running | EngineState::Starting | EngineState::Stopping
    );
    // Deterministic order: XMR then RVN.
    let lanes = [Lane::Xmr, Lane::GpuRvn];
    let pick = std::cell::Cell::new(None);
    centered(ui, |ui| {
        ui.spacing_mut().item_spacing.x = 7.0;
        for lane in lanes {
            let support = app.lane_support(lane);
            let is_sel = lane == selected;
            let resp = lane_chip(ui, lane, support, is_sel, locked);
            if resp.clicked() && !locked && support.is_runnable() && !is_sel {
                pick.set(Some(lane));
            }
        }
    });
    if let Some(lane) = pick.get() {
        app.select_lane(lane);
    }
}

/// The dual-mine toggle row beneath the lane selector. Runs BOTH lanes together
/// (CPU-XMR + GPU-RVN), each crash-isolated, `cores-2` XMR headroom. The toggle
/// is **gated on viability**: enabled only when ≥2 lanes are runnable. On this
/// Mac (Apple Silicon, no NVIDIA) only XMR is viable, so it renders DISABLED with
/// an honest "needs a supported GPU" hint — the user can't even flip it. When it
/// IS enabled and the user turns it on, a brief heat/fan confirmation is shown.
/// Hidden while a run is in flight (can't change topology under running children).
fn dual_mine_row(ui: &mut egui::Ui, app: &mut MinerApp) {
    let mid_run = matches!(
        app.state(),
        EngineState::Running | EngineState::Starting | EngineState::Stopping
    );
    if mid_run {
        // While mining, just reflect the active mode (no toggling).
        if app.snapshot.as_ref().map(|s| s.dual).unwrap_or(false) {
            centered(ui, |ui| {
                widgets::status_dot(ui, THEME.lane_gpu, 7.0, false);
                ui.add_space(7.0);
                ui.label(RichText::new("Dual-mine active · CPU + GPU").size(11.5).color(THEME.text3));
            });
        }
        return;
    }

    let viable = app.dual_viable();
    let on = app.dual_requested && viable;
    let toggled = std::cell::Cell::new(false);

    centered(ui, |ui| {
        ui.spacing_mut().item_spacing.x = 9.0;
        // Label + sub.
        ui.label(RichText::new("Dual-mine").size(12.5).strong().color(if viable { THEME.text2 } else { THEME.text4 }));
        ui.label(
            RichText::new(if viable { "CPU + GPU" } else { "needs a supported GPU" })
                .size(11.0)
                .color(THEME.text4),
        );
        // The toggle itself — only interactive when viable.
        if viable {
            if widgets::toggle(ui, on).clicked() {
                toggled.set(true);
            }
        } else {
            // A visibly disabled toggle (off, dimmed, no pointer / no click).
            let (rect, _resp) =
                ui.allocate_exact_size(egui::vec2(42.0, 24.0), egui::Sense::hover());
            let p = ui.painter_at(rect);
            p.rect_filled(rect, 255.0, THEME.well);
            p.rect_stroke(
                rect,
                255.0,
                egui::Stroke::new(1.0, THEME.line),
                egui::epaint::StrokeKind::Inside,
            );
            p.circle_filled(
                egui::pos2(rect.left() + 12.0, rect.center().y),
                9.0,
                THEME.off.gamma_multiply(0.6),
            );
        }
    });

    if toggled.get() {
        if app.dual_requested {
            // Turning OFF → clear the confirm too.
            app.dual_requested = false;
            app.dual_confirm_open = false;
        } else {
            // Turning ON → open the heat/fan confirmation (require an explicit ack).
            app.dual_confirm_open = true;
        }
    }

    // The brief heat/fan confirmation (shown until acknowledged). A calm, honest
    // note that dual-mine pushes the device harder; "Enable" commits, "Cancel"
    // reverts to single-lane.
    if app.dual_confirm_open && viable {
        ui.add_space(8.0);
        let commit = std::cell::Cell::new(false);
        let cancel = std::cell::Cell::new(false);
        egui::Frame::NONE
            .fill(THEME.well)
            .corner_radius(11)
            .inner_margin(egui::Margin::symmetric(13, 11))
            .stroke(egui::Stroke::new(1.0, THEME.line_strong))
            .show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.label(
                        RichText::new("Dual-mine runs CPU and GPU together")
                            .size(12.0)
                            .strong()
                            .color(THEME.text),
                    );
                    ui.add_space(3.0);
                    ui.label(
                        RichText::new("More heat + fan noise; XMR drops 2 cores for the GPU. You can stop anytime.")
                            .size(11.0)
                            .color(THEME.text3),
                    );
                    ui.add_space(9.0);
                    ui.horizontal(|ui| {
                        let cancel_btn = egui::Button::new(RichText::new("Cancel").size(12.0).color(THEME.text2))
                            .fill(THEME.surface2)
                            .stroke(egui::Stroke::new(1.0, THEME.line))
                            .corner_radius(8)
                            .min_size(egui::vec2(84.0, 30.0));
                        if ui.add(cancel_btn).clicked() {
                            cancel.set(true);
                        }
                        ui.add_space(8.0);
                        let ok_btn = egui::Button::new(RichText::new("Enable dual-mine").size(12.0).strong().color(THEME.ink_on_brand))
                            .fill(THEME.brand)
                            .corner_radius(8)
                            .min_size(egui::vec2(140.0, 30.0));
                        if ui.add(ok_btn).clicked() {
                            commit.set(true);
                        }
                    });
                });
            });
        if commit.get() {
            app.dual_requested = true;
            app.dual_confirm_open = false;
        }
        if cancel.get() {
            app.dual_requested = false;
            app.dual_confirm_open = false;
        }
    }
}

/// One lane chip. Selected → filled with the lane accent + a dot. Runnable but
/// unselected → a normal selectable chip (pointer cursor). Coming-soon →
/// muted, with a "coming soon" tail, NON-interactive. Unavailable (e.g. RVN on
/// Apple) → dim "XMR only"/"not supported" tail, NON-interactive.
fn lane_chip(
    ui: &mut egui::Ui,
    lane: Lane,
    support: LaneSupport,
    selected: bool,
    locked: bool,
) -> egui::Response {
    let accent = lane_accent(lane);
    let base = lane_chip_label(lane); // "XMR · RandomX" / "RVN · KawPoW"
    let runnable = support.is_runnable();

    // Compose the chip text: the base label, plus a state tail for non-runnable.
    let (text, text_color, dot, stroke) = match support {
        LaneSupport::Viable => {
            if selected {
                (
                    base.to_string(),
                    THEME.text,
                    Some(accent),
                    egui::Stroke::new(1.0, accent.gamma_multiply(0.8)),
                )
            } else {
                (
                    base.to_string(),
                    THEME.text2,
                    Some(accent.gamma_multiply(0.6)),
                    egui::Stroke::new(1.0, THEME.line),
                )
            }
        }
        LaneSupport::ComingSoon => (
            // "RVN · coming soon" (drop the algo to make room for the state).
            format!("{} · coming soon", lane_short(lane)),
            THEME.text4,
            None,
            egui::Stroke::new(1.0, THEME.line),
        ),
        LaneSupport::Unavailable => (
            format!("{} · {}", lane_short(lane), unavailable_tail(lane)),
            THEME.text4,
            None,
            egui::Stroke::new(1.0, THEME.line),
        ),
    };

    let fill = if selected && runnable {
        // A subtle accent-tinted fill so the selected lane reads as "active".
        egui::Color32::from_rgba_unmultiplied(accent.r(), accent.g(), accent.b(), 26)
    } else {
        THEME.surface2
    };

    let frame = egui::Frame::NONE
        .fill(fill)
        .corner_radius(255)
        .inner_margin(egui::Margin::symmetric(12, 6))
        .stroke(stroke)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                if let Some(c) = dot {
                    let (r, _) = ui.allocate_exact_size(egui::vec2(7.0, 7.0), egui::Sense::hover());
                    ui.painter().circle_filled(r.center(), 3.5, c);
                }
                ui.label(RichText::new(text).size(12.5).color(text_color));
            });
        });

    // Make runnable, unselected, unlocked chips clickable (pointer cursor).
    let resp = frame.response;
    if runnable && !selected && !locked {
        resp.clone()
            .interact(egui::Sense::click())
            .on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        resp.interact(egui::Sense::hover())
    }
}

/// The short lane tag (no algo), for the constrained "coming soon" chips.
fn lane_short(lane: Lane) -> &'static str {
    match lane {
        Lane::Xmr => "XMR",
        Lane::GpuRvn => "RVN",
    }
}

/// The honest tail for an Unavailable lane (why it can't run here).
fn unavailable_tail(lane: Lane) -> &'static str {
    match lane {
        // RVN unavailable means no NVIDIA (Apple/CPU-only) → XMR is the lane.
        Lane::GpuRvn => "needs NVIDIA",
        Lane::Xmr => "not supported",
    }
}

/// Centre a row of inline widgets horizontally within the card (delegates to the
/// measured-centering helper so a mixed icon+text row truly centres).
fn centered(ui: &mut egui::Ui, add: impl Fn(&mut egui::Ui)) {
    widgets::center_row(ui, add);
}

fn footer(ui: &mut egui::Ui) {
    // Two STACKED centered lines (not a row) — center each independently.
    centered(ui, |ui| {
        ui.label(RichText::new(strings::FOOTER_LINE_1).size(10.5).color(THEME.text3));
    });
    centered(ui, |ui| {
        ui.label(RichText::new(strings::FOOTER_LINE_2).size(10.5).color(THEME.text3));
    });
}
