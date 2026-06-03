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
use crate::app::MinerApp;
use alice_miner_core::EngineState;

pub fn render(ui: &mut egui::Ui, app: &mut MinerApp) {
    // Vertically + horizontally centre the hero card. The card is tall (hero orb
    // + readout + footer ≈ 600px), so we only add a modest top inset and let the
    // surrounding panel scroll if a very short window clips it.
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.vertical_centered(|ui| {
                let slack = (ui.available_height() - 600.0).max(0.0);
                ui.add_space((slack * 0.5).clamp(8.0, 40.0));
                widgets::card(ui, 392.0, |ui| {
                    hero_card_body(ui, app);
                });
                ui.add_space(20.0);
            });
        });
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
    ui.add_space(14.0);

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

    ui.add_space(12.0);
    // Lane chip (XMR · RandomX).
    centered(ui, |ui| {
        widgets::chip(ui, Some(THEME.lane_xmr), "XMR · RandomX");
    });

    // ── The Alice Core hero ───────────────────────────────────────────────────
    ui.add_space(18.0);
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
        .vertical_centered(|ui| hero::alice_core(ui, 150.0, mode, gauge, motion, &tex))
        .inner;
    if resp.clicked() {
        match state {
            EngineState::Running | EngineState::Starting => app.stop_mining(),
            // Idle OR Error OR (defensively) Stopping → (re)start.
            _ => app.start_mining(),
        }
    }

    // ── Readout BELOW the orb ─────────────────────────────────────────────────
    ui.add_space(14.0);
    readout(ui, app, mode);

    // ── Rewards-to line ───────────────────────────────────────────────────────
    ui.add_space(12.0);
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
    ui.add_space(13.0);
    status_line(ui, app);

    // ── Stop button + dashboard link while mining/connecting/stopping ─────────
    if matches!(
        state,
        EngineState::Running | EngineState::Starting | EngineState::Stopping
    ) {
        ui.add_space(15.0);
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
            ui.add_space(11.0);
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
    ui.add_space(14.0);
    let r = ui.available_rect_before_wrap();
    ui.painter().hline(r.x_range(), r.top(), egui::Stroke::new(1.0, THEME.line));
    ui.add_space(12.0);
    footer(ui);
}

/// The readout beneath the orb — a different treatment per state, all centered.
fn readout(ui: &mut egui::Ui, app: &MinerApp, mode: HeroMode) {
    match mode {
        HeroMode::Mining => {
            // The live hashrate number (mono) + unit, then the hashing sub-line.
            let txt = format!("{:.2}", app.hr_display_khs);
            centered(ui, |ui| {
                ui.label(widgets::mono(txt.clone(), 33.0, THEME.text).strong());
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
