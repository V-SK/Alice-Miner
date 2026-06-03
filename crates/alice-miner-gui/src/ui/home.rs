//! Home — the one-click screen (mockup `02a` idle / `02b` mining).
//!
//! Device auto-detected line + lane chip, the Alice Core hero as the single
//! Start/Stop control, "Rewards to <addr>", a status line, and the honest
//! credit-only footer. All reward copy comes from [`crate::ui::strings`].

use eframe::egui::{self, RichText};

use super::hero::{self, HeroMode};
use super::icons::Icon;
use super::strings;
use super::theme::THEME;
use super::widgets::{self, Tone};
use crate::app::MinerApp;
use alice_miner_core::EngineState;

pub fn render(ui: &mut egui::Ui, app: &mut MinerApp) {
    // Vertically + horizontally centre the hero card.
    ui.vertical_centered(|ui| {
        ui.add_space((ui.available_height() * 0.5 - 290.0).max(18.0));
        widgets::card(ui, 392.0, |ui| {
            ui.vertical_centered(|ui| {
                hero_card_body(ui, app);
            });
        });
    });
}

fn hero_card_body(ui: &mut egui::Ui, app: &mut MinerApp) {
    let mining = app.is_mining();

    // Eyebrow.
    widgets::eyebrow(ui, if mining { "Mining · live" } else { "Device auto-detected" });
    ui.add_space(14.0);

    // Device line: chip + model string (model only, e.g. "Apple M2 Max · 12 cores").
    let model = app
        .device
        .as_ref()
        .map(|d| d.display.clone())
        .unwrap_or_else(|| "Detecting device…".to_string());
    centered_row(ui, |ui| {
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
        ui.label(RichText::new(model).size(15.5).strong().color(THEME.text));
    });

    ui.add_space(12.0);
    // Lane chip (XMR · RandomX).
    centered_row(ui, |ui| {
        widgets::chip(ui, Some(THEME.lane_xmr), "XMR · RandomX");
    });

    // ── The Alice Core hero ───────────────────────────────────────────────────
    ui.add_space(26.0);
    let mode = match app.state() {
        EngineState::Running => HeroMode::Mining,
        EngineState::Starting => HeroMode::Connecting,
        _ => HeroMode::Idle,
    };
    let gauge = app.gauge();
    let tex = app.mark_tex.clone().expect("mark texture loaded by chrome");
    let resp = ui
        .vertical_centered(|ui| hero::alice_core(ui, 170.0, mode, gauge, &tex))
        .inner;
    if resp.clicked() {
        match app.state() {
            EngineState::Running | EngineState::Starting => app.stop_mining(),
            _ => app.start_mining(),
        }
    }

    // ── Readout BELOW the orb ─────────────────────────────────────────────────
    ui.add_space(20.0);
    match mode {
        HeroMode::Mining => {
            // The live hashrate number (mono) + unit, then the hashing sub-line.
            let txt = format!("{:.2}", app.hr_display_khs);
            centered_row(ui, |ui| {
                ui.label(widgets::mono(txt, 33.0, THEME.text).strong());
                ui.add_space(5.0);
                ui.label(RichText::new("kH/s").size(13.0).strong().color(THEME.text3));
            });
            ui.add_space(4.0);
            ui.label(
                RichText::new(strings::HASHING_SUB)
                    .size(10.5)
                    .extra_letter_spacing(1.0)
                    .color(THEME.text4),
            );
        }
        HeroMode::Connecting => {
            ui.label(RichText::new("CONNECTING").size(15.0).strong().extra_letter_spacing(3.0).color(THEME.warn));
            ui.add_space(4.0);
            ui.label(RichText::new("starting engine · 连接中").size(10.5).color(THEME.text4));
        }
        HeroMode::Idle => {
            // START cta + sub.
            centered_row(ui, |ui| {
                super::icons::show(ui, Icon::Play, 13.0, THEME.text_brand);
                ui.add_space(8.0);
                ui.label(
                    RichText::new(strings::CTA_START)
                        .size(15.0)
                        .strong()
                        .extra_letter_spacing(3.0)
                        .color(THEME.text_brand),
                );
            });
            ui.add_space(6.0);
            ui.label(
                RichText::new(strings::CTA_START_SUB)
                    .size(10.5)
                    .extra_letter_spacing(1.0)
                    .color(THEME.text4),
            );
        }
    }

    // ── Rewards-to line ───────────────────────────────────────────────────────
    ui.add_space(14.0);
    if let Some(addr) = app.reward_address() {
        let mut do_copy = false;
        centered_row(ui, |ui| {
            ui.label(RichText::new(strings::REWARDS_TO).size(12.5).color(THEME.text2));
            ui.add_space(6.0);
            ui.label(widgets::mono(widgets::shorten(&addr), 12.5, THEME.text));
            ui.add_space(4.0);
            if super::icons::show(ui, Icon::Copy, 13.0, THEME.text4)
                .interact(egui::Sense::click())
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .clicked()
            {
                do_copy = true;
            }
        });
        if do_copy {
            ui.ctx().copy_text(addr.clone());
            app.copied_at = Some(std::time::Instant::now());
        }
    }

    // ── Status line ───────────────────────────────────────────────────────────
    ui.add_space(13.0);
    status_line(ui, app);

    // Error (if any).
    if let Some(err) = &app.error {
        ui.add_space(10.0);
        ui.label(RichText::new(err).size(11.5).color(THEME.err));
    }

    // ── Stop button + dashboard link while mining ─────────────────────────────
    if matches!(app.state(), EngineState::Running | EngineState::Starting | EngineState::Stopping) {
        ui.add_space(15.0);
        let mut do_stop = false;
        centered_row(ui, |ui| {
            let stop = egui::Button::new(RichText::new("Stop mining").size(12.5).color(THEME.text2))
                .fill(THEME.surface2)
                .stroke(egui::Stroke::new(1.0, THEME.line))
                .corner_radius(255)
                .min_size(egui::vec2(130.0, 34.0));
            if ui.add(stop).clicked() {
                do_stop = true;
            }
        });
        if do_stop {
            app.stop_mining();
        }
        ui.add_space(11.0);
        if ui
            .add(egui::Label::new(RichText::new("Open dashboard →").size(12.0).strong().color(THEME.text_brand)).sense(egui::Sense::click()))
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .clicked()
        {
            app.screen = crate::app::Screen::Dashboard;
        }
    }

    // ── Honest footer ─────────────────────────────────────────────────────────
    ui.add_space(18.0);
    let r = ui.available_rect_before_wrap();
    ui.painter().hline(r.x_range(), r.top(), egui::Stroke::new(1.0, THEME.line));
    ui.add_space(14.0);
    footer(ui);
}

fn status_line(ui: &mut egui::Ui, app: &MinerApp) {
    let (tone, text) = match app.state() {
        EngineState::Running => {
            let a = app.snapshot.as_ref().map(|s| s.shares_accepted).unwrap_or(0);
            let r = app.snapshot.as_ref().map(|s| s.shares_rejected).unwrap_or(0);
            (Tone::Live, format!("Mining · {a}/{r} shares"))
        }
        EngineState::Starting => (Tone::Warn, "Connecting to relay…".into()),
        EngineState::Stopping => (Tone::Warn, "Stopping…".into()),
        EngineState::Error => (
            Tone::Danger,
            app.snapshot
                .as_ref()
                .and_then(|s| s.message.clone())
                .unwrap_or_else(|| "Engine error".into()),
        ),
        EngineState::Idle => (Tone::Off, "Idle — press Start to begin".into()),
    };
    centered_row(ui, |ui| {
        widgets::status_dot(ui, tone.fg(), 8.0, matches!(tone, Tone::Live | Tone::Warn));
        ui.add_space(9.0);
        ui.label(RichText::new(text).size(12.5).color(THEME.text2));
    });
}

/// Lay out a row of inline widgets centered horizontally within the card. egui
/// centers a child block that sizes to its content, so we run the row in a
/// `top_down(Center)` sub-layout — no manual pixel measurement needed.
fn centered_row(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    ui.with_layout(egui::Layout::top_down(egui::Align::Center), |ui| {
        ui.horizontal(|ui| add(ui));
    });
}

fn footer(ui: &mut egui::Ui) {
    ui.vertical_centered(|ui| {
        // Line 1 with the pending tag emphasised in brand colour.
        ui.label(
            RichText::new(strings::FOOTER_LINE_1)
                .size(10.5)
                .color(THEME.text3),
        );
        ui.label(
            RichText::new(strings::FOOTER_LINE_2)
                .size(10.5)
                .color(THEME.text3),
        );
    });
}
