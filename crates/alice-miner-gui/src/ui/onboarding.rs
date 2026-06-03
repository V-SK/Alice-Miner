//! Onboarding (mockup `01`/`01b`) — only shown when there is no
//! `~/.alice/identity.json`. Three entry points:
//!   * **Create** → generate a 24-word mnemonic; the core returns it for a
//!     FORCED backup step (show the words, require acknowledgement) → Home.
//!   * **Import** → paste a 12/24-word mnemonic or a raw seed (hex).
//!   * **Paste address** → watch-only (no keystore).
//!
//! Functional + lightly styled (M2 polishes); all identity work goes through the
//! engine (`Command::Identity`) so the core writes the keystore + pointer.

use eframe::egui::{self, RichText};

use super::icons::Icon;
use super::theme::THEME;
use super::widgets;
use crate::app::{MinerApp, Onboarding};

pub fn render(ui: &mut egui::Ui, app: &mut MinerApp) {
    let step = app.onboarding.clone().unwrap_or(Onboarding::Choose);
    ui.vertical_centered(|ui| {
        ui.add_space((ui.available_height() * 0.5 - 250.0).max(18.0));
        widgets::card(ui, 440.0, |ui| match step {
            Onboarding::Choose => choose(ui, app),
            Onboarding::Backup { mnemonic, acknowledged } => backup(ui, app, &mnemonic, acknowledged),
            Onboarding::Import => import(ui, app),
            Onboarding::Paste => paste(ui, app),
        });
    });
}

fn header(ui: &mut egui::Ui, eyebrow: &str, title: &str, sub: &str) {
    ui.vertical_centered(|ui| {
        widgets::eyebrow(ui, eyebrow);
        ui.add_space(12.0);
        ui.label(RichText::new(title).size(19.0).strong().color(THEME.text));
        ui.add_space(6.0);
        ui.label(RichText::new(sub).size(12.5).color(THEME.text3));
    });
    ui.add_space(18.0);
}

fn choose(ui: &mut egui::Ui, app: &mut MinerApp) {
    header(
        ui,
        "Welcome · 欢迎",
        "Set up your reward identity",
        "One Alice identity works in Wallet, Miner & AI.",
    );

    // Create (primary).
    ui.label(RichText::new("Create a new identity").size(13.0).strong().color(THEME.text));
    ui.add_space(4.0);
    ui.label(RichText::new("Generate a fresh 24-word recovery phrase.").size(11.5).color(THEME.text3));
    ui.add_space(8.0);
    widgets::field_label(ui, "Password (encrypts the keystore)");
    widgets::text_input(ui, &mut app.form_password, "at least 8 characters", false).changed();
    ui.add_space(6.0);
    widgets::field_label(ui, "Confirm password");
    widgets::text_input(ui, &mut app.form_password2, "re-enter password", false);
    ui.add_space(12.0);
    if widgets::primary_button(ui, "Generate identity", true, true).clicked() {
        app.submit_create();
    }

    ui.add_space(16.0);
    divider_or(ui);
    ui.add_space(14.0);

    // Import / paste (ghost rows).
    ui.horizontal(|ui| {
        if variant_button(ui, Icon::Import, "Import existing", "mnemonic / seed").clicked() {
            app.error = None;
            app.onboarding = Some(Onboarding::Import);
        }
    });
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        if variant_button(ui, Icon::Eye, "Paste address", "watch-only").clicked() {
            app.error = None;
            app.onboarding = Some(Onboarding::Paste);
        }
    });

    error(ui, app);
}

fn backup(ui: &mut egui::Ui, app: &mut MinerApp, mnemonic: &str, acknowledged: bool) {
    header(
        ui,
        "Step · back up",
        "Write down your recovery phrase",
        "24 words. The only way to recover this identity.",
    );

    // Warning banner.
    egui::Frame::NONE
        .fill(egui::Color32::from_rgba_unmultiplied(245, 158, 11, 26))
        .corner_radius(10)
        .inner_margin(egui::Margin::same(13))
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(245, 158, 11, 72)))
        .show(ui, |ui| {
            ui.horizontal_top(|ui| {
                super::icons::show(ui, Icon::Alert, 15.0, THEME.warn);
                ui.add_space(10.0);
                ui.label(
                    RichText::new(
                        "This is the only way to recover. Anyone with these words controls the address. Store offline — never paste it online.",
                    )
                    .size(11.5)
                    .color(egui::Color32::from_rgb(0xFC, 0xD9, 0xA0)),
                );
            });
        });

    // The 24 words in a 3-column grid.
    ui.add_space(14.0);
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    egui::Grid::new("mnemonic-grid")
        .num_columns(3)
        .spacing(egui::vec2(7.0, 7.0))
        .show(ui, |ui| {
            for (i, w) in words.iter().enumerate() {
                word_cell(ui, i + 1, w);
                if (i + 1) % 3 == 0 {
                    ui.end_row();
                }
            }
        });

    ui.add_space(12.0);
    if ui
        .add(egui::Button::new(RichText::new("Copy all").size(11.5).color(THEME.text3))
            .fill(egui::Color32::TRANSPARENT)
            .stroke(egui::Stroke::new(1.0, THEME.line))
            .corner_radius(8))
        .clicked()
    {
        ui.ctx().copy_text(mnemonic.to_string());
        app.copied_at = Some(std::time::Instant::now());
    }

    ui.add_space(14.0);
    // Acknowledgement checkbox.
    let mut ack = acknowledged;
    if ui
        .checkbox(&mut ack, RichText::new("I've written down all 24 words and stored them safely.").size(12.0).color(THEME.text2))
        .changed()
    {
        app.onboarding = Some(Onboarding::Backup { mnemonic: mnemonic.to_string(), acknowledged: ack });
    }

    ui.add_space(14.0);
    if widgets::primary_button(ui, "Continue to Home", ack, true).clicked() {
        app.finish_backup();
    }
}

fn import(ui: &mut egui::Ui, app: &mut MinerApp) {
    header(ui, "Import", "Import an existing identity", "Paste a 12/24-word phrase, or a raw seed (hex).");

    // Toggle: mnemonic vs seed.
    ui.horizontal(|ui| {
        if seg_button(ui, "Mnemonic", !app.form_use_seed).clicked() {
            app.form_use_seed = false;
        }
        ui.add_space(2.0);
        if seg_button(ui, "Seed (hex)", app.form_use_seed).clicked() {
            app.form_use_seed = true;
        }
    });
    ui.add_space(12.0);

    if app.form_use_seed {
        widgets::field_label(ui, "32-byte seed (hex, optional 0x)");
        widgets::text_input(ui, &mut app.form_seed, "0x…", true);
    } else {
        widgets::field_label(ui, "Recovery phrase");
        widgets::text_area(ui, &mut app.form_mnemonic, "word1 word2 word3 …", 3);
    }

    ui.add_space(10.0);
    widgets::field_label(ui, "Password (encrypts the keystore)");
    widgets::text_input(ui, &mut app.form_password, "at least 8 characters", false);

    ui.add_space(14.0);
    ui.horizontal(|ui| {
        if widgets::ghost_button(ui, "Back", false).clicked() {
            app.onboarding = Some(Onboarding::Choose);
        }
        ui.add_space(8.0);
        if widgets::primary_button(ui, "Import", true, true).clicked() {
            app.submit_import();
        }
    });
    error(ui, app);
}

fn paste(ui: &mut egui::Ui, app: &mut MinerApp) {
    header(ui, "Watch-only", "Paste an Alice address", "Track rewards for an address you own. No keys stored.");

    widgets::field_label(ui, "Alice address (SS58-300)");
    widgets::text_input(ui, &mut app.form_address, "a2x9…", true);

    ui.add_space(14.0);
    ui.horizontal(|ui| {
        if widgets::ghost_button(ui, "Back", false).clicked() {
            app.onboarding = Some(Onboarding::Choose);
        }
        ui.add_space(8.0);
        if widgets::primary_button(ui, "Use this address", true, true).clicked() {
            app.submit_paste();
        }
    });
    error(ui, app);
}

// ── small helpers ─────────────────────────────────────────────────────────────

fn word_cell(ui: &mut egui::Ui, idx: usize, word: &str) {
    egui::Frame::NONE
        .fill(THEME.well)
        .corner_radius(9)
        .inner_margin(egui::Margin::symmetric(10, 9))
        .stroke(egui::Stroke::new(1.0, THEME.line))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.set_min_width(96.0);
                ui.label(widgets::mono(format!("{idx:>2}"), 10.0, THEME.text4));
                ui.add_space(7.0);
                ui.label(widgets::mono(word, 12.5, THEME.text));
            });
        });
}

fn variant_button(ui: &mut egui::Ui, icon: Icon, title: &str, badge: &str) -> egui::Response {
    let resp = egui::Frame::NONE
        .fill(THEME.surface2)
        .corner_radius(12)
        .inner_margin(egui::Margin::symmetric(15, 13))
        .stroke(egui::Stroke::new(1.0, THEME.line))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                egui::Frame::NONE
                    .fill(THEME.surface3)
                    .corner_radius(8)
                    .inner_margin(egui::Margin::same(5))
                    .show(ui, |ui| super::icons::show(ui, icon, 15.0, THEME.text2));
                ui.add_space(9.0);
                ui.label(RichText::new(title).size(13.0).strong().color(THEME.text));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    super::icons::show(ui, Icon::ArrowRight, 14.0, THEME.text3);
                    ui.add_space(8.0);
                    egui::Frame::NONE
                        .corner_radius(255)
                        .inner_margin(egui::Margin::symmetric(8, 3))
                        .stroke(egui::Stroke::new(1.0, THEME.line))
                        .show(ui, |ui| {
                            ui.label(RichText::new(badge.to_uppercase()).size(9.5).extra_letter_spacing(0.8).color(THEME.text3));
                        });
                });
            });
        });
    resp.response.interact(egui::Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn seg_button(ui: &mut egui::Ui, label: &str, on: bool) -> egui::Response {
    let btn = egui::Button::new(
        RichText::new(label).size(12.0).strong().color(if on { THEME.ink_on_brand } else { THEME.text3 }),
    )
    .fill(if on { THEME.brand } else { THEME.well })
    .stroke(egui::Stroke::new(1.0, if on { THEME.brand } else { THEME.line_strong }))
    .corner_radius(8)
    .min_size(egui::vec2(110.0, 32.0));
    ui.add(btn)
}

fn divider_or(ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        let avail = ui.available_width();
        let seg = (avail - 40.0) / 2.0;
        let (r1, _) = ui.allocate_exact_size(egui::vec2(seg, 1.0), egui::Sense::hover());
        ui.painter().hline(r1.x_range(), r1.center().y, egui::Stroke::new(1.0, THEME.line));
        ui.label(RichText::new("or").size(11.0).color(THEME.text4));
        let (r2, _) = ui.allocate_exact_size(egui::vec2(seg, 1.0), egui::Sense::hover());
        ui.painter().hline(r2.x_range(), r2.center().y, egui::Stroke::new(1.0, THEME.line));
    });
}

fn error(ui: &mut egui::Ui, app: &MinerApp) {
    if let Some(err) = &app.error {
        ui.add_space(12.0);
        egui::Frame::NONE
            .fill(egui::Color32::from_rgba_unmultiplied(239, 68, 68, 26))
            .corner_radius(10)
            .inner_margin(egui::Margin::same(12))
            .stroke(egui::Stroke::new(1.0, THEME.err))
            .show(ui, |ui| {
                ui.label(RichText::new(err).size(12.0).color(THEME.err));
            });
    }
}
