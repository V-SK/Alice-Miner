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
use super::strings;
use super::theme::THEME;
use super::widgets;
use crate::app::{MinerApp, Onboarding};

pub fn render(ui: &mut egui::Ui, app: &mut MinerApp) {
    let step = app.onboarding.clone().unwrap_or(Onboarding::Choose);
    // Wrap in a vertical ScrollArea so the taller wizard steps (backup / confirm)
    // are never clipped at the min window size — they scroll instead.
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.vertical_centered(|ui| {
                // Only enough top inset to centre on a tall window; on a short one
                // it collapses to a small margin and the ScrollArea takes over.
                ui.add_space((ui.available_height() * 0.5 - 250.0).max(18.0));
                widgets::card(ui, 440.0, |ui| match step {
                    Onboarding::Choose => choose(ui, app),
                    Onboarding::Backup { mnemonic, acknowledged } => backup(ui, app, &mnemonic, acknowledged),
                    Onboarding::Confirm { mnemonic } => confirm(ui, app, &mnemonic),
                    Onboarding::Import => import(ui, app),
                    Onboarding::Paste => paste(ui, app),
                });
                ui.add_space(24.0);
            });
        });
}

/// The 3-dot progress rail at the top of a wizard step. `step` is 1-based; dots
/// before it read "done", the current one is the elongated brand pill.
fn steps(ui: &mut egui::Ui, step: usize) {
    widgets::center_row(ui, |ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        for i in 1..=3 {
            let (w, color) = if i == step {
                (22.0, THEME.brand) // current — elongated pill
            } else if i < step {
                (7.0, THEME.brand700) // done
            } else {
                (7.0, THEME.line_strong) // upcoming
            };
            let (r, _) = ui.allocate_exact_size(egui::vec2(w, 7.0), egui::Sense::hover());
            ui.painter().rect_filled(r, 255.0, color);
        }
    });
    ui.add_space(10.0);
}

/// Centre a content block horizontally (same idiom as `home::centered`).
fn centered(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    ui.with_layout(egui::Layout::top_down(egui::Align::Center), |ui| add(ui));
}

fn header(ui: &mut egui::Ui, eyebrow: &str, title: &str, sub: &str) {
    centered(ui, |ui| {
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
        strings::OB_WELCOME_EYEBROW,
        strings::OB_WELCOME_TITLE,
        strings::OB_WELCOME_SUB,
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
    steps(ui, 2);
    header(
        ui,
        strings::OB_BACKUP_EYEBROW,
        strings::OB_BACKUP_TITLE,
        strings::OB_BACKUP_SUB,
    );

    // Warning banner.
    egui::Frame::NONE
        .fill(egui::Color32::from_rgba_unmultiplied(245, 158, 11, 26))
        .corner_radius(10)
        .inner_margin(egui::Margin::same(13))
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(245, 158, 11, 72)))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                super::icons::show(ui, Icon::Alert, 15.0, THEME.warn);
                ui.add_space(10.0);
                ui.label(
                    RichText::new(strings::OB_BACKUP_WARNING)
                        .size(11.5)
                        .color(egui::Color32::from_rgb(0xFC, 0xD9, 0xA0)),
                );
            });
        });

    // The 24 words in a 3-column grid (centered within the card).
    ui.add_space(14.0);
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    centered(ui, |ui| {
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
        .checkbox(&mut ack, RichText::new(strings::OB_BACKUP_ACK).size(12.0).color(THEME.text2))
        .changed()
    {
        app.onboarding = Some(Onboarding::Backup { mnemonic: mnemonic.to_string(), acknowledged: ack });
    }

    ui.add_space(14.0);
    if widgets::primary_button(ui, "Continue to confirm", ack, true).clicked() {
        app.begin_confirm(mnemonic);
    }
}

/// Step 3 — confirm the backup by re-picking the words at 3 random positions
/// (PLAN §4 forced-backup divergence). Empty slots + a shuffled chip pool; tap a
/// chip to fill the next slot, tap a filled slot to clear it. All-correct + full
/// → finish onboarding to Home.
fn confirm(ui: &mut egui::Ui, app: &mut MinerApp, mnemonic: &str) {
    steps(ui, 3);
    header(
        ui,
        strings::OB_CONFIRM_EYEBROW,
        strings::OB_CONFIRM_TITLE,
        "",
    );

    // Prompt: "Tap the right words for positions #3, #9 and #11."
    let positions = app
        .confirm_targets
        .iter()
        .map(|p| format!("#{p}"))
        .collect::<Vec<_>>()
        .join(" · ");
    centered(ui, |ui| {
        ui.label(
            RichText::new(format!("Tap the right words for positions {positions}."))
                .size(12.0)
                .color(THEME.text2),
        );
    });

    // Slots.
    ui.add_space(12.0);
    let targets = app.confirm_targets.clone();
    let filled = app.confirm_filled.clone();
    let mut clear_idx: Option<usize> = None;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        let slot_w = (ui.available_width() - 8.0 * (targets.len().max(1) as f32 - 1.0))
            / targets.len().max(1) as f32;
        for (i, pos) in targets.iter().enumerate() {
            if confirm_slot(ui, slot_w, *pos, filled.get(i).and_then(|f| f.as_deref())).clicked()
                && filled.get(i).map(|f| f.is_some()).unwrap_or(false)
            {
                clear_idx = Some(i);
            }
        }
    });
    if let Some(i) = clear_idx {
        app.confirm_clear(i);
        app.error = None;
    }

    // Chip pool. Pre-compute a per-chip-instance "used" flag so that if the same
    // word appears twice in the pool, only as many instances grey out as there
    // are filled slots holding it (correct behaviour for duplicate BIP39 words).
    ui.add_space(12.0);
    let pool = app.confirm_pool.clone();
    let used_count = app.confirm_filled.iter().filter(|f| f.is_some()).count();
    let mut budget: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for f in app.confirm_filled.iter().flatten() {
        *budget.entry(f.as_str()).or_insert(0) += 1;
    }
    let used_flags: Vec<bool> = pool
        .iter()
        .map(|w| {
            let c = budget.entry(w.as_str()).or_insert(0);
            if *c > 0 {
                *c -= 1;
                true
            } else {
                false
            }
        })
        .collect();
    let mut to_place: Option<String> = None;
    centered(ui, |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = egui::vec2(7.0, 7.0);
            for (w, &is_used) in pool.iter().zip(used_flags.iter()) {
                if word_chip(ui, w, is_used).clicked() && !is_used && used_count < targets.len() {
                    to_place = Some(w.clone());
                }
            }
        });
    });
    if let Some(w) = to_place {
        app.confirm_place(&w);
        app.error = None;
    }

    // Feedback: if all slots are full but wrong, show a calm hint.
    let all_full = app.confirm_filled.iter().all(|f| f.is_some());
    let correct = app.confirm_is_correct(mnemonic);
    if all_full && !correct {
        ui.add_space(10.0);
        centered(ui, |ui| {
            ui.label(RichText::new(strings::OB_CONFIRM_WRONG).size(11.5).color(THEME.warn));
        });
    }

    // Actions: Back (to backup) + Confirm (enabled only when correct).
    ui.add_space(16.0);
    ui.horizontal(|ui| {
        if widgets::ghost_button(ui, "Back", false).clicked() {
            app.onboarding = Some(Onboarding::Backup {
                mnemonic: mnemonic.to_string(),
                acknowledged: true,
            });
            app.error = None;
        }
        ui.add_space(8.0);
        if widgets::primary_button(ui, "Confirm & finish", correct, true).clicked() {
            app.finish_backup();
        }
    });
}

fn import(ui: &mut egui::Ui, app: &mut MinerApp) {
    header(ui, strings::OB_IMPORT_EYEBROW, strings::OB_IMPORT_TITLE, strings::OB_IMPORT_SUB);

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
    header(ui, strings::OB_PASTE_EYEBROW, strings::OB_PASTE_TITLE, strings::OB_PASTE_SUB);

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

/// A confirm slot: a fixed-height pill showing `#pos` and either the chosen word
/// (filled, brand-tinted) or a dashed "tap word" placeholder. Returns its click
/// response (a filled slot is clickable to clear).
fn confirm_slot(ui: &mut egui::Ui, width: f32, pos: usize, word: Option<&str>) -> egui::Response {
    let filled = word.is_some();
    let (fill, stroke, kind) = if filled {
        (
            egui::Color32::from_rgba_unmultiplied(249, 115, 22, 20),
            egui::Stroke::new(1.0, THEME.line_brand),
            egui::StrokeKind::Inside,
        )
    } else {
        (THEME.well, egui::Stroke::new(1.0, THEME.line_strong), egui::StrokeKind::Inside)
    };
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(width, 40.0), egui::Sense::click());
    let p = ui.painter_at(rect);
    p.rect_filled(rect, 9.0, fill);
    if filled {
        p.rect_stroke(rect, 9.0, stroke, kind);
    } else {
        // Dashed border for an empty slot.
        dashed_rrect(&p, rect, 9.0, THEME.line_strong);
        let _ = (stroke, kind);
    }
    // Content: "#pos  word".
    let posg = format!("#{pos}");
    p.text(
        rect.left_center() + egui::vec2(10.0, 0.0),
        egui::Align2::LEFT_CENTER,
        posg,
        egui::FontId::new(10.0, egui::FontFamily::Monospace),
        THEME.text4,
    );
    let (label, col) = match word {
        Some(w) => (w.to_string(), THEME.text),
        None => ("tap word".to_string(), THEME.text4),
    };
    p.text(
        rect.center() + egui::vec2(8.0, 0.0),
        egui::Align2::CENTER_CENTER,
        label,
        egui::FontId::new(12.5, if word.is_some() { egui::FontFamily::Monospace } else { egui::FontFamily::Proportional }),
        col,
    );
    if filled {
        resp.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        resp
    }
}

/// A tappable word chip in the confirm pool. `used` greys + strikes it.
fn word_chip(ui: &mut egui::Ui, word: &str, used: bool) -> egui::Response {
    let text = if used {
        widgets::mono(word, 12.0, THEME.text4).strikethrough()
    } else {
        widgets::mono(word, 12.0, THEME.text2)
    };
    let btn = egui::Button::new(text)
        .fill(THEME.surface2)
        .stroke(egui::Stroke::new(1.0, THEME.line))
        .corner_radius(8)
        .min_size(egui::vec2(0.0, 30.0));
    let resp = ui.add_enabled(!used, btn);
    if used {
        resp
    } else {
        resp.on_hover_cursor(egui::CursorIcon::PointingHand)
    }
}

/// Paint a dashed rounded-rect border (egui has no dashed stroke; we step short
/// segments around the perimeter). Used for the empty confirm slot.
fn dashed_rrect(painter: &egui::Painter, rect: egui::Rect, _radius: f32, color: egui::Color32) {
    let stroke = egui::Stroke::new(1.0, color);
    let dash = 5.0;
    let gap = 4.0;
    let seg = |a: egui::Pos2, b: egui::Pos2| {
        let len = (b - a).length();
        let dir = (b - a) / len.max(1e-3);
        let mut t = 0.0;
        while t < len {
            let s = a + dir * t;
            let e = a + dir * (t + dash).min(len);
            painter.line_segment([s, e], stroke);
            t += dash + gap;
        }
    };
    let (l, r, tp, bt) = (rect.left() + 4.0, rect.right() - 4.0, rect.top(), rect.bottom());
    seg(egui::pos2(l, tp), egui::pos2(r, tp));
    seg(egui::pos2(l, bt), egui::pos2(r, bt));
    seg(egui::pos2(rect.left(), tp + 4.0), egui::pos2(rect.left(), bt - 4.0));
    seg(egui::pos2(rect.right(), tp + 4.0), egui::pos2(rect.right(), bt - 4.0));
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
