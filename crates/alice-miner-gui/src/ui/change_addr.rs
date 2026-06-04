//! The post-onboarding **"change reward address"** modal — lets the user point
//! mining at a DIFFERENT Alice address after first-run setup (the missing core
//! feature: the reward address used to be set-once during onboarding).
//!
//! It is reachable from two places once an identity exists:
//!   * **Settings → Identity → "Change reward address"**, and
//!   * the **Home "Rewards to <addr>" edit affordance** (the pencil).
//!
//! It offers the SAME three paths onboarding uses and drives the EXACT same
//! `alice-miner-core` identity functions (no duplicated crypto):
//!   * **Create new** → an explicit overwrite-confirm (the existing keystore is
//!     backed up first via `alice_crypto::backup_existing_wallet`, surfaced as a
//!     `.bak-…` path) → generate → forced 24-word backup → retype-confirm.
//!   * **Import** → mnemonic / seed-hex, with the same overwrite-confirm warning.
//!   * **Paste** → a different address, WATCH-ONLY: it repoints `identity.json`
//!     and PRESERVES the existing keystore (paste never unlocks/destroys a key).
//!
//! Two safety rails enforced here + in `app.rs`:
//!   * it only opens / applies when **NOT mining** (the engine's reward target is
//!     never re-keyed under a live lane — `MinerApp::change_blocked_by_mining`), and
//!   * a confirmation step precedes any keystore OVERWRITE (create / import).
//!
//! Rendered as a centred modal card over a dimmed backdrop (NOT the full-screen
//! onboarding takeover), so the user keeps their place in Home/Settings. The
//! backup-step + confirm-step bodies are SHARED with onboarding (see
//! `onboarding::backup_body` / `onboarding::confirm_body`).

use eframe::egui::{self, RichText};

use super::icons::Icon;
use super::onboarding::{self, ConfirmAction};
use super::strings;
use super::theme::THEME;
use super::widgets;
use crate::app::{ChangeAddr, MinerApp};

/// The modal card's inner width (points) — matches the onboarding card so the two
/// flows feel like one product.
const CARD_W: f32 = 440.0;

/// Render the change-address modal over the current screen. Caller guarantees
/// `app.change_addr.is_some()`. Paints a dim scrim first (and swallows clicks
/// behind the card), then the centred step card.
pub fn render(ui: &mut egui::Ui, app: &mut MinerApp) {
    let step = match app.change_addr.clone() {
        Some(s) => s,
        None => return,
    };

    // Dim the content area behind the modal + capture background clicks so the
    // screen underneath stays inert while the modal is up. We scrim the panel
    // rect (the area this modal Ui owns) rather than the whole window, so the
    // titlebar + nav rail stay readable. `interact` (NOT `allocate_rect`) so the
    // scrim paints + swallows clicks WITHOUT consuming layout space (otherwise it
    // pushes the card to the bottom of the panel).
    let scrim = ui.max_rect();
    ui.painter()
        .rect_filled(scrim, 0.0, egui::Color32::from_black_alpha(160));
    let _ = ui.interact(scrim, ui.id().with("change-scrim"), egui::Sense::click());

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(22.0);
                widgets::card(ui, CARD_W, |ui| match step {
                    ChangeAddr::Choose => choose(ui, app),
                    ChangeAddr::ConfirmCreate { backup_hint } => {
                        overwrite_confirm(ui, app, &backup_hint)
                    }
                    ChangeAddr::CreateForm => create_form(ui, app),
                    ChangeAddr::Backup { mnemonic, acknowledged } => {
                        backup(ui, app, &mnemonic, acknowledged)
                    }
                    ChangeAddr::Confirm { mnemonic } => confirm(ui, app, &mnemonic),
                    ChangeAddr::Import { backup_hint } => import(ui, app, &backup_hint),
                    ChangeAddr::Paste => paste(ui, app),
                });
                ui.add_space(28.0);
            });
        });
}

// ── Steps ─────────────────────────────────────────────────────────────────────

/// The launcher: the current address (+ keystore-backed/watch-only tag) and the
/// three change paths. Create/Import route THROUGH an overwrite-confirm; Paste
/// goes straight to the watch-only entry (it never overwrites a keystore).
fn choose(ui: &mut egui::Ui, app: &mut MinerApp) {
    modal_header(
        ui,
        strings::CHANGE_ADDR_EYEBROW,
        strings::CHANGE_ADDR_TITLE,
        strings::CHANGE_ADDR_SUB,
    );

    // Current address card (read-only, with copy + the keystore/watch-only tag).
    current_address_panel(ui, app);
    ui.add_space(16.0);

    // Create → overwrite-confirm (compute the backup hint NOW so the warning can
    // name the `.bak-…` destination before anything is touched).
    if onboarding::variant_button(
        ui,
        Icon::Plus,
        strings::CHANGE_ADDR_CREATE_TITLE,
        "new",
    )
    .clicked()
    {
        app.error = None;
        app.change_addr = Some(ChangeAddr::ConfirmCreate {
            backup_hint: app.keystore_backup_hint(),
        });
    }
    ui.add_space(8.0);
    if onboarding::variant_button(
        ui,
        Icon::Import,
        strings::CHANGE_ADDR_IMPORT_TITLE,
        "mnemonic / seed",
    )
    .clicked()
    {
        app.error = None;
        app.change_addr = Some(ChangeAddr::Import {
            backup_hint: app.keystore_backup_hint(),
        });
    }
    ui.add_space(8.0);
    if onboarding::variant_button(
        ui,
        Icon::Eye,
        strings::CHANGE_ADDR_PASTE_TITLE,
        "watch-only",
    )
    .clicked()
    {
        app.error = None;
        app.change_addr = Some(ChangeAddr::Paste);
    }

    // A live "stop mining first" note if the user somehow got here while mining
    // (defensive — the affordances that open this are already gated).
    if app.is_mining() {
        ui.add_space(12.0);
        warn_banner(ui, strings::CHANGE_ADDR_MINING_BLOCK);
    }

    ui.add_space(14.0);
    if widgets::ghost_button(ui, "Cancel", true).clicked() {
        app.close_change_addr();
    }
    error(ui, app);
}

/// The overwrite-confirm gate before Create: a clear warning that this REPLACES
/// the current reward identity, naming the `.bak-…` path the existing keystore is
/// moved to first (or that nothing is overwritten when there's no prior
/// keystore). "Continue" advances to the create password form.
fn overwrite_confirm(ui: &mut egui::Ui, app: &mut MinerApp, backup_hint: &Option<String>) {
    modal_header(
        ui,
        strings::CHANGE_ADDR_EYEBROW,
        strings::CHANGE_ADDR_OVERWRITE_TITLE,
        "",
    );

    // The warning body — amber, with the backup destination spelled out.
    egui::Frame::NONE
        .fill(egui::Color32::from_rgba_unmultiplied(245, 158, 11, 26))
        .corner_radius(10)
        .inner_margin(egui::Margin::symmetric(13, 12))
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(245, 158, 11, 72)))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                super::icons::show(ui, Icon::Alert, 16.0, THEME.warn);
                ui.add_space(10.0);
                let body = match backup_hint {
                    Some(_) => strings::CHANGE_ADDR_OVERWRITE_BODY,
                    None => strings::CHANGE_ADDR_OVERWRITE_NOPRIOR,
                };
                ui.label(
                    RichText::new(body)
                        .size(12.0)
                        .color(egui::Color32::from_rgb(0xFC, 0xD9, 0xA0)),
                );
            });
        });

    // The exact backup destination (mono, wrapped) when there's a keystore.
    if let Some(path) = backup_hint {
        ui.add_space(10.0);
        backup_dest_panel(ui, path);
    }

    ui.add_space(16.0);
    ui.horizontal(|ui| {
        if widgets::ghost_button(ui, "Back", false).clicked() {
            app.change_addr = Some(ChangeAddr::Choose);
            app.error = None;
        }
        ui.add_space(8.0);
        if widgets::primary_button(ui, "Continue · generate new", true, true).clicked() {
            app.error = None;
            app.change_addr = Some(ChangeAddr::CreateForm);
        }
    });
    error(ui, app);
}

/// The create password form (after the overwrite warning is accepted). On submit
/// the engine generates → backs up the old keystore → writes the new one and
/// emits the mnemonic, which advances us into the shared forced-backup step.
fn create_form(ui: &mut egui::Ui, app: &mut MinerApp) {
    modal_header(
        ui,
        strings::CHANGE_ADDR_EYEBROW,
        strings::CHANGE_ADDR_CREATE_TITLE,
        strings::CHANGE_ADDR_CREATE_SUB,
    );
    widgets::field_label(ui, "Password (encrypts the new keystore)");
    widgets::text_input(ui, &mut app.form_password, "at least 8 characters", false);
    ui.add_space(8.0);
    widgets::field_label(ui, "Confirm password");
    widgets::text_input(ui, &mut app.form_password2, "re-enter password", false);

    ui.add_space(14.0);
    ui.horizontal(|ui| {
        if widgets::ghost_button(ui, "Back", false).clicked() {
            app.change_addr = Some(ChangeAddr::ConfirmCreate {
                backup_hint: app.keystore_backup_hint(),
            });
            app.error = None;
        }
        ui.add_space(8.0);
        if widgets::primary_button(ui, "Generate new identity", true, true).clicked() {
            app.submit_create();
        }
    });
    error(ui, app);
}

/// The forced-backup step (after a create commits): the SHARED 24-word backup
/// body, persisting the ack into the change-flow enum.
fn backup(ui: &mut egui::Ui, app: &mut MinerApp, mnemonic: &str, acknowledged: bool) {
    modal_header(ui, strings::CHANGE_ADDR_EYEBROW, "Back up the new phrase", "");
    let out = onboarding::backup_body(ui, app, mnemonic, acknowledged);
    if out.acknowledged != acknowledged {
        app.change_addr = Some(ChangeAddr::Backup {
            mnemonic: mnemonic.to_string(),
            acknowledged: out.acknowledged,
        });
    }
    if out.continue_clicked {
        app.begin_confirm(mnemonic);
    }
}

/// The retype-confirm step: the SHARED confirm body; finishing CLOSES the modal
/// (the new address is already live via `self.identity`).
fn confirm(ui: &mut egui::Ui, app: &mut MinerApp, mnemonic: &str) {
    modal_header(ui, strings::CHANGE_ADDR_EYEBROW, strings::OB_CONFIRM_TITLE, "");
    match onboarding::confirm_body(ui, app, mnemonic) {
        ConfirmAction::Back => {
            app.change_addr = Some(ChangeAddr::Backup {
                mnemonic: mnemonic.to_string(),
                acknowledged: true,
            });
            app.error = None;
        }
        ConfirmAction::Finish => app.finish_change_addr(),
        ConfirmAction::None => {}
    }
}

/// Import a DIFFERENT mnemonic / seed. The overwrite warning is recapped inline
/// (Import also replaces + backs up the keystore). Reuses the onboarding fields.
fn import(ui: &mut egui::Ui, app: &mut MinerApp, backup_hint: &Option<String>) {
    modal_header(
        ui,
        strings::CHANGE_ADDR_EYEBROW,
        strings::CHANGE_ADDR_IMPORT_TITLE,
        strings::CHANGE_ADDR_IMPORT_SUB,
    );

    // Recap the overwrite + backup destination compactly.
    overwrite_recap(ui, backup_hint);
    ui.add_space(12.0);

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
    widgets::field_label(ui, "Password (encrypts the new keystore)");
    widgets::text_input(ui, &mut app.form_password, "at least 8 characters", false);

    ui.add_space(14.0);
    ui.horizontal(|ui| {
        if widgets::ghost_button(ui, "Back", false).clicked() {
            app.change_addr = Some(ChangeAddr::Choose);
            app.error = None;
        }
        ui.add_space(8.0);
        if widgets::primary_button(ui, "Replace & import", true, true).clicked() {
            // The engine backs up the existing keystore before writing the new one.
            app.submit_import();
        }
    });
    error(ui, app);
}

/// Paste a DIFFERENT address (watch-only). PRESERVES the existing keystore — this
/// only repoints `identity.json`. A caution makes clear mining will credit the
/// pasted address (which the user may not hold the key for).
fn paste(ui: &mut egui::Ui, app: &mut MinerApp) {
    modal_header(
        ui,
        strings::CHANGE_ADDR_EYEBROW,
        strings::CHANGE_ADDR_PASTE_TITLE,
        strings::CHANGE_ADDR_PASTE_SUB,
    );

    // Caution banner — watch-only, you may not hold the key + your existing
    // keystore is left untouched.
    egui::Frame::NONE
        .fill(THEME.well)
        .corner_radius(10)
        .inner_margin(egui::Margin::symmetric(13, 11))
        .stroke(egui::Stroke::new(1.0, THEME.line_strong))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                super::icons::show(ui, Icon::Eye, 15.0, THEME.text3);
                ui.add_space(10.0);
                ui.label(RichText::new(strings::CHANGE_ADDR_PASTE_CAUTION).size(11.5).color(THEME.text2));
            });
        });
    ui.add_space(14.0);

    widgets::field_label(ui, "Alice address (SS58-300)");
    widgets::text_input(ui, &mut app.form_address, "a2x9…", true);

    ui.add_space(14.0);
    ui.horizontal(|ui| {
        if widgets::ghost_button(ui, "Back", false).clicked() {
            app.change_addr = Some(ChangeAddr::Choose);
            app.error = None;
        }
        ui.add_space(8.0);
        if widgets::primary_button(ui, "Use this address", true, true).clicked() {
            app.submit_paste();
        }
    });
    error(ui, app);
}

// ── small pieces ────────────────────────────────────────────────────────────

/// The current-address read-only panel at the top of the launcher: the shortened
/// address, a copy affordance, and the keystore-backed / watch-only tag.
fn current_address_panel(ui: &mut egui::Ui, app: &mut MinerApp) {
    let addr = app.reward_address();
    let watch_only = app.reward_is_watch_only();
    egui::Frame::NONE
        .fill(THEME.well)
        .corner_radius(11)
        .inner_margin(egui::Margin::symmetric(13, 11))
        .stroke(egui::Stroke::new(1.0, THEME.line))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
                RichText::new(strings::CHANGE_ADDR_CURRENT.to_uppercase())
                    .size(9.5)
                    .extra_letter_spacing(1.2)
                    .strong()
                    .color(THEME.text4),
            );
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                match &addr {
                    Some(a) => {
                        ui.label(widgets::mono(widgets::shorten(a), 13.0, THEME.text));
                        ui.add_space(6.0);
                        if super::icons::show(ui, Icon::Copy, 13.0, THEME.text4)
                            .interact(egui::Sense::click())
                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                            .on_hover_text("Click to copy")
                            .clicked()
                        {
                            ui.ctx().copy_text(a.clone());
                            app.copied_at = Some(std::time::Instant::now());
                        }
                    }
                    None => {
                        ui.label(RichText::new("none").size(13.0).color(THEME.text4));
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    identity_tag(ui, watch_only);
                });
            });
        });
}

/// The keystore-backed / watch-only tag chip.
pub(crate) fn identity_tag(ui: &mut egui::Ui, watch_only: bool) {
    let (label, fg) = if watch_only {
        (strings::IDENTITY_WATCH_ONLY, THEME.text3)
    } else {
        (strings::IDENTITY_KEYSTORE_BACKED, THEME.live)
    };
    egui::Frame::NONE
        .fill(egui::Color32::from_rgba_unmultiplied(fg.r(), fg.g(), fg.b(), 20))
        .corner_radius(255)
        .inner_margin(egui::Margin::symmetric(9, 3))
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(fg.r(), fg.g(), fg.b(), 70)))
        .show(ui, |ui| {
            ui.label(RichText::new(label).size(10.0).strong().color(fg));
        });
}

/// The "backed up to <path>" destination box (mono, wrapped).
fn backup_dest_panel(ui: &mut egui::Ui, path: &str) {
    ui.label(RichText::new(strings::CHANGE_ADDR_BACKUP_TO).size(11.0).color(THEME.text3));
    ui.add_space(3.0);
    egui::Frame::NONE
        .fill(THEME.well)
        .corner_radius(8)
        .inner_margin(egui::Margin::symmetric(11, 8))
        .stroke(egui::Stroke::new(1.0, THEME.line))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
            ui.label(widgets::mono(path.to_string(), 11.0, THEME.text2));
        });
}

/// A compact recap of the overwrite + backup destination (used on the Import
/// form so the warning is never out of sight).
fn overwrite_recap(ui: &mut egui::Ui, backup_hint: &Option<String>) {
    egui::Frame::NONE
        .fill(egui::Color32::from_rgba_unmultiplied(245, 158, 11, 20))
        .corner_radius(9)
        .inner_margin(egui::Margin::symmetric(11, 9))
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(245, 158, 11, 60)))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                super::icons::show(ui, Icon::Alert, 14.0, THEME.warn);
                ui.add_space(9.0);
                let body = match backup_hint {
                    Some(_) => strings::CHANGE_ADDR_OVERWRITE_BODY,
                    None => strings::CHANGE_ADDR_OVERWRITE_NOPRIOR,
                };
                ui.label(RichText::new(body).size(11.0).color(egui::Color32::from_rgb(0xFC, 0xD9, 0xA0)));
            });
        });
}

fn warn_banner(ui: &mut egui::Ui, text: &str) {
    egui::Frame::NONE
        .fill(egui::Color32::from_rgba_unmultiplied(245, 158, 11, 24))
        .corner_radius(9)
        .inner_margin(egui::Margin::symmetric(12, 10))
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(245, 158, 11, 64)))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                super::icons::show(ui, Icon::Alert, 14.0, THEME.warn);
                ui.add_space(9.0);
                ui.label(RichText::new(text).size(11.5).color(egui::Color32::from_rgb(0xFC, 0xD9, 0xA0)));
            });
        });
}

fn modal_header(ui: &mut egui::Ui, eyebrow: &str, title: &str, sub: &str) {
    ui.with_layout(egui::Layout::top_down(egui::Align::Center), |ui| {
        widgets::eyebrow(ui, eyebrow);
        ui.add_space(10.0);
        ui.label(RichText::new(title).size(19.0).strong().color(THEME.text));
        if !sub.is_empty() {
            ui.add_space(6.0);
            ui.label(RichText::new(sub).size(12.5).color(THEME.text3));
        }
    });
    ui.add_space(16.0);
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
