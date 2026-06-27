//! The **background-mining unlock-password** modal (B4-keyring 3/3).
//!
//! Turning ON background mining for a GPU **pearlhash** lane (`GpuPrl`/`GpuAlpha`)
//! needs the wallet-unlock password: the background service runs the secret-free
//! `--from-service` start, which signs the OOB proof-of-possession from the keystore,
//! so the password is stored in the OS keyring keyed to the address. This modal
//! captures it, then `confirm_bg_enable` VALIDATES it (the same keystore unlock the
//! background start performs), stores it in the keyring, **zeroizes** the GUI-held
//! `String`, and installs the GPU-lane service. CPU-XMR is secret-free and never
//! raises this (it enables straight away).
//!
//! On EITHER close path (confirm or cancel) the owned `String` is zeroized AND the
//! password field's persisted egui `TextEdit` state is cleared
//! (`widgets::clear_text_edit_state`) — egui's `Undoer` otherwise retains a few past
//! snapshots of the buffer (the typed password) until evicted, which the `String`
//! zeroize alone doesn't touch. Both are in-process residue only (no disk/log/argv).
//!
//! Same centred-card-over-dim-scrim pattern as the foreground PRL-unlock modal
//! (`ui/prl_unlock.rs`) and the change-reward-address modal, so the flows feel like
//! one product. The password field is MASKED + given a stable id so its undo state
//! can be wiped (`widgets::password_input_with_id`).

use eframe::egui::{self, RichText};

use super::icons::Icon;
use super::strings;
use super::theme::THEME;
use super::widgets;
use crate::app::MinerApp;

/// The modal card's inner width (points) — matches the sibling unlock cards.
const CARD_W: f32 = 440.0;

/// A STABLE id for the password field so its persisted `TextEdit` state (cursor +
/// undo history) can be wiped on modal close. egui's `Undoer` retains a few past
/// snapshots of the buffer — i.e. the typed password — after the owned `String` is
/// zeroized; clearing this id's state drops that in-process residue immediately.
fn password_field_id(ui: &egui::Ui) -> egui::Id {
    ui.id().with("bg-unlock-password")
}

/// Render the background-mining unlock-password modal. Caller guarantees
/// `app.bg_unlock.is_some()`. Paints a dim scrim (swallowing background clicks),
/// then the centred step card.
pub fn render(ui: &mut egui::Ui, app: &mut MinerApp) {
    if app.bg_unlock.is_none() {
        return;
    }

    // Dim + capture clicks behind the modal (same approach as prl_unlock.rs).
    let scrim = ui.max_rect();
    ui.painter()
        .rect_filled(scrim, 0.0, egui::Color32::from_black_alpha(160));
    let _ = ui.interact(scrim, ui.id().with("bg-unlock-scrim"), egui::Sense::click());

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(22.0);
                widgets::card(ui, CARD_W, |ui| body(ui, app));
                ui.add_space(28.0);
            });
        });
}

fn body(ui: &mut egui::Ui, app: &mut MinerApp) {
    // Header.
    ui.with_layout(egui::Layout::top_down(egui::Align::Center), |ui| {
        widgets::eyebrow(ui, strings::BG_UNLOCK_EYEBROW);
        ui.add_space(10.0);
        ui.label(RichText::new(strings::BG_UNLOCK_TITLE).size(19.0).strong().color(THEME.text));
        ui.add_space(6.0);
        ui.label(RichText::new(strings::BG_UNLOCK_SUB).size(12.5).color(THEME.text3));
    });
    ui.add_space(16.0);

    // The masked password field. Enter submits (same affordance as a click). An
    // EXPLICIT id so its undo history (which mirrors the typed password) can be wiped
    // when the modal closes — see `password_field_id`.
    widgets::field_label(ui, strings::PRL_UNLOCK_FIELD);
    let pw_id = password_field_id(ui);
    let mut submit = false;
    {
        // Borrow the modal state to edit the password buffer in place.
        let unlock = app.bg_unlock.as_mut().expect("caller guarantees Some");
        let resp =
            widgets::password_input_with_id(ui, pw_id, &mut unlock.password, strings::PRL_UNLOCK_HINT);
        if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            submit = true;
        }
    }

    ui.add_space(8.0);
    ui.horizontal_top(|ui| {
        super::icons::show(ui, Icon::Eye, 13.0, THEME.text4);
        ui.add_space(8.0);
        ui.label(RichText::new(strings::BG_UNLOCK_NOTE).size(11.0).color(THEME.text4));
    });

    ui.add_space(16.0);
    let mut cancelled = false;
    ui.horizontal(|ui| {
        if widgets::ghost_button(ui, "Cancel", false).clicked() {
            app.cancel_bg_enable();
            cancelled = true;
            return;
        }
        ui.add_space(8.0);
        // Disable confirm until something is typed (an empty password can't unlock).
        let has_pw = app
            .bg_unlock
            .as_ref()
            .map(|u| !u.password.is_empty())
            .unwrap_or(false);
        if widgets::primary_button(ui, strings::BG_UNLOCK_CONFIRM, has_pw, true).clicked() {
            submit = true;
        }
    });

    let confirmed = submit
        && app
            .bg_unlock
            .as_ref()
            .map(|u| !u.password.is_empty())
            .unwrap_or(false);
    if confirmed {
        app.confirm_bg_enable();
    }

    // On EITHER close path, wipe the password field's persisted egui state so its undo
    // history (which mirrors the typed password) doesn't outlive the zeroized `String`.
    // The owned copy is zeroized in `confirm_bg_enable`/`cancel_bg_enable`; this drops
    // egui's in-process buffer snapshots too (NIT 2). Both are in-process residue only.
    if cancelled || confirmed {
        widgets::clear_text_edit_state(ui.ctx(), pw_id);
    }

    error(ui, app);
}

fn error(ui: &mut egui::Ui, app: &MinerApp) {
    if let Some(err) = &app.bg_service_error {
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
