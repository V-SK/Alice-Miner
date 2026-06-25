//! The GPU-PRL **unlock-password** modal (A2a).
//!
//! The GPU · PRL lane signs a proof-of-possession with the wallet key, so a Start
//! must unlock the on-disk keystore first (`alice-miner-core` `resolve_prl_secrets`
//! → `engine.rs` `prl_in_play`). XMR/RVN are address-only and never raise this.
//!
//! When the user starts mining with PRL as the resolved lane AND the active
//! identity is keystore-backed, `MinerApp::start_mining` opens this modal instead
//! of sending Start; confirm dispatches `Start{GpuPrl, unlock_password: Some(pw)}`
//! and **zeroizes** the GUI-held password immediately (`confirm_prl_start`). A
//! watch-only identity is refused up-front in `start_mining` (no modal — it can't
//! sign a PoP), so this modal only ever sees a signable identity.
//!
//! Rendered with the SAME centred-card-over-dim-scrim pattern as the
//! change-reward-address modal (`ui/change_addr.rs`) so the two flows feel like one
//! product. The password field is MASKED (`widgets::password_input`).

use eframe::egui::{self, RichText};

use super::icons::Icon;
use super::strings;
use super::theme::THEME;
use super::widgets;
use crate::app::MinerApp;

/// The modal card's inner width (points) — matches the change-address / onboarding
/// cards.
const CARD_W: f32 = 440.0;

/// Render the GPU-PRL unlock-password modal. Caller guarantees
/// `app.prl_unlock.is_some()`. Paints a dim scrim (swallowing background clicks),
/// then the centred step card.
pub fn render(ui: &mut egui::Ui, app: &mut MinerApp) {
    if app.prl_unlock.is_none() {
        return;
    }

    // Dim + capture clicks behind the modal (same approach as change_addr.rs:
    // `interact`, not `allocate_rect`, so the scrim consumes no layout space).
    let scrim = ui.max_rect();
    ui.painter()
        .rect_filled(scrim, 0.0, egui::Color32::from_black_alpha(160));
    let _ = ui.interact(scrim, ui.id().with("prl-unlock-scrim"), egui::Sense::click());

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
        widgets::eyebrow(ui, strings::PRL_UNLOCK_EYEBROW);
        ui.add_space(10.0);
        ui.label(RichText::new(strings::PRL_UNLOCK_TITLE).size(19.0).strong().color(THEME.text));
        ui.add_space(6.0);
        ui.label(RichText::new(strings::PRL_UNLOCK_SUB).size(12.5).color(THEME.text3));
    });
    ui.add_space(16.0);

    // The masked password field. Enter submits (same affordance as a click).
    widgets::field_label(ui, strings::PRL_UNLOCK_FIELD);
    let mut submit = false;
    {
        // Borrow the modal state to edit the password buffer in place.
        let unlock = app.prl_unlock.as_mut().expect("caller guarantees Some");
        let resp = widgets::password_input(ui, &mut unlock.password, strings::PRL_UNLOCK_HINT);
        if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            submit = true;
        }
    }

    ui.add_space(8.0);
    ui.horizontal_top(|ui| {
        super::icons::show(ui, Icon::Eye, 13.0, THEME.text4);
        ui.add_space(8.0);
        ui.label(RichText::new(strings::PRL_UNLOCK_NOTE).size(11.0).color(THEME.text4));
    });

    ui.add_space(16.0);
    ui.horizontal(|ui| {
        if widgets::ghost_button(ui, "Cancel", false).clicked() {
            app.cancel_prl_start();
            return;
        }
        ui.add_space(8.0);
        // Disable confirm until something is typed (an empty password can't unlock).
        let has_pw = app
            .prl_unlock
            .as_ref()
            .map(|u| !u.password.is_empty())
            .unwrap_or(false);
        if widgets::primary_button(ui, strings::PRL_UNLOCK_CONFIRM, has_pw, true).clicked() {
            submit = true;
        }
    });

    if submit
        && app
            .prl_unlock
            .as_ref()
            .map(|u| !u.password.is_empty())
            .unwrap_or(false)
    {
        app.confirm_prl_start();
    }

    error(ui, app);
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
