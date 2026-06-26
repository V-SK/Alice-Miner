//! Window chrome: the custom dark titlebar (with a global mining-status pill +
//! lang chip, macOS traffic-light clearance) and the left icon rail
//! (Home / Dashboard / Settings), then routing into the active screen.
//!
//! Frameless-window approach ported from `alice-wallet/gui/src/ui/shell.rs`
//! (~L44 macOS top clearance, ~L163 the left rail). On macOS the OS draws our
//! header UNDER the traffic lights (fullsize-content view), so the titlebar gets
//! a taller top inset; other OSes keep a normal bar.

use eframe::egui::{self, Color32, CornerRadius, RichText, Stroke};

use super::icons::{self, Icon};
use super::theme::THEME;
use super::widgets::{self, Tone};
use crate::app::{MinerApp, Screen};
use alice_miner_core::{EngineState, Lane};

/// Render the whole window: titlebar + rail + content.
pub fn render(ui_root: &mut egui::Ui, app: &mut MinerApp) {
    let ctx = ui_root.ctx().clone();
    // Ensure the mark texture is loaded (used by the hero + brand marks).
    let _ = app.mark_texture(&ctx);

    titlebar(ui_root, app);
    rail(ui_root, app);

    egui::CentralPanel::default()
        .frame(egui::Frame::NONE.fill(THEME.bg))
        .show_inside(ui_root, |ui| {
            let rect = ui.max_rect();
            super::theme::paint_backdrop(&ui.painter_at(rect), rect);

            // Onboarding takes over the whole content area until an identity
            // exists; otherwise route to the selected screen.
            if app.onboarding.is_some() {
                super::onboarding::render(ui, app);
            } else {
                match app.screen {
                    Screen::Home => super::home::render(ui, app),
                    Screen::Dashboard => super::dashboard::render(ui, app),
                    Screen::Settings => super::dashboard::render_settings(ui, app),
                }
                // The "change reward address" modal overlays the current screen
                // (dim scrim + centred card) once an identity exists. Drawn in a
                // foreground Area covering the content panel so it sits above the
                // screen content + intercepts interaction behind the card. The
                // Area is given the panel rect as BOTH its position and its
                // layout size so the centred card lands correctly.
                if app.change_addr.is_some() {
                    let panel = ui.max_rect();
                    egui::Area::new(egui::Id::new("change-addr-modal"))
                        .order(egui::Order::Foreground)
                        .fixed_pos(panel.min)
                        .default_size(panel.size())
                        .show(ui.ctx(), |ui| {
                            ui.set_min_size(panel.size());
                            ui.set_max_size(panel.size());
                            super::change_addr::render(ui, app);
                        });
                }

                // The GPU-PRL unlock-password modal — same overlay treatment.
                // Opened by `start_mining` when the resolved lane is GPU-PRL and the
                // identity is keystore-backed (PoP needs the wallet key).
                if app.prl_unlock.is_some() {
                    let panel = ui.max_rect();
                    egui::Area::new(egui::Id::new("prl-unlock-modal"))
                        .order(egui::Order::Foreground)
                        .fixed_pos(panel.min)
                        .default_size(panel.size())
                        .show(ui.ctx(), |ui| {
                            ui.set_min_size(panel.size());
                            ui.set_max_size(panel.size());
                            super::prl_unlock::render(ui, app);
                        });
                }
            }
        });
}

/// The titlebar: traffic-light clearance, brand mark + name, drag region, a
/// global mining-status pill, and a language chip.
fn titlebar(ui_root: &mut egui::Ui, app: &mut MinerApp) {
    #[cfg(target_os = "macos")]
    let (h, margin) = (
        72.0_f32,
        egui::Margin { left: 84, right: 16, top: 22, bottom: 10 },
    );
    #[cfg(not(target_os = "macos"))]
    let (h, margin) = (54.0_f32, egui::Margin::symmetric(16, 10));

    egui::Panel::top("titlebar")
        .exact_size(h)
        .frame(
            egui::Frame::NONE
                .fill(THEME.titlebar_top)
                .inner_margin(margin)
                .stroke(Stroke::new(1.0, THEME.line)),
        )
        .show_inside(ui_root, |ui| {
            // The whole bar (minus the interactive widgets) is a window-drag
            // region — sense drags on the background.
            let bar_rect = ui.max_rect();
            let drag = ui.interact(bar_rect, ui.id().with("drag"), egui::Sense::click_and_drag());
            if drag.drag_started() || drag.is_pointer_button_down_on() {
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::StartDrag);
            }

            ui.horizontal_centered(|ui| {
                ui.spacing_mut().item_spacing.x = 9.0;
                // Brand mark (the Alice logo, glowing faintly).
                if let Some(tex) = &app.mark_tex {
                    let (r, _) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::hover());
                    super::theme::radial_glow(ui.painter(), r.center(), 14.0, THEME.brand, 40);
                    ui.painter().image(
                        tex.id(),
                        r,
                        egui::Rect::from_min_max(egui::Pos2::ZERO, egui::pos2(1.0, 1.0)),
                        THEME.brand,
                    );
                }
                ui.label(RichText::new("Alice Miner").size(13.0).strong().color(THEME.text));

                // Right-aligned: lang chip, then the global status pill.
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let lang = if app.lang_zh { "中" } else { "EN" };
                    if lang_chip(ui, lang).clicked() {
                        app.lang_zh = !app.lang_zh;
                    }
                    ui.add_space(8.0);
                    let (tone, label, blink) = status_for(app);
                    widgets::status_pill(ui, tone, &label, blink && app.motion_enabled());
                });
            });
        });
}

/// Map the engine state to the titlebar pill (tone, label, blink).
fn status_for(app: &MinerApp) -> (Tone, String, bool) {
    match app.state() {
        EngineState::Running => {
            // Reflect the ACTUAL active lane (was hardcoded "XMR" — wrong for the
            // GPU-PRL mainline and for dual-mine).
            let dual = app.snapshot.as_ref().map(|s| s.dual).unwrap_or(false);
            let lane = pill_lane_label(app.active_lane(), dual);
            (Tone::Live, format!("Mining · {lane}"), true)
        }
        EngineState::Starting => (Tone::Warn, "Connecting".into(), true),
        EngineState::Stopping => (Tone::Warn, "Stopping".into(), true),
        EngineState::Error => (Tone::Danger, "Error".into(), false),
        EngineState::Idle => (Tone::Off, "Idle".into(), false),
    }
}

/// The short lane tag for the titlebar mining pill. Dual-mine reads "Dual"; a
/// single lane reads its short tag (XMR / PRL / RVN).
fn pill_lane_label(lane: Lane, dual: bool) -> &'static str {
    if dual {
        return "Dual";
    }
    match lane {
        Lane::Xmr => "XMR",
        Lane::GpuPrl => "PRL",
        Lane::GpuAlpha => "Alpha",
        Lane::GpuRvn => "RVN",
    }
}

fn lang_chip(ui: &mut egui::Ui, label: &str) -> egui::Response {
    let btn = egui::Button::new(RichText::new(label).size(11.0).strong().color(THEME.text3))
        .fill(Color32::TRANSPARENT)
        .stroke(Stroke::new(1.0, THEME.line))
        .corner_radius(8)
        .min_size(egui::vec2(34.0, 26.0));
    ui.add(btn)
}

/// The left icon rail: brand mark on top, Home / Dashboard / Settings nav, the
/// version at the bottom. Active item gets the brand-tinted pill + left bar.
fn rail(ui_root: &mut egui::Ui, app: &mut MinerApp) {
    egui::Panel::left("rail")
        .exact_size(68.0)
        .resizable(false)
        .frame(
            egui::Frame::NONE
                .fill(THEME.rail_top)
                .inner_margin(egui::Margin { left: 0, right: 0, top: 16, bottom: 14 })
                .stroke(Stroke::new(1.0, THEME.line)),
        )
        .show_inside(ui_root, |ui| {
            ui.vertical_centered(|ui| {
                ui.spacing_mut().item_spacing.y = 7.0;
                // Brand mark.
                if let Some(tex) = &app.mark_tex {
                    let (r, _) = ui.allocate_exact_size(egui::vec2(26.0, 26.0), egui::Sense::hover());
                    super::theme::radial_glow(ui.painter(), r.center(), 18.0, THEME.brand, 50);
                    ui.painter().image(
                        tex.id(),
                        r,
                        egui::Rect::from_min_max(egui::Pos2::ZERO, egui::pos2(1.0, 1.0)),
                        THEME.brand,
                    );
                }
                ui.add_space(12.0);

                // Nav items are disabled during onboarding (no identity yet).
                let enabled = app.onboarding.is_none();
                if nav_item(ui, Icon::Home, app.screen == Screen::Home && enabled, enabled).clicked() {
                    app.screen = Screen::Home;
                }
                if nav_item(ui, Icon::Grid, app.screen == Screen::Dashboard && enabled, enabled).clicked() {
                    app.screen = Screen::Dashboard;
                }
                let gear = nav_item(ui, Icon::Gear, app.screen == Screen::Settings && enabled, enabled);
                // Update badge: a brand dot on the gear when the launch-time check
                // surfaced something actionable (an offer / manual-download / forced
                // upgrade / applied-pending-restart), so the user notices without
                // opening Settings — the v0.3.1 "didn't know it could update" fix.
                if enabled && app.updater.ui.wants_attention() {
                    let c = gear.rect.right_top() + egui::vec2(-8.0, 8.0);
                    let p = ui.painter();
                    p.circle_filled(c, 4.5, THEME.brand);
                    p.circle_stroke(c, 4.5, Stroke::new(1.5, THEME.rail_top));
                }
                if gear.clicked() {
                    app.screen = Screen::Settings;
                }

                ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
                    ui.label(
                        widgets::mono(format!("v{}", env!("CARGO_PKG_VERSION")), 9.0, THEME.text4),
                    );
                });
            });
        });
}

/// One rail nav button: a 42×42 rounded slot with a monoline icon; active state
/// gets a brand-tinted fill, a brand icon, and a glowing left accent bar.
fn nav_item(ui: &mut egui::Ui, icon: Icon, active: bool, enabled: bool) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(42.0, 42.0), egui::Sense::click());
    let hovered = resp.hovered() && enabled;
    let painter = ui.painter();

    if active {
        painter.rect_filled(rect, CornerRadius::same(12), Color32::from_rgba_unmultiplied(249, 115, 22, 30));
        painter.rect_stroke(
            rect,
            CornerRadius::same(12),
            Stroke::new(1.0, Color32::from_rgba_unmultiplied(249, 115, 22, 60)),
            egui::epaint::StrokeKind::Inside,
        );
        // Glowing left accent bar.
        let bar = egui::Rect::from_min_max(
            egui::pos2(rect.left() - 16.0, rect.top() + 10.0),
            egui::pos2(rect.left() - 13.0, rect.bottom() - 10.0),
        );
        painter.rect_filled(bar, 3.0, THEME.brand);
    } else if hovered {
        painter.rect_filled(rect, CornerRadius::same(12), THEME.surface2);
    }

    let color = if active {
        THEME.brand300
    } else if hovered {
        THEME.text2
    } else if enabled {
        THEME.text3
    } else {
        THEME.text4
    };
    icons::draw(ui.painter(), icon, rect, color, 1.6);
    if enabled {
        resp.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pill_lane_label_reflects_active_lane_not_hardcoded_xmr() {
        // Single-lane: the tag is the active lane (regression: was always "XMR").
        assert_eq!(pill_lane_label(Lane::Xmr, false), "XMR");
        assert_eq!(pill_lane_label(Lane::GpuPrl, false), "PRL");
        assert_eq!(pill_lane_label(Lane::GpuRvn, false), "RVN");
        // Dual-mine reads "Dual" regardless of the primary lane.
        assert_eq!(pill_lane_label(Lane::Xmr, true), "Dual");
        assert_eq!(pill_lane_label(Lane::GpuPrl, true), "Dual");
    }
}
