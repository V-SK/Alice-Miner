//! Dashboard (mockup `03`) — live cards from the credit-only [`Snapshot`]:
//! hashrate, shares A/R, accepted %, est. rewards = **pending** (never a number
//! or `$`), the lane row, the connection (PUBLIC relay endpoint + derived
//! worker), and a small log tail. Honest by construction (rewards come only from
//! [`crate::ui::strings`]). Plus a minimal Settings view.

use eframe::egui::{self, RichText};

use super::icons::Icon;
use super::strings;
use super::theme::THEME;
use super::widgets::{self, Tone};
use crate::app::MinerApp;

pub fn render(ui: &mut egui::Ui, app: &mut MinerApp) {
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.add_space(22.0);
            ui.allocate_ui_with_layout(
                egui::vec2(ui.available_width(), ui.available_height()),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.set_max_width(1000.0);
                    ui.add_space(0.0);
                    let pad = ((ui.available_width() - 1000.0_f32.min(ui.available_width())) * 0.0).max(0.0);
                    ui.add_space(pad);
                    dashboard_inner(ui, app);
                    ui.add_space(28.0);
                },
            );
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
            let sub = app
                .device
                .as_ref()
                .map(|d| format!("{} · XMR · RandomX", d.display))
                .unwrap_or_else(|| "XMR · RandomX".into());
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
        });
    });

    ui.add_space(16.0);
    ui.painter().hline(
        ui.available_rect_before_wrap().x_range(),
        ui.cursor().top(),
        egui::Stroke::new(1.0, THEME.line),
    );
    ui.add_space(18.0);

    // ── Stat grid (4 cards) ───────────────────────────────────────────────────
    let total_w = ui.available_width();
    let gap = 13.0;
    let card_w = ((total_w - gap * 3.0) / 4.0).max(120.0);
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = gap;

        // Hashrate (accent, with sparkline).
        let hr_val = if mining {
            widgets::mono(format!("{:.2}", app.hr_display_khs), 25.0, THEME.text).strong()
        } else {
            widgets::mono("—", 25.0, THEME.text3)
        };
        let spark: Vec<f32> = app.spark.iter().cloned().collect();
        let spark_ref = &spark;
        widgets::stat_card(
            ui,
            card_w,
            "Hashrate",
            hr_val,
            None,
            Some(THEME.lane_xmr),
            Some(&move |ui: &mut egui::Ui| {
                if spark_ref.is_empty() {
                    ui.label(RichText::new("kH/s").size(11.0).color(THEME.text3));
                } else {
                    widgets::sparkline(ui, spark_ref, ui.available_width().min(card_w - 4.0), 26.0);
                }
            }),
        );

        // Shares A / R.
        let shares_val = widgets::mono(format!("{a}"), 25.0, THEME.text).strong();
        widgets::stat_card(
            ui,
            card_w,
            "Shares A / R",
            shares_val,
            Some(widgets::mono(format!("/ {r} rejected"), 11.5, THEME.text3)),
            None,
            None,
        );

        // Accepted %.
        let pct = if a + r > 0 {
            format!("{:.1}", a as f64 / (a + r) as f64 * 100.0)
        } else {
            "—".to_string()
        };
        widgets::stat_card(
            ui,
            card_w,
            "Accepted",
            widgets::mono(format!("{pct}%"), 25.0, THEME.text).strong(),
            Some(RichText::new(if a + r > 0 { "rolling · healthy" } else { "no shares yet" }).size(11.0).color(if a + r > 0 { THEME.live } else { THEME.text3 })),
            None,
            None,
        );

        // Est. rewards — PENDING ONLY (never a number / $).
        widgets::stat_card(
            ui,
            card_w,
            "Est. rewards",
            RichText::new(strings::REWARD_PENDING_SHORT).size(20.0).strong().color(THEME.brand300),
            Some(RichText::new(strings::REWARD_RATE_PENDING).size(11.0).color(THEME.text3)),
            None,
            None,
        );
    });

    // ── Lanes ─────────────────────────────────────────────────────────────────
    ui.add_space(22.0);
    widgets::section_label(ui, "Lanes");
    ui.add_space(10.0);
    lane_row(
        ui,
        THEME.lane_xmr,
        "XMR · RandomX",
        &format!("· CPU · {} threads", app.device.as_ref().map(|d| d.logical_cores).unwrap_or(0)),
        if mining { Some(app.hr_display_khs) } else { None },
        (a, r),
        mining,
    );
    lane_row(ui, THEME.lane_gpu, "RVN · KawPoW", "· GPU · idle (M3)", None, (0, 0), false);

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
                    let hr = hr_khs.map(|h| format!("{h:.2} kH/s")).unwrap_or_else(|| "—".into());
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
    let endpoint = snap
        .as_ref()
        .and_then(|s| s.endpoint.clone())
        .unwrap_or_else(|| "hk.aliceprotocol.org:3333".into());
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
                srow(ui, "Lane", "Auto picks the best lane for your device. XMR uses the CPU (RandomX).", |ui| {
                    widgets::chip(ui, Some(THEME.lane_xmr), "XMR · RandomX");
                });
            });

            // Network panel.
            panel(ui, "Network", Icon::Globe, |ui| {
                srow(ui, "Endpoint", "Primary relay. The client handles failover automatically.", |ui| {
                    let ep = app
                        .snapshot
                        .as_ref()
                        .and_then(|s| s.endpoint.clone())
                        .unwrap_or_else(|| "hk.aliceprotocol.org:3333".into());
                    ui.horizontal(|ui| {
                        ui.label(widgets::mono(ep, 12.5, THEME.text2));
                        ui.label(RichText::new("read-only").size(10.0).extra_letter_spacing(0.8).color(THEME.text4));
                    });
                });
            });

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

            // Identity panel.
            panel(ui, "Identity", Icon::Eye, |ui| {
                srow(ui, "Reward address", "Your own Alice address. Rewards accrue to it as pending.", |ui| {
                    if let Some(addr) = app.reward_address() {
                        let copy = egui::Button::new(widgets::mono(widgets::shorten(&addr), 12.5, THEME.text))
                            .fill(THEME.well)
                            .stroke(egui::Stroke::new(1.0, THEME.line_strong))
                            .corner_radius(9);
                        if ui.add(copy).on_hover_text("Click to copy").clicked() {
                            ui.ctx().copy_text(addr.clone());
                            app.copied_at = Some(std::time::Instant::now());
                        }
                    } else {
                        ui.label(RichText::new("none").size(12.5).color(THEME.text4));
                    }
                });
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
