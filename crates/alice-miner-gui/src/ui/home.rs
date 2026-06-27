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

    // Eyebrow reflects the state (live vs setup vs the calm fault label). While
    // Running-but-no-hashrate (connecting / RandomX warm-up / a reconnecting
    // miner), show "Connecting" instead of a confident "live" so a 0 H/s screen
    // never reads as healthy mining (the macOS "0 under LIVE" symptom).
    let eyebrow = match state {
        EngineState::Running if app.is_warming_up() => "Connecting · 连接中",
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
        // on a non-NVIDIA/AMD box the PRL chip reads "needs NVIDIA/AMD GPU" and
        // is inert; XMR stays the default.
        lane_selector(ui, app);
        // Multi-GPU picker (A5c): a simple per-card checkbox list, shown ONLY on a
        // ≥2-GPU box while a GPU lane is selected. Default = all cards checked (=
        // All, argv unchanged). Hidden on this Mac (single unified GPU) and for the
        // CPU-XMR lane — the no-regression contract.
        if app.show_gpu_selector() {
            ui.add_space(8.0);
            gpu_selector(ui, app);
        }
        // Dual-mine toggle: run BOTH lanes (CPU-XMR + GPU-PRL) together. Gated on
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
        // so the click flags use interior mutability (the sizing pass never
        // registers a real click, so these fire at most once). A small pencil
        // "change" affordance opens the post-onboarding change-reward-address
        // flow; it is INERT while mining (the address can't change under a live
        // lane) and shows a "stop first" hover then.
        let do_copy = std::cell::Cell::new(false);
        let do_change = std::cell::Cell::new(false);
        let can_change = !app.is_mining();
        centered(ui, |ui| {
            ui.label(RichText::new(strings::REWARDS_TO).size(12.5).color(THEME.text2));
            ui.add_space(6.0);
            ui.label(widgets::mono(widgets::shorten(&addr), 12.5, THEME.text));
            ui.add_space(4.0);
            if super::icons::show(ui, Icon::Copy, 13.0, THEME.text4)
                .interact(egui::Sense::click())
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .on_hover_text("Copy address")
                .clicked()
            {
                do_copy.set(true);
            }
            ui.add_space(6.0);
            // Change (pencil) affordance — brand-tinted when actionable, muted
            // while mining.
            let edit_color = if can_change { THEME.text_brand } else { THEME.text4 };
            let edit = super::icons::show(ui, Icon::Edit, 13.0, edit_color)
                .interact(egui::Sense::click());
            let edit = if can_change {
                edit.on_hover_cursor(egui::CursorIcon::PointingHand)
                    .on_hover_text("Change reward address")
            } else {
                edit.on_hover_text(strings::CHANGE_ADDR_MINING_BLOCK)
            };
            if edit.clicked() && can_change {
                do_change.set(true);
            }
        });
        if do_copy.get() {
            ui.ctx().copy_text(addr.clone());
            app.copied_at = Some(std::time::Instant::now());
        }
        if do_change.get() {
            app.open_change_addr();
        }
    }

    // ── Status line ───────────────────────────────────────────────────────────
    ui.add_space(10.0);
    status_line(ui, app);

    // ── Error banner ──────────────────────────────────────────────────────────
    // Unconditional surface for `app.error`, independent of engine state. The
    // engine emits `Event::Error` on a pre-spawn failure (engine-resolve /
    // SHA-pin mismatch / watch-only-PRL refusal) WITHOUT transitioning to the
    // Error state (engine.rs:444 `start_run` Err arm) — so the status line, which
    // only shows the error text in `EngineState::Error`, would otherwise swallow
    // it and Start appears to do nothing (the v0.3.1 macOS silence). This banner
    // makes every such failure visible; it auto-clears on the next Start (which
    // sets `error = None`).
    error_banner(ui, app);

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
            // The live hashrate number (mono) + AUTO-SCALED unit, then the hashing
            // sub-line. CPU-XMR is kH/s; GPU-PRL (pearlhash) is MH/s–TH/s, so a
            // fixed "kH/s" would render a real ~0.87 TH/s rate as the absurd
            // "865549824.00 kH/s". `fmt_hashrate` picks H/s … TH/s by magnitude.
            let (txt, unit) = widgets::fmt_hashrate(app.hr_display_khs);
            centered(ui, |ui| {
                ui.label(widgets::mono(txt.clone(), 31.0, THEME.text).strong());
                ui.add_space(5.0);
                ui.label(RichText::new(unit).size(13.0).strong().color(THEME.text3));
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
        // Running but no hashrate yet → connecting/warming up (not a confident
        // green "live" next to 0.00 kH/s).
        EngineState::Running if app.is_warming_up() => {
            (Tone::Warn, strings::STATUS_CONNECTING.to_string())
        }
        EngineState::Running => {
            // A transient warning pushed while STILL mining (e.g. the PoP-refresh
            // "crediting may pause" note) must be visible — a full-hashrate lane can be
            // earning nothing. Show it in a Warn tone rather than a confident green
            // "Mining"; otherwise the calm share line.
            if let Some(msg) = app.snapshot.as_ref().and_then(|s| s.message.clone()) {
                (Tone::Warn, msg)
            } else {
                let a = app.snapshot.as_ref().map(|s| s.shares_accepted).unwrap_or(0);
                let r = app.snapshot.as_ref().map(|s| s.shares_rejected).unwrap_or(0);
                (Tone::Live, format!("Mining · {a}/{r} shares"))
            }
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

/// A danger banner that surfaces `app.error` whenever it is set — UNLESS the
/// engine is in the Error state, where `status_line` already shows it (avoid a
/// double message). This catches the pre-spawn failures the status line misses:
/// `start_run` (engine.rs) reports an engine-resolve / SHA-pin / watch-only-PRL
/// failure via `Event::Error` while leaving the engine Idle, so without this the
/// message is invisible and Start silently does nothing. Full-width within the
/// hero card; wraps long messages. The text is the engine's own honest string.
fn error_banner(ui: &mut egui::Ui, app: &MinerApp) {
    let Some(err) = app.error.as_ref() else {
        return;
    };
    if matches!(app.state(), EngineState::Error) {
        return; // already surfaced by the status line
    }
    ui.add_space(11.0);
    let fg = THEME.err;
    egui::Frame::NONE
        .fill(egui::Color32::from_rgba_unmultiplied(fg.r(), fg.g(), fg.b(), 20))
        .stroke(egui::Stroke::new(
            1.0,
            egui::Color32::from_rgba_unmultiplied(fg.r(), fg.g(), fg.b(), 80),
        ))
        .corner_radius(10)
        .inner_margin(egui::Margin::symmetric(13, 10))
        .show(ui, |ui| {
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
            ui.horizontal(|ui| {
                ui.add_space(0.0);
                // Vector icon, NOT an emoji (the no-emoji/SVG brand rule; emoji also
                // renders inconsistently across OS/fonts on this safety-critical surface).
                super::icons::show(ui, super::icons::Icon::Alert, 14.0, fg);
                ui.add_space(7.0);
                ui.label(RichText::new(err).size(12.5).color(THEME.text));
            });
        });
}

/// The lane row beneath the device line: the CPU-XMR chip plus a selectable chip
/// for each runnable GPU **engine** on this device. The two pearlhash lanes —
/// **PRL** (SRBMiner → herominers relay) and **Alpha** (AlphaMiner → AlphaPool
/// relay) — earn the SAME reward and are a genuine ENGINE CHOICE on a Turing+
/// NVIDIA box where BOTH run: both render as live, selectable chips, with the
/// device's RECOMMENDED engine pre-selected so one-click still "just works" and the
/// miner can switch. On Volta/V100 only Alpha is runnable (SRBMiner can't run there),
/// so only that GPU chip shows — cleanly, not as "coming soon". On a non-GPU Mac no
/// GPU chip is runnable, so a single muted PRL chip shows the honest "needs
/// NVIDIA/AMD GPU" reason and XMR stays selected (the prior CPU-only behaviour).
fn lane_selector(ui: &mut egui::Ui, app: &mut MinerApp) {
    let selected = app.active_lane();
    // While a run is in flight, the lane is locked (can't switch under a child).
    let locked = matches!(
        app.state(),
        EngineState::Running | EngineState::Starting | EngineState::Stopping
    );
    // The runnable GPU engines to OFFER (recommended-first). Empty on a non-GPU /
    // undetected box. When BOTH pearlhash engines run this is the PRL-vs-Alpha pick.
    let offered = app.offered_gpu_lanes();
    // XMR always leads; then each offered GPU engine. When no GPU engine is runnable
    // we still show a single muted PRL chip so the "needs NVIDIA/AMD GPU" reason is
    // honest (the prior behaviour on a CPU-only / Apple box).
    let mut lanes: Vec<Lane> = vec![Lane::Xmr];
    if offered.is_empty() {
        lanes.push(Lane::GpuPrl);
    } else {
        lanes.extend(offered);
    }
    let pick = std::cell::Cell::new(None);
    centered(ui, |ui| {
        ui.spacing_mut().item_spacing.x = 7.0;
        for &lane in &lanes {
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
/// (CPU-XMR + GPU-PRL), each crash-isolated, `cores-2` XMR headroom. The toggle
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

/// The **simple multi-GPU picker** (A5c): one checkbox row per enumerated card
/// (index · name · VRAM), defaulting to all-checked (= All, the every-card argv).
/// Shown only on a ≥2-GPU box with a GPU lane selected; the caller gates on
/// [`MinerApp::show_gpu_selector`]. Unchecking a card resolves Start to
/// `GpuSelection::Ids(checked indices)` (opt-in); the last checked card can't be
/// cleared (an empty set is meaningless — pick XMR to not GPU-mine). Credit-only:
/// the control only toggles device indices — no address/secret rides along.
fn gpu_selector(ui: &mut egui::Ui, app: &mut MinerApp) {
    let accent = lane_accent(app.active_lane());
    // Snapshot the rows we need (index/name/vram + checked) so we don't hold an
    // immutable borrow of `app` across the toggle mutation.
    let rows: Vec<(usize, u32, String, u32, bool)> = app
        .gpu_devices()
        .iter()
        .enumerate()
        .map(|(pos, d)| {
            let checked = app.gpu_selected.get(pos).copied().unwrap_or(true);
            (pos, d.index, d.name.clone(), d.vram_gb, checked)
        })
        .collect();
    let checked_count = rows.iter().filter(|(_, _, _, _, c)| *c).count();
    let toggle = std::cell::Cell::new(None);

    egui::Frame::NONE
        .fill(THEME.surface2)
        .corner_radius(12)
        .inner_margin(egui::Margin::symmetric(13, 10))
        .stroke(egui::Stroke::new(1.0, THEME.line))
        .show(ui, |ui| {
            ui.set_width(HERO_CARD_W - 64.0);
            // Header: label + the "N of M cards" count.
            centered(ui, |ui| {
                ui.label(RichText::new("GPUs to mine").size(12.0).strong().color(THEME.text2));
                ui.add_space(7.0);
                ui.label(
                    RichText::new(format!("{} of {} selected", checked_count, rows.len()))
                        .size(11.0)
                        .color(THEME.text4),
                );
            });
            ui.add_space(8.0);
            for (pos, index, name, vram, checked) in &rows {
                // A single card row: checkbox square + "GPU N · <name> · <vram> GB".
                // The last checked card is non-interactive (can't clear it).
                let is_last_checked = *checked && checked_count <= 1;
                let label = if *vram > 0 {
                    format!("GPU {index} · {name} · {vram} GB")
                } else {
                    format!("GPU {index} · {name}")
                };
                let resp = gpu_row(ui, *checked, &label, accent, is_last_checked);
                if resp.clicked() && !is_last_checked {
                    toggle.set(Some(*pos));
                }
            }
        });

    if let Some(pos) = toggle.get() {
        app.toggle_gpu(pos);
    }
}

/// One GPU checkbox row: a square checkbox (filled+check when on) + the card
/// label. Clickable unless it's the last checked card (then inert/dimmed).
fn gpu_row(
    ui: &mut egui::Ui,
    checked: bool,
    label: &str,
    accent: egui::Color32,
    last_checked: bool,
) -> egui::Response {
    let frame = egui::Frame::NONE
        .inner_margin(egui::Margin::symmetric(2, 4))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 9.0;
                // The checkbox square.
                let (rect, _) =
                    ui.allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::hover());
                let p = ui.painter_at(rect);
                if checked {
                    p.rect_filled(rect, 4.0, accent);
                    // A simple check mark.
                    let c = rect.center();
                    let s = rect.width();
                    p.line_segment(
                        [
                            egui::pos2(c.x - s * 0.24, c.y + s * 0.02),
                            egui::pos2(c.x - s * 0.05, c.y + s * 0.20),
                        ],
                        egui::Stroke::new(1.8, THEME.ink_on_brand),
                    );
                    p.line_segment(
                        [
                            egui::pos2(c.x - s * 0.05, c.y + s * 0.20),
                            egui::pos2(c.x + s * 0.26, c.y - s * 0.20),
                        ],
                        egui::Stroke::new(1.8, THEME.ink_on_brand),
                    );
                } else {
                    p.rect_stroke(
                        rect,
                        4.0,
                        egui::Stroke::new(1.0, THEME.line_strong),
                        egui::epaint::StrokeKind::Inside,
                    );
                }
                let text_color = if checked { THEME.text } else { THEME.text3 };
                ui.label(RichText::new(label).size(11.5).color(text_color));
            });
        });

    let resp = frame.response;
    if last_checked {
        resp.interact(egui::Sense::hover())
            .on_hover_text("At least one GPU must stay selected")
    } else {
        resp.interact(egui::Sense::click())
            .on_hover_cursor(egui::CursorIcon::PointingHand)
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
        Lane::GpuPrl => "PRL",
        Lane::GpuAlpha => "Alpha",
        Lane::GpuRvn => "RVN",
    }
}

/// The honest tail for an Unavailable lane (why it can't run here).
fn unavailable_tail(lane: Lane) -> &'static str {
    match lane {
        // RVN unavailable means no NVIDIA (Apple/CPU-only) → XMR is the lane.
        Lane::GpuRvn => "needs NVIDIA",
        // PRL (SRBMiner) needs an NVIDIA/AMD GPU; no macOS build.
        Lane::GpuPrl => "needs NVIDIA/AMD GPU",
        // Alpha (alpha-miner) is NVIDIA-CUDA only (the Volta/V100 path).
        Lane::GpuAlpha => "needs NVIDIA GPU",
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
