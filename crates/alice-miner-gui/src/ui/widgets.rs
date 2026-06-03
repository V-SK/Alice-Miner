//! Shared widgets for the Miner UI — chips, pills, stat cards, section labels,
//! eyebrows. Tuned to the contract palette (zinc surfaces, brand orange spine).

use eframe::egui::{self, Color32, CornerRadius, FontFamily, Pos2, Response, RichText, Stroke, Ui, Vec2};

use super::theme::THEME;

/// Status tone for the connection/mining pill.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Live,
    Warn,
    Danger,
    Off,
}

impl Tone {
    pub fn fg(self) -> Color32 {
        match self {
            Tone::Live => THEME.live,
            Tone::Warn => THEME.warn,
            Tone::Danger => THEME.err,
            Tone::Off => THEME.off,
        }
    }
}

/// A blinking status dot (the contract's `.dot.online` pulse). `blink` toggles a
/// subtle opacity pulse using the egui clock.
pub fn status_dot(ui: &mut Ui, color: Color32, size: f32, blink: bool) -> Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
    let painter = ui.painter();
    let alpha = if blink {
        let t = ui.input(|i| i.time) as f32;
        ui.ctx().request_repaint();
        (0.55 + 0.45 * (t * 2.4).sin()).clamp(0.0, 1.0)
    } else {
        1.0
    };
    let c = Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), (alpha * 255.0) as u8);
    // Soft halo.
    painter.circle_filled(
        rect.center(),
        size * 0.9,
        Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), (alpha * 90.0) as u8),
    );
    painter.circle_filled(rect.center(), size * 0.5, c);
    resp
}

/// A rounded status pill: dot + label on a tinted, bordered chip (titlebar +
/// dashboard header). `blink` animates the dot when live.
pub fn status_pill(ui: &mut Ui, tone: Tone, label: &str, blink: bool) -> Response {
    let fg = tone.fg();
    let tint = Color32::from_rgba_unmultiplied(fg.r(), fg.g(), fg.b(), 26);
    let border = Color32::from_rgba_unmultiplied(fg.r(), fg.g(), fg.b(), 96);
    egui::Frame::NONE
        .fill(tint)
        .corner_radius(CornerRadius::same(255))
        .inner_margin(egui::Margin::symmetric(11, 5))
        .stroke(Stroke::new(1.0, border))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 7.0;
                status_dot(ui, fg, 7.0, blink);
                ui.label(RichText::new(label).size(11.5).strong().color(fg));
            });
        })
        .response
}

/// A neutral chip (lane chip, legend chip): optional coloured dot + text.
pub fn chip(ui: &mut Ui, dot: Option<Color32>, text: &str) -> Response {
    egui::Frame::NONE
        .fill(THEME.surface2)
        .corner_radius(CornerRadius::same(255))
        .inner_margin(egui::Margin::symmetric(12, 6))
        .stroke(Stroke::new(1.0, THEME.line))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                if let Some(c) = dot {
                    let (r, _) = ui.allocate_exact_size(Vec2::splat(7.0), egui::Sense::hover());
                    ui.painter().circle_filled(r.center(), 3.5, c);
                }
                ui.label(RichText::new(text).size(12.5).color(THEME.text2));
            });
        })
        .response
}

/// A small field label above an input.
pub fn field_label(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).size(11.5).strong().color(THEME.text2));
    ui.add_space(4.0);
}

/// An eyebrow: tiny, brand-tinted, uppercase, letter-spaced label.
pub fn eyebrow(ui: &mut Ui, text: &str) {
    ui.label(
        RichText::new(text.to_uppercase())
            .size(10.5)
            .extra_letter_spacing(2.0)
            .strong()
            .color(THEME.text_brand),
    );
}

/// A small-caps section label with a trailing rule (dashboard sections).
pub fn section_label(ui: &mut Ui, text: &str) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(text.to_uppercase())
                .size(10.0)
                .extra_letter_spacing(1.6)
                .strong()
                .color(THEME.text3),
        );
        let (rect, _) = ui.allocate_exact_size(
            Vec2::new(ui.available_width(), 1.0),
            egui::Sense::hover(),
        );
        ui.painter().hline(
            rect.x_range(),
            rect.center().y,
            Stroke::new(1.0, THEME.line),
        );
    });
}

/// Monospace number text (every numeral is mono per the contract).
pub fn mono(text: impl Into<String>, size: f32, color: Color32) -> RichText {
    RichText::new(text.into())
        .family(FontFamily::Monospace)
        .size(size)
        .color(color)
}

/// A primary brand button (filled orange, dark ink text).
pub fn primary_button(ui: &mut Ui, label: &str, enabled: bool, full: bool) -> Response {
    let mut btn = egui::Button::new(
        RichText::new(label).size(14.0).strong().color(THEME.ink_on_brand),
    )
    .fill(THEME.brand)
    .corner_radius(10);
    btn = if full {
        btn.min_size(Vec2::new(ui.available_width(), 44.0))
    } else {
        btn.min_size(Vec2::new(150.0, 42.0))
    };
    ui.add_enabled(enabled, btn)
}

/// A ghost (outline) button.
pub fn ghost_button(ui: &mut Ui, label: &str, full: bool) -> Response {
    let mut btn = egui::Button::new(RichText::new(label).size(13.5).color(THEME.text))
        .fill(Color32::TRANSPARENT)
        .stroke(Stroke::new(1.0, THEME.line_strong))
        .corner_radius(10);
    if full {
        btn = btn.min_size(Vec2::new(ui.available_width(), 44.0));
    }
    ui.add(btn)
}

/// A recessed text input on the well surface.
pub fn text_input(ui: &mut Ui, value: &mut String, hint: &str, mono: bool) -> Response {
    let mut edit = egui::TextEdit::singleline(value)
        .desired_width(f32::INFINITY)
        .hint_text(hint)
        .margin(egui::vec2(12.0, 10.0))
        .background_color(THEME.well);
    if mono {
        edit = edit.font(egui::TextStyle::Monospace);
    }
    ui.add(edit)
}

/// A recessed multi-line text input (mnemonic paste).
pub fn text_area(ui: &mut Ui, value: &mut String, hint: &str, rows: usize) -> Response {
    ui.add(
        egui::TextEdit::multiline(value)
            .desired_width(f32::INFINITY)
            .desired_rows(rows)
            .hint_text(hint)
            .font(egui::TextStyle::Monospace)
            .margin(egui::vec2(12.0, 10.0))
            .background_color(THEME.well),
    )
}

/// Shorten a long address as `head…tail` (display only; never a collection addr).
pub fn shorten(addr: &str) -> String {
    if addr.chars().count() <= 14 {
        return addr.to_string();
    }
    let head: String = addr.chars().take(6).collect();
    let tail: String = addr.chars().rev().take(4).collect::<String>().chars().rev().collect();
    format!("{head}…{tail}")
}

/// Paint a card frame (opaque zinc surface + 1px line + soft shadow + a faint
/// top inner highlight). Returns the inner-closure result.
pub fn card<R>(ui: &mut Ui, max_width: f32, inner: impl FnOnce(&mut Ui) -> R) -> R {
    let t = THEME;
    let r = egui::Frame::NONE
        .fill(t.surface)
        .corner_radius(CornerRadius::same(20))
        .inner_margin(egui::Margin::same(26))
        .stroke(Stroke::new(1.0, t.line))
        .shadow(egui::epaint::Shadow {
            offset: [0, 12],
            blur: 36,
            spread: 0,
            color: Color32::from_rgba_premultiplied(0, 0, 0, 120),
        })
        .show(ui, |ui| {
            ui.set_max_width(max_width);
            inner(ui)
        });
    // Faint top inner highlight along the card's top edge.
    let top = r.response.rect;
    ui.painter().hline(
        (top.left() + 20.0)..=(top.right() - 20.0),
        top.top() + 1.0,
        Stroke::new(1.0, Color32::from_rgba_unmultiplied(255, 255, 255, 16)),
    );
    r.inner
}

/// A flat stat card for the dashboard grid. `accent` paints a lane-coloured top
/// rule. `value` is rendered mono; `pending` makes it brand-coloured (no number).
pub fn stat_card(
    ui: &mut Ui,
    width: f32,
    label: &str,
    value: RichText,
    meta: Option<RichText>,
    accent: Option<Color32>,
    body: Option<&dyn Fn(&mut Ui)>,
) {
    let t = THEME;
    let resp = egui::Frame::NONE
        .fill(t.surface2)
        .corner_radius(CornerRadius::same(14))
        .inner_margin(egui::Margin::symmetric(16, 14))
        .stroke(Stroke::new(1.0, t.line_strong))
        .show(ui, |ui| {
            ui.set_width(width);
            ui.label(
                RichText::new(label.to_uppercase())
                    .size(10.0)
                    .extra_letter_spacing(1.3)
                    .strong()
                    .color(t.text3),
            );
            ui.add_space(8.0);
            ui.label(value);
            if let Some(m) = meta {
                ui.add_space(6.0);
                ui.label(m);
            }
            if let Some(b) = body {
                ui.add_space(8.0);
                b(ui);
            }
        });
    if let Some(c) = accent {
        let r = resp.response.rect;
        ui.painter().hline(
            r.x_range(),
            r.top() + 1.0,
            Stroke::new(2.0, c),
        );
    }
}

/// A tiny sparkline of recent samples (dashboard hashrate card). `samples` are
/// arbitrary positive values; the last bar is highlighted.
pub fn sparkline(ui: &mut Ui, samples: &[f32], width: f32, height: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, height), egui::Sense::hover());
    if samples.is_empty() {
        return;
    }
    let max = samples.iter().cloned().fold(f32::MIN, f32::max).max(1e-3);
    let min = samples.iter().cloned().fold(f32::MAX, f32::min);
    let span = (max - min).max(1e-3);
    let n = samples.len();
    let gap = 2.5;
    let bar_w = ((width - gap * (n as f32 - 1.0)) / n as f32).max(1.0);
    let painter = ui.painter();
    for (i, &v) in samples.iter().enumerate() {
        let norm = ((v - min) / span).clamp(0.0, 1.0);
        let h = (norm * (height - 3.0) + 3.0).min(height);
        let x = rect.left() + i as f32 * (bar_w + gap);
        let bar = egui::Rect::from_min_max(
            Pos2::new(x, rect.bottom() - h),
            Pos2::new(x + bar_w, rect.bottom()),
        );
        let last = i == n - 1;
        let col = if last { THEME.brand300 } else { THEME.brand400.linear_multiply(0.7) };
        painter.rect_filled(bar, 2.0, col);
    }
}
