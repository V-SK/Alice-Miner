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

/// A pill toggle (the contract's `.tog`): a 42×24 track with a sliding knob.
/// Brand-filled when on, recessed well when off. Returns the click response;
/// the caller flips its bound bool.
pub fn toggle(ui: &mut Ui, on: bool) -> Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(42.0, 24.0), egui::Sense::click());
    let p = ui.painter_at(rect);
    let (track, knob) = if on {
        (THEME.brand, Color32::WHITE)
    } else {
        (THEME.well, THEME.off)
    };
    p.rect_filled(rect, 255.0, track);
    if !on {
        p.rect_stroke(rect, 255.0, Stroke::new(1.0, THEME.line_strong), egui::epaint::StrokeKind::Inside);
    }
    let r = 9.0;
    let cx = if on { rect.right() - 12.0 } else { rect.left() + 12.0 };
    p.circle_filled(Pos2::new(cx, rect.center().y), r, knob);
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
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

/// A recessed single-line input that MASKS its content (egui `.password(true)`)
/// — used for the wallet-unlock password prompt so the passphrase is never shown
/// on screen. Same recessed styling as [`text_input`]; always non-mono.
pub fn password_input(ui: &mut Ui, value: &mut String, hint: &str) -> Response {
    ui.add(
        egui::TextEdit::singleline(value)
            .desired_width(f32::INFINITY)
            .hint_text(hint)
            .password(true)
            .margin(egui::vec2(12.0, 10.0))
            .background_color(THEME.well),
    )
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

/// Lay out a row of inline widgets and CENTRE the whole row horizontally within
/// the current `Ui`.
///
/// egui's `top_down(Align::Center)` only centres a child by its *allocated* width,
/// and `ui.horizontal` left-aligns its content, so we measure the row's natural
/// width in a throwaway **sizing pass** and indent by half the slack before the
/// real `horizontal`. The sizing-pass scope advances the parent cursor by the
/// measured height, so we immediately pull it back up by the same amount
/// (`add_space(-measured_h)`) — WITHOUT that correction every centred row consumed
/// its height TWICE vertically and inflated tall cards (the Home hero) far past
/// the viewport. `add` runs twice (measure + real), so it is `Fn`.
pub fn center_row(ui: &mut Ui, add: impl Fn(&mut Ui)) {
    // ── Pass 1: measure the row's natural size (sizing pass — not painted). ──
    let avail = ui.available_width();
    let measured = ui
        .scope_builder(
            egui::UiBuilder::new()
                .sizing_pass()
                .layout(egui::Layout::left_to_right(egui::Align::Center)),
            |ui| {
                ui.set_invisible(); // belt-and-braces: never paints
                add(ui);
            },
        )
        .response
        .rect;
    // Reclaim the vertical space the sizing-pass scope just advanced past, so the
    // real row below occupies the slot ONCE (negative advance moves the top-down
    // cursor back up; the real row re-expands the min_rect to the same place).
    ui.add_space(-measured.height());

    // ── Pass 2: indent by half the slack, then lay the row out for real. ──
    let pad = ((avail - measured.width()) * 0.5).max(0.0);
    ui.horizontal(|ui| {
        if pad > 0.0 {
            ui.add_space(pad);
        }
        add(ui);
    });
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

/// Like [`card`] but with a FIXED inner `width` and a STABLE minimum inner height
/// (`min_h`). Used by onboarding so the card frame + its centred position are the
/// SAME across every wizard step (the fix for the card drifting between steps):
/// the body never shrinks below `min_h`, so shorter steps don't pull the card up.
/// Content taller than `min_h` still grows (the outer ScrollArea catches it).
pub fn card_min_h<R>(ui: &mut Ui, width: f32, min_h: f32, inner: impl FnOnce(&mut Ui) -> R) -> R {
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
            // Pin BOTH dimensions: exact content width (so the frame can't widen)
            // and a min height (so it can't shrink below the tallest step).
            ui.set_width(width);
            ui.set_min_height(min_h);
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
#[allow(clippy::too_many_arguments)]
pub fn stat_card(
    ui: &mut Ui,
    width: f32,
    // Minimum CONTENT height so a row of cards shares one bottom edge (equal-height
    // cards) instead of each sizing to its own content — without this the four
    // dashboard KPI cards were ragged/staircased. Pass 0.0 to size to content.
    min_content_height: f32,
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
            ui.set_min_height(min_content_height);
            // WRAP (don't extend) so a long label/value/meta can never widen the
            // card past `width` in a horizontal grid — it wraps to a second line
            // instead, so text (incl. the honesty-critical "pending") is always
            // fully visible and the card footprint stays `width + inner_margin`.
            // (egui labels otherwise EXTEND inside a horizontal-ancestor layout,
            // which was letting "Est. rewards" balloon and clip off the right.)
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
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

/// Format a hashrate (given in **kH/s**, the smoothed readout value) auto-scaled
/// to a human unit, returning `(number, unit)`. CPU-XMR sits at a few kH/s; a
/// GPU-PRL pearlhash lane runs MH/s–TH/s, so a fixed "kH/s" makes a real ~0.87
/// TH/s rate read as "865549824.00 kH/s". Picks H/s · kH/s · MH/s · GH/s · TH/s
/// by magnitude. Shared by the Home hero, the Dashboard hero, and lane rows.
pub fn fmt_hashrate(khs: f32) -> (String, &'static str) {
    let hs = (khs as f64) * 1000.0;
    let (v, unit) = if !hs.is_finite() || hs < 1_000.0 {
        (hs.max(0.0), "H/s")
    } else if hs < 1_000_000.0 {
        (hs / 1_000.0, "kH/s")
    } else if hs < 1_000_000_000.0 {
        (hs / 1_000_000.0, "MH/s")
    } else if hs < 1_000_000_000_000.0 {
        (hs / 1_000_000_000.0, "GH/s")
    } else {
        (hs / 1_000_000_000_000.0, "TH/s")
    };
    (format!("{v:.2}"), unit)
}

#[cfg(test)]
mod tests {
    use super::fmt_hashrate;

    #[test]
    fn hashrate_unit_auto_scales_by_magnitude() {
        // CPU-XMR: a few kH/s stays kH/s.
        assert_eq!(fmt_hashrate(8.4), ("8.40".into(), "kH/s"));
        // The reported PRL value 865549824 kH/s is really ~0.87 TH/s → GH/s, NOT a
        // 9-digit "kH/s". This is the exact field bug.
        assert_eq!(fmt_hashrate(865_549_824.0), ("865.55".into(), "GH/s"));
        // Sub-kH/s → H/s; >1 TH/s → TH/s.
        assert_eq!(fmt_hashrate(0.5), ("500.00".into(), "H/s"));
        assert_eq!(fmt_hashrate(2_000_000_000.0), ("2.00".into(), "TH/s"));
        // Non-finite / negative → 0 H/s (never panics).
        assert_eq!(fmt_hashrate(f32::NAN).1, "H/s");
        assert_eq!(fmt_hashrate(-1.0), ("0.00".into(), "H/s"));
    }
}
