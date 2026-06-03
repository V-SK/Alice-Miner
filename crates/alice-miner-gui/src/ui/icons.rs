//! Monoline icons drawn with epaint — NO emoji anywhere (the brief's hard rule).
//!
//! Each icon is a small set of strokes/shapes on a 24×24 viewbox, transcribed
//! from the mockup's inline `<svg class="ic">` paths (stroke-width 1.5, round
//! caps/joins). They are painted directly with `egui::Painter` so they tint to
//! any colour and stay crisp at any size — the egui-native equivalent of the
//! contract's monoline SVG set.

use eframe::egui::{self, Color32, Pos2, Rect, Stroke, Vec2};

/// Which monoline glyph to draw. The full set is the contract's monoline icon
/// vocabulary; a few are used only by later screens / M2 polish.
#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Icon {
    /// House (Home nav).
    Home,
    /// 2×2 grid (Dashboard nav).
    Grid,
    /// Gear (Settings nav).
    Gear,
    /// Play triangle (Start CTA).
    Play,
    /// Filled rounded square (Stop).
    Stop,
    /// Overlapping rectangles (copy).
    Copy,
    /// Chevron down (change / expand).
    ChevronDown,
    /// Arrow right (continue / open).
    ArrowRight,
    /// CPU chip (device line).
    Cpu,
    /// Eye (watch-only / paste address).
    Eye,
    /// Warning triangle (backup banner).
    Alert,
    /// Check mark (confirmations / accepted).
    Check,
    /// Activity zigzag (hashrate).
    Activity,
    /// Globe (network / endpoint).
    Globe,
    /// Plus (add / generate).
    Plus,
    /// Import card (mnemonic / seed).
    Import,
}

/// Draw `icon` centered in `rect`, stroked in `color`. `width` is the stroke
/// width in points (the contract uses ~1.5 at 24px; scale with the box).
pub fn draw(painter: &egui::Painter, icon: Icon, rect: Rect, color: Color32, width: f32) {
    // Map the 24×24 viewbox onto `rect`.
    let s = rect.width().min(rect.height());
    let o = rect.center() - Vec2::splat(s / 2.0);
    let p = |x: f32, y: f32| Pos2::new(o.x + x / 24.0 * s, o.y + y / 24.0 * s);
    let stroke = Stroke::new(width, color);
    let line = |a: Pos2, b: Pos2| painter.line_segment([a, b], stroke);
    let poly = |pts: Vec<Pos2>| {
        for w in pts.windows(2) {
            painter.line_segment([w[0], w[1]], stroke);
        }
    };

    match icon {
        Icon::Home => {
            // Roof + body.
            poly(vec![p(3.0, 11.2), p(12.0, 4.0), p(21.0, 11.2)]);
            poly(vec![p(5.0, 9.6), p(5.0, 20.0), p(19.0, 20.0), p(19.0, 9.6)]);
        }
        Icon::Grid => {
            for (x, y) in [(3.0, 3.0), (13.5, 3.0), (3.0, 13.5), (13.5, 13.5)] {
                stroke_rrect(painter, p(x, y), p(x + 7.5, y + 7.5), 1.5 / 24.0 * s, stroke);
            }
        }
        Icon::Gear => {
            // A clean gear: outer ring + 8 teeth + hub (simpler than the CSS
            // path but reads identically as a settings glyph).
            let c = p(12.0, 12.0);
            let r_out = 6.4 / 24.0 * s;
            let r_in = 3.0 / 24.0 * s;
            painter.circle_stroke(c, r_out, stroke);
            painter.circle_stroke(c, r_in, stroke);
            for k in 0..8 {
                let ang = std::f32::consts::TAU * k as f32 / 8.0;
                let d = Vec2::angled(ang);
                line(c + d * r_out, c + d * (r_out + 2.4 / 24.0 * s));
            }
        }
        Icon::Play => {
            // Filled triangle (a CTA glyph). 7,5.5 → 19,12 → 7,18.5.
            painter.add(egui::Shape::convex_polygon(
                vec![p(7.0, 5.5), p(19.0, 12.0), p(7.0, 18.5)],
                color,
                Stroke::NONE,
            ));
        }
        Icon::Stop => {
            let r = stroke_rrect_filled(p(6.0, 6.0), p(18.0, 18.0), 2.0 / 24.0 * s);
            painter.rect_filled(r.0, r.1, color);
        }
        Icon::Copy => {
            stroke_rrect(painter, p(9.0, 9.0), p(20.0, 20.0), 2.0 / 24.0 * s, stroke);
            poly(vec![p(5.0, 15.0), p(5.0, 5.0)]);
            poly(vec![p(5.0, 5.0), p(7.0, 3.0)]);
            poly(vec![p(7.0, 3.0), p(17.0, 3.0)]);
        }
        Icon::ChevronDown => poly(vec![p(6.0, 9.0), p(12.0, 15.0), p(18.0, 9.0)]),
        Icon::ArrowRight => {
            line(p(5.0, 12.0), p(19.0, 12.0));
            poly(vec![p(13.0, 6.0), p(19.0, 12.0), p(13.0, 18.0)]);
        }
        Icon::Cpu => {
            stroke_rrect(painter, p(6.0, 6.0), p(18.0, 18.0), 2.0 / 24.0 * s, stroke);
            // Pins on all four sides.
            for x in [9.0, 12.0, 15.0] {
                line(p(x, 2.0), p(x, 4.0));
                line(p(x, 20.0), p(x, 22.0));
            }
            for y in [9.0, 12.0, 15.0] {
                line(p(2.0, y), p(4.0, y));
                line(p(20.0, y), p(22.0, y));
            }
        }
        Icon::Eye => {
            // Almond outline (two arcs) + pupil.
            eye_almond(painter, p, stroke);
            painter.circle_stroke(p(12.0, 12.0), 3.0 / 24.0 * s, stroke);
        }
        Icon::Alert => {
            poly(vec![p(10.3, 3.9), p(2.4, 18.0)]);
            poly(vec![p(2.4, 18.0), p(4.1, 21.0), p(19.9, 21.0), p(21.6, 18.0)]);
            poly(vec![p(21.6, 18.0), p(13.7, 3.9), p(10.3, 3.9)]);
            line(p(12.0, 9.0), p(12.0, 13.0));
            painter.circle_filled(p(12.0, 16.8), width * 0.7, color);
        }
        Icon::Check => poly(vec![p(20.0, 6.0), p(9.0, 17.0), p(4.0, 12.0)]),
        Icon::Activity => poly(vec![
            p(3.0, 12.0),
            p(7.0, 12.0),
            p(10.0, 4.0),
            p(14.0, 20.0),
            p(17.0, 12.0),
            p(21.0, 12.0),
        ]),
        Icon::Globe => {
            let c = p(12.0, 12.0);
            painter.circle_stroke(c, 9.0 / 24.0 * s, stroke);
            line(p(3.0, 12.0), p(21.0, 12.0));
            // Two meridian ellipses approximated by vertical line + arcs.
            ellipse_v(painter, c, 4.5 / 24.0 * s, 9.0 / 24.0 * s, stroke);
        }
        Icon::Plus => {
            line(p(12.0, 5.0), p(12.0, 19.0));
            line(p(5.0, 12.0), p(19.0, 12.0));
        }
        Icon::Import => {
            stroke_rrect(painter, p(3.0, 7.0), p(21.0, 20.0), 2.0 / 24.0 * s, stroke);
            poly(vec![p(4.0, 7.0), p(4.0, 5.0), p(6.0, 3.0)]);
            poly(vec![p(6.0, 3.0), p(18.0, 3.0), p(20.0, 5.0), p(20.0, 7.0)]);
            line(p(3.0, 11.0), p(21.0, 11.0));
        }
    }
}

/// Convenience: allocate a fixed square in the current layout and draw `icon`.
pub fn show(ui: &mut egui::Ui, icon: Icon, size: f32, color: Color32) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
    let w = (size / 24.0 * 1.5).max(1.2);
    draw(ui.painter(), icon, rect, color, w);
    resp
}

fn stroke_rrect(painter: &egui::Painter, a: Pos2, b: Pos2, r: f32, stroke: Stroke) {
    let rect = Rect::from_two_pos(a, b);
    painter.rect_stroke(
        rect,
        r,
        stroke,
        egui::epaint::StrokeKind::Middle,
    );
}

fn stroke_rrect_filled(a: Pos2, b: Pos2, r: f32) -> (Rect, f32) {
    (Rect::from_two_pos(a, b), r)
}

fn eye_almond(painter: &egui::Painter, p: impl Fn(f32, f32) -> Pos2, stroke: Stroke) {
    // Approximate the almond with two shallow quadratic-ish arcs via short
    // segments through (2,12)-(12,5)-(22,12) and the mirror.
    let top = [p(2.0, 12.0), p(7.0, 7.0), p(12.0, 5.5), p(17.0, 7.0), p(22.0, 12.0)];
    let bot = [p(2.0, 12.0), p(7.0, 17.0), p(12.0, 18.5), p(17.0, 17.0), p(22.0, 12.0)];
    for w in top.windows(2) {
        painter.line_segment([w[0], w[1]], stroke);
    }
    for w in bot.windows(2) {
        painter.line_segment([w[0], w[1]], stroke);
    }
}

fn ellipse_v(painter: &egui::Painter, c: Pos2, rx: f32, ry: f32, stroke: Stroke) {
    let n = 28;
    let mut prev = None;
    for i in 0..=n {
        let a = std::f32::consts::TAU * i as f32 / n as f32;
        let pt = Pos2::new(c.x + a.sin() * rx, c.y - a.cos() * ry);
        if let Some(pp) = prev {
            painter.line_segment([pp, pt], stroke);
        }
        prev = Some(pt);
    }
}
