//! The **Alice Core hero** — the centerpiece (the screen the owner judges).
//!
//! Transcribes the locked contract's `.hero-wrap` (mockup `02a`/`02b`) into
//! epaint. egui has no blur, no conic-gradient, no radial Rect fill, so each of
//! those is rebuilt the way the mockup's EGUI-FLAG notes prescribe — and ALL of
//! them share ONE exact `center` and ONE base radius `r`, so the glow, the orb
//! body, the gauge ring and the Alice mark are strictly concentric:
//!
//!   * **Atmospheric aura** (`.hero-aura`) → a smooth additive radial glow drawn
//!     as a triangle-fan [`egui::Mesh`] (center vertex at full warm-orange alpha,
//!     rim vertices at alpha 0 → the GPU interpolates a clean gradient, NO
//!     concentric banding). Its center alpha BREATHES while mining (time sine,
//!     respecting `reduce_motion`).
//!   * **Conic gauge ring** (`.ring`, EGUI-FLAG[conic-OK]) → a faint full-circle
//!     track + a thick stroked arc sweeping `p·360°` from top (−90°), drawn as a
//!     polyline of short segments at a FIXED small offset just outside the orb
//!     (`ring_r = r·RING_OFFSET`), all centred on the same `center`.
//!   * **Dark glassy orb** (`.start-btn`, EGUI-FLAG[radial-fill]) → a triangle-fan
//!     [`egui::Mesh`] whose rim vertices lie exactly on the circle of radius `r`
//!     around `center` (a perfectly circular silhouette) while the apex colour is
//!     biased toward a lit top-centre — so the highlight reads off-axis WITHOUT
//!     moving the silhouette. Plus a top inner sheen arc + a bottom inner shadow
//!     arc + a layered soft drop-shadow, all on the same `center`.
//!   * **Alice mark glowing inside** → the bundled `alice-logo.png` painted as a
//!     texture tinted orange (#FB923C idle ember → #FDBA74 mining), CENTERED in
//!     the orb, with a smooth Mesh glow behind it that brightens/breathes while
//!     mining.
//!
//! The whole hero is one clickable region (Start when idle, Stop when running).

use eframe::egui::{self, Color32, Mesh, Pos2, Rect, Sense, Shape, Stroke, Vec2};

use super::theme::{radial_glow as smooth_radial, THEME};

// ── Concentric radii, all expressed as fractions of the orb radius `r` ─────────
// (so every element scales together and shares one center).
/// The atmospheric aura reaches this multiple of `r` (mockup `.hero-aura`
/// `inset:-30px` on a 170px orb → ~1.35·r; a touch more for the soft tail). The
/// allocated square's `pad` is sized so this never hard-clips at the rect edge.
const AURA_RADIUS: f32 = 1.42;
/// The gauge ring sits at this multiple of `r` — a fixed small offset just
/// outside the orb (mockup `.ring` `inset:-8px` on r=85 → 93/85 ≈ 1.094).
const RING_OFFSET: f32 = 1.094;
/// Ring stroke width as a fraction of `r`.
const RING_WIDTH: f32 = 0.082;
/// The Alice mark spans this fraction of the orb DIAMETER (mockup 88/170 ≈ 0.52).
const MARK_FRAC: f32 = 0.52;
/// The mark's inner glow reaches this fraction of `r`.
const MARK_GLOW_RADIUS: f32 = 0.92;

/// Visual mode of the hero (drives glow/ring/colour), derived from the engine
/// snapshot by the caller.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HeroMode {
    /// Not mining — dim ember mark + START readout, ring hidden.
    Idle,
    /// Spawn requested / connecting — amber, indeterminate sweep.
    Connecting,
    /// Mining — brighter mark, breathing glow, ring fills to `p`.
    Mining,
    /// The lane stopped / failed — a CALM muted-orange core (no scary red dump),
    /// glow off, a thin red rim, "Start again" readout. NOT animated.
    Error,
    /// Brief tear-down transient as the child is killed — the mark dims, a faint
    /// amber settling track, no breathing.
    Stopping,
}

impl HeroMode {
    /// Whether this mode runs a continuous animation (breathing / sweep). Idle,
    /// Error and (under reduced motion) all modes are static.
    fn animates(self) -> bool {
        matches!(self, HeroMode::Connecting | HeroMode::Mining | HeroMode::Stopping)
    }
}

/// Draw the hero. `diameter` is the orb diameter; `gauge` is 0..1 (the ring fill,
/// e.g. hashrate / a soft ceiling). `mark_tex` is the loaded Alice-mark texture.
/// Returns the click response of the whole orb. Repaints itself while animated.
pub fn alice_core(
    ui: &mut egui::Ui,
    diameter: f32,
    mode: HeroMode,
    gauge: f32,
    motion: bool,
    mark_tex: &egui::TextureHandle,
) -> egui::Response {
    let t = THEME;
    // Reserve a SQUARE a little larger than the orb so the ring + aura have room,
    // then derive ONE center + ONE radius `r` from it. Everything below is drawn
    // from this exact center with radii as fractions of `r` → strictly concentric.
    // `pad` clears the aura halo (AURA_RADIUS·r) within the allocated square:
    // half-square = r + pad ≥ AURA_RADIUS·r ⇒ pad ≥ (AURA_RADIUS−1)·r = 0.21·r.
    let pad = diameter * 0.22;
    let total = diameter + pad * 2.0;
    let (alloc, resp) = ui.allocate_exact_size(Vec2::splat(total), Sense::click());
    // Force a centered square (guards against any non-square allocation drift).
    let side = alloc.width().min(alloc.height());
    let rect = Rect::from_center_size(alloc.center(), Vec2::splat(side));
    let painter = ui.painter_at(rect);
    let center = rect.center();
    let r = diameter / 2.0;

    // Animation clock + a breathing factor (0..1) used while mining/connecting.
    // Under reduced motion `breathe` is pinned to its lit midpoint (0.5) so the
    // colour/state semantics survive without any pulsing, and we DON'T request
    // continuous repaints from the hero.
    let time = ui.input(|i| i.time) as f32;
    let breathe = if motion {
        0.5 + 0.5 * (time * 1.85).sin() // ~3.4s period like the CSS
    } else {
        0.5
    };
    let animated = motion && mode.animates();
    if animated {
        ui.ctx().request_repaint();
    }

    // ---- 1. Atmospheric aura behind everything (smooth Mesh, breathing) ------
    let (aura_color, aura_peak) = match mode {
        HeroMode::Idle => (t.brand, 30u8),
        HeroMode::Connecting => (t.warn, 46u8),
        HeroMode::Mining => (t.brand, (52.0 + 40.0 * breathe) as u8),
        // Error: a faint, cool ember — present but clearly "off" (calm, not red-hot).
        HeroMode::Error => (t.brand700, 18u8),
        // Stopping: a soft amber settling glow.
        HeroMode::Stopping => (t.warn, 28u8),
    };
    smooth_radial(&painter, center, r * AURA_RADIUS, aura_color, aura_peak);

    // ---- 2. Layered soft drop-shadow under the orb (concentric on `center`) --
    for i in 0..7 {
        let f = i as f32 / 7.0;
        let rr = r + r * (0.06 + f * 0.10);
        let a = (60.0 * (1.0 - f)) as u8;
        painter.circle_filled(
            center + Vec2::new(0.0, r * (0.05 + f * 0.04)),
            rr,
            Color32::from_rgba_unmultiplied(0, 0, 0, a),
        );
    }

    // ---- 3. Conic gauge: faint full track + swept arc (fixed offset outside) -
    let ring_r = r * RING_OFFSET;
    let ring_w = r * RING_WIDTH;
    // The groove track shows whenever the ring is meaningful (mining, connecting,
    // stopping) — NOT idle (clean) and NOT error (we draw a calm rim instead).
    let show_track = matches!(
        mode,
        HeroMode::Mining | HeroMode::Connecting | HeroMode::Stopping
    );
    if show_track {
        // Faint full-circle groove track (centred on the same `center`).
        painter.circle_stroke(
            center,
            ring_r,
            Stroke::new(ring_w, Color32::from_rgba_unmultiplied(255, 255, 255, 10)),
        );
        painter.circle_stroke(
            center,
            ring_r,
            Stroke::new(1.0, Color32::from_rgba_unmultiplied(0, 0, 0, 110)),
        );
    }
    match mode {
        HeroMode::Mining => {
            // Soft under-glow then the crisp arc, from top (−90°) sweeping
            // clockwise p·360°. Colour ramps brand-300 → brand-600 along it.
            draw_gauge_arc(&painter, center, ring_r, ring_w + 4.0, gauge.clamp(0.0, 1.0), 70, true);
            draw_gauge_arc(&painter, center, ring_r, ring_w, gauge.clamp(0.0, 1.0), 255, false);
        }
        HeroMode::Connecting => {
            // Indeterminate: a short bright comet. Spins while motion is on; under
            // reduced motion it rests as a static amber arc at the top.
            let head = if motion { (time * 1.1).rem_euclid(1.0) } else { 0.12 };
            draw_gauge_segment(&painter, center, ring_r, ring_w, head - 0.16, head, t.warn);
        }
        HeroMode::Stopping => {
            // A dim amber arc that recedes (a calm "winding down" cue). Static
            // under reduced motion.
            let p = if motion {
                0.5 - 0.5 * (time * 1.1).rem_euclid(1.0) // shrinks 0.5→0
            } else {
                0.25
            };
            draw_gauge_segment(&painter, center, ring_r, ring_w, 0.0, p.max(0.02), t.warn);
        }
        HeroMode::Error => {
            // A thin, calm red rim just outside the orb — signals "stopped"
            // without a loud fill. No track, no sweep.
            painter.circle_stroke(
                center,
                ring_r,
                Stroke::new(2.0, Color32::from_rgba_unmultiplied(239, 68, 68, 120)),
            );
        }
        HeroMode::Idle => {}
    }

    // ---- 4. The dark glassy orb (mesh radial + sheen + inner shadow) ---------
    paint_orb(&painter, center, r, &resp);

    // ---- 5. The Alice mark glowing inside (centered) -------------------------
    let (glow_alpha, tint) = match mode {
        HeroMode::Idle => {
            let hover = if resp.hovered() { 1.3 } else { 1.0 };
            ((46.0 * hover) as u8, t.brand400) // dim ember
        }
        HeroMode::Connecting => (40, t.text2),
        HeroMode::Mining => ((90.0 + 90.0 * breathe) as u8, t.brand300), // bright + breathing
        // Error: a muted, cool ember — the mark is clearly "asleep" but still the
        // brand (a calm "off", never an angry red glyph).
        HeroMode::Error => (22, t.text3),
        // Stopping: the mark fades toward the idle ember.
        HeroMode::Stopping => (32, t.brand400),
    };
    // Glow: a smooth Mesh radial behind the mark (skip on the glow-less modes
    // where the mark should read as dimmed/asleep). Concentric on `center`.
    if !matches!(mode, HeroMode::Connecting | HeroMode::Error) {
        smooth_radial(&painter, center, r * MARK_GLOW_RADIUS, t.brand, glow_alpha);
    }
    // The mark itself, tinted, centered in the orb (~52% of the orb diameter).
    let mark_sz = diameter * MARK_FRAC;
    let mark_rect = Rect::from_center_size(center, Vec2::splat(mark_sz));
    let uv = Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0));
    painter.image(mark_tex.id(), mark_rect, uv, tint);

    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Paint the dark glassy orb as a triangle-fan [`Mesh`]: the rim vertices lie
/// exactly on the circle of radius `r` around `center` (a perfectly circular,
/// concentric silhouette), while the apex colour is biased toward a lit
/// top-centre so the highlight reads off-axis WITHOUT moving the silhouette.
/// Then a faint warm inner rim, a crisp outer hairline, a light top inner sheen,
/// and a dark bottom inner shadow — all on the same `center`.
/// EGUI-FLAG[radial-fill-OK].
fn paint_orb(painter: &egui::Painter, center: Pos2, r: f32, resp: &egui::Response) {
    let lit = Color32::from_rgb(0x20, 0x20, 0x24); // lit top-centre
    let mid = Color32::from_rgb(0x16, 0x16, 0x18);
    let edge = Color32::from_rgb(0x09, 0x09, 0x0A); // near-black rim
    // The highlight sits at ~14% from the top of the orb (mockup `at 50% 14%`),
    // expressed as an offset from the (true) center so the fan apex is lit there.
    let hi = center + Vec2::new(0.0, -r * 0.30);

    // Triangle fan: apex at the lit highlight point, rim on the exact circle.
    // Each rim vertex's colour is `edge`, blended slightly toward `mid` on the
    // top half so the body reads as a smooth dark sphere. The apex is `lit`.
    let n = 96usize;
    let mut mesh = Mesh::default();
    mesh.vertices.push(epaint_vertex(hi, lit));
    for i in 0..=n {
        let a = (i as f32 / n as f32) * std::f32::consts::TAU - std::f32::consts::FRAC_PI_2;
        let p = Pos2::new(center.x + a.cos() * r, center.y + a.sin() * r);
        // Slightly lighter toward the top of the rim (a, near −90°), darker at
        // the bottom — a gentle vertical shade on top of the radial falloff.
        let top = (0.5 - 0.5 * a.sin()).clamp(0.0, 1.0); // 1 at top, 0 at bottom
        let rim = lerp_color(edge, mid, top * 0.5);
        mesh.vertices.push(epaint_vertex(p, rim));
    }
    for i in 1..=n as u32 {
        mesh.add_triangle(0, i, i + 1);
    }
    painter.add(Shape::mesh(mesh));

    // Faint warm inner rim (brand, very low alpha).
    painter.circle_stroke(
        center,
        r - 1.0,
        Stroke::new(1.5, Color32::from_rgba_unmultiplied(249, 115, 22, if resp.hovered() { 64 } else { 30 })),
    );
    // Crisp outer hairline (the exact silhouette).
    painter.circle_stroke(center, r, Stroke::new(1.0, Color32::from_rgba_unmultiplied(0, 0, 0, 150)));
    // Top inner sheen (a bright short arc near the top).
    draw_arc(
        painter,
        center,
        r - 2.5,
        -0.62,
        -0.38,
        Stroke::new(2.0, Color32::from_rgba_unmultiplied(255, 255, 255, if resp.hovered() { 30 } else { 20 })),
    );
    // Bottom inner shadow (a dark short arc near the bottom).
    draw_arc(
        painter,
        center,
        r - 3.0,
        0.30,
        0.70,
        Stroke::new(6.0, Color32::from_rgba_unmultiplied(0, 0, 0, 120)),
    );
}

/// Build a solid-colour epaint vertex (white UV → drawn untextured).
fn epaint_vertex(pos: Pos2, color: Color32) -> egui::epaint::Vertex {
    egui::epaint::Vertex {
        pos,
        uv: egui::epaint::WHITE_UV,
        color,
    }
}

/// Draw the filled-progress gauge arc from top (−90°) clockwise for `p` of the
/// circle, as a polyline of short segments. When `glow` is set it is drawn wide
/// + translucent (an under-glow); otherwise crisp with a brand-ramp colour.
fn draw_gauge_arc(
    painter: &egui::Painter,
    center: Pos2,
    radius: f32,
    width: f32,
    p: f32,
    alpha: u8,
    glow: bool,
) {
    if p <= 0.0 {
        return;
    }
    let t = THEME;
    let start = -std::f32::consts::FRAC_PI_2; // top
    let sweep = std::f32::consts::TAU * p;
    let segs = (96.0 * p).ceil().max(2.0) as usize;
    let mut prev: Option<Pos2> = None;
    for i in 0..=segs {
        let f = i as f32 / segs as f32;
        let a = start + sweep * f;
        let pt = Pos2::new(center.x + a.cos() * radius, center.y + a.sin() * radius);
        if let Some(pp) = prev {
            // Colour ramps brand-300 → brand-500 → brand-600 along the sweep.
            let col = if glow {
                Color32::from_rgba_unmultiplied(249, 115, 22, alpha.min(70))
            } else {
                let c = if f < 0.55 {
                    lerp_color(t.brand300, t.brand, f / 0.55)
                } else {
                    lerp_color(t.brand, t.brand600, (f - 0.55) / 0.45)
                };
                Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), alpha)
            };
            painter.line_segment([pp, pt], Stroke::new(width, col));
        }
        prev = Some(pt);
    }
    // Round the leading cap (on the same circle → concentric).
    if !glow {
        let a = start + sweep;
        let cap = Pos2::new(center.x + a.cos() * radius, center.y + a.sin() * radius);
        painter.circle_filled(cap, width * 0.5, t.brand300);
    }
}

/// Draw a single coloured segment of the ring between two fractions (used for
/// the connecting comet). Fractions are 0..1 around the circle from the top.
fn draw_gauge_segment(
    painter: &egui::Painter,
    center: Pos2,
    radius: f32,
    width: f32,
    f0: f32,
    f1: f32,
    color: Color32,
) {
    let start = -std::f32::consts::FRAC_PI_2;
    let n = 24;
    let mut prev: Option<Pos2> = None;
    for i in 0..=n {
        let f = f0 + (f1 - f0) * (i as f32 / n as f32);
        let a = start + std::f32::consts::TAU * f;
        let pt = Pos2::new(center.x + a.cos() * radius, center.y + a.sin() * radius);
        if let Some(pp) = prev {
            let frac = i as f32 / n as f32; // fade the tail
            let col = Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), (frac * 230.0) as u8);
            painter.line_segment([pp, pt], Stroke::new(width, col));
        }
        prev = Some(pt);
    }
}

/// Generic arc helper (angles in turns·2π, i.e. radians). Used for the orb sheen.
fn draw_arc(painter: &egui::Painter, center: Pos2, radius: f32, a0: f32, a1: f32, stroke: Stroke) {
    let n = 20;
    let mut prev: Option<Pos2> = None;
    for i in 0..=n {
        let a = (a0 + (a1 - a0) * (i as f32 / n as f32)) * std::f32::consts::TAU;
        let pt = Pos2::new(center.x + a.cos() * radius, center.y + a.sin() * radius);
        if let Some(pp) = prev {
            painter.line_segment([pp, pt], stroke);
        }
        prev = Some(pt);
    }
}

fn lerp_color(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let l = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    Color32::from_rgb(l(a.r(), b.r()), l(a.g(), b.g()), l(a.b(), b.b()))
}
