//! Theme + fonts — ported from `alice-wallet/gui/src/ui/theme.rs` and EXTENDED
//! with the full token palette from the locked visual contract
//! (`docs/design/mockup.html` `:root`): the brand-orange ramp, the layered zinc
//! surfaces (so depth survives without blur), and the lane colours.
//!
//! Fonts: JetBrains Mono (all numerals), Inter (UI sans), NotoSansSC subset
//! (CJK fallback) — bundled in `assets/fonts/`, the same files the Wallet ships.
//! NO emoji is ever rendered; glyphs are monoline strokes drawn with epaint
//! (see [`crate::ui::icons`]).

use eframe::egui::{self, Color32, FontData, FontDefinitions, FontFamily, Stroke};
use std::sync::Arc;

/// The Alice Miner palette. Field names follow the mockup `:root` tokens so the
/// transcription is auditable token-for-token. The full token set is carried
/// intentionally (some are referenced only by later screens / M2 polish).
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub struct Theme {
    // Backgrounds / surfaces (opaque zinc — depth without blur).
    pub bg: Color32,        // --a-bg  #050505
    pub bg2: Color32,       // --a-bg-2 #0A0A0A
    pub surface: Color32,   // --a-surface  #161618 (card base)
    pub surface2: Color32,  // --a-surface-2 #1E1E22 (hover/nested)
    pub surface3: Color32,  // --a-surface-3 #242429 (top of an elevated card)
    pub well: Color32,      // --a-well #08080A (recessed wells: logs, inputs)
    pub elevate_top: Color32,    // top stop of --a-elevate gradient (#232327)
    pub elevate_bottom: Color32, // bottom stop of --a-elevate gradient (#0C0C0E)
    pub titlebar_top: Color32,   // titlebar gradient top  #101012
    pub titlebar_bottom: Color32,// titlebar gradient bottom #0A0A0C
    pub rail_top: Color32,       // rail gradient top  #0B0B0D
    pub rail_bottom: Color32,    // rail gradient bottom #08080A

    // Lines / borders.
    pub line: Color32,        // --a-line  rgba(63,63,70,.55)
    pub line_strong: Color32, // --a-line-strong rgba(82,82,91,.65)
    pub line_brand: Color32,  // --a-line-brand rgba(249,115,22,.32)
    pub hair_top: Color32,    // --a-hair-top rgba(255,255,255,.06)

    // Text.
    pub text: Color32,       // --a-text  #FAFAFA
    pub text2: Color32,      // --a-text-2 #A1A1AA
    pub text3: Color32,      // --a-text-3 #71717A
    pub text4: Color32,      // --a-text-4 #52525B
    pub text_brand: Color32, // --a-text-brand #FDBA74

    // Brand-orange ramp (the spine).
    pub brand300: Color32, // #FDBA74
    pub brand400: Color32, // #FB923C
    pub brand: Color32,    // #F97316 (brand-500)
    pub brand600: Color32, // #EA580C
    pub brand700: Color32, // #C2410C
    pub ink_on_brand: Color32, // text on a brand fill  #2A0E00

    // Status + lanes.
    pub live: Color32, // #22C55E
    pub warn: Color32, // #F59E0B
    pub off: Color32,  // #52525B
    pub err: Color32,  // #EF4444
    pub lane_xmr: Color32, // #FB923C
    pub lane_gpu: Color32, // #3B82F6
    pub lane_mac: Color32, // #22D3EE
}

pub const THEME: Theme = Theme {
    bg: Color32::from_rgb(0x05, 0x05, 0x05),
    bg2: Color32::from_rgb(0x0A, 0x0A, 0x0A),
    surface: Color32::from_rgb(0x16, 0x16, 0x18),
    surface2: Color32::from_rgb(0x1E, 0x1E, 0x22),
    surface3: Color32::from_rgb(0x24, 0x24, 0x29),
    well: Color32::from_rgb(0x08, 0x08, 0x0A),
    elevate_top: Color32::from_rgb(0x23, 0x23, 0x27),
    elevate_bottom: Color32::from_rgb(0x0C, 0x0C, 0x0E),
    titlebar_top: Color32::from_rgb(0x10, 0x10, 0x12),
    titlebar_bottom: Color32::from_rgb(0x0A, 0x0A, 0x0C),
    rail_top: Color32::from_rgb(0x0B, 0x0B, 0x0D),
    rail_bottom: Color32::from_rgb(0x08, 0x08, 0x0A),

    // The mockup lines are translucent over near-black; we bake them to opaque
    // equivalents (over #0A0A0A) so single-pixel borders read crisp.
    line: Color32::from_rgb(0x2C, 0x2C, 0x30),
    line_strong: Color32::from_rgb(0x3A, 0x3A, 0x40),
    line_brand: Color32::from_rgba_premultiplied(0x4F, 0x25, 0x09, 0x52),
    hair_top: Color32::from_rgba_premultiplied(0x0F, 0x0F, 0x0F, 0x0F),

    text: Color32::from_rgb(0xFA, 0xFA, 0xFA),
    text2: Color32::from_rgb(0xA1, 0xA1, 0xAA),
    text3: Color32::from_rgb(0x71, 0x71, 0x7A),
    text4: Color32::from_rgb(0x52, 0x52, 0x5B),
    text_brand: Color32::from_rgb(0xFD, 0xBA, 0x74),

    brand300: Color32::from_rgb(0xFD, 0xBA, 0x74),
    brand400: Color32::from_rgb(0xFB, 0x92, 0x3C),
    brand: Color32::from_rgb(0xF9, 0x73, 0x16),
    brand600: Color32::from_rgb(0xEA, 0x58, 0x0C),
    brand700: Color32::from_rgb(0xC2, 0x41, 0x0C),
    ink_on_brand: Color32::from_rgb(0x2A, 0x0E, 0x00),

    live: Color32::from_rgb(0x22, 0xC5, 0x5E),
    warn: Color32::from_rgb(0xF5, 0x9E, 0x0B),
    off: Color32::from_rgb(0x52, 0x52, 0x5B),
    err: Color32::from_rgb(0xEF, 0x44, 0x44),
    lane_xmr: Color32::from_rgb(0xFB, 0x92, 0x3C),
    lane_gpu: Color32::from_rgb(0x3B, 0x82, 0xF6),
    lane_mac: Color32::from_rgb(0x22, 0xD3, 0xEE),
};

/// Register the bundled fonts. JetBrains Mono leads the Monospace family (every
/// numeral is rendered mono per the contract); Inter leads Proportional; the
/// NotoSansSC subset is the CJK fallback in both families.
pub fn install_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();

    fonts.font_data.insert(
        "Inter".into(),
        Arc::new(FontData::from_static(include_bytes!(
            "../../assets/fonts/Inter-Regular.ttf"
        ))),
    );
    fonts.font_data.insert(
        "Inter-Bold".into(),
        Arc::new(FontData::from_static(include_bytes!(
            "../../assets/fonts/Inter-Bold.ttf"
        ))),
    );
    fonts.font_data.insert(
        "JBMono".into(),
        Arc::new(FontData::from_static(include_bytes!(
            "../../assets/fonts/JetBrainsMono-Regular.ttf"
        ))),
    );
    fonts.font_data.insert(
        "JBMono-Bold".into(),
        Arc::new(FontData::from_static(include_bytes!(
            "../../assets/fonts/JetBrainsMono-Bold.ttf"
        ))),
    );
    fonts.font_data.insert(
        "NotoSC".into(),
        Arc::new(FontData::from_static(include_bytes!(
            "../../assets/fonts/NotoSansSC-Subset.ttf"
        ))),
    );

    let prop = fonts.families.entry(FontFamily::Proportional).or_default();
    prop.insert(0, "Inter".into());
    prop.insert(1, "Inter-Bold".into());
    prop.insert(2, "NotoSC".into());

    let mono = fonts.families.entry(FontFamily::Monospace).or_default();
    mono.insert(0, "JBMono".into());
    mono.insert(1, "JBMono-Bold".into());
    mono.insert(2, "NotoSC".into());

    ctx.set_fonts(fonts);
}

/// Apply the global egui style (dark, brand-orange selection/links, rounded
/// widgets). Mirrors the Wallet's `apply_style`, retuned to the Miner palette.
pub fn apply_style(ctx: &egui::Context) {
    let t = THEME;
    let mut style = (*ctx.global_style()).clone();

    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.button_padding = egui::vec2(14.0, 9.0);
    style.spacing.interact_size.y = 34.0;

    style.visuals.override_text_color = Some(t.text);
    style.visuals.panel_fill = t.bg;
    style.visuals.window_fill = t.surface;
    style.visuals.extreme_bg_color = t.well;
    style.visuals.window_stroke = Stroke::new(1.0, t.line);
    style.visuals.window_shadow = egui::epaint::Shadow {
        offset: [0, 18],
        blur: 52,
        spread: 0,
        color: Color32::from_rgba_premultiplied(0, 0, 0, 160),
    };
    style.visuals.popup_shadow = egui::epaint::Shadow {
        offset: [0, 8],
        blur: 24,
        spread: 0,
        color: Color32::from_rgba_premultiplied(0, 0, 0, 120),
    };
    style.visuals.selection.bg_fill = Color32::from_rgba_unmultiplied(249, 115, 22, 64);
    style.visuals.selection.stroke = Stroke::new(1.0, t.brand);
    style.visuals.hyperlink_color = t.brand300;

    let w = &mut style.visuals.widgets;
    for ws in [&mut w.noninteractive, &mut w.inactive] {
        ws.bg_fill = t.surface2;
        ws.weak_bg_fill = t.surface2;
        ws.fg_stroke = Stroke::new(1.0, t.text);
        ws.bg_stroke = Stroke::new(1.0, t.line);
        ws.corner_radius = 10.into();
    }
    w.noninteractive.bg_fill = t.surface;
    w.noninteractive.weak_bg_fill = t.surface;

    w.hovered.bg_fill = t.surface2;
    w.hovered.weak_bg_fill = t.surface2;
    w.hovered.fg_stroke = Stroke::new(1.0, t.text);
    w.hovered.bg_stroke = Stroke::new(1.0, t.line_strong);
    w.hovered.corner_radius = 10.into();

    w.active.bg_fill = t.surface2;
    w.active.weak_bg_fill = t.surface2;
    w.active.fg_stroke = Stroke::new(1.0, t.text);
    w.active.bg_stroke = Stroke::new(1.0, t.brand);
    w.active.corner_radius = 10.into();

    w.open.bg_fill = t.surface2;
    w.open.weak_bg_fill = t.surface2;
    w.open.fg_stroke = Stroke::new(1.0, t.text);
    w.open.bg_stroke = Stroke::new(1.0, t.brand);
    w.open.corner_radius = 10.into();

    ctx.set_global_style(style);
}

/// Paint the page atmosphere: the near-black base + a faint warm aura at the top
/// and a cool aura bottom-right, transcribing the mockup `body` radial stack
/// (EGUI-FLAG[atmosphere-OK]). The auras are smooth radial [`egui::Mesh`] fans
/// (see [`radial_glow`]) so there is no concentric banding.
pub fn paint_backdrop(painter: &egui::Painter, rect: egui::Rect) {
    let t = THEME;
    painter.rect_filled(rect, 0.0, t.bg);
    // Warm aura, top-centre.
    radial_glow(
        painter,
        egui::pos2(rect.center().x, rect.top() - rect.height() * 0.06),
        rect.width() * 0.55,
        Color32::from_rgb(0xF9, 0x73, 0x16),
        18,
    );
    // Cool aura, bottom-right.
    radial_glow(
        painter,
        egui::pos2(rect.right(), rect.bottom() + rect.height() * 0.06),
        rect.width() * 0.45,
        Color32::from_rgb(0x3B, 0x82, 0xF6),
        12,
    );
}

/// A smooth additive radial glow drawn as a triangle-fan [`egui::Mesh`]: ONE
/// center vertex at full `color`·`peak_alpha`, and a rim of vertices at alpha 0.
/// The GPU interpolates a clean radial gradient, so there is NO concentric
/// banding (the documented egui way; mockup EGUI-FLAG[atmosphere-OK] "radial
/// Mesh fill"). Replaces the old stacked-circles approximation which banded.
pub fn radial_glow(
    painter: &egui::Painter,
    center: egui::Pos2,
    radius: f32,
    color: Color32,
    peak_alpha: u8,
) {
    if peak_alpha == 0 || radius <= 0.0 {
        return;
    }
    const RIM: usize = 56;
    let mut mesh = egui::Mesh::default();
    // Center vertex: full warm colour at the peak alpha.
    let core = Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), peak_alpha);
    mesh.vertices.push(egui::epaint::Vertex {
        pos: center,
        uv: egui::epaint::WHITE_UV,
        color: core,
    });
    // Rim vertices: same hue, alpha 0 → premultiplied (0,0,0,0), a clean fade to
    // true transparency at the edge (no dark fringe).
    let transparent = Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 0);
    for i in 0..=RIM {
        let a = (i as f32 / RIM as f32) * std::f32::consts::TAU;
        mesh.vertices.push(egui::epaint::Vertex {
            pos: egui::pos2(center.x + a.cos() * radius, center.y + a.sin() * radius),
            uv: egui::epaint::WHITE_UV,
            color: transparent,
        });
    }
    for i in 1..=RIM as u32 {
        mesh.add_triangle(0, i, i + 1);
    }
    painter.add(egui::Shape::mesh(mesh));
}
