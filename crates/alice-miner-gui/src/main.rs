//! Alice Miner — GUI binary (eframe/egui).
//!
//! M1b: the real desktop app to the LOCKED visual contract
//! (`docs/design/mockup.html`): a frameless dark window with a custom titlebar
//! (drag region + global mining-status pill + lang chip, macOS traffic-lights
//! preserved), the left icon rail (Home / Dashboard / Settings), the **Alice
//! Core hero** (dark glassy orb + conic hashrate gauge + glowing Alice mark),
//! onboarding (create / import / paste), Home (one-click Start/Stop), and a
//! minimal Dashboard — all driven by the UI-agnostic `alice-miner-core` engine
//! (the SAME engine the CLI drives, so the two can't drift — PLAN §2.2).
//!
//! Frameless-window + macOS clearance approach ported from
//! `alice-wallet/gui/src/main.rs` (~L52).

mod app;
mod shot;
mod ui;

use eframe::egui::IconData;

/// Rasterise the bundled Alice mark SVG into the OS window/dock icon (the exact
/// `load_icon` the Wallet ships).
fn load_icon() -> Option<IconData> {
    use usvg::TreeParsing;
    let svg_data = include_bytes!("../assets/brand/alice-logo.svg");
    let opt = usvg::Options::default();
    let tree = usvg::Tree::from_data(svg_data, &opt).ok()?;

    let (width, height) = (64u32, 64u32);
    let mut pixmap = tiny_skia::Pixmap::new(width, height)?;
    let size = tree.size;
    let scale = (width as f32 / size.width()).min(height as f32 / size.height());
    let transform = tiny_skia::Transform::from_scale(scale, scale);
    resvg::Tree::from_usvg(&tree).render(transform, &mut pixmap.as_mut());

    Some(IconData {
        rgba: pixmap.data().to_vec(),
        width,
        height,
    })
}

fn main() -> eframe::Result<()> {
    // Shot mode frames to the mockup size (~1040×720) so captures match; normal
    // runs keep the default size. (Only the inner size changes — the custom
    // titlebar + rail still render so the screenshot reflects the real chrome.)
    let inner_size = if std::env::var_os("ALICE_MINER_SHOT_DIR").is_some() {
        shot::ShotRunner::window_size()
    } else {
        // Tall enough that the full hero card (orb + readout + identity + footer)
        // is visible without scrolling on first run; still resizable smaller.
        [1040.0, 800.0]
    };
    let mut viewport = eframe::egui::ViewportBuilder::default()
        .with_inner_size(inner_size)
        .with_min_inner_size([920.0, 660.0])
        .with_title("Alice Miner")
        // Draw our own dark header flush to the window top instead of a
        // system-coloured title bar clashing with the dark theme. The bar stays
        // present (OS-draggable + traffic lights work), just transparent with the
        // title text hidden. macOS-only effect; no-op elsewhere.
        .with_fullsize_content_view(true)
        .with_title_shown(false)
        .with_titlebar_buttons_shown(true);

    if let Some(icon) = load_icon() {
        viewport = viewport.with_icon(icon);
    }

    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "Alice Miner",
        options,
        Box::new(|cc| {
            egui_extras::install_image_loaders(&cc.egui_ctx);
            ui::theme::install_fonts(&cc.egui_ctx);
            match app::MinerApp::new() {
                Ok(app) => Ok(Box::new(app)),
                Err(e) => {
                    // Surface a fatal engine-spawn failure as a minimal error app
                    // rather than panicking the process.
                    Ok(Box::new(FatalApp { message: e }))
                }
            }
        }),
    )
}

/// A tiny fallback shown only if the engine fails to spawn at launch.
struct FatalApp {
    message: String,
}

impl eframe::App for FatalApp {
    fn ui(&mut self, ui: &mut eframe::egui::Ui, _f: &mut eframe::Frame) {
        use eframe::egui::{self, RichText};
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(ui::theme::THEME.bg))
            .show_inside(ui, |ui| {
                ui.centered_and_justified(|ui| {
                    ui.label(
                        RichText::new(format!("Failed to start engine:\n{}", self.message))
                            .size(14.0)
                            .color(ui::theme::THEME.err),
                    );
                });
            });
    }
}
