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
mod platform;
mod shot;
mod ui;
mod update;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use eframe::egui::IconData;
use eframe::glow::HasContext;

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
    // Shot mode frames to the real default size so captures reflect what the
    // owner sees on first run; normal runs use the same default. (Only the inner
    // size changes — the custom titlebar + rail still render so the screenshot
    // reflects the real chrome.)
    let inner_size = if std::env::var_os("ALICE_MINER_SHOT_DIR").is_some() {
        shot::ShotRunner::window_size()
    } else {
        // Comfortably above the mockup's 1040×720 so the full hero card (orb +
        // readout + identity + status line + footer) — in EVERY Home state incl.
        // the tallest (error, which stacks "Start again" + the reason line + the
        // honest footer) — and the 4-up dashboard grid are visible without
        // scrolling on first run; still resizable down to `min` below, where the
        // scroll areas guarantee nothing is clipped.
        [1120.0, 800.0]
    };
    let mut viewport = eframe::egui::ViewportBuilder::default()
        .with_inner_size(inner_size)
        // Sane floor so the hero never clips; below this the screen bodies scroll.
        .with_min_inner_size([960.0, 680.0])
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

    // Pick the rendering backend BEFORE building the window. `glow` (OpenGL) stays
    // the default for local sessions; a genuine Windows RDP / Terminal Services
    // session auto-switches to `wgpu` (DX12/DX11 + WARP), which survives remote
    // desktops where OpenGL paints a solid-white window. Mirror tools (DeskIn /
    // AnyDesk) aren't flagged as remote by Windows, so those users set
    // `ALICE_GUI_RENDERER=wgpu` manually — and the live-GL-renderer probe below is
    // the runtime backstop that still catches them. `ALICE_GUI_RENDERER=glow|wgpu`
    // overrides. See `platform.rs`.
    let decision = platform::choose_renderer();
    platform::log_line(&format!(
        "launch os={} remote_session={} renderer={} :: {}",
        std::env::consts::OS,
        decision.remote,
        decision.name,
        decision.reason,
    ));

    let renderer_name = decision.name;
    let options = eframe::NativeOptions {
        viewport,
        renderer: decision.renderer,
        ..Default::default()
    };

    // Runtime backstop for the mirror-tool case (DeskIn/AnyDesk), which the
    // remote-session check can't see: if glow comes up on a *software* GL context
    // (the real white-screen signature), flag it here and surface wgpu guidance
    // after the window closes. Set only from the glow path; on hardware GPUs it
    // never fires, so local users are unaffected.
    let software_gl = Arc::new(AtomicBool::new(false));
    let software_gl_seen = Arc::new(std::sync::Mutex::new(String::new()));
    let software_gl_cl = Arc::clone(&software_gl);
    let software_gl_seen_cl = Arc::clone(&software_gl_seen);

    let result = eframe::run_native(
        "Alice Miner",
        options,
        Box::new(move |cc| {
            egui_extras::install_image_loaders(&cc.egui_ctx);
            ui::theme::install_fonts(&cc.egui_ctx);
            // When the glow backend is active, `cc.gl` is `Some`; read GL_RENDERER
            // and record it in the startup log so a white-screen bug report carries
            // the smoking gun (e.g. `gl_renderer="GDI Generic"`). If it's a software
            // rasterizer, mark it so we can advise wgpu once the window closes.
            if let Some(gl) = cc.gl.as_ref() {
                // SAFETY: read-only glGetString(GL_RENDERER) on the live context;
                // no pointers cross the FFI boundary, returns an owned String.
                let renderer_str = unsafe { gl.get_parameter_string(eframe::glow::RENDERER) };
                platform::log_line(&format!("glow gl_renderer={renderer_str:?}"));
                if platform::is_software_gl_renderer(&renderer_str) {
                    platform::log_line(&format!(
                        "WARN software OpenGL renderer ({renderer_str:?}) — window can blank \
                         over remote desktop; set ALICE_GUI_RENDERER=wgpu"
                    ));
                    if let Ok(mut slot) = software_gl_seen_cl.lock() {
                        *slot = renderer_str;
                    }
                    software_gl_cl.store(true, Ordering::SeqCst);
                }
            }
            match app::MinerApp::new() {
                Ok(app) => Ok(Box::new(app)),
                Err(e) => {
                    // Surface a fatal engine-spawn failure as a minimal error app
                    // rather than panicking the process.
                    Ok(Box::new(FatalApp { message: e }))
                }
            }
        }),
    );

    // A hard renderer/window init failure returns `Err` here. A white screen is
    // different: it's a *successful* run (`Ok`) that simply never paints. True
    // RDP/TS sessions are pre-empted to wgpu above, but mirror tools (DeskIn/…)
    // aren't flagged as remote — so on the glow path we detected a software GL
    // context inside the closure and now surface wgpu guidance on the `Ok` path
    // too. Either way, don't exit silently.
    match &result {
        Ok(()) => {
            platform::log_line("exited cleanly");
            if software_gl.load(Ordering::SeqCst) {
                let renderer_str = software_gl_seen
                    .lock()
                    .map(|s| s.clone())
                    .unwrap_or_default();
                platform::log_line("software-GL guidance dialog shown");
                platform::show_error_dialog(
                    "Alice Miner \u{2014} graphics notice",
                    &platform::software_gl_message(&renderer_str),
                );
            }
        }
        Err(e) => {
            platform::log_line(&format!("run_native failed (renderer={renderer_name}): {e}"));
            platform::show_error_dialog(
                "Alice Miner \u{2014} display error",
                &platform::init_failure_message(renderer_name),
            );
        }
    }

    result
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
