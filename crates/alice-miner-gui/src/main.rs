//! Alice Miner — GUI binary (eframe/egui).
//!
//! M0: a trivial empty window titled "Alice Miner" that validates the egui
//! stack decision (PLAN §2.1) and the eframe feature set matches the Wallet's.
//! The real UI (the "Alice Core" hero, conic hashrate gauge, onboarding, the
//! Dashboard) lands from M2 onward.

use eframe::egui;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Alice Miner")
            .with_inner_size([1040.0, 720.0])
            .with_min_inner_size([920.0, 640.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Alice Miner",
        options,
        Box::new(|_cc| Ok(Box::<MinerApp>::default())),
    )
}

#[derive(Default)]
struct MinerApp;

impl eframe::App for MinerApp {
    // eframe 0.34's `App::ui` is the required entry point (`update` is
    // deprecated). The given `Ui` has no margin/background, so wrap it in a
    // CentralPanel to get the panel surface.
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show_inside(ui, |ui| {
            ui.centered_and_justified(|ui| {
                ui.heading("Alice Miner");
            });
        });
    }
}
