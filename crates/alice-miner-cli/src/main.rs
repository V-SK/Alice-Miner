//! Alice Miner — headless CLI binary (clap).
//!
//! Drives the same `alice-miner-core` engine as the GUI, with NO egui/eframe in
//! its dependency tree (PLAN §2.2 / C2; verified via `cargo tree`). M0 ships a
//! single placeholder subcommand to validate the clap wiring; full parity
//! (`detect | identity | start | status | stop`) is M6.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "alice-miner-cli", about = "Alice Miner — headless client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Placeholder. Real subcommands (detect / identity / start / status /
    /// stop) arrive in M6, all driving `alice-miner-core`.
    Detect,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Detect => {
            // M0 stub: the engine is a placeholder until M1+.
            let _engine = alice_miner_core::Engine;
            println!("alice-miner-cli: detect not yet implemented (M0 skeleton)");
        }
    }
}
