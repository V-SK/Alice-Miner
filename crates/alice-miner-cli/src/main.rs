//! Alice Miner — headless CLI binary (clap).
//!
//! Drives the same `alice-miner-core` engine as the GUI, with NO egui/eframe in
//! its dependency tree (PLAN §2.2 / C2; verify via `cargo tree`). M1a wires the
//! real subcommands `detect | identity | start`; full parity (`status | stop` as
//! peers, `--dual`, `--lane gpu|auto`) is M6.
//!
//! This is the M1 test harness: `start --lane xmr` drives the engine end-to-end
//! to `hk.aliceprotocol.org:3333` with ADDRESS-ONLY login, streams live
//! [`Snapshot`]s to stdout, and on Ctrl-C issues `Stop` (SIGTERM→SIGKILL on the
//! owned child) before exiting.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};

use alice_miner_core::engine::{Command as EngineCommand, Event, IdentitySpec};
use alice_miner_core::{EngineHandle, Lane};

#[derive(Parser)]
#[command(name = "alice-miner-cli", about = "Alice Miner — headless client (credit-only)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Probe the device and print its profile.
    Detect,
    /// Create, import, or paste the Alice reward identity.
    Identity(IdentityArgs),
    /// Start mining to the user's own Alice address and stream live stats.
    Start(StartArgs),
}

#[derive(clap::Args)]
struct IdentityArgs {
    /// Create a fresh 24-word identity (prints the mnemonic — BACK IT UP).
    #[arg(long, conflicts_with_all = ["import", "paste"])]
    create: bool,
    /// Import from a 24-word mnemonic (quote it).
    #[arg(long, value_name = "MNEMONIC", conflicts_with_all = ["create", "paste"])]
    import: Option<String>,
    /// Import from a raw 32-byte seed hex (0x…).
    #[arg(long, value_name = "SEED_HEX", conflicts_with_all = ["create", "import", "paste"])]
    import_seed: Option<String>,
    /// Paste an address only (watch-only — no keystore).
    #[arg(long, value_name = "ADDRESS", conflicts_with_all = ["create", "import"])]
    paste: Option<String>,
    /// Optional label for the identity.
    #[arg(long)]
    label: Option<String>,
    /// Keystore passphrase (prompted securely if omitted for create/import).
    #[arg(long)]
    password: Option<String>,
}

#[derive(clap::Args)]
struct StartArgs {
    /// Which lane to mine: `xmr` (CPU/RandomX), `gpu`/`rvn` (NVIDIA/KawPoW), or
    /// `auto` (the recommended lane for this device).
    #[arg(long, default_value = "xmr")]
    lane: String,
    /// Override the reward address (defaults to the active `~/.alice` identity).
    #[arg(long)]
    address: Option<String>,
    /// Stop automatically after this many seconds (0 = run until Ctrl-C). Used
    /// for the M1 live-connect verification.
    #[arg(long, default_value_t = 0)]
    duration_s: u64,
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Command::Detect => cmd_detect(),
        Command::Identity(args) => cmd_identity(args),
        Command::Start(args) => cmd_start(args),
    };
    std::process::exit(code);
}

fn cmd_detect() -> i32 {
    let engine = match EngineHandle::spawn() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    if let Err(e) = engine.send(EngineCommand::Detect) {
        eprintln!("error: {e}");
        return 1;
    }
    match engine.recv_timeout(Duration::from_secs(10)) {
        Ok(Event::Device(p)) => {
            println!("Device:  {}", p.display);
            println!("  os:            {}", p.os.label());
            println!("  arch:          {}", p.arch);
            println!("  apple_silicon: {}", p.apple_silicon);
            println!("  logical_cores: {}", p.logical_cores);
            if !p.cpu_model.is_empty() {
                println!("  cpu_model:     {}", p.cpu_model);
            }
            println!("  gpu:           {}", fmt_gpu(&p.gpu));
            println!("  memory_gb:     {}", p.memory_gb);
            if !p.warnings.is_empty() {
                println!("  warnings:      {}", p.warnings.join(", "));
            }
            // The lane-viability matrix (which lanes this device can run).
            let cap = alice_miner_core::CapabilityProfile::from_profile(p.clone());
            println!("Lanes:");
            for lane in alice_miner_core::detect::capability::ALL_LANES {
                let support = cap.support(lane);
                let marker = if lane == cap.recommended_lane() { " (recommended)" } else { "" };
                println!(
                    "  {:<10} {}{}",
                    lane.label(),
                    support.label(),
                    marker
                );
            }
            engine.shutdown();
            0
        }
        Ok(other) => {
            eprintln!("unexpected event: {other:?}");
            1
        }
        Err(_) => {
            eprintln!("error: timed out waiting for device profile");
            1
        }
    }
}

fn cmd_identity(args: IdentityArgs) -> i32 {
    let spec = if args.create {
        let password = match resolve_password(args.password, true) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("error: {e}");
                return 2;
            }
        };
        IdentitySpec::Create { label: args.label, password }
    } else if let Some(mnemonic) = args.import {
        let password = match resolve_password(args.password, true) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("error: {e}");
                return 2;
            }
        };
        IdentitySpec::ImportMnemonic { mnemonic, label: args.label, password }
    } else if let Some(seed_hex) = args.import_seed {
        let password = match resolve_password(args.password, true) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("error: {e}");
                return 2;
            }
        };
        IdentitySpec::ImportSeedHex { seed_hex, label: args.label, password }
    } else if let Some(address) = args.paste {
        IdentitySpec::Paste { address, label: args.label }
    } else {
        eprintln!("error: choose one of --create | --import <MNEMONIC> | --import-seed <HEX> | --paste <ADDR>");
        return 2;
    };

    let engine = match EngineHandle::spawn() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    if let Err(e) = engine.send(EngineCommand::Identity(spec)) {
        eprintln!("error: {e}");
        return 1;
    }
    match engine.recv_timeout(Duration::from_secs(30)) {
        Ok(Event::Identity { identity, mnemonic }) => {
            println!("Identity established:");
            println!("  address:    {}", identity.address);
            println!("  watch_only: {}", identity.watch_only);
            if let Some(ks) = identity.keystore_path.as_ref() {
                println!("  keystore:   {}", ks.display());
            }
            println!("  pointer:    {}", alice_miner_core::identity::identity_path().display());
            if let Some(phrase) = mnemonic {
                println!();
                println!("  ── BACK UP THIS RECOVERY PHRASE (24 words) ──");
                println!("  {phrase}");
                println!("  ─────────────────────────────────────────────");
            }
            engine.shutdown();
            0
        }
        Ok(Event::Error(e)) => {
            eprintln!("error: {e}");
            1
        }
        Ok(other) => {
            eprintln!("unexpected event: {other:?}");
            1
        }
        Err(_) => {
            eprintln!("error: timed out establishing identity");
            1
        }
    }
}

fn cmd_start(args: StartArgs) -> i32 {
    let lane = match args.lane.to_ascii_lowercase().as_str() {
        "xmr" | "cpu" => Lane::Xmr,
        "gpu" | "rvn" => Lane::GpuRvn,
        "auto" => {
            // Pick the recommended lane for this device (RVN on NVIDIA, else XMR).
            alice_miner_core::CapabilityProfile::detect().recommended_lane()
        }
        other => {
            eprintln!("error: unknown lane `{other}` (use xmr | gpu | auto)");
            return 2;
        }
    };
    // If the chosen lane isn't runnable on this device, say so up front (the
    // engine would also error, but a clear pre-flight message is friendlier).
    let cap = alice_miner_core::CapabilityProfile::detect();
    if !cap.support(lane).is_runnable() {
        eprintln!(
            "error: the {} lane is {} on this device ({}). Recommended lane: {}.",
            lane.label(),
            cap.support(lane).label(),
            cap.viability.reason(lane).unwrap_or("not viable"),
            cap.recommended_lane().label(),
        );
        return 2;
    }

    let engine = match EngineHandle::spawn() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };

    // Ctrl-C → graceful Stop. We set a flag the main loop watches; the engine's
    // Stop command does the SIGTERM→SIGKILL on the owned child.
    let stop_flag = Arc::new(AtomicBool::new(false));
    {
        let f = stop_flag.clone();
        let _ = ctrlc::set_handler(move || {
            f.store(true, Ordering::SeqCst);
        });
    }

    if let Err(e) = engine.send(EngineCommand::Start { lane, address: args.address }) {
        eprintln!("error: {e}");
        return 1;
    }

    println!("Starting {} lane (Ctrl-C to stop)…", lane.label());

    let start = std::time::Instant::now();
    let deadline = if args.duration_s > 0 {
        Some(Duration::from_secs(args.duration_s))
    } else {
        None
    };

    let mut exit_code = 0;
    let mut requested_stop = false;
    let mut saw_running = false;

    loop {
        // Drain any pending events (snapshots / errors).
        match engine.recv_timeout(Duration::from_millis(500)) {
            Ok(Event::Snapshot(snap)) => {
                print_snapshot(&snap);
                if matches!(snap.state, alice_miner_core::EngineState::Running) {
                    saw_running = true;
                }
                if requested_stop
                    && matches!(
                        snap.state,
                        alice_miner_core::EngineState::Idle | alice_miner_core::EngineState::Error
                    )
                {
                    break;
                }
            }
            Ok(Event::Error(e)) => {
                eprintln!("engine error: {e}");
                exit_code = 1;
                break;
            }
            Ok(_other) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // Nudge the engine for a fresh snapshot so the stream stays live.
                let _ = engine.send(EngineCommand::Poll);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }

        // Ctrl-C or duration elapsed → request Stop once.
        let timed_out = deadline.map(|d| start.elapsed() >= d).unwrap_or(false);
        if !requested_stop && (stop_flag.load(Ordering::SeqCst) || timed_out) {
            println!("Stopping…");
            let _ = engine.send(EngineCommand::Stop);
            requested_stop = true;
        }
    }

    // Best-effort: ensure the child is torn down on the way out.
    engine.shutdown();

    if exit_code == 0 && !saw_running {
        // We never reached Running — surface that as a soft failure for the
        // harness (the relay may have been unreachable).
        eprintln!("note: the lane never reached the Running state");
    }
    exit_code
}

fn print_snapshot(snap: &alice_miner_core::Snapshot) {
    let hr = snap
        .hashrate_hs
        .map(|h| format!("{h:.1} H/s"))
        .unwrap_or_else(|| "—".into());
    let endpoint = snap.endpoint.as_deref().unwrap_or("—");
    println!(
        "[{:?}] hashrate={} shares={}A/{}R uptime={}s endpoint={}{}",
        snap.state,
        hr,
        snap.shares_accepted,
        snap.shares_rejected,
        snap.uptime_s,
        endpoint,
        snap.last_line
            .as_deref()
            .map(|l| format!("  | {l}"))
            .unwrap_or_default(),
    );
}

/// Human-friendly one-line GPU description for `detect` (model + VRAM, or the
/// vendor when no model was probed; `none` when CPU-only).
fn fmt_gpu(gpu: &alice_miner_core::GpuInfo) -> String {
    use alice_miner_core::GpuVendor;
    match gpu.vendor {
        GpuVendor::None => "none (CPU-only)".to_string(),
        GpuVendor::Nvidia => {
            if gpu.vram_gb > 0 {
                format!("{} · {} GB VRAM", gpu.model, gpu.vram_gb)
            } else {
                gpu.model.clone()
            }
        }
        GpuVendor::Amd => format!("{} (lane coming soon)", gpu.model),
        GpuVendor::Apple => format!("{} (unified memory)", gpu.model),
    }
}

/// Resolve a keystore passphrase: use the flag if given, else prompt securely.
/// (Never echoes the passphrase; the engine zeroizes it after use.)
fn resolve_password(flag: Option<String>, required: bool) -> Result<String, String> {
    if let Some(p) = flag {
        return Ok(p);
    }
    if !required {
        return Ok(String::new());
    }
    rpassword::prompt_password("Keystore passphrase: ")
        .map_err(|e| format!("failed to read passphrase: {e}"))
        .and_then(|p| {
            if p.is_empty() {
                Err("passphrase must not be empty".into())
            } else {
                Ok(p)
            }
        })
}
