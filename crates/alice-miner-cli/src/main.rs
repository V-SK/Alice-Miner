//! Alice Miner — headless CLI binary (clap).
//!
//! A clean, complete **headless front-end** with full parity to the GUI, driving
//! the SAME `alice-miner-core` engine over the `Command`/`Event` channel pair, so
//! the two front-ends cannot drift (PLAN §2.2 / §5 M6). It adds **zero new mining
//! logic** — every subcommand is a thin presentation layer over the engine.
//!
//! Subcommands (M6):
//!
//! - `detect` — print the [`CapabilityProfile`]: device model string, CPU/GPU,
//!   and the lane-viability matrix (runnable lanes + the recommended one).
//!   `--json` for machine-readable output.
//! - `identity` — `--create` / `--import <MNEMONIC>` / `--import-seed <HEX>` /
//!   `--paste <ADDRESS>` (watch-only) / `--show` (print the active address;
//!   never a secret).
//! - `start` — `--lane xmr|gpu|auto` (auto = recommended), `--dual` (gated:
//!   refuses honestly with the viability reason when <2 viable lanes),
//!   `--address <A>` (else the `~/.alice` identity). Streams a clean headless
//!   dashboard each interval; `--json` emits one [`Snapshot`] JSON line per tick.
//! - `stop` — graceful `Command::Stop` (SIGTERM→SIGKILL) of a running `start`
//!   (recorded via a pid file), clean exit, no orphan.
//!
//! ── Hard invariants (the brief, PLAN §3) ────────────────────────────────────
//!
//! - **NO egui/eframe** in this binary (verified by `cargo tree -p
//!   alice-miner-cli`, `otool -L`, AND a `no_egui_in_dep_tree` unit test).
//! - **Credit-only honesty** — the dashboard shows rewards only as
//!   "pending · 待发放"; it NEVER prints `$`/fiat/`paid`/`earned`, and never the
//!   collection address / upstream pool / core IP (those never reach the client
//!   — the engine bakes only the PUBLIC relay). A strings honesty test scans
//!   this file's user-facing copy.
//! - Exit codes: `0` ok, non-zero on error (`1` engine/runtime fault, `2`
//!   usage/argument error).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use alice_miner_core::engine::{Command as EngineCommand, Event, IdentitySpec};
use alice_miner_core::{EngineHandle, EngineState, GpuSelection, Lane, Snapshot};

mod dashboard;
mod fleet;
mod pidfile;
mod tui;

// ── Exit codes ──────────────────────────────────────────────────────────────
/// Success.
const EXIT_OK: i32 = 0;
/// Runtime / engine fault (spawn failed, relay unreachable, …).
const EXIT_RUNTIME: i32 = 1;
/// Usage / argument error (bad lane, no identity flag, dual refused, …).
const EXIT_USAGE: i32 = 2;

#[derive(Parser)]
#[command(
    name = "alice-miner",
    bin_name = "alice-miner",
    version,
    about = "Alice Miner — headless client (credit-only).",
    long_about = "Alice Miner — the headless front-end for the Alice one-click miner.\n\
        \n\
        Detects your device, manages your Alice reward identity, and mines ALICE\n\
        credit to your OWN address against the public relay. Drives the same engine\n\
        as the desktop app. Rewards accrue as pending (待发放); payout, settlement,\n\
        and on-chain transfer stay gated (phase-J).",
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Probe this device and print its capability profile + lane matrix.
    #[command(long_about = "Probe this device (CPU / GPU / Apple Silicon) and print its\n\
        capability profile: the model string, core count, memory, and the\n\
        lane-viability matrix — which lanes are runnable here and which one is\n\
        recommended. Use --json for machine-readable output.")]
    Detect(DetectArgs),

    /// List the GPU device ids the miner sees (the numbers `--gpus` selects).
    #[command(long_about = "List the GPUs as the bundled SRBMiner engine enumerates them — the\n\
        device ids that `start --lane gpu --gpus <ids>` selects. These are the MINER's\n\
        OWN ids: they can differ from the OS / `detect` order and may include an\n\
        integrated GPU at id 0, so always pick the id from THIS list (not the gpu[n]\n\
        index in `detect`). Resolves (downloads + verifies) the GPU engine if needed.\n\
        Use --json for machine-readable output.")]
    GpuDevices(GpuDevicesArgs),

    /// Create, import, paste, or show the Alice reward identity.
    #[command(long_about = "Manage the Alice reward identity stored at ~/.alice/identity.json.\n\
        \n\
        --create            generate a fresh 24-word identity (prints the mnemonic — BACK IT UP)\n\
        --import <MNEMONIC> import from a 24-word recovery phrase\n\
        --import-seed <HEX> import from a raw 32-byte seed (hex, optional 0x)\n\
        --paste <ADDRESS>   watch-only: track an address you own (no keystore)\n\
        --show              print the active address (never any secret)")]
    Identity(IdentityArgs),

    /// Start mining to your Alice address and stream a live dashboard.
    #[command(long_about = "Start mining to your OWN Alice address and stream a clean headless\n\
        dashboard (state, hashrate, accepted/rejected shares, endpoint, failovers,\n\
        uptime). The reward address defaults to the active ~/.alice identity.\n\
        \n\
        --lane xmr   CPU RandomX/XMR lane\n\
        --lane gpu   NVIDIA/AMD pearlhash/PRL lane (the GPU mainline)\n\
        --lane rvn   NVIDIA KawPoW/RVN lane (legacy)\n\
        --lane auto  the recommended lane for this device\n\
        --dual       run BOTH lanes (needs >=2 viable lanes; refuses honestly otherwise)\n\
        --json       emit one Snapshot JSON line per tick (for scripting)\n\
        \n\
        Ctrl-C (or `alice-miner stop`) stops gracefully. Rewards accrue as pending\n\
        (待发放); the collection address and upstream pool are never shown.")]
    Start(StartArgs),

    /// Gracefully stop a running `start` (SIGTERM→SIGKILL, no orphan).
    #[command(long_about = "Gracefully stop a miner started by `alice-miner start` in another\n\
        terminal. Reads the pid recorded at start, sends SIGTERM (which the running\n\
        process handles exactly like Ctrl-C: Command::Stop → SIGTERM→SIGKILL on the\n\
        owned child), and escalates to SIGKILL if it doesn't exit. Leaves no orphan.")]
    Stop(StopArgs),

    /// Run mining in the background so it PERSISTS when you close the window.
    #[command(long_about = "Install / remove a background mining service so mining keeps running\n\
        after you close the window (and, with --at-login, restarts at login/boot).\n\
        macOS only for now (launchd LaunchAgent). The CPU-XMR lane runs with NO\n\
        stored secret — the reward address is read from your ~/.alice identity at\n\
        runtime, never written into the service definition.\n\
        \n\
        --install     install + start the background agent\n\
        --uninstall   stop + remove the background agent\n\
        --status      print whether it is installed / running (the default)\n\
        --lane xmr    the lane to background (xmr only today; GPU needs a follow-up)\n\
        --at-login    also start mining automatically at login/boot")]
    Service(ServiceArgs),

    /// Aggregate several miners (same Alice address) into one local roster.
    #[command(long_about = "Watch several miner instances reporting to the same Alice address as\n\
        one LOCAL roster — no server. Each miner emits its `--json` Snapshot stream to\n\
        stdout; redirect each to a file, then pass those files here:\n\
        \n\
            alice-miner start --lane prl --json > rig-a.jsonl   (on box A)\n\
            alice-miner start --lane xmr --json > rig-b.jsonl   (on box B, synced/NFS)\n\
            alice-miner fleet rig-a.jsonl rig-b.jsonl\n\
        \n\
        Reads the LAST complete Snapshot line from each file and prints a roster keyed\n\
        by worker id (lane, hashrate, shares A/R, accepted %, state, failovers,\n\
        last-seen). Refreshes on an interval until Ctrl-C; --once prints one frame.\n\
        A missing / partial / garbage source is shown as a dim `no data` row (never a\n\
        panic). Activity only — credit-only, like the live dashboard.")]
    Fleet(FleetArgs),
}

#[derive(clap::Args)]
struct DetectArgs {
    /// Emit the full capability profile as a single JSON object (machine-readable).
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args)]
struct GpuDevicesArgs {
    /// Emit the device list as a JSON array (machine-readable).
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args)]
struct IdentityArgs {
    /// Create a fresh 24-word identity (prints the mnemonic — BACK IT UP).
    #[arg(long, conflicts_with_all = ["import", "import_seed", "paste", "show"])]
    create: bool,
    /// Import from a 24-word mnemonic (quote it).
    #[arg(long, value_name = "MNEMONIC", conflicts_with_all = ["create", "import_seed", "paste", "show"])]
    import: Option<String>,
    /// Import from a raw 32-byte seed hex (0x…).
    #[arg(long, value_name = "SEED_HEX", conflicts_with_all = ["create", "import", "paste", "show"])]
    import_seed: Option<String>,
    /// Paste an address only (watch-only — no keystore).
    #[arg(long, value_name = "ADDRESS", conflicts_with_all = ["create", "import", "import_seed", "show"])]
    paste: Option<String>,
    /// Print the active reward address from ~/.alice/identity.json (no secret).
    #[arg(long, conflicts_with_all = ["create", "import", "import_seed", "paste"])]
    show: bool,
    /// Set your 15%-PRL RETURN address — where the foundation sends your 15% PRL
    /// kickback (a public `prl1p…` address). Stored at ~/.alice/prl_payout_address
    /// and bound to your Alice address on the next GPU-lane start (PoP). OPTIONAL:
    /// mining works without it; you just forgo the 15% return until it is set.
    #[arg(long, value_name = "PRL1", conflicts_with_all = ["create", "import", "import_seed", "paste", "show", "show_prl_payout"])]
    set_prl_payout: Option<String>,
    /// Print your stored 15%-PRL return address (masked), or `not set`.
    #[arg(long, conflicts_with_all = ["create", "import", "import_seed", "paste", "show", "set_prl_payout"])]
    show_prl_payout: bool,
    /// Optional label for the identity.
    #[arg(long)]
    label: Option<String>,
    /// INSECURE — keystore passphrase on the command line. Visible in `ps`/the
    /// process table and shell history; prefer the interactive prompt (omit this)
    /// or `--password-stdin`. Kept only for non-interactive automation; using it
    /// prints a loud warning.
    #[arg(long, value_name = "PASS")]
    password: Option<String>,
    /// Read the keystore passphrase from STDIN (the first line) instead of the
    /// command line — the secure non-interactive path for scripts/pipes.
    #[arg(long, conflicts_with = "password")]
    password_stdin: bool,
    /// Machine-readable output (the resulting identity / active address as JSON).
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args)]
struct StartArgs {
    /// Which lane to mine: `xmr` (CPU/RandomX), `gpu`/`prl` (NVIDIA/AMD pearlhash via
    /// SRBMiner — the GPU mainline, CC≥7.5), `alpha` (pearlhash via AlphaMiner — the
    /// Volta/V100 path, where SRBMiner can't run), `rvn` (legacy KawPoW), or `auto`.
    #[arg(long, default_value = "auto", value_name = "LANE")]
    lane: String,
    /// Override the reward address (defaults to the active ~/.alice identity).
    #[arg(long, value_name = "ADDRESS")]
    address: Option<String>,
    /// Dual-mine: run BOTH lanes together (CPU-XMR + GPU-PRL), each crash-isolated,
    /// with `cores-2` XMR headroom. Requires >=2 viable lanes on this device.
    #[arg(long)]
    dual: bool,
    /// Emit one Snapshot JSON line per tick (for scripting) instead of the
    /// human dashboard.
    #[arg(long)]
    json: bool,
    /// Stop automatically after this many seconds (0 = run until Ctrl-C / stop).
    /// Used for the live-connect verification.
    #[arg(long, default_value_t = 0, value_name = "SECONDS")]
    duration_s: u64,
    /// Wallet keystore password — **only needed for the GPU-PRL (`prl`) lane**,
    /// which must unlock the signing key to prove possession (the relay credits no
    /// shares without it). INSECURE on the command line (visible in `ps`); prefer
    /// `--password-stdin` or the interactive prompt. Ignored for XMR/RVN.
    #[arg(long, value_name = "PASS")]
    password: Option<String>,
    /// Read the GPU-PRL unlock password from the first line of STDIN (secure for
    /// scripts). Conflicts with `--password`.
    #[arg(long, conflicts_with = "password")]
    password_stdin: bool,
    /// Restrict a GPU lane (`prl`/`gpu`) to specific cards, as a comma-separated
    /// list of 0-based device indices (e.g. `--gpus 0,1,2`). OMIT this flag to use
    /// EVERY detected card (the default — argv is unchanged). Indices come from
    /// `alice-miner detect` (the per-GPU list). Ignored for the CPU-XMR lane.
    #[arg(long, value_name = "IDS")]
    gpus: Option<String>,
    /// Internal marker set on the invocation the BACKGROUND SERVICE runs, so the
    /// single-owner check below doesn't make the agent refuse to start itself.
    /// Not for manual use. Hidden.
    #[arg(long, hide = true)]
    from_service: bool,
}

#[derive(clap::Args)]
struct StopArgs {
    /// Seconds to wait for a graceful exit before escalating to SIGKILL.
    #[arg(long, default_value_t = 8, value_name = "SECONDS")]
    timeout_s: u64,
}

#[derive(clap::Args)]
struct ServiceArgs {
    /// Install + start the background mining agent.
    #[arg(long, conflicts_with_all = ["uninstall", "status"])]
    install: bool,
    /// Stop + remove the background mining agent.
    #[arg(long, conflicts_with_all = ["install", "status"])]
    uninstall: bool,
    /// Print whether the agent is installed / running (the default action).
    #[arg(long, conflicts_with_all = ["install", "uninstall"])]
    status: bool,
    /// Which lane to background: `xmr` (secret-free), or a GPU pearlhash lane
    /// (`prl`/`alpha`/`gpu`/`auto`) whose wallet unlock is stored in the OS keyring.
    #[arg(long, default_value = "xmr", value_name = "LANE")]
    lane: String,
    /// Also start mining automatically at login / boot (launchd RunAtLoad).
    #[arg(long)]
    at_login: bool,
    /// Keystore passphrase for a GPU lane (validated, then stored in the OS keyring so
    /// the background agent can unlock without a prompt). Omit to be prompted; INSECURE
    /// on the command line (visible in `ps`) — prefer the prompt or `--password-stdin`.
    #[arg(long, value_name = "PASS")]
    password: Option<String>,
    /// Read the GPU keystore passphrase from the first line of STDIN.
    #[arg(long)]
    password_stdin: bool,
    /// Machine-readable status output.
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args)]
struct FleetArgs {
    /// One or more `--json` stream files (each fed by a miner's `start --json`).
    #[arg(value_name = "PATH", required = true)]
    paths: Vec<std::path::PathBuf>,
    /// Print one roster frame and exit (no live refresh loop).
    #[arg(long)]
    once: bool,
    /// Refresh interval in seconds for the live loop (ignored with --once).
    #[arg(long, default_value_t = 2, value_name = "SECONDS")]
    interval_s: u64,
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Command::Detect(args) => cmd_detect(args),
        Command::GpuDevices(args) => cmd_gpu_devices(args),
        Command::Identity(args) => cmd_identity(args),
        Command::Start(args) => cmd_start(args),
        Command::Stop(args) => cmd_stop(args),
        Command::Service(args) => cmd_service(args),
        Command::Fleet(args) => fleet::run(
            &args.paths,
            args.once,
            std::time::Duration::from_secs(args.interval_s.max(1)),
        ),
    };
    std::process::exit(code);
}

// ─────────────────────────────────────────────────────────────────────────────
// service (background mining persistence)
// ─────────────────────────────────────────────────────────────────────────────

fn cmd_service(args: ServiceArgs) -> i32 {
    use alice_miner_core::service::{self, ServiceSpec, ServiceState};

    // Default + explicit --status: report state.
    if args.status || (!args.install && !args.uninstall) {
        let (word, msg) = match service::status() {
            ServiceState::Running => ("running", "Background mining is installed and running."),
            ServiceState::Loaded => (
                "loaded",
                "Background mining is installed (not currently running; it will keep retrying).",
            ),
            ServiceState::NotInstalled => ("not_installed", "Background mining is not installed."),
        };
        if args.json {
            println!("{{\"service\":\"{word}\"}}");
        } else {
            println!("{msg}");
        }
        return EXIT_OK;
    }

    if args.uninstall {
        // Best-effort: drop any background-unlock password stored for the current
        // identity (idempotent; a no-op if XMR-only / nothing was stored).
        if let Some(addr) = alice_miner_core::identity::load_pointer().map(|p| p.address) {
            let _ = alice_miner_core::keyring::delete_unlock_password(&addr);
        }
        return match service::uninstall() {
            Ok(()) => {
                println!("Background mining removed.");
                EXIT_OK
            }
            Err(e) => {
                eprintln!("error: {e}");
                EXIT_RUNTIME
            }
        };
    }

    // install: the bundled CLI to run in the background is THIS binary.
    let cli_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: cannot locate the miner CLI to background: {e}");
            return EXIT_RUNTIME;
        }
    };
    let cap = alice_miner_core::CapabilityProfile::detect();
    let lane = match resolve_lane(&args.lane, &cap) {
        Ok(l) => l,
        Err(code) => return code,
    };
    // Single owner: stop any running FOREGROUND miner before handing the machine
    // to the background service, so we never double-mine to the same address.
    if let Some(pid) = pidfile::read_pid() {
        if pidfile::is_alive(pid) {
            let _ = pidfile::stop_pid(pid, std::time::Duration::from_secs(8));
        }
    }
    // A GPU pearlhash lane needs an OS keyring to hold its unlock (the unit carries no
    // secret). Refuse early on a box without one (e.g. a headless Linux rig).
    if let Err(e) = service::require_backgroundable(lane) {
        eprintln!("error: {e}");
        return EXIT_USAGE;
    }
    // For a pearlhash lane, resolve + VALIDATE the keystore passphrase against the
    // active identity, then stash it in the OS keyring (keyed to that address) so the
    // `--from-service` start can unlock without a prompt and without a secret in the
    // unit. Validation reuses the exact unlock the background start will perform, so a
    // wrong password (or a watch-only identity) is caught HERE, not after install.
    if lane.is_prl_lane() {
        let Some(addr) = alice_miner_core::identity::load_pointer().map(|p| p.address) else {
            eprintln!(
                "error: no identity yet — create or import one (`identity --create`) before \
                 backgrounding a GPU lane."
            );
            return EXIT_USAGE;
        };
        // Wrap in `Zeroizing` so the in-memory passphrase is scrubbed on EVERY exit of
        // this block (success and the early-return error paths) — parity with the GUI
        // (`confirm_bg_enable`) + engine (`start_run`), which both zeroize. Without it
        // the validated `String` dropped un-scrubbed, leaving heap residue (in-process
        // only — no disk/log/argv exposure; the validate→store flow is unchanged).
        let pw = Zeroizing::new(match resolve_password(args.password.clone(), args.password_stdin) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("error: {e}");
                return EXIT_USAGE;
            }
        });
        // Unlock to validate (the returned secrets zeroize on drop — we keep nothing).
        if let Err(e) = alice_miner_core::engine::resolve_prl_secrets(Some(pw.as_str())) {
            eprintln!("error: {e}");
            return EXIT_USAGE;
        }
        if let Err(e) = alice_miner_core::keyring::store_unlock_password(&addr, pw.as_str()) {
            eprintln!("error: {e}");
            return EXIT_RUNTIME;
        }
    }
    let spec = ServiceSpec { lane, cli_path, run_at_login: args.at_login };
    match service::install(&spec) {
        Ok(()) => {
            let tail = if args.at_login { " It will also start at login." } else { "" };
            println!("Background mining installed and started.{tail}");
            EXIT_OK
        }
        Err(e) => {
            eprintln!("error: {e}");
            EXIT_USAGE
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// detect
// ─────────────────────────────────────────────────────────────────────────────

fn cmd_detect(args: DetectArgs) -> i32 {
    // Detect synchronously (the probe is fail-safe + cheap); no engine thread
    // needed for a one-shot read. Build the full CapabilityProfile so we print
    // the same matrix the GUI/engine compute.
    let cap = alice_miner_core::CapabilityProfile::detect();

    if args.json {
        match serde_json::to_string_pretty(&cap) {
            Ok(s) => {
                println!("{s}");
                EXIT_OK
            }
            Err(e) => {
                eprintln!("error: failed to serialize profile: {e}");
                EXIT_RUNTIME
            }
        }
    } else {
        print!("{}", dashboard::render_detect(&cap));
        EXIT_OK
    }
}

/// `gpu-devices`: list the GPUs as the SRBMiner engine enumerates them (the ids
/// `--gpus` selects). Resolves/downloads the engine to ask it directly, so the ids
/// are authoritative (and may differ from `detect`'s gpu[n] / include an iGPU).
fn cmd_gpu_devices(args: GpuDevicesArgs) -> i32 {
    let devices = match alice_miner_core::lane::gpu_prl::list_srbminer_devices() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_RUNTIME;
        }
    };
    if args.json {
        let arr: Vec<serde_json::Value> = devices
            .iter()
            .map(|d| {
                serde_json::json!({"id": d.id, "backend": d.backend, "pci": d.pci, "name": d.name})
            })
            .collect();
        println!("{}", serde_json::Value::Array(arr));
        EXIT_OK
    } else {
        print!("{}", dashboard::render_gpu_devices(&devices));
        EXIT_OK
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// identity
// ─────────────────────────────────────────────────────────────────────────────

fn cmd_identity(args: IdentityArgs) -> i32 {
    // `--show` is a pure read of the public pointer — no engine, no secret.
    if args.show {
        return cmd_identity_show(args.json);
    }
    // The 15%-PRL return address ops are pure local file IO (public address, no
    // engine, no secret, never touches the keystore).
    if let Some(addr) = args.set_prl_payout.as_deref() {
        return cmd_set_prl_payout(addr, args.json);
    }
    if args.show_prl_payout {
        return cmd_show_prl_payout(args.json);
    }

    let spec = match build_identity_spec(
        args.create,
        args.import,
        args.import_seed,
        args.paste,
        args.label,
        args.password,
        args.password_stdin,
    ) {
        Ok(spec) => spec,
        Err(code) => return code,
    };

    let engine = match EngineHandle::spawn() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_RUNTIME;
        }
    };
    if let Err(e) = engine.send(EngineCommand::Identity(spec)) {
        eprintln!("error: {e}");
        return EXIT_RUNTIME;
    }
    match engine.recv_timeout(Duration::from_secs(30)) {
        Ok(Event::Identity { identity, mnemonic }) => {
            if args.json {
                // JSON form: the public identity (never the mnemonic — it stays
                // human-only so it can't be slurped into a log/file by mistake).
                let pointer_path = alice_miner_core::identity::identity_path();
                let obj = serde_json::json!({
                    "address": identity.address,
                    "pubkey": identity.pubkey,
                    "watch_only": identity.watch_only,
                    "keystore_path": identity.keystore_path.as_ref().map(|p| p.display().to_string()),
                    "pointer": pointer_path.display().to_string(),
                });
                println!("{}", serde_json::to_string_pretty(&obj).unwrap_or_default());
                // The mnemonic, when present, still goes to STDERR with the
                // back-up warning so machine consumers of stdout never capture it.
                if let Some(phrase) = mnemonic {
                    eprintln!();
                    eprintln!("  ── BACK UP THIS RECOVERY PHRASE (24 words) ──");
                    eprintln!("  {phrase}");
                    eprintln!("  ─────────────────────────────────────────────");
                }
            } else {
                print!("{}", dashboard::render_identity(&identity, mnemonic.as_deref()));
            }
            engine.shutdown();
            EXIT_OK
        }
        Ok(Event::Error(e)) => {
            eprintln!("error: {e}");
            EXIT_RUNTIME
        }
        Ok(other) => {
            eprintln!("unexpected event: {other:?}");
            EXIT_RUNTIME
        }
        Err(_) => {
            eprintln!("error: timed out establishing identity");
            EXIT_RUNTIME
        }
    }
}

/// `identity --show`: print the active address from the pointer. NEVER a secret.
fn cmd_identity_show(json: bool) -> i32 {
    match alice_miner_core::identity::load_pointer() {
        Some(p) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&p).unwrap_or_default());
            } else {
                print!("{}", dashboard::render_identity_show(&p));
            }
            EXIT_OK
        }
        None => {
            let path = alice_miner_core::identity::identity_path();
            if json {
                println!("{}", serde_json::json!({ "address": null, "pointer": path.display().to_string() }));
            } else {
                eprintln!(
                    "No identity yet. Create or import one first:\n  \
                     alice-miner identity --create\n  \
                     alice-miner identity --import \"<24 words>\"\n  \
                     alice-miner identity --paste <address>   (watch-only)\n\
                     (expected pointer: {})",
                    path.display()
                );
            }
            EXIT_RUNTIME
        }
    }
}

/// `identity --set-prl-payout <prl1p…>`: store the user's 15%-PRL return address
/// (public, shape-validated, no engine/secret). Bound to the Alice address on the
/// next GPU-lane start.
fn cmd_set_prl_payout(addr: &str, json: bool) -> i32 {
    match alice_miner_core::prl_payout::save_payout_address(addr) {
        Ok(path) => {
            let masked = alice_miner_core::prl_payout::mask_payout(addr.trim());
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "prl_payout": masked, "set": true, "stored": path.display().to_string() })
                );
            } else {
                println!("15% PRL return address saved: {masked}");
                println!("  binds to your Alice address on the next GPU mining start (PoP).");
            }
            EXIT_OK
        }
        Err(e) => {
            eprintln!("error: {e}");
            EXIT_USAGE
        }
    }
}

/// `identity --show-prl-payout`: print the stored 15%-PRL return address (masked).
fn cmd_show_prl_payout(json: bool) -> i32 {
    match alice_miner_core::prl_payout::load_payout_address() {
        Ok(Some(addr)) => {
            let masked = alice_miner_core::prl_payout::mask_payout(&addr);
            if json {
                println!("{}", serde_json::json!({ "prl_payout": masked, "set": true }));
            } else {
                println!("15% PRL return address: {masked}");
            }
            EXIT_OK
        }
        Ok(None) => {
            if json {
                println!("{}", serde_json::json!({ "prl_payout": null, "set": false }));
            } else {
                println!("15% PRL return address: not set");
                println!("  set one with:  alice-miner identity --set-prl-payout <prl1p…>");
            }
            EXIT_OK
        }
        Err(e) => {
            eprintln!("error: {e}");
            EXIT_USAGE
        }
    }
}

/// Map the identity flags to an [`IdentitySpec`], resolving the passphrase where
/// a keystore is written. Returns the exit code to use on a usage error.
fn build_identity_spec(
    create: bool,
    import: Option<String>,
    import_seed: Option<String>,
    paste: Option<String>,
    label: Option<String>,
    password: Option<String>,
    password_stdin: bool,
) -> Result<IdentitySpec, i32> {
    if create {
        let password = resolve_password(password, password_stdin).map_err(|e| {
            eprintln!("error: {e}");
            EXIT_USAGE
        })?;
        Ok(IdentitySpec::Create { label, password })
    } else if let Some(mnemonic) = import {
        let password = resolve_password(password, password_stdin).map_err(|e| {
            eprintln!("error: {e}");
            EXIT_USAGE
        })?;
        Ok(IdentitySpec::ImportMnemonic { mnemonic, label, password })
    } else if let Some(seed_hex) = import_seed {
        let password = resolve_password(password, password_stdin).map_err(|e| {
            eprintln!("error: {e}");
            EXIT_USAGE
        })?;
        Ok(IdentitySpec::ImportSeedHex { seed_hex, label, password })
    } else if let Some(address) = paste {
        Ok(IdentitySpec::Paste { address, label })
    } else {
        eprintln!(
            "error: choose one of:\n  \
             --create | --import <MNEMONIC> | --import-seed <HEX> | --paste <ADDR> | --show"
        );
        Err(EXIT_USAGE)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// start
// ─────────────────────────────────────────────────────────────────────────────

fn cmd_start(args: StartArgs) -> i32 {
    // Resolve the lane (auto = recommended for this device), then pre-flight the
    // viability gates so we refuse HONESTLY before spawning a child.
    let cap = alice_miner_core::CapabilityProfile::detect();
    let lane = match resolve_lane(&args.lane, &cap) {
        Ok(l) => l,
        Err(code) => return code,
    };

    // A5b: resolve the optional per-card GPU selection. Absent → All (every card,
    // unchanged argv); a malformed `--gpus` value is a usage error (we never
    // silently degrade to "all cards" on a typo).
    let gpus = match args.gpus.as_deref() {
        None => GpuSelection::All,
        Some(s) => match GpuSelection::parse_ids(s) {
            Ok(sel) => sel,
            Err(e) => {
                eprintln!("error: {e}");
                return EXIT_USAGE;
            }
        },
    };

    // Single-owner lock: a MANUAL `start` refuses while the background service is
    // installed/running — two miners to the same address only waste the machine.
    // The service's own invocation passes `--from-service` to bypass this (it IS
    // the single owner). See `alice_miner_core::service`.
    if !args.from_service {
        use alice_miner_core::service::ServiceState;
        if matches!(
            alice_miner_core::service::status(),
            ServiceState::Running | ServiceState::Loaded
        ) {
            eprintln!(
                "error: background mining is already active (one miner per machine). Stop it with \
                 `alice-miner-cli service --uninstall` first, then run start — or just let the \
                 background service keep mining."
            );
            return EXIT_USAGE;
        }
    }

    // Background agent: cap the launchd log so a long-uptime or crash-looping agent
    // can't grow it without bound (best-effort, before we spawn the child).
    if args.from_service {
        alice_miner_core::service::rotate_background_log_if_oversized();
    }

    if !cap.support(lane).is_runnable() {
        eprintln!(
            "error: the {} lane is {} on this device ({}). Recommended lane: {}.",
            lane.label(),
            cap.support(lane).label(),
            cap.viability.reason(lane).unwrap_or("not viable"),
            cap.recommended_lane().label(),
        );
        return EXIT_USAGE;
    }

    // Dual-mine requires >=2 viable lanes. On a Mac / no-NVIDIA box only XMR is
    // viable, so refuse with the honest per-lane reason.
    if args.dual {
        let runnable = cap.viability.runnable_lanes();
        if runnable.len() < 2 {
            // Report the GPU partner this selection would actually pair (Alpha on a
            // Volta box), not a hardcoded PRL, so the honest reason matches the device.
            let gpu = lane.dual_gpu_partner();
            eprintln!(
                "error: dual-mine needs 2 viable lanes; this device has {} ({} is {}: {}). \
                 Run a single lane instead, e.g. `alice-miner start --lane {}`.",
                runnable.len(),
                gpu.label(),
                cap.support(gpu).label(),
                cap.viability.reason(gpu).unwrap_or("not viable"),
                cap.recommended_lane().id(),
            );
            return EXIT_USAGE;
        }
    }

    let engine = match EngineHandle::spawn() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_RUNTIME;
        }
    };

    // Ctrl-C / SIGTERM (from `alice-miner stop`) → graceful Stop. We set a flag
    // the main loop watches; the engine's Stop does the SIGTERM→SIGKILL on the
    // owned child. The `termination` feature traps SIGTERM/SIGHUP too.
    let stop_flag = Arc::new(AtomicBool::new(false));
    {
        let f = stop_flag.clone();
        let _ = ctrlc::set_handler(move || {
            f.store(true, Ordering::SeqCst);
        });
    }

    // Record our pid so `alice-miner stop` (another process) can find us. Removed
    // on the way out so a stale pid never lingers. Best-effort: a write failure
    // (e.g. read-only home) does not block mining — only `stop` would be unable
    // to find us, and Ctrl-C still works.
    let pid_guard = pidfile::PidGuard::acquire();

    // A pearlhash lane needs the wallet password to unlock the signing key for the OOB
    // M4 PoP. Resolve it (stdin / flag / interactive prompt) when a pearlhash lane is in
    // play: a single GpuPrl OR GpuAlpha start, or a dual-mine whose GPU partner is
    // pearlhash (anything but an explicit RVN selection). Delegates to the SAME
    // `Lane::start_needs_unlock` rule the GUI modal + engine `prl_in_play` use, so the
    // three can never drift (the GpuAlpha-can't-start bug). XMR / RVN pass None.
    let prl_in_play = lane.start_needs_unlock(args.dual);
    let unlock_password = if !prl_in_play {
        None
    } else if args.from_service {
        // The background agent has no TTY to prompt: read the unlock from the OS keyring
        // (stored at `service --install` time), keyed to the active identity.
        let Some(addr) = alice_miner_core::identity::load_pointer().map(|p| p.address) else {
            eprintln!("error: background GPU start found no identity to unlock");
            return EXIT_RUNTIME;
        };
        match alice_miner_core::keyring::get_unlock_password(&addr) {
            Ok(Some(pw)) => Some(pw.as_str().to_string()),
            Ok(None) => {
                eprintln!(
                    "error: no background unlock is stored in the OS keyring for this identity \
                     — re-run `alice-miner-cli service --install --lane {}`.",
                    lane.cli_lane_arg()
                );
                return EXIT_RUNTIME;
            }
            Err(e) => {
                eprintln!("error: {e}");
                return EXIT_RUNTIME;
            }
        }
    } else {
        match resolve_password(args.password.clone(), args.password_stdin) {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!("error: {e}");
                return EXIT_USAGE;
            }
        }
    };

    if let Err(e) = engine.send(EngineCommand::Start {
        lane,
        address: args.address.clone(),
        dual: args.dual,
        unlock_password,
        gpus,
    }) {
        eprintln!("error: {e}");
        return EXIT_RUNTIME;
    }

    // Choose the live-output mode ONCE (the three honest paths):
    //   * --json          → machine JSON lines (TUI/line renderer never touch it).
    //   * non-TTY, !json   → the plain scrolling line renderer (piped / CI).
    //   * interactive TTY  → the in-place ratatui panel (falls back to the line
    //                        renderer if the terminal can't enter raw mode).
    // The `--json` output is byte-for-byte unchanged in every case.
    use std::io::IsTerminal;
    let interactive = !args.json && std::io::stdout().is_terminal();
    let mut tui = if interactive { tui::Tui::new().ok() } else { None };

    // Banners only make sense for the scrolling line renderer (the TUI shows state
    // in its status bar; --json is machine-only).
    if !args.json && tui.is_none() {
        print!("{}", dashboard::render_start_banner(lane, args.dual));
    }

    // ── Source B: cumulative server-confirmed credit poller ──────────────────
    // A best-effort, READ-ONLY background poll of the public read-API for THIS
    // address's cumulative accepted-share COUNTS (credit-only). It runs on its OWN
    // thread on a slow cadence (off the 500ms render hot path) and publishes the
    // latest CreditState into a shared cell the render loop reads. Watch-only
    // addresses resolve fine (a read needs only the public address). In `--json`
    // mode we skip it entirely (the JSON stream is unchanged + machine-only).
    let credit_cell = std::sync::Arc::new(std::sync::Mutex::new(
        alice_miner_core::CreditState::NotExposed,
    ));
    let effective_address = args
        .address
        .clone()
        .or_else(|| alice_miner_core::identity::load_pointer().map(|p| p.address));
    if !args.json {
        if let Some(addr) = effective_address {
            let cell = std::sync::Arc::clone(&credit_cell);
            let stop = std::sync::Arc::clone(&stop_flag);
            std::thread::spawn(move || {
                let mut client = alice_miner_core::PoolStatsClient::public_default();
                // A tiny deterministic jitter from the address so a fleet doesn't poll
                // in lockstep (no rng dep needed).
                let jitter = (addr.bytes().map(|b| b as u64).sum::<u64>() % 30) as f64 / 30.0;
                loop {
                    // poll() is single-flight + https-only + ~10s-timeout + capped;
                    // it never panics and never blocks the engine.
                    let state = client.poll(&addr);
                    if let Ok(mut c) = cell.lock() {
                        *c = state;
                    }
                    // Sleep the poll cadence in short slices so a Ctrl-C tears the
                    // thread down promptly instead of after a full interval.
                    let secs = client.next_poll_in_secs(jitter).unwrap_or(45);
                    for _ in 0..(secs * 2) {
                        if stop.load(Ordering::SeqCst) {
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(500));
                    }
                }
            });
        }
    }

    let start = std::time::Instant::now();
    let deadline = (args.duration_s > 0).then(|| Duration::from_secs(args.duration_s));

    let mut exit_code = EXIT_OK;
    let mut requested_stop = false;
    let mut saw_running = false;
    // A fatal engine error message, deferred until AFTER the TUI is torn down so it
    // prints to the restored terminal (not the alternate screen). `None` in line mode
    // (it's printed inline there immediately, as before).
    let mut deferred_error: Option<String> = None;

    loop {
        match engine.recv_timeout(Duration::from_millis(500)) {
            Ok(Event::Snapshot(snap)) => {
                let credit = credit_cell
                    .lock()
                    .map(|c| c.clone())
                    .unwrap_or(alice_miner_core::CreditState::NotExposed);
                if let Some(t) = tui.as_mut() {
                    // In-place panel; a draw failure (terminal lost) falls back to the
                    // line renderer for the rest of the run rather than aborting.
                    if t.draw(&snap).is_err() {
                        tui = None;
                        emit_snapshot(&snap, args.json, &credit);
                    }
                } else {
                    emit_snapshot(&snap, args.json, &credit);
                }
                if matches!(snap.state, EngineState::Running) {
                    saw_running = true;
                }
                if requested_stop
                    && matches!(snap.state, EngineState::Idle | EngineState::Error)
                {
                    break;
                }
            }
            Ok(Event::Error(e)) => {
                if args.json {
                    println!("{}", serde_json::json!({ "error": e }));
                } else if tui.is_some() {
                    // Defer: print after the alt screen is gone.
                    deferred_error = Some(e);
                } else {
                    eprintln!("engine error: {e}");
                }
                exit_code = EXIT_RUNTIME;
                break;
            }
            Ok(_other) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // Nudge the engine for a fresh snapshot so the stream stays live.
                let _ = engine.send(EngineCommand::Poll);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }

        // In the TUI, the process-wide ctrlc handler may not fire while the terminal
        // is in raw mode, so also poll the panel for a quit key (q / Esc / Ctrl-C).
        let tui_quit = match tui.as_ref() {
            Some(t) => t.poll_quit(0).unwrap_or(false),
            None => false,
        };

        // Ctrl-C / SIGTERM, a TUI quit key, or the duration elapsed → request Stop once.
        let timed_out = deadline.map(|d| start.elapsed() >= d).unwrap_or(false);
        if !requested_stop && (stop_flag.load(Ordering::SeqCst) || tui_quit || timed_out) {
            if !args.json && tui.is_none() {
                print!("{}", dashboard::render_stopping_banner());
            }
            let _ = engine.send(EngineCommand::Stop);
            requested_stop = true;
        }
    }

    // Tear the TUI down (restore the terminal) BEFORE any post-loop printing so the
    // notes/errors land on the user's real shell, not the alternate screen.
    drop(tui);
    if let Some(e) = deferred_error {
        eprintln!("engine error: {e}");
    }

    // Best-effort: ensure the child is torn down on the way out (kill_on_drop is
    // the backstop). Then drop the pid file.
    engine.shutdown();
    drop(pid_guard);

    if exit_code == EXIT_OK && !saw_running {
        // We never reached Running — surface that as a soft failure for the
        // harness (e.g. the relay was unreachable from this context).
        if !args.json {
            eprintln!(
                "note: the lane never reached the Running state \
                 (the relay may be unreachable from here)."
            );
        }
    }
    exit_code
}

/// Emit one snapshot, either as a JSON line (`--json`) or rendered into the
/// human dashboard block. `credit` is the latest Source-B server-confirmed credit
/// state (cumulative accepted-share COUNTS); its honest line is appended to the
/// human block only (the `--json` stream is byte-for-byte unchanged — credit-only,
/// and a parser-facing schema we don't perturb).
fn emit_snapshot(snap: &Snapshot, json: bool, credit: &alice_miner_core::CreditState) {
    if json {
        // One compact JSON object per tick — credit-only by construction (the
        // Snapshot type has no payout field; a core test asserts the JSON shape).
        match serde_json::to_string(snap) {
            Ok(line) => println!("{line}"),
            Err(e) => eprintln!("error: failed to serialize snapshot: {e}"),
        }
    } else {
        print!("{}", dashboard::render_snapshot(snap));
        // The cumulative server-confirmed credit line (Source B), when there is one
        // to show (NotExposed yields None — no fabricated line).
        if let Some(line) = dashboard::render_credit_line(credit) {
            print!("{line}");
        }
    }
}

/// Resolve the `--lane` string to a [`Lane`]. `auto` → the device's recommended
/// lane. Returns the usage exit code on an unknown lane.
fn resolve_lane(s: &str, cap: &alice_miner_core::CapabilityProfile) -> Result<Lane, i32> {
    match s.to_ascii_lowercase().as_str() {
        "xmr" | "cpu" => Ok(Lane::Xmr),
        // `gpu` means the GPU **mainline** = PRL (pearlhash). `rvn` selects the
        // legacy KawPoW lane explicitly.
        "gpu" | "prl" => Ok(Lane::GpuPrl),
        // `alpha` = the AlphaMiner pearlhash lane (V100/Volta — where SRBMiner can't run).
        "alpha" => Ok(Lane::GpuAlpha),
        "rvn" => Ok(Lane::GpuRvn),
        "auto" => Ok(cap.recommended_lane()),
        other => {
            eprintln!("error: unknown lane `{other}` (use: xmr | gpu | prl | alpha | rvn | auto)");
            Err(EXIT_USAGE)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// stop
// ─────────────────────────────────────────────────────────────────────────────

fn cmd_stop(args: StopArgs) -> i32 {
    match pidfile::read_pid() {
        None => {
            eprintln!(
                "No running miner found (no pid file at {}).",
                pidfile::pid_path().display()
            );
            // Not an error per se, but non-zero so scripts can branch.
            EXIT_RUNTIME
        }
        Some(pid) if !pidfile::is_alive(pid) => {
            eprintln!("No running miner (stale pid {pid}); cleaning up.");
            pidfile::remove();
            EXIT_RUNTIME
        }
        Some(pid) => {
            println!("Stopping miner (pid {pid})…");
            match pidfile::stop_pid(pid, Duration::from_secs(args.timeout_s)) {
                pidfile::StopOutcome::Graceful => {
                    println!("Miner stopped cleanly.");
                    pidfile::remove();
                    EXIT_OK
                }
                pidfile::StopOutcome::Killed => {
                    println!("Miner did not exit in time; sent SIGKILL. No orphan left.");
                    pidfile::remove();
                    EXIT_OK
                }
                pidfile::StopOutcome::Error(e) => {
                    eprintln!("error: {e}");
                    EXIT_RUNTIME
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// shared helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Resolve a keystore passphrase, in order of preference:
///   1. `--password-stdin` → read the first line of STDIN (secure for scripts).
///   2. `--password <PASS>` → use it, but print a LOUD warning that it's visible
///      in `ps`/shell history (audit MED-5: deprecated, kept only for automation).
///   3. neither → prompt securely (no echo) via `rpassword`.
///
/// Never echoes the passphrase; the engine zeroizes it after use.
fn resolve_password(flag: Option<String>, from_stdin: bool) -> Result<String, String> {
    if from_stdin {
        use std::io::BufRead;
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| format!("failed to read passphrase from stdin: {e}"))?;
        // Strip exactly the trailing newline(s); a passphrase may contain spaces.
        let pw = line.trim_end_matches(['\n', '\r']).to_string();
        return if pw.is_empty() {
            Err("passphrase (stdin) must not be empty".into())
        } else {
            Ok(pw)
        };
    }
    if let Some(p) = flag {
        eprintln!(
            "warning: --password is INSECURE — it is visible in the process table (ps) and \
             your shell history. Use the interactive prompt (omit --password) or --password-stdin."
        );
        return if p.is_empty() {
            Err("passphrase must not be empty".into())
        } else {
            Ok(p)
        };
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

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    /// Clap wiring is sane: every subcommand + flag parses to the expected shape.
    /// (`try_parse_from` does NOT exit the process, so this is a pure check.)
    #[test]
    fn cli_parses_all_subcommands() {
        // detect (+ --json)
        let cli = Cli::try_parse_from(["alice-miner", "detect"]).unwrap();
        assert!(matches!(cli.command, Command::Detect(DetectArgs { json: false })));
        let cli = Cli::try_parse_from(["alice-miner", "detect", "--json"]).unwrap();
        assert!(matches!(cli.command, Command::Detect(DetectArgs { json: true })));

        // identity variants
        let cli = Cli::try_parse_from(["alice-miner", "identity", "--create"]).unwrap();
        match cli.command {
            Command::Identity(a) => {
                assert!(a.create && a.import.is_none() && !a.show);
            }
            _ => panic!("expected identity"),
        }
        let cli =
            Cli::try_parse_from(["alice-miner", "identity", "--import", "a b c"]).unwrap();
        match cli.command {
            Command::Identity(a) => assert_eq!(a.import.as_deref(), Some("a b c")),
            _ => panic!("expected identity"),
        }
        let cli =
            Cli::try_parse_from(["alice-miner", "identity", "--import-seed", "0xdead"]).unwrap();
        match cli.command {
            Command::Identity(a) => assert_eq!(a.import_seed.as_deref(), Some("0xdead")),
            _ => panic!("expected identity"),
        }
        let cli = Cli::try_parse_from(["alice-miner", "identity", "--paste", "addr"]).unwrap();
        match cli.command {
            Command::Identity(a) => assert_eq!(a.paste.as_deref(), Some("addr")),
            _ => panic!("expected identity"),
        }
        let cli = Cli::try_parse_from(["alice-miner", "identity", "--show"]).unwrap();
        match cli.command {
            Command::Identity(a) => assert!(a.show),
            _ => panic!("expected identity"),
        }

        // start defaults: lane=auto, no dual, no json.
        let cli = Cli::try_parse_from(["alice-miner", "start"]).unwrap();
        match cli.command {
            Command::Start(a) => {
                assert_eq!(a.lane, "auto");
                assert!(!a.dual && !a.json);
                assert_eq!(a.duration_s, 0);
                // A5b: no --gpus by default (→ GpuSelection::All at runtime).
                assert!(a.gpus.is_none());
            }
            _ => panic!("expected start"),
        }
        let cli = Cli::try_parse_from([
            "alice-miner", "start", "--lane", "xmr", "--dual", "--json", "--duration-s", "30",
        ])
        .unwrap();
        match cli.command {
            Command::Start(a) => {
                assert_eq!(a.lane, "xmr");
                assert!(a.dual && a.json);
                assert_eq!(a.duration_s, 30);
            }
            _ => panic!("expected start"),
        }

        // stop (+ default timeout)
        let cli = Cli::try_parse_from(["alice-miner", "stop"]).unwrap();
        match cli.command {
            Command::Stop(a) => assert_eq!(a.timeout_s, 8),
            _ => panic!("expected stop"),
        }
    }

    /// Mutually-exclusive identity flags are rejected by clap (e.g. --create with
    /// --paste), so the user can't ask for two contradictory things.
    #[test]
    fn conflicting_identity_flags_are_rejected() {
        assert!(Cli::try_parse_from(["alice-miner", "identity", "--create", "--paste", "x"]).is_err());
        assert!(Cli::try_parse_from(["alice-miner", "identity", "--show", "--create"]).is_err());
        assert!(Cli::try_parse_from(["alice-miner", "identity", "--import", "x", "--import-seed", "y"]).is_err());
    }

    /// Unknown subcommands / bad lanes are usage errors (clap rejects unknown
    /// subcommands; the lane string is validated at runtime in `resolve_lane`).
    #[test]
    fn unknown_subcommand_is_rejected() {
        assert!(Cli::try_parse_from(["alice-miner", "mine-everything"]).is_err());
    }

    /// A5b: `--gpus 0,1,2` parses to the raw string on `StartArgs`; absence leaves
    /// it `None` (→ `GpuSelection::All`). The string→`GpuSelection` mapping +
    /// malformed-input rejection is covered by the core `GpuSelection::parse_ids`
    /// tests; here we confirm the CLI flag itself parses and threads the value.
    #[test]
    fn start_gpus_flag_parses_and_maps_to_selection() {
        let cli = Cli::try_parse_from(["alice-miner", "start", "--gpus", "0,1,2"]).unwrap();
        match cli.command {
            Command::Start(a) => {
                assert_eq!(a.gpus.as_deref(), Some("0,1,2"));
                // The CLI maps a present, well-formed value to Ids in order.
                assert_eq!(
                    GpuSelection::parse_ids(a.gpus.as_deref().unwrap()).unwrap(),
                    GpuSelection::Ids(vec![0, 1, 2])
                );
            }
            _ => panic!("expected start"),
        }
        // Absent → None → All.
        let cli = Cli::try_parse_from(["alice-miner", "start"]).unwrap();
        match cli.command {
            Command::Start(a) => {
                assert!(a.gpus.is_none());
                let sel = match a.gpus.as_deref() {
                    None => GpuSelection::All,
                    Some(s) => GpuSelection::parse_ids(s).unwrap(),
                };
                assert_eq!(sel, GpuSelection::All);
            }
            _ => panic!("expected start"),
        }
        // A malformed value still PARSES at the clap layer (it's a free string);
        // the rejection happens in cmd_start via parse_ids (asserted in core).
        let cli = Cli::try_parse_from(["alice-miner", "start", "--gpus", "0,x"]).unwrap();
        match cli.command {
            Command::Start(a) => assert!(GpuSelection::parse_ids(a.gpus.as_deref().unwrap()).is_err()),
            _ => panic!("expected start"),
        }
    }

    #[test]
    fn resolve_lane_maps_aliases_and_auto() {
        let cap = alice_miner_core::CapabilityProfile::detect();
        assert_eq!(resolve_lane("xmr", &cap).unwrap(), Lane::Xmr);
        assert_eq!(resolve_lane("cpu", &cap).unwrap(), Lane::Xmr);
        // `gpu` now means the GPU mainline (PRL); `rvn` selects the legacy lane.
        assert_eq!(resolve_lane("gpu", &cap).unwrap(), Lane::GpuPrl);
        assert_eq!(resolve_lane("prl", &cap).unwrap(), Lane::GpuPrl);
        assert_eq!(resolve_lane("alpha", &cap).unwrap(), Lane::GpuAlpha);
        assert_eq!(resolve_lane("ALPHA", &cap).unwrap(), Lane::GpuAlpha);
        assert_eq!(resolve_lane("rvn", &cap).unwrap(), Lane::GpuRvn);
        assert_eq!(resolve_lane("AUTO", &cap).unwrap(), cap.recommended_lane());
        assert!(resolve_lane("bogus", &cap).is_err());
    }

    /// build_identity_spec maps each flag and errors when none is given.
    #[test]
    fn build_identity_spec_requires_a_mode() {
        // Paste needs no password.
        let spec =
            build_identity_spec(false, None, None, Some("addr".into()), None, None, false).unwrap();
        assert!(matches!(spec, IdentitySpec::Paste { .. }));
        // Create with an explicit password (no prompt in tests).
        let spec =
            build_identity_spec(true, None, None, None, None, Some("pw".into()), false).unwrap();
        assert!(matches!(spec, IdentitySpec::Create { .. }));
        // No mode → usage error.
        assert_eq!(
            build_identity_spec(false, None, None, None, None, None, false).unwrap_err(),
            EXIT_USAGE
        );
    }

    /// MED-5: `--password-stdin` parses and conflicts with `--password`, and the
    /// plain `--password` still parses (deprecated, not removed). The runtime
    /// stdin read is covered by the integration test (it needs a real stdin pipe).
    #[test]
    fn password_flags_parse_and_conflict() {
        // --password-stdin parses on its own.
        let cli = Cli::try_parse_from(["alice-miner", "identity", "--create", "--password-stdin"])
            .unwrap();
        match cli.command {
            Command::Identity(a) => {
                assert!(a.create && a.password_stdin && a.password.is_none());
            }
            _ => panic!("expected identity"),
        }
        // --password still parses (kept for automation, with a loud warning).
        let cli =
            Cli::try_parse_from(["alice-miner", "identity", "--create", "--password", "s3cret"])
                .unwrap();
        match cli.command {
            Command::Identity(a) => {
                assert_eq!(a.password.as_deref(), Some("s3cret"));
                assert!(!a.password_stdin);
            }
            _ => panic!("expected identity"),
        }
        // The two are mutually exclusive (you can't give both).
        assert!(Cli::try_parse_from([
            "alice-miner",
            "identity",
            "--create",
            "--password",
            "x",
            "--password-stdin",
        ])
        .is_err());
    }

    /// A non-empty `--password` flag is honored by `build_identity_spec` (the
    /// warning is printed to stderr; we just confirm the spec carries the pw).
    #[test]
    fn password_flag_is_honored_for_create() {
        let spec =
            build_identity_spec(true, None, None, None, None, Some("hunter2".into()), false).unwrap();
        match spec {
            IdentitySpec::Create { password, .. } => assert_eq!(password, "hunter2"),
            _ => panic!("expected Create"),
        }
    }
}
