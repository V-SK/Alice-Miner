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
//!   "credit · 积分 (credit-only)"; it NEVER prints `$`/fiat/`paid`/`earned`, and never the
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

mod color;
mod dashboard;
mod doctor;
mod fleet;
mod pidfile;
mod setup;
mod tui;

// ── Exit codes ──────────────────────────────────────────────────────────────
/// Success.
const EXIT_OK: i32 = 0;
/// Runtime / engine fault (spawn failed, relay unreachable, …).
const EXIT_RUNTIME: i32 = 1;
/// Usage / argument error (bad lane, no identity flag, dual refused, …).
const EXIT_USAGE: i32 = 2;

/// ONE crate-wide lock for every test that mutates the process-global
/// `$ALICE_IDENTITY_DIR` (or other shared env). Rust runs a crate's tests in
/// parallel, and these live in DIFFERENT modules (`pidfile`, `setup`), so a
/// module-local lock can't serialize them against each other — they'd race on the
/// shared env var. Funnel all of them through this single lock (the same discipline
/// `alice-miner-core` uses with its crate-wide `IDENTITY_ENV_LOCK`).
#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
        as the desktop app. Rewards accrue as credit (积分, credit-only); payout, settlement,\n\
        and on-chain transfer stay gated (phase-J).",
    propagate_version = true
)]
struct Cli {
    /// Disable ANSI color in the live dashboard (also honored: the `NO_COLOR` env
    /// var, `TERM=dumb`, and a non-TTY stdout). A global flag so it applies to any
    /// subcommand. `FORCE_COLOR` overrides all of these and forces color on.
    #[arg(long, global = true)]
    no_color: bool,

    /// The subcommand to run. OPTIONAL: with no subcommand, the binary auto-runs
    /// the `setup` wizard on a FIRST launch (no `~/.alice` identity AND an
    /// interactive TTY), and otherwise prints help — so a non-developer who just
    /// double-clicks / runs the bare binary is guided, while a script that pipes in
    /// gets the usual help (never an unexpected interactive prompt).
    #[command(subcommand)]
    command: Option<Command>,
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
        --json       emit one Snapshot JSON line per tick (suppresses the credit\n\
                     poller + all banners; see `start --help` for the full contract)\n\
        --plain      force the plain greppable line renderer + no color (clean logs)\n\
        \n\
        Ctrl-C (or `alice-miner stop`) stops gracefully. Rewards accrue as credit\n\
        (积分, credit-only); the collection address and upstream pool are never shown.")]
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
        Works on macOS (launchd LaunchAgent), Linux (systemd --user), and Windows\n\
        (Task Scheduler). The service definition itself carries NO secret and NO\n\
        reward address — the address is read from your ~/.alice identity at runtime.\n\
        \n\
        The CPU-XMR lane is secret-free, so it always backgrounds. A GPU pearlhash\n\
        lane (prl/alpha) also backgrounds, but needs an OS keyring (macOS Keychain /\n\
        Windows Credential Manager / Linux Secret Service) to hold the wallet unlock,\n\
        so it is REFUSED on a box with no keyring (e.g. a headless Linux rig — keep\n\
        the miner window open there, or background CPU-XMR instead).\n\
        \n\
        --install     install + start the background agent\n\
        --uninstall   stop + remove the background agent\n\
        --status      print whether it is installed / running (the default)\n\
        --lane xmr    the lane to background: xmr (secret-free) or a GPU pearlhash\n\
                      lane (prl/alpha/gpu/auto) whose unlock is stored in the keyring\n\
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

    /// Self-diagnose: PASS/FAIL per check + the EXACT fix (run this when stuck).
    #[command(long_about = "Run a preflight / on-stuck self-diagnostic and print, per check, a\n\
        PASS / WARN / FAIL line plus the EXACT fix when something is wrong. Collapses the\n\
        recurring issues (no identity, an unrunnable lane, a Volta card that can't run\n\
        SRBMiner, a missing engine, an unreachable relay, a headless box with no keyring,\n\
        Windows Defender / macOS App-Nap) into one self-serve screen.\n\
        \n\
        --lane <LANE>  scope the engine / relay / GPU checks to a lane (default: auto)\n\
        --json         emit the report as one JSON object (for scripting)\n\
        \n\
        Exits non-zero if any check FAILs, so a script can gate `start` on a clean\n\
        preflight. Diagnostics only — credit-only, never a secret or a reward amount.")]
    Doctor(DoctorArgs),

    /// Guided first-run wizard: hardware → address → (15% PRL) → start.
    #[command(long_about = "A guided setup wizard for the first 60 seconds: detect your hardware and\n\
        recommend a lane, set your reward address (paste an existing one or generate a new\n\
        identity, validated inline), optionally set your 15% PRL return address for a GPU\n\
        lane, confirm, and start mining.\n\
        \n\
        Every step has a flag so the WHOLE wizard runs non-interactively from a single\n\
        copy-paste line (what the website publishes):\n\
        \n\
            alice-miner setup --lane auto --address <alice-addr> --yes\n\
        \n\
        --lane <LANE>      the lane to use (default: the recommended one)\n\
        --address <ADDR>   your Alice reward address (skips the paste/generate prompt)\n\
        --generate         generate a NEW identity for the reward address (prints the\n\
                           mnemonic to back up; refuses to clobber an existing identity)\n\
        --prl-payout <P>   your 15% PRL return address (prl1p…) for a GPU lane\n\
        --yes              accept the confirmation without prompting\n\
        --no-input         never prompt (fail if a required value is missing) — for scripts\n\
        --start / --no-start  whether to begin mining at the end (default: ask / --yes = yes)\n\
        \n\
        Auto-runs on first launch ONLY when ~/.alice has no identity AND stdin is a TTY;\n\
        otherwise it does nothing. Re-runnable. Credit-only — never a secret in argv, and\n\
        the generate path warns + never silently overwrites an existing identity.")]
    Setup(SetupArgs),
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
    /// Emit one Snapshot JSON line per tick (for scripting) instead of the human
    /// dashboard. CONTRACT: `--json` SUPPRESSES the Source-B server-confirmed credit
    /// poller (the JSON stream is the engine Snapshot only — credit-only, no
    /// `paid_acu`/payout key) and emits NO human banners or hints. On a clean exit
    /// that NEVER reached Running, a final Snapshot is emitted with `message` set to
    /// a machine reason (e.g. "never_reached_running") so a harness gets a signal
    /// beyond exit 0. `ALICE_READ_API_URL` overrides the read-API endpoint the human
    /// (non-`--json`) credit poller queries; it is `https://`-only.
    #[arg(long)]
    json: bool,
    /// Plain greppable line mode: force the scrolling line renderer (never the
    /// in-place TUI panel) and disable ANSI color, for clean logs / `grep`. Implied
    /// off a non-TTY; this makes it explicit on a TTY too. Has no effect with
    /// `--json` (that stream is already machine-only).
    #[arg(long)]
    plain: bool,
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

#[derive(clap::Args)]
struct DoctorArgs {
    /// Scope the engine / relay / GPU checks to a lane (default: the recommended one).
    #[arg(long, default_value = "auto", value_name = "LANE")]
    lane: String,
    /// Emit the report as a single JSON object (machine-readable).
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args)]
struct SetupArgs {
    /// The lane to use (default: the recommended one for this device).
    #[arg(long, default_value = "auto", value_name = "LANE")]
    lane: String,
    /// Your Alice reward address (skips the paste/generate prompt). Validated as
    /// an SS58-300 Alice address before anything is written.
    #[arg(long, value_name = "ADDRESS", conflicts_with = "generate")]
    address: Option<String>,
    /// Generate a NEW identity for the reward address (prints the 24-word mnemonic
    /// to back up). REFUSES to clobber an existing identity (the keystore hazard).
    #[arg(long)]
    generate: bool,
    /// Your 15% PRL return address (`prl1p…`) for a GPU lane. Optional.
    #[arg(long, value_name = "PRL1")]
    prl_payout: Option<String>,
    /// Accept the confirmation summary without prompting.
    #[arg(long)]
    yes: bool,
    /// Never prompt — fail if a required value is missing (for non-interactive use).
    #[arg(long)]
    no_input: bool,
    /// Begin mining at the end of the wizard.
    #[arg(long, conflicts_with = "no_start")]
    start: bool,
    /// Do NOT begin mining at the end (just finish setup).
    #[arg(long)]
    no_start: bool,
    /// Keystore passphrase for `--generate` (INSECURE on the command line; prefer
    /// the prompt or `--password-stdin`).
    #[arg(long, value_name = "PASS")]
    password: Option<String>,
    /// Read the `--generate` keystore passphrase from the first line of STDIN.
    #[arg(long, conflicts_with = "password")]
    password_stdin: bool,
}

fn main() {
    let cli = Cli::parse();
    let no_color = cli.no_color;
    let code = match cli.command {
        Some(Command::Detect(args)) => cmd_detect(args),
        Some(Command::GpuDevices(args)) => cmd_gpu_devices(args),
        Some(Command::Identity(args)) => cmd_identity(args),
        Some(Command::Start(args)) => cmd_start(args, no_color),
        Some(Command::Stop(args)) => cmd_stop(args),
        Some(Command::Service(args)) => cmd_service(args),
        Some(Command::Fleet(args)) => fleet::run(
            &args.paths,
            args.once,
            std::time::Duration::from_secs(args.interval_s.max(1)),
        ),
        Some(Command::Doctor(args)) => cmd_doctor(args),
        Some(Command::Setup(args)) => setup::run(args.into(), no_color),
        // No subcommand: guide a first-launch user (auto-setup when ~/.alice has no
        // identity AND stdin is a TTY), else print help. Skips silently otherwise.
        None => cmd_no_subcommand(no_color),
    };
    std::process::exit(code);
}

/// The bare-binary path (no subcommand). On a FIRST launch — no `~/.alice`
/// identity AND an interactive stdin TTY — auto-run the guided `setup` wizard.
/// Otherwise print the top-level help (a script piping in, or an already-set-up
/// user who just typed the bare command, gets help, never a surprise prompt).
fn cmd_no_subcommand(no_color: bool) -> i32 {
    use std::io::IsTerminal;
    let has_identity = alice_miner_core::identity::load_pointer().is_some();
    let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    if !has_identity && interactive {
        // First launch, interactive → guide them through setup.
        return setup::run(setup::SetupConfig::first_launch(), no_color);
    }
    // Otherwise: print help and exit cleanly (clap renders the long help).
    use clap::CommandFactory;
    let mut cmd = Cli::command();
    let _ = cmd.print_help();
    println!();
    EXIT_OK
}

/// `doctor`: run the self-diagnostic battery for the resolved lane and print the
/// report (human or `--json`). Exits non-zero if any check FAILs so a script can
/// gate `start` on a clean preflight.
fn cmd_doctor(args: DoctorArgs) -> i32 {
    let cap = alice_miner_core::CapabilityProfile::detect();
    let lane = match resolve_lane(&args.lane, &cap) {
        Ok(l) => l,
        Err(code) => return code,
    };
    let checks = doctor::run_checks(lane, &cap);
    if args.json {
        println!("{}", doctor::render_json(&checks, lane));
    } else {
        print!("{}", doctor::render_report(&checks, lane));
    }
    if doctor::has_blocking_failure(&checks) {
        EXIT_USAGE
    } else {
        EXIT_OK
    }
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
            if !args.json {
                print!("{}", next_steps_after_service_install());
            }
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
                // Next-step hint (onboarding): the user now has a reward identity,
                // so point them straight at mining. Human path only (the --json
                // stream stays machine-clean). Credit-only — no payout wording.
                print!("{}", next_steps_after_identity(&identity));
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

fn cmd_start(args: StartArgs, no_color: bool) -> i32 {
    cmd_start_with_unlock(args, no_color, None)
}

/// `cmd_start` with an OPTIONAL pre-resolved keystore passphrase for a pearlhash
/// lane's unlock. `prefetched_unlock` is `Some` only from the setup wizard's
/// generate-then-start handoff (NIT B): the passphrase that just created the keystore
/// is reused to unlock it, so the user is not prompted a SECOND time for the same
/// secret. It is `Zeroizing` (scrubbed on drop), arrives ONLY through this in-process
/// argument (NEVER via argv / `StartArgs.password`), and is never logged. `None` (every
/// other start) preserves the existing prompt/stdin/keyring resolution exactly.
fn cmd_start_with_unlock(
    args: StartArgs,
    no_color: bool,
    prefetched_unlock: Option<Zeroizing<String>>,
) -> i32 {
    // Resolve the color / TUI decision ONCE (NO_COLOR / --no-color / TERM=dumb /
    // FORCE_COLOR + the TTY check). Drives both whether the in-place panel is used
    // and whether the line renderer emits ANSI — so a journal / pipe stays clean.
    let color_env = color::ColorEnv::detect(no_color);
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
                 `alice-miner service --uninstall` first, then run start — or just let the \
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

    // Light preflight (a subset of `doctor`): surface the first BLOCKING issue (e.g.
    // an unreachable relay / missing engine the viability gate doesn't catch) to
    // stderr before we spawn, with the exact fix + a pointer to `doctor`. Human path
    // only (the --json stream stays machine-clean); best-effort, never blocks mining.
    if !args.json {
        doctor::print_preflight_summary(lane, &cap);
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
                     — re-run `alice-miner service --install --lane {}`.",
                    lane.cli_lane_arg()
                );
                return EXIT_RUNTIME;
            }
            Err(e) => {
                eprintln!("error: {e}");
                return EXIT_RUNTIME;
            }
        }
    } else if let Some(pw) = prefetched_unlock {
        // NIT B: the setup wizard just created this keystore and handed us its
        // passphrase — unlock with it instead of prompting a SECOND time for the same
        // secret. Consumed here (zeroized on drop); it never reached argv or a log.
        Some(pw.as_str().to_string())
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
    //   * non-TTY, !json   → the plain scrolling line renderer (piped / CI / a
    //                        launchd|systemd journal — kept clean + greppable).
    //   * interactive TTY  → the in-place ratatui panel (falls back to the line
    //                        renderer if the terminal can't enter raw mode).
    // The `--json` output is byte-for-byte unchanged in every case. `use_tui()` is
    // FALSE off a TTY (and under TERM=dumb), so a non-TTY never gets screen-paint
    // escapes — even under FORCE_COLOR (a pipe isn't a screen). `--plain` forces the
    // scrolling line renderer (never the in-place panel) and drops color, for clean
    // greppable logs even on an interactive TTY.
    let interactive = !args.json && !args.plain && color_env.use_tui();
    let mut tui = if interactive { tui::Tui::new().ok() } else { None };
    // Whether the plain line renderer emits ANSI color (semaphore + heartbeat). Only
    // meaningful for the line path; the TUI does its own coloring. `--plain` forces
    // color OFF regardless of the env decision.
    let line_color = !args.plain && color_env.color_enabled();

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
    // Heartbeat + staleness state for the line renderer: a spinner frame that advances
    // every emitted tick, and the instant the stream last ADVANCED (a real activity
    // change). When the stream stops advancing, the rendered "no update Ns" chip grows
    // — the App-Nap "process alive but wedged" tell. (The TUI tracks its own.)
    let mut spinner_frame: u64 = 0;
    let mut last_advance = std::time::Instant::now();
    let mut prev_fingerprint: Option<(u64, u64, u64, u64)> = None;
    // The most recent Snapshot seen this run. Reused (only `message` is set) to emit
    // a TERMINAL `--json` Snapshot carrying a machine reason when the lane never
    // reached Running — so a CI/harness gets a signal beyond exit 0.
    let mut last_snapshot: Option<Snapshot> = None;

    loop {
        match engine.recv_timeout(Duration::from_millis(500)) {
            Ok(Event::Snapshot(snap)) => {
                let credit = credit_cell
                    .lock()
                    .map(|c| c.clone())
                    .unwrap_or(alice_miner_core::CreditState::NotExposed);
                // Advance detection: a coarse fingerprint of the live activity. When it
                // changes, the stream advanced (reset the staleness clock); when it
                // doesn't, `stale_for_s` keeps growing and the chip lights up.
                let fp = snapshot_fingerprint(&snap);
                if prev_fingerprint != Some(fp) {
                    prev_fingerprint = Some(fp);
                    last_advance = std::time::Instant::now();
                }
                let ctx = dashboard::RenderCtx {
                    spinner_frame,
                    stale_for_s: Some(last_advance.elapsed().as_secs()),
                    color: line_color,
                };
                spinner_frame = spinner_frame.wrapping_add(1);
                if let Some(t) = tui.as_mut() {
                    // In-place panel; a draw failure (terminal lost) falls back to the
                    // line renderer for the rest of the run rather than aborting.
                    if t.draw(&snap).is_err() {
                        tui = None;
                        emit_snapshot(&snap, args.json, &credit, &ctx);
                    }
                } else {
                    emit_snapshot(&snap, args.json, &credit, &ctx);
                }
                if matches!(snap.state, EngineState::Running) {
                    // First transition into Running: print the background-service tip
                    // + the 15%-PRL nudge (human path only — never on --json, never in
                    // the in-place TUI, which has no scrollback for one-shot hints).
                    if !saw_running && !args.json && tui.is_none() {
                        print!("{}", next_steps_after_running(lane));
                        if let Some(nudge) = prl_payout_nudge(lane) {
                            print!("{nudge}");
                        }
                    }
                    saw_running = true;
                }
                last_snapshot = Some(snap.clone());
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
        if args.json {
            // Structured terminal Snapshot: reuse the last one seen (real terminal
            // state — Idle/Error/Starting), tagging `message` with a MACHINE reason so
            // a harness gets a signal beyond exit 0. Still credit-only (a Snapshot has
            // no payout field; we only set the existing `message`). Skipped if no
            // snapshot was ever seen (nothing to base it on).
            if let Some(mut snap) = last_snapshot {
                snap.message = Some(TERMINAL_REASON_NEVER_RUNNING.to_string());
                emit_snapshot(
                    &snap,
                    true,
                    &alice_miner_core::CreditState::NotExposed,
                    &dashboard::RenderCtx { spinner_frame: 0, stale_for_s: None, color: false },
                );
            }
        } else {
            eprintln!(
                "note: the lane never reached the Running state \
                 (the relay may be unreachable from here)."
            );
        }
    }
    exit_code
}

/// The `message` reason set on the terminal `--json` Snapshot when a run exited
/// cleanly without ever reaching Running (a CI/harness signal beyond exit 0). A
/// stable, machine-grep-able token — credit-only (it is a status reason, not a
/// reward field).
const TERMINAL_REASON_NEVER_RUNNING: &str = "never_reached_running";

/// Emit one snapshot, either as a JSON line (`--json`) or rendered into the
/// human dashboard block. `credit` is the latest Source-B server-confirmed credit
/// state (cumulative accepted-share COUNTS); its honest line is appended to the
/// human block only (the `--json` stream is byte-for-byte unchanged — credit-only,
/// and a parser-facing schema we don't perturb). `ctx` carries the per-tick heartbeat
/// frame + staleness + color decision for the human block (ignored for `--json`).
fn emit_snapshot(
    snap: &Snapshot,
    json: bool,
    credit: &alice_miner_core::CreditState,
    ctx: &dashboard::RenderCtx,
) {
    if json {
        // One compact JSON object per tick — credit-only by construction (the
        // Snapshot type has no payout field; a core test asserts the JSON shape).
        match serde_json::to_string(snap) {
            Ok(line) => println!("{line}"),
            Err(e) => eprintln!("error: failed to serialize snapshot: {e}"),
        }
    } else {
        print!("{}", dashboard::render_snapshot_ctx(snap, ctx));
        // The cumulative server-confirmed credit line (Source B), when there is one
        // to show (NotExposed yields None — no fabricated line).
        if let Some(line) = dashboard::render_credit_line(credit) {
            print!("{line}");
        }
        // The credited-vs-raw divergence note: a healthy local hashrate while the
        // server confirms 0 credited shares = the "hashing but not landing" bug made
        // visible. Counts/rates only, never fiat; fires only on a confirmed read.
        if let Some(note) = dashboard::render_credited_vs_raw_note(snap, credit) {
            print!("{note}");
        }
    }
}

/// A coarse activity fingerprint of a snapshot used to detect whether the stream
/// ADVANCED between ticks (drives the line dashboard's "no update Ns" staleness
/// chip). Folds the fields that move on a live, healthy stream — uptime, the share
/// counts, and a quantized hashrate — so a wedged miner (process alive, stream
/// frozen) reads as "not advancing". Credit-only (counts only, never a reward).
fn snapshot_fingerprint(snap: &Snapshot) -> (u64, u64, u64, u64) {
    let hr_q = snap.hashrate_hs.map(|h| h as u64).unwrap_or(0);
    (snap.uptime_s, snap.shares_accepted, snap.shares_rejected, hr_q)
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

// ─────────────────────────────────────────────────────────────────────────────
// Onboarding hints (Theme 2 #8) — the first-60-seconds guidance the website now
// funnels a non-developer audience into. Every hint is plain activity guidance:
// CREDIT-ONLY (no $/paid/earned/payout-amount), and it never prints a secret or a
// server address. Returned as Strings (printed by the human path only) so they are
// unit-testable without capturing stdout.
// ─────────────────────────────────────────────────────────────────────────────

/// After an identity is established (`identity --create`/`--import`/`--paste`):
/// the user now has a reward address, so point them straight at mining. A
/// watch-only (pasted) identity can still mine to its own address.
fn next_steps_after_identity(_identity: &alice_miner_core::Identity) -> String {
    "\nNext: start mining to this address\n  alice-miner start\n".to_string()
}

/// After `start` reaches the Running state: tell the user how to keep mining in
/// the background after they close the window. The lane token is the SAME one
/// `service --install --lane <lane>` accepts, so the line is copy-paste ready.
fn next_steps_after_running(lane: Lane) -> String {
    format!(
        "\nTip: to keep mining after you close this window, install the background service:\n  \
         alice-miner service --install --lane {}\n",
        lane.cli_lane_arg()
    )
}

/// On a GPU (pearlhash) lane with NO 15%-PRL return address configured: surface
/// the 15% PRL return (advertised on the website but otherwise buried as an
/// `identity` sub-flag). Returns `None` when the lane doesn't earn the return, or
/// when a return address is already set / can't be read. Credit-only: it offers
/// to set an ADDRESS to enroll, never implies a paid amount.
fn prl_payout_nudge(lane: Lane) -> Option<String> {
    if !lane.is_prl_lane() {
        return None;
    }
    // Already set (or unreadable) → no nudge. `load_payout_address` returns
    // Ok(Some) when set, Ok(None) when unset; an Err (typo on disk) we treat as
    // "don't nag" since the existing show/set path surfaces that.
    match alice_miner_core::prl_payout::load_payout_address() {
        Ok(Some(_)) => None,
        Ok(None) => Some(
            "\nThis GPU lane earns the 15% PRL return. To claim it, set your PRL return address:\n  \
             alice-miner identity --set-prl-payout <prl1p…>\n"
                .to_string(),
        ),
        Err(_) => None,
    }
}

/// After `service --install` succeeds: how to check status / uninstall, so the
/// user isn't left guessing whether the background agent took.
fn next_steps_after_service_install() -> String {
    "\nCheck it any time:   alice-miner service --status\n\
     Stop background mining: alice-miner service --uninstall\n"
        .to_string()
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
        assert!(matches!(cli.command, Some(Command::Detect(DetectArgs { json: false }))));
        let cli = Cli::try_parse_from(["alice-miner", "detect", "--json"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Detect(DetectArgs { json: true }))));

        // identity variants
        let cli = Cli::try_parse_from(["alice-miner", "identity", "--create"]).unwrap();
        match cli.command.unwrap() {
            Command::Identity(a) => {
                assert!(a.create && a.import.is_none() && !a.show);
            }
            _ => panic!("expected identity"),
        }
        let cli =
            Cli::try_parse_from(["alice-miner", "identity", "--import", "a b c"]).unwrap();
        match cli.command.unwrap() {
            Command::Identity(a) => assert_eq!(a.import.as_deref(), Some("a b c")),
            _ => panic!("expected identity"),
        }
        let cli =
            Cli::try_parse_from(["alice-miner", "identity", "--import-seed", "0xdead"]).unwrap();
        match cli.command.unwrap() {
            Command::Identity(a) => assert_eq!(a.import_seed.as_deref(), Some("0xdead")),
            _ => panic!("expected identity"),
        }
        let cli = Cli::try_parse_from(["alice-miner", "identity", "--paste", "addr"]).unwrap();
        match cli.command.unwrap() {
            Command::Identity(a) => assert_eq!(a.paste.as_deref(), Some("addr")),
            _ => panic!("expected identity"),
        }
        let cli = Cli::try_parse_from(["alice-miner", "identity", "--show"]).unwrap();
        match cli.command.unwrap() {
            Command::Identity(a) => assert!(a.show),
            _ => panic!("expected identity"),
        }

        // start defaults: lane=auto, no dual, no json.
        let cli = Cli::try_parse_from(["alice-miner", "start"]).unwrap();
        match cli.command.unwrap() {
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
        match cli.command.unwrap() {
            Command::Start(a) => {
                assert_eq!(a.lane, "xmr");
                assert!(a.dual && a.json);
                assert_eq!(a.duration_s, 30);
            }
            _ => panic!("expected start"),
        }

        // stop (+ default timeout)
        let cli = Cli::try_parse_from(["alice-miner", "stop"]).unwrap();
        match cli.command.unwrap() {
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
        match cli.command.unwrap() {
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
        match cli.command.unwrap() {
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
        match cli.command.unwrap() {
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
        match cli.command.unwrap() {
            Command::Identity(a) => {
                assert!(a.create && a.password_stdin && a.password.is_none());
            }
            _ => panic!("expected identity"),
        }
        // --password still parses (kept for automation, with a loud warning).
        let cli =
            Cli::try_parse_from(["alice-miner", "identity", "--create", "--password", "s3cret"])
                .unwrap();
        match cli.command.unwrap() {
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

    /// The onboarding hints carry the RIGHT next command and the right lane token,
    /// and stay credit-only (no $/paid/earned/payout-amount wording, no secret).
    #[test]
    fn onboarding_hints_are_actionable_and_credit_only() {
        let id = alice_miner_core::Identity {
            address: "a2test".into(),
            pubkey: None,
            keystore_path: None,
            watch_only: false,
        };
        let after_id = next_steps_after_identity(&id);
        assert!(after_id.contains("alice-miner start"), "points at start: {after_id}");

        // The background tip uses the SAME --lane token `service --install` accepts.
        for lane in [Lane::Xmr, Lane::GpuPrl, Lane::GpuAlpha, Lane::GpuRvn] {
            let tip = next_steps_after_running(lane);
            assert!(
                tip.contains(&format!("service --install --lane {}", lane.cli_lane_arg())),
                "{lane:?} tip must use its cli lane token: {tip}"
            );
        }

        let svc = next_steps_after_service_install();
        assert!(svc.contains("service --status"));
        assert!(svc.contains("service --uninstall"));

        // Credit-only honesty across every hint string + the PRL nudge text. The
        // nudge offers an ADDRESS to enroll — never a paid figure.
        let nudge = "\nThis GPU lane earns the 15% PRL return. To claim it, set your PRL return address:\n  \
             alice-miner identity --set-prl-payout <prl1p…>\n"
            .to_string();
        let all = format!("{after_id}{}{svc}{nudge}", next_steps_after_running(Lane::GpuPrl));
        let lower = all.to_ascii_lowercase();
        for forbidden in ["$", "usd", "fiat", "paid", "earned", "待发放", "已发放"] {
            assert!(!lower.contains(forbidden), "hint leaked forbidden token `{forbidden}`: {all}");
        }
    }

    /// The 15%-PRL nudge fires only on a pearlhash lane AND only when no return
    /// address is configured. Drive the "set" branch via the env override so the
    /// test never touches the real `~/.alice` file.
    #[test]
    fn prl_nudge_only_for_unset_gpu_lane() {
        // XMR / RVN never nudge (they don't earn the 15% return).
        assert!(prl_payout_nudge(Lane::Xmr).is_none());
        assert!(prl_payout_nudge(Lane::GpuRvn).is_none());

        // A pearlhash lane with a configured return address → no nudge.
        let _g = PRL_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var(alice_miner_core::prl_payout::ENV_PAYOUT_ADDRESS).ok();
        std::env::set_var(
            alice_miner_core::prl_payout::ENV_PAYOUT_ADDRESS,
            format!("prl1p{}", "q".repeat(30)),
        );
        assert!(prl_payout_nudge(Lane::GpuPrl).is_none(), "set address → no nudge");
        // Cleared → the nudge appears for a pearlhash lane.
        std::env::remove_var(alice_miner_core::prl_payout::ENV_PAYOUT_ADDRESS);
        let nudge = prl_payout_nudge(Lane::GpuPrl).expect("unset GPU lane nudges");
        assert!(nudge.contains("--set-prl-payout"), "nudge gives the exact flag: {nudge}");
        assert!(nudge.contains("15% PRL"), "nudge names the 15% return: {nudge}");
        match prev {
            Some(v) => std::env::set_var(alice_miner_core::prl_payout::ENV_PAYOUT_ADDRESS, v),
            None => std::env::remove_var(alice_miner_core::prl_payout::ENV_PAYOUT_ADDRESS),
        }
    }

    /// Serialize the PRL payout-env tests (process env is global).
    static PRL_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// `--plain` parses on `start` and defaults off; the `--json` contract docs
    /// don't change its parsing (both can coexist on the args struct).
    #[test]
    fn start_plain_flag_parses_and_defaults_off() {
        let cli = Cli::try_parse_from(["alice-miner", "start"]).unwrap();
        match cli.command.unwrap() {
            Command::Start(a) => assert!(!a.plain, "plain defaults off"),
            _ => panic!("expected start"),
        }
        let cli = Cli::try_parse_from(["alice-miner", "start", "--plain"]).unwrap();
        match cli.command.unwrap() {
            Command::Start(a) => assert!(a.plain),
            _ => panic!("expected start"),
        }
        // --plain + --json coexist (plain is a no-op under json; parsing is permissive).
        let cli = Cli::try_parse_from(["alice-miner", "start", "--plain", "--json"]).unwrap();
        match cli.command.unwrap() {
            Command::Start(a) => assert!(a.plain && a.json),
            _ => panic!("expected start"),
        }
    }

    /// The terminal `--json` reason is a stable machine token AND is credit-only:
    /// a Snapshot carrying it in `message` still serializes with NO payout/paid key.
    #[test]
    fn terminal_never_running_reason_is_credit_only() {
        assert_eq!(TERMINAL_REASON_NEVER_RUNNING, "never_reached_running");
        // Build a minimal terminal-shaped Snapshot via JSON (the struct's fields are
        // additive + skip-when-None) so we exercise the real serialized wire form.
        let snap = alice_miner_core::Snapshot {
            state: EngineState::Idle,
            device: None,
            lane: Some(Lane::GpuPrl),
            hashrate_hs: None,
            hashrate_60s_hs: None,
            hashrate_15m_hs: None,
            shares_accepted: 0,
            shares_rejected: 0,
            endpoint: None,
            worker_id: None,
            uptime_s: 0,
            failovers: 0,
            dual: false,
            lanes: vec![],
            last_line: None,
            message: Some(TERMINAL_REASON_NEVER_RUNNING.to_string()),
            prl_payout: None,
        };
        let wire = serde_json::to_string(&snap).unwrap();
        assert!(wire.contains("never_reached_running"), "reason present: {wire}");
        let lower = wire.to_ascii_lowercase();
        for forbidden in ["paid_acu", "payout", "\"paid\"", "earned", "fiat"] {
            assert!(!lower.contains(forbidden), "terminal snapshot leaked `{forbidden}`: {wire}");
        }
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
