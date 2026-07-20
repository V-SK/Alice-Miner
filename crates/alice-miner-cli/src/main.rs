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
use alice_miner_core::i18n::{self, Lang};
use alice_miner_core::tr;
use alice_miner_core::{EngineHandle, EngineState, GpuSelection, Lane, Snapshot};

mod ai;
mod balance;
mod color;
mod companion;
mod dashboard;
mod doctor;
mod errmsg;
mod fleet;
mod guide;
mod logo;
mod menu;
mod pidfile;
mod region;
mod setup;
mod train;
mod tui;
mod update;

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

    /// UI language for messages: `en` (English) or `zh` (中文). A global flag so it
    /// applies to any subcommand. When passed it is remembered (`~/.alice/settings.json`)
    /// so later runs default to it. Without it: the saved preference, else a first-run
    /// prompt on an interactive terminal, else the `LANG`/`LC_ALL` env, else English.
    #[arg(long = "lang", visible_alias = "language", global = true, value_name = "LANG")]
    lang: Option<String>,

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

    /// Help me choose: detect hardware → recommend a lane → how to connect.
    #[command(long_about = "A read-only ADVISOR for the question \"what should I mine, and how do I\n\
        connect?\". It detects your hardware (CPU / GPU), recommends a lane (GPU → PRL or\n\
        Alpha; CPU → XMR) with one sentence of why, and gives the next step TWO ways:\n\
        \n\
          * mine with the OFFICIAL bundled client (`alice-miner setup` / `start`), or\n\
          * bring your OWN third-party miner — the exact stratum connection parameters\n\
            (pool host:port, algorithm, login), and — for the possession-proof-gated\n\
            pearlhash lanes — a pointer at `alice-miner companion` (which holds the proof\n\
            so your key never leaves this box).\n\
        \n\
        Unlike `setup`, `guide` only EXPLAINS — it needs no identity and writes nothing.\n\
        --json emits the advice as one object (for the website). Credit-only.")]
    Guide(GuideArgs),

    /// Companion: hold the possession proof for your OWN pearlhash miner (no mining).
    #[command(long_about = "Hold the M4 possession proof for a BRING-YOUR-OWN (third-party, closed-\n\
        source) pearlhash miner — WITHOUT running any miner. The PRL/Alpha relays require a\n\
        proof-of-possession; the official client proves it internally, but a third-party rig\n\
        can't. This companion does it for it: it unlocks your Alice key LOCALLY and runs the\n\
        same /m4/challenge → sign → /m4/verify handshake on a refresh loop (inside the relay's\n\
        ~1800s allowlist TTL), keeping `(your address, device)` authorized.\n\
        \n\
        You then point your own rig at the SAME region relay with the login\n\
        `<your-address>.<device>` and any password; the relay credits the shares to your\n\
        address. Your private key NEVER leaves this machine.\n\
        \n\
        --lane prl|alpha    which pearlhash relay to enroll against (default: prl)\n\
        --device <NAME>     the worker label your rig logs in with (default: a hostname)\n\
        --region us|asia|eu pin the region relay (default: remembered / nearest)\n\
        --address <ADDR>    the address to enroll — MUST be this box's signing identity\n\
                            (not a way to enroll a different address; switch identity for that)\n\
        --refresh-secs <N>  re-enroll cadence (default ~9 min; clamped inside the TTL)\n\
        --once              enroll once and exit (prime the allowlist / scripting)\n\
        --duration-s <N>    stop after N seconds (0 = until Ctrl-C)\n\
        \n\
        It NEVER spawns a miner. Credit-only — it prints no secret and no earnings figure.")]
    Companion(CompanionArgs),

    /// Run as an AI inference STAGE: join the Alice pipeline-parallel swarm.
    #[command(long_about = "Run this GPU as a pipeline-parallel INFERENCE STAGE coordinated by the\n\
        Alice scheduling center. The miner registers its public endpoint + free VRAM with the\n\
        center (proving it owns the reward address), heartbeats to stay in the pool, and — once\n\
        the center places it into a formed swarm — runs the shard engine as its stage (loading\n\
        its layer range and serving the pipeline).\n\
        \n\
        --center-url <URL>   the acp gateway base URL (default: the production gateway)\n\
        --endpoint <H:PORT>  the PUBLIC host:port this stage listens on (required; the address\n\
                             the swarm dials — set up port-forwarding/NAT so peers can reach it)\n\
        --engine-dir <DIR>   path to your alice-shard-engine checkout (must contain\n\
                             phase0/pipeline.py; also honored: ALICE_SHARD_ENGINE_PATH)\n\
        --python <PATH>      the python3 interpreter to run the engine (default: python3)\n\
        --vram-gb <GB>       free VRAM to advertise (default: auto-detect via nvidia-smi)\n\
        --region <R>         optional region hint (for locality)\n\
        --allow-cpu          run without an NVIDIA GPU (for testing — a real stage needs a GPU)\n\
        --stake-ref <REF>    stake reference for the sybil gate (default: enroll:<address>)\n\
        \n\
        The shared swarm key rides the SHARD_PSK environment variable (never the command line);\n\
        set it before starting. Ctrl-C stops gracefully (the engine subprocess is killed).\n\
        Credit-only (积分): the ai role serves inference for credit; it shows no hashrate and no\n\
        earnings. Re-runnable: resolved flags are saved so a bare `alice-miner ai` replays them.")]
    Ai(AiArgs),

    /// Run as an RLVR TRAINING worker: lease a coding task, solve it, submit it.
    #[command(long_about = "Run this GPU as an RLVR TRAINING worker coordinated by the Alice training\n\
        coordinator. The miner registers its reward address (proving it owns it), LEASES one coding\n\
        task (a prompt + entry point; the hidden tests never leave the coordinator), produces a\n\
        CANDIDATE solution with your own GPU/model, and SUBMITS it — the coordinator re-executes it\n\
        against the hidden tests and (credit-only) folds a credit weight. Loops back to lease.\n\
        \n\
        --center-url <URL>    the acp gateway base URL (default: the production gateway)\n\
        --trainer-dir <DIR>   path to your training-mint-m0 checkout (must contain run_m0.py +\n\
                              code_exec.py; also honored: ALICE_TRAIN_TRAINER_PATH)\n\
        --python <PATH>       the python3 interpreter to run the generator (default: python3)\n\
        --base-model <ID>     the base model to generate candidates with (HF id or local path)\n\
        --device <DEV>        the device the generation runs on: cuda | cpu | mps (default: cuda)\n\
        --allow-cpu           auto-downshift to CPU when no NVIDIA GPU is present (for testing —\n\
                              a real training worker needs a GPU)\n\
        --region <R>          optional region hint (for locality)\n\
        --stake-ref <REF>     stake reference for the sybil gate (default: enroll:<address>)\n\
        \n\
        The candidate generator reuses the M0 harness's OWN model loader + prompt renderer (imported\n\
        from your trainer dir) so its precision can never drift from the harness. Ctrl-C stops\n\
        gracefully. Credit-only (积分): the train role trains for credit; it shows no hashrate and no\n\
        earnings. Re-runnable: resolved flags are saved so a bare `alice-miner train` replays them.")]
    Train(TrainArgs),

    /// Set or show the UI language (`en` / `zh`), persisted for later runs.
    #[command(long_about = "Set or show the UI language for the headless CLI, persisted to\n\
        ~/.alice/settings.json so every later run defaults to it.\n\
        \n\
        alice-miner lang        print the current language\n\
        alice-miner lang en     switch to English\n\
        alice-miner lang zh     switch to 中文\n\
        \n\
        The global `--lang <en|zh>` flag does the same for a single run (and also\n\
        persists when passed explicitly).")]
    Lang(LangArgs),

    /// Show your THREE reward buckets: credit (积分), PRL rebate, and ALICE token.
    #[command(long_about = "Show the three honest reward buckets for your Alice address (or\n\
        --address), by querying the PUBLIC read API (credit-only, no secret):\n\
        \n\
        Credit (积分)        credit-only points from AI + credit mining (a cumulative\n\
                            accepted-share count). Converts to ALICE at the real-money launch.\n\
        PRL rebate          the REAL 15% pearlhash return (returned crypto) to your prl1p\n\
                            address — its binding + accrual state (the amount is off until\n\
                            payout is enabled; never a fabricated number).\n\
        ALICE (real token)  the REAL on-chain token. Not exposed on-chain pre-launch, so it\n\
                            shows the honest pending state — never a fabricated balance.\n\
        \n\
        --address <ADDR>  look up an address other than the active identity (watch-only OK)\n\
        --json            emit the three buckets as one JSON object (nulls where unknown)\n\
        \n\
        Credit is credit-only (not cash); PRL is real returned crypto; ALICE is the real\n\
        token (pending launch). An offline / unreachable read API is reported clearly.")]
    Balance(balance::BalanceArgs),

    /// Check for a newer signed version and (with consent) apply it.
    #[command(long_about = "Check for a newer signed release and, with your consent, apply it —\n\
        using the SAME ed25519-signed manifest + SHA-256-verified artifact + atomic-swap\n\
        pipeline the desktop app uses. NEVER auto-applies without consent.\n\
        \n\
        alice-miner update           check → if newer, show it and ask before applying\n\
        alice-miner update --check   check + report (current vs latest + notes) only\n\
        alice-miner update --yes     check → apply a newer version without prompting\n\
        \n\
        A non-blocking startup check also prints a one-line 'new version available' banner\n\
        on `start` / `ai` (cached ~6h; opt out with ALICE_MINER_NO_UPDATE_CHECK=1). The\n\
        check never blocks or delays mining.")]
    Update(update::UpdateArgs),
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
    /// Volta/V100 path, where SRBMiner can't run), or `auto`. (The `rvn`/KawPoW lane
    /// is not yet released — coming in M7.)
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
    /// PIN the GPU-PRL region: `us`, `asia`, or `eu`. LOCKS the lane to that region —
    /// it never auto-fails-over to another region; if the region is unreachable it
    /// retries that one and reports a clear error. The choice is REMEMBERED (persisted
    /// to `~/.alice/settings.json`), so later runs stay on it. Pass `--region auto` to
    /// CLEAR the lock and return to automatic (nearest region, with auto-failover). OMIT
    /// the flag to keep whatever was remembered. With no lock and no history the lane
    /// picks the nearest region (unchanged default). Only affects the GPU-PRL lane.
    #[arg(long, value_name = "REGION")]
    region: Option<String>,
    /// Internal marker set on the invocation the BACKGROUND SERVICE runs, so the
    /// single-owner check below doesn't make the agent refuse to start itself.
    /// Not for manual use. Hidden.
    #[arg(long, hide = true)]
    from_service: bool,
    /// Internal: mirror each live `Snapshot` to this file (atomic overwrite) so the
    /// desktop GUI — which launches this CLI in a visible terminal — can poll it and
    /// show the live hashrate/shares. The file carries ONLY the credit-only `Snapshot`
    /// (no secret; a core test asserts its wire form). Not for manual use. Hidden.
    #[arg(long, value_name = "PATH", hide = true)]
    telemetry_file: Option<std::path::PathBuf>,
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
    /// Diagnose the `ai` (shard-stage inference) role instead of a mining lane:
    /// python3, the shard engine + torch, NVIDIA (or --allow-cpu), the endpoint
    /// port, and the center URL. Reads the same saved ai config `alice-miner ai`
    /// uses; the flags below refine the probe.
    #[arg(long, conflicts_with = "train")]
    ai: bool,
    /// Diagnose the `train` (RLVR training) role instead of a mining lane: python3,
    /// torch, the trainer dir (run_m0.py + code_exec.py), a base model resolvable,
    /// NVIDIA (or --allow-cpu), and the center URL. Reads the same saved train config
    /// `alice-miner train` uses; the flags below refine the probe.
    #[arg(long, conflicts_with = "ai")]
    train: bool,
    /// (with --train) The training-mint-m0 trainer dir to check (else
    /// ALICE_TRAIN_TRAINER_PATH / saved).
    #[arg(long, value_name = "DIR")]
    trainer_dir: Option<String>,
    /// (with --train) The base model id to check is resolvable (else the saved / default).
    #[arg(long, value_name = "ID")]
    base_model: Option<String>,
    /// (with --train) The device to check: cuda | cpu | mps (else the saved / default).
    #[arg(long, value_name = "DEV")]
    device: Option<String>,
    /// (with --ai) The acp gateway base URL to probe (else the saved / default one).
    #[arg(long, value_name = "URL")]
    center_url: Option<String>,
    /// (with --ai) The public endpoint host:port to check (else the saved one).
    #[arg(long, value_name = "HOST:PORT")]
    endpoint: Option<String>,
    /// (with --ai) The shard-engine dir to check (else ALICE_SHARD_ENGINE_PATH / saved).
    #[arg(long, value_name = "DIR")]
    engine_dir: Option<String>,
    /// (with --ai) The python3 interpreter to check (default: python3 / saved).
    #[arg(long, value_name = "PATH")]
    python: Option<String>,
    /// (with --ai) Treat a missing NVIDIA GPU as a warning, not a failure (testing).
    #[arg(long)]
    allow_cpu: bool,
    /// Emit the report as a single JSON object (machine-readable).
    #[arg(long)]
    json: bool,
    /// Apply the SAFE auto-repairs for any failing checks (re-download a missing/corrupt
    /// engine, recreate a malformed config with a backup) and report what was done.
    /// Prompt-required fixes (background service) ask first on a terminal and are skipped
    /// in a scripted run. NEVER auto-touches identity / keystore / wallet — those are only
    /// printed as manual steps.
    #[arg(long)]
    fix: bool,
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
    /// Which miner to run: `bundled` (the recommended SHA-pinned engine — the
    /// default), `custom` (your OWN, possibly closed-source binary — the CLI fully
    /// manages it), or `companion` (don't spawn a miner; run only the possession-proof
    /// keep-alive so YOUR own rig's shares are credited to you). Omit to be asked.
    #[arg(long, value_name = "MODE")]
    miner: Option<String>,
    /// (with `--miner custom`) Absolute path to your miner binary.
    #[arg(long, value_name = "PATH")]
    miner_bin: Option<String>,
    /// (with `--miner custom`) The miner family / argv shape: `srbminer`, `xmrig`,
    /// `trex`, `lolminer`, `gminer`, `nbminer`, `alpha-miner`, `generic-stratum`, or
    /// `template` (used with `--miner-arg-template`).
    #[arg(long, value_name = "PRESET")]
    miner_preset: Option<String>,
    /// (with `--miner custom --miner-preset template`) A fully custom argv with the
    /// placeholders {POOL} {HOST} {PORT} {WALLET} {PASSWORD} {ALGO} {LOGFILE}
    /// (space-separated; Alice substitutes the real values).
    #[arg(long, value_name = "ARGV")]
    miner_arg_template: Option<String>,
    /// (with `--miner custom`) Confirm you want to run your OWN unverified binary (its
    /// integrity is NOT SHA-checked). Required for a non-interactive custom setup.
    #[arg(long)]
    i_understand_unverified: bool,
    /// Pin the GPU region: `us`, `asia`, `eu`, or `auto` (nearest — the default).
    /// Remembered for later runs (only affects the GPU-PRL lane).
    #[arg(long, value_name = "REGION")]
    region: Option<String>,
}

#[derive(clap::Args)]
struct GuideArgs {
    /// Emit the advice as a single JSON object (for the website / a script).
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args)]
struct CompanionArgs {
    /// Which pearlhash relay to enroll against: `prl` (SRBMiner mainline) or `alpha`
    /// (Volta/V100). XMR/RVN are open-enrollment (no companion needed).
    #[arg(long, default_value = "prl", value_name = "LANE")]
    lane: String,
    /// The device label your rig logs in with (the stratum worker suffix; the login
    /// is `<your-address>.<device>`). Must be `[A-Za-z0-9_-]`, ≤32 chars. Omit for a
    /// sanitized hostname default.
    #[arg(long, value_name = "NAME")]
    device: Option<String>,
    /// Pin the region relay the companion enrolls against (and your rig must then
    /// connect to — the allowlist is per-relay): `us`, `asia`, or `eu`. Omit / `auto` uses
    /// the remembered (or nearest) region.
    #[arg(long, value_name = "REGION")]
    region: Option<String>,
    /// The address to enroll (a validated Alice SS58-300 address). It MUST be the
    /// address of this box's active signing identity: the companion signs the
    /// possession proof with the local key and the relay verifies it against the
    /// enrolled address, so any OTHER address is silently never allow-listed. Omit to
    /// use the active `~/.alice` identity. To mine to a different address, switch
    /// identity — this is NOT that. (A PRL cashback address is separate:
    /// `identity --set-prl-payout`.)
    #[arg(long, value_name = "ADDRESS")]
    address: Option<String>,
    /// Re-enroll cadence in seconds (default ~9 min). Clamped strictly inside the
    /// relay's ~1800s allowlist TTL, so the pair never lapses between refreshes.
    #[arg(long, value_name = "SECONDS")]
    refresh_secs: Option<u64>,
    /// Enroll ONCE and exit (prime the allowlist for a scripted run / a test) instead
    /// of looping.
    #[arg(long)]
    once: bool,
    /// Stop automatically after this many seconds (0 = run until Ctrl-C). For the
    /// live-connect verification.
    #[arg(long, default_value_t = 0, value_name = "SECONDS")]
    duration_s: u64,
    /// Wallet keystore password — the companion must unlock the signing key to prove
    /// possession (a watch-only identity can't). INSECURE on the command line (visible
    /// in `ps`); prefer `--password-stdin` or the interactive prompt.
    #[arg(long, value_name = "PASS")]
    password: Option<String>,
    /// Read the unlock password from the first line of STDIN (secure for scripts).
    #[arg(long, conflicts_with = "password")]
    password_stdin: bool,
}

#[derive(clap::Args)]
struct AiArgs {
    /// The acp gateway base URL the stage registers/heartbeats/pulls against
    /// (https:// only). Defaults to the production gateway; saved for re-runs.
    #[arg(long, value_name = "URL")]
    center_url: Option<String>,
    /// The PUBLIC `host:port` this stage listens on — the address the swarm dials.
    /// Required (set up NAT/port-forwarding so peers can reach it). Saved for re-runs.
    #[arg(long, value_name = "HOST:PORT")]
    endpoint: Option<String>,
    /// Path to your alice-shard-engine checkout (must contain phase0/pipeline.py).
    /// Also honored via the ALICE_SHARD_ENGINE_PATH env var. Saved for re-runs.
    #[arg(long, value_name = "DIR")]
    engine_dir: Option<String>,
    /// The python3 interpreter used to run the engine (default: `python3`).
    #[arg(long, value_name = "PATH")]
    python: Option<String>,
    /// Free VRAM (GB) to advertise. Omit to auto-detect the largest GPU via nvidia-smi.
    #[arg(long, value_name = "GB")]
    vram_gb: Option<f64>,
    /// Optional region hint (informational — used for locality).
    #[arg(long, value_name = "REGION")]
    region: Option<String>,
    /// Explicitly opt in to run WITHOUT an NVIDIA GPU (for testing). A real
    /// inference stage needs a GPU; this only lets a no-NVIDIA box register.
    #[arg(long)]
    allow_cpu: bool,
    /// Stake reference for the swarm's sybil gate (the server only needs it
    /// non-empty). Default: `enroll:<your-address>`.
    #[arg(long, value_name = "REF")]
    stake_ref: Option<String>,
    /// Wallet keystore password — the ai role must unlock the signing key to prove
    /// possession when it registers the stage (the center credits no stage without
    /// it). INSECURE on the command line (visible in `ps`); prefer `--password-stdin`
    /// or the interactive prompt.
    #[arg(long, value_name = "PASS")]
    password: Option<String>,
    /// Read the unlock password from the first line of STDIN (secure for scripts).
    #[arg(long, conflicts_with = "password")]
    password_stdin: bool,
}

#[derive(clap::Args)]
struct TrainArgs {
    /// The acp gateway base URL the worker registers/leases/submits against
    /// (https:// only). Defaults to the production gateway; saved for re-runs.
    #[arg(long, value_name = "URL")]
    center_url: Option<String>,
    /// Path to your training-mint-m0 checkout (must contain run_m0.py + code_exec.py).
    /// Also honored via the ALICE_TRAIN_TRAINER_PATH env var. Saved for re-runs.
    #[arg(long, value_name = "DIR")]
    trainer_dir: Option<String>,
    /// The python3 interpreter used to run the candidate generator (default: `python3`).
    #[arg(long, value_name = "PATH")]
    python: Option<String>,
    /// The base model to generate candidates with (a HF model id or a local path).
    /// Default: a small instruct model; override to match the coordinator's corpus.
    #[arg(long, value_name = "ID")]
    base_model: Option<String>,
    /// The device the generation runs on: `cuda` | `cpu` | `mps` (default: cuda).
    #[arg(long, value_name = "DEV")]
    device: Option<String>,
    /// Auto-downshift to CPU when no NVIDIA GPU is present (for testing). A real
    /// training worker needs a GPU; this only lets a no-NVIDIA box generate on CPU.
    #[arg(long)]
    allow_cpu: bool,
    /// Optional region hint (informational — used for locality).
    #[arg(long, value_name = "REGION")]
    region: Option<String>,
    /// Stake reference for the coordinator's sybil gate (the server only needs it
    /// non-empty). Default: `enroll:<your-address>`.
    #[arg(long, value_name = "REF")]
    stake_ref: Option<String>,
    /// Wallet keystore password — the train role must unlock the signing key to prove
    /// possession when it registers/leases/submits (the center credits nothing without
    /// it). INSECURE on the command line (visible in `ps`); prefer `--password-stdin`
    /// or the interactive prompt.
    #[arg(long, value_name = "PASS")]
    password: Option<String>,
    /// Read the unlock password from the first line of STDIN (secure for scripts).
    #[arg(long, conflicts_with = "password")]
    password_stdin: bool,
}

#[derive(clap::Args)]
struct LangArgs {
    /// The language to switch to: `en` (English) or `zh` (中文). Omit to just print
    /// the current language.
    #[arg(value_name = "LANG")]
    lang: Option<String>,
}

fn main() {
    // FIRST, before ANY output (including clap's help/version/usage errors): on
    // Windows, force the console code pages to UTF-8 so our UTF-8 text — notably
    // 中文 — is not mojibake'd by a legacy OEM code page (cp950/Big5 on 繁中
    // Windows). No-op on other platforms and when no console is attached. See
    // `alice_miner_core::console::init_utf8_console` for the full root-cause note.
    alice_miner_core::console::init_utf8_console();

    let cli = Cli::parse();
    let no_color = cli.no_color;
    // Resolve + set the process-global UI language ONCE, before any user-facing
    // output. Order: --lang flag → saved settings → interactive first-run prompt →
    // LANG/LC_ALL/LANGUAGE env → English. See `resolve_language`.
    resolve_language(cli.lang.as_deref(), cli.command.as_ref());
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
        Some(Command::Guide(args)) => guide::run(args.json),
        Some(Command::Companion(args)) => cmd_companion(args),
        Some(Command::Ai(args)) => cmd_ai(args),
        Some(Command::Train(args)) => cmd_train(args),
        Some(Command::Lang(args)) => cmd_lang(args),
        Some(Command::Balance(args)) => balance::run(args),
        Some(Command::Update(args)) => update::run(args),
        // No subcommand: on an interactive TTY, launch the interactive menu; else
        // (piped / non-TTY) print help. Never a surprise prompt for a script.
        None => cmd_no_subcommand(no_color),
    };
    std::process::exit(code);
}

/// Resolve the process-global UI language ONCE, before any user-facing output, and
/// install it via [`i18n::set_lang`]. Resolution order (first hit wins):
///
///   (a) the `--lang <en|zh>` flag — always honored, and PERSISTED when explicitly
///       passed so a later bare run keeps it.
///   (b) the persisted `~/.alice/settings.json` preference.
///   (c) an INTERACTIVE first-run prompt — only when stdout+stdin are TTYs, there is
///       NO saved preference, and the subcommand is one where a prompt is safe (not
///       a scripted / service / `--json` context). The choice is persisted so it is
///       never asked again.
///   (d) the `LANG` / `LC_ALL` / `LANGUAGE` env (zh* ⇒ 中文).
///   (e) English (the default).
///
/// The prompt NEVER blocks a scripted or service run: a non-TTY stdin/stdout, a
/// `--json` output mode, the `service`/`fleet`/`stop` paths, and an explicit
/// `--lang`/saved-pref all skip it.
fn resolve_language(flag: Option<&str>, command: Option<&Command>) {
    // (a) --lang flag: honor + persist (an explicit choice is remembered).
    if let Some(raw) = flag {
        match raw.parse::<Lang>() {
            Ok(lang) => {
                i18n::set_lang(lang);
                let _ = alice_miner_core::settings::save_lang(lang);
                return;
            }
            Err(e) => {
                // Bad value: warn (in English — lang isn't resolved yet) and fall
                // through to the remaining sources rather than aborting.
                eprintln!("warning: {e}; ignoring --lang");
            }
        }
    }

    // (b) persisted preference.
    if let Some(lang) = alice_miner_core::settings::load().parsed_lang() {
        i18n::set_lang(lang);
        return;
    }

    // (c) interactive first-run prompt (only when safe — see `command_allows_prompt`).
    use std::io::IsTerminal;
    let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    if interactive && command_allows_prompt(command) {
        if let Some(lang) = prompt_for_language() {
            i18n::set_lang(lang);
            // Persist so we never ask again (best-effort; a write failure just means
            // we may ask next time — never fatal).
            let _ = alice_miner_core::settings::save_lang(lang);
            return;
        }
    }

    // (d) environment locale.
    if let Some(lang) = lang_from_env() {
        i18n::set_lang(lang);
        return;
    }

    // (e) default English (the global already starts at En; set explicitly for clarity).
    i18n::set_lang(Lang::En);
}

/// Whether a subcommand is one where an interactive first-run language prompt is
/// safe. FALSE for the machine / daemon / file-reading paths so a scripted or
/// service run is NEVER blocked on a prompt: `service` (daemon), `fleet` (reads
/// files), `stop` (one-shot control), and any invocation that carries `--json`.
fn command_allows_prompt(command: Option<&Command>) -> bool {
    match command {
        // Daemon / control / file-reader paths: never prompt.
        Some(Command::Service(_)) | Some(Command::Fleet(_)) | Some(Command::Stop(_)) => false,
        // A `--json` output mode is a machine consumer — never prompt.
        Some(Command::Detect(a)) => !a.json,
        Some(Command::GpuDevices(a)) => !a.json,
        Some(Command::Identity(a)) => !a.json,
        Some(Command::Start(a)) => !a.json && !a.from_service,
        Some(Command::Doctor(a)) => !a.json,
        Some(Command::Balance(a)) => !a.json,
        // `guide` is interactive-friendly, but its `--json` form is a machine consumer.
        Some(Command::Guide(a)) => !a.json,
        // `companion` prompts for the keystore unlock; allow the pre-prompt.
        Some(Command::Companion(_)) => true,
        // `lang` itself sets the language; don't first-run-prompt on the way in.
        Some(Command::Lang(_)) => false,
        // `update`: the interactive apply already confirms; the terminal-line prompt
        // for language would clash with its own prompt — skip the pre-prompt.
        Some(Command::Update(_)) => false,
        // setup / ai / train: interactive-friendly → allow the stderr line prompt.
        Some(Command::Setup(_)) | Some(Command::Ai(_)) | Some(Command::Train(_)) => true,
        // Bare-binary: the interactive MENU owns the first-run language pick (a nicer
        // TUI chooser), so DON'T fire the stderr line prompt on the way in. The menu's
        // fallback (non-TTY) path prints help, which needs no language pick.
        None => false,
    }
}

/// Print the first-run language chooser to STDERR (so it never pollutes a stdout
/// the user might capture) and read one line from stdin. `1`→English, `2`→中文;
/// empty / invalid / a read error → `None` (the caller then falls through to the
/// env → English default without persisting). Only reached on an interactive TTY.
fn prompt_for_language() -> Option<Lang> {
    use std::io::Write;
    // Bilingual prompt (we don't know the language yet, so show both).
    eprint!("Select language / 选择语言:\n  [1] English\n  [2] 中文\n> ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return None;
    }
    match line.trim() {
        "1" => Some(Lang::En),
        "2" => Some(Lang::Zh),
        // Also accept the codes/names directly, for the power user.
        other => other.parse::<Lang>().ok().or(Some(Lang::En)).filter(|_| !other.is_empty()),
    }
}

/// Read a language preference from the `LANG` / `LC_ALL` / `LANGUAGE` env vars, in
/// that precedence. Returns the FIRST that parses to a known language; `None` if
/// none are set or none parse (the caller then defaults to English). A `C` /
/// `POSIX` locale parses to nothing → `None` → English.
fn lang_from_env() -> Option<Lang> {
    for var in ["LC_ALL", "LANG", "LANGUAGE"] {
        if let Ok(val) = std::env::var(var) {
            if let Ok(lang) = val.parse::<Lang>() {
                return Some(lang);
            }
        }
    }
    None
}

/// `lang`: set or show the persisted UI language. With an argument, parse + persist
/// it (and apply it to this run's remaining output); with none, print the current
/// resolved language. Credit-only-irrelevant (pure preference).
fn cmd_lang(args: LangArgs) -> i32 {
    match args.lang.as_deref() {
        Some(raw) => match raw.parse::<Lang>() {
            Ok(lang) => {
                i18n::set_lang(lang);
                match alice_miner_core::settings::save_lang(lang) {
                    Ok(path) => {
                        println!(
                            "{} {} ({})",
                            tr!("Language set to", "语言已设为"),
                            lang.code(),
                            path.display()
                        );
                        EXIT_OK
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        EXIT_RUNTIME
                    }
                }
            }
            Err(e) => {
                eprintln!("error: {e}");
                EXIT_USAGE
            }
        },
        None => {
            println!("{} {}", tr!("Current language:", "当前语言:"), i18n::lang().code());
            EXIT_OK
        }
    }
}

/// The bare-binary path (no subcommand):
///
///   * FIRST launch (no `~/.alice` identity AND an interactive TTY) → the guided
///     `setup` wizard, unchanged (the right first step for a brand-new user).
///   * Already set up + interactive TTY → the fancy interactive MENU (logo + items),
///     which dispatches to the SAME command entry points a power user would type.
///   * Non-TTY / piped / redirected → print the top-level help (never a prompt), so a
///     script that pipes in gets the usual help.
fn cmd_no_subcommand(no_color: bool) -> i32 {
    use std::io::IsTerminal;
    let has_identity = alice_miner_core::identity::load_pointer().is_some();
    let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    if !has_identity && interactive {
        // First launch, interactive → guide them through setup.
        return setup::run(setup::SetupConfig::first_launch(), no_color);
    }
    if interactive {
        // Already set up → the interactive launcher. It owns the first-run language
        // pick (a TUI chooser), returns a MenuAction, and we dispatch it below to the
        // existing command functions (the menu never reimplements a command).
        let action = menu::run();
        // Non-blocking version banner AFTER the menu screen is torn down (so it prints
        // to the restored terminal, not the alternate screen). Bounded + ~6h cached +
        // opt-out; never blocks. Skipped when the user chose Update (which checks itself).
        if action != menu::MenuAction::Update {
            update::startup_banner(false);
        }
        return run_menu_action(action, no_color);
    }
    // Non-TTY / piped: print help and exit cleanly (clap renders the long help).
    use clap::CommandFactory;
    let mut cmd = Cli::command();
    let _ = cmd.print_help();
    println!();
    EXIT_OK
}

/// Dispatch a [`menu::MenuAction`] to the EXISTING command entry point (never a
/// reimplementation). This is the one place the menu's choice becomes a real command.
fn run_menu_action(action: menu::MenuAction, no_color: bool) -> i32 {
    match action {
        // Start mining on the recommended (auto) lane — the same `cmd_start` a power
        // user drives with `alice-miner start --lane auto`.
        menu::MenuAction::StartMining => cmd_start(start_args_auto(), no_color),
        // Status & telemetry: the read-only device + lane-viability telemetry screen
        // (`detect`). The LIVE mining dashboard streams from Start; this is the
        // no-mining "what does this box see" view.
        menu::MenuAction::Status => cmd_detect(DetectArgs { json: false }),
        // Balance: the three-bucket read-only balance for the active identity.
        menu::MenuAction::Balance => balance::run(balance::BalanceArgs { address: None, json: false }),
        // Settings: language / identity / background service. A small sub-screen that
        // just shows the current settings + how to change them (each via its own
        // command); we surface the active identity + language and the service status.
        menu::MenuAction::Settings => cmd_settings_overview(),
        // Doctor + self-repair on the recommended lane.
        menu::MenuAction::Doctor => cmd_doctor(DoctorArgs {
            lane: "auto".to_string(),
            ai: false,
            train: false,
            center_url: None,
            endpoint: None,
            engine_dir: None,
            trainer_dir: None,
            base_model: None,
            device: None,
            python: None,
            allow_cpu: false,
            json: false,
            // The menu item is "Doctor + self-repair": apply the SAFE fixes (engine
            // re-download / config recreate); service is prompted, identity never touched.
            fix: true,
        }),
        // Check for updates (interactive apply flow — asks before applying).
        menu::MenuAction::Update => update::run(update::UpdateArgs { check: false, yes: false }),
        // Training: run the RLVR training worker with default flags (the config the
        // user saved on a prior `train` run replays; a first run without a saved
        // trainer dir fails closed with the exact flag to pass — never a fake run).
        menu::MenuAction::Training => cmd_train(train_args_default()),
        menu::MenuAction::Quit => EXIT_OK,
    }
}

/// A default `train` invocation (every flag at its clap default) — the menu's
/// "Training" path. Resolved settings from a prior run replay; an unconfigured first
/// run reports the exact `--trainer-dir` to pass rather than pretending to train.
fn train_args_default() -> TrainArgs {
    TrainArgs {
        center_url: None,
        trainer_dir: None,
        python: None,
        base_model: None,
        device: None,
        allow_cpu: false,
        region: None,
        stake_ref: None,
        password: None,
        password_stdin: false,
    }
}

/// A default `start` invocation on the AUTO (recommended) lane — the menu's "Start
/// mining" path. Mirrors `alice-miner start --lane auto` with every other flag at its
/// clap default.
fn start_args_auto() -> StartArgs {
    StartArgs {
        lane: "auto".to_string(),
        address: None,
        dual: false,
        json: false,
        plain: false,
        duration_s: 0,
        password: None,
        password_stdin: false,
        gpus: None,
        region: None,
        from_service: false,
        telemetry_file: None,
    }
}

/// The Settings overview the menu's [4] item shows: the active identity address, the
/// current UI language, and the background-service status — plus the exact command to
/// change each. Read-only; it dispatches to no mutating path (the user runs the named
/// command to change a setting). Credit-only — never a secret.
fn cmd_settings_overview() -> i32 {
    println!("\n  {}", tr!("Settings", "设置"));
    println!("  {}", "─".repeat(50));
    // Language.
    println!(
        "  {}: {}   ({}: alice-miner lang <en|zh>)",
        tr!("Language", "语言"),
        i18n::lang().code(),
        tr!("change", "更改")
    );
    // Identity (public address only; never a secret).
    match alice_miner_core::identity::load_pointer() {
        Some(p) => println!(
            "  {}: {}   ({}: alice-miner identity --show)",
            tr!("Identity", "身份"),
            p.address,
            tr!("details", "详情")
        ),
        None => println!(
            "  {}: {}   ({}: alice-miner identity --create)",
            tr!("Identity", "身份"),
            tr!("none yet", "尚无"),
            tr!("create", "创建")
        ),
    }
    // Background service status.
    use alice_miner_core::service::{self, ServiceState};
    let svc = match service::status() {
        ServiceState::Running => tr!("running", "运行中"),
        ServiceState::Loaded => tr!("installed (idle)", "已安装(空闲)"),
        ServiceState::NotInstalled => tr!("not installed", "未安装"),
    };
    println!(
        "  {}: {}   ({}: alice-miner service --install)",
        tr!("Background mining", "后台挖矿"),
        svc,
        tr!("manage", "管理")
    );
    println!("  {}\n", "─".repeat(50));
    EXIT_OK
}

/// `doctor`: run the self-diagnostic battery for the resolved lane and print the
/// report (human or `--json`). Exits non-zero if any check FAILs so a script can
/// gate `start` on a clean preflight.
fn cmd_doctor(args: DoctorArgs) -> i32 {
    // `--ai` diagnoses the shard-stage inference role instead of a mining lane.
    if args.ai {
        return cmd_doctor_ai(args);
    }
    // `--train` diagnoses the RLVR training role instead of a mining lane.
    if args.train {
        return cmd_doctor_train(args);
    }
    let cap = alice_miner_core::CapabilityProfile::detect();
    let lane = match resolve_lane(&args.lane, &cap) {
        Ok(l) => l,
        Err(code) => return code,
    };
    let checks = doctor::run_checks(lane, &cap);
    // `--fix`: apply the SAFE (and, on a TTY, prompt-gated) auto-repairs, then re-run the
    // battery so the printed report reflects the post-fix state. `--fix` is a human action
    // (it may prompt) so it is not combined with `--json`.
    if args.fix {
        use std::io::IsTerminal;
        let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
        print!("{}", doctor::apply_fixes(&checks, interactive, &mut confirm_prompt));
        println!();
        let rechecked = doctor::run_checks(lane, &cap);
        print!("{}", doctor::render_report(&rechecked, lane));
        return if doctor::has_blocking_failure(&rechecked) { EXIT_USAGE } else { EXIT_OK };
    }
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

/// A yes/no confirmation prompt on the terminal (used by `doctor --fix` for the
/// prompt-required service repair). Prints `question`, reads a line, returns true only
/// for an explicit `y`/`yes`. EOF / anything else → false (the safe default).
fn confirm_prompt(question: &str) -> bool {
    use std::io::{BufRead, Write};
    print!("{question}");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// `doctor --ai`: run the shard-stage inference battery. Merges the `--ai` flags
/// over the saved ai config (the same one `alice-miner ai` reads), so a bare
/// `doctor --ai` diagnoses exactly what a subsequent `ai` run would use.
fn cmd_doctor_ai(args: DoctorArgs) -> i32 {
    let saved = alice_miner_core::ai_config::load();
    let engine_dir = args
        .engine_dir
        .or_else(|| std::env::var("ALICE_SHARD_ENGINE_PATH").ok().filter(|s| !s.is_empty()))
        .or(saved.engine_dir)
        .map(std::path::PathBuf::from);
    let input = doctor::AiDoctorInput {
        center_url: args.center_url.or(saved.center_url),
        endpoint: args.endpoint.or(saved.endpoint),
        engine_dir,
        python: args.python.or(saved.python).unwrap_or_else(|| "python3".to_string()),
        allow_cpu: args.allow_cpu,
    };
    let checks = doctor::run_ai_checks(&input);
    if args.fix {
        use std::io::IsTerminal;
        let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
        print!("{}", doctor::apply_fixes(&checks, interactive, &mut confirm_prompt));
        println!();
        let rechecked = doctor::run_ai_checks(&input);
        print!("{}", doctor::render_ai_report(&rechecked));
        return if doctor::has_blocking_failure(&rechecked) { EXIT_USAGE } else { EXIT_OK };
    }
    if args.json {
        println!("{}", doctor::render_ai_json(&checks));
    } else {
        print!("{}", doctor::render_ai_report(&checks));
    }
    if doctor::has_blocking_failure(&checks) {
        EXIT_USAGE
    } else {
        EXIT_OK
    }
}

/// `doctor --train`: run the RLVR training-role battery. Merges the `--train` flags
/// over the saved train config (the same one `alice-miner train` reads), so a bare
/// `doctor --train` diagnoses exactly what a subsequent `train` run would use.
fn cmd_doctor_train(args: DoctorArgs) -> i32 {
    let saved = alice_miner_core::train_config::load();
    let trainer_dir = args
        .trainer_dir
        .or_else(|| std::env::var("ALICE_TRAIN_TRAINER_PATH").ok().filter(|s| !s.is_empty()))
        .or(saved.trainer_dir)
        .map(std::path::PathBuf::from);
    let input = doctor::TrainDoctorInput {
        center_url: args.center_url.or(saved.center_url),
        trainer_dir,
        python: args.python.or(saved.python).unwrap_or_else(|| "python3".to_string()),
        base_model: args.base_model.or(saved.base_model),
        device: args.device.or(saved.device).unwrap_or_else(|| "cuda".to_string()),
        allow_cpu: args.allow_cpu,
    };
    let checks = doctor::run_train_checks(&input);
    if args.fix {
        use std::io::IsTerminal;
        let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
        print!("{}", doctor::apply_fixes(&checks, interactive, &mut confirm_prompt));
        println!();
        let rechecked = doctor::run_train_checks(&input);
        print!("{}", doctor::render_train_report(&rechecked));
        return if doctor::has_blocking_failure(&rechecked) { EXIT_USAGE } else { EXIT_OK };
    }
    if args.json {
        println!("{}", doctor::render_train_json(&checks));
    } else {
        print!("{}", doctor::render_train_report(&checks));
    }
    if doctor::has_blocking_failure(&checks) {
        EXIT_USAGE
    } else {
        EXIT_OK
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ai (shard-stage inference worker)
// ─────────────────────────────────────────────────────────────────────────────

/// `ai`: run this GPU as a pipeline-parallel inference STAGE coordinated by the
/// Alice scheduling center. Resolves the wallet unlock password (the register PoP
/// needs the signing key), builds the resolved config, and hands off to
/// [`ai::run`]. Credit-only; NEVER creates/overwrites an identity (read-only).
fn cmd_ai(args: AiArgs) -> i32 {
    // Non-blocking startup version check (the ai role has no `--json` toggle here, so
    // the banner is allowed; it never blocks or delays the stage). Opt out with
    // ALICE_MINER_NO_UPDATE_CHECK=1. See `update::startup_banner`.
    update::startup_banner(false);

    // The register/heartbeat PoP needs the sr25519 signing key, so a keystore-backed
    // identity needs its unlock. Resolve it up front (stdin / flag / prompt); a
    // watch-only identity has no keystore and `ai::run` fails closed with a clear
    // message, so we skip the prompt there (no keystore to unlock).
    let has_keystore = alice_miner_core::identity::load_pointer()
        .map(|p| p.keystore_path.is_some())
        .unwrap_or(false);
    let unlock = if has_keystore {
        match resolve_password(args.password.clone(), args.password_stdin) {
            Ok(p) => Some(Zeroizing::new(p)),
            Err(e) => {
                eprintln!("error: {e}");
                return EXIT_USAGE;
            }
        }
    } else {
        None
    };

    let flags = ai::AiFlags {
        center_url: args.center_url,
        endpoint: args.endpoint,
        engine_dir: args.engine_dir,
        python: args.python,
        vram_gb: args.vram_gb,
        region: args.region,
        stake_ref: args.stake_ref,
        allow_cpu: args.allow_cpu,
    };
    ai::run(flags, unlock)
}

// ─────────────────────────────────────────────────────────────────────────────
// companion (hold the M4 PoP for a bring-your-own pearlhash miner)
// ─────────────────────────────────────────────────────────────────────────────

/// `companion`: resolve the keystore unlock (the possession proof needs the signing
/// key), then hand off to [`companion::run`] — which runs the /m4 handshake on a
/// refresh loop WITHOUT ever spawning a miner. A watch-only identity has no keystore
/// and fails closed inside `run`, so we only prompt for a password when one exists.
fn cmd_companion(args: CompanionArgs) -> i32 {
    // Non-blocking startup version check (no `--json` here). Opt out with
    // ALICE_MINER_NO_UPDATE_CHECK=1.
    update::startup_banner(false);

    // The companion's PoP signature needs the sr25519 signing key. Resolve the
    // unlock up front (stdin / flag / prompt) ONLY for a keystore-backed identity; a
    // watch-only one has no keystore and `companion::run` fails closed with a clear
    // message, so we skip the prompt there. An explicit `--address` must EQUAL this
    // box's signing identity (the key we unlock here is the one that signs the PoP);
    // `companion::run` rejects a mismatch up front rather than silently failing PoP.
    let has_keystore = alice_miner_core::identity::load_pointer()
        .map(|p| p.keystore_path.is_some())
        .unwrap_or(false);
    let unlock = if has_keystore {
        match resolve_password(args.password.clone(), args.password_stdin) {
            Ok(p) => Some(Zeroizing::new(p)),
            Err(e) => {
                eprintln!("error: {e}");
                return EXIT_USAGE;
            }
        }
    } else {
        None
    };

    let flags = companion::CompanionFlags {
        lane: args.lane,
        device: args.device,
        region: args.region,
        address: args.address,
        refresh_secs: args.refresh_secs,
        once: args.once,
        duration_s: args.duration_s,
    };
    companion::run(flags, unlock)
}

// ─────────────────────────────────────────────────────────────────────────────
// train (RLVR training worker)
// ─────────────────────────────────────────────────────────────────────────────

/// `train`: run this GPU as an RLVR TRAINING worker coordinated by the Alice training
/// coordinator. Resolves the wallet unlock password (the register/lease/submit PoP
/// needs the signing key), builds the resolved config, and hands off to [`train::run`].
/// Credit-only; NEVER creates/overwrites an identity (read-only).
fn cmd_train(args: TrainArgs) -> i32 {
    // Non-blocking startup version check (the train role has no `--json` toggle here, so
    // the banner is allowed; it never blocks or delays the worker). Opt out with
    // ALICE_MINER_NO_UPDATE_CHECK=1. See `update::startup_banner`.
    update::startup_banner(false);

    // The register/lease/submit PoP needs the sr25519 signing key, so a keystore-backed
    // identity needs its unlock. Resolve it up front (stdin / flag / prompt); a
    // watch-only identity has no keystore and `train::run` fails closed with a clear
    // message, so we skip the prompt there (no keystore to unlock).
    let has_keystore = alice_miner_core::identity::load_pointer()
        .map(|p| p.keystore_path.is_some())
        .unwrap_or(false);
    let unlock = if has_keystore {
        match resolve_password(args.password.clone(), args.password_stdin) {
            Ok(p) => Some(Zeroizing::new(p)),
            Err(e) => {
                eprintln!("error: {e}");
                return EXIT_USAGE;
            }
        }
    } else {
        None
    };

    let flags = train::TrainFlags {
        center_url: args.center_url,
        trainer_dir: args.trainer_dir,
        python: args.python,
        base_model: args.base_model,
        device: args.device,
        region: args.region,
        stake_ref: args.stake_ref,
        allow_cpu: args.allow_cpu,
    };
    train::run(flags, unlock)
}

// ─────────────────────────────────────────────────────────────────────────────
// service (background mining persistence)
// ─────────────────────────────────────────────────────────────────────────────

fn cmd_service(args: ServiceArgs) -> i32 {
    use alice_miner_core::service::{self, ServiceSpec, ServiceState};

    // Default + explicit --status: report state.
    if args.status || (!args.install && !args.uninstall) {
        let (word, msg) = match service::status() {
            ServiceState::Running => (
                "running",
                tr!(
                    "Background mining is installed and running.",
                    "后台挖矿已安装并正在运行。"
                ),
            ),
            ServiceState::Loaded => (
                "loaded",
                tr!(
                    "Background mining is installed (not currently running; it will keep retrying).",
                    "后台挖矿已安装(当前未运行;它会持续重试)。"
                ),
            ),
            ServiceState::NotInstalled => (
                "not_installed",
                tr!("Background mining is not installed.", "后台挖矿未安装。"),
            ),
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
                println!("{}", tr!("Background mining removed.", "后台挖矿已移除。"));
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
            eprintln!(
                "error: {}",
                tr!(
                    "cannot locate the miner CLI to background: {e}",
                    "无法定位要放入后台的矿工 CLI: {e}"
                )
                .replace("{e}", &e.to_string())
            );
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
                "error: {}",
                tr!(
                    "no identity yet — create or import one (`identity --create`) before backgrounding a GPU lane.",
                    "尚无身份 — 在将 GPU 通道放入后台前,请先创建或导入一个(`identity --create`)。"
                )
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
            let tail = if args.at_login {
                tr!(" It will also start at login.", " 它也会在登录时启动。")
            } else {
                ""
            };
            println!(
                "{}{tail}",
                tr!(
                    "Background mining installed and started.",
                    "后台挖矿已安装并启动。"
                )
            );
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
            eprintln!("{}", errmsg::render_error(&e));
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
                    "{}\n  \
                     alice-miner identity --create\n  \
                     alice-miner identity --import \"<24 words>\"\n  \
                     alice-miner identity --paste <address>   {}\n\
                     ({}: {})",
                    tr!(
                        "No identity yet. Create or import one first:",
                        "尚无身份。请先创建或导入一个:"
                    ),
                    tr!("(watch-only)", "(仅观察)"),
                    tr!("expected pointer", "预期指针"),
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
                println!("{}: {masked}", tr!("15% PRL return address saved", "15% PRL 返还地址已保存"));
                println!(
                    "  {}",
                    tr!(
                        "binds to your Alice address on the next GPU mining start (PoP).",
                        "将在下次 GPU 挖矿启动时(PoP)绑定到你的 Alice 地址。"
                    )
                );
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
                println!("{}: {masked}", tr!("15% PRL return address", "15% PRL 返还地址"));
            }
            EXIT_OK
        }
        Ok(None) => {
            if json {
                println!("{}", serde_json::json!({ "prl_payout": null, "set": false }));
            } else {
                println!(
                    "{}: {}",
                    tr!("15% PRL return address", "15% PRL 返还地址"),
                    tr!("not set", "未设置")
                );
                println!(
                    "  {}  alice-miner identity --set-prl-payout <prl1p…>",
                    tr!("set one with:", "设置方式:")
                );
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
            "error: {}\n  \
             --create | --import <MNEMONIC> | --import-seed <HEX> | --paste <ADDR> | --show",
            tr!("choose one of:", "请选择其中之一:")
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
    // Non-blocking startup version check: print a one-line "new version available"
    // banner if one exists, WITHOUT ever blocking or delaying mining (bounded thread +
    // ~6h cache; opt out with ALICE_MINER_NO_UPDATE_CHECK=1). Suppressed in `--json` /
    // background-service mode (machine consumers get no banner). See `update::startup_banner`.
    update::startup_banner(args.json || args.from_service);

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

    // D-line region pin: `--region <us|asia|eu>` LOCKS the GPU-PRL lane to a region
    // (persisted, no auto-failover); `--region auto` CLEARS the lock. Persist BEFORE
    // the engine starts (it reads the setting when it builds the region plan). A
    // usage error on an unknown value (never a silent no-op). Omitting the flag keeps
    // whatever was remembered.
    if let Some(raw) = args.region.as_deref() {
        if let Err(code) = apply_region_flag(raw, args.json) {
            return code;
        }
    }
    // Human path only: label the effective region MODE (locked vs auto + last-good) AND
    // the effective endpoint order, so the user always knows whether the lane will
    // auto-failover and exactly which relays it will use — for the GPU-PRL lane, where
    // region applies. Computed probe-free (the engine runs the one real probe at start).
    if !args.json && !args.from_service && lane == Lane::GpuPrl {
        let view = region::view();
        println!("{}", view.mode);
        println!("{}", region::endpoints_line(&view));
        // A stale binary / `ALICE_MINER_ENDPOINTS_JSON` override that reintroduced the
        // removed `fi` relay — surface it here too (doctor gives the full diagnosis).
        if view.has_removed_region {
            eprintln!(
                "{}",
                tr!(
                    "warning: a removed region host (fi) is in the effective endpoints — run `alice-miner doctor` (likely an old binary or ALICE_MINER_ENDPOINTS_JSON override).",
                    "警告: 效端点中含已移除的区域主机(fi)— 请运行 `alice-miner doctor`(很可能是旧版 binary 或 ALICE_MINER_ENDPOINTS_JSON 覆盖)。"
                )
            );
        }
    }

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
                "error: {}",
                tr!(
                    "background mining is already active (one miner per machine). Stop it with \
                     `alice-miner service --uninstall` first, then run start — or just let the \
                     background service keep mining.",
                    "后台挖矿已在运行(每台机器只允许一个矿工)。请先用 \
                     `alice-miner service --uninstall` 停止它再运行 start — 或直接让后台服务继续挖矿。"
                )
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
            "error: {}",
            tr!(
                "the {lane} lane is {state} on this device ({reason}). Recommended lane: {rec}.",
                "本设备上 {lane} 通道 {state}({reason})。推荐通道: {rec}。"
            )
            .replace("{lane}", lane.label())
            .replace("{state}", cap.support(lane).label())
            .replace("{reason}", cap.viability.reason(lane).unwrap_or("not viable"))
            .replace("{rec}", cap.recommended_lane().label())
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
                "error: {}",
                tr!(
                    "dual-mine needs 2 viable lanes; this device has {n} ({gpu} is {state}: {reason}). \
                     Run a single lane instead, e.g. `alice-miner start --lane {rec}`.",
                    "双挖需要 2 个可用通道;本设备只有 {n} 个({gpu} {state}: {reason})。\
                     请改用单通道,例如 `alice-miner start --lane {rec}`。"
                )
                .replace("{n}", &runnable.len().to_string())
                .replace("{gpu}", gpu.label())
                .replace("{state}", cap.support(gpu).label())
                .replace("{reason}", cap.viability.reason(gpu).unwrap_or("not viable"))
                .replace("{rec}", cap.recommended_lane().id())
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
    // v0.6.0 upgrade gate: once the read API tells us this build is below its minimum
    // supported version, we print a clear one-time CTA and mark a non-zero exit so
    // automation notices (we do NOT force-stop an active miner mid-share — the operator
    // sees the CTA + non-zero exit and updates).
    let mut printed_upgrade_notice = false;

    loop {
        match engine.recv_timeout(Duration::from_millis(500)) {
            Ok(Event::Snapshot(snap)) => {
                let credit = credit_cell
                    .lock()
                    .map(|c| c.clone())
                    .unwrap_or(alice_miner_core::CreditState::NotExposed);
                // v0.6.0 upgrade gate: if the read API reports this build is below its
                // minimum supported version, print a clear upgrade CTA ONCE and mark a
                // non-zero exit. Human path prints the CTA; --json path skips the CTA
                // (the JSON stream stays a stable schema) but still exits non-zero.
                if let Some((min_supported, download_url)) = credit.upgrade_required() {
                    if !printed_upgrade_notice {
                        printed_upgrade_notice = true;
                        if !args.json && tui.is_none() {
                            eprintln!(
                                "{}",
                                tr!(
                                    format!(
                                        "⚠ This client is out of date. The network now requires \
                                         v{min_supported} or newer to confirm your credit. Please \
                                         update: {download_url}"
                                    ),
                                    format!(
                                        "⚠ 客户端版本过旧。网络现在要求 v{min_supported} 或更高版本才能\
                                         确认积分。请更新:{download_url}"
                                    )
                                )
                            );
                        }
                        exit_code = EXIT_RUNTIME;
                    }
                }
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
                // Mirror the latest snapshot to the telemetry file (when the GUI
                // launched us with `--telemetry-file`) so the desktop Dashboard shows
                // this terminal's live hashrate/shares. Atomic overwrite; credit-only.
                if let Some(tf) = args.telemetry_file.as_deref() {
                    write_telemetry_file(tf, &snap);
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
                    // Machine path: keep the RAW string (a consumer wants the exact detail).
                    println!("{}", serde_json::json!({ "error": e }));
                } else if tui.is_some() {
                    // Defer: print the polished message after the alt screen is gone.
                    deferred_error = Some(errmsg::render_error(&e));
                } else {
                    // Human path: the consistent bilingual "what happened + what to do"
                    // shape (raw detail only under ALICE_MINER_VERBOSE=1).
                    eprintln!("{}", errmsg::render_error(&e));
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
        // `e` is already the polished multi-line message (built via errmsg::render_error
        // when the error was captured), so print it as-is.
        eprintln!("{e}");
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
                "note: {}",
                tr!(
                    "the lane never reached the Running state (the relay may be unreachable from here).",
                    "该通道从未进入 Running 状态(此处可能无法连接到中继)。"
                )
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

/// Mirror the latest [`Snapshot`] to `path` for the desktop GUI to poll (the GUI
/// launches this CLI in a visible terminal, then reads this file to drive its live
/// Dashboard). **Atomic overwrite**: serialize → write a sibling tmp in the SAME dir
/// → rename over `path`, so the GUI never reads a half-written file AND the file only
/// ever holds the LATEST snapshot (never appended → it can't grow without bound).
/// Best-effort + **credit-only**: the `Snapshot` wire form carries no secret (no
/// address-adjacent secret, no `paid_acu`/payout, and `prl_payout` is `#[serde(skip)]`
/// — a core test asserts the shape), so this is safe to write to a plain file. Any I/O
/// error is silently ignored — telemetry is a convenience, never worth interrupting a
/// mining run.
fn write_telemetry_file(path: &std::path::Path, snap: &Snapshot) {
    let Ok(json) = serde_json::to_string(snap) else {
        return;
    };
    // A sibling tmp keyed to our pid (same dir → the rename is same-filesystem +
    // atomic; the pid suffix keeps two miners from clobbering each other's tmp).
    let Some(name) = path.file_name() else {
        return;
    };
    let tmp = path.with_file_name(format!(".{}.tmp.{}", name.to_string_lossy(), std::process::id()));
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if std::fs::write(&tmp, json.as_bytes()).is_ok() && std::fs::rename(&tmp, path).is_err() {
        // Don't leak the tmp file if the rename failed (e.g. a racing reader on Windows).
        let _ = std::fs::remove_file(&tmp);
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
        // The RVN (KawPoW) lane is NOT shipped in this release — its miner binary is a
        // packaging placeholder pinned for M7. Reject `--lane rvn` here with a clear,
        // actionable message instead of resolving it and letting the run fail deep in
        // binary resolution with an opaque "binary unavailable" error.
        "rvn" => {
            eprintln!(
                "error: {}",
                tr!(
                    "the RVN (KawPoW) lane is not available in this release — it is coming in M7. Use `--lane gpu` (PRL) or `--lane xmr` for now.",
                    "RVN(KawPoW)通道本版尚未发布 — 预计 M7 上线。请暂用 `--lane gpu`(PRL)或 `--lane xmr`。"
                )
            );
            Err(EXIT_USAGE)
        }
        "auto" => Ok(cap.recommended_lane()),
        other => {
            eprintln!(
                "error: {}",
                tr!(
                    "unknown lane `{lane}` (use: xmr | gpu | prl | alpha | auto)",
                    "未知通道 `{lane}`(可用: xmr | gpu | prl | alpha | auto)"
                )
                .replace("{lane}", other)
            );
            Err(EXIT_USAGE)
        }
    }
}

/// Apply `--region <value>` (D-line): validate + PERSIST the GPU-PRL region pin
/// BEFORE the engine builds its plan. A known region tag (`us`/`asia`/`eu`) LOCKS
/// the lane to that region (no auto-failover); `auto`/`off`/`clear`/`none` CLEAR the
/// lock. The accepted tags come from [`gpu_prl::region_tags`], so this stays in
/// lockstep with the compiled region set. Returns `Err(exit)`
/// only on an unknown value (a usage error — never a silent no-op). A persistence
/// failure (e.g. a read-only home) is a non-fatal warning: the run continues on
/// whatever is on disk. Confirmation is printed on the human path (suppressed under
/// `--json`).
fn apply_region_flag(raw: &str, json: bool) -> Result<(), i32> {
    let v = raw.trim().to_ascii_lowercase();
    // Clear the lock → back to automatic (nearest region + auto-failover).
    if matches!(v.as_str(), "auto" | "off" | "clear" | "none" | "") {
        match alice_miner_core::settings::clear_region_lock() {
            Ok(_) if !json => println!(
                "{}",
                tr!(
                    "Region lock cleared — the GPU-PRL lane will pick the nearest region and auto-failover.",
                    "已清除区域锁定 — GPU-PRL 通道将选择最近区域并自动切换。"
                )
            ),
            Ok(_) => {}
            Err(e) => eprintln!("warning: could not persist region setting: {e}"),
        }
        return Ok(());
    }
    // Lock to a known region tag.
    match alice_miner_core::lane::gpu_prl::normalize_region_tag(&v) {
        Some(tag) => {
            match alice_miner_core::settings::save_region_lock(tag) {
                Ok(_) if !json => println!(
                    "{}",
                    tr!(
                        "Region locked to {tag} — the GPU-PRL lane will only use this region (no auto-failover). Use `--region auto` to unlock.",
                        "区域已锁定为 {tag} — GPU-PRL 通道将只使用该区域(不自动切换)。用 `--region auto` 解除。"
                    )
                    .replace("{tag}", tag)
                ),
                Ok(_) => {}
                Err(e) => eprintln!("warning: could not persist region setting: {e}"),
            }
            Ok(())
        }
        None => {
            let tags = alice_miner_core::lane::gpu_prl::region_tags().join(" | ");
            eprintln!(
                "error: {}",
                tr!(
                    "unknown region `{r}` (use: {tags} | auto)",
                    "未知区域 `{r}`(可用: {tags} | auto)"
                )
                .replace("{r}", raw)
                .replace("{tags}", &tags)
            );
            Err(EXIT_USAGE)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// stop
// ─────────────────────────────────────────────────────────────────────────────

/// Stop a running miner — with a robust ORPHAN backstop so `stop` never leaves the
/// engine child (xmrig / SRBMiner) eating CPU when the CLI parent pid file is stale
/// (the M4-Max "stopped, but xmrig still at 1200% CPU" report). Three layers, most
/// specific first:
///   1. **CLI parent** (`miner-cli.pid`) — the clean path: stopping it drops its
///      engine + child (process group / `kill_on_drop`).
///   2. **engine child** (`miner-child.pid`, written by `core::supervise` with the
///      exact engine path) — reached when the parent pid is stale / missing, OR as a
///      belt-and-suspenders after a parent SIGKILL that skipped the supervisor's own
///      cleanup. Signalled ONLY after we RE-VERIFY the live pid's command line still
///      contains OUR recorded engine path — so a stale pid the OS REUSED for an
///      unrelated process (e.g. after a reboot) is never mis-killed.
///   3. **last resort (unix)** — a still-running orphan of OUR EXACT bundled xmrig
///      (the sibling binary next to this exe) that neither pid file caught. Each
///      candidate's command line is re-verified against the exact bundled path AND
///      its liveness re-checked before we ever signal it — we NEVER kill by the bare
///      name `xmrig`, and NEVER a non-bundled process.
fn cmd_stop(args: StopArgs) -> i32 {
    let timeout = Duration::from_secs(args.timeout_s);
    let mut acted = false; // stopped at least one LIVE process
    let mut had_error = false;

    // ── 1) The CLI parent process (`miner-cli.pid`). ─────────────────────────────
    match pidfile::read_pid() {
        Some(pid) if pidfile::is_alive(pid) => {
            println!(
                "{}",
                tr!("Stopping miner (pid {pid})…", "正在停止矿工(pid {pid})…")
                    .replace("{pid}", &pid.to_string())
            );
            match pidfile::stop_pid(pid, timeout) {
                pidfile::StopOutcome::Graceful => {
                    println!("{}", tr!("Miner stopped cleanly.", "矿工已干净停止。"));
                    pidfile::remove();
                    acted = true;
                }
                pidfile::StopOutcome::Killed => {
                    println!(
                        "{}",
                        tr!(
                            "Miner did not exit in time; sent SIGKILL. No orphan left.",
                            "矿工未按时退出;已发送 SIGKILL。没有遗留孤儿进程。"
                        )
                    );
                    pidfile::remove();
                    acted = true;
                }
                pidfile::StopOutcome::Error(e) => {
                    eprintln!("error: {e}");
                    had_error = true;
                }
            }
        }
        Some(stale) => {
            // A stale parent pid — clean it, then fall through to the child backstop
            // (this is EXACTLY the "stopped but xmrig still alive" case).
            eprintln!(
                "{}",
                tr!(
                    "No running miner at the CLI pid (stale pid {pid}); checking for a leftover engine child.",
                    "CLI 进程已不在(过期 pid {pid});正在检查是否有遗留的引擎子进程。"
                )
                .replace("{pid}", &stale.to_string())
            );
            pidfile::remove();
        }
        None => { /* no parent pid file — still check the child + orphan backstops */ }
    }

    // ── 2) The engine child backstop (`miner-child.pid`). ────────────────────────
    // Signal it ONLY after re-verifying the live pid's command line still contains OUR
    // recorded engine path — never a stale pid the OS reused for an unrelated process.
    if let Some(cpid) = alice_miner_core::terminal::read_child_pid() {
        if !pidfile::is_alive(cpid) {
            // The recorded child is gone — tidy its stale pid file.
            alice_miner_core::terminal::remove_child_pid(cpid);
        } else if child_pid_is_our_engine(cpid) {
            // Alive AND its command line is OUR recorded engine → safe to stop.
            println!(
                "{}",
                tr!(
                    "Stopping a leftover bundled miner process (pid {pid})…",
                    "正在停止遗留的内置矿工进程(pid {pid})…"
                )
                .replace("{pid}", &cpid.to_string())
            );
            match pidfile::stop_pid(cpid, timeout) {
                pidfile::StopOutcome::Error(e) => {
                    eprintln!("error: {e}");
                    had_error = true;
                }
                _ => acted = true,
            }
            alice_miner_core::terminal::remove_child_pid(cpid);
        } else {
            // Alive, but its command line is NOT our recorded engine: the OS has REUSED
            // this stale pid for an unrelated process. NEVER signal it. Leave the file
            // untouched — a genuine orphan would still verify + be caught on a later
            // stop, and a fresh `start` overwrites the record anyway.
            eprintln!(
                "{}",
                tr!(
                    "Recorded engine-child pid {pid} is now an unrelated process (reused pid); left it untouched.",
                    "记录的引擎子进程 pid {pid} 现在是无关进程(pid 已被系统复用);已跳过,不做处理。"
                )
                .replace("{pid}", &cpid.to_string())
            );
        }
    }

    // ── 3) Last resort (unix): an orphan of OUR EXACT bundled xmrig. ─────────────
    #[cfg(unix)]
    for pid in orphaned_bundled_xmrig_pids() {
        println!(
            "{}",
            tr!(
                "Stopping an orphaned bundled xmrig (pid {pid})…",
                "正在停止遗留的内置 xmrig 进程(pid {pid})…"
            )
            .replace("{pid}", &pid.to_string())
        );
        match pidfile::stop_pid(pid, timeout) {
            pidfile::StopOutcome::Error(e) => {
                eprintln!("error: {e}");
                had_error = true;
            }
            _ => acted = true,
        }
    }

    // ── Outcome. ─────────────────────────────────────────────────────────────────
    if acted {
        println!(
            "{}",
            tr!("Miner stopped. No orphan left.", "矿工已停止。没有遗留孤儿进程。")
        );
        EXIT_OK
    } else if had_error {
        EXIT_RUNTIME
    } else {
        eprintln!(
            "{}",
            tr!("No running miner found.", "未找到运行中的矿工。")
        );
        // Not an error per se, but non-zero so scripts can branch.
        EXIT_RUNTIME
    }
}

/// Parse a newline-separated pid list (e.g. `pgrep` stdout) into unique pids, dropping
/// blanks / junk, pid 0, and our OWN pid (we must never signal ourselves). Pure +
/// testable; the caller re-verifies each pid's liveness AND command line before ever
/// signalling it (see [`orphaned_bundled_xmrig_pids`]).
fn parse_pid_list(stdout: &str, self_pid: u32) -> Vec<u32> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        if let Ok(pid) = line.trim().parse::<u32>() {
            if pid != 0 && pid != self_pid && !out.contains(&pid) {
                out.push(pid);
            }
        }
    }
    out
}

/// Find live orphans running OUR EXACT bundled xmrig (the sibling binary next to this
/// executable). The **safety red line**: we `pgrep -f` the exact bundled path, then
/// for EACH candidate re-verify (a) it is still alive AND (b) its actual command line
/// contains that exact path — so a process that merely shares the name `xmrig` (or any
/// non-bundled xmrig the user runs) can NEVER be matched or killed. Returns the
/// verified pids (empty when there is no bundled xmrig, no `pgrep`, or nothing matches).
#[cfg(unix)]
fn orphaned_bundled_xmrig_pids() -> Vec<u32> {
    use std::process::Command;
    let Some(bundled) = alice_miner_core::terminal::bundled_xmrig_path() else {
        return Vec::new(); // no bundled xmrig beside us → nothing we're allowed to touch
    };
    let needle = bundled.to_string_lossy().to_string();
    // `-f` matches the FULL command line; the exact absolute bundled path means only
    // processes actually running OUR xmrig can appear — and we STILL re-verify below.
    let Ok(out) = Command::new("pgrep").arg("-f").arg(&needle).output() else {
        return Vec::new(); // no pgrep available → skip the last resort (layers 1–2 stand)
    };
    parse_pid_list(&String::from_utf8_lossy(&out.stdout), std::process::id())
        .into_iter()
        .filter(|&pid| pidfile::is_alive(pid))
        .filter(|&pid| process_cmdline_contains(pid, &needle))
        .collect()
}

/// True iff live process `cpid`'s command line contains OUR recorded engine binary
/// path — the path `core::supervise` wrote next to the child pid (engine-agnostic:
/// xmrig / SRBMiner / kawpowminer / AlphaMiner / an env-override engine). Falls back to
/// the bundled xmrig path for a legacy pid-only child file. The hard guard that the
/// layer-2 child-pid backstop can NEVER signal an unrelated process that merely
/// inherited a reused pid; returns `false` when we cannot positively identify the
/// process, so we decline to kill what we cannot verify.
fn child_pid_is_our_engine(cpid: u32) -> bool {
    let needle = alice_miner_core::terminal::read_child_engine_path()
        .or_else(alice_miner_core::terminal::bundled_xmrig_path);
    match needle {
        Some(path) => process_cmdline_contains(cpid, &path.to_string_lossy()),
        None => false,
    }
}

/// Re-verify (defense in depth) that live process `pid`'s command line actually
/// contains `needle` (an exact engine path) before we ever signal it — the hard guard
/// that BOTH the layer-2 child-pid backstop AND the layer-3 last-resort orphan sweep
/// can only ever hit OUR engine. Returns `false` on any failure to read the command
/// line, so a process we cannot positively identify is never killed.
fn process_cmdline_contains(pid: u32, needle: &str) -> bool {
    #[cfg(unix)]
    {
        use std::process::Command;
        Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "command="])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(needle))
            .unwrap_or(false)
    }
    #[cfg(windows)]
    {
        use std::process::Command;
        // WMIC exposes the FULL command line for a pid. A missing / failed WMIC (e.g.
        // removed on very recent Windows) yields `false`, so we conservatively DECLINE
        // to signal a pid we cannot positively identify.
        Command::new("wmic")
            .args(["process", "where", &format!("ProcessId={pid}"), "get", "CommandLine", "/value"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(needle))
            .unwrap_or(false)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (pid, needle);
        false
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
            "warning: {}",
            tr!(
                "--password is INSECURE — it is visible in the process table (ps) and your shell \
                 history. Use the interactive prompt (omit --password) or --password-stdin.",
                "--password 不安全 — 它在进程表(ps)和 shell 历史中可见。\
                 请使用交互式提示(省略 --password)或 --password-stdin。"
            )
        );
        return if p.is_empty() {
            Err("passphrase must not be empty".into())
        } else {
            Ok(p)
        };
    }
    rpassword::prompt_password(tr!("Keystore passphrase: ", "密钥库口令: "))
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
    format!(
        "\n{}\n  alice-miner start\n",
        tr!("Next: start mining to this address", "下一步: 向此地址开始挖矿")
    )
}

/// After `start` reaches the Running state: tell the user how to keep mining in
/// the background after they close the window. The lane token is the SAME one
/// `service --install --lane <lane>` accepts, so the line is copy-paste ready.
fn next_steps_after_running(lane: Lane) -> String {
    format!(
        "\n{}\n  alice-miner service --install --lane {}\n",
        tr!(
            "Tip: to keep mining after you close this window, install the background service:",
            "提示: 想在关闭此窗口后继续挖矿,请安装后台服务:"
        ),
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
        Ok(None) => Some(format!(
            "\n{}\n  alice-miner identity --set-prl-payout <prl1p…>\n",
            tr!(
                "This GPU lane earns the 15% PRL return. To claim it, set your PRL return address:",
                "此 GPU 通道可获得 15% PRL 返还。要领取它,请设置你的 PRL 返还地址:"
            )
        )),
        Err(_) => None,
    }
}

/// After `service --install` succeeds: how to check status / uninstall, so the
/// user isn't left guessing whether the background agent took.
fn next_steps_after_service_install() -> String {
    format!(
        "\n{}:   alice-miner service --status\n{}: alice-miner service --uninstall\n",
        tr!("Check it any time", "随时查看状态"),
        tr!("Stop background mining", "停止后台挖矿")
    )
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

        // train: defaults (all None) + full flags parse to the expected shape.
        let cli = Cli::try_parse_from(["alice-miner", "train"]).unwrap();
        match cli.command.unwrap() {
            Command::Train(a) => {
                assert!(a.center_url.is_none() && a.trainer_dir.is_none());
                assert!(!a.allow_cpu);
            }
            _ => panic!("expected train"),
        }
        let cli = Cli::try_parse_from([
            "alice-miner", "train", "--center-url", "https://api.aliceprotocol.org",
            "--trainer-dir", "/opt/m0", "--base-model", "Qwen/Qwen2.5-3B-Instruct",
            "--device", "cpu", "--allow-cpu", "--region", "us",
        ])
        .unwrap();
        match cli.command.unwrap() {
            Command::Train(a) => {
                assert_eq!(a.center_url.as_deref(), Some("https://api.aliceprotocol.org"));
                assert_eq!(a.trainer_dir.as_deref(), Some("/opt/m0"));
                assert_eq!(a.base_model.as_deref(), Some("Qwen/Qwen2.5-3B-Instruct"));
                assert_eq!(a.device.as_deref(), Some("cpu"));
                assert!(a.allow_cpu);
                assert_eq!(a.region.as_deref(), Some("us"));
            }
            _ => panic!("expected train"),
        }

        // doctor --train parses with the train-specific flags; --ai and --train conflict.
        let cli = Cli::try_parse_from([
            "alice-miner", "doctor", "--train", "--trainer-dir", "/opt/m0", "--device", "cpu",
        ])
        .unwrap();
        match cli.command.unwrap() {
            Command::Doctor(a) => {
                assert!(a.train && !a.ai);
                assert_eq!(a.trainer_dir.as_deref(), Some("/opt/m0"));
            }
            _ => panic!("expected doctor"),
        }
        assert!(
            Cli::try_parse_from(["alice-miner", "doctor", "--ai", "--train"]).is_err(),
            "--ai and --train are mutually exclusive"
        );
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
    fn start_region_flag_parses_else_none() {
        // Present → the raw value is carried (validation happens in apply_region_flag).
        let cli = Cli::try_parse_from(["alice-miner", "start", "--region", "asia"]).unwrap();
        match cli.command.unwrap() {
            Command::Start(a) => assert_eq!(a.region.as_deref(), Some("asia")),
            _ => panic!("expected start"),
        }
        // Absent → None (keep whatever region was remembered — the conservative default).
        let cli = Cli::try_parse_from(["alice-miner", "start"]).unwrap();
        match cli.command.unwrap() {
            Command::Start(a) => assert!(a.region.is_none()),
            _ => panic!("expected start"),
        }
    }

    /// The hidden `--telemetry-file <PATH>` parses onto `StartArgs.telemetry_file`
    /// (the GUI passes it so the desktop Dashboard can poll this terminal's live
    /// snapshot); absent leaves it `None` (a normal `start` writes no telemetry).
    #[test]
    fn start_telemetry_file_flag_parses_else_none() {
        let cli = Cli::try_parse_from([
            "alice-miner", "start", "--telemetry-file", "/tmp/snap.json",
        ])
        .unwrap();
        match cli.command.unwrap() {
            Command::Start(a) => {
                assert_eq!(a.telemetry_file.as_deref(), Some(std::path::Path::new("/tmp/snap.json")))
            }
            _ => panic!("expected start"),
        }
        let cli = Cli::try_parse_from(["alice-miner", "start"]).unwrap();
        match cli.command.unwrap() {
            Command::Start(a) => assert!(a.telemetry_file.is_none()),
            _ => panic!("expected start"),
        }
    }

    /// The telemetry file is an ATOMIC OVERWRITE, never an append: a second write
    /// REPLACES the file (its byte length tracks only the latest snapshot, and it
    /// deserializes back to exactly that snapshot). Also proves the on-disk JSON is
    /// secret-free (no password / seed / paid_acu — the credit-only wire form).
    #[test]
    fn telemetry_file_overwrites_not_appends_and_is_secret_free() {
        use alice_miner_core::Snapshot;
        let dir = std::env::temp_dir().join(format!(
            "alice-telemetry-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("snap.json");

        // A first, LONG snapshot (running, big share count + a live hashrate). Built via
        // serde (the `Snapshot` constructors are crate-private) — EngineState is
        // `snake_case`. Only the required fields are present; Option/default fields fill in.
        let running: Snapshot = serde_json::from_str(
            r#"{"state":"running","shares_accepted":123456789,"shares_rejected":0,
                "hashrate_hs":6520.0,"uptime_s":42,"failovers":0,"dual":false,
                "endpoint":"asia.aliceprotocol.org:3340"}"#,
        )
        .unwrap();
        write_telemetry_file(&path, &running);
        let first = std::fs::read(&path).unwrap();

        // A second, SHORTER snapshot (idle, zero shares) must REPLACE the file — if we
        // appended, the file would only ever grow; here the byte length shrinks and the
        // parsed content is exactly the second snapshot.
        let idle: Snapshot = serde_json::from_str(
            r#"{"state":"idle","shares_accepted":0,"shares_rejected":0,"uptime_s":0,
                "failovers":0,"dual":false}"#,
        )
        .unwrap();
        write_telemetry_file(&path, &idle);
        let second = std::fs::read(&path).unwrap();
        assert!(second.len() < first.len(), "overwrite must not append (file grew)");
        let parsed: Snapshot = serde_json::from_slice(&second).unwrap();
        assert_eq!(parsed, idle);

        // Secret-free wire form: no reward/secret tokens ever reach the file.
        let text = String::from_utf8_lossy(&first).to_lowercase();
        for forbidden in ["password", "paid_acu", "seed", "mnemonic", "prl1p"] {
            assert!(!text.contains(forbidden), "telemetry JSON leaked `{forbidden}`");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The stop last-resort pid-list parser drops blanks / junk / pid 0 and our OWN
    /// pid, and de-dups — so the orphan backstop never signals a bogus or self pid.
    #[test]
    fn parse_pid_list_filters_junk_self_and_dedups() {
        let self_pid = std::process::id();
        let stdout = format!("1234\n  5678 \n\nnot-a-pid\n0\n{self_pid}\n1234\n");
        assert_eq!(parse_pid_list(&stdout, self_pid), vec![1234, 5678]);
        // Empty / all-junk input → no pids.
        assert!(parse_pid_list("\n\n  \nxyz\n", self_pid).is_empty());
    }

    /// `process_cmdline_contains` matches a LIVE process ONLY when its command line
    /// actually carries the exact engine path — the defense-in-depth guard both stop
    /// backstops re-check. We spawn a real child via an ABSOLUTE program path (exactly
    /// how the engine is launched: `Command::new(<abs engine path>)`), so its command
    /// line contains that path, and confirm a DIFFERENT path never matches it.
    #[cfg(unix)]
    #[test]
    fn process_cmdline_contains_matches_only_the_exact_path() {
        use std::process::{Command, Stdio};
        let sleep = if std::path::Path::new("/bin/sleep").exists() {
            "/bin/sleep"
        } else {
            "/usr/bin/sleep"
        };
        let mut child = Command::new(sleep)
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        // Positive: the child's command line DOES contain its exact program path.
        assert!(process_cmdline_contains(pid, sleep));
        // Negative (the pid-reuse guard): a DIFFERENT engine path is NOT in its command
        // line, so a reused pid can never be mistaken for our engine.
        assert!(!process_cmdline_contains(pid, "/opt/AliceMiner/Contents/MacOS/xmrig"));
        let _ = child.kill();
        let _ = child.wait();
    }

    /// The layer-2 backstop's identity gate: `child_pid_is_our_engine` returns TRUE only
    /// when the LIVE recorded pid actually runs the engine path we recorded, and FALSE
    /// when the pid is alive but running SOMETHING ELSE (the OS reused a stale pid) — the
    /// exact reboot/SIGKILL mis-kill this fix closes. Isolated under `$ALICE_IDENTITY_DIR`.
    #[cfg(unix)]
    #[test]
    fn child_pid_is_our_engine_rejects_a_reused_pid() {
        use std::process::{Command, Stdio};
        let _g = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!(
            "alice-childguard-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        std::env::set_var("ALICE_IDENTITY_DIR", &tmp);

        let sleep = if std::path::Path::new("/bin/sleep").exists() {
            "/bin/sleep"
        } else {
            "/usr/bin/sleep"
        };
        let mut child = Command::new(sleep)
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();

        // Record the SAME live pid but a MISMATCHED engine path (models a reused pid:
        // the process is alive, but it is NOT our engine) → the guard must REFUSE it.
        alice_miner_core::terminal::write_child_pid(
            pid,
            std::path::Path::new("/opt/AliceMiner/Contents/MacOS/xmrig"),
        );
        assert!(
            !child_pid_is_our_engine(pid),
            "a live pid running something OTHER than the recorded engine must never verify"
        );

        // Record the pid with the CORRECT engine path it is actually running → verifies.
        alice_miner_core::terminal::write_child_pid(pid, std::path::Path::new(sleep));
        assert!(
            child_pid_is_our_engine(pid),
            "a live pid running the recorded engine path must verify"
        );

        let _ = child.kill();
        let _ = child.wait();
        std::env::remove_var("ALICE_IDENTITY_DIR");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// `apply_region_flag` LOCKS a known region, CLEARS on `auto`, and rejects an
    /// unknown value with a usage error — all persisted under an ISOLATED identity
    /// dir (never the real `~/.alice`).
    #[test]
    fn apply_region_flag_locks_clears_and_rejects() {
        let _g = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!(
            "alice-region-flag-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        std::env::set_var("ALICE_IDENTITY_DIR", &tmp);

        // Lock (case-insensitive) → persisted.
        assert!(apply_region_flag("ASIA", /*json=*/ true).is_ok());
        assert_eq!(
            alice_miner_core::settings::load().region_lock.as_deref(),
            Some("asia")
        );
        // Clear via `auto` → lock removed.
        assert!(apply_region_flag("auto", true).is_ok());
        assert_eq!(alice_miner_core::settings::load().region_lock, None);
        // Unknown region → usage error (never a silent no-op), and NOTHING persisted.
        assert_eq!(apply_region_flag("atlantis", true), Err(EXIT_USAGE));
        assert_eq!(alice_miner_core::settings::load().region_lock, None);

        std::env::remove_var("ALICE_IDENTITY_DIR");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn resolve_lane_maps_aliases_and_auto() {
        let cap = alice_miner_core::CapabilityProfile::detect();
        assert_eq!(resolve_lane("xmr", &cap).unwrap(), Lane::Xmr);
        assert_eq!(resolve_lane("cpu", &cap).unwrap(), Lane::Xmr);
        // `gpu` now means the GPU mainline (PRL).
        assert_eq!(resolve_lane("gpu", &cap).unwrap(), Lane::GpuPrl);
        assert_eq!(resolve_lane("prl", &cap).unwrap(), Lane::GpuPrl);
        assert_eq!(resolve_lane("alpha", &cap).unwrap(), Lane::GpuAlpha);
        assert_eq!(resolve_lane("ALPHA", &cap).unwrap(), Lane::GpuAlpha);
        assert_eq!(resolve_lane("AUTO", &cap).unwrap(), cap.recommended_lane());
        assert!(resolve_lane("bogus", &cap).is_err());
    }

    /// The RVN (KawPoW) lane is not shipped in this release (its miner binary is an
    /// M7 packaging placeholder). `--lane rvn` must be rejected with a clean usage
    /// error (the "coming in M7" message) rather than resolved to `Lane::GpuRvn` and
    /// left to fail opaquely in binary resolution. Case-insensitive.
    #[test]
    fn resolve_lane_gates_rvn_with_usage_error() {
        let cap = alice_miner_core::CapabilityProfile::detect();
        assert_eq!(resolve_lane("rvn", &cap).unwrap_err(), EXIT_USAGE);
        assert_eq!(resolve_lane("RVN", &cap).unwrap_err(), EXIT_USAGE);
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
            temp_c: None,
            power_w: None,
            util_pct: None,
            fan_pct: None,
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
