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
mod engines;
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

/// ONE crate-wide serialization lock for tests that pin the PROCESS-GLOBAL language
/// ([`alice_miner_core::i18n::set_lang`]).
///
/// Until now each module kept its own private `LANG_LOCK`, which serializes a module's
/// tests against *itself* but not against the five other modules doing the same thing —
/// cargo runs the whole bin's unit tests in one process, on parallel threads, so
/// `balance`'s EN test could observe the `zh` that `region` had just set. Nothing had
/// tripped it yet; adding a sixth participant (`errmsg`, whose whole point is an
/// EN-mode-emits-no-Chinese assertion) makes an actual flake likely. Test-only.
#[cfg(test)]
pub(crate) static LANG_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// ── Exit codes ──────────────────────────────────────────────────────────────
/// Success.
const EXIT_OK: i32 = 0;
/// Runtime / engine fault (spawn failed, relay unreachable, …).
const EXIT_RUNTIME: i32 = 1;
/// Usage / argument error (bad lane, no identity flag, dual refused, …).
const EXIT_USAGE: i32 = 2;
/// `stop` only: **we could not confirm the miner stopped** — it may still be mining.
/// Split out of the generic runtime code (1) so a caller can tell this apart from the
/// ordinary, harmless "no running miner found", which is also non-zero. The GUI keys
/// its "could not confirm" warning off exactly this code
/// (`core::terminal::EXIT_STOP_UNVERIFIED`, kept in sync by a test below).
const EXIT_UNVERIFIED: i32 = 3;
/// `stop` only: **the miner stopped and everything we probed was confirmed — but the
/// last-resort sweep for leftover engine processes could not RUN** (no `pgrep` / a
/// `pgrep` that failed / PowerShell blocked by AppLocker or an execution policy).
///
/// Why its own code rather than 0 (round 3). The stop itself is a success and stays
/// one — round 2 deliberately stopped crying wolf here — but the CLI drops the
/// "No orphan left" half of its claim, and the GUI had no way to learn that: it reads
/// only the exit code and the CLI's stderr, and that stderr is BILINGUAL (`tr!`), so
/// matching on its prose would silently do nothing for a Chinese-locale miner. A code
/// is the only channel that survives translation. The GUI shows it as a calm one-line
/// note, never the red banner — nothing here says the miner is still running (that is
/// what [`EXIT_UNVERIFIED`] is for), only that one check could not be performed.
///
/// For scripts: `0` and `4` both mean **stopped**; `3` means may-still-be-running.
const EXIT_SCAN_GAP: i32 = 4;
/// `start` only: **refused because another `alice-miner start` is already running**
/// on this data directory (AM-REL-007). Its own code so a supervisor script can tell
/// "already running, nothing to do" apart from a real failure — restarting on this
/// code would be exactly the wrong move.
const EXIT_ALREADY_RUNNING: i32 = 5;

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
    // `--version` prints version + target triple + OS (the build stamp), so a field
    // bug report pins the exact artifact. clap prefixes the bin name.
    version = doctor::VERSION_LINE,
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

    /// Show which mining engine is pinned, where it came from, and check for a
    /// newer signed pin.
    #[command(long_about = "Show the mining ENGINE this client is allowed to run: the pinned\n\
        SHA-256, the upstream version + release URL, when we endorsed it, whether the\n\
        pin comes from this client's built-in table or from a separately-signed engine\n\
        pin list, and whether the bytes are present + verified on this machine.\n\
        \n\
        The engine is a third-party binary, so it is only ever run when its SHA-256\n\
        matches the pin. If it does not match, the lane stops and says so — it never\n\
        silently falls back to an older engine.\n\
        \n\
        --check   check for a newer signed engine pin list right now (an upstream\n\
                  emergency fork can be answered this way with no client update).\n\
                  The new engine is downloaded and verified BEFORE it takes effect;\n\
                  if anything fails, the current engine stays exactly as it is.\n\
        --json    machine-readable output")]
    Engines(engines::EnginesArgs),

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
    /// `--set-prl-payout` only: "I have compared the FULL address against my PRL
    /// wallet." Without it, an interactive run prints the whole address and asks
    /// y/N, and a NON-interactive run REFUSES (we never infer consent for the
    /// address that decides where your 15% return is sent).
    #[arg(long, requires = "set_prl_payout")]
    confirm_payout: bool,
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
    /// Skip the "a keystore already exists — overwrite?" confirmation that
    /// `--create` shows before replacing an existing wallet (the old key is
    /// backed up to a `.bak-…` either way). REQUIRED for non-interactive
    /// automation: without it, a `--create` over an existing keystore prompts
    /// y/N on a TTY and REFUSES on a non-TTY, so a mistaken re-run can never
    /// silently swap your wallet.
    #[arg(long, visible_alias = "yes")]
    force: bool,
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
    /// Start even though another `alice-miner start` already holds this data
    /// directory's rendezvous. NOT recommended: both instances drive the same engine
    /// directory and overwrite each other's telemetry, and `alice-miner stop` can only
    /// reach the recorded one. The legitimate use is a FALSE positive — pids are
    /// recycled, so a recorded pid can be alive as an unrelated program. For genuinely
    /// running two miners, give each one its own `ALICE_IDENTITY_DIR` instead.
    #[arg(long)]
    allow_multiple: bool,
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

/// How often the background agent re-checks a held rendezvous.
const SERVICE_RENDEZVOUS_POLL: std::time::Duration = std::time::Duration::from_secs(15);
/// How often it says so while waiting (a line every ~5 minutes, not every poll).
const SERVICE_RENDEZVOUS_LOG_EVERY: u32 = 20;

/// Claim the rendezvous, or — for the BACKGROUND AGENT only — wait for it.
///
/// A user-launched `start` gets an immediate, actionable refusal. The agent instead
/// polls, because its supervisor respawns it on every exit: refusing would turn one
/// foreground mining session into a restart storm (launchd) or a tripped start limit
/// that leaves the agent dead afterwards (systemd). It reports the wait once, then
/// roughly every five minutes, so the state is visible in the service log without
/// flooding it.
fn wait_or_acquire_rendezvous(args: &StartArgs) -> Result<pidfile::PidGuard, pidfile::InstanceConflict> {
    let first = pidfile::PidGuard::try_acquire(args.allow_multiple);
    if !args.from_service {
        return first;
    }
    let Err(conflict) = first else {
        return first;
    };
    eprintln!(
        "{}",
        tr!(
            format!(
                "background agent: pid {} is already mining on this data directory; waiting for \
                 it to finish rather than starting a second miner.",
                conflict.pid
            ),
            format!(
                "后台代理:进程 {} 已在本数据目录上挖矿;等待其结束,而不是启动第二个矿工。",
                conflict.pid
            )
        )
    );
    let mut ticks: u32 = SERVICE_RENDEZVOUS_LOG_EVERY;
    loop {
        std::thread::sleep(SERVICE_RENDEZVOUS_POLL);
        match pidfile::PidGuard::try_acquire(args.allow_multiple) {
            Ok(g) => {
                eprintln!(
                    "{}",
                    tr!(
                        "background agent: the rendezvous is free — starting.",
                        "后台代理:会合已释放 —— 正在启动。"
                    )
                );
                return Ok(g);
            }
            Err(c) => {
                // A countdown rather than a modulo: `u32::is_multiple_of` is newer
                // than this workspace's floor toolchain, and clippy rejects the
                // hand-rolled `%` form.
                ticks = if ticks == 0 {
                    SERVICE_RENDEZVOUS_LOG_EVERY - 1
                } else {
                    ticks - 1
                };
                if ticks == 0 {
                    eprintln!(
                        "{}",
                        tr!(
                            format!("background agent: still waiting for pid {}.", c.pid),
                            format!("后台代理:仍在等待进程 {}。", c.pid)
                        )
                    );
                }
            }
        }
    }
}

/// The warning for a start that is running WITHOUT owning the rendezvous. Each of
/// the three reasons is genuinely different, and the advice differs with it — one
/// generic "another instance may be running" line would be the vague guess the
/// honesty rule forbids. Pure, so the wording is unit-tested.
fn describe_sharing(reason: &pidfile::SharingReason) -> String {
    match reason {
        pidfile::SharingReason::UserOverride { pid, data_dir } => {
            let dir = data_dir
                .as_ref()
                .map(|d| d.display().to_string())
                .unwrap_or_else(|| tr!("(not recorded)", "(未记录)").to_string());
            tr!(
                format!(
                    "warning: starting anyway (--allow-multiple) while pid {pid} holds this \
                     rendezvous (data dir {dir}).\n\
                     This instance did NOT take the rendezvous, so `alice-miner stop` will \
                     target pid {pid}, not this one —\n\
                     stop this window with Ctrl-C. If both are really miners they share one \
                     engine directory and\n\
                     overwrite each other's telemetry; give each its own ALICE_IDENTITY_DIR \
                     instead."
                ),
                format!(
                    "警告:已按 --allow-multiple 强行启动,而进程 {pid} 仍持有本会合文件\
                     (数据目录 {dir})。\n\
                     本实例未取得会合登记,因此 `alice-miner stop` 会停掉进程 {pid} 而不是\
                     本实例 —— 请用 Ctrl-C 停止本窗口。\n\
                     若两者都是矿工,它们会共用同一个引擎目录并互相覆盖遥测;\
                     请改为各自使用独立的 ALICE_IDENTITY_DIR。"
                )
            )
        }
        pidfile::SharingReason::Unverifiable { pid } => tr!(
            format!(
                "warning: pid {pid} is recorded as the running miner, but this system could \
                 NOT tell us whether it\n\
                 is still alive (the process probe did not run). We do not know, so we are \
                 neither refusing to start\n\
                 nor claiming the rendezvous: `alice-miner stop` will target pid {pid}. If \
                 that is stale, delete the\n\
                 pid file and restart; if a miner really is running there, stop it first."
            ),
            format!(
                "警告:记录中的运行矿工为进程 {pid},但本系统无法判断它是否仍在运行\
                 (进程探测未能执行)。\n\
                 既然无法确定,我们既不拒绝启动、也不接管会合登记:`alice-miner stop` \
                 仍会指向进程 {pid}。\n\
                 若该记录已过期,请删除 pid 文件后重启;若那里确有矿工在跑,请先停止它。"
            )
        ),
        pidfile::SharingReason::RendezvousUnavailable => tr!(
            "note: the pid file could not be written (read-only home?). Mining works \
             normally, but `alice-miner stop` from another window will not find this \
             process — stop it with Ctrl-C.",
            "提示:无法写入 pid 文件(只读的主目录?)。挖矿不受影响,但从另一个窗口运行 \
             `alice-miner stop` 将找不到本进程 —— 请用 Ctrl-C 停止。"
        )
        .to_string(),
    }
}

fn main() {
    // FIRST, before ANY output (including clap's help/version/usage errors): on
    // Windows, force the console code pages to UTF-8 so our UTF-8 text — notably
    // 中文 — is not mojibake'd by a legacy OEM code page (cp950/Big5 on 繁中
    // Windows). No-op on other platforms and when no console is attached. See
    // `alice_miner_core::console::init_utf8_console` for the full root-cause note.
    alice_miner_core::console::init_utf8_console();

    // AM-REL-009, step 1: resolve the self-update health gate BEFORE anything that
    // can fail, so a freshly-installed build that dies during startup is on record
    // and gets rolled back on its next attempt. (The CLI never called this; only the
    // GUI did, so headless self-updates had no rollback at all.)
    let launch_health = update::register_launch_at_startup();

    // The same question for an update NOBODY asked for. Separate gate, separate
    // record, deliberately: the manual gate commits as soon as the binary starts,
    // which is the right bar for a build a human chose and too low a bar for one
    // that installed itself. A rollback here has already happened on disk by the
    // time this returns — the line it hands back says so precisely.
    let auto_rollback = alice_miner_core::autoupdate::register_launch();

    // Parse WITHOUT clap's built-in exit, so the health gate below runs even on
    // `--help` / a usage error — both of which prove the binary loads and runs.
    let parsed = Cli::try_parse();

    // AM-REL-009, step 2: the process is demonstrably up. Commit a pending update
    // (drop last-known-good) or report a rollback that already happened.
    update::confirm_launch_health(&launch_health);
    alice_miner_core::autoupdate::confirm_start();
    if let Some(msg) = auto_rollback {
        eprintln!("{msg}");
    }

    let cli = match parsed {
        Ok(c) => c,
        // `exit` prints to the right stream (stdout for --help/--version, stderr for
        // an error) with clap's own exit code — identical to what `parse()` did.
        Err(e) => e.exit(),
    };
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
        Some(Command::Engines(args)) => engines::run(args),
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
        Some(Command::Engines(a)) => !a.json,
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
        menu::MenuAction::Update => update::run(update::UpdateArgs { check: false, yes: false, auto: None }),
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
        allow_multiple: false,
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
        return cmd_set_prl_payout(addr, args.json, args.confirm_payout);
    }
    if args.show_prl_payout {
        return cmd_show_prl_payout(args.json);
    }

    // Overwrite guard: `--create` mints a FRESH random wallet, so a mistaken
    // re-run over an existing keystore would replace the active signing key
    // (backed up to a `.bak-…`, but a silent swap is still a footgun). Ask for
    // an explicit y/N first; `--force`/`--yes` skips it for automation, and a
    // non-interactive run without `--force` REFUSES rather than clobbering.
    // Runs BEFORE `build_identity_spec` so we never prompt for a passphrase only
    // to abort. Reuses `keystore_status` (public read; no secret touched).
    if let Some(code) = identity_overwrite_gate(args.create, args.force) {
        return code;
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

/// The overwrite decision for `--create`, factored out of all IO so it can be
/// unit-tested exhaustively. Given whether this is a `--create` over an EXISTING
/// keystore, whether `--force` was passed, TTY-ness, and (on a TTY) the user's
/// answer line, decide whether create proceeds or aborts.
#[derive(Debug, PartialEq, Eq)]
enum OverwriteDecision {
    /// Proceed with create: no existing keystore, `--force`, or an explicit y/yes.
    Proceed,
    /// Abort with this exit code: a non-TTY refusal (`EXIT_USAGE`) or a decline
    /// (`EXIT_OK` — the user chose not to overwrite; that is not an error).
    Abort(i32),
}

/// Pure overwrite policy (no IO). Only a `--create` over an existing keystore is
/// guarded; every other case (import, paste, no existing key, or `--force`)
/// proceeds exactly as before, so behaviour is unchanged unless you are about to
/// clobber a wallet. `answer` is the raw prompt line (only consulted on a TTY).
fn decide_overwrite(
    create: bool,
    force: bool,
    exists: bool,
    is_tty: bool,
    answer: Option<&str>,
) -> OverwriteDecision {
    if !create || force || !exists {
        return OverwriteDecision::Proceed;
    }
    if !is_tty {
        // Never silently swap a wallet in a non-interactive run: require --force.
        return OverwriteDecision::Abort(EXIT_USAGE);
    }
    match answer.map(|a| a.trim().to_ascii_lowercase()) {
        Some(a) if a == "y" || a == "yes" => OverwriteDecision::Proceed,
        _ => OverwriteDecision::Abort(EXIT_OK),
    }
}

/// Interactive/IO wrapper around [`decide_overwrite`]. Returns `Some(exit_code)`
/// when the caller must ABORT the create (declined, or non-interactive without
/// `--force`) and `None` when create may proceed. Shows the existing reward
/// address and the projected `.bak-…` path (reusing `keystore_status` +
/// `load_pointer`; both are public reads — no secret is touched).
fn identity_overwrite_gate(create: bool, force: bool) -> Option<i32> {
    use std::io::{IsTerminal, Write};
    // Fast path: nothing is at risk unless this is a create over an existing
    // keystore and `--force` was not given. Keep the keystore/TTY probes out of
    // every other identity invocation.
    if !create || force {
        return None;
    }
    let status = alice_miner_core::identity::keystore_status();
    if !status.exists {
        return None;
    }

    // Surface what would be replaced so the user knows this is a real wallet.
    eprintln!();
    eprintln!(
        "  {}",
        tr!("A miner keystore already exists:", "已存在一个矿工密钥库:")
    );
    eprintln!("    {}", status.path.display());
    if let Some(addr) = alice_miner_core::identity::load_pointer().map(|p| p.address) {
        eprintln!(
            "    {} {addr}",
            tr!("active reward address:", "当前奖励地址:")
        );
    }
    if let Some(bak) = status.projected_backup_path() {
        eprintln!(
            "  {} {}",
            tr!(
                "Creating a new identity backs up the old key to:",
                "创建新身份会先把旧密钥备份到:"
            ),
            bak.display()
        );
    }

    let is_tty = std::io::stdin().is_terminal();
    let answer = if is_tty {
        eprint!(
            "  {} [y/N] ",
            tr!("Overwrite and create a new identity?", "覆盖并创建新身份?")
        );
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return Some(EXIT_RUNTIME);
        }
        Some(line)
    } else {
        None
    };

    match decide_overwrite(create, force, status.exists, is_tty, answer.as_deref()) {
        OverwriteDecision::Proceed => None,
        OverwriteDecision::Abort(code) => {
            if is_tty {
                eprintln!(
                    "  {}",
                    tr!("aborted — keystore unchanged.", "已取消 — 密钥库未改动。")
                );
            } else {
                eprintln!(
                    "  {}",
                    tr!(
                        "not a terminal — re-run with --force to overwrite (the old key is backed up).",
                        "非终端 — 请加 --force 重新运行以覆盖(旧密钥会被备份)。"
                    )
                );
            }
            Some(code)
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
/// (public, no engine/secret). Bound to the Alice address on the next GPU-lane start.
///
/// AM-SEC-008 — two gates run BEFORE anything is written (and therefore long before
/// the address is ever signed into an enroll):
///   1. **full bech32m verify** (`validate_payout_address`) — a one-character typo is
///      caught here with a message that says so, instead of being signed, POSTed and
///      rejected server-side hours later;
///   2. **human confirmation of the FULL address** — printed unmasked and grouped, then
///      y/N on a terminal. Non-interactive runs must pass `--confirm-payout`; we do not
///      infer consent from a non-TTY.
fn cmd_set_prl_payout(addr: &str, json: bool, confirm_flag: bool) -> i32 {
    use alice_miner_core::prl_payout::{self, PayoutConfirm};
    use std::io::{IsTerminal, Write};

    let trimmed = addr.trim();
    // (1) Validate first, so a typo is reported as a typo and we never prompt the user
    //     to confirm an address that could not possibly be theirs.
    if let Err(e) = prl_payout::validate_payout_address(trimmed) {
        if json {
            println!("{}", serde_json::json!({ "set": false, "error": e }));
        } else {
            eprintln!("error: {e}");
        }
        return EXIT_USAGE;
    }

    // (2) Confirm the FULL address. `--json` is a machine surface: there is nobody to
    //     prompt, so it takes the non-interactive path and needs the explicit flag.
    let is_tty = std::io::stdin().is_terminal() && std::io::stderr().is_terminal() && !json;
    let answer = if !confirm_flag && is_tty {
        eprintln!();
        eprintln!(
            "  {}",
            tr!(
                "Your 15% PRL return will be sent to THIS address:",
                "你的 15% PRL 返还将发送到此地址:"
            )
        );
        eprintln!("    {}", prl_payout::format_for_confirm(trimmed));
        eprintln!(
            "  {}",
            tr!(
                "Compare it against your PRL wallet, character by character.",
                "请逐字与你的 PRL 钱包核对。"
            )
        );
        eprint!("  {} [y/N] ", tr!("Is this exactly your address?", "这确实是你的地址吗?"));
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        match std::io::stdin().read_line(&mut line) {
            Ok(_) => Some(line),
            Err(_) => return EXIT_RUNTIME,
        }
    } else {
        None
    };

    match prl_payout::decide_payout_confirm(is_tty, confirm_flag, answer.as_deref()) {
        PayoutConfirm::Proceed => {}
        PayoutConfirm::Declined => {
            eprintln!(
                "  {}",
                tr!("aborted — nothing was stored.", "已取消 — 未存储任何地址。")
            );
            return EXIT_USAGE;
        }
        PayoutConfirm::NeedsExplicitFlag => {
            let msg = tr!(
                "refusing to store an unconfirmed payout address: not a terminal, so nobody could verify it. Re-run with --confirm-payout once you have compared the full address against your PRL wallet.",
                "拒绝存储未经确认的返还地址: 当前不是终端,无人能核对。请先逐字核对完整地址,再加 --confirm-payout 重新运行。"
            );
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "set": false, "error": msg, "needs": "--confirm-payout" })
                );
            } else {
                eprintln!("error: {msg}");
            }
            return EXIT_USAGE;
        }
    }

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

    // F5 (acceptance halt): `--from-service` is the argv the launchd plist / systemd
    // unit / logon task run and that a human never types, so it is the one honest
    // signal that THIS start is a service manager relaunching us rather than a person
    // asking to mine. Declaring it makes the lane HONOR a persisted acceptance halt
    // (waiting out its bounded re-probe cooldown) instead of silently resuming a run
    // that earns nothing — the reboot/KeepAlive loop that used to burn a fresh window
    // every time. A human's `alice-miner start` keeps clearing the halt outright.
    if args.from_service {
        alice_miner_core::supervise::set_process_start_cause(
            alice_miner_core::supervise::StartCause::Automatic,
        );
    }

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
    // Capture the lock state BEFORE applying `--region`, so we can tell whether THIS run is
    // the one that newly established a lock (→ the one-time reminder below) vs a restart that
    // merely inherits a persisted lock (→ no nag).
    let prior_region_lock = alice_miner_core::settings::load().region_lock;
    if let Some(raw) = args.region.as_deref() {
        if let Err(code) = apply_region_flag(raw, args.json) {
            return code;
        }
    }
    // Region transparency for the GPU-PRL lane: label the effective MODE (locked vs auto +
    // last-good) AND the effective endpoint order, so the user always knows whether the lane
    // will auto-failover and exactly which relays it will use. Computed probe-free (the engine
    // runs the one real probe at start). The human banner (stdout) is still suppressed under
    // `--json` (machine consumers), but NO LONGER under `--from-service` — a service/GUI start
    // now surfaces the same region story in its own log.
    if lane == Lane::GpuPrl {
        let view = region::view();
        if !args.json {
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
        // One-time lock reminder: when THIS run just established a region lock, nudge ONCE on
        // stderr — which survives `--json`, so it reaches a non-interactive service/GUI start
        // too — that auto-failover is now off and how to unlock. A plain restart that inherits
        // the same persisted lock does NOT re-fire (prior == now), so it never nags. `failover_on`
        // is false ONLY for a valid LOCK, so this is precisely the locked state.
        if !view.failover_on {
            let norm = alice_miner_core::lane::gpu_prl::normalize_region_tag;
            let prior = prior_region_lock.as_deref().and_then(norm);
            let now = view.region_lock.as_deref().and_then(norm);
            if now.is_some() && prior != now {
                let tag = now.unwrap_or("this region");
                eprintln!(
                    "{}",
                    tr!(
                        "note: GPU-PRL is now locked to {tag} — auto-failover is off. Run `alice-miner start --region auto` any time to unlock and restore automatic nearest-region selection + failover.",
                        "提示: GPU-PRL 现已锁定到 {tag} — 自动切换已关闭。随时可跑 `alice-miner start --region auto` 解锁,恢复自动最近区域选择 + failover。"
                    )
                    .replace("{tag}", tag)
                );
            }
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

    // Claim the single-instance rendezvous ATOMICALLY, or refuse (AM-REL-007). The
    // guard removes the pid file on the way out so a stale pid never lingers.
    //
    // The BACKGROUND AGENT waits instead of refusing. It is supervised by launchd
    // (`KeepAlive` + a 30s throttle) / systemd (`Restart=always` with a start limit),
    // both of which respawn on ANY exit — so an agent that exited here would either
    // hammer the rendezvous every 30 seconds or, on systemd, trip its start limit and
    // stay down even after the user's foreground miner stopped. Waiting keeps the
    // single-miner guarantee AND leaves the agent ready to take over the moment the
    // foreground run ends, with no supervisor churn either way.
    let pid_guard = match wait_or_acquire_rendezvous(&args) {
        Ok(g) => g,
        Err(conflict) => {
            let dir = conflict
                .data_dir
                .as_ref()
                .map(|d| d.display().to_string())
                .unwrap_or_else(|| {
                    tr!("(not recorded by that instance)", "(该实例未记录)").to_string()
                });
            let pid = conflict.pid;
            eprintln!(
                "{}",
                tr!(
                    format!(
                        "error: another `alice-miner start` is already running.\n  \
                         process id : {pid}\n  \
                         data dir   : {dir}\n\n\
                         Refusing to start a second miner on the same data directory: both would \
                         drive the same\n\
                         engine directory and overwrite each other's telemetry, and \
                         `alice-miner stop` can only\n\
                         reach the recorded one — the survivor would keep the GPU busy while \
                         everything reported\n\
                         'stopped'.\n\n\
                         What to do:\n  \
                         • stop the running miner:      alice-miner stop\n  \
                         • or run this one in its own data directory:\n      \
                         ALICE_IDENTITY_DIR=/path/to/other-alice alice-miner start …\n  \
                         • if pid {pid} is NOT a miner (pids get recycled), re-run with \
                         --allow-multiple"
                    ),
                    format!(
                        "错误:已有另一个 `alice-miner start` 在运行。\n  \
                         进程号   : {pid}\n  \
                         数据目录 : {dir}\n\n\
                         拒绝在同一数据目录上启动第二个矿工:两者会驱动同一个引擎目录、互相覆盖\
                         遥测数据,\n\
                         而 `alice-miner stop` 只能停掉登记的那一个 —— 幸存的那个会继续占用 GPU,\
                         但所有界面都会\n\
                         显示“已停止”。\n\n\
                         可行做法:\n  \
                         • 停止正在运行的矿工:      alice-miner stop\n  \
                         • 或用独立数据目录运行本实例:\n      \
                         ALICE_IDENTITY_DIR=/path/to/other-alice alice-miner start …\n  \
                         • 若进程 {pid} 并不是矿工(进程号会被系统回收),请加 --allow-multiple 重试"
                    )
                )
            );
            return EXIT_ALREADY_RUNNING;
        }
    };

    // Running without the rendezvous is allowed in exactly three cases, and each one
    // says WHICH it is rather than printing one vague warning for all of them.
    if let Some(reason) = pid_guard.sharing() {
        if !args.json {
            eprintln!("{}", describe_sharing(reason));
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

    // The guarded automatic updater, for the life of this session. It checks in
    // the background (never on this thread), installs only what clears every
    // guardrail, and NEVER interrupts the running engine — an installed build
    // takes effect on the next start and the message says exactly that. It also
    // owns the mining half of the post-update health probation, because this loop
    // is the only place that can see both the elapsed session and the accepted
    // share count. `--json` / service runs keep the machinery and lose the prose.
    let mut auto = update::AutoUpdater::start(args.json || args.from_service);
    // Held until the in-place panel is torn down, so an update line is not painted
    // over by the next frame and then lost. Kept SEPARATE from `deferred_error` —
    // an update note must never overwrite an error the user needs to read.
    let mut deferred_update: Option<String> = None;

    loop {
        if let Some(msg) = auto.tick(last_snapshot.as_ref().map(|s| s.shares_accepted).unwrap_or(0))
        {
            if args.json {
                println!("{}", serde_json::json!({ "update": msg }));
            } else if tui.is_none() {
                eprintln!("{msg}");
            } else {
                deferred_update = Some(msg);
            }
        }
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
    if let Some(u) = deferred_update {
        eprintln!("{u}");
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
        // `gpu` means the GPU **mainline** = PRL (pearlhash). (`rvn`/KawPoW is not
        // shipped this release — gated below.)
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
///   3. **last resort** — a still-running orphan of OUR EXACT engine binary (the
///      recorded engine path, else the bundled xmrig beside this exe) that neither pid
///      file caught. Each candidate's command line is re-verified against that exact
///      path AND its liveness re-checked before we ever signal it — we NEVER kill by
///      the bare name `xmrig`, and NEVER a non-bundled process.
///
/// **The reporting rule (bug fix): never claim a success we did not verify.** Every
/// layer can end in "I could not tell" — a pid probe that failed, a command line we
/// could not read, an orphan scan we could not run. Those used to be silently folded
/// into the happy path, so `stop` printed "Miner stopped. No orphan left." while
/// xmrig kept mining (worst on Windows 11, where the `wmic` used to identify the
/// child no longer exists). Unverifiable outcomes are now collected and reported as
/// such, with a non-zero exit, telling the user exactly what to check.
fn cmd_stop(args: StopArgs) -> i32 {
    let timeout = Duration::from_secs(args.timeout_s);
    let mut acted = false; // stopped at least one LIVE process
    let mut had_error = false;
    // Things we could NOT confirm. Non-empty ⇒ we must not claim a clean stop.
    let mut unverified: Vec<String> = Vec::new();

    // The exact engine binary this install runs, captured BEFORE layer 2 consumes the
    // child pid file: the path `core::supervise` recorded (xmrig / SRBMiner /
    // kawpowminer / AlphaMiner / an env-override engine), else the bundled xmrig beside
    // us for a legacy pid-only file. Used as the identity needle by layers 2 AND 3, so
    // the orphan sweep covers whichever engine is actually installed.
    let engine_needle: Option<String> = alice_miner_core::terminal::read_child_engine_path()
        .or_else(alice_miner_core::terminal::bundled_xmrig_path)
        .map(|p| p.to_string_lossy().to_string());

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
                    // `Killed` is only returned after re-probing the pid and finding it
                    // gone, so this is a CONFIRMED termination, not "we sent a signal".
                    println!(
                        "{}",
                        tr!(
                            "Miner did not exit in time; force-terminated (confirmed stopped).",
                            "矿工未按时退出;已强制终止(已确认停止)。"
                        )
                    );
                    pidfile::remove();
                    acted = true;
                }
                pidfile::StopOutcome::Error(e) => {
                    eprintln!("error: {e}");
                    had_error = true;
                    // We asked it to stop and could not confirm it did — the engine may
                    // still be mining. Say so; do NOT delete the pid file (a later stop
                    // should still find it).
                    unverified.push(
                        tr!("the miner process (pid {pid})", "矿工进程(pid {pid})")
                            .replace("{pid}", &pid.to_string()),
                    );
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
        // `liveness_settled`: a killed-but-unreaped engine (zombie) is finished, not an
        // orphan — treat it as gone and tidy its pid file rather than warn about it.
        let identity = if pidfile::liveness_settled(cpid) == pidfile::Liveness::Dead {
            ChildIdentity::Gone
        } else {
            identify_child_pid(cpid, engine_needle.as_deref())
        };
        if identity == ChildIdentity::Gone {
            // The recorded child is positively gone — tidy its stale pid file.
            alice_miner_core::terminal::remove_child_pid(cpid);
        } else if identity == ChildIdentity::Ours {
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
                    unverified.push(
                        tr!("the mining engine (pid {pid})", "挖矿引擎进程(pid {pid})")
                            .replace("{pid}", &cpid.to_string()),
                    );
                }
                _ => {
                    acted = true;
                    alice_miner_core::terminal::remove_child_pid(cpid);
                }
            }
        } else if identity == ChildIdentity::Unrelated {
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
        } else {
            // ChildIdentity::Unknown — the pid is (or may be) alive and we could NOT
            // read its command line, so we cannot tell an orphaned engine from an
            // unrelated process that inherited a reused pid. We still refuse to signal
            // what we cannot identify (the safety red line), but this is precisely the
            // case that used to be swallowed and reported as "no orphan left": on
            // Windows 11 `wmic` is gone, so EVERY leftover engine landed here.
            eprintln!(
                "{}",
                tr!(
                    "Could not identify the recorded engine-child pid {pid} (unable to read its command line); left it untouched.",
                    "无法识别记录的引擎子进程 pid {pid}(读取其命令行失败);已跳过,不做处理。"
                )
                .replace("{pid}", &cpid.to_string())
            );
            unverified.push(
                tr!(
                    "an unidentifiable recorded engine process (pid {pid})",
                    "无法识别的引擎进程记录(pid {pid})"
                )
                .replace("{pid}", &cpid.to_string()),
            );
        }
    }

    // ── 3) Last resort: an orphan running OUR EXACT engine binary. ───────────────
    // Now runs on Windows too (via PowerShell's `Get-CimInstance Win32_Process`);
    // previously the sweep was unix-only, so Windows had NO orphan backstop at all.
    // `engine_needle == None` means this install has NO engine on record and no
    // bundled engine beside it — the sweep's contract is "processes running OUR exact
    // engine path", so with no such path the candidate set is empty BY DEFINITION.
    // That is not a scan gap and must not raise a warning (a `stop` on a machine with
    // nothing installed would otherwise cry wolf, which is its own dishonesty).
    let mut scan_gap = false;
    match engine_needle.as_deref().map(orphaned_engine_pids) {
        None => {}
        Some(Some(pids)) => {
            for pid in pids {
                println!(
                    "{}",
                    tr!(
                        "Stopping an orphaned mining engine (pid {pid})…",
                        "正在停止遗留的挖矿引擎进程(pid {pid})…"
                    )
                    .replace("{pid}", &pid.to_string())
                );
                match pidfile::stop_pid(pid, timeout) {
                    pidfile::StopOutcome::Error(e) => {
                        eprintln!("error: {e}");
                        had_error = true;
                        unverified.push(
                            tr!("an orphaned engine (pid {pid})", "遗留的引擎进程(pid {pid})")
                                .replace("{pid}", &pid.to_string()),
                        );
                    }
                    _ => acted = true,
                }
            }
        }
        // We know which engine to look for but could NOT scan (no `pgrep` / no
        // PowerShell — e.g. PowerShell blocked by AppLocker / an execution policy).
        // Everything above may still have succeeded, but we cannot back the "no orphan
        // left" claim, so we don't make it.
        Some(None) => scan_gap = true,
    }
    // ROUND 2 — a missing CAPABILITY is not evidence of a leftover. A scan gap used to
    // be pushed into `unverified`, so on a locked-down machine EVERY ordinary, fully
    // confirmed stop ended in "WARNING: could not confirm the miner stopped" + a
    // non-zero exit. That is honest about the gap but cries wolf about the outcome, and
    // a warning that fires every time is a warning nobody reads. The honest split:
    //   * everything we ACTUALLY probed was confirmed ⇒ this is a success — we just
    //     drop the part of the claim we cannot back ("No orphan left") and say why.
    //   * anything else unconfirmed ⇒ it stays a warning, and the scan gap is then
    //     listed with it, because now it might be hiding something.
    if scan_gap && !unverified.is_empty() {
        unverified.push(
            tr!(
                "leftover engine processes could not be scanned for on this system",
                "本机无法扫描是否存在遗留的引擎进程"
            )
            .to_string(),
        );
    }

    // ── Outcome. ─────────────────────────────────────────────────────────────────
    // Honesty first: an unverifiable outcome outranks a partial success. Better to
    // tell the user to check Task Manager than to promise a clean stop we didn't see.
    if !unverified.is_empty() {
        eprintln!(
            "{}",
            tr!(
                "WARNING: could not confirm the miner stopped.",
                "警告:无法确认矿工已停止。"
            )
        );
        for what in &unverified {
            eprintln!("  - {what}");
        }
        eprintln!(
            "{}",
            tr!(
                "Please check your task manager for a running xmrig / SRBMiner and end it manually.",
                "请在任务管理器中检查是否仍有 xmrig / SRBMiner 在运行,并手动结束它。"
            )
        );
    } else if acted {
        // "No orphan left" is a claim about a SCAN we ran. Without the scan we say the
        // part we verified — the processes we knew about are gone — and name the gap.
        if claims_no_orphan(scan_gap) {
            println!(
                "{}",
                tr!("Miner stopped. No orphan left.", "矿工已停止。没有遗留孤儿进程。")
            );
        } else {
            println!("{}", tr!("Miner stopped.", "矿工已停止。"));
            // The caveat goes to STDERR, not stdout: it is a diagnostic, not the
            // result — and the GUI nulls our stdout while capturing stderr, so on
            // stdout the miner running the app would never see these words at all.
            eprintln!(
                "{}",
                tr!(
                    "(This system could not be scanned for leftover engine processes; if your task \
                     manager still shows xmrig / SRBMiner, end it manually.)",
                    "(本机无法扫描是否存在遗留的引擎进程;如果任务管理器中仍有 xmrig / SRBMiner,\
                     请手动结束它。)"
                )
            );
        }
    } else if !had_error {
        eprintln!(
            "{}",
            tr!("No running miner found.", "未找到运行中的矿工。")
        );
        // We found nothing — but if we also could not run the orphan scan, say so
        // rather than let "nothing found" imply "nothing is running".
        if scan_gap {
            eprintln!(
                "{}",
                tr!(
                    "(Note: this system could not be scanned for leftover engine processes.)",
                    "(注意:本机无法扫描是否存在遗留的引擎进程。)"
                )
            );
        }
    }
    stop_exit_code(acted, had_error, !unverified.is_empty(), scan_gap)
}

/// May `stop` print "**No orphan left**"? Only when the last-resort sweep actually
/// RAN. Pure, so the rule is a test rather than a comment: the claim is about a scan,
/// so no scan ⇒ no claim (we still report the stop itself, which we did verify).
fn claims_no_orphan(scan_gap: bool) -> bool {
    !scan_gap
}

/// The `stop` exit code. Pure, so the rules that matter are directly testable:
///   * an unverified outcome NEVER exits 0, no matter how much else succeeded, and it
///     gets its OWN code ([`EXIT_UNVERIFIED`]) so a caller (the GUI) can tell "the
///     miner may still be running" apart from every other non-zero result;
///   * "no running miner found" is not an error per se, but stays non-zero so scripts
///     can branch on it — unchanged behaviour;
///   * a confirmed stop whose orphan SWEEP could not run is still a success, but it is
///     a success with a smaller claim, so it gets [`EXIT_SCAN_GAP`] instead of 0 — the
///     only translation-proof way to tell the GUI (round 3).
///
/// Precedence is the honesty order: "may still be running" outranks "something went
/// wrong", which outranks "one check could not be performed", which outranks clean.
/// A scan gap NEVER masks a worse outcome — when anything else was unconfirmed the
/// gap is folded into the `unverified` list by the caller and this returns 3.
fn stop_exit_code(acted: bool, had_error: bool, unverified: bool, scan_gap: bool) -> i32 {
    if unverified {
        EXIT_UNVERIFIED
    } else if had_error || !acted {
        EXIT_RUNTIME
    } else if scan_gap {
        EXIT_SCAN_GAP
    } else {
        EXIT_OK
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

/// Find live orphans running OUR EXACT engine binary (`needle` — the recorded engine
/// path, else the bundled xmrig beside this executable).
///
/// The **safety red line** is unchanged: we ask the OS for candidates by the exact
/// absolute path, then for EACH candidate re-verify (a) it is still alive AND (b) its
/// actual command line contains that exact path — so a process that merely shares the
/// name `xmrig` (or any non-bundled xmrig the user runs) can NEVER be matched or
/// killed.
///
/// `None` means **we could not scan** (the OS query tool is unavailable) — distinct
/// from `Some(vec![])`, "we scanned and found none". The caller must not claim "no
/// orphan left" on a `None`.
fn orphaned_engine_pids(needle: &str) -> Option<Vec<u32>> {
    let stdout = engine_pid_candidates(needle)?;
    Some(
        parse_pid_list(&stdout, std::process::id())
            .into_iter()
            .filter(|&pid| pidfile::is_alive(pid))
            .filter(|&pid| process_cmdline_contains(pid, needle))
            .collect(),
    )
}

/// Ask the OS for pids whose command line contains `needle`, as newline-separated
/// text. `None` when the query tool is unavailable / failed.
fn engine_pid_candidates(needle: &str) -> Option<String> {
    use std::process::Command;
    #[cfg(unix)]
    {
        // `-f` matches the FULL command line; the exact absolute path means only
        // processes actually running OUR engine can appear — and we STILL re-verify.
        let out = Command::new("pgrep").arg("-f").arg(needle).output().ok()?;
        // ROUND 3 — the ANSWER is the exit status, not the stdout. This branch used to
        // read stdout and nothing else, so a `pgrep` that ran and FAILED (no readable
        // `/proc` in a hardened container, a restricted session) printed nothing and
        // "nothing" became a positive "no orphans" — the unix twin of the Windows
        // false success closed in round 2, in the same function, four lines apart.
        // `PgrepScan` keeps the third answer: exit 1 ("no match") is still a real
        // result, only ≥2 / signal-killed is a scan gap.
        if !alice_miner_core::proc::classify_pgrep(out.status.code()).ran() {
            return None; // pgrep ran but FAILED → we did NOT scan
        }
        Some(String::from_utf8_lossy(&out.stdout).to_string())
    }
    #[cfg(windows)]
    {
        // `Get-CimInstance Win32_Process` is the supported replacement for `wmic`
        // (removed in recent Windows 11). The needle is passed through the ENVIRONMENT
        // and compared with `.Contains()`, never interpolated into the script text and
        // never treated as a wildcard pattern — so a path containing quotes, `$`, or
        // `[` `]` can neither break the command nor widen the match.
        let out = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-CimInstance Win32_Process | \
                 Where-Object { $_.CommandLine -and $_.CommandLine.Contains($env:ALICE_STOP_NEEDLE) } | \
                 ForEach-Object { $_.ProcessId }",
            ])
            .env("ALICE_STOP_NEEDLE", needle)
            .output()
            .ok()?;
        if !out.status.success() {
            return None; // PowerShell ran but failed → we did NOT scan
        }
        Some(String::from_utf8_lossy(&out.stdout).to_string())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = needle;
        None
    }
}

/// What we could establish about the recorded engine-child pid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildIdentity {
    /// Alive and its command line is OUR recorded engine → safe to stop.
    Ours,
    /// Alive but positively NOT our engine (the OS reused the pid) → never signal it.
    Unrelated,
    /// Positively gone.
    Gone,
    /// We could not read its command line → we neither signal it NOR claim it is gone.
    Unknown,
}

/// Classify the recorded engine-child pid against `needle` (our exact engine path).
///
/// The hard guard that the layer-2 backstop can NEVER signal an unrelated process
/// that merely inherited a reused pid. The change from the old boolean: "could not
/// identify" is no longer indistinguishable from "identified as someone else". Both
/// still decline to kill, but only the latter is a clean outcome — the former is
/// reported to the user, because on Windows 11 (no `wmic`) it was the NORMAL case and
/// silently produced a false "no orphan left".
///
/// **BACKLOG (known, not fixed here) — pid reuse with no start-time token.** The
/// command-line comparison narrows the window but does not close it: if the OS reuses
/// our recorded pid for a process that happens to run the SAME engine path (a second
/// Alice install, the user launching the bundled engine by hand), we classify it
/// `Ours` and stop it — and then report success for stopping something that was never
/// ours. The fix is to record the process START TIME alongside the pid and require
/// both to match; every platform exposes it (`ps -o lstart=`, `Win32_Process.CreationDate`).
/// Same gap on unix and Windows. Deliberately left for its own change: it touches the
/// pid-file FORMAT and every reader of it.
fn identify_child_pid(cpid: u32, needle: Option<&str>) -> ChildIdentity {
    let Some(needle) = needle else {
        return ChildIdentity::Unknown; // nothing to compare against
    };
    match process_cmdline(cpid) {
        Some(cmd) if cmd.contains(needle) => ChildIdentity::Ours,
        Some(_) => ChildIdentity::Unrelated,
        None => ChildIdentity::Unknown,
    }
}

/// Re-verify (defense in depth) that live process `pid`'s command line actually
/// contains `needle` (an exact engine path) before we ever signal it — the hard guard
/// that BOTH the layer-2 child-pid backstop AND the layer-3 last-resort orphan sweep
/// can only ever hit OUR engine. Returns `false` on any failure to read the command
/// line, so a process we cannot positively identify is never killed.
fn process_cmdline_contains(pid: u32, needle: &str) -> bool {
    process_cmdline(pid).map(|c| c.contains(needle)).unwrap_or(false)
}

/// Read live process `pid`'s full command line. `None` when it cannot be read (no
/// such process, no permission, or the query tool is missing) — the caller must treat
/// that as "unknown", never as "not ours".
fn process_cmdline(pid: u32) -> Option<String> {
    use std::process::Command;
    #[cfg(unix)]
    {
        let out = Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "command="])
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!s.is_empty()).then_some(s)
    }
    #[cfg(windows)]
    {
        // `wmic` was the old source and is REMOVED on current Windows 11, which is the
        // root of the false "no orphan left" report: every lookup failed, so every
        // leftover engine looked "unidentifiable" and was silently skipped. PowerShell's
        // CIM query is the supported replacement and ships with every supported Windows.
        let out = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "(Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}').CommandLine"
                ),
            ])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!s.is_empty()).then_some(s)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        None
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
    /// Spawn a long-lived child from an ABSOLUTE program path (exactly how the engine
    /// is launched), returning it plus that path — so its command line provably
    /// contains the path. Cross-platform so the stop-path tests below run on Windows
    /// CI too, where every one of these code paths was previously untested.
    #[cfg(any(unix, windows))]
    fn long_lived_child() -> (std::process::Child, String) {
        use std::process::{Command, Stdio};
        #[cfg(unix)]
        let (prog, args): (String, Vec<String>) = (
            if std::path::Path::new("/bin/sleep").exists() {
                "/bin/sleep".to_string()
            } else {
                "/usr/bin/sleep".to_string()
            },
            vec!["30".to_string()],
        );
        #[cfg(windows)]
        let (prog, args): (String, Vec<String>) = (
            format!(
                "{}\\System32\\cmd.exe",
                std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string())
            ),
            vec!["/C".to_string(), "ping -n 30 127.0.0.1".to_string()],
        );
        let child = Command::new(&prog)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn long-lived test child");
        (child, prog)
    }

    /// A path that is certainly not any live process's program.
    #[cfg(any(unix, windows))]
    const FOREIGN_ENGINE_PATH: &str = if cfg!(windows) {
        "C:\\Program Files\\AliceMiner\\xmrig.exe"
    } else {
        "/opt/AliceMiner/Contents/MacOS/xmrig"
    };

    /// `process_cmdline_contains` matches a LIVE process ONLY when its command line
    /// actually carries the exact engine path — the defense-in-depth guard both stop
    /// backstops re-check. On Windows this also exercises the PowerShell/CIM lookup
    /// that replaced `wmic` (removed in current Windows 11), which is the whole reason
    /// the orphan backstop silently failed there.
    #[cfg(any(unix, windows))]
    #[test]
    fn process_cmdline_contains_matches_only_the_exact_path() {
        let (mut child, prog) = long_lived_child();
        let pid = child.id();
        // Positive: the child's command line DOES contain its exact program path.
        assert!(
            process_cmdline_contains(pid, &prog),
            "a live process must be identifiable by its own program path \
             (on Windows: the PowerShell CIM lookup must work — wmic is gone)"
        );
        // Negative (the pid-reuse guard): a DIFFERENT engine path is NOT in its command
        // line, so a reused pid can never be mistaken for our engine.
        assert!(!process_cmdline_contains(pid, FOREIGN_ENGINE_PATH));
        let _ = child.kill();
        let _ = child.wait();
    }

    /// The honesty rule, isolated and pinned: an outcome we could not verify NEVER
    /// exits 0 — regardless of how many layers reported success. This is the invariant
    /// behind "better to say 'check Task Manager' than to promise a clean stop".
    #[test]
    fn unverified_stop_never_reports_success() {
        // The only path to EXIT_OK: we acted, no error, nothing unverified, and the
        // orphan sweep actually RAN.
        assert_eq!(stop_exit_code(true, false, false, false), EXIT_OK);
        // Acted AND fully "successful", but something could not be confirmed → its OWN
        // non-zero code, so the GUI can single out "the miner may still be running".
        assert_eq!(stop_exit_code(true, false, true, false), EXIT_UNVERIFIED);
        assert_eq!(stop_exit_code(true, true, true, false), EXIT_UNVERIFIED);
        // Errors and "nothing found" stay non-zero as before, on the generic code.
        assert_eq!(stop_exit_code(true, true, false, false), EXIT_RUNTIME);
        assert_eq!(stop_exit_code(false, false, false, false), EXIT_RUNTIME);
        // Whatever else changes: unverified is never 0, and never the same code as the
        // ordinary "nothing to stop" result (which the GUI must NOT alarm about).
        assert_ne!(EXIT_UNVERIFIED, EXIT_OK);
        assert_ne!(EXIT_UNVERIFIED, EXIT_RUNTIME);
        // A scan gap must never MASK a worse answer: whatever else is true, the
        // unverified/error codes win over it.
        assert_eq!(stop_exit_code(true, false, true, true), EXIT_UNVERIFIED);
        assert_eq!(stop_exit_code(true, true, false, true), EXIT_RUNTIME);
        assert_eq!(stop_exit_code(false, false, false, true), EXIT_RUNTIME);
    }

    /// The GUI decides whether to alarm the miner purely from this exit code, so the
    /// two crates' constants must not drift (the core crate can't depend on the CLI).
    #[test]
    fn unverified_exit_code_matches_the_value_the_gui_watches_for() {
        assert_eq!(
            EXIT_UNVERIFIED,
            alice_miner_core::terminal::EXIT_STOP_UNVERIFIED
        );
    }

    /// ROUND 2 (noise): a machine where the orphan SWEEP cannot run (PowerShell blocked
    /// by AppLocker / an execution policy, no `pgrep`) must not turn every ordinary,
    /// fully-confirmed stop into a WARNING. The scan gap costs us the "No orphan left"
    /// CLAIM (which is about the scan) — not the success.
    ///
    /// ROUND 3 refines the second half: the outcome is still a success, but it is no
    /// longer reported as plain `EXIT_OK`. It carries its own code so the GUI can say
    /// the one true, calm sentence about it, without ever entering the alarm channel.
    #[test]
    fn a_scan_gap_alone_downgrades_the_claim_not_the_outcome() {
        // No scan ⇒ we do not claim "No orphan left"…
        assert!(!claims_no_orphan(true));
        assert!(claims_no_orphan(false));
        // …and with everything we DID probe confirmed, the stop remains a SUCCESS —
        // simply one with a smaller claim, so it gets its own code and NOT the "may
        // still be running" one.
        assert_eq!(stop_exit_code(true, false, false, true), EXIT_SCAN_GAP);
        assert_ne!(EXIT_SCAN_GAP, EXIT_UNVERIFIED);
        // With no gap at all, nothing changed: a clean stop is still exactly 0.
        assert_eq!(stop_exit_code(true, false, false, false), EXIT_OK);
        // And if anything else was unconfirmed, the gap is listed with it and the
        // outcome is unverified (that path pushes the gap into `unverified`).
        assert_eq!(stop_exit_code(true, false, true, true), EXIT_UNVERIFIED);
    }

    /// ROUND 3 — the scan gap needed a channel of its own. The CLI exited plain 0 on a
    /// confirmed stop it could not sweep after, so the GUI (which alarms only on 3)
    /// showed the miner NOTHING: a check had been skipped and nobody said so. The fix
    /// is a dedicated code, because the alternative — matching the CLI's stderr — means
    /// matching BILINGUAL prose, which would silently do nothing on a Chinese locale.
    ///
    /// The contract pinned here: distinct from every other code, never confusable with
    /// "may still be running", and identical to the constant the GUI watches for.
    #[test]
    fn scan_gap_has_its_own_code_and_the_gui_watches_for_that_exact_value() {
        assert_eq!(
            EXIT_SCAN_GAP,
            alice_miner_core::terminal::EXIT_STOP_SCAN_GAP,
            "the two crates' constants must not drift (core cannot depend on the CLI)"
        );
        // Distinct from every other stop outcome, or the GUI cannot tell them apart.
        for other in [EXIT_OK, EXIT_RUNTIME, EXIT_USAGE, EXIT_UNVERIFIED] {
            assert_ne!(EXIT_SCAN_GAP, other);
        }
        // The two report predicates are mutually exclusive BY CONSTRUCTION.
        let gap = alice_miner_core::terminal::CliStopReport {
            code: Some(EXIT_SCAN_GAP),
            stderr: String::new(),
        };
        assert!(gap.scan_gap());
        assert!(
            !gap.unverified(),
            "a scan gap is a confirmed stop — it must never trip the alarm surface"
        );
    }

    /// ROUND 3 — the orphan sweep's THREE-way contract, against the REAL OS query tool
    /// on both unix (`pgrep`) and Windows (PowerShell/CIM):
    ///   * a needle that matches a LIVE process → `Some(pids)` containing it;
    ///   * a needle that matches nothing → `Some(vec![])` — "we looked and found none",
    ///     which is precisely what lets an ordinary stop say "No orphan left."
    ///
    /// The second half guards against OVER-correcting the unix fix: `pgrep` exits 1
    /// when it matches nothing, and folding that status into "could not scan" would
    /// make every clean stop on every unix report a scan gap — a cry-wolf note on the
    /// most common path. (`None`, a genuine gap, cannot be provoked here without
    /// breaking the tool, so it is pinned as a pure table in `core::proc::classify_pgrep`.)
    /// A machine that genuinely cannot scan is a SUPPORTED state, not a test failure
    /// (that is the entire point of `Option` here), so the assertions are made only
    /// where the premise holds. On unix that is always — `pgrep` is POSIX and present
    /// on both CI legs, which is exactly where the bug being fixed lived. On Windows
    /// the sweep needs PowerShell, which a hardened runner may refuse; there we assert
    /// when it ran and stay quiet when it did not, rather than fail CI over the
    /// environment.
    #[cfg(any(unix, windows))]
    #[test]
    fn orphan_sweep_reports_found_none_not_a_scan_gap() {
        let (mut child, prog) = long_lived_child();
        let pid = child.id();

        let found = orphaned_engine_pids(&prog);
        // A path NOTHING is running: if the scan ran, this must be an EMPTY list, never
        // `None`. `None` means "could not scan", and claiming it here would cost every
        // stop on this machine the "No orphan left" it has every right to say — the
        // over-correction this test exists to prevent (`pgrep` exits 1 on no match).
        let empty = orphaned_engine_pids(FOREIGN_ENGINE_PATH);

        let _ = child.kill();
        let _ = child.wait();

        #[cfg(unix)]
        let (found, empty) = (
            Some(found.expect("`pgrep` is POSIX — it is present here")),
            Some(empty.expect("exit 1 is 'no match' — an ANSWER, not a scan failure")),
        );

        if let Some(found) = found {
            assert!(
                found.contains(&pid),
                "a live process running the exact needle path must be found \
                 (needle {prog}, pid {pid})"
            );
        }
        if let Some(empty) = empty {
            assert!(
                empty.is_empty(),
                "nothing is running {FOREIGN_ENGINE_PATH}; got {empty:?}"
            );
        }
    }

    /// The layer-2 backstop's identity gate: `identify_child_pid` says `Ours` only when
    /// the LIVE recorded pid actually runs the engine path we recorded, `Unrelated` when
    /// the pid is alive but running SOMETHING ELSE (the OS reused a stale pid — the
    /// mis-kill this guard closes), and `Unknown` when we cannot read the command line
    /// at all. The `Unknown` case is the one that matters for honest reporting: it must
    /// NOT be indistinguishable from `Unrelated`, because on Windows 11 it was the
    /// normal outcome and produced a false "no orphan left". Runs on Windows too.
    #[cfg(any(unix, windows))]
    #[test]
    fn identify_child_pid_separates_ours_reused_and_unknown() {
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

        let (mut child, prog) = long_lived_child();
        let pid = child.id();

        // A live pid whose command line is NOT the recorded engine (models a reused
        // pid) → Unrelated: known not to be ours, so never signalled AND not a warning.
        assert_eq!(
            identify_child_pid(pid, Some(FOREIGN_ENGINE_PATH)),
            ChildIdentity::Unrelated,
            "a live pid running something OTHER than the recorded engine must never verify"
        );

        // The pid running exactly the recorded engine path → Ours.
        assert_eq!(
            identify_child_pid(pid, Some(&prog)),
            ChildIdentity::Ours,
            "a live pid running the recorded engine path must verify"
        );

        // No recorded engine path to compare against → Unknown (never "not ours").
        assert_eq!(identify_child_pid(pid, None), ChildIdentity::Unknown);

        let _ = child.kill();
        let _ = child.wait();

        // A pid that does not exist: its command line cannot be read → Unknown, NOT
        // Unrelated. (Liveness is checked by the caller before this is consulted.)
        assert_eq!(
            identify_child_pid(0x7FFF_FFFE, Some(&prog)),
            ChildIdentity::Unknown
        );

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

    /// The `--create` overwrite guard (`decide_overwrite`). The three required
    /// cases: (1) existing keystore + no `--force` + non-interactive → REFUSE
    /// (never silently clobber); (2) `--force` → overwrite as before; (3) no
    /// existing keystore → proceed as before. Plus the TTY y/N branches and the
    /// proof that non-create modes (import/paste) are never gated.
    #[test]
    fn decide_overwrite_guards_create_over_existing_keystore() {
        use OverwriteDecision::{Abort, Proceed};

        // (1) exists + no --force + NON-interactive → refuse with a usage code,
        //     so an automation script cannot silently swap a wallet.
        assert_eq!(
            decide_overwrite(true, false, true, false, None),
            Abort(EXIT_USAGE)
        );

        // (2) --force ALWAYS proceeds (interactive or not, existing or not) —
        //     the non-interactive automation escape hatch, behaviour unchanged.
        assert_eq!(decide_overwrite(true, true, true, false, None), Proceed);
        assert_eq!(decide_overwrite(true, true, true, true, None), Proceed);

        // (3) no existing keystore → proceed exactly as before (nothing to back up).
        assert_eq!(decide_overwrite(true, false, false, true, None), Proceed);
        assert_eq!(decide_overwrite(true, false, false, false, None), Proceed);

        // Interactive prompt branches (exists, no --force, TTY):
        assert_eq!(
            decide_overwrite(true, false, true, true, Some("y\n")),
            Proceed
        );
        assert_eq!(
            decide_overwrite(true, false, true, true, Some("  YES ")),
            Proceed
        );
        // Anything that is not y/yes (incl. empty ⇒ the safe default) → abort,
        // and a decline is EXIT_OK (the user chose safety, not an error).
        assert_eq!(
            decide_overwrite(true, false, true, true, Some("n\n")),
            Abort(EXIT_OK)
        );
        assert_eq!(
            decide_overwrite(true, false, true, true, Some("\n")),
            Abort(EXIT_OK)
        );
        assert_eq!(decide_overwrite(true, false, true, true, None), Abort(EXIT_OK));

        // Non-create modes are NEVER gated even over an existing keystore, so
        // import/paste behaviour is untouched by this change.
        assert_eq!(
            decide_overwrite(false, false, true, false, None),
            Proceed,
            "import/paste must not be gated by the create guard"
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
            message_key: None,
            message_args: None,
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

    // ── AM-REL-007: the single-instance surface ───────────────────────────────

    /// `--allow-multiple` is a real, parseable flag on `start` and defaults OFF.
    #[test]
    fn allow_multiple_flag_parses_and_defaults_off() {
        let cli = Cli::try_parse_from(["alice-miner", "start", "--lane", "xmr"]).unwrap();
        match cli.command {
            Some(Command::Start(a)) => assert!(!a.allow_multiple, "must default to refusing"),
            _ => panic!("expected start"),
        }
        let cli = Cli::try_parse_from(["alice-miner", "start", "--allow-multiple"]).unwrap();
        match cli.command {
            Some(Command::Start(a)) => assert!(a.allow_multiple),
            _ => panic!("expected start"),
        }
    }

    /// The refusal exit code is its OWN value, distinct from every other, so a
    /// supervisor script can tell "already running" from a real failure (restarting
    /// on this code would be exactly wrong).
    #[test]
    fn already_running_exit_code_is_distinct() {
        let codes = [
            EXIT_OK,
            EXIT_RUNTIME,
            EXIT_USAGE,
            EXIT_UNVERIFIED,
            EXIT_SCAN_GAP,
            EXIT_ALREADY_RUNNING,
        ];
        let mut sorted = codes.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len(), "exit codes must be distinct");
        assert_eq!(EXIT_ALREADY_RUNNING, 5);
    }

    /// Each reason for running WITHOUT the rendezvous gets its own wording and its
    /// own advice. A single vague "another instance may be running" for all three
    /// would be the guess the honesty rule forbids — "we could not check" and "you
    /// told us to" are different facts and need different fixes.
    #[test]
    fn sharing_warnings_say_which_case_it_is() {
        i18n::set_lang(Lang::En);

        let override_msg = describe_sharing(&pidfile::SharingReason::UserOverride {
            pid: 4242,
            data_dir: Some(std::path::PathBuf::from("/Users/x/.alice")),
        });
        assert!(override_msg.contains("--allow-multiple"));
        assert!(override_msg.contains("4242"));
        assert!(override_msg.contains("/Users/x/.alice"), "names the shared data dir");
        assert!(
            override_msg.contains("did NOT take the rendezvous"),
            "must say `stop` will not reach THIS process: {override_msg}"
        );

        let unknown_msg = describe_sharing(&pidfile::SharingReason::Unverifiable { pid: 909 });
        assert!(
            unknown_msg.contains("could NOT tell us") && unknown_msg.contains("do not know"),
            "an unverifiable probe must admit it is unverifiable: {unknown_msg}"
        );
        assert!(
            !unknown_msg.contains("--allow-multiple"),
            "this case is not a user override; do not offer an irrelevant flag"
        );

        let unavailable = describe_sharing(&pidfile::SharingReason::RendezvousUnavailable);
        assert!(unavailable.contains("pid file could not be written"));
        assert!(unavailable.contains("Ctrl-C"), "gives the working way to stop");

        // The three are genuinely different texts.
        assert_ne!(override_msg, unknown_msg);
        assert_ne!(unknown_msg, unavailable);
    }
}
