//! `update` — the signed self-updater for the headless CLI, plus a NON-BLOCKING
//! startup version-check banner.
//!
//! The cryptographic kernel lives in `alice-release` (ed25519-signed manifest →
//! SHA-256-verified artifact → atomic swap with last-known-good rollback, and a
//! data-dir guard that can NEVER write into the keystore home). This module is the
//! thin CLI front-end over it — the exact same pipeline the GUI's `update.rs` uses:
//!
//!   * `alice-miner update --check`  → check + report (current vs latest, notes) only.
//!   * `alice-miner update`          → check → if newer, show + (with `--yes` or an
//!     interactive confirm) apply the signed update; if up-to-date, say so.
//!   * `alice-miner update --yes`    → check → apply without prompting (still verified).
//!
//! **NEVER auto-applies without consent** (mirrors the Wallet/GUI: "never silent-apply").
//!
//! Separately, [`startup_banner`] runs a bounded, cached, opt-out-able background
//! check that `start` / `ai` / the menu call ONCE, printing a single one-line banner
//! when a newer version exists. It NEVER blocks or delays mining: it spawns a thread
//! with a short join deadline, uses a ~6h on-disk cache under `~/.alice`, and is
//! disabled entirely by `ALICE_MINER_NO_UPDATE_CHECK=1`. Localized via [`tr!`].

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use alice_miner_core::alice_release as release;
use alice_miner_core::tr;
use release::{Artifact, CheckOutcome, Manifest};

use crate::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE};

/// `alice-miner update` arguments.
#[derive(clap::Args)]
pub struct UpdateArgs {
    /// Only CHECK + report (current vs latest version + release notes); never apply.
    #[arg(long)]
    pub check: bool,
    /// Apply a newer version without the interactive confirmation (still verified —
    /// ed25519 signature + SHA-256 — before anything is written).
    #[arg(long)]
    pub yes: bool,
    /// Set how much this machine may update WITHOUT being asked:
    /// `off` (never), `notify` (tell me, install nothing),
    /// `security-only` (auto-install security releases only — the default),
    /// or `full` (auto-install any release that clears the guardrails).
    /// With no value, prints the current setting and what it means.
    #[arg(long, value_name = "MODE", num_args = 0..=1, default_missing_value = "")]
    pub auto: Option<String>,
}

/// Run the `update` command.
pub fn run(args: UpdateArgs) -> i32 {
    // `--auto` is a settings command, not an update: handle it and return.
    if let Some(v) = args.auto.as_deref() {
        return run_auto_setting(v);
    }
    let current = release::current_version();
    println!(
        "{} v{current} · {}",
        tr!("Alice Miner", "Alice 矿工"),
        tr!("checking for updates…", "正在检查更新…")
    );

    // Fetch the manifest WHOLE rather than via `check_for_update`, which collapses
    // it into a `CheckOutcome` and throws the manifest away on the up-to-date path.
    // That path is exactly where `revoked` matters: it is the run where the newest
    // published version IS the one we are on, and telling someone "you are on the
    // latest version" about a build the publisher has withdrawn would be the most
    // reassuring possible way to be wrong.
    let manifest = match release::fetch_verified_manifest() {
        Ok(m) => m,
        Err(e) => {
            eprintln!(
                "error: {} ({e})",
                tr!("could not check for updates", "无法检查更新")
            );
            return EXIT_RUNTIME;
        }
    };
    if manifest.is_revoked(current) {
        eprintln!(
            "{}",
            tr!(
                format!("⚠ v{current} has been WITHDRAWN by the publisher — do not keep running it."),
                format!("⚠ v{current} 已被发布方撤回 —— 请不要继续运行它。")
            )
        );
    }
    act(release::evaluate(manifest, current), args.check, args.yes)
}

/// What to DO about a check result.
///
/// Split out of [`run`] so the `--check` contract can be tested at all: `run`
/// cannot be called without a network, and the arm that ignored `--check` was
/// therefore the one arm with no test on it.
fn act(outcome: CheckOutcome, check: bool, yes: bool) -> i32 {
    match outcome {
        CheckOutcome::UpToDate { current } => {
            println!(
                "{} (v{current}).",
                tr!("You are on the latest version", "你已是最新版本")
            );
            EXIT_OK
        }
        CheckOutcome::UpdateAvailableNoArtifact { current, manifest } => {
            println!(
                "{}: v{current} → v{}",
                tr!("A newer version exists", "有更新版本"),
                manifest.version
            );
            print_notes(&manifest);
            println!(
                "  {} {}",
                tr!(
                    "No auto-update package for this platform — download it from:",
                    "本平台无自动更新包 — 请从此处下载:"
                ),
                release::update_url()
            );
            EXIT_OK
        }
        CheckOutcome::Unsupported { current, min_supported, manifest } => {
            println!(
                "{}: v{current} < v{min_supported} ({} v{})",
                tr!("This version is no longer supported", "此版本已不再受支持"),
                tr!("latest", "最新"),
                manifest.version
            );
            print_notes(&manifest);
            // A hard-upgrade notice: offer the same apply flow.
            //
            // Two things this arm used to get wrong, both of them because
            // `evaluate` tests `min_supported` BEFORE `is_newer`, so this state
            // does NOT imply the manifest is offering something newer.
            //
            //   * `--check` was never consulted, so the flag documented as
            //     "only CHECK and report, never apply" downloaded and installed;
            //   * neither was `is_newer`, so a manifest pairing an unreachable
            //     `min_supported` with an OLD `version` landed here and was
            //     applied as a "required upgrade" that is in fact a downgrade —
            //     on a loop, since the downgraded build is still unsupported.
            //
            // The no-downgrade half is enforced in the shared gate (both
            // front-ends), not here; this is the `--check` half.
            if check {
                return report_only();
            }
            apply_flow(&manifest, manifest.artifact_for_current_platform(), yes, current.as_str())
        }
        CheckOutcome::UpdateAvailable { current, manifest, artifact } => {
            println!(
                "{}: v{current} → v{}",
                tr!("A new version is available", "有新版本可用"),
                manifest.version
            );
            print_notes(&manifest);
            if check {
                return report_only();
            }
            apply_flow(&manifest, Some(&artifact), yes, current.as_str())
        }
    }
}

/// `--check`: say how to apply it, and apply nothing. The ONE place that decides
/// what `--check` does, so a new outcome arm cannot quietly forget to honour it.
fn report_only() -> i32 {
    println!(
        "  {}  alice-miner update",
        tr!("apply it with:", "应用更新:")
    );
    EXIT_OK
}

/// The confirm → download → verify → apply → arm-health-gate flow for a newer
/// manifest. With `yes`, applies without prompting; otherwise asks for an explicit
/// interactive confirm (and if stdin is NOT a TTY, refuses to apply — never silent).
fn apply_flow(manifest: &Manifest, artifact: Option<&Artifact>, yes: bool, current: &str) -> i32 {
    // The SHARED guardrails — the same ones the automatic path applies, run from
    // the same driver in `alice_miner_core::autoupdate` so there is exactly one
    // copy of them (AM-REL-009). This also records the sighting, so a version
    // installed by hand still starts this machine's soak clock and still pins the
    // bytes we saw it carrying.
    //
    // Note what `--yes` does and does not reach. It means "stop asking me", and
    // it settles the ordinary confirmation below. It does not settle a refusal,
    // and it does not settle the second, explicit question a concern raises: a
    // flag typed before we knew anything cannot be consent to something we only
    // learned afterwards.
    let check = alice_miner_core::autoupdate::manual_check(manifest, artifact, current);
    if let Some(line) = &check.visibility {
        println!("  {line}");
    }
    match &check.outcome {
        alice_miner_core::autoupdate::ManualOutcome::Refuse { message } => {
            eprintln!("error: {message}");
            return EXIT_RUNTIME;
        }
        alice_miner_core::autoupdate::ManualOutcome::Confirm { message } => {
            println!("  {} {message}", tr!("note:", "提示:"));
            if !confirm_apply_pinned(&manifest.version) {
                println!("{}", tr!("Update cancelled.", "已取消更新。"));
                return EXIT_OK;
            }
        }
        alice_miner_core::autoupdate::ManualOutcome::Proceed => {}
    }

    let Some(artifact) = artifact else {
        println!(
            "  {} {}",
            tr!(
                "No auto-update package for this platform — download it from:",
                "本平台无自动更新包 — 请从此处下载:"
            ),
            release::update_url()
        );
        return EXIT_OK;
    };

    if !yes && !confirm_apply(&manifest.version) {
        println!("{}", tr!("Update cancelled.", "已取消更新。"));
        return EXIT_OK;
    }

    println!(
        "{} v{}…",
        tr!("Downloading + verifying update", "正在下载并校验更新"),
        manifest.version
    );
    match apply_pipeline(manifest, artifact) {
        Ok(version) => {
            println!(
                "{} v{version}. {}",
                tr!("Updated to", "已更新到"),
                tr!("Restart alice-miner to run it.", "请重启 alice-miner 以运行新版本。")
            );
            EXIT_OK
        }
        Err(e) => {
            eprintln!("error: {} ({e})", tr!("update failed", "更新失败"));
            EXIT_RUNTIME
        }
    }
}

/// Ask for an explicit interactive confirmation before applying. Returns `false`
/// (do NOT apply) when stdin is not a TTY — the CLI never silent-applies, and a
/// non-interactive run without `--yes` must not be surprised by a swap.
fn confirm_apply(version: &str) -> bool {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        println!(
            "  {}",
            tr!(
                "not a terminal — re-run with --yes to apply the signed update.",
                "非终端 — 请加 --yes 重新运行以应用已签名的更新。"
            )
        );
        return false;
    }
    print!(
        "{} v{version}? [y/N] ",
        tr!("Apply the signed update now", "现在应用已签名的更新")
    );
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// The download → verify → swap → arm-health-gate pipeline (identical discipline to
/// the GUI's `apply_pipeline`): the SHA-256 + size are verified inside
/// `download_and_verify` BEFORE any byte is written, `apply_update` re-verifies from
/// disk, and the swap can never touch the keystore (`assert_not_in_data_dir`).
fn apply_pipeline(manifest: &Manifest, artifact: &Artifact) -> Result<String, String> {
    let bytes = release::download_and_verify(artifact).map_err(|e| e.to_string())?;
    let applied = release::apply_update(artifact, &bytes).map_err(|e| e.to_string())?;
    release::arm_pending_health_check(&applied.app_path, &manifest.version)
        .map_err(|e| e.to_string())?;
    Ok(manifest.version.clone())
}

/// A second, explicit confirmation for re-installing a version this machine
/// already rolled back. Never auto-answers "yes": off a TTY it refuses.
fn confirm_apply_pinned(version: &str) -> bool {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        println!(
            "  {}",
            tr!(
                "not a terminal — re-installing a version this machine rolled back needs an interactive confirmation.",
                "非终端 —— 重新安装本机曾回滚过的版本需要交互式确认。"
            )
        );
        return false;
    }
    print!(
        "{} v{version}? [y/N] ",
        tr!(
            "Install it anyway",
            "仍然安装"
        )
    );
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

// ─────────────────────────────────────────────────────────────────────────────
// `alice-miner update --auto <mode>` — the opt-out / opt-in switch
// ─────────────────────────────────────────────────────────────────────────────

/// Show or set the automatic-update mode. An empty value shows; a value sets.
fn run_auto_setting(value: &str) -> i32 {
    use alice_miner_core::alice_release::auto::Mode;
    use alice_miner_core::autoupdate;

    if value.trim().is_empty() {
        let m = autoupdate::mode();
        println!(
            "{}: {}",
            tr!("Automatic updates", "自动更新"),
            m.as_str()
        );
        println!("  {}", explain_mode(m));
        if !autoupdate::mode_is_explicit() {
            println!(
                "  {}",
                tr!(
                    "(this machine has not chosen — it is on the built-in default)",
                    "(本机尚未做过选择 —— 当前为内置默认值)"
                )
            );
        }
        println!(
            "  {}  alice-miner update --auto <off|notify|security-only|full>",
            tr!("change it with:", "修改:")
        );
        return EXIT_OK;
    }

    let Some(m) = Mode::parse(value) else {
        eprintln!(
            "error: {}",
            tr!(
                format!("unknown auto-update mode '{value}' — expected off, notify, security-only, or full. Nothing was changed."),
                format!("未知的自动更新模式 '{value}' —— 可选值为 off、notify、security-only、full。未做任何修改。")
            )
        );
        return EXIT_USAGE;
    };
    match autoupdate::set_mode(m) {
        Ok(stored) => {
            println!(
                "{}: {stored}",
                tr!("Automatic updates", "自动更新")
            );
            println!("  {}", explain_mode(m));
            EXIT_OK
        }
        Err(e) => {
            eprintln!("error: {e}");
            EXIT_RUNTIME
        }
    }
}

/// One sentence per mode — including, for the installing modes, the fact that
/// this is a trust decision and not just a convenience one.
fn explain_mode(m: alice_miner_core::alice_release::auto::Mode) -> String {
    use alice_miner_core::alice_release::auto::Mode;
    match m {
        Mode::Off => tr!(
            "Never check, never notify, never install. You are on your own for updates.",
            "从不检查、不提示、不安装。更新完全由你自己负责。"
        )
        .to_string(),
        Mode::Notify => tr!(
            "Check and tell you; install nothing. Nothing reaches this machine without you typing a command.",
            "只检查并提示,不安装任何东西。没有你亲自输入命令,任何东西都不会装到本机。"
        )
        .to_string(),
        Mode::SecurityOnly => tr!(
            "Auto-install security releases only; notify for everything else. Held for a day first, rolled out in batches, and rolled back automatically if the new build fails to start or stops earning.",
            "仅自动安装安全更新,其它版本只提示。新版本会先观察一天、分批放量,若新版本无法启动或不再有收益会自动回滚。"
        )
        .to_string(),
        Mode::Full => tr!(
            "Auto-install any release that clears the guardrails (day-long hold, batched rollout, automatic rollback). This is the most convenient setting and the one that trusts the release key the most.",
            "自动安装任何通过护栏的版本(一天观察期、分批放量、自动回滚)。这是最省事、也是最依赖发布密钥安全性的设置。"
        )
        .to_string(),
    }
}

/// Print the release notes block (indented), if the manifest carries any.
fn print_notes(manifest: &Manifest) {
    let notes = manifest.notes.trim();
    if !notes.is_empty() {
        println!("  {}:", tr!("Release notes", "更新说明"));
        for line in notes.lines() {
            println!("    {line}");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// First-launch health gate (AM-REL-009)
//
// `apply_pipeline` above arms `arm_pending_health_check` after every CLI
// self-update — the marker that says "a freshly-installed build is on probation".
// Resolving that marker (bump the attempt, roll back a build that never confirms,
// commit one that does) is `register_launch` + `confirm_health_and_commit`, and
// until now ONLY the GUI called them.
//
// So on a headless box the designed safety net did not exist: `alice-miner update`
// installed a new binary, armed the marker, and nothing ever cleared it. A build
// that crashed on launch was never rolled back — the whole point of last-known-good
// — and the marker plus the `.lkg` copy stayed on disk indefinitely.
//
// The CLI now drives the same gate:
//   * [`register_launch_at_startup`] runs as early as possible in `main`, BEFORE
//     argument parsing, so a build that dies during startup is on record;
//   * [`confirm_launch_health`] runs the moment the process has demonstrably come
//     up — clap has parsed (or produced a usage error, which equally proves the
//     binary loads and runs).
//
// Deliberately NOT gated on "the miner mined successfully": that would roll a good
// build back over an unrelated network outage. The claim being verified is only
// "this binary starts", which is exactly the failure last-known-good exists for.
// ─────────────────────────────────────────────────────────────────────────────

/// What the health gate found at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchHealth {
    /// No update probation in effect (or the gate could not be resolved — a missing
    /// app path is not an error worth blocking a miner over).
    Normal,
    /// This is the first run of a freshly-installed build; it must confirm.
    Fresh { version: String },
    /// A previously-installed build reached startup twice without ever confirming
    /// health, and has been rolled back to last-known-good.
    RolledBack { failed_version: String },
}

/// Resolve the first-launch health gate. Call ONCE, as early in `main` as possible.
/// Never panics; never blocks; a failure to resolve is [`LaunchHealth::Normal`].
pub fn register_launch_at_startup() -> LaunchHealth {
    let Ok(app_path) = release::current_app_path() else {
        return LaunchHealth::Normal;
    };
    match release::register_launch(&app_path, release::current_version()) {
        Ok(release::LaunchDecision::FreshFirstRun { version }) => LaunchHealth::Fresh { version },
        Ok(release::LaunchDecision::RolledBack { failed_version }) => {
            LaunchHealth::RolledBack { failed_version }
        }
        _ => LaunchHealth::Normal,
    }
}

/// Commit (or report) the health gate once the process has proven it starts.
/// Prints a single line to STDERR so `--json` stdout stays machine-clean.
pub fn confirm_launch_health(health: &LaunchHealth) {
    match health {
        LaunchHealth::Normal => {}
        LaunchHealth::Fresh { version } => {
            let Ok(app_path) = release::current_app_path() else {
                return;
            };
            // Clears the marker and drops last-known-good.
            if matches!(release::confirm_health_and_commit(&app_path), Ok(true)) {
                eprintln!(
                    "{}",
                    tr!(
                        format!("Updated to v{version}."),
                        format!("已更新到 v{version}。")
                    )
                );
            }
        }
        LaunchHealth::RolledBack { failed_version } => {
            // Be precise about what just happened: the rollback replaced the binary
            // ON DISK, but THIS process is still the failed build. Telling the user
            // "rolled back" without that would be a half-truth they act on wrongly.
            eprintln!(
                "{}",
                tr!(
                    format!(
                        "warning: v{failed_version} was installed but never started \
                         successfully, so it has been rolled back to the previous version.\n\
                         This process is still running the failed build — restart alice-miner \
                         to use the restored one."
                    ),
                    format!(
                        "警告:v{failed_version} 安装后从未成功启动,已回滚到上一个版本。\n\
                         本进程仍在运行那个失败的版本 —— 请重启 alice-miner 以使用已恢复的版本。"
                    )
                )
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The in-session automatic updater
//
// Everything here is subordinate to one rule: MINING COMES FIRST. The check runs
// on a background thread, an install never touches the running engine (the new
// build takes effect on the next start, and we say so), and every failure path
// is silent rather than fatal. A miner must never lose a share because the
// updater had an opinion.
//
// It also owns the mining half of the health probation, because this is the only
// place that can see both halves of the question "is the new build earning":
// the elapsed session time and the accepted-share counter.
// ─────────────────────────────────────────────────────────────────────────────

use std::sync::mpsc::{Receiver, Sender};
use std::time::Instant;

/// How often a long-running session re-checks. Matches `alice-release`'s own
/// `CHECK_INTERVAL`; a rig that runs for weeks still sees a security release
/// within a day of it clearing the soak window.
const AUTO_RECHECK: Duration = Duration::from_secs(6 * 60 * 60);

/// How often an accepted-share run refreshes the "this machine was earning"
/// mark. Cheap, but not once per share.
const PRODUCTIVE_MARK_EVERY: Duration = Duration::from_secs(10 * 60);

/// Drives automatic updates for the lifetime of one `start` session.
pub struct AutoUpdater {
    tx: Sender<String>,
    rx: Receiver<String>,
    /// A check is in flight (never two at once).
    in_flight: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// A session report is in flight on a worker thread (never two — two
    /// concurrent reports could double-count a strike against the probation).
    session_in_flight: std::sync::Arc<std::sync::atomic::AtomicBool>,
    last_check: Instant,
    session_start: Instant,
    last_productive_mark: Option<Instant>,
    /// Whether we have already recorded a long, zero-accepted stretch against
    /// the probation for THIS session (once per session, not once per tick).
    judged_this_session: bool,
    /// Suppress all output (the `--json` / service paths).
    quiet: bool,
}

impl AutoUpdater {
    /// Start the session's updater and kick the first check immediately.
    /// `quiet` (machine output / background service) suppresses every line but
    /// keeps the machinery — a headless rig is exactly the one that most needs
    /// an automatic security update and an automatic rollback.
    pub fn start(quiet: bool) -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut me = Self {
            tx,
            rx,
            in_flight: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            session_in_flight: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            last_check: Instant::now(),
            session_start: Instant::now(),
            last_productive_mark: None,
            judged_this_session: false,
            quiet,
        };
        me.kick(false);
        me
    }

    /// Hand one session report to the probation, on the right thread.
    ///
    /// A report that could decide a ROLLBACK first asks the network whether the
    /// whole lane is down (F4) — a bounded but blocking GET, which must never run
    /// on this loop: it drives the terminal UI and the engine event pump. That
    /// case (at most once per session) goes to a worker thread and its verdict
    /// comes back through the same channel the update lines use. Every other
    /// report — the per-tick ones — is local-only and stays inline.
    fn report_session(
        &mut self,
        ran: Duration,
        mining: alice_miner_core::autoupdate::MiningEvidence,
    ) -> Option<String> {
        use std::sync::atomic::Ordering;
        if !alice_miner_core::autoupdate::session_may_consult_the_network(ran, &mining) {
            return alice_miner_core::autoupdate::note_session(ran, &mining);
        }
        if self.session_in_flight.swap(true, Ordering::SeqCst) {
            return None;
        }
        let tx = self.tx.clone();
        let flag = self.session_in_flight.clone();
        std::thread::spawn(move || {
            if let Some(msg) = alice_miner_core::autoupdate::note_session(ran, &mining) {
                let _ = tx.send(msg);
            }
            flag.store(false, Ordering::SeqCst);
        });
        None
    }

    /// Spawn one background check cycle, unless one is already running.
    fn kick(&mut self, quiet_holds: bool) {
        use std::sync::atomic::Ordering;
        if std::env::var_os(ENV_NO_UPDATE_CHECK).is_some() {
            return;
        }
        if self.in_flight.swap(true, Ordering::SeqCst) {
            return;
        }
        self.last_check = Instant::now();
        let tx = self.tx.clone();
        let flag = self.in_flight.clone();
        std::thread::spawn(move || {
            let outcome = alice_miner_core::autoupdate::tick(quiet_holds);
            if let Some(msg) = outcome.message() {
                let _ = tx.send(msg.to_string());
            }
            flag.store(false, Ordering::SeqCst);
        });
    }

    /// Call once per engine snapshot. Handles the periodic re-check, the
    /// "this machine is earning" mark, and the mining half of the health
    /// probation. Returns any line the caller should print.
    ///
    /// Takes the whole snapshot rather than a bare share count, because the share
    /// count alone is a lie the moment the acceptance guard halts a lane: it
    /// freezes, and reading a frozen counter as "this build stopped earning" is
    /// layer 2 rolling a client back over layer 3 doing its job (F4). The
    /// derivation lives in `MiningEvidence` so the GUI reads it identically.
    pub fn tick(&mut self, snap: Option<&alice_miner_core::engine::Snapshot>) -> Option<String> {
        let mining = snap
            .map(alice_miner_core::autoupdate::MiningEvidence::from_snapshot)
            .unwrap_or_default();

        // 1. An accepted share on a lane that is actually allowed to run is two
        //    things at once: proof that THIS build works (which commits a
        //    probation), and the baseline a FUTURE update will be judged against.
        if mining.counts_as_earning() {
            let due = self
                .last_productive_mark
                .map(|t| t.elapsed() >= PRODUCTIVE_MARK_EVERY)
                .unwrap_or(true);
            if due {
                self.last_productive_mark = Some(Instant::now());
                alice_miner_core::autoupdate::mark_productive();
            }
        }

        // 2. Feed the probation. An accepted share commits immediately; a long
        //    stretch with none counts against the build ONCE per session, and only
        //    when the build we replaced had been earning here AND the acceptance
        //    guard has not disqualified the session (both of those checks live in
        //    the kernel, which is where the outage-versus-client distinction is
        //    made).
        let accepted = mining.accepted;
        let ran = self.session_start.elapsed();
        let judge = accepted > 0
            || (!self.judged_this_session
                && ran >= alice_miner_core::alice_release::auto::MIN_JUDGED_SESSION);
        if judge {
            if accepted == 0 {
                self.judged_this_session = true;
            }
            if let Some(msg) = self.report_session(ran, mining) {
                return Some(msg);
            }
        }

        // 3. Periodic re-check for a long-lived session.
        if self.last_check.elapsed() >= AUTO_RECHECK {
            self.kick(true);
        }

        // 4. Drain anything the background thread produced.
        while let Ok(msg) = self.rx.try_recv() {
            if !self.quiet {
                return Some(msg);
            }
        }
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Non-blocking startup version-check banner
// ─────────────────────────────────────────────────────────────────────────────

/// The env var that disables the startup version check entirely (opt-out).
pub const ENV_NO_UPDATE_CHECK: &str = "ALICE_MINER_NO_UPDATE_CHECK";

/// Don't re-check more often than this (the on-disk cache TTL) — ~6h.
const CHECK_CACHE_TTL: Duration = Duration::from_secs(6 * 60 * 60);

/// How long we're willing to WAIT for the background check at startup before giving
/// up and letting mining proceed. Tiny — mining must NEVER be delayed by this.
const STARTUP_CHECK_BUDGET: Duration = Duration::from_millis(600);

/// Print a ONE-LINE "a new version is available" banner at startup, if a newer
/// version exists — WITHOUT ever blocking or delaying mining. Called once by `start`
/// / `ai` / the menu.
///
/// Discipline:
///   * `ALICE_MINER_NO_UPDATE_CHECK=1` (or `--json` callers, who pass `quiet=true`) →
///     no-op.
///   * A fresh (< ~6h) cached result is used WITHOUT any network call.
///   * Otherwise a check runs on a background thread with a tiny join budget
///     ([`STARTUP_CHECK_BUDGET`]); if it doesn't finish in time we simply don't print
///     (the result is still cached by the thread for next time). Mining is never held.
///
/// `quiet` suppresses the banner entirely (the `--json` / machine paths pass `true`).
pub fn startup_banner(quiet: bool) {
    if quiet || std::env::var_os(ENV_NO_UPDATE_CHECK).is_some() {
        return;
    }
    let current = release::current_version();

    // 1) A fresh cached "latest" wins with zero network.
    if let Some(latest) = read_cache_if_fresh() {
        maybe_print(&latest, current);
        return;
    }

    // 2) Kick a bounded background check. We do NOT join indefinitely: mining proceeds
    // regardless. The thread writes the cache on completion so the NEXT run is instant.
    let (tx, rx) = std::sync::mpsc::channel::<Option<String>>();
    std::thread::spawn(move || {
        let latest = match release::check_for_update(release::current_version()) {
            Ok(CheckOutcome::UpdateAvailable { manifest, .. })
            | Ok(CheckOutcome::UpdateAvailableNoArtifact { manifest, .. })
            | Ok(CheckOutcome::Unsupported { manifest, .. }) => Some(manifest.version),
            Ok(CheckOutcome::UpToDate { current }) => Some(current),
            Err(_) => None,
        };
        if let Some(v) = &latest {
            let _ = write_cache(v);
        }
        let _ = tx.send(latest);
    });

    // Wait only the tiny budget; if it's not ready, move on silently (never block mining).
    if let Ok(Some(latest)) = rx.recv_timeout(STARTUP_CHECK_BUDGET) {
        maybe_print(&latest, current);
    }
}

/// Print the one-line banner iff `latest` is strictly newer than `current`.
fn maybe_print(latest: &str, current: &str) {
    if release::is_newer(latest, current) {
        // A single, quiet, non-blocking line. Goes to STDERR so it never pollutes a
        // captured stdout (the dashboard / any redirected output stays clean).
        eprintln!(
            "{}",
            tr!(
                "A new version v{V} is available · run `alice-miner update`",
                "有新版 v{V} · 运行 `alice-miner update`"
            )
            .replace("{V}", latest)
        );
    }
}

/// The cache file path: `<identity_dir>/update-check.json` (honors `$ALICE_IDENTITY_DIR`
/// like the rest of `~/.alice`). Holds only a public version string + a timestamp.
fn cache_path() -> PathBuf {
    identity_dir().join("update-check.json")
}

/// Resolve `~/.alice` (honoring `$ALICE_IDENTITY_DIR`) via the core settings module,
/// so the cache lives beside `settings.json` / the identity pointer and this crate
/// needs no `dirs` dependency of its own.
fn identity_dir() -> PathBuf {
    alice_miner_core::settings::settings_path()
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".alice"))
}

/// Read the cached "latest version" if the cache is younger than [`CHECK_CACHE_TTL`].
/// Returns `None` on any absence / parse error / staleness (fail-open → a fresh check).
fn read_cache_if_fresh() -> Option<String> {
    let body = std::fs::read_to_string(cache_path()).ok()?;
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    let checked_at = v.get("checked_at_unix")?.as_u64()?;
    let latest = v.get("latest")?.as_str()?.to_string();
    let now = now_unix();
    if now.saturating_sub(checked_at) <= CHECK_CACHE_TTL.as_secs() {
        Some(latest)
    } else {
        None
    }
}

/// Persist the latest-version + a timestamp (public, atomic temp+rename). Best-effort:
/// a write failure just means we check again next time (never fatal).
fn write_cache(latest: &str) -> Result<(), String> {
    let path = cache_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let obj = serde_json::json!({ "latest": latest, "checked_at_unix": now_unix() });
    let encoded = serde_json::to_vec(&obj).map_err(|e| e.to_string())?;
    let tmp = path.with_file_name(format!(".update-check.json.tmp-{}", std::process::id()));
    std::fs::write(&tmp, &encoded).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        e.to_string()
    })
}

/// Seconds since the Unix epoch (0 on the impossible pre-epoch clock).
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alice_miner_core::i18n::{set_lang, Lang};

    /// A temp `$ALICE_IDENTITY_DIR` so the cache read/write is isolated. Serialized via
    /// the crate-wide env lock (the cache honors `$ALICE_IDENTITY_DIR`).
    fn with_temp_dir<F: FnOnce()>(f: F) {
        let _g = crate::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "alice-update-{}-{}",
            std::process::id(),
            now_unix()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("ALICE_IDENTITY_DIR", &dir);
        f();
        std::env::remove_var("ALICE_IDENTITY_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A freshly-written cache round-trips (read back within the TTL).
    #[test]
    fn cache_round_trips_within_ttl() {
        with_temp_dir(|| {
            write_cache("9.9.9").expect("write");
            assert_eq!(read_cache_if_fresh().as_deref(), Some("9.9.9"));
        });
    }

    /// A stale cache (older than the TTL) reads as `None` → a fresh check is forced.
    #[test]
    fn stale_cache_is_ignored() {
        with_temp_dir(|| {
            let stale = now_unix().saturating_sub(CHECK_CACHE_TTL.as_secs() + 60);
            let obj = serde_json::json!({ "latest": "9.9.9", "checked_at_unix": stale });
            std::fs::write(cache_path(), serde_json::to_vec(&obj).unwrap()).unwrap();
            assert_eq!(read_cache_if_fresh(), None, "stale cache must be ignored");
        });
    }

    /// A missing / corrupt cache reads as `None` (fail-open), never a panic.
    #[test]
    fn absent_or_corrupt_cache_is_none() {
        with_temp_dir(|| {
            assert_eq!(read_cache_if_fresh(), None, "absent");
            std::fs::write(cache_path(), b"{ not json").unwrap();
            assert_eq!(read_cache_if_fresh(), None, "corrupt");
        });
    }

    /// `maybe_print` prints ONLY when latest is strictly newer (no version-shaming a
    /// current/older build). We can't capture stderr here, but we assert `is_newer`
    /// gates it exactly (the load-bearing decision).
    #[test]
    fn banner_gate_is_strictly_newer() {
        set_lang(Lang::En);
        assert!(release::is_newer("9.9.9", "0.1.0"));
        assert!(!release::is_newer("0.1.0", "0.1.0"), "equal is not newer");
        assert!(!release::is_newer("0.1.0", "9.9.9"), "older is not newer");
    }

    /// The opt-out env makes `startup_banner` a no-op with no network / no cache write.
    #[test]
    fn opt_out_env_disables_check() {
        with_temp_dir(|| {
            std::env::set_var(ENV_NO_UPDATE_CHECK, "1");
            startup_banner(false);
            std::env::remove_var(ENV_NO_UPDATE_CHECK);
            // No cache file should have been written (we never checked).
            assert!(!cache_path().exists(), "opt-out must not write a cache");
        });
    }

    /// A manifest for a version newer than this build, with a package for this
    /// platform. `sha` is what the server is offering for it.
    fn newer_manifest(sha: &str) -> Manifest {
        Manifest {
            schema: 1,
            product: release::PRODUCT.to_string(),
            version: "9.9.9".to_string(),
            min_supported: "0.1.0".to_string(),
            released: "2026-08-14T00:00:00Z".to_string(),
            notes: String::new(),
            artifacts: vec![Artifact {
                platform: release::current_platform().to_string(),
                url: "https://example.invalid/pkg.tar.gz".to_string(),
                sha256: sha.to_string(),
                size: 1,
            }],
            rollout_pct: None,
            soak_hours: None,
            revoked: Vec::new(),
            security: None,
        }
    }

    /// A manifest that WITHDRAWS its own newest version must be refused by the
    /// manual path too — including under `--yes`.
    ///
    /// Revocation is the only switch we have for "we know this build is
    /// harmful". A flag whose meaning is "stop asking me" must not quietly also
    /// mean "ignore what we know", so this asserts the refusal happens BEFORE
    /// the confirmation prompt and before any byte is downloaded.
    #[test]
    fn manual_apply_refuses_a_revoked_version_even_with_yes() {
        with_temp_dir(|| {
            set_lang(Lang::En);
            let mut m = newer_manifest(&"00".repeat(32));
            m.revoked = vec!["9.9.9".to_string()];
            let artifact = m.artifacts[0].clone();
            assert_eq!(
                apply_flow(&m, Some(&artifact), true, "0.6.7"),
                EXIT_RUNTIME,
                "a withdrawn version must not be installed by hand either"
            );
            // …and the same manifest without the revocation is NOT refused here (it
            // proceeds to the download, which this offline test does not follow):
            // the point is that the refusal is the revocation and nothing else.
            m.revoked.clear();
            assert!(!m.is_revoked(&m.version));
        });
    }

    /// F1 — the headline defect. The AUTOMATIC path refuses a version whose
    /// bytes changed under a fixed version number; the manual path installed it,
    /// which made `alice-miner update` the front door around the guardrail.
    ///
    /// The discriminator matters here, so it is worth stating rather than
    /// assumed. `apply_flow` returns an exit code, and BOTH "the gate refused"
    /// and "the download failed" are `EXIT_RUNTIME` — so asserting `EXIT_RUNTIME`
    /// under `--yes` and stopping there would pass just as happily with the
    /// entire gate deleted, because `https://example.invalid/` cannot be fetched
    /// in a test either way. (It does: that exact assertion was written first,
    /// and it survived deleting the guard.) Nor can the test fall back to the
    /// no-`--yes` path, which reaches an interactive prompt and would block on a
    /// developer's terminal.
    ///
    /// What pins it down is the gate's own local history line.
    /// `manual-hash-conflict` is written by the refusal and by nothing else, so
    /// its presence says the ledger was consulted and the version was refused on
    /// it — and the clean-bytes control shows the marker is specific to the
    /// conflict rather than to running the gate at all.
    #[test]
    fn yes_does_not_defeat_a_hash_conflict_on_the_manual_path() {
        with_temp_dir(|| {
            set_lang(Lang::En);
            let dir = alice_miner_core::autoupdate::state_dir();
            let hist = || {
                std::fs::read_to_string(dir.join("update-history.jsonl")).unwrap_or_default()
            };
            // This machine first saw 9.9.9 carrying "bb…".
            alice_miner_core::alice_release::auto::note_seen(&dir, "9.9.9", &"bb".repeat(32));

            // The control: the SAME version, offering the bytes this machine
            // actually recorded. It is not refused — it goes on to the download,
            // which fails offline — and it leaves no conflict on the record.
            let same = newer_manifest(&"bb".repeat(32));
            apply_flow(&same, Some(&same.artifacts[0]), /* yes */ true, "0.6.7");
            assert!(
                !hist().contains("manual-hash-conflict"),
                "matching bytes are not a conflict: {}",
                hist()
            );

            // The server now offers "aa…" under the SAME version number.
            let m = newer_manifest(&"aa".repeat(32));
            assert_eq!(
                apply_flow(&m, Some(&m.artifacts[0]), /* yes */ true, "0.6.7"),
                EXIT_RUNTIME,
                "`--yes` must not install a version whose bytes changed under it"
            );
            assert!(
                hist().contains("manual-hash-conflict"),
                "the ledger must be what stopped it, not a later download failure: {}",
                hist()
            );
        });
    }

    /// …and the guardrails run BEFORE the rest of `apply_flow`, not somewhere
    /// after it. This is the ordering proof, and it needs no network and no
    /// terminal: with no package for this platform the ungated flow returns
    /// `EXIT_OK` at the "download it yourself" branch, so a withdrawn version
    /// reaching `EXIT_RUNTIME` can only be the gate having fired first.
    #[test]
    fn the_guardrails_run_before_the_rest_of_the_manual_flow() {
        with_temp_dir(|| {
            set_lang(Lang::En);
            let mut m = newer_manifest(&"00".repeat(32));
            m.artifacts[0].platform = "definitely-not-this-platform".to_string();

            // Clean version, no package here → the download-it-yourself branch.
            assert_eq!(apply_flow(&m, None, true, "0.6.7"), EXIT_OK);

            // Withdrawn, everything else identical → refused before that branch.
            m.revoked = vec!["9.9.9".to_string()];
            assert_eq!(
                apply_flow(&m, None, true, "0.6.7"),
                EXIT_RUNTIME,
                "the guardrails must be consulted before anything else in the flow"
            );
        });
    }

    /// The manual path must RECORD the sighting, not just read it. Before this,
    /// nothing on the manual path ever wrote the seen ledger, so a version
    /// installed by hand left no bytes on record for the next check to compare
    /// against — the hash-conflict guard had nothing to guard with on exactly
    /// the machines that update by hand.
    #[test]
    fn the_manual_path_records_what_it_was_offered() {
        with_temp_dir(|| {
            set_lang(Lang::En);
            let dir = alice_miner_core::autoupdate::state_dir();
            assert!(!dir.join("update-seen.json").exists());
            let m = newer_manifest(&"cd".repeat(32));
            let check = alice_miner_core::autoupdate::manual_check(&m, Some(&m.artifacts[0]), "0.6.7");
            assert_eq!(
                check.outcome,
                alice_miner_core::autoupdate::ManualOutcome::Proceed,
                "a clean version is not blocked just because it is new"
            );
            assert!(
                dir.join("update-seen.json").exists(),
                "the manual path must write the seen ledger"
            );
            // And it says how long the version has been visible, so the person
            // choosing has the same fact the automatic path decides on.
            let v = check.visibility.expect("a visibility line");
            assert!(v.contains("9.9.9") && v.contains("less than a minute"), "{v}");
        });
    }

    // ── `--check` must never install, and no "required upgrade" may go backwards ──

    /// `--check` is documented as "Only CHECK + report …; never apply", and the
    /// `Unsupported` arm never looked at it: it called `apply_flow`
    /// unconditionally, so `alice-miner update --check --yes` downloaded and
    /// installed, and without `--yes` on a terminal it put an unexpected apply
    /// prompt in front of someone who asked for a report.
    ///
    /// The discriminator is the seen ledger, not the exit code. `apply_flow`'s
    /// first act is the shared gate, which RECORDS the sighting; `--check` never
    /// enters it, so the file must not exist. The control — the same manifest,
    /// same everything, `check = false` — writes it, which is what shows the
    /// file's absence means "the flow was not entered" rather than "the flow
    /// does not write files".
    #[test]
    fn check_only_never_enters_the_apply_flow_on_a_hard_upgrade_notice() {
        with_temp_dir(|| {
            set_lang(Lang::En);
            let dir = alice_miner_core::autoupdate::state_dir();
            let ledger = dir.join("update-seen.json");

            // A genuine hard-upgrade notice: newer version, and this build is
            // below `min_supported`, so `evaluate` returns `Unsupported`.
            let mut m = newer_manifest(&"aa".repeat(32));
            m.min_supported = "99.0.0".to_string();
            assert!(matches!(
                release::evaluate(m.clone(), "0.6.7"),
                CheckOutcome::Unsupported { .. }
            ));

            // The ledger is checked FIRST and deliberately. The exit code is the
            // weaker signal — an apply that merely failed to download offline
            // also returns non-zero — so the assertion that must fire when this
            // regresses is the one about the flow having been entered at all.
            let code = act(release::evaluate(m.clone(), "0.6.7"), /* check */ true, /* yes */ true);
            assert!(
                !ledger.exists(),
                "--check must not reach the apply flow at all (ledger: {:?})",
                std::fs::read_to_string(&ledger).unwrap_or_default()
            );
            assert_eq!(code, EXIT_OK);

            // The control: identical input, `--check` dropped. Now the flow IS
            // entered — the sighting lands — and only the offline download stops
            // it. Without this, the assertion above would pass on a build that
            // simply never records anything.
            act(release::evaluate(m, "0.6.7"), /* check */ false, /* yes */ true);
            assert!(
                ledger.exists(),
                "the control must show --check is what stopped it"
            );
        });
    }

    /// `evaluate` tests `min_supported` BEFORE `is_newer`, so a manifest saying
    /// `min_supported: 99.0.0` with `version: 0.6.4` arrives as `Unsupported` —
    /// the state the CLI renders as "you must upgrade" — while what it offers is
    /// a DOWNGRADE. Applied, that is a signed, silent return to exactly the
    /// builds this release exists to escape, on a loop, because the downgraded
    /// build is still below `min_supported`.
    ///
    /// The exit code alone would prove nothing here: `EXIT_RUNTIME` is also what
    /// an offline download failure returns. So this uses the ordering trick the
    /// F1 tests use — with no package for this platform, an ungated flow returns
    /// `EXIT_OK` at the "download it yourself" branch, and the newer-version
    /// control shows that is genuinely where it lands. `EXIT_RUNTIME` can then
    /// only be the gate, and the history line names which gate.
    #[test]
    fn a_required_upgrade_that_is_really_a_downgrade_is_refused() {
        with_temp_dir(|| {
            set_lang(Lang::En);
            let dir = alice_miner_core::autoupdate::state_dir();
            let hist =
                || std::fs::read_to_string(dir.join("update-history.jsonl")).unwrap_or_default();

            // No package for this platform → the ungated flow ends at EXIT_OK.
            let mut newer = newer_manifest(&"aa".repeat(32));
            newer.min_supported = "99.0.0".to_string();
            newer.artifacts[0].platform = "definitely-not-this-platform".to_string();
            assert_eq!(
                act(release::evaluate(newer, "0.6.7"), false, true),
                EXIT_OK,
                "the control: a genuine hard upgrade with no package here"
            );
            assert!(!hist().contains("manual-downgrade-refused"), "{}", hist());

            // The same shape, pointing backwards.
            let mut down = newer_manifest(&"aa".repeat(32));
            down.version = "0.6.4".to_string();
            down.min_supported = "99.0.0".to_string();
            down.artifacts[0].platform = "definitely-not-this-platform".to_string();
            match release::evaluate(down.clone(), "0.6.8") {
                CheckOutcome::Unsupported { manifest, .. } => assert_eq!(manifest.version, "0.6.4"),
                other => panic!("expected the trap state, got {other:?}"),
            }
            assert_eq!(
                act(release::evaluate(down, "0.6.8"), false, true),
                EXIT_RUNTIME,
                "a 'required upgrade' that is a downgrade must not be applied"
            );
            assert!(
                hist().contains("manual-downgrade-refused"),
                "the gate must be what stopped it, not a download failure: {}",
                hist()
            );
        });
    }

    /// `quiet=true` (the `--json` / machine paths) is also a no-op.
    #[test]
    fn quiet_is_a_noop() {
        with_temp_dir(|| {
            startup_banner(true);
            assert!(!cache_path().exists(), "quiet must not write a cache");
        });
    }

    // ── AM-REL-009: the CLI now drives the first-launch health gate ───────────

    /// The gate's full state machine, driven against a REAL marker file on a stub
    /// app path — the same `alice-release` primitives the CLI calls, so this pins
    /// the wiring, not a mock of it.
    ///
    /// This is the regression that matters: `arm_pending_health_check` was called by
    /// the CLI's `apply_pipeline` and resolved by nobody, so a headless self-update
    /// left the marker armed forever and a crash-on-launch build was never rolled
    /// back.
    #[test]
    fn health_gate_arms_confirms_and_rolls_back() {
        let dir = std::env::temp_dir().join(format!(
            "alice-cli-health-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let app = dir.join(if cfg!(windows) { "alice-miner.exe" } else { "alice-miner" });
        std::fs::write(&app, b"new-build").unwrap();

        // Nothing armed → Normal, and confirming is a no-op.
        assert_eq!(
            release::register_launch(&app, "1.4.0").unwrap(),
            release::LaunchDecision::Normal
        );

        // An update armed the gate (what `apply_pipeline` does).
        release::arm_pending_health_check(&app, "1.4.0").unwrap();
        assert!(release::has_pending_health_check(&app));

        // First run of the new build: on probation.
        assert_eq!(
            release::register_launch(&app, "1.4.0").unwrap(),
            release::LaunchDecision::FreshFirstRun {
                version: "1.4.0".into()
            }
        );
        assert!(
            release::has_pending_health_check(&app),
            "the marker stays armed until the build proves it starts"
        );

        // The process came up → commit. THIS is the step the CLI never took.
        assert!(release::confirm_health_and_commit(&app).unwrap());
        assert!(
            !release::has_pending_health_check(&app),
            "a confirmed launch must clear the marker (it used to linger forever)"
        );

        // Now the crash-on-launch path: armed, reaches startup, never confirms.
        release::arm_pending_health_check(&app, "1.5.0").unwrap();
        assert_eq!(
            release::register_launch(&app, "1.5.0").unwrap(),
            release::LaunchDecision::FreshFirstRun {
                version: "1.5.0".into()
            }
        );
        // (no confirm — the build died here)
        assert_eq!(
            release::register_launch(&app, "1.5.0").unwrap(),
            release::LaunchDecision::RolledBack {
                failed_version: "1.5.0".into()
            },
            "a build that reaches startup twice without confirming must roll back"
        );
        assert!(!release::has_pending_health_check(&app), "no marker is left behind");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `register_launch_at_startup` + `confirm_launch_health` must never panic and
    /// must be safe to call on a plain, never-updated build (the overwhelmingly
    /// common case — including inside the test harness, whose exe has no marker).
    #[test]
    fn health_gate_entry_points_are_safe_on_a_normal_build() {
        let h = register_launch_at_startup();
        assert_eq!(h, LaunchHealth::Normal, "no marker → nothing to report");
        confirm_launch_health(&h);
        // A RolledBack report is print-only and must not panic either.
        confirm_launch_health(&LaunchHealth::RolledBack {
            failed_version: "9.9.9".into(),
        });
    }
}
