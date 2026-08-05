//! `alice-miner setup` — the guided first-run wizard (Theme 2 #6).
//!
//! Walks a non-developer through the first 60 seconds:
//!   1. detect hardware + recommend a lane,
//!   2. reward address — paste an existing Alice address (validated SS58-300
//!      inline) or generate a fresh identity inline,
//!   3. optional 15% PRL return address for a GPU lane,
//!   4. confirm a summary,
//!   5. start mining,
//!   6. point at the live dashboard.
//!
//! Every step has a FLAG equivalent (`--lane` / `--address` / `--generate` /
//! `--prl-payout` / `--yes` / `--no-input` / `--start`/`--no-start`) so the WHOLE
//! wizard runs from a single non-interactive copy-paste line — the line the
//! website publishes (web→CLI continuity). It is re-runnable.
//!
//! ── HAZARD (kept) ───────────────────────────────────────────────────────────
//! `$ALICE_IDENTITY_DIR` isolates only the pointer, not necessarily the keystore.
//! The `--generate` path therefore REFUSES to clobber an existing identity: if a
//! pointer already exists we warn and stop rather than silently overwrite a
//! reward identity (the core `create` ALSO backs up any keystore, but we refuse
//! up-front so the user makes the choice). A secret never lands in argv.
//!
//! ── CREDIT-ONLY ─────────────────────────────────────────────────────────────
//! The wizard prints only setup status (hardware, lane, address shape, the 15%
//! PRL ENROLLMENT step) — never a `$`/`paid`/`earned`/`payout` figure, and never a
//! seed/mnemonic into a file or stdout it shouldn't (a generated mnemonic goes to
//! the same forced-backup block `identity --create` uses).

use std::io::{IsTerminal, Write};

use alice_miner_core::tr;
use alice_miner_core::{CapabilityProfile, Lane};
use zeroize::Zeroizing;

use crate::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE};

/// How the reward address is obtained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressMode {
    /// Use this already-known Alice address (from `--address`, validated later).
    Paste(String),
    /// Generate a fresh identity for the reward address.
    Generate,
    /// Decide interactively (prompt the user to paste or generate).
    Ask,
}

/// Whether to start mining at the end of the wizard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartChoice {
    /// Start mining when the wizard finishes.
    Yes,
    /// Finish setup but do not start.
    No,
    /// Decide interactively (or default to Yes under `--yes`).
    Ask,
}

/// Which miner program the wizard configures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinerChoice {
    /// The recommended bundled (SHA-pinned) engine — the default.
    Bundled,
    /// A user-supplied custom (bring-your-own, possibly closed-source) miner — the
    /// CLI fully manages it (form A).
    Custom,
    /// Don't spawn a miner; run only the possession-proof keep-alive for the user's
    /// OWN rig (form B — `companion`).
    CompanionOnly,
    /// Decide interactively (default to Bundled when non-interactive).
    Ask,
}

impl MinerChoice {
    /// Parse the `--miner` token. `None` for an unknown value.
    fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "bundled" | "official" | "default" => Some(MinerChoice::Bundled),
            "custom" | "byo" => Some(MinerChoice::Custom),
            "companion" | "companion-only" | "byo-companion" => Some(MinerChoice::CompanionOnly),
            _ => None,
        }
    }
}

/// The resolved wizard configuration (flags + interactivity).
#[derive(Debug, Clone)]
pub struct SetupConfig {
    /// The `--lane` token (resolved to a [`Lane`] inside `run`, honoring `auto`).
    pub lane: String,
    pub address: AddressMode,
    /// The 15% PRL return address to set (a `prl1p…`), if provided.
    pub prl_payout: Option<String>,
    /// Accept the confirmation without prompting.
    pub yes: bool,
    /// Never prompt — fail if a required value is missing.
    pub no_input: bool,
    /// Whether to start mining at the end.
    pub start: StartChoice,
    /// `--generate` keystore passphrase (flag form; insecure — warned by the
    /// shared resolver) — or read from stdin when `password_stdin`.
    pub password: Option<String>,
    pub password_stdin: bool,
    /// Which miner program to run (`--miner`): bundled / custom / companion-only, or
    /// [`MinerChoice::Ask`].
    pub miner: MinerChoice,
    /// (custom) The user's miner binary path (`--miner-bin`).
    pub miner_bin: Option<String>,
    /// (custom) The miner family / argv shape (`--miner-preset`).
    pub miner_preset: Option<String>,
    /// (custom + template preset) A custom argv with placeholders (`--miner-arg-template`).
    pub miner_arg_template: Option<String>,
    /// (custom) The explicit "run my own unverified binary" acknowledgement.
    pub i_understand_unverified: bool,
    /// The GPU region to pin (`--region`): `us`/`asia`/`eu`/`auto`, or `None` to ask
    /// (interactive) / keep the remembered value (non-interactive).
    pub region: Option<String>,
}

impl SetupConfig {
    /// The config used when the bare binary auto-runs setup on a first launch:
    /// fully interactive (ask everything), no flags supplied.
    pub fn first_launch() -> Self {
        SetupConfig {
            lane: "auto".to_string(),
            address: AddressMode::Ask,
            prl_payout: None,
            yes: false,
            no_input: false,
            start: StartChoice::Ask,
            password: None,
            password_stdin: false,
            miner: MinerChoice::Ask,
            miner_bin: None,
            miner_preset: None,
            miner_arg_template: None,
            i_understand_unverified: false,
            region: None,
        }
    }
}

impl From<crate::SetupArgs> for SetupConfig {
    fn from(a: crate::SetupArgs) -> Self {
        let address = if a.generate {
            AddressMode::Generate
        } else if let Some(addr) = a.address {
            AddressMode::Paste(addr)
        } else {
            AddressMode::Ask
        };
        let start = if a.start {
            StartChoice::Yes
        } else if a.no_start {
            StartChoice::No
        } else {
            StartChoice::Ask
        };
        // A `--miner-bin`/`--miner-preset` without an explicit `--miner custom` still
        // implies the custom path (the user is clearly configuring a custom miner).
        let miner = match a.miner.as_deref().and_then(MinerChoice::parse) {
            Some(c) => c,
            None if a.miner_bin.is_some() || a.miner_preset.is_some() => MinerChoice::Custom,
            None => MinerChoice::Ask,
        };
        SetupConfig {
            lane: a.lane,
            address,
            prl_payout: a.prl_payout,
            yes: a.yes,
            no_input: a.no_input,
            start,
            password: a.password,
            password_stdin: a.password_stdin,
            miner,
            miner_bin: a.miner_bin,
            miner_preset: a.miner_preset,
            miner_arg_template: a.miner_arg_template,
            i_understand_unverified: a.i_understand_unverified,
            region: a.region,
        }
    }
}

/// Whether prompting is allowed: an interactive stdin TTY AND `--no-input` not set.
fn can_prompt(cfg: &SetupConfig) -> bool {
    !cfg.no_input && std::io::stdin().is_terminal()
}

/// Read a trimmed line from stdin (the wizard's prompt primitive). `None` on EOF.
fn prompt_line(prompt: &str) -> Option<String> {
    use std::io::BufRead;
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let n = std::io::stdin().lock().read_line(&mut line).ok()?;
    if n == 0 {
        return None; // EOF
    }
    Some(line.trim().to_string())
}

/// Run the guided wizard. Returns a process exit code. Never panics; never puts a
/// secret in argv; refuses to clobber an existing identity in the generate path.
pub fn run(cfg: SetupConfig, no_color: bool) -> i32 {
    println!("{}", tr!("Alice Miner setup", "Alice Miner 安装向导"));
    println!("─────────────────");

    // (1) Detect hardware + recommend a lane.
    let cap = CapabilityProfile::detect();
    println!("{}: {}", tr!("Device", "设备"), cap.profile.display);
    let lane = match crate::resolve_lane(&cfg.lane, &cap) {
        Ok(l) => l,
        Err(code) => return code,
    };
    println!(
        "{}:   {} ({})",
        tr!("Lane", "通道"),
        lane.label(),
        if cfg.lane.eq_ignore_ascii_case("auto") {
            tr!("recommended", "推荐")
        } else {
            tr!("selected", "已选")
        }
    );

    // (1b) Miner program: the recommended bundled engine, your OWN custom miner, or
    // companion-only (you launch your rig; the CLI only holds the possession proof).
    let miner_choice = resolve_miner_choice(&cfg);

    // Honest viability gate (the same one `start` uses) — refuse early. Skipped for
    // companion-only: there the miner runs on the USER's rig (possibly another box),
    // so this machine's GPU viability is irrelevant — the CLI only holds the PoP.
    if miner_choice != MinerChoice::CompanionOnly && !cap.support(lane).is_runnable() {
        eprintln!(
            "error: {}",
            tr!(
                "the {lane} lane is {state} on this device ({reason}). Try `alice-miner setup --lane {rec}`.",
                "本设备上 {lane} 通道 {state}({reason})。请尝试 `alice-miner setup --lane {rec}`。"
            )
            .replace("{lane}", lane.label())
            .replace("{state}", cap.support(lane).label())
            .replace("{reason}", cap.viability.reason(lane).unwrap_or("not viable"))
            .replace("{rec}", cap.recommended_lane().id())
        );
        return EXIT_USAGE;
    }

    // (2) Reward address: paste (validate SS58-300 inline) or generate inline. The
    // generate path also hands back the keystore passphrase it just resolved, so a
    // pearlhash `start` below can unlock with the SAME secret instead of re-prompting
    // (NIT B). It stays zeroized and never reaches argv.
    let (address, generated_passphrase) = match resolve_reward_address(&cfg) {
        Ok(pair) => pair,
        Err(code) => return code,
    };
    println!("{}: {address}", tr!("Address", "地址"));

    // Companion-only (form B): don't spawn a miner — collect the region, then run the
    // possession-proof keep-alive for the user's OWN rig. Routes to the existing
    // `companion` path; never touches the mining start / prl-payout / difficulty steps.
    if miner_choice == MinerChoice::CompanionOnly {
        return run_companion_only(&cfg, lane, address, generated_passphrase);
    }

    // (2b) Custom miner (form A): configure + persist the backend, or clear any stale
    // custom config for a bundled choice (so a prior custom setup doesn't linger).
    if let Err(code) = apply_miner_choice(&cfg, miner_choice, lane) {
        return code;
    }

    // (2c) Region: `us`/`asia`/`eu` LOCKS the GPU-PRL lane to a region (remembered);
    // `auto` clears the lock (nearest, with auto-failover). Only affects GPU-PRL.
    if let Err(code) = resolve_and_persist_region(&cfg, lane) {
        return code;
    }

    // (3) Optional 15% PRL return address for a GPU lane.
    if let Err(code) = maybe_set_prl_payout(&cfg, lane) {
        return code;
    }

    // (4) Confirm.
    if !confirm(&cfg, lane, &address) {
        println!(
            "{}",
            tr!(
                "Setup cancelled. Re-run `alice-miner setup` any time.",
                "已取消安装。你可以随时重新运行 `alice-miner setup`。"
            )
        );
        return EXIT_OK;
    }

    // A one-line difficulty explainer — takes "difficulty" out of the miner's
    // mental model before the first run. The server auto-matches the workload to
    // the device (vardiff on XMR/LTC, fixed on PRL — one sentence either way); a
    // miner's share tracks hashpower over a rolling ~24h average, not raw submitted
    // shares, so an occasional stale/rejected share doesn't change what they earn.
    println!(
        "\n{}",
        tr!(
            "No difficulty to set — the server matches the workload to your device automatically. \
Your reward tracks your share of hashpower (a rolling ~24h average), not how many shares you submit.",
            "无需设置难度 —— 服务端会自动把工作量匹配到你的设备。\
你的奖励取决于你的算力份额(近 24 小时滚动平均),而不是你提交了多少 share。"
        )
    );

    // (5) Start (or stop here) + (6) point at the live dashboard.
    match start_choice(&cfg) {
        StartChoice::No => {
            println!(
                "\n{}",
                tr!(
                    "Setup complete. Start mining when ready:",
                    "安装完成。准备好后即可开始挖矿:"
                )
            );
            println!("  alice-miner start --lane {}", lane.cli_lane_arg());
            EXIT_OK
        }
        _ => {
            println!(
                "\n{}",
                tr!(
                    "Starting the miner — a live dashboard follows (Ctrl-C to stop).",
                    "正在启动矿工 — 稍后显示实时面板 (Ctrl-C 停止)。"
                )
            );
            // Reuse the EXACT `start` path so setup can't drift from real mining.
            // `password` stays None — the generated passphrase is NEVER put on argv;
            // it rides the separate in-process `prefetched_unlock` channel below.
            let start_args = crate::StartArgs {
                lane: lane.cli_lane_arg().to_string(),
                address: Some(address),
                dual: false,
                json: false,
                plain: false,
                duration_s: 0,
                password: None,
                password_stdin: false,
                gpus: None,
                // The wizard inherits whatever region was remembered (no pin here);
                // a user sets/clears the lock later with `start --region <tag|auto>`.
                region: None,
                from_service: false,
                telemetry_file: None,
                allow_multiple: false,
            };
            // NIT B: if we just generated the keystore, hand its passphrase straight to
            // start so a pearlhash lane unlocks without a SECOND prompt for the same
            // secret. `None` for paste/reuse (start prompts to unlock the existing key).
            crate::cmd_start_with_unlock(start_args, no_color, generated_passphrase)
        }
    }
}

/// Resolve the reward address per the configured [`AddressMode`], validating an
/// SS58-300 Alice address inline and offering to generate one interactively.
///
/// Returns `(address, Option<keystore passphrase>)`. The passphrase is `Some` ONLY on
/// the GENERATE path (where we just created the keystore and so already hold its
/// passphrase) — every paste / reuse path returns `None`, since no keystore was created
/// and a pearlhash `start` must still prompt to unlock the existing key. The `Some`
/// passphrase is threaded into the start handoff so a "generate then start a GPU lane"
/// first run prompts for the SAME secret only ONCE (NIT B).
fn resolve_reward_address(
    cfg: &SetupConfig,
) -> Result<(String, Option<Zeroizing<String>>), i32> {
    match &cfg.address {
        AddressMode::Paste(addr) => validate_or_reject(addr).map(|a| (a, None)),
        AddressMode::Generate => generate_identity_address(cfg).map(|(a, pw)| (a, Some(pw))),
        AddressMode::Ask => {
            // An existing identity? Offer to reuse it (the common re-run case).
            if let Some(p) = alice_miner_core::identity::load_pointer() {
                if alice_miner_core::lane::xmr::validate_alice_address(&p.address).is_some() {
                    println!(
                        "{}: {}",
                        tr!("Found an existing reward address", "找到已有的奖励地址"),
                        p.address
                    );
                    if !can_prompt(cfg) {
                        return Ok((p.address, None));
                    }
                    let ans = prompt_line(tr!("Use it? [Y/n] ", "使用它?[Y/n] ")).unwrap_or_default();
                    if ans.is_empty() || ans.eq_ignore_ascii_case("y") || ans.eq_ignore_ascii_case("yes") {
                        return Ok((p.address, None));
                    }
                }
            }
            if !can_prompt(cfg) {
                eprintln!(
                    "error: {}",
                    tr!(
                        "no reward address. Pass --address <alice-addr> or --generate (no interactive prompt available).",
                        "没有奖励地址。请传入 --address <alice-地址> 或 --generate(无法进行交互式提示)。"
                    )
                );
                return Err(EXIT_USAGE);
            }
            // No reward address yet: make generating one the frictionless DEFAULT
            // (`[Y/n]`), and treat "no" as "paste an existing address" — so a brand-new
            // miner just presses Enter to get an identity + backup phrase.
            println!(
                "{}",
                tr!(
                    "No reward address yet.",
                    "尚无奖励地址。"
                )
            );
            let ans = prompt_line(tr!(
                "Generate a new identity now? (you'll back up a 24-word phrase) [Y/n] ",
                "现在生成一个新身份?(你需要备份 24 个词的助记词)[Y/n] "
            ))
            .unwrap_or_default();
            if ans.is_empty() || ans.eq_ignore_ascii_case("y") || ans.eq_ignore_ascii_case("yes") {
                generate_identity_address(cfg).map(|(a, pw)| (a, Some(pw)))
            } else {
                let pasted = prompt_line(tr!(
                    "Paste your existing Alice address: ",
                    "粘贴你已有的 Alice 地址: "
                ))
                .unwrap_or_default();
                validate_or_reject(&pasted).map(|a| (a, None))
            }
        }
    }
}

/// Validate a pasted address as an Alice SS58-300 address, returning the canonical
/// form or a usage error. Reuses the SAME validator the lane uses.
fn validate_or_reject(addr: &str) -> Result<String, i32> {
    match alice_miner_core::lane::xmr::validate_alice_address(addr.trim()) {
        Some(canonical) => {
            // Persist it as a watch-only pointer so subsequent `start` (no --address)
            // and the dashboard find it — this is the wizard "saving" the choice.
            match alice_miner_core::identity::paste(&canonical, Some("setup".to_string())) {
                Ok(_) => Ok(canonical),
                // The pointer write failed (e.g. read-only home): still proceed with
                // the validated address in-memory (start gets it via --address).
                Err(e) => {
                    eprintln!(
                        "warning: {}",
                        tr!(
                            "could not save the address pointer ({e}); continuing.",
                            "无法保存地址指针({e});继续。"
                        )
                        .replace("{e}", &e.to_string())
                    );
                    Ok(canonical)
                }
            }
        }
        None => {
            eprintln!(
                "error: {}",
                tr!(
                    "'{addr}' is not a valid Alice address (must be SS58 format-300).",
                    "'{addr}' 不是有效的 Alice 地址(必须是 SS58 format-300)。"
                )
                .replace("{addr}", addr)
            );
            Err(EXIT_USAGE)
        }
    }
}

/// Generate a fresh identity for the reward address. REFUSES to clobber an
/// existing identity (the `$ALICE_IDENTITY_DIR` keystore hazard): if a pointer
/// already exists we warn and stop. The mnemonic is printed via the SAME forced-
/// backup block `identity --create` uses; no secret reaches argv.
///
/// Returns the reward address AND the resolved keystore passphrase (zeroized): the
/// passphrase that just CREATED the keystore is the SAME one a pearlhash `start` needs
/// to unlock it for the PoP, so the caller threads it straight into the start handoff
/// (NIT B) — no second prompt for the same secret. It NEVER reaches argv, is never
/// logged, and is dropped/zeroized the moment the start command consumes it.
fn generate_identity_address(cfg: &SetupConfig) -> Result<(String, Zeroizing<String>), i32> {
    // HAZARD GUARD: never silently overwrite an existing identity.
    if let Some(p) = alice_miner_core::identity::load_pointer() {
        eprintln!(
            "error: {}",
            tr!(
                "an identity already exists ({addr}). Generating a new one would replace your \
                 reward identity. If that's what you want, run `alice-miner identity --create` \
                 explicitly (it backs up the old keystore first); otherwise re-run setup with \
                 --address <that-address> to keep mining to it.",
                "身份已存在({addr})。生成新身份会替换你的奖励身份。如果你确实想这么做,\
                 请显式运行 `alice-miner identity --create`(它会先备份旧的密钥库);\
                 否则请用 --address <该地址> 重新运行 setup 以继续向它挖矿。"
            )
            .replace("{addr}", &p.address)
        );
        return Err(EXIT_USAGE);
    }
    // Resolve the keystore passphrase (stdin / flag / interactive prompt) via the
    // SAME shared resolver `identity --create` uses — it warns on the insecure flag.
    // Wrap in `Zeroizing` so it is scrubbed on EVERY exit path (success threads it on,
    // an error drops it here) and never lingers in plaintext.
    let password = match crate::resolve_password(cfg.password.clone(), cfg.password_stdin) {
        Ok(p) => Zeroizing::new(p),
        Err(e) => {
            eprintln!("error: {e}");
            return Err(EXIT_USAGE);
        }
    };
    match alice_miner_core::identity::create(Some("setup".to_string()), &password) {
        Ok((identity, mnemonic)) => {
            // Forced-backup block — same wording family as `identity --create`. The
            // mnemonic goes to STDERR so a piped stdout can't slurp it.
            eprintln!();
            eprintln!(
                "  {}",
                tr!(
                    "── BACK UP THIS RECOVERY PHRASE (24 words) ──",
                    "── 请备份此恢复助记词(24 个词)──"
                )
            );
            eprintln!("  {}", mnemonic.as_str());
            eprintln!("  ─────────────────────────────────────────────");
            Ok((identity.address, password))
        }
        Err(e) => {
            eprintln!(
                "error: {}",
                tr!("failed to create identity: {e}", "创建身份失败: {e}").replace("{e}", &e.to_string())
            );
            Err(EXIT_RUNTIME)
        }
    }
}

/// Set the 15% PRL return address for a GPU lane, if provided / chosen. Pure local
/// file IO (a public address; no engine, no secret). On a GPU lane with no value
/// provided, offer to set one interactively; otherwise it's a no-op.
fn maybe_set_prl_payout(cfg: &SetupConfig, lane: Lane) -> Result<(), i32> {
    // An explicit value always wins (even off a GPU lane it's harmless to store).
    if let Some(addr) = cfg.prl_payout.as_deref() {
        return save_prl(addr);
    }
    if !lane.is_prl_lane() {
        return Ok(()); // the return only applies to GPU pearlhash lanes
    }
    // Already set? Then nothing to do.
    if matches!(alice_miner_core::prl_payout::load_payout_address(), Ok(Some(_))) {
        return Ok(());
    }
    if !can_prompt(cfg) {
        // Non-interactive + GPU lane + unset: just note it (mining still works).
        println!(
            "{}",
            tr!(
                "Note: this GPU lane earns the 15% PRL return. Set it later with `alice-miner identity --set-prl-payout <prl1p…>`.",
                "提示: 此 GPU 通道可获得 15% PRL 返还。稍后可用 `alice-miner identity --set-prl-payout <prl1p…>` 设置。"
            )
        );
        return Ok(());
    }
    println!(
        "{}",
        tr!(
            "This GPU lane earns the 15% PRL return (optional).",
            "此 GPU 通道可获得 15% PRL 返还(可选)。"
        )
    );
    let ans = prompt_line(tr!(
        "Set your PRL return address now? paste prl1p… or leave blank to skip: ",
        "现在设置 PRL 返还地址?粘贴 prl1p… 或留空跳过: "
    ))
    .unwrap_or_default();
    if ans.is_empty() {
        return Ok(());
    }
    save_prl(&ans)
}

/// Persist a PRL return address (shape-validated by the core). A typo is surfaced
/// as a usage error and NEVER written.
fn save_prl(addr: &str) -> Result<(), i32> {
    match alice_miner_core::prl_payout::save_payout_address(addr) {
        Ok(_) => {
            let masked = alice_miner_core::prl_payout::mask_payout(addr.trim());
            println!(
                "{}: {masked}",
                tr!("15% PRL return address saved", "15% PRL 返还地址已保存")
            );
            Ok(())
        }
        Err(e) => {
            eprintln!("error: {e}");
            Err(EXIT_USAGE)
        }
    }
}

/// The confirmation step. `--yes` (or a non-interactive run) accepts silently.
fn confirm(cfg: &SetupConfig, lane: Lane, address: &str) -> bool {
    println!("\n{}", tr!("Ready to mine:", "准备开始挖矿:"));
    println!("  {}:    {}", tr!("lane", "通道"), lane.label());
    println!("  {}: {address}", tr!("address", "地址"));
    if cfg.yes || !can_prompt(cfg) {
        return true;
    }
    let ans = prompt_line(tr!("Start now? [Y/n] ", "现在开始?[Y/n] ")).unwrap_or_default();
    ans.is_empty() || ans.eq_ignore_ascii_case("y") || ans.eq_ignore_ascii_case("yes")
}

/// Resolve the final start choice: `Ask` becomes Yes under `--yes` or a
/// non-interactive run (the copy-paste line is meant to start), else it prompts in
/// `confirm` already, so by here Ask → Yes.
fn start_choice(cfg: &SetupConfig) -> StartChoice {
    match cfg.start {
        StartChoice::Ask => StartChoice::Yes,
        other => other,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// T6: miner-program selection, custom-miner configuration, region, companion.
// ─────────────────────────────────────────────────────────────────────────────

/// Resolve which miner program to configure. A flag choice wins; otherwise, on a
/// terminal, ask (default = the recommended bundled engine); non-interactive with no
/// flag defaults to Bundled (the copy-paste line's zero-config path).
fn resolve_miner_choice(cfg: &SetupConfig) -> MinerChoice {
    if cfg.miner != MinerChoice::Ask {
        return cfg.miner;
    }
    if !can_prompt(cfg) {
        return MinerChoice::Bundled;
    }
    println!("\n{}", tr!("Miner program:", "挖矿程序:"));
    println!(
        "  {}",
        tr!(
            "1) recommended engine, managed for you (default)",
            "1) 推荐引擎,由我们托管(默认)"
        )
    );
    println!(
        "  {}",
        tr!(
            "2) my own miner program (I'll give its path)",
            "2) 我自己的挖矿程序(我来提供路径)"
        )
    );
    println!(
        "  {}",
        tr!(
            "3) I run my own rig — just hold my authorization (companion)",
            "3) 我自己启动矿机 —— 只需持有我的授权(伴侣模式)"
        )
    );
    match prompt_line(tr!("Choose [1/2/3]: ", "选择 [1/2/3]: "))
        .unwrap_or_default()
        .trim()
    {
        "2" => MinerChoice::Custom,
        "3" => MinerChoice::CompanionOnly,
        _ => MinerChoice::Bundled,
    }
}

/// Apply the miner choice: configure + persist a custom miner, or clear any stale
/// custom config for a bundled run (so a prior custom setup never lingers).
/// Companion-only is handled earlier in `run` and never reaches here.
fn apply_miner_choice(cfg: &SetupConfig, choice: MinerChoice, lane: Lane) -> Result<(), i32> {
    match choice {
        MinerChoice::Custom => configure_custom_miner(cfg, lane),
        _ => {
            // Bundled (or a stray Ask): clear any previously-saved custom miner so the
            // bundled engine actually runs. Best-effort (a read-only home is not fatal).
            let _ = alice_miner_core::settings::clear_custom_miner();
            Ok(())
        }
    }
}

/// Configure + persist a CUSTOM (bring-your-own) miner for `lane`: resolve the binary
/// path (flag / detected / prompt), the preset (flag / detected family / prompt), an
/// arg-template for the `template` preset, and the explicit unverified acknowledgement.
fn configure_custom_miner(cfg: &SetupConfig, lane: Lane) -> Result<(), i32> {
    use alice_miner_core::backend::{CustomMiner, MinerPreset};

    // 1) Binary path: an explicit flag, else a detected miner / manual prompt.
    let (path, detected_family): (String, Option<MinerPreset>) = match cfg.miner_bin.clone() {
        Some(p) => (p, None),
        None => pick_custom_binary(cfg, lane)?,
    };

    // 2) Preset: flag → detected family → prompt/default.
    let preset = resolve_custom_preset(cfg, detected_family)?;

    // 3) arg_template (only for the `template` preset).
    let arg_template = if preset == MinerPreset::Template {
        let raw = cfg.miner_arg_template.clone().or_else(|| {
            can_prompt(cfg)
                .then(|| {
                    prompt_line(tr!(
                        "argv template (use {POOL} {WALLET} {PASSWORD} {ALGO} [{LOGFILE}]): ",
                        "argv 模板(使用 {POOL} {WALLET} {PASSWORD} {ALGO} [{LOGFILE}]): "
                    ))
                })
                .flatten()
        });
        let tokens: Vec<String> = raw
            .as_deref()
            .unwrap_or("")
            .split_whitespace()
            .map(str::to_string)
            .collect();
        if tokens.is_empty() {
            eprintln!(
                "error: {}",
                tr!(
                    "the `template` preset needs an argv template (--miner-arg-template).",
                    "`template` 预设需要 argv 模板(--miner-arg-template)。"
                )
            );
            return Err(EXIT_USAGE);
        }
        Some(tokens)
    } else {
        None
    };

    // 4) Explicit unverified acknowledgement (flag or one [y/N] prompt).
    let acknowledged = cfg.i_understand_unverified || ack_unverified(cfg, &path);
    if !acknowledged {
        eprintln!(
            "error: {}",
            tr!(
                "a custom miner is not integrity-checked; re-run with --i-understand-unverified to confirm.",
                "自定义矿机不做完整性校验;请加 --i-understand-unverified 确认后重试。"
            )
        );
        return Err(EXIT_USAGE);
    }

    // 5) Build (validates lane/preset/template) + persist.
    let store = alice_miner_core::settings::CustomMinerConfig {
        path,
        lane: lane.cli_lane_arg().to_string(),
        preset: preset.id().to_string(),
        arg_template,
        log_file: None,
        // Defence-in-depth: use the value we actually computed above (the early return
        // at the `!acknowledged` check already guarantees it is `true` here, but binding
        // the real variable keeps the two in lockstep if that guard is ever refactored).
        acknowledged_unverified: acknowledged,
    };
    match CustomMiner::from_config(&store) {
        Ok(cm) => {
            if !cm.path.is_file() {
                eprintln!(
                    "warning: {}",
                    tr!(
                        "custom miner path does not exist yet: {p}",
                        "自定义矿机路径尚不存在: {p}"
                    )
                    .replace("{p}", &cm.path.display().to_string())
                );
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            return Err(EXIT_USAGE);
        }
    }
    match alice_miner_core::settings::save_custom_miner(&store) {
        Ok(_) => {
            println!(
                "{}: {} [{}]",
                tr!("Custom miner set", "已设置自定义矿机"),
                store.path,
                store.preset
            );
            Ok(())
        }
        Err(e) => {
            eprintln!("error: {e}");
            Err(EXIT_RUNTIME)
        }
    }
}

/// Pick the custom binary: scan for installed miners compatible with `lane`, list
/// them, and let the user choose one or enter a path. Returns `(path, detected
/// family)`. Non-interactive with no `--miner-bin` is a usage error.
fn pick_custom_binary(cfg: &SetupConfig, lane: Lane) -> Result<(String, Option<alice_miner_core::backend::MinerPreset>), i32> {
    let candidates: Vec<alice_miner_core::detect::DetectedMiner> =
        alice_miner_core::detect::scan_installed_miners()
            .into_iter()
            .filter(|m| m.supports_lane(lane))
            .collect();

    if !can_prompt(cfg) {
        eprintln!(
            "error: {}",
            tr!(
                "no --miner-bin given and no interactive prompt available.",
                "未提供 --miner-bin,且无法进行交互式提示。"
            )
        );
        return Err(EXIT_USAGE);
    }

    if !candidates.is_empty() {
        println!("\n{}", tr!("Detected miners:", "检测到的矿机:"));
        for (i, m) in candidates.iter().enumerate() {
            println!(
                "  {}) {} [{}]{}",
                i + 1,
                m.path.display(),
                m.family.id(),
                m.version.as_deref().map(|v| format!("  {v}")).unwrap_or_default()
            );
        }
        println!(
            "  {}) {}",
            candidates.len() + 1,
            tr!("enter a path manually", "手动输入路径")
        );
        let ans = prompt_line(tr!("Choose a miner: ", "选择矿机: ")).unwrap_or_default();
        if let Ok(n) = ans.trim().parse::<usize>() {
            if (1..=candidates.len()).contains(&n) {
                let m = &candidates[n - 1];
                return Ok((m.path.display().to_string(), Some(m.family)));
            }
        }
        // Any other answer → fall through to a manual path.
    }

    let p = prompt_line(tr!(
        "Absolute path to your miner binary: ",
        "你的矿机二进制的绝对路径: "
    ))
    .unwrap_or_default();
    if p.trim().is_empty() {
        eprintln!("error: {}", tr!("no miner path given.", "未提供矿机路径。"));
        return Err(EXIT_USAGE);
    }
    Ok((p.trim().to_string(), None))
}

/// Resolve the custom miner PRESET: an explicit `--miner-preset`, else the detected
/// family, else a prompt (default `generic-stratum`). Non-interactive with neither
/// → `generic-stratum` (the safe standard shape).
fn resolve_custom_preset(
    cfg: &SetupConfig,
    detected: Option<alice_miner_core::backend::MinerPreset>,
) -> Result<alice_miner_core::backend::MinerPreset, i32> {
    use alice_miner_core::backend::MinerPreset;
    if let Some(tok) = cfg.miner_preset.as_deref() {
        return MinerPreset::parse(tok).ok_or_else(|| {
            eprintln!(
                "error: {}",
                tr!("unknown --miner-preset `{p}`.", "未知的 --miner-preset `{p}`。").replace("{p}", tok)
            );
            EXIT_USAGE
        });
    }
    if let Some(f) = detected {
        return Ok(f);
    }
    if can_prompt(cfg) {
        let ans = prompt_line(tr!(
            "Miner family [srbminer/xmrig/trex/lolminer/gminer/nbminer/alpha-miner/generic-stratum/template] (default generic-stratum): ",
            "矿机族 [srbminer/xmrig/trex/lolminer/gminer/nbminer/alpha-miner/generic-stratum/template](默认 generic-stratum): "
        ))
        .unwrap_or_default();
        if ans.trim().is_empty() {
            return Ok(MinerPreset::GenericStratum);
        }
        return MinerPreset::parse(ans.trim()).ok_or_else(|| {
            eprintln!("error: {}", tr!("unknown miner family.", "未知的矿机族。"));
            EXIT_USAGE
        });
    }
    Ok(MinerPreset::GenericStratum)
}

/// One `[y/N]` confirmation that the user wants to run their OWN unverified binary
/// (its integrity is not SHA-checked). Non-interactive → `false` (the caller then
/// requires the `--i-understand-unverified` flag).
fn ack_unverified(cfg: &SetupConfig, path: &str) -> bool {
    if !can_prompt(cfg) {
        return false;
    }
    println!(
        "\n{}",
        tr!(
            "A custom miner is YOUR binary — its integrity is NOT checked against any signed release.",
            "自定义矿机是你自己的二进制 —— 其完整性不会与任何签名发布做校验。"
        )
    );
    let ans = prompt_line(
        &tr!("Run {p} anyway? [y/N] ", "仍然运行 {p} 吗?[y/N] ").replace("{p}", path),
    )
    .unwrap_or_default();
    ans.eq_ignore_ascii_case("y") || ans.eq_ignore_ascii_case("yes")
}

/// Resolve + persist the GPU-PRL region pin from `--region` (or a prompt on the
/// GPU-PRL lane): a known tag LOCKS the lane to it (remembered); `auto`/blank CLEARS
/// the lock. Only the GPU-PRL lane is region-aware; other lanes are a no-op.
fn resolve_and_persist_region(cfg: &SetupConfig, lane: Lane) -> Result<(), i32> {
    let raw: String = if let Some(r) = cfg.region.as_deref() {
        r.to_string()
    } else if lane == Lane::GpuPrl && can_prompt(cfg) {
        let tags = alice_miner_core::lane::gpu_prl::region_tags().join("/");
        prompt_line(
            &tr!(
                "Region? [auto/{tags}] (default auto): ",
                "区域?[auto/{tags}](默认 auto): "
            )
            .replace("{tags}", &tags),
        )
        .unwrap_or_default()
    } else {
        return Ok(()); // keep whatever's remembered
    };
    let v = raw.trim().to_ascii_lowercase();
    if v.is_empty() || v == "auto" {
        let _ = alice_miner_core::settings::clear_region_lock();
        return Ok(());
    }
    match alice_miner_core::lane::gpu_prl::normalize_region_tag(&v) {
        Some(tag) => {
            match alice_miner_core::settings::save_region_lock(tag) {
                Ok(_) => println!("{}: {tag}", tr!("Region locked", "已锁定区域")),
                Err(e) => eprintln!("warning: {e}"), // non-fatal (read-only home)
            }
            Ok(())
        }
        None => {
            eprintln!(
                "error: {}",
                tr!("unknown region `{r}` (use: us/asia/eu/auto).", "未知区域 `{r}`(可用: us/asia/eu/auto)。")
                    .replace("{r}", raw.trim())
            );
            Err(EXIT_USAGE)
        }
    }
}

/// Companion-only (form B): don't spawn a miner — run the possession-proof keep-alive
/// for the user's OWN rig. Reuses the existing `companion` path. The companion needs
/// the wallet UNLOCK to sign the proof: the freshly-generated passphrase (generate
/// path), else a resolved keystore passphrase; a watch-only identity fails closed in
/// `companion::run` with a clear message.
fn run_companion_only(
    cfg: &SetupConfig,
    lane: Lane,
    address: String,
    generated: Option<Zeroizing<String>>,
) -> i32 {
    // The companion is only for the PoP-gated pearlhash lanes; default to `prl` when
    // the resolved lane isn't one (e.g. a laptop holding the proof for a remote rig).
    let companion_lane = if lane.is_prl_lane() { lane.cli_lane_arg() } else { "prl" }.to_string();

    let unlock = match generated {
        Some(pw) => Some(pw),
        None => {
            let has_keystore = alice_miner_core::identity::load_pointer()
                .map(|p| p.keystore_path.is_some())
                .unwrap_or(false);
            if has_keystore {
                match crate::resolve_password(cfg.password.clone(), cfg.password_stdin) {
                    Ok(p) => Some(Zeroizing::new(p)),
                    Err(e) => {
                        eprintln!("error: {e}");
                        return EXIT_USAGE;
                    }
                }
            } else {
                None
            }
        }
    };

    println!(
        "\n{}",
        tr!(
            "Companion mode — this holds your authorization while YOUR miner runs (Ctrl-C to stop).",
            "伴侣模式 —— 在你自己的矿机运行期间由它持有你的授权(Ctrl-C 停止)。"
        )
    );
    let flags = crate::companion::CompanionFlags {
        lane: companion_lane,
        device: None,
        region: cfg.region.clone(),
        address: Some(address),
        refresh_secs: None,
        once: false,
        duration_s: 0,
    };
    crate::companion::run(flags, unlock)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `From<SetupArgs>` maps the flags to the right modes (generate wins over a
    /// stray address per clap's conflict, but we still assert the mapping rules).
    #[test]
    fn config_from_args_maps_modes() {
        // A pasted address.
        let cfg = SetupConfig::from(crate::SetupArgs {
            lane: "xmr".into(),
            address: Some("a2abc".into()),
            generate: false,
            prl_payout: None,
            yes: true,
            no_input: false,
            start: false,
            no_start: false,
            password: None,
            password_stdin: false,
            miner: None,
            miner_bin: None,
            miner_preset: None,
            miner_arg_template: None,
            i_understand_unverified: false,
            region: None,
        });
        assert!(matches!(cfg.address, AddressMode::Paste(ref a) if a == "a2abc"));
        assert_eq!(cfg.lane, "xmr");
        assert!(cfg.yes);
        assert_eq!(start_choice(&cfg), StartChoice::Yes);

        // Generate mode.
        let cfg = SetupConfig::from(crate::SetupArgs {
            lane: "auto".into(),
            address: None,
            generate: true,
            prl_payout: Some("prl1pxyz".into()),
            yes: false,
            no_input: true,
            start: false,
            no_start: true,
            password: None,
            password_stdin: false,
            miner: None,
            miner_bin: None,
            miner_preset: None,
            miner_arg_template: None,
            i_understand_unverified: false,
            region: None,
        });
        assert_eq!(cfg.address, AddressMode::Generate);
        assert_eq!(cfg.prl_payout.as_deref(), Some("prl1pxyz"));
        assert!(cfg.no_input);
        assert_eq!(start_choice(&cfg), StartChoice::No);

        // No address, no generate → Ask.
        let cfg = SetupConfig::from(crate::SetupArgs {
            lane: "auto".into(),
            address: None,
            generate: false,
            prl_payout: None,
            yes: false,
            no_input: false,
            start: true,
            no_start: false,
            password: None,
            password_stdin: false,
            miner: None,
            miner_bin: None,
            miner_preset: None,
            miner_arg_template: None,
            i_understand_unverified: false,
            region: None,
        });
        assert_eq!(cfg.address, AddressMode::Ask);
        assert_eq!(start_choice(&cfg), StartChoice::Yes);
    }

    /// T6: `--miner`/`--region` map onto the config; a `--miner-bin` with no explicit
    /// `--miner` still implies the custom path; `--miner companion` maps to companion.
    #[test]
    fn config_maps_miner_and_region_flags() {
        // Explicit custom + region.
        let cfg = SetupConfig::from(crate::SetupArgs {
            lane: "prl".into(),
            address: None,
            generate: false,
            prl_payout: None,
            yes: false,
            no_input: true,
            start: false,
            no_start: true,
            password: None,
            password_stdin: false,
            miner: Some("custom".into()),
            miner_bin: Some("/opt/my-srb".into()),
            miner_preset: Some("srbminer".into()),
            miner_arg_template: None,
            i_understand_unverified: true,
            region: Some("asia".into()),
        });
        assert_eq!(cfg.miner, MinerChoice::Custom);
        assert_eq!(cfg.miner_bin.as_deref(), Some("/opt/my-srb"));
        assert_eq!(cfg.miner_preset.as_deref(), Some("srbminer"));
        assert!(cfg.i_understand_unverified);
        assert_eq!(cfg.region.as_deref(), Some("asia"));

        // A bare --miner-bin (no --miner) implies custom.
        let cfg2 = SetupConfig::from(crate::SetupArgs {
            lane: "auto".into(),
            address: None,
            generate: false,
            prl_payout: None,
            yes: false,
            no_input: true,
            start: false,
            no_start: true,
            password: None,
            password_stdin: false,
            miner: None,
            miner_bin: Some("/opt/m".into()),
            miner_preset: None,
            miner_arg_template: None,
            i_understand_unverified: false,
            region: None,
        });
        assert_eq!(cfg2.miner, MinerChoice::Custom, "--miner-bin implies custom");

        // --miner companion.
        let cfg3 = SetupConfig::from(crate::SetupArgs {
            lane: "auto".into(),
            address: None,
            generate: false,
            prl_payout: None,
            yes: false,
            no_input: false,
            start: false,
            no_start: false,
            password: None,
            password_stdin: false,
            miner: Some("companion".into()),
            miner_bin: None,
            miner_preset: None,
            miner_arg_template: None,
            i_understand_unverified: false,
            region: None,
        });
        assert_eq!(cfg3.miner, MinerChoice::CompanionOnly);

        // No flag → Ask.
        assert_eq!(SetupConfig::first_launch().miner, MinerChoice::Ask);
    }

    /// The first-launch config is fully interactive (Ask everything), no flags.
    #[test]
    fn first_launch_config_asks_everything() {
        let cfg = SetupConfig::first_launch();
        assert_eq!(cfg.address, AddressMode::Ask);
        assert_eq!(cfg.start, StartChoice::Ask);
        assert!(!cfg.yes && !cfg.no_input);
        assert_eq!(cfg.lane, "auto");
    }

    /// A bad pasted address is rejected with a usage error and writes NOTHING.
    /// Drive it through an isolated identity dir so the real ~/.alice is untouched.
    #[test]
    fn paste_validation_rejects_garbage() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("alice-setup-paste-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let prev = std::env::var("ALICE_IDENTITY_DIR").ok();
        std::env::set_var("ALICE_IDENTITY_DIR", &dir);

        assert_eq!(validate_or_reject("not-an-alice-address"), Err(EXIT_USAGE));
        // A valid SS58 address from a different chain is also rejected (prefix gate).
        assert_eq!(
            validate_or_reject("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"),
            Err(EXIT_USAGE)
        );
        // Nothing was written.
        assert!(!alice_miner_core::identity::identity_path().is_file());

        match prev {
            Some(v) => std::env::set_var("ALICE_IDENTITY_DIR", v),
            None => std::env::remove_var("ALICE_IDENTITY_DIR"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The generate path REFUSES to clobber an existing identity (the keystore
    /// hazard): with a pointer already present, generate errors out and leaves it.
    #[test]
    fn generate_refuses_to_clobber_existing_identity() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("alice-setup-gen-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let prev = std::env::var("ALICE_IDENTITY_DIR").ok();
        std::env::set_var("ALICE_IDENTITY_DIR", &dir);

        // Plant a watch-only pointer (no keystore needed for the guard).
        let addr = "a2existingExistingExistingExisting";
        // We can't easily mint a real address here without crypto; write the pointer
        // JSON directly so load_pointer() returns Some (the guard only needs that).
        let pointer_json = format!(r#"{{"schema":1,"address":"{addr}","created":1}}"#);
        std::fs::write(alice_miner_core::identity::identity_path(), pointer_json).unwrap();
        assert!(alice_miner_core::identity::load_pointer().is_some());

        let cfg = SetupConfig::first_launch();
        let r = generate_identity_address(&cfg);
        assert_eq!(r, Err(EXIT_USAGE), "must refuse to clobber");
        // The original pointer is intact (unchanged).
        assert_eq!(alice_miner_core::identity::load_pointer().unwrap().address, addr);

        match prev {
            Some(v) => std::env::set_var("ALICE_IDENTITY_DIR", v),
            None => std::env::remove_var("ALICE_IDENTITY_DIR"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// NIT B: the generate path hands back the SAME passphrase it used to create the
    /// keystore, so the start handoff can unlock without a second prompt. The
    /// passphrase rides the function's return value (an in-process channel) — never
    /// argv — and is `Zeroizing` (scrubbed on drop).
    #[test]
    fn generate_returns_the_passphrase_for_the_start_handoff() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("alice-setup-genpw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let prev = std::env::var("ALICE_IDENTITY_DIR").ok();
        std::env::set_var("ALICE_IDENTITY_DIR", &dir);
        // Clean slate — no pre-existing identity (else the clobber guard fires).
        let _ = std::fs::remove_file(alice_miner_core::identity::identity_path());

        // Drive the passphrase in via the flag path (no interactive prompt in a test);
        // the wizard resolves it through the SAME shared resolver `start` would use.
        let known = "known-handoff-passphrase";
        let mut cfg = SetupConfig::first_launch();
        cfg.password = Some(known.to_string());

        let (address, passphrase) =
            generate_identity_address(&cfg).expect("generate succeeds on a clean slate");
        assert!(!address.is_empty(), "an address was produced");
        // The returned passphrase is exactly what start needs to unlock the new keystore
        // — proving the handoff carries the right secret (no second prompt).
        assert_eq!(passphrase.as_str(), known, "the created-keystore passphrase is returned");
        // And a keystore was actually written for it (the pointer names one).
        assert!(
            alice_miner_core::identity::load_pointer()
                .and_then(|p| p.keystore_path)
                .is_some(),
            "a signing keystore exists to unlock"
        );

        match prev {
            Some(v) => std::env::set_var("ALICE_IDENTITY_DIR", v),
            None => std::env::remove_var("ALICE_IDENTITY_DIR"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Serialize the identity-dir-env tests through the ONE crate-wide lock (shared
    /// with the `pidfile` tests, which also set `$ALICE_IDENTITY_DIR`).
    use crate::TEST_ENV_LOCK as ENV_LOCK;
}
