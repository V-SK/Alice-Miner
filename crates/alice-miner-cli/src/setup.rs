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
        SetupConfig {
            lane: a.lane,
            address,
            prl_payout: a.prl_payout,
            yes: a.yes,
            no_input: a.no_input,
            start,
            password: a.password,
            password_stdin: a.password_stdin,
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
    println!("Alice Miner setup");
    println!("─────────────────");

    // (1) Detect hardware + recommend a lane.
    let cap = CapabilityProfile::detect();
    println!("Device: {}", cap.profile.display);
    let lane = match crate::resolve_lane(&cfg.lane, &cap) {
        Ok(l) => l,
        Err(code) => return code,
    };
    println!(
        "Lane:   {} ({})",
        lane.label(),
        if cfg.lane.eq_ignore_ascii_case("auto") { "recommended" } else { "selected" }
    );
    // Honest viability gate (the same one `start` uses) — refuse early.
    if !cap.support(lane).is_runnable() {
        eprintln!(
            "error: the {} lane is {} on this device ({}). Try `alice-miner setup --lane {}`.",
            lane.label(),
            cap.support(lane).label(),
            cap.viability.reason(lane).unwrap_or("not viable"),
            cap.recommended_lane().id()
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
    println!("Address: {address}");

    // (3) Optional 15% PRL return address for a GPU lane.
    if let Err(code) = maybe_set_prl_payout(&cfg, lane) {
        return code;
    }

    // (4) Confirm.
    if !confirm(&cfg, lane, &address) {
        println!("Setup cancelled. Re-run `alice-miner setup` any time.");
        return EXIT_OK;
    }

    // (5) Start (or stop here) + (6) point at the live dashboard.
    match start_choice(&cfg) {
        StartChoice::No => {
            println!("\nSetup complete. Start mining when ready:");
            println!("  alice-miner start --lane {}", lane.cli_lane_arg());
            EXIT_OK
        }
        _ => {
            println!("\nStarting the miner — a live dashboard follows (Ctrl-C to stop).");
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
                from_service: false,
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
                    println!("Found an existing reward address: {}", p.address);
                    if !can_prompt(cfg) {
                        return Ok((p.address, None));
                    }
                    let ans = prompt_line("Use it? [Y/n] ").unwrap_or_default();
                    if ans.is_empty() || ans.eq_ignore_ascii_case("y") || ans.eq_ignore_ascii_case("yes") {
                        return Ok((p.address, None));
                    }
                }
            }
            if !can_prompt(cfg) {
                eprintln!(
                    "error: no reward address. Pass --address <alice-addr> or --generate \
                     (no interactive prompt available)."
                );
                return Err(EXIT_USAGE);
            }
            // Paste or generate?
            println!("Set your reward address:");
            println!("  1) paste an existing Alice address");
            println!("  2) generate a new identity (you'll back up a 24-word phrase)");
            let choice = prompt_line("Choose [1/2]: ").unwrap_or_default();
            if choice == "2" {
                generate_identity_address(cfg).map(|(a, pw)| (a, Some(pw)))
            } else {
                let pasted = prompt_line("Alice address: ").unwrap_or_default();
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
                    eprintln!("warning: could not save the address pointer ({e}); continuing.");
                    Ok(canonical)
                }
            }
        }
        None => {
            eprintln!("error: '{addr}' is not a valid Alice address (must be SS58 format-300).");
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
            "error: an identity already exists ({}). Generating a new one would replace your \
             reward identity. If that's what you want, run `alice-miner identity --create` \
             explicitly (it backs up the old keystore first); otherwise re-run setup with \
             --address <that-address> to keep mining to it.",
            p.address
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
            eprintln!("  ── BACK UP THIS RECOVERY PHRASE (24 words) ──");
            eprintln!("  {}", mnemonic.as_str());
            eprintln!("  ─────────────────────────────────────────────");
            Ok((identity.address, password))
        }
        Err(e) => {
            eprintln!("error: failed to create identity: {e}");
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
            "Note: this GPU lane earns the 15% PRL return. Set it later with \
             `alice-miner identity --set-prl-payout <prl1p…>`."
        );
        return Ok(());
    }
    println!("This GPU lane earns the 15% PRL return (optional).");
    let ans = prompt_line("Set your PRL return address now? paste prl1p… or leave blank to skip: ")
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
            println!("15% PRL return address saved: {masked}");
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
    println!("\nReady to mine:");
    println!("  lane:    {}", lane.label());
    println!("  address: {address}");
    if cfg.yes || !can_prompt(cfg) {
        return true;
    }
    let ans = prompt_line("Start now? [Y/n] ").unwrap_or_default();
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
        });
        assert_eq!(cfg.address, AddressMode::Ask);
        assert_eq!(start_choice(&cfg), StartChoice::Yes);
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
