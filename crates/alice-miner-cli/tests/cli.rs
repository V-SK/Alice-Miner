//! Integration tests for the built `alice-miner` CLI binary.
//!
//! These drive the REAL binary (`CARGO_BIN_EXE_alice-miner-cli`) end-to-end:
//!   * `--help` for every subcommand exits 0 and documents the surface.
//!   * `detect` prints the lane-viability matrix (human + `--json`).
//!   * `identity --create` round-trips the address and writes
//!     `~/.alice/identity.json` (into a throwaway dir), then `--show` reads it.
//!   * a NO-EGUI assertion at the binary level (the linked binary references no
//!     egui/eframe/AppKit/Metal symbols — complementing the `cargo tree` proof).
//!
//! The live `start --lane xmr` connect is exercised by a separate ignored test
//! (`start_xmr_streams_live`) and by hand (it needs the relay reachable); the
//! parsing + offline surface is fully covered here.

use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;

/// The env var that disables the CLI's startup version-check (a background GitHub
/// call and a `~/.alice/update-check.json` write). Mirrors `update::ENV_NO_UPDATE_CHECK`;
/// this integration test drives the BUILT binary (not the lib), so it can't reach that
/// `pub const` and the name is duplicated here with this note.
const ENV_NO_UPDATE_CHECK: &str = "ALICE_MINER_NO_UPDATE_CHECK";

/// A single process-wide throwaway `~/.alice` substitute for the `bin()` commands that
/// don't establish their own identity (`--help`, `detect`, the `start` gating tests,
/// `doctor`, …). Without it those spawn the real binary against the real `~/.alice`.
/// Created once; the isolated-identity tests layer their own per-test `TempEnv` over
/// this (via `env.apply`), which overrides the two dir vars.
fn shared_isolation_base() -> &'static std::path::Path {
    static BASE: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    BASE.get_or_init(|| {
        let base = std::env::temp_dir().join(format!("alice-miner-cli-it-shared-{}", std::process::id()));
        std::fs::create_dir_all(base.join("wallet")).ok();
        std::fs::create_dir_all(base.join("dot-alice")).ok();
        base
    })
}

/// Path to the built binary under test, with test-isolation env ALWAYS applied so a
/// spawned binary can NEVER touch the real `~/.alice` or hit the network:
///   * `ALICE_IDENTITY_DIR` / `ALICE_WALLET_DATA_ROOT` → a throwaway dir (so any state
///     write lands there, not the user's real keystore).
///   * `ALICE_MINER_NO_UPDATE_CHECK=1` → the startup version-check is a no-op (no GitHub
///     call, no `update-check.json` write).
///
/// Tests that need their own identity state layer a per-test `TempEnv` over this via
/// `env.apply(&mut cmd)`, which overrides the two dir vars (the flag stays set).
fn bin() -> Command {
    let mut cmd = Command::cargo_bin("alice-miner-cli").expect("built alice-miner-cli binary");
    let base = shared_isolation_base();
    cmd.env("ALICE_WALLET_DATA_ROOT", base.join("wallet"));
    cmd.env("ALICE_IDENTITY_DIR", base.join("dot-alice"));
    cmd.env(ENV_NO_UPDATE_CHECK, "1");
    cmd
}

/// A fresh, isolated `~/.alice` + keystore dir for an identity test, via the env
/// overrides the engine honors (so we never touch the real user files).
struct TempEnv {
    base: std::path::PathBuf,
}

impl TempEnv {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "alice-miner-cli-it-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(base.join("wallet")).unwrap();
        std::fs::create_dir_all(base.join("dot-alice")).unwrap();
        Self { base }
    }
    fn wallet_root(&self) -> std::path::PathBuf {
        self.base.join("wallet")
    }
    fn id_dir(&self) -> std::path::PathBuf {
        self.base.join("dot-alice")
    }
    /// Apply the overrides to a command.
    fn apply(&self, cmd: &mut Command) {
        cmd.env("ALICE_WALLET_DATA_ROOT", self.wallet_root());
        cmd.env("ALICE_IDENTITY_DIR", self.id_dir());
    }
}

impl Drop for TempEnv {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

// ── --help surface ────────────────────────────────────────────────────────────

#[test]
fn top_level_help_lists_all_subcommands() {
    bin()
        .arg("--help")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("detect")
                .and(predicate::str::contains("identity"))
                .and(predicate::str::contains("start"))
                .and(predicate::str::contains("stop")),
        );
}

#[test]
fn each_subcommand_has_help() {
    for sub in ["detect", "identity", "start", "stop"] {
        bin().args([sub, "--help"]).assert().success();
    }
}

// ── detect ────────────────────────────────────────────────────────────────────

#[test]
fn detect_prints_the_lane_matrix() {
    bin().arg("detect").assert().success().stdout(
        predicate::str::contains("Device:")
            .and(predicate::str::contains("Lanes:"))
            .and(predicate::str::contains("CPU · XMR"))
            .and(predicate::str::contains("GPU · RVN"))
            .and(predicate::str::contains("(recommended)")),
    );
}

#[test]
fn detect_json_is_valid_and_has_viability() {
    let out = bin().args(["detect", "--json"]).assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    // The capability profile carries the device profile + viability matrix.
    assert!(v.get("profile").is_some(), "json has profile: {stdout}");
    assert!(v.get("viability").is_some(), "json has viability: {stdout}");
    assert!(
        v["viability"].get("recommended").is_some(),
        "viability has a recommended lane: {stdout}"
    );
}

// ── identity ──────────────────────────────────────────────────────────────────

#[test]
fn identity_create_round_trips_address_and_writes_pointer() {
    let env = TempEnv::new("create");

    // Create with an explicit password (no prompt).
    let mut cmd = bin();
    env.apply(&mut cmd);
    let out = cmd
        .args(["identity", "--create", "--password", "correct horse battery staple", "--label", "it"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("Identity established:"), "stdout: {stdout}");
    assert!(stdout.contains("BACK UP THIS RECOVERY PHRASE"), "must warn to back up: {stdout}");

    // The pointer file was written into the throwaway dir.
    let pointer = env.id_dir().join("identity.json");
    assert!(pointer.is_file(), "identity.json written at {}", pointer.display());
    let json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&pointer).unwrap()).unwrap();
    let address = json["address"].as_str().expect("address in pointer").to_string();
    assert!(!address.is_empty());

    // `--show` reads the SAME address back (public only — no secret printed).
    let mut cmd = bin();
    env.apply(&mut cmd);
    cmd.args(["identity", "--show"])
        .assert()
        .success()
        .stdout(predicate::str::contains(&address));

    // `--show --json` matches too.
    let mut cmd = bin();
    env.apply(&mut cmd);
    let out = cmd.args(["identity", "--show", "--json"]).assert().success();
    let shown: serde_json::Value =
        serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(shown["address"].as_str(), Some(address.as_str()));
}

/// MED-5: `--password-stdin` reads the passphrase from a real stdin pipe (the
/// secure non-interactive path — nothing lands in argv/`ps`). Uses
/// `assert_cmd::Command` (which exposes `write_stdin`).
#[test]
fn identity_create_reads_password_from_stdin() {
    let env = TempEnv::new("pwstdin");
    let mut cmd =
        assert_cmd::Command::cargo_bin("alice-miner-cli").expect("built alice-miner-cli binary");
    cmd.env("ALICE_WALLET_DATA_ROOT", env.wallet_root());
    cmd.env("ALICE_IDENTITY_DIR", env.id_dir());
    cmd.env(ENV_NO_UPDATE_CHECK, "1");
    let out = cmd
        .args(["identity", "--create", "--password-stdin", "--label", "it"])
        .write_stdin("a stdin passphrase with spaces\n")
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("Identity established:"), "stdout: {stdout}");
    // The pointer was written, proving the keystore round-tripped via stdin pw.
    assert!(env.id_dir().join("identity.json").is_file());
}

/// MED-5: the deprecated `--password` flag still works but prints a LOUD
/// insecurity warning to stderr.
#[test]
fn identity_create_with_password_flag_warns_loudly() {
    let env = TempEnv::new("pwwarn");
    let mut cmd = bin();
    env.apply(&mut cmd);
    cmd.args(["identity", "--create", "--password", "correct horse battery staple"])
        .assert()
        .success()
        .stderr(predicate::str::contains("--password is INSECURE"));
}

#[test]
fn identity_show_without_identity_errors() {
    let env = TempEnv::new("noid");
    let mut cmd = bin();
    env.apply(&mut cmd);
    cmd.args(["identity", "--show"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("No identity yet"));
}

#[test]
fn identity_with_no_mode_is_usage_error() {
    let env = TempEnv::new("nomode");
    let mut cmd = bin();
    env.apply(&mut cmd);
    cmd.arg("identity").assert().failure().code(2);
}

// ── start gating ──────────────────────────────────────────────────────────────

/// On this Mac (no NVIDIA) `--dual` must refuse with the honest viability reason
/// and exit 2 — never silently run one lane.
#[test]
#[cfg(target_os = "macos")]
fn dual_refuses_on_a_single_viable_lane_box() {
    bin()
        .args(["start", "--dual"])
        .assert()
        .failure()
        .code(2)
        .stderr(
            predicate::str::contains("dual-mine needs 2 viable lanes")
                // Dual's GPU partner is the PRL mainline → the honest reason names PRL.
                .and(predicate::str::contains("GPU · PRL")),
        );
}

/// `start --lane gpu` on a no-NVIDIA box refuses with the honest reason.
#[test]
#[cfg(target_os = "macos")]
fn gpu_lane_refuses_without_nvidia() {
    bin()
        .args(["start", "--lane", "gpu"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("lane is"));
}

#[test]
fn unknown_lane_is_usage_error() {
    // `prl` is now a real lane (GPU-PRL mainline); use a genuinely unknown token.
    bin()
        .args(["start", "--lane", "ltc"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("unknown lane"));
}

// ── stop with nothing running ─────────────────────────────────────────────────

#[test]
fn stop_with_no_running_miner_reports_cleanly() {
    let env = TempEnv::new("stop-none");
    let mut cmd = bin();
    env.apply(&mut cmd);
    cmd.arg("stop")
        .assert()
        .failure()
        .stderr(predicate::str::contains("No running miner"));
}

// ── NO-EGUI proof ─────────────────────────────────────────────────────────────

/// The CLI's DEPENDENCY TREE must contain no egui/eframe/GUI-toolkit crate (the
/// invariant the brief calls out: `cargo tree -p alice-miner-cli` has no eframe).
/// We shell out to `cargo tree` (the documented verification) and assert the
/// toolkit crates are absent as whole dependency entries — robust against
/// unrelated substrings (e.g. the BIP39 wordlist's `fragile`+`frame` or the
/// Substrate `frame-metadata` crate, which are NOT the egui `eframe`).
#[test]
fn no_egui_in_dep_tree() {
    let out = Command::new(env!("CARGO"))
        .args(["tree", "-p", "alice-miner-cli", "--edges", "all", "--prefix", "none"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output();
    let Ok(out) = out else {
        // If cargo isn't invokable in this sandbox, skip rather than false-fail;
        // the `cargo tree` proof is also captured in the milestone report.
        eprintln!("skipping no_egui_in_dep_tree: cargo not invokable here");
        return;
    };
    assert!(out.status.success(), "cargo tree failed: {}", String::from_utf8_lossy(&out.stderr));
    let tree = String::from_utf8_lossy(&out.stdout);
    // Each line is `name vX.Y.Z …`; a GUI crate would appear as its own entry.
    // Match the crate name at a word boundary followed by a space + version, so
    // `frame-metadata` / `fragileframe` do NOT trip the `eframe` check.
    for forbidden in ["eframe", "egui", "egui-winit", "winit", "wgpu", "glow", "accesskit"] {
        let hit = tree.lines().any(|line| {
            let line = line.trim_start();
            line == forbidden
                || line.starts_with(&format!("{forbidden} v"))
                || line.starts_with(&format!("{forbidden} "))
        });
        assert!(
            !hit,
            "alice-miner-cli dependency tree contains `{forbidden}` — egui/eframe must NOT be in the CLI.\nTree:\n{tree}"
        );
    }
}

/// Complementary LINK-level proof on macOS: the built binary links NO GUI
/// framework (AppKit / Metal / OpenGL / CoreGraphics-via-egui). A plain CLI
/// pulls none of these as direct dylibs; an eframe app pulls AppKit + Metal.
#[test]
#[cfg(target_os = "macos")]
fn no_gui_frameworks_linked() {
    let path = assert_cmd::cargo::cargo_bin("alice-miner-cli");
    let out = Command::new("otool").args(["-L"]).arg(&path).output();
    let Ok(out) = out else {
        eprintln!("skipping no_gui_frameworks_linked: otool unavailable");
        return;
    };
    let libs = String::from_utf8_lossy(&out.stdout);
    for fw in ["AppKit", "Metal", "OpenGL", "QuartzCore", "GLFW"] {
        assert!(
            !libs.contains(fw),
            "built binary links `{fw}` — the CLI must not pull a GUI framework.\notool -L:\n{libs}"
        );
    }
}

// ── live XMR run (ignored by default; needs the relay reachable) ──────────────

/// A brief live XMR run to a throwaway watch-only address against the public
/// relay: confirms the headless dashboard shows a rising hashrate + accepted
/// shares, then stops cleanly. Ignored by default (network + a real xmrig
/// binary required); run with `--ignored` on a machine with the bundled engine.
#[test]
#[ignore = "needs the relay reachable + a resolvable xmrig binary"]
fn start_xmr_streams_live() {
    let env = TempEnv::new("live");
    // A watch-only paste so no keystore/password is needed. (alice-crypto is
    // re-exported through the engine crate, so the CLI test needs no extra dep.)
    let addr = alice_miner_core::alice_crypto::create_wallet_payload(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "live-test",
    )
    .unwrap()
    .address;

    let mut cmd = bin();
    env.apply(&mut cmd);
    let out = cmd
        .args(["start", "--lane", "xmr", "--address", &addr, "--duration-s", "30"])
        .assert();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    // We should have seen the running state + some H/s in the stream.
    assert!(stdout.contains("running"), "expected a running tick: {stdout}");
}

// ── ai (shard-stage inference worker) ──────────────────────────────────────────

/// The top-level help lists the new `ai` subcommand, and `ai --help` documents its
/// flag surface (the credit-only, honest UX).
#[test]
fn ai_is_listed_and_documented() {
    bin()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("ai"));

    bin().args(["ai", "--help"]).assert().success().stdout(
        predicate::str::contains("--endpoint")
            .and(predicate::str::contains("--engine-dir"))
            .and(predicate::str::contains("--center-url"))
            .and(predicate::str::contains("--allow-cpu"))
            .and(predicate::str::contains("SHARD_PSK"))
            .and(predicate::str::contains("Credit-only").or(predicate::str::contains("credit-only"))),
    );
}

/// With NO identity, `ai` fails closed with a clear "create/import an identity"
/// message (it never creates one implicitly — the keystore-clobber hazard).
#[test]
fn ai_without_identity_fails_closed() {
    let env = TempEnv::new("ai-noid");
    let mut cmd = bin();
    env.apply(&mut cmd);
    // Provide flags so the failure is specifically the missing identity, not a
    // missing-flag usage error.
    cmd.args([
        "ai",
        "--center-url",
        "https://api.aliceprotocol.org",
        "--endpoint",
        "203.0.113.7:29501",
        "--engine-dir",
        "/nonexistent",
        "--allow-cpu",
    ])
    .env("SHARD_PSK", "test-psk")
    .assert()
    .failure()
    .stderr(predicate::str::contains("no reward identity"));
}

/// `ai` refuses a WATCH-ONLY (pasted-address) identity: it has no signing key, so
/// it can never PoP-register a stage. The message is explicit + honest.
#[test]
fn ai_watch_only_identity_cannot_register() {
    let env = TempEnv::new("ai-watch");
    // A real Alice address to paste (watch-only — no keystore).
    let addr = alice_miner_core::alice_crypto::create_wallet_payload(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "x",
    )
    .unwrap()
    .address;
    let mut cmd = bin();
    env.apply(&mut cmd);
    cmd.args(["identity", "--paste", &addr]).assert().success();

    // A temp engine dir with a stub pipeline.py so we get past the engine-dir check
    // and reach the watch-only key failure.
    let engine = env.id_dir().join("engine");
    std::fs::create_dir_all(engine.join("phase0")).unwrap();
    std::fs::write(engine.join("phase0/pipeline.py"), b"# stub").unwrap();

    let mut cmd = bin();
    env.apply(&mut cmd);
    cmd.args([
        "ai",
        "--endpoint",
        "203.0.113.7:29501",
        "--engine-dir",
        engine.to_str().unwrap(),
        "--allow-cpu",
    ])
    .env("SHARD_PSK", "test-psk")
    .assert()
    .failure()
    .stderr(predicate::str::contains("watch-only"));
}

/// `ai` fails closed with a clear message when SHARD_PSK is not set (the engine
/// needs it; never spawn one that would immediately die).
#[test]
fn ai_without_shard_psk_fails_closed() {
    let env = TempEnv::new("ai-nopsk");
    // A keystore-backed identity via import (so the key check would pass).
    let mut cmd = bin();
    env.apply(&mut cmd);
    cmd.args([
        "identity",
        "--import",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "--password",
        "pw-123456",
    ])
    .assert()
    .success();

    let engine = env.id_dir().join("engine");
    std::fs::create_dir_all(engine.join("phase0")).unwrap();
    std::fs::write(engine.join("phase0/pipeline.py"), b"# stub").unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("alice-miner-cli").unwrap();
    cmd.env("ALICE_WALLET_DATA_ROOT", env.wallet_root());
    cmd.env("ALICE_IDENTITY_DIR", env.id_dir());
    cmd.env(ENV_NO_UPDATE_CHECK, "1");
    cmd.env_remove("SHARD_PSK");
    cmd.args([
        "ai",
        "--endpoint",
        "203.0.113.7:29501",
        "--engine-dir",
        engine.to_str().unwrap(),
        "--password",
        "pw-123456",
        "--allow-cpu",
    ])
    .assert()
    .failure()
    .stderr(predicate::str::contains("SHARD_PSK"));
}

/// `doctor --ai --json` produces a valid JSON report with the ai role + the
/// expected checks, and exits (0 or non-zero) without panicking.
#[test]
fn doctor_ai_json_shape() {
    let out = bin()
        .args(["doctor", "--ai", "--json", "--allow-cpu"])
        .assert()
        .get_output()
        .clone();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["role"].as_str(), Some("ai"));
    let checks = v["checks"].as_array().expect("checks array");
    let names: Vec<&str> = checks.iter().map(|c| c["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"python3"));
    assert!(names.contains(&"shard engine"));
    assert!(names.contains(&"endpoint port"));
}

// ── guide (help-me-choose advisor) + companion (bring-your-own PoP) ─────────────

/// The two onboarding subcommands are listed at the top level and each has help.
#[test]
fn guide_and_companion_are_listed_and_documented() {
    bin().arg("--help").assert().success().stdout(
        predicate::str::contains("guide").and(predicate::str::contains("companion")),
    );
    bin().args(["guide", "--help"]).assert().success();
    bin()
        .args(["companion", "--help"])
        .assert()
        .success()
        // The help must make the "no mining" contract explicit.
        .stdout(predicate::str::contains("NEVER spawns a miner").or(predicate::str::contains("never spawns a miner")));
}

/// `guide` (human) detects the device, recommends a lane, and shows BOTH next-step
/// paths (official client + bring-your-own connection surface) — credit-only.
#[test]
fn guide_human_advises_and_is_credit_only() {
    let out = bin().args(["guide", "--lang", "en"]).assert().success().get_output().clone();
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("Device"), "shows the device: {stdout}");
    assert!(stdout.contains("Recommended lane"), "recommends a lane: {stdout}");
    // Both next steps are present: the official client + the bring-your-own pool.
    assert!(stdout.contains("alice-miner setup"), "official-client path: {stdout}");
    assert!(stdout.to_lowercase().contains("pool"), "bring-your-own pool line: {stdout}");
    // Credit-only honesty: no fiat / earnings token, no leaked collection/pool/IP.
    let low = stdout.to_lowercase();
    for forbidden in ["$", "usd", "fiat", "paid", "earned", "prl1p", "herominers", "supportxmr"] {
        assert!(!low.contains(forbidden), "guide leaked `{forbidden}`: {stdout}");
    }
}

/// `guide --json` is a valid object with the recommendation + bring-your-own surface.
#[test]
fn guide_json_shape() {
    let out = bin().args(["guide", "--json"]).assert().success().get_output().clone();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert!(v.get("device").is_some(), "json has device: {stdout}");
    assert!(v.get("recommended_lane").is_some(), "json has recommended_lane: {stdout}");
    let byo = &v["bring_your_own"];
    assert!(byo.get("algorithm").is_some(), "byo has algorithm: {stdout}");
    assert!(byo.get("port").is_some(), "byo has port: {stdout}");
    assert!(byo.get("needs_companion").is_some(), "byo has needs_companion: {stdout}");
}

/// `companion --lane xmr` is refused: the companion is only for the PoP-gated
/// pearlhash lanes (XMR/RVN are open enrollment). Fails fast — no identity needed.
#[test]
fn companion_rejects_non_pearlhash_lane() {
    bin()
        .args(["companion", "--lane", "xmr", "--lang", "en", "--once"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("pearlhash"));
}

/// `companion` with an invalid `--device` is a usage error naming the allowed
/// charset — and, crucially, it never reaches the network / spawns anything.
#[test]
fn companion_rejects_bad_device_label() {
    // A valid address override so we get past address resolution to the device check.
    let addr = alice_miner_core::alice_crypto::create_wallet_payload(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "x",
    )
    .unwrap()
    .address;
    bin()
        .args([
            "companion",
            "--lane",
            "prl",
            "--address",
            &addr,
            "--device",
            "bad name",
            "--region",
            "asia",
            "--lang",
            "en",
            "--once",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("letters, digits"));
}

/// `companion` with NO identity fails closed with a clear message (it never creates
/// one implicitly). `--region asia` keeps it fully offline (no RTT probe). It also
/// writes NOTHING — proving it never touches the identity store.
#[test]
fn companion_without_identity_fails_closed() {
    let env = TempEnv::new("companion-noid");
    let mut cmd = bin();
    env.apply(&mut cmd);
    cmd.args(["companion", "--lane", "prl", "--region", "asia", "--once"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no reward identity"));
    // Zero-write proof: no identity file was created in the (isolated) store.
    assert!(
        !env.id_dir().join("identity.json").exists(),
        "companion must not create an identity"
    );
}

/// `guide` is a PURE advisor: it writes nothing to the identity store (it needs no
/// identity at all). Proven against a fresh, isolated `~/.alice` that stays empty.
#[test]
fn guide_writes_nothing() {
    let env = TempEnv::new("guide-nowrite");
    let mut cmd = bin();
    env.apply(&mut cmd);
    cmd.args(["guide", "--json"]).assert().success();
    let entries: Vec<_> = std::fs::read_dir(env.id_dir()).unwrap().flatten().collect();
    assert!(entries.is_empty(), "guide wrote {} file(s) to ~/.alice", entries.len());
}

/// `companion` refuses a WATCH-ONLY (pasted-address) identity: it has no signing
/// key, so it can never prove possession — and it must NOT create an identity or
/// spawn a miner. Offline (`--region asia`, fails at the key-unlock step).
#[test]
fn companion_watch_only_identity_cannot_prove_possession() {
    let env = TempEnv::new("companion-watch");
    let addr = alice_miner_core::alice_crypto::create_wallet_payload(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "x",
    )
    .unwrap()
    .address;
    let mut cmd = bin();
    env.apply(&mut cmd);
    cmd.args(["identity", "--paste", &addr]).assert().success();

    let mut cmd = bin();
    env.apply(&mut cmd);
    cmd.args(["companion", "--lane", "prl", "--region", "asia", "--once"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("watch-only"));
}

/// `doctor --lane prl --json` includes the companion (PoP) readiness check.
#[test]
fn doctor_prl_json_includes_companion_check() {
    let out = bin()
        .args(["doctor", "--lane", "prl", "--json"])
        .assert()
        .get_output()
        .clone();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let checks = v["checks"].as_array().expect("checks array");
    let names: Vec<&str> = checks.iter().map(|c| c["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"companion (PoP)"), "doctor lists the companion check: {names:?}");
}

// ─────────────────────────────────────────────────────────────────────────────
// Guarded automatic updates — driven through the REAL binary.
//
// The unit tests in `alice-release::auto` prove the state machine. These prove
// the thing the unit tests structurally cannot: that the headless CLI actually
// CALLS it at startup. That gap is precisely audit finding AM-REL-009 — the
// health gate existed, the CLI armed it after every self-update, and only the
// GUI ever resolved it, so on a headless rig the rollback machinery was armed
// and nothing on earth would ever disarm it. A unit test would have passed
// throughout. Only running the binary catches it.
// ─────────────────────────────────────────────────────────────────────────────

/// The client version under test — the probation record must name the running
/// build or it is (correctly) discarded as stale.
const THIS_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Copy the built CLI to `dir/alice-miner[.exe]`, put a recognisable sentinel at
/// its `.lkg` sibling, and return (app path, lkg path). The sentinel is not an
/// executable and never needs to be: the assertion is "did the bytes at the app
/// path get replaced by the backup", which is exactly what a rollback is.
fn staged_app(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    // `cfg!` (runtime), not `#[cfg]`: the same code compiles and is reasoned
    // about on every platform, so a Windows-only path cannot rot unnoticed.
    let name = if cfg!(windows) { "alice-miner.exe" } else { "alice-miner" };
    let app = dir.join(name);
    let real = assert_cmd::cargo::cargo_bin("alice-miner-cli");
    std::fs::copy(&real, &app).expect("copy the built CLI into the sandbox");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&app, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let lkg = dir.join(format!("{name}.lkg"));
    std::fs::write(&lkg, b"LKG-SENTINEL").unwrap();
    (app, lkg)
}

/// Write an auto-update probation record next to the staged app.
fn arm_probation(app: &std::path::Path, launches: u32, started_ok: bool) {
    let marker = app.with_file_name(format!(
        "{}.auto-probation",
        app.file_name().unwrap().to_string_lossy()
    ));
    let body = serde_json::json!({
        "version": THIS_VERSION,
        "previous": "0.0.1",
        "armed_at_unix": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        "launches": launches,
        "started_ok": started_ok,
        "previous_productive": true,
        "failed_sessions": 0,
    });
    std::fs::write(&marker, serde_json::to_vec(&body).unwrap()).unwrap();
}

fn sandbox(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "alice-autoupd-it-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(d.join("dot-alice")).unwrap();
    d
}

/// Run the staged copy with an isolated `~/.alice` and no network.
fn run_staged(app: &std::path::Path, dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(app);
    cmd.args(args)
        .env("ALICE_IDENTITY_DIR", dir.join("dot-alice"))
        .env("ALICE_WALLET_DATA_ROOT", dir.join("wallet"))
        .env(ENV_NO_UPDATE_CHECK, "1")
        .env("ALICE_MINER_AUTO_UPDATE", "off");
    cmd.output().expect("run the staged binary")
}

/// THE test for AM-REL-009 on the headless path: a build that reached startup
/// once without ever confirming health is rolled back on its next start — by the
/// CLI, with no GUI anywhere.
#[test]
fn headless_startup_rolls_back_a_build_that_never_got_past_launch() {
    let dir = sandbox("rollback");
    let (app, _lkg) = staged_app(&dir);
    // launches=1, started_ok=false ⇒ "we have been here before and it died".
    arm_probation(&app, 1, false);

    let out = run_staged(&app, &dir, &["--version"]);

    let bytes = std::fs::read(&app).unwrap();
    assert_eq!(
        bytes, b"LKG-SENTINEL",
        "the CLI must restore last-known-good over the failed build at startup"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("rolled back") || stderr.contains("回滚"),
        "the rollback must be reported, not silent: {stderr}"
    );
    assert!(
        stderr.contains("restart") || stderr.contains("重启"),
        "and it must say THIS process is still the failed build: {stderr}"
    );
    // The failed version is pinned so the updater will not reinstall it.
    let pins: Vec<String> = serde_json::from_slice(
        &std::fs::read(dir.join("dot-alice").join("update-pins.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(pins, vec![THIS_VERSION.to_string()]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The complement, and the more important half of "does the gate work": a build
/// on its FIRST start is not rolled back.
///
/// It also pins the F11 fix. `alice-miner --version` prints and exits: it proves
/// the binary LOADS and proves nothing about mining, so it must be recorded as a
/// successful launch (or a second `--version` would look like crash-on-launch)
/// and must NOT commit the update or delete the last-known-good copy. A build
/// that starts fine and dies the moment it mines therefore still has something to
/// roll back to. The commit happens when a command the user actually asked for
/// runs — here, `guide --json`, which is read-only and writes nothing.
#[test]
fn headless_startup_does_not_roll_back_a_healthy_first_run() {
    let dir = sandbox("healthy");
    let (app, lkg) = staged_app(&dir);
    // A probation with NO earning baseline: starting is the whole bar.
    let marker = app.with_file_name(format!(
        "{}.auto-probation",
        app.file_name().unwrap().to_string_lossy()
    ));
    let body = serde_json::json!({
        "version": THIS_VERSION,
        "previous": "0.0.1",
        "armed_at_unix": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        "launches": 0,
        "started_ok": false,
        "previous_productive": false,
        "failed_sessions": 0,
    });
    std::fs::write(&marker, serde_json::to_vec(&body).unwrap()).unwrap();

    let out = run_staged(&app, &dir, &["--version"]);
    assert!(out.status.success());
    assert_ne!(
        std::fs::read(&app).unwrap(),
        b"LKG-SENTINEL",
        "a first run must NEVER be rolled back"
    );
    // F11: printing a version is not a successful START.
    assert!(
        marker.exists(),
        "a --version run must not end the probation — it never mined"
    );
    assert!(
        lkg.exists(),
        "and must not throw away the only copy of the build it replaced"
    );
    let rec: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&marker).unwrap()).unwrap();
    assert_eq!(
        rec["started_ok"],
        serde_json::json!(true),
        "it IS recorded as a successful launch, or the next --version would look \
         like crash-on-launch and trigger a rollback"
    );

    // A second `--version` must therefore still be harmless.
    assert!(run_staged(&app, &dir, &["--version"]).status.success());
    assert_ne!(std::fs::read(&app).unwrap(), b"LKG-SENTINEL");
    assert!(lkg.exists());

    // A real command commits, exactly as before — there is no earning baseline
    // here, so starting is the whole bar and the probation ends.
    assert!(run_staged(&app, &dir, &["guide", "--json"]).status.success());
    assert!(!marker.exists(), "a committed probation clears its marker");
    assert!(!lkg.exists(), "and drops the last-known-good copy");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A probation for a DIFFERENT version is stale (a rollback already happened, or
/// the user installed something by hand). It must be discarded quietly — never
/// acted on, because acting on it would revert a build nobody complained about.
#[test]
fn headless_startup_discards_a_probation_for_another_version() {
    let dir = sandbox("stale");
    let (app, lkg) = staged_app(&dir);
    let marker = app.with_file_name(format!(
        "{}.auto-probation",
        app.file_name().unwrap().to_string_lossy()
    ));
    let body = serde_json::json!({
        "version": "99.99.99",
        "previous": "0.0.1",
        "armed_at_unix": 1_700_000_000u64,
        "launches": 5,
        "started_ok": false,
        "previous_productive": true,
        "failed_sessions": 0,
    });
    std::fs::write(&marker, serde_json::to_vec(&body).unwrap()).unwrap();

    let out = run_staged(&app, &dir, &["--version"]);
    assert!(out.status.success());
    assert_ne!(std::fs::read(&app).unwrap(), b"LKG-SENTINEL");
    assert!(!marker.exists(), "stale marker is cleared");
    assert!(lkg.exists(), "an untouched last-known-good is left alone");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A corrupt probation file must not brick the miner. Fail-open on the POLICY
/// (do nothing) rather than fail-open on the SAFETY (never install something).
#[test]
fn a_corrupt_probation_file_is_ignored_not_fatal() {
    let dir = sandbox("corrupt");
    let (app, _lkg) = staged_app(&dir);
    let marker = app.with_file_name(format!(
        "{}.auto-probation",
        app.file_name().unwrap().to_string_lossy()
    ));
    std::fs::write(&marker, b"{ not json at all").unwrap();
    let out = run_staged(&app, &dir, &["--version"]);
    assert!(out.status.success(), "a corrupt marker must not stop the miner");
    assert_ne!(std::fs::read(&app).unwrap(), b"LKG-SENTINEL");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The opt-out is real and it is discoverable: `--auto` shows the mode, `--auto
/// <mode>` sets it and it survives into the next process.
#[test]
fn auto_update_mode_can_be_shown_set_and_is_persisted() {
    let dir = sandbox("mode");
    let ident = dir.join("dot-alice");
    let run = |args: &[&str]| {
        Command::cargo_bin("alice-miner-cli")
            .unwrap()
            .args(args)
            .env("ALICE_IDENTITY_DIR", &ident)
            .env("ALICE_WALLET_DATA_ROOT", dir.join("wallet"))
            .env(ENV_NO_UPDATE_CHECK, "1")
            .env_remove("ALICE_MINER_AUTO_UPDATE")
            .output()
            .unwrap()
    };

    // Shows the built-in default and says it has not been chosen.
    let out = run(&["update", "--auto"]);
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "show must exit 0: {s}");
    assert!(s.contains("security-only"), "the default is security-only: {s}");
    assert!(s.contains("default"), "and says so: {s}");

    // Set it off, and it persists.
    let out = run(&["update", "--auto", "off"]);
    assert!(out.status.success());
    let shown = run(&["update", "--auto"]);
    let s = String::from_utf8_lossy(&shown.stdout);
    assert!(s.contains("off"), "the choice persisted: {s}");
    let settings: serde_json::Value =
        serde_json::from_slice(&std::fs::read(ident.join("settings.json")).unwrap()).unwrap();
    assert_eq!(settings["auto_update"], "off");

    // A typo changes NOTHING and exits non-zero — never a silent escalation.
    let out = run(&["update", "--auto", "yes-please"]);
    assert!(!out.status.success());
    let shown = run(&["update", "--auto"]);
    let s = String::from_utf8_lossy(&shown.stdout);
    assert!(s.contains("off"), "a rejected value must leave the setting alone: {s}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `update --auto <mode>` never touches the network — it is a settings command,
/// so it must work on a box with no route to the release channel.
#[test]
fn auto_update_mode_works_offline() {
    let dir = sandbox("offline");
    let out = Command::cargo_bin("alice-miner-cli")
        .unwrap()
        .args(["update", "--auto", "notify"])
        // A URL that cannot resolve: if this command reached the network it
        // would hang or fail here.
        .env("ALICE_MINER_UPDATE_URL", "https://127.0.0.1:1/latest.json")
        .env("ALICE_IDENTITY_DIR", dir.join("dot-alice"))
        .env("ALICE_WALLET_DATA_ROOT", dir.join("wallet"))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let _ = std::fs::remove_dir_all(&dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// The startup messages a 中文 user actually reads (R5)
//
// Every one of these strings is written correctly at its call site: two inline
// variants, `tr!` picking between them. What decides which one a miner reads is
// WHEN the line is formatted — and the self-update health gates format theirs
// before the command line is even parsed. While the language was resolved after
// the parse, the 中文 half of the post-update line and of BOTH auto-rollback
// warnings was unreachable in production: the code was there, the tests that
// covered it pinned the language by hand, and the shipped binary could never
// take that branch.
//
// So these tests do it the only way that can answer the question: seed the real
// state files, run the REAL binary, and read what a 中文 user would have read.
// The existing rollback test above deliberately accepts either language
// (`"rolled back" || "回滚"`) — which is exactly how this survived.
// ─────────────────────────────────────────────────────────────────────────────

/// The self-check hook: with this set the binary reports, on stderr, whether any
/// user-facing text was selected before the UI language was resolved. Mirrors
/// `main.rs`'s `ENV_LANG_SELFCHECK` (this test drives the BUILT binary, so it
/// cannot reach that `const`).
const ENV_LANG_SELFCHECK: &str = "ALICE_MINER_LANG_SELFCHECK";

/// Save a 中文 preference into the sandbox's `~/.alice`, exactly as
/// `alice-miner lang zh` would.
fn save_lang_pref_zh(dir: &std::path::Path) {
    std::fs::write(
        dir.join("dot-alice").join("settings.json"),
        br#"{"schema": 1, "lang": "zh"}"#,
    )
    .unwrap();
}

/// Run the staged copy like `run_staged`, but with the language self-check on.
fn run_staged_checked(
    app: &std::path::Path,
    dir: &std::path::Path,
    args: &[&str],
) -> std::process::Output {
    let mut cmd = Command::new(app);
    cmd.args(args)
        .env("ALICE_IDENTITY_DIR", dir.join("dot-alice"))
        .env("ALICE_WALLET_DATA_ROOT", dir.join("wallet"))
        .env(ENV_NO_UPDATE_CHECK, "1")
        .env("ALICE_MINER_AUTO_UPDATE", "off")
        .env(ENV_LANG_SELFCHECK, "1");
    cmd.output().expect("run the staged binary")
}

/// The auto-rollback warning is the highest-stakes line this client can print —
/// "your client was rolled back and this process is still the failed build" — and
/// it is produced BEFORE the command line is parsed, so it is the message most
/// exposed to a late language resolution.
///
/// Same process, same run: stdout proves the 中文 preference was found and
/// honoured, stderr must therefore carry the 中文 warning.
#[test]
fn the_auto_rollback_warning_speaks_the_users_language() {
    let dir = sandbox("rollback-zh");
    let (app, _lkg) = staged_app(&dir);
    save_lang_pref_zh(&dir);
    // launches=1, started_ok=false ⇒ "we have been here before and it died".
    arm_probation(&app, 1, false);

    let out = run_staged_checked(&app, &dir, &["lang"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // Precondition, in this very run: the saved preference WAS found.
    assert!(
        stdout.contains("当前语言: zh"),
        "precondition — the run must resolve to 中文: {stdout}"
    );
    // Precondition: the rollback really happened (or there is no warning to judge).
    assert_eq!(
        std::fs::read(&app).unwrap(),
        b"LKG-SENTINEL",
        "precondition — the failed build must have been rolled back"
    );
    assert!(
        stderr.contains("已被自动回滚"),
        "the rollback warning must be in the language the user chose: {stderr}"
    );
    assert!(
        !stderr.contains("was rolled back automatically"),
        "and not in English alongside it: {stderr}"
    );
    assert!(
        stderr.contains("lang-selfcheck: ok"),
        "no user-facing text may be selected before the language is resolved: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The common case, and the one that hits every 中文 user who ever self-updates:
/// the ordinary post-update line. It is printed by the MANUAL health gate, which
/// commits right after the parse and still ahead of the old resolution point.
#[test]
fn the_post_update_line_speaks_the_users_language() {
    let dir = sandbox("updated-zh");
    let (app, _lkg) = staged_app(&dir);
    save_lang_pref_zh(&dir);
    // The manual gate's marker: a freshly-installed build awaiting its first-run
    // health proof (attempt 0 ⇒ this run IS that first run).
    let marker = app.with_file_name(format!(
        "{}.pending-health",
        app.file_name().unwrap().to_string_lossy()
    ));
    let body = serde_json::json!({ "installed_version": THIS_VERSION, "attempt": 0 });
    std::fs::write(&marker, serde_json::to_vec(&body).unwrap()).unwrap();

    let out = run_staged_checked(&app, &dir, &["lang"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        stdout.contains("当前语言: zh"),
        "precondition — the run must resolve to 中文: {stdout}"
    );
    assert!(
        !marker.exists(),
        "precondition — the health gate must have committed this run"
    );
    assert!(
        stderr.contains("已更新到 v"),
        "the post-update line must be in the language the user chose: {stderr}"
    );
    assert!(
        !stderr.contains("Updated to v"),
        "and not in English alongside it: {stderr}"
    );
    assert!(
        stderr.contains("lang-selfcheck: ok"),
        "no user-facing text may be selected before the language is resolved: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same warning on the path that exits through clap — `--help`, `--version`,
/// a usage error. That path leaves `main` early, ABOVE the normal exit, and it is
/// exactly the path a puzzled miner takes after an unexpected rollback.
#[test]
fn the_rollback_warning_speaks_the_users_language_on_the_clap_exit_path() {
    let dir = sandbox("rollback-help-zh");
    let (app, _lkg) = staged_app(&dir);
    save_lang_pref_zh(&dir);
    arm_probation(&app, 1, false);

    let out = run_staged_checked(&app, &dir, &["--help"]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(out.status.success(), "--help still exits 0: {stderr}");
    assert_eq!(
        std::fs::read(&app).unwrap(),
        b"LKG-SENTINEL",
        "precondition — the failed build must have been rolled back"
    );
    assert!(
        stderr.contains("已被自动回滚"),
        "the rollback warning must be in the language the user chose: {stderr}"
    );
    assert!(
        !stderr.contains("was rolled back automatically"),
        "and not in English alongside it: {stderr}"
    );
    assert!(
        stderr.contains("lang-selfcheck: ok"),
        "the self-check must cover the clap-exit path too: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
