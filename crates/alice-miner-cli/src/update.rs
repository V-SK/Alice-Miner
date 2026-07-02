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

use crate::{EXIT_OK, EXIT_RUNTIME};

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
}

/// Run the `update` command.
pub fn run(args: UpdateArgs) -> i32 {
    let current = release::current_version();
    println!(
        "{} v{current} · {}",
        tr!("Alice Miner", "Alice 矿工"),
        tr!("checking for updates…", "正在检查更新…")
    );

    let outcome = match release::check_for_update(current) {
        Ok(o) => o,
        Err(e) => {
            eprintln!(
                "error: {} ({e})",
                tr!("could not check for updates", "无法检查更新")
            );
            return EXIT_RUNTIME;
        }
    };

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
            // A hard-upgrade notice: offer the same apply flow (it IS newer).
            apply_flow(&manifest, manifest.artifact_for_current_platform(), args.yes, current.as_str())
        }
        CheckOutcome::UpdateAvailable { current, manifest, artifact } => {
            println!(
                "{}: v{current} → v{}",
                tr!("A new version is available", "有新版本可用"),
                manifest.version
            );
            print_notes(&manifest);
            if args.check {
                // --check: report only, point at how to apply.
                println!(
                    "  {}  alice-miner update",
                    tr!("apply it with:", "应用更新:")
                );
                return EXIT_OK;
            }
            apply_flow(&manifest, Some(&artifact), args.yes, current.as_str())
        }
    }
}

/// The confirm → download → verify → apply → arm-health-gate flow for a newer
/// manifest. With `yes`, applies without prompting; otherwise asks for an explicit
/// interactive confirm (and if stdin is NOT a TTY, refuses to apply — never silent).
fn apply_flow(manifest: &Manifest, artifact: Option<&Artifact>, yes: bool, current: &str) -> i32 {
    let _ = current;
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

    /// `quiet=true` (the `--json` / machine paths) is also a no-op.
    #[test]
    fn quiet_is_a_noop() {
        with_temp_dir(|| {
            startup_banner(true);
            assert!(!cache_path().exists(), "quiet must not write a cache");
        });
    }
}
