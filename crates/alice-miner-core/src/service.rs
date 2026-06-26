//! `core/service` — run the miner as a background OS service so mining PERSISTS
//! across closing the GUI window and (with start-at-login) across reboots. This
//! is the fix for the "挖矿进程没法持久化 (Mac)" report: the GUI is just a remote
//! control; the actual mining runs under the OS service manager.
//!
//! v0.3.2 ships the **macOS launchd** backend for the **CPU-XMR** lane — the only
//! lane macOS runs (SRBMiner / GPU-PRL has no Apple build). That lane needs NO
//! keystore secret, so the LaunchAgent is clean:
//!
//!   ProgramArguments = [ <bundle>/Contents/MacOS/alice-miner-cli, start,
//!                        --lane, xmr, --json ]
//!
//! INVARIANT (asserted by tests): the plist carries **NO secret, NO reward
//! address, NO payout string**. The reward address is resolved by the CLI from
//! the user's own `~/.alice` identity at runtime — never baked into the world-
//! readable plist. A GPU lane (which would need a keystore unlock) is refused
//! here until the Keychain-backed keyring ships (honest "coming soon").
//!
//! Windows (Task Scheduler / service) and Linux (systemd --user) backends are
//! the same shape and are deliberately deferred — the trait makes them
//! mechanical to add. On a non-macOS host every entry point returns a clear
//! "not supported yet" error (never a panic).

#![allow(dead_code)]

use std::path::PathBuf;

use crate::lane::Lane;

/// The launchd label / plist basename. One agent per user; a second install
/// replaces the first (single background owner).
pub const SERVICE_LABEL: &str = "org.aliceprotocol.miner";

/// What to run in the background.
#[derive(Debug, Clone)]
pub struct ServiceSpec {
    /// The lane to mine. Only [`Lane::Xmr`] is backgroundable today (no secret).
    pub lane: Lane,
    /// Absolute path to the bundled `alice-miner-cli` (the headless engine).
    pub cli_path: PathBuf,
    /// `RunAtLoad` — also start mining automatically at login / boot.
    pub run_at_login: bool,
}

/// Whether the background agent is installed and/or running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// Agent installed and a mining process is running.
    Running,
    /// Agent installed but not currently running (e.g. KeepAlive backing off).
    Loaded,
    /// No agent installed.
    NotInstalled,
}

/// The CLI `--lane` token for a lane that can run in the background WITHOUT a
/// stored secret, or an error for one that can't yet. XMR is the secret-free
/// background lane; a GPU lane needs the (not-yet-shipped) Keychain keyring.
fn background_lane_arg(lane: Lane) -> Result<&'static str, String> {
    match lane {
        Lane::Xmr => Ok("xmr"),
        Lane::GpuPrl | Lane::GpuRvn => Err(
            "background mining for a GPU lane needs the keystore unlock stored in the OS \
             keychain (a follow-up). The CPU-XMR lane runs in the background today with no \
             stored secret — switch to XMR for background mining, or keep the window open."
                .to_string(),
        ),
    }
}

/// Minimal XML text escape for the few values we interpolate into the plist (the
/// CLI path). Paths rarely contain XML-special chars, but escape defensively so a
/// `&`/`<`/`>` in a path can never break the plist or inject an element.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The per-user log path for the agent's stdout/stderr (under the AliceMiner data
/// dir, NOT the keystore). Used by the launchd `StandardOutPath` keys.
fn agent_log_path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("AliceMiner")
        .join("logs")
        .join("miner.background.log")
}

/// Render the launchd LaunchAgent plist for `spec`. Pure + fully testable.
///
/// The ProgramArguments are exactly `[cli, start, --lane, <lane>, --json]` — no
/// `--address`, no secret, no payout. `KeepAlive` restarts the miner if it dies;
/// `RunAtLoad` (gated on `run_at_login`) also starts it at login.
pub fn launchd_plist_xml(spec: &ServiceSpec) -> Result<String, String> {
    let lane = background_lane_arg(spec.lane)?;
    let cli = xml_escape(&spec.cli_path.to_string_lossy());
    let log = xml_escape(&agent_log_path().to_string_lossy());
    let run_at_load = if spec.run_at_login { "<true/>" } else { "<false/>" };
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{SERVICE_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{cli}</string>
        <string>start</string>
        <string>--lane</string>
        <string>{lane}</string>
        <string>--json</string>
    </array>
    <key>RunAtLoad</key>
    {run_at_load}
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
    <key>StandardOutPath</key>
    <string>{log}</string>
    <key>StandardErrorPath</key>
    <string>{log}</string>
</dict>
</plist>
"#
    ))
}

/// The on-disk path of the LaunchAgent plist (`~/Library/LaunchAgents/<label>.plist`).
#[cfg(target_os = "macos")]
pub fn launch_agent_plist_path() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or_else(|| "no home directory".to_string())?;
    Ok(home
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{SERVICE_LABEL}.plist")))
}

/// Install (or replace) the background mining agent and load it. Writes the plist
/// to `~/Library/LaunchAgents/`, ensures the log dir exists, then `launchctl
/// load -w`s it (unloading any prior copy first so re-install is idempotent).
#[cfg(target_os = "macos")]
pub fn install(spec: &ServiceSpec) -> Result<(), String> {
    use std::process::Command;
    if !spec.cli_path.is_file() {
        return Err(format!(
            "the headless miner CLI was not found at {} — cannot install the background agent.",
            spec.cli_path.display()
        ));
    }
    let plist = launchd_plist_xml(spec)?; // also validates the lane
    let path = launch_agent_plist_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    if let Some(logdir) = agent_log_path().parent() {
        let _ = std::fs::create_dir_all(logdir);
    }
    // Best-effort unload of any prior agent so the new definition takes effect.
    let _ = Command::new("/bin/launchctl").args(["unload", "-w"]).arg(&path).output();
    std::fs::write(&path, plist).map_err(|e| format!("writing {}: {e}", path.display()))?;
    let out = Command::new("/bin/launchctl")
        .args(["load", "-w"])
        .arg(&path)
        .output()
        .map_err(|e| format!("launchctl load: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "launchctl load failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// Stop + remove the background mining agent. Idempotent: a missing agent is a
/// success (already not installed).
#[cfg(target_os = "macos")]
pub fn uninstall() -> Result<(), String> {
    use std::process::Command;
    let path = launch_agent_plist_path()?;
    let _ = Command::new("/bin/launchctl").args(["unload", "-w"]).arg(&path).output();
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| format!("removing {}: {e}", path.display()))?;
    }
    Ok(())
}

/// Report whether the agent is installed / running, via `launchctl list <label>`.
#[cfg(target_os = "macos")]
pub fn status() -> ServiceState {
    use std::process::Command;
    let installed = launch_agent_plist_path().map(|p| p.exists()).unwrap_or(false);
    if !installed {
        return ServiceState::NotInstalled;
    }
    // `launchctl list <label>` prints a dict with a "PID" key when running.
    match Command::new("/bin/launchctl").args(["list", SERVICE_LABEL]).output() {
        Ok(out) if out.status.success() => {
            let s = String::from_utf8_lossy(&out.stdout);
            if s.contains("\"PID\"") {
                ServiceState::Running
            } else {
                ServiceState::Loaded
            }
        }
        _ => ServiceState::Loaded,
    }
}

// ── Non-macOS stubs (Windows / Linux backends are a deferred follow-up) ──────
#[cfg(not(target_os = "macos"))]
pub fn install(_spec: &ServiceSpec) -> Result<(), String> {
    Err("background mining is currently supported on macOS only (Windows/Linux \
         backends are a follow-up). Keep the window open to keep mining."
        .to_string())
}

#[cfg(not(target_os = "macos"))]
pub fn uninstall() -> Result<(), String> {
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn status() -> ServiceState {
    ServiceState::NotInstalled
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xmr_spec() -> ServiceSpec {
        ServiceSpec {
            lane: Lane::Xmr,
            cli_path: PathBuf::from("/Applications/AliceMiner.app/Contents/MacOS/alice-miner-cli"),
            run_at_login: true,
        }
    }

    /// The rendered plist runs exactly `start --lane xmr --json`, keeps the miner
    /// alive, and (most importantly) carries NO secret / address / payout.
    #[test]
    fn xmr_plist_has_expected_argv_and_no_secret() {
        let xml = launchd_plist_xml(&xmr_spec()).expect("xmr plist renders");
        // Expected argv + behaviour.
        assert!(xml.contains("<string>start</string>"));
        assert!(xml.contains("<string>--lane</string>"));
        assert!(xml.contains("<string>xmr</string>"));
        assert!(xml.contains("<string>--json</string>"));
        assert!(xml.contains("alice-miner-cli"));
        assert!(xml.contains("<key>KeepAlive</key>\n    <true/>"));
        assert!(xml.contains("<key>RunAtLoad</key>\n    <true/>"), "run_at_login=true → RunAtLoad true");
        assert!(xml.contains(SERVICE_LABEL));
        // The credit-only / no-secret invariant: nothing sensitive in the plist.
        // NB: "key" is intentionally absent — the plist legitimately contains
        // `<key>…</key>` XML elements. We forbid only secret / address / payout
        // material.
        for forbidden in [
            "--address", "address", "seed", "mnemonic", "password", "passwd",
            "unlock", "payout", "prl1", "private", "secret",
        ] {
            assert!(
                !xml.to_ascii_lowercase().contains(forbidden),
                "plist must not contain {forbidden:?}: the reward address is resolved from \
                 ~/.alice at runtime, never baked into the world-readable plist"
            );
        }
    }

    /// `run_at_login=false` → the agent installs but does NOT auto-start at login
    /// (RunAtLoad false); KeepAlive still restarts it within a session.
    #[test]
    fn run_at_login_false_sets_runatload_false() {
        let mut spec = xmr_spec();
        spec.run_at_login = false;
        let xml = launchd_plist_xml(&spec).unwrap();
        assert!(xml.contains("<key>RunAtLoad</key>\n    <false/>"));
    }

    /// A GPU lane is refused (no secret store yet) with an honest message — so we
    /// can never accidentally try to background a lane that needs the keystore.
    #[test]
    fn gpu_lane_background_is_refused_until_keyring() {
        for lane in [Lane::GpuPrl, Lane::GpuRvn] {
            let spec = ServiceSpec { lane, cli_path: PathBuf::from("/x/alice-miner-cli"), run_at_login: true };
            let err = launchd_plist_xml(&spec).expect_err("GPU background refused");
            assert!(err.contains("keychain") || err.contains("keystore"), "got: {err}");
        }
    }

    /// XML escaping neutralises special chars in an interpolated path.
    #[test]
    fn xml_escape_neutralises_specials() {
        assert_eq!(xml_escape("a & b < c > d \" e"), "a &amp; b &lt; c &gt; d &quot; e");
    }
}
