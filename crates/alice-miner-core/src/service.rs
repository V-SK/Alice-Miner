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
//! Three backends, same shape (install/uninstall/status over a per-OS unit
//! definition): **macOS launchd** (`~/Library/LaunchAgents`), **Linux systemd
//! `--user`** (`~/.config/systemd/user`), **Windows Task Scheduler** (a logon
//! task). Each unit/task runs `<cli> start --lane <lane> --json` — NO secret,
//! address, or payout — and restarts on exit (KeepAlive / Restart=always /
//! RestartOnFailure). Background mining is still **CPU-XMR only** on every
//! platform: a GPU lane needs the keystore unlock, which can't go in a
//! world-readable unit, so it's refused until the OS-keyring integration lands.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

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
        // Every GPU lane (incl. GPU-Alpha, which needs the wallet unlock for its
        // out-of-band PoP) is NOT secret-free, so it cannot background via launchd —
        // use the one-click terminal launcher for GPU persistence instead.
        Lane::GpuPrl | Lane::GpuAlpha | Lane::GpuRvn => Err(
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

/// Cap the background-agent log so it can't grow without bound. The launchd plist
/// points `StandardOutPath`/`StandardErrorPath` at a single fixed file with no native
/// rotation; a crash-looping or very-long-uptime agent would otherwise accumulate
/// forever. Called once at each `--from-service` start: if the file exceeds the cap,
/// truncate it in place. launchd holds the path open in `O_APPEND`, so truncating the
/// inode resets growth (the next append lands at the new EOF) without breaking the
/// writer. Best-effort — any error is ignored so it can never block mining. The file
/// isn't read by anything today (the GUI tails its own in-memory ring); this only
/// bounds disk use. No-op on a box where the file doesn't exist (Linux=journald,
/// Windows=Task Scheduler don't use it).
pub fn rotate_background_log_if_oversized() {
    const MAX_BYTES: u64 = 8 * 1024 * 1024; // 8 MiB
    rotate_log_if_oversized(&agent_log_path(), MAX_BYTES);
}

/// Inner, path-parameterised body of [`rotate_background_log_if_oversized`] (testable
/// without touching the real data dir). Truncates `path` to 0 iff it exceeds
/// `max_bytes`; any IO error is swallowed (best-effort).
fn rotate_log_if_oversized(path: &Path, max_bytes: u64) {
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > max_bytes {
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .open(path)
                .and_then(|f| f.set_len(0));
        }
    }
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
        <string>--from-service</string>
    </array>
    <key>RunAtLoad</key>
    {run_at_load}
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>30</integer>
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

/// Render the Linux systemd `--user` unit for `spec`. Pure + fully testable.
/// `ExecStart` is exactly `<cli> start --lane <lane> --json` — no `--address`,
/// no secret, no payout. `Restart=always` is the KeepAlive equivalent; the unit
/// is wanted by `default.target` so `enable` makes it start at login.
pub fn systemd_unit(spec: &ServiceSpec) -> Result<String, String> {
    let lane = background_lane_arg(spec.lane)?;
    let cli = spec.cli_path.to_string_lossy();
    // systemd unit ExecStart: arguments are space-separated; quote the cli path so
    // a space in it can't split the argv. The lane token is a fixed [a-z] literal.
    // Restart-storm bound: with Restart=always + RestartSec=5 and NO explicit
    // StartLimit, a hard-failing start (e.g. the identity pointer was deleted after
    // install) would relaunch every 5s forever — the 5s gap never accumulates against
    // systemd's default 10s window, so the burst limit is never reached. Set an explicit
    // 5-failures-per-5-minutes limit so a persistently-failing unit lands in `failed`
    // instead of looping; a healthy miner that restarts occasionally never trips it.
    Ok(format!(
        "[Unit]\n\
         Description=Alice Miner (background mining)\n\
         After=network-online.target\n\
         StartLimitIntervalSec=300\n\
         StartLimitBurst=5\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart=\"{cli}\" start --lane {lane} --json --from-service\n\
         Restart=always\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n"
    ))
}

/// Render the Windows Task Scheduler task XML for `spec`. Pure + fully testable.
/// The action runs `<cli> start --lane <lane> --json` at logon, restarting on
/// failure (KeepAlive equivalent). No `--address`, no secret, no payout.
pub fn windows_task_xml(spec: &ServiceSpec) -> Result<String, String> {
    let lane = background_lane_arg(spec.lane)?;
    let cli = xml_escape(&spec.cli_path.to_string_lossy());
    // Arguments element is XML-escaped; the lane token is a fixed [a-z] literal.
    let args = xml_escape(&format!("start --lane {lane} --json --from-service"));
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Alice Miner (background mining)</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>10</Count>
    </RestartOnFailure>
  </Settings>
  <Actions>
    <Exec>
      <Command>{cli}</Command>
      <Arguments>{args}</Arguments>
    </Exec>
  </Actions>
</Task>
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

// ── Linux backend (systemd --user) ──────────────────────────────────────────
/// The on-disk path of the systemd user unit (`~/.config/systemd/user/<label>.service`).
#[cfg(target_os = "linux")]
pub fn systemd_unit_path() -> Result<PathBuf, String> {
    let base = dirs::config_dir().ok_or_else(|| "no user config directory".to_string())?;
    Ok(base.join("systemd").join("user").join(format!("{SERVICE_LABEL}.service")))
}

#[cfg(target_os = "linux")]
fn run_systemctl(args: &[&str]) -> Result<(), String> {
    use std::process::Command;
    let out = Command::new("systemctl")
        .arg("--user")
        .args(args)
        .output()
        .map_err(|e| format!("systemctl --user {}: {e}", args.join(" ")))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "systemctl --user {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

#[cfg(target_os = "linux")]
pub fn install(spec: &ServiceSpec) -> Result<(), String> {
    use std::process::Command;
    if !spec.cli_path.is_file() {
        return Err(format!(
            "the headless miner CLI was not found at {} — cannot install the background service.",
            spec.cli_path.display()
        ));
    }
    let unit = systemd_unit(spec)?; // validates the lane
    let path = systemd_unit_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    std::fs::write(&path, unit).map_err(|e| format!("writing {}: {e}", path.display()))?;
    run_systemctl(&["daemon-reload"])?;
    let svc = format!("{SERVICE_LABEL}.service");
    if spec.run_at_login {
        run_systemctl(&["enable", "--now", svc.as_str()])?;
        // Best-effort: survive logout/reboot (otherwise --user units stop at logout).
        let _ = Command::new("loginctl").arg("enable-linger").output();
    } else {
        run_systemctl(&["start", svc.as_str()])?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn uninstall() -> Result<(), String> {
    let svc = format!("{SERVICE_LABEL}.service");
    let _ = run_systemctl(&["disable", "--now", svc.as_str()]); // best-effort
    let path = systemd_unit_path()?;
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| format!("removing {}: {e}", path.display()))?;
    }
    let _ = run_systemctl(&["daemon-reload"]);
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn status() -> ServiceState {
    use std::process::Command;
    let installed = systemd_unit_path().map(|p| p.exists()).unwrap_or(false);
    if !installed {
        return ServiceState::NotInstalled;
    }
    let svc = format!("{SERVICE_LABEL}.service");
    match Command::new("systemctl").args(["--user", "is-active", svc.as_str()]).output() {
        Ok(out) if String::from_utf8_lossy(&out.stdout).trim() == "active" => ServiceState::Running,
        _ => ServiceState::Loaded,
    }
}

// ── Windows backend (Task Scheduler) ────────────────────────────────────────
#[cfg(target_os = "windows")]
const WIN_TASK_NAME: &str = "AliceMiner";

#[cfg(target_os = "windows")]
pub fn install(spec: &ServiceSpec) -> Result<(), String> {
    use std::process::Command;
    if !spec.cli_path.is_file() {
        return Err(format!(
            "the headless miner CLI was not found at {} — cannot install the background task.",
            spec.cli_path.display()
        ));
    }
    let xml = windows_task_xml(spec)?; // validates the lane
    let tmp = std::env::temp_dir().join(format!("alice-miner-task-{}.xml", std::process::id()));
    std::fs::write(&tmp, xml).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    let out = Command::new("schtasks")
        .args(["/Create", "/TN", WIN_TASK_NAME, "/F", "/XML"])
        .arg(&tmp)
        .output()
        .map_err(|e| format!("schtasks /Create: {e}"))?;
    let _ = std::fs::remove_file(&tmp);
    if !out.status.success() {
        return Err(format!(
            "schtasks /Create failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    // The LogonTrigger fires at next logon; start it now too.
    let _ = Command::new("schtasks").args(["/Run", "/TN", WIN_TASK_NAME]).output();
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn uninstall() -> Result<(), String> {
    use std::process::Command;
    let out = Command::new("schtasks")
        .args(["/Delete", "/TN", WIN_TASK_NAME, "/F"])
        .output()
        .map_err(|e| format!("schtasks /Delete: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    // Deleting a non-existent task is non-zero — treat "not found" as success.
    let err = String::from_utf8_lossy(&out.stderr).to_lowercase();
    if err.contains("cannot find") || err.contains("does not exist") {
        Ok(())
    } else {
        Err(format!("schtasks /Delete failed: {}", err.trim()))
    }
}

#[cfg(target_os = "windows")]
pub fn status() -> ServiceState {
    use std::process::Command;
    match Command::new("schtasks")
        .args(["/Query", "/TN", WIN_TASK_NAME, "/FO", "LIST", "/V"])
        .output()
    {
        Ok(out) if out.status.success() => {
            let s = String::from_utf8_lossy(&out.stdout);
            if s.lines().any(|l| l.trim_start().starts_with("Status:") && l.contains("Running")) {
                ServiceState::Running
            } else {
                ServiceState::Loaded
            }
        }
        _ => ServiceState::NotInstalled,
    }
}

// ── Fallback for any other OS ────────────────────────────────────────────────
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn install(_spec: &ServiceSpec) -> Result<(), String> {
    Err("background mining is not supported on this platform yet.".to_string())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn uninstall() -> Result<(), String> {
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
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
        assert!(xml.contains("<string>--from-service</string>"), "marks the agent's own start");
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

    /// The same no-secret/address/payout invariant the plist test enforces, reused
    /// for the Linux unit + Windows task definitions.
    fn assert_no_secret(def: &str, what: &str) {
        for forbidden in [
            "--address", "address", "seed", "mnemonic", "password", "passwd",
            "unlock", "payout", "prl1", "private", "secret",
        ] {
            assert!(
                !def.to_ascii_lowercase().contains(forbidden),
                "{what} must not contain {forbidden:?} — the reward address is resolved from \
                 ~/.alice at runtime, never written into the world-readable service definition"
            );
        }
    }

    /// The systemd --user unit runs exactly `start --lane xmr --json`, restarts
    /// always (KeepAlive), is wanted by default.target (so `enable` = at-login),
    /// and carries NO secret / address / payout.
    #[test]
    fn linux_systemd_unit_argv_and_no_secret() {
        let unit = systemd_unit(&xmr_spec()).expect("xmr unit renders");
        assert!(unit.contains("start --lane xmr --json --from-service"), "exact argv: {unit}");
        assert!(unit.contains("Restart=always"));
        assert!(unit.contains("WantedBy=default.target"));
        assert!(unit.contains("alice-miner-cli"));
        assert_no_secret(&unit, "systemd unit");
    }

    /// The Windows Task Scheduler XML runs the CLI with the same argv, restarts on
    /// failure (KeepAlive), triggers at logon, and carries NO secret / address /
    /// payout.
    #[test]
    fn windows_task_xml_argv_and_no_secret() {
        let xml = windows_task_xml(&xmr_spec()).expect("xmr task renders");
        assert!(xml.contains("<Arguments>start --lane xmr --json --from-service</Arguments>"), "exact argv: {xml}");
        assert!(xml.contains("alice-miner-cli"));
        assert!(xml.contains("<LogonTrigger>"));
        assert!(xml.contains("<RestartOnFailure>"));
        assert_no_secret(&xml, "windows task xml");
    }

    /// Restart-storm bound: each backend caps a hard-failing relaunch loop (e.g. the
    /// identity pointer deleted after install). systemd gets an explicit StartLimit
    /// (with RestartSec=5 the gap never trips the 10s DEFAULT window → infinite loop);
    /// launchd gets a ThrottleInterval; Windows caps RestartOnFailure Count.
    #[test]
    fn restart_storm_is_bounded() {
        let plist = launchd_plist_xml(&xmr_spec()).unwrap();
        assert!(plist.contains("<key>ThrottleInterval</key>"), "launchd throttle: {plist}");

        let unit = systemd_unit(&xmr_spec()).unwrap();
        assert!(unit.contains("StartLimitIntervalSec="), "systemd start-limit window: {unit}");
        assert!(unit.contains("StartLimitBurst="), "systemd start-limit burst: {unit}");

        let task = windows_task_xml(&xmr_spec()).unwrap();
        assert!(task.contains("<Count>10</Count>"), "windows bounded restart count");
        assert!(!task.contains("<Count>999</Count>"), "the unbounded 999 is gone");
    }

    /// The background log is truncated when it exceeds the cap, and left alone below it.
    #[test]
    fn background_log_rotates_when_oversized() {
        let dir = std::env::temp_dir();
        let big = dir.join(format!("alice-rotate-big-{}.log", std::process::id()));
        let small = dir.join(format!("alice-rotate-small-{}.log", std::process::id()));
        std::fs::write(&big, vec![b'x'; 1024]).unwrap();
        std::fs::write(&small, vec![b'x'; 10]).unwrap();
        // Cap at 100 bytes: the 1 KiB file is truncated, the 10-byte file is untouched.
        rotate_log_if_oversized(&big, 100);
        rotate_log_if_oversized(&small, 100);
        assert_eq!(std::fs::metadata(&big).unwrap().len(), 0, "oversized → truncated");
        assert_eq!(std::fs::metadata(&small).unwrap().len(), 10, "under cap → untouched");
        let _ = std::fs::remove_file(&big);
        let _ = std::fs::remove_file(&small);
    }

    /// Every backend's definition refuses a GPU lane (needs the keyring) — so no
    /// platform can accidentally background a lane that needs the keystore secret.
    #[test]
    fn all_backends_refuse_gpu_lane_until_keyring() {
        for lane in [Lane::GpuPrl, Lane::GpuRvn] {
            let spec = ServiceSpec { lane, cli_path: PathBuf::from("/x/alice-miner-cli"), run_at_login: true };
            for (name, res) in [
                ("launchd", launchd_plist_xml(&spec)),
                ("systemd", systemd_unit(&spec)),
                ("schtasks", windows_task_xml(&spec)),
            ] {
                let err = res.expect_err(&format!("{name} must refuse a GPU lane"));
                assert!(err.contains("keychain") || err.contains("keystore"), "{name}: {err}");
            }
        }
    }
}
