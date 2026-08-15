//! `autoupdate` — the one driver both front-ends use for guarded automatic updates.
//!
//! `alice_release::auto` holds the policy (pure, exhaustively tested, no clock and
//! no disk in the decision). This module is the part that touches the world: it
//! resolves the mode from settings, points the policy at `~/.alice`, performs the
//! install, arms the probation, and turns every outcome into a sentence in the
//! user's language.
//!
//! It lives in `core` rather than in the CLI or the GUI on purpose. The August
//! 2026 audit finding (AM-REL-009) was exactly a case of one front-end driving a
//! safety mechanism and the other not: `arm_pending_health_check` fired after
//! every CLI self-update, and only the GUI ever resolved the marker, so a
//! headless box had the rollback machinery armed and nothing to disarm it. Two
//! copies of an update flow is how that happens. There is one copy here.
//!
//! Everything in here is best-effort: a miner must never fail to mine because
//! the updater had an opinion. Network failures, unreadable state and missing
//! paths all resolve to "do nothing, say nothing", never to a panic and never to
//! a blocked start.

use std::path::PathBuf;
use std::time::Duration;

use alice_release::auto::{self, Decision, Hold, Mode};
use alice_release as release;

use crate::tr;

/// Env override for the mode, for operators who manage a fleet with
/// configuration management and want it stated at launch rather than persisted.
/// Takes precedence over the saved setting; an unparseable value is IGNORED (we
/// fall back to the saved setting / default rather than guessing).
pub const MODE_ENV: &str = "ALICE_MINER_AUTO_UPDATE";

/// Where the updater keeps its local policy state (rollout label, seen-version
/// ledger, failure pins, history). All public, none of it transmitted.
pub fn state_dir() -> PathBuf {
    crate::settings::alice_home()
}

/// Resolve the effective mode: env → saved setting → build default.
///
/// An unrecognised value anywhere in that chain falls through to the NEXT source
/// rather than to a permissive default, so a typo can only ever leave the
/// machine where it already was.
pub fn mode() -> Mode {
    if let Some(v) = std::env::var(MODE_ENV).ok().filter(|s| !s.trim().is_empty()) {
        if let Some(m) = Mode::parse(&v) {
            return m;
        }
    }
    if let Some(saved) = crate::settings::load().auto_update {
        if let Some(m) = Mode::parse(&saved) {
            return m;
        }
    }
    auto::DEFAULT_MODE
}

/// Whether an explicit choice has ever been made on this machine (used to offer
/// the choice once, rather than nagging).
pub fn mode_is_explicit() -> bool {
    std::env::var(MODE_ENV)
        .ok()
        .and_then(|v| Mode::parse(&v))
        .is_some()
        || crate::settings::load()
            .auto_update
            .and_then(|s| Mode::parse(&s))
            .is_some()
}

/// Persist an explicit choice. Returns the canonical spelling stored.
pub fn set_mode(m: Mode) -> Result<String, String> {
    crate::settings::save_auto_update(m.as_str())?;
    auto::log_event(
        &state_dir(),
        "mode-changed",
        serde_json::json!({ "mode": m.as_str() }),
    );
    Ok(m.as_str().to_string())
}

/// What one automatic-update check concluded, already phrased for a human.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing to do, nothing to say.
    Quiet,
    /// A newer version exists but was not installed. `message` says why, in one
    /// line. This is the mode the client spends most of its life in and it is
    /// the whole point: a miner should never have to guess whether their client
    /// is current.
    Held { version: String, message: String },
    /// An update was downloaded, verified and installed. The user must restart
    /// to run it — we never kill a running miner to apply an update.
    Installed { version: String, message: String },
    /// The running build has been withdrawn by the publisher.
    CurrentRevoked { message: String },
    /// The check itself failed (offline, TLS, bad signature). Kept separate from
    /// "up to date" so we never render a failure as reassurance.
    CheckFailed { message: String },
}

impl Outcome {
    /// The line to show, if any.
    pub fn message(&self) -> Option<&str> {
        match self {
            Outcome::Quiet => None,
            Outcome::Held { message, .. }
            | Outcome::Installed { message, .. }
            | Outcome::CurrentRevoked { message }
            | Outcome::CheckFailed { message } => Some(message),
        }
    }
}

/// Run one full automatic-update cycle: fetch + verify the manifest, apply the
/// policy, and install if (and only if) every guardrail says yes.
///
/// Network-bound — call it from a background thread. Never panics.
///
/// `quiet_holds` suppresses the routine "held because …" line (the periodic
/// in-session check uses it; the once-per-start check does not), because a
/// reason worth reading once an hour is noise every six hours.
pub fn tick(quiet_holds: bool) -> Outcome {
    let m = mode();
    if !m.checks() {
        return Outcome::Quiet;
    }
    let dir = state_dir();
    let current = release::current_version();

    let manifest = match release::fetch_verified_manifest() {
        Ok(m) => m,
        Err(e) => {
            // An unverifiable manifest is the one case worth saying out loud even
            // in quiet mode: it is what a tampered mirror looks like from here.
            let loud = matches!(e, release::UpdateError::Signature(_));
            if !loud {
                return Outcome::Quiet;
            }
            return Outcome::CheckFailed {
                message: tr!(
                    format!("update check REFUSED: the release manifest did not verify against the built-in key ({e}). Nothing was downloaded. If this persists, do not install anything and report it."),
                    format!("更新检查已拒绝:发布清单未能通过内置密钥校验({e})。没有下载任何内容。若持续出现,请不要安装任何东西并上报。")
                ),
            };
        }
    };

    // Record the sighting BEFORE deciding: the soak clock starts when we first
    // see a version, and the recorded hash is what makes a later re-publish of
    // the same version detectable.
    let seen = manifest
        .artifact_for_current_platform()
        .map(|a| auto::note_seen(&dir, &manifest.version, &a.sha256));

    let app_path = release::current_app_path().ok();
    let pins = auto::pins(&dir);
    let input = auto::Input {
        manifest: &manifest,
        current,
        mode: m,
        rollout_id: &auto::rollout_id(&dir),
        now_unix: now_unix(),
        first_seen_unix: seen.as_ref().map(|s| s.first_seen_unix).unwrap_or_else(now_unix),
        seen_sha256: seen.as_ref().map(|s| s.sha256.as_str()),
        pinned: &pins,
        lkg_present: app_path
            .as_deref()
            .map(release::has_last_known_good)
            .unwrap_or(false),
    };

    match auto::decide(&input) {
        Decision::UpToDate => Outcome::Quiet,

        Decision::CurrentRevoked { current, latest, rollback_available } => {
            auto::log_event(
                &dir,
                "current-revoked",
                serde_json::json!({ "current": current, "latest": latest }),
            );
            // Revocation is the publisher saying "this build should not be
            // running". Where we are allowed to act unattended AND there is a
            // last-known-good copy to go back to, we act: revert on disk, pin the
            // withdrawn version so nothing re-installs it, and tell them to
            // restart. Where we are NOT allowed to act (mode off / notify), we do
            // exactly nothing and say exactly that — a machine set to "install
            // nothing" does not get software swapped under it just because the
            // trigger was a withdrawal rather than an upgrade.
            //
            // Note what this deliberately is NOT: a downgrade an attacker can
            // aim anywhere. The only place it can go is the copy this machine was
            // already running before its last update.
            let may_act = m.installs() && rollback_available;
            let reverted = if may_act {
                app_path
                    .as_deref()
                    .map(|p| release::rollback(p).is_ok())
                    .unwrap_or(false)
            } else {
                false
            };
            if reverted {
                auto::pin(&dir, &current);
                auto::log_event(
                    &dir,
                    "reverted-revoked",
                    serde_json::json!({ "from": current }),
                );
            }
            let tail = if reverted {
                tr!(
                    "The previous version has been restored on disk — restart alice-miner to run it. This process is still the withdrawn build.",
                    "上一个版本已恢复到磁盘 —— 请重启 alice-miner 以运行它。当前进程仍是被撤回的版本。"
                )
                .to_string()
            } else if rollback_available {
                tr!(
                    "A previous version is still on this machine, but this machine is set not to install anything on its own, so nothing was changed.",
                    "本机仍保留上一个版本,但本机设置为不自动安装任何东西,因此未做任何更改。"
                )
                .to_string()
            } else {
                tr!(
                    "There is no previous version on this machine to fall back to.",
                    "本机没有可回退的旧版本。"
                )
                .to_string()
            };
            Outcome::CurrentRevoked {
                message: format!(
                    "{} {}",
                    tr!(
                        format!("⚠ v{current} has been WITHDRAWN by the publisher. Install v{latest} with `alice-miner update` as soon as you can."),
                        format!("⚠ v{current} 已被发布方撤回。请尽快运行 `alice-miner update` 安装 v{latest}。")
                    ),
                    tail
                )
                .trim_end()
                .to_string(),
            }
        }

        Decision::Notify { version, hold } => {
            let message = describe_hold(&version, &hold);
            // A hash conflict is never routine and is never quiet.
            let loud = matches!(hold, Hold::HashConflict { .. });
            if loud {
                auto::log_event(
                    &dir,
                    "hash-conflict",
                    serde_json::json!({ "version": version }),
                );
            }
            if quiet_holds && !loud {
                Outcome::Quiet
            } else {
                Outcome::Held { version, message }
            }
        }

        Decision::Install { version, artifact, security } => {
            if app_path.is_none() {
                // We could not resolve where this app lives, so there is nothing
                // we could swap safely. Do nothing rather than guess at a path.
                return Outcome::Quiet;
            }
            // The build we are about to replace: was it earning? This is the only
            // thing that lets the probation tell "the new client broke" apart from
            // "the pool is down", so it is read BEFORE the swap.
            let previous_productive = auto::was_recently_productive(&dir);
            auto::log_event(
                &dir,
                "installing",
                serde_json::json!({
                    "version": version,
                    "security": security,
                    "sha256": artifact.sha256,
                    "previous_productive": previous_productive,
                }),
            );
            match install(&artifact, &version, current, previous_productive) {
                Ok(()) => Outcome::Installed {
                    version: version.clone(),
                    message: tr!(
                        format!("Installed the signed update v{version}. It runs the next time you start alice-miner — your current session was NOT interrupted. If it fails to start, or stops landing accepted shares, this machine rolls back to v{current} on its own."),
                        format!("已安装已签名的更新 v{version}。下次启动 alice-miner 时生效 —— 当前挖矿会话未被打断。若新版本无法启动、或不再有被接受的份额,本机会自动回滚到 v{current}。")
                    ),
                },
                Err(e) => {
                    auto::log_event(
                        &dir,
                        "install-failed",
                        serde_json::json!({ "version": version, "error": e }),
                    );
                    Outcome::CheckFailed {
                        message: tr!(
                            format!("automatic update to v{version} failed and was NOT applied ({e}). You are still on v{current}."),
                            format!("自动更新到 v{version} 失败,未被应用({e})。你仍在 v{current}。")
                        ),
                    }
                }
            }
        }
    }
}

/// Download → verify → atomic swap → arm the probation.
///
/// The probation, not `alice_release::arm_pending_health_check`: the manual gate
/// commits (and drops last-known-good) as soon as the process starts, which is
/// the right bar for an update a human chose and the wrong one for an update
/// nobody asked for. See `alice_release::auto` for why the two gates are
/// separate rather than one with a flag.
fn install(
    artifact: &release::Artifact,
    version: &str,
    previous: &str,
    previous_productive: bool,
) -> Result<(), String> {
    let bytes = release::download_and_verify(artifact).map_err(|e| e.to_string())?;
    let applied = release::apply_update(artifact, &bytes).map_err(|e| e.to_string())?;
    auto::arm(&applied.app_path, version, previous, previous_productive)
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// One honest line for every reason we did not install something.
fn describe_hold(version: &str, hold: &Hold) -> String {
    match hold {
        Hold::ModeOff => tr!(
            format!("v{version} is available. Automatic updates are OFF on this machine — run `alice-miner update` to install it."),
            format!("有新版本 v{version}。本机已关闭自动更新 —— 运行 `alice-miner update` 安装。")
        ),
        Hold::NotifyOnly => tr!(
            format!("v{version} is available. This machine is set to notify only — run `alice-miner update` to install it."),
            format!("有新版本 v{version}。本机设置为仅提示 —— 运行 `alice-miner update` 安装。")
        ),
        Hold::NotSecurity => tr!(
            format!("v{version} is available. This machine auto-installs security releases only — run `alice-miner update` to take this one."),
            format!("有新版本 v{version}。本机仅自动安装安全更新 —— 运行 `alice-miner update` 安装此版本。")
        ),
        Hold::Soaking { ready_in_s } => {
            let h = (*ready_in_s).div_ceil(3600);
            tr!(
                format!("v{version} is available. New versions are held for a day before this machine installs them on its own (~{h}h to go) — `alice-miner update` installs it now."),
                format!("有新版本 v{version}。新版本会先观察一天本机才会自动安装(还剩约 {h} 小时)—— 运行 `alice-miner update` 可立即安装。")
            )
        }
        Hold::Rollout { bucket, pct } => tr!(
            format!("v{version} is available and is rolling out to {pct}% of machines first; this one is in group {bucket} and is not in that slice yet — `alice-miner update` installs it now."),
            format!("有新版本 v{version},正在向 {pct}% 的机器分批放量;本机分组为 {bucket},尚未轮到 —— 运行 `alice-miner update` 可立即安装。")
        ),
        Hold::Pinned => tr!(
            format!("v{version} is available but this machine already tried it and rolled back, so it will not install it again on its own. `alice-miner update` will still install it if you want to retry."),
            format!("有新版本 v{version},但本机曾安装并回滚过,因此不会再自动安装。如需重试,可运行 `alice-miner update`。")
        ),
        Hold::Revoked => tr!(
            format!("v{version} is the newest published version but the publisher has WITHDRAWN it. It will not be installed."),
            format!("v{version} 是最新发布版本,但已被发布方撤回,不会被安装。")
        ),
        Hold::NoArtifact => tr!(
            format!("v{version} is available but ships no package for this platform — download it manually from the releases page."),
            format!("有新版本 v{version},但没有适用于本平台的安装包 —— 请从发布页手动下载。")
        ),
        Hold::HashConflict { seen_sha256, now_sha256 } => {
            let seen = short(seen_sha256);
            let now = short(now_sha256);
            tr!(
                format!("⚠ REFUSED to install v{version}: this machine first saw that version with package {seen}, and the server is now offering {now} under the SAME version number. Nothing was downloaded. Do not install it by hand either until this is explained."),
                format!("⚠ 已拒绝安装 v{version}:本机首次见到该版本时安装包为 {seen},服务器现在以同一个版本号提供 {now}。没有下载任何内容。在弄清原因之前也请不要手动安装。")
            )
        }
    }
}

fn short(sha: &str) -> String {
    sha.chars().take(12).collect()
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ────────────────────────────────────────────────────────────────────────────
// Startup + session hooks (both front-ends call these)
// ────────────────────────────────────────────────────────────────────────────

/// Resolve the auto-update probation at startup. Call ONCE, as early as
/// possible, right next to the manual gate. Returns a line to print, if there is
/// something the user needs to know.
pub fn register_launch() -> Option<String> {
    let app_path = release::current_app_path().ok()?;
    let dir = state_dir();
    match auto::register_launch(&dir, &app_path, release::current_version()) {
        auto::LaunchVerdict::Normal | auto::LaunchVerdict::OnTrial { .. } => None,
        auto::LaunchVerdict::RolledBack { failed_version, reason, restored } => {
            let why = match reason {
                auto::RollbackReason::CrashOnLaunch => tr!(
                    "it was installed but never started successfully",
                    "它安装后从未成功启动"
                ),
                auto::RollbackReason::StoppedEarning => tr!(
                    "it started but stopped landing accepted shares, while the version before it had been landing them on this machine",
                    "它能启动,但不再有被接受的份额,而它替换掉的版本在本机是有的"
                ),
            };
            // Precision matters twice here. The binary on disk was replaced, but
            // THIS process is still the failed build — a user told "rolled back"
            // without that sentence will act on a false belief. And when the
            // restore itself did not succeed we say THAT, rather than reporting a
            // recovery we did not perform.
            if !restored {
                return Some(tr!(
                    format!("warning: v{failed_version} failed its health check — {why} — but the previous version could NOT be restored automatically. This machine is still running v{failed_version}. Reinstall the client from the releases page. It will not install v{failed_version} again on its own."),
                    format!("警告:v{failed_version} 未通过健康检查 —— {why} —— 但上一个版本无法自动恢复。本机仍在运行 v{failed_version}。请从发布页重新安装客户端。本机不会再自动安装 v{failed_version}。")
                ));
            }
            Some(tr!(
                format!("warning: v{failed_version} was rolled back automatically — {why}. The previous version has been restored on disk, but this process is STILL the failed build: restart alice-miner to run the restored one. This machine will not install v{failed_version} again on its own."),
                format!("警告:v{failed_version} 已被自动回滚 —— {why}。上一个版本已恢复到磁盘,但当前进程仍是那个失败的版本:请重启 alice-miner 以运行已恢复的版本。本机不会再自动安装 v{failed_version}。")
            ))
        }
    }
}

/// The process is demonstrably up and doing real work. Best-effort.
pub fn confirm_start() {
    if let Ok(app_path) = release::current_app_path() {
        auto::confirm_start(&state_dir(), &app_path, release::current_version());
    }
}

/// What the ACCEPTANCE guard (layer 3) is doing on this machine right now, as
/// both front-ends read it out of the same engine snapshot.
///
/// This exists because layer 2 cannot see layer 3 from where it sits, and the two
/// disagree in the most damaging possible way if left unwired: layer 3 stops
/// mining on purpose during an upstream outage, and layer 2 reads the resulting
/// zero-accepted stretch as "the version I installed does not earn". See F4.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MiningEvidence {
    /// Accepted shares so far this session (the figure the probation judges).
    pub accepted: u64,
    /// Any lane was HALTED or stopped by the acceptance guard. Once that happens
    /// `accepted` is frozen by design, so the session says nothing about the build.
    pub halted: bool,
    /// The lanes this session is mining — the input to the network-wide check.
    /// Empty means "we do not know which lane", and the check is skipped.
    pub lanes: Vec<crate::lane::Lane>,
}

impl MiningEvidence {
    /// Read the live evidence out of an engine snapshot. ONE copy of this
    /// derivation, shared by the CLI and the GUI, on purpose.
    pub fn from_snapshot(s: &crate::engine::Snapshot) -> Self {
        Self {
            accepted: s.shares_accepted,
            halted: s.lanes.iter().any(|l| l.halted),
            lanes: if s.lanes.is_empty() {
                s.lane.into_iter().collect()
            } else {
                s.lanes.iter().map(|l| l.lane).collect()
            },
        }
    }

    /// Whether this counts as "this machine is earning" for the purposes of the
    /// baseline a FUTURE update is judged against. A halted lane's frozen counter
    /// is not evidence of current earning, however large it is.
    pub fn counts_as_earning(&self) -> bool {
        self.accepted > 0 && !self.halted
    }
}

/// Decide what layer 3 says about the session being reported.
///
/// Split out and pure (bar the caller-supplied probe) so the *order* of the two
/// guards is testable: a halted lane abstains without ever touching the network,
/// and the network is asked ONLY when a rollback is otherwise imminent — never
/// once per tick.
fn resolve_evidence(
    halted: bool,
    rollback_imminent: bool,
    network_wide: impl FnOnce() -> bool,
) -> auto::SessionEvidence {
    if halted {
        return auto::SessionEvidence::MiningHalted;
    }
    if rollback_imminent && network_wide() {
        return auto::SessionEvidence::NetworkWide;
    }
    auto::SessionEvidence::Judgeable
}

/// Whether reporting this session could reach the (bounded, blocking) lane-health
/// call inside [`note_session`] — the caller's cue to hand the report to a worker
/// thread instead of running it on a UI / render loop.
///
/// Deliberately a SUPERSET of the condition that actually probes: it is cheap and
/// pure (no disk), and being wrong in this direction costs one idle thread, while
/// being wrong the other way costs a ten-second freeze. The overwhelmingly common
/// reports — a session with accepted shares, a short one, a halted lane — are all
/// `false` here and stay inline.
pub fn session_may_consult_the_network(ran: Duration, mining: &MiningEvidence) -> bool {
    !mining.halted
        && mining.accepted == 0
        && !mining.lanes.is_empty()
        && ran.as_secs() >= auto::MIN_JUDGED_SESSION.as_secs()
}

/// Report a mining session (elapsed time + what layer 3 saw) against the
/// probation. Returns a line to print when the verdict changed something.
///
/// **May block** for one bounded HTTP GET — but only when it is about to decide a
/// rollback, and only when [`session_may_consult_the_network`] said so first. Call
/// it off the UI thread whenever that predicate is true.
pub fn note_session(ran: Duration, mining: &MiningEvidence) -> Option<String> {
    let app_path = release::current_app_path().ok()?;
    let dir = state_dir();
    let version = release::current_version();
    let ran_secs = ran.as_secs();

    // A long session with nothing accepted is the only shape that can ever be held
    // against the build. Everything below is gated on it, so the common paths (a
    // short session, a session with accepted shares) cost exactly what they did.
    let counts_against = mining.accepted == 0 && ran_secs >= auto::MIN_JUDGED_SESSION.as_secs();

    // Would this one, taken at face value, roll the build back and pin it forever?
    // Only THEN is it worth a network call to ask whether the whole network is
    // being rejected — the answer that makes blaming this build wrong.
    let rollback_imminent = counts_against
        && !mining.halted
        && auto::session_would_roll_back(
            &app_path,
            version,
            &auto::SessionResult::judgeable(ran_secs, 0),
        );
    let evidence = resolve_evidence(mining.halted, rollback_imminent, || {
        crate::acceptance::any_lane_collapsed_network_wide(&mining.lanes)
    });

    let v = auto::note_session(
        &dir,
        &app_path,
        version,
        auto::SessionResult {
            ran_secs,
            accepted: mining.accepted,
            evidence,
        },
    );
    match v {
        auto::SessionVerdict::NoChange => None,
        auto::SessionVerdict::Committed { .. } => None,
        auto::SessionVerdict::Abstained { reason } => {
            // Log only the abstentions that actually SPARED the build something —
            // a session that would otherwise have been a strike or a rollback. A
            // halted rig reports its (frozen, non-zero) counters every tick, and a
            // history file full of "did nothing" would bury the line that matters.
            if counts_against {
                auto::log_event(
                    &dir,
                    "probation-abstained",
                    serde_json::json!({
                        "version": version,
                        "reason": reason.key(),
                        "ran_secs": ran_secs,
                        "would_have_rolled_back": rollback_imminent,
                    }),
                );
            }
            None
        }
        auto::SessionVerdict::RolledBack { failed_version, previous, restored } => {
            if !restored {
                return Some(tr!(
                    format!("warning: v{failed_version} ran twice without landing a single accepted share, on a machine that was landing them before the update — but v{previous} could NOT be restored automatically. You are still on v{failed_version}. Reinstall from the releases page."),
                    format!("警告:v{failed_version} 连续两次长时间运行都没有任何被接受的份额(本机在更新前是有的),但无法自动恢复 v{previous}。你仍在 v{failed_version}。请从发布页重新安装。")
                ));
            }
            Some(tr!(
                format!("warning: v{failed_version} has been rolled back to v{previous} — it ran without landing a single accepted share, twice, on a machine that was landing them before the update. Restart alice-miner to run v{previous}."),
                format!("警告:v{failed_version} 已回滚到 v{previous} —— 它连续两次长时间运行都没有任何被接受的份额,而本机在更新前是有的。请重启 alice-miner 以运行 v{previous}。")
            ))
        }
    }
}

/// Record that accepted shares are landing. Throttled by the caller; this is the
/// baseline the mining probation judges a future update against.
///
/// Callers must gate this on [`MiningEvidence::counts_as_earning`]: a lane the
/// acceptance guard has halted keeps a non-zero, FROZEN accepted counter, and
/// refreshing "this machine earns" from it would keep a stale baseline alive for
/// as long as the rig stays halted.
pub fn mark_productive() {
    auto::mark_productive(&state_dir());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The full resolution chain, in an isolated `$ALICE_IDENTITY_DIR` so the
    /// developer's real `~/.alice` is never read or written.
    ///
    /// The property under test is not just "the override works" — it is that
    /// every failure mode falls back to something NO MORE permissive: a typo in
    /// the env var, a typo in the settings file, and an absent setting must all
    /// end at the build default, never at `full`.
    #[test]
    fn mode_resolution_never_fails_open() {
        let _g = crate::IDENTITY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("alice-autoupd-mode-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::env::set_var("ALICE_IDENTITY_DIR", &dir);
        std::env::remove_var(MODE_ENV);
        let _ = std::fs::remove_file(dir.join("settings.json"));

        // 1. Nothing set anywhere → the build default (and it is not `full`).
        assert_eq!(mode(), auto::DEFAULT_MODE);
        assert_ne!(auto::DEFAULT_MODE, Mode::Full, "the default must not be the most permissive mode");
        assert!(!mode_is_explicit());

        // 2. A saved setting is honoured, and counts as an explicit choice.
        set_mode(Mode::Off).unwrap();
        assert_eq!(mode(), Mode::Off);
        assert!(mode_is_explicit());

        // 3. The env override outranks the saved setting.
        std::env::set_var(MODE_ENV, "FULL");
        assert_eq!(mode(), Mode::Full);

        // 4. A typo in the env var falls THROUGH to the saved setting (off) —
        //    it does not become "full", and it does not become the default either.
        std::env::set_var(MODE_ENV, "sure-why-not");
        assert_eq!(mode(), Mode::Off);

        // 5. A typo in the SAVED setting falls through to the build default.
        std::env::remove_var(MODE_ENV);
        crate::settings::save_auto_update("yes-obviously").unwrap();
        assert_eq!(mode(), auto::DEFAULT_MODE);
        assert!(!mode_is_explicit(), "an unparseable setting is not a choice");

        std::env::remove_var(MODE_ENV);
        std::env::remove_var("ALICE_IDENTITY_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `off` must mean off: no network, no install, nothing.
    #[test]
    fn off_mode_does_not_even_check() {
        let _g = crate::IDENTITY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var(MODE_ENV, "off");
        // No network is reachable in CI; the point is that this returns instantly
        // and quietly rather than attempting a fetch at all.
        assert_eq!(tick(false), Outcome::Quiet);
        std::env::remove_var(MODE_ENV);
    }

    #[test]
    fn hold_reasons_all_render_something_actionable() {
        let holds = [
            Hold::ModeOff,
            Hold::NotifyOnly,
            Hold::NotSecurity,
            Hold::Soaking { ready_in_s: 3600 },
            Hold::Rollout { bucket: 42, pct: 10 },
            Hold::Pinned,
            Hold::Revoked,
            Hold::NoArtifact,
            Hold::HashConflict {
                seen_sha256: "aa".repeat(32),
                now_sha256: "bb".repeat(32),
            },
        ];
        for h in holds {
            let s = describe_hold("0.6.8", &h);
            assert!(s.contains("0.6.8"), "hold line must name the version: {s}");
            assert!(s.len() > 40, "hold line must actually explain: {s}");
        }
    }

    #[test]
    fn hash_conflict_line_names_both_packages_and_refuses() {
        let s = describe_hold(
            "0.6.8",
            &Hold::HashConflict {
                seen_sha256: "aabbccddeeff00112233".into(),
                now_sha256: "ffeeddccbbaa99887766".into(),
            },
        );
        assert!(s.contains("aabbccddeeff") || s.contains("拒绝"));
        assert!(s.to_lowercase().contains("refused") || s.contains("拒绝"));
    }

    // ── F4: the layer-2 ↔ layer-3 wiring ────────────────────────────────────

    /// A halted lane abstains WITHOUT asking the network, and the network is
    /// asked only when a rollback is actually imminent.
    ///
    /// The "never asked" half is not a nicety: `note_session` runs on the mining
    /// tick, and a probe on every tick would be a request every few hundred
    /// milliseconds from every rig on the fleet.
    #[test]
    fn evidence_resolution_prefers_the_local_halt_and_asks_the_network_once() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let asked = AtomicU32::new(0);
        let counter = &asked;
        // `ask(x)` hands `resolve_evidence` a probe that records that it was called.
        let ask = move |answer: bool| {
            move || {
                counter.fetch_add(1, Ordering::Relaxed);
                answer
            }
        };
        let asked = || counter.load(Ordering::Relaxed);

        // A halted lane: not evidence, and no network call at all.
        assert_eq!(
            resolve_evidence(true, false, ask(true)),
            auto::SessionEvidence::MiningHalted
        );
        assert_eq!(
            resolve_evidence(true, true, ask(true)),
            auto::SessionEvidence::MiningHalted,
            "the local halt is conclusive on its own"
        );
        assert_eq!(asked(), 0, "a halted lane must not cost a request");

        // Nothing imminent: still no request.
        assert_eq!(
            resolve_evidence(false, false, ask(true)),
            auto::SessionEvidence::Judgeable
        );
        assert_eq!(asked(), 0, "the probe is not a per-tick call");

        // A rollback IS imminent and the whole network is down → abstain.
        assert_eq!(
            resolve_evidence(false, true, ask(true)),
            auto::SessionEvidence::NetworkWide
        );
        assert_eq!(asked(), 1);

        // …and when the network is fine, the local build stays on trial.
        assert_eq!(
            resolve_evidence(false, true, ask(false)),
            auto::SessionEvidence::Judgeable,
            "a healthy network must not suppress a real local failure"
        );
        assert_eq!(asked(), 2);
    }

    /// The predicate both front-ends use to decide "inline or worker thread".
    ///
    /// It gates a ten-second-timeout HTTP GET, and the callers are a terminal
    /// render loop and an egui frame. It must be `true` for every shape that can
    /// reach the probe and `false` for the per-tick reports — otherwise either the
    /// UI freezes or we spawn a thread twice a second.
    #[test]
    fn only_a_long_empty_unhalted_session_is_allowed_to_touch_the_network() {
        use crate::lane::Lane;
        let long = auto::MIN_JUDGED_SESSION;
        let base = MiningEvidence {
            accepted: 0,
            halted: false,
            lanes: vec![Lane::GpuPrl],
        };

        assert!(session_may_consult_the_network(long, &base));
        assert!(
            !session_may_consult_the_network(long - Duration::from_secs(1), &base),
            "a short session can never roll anything back, so it never probes"
        );
        assert!(
            !session_may_consult_the_network(
                long,
                &MiningEvidence { accepted: 1, ..base.clone() }
            ),
            "the per-tick earning report must stay inline"
        );
        assert!(
            !session_may_consult_the_network(
                long,
                &MiningEvidence { halted: true, ..base.clone() }
            ),
            "a halted lane is decided locally — no request, no thread"
        );
        assert!(
            !session_may_consult_the_network(
                long,
                &MiningEvidence { lanes: Vec::new(), ..base.clone() }
            ),
            "with no lane there is nothing to ask about"
        );
    }

    /// The two front-ends must read layer 3 out of the snapshot identically, so
    /// this derivation lives here and is tested here.
    #[test]
    fn mining_evidence_reads_the_halt_out_of_the_snapshot() {
        use crate::engine::{EngineState, LaneSnapshot, Snapshot};
        use crate::lane::Lane;

        let lane_row = |lane: Lane, halted: bool| LaneSnapshot {
            lane,
            state: EngineState::Running,
            hashrate_hs: None,
            hashrate_60s_hs: None,
            hashrate_15m_hs: None,
            shares_accepted: 0,
            shares_rejected: 0,
            uptime_s: 0,
            endpoint: None,
            failovers: 0,
            temp_c: None,
            power_w: None,
            util_pct: None,
            fan_pct: None,
            acceptance: "collapsed".to_string(),
            accept_pct: None,
            halted,
        };

        let mut s = Snapshot::idle();
        s.shares_accepted = 7;
        s.lane = Some(Lane::GpuPrl);
        s.lanes = vec![lane_row(Lane::GpuPrl, false)];
        let e = MiningEvidence::from_snapshot(&s);
        assert!(!e.halted);
        assert_eq!(e.lanes, vec![Lane::GpuPrl]);
        assert!(e.counts_as_earning(), "a running lane with accepted shares earns");

        // ANY halted lane disqualifies the session: in dual mode the accepted
        // counter can no longer be attributed to a lane that is still allowed to run.
        s.lanes = vec![lane_row(Lane::Xmr, false), lane_row(Lane::GpuPrl, true)];
        let e = MiningEvidence::from_snapshot(&s);
        assert!(e.halted);
        assert_eq!(e.lanes, vec![Lane::Xmr, Lane::GpuPrl]);
        assert!(
            !e.counts_as_earning(),
            "a frozen counter behind a halt is not proof this machine is earning"
        );

        // A snapshot with no per-lane rows still names its lane for the network check.
        s.lanes.clear();
        assert_eq!(MiningEvidence::from_snapshot(&s).lanes, vec![Lane::GpuPrl]);
        s.lane = None;
        assert!(MiningEvidence::from_snapshot(&s).lanes.is_empty());
    }

    #[test]
    fn outcome_message_is_none_only_when_quiet() {
        assert!(Outcome::Quiet.message().is_none());
        assert!(Outcome::Held {
            version: "1".into(),
            message: "m".into()
        }
        .message()
        .is_some());
    }
}
