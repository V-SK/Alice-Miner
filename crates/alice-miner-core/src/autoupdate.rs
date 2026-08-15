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

use crate::acceptance::GuardCustody;
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
    let installed = auto::installed(&dir);
    let input = auto::Input {
        manifest: &manifest,
        current,
        mode: m,
        rollout_id: &auto::rollout_id(&dir),
        now_unix: now_unix(),
        first_seen_unix: seen
            .as_ref()
            .map(|s| s.seen.first_seen_unix)
            .unwrap_or_else(now_unix),
        seen_sha256: seen.as_ref().map(|s| s.seen.sha256.as_str()),
        // Nothing to record (no package for this platform) is not a failure to
        // record; that path holds on `NoArtifact` long before this matters.
        ledger: seen
            .as_ref()
            .map(|s| s.ledger)
            .unwrap_or(auto::LedgerStatus::Intact),
        pinned: &pins,
        installed: installed.as_ref(),
        lkg_present: app_path
            .as_deref()
            .map(release::has_last_known_good)
            .unwrap_or(false),
    };

    match auto::decide(&input) {
        Decision::UpToDate => Outcome::Quiet,

        Decision::CurrentRevoked { current, newer, rollback_available } => {
            auto::log_event(
                &dir,
                "current-revoked",
                serde_json::json!({
                    "current": current,
                    "newer": newer.as_ref().map(|n| n.version.clone()),
                    "newer_visible_for_s": newer.as_ref().map(|n| n.visible_for_s),
                    "newer_inside_soak": newer.as_ref().map(|n| n.inside_soak()),
                }),
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
            Outcome::CurrentRevoked {
                message: describe_revoked(&current, &newer, reverted, rollback_available, may_act),
            }
        }

        Decision::Notify { version, hold } => {
            let message = describe_hold(&version, &hold);
            let loud = match &hold {
                // A hash conflict is never routine and is never quiet.
                Hold::HashConflict { .. } => {
                    auto::log_event(
                        &dir,
                        "hash-conflict",
                        serde_json::json!({ "version": version }),
                    );
                    true
                }
                // Nor is losing the record that check runs on. It self-heals on
                // the very next tick, so there is exactly ONE check at which this
                // can be said out loud — and suppressing it because the tick
                // happened to be a quiet one would mean nobody ever hears it.
                // (`note_seen` has already written it to the local history; it is
                // the only code that knows the reset happened.)
                Hold::LedgerReset => true,
                _ => false,
            };
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
            let baseline = earning_baseline(&dir);
            auto::log_event(
                &dir,
                "installing",
                serde_json::json!({
                    "version": version,
                    "security": security,
                    "sha256": artifact.sha256,
                    "previous_productive": baseline == auto::EarningBaseline::Earning,
                    "baseline": format!("{baseline:?}"),
                }),
            );
            match install(&dir, &artifact, &version, current, baseline) {
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
    dir: &std::path::Path,
    artifact: &release::Artifact,
    version: &str,
    previous: &str,
    baseline: auto::EarningBaseline,
) -> Result<(), String> {
    let bytes = release::download_and_verify(artifact).map_err(|e| e.to_string())?;
    let applied = release::apply_update(artifact, &bytes).map_err(|e| e.to_string())?;
    // Record the install the moment the swap lands, and BEFORE arming — never
    // before the swap, because a record of an install that did not happen would
    // hold every future check on a build this machine has not got.
    //
    // Before arming, because the probation is not this record's substitute: it is
    // discarded the first time the running version disagrees with it, which is
    // exactly the situation the record exists to survive. If the write fails we
    // say so and continue — the install itself has already succeeded, and the
    // cost is only that a re-check may repeat it.
    if !auto::note_installed(dir, version, &artifact.sha256) {
        auto::log_event(
            dir,
            "install-unrecorded",
            serde_json::json!({ "version": version }),
        );
    }
    auto::arm(&applied.app_path, version, previous, baseline).map_err(|e| e.to_string())?;
    Ok(())
}

/// What this machine knows about whether the OUTGOING build was earning.
///
/// The productive stamp alone cannot answer this, and the way it fails is the
/// specific one this release exists for. The acceptance guard (layer 3) halts a
/// lane during an upstream collapse and the stamp then freezes by design — the
/// August 2026 fork froze it for 78 hours, past the 72-hour
/// [`auto::PRODUCTIVE_WINDOW`]. A stale stamp during a halt does NOT mean "this
/// machine was not earning"; it means "this machine was not allowed to try".
///
/// So the halt is read here, from the record layer 3 persists precisely so that
/// it survives a restart. Nothing in the acceptance layer is touched or changed:
/// this is a read of a public, on-disk fact, at the one moment the arming path
/// needs it.
fn earning_baseline(dir: &std::path::Path) -> auto::EarningBaseline {
    if auto::was_recently_productive(dir) {
        return auto::EarningBaseline::Earning;
    }
    if any_lane_halted() {
        return auto::EarningBaseline::Unknown;
    }
    auto::EarningBaseline::NotEarning
}

/// Whether the acceptance guard is holding ANY lane on this machine right now.
///
/// One halted lane is enough: it is the lane whose accepted shares would have
/// refreshed the stamp, and we would rather defer a verdict we cannot reach than
/// commit a build that has never mined.
fn any_lane_halted() -> bool {
    use crate::lane::Lane;
    [Lane::Xmr, Lane::GpuPrl, Lane::GpuAlpha, Lane::GpuRvn]
        .into_iter()
        .any(|l| crate::acceptance::load_halt_record(l).is_some())
}

/// The whole withdrawal notice: what is wrong, what (if anything) there is to
/// move to, and what this machine did or did not do about it.
///
/// Three clauses, and the middle one is the load-bearing change. It used to read
/// "Install v{latest} with `alice-miner update` as soon as you can" and it was
/// generated on every machine in the fleet the moment a `revoked` list arrived.
fn describe_revoked(
    current: &str,
    newer: &Option<auto::NewerRelease>,
    reverted: bool,
    rollback_available: bool,
    may_act: bool,
) -> String {
    let tail = if reverted {
        tr!(
            "The previous version has been restored on disk — restart alice-miner to run it. This process is still the withdrawn build.",
            "上一个版本已恢复到磁盘 —— 请重启 alice-miner 以运行它。当前进程仍是被撤回的版本。"
        ).to_string()
    } else if rollback_available && may_act {
        // We were allowed to act, a copy was there, and the restore still did
        // not happen. Saying "nothing was changed because of a setting" here
        // would blame a setting for a failure — the same class of half-truth the
        // rollback notices are careful to avoid.
        tr!(
            "A previous version is on this machine but it could NOT be restored automatically. Reinstall the previous release yourself from {url}.",
            "本机保留有上一个版本,但无法自动恢复。请自行从 {url} 重新安装上一个版本。"
        ).replace("{url}", release::RELEASES_PAGE_URL)
    } else if rollback_available {
        // The load-bearing correction: this client is HOLDING the copy it would
        // put back, and the only thing stopping it is a setting the reader can
        // change. Telling them to go and reinstall by hand — as the "nowhere
        // forward to go" clause used to — sends someone running a build we have
        // just called dangerous off to do manually what one command would do.
        tr!(
            "A previous version is still on this machine and this client can restore it, but this machine is set not to install anything on its own, so nothing was changed. Allow it with `alice-miner update --auto security-only` and it will roll back on the next check.",
            "本机仍保留上一个版本,客户端也能把它装回去,但本机设置为不自动安装任何东西,因此未做任何更改。可运行 `alice-miner update --auto security-only` 允许它,下次检查时便会自动回滚。"
        ).to_string()
    } else {
        tr!(
            "There is no previous version on this machine to fall back to.",
            "本机没有可回退的旧版本。"
        ).to_string()
    };
    [
        tr!(
            format!("⚠ WARNING: v{current} has been WITHDRAWN by the publisher — do not keep running it."),
            format!("⚠ 警告:v{current} 已被发布方撤回 —— 请不要继续运行它。")
        ),
        describe_forward(newer, reverted, rollback_available),
        tail,
    ]
    .iter()
    .filter(|s| !s.is_empty())
    .cloned()
    .collect::<Vec<_>>()
    .join(" ")
}

/// After a withdrawal: what — if anything — there is to move TO, stated as
/// facts and never as an instruction.
///
/// A withdrawal notice is the one message we send that arrives sounding urgent
/// and carrying our voice on every machine at once, and under key compromise the
/// attacker writes the `revoked` list that triggers it. An instruction here
/// ("install vNEW as soon as you can") would therefore be OUR contribution to
/// the attack: it collapses the soak window from a day to however long it takes
/// someone to read a line of text, on a version they have no reason to distrust
/// because we just told them to take it. So this says what is true and stops.
fn describe_forward(
    newer: &Option<auto::NewerRelease>,
    reverted: bool,
    rollback_available: bool,
) -> String {
    match newer {
        // F2b — the ordinary case: we shipped it, it is bad, we pulled it. The
        // withdrawn build IS the newest published version, so there is nowhere
        // forward to go and we must not pretend there is.
        None if reverted => {
            // The tail already says the previous build is back on disk. Pointing
            // at the releases page on top of that would be noise.
            String::new()
        }
        // Nowhere forward, but a last-known-good copy IS here. What to do about
        // it is entirely the tail's business (it knows whether the client is
        // allowed to use that copy, and whether it tried and failed), so this
        // clause states the one fact it owns and stops. It must NOT say "this
        // client cannot put it back for you": in this branch the client is
        // holding the copy, and that sentence would be false as well as
        // discouraging.
        None if rollback_available => tr!(
            "There is no newer version to move to — the withdrawn build is the newest one published.",
            "没有可以升级过去的更新版本 —— 被撤回的就是当前最新发布版本。"
        )
        .to_string(),
        None => tr!(
            format!("There is no newer version to move to — the withdrawn build is the newest one published. Leaving it means reinstalling the previous release yourself from {url}; this client cannot put it back for you from here.", url = release::RELEASES_PAGE_URL),
            format!("没有可以升级过去的更新版本 —— 被撤回的就是当前最新发布版本。要离开它,需要你自己从 {url} 重新安装上一个版本;客户端无法在这里替你装回去。", url = release::RELEASES_PAGE_URL)
        ),
        Some(n) if n.inside_soak() => {
            let v = &n.version;
            let age = age_phrase(n.visible_for_s);
            tr!(
                format!("A newer version v{v} exists, but this machine has only been able to see it for {age} — less than the day this client waits before it will trust a new build on its own. Installing it right now is NOT advised, and nothing here will install it for you."),
                format!("存在更新的版本 v{v},但本机只见到它 {age} —— 短于本客户端自动信任一个新版本所需的一天。现在就安装并不可取,本机也不会替你安装。")
            )
        }
        Some(n) => {
            let v = &n.version;
            let age = age_phrase(n.visible_for_s);
            tr!(
                format!("A newer version v{v} exists and this machine has been able to see it for {age}. What to do next is your call: a withdrawal says something is wrong with the build you have, not which build you should take instead."),
                format!("存在更新的版本 v{v},本机已见到它 {age}。接下来怎么做由你决定:撤回说明的是你手上这个版本有问题,而不是你接下来该换成哪个版本。")
            )
        }
    }
}

/// A rough, honest age. Rough on purpose — the reader needs "minutes" versus
/// "days", and a precise number would imply a precision the local clock does not
/// have.
fn age_phrase(secs: u64) -> String {
    if secs < 60 {
        return tr!("less than a minute", "不到一分钟").to_string();
    }
    if secs < 90 * 60 {
        let n = secs / 60;
        return tr!(format!("{n} minutes"), format!("{n} 分钟"));
    }
    if secs < 48 * 3600 {
        let n = secs / 3600;
        return tr!(format!("{n} hours"), format!("{n} 小时"));
    }
    let n = secs / (24 * 3600);
    tr!(format!("{n} days"), format!("{n} 天"))
}

/// One honest line for every reason we did not install something.
///
/// A hold is not a problem to be worked around, and the line that reports it
/// must not read as one. Three of these exist because the user CHOSE a quieter
/// setting (`ModeOff`, `NotifyOnly`, `NotSecurity`) and for those, "run
/// `alice-miner update`" genuinely is the remedy — it is the thing their setting
/// asked us to leave to them. The rest exist for a safety reason: the soak
/// window, the staged rollout and the failure pin are the guardrails, and a line
/// that ends by offering the command to skip them is our own copy walking the
/// user off the guarded path onto the unguarded one. Those lines still say the
/// command exists — hiding it would be its own dishonesty — but they say what
/// using it costs, and they never present it as the fix.
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
                format!("v{version} is available. Nothing is wrong and there is nothing to do: this machine waits a day before installing a new version on its own, so that problems are found on the machines that took it first (~{h}h to go). `alice-miner update` would install it immediately, which is you taking that first look instead of waiting for it."),
                format!("有新版本 v{version}。一切正常,你无需做任何事:本机会先等待一天再自动安装新版本,好让问题先在最早安装的机器上暴露(还剩约 {h} 小时)。`alice-miner update` 可以立刻安装,那等于由你来当第一批试用者,而不是等别人先试。")
            )
        }
        Hold::Rollout { bucket, pct } => tr!(
            format!("v{version} is available and is going to {pct}% of machines first; this one is in group {bucket} and is not in that slice yet. Nothing is wrong and there is nothing to do — a staged rollout exists so a bad build stops at the first slice instead of reaching everyone. `alice-miner update` would install it immediately, which opts this machine out of that."),
            format!("有新版本 v{version},正在先向 {pct}% 的机器放量;本机分组为 {bucket},尚未轮到。一切正常,你无需做任何事 —— 分批放量的意义在于让有问题的版本止步于第一批,而不是一次铺到所有人。`alice-miner update` 可以立刻安装,那等于让本机退出这一保护。")
        ),
        Hold::Pinned => tr!(
            format!("v{version} is available, but this machine installed it before and rolled it back automatically, so it will not install it again on its own. That is a record of something having gone wrong here, not a formality. `alice-miner update` can retry it if you have reason to think it will behave differently this time — it will ask you again first."),
            format!("有新版本 v{version},但本机曾安装它并自动回滚过,因此不会再自动安装。那是本机确实出过问题的记录,不是走过场。若你有理由认为这次会不同,可以用 `alice-miner update` 重试 —— 它会再次向你确认。")
        ),
        Hold::Revoked => tr!(
            format!("v{version} is the newest published version but the publisher has WITHDRAWN it. It will not be installed."),
            format!("v{version} 是最新发布版本,但已被发布方撤回,不会被安装。")
        ),
        Hold::NoArtifact => tr!(
            format!("v{version} is available but ships no package for this platform — download it manually from the releases page."),
            format!("有新版本 v{version},但没有适用于本平台的安装包 —— 请从发布页手动下载。")
        ),
        Hold::LedgerUnwritable => tr!(
            format!("v{version} is available but was NOT installed automatically: this machine could not write its update ledger, so it cannot remember which package a version number arrived with — the check that catches a version being re-published with different bytes. Fix the permissions on the alice-miner data directory (or free some disk) and it will resume on its own. `alice-miner update` still works and will say the same thing before it installs anything."),
            format!("有新版本 v{version},但未自动安装:本机无法写入更新台账,也就记不住某个版本号当初对应的安装包 —— 那正是用来发现「同一版本号换了字节」的检查。请修复 alice-miner 数据目录的权限(或清出磁盘空间),之后会自动恢复。`alice-miner update` 仍可使用,并会在安装前给出同样的提示。")
        ),
        Hold::AlreadyInstalled { installed_ago_s } => {
            let age = age_phrase(*installed_ago_s);
            // Under a day this is simply the ordinary state of affairs: the swap
            // is on disk and the process running it has not started yet. Past
            // that, on a machine that is plainly being restarted and still
            // reports the old version, the honest reading is different — and
            // saying "restart to run it" for the tenth day running would be the
            // client insisting on something the machine has already disproved.
            if *installed_ago_s < 24 * 3600 {
                tr!(
                    format!("v{version} is already installed on this machine ({age} ago) and runs the next time you start alice-miner. Your current session was not interrupted and there is nothing to do."),
                    format!("v{version} 已安装到本机({age}前),下次启动 alice-miner 时生效。当前会话未被打断,你无需做任何事。")
                )
            } else {
                tr!(
                    format!("v{version} was installed on this machine {age} ago, but this program is still reporting an older version, so it has NOT been installed again. If you have restarted alice-miner since then, the installed build is not reporting the version it was published under — that is a fault at our end, not yours: please report it. Until it is sorted out this machine stays on the version it is running, which is the safe direction."),
                    format!("v{version} 已在 {age}前安装到本机,但本程序报告的仍是更旧的版本,因此没有重复安装。如果你在那之后重启过 alice-miner,说明安装上去的版本并未报告它发布时的版本号 —— 这是我方的问题,不是你的:请上报。在弄清之前,本机会停留在当前运行的版本,这是安全的方向。")
                )
            }
        }
        Hold::LedgerReset => tr!(
            format!("v{version} is available but was NOT installed automatically this time: this machine's update ledger could not be read, so what it remembered — which package each version number arrived with — is gone. The old file has been kept as `update-seen.json.unreadable` and a fresh ledger starts from what the server offered just now. Nothing here is yours to fix and nothing is wrong with this machine's disk. What is missing is the comparison that catches a version being re-published with different bytes, and it has nothing to compare against for v{version} any more, so this install waits and the version soaks again from today. `alice-miner update` still works and will say the same thing before it installs anything."),
            format!("有新版本 v{version},但这次未自动安装:本机的更新台账读不出来,它记住的东西 —— 每个版本号当初对应哪个安装包 —— 已经没了。原文件已保留为 `update-seen.json.unreadable`,新的台账从服务器刚才给出的内容重新开始。这不需要你做什么,本机磁盘也没有问题。缺的是用来发现「同一版本号被换成不同字节」的那次比对,它对 v{version} 已无可比之物,因此本次安装暂缓,该版本从今天起重新计算观察期。`alice-miner update` 仍可使用,并会在安装前给出同样的提示。")
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

// ────────────────────────────────────────────────────────────────────────────
// The MANUAL path — same guardrails, one driver, both front-ends
//
// `alice-miner update` and the GUI's "Update now" used to be the way around
// every check in this file. The automatic path refused a version whose bytes had
// changed under a fixed version number; the manual path downloaded it. The
// automatic path anchored a soak window on this machine's own first sighting;
// the manual path never recorded a sighting at all, so a version installed by
// hand left no trace for the NEXT check to compare against.
//
// This is the one place both front-ends run those checks, for the same reason
// `tick` is the one place they run the automatic ones (AM-REL-009: two copies of
// an update flow is how one front-end ends up with a safety mechanism the other
// does not have).
// ────────────────────────────────────────────────────────────────────────────

/// What the manual path may do, already phrased for a human.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManualOutcome {
    /// Nothing known stands in the way. The caller's ordinary confirmation
    /// (or `--yes`, or a click) is enough.
    Proceed,
    /// Do NOT install. Not with `--yes`, not with a click, not at all.
    Refuse { message: String },
    /// Install only after a SEPARATE, explicit, interactive confirmation that
    /// names this. A "don't ask me" flag must never satisfy it.
    Confirm { message: String },
}

/// The result of running the manual guardrails, including the facts the
/// automatic path uses so the person choosing has the same ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualCheck {
    pub outcome: ManualOutcome,
    /// One line saying how long this machine has been able to see this version.
    /// `None` only when there is no package for this platform, so there was no
    /// sighting to record.
    pub visibility: Option<String>,
    /// Seconds this machine has been able to see the version.
    pub visible_for_s: u64,
    /// Whether that is still inside the soak floor the automatic path enforces.
    pub inside_soak: bool,
}

/// Run the manual path's guardrails and record the sighting.
///
/// Two things happen here and the order matters. First the sighting is recorded,
/// exactly as `tick` does it, so that a version installed by hand still starts
/// this machine's local soak clock and still pins the bytes we saw it carrying —
/// a manual install that left no record would blind the next automatic check.
/// Then the pure gate runs against that record.
///
/// What this deliberately does NOT enforce: the soak window, the rollout slice
/// and the mode. Those are statements about how eager the machine may be without
/// being asked, and someone typing the command has answered all three. They are
/// REPORTED instead ([`ManualCheck::visibility`]), because a person installing a
/// version twenty minutes old should know that is what they are doing.
pub fn manual_check(
    manifest: &release::Manifest,
    artifact: Option<&release::Artifact>,
    current: &str,
) -> ManualCheck {
    let dir = state_dir();
    // The ledger is keyed by (version, platform artifact hash). With no artifact
    // for this platform there is no hash to record, and writing a placeholder
    // would poison the append-only ledger with bytes we never saw.
    let seen = artifact.map(|a| auto::note_seen(&dir, &manifest.version, &a.sha256));
    let visible_for_s = seen
        .as_ref()
        .map(|s| {
            auto::visible_for(
                now_unix(),
                auto::soak_anchor(s.seen.first_seen_unix, manifest.released_unix()),
            )
        })
        .unwrap_or(0);
    let inside_soak = auto::inside_soak(visible_for_s);
    let pins = auto::pins(&dir);
    let installed = auto::installed(&dir);
    let verdict = auto::decide_manual(&auto::ManualInput {
        manifest,
        current,
        artifact_sha256: artifact.map(|a| a.sha256.as_str()),
        seen_sha256: seen.as_ref().map(|s| s.seen.sha256.as_str()),
        ledger: seen
            .as_ref()
            .map(|s| s.ledger)
            .unwrap_or(auto::LedgerStatus::Intact),
        pinned: &pins,
        installed: installed.as_ref(),
    });

    let version = &manifest.version;
    let outcome = match verdict {
        auto::ManualVerdict::Proceed => ManualOutcome::Proceed,
        auto::ManualVerdict::Refuse(auto::ManualRefusal::HashConflict {
            seen_sha256,
            now_sha256,
        }) => {
            auto::log_event(
                &dir,
                "manual-hash-conflict",
                serde_json::json!({
                    "version": version,
                    "seen_sha256": seen_sha256,
                    "now_sha256": now_sha256,
                }),
            );
            let first = short(&seen_sha256);
            let now = short(&now_sha256);
            ManualOutcome::Refuse {
                message: tr!(
                    format!("REFUSED to install v{version}: this machine first saw that version with package {first}, and the server is now offering {now} under the SAME version number. Nothing was downloaded. This is not something to click past — a version number that changes its bytes is either a mistake on our side or someone else signing with our key, and neither is fixed by installing it. Report it, and take a version with a different number."),
                    format!("已拒绝安装 v{version}:本机首次见到该版本时安装包是 {first},而服务器现在以同一个版本号提供 {now}。没有下载任何内容。这不是点一下就能跳过的事 —— 同一个版本号换了字节,要么是我方出错,要么是别人拿着我们的密钥在签名,而这两种情况都不会因为你装上去而变好。请上报,并改装一个版本号不同的版本。")
                ),
            }
        }
        auto::ManualVerdict::Refuse(auto::ManualRefusal::NotNewer { offered, current }) => {
            auto::log_event(
                &dir,
                "manual-downgrade-refused",
                serde_json::json!({ "offered": offered, "current": current }),
            );
            ManualOutcome::Refuse {
                message: tr!(
                    format!("REFUSED to install v{offered}: it is not newer than the v{current} this machine is already running, and `update` never means going backwards. Nothing was downloaded. If a manifest is offering an older build as a required upgrade, that is either a mistake on our side or someone else signing with our key — report it. A downgrade you genuinely want is a manual install from the releases page, not an update."),
                    format!("已拒绝安装 v{offered}:它并不比本机正在运行的 v{current} 更新,而 `update` 从来不是往回退。没有下载任何内容。如果清单把一个更旧的版本当作必须升级的目标,要么是我方出错,要么是别人拿着我们的密钥在签名 —— 请上报。若你确实想降级,请到发布页手动安装,而不是走更新。")
                ),
            }
        }
        auto::ManualVerdict::Refuse(auto::ManualRefusal::Revoked) => ManualOutcome::Refuse {
            message: tr!(
                format!("v{version} has been WITHDRAWN by the publisher and will not be installed."),
                format!("v{version} 已被发布方撤回,不会被安装。")
            ),
        },
        auto::ManualVerdict::ConfirmFirst(auto::ManualConcern::Pinned) => ManualOutcome::Confirm {
            message: tr!(
                format!("this machine installed v{version} before and rolled it back automatically, because it either failed to start or stopped landing accepted shares here."),
                format!("本机曾安装过 v{version} 并自动回滚,原因是它要么无法启动,要么在本机不再有被接受的份额。")
            ),
        },
        auto::ManualVerdict::ConfirmFirst(auto::ManualConcern::AlreadyInstalled) => {
            ManualOutcome::Confirm {
                message: tr!(
                    format!("this machine has already installed v{version} — it takes effect the next time you start alice-miner, and there is nothing to download. Applying it a second time replaces the copy this machine would roll back to (the version you are running now) with v{version} itself, so if v{version} then fails there is nothing left to go back to."),
                    format!("本机已经安装过 v{version} —— 下次启动 alice-miner 时即生效,无需再下载。再装一次会把本机用于回滚的那份副本(也就是你现在运行的版本)替换成 v{version} 自己,那样一来若 v{version} 出问题,就没有可回退的版本了。")
                ),
            }
        }
        auto::ManualVerdict::ConfirmFirst(auto::ManualConcern::LedgerReset) => {
            auto::log_event(
                &dir,
                "ledger-reset-manual",
                serde_json::json!({ "version": version }),
            );
            ManualOutcome::Confirm {
                message: tr!(
                    "this machine's update ledger could not be read and has been replaced, so what it remembered — which package each version number arrived with — is gone. The old file was kept as `update-seen.json.unreadable`. The check that catches the same version being re-published with different bytes has nothing to compare this version against any more; it will work again for versions seen from now on.",
                    "本机的更新台账读不出来,已被替换,它记住的东西 —— 每个版本号当初对应哪个安装包 —— 已经没了。原文件保留为 `update-seen.json.unreadable`。用于发现「同一版本号被换成不同字节」的检查,对这个版本已无可比之物;从现在起新见到的版本会重新受它保护。"
                )
                .to_string(),
            }
        }
        auto::ManualVerdict::ConfirmFirst(auto::ManualConcern::UnrecordedSighting) => {
            auto::log_event(
                &dir,
                "ledger-unwritable",
                serde_json::json!({ "version": version }),
            );
            ManualOutcome::Confirm {
                message: tr!(
                    "this machine could not write its update ledger, so it cannot remember which package this version number arrived with. The check that catches the same version being re-published with different bytes is not running here, and will not run on the next install either. Fixing the permissions on the alice-miner data directory (or freeing disk space) restores it.",
                    "本机无法写入更新台账,因而记不住这个版本号当初对应的是哪个安装包。用于发现「同一版本号被换成不同字节」的检查在本机没有生效,下次安装时同样不会生效。修复 alice-miner 数据目录的权限(或清出磁盘空间)即可恢复。"
                )
                .to_string(),
            }
        }
    };

    let visibility = seen.as_ref().map(|_| {
        let age = age_phrase(visible_for_s);
        if inside_soak {
            tr!(
                format!("This machine first saw v{version} {age} ago. The automatic updater waits a day before trusting a new version on its own, so installing it now means you are looking at it first rather than after other machines have."),
                format!("本机首次见到 v{version} 已过去 {age}。自动更新会先等待一天才信任一个新版本,所以现在安装意味着由你先行试用,而不是等别的机器先试。")
            )
        } else {
            tr!(
                format!("This machine has been able to see v{version} for {age} — past the day the automatic updater waits."),
                format!("本机见到 v{version} 已有 {age} —— 已超过自动更新等待的一天。")
            )
        }
    });

    ManualCheck {
        outcome,
        visibility,
        visible_for_s,
        inside_soak,
    }
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

/// The binary loaded and parsed its command line — enough to rule out
/// crash-on-launch, and NOT enough to commit the update. Best-effort.
pub fn note_launch_ok() {
    if let Ok(app_path) = release::current_app_path() {
        auto::note_launch_ok(&app_path, release::current_version());
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
    /// What layer 3 is doing with this session's lanes, folded to the strongest
    /// answer across them ([`GuardCustody::strongest`]).
    ///
    /// This replaced a bare `halted: bool`, and the replacement IS the F4 fix. The
    /// boolean answered "is the engine stopped by the guard?"; layer 2 needs the
    /// answer to "is this session's zero the guard's doing?", and those diverge for
    /// the entire length of a re-probe — a run that deliberately clears `halted` (its
    /// child could not otherwise start) and deliberately earns nothing while it
    /// measures. Reading the boolean there rolled v0.6.8 back and pinned it during
    /// exactly the upstream fork it was released to survive.
    pub activity: GuardCustody,
    /// At least one of this session's lanes is one the acceptance guard has reached
    /// NO verdict about — warm-up, an incomplete period, or an engine that cannot
    /// report pool rejections at all
    /// ([`crate::acceptance::verdict_key_is_conclusive`]).
    ///
    /// This is the second half of the F4 question, and [`Self::activity`] cannot
    /// carry it. Custody says who OWNS the lane, and the guard only takes custody
    /// AFTER it has concluded something — which needs a full window AND twenty
    /// submissions, i.e. hours on a slow rig and never at all on a lane whose relay
    /// is unreachable. Between "the pool is rejecting everything" and "the guard can
    /// say so", custody honestly reports `Mining` and the session is a plain
    /// zero-accepted stretch: two of those roll the build back and pin it forever,
    /// and the network-wide backstop cannot intervene because `LaneHealth::attribute`
    /// answers `Unknown`, never `NetworkWide`, for a single-miner lane.
    ///
    /// `false` is the wire/`Default` answer — "nothing says we are undecided" — so a
    /// snapshot that carries no lane rows behaves exactly as it did before.
    pub guard_undecided: bool,
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
            // `LaneSnapshot::activity()` folds in the older `halted` flag, so a lane
            // row from a stream that predates the field still disqualifies its session.
            activity: s
                .lanes
                .iter()
                .fold(GuardCustody::Mining, |acc, l| acc.strongest(l.activity())),
            // ANY lane the guard has not judged makes the session's zero unmeasured.
            // The lane row already carries the verdict key, so nothing new goes on the
            // wire; an unreadable key counts as undecided (see the classifier).
            guard_undecided: s
                .lanes
                .iter()
                .any(|l| !crate::acceptance::verdict_key_is_conclusive(&l.acceptance)),
            lanes: if s.lanes.is_empty() {
                s.lane.into_iter().collect()
            } else {
                s.lanes.iter().map(|l| l.lane).collect()
            },
        }
    }

    /// Whether this session may be held against — or credited to — the installed
    /// build at all. False whenever layer 3 owns a lane, in either of its two ways.
    ///
    /// Deliberately NOT widened to cover [`Self::guard_undecided`]. An undecided lane
    /// is being mined normally: its accepted shares are real and must still commit a
    /// probation and refresh the earning baseline ([`Self::counts_as_earning`]). It is
    /// only its ZERO that means nothing, and that asymmetry is resolved one layer up,
    /// in [`resolve_evidence`], where the share count is in scope.
    pub fn judges_the_build(&self) -> bool {
        self.activity.is_ordinary_mining()
    }

    /// Whether this counts as "this machine is earning" for the purposes of the
    /// baseline a FUTURE update is judged against. A halted lane's frozen counter
    /// is not evidence of current earning, however large it is; nor is a re-probe's,
    /// which is a measurement the guard asked for rather than a session the machine
    /// chose to run.
    pub fn counts_as_earning(&self) -> bool {
        self.accepted > 0 && self.judges_the_build()
    }
}

/// Decide what layer 3 says about the session being reported.
///
/// Split out and pure (bar the caller-supplied probe) so the *order* of the two
/// guards is testable: a halted lane abstains without ever touching the network,
/// and the network is asked ONLY when a rollback is otherwise imminent — never
/// once per tick.
///
/// [`evidence_for_session`] is the same decision taken on a whole [`MiningEvidence`];
/// [`note_session`] and the cross-layer tests both go through it, so a test can never
/// assert against a classification that has drifted from the shipped one.
pub(crate) fn evidence_for_session(
    mining: &MiningEvidence,
    rollback_imminent: bool,
    network_wide: impl FnOnce() -> bool,
) -> auto::SessionEvidence {
    resolve_evidence(
        mining.activity,
        mining.guard_undecided,
        mining.accepted,
        rollback_imminent,
        network_wide,
    )
}

fn resolve_evidence(
    activity: GuardCustody,
    guard_undecided: bool,
    accepted: u64,
    rollback_imminent: bool,
    network_wide: impl FnOnce() -> bool,
) -> auto::SessionEvidence {
    // 1. Custody. Exhaustive, no wildcard: a lane state that is neither ordinary
    //    mining nor one of these two must be classified here rather than falling
    //    through to "judgeable", which is the direction that costs a machine its
    //    build. Checked first because it holds even WITH accepted shares on the
    //    clock — a halted lane's counter is frozen, and a probe's belongs to the
    //    guard's measurement, not to the session.
    match activity {
        GuardCustody::Halted => return auto::SessionEvidence::MiningHalted,
        GuardCustody::Probing => return auto::SessionEvidence::AcceptanceProbe,
        GuardCustody::Mining => {}
    }
    // 2. A real accepted share on a lane that is mining on its own account is proof
    //    the build works, whatever the guard has or has not concluded — and it is the
    //    one outcome that ends a trial honestly. It must be reached BEFORE the
    //    undecided gate below, or a slow rig that is quietly earning would abstain
    //    forever instead of committing.
    if accepted > 0 {
        return auto::SessionEvidence::Judgeable;
    }
    // 3. Nothing accepted — so the question is whether that zero MEANS anything, and
    //    it does not until the guard has judged a period. `Gathering`, `Warmup` and
    //    "this engine cannot report rejections" are all the client not knowing, and
    //    the client must not act as though it does.
    if guard_undecided {
        return auto::SessionEvidence::AcceptanceUndecided;
    }
    // 4. A measured zero, about to cost the build its life: this is the one moment
    //    worth a network round-trip.
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
/// reports — a session with accepted shares, a short one, a halted lane, a lane the
/// guard has reached no verdict about — are all `false` here and stay inline.
pub fn session_may_consult_the_network(ran: Duration, mining: &MiningEvidence) -> bool {
    mining.judges_the_build()
        && !mining.guard_undecided
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
        && mining.judges_the_build()
        && auto::session_would_roll_back(
            &app_path,
            version,
            &auto::SessionResult::judgeable(ran_secs, 0),
        );
    let evidence = evidence_for_session(mining, rollback_imminent, || {
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
            Hold::LedgerUnwritable,
            Hold::LedgerReset,
            Hold::AlreadyInstalled { installed_ago_s: 4 * 3600 },
            Hold::AlreadyInstalled { installed_ago_s: 9 * 24 * 3600 },
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

        // `guard_undecided`: false everywhere below except where the case is about it.
        const DECIDED: bool = false;

        // A halted lane: not evidence, and no network call at all.
        assert_eq!(
            resolve_evidence(GuardCustody::Halted, DECIDED, 0, false, ask(true)),
            auto::SessionEvidence::MiningHalted
        );
        assert_eq!(
            resolve_evidence(GuardCustody::Halted, DECIDED, 0, true, ask(true)),
            auto::SessionEvidence::MiningHalted,
            "the local halt is conclusive on its own"
        );
        assert_eq!(asked(), 0, "a halted lane must not cost a request");

        // A RE-PROBE is the case the old boolean could not express: the engine is up,
        // the halt flag is off, and the run is measuring rather than earning. It must
        // abstain on local knowledge alone — the network check cannot save it, because
        // `attribute()` answers `Unknown` (never `NetworkWide`) for a single-miner lane,
        // and PRL is a single-miner lane.
        assert_eq!(
            resolve_evidence(GuardCustody::Probing, DECIDED, 0, true, ask(true)),
            auto::SessionEvidence::AcceptanceProbe,
            "a deliberate measurement is never evidence about the installed build"
        );
        assert_eq!(asked(), 0, "and it costs no request either");

        // Nothing imminent: still no request.
        assert_eq!(
            resolve_evidence(GuardCustody::Mining, DECIDED, 0, false, ask(true)),
            auto::SessionEvidence::Judgeable
        );
        assert_eq!(asked(), 0, "the probe is not a per-tick call");

        // A rollback IS imminent and the whole network is down → abstain.
        assert_eq!(
            resolve_evidence(GuardCustody::Mining, DECIDED, 0, true, ask(true)),
            auto::SessionEvidence::NetworkWide
        );
        assert_eq!(asked(), 1);

        // …and when the network is fine, the local build stays on trial.
        assert_eq!(
            resolve_evidence(GuardCustody::Mining, DECIDED, 0, true, ask(false)),
            auto::SessionEvidence::Judgeable,
            "a healthy network must not suppress a real local failure"
        );
        assert_eq!(asked(), 2);

        // Every activity is classified, and ONLY ordinary mining is judgeable — so a
        // future variant cannot be added and silently fall through to "judge it".
        for a in GuardCustody::ALL {
            let e = resolve_evidence(a, DECIDED, 0, false, ask(false));
            assert_eq!(
                e.abstains(),
                !a.is_ordinary_mining(),
                "{a:?} must abstain iff it is not ordinary mining"
            );
        }
    }

    /// **The hole the custody fix did not cover: a lane the guard has NOT concluded
    /// about.**
    ///
    /// Custody can only report `Probing`/`Halted` once a halt exists, and a halt needs
    /// a completed period — ten minutes AND twenty submissions. Below roughly one
    /// submission a minute that takes hours, and a lane whose relay is unreachable
    /// never gets there at all. Meanwhile two 20-minute zero-accepted sessions roll a
    /// build back and pin it permanently, and the network-wide backstop cannot save it
    /// (`LaneHealth::attribute` answers `Unknown`, never `NetworkWide`, for a
    /// single-miner lane — and PRL is one).
    ///
    /// So an undecided lane's ZERO must abstain, without a network call, while an
    /// accepted share on the same lane must still be judged (and committed).
    #[test]
    fn a_lane_the_guard_has_not_judged_is_not_evidence_against_the_build_either() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let asked = AtomicU32::new(0);
        let counter = &asked;
        let ask = move |answer: bool| {
            move || {
                counter.fetch_add(1, Ordering::Relaxed);
                answer
            }
        };
        let asked = || counter.load(Ordering::Relaxed);
        const UNDECIDED: bool = true;

        // The exact shape that used to uninstall v0.6.8: mining normally, nothing
        // accepted, a rollback one report away — and the guard with nothing to say.
        assert_eq!(
            resolve_evidence(GuardCustody::Mining, UNDECIDED, 0, true, ask(true)),
            auto::SessionEvidence::AcceptanceUndecided
        );
        assert_eq!(asked(), 0, "decided locally — a single-miner lane cannot be asked about");
        assert!(auto::SessionEvidence::AcceptanceUndecided.abstains());

        // An accepted share ends the trial honestly, undecided or not. This is the
        // gate that keeps a slow-but-earning rig from abstaining forever.
        assert_eq!(
            resolve_evidence(GuardCustody::Mining, UNDECIDED, 1, false, ask(true)),
            auto::SessionEvidence::Judgeable,
            "a real accepted share is proof about the build regardless of the verdict"
        );
        assert_eq!(asked(), 0);

        // Custody still outranks it: a halted or probing lane's counter is not the
        // session's to spend, however many shares it shows.
        for (a, want) in [
            (GuardCustody::Halted, auto::SessionEvidence::MiningHalted),
            (GuardCustody::Probing, auto::SessionEvidence::AcceptanceProbe),
        ] {
            assert_eq!(resolve_evidence(a, UNDECIDED, 99, true, ask(true)), want, "{a:?}");
        }
        assert_eq!(asked(), 0);
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
            activity: GuardCustody::Mining,
            guard_undecided: false,
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
        for a in [GuardCustody::Halted, GuardCustody::Probing] {
            assert!(
                !session_may_consult_the_network(
                    long,
                    &MiningEvidence { activity: a, ..base.clone() }
                ),
                "{a:?} is decided locally — no request, no thread"
            );
        }
        assert!(
            !session_may_consult_the_network(
                long,
                &MiningEvidence { lanes: Vec::new(), ..base.clone() }
            ),
            "with no lane there is nothing to ask about"
        );
        assert!(
            !session_may_consult_the_network(
                long,
                &MiningEvidence { guard_undecided: true, ..base.clone() }
            ),
            "a lane the guard has not judged abstains locally — no request, no thread"
        );
    }

    /// The two front-ends must read layer 3 out of the snapshot identically, so
    /// this derivation lives here and is tested here.
    #[test]
    fn mining_evidence_reads_the_halt_out_of_the_snapshot() {
        use crate::engine::{EngineState, LaneSnapshot, Snapshot};
        use crate::lane::Lane;

        let lane_row = |lane: Lane, activity: GuardCustody| LaneSnapshot {
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
            halted: activity == GuardCustody::Halted,
            activity,
        };

        let mut s = Snapshot::idle();
        s.shares_accepted = 7;
        s.lane = Some(Lane::GpuPrl);
        s.lanes = vec![lane_row(Lane::GpuPrl, GuardCustody::Mining)];
        let e = MiningEvidence::from_snapshot(&s);
        assert!(e.judges_the_build());
        assert_eq!(e.lanes, vec![Lane::GpuPrl]);
        assert!(e.counts_as_earning(), "a running lane with accepted shares earns");

        // ANY halted lane disqualifies the session: in dual mode the accepted
        // counter can no longer be attributed to a lane that is still allowed to run.
        s.lanes = vec![
            lane_row(Lane::Xmr, GuardCustody::Mining),
            lane_row(Lane::GpuPrl, GuardCustody::Halted),
        ];
        let e = MiningEvidence::from_snapshot(&s);
        assert_eq!(e.activity, GuardCustody::Halted);
        assert!(!e.judges_the_build());
        assert_eq!(e.lanes, vec![Lane::Xmr, Lane::GpuPrl]);
        assert!(
            !e.counts_as_earning(),
            "a frozen counter behind a halt is not proof this machine is earning"
        );

        // …and so does a lane that is merely RE-PROBING, which is the one the old
        // `halted` boolean reported as an ordinary miner earning nothing.
        s.lanes = vec![
            lane_row(Lane::Xmr, GuardCustody::Mining),
            lane_row(Lane::GpuPrl, GuardCustody::Probing),
        ];
        let e = MiningEvidence::from_snapshot(&s);
        assert_eq!(e.activity, GuardCustody::Probing);
        assert!(!e.judges_the_build(), "a measurement is not evidence about the build");
        assert!(!e.counts_as_earning());

        // An OLDER `--json` stream carries `halted` and no `activity` at all. It must
        // still disqualify: the two fields can only ever agree upward.
        let mut legacy = lane_row(Lane::GpuPrl, GuardCustody::Mining);
        legacy.halted = true;
        assert_eq!(legacy.activity(), GuardCustody::Halted);
        s.lanes = vec![legacy];
        assert!(!MiningEvidence::from_snapshot(&s).judges_the_build());

        // A snapshot with no per-lane rows still names its lane for the network check.
        s.lanes.clear();
        assert_eq!(MiningEvidence::from_snapshot(&s).lanes, vec![Lane::GpuPrl]);
        s.lane = None;
        assert!(MiningEvidence::from_snapshot(&s).lanes.is_empty());
        assert!(
            !MiningEvidence::from_snapshot(&s).guard_undecided,
            "no lane rows must behave exactly as it did before this field existed"
        );
    }

    /// The verdict half of the same derivation: whether the guard has CONCLUDED
    /// anything about each lane, read out of the key the lane row already carries.
    #[test]
    fn mining_evidence_reads_the_guards_verdict_out_of_the_snapshot() {
        use crate::engine::{EngineState, LaneSnapshot, Snapshot};
        use crate::lane::Lane;

        let row = |lane: Lane, acceptance: &str| LaneSnapshot {
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
            acceptance: acceptance.to_string(),
            accept_pct: None,
            halted: false,
            activity: GuardCustody::Mining,
        };

        let mut s = Snapshot::idle();
        s.lane = Some(Lane::GpuPrl);

        // A judged lane: the session's zero is a measurement, so it may be judged.
        s.lanes = vec![row(Lane::GpuPrl, "healthy")];
        assert!(!MiningEvidence::from_snapshot(&s).guard_undecided);

        // The three "we do not know" verdicts, each on its own.
        for key in ["warmup", "gathering", "unknown"] {
            s.lanes = vec![row(Lane::GpuPrl, key)];
            assert!(
                MiningEvidence::from_snapshot(&s).guard_undecided,
                "{key} is the client not knowing"
            );
        }

        // Dual mine: ONE unjudged lane is enough. The accepted counter is a whole-
        // snapshot figure, so a zero cannot be attributed to the judged lane alone.
        s.lanes = vec![row(Lane::Xmr, "healthy"), row(Lane::GpuPrl, "gathering")];
        assert!(MiningEvidence::from_snapshot(&s).guard_undecided);

        // An older stream carries no verdict at all. That is not a judgement either.
        s.lanes = vec![row(Lane::GpuPrl, "")];
        assert!(MiningEvidence::from_snapshot(&s).guard_undecided);
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

    // ── F1: a hold must not read as an invitation to bypass itself ───────────

    /// The imperative form — "run `alice-miner update` [to install it]" — in
    /// both languages. This is the shape that turns a line the user reads into
    /// an instruction they follow.
    fn reads_as_an_instruction(s: &str) -> bool {
        s.contains("run `alice-miner update`")
            || s.contains("运行 `alice-miner update`")
            || s.contains("installs it now")
            || s.contains("可立即安装")
    }

    /// Three holds exist because the USER chose a quieter setting. For those,
    /// "run `alice-miner update`" is the remedy — it is precisely the step their
    /// setting asked us to leave to them — and the line should say so.
    ///
    /// Three other holds exist for a SAFETY reason: the soak window, the staged
    /// rollout and the failure pin. Every one of those lines used to end with an
    /// offer to skip it (`— alice-miner update installs it now`), which meant our
    /// own copy walked the user off the guarded path onto the unguarded one at
    /// the exact moment the guard engaged. Under a stolen key that sentence is
    /// worth more to the attacker than the guardrail is worth to us.
    ///
    /// The line may still say the command exists. It must not present it as the
    /// fix.
    #[test]
    fn a_safety_hold_never_reads_as_an_invitation_to_bypass_itself() {
        let _g = crate::i18n::LANG_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let safety = [
            Hold::Soaking { ready_in_s: 3600 },
            Hold::Rollout { bucket: 42, pct: 10 },
            Hold::Pinned,
            Hold::LedgerUnwritable,
            Hold::LedgerReset,
        ];
        let preference = [Hold::ModeOff, Hold::NotifyOnly, Hold::NotSecurity];

        for lang in [crate::i18n::Lang::En, crate::i18n::Lang::Zh] {
            crate::i18n::set_lang(lang);
            for h in &safety {
                let s = describe_hold("0.6.8", h);
                assert!(
                    !reads_as_an_instruction(&s),
                    "a safety hold must not tell the user to run the bypass ({lang:?}): {s}"
                );
                assert!(
                    s.contains("alice-miner update"),
                    "…but it must not hide that the command exists either ({lang:?}): {s}"
                );
            }
            for h in &preference {
                let s = describe_hold("0.6.8", h);
                assert!(
                    reads_as_an_instruction(&s),
                    "a hold that exists because of a SETTING should name the remedy ({lang:?}): {s}"
                );
            }
        }
        crate::i18n::set_lang(crate::i18n::Lang::En);
    }

    // ── F2 / F2b: a withdrawal is not an install instruction ─────────────────

    fn newer(version: &str, visible_for_s: u64) -> auto::NewerRelease {
        auto::NewerRelease {
            version: version.to_string(),
            visible_for_s,
        }
    }

    /// F2 — the attack this closes: a stolen key publishes a malicious vNEW and
    /// lists every legitimate version in `revoked[]`. The withdrawal branch then
    /// prints, on every machine, a correctly-signed, urgent-sounding instruction
    /// to install vNEW at once — collapsing the soak window from a day to
    /// however long it takes someone to read one line.
    ///
    /// Inside the soak floor the wording must say the OPPOSITE, and it must say
    /// how long the thing has actually been public.
    #[test]
    fn a_withdrawal_inside_the_soak_floor_advises_against_installing() {
        let _g = crate::i18n::LANG_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for lang in [crate::i18n::Lang::En, crate::i18n::Lang::Zh] {
            crate::i18n::set_lang(lang);
            let s = describe_forward(&Some(newer("9.9.9", 2 * 3600)), false, false);
            assert!(
                !reads_as_an_instruction(&s),
                "a withdrawal must never double as an install instruction ({lang:?}): {s}"
            );
            assert!(s.contains("9.9.9"), "must name the version ({lang:?}): {s}");
            assert!(
                s.contains("2 hours") || s.contains("2 小时"),
                "must say how long it has been visible ({lang:?}): {s}"
            );
            assert!(
                s.contains("NOT advised") || s.contains("并不可取"),
                "must advise against it, not for it ({lang:?}): {s}"
            );
        }
        crate::i18n::set_lang(crate::i18n::Lang::En);
    }

    /// Past the soak floor the notice is neutral: facts, and no next move chosen
    /// on the user's behalf. A withdrawal says something is wrong with the build
    /// they have — it is not a statement about which build they should take.
    #[test]
    fn a_withdrawal_past_the_soak_floor_states_facts_without_instructing() {
        let _g = crate::i18n::LANG_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::i18n::set_lang(crate::i18n::Lang::En);
        let s = describe_forward(&Some(newer("9.9.9", 5 * 24 * 3600)), false, false);
        assert!(!reads_as_an_instruction(&s), "{s}");
        assert!(s.contains("5 days"), "{s}");
        assert!(!s.contains("NOT advised"), "no scolding past the floor: {s}");
    }

    /// F2b — the most common withdrawal there is: we shipped v0.6.9, it is bad,
    /// we pulled it. `latest == current`, so the old branch rendered "v0.6.9 has
    /// been withdrawn, please install v0.6.9" and the manual path then hard-errored
    /// on the very thing it had just recommended.
    #[test]
    fn a_withdrawal_with_nowhere_to_go_says_so_and_points_at_the_releases_page() {
        let _g = crate::i18n::LANG_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for lang in [crate::i18n::Lang::En, crate::i18n::Lang::Zh] {
            crate::i18n::set_lang(lang);
            let s = describe_forward(&None, false, /* rollback_available */ false);
            assert!(!reads_as_an_instruction(&s), "({lang:?}): {s}");
            assert!(
                s.contains(release::RELEASES_PAGE_URL),
                "must point at the releases page ({lang:?}): {s}"
            );
            assert!(
                s.contains("cannot") || s.contains("无法"),
                "must say plainly that we cannot do it from here ({lang:?}): {s}"
            );
        }
        // …unless we already put the previous build back, in which case the tail
        // covers it and a releases-page link would be noise.
        crate::i18n::set_lang(crate::i18n::Lang::En);
        assert_eq!(describe_forward(&None, true, true), "");
    }

    /// The whole notice, as the miner actually reads it. The clause tests above
    /// check the middle sentence in isolation; this checks that assembling it
    /// does not put an instruction back in, and that a skipped clause does not
    /// leave a hole in the line.
    #[test]
    fn the_assembled_withdrawal_notice_warns_without_instructing() {
        let _g = crate::i18n::LANG_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for lang in [crate::i18n::Lang::En, crate::i18n::Lang::Zh] {
            crate::i18n::set_lang(lang);
            for (newer, reverted, lkg, may_act) in [
                (Some(newer("9.9.9", 2 * 3600)), false, false, false),
                (Some(newer("9.9.9", 9 * 24 * 3600)), false, true, false),
                (None, false, false, false),
                (None, true, true, true),
                // The two branches F3 is about: a last-known-good copy is here
                // and we either were not allowed to use it, or tried and failed.
                (None, false, true, false),
                (None, false, true, true),
            ] {
                let s = describe_revoked("0.6.9", &newer, reverted, lkg, may_act);
                assert!(
                    !reads_as_an_instruction(&s),
                    "({lang:?}) the notice must never become an install instruction: {s}"
                );
                assert!(s.contains("0.6.9"), "({lang:?}) names the withdrawn build: {s}");
                assert!(
                    s.contains("⚠"),
                    "({lang:?}) reaches the user as a warning: {s}"
                );
                assert!(!s.contains("  "), "({lang:?}) a skipped clause left a hole: {s}");
            }
        }
        crate::i18n::set_lang(crate::i18n::Lang::En);
    }

    /// The ordinary "we shipped it, it is bad, we pulled it" withdrawal, on a
    /// machine set to `off`/`notify` that IS holding a last-known-good copy.
    ///
    /// The notice used to say both "this client cannot put it back for you from
    /// here" and "a previous version is still on this machine". The middle
    /// clause was false in this branch — the client is holding the copy and
    /// declined to use it on policy grounds — so we sent a miner running a build
    /// we had just called dangerous off to reinstall by hand, when flipping one
    /// setting would have done it.
    #[test]
    fn a_withdrawal_with_a_rollback_copy_in_hand_does_not_send_the_user_away() {
        let _g = crate::i18n::LANG_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for lang in [crate::i18n::Lang::En, crate::i18n::Lang::Zh] {
            crate::i18n::set_lang(lang);
            let s = describe_revoked(
                "0.6.9",
                &None,
                /* reverted */ false,
                /* rollback_available */ true,
                /* may_act */ false,
            );
            assert!(
                !s.contains("cannot put it back") && !s.contains("无法在这里替你装回去"),
                "the client IS holding the copy — saying otherwise is false ({lang:?}): {s}"
            );
            assert!(
                !s.contains(release::RELEASES_PAGE_URL),
                "do not send them to reinstall by hand when a setting would do it ({lang:?}): {s}"
            );
            assert!(
                s.contains("--auto security-only"),
                "it must name the one thing that actually recovers this machine ({lang:?}): {s}"
            );
            assert!(!reads_as_an_instruction(&s), "({lang:?}): {s}");

            // The control, and the branch that keeps the old wording: no copy on
            // disk, so reinstalling by hand really is the only way out.
            let none = describe_revoked("0.6.9", &None, false, false, false);
            assert!(
                none.contains(release::RELEASES_PAGE_URL)
                    && (none.contains("cannot") || none.contains("无法")),
                "({lang:?}): {none}"
            );
            assert!(
                !none.contains("--auto security-only"),
                "there is nothing for a setting to unlock here ({lang:?}): {none}"
            );

            // And the third case, which the old shape could not express at all:
            // we WERE allowed to act, there WAS a copy, and the restore failed.
            // Blaming a setting there would be a different false statement.
            let failed = describe_revoked("0.6.9", &None, false, true, /* may_act */ true);
            assert!(
                !failed.contains("--auto security-only"),
                "a failed restore is not a settings problem ({lang:?}): {failed}"
            );
            assert!(
                failed.contains("could NOT be restored") || failed.contains("无法自动恢复"),
                "({lang:?}): {failed}"
            );
        }
        crate::i18n::set_lang(crate::i18n::Lang::En);
    }

    #[test]
    fn age_phrase_reads_in_the_unit_a_human_would_use() {
        let _g = crate::i18n::LANG_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::i18n::set_lang(crate::i18n::Lang::En);
        assert_eq!(age_phrase(30), "less than a minute");
        assert_eq!(age_phrase(20 * 60), "20 minutes");
        assert_eq!(age_phrase(5 * 3600), "5 hours");
        assert_eq!(age_phrase(9 * 24 * 3600), "9 days");
    }

    // ── F1: the manual path runs the same guardrails ─────────────────────────

    /// An isolated `$ALICE_IDENTITY_DIR` so `state_dir()` (and therefore the
    /// seen ledger and the pins) never touches the developer's real `~/.alice`.
    fn with_state_dir<T>(name: &str, f: impl FnOnce(&std::path::Path) -> T) -> T {
        let _g = crate::IDENTITY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "alice-manual-{}-{}-{}",
            name,
            std::process::id(),
            now_unix()
        ));
        let _ = std::fs::create_dir_all(&dir);
        std::env::set_var("ALICE_IDENTITY_DIR", &dir);
        let out = f(&dir);
        std::env::remove_var("ALICE_IDENTITY_DIR");
        let _ = std::fs::remove_dir_all(&dir);
        out
    }

    fn test_manifest(version: &str) -> release::Manifest {
        release::Manifest {
            schema: 1,
            product: release::PRODUCT.to_string(),
            version: version.to_string(),
            min_supported: "0.1.0".to_string(),
            released: "2026-08-14T00:00:00Z".to_string(),
            notes: String::new(),
            artifacts: vec![release::Artifact {
                platform: release::current_platform().to_string(),
                url: "https://example.invalid/pkg.tar.gz".to_string(),
                sha256: "aa".repeat(32),
                size: 1,
            }],
            rollout_pct: None,
            soak_hours: None,
            revoked: Vec::new(),
            security: None,
        }
    }

    /// The manual path records the sighting. Without this the ledger only ever
    /// learned about versions the AUTOMATIC path looked at, so a version
    /// installed by hand left no trace for the next check to compare against —
    /// and the hash-conflict guard had nothing to guard with.
    #[test]
    fn the_manual_path_records_the_sighting_and_reports_visibility() {
        let _l = crate::i18n::LANG_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::i18n::set_lang(crate::i18n::Lang::En);
        with_state_dir("seen", |dir| {
            let m = test_manifest("9.9.9");
            let check = manual_check(&m, Some(&m.artifacts[0]), "0.6.7");
            assert_eq!(check.outcome, ManualOutcome::Proceed);
            assert!(
                dir.join("update-seen.json").exists(),
                "the manual path must write the seen ledger too"
            );
            assert!(check.inside_soak, "a version seen just now is inside the floor");
            let v = check.visibility.expect("a visibility line");
            assert!(v.contains("9.9.9"), "{v}");
            assert!(
                v.contains("less than a minute"),
                "a manual install must SAY how long the version has been visible: {v}"
            );
            // The recorded hash is the one we were offered.
            let seen = auto::note_seen(dir, "9.9.9", "ff".repeat(32).as_str());
            assert_eq!(seen.seen.sha256, "aa".repeat(32), "first bytes win");
        });
    }

    /// The F1 headline: a version this machine first saw carrying one package,
    /// now offered as different bytes under the same version number, is refused
    /// on the MANUAL path exactly as it is on the automatic one.
    #[test]
    fn the_manual_path_refuses_a_republished_version() {
        let _l = crate::i18n::LANG_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::i18n::set_lang(crate::i18n::Lang::En);
        with_state_dir("conflict", |dir| {
            // This machine saw 9.9.9 carrying "bb…" first.
            auto::note_seen(dir, "9.9.9", "bb".repeat(32).as_str());
            // The server now offers "aa…" under the same number.
            let m = test_manifest("9.9.9");
            let check = manual_check(&m, Some(&m.artifacts[0]), "0.6.7");
            match check.outcome {
                ManualOutcome::Refuse { message } => {
                    assert!(message.contains("REFUSED"), "{message}");
                    assert!(message.contains("bbbbbbbbbbbb"), "names the first bytes: {message}");
                    assert!(message.contains("aaaaaaaaaaaa"), "names the offered bytes: {message}");
                }
                other => panic!("expected a refusal, got {other:?}"),
            }
            // …and it is on the local record, which is the only place a fleet
            // operator can see it without a server.
            let hist = std::fs::read_to_string(dir.join("update-history.jsonl")).unwrap_or_default();
            assert!(hist.contains("manual-hash-conflict"), "history: {hist}");
        });
    }

    /// A version this machine already rolled back is a SECOND question, not a
    /// refusal: the user may still choose it, knowing what happened here.
    #[test]
    fn the_manual_path_asks_again_about_a_version_this_machine_rolled_back() {
        let _l = crate::i18n::LANG_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::i18n::set_lang(crate::i18n::Lang::En);
        with_state_dir("pinned", |dir| {
            auto::pin(dir, "9.9.9");
            let m = test_manifest("9.9.9");
            match manual_check(&m, Some(&m.artifacts[0]), "0.6.7").outcome {
                ManualOutcome::Confirm { message } => {
                    assert!(message.contains("9.9.9"), "{message}");
                    assert!(message.contains("rolled it back"), "{message}");
                }
                other => panic!("expected a second question, got {other:?}"),
            }
        });
    }

    /// The manual driver refuses a build that is not newer than the running
    /// one, in the shape both front-ends actually call.
    #[test]
    fn the_manual_path_refuses_a_downgrade() {
        let _l = crate::i18n::LANG_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::i18n::set_lang(crate::i18n::Lang::En);
        with_state_dir("downgrade", |dir| {
            // A perfectly ordinary, correctly-signed manifest — the only thing
            // wrong with it is the direction.
            let m = test_manifest("0.6.4");
            match manual_check(&m, Some(&m.artifacts[0]), "0.6.8").outcome {
                ManualOutcome::Refuse { message } => {
                    assert!(message.contains("REFUSED"), "{message}");
                    assert!(message.contains("0.6.4") && message.contains("0.6.8"), "{message}");
                }
                other => panic!("expected a refusal, got {other:?}"),
            }
            let hist = std::fs::read_to_string(dir.join("update-history.jsonl")).unwrap_or_default();
            assert!(hist.contains("manual-downgrade-refused"), "history: {hist}");

            // The control: the same driver, the same machine, one version later.
            let up = test_manifest("0.6.9");
            assert_eq!(
                manual_check(&up, Some(&up.artifacts[0]), "0.6.8").outcome,
                ManualOutcome::Proceed
            );
        });
    }

    /// The cross-layer half of the arming fix: layer 3 persists its halt so it
    /// survives a restart, and the arming path reads it. Without that read, a
    /// build installed during a multi-day outage arms with no baseline and
    /// commits — dropping last-known-good — on the first command the user types.
    #[test]
    fn a_halted_lane_makes_the_earning_baseline_unknown_rather_than_absent() {
        with_state_dir("baseline", |_dir| {
            let dir = state_dir();
            // Nothing earning, nothing halted: a genuinely idle rig.
            assert_eq!(earning_baseline(&dir), auto::EarningBaseline::NotEarning);

            // Layer 3 halts the lane. The productive stamp is now frozen by
            // design — and it is still stale, because the outage outlasted the
            // 72-hour window (August 2026 ran 78).
            let rec = crate::acceptance::HaltRecord {
                schema: crate::acceptance::HALT_SCHEMA,
                lane: crate::acceptance::lane_wire_name(crate::lane::Lane::GpuPrl).to_string(),
                halted_at: crate::acceptance::now_unix(),
                next_probe_at: crate::acceptance::now_unix() + 1800,
                probes: 3,
                run_accepted: 0,
                run_rejected: 7_743,
                period_accepted: 0,
                period_rejected: 500,
                period_elapsed_s: 900,
                shutout: true,
                attribution: "upstream".to_string(),
                version: "0.6.8".to_string(),
            };
            crate::acceptance::save_halt_record(&rec).expect("seed the halt");
            assert_eq!(
                earning_baseline(&dir),
                auto::EarningBaseline::Unknown,
                "a stale stamp behind a halt is 'we could not tell', not 'it was not earning'"
            );

            // A fresh accepted share still outranks everything: if the machine
            // IS earning we have a real baseline and the mining gate arms.
            auto::mark_productive(&dir);
            assert_eq!(earning_baseline(&dir), auto::EarningBaseline::Earning);

            crate::acceptance::clear_halt_record(crate::lane::Lane::GpuPrl);
        });
    }

    /// A state directory that cannot be written disarms the hash-conflict
    /// refusal permanently — the sighting handed back is built from the manifest
    /// and therefore agrees with it, every run, forever. The manual path must
    /// say so rather than proceed as if the check had passed.
    #[test]
    fn the_manual_path_says_when_it_could_not_record_what_it_was_offered() {
        let _l = crate::i18n::LANG_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::i18n::set_lang(crate::i18n::Lang::En);
        let _g = crate::IDENTITY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // `$ALICE_IDENTITY_DIR` pointed at a regular FILE: `create_dir_all`
        // fails on every platform, which is what an unwritable state dir does.
        let base = std::env::temp_dir().join(format!(
            "alice-noledger-{}-{}",
            std::process::id(),
            now_unix()
        ));
        let _ = std::fs::create_dir_all(&base);
        let not_a_dir = base.join("state");
        std::fs::write(&not_a_dir, b"not a directory").unwrap();
        std::env::set_var("ALICE_IDENTITY_DIR", &not_a_dir);

        let m = test_manifest("9.9.9");
        let outcome = manual_check(&m, Some(&m.artifacts[0]), "0.6.7").outcome;

        std::env::remove_var("ALICE_IDENTITY_DIR");
        let _ = std::fs::remove_dir_all(&base);

        match outcome {
            ManualOutcome::Confirm { message } => {
                assert!(
                    message.contains("could not write its update ledger"),
                    "{message}"
                );
                assert!(
                    message.contains("re-published") || message.contains("different bytes"),
                    "it must name the check that is missing, not just the file: {message}"
                );
            }
            other => panic!("expected a second question, got {other:?}"),
        }
    }

    /// The two sentences the "already installed" hold has to be able to say, and
    /// why there are two. Inside a day it is the ordinary state of affairs — the
    /// swap is on disk, the process running it has not started yet, and there is
    /// nothing for anyone to do. Past that, on a machine that is plainly being
    /// restarted and still reports the old version, repeating "restart to run it"
    /// would be the client insisting on something the machine has already
    /// disproved; the honest reading is that the installed build does not report
    /// the version it was published under, and that is ours to fix, not theirs.
    #[test]
    fn the_already_installed_line_stops_saying_restart_once_that_is_disproved() {
        let _g = crate::i18n::LANG_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::i18n::set_lang(crate::i18n::Lang::En);

        let fresh = describe_hold("0.6.8", &Hold::AlreadyInstalled { installed_ago_s: 4 * 3600 });
        assert!(fresh.contains("next time you start"), "{fresh}");
        assert!(fresh.contains("nothing to do"), "{fresh}");

        let stale = describe_hold(
            "0.6.8",
            &Hold::AlreadyInstalled { installed_ago_s: 9 * 24 * 3600 },
        );
        assert!(
            !stale.contains("nothing to do"),
            "nine days of this is not 'nothing to do': {stale}"
        );
        assert!(
            stale.contains("report it"),
            "it must say whose problem this is and what to do with it: {stale}"
        );
        assert!(
            stale.contains("has NOT been installed again"),
            "and that the client stopped rather than looping: {stale}"
        );
    }

    /// The manual path is not a way around the hold above. Applying an update
    /// that is already on disk moves the CURRENT app into the last-known-good
    /// slot, so the copy the machine would roll back to becomes the build on
    /// trial — and `--yes` must not reach that.
    #[test]
    fn the_manual_path_asks_before_re_applying_an_update_already_on_disk() {
        let _l = crate::i18n::LANG_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::i18n::set_lang(crate::i18n::Lang::En);
        with_state_dir("already", |dir| {
            let m = test_manifest("9.9.9");
            // Control: nothing installed yet, the ordinary manual update.
            assert_eq!(
                manual_check(&m, Some(&m.artifacts[0]), "0.6.7").outcome,
                ManualOutcome::Proceed
            );

            assert!(auto::note_installed(dir, "9.9.9", &"aa".repeat(32)));
            match manual_check(&m, Some(&m.artifacts[0]), "0.6.7").outcome {
                ManualOutcome::Confirm { message } => {
                    assert!(message.contains("already installed"), "{message}");
                    assert!(
                        message.contains("roll back"),
                        "it must say what a second install costs, not just that it is redundant: {message}"
                    );
                }
                other => panic!("expected a second question, got {other:?}"),
            }
        });
    }

    /// The other ledger failure, through the real driver: the file was there, it
    /// could not be read, and the records it held are gone.
    ///
    /// The old behaviour was the worst of both directions at once — the ledger was
    /// silently overwritten AND the sighting was reported as recorded, so the
    /// manual path proceeded as if the republish check had passed on a machine
    /// where it had just been erased. It must ask instead, and it must say what
    /// actually happened: nothing here is a permissions problem, and telling
    /// someone to go and check their disk would be a guess wearing a diagnosis.
    #[test]
    fn the_manual_path_says_when_its_ledger_was_lost_rather_than_unwritable() {
        let _l = crate::i18n::LANG_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::i18n::set_lang(crate::i18n::Lang::En);
        with_state_dir("ledgerreset", |dir| {
            // This machine had a record, and then the file stopped being readable.
            auto::note_seen(dir, "9.9.9", "bb".repeat(32).as_str());
            std::fs::write(dir.join("update-seen.json"), b"<<<not json>>>").unwrap();

            let m = test_manifest("9.9.9");
            match manual_check(&m, Some(&m.artifacts[0]), "0.6.7").outcome {
                ManualOutcome::Confirm { message } => {
                    assert!(
                        message.contains("could not be read"),
                        "it must name the failure it actually had: {message}"
                    );
                    assert!(
                        !message.contains("could not write"),
                        "and must not blame the write, which succeeded: {message}"
                    );
                    assert!(
                        message.contains("re-published") || message.contains("different bytes"),
                        "it must name the check that is missing, not just the file: {message}"
                    );
                }
                other => panic!("expected a second question, got {other:?}"),
            }
            let hist =
                std::fs::read_to_string(dir.join("update-history.jsonl")).unwrap_or_default();
            assert!(hist.contains("ledger-reset"), "history: {hist}");
        });
    }

    /// With no package for this platform there is nothing to compare, and the
    /// gate must not invent a conflict out of the absence — nor write a
    /// placeholder hash into an append-only ledger.
    #[test]
    fn the_manual_path_with_no_platform_package_records_nothing() {
        with_state_dir("noartifact", |dir| {
            let m = test_manifest("9.9.9");
            let check = manual_check(&m, None, "0.6.7");
            assert_eq!(check.outcome, ManualOutcome::Proceed);
            assert_eq!(check.visibility, None);
            assert!(!dir.join("update-seen.json").exists());
        });
    }
}

