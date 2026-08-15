//! `auto` — the GUARDED automatic-update layer on top of the signed updater.
//!
//! The kernel in `lib.rs` answers "is this manifest genuine and is this artifact
//! the bytes it claims to be". That is necessary and not sufficient: turning an
//! opt-in manual updater into an automatic one is a **supply-chain amplifier**.
//! Today the release root key signs the miner AND the wallet; if it leaks, the
//! thief can sign a malicious client and every machine that auto-installs it is
//! remotely executing their code. Rotating the key does not un-install it. The
//! current "the user has to click" behaviour is, whether we designed it that way
//! or not, a real brake on how fast a stolen key spreads.
//!
//! So this module exists to answer a different question: **how much faster does
//! each automation make an attacker who already holds the key?** Every guardrail
//! below is written to that standard, and one rule falls out of it:
//!
//! > **A manifest may only make auto-update slower or narrower — never faster or
//! > wider.**
//!
//! That rule matters because every field of the manifest is attacker-controlled
//! under key compromise. A thief who could set `soak_hours: 0`, `rollout_pct:
//! 100` and `released:` to last week would have guardrails in name only. So:
//!
//!   * the **soak window** is anchored on when THIS machine first *saw* the
//!     version — a local clock the manifest cannot move — and the manifest's
//!     `soak_hours` can only extend it past the [`SOAK_FLOOR`] the client
//!     hard-codes. The manifest's `released` field is read for exactly one
//!     purpose, a FLOOR under that anchor ([`soak_anchor`]): a machine cannot
//!     have seen a version before it was published, so a local sighting that
//!     predates `released` is a broken clock rather than a long soak. That use
//!     can only push an install later, never sooner;
//!   * the **rollout percentage** is a ceiling the manifest can only lower;
//!   * the **artifact hash for a version is remembered forever**: the same
//!     version re-appearing with different bytes is refused outright, so the
//!     "publish v0.6.8, then quietly re-publish v0.6.8" attack fails;
//!   * a version that **failed its health probation is pinned** and never
//!     auto-installed again on this machine, even if the manifest still offers it;
//!   * **revocation** (`revoked: [...]`) is honoured in both directions: a
//!     revoked version is never installed, and running a revoked version rolls
//!     back to last-known-good if one exists.
//!
//! What this does NOT do, and we should not pretend otherwise: it does not stop
//! a stolen key. It compresses the window in which a stolen key reaches every
//! miner from "however long until people update by hand" to about a day, and
//! buys back a day of detection time plus a revocation switch. The real fix is a
//! two-person threshold signature on releases; this module is the harm reduction
//! until that exists.
//!
//! ## Health probation (why this module owns it rather than `lib.rs`)
//!
//! `lib.rs` has a first-launch gate: arm a marker, and if the new build reaches
//! startup twice without ever confirming health, roll back. That gate answers
//! "does the binary start". For an update the *user* asked for, that is the right
//! question — rolling a manually-chosen build back because the pool was down
//! would be worse than the disease.
//!
//! An update the user did NOT ask for has to clear a higher bar, because nobody
//! is watching it land. So an auto-applied build runs its own probation here:
//! it must start, and then it must still be *earning* — at least one accepted
//! share — before we drop last-known-good. And because "no accepted shares" is
//! exactly what an upstream outage looks like (2026-08-11: every miner on the
//! network had zero accepted shares for three days and no client was at fault),
//! the mining half of the probation only ever votes to roll back when the
//! OUTGOING build was landing shares on this same machine shortly before the
//! swap. If the previous build was not earning either, the new one is not on
//! trial for it — we commit and say so, rather than blaming the client for the
//! network.
//!
//! ## Why "the previous build was earning" is NOT enough on its own (F4)
//!
//! That baseline says only "this machine landed a share in the last 72 h", which
//! is true of every normally-mining machine. Replay August against it: a rig
//! auto-updates on the 10th, the upstream fork lands on the 11th, two long
//! sessions land nothing, and the client rolls back and permanently pins a
//! completely innocent version — the exact mistake this release exists to stop.
//!
//! So the caller may also tell us that the session it is reporting is **not
//! evidence**, via [`SessionEvidence`]:
//!
//!   * [`SessionEvidence::MiningHalted`] — the acceptance guard (layer 3) stopped
//!     mining on purpose. Its zero-accepted is *ours*, not the build's. Layer 3
//!     halting must never be read here as "the new version does not earn".
//!   * [`SessionEvidence::AcceptanceProbe`] — the guard is spending one deliberate
//!     window RE-MEASURING a halted lane. The engine is running and the halt flag is
//!     off (it must be, or the probe's own child could not start), so this session
//!     looks exactly like an ordinary miner earning nothing — and it is not one.
//!   * [`SessionEvidence::AcceptanceUndecided`] — the guard is mining the lane
//!     normally and has reached NO verdict about it (warm-up, an incomplete period,
//!     or an engine that cannot report rejections). Its zero is unmeasured, not
//!     measured-as-bad. This is the case the two above do not cover: they are states
//!     the guard only enters AFTER it has concluded something, and concluding takes
//!     ten minutes and twenty submissions — hours on a slow rig, forever on a lane
//!     that submits nothing — while two 20-minute sessions roll a build back.
//!   * [`SessionEvidence::NetworkWide`] — the network-wide lane health says every
//!     miner on this lane is being rejected. Blaming the local build for a
//!     network-wide failure is never correct.
//!
//! An abstained session is neither good nor bad evidence: it does not record a
//! strike, and it does **not** commit the build either (the probation simply
//! stays open — see [`SessionVerdict::Abstained`]). We deliberately do not let a
//! session we refused to judge drop last-known-good.
//!
//! All state lives in a caller-supplied directory (`~/.alice` in the app) so this
//! module stays testable and never guesses at a data dir. Nothing here is ever
//! transmitted: the rollout id is a local random label, not a machine
//! fingerprint, and it is deliberately NOT derived from any hardware id or from
//! the miner's address.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Artifact, Manifest, UpdateError};

type Result<T> = std::result::Result<T, UpdateError>;

// ────────────────────────────────────────────────────────────────────────────
// Client-side floors. A manifest can tighten these; it can never loosen them.
// ────────────────────────────────────────────────────────────────────────────

/// The minimum time a version must have been VISIBLE TO THIS MACHINE before it
/// may be installed without the user asking.
///
/// 24h is not a round number picked for looks. The 2026-08-11 PRL fork went
/// unnoticed for 78 hours, and the honest reading of that is that our detection
/// floor is "about a day if someone is paying attention". A soak shorter than
/// our own detection time would mean the bad build reaches everyone before we
/// can know it is bad; a soak much longer than a day and an automatic updater
/// stops being useful in the emergencies it exists for. So: one day, enforced
/// locally, on a clock the manifest cannot move.
pub const SOAK_FLOOR: Duration = Duration::from_secs(24 * 60 * 60);

/// A mining session must run at least this long before "zero accepted shares"
/// counts as evidence against the build. Below this the sample is meaningless —
/// engines take minutes to warm up and share intervals of several minutes are
/// normal on the ASIC lane.
pub const MIN_JUDGED_SESSION: Duration = Duration::from_secs(20 * 60);

/// How many long, zero-accepted sessions it takes to roll an auto-installed
/// build back. Two, not one: a single bad session is as likely to be a relay
/// hiccup as a bad client.
pub const FAILED_SESSIONS_TO_ROLLBACK: u32 = 2;

/// "The previous build was earning" means an accepted share landed on this
/// machine within this window before the swap. Older than that and we have no
/// fresh baseline to judge the new build against, so the mining probation
/// abstains instead of guessing.
///
/// Note what this gate is NOT: it is true of every normally-mining machine, so it
/// cannot by itself tell "the new build broke earning" from "the pool started
/// rejecting everyone". [`SessionEvidence`] is the input that can.
pub const PRODUCTIVE_WINDOW: Duration = Duration::from_secs(72 * 60 * 60);

/// A probation that never reaches a verdict is committed after this long. We do
/// NOT keep a last-known-good copy on the miner's disk forever waiting for a
/// verdict that is not coming (e.g. they installed, then stopped mining).
pub const PROBATION_MAX: Duration = Duration::from_secs(14 * 24 * 60 * 60);

/// The default auto-update mode for a machine that has never chosen one.
///
/// **`SecurityOnly`, and the reasoning is worth keeping next to the constant.**
///
/// Arguments for a more permissive default (`Full`): a miner who never updates
/// burns electricity on a broken build, which is exactly what happened for 78
/// hours in August 2026.
///
/// Arguments for a more conservative default (`Notify`): with a single release
/// key covering both the miner and the wallet, a stolen key plus automatic
/// installation is remote code execution on every mining machine, and no
/// rotation undoes it. Manual updating is slow, and slow is a security property
/// here.
///
/// `SecurityOnly` is where those meet. It auto-installs only releases the
/// publisher explicitly marked `security: true`, so ordinary feature releases
/// keep today's manual behaviour and the day-to-day exposure is unchanged, while
/// an emergency client fix still reaches machines within about a day without
/// anyone having to notice a banner.
///
/// Two things about it should be said plainly rather than implied. First, the
/// `security` flag is in the manifest, so an attacker holding the key can simply
/// set it — `SecurityOnly` narrows *routine* churn, not an attacker. What
/// actually bounds an attacker is the local soak floor, the rollout ceiling, the
/// hash-conflict refusal and revocation, all of which apply in every mode.
/// Second, the incident that prompted all of this would NOT have been fixed by
/// this layer at all: v0.6.5, v0.6.6 and v0.6.7 pin byte-identical engines, so a
/// miner on the newest client was rejected exactly as hard as one on the oldest.
/// The fix for that class of failure is the independently-updatable engine pin.
/// We are not buying availability with security here; we are buying the ability
/// to ship an emergency *client* fix inside a day.
///
/// If the operator wants maximum caution, this one constant is the switch:
/// `Mode::Notify` keeps every check, every banner and every manual path, and
/// installs nothing on its own.
pub const DEFAULT_MODE: Mode = Mode::SecurityOnly;

// ────────────────────────────────────────────────────────────────────────────
// Mode
// ────────────────────────────────────────────────────────────────────────────

/// How much the client may do without asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// Never check, never notify, never install. Fully silent.
    Off,
    /// Check and TELL the user, but never install. The "just warn me" mode.
    Notify,
    /// Auto-install only releases flagged `security` in the manifest; notify for
    /// everything else. The default — see [`DEFAULT_MODE`].
    SecurityOnly,
    /// Auto-install any release that clears the guardrails.
    Full,
}

impl Mode {
    /// Parse a persisted / CLI value. Unknown values are NOT silently coerced to
    /// something permissive: they fall back to [`DEFAULT_MODE`]'s caller choice
    /// via `None`, so the caller can complain rather than quietly upgrading the
    /// user's exposure.
    pub fn parse(s: &str) -> Option<Mode> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "off" | "never" | "none" => Some(Mode::Off),
            "notify" | "notify-only" | "check" => Some(Mode::Notify),
            "security-only" | "security" => Some(Mode::SecurityOnly),
            "full" | "all" | "on" => Some(Mode::Full),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Notify => "notify",
            Mode::SecurityOnly => "security-only",
            Mode::Full => "full",
        }
    }

    /// Whether this mode ever performs an unattended install.
    pub fn installs(self) -> bool {
        matches!(self, Mode::SecurityOnly | Mode::Full)
    }

    /// Whether this mode may touch the network for a background check at all.
    pub fn checks(self) -> bool {
        !matches!(self, Mode::Off)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// The decision (pure)
// ────────────────────────────────────────────────────────────────────────────

/// Why an available update was NOT installed automatically. Every variant is a
/// sentence we are willing to show the user — "we are not telling you why" is
/// how the last three days happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hold {
    /// Auto-update is switched off entirely.
    ModeOff,
    /// The user asked to be told, not updated.
    NotifyOnly,
    /// `security-only` and this release is not flagged as a security release.
    NotSecurity,
    /// Still inside the soak window; `ready_in_s` seconds to go.
    Soaking { ready_in_s: u64 },
    /// This machine's bucket is outside the current rollout slice.
    Rollout { bucket: u8, pct: u8 },
    /// This exact version already failed its health probation here.
    Pinned,
    /// The manifest itself withdraws this version.
    Revoked,
    /// No artifact for this platform (manual download only).
    NoArtifact,
    /// This machine has ALREADY installed this exact version — the swap is on
    /// disk and the process running it has not started yet.
    ///
    /// Almost always the ordinary state of affairs between an install and the
    /// next restart, which on a mining rig can be a week. It is a hold rather
    /// than a no-op because the alternative is installing the same build again on
    /// every re-check: each install moves the current app aside into `.lkg`, so
    /// the second one overwrites the real rollback copy with the new build and
    /// quietly disarms the probation it just armed.
    ///
    /// It also covers the case nobody wants to be in: a build that answers with a
    /// different version than the one it was published under. There, the restart
    /// never resolves this, and `installed_ago_s` is what lets a caller tell the
    /// two apart out loud rather than repeating "restart to run it" for ever.
    AlreadyInstalled { installed_ago_s: u64 },
    /// The version was previously seen with DIFFERENT artifact bytes. Refuse and
    /// shout: a re-published version is either a mistake or an attack, and we do
    /// not need to know which to know we should not install it.
    HashConflict { seen_sha256: String, now_sha256: String },
    /// This machine could not write the sighting to its own update ledger, so
    /// the hash-conflict refusal has nothing to compare against — now or ever.
    ///
    /// That check is the one guarantee in the whole update path that does not
    /// rest on the release key, and an unattended install is the one act that
    /// depends on it most. With the ledger dead we cannot make the promise, so
    /// we do not perform the act. A human can still install by hand and is told
    /// what is missing (see [`ManualConcern::UnrecordedSighting`]).
    LedgerUnwritable,
    /// The ledger on disk could not be READ, so it was replaced with a fresh one
    /// holding only this sighting. Every earlier record is gone — including,
    /// possibly, the bytes this very version first arrived carrying.
    ///
    /// Kept distinct from [`Self::LedgerUnwritable`] because the remedy and the
    /// honest sentence are different ones: nothing is wrong with the permissions
    /// or the disk, and there is nothing for the user to fix. What there is, is
    /// a comparison we can no longer make, on the one refusal with no override
    /// anywhere. So this install waits — and the version starts its soak again
    /// from the sighting we just wrote, because that is genuinely all this
    /// machine now knows about it.
    LedgerReset,
}

/// A version newer than the one we are running, together with the only fact
/// about it that this machine can actually vouch for: how long it has been able
/// to SEE it.
///
/// This exists because of what a withdrawal notice is capable of. An attacker
/// holding the release key can publish a malicious version and revoke every
/// legitimate one, and the withdrawal message then goes out on every machine in
/// the fleet carrying our voice. If that message says "install the new one now",
/// the soak window — the single guardrail that costs an attacker real time — is
/// gone, not because it was bypassed but because we talked the user out of it.
/// So the notice carries the visibility instead of an instruction, and a caller
/// that renders it has the facts to say "this has been public for two hours"
/// rather than "install it".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewerRelease {
    pub version: String,
    /// Seconds since THIS machine first saw this version (the same local,
    /// tamper-proof clock the soak window is anchored on).
    pub visible_for_s: u64,
}

impl NewerRelease {
    /// Whether this version is still inside the client's soak floor — i.e.
    /// whether the automatic path would refuse to install it right now.
    pub fn inside_soak(&self) -> bool {
        self.visible_for_s < SOAK_FLOOR.as_secs()
    }

    /// Whole hours of visibility, rounded down; the unit a human notice uses.
    pub fn visible_hours(&self) -> u64 {
        self.visible_for_s / 3600
    }
}

/// What the caller should do after a check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Nothing available (already current, or the manifest offers nothing newer).
    UpToDate,
    /// Install it. The artifact is the platform match from the manifest.
    Install { version: String, artifact: Artifact, security: bool },
    /// Do not install; tell the user a newer version exists and why we held.
    Notify { version: String, hold: Hold },
    /// The version we are RUNNING has been withdrawn by the publisher.
    ///
    /// `newer` is the version the manifest offers to move to, if there is one
    /// that is both strictly newer AND not itself withdrawn. It is `None` in the
    /// most ordinary withdrawal there is — "we shipped it, it is bad, we pulled
    /// it" — where the withdrawn build IS the newest published version and there
    /// is nowhere forward to go. Callers must render that case differently:
    /// telling someone to install the version they are already running and have
    /// just been told is broken is not a recovery instruction, it is noise.
    ///
    /// `rollback_available` says whether a last-known-good copy is on disk.
    CurrentRevoked {
        current: String,
        newer: Option<NewerRelease>,
        rollback_available: bool,
    },
}

/// Everything [`decide`] needs, all of it already fetched/verified/read by the
/// caller. Pure in, pure out — no clock, no disk, no network in here, so the
/// policy is exhaustively testable.
#[derive(Debug, Clone)]
pub struct Input<'a> {
    pub manifest: &'a Manifest,
    pub current: &'a str,
    pub mode: Mode,
    /// Local rollout label (see [`rollout_id`]). Never transmitted.
    pub rollout_id: &'a str,
    pub now_unix: u64,
    /// When THIS machine first saw this exact version (see [`note_seen`]).
    pub first_seen_unix: u64,
    /// The artifact sha256 this machine recorded the first time it saw this
    /// version, if any.
    pub seen_sha256: Option<&'a str>,
    /// What the local ledger can actually vouch for after recording that
    /// sighting (see [`LedgerStatus`]). Anything but [`LedgerStatus::Intact`]
    /// means `seen_sha256` is a value we invented this run, so it cannot
    /// disagree with the manifest and the hash-conflict refusal is not running.
    pub ledger: LedgerStatus,
    /// Versions that failed a health probation here.
    pub pinned: &'a [String],
    /// The last unattended install this machine performed, if it remembers one
    /// (see [`Installed`]). `None` on a machine that has never auto-installed —
    /// or that installed with a client older than this record.
    pub installed: Option<&'a Installed>,
    /// Whether a last-known-good copy exists on disk right now.
    pub lkg_present: bool,
}

/// The whole auto-update policy, as one pure function.
pub fn decide(input: &Input<'_>) -> Decision {
    let m = input.manifest;

    // 1. Is the build we are RUNNING withdrawn? This outranks everything: a
    //    revoked build is one we have said out loud should not be running.
    if m.is_revoked(input.current) {
        // Where there is somewhere forward to go, say where AND how long this
        // machine has been able to see it — never "install it now". A version
        // that is itself withdrawn is not somewhere to go, and neither is the
        // version we are already running (the `latest == current` case, which is
        // what an ordinary "we pulled the release we just shipped" looks like).
        let newer = if crate::is_newer(&m.version, input.current) && !m.is_revoked(&m.version) {
            Some(NewerRelease {
                version: m.version.clone(),
                visible_for_s: input
                    .now_unix
                    .saturating_sub(soak_anchor(input.first_seen_unix, m.released_unix())),
            })
        } else {
            None
        };
        return Decision::CurrentRevoked {
            current: input.current.to_string(),
            newer,
            rollback_available: input.lkg_present,
        };
    }

    if !crate::is_newer(&m.version, input.current) {
        return Decision::UpToDate;
    }
    let version = m.version.clone();
    let notify = |hold: Hold| Decision::Notify { version: version.clone(), hold };

    // 2. Refusals that apply in EVERY mode, including manual-adjacent ones,
    //    because they are statements about the artifact rather than about how
    //    eager the user is.
    if m.is_revoked(&m.version) {
        return notify(Hold::Revoked);
    }
    let Some(artifact) = m.artifact_for_current_platform().cloned() else {
        return notify(Hold::NoArtifact);
    };
    if let Some(seen) = input.seen_sha256 {
        if !seen.eq_ignore_ascii_case(&artifact.sha256) {
            return notify(Hold::HashConflict {
                seen_sha256: seen.to_string(),
                now_sha256: artifact.sha256.clone(),
            });
        }
    }
    if input.pinned.iter().any(|p| crate::same_version(p, &m.version)) {
        return notify(Hold::Pinned);
    }

    // 2b. Have we already done exactly this? An install does not replace the
    //     running process, so between the swap and the next restart `current` is
    //     STILL the old version and every check would otherwise install the same
    //     build again — each one moving the app into `.lkg` and so overwriting
    //     the rollback copy with the build on trial. Checked BEFORE the mode
    //     gates: a machine set to `notify` that already has the swap on disk
    //     needs to hear "restart to run it", not "run `alice-miner update`".
    //
    //     This is also the only thing standing between a version-mismatched build
    //     and an unbounded install loop, because for such a build the restart
    //     never reconciles `current` with the manifest. See [`Installed`].
    if let Some(rec) = input.installed {
        if crate::same_version(&rec.version, &m.version) {
            return notify(Hold::AlreadyInstalled {
                installed_ago_s: input.now_unix.saturating_sub(rec.at_unix),
            });
        }
    }

    // 3. Mode gates.
    match input.mode {
        Mode::Off => return notify(Hold::ModeOff),
        Mode::Notify => return notify(Hold::NotifyOnly),
        Mode::SecurityOnly if !m.is_security() => return notify(Hold::NotSecurity),
        _ => {}
    }

    // 3b. From here on we are deciding to install something nobody asked for,
    //     and that decision leans on the local ledger: it is what makes "the
    //     same version, different bytes" detectable at all. If the sighting did
    //     not make it to disk, the ledger will agree with whatever the server
    //     says forever, so the check is not merely failing — it is gone. Hold.
    //     (This is checked HERE, after the mode gates, so a machine set to
    //     `off`/`notify` still hears the reason it actually cares about.)
    //     Both failure directions hold, and they say different things: one is a
    //     write we could not make, the other is a read that came back empty and
    //     took the prior records with it. Neither is "recorded".
    match input.ledger {
        LedgerStatus::Intact => {}
        LedgerStatus::Unwritable => return notify(Hold::LedgerUnwritable),
        LedgerStatus::Reset => return notify(Hold::LedgerReset),
    }

    // 4. Soak. Anchored on OUR first sighting, floored by OUR constant; the
    //    manifest may only push it further out.
    let soak = SOAK_FLOOR
        .as_secs()
        .max(m.soak_hours.unwrap_or(0).saturating_mul(3600));
    let ready_at = soak_anchor(input.first_seen_unix, m.released_unix()).saturating_add(soak);
    if input.now_unix < ready_at {
        return notify(Hold::Soaking {
            ready_in_s: ready_at - input.now_unix,
        });
    }

    // 5. Rollout slice. `rollout_pct` is a CEILING: absent means 100, and a
    //    value above 100 is clamped rather than trusted.
    let pct = m.rollout_pct.unwrap_or(100).min(100);
    let bucket = rollout_bucket(input.rollout_id, &m.version);
    if bucket >= pct {
        return notify(Hold::Rollout { bucket, pct });
    }

    Decision::Install {
        version: m.version.clone(),
        artifact,
        security: m.is_security(),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// The MANUAL path (pure)
//
// `decide` above answers "may this machine install this WITHOUT being asked".
// The manual path asks a different question and must not reuse that answer: a
// soak hold, a rollout slice and a mode setting are all statements about how
// eager the machine is allowed to be, and a human typing `alice-miner update` has
// overridden all three on purpose. That is what manual means.
//
// But three of the checks in `decide` are not about eagerness at all. They are
// statements about the ARTIFACT — "the publisher withdrew this", "the bytes
// behind this version number changed", "this exact build already failed here" —
// and those do not become less true because a human typed a command. Until now
// they lived only on the automatic path, which made `alice-miner update` the
// front door around every one of them: a re-published version was refused
// automatically and installed manually.
//
// So the manual path gets its own pure gate. It is deliberately NARROWER than
// `decide` (no soak, no rollout, no mode) and it never widens it.
// ────────────────────────────────────────────────────────────────────────────

/// Everything [`decide_manual`] needs. Pure in, pure out, like [`Input`].
#[derive(Debug, Clone)]
pub struct ManualInput<'a> {
    pub manifest: &'a Manifest,
    /// The version this process is RUNNING. Not the version some earlier check
    /// reported, and not a version the manifest supplies: the manual path must
    /// be able to answer "is this thing older than what I am" from a fact the
    /// publisher cannot restate.
    pub current: &'a str,
    /// The sha256 of the artifact we are about to install, if this platform has
    /// one. `None` means there is nothing to install here (manual download), and
    /// there is correspondingly nothing to compare against the ledger.
    pub artifact_sha256: Option<&'a str>,
    /// The sha256 this machine recorded the FIRST time it saw this version.
    pub seen_sha256: Option<&'a str>,
    /// What the local ledger can vouch for (see [`Input::ledger`]).
    /// [`LedgerStatus::Intact`] when there was nothing to record.
    pub ledger: LedgerStatus,
    /// Versions that failed a health probation here.
    pub pinned: &'a [String],
    /// The last unattended install this machine performed, if any (see
    /// [`Installed`]). The manual path needs it for the same reason the
    /// automatic one does — applying an update that is already on disk moves the
    /// genuine last-known-good copy aside and replaces it with the build being
    /// tested — and because a check the automatic path makes and the manual path
    /// skips is a check with a front door around it.
    pub installed: Option<&'a Installed>,
}

/// A refusal on the manual path. These are not negotiable by a "don't ask me"
/// flag: `--yes` means "stop asking me questions", and it must never quietly
/// also mean "ignore what we already know".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManualRefusal {
    /// The version this machine first saw carrying one package is now being
    /// offered as a DIFFERENT package under the same version number.
    ///
    /// There is no override for this, by design. Every other guardrail here has
    /// a human escape hatch because a human can have context we do not. This one
    /// does not, because the evidence is the machine's own append-only ledger —
    /// the one input in the whole update path that a stolen key cannot rewrite —
    /// and "install it anyway" is never the right answer to it. The remedy is a
    /// new version number, not a louder click.
    HashConflict { seen_sha256: String, now_sha256: String },
    /// The build being offered is not newer than the one running. `update` means
    /// "move forward"; it has never meant "put an older build back".
    ///
    /// This is not a theoretical tidiness rule. `evaluate` tests `min_supported`
    /// BEFORE it tests `is_newer`, so a manifest saying `min_supported: 99.0.0`
    /// with `version: 0.6.4` lands in `CheckOutcome::Unsupported` — a state whose
    /// whole purpose is "you must upgrade" — while pointing at a DOWNGRADE. On a
    /// client that reads that state as a hard-upgrade notice and applies it, the
    /// reachable end of that is a signed, silent return to the exact builds this
    /// release exists to escape (v0.6.5/6/7 pin an engine that cannot mine
    /// post-fork Pearl), reinstalled on a loop because the downgraded build is
    /// still below `min_supported`.
    ///
    /// No override, for the same reason as the hash conflict: the evidence is
    /// the version this process is running, which the publisher cannot rewrite.
    /// The remedy for a genuinely wanted downgrade is a manual install, not a
    /// flag on the updater.
    NotNewer { offered: String, current: String },
    /// The publisher has withdrawn this version.
    Revoked,
}

/// A concern that does not refuse the install but must be raised, in its own
/// right, before it happens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManualConcern {
    /// This machine installed this exact version before and rolled it back.
    /// The user may still choose it — their machine, their call — but it is a
    /// decision they get to make knowingly, and a `--yes` on the command line is
    /// not that decision.
    Pinned,
    /// The sighting could not be written to the local ledger, so the
    /// hash-conflict refusal — the one check here with no override — is not
    /// running on this machine and will not run on the next install either.
    ///
    /// A concern rather than a refusal, deliberately. Refusing would mean a
    /// machine with an unwritable `~/.alice` could never update by hand at all,
    /// and the person typing the command is the one entitled to weigh that. But
    /// it must not pass silently under `--yes`: "stop asking me questions" was
    /// typed before anyone knew the machine had stopped remembering answers.
    UnrecordedSighting,
    /// This machine has already installed this exact version; the swap is on
    /// disk and takes effect at the next start.
    ///
    /// A second question rather than a refusal: someone who believes the
    /// installed copy is damaged is entitled to re-apply it, and it is their
    /// machine. But it must not pass silently under `--yes`, because applying it
    /// again moves the CURRENT app into the last-known-good slot — i.e. it
    /// replaces the copy the machine would roll back to with the build that has
    /// not proven itself yet, and the rollback then restores the same build it is
    /// rolling back from.
    AlreadyInstalled,
    /// The ledger could not be read and has been replaced, so this machine's
    /// memory of which package each version arrived with starts again from this
    /// sighting. A concern for the same reason as
    /// [`Self::UnrecordedSighting`] — and a DIFFERENT sentence, because nothing
    /// here is the user's to fix and telling them to go and check their disk
    /// permissions would be a guess dressed up as a diagnosis.
    LedgerReset,
}

/// What the manual path may do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManualVerdict {
    /// Nothing we know stands in the way. The caller's ordinary confirmation
    /// (or `--yes`) is enough.
    Proceed,
    /// Do not install. Not with `--yes`, not with a click.
    Refuse(ManualRefusal),
    /// Install only after a SEPARATE, explicit, interactive confirmation that
    /// names the concern. Never satisfied by `--yes`.
    ConfirmFirst(ManualConcern),
}

/// The manual-path gate, as one pure function.
///
/// Ordering is deliberate. The two findings that rest on evidence the publisher
/// cannot restate come first — the local ledger, and the version this process is
/// actually running. Revocation and the pin are claims made elsewhere: one by the
/// manifest (attacker-controlled under key compromise), one by this machine's own
/// past. If several findings apply at once, the one the user most needs to read
/// is the one nobody upstream could have written.
pub fn decide_manual(input: &ManualInput<'_>) -> ManualVerdict {
    let m = input.manifest;

    if let (Some(seen), Some(now)) = (input.seen_sha256, input.artifact_sha256) {
        if !seen.eq_ignore_ascii_case(now) {
            return ManualVerdict::Refuse(ManualRefusal::HashConflict {
                seen_sha256: seen.to_string(),
                now_sha256: now.to_string(),
            });
        }
    }
    if !crate::is_newer(&m.version, input.current) {
        return ManualVerdict::Refuse(ManualRefusal::NotNewer {
            offered: m.version.clone(),
            current: input.current.to_string(),
        });
    }
    if m.is_revoked(&m.version) {
        return ManualVerdict::Refuse(ManualRefusal::Revoked);
    }
    if input.pinned.iter().any(|p| crate::same_version(p, &m.version)) {
        return ManualVerdict::ConfirmFirst(ManualConcern::Pinned);
    }
    if input
        .installed
        .is_some_and(|rec| crate::same_version(&rec.version, &m.version))
    {
        return ManualVerdict::ConfirmFirst(ManualConcern::AlreadyInstalled);
    }
    match input.ledger {
        LedgerStatus::Intact => {}
        LedgerStatus::Unwritable => {
            return ManualVerdict::ConfirmFirst(ManualConcern::UnrecordedSighting)
        }
        LedgerStatus::Reset => return ManualVerdict::ConfirmFirst(ManualConcern::LedgerReset),
    }
    ManualVerdict::Proceed
}

/// The instant the soak window may be measured from.
///
/// `first_seen_unix` is a wall-clock reading taken on THIS machine, and that is
/// exactly its weakness. A rig whose RTC has no battery — ordinary on cheap
/// mining boxes — boots at a fixed old date, records its one sighting there, and
/// then NTP corrects the clock. The subtraction `now - first_seen` is now years,
/// so the soak floor is satisfied instantly by a version that has existed for
/// minutes: the single guardrail that costs an attacker holding the release key
/// real time, defeated by a dead coin cell rather than by anything the attacker
/// had to do.
///
/// The repair is the only other timestamp in the problem, `released`, used as a
/// FLOOR and nothing else. Read the direction carefully, because this is a
/// manifest field and every manifest field is attacker-controlled under key
/// compromise:
///
///   * an attacker back-dating `released` (or writing garbage into it) makes the
///     floor lower than the sighting, so `max` picks the sighting and the
///     behaviour is *exactly* what it was before this function existed — they
///     gain nothing;
///   * an attacker post-dating `released` pushes the anchor later, i.e. makes
///     the soak LONGER — the harmless direction;
///   * an honest manifest on a machine with a working clock is a no-op: you
///     cannot see a version before it is published, so the sighting is always
///     the later of the two.
///
/// It bites in exactly one case: a local clock claiming to have seen a version
/// before that version existed. Which is the bug.
///
/// What it does NOT fix, stated plainly: a stolen key plus a broken clock. An
/// attacker who knows a target's RTC is dead can back-date `released` and get
/// today's (defective) behaviour on that machine. Fixing that needs a time
/// source the release key does not control, which this client does not have.
pub fn soak_anchor(first_seen_unix: u64, released_unix: Option<u64>) -> u64 {
    match released_unix {
        Some(released) => first_seen_unix.max(released),
        None => first_seen_unix,
    }
}

/// How long a version has been visible to this machine, in seconds. Saturating,
/// so a clock that went backwards reads as "just seen" rather than as an
/// enormous, install-clearing age.
///
/// Callers that have the manifest should pass [`soak_anchor`]'s output rather
/// than the raw sighting, so the reported age and the enforced soak cannot
/// disagree — a notice reading "seen for 2400 days" next to a hold that is
/// counting down would be the client contradicting itself.
pub fn visible_for(now_unix: u64, first_seen_unix: u64) -> u64 {
    now_unix.saturating_sub(first_seen_unix)
}

/// Whether that visibility is still inside the client's soak floor — i.e.
/// whether the automatic path would decline to install it right now.
///
/// The manual path does NOT gate on this. It reports it: a human who asks for a
/// version minutes after it appeared is allowed to have it, and is entitled to
/// know they are the one taking the first look.
pub fn inside_soak(visible_for_s: u64) -> bool {
    visible_for_s < SOAK_FLOOR.as_secs()
}

/// This machine's stable 0..99 bucket for a given version. Deterministic (the
/// same machine gets the same answer every restart, so a held machine stays held
/// and a chosen one stays chosen — reproducible when someone asks "why did MY
/// box update"), and re-drawn per version so a machine is not permanently last
/// in every rollout.
pub fn rollout_bucket(rollout_id: &str, version: &str) -> u8 {
    let mut h = Sha256::new();
    h.update(b"alice-miner/rollout/v1\n");
    h.update(rollout_id.as_bytes());
    h.update(b"\n");
    h.update(version.as_bytes());
    let d = h.finalize();
    let n = u64::from_be_bytes(d[..8].try_into().expect("sha256 is 32 bytes"));
    (n % 100) as u8
}

// ────────────────────────────────────────────────────────────────────────────
// Local state: rollout id, seen ledger, pins, productivity mark
// ────────────────────────────────────────────────────────────────────────────

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| UpdateError::Io(format!("create {}: {e}", parent.display())))?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, bytes).map_err(|e| UpdateError::Io(format!("write tmp: {e}")))?;
    std::fs::rename(&tmp, path).map_err(|e| UpdateError::Io(format!("rename: {e}")))
}

/// The local rollout label, created once and reused. **Not** a machine
/// fingerprint: it is random bytes with no hardware or identity input, it never
/// leaves the machine, and deleting the file simply re-draws the bucket.
///
/// A machine id derived from hardware would have been easier and is deliberately
/// not used — a value that identifies the machine tends to end up in a request
/// eventually, and there is no reason for a rollout bucket to be re-identifiable.
pub fn rollout_id(state_dir: &Path) -> String {
    let path = state_dir.join("update-rollout-id");
    if let Ok(s) = std::fs::read_to_string(&path) {
        let s = s.trim().to_string();
        if s.len() >= 16 {
            return s;
        }
    }
    // Seed from sources that differ per machine AND per creation moment. This is
    // a label, not a key: it needs to be unpredictable enough that buckets are
    // uncorrelated across machines, nothing more.
    let mut h = Sha256::new();
    h.update(b"alice-miner/rollout-id/v1\n");
    h.update(now_unix().to_be_bytes());
    h.update(std::process::id().to_be_bytes());
    h.update(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
            .to_be_bytes(),
    );
    h.update(path.as_os_str().as_encoded_bytes());
    if let Ok(exe) = std::env::current_exe() {
        h.update(exe.as_os_str().as_encoded_bytes());
    }
    let id = hex::encode(&h.finalize()[..16]);
    let _ = write_atomic(&path, id.as_bytes());
    id
}

/// One remembered sighting of a version.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Seen {
    pub version: String,
    pub first_seen_unix: u64,
    /// The artifact sha256 for THIS platform when we first saw the version.
    pub sha256: String,
}

fn seen_path(state_dir: &Path) -> PathBuf {
    state_dir.join("update-seen.json")
}

/// Where an unreadable ledger is moved before it is replaced, so the evidence
/// survives for whoever asks what happened. One slot, deliberately: a machine
/// that damages its ledger repeatedly should not accumulate files.
fn seen_quarantine_path(state_dir: &Path) -> PathBuf {
    state_dir.join("update-seen.json.unreadable")
}

/// The ledger as found on disk, and whether reading it lost anything.
struct LedgerRead {
    entries: Vec<Seen>,
    /// A ledger file was PRESENT and could not be read or parsed. `entries` is
    /// therefore empty for a reason that is not "this machine has never seen a
    /// version" — the distinction the old `unwrap_or_default()` erased.
    damaged: bool,
}

fn read_seen(state_dir: &Path) -> LedgerRead {
    let empty = |damaged| LedgerRead {
        entries: Vec::new(),
        damaged,
    };
    match std::fs::read(seen_path(state_dir)) {
        // No ledger yet: an ordinary first run, and nothing was lost.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => empty(false),
        // A file we cannot read is a record we cannot consult. Whatever the
        // reason, we no longer know what this machine used to know.
        Err(_) => empty(true),
        Ok(bytes) => match serde_json::from_slice::<Vec<Seen>>(&bytes) {
            Ok(entries) => LedgerRead {
                entries,
                damaged: false,
            },
            Err(_) => empty(true),
        },
    }
}

/// What this machine's own update ledger can vouch for, after a sighting.
///
/// Three states, not two, and the third is the whole point: the old boolean
/// collapsed "we wrote it and everything we knew is still there" together with
/// "we wrote it over the top of a ledger we could not read", and reported both as
/// recorded. The second one is the erasure of the only check in the update path
/// that does not rest on the release key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerStatus {
    /// The sighting is on disk and every earlier sighting is still with it.
    /// This is the only state in which the hash-conflict refusal is actually
    /// running on this machine.
    Intact,
    /// The ledger on disk could not be read, so it was replaced with a fresh one
    /// holding this sighting alone. Everything this machine had written down —
    /// including, possibly, the bytes this very version first arrived with — is
    /// gone.
    ///
    /// The replacement is deliberate and is NOT the bug: refusing to overwrite
    /// would let a single bad byte permanently disable auto-update on a rig
    /// nobody visits, which is a worse failure than starting the record again.
    /// What was the bug is doing it silently and calling it recorded.
    Reset,
    /// The sighting could not be written at all.
    Unwritable,
}

/// A sighting, plus the one thing the caller cannot see from the record itself:
/// what the ledger it went into can still vouch for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sighting {
    pub seen: Seen,
    /// What the ledger can vouch for. Anything but [`LedgerStatus::Intact`] is a
    /// statement that the hash-conflict refusal did not run here.
    ///
    /// This is not a detail. [`note_seen`] hands back the record it MADE
    /// whenever it has no earlier one, and that record trivially agrees with
    /// the manifest it was built from, so a caller that cannot tell the two
    /// apart will compare the server's hash against the server's hash and
    /// conclude, forever, that nothing is wrong.
    pub ledger: LedgerStatus,
}

impl Sighting {
    /// Whether this sighting can be used as evidence — i.e. whether it came out
    /// of a ledger that still holds what it held before.
    ///
    /// False in BOTH failure directions, on purpose: "we could not write it" and
    /// "we wrote it over records we had already lost" are different sentences to
    /// a human and the same answer to this question. Nothing that lost the
    /// record may ever render as "recorded".
    pub fn on_record(&self) -> bool {
        self.ledger == LedgerStatus::Intact
    }
}

/// Record that we have seen `version` carrying `sha256`, and return the record
/// this machine holds — the FIRST one, never overwritten — together with whether
/// the ledger accepted it.
///
/// This is the append-only local half of a transparency log. It is what makes
/// "the same version, different bytes" detectable on the client rather than only
/// on a server we would also have to trust. Which is precisely why a failed
/// write is reported rather than swallowed: an unwritable state directory used
/// to disarm that check permanently and invisibly.
///
/// The recorded timestamp is also floored by the newest timestamp already in
/// this machine's own ledger. A clock that reads EARLIER than something this
/// machine has already written down is a clock that went backwards (a dead RTC
/// at boot, a dual-boot BIOS in local time), and anchoring a soak window on it
/// would credit the version with time that has not passed. Moving the anchor
/// forward can only ever make the soak longer, so the clamp is safe in the one
/// direction it acts.
pub fn note_seen(state_dir: &Path, version: &str, sha256: &str) -> Sighting {
    let LedgerRead {
        entries: mut all,
        damaged,
    } = read_seen(state_dir);
    // Keyed by the CANONICAL version (see `crate::normalize_version`). Two
    // spellings of one version must be one entry, or re-spelling the number is a
    // free reset of both the soak clock and the recorded bytes — i.e. a way
    // around the hash-conflict refusal, the one check with no override anywhere.
    if let Some(existing) = all.iter().find(|s| crate::same_version(&s.version, version)) {
        return Sighting {
            seen: existing.clone(),
            ledger: LedgerStatus::Intact,
        };
    }
    if damaged {
        // Move the unreadable file aside before replacing it, so the evidence
        // survives for whoever asks, and say so in the local history — this is
        // the moment a machine forgets what it saw, and it must not be the
        // quietest line in the file.
        let _ = std::fs::rename(seen_path(state_dir), seen_quarantine_path(state_dir));
        log_event(
            state_dir,
            "ledger-reset",
            serde_json::json!({
                "version": crate::normalize_version(version),
                "kept_at": seen_quarantine_path(state_dir).display().to_string(),
            }),
        );
    }
    let floor = all.iter().map(|s| s.first_seen_unix).max().unwrap_or(0);
    let rec = Seen {
        version: crate::normalize_version(version).to_string(),
        first_seen_unix: now_unix().max(floor),
        sha256: sha256.to_ascii_lowercase(),
    };
    all.push(rec.clone());
    // Bounded: keep the most recent 200 sightings. Old versions falling off
    // cannot weaken anything — a version we no longer remember is one nobody is
    // offering us any more.
    if all.len() > 200 {
        let drop = all.len() - 200;
        all.drain(..drop);
    }
    let written = serde_json::to_vec_pretty(&all)
        .ok()
        .map(|bytes| write_atomic(&seen_path(state_dir), &bytes).is_ok())
        .unwrap_or(false);
    // Precedence: a write we could not make outranks a read we could not make.
    // If the write failed there is no fresh ledger either, so calling it a reset
    // would claim a self-heal that did not happen.
    let ledger = match (written, damaged) {
        (false, _) => LedgerStatus::Unwritable,
        (true, true) => LedgerStatus::Reset,
        (true, false) => LedgerStatus::Intact,
    };
    Sighting { seen: rec, ledger }
}

fn pins_path(state_dir: &Path) -> PathBuf {
    state_dir.join("update-pins.json")
}

/// Versions this machine refuses to auto-install because they already failed a
/// health probation here.
pub fn pins(state_dir: &Path) -> Vec<String> {
    std::fs::read(pins_path(state_dir))
        .ok()
        .and_then(|b| serde_json::from_slice::<Vec<String>>(&b).ok())
        .unwrap_or_default()
}

/// How many failed versions one machine remembers. Each entry costs a few bytes
/// and each one costs an install + a full probation + a rollback to earn, so the
/// list cannot realistically grow to this in a machine's lifetime; the cap exists
/// so a misbehaving update server cannot make the file unbounded.
const MAX_PINS: usize = 512;

/// Pin a version so it is never auto-installed on this machine again. A manual
/// `alice-miner update` can still install it — the user overriding a machine's
/// own bad experience is a decision they are allowed to make, with the warning
/// in front of them.
///
/// When the cap is reached the LOWEST version is dropped, not the oldest entry.
/// The updater only ever installs something [`crate::is_newer`] than what is
/// running, so the lowest pinned version is the one least able to be offered
/// again; dropping by insertion order could evict a *high* version that is very
/// much still offerable. (Residual, stated rather than hidden: any bounded list
/// can in principle forget a version that is later re-published as `latest`. With
/// this rule that needs 512 distinct failed auto-updates on one machine first.)
pub fn pin(state_dir: &Path, version: &str) {
    let mut all = pins(state_dir);
    // Canonical in, canonical compared: a pin written from a `v`-prefixed
    // probation record must still match a manifest that spells the same version
    // without the prefix, and vice versa.
    let version = crate::normalize_version(version);
    if all.iter().any(|v| crate::same_version(v, version)) {
        return;
    }
    all.push(version.to_string());
    while all.len() > MAX_PINS {
        // The lowest by the same comparator the updater uses to decide "newer".
        // An unparseable version reads as (0,0,0) — which also makes it the one the
        // updater can never consider newer than anything, so it is the right one to
        // lose first.
        let lowest = all
            .iter()
            .enumerate()
            .min_by_key(|(_, v)| crate::parse_version(v))
            .map(|(i, _)| i)
            .unwrap_or(0);
        all.remove(lowest);
    }
    if let Ok(bytes) = serde_json::to_vec_pretty(&all) {
        let _ = write_atomic(&pins_path(state_dir), &bytes);
    }
}

/// What this machine did the last time it installed something without being
/// asked — the durable answer to "have I already applied this?".
///
/// Nothing on the automatic path used to record it, and the omission had a
/// reachable cost. [`decide`] gates on `is_newer(manifest.version, current)` and
/// nothing else, where `current` is what the RUNNING BINARY answers
/// (`CARGO_PKG_VERSION`). Those two disagree in two ordinary situations:
///
///   * **between the swap and the restart.** An install does not replace the
///     running process — the new build takes over at the next start. A rig that
///     mines for a week therefore keeps reporting the old version, and the
///     six-hourly re-check kept seeing "newer version available" and installing
///     it again. Each install moves the app aside into `.lkg`, so the SECOND one
///     overwrote the genuine rollback copy with the new build: the probation
///     would then "roll back" to the same build it was rolling back FROM, and
///     report a restore that restores nothing.
///   * **when the published number and the binary's own number differ at all.**
///     Ship a tree that says `0.6.7` as `0.6.8` and the disagreement is
///     permanent: install, arm a probation for `0.6.8`, discard it at the next
///     launch because the binary says `0.6.7`, and install again six hours
///     later, for ever.
///
/// The version bump fixes the second case for this release. It does not fix the
/// first, and it does not fix the class: `decide` had no memory of a completed
/// install, so any future disagreement between the manifest's claim and the
/// binary's answer becomes an unbounded loop. This record is that memory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Installed {
    /// The version this machine installed, in its canonical spelling.
    pub version: String,
    /// The artifact sha256 it installed, for the local history.
    pub sha256: String,
    pub at_unix: u64,
}

fn installed_path(state_dir: &Path) -> PathBuf {
    state_dir.join("update-installed.json")
}

/// The last unattended install this machine performed, if it remembers one.
///
/// A record that cannot be read reads as `None` — i.e. as the behaviour that
/// existed before this record did. That is a deliberate fail-OPEN, and it is the
/// same trade the seen ledger makes: the alternative, holding on an unreadable
/// file, would let one bad byte disable auto-update permanently on a machine
/// nobody visits, and unlike the ledger there would be nothing to self-heal it —
/// the only thing that rewrites this file is an install we would be refusing to
/// perform. The exposure is bounded by what it protects: worst case we are back
/// to re-installing, which is what happened before.
pub fn installed(state_dir: &Path) -> Option<Installed> {
    let b = std::fs::read(installed_path(state_dir)).ok()?;
    serde_json::from_slice(&b).ok()
}

/// Record that this machine has installed `version`. Called by the driver
/// immediately after the swap succeeds — never before, because a record of an
/// install that did not happen would hold every future check on a build the
/// machine has not got.
///
/// Returns whether it reached disk. A failure here costs the loop protection and
/// nothing else, so the caller logs it rather than failing the install.
pub fn note_installed(state_dir: &Path, version: &str, sha256: &str) -> bool {
    let rec = Installed {
        version: crate::normalize_version(version).to_string(),
        sha256: sha256.to_ascii_lowercase(),
        at_unix: now_unix(),
    };
    serde_json::to_vec_pretty(&rec)
        .ok()
        .map(|bytes| write_atomic(&installed_path(state_dir), &bytes).is_ok())
        .unwrap_or(false)
}

fn productive_path(state_dir: &Path) -> PathBuf {
    state_dir.join("last-accepted-share.json")
}

/// Record that an accepted share landed. Called (throttled) by the mining loop.
/// This is the ONLY input that lets the mining probation tell "the new build
/// broke earning" apart from "the network is down".
pub fn mark_productive(state_dir: &Path) {
    let body = serde_json::json!({ "last_accepted_unix": now_unix() });
    if let Ok(bytes) = serde_json::to_vec(&body) {
        let _ = write_atomic(&productive_path(state_dir), &bytes);
    }
}

/// When an accepted share last landed on this machine, if ever.
pub fn last_productive_unix(state_dir: &Path) -> Option<u64> {
    let b = std::fs::read(productive_path(state_dir)).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&b).ok()?;
    v.get("last_accepted_unix")?.as_u64()
}

/// Whether the build being replaced was earning recently enough to serve as a
/// baseline for judging the new one.
pub fn was_recently_productive(state_dir: &Path) -> bool {
    match last_productive_unix(state_dir) {
        Some(t) => now_unix().saturating_sub(t) <= PRODUCTIVE_WINDOW.as_secs(),
        None => false,
    }
}

/// Append one line to the local, human-readable auto-update history. Best-effort
/// and capped; it exists so a miner (or we, over their shoulder) can answer
/// "what did this machine install, when, and why" without a server.
pub fn log_event(state_dir: &Path, event: &str, detail: serde_json::Value) {
    let path = state_dir.join("update-history.jsonl");
    let line = serde_json::json!({
        "at_unix": now_unix(),
        "event": event,
        "client": crate::current_version(),
        "detail": detail,
    });
    let Ok(mut s) = serde_json::to_string(&line) else {
        return;
    };
    s.push('\n');
    // Rotate at ~256 KiB so a long-lived rig cannot grow this without bound.
    if std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) > 256 * 1024 {
        let _ = std::fs::rename(&path, path.with_extension("jsonl.1"));
    }
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = f.write_all(s.as_bytes());
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Health probation for an AUTO-installed build
// ────────────────────────────────────────────────────────────────────────────

/// What the machine knows, at the moment of an unattended install, about whether
/// the build being REPLACED was earning.
///
/// There are three answers, not two, and collapsing them into a bool is the F5
/// half of the F4 bug. [`was_recently_productive`] reads one stamp and reports
/// "an accepted share landed here within [`PRODUCTIVE_WINDOW`]" — and the
/// acceptance guard (layer 3) freezes that stamp on purpose when it halts a lane,
/// which is exactly what a multi-day upstream collapse looks like. The August
/// 2026 outage ran 78 hours, past the 72-hour window. [`judge_session`] knows
/// about that halt and abstains; `mark_productive`'s caller knows about it and
/// declines to refresh a frozen counter. The ARMING path did not, so a build
/// installed mid-outage armed as "there was no baseline anyway", and
/// [`confirm_start`] then committed it — dropping last-known-good — on the first
/// `status` or `stop` the user typed, having never mined a share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EarningBaseline {
    /// An accepted share landed here recently. The mining half of the probation
    /// is armed: the new build can be rolled back for not earning.
    Earning,
    /// Nothing was earning here and nothing was stopping it — an idle rig, a
    /// fresh install, a machine that has never mined. "The new build is not
    /// earning either" would say nothing about the new build, so the probation
    /// commits on the start proof alone, the same bar a manual update clears.
    NotEarning,
    /// We cannot tell: the acceptance guard was holding this machine's lane when
    /// the install happened, which freezes the earning stamp by design.
    ///
    /// Neither of the other two answers is available here, and both are wrong in
    /// a costly direction — `Earning` would let an upstream outage roll back an
    /// innocent build, `NotEarning` would throw away last-known-good for a build
    /// that has not mined once. So this one waits: it never strikes and never
    /// rolls back, it commits when a real accepted share arrives, and failing
    /// that it expires with [`PROBATION_MAX`] like any other stalled trial.
    Unknown,
}

/// The on-disk probation record for a build installed without being asked for.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Probation {
    /// The version on trial.
    pub version: String,
    /// The version it replaced (the rollback target).
    pub previous: String,
    pub armed_at_unix: u64,
    /// How many times a process of `version` has reached startup.
    pub launches: u32,
    /// Whether `version` has ever got past startup into real work.
    pub started_ok: bool,
    /// Whether the OUTGOING build was landing accepted shares shortly before the
    /// swap. When false the mining half of the probation abstains entirely.
    pub previous_productive: bool,
    /// Whether that `false` means "we could not tell" rather than "it was not
    /// earning" — see [`EarningBaseline::Unknown`].
    ///
    /// `#[serde(default)]` so a probation record written by an earlier build
    /// still parses, and reads as the answer that build believed it had.
    #[serde(default)]
    pub baseline_unknown: bool,
    /// Mining sessions of at least [`MIN_JUDGED_SESSION`] that saw zero accepted
    /// shares.
    pub failed_sessions: u32,
}

impl Probation {
    /// The three-valued baseline behind the two persisted flags.
    pub fn baseline(&self) -> EarningBaseline {
        if self.previous_productive {
            EarningBaseline::Earning
        } else if self.baseline_unknown {
            EarningBaseline::Unknown
        } else {
            EarningBaseline::NotEarning
        }
    }
}

fn probation_path(app_path: &Path) -> PathBuf {
    let mut s = app_path.as_os_str().to_os_string();
    s.push(".auto-probation");
    PathBuf::from(s)
}

/// Read the probation record, if a build is on trial.
pub fn probation(app_path: &Path) -> Option<Probation> {
    let b = std::fs::read(probation_path(app_path)).ok()?;
    serde_json::from_slice(&b).ok()
}

fn write_probation(app_path: &Path, p: &Probation) -> Result<()> {
    let bytes =
        serde_json::to_vec(p).map_err(|e| UpdateError::Io(format!("encode probation: {e}")))?;
    write_atomic(&probation_path(app_path), &bytes)
}

fn clear_probation(app_path: &Path) {
    let _ = std::fs::remove_file(probation_path(app_path));
}

/// Arm the probation immediately after an unattended install. The caller must
/// NOT also arm `lib.rs`'s manual first-launch marker: this record subsumes it
/// (it covers crash-on-launch too) and, unlike the manual gate, it deliberately
/// keeps the last-known-good copy until a verdict is in.
pub fn arm(
    app_path: &Path,
    version: &str,
    previous: &str,
    baseline: EarningBaseline,
) -> Result<()> {
    write_probation(
        app_path,
        &Probation {
            // Canonical, so a record written from a `v`-prefixed manifest names
            // the build the way the binary will answer. Records written by an
            // earlier client still parse and still match: every comparison below
            // goes through `crate::same_version`.
            version: crate::normalize_version(version).to_string(),
            previous: crate::normalize_version(previous).to_string(),
            armed_at_unix: now_unix(),
            launches: 0,
            started_ok: false,
            previous_productive: baseline == EarningBaseline::Earning,
            baseline_unknown: baseline == EarningBaseline::Unknown,
            failed_sessions: 0,
        },
    )
}

/// What [`register_launch`] concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchVerdict {
    /// No auto-update probation applies.
    Normal,
    /// This process IS the build on trial; it still has to prove itself.
    OnTrial { version: String, mining_gate: bool },
    /// The build on trial reached startup and died there, twice. It has been
    /// pinned, and `restored` says whether the previous build actually made it
    /// back onto disk — a rollback we could not perform must never be reported
    /// as one we did. THIS process is still the failed build either way.
    RolledBack {
        failed_version: String,
        reason: RollbackReason,
        restored: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackReason {
    /// Reached startup repeatedly without ever getting past it.
    CrashOnLaunch,
    /// Started fine but stopped earning, while the build it replaced had been
    /// earning on this same machine.
    StoppedEarning,
}

/// Resolve the auto-update probation at startup. Call once, early, alongside
/// `lib.rs`'s `register_launch` (the two gates are independent and only one can
/// be armed at a time — a manual update arms the marker, an automatic one arms
/// this).
pub fn register_launch(
    state_dir: &Path,
    app_path: &Path,
    running_version: &str,
) -> LaunchVerdict {
    let Some(mut p) = probation(app_path) else {
        return LaunchVerdict::Normal;
    };

    if !crate::same_version(&p.version, running_version) {
        // We are not running the build on trial — either a rollback already took
        // effect or the user installed something else by hand. Either way the
        // trial is over and its record is stale.
        //
        // `same_version`, never `!=`: this is the check that a `v`-prefixed
        // manifest version used to fail, discarding an entirely healthy trial on
        // its first launch and leaving the build with no rollback of any kind.
        clear_probation(app_path);
        return LaunchVerdict::Normal;
    }

    // A trial that never reached a verdict does not keep a spare copy of the app
    // on the miner's disk forever.
    if now_unix().saturating_sub(p.armed_at_unix) > PROBATION_MAX.as_secs() {
        clear_probation(app_path);
        let _ = crate::commit_update(app_path);
        log_event(
            state_dir,
            "probation-expired",
            serde_json::json!({ "version": p.version }),
        );
        return LaunchVerdict::Normal;
    }

    if !p.started_ok && p.launches >= 1 {
        // We have been here before and never got past startup: crash-on-launch.
        return do_rollback(state_dir, app_path, &p, RollbackReason::CrashOnLaunch);
    }

    p.launches = p.launches.saturating_add(1);
    let _ = write_probation(app_path, &p);
    LaunchVerdict::OnTrial {
        version: p.version.clone(),
        mining_gate: p.previous_productive,
    }
}

fn do_rollback(
    state_dir: &Path,
    app_path: &Path,
    p: &Probation,
    reason: RollbackReason,
) -> LaunchVerdict {
    clear_probation(app_path);
    pin(state_dir, &p.version);
    let rolled = crate::rollback(app_path).is_ok();
    log_event(
        state_dir,
        "rolled-back",
        serde_json::json!({
            "version": p.version,
            "to": p.previous,
            "reason": format!("{reason:?}"),
            "restored": rolled,
        }),
    );
    LaunchVerdict::RolledBack {
        failed_version: p.version.clone(),
        reason,
        restored: rolled,
    }
}

/// The binary LOADED and got as far as understanding its command line — it is not
/// crash-on-launch. Records only that; it never commits the update and never drops
/// the last-known-good copy.
///
/// Split out of [`confirm_start`] because those are two different claims and the
/// CLI could only make the weaker one at the point it was calling the stronger:
/// `alice-miner --version` prints and exits, which proves the binary loads and
/// proves nothing about mining. Without this half, simply *not* calling
/// `confirm_start` on such a run would leave `started_ok` false and make the second
/// `--version` look like a crash-on-launch and trigger a rollback.
///
/// Returns `true` if a probation record was updated.
pub fn note_launch_ok(app_path: &Path, running_version: &str) -> bool {
    let Some(mut p) = probation(app_path) else {
        return false;
    };
    if !crate::same_version(&p.version, running_version) || p.started_ok {
        return false;
    }
    p.started_ok = true;
    write_probation(app_path, &p).is_ok()
}

/// The build got past startup into real work. Records that fact, and — when
/// there is no fair mining baseline to judge against — ends the probation right
/// here rather than holding a last-known-good copy hostage to a verdict we have
/// no honest way to reach.
///
/// "Real work" means a command the user actually asked for is about to run. It
/// does NOT mean `--version` or `--help`: those exit before anything happens, and
/// treating them as a successful start is how a build could commit itself (and
/// discard its rollback copy) without ever having mined. Use [`note_launch_ok`]
/// for that weaker claim.
pub fn confirm_start(state_dir: &Path, app_path: &Path, running_version: &str) -> bool {
    let Some(mut p) = probation(app_path) else {
        return false;
    };
    if !crate::same_version(&p.version, running_version) {
        return false;
    }
    if p.baseline() == EarningBaseline::NotEarning {
        // The build we replaced was not earning either, so "this one is not
        // earning" would say nothing about this one. Commit on the start proof
        // alone — the same bar a manual update clears.
        //
        // Note which of the three baselines reaches this: only the one that
        // means "nothing was earning and nothing was stopping it".
        // `EarningBaseline::Unknown` — the lane was HALTED when this landed —
        // must not, because "we watched it not run" is not a reason to throw
        // away the copy we would roll back to.
        clear_probation(app_path);
        let _ = crate::commit_update(app_path);
        log_event(
            state_dir,
            "committed",
            serde_json::json!({ "version": p.version, "on": "start-only (no earning baseline)" }),
        );
        return true;
    }
    p.started_ok = true;
    let _ = write_probation(app_path, &p);
    false
}

/// What the ACCEPTANCE guard (layer 3) has to say about the session being
/// reported — i.e. whether this session is evidence about the build at all.
///
/// This is the cross-layer input F4 is about. Layer 3 can stop mining on purpose,
/// and it can know that the whole network is being rejected; both of those make a
/// zero-accepted session say nothing whatsoever about the client build, and both
/// of them are invisible from inside this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionEvidence {
    /// Nothing disqualifies this session: judge it on its shares.
    #[default]
    Judgeable,
    /// The acceptance guard halted or stopped this machine's lane during the
    /// session. Once it halts, `accepted` is necessarily frozen — reading that as
    /// "the new version does not earn" is layer 2 mistaking layer 3's deliberate
    /// stop for a client failure.
    MiningHalted,
    /// The acceptance guard is spending one bounded window RE-PROBING a halted lane:
    /// the engine is up, the halt flag is deliberately off, and the run is measuring
    /// rather than earning. Kept distinct from [`Self::MiningHalted`] because on the
    /// wire they look nothing alike — a halted rig has no engine at all, a probing one
    /// is indistinguishable from an ordinary miner that earns nothing — and the local
    /// history log is the only place anybody will ever see which of the two spared a
    /// build its rollback.
    AcceptanceProbe,
    /// The acceptance guard is mining this lane normally and has NOT reached a
    /// verdict about it: it is still inside its warm-up, still gathering a period
    /// that has reached neither its window nor its sample floor, or driving an
    /// engine that cannot report pool rejections at all.
    ///
    /// The guard's own rule is that a lane it has not measured is `Unknown`, never
    /// 0%. This is that rule applied one layer up: a zero-accepted session on a lane
    /// nobody has judged is UNMEASURED, not measured-as-broken, and the build must
    /// not be uninstalled over it. It bites hardest exactly where the guard is
    /// slowest — a rig submitting under ~1 share/min needs hours to complete a
    /// period, and one whose relay is unreachable never completes one at all, while
    /// two 20-minute sessions are enough to roll a build back and pin it forever.
    AcceptanceUndecided,
    /// The network-wide lane health says every miner on this lane is being
    /// rejected right now. The local build cannot be the cause.
    NetworkWide,
}

impl SessionEvidence {
    /// Whether this session must not be judged in either direction.
    pub fn abstains(self) -> bool {
        !matches!(self, SessionEvidence::Judgeable)
    }

    /// A stable machine key for the local history log.
    pub fn key(self) -> &'static str {
        match self {
            SessionEvidence::Judgeable => "judgeable",
            SessionEvidence::MiningHalted => "mining-halted",
            SessionEvidence::AcceptanceProbe => "acceptance-probe",
            SessionEvidence::AcceptanceUndecided => "acceptance-undecided",
            SessionEvidence::NetworkWide => "network-wide",
        }
    }
}

/// The outcome of one mining session, fed to the probation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionResult {
    pub ran_secs: u64,
    pub accepted: u64,
    /// What layer 3 says about this session. There is deliberately no `Default`
    /// on this struct: a caller that has not thought about the acceptance guard
    /// should fail to compile rather than silently report a halted lane as if it
    /// were an honest zero.
    pub evidence: SessionEvidence,
}

impl SessionResult {
    /// A session the acceptance guard has no objection to.
    pub fn judgeable(ran_secs: u64, accepted: u64) -> Self {
        Self {
            ran_secs,
            accepted,
            evidence: SessionEvidence::Judgeable,
        }
    }
}

/// What a finished (or long-running) mining session did to the probation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionVerdict {
    /// Not on trial, or the session is too short / too ambiguous to judge.
    NoChange,
    /// Layer 3 disqualified this session, so it counted for NOTHING: no strike,
    /// and no commit either. The probation stays exactly as it was and the build
    /// keeps its last-known-good copy until a session we CAN judge arrives (or
    /// the probation expires). Distinct from [`Self::NoChange`] so an abstention
    /// is visible rather than being indistinguishable from "nothing happened".
    Abstained { reason: SessionEvidence },
    /// The build proved it still earns; probation over, last-known-good dropped.
    Committed { version: String },
    /// The build has now failed enough long sessions; rolled back and pinned.
    /// The caller should tell the user to restart into the restored build.
    RolledBack {
        failed_version: String,
        previous: String,
        /// Whether the previous build is actually back on disk.
        restored: bool,
    },
}

/// What reporting a session DOES to a probation record — the pure half of
/// [`note_session`], so the decision can be tested without a filesystem and so
/// [`session_would_roll_back`] cannot drift from what actually happens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAction {
    /// Say nothing: not on trial, no earning baseline, or too short to judge.
    Ignore,
    /// Not evidence in either direction (see [`SessionEvidence`]).
    Abstain(SessionEvidence),
    /// The build is earning: commit it and drop last-known-good.
    Commit,
    /// One more long, empty, JUDGEABLE session — recorded, below the threshold.
    Strike,
    /// Enough of them: roll back and pin.
    RollBack,
}

/// The pure decision behind [`note_session`]. No clock, no disk, no network.
///
/// Order matters and is the whole of F4: the acceptance guard's word is checked
/// BEFORE the share count, so a halted lane can neither strike the build (its
/// zero is layer 3's doing) nor commit it (we did not watch it earn — we watched
/// it not run).
pub fn judge_session(p: &Probation, running_version: &str, result: &SessionResult) -> SessionAction {
    if !crate::same_version(&p.version, running_version) {
        return SessionAction::Ignore;
    }
    match p.baseline() {
        // No baseline and no reason to expect one: the mining half never votes.
        EarningBaseline::NotEarning => SessionAction::Ignore,

        // We could not tell what the outgoing build was doing, because layer 3
        // was holding the lane when this build landed. That is not a licence to
        // judge the new one either way — but a genuine accepted share is proof
        // enough on its own, and it is the one outcome that can end the trial
        // honestly. Everything short of that waits.
        EarningBaseline::Unknown => {
            if result.evidence.abstains() {
                return SessionAction::Abstain(result.evidence);
            }
            if result.accepted > 0 {
                return SessionAction::Commit;
            }
            SessionAction::Ignore
        }

        EarningBaseline::Earning => {
            if result.evidence.abstains() {
                return SessionAction::Abstain(result.evidence);
            }
            if result.accepted > 0 {
                return SessionAction::Commit;
            }
            if result.ran_secs < MIN_JUDGED_SESSION.as_secs() {
                return SessionAction::Ignore;
            }
            if p.failed_sessions.saturating_add(1) >= FAILED_SESSIONS_TO_ROLLBACK {
                SessionAction::RollBack
            } else {
                SessionAction::Strike
            }
        }
    }
}

/// Whether reporting `result` RIGHT NOW would roll this build back and pin it.
///
/// Read-only: it changes nothing. It exists so the caller can spend a network
/// call establishing whether the WHOLE NETWORK is being rejected at the one
/// moment that matters — the moment before we would otherwise blame the local
/// build — instead of on every tick of every session.
pub fn session_would_roll_back(
    app_path: &Path,
    running_version: &str,
    result: &SessionResult,
) -> bool {
    probation(app_path)
        .map(|p| judge_session(&p, running_version, result) == SessionAction::RollBack)
        .unwrap_or(false)
}

/// Report a mining session against the probation. Safe to call repeatedly with
/// the running totals of a live session: an accepted share commits immediately,
/// and a long zero-accepted session is only counted once per session because the
/// caller passes each session exactly once at its end (or at the moment it
/// crosses [`MIN_JUDGED_SESSION`] with nothing to show).
pub fn note_session(
    state_dir: &Path,
    app_path: &Path,
    running_version: &str,
    result: SessionResult,
) -> SessionVerdict {
    let Some(mut p) = probation(app_path) else {
        return SessionVerdict::NoChange;
    };

    match judge_session(&p, running_version, &result) {
        SessionAction::Ignore => SessionVerdict::NoChange,

        // Nothing is written: not the strike counter, not a commit, not a pin.
        // The probation record survives untouched for a session we CAN judge.
        SessionAction::Abstain(reason) => SessionVerdict::Abstained { reason },

        SessionAction::Commit => {
            clear_probation(app_path);
            let _ = crate::commit_update(app_path);
            log_event(
                state_dir,
                "committed",
                serde_json::json!({ "version": p.version, "on": "accepted share" }),
            );
            SessionVerdict::Committed { version: p.version }
        }

        SessionAction::Strike => {
            p.failed_sessions = p.failed_sessions.saturating_add(1);
            let _ = write_probation(app_path, &p);
            SessionVerdict::NoChange
        }

        SessionAction::RollBack => {
            // No need to persist the final strike: `do_rollback` clears the record.
            let previous = p.previous.clone();
            match do_rollback(state_dir, app_path, &p, RollbackReason::StoppedEarning) {
                LaunchVerdict::RolledBack { failed_version, restored, .. } => {
                    SessionVerdict::RolledBack {
                        failed_version,
                        previous,
                        restored,
                    }
                }
                _ => SessionVerdict::NoChange,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "alice-auto-{}-{}-{}",
            name,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn artifact() -> Artifact {
        Artifact {
            platform: crate::current_platform().to_string(),
            url: "https://example.invalid/a.tar.gz".into(),
            sha256: "aa".repeat(32),
            size: 10,
        }
    }

    fn manifest(version: &str) -> Manifest {
        Manifest {
            schema: 1,
            product: crate::PRODUCT.to_string(),
            version: version.to_string(),
            min_supported: "0.3.0".into(),
            // Before the fixture's `now_unix` (2001-09-09) and before every
            // `first_seen_unix` derived from it, i.e. the ordinary relationship
            // between the two: you cannot see a version before it is published.
            // `soak_anchor` is therefore a no-op in every test that does not set
            // out to exercise it.
            released: "2001-01-01T00:00:00Z".into(),
            notes: String::new(),
            artifacts: vec![artifact()],
            rollout_pct: None,
            soak_hours: None,
            revoked: Vec::new(),
            security: None,
        }
    }

    fn input<'a>(m: &'a Manifest, pins: &'a [String]) -> Input<'a> {
        Input {
            manifest: m,
            current: "0.6.7",
            mode: Mode::Full,
            rollout_id: "test-rollout-id",
            now_unix: 1_000_000_000,
            first_seen_unix: 1_000_000_000 - 10 * 24 * 3600,
            seen_sha256: None,
            ledger: LedgerStatus::Intact,
            pinned: pins,
            installed: None,
            lkg_present: true,
        }
    }

    // ── mode / opt-out ──────────────────────────────────────────────────────

    #[test]
    fn mode_parses_and_round_trips() {
        for m in [Mode::Off, Mode::Notify, Mode::SecurityOnly, Mode::Full] {
            assert_eq!(Mode::parse(m.as_str()), Some(m));
        }
        assert_eq!(Mode::parse("SECURITY_ONLY"), Some(Mode::SecurityOnly));
        // An unknown value never resolves to something MORE permissive.
        assert_eq!(Mode::parse("yes-please"), None);
        assert!(!Mode::Off.installs() && !Mode::Notify.installs());
        assert!(Mode::SecurityOnly.installs() && Mode::Full.installs());
        assert!(!Mode::Off.checks());
    }

    #[test]
    fn opt_out_holds_but_still_reports() {
        let m = manifest("0.6.8");
        let mut i = input(&m, &[]);
        i.mode = Mode::Off;
        assert_eq!(
            decide(&i),
            Decision::Notify { version: "0.6.8".into(), hold: Hold::ModeOff }
        );
        i.mode = Mode::Notify;
        assert_eq!(
            decide(&i),
            Decision::Notify { version: "0.6.8".into(), hold: Hold::NotifyOnly }
        );
    }

    #[test]
    fn security_only_installs_only_flagged_releases() {
        let mut m = manifest("0.6.8");
        let mut i = input(&m, &[]);
        i.mode = Mode::SecurityOnly;
        assert!(matches!(
            decide(&i),
            Decision::Notify { hold: Hold::NotSecurity, .. }
        ));
        m.security = Some(true);
        let i = Input { manifest: &m, mode: Mode::SecurityOnly, ..input(&m, &[]) };
        assert!(matches!(decide(&i), Decision::Install { security: true, .. }));
    }

    // ── staged rollout ──────────────────────────────────────────────────────

    #[test]
    fn rollout_bucket_is_stable_and_version_scoped() {
        let a = rollout_bucket("id-a", "0.6.8");
        assert_eq!(a, rollout_bucket("id-a", "0.6.8"), "must not move on restart");
        assert!(a < 100);
        // Re-drawn per version, so one machine is not permanently last.
        let differs = (0..40).any(|n| rollout_bucket("id-a", &format!("0.6.{n}")) != a);
        assert!(differs);
    }

    #[test]
    fn rollout_bucket_spreads_across_machines() {
        let mut seen = [0usize; 10];
        for n in 0..2000 {
            let b = rollout_bucket(&format!("machine-{n}"), "0.6.8");
            seen[(b / 10) as usize] += 1;
        }
        // Every decile populated: a "10% rollout" must actually be ~10% of the
        // fleet and not a constant.
        assert!(seen.iter().all(|c| *c > 100), "uneven buckets: {seen:?}");
    }

    #[test]
    fn rollout_pct_gates_and_manifest_can_only_narrow() {
        let mut m = manifest("0.6.8");
        let id = "test-rollout-id";
        let b = rollout_bucket(id, "0.6.8");

        m.rollout_pct = Some(0);
        assert!(matches!(
            decide(&input(&m, &[])),
            Decision::Notify { hold: Hold::Rollout { pct: 0, .. }, .. }
        ));

        m.rollout_pct = Some(b); // bucket == pct is OUTSIDE the slice
        assert!(matches!(
            decide(&input(&m, &[])),
            Decision::Notify { hold: Hold::Rollout { .. }, .. }
        ));

        m.rollout_pct = Some(b + 1);
        assert!(matches!(decide(&input(&m, &[])), Decision::Install { .. }));

        // A manifest claiming 200% is clamped, not trusted.
        m.rollout_pct = Some(200);
        assert!(matches!(decide(&input(&m, &[])), Decision::Install { .. }));
    }

    // ── soak window ─────────────────────────────────────────────────────────

    #[test]
    fn soak_window_holds_until_the_floor_elapses() {
        let m = manifest("0.6.8");
        let mut i = input(&m, &[]);
        i.first_seen_unix = i.now_unix; // just seen
        match decide(&i) {
            Decision::Notify { hold: Hold::Soaking { ready_in_s }, .. } => {
                assert_eq!(ready_in_s, SOAK_FLOOR.as_secs());
            }
            other => panic!("expected soak hold, got {other:?}"),
        }
        i.first_seen_unix = i.now_unix - SOAK_FLOOR.as_secs() + 1;
        assert!(matches!(decide(&i), Decision::Notify { hold: Hold::Soaking { .. }, .. }));
        i.first_seen_unix = i.now_unix - SOAK_FLOOR.as_secs();
        assert!(matches!(decide(&i), Decision::Install { .. }));
    }

    #[test]
    fn manifest_can_lengthen_the_soak_but_never_shorten_it() {
        // The attack this closes: a stolen key publishes `soak_hours: 0` (or a
        // back-dated `released`) to reach every machine immediately.
        let mut m = manifest("0.6.8");
        m.soak_hours = Some(0);
        let mut i = input(&m, &[]);
        i.first_seen_unix = i.now_unix - 3600; // seen an hour ago
        assert!(
            matches!(decide(&i), Decision::Notify { hold: Hold::Soaking { .. }, .. }),
            "soak_hours=0 must not shorten the client floor"
        );

        // And the manifest CAN ask for longer.
        m.soak_hours = Some(72);
        let mut i = input(&m, &[]);
        i.first_seen_unix = i.now_unix - 25 * 3600;
        assert!(matches!(decide(&i), Decision::Notify { hold: Hold::Soaking { .. }, .. }));
        i.first_seen_unix = i.now_unix - 73 * 3600;
        assert!(matches!(decide(&i), Decision::Install { .. }));
    }

    /// `released` may only ever make the soak LONGER. A back-dated one — the
    /// field an attacker holding the key would reach for — changes nothing at
    /// all, because the anchor is the later of the two and our own sighting is
    /// already later.
    #[test]
    fn a_back_dated_released_field_cannot_shorten_the_soak() {
        let mut m = manifest("0.6.8");
        m.released = "1970-01-02T00:00:00Z".into();
        let mut i = input(&m, &[]);
        i.first_seen_unix = i.now_unix; // just seen
        match decide(&i) {
            Decision::Notify { hold: Hold::Soaking { ready_in_s }, .. } => {
                assert_eq!(ready_in_s, SOAK_FLOOR.as_secs(), "the full floor, unchanged");
            }
            other => panic!("expected the full soak hold, got {other:?}"),
        }
        // Unparseable is the same story: no floor, so no change either.
        m.released = "whenever, really".into();
        let mut i = input(&m, &[]);
        i.first_seen_unix = i.now_unix - SOAK_FLOOR.as_secs();
        assert!(
            matches!(decide(&i), Decision::Install { .. }),
            "an unreadable `released` must fall back to the pre-existing behaviour"
        );
    }

    /// The dead-RTC defect. A rig whose clock battery is gone boots at a fixed
    /// old date, records its one sighting THERE, and then NTP corrects the
    /// clock. `now - first_seen` is suddenly years, so the 24-hour soak — the
    /// only guardrail that costs an attacker holding the release key real time —
    /// is satisfied instantly by a version that has existed for minutes.
    ///
    /// The two clamps that stop it are tested here as they compose in practice:
    /// the anchor cannot predate the publisher's own `released` (a floor a
    /// manifest can only raise), and it cannot predate what this machine has
    /// already written in its own ledger.
    #[test]
    fn a_backdated_sighting_does_not_satisfy_the_soak() {
        let mut m = manifest("0.6.8");
        // Published one hour before "now"; the machine cannot have seen it for
        // longer than that no matter what its clock says.
        m.released = "2001-09-09T00:46:40Z".into(); // now_unix - 3600
        let mut i = input(&m, &[]);
        // The broken clock's story: "I have been looking at this for 6 years."
        i.first_seen_unix = i.now_unix - 6 * 365 * 24 * 3600;

        assert_eq!(
            soak_anchor(i.first_seen_unix, m.released_unix()),
            i.now_unix - 3600,
            "the anchor must come forward to the publication time"
        );
        match decide(&i) {
            Decision::Notify { hold: Hold::Soaking { ready_in_s }, .. } => {
                assert_eq!(
                    ready_in_s,
                    SOAK_FLOOR.as_secs() - 3600,
                    "a version published an hour ago has 23 hours of soak left"
                );
            }
            other => panic!("a backdated sighting must not clear the soak, got {other:?}"),
        }

        // And the withdrawal notice cannot tell the user the opposite story
        // while the hold is counting down.
        m.revoked = vec!["0.6.7".into()];
        let i = Input { manifest: &m, ..input(&m, &[]) };
        let mut i = Input { first_seen_unix: i.now_unix - 6 * 365 * 24 * 3600, ..i };
        i.current = "0.6.7";
        match decide(&i) {
            Decision::CurrentRevoked { newer: Some(n), .. } => {
                assert_eq!(n.visible_for_s, 3600, "not 2190 days");
                assert!(n.inside_soak());
            }
            other => panic!("expected a successor, got {other:?}"),
        }
    }

    /// The second clamp on its own, with no help from the manifest: the ledger
    /// is this machine's own record, and a clock that reads EARLIER than
    /// something already written in it has gone backwards. A sighting recorded
    /// on such a clock is floored at the newest timestamp the ledger holds, so
    /// the anchor can only move forward — never into credit for time that has
    /// not passed.
    #[test]
    fn a_sighting_is_never_recorded_before_what_the_ledger_already_knows() {
        let d = tmp("clockback");
        let now = now_unix();
        // Something this machine wrote "in the future" relative to the broken
        // clock we are about to simulate — i.e. an ordinary record written
        // before the RTC lost its battery.
        let ahead = Seen {
            version: "0.6.7".into(),
            first_seen_unix: now + 3600,
            sha256: "cc".repeat(32),
        };
        std::fs::write(
            d.join("update-seen.json"),
            serde_json::to_vec(&vec![ahead]).unwrap(),
        )
        .unwrap();

        let s = note_seen(&d, "0.6.8", &"aa".repeat(32));
        assert!(s.on_record());
        assert!(
            s.seen.first_seen_unix >= now + 3600,
            "a sighting must not be recorded before the ledger's own high-water mark: {} < {}",
            s.seen.first_seen_unix,
            now + 3600
        );
    }

    // ── revocation ──────────────────────────────────────────────────────────

    #[test]
    fn revoked_target_is_never_installed() {
        let mut m = manifest("0.6.8");
        m.revoked = vec!["0.6.8".into()];
        assert!(matches!(
            decide(&input(&m, &[])),
            Decision::Notify { hold: Hold::Revoked, .. }
        ));
    }

    #[test]
    fn revoked_current_outranks_everything() {
        let mut m = manifest("0.6.8");
        m.revoked = vec!["0.6.7".into()];
        let d = decide(&input(&m, &[]));
        assert_eq!(
            d,
            Decision::CurrentRevoked {
                current: "0.6.7".into(),
                newer: Some(NewerRelease {
                    version: "0.6.8".into(),
                    visible_for_s: 10 * 24 * 3600,
                }),
                rollback_available: true,
            }
        );
        // Even when there is nothing newer to move to.
        let mut m2 = manifest("0.6.7");
        m2.revoked = vec!["0.6.7".into()];
        assert!(matches!(decide(&input(&m2, &[])), Decision::CurrentRevoked { .. }));
    }

    /// F2b — the ORDINARY withdrawal: we shipped v0.6.9, it is bad, we withdrew
    /// it. The withdrawn build IS the newest published version, so there is
    /// nowhere forward to go and the notice must not pretend otherwise. The old
    /// shape carried `latest = m.version`, which read as "v0.6.9 has been
    /// withdrawn, please install v0.6.9" on what is by far the most common
    /// withdrawal there is.
    #[test]
    fn withdrawing_the_newest_version_offers_nowhere_to_go() {
        let mut m = manifest("0.6.9");
        m.revoked = vec!["0.6.9".into()];
        let mut i = input(&m, &[]);
        i.current = "0.6.9";
        match decide(&i) {
            Decision::CurrentRevoked { current, newer, .. } => {
                assert_eq!(current, "0.6.9");
                assert_eq!(newer, None, "the withdrawn build must never be its own remedy");
            }
            other => panic!("expected CurrentRevoked, got {other:?}"),
        }
    }

    /// A newer version that is ITSELF withdrawn is not somewhere to go either —
    /// "revoke everything" must not resolve to "so install this other revoked
    /// thing".
    #[test]
    fn a_revoked_successor_is_not_offered_as_a_destination() {
        let mut m = manifest("0.6.8");
        m.revoked = vec!["0.6.7".into(), "0.6.8".into()];
        match decide(&input(&m, &[])) {
            Decision::CurrentRevoked { newer, .. } => assert_eq!(newer, None),
            other => panic!("expected CurrentRevoked, got {other:?}"),
        }
    }

    /// F2 — the withdrawal notice carries the successor's LOCAL visibility, so a
    /// caller can say "this has been public for two hours" instead of "install it
    /// now". Without this the notice is a social-engineering channel: a stolen
    /// key revokes every good version and every machine in the fleet reads an
    /// urgent, correctly-signed instruction to take the attacker's build inside
    /// the soak window.
    #[test]
    fn a_withdrawal_reports_how_long_the_successor_has_been_visible() {
        let mut m = manifest("9.9.9");
        m.revoked = vec!["0.6.7".into()];
        let mut i = input(&m, &[]);
        i.first_seen_unix = i.now_unix - 2 * 3600; // seen two hours ago
        match decide(&i) {
            Decision::CurrentRevoked { newer: Some(n), .. } => {
                assert_eq!(n.version, "9.9.9");
                assert_eq!(n.visible_for_s, 2 * 3600);
                assert_eq!(n.visible_hours(), 2);
                assert!(n.inside_soak(), "two hours is inside the 24h floor");
            }
            other => panic!("expected a successor, got {other:?}"),
        }
        // …and past the floor it reads the other way.
        i.first_seen_unix = i.now_unix - SOAK_FLOOR.as_secs();
        match decide(&i) {
            Decision::CurrentRevoked { newer: Some(n), .. } => assert!(!n.inside_soak()),
            other => panic!("expected a successor, got {other:?}"),
        }
    }

    // ── an install this machine has already performed ───────────────────────

    /// **The loop.** `decide` gated on `is_newer(manifest, current)` and nothing
    /// else, and `current` is what the running BINARY answers — which is not the
    /// version on disk between an install and the next restart, and is not the
    /// published version at all if the two were ever cut apart.
    ///
    /// A rig mines for days between restarts and re-checks every six hours, so
    /// the same version was installed again, and again. Each install moves the
    /// current app into `.lkg`: the second one therefore overwrites the genuine
    /// rollback copy with the build being tested, and the probation's "rolled back
    /// to v0.6.7, restart to run it" becomes a sentence about a file that is
    /// v0.6.8. The version bump makes today's instance of this go away. It does
    /// not make the class go away, because nothing recorded that an install had
    /// happened at all.
    #[test]
    fn a_version_this_machine_has_already_installed_is_not_installed_again() {
        let m = manifest("0.6.8");

        // The control: no install on record, everything else identical.
        assert!(matches!(decide(&input(&m, &[])), Decision::Install { .. }));

        // We installed it four hours ago; this process is still the old build,
        // because an install does not replace a running process.
        let rec = Installed {
            version: "0.6.8".into(),
            sha256: "aa".repeat(32),
            at_unix: 1_000_000_000 - 4 * 3600,
        };
        let mut i = input(&m, &[]);
        i.installed = Some(&rec);
        assert_eq!(
            decide(&i),
            Decision::Notify {
                version: "0.6.8".into(),
                hold: Hold::AlreadyInstalled { installed_ago_s: 4 * 3600 },
            },
            "the swap is already on disk — installing it again overwrites the rollback copy"
        );

        // A record of a DIFFERENT version says nothing about this one: a machine
        // that took 0.6.8 last month must still be offered 0.6.9.
        let old = Installed {
            version: "0.6.7".into(),
            sha256: "cc".repeat(32),
            at_unix: 1,
        };
        let mut i = input(&m, &[]);
        i.installed = Some(&old);
        assert!(
            matches!(decide(&i), Decision::Install { .. }),
            "a stale record must not block the next real update"
        );

        // …and the spelling of the record cannot get in the way either.
        let v_spelled = Installed {
            version: "0.6.8".into(),
            sha256: "aa".repeat(32),
            at_unix: 1_000_000_000,
        };
        let vm = manifest("v0.6.8");
        let mut i = input(&vm, &[]);
        i.installed = Some(&v_spelled);
        assert!(matches!(
            decide(&i),
            Decision::Notify { hold: Hold::AlreadyInstalled { .. }, .. }
        ));
    }

    /// The loop as it actually runs, on the machine described in Defect 1: the
    /// published version is `0.6.8` and the binary answers `0.6.7`, so no restart
    /// ever reconciles them. Before the record, this installed on every check
    /// until the rig was rebuilt. After it, it installs exactly once and then
    /// says so — with the age that lets the caller tell "restart pending" from
    /// "this build is not the version it claims to be".
    #[test]
    fn a_build_that_never_reports_the_version_it_was_published_as_installs_once() {
        let m = manifest("0.6.8");
        let mut i = input(&m, &[]); // current: "0.6.7", for ever
        assert!(matches!(decide(&i), Decision::Install { .. }), "check 1: installs");

        // …which the driver records. Every later check, at any distance:
        let rec = Installed {
            version: "0.6.8".into(),
            sha256: "aa".repeat(32),
            at_unix: 1_000_000_000,
        };
        i.installed = Some(&rec);
        for (n, ahead) in [6 * 3600u64, 24 * 3600, 30 * 24 * 3600].iter().enumerate() {
            i.now_unix = 1_000_000_000 + ahead;
            match decide(&i) {
                Decision::Notify { hold: Hold::AlreadyInstalled { installed_ago_s }, .. } => {
                    assert_eq!(installed_ago_s, *ahead, "check {}", n + 2);
                }
                other => panic!("check {}: expected a hold, got {other:?}", n + 2),
            }
        }
    }

    /// The record must not outrank the findings that are about the ARTIFACT. A
    /// version that has been re-published with different bytes, or withdrawn, is
    /// not "already installed, nothing to see here" — those are the loud ones and
    /// they stay loud.
    #[test]
    fn an_install_on_record_does_not_mask_a_hash_conflict_or_a_withdrawal() {
        let rec = Installed {
            version: "0.6.8".into(),
            sha256: "aa".repeat(32),
            at_unix: 1_000_000_000,
        };
        let other = "bb".repeat(32);

        let m = manifest("0.6.8");
        let mut i = input(&m, &[]);
        i.installed = Some(&rec);
        i.seen_sha256 = Some(&other);
        assert!(
            matches!(decide(&i), Decision::Notify { hold: Hold::HashConflict { .. }, .. }),
            "a re-published version outranks 'we already installed it'"
        );

        let mut m = manifest("0.6.8");
        m.revoked = vec!["0.6.8".into()];
        let mut i = input(&m, &[]);
        i.installed = Some(&rec);
        assert!(matches!(decide(&i), Decision::Notify { hold: Hold::Revoked, .. }));
    }

    /// The manual path must not be the front door around the new hold. Applying
    /// an update that is already on disk moves the CURRENT app into `.lkg` — so
    /// the copy the machine would roll back to becomes the build on trial — and
    /// `--yes` must not be able to do that silently.
    #[test]
    fn the_manual_path_asks_before_applying_an_update_that_is_already_installed() {
        let m = manifest("0.6.8");
        assert_eq!(decide_manual(&manual(&m, &[])), ManualVerdict::Proceed);

        let rec = Installed {
            version: "v0.6.8".into(),
            sha256: "aa".repeat(32),
            at_unix: 1,
        };
        let mut i = manual(&m, &[]);
        i.installed = Some(&rec);
        assert_eq!(
            decide_manual(&i),
            ManualVerdict::ConfirmFirst(ManualConcern::AlreadyInstalled),
            "a second question, not a refusal: re-applying is the user's call to make"
        );

        // A record about another version is not about this one.
        let other = Installed {
            version: "0.6.7".into(),
            sha256: "cc".repeat(32),
            at_unix: 1,
        };
        let mut i = manual(&m, &[]);
        i.installed = Some(&other);
        assert_eq!(decide_manual(&i), ManualVerdict::Proceed);

        // …and the findings that rest on evidence the publisher cannot restate
        // still outrank it.
        let seen = "bb".repeat(32);
        let mut i = manual(&m, &[]);
        i.installed = Some(&rec);
        i.seen_sha256 = Some(&seen);
        assert!(matches!(
            decide_manual(&i),
            ManualVerdict::Refuse(ManualRefusal::HashConflict { .. })
        ));
    }

    #[test]
    fn the_install_record_round_trips_and_is_canonical() {
        let d = tmp("installed");
        assert_eq!(installed(&d), None, "a machine that has never auto-installed");
        assert!(note_installed(&d, "v0.6.8", &"AA".repeat(32)));
        let rec = installed(&d).expect("the record is on disk");
        assert_eq!(rec.version, "0.6.8", "stored in the canonical spelling");
        assert_eq!(rec.sha256, "aa".repeat(32));
        // An unreadable record reads as "no memory", i.e. as the behaviour that
        // existed before the record did — never as a permanent hold.
        std::fs::write(installed_path(&d), b"not json").unwrap();
        assert_eq!(installed(&d), None);
    }

    // ── the manual path ─────────────────────────────────────────────────────

    fn manual<'a>(m: &'a Manifest, pins: &'a [String]) -> ManualInput<'a> {
        ManualInput {
            manifest: m,
            current: "0.6.7",
            artifact_sha256: Some(&m.artifacts[0].sha256),
            seen_sha256: None,
            ledger: LedgerStatus::Intact,
            pinned: pins,
            installed: None,
        }
    }

    /// F1 — the core of it. The automatic path refuses a version whose bytes
    /// changed under a fixed version number; the manual path used to install it.
    #[test]
    fn manual_refuses_the_same_version_with_different_bytes() {
        let m = manifest("0.6.8");
        let seen = "bb".repeat(32);
        let mut i = manual(&m, &[]);
        i.seen_sha256 = Some(&seen);
        match decide_manual(&i) {
            ManualVerdict::Refuse(ManualRefusal::HashConflict { seen_sha256, now_sha256 }) => {
                assert_eq!(seen_sha256, seen);
                assert_eq!(now_sha256, "aa".repeat(32));
            }
            other => panic!("expected a hash-conflict refusal, got {other:?}"),
        }
        // Matching bytes are fine, case-insensitively — the ledger lower-cases
        // what it stores and a manifest may not.
        let up = "AA".repeat(32);
        i.seen_sha256 = Some(&up);
        assert_eq!(decide_manual(&i), ManualVerdict::Proceed);
    }

    /// The hash conflict outranks the other findings: it is the only one whose
    /// evidence a stolen key cannot restate.
    #[test]
    fn a_hash_conflict_outranks_a_revocation_and_a_pin() {
        let mut m = manifest("0.6.8");
        m.revoked = vec!["0.6.8".into()];
        let seen = "bb".repeat(32);
        let pins = vec!["0.6.8".to_string()];
        let mut i = manual(&m, &pins);
        i.seen_sha256 = Some(&seen);
        assert!(matches!(
            decide_manual(&i),
            ManualVerdict::Refuse(ManualRefusal::HashConflict { .. })
        ));
    }

    #[test]
    fn manual_refuses_a_withdrawn_version_and_double_checks_a_pinned_one() {
        let mut m = manifest("0.6.8");
        m.revoked = vec!["0.6.8".into()];
        assert_eq!(
            decide_manual(&manual(&m, &[])),
            ManualVerdict::Refuse(ManualRefusal::Revoked)
        );

        let clean = manifest("0.6.8");
        let pins = vec!["0.6.8".to_string()];
        assert_eq!(
            decide_manual(&manual(&clean, &pins)),
            ManualVerdict::ConfirmFirst(ManualConcern::Pinned)
        );
        assert_eq!(decide_manual(&manual(&clean, &[])), ManualVerdict::Proceed);
    }

    /// The manual gate is NARROWER than the automatic one on purpose: soak,
    /// rollout and mode are statements about how eager the machine may be, and a
    /// human typing the command has answered all three. A manual path that also
    /// enforced the soak would not be a manual path.
    #[test]
    fn manual_does_not_inherit_the_soak_the_rollout_or_the_mode() {
        let mut m = manifest("0.6.8");
        m.soak_hours = Some(72);
        m.rollout_pct = Some(0);
        // The automatic path holds this hard…
        let mut i = input(&m, &[]);
        i.first_seen_unix = i.now_unix;
        assert!(matches!(decide(&i), Decision::Notify { hold: Hold::Soaking { .. }, .. }));
        // …and the manual path lets a human have it, while reporting that they
        // are the one taking the first look.
        assert_eq!(decide_manual(&manual(&m, &[])), ManualVerdict::Proceed);
        assert!(inside_soak(visible_for(1_000, 1_000)));
        assert!(!inside_soak(SOAK_FLOOR.as_secs()));
        // A clock that went backwards reads as "just seen", never as "ancient".
        assert_eq!(visible_for(10, 1_000), 0);
    }

    /// A build that is not NEWER than the one running is refused on the manual
    /// path, and the refusal is not negotiable by `--yes`.
    ///
    /// The reachable version of this is not hypothetical. `crate::evaluate`
    /// tests `min_supported` BEFORE `is_newer`, so a manifest pairing an
    /// unreachable `min_supported` with an OLD `version` lands in
    /// `CheckOutcome::Unsupported` — the state a client reads as "you must
    /// upgrade" — while what it is actually offering is a downgrade. The second
    /// half of this test pins that ordering, because it is the thing that makes
    /// the first half reachable rather than academic.
    #[test]
    fn manual_refuses_a_build_that_is_not_newer_than_the_running_one() {
        let older = manifest("0.6.4");
        let mut i = manual(&older, &[]);
        i.current = "0.6.8";
        assert_eq!(
            decide_manual(&i),
            ManualVerdict::Refuse(ManualRefusal::NotNewer {
                offered: "0.6.4".into(),
                current: "0.6.8".into(),
            }),
            "a downgrade is not an update"
        );

        // The same build number is not an update either.
        let same = manifest("0.6.8");
        let mut i = manual(&same, &[]);
        i.current = "0.6.8";
        assert!(matches!(
            decide_manual(&i),
            ManualVerdict::Refuse(ManualRefusal::NotNewer { .. })
        ));

        // …and a genuinely newer one still proceeds, so the refusal is about the
        // ordering and not about the gate having become a wall.
        let newer = manifest("0.6.9");
        let mut i = manual(&newer, &[]);
        i.current = "0.6.8";
        assert_eq!(decide_manual(&i), ManualVerdict::Proceed);

        // The route that gets a downgrade in front of this gate in the first
        // place: `min_supported` is tested first, so an OLD `version` with an
        // unreachable `min_supported` is reported as a required upgrade.
        let mut trap = manifest("0.6.4");
        trap.min_supported = "99.0.0".into();
        match crate::evaluate(trap, "0.6.8") {
            crate::CheckOutcome::Unsupported { manifest, .. } => {
                assert_eq!(manifest.version, "0.6.4");
                assert!(
                    !crate::is_newer(&manifest.version, "0.6.8"),
                    "the 'required upgrade' is a downgrade — this is the trap"
                );
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    /// The ledger is what makes "same version, different bytes" detectable, and
    /// a state directory that cannot be written disarms it permanently: the
    /// record handed back is the one we just built from the manifest, so it
    /// agrees with the manifest by construction, every run, forever.
    ///
    /// The automatic path must therefore hold rather than install — and say so
    /// as itself, not as a soak that is quietly never going to end.
    #[test]
    fn an_unwritable_ledger_holds_the_automatic_path_and_asks_on_the_manual_one() {
        let m = manifest("0.6.8");

        // Control: everything else identical, ledger fine → it installs.
        assert!(matches!(decide(&input(&m, &[])), Decision::Install { .. }));

        let mut i = input(&m, &[]);
        i.ledger = LedgerStatus::Unwritable;
        assert_eq!(
            decide(&i),
            Decision::Notify { version: "0.6.8".into(), hold: Hold::LedgerUnwritable },
            "an unattended install must not rest on a check that cannot run"
        );

        // The manual path is a person, not a machine: it asks rather than
        // refusing, but it must not pass silently under `--yes`.
        let mut mi = manual(&m, &[]);
        assert_eq!(decide_manual(&mi), ManualVerdict::Proceed);
        mi.ledger = LedgerStatus::Unwritable;
        assert_eq!(
            decide_manual(&mi),
            ManualVerdict::ConfirmFirst(ManualConcern::UnrecordedSighting)
        );
    }

    /// The SAME two consumers, for the other way a ledger fails: the records were
    /// there, we could not read them, and they are now gone. Both directions hold
    /// — and each says what actually happened, because "fix your disk permissions"
    /// is a guess when the disk is fine, and a client that guesses a cause is
    /// worse than one that says what it knows.
    #[test]
    fn a_reset_ledger_holds_the_automatic_path_and_asks_on_the_manual_one() {
        let m = manifest("0.6.8");

        let mut i = input(&m, &[]);
        i.ledger = LedgerStatus::Reset;
        assert_eq!(
            decide(&i),
            Decision::Notify { version: "0.6.8".into(), hold: Hold::LedgerReset },
            "an unattended install must not rest on a comparison we have just lost"
        );

        let mut mi = manual(&m, &[]);
        mi.ledger = LedgerStatus::Reset;
        assert_eq!(
            decide_manual(&mi),
            ManualVerdict::ConfirmFirst(ManualConcern::LedgerReset)
        );

        // …and the two failures are not interchangeable: each renders as itself.
        assert_ne!(Hold::LedgerReset, Hold::LedgerUnwritable);
        assert_ne!(
            ManualConcern::LedgerReset,
            ManualConcern::UnrecordedSighting
        );
    }

    /// A ledger that cannot be PARSED is a ledger whose records are gone, and the
    /// record it holds that matters most is the one with no override on any path:
    /// the bytes a version first arrived carrying. Overwriting it and carrying on
    /// is the deliberate trade (refusing would let one bad byte permanently
    /// disable auto-update on a rig nobody visits) — but doing it silently, and
    /// then reporting the write as if the sighting were on record, told every
    /// consumer the republish check was running at the exact moment it was erased.
    #[test]
    fn a_ledger_that_cannot_be_parsed_is_never_reported_as_recorded() {
        let d = tmp("corrupt");
        // What this machine actually knew: 0.6.9 arrived carrying bb…
        assert!(note_seen(&d, "0.6.9", &"bb".repeat(32)).on_record());
        // …and then the file stopped being readable.
        std::fs::write(seen_path(&d), b"{ not json at all").unwrap();

        let s = note_seen(&d, "0.6.9", &"aa".repeat(32));
        assert!(
            !s.on_record(),
            "a sighting written over a ledger we could not read must not be reported as recorded"
        );
        assert_eq!(
            s.ledger,
            LedgerStatus::Reset,
            "and it says WHICH failure this was: nothing here is a permissions problem"
        );
        assert_eq!(
            s.seen.sha256,
            "aa".repeat(32),
            "the trap: the record handed back is the one we just built from the server's own answer"
        );

        // The evidence is kept rather than destroyed, and the moment this machine
        // forgot what it saw is in its own history file.
        assert_eq!(
            std::fs::read(seen_quarantine_path(&d)).unwrap(),
            b"{ not json at all",
            "the unreadable ledger must be moved aside, not overwritten in place"
        );
        let hist = std::fs::read_to_string(d.join("update-history.jsonl")).unwrap_or_default();
        assert!(hist.contains("ledger-reset"), "history: {hist}");

        // The self-heal is real and is NOT the bug: the very next check finds a
        // readable ledger and reports the truth in the other direction. One bad
        // byte must not disable auto-update on a rig nobody visits.
        let after = note_seen(&d, "0.6.10", &"cc".repeat(32));
        assert_eq!(after.ledger, LedgerStatus::Intact);
        assert_eq!(read_seen(&d).entries.len(), 2);

        // Stated plainly because it is the residual we are accepting: the bytes
        // 0.6.9 first arrived with are gone, and the re-recorded ones are
        // whatever the server said this time. The soak clock restarts with them.
        assert_eq!(
            read_seen(&d)
                .entries
                .iter()
                .find(|e| e.version == "0.6.9")
                .map(|e| e.sha256.clone()),
            Some("aa".repeat(32)),
            "the reset really did lose the original bytes — the hold and the fresh \
             soak are what stand in for the comparison we can no longer make"
        );
    }

    /// A ledger that is simply ABSENT is not a ledger that was lost. The ordinary
    /// first run on a fresh machine must report `Intact`, or every new install
    /// would spend its first check holding on a failure that did not happen.
    #[test]
    fn a_first_run_with_no_ledger_at_all_is_intact_not_reset() {
        let d = tmp("noledger");
        assert!(!seen_path(&d).exists());
        assert_eq!(
            note_seen(&d, "0.6.8", &"aa".repeat(32)).ledger,
            LedgerStatus::Intact
        );
        assert!(!seen_quarantine_path(&d).exists(), "nothing was quarantined");
    }

    /// …and the write failure is actually detected, rather than being a flag no
    /// caller can ever set. A state "directory" that is a regular file fails
    /// `create_dir_all` on every platform, which is the failure this models.
    #[test]
    fn note_seen_reports_a_ledger_it_could_not_write() {
        let d = tmp("nowrite");
        let not_a_dir = d.join("state");
        std::fs::write(&not_a_dir, b"this is a file, not a directory").unwrap();

        let s = note_seen(&not_a_dir, "0.6.8", &"aa".repeat(32));
        assert!(
            !s.on_record(),
            "a sighting that never reached disk must not be reported as recorded"
        );
        // And the trap it used to lay: the record handed back agrees with the
        // manifest it came from, so a caller that trusted it would compare the
        // server's hash against the server's hash.
        assert_eq!(s.seen.sha256, "aa".repeat(32));

        // A writable directory reports the truth in the other direction.
        assert!(note_seen(&d, "0.6.8", &"aa".repeat(32)).on_record());
    }

    /// With no artifact for this platform there are no bytes to compare, and the
    /// gate must not invent a conflict out of the absence.
    #[test]
    fn manual_without_a_platform_artifact_finds_no_conflict() {
        let m = manifest("0.6.8");
        let seen = "bb".repeat(32);
        let i = ManualInput {
            manifest: &m,
            current: "0.6.7",
            artifact_sha256: None,
            seen_sha256: Some(&seen),
            ledger: LedgerStatus::Intact,
            pinned: &[],
            installed: None,
        };
        assert_eq!(decide_manual(&i), ManualVerdict::Proceed);
    }

    #[test]
    fn revocation_does_not_waive_the_soak() {
        // Otherwise "revoke everything" becomes an instant-deploy button for a
        // stolen key.
        let mut m = manifest("0.6.8");
        m.revoked = vec!["0.6.6".into()]; // not us
        let mut i = input(&m, &[]);
        i.first_seen_unix = i.now_unix;
        assert!(matches!(decide(&i), Decision::Notify { hold: Hold::Soaking { .. }, .. }));
    }

    // ── re-published bytes / pins ───────────────────────────────────────────

    #[test]
    fn same_version_with_different_bytes_is_refused() {
        let m = manifest("0.6.8");
        let mut i = input(&m, &[]);
        let other = "bb".repeat(32);
        i.seen_sha256 = Some(&other);
        match decide(&i) {
            Decision::Notify { hold: Hold::HashConflict { seen_sha256, now_sha256 }, .. } => {
                assert_eq!(seen_sha256, other);
                assert_eq!(now_sha256, "aa".repeat(32));
            }
            other => panic!("expected hash conflict, got {other:?}"),
        }
        // The matching hash is fine (and case-insensitive).
        let up = "AA".repeat(32);
        i.seen_sha256 = Some(&up);
        assert!(matches!(decide(&i), Decision::Install { .. }));
    }

    #[test]
    fn a_version_that_failed_here_is_never_auto_installed_again() {
        let m = manifest("0.6.8");
        let pins = vec!["0.6.8".to_string()];
        assert!(matches!(
            decide(&input(&m, &pins)),
            Decision::Notify { hold: Hold::Pinned, .. }
        ));
    }

    #[test]
    fn no_artifact_for_this_platform_is_a_notify_not_an_install() {
        let mut m = manifest("0.6.8");
        m.artifacts[0].platform = "totally-other-os".into();
        assert!(matches!(
            decide(&input(&m, &[])),
            Decision::Notify { hold: Hold::NoArtifact, .. }
        ));
    }

    #[test]
    fn older_or_equal_manifest_is_up_to_date() {
        assert_eq!(decide(&input(&manifest("0.6.7"), &[])), Decision::UpToDate);
        assert_eq!(decide(&input(&manifest("0.6.6"), &[])), Decision::UpToDate);
    }

    // ── local state ─────────────────────────────────────────────────────────

    #[test]
    fn rollout_id_is_persisted_and_stable() {
        let d = tmp("rid");
        let a = rollout_id(&d);
        let b = rollout_id(&d);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        // A different machine (different dir) gets a different label.
        assert_ne!(a, rollout_id(&tmp("rid2")));
    }

    #[test]
    fn seen_ledger_keeps_the_first_sighting() {
        let d = tmp("seen");
        let first = note_seen(&d, "0.6.8", "AA");
        std::thread::sleep(Duration::from_millis(5));
        let again = note_seen(&d, "0.6.8", "BB");
        assert_eq!(first.seen.first_seen_unix, again.seen.first_seen_unix);
        assert_eq!(again.seen.sha256, "aa", "first bytes win; the ledger is append-only");
        assert!(
            first.on_record() && again.on_record(),
            "a writable dir records both"
        );
    }

    #[test]
    fn pins_persist_and_dedupe() {
        let d = tmp("pins");
        assert!(pins(&d).is_empty());
        pin(&d, "0.6.8");
        pin(&d, "0.6.8");
        pin(&d, "0.6.9");
        assert_eq!(pins(&d), vec!["0.6.8".to_string(), "0.6.9".to_string()]);
    }

    /// F12: the cap evicts the LOWEST version, not the oldest entry. The updater
    /// only installs something newer than what is running, so the lowest pinned
    /// version is the one least able to be offered again — while eviction by
    /// insertion order would throw away a high version that very much can be.
    #[test]
    fn the_pin_cap_evicts_the_lowest_version_not_the_oldest_entry() {
        let d = tmp("pincap");
        // A high version pinned FIRST (so it is the oldest entry), then the cap
        // filled with lower ones.
        pin(&d, "9.9.9");
        for i in 0..MAX_PINS {
            pin(&d, &format!("1.0.{i}"));
        }
        let all = pins(&d);
        assert_eq!(all.len(), MAX_PINS);
        assert!(
            all.contains(&"9.9.9".to_string()),
            "the highest version must survive even though it was pinned first"
        );
        assert!(
            !all.contains(&"1.0.0".to_string()),
            "the lowest version is the one dropped"
        );
        // An unparseable version reads as (0,0,0) — the updater can never call it
        // newer than anything, so it is also the first thing to lose.
        let d2 = tmp("pincap2");
        pin(&d2, "not-a-version");
        for i in 0..MAX_PINS {
            pin(&d2, &format!("1.0.{i}"));
        }
        assert!(!pins(&d2).contains(&"not-a-version".to_string()));
    }

    /// F11: `alice-miner --version` proves the binary LOADS. It must be recorded
    /// as such — otherwise a second `--version` looks like crash-on-launch — and it
    /// must NOT commit the update or drop the rollback copy, which is what the CLI
    /// used to do the instant clap finished parsing.
    #[test]
    fn a_version_print_proves_launch_but_never_commits_the_update() {
        let d = tmp("launchok");
        let app = fake_app(&d, "NEW", "OLD");
        let mut lkg = app.as_os_str().to_os_string();
        lkg.push(".lkg");
        let lkg = PathBuf::from(lkg);
        // No earning baseline: this is exactly the case where `confirm_start`
        // commits on the start proof alone.
        arm(&app, "0.6.8", "0.6.7", EarningBaseline::NotEarning).unwrap();
        assert!(matches!(
            register_launch(&d, &app, "0.6.8"),
            LaunchVerdict::OnTrial { mining_gate: false, .. }
        ));

        // `--version`: loaded, nothing more.
        assert!(note_launch_ok(&app, "0.6.8"));
        assert!(
            probation(&app).is_some(),
            "a --version run must NOT end the probation"
        );
        assert!(lkg.exists(), "a --version run must NOT drop the rollback copy");
        assert!(probation(&app).unwrap().started_ok);

        // …and a SECOND --version must not be mistaken for crash-on-launch, which
        // is the trap that makes "just don't call confirm_start" the wrong fix.
        assert!(matches!(
            register_launch(&d, &app, "0.6.8"),
            LaunchVerdict::OnTrial { .. }
        ));
        assert!(lkg.exists());
        assert!(pins(&d).is_empty(), "nothing was rolled back or pinned");

        // A real command: now it commits, exactly as before.
        assert!(confirm_start(&d, &app, "0.6.8"));
        assert!(probation(&app).is_none());
        assert!(!lkg.exists(), "the commit drops the last-known-good copy");
    }

    /// The arming path's own version of the F4 bug.
    ///
    /// `previous_productive` is derived at install time from one stamp, and the
    /// acceptance guard freezes that stamp on purpose when it halts a lane —
    /// which is what a multi-day upstream collapse looks like. August 2026 ran
    /// 78 hours, past the 72-hour `PRODUCTIVE_WINDOW`. So a build that installs
    /// itself mid-outage sees a stale stamp, arms as "there was no baseline
    /// anyway", and the very next command the user types — `status`, `stop`,
    /// anything that reaches `confirm_start` — ends the probation and deletes
    /// last-known-good. The build becomes permanent without having mined once.
    ///
    /// `EarningBaseline::Unknown` is the third answer that stops it.
    #[test]
    fn a_build_installed_during_a_halt_does_not_commit_on_the_first_start() {
        let d = tmp("halted-arm");
        let app = fake_app(&d, "NEW", "OLD");
        let mut lkg = app.as_os_str().to_os_string();
        lkg.push(".lkg");
        let lkg = PathBuf::from(lkg);

        arm(&app, "0.6.8", "0.6.7", EarningBaseline::Unknown).unwrap();
        assert_eq!(probation(&app).unwrap().baseline(), EarningBaseline::Unknown);
        assert!(matches!(
            register_launch(&d, &app, "0.6.8"),
            LaunchVerdict::OnTrial { mining_gate: false, .. }
        ));

        // The step that used to end it. Twice, because `confirm_start` is
        // reached by every command and being idempotent is not the point.
        assert!(!confirm_start(&d, &app, "0.6.8"));
        assert!(!confirm_start(&d, &app, "0.6.8"));
        assert!(
            probation(&app).is_some(),
            "a build that has never mined must stay on trial"
        );
        assert!(
            lkg.exists(),
            "last-known-good must survive: this build has shown nothing yet"
        );

        // Nor does a long, empty session convict it — we have no baseline to
        // convict it against, and blaming it for an outage is the mistake at the
        // other end of the same stick.
        let long = SessionResult::judgeable(MIN_JUDGED_SESSION.as_secs(), 0);
        assert_eq!(
            note_session(&d, &app, "0.6.8", long),
            SessionVerdict::NoChange
        );
        assert!(lkg.exists() && pins(&d).is_empty(), "nothing rolled back, nothing pinned");

        // One real accepted share is proof it works, and ends the trial.
        assert_eq!(
            note_session(&d, &app, "0.6.8", SessionResult::judgeable(60, 1)),
            SessionVerdict::Committed { version: "0.6.8".into() }
        );
        assert!(!lkg.exists() && probation(&app).is_none());
    }

    /// The control for the test above: with a genuinely absent baseline —
    /// nothing was earning and nothing was stopping it — `confirm_start` still
    /// commits on the start proof alone. The fix must not turn every idle rig
    /// into one that keeps a spare copy of the app forever.
    #[test]
    fn a_build_installed_on_an_idle_rig_still_commits_on_start() {
        let d = tmp("idle-arm");
        let app = fake_app(&d, "NEW", "OLD");
        let mut lkg = app.as_os_str().to_os_string();
        lkg.push(".lkg");
        let lkg = PathBuf::from(lkg);
        arm(&app, "0.6.8", "0.6.7", EarningBaseline::NotEarning).unwrap();
        assert!(confirm_start(&d, &app, "0.6.8"));
        assert!(probation(&app).is_none() && !lkg.exists());
    }

    /// The pure decision table for the third baseline: a frozen counter is still
    /// not evidence (the F4 ordering holds), a real share commits, and nothing
    /// else moves.
    #[test]
    fn an_unknown_baseline_never_strikes_and_never_rolls_back() {
        let p = Probation {
            version: "0.6.8".into(),
            previous: "0.6.7".into(),
            armed_at_unix: 0,
            launches: 1,
            started_ok: true,
            previous_productive: false,
            baseline_unknown: true,
            failed_sessions: FAILED_SESSIONS_TO_ROLLBACK - 1,
        };
        let long = MIN_JUDGED_SESSION.as_secs();

        // The same record with `Earning` would roll back right here…
        let earning = Probation { previous_productive: true, baseline_unknown: false, ..p.clone() };
        assert_eq!(
            judge_session(&earning, "0.6.8", &SessionResult::judgeable(long, 0)),
            SessionAction::RollBack,
            "the control: this is genuinely the tipping session"
        );
        // …and with `Unknown` it does nothing at all.
        assert_eq!(
            judge_session(&p, "0.6.8", &SessionResult::judgeable(long, 0)),
            SessionAction::Ignore
        );
        // A halted lane's frozen counter is not a commit either — the F4
        // ordering has to hold in this branch too, or the fix for one bug
        // becomes the other bug.
        assert_eq!(
            judge_session(
                &p,
                "0.6.8",
                &SessionResult { ran_secs: long, accepted: 99, evidence: SessionEvidence::MiningHalted }
            ),
            SessionAction::Abstain(SessionEvidence::MiningHalted)
        );
        // A genuine share commits.
        assert_eq!(
            judge_session(&p, "0.6.8", &SessionResult::judgeable(long, 1)),
            SessionAction::Commit
        );
    }

    /// A probation record written by an earlier build has no `baseline_unknown`
    /// field. It must still parse, and it must read as the answer that build
    /// believed it had — not as the new third state.
    #[test]
    fn an_older_probation_record_still_parses() {
        let legacy = br#"{"version":"0.6.8","previous":"0.6.7","armed_at_unix":1,
            "launches":1,"started_ok":true,"previous_productive":false,"failed_sessions":0}"#;
        let p: Probation = serde_json::from_slice(legacy).unwrap();
        assert_eq!(p.baseline(), EarningBaseline::NotEarning);
        assert!(!p.baseline_unknown);
    }

    /// `note_launch_ok` is inert when there is no probation, or when this process
    /// is not the build on trial.
    #[test]
    fn note_launch_ok_is_inert_off_the_probation_path() {
        let d = tmp("launchok2");
        let app = fake_app(&d, "NEW", "OLD");
        assert!(!note_launch_ok(&app, "0.6.8"), "no probation armed");
        arm(&app, "0.6.8", "0.6.7", EarningBaseline::NotEarning).unwrap();
        assert!(!note_launch_ok(&app, "0.6.7"), "not the build on trial");
        assert!(!probation(&app).unwrap().started_ok);
    }

    #[test]
    fn productivity_mark_round_trips() {
        let d = tmp("prod");
        assert!(!was_recently_productive(&d));
        mark_productive(&d);
        assert!(was_recently_productive(&d));
        assert!(last_productive_unix(&d).is_some());
    }

    // ── probation state machine ─────────────────────────────────────────────

    /// Build a fake "installed app" plus its last-known-good copy, so the real
    /// `crate::rollback` / `crate::commit_update` run against actual files.
    fn fake_app(dir: &Path, new: &str, old: &str) -> PathBuf {
        let app = dir.join(if cfg!(windows) { "alice-miner.exe" } else { "alice-miner" });
        std::fs::write(&app, new).unwrap();
        let mut lkg = app.as_os_str().to_os_string();
        lkg.push(".lkg");
        std::fs::write(PathBuf::from(lkg), old).unwrap();
        app
    }

    #[test]
    fn crash_on_launch_rolls_back_and_pins() {
        let d = tmp("crash");
        let app = fake_app(&d, "NEW", "OLD");
        arm(&app, "0.6.8", "0.6.7", EarningBaseline::Earning).unwrap();

        // First launch: on trial.
        assert!(matches!(
            register_launch(&d, &app, "0.6.8"),
            LaunchVerdict::OnTrial { .. }
        ));
        // It died before confirming. Second launch: rolled back.
        match register_launch(&d, &app, "0.6.8") {
            LaunchVerdict::RolledBack { failed_version, reason, restored } => {
                assert_eq!(failed_version, "0.6.8");
                assert_eq!(reason, RollbackReason::CrashOnLaunch);
                assert!(restored, "the previous build must actually be back on disk");
            }
            other => panic!("expected rollback, got {other:?}"),
        }
        assert_eq!(std::fs::read_to_string(&app).unwrap(), "OLD", "binary restored");
        assert_eq!(pins(&d), vec!["0.6.8".to_string()]);
        assert!(probation(&app).is_none());
    }

    #[test]
    fn a_build_that_starts_and_earns_commits_and_drops_lkg() {
        let d = tmp("earn");
        let app = fake_app(&d, "NEW", "OLD");
        arm(&app, "0.6.8", "0.6.7", EarningBaseline::Earning).unwrap();
        assert!(matches!(
            register_launch(&d, &app, "0.6.8"),
            LaunchVerdict::OnTrial { mining_gate: true, .. }
        ));
        // Starting is not enough while there IS an earning baseline to judge on.
        assert!(!confirm_start(&d, &app, "0.6.8"));
        assert!(probation(&app).is_some());

        let v = note_session(&d, &app, "0.6.8", SessionResult::judgeable(60, 1));
        assert_eq!(v, SessionVerdict::Committed { version: "0.6.8".into() });
        assert!(probation(&app).is_none());
        let mut lkg = app.as_os_str().to_os_string();
        lkg.push(".lkg");
        assert!(!PathBuf::from(lkg).exists(), "last-known-good dropped on commit");
        assert!(pins(&d).is_empty());
    }

    #[test]
    fn a_build_that_stops_earning_rolls_back_after_two_long_sessions() {
        let d = tmp("stop");
        let app = fake_app(&d, "NEW", "OLD");
        arm(&app, "0.6.8", "0.6.7", EarningBaseline::Earning).unwrap();
        register_launch(&d, &app, "0.6.8");
        confirm_start(&d, &app, "0.6.8");

        let long = SessionResult::judgeable(MIN_JUDGED_SESSION.as_secs(), 0);
        let short = SessionResult::judgeable(60, 0);

        // Short sessions never count against it.
        assert_eq!(note_session(&d, &app, "0.6.8", short), SessionVerdict::NoChange);
        assert_eq!(note_session(&d, &app, "0.6.8", short), SessionVerdict::NoChange);
        // One long empty session is a hiccup.
        assert_eq!(note_session(&d, &app, "0.6.8", long), SessionVerdict::NoChange);
        // Two is a pattern.
        assert_eq!(
            note_session(&d, &app, "0.6.8", long),
            SessionVerdict::RolledBack {
                failed_version: "0.6.8".into(),
                previous: "0.6.7".into(),
                restored: true,
            }
        );
        assert_eq!(std::fs::read_to_string(&app).unwrap(), "OLD");
        assert_eq!(pins(&d), vec!["0.6.8".to_string()]);
    }

    #[test]
    fn an_upstream_outage_does_not_roll_the_client_back() {
        // 2026-08-11 in one test: nobody is earning, including the build we
        // replaced. The client must not blame itself.
        let d = tmp("outage");
        let app = fake_app(&d, "NEW", "OLD");
        arm(&app, "0.6.8", "0.6.7", EarningBaseline::NotEarning).unwrap();
        assert!(matches!(
            register_launch(&d, &app, "0.6.8"),
            LaunchVerdict::OnTrial { mining_gate: false, .. }
        ));
        // With no earning baseline, starting is the whole bar: commit now.
        assert!(confirm_start(&d, &app, "0.6.8"));
        assert!(probation(&app).is_none());

        // And later zero-share sessions cannot resurrect a verdict.
        let long = SessionResult::judgeable(10 * 3600, 0);
        assert_eq!(note_session(&d, &app, "0.6.8", long), SessionVerdict::NoChange);
        assert_eq!(std::fs::read_to_string(&app).unwrap(), "NEW");
        assert!(pins(&d).is_empty());
    }

    // ── F4: layer 3 halting must not be read as "this build does not earn" ──

    /// **The August timeline, replayed against the probation.** A rig auto-updates
    /// on the 10th; the upstream fork lands on the 11th; the acceptance guard does
    /// its job and halts the lane; the client then keeps feeding the frozen
    /// zero-accepted counter into the probation.
    ///
    /// Without the evidence gate this is two long empty sessions and a rollback +
    /// permanent pin of a completely innocent version. With it, the halted lane is
    /// simply not evidence: nothing is written, nothing is pinned, and the binary
    /// on disk is untouched.
    #[test]
    fn a_halted_lane_never_produces_a_stopped_earning_rollback() {
        let d = tmp("halted");
        let app = fake_app(&d, "NEW", "OLD");
        arm(&app, "0.6.8", "0.6.7", EarningBaseline::Earning).unwrap();
        register_launch(&d, &app, "0.6.8");
        confirm_start(&d, &app, "0.6.8");

        let halted = SessionResult {
            ran_secs: 20 * 3600,
            accepted: 0,
            evidence: SessionEvidence::MiningHalted,
        };
        // Ten of them — a halted rig reports every tick, forever.
        for _ in 0..10 {
            assert_eq!(
                note_session(&d, &app, "0.6.8", halted),
                SessionVerdict::Abstained { reason: SessionEvidence::MiningHalted },
            );
        }
        assert_eq!(std::fs::read_to_string(&app).unwrap(), "NEW", "no rollback");
        assert!(pins(&d).is_empty(), "an innocent version must never be pinned");
        let p = probation(&app).expect("the probation must survive an abstention");
        assert_eq!(p.failed_sessions, 0, "an abstained session is not a strike");
    }

    /// The other half of "not evidence": an abstained session must not COMMIT the
    /// build either. Committing drops last-known-good, so treating a halt as an
    /// all-clear would quietly throw away the rollback copy on the strength of a
    /// session in which the miner was deliberately not mining.
    #[test]
    fn an_abstained_session_does_not_silently_commit_the_build() {
        let d = tmp("abstain-commit");
        let app = fake_app(&d, "NEW", "OLD");
        let mut lkg = app.as_os_str().to_os_string();
        lkg.push(".lkg");
        let lkg = PathBuf::from(lkg);
        arm(&app, "0.6.8", "0.6.7", EarningBaseline::Earning).unwrap();
        register_launch(&d, &app, "0.6.8");

        for reason in [
            SessionEvidence::MiningHalted,
            SessionEvidence::AcceptanceProbe,
            SessionEvidence::AcceptanceUndecided,
            SessionEvidence::NetworkWide,
        ] {
            // Even WITH accepted shares on the clock: a session layer 3 disqualified
            // is not evidence in either direction.
            let v = note_session(
                &d,
                &app,
                "0.6.8",
                SessionResult { ran_secs: 3600, accepted: 42, evidence: reason },
            );
            assert_eq!(v, SessionVerdict::Abstained { reason });
            assert!(probation(&app).is_some(), "{reason:?} must leave the trial open");
            assert!(lkg.exists(), "{reason:?} must not drop last-known-good");
        }
        // …and a real, judgeable session still decides it.
        assert_eq!(
            note_session(&d, &app, "0.6.8", SessionResult::judgeable(60, 1)),
            SessionVerdict::Committed { version: "0.6.8".into() }
        );
        assert!(!lkg.exists(), "a judgeable earning session commits normally");
    }

    /// A network-wide collapse must make the probation abstain — including on the
    /// very session that would otherwise have tipped it into a rollback. Blaming
    /// the local build for a failure every miner on the lane is having is never
    /// correct.
    #[test]
    fn a_network_wide_collapse_makes_the_probation_abstain() {
        let d = tmp("networkwide");
        let app = fake_app(&d, "NEW", "OLD");
        arm(&app, "0.6.8", "0.6.7", EarningBaseline::Earning).unwrap();
        register_launch(&d, &app, "0.6.8");
        confirm_start(&d, &app, "0.6.8");

        // One honest strike first (nothing knew anything yet).
        let long = SessionResult::judgeable(MIN_JUDGED_SESSION.as_secs(), 0);
        assert_eq!(note_session(&d, &app, "0.6.8", long), SessionVerdict::NoChange);
        assert_eq!(probation(&app).unwrap().failed_sessions, 1);

        // The next one WOULD roll back — that is exactly when the caller asks the
        // network, and the network says everybody is down.
        assert!(
            session_would_roll_back(&app, "0.6.8", &long),
            "the guard is only useful if this is the tipping session"
        );
        let v = note_session(
            &d,
            &app,
            "0.6.8",
            SessionResult {
                ran_secs: long.ran_secs,
                accepted: 0,
                evidence: SessionEvidence::NetworkWide,
            },
        );
        assert_eq!(v, SessionVerdict::Abstained { reason: SessionEvidence::NetworkWide });
        assert_eq!(std::fs::read_to_string(&app).unwrap(), "NEW", "no rollback");
        assert!(pins(&d).is_empty());
        assert_eq!(
            probation(&app).unwrap().failed_sessions,
            1,
            "the abstained session must not have added a strike"
        );
    }

    /// `session_would_roll_back` is the caller's "is it worth a network call"
    /// probe, so it must agree with what `note_session` actually does — for every
    /// shape, and without changing anything itself.
    #[test]
    fn would_roll_back_matches_what_note_session_does_and_writes_nothing() {
        let d = tmp("would");
        let app = fake_app(&d, "NEW", "OLD");
        arm(&app, "0.6.8", "0.6.7", EarningBaseline::Earning).unwrap();
        register_launch(&d, &app, "0.6.8");
        let long = SessionResult::judgeable(MIN_JUDGED_SESSION.as_secs(), 0);

        // Not on the tipping session yet, and asking does not move it there.
        assert!(!session_would_roll_back(&app, "0.6.8", &long));
        assert!(!session_would_roll_back(&app, "0.6.8", &long));
        assert_eq!(probation(&app).unwrap().failed_sessions, 0, "probing wrote nothing");
        // Nor for another version, a short session, or an abstaining one.
        assert!(!session_would_roll_back(&app, "0.6.9", &long));
        assert!(!session_would_roll_back(&app, "0.6.8", &SessionResult::judgeable(60, 0)));

        assert_eq!(note_session(&d, &app, "0.6.8", long), SessionVerdict::NoChange);
        assert!(session_would_roll_back(&app, "0.6.8", &long), "now it would");
        for reason in [
            SessionEvidence::MiningHalted,
            SessionEvidence::AcceptanceProbe,
            SessionEvidence::AcceptanceUndecided,
            SessionEvidence::NetworkWide,
        ] {
            assert!(
                !session_would_roll_back(
                    &app,
                    "0.6.8",
                    &SessionResult { ran_secs: long.ran_secs, accepted: 0, evidence: reason }
                ),
                "{reason:?} can never roll back"
            );
        }
        // …and it was telling the truth.
        assert!(matches!(
            note_session(&d, &app, "0.6.8", long),
            SessionVerdict::RolledBack { .. }
        ));
    }

    /// The pure decision table, straight from `judge_session` — no filesystem.
    #[test]
    fn judge_session_checks_layer_three_before_the_share_count() {
        let base = Probation {
            version: "0.6.8".into(),
            previous: "0.6.7".into(),
            armed_at_unix: 0,
            launches: 1,
            started_ok: true,
            previous_productive: true,
            baseline_unknown: false,
            failed_sessions: 0,
        };
        let long = MIN_JUDGED_SESSION.as_secs();

        assert_eq!(
            judge_session(&base, "0.6.8", &SessionResult::judgeable(long, 0)),
            SessionAction::Strike
        );
        assert_eq!(
            judge_session(&base, "0.6.8", &SessionResult::judgeable(60, 0)),
            SessionAction::Ignore
        );
        assert_eq!(
            judge_session(&base, "0.6.8", &SessionResult::judgeable(60, 1)),
            SessionAction::Commit
        );
        let tipping = Probation { failed_sessions: FAILED_SESSIONS_TO_ROLLBACK - 1, ..base.clone() };
        assert_eq!(
            judge_session(&tipping, "0.6.8", &SessionResult::judgeable(long, 0)),
            SessionAction::RollBack
        );
        // Layer 3 outranks BOTH the rollback and the commit.
        for reason in [
            SessionEvidence::MiningHalted,
            SessionEvidence::AcceptanceProbe,
            SessionEvidence::NetworkWide,
        ] {
            for accepted in [0, 99] {
                assert_eq!(
                    judge_session(
                        &tipping,
                        "0.6.8",
                        &SessionResult { ran_secs: long, accepted, evidence: reason }
                    ),
                    SessionAction::Abstain(reason),
                    "{reason:?} with accepted={accepted}"
                );
            }
        }
        // No earning baseline / another version: nothing to say, as before.
        let no_baseline = Probation { previous_productive: false, ..base.clone() };
        assert_eq!(
            judge_session(&no_baseline, "0.6.8", &SessionResult::judgeable(long, 0)),
            SessionAction::Ignore
        );
        assert_eq!(
            judge_session(&base, "0.6.9", &SessionResult::judgeable(long, 0)),
            SessionAction::Ignore
        );
        assert!(SessionEvidence::default() == SessionEvidence::Judgeable);
        assert!(!SessionEvidence::Judgeable.abstains());
        // Every reason a caller can give us abstains, and every one is a distinct key
        // in the local history — the only place anybody will see WHICH of them spared a
        // build its rollback.
        let mut keys = std::collections::BTreeSet::new();
        for e in [
            SessionEvidence::MiningHalted,
            SessionEvidence::AcceptanceProbe,
            SessionEvidence::NetworkWide,
        ] {
            assert!(e.abstains(), "{e:?}");
            assert!(keys.insert(e.key()), "duplicate history key for {e:?}");
        }
        assert!(!keys.contains(SessionEvidence::Judgeable.key()));
    }

    // ── version IDENTITY vs version ORDERING ────────────────────────────────

    /// A manifest publishing `"v0.6.9"` soaks, orders and installs exactly like
    /// `"0.6.9"` — every ordering check (`parse_version`, `is_revoked`) trims the
    /// leading `v`. Every IDENTITY check used to byte-compare the raw string, and
    /// that asymmetry voided the entire probation: `arm` stored `"v0.6.9"`, the
    /// binary answers `"0.6.9"`, and on the very first launch the trial was
    /// discarded as belonging to some other build. No crash-on-launch rollback, no
    /// stopped-earning rollback, and a `.lkg` copy that is never dropped — leaked
    /// on every rig.
    ///
    /// This is not an exotic manifest. `scripts/release.sh` took `--version`
    /// verbatim, `parse_verified_manifest` checked only `schema` and `product`,
    /// and the repo tags its releases `v0.6.7`: typing the tag is the natural
    /// mistake, and it is a silent one.
    #[test]
    fn a_v_prefixed_version_names_the_same_build_everywhere() {
        let d = tmp("vprefix");
        let app = fake_app(&d, "NEW", "OLD");
        let mut lkg = app.as_os_str().to_os_string();
        lkg.push(".lkg");
        let lkg = PathBuf::from(lkg);

        // The manifest spelling goes in…
        arm(&app, "v0.6.9", "0.6.8", EarningBaseline::Earning).unwrap();
        // …and the BINARY's own answer comes out. These name one build.
        assert!(
            matches!(register_launch(&d, &app, "0.6.9"), LaunchVerdict::OnTrial { .. }),
            "the running build IS the one on trial"
        );
        assert!(probation(&app).is_some(), "the trial must survive its first launch");
        assert!(note_launch_ok(&app, "0.6.9"), "and the launch must register");
        assert!(
            !confirm_start(&d, &app, "0.6.9"),
            "an earning baseline is not satisfied by starting"
        );
        assert!(lkg.exists(), "last-known-good must still be there to roll back to");

        // The mining half judges it too, rather than ignoring it as another build.
        let p = probation(&app).unwrap();
        assert_eq!(
            judge_session(&p, "0.6.9", &SessionResult::judgeable(60, 1)),
            SessionAction::Commit
        );
        assert_eq!(
            note_session(&d, &app, "0.6.9", SessionResult::judgeable(60, 1)),
            SessionVerdict::Committed { version: "0.6.9".into() },
            "the committed version is reported in its canonical spelling"
        );
        assert!(!lkg.exists(), "the commit drops last-known-good");
    }

    /// The other end of the same trial: a `v`-prefixed build that dies on launch
    /// must actually roll back and pin, and the pin it writes must be the one
    /// `decide` later matches against a manifest spelling it either way.
    #[test]
    fn a_v_prefixed_version_rolls_back_and_the_pin_matches_either_spelling() {
        let d = tmp("vprefix-rollback");
        let app = fake_app(&d, "NEW", "OLD");
        arm(&app, "v0.6.9", "0.6.8", EarningBaseline::Earning).unwrap();
        register_launch(&d, &app, "0.6.9");
        match register_launch(&d, &app, "0.6.9") {
            LaunchVerdict::RolledBack { failed_version, restored, .. } => {
                assert_eq!(failed_version, "0.6.9");
                assert!(restored);
            }
            other => panic!("expected a rollback, got {other:?}"),
        }
        assert_eq!(std::fs::read_to_string(&app).unwrap(), "OLD");
        assert_eq!(
            pins(&d),
            vec!["0.6.9".to_string()],
            "a pin is stored in the canonical spelling"
        );

        // …and it is honoured whichever way the manifest spells it next time.
        for spelling in ["0.6.9", "v0.6.9"] {
            let m = manifest(spelling);
            let pinned = pins(&d);
            assert!(
                matches!(decide(&input(&m, &pinned)), Decision::Notify { hold: Hold::Pinned, .. }),
                "a machine that rolled this back must not auto-install it as {spelling}"
            );
        }
    }

    /// The ledger is keyed by version, so it has to agree with everything else
    /// about what a version IS. Two spellings of one version must be one entry —
    /// otherwise re-spelling the number is a free reset of both the soak clock and
    /// the hash-conflict record, which is the one refusal with no override.
    #[test]
    fn the_seen_ledger_treats_both_spellings_as_one_version() {
        let d = tmp("vprefix-seen");
        let first = note_seen(&d, "0.6.9", &"aa".repeat(32));
        let again = note_seen(&d, "v0.6.9", &"bb".repeat(32));
        assert_eq!(
            again.seen.sha256,
            "aa".repeat(32),
            "the first bytes must still win: re-spelling a version is not a new sighting"
        );
        assert_eq!(again.seen.first_seen_unix, first.seen.first_seen_unix);
        assert_eq!(read_seen(&d).entries.len(), 1, "one version, one ledger entry");
    }

    #[test]
    fn a_stale_probation_for_another_version_is_discarded() {
        let d = tmp("stale");
        let app = fake_app(&d, "NEW", "OLD");
        arm(&app, "0.6.8", "0.6.7", EarningBaseline::Earning).unwrap();
        assert_eq!(register_launch(&d, &app, "0.6.7"), LaunchVerdict::Normal);
        assert!(probation(&app).is_none());
        assert_eq!(std::fs::read_to_string(&app).unwrap(), "NEW", "no surprise rollback");
    }

    #[test]
    fn an_abandoned_probation_expires_instead_of_hoarding_a_backup() {
        let d = tmp("expire");
        let app = fake_app(&d, "NEW", "OLD");
        arm(&app, "0.6.8", "0.6.7", EarningBaseline::Earning).unwrap();
        let mut p = probation(&app).unwrap();
        p.armed_at_unix = now_unix() - PROBATION_MAX.as_secs() - 1;
        write_probation(&app, &p).unwrap();
        assert_eq!(register_launch(&d, &app, "0.6.8"), LaunchVerdict::Normal);
        let mut lkg = app.as_os_str().to_os_string();
        lkg.push(".lkg");
        assert!(!PathBuf::from(lkg).exists());
        assert!(pins(&d).is_empty(), "expiry is not a failure — do not pin");
    }

    /// The rollback must work on the file that is CURRENTLY OPEN, because a
    /// rollback is always driven from the startup of the build being rolled back.
    ///
    /// On Windows a running `.exe` cannot be deleted but can be renamed, which is
    /// why `crate::rollback` moves the failed build aside instead of removing it.
    /// This test holds the file open for the whole rollback on every platform;
    /// on Windows that open handle is what the old delete-first order tripped on.
    #[test]
    fn rollback_works_while_the_failed_build_is_open() {
        let d = tmp("openfile");
        let app = fake_app(&d, "NEW", "OLD");
        let held = std::fs::File::open(&app).expect("hold the failed build open");
        arm(&app, "0.6.8", "0.6.7", EarningBaseline::Earning).unwrap();
        register_launch(&d, &app, "0.6.8");
        match register_launch(&d, &app, "0.6.8") {
            LaunchVerdict::RolledBack { restored, .. } => {
                assert!(restored, "a rollback we report must be one we performed");
            }
            other => panic!("expected rollback, got {other:?}"),
        }
        drop(held);
        assert_eq!(
            std::fs::read_to_string(&app).unwrap(),
            "OLD",
            "the previous build must be back at the app path, open handle or not"
        );
    }

    /// With no last-known-good on disk there is nothing to restore. We must pin
    /// the bad version and say so — never claim a rollback that did not happen.
    #[test]
    fn a_rollback_with_nothing_to_restore_is_reported_as_such() {
        let d = tmp("nolkg");
        let app = d.join(if cfg!(windows) { "alice-miner.exe" } else { "alice-miner" });
        std::fs::write(&app, "NEW").unwrap(); // no .lkg sibling
        arm(&app, "0.6.8", "0.6.7", EarningBaseline::Earning).unwrap();
        register_launch(&d, &app, "0.6.8");
        match register_launch(&d, &app, "0.6.8") {
            LaunchVerdict::RolledBack { restored, failed_version, .. } => {
                assert!(!restored, "must not claim a restore with no backup present");
                assert_eq!(failed_version, "0.6.8");
            }
            other => panic!("expected rollback verdict, got {other:?}"),
        }
        assert_eq!(std::fs::read_to_string(&app).unwrap(), "NEW");
        assert_eq!(pins(&d), vec!["0.6.8".to_string()], "still pinned");
    }

    /// Paths are built by pushing onto the app path's `OsString`, so they must
    /// come out right for a macOS bundle directory, a bare Linux binary and a
    /// Windows `.exe` alike. Exercised for all three shapes on every platform.
    #[test]
    fn probation_paths_are_correct_for_every_platform_shape() {
        for name in ["Alice Miner.app", "alice-miner", "alice-miner.exe"] {
            let d = tmp("shapes");
            let app = d.join(name);
            std::fs::write(&app, "NEW").unwrap();
            arm(&app, "1.0.0", "0.9.0", EarningBaseline::NotEarning).unwrap();
            let marker = probation_path(&app);
            assert_eq!(
                marker.file_name().unwrap().to_string_lossy(),
                format!("{name}.auto-probation"),
                "marker must sit BESIDE the app, not inside it or replacing its extension"
            );
            assert!(probation(&app).is_some());
            // And the state dir is untouched by any of it.
            assert!(!d.join("update-pins.json").exists());
        }
    }

    /// The publisher and the client must agree on the wire, byte for byte.
    ///
    /// This is the exact `latest.json` that `scripts/release.sh --rollout-pct 25
    /// --soak-hours 48 --revoke "0.6.6" --security` emits. If someone changes the
    /// shell here-doc and not the struct (or the reverse), this fails — which is
    /// better than discovering it when a revocation silently does not apply.
    #[test]
    fn the_manifest_the_release_script_emits_drives_the_policy() {
        let json = br#"{"schema":1,"product":"alice-miner","version":"0.6.8","min_supported":"0.3.0","released":"2026-08-14T00:00:00Z","notes":"n","artifacts":[{"platform":"macos-arm64","url":"https://example.invalid/a.zip","sha256":"aa","size":1}],"rollout_pct":25,"soak_hours":48,"revoked":["0.6.6"],"security":true}"#;
        let m = crate::parse_verified_manifest(json).expect("release.sh output must parse");
        assert_eq!(m.rollout_pct, Some(25));
        assert_eq!(m.soak_hours, Some(48));
        assert!(m.is_security());
        assert!(m.is_revoked("0.6.6"));

        // …and the policy actually reads them: 48h > the 24h floor, so a version
        // seen 30h ago is still soaking.
        let mut i = input(&m, &[]);
        i.mode = Mode::SecurityOnly;
        i.first_seen_unix = i.now_unix - 30 * 3600;
        assert!(matches!(
            decide(&i),
            Decision::Notify { hold: Hold::Soaking { .. }, .. }
        ));

        // A client on the revoked 0.6.6 is told so rather than offered 0.6.8.
        let mut i = input(&m, &[]);
        i.current = "0.6.6";
        assert!(matches!(decide(&i), Decision::CurrentRevoked { .. }));
    }

    /// The publisher's spelling is canonicalised at the ONE boundary where an
    /// untrusted manifest becomes a `Manifest` — so nothing downstream can key
    /// off `"v0.6.9"` even in a code path nobody has written yet.
    ///
    /// Normalising rather than rejecting is the deliberate direction: refusing a
    /// manifest over a cosmetic spelling would stop a whole fleet from seeing
    /// updates at all, which is the same self-inflicted blackout as bumping
    /// `schema`. The install this produces is the ordinary one, named the
    /// ordinary way.
    #[test]
    fn a_v_prefixed_manifest_version_is_canonical_by_the_time_policy_sees_it() {
        let json = br#"{"schema":1,"product":"alice-miner","version":"v0.6.9","min_supported":"0.3.0","released":"2026-08-14T00:00:00Z","notes":"n","artifacts":[{"platform":"macos-arm64","url":"https://example.invalid/a.zip","sha256":"aa","size":1}]}"#;
        let m = crate::parse_verified_manifest(json).expect("a v-prefixed manifest still parses");
        assert_eq!(m.version, "0.6.9", "the leading v is gone by the time we hold it");

        // And the whole decision runs on it as if it had never been there. (The
        // artifact only matches this platform on macos-arm64; the point being
        // asserted is the version, so drive `decide` with the fixture manifest
        // carrying the parsed version.)
        let mut policy = manifest(&m.version);
        policy.revoked = vec!["v0.6.7".into()];
        let i = input(&policy, &[]);
        assert!(
            matches!(decide(&i), Decision::CurrentRevoked { .. }),
            "a v-prefixed revocation withdraws the running build"
        );
        let policy = manifest(&m.version);
        match decide(&input(&policy, &[])) {
            Decision::Install { version, .. } => assert_eq!(version, "0.6.9"),
            other => panic!("expected an ordinary install, got {other:?}"),
        }
    }

    #[test]
    fn history_log_appends_and_survives_rotation() {
        let d = tmp("hist");
        log_event(&d, "test", serde_json::json!({ "n": 1 }));
        log_event(&d, "test", serde_json::json!({ "n": 2 }));
        let body = std::fs::read_to_string(d.join("update-history.jsonl")).unwrap();
        assert_eq!(body.lines().count(), 2);
        assert!(body.contains("\"event\":\"test\""));
    }
}
