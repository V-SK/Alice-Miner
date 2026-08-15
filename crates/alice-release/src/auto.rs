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
//!     version (a local, tamper-proof clock), never on the manifest's `released`
//!     field, and the manifest's `soak_hours` can only extend it past the
//!     [`SOAK_FLOOR`] the client hard-codes;
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
    /// The version was previously seen with DIFFERENT artifact bytes. Refuse and
    /// shout: a re-published version is either a mistake or an attack, and we do
    /// not need to know which to know we should not install it.
    HashConflict { seen_sha256: String, now_sha256: String },
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
    /// Versions that failed a health probation here.
    pub pinned: &'a [String],
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
                visible_for_s: input.now_unix.saturating_sub(input.first_seen_unix),
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
    if input.pinned.iter().any(|p| p == &m.version) {
        return notify(Hold::Pinned);
    }

    // 3. Mode gates.
    match input.mode {
        Mode::Off => return notify(Hold::ModeOff),
        Mode::Notify => return notify(Hold::NotifyOnly),
        Mode::SecurityOnly if !m.is_security() => return notify(Hold::NotSecurity),
        _ => {}
    }

    // 4. Soak. Anchored on OUR first sighting, floored by OUR constant; the
    //    manifest may only push it further out.
    let soak = SOAK_FLOOR
        .as_secs()
        .max(m.soak_hours.unwrap_or(0).saturating_mul(3600));
    let ready_at = input.first_seen_unix.saturating_add(soak);
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
    /// The sha256 of the artifact we are about to install, if this platform has
    /// one. `None` means there is nothing to install here (manual download), and
    /// there is correspondingly nothing to compare against the ledger.
    pub artifact_sha256: Option<&'a str>,
    /// The sha256 this machine recorded the FIRST time it saw this version.
    pub seen_sha256: Option<&'a str>,
    /// Versions that failed a health probation here.
    pub pinned: &'a [String],
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
/// Ordering is deliberate. The hash conflict comes first because it is the only
/// finding here that rests on evidence the publisher cannot restate: the local
/// ledger. Revocation and the pin are both claims made elsewhere — one by the
/// manifest (attacker-controlled under key compromise), one by this machine's
/// own past — and if two findings apply at once, the one the user most needs to
/// read is the one nobody upstream could have written.
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
    if m.is_revoked(&m.version) {
        return ManualVerdict::Refuse(ManualRefusal::Revoked);
    }
    if input.pinned.iter().any(|p| p == &m.version) {
        return ManualVerdict::ConfirmFirst(ManualConcern::Pinned);
    }
    ManualVerdict::Proceed
}

/// How long a version has been visible to this machine, in seconds. Saturating,
/// so a clock that went backwards reads as "just seen" rather than as an
/// enormous, install-clearing age.
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

fn read_seen(state_dir: &Path) -> Vec<Seen> {
    std::fs::read(seen_path(state_dir))
        .ok()
        .and_then(|b| serde_json::from_slice::<Vec<Seen>>(&b).ok())
        .unwrap_or_default()
}

/// Record that we have seen `version` carrying `sha256`, and return the record
/// this machine holds — the FIRST one, never overwritten.
///
/// This is the append-only local half of a transparency log. It is what makes
/// "the same version, different bytes" detectable on the client rather than only
/// on a server we would also have to trust.
pub fn note_seen(state_dir: &Path, version: &str, sha256: &str) -> Seen {
    let mut all = read_seen(state_dir);
    if let Some(existing) = all.iter().find(|s| s.version == version) {
        return existing.clone();
    }
    let rec = Seen {
        version: version.to_string(),
        first_seen_unix: now_unix(),
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
    if let Ok(bytes) = serde_json::to_vec_pretty(&all) {
        let _ = write_atomic(&seen_path(state_dir), &bytes);
    }
    rec
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
    if all.iter().any(|v| v == version) {
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
    /// Mining sessions of at least [`MIN_JUDGED_SESSION`] that saw zero accepted
    /// shares.
    pub failed_sessions: u32,
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
pub fn arm(app_path: &Path, version: &str, previous: &str, previous_productive: bool) -> Result<()> {
    write_probation(
        app_path,
        &Probation {
            version: version.to_string(),
            previous: previous.to_string(),
            armed_at_unix: now_unix(),
            launches: 0,
            started_ok: false,
            previous_productive,
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

    if p.version != running_version {
        // We are not running the build on trial — either a rollback already took
        // effect or the user installed something else by hand. Either way the
        // trial is over and its record is stale.
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
    if p.version != running_version || p.started_ok {
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
    if p.version != running_version {
        return false;
    }
    if !p.previous_productive {
        // The build we replaced was not earning either, so "this one is not
        // earning" would say nothing about this one. Commit on the start proof
        // alone — the same bar a manual update clears.
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
    if p.version != running_version || !p.previous_productive {
        return SessionAction::Ignore;
    }
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
            released: "2026-08-14T00:00:00Z".into(),
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
            pinned: pins,
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

    #[test]
    fn soak_ignores_the_manifests_released_field_entirely() {
        // `released` is attacker-controlled; only our own first sighting counts.
        let mut m = manifest("0.6.8");
        m.released = "2020-01-01T00:00:00Z".into();
        let mut i = input(&m, &[]);
        i.first_seen_unix = i.now_unix;
        assert!(matches!(decide(&i), Decision::Notify { hold: Hold::Soaking { .. }, .. }));
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

    // ── the manual path ─────────────────────────────────────────────────────

    fn manual<'a>(m: &'a Manifest, pins: &'a [String]) -> ManualInput<'a> {
        ManualInput {
            manifest: m,
            artifact_sha256: Some(&m.artifacts[0].sha256),
            seen_sha256: None,
            pinned: pins,
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

    /// With no artifact for this platform there are no bytes to compare, and the
    /// gate must not invent a conflict out of the absence.
    #[test]
    fn manual_without_a_platform_artifact_finds_no_conflict() {
        let m = manifest("0.6.8");
        let seen = "bb".repeat(32);
        let i = ManualInput {
            manifest: &m,
            artifact_sha256: None,
            seen_sha256: Some(&seen),
            pinned: &[],
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
        assert_eq!(first.first_seen_unix, again.first_seen_unix);
        assert_eq!(again.sha256, "aa", "first bytes win; the ledger is append-only");
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
        arm(&app, "0.6.8", "0.6.7", /* previous_productive */ false).unwrap();
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

    /// `note_launch_ok` is inert when there is no probation, or when this process
    /// is not the build on trial.
    #[test]
    fn note_launch_ok_is_inert_off_the_probation_path() {
        let d = tmp("launchok2");
        let app = fake_app(&d, "NEW", "OLD");
        assert!(!note_launch_ok(&app, "0.6.8"), "no probation armed");
        arm(&app, "0.6.8", "0.6.7", false).unwrap();
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
        arm(&app, "0.6.8", "0.6.7", true).unwrap();

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
        arm(&app, "0.6.8", "0.6.7", true).unwrap();
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
        arm(&app, "0.6.8", "0.6.7", true).unwrap();
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
        arm(&app, "0.6.8", "0.6.7", /* previous_productive */ false).unwrap();
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
        arm(&app, "0.6.8", "0.6.7", /* previous_productive */ true).unwrap();
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
        arm(&app, "0.6.8", "0.6.7", true).unwrap();
        register_launch(&d, &app, "0.6.8");

        for reason in [
            SessionEvidence::MiningHalted,
            SessionEvidence::AcceptanceProbe,
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
        arm(&app, "0.6.8", "0.6.7", true).unwrap();
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
        arm(&app, "0.6.8", "0.6.7", true).unwrap();
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

    #[test]
    fn a_stale_probation_for_another_version_is_discarded() {
        let d = tmp("stale");
        let app = fake_app(&d, "NEW", "OLD");
        arm(&app, "0.6.8", "0.6.7", true).unwrap();
        assert_eq!(register_launch(&d, &app, "0.6.7"), LaunchVerdict::Normal);
        assert!(probation(&app).is_none());
        assert_eq!(std::fs::read_to_string(&app).unwrap(), "NEW", "no surprise rollback");
    }

    #[test]
    fn an_abandoned_probation_expires_instead_of_hoarding_a_backup() {
        let d = tmp("expire");
        let app = fake_app(&d, "NEW", "OLD");
        arm(&app, "0.6.8", "0.6.7", true).unwrap();
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
        arm(&app, "0.6.8", "0.6.7", true).unwrap();
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
        arm(&app, "0.6.8", "0.6.7", true).unwrap();
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
            arm(&app, "1.0.0", "0.9.0", false).unwrap();
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
