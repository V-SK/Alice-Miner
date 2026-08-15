//! GUI wiring for the signed self-updater (`alice_release`).
//!
//! The cryptographic kernel lives in `alice-release` (ed25519-signed manifest →
//! SHA-256-verified artifact → atomic swap with last-known-good rollback, and a
//! data-dir guard that can NEVER write into the keystore home). That kernel is
//! audited-sound but was dormant: nothing called it. This module is the thin,
//! USER-INITIATED front-end the audit (H-1) asked for:
//!
//!   * [`UpdateManager::register_launch`] — run ONCE at startup to resolve the
//!     first-launch health gate (commit-or-rollback after an update).
//!   * [`UpdateManager::check`] — kick a background `check_for_update`
//!     (network-bound; never on the UI thread). The Settings "Check for updates"
//!     button drives this.
//!   * [`UpdateManager::apply`] — on a verified NEWER manifest, download +
//!     verify + atomically swap, then arm the health gate. Also background.
//!
//! v1 policy: **never silent-apply**. A check only ever surfaces a state; the
//! user must press "Update now" to apply. This mirrors the Wallet ("the wallet
//! NEVER silent-applies").
//!
//! Nothing here is reward- or identity-adjacent: the only network this performs
//! is the manifest/artifact fetch over rustls TLS, and the only filesystem write
//! is the app swap (guarded away from the keystore by `assert_not_in_data_dir`).

use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use alice_miner_core::alice_release as release;
use release::{Artifact, CheckOutcome, Manifest};

/// What the updater is doing right now, for the Settings UI to render. Kept
/// deliberately small + non-numeric (no version-shaming, no fake progress bar).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum UpdateUi {
    /// No check has run this session.
    #[default]
    Idle,
    /// A background check or apply is in flight (spinner / disabled button).
    Checking,
    /// The check completed: already on the latest (or newer) build.
    UpToDate { current: String },
    /// A newer version is available WITH an artifact for this platform — offer
    /// "Update now". Carries everything `apply` needs. The (large) `Manifest` is
    /// boxed so this enum stays small.
    Available {
        current: String,
        version: String,
        notes: String,
        /// How long this machine has been able to see this version — the fact
        /// the automatic path decides on, shown to the person deciding instead.
        /// `None` when there was no sighting to record.
        visibility: Option<String>,
        /// A concern the shared guardrails raised that does not refuse the
        /// install but must be answered in its own right. When this is `Some`,
        /// the panel names it and the button becomes an explicit "install
        /// anyway" — never the ordinary "Update now".
        risk: Option<String>,
        manifest: Box<Manifest>,
        artifact: Artifact,
    },
    /// The shared guardrails REFUSED this install: the publisher withdrew the
    /// version, or the same version number is now being offered with different
    /// bytes than this machine first saw it carrying. There is no button here on
    /// purpose — this is not a confirmation, it is a refusal.
    Refused { version: String, message: String },
    /// A newer version exists but ships no artifact for this platform — point the
    /// user at the download page instead of an in-app update.
    AvailableNoArtifact { current: String, version: String },
    /// The running build is below `min_supported`: a hard "must upgrade" notice.
    Unsupported {
        current: String,
        min_supported: String,
    },
    /// An apply is in flight (downloading + verifying + swapping).
    Applying,
    /// An update was applied and verified; the user should relaunch to run it.
    Applied { version: String },
    /// The check or apply failed (network down, signature/integrity failure, …).
    /// The message is the human-readable `UpdateError` (never a secret).
    Failed { message: String },
}

impl UpdateUi {
    /// Whether a background job is in flight (so the button renders disabled).
    pub fn is_busy(&self) -> bool {
        matches!(self, UpdateUi::Checking | UpdateUi::Applying)
    }

    /// Whether this state should draw a badge on the Settings nav so the user
    /// notices it without opening Settings — i.e. there is something actionable
    /// about the build (an offer, a manual-download pointer, a forced-upgrade
    /// notice, an applied build waiting on a restart, or a refusal they need to
    /// know about). `Idle`/`Checking`/`UpToDate`/`Applying`/`Failed` carry no
    /// standing call-to-action here.
    pub fn wants_attention(&self) -> bool {
        matches!(
            self,
            UpdateUi::Available { .. }
                | UpdateUi::AvailableNoArtifact { .. }
                | UpdateUi::Unsupported { .. }
                | UpdateUi::Applied { .. }
                | UpdateUi::Refused { .. }
        )
    }
}

/// A message from a background updater job back to the UI thread.
enum Msg {
    /// A completed check, already through the shared manual guardrails. The
    /// (large) state is boxed to keep the enum small (it can carry a full
    /// manifest). The gate runs on the worker thread rather than in `poll`
    /// because it touches the disk (the seen ledger, the failure pins) and
    /// `poll` runs once per frame on the UI thread.
    Checked(Box<UpdateUi>),
    CheckFailed(String),
    Applied(String),
    ApplyFailed(String),
    /// A line from the GUARDED automatic updater (installed / held / refused).
    Auto(String),
}

/// Owns the updater state + the channel to its background worker. One per app.
pub struct UpdateManager {
    pub ui: UpdateUi,
    /// The most recent line from the guarded automatic updater — what it did, or
    /// what it declined to do and why. Rendered in Settings → Software update and
    /// kept until it is replaced, so a miner can always answer "is my client
    /// current, and if not, why not" without opening a terminal.
    pub auto_note: Option<String>,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    auto_in_flight: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// A session report is in flight on a worker thread (never two — two
    /// concurrent reports could double-count a strike against the probation).
    session_in_flight: std::sync::Arc<std::sync::atomic::AtomicBool>,
    last_auto_check: Option<std::time::Instant>,
    last_productive_mark: Option<std::time::Instant>,
    session_start: Option<std::time::Instant>,
    judged_this_session: bool,
}

impl Default for UpdateManager {
    fn default() -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        Self {
            ui: UpdateUi::Idle,
            auto_note: None,
            tx,
            rx,
            auto_in_flight: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            session_in_flight: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            last_auto_check: None,
            last_productive_mark: None,
            session_start: None,
            judged_this_session: false,
        }
    }
}

impl UpdateManager {
    /// Resolve the first-launch health gate ONCE at startup. If a freshly-applied
    /// build came up and is healthy, this is where we'd `confirm_health_and_commit`;
    /// a crash-looping build is rolled back to last-known-good. Best-effort and
    /// silent — a failure here must never block the app from starting.
    ///
    /// Returns an optional one-time "updated to vX" note the caller can surface.
    pub fn register_launch_at_startup() -> Option<String> {
        let app_path = release::current_app_path().ok()?;
        match release::register_launch(&app_path, release::current_version()) {
            Ok(release::LaunchDecision::FreshFirstRun { version }) => {
                // The new build reached startup. We consider "the GUI constructed
                // successfully" as healthy enough to commit (drop last-known-good)
                // so a later unrelated crash doesn't roll back a good update.
                let _ = release::confirm_health_and_commit(&app_path);
                Some(version)
            }
            // Normal / rolled-back / error: nothing to surface here. A RolledBack
            // means a bad update was reverted; the user is back on the good build.
            _ => None,
        }
    }

    /// Resolve the GUARDED-automatic-update probation at startup, alongside the
    /// manual gate above. Returns a line to show the user when a build was
    /// automatically rolled back (they need to restart to leave it), otherwise
    /// `None`.
    ///
    /// Two gates rather than one with a flag, on purpose: the manual gate treats
    /// "the process started" as proof of health, which is right for a build the
    /// user chose and too weak for one that installed itself while they slept.
    pub fn auto_gate_at_startup() -> Option<String> {
        let note = alice_miner_core::autoupdate::register_launch();
        // The GUI has constructed and is about to paint: that is this process
        // demonstrably up and doing its job.
        alice_miner_core::autoupdate::confirm_start();
        note
    }

    /// Kick one guarded automatic-update cycle in the background, unless one is
    /// already running or it is not yet due. `force` runs it regardless of the
    /// timer (used once at launch).
    ///
    /// This never blocks the UI thread and never interrupts mining: an install
    /// swaps the app on disk and takes effect on the next launch.
    pub fn auto_check(&mut self, force: bool) {
        use std::sync::atomic::Ordering;
        const RECHECK: std::time::Duration = std::time::Duration::from_secs(6 * 60 * 60);
        if !force {
            match self.last_auto_check {
                Some(t) if t.elapsed() < RECHECK => return,
                None => return,
                _ => {}
            }
        }
        if self.auto_in_flight.swap(true, Ordering::SeqCst) {
            return;
        }
        self.last_auto_check = Some(std::time::Instant::now());
        let tx = self.tx.clone();
        let flag = self.auto_in_flight.clone();
        let quiet_holds = !force;
        thread::spawn(move || {
            let outcome = alice_miner_core::autoupdate::tick(quiet_holds);
            if let Some(m) = outcome.message() {
                let _ = tx.send(Msg::Auto(m.to_string()));
            }
            flag.store(false, Ordering::SeqCst);
        });
    }

    /// Feed the mining half of the post-update health probation. Call once per
    /// frame with the live mining snapshot (`None` when not mining).
    ///
    /// Identical logic to the CLI's session driver, calling the identical kernel:
    /// an accepted share commits the probation and refreshes the "this machine
    /// earns" baseline; a long stretch with none counts against the build once
    /// per session, and only when the build it replaced HAD been earning here and
    /// the acceptance guard has not disqualified the session (F4 — a halted lane's
    /// accepted counter is frozen by design and says nothing about the build).
    pub fn note_mining(&mut self, snap: Option<&alice_miner_core::engine::Snapshot>) {
        let Some(snap) = snap else {
            self.session_start = None;
            self.judged_this_session = false;
            return;
        };
        let mining = alice_miner_core::autoupdate::MiningEvidence::from_snapshot(snap);
        let start = *self.session_start.get_or_insert_with(std::time::Instant::now);

        if mining.counts_as_earning() {
            let due = self
                .last_productive_mark
                .map(|t| t.elapsed() >= std::time::Duration::from_secs(10 * 60))
                .unwrap_or(true);
            if due {
                self.last_productive_mark = Some(std::time::Instant::now());
                alice_miner_core::autoupdate::mark_productive();
            }
        }

        let accepted = mining.accepted;
        let ran = start.elapsed();
        let judge = accepted > 0
            || (!self.judged_this_session
                && ran >= alice_miner_core::alice_release::auto::MIN_JUDGED_SESSION);
        if !judge {
            return;
        }
        if accepted == 0 {
            self.judged_this_session = true;
        }

        // A report that could decide a ROLLBACK first asks the network whether the
        // whole lane is down (F4) — a bounded but blocking GET, and this is the UI
        // thread. That case (at most once per session) goes to a worker and its
        // verdict arrives through `poll()`; every other report is local-only and
        // runs inline.
        if !alice_miner_core::autoupdate::session_may_consult_the_network(ran, &mining) {
            if let Some(msg) = alice_miner_core::autoupdate::note_session(ran, &mining) {
                self.auto_note = Some(msg);
            }
            return;
        }
        use std::sync::atomic::Ordering;
        if self.session_in_flight.swap(true, Ordering::SeqCst) {
            return;
        }
        let tx = self.tx.clone();
        let flag = self.session_in_flight.clone();
        thread::spawn(move || {
            if let Some(msg) = alice_miner_core::autoupdate::note_session(ran, &mining) {
                let _ = tx.send(Msg::Auto(msg));
            }
            flag.store(false, Ordering::SeqCst);
        });
    }

    /// Drain any completed background results into [`Self::ui`]. Call once per
    /// frame from the app's update loop (cheap; non-blocking).
    pub fn poll(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::Checked(ui) => self.ui = *ui,
                Msg::CheckFailed(m) => self.ui = UpdateUi::Failed { message: m },
                Msg::Applied(version) => self.ui = UpdateUi::Applied { version },
                Msg::ApplyFailed(m) => self.ui = UpdateUi::Failed { message: m },
                // The automatic updater speaks in whole sentences and does NOT
                // overwrite the manual updater's state — the two are independent
                // and a user mid-manual-check should not see it hijacked.
                Msg::Auto(m) => self.auto_note = Some(m),
            }
        }
    }

    /// Kick a background `check_for_update`. No-op if a job is already running.
    pub fn check(&mut self) {
        if self.ui.is_busy() {
            return;
        }
        self.ui = UpdateUi::Checking;
        let tx = self.tx.clone();
        thread::spawn(move || {
            let msg = match release::check_for_update(release::current_version()) {
                Ok(outcome) => Msg::Checked(Box::new(outcome_to_ui(outcome))),
                Err(e) => Msg::CheckFailed(e.to_string()),
            };
            let _ = tx.send(msg);
        });
    }

    /// Apply the currently-`Available` update (guardrails → download → verify →
    /// atomic swap → arm health gate). No-op unless the UI is in the `Available`
    /// state. The artifact is re-verified (size + SHA-256) before anything is
    /// written, and the swap can never touch the keystore
    /// (`assert_not_in_data_dir`).
    ///
    /// The shared guardrails run AGAIN here, on the worker thread, rather than
    /// being trusted from the state the check left behind. That state can be
    /// minutes or hours old, and the two findings that matter — the publisher
    /// withdrawing the version, and the bytes behind the version number
    /// changing — are exactly the ones that appear between a check and a click.
    /// A refusal found here turns the click into the refusal notice; a concern
    /// found here that the user has NOT already been shown turns the click into
    /// showing it, rather than into an install.
    pub fn apply(&mut self) {
        let (manifest, artifact, acknowledged) = match &self.ui {
            UpdateUi::Available {
                manifest,
                artifact,
                risk,
                ..
            } => (manifest.clone(), artifact.clone(), risk.is_some()),
            _ => return,
        };
        self.ui = UpdateUi::Applying;
        let tx = self.tx.clone();
        thread::spawn(move || {
            let check = alice_miner_core::autoupdate::manual_check(
                &manifest,
                Some(&artifact),
                release::current_version(),
            );
            let msg = match &check.outcome {
                alice_miner_core::autoupdate::ManualOutcome::Refuse { message } => {
                    Msg::Checked(Box::new(UpdateUi::Refused {
                        version: manifest.version.clone(),
                        message: message.clone(),
                    }))
                }
                // A concern the user has not been shown yet is not something a
                // click can have answered. Surface it and let them press again.
                alice_miner_core::autoupdate::ManualOutcome::Confirm { .. } if !acknowledged => {
                    Msg::Checked(Box::new(with_gate(
                        UpdateUi::Available {
                            current: release::current_version().to_string(),
                            version: manifest.version.clone(),
                            notes: manifest.notes.clone(),
                            visibility: None,
                            risk: None,
                            manifest: manifest.clone(),
                            artifact: artifact.clone(),
                        },
                        check,
                    )))
                }
                _ => match apply_pipeline(&manifest, &artifact) {
                    Ok(version) => Msg::Applied(version),
                    Err(e) => Msg::ApplyFailed(e),
                },
            };
            let _ = tx.send(msg);
        });
    }
}

/// Run the SHARED manual guardrails over a freshly-checked state.
///
/// This is the GUI's half of the F1 fix. `alice-miner update` and this button are
/// the same act, and until now only the CLI ran any of these checks — the GUI's
/// "Update now" went straight from a verified manifest to a download, past the
/// seen ledger, past the hash-conflict refusal and past the failure pin. Both
/// front-ends now call one driver in `alice_miner_core::autoupdate`.
fn gate(ui: UpdateUi) -> UpdateUi {
    let UpdateUi::Available {
        ref manifest,
        ref artifact,
        ..
    } = ui
    else {
        return ui;
    };
    // The RUNNING version, not the `current` the checked state carries: the
    // no-downgrade refusal has to rest on what this process actually is.
    let check =
        alice_miner_core::autoupdate::manual_check(manifest, Some(artifact), release::current_version());
    with_gate(ui, check)
}

/// Fold a completed guardrail result into an `Available` state.
fn with_gate(ui: UpdateUi, check: alice_miner_core::autoupdate::ManualCheck) -> UpdateUi {
    use alice_miner_core::autoupdate::ManualOutcome;
    let UpdateUi::Available {
        current,
        version,
        notes,
        manifest,
        artifact,
        ..
    } = ui
    else {
        return ui;
    };
    match check.outcome {
        ManualOutcome::Refuse { message } => UpdateUi::Refused { version, message },
        ManualOutcome::Confirm { message } => UpdateUi::Available {
            current,
            version,
            notes,
            visibility: check.visibility,
            risk: Some(message),
            manifest,
            artifact,
        },
        ManualOutcome::Proceed => UpdateUi::Available {
            current,
            version,
            notes,
            visibility: check.visibility,
            risk: None,
            manifest,
            artifact,
        },
    }
}

/// The download → verify → swap → arm-health-gate pipeline, off the UI thread.
fn apply_pipeline(manifest: &Manifest, artifact: &Artifact) -> Result<String, String> {
    // SHA-256 + size are verified inside download_and_verify BEFORE any byte is
    // written; apply_update re-reads + re-verifies from disk before extraction.
    let bytes = release::download_and_verify(artifact).map_err(|e| e.to_string())?;
    let applied = release::apply_update(artifact, &bytes).map_err(|e| e.to_string())?;
    // Arm the first-launch health gate so a crash-on-launch of the new build
    // rolls back to last-known-good on the next start.
    release::arm_pending_health_check(&applied.app_path, &manifest.version)
        .map_err(|e| e.to_string())?;
    Ok(manifest.version.clone())
}

/// Map a verified [`CheckOutcome`] onto the UI state, guardrails included.
///
/// This is the ONLY conversion production code uses, and it is deliberately the
/// one with the plain name. The unguarded mapping below is `map_outcome`, which
/// reads as the special case it is: reaching an installable `Available` state
/// without the shared guardrails having run should require asking for it by
/// name, not be what you get by writing the obvious thing.
fn outcome_to_ui(outcome: CheckOutcome) -> UpdateUi {
    gate(map_outcome(outcome))
}

/// The pure half: shape only, no disk, no policy.
fn map_outcome(outcome: CheckOutcome) -> UpdateUi {
    match outcome {
        CheckOutcome::UpToDate { current } => UpdateUi::UpToDate { current },
        CheckOutcome::UpdateAvailable {
            current,
            manifest,
            artifact,
        } => UpdateUi::Available {
            current,
            version: manifest.version.clone(),
            notes: manifest.notes.clone(),
            // Filled in by `gate`, which is the half that touches the disk.
            visibility: None,
            risk: None,
            manifest: Box::new(manifest),
            artifact,
        },
        CheckOutcome::UpdateAvailableNoArtifact { current, manifest } => {
            UpdateUi::AvailableNoArtifact {
                current,
                version: manifest.version,
            }
        }
        CheckOutcome::Unsupported {
            current,
            min_supported,
            ..
        } => UpdateUi::Unsupported {
            current,
            min_supported,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use release::{Artifact, Manifest};

    fn manifest_with(version: &str, min: &str, with_artifact: bool) -> Manifest {
        let artifacts = if with_artifact {
            vec![Artifact {
                platform: release::current_platform().to_string(),
                url: "https://example.invalid/alice-miner-update.tar.gz".to_string(),
                sha256: "00".repeat(32),
                size: 1,
            }]
        } else {
            // An artifact for a platform that is NOT ours, so the "no artifact for
            // this platform" branch is exercised deterministically.
            vec![Artifact {
                platform: "definitely-not-this-platform".to_string(),
                url: "https://example.invalid/other.tar.gz".to_string(),
                sha256: "00".repeat(32),
                size: 1,
            }]
        };
        Manifest {
            schema: 1,
            product: release::PRODUCT.to_string(),
            version: version.to_string(),
            min_supported: min.to_string(),
            released: "2026-06-03T00:00:00Z".to_string(),
            notes: "Test notes.".to_string(),
            artifacts,
            rollout_pct: None,
            soak_hours: None,
            revoked: Vec::new(),
            security: None,
        }
    }

    /// A VERIFIED, strictly-newer manifest with an artifact for this platform is
    /// surfaced as `Available` (the "update offered" path).
    #[test]
    fn newer_manifest_with_artifact_is_offered() {
        let m = manifest_with("99.0.0", "0.0.1", true);
        let ui = map_outcome(release::evaluate(m, "0.1.0"));
        match ui {
            UpdateUi::Available {
                version, artifact, ..
            } => {
                assert_eq!(version, "99.0.0");
                assert_eq!(artifact.platform, release::current_platform());
            }
            other => panic!("expected Available, got {other:?}"),
        }
    }

    /// A newer manifest with NO artifact for this platform points at the download
    /// page (no in-app apply offered).
    #[test]
    fn newer_manifest_without_artifact_points_to_download() {
        let m = manifest_with("99.0.0", "0.0.1", false);
        let ui = map_outcome(release::evaluate(m, "0.1.0"));
        assert!(matches!(ui, UpdateUi::AvailableNoArtifact { .. }));
    }

    /// A DOWNGRADE (manifest older than current) is NOT offered — strict
    /// no-downgrade. `evaluate` reports UpToDate, which we render as such.
    #[test]
    fn downgrade_manifest_is_rejected_as_up_to_date() {
        let m = manifest_with("0.0.1", "0.0.1", true);
        let ui = map_outcome(release::evaluate(m, "9.9.9"));
        assert!(matches!(ui, UpdateUi::UpToDate { .. }), "got {ui:?}");
    }

    /// An EQUAL version is not newer (no-downgrade boundary) → UpToDate.
    #[test]
    fn equal_version_is_up_to_date() {
        let m = manifest_with("1.2.3", "0.0.1", true);
        let ui = map_outcome(release::evaluate(m, "1.2.3"));
        assert!(matches!(ui, UpdateUi::UpToDate { .. }));
    }

    /// Running below `min_supported` is surfaced as a hard `Unsupported` notice.
    #[test]
    fn below_min_supported_is_unsupported() {
        let m = manifest_with("99.0.0", "2.0.0", true);
        let ui = map_outcome(release::evaluate(m, "1.0.0"));
        match ui {
            UpdateUi::Unsupported { min_supported, .. } => assert_eq!(min_supported, "2.0.0"),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    /// The nav badge lights up exactly for the actionable states (an offer, a
    /// manual-download pointer, a forced-upgrade notice, or an applied build
    /// pending restart) and stays dark for the no-action states. This is what the
    /// launch-time check feeds, so a real update is never silently invisible.
    #[test]
    fn wants_attention_only_for_actionable_states() {
        let actionable = [
            UpdateUi::AvailableNoArtifact { current: "0.3.0".into(), version: "0.3.2".into() },
            UpdateUi::Unsupported { current: "0.2.0".into(), min_supported: "0.3.0".into() },
            UpdateUi::Applied { version: "0.3.2".into() },
        ];
        for ui in actionable {
            assert!(ui.wants_attention(), "expected a badge for {ui:?}");
        }
        let quiet = [
            UpdateUi::Idle,
            UpdateUi::Checking,
            UpdateUi::UpToDate { current: "0.3.2".into() },
            UpdateUi::Applying,
            UpdateUi::Failed { message: "network down".into() },
        ];
        for ui in quiet {
            assert!(!ui.wants_attention(), "expected NO badge for {ui:?}");
        }
    }

    /// A WRONG-PRODUCT manifest (the Wallet's) signed by the same key is rejected
    /// at parse time — proving the cross-product guard the GUI relies on. (We test
    /// the parse guard directly since `map_outcome` only ever sees a verified,
    /// product-checked manifest.)
    #[test]
    fn wrong_product_manifest_is_rejected_before_offer() {
        let mut m = manifest_with("99.0.0", "0.0.1", true);
        m.product = "alice-wallet".to_string();
        let bytes = serde_json::to_vec(&m).unwrap();
        assert!(
            release::parse_verified_manifest(&bytes).is_err(),
            "a Wallet manifest must never reach the Miner's update offer"
        );
    }

    /// `apply()` is a no-op (stays put) unless the UI is in the `Available` state,
    /// so a stray button press in any other state can never download/swap.
    #[test]
    fn apply_is_noop_unless_available() {
        let mut mgr = UpdateManager {
            ui: UpdateUi::UpToDate {
                current: "1.0.0".into(),
            },
            ..Default::default()
        };
        mgr.apply();
        assert!(
            matches!(mgr.ui, UpdateUi::UpToDate { .. }),
            "apply must not transition out of a non-Available state"
        );
    }

    /// `check()` does not start a second job while one is in flight.
    #[test]
    fn check_is_noop_while_busy() {
        let mut mgr = UpdateManager {
            ui: UpdateUi::Applying,
            ..Default::default()
        };
        mgr.check();
        assert_eq!(mgr.ui, UpdateUi::Applying, "must not clobber an in-flight job");
    }

    /// The automatic updater and the manual one share a channel but MUST NOT
    /// share state: a background auto result arriving while the user is running
    /// a manual check must not hijack the panel they are looking at.
    #[test]
    fn an_auto_note_never_clobbers_the_manual_updater_state() {
        let mut mgr = UpdateManager {
            ui: UpdateUi::Checking,
            ..Default::default()
        };
        mgr.tx.send(Msg::Auto("held: soaking".into())).unwrap();
        mgr.poll();
        assert_eq!(mgr.ui, UpdateUi::Checking, "manual state is untouched");
        assert_eq!(mgr.auto_note.as_deref(), Some("held: soaking"));
    }

    /// The periodic automatic check is a no-op until it is due; the launch-time
    /// call is the only one that forces it. Without this a busy UI loop would
    /// hammer the release channel once per frame.
    #[test]
    fn periodic_auto_check_does_not_fire_before_it_is_due() {
        let mut mgr = UpdateManager::default();
        // Never checked yet: the un-forced path must NOT decide "overdue" and fire.
        mgr.auto_check(false);
        assert!(mgr.last_auto_check.is_none(), "unforced first call must not check");
    }

    /// Leaving the mining state resets the session accounting, so a fresh session
    /// starts its own 20-minute clock rather than inheriting a stale one.
    #[test]
    fn leaving_the_mining_state_resets_the_session_clock() {
        let mut mgr = UpdateManager {
            session_start: Some(std::time::Instant::now()),
            judged_this_session: true,
            ..Default::default()
        };
        mgr.note_mining(None);
        assert!(mgr.session_start.is_none());
        assert!(!mgr.judged_this_session);
    }

    /// F4: a HALTED lane must not refresh the "this machine is earning" baseline.
    /// The acceptance guard freezes the accepted counter when it stops a lane, so
    /// a halted rig would otherwise keep re-marking itself productive forever off
    /// a number that stopped moving days ago — and that mark is precisely what
    /// arms the rollback for the NEXT update.
    #[test]
    fn a_halted_lane_does_not_refresh_the_earning_baseline() {
        use alice_miner_core::autoupdate::MiningEvidence;
        let mut mgr = UpdateManager::default();

        // Not mining at all: nothing to mark, session accounting reset.
        mgr.note_mining(None);
        assert!(mgr.last_productive_mark.is_none());

        let mut snap = running_snapshot();
        snap.shares_accepted = 12;
        assert!(
            MiningEvidence::from_snapshot(&snap).counts_as_earning(),
            "a running lane with accepted shares is the baseline"
        );
        // The same counter, behind a halt, is not.
        snap.lanes = vec![halted_lane_row()];
        assert!(!MiningEvidence::from_snapshot(&snap).counts_as_earning());
        mgr.note_mining(Some(&snap));
        assert!(
            mgr.last_productive_mark.is_none(),
            "a halted lane must not stamp the productive mark"
        );
    }

    fn running_snapshot() -> alice_miner_core::engine::Snapshot {
        alice_miner_core::engine::Snapshot {
            state: alice_miner_core::EngineState::Running,
            device: None,
            lane: Some(alice_miner_core::Lane::GpuPrl),
            hashrate_hs: Some(8400.0),
            hashrate_60s_hs: None,
            hashrate_15m_hs: None,
            shares_accepted: 0,
            shares_rejected: 0,
            endpoint: None,
            worker_id: None,
            uptime_s: 5,
            failovers: 0,
            temp_c: None,
            power_w: None,
            util_pct: None,
            fan_pct: None,
            dual: false,
            lanes: Vec::new(),
            last_line: None,
            message: None,
            message_key: None,
            message_args: None,
            prl_payout: None,
        }
    }

    fn halted_lane_row() -> alice_miner_core::engine::LaneSnapshot {
        alice_miner_core::engine::LaneSnapshot {
            lane: alice_miner_core::Lane::GpuPrl,
            state: alice_miner_core::EngineState::Error,
            hashrate_hs: None,
            hashrate_60s_hs: None,
            hashrate_15m_hs: None,
            shares_accepted: 12,
            shares_rejected: 400,
            uptime_s: 3600,
            endpoint: None,
            failovers: 0,
            temp_c: None,
            power_w: None,
            util_pct: None,
            fan_pct: None,
            acceptance: "collapsed".to_string(),
            accept_pct: Some(0.0),
            halted: true,
            activity: alice_miner_core::acceptance::GuardCustody::Halted,
        }
    }

    /// The busy flag drives the disabled-button state.
    #[test]
    fn is_busy_reflects_in_flight_states() {
        assert!(UpdateUi::Checking.is_busy());
        assert!(UpdateUi::Applying.is_busy());
        assert!(!UpdateUi::Idle.is_busy());
        assert!(!UpdateUi::UpToDate { current: "x".into() }.is_busy());
    }

    // ── F1: the GUI's "Update now" runs the SAME guardrails ──────────────────

    fn offered(version: &str) -> UpdateUi {
        let m = manifest_with(version, "0.0.1", true);
        let artifact = m.artifacts[0].clone();
        UpdateUi::Available {
            current: "0.1.0".into(),
            version: version.to_string(),
            notes: m.notes.clone(),
            visibility: None,
            risk: None,
            manifest: Box::new(m),
            artifact,
        }
    }

    fn check(outcome: alice_miner_core::autoupdate::ManualOutcome) -> alice_miner_core::autoupdate::ManualCheck {
        alice_miner_core::autoupdate::ManualCheck {
            outcome,
            visibility: Some("seen for 3 days".into()),
            visible_for_s: 3 * 24 * 3600,
            inside_soak: false,
        }
    }

    /// A refusal from the shared driver replaces the offer entirely. There is no
    /// "Update now" button in the `Refused` state on purpose: a refusal is not a
    /// confirmation dialog with its buttons rearranged.
    ///
    /// Before this, the GUI's manual path ran NONE of these checks — it went from
    /// a verified manifest straight to a download, past the seen ledger, past the
    /// hash-conflict refusal and past the failure pin. The CLI had (some of) them
    /// and the GUI had none, which is the same shape as AM-REL-009.
    #[test]
    fn a_refusal_from_the_shared_driver_removes_the_update_button() {
        use alice_miner_core::autoupdate::ManualOutcome;
        let ui = with_gate(
            offered("99.0.0"),
            check(ManualOutcome::Refuse {
                message: "REFUSED: the bytes changed".into(),
            }),
        );
        match ui {
            UpdateUi::Refused { version, message } => {
                assert_eq!(version, "99.0.0");
                assert!(message.contains("REFUSED"));
            }
            other => panic!("expected Refused, got {other:?}"),
        }
        // A refusal is something the user needs to see without digging.
        assert!(UpdateUi::Refused {
            version: "99.0.0".into(),
            message: "m".into()
        }
        .wants_attention());
    }

    /// A concern turns the ordinary offer into an explicit one: the panel names
    /// what is wrong and the button becomes "Install anyway".
    #[test]
    fn a_concern_from_the_shared_driver_becomes_an_explicit_second_question() {
        use alice_miner_core::autoupdate::ManualOutcome;
        match with_gate(
            offered("99.0.0"),
            check(ManualOutcome::Confirm {
                message: "this machine rolled it back before".into(),
            }),
        ) {
            UpdateUi::Available { risk, visibility, .. } => {
                assert_eq!(risk.as_deref(), Some("this machine rolled it back before"));
                assert_eq!(visibility.as_deref(), Some("seen for 3 days"));
            }
            other => panic!("expected Available with a risk, got {other:?}"),
        }
    }

    /// A clean version is offered normally — and still carries the visibility
    /// line, so a manual install is made with the same facts the automatic path
    /// decides on.
    #[test]
    fn a_clean_version_is_offered_with_its_visibility_stated() {
        use alice_miner_core::autoupdate::ManualOutcome;
        match with_gate(offered("99.0.0"), check(ManualOutcome::Proceed)) {
            UpdateUi::Available { risk, visibility, .. } => {
                assert_eq!(risk, None);
                assert_eq!(visibility.as_deref(), Some("seen for 3 days"));
            }
            other => panic!("expected a plain offer, got {other:?}"),
        }
    }

    /// The gate only ever rewrites an `Available` state; every other state
    /// passes through untouched (there is nothing to install from them).
    #[test]
    fn the_gate_leaves_non_offer_states_alone() {
        use alice_miner_core::autoupdate::ManualOutcome;
        let ui = UpdateUi::UpToDate { current: "1.0.0".into() };
        assert_eq!(
            with_gate(ui.clone(), check(ManualOutcome::Refuse { message: "x".into() })),
            ui,
            "a refusal about nothing must not invent a Refused state"
        );
    }

    /// The wiring itself, not a stand-in for it: the conversion `check` actually
    /// calls, driven against the REAL shared driver and a real (temporary)
    /// `~/.alice`. The three tests above pin what the GUI does with a verdict;
    /// this one pins that a state reaching the UI has been through the
    /// guardrails at all, which is the half that was missing — the GUI's manual
    /// path went from a verified manifest straight to a download.
    ///
    /// `$ALICE_IDENTITY_DIR` is a process global, so this holds the crate-wide
    /// env lock; without it a parallel test could restore the variable mid-run
    /// and this would write into the developer's real `~/.alice`.
    #[test]
    fn a_checked_state_reaches_the_ui_already_through_the_guardrails() {
        let _g = crate::ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("ALICE_IDENTITY_DIR").ok();
        let dir = std::env::temp_dir().join(format!(
            "alice-gui-gate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("ALICE_IDENTITY_DIR", &dir);

        // A clean offer survives — and comes back carrying the visibility line,
        // which only the shared driver can produce.
        let clean = outcome_to_ui(release::evaluate(manifest_with("99.0.0", "0.0.1", true), "0.1.0"));
        let clean_ok =
            matches!(&clean, UpdateUi::Available { visibility: Some(_), risk: None, .. });

        // Now teach this machine that 98.0.0 carried different bytes than the
        // ones about to be offered for it, and that offer must come back
        // refused. (A different version number, because the ledger is
        // append-only: the sighting the clean case just recorded is final.)
        alice_miner_core::alice_release::auto::note_seen(&dir, "98.0.0", &"bb".repeat(32));
        let conflicted =
            outcome_to_ui(release::evaluate(manifest_with("98.0.0", "0.0.1", true), "0.1.0"));
        let refused = matches!(&conflicted, UpdateUi::Refused { .. });

        // The unguarded mapping is the control: same input, and it hands back an
        // installable offer. That is what `check` used to do.
        let ungated = map_outcome(release::evaluate(manifest_with("98.0.0", "0.0.1", true), "0.1.0"));
        let ungated_offers = matches!(&ungated, UpdateUi::Available { .. });

        match prev {
            Some(v) => std::env::set_var("ALICE_IDENTITY_DIR", v),
            None => std::env::remove_var("ALICE_IDENTITY_DIR"),
        }
        let _ = std::fs::remove_dir_all(&dir);

        assert!(clean_ok, "a clean offer must survive and carry visibility: {clean:?}");
        assert!(
            refused,
            "a re-published version must be refused in the GUI too: {conflicted:?}"
        );
        assert!(
            ungated_offers,
            "the control must show the refusal came from the gate: {ungated:?}"
        );
    }
}
