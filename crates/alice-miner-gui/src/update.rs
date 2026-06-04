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
        manifest: Box<Manifest>,
        artifact: Artifact,
    },
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
}

/// A message from a background updater job back to the UI thread.
enum Msg {
    /// A completed check. The (large) [`CheckOutcome`] is boxed to keep the enum
    /// small (it can carry a full manifest).
    Checked(Box<CheckOutcome>),
    CheckFailed(String),
    Applied(String),
    ApplyFailed(String),
}

/// Owns the updater state + the channel to its background worker. One per app.
pub struct UpdateManager {
    pub ui: UpdateUi,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
}

impl Default for UpdateManager {
    fn default() -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        Self {
            ui: UpdateUi::Idle,
            tx,
            rx,
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

    /// Drain any completed background results into [`Self::ui`]. Call once per
    /// frame from the app's update loop (cheap; non-blocking).
    pub fn poll(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::Checked(outcome) => self.ui = outcome_to_ui(*outcome),
                Msg::CheckFailed(m) => self.ui = UpdateUi::Failed { message: m },
                Msg::Applied(version) => self.ui = UpdateUi::Applied { version },
                Msg::ApplyFailed(m) => self.ui = UpdateUi::Failed { message: m },
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
                Ok(outcome) => Msg::Checked(Box::new(outcome)),
                Err(e) => Msg::CheckFailed(e.to_string()),
            };
            let _ = tx.send(msg);
        });
    }

    /// Apply the currently-`Available` update (download → verify → atomic swap →
    /// arm health gate). No-op unless the UI is in the `Available` state. The
    /// artifact is re-verified (size + SHA-256) before anything is written, and
    /// the swap can never touch the keystore (`assert_not_in_data_dir`).
    pub fn apply(&mut self) {
        let (manifest, artifact) = match &self.ui {
            UpdateUi::Available {
                manifest, artifact, ..
            } => (manifest.clone(), artifact.clone()),
            _ => return,
        };
        self.ui = UpdateUi::Applying;
        let tx = self.tx.clone();
        thread::spawn(move || {
            let msg = match apply_pipeline(&manifest, &artifact) {
                Ok(version) => Msg::Applied(version),
                Err(e) => Msg::ApplyFailed(e),
            };
            let _ = tx.send(msg);
        });
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

/// Map a verified [`CheckOutcome`] onto the UI state.
fn outcome_to_ui(outcome: CheckOutcome) -> UpdateUi {
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
        }
    }

    /// A VERIFIED, strictly-newer manifest with an artifact for this platform is
    /// surfaced as `Available` (the "update offered" path).
    #[test]
    fn newer_manifest_with_artifact_is_offered() {
        let m = manifest_with("99.0.0", "0.0.1", true);
        let ui = outcome_to_ui(release::evaluate(m, "0.1.0"));
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
        let ui = outcome_to_ui(release::evaluate(m, "0.1.0"));
        assert!(matches!(ui, UpdateUi::AvailableNoArtifact { .. }));
    }

    /// A DOWNGRADE (manifest older than current) is NOT offered — strict
    /// no-downgrade. `evaluate` reports UpToDate, which we render as such.
    #[test]
    fn downgrade_manifest_is_rejected_as_up_to_date() {
        let m = manifest_with("0.0.1", "0.0.1", true);
        let ui = outcome_to_ui(release::evaluate(m, "9.9.9"));
        assert!(matches!(ui, UpdateUi::UpToDate { .. }), "got {ui:?}");
    }

    /// An EQUAL version is not newer (no-downgrade boundary) → UpToDate.
    #[test]
    fn equal_version_is_up_to_date() {
        let m = manifest_with("1.2.3", "0.0.1", true);
        let ui = outcome_to_ui(release::evaluate(m, "1.2.3"));
        assert!(matches!(ui, UpdateUi::UpToDate { .. }));
    }

    /// Running below `min_supported` is surfaced as a hard `Unsupported` notice.
    #[test]
    fn below_min_supported_is_unsupported() {
        let m = manifest_with("99.0.0", "2.0.0", true);
        let ui = outcome_to_ui(release::evaluate(m, "1.0.0"));
        match ui {
            UpdateUi::Unsupported { min_supported, .. } => assert_eq!(min_supported, "2.0.0"),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    /// A WRONG-PRODUCT manifest (the Wallet's) signed by the same key is rejected
    /// at parse time — proving the cross-product guard the GUI relies on. (We test
    /// the parse guard directly since `outcome_to_ui` only ever sees a verified,
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
        let mut mgr = UpdateManager::default();
        mgr.ui = UpdateUi::UpToDate {
            current: "1.0.0".into(),
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
        let mut mgr = UpdateManager::default();
        mgr.ui = UpdateUi::Applying;
        mgr.check();
        assert_eq!(mgr.ui, UpdateUi::Applying, "must not clobber an in-flight job");
    }

    /// The busy flag drives the disabled-button state.
    #[test]
    fn is_busy_reflects_in_flight_states() {
        assert!(UpdateUi::Checking.is_busy());
        assert!(UpdateUi::Applying.is_busy());
        assert!(!UpdateUi::Idle.is_busy());
        assert!(!UpdateUi::UpToDate { current: "x".into() }.is_busy());
    }
}
