//! The Alice Miner application state + engine wiring.
//!
//! Drives the UI-agnostic [`alice_miner_core`] engine over its
//! `Command`/`Event` channel (the SAME engine the CLI drives — PLAN §2.2). On
//! launch it sends `Detect`; every frame it drains `Event`s, keeps the latest
//! credit-only [`Snapshot`], and (while mining) requests a repaint so the hero
//! gauge + readout animate. Start sends `Start{Xmr}`; Stop sends `Stop`.

use std::collections::VecDeque;
use std::time::Instant;

use alice_miner_core::engine::{Command, EngineHandle, Event, IdentitySpec, Snapshot};
use alice_miner_core::identity::{self, IdentityPointer};
use alice_miner_core::{
    CreditState, DashboardModel, DeviceProfile, EngineState, GpuSelection, Identity, Lane,
    LaneSupport, LaneViability, LocalActivity, PoolStatsClient, Reconciliation,
};
use eframe::egui::{self, TextureHandle};

use crate::ui;

/// Which top-level screen is showing.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Home,
    Dashboard,
    Settings,
}

/// The post-onboarding "change reward address" overlay. Reachable from Settings
/// (Identity section) and the Home "Rewards to <addr>" edit affordance once an
/// identity already exists. It offers the SAME three paths onboarding uses
/// (create / import / paste) and drives the exact same `alice-miner-core`
/// identity functions — but as a modal over Home/Settings (NOT the full-screen
/// onboarding takeover), and only when NOT mining. Create/Import gain an explicit
/// overwrite-confirm step first (the existing keystore is backed up before being
/// replaced); Paste is watch-only and never touches the keystore.
// No PartialEq/Eq: the mnemonic field is a `Zeroizing<String>` (zeroizes every
// dropped copy, incl. the egui per-frame clones) which doesn't impl PartialEq,
// and the enum is only ever `matches!`-ed, never compared with `==`.
#[derive(Clone)]
pub enum ChangeAddr {
    /// The launcher: pick create / import / paste, with the current address shown.
    Choose,
    /// Create-new OVERWRITE gate: warn that this REPLACES + backs up the current
    /// keystore before we generate. Carries the `.bak-…` path we'll move the old
    /// keystore to (when one exists) so the warning can name it. "Continue"
    /// advances to [`ChangeAddr::CreateForm`].
    ConfirmCreate { backup_hint: Option<String> },
    /// The create password form (shown after the overwrite warning is accepted).
    CreateForm,
    /// After a create commits: the 24-word phrase for the forced-backup step.
    Backup { mnemonic: zeroize::Zeroizing<String>, acknowledged: bool },
    /// Confirm the new phrase by re-picking 3 words (reuses the onboarding logic).
    Confirm { mnemonic: zeroize::Zeroizing<String> },
    /// Import a different mnemonic / seed. The overwrite warning is recapped inline
    /// (Import also replaces + backs up the keystore).
    Import { backup_hint: Option<String> },
    /// Paste a different address (watch-only). Preserves the existing keystore.
    Paste,
}

/// The GPU-PRL **unlock-password** modal state. The GPU-PRL lane signs a
/// proof-of-possession with the wallet key, so it needs the keystore password to
/// start (XMR/RVN are address-only and never raise this). `Some` while the prompt
/// is open; it carries the captured password (masked in the UI, zeroized the
/// instant Start is sent or the modal is cancelled) and the exact lane/dual the
/// user asked to start so confirm can replay it verbatim. Only ever opened for a
/// keystore-backed identity — a watch-only paste can't sign a PoP and is refused
/// up-front with a clear message (no modal).
#[derive(Clone)]
pub struct PrlUnlock {
    /// The masked password the user is typing (cleared+zeroized on confirm/cancel).
    pub password: String,
    /// The lane the user asked to start (always [`Lane::GpuPrl`] in practice; kept
    /// so confirm replays the exact request the engine would have received).
    pub lane: Lane,
    /// Whether the user asked for dual-mine — replayed verbatim into Start.
    pub dual: bool,
}

/// Onboarding sub-flow (only reachable when there is no `~/.alice/identity.json`).
// No PartialEq/Eq — see ChangeAddr above (mnemonic is `Zeroizing<String>`).
#[derive(Clone)]
pub enum Onboarding {
    /// Pick: create new / import / paste address.
    Choose,
    /// Created: show the 24-word mnemonic for the forced-backup step.
    Backup { mnemonic: zeroize::Zeroizing<String>, acknowledged: bool },
    /// Confirm the backup by re-picking 3 random words (PLAN §4 — the deliberate
    /// divergence from the Wallet). Carries the mnemonic so a wrong pick can be
    /// re-prompted without regenerating.
    Confirm { mnemonic: zeroize::Zeroizing<String> },
    /// Import an existing mnemonic or seed.
    Import,
    /// Paste an address (watch-only).
    Paste,
}

/// The application.
pub struct MinerApp {
    pub engine: EngineHandle,
    /// Latest engine snapshot (the live mining state). `None` before the first.
    pub snapshot: Option<Snapshot>,
    /// Detected device (model string line). Filled by the `Detect` reply.
    pub device: Option<DeviceProfile>,
    /// The lane-viability matrix for the detected device (which lanes are
    /// runnable / coming-soon / unavailable). `None` until `Detect` replies.
    pub viability: Option<LaneViability>,
    /// The lane the user has selected to mine. Defaults to the recommended lane
    /// once the device is known (RVN on NVIDIA, else XMR); the user can switch it
    /// via the Home "change lane" affordance (only to a runnable lane).
    pub selected_lane: Lane,
    /// Whether the user has manually picked a lane (so we stop auto-defaulting to
    /// the recommended one when a fresh `Detect` lands).
    pub lane_user_picked: bool,
    /// Whether the user has turned the dual-mine toggle ON (run BOTH lanes). Only
    /// honoured when [`MinerApp::dual_viable`] (≥2 viable lanes); the toggle is
    /// rendered disabled otherwise. Default OFF (PLAN §5 M4 / D-dual).
    pub dual_requested: bool,
    /// Whether the dual-mine "heat / fan" confirmation has been shown+accepted for
    /// the current enable (a brief acknowledgement that dual-mine pushes the
    /// device harder). Resets when dual is turned off.
    pub dual_confirm_open: bool,
    /// The active reward identity pointer (address etc.), if one exists.
    pub identity: Option<IdentityPointer>,
    /// The active screen.
    pub screen: Screen,
    /// `Some` while onboarding (no identity yet, or user chose to add one).
    pub onboarding: Option<Onboarding>,
    /// `Some` while the post-onboarding "change reward address" modal is open
    /// (reachable from Settings + the Home edit affordance once an identity
    /// exists). Mutually exclusive with `onboarding` in practice (onboarding only
    /// runs when there is no identity; the change flow only when there IS one).
    pub change_addr: Option<ChangeAddr>,

    /// `Some` while the GPU-PRL unlock-password prompt is open (the PRL lane needs
    /// the wallet key to sign a proof-of-possession). Holds the captured password
    /// (masked + zeroized on confirm/cancel) and the lane/dual to replay. `None`
    /// for every non-PRL start (XMR/RVN never raise this).
    pub prl_unlock: Option<PrlUnlock>,

    /// The simple per-GPU **selection** checkbox state (A5c). One `bool` per
    /// enumerated card (parallel to `device.gpu.gpus`, by position) — `true` =
    /// checked = include that card. Kept in sync with the detected GPU list by
    /// [`MinerApp::sync_gpu_selection`]; reset to "all checked" whenever the GPU
    /// list changes (a fresh `Detect` / device swap), so the default is always
    /// **All cards** and the start argv stays byte-identical to pre-A5c unless the
    /// user actively unchecks a card. Only rendered when ≥2 GPUs are enumerated AND
    /// a GPU lane is selected (single-GPU / no-list machines never see the control
    /// and always run All). It NEVER carries an address/secret — pure indices.
    pub gpu_selected: Vec<bool>,

    /// The Alice mark texture — a WHITE / alpha mask (rasterised once from the
    /// bundled SVG), tinted to the brand colour at each draw site. See
    /// [`MinerApp::mark_texture`].
    pub mark_tex: Option<TextureHandle>,

    // ── Onboarding form state ────────────────────────────────────────────────
    pub form_password: String,
    pub form_password2: String,
    pub form_mnemonic: String,
    pub form_seed: String,
    pub form_address: String,
    pub form_use_seed: bool,

    // ── Animation / display state ────────────────────────────────────────────
    /// Smoothed hashrate (kH/s) the readout shows — tweened toward the snapshot.
    pub hr_display_khs: f32,
    /// Ring buffer of recent hashrate samples (kH/s) for the dashboard sparkline.
    pub spark: VecDeque<f32>,
    /// Rolling log tail (sanitised last-lines from the engine).
    pub log: VecDeque<String>,
    /// Soft ceiling used to scale the gauge (auto-adapts to the observed max).
    pub gauge_ceiling_khs: f32,

    // ── Transient UI feedback ────────────────────────────────────────────────
    pub error: Option<String>,
    pub last_spark_push: Option<Instant>,
    pub copied_at: Option<Instant>,
    /// Language toggle (display-only; copy is bilingual already).
    pub lang_zh: bool,
    /// Reduced-motion setting (Settings · Appearance). When on, the breathing
    /// glow / gauge sweep / number tween are disabled but the colour + state
    /// semantics are KEPT, so the app stays legible + calm for motion-sensitive
    /// users (PLAN §4, doc 06 §4/§12). egui 0.34 does not surface the OS
    /// `prefers-reduced-motion` hint, so this is an explicit in-app toggle.
    pub reduce_motion: bool,

    // ── Onboarding · confirm-by-retyping (forced-backup divergence, PLAN §4) ──
    /// The 3 positions (1-based word indices) the user must re-pick to confirm.
    pub confirm_targets: Vec<usize>,
    /// The shuffled word pool shown as tappable chips during confirm.
    pub confirm_pool: Vec<String>,
    /// The word the user has chosen for each target slot (`None` = empty).
    pub confirm_filled: Vec<Option<String>>,

    // ── Source B — server-confirmed credit (M5) ──────────────────────────────
    /// The Source-B credit poller (poll discipline + source config). v1 is the
    /// `NotExposed` configuration (no reachable public per-address endpoint today
    /// — see [`alice_miner_core::dashboard`]), so it never touches the network; it
    /// just yields the honest `NotExposed` panel. The fast-follow to a live
    /// public read-model endpoint is a one-line config flip here.
    pub credit_client: PoolStatsClient,
    /// The latest server-confirmed credit state (Source B), kept separate from the
    /// live local activity (Source A) so the UI never blurs the two.
    pub credit_state: CreditState,

    /// Headless screenshot-mode driver. `None` on every normal run; `Some` only
    /// when `ALICE_MINER_SHOT_DIR` is set (see [`crate::shot`]). When set, the
    /// `ui()` loop is driven by the shot state machine instead of the engine.
    pub shot: Option<crate::shot::ShotRunner>,

    /// The signed self-updater (ed25519 + SHA-256, last-known-good rollback).
    /// Auto-CHECKS once at launch (notify-only; surfaces availability in the
    /// chrome/Settings) and can be re-checked from Settings → "Check for
    /// updates". It NEVER silent-applies — the user clicks Apply. See
    /// [`crate::update`].
    pub updater: crate::update::UpdateManager,
    /// A one-time "updated to vX" note set when the health gate confirmed a
    /// freshly-applied build at startup. Shown once in Settings, then cleared.
    pub update_committed_note: Option<String>,
    /// Guards the one-shot launch-time update check so it fires exactly once
    /// (on the first real `ui()` frame, never in screenshot mode). Without a
    /// launch check the user only learned of a new build by manually opening
    /// Settings — the v0.3.1 "didn't know it could update" report.
    pub launch_update_checked: bool,
    /// Cached background-mining service state (launchd), queried lazily when the
    /// Settings panel opens and after a toggle — querying spawns `launchctl`, so
    /// we never do it per-frame. `None` = not yet queried this session.
    pub bg_service: Option<alice_miner_core::service::ServiceState>,
    /// Last error from a background-mining enable/disable, shown inline.
    pub bg_service_error: Option<String>,
}

impl MinerApp {
    pub fn new() -> Result<Self, String> {
        let engine = EngineHandle::spawn()?;
        // Kick off device detection immediately (PLAN: Detect on launch).
        engine.send(Command::Detect)?;
        let identity = identity::load_pointer();
        // Resolve the first-launch update health gate ONCE, early — commit a
        // freshly-applied build (drop last-known-good) or roll back a crash-loop.
        // Skipped in screenshot mode so captures stay byte-for-byte unchanged.
        let shot = crate::shot::ShotRunner::from_env();
        let update_committed_note = if shot.is_none() {
            crate::update::UpdateManager::register_launch_at_startup()
        } else {
            None
        };
        // No identity on disk → start in onboarding.
        let onboarding = if identity.is_none() {
            Some(Onboarding::Choose)
        } else {
            None
        };
        Ok(Self {
            engine,
            snapshot: None,
            device: None,
            viability: None,
            // Sensible default before detection lands; recomputed to the
            // recommended lane when the device arrives (unless the user picked).
            selected_lane: Lane::Xmr,
            lane_user_picked: false,
            dual_requested: false,
            dual_confirm_open: false,
            identity,
            screen: Screen::Home,
            onboarding,
            change_addr: None,
            prl_unlock: None,
            gpu_selected: Vec::new(),
            mark_tex: None,
            form_password: String::new(),
            form_password2: String::new(),
            form_mnemonic: String::new(),
            form_seed: String::new(),
            form_address: String::new(),
            form_use_seed: false,
            hr_display_khs: 0.0,
            spark: VecDeque::with_capacity(40),
            log: VecDeque::with_capacity(64),
            gauge_ceiling_khs: 1.0,
            error: None,
            last_spark_push: None,
            copied_at: None,
            lang_zh: false,
            reduce_motion: false,
            confirm_targets: Vec::new(),
            confirm_pool: Vec::new(),
            confirm_filled: Vec::new(),
            // Source B v1: the investigated reality is that no reachable public
            // per-address credit endpoint exists, so the poller is `NotExposed`
            // (no network, honest panel). See `alice_miner_core::dashboard`.
            credit_client: PoolStatsClient::not_exposed(),
            credit_state: CreditState::NotExposed,
            shot,
            updater: crate::update::UpdateManager::default(),
            update_committed_note,
            launch_update_checked: false,
            bg_service: None,
            bg_service_error: None,
        })
    }

    /// Lazily query + cache the background-mining service state. Spawns
    /// `launchctl`, so call only on demand (Settings open / after a toggle), not
    /// every frame.
    pub fn refresh_bg_service(&mut self) {
        self.bg_service = Some(alice_miner_core::service::status());
    }

    /// The headless miner CLI bundled next to this GUI executable
    /// (`Contents/MacOS/alice-miner-cli`), if present. The launchd agent runs it.
    fn bundled_cli_path(&self) -> Option<std::path::PathBuf> {
        let exe = std::env::current_exe().ok()?;
        let dir = exe.parent()?;
        let name = if cfg!(windows) { "alice-miner-cli.exe" } else { "alice-miner-cli" };
        let cli = dir.join(name);
        cli.is_file().then_some(cli)
    }

    /// Enable background mining: install the launchd agent for the CPU-XMR lane
    /// (start at login). Stops the foreground miner first so there is a single
    /// owner (no double-mining to the same address). Refreshes the cached state.
    pub fn enable_bg_service(&mut self) {
        use alice_miner_core::service::{self, ServiceSpec};
        self.bg_service_error = None;
        let Some(cli) = self.bundled_cli_path() else {
            self.bg_service_error = Some(
                "the bundled miner CLI wasn't found next to the app — reinstall Alice Miner."
                    .into(),
            );
            return;
        };
        // Single owner: stop foreground mining so the agent doesn't double-mine.
        let _ = self.engine.send(Command::Stop);
        let spec = ServiceSpec { lane: Lane::Xmr, cli_path: cli, run_at_login: true };
        if let Err(e) = service::install(&spec) {
            self.bg_service_error = Some(e);
        }
        self.refresh_bg_service();
    }

    /// Disable background mining: stop + remove the launchd agent.
    pub fn disable_bg_service(&mut self) {
        self.bg_service_error = None;
        if let Err(e) = alice_miner_core::service::uninstall() {
            self.bg_service_error = Some(e);
        }
        self.refresh_bg_service();
    }

    /// Source-B credit tick (called each frame). The credit state is sourced from
    /// the [`PoolStatsClient`], which in the v1 `NotExposed` configuration performs
    /// **no network I/O** (it just yields `NotExposed`). When the fast-follow flips
    /// `credit_client` to a live public read-model endpoint, this is where the
    /// poll-due / single-flight / backoff logic would drive an actual GET; the
    /// `polls_network()` guard keeps v1 a pure, server-independent no-op.
    ///
    /// Crucially this NEVER computes an estimated/projected reward (the #18
    /// red-team trap) — it only reflects what the server has CONFIRMED.
    pub fn tick_credit(&mut self) {
        if !self.credit_client.polls_network() {
            // v1: no reachable public per-address endpoint → the honest panel.
            self.credit_state = self.credit_client.state();
            return;
        }
        // (Fast-follow path — inert in v1.) A real implementation would check
        // `next_poll_in_secs` against a timer, `begin_poll()` (single-flight), fire
        // the GET on the worker, and feed the body to `complete()` / `fail()`. Here
        // we simply surface the client's last-known state so the UI stays in sync.
        self.credit_state = self.credit_client.state();
    }

    /// Build the M5 [`DashboardModel`] for the current frame: Source A (live local
    /// activity, from the latest snapshot) + Source B (server-confirmed credit) +
    /// the qualitative reconciliation badge. Used by the dashboard UI; never
    /// performs a reward projection (the #18 red-team trap).
    pub fn dashboard_model(&self) -> DashboardModel {
        let activity = self
            .snapshot
            .as_ref()
            .map(LocalActivity::from_snapshot)
            .unwrap_or_else(LocalActivity::idle);
        DashboardModel::new(activity, self.credit_state.clone())
    }

    /// The qualitative reconciliation badge (Source A vs Source B) for the current
    /// frame.
    pub fn reconciliation(&self) -> Reconciliation {
        self.dashboard_model().reconciliation
    }

    /// Whether motion (breathing glow, gauge sweep, number tween, blinking dots)
    /// is enabled. `false` when the user turned on reduced motion.
    pub fn motion_enabled(&self) -> bool {
        !self.reduce_motion
    }

    /// Make the UI **scale proportionally with the window** so content always
    /// fills a consistent fraction of the frame — never a tiny card floating in a
    /// black void on a big monitor, and never cramped on a small one.
    ///
    /// egui composes `pixels_per_point = zoom_factor × native_pixels_per_point`,
    /// so we drive the **zoom factor** (and let egui fold in the OS DPI itself).
    /// The window's true size in native-DPI points is `inner_width_points ×
    /// current_zoom` (independent of the zoom we're about to set), so the target
    /// zoom is a one-step fixed point:
    ///
    /// ```text
    /// zoom = clamp(window_logical_width / REFERENCE_W, MIN, MAX)
    /// ```
    ///
    /// with `REFERENCE_W = 1120` (the design/default width → zoom 1.0). Clamped to
    /// [0.9, 1.5] so text stays legible at the 960 floor and doesn't get cartoonish
    /// at 1600+. Applied every frame; egui only rebuilds layout when it changes.
    pub fn apply_window_scaling(&self, ctx: &egui::Context) {
        /// The design reference width (points). At this window width the UI renders
        /// at its natural 1.0 zoom; wider scales up, narrower scales down.
        const REFERENCE_W: f32 = 1120.0;
        const MIN_ZOOM: f32 = 0.9;
        const MAX_ZOOM: f32 = 1.5;

        // `content_rect` is the content area in points at the CURRENT ppp; the
        // window's true width in native-DPI points is therefore width × zoom
        // (zoom-independent). Robust headless too (no `inner_rect` needed).
        let content_w_pts = ctx.input(|i| i.content_rect().width());
        let cur_zoom = ctx.zoom_factor();
        let logical_w = content_w_pts * cur_zoom;
        if logical_w <= 1.0 {
            return; // not yet known (first frame); keep current zoom
        }
        let target = (logical_w / REFERENCE_W).clamp(MIN_ZOOM, MAX_ZOOM);
        // Only nudge when it actually moved (avoid churn / repaint storms).
        if (target - cur_zoom).abs() > 0.005 {
            ctx.set_zoom_factor(target);
        }
    }

    /// Lazily load (and cache) the Alice mark texture as a **WHITE / alpha mask**
    /// (the brand-orange source artwork rasterised then whitened — see
    /// [`ui::theme::alice_mark_mask`]). Every call site tints it with the exact
    /// brand colour for its state, so the mark is always brand-orange (white·tint
    /// = tint) and never the orange×orange = RED bug. Rendered at a generous 256px
    /// so it stays crisp at any UI scale / high-DPI.
    pub fn mark_texture(&mut self, ctx: &egui::Context) -> TextureHandle {
        if let Some(t) = &self.mark_tex {
            return t.clone();
        }
        let color = ui::theme::alice_mark_mask(256);
        let tex = ctx.load_texture("alice-mark", color, egui::TextureOptions::LINEAR);
        self.mark_tex = Some(tex.clone());
        tex
    }

    /// Drain all pending engine events into local state.
    pub fn drain_events(&mut self) {
        while let Some(evt) = self.engine.try_recv() {
            match evt {
                Event::Device(p) => self.set_device(p),
                Event::Identity { identity, mnemonic } => self.on_identity(identity, mnemonic),
                Event::Snapshot(s) => self.on_snapshot(s),
                Event::Error(e) => self.error = Some(e),
            }
        }
    }

    /// Record the detected device, derive its lane-viability matrix, and (unless
    /// the user has manually picked) default the selected lane to the recommended
    /// one. The override-applied capability bundle is used so an operator
    /// `ALICE_MINER_LANES` env restriction is honoured in the UI too.
    pub fn set_device(&mut self, p: DeviceProfile) {
        let cap = alice_miner_core::CapabilityProfile::from_profile(p.clone());
        if !self.lane_user_picked {
            self.selected_lane = cap.recommended_lane();
        }
        self.viability = Some(cap.viability);
        self.device = Some(p);
        // Re-sync the per-GPU selection to the (possibly new) enumerated card list.
        self.sync_gpu_selection();
    }

    /// The enumerated GPU devices for the detected machine (one entry per physical
    /// card). Empty when no device is known yet, or when per-GPU enumeration is
    /// unavailable (non-NVIDIA / single-summary / probe failure — see
    /// [`alice_miner_core::detect::GpuInfo::gpus`]). The multi-GPU picker keys off
    /// this list.
    pub fn gpu_devices(&self) -> &[alice_miner_core::detect::GpuDevice] {
        self.device.as_ref().map(|d| d.gpu.gpus.as_slice()).unwrap_or(&[])
    }

    /// Re-shape [`MinerApp::gpu_selected`] to match the current enumerated GPU
    /// list. When the list's LENGTH changed (a fresh device / first detect / a
    /// hot-plug), we reset to **all cards checked** — the honest default that keeps
    /// the start argv byte-identical to "use every card". When the length is the
    /// same we leave the user's existing checks untouched (a re-detect of the same
    /// machine must not silently clobber a deliberate selection). Idempotent.
    pub fn sync_gpu_selection(&mut self) {
        let n = self.gpu_devices().len();
        if self.gpu_selected.len() != n {
            self.gpu_selected = vec![true; n];
        }
    }

    /// Whether the simple multi-GPU picker should be SHOWN: only when ≥2 cards are
    /// enumerated AND a GPU lane is selected. A single GPU / no enumeration / a
    /// CPU-XMR selection keeps the picker hidden and the behaviour at All (the UI
    /// is unchanged for those cases — the no-regression contract).
    pub fn show_gpu_selector(&self) -> bool {
        self.gpu_devices().len() >= 2
            && matches!(self.selected_lane, Lane::GpuPrl | Lane::GpuRvn)
    }

    /// Toggle the checkbox for the card at position `idx` (a no-op when out of
    /// range). Never lets the user uncheck the LAST remaining card — at least one
    /// card must stay selected (an empty set would be a meaningless "mine on no
    /// GPU"; the user picks XMR to not GPU-mine), so unchecking the final checked
    /// box is ignored.
    pub fn toggle_gpu(&mut self, idx: usize) {
        let checked_count = self.gpu_selected.iter().filter(|&&b| b).count();
        if let Some(slot) = self.gpu_selected.get_mut(idx) {
            if *slot && checked_count <= 1 {
                // Refuse to clear the last remaining card.
                return;
            }
            *slot = !*slot;
        }
    }

    /// The [`GpuSelection`] the current checkbox state resolves to — the value a
    /// Start of a GPU lane should carry. Returns [`GpuSelection::All`] (the
    /// unchanged, every-card default) when the picker isn't applicable (no GPU
    /// lane, <2 cards, or every card checked); only an actual partial selection
    /// yields [`GpuSelection::Ids`] (the opt-in argv). The ids are the enumerated
    /// cards' real device indices (NOT positions), in enumeration order.
    pub fn resolved_gpu_selection(&self) -> GpuSelection {
        // Not a multi-GPU GPU-lane situation → All (argv unchanged).
        if !self.show_gpu_selector() {
            return GpuSelection::All;
        }
        let devices = self.gpu_devices();
        let ids: Vec<u32> = devices
            .iter()
            .zip(self.gpu_selected.iter())
            .filter(|(_, &checked)| checked)
            .map(|(dev, _)| dev.index)
            .collect();
        // All checked (or, defensively, none enumerable) → All so the argv is
        // byte-for-byte the every-card default; a real subset → Ids (opt-in).
        if ids.is_empty() || ids.len() == devices.len() {
            GpuSelection::All
        } else {
            GpuSelection::Ids(ids)
        }
    }

    /// The support level of a lane on the detected device (defaults to `Viable`
    /// for XMR / `Unavailable` for the GPU lane before detection completes, so
    /// the UI is honest even on the very first frame).
    pub fn lane_support(&self, lane: Lane) -> LaneSupport {
        match &self.viability {
            Some(v) => v.support(lane),
            None => {
                if lane == Lane::Xmr {
                    LaneSupport::Viable
                } else {
                    LaneSupport::Unavailable
                }
            }
        }
    }

    /// Select `lane` to mine (only honoured if the lane is runnable). Marks the
    /// choice as user-picked so a later `Detect` won't override it.
    pub fn select_lane(&mut self, lane: Lane) {
        if self.lane_support(lane).is_runnable() {
            self.selected_lane = lane;
            self.lane_user_picked = true;
        }
    }

    fn on_identity(&mut self, identity: Identity, mnemonic: Option<String>) {
        // Refresh the on-disk pointer view (the core wrote it). This single line
        // is what makes the engine/dashboards/Home immediately reflect the NEW
        // reward address — every reward-address read goes through `self.identity`
        // / `reward_address()`.
        self.identity = identity::load_pointer().or(Some(IdentityPointer {
            address: identity.address.clone(),
            pubkey: identity.pubkey.clone(),
            keystore_path: identity
                .keystore_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            label: None,
            created: 0,
        }));
        // Route the completion differently depending on whether this was the
        // first-run onboarding or the post-onboarding CHANGE flow.
        let changing = self.change_addr.is_some();
        match (changing, mnemonic) {
            // CHANGE → create: force the backup step inside the MODAL (stay over
            // the current screen), don't fall back into onboarding.
            (true, Some(m)) => {
                self.change_addr = Some(ChangeAddr::Backup {
                    mnemonic: m.into(),
                    acknowledged: false,
                });
            }
            // CHANGE → import / paste: done — close the modal, stay where we are.
            (true, None) => {
                self.change_addr = None;
            }
            // ONBOARDING → create: the forced-backup onboarding step.
            (false, Some(m)) => {
                self.onboarding = Some(Onboarding::Backup {
                    mnemonic: m.into(),
                    acknowledged: false,
                });
            }
            // ONBOARDING → import / paste: onboarding done, go Home.
            (false, None) => {
                self.onboarding = None;
                self.screen = Screen::Home;
            }
        }
        // Wipe sensitive form fields after use — ZEROIZE the backing buffers (not
        // a bare `.clear()`, which leaves the bytes in memory). Audit U-2.
        self.wipe_secret_forms();
    }

    /// Zeroize-and-clear the sensitive identity-entry buffers (password ×2,
    /// mnemonic, seed). `String::zeroize()` overwrites the bytes before emptying,
    /// so the passphrase/seed don't linger on the heap after the op completes.
    /// (The downstream engine ALSO zeroizes the password it receives; this closes
    /// the small window on the UI side.) The pasted address is PUBLIC, so it is
    /// only `.clear()`-ed, not zeroized.
    fn wipe_secret_forms(&mut self) {
        use zeroize::Zeroize;
        self.form_password.zeroize();
        self.form_password2.zeroize();
        self.form_mnemonic.zeroize();
        self.form_seed.zeroize();
    }

    fn on_snapshot(&mut self, s: Snapshot) {
        // Keep device + viability in sync (the snapshot also carries the device).
        if let Some(d) = &s.device {
            if self.device.as_ref() != Some(d) {
                self.set_device(d.clone());
            }
        }
        // Push the last-line into the rolling log (deduped against the tail).
        if let Some(line) = &s.last_line {
            if self.log.back().map(|l| l != line).unwrap_or(true) {
                self.log.push_back(line.clone());
                while self.log.len() > 60 {
                    self.log.pop_front();
                }
            }
        }
        self.snapshot = Some(s);
    }

    /// The engine lifecycle state (Idle until the first snapshot).
    pub fn state(&self) -> EngineState {
        self.snapshot.as_ref().map(|s| s.state).unwrap_or(EngineState::Idle)
    }

    pub fn is_mining(&self) -> bool {
        matches!(self.state(), EngineState::Running)
    }

    /// The current reward address (the user's OWN public address), if known.
    pub fn reward_address(&self) -> Option<String> {
        self.identity.as_ref().map(|p| p.address.clone())
    }

    /// The endpoint string to display for the dashboard/Settings.
    ///
    /// While mining (or after a snapshot exists), the ACTIVE endpoint comes from
    /// the snapshot (so a Layer-B failover is reflected). When **idle / not yet
    /// connected**, it must reflect the **SELECTED lane's** default relay port —
    /// `:3333` for XMR, `:8888` for RVN — NOT a hardcoded `:3333` (the M3
    /// follow-up). We derive it from the SAME source the engine uses
    /// ([`EndpointPlan::default_for_lane`]) so the relay-only honesty invariant
    /// holds and the port can never drift from the real launch plan.
    pub fn display_endpoint(&self) -> String {
        if let Some(ep) = self.snapshot.as_ref().and_then(|s| s.endpoint.clone()) {
            return ep;
        }
        use alice_miner_core::EndpointPlan;
        EndpointPlan::default_for_lane(self.active_lane())
            .current()
            .host_port()
    }

    /// Current raw hashrate in kH/s from the snapshot (0 if none).
    pub fn hashrate_khs(&self) -> f32 {
        self.snapshot
            .as_ref()
            .and_then(|s| s.hashrate_hs)
            .map(|h| (h / 1000.0) as f32)
            .unwrap_or(0.0)
    }

    /// Per-frame animation/data tick: tween the displayed hashrate toward the
    /// real one, adapt the gauge ceiling, and push a sparkline sample ~1×/s.
    pub fn tick_anim(&mut self, ctx: &egui::Context) {
        let target = self.hashrate_khs();
        if self.motion_enabled() {
            // Ease toward the target (the contract's fluid tween, `+= (t-x)*0.16`).
            self.hr_display_khs += (target - self.hr_display_khs) * 0.16;
        } else {
            // Reduced motion: snap to the target (no tween) — the number is still
            // accurate, it just doesn't animate toward the value.
            self.hr_display_khs = target;
        }
        if self.hr_display_khs < 0.001 {
            self.hr_display_khs = 0.0;
        }
        // Adapt the gauge ceiling upward so the ring never pins at 100%; decay
        // slowly when idle.
        if target > self.gauge_ceiling_khs * 0.95 {
            self.gauge_ceiling_khs = (target * 1.12).max(self.gauge_ceiling_khs);
        }
        // Sample the sparkline about once a second while mining.
        let now = Instant::now();
        let due = self
            .last_spark_push
            .map(|t| now.duration_since(t).as_millis() >= 900)
            .unwrap_or(true);
        if due && self.is_mining() {
            self.last_spark_push = Some(now);
            self.spark.push_back(self.hr_display_khs.max(0.0));
            while self.spark.len() > 32 {
                self.spark.pop_front();
            }
        }
        // While active (mining / starting / stopping) keep the frame loop live so
        // the breathing glow + number tween animate AND engine events keep
        // draining. Under reduced motion we still need to poll the engine for
        // snapshots, but a calmer ~10 Hz cadence is enough (no per-frame anim).
        match (self.state(), self.motion_enabled()) {
            (EngineState::Idle, _) => {
                ctx.request_repaint_after(std::time::Duration::from_millis(400));
            }
            (_, true) => ctx.request_repaint(),
            (_, false) => ctx.request_repaint_after(std::time::Duration::from_millis(100)),
        }
    }

    /// Gauge fill 0..1 from the smoothed hashrate / adaptive ceiling.
    pub fn gauge(&self) -> f32 {
        if self.gauge_ceiling_khs <= 0.0 {
            return 0.0;
        }
        (self.hr_display_khs / self.gauge_ceiling_khs).clamp(0.0, 1.0)
    }

    // ── Engine commands ──────────────────────────────────────────────────────

    /// The lane that a Start would ACTUALLY run, given the user's selection and the
    /// device viability (falls back to XMR — always viable — when the selection is
    /// somehow not runnable). Mirrors the resolution in [`start_mining`] so the
    /// PoP-needed decision is computed from the same lane the engine would launch.
    pub fn resolved_start_lane(&self) -> Lane {
        if self.lane_support(self.selected_lane).is_runnable() {
            self.selected_lane
        } else {
            Lane::Xmr
        }
    }

    /// Whether a Start of the resolved lane needs the wallet UNLOCK password (a
    /// proof-of-possession signature). True iff the resolved lane is GPU-PRL — the
    /// only lane the engine gates on `resolve_prl_secrets` (XMR/RVN are
    /// address-only). Pure + testable; mirrors `engine.rs` `prl_in_play`.
    pub fn start_needs_prl_password(&self) -> bool {
        self.resolved_start_lane() == Lane::GpuPrl
    }

    /// True when the engine reports Running but no hashrate has materialised yet
    /// (no xmrig speed line) AND no shares are in — i.e. the lane is connecting /
    /// warming up (RandomX dataset init, or a stalled/reconnecting miner). Shown
    /// honestly as "Connecting" rather than a confident green "live · 0.00 kH/s"
    /// (the macOS "0 H/s under MINING LIVE" symptom).
    pub fn is_warming_up(&self) -> bool {
        if self.state() != EngineState::Running {
            return false;
        }
        let hr = self.snapshot.as_ref().and_then(|s| s.hashrate_hs).unwrap_or(0.0);
        let acc = self.snapshot.as_ref().map(|s| s.shares_accepted).unwrap_or(0);
        hr <= 0.0 && acc == 0
    }

    pub fn start_mining(&mut self) {
        self.error = None;
        // Single owner: don't start a foreground miner while the background service
        // is active — two miners to the same address only waste the machine. Point
        // the user to Settings to turn it off first.
        if matches!(
            self.bg_service,
            Some(alice_miner_core::service::ServiceState::Running)
                | Some(alice_miner_core::service::ServiceState::Loaded)
        ) {
            self.error = Some(
                "Background mining is on — turn it off in Settings (Background mining) to mine \
                 in the foreground."
                    .into(),
            );
            return;
        }
        // Mine the selected lane (defaults to the recommended one for the device).
        // If somehow not runnable, fall back to XMR (always viable) — defensive.
        let lane = self.resolved_start_lane();
        // Dual-mine only when the user opted in AND it's actually viable (≥2 lanes).
        // The GUI gates the toggle on viability, but re-check here defensively.
        let dual = self.dual_requested && self.dual_viable();

        // The GPU-PRL lane signs a proof-of-possession with the wallet key, so it
        // needs the keystore password to start (XMR/RVN never do). Branch here:
        //   * watch-only identity selected PRL → no keystore to sign → refuse with a
        //     clear message (no modal; importing the key is the fix), and
        //   * keystore-backed identity → open the unlock-password modal; the actual
        //     Start{GpuPrl, unlock_password: Some(pw)} is sent from
        //     `confirm_prl_start` once the user confirms (then the password is
        //     zeroized immediately on the GUI side).
        // Non-PRL lanes send Start{unlock_password: None} straight away (unchanged).
        if self.start_needs_prl_password() {
            if self.reward_is_watch_only() {
                self.error = Some(
                    "GPU · PRL needs a signable wallet (not a pasted address): import \
                     the mnemonic/seed for this address, then start PRL."
                        .into(),
                );
                return;
            }
            // Keystore-backed → prompt for the unlock password.
            self.prl_unlock = Some(PrlUnlock { password: String::new(), lane, dual });
            return;
        }

        // A5c: the simple per-GPU picker resolves to All (every card, unchanged
        // behavior) unless the user unchecked some cards on a ≥2-GPU box with a GPU
        // lane — then Ids(selected indices). CPU-XMR / single-GPU → All.
        let gpus = self.resolved_gpu_selection();
        // Prefer the visible-terminal persistence path (production builds with the
        // bundled CLI); fall back to the in-window engine on a dev build. XMR/RVN
        // are address-only, so no password is involved here.
        if self.launch_in_terminal(lane, &gpus) {
            return;
        }
        if let Err(e) = self.engine.send(Command::Start {
            lane,
            address: None,
            dual,
            unlock_password: None,
            gpus,
        }) {
            self.error = Some(e);
        }
    }

    /// Confirm the GPU-PRL unlock prompt. The GPU mainline persists best in a
    /// **visible terminal** (the operator's chosen model: Start → a real terminal
    /// running the headless CLI, which prompts for the wallet password ITSELF and
    /// keeps mining after the GUI closes). So when the bundled CLI is present we
    /// pop the terminal and DROP the just-typed password unused (the CLI re-prompts
    /// securely in its own window — no secret is ever passed on a command line).
    /// On a dev build with no adjacent CLI we fall back to the in-window engine,
    /// sending `Start{unlock_password: Some(pw)}`. Either way the GUI-held password
    /// is **zeroized** the instant we're done. No-op if the modal isn't open; the
    /// lane/dual are replayed verbatim from the modal.
    pub fn confirm_prl_start(&mut self) {
        use zeroize::Zeroize;
        let Some(mut unlock) = self.prl_unlock.take() else {
            return;
        };
        self.error = None;
        let PrlUnlock { lane, dual, .. } = unlock;
        // A5c: PRL is a GPU lane, so honour the multi-GPU picker here too (resolves
        // to All unless the user picked a subset on a ≥2-GPU box).
        let gpus = self.resolved_gpu_selection();
        // Prefer the visible-terminal persistence path (the GPU mainline). The
        // password the user typed is NOT forwarded — the CLI prompts in its own
        // terminal — so we zeroize it here regardless of which path we take.
        if self.launch_in_terminal(lane, &gpus) {
            unlock.password.zeroize();
            return;
        }
        // Fallback (no bundled CLI — dev build): the in-window engine path needs
        // the unlock password. Send a CLONE; the original is zeroized below.
        let send_result = self.engine.send(Command::Start {
            lane,
            address: None,
            dual,
            unlock_password: Some(unlock.password.clone()),
            gpus,
        });
        // Zeroize the GUI-held password the instant Start is dispatched.
        unlock.password.zeroize();
        if let Err(e) = send_result {
            self.error = Some(e);
        }
    }

    /// Try to launch the headless CLI in a **visible OS terminal** for `lane` (the
    /// GPU-persistence path: the user sees live output + mining survives the GUI
    /// closing; for the PRL/Alpha lanes the CLI prompts for the wallet password in
    /// its own terminal, so NO secret is passed here). The argv is secret-free —
    /// only `start --lane <lane> [--gpus <ids>]`.
    ///
    /// Returns `true` when a terminal launch was ATTEMPTED (so the caller skips the
    /// in-window engine — single owner). Returns `false` only when the bundled CLI
    /// isn't present next to the app (a dev build), so the caller falls back to the
    /// in-window engine. A terminal-spawn failure still returns `true` (we tried,
    /// and surfaced the error) so we never double-launch. Dual-mine is left to the
    /// in-window engine for now (the CLI `--dual` path is a follow-up), so this
    /// returns `false` when `dual` is requested.
    fn launch_in_terminal(&mut self, lane: Lane, gpus: &GpuSelection) -> bool {
        use alice_miner_core::terminal;
        // Dual-mine isn't wired into the terminal launcher yet → use the engine.
        if self.dual_requested && self.dual_viable() {
            return false;
        }
        let cli_path = match terminal::resolve_cli_path() {
            Ok(p) => p,
            // No adjacent CLI (dev build) → signal the caller to use the engine.
            Err(_) => return false,
        };
        let args = terminal::terminal_start_args(lane.cli_lane_arg(), gpus.csv().as_deref());
        if let Err(e) = terminal::spawn_in_terminal(&cli_path, &args) {
            self.error = Some(e);
        }
        true
    }

    /// Cancel the GPU-PRL unlock prompt without starting: zeroize+drop the captured
    /// password and close the modal. No-op if it isn't open.
    pub fn cancel_prl_start(&mut self) {
        use zeroize::Zeroize;
        if let Some(mut unlock) = self.prl_unlock.take() {
            unlock.password.zeroize();
        }
        self.error = None;
    }

    /// Whether dual-mine is VIABLE on this device — at least two lanes are
    /// runnable (CPU-XMR is always viable; the GPU-RVN lane must also be viable,
    /// i.e. a real NVIDIA GPU). On this Mac only XMR is viable, so this is `false`
    /// and the dual toggle renders disabled ("needs a supported GPU").
    pub fn dual_viable(&self) -> bool {
        use alice_miner_core::detect::capability::ALL_LANES;
        match &self.viability {
            Some(v) => ALL_LANES.iter().filter(|&&l| v.is_runnable(l)).count() >= 2,
            None => false,
        }
    }

    /// The lane currently active/selected, and its accent colour — used by the
    /// Home lane chip + hero so the UI reflects the chosen lane.
    pub fn active_lane(&self) -> Lane {
        // While running, trust the snapshot's lane; otherwise the selection.
        self.snapshot
            .as_ref()
            .and_then(|s| s.lane)
            .unwrap_or(self.selected_lane)
    }

    pub fn stop_mining(&mut self) {
        if let Err(e) = self.engine.send(Command::Stop) {
            self.error = Some(e);
        }
    }

    /// Refuse an identity change while a lane is running (security/safety: never
    /// re-key the reward target out from under a live miner). Returns `true` when
    /// the change is BLOCKED (and sets the error). Always `false` during
    /// onboarding (no identity ⇒ nothing is mining), so it's a no-op there.
    fn change_blocked_by_mining(&mut self) -> bool {
        if self.is_mining() {
            self.error =
                Some("Stop mining before changing the reward address.".into());
            true
        } else {
            false
        }
    }

    pub fn submit_create(&mut self) {
        self.error = None;
        if self.change_blocked_by_mining() {
            return;
        }
        if self.form_password.len() < 8 {
            self.error = Some("Password must be at least 8 characters.".into());
            return;
        }
        if self.form_password != self.form_password2 {
            self.error = Some("Passwords do not match.".into());
            return;
        }
        let spec = IdentitySpec::Create {
            label: None,
            password: self.form_password.clone(),
        };
        if let Err(e) = self.engine.send(Command::Identity(spec)) {
            self.error = Some(e);
        }
    }

    pub fn submit_import(&mut self) {
        self.error = None;
        if self.change_blocked_by_mining() {
            return;
        }
        if self.form_password.len() < 8 {
            self.error = Some("Password must be at least 8 characters.".into());
            return;
        }
        let spec = if self.form_use_seed {
            IdentitySpec::ImportSeedHex {
                seed_hex: self.form_seed.trim().to_string(),
                label: None,
                password: self.form_password.clone(),
            }
        } else {
            IdentitySpec::ImportMnemonic {
                mnemonic: self.form_mnemonic.trim().to_string(),
                label: None,
                password: self.form_password.clone(),
            }
        };
        if let Err(e) = self.engine.send(Command::Identity(spec)) {
            self.error = Some(e);
        }
    }

    pub fn submit_paste(&mut self) {
        self.error = None;
        if self.change_blocked_by_mining() {
            return;
        }
        let spec = IdentitySpec::Paste {
            address: self.form_address.trim().to_string(),
            label: None,
        };
        if let Err(e) = self.engine.send(Command::Identity(spec)) {
            self.error = Some(e);
        }
    }

    /// Move from the backup step to the confirm step: pick 3 distinct word
    /// positions to verify and build a shuffled chip pool (the 3 correct words
    /// plus filler decoys from the phrase). Deterministic shuffle (no `rand`
    /// dep) seeded off the current time — good enough for an anti-skip check.
    pub fn begin_confirm(&mut self, mnemonic: &str) {
        let words: Vec<String> = mnemonic.split_whitespace().map(|s| s.to_string()).collect();
        let n = words.len().max(1);
        // Pick 3 distinct positions via a time-seeded LCG (ascending for a calm
        // "#3 · #9 · #11" prompt).
        let mut seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E3779B97F4A7C15)
            | 1;
        let mut next = |bound: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed as usize) % bound.max(1)
        };
        let mut targets: Vec<usize> = Vec::new();
        let want = 3.min(n);
        while targets.len() < want {
            let i = next(n);
            if !targets.contains(&i) {
                targets.push(i);
            }
        }
        targets.sort_unstable();

        // Build the chip pool: the correct words + a few decoys, then shuffle.
        let mut pool: Vec<String> = targets.iter().map(|&i| words[i].clone()).collect();
        let mut decoys: Vec<String> = words
            .iter()
            .enumerate()
            .filter(|(i, _)| !targets.contains(i))
            .map(|(_, w)| w.clone())
            .collect();
        // Take up to 5 decoys.
        let mut chosen_decoys = Vec::new();
        while chosen_decoys.len() < 5.min(decoys.len()) {
            let i = next(decoys.len());
            chosen_decoys.push(decoys.remove(i));
        }
        pool.extend(chosen_decoys);
        // Fisher–Yates shuffle the pool.
        for i in (1..pool.len()).rev() {
            let j = next(i + 1);
            pool.swap(i, j);
        }

        self.confirm_targets = targets.iter().map(|&i| i + 1).collect(); // 1-based for display
        self.confirm_pool = pool;
        self.confirm_filled = vec![None; want];
        self.error = None;
        // Advance whichever flow is active (the post-onboarding change modal, or
        // first-run onboarding) into its confirm step — same retype check for both.
        if self.change_addr.is_some() {
            self.change_addr = Some(ChangeAddr::Confirm {
                mnemonic: mnemonic.to_string().into(),
            });
        } else {
            self.onboarding = Some(Onboarding::Confirm {
                mnemonic: mnemonic.to_string().into(),
            });
        }
    }

    /// True when every confirm slot holds the word at its (1-based) target index.
    pub fn confirm_is_correct(&self, mnemonic: &str) -> bool {
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        if self.confirm_filled.iter().any(|f| f.is_none()) {
            return false;
        }
        self.confirm_targets
            .iter()
            .zip(self.confirm_filled.iter())
            .all(|(&pos, filled)| {
                filled
                    .as_deref()
                    .zip(words.get(pos - 1))
                    .map(|(f, &w)| f == w)
                    .unwrap_or(false)
            })
    }

    /// Place `word` into the first empty confirm slot (chip tap).
    pub fn confirm_place(&mut self, word: &str) {
        if let Some(slot) = self.confirm_filled.iter_mut().find(|s| s.is_none()) {
            *slot = Some(word.to_string());
        }
    }

    /// Clear a confirm slot (tap a filled slot to undo).
    pub fn confirm_clear(&mut self, idx: usize) {
        if let Some(slot) = self.confirm_filled.get_mut(idx) {
            *slot = None;
        }
    }

    /// Finish onboarding (after a correct confirm, or import/paste) → Home.
    pub fn finish_backup(&mut self) {
        self.onboarding = None;
        self.screen = Screen::Home;
        self.confirm_targets.clear();
        self.confirm_pool.clear();
        self.confirm_filled.clear();
    }

    // ── Change reward address (post-onboarding) ───────────────────────────────

    /// Open the "change reward address" modal at its launcher. No-op (and clears
    /// any half-typed forms) — guarded by the caller on `!is_mining()`. We reset
    /// the shared identity form fields so a stale paste/password can't leak in.
    pub fn open_change_addr(&mut self) {
        self.error = None;
        self.reset_identity_forms();
        self.change_addr = Some(ChangeAddr::Choose);
    }

    /// Whether the active reward identity is WATCH-ONLY (a pasted address with no
    /// signing keystore). Used to label the Settings Identity section honestly.
    pub fn reward_is_watch_only(&self) -> bool {
        match &self.identity {
            Some(p) => p.keystore_path.is_none(),
            None => false,
        }
    }

    /// The `…/wallet.json.bak-<unix>` path the current keystore WOULD be moved to
    /// on the next create/import overwrite (`None` when no keystore exists). This
    /// is the exact destination `alice_crypto::backup_existing_wallet` will use,
    /// surfaced so the overwrite warning can name it BEFORE the user confirms.
    pub fn keystore_backup_hint(&self) -> Option<String> {
        identity::keystore_status()
            .projected_backup_path()
            .map(|p| p.to_string_lossy().to_string())
    }

    /// Close the change-address modal without applying anything (Cancel / done),
    /// wiping the transient form + confirm scratch state.
    pub fn close_change_addr(&mut self) {
        self.change_addr = None;
        self.reset_identity_forms();
        self.confirm_targets.clear();
        self.confirm_pool.clear();
        self.confirm_filled.clear();
        self.error = None;
    }

    /// Clear every shared identity-entry form field (password, mnemonic, seed,
    /// pasted address). Called when opening/closing the change modal so secrets +
    /// addresses never bleed between the onboarding and change flows. The secret
    /// fields are ZEROIZED (audit U-2); the public address is just cleared.
    fn reset_identity_forms(&mut self) {
        self.wipe_secret_forms();
        self.form_address.clear();
        self.form_use_seed = false;
    }

    /// Finish a change-address CREATE after a correct phrase confirm → close the
    /// modal. The pointer + keystore were already updated by the engine; this just
    /// tears the modal down (the new address is already live via `self.identity`).
    pub fn finish_change_addr(&mut self) {
        self.close_change_addr();
    }
}

impl Drop for MinerApp {
    /// Zeroize any passphrase/seed still sitting in the form buffers when the app
    /// is torn down (e.g. the user quits mid-onboarding) — so a secret never
    /// lingers in freed heap memory after exit. Audit U-2.
    fn drop(&mut self) {
        self.wipe_secret_forms();
    }
}

impl eframe::App for MinerApp {
    fn ui(&mut self, ui_root: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui_root.ctx().clone();
        // Scale the whole UI proportionally to the window FIRST (drives egui's
        // zoom factor), so every screen fills a consistent fraction at any size.
        self.apply_window_scaling(&ctx);
        ui::theme::apply_style(&ctx);
        if self.shot.is_some() {
            // Screenshot mode: the shot state machine poses the app + captures;
            // we skip draining real engine events so the injected demo snapshot
            // is not clobbered. `tick_anim` still runs for the breathing glow.
            // (Shot poses set `credit_state` directly, so we DON'T tick the client
            // here — that would overwrite a posed Confirmed/Confirming state.)
            crate::shot::drive(self, &ctx);
            self.tick_anim(&ctx);
            ui::chrome::render(ui_root, self);
            return;
        }
        self.drain_events();
        // One-shot launch-time update check (notify-only): kick a background
        // `check_for_update` on the first real frame so a new build is surfaced
        // without the user having to open Settings (the v0.3.1 "didn't auto-
        // update" report). Never applies on its own — the result just populates
        // the updater UI state, and the user clicks Apply. Off the screenshot path
        // (this runs after the shot early-return above).
        if !self.launch_update_checked {
            self.launch_update_checked = true;
            self.updater.check();
            // Also learn the background-service state once at launch so the Home
            // Start control can enforce single-owner (don't foreground-mine while
            // the background agent is active) without re-querying every frame.
            self.refresh_bg_service();
        }
        // Drain any completed background updater results (check / apply) into the
        // UI state. Cheap + non-blocking; the actual network/FS work runs on a
        // worker thread (see `crate::update`). Kept off the screenshot path.
        self.updater.poll();
        // Source B: refresh the server-confirmed credit state from the poller
        // (v1: a pure no-op yielding `NotExposed`; the fast-follow drives a real
        // poll here). Kept off the screenshot path so posed states survive.
        self.tick_credit();
        self.tick_anim(&ctx);
        ui::chrome::render(ui_root, self);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // Best-effort: stop any running lane so the child never outlives the app.
        let _ = self.engine.send(Command::Stop);
        std::thread::sleep(std::time::Duration::from_millis(400));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str =
        "harvest copper lunar ribbon orbit tundra cipher meadow violet anchor summit frost \
hazard pioneer velvet cradle ginger lantern marble pottery sunset timber walnut zephyr";

    /// `begin_confirm` must pick 3 distinct, in-range, ascending positions and a
    /// pool that contains each correct word — and picking those words must verify.
    #[test]
    fn confirm_flow_accepts_correct_words() {
        let mut app = MinerApp::new().expect("engine spawns");
        app.begin_confirm(PHRASE);

        let words: Vec<&str> = PHRASE.split_whitespace().collect();
        // 3 distinct, ascending, 1-based, in range.
        assert_eq!(app.confirm_targets.len(), 3);
        assert!(app.confirm_targets.windows(2).all(|w| w[0] < w[1]));
        assert!(app.confirm_targets.iter().all(|&p| p >= 1 && p <= words.len()));
        // The pool contains each correct word.
        for &p in &app.confirm_targets {
            assert!(app.confirm_pool.iter().any(|w| w == words[p - 1]));
        }
        // Not yet correct (all slots empty).
        assert!(!app.confirm_is_correct(PHRASE));
        // Place the correct word for each target in order.
        let targets = app.confirm_targets.clone();
        for &p in &targets {
            app.confirm_place(words[p - 1]);
        }
        assert!(app.confirm_is_correct(PHRASE), "correct picks must verify");
    }

    /// A wrong pick must NOT verify; clearing a slot frees it again.
    #[test]
    fn confirm_flow_rejects_wrong_and_supports_clear() {
        let mut app = MinerApp::new().expect("engine spawns");
        app.begin_confirm(PHRASE);
        let words: Vec<&str> = PHRASE.split_whitespace().collect();
        let targets = app.confirm_targets.clone();

        // Fill all slots with a deliberately wrong word (not in the phrase).
        for _ in &targets {
            app.confirm_place("zzz-not-a-word");
        }
        assert!(!app.confirm_is_correct(PHRASE));
        // Clear every slot, then place the correct words → verifies.
        for i in 0..targets.len() {
            app.confirm_clear(i);
        }
        assert!(app.confirm_filled.iter().all(|f| f.is_none()));
        for &p in &targets {
            app.confirm_place(words[p - 1]);
        }
        assert!(app.confirm_is_correct(PHRASE));
    }

    /// THE M3 FOLLOW-UP FIX: when idle / not yet connected, the displayed endpoint
    /// must reflect the SELECTED lane's relay port — `:8888` for RVN, `:3333` for
    /// XMR — not a hardcoded `:3333`.
    #[test]
    fn idle_endpoint_reflects_selected_lane_port() {
        use alice_miner_core::detect::{DeviceProfile, GpuInfo, GpuVendor, OsFamily};
        let mut app = MinerApp::new().expect("engine spawns");
        // Make RVN a runnable lane (a simulated NVIDIA box) so we can select it.
        app.set_device(DeviceProfile {
            os: OsFamily::Linux,
            arch: "x86_64".into(),
            apple_silicon: false,
            logical_cores: 16,
            cpu_model: "AMD Ryzen 9 5950X".into(),
            gpu: GpuInfo {
                vendor: GpuVendor::Nvidia,
                model: "NVIDIA GeForce RTX 3070 Ti".into(),
                vram_gb: 8,
                gpus: Vec::new(),
                max_compute_cap_x10: Some(86),
            },
            memory_gb: 64,
            display: "AMD Ryzen 9 5950X · 16 cores".into(),
            warnings: vec![],
        });
        app.snapshot = None; // idle / not connected

        // XMR selected → :3333.
        app.select_lane(Lane::Xmr);
        assert_eq!(app.display_endpoint(), "hk.aliceprotocol.org:3333");

        // RVN selected → :8888 (was hardcoded to :3333 before the fix).
        app.select_lane(Lane::GpuRvn);
        assert_eq!(app.display_endpoint(), "hk.aliceprotocol.org:8888");
    }

    /// Reduced motion flips `motion_enabled`.
    #[test]
    fn reduce_motion_toggles_motion_enabled() {
        let mut app = MinerApp::new().expect("engine spawns");
        assert!(app.motion_enabled(), "motion on by default");
        app.reduce_motion = true;
        assert!(!app.motion_enabled());
    }

    /// DUAL gating (the M4 gate): `dual_viable()` is `false` with a single viable
    /// lane (this Mac: XMR only → the toggle renders disabled), and `true` once a
    /// second lane (a simulated NVIDIA RVN) is viable (→ the toggle enables).
    #[test]
    fn dual_viable_requires_two_runnable_lanes() {
        use alice_miner_core::detect::{DeviceProfile, GpuInfo, GpuVendor, OsFamily};
        let mut app = MinerApp::new().expect("engine spawns");

        // Apple Silicon (no NVIDIA): only XMR viable → dual NOT viable.
        app.set_device(DeviceProfile {
            os: OsFamily::Macos,
            arch: "aarch64".into(),
            apple_silicon: true,
            logical_cores: 12,
            cpu_model: "Apple M2 Max".into(),
            gpu: GpuInfo { vendor: GpuVendor::Apple, model: "Apple M2 Max".into(), vram_gb: 0, gpus: Vec::new(), max_compute_cap_x10: None },
            memory_gb: 32,
            display: "Apple M2 Max · 12 cores".into(),
            warnings: vec![],
        });
        assert!(!app.dual_viable(), "Apple/CPU-only → dual disabled (one viable lane)");

        // Simulated NVIDIA box: XMR + RVN both viable → dual viable.
        app.set_device(DeviceProfile {
            os: OsFamily::Linux,
            arch: "x86_64".into(),
            apple_silicon: false,
            logical_cores: 16,
            cpu_model: "AMD Ryzen 9 5950X".into(),
            gpu: GpuInfo {
                vendor: GpuVendor::Nvidia,
                model: "NVIDIA GeForce RTX 3070 Ti".into(),
                vram_gb: 8,
                gpus: Vec::new(),
                max_compute_cap_x10: Some(86),
            },
            memory_gb: 64,
            display: "AMD Ryzen 9 5950X · 16 cores".into(),
            warnings: vec![],
        });
        assert!(app.dual_viable(), "NVIDIA box → dual enabled (two viable lanes)");
    }

    // ── Change reward address (post-onboarding) ───────────────────────────────

    /// A minimal Running snapshot so `is_mining()` is true (drives the change
    /// guard + the disabled affordances).
    fn running_snapshot() -> Snapshot {
        Snapshot {
            state: EngineState::Running,
            device: None,
            lane: Some(Lane::Xmr),
            hashrate_hs: Some(8400.0),
            shares_accepted: 10,
            shares_rejected: 0,
            endpoint: Some("hk.aliceprotocol.org:3333".into()),
            worker_id: Some("rig-1".into()),
            uptime_s: 5,
            failovers: 0,
            dual: false,
            lanes: Vec::new(),
            last_line: None,
            message: None,
            prl_payout: None,
        }
    }

    /// `open_change_addr` opens the modal at its launcher and wipes any stale
    /// identity-form scratch (so a half-typed paste/password can't leak in).
    #[test]
    fn open_change_addr_opens_launcher_and_clears_forms() {
        let mut app = MinerApp::new().expect("engine spawns");
        app.form_address = "leftover".into();
        app.form_password = "leftover-pw".into();
        app.open_change_addr();
        assert!(matches!(app.change_addr, Some(ChangeAddr::Choose)));
        assert!(app.form_address.is_empty(), "paste field cleared");
        assert!(app.form_password.is_empty(), "password field cleared");
    }

    /// The MINING GUARD: while a lane is running, none of the three change submits
    /// fire an identity change — each sets the honest "stop mining first" error
    /// instead. (Onboarding is unaffected: with no identity nothing is mining, so
    /// the guard is a no-op there.)
    #[test]
    fn change_refused_while_mining() {
        let mut app = MinerApp::new().expect("engine spawns");
        app.snapshot = Some(running_snapshot());
        assert!(app.is_mining());

        // A valid-looking create attempt is blocked BEFORE the password checks.
        app.form_password = "a-good-password".into();
        app.form_password2 = "a-good-password".into();
        app.submit_create();
        assert_eq!(
            app.error.as_deref(),
            Some("Stop mining before changing the reward address.")
        );

        // Import is blocked too.
        app.error = None;
        app.form_mnemonic = "abandon abandon abandon".into();
        app.submit_import();
        assert_eq!(
            app.error.as_deref(),
            Some("Stop mining before changing the reward address.")
        );

        // Paste is blocked too.
        app.error = None;
        app.form_address = "a2x9whatever".into();
        app.submit_paste();
        assert_eq!(
            app.error.as_deref(),
            Some("Stop mining before changing the reward address.")
        );
    }

    /// When NOT mining the guard does not trip: a too-short create password then
    /// fails on its OWN validation (proving the guard isn't masking later checks).
    #[test]
    fn change_allowed_when_idle_then_hits_own_validation() {
        let mut app = MinerApp::new().expect("engine spawns");
        app.snapshot = None; // idle
        assert!(!app.is_mining());
        app.form_password = "short".into(); // < 8 chars
        app.form_password2 = "short".into();
        app.submit_create();
        assert_eq!(
            app.error.as_deref(),
            Some("Password must be at least 8 characters."),
            "idle → guard passes, the real validation runs"
        );
    }

    /// `reward_is_watch_only` reflects the pointer's keystore presence (so the
    /// Settings/modal tag is honest), and `close_change_addr` tears the modal +
    /// scratch down.
    #[test]
    fn watch_only_flag_and_close_modal() {
        let mut app = MinerApp::new().expect("engine spawns");
        // Watch-only pointer (no keystore_path) → watch-only true.
        app.identity = Some(IdentityPointer {
            address: "a2x9k4f7q2w8e3r5t6y1u0p9s8d7f6g5h4j3k2l1z0x9c8v7b6n5m4Q".into(),
            pubkey: None,
            keystore_path: None,
            label: None,
            created: 0,
        });
        assert!(app.reward_is_watch_only());
        // Keystore-backed pointer → watch-only false.
        app.identity = Some(IdentityPointer {
            address: "a2x9k4f7q2w8e3r5t6y1u0p9s8d7f6g5h4j3k2l1z0x9c8v7b6n5m4Q".into(),
            pubkey: Some("0x00".into()),
            keystore_path: Some("/tmp/wallet.json".into()),
            label: None,
            created: 0,
        });
        assert!(!app.reward_is_watch_only());

        app.change_addr = Some(ChangeAddr::Paste);
        app.form_address = "scratch".into();
        app.close_change_addr();
        assert!(app.change_addr.is_none());
        assert!(app.form_address.is_empty());
    }

    // ── GPU-PRL unlock-password gating (A2a) ──────────────────────────────────

    /// A simulated NVIDIA box (so PRL is a runnable lane the user can select).
    fn nvidia_device() -> alice_miner_core::detect::DeviceProfile {
        use alice_miner_core::detect::{DeviceProfile, GpuInfo, GpuVendor, OsFamily};
        DeviceProfile {
            os: OsFamily::Linux,
            arch: "x86_64".into(),
            apple_silicon: false,
            logical_cores: 16,
            cpu_model: "AMD Ryzen 9 5950X".into(),
            gpu: GpuInfo {
                vendor: GpuVendor::Nvidia,
                model: "NVIDIA GeForce RTX 3070 Ti".into(),
                vram_gb: 8,
                gpus: Vec::new(),
                max_compute_cap_x10: Some(86),
            },
            memory_gb: 64,
            display: "AMD Ryzen 9 5950X · 16 cores".into(),
            warnings: vec![],
        }
    }

    fn keystore_identity() -> IdentityPointer {
        IdentityPointer {
            address: "a2x9k4f7q2w8e3r5t6y1u0p9s8d7f6g5h4j3k2l1z0x9c8v7b6n5m4Q".into(),
            pubkey: Some("0x00".into()),
            keystore_path: Some("/tmp/wallet.json".into()),
            label: None,
            created: 0,
        }
    }

    fn watch_only_identity() -> IdentityPointer {
        IdentityPointer {
            address: "a2x9k4f7q2w8e3r5t6y1u0p9s8d7f6g5h4j3k2l1z0x9c8v7b6n5m4Q".into(),
            pubkey: None,
            keystore_path: None,
            label: None,
            created: 0,
        }
    }

    /// The PoP-needed predicate: only the GPU-PRL lane raises the unlock prompt;
    /// XMR/RVN are address-only. Computed from the RESOLVED lane (what Start would
    /// actually launch), so it mirrors the engine's `prl_in_play`.
    #[test]
    fn start_needs_prl_password_only_for_resolved_prl_lane() {
        let mut app = MinerApp::new().expect("engine spawns");
        app.set_device(nvidia_device());

        app.select_lane(Lane::Xmr);
        assert!(!app.start_needs_prl_password(), "XMR is address-only");

        app.select_lane(Lane::GpuRvn);
        assert!(!app.start_needs_prl_password(), "RVN is address-only");

        app.select_lane(Lane::GpuPrl);
        assert!(app.start_needs_prl_password(), "PRL signs a PoP → needs the key");
    }

    /// Starting PRL with a KEYSTORE-backed identity opens the unlock-password modal
    /// (it does NOT send Start yet — the engine receives the password only on
    /// confirm). XMR never opens it.
    #[test]
    fn start_prl_keystore_opens_unlock_modal() {
        let mut app = MinerApp::new().expect("engine spawns");
        app.set_device(nvidia_device());
        app.identity = Some(keystore_identity());

        // XMR → no modal (sends Start straight through).
        app.select_lane(Lane::Xmr);
        app.start_mining();
        assert!(app.prl_unlock.is_none(), "XMR never prompts for a password");

        // PRL → modal opens, carrying the resolved lane + dual, no error.
        app.select_lane(Lane::GpuPrl);
        app.start_mining();
        let unlock = app.prl_unlock.as_ref().expect("PRL opens the unlock modal");
        assert_eq!(unlock.lane, Lane::GpuPrl);
        assert!(!unlock.dual);
        assert!(unlock.password.is_empty(), "starts empty");
        assert!(app.error.is_none(), "no error — just a prompt");
    }

    /// Starting PRL with a WATCH-ONLY identity (pasted address, no key) is refused
    /// up-front with a clear message and NO modal (it can't sign a PoP — importing
    /// the key is the fix).
    #[test]
    fn start_prl_watch_only_refused_without_modal() {
        let mut app = MinerApp::new().expect("engine spawns");
        app.set_device(nvidia_device());
        app.identity = Some(watch_only_identity());

        app.select_lane(Lane::GpuPrl);
        app.start_mining();
        assert!(app.prl_unlock.is_none(), "watch-only never opens the modal");
        let err = app.error.as_deref().expect("a refusal message is set");
        assert!(err.contains("import"), "message points at importing the key: {err}");
    }

    /// Single-owner lock: a foreground Start is refused while the background
    /// service is active (would double-mine to the same address).
    #[test]
    fn start_refused_while_background_service_active() {
        let mut app = MinerApp::new().expect("engine spawns");
        app.set_device(nvidia_device());
        app.identity = Some(watch_only_identity());
        app.bg_service = Some(alice_miner_core::service::ServiceState::Running);
        app.start_mining();
        let err = app.error.as_deref().expect("single-owner refusal is set");
        assert!(err.contains("Background mining is on"), "got: {err}");
        assert!(app.prl_unlock.is_none(), "no modal opened — refused before lane handling");
    }

    /// PIECE 1 — the terminal-launch argv the GUI hands the headless CLI is
    /// SECRET-FREE and replays the user's lane + (subset) GPU selection. We exercise
    /// the exact building blocks `launch_in_terminal` uses (lane→CLI token +
    /// resolved GPU CSV → `terminal_start_args`) without spawning a process.
    #[test]
    fn terminal_launch_args_are_secret_free_and_replay_selection() {
        use alice_miner_core::terminal;
        let mut app = MinerApp::new().expect("engine spawns");
        app.set_device(multigpu_device(3));
        app.select_lane(Lane::GpuPrl);

        // All cards checked → `start --lane prl` (no --gpus; every-card argv).
        let gpus = app.resolved_gpu_selection();
        assert_eq!(gpus, GpuSelection::All);
        let args = terminal::terminal_start_args(Lane::GpuPrl.cli_lane_arg(), gpus.csv().as_deref());
        assert_eq!(args, vec!["start", "--lane", "prl"]);

        // Uncheck the middle card → `start --lane prl --gpus 0,2`.
        app.toggle_gpu(1);
        let gpus = app.resolved_gpu_selection();
        let args = terminal::terminal_start_args(Lane::GpuPrl.cli_lane_arg(), gpus.csv().as_deref());
        assert_eq!(args, vec!["start", "--lane", "prl", "--gpus", "0,2"]);

        // SECRET-FREE under both shapes (no password / address / seed token).
        for tok in &args {
            let l = tok.to_lowercase();
            assert!(!l.contains("password") && !l.contains("prl1p") && !l.contains("seed"),
                "terminal argv leaked a secret: {tok}");
        }

        // RVN must spell `rvn` for the CLI (its id() "gpu" would launch PRL).
        let rvn = terminal::terminal_start_args(Lane::GpuRvn.cli_lane_arg(), None);
        assert_eq!(rvn, vec!["start", "--lane", "rvn"]);
    }

    /// Cancelling the unlock prompt zeroizes+drops the captured password and closes
    /// the modal — without starting.
    #[test]
    fn cancel_prl_unlock_clears_and_closes() {
        let mut app = MinerApp::new().expect("engine spawns");
        app.prl_unlock = Some(PrlUnlock {
            password: "secret-pw".into(),
            lane: Lane::GpuPrl,
            dual: false,
        });
        app.cancel_prl_start();
        assert!(app.prl_unlock.is_none(), "modal closed on cancel");
        assert!(app.error.is_none());
    }

    /// Confirming the unlock prompt consumes the modal (the password is dispatched
    /// to the engine and the GUI-held copy is zeroized+dropped). After confirm the
    /// modal is closed regardless of whether the engine accepts the password (the
    /// outcome surfaces later as an Event::Error snapshot).
    #[test]
    fn confirm_prl_unlock_consumes_modal() {
        let mut app = MinerApp::new().expect("engine spawns");
        app.prl_unlock = Some(PrlUnlock {
            password: "secret-pw".into(),
            lane: Lane::GpuPrl,
            dual: false,
        });
        app.confirm_prl_start();
        assert!(app.prl_unlock.is_none(), "modal consumed on confirm");
    }

    // ── A5c: the simple multi-GPU selector ────────────────────────────────────

    /// A simulated NVIDIA box with `n` enumerated cards (so the picker is
    /// applicable). Indices are deliberately NON-contiguous offsets to prove the
    /// resolved `Ids` carry the cards' real device indices, not their positions.
    fn multigpu_device(n: u32) -> alice_miner_core::detect::DeviceProfile {
        use alice_miner_core::detect::{DeviceProfile, GpuDevice, GpuInfo, GpuVendor, OsFamily};
        let gpus: Vec<GpuDevice> = (0..n)
            .map(|i| GpuDevice {
                index: i,
                name: format!("NVIDIA Test {i}"),
                vram_gb: 24,
                uuid: format!("GPU-{i}"),
            })
            .collect();
        DeviceProfile {
            os: OsFamily::Linux,
            arch: "x86_64".into(),
            apple_silicon: false,
            logical_cores: 16,
            cpu_model: "AMD Ryzen 9 5950X".into(),
            gpu: GpuInfo {
                vendor: GpuVendor::Nvidia,
                model: "NVIDIA Test".into(),
                vram_gb: 24,
                gpus,
                max_compute_cap_x10: Some(86),
            },
            memory_gb: 64,
            display: "AMD Ryzen 9 5950X · 16 cores".into(),
            warnings: vec![],
        }
    }

    /// `set_device` sizes the selection to the enumerated cards (all checked), and
    /// the picker is shown only on a ≥2-GPU box with a GPU lane selected.
    #[test]
    fn gpu_selection_defaults_all_and_visibility() {
        let mut app = MinerApp::new().expect("engine spawns");

        // Single-GPU NVIDIA (the summary GPU but no enumeration) → picker hidden.
        app.set_device(nvidia_device()); // gpus: [] (no enumeration)
        app.select_lane(Lane::GpuRvn);
        assert!(!app.show_gpu_selector(), "no enumerated list → no picker");
        assert_eq!(app.resolved_gpu_selection(), GpuSelection::All);

        // 3-GPU box → selection sized to 3, all checked.
        app.set_device(multigpu_device(3));
        assert_eq!(app.gpu_selected, vec![true, true, true]);

        // With a CPU lane the picker stays hidden even on a 3-GPU box.
        app.select_lane(Lane::Xmr);
        assert!(!app.show_gpu_selector(), "CPU-XMR → no GPU picker");
        assert_eq!(app.resolved_gpu_selection(), GpuSelection::All);

        // With a GPU lane the picker shows; all-checked still resolves to All
        // (byte-identical every-card argv — the no-regression contract).
        app.select_lane(Lane::GpuRvn);
        assert!(app.show_gpu_selector(), "≥2 GPUs + GPU lane → picker shows");
        assert_eq!(
            app.resolved_gpu_selection(),
            GpuSelection::All,
            "all cards checked ⇒ All (argv unchanged)"
        );
    }

    /// Unchecking a card resolves Start to `Ids(<checked device indices>)`, in
    /// enumeration order, using the cards' real indices.
    #[test]
    fn gpu_selection_subset_resolves_to_ids() {
        let mut app = MinerApp::new().expect("engine spawns");
        app.set_device(multigpu_device(3));
        app.select_lane(Lane::GpuPrl);

        // Uncheck the middle card (position 1, device index 1).
        app.toggle_gpu(1);
        assert_eq!(app.gpu_selected, vec![true, false, true]);
        assert_eq!(
            app.resolved_gpu_selection(),
            GpuSelection::Ids(vec![0, 2]),
            "checked positions → their device indices, in order"
        );

        // Re-check it → back to All.
        app.toggle_gpu(1);
        assert_eq!(app.resolved_gpu_selection(), GpuSelection::All);
    }

    /// The picker never lets the user clear the LAST checked card (an empty set is
    /// meaningless — pick XMR to not GPU-mine).
    #[test]
    fn gpu_selection_keeps_at_least_one_card() {
        let mut app = MinerApp::new().expect("engine spawns");
        app.set_device(multigpu_device(2));
        app.select_lane(Lane::GpuRvn);

        app.toggle_gpu(0); // now only card 1 checked
        assert_eq!(app.gpu_selected, vec![false, true]);
        // Clearing the last remaining card is refused.
        app.toggle_gpu(1);
        assert_eq!(app.gpu_selected, vec![false, true], "last card stays checked");
        // It resolves to the single remaining card (index 1).
        assert_eq!(app.resolved_gpu_selection(), GpuSelection::Ids(vec![1]));
    }

    /// Re-detecting the SAME-sized GPU list must NOT clobber a deliberate user
    /// selection (only a length change resets to all-checked).
    #[test]
    fn gpu_selection_survives_redetect_same_size() {
        let mut app = MinerApp::new().expect("engine spawns");
        app.set_device(multigpu_device(3));
        app.select_lane(Lane::GpuRvn);
        app.toggle_gpu(2); // user unchecks card 2
        assert_eq!(app.gpu_selected, vec![true, true, false]);

        // A re-detect of the same 3-GPU machine keeps the selection.
        app.set_device(multigpu_device(3));
        assert_eq!(
            app.gpu_selected,
            vec![true, true, false],
            "same-size re-detect preserves the user's checks"
        );

        // A device with a DIFFERENT card count resets to all-checked.
        app.set_device(multigpu_device(2));
        assert_eq!(app.gpu_selected, vec![true, true], "count change → reset to All");
    }
}
