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
    CreditState, DashboardModel, DeviceProfile, EngineState, Identity, Lane, LaneSupport,
    LaneViability, LocalActivity, PoolStatsClient, Reconciliation,
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
#[derive(Clone, PartialEq, Eq)]
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
    Backup { mnemonic: String, acknowledged: bool },
    /// Confirm the new phrase by re-picking 3 words (reuses the onboarding logic).
    Confirm { mnemonic: String },
    /// Import a different mnemonic / seed. The overwrite warning is recapped inline
    /// (Import also replaces + backs up the keystore).
    Import { backup_hint: Option<String> },
    /// Paste a different address (watch-only). Preserves the existing keystore.
    Paste,
}

/// Onboarding sub-flow (only reachable when there is no `~/.alice/identity.json`).
#[derive(Clone, PartialEq, Eq)]
pub enum Onboarding {
    /// Pick: create new / import / paste address.
    Choose,
    /// Created: show the 24-word mnemonic for the forced-backup step.
    Backup { mnemonic: String, acknowledged: bool },
    /// Confirm the backup by re-picking 3 random words (PLAN §4 — the deliberate
    /// divergence from the Wallet). Carries the mnemonic so a wrong pick can be
    /// re-prompted without regenerating.
    Confirm { mnemonic: String },
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
}

impl MinerApp {
    pub fn new() -> Result<Self, String> {
        let engine = EngineHandle::spawn()?;
        // Kick off device detection immediately (PLAN: Detect on launch).
        engine.send(Command::Detect)?;
        let identity = identity::load_pointer();
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
            shot: crate::shot::ShotRunner::from_env(),
        })
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
                    mnemonic: m,
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
                    mnemonic: m,
                    acknowledged: false,
                });
            }
            // ONBOARDING → import / paste: onboarding done, go Home.
            (false, None) => {
                self.onboarding = None;
                self.screen = Screen::Home;
            }
        }
        // Clear sensitive form fields after use.
        self.form_password.clear();
        self.form_password2.clear();
        self.form_mnemonic.clear();
        self.form_seed.clear();
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

    pub fn start_mining(&mut self) {
        self.error = None;
        // Mine the selected lane (defaults to the recommended one for the device).
        // If somehow not runnable, fall back to XMR (always viable) — defensive.
        let lane = if self.lane_support(self.selected_lane).is_runnable() {
            self.selected_lane
        } else {
            Lane::Xmr
        };
        // Dual-mine only when the user opted in AND it's actually viable (≥2 lanes).
        // The GUI gates the toggle on viability, but re-check here defensively.
        let dual = self.dual_requested && self.dual_viable();
        if let Err(e) = self.engine.send(Command::Start { lane, address: None, dual }) {
            self.error = Some(e);
        }
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
                mnemonic: mnemonic.to_string(),
            });
        } else {
            self.onboarding = Some(Onboarding::Confirm {
                mnemonic: mnemonic.to_string(),
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
    /// addresses never bleed between the onboarding and change flows.
    fn reset_identity_forms(&mut self) {
        self.form_password.clear();
        self.form_password2.clear();
        self.form_mnemonic.clear();
        self.form_seed.clear();
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
            gpu: GpuInfo { vendor: GpuVendor::Apple, model: "Apple M2 Max".into(), vram_gb: 0 },
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
}
