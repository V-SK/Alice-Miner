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
use alice_miner_core::{DeviceProfile, EngineState, Identity, Lane};
use eframe::egui::{self, TextureHandle};

use crate::ui;

/// Which top-level screen is showing.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Home,
    Dashboard,
    Settings,
}

/// Onboarding sub-flow (only reachable when there is no `~/.alice/identity.json`).
#[derive(Clone, PartialEq, Eq)]
pub enum Onboarding {
    /// Pick: create new / import / paste address.
    Choose,
    /// Created: show the 24-word mnemonic for the forced-backup step.
    Backup { mnemonic: String, acknowledged: bool },
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
    /// The active reward identity pointer (address etc.), if one exists.
    pub identity: Option<IdentityPointer>,
    /// The active screen.
    pub screen: Screen,
    /// `Some` while onboarding (no identity yet, or user chose to add one).
    pub onboarding: Option<Onboarding>,

    /// The Alice mark texture (loaded once from the bundled PNG).
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
            identity,
            screen: Screen::Home,
            onboarding,
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
            shot: crate::shot::ShotRunner::from_env(),
        })
    }

    /// Lazily load (and cache) the Alice mark texture from the bundled PNG.
    pub fn mark_texture(&mut self, ctx: &egui::Context) -> TextureHandle {
        if let Some(t) = &self.mark_tex {
            return t.clone();
        }
        let bytes = include_bytes!("../assets/brand/alice-logo.png");
        let img = image::load_from_memory(bytes)
            .expect("bundled alice-logo.png decodes")
            .to_rgba8();
        let (w, h) = img.dimensions();
        let color = egui::ColorImage::from_rgba_unmultiplied([w as usize, h as usize], &img);
        let tex = ctx.load_texture("alice-mark", color, egui::TextureOptions::LINEAR);
        self.mark_tex = Some(tex.clone());
        tex
    }

    /// Drain all pending engine events into local state.
    pub fn drain_events(&mut self) {
        while let Some(evt) = self.engine.try_recv() {
            match evt {
                Event::Device(p) => self.device = Some(p),
                Event::Identity { identity, mnemonic } => self.on_identity(identity, mnemonic),
                Event::Snapshot(s) => self.on_snapshot(s),
                Event::Error(e) => self.error = Some(e),
            }
        }
    }

    fn on_identity(&mut self, identity: Identity, mnemonic: Option<String>) {
        // Refresh the on-disk pointer view (the core wrote it).
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
        match mnemonic {
            // A freshly created identity → force the backup step (show the
            // mnemonic once, require an explicit acknowledgement).
            Some(m) => {
                self.onboarding = Some(Onboarding::Backup {
                    mnemonic: m,
                    acknowledged: false,
                });
            }
            // Import / paste → onboarding done, go Home.
            None => {
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
        // Keep device in sync (the snapshot also carries it).
        if let Some(d) = &s.device {
            self.device = Some(d.clone());
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
        // Ease toward the target (the contract's fluid tween, `+= (t-x)*0.16`).
        self.hr_display_khs += (target - self.hr_display_khs) * 0.16;
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
        // While mining (or starting/stopping) keep the frame loop live for the
        // breathing glow + number tween; otherwise a gentle idle cadence.
        if !matches!(self.state(), EngineState::Idle) {
            ctx.request_repaint();
        } else {
            ctx.request_repaint_after(std::time::Duration::from_millis(400));
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
        if let Err(e) = self.engine.send(Command::Start { lane: Lane::Xmr, address: None }) {
            self.error = Some(e);
        }
    }

    pub fn stop_mining(&mut self) {
        if let Err(e) = self.engine.send(Command::Stop) {
            self.error = Some(e);
        }
    }

    pub fn submit_create(&mut self) {
        self.error = None;
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
        let spec = IdentitySpec::Paste {
            address: self.form_address.trim().to_string(),
            label: None,
        };
        if let Err(e) = self.engine.send(Command::Identity(spec)) {
            self.error = Some(e);
        }
    }

    pub fn finish_backup(&mut self) {
        self.onboarding = None;
        self.screen = Screen::Home;
    }
}

impl eframe::App for MinerApp {
    fn ui(&mut self, ui_root: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui_root.ctx().clone();
        ui::theme::apply_style(&ctx);
        if self.shot.is_some() {
            // Screenshot mode: the shot state machine poses the app + captures;
            // we skip draining real engine events so the injected demo snapshot
            // is not clobbered. `tick_anim` still runs for the breathing glow.
            crate::shot::drive(self, &ctx);
            self.tick_anim(&ctx);
            ui::chrome::render(ui_root, self);
            return;
        }
        self.drain_events();
        self.tick_anim(&ctx);
        ui::chrome::render(ui_root, self);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // Best-effort: stop any running lane so the child never outlives the app.
        let _ = self.engine.send(Command::Stop);
        std::thread::sleep(std::time::Duration::from_millis(400));
    }
}
