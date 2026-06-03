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
            reduce_motion: false,
            confirm_targets: Vec::new(),
            confirm_pool: Vec::new(),
            confirm_filled: Vec::new(),
            shot: crate::shot::ShotRunner::from_env(),
        })
    }

    /// Whether motion (breathing glow, gauge sweep, number tween, blinking dots)
    /// is enabled. `false` when the user turned on reduced motion.
    pub fn motion_enabled(&self) -> bool {
        !self.reduce_motion
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
        self.onboarding = Some(Onboarding::Confirm {
            mnemonic: mnemonic.to_string(),
        });
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

    /// Reduced motion flips `motion_enabled`.
    #[test]
    fn reduce_motion_toggles_motion_enabled() {
        let mut app = MinerApp::new().expect("engine spawns");
        assert!(app.motion_enabled(), "motion on by default");
        app.reduce_motion = true;
        assert!(!app.motion_enabled());
    }
}
