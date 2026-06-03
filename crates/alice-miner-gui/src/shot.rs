//! Headless **screenshot mode** (dev/marketing tooling, NOT part of normal runs).
//!
//! Activated only when the env var `ALICE_MINER_SHOT_DIR` is set to a directory.
//! In that mode the app drives a tiny per-frame state machine that forces the
//! UI into specific states (Home idle, Home mining, Dashboard mining), captures
//! each via **eframe/egui's own render-target screenshot** (so it needs NO OS
//! screen-recording permission — `screencapture`/TCC is bypassed entirely),
//! writes the PNGs into the directory, and then closes the window.
//!
//! Capture protocol (egui 0.34): on the frame a shot is wanted we send
//! [`egui::ViewportCommand::Screenshot`]; egui renders, then delivers the pixels
//! as an [`egui::Event::Screenshot`] on the FOLLOWING frame, which we read out of
//! `ctx.input(..).events` and save with the `image` crate.
//!
//! Everything here is inert unless the env var is present — see
//! [`ShotRunner::from_env`] returning `None`. The hooks in `app.rs` are all
//! guarded behind `app.shot.is_some()`, so normal launches are byte-for-byte
//! unchanged.

use std::path::PathBuf;
use std::sync::Arc;

use alice_miner_core::{DeviceProfile, EngineState, GpuInfo, GpuVendor, Lane, OsFamily};
use alice_miner_core::engine::Snapshot;
use eframe::egui;

use crate::app::{MinerApp, Screen};

/// Frames to let layout / fonts / textures / the breathing glow settle before
/// each capture. The hero loads its mark texture on the first chrome render and
/// the gauge tweens, so a handful of frames gives a clean, fully-painted shot.
const SETTLE_FRAMES: u32 = 8;
/// Safety bound: if a capture never comes back (empty event), give up on this
/// step after this many frames rather than spinning forever.
const MAX_FRAMES_PER_STEP: u32 = 240;

/// One scripted screenshot: the output filename + how to pose the app for it.
struct Shot {
    file: &'static str,
    pose: fn(&mut MinerApp),
}

/// Where we are within a single shot.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Posing + letting frames settle; `frame` counts up to `SETTLE_FRAMES`.
    Settling,
    /// Screenshot command sent; waiting for the `Event::Screenshot` next frame.
    Awaiting,
}

/// The screenshot-mode driver. Lives in `Option` on the app; `None` ⇒ normal run.
pub struct ShotRunner {
    dir: PathBuf,
    shots: Vec<Shot>,
    /// Index of the shot currently being produced.
    idx: usize,
    phase: Phase,
    /// Frames elapsed in the current phase/step.
    frame: u32,
    /// Set once the last shot is saved → on the next frame we ask to close.
    done: bool,
}

impl ShotRunner {
    /// Build the runner iff `ALICE_MINER_SHOT_DIR` is set. Creates the directory
    /// (and parents). Returns `None` for a normal run (env var absent).
    pub fn from_env() -> Option<Self> {
        let dir = std::env::var_os("ALICE_MINER_SHOT_DIR").map(PathBuf::from)?;
        if let Err(e) = std::fs::create_dir_all(&dir) {
            eprintln!(
                "[shot] could not create ALICE_MINER_SHOT_DIR {}: {e}",
                dir.display()
            );
        }
        eprintln!("[shot] screenshot mode → {}", dir.display());
        Some(Self {
            dir,
            shots: vec![
                // The M2 state matrix the milestone asks to self-verify.
                Shot { file: "home-idle.png", pose: pose_home_idle },
                Shot { file: "home-connecting.png", pose: pose_home_connecting },
                Shot { file: "home-mining.png", pose: pose_home_mining },
                Shot { file: "home-error.png", pose: pose_home_error },
                Shot { file: "home-stopping.png", pose: pose_home_stopping },
                Shot { file: "onboarding-create.png", pose: pose_ob_create },
                Shot { file: "onboarding-backup.png", pose: pose_ob_backup },
                Shot { file: "onboarding-confirm.png", pose: pose_ob_confirm },
                Shot { file: "dashboard.png", pose: pose_dashboard_mining },
                Shot { file: "settings.png", pose: pose_settings },
                // Reduced-motion variants (same states, motion off) — proves the
                // colour/state semantics survive without pulses/sweeps/tween.
                Shot { file: "home-mining-reduced-motion.png", pose: pose_home_mining_rm },
                // ── M3: lane viability on Home ──────────────────────────────
                // This Mac (Apple Silicon): RVN shows "coming soon", XMR default.
                Shot { file: "home-idle-lanes-apple.png", pose: pose_home_idle },
                // A simulated NVIDIA box: RVN becomes selectable + recommended.
                Shot { file: "home-idle-lanes-nvidia.png", pose: pose_home_idle_nvidia },
                // The same NVIDIA box's dashboard (RVN row reads "ready").
                Shot { file: "dashboard-nvidia.png", pose: pose_dashboard_nvidia },
                // ── M4: dual-mine + failover ────────────────────────────────
                // This Mac (Apple Silicon): the dual-mine toggle renders DISABLED
                // ("needs a supported GPU") — honest gating. (Same Home-idle shot
                // but named so it's easy to inspect the disabled toggle row.)
                Shot { file: "home-idle-dual-disabled-apple.png", pose: pose_home_idle },
                // A simulated NVIDIA box: the dual-mine toggle is ENABLED.
                Shot { file: "home-idle-dual-enabled-nvidia.png", pose: pose_home_dual_enabled_nvidia },
                // The dual-mine dashboard (NVIDIA box): BOTH lane rows live + an
                // active "failed over" endpoint note.
                Shot { file: "dashboard-dual-failover.png", pose: pose_dashboard_dual_failover },
                // ── M5: dashboard depth + Source-B credit ───────────────────
                // The deepened dashboard while mining: Source-A "Local activity"
                // section + the Source-B "Server-confirmed credit" NotExposed panel
                // (honest: accounting live, payout off, explorer deep-link) + the
                // reconciliation badge ("activity flowing").
                Shot { file: "dashboard-m5-mining.png", pose: pose_dashboard_m5_mining },
                // The M3 follow-up FIX, visualised: dashboard IDLE on an NVIDIA box
                // with RVN selected → RVN row reads "ready" + the Connection
                // endpoint reflects the lane. Reconciliation badge reads "idle".
                Shot { file: "dashboard-m5-idle-rvn-endpoint.png", pose: pose_dashboard_m5_idle_rvn },
                // The DEFINITIVE :8888 proof (short page): Settings → Network on an
                // NVIDIA box, RVN selected → Endpoint reads :8888, not :3333.
                Shot { file: "settings-m5-rvn-endpoint.png", pose: pose_settings_rvn_endpoint },
                // The Source-B fast-follow path rendered honestly: a CONFIRMED
                // credit state shows ONLY "pending" (never the number) + "in sync".
                Shot { file: "dashboard-m5-credit-confirmed.png", pose: pose_dashboard_m5_confirmed },
            ],
            idx: 0,
            phase: Phase::Settling,
            frame: 0,
            done: false,
        })
    }

    /// The window size to request in shot mode — the SAME as the real default
    /// (see `main.rs`), so the captures show exactly what the owner sees on first
    /// run. The scroll areas in each screen body guarantee nothing clips at this
    /// size (or at the smaller `min_inner_size`).
    pub fn window_size() -> [f32; 2] {
        [1120.0, 800.0]
    }
}

/// Per-frame driver, called at the very top of `MinerApp::ui` when shot mode is
/// active. Poses the app for the current shot, requests/saves the capture, and
/// advances; closes the viewport after the last one. Always requests a repaint
/// so the headless event loop keeps ticking frames without user input.
///
/// Returns nothing; mutates `app` (its `shot` field included) in place.
pub fn drive(app: &mut MinerApp, ctx: &egui::Context) {
    // Keep the frame loop alive headlessly.
    ctx.request_repaint();

    // Take the runner out so we can borrow `app` mutably for posing.
    let mut runner = match app.shot.take() {
        Some(r) => r,
        None => return,
    };

    // All shots done → request close, then drop the runner (leaving `None`).
    if runner.done {
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        return; // runner dropped → app.shot stays None
    }

    // Defensive: nothing to do (shouldn't happen) → close.
    if runner.idx >= runner.shots.len() {
        runner.done = true;
        app.shot = Some(runner);
        return;
    }

    match runner.phase {
        Phase::Settling => {
            // Re-pose every settle frame so the injected state is not clobbered
            // by anything else (and `tick_anim` keeps the gauge pinned).
            (runner.shots[runner.idx].pose)(app);
            if runner.frame >= SETTLE_FRAMES {
                // Ask egui for the framebuffer; it arrives next frame as an event.
                ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(
                    egui::UserData::default(),
                ));
                runner.phase = Phase::Awaiting;
                runner.frame = 0;
            } else {
                runner.frame += 1;
            }
        }
        Phase::Awaiting => {
            // Re-pose (the capture frame paints this) and look for the result.
            (runner.shots[runner.idx].pose)(app);
            let image = ctx.input(|i| {
                i.events.iter().rev().find_map(|e| {
                    if let egui::Event::Screenshot { image, .. } = e {
                        Some(image.clone())
                    } else {
                        None
                    }
                })
            });
            if let Some(image) = image {
                let path = runner.dir.join(runner.shots[runner.idx].file);
                match save_png(&image, &path) {
                    Ok(()) => {
                        let [w, h] = image.size;
                        eprintln!("[shot] saved {} ({}×{})", path.display(), w, h);
                    }
                    Err(e) => eprintln!("[shot] FAILED to save {}: {e}", path.display()),
                }
                // Advance to the next shot (or finish).
                runner.idx += 1;
                runner.frame = 0;
                runner.phase = Phase::Settling;
                if runner.idx >= runner.shots.len() {
                    runner.done = true;
                }
            } else if runner.frame >= MAX_FRAMES_PER_STEP {
                // Capture never arrived — retry with a longer settle window.
                eprintln!(
                    "[shot] no screenshot event for {} after {} frames; retrying with more settle frames",
                    runner.shots[runner.idx].file, runner.frame
                );
                runner.phase = Phase::Settling;
                runner.frame = 0;
            } else {
                runner.frame += 1;
            }
        }
    }

    app.shot = Some(runner);
}

// ── Poses ───────────────────────────────────────────────────────────────────
// Each pose forces the app into a deterministic state WITHOUT the real engine:
// it overrides `screen`, `onboarding`, `snapshot`, and the animation fields so
// the hero/cards read exactly as designed. Re-applied every shot frame.

/// A demo device line so the model row reads like a real machine (this Mac:
/// Apple Silicon, unified-memory GPU → RVN is "coming soon", XMR is the lane).
fn demo_device() -> DeviceProfile {
    DeviceProfile {
        os: OsFamily::Macos,
        arch: "aarch64".into(),
        apple_silicon: true,
        logical_cores: 12,
        cpu_model: "Apple M2 Max".into(),
        gpu: GpuInfo {
            vendor: GpuVendor::Apple,
            model: "Apple M2 Max".into(),
            vram_gb: 0,
        },
        memory_gb: 32,
        display: "Apple M2 Max · 12 cores".into(),
        warnings: vec![],
    }
}

/// A simulated NVIDIA box (for the M3 lane-select shot): RVN becomes selectable
/// and recommended. NOT this Mac — purely a posed capture to prove the UI flips.
fn demo_nvidia_device() -> DeviceProfile {
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
        },
        memory_gb: 64,
        display: "AMD Ryzen 9 5950X · 16 cores".into(),
        warnings: vec![],
    }
}

/// A demo *mining* snapshot: ~8400 H/s, 142/1 shares, XMR lane, the public relay
/// endpoint, a worker id, and some uptime — the credit-only activity shape only.
fn demo_mining_snapshot() -> Snapshot {
    Snapshot {
        state: EngineState::Running,
        device: Some(demo_device()),
        lane: Some(Lane::Xmr),
        hashrate_hs: Some(8400.0),
        shares_accepted: 142,
        shares_rejected: 1,
        endpoint: Some("hk.aliceprotocol.org:3333".into()),
        worker_id: Some("rig-7f3a9c21".into()),
        uptime_s: 2 * 3600 + 14 * 60 + 9, // 02:14:09
        failovers: 0,
        dual: false,
        lanes: Vec::new(),
        last_line: Some("accepted (142/1) diff 32001 (12 ms)".into()),
        message: None,
    }
}

/// Pin the animation fields so the gauge ring reads ~0.9 and the readout shows
/// the live number immediately (no waiting on the per-frame tween).
fn pin_mining_anim(app: &mut MinerApp, hashrate_khs: f32) {
    app.hr_display_khs = hashrate_khs;
    // gauge() = hr_display / gauge_ceiling, clamped — target ≈ 0.9.
    app.gauge_ceiling_khs = hashrate_khs / 0.9;
    // A gently rising sparkline for the dashboard hashrate card.
    if app.spark.is_empty() {
        let base = hashrate_khs;
        for i in 0..28 {
            let w = 0.82 + 0.18 * (i as f32 / 27.0); // ramp up to current
            let jitter = 0.04 * ((i as f32 * 1.3).sin());
            app.spark.push_back((base * (w + jitter)).max(0.0));
        }
    }
}

/// Seed a short, realistic log tail for the dashboard log panel.
fn seed_log(app: &mut MinerApp) {
    if !app.log.is_empty() {
        return;
    }
    for line in [
        "RandomX dataset allocated (2080 MiB)",
        "connected to hk.aliceprotocol.org:3333",
        "new job from relay diff 32001",
        "accepted (139/1) diff 32001 (11 ms)",
        "speed 10s/60s/15m 8.41 8.39 8.40 kH/s",
        "accepted (142/1) diff 32001 (12 ms)",
    ] {
        app.log.push_back(line.to_string());
    }
}

/// A demo identity pointer so the "Rewards to <addr>" row + dashboard worker copy
/// render with a realistic SS58-300 address (NOT a collection address).
fn install_demo_identity(app: &mut MinerApp) {
    if app.identity.is_none() {
        app.identity = Some(alice_miner_core::identity::IdentityPointer {
            address: "a2x9k4f7q2w8e3r5t6y1u0p9s8d7f6g5h4j3k2l1z0x9c8v7b6n5m4Q".into(),
            pubkey: None,
            keystore_path: None,
            label: None,
            created: 0,
        });
    }
}

/// A non-running snapshot in a specific lifecycle state (connecting / error /
/// stopping), carrying the device + an optional calm message.
fn demo_state_snapshot(state: EngineState, message: Option<&str>) -> Snapshot {
    Snapshot {
        state,
        device: Some(demo_device()),
        lane: Some(Lane::Xmr),
        hashrate_hs: None,
        shares_accepted: 0,
        shares_rejected: 0,
        endpoint: Some("hk.aliceprotocol.org:3333".into()),
        worker_id: Some("rig-7f3a9c21".into()),
        uptime_s: 0,
        failovers: 0,
        dual: false,
        lanes: Vec::new(),
        last_line: None,
        message: message.map(|m| m.to_string()),
    }
}

fn pose_home_idle(app: &mut MinerApp) {
    app.onboarding = None; // identity exists on disk → skip onboarding
    app.screen = Screen::Home;
    app.snapshot = None; // no snapshot ⇒ EngineState::Idle ⇒ START readout
    app.set_device(demo_device());
    install_demo_identity(app);
    app.error = None;
    app.hr_display_khs = 0.0;
}

fn pose_home_connecting(app: &mut MinerApp) {
    app.onboarding = None;
    app.screen = Screen::Home;
    app.set_device(demo_device());
    install_demo_identity(app);
    app.error = None;
    app.snapshot = Some(demo_state_snapshot(EngineState::Starting, None));
    app.hr_display_khs = 0.0;
}

fn pose_home_error(app: &mut MinerApp) {
    app.onboarding = None;
    app.screen = Screen::Home;
    app.set_device(demo_device());
    install_demo_identity(app);
    app.error = None;
    // A calm, human reason — not a stack dump.
    app.snapshot = Some(demo_state_snapshot(
        EngineState::Error,
        Some("Lost connection to the relay. You can start again."),
    ));
    app.hr_display_khs = 0.0;
}

fn pose_home_stopping(app: &mut MinerApp) {
    app.onboarding = None;
    app.screen = Screen::Home;
    app.set_device(demo_device());
    install_demo_identity(app);
    app.error = None;
    app.snapshot = Some(demo_state_snapshot(EngineState::Stopping, None));
    // A little residual hashrate as the child winds down.
    app.hr_display_khs = 3.1;
    app.gauge_ceiling_khs = 9.3;
}

fn pose_ob_create(app: &mut MinerApp) {
    app.screen = Screen::Home;
    app.set_device(demo_device());
    app.identity = None;
    app.error = None;
    app.snapshot = None; // engine idle during onboarding → titlebar pill "Idle"
    app.onboarding = Some(crate::app::Onboarding::Choose);
}

/// The forced-backup step: a fixed demo 24-word phrase in the grid (NOT a real
/// key — screenshot tooling only).
fn pose_ob_backup(app: &mut MinerApp) {
    app.screen = Screen::Home;
    app.set_device(demo_device());
    app.identity = None;
    app.error = None;
    app.snapshot = None;
    app.onboarding = Some(crate::app::Onboarding::Backup {
        mnemonic: DEMO_MNEMONIC.to_string(),
        acknowledged: true,
    });
}

/// The confirm-by-retyping step, posed mid-fill (one slot filled, two empty) so
/// the slots + chip pool + the "tap word" placeholders are all visible.
fn pose_ob_confirm(app: &mut MinerApp) {
    app.screen = Screen::Home;
    app.set_device(demo_device());
    app.identity = None;
    app.error = None;
    app.snapshot = None;
    if !matches!(app.onboarding, Some(crate::app::Onboarding::Confirm { .. })) {
        // Build the confirm state deterministically for the shot (fixed targets +
        // a fixed pool so the capture is stable frame-to-frame).
        let words: Vec<&str> = DEMO_MNEMONIC.split_whitespace().collect();
        app.confirm_targets = vec![3, 9, 11];
        app.confirm_filled = vec![Some(words[2].to_string()), None, None];
        app.confirm_pool = vec![
            words[2].to_string(),
            words[8].to_string(),
            words[10].to_string(),
            words[0].to_string(),
            words[5].to_string(),
            words[15].to_string(),
            words[20].to_string(),
            words[18].to_string(),
        ];
        app.onboarding = Some(crate::app::Onboarding::Confirm {
            mnemonic: DEMO_MNEMONIC.to_string(),
        });
    }
}

fn pose_settings(app: &mut MinerApp) {
    app.onboarding = None;
    app.screen = Screen::Settings;
    app.set_device(demo_device());
    install_demo_identity(app);
    app.error = None;
    app.snapshot = Some(demo_mining_snapshot());
}

fn pose_home_mining_rm(app: &mut MinerApp) {
    pose_home_mining(app);
    app.reduce_motion = true;
}

/// A fixed demo 24-word mnemonic for the onboarding screenshots. These are real
/// BIP39 words but an arbitrary, NON-secret sequence used only by shot tooling.
const DEMO_MNEMONIC: &str = "harvest copper lunar ribbon orbit tundra cipher meadow violet anchor summit frost \
hazard pioneer velvet cradle ginger lantern marble pottery sunset timber walnut zephyr";

fn pose_home_mining(app: &mut MinerApp) {
    app.onboarding = None;
    app.screen = Screen::Home;
    app.set_device(demo_device());
    app.error = None;
    app.snapshot = Some(demo_mining_snapshot());
    pin_mining_anim(app, 8.4);
}

fn pose_dashboard_mining(app: &mut MinerApp) {
    app.onboarding = None;
    app.screen = Screen::Dashboard;
    app.set_device(demo_device());
    app.error = None;
    app.snapshot = Some(demo_mining_snapshot());
    pin_mining_anim(app, 8.4);
    seed_log(app);
}

/// M3: Home idle on a SIMULATED NVIDIA box — RVN becomes selectable + the
/// recommended/default lane (proves the viability matrix flips the UI). NOT this
/// Mac; a posed capture only.
fn pose_home_idle_nvidia(app: &mut MinerApp) {
    app.onboarding = None;
    app.screen = Screen::Home;
    app.set_device(demo_nvidia_device()); // recomputes viability → RVN recommended
    install_demo_identity(app);
    app.error = None;
    app.snapshot = None;
    app.hr_display_khs = 0.0;
}

/// M3: the NVIDIA box's dashboard — the RVN lane row reads "ready" (viable).
fn pose_dashboard_nvidia(app: &mut MinerApp) {
    app.onboarding = None;
    app.screen = Screen::Dashboard;
    app.set_device(demo_nvidia_device());
    install_demo_identity(app);
    app.error = None;
    // Idle (not mining) so both lane rows show their viability state cleanly.
    app.snapshot = None;
    app.hr_display_khs = 0.0;
    seed_log(app);
}

/// M4: Home idle on a simulated NVIDIA box with dual-mine TURNED ON — the toggle
/// is enabled (≥2 viable lanes) and reads active. Proves the gating flips on a
/// supported GPU. NOT this Mac; a posed capture only.
fn pose_home_dual_enabled_nvidia(app: &mut MinerApp) {
    app.onboarding = None;
    app.screen = Screen::Home;
    app.set_device(demo_nvidia_device()); // RVN viable → dual_viable() == true
    install_demo_identity(app);
    app.error = None;
    app.snapshot = None;
    app.hr_display_khs = 0.0;
    app.dual_requested = true; // toggle ON (the confirm already acknowledged)
    app.dual_confirm_open = false;
}

/// A dual-mine *running* snapshot: BOTH lanes live (CPU-XMR + GPU-RVN), with the
/// XMR lane having failed over once to demonstrate the M4 endpoint note. The
/// per-lane breakdown drives the two-row lane stack; top-level mirrors the
/// (XMR) primary with a summed hashrate. Credit-only activity only.
fn demo_dual_snapshot() -> Snapshot {
    Snapshot {
        state: EngineState::Running,
        device: Some(demo_nvidia_device()),
        lane: Some(Lane::Xmr),
        // Top-level hashrate = XMR (8.4 kH/s) + RVN (25.4 MH/s) summed in H/s.
        hashrate_hs: Some(8_400.0 + 25_430_000.0),
        shares_accepted: 142 + except_rvn_accepted(),
        shares_rejected: 1,
        endpoint: Some("hk.aliceprotocol.org:3333".into()),
        worker_id: Some("rig-7f3a9c21".into()),
        uptime_s: 47 * 60 + 12,
        failovers: 1, // the XMR lane rotated once (Layer B)
        dual: true,
        lanes: vec![
            alice_miner_core::engine::LaneSnapshot {
                lane: Lane::Xmr,
                state: EngineState::Running,
                hashrate_hs: Some(8_400.0),
                shares_accepted: 142,
                shares_rejected: 1,
                endpoint: Some("hk.aliceprotocol.org:3333".into()),
                failovers: 1,
            },
            alice_miner_core::engine::LaneSnapshot {
                lane: Lane::GpuRvn,
                state: EngineState::Running,
                hashrate_hs: Some(25_430_000.0),
                shares_accepted: except_rvn_accepted(),
                shares_rejected: 0,
                endpoint: Some("hk.aliceprotocol.org:8888".into()),
                failovers: 0,
            },
        ],
        last_line: Some("accepted (142/1) diff 32001 (12 ms)".into()),
        message: None,
    }
}

/// A fixed RVN accepted-share count for the dual demo (kept as a fn so both the
/// per-lane row and the top-level sum use the same value).
fn except_rvn_accepted() -> u64 {
    58
}

/// M4: the dual-mine dashboard (NVIDIA box) — BOTH lane rows live, each with its
/// own hashrate + shares, and the connection panel shows the "failed over" note.
fn pose_dashboard_dual_failover(app: &mut MinerApp) {
    app.onboarding = None;
    app.screen = Screen::Dashboard;
    app.set_device(demo_nvidia_device());
    install_demo_identity(app);
    app.error = None;
    app.snapshot = Some(demo_dual_snapshot());
    // The top-level (summed) hashrate is dominated by the GPU lane — pin the
    // display so the header/cards read a stable big number.
    pin_mining_anim(app, (8_400.0 + 25_430_000.0) / 1000.0);
    seed_log(app);
}

// ── M5 poses (dashboard depth + Source-B credit) ─────────────────────────────

/// M5: the deepened dashboard while mining (this Mac, XMR lane). Shows the
/// Source-A "Local activity" section + the Source-B "Server-confirmed credit"
/// NotExposed panel + the "activity flowing" reconciliation badge.
fn pose_dashboard_m5_mining(app: &mut MinerApp) {
    app.onboarding = None;
    app.screen = Screen::Dashboard;
    app.set_device(demo_device());
    install_demo_identity(app);
    app.error = None;
    app.snapshot = Some(demo_mining_snapshot());
    pin_mining_anim(app, 8.4);
    seed_log(app);
    // v1 Source-B reality: no public per-address endpoint → the honest panel.
    app.credit_state = alice_miner_core::CreditState::NotExposed;
}

/// M5 (the M3 follow-up FIX visualised): dashboard IDLE on a simulated NVIDIA box
/// with the RVN lane SELECTED — the Connection endpoint must read :8888, NOT the
/// old hardcoded :3333. Not mining, so the lane rows + endpoint show the idle
/// (selected-lane) state.
fn pose_dashboard_m5_idle_rvn(app: &mut MinerApp) {
    app.onboarding = None;
    app.screen = Screen::Dashboard;
    app.set_device(demo_nvidia_device()); // RVN becomes runnable
    install_demo_identity(app);
    app.error = None;
    app.snapshot = None; // idle / not connected → display_endpoint uses the lane
    app.select_lane(Lane::GpuRvn); // → :8888 (the fix)
    app.hr_display_khs = 0.0;
    app.credit_state = alice_miner_core::CreditState::NotExposed;
}

/// M5 (the M3 follow-up FIX, definitive visual proof): the Settings → Network
/// panel on a simulated NVIDIA box with RVN selected. Settings is a short page so
/// the Network "Endpoint" row — which uses the SAME lane-aware `display_endpoint()`
/// — is clearly in view, reading `hk.aliceprotocol.org:8888` (NOT the old
/// hardcoded :3333) while idle.
fn pose_settings_rvn_endpoint(app: &mut MinerApp) {
    app.onboarding = None;
    app.screen = Screen::Settings;
    app.set_device(demo_nvidia_device()); // RVN runnable
    install_demo_identity(app);
    app.error = None;
    app.snapshot = None; // idle → endpoint reflects the selected lane
    app.select_lane(Lane::GpuRvn); // → :8888 (the fix)
}

/// M5: the Source-B fast-follow path rendered honestly — a CONFIRMED credit state
/// (as if a live public read-model endpoint had confirmed credit for this
/// address). The panel shows ONLY "pending" (NEVER the magnitude) + the
/// reconciliation badge reads "in sync". Proves the credit-only rendering holds
/// even on the confirmed path. (Posed only; the live client ships NotExposed.)
fn pose_dashboard_m5_confirmed(app: &mut MinerApp) {
    app.onboarding = None;
    app.screen = Screen::Dashboard;
    app.set_device(demo_device());
    install_demo_identity(app);
    app.error = None;
    app.snapshot = Some(demo_mining_snapshot());
    pin_mining_anim(app, 8.4);
    seed_log(app);
    // A confirmed (non-zero) credit score — but the UI renders only "pending".
    app.credit_state = alice_miner_core::CreditState::Confirmed {
        score: alice_miner_core::CreditScore::new(12.56),
    };
}

// ── PNG writer ────────────────────────────────────────────────────────────────

/// Save an egui screenshot [`egui::ColorImage`] to a PNG via the `image` crate.
/// The image is RGBA8 row-major top-to-bottom: width/height from `image.size`,
/// bytes from `as_raw()` (premultiplied, but the opaque UI ⇒ identical to
/// straight RGBA).
fn save_png(image: &Arc<egui::ColorImage>, path: &std::path::Path) -> Result<(), String> {
    let [w, h] = image.size;
    let buf = image::RgbaImage::from_raw(w as u32, h as u32, image.as_raw().to_vec())
        .ok_or_else(|| "RGBA buffer size mismatch".to_string())?;
    buf.save(path).map_err(|e| e.to_string())
}
