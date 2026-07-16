//! Platform helpers for renderer selection, remote-session detection, startup
//! logging, and native error dialogs.
//!
//! ## Why this exists (soak bug, 2026-07-16)
//!
//! An external tester on Windows + RTX 3080, connected over a **remote-desktop**
//! session (DeskIn; the same class as RDP / AnyDesk), reported that both
//! `AliceMiner.exe` and the Wallet open to a **solid-white window** — while the
//! headless CLI works fine. That is the classic eframe/egui failure mode on a
//! remote session: the default OpenGL backend (`glow`) is handed a broken or
//! purely-software GL context by the remote display driver, so the app *runs*
//! but never paints anything (no crash, no error — just white).
//!
//! The robust fix is to run the **`wgpu`** backend (DX12/DX11, and — crucially —
//! with a WARP software adapter available), since Direct3D survives remote
//! desktops where OpenGL does not.
//!
//! ## What is (and is NOT) auto-detected
//!
//! `GetSystemMetrics(SM_REMOTESESSION)` only reports `true` for a genuine Windows
//! **Terminal Services / RDP** *client* session (the built-in `mstsc` remote
//! desktop). Mirror / console-sharing tools — **DeskIn** (what the tester used),
//! AnyDesk, TeamViewer, Parsec, Sunflower, Chrome Remote Desktop, Splashtop —
//! attach to the **physical console** session, so Windows reports them as *not*
//! remote and the auto-switch to wgpu does **not** fire for them. There is no
//! reliable API to tell "someone is mirroring my console" apart from a genuine
//! local user, so we deliberately do **not** guess (guessing would white-screen-
//! proof RDP at the cost of wrongly flagging local users, which the soak
//! discipline forbids). Instead:
//!   * `docs/remote-desktop.md` tells mirror-tool users to set
//!     `ALICE_GUI_RENDERER=wgpu` manually (the reliable path for that class), and
//!   * once the glow window is up we read the live OpenGL renderer string and, if
//!     it is a **software** rasterizer (`GDI Generic`, `llvmpipe`, …) — the actual
//!     white-screen signature, and a factual signal with no local false positive —
//!     we log it and surface wgpu guidance (see `is_software_gl_renderer` +
//!     `main.rs`).
//!
//! This module centralises the renderer decision, the `ALICE_GUI_RENDERER`
//! override, a startup log, and a native error dialog so a hard init failure — or
//! a running-but-software-GL window — surfaces as a message the user can act on
//! instead of a white void.

use std::io::Write;
use std::path::PathBuf;

use eframe::Renderer;

/// The renderer we asked eframe to use, plus context for the startup log and the
/// error dialog.
pub struct RendererDecision {
    /// The concrete eframe backend.
    pub renderer: Renderer,
    /// Short stable name for logs / dialogs (`"glow"` | `"wgpu"`).
    pub name: &'static str,
    /// Whether we detected a Windows remote-desktop session.
    pub remote: bool,
    /// Human-readable reason the choice was made (logged).
    pub reason: String,
}

/// `true` when the process is running inside a Windows Terminal Services / RDP
/// **client** session, via `GetSystemMetrics(SM_REMOTESESSION)` — the signal
/// Microsoft documents for "am I on a remote desktop". Always `false` off
/// Windows.
///
/// NOTE (detection scope): this is `true` only for a genuine RDP / Terminal
/// Services session (`mstsc`). Mirror / console-sharing tools — DeskIn, AnyDesk,
/// TeamViewer, Parsec, Sunflower, Chrome Remote Desktop — run in the physical
/// console session and return `false` here, so they are NOT auto-switched to
/// wgpu; those users set `ALICE_GUI_RENDERER=wgpu` manually (see the module docs
/// and `docs/remote-desktop.md`). The live-GL-renderer probe in `main.rs` is the
/// runtime backstop that still catches the software-context case for them.
///
/// The call is a side-effect-free integer query, so the `unsafe` FFI is trivially
/// sound (no pointers, no allocation, no state).
pub fn is_remote_session() -> bool {
    #[cfg(windows)]
    {
        // winuser.h: SM_REMOTESESSION = 0x1000.
        const SM_REMOTESESSION: i32 = 0x1000;
        #[link(name = "user32")]
        extern "system" {
            fn GetSystemMetrics(n_index: i32) -> i32;
        }
        // SAFETY: GetSystemMetrics takes an integer and returns an integer; there
        // are no pointers or lifetimes involved.
        unsafe { GetSystemMetrics(SM_REMOTESESSION) != 0 }
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// `true` when an OpenGL `GL_RENDERER` string names a known **software**
/// rasterizer rather than a real GPU. This is the runtime backstop for the
/// mirror-tool case (DeskIn/AnyDesk/…), which `is_remote_session` cannot see:
/// when a remote/console-sharing driver hands glow a software GL context, egui
/// paints a solid-white window, and that context reports one of these names.
///
/// Crucially this is a **factual** test, not a heuristic — a local user with a
/// working GPU reports a hardware string (`NVIDIA GeForce …`, `Apple M2 …`,
/// `AMD Radeon …`), never one of these markers — so it carries **no local false
/// positive** and only ever fires when OpenGL genuinely fell back to software.
pub fn is_software_gl_renderer(renderer: &str) -> bool {
    let r = renderer.to_ascii_lowercase();
    // Case-insensitive substrings that only appear in software GL backends.
    const SOFTWARE_MARKERS: [&str; 6] = [
        // Windows built-in OpenGL 1.1 (no GPU) — the classic remote-desktop white screen.
        "gdi generic",
        // Mesa software rasterizers.
        "llvmpipe",
        "softpipe",
        // Google software GL.
        "swiftshader",
        // Generic self-descriptions / WARP-style software device names.
        "software rasterizer",
        "microsoft basic render",
    ];
    SOFTWARE_MARKERS.iter().any(|m| r.contains(m))
}

/// Decide which renderer to run, in priority order:
///
/// 1. `ALICE_GUI_RENDERER=glow|wgpu` forces the backend (aliases: `gl`/`opengl`
///    → glow; `wgpu`/`dx12`/`directx`/`vulkan`/`metal` → wgpu). An unrecognised
///    value is ignored (and noted in the reason) so a typo can never wedge the
///    launcher.
/// 2. Otherwise, in a genuine Windows RDP / Terminal Services session
///    (`SM_REMOTESESSION`; NOT mirror tools like DeskIn/AnyDesk — see
///    `is_remote_session`), default to **wgpu** (OpenGL/glow white-screens over
///    RDP).
/// 3. Otherwise the shipping default, **glow** (unchanged for every local user).
pub fn choose_renderer() -> RendererDecision {
    let remote = is_remote_session();

    if let Ok(raw) = std::env::var("ALICE_GUI_RENDERER") {
        let v = raw.trim().to_ascii_lowercase();
        match v.as_str() {
            "glow" | "gl" | "opengl" => {
                return RendererDecision {
                    renderer: Renderer::Glow,
                    name: "glow",
                    remote,
                    reason: format!("forced by ALICE_GUI_RENDERER={raw:?}"),
                };
            }
            "wgpu" | "dx12" | "dx" | "directx" | "d3d" | "vulkan" | "metal" => {
                return RendererDecision {
                    renderer: Renderer::Wgpu,
                    name: "wgpu",
                    remote,
                    reason: format!("forced by ALICE_GUI_RENDERER={raw:?}"),
                };
            }
            _ => {
                // Fall through to the auto choice below, but record the typo.
                let (renderer, name) = if remote {
                    (Renderer::Wgpu, "wgpu")
                } else {
                    (Renderer::Glow, "glow")
                };
                return RendererDecision {
                    renderer,
                    name,
                    remote,
                    reason: format!(
                        "auto ({}); ALICE_GUI_RENDERER={raw:?} not recognised, ignored",
                        if remote { "remote session" } else { "local session" }
                    ),
                };
            }
        }
    }

    if remote {
        RendererDecision {
            renderer: Renderer::Wgpu,
            name: "wgpu",
            remote,
            reason: "remote-desktop session detected -> wgpu (OpenGL/glow white-screens over RDP)"
                .to_string(),
        }
    } else {
        RendererDecision {
            renderer: Renderer::Glow,
            name: "glow",
            remote,
            reason: "local session -> glow (default)".to_string(),
        }
    }
}

/// The GUI startup-log path: `<data_local_dir>/AliceMiner/logs/gui-startup.log`
/// (created on demand), falling back to the system temp dir if there's no OS data
/// dir. DELIBERATELY under the AliceMiner data dir, never the `~/.alice` keystore
/// root — a diagnostic log must never sit next to a key (matches the `ai_log_dir`
/// / `agent_log_path` convention in `alice-miner-core`).
pub fn gui_log_path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("AliceMiner")
        .join("logs")
        .join("gui-startup.log")
}

/// Append a timestamped line to the GUI startup log. Best-effort: every IO error
/// is swallowed (diagnostics must never block or crash the launcher). Caps the
/// file at ~256 KiB by starting fresh first, so a long-lived install can't grow
/// it without bound.
pub fn log_line(msg: &str) {
    let path = gui_log_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    const CAP: u64 = 256 * 1024;
    if std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) > CAP {
        let _ = std::fs::write(&path, b"");
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "{} {}", utc_stamp(), msg);
    }
}

/// A dependency-free UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`) for the startup log.
/// Uses Howard Hinnant's `civil_from_days` algorithm on the Unix epoch so we
/// don't pull in `chrono`/`time` for one log line.
fn utc_stamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Break a Unix timestamp (seconds, UTC) into `(year, month, day, hour, min,
/// sec)`. Pure integer arithmetic (Hinnant, "chrono-Compatible Low-Level Date
/// Algorithms"), valid across the full range we'll ever log.
fn civil_from_unix(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = (rem / 3600) as u32;
    let min = ((rem % 3600) / 60) as u32;
    let sec = (rem % 60) as u32;

    // Shift the epoch to 0000-03-01 to make leap-year handling branch-free.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if month <= 2 { year + 1 } else { year };

    (year, month, day, hour, min, sec)
}

/// Guidance shown when the graphics window fails to come up. Names the alternate
/// backend to try via `ALICE_GUI_RENDERER`, points at the headless CLI as a
/// no-graphics fallback, and cites the log path.
pub fn init_failure_message(tried: &str) -> String {
    let alt = if tried == "glow" { "wgpu" } else { "glow" };
    format!(
        "Alice Miner could not open its graphics window (renderer: {tried}).\n\n\
         This usually happens over remote desktop (RDP / DeskIn / AnyDesk) or on a \
         machine without a working GPU driver.\n\n\
         Try one of these:\n\
         \u{2022} Set the environment variable  ALICE_GUI_RENDERER={alt}  and relaunch.\n\
         \u{2022} Or use the command-line miner, which needs no graphics window:\n\
         \u{20}\u{20}\u{20}\u{20}alice-miner-cli\n\n\
         A startup log was written to:\n{log}",
        log = gui_log_path().display(),
    )
}

/// Guidance shown when the window *did* open but on a software OpenGL renderer
/// (see `is_software_gl_renderer`) — the running-but-white-screen case that a
/// mirror tool (DeskIn/AnyDesk) produces and that `is_remote_session` can't
/// pre-empt. Points at the wgpu override and the headless CLI, and cites the log.
pub fn software_gl_message(renderer: &str) -> String {
    format!(
        "Alice Miner is running, but Windows gave it a software OpenGL renderer \
         ({renderer}).\n\n\
         Over remote-control tools (DeskIn / AnyDesk / TeamViewer / RDP) this often \
         shows as a blank or white window — the app works, it just can't paint.\n\n\
         For reliable graphics:\n\
         \u{2022} Set the environment variable  ALICE_GUI_RENDERER=wgpu  and relaunch.\n\
         \u{2022} Or use the command-line miner, which needs no graphics window:\n\
         \u{20}\u{20}\u{20}\u{20}alice-miner-cli\n\n\
         A startup log was written to:\n{log}",
        log = gui_log_path().display(),
    )
}

/// Show a blocking native error dialog. On Windows this is a real `MessageBoxW`,
/// so it appears even when the egui window itself never painted; elsewhere it
/// falls back to stderr. `title` / `body` are plain UTF-8 text.
pub fn show_error_dialog(title: &str, body: &str) {
    #[cfg(windows)]
    {
        // winuser.h: MB_OK=0x0, MB_ICONERROR=0x10, MB_SETFOREGROUND=0x10000,
        // MB_TOPMOST=0x40000 — force it in front of the (blank) main window.
        const MB_OK: u32 = 0x0000_0000;
        const MB_ICONERROR: u32 = 0x0000_0010;
        const MB_SETFOREGROUND: u32 = 0x0001_0000;
        const MB_TOPMOST: u32 = 0x0004_0000;
        #[link(name = "user32")]
        extern "system" {
            fn MessageBoxW(
                hwnd: *mut core::ffi::c_void,
                text: *const u16,
                caption: *const u16,
                u_type: u32,
            ) -> i32;
        }
        let wide_body: Vec<u16> = body.encode_utf16().chain(std::iter::once(0)).collect();
        let wide_title: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: both buffers are NUL-terminated UTF-16 and outlive the call;
        // a null owner HWND is valid ("no owner window").
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                wide_body.as_ptr(),
                wide_title.as_ptr(),
                MB_OK | MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST,
            );
        }
    }
    #[cfg(not(windows))]
    {
        eprintln!("{title}: {body}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // ALICE_GUI_RENDERER is process-global; serialise the cases that touch it.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn env_override_selects_backend() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // Off Windows `is_remote_session()` is always false, so the auto choice is
        // deterministic (glow) and only the env override moves it.
        std::env::remove_var("ALICE_GUI_RENDERER");
        assert_eq!(choose_renderer().name, if is_remote_session() { "wgpu" } else { "glow" });

        for v in ["wgpu", "WGPU", " dx12 ", "vulkan", "metal"] {
            std::env::set_var("ALICE_GUI_RENDERER", v);
            let d = choose_renderer();
            assert_eq!(d.name, "wgpu", "value {v:?} should force wgpu");
            assert_eq!(d.renderer, Renderer::Wgpu);
        }

        for v in ["glow", "GLOW", "opengl", " gl "] {
            std::env::set_var("ALICE_GUI_RENDERER", v);
            let d = choose_renderer();
            assert_eq!(d.name, "glow", "value {v:?} should force glow");
            assert_eq!(d.renderer, Renderer::Glow);
        }

        // Unrecognised value → ignored, falls back to the auto choice, reason notes it.
        std::env::set_var("ALICE_GUI_RENDERER", "banana");
        let d = choose_renderer();
        assert!(d.reason.contains("not recognised"), "reason: {}", d.reason);

        std::env::remove_var("ALICE_GUI_RENDERER");
    }

    #[test]
    fn software_gl_renderer_flags_only_software_backends() {
        // Known software backends → flagged (case-insensitive, substring).
        for s in [
            "GDI Generic",
            "llvmpipe (LLVM 15.0.7, 256 bits)",
            "SwiftShader Device (Subzero)",
            "Software Rasterizer",
            "softpipe",
            "Microsoft Basic Render Driver",
        ] {
            assert!(is_software_gl_renderer(s), "{s:?} should read as software");
        }
        // Real GPUs (incl. the tester's RTX 3080) → never flagged: no local false
        // positive, so the wgpu guidance only fires when GL truly fell to software.
        for s in [
            "NVIDIA GeForce RTX 3080/PCIe/SSE2",
            "Apple M2 Max",
            "AMD Radeon RX 6800 XT",
            "Intel(R) UHD Graphics 630",
            "",
        ] {
            assert!(!is_software_gl_renderer(s), "{s:?} should read as hardware");
        }
    }

    #[test]
    fn software_gl_message_points_at_wgpu_and_the_cli() {
        let m = software_gl_message("GDI Generic");
        assert!(m.contains("ALICE_GUI_RENDERER=wgpu"));
        assert!(m.contains("alice-miner-cli"));
        assert!(m.contains("GDI Generic"));
    }

    #[test]
    fn is_remote_session_is_a_bool_and_does_not_panic() {
        // Off Windows this must be false; on Windows it just must not panic.
        let r = is_remote_session();
        #[cfg(not(windows))]
        assert!(!r);
        #[cfg(windows)]
        let _ = r;
    }

    #[test]
    fn log_path_is_under_aliceminer_and_not_the_keystore() {
        let p = gui_log_path();
        let s = p.to_string_lossy();
        assert!(s.contains("AliceMiner"), "log path: {s}");
        assert!(s.ends_with("gui-startup.log"), "log path: {s}");
        // Must never live under the ~/.alice keystore root.
        assert!(!s.contains("/.alice/"), "log must not be in the keystore: {s}");
    }

    #[test]
    fn init_failure_message_names_the_other_backend_and_the_cli() {
        let m = init_failure_message("glow");
        assert!(m.contains("ALICE_GUI_RENDERER=wgpu"));
        assert!(m.contains("alice-miner-cli"));
        let m2 = init_failure_message("wgpu");
        assert!(m2.contains("ALICE_GUI_RENDERER=glow"));
    }

    #[test]
    fn utc_stamp_matches_known_epochs() {
        // 1700000000 == 2023-11-14T22:13:20Z (verified against date -u).
        assert_eq!(civil_from_unix(1_700_000_000), (2023, 11, 14, 22, 13, 20));
        // Unix epoch itself.
        assert_eq!(civil_from_unix(0), (1970, 1, 1, 0, 0, 0));
        // A leap day: 2020-02-29T12:00:00Z == 1582977600.
        assert_eq!(civil_from_unix(1_582_977_600), (2020, 2, 29, 12, 0, 0));
        // Shape check on the formatted stamp.
        let s = utc_stamp();
        assert_eq!(s.len(), 20, "stamp: {s}");
        assert!(s.ends_with('Z'));
    }
}
