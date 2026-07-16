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
//! with a WARP software adapter available) whenever we detect a remote session,
//! since Direct3D survives remote desktops where OpenGL does not. This module
//! centralises that decision, an `ALICE_GUI_RENDERER` override, a startup log,
//! and a native error dialog so a hard init failure surfaces as a message the
//! user can act on instead of a white void.

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

/// `true` when the process is running inside a Windows Terminal Services / remote
/// desktop session, via `GetSystemMetrics(SM_REMOTESESSION)` — the signal
/// Microsoft documents for "am I on a remote desktop". Always `false` off
/// Windows. The call is a side-effect-free integer query, so the `unsafe` FFI is
/// trivially sound (no pointers, no allocation, no state).
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

/// Decide which renderer to run, in priority order:
///
/// 1. `ALICE_GUI_RENDERER=glow|wgpu` forces the backend (aliases: `gl`/`opengl`
///    → glow; `wgpu`/`dx12`/`directx`/`vulkan`/`metal` → wgpu). An unrecognised
///    value is ignored (and noted in the reason) so a typo can never wedge the
///    launcher.
/// 2. Otherwise, in a Windows remote-desktop session, default to **wgpu**
///    (OpenGL/glow white-screens over RDP).
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
