# Remote desktop & the "white window" fix

**Symptom.** You launch **AliceMiner** (or the Wallet) over a remote-desktop
connection — Windows RDP, DeskIn, AnyDesk, Parsec, TeamViewer, etc. — and the
window opens **solid white**. Nothing renders, but the app is actually running:
the command-line miner (`alice-miner-cli`) works fine on the same machine.

**Cause.** The desktop app draws with GPU acceleration. Its default backend is
**OpenGL** (`glow`). Many remote-desktop servers hand the app a broken or
software-only OpenGL context, so the window comes up but never paints — a white
void, with no crash and no error. This is a known egui/OpenGL limitation over
remote sessions, not an Alice bug.

## The fix (automatic)

As of **v0.6.1**, AliceMiner detects a Windows remote-desktop session at startup
(`GetSystemMetrics(SM_REMOTESESSION)`) and automatically switches to the
**`wgpu`** backend (Direct3D 12/11, with a software WARP adapter as a last
resort). Direct3D survives remote desktops where OpenGL does not, so the window
paints normally. Local (non-remote) launches are unchanged — they keep using
OpenGL/`glow`.

## Forcing a backend manually

If you still hit a blank window, or want to pick the backend yourself, set the
`ALICE_GUI_RENDERER` environment variable before launching:

| Value | Backend | When to use |
|-------|---------|-------------|
| `wgpu` | Direct3D 12/11 (+ WARP) | Remote desktop, or an OpenGL/OpenGL-driver problem |
| `glow` | OpenGL | Force the classic backend (e.g. to compare) |

**Windows (PowerShell):**

```powershell
$env:ALICE_GUI_RENDERER = "wgpu"
& "C:\Path\To\AliceMiner.exe"
```

**Windows (cmd.exe):**

```cmd
set ALICE_GUI_RENDERER=wgpu
AliceMiner.exe
```

## The headless fallback — no graphics window at all

The command-line miner never opens a graphics window, so it is immune to this
problem and is also the recommended path for headless GPU/ASIC rigs:

```
alice-miner-cli            # interactive menu
alice-miner-cli --help     # all commands
```

It drives the exact same mining engine as the desktop app, so you lose nothing
but the GUI.

## Startup log

Every launch appends a line to a diagnostic log recording the OS, whether a
remote session was detected, which backend was chosen, and any window-init
failure:

- **Windows:** `%LOCALAPPDATA%\AliceMiner\logs\gui-startup.log`
- **macOS:** `~/Library/Application Support/AliceMiner/logs/gui-startup.log`
- **Linux:** `~/.local/share/AliceMiner/logs/gui-startup.log`

If a window still won't open, include this file when you report the issue. On a
hard init failure the app now shows a native error dialog with these same steps
instead of exiting silently.
