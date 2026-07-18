//! `core/detect/scan` — best-effort discovery of ALREADY-INSTALLED third-party
//! miners on this box, so the setup wizard can OFFER a detected miner instead of
//! making the user hunt for a path (design §3 / §2).
//!
//! ── HONEST scope (design §3) ─────────────────────────────────────────────────
//! This does NOT promise "any binary, zero config". It scans a fixed table of
//! KNOWN miner basenames on `$PATH` + each OS's common install/download dirs
//! (top-level plus ONE level deep, with per-directory caps so startup is bounded),
//! `--version`-probes each hit (bounded timeout), and filters a family to the
//! lane(s) it can actually serve ([`crate::backend::MinerPreset::compatible_lanes`]).
//! When it finds nothing the wizard falls back to "enter a path manually" +
//! "use the bundled engine". It never claims a miner works where it can't.
//!
//! Pure + injectable: [`scan_with`] takes the search dirs + a
//! [`crate::detect::Runner`] so tests drive it against a fixture tree with a fake
//! version prober — never the real machine, never a wallet/keystore.

use std::path::{Path, PathBuf};

use crate::backend::MinerPreset;
use crate::detect::Runner;
use crate::lane::Lane;

/// One installed miner found on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedMiner {
    /// Absolute path to the discovered binary.
    pub path: PathBuf,
    /// The miner family inferred from its basename (fixes argv shape + parser).
    pub family: MinerPreset,
    /// The `--version` line if the probe succeeded (best-effort; `None` on failure).
    pub version: Option<String>,
}

impl DetectedMiner {
    /// The Alice lane(s) this detected miner can serve (its family's compatibility).
    pub fn compatible_lanes(&self) -> &'static [Lane] {
        self.family.compatible_lanes()
    }

    /// Whether this detected miner can serve `lane`.
    pub fn supports_lane(&self, lane: Lane) -> bool {
        self.family.compatible_lanes().contains(&lane)
    }
}

/// The KNOWN miner basenames (lower-cased, WITHOUT any `.exe`) → the family they
/// map to. Kept small + explicit — an unknown binary is simply not detected (the
/// wizard's manual-path + template path covers it).
fn known_basenames() -> &'static [(&'static str, MinerPreset)] {
    &[
        ("srbminer-multi", MinerPreset::Srbminer),
        ("srbminer", MinerPreset::Srbminer),
        ("xmrig", MinerPreset::Xmrig),
        ("t-rex", MinerPreset::Trex),
        ("trex", MinerPreset::Trex),
        ("lolminer", MinerPreset::Lolminer),
        ("gminer", MinerPreset::Gminer),
        ("nbminer", MinerPreset::Nbminer),
        ("alpha-miner", MinerPreset::AlphaMiner),
        ("alphaminer", MinerPreset::AlphaMiner),
        // KawPoW miners without a dedicated standard preset → generic best-effort.
        ("kawpowminer", MinerPreset::GenericStratum),
        ("teamredminer", MinerPreset::GenericStratum),
    ]
}

/// The family for a filename, or `None` if it isn't a known miner. Case-insensitive;
/// tolerates a `.exe` suffix (Windows).
fn family_for_filename(name: &str) -> Option<MinerPreset> {
    let n = name.trim().to_ascii_lowercase();
    let n = n.strip_suffix(".exe").unwrap_or(&n);
    known_basenames()
        .iter()
        .find(|(base, _)| *base == n)
        .map(|(_, fam)| *fam)
}

/// Max directory entries scanned per directory (bounds a huge `~/Downloads`).
const MAX_ENTRIES_PER_DIR: usize = 400;
/// Max total binaries reported (a defensive cap; there are never this many).
const MAX_RESULTS: usize = 32;

/// Scan the real machine for installed miners (`$PATH` + common OS dirs). The
/// production entry point.
pub fn scan_installed_miners() -> Vec<DetectedMiner> {
    scan_with(&crate::detect::RealRunner, &search_dirs())
}

/// Scan `dirs` (top-level + one level deep) for known miner binaries, `--version`-
/// probing each with `runner`. Deterministic + injectable for tests. De-dupes by
/// resolved path; bounded per directory and in total.
pub fn scan_with(runner: &dyn Runner, dirs: &[PathBuf]) -> Vec<DetectedMiner> {
    let mut out: Vec<DetectedMiner> = Vec::new();
    let mut seen: Vec<PathBuf> = Vec::new();
    for dir in dirs {
        if out.len() >= MAX_RESULTS {
            break;
        }
        scan_dir(dir, runner, &mut out, &mut seen, /*descend=*/ true);
    }
    out
}

/// Scan a single directory for known miner basenames; when `descend`, also scan its
/// immediate subdirectories (ONE level — many miners live in a versioned folder like
/// `~/Downloads/SRBMiner-Multi-2-6-0/`). Never recurses deeper.
fn scan_dir(
    dir: &Path,
    runner: &dyn Runner,
    out: &mut Vec<DetectedMiner>,
    seen: &mut Vec<PathBuf>,
    descend: bool,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut subdirs: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten().take(MAX_ENTRIES_PER_DIR) {
        if out.len() >= MAX_RESULTS {
            return;
        }
        let path = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_dir() {
            if descend {
                subdirs.push(path);
            }
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(family) = family_for_filename(name) else {
            continue;
        };
        // De-dupe by absolute path (a binary reachable via several search dirs).
        let abs = path.canonicalize().unwrap_or_else(|_| path.clone());
        if seen.contains(&abs) {
            continue;
        }
        seen.push(abs.clone());
        let version = probe_version(runner, &abs);
        out.push(DetectedMiner { path: abs, family, version });
    }
    if descend {
        for sub in subdirs {
            if out.len() >= MAX_RESULTS {
                return;
            }
            scan_dir(&sub, runner, out, seen, /*descend=*/ false);
        }
    }
}

/// Best-effort `--version` probe. Returns the first non-empty line of stdout,
/// trimmed + length-bounded, or `None` on any failure (the miner still gets
/// offered — the version is only informational).
fn probe_version(runner: &dyn Runner, path: &Path) -> Option<String> {
    let p = path.to_str()?;
    let out = runner.run(p, &["--version"]).ok()?;
    let line = out.lines().map(str::trim).find(|l| !l.is_empty())?;
    let line = line.chars().take(120).collect::<String>();
    if line.is_empty() {
        None
    } else {
        Some(line)
    }
}

/// The directories to scan: every `$PATH` entry plus each OS's common miner
/// install / download locations + the cwd. Non-existent dirs are harmless (the
/// scan skips them). De-duplicated, order-preserving.
fn search_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let push = |p: PathBuf, dirs: &mut Vec<PathBuf>| {
        if !p.as_os_str().is_empty() && !dirs.contains(&p) {
            dirs.push(p);
        }
    };

    // $PATH entries.
    if let Some(path) = std::env::var_os("PATH") {
        for p in std::env::split_paths(&path) {
            push(p, &mut dirs);
        }
    }
    // Current working directory (a miner unpacked "right here").
    if let Ok(cwd) = std::env::current_dir() {
        push(cwd, &mut dirs);
    }
    let home = dirs_next_home();
    if cfg!(windows) {
        if let Some(h) = &home {
            push(h.join("Downloads"), &mut dirs);
        }
        for p in ["C:\\", "C:\\Program Files", "C:\\Program Files (x86)", "C:\\Miners"] {
            push(PathBuf::from(p), &mut dirs);
        }
    } else {
        if let Some(h) = &home {
            for sub in ["Downloads", "miners", ".local/bin", "bin"] {
                push(h.join(sub), &mut dirs);
            }
        }
        for p in ["/opt", "/usr/local/bin", "/usr/local/miners"] {
            push(PathBuf::from(p), &mut dirs);
        }
    }
    dirs
}

/// The user's home dir (via `dirs`), or `None`. A thin wrapper so `search_dirs`
/// reads cleanly.
fn dirs_next_home() -> Option<PathBuf> {
    dirs::home_dir()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake version prober: returns a canned `--version` line for any path whose
    /// basename is in its allow-set; else `Err` (probe failure).
    struct FakeRunner {
        versions: std::collections::HashMap<String, String>,
    }
    impl Runner for FakeRunner {
        fn run(&self, program: &str, args: &[&str]) -> Result<String, ()> {
            if args != ["--version"] {
                return Err(());
            }
            let base = Path::new(program)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            self.versions.get(&base).cloned().ok_or(())
        }
    }

    fn touch_exec(path: &Path) {
        std::fs::write(path, b"#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(path).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(path, perm).unwrap();
        }
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "alice-scan-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn family_for_filename_matches_known_names_case_and_exe_insensitive() {
        assert_eq!(family_for_filename("SRBMiner-MULTI"), Some(MinerPreset::Srbminer));
        assert_eq!(family_for_filename("xmrig.exe"), Some(MinerPreset::Xmrig));
        assert_eq!(family_for_filename("T-Rex"), Some(MinerPreset::Trex));
        assert_eq!(family_for_filename("alpha-miner"), Some(MinerPreset::AlphaMiner));
        assert_eq!(family_for_filename("not-a-miner"), None);
    }

    #[test]
    fn scan_finds_known_miners_and_probes_version() {
        let dir = tmpdir("hits");
        touch_exec(&dir.join("SRBMiner-MULTI"));
        touch_exec(&dir.join("xmrig"));
        touch_exec(&dir.join("random-tool")); // not a miner → ignored
        let mut versions = std::collections::HashMap::new();
        versions.insert("SRBMiner-MULTI".to_string(), "SRBMiner-MULTI 2.6.0".to_string());
        // xmrig deliberately has NO version → probe fails, still detected.
        let runner = FakeRunner { versions };

        let found = scan_with(&runner, std::slice::from_ref(&dir));
        assert_eq!(found.len(), 2, "the two known miners, not the random tool");
        let srb = found.iter().find(|m| m.family == MinerPreset::Srbminer).unwrap();
        assert_eq!(srb.version.as_deref(), Some("SRBMiner-MULTI 2.6.0"));
        assert!(srb.supports_lane(Lane::GpuPrl));
        assert!(!srb.supports_lane(Lane::Xmr), "SRBMiner is a PRL miner, not XMR");
        let xm = found.iter().find(|m| m.family == MinerPreset::Xmrig).unwrap();
        assert_eq!(xm.version, None, "a failed --version probe is not fatal");
        assert!(xm.supports_lane(Lane::Xmr));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_descends_one_level_but_not_deeper() {
        let root = tmpdir("depth");
        // A miner one level deep (the common versioned-folder layout).
        let sub = root.join("SRBMiner-Multi-2-6-0");
        std::fs::create_dir_all(&sub).unwrap();
        touch_exec(&sub.join("SRBMiner-MULTI"));
        // A miner TWO levels deep must NOT be found (bounded scan).
        let deep = sub.join("nested");
        std::fs::create_dir_all(&deep).unwrap();
        touch_exec(&deep.join("xmrig"));

        let runner = FakeRunner { versions: Default::default() };
        let found = scan_with(&runner, std::slice::from_ref(&root));
        assert_eq!(found.len(), 1, "only the one-level-deep miner");
        assert_eq!(found[0].family, MinerPreset::Srbminer);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scan_empty_when_nothing_installed_never_panics() {
        let dir = tmpdir("empty");
        let runner = FakeRunner { versions: Default::default() };
        assert!(scan_with(&runner, std::slice::from_ref(&dir)).is_empty());
        // A non-existent dir is skipped, not an error.
        assert!(scan_with(&runner, &[dir.join("does-not-exist")]).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_dedupes_a_binary_reachable_via_two_dirs() {
        let dir = tmpdir("dedup");
        touch_exec(&dir.join("xmrig"));
        let runner = FakeRunner { versions: Default::default() };
        // The same dir listed twice → the binary reported once.
        let found = scan_with(&runner, &[dir.clone(), dir.clone()]);
        assert_eq!(found.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
