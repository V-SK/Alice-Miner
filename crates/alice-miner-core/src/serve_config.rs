//! Persisted **single-GPU serve choice** for the `alice-miner ai --menu` wizard.
//!
//! When a miner picks a serving tier in the participation wizard and confirms the
//! download, the choice is saved here so a later `serve` update (M3, which wires the
//! actual worker spawn) knows which model this machine committed to — without asking
//! again. Small, PUBLIC-only JSON at `<identity_dir>/serve_config.json` (honors
//! `$ALICE_IDENTITY_DIR` like the identity pointer + [`crate::ai_config`], so the
//! three live side-by-side and a test env isolates all of them).
//!
//! Holds NO secret: the center URL, the chosen tier's class id + runtime, and the
//! artifact coordinates (repo/revision/subpath) needed to fetch it. The wallet key
//! never touches this file — the serve role, like the shard role, proves possession
//! with the keystore key at run time, not from anything stored here.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Current on-disk schema for [`ServeConfig`]. Bump only on an INCOMPATIBLE change.
pub const SERVE_CONFIG_SCHEMA: u32 = 1;

fn default_schema() -> u32 {
    1
}

/// The persisted single-GPU serve choice. Every field is public (no secret).
/// Fields the wizard did not set stay `None` so a partial save only records what
/// was actually chosen.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServeConfig {
    #[serde(default = "default_schema")]
    pub schema: u32,
    /// The acp gateway base URL the menu was fetched from (so a later serve run
    /// dials the same center by default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub center_url: Option<String>,
    /// The chosen tier's stable class id (e.g. `alice_lite_4b`) — the model_class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    /// The serving runtime the tier runs on (e.g. `cuda`, `mlx`, `gguf`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    /// The HF repo the artifact is pulled from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_id: Option<String>,
    /// The pinned revision (a 40-hex commit) — reproducible fetch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    /// The file within the repo (e.g. the `.gguf` name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_subpath: Option<String>,
    /// Path to the `alice-acp-minerai` worker checkout the `serve` role spawns the
    /// Python worker_client from (must contain `src/alice_acp/worker_client/__main__.py`).
    /// Set by `alice-miner serve` on a successful run so a bare re-run replays it; the
    /// wizard never sets it (the wizard only records the model choice, not the checkout).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_dir: Option<String>,
    /// Path to the python3 interpreter the `serve` role runs the worker_client with
    /// (default: `python3`). Saved by `alice-miner serve` for re-runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub python: Option<String>,
}

/// Resolve the config path: `<identity_dir>/serve_config.json`. Honors
/// `$ALICE_IDENTITY_DIR` (tests) exactly like the identity pointer + `ai_config`,
/// so the three live side-by-side and a test env isolates all of them.
pub fn serve_config_path() -> PathBuf {
    identity_dir().join("serve_config.json")
}

fn identity_dir() -> PathBuf {
    if let Some(over) = std::env::var_os("ALICE_IDENTITY_DIR") {
        let s = over.to_string_lossy().trim().to_string();
        if !s.is_empty() {
            return PathBuf::from(s);
        }
    }
    dirs::home_dir()
        .map(|h| h.join(".alice"))
        .unwrap_or_else(|| PathBuf::from(".alice"))
}

/// Load the persisted serve choice, or a default (all-`None`) config when the file
/// is absent / unparseable (a corrupt file is treated as "no saved choice", never
/// an error — the wizard just re-asks).
pub fn load() -> ServeConfig {
    let path = serve_config_path();
    match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => ServeConfig::default(),
    }
}

/// The directory the `serve` role writes the Python worker's stdout/stderr logs to:
/// `<data_local_dir>/AliceMiner/serve-logs/` (created on demand). DELIBERATELY
/// outside the `~/.alice` keystore root — a verbose worker log must never sit next
/// to a key (mirrors [`crate::ai_config::ai_log_dir`]). Falls back to
/// `<identity_dir>/serve-logs` only if no OS data dir is found.
pub fn serve_log_dir() -> PathBuf {
    dirs::data_local_dir()
        .map(|b| b.join("AliceMiner").join("serve-logs"))
        .unwrap_or_else(|| identity_dir().join("serve-logs"))
}

/// Persist the serve choice atomically (temp + rename). PUBLIC data; written when
/// the wizard's download is confirmed. Returns the path written.
pub fn save(cfg: &ServeConfig) -> Result<PathBuf, String> {
    let path = serve_config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    let mut out = cfg.clone();
    out.schema = SERVE_CONFIG_SCHEMA;
    let encoded = serde_json::to_vec_pretty(&out)
        .map_err(|e| format!("failed to serialize serve config: {e}"))?;
    let tmp = path.with_file_name(format!(".serve_config.json.tmp-{}", std::process::id()));
    std::fs::write(&tmp, &encoded).map_err(|e| format!("failed to write serve config: {e}"))?;
    std::fs::rename(&tmp, &path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("failed to store serve config: {e}")
    })?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_temp_id_dir<F: FnOnce()>(f: F) {
        let _g = crate::IDENTITY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "alice-serve-cfg-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("ALICE_IDENTITY_DIR", &dir);
        f();
        std::env::remove_var("ALICE_IDENTITY_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn absent_config_loads_as_default() {
        with_temp_id_dir(|| {
            let cfg = load();
            assert_eq!(cfg, ServeConfig::default());
            assert!(cfg.tier.is_none());
        });
    }

    #[test]
    fn save_then_load_round_trips_set_fields_only() {
        with_temp_id_dir(|| {
            let cfg = ServeConfig {
                schema: SERVE_CONFIG_SCHEMA,
                center_url: Some("https://api.aliceprotocol.org".into()),
                tier: Some("alice_lite_4b".into()),
                runtime: Some("cuda".into()),
                repo_id: Some("v102ss/Alice-Qwen3-4B-Instruct-2507-Heretic-Light-GGUF".into()),
                revision: Some("aa4bf90e83b7acb4fb78881186e7bd623bfc004b".into()),
                artifact_subpath: None,
                worker_dir: Some("/opt/alice-acp-minerai".into()),
                python: Some("python3".into()),
            };
            let path = save(&cfg).expect("save");
            assert!(path.is_file());
            let loaded = load();
            assert_eq!(loaded, cfg);
            // A None field is omitted from the JSON entirely (skip_serializing_if).
            let raw = std::fs::read_to_string(&path).unwrap();
            assert!(
                !raw.contains("artifact_subpath"),
                "unset artifact_subpath omitted: {raw}"
            );
            // The M3 fields the serve role adds round-trip when set.
            assert!(raw.contains("worker_dir"), "worker_dir persisted: {raw}");
            assert!(raw.contains("python"), "python persisted: {raw}");
            assert!(raw.contains("\"schema\": 1"));
        });
    }

    #[test]
    fn corrupt_config_falls_back_to_default() {
        with_temp_id_dir(|| {
            std::fs::write(serve_config_path(), b"{ not json").unwrap();
            assert_eq!(load(), ServeConfig::default());
        });
    }

    #[test]
    fn log_dir_is_outside_the_keystore_root() {
        // The worker log dir must not live under ~/.alice (or the test id dir) when an
        // OS data dir exists — a verbose worker log must never share the keystore dir.
        if dirs::data_local_dir().is_some() {
            let log = serve_log_dir();
            assert!(log.ends_with("AliceMiner/serve-logs"));
        }
    }

    #[test]
    fn config_written_before_m3_still_loads() {
        // Forward-compat: a serve_config.json written by the M2 wizard (no worker_dir /
        // python keys) still loads — the new fields default to None.
        with_temp_id_dir(|| {
            std::fs::write(
                serve_config_path(),
                br#"{"schema":1,"center_url":"https://api.aliceprotocol.org","tier":"alice_lite_4b","runtime":"cuda"}"#,
            )
            .unwrap();
            let cfg = load();
            assert_eq!(cfg.tier.as_deref(), Some("alice_lite_4b"));
            assert!(cfg.worker_dir.is_none());
            assert!(cfg.python.is_none());
        });
    }
}
