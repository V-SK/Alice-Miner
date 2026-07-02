//! Persisted config for the `alice-miner ai` (shard-stage inference) role.
//!
//! Small, PUBLIC-only JSON at `~/.alice/ai_config.json` (honors `$ALICE_IDENTITY_DIR`
//! like the identity pointer) so `alice-miner ai` can be re-run without retyping the
//! flags. Holds NO secret: the center URL, the public endpoint, the engine dir, the
//! python path, and the optional VRAM/region hints. The wallet key + the swarm
//! `SHARD_PSK` are NEVER stored here — the key stays in the keystore, the PSK in the
//! env only.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Current on-disk schema for [`AiConfig`]. Bump only on an INCOMPATIBLE change.
pub const AI_CONFIG_SCHEMA: u32 = 1;

fn default_schema() -> u32 {
    1
}

/// The persisted `ai`-role settings. Every field is public (no secret). Fields the
/// user did not set stay `None` so a re-run only fills what was actually provided.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AiConfig {
    #[serde(default = "default_schema")]
    pub schema: u32,
    /// The acp gateway base URL the stage registers/heartbeats/pulls against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub center_url: Option<String>,
    /// The PUBLIC `host:port` this stage listens on (what the swarm dials).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Path to the `alice-shard-engine` checkout (holds `phase0/pipeline.py`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_dir: Option<String>,
    /// Path to the python3 interpreter to run the engine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub python: Option<String>,
    /// Free VRAM to advertise (GB); when unset the CLI auto-detects via nvidia-smi.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vram_gb: Option<f64>,
    /// Optional region hint (informational — the center uses it for locality).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

/// Resolve the config path: `<identity_dir>/ai_config.json`. Honors
/// `$ALICE_IDENTITY_DIR` (tests) exactly like the identity pointer, so the two live
/// side-by-side and a test env isolates both.
pub fn ai_config_path() -> PathBuf {
    identity_dir().join("ai_config.json")
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

/// Load the persisted config, or a default (all-`None`) config when the file is
/// absent / unparseable (a corrupt file is treated as "no saved config", never an
/// error — the user just re-supplies flags).
pub fn load() -> AiConfig {
    let path = ai_config_path();
    match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => AiConfig::default(),
    }
}

/// Persist the config atomically (temp + rename). PUBLIC data; written whenever the
/// user runs `ai` with resolved flags so a bare re-run replays them. Returns the
/// path written.
pub fn save(cfg: &AiConfig) -> Result<PathBuf, String> {
    let path = ai_config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    let mut out = cfg.clone();
    out.schema = AI_CONFIG_SCHEMA;
    let encoded =
        serde_json::to_vec_pretty(&out).map_err(|e| format!("failed to serialize ai config: {e}"))?;
    let tmp = path.with_file_name(format!(".ai_config.json.tmp-{}", std::process::id()));
    std::fs::write(&tmp, &encoded).map_err(|e| format!("failed to write ai config: {e}"))?;
    std::fs::rename(&tmp, &path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("failed to store ai config: {e}")
    })?;
    Ok(path)
}

/// The directory the ai role writes engine stdout/stderr logs to:
/// `<data_local_dir>/AliceMiner/ai-logs/` (created on demand). DELIBERATELY outside
/// the `~/.alice` keystore root — a verbose engine log must never sit next to a key.
/// Falls back to `<identity_dir>/ai-logs` only if no OS data dir is found.
pub fn ai_log_dir() -> PathBuf {
    dirs::data_local_dir()
        .map(|b| b.join("AliceMiner").join("ai-logs"))
        .unwrap_or_else(|| identity_dir().join("ai-logs"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_temp_id_dir<F: FnOnce()>(f: F) {
        let _g = crate::IDENTITY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "alice-ai-cfg-{}-{}",
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
            assert_eq!(cfg, AiConfig::default());
            assert!(cfg.center_url.is_none());
        });
    }

    #[test]
    fn save_then_load_round_trips_set_fields_only() {
        with_temp_id_dir(|| {
            let cfg = AiConfig {
                schema: AI_CONFIG_SCHEMA,
                center_url: Some("https://api.aliceprotocol.org".into()),
                endpoint: Some("203.0.113.7:29501".into()),
                engine_dir: Some("/opt/alice-shard-engine".into()),
                python: Some("python3".into()),
                vram_gb: Some(24.0),
                region: None,
            };
            let path = save(&cfg).expect("save");
            assert!(path.is_file());
            let loaded = load();
            assert_eq!(loaded, cfg);
            // A None field is omitted from the JSON entirely (skip_serializing_if).
            let raw = std::fs::read_to_string(&path).unwrap();
            assert!(!raw.contains("region"), "unset region omitted: {raw}");
            assert!(raw.contains("\"schema\": 1"));
        });
    }

    #[test]
    fn corrupt_config_falls_back_to_default() {
        with_temp_id_dir(|| {
            std::fs::write(ai_config_path(), b"{ not json").unwrap();
            assert_eq!(load(), AiConfig::default());
        });
    }

    #[test]
    fn log_dir_is_outside_the_keystore_root() {
        // The engine log dir must not live under ~/.alice (or the test id dir) when
        // an OS data dir exists — a verbose log must never share the keystore dir.
        if dirs::data_local_dir().is_some() {
            let log = ai_log_dir();
            assert!(log.ends_with("AliceMiner/ai-logs"));
        }
    }
}
