//! Persisted config for the `alice-miner train` (RLVR training-worker) role.
//!
//! Small, PUBLIC-only JSON at `<identity_dir>/train_config.json` (honors
//! `$ALICE_IDENTITY_DIR` like the identity pointer + ai config) so `alice-miner train`
//! can be re-run without retyping the flags. Holds NO secret: the center URL, the
//! trainer dir, the python path, the base model, and the optional device/region hints.
//! The wallet key is NEVER stored here — it stays in the keystore.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Current on-disk schema for [`TrainConfig`]. Bump only on an INCOMPATIBLE change.
pub const TRAIN_CONFIG_SCHEMA: u32 = 1;

fn default_schema() -> u32 {
    1
}

/// The persisted `train`-role settings. Every field is public (no secret). Fields the
/// user did not set stay `None` so a re-run only fills what was actually provided.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TrainConfig {
    #[serde(default = "default_schema")]
    pub schema: u32,
    /// The acp gateway base URL the worker registers/leases/submits against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub center_url: Option<String>,
    /// Path to the trainer dir (must contain `run_m0.py` + `code_exec.py`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trainer_dir: Option<String>,
    /// Path to the python3 interpreter to run the trainer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub python: Option<String>,
    /// The base model id the worker generates candidates with (HF id or local path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_model: Option<String>,
    /// The device the generation runs on ("cuda" / "cpu" / "mps").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// Load the base in 4-bit (QLoRA-class NF4) so a big MoE base fits a modest card.
    #[serde(default, skip_serializing_if = "is_false")]
    pub four_bit: bool,
    /// Multi-GPU placement for a base that won't fit one card. Only `"shard"` today
    /// (device_map="auto", naive pipeline split across all local GPUs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi_gpu: Option<String>,
    /// Optional region hint (informational — the coordinator uses it for locality).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

/// serde skip helper: omit a `false` bool from the persisted JSON.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(b: &bool) -> bool {
    !*b
}

/// Resolve the config path: `<identity_dir>/train_config.json`. Honors
/// `$ALICE_IDENTITY_DIR` (tests) exactly like the identity pointer + ai config, so the
/// three live side-by-side and a test env isolates all of them.
pub fn train_config_path() -> PathBuf {
    identity_dir().join("train_config.json")
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
pub fn load() -> TrainConfig {
    let path = train_config_path();
    match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => TrainConfig::default(),
    }
}

/// Persist the config atomically (temp + rename). PUBLIC data; written whenever the
/// user runs `train` with resolved flags so a bare re-run replays them. Returns the
/// path written.
pub fn save(cfg: &TrainConfig) -> Result<PathBuf, String> {
    let path = train_config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    let mut out = cfg.clone();
    out.schema = TRAIN_CONFIG_SCHEMA;
    let encoded = serde_json::to_vec_pretty(&out)
        .map_err(|e| format!("failed to serialize train config: {e}"))?;
    let tmp = path.with_file_name(format!(".train_config.json.tmp-{}", std::process::id()));
    std::fs::write(&tmp, &encoded).map_err(|e| format!("failed to write train config: {e}"))?;
    std::fs::rename(&tmp, &path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("failed to store train config: {e}")
    })?;
    Ok(path)
}

/// The directory the train role writes trainer stdout/stderr logs to:
/// `<data_local_dir>/AliceMiner/train-logs/` (created on demand). DELIBERATELY outside
/// the `~/.alice` keystore root — a verbose trainer log must never sit next to a key.
/// Falls back to `<identity_dir>/train-logs` only if no OS data dir is found.
pub fn train_log_dir() -> PathBuf {
    dirs::data_local_dir()
        .map(|b| b.join("AliceMiner").join("train-logs"))
        .unwrap_or_else(|| identity_dir().join("train-logs"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_temp_id_dir<F: FnOnce()>(f: F) {
        let _g = crate::IDENTITY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "alice-train-cfg-{}-{}",
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
            assert_eq!(cfg, TrainConfig::default());
            assert!(cfg.center_url.is_none());
        });
    }

    #[test]
    fn save_then_load_round_trips_set_fields_only() {
        with_temp_id_dir(|| {
            let cfg = TrainConfig {
                schema: TRAIN_CONFIG_SCHEMA,
                center_url: Some("https://api.aliceprotocol.org".into()),
                trainer_dir: Some("/opt/training-mint-m0".into()),
                python: Some("python3".into()),
                base_model: Some("Qwen/Qwen3-30B-A3B-Instruct-2507".into()),
                device: Some("cuda".into()),
                four_bit: true,
                multi_gpu: Some("shard".into()),
                region: None,
            };
            let path = save(&cfg).expect("save");
            assert!(path.is_file());
            let loaded = load();
            assert_eq!(loaded, cfg);
            let raw = std::fs::read_to_string(&path).unwrap();
            assert!(!raw.contains("region"), "unset region omitted: {raw}");
            assert!(raw.contains("\"schema\": 1"));
            // set 4-bit + shard round-trip through the JSON.
            assert!(raw.contains("\"four_bit\": true"), "four_bit persisted: {raw}");
            assert!(raw.contains("\"multi_gpu\": \"shard\""), "multi_gpu persisted: {raw}");
        });
    }

    #[test]
    fn corrupt_config_falls_back_to_default() {
        with_temp_id_dir(|| {
            std::fs::write(train_config_path(), b"{ not json").unwrap();
            assert_eq!(load(), TrainConfig::default());
        });
    }

    #[test]
    fn log_dir_is_outside_the_keystore_root() {
        if dirs::data_local_dir().is_some() {
            let log = train_log_dir();
            assert!(log.ends_with("AliceMiner/train-logs"));
        }
    }
}
