//! Small, PUBLIC-only CLI settings JSON at `~/.alice/settings.json` (honors
//! `$ALICE_IDENTITY_DIR` like the identity pointer + ai config, so a test env
//! isolates it and it lives side-by-side with them).
//!
//! Today it holds ONE thing — the persisted UI language for the headless CLI — but
//! it is a general settings bag: new fields are `Option` and merge over the loaded
//! file, so writing the language never clobbers a future setting (and vice-versa).
//! Holds NO secret.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::i18n::Lang;

/// Current on-disk schema for [`Settings`]. Bump only on an INCOMPATIBLE change.
pub const SETTINGS_SCHEMA: u32 = 1;

fn default_schema() -> u32 {
    1
}

/// The persisted CLI settings. Every field is public (no secret). A field the user
/// never set stays `None`, and any field this build does not recognise is preserved
/// verbatim through [`extra`] so an older binary never drops a newer setting.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default = "default_schema")]
    pub schema: u32,
    /// The persisted UI language for the headless CLI (`"en"` / `"zh"`). `None`
    /// until the user picks one (via `--lang`, `lang <code>`, or the first-run
    /// prompt), at which point the resolver persists their choice so it never asks
    /// again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,
    /// Any settings keys this build does not know about, preserved verbatim so a
    /// round-trip through an older binary never drops a newer field.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl Settings {
    /// The persisted language, parsed. `None` when unset OR unparseable (a garbage
    /// value is treated as "no saved preference", never an error — the resolver
    /// falls through to the next source).
    pub fn parsed_lang(&self) -> Option<Lang> {
        self.lang.as_deref().and_then(|s| s.parse::<Lang>().ok())
    }
}

/// Resolve the settings path: `<identity_dir>/settings.json`. Honors
/// `$ALICE_IDENTITY_DIR` (tests) exactly like the identity pointer + ai config.
pub fn settings_path() -> PathBuf {
    identity_dir().join("settings.json")
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

/// Load the persisted settings, or a default (all-`None`) settings when the file is
/// absent / unparseable (a corrupt file is treated as "no saved settings", never an
/// error).
pub fn load() -> Settings {
    match std::fs::read_to_string(settings_path()) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => Settings::default(),
    }
}

/// Persist the settings atomically (temp + rename). PUBLIC data. Returns the path
/// written.
pub fn save(settings: &Settings) -> Result<PathBuf, String> {
    let path = settings_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    let mut out = settings.clone();
    out.schema = SETTINGS_SCHEMA;
    let encoded = serde_json::to_vec_pretty(&out)
        .map_err(|e| format!("failed to serialize settings: {e}"))?;
    let tmp = path.with_file_name(format!(".settings.json.tmp-{}", std::process::id()));
    std::fs::write(&tmp, &encoded).map_err(|e| format!("failed to write settings: {e}"))?;
    std::fs::rename(&tmp, &path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("failed to store settings: {e}")
    })?;
    Ok(path)
}

/// Persist ONLY the language, merging over whatever else is on disk (never clobbers
/// another setting). Load → set `lang` → save. Returns the path written.
pub fn save_lang(lang: Lang) -> Result<PathBuf, String> {
    let mut settings = load();
    settings.lang = Some(lang.code().to_string());
    save(&settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_temp_id_dir<F: FnOnce()>(f: F) {
        let _g = crate::IDENTITY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "alice-settings-{}-{}",
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
    fn absent_settings_loads_as_default() {
        with_temp_id_dir(|| {
            let s = load();
            assert_eq!(s.lang, None);
            assert_eq!(s.parsed_lang(), None);
        });
    }

    #[test]
    fn save_lang_round_trips() {
        with_temp_id_dir(|| {
            let path = save_lang(Lang::Zh).expect("save");
            assert!(path.is_file());
            let loaded = load();
            assert_eq!(loaded.lang.as_deref(), Some("zh"));
            assert_eq!(loaded.parsed_lang(), Some(Lang::Zh));
            let raw = std::fs::read_to_string(&path).unwrap();
            assert!(raw.contains("\"schema\": 1"));
            assert!(raw.contains("\"lang\": \"zh\""));
        });
    }

    #[test]
    fn save_lang_preserves_unknown_fields() {
        with_temp_id_dir(|| {
            // A future binary wrote an extra setting; this build must not drop it.
            std::fs::write(
                settings_path(),
                br#"{"schema":1,"lang":"en","future_setting":42}"#,
            )
            .unwrap();
            save_lang(Lang::Zh).expect("save");
            let raw = std::fs::read_to_string(settings_path()).unwrap();
            assert!(raw.contains("future_setting"), "kept unknown field: {raw}");
            assert!(raw.contains("\"lang\": \"zh\""), "updated lang: {raw}");
            let loaded = load();
            assert_eq!(loaded.parsed_lang(), Some(Lang::Zh));
        });
    }

    #[test]
    fn corrupt_settings_falls_back_to_default() {
        with_temp_id_dir(|| {
            std::fs::write(settings_path(), b"{ not json").unwrap();
            assert_eq!(load().lang, None);
        });
    }

    #[test]
    fn garbage_lang_value_parses_as_none() {
        with_temp_id_dir(|| {
            std::fs::write(settings_path(), br#"{"schema":1,"lang":"martian"}"#).unwrap();
            let s = load();
            assert_eq!(s.lang.as_deref(), Some("martian"));
            assert_eq!(s.parsed_lang(), None, "unknown lang → no preference");
        });
    }
}
