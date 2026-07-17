//! Process-global bilingual (English / 中文) string selection for the HEADLESS
//! `alice-miner` CLI.
//!
//! Design (the brief):
//!   * ONE language per process run. The front-end resolves it ONCE at startup
//!     (flag → saved settings → interactive first-run prompt → `LANG*` env →
//!     default English) and calls [`set_lang`] before any user-facing output.
//!   * Call sites carry BOTH variants inline — [`tr!("Starting miner", "启动矿工")`](tr) —
//!     so there is no central key catalog to keep in sync and each migration is
//!     local + merge-conflict-free. `tr!` expands to the `&'static str` for the
//!     current global language, so it drops straight into `println!`/`format!`.
//!
//! The GUI crate ALSO drives this global: `alice-miner-gui`'s `MinerApp::ui` mirrors
//! its `app.lang_zh` toggle into [`set_lang`] each frame, so the desktop titlebar
//! pill + Settings labels localize through the SAME `tr!` mechanism (no second i18n
//! system). The GUI's bilingual-inline `ui/strings.rs` constants (which embed both
//! languages in one string) are unaffected.

use std::str::FromStr;
use std::sync::atomic::{AtomicU8, Ordering};

/// The two languages the CLI speaks. `Default` is [`Lang::En`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    /// English (the default).
    #[default]
    En,
    /// 中文 (Simplified Chinese).
    Zh,
}

impl Lang {
    /// The canonical short code (`"en"` / `"zh"`) — what we persist to settings.
    pub const fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Zh => "zh",
        }
    }

    /// Map to the packed [`AtomicU8`] discriminant used by the global cell.
    const fn to_u8(self) -> u8 {
        match self {
            Lang::En => 0,
            Lang::Zh => 1,
        }
    }

    /// Inverse of [`Lang::to_u8`]; any unknown byte decodes to the English default
    /// (fail-safe — the global can never hold a "poisoned" language).
    const fn from_u8(v: u8) -> Lang {
        match v {
            1 => Lang::Zh,
            _ => Lang::En,
        }
    }
}

impl std::fmt::Display for Lang {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl FromStr for Lang {
    type Err = String;

    /// Parse a language from a user- or env-supplied string. Accepts the flag
    /// values (`en` / `english`, `zh` / `中文` / `中`) AND the shapes an `LANG` /
    /// `LC_ALL` / `LANGUAGE` env var takes (`zh`, `zh-cn`, `zh_CN`, `zh_CN.UTF-8`,
    /// …). Case- and separator-insensitive; anything starting `zh` is Chinese.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // The literal native name may arrive un-lowercased; check the raw trimmed
        // form first (ASCII-lowercasing leaves CJK untouched but this is clearer).
        let raw = s.trim();
        if raw == "中文" || raw == "中" {
            return Ok(Lang::Zh);
        }
        let t = raw.to_ascii_lowercase();
        // Chinese: the code and any `zh*` locale (zh, zh-cn, zh_CN.UTF-8, zh_TW…).
        if t == "zh" || t.starts_with("zh-") || t.starts_with("zh_") {
            return Ok(Lang::Zh);
        }
        // English: the code, the name, and any `en*` locale (en, en_US.UTF-8…).
        if t == "en" || t == "english" || t.starts_with("en-") || t.starts_with("en_") {
            return Ok(Lang::En);
        }
        Err(format!("unknown language {s:?} (expected en or zh)"))
    }
}

/// The process-global current language. `0` = En, `1` = Zh (see [`Lang::to_u8`]).
/// Starts at En so any code path that reads it before [`set_lang`] is safe.
static CURRENT: AtomicU8 = AtomicU8::new(0);

/// Set the process-global language. The front-end calls this ONCE, early in
/// `main`, after resolving the preference — one language per process run. Later
/// calls are allowed (harmless overwrite) but the design is set-once.
pub fn set_lang(lang: Lang) {
    CURRENT.store(lang.to_u8(), Ordering::Relaxed);
}

/// The process-global current language (English until [`set_lang`] runs).
pub fn lang() -> Lang {
    Lang::from_u8(CURRENT.load(Ordering::Relaxed))
}

/// Return the variant matching the current global language. The function form of
/// [`tr!`]; both take two `&'static str` (English first, then 中文) and return the
/// selected one. Prefer the [`tr!`] macro at call sites (it reads better and is
/// the documented convention); this is here for the rare dynamic dispatch.
pub fn tr(en: &'static str, zh: &'static str) -> &'static str {
    match lang() {
        Lang::En => en,
        Lang::Zh => zh,
    }
}

/// Pick the string for the current global language: `tr!("English", "中文")`.
///
/// BOTH variants live inline at the call site (English first, then 中文) — there
/// is NO central catalog. Expands to the selected `&'static str`, so it drops
/// straight into `println!("{}", tr!(...))`, `format!`, string concatenation, and
/// anywhere a `&str` is wanted.
#[macro_export]
macro_rules! tr {
    ($en:expr, $zh:expr $(,)?) => {
        match $crate::i18n::lang() {
            $crate::i18n::Lang::En => $en,
            $crate::i18n::Lang::Zh => $zh,
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests here mutate the PROCESS-GLOBAL language, so they must not run
    /// concurrently with each other. Funnel them through one mutex (Rust runs a
    /// crate's tests in parallel).
    static LANG_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn default_lang_is_english() {
        assert_eq!(Lang::default(), Lang::En);
    }

    #[test]
    fn tr_returns_english_when_en_and_chinese_when_zh() {
        let _g = LANG_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_lang(Lang::En);
        assert_eq!(tr!("Starting miner", "启动矿工"), "Starting miner");
        assert_eq!(tr("Starting miner", "启动矿工"), "Starting miner");
        set_lang(Lang::Zh);
        assert_eq!(tr!("Starting miner", "启动矿工"), "启动矿工");
        assert_eq!(tr("Starting miner", "启动矿工"), "启动矿工");
        // Reset so we don't leak the global into other tests in this crate.
        set_lang(Lang::En);
    }

    #[test]
    fn tr_works_inside_format() {
        let _g = LANG_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_lang(Lang::Zh);
        let s = format!("{}: {}", tr!("state", "状态"), "running");
        assert_eq!(s, "状态: running");
        set_lang(Lang::En);
    }

    #[test]
    fn from_str_parses_flag_values() {
        assert_eq!("en".parse::<Lang>().unwrap(), Lang::En);
        assert_eq!("EN".parse::<Lang>().unwrap(), Lang::En);
        assert_eq!("english".parse::<Lang>().unwrap(), Lang::En);
        assert_eq!("English".parse::<Lang>().unwrap(), Lang::En);
        assert_eq!("zh".parse::<Lang>().unwrap(), Lang::Zh);
        assert_eq!("ZH".parse::<Lang>().unwrap(), Lang::Zh);
        assert_eq!("中文".parse::<Lang>().unwrap(), Lang::Zh);
        assert_eq!("中".parse::<Lang>().unwrap(), Lang::Zh);
        assert!(" en ".parse::<Lang>().unwrap() == Lang::En);
    }

    #[test]
    fn from_str_parses_env_style_locales() {
        // The shapes `LANG` / `LC_ALL` / `LANGUAGE` take.
        assert_eq!("zh-cn".parse::<Lang>().unwrap(), Lang::Zh);
        assert_eq!("zh_CN".parse::<Lang>().unwrap(), Lang::Zh);
        assert_eq!("zh_CN.UTF-8".parse::<Lang>().unwrap(), Lang::Zh);
        assert_eq!("zh_TW".parse::<Lang>().unwrap(), Lang::Zh);
        assert_eq!("en_US.UTF-8".parse::<Lang>().unwrap(), Lang::En);
        assert_eq!("en-GB".parse::<Lang>().unwrap(), Lang::En);
    }

    #[test]
    fn from_str_rejects_unknown() {
        assert!("fr".parse::<Lang>().is_err());
        assert!("".parse::<Lang>().is_err());
        assert!("de_DE".parse::<Lang>().is_err());
    }

    #[test]
    fn code_and_display_round_trip() {
        assert_eq!(Lang::En.code(), "en");
        assert_eq!(Lang::Zh.code(), "zh");
        assert_eq!(Lang::En.to_string(), "en");
        assert_eq!(Lang::Zh.to_string(), "zh");
        assert_eq!(Lang::En.code().parse::<Lang>().unwrap(), Lang::En);
        assert_eq!(Lang::Zh.code().parse::<Lang>().unwrap(), Lang::Zh);
    }
}
