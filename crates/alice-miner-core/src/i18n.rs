//! Bilingual (English / 中文) string selection for the HEADLESS `alice-miner` CLI.
//!
//! Design (the brief):
//!   * ONE language per process run IN PRODUCTION. The front-end resolves it ONCE at
//!     startup (flag → saved settings → interactive first-run prompt → `LANG*` env →
//!     default English) and calls [`set_process_lang`] before any user-facing output.
//!   * Call sites carry BOTH variants inline — [`tr!("Starting miner", "启动矿工")`](tr) —
//!     so there is no central key catalog to keep in sync and each migration is
//!     local + merge-conflict-free. `tr!` expands to the `&'static str` for the
//!     current global language, so it drops straight into `println!`/`format!`.
//!
//! The GUI crate ALSO drives this: `alice-miner-gui`'s `MinerApp::ui` mirrors its
//! `app.lang_zh` toggle into [`set_process_lang`] each frame, so the desktop titlebar
//! pill + Settings labels localize through the SAME `tr!` mechanism (no second i18n
//! system). The GUI's bilingual-inline `ui/strings.rs` constants (which embed both
//! languages in one string) are unaffected.
//!
//! ## Two setters, and why
//!
//! [`lang`] reads a THREAD-LOCAL override first and falls back to the process-wide
//! value. There are therefore two setters, and picking the wrong one is the only way
//! to get this wrong:
//!
//!   * [`set_process_lang`] — production. Every thread sees it. Required, because
//!     user-facing text IS produced off the main thread (`supervise`'s failover status
//!     is built inside the engine runtime on the `alice-miner-engine` worker).
//!   * [`set_lang`] — tests. Scoped to the calling thread.
//!
//! Tests are why the override exists at all. `cargo test` runs a crate's tests in
//! PARALLEL THREADS in ONE process, so while the language was a bare process global a
//! single test switching to 中文 changed the answer for the ~1000 reader call sites in
//! every test running beside it. The old answer was a `LANG_TEST_LOCK` that every
//! mutating test had to remember to take — which only ever worked if the ~174 unlocked
//! READER tests took it too, and they did not. Thread-scoping makes the lock
//! unnecessary rather than mandatory, so the next test author is safe without knowing
//! any of this.

use std::cell::Cell;
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

/// The process-wide current language. `0` = En, `1` = Zh (see [`Lang::to_u8`]).
/// Starts at En so any code path that reads it before [`set_process_lang`] is safe.
static CURRENT: AtomicU8 = AtomicU8::new(0);

thread_local! {
    /// A language override scoped to ONE thread. `None` — the value every freshly
    /// spawned thread starts with, which is what the test runner hands each test —
    /// means "follow [`CURRENT`]".
    ///
    /// PRODUCTION NEVER SETS THIS, and that is exactly why the fallback exists: the
    /// engine worker thread (`alice-miner-engine`) and the log-pump / update / probe
    /// threads must render in the SAME language the front-end resolved, and they only
    /// reach it through [`CURRENT`].
    static THREAD_LANG: Cell<Option<Lang>> = const { Cell::new(None) };
}

/// Set the PROCESS-WIDE language — **the production setter**. The front-end calls this
/// ONCE, early in `main`, after resolving the preference; the GUI additionally mirrors
/// its EN/中 toggle into it each frame. Visible to EVERY thread, which is required:
/// `supervise`'s failover status text is built on the engine worker thread, not main.
///
/// TESTS SHOULD NOT CALL THIS. A test that moves the process-wide language changes the
/// answer for every other test running at that moment — use [`set_lang`], which is
/// scoped to the calling thread.
pub fn set_process_lang(lang: Lang) {
    CURRENT.store(lang.to_u8(), Ordering::Relaxed);
}

/// Set the language for the CALLING THREAD ONLY, leaving every other thread on the
/// process-wide value. **This is the setter tests want.**
///
/// `cargo test` runs a crate's tests in parallel threads inside one process and libtest
/// gives each test its own thread, so a thread-scoped override isolates a test by
/// construction: no lock is needed by the test that pins a language, and none by the
/// ~1000 call sites that read one. Before this was thread-scoped, one test switching to
/// 中文 changed the answer under every English-asserting test running beside it.
///
/// See [`clear_lang_override`] to go back to following the process-wide value.
pub fn set_lang(lang: Lang) {
    let _ = THREAD_LANG.try_with(|c| c.set(Some(lang)));
}

/// Drop this thread's [`set_lang`] override so [`lang`] follows the process-wide value
/// again. Rarely needed — a test thread is discarded once the test ends.
pub fn clear_lang_override() {
    let _ = THREAD_LANG.try_with(|c| c.set(None));
}

/// The current language: this thread's [`set_lang`] override when it has one, else the
/// process-wide value (English until [`set_process_lang`] runs).
///
/// `try_with` rather than `with` so a `tr!` reached during thread teardown degrades to
/// the process-wide language instead of panicking.
pub fn lang() -> Lang {
    match THREAD_LANG.try_with(Cell::get) {
        Ok(Some(l)) => l,
        _ => Lang::from_u8(CURRENT.load(Ordering::Relaxed)),
    }
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

// NOTE: there used to be a `LANG_TEST_LOCK` here, which every test that pinned a
// language had to remember to take. It is gone: [`set_lang`] is scoped to the calling
// thread, so there is nothing left for such a lock to protect. Removing it also
// removed a real hazard — two core tests took it and `IDENTITY_ENV_LOCK` in OPPOSITE
// orders (`autoupdate.rs` lang-then-identity, `supervise.rs` identity-then-lang), an
// AB-BA inversion that deadlocked the whole `alice-miner-core` test binary under a
// high `--test-threads`.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_lang_is_english() {
        assert_eq!(Lang::default(), Lang::En);
    }

    #[test]
    fn tr_returns_english_when_en_and_chinese_when_zh() {
        set_lang(Lang::En);
        assert_eq!(tr!("Starting miner", "启动矿工"), "Starting miner");
        assert_eq!(tr("Starting miner", "启动矿工"), "Starting miner");
        set_lang(Lang::Zh);
        assert_eq!(tr!("Starting miner", "启动矿工"), "启动矿工");
        assert_eq!(tr("Starting miner", "启动矿工"), "启动矿工");
        set_lang(Lang::En);
    }

    #[test]
    fn tr_works_inside_format() {
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

    // ── the race these three exist to catch ─────────────────────────────────
    //
    // REGRESSION GUARD. libtest runs the writer and reader below CONCURRENTLY. While
    // `set_lang` moved a bare PROCESS GLOBAL, the writer changed the language out from
    // under the reader mid-assertion and the reader failed on the first or second
    // iteration, every run — the exact shape that left ~174 unlocked English-asserting
    // tests across the workspace at the mercy of whichever test happened to be mid-中文.
    // `set_lang` is now scoped to the calling thread, so the writer cannot reach the
    // reader at all.
    //
    // If either of these ever flakes, `set_lang` has been made process-wide again.

    /// The writer half: flips the language as fast as it can for as long as the reader
    /// below is asserting English.
    #[test]
    fn a_language_writer_running_concurrently_disturbs_no_one() {
        for _ in 0..20_000 {
            set_lang(Lang::Zh);
            std::thread::yield_now();
            set_lang(Lang::En);
        }
    }

    /// The reader half: asserts English holding NO lock, exactly like the ~174 unlocked
    /// reader tests across the workspace.
    #[test]
    fn an_english_reader_holding_no_lock_is_never_disturbed() {
        for i in 0..20_000 {
            assert_eq!(tr!("Starting miner", "启动矿工"), "Starting miner", "iteration {i}");
            std::thread::yield_now();
        }
    }

    /// Both halves of the contract, stated directly: an override belongs to the thread
    /// that set it, and a thread WITHOUT one reads the process-wide language. The
    /// second half is what production depends on — `supervise` builds its failover
    /// status text on the `alice-miner-engine` worker thread, never on main, so a
    /// thread-local that did not fall back would show that text in the wrong language.
    #[test]
    fn an_override_is_thread_scoped_and_workers_read_the_process_language() {
        set_lang(Lang::Zh);
        assert_eq!(lang(), Lang::Zh, "the override applies to the thread that set it");

        let on_worker = std::thread::spawn(lang).join().unwrap();
        assert_eq!(
            on_worker,
            Lang::En,
            "a worker thread must NOT inherit a test's override; it reads the process language"
        );

        clear_lang_override();
        assert_eq!(lang(), Lang::En, "clearing returns this thread to the process language");
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
