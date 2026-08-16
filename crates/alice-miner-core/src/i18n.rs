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
//! [`init_startup_lang`] is how a front-end keeps the first half of that bargain, and
//! it is deliberately shaped so there is only ONE right place to call it: the first
//! statement of `main`, before the process can produce any user-facing text at all.
//! Both front-ends do exactly that. It needs no parsed command line (it scans argv for
//! `--lang` itself) and never prompts, so nothing has to run ahead of it. The CLI then
//! re-resolves post-parse — same precedence, plus clap's validated flag, the
//! interactive first-run prompt and persistence — which can only ever CONFIRM or
//! REFINE the early answer.
//!
//! The GUI crate reads this same global as its ONE language state: `MinerApp::lang_zh`
//! is a view of [`lang`] rather than a field, and the EN/中 chip writes through
//! `MinerApp::set_lang_zh` (which sets the process language AND persists the choice).
//! The desktop titlebar pill + Settings labels therefore localize through the SAME
//! `tr!` mechanism as the CLI (no second i18n system, and no per-frame global write).
//! The GUI's bilingual-inline `ui/strings.rs` constants (which embed both languages in
//! one string) are unaffected.
//!
//! ## The ordering bug this module now audits
//!
//! Text formatted before the front-end resolves the language is silently English,
//! whatever the user picked — and the code reads correctly at every individual call
//! site, because each one uses `tr!` properly. The only thing wrong is WHEN it ran.
//! [`lang`] therefore records whether anything read the process language before
//! [`set_process_lang`] ever ran; [`text_selected_before_language_resolved`] reports
//! it, and the CLI surfaces that under `ALICE_MINER_LANG_SELFCHECK` so a test can put
//! the question to the REAL binary instead of to a reviewer's memory.
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
//!
//! ## Picking the wrong one of the two is not a hazard either
//!
//! Which matters, because a test does not always get to choose: the honest way to test
//! a front-end's startup resolution or its EN/中 chip is to CALL them, and what they
//! call is [`set_process_lang`]. So the process-wide setter is process-wide only when
//! it is reached from the FRONT-END thread — the one running `main`. Reached from any
//! other thread it scopes to that thread, and libtest gives every test its own named
//! thread, in parallel and `--test-threads=1` mode alike.
//!
//! The result is the property the reader tests need and cannot state for themselves: a
//! test that never mentions the language cannot be affected by one that does, whichever
//! setter that one used, without either test knowing anything. `on_front_end_thread`
//! carries the argument for why no production caller is on the other side of that line,
//! and why CI checks it on each OS rather than asserting it.

use std::cell::Cell;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

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

/// Whether the calling thread is the process's FRONT-END thread — the one that runs
/// `main`, and in production the ONLY thread that ever resolves a language.
///
/// This is the whole of the test-isolation mechanism, so it is worth being precise
/// about what it can and cannot mistake:
///
///   * `Some("main")` — std names the thread that runs `main` exactly this, on every
///     platform, and both front-ends resolve the language synchronously inside `main`.
///     The CLI: `init_startup_lang`, `resolve_language`, `cmd_lang` and the launcher
///     menu, all called straight from `fn main` with no thread between (the one
///     `thread::spawn` in that file is the pool-stats poller, which touches no
///     language). The GUI: `init_startup_lang`, plus the EN/中 chip, which is drawn by
///     the eframe event loop — and winit PANICS if that loop is created off the main
///     thread, so a GUI whose chip ran anywhere else would not open a window at all.
///     Process-wide.
///   * `Some(_)` — a thread somebody NAMED. libtest names every test thread after the
///     test it runs, so this is what a test looks like from in here, and nothing in
///     production reaches this function on a named thread. Thread-scoped.
///   * `None` — an unnamed thread. libtest never produces one, so this cannot be a
///     test; it is some worker that has been handed the front-end's job. Treated as
///     production, so the failure direction is "a miner still sees his language"
///     rather than "a miner silently reads English".
///
/// The `Some("main")` half is not taken on trust: [`set_process_lang`] records when it
/// is false ([`process_lang_set_off_front_end_thread`]), the CLI reports that under
/// `ALICE_MINER_LANG_SELFCHECK`, and `tests/cli.rs` drives the REAL binary — on all
/// three OSes in CI — and additionally asserts that a 中文 user's rollback warning,
/// which is formatted off the main thread, comes out in 中文. If std named the main
/// thread something else on some platform, that test fails loudly there instead of
/// shipping English.
fn on_front_end_thread() -> bool {
    !matches!(std::thread::current().name(), Some(name) if name != "main")
}

/// Set the PROCESS-WIDE language — **the production setter**. The front-end calls this
/// ONCE at startup, via [`init_startup_lang`], as the first statement of `main`; after
/// that only an explicit user action moves it (the CLI's `lang` subcommand and
/// `--lang`, the GUI's EN/中 chip), and each of those persists the choice too. Visible
/// to EVERY thread, which is required: `supervise`'s failover status text is built on
/// the engine worker thread, not main.
///
/// It also latches "the language has been resolved" for
/// [`text_selected_before_language_resolved`], so call it only when that is true —
/// which is another way of saying: resolve, then set, then print.
///
/// ## Called off the front-end thread, this is scoped to that thread
///
/// …and that is what makes the test suite safe rather than careful. The process
/// language is one machine-wide cell, and `cargo test` puts a whole crate's tests in
/// ONE process; a test that reached that cell changed the answer under every English-
/// asserting test running beside it — which is not a thing those tests can defend
/// against, because they never mention the language at all. That is exactly how it
/// failed: `alice-miner-gui`'s "the language the user picks survives the window
/// closing" drives the real EN/中 chip, so it came through here, and it held the
/// process in 中文 for ~2.4ms of a ~1s test binary. Two `ui::dashboard` tests read
/// their `tr!` strings inside that window on the CI runners and asserted English
/// against 中文.
///
/// Making the write thread-scoped whenever it does not come from the front-end thread
/// closes that at the mechanism: libtest gives every test its own NAMED thread (in
/// parallel AND `--test-threads=1` mode alike), and no production caller is on one, so
/// the process-wide cell is unreachable from a test and CANNOT be moved out from under
/// a reader. Nothing has to be added to the reader, or to the writer, or remembered by
/// whoever writes the next test — which is the specific way the `LANG_TEST_LOCK` this
/// replaced used to fail (see the note at the foot of this module).
///
/// A test that wants a language should still say [`set_lang`]: it says what it means,
/// and it does not latch [`process_lang_resolved`].
pub fn set_process_lang(lang: Lang) {
    AUDIT.mark_resolved();
    if on_front_end_thread() {
        CURRENT.store(lang.to_u8(), Ordering::Relaxed);
    } else {
        AUDIT.note_off_front_end_set();
        set_lang(lang);
    }
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
        _ => {
            // Only a read that actually FALLS THROUGH to the process value can be
            // "text selected before the language was resolved" — a thread with its
            // own override (i.e. a test) answered its own question.
            AUDIT.note_read();
            Lang::from_u8(CURRENT.load(Ordering::Relaxed))
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Resolution audit — "was any text selected before the language was resolved?"
// ────────────────────────────────────────────────────────────────────────────

/// Two facts about this process: whether the front-end has resolved the language
/// yet, and whether anything read the process language BEFORE it did.
///
/// Its own type (rather than two loose statics) so the state machine can be tested
/// on a fresh instance — the process-wide one is a global whose history depends on
/// whichever test in the binary touched it first, and a test of "starts unresolved"
/// written against THAT would pass or fail depending on test order.
struct ResolveAudit {
    resolved: AtomicBool,
    read_early: AtomicBool,
    off_front_end_set: AtomicBool,
}

impl ResolveAudit {
    const fn new() -> Self {
        Self {
            resolved: AtomicBool::new(false),
            read_early: AtomicBool::new(false),
            off_front_end_set: AtomicBool::new(false),
        }
    }

    /// The front-end resolved the language. Latches: a later re-resolution (the
    /// CLI's post-parse pass, the GUI's EN/中 chip) is not a new startup.
    fn mark_resolved(&self) {
        self.resolved.store(true, Ordering::Relaxed);
    }

    /// Somebody asked for the process language. Before [`Self::mark_resolved`],
    /// that answer was the English DEFAULT rather than the user's choice — latch it.
    fn note_read(&self) {
        if !self.resolved.load(Ordering::Relaxed) {
            self.read_early.store(true, Ordering::Relaxed);
        }
    }

    /// A PROCESS-wide language set arrived from a thread that is not the front-end's
    /// (see [`on_front_end_thread`]) and was scoped to that thread instead. Normal and
    /// expected in a test binary — every test runs on such a thread, which is the
    /// point. In the REAL binary it means some worker has been handed the front-end's
    /// job and the language it installed reached only itself, so the CLI reports it.
    fn note_off_front_end_set(&self) {
        self.off_front_end_set.store(true, Ordering::Relaxed);
    }

    fn resolved(&self) -> bool {
        self.resolved.load(Ordering::Relaxed)
    }

    fn read_before_resolve(&self) -> bool {
        self.read_early.load(Ordering::Relaxed)
    }

    fn set_off_front_end(&self) -> bool {
        self.off_front_end_set.load(Ordering::Relaxed)
    }
}

static AUDIT: ResolveAudit = ResolveAudit::new();

/// Whether [`set_process_lang`] has run at all in this process.
pub fn process_lang_resolved() -> bool {
    AUDIT.resolved()
}

/// Whether any `tr!` / [`lang`] read reached the process language BEFORE the
/// front-end resolved it — i.e. whether this run produced user-facing text in the
/// English default while the user may have chosen 中文.
///
/// `false` is the contract; `true` is a bug in the front-end's startup ORDER, not
/// at the call site that formatted the text. The CLI prints this under
/// `ALICE_MINER_LANG_SELFCHECK` so a test can ask the real binary.
pub fn text_selected_before_language_resolved() -> bool {
    AUDIT.read_before_resolve()
}

/// Whether any [`set_process_lang`] in this process came from a thread that is not the
/// front-end's, and was therefore scoped to that thread rather than made process-wide.
///
/// TRUE is the norm inside a test binary — libtest runs every test on its own named
/// thread, and that scoping is exactly what keeps one test's language off another's.
/// In the REAL binary `false` is the contract, and `true` means one of two things,
/// both of which end with a 中文 user reading English on some other thread: a
/// front-end resolved the language somewhere other than `main`, or std did not name
/// the main thread `"main"` on this platform. The CLI prints this under
/// `ALICE_MINER_LANG_SELFCHECK` so CI can put the question to the real binary on each
/// OS instead of taking the mechanism on trust.
pub fn process_lang_set_off_front_end_thread() -> bool {
    AUDIT.set_off_front_end()
}

// ────────────────────────────────────────────────────────────────────────────
// Startup resolution — the one place a front-end turns a preference into the
// process language
// ────────────────────────────────────────────────────────────────────────────

/// The env vars that can carry a locale, in the precedence we read them.
const LOCALE_ENV_VARS: [&str; 3] = ["LC_ALL", "LANG", "LANGUAGE"];

/// Read a language preference from the `LC_ALL` / `LANG` / `LANGUAGE` env vars, in
/// that precedence. Returns the FIRST that parses to a known language; `None` if
/// none are set or none parse (the caller then defaults to English). A `C` /
/// `POSIX` locale parses to nothing → `None` → English.
pub fn lang_from_env() -> Option<Lang> {
    for var in LOCALE_ENV_VARS {
        if let Ok(val) = std::env::var(var) {
            if let Ok(lang) = val.parse::<Lang>() {
                return Some(lang);
            }
        }
    }
    None
}

/// Find a `--lang` / `--language` VALUE in a raw argument list, in both the
/// `--lang zh` and `--lang=zh` spellings (the CLI declares the flag global, so it
/// can sit anywhere on the line).
///
/// This exists so the language can be resolved BEFORE the command line is parsed —
/// argument parsing is itself a step that can produce user-facing output (clap's
/// `--help` / usage error), and the startup health gates run ahead of it on purpose.
/// The value is returned RAW and unvalidated: the front-end's post-parse resolution
/// owns the "unknown language" warning, and warning from here too would print it
/// twice.
///
/// Stops at a bare `--`: everything after it is a subcommand's data, not our flags.
pub fn lang_flag_in_args<I, S>(args: I) -> Option<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        let arg = arg.as_ref();
        if arg == "--" {
            return None;
        }
        for name in ["--lang", "--language"] {
            if arg == name {
                return iter.next().map(|v| v.as_ref().to_string());
            }
            if let Some(v) = arg.strip_prefix(name).and_then(|r| r.strip_prefix('=')) {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Resolve the startup language from the sources EVERY front-end shares, in the
/// documented precedence, with NO prompting, NO persistence and no output:
///
///   (a) an explicit flag value, when it parses (an unparseable one falls through);
///   (b) the persisted `~/.alice/settings.json` preference;
///   (c) the `LC_ALL` / `LANG` / `LANGUAGE` environment;
///   (d) English.
///
/// The CLI's post-parse `resolve_language` is this same order with the interactive
/// first-run prompt inserted between (b) and (c) — the one step that cannot run
/// before the command line is known (it must not fire for `service` / `--json` /
/// non-TTY runs), and the only reason a front-end resolves twice.
pub fn resolve_startup_lang(flag: Option<&str>) -> Lang {
    if let Some(lang) = flag.and_then(|f| f.parse::<Lang>().ok()) {
        return lang;
    }
    if let Some(lang) = crate::settings::load().parsed_lang() {
        return lang;
    }
    lang_from_env().unwrap_or(Lang::En)
}

/// Resolve the startup language from argv + settings + env and install it
/// process-wide. **Call this as the FIRST statement of `main`, in every front-end.**
///
/// Everything a miner reads is bilingual, so anything that runs before this line
/// prints in English no matter what the user chose — and the startup self-update
/// health gates, which run before the command line is even parsed, produce exactly
/// such text (a post-update line, and the auto-rollback warning: the highest-stakes
/// message this client can emit). Hence the shape of this function: it takes no
/// arguments, needs no parse, never prompts and never blocks, so there is nothing
/// that legitimately has to happen first.
///
/// Returns the language it installed.
pub fn init_startup_lang() -> Lang {
    let flag = lang_flag_in_args(
        std::env::args_os()
            .skip(1)
            .map(|a| a.to_string_lossy().into_owned()),
    );
    let lang = resolve_startup_lang(flag.as_deref());
    set_process_lang(lang);
    lang
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
//
// DO NOT BRING A LOCK BACK to close the `set_process_lang` hole either — that is the
// same mistake wearing a different hat, and it re-opens the same AB-BA cycle the
// moment one holder also wants `IDENTITY_ENV_LOCK`. The hole is closed by SCOPE (see
// `on_front_end_thread`), which needs no mutual exclusion at all: there is nothing to
// serialise once two tests cannot reach the same cell.

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

    /// The setter a front-end calls is the one a test of that front-end has to call
    /// too, so it must be safe from a test thread — and "safe" means the process-wide
    /// cell does not move, because that cell is what every OTHER test in the binary
    /// reads when it never mentioned a language.
    ///
    /// This is the mechanism the CI failure needed. Three consecutive 3-OS runs failed
    /// in `alice-miner-gui` on tests that assert English and set no language, because
    /// the test that drives the real EN/中 chip came through `set_process_lang` and
    /// held the process in 中文 for ~2.4ms.
    #[test]
    fn a_process_wide_set_from_a_test_thread_cannot_move_the_process_language() {
        // Whatever the rest of this binary is doing, an unrelated thread's view is the
        // process value, and this test is about to try to move it.
        let before = std::thread::spawn(lang).join().unwrap();

        set_process_lang(Lang::Zh);
        assert_eq!(lang(), Lang::Zh, "the calling thread still gets what it asked for");

        let on_worker = std::thread::spawn(lang).join().unwrap();
        assert_eq!(
            on_worker, before,
            "but a test CANNOT move the process-wide language — that is the cell every \
             English-asserting test in this binary reads, and none of them can defend it"
        );
        assert!(
            process_lang_set_off_front_end_thread(),
            "and the attempt is on record, which is what the CLI's real-binary \
             self-check reports"
        );

        clear_lang_override();
    }

    /// The rule that produces the isolation above, stated on its own so a change to it
    /// fails HERE rather than as a flake somewhere downstream: libtest names every test
    /// thread after its test, and that name is not `main`.
    ///
    /// Production is the other side of this: the front-ends resolve the language
    /// synchronously inside `main`. Nothing in a test binary can check THAT — which is
    /// why `lang_selfcheck` asks the real binary, on every OS, instead.
    #[test]
    fn a_libtest_thread_is_never_mistaken_for_the_front_end() {
        assert_eq!(
            std::thread::current().name(),
            Some("i18n::tests::a_libtest_thread_is_never_mistaken_for_the_front_end"),
            "libtest names a test's thread after the test — its FULL path, not the bare \
             fn name; the isolation rests on that name existing and not being `main`"
        );
        assert!(!on_front_end_thread(), "so a test is never the front-end thread");

        // An unnamed worker is not a test either, and is treated as production — the
        // fail-safe direction (a miner keeps his language; he never silently reads
        // English because a thread happened to be anonymous).
        assert!(std::thread::spawn(on_front_end_thread).join().unwrap());
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

    // ── startup resolution (the contract the front-ends have to keep) ───────

    /// Run `f` with `$ALICE_IDENTITY_DIR` pointed at a throwaway dir and the three
    /// locale env vars CLEARED (whatever the developer's shell has set), restoring
    /// both afterwards. Serialized on the crate-wide env lock, because every one of
    /// those is a process global.
    fn with_isolated_lang_env<F: FnOnce()>(f: F) {
        let _g = crate::IDENTITY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "alice-i18n-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let saved: Vec<(&str, Option<String>)> = LOCALE_ENV_VARS
            .iter()
            .map(|v| (*v, std::env::var(v).ok()))
            .collect();
        for (v, _) in &saved {
            std::env::remove_var(v);
        }
        std::env::set_var("ALICE_IDENTITY_DIR", &dir);

        f();

        std::env::remove_var("ALICE_IDENTITY_DIR");
        for (v, old) in saved {
            match old {
                Some(val) => std::env::set_var(v, val),
                None => std::env::remove_var(v),
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The audit's whole point is the ORDER of two events, so test it on a fresh
    /// instance: the process-wide one has already seen both by the time any test
    /// runs, and asserting against that would pass or fail by test order.
    #[test]
    fn resolve_audit_latches_only_a_read_that_preceded_resolution() {
        // Read first → the read got the English default, and that stays on record
        // even once the front-end resolves.
        let early = ResolveAudit::new();
        assert!(!early.resolved());
        assert!(!early.read_before_resolve());
        early.note_read();
        assert!(early.read_before_resolve(), "a read before resolution is recorded");
        early.mark_resolved();
        assert!(early.resolved());
        assert!(early.read_before_resolve(), "and it is not erased by resolving later");

        // Resolve first (the contract) → any number of later reads are clean.
        let ordered = ResolveAudit::new();
        ordered.mark_resolved();
        for _ in 0..3 {
            ordered.note_read();
        }
        assert!(ordered.resolved());
        assert!(
            !ordered.read_before_resolve(),
            "reads after resolution are what production is supposed to look like"
        );
    }

    /// `--lang` is a GLOBAL clap flag, so the pre-parse scan has to find it in both
    /// spellings and anywhere on the line — including after the subcommand.
    #[test]
    fn lang_flag_in_args_finds_every_spelling() {
        let f = |args: &[&str]| lang_flag_in_args(args.iter().copied());
        assert_eq!(f(&["--lang", "zh"]).as_deref(), Some("zh"));
        assert_eq!(f(&["--lang=zh"]).as_deref(), Some("zh"));
        assert_eq!(f(&["--language", "zh"]).as_deref(), Some("zh"));
        assert_eq!(f(&["--language=zh"]).as_deref(), Some("zh"));
        // Global flag: after the subcommand is a legal place for it.
        assert_eq!(f(&["start", "--lane", "xmr", "--lang", "zh"]).as_deref(), Some("zh"));
        // Nothing to find.
        assert_eq!(f(&["start", "--lane", "xmr"]), None);
        // A dangling `--lang` (clap will reject it) yields no value, not a panic.
        assert_eq!(f(&["start", "--lang"]), None);
        // Past a bare `--` it is a subcommand's data, not our flag.
        assert_eq!(f(&["ai", "--", "--lang", "zh"]), None);
        // The value is returned RAW — validating it is the front-end's job (it owns
        // the one "unknown language" warning).
        assert_eq!(f(&["--lang", "martian"]).as_deref(), Some("martian"));
    }

    /// The shared precedence, end to end: flag → saved settings → env → English.
    #[test]
    fn resolve_startup_lang_follows_the_documented_precedence() {
        with_isolated_lang_env(|| {
            // (d) nothing anywhere → English.
            assert_eq!(resolve_startup_lang(None), Lang::En);

            // (c) env only.
            std::env::set_var("LANG", "zh_CN.UTF-8");
            assert_eq!(resolve_startup_lang(None), Lang::Zh);

            // (b) a saved preference beats the env.
            std::env::set_var("LANG", "en_US.UTF-8");
            crate::settings::save_lang(Lang::Zh).expect("save");
            assert_eq!(resolve_startup_lang(None), Lang::Zh);

            // (a) an explicit flag beats the saved preference.
            assert_eq!(resolve_startup_lang(Some("en")), Lang::En);
            // An UNPARSEABLE flag falls through to the next source rather than
            // silently meaning English.
            assert_eq!(resolve_startup_lang(Some("martian")), Lang::Zh);
        });
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
