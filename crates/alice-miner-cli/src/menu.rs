//! `menu` — the interactive TUI launcher shown when `alice-miner` runs with NO
//! subcommand on an interactive TTY (and not `--json`, not `--from-service`).
//!
//! This module OWNS only presentation + selection. It NEVER reimplements a command:
//! it returns a [`MenuAction`] and `main.rs` dispatches it to the SAME entry points
//! the power-user subcommands use (`cmd_start`, the live dashboard/`start` render,
//! `balance::run`, `cmd_doctor`, `update::run`, `cmd_lang`, `cmd_identity_show`,
//! `cmd_service`). Any subcommand or flag on the command line bypasses this entirely.
//!
//! Flow:
//!   1. If there is NO saved language preference (settings.json), show a language pick
//!      FIRST (English / 中文) and persist the choice (reusing core `set_lang` +
//!      `save_lang`).
//!   2. Show a polished menu with the Alice logo (see [`crate::logo`]) at the top and
//!      the items — arrow-key / number selection, brand-styled.
//!
//! ROBUSTNESS: a raw-mode + alternate-screen RAII guard restores the terminal on exit
//! AND on panic (a hook), and Ctrl-C / `q` / Esc exit cleanly. On a terminal that
//! can't enter raw mode, [`run`] returns [`MenuAction::Quit`] and `main.rs` falls back
//! to printing help — the menu never wedges the shell.

use std::io::{self, Stdout};

use ratatui::crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::{Frame, Terminal};

use alice_miner_core::i18n::{self, Lang};
use alice_miner_core::tr;

use crate::logo;

/// What the user chose in the menu — dispatched by `main.rs` to the existing command
/// entry points (this module never runs a command itself).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuAction {
    /// [1] Start mining (auto lane). `main.rs` calls `cmd_start` with an auto lane.
    StartMining,
    /// [2] Status & telemetry — the live dashboard (`main.rs` runs the `start`
    /// render / status view).
    Status,
    /// [3] Balance — the three-bucket `balance` command.
    Balance,
    /// [4] Settings (language / identity show / background service).
    Settings,
    /// [5] Doctor + self-repair.
    Doctor,
    /// [6] Check for updates.
    Update,
    /// [7] Training — the RLVR training worker (`main.rs` runs the `train` role).
    Training,
    /// [0] Quit (also chosen on q / Esc / Ctrl-C, or when the terminal can't go raw).
    Quit,
}

/// One selectable menu item: its action + the localized label/hint at render time.
struct Item {
    action: MenuAction,
    /// The 1-char selector shown in the gutter (`1`..`6`, `0` for quit).
    key: char,
}

/// The menu items, in display order. Labels are localized in [`item_label`] so the
/// list itself is language-agnostic.
const ITEMS: &[Item] = &[
    Item { action: MenuAction::StartMining, key: '1' },
    Item { action: MenuAction::Status, key: '2' },
    Item { action: MenuAction::Balance, key: '3' },
    Item { action: MenuAction::Settings, key: '4' },
    Item { action: MenuAction::Doctor, key: '5' },
    Item { action: MenuAction::Update, key: '6' },
    Item { action: MenuAction::Training, key: '7' },
    Item { action: MenuAction::Quit, key: '0' },
];

/// The localized label for a menu action.
fn item_label(a: MenuAction) -> String {
    match a {
        MenuAction::StartMining => tr!("Start mining", "开始挖矿").to_string(),
        MenuAction::Status => tr!("Status & telemetry", "状态与遥测").to_string(),
        MenuAction::Balance => tr!("Balance", "余额").to_string(),
        MenuAction::Settings => tr!("Settings", "设置").to_string(),
        MenuAction::Doctor => tr!("Doctor + self-repair", "诊断与自修复").to_string(),
        MenuAction::Update => tr!("Check for updates", "检查更新").to_string(),
        MenuAction::Training => tr!("Training", "训练").to_string(),
        MenuAction::Quit => tr!("Quit", "退出").to_string(),
    }
}

/// A one-line hint shown under the highlighted item (what it does).
fn item_hint(a: MenuAction) -> String {
    match a {
        MenuAction::StartMining => {
            tr!("mine to your Alice address (auto lane)", "挖矿到你的 Alice 地址(自动通道)").to_string()
        }
        MenuAction::Status => {
            tr!("the live dashboard for a running miner", "运行中矿工的实时看板").to_string()
        }
        MenuAction::Balance => {
            tr!("credit · PRL rebate · ALICE token", "积分 · PRL 返现 · ALICE 代币").to_string()
        }
        MenuAction::Settings => {
            tr!("language · identity · background service", "语言 · 身份 · 后台服务").to_string()
        }
        MenuAction::Doctor => {
            tr!("diagnose problems and print the exact fix", "诊断问题并给出确切修复方法").to_string()
        }
        MenuAction::Update => {
            tr!("check for a newer signed version", "检查更新的已签名版本").to_string()
        }
        MenuAction::Training => {
            tr!("solve RLVR coding tasks for credit (积分)", "为积分解决 RLVR 编码任务").to_string()
        }
        MenuAction::Quit => tr!("exit alice-miner", "退出 alice-miner").to_string(),
    }
}

/// The terminal guard: enters raw mode + the alternate screen, restores both on
/// `Drop` and on panic (a hook). Mirrors `tui::Tui`'s discipline exactly.
struct MenuTerm {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl MenuTerm {
    fn new() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = restore_terminal();
            prev(info);
        }));
        let terminal = Terminal::new(CrosstermBackend::new(stdout))?;
        Ok(MenuTerm { terminal })
    }
}

impl Drop for MenuTerm {
    fn drop(&mut self) {
        let _ = restore_terminal();
    }
}

/// Leave the alternate screen + disable raw mode (idempotent / best-effort).
fn restore_terminal() -> io::Result<()> {
    let mut stdout = io::stdout();
    let _ = execute!(stdout, LeaveAlternateScreen);
    disable_raw_mode()
}

/// Run the interactive launcher and return the chosen [`MenuAction`]. On a terminal
/// that can't enter raw mode (or any setup error), returns [`MenuAction::Quit`] so
/// `main.rs` falls back to help — the menu never wedges the shell.
///
/// If there is NO saved language preference yet, a language pick is shown FIRST and
/// the choice is persisted (so it's never asked again). Then the main menu is shown.
pub fn run() -> MenuAction {
    // If the terminal can't go raw, bail to Quit (main prints help). Never a panic.
    let mut term = match MenuTerm::new() {
        Ok(t) => t,
        Err(_) => return MenuAction::Quit,
    };

    // 1) First-run language pick, only when there's no saved preference.
    if alice_miner_core::settings::load().parsed_lang().is_none() {
        match pick_language(&mut term) {
            Some(lang) => {
                i18n::set_lang(lang);
                let _ = alice_miner_core::settings::save_lang(lang);
            }
            // User quit the language screen → quit the whole launcher cleanly.
            None => return MenuAction::Quit,
        }
    }

    // 2) The main menu.
    main_menu(&mut term)
}

/// The language-pick screen (English / 中文). Returns the chosen language, or `None`
/// if the user quit (q / Esc / Ctrl-C). Reached only on the very first run.
fn pick_language(term: &mut MenuTerm) -> Option<Lang> {
    let langs = [Lang::En, Lang::Zh];
    let mut sel: usize = 0;
    loop {
        let _ = term.terminal.draw(|f| draw_language(f, sel));
        match read_key() {
            Key::Up => sel = (sel + langs.len() - 1) % langs.len(),
            Key::Down => sel = (sel + 1) % langs.len(),
            Key::Digit('1') => return Some(Lang::En),
            Key::Digit('2') => return Some(Lang::Zh),
            Key::Enter => return Some(langs[sel]),
            Key::Quit => return None,
            _ => {}
        }
    }
}

/// The main menu loop. Returns the chosen [`MenuAction`] (Quit on q / Esc / Ctrl-C).
fn main_menu(term: &mut MenuTerm) -> MenuAction {
    // Start on the first item (Start mining).
    let mut sel: usize = 0;
    loop {
        let _ = term.terminal.draw(|f| draw_menu(f, sel));
        match read_key() {
            Key::Up => sel = (sel + ITEMS.len() - 1) % ITEMS.len(),
            Key::Down => sel = (sel + 1) % ITEMS.len(),
            Key::Enter => return ITEMS[sel].action,
            Key::Digit(d) => {
                if let Some(item) = ITEMS.iter().find(|i| i.key == d) {
                    return item.action;
                }
            }
            Key::Quit => return MenuAction::Quit,
            _ => {}
        }
    }
}

/// A minimal key abstraction over crossterm events (so the loops read clearly).
enum Key {
    Up,
    Down,
    Enter,
    Digit(char),
    Quit,
    Other,
}

/// Block for one key event and classify it. Ctrl-C, `q`, and Esc all map to `Quit`
/// (crossterm consumes Ctrl-C in raw mode, so we treat it as quit explicitly).
fn read_key() -> Key {
    // A read error (should not happen in raw mode) is treated as Quit so we never spin.
    let ev = match event::read() {
        Ok(e) => e,
        Err(_) => return Key::Quit,
    };
    if let Event::Key(k) = ev {
        if k.kind != KeyEventKind::Press {
            return Key::Other;
        }
        if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
            return Key::Quit;
        }
        return match k.code {
            KeyCode::Up | KeyCode::Char('k') => Key::Up,
            KeyCode::Down | KeyCode::Char('j') => Key::Down,
            KeyCode::Enter => Key::Enter,
            KeyCode::Esc | KeyCode::Char('q') => Key::Quit,
            KeyCode::Char(c) if c.is_ascii_digit() => Key::Digit(c),
            _ => Key::Other,
        };
    }
    Key::Other
}

/// Draw the language-pick screen: the logo, a bilingual prompt, and the two options.
fn draw_language(f: &mut Frame, sel: usize) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(logo::LOGO_ROWS + 2),
            Constraint::Length(2),
            Constraint::Min(4),
            Constraint::Length(1),
        ])
        .split(f.area());

    render_logo_block(f, chunks[0]);

    let prompt = Paragraph::new("Select language / 选择语言")
        .alignment(Alignment::Center)
        .style(Style::default().add_modifier(Modifier::BOLD));
    f.render_widget(prompt, chunks[1]);

    let options = [("1", "English"), ("2", "中文")];
    let mut lines: Vec<Line> = Vec::new();
    for (i, (key, label)) in options.iter().enumerate() {
        lines.push(option_line(key, label, "", i == sel));
    }
    let list = Paragraph::new(lines)
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::NONE));
    f.render_widget(list, chunks[2]);

    let footer = Paragraph::new("↑/↓ · Enter · q")
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(footer, chunks[3]);
}

/// Draw the main menu: the logo, the tagline, the selectable list (with the hint under
/// the highlighted row), and the keybinding footer.
fn draw_menu(f: &mut Frame, sel: usize) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(logo::LOGO_ROWS + 2),
            Constraint::Length(2),
            Constraint::Min((ITEMS.len() as u16) + 2),
            Constraint::Length(1),
        ])
        .split(f.area());

    render_logo_block(f, chunks[0]);

    // Tagline (credit-only honest — the product one-liner, no reward promise).
    let tagline = Paragraph::new(tr!(
        "Alice Miner · one-click mining (credit-only)",
        "Alice 矿工 · 一键挖矿(credit-only)"
    ))
    .alignment(Alignment::Center)
    .style(Style::default().fg(logo::BRAND).add_modifier(Modifier::BOLD));
    f.render_widget(tagline, chunks[1]);

    // The item list.
    let mut lines: Vec<Line> = Vec::new();
    for (i, item) in ITEMS.iter().enumerate() {
        let selected = i == sel;
        let hint = if selected { item_hint(item.action) } else { String::new() };
        lines.push(option_line(
            &item.key.to_string(),
            &item_label(item.action),
            &hint,
            selected,
        ));
    }
    let list = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} ", tr!("Menu", "菜单"))),
    );
    f.render_widget(list, chunks[2]);

    // Footer keybindings.
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" ↑/↓ ", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::styled(format!(" {}  ", tr!("move", "移动")), Style::default().fg(Color::DarkGray)),
        Span::styled(" Enter ", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::styled(format!(" {}  ", tr!("select", "选择")), Style::default().fg(Color::DarkGray)),
        Span::styled(" 1-7 ", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::styled(format!(" {}  ", tr!("jump", "跳转")), Style::default().fg(Color::DarkGray)),
        Span::styled(" q ", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::styled(format!(" {}", tr!("quit", "退出")), Style::default().fg(Color::DarkGray)),
    ]));
    f.render_widget(footer, chunks[3]);
}

/// Render the logo centered in `area` (a bordered block titled "Alice").
fn render_logo_block(f: &mut Frame, area: ratatui::layout::Rect) {
    let logo = Paragraph::new(logo::lines())
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::NONE));
    f.render_widget(logo, area);
}

/// One selectable option row: a gutter key, the label (bold + brand when selected),
/// and an optional dim hint. Selected rows are prefixed with a brand-colored `▸`.
fn option_line(key: &str, label: &str, hint: &str, selected: bool) -> Line<'static> {
    let marker = if selected { "▸ " } else { "  " };
    let key_style = if selected {
        Style::default().fg(Color::Black).bg(logo::BRAND).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let label_style = if selected {
        Style::default().fg(logo::BRAND).add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    let mut spans = vec![
        Span::styled(marker.to_string(), Style::default().fg(logo::BRAND)),
        Span::styled(format!(" {key} "), key_style),
        Span::raw("  "),
        Span::styled(label.to_string(), label_style),
    ];
    if selected && !hint.is_empty() {
        spans.push(Span::styled(
            format!("   — {hint}"),
            Style::default().fg(Color::DarkGray),
        ));
    }
    Line::from(spans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alice_miner_core::i18n::{set_lang, Lang};

    /// The language global is process-wide, so language-sensitive tests serialize on
    /// this lock (Rust runs a crate's tests in parallel). Returns the held guard.
    // The PROCESS-GLOBAL language is shared by EVERY module's tests in this one test
    // binary, so they serialize on the CRATE-wide lock (see `main.rs::LANG_TEST_LOCK`) —
    // a module-private mutex would only order this module against itself.
    fn lang_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::LANG_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Every menu item has a localized label + hint in BOTH languages (no empty
    /// strings, no missing translation).
    #[test]
    fn all_items_localized_both_languages() {
        let _g = lang_lock();
        for lang in [Lang::En, Lang::Zh] {
            set_lang(lang);
            for item in ITEMS {
                assert!(!item_label(item.action).is_empty(), "empty label for {:?}", item.action);
                assert!(!item_hint(item.action).is_empty(), "empty hint for {:?}", item.action);
            }
        }
        set_lang(Lang::En);
    }

    /// The item keys are the documented selectors (1-6 then 0 for quit), unique.
    #[test]
    fn item_keys_are_expected_and_unique() {
        let keys: Vec<char> = ITEMS.iter().map(|i| i.key).collect();
        assert_eq!(keys, vec!['1', '2', '3', '4', '5', '6', '7', '0']);
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), keys.len(), "keys must be unique");
    }

    /// The digit selectors map to the right actions (the number-jump path).
    #[test]
    fn digit_selectors_map_to_actions() {
        let find = |d: char| ITEMS.iter().find(|i| i.key == d).map(|i| i.action);
        assert_eq!(find('1'), Some(MenuAction::StartMining));
        assert_eq!(find('3'), Some(MenuAction::Balance));
        assert_eq!(find('6'), Some(MenuAction::Update));
        assert_eq!(find('0'), Some(MenuAction::Quit));
    }

    /// A selected option line carries the brand marker + the hint; an unselected one
    /// does not show the hint.
    #[test]
    fn option_line_shows_hint_only_when_selected() {
        let _g = lang_lock();
        set_lang(Lang::En);
        let sel: String = option_line("1", "Start mining", "mine now", true)
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect();
        assert!(sel.contains("▸"), "selected marker");
        assert!(sel.contains("mine now"), "hint shown when selected");

        let unsel: String = option_line("1", "Start mining", "mine now", false)
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect();
        assert!(!unsel.contains("mine now"), "hint hidden when unselected");
    }
}
