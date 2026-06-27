//! `tui` — the in-place live dashboard for an INTERACTIVE TTY (the `start` loop).
//!
//! This is a **render-layer swap only**: every value comes from the same
//! [`Snapshot`] the plain line renderer ([`crate::dashboard::render_snapshot`])
//! uses — no engine change, no new field. The append-only scrolling block becomes a
//! fixed `ratatui` panel that redraws in place each tick: a top status bar
//! (state / lane / uptime / endpoint / failovers), a stats row (hashrate, shares
//! A/R, accepted %, the reject-tone + crediting line), a per-lane table for a dual
//! run, and a bottom message / last-line ticker.
//!
//! WHEN it's used (the three honest paths, chosen ONCE in `cmd_start`):
//!   * `--json`            → JSON lines (machine output) — TUI never touches it.
//!   * non-TTY, non-json   → the existing line renderer (piped / CI) — unchanged.
//!   * interactive TTY     → this panel.
//!
//! TEARDOWN: [`Tui`] is an RAII guard — `new` enters raw mode + the alternate
//! screen; `Drop` leaves them, and a panic hook restores the terminal first so a
//! crash never leaves the user's shell in raw mode. The pure row/string builders
//! ([`status_spans`], [`stats_line`], [`lane_rows`], [`ticker_text`]) are
//! unit-tested without a terminal.
//!
//! HONEST / CREDIT-ONLY: the panel renders the SAME activity the line dashboard
//! does (rewards only ever "pending · 待发放"; the crediting line is the engine's
//! own confirmation), and shows only the PUBLIC relay endpoint the snapshot carries.

use std::io::{self, Stdout};

use ratatui::crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use ratatui::{Frame, Terminal};
use ratatui::backend::CrosstermBackend;

use alice_miner_core::{EngineState, Snapshot};

use crate::dashboard::{fmt_hashrate, fmt_uptime};

/// The reward wording — the ONLY way rewards are shown (mirrors the line
/// dashboard's `REWARD_PENDING`). Never a number / `$`.
const REWARD_PENDING: &str = "pending · 待发放";

/// The live-TUI terminal guard. Owns the alternate-screen + raw-mode lifecycle so
/// the terminal is always restored — on normal exit (`Drop`) and on panic (a hook
/// set in [`Tui::new`]).
pub struct Tui {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl Tui {
    /// Enter raw mode + the alternate screen and install a panic hook that restores
    /// the terminal before the default hook prints the panic (so a crash mid-draw
    /// never leaves the shell in raw mode). Returns an error if the terminal can't be
    /// put into raw mode (the caller then falls back to the line renderer).
    pub fn new() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;

        // Restore the terminal on panic BEFORE the default hook runs.
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = restore_terminal();
            prev(info);
        }));

        let terminal = Terminal::new(CrosstermBackend::new(stdout))?;
        Ok(Tui { terminal })
    }

    /// Redraw the whole panel from `snap` (in place — clears + repaints each tick).
    pub fn draw(&mut self, snap: &Snapshot) -> io::Result<()> {
        self.terminal.draw(|f| render(f, snap))?;
        Ok(())
    }

    /// Poll for a quit key (`q` / `Esc` / Ctrl-C) without blocking longer than
    /// `timeout_ms`. Returns `true` when the user asked to quit. Crossterm's own
    /// Ctrl-C is consumed here in raw mode (the process-wide ctrlc handler may not
    /// fire while raw), so we treat Ctrl-C as quit explicitly.
    pub fn poll_quit(&self, timeout_ms: u64) -> io::Result<bool> {
        if event::poll(std::time::Duration::from_millis(timeout_ms))? {
            if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press {
                    let ctrl_c =
                        k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c');
                    if ctrl_c || matches!(k.code, KeyCode::Char('q') | KeyCode::Esc) {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        let _ = restore_terminal();
    }
}

/// Leave the alternate screen + disable raw mode (idempotent / best-effort). Shared
/// by `Drop` and the panic hook so the terminal is restored exactly once each way.
fn restore_terminal() -> io::Result<()> {
    let mut stdout = io::stdout();
    let _ = execute!(stdout, LeaveAlternateScreen);
    disable_raw_mode()
}

/// The short engine-state label (mirrors the line dashboard's `fmt_state`).
fn state_label(state: EngineState) -> &'static str {
    match state {
        EngineState::Idle => "idle",
        EngineState::Starting => "starting",
        EngineState::Running => "running",
        EngineState::Stopping => "stopping",
        EngineState::Error => "error",
    }
}

/// A theme colour for an engine state (green running / yellow transitional / red
/// error / dim idle).
fn state_color(state: EngineState) -> Color {
    match state {
        EngineState::Running => Color::Green,
        EngineState::Starting | EngineState::Stopping => Color::Yellow,
        EngineState::Error => Color::Red,
        EngineState::Idle => Color::DarkGray,
    }
}

/// Accepted-share percentage, e.g. `99%`; empty until a share is submitted.
fn accepted_pct(accepted: u64, rejected: u64) -> String {
    let total = accepted + rejected;
    if total == 0 {
        String::new()
    } else {
        format!("{:.0}%", accepted as f64 / total as f64 * 100.0)
    }
}

/// Build the status-bar spans: `[state] LANE · up HH:MM:SS · ENDPOINT [· failed-over×N]`.
/// Pure — exposed for tests.
pub fn status_spans(snap: &Snapshot) -> Vec<Span<'static>> {
    let mut spans = vec![
        Span::styled(
            format!(" {} ", state_label(snap.state)),
            Style::default().fg(Color::Black).bg(state_color(snap.state)).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            snap.lane.map(|l| l.label().to_string()).unwrap_or_else(|| "—".into()),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("  ·  up {}", fmt_uptime(snap.uptime_s))),
        Span::raw(format!("  ·  {}", snap.endpoint.as_deref().unwrap_or("—"))),
    ];
    if snap.failovers > 0 {
        spans.push(Span::styled(
            format!("  ·  failed-over×{}", snap.failovers),
            Style::default().fg(Color::Yellow),
        ));
    }
    if snap.dual {
        spans.push(Span::styled("  ·  [dual]", Style::default().fg(Color::Cyan)));
    }
    spans
}

/// Build the one-line stats string: `HASHRATE · shares A/R (acc%) · rewards pending`.
/// Pure — exposed for tests.
pub fn stats_line(snap: &Snapshot) -> String {
    let pct = accepted_pct(snap.shares_accepted, snap.shares_rejected);
    let pct = if pct.is_empty() { String::new() } else { format!(" ({pct})") };
    format!(
        "{}   ·   shares {}A/{}R{}   ·   rewards {}",
        fmt_hashrate(snap.hashrate_hs),
        snap.shares_accepted,
        snap.shares_rejected,
        pct,
        REWARD_PENDING,
    )
}

/// The crediting-health line for a pearlhash lane: the positive "counting"
/// confirmation when Running with no pause message; `None` otherwise (the pause case
/// is carried by the ticker, so the two never contradict — same rule as the line
/// dashboard). Pure — exposed for tests.
pub fn crediting_line(snap: &Snapshot) -> Option<String> {
    let is_prl = snap.lane.map(|l| l.is_prl_lane()).unwrap_or(false);
    let healthy = snap.state == EngineState::Running
        && snap.message.as_deref().map(str::is_empty).unwrap_or(true);
    (is_prl && healthy).then(|| "rewards: counting (PoP active · credit-only)".to_string())
}

/// Build the per-lane rows for a dual run (empty for a single lane). Each row:
/// lane label, state, hashrate, shares A/R, endpoint. Pure — exposed for tests.
pub fn lane_rows(snap: &Snapshot) -> Vec<[String; 5]> {
    if !snap.dual {
        return Vec::new();
    }
    snap.lanes
        .iter()
        .map(|l| {
            [
                l.lane.label().to_string(),
                state_label(l.state).to_string(),
                fmt_hashrate(l.hashrate_hs),
                format!("{}A/{}R", l.shares_accepted, l.shares_rejected),
                l.endpoint.clone().unwrap_or_else(|| "—".into()),
            ]
        })
        .collect()
}

/// The bottom ticker text: the engine `message` (a warning / pause reason) when set,
/// else the sanitised `last_line`, else a hint. Pure — exposed for tests.
pub fn ticker_text(snap: &Snapshot) -> String {
    if let Some(m) = snap.message.as_deref() {
        if !m.is_empty() {
            return format!("! {m}");
        }
    }
    if let Some(l) = snap.last_line.as_deref() {
        if !l.is_empty() {
            return format!("| {l}");
        }
    }
    "q / Esc / Ctrl-C to stop".to_string()
}

/// Render the whole panel into `frame` from `snap`.
fn render(frame: &mut Frame, snap: &Snapshot) {
    let dual = snap.dual && !snap.lanes.is_empty();
    // Vertical layout: status bar, stats, [lane table?], ticker.
    let mut constraints = vec![Constraint::Length(3), Constraint::Length(4)];
    if dual {
        // 2 header + N lane rows + borders.
        let h = (snap.lanes.len() as u16) + 3;
        constraints.push(Constraint::Length(h));
    }
    constraints.push(Constraint::Min(3));
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(frame.area());

    // 1) Status bar.
    let status = Paragraph::new(Line::from(status_spans(snap))).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Alice Miner ")
            .title_style(Style::default().add_modifier(Modifier::BOLD)),
    );
    frame.render_widget(status, chunks[0]);

    // 2) Stats + (optional) crediting line.
    let mut stats_lines = vec![Line::from(stats_line(snap))];
    if let Some(c) = crediting_line(snap) {
        stats_lines.push(Line::from(Span::styled(c, Style::default().fg(Color::Green))));
    }
    let stats = Paragraph::new(stats_lines)
        .block(Block::default().borders(Borders::ALL).title(" Activity "));
    frame.render_widget(stats, chunks[1]);

    // 3) Per-lane table (dual only).
    let mut next = 2;
    if dual {
        let header = Row::new(["LANE", "STATE", "HASHRATE", "SHARES", "ENDPOINT"])
            .style(Style::default().add_modifier(Modifier::BOLD));
        let rows: Vec<Row> = lane_rows(snap)
            .into_iter()
            .map(|r| Row::new(r.map(Cell::from)))
            .collect();
        let widths = [
            Constraint::Length(16),
            Constraint::Length(9),
            Constraint::Length(24),
            Constraint::Length(10),
            Constraint::Min(20),
        ];
        let table = Table::new(rows, widths)
            .header(header)
            .block(Block::default().borders(Borders::ALL).title(" Lanes "));
        frame.render_widget(table, chunks[next]);
        next += 1;
    }

    // 4) Bottom ticker.
    let ticker = Paragraph::new(ticker_text(snap))
        .style(Style::default().fg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(ticker, chunks[next]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alice_miner_core::engine::{LaneSnapshot, Snapshot};
    use alice_miner_core::Lane;

    fn running() -> Snapshot {
        Snapshot {
            state: EngineState::Running,
            device: None,
            lane: Some(Lane::Xmr),
            hashrate_hs: Some(8_432.0),
            shares_accepted: 142,
            shares_rejected: 1,
            endpoint: Some("hk.aliceprotocol.org:3333".into()),
            worker_id: Some("rig-7f3a".into()),
            uptime_s: 3_661,
            failovers: 0,
            dual: false,
            lanes: vec![],
            last_line: Some("net accepted (142/1) diff 100".into()),
            message: None,
            prl_payout: None,
        }
    }

    fn dual() -> Snapshot {
        Snapshot {
            state: EngineState::Running,
            device: None,
            lane: Some(Lane::Xmr),
            hashrate_hs: Some(25_008_432.0),
            shares_accepted: 145,
            shares_rejected: 1,
            endpoint: Some("hk.aliceprotocol.org:3333".into()),
            worker_id: Some("rig-7f3a".into()),
            uptime_s: 65,
            failovers: 1,
            dual: true,
            lanes: vec![
                LaneSnapshot {
                    lane: Lane::Xmr,
                    state: EngineState::Running,
                    hashrate_hs: Some(8_432.0),
                    shares_accepted: 142,
                    shares_rejected: 1,
                    endpoint: Some("hk.aliceprotocol.org:3333".into()),
                    failovers: 1,
                },
                LaneSnapshot {
                    lane: Lane::GpuRvn,
                    state: EngineState::Running,
                    hashrate_hs: Some(25_000_000.0),
                    shares_accepted: 3,
                    shares_rejected: 0,
                    endpoint: Some("hk.aliceprotocol.org:8888".into()),
                    failovers: 0,
                },
            ],
            last_line: None,
            message: None,
            prl_payout: None,
        }
    }

    fn prl() -> Snapshot {
        let mut s = running();
        s.lane = Some(Lane::GpuPrl);
        s.endpoint = Some("us.aliceprotocol.org:3340".into());
        s
    }

    /// The status spans carry the state, lane label, uptime, and endpoint; the
    /// failover marker appears only when failovers > 0.
    #[test]
    fn status_spans_carry_core_fields() {
        let text: String = status_spans(&running()).iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("running"));
        assert!(text.contains("CPU · XMR"));
        assert!(text.contains("01:01:01"), "uptime: {text}");
        assert!(text.contains("hk.aliceprotocol.org:3333"));
        assert!(!text.contains("failed-over"), "no failover marker at 0");

        let mut s = running();
        s.failovers = 2;
        let text: String = status_spans(&s).iter().map(|x| x.content.as_ref()).collect();
        assert!(text.contains("failed-over×2"));
    }

    /// The stats line carries the human hashrate, shares A/R + accepted %, and the
    /// ONLY reward wording — credit-only (no `$` / paid).
    #[test]
    fn stats_line_is_credit_only() {
        let s = stats_line(&running());
        assert!(s.contains("8.43 kH/s"), "{s}");
        assert!(s.contains("142A/1R"));
        assert!(s.contains("(99%)"));
        assert!(s.contains(REWARD_PENDING));
        let lower = s.to_lowercase();
        for forbidden in ["$", "usd", "paid", "earned", "已发放"] {
            assert!(!lower.contains(forbidden), "stats leaked `{forbidden}`: {s}");
        }
    }

    /// Accepted % is omitted before any share (no "100%" of zero).
    #[test]
    fn stats_line_no_pct_until_a_share() {
        let mut s = running();
        s.shares_accepted = 0;
        s.shares_rejected = 0;
        assert!(!stats_line(&s).contains('%'), "no pct of zero shares");
    }

    /// The crediting line shows for a healthy pearlhash lane, is suppressed when a
    /// pause message is set, and never appears for XMR (address-only).
    #[test]
    fn crediting_line_rules_match_dashboard() {
        assert!(crediting_line(&prl()).is_some(), "healthy PRL counts");

        let mut paused = prl();
        paused.message = Some("PoP re-verify failing — crediting may pause".into());
        assert!(crediting_line(&paused).is_none(), "pause suppresses counting");

        assert!(crediting_line(&running()).is_none(), "XMR has no OOB-PoP crediting");
    }

    /// Lane rows are empty for a single lane and carry both lanes (with their own
    /// ports) for a dual run.
    #[test]
    fn lane_rows_only_for_dual() {
        assert!(lane_rows(&running()).is_empty(), "single lane → no per-lane rows");
        let rows = lane_rows(&dual());
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0][0], "CPU · XMR");
        assert_eq!(rows[1][0], "GPU · RVN");
        assert!(rows[0][4].contains(":3333"), "XMR port");
        assert!(rows[1][4].contains(":8888"), "RVN port");
    }

    /// The ticker prefers the engine message, falls back to the last line, then a
    /// hint — and prefixes them distinctly.
    #[test]
    fn ticker_prefers_message_then_last_line_then_hint() {
        let mut s = running();
        s.message = Some("retrying relay".into());
        assert_eq!(ticker_text(&s), "! retrying relay");

        // No message → last line.
        let base = running(); // last_line = Some(...)
        assert!(ticker_text(&base).starts_with("| net accepted"));

        // Neither → the quit hint.
        let mut bare = running();
        bare.message = None;
        bare.last_line = None;
        assert!(ticker_text(&bare).contains("Ctrl-C to stop"));
    }
}
