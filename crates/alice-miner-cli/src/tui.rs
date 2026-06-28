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
//! does (rewards only ever "credit · 积分 (credit-only)"; the crediting line is the engine's
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

use crate::dashboard::{
    fmt_hashrate, fmt_uptime, lane_table_rows, LaneHealth, LaneRow, SPINNER, STALE_AFTER_S,
};

/// The reward wording — the ONLY way rewards are shown (mirrors the line
/// dashboard's `REWARD_CREDIT`). Never a number / `$`.
const REWARD_CREDIT: &str = "credit · 积分 (credit-only)";

/// The footer keybinding bar — k9s/lazygit style, persistent across the dashboard.
/// Lists the keys that actually do something in the `start` panel.
const KEYBINDINGS: &[(&str, &str)] = &[("q", "quit"), ("Esc", "quit"), ("^C", "quit")];

/// The live-TUI terminal guard. Owns the alternate-screen + raw-mode lifecycle so
/// the terminal is always restored — on normal exit (`Drop`) and on panic (a hook
/// set in [`Tui::new`]).
pub struct Tui {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    /// Heartbeat spinner frame — advances every `draw` so an App-Nap stall (process
    /// alive but the stream wedged) is visible even though state still reads Running.
    spinner_frame: u64,
    /// The instant the stream last ADVANCED (a real activity change) + the last
    /// fingerprint, so a frozen stream lights the "no update Ns" chip.
    last_advance: std::time::Instant,
    prev_fingerprint: Option<(u64, u64, u64, u64)>,
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
        Ok(Tui {
            terminal,
            spinner_frame: 0,
            last_advance: std::time::Instant::now(),
            prev_fingerprint: None,
        })
    }

    /// Redraw the whole panel from `snap` (in place — clears + repaints each tick).
    pub fn draw(&mut self, snap: &Snapshot) -> io::Result<()> {
        // Advance the heartbeat + recompute staleness BEFORE drawing so a wedged
        // stream (no activity change) lights the "no update Ns" chip.
        let fp = fingerprint(snap);
        if self.prev_fingerprint != Some(fp) {
            self.prev_fingerprint = Some(fp);
            self.last_advance = std::time::Instant::now();
        }
        let beat = SPINNER[(self.spinner_frame as usize) % SPINNER.len()];
        let stale_s = self.last_advance.elapsed().as_secs();
        self.spinner_frame = self.spinner_frame.wrapping_add(1);
        self.terminal.draw(|f| render(f, snap, beat, stale_s))?;
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

/// The semaphore colour for a [`LaneHealth`] (green/amber/red/dim) — the per-lane
/// row tint in the always-on lane table.
fn health_color(h: LaneHealth) -> Color {
    match h {
        LaneHealth::Green => Color::Green,
        LaneHealth::Amber => Color::Yellow,
        LaneHealth::Red => Color::Red,
        LaneHealth::Idle => Color::DarkGray,
    }
}

/// A coarse activity fingerprint (uptime + share counts + quantized hashrate) — when
/// it stops changing, the stream is wedged and the heartbeat goes stale. Mirrors the
/// line renderer's `snapshot_fingerprint`. Credit-only (counts only).
fn fingerprint(snap: &Snapshot) -> (u64, u64, u64, u64) {
    let hr_q = snap.hashrate_hs.map(|h| h as u64).unwrap_or(0);
    (snap.uptime_s, snap.shares_accepted, snap.shares_rejected, hr_q)
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

/// Build the status-bar spans with a neutral (frame-0, fresh) heartbeat — the
/// back-compat / test entry point; the live path uses [`status_spans_beat`] with the
/// advancing frame + real staleness.
#[allow(dead_code)] // test / back-compat entry point; live path uses *_beat
pub fn status_spans(snap: &Snapshot) -> Vec<Span<'static>> {
    status_spans_beat(snap, SPINNER[0], 0)
}

/// The status-bar spans with an explicit heartbeat glyph + staleness (the live path).
pub fn status_spans_beat(snap: &Snapshot, beat: char, stale_s: u64) -> Vec<Span<'static>> {
    let stale = stale_s >= STALE_AFTER_S;
    // The heartbeat: green dot when fresh, amber when the stream wedged (App-Nap).
    let beat_color = if stale { Color::Yellow } else { Color::Green };
    let mut spans = vec![
        Span::styled(
            format!("{beat} "),
            Style::default().fg(beat_color).add_modifier(Modifier::BOLD),
        ),
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
    if stale {
        spans.push(Span::styled(
            format!("  ·  no update {stale_s}s"),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ));
    }
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
        REWARD_CREDIT,
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

/// Build the ALWAYS-ON per-lane rows for the lane table (was dual-only). Reuses the
/// shared [`lane_table_rows`] so the TUI and the line renderer can never drift: one
/// row per running lane, or a single synthesized row for a single-lane / older
/// stream. Each [`LaneRow`] carries its green/amber/red [`LaneHealth`] semaphore for
/// per-row tinting. Pure — exposed for tests.
pub fn lane_rows(snap: &Snapshot) -> Vec<LaneRow> {
    lane_table_rows(snap)
}

/// The footer keybinding bar text (k9s/lazygit style): `q quit · Esc quit · ^C quit`.
/// The plain-text form of the footer (the rendered panel uses [`footer_spans`] for
/// the styled bar; this is the greppable equivalent, exposed for tests).
#[allow(dead_code)] // plain-text mirror of footer_spans; used by tests
pub fn keybindings_line() -> String {
    KEYBINDINGS
        .iter()
        .map(|(k, a)| format!("{k} {a}"))
        .collect::<Vec<_>>()
        .join("  ·  ")
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

/// Render the whole panel into `frame` from `snap`. `beat` is the heartbeat glyph and
/// `stale_s` the seconds since the stream last advanced (the staleness chip).
fn render(frame: &mut Frame, snap: &Snapshot, beat: char, stale_s: u64) {
    let rows = lane_rows(snap);
    // Vertical layout: status bar, stats, ALWAYS-ON lane table (when there's a lane),
    // ticker, and the persistent footer keybinding bar.
    let mut constraints = vec![Constraint::Length(3), Constraint::Length(4)];
    let has_table = !rows.is_empty();
    if has_table {
        // 1 header + N lane rows + top/bottom border.
        let h = (rows.len() as u16) + 3;
        constraints.push(Constraint::Length(h));
    }
    constraints.push(Constraint::Min(3)); // ticker
    constraints.push(Constraint::Length(1)); // footer keybinding bar (no border)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(frame.area());

    // 1) Status bar (with the advancing heartbeat + staleness chip).
    let status = Paragraph::new(Line::from(status_spans_beat(snap, beat, stale_s))).block(
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

    // 3) ALWAYS-ON per-lane table with the green/amber/red semaphore per row.
    let mut next = 2;
    if has_table {
        let header = Row::new(["", "LANE", "STATE", "SPEED", "SHARES", "ENDPOINT", "F/O"])
            .style(Style::default().add_modifier(Modifier::BOLD));
        let table_rows: Vec<Row> = rows
            .iter()
            .map(|r| {
                let cells = [
                    r.health.chip().to_string(),
                    r.lane.label().to_string(),
                    r.state.clone(),
                    r.speed.clone(),
                    r.shares.clone(),
                    r.endpoint.clone(),
                    r.failovers.to_string(),
                ];
                // Tint the whole row by its semaphore health (the loud signal).
                Row::new(cells.map(Cell::from)).style(Style::default().fg(health_color(r.health)))
            })
            .collect();
        let widths = [
            Constraint::Length(5),  // health chip (OK/STALL/ERR)
            Constraint::Length(18), // lane label (fits "GPU · Alpha (V100)")
            Constraint::Length(9),  // state
            Constraint::Length(22), // speed
            Constraint::Length(11), // shares
            Constraint::Min(20),    // endpoint
            Constraint::Length(4),  // failovers
        ];
        let table = Table::new(table_rows, widths)
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
    next += 1;

    // 5) Persistent footer keybinding bar (k9s/lazygit style).
    let footer = Paragraph::new(Line::from(footer_spans()));
    frame.render_widget(footer, chunks[next]);
}

/// The footer keybinding spans: each key in reverse-video, its action dimmed.
fn footer_spans() -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    for (i, (k, a)) in KEYBINDINGS.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        spans.push(Span::styled(
            format!(" {k} "),
            Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(format!(" {a}"), Style::default().fg(Color::DarkGray)));
    }
    spans
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
        assert!(s.contains(REWARD_CREDIT));
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

    /// The lane table is ALWAYS-ON: a single lane synthesizes one row (was empty
    /// before); a dual run carries both lanes with their own ports + per-row health.
    #[test]
    fn lane_rows_are_always_on() {
        // Single lane → one synthesized row (not empty).
        let single = lane_rows(&running());
        assert_eq!(single.len(), 1, "single lane → one synthesized row");
        assert_eq!(single[0].lane, Lane::Xmr);
        assert_eq!(single[0].health, LaneHealth::Green, "running + nonzero = green");
        assert!(single[0].endpoint.contains(":3333"));

        // Dual → both lanes, each with its own port.
        let rows = lane_rows(&dual());
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].lane, Lane::Xmr);
        assert_eq!(rows[1].lane, Lane::GpuRvn);
        assert!(rows[0].endpoint.contains(":3333"), "XMR port");
        assert!(rows[1].endpoint.contains(":8888"), "RVN port");
    }

    /// A Running lane at 0 H/s is AMBER in the table (the loud stall signal), and a
    /// crashed lane is RED — so a wedged/dead lane is visible at a glance.
    #[test]
    fn lane_rows_amber_on_zero_red_on_error() {
        let mut stalled = running();
        stalled.hashrate_hs = Some(0.0);
        assert_eq!(lane_rows(&stalled)[0].health, LaneHealth::Amber, "0 H/s while running = amber");

        let mut errored = running();
        errored.state = EngineState::Error;
        errored.hashrate_hs = None;
        assert_eq!(lane_rows(&errored)[0].health, LaneHealth::Red, "error = red");
    }

    /// The status bar carries the advancing heartbeat and, once stale, the amber
    /// "no update Ns" chip (the App-Nap "alive but wedged" tell).
    #[test]
    fn status_heartbeat_goes_stale() {
        // Fresh: the heartbeat glyph is present, no "no update" chip.
        let fresh: String = status_spans_beat(&running(), '|', 1)
            .iter()
            .map(|s| s.content.as_ref())
            .collect();
        assert!(fresh.starts_with('|'), "leads with the heartbeat: {fresh}");
        assert!(!fresh.contains("no update"));
        // Stale: the amber chip with the age.
        let stale: String = status_spans_beat(&running(), '/', STALE_AFTER_S + 4)
            .iter()
            .map(|s| s.content.as_ref())
            .collect();
        assert!(stale.contains("no update"), "stale shows the chip: {stale}");
        assert!(stale.contains(&format!("{}s", STALE_AFTER_S + 4)));
    }

    /// The footer keybinding bar lists the active keys (q / Esc / ^C → quit).
    #[test]
    fn keybindings_footer_lists_keys() {
        let line = keybindings_line();
        assert!(line.contains("q quit"), "q binding: {line}");
        assert!(line.contains("Esc quit"));
        assert!(line.contains("^C quit"));
        // The rendered footer spans carry the same keys.
        let spans: String = footer_spans().iter().map(|s| s.content.as_ref()).collect();
        assert!(spans.contains('q') && spans.contains("quit"));
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
