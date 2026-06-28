//! `fleet` — a LOCAL roster that aggregates several miner instances reporting to
//! the same Alice address into one table. **No server**: each running miner emits
//! its `--json` Snapshot stream (one JSON object per tick) to stdout, the operator
//! redirects each to a file, and `fleet <path>…` reads the LAST complete Snapshot
//! line from each file and renders a roster keyed by `worker_id`.
//!
//! Honest by construction (same credit-only gate as the live dashboard): every
//! figure is local mining ACTIVITY — state, lane, hashrate, accepted/rejected
//! shares, accepted %, failovers, last-seen. No reward number, no `$`, no
//! collection address / upstream pool (a Snapshot carries none — `prl_payout` is
//! `#[serde(skip)]`). The endpoint shown is the PUBLIC relay the snapshot carries.
//!
//! Robust: a missing / partial / garbage source is rendered as a dim "no data" row
//! (it never panics, and never aborts the whole roster). The pure parts —
//! [`parse_last_snapshot_line`] and [`RosterRow::from_source`] — are unit-tested
//! without any filesystem.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use alice_miner_core::Snapshot;

use crate::dashboard::fmt_hashrate;

/// The max sources we render (a roster is a local at-a-glance view, not a fleet
/// manager). Extra paths past this are dropped with a printed note — honest, never
/// silent. 64 is far more than a hand-run roster needs.
const MAX_SOURCES: usize = 64;

/// One roster line: a worker's source file + its last-known activity, or a "no
/// data" marker when the file is missing / empty / unparsable.
#[derive(Debug, Clone, PartialEq)]
pub struct RosterRow {
    /// The source label (the file's basename, or the full path when that's empty).
    pub source: String,
    /// The parsed activity, or `None` when the source had no usable Snapshot line.
    pub data: Option<RowData>,
    /// Seconds since the source file was last modified, when known (the "last-seen"
    /// freshness signal). `None` when the mtime is unavailable (e.g. the file is
    /// missing) — rendered as `—`.
    pub last_seen_s: Option<u64>,
}

/// The activity fields lifted from a worker's last Snapshot (presentation only).
#[derive(Debug, Clone, PartialEq)]
pub struct RowData {
    /// The miner's stable worker id (the roster key). `—` when the snapshot carried
    /// none (older streams) — the row still renders under the file label.
    pub worker_id: String,
    /// Short lane label (`xmr` / `prl` / `alpha` / `rvn`), or `—` when unset.
    pub lane: String,
    /// Short engine state (`running` / `idle` / …).
    pub state: String,
    /// Human hashrate string (reuses the dashboard's [`fmt_hashrate`]).
    pub hashrate: String,
    pub shares_accepted: u64,
    pub shares_rejected: u64,
    /// Accepted-share percentage, e.g. `99%`; `—` until a share is submitted.
    pub accepted_pct: String,
    pub failovers: u64,
}

/// Parse the LAST complete JSON [`Snapshot`] line from a `--json` stream. Scans
/// bottom-up and returns the first line that parses (so a partial final line — a
/// half-written tick — is skipped in favour of the last COMPLETE one above it).
/// `None` when no line parses (empty / garbage / not yet emitting). Pure: no IO.
pub fn parse_last_snapshot_line(content: &str) -> Option<Snapshot> {
    content
        .lines()
        .rev()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .find_map(|l| serde_json::from_str::<Snapshot>(l).ok())
}

impl RowData {
    /// Lift the presentation fields from a parsed [`Snapshot`]. Reuses the
    /// dashboard's formatters so the roster never drifts from the live view.
    fn from_snapshot(snap: &Snapshot) -> Self {
        let total = snap.shares_accepted + snap.shares_rejected;
        let accepted_pct = if total == 0 {
            "—".to_string()
        } else {
            let pct = (snap.shares_accepted as f64 / total as f64) * 100.0;
            format!("{pct:.0}%")
        };
        RowData {
            worker_id: snap.worker_id.clone().unwrap_or_else(|| "—".to_string()),
            lane: snap.lane.map(|l| l.cli_lane_arg().to_string()).unwrap_or_else(|| "—".to_string()),
            state: fmt_state(snap.state),
            hashrate: fmt_hashrate(snap.hashrate_hs),
            shares_accepted: snap.shares_accepted,
            shares_rejected: snap.shares_rejected,
            accepted_pct,
            failovers: snap.failovers,
        }
    }
}

impl RosterRow {
    /// Build a row from a source's raw `--json` file `content` + its `mtime` (the
    /// last-modified time, or `None` when unavailable). Pure — the caller does the
    /// IO and hands the bytes in, so this is fully unit-testable. A source with no
    /// parsable Snapshot yields a `None` data row (the "no data" marker).
    pub fn from_source(
        path: &Path,
        content: &str,
        mtime: Option<SystemTime>,
        now: SystemTime,
    ) -> Self {
        let source = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| path.to_string_lossy().into_owned());
        let data = parse_last_snapshot_line(content).map(|s| RowData::from_snapshot(&s));
        let last_seen_s = mtime.and_then(|m| now.duration_since(m).ok()).map(|d| d.as_secs());
        RosterRow { source, data, last_seen_s }
    }
}

/// Short engine state label (mirrors the dashboard's `fmt_state`, kept local so the
/// roster needs nothing pub-exported from `dashboard`).
fn fmt_state(state: alice_miner_core::EngineState) -> String {
    use alice_miner_core::EngineState::*;
    match state {
        Idle => "idle",
        Starting => "starting",
        Running => "running",
        Stopping => "stopping",
        Error => "error",
    }
    .to_string()
}

/// A short "last-seen" string from a seconds-ago delta: `now` (<2s), `12s`, `5m`,
/// `3h`, `2d`, or `—` when unknown. Keeps the column narrow + scannable.
fn fmt_last_seen(secs: Option<u64>) -> String {
    match secs {
        None => "—".to_string(),
        Some(s) if s < 2 => "now".to_string(),
        Some(s) if s < 60 => format!("{s}s"),
        Some(s) if s < 3600 => format!("{}m", s / 60),
        Some(s) if s < 86_400 => format!("{}h", s / 3600),
        Some(s) => format!("{}d", s / 86_400),
    }
}

/// Render the full roster as a fixed-width text table (header + one row per source).
/// Pure `&[RosterRow] -> String`; the live loop clears the screen and reprints this.
/// A "no data" source renders a single explanatory cell so the operator sees the
/// box is being watched but isn't streaming yet (never a blank/missing line).
pub fn render_roster(rows: &[RosterRow]) -> String {
    // Column widths — source/worker can be long, so cap + pad the rest.
    let mut out = String::new();
    out.push_str(&format!(
        "{:<18} {:<14} {:<7} {:<8} {:>15}  {:>10}  {:>5}  {:>4}  {:>6}\n",
        "SOURCE", "WORKER", "LANE", "STATE", "HASHRATE", "SHARES A/R", "ACC%", "F/O", "SEEN",
    ));
    out.push_str(&format!("{}\n", "─".repeat(96)));
    if rows.is_empty() {
        out.push_str("  (no sources)\n");
        return out;
    }
    for row in rows {
        let seen = fmt_last_seen(row.last_seen_s);
        match &row.data {
            None => {
                // Dim "no data" marker — the file is missing / empty / unparsable.
                out.push_str(&format!(
                    "{:<18} {:<14} {:<7} {:<8} {:>15}  {:>10}  {:>5}  {:>4}  {:>6}\n",
                    truncate(&row.source, 18),
                    "—",
                    "—",
                    "no data",
                    "—",
                    "—",
                    "—",
                    "—",
                    seen,
                ));
            }
            Some(d) => {
                let shares = format!("{}/{}", d.shares_accepted, d.shares_rejected);
                let hr = truncate(&d.hashrate, 15);
                out.push_str(&format!(
                    "{:<18} {:<14} {:<7} {:<8} {:>15}  {:>10}  {:>5}  {:>4}  {:>6}\n",
                    truncate(&row.source, 18),
                    truncate(&d.worker_id, 14),
                    truncate(&d.lane, 7),
                    truncate(&d.state, 8),
                    hr,
                    shares,
                    d.accepted_pct,
                    d.failovers,
                    seen,
                ));
            }
        }
    }
    out
}

/// Truncate `s` to `max` chars with a trailing `…` when it would overflow (keeps the
/// table columns aligned; counts chars, not bytes, so a `·` middot never splits).
fn truncate(s: &str, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        s.to_string()
    } else if max == 0 {
        String::new()
    } else {
        let kept: String = chars.into_iter().take(max.saturating_sub(1)).collect();
        format!("{kept}…")
    }
}

/// Read one source file and build its [`RosterRow`] (the IO wrapper around the pure
/// [`RosterRow::from_source`]). A missing / unreadable file yields a "no data" row
/// with no mtime — never an error that aborts the roster.
fn read_row(path: &Path, now: SystemTime) -> RosterRow {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    let mtime = std::fs::metadata(path).and_then(|m| m.modified()).ok();
    RosterRow::from_source(path, &content, mtime, now)
}

/// Build the full roster for `paths` (capped at [`MAX_SOURCES`]).
fn build_rows(paths: &[PathBuf]) -> Vec<RosterRow> {
    let now = SystemTime::now();
    paths.iter().take(MAX_SOURCES).map(|p| read_row(p, now)).collect()
}

/// Run the `fleet` roster: read each source's last Snapshot line and render the
/// table. With `once`, print one frame and return; otherwise refresh every
/// `interval` until Ctrl-C (clearing the screen each frame for an in-place view —
/// only on a TTY; piped/non-TTY just prints one frame so the output stays clean).
pub fn run(paths: &[PathBuf], once: bool, interval: Duration) -> i32 {
    if paths.is_empty() {
        eprintln!("error: fleet needs at least one --json stream file to read.");
        return crate::EXIT_USAGE;
    }
    if paths.len() > MAX_SOURCES {
        // Honest: say we capped, don't silently drop.
        println!(
            "note: {} sources given; showing the first {MAX_SOURCES} (roster cap).",
            paths.len()
        );
    }

    // A non-TTY (piped / redirected / CI) gets a single clean frame regardless of
    // --once, so we never spew screen-clear escapes into a file.
    let interactive = std::io::stdout().is_terminal();
    if once || !interactive {
        print!("{}", render_roster(&build_rows(paths)));
        return crate::EXIT_OK;
    }

    let stop = Arc::new(AtomicBool::new(false));
    {
        let f = stop.clone();
        let _ = ctrlc::set_handler(move || f.store(true, Ordering::SeqCst));
    }

    while !stop.load(Ordering::SeqCst) {
        // Clear screen + home cursor, then reprint (a simple in-place refresh; the
        // ratatui panel is `start`'s job, the roster stays dependency-light).
        print!("\x1b[2J\x1b[H");
        print!("{}", render_roster(&build_rows(paths)));
        println!("  (refreshing every {}s · Ctrl-C to exit)", interval.as_secs());
        use std::io::Write;
        let _ = std::io::stdout().flush();
        // Sleep in small slices so Ctrl-C is responsive.
        let mut slept = Duration::ZERO;
        while slept < interval && !stop.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(100));
            slept += Duration::from_millis(100);
        }
    }
    crate::EXIT_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use alice_miner_core::engine::{LaneSnapshot, Snapshot};
    use alice_miner_core::{EngineState, Lane};

    fn snap(worker: &str, lane: Lane, acc: u64, rej: u64) -> Snapshot {
        Snapshot {
            state: EngineState::Running,
            device: None,
            lane: Some(lane),
            hashrate_hs: Some(8_432.0),
            hashrate_60s_hs: None,
            hashrate_15m_hs: None,
            shares_accepted: acc,
            shares_rejected: rej,
            endpoint: Some("hk.aliceprotocol.org:3333".into()),
            worker_id: Some(worker.into()),
            uptime_s: 120,
            failovers: 2,
            dual: false,
            lanes: vec![LaneSnapshot {
                lane,
                state: EngineState::Running,
                hashrate_hs: Some(8_432.0),
                hashrate_60s_hs: None,
                hashrate_15m_hs: None,
                shares_accepted: acc,
                shares_rejected: rej,
                endpoint: Some("hk.aliceprotocol.org:3333".into()),
                failovers: 2,
            }],
            last_line: None,
            message: None,
            prl_payout: None,
        }
    }

    fn json_line(s: &Snapshot) -> String {
        serde_json::to_string(s).expect("serialize")
    }

    /// The LAST complete Snapshot line is returned; a trailing partial/garbage line
    /// is skipped in favour of the last COMPLETE one above it.
    #[test]
    fn parse_last_picks_the_last_complete_line() {
        let a = json_line(&snap("rig-a", Lane::Xmr, 10, 0));
        let b = json_line(&snap("rig-b", Lane::GpuPrl, 99, 1));
        // Two ticks then a half-written final line (a real `--json` tail can cut off).
        let stream = format!("{a}\n{b}\n{{\"state\":\"Runn");
        let got = parse_last_snapshot_line(&stream).expect("parses the last COMPLETE line");
        assert_eq!(got.worker_id.as_deref(), Some("rig-b"), "the most recent complete tick");
    }

    /// The triple-window fields are ADDITIVE: a Snapshot JSON line emitted by an
    /// OLDER miner (no `hashrate_60s_hs` / `hashrate_15m_hs` keys) still parses — the
    /// missing Option fields default to None. Guards the fleet roster against a
    /// schema-version skew across a mixed fleet.
    #[test]
    fn parse_tolerates_a_snapshot_without_window_fields() {
        let old = r#"{"state":"running","lane":"xmr","hashrate_hs":8432.0,"shares_accepted":10,"shares_rejected":0,"endpoint":"hk.aliceprotocol.org:3333","worker_id":"rig-old","uptime_s":60,"failovers":0,"dual":false}"#;
        let snap = parse_last_snapshot_line(old).expect("older stream still parses");
        assert_eq!(snap.worker_id.as_deref(), Some("rig-old"));
        assert_eq!(snap.hashrate_60s_hs, None, "absent window field → None");
        assert_eq!(snap.hashrate_15m_hs, None);
        let row = RowData::from_snapshot(&snap);
        assert_eq!(row.shares_accepted, 10);
    }

    /// Empty / whitespace / pure-garbage content yields no snapshot (never panics).
    #[test]
    fn parse_last_tolerates_empty_and_garbage() {
        assert!(parse_last_snapshot_line("").is_none());
        assert!(parse_last_snapshot_line("   \n\n  ").is_none());
        assert!(parse_last_snapshot_line("not json at all\n{nope}\n").is_none());
    }

    /// A populated source produces a row with the worker as key, the lane token, the
    /// human hashrate, shares A/R, accepted %, failovers, and a last-seen string.
    #[test]
    fn row_from_source_lifts_activity_fields() {
        let content = json_line(&snap("rig-7f3a", Lane::GpuPrl, 198, 2));
        let now = SystemTime::now();
        let mtime = Some(now - Duration::from_secs(5));
        let row = RosterRow::from_source(Path::new("/tmp/rig-7f3a.jsonl"), &content, mtime, now);

        assert_eq!(row.source, "rig-7f3a.jsonl", "source is the file basename");
        let d = row.data.expect("parsed");
        assert_eq!(d.worker_id, "rig-7f3a");
        assert_eq!(d.lane, "prl");
        assert_eq!(d.state, "running");
        assert!(d.hashrate.contains("kH/s"), "human hashrate: {}", d.hashrate);
        assert_eq!(d.shares_accepted, 198);
        assert_eq!(d.shares_rejected, 2);
        assert_eq!(d.accepted_pct, "99%");
        assert_eq!(d.failovers, 2);
        assert_eq!(row.last_seen_s, Some(5));
    }

    /// A missing / unparsable source yields a "no data" row (None data) — never a
    /// panic, and the row still carries the source label so the box is visible.
    #[test]
    fn row_from_source_no_data_for_garbage() {
        let now = SystemTime::now();
        let row = RosterRow::from_source(Path::new("/tmp/dead.jsonl"), "garbage\n", None, now);
        assert_eq!(row.source, "dead.jsonl");
        assert!(row.data.is_none(), "no parsable snapshot → no data row");
        assert_eq!(row.last_seen_s, None);
    }

    /// Accepted-% is `—` until a share is submitted (no "100%" of zero).
    #[test]
    fn accepted_pct_dash_until_a_share() {
        let content = json_line(&snap("rig-fresh", Lane::Xmr, 0, 0));
        let now = SystemTime::now();
        let row = RosterRow::from_source(Path::new("a.jsonl"), &content, Some(now), now);
        assert_eq!(row.data.unwrap().accepted_pct, "—");
    }

    /// The rendered table has the header columns, one row per source, and a "no data"
    /// cell for an unparsable source — and renders without panicking on a mix.
    #[test]
    fn render_roster_has_header_and_rows() {
        let now = SystemTime::now();
        let good = RosterRow::from_source(
            Path::new("rig-a.jsonl"),
            &json_line(&snap("rig-a", Lane::Xmr, 100, 0)),
            Some(now - Duration::from_secs(3)),
            now,
        );
        let bad = RosterRow::from_source(Path::new("rig-b.jsonl"), "junk", None, now);
        let table = render_roster(&[good, bad]);
        assert!(table.contains("SOURCE"), "header present");
        assert!(table.contains("WORKER"));
        assert!(table.contains("HASHRATE"));
        assert!(table.contains("rig-a"), "good worker shown");
        assert!(table.contains("no data"), "bad source shows the no-data marker");
    }

    /// Empty roster renders a placeholder (never a bare header), no panic.
    #[test]
    fn render_roster_empty_is_safe() {
        let t = render_roster(&[]);
        assert!(t.contains("(no sources)"));
    }

    /// CREDIT-ONLY: the roster table carries no fiat/payout token (the Snapshot has
    /// no payout field, and we render activity only).
    #[test]
    fn roster_is_credit_only() {
        let now = SystemTime::now();
        let row = RosterRow::from_source(
            Path::new("rig.jsonl"),
            &json_line(&snap("rig-x", Lane::GpuPrl, 50, 0)),
            Some(now),
            now,
        );
        let table = render_roster(&[row]).to_lowercase();
        for forbidden in ["$", "usd", "paid", "earned", "已发放"] {
            assert!(!table.contains(forbidden), "roster leaked `{forbidden}`: {table}");
        }
    }

    /// The last-seen formatter is compact + monotone across the time buckets.
    #[test]
    fn last_seen_buckets() {
        assert_eq!(fmt_last_seen(None), "—");
        assert_eq!(fmt_last_seen(Some(0)), "now");
        assert_eq!(fmt_last_seen(Some(12)), "12s");
        assert_eq!(fmt_last_seen(Some(120)), "2m");
        assert_eq!(fmt_last_seen(Some(7200)), "2h");
        assert_eq!(fmt_last_seen(Some(172_800)), "2d");
    }

    /// Truncation keeps columns aligned and never splits a char mid-way; it counts
    /// chars (not bytes) so a multibyte `·` is safe.
    #[test]
    fn truncate_caps_with_ellipsis() {
        assert_eq!(truncate("short", 18), "short");
        assert_eq!(truncate("0123456789abcdef", 8), "0123456…");
        assert_eq!(truncate("a·b·c·d·e·f·g", 5), "a·b·…");
    }
}
