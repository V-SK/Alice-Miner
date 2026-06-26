//! `parse_srbminer` — extract hashrate (normalized to **H/s**) + CUMULATIVE
//! accepted/rejected shares from **SRBMiner-MULTI** (pearlhash) log lines, into the
//! shared [`KawpowSample`] shape so the GPU-PRL lane reports identically to GPU-RVN.
//!
//! **VALIDATED against a real 12-hour SRBMiner-MULTI pearlhash `--log-file`** captured
//! 2026-06-26 (`_launch/artifacts/srbminer-real-logs/matrix_4070-narissa-2026-06-26.log`).
//! The earlier parser was written against an ASSUMED format (`Total speed: 62.4 Mh/s`,
//! `Accepted: 12`) that SRBMiner does NOT emit — so on real boxes hashrate read 0 and
//! shares read 0/0 (which also false-tripped the Layer-B no-progress watchdog → the
//! lane "mined a while then stopped"). The REAL lines (and how this parser treats
//! each) are:
//!
//! - per-GPU hashrate, ~every 90s, with a CUMULATIVE share bracket, e.g.
//!   `GPU2: 125.35 TH/s   [ 719| 1| 0| 442.94 GH/W]`. The unit is TH/s (not Mh/s);
//!   the bracket is `[accepted|rejected|stale|efficiency GH/W]`. `GH/W` is POWER
//!   efficiency and must never be read as a hashrate.
//! - a periodic summary with abbreviated keys: `Shares acc.  : 713` and
//!   `Shares rej.  : 1`.
//! - per-share EVENT lines are IGNORED — they carry a latency or a text reason, not
//!   a count (the old "integer after `accepted`" read the 180 ms latency):
//!   `GPU2[t0] share accepted [  180ms] [pearlhash][0]`.
//! - lagging multi-hour averages read `0.00 H/s` until warmed up; they are
//!   suppressed so they never zero the live rate: `Avg. 6  hr.  : 0.00 H/s`.
//!
//! The supervisor tails the `--log-file` and feeds each line here; the consumer
//! (`supervise::apply_log_line`, GpuPrl arm) ASSIGNS each field when present
//! (cumulative, last-wins) and skips `None`, so this parser returns CUMULATIVE
//! counts (from the bracket or the summary) and `None` for a field a line can't
//! determine. It is per-line and tolerant — `None` for a line carrying no figure.
//!
//! KNOWN LIMITATION: with multiple ACTIVE GPUs SRBMiner prints one `GPU<N>:` line
//! per card; this per-line parser reports the most-recent card's rate (still far
//! better than 0). Summing across cards within a cycle is a follow-up; the field
//! reports were single-active-GPU boxes.

use super::KawpowSample;

/// Parse one SRBMiner log line into a [`KawpowSample`] (H/s + accepted/rejected).
/// Returns `None` when the line carries no recognizable figure.
pub fn parse_srbminer(raw: &str) -> Option<KawpowSample> {
    let line = raw.trim();
    if line.is_empty() {
        return None;
    }
    let lower = line.to_ascii_lowercase();
    let (accepted, rejected) = share_counts(line, &lower);
    let sample = KawpowSample {
        hashrate_hs: parse_hashrate_hs(&lower),
        accepted,
        rejected,
    };
    if sample.hashrate_hs.is_none() && sample.accepted.is_none() && sample.rejected.is_none() {
        None
    } else {
        Some(sample)
    }
}

/// CUMULATIVE `(accepted, rejected)` for a line, from the two REAL sources (both
/// cumulative). NEVER from the bare words `accepted`/`rejected`: on event lines
/// those are followed by a latency (`share accepted [180ms]`) or a text reason.
///   1. the per-GPU hashrate line's pipe bracket `[<acc>|<rej>|<stale>|<eff> GH/W]`;
///   2. the summary lines `Shares acc.  : N` / `Shares rej.  : N`.
fn share_counts(line: &str, lower: &str) -> (Option<u64>, Option<u64>) {
    // 1. The share bracket: the FIRST `[..]` segment that contains `|`. The leading
    //    `[timestamp]` and tags like `[pearlhash]` / `[180ms]` carry no `|`, and the
    //    `Shares tot.  : 7 [100.00|0.00]` ratio bracket holds floats (parse fails →
    //    we fall through), so this only matches the integer `[acc|rej|...]` bracket.
    if let Some((a, r)) = bracket_counts(line) {
        return (Some(a), Some(r));
    }
    // 2. The summary abbreviations `acc.` / `rej.` (each on its own line).
    let acc = if lower.contains("acc.") {
        integer_after(lower, "acc.")
    } else {
        None
    };
    let rej = if lower.contains("rej.") {
        integer_after(lower, "rej.")
    } else {
        None
    };
    (acc, rej)
}

/// Parse `[<int>|<int>| ... ]` — the first bracket containing `|` whose first two
/// `|`-separated fields are integers. Returns `(accepted, rejected)` or `None`.
fn bracket_counts(line: &str) -> Option<(u64, u64)> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'[' {
            let rest = &line[i + 1..];
            let Some(end_rel) = rest.find(']') else {
                break;
            };
            let inner = &rest[..end_rel];
            if inner.contains('|') {
                let mut it = inner.split('|');
                if let (Some(a), Some(r)) = (it.next(), it.next()) {
                    if let (Ok(a), Ok(r)) = (a.trim().parse::<u64>(), r.trim().parse::<u64>()) {
                        return Some((a, r));
                    }
                }
                // A `|` bracket whose fields aren't integers (e.g. the float ratio
                // `[100.00|0.00]`) is not the share bracket — keep scanning.
            }
            i += 1 + end_rel + 1;
            continue;
        }
        i += 1;
    }
    None
}

/// The first run of digits appearing AFTER `keyword` in `lower` (already
/// lower-cased). Used ONLY for the `acc.` / `rej.` summary keys.
fn integer_after(lower: &str, keyword: &str) -> Option<u64> {
    let idx = lower.find(keyword)?;
    let rest = &lower.as_bytes()[idx + keyword.len()..];
    let mut i = 0;
    while i < rest.len() && !rest[i].is_ascii_digit() {
        i += 1;
    }
    let start = i;
    while i < rest.len() && rest[i].is_ascii_digit() {
        i += 1;
    }
    if start == i {
        return None;
    }
    std::str::from_utf8(&rest[start..i]).ok()?.parse().ok()
}

/// The hashrate multiplier for a unit token, or `None` if not a hashrate unit.
/// Trailing punctuation/bracket is tolerated. Includes **TH/s** and **PH/s** — the
/// real pearlhash units (a GPU runs ~0.1–1+ TH/s) the old table was missing.
/// `GH/W` (power efficiency) is deliberately NOT a unit here (`/w`, not `/s`).
fn unit_multiplier(tok: &str) -> Option<f64> {
    match tok.trim_end_matches([',', ';', ')', ']']) {
        "h/s" => Some(1.0),
        "kh/s" => Some(1_000.0),
        "mh/s" => Some(1_000_000.0),
        "gh/s" => Some(1_000_000_000.0),
        "th/s" => Some(1_000_000_000_000.0),
        "ph/s" => Some(1_000_000_000_000_000.0),
        _ => None,
    }
}

/// Scan a lower-cased line for a `<number> <unit>` hashrate (space-separated, the
/// SRBMiner form) and normalize to H/s. Prefers a value on a `total` line; else
/// takes the last `<n> <unit>` seen (e.g. the per-GPU speed). Lagging multi-hour
/// averages (`Avg. 6 hr.  : 0.00 H/s`) are suppressed so a warm-up 0.00 never
/// zeroes the live rate — the per-GPU line and `Avg. 1 min.` carry the real rate.
fn parse_hashrate_hs(lower: &str) -> Option<f64> {
    if lower.contains("avg") && lower.contains("hr") {
        return None;
    }
    let toks: Vec<&str> = lower.split_whitespace().collect();
    let prefer_total = lower.contains("total");
    let mut last: Option<f64> = None;
    let mut total: Option<f64> = None;
    for i in 0..toks.len() {
        let num: f64 = match toks[i].trim_end_matches([',', ';']).parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(unit) = toks.get(i + 1).and_then(|u| unit_multiplier(u)) else {
            continue;
        };
        let hs = num * unit;
        last = Some(hs);
        if prefer_total {
            total = Some(hs);
        }
    }
    if prefer_total {
        total.or(last)
    } else {
        last
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Real lines from matrix_4070-narissa-2026-06-26.log ──────────────────────

    #[test]
    fn real_per_gpu_line_hashrate_th_s_and_bracket_counts() {
        // The dominant informative line: TH/s rate + the cumulative `[acc|rej|..]`.
        let s = parse_srbminer(
            "[2026-06-26 13:05:45] GPU2: 125.35 TH/s        [    719|    1|   0|  442.94 GH/W]",
        )
        .unwrap();
        assert_eq!(s.hashrate_hs, Some(125.35e12));
        assert_eq!(s.accepted, Some(719));
        assert_eq!(s.rejected, Some(1));
    }

    #[test]
    fn gh_per_w_efficiency_is_not_read_as_hashrate() {
        let s = parse_srbminer(
            "[2026-06-26 00:56:22] GPU2: 119.55 TH/s        [      1|    0|   0|  422.44 GH/W]",
        )
        .unwrap();
        assert_eq!(s.hashrate_hs, Some(119.55e12)); // NOT 422.44e9
    }

    #[test]
    fn share_accepted_event_line_is_not_misread_as_count() {
        // The old parser read "the integer after accepted" → 180 (the latency!).
        // The real cumulative count comes from the bracket/summary, so this event
        // line must contribute nothing (and the line carries no other figure).
        assert!(parse_srbminer(
            "[2026-06-26 13:06:07] GPU2[t0] share accepted [  180ms] [pearlhash][0]"
        )
        .is_none());
    }

    #[test]
    fn share_rejected_event_line_with_text_reason_is_ignored() {
        assert!(parse_srbminer(
            "[2026-06-26 11:30:52] GPU2[t0] share rejected [jackpot condition not satisfied: hash does not meet difficulty target] [pearlhash][0]"
        )
        .is_none());
    }

    #[test]
    fn summary_acc_and_rej_lines() {
        let a = parse_srbminer("[2026-06-26 01:01:17] Shares acc.  : 713").unwrap();
        assert_eq!(a.accepted, Some(713));
        assert_eq!(a.rejected, None);
        let r = parse_srbminer("[2026-06-26 01:01:17] Shares rej.  : 1").unwrap();
        assert_eq!(r.rejected, Some(1));
        assert_eq!(r.accepted, None);
    }

    #[test]
    fn shares_total_ratio_bracket_is_not_a_count() {
        // `[100.00|0.00]` holds floats → must not be parsed as accepted/rejected.
        let s = parse_srbminer("[2026-06-26 01:01:17] Shares tot.  : 7 [100.00|0.00]");
        // "tot." is neither acc. nor rej. and the bracket is non-integer → no figure.
        assert!(s.is_none());
    }

    #[test]
    fn avg_1_min_is_a_valid_rate_but_multi_hour_avgs_are_suppressed() {
        assert_eq!(
            parse_srbminer("[2026-06-26 01:01:17] Avg. 1 min.  : 125.32 TH/s")
                .unwrap()
                .hashrate_hs,
            Some(125.32e12)
        );
        // The warm-up `0.00 H/s` multi-hour averages must NOT zero the live rate.
        assert!(parse_srbminer("[2026-06-26 01:01:17] Avg. 6  hr.  : 0.00 H/s").is_none());
        assert!(parse_srbminer("[2026-06-26 01:01:17] Avg. 12 hr.  : 0.00 H/s").is_none());
    }

    #[test]
    fn sub_th_rate_uses_correct_unit() {
        // The "865549824.00 kH/s" field report was really ~0.87 TH/s; with TH/s now
        // recognized the value + counts parse correctly.
        let s = parse_srbminer("[ts] GPU0: 0.87 TH/s [3|0|0| 1.20 GH/W]").unwrap();
        assert_eq!(s.hashrate_hs, Some(0.87e12));
        assert_eq!(s.accepted, Some(3));
        assert_eq!(s.rejected, Some(0));
    }

    // ── Generic unit handling (still valid) ─────────────────────────────────────

    #[test]
    fn unit_scaling_kh_mh_gh_th() {
        assert_eq!(parse_srbminer("speed 500 kh/s").unwrap().hashrate_hs, Some(500_000.0));
        assert_eq!(parse_srbminer("speed 2 Gh/s").unwrap().hashrate_hs, Some(2_000_000_000.0));
        assert_eq!(
            parse_srbminer("speed 1.5 Th/s").unwrap().hashrate_hs,
            Some(1_500_000_000_000.0)
        );
    }

    #[test]
    fn noise_line_returns_none() {
        assert!(parse_srbminer("connecting to pool...").is_none());
        assert!(parse_srbminer("[2026-06-26 00:55:19] Connected to 127.0.0.1:11200 [0]").is_none());
        assert!(parse_srbminer("").is_none());
    }
}
