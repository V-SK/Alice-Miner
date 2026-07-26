//! `parse_generic` — a **best-effort, honest** log parser for an UNKNOWN
//! third-party miner (the [`crate::backend::MinerPreset::GenericStratum`] /
//! `Template` custom backend). It has NO fixed format: it scans a line for a
//! `<number> <hash-unit>` speed and for `accepted` / `rejected` share counts, and
//! returns [`None`] for anything it can't recognise.
//!
//! ── HONESTY (the whole point) ────────────────────────────────────────────────
//! This parser NEVER fabricates a number. When a custom miner prints a format it
//! can't read, every field stays `None`; the supervisor then shows the lane as
//! "running (telemetry unavailable)" rather than inventing a hashrate or a share
//! count. It is deliberately CONSERVATIVE — a false 0 or a mis-read latency (the
//! SRBMiner `share accepted [180ms]` trap) is worse than a missing number, so:
//!   * a hashrate needs an explicit hash unit (`h/s`…`ph/s`); a bare number is
//!     ignored (it could be anything);
//!   * a share count is read ONLY right after an `accepted`/`rejected` keyword and
//!     is DROPPED when the integer is immediately followed by a time unit
//!     (`ms`/`s`) — that is a latency, not a count.
//!
//! Telemetry (temp/power/util/fan) is left to `None` here — a generic line rarely
//! carries it in a reliable shape, and the GPU-lane `nvidia-smi` fallback still
//! fills it. Never fabricated.

use super::KawpowSample;

/// Parse one arbitrary miner log line, best-effort, into a [`KawpowSample`].
/// Returns `None` when the line carries no recognisable hashrate or share figure —
/// the caller then leaves the lane as "running, telemetry unavailable" (it NEVER
/// invents a value).
pub fn parse_generic(raw: &str) -> Option<KawpowSample> {
    let line = raw.trim();
    if line.is_empty() {
        return None;
    }
    let lower = line.to_ascii_lowercase();
    let hashrate_hs = scan_hashrate(&lower);
    let (accepted, rejected) = scan_shares(&lower);
    if hashrate_hs.is_none() && accepted.is_none() && rejected.is_none() {
        return None;
    }
    Some(KawpowSample {
        hashrate_hs,
        accepted,
        rejected,
        temp_c: None,
        power_w: None,
        util_pct: None,
        fan_pct: None,
    })
}

/// The multiplier to H/s for a hashrate unit token (`h/s`…`ph/s`), or `None` if the
/// token is not a hashrate unit. Trailing punctuation is tolerated. Power efficiency
/// (`gh/w`, `j/mh`) is deliberately NOT a hashrate unit (it ends in `/w` / `/mh`).
fn hashrate_unit(tok: &str) -> Option<f64> {
    match tok.trim_end_matches([',', ';', ')', ']', '.']) {
        "h/s" => Some(1.0),
        "kh/s" => Some(1_000.0),
        "mh/s" => Some(1_000_000.0),
        "gh/s" => Some(1_000_000_000.0),
        "th/s" => Some(1_000_000_000_000.0),
        "ph/s" => Some(1_000_000_000_000_000.0),
        _ => None,
    }
}

/// Scan a lower-cased line for a `<number> <hash-unit>` pair and normalise to H/s.
/// Prefers a value on a `total` line; otherwise the LAST recognised rate on the line
/// (a periodic per-GPU / summary line). A warm-up `0.00 <unit>` on an `avg … hr`
/// line is suppressed (matches the SRBMiner parser's rule) so it never zeroes a live
/// rate. Requires an EXPLICIT unit — a bare number is never read as a hashrate.
fn scan_hashrate(lower: &str) -> Option<f64> {
    if lower.contains("avg") && lower.contains("hr") {
        return None;
    }
    let toks: Vec<&str> = lower.split_whitespace().collect();
    let prefer_total = lower.contains("total");
    let mut last: Option<f64> = None;
    let mut total: Option<f64> = None;
    for i in 0..toks.len() {
        // A number can be glued to its unit (`25.4mh/s`) or space-separated
        // (`25.4 mh/s`). Try the split form first, then a glued suffix.
        let cleaned = toks[i].trim_end_matches([',', ';']);
        if let Ok(num) = cleaned.parse::<f64>() {
            if let Some(mult) = toks.get(i + 1).and_then(|u| hashrate_unit(u)) {
                let hs = num * mult;
                last = Some(hs);
                if prefer_total {
                    total = Some(hs);
                }
                continue;
            }
        }
        if let Some(hs) = glued_number_unit(cleaned) {
            last = Some(hs);
            if prefer_total {
                total = Some(hs);
            }
        }
    }
    if prefer_total {
        total.or(last)
    } else {
        last
    }
}

/// Parse a glued `<number><unit>` token like `25.4mh/s` → H/s. Splits at the first
/// non-numeric char and checks the tail is a hashrate unit. `None` otherwise.
fn glued_number_unit(tok: &str) -> Option<f64> {
    let split = tok.find(|c: char| !(c.is_ascii_digit() || c == '.'))?;
    if split == 0 {
        return None;
    }
    let num: f64 = tok[..split].parse().ok()?;
    let mult = hashrate_unit(&tok[split..])?;
    Some(num * mult)
}

/// Best-effort `(accepted, rejected)` from an arbitrary line. Reads the integer that
/// follows an `accepted`/`rejected` keyword, but DROPS it when it is immediately
/// followed by a time unit (`ms`/`s`) — that is a share LATENCY, not a count (the
/// SRBMiner `share accepted [180ms]` trap). `None` for a field the line doesn't
/// carry (never fabricated). Also recognises the compact `a:<n> r:<n>` / `a/<n>`
/// forms some miners print.
fn scan_shares(lower: &str) -> (Option<u64>, Option<u64>) {
    let accepted = integer_after_keyword(lower, "accepted")
        .or_else(|| integer_after_keyword(lower, "accept"))
        .or_else(|| compact_count(lower, "a:"))
        .or_else(|| compact_count(lower, "acc:"));
    let rejected = integer_after_keyword(lower, "rejected")
        .or_else(|| integer_after_keyword(lower, "reject"))
        .or_else(|| compact_count(lower, "r:"))
        .or_else(|| compact_count(lower, "rej:"));
    (accepted, rejected)
}

/// The integer immediately following `keyword` (after any `: = / [ ] ( ) ,` /
/// whitespace run), or `None`. Returns `None` when the integer is directly followed
/// by a time unit (`ms` / `s`) — that indicates a latency figure, not a count.
fn integer_after_keyword(lower: &str, keyword: &str) -> Option<u64> {
    let idx = lower.find(keyword)?;
    let rest = &lower[idx + keyword.len()..];
    let bytes = rest.as_bytes();
    let mut i = 0;
    // Skip separators / whitespace up to the first digit; bail if a letter appears
    // first (e.g. `accepted_shares` — a label, not `accepted 42`).
    while i < bytes.len() && !bytes[i].is_ascii_digit() {
        if bytes[i].is_ascii_alphabetic() {
            return None;
        }
        i += 1;
    }
    let start = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if start == i {
        return None;
    }
    // Reject a latency: `... accepted [180ms]` / `... 42 ms`.
    let tail = rest[i..].trim_start();
    if tail.starts_with("ms") || tail.starts_with("s ") || tail == "s" || tail.starts_with("sec") {
        return None;
    }
    rest[start..i].parse().ok()
}

/// A compact `<prefix><int>` count (e.g. `a:42`, `rej:1`). The prefix already ends
/// in `:`. Returns `None` unless a plain integer immediately follows.
///
/// **Word boundary (bug fix).** A bare substring search read the `a:` inside
/// `cuda:0` as "accepted = 0" and the `r:` inside `power:120` as "rejected = 120",
/// so ONE ordinary device/telemetry line from a custom miner (`gpu0 cuda:0
/// power:120`) silently overwrote the real share counters. The prefix therefore
/// only counts at a real word start — see [`starts_word`]. We scan EVERY
/// occurrence, not just the first, so a real `a:42` later in a line that also
/// contains `cuda:0` is still found.
fn compact_count(lower: &str, prefix: &str) -> Option<u64> {
    let mut from = 0usize;
    while let Some(rel) = lower[from..].find(prefix) {
        let idx = from + rel;
        if starts_word(lower, idx) {
            let rest = &lower[idx + prefix.len()..];
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if !digits.is_empty() {
                return digits.parse().ok();
            }
        }
        // Advance past this occurrence and keep looking.
        from = idx + prefix.len();
    }
    None
}

/// Whether byte offset `idx` begins a real "word" — the guard that keeps `cuda:0` /
/// `power:120` from matching the `a:` / `r:` compact-count prefixes.
///
/// **Round 2: an ALLOWLIST, not a blocklist.** Round 1 excluded alphanumerics plus
/// `_`, `.` and `:`, which still let a hyphen through: `gpu-a:0` was read as
/// accepted = 0 and `core-r:120` as rejected = 120 — the identical false-zero, one
/// character away. Enumerating the separators that must NOT count is a losing game
/// (`-`, `=`, `/`, `+`, `#`, …), so we invert it: the prefix counts only when it is
/// at the start of the line or directly after WHITESPACE or one of a few opening
/// delimiters. That covers every shape a miner actually prints a compact counter in
/// (` a:42`, `[a:42]`, `(rej:1`, `,a:5`, `|r:0`) and rejects everything else by
/// default — which is the right bias here, because a MISSED count leaves the field
/// `None` ("telemetry unavailable"), while a WRONG one corrupts the user's totals.
fn starts_word(lower: &str, idx: usize) -> bool {
    if idx == 0 {
        return true;
    }
    match lower[..idx].chars().next_back() {
        None => true,
        Some(c) => c.is_whitespace() || matches!(c, '[' | '(' | '{' | ',' | ';' | '|'),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_spaced_and_glued_hashrate_units() {
        assert_eq!(parse_generic("Speed: 25.4 MH/s").unwrap().hashrate_hs, Some(25_400_000.0));
        assert_eq!(parse_generic("[GPU0] 1.20 GH/s").unwrap().hashrate_hs, Some(1_200_000_000.0));
        assert_eq!(parse_generic("hashrate 30.5mh/s").unwrap().hashrate_hs, Some(30_500_000.0));
        assert_eq!(parse_generic("total 2 Th/s").unwrap().hashrate_hs, Some(2_000_000_000_000.0));
    }

    #[test]
    fn bare_number_without_unit_is_never_a_hashrate() {
        // A number with no hash unit must NOT be read (it could be anything).
        assert!(parse_generic("connected to pool, difficulty 4096").is_none());
        assert!(parse_generic("uptime 1200 seconds").is_none());
    }

    #[test]
    fn reads_accepted_rejected_counts() {
        let s = parse_generic("share accepted 42").unwrap();
        assert_eq!(s.accepted, Some(42));
        assert_eq!(s.rejected, None);
        let r = parse_generic("rejected: 3").unwrap();
        assert_eq!(r.rejected, Some(3));
        // Compact forms.
        let c = parse_generic("shares a:100 r:2").unwrap();
        assert_eq!(c.accepted, Some(100));
        assert_eq!(c.rejected, Some(2));
    }

    /// REGRESSION (Bug 3): a device / telemetry token whose tail merely CONTAINS
    /// the compact prefix must never be read as a share count. `cuda:0` contains
    /// `a:0` and `power:120` contains `r:120`; before the word-boundary fix ONE such
    /// line reset the dashboard's accepted counter to 0 and invented 120 rejects.
    #[test]
    fn device_tokens_are_not_read_as_compact_share_counts() {
        // `cuda:0` must not become accepted=0.
        let s = parse_generic("gpu0 cuda:0 temp 61c 30.0 mh/s").unwrap();
        assert_eq!(s.accepted, None, "cuda:0 must not be read as accepted");
        // `power:120` must not become rejected=120.
        let p = parse_generic("dev0 power:120 fan 55% 30.0 mh/s").unwrap();
        assert_eq!(p.rejected, None, "power:120 must not be read as rejected");
        // Both at once, plus a real rate.
        let b = parse_generic("worker cuda:0 power:120 speed 30.0 mh/s").unwrap();
        assert_eq!(b.accepted, None);
        assert_eq!(b.rejected, None);
        assert_eq!(b.hashrate_hs, Some(30_000_000.0));
        // Other glued forms that must stay inert.
        assert_eq!(parse_generic("30.0 mh/s extra:5").unwrap().rejected, None);
        assert_eq!(parse_generic("30.0 mh/s beta:7").unwrap().accepted, None);
    }

    /// ROUND-2 REGRESSION: the round-1 word boundary was a BLOCKLIST and still let a
    /// hyphen (and `=`, `/`, `+`, `#`) through, so `gpu-a:0` was read as accepted = 0
    /// and `core-r:120` as rejected = 120 — the same false zero, one character away.
    /// Every one of these must leave the counters untouched.
    #[test]
    fn separator_glued_device_tokens_are_not_compact_share_counts() {
        for line in [
            "gpu-a:0 30.0 mh/s",
            "core-r:120 30.0 mh/s",
            "dev=a:0 30.0 mh/s",
            "opt=r:9 30.0 mh/s",
            "gpu/a:0 30.0 mh/s",
            "x+r:5 30.0 mh/s",
            "#a:3 30.0 mh/s",
            "temp-a:0 fan-r:80 30.0 mh/s",
        ] {
            let s = parse_generic(line).unwrap_or_else(|| panic!("no sample for {line}"));
            assert_eq!(s.accepted, None, "{line} must not yield an accepted count");
            assert_eq!(s.rejected, None, "{line} must not yield a rejected count");
            assert_eq!(s.hashrate_hs, Some(30_000_000.0), "{line} rate still read");
        }
    }

    /// …and the genuine forms still read, INCLUDING a real `a:`/`r:` that follows a
    /// hyphen-glued decoy on the same line (the exact shape the round-1 fix missed).
    #[test]
    fn real_compact_counts_still_read_after_a_hyphenated_decoy() {
        let s = parse_generic("gpu-a:0 core-r:120 shares a:42 r:1").unwrap();
        assert_eq!(s.accepted, Some(42));
        assert_eq!(s.rejected, Some(1));
        // Comma / pipe / brace separated forms are word starts too.
        assert_eq!(parse_generic("stats,a:5 1.0 mh/s").unwrap().accepted, Some(5));
        assert_eq!(parse_generic("stats|r:6 1.0 mh/s").unwrap().rejected, Some(6));
        assert_eq!(parse_generic("{a:8} 1.0 mh/s").unwrap().accepted, Some(8));
        // Tab-separated (whitespace is a word start, not just ' ').
        assert_eq!(parse_generic("shares\ta:11 1.0 mh/s").unwrap().accepted, Some(11));
    }

    /// The word-boundary guard must NOT break the real compact forms, including a
    /// genuine `a:`/`r:` that appears AFTER a decoy token on the same line.
    #[test]
    fn real_compact_counts_still_read_after_a_decoy_token() {
        let c = parse_generic("gpu0 cuda:0 shares a:100 r:2").unwrap();
        assert_eq!(c.accepted, Some(100), "a real a: after cuda: is still found");
        assert_eq!(c.rejected, Some(2), "a real r: after power-like tokens is still found");
        // Bracketed / parenthesised prefixes are word starts too.
        let br = parse_generic("[a:7] [r:1] 1.0 mh/s").unwrap();
        assert_eq!(br.accepted, Some(7));
        assert_eq!(br.rejected, Some(1));
        // Line-initial prefix.
        assert_eq!(parse_generic("a:9 1.0 mh/s").unwrap().accepted, Some(9));
    }

    #[test]
    fn latency_after_accepted_is_not_read_as_a_count() {
        // The SRBMiner trap: `share accepted [180ms]` → the 180 is a latency.
        assert!(parse_generic("GPU2 share accepted [180ms] [pearlhash]").is_none());
        assert!(parse_generic("share accepted in 42 ms").is_none());
    }

    #[test]
    fn avg_multi_hour_zero_does_not_zero_the_rate() {
        assert!(parse_generic("Avg 6 hr : 0.00 H/s").is_none());
    }

    #[test]
    fn power_efficiency_is_not_a_hashrate() {
        // `442.94 GH/W` (efficiency) must not be read as a rate — the line carries
        // no real speed, so it is None.
        assert!(parse_generic("efficiency 442.94 GH/W").is_none());
    }

    #[test]
    fn pure_noise_returns_none() {
        assert!(parse_generic("connecting to relay...").is_none());
        assert!(parse_generic("").is_none());
        assert!(parse_generic("   ").is_none());
    }
}
