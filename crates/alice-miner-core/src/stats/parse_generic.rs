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
fn compact_count(lower: &str, prefix: &str) -> Option<u64> {
    let idx = lower.find(prefix)?;
    let rest = &lower[idx + prefix.len()..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
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
