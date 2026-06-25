//! `parse_srbminer` — extract hashrate (normalized to **H/s**) + accepted/rejected
//! shares from **SRBMiner-MULTI** (pearlhash) log lines, into the shared
//! [`KawpowSample`] shape so the GPU-PRL lane reports identically to GPU-RVN.
//!
//! SRBMiner is a DIFFERENT format from kawpowminer/T-Rex (so [`super::parse_kawpow`]
//! does NOT apply). Hand-rolled (no `regex` dep), mirroring the worker-v1 Python
//! parser `relay_lane_runner.parse_srbminer_rvn_logs`:
//!   * accepted: the integer following the word `accepted` (e.g. `Accepted: 12`);
//!   * rejected: the integer following the word `rejected`;
//!   * hashrate: a `<n> <unit>` value where unit ∈ {h/s, kh/s, mh/s, gh/s} (e.g.
//!     `Total speed: 62.4 Mh/s` or `GPU0: ... 31.21 Mh/s`), normalized to H/s.
//!
//! SRBMiner writes these to its `--log-file` (the supervisor tails it); the parser
//! is per-line and tolerant — it returns `None` for a line carrying none of the
//! three figures.

use super::KawpowSample;

/// Parse one SRBMiner log line into a [`KawpowSample`] (H/s + accepted/rejected).
/// Returns `None` when the line carries no recognizable figure.
pub fn parse_srbminer(raw: &str) -> Option<KawpowSample> {
    let line = raw.trim();
    if line.is_empty() {
        return None;
    }
    let lower = line.to_ascii_lowercase();
    let sample = KawpowSample {
        hashrate_hs: parse_hashrate_hs(&lower),
        accepted: integer_after(&lower, "accepted"),
        rejected: integer_after(&lower, "rejected"),
    };
    if sample.hashrate_hs.is_none() && sample.accepted.is_none() && sample.rejected.is_none() {
        None
    } else {
        Some(sample)
    }
}

/// The first run of digits appearing AFTER `keyword` in `lower` (already
/// lower-cased). Mirrors the Python `\b<keyword>\b[^0-9]*([0-9]+)` shape.
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

/// The hashrate multiplier for a unit token (`h/s`, `kh/s`, `mh/s`, `gh/s`), or
/// `None` if the token is not a hashrate unit. Trailing punctuation is tolerated.
fn unit_multiplier(tok: &str) -> Option<f64> {
    match tok.trim_end_matches([',', ';', ')']) {
        "h/s" => Some(1.0),
        "kh/s" => Some(1_000.0),
        "mh/s" => Some(1_000_000.0),
        "gh/s" => Some(1_000_000_000.0),
        _ => None,
    }
}

/// Scan a lower-cased line for a `<number> <unit>` hashrate (space-separated, the
/// SRBMiner form) and normalize to H/s. Prefers a value on a `total` line; else
/// takes the last `<n> <unit>` seen (e.g. the per-GPU speed).
fn parse_hashrate_hs(lower: &str) -> Option<f64> {
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

    #[test]
    fn parses_accepted_rejected() {
        let s = parse_srbminer("[12:00:00] Accepted: 12 / Rejected: 3").unwrap();
        assert_eq!(s.accepted, Some(12));
        assert_eq!(s.rejected, Some(3));
    }

    #[test]
    fn parses_total_speed_to_hs() {
        let s = parse_srbminer("Total speed: 62.4 Mh/s").unwrap();
        assert_eq!(s.hashrate_hs, Some(62_400_000.0));
    }

    #[test]
    fn parses_per_gpu_speed() {
        let s = parse_srbminer("GPU0: pearlhash 31.21 Mh/s [stable]").unwrap();
        assert_eq!(s.hashrate_hs, Some(31_210_000.0));
    }

    #[test]
    fn prefers_total_over_per_gpu_on_same_line() {
        // A line mentioning total takes the total value.
        let s = parse_srbminer("GPU0 31.0 Mh/s | Total: 60.0 Mh/s").unwrap();
        assert_eq!(s.hashrate_hs, Some(60_000_000.0));
    }

    #[test]
    fn unit_scaling_kh_gh() {
        assert_eq!(parse_srbminer("speed 500 kh/s").unwrap().hashrate_hs, Some(500_000.0));
        assert_eq!(parse_srbminer("speed 2 Gh/s").unwrap().hashrate_hs, Some(2_000_000_000.0));
    }

    #[test]
    fn noise_line_returns_none() {
        assert!(parse_srbminer("connecting to pool...").is_none());
        assert!(parse_srbminer("").is_none());
    }
}
