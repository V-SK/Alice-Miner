//! `parse_kawpow` — extract hashrate (normalized to **H/s**) + accepted/rejected
//! shares from one KawPoW miner log line, tolerating **both** the bundled
//! **kawpowminer** and the **T-Rex** (`ALICE_MINER_GPU_BIN` override) formats.
//!
//! Ported + generalized from
//! `Alice-Protocol/miner/mining_internal/trex_logs.py` (`HASHRATE_RANGE_RE` /
//! `HASHRATE_SINGLE_RE` / `SHARE_COUNTER_RE` + ANSI strip). The Python reference
//! parsed T-Rex only; this Rust port also accepts kawpowminer's distinct shapes.
//! Hand-rolled (no `regex` dependency) to match the codebase's verbatim-ported
//! XMR parsers ([`crate::supervise::parse_hashrate_hs`]).
//!
//! ── The two log dialects this tolerates ─────────────────────────────────────
//!
//! **kawpowminer** (ethminer lineage), e.g.:
//! ```text
//!   m 12:01:42 kawpowminer Speed 25.43 Mh/s gpu0 25.43 [A4+0:R0+0:F0] Time: 00:05
//!   i 12:01:10 kawpowminer Accepted 0 ms. ... 4:0
//! ```
//!   * hashrate: `Speed <n> <unit>` (unit `Mh/s` / `kh/s` / `h/s`, any case);
//!   * shares: the `[A<acc>+<n>:R<rej>+<n>:F<n>]` block (accepted / rejected).
//!
//! **T-Rex**, e.g.:
//! ```text
//!   20240101 12:01:42 [ OK ] GPU #0: 20.83 MH/s [T:65C, P:120W, E:0.17 MH/W]
//!   20240101 12:01:42 Shares: 12/12 (100%) ...    or a bare  12/12  counter
//!   20240101 12:01:42 Hashrate: 20.50 - 21.00 MH/s
//! ```
//!   * hashrate: a `<lo> - <hi> <unit>` RANGE (we take the hi as "current"), else
//!     a single `<n> <unit>` on a `GPU`/`[ OK ]` line;
//!   * shares: an `<acc>/<sub>` counter (submitted total → rejected = sub-acc).
//!
//! Both are ANSI-stripped first (T-Rex colorizes). Every figure is normalized to
//! **H/s** so the engine `Snapshot` carries one unit across all lanes.

#![allow(dead_code)]

/// One parsed observation from a GPU miner log line (shared by the kawpow, SRBMiner,
/// and alpha parsers). Any field is `None`/absent when the line didn't carry it (most
/// lines carry at most one kind of figure). The telemetry fields (temp/power/util/fan)
/// are FAIL-SOFT: a parser leaves them `None` whenever the engine didn't report them,
/// and an unparseable telemetry token never breaks hashrate/share parsing.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct KawpowSample {
    /// Hashrate normalized to H/s (e.g. `25.43 Mh/s` → `25_430_000.0`).
    pub hashrate_hs: Option<f64>,
    /// Cumulative accepted shares, if the line carried a share figure.
    pub accepted: Option<u64>,
    /// Cumulative rejected shares, if the line carried a share figure.
    pub rejected: Option<u64>,
    /// GPU core temperature in °C, if the line reported it (e.g. T-Rex `[T:65C, …]`).
    pub temp_c: Option<f64>,
    /// GPU board power draw in watts, if the line reported it (e.g. `P:120W`).
    pub power_w: Option<f64>,
    /// GPU utilization percent (0..=100), if the line reported it.
    pub util_pct: Option<f64>,
    /// GPU fan speed percent (0..=100), if the line reported it.
    pub fan_pct: Option<f64>,
}

impl KawpowSample {
    fn is_empty(&self) -> bool {
        self.hashrate_hs.is_none()
            && self.accepted.is_none()
            && self.rejected.is_none()
            && self.temp_c.is_none()
            && self.power_w.is_none()
            && self.util_pct.is_none()
            && self.fan_pct.is_none()
    }
}

/// Parse one KawPoW miner log line. Returns `None` when the line carries no
/// recognizable figure (so the supervisor only updates state on real data).
pub fn parse_kawpow(raw: &str) -> Option<KawpowSample> {
    let line = strip_ansi(raw);
    let shares = parse_shares(&line);
    let telem = parse_telemetry(&line);
    let sample = KawpowSample {
        hashrate_hs: parse_hashrate(&line),
        accepted: shares.map(|(a, _)| a),
        rejected: shares.map(|(_, r)| r),
        temp_c: telem.temp_c,
        power_w: telem.power_w,
        util_pct: telem.util_pct,
        fan_pct: telem.fan_pct,
    };
    if sample.is_empty() {
        None
    } else {
        Some(sample)
    }
}

// ── Hashrate ─────────────────────────────────────────────────────────────────

/// Extract a hashrate (→ H/s) from a line, trying, in order:
///   1. kawpowminer `Speed <n> <unit>` (the authoritative total-speed line);
///   2. a T-Rex `<lo> - <hi> <unit>` RANGE → take the hi as current;
///   3. a single `<n> <unit>` on a `GPU` / `[ OK ]` line (T-Rex per-GPU/OK line).
fn parse_hashrate(line: &str) -> Option<f64> {
    // 1) kawpowminer "Speed <n> <unit>".
    if let Some(after) = find_keyword(line, "speed") {
        if let Some(hs) = first_value_with_unit(after) {
            return Some(hs);
        }
    }

    // 2) T-Rex range "<lo> - <hi> <unit>" — return the hi (most-recent/current).
    if let Some(hs) = parse_range_hashrate(line) {
        return Some(hs);
    }

    // 3) Single value on a GPU/OK line (avoid matching arbitrary numbers on
    //    unrelated lines — only trust a hashrate-unit token that follows a
    //    number on a recognizably-hashrate line).
    let lower = line.to_ascii_lowercase();
    if lower.contains("gpu") || lower.contains("[ ok ]") || lower.contains("hashrate") {
        if let Some(hs) = last_value_with_unit(line) {
            return Some(hs);
        }
    }
    None
}

/// Parse a `<lo> - <hi> <unit>` range and return the HI normalized to H/s.
/// Tolerant of surrounding text; finds the first ` - ` separating two numbers
/// where a hashrate unit follows.
fn parse_range_hashrate(line: &str) -> Option<f64> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    for i in 0..tokens.len() {
        if tokens[i] == "-" && i >= 1 && i + 2 < tokens.len() + 1 {
            // tokens[i-1] = lo, tokens[i+1] = hi, tokens[i+2] = unit (maybe).
            let lo = tokens[i - 1].parse::<f64>().ok();
            let hi = tokens.get(i + 1).and_then(|t| t.parse::<f64>().ok());
            let unit = tokens.get(i + 2).copied();
            if let (Some(_lo), Some(hi), Some(unit)) = (lo, hi, unit) {
                if let Some(mult) = unit_multiplier(unit) {
                    return Some(hi * mult);
                }
            }
        }
    }
    None
}

/// Scan tokens AFTER a keyword for the first `<number> <unit>` pair → H/s.
fn first_value_with_unit(tokens_after: &str) -> Option<f64> {
    let toks: Vec<&str> = tokens_after.split_whitespace().collect();
    for w in toks.windows(2) {
        if let (Ok(v), Some(mult)) = (w[0].parse::<f64>(), unit_multiplier(w[1])) {
            return Some(v * mult);
        }
    }
    // Also tolerate a glued "25.43Mh/s" token (no space).
    for t in toks {
        if let Some(hs) = parse_glued_value_unit(t) {
            return Some(hs);
        }
    }
    None
}

/// Like [`first_value_with_unit`] but returns the LAST match on the line (T-Rex
/// per-GPU lines may carry several figures; the trailing one is the speed).
fn last_value_with_unit(line: &str) -> Option<f64> {
    let toks: Vec<&str> = line.split_whitespace().collect();
    let mut found = None;
    for w in toks.windows(2) {
        if let (Ok(v), Some(mult)) = (w[0].parse::<f64>(), unit_multiplier(w[1])) {
            found = Some(v * mult);
        }
    }
    if found.is_some() {
        return found;
    }
    for t in toks {
        if let Some(hs) = parse_glued_value_unit(t) {
            found = Some(hs);
        }
    }
    found
}

/// Parse a glued `25.43Mh/s` token (number directly followed by a unit).
fn parse_glued_value_unit(tok: &str) -> Option<f64> {
    // Split at the first non-(digit/dot) char.
    let split = tok.find(|c: char| !(c.is_ascii_digit() || c == '.'))?;
    if split == 0 {
        return None;
    }
    let (num, unit) = tok.split_at(split);
    let v = num.parse::<f64>().ok()?;
    let mult = unit_multiplier(unit)?;
    Some(v * mult)
}

/// Multiplier to convert a hashrate unit token to H/s, or `None` if the token is
/// not a hashrate unit. Accepts `h/s`, `kh/s`, `mh/s`, `gh/s` (any case), with or
/// without a trailing comma/bracket (e.g. `MH/s,`). Deliberately REJECTS the
/// efficiency unit `H/W` (so the `[... E:0.17 MH/W]` block is not mistaken for a
/// hashrate).
fn unit_multiplier(unit: &str) -> Option<f64> {
    let u = unit
        .trim_matches(|c: char| c == ',' || c == ']' || c == '[' || c == ')' || c == '(')
        .to_ascii_lowercase();
    match u.as_str() {
        "h/s" => Some(1.0),
        "kh/s" => Some(1_000.0),
        "mh/s" => Some(1_000_000.0),
        "gh/s" => Some(1_000_000_000.0),
        _ => None,
    }
}

/// Find the substring AFTER the first case-insensitive occurrence of `keyword`.
fn find_keyword<'a>(line: &'a str, keyword: &str) -> Option<&'a str> {
    let lower = line.to_ascii_lowercase();
    let pos = lower.find(keyword)?;
    Some(&line[pos + keyword.len()..])
}

// ── Shares ───────────────────────────────────────────────────────────────────

/// Extract `(accepted, rejected)` from a line, trying, in order:
///   1. kawpowminer `[A<acc>+<n>:R<rej>+<n>:F<n>]` block;
///   2. a T-Rex `<acc>/<sub>` counter (rejected = submitted − accepted);
///   3. labelled `Accepted: <n>` / `Rejected: <n>` (some kawpowminer builds).
fn parse_shares(line: &str) -> Option<(u64, u64)> {
    if let Some(s) = parse_bracket_shares(line) {
        return Some(s);
    }
    if let Some(s) = parse_slash_counter(line) {
        return Some(s);
    }
    parse_labelled_shares(line)
}

/// kawpowminer `[A<acc>(+<n>)?:R<rej>(+<n>)?:F<n>]` → `(acc, rej)`. The `+<n>`
/// suffixes (stale/extra) are ignored; we read the leading integer after `A`/`R`.
fn parse_bracket_shares(line: &str) -> Option<(u64, u64)> {
    let open = line.find('[')?;
    let close = line[open..].find(']')? + open;
    let inside = &line[open + 1..close];
    // Must look like a share block: contains 'A' and 'R' and ':'.
    if !(inside.contains('A') && inside.contains('R') && inside.contains(':')) {
        return None;
    }
    let acc = field_after(inside, 'A')?;
    let rej = field_after(inside, 'R')?;
    Some((acc, rej))
}

/// Read the leading unsigned integer immediately after the FIRST occurrence of
/// `tag` in `s` (e.g. `A12+0` after 'A' → 12). `None` if no digits follow.
fn field_after(s: &str, tag: char) -> Option<u64> {
    let pos = s.find(tag)?;
    let rest = &s[pos + 1..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

/// T-Rex `<acc>/<sub>` counter → `(acc, sub-acc)`. Validates `acc <= sub` (the
/// Python guard: an `acc > sub` pair is a false match and skipped). Picks the
/// LAST valid counter on the line (the cumulative one).
fn parse_slash_counter(line: &str) -> Option<(u64, u64)> {
    let mut best: Option<(u64, u64)> = None;
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/' {
            // Walk left for the accepted digits, right for the submitted digits.
            let mut l = i;
            while l > 0 && bytes[l - 1].is_ascii_digit() {
                l -= 1;
            }
            let mut r = i + 1;
            while r < bytes.len() && bytes[r].is_ascii_digit() {
                r += 1;
            }
            if l < i && r > i + 1 {
                let acc = line[l..i].parse::<u64>().ok();
                let sub = line[i + 1..r].parse::<u64>().ok();
                if let (Some(acc), Some(sub)) = (acc, sub) {
                    if acc <= sub {
                        best = Some((acc, sub - acc));
                    }
                }
            }
            i = r;
        } else {
            i += 1;
        }
    }
    best
}

/// Labelled `Accepted: <n>` / `Rejected: <n>` shares (some kawpowminer builds
/// print a summary). Returns `Some` only when at least one label is present.
fn parse_labelled_shares(line: &str) -> Option<(u64, u64)> {
    let acc = labelled_value(line, "accepted");
    let rej = labelled_value(line, "rejected");
    match (acc, rej) {
        (None, None) => None,
        (a, r) => Some((a.unwrap_or(0), r.unwrap_or(0))),
    }
}

/// First integer after a case-insensitive `label` (skipping a `:`/spaces).
fn labelled_value(line: &str, label: &str) -> Option<u64> {
    let after = find_keyword(line, label)?;
    let trimmed = after.trim_start_matches(|c: char| c == ':' || c.is_whitespace());
    let digits: String = trimmed.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

// ── Telemetry (temp / power / util / fan) — FAIL-SOFT ─────────────────────────

/// The optional hardware-telemetry fields a KawPoW line may carry. Every field is
/// best-effort: absent / unparseable → `None` (never breaks hashrate/share parsing).
#[derive(Debug, Clone, Copy, Default)]
struct Telemetry {
    temp_c: Option<f64>,
    power_w: Option<f64>,
    util_pct: Option<f64>,
    fan_pct: Option<f64>,
}

/// Extract temp/power/util/fan from a KawPoW line, tolerating BOTH the T-Rex compact
/// `[T:65C, P:120W, ...]` block AND kawpowminer's labelled `temperature 65C` / `fan
/// 55%` / `power 120W` forms. Every figure is best-effort; the block is IGNORED for
/// the hashrate path (E:0.17 MH/W efficiency stays out of the rate). Fail-soft.
fn parse_telemetry(line: &str) -> Telemetry {
    let lower = line.to_ascii_lowercase();
    Telemetry {
        // T-Rex `T:65C` / `T:65` OR labelled `temperature 65C` / `temp 65`.
        temp_c: value_after_colon(&lower, "t:")
            .or_else(|| labelled_number(&lower, "temperature"))
            .or_else(|| labelled_number(&lower, "temp")),
        // T-Rex `P:120W` / `P:120` OR labelled `power 120W` / `power 120`.
        power_w: value_after_colon(&lower, "p:").or_else(|| labelled_number(&lower, "power")),
        // Utilization is rarely on a kawpow line, but honor a labelled `util 98%`.
        util_pct: labelled_number(&lower, "util")
            .or_else(|| labelled_number(&lower, "utilization")),
        // Fan `fan 55%` / `fan:55`.
        fan_pct: value_after_colon(&lower, "fan:").or_else(|| labelled_number(&lower, "fan")),
    }
}

/// The number immediately after a `key:` token (T-Rex compact block form, e.g. the
/// `T:65C` inside `[T:65C, P:120W]`). Tolerates a trailing unit letter (`C`/`W`) and
/// bracket/comma punctuation. `None` if the key/number is absent.
fn value_after_colon(lower: &str, key: &str) -> Option<f64> {
    let idx = lower.find(key)?;
    let rest = &lower[idx + key.len()..];
    parse_leading_number(rest)
}

/// The first number after a case-insensitive `label` word (kawpowminer labelled form,
/// e.g. `temperature 65C`). Skips a separating `:`/`=`/space run. `None` if absent.
fn labelled_number(lower: &str, label: &str) -> Option<f64> {
    let idx = lower.find(label)?;
    let rest = &lower[idx + label.len()..];
    let trimmed = rest.trim_start_matches(|c: char| c == ':' || c == '=' || c.is_whitespace());
    parse_leading_number(trimmed)
}

/// Parse the leading signed-decimal number from `s` (ignoring a trailing unit like
/// `C` / `W` / `%`). `None` if `s` does not start with a digit / sign.
fn parse_leading_number(s: &str) -> Option<f64> {
    let bytes = s.as_bytes();
    let mut i = 0;
    if i < bytes.len() && (bytes[i] == b'-' || bytes[i] == b'+') {
        i += 1;
    }
    let start_digits = i;
    while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
        i += 1;
    }
    if i == start_digits {
        return None;
    }
    s[..i].parse().ok()
}

// ── ANSI ─────────────────────────────────────────────────────────────────────

/// Strip ANSI/VT100 CSI escape sequences (`ESC [ ... <final>`), mirroring the
/// Python `ANSI_RE`. T-Rex colorizes its output; kawpowminer may too.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // Expect '[' then params until a final byte in @..~ (0x40..0x7e).
            if matches!(chars.peek(), Some('[')) {
                chars.next(); // consume '['
                while let Some(&n) = chars.peek() {
                    chars.next();
                    if ('\u{40}'..='\u{7e}').contains(&n) {
                        break; // final byte consumed
                    }
                }
            }
            // else: a lone ESC — drop it.
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── kawpowminer format ─────────────────────────────────────────────────

    #[test]
    fn kawpowminer_speed_line_to_hs() {
        let line = "m 12:01:42 kawpowminer Speed 25.43 Mh/s gpu0 25.43 [A4+0:R0+0:F0] Time: 00:05";
        let s = parse_kawpow(line).expect("parsed");
        // 25.43 Mh/s → 25_430_000 H/s.
        assert_eq!(s.hashrate_hs, Some(25_430_000.0));
        // Shares from the [A4+0:R0+0:F0] block.
        assert_eq!(s.accepted, Some(4));
        assert_eq!(s.rejected, Some(0));
    }

    #[test]
    fn kawpowminer_share_block_with_rejects() {
        let line = "m 12:05:10 kawpowminer Speed 31.10 Mh/s [A128+0:R3+1:F0]";
        let s = parse_kawpow(line).expect("parsed");
        assert_eq!(s.hashrate_hs, Some(31_100_000.0));
        assert_eq!(s.accepted, Some(128));
        assert_eq!(s.rejected, Some(3));
    }

    #[test]
    fn kawpowminer_glued_unit() {
        // Some builds glue the unit to the number.
        let s = parse_kawpow("kawpowminer Speed 18.7Mh/s").expect("parsed");
        assert_eq!(s.hashrate_hs, Some(18_700_000.0));
    }

    #[test]
    fn kawpowminer_labelled_accepted() {
        let s = parse_kawpow("i 12:01:10 kawpowminer Accepted: 12  Rejected: 1").expect("parsed");
        assert_eq!(s.accepted, Some(12));
        assert_eq!(s.rejected, Some(1));
    }

    // ── T-Rex format ───────────────────────────────────────────────────────

    #[test]
    fn trex_single_gpu_ok_line_to_hs() {
        let line = "20240101 12:01:42 [ OK ] GPU #0: 20.83 MH/s [T:65C, P:120W, E:0.17 MH/W]";
        let s = parse_kawpow(line).expect("parsed");
        // 20.83 MH/s → 20_830_000 H/s. The E:0.17 MH/W must NOT be mistaken for it.
        assert_eq!(s.hashrate_hs, Some(20_830_000.0));
    }

    #[test]
    fn trex_range_hashrate_takes_high() {
        let line = "20240101 12:01:42 Hashrate: 20.50 - 21.00 MH/s";
        let s = parse_kawpow(line).expect("parsed");
        assert_eq!(s.hashrate_hs, Some(21_000_000.0));
    }

    #[test]
    fn trex_slash_share_counter() {
        // T-Rex "Shares: 12/12" → accepted 12, rejected 0.
        let s = parse_kawpow("20240101 12:01:42 Shares: 12/12 (100%)").expect("parsed");
        assert_eq!(s.accepted, Some(12));
        assert_eq!(s.rejected, Some(0));

        // 30 accepted of 32 submitted → 2 rejected.
        let s = parse_kawpow("Shares accepted 30/32").expect("parsed");
        assert_eq!(s.accepted, Some(30));
        assert_eq!(s.rejected, Some(2));
    }

    #[test]
    fn trex_ansi_colored_line_is_stripped() {
        // A colorized T-Rex OK line still parses.
        let line = "\u{1b}[32m[ OK ]\u{1b}[0m GPU #0: 22.10 MH/s";
        let s = parse_kawpow(line).expect("parsed");
        assert_eq!(s.hashrate_hs, Some(22_100_000.0));
    }

    // ── Non-data lines + edge cases ─────────────────────────────────────────

    #[test]
    fn non_data_lines_return_none() {
        assert!(parse_kawpow("kawpowminer 1.2.4").is_none());
        assert!(parse_kawpow("Eth: Connected to stratum server").is_none());
        assert!(parse_kawpow("").is_none());
        // A bare temperature line now carries telemetry (temp), but must STILL never be
        // read as a hashrate (the load-bearing invariant): the sample has temp, no rate.
        let s = parse_kawpow("GPU #0 temperature 65C").expect("temperature is telemetry");
        assert_eq!(s.temp_c, Some(65.0));
        assert_eq!(s.hashrate_hs, None, "a bare temperature line is never a hashrate");
    }

    #[test]
    fn efficiency_unit_is_not_a_hashrate() {
        // Only the efficiency figure present (no MH/s) → no hashrate.
        let s = parse_kawpow("[T:65C, P:120W, E:0.17 MH/W]");
        // It may carry no shares either → None overall.
        assert!(s.is_none() || s.unwrap().hashrate_hs.is_none());
    }

    #[test]
    fn gh_s_unit_normalizes() {
        let s = parse_kawpow("kawpowminer Speed 1.5 Gh/s").expect("parsed");
        assert_eq!(s.hashrate_hs, Some(1_500_000_000.0));
    }

    // ── Telemetry (temp / power / util / fan) ──────────────────────────────────

    #[test]
    fn trex_compact_block_captures_temp_and_power() {
        // The T-Rex `[T:65C, P:120W, E:0.17 MH/W]` block: temp + power captured; the
        // efficiency figure is NOT read as a hashrate (still 20.83 MH/s).
        let line = "20240101 12:01:42 [ OK ] GPU #0: 20.83 MH/s [T:65C, P:120W, E:0.17 MH/W]";
        let s = parse_kawpow(line).expect("parsed");
        assert_eq!(s.hashrate_hs, Some(20_830_000.0));
        assert_eq!(s.temp_c, Some(65.0));
        assert_eq!(s.power_w, Some(120.0));
        // util/fan absent on this line → None.
        assert_eq!(s.util_pct, None);
        assert_eq!(s.fan_pct, None);
    }

    #[test]
    fn kawpowminer_labelled_temp_fan_power_captured() {
        // kawpowminer's labelled telemetry (previously discarded).
        let line = "m 12:01:42 kawpowminer Speed 25.43 Mh/s gpu0 temperature 62C fan 55% power 145W";
        let s = parse_kawpow(line).expect("parsed");
        assert_eq!(s.hashrate_hs, Some(25_430_000.0));
        assert_eq!(s.temp_c, Some(62.0));
        assert_eq!(s.fan_pct, Some(55.0));
        assert_eq!(s.power_w, Some(145.0));
    }

    #[test]
    fn telemetry_only_line_still_parses() {
        // A bare telemetry block (no hashrate/shares) still yields a sample so the
        // supervisor can update temp/power between speed lines.
        let s = parse_kawpow("[ OK ] GPU #0: idle [T:48C, P:35W]").expect("telemetry-only");
        assert_eq!(s.temp_c, Some(48.0));
        assert_eq!(s.power_w, Some(35.0));
        assert_eq!(s.hashrate_hs, None);
    }

    #[test]
    fn telemetry_is_fail_soft_and_never_breaks_hashrate() {
        // A garbled telemetry token must not disturb the hashrate parse.
        let s = parse_kawpow("kawpowminer Speed 18.00 Mh/s [T:xxC, P:??]").expect("parsed");
        assert_eq!(s.hashrate_hs, Some(18_000_000.0));
        assert_eq!(s.temp_c, None, "unparseable temp → None, not a panic");
        assert_eq!(s.power_w, None);
    }

    #[test]
    fn kawpow_and_trex_produce_same_unit_for_equal_rate() {
        // The whole point of the generalization: both dialects normalize to H/s,
        // so 20 MH/s reads identically regardless of which miner emitted it.
        let kp = parse_kawpow("kawpowminer Speed 20.00 Mh/s").unwrap();
        let tr = parse_kawpow("[ OK ] GPU #0: 20.00 MH/s").unwrap();
        assert_eq!(kp.hashrate_hs, tr.hashrate_hs);
        assert_eq!(kp.hashrate_hs, Some(20_000_000.0));
    }
}
