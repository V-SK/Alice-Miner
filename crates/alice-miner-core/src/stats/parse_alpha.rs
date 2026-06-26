//! `parse_alpha` — extract hashrate (normalized to **H/s**) + the CUMULATIVE
//! shares-found count from **AlphaMiner** (`alpha-miner` v1.8.3, pearl/v1) stdout,
//! into the shared [`KawpowSample`] shape so the GPU-Alpha (V100/Volta) lane reports
//! identically to the SRBMiner / KawPoW lanes.
//!
//! **VALIDATED against a real V100 capture 2026-06-26**
//! (`_launch/artifacts/alphaminer-real-logs/alpha-miner-v183-mining-stdout-V100-2026-06-26.log`).
//! alpha-miner emits **logfmt** — `<ISO8601> level=INFO ver=1.8.3 gpu=0:Tesla… component=<c> key=val…`.
//! The ONE line the lane reads is the periodic miner status:
//!
//! ```text
//! …component=miner status attempts=8 hits=2 hashrate_th_s=9.58 tmac_s=9.58 share_equiv_th_s=8.58 …
//! ```
//!
//! → **hashrate** from `hashrate_th_s` (TH/s, the GPU's raw compute rate); the
//!   **CUMULATIVE share count** from `hits` (shares found + submitted THIS run).
//!
//! HONESTY: alpha-miner async-submits and NEVER logs a pool accept/reject (the
//! `component=share submitted` events carry no count, and there is no acceptance
//! line) — pool ACCEPTANCE is the RELAY's truth (it observes the pool `result:true`),
//! exactly the dual-path credit model. So the client surfaces `hits` as the
//! submitted-share count and `rejected` is ALWAYS `None` (the client cannot know a
//! pool reject). `share_equiv_th_s` is deliberately NOT read as the hashrate (it is a
//! difficulty-weighted equivalent, not the compute rate); the exact-key match below
//! guarantees it is never confused with `hashrate_th_s`.
//!
//! Like the SRBMiner parser this is per-line + tolerant: a line that is not the miner
//! status line (connection, difficulty, share events, errors) yields `None`, and the
//! supervisor (`supervise::apply_log_line`, GpuAlpha arm) assigns each present field
//! cumulative/last-wins.

use super::KawpowSample;

/// Parse one alpha-miner stdout line into a [`KawpowSample`]. Only the
/// `component=miner status` line carries the rate + cumulative count; every other
/// line returns `None`.
pub fn parse_alpha(raw: &str) -> Option<KawpowSample> {
    let line = raw.trim();
    if line.is_empty() {
        return None;
    }
    // The rate + cumulative `hits` live ONLY on the miner status line. Gate on it so
    // a stray `hits=`/`hashrate_th_s=` elsewhere can't be misread (and we don't pay
    // the scan for every connection/share/job line).
    if !(line.contains("component=miner") && contains_token(line, "status")) {
        return None;
    }
    let hashrate_hs = logfmt_f64(line, "hashrate_th_s").map(|th| th * 1e12);
    let accepted = logfmt_u64(line, "hits");
    if hashrate_hs.is_none() && accepted.is_none() {
        return None;
    }
    Some(KawpowSample {
        hashrate_hs,
        accepted,
        rejected: None, // the client never sees a pool reject — the relay owns acceptance
    })
}

/// Whether `tok` appears in `line` as a whitespace-delimited token (so `status`
/// matches the bare word, not a substring of some other key).
fn contains_token(line: &str, tok: &str) -> bool {
    line.split_whitespace().any(|t| t == tok)
}

/// The value of a logfmt `key=<token>` pair (token = up to the next whitespace),
/// matched on a WHOLE key so `hashrate_th_s` never matches inside `share_equiv_th_s`
/// and `hits` never matches inside another key. Returns `None` if absent.
fn logfmt_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("{key}=");
    let mut from = 0;
    while let Some(rel) = line[from..].find(&needle) {
        let idx = from + rel;
        // Key boundary: start-of-line or a preceding space (logfmt is space-delimited).
        let boundary_ok = idx == 0 || line.as_bytes()[idx - 1] == b' ';
        if boundary_ok {
            let after = &line[idx + needle.len()..];
            let end = after.find(char::is_whitespace).unwrap_or(after.len());
            return Some(&after[..end]);
        }
        from = idx + needle.len();
    }
    None
}

fn logfmt_f64(line: &str, key: &str) -> Option<f64> {
    logfmt_value(line, key)?.parse().ok()
}

fn logfmt_u64(line: &str, key: &str) -> Option<u64> {
    logfmt_value(line, key)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Real lines from alpha-miner-v183-mining-stdout-V100-2026-06-26.log ──────

    const STATUS1: &str = "2026-06-26T22:28:32.368Z level=INFO ver=1.8.3 gpu=0:Tesla V100-PCIE-16GB component=miner status attempts=4 hits=2 hashrate_th_s=11.64 tmac_s=11.64 share_equiv_th_s=27.69 share_equiv_tmac_s=27.69";
    const STATUS2: &str = "2026-06-26T22:29:06.942Z level=INFO ver=1.8.3 gpu=0:Tesla V100-PCIE-16GB component=miner status attempts=8 hits=2 hashrate_th_s=9.58 tmac_s=9.58 share_equiv_th_s=8.58 share_equiv_tmac_s=8.58";

    #[test]
    fn real_status_line_hashrate_th_s_and_cumulative_hits() {
        let s = parse_alpha(STATUS1).unwrap();
        assert_eq!(s.hashrate_hs, Some(11.64e12)); // TH/s → H/s
        assert_eq!(s.accepted, Some(2)); // cumulative hits
        assert_eq!(s.rejected, None); // client never knows a pool reject
        let s2 = parse_alpha(STATUS2).unwrap();
        assert_eq!(s2.hashrate_hs, Some(9.58e12));
        assert_eq!(s2.accepted, Some(2));
    }

    #[test]
    fn share_equiv_is_not_confused_with_hashrate() {
        // hashrate_th_s=11.64 must win; share_equiv_th_s=27.69 must NOT be read.
        assert_eq!(parse_alpha(STATUS1).unwrap().hashrate_hs, Some(11.64e12));
    }

    #[test]
    fn non_status_lines_yield_none() {
        for line in [
            "2026-06-26T22:28:07.749Z level=INFO ver=1.8.3 gpu=0:Tesla V100-PCIE-16GB component=pool connected host=us1.alphapool.tech port=5566 tls=false",
            "2026-06-26T22:28:08.184Z level=INFO ver=1.8.3 gpu=0:Tesla V100-PCIE-16GB component=pool difficulty_set difficulty=50000.00 share_nbits=1b014f8a",
            "2026-06-26T22:28:18.281Z level=INFO ver=1.8.3 gpu=0:Tesla V100-PCIE-16GB component=share submitted job=00013338-7082db0cf742bf40",
            "2026-06-26T22:28:17.779Z level=INFO ver=1.8.3 gpu=0:Tesla V100-PCIE-16GB component=share found_candidate rows=2 cols=64 job=00013338-7082db0cf742bf40",
            "2026-06-26T22:26:46.955Z level=ERROR ver=1.8.3 gpu=system component=miner error=\"unknown argument: --algorithm\"",
            "",
            "Welcome to vast.ai.",
        ] {
            assert!(parse_alpha(line).is_none(), "should be None: {line}");
        }
    }

    #[test]
    fn status_with_only_hashrate_or_only_hits_still_parses() {
        let only_hr = "ts component=miner status attempts=1 hashrate_th_s=5.0";
        assert_eq!(parse_alpha(only_hr).unwrap().hashrate_hs, Some(5.0e12));
        assert_eq!(parse_alpha(only_hr).unwrap().accepted, None);
        let only_hits = "ts component=miner status attempts=1 hits=7";
        assert_eq!(parse_alpha(only_hits).unwrap().accepted, Some(7));
        assert_eq!(parse_alpha(only_hits).unwrap().hashrate_hs, None);
    }

    #[test]
    fn logfmt_value_matches_whole_key_only() {
        // `th_s` must not match inside `hashrate_th_s`; `hits` only as a whole key.
        assert_eq!(logfmt_value("a=1 hits=9 b=2", "hits"), Some("9"));
        assert_eq!(logfmt_value("xhits=9 hits=3", "hits"), Some("3")); // skip the glued one
        assert_eq!(logfmt_value("share_equiv_th_s=27.69 hashrate_th_s=11.64", "hashrate_th_s"), Some("11.64"));
        assert_eq!(logfmt_value("no key here", "hits"), None);
    }
}
