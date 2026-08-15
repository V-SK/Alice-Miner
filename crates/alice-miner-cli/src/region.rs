//! `region` — the SHARED, localized "what region will this run use, and will it
//! auto-failover?" VIEW that both the `start` banner and `doctor` render, so they tell
//! the identical story (B-line region transparency).
//!
//! The view is computed WITHOUT the RTT probe (from persisted [`settings`] +
//! `ALICE_GPU_RELAY_REGION`), so showing it costs no network round-trip and never
//! double-probes the region relays — the engine runs the ONE real probe at start. For
//! the plain auto/probe default the shown endpoint order is the compiled candidate set
//! (US-first); the real head is chosen by the live probe, which the label makes clear.
//!
//! It ALSO surfaces the tester-facing "where did Finland come from?" signal: if the
//! effective endpoints (or a raw `ALICE_MINER_ENDPOINTS_JSON` override) name the removed
//! `fi` relay, [`RegionView::has_removed_region`] is set so `doctor` can point at a stale
//! binary / env override (the compiled defaults are `us`/`asia`/`eu` — `fi` is never one).

use alice_miner_core::lane::gpu_prl::{self, RegionDecision};
use alice_miner_core::tr;

/// The effective GPU-PRL region view (localized), resolved from settings + env with no
/// network probe. Consumed by the `start` banner and `doctor`.
pub(crate) struct RegionView {
    /// Localized one-line MODE label (locked / operator-override / last-good / auto).
    pub mode: String,
    /// The effective endpoint authorities (`host:port`) in decided order (no probe).
    pub authorities: Vec<String>,
    /// Whether auto-failover is available (false ONLY for a region LOCK).
    pub failover_on: bool,
    /// True when the shown order is the candidate default and the REAL head is chosen by
    /// a live RTT probe at engine start (the plain auto default) — so callers label it.
    pub probed: bool,
    /// Whether the effective set / an endpoints-JSON override names a REMOVED region host
    /// (`fi`): a stale-binary / override signal.
    pub has_removed_region: bool,
    /// The resolved per-source inputs (for `doctor`'s breakdown). Raw persisted / env
    /// values, unvalidated (so `doctor` shows exactly what is on disk / in the env).
    pub region_lock: Option<String>,
    pub env_region: Option<String>,
    pub last_good: Option<String>,
    /// Whether `ALICE_MINER_ENDPOINTS_JSON` is set (presence only — never its content).
    pub endpoints_json_set: bool,
}

/// Build the view from the LIVE settings + env (the production entry point).
pub(crate) fn view() -> RegionView {
    let s = alice_miner_core::settings::load();
    let env_region = std::env::var(gpu_prl::ENV_REGION).ok().filter(|v| !v.trim().is_empty());
    let endpoints_json = std::env::var(alice_miner_core::endpoint::ENDPOINTS_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty());
    from_inputs(s.region_lock, env_region, s.last_good_region, endpoints_json)
}

/// Build the view from already-resolved inputs — the pure, testable core (no settings /
/// env / network access). `endpoints_json` is the RAW override value (or `None`), used
/// only for the presence flag + the removed-host substring scan.
pub(crate) fn from_inputs(
    lock: Option<String>,
    env_region: Option<String>,
    last_good: Option<String>,
    endpoints_json: Option<String>,
) -> RegionView {
    let decision = gpu_prl::decide_region(lock.as_deref(), env_region.as_deref(), last_good.as_deref());
    let failover_on = !matches!(&decision, RegionDecision::Locked(_));
    let probed = matches!(&decision, RegionDecision::Probe);
    let authorities =
        gpu_prl::planned_endpoint_authorities(lock.as_deref(), env_region.as_deref(), last_good.as_deref());
    let has_removed_region = gpu_prl::contains_removed_region(&authorities)
        || endpoints_json.as_deref().map(gpu_prl::text_names_removed_region).unwrap_or(false);
    let mode = mode_line(&decision, env_region.as_deref());
    RegionView {
        mode,
        authorities,
        failover_on,
        probed,
        has_removed_region,
        region_lock: lock,
        env_region,
        last_good,
        endpoints_json_set: endpoints_json.is_some(),
    }
}

/// The localized one-line MODE label for a [`RegionDecision`] — the single source of
/// truth for the `start` banner AND the `doctor` "PRL region mode" line. `env` is the
/// raw `ALICE_GPU_RELAY_REGION` value, used only to distinguish an operator override
/// from a remembered last-good region in the prefer-head case.
fn mode_line(decision: &RegionDecision, env: Option<&str>) -> String {
    match decision {
        RegionDecision::Locked(tag) => tr!(
            "Region: locked to {tag} — no auto-failover (use `--region auto` to unlock).",
            "区域: 已锁定 {tag} — 不自动切换(用 `--region auto` 解除)。"
        )
        .replace("{tag}", tag),
        RegionDecision::PreferHead(tag) => {
            // An operator env override vs a remembered last-good region.
            if gpu_prl::normalize_region_tag(env.unwrap_or("")) == Some(tag) {
                tr!(
                    "Region: {tag} (operator override) — auto-failover on.",
                    "区域: {tag}(操作员指定)— 自动切换开启。"
                )
                .replace("{tag}", tag)
            } else {
                tr!(
                    "Region: auto — resuming last-good {tag}; auto-failover on.",
                    "区域: 自动 — 沿用上次可用的 {tag};自动切换开启。"
                )
                .replace("{tag}", tag)
            }
        }
        RegionDecision::Probe => tr!(
            "Region: auto (nearest region) — auto-failover on.",
            "区域: 自动(最近区域)— 自动切换开启。"
        )
        .to_string(),
    }
}

/// The localized effective-endpoint-order line: `endpoints: <a> -> <b>`. For the plain
/// auto default the head is decided by a live RTT probe at start, so the order shown is
/// the candidate default and the note says so. Used by the `start` banner.
pub(crate) fn endpoints_line(view: &RegionView) -> String {
    let joined = view.authorities.join(" -> ");
    if view.probed {
        format!(
            "{} {} {}",
            tr!("endpoints:", "端点:"),
            joined,
            tr!("(nearest-first, chosen at start)", "(启动时按最近优先选择)")
        )
    } else {
        format!("{} {}", tr!("endpoints:", "端点:"), joined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alice_miner_core::i18n::{set_lang, Lang};

    // `mode`/`endpoints` read the current language. `set_lang` is scoped to the calling
    // thread and libtest gives each test its own, so pinning one here is invisible to
    // every test running beside it — no lock involved.

    /// The DECISION MATRIX (task ⑤): the failover flag, the probe flag, and the
    /// effective endpoint order for each of the four sources (lock / env / last-good /
    /// default) + precedence. Language-INDEPENDENT — no lang lock needed.
    #[test]
    fn view_matrix_over_four_sources() {
        // (1) LOCK: single region, no failover.
        let v = from_inputs(Some("asia".into()), None, None, None);
        assert!(!v.failover_on && !v.probed);
        assert_eq!(v.authorities, vec!["asia.aliceprotocol.org:3340".to_string()]);

        // (2) ENV override: prefer-head, failover on, that region first then the rest.
        let v = from_inputs(None, Some("asia".into()), None, None);
        assert!(v.failover_on && !v.probed);
        assert_eq!(
            v.authorities,
            vec![
                "asia.aliceprotocol.org:3340".to_string(),
                "us.aliceprotocol.org:3340".to_string(),
                "eu.aliceprotocol.org:3340".to_string(),
            ]
        );

        // (3) LAST-GOOD: prefer-head, failover on, same shape from history.
        let v = from_inputs(None, None, Some("asia".into()), None);
        assert!(v.failover_on && !v.probed);
        assert_eq!(v.authorities.first().map(String::as_str), Some("asia.aliceprotocol.org:3340"));

        // (4) DEFAULT: probe, failover on, compiled candidates US-first.
        let v = from_inputs(None, None, None, None);
        assert!(v.failover_on && v.probed);
        assert_eq!(
            v.authorities,
            vec![
                "us.aliceprotocol.org:3340".to_string(),
                "asia.aliceprotocol.org:3340".to_string(),
                "eu.aliceprotocol.org:3340".to_string(),
            ]
        );

        // Precedence: lock beats env beats last-good.
        let v = from_inputs(Some("us".into()), Some("asia".into()), Some("asia".into()), None);
        assert_eq!(v.authorities, vec!["us.aliceprotocol.org:3340".to_string()]);
        assert!(!v.failover_on);
    }

    /// The localized MODE + ENDPOINT lines render correctly in BOTH languages (proves the
    /// bilingual path is wired and the endpoint-order line matches the report's format).
    #[test]
    fn mode_and_endpoint_lines_bilingual() {
        // English.
        set_lang(Lang::En);
        let v = from_inputs(Some("asia".into()), None, None, None);
        assert!(v.mode.contains("locked to asia") && v.mode.contains("no auto-failover"));
        assert_eq!(endpoints_line(&v), "endpoints: asia.aliceprotocol.org:3340");
        let v = from_inputs(None, Some("asia".into()), None, None);
        assert!(v.mode.contains("asia (operator override)"));
        assert_eq!(
            endpoints_line(&v),
            "endpoints: asia.aliceprotocol.org:3340 -> us.aliceprotocol.org:3340 -> eu.aliceprotocol.org:3340"
        );
        let v = from_inputs(None, None, Some("asia".into()), None);
        assert!(v.mode.contains("resuming last-good asia"));
        let v = from_inputs(None, None, None, None);
        assert!(v.mode.contains("auto (nearest region)"));
        assert!(endpoints_line(&v).contains("nearest-first, chosen at start"));

        // Chinese.
        set_lang(Lang::Zh);
        let v = from_inputs(Some("asia".into()), None, None, None);
        assert!(v.mode.contains("已锁定 asia"));
        let v = from_inputs(None, None, None, None);
        assert!(v.mode.contains("自动"));
        assert!(endpoints_line(&v).contains("端点:"));
        set_lang(Lang::En);
    }

    /// The removed-`fi` signal fires from an endpoints-JSON override even though the
    /// effective PRL order (compiled defaults) never contains it — and is clean otherwise.
    #[test]
    fn fi_override_sets_removed_region_flag() {
        let clean = from_inputs(None, None, None, None);
        assert!(!clean.has_removed_region, "compiled defaults are fi-free");
        assert!(!clean.endpoints_json_set);

        let leaked = from_inputs(
            None,
            None,
            None,
            Some("{\"gpu-prl\":[\"fi.aliceprotocol.org:3340\"]}".into()),
        );
        assert!(leaked.has_removed_region, "fi in the override is flagged");
        assert!(leaked.endpoints_json_set);
    }
}
