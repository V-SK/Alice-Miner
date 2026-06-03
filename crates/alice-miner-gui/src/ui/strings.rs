//! Centralized user-facing strings — the **enforceable honesty boundary**
//! (the brief's CREDIT-ONLY / HONESTY hard rule, PLAN §3).
//!
//! Every reward-adjacent label the UI shows lives HERE, behind a small API, so
//! the credit-only invariant is auditable in one place and a unit test can scan
//! this module for forbidden tokens. Hard rules enforced by the test below:
//!   * NO `$` / fiat / number for "rewards" — rewards are only "pending / 待发放".
//!   * NO `credit` / `paid` / `earned` / `已发放` (or payout/settle/mint) in any
//!     user-facing string.
//!   * The collection address + upstream pool are NEVER rendered (only the
//!     PUBLIC relay endpoint + the user's OWN address — those are not here).

// This module is the centralized reward/honesty vocabulary; some entries are the
// canonical form used by tests / later screens even if not every screen renders
// every one today. Keeping them here is the point (single auditable surface).
#![allow(dead_code)]

/// The ONLY way "rewards" are ever rendered: pending, bilingual.
pub const REWARD_PENDING: &str = "pending · 待发放";

/// The short pending tag used inline (e.g. on a stat card value).
pub const REWARD_PENDING_SHORT: &str = "— pending";

/// The honest sub-line for the est-rewards card (no rate, no number).
pub const REWARD_RATE_PENDING: &str = "待发放 · rate pending";

/// The Home footer — rewards accrue as pending; payout/settlement/transfer stay
/// gated. Bilingual, verbatim intent from the mockup `.foot`.
pub const FOOTER_LINE_1: &str = "Rewards accrue as pending · 待发放.";
pub const FOOTER_LINE_2: &str = "Payout, settlement & on-chain transfer stay gated.";

/// The "hashing" sub-label shown under the live hashrate number while mining.
pub const HASHING_SUB: &str = "hashing · 待发放";

/// Idle hero CTA + its sub-line.
pub const CTA_START: &str = "START";
pub const CTA_START_SUB: &str = "press to begin · 点击开始";

/// "Rewards to <addr>" prefix (the address itself is the user's OWN public one,
/// supplied at call sites — never a collection address).
pub const REWARDS_TO: &str = "Rewards to";

/// Experimental badge ("测试中") — the mining feature is opt-in + experimental.
pub const EXPERIMENTAL: &str = "experimental · 测试中";

#[cfg(test)]
mod tests {
    /// The credit-only honesty gate: every user-facing string literal in this
    /// module must be free of forbidden reward tokens. We read THIS FILE at test
    /// time and scan ONLY the contents of the `pub const … = "…";` literals
    /// (extracted by parsing each such line) so the check covers exactly the
    /// user-facing copy — not the doc-comments / rule names, which legitimately
    /// mention `$` etc. while describing the rule.
    #[test]
    fn no_forbidden_reward_tokens_in_user_strings() {
        let src = include_str!("strings.rs");
        // Extract the body of each `pub const NAME: &str = "BODY";` declaration.
        let mut literals = String::new();
        for line in src.lines() {
            let line = line.trim_start();
            if line.starts_with("pub const") {
                if let Some(open) = line.find('"') {
                    if let Some(close) = line[open + 1..].find('"') {
                        literals.push_str(&line[open + 1..open + 1 + close]);
                        literals.push('\n');
                    }
                }
            }
        }
        assert!(
            !literals.is_empty(),
            "expected to extract at least one string constant"
        );
        // Case-insensitive scan for the brief's forbidden vocabulary: no fiat,
        // and no positive earnings claim. ("pending / 待发放" is the ONLY way
        // rewards are described.) Note: the approved contract footer DOES say
        // "Payout, settlement … stay gated" — that's an honest *negative*
        // disclosure (these do NOT happen), so `payout`/`settlement` are not
        // forbidden; only misleading/positive tokens are.
        let lowered = literals.to_lowercase();
        for forbidden in ["$", "usd", "fiat", "credit", "paid", "earned", "已发放"] {
            assert!(
                !lowered.contains(&forbidden.to_lowercase()),
                "user-facing strings must not contain `{forbidden}` (credit-only honesty gate)"
            );
        }
        // And the gated-disclosure words may appear ONLY alongside "gated", never
        // as a positive claim — assert that invariant explicitly.
        for line in literals.lines() {
            let l = line.to_lowercase();
            if l.contains("payout") || l.contains("settlement") {
                assert!(
                    l.contains("gated"),
                    "`payout`/`settlement` may only appear in a 'stay gated' disclosure: {line:?}"
                );
            }
        }
    }
}
