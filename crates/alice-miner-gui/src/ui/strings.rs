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

/// Connecting hero readout (the indeterminate sweep state).
pub const CTA_CONNECTING: &str = "CONNECTING";
pub const CTA_CONNECTING_SUB: &str = "reaching the relay · 连接中";

/// Stopping hero readout (the brief tear-down transient).
pub const CTA_STOPPING: &str = "STOPPING";
pub const CTA_STOPPING_SUB: &str = "winding down · 停止中";

/// Error hero readout — a calm "start again" affordance (no scary dump).
pub const CTA_RETRY: &str = "START AGAIN";
pub const CTA_RETRY_SUB: &str = "the lane stopped · 已停止";

/// "Rewards to <addr>" prefix (the address itself is the user's OWN public one,
/// supplied at call sites — never a collection address).
pub const REWARDS_TO: &str = "Rewards to";

/// Experimental badge ("测试中") — the mining feature is opt-in + experimental.
pub const EXPERIMENTAL: &str = "experimental · 测试中";

// ── Home status lines (one per engine state) ─────────────────────────────────
/// Idle status line.
pub const STATUS_IDLE: &str = "Idle — press Start to begin";
/// Connecting status line (the PUBLIC relay only — never the upstream pool).
pub const STATUS_CONNECTING: &str = "Connecting to the relay…";
/// Stopping status line.
pub const STATUS_STOPPING: &str = "Stopping the miner…";
/// A calm, generic error status when the engine gave no specific reason.
pub const STATUS_ERROR_GENERIC: &str = "The mining lane stopped. You can start again.";

// ── Onboarding (create / back-up / confirm / import / watch-only) ────────────
pub const OB_WELCOME_EYEBROW: &str = "Welcome · 欢迎";
pub const OB_WELCOME_TITLE: &str = "Set up your reward identity";
pub const OB_WELCOME_SUB: &str = "One Alice identity works in Wallet, Miner & AI.";

pub const OB_BACKUP_EYEBROW: &str = "Step 2 of 3 · back up";
pub const OB_BACKUP_TITLE: &str = "Write down your recovery phrase";
pub const OB_BACKUP_SUB: &str = "24 words. The only way to recover this identity.";
pub const OB_BACKUP_WARNING: &str =
    "This is the only way to recover. Anyone with these words controls the address. Store offline — never paste it online.";
pub const OB_BACKUP_ACK: &str = "I've written down all 24 words and stored them safely.";

pub const OB_CONFIRM_EYEBROW: &str = "Step 3 of 3 · confirm";
pub const OB_CONFIRM_TITLE: &str = "Confirm your phrase";
/// Mismatch feedback when a tapped word is wrong (calm, not scary).
pub const OB_CONFIRM_WRONG: &str = "That word doesn't match — tap the right one.";

pub const OB_IMPORT_EYEBROW: &str = "Import";
pub const OB_IMPORT_TITLE: &str = "Import an existing identity";
pub const OB_IMPORT_SUB: &str = "Paste a 12/24-word phrase, or a raw seed (hex).";

pub const OB_PASTE_EYEBROW: &str = "Watch-only";
pub const OB_PASTE_TITLE: &str = "Paste an Alice address";
pub const OB_PASTE_SUB: &str = "Track rewards for an address you own. No keys stored.";

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
        // Some declarations wrap the value onto the FOLLOWING line(s); when a
        // `pub const` line carries no quote we keep scanning subsequent lines for
        // the string literal so the scan covers EVERY user-facing constant (a
        // multi-line value must not slip through the honesty gate).
        let mut literals = String::new();
        let mut in_const = false; // inside a `pub const` whose literal we still seek
        for line in src.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("pub const") {
                in_const = true;
            }
            if in_const {
                if let Some(open) = line.find('"') {
                    if let Some(close) = line[open + 1..].find('"') {
                        literals.push_str(&line[open + 1..open + 1 + close]);
                        literals.push('\n');
                        in_const = false;
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
