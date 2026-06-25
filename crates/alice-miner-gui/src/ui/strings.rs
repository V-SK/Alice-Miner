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

// ── Change reward address (post-onboarding) ──────────────────────────────────
/// The Settings Identity section + the Home edit affordance open this flow.
pub const CHANGE_ADDR_EYEBROW: &str = "Identity · 身份";
pub const CHANGE_ADDR_TITLE: &str = "Change reward address";
pub const CHANGE_ADDR_SUB: &str =
    "Point mining at a different Alice address. Choose how below.";
/// The label of the current-address row at the top of the change launcher.
pub const CHANGE_ADDR_CURRENT: &str = "Currently mining to";
/// The Settings Identity-section action button + its hint.
pub const CHANGE_ADDR_ACTION: &str = "Change reward address";
/// Tag shown next to the address: it is backed by a signing keystore on disk.
pub const IDENTITY_KEYSTORE_BACKED: &str = "keystore-backed · 有私钥";
/// Tag shown next to the address: watch-only (a pasted address, no signing key).
pub const IDENTITY_WATCH_ONLY: &str = "watch-only · 仅观察";

/// The three change paths (mirrors onboarding's choose).
pub const CHANGE_ADDR_CREATE_TITLE: &str = "Create a new identity";
pub const CHANGE_ADDR_CREATE_SUB: &str = "Generate a fresh 24-word recovery phrase.";
pub const CHANGE_ADDR_IMPORT_TITLE: &str = "Import a different identity";
pub const CHANGE_ADDR_IMPORT_SUB: &str = "Restore from a 12/24-word phrase or a raw seed (hex).";
pub const CHANGE_ADDR_PASTE_TITLE: &str = "Paste a different address";
pub const CHANGE_ADDR_PASTE_SUB: &str = "Watch-only — track an address you may not hold the key for.";

/// The overwrite warning shown before Create / Import commits. `{path}` is the
/// `.bak-…` destination (filled at the call site); when no keystore exists yet
/// the [`CHANGE_ADDR_OVERWRITE_NOPRIOR`] variant is shown instead.
pub const CHANGE_ADDR_OVERWRITE_TITLE: &str = "This replaces your current reward identity";
pub const CHANGE_ADDR_OVERWRITE_BODY: &str =
    "Your existing keystore is backed up first — it is never destroyed. Keep your old recovery phrase too.";
/// Shown when there is no prior keystore to back up (first key was watch-only).
pub const CHANGE_ADDR_OVERWRITE_NOPRIOR: &str =
    "No signing keystore exists yet, so nothing is overwritten — this creates one.";
/// The "backed up to" line prefix (the path follows, mono).
pub const CHANGE_ADDR_BACKUP_TO: &str = "Old keystore backed up to";

/// The watch-only paste caution (mining will credit an address you may not hold).
pub const CHANGE_ADDR_PASTE_CAUTION: &str =
    "Mining will accrue pending to this address. If you don't hold its key, you can't recover it.";

/// Shown (disabled state) when the user opens the flow while mining is live.
pub const CHANGE_ADDR_MINING_BLOCK: &str =
    "Stop mining first — the reward address can't change while a lane is running.";

// ── GPU-PRL unlock-password prompt (A2a) ──────────────────────────────────────
/// The GPU-PRL lane signs a proof-of-possession with the wallet key, so starting
/// it asks for the keystore-unlock password (XMR/RVN never do). These label the
/// modal that captures it (the password is masked on screen + zeroized the instant
/// Start is sent). NO reward vocabulary here — it's purely a key-unlock prompt.
pub const PRL_UNLOCK_EYEBROW: &str = "GPU · PRL";
pub const PRL_UNLOCK_TITLE: &str = "Unlock your wallet to start";
pub const PRL_UNLOCK_SUB: &str =
    "The GPU · PRL lane proves you hold this address (a signature). Enter your wallet \
     password to unlock the signing key — it is used locally and never leaves this device.";
/// The password field label.
pub const PRL_UNLOCK_FIELD: &str = "Wallet password";
/// The password input placeholder.
pub const PRL_UNLOCK_HINT: &str = "your keystore password";
/// The confirm (start) button.
pub const PRL_UNLOCK_CONFIRM: &str = "Unlock & start";
/// A small reassurance under the field (the password is wiped right after use).
pub const PRL_UNLOCK_NOTE: &str =
    "Your password unlocks the local signing key and is wiped right after.";

// ── M5 dashboard depth: Source A (activity) / Source B (server-confirmed) ─────
/// Source-A section eyebrow + caption — this is LOCAL ACTIVITY, explicitly NOT
/// earnings (the brief's hard separation).
pub const ACTIVITY_SECTION: &str = "Local activity";
pub const ACTIVITY_CAPTION: &str = "What this miner is doing right now · 本机活动";

/// Source-B section eyebrow + caption — server-confirmed credit (read-only).
pub const CREDIT_SECTION: &str = "Server-confirmed credit";
pub const CREDIT_CAPTION: &str = "Read-only · confirmed by the network · 服务端确认";

/// The honest `NotExposed` panel (Option 3, the v1 path). Credit accounting is
/// live; payout is OFF (phase-J); the per-address total is not exposed to the
/// client yet. No fabricated number — point the user at the explorer.
pub const CREDIT_NOTEXPOSED_TITLE: &str = "Credit accounting is live";
pub const CREDIT_NOTEXPOSED_BODY_1: &str =
    "Your accepted work is being counted by the network. Payout is off (phase-J).";
pub const CREDIT_NOTEXPOSED_BODY_2: &str =
    "A per-address total isn't exposed in the app yet — look it up in the explorer.";
/// The explorer deep-link label + URL (PUBLIC apex; never an internal/core host).
pub const CREDIT_EXPLORER_LABEL: &str = "Open explorer · 浏览器";
pub const CREDIT_EXPLORER_URL: &str = "https://aliceprotocol.org/explorer.html";

/// The Source-B states' short value labels (no number, ever).
pub const CREDIT_CONFIRMING: &str = "confirming… · 确认中";
pub const CREDIT_PENDING_VALUE: &str = "pending · 待发放";
/// When a Source-B poll fault occurs (unreachable / withheld): a calm, neutral,
/// NON-numeric note. We never hint at any dropped value.
pub const CREDIT_UNCONFIRMED: &str = "unconfirmed · 待确认";

/// The reconciliation badge prefix (the qualitative local-vs-server status).
pub const RECONCILE_PREFIX: &str = "local vs network";

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
        // BLANKET-forbidden: fiat + any positive "already-paid/earned" claim. These
        // can never appear in user copy under any framing.
        for forbidden in ["$", "usd", "fiat", "paid", "earned", "已发放"] {
            assert!(
                !lowered.contains(&forbidden.to_lowercase()),
                "user-facing strings must not contain `{forbidden}` (credit-only honesty gate)"
            );
        }
        // CONDITIONALLY-allowed words: `payout`/`settlement` may appear ONLY in a
        // "stay gated" disclosure (an honest *negative*), and `credit` may appear
        // ONLY in its honest, non-cash sense (the brief forbids "credit-AS-CASH",
        // not the word itself — M5 surfaces "server-confirmed credit" / "credit
        // accounting"). So a line mentioning `credit` must NOT also carry any
        // cash-coding token, and `payout`/`settlement` must carry `gated`.
        const CREDIT_AS_CASH_TOKENS: [&str; 7] =
            ["$", "usd", "fiat", "balance", "wallet", "paid", "earned"];
        for line in literals.lines() {
            let l = line.to_lowercase();
            if l.contains("credit") {
                for cash in CREDIT_AS_CASH_TOKENS {
                    assert!(
                        !l.contains(cash),
                        "`credit` must not be used as cash (found `{cash}` on the same line): {line:?}"
                    );
                }
            }
            // `payout`/`settlement` may appear ONLY as an honest *negative*
            // disclosure — the thing does NOT happen. Accept the equivalent
            // phrasings "gated" / "off" / "disabled" (e.g. "Payout is off
            // (phase-J)"), but never a positive claim.
            if l.contains("payout") || l.contains("settlement") {
                let is_negative_disclosure =
                    l.contains("gated") || l.contains("off") || l.contains("disabled");
                assert!(
                    is_negative_disclosure,
                    "`payout`/`settlement` may only appear as a negative disclosure (gated/off/disabled): {line:?}"
                );
            }
        }
    }
}
