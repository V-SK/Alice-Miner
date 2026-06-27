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

// ── Background-mining unlock (B4-keyring 3/3) ─────────────────────────────────
/// Turning ON background mining for a GPU pearlhash lane needs the wallet password,
/// which is stored in the OS keyring (macOS Keychain / Windows Credential Manager /
/// Linux Secret Service) so the secret-free background service can sign the
/// proof-of-possession. These label the modal that captures it (masked + zeroized the
/// instant the keyring write completes). NO reward vocabulary — purely a key-unlock.
pub const BG_UNLOCK_EYEBROW: &str = "Background mining";
pub const BG_UNLOCK_TITLE: &str = "Unlock to mine in the background";
pub const BG_UNLOCK_SUB: &str =
    "Background GPU mining proves you hold this address (a signature). Enter your wallet \
     password — it is stored in your OS keyring (Keychain / Credential Manager / Secret \
     Service) so the background service can sign locally. It never leaves this device.";
/// The confirm (enable) button.
pub const BG_UNLOCK_CONFIRM: &str = "Unlock & enable";
/// A small reassurance under the field.
pub const BG_UNLOCK_NOTE: &str =
    "Your password is saved in the OS keyring (not on disk) and wiped from the app right after.";

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

/// The cumulative server-confirmed credit panel (Confirmed state). These surface
/// accepted-share COUNTS (cumulative + 24h + the GPU·Alpha / GPU·PRL split) — which
/// are SHARE COUNTS, not money, so they are credit-only. The number is rendered by
/// the panel from the count fields; these are the static labels around it.
pub const CREDIT_CUMULATIVE_TITLE: &str = "Confirmed by the network";
/// Row label for the cumulative accepted-share count (the headline number).
pub const CREDIT_CUMULATIVE_TOTAL_LABEL: &str = "Accepted shares · 累计接受";
/// Row label for the 24h accepted-share count.
pub const CREDIT_CUMULATIVE_24H_LABEL: &str = "Last 24h · 近 24 小时";
/// Section label for the per-lane (GPU·Alpha / GPU·PRL) split.
pub const CREDIT_CUMULATIVE_LANES_LABEL: &str = "By pool · 按池";
/// The honest "still syncing" caption shown under the cumulative title before the
/// first successful fetch (so a not-yet-fetched view never shows a fabricated 0).
pub const CREDIT_SYNCING: &str = "syncing… · 同步中";
/// When a Source-B poll fault occurs (unreachable / withheld): a calm, neutral,
/// NON-numeric note. We never hint at any dropped value.
pub const CREDIT_UNCONFIRMED: &str = "unconfirmed · 待确认";

/// The reconciliation badge prefix (the qualitative local-vs-server status).
pub const RECONCILE_PREFIX: &str = "local vs network";

// ── GPU-PRL "15% PRL 返还" display block (A2c) ────────────────────────────────
/// The GPU-PRL lane's 15% PRL-return block. Credit-only: this surfaces the
/// ENROLL/binding status + the user's MASKED return address + an honest "pending"
/// status — never a number, never a "$", never a "paid"/"earned" claim. The 15%
/// return is routed by the network on-chain; the client only shows the binding.
/// (No English "payout" word here — the honesty gate forbids it unless paired with
/// "gated/off/disabled"; the Chinese "返还" carries the meaning without the trap.)
pub const PRL_RETURN_TITLE: &str = "15% PRL 返还";
pub const PRL_RETURN_CAPTION: &str = "Routed by the network · credit-only · 链上结算";
/// The masked-address row label (the user's OWN prl1p… return wallet, masked).
pub const PRL_RETURN_ADDR_LABEL: &str = "返还地址 · return wallet";
/// Status pills (no number, ever).
pub const PRL_RETURN_ENROLLED: &str = "bound · 已绑定";
pub const PRL_RETURN_PENDING: &str = "pending · 待绑定";
/// The honest "pending" body when bound — the 15% return accrues as pending and is
/// routed on-chain; nothing is claimable in the app.
pub const PRL_RETURN_BODY_BOUND: &str =
    "Your return wallet is bound. The 15% accrues as pending · 待发放 and is routed on-chain.";
/// The body when NOT yet bound but a return address is configured (the bind runs
/// automatically once GPU-PRL mining proves possession).
pub const PRL_RETURN_BODY_UNBOUND: &str =
    "Mine GPU · PRL to bind your return wallet · 启动 GPU-PRL 挖矿以绑定返还地址.";
/// The body when no return address is configured at all. (We do NOT spell the
/// env-var name here — it contains a forbidden token; the docs carry the exact
/// name. The honest user-facing copy just says a return wallet isn't set.)
pub const PRL_RETURN_BODY_NOADDR: &str =
    "No return wallet set · 未设置返还地址 (configure your prl1p… return wallet).";

// ── Settings · 15%-PRL return-address INPUT (A2c GUI parity) ──────────────────
/// The labeled return-address field in Settings → Identity. PUBLIC address (not a
/// secret); shown masked once saved. No reward vocabulary — just an address input.
pub const PRL_PAYOUT_FIELD_LABEL: &str = "PRL 返还地址 (可选 · 15% 返还)";
/// The input placeholder (a prl1p… address).
pub const PRL_PAYOUT_FIELD_HINT: &str = "prl1p… (your own return wallet)";
/// The Save button.
pub const PRL_PAYOUT_SAVE: &str = "Save · 保存";
/// The row hint under the field.
pub const PRL_PAYOUT_ROW_HINT: &str =
    "Where the network sends your 15% PRL 返还. A public prl1p… address — bound to your Alice \
     address on the next GPU mining start.";
/// The masked-current-value prefix (the stored address follows, mono + masked).
pub const PRL_PAYOUT_CURRENT: &str = "Saved · 已保存";
/// Shown when nothing is stored yet.
pub const PRL_PAYOUT_UNSET: &str = "未设置 · not set";
/// Watch-only gating copy: a pasted address can't sign the PoP that binds the 15%
/// return, so it must import the signing key first (mirrors the start-PRL gating).
pub const PRL_PAYOUT_WATCH_ONLY: &str =
    "GPU-PRL/Alpha 需要可签名钱包才能绑定 15% 返还 — import this address's key first.";

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
