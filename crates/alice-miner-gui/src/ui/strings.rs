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

// Some entries are LANGUAGE-AWARE: a bilingual pair `NAME_EN` / `NAME_ZH` (both
// scanned by the honesty gate below) plus a tiny `pub fn name()` accessor that
// returns the variant for the current global language via `tr!`. This keeps the
// user string a SINGLE clean language in the UI (no "English 残留" in 中文 mode)
// while every reward-adjacent literal stays on this one auditable surface.
use alice_miner_core::tr;

/// The ONLY way "rewards" are ever rendered: pending, bilingual.
pub const REWARD_PENDING: &str = "pending · 待发放";

/// The short pending tag used inline (e.g. on a stat card value). Bilingual-aware.
pub const REWARD_PENDING_SHORT_EN: &str = "— pending";
pub const REWARD_PENDING_SHORT_ZH: &str = "— 待发放";
pub fn reward_pending_short() -> &'static str {
    tr!(REWARD_PENDING_SHORT_EN, REWARD_PENDING_SHORT_ZH)
}

/// The honest sub-line for the est-rewards card (no rate, no number).
pub const REWARD_RATE_PENDING: &str = "待发放 · rate pending";

/// The Home footer — rewards accrue as pending; payout/settlement/transfer stay
/// gated. Bilingual-aware (LINE_1 already carried both; LINE_2 gains a 中文 variant).
/// The `payout … gated` wording is an honest NEGATIVE disclosure (the honesty gate
/// permits `payout`/`settlement` only alongside gated/off/disabled).
pub const FOOTER_LINE_1_EN: &str = "Rewards accrue as pending.";
pub const FOOTER_LINE_1_ZH: &str = "奖励以待发放形式累积。";
pub fn footer_line_1() -> &'static str {
    tr!(FOOTER_LINE_1_EN, FOOTER_LINE_1_ZH)
}
pub const FOOTER_LINE_2_EN: &str = "Payout, settlement & on-chain transfer stay gated.";
pub const FOOTER_LINE_2_ZH: &str = "发放、结算与链上转账均处于关闭(gated)状态。";
pub fn footer_line_2() -> &'static str {
    tr!(FOOTER_LINE_2_EN, FOOTER_LINE_2_ZH)
}

/// The "hashing" sub-label shown under the live hashrate number while mining.
/// Bilingual-aware; reward-adjacent (carries the "pending · 待发放" framing).
pub const HASHING_SUB_EN: &str = "hashing · pending";
pub const HASHING_SUB_ZH: &str = "哈希中 · 待发放";
pub fn hashing_sub() -> &'static str {
    tr!(HASHING_SUB_EN, HASHING_SUB_ZH)
}

/// The difficulty explainer — one honest line that removes "difficulty" from the
/// miner's mental model. There is nothing to configure: the server matches the
/// workload to the device automatically (vardiff on XMR/LTC, a fixed difficulty
/// on PRL — one sentence for the miner either way), and a contributor's share
/// tracks hashpower, not raw submitted-share count. Number-free + reward-neutral
/// (no `$`/`paid`/`earned`), so it clears the honesty gate. Bilingual.
pub const DIFFICULTY_EXPLAINER: &str =
    "No difficulty to set — Alice matches the workload to your device automatically. \
     Your share tracks your hashpower, not how many shares you submit. \
     · 无需设置难度 —— Alice 会自动把工作量匹配到你的设备;你的份额取决于你的算力,\
     而非你提交了多少 share。";

// The idle/connecting/stopping/error hero CTA labels + sub-lines are NEUTRAL chrome
// (no reward claim), so they live inline as `tr!(en, zh)` at their single call site in
// `ui/home.rs::readout` rather than here — this module stays the reward/honesty surface.

/// "Rewards to <addr>" prefix (the address itself is the user's OWN public one,
/// supplied at call sites — never a collection address). Bilingual-aware.
pub const REWARDS_TO_EN: &str = "Rewards to";
pub const REWARDS_TO_ZH: &str = "奖励到";
pub fn rewards_to() -> &'static str {
    tr!(REWARDS_TO_EN, REWARDS_TO_ZH)
}

/// Experimental badge ("测试中") — the mining feature is opt-in + experimental.
pub const EXPERIMENTAL: &str = "experimental · 测试中";

// ── Home status lines (one per engine state) ─────────────────────────────────
// These are NEUTRAL status chrome (no reward claim), so they live inline as
// `tr!(en, zh)` at their single call site in `ui/home.rs::status_line`.

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
/// earnings (the brief's hard separation). Bilingual-aware.
pub const ACTIVITY_SECTION_EN: &str = "Local activity";
pub const ACTIVITY_SECTION_ZH: &str = "本机活动";
pub fn activity_section() -> &'static str {
    tr!(ACTIVITY_SECTION_EN, ACTIVITY_SECTION_ZH)
}
pub const ACTIVITY_CAPTION_EN: &str = "What this miner is doing right now";
pub const ACTIVITY_CAPTION_ZH: &str = "本机此刻的活动";
pub fn activity_caption() -> &'static str {
    tr!(ACTIVITY_CAPTION_EN, ACTIVITY_CAPTION_ZH)
}

/// Source-B section eyebrow + caption — server-confirmed credit (read-only).
/// Bilingual-aware.
pub const CREDIT_SECTION_EN: &str = "Server-confirmed credit";
pub const CREDIT_SECTION_ZH: &str = "服务端确认的积分";
pub fn credit_section() -> &'static str {
    tr!(CREDIT_SECTION_EN, CREDIT_SECTION_ZH)
}
pub const CREDIT_CAPTION_EN: &str = "Read-only · confirmed by the network";
pub const CREDIT_CAPTION_ZH: &str = "只读 · 由网络确认";
pub fn credit_caption() -> &'static str {
    tr!(CREDIT_CAPTION_EN, CREDIT_CAPTION_ZH)
}

/// The honest `NotExposed` panel (Option 3, the v1 path). Credit accounting is
/// live; payout is OFF (phase-J); the per-address total is not exposed to the
/// client yet. No fabricated number — point the user at the explorer.
pub const CREDIT_NOTEXPOSED_TITLE_EN: &str = "Credit accounting is live";
pub const CREDIT_NOTEXPOSED_TITLE_ZH: &str = "积分记账已上线";
pub fn credit_notexposed_title() -> &'static str {
    tr!(CREDIT_NOTEXPOSED_TITLE_EN, CREDIT_NOTEXPOSED_TITLE_ZH)
}
pub const CREDIT_NOTEXPOSED_BODY_1_EN: &str =
    "Your accepted work is being counted by the network. Payout is off (phase-J).";
pub const CREDIT_NOTEXPOSED_BODY_1_ZH: &str =
    "你被接受的工作正在由网络计数。发放功能未开启(phase-J)。";
pub fn credit_notexposed_body_1() -> &'static str {
    tr!(CREDIT_NOTEXPOSED_BODY_1_EN, CREDIT_NOTEXPOSED_BODY_1_ZH)
}
pub const CREDIT_NOTEXPOSED_BODY_2_EN: &str =
    "A per-address total isn't exposed in the app yet — look it up in the explorer.";
pub const CREDIT_NOTEXPOSED_BODY_2_ZH: &str =
    "应用暂不显示单地址累计 —— 请在区块浏览器中查询。";
pub fn credit_notexposed_body_2() -> &'static str {
    tr!(CREDIT_NOTEXPOSED_BODY_2_EN, CREDIT_NOTEXPOSED_BODY_2_ZH)
}
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
pub const CREDIT_CUMULATIVE_TITLE_EN: &str = "Confirmed by the network";
pub const CREDIT_CUMULATIVE_TITLE_ZH: &str = "已由网络确认";
pub fn credit_cumulative_title() -> &'static str {
    tr!(CREDIT_CUMULATIVE_TITLE_EN, CREDIT_CUMULATIVE_TITLE_ZH)
}
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

// ── v0.6.0 real-money PAYOUT sub-panel (Confirmed + live PayoutView) ──────────
/// Shown ONLY once the server flips real-money payout ON (a self-consistent payout
/// envelope). Unlike the credit-only counts these ARE real ALICE figures — but only
/// the server's own settled/paid values, self-verifiable on the explorer.
pub const CREDIT_PAYOUT_TITLE: &str = "Payout is live · 已开通发放";
/// Row label for the settled-ALICE figure (finalized accounting).
pub const CREDIT_PAYOUT_SETTLED_LABEL: &str = "Settled · 已结算";
/// Row label for the paid-ALICE figure (actually disbursed on-chain).
pub const CREDIT_PAYOUT_PAID_LABEL: &str = "Paid · 已发放";
/// The self-verify hint pointing the miner at the on-chain explorer.
pub const CREDIT_PAYOUT_VERIFY_HINT: &str =
    "Verify these amounts on-chain in the explorer · 在浏览器链上核对";

// ── v0.6.0 upgrade banner (CreditState::UpgradeRequired) ──────────────────────
/// The server advertised a minimum client version this build does not meet.
pub const CREDIT_UPGRADE_TITLE: &str = "Please update to keep mining · 请更新以继续挖矿";
/// The body prefix — the panel appends the required "vX.Y+" version.
pub const CREDIT_UPGRADE_BODY: &str =
    "The network now requires a newer client to confirm your credit. Please update to";
/// The download call-to-action button label.
pub const CREDIT_UPGRADE_CTA: &str = "Get the update · 获取更新";

/// The reconciliation badge prefix (the qualitative local-vs-server status).
/// Bilingual-aware.
pub const RECONCILE_PREFIX_EN: &str = "local vs network";
pub const RECONCILE_PREFIX_ZH: &str = "本地 vs 网络";
pub fn reconcile_prefix() -> &'static str {
    tr!(RECONCILE_PREFIX_EN, RECONCILE_PREFIX_ZH)
}

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
/// routed on-chain; nothing is claimable in the app. Bilingual-aware.
pub const PRL_RETURN_BODY_BOUND_EN: &str =
    "Your return wallet is bound. The 15% accrues as pending and is routed on-chain.";
pub const PRL_RETURN_BODY_BOUND_ZH: &str =
    "返还钱包已绑定。15% 以待发放形式累积,并在链上路由。";
pub fn prl_return_body_bound() -> &'static str {
    tr!(PRL_RETURN_BODY_BOUND_EN, PRL_RETURN_BODY_BOUND_ZH)
}
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
/// Bilingual-aware.
pub const PRL_PAYOUT_FIELD_LABEL_EN: &str = "PRL return address (optional · 15% return)";
pub const PRL_PAYOUT_FIELD_LABEL_ZH: &str = "PRL 返还地址(可选 · 15% 返还)";
pub fn prl_payout_field_label() -> &'static str {
    tr!(PRL_PAYOUT_FIELD_LABEL_EN, PRL_PAYOUT_FIELD_LABEL_ZH)
}
/// The input placeholder (a prl1p… address). Bilingual-aware.
pub const PRL_PAYOUT_FIELD_HINT_EN: &str = "prl1p… (your own return wallet)";
pub const PRL_PAYOUT_FIELD_HINT_ZH: &str = "prl1p…(你自己的返还钱包)";
pub fn prl_payout_field_hint() -> &'static str {
    tr!(PRL_PAYOUT_FIELD_HINT_EN, PRL_PAYOUT_FIELD_HINT_ZH)
}
/// The Save button.
pub const PRL_PAYOUT_SAVE: &str = "Save · 保存";
/// The row hint under the field. Bilingual-aware.
pub const PRL_PAYOUT_ROW_HINT_EN: &str =
    "Where the network sends your 15% PRL return. A public prl1p… address — bound to your Alice \
     address on the next GPU mining start.";
pub const PRL_PAYOUT_ROW_HINT_ZH: &str =
    "网络把你的 15% PRL 返还发送到的地址。一个公开的 prl1p… 地址 —— 在下次 GPU 挖矿启动时\
     绑定到你的 Alice 地址。";
pub fn prl_payout_row_hint() -> &'static str {
    tr!(PRL_PAYOUT_ROW_HINT_EN, PRL_PAYOUT_ROW_HINT_ZH)
}
/// The masked-current-value prefix (the stored address follows, mono + masked).
pub const PRL_PAYOUT_CURRENT: &str = "Saved · 已保存";
/// Shown when nothing is stored yet.
pub const PRL_PAYOUT_UNSET: &str = "未设置 · not set";
/// Watch-only gating copy: a pasted address can't sign the PoP that binds the 15%
/// return, so it must import the signing key first (mirrors the start-PRL gating).
/// Bilingual-aware.
pub const PRL_PAYOUT_WATCH_ONLY_EN: &str =
    "GPU-PRL/Alpha needs a signable wallet to bind the 15% return — import this address's key first.";
pub const PRL_PAYOUT_WATCH_ONLY_ZH: &str =
    "GPU-PRL/Alpha 需要可签名钱包才能绑定 15% 返还 —— 请先导入该地址的私钥。";
pub fn prl_payout_watch_only() -> &'static str {
    tr!(PRL_PAYOUT_WATCH_ONLY_EN, PRL_PAYOUT_WATCH_ONLY_ZH)
}

#[cfg(test)]
mod tests {
    /// The credit-only honesty gate: every user-facing string literal in this
    /// module must be free of forbidden reward tokens. We read THIS FILE at test
    /// time and scan ONLY the contents of the `pub const … = "…";` literals
    /// (extracted by parsing each such line) so the check covers exactly the
    /// user-facing copy — not the doc-comments / rule names, which legitimately
    /// mention `$` etc. while describing the rule.
    /// The v0.6.0 payout-aware EXCEPTION set: constants that DELIBERATELY carry a
    /// positive "paid / settled / 发放" claim because they render ONLY once the server
    /// has flipped real-money payout ON (a self-consistent payout-live envelope —
    /// proven by the core `parse_credit_envelope` tests) or when the client is below
    /// the supported floor. These are the reviewed exception to the credit-only blanket
    /// ban; every OTHER user string stays fully gated. (They are STILL barred from raw
    /// fiat tokens `$`/`usd`/`fiat` — see the assertion below.)
    const PAYOUT_ERA_CONST_PREFIXES: [&str; 2] = ["CREDIT_PAYOUT_", "CREDIT_UPGRADE_"];

    #[test]
    fn no_forbidden_reward_tokens_in_user_strings() {
        let src = include_str!("strings.rs");
        // Extract each `pub const NAME: &str = "BODY";` declaration as (name, body).
        // Some declarations wrap the value onto the FOLLOWING line(s); when a
        // `pub const` line carries no quote we keep scanning subsequent lines for
        // the string literal so the scan covers EVERY user-facing constant (a
        // multi-line value must not slip through the honesty gate).
        let mut consts: Vec<(String, String)> = Vec::new();
        let mut cur_name: Option<String> = None; // inside a `pub const` whose literal we still seek
        for line in src.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("pub const") {
                // Parse the NAME between `pub const ` and the `:`.
                cur_name = trimmed
                    .strip_prefix("pub const ")
                    .and_then(|r| r.split(':').next())
                    .map(|n| n.trim().to_string());
            }
            if cur_name.is_some() {
                if let Some(open) = line.find('"') {
                    if let Some(close) = line[open + 1..].find('"') {
                        let name = cur_name.take().unwrap();
                        consts.push((name, line[open + 1..open + 1 + close].to_string()));
                    }
                }
            }
        }
        assert!(!consts.is_empty(), "expected to extract at least one string constant");

        // The blanket-gated corpus = every constant EXCEPT the reviewed payout-era set.
        let is_payout_era =
            |name: &str| PAYOUT_ERA_CONST_PREFIXES.iter().any(|p| name.starts_with(p));
        let gated_literals: String = consts
            .iter()
            .filter(|(n, _)| !is_payout_era(n))
            .map(|(_, b)| format!("{b}\n"))
            .collect();
        let literals = gated_literals.clone(); // (the per-line checks below reuse this)

        // Case-insensitive scan for the brief's forbidden vocabulary: no fiat,
        // and no positive earnings claim. ("pending / 待发放" is the ONLY way
        // rewards are described in the credit-only phase.) Note: the approved
        // contract footer DOES say "Payout, settlement … stay gated" — that's an
        // honest *negative* disclosure, so `payout`/`settlement` are not forbidden;
        // only misleading/positive tokens are.
        let lowered = gated_literals.to_lowercase();
        // BLANKET-forbidden in the CREDIT-ONLY corpus: fiat + any positive
        // "already-paid/earned" claim.
        for forbidden in ["$", "usd", "fiat", "paid", "earned", "已发放"] {
            assert!(
                !lowered.contains(&forbidden.to_lowercase()),
                "credit-only user strings must not contain `{forbidden}` (credit-only honesty gate)"
            );
        }
        // The payout-era EXCEPTION strings may say "paid"/"settled"/"发放" (payout is
        // genuinely live when they render) but STILL must never carry a raw fiat token.
        for (name, body) in consts.iter().filter(|(n, _)| is_payout_era(n)) {
            let low = body.to_lowercase();
            for fiat in ["$", "usd", "fiat"] {
                assert!(
                    !low.contains(fiat),
                    "payout-era string `{name}` must not carry a fiat token `{fiat}`: {body:?}"
                );
            }
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
