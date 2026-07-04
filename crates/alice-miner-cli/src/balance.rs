//! `balance` — the THREE honest reward buckets for an Alice address.
//!
//! `alice-miner balance [--address a2…] [--json]`
//!
//! Resolves the active identity address (or `--address`; watch-only friendly) and
//! queries the PUBLIC read API — the SAME `{base}/read/miner-lookup?address=` path,
//! https-only, capped, ~10 s transport the live `start` credit poller uses (via
//! [`alice_miner_core::fetch_balance_lookup`]) — then renders three
//! NON-overlapping, honestly-labelled buckets.
//!
//!   1. **Credit (积分)** — credit-only cumulative accepted-share COUNT from AI +
//!      credit mining. Converts to ALICE only at the real-money launch. NOT fiat.
//!   2. **PRL rebate (real PRL)** — the REAL 15% pearlhash return (returned crypto),
//!      from the read model's `prl_subsidy` section: bound status + accrual state.
//!      The payout rail is gated OFF, so NO amount is shown (never fabricated) — the
//!      binding + "accruing" state is the honest surface.
//!   3. **ALICE (real token)** — the REAL on-chain token. The public read model does
//!      NOT expose an on-chain balance (`paid_acu` is stamped `"0"` — credit-only),
//!      so this shows the honest pending state "0 · real-money mining not yet
//!      enabled" UNLESS a read-only chain RPC is configured (`ALICE_MINER_CHAIN_RPC`).
//!      We NEVER invent a number.
//!
//! Offline / network-fail → a clear message, never a crash and never a fabricated
//! value. `--json` returns a structured object with the SAME honesty (nulls where
//! unknown). Everything is localized via [`tr!`].

use alice_miner_core::tr;
use alice_miner_core::{BalanceLookup, CreditError, CreditState, PrlRebateView};

use crate::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE};

/// `alice-miner balance` arguments.
#[derive(clap::Args)]
pub struct BalanceArgs {
    /// The Alice address to look up (defaults to the active `~/.alice` identity).
    /// A public read only needs the address — a watch-only / pasted identity works.
    #[arg(long, value_name = "ADDRESS")]
    pub address: Option<String>,
    /// Emit the three buckets as one JSON object (machine-readable) with the same
    /// honesty: `null` where a value is unknown / not exposed, never a fabricated 0.
    #[arg(long)]
    pub json: bool,
}

/// Run the `balance` command. Resolves the address, fetches the read-model buckets,
/// resolves the on-chain ALICE-token bucket (honest pending state today), and prints
/// the human table or the `--json` object.
pub fn run(args: BalanceArgs) -> i32 {
    // Resolve the address: --address wins, else the active identity pointer.
    let address = match args.address.clone().or_else(|| {
        alice_miner_core::identity::load_pointer().map(|p| p.address)
    }) {
        Some(a) if !a.trim().is_empty() => a.trim().to_string(),
        _ => {
            let msg = tr!(
                "no address: pass --address <a2…> or create an identity first (`alice-miner identity --create`).",
                "无地址:请传入 --address <a2…>,或先创建身份(`alice-miner identity --create`)。"
            );
            if args.json {
                println!("{}", serde_json::json!({ "ok": false, "error": "no_address" }));
            } else {
                eprintln!("error: {msg}");
            }
            return EXIT_USAGE;
        }
    };

    // Fetch the read-model buckets (credit + PRL rebate). A transport / non-https
    // failure is surfaced honestly (no crash, no fabricated value).
    let lookup = alice_miner_core::fetch_balance_lookup(&address);

    // Resolve the on-chain ALICE-token bucket. The public read model does NOT expose
    // it (credit-only), so this is the honest pending state today. See `resolve_alice_token`.
    let alice_token = resolve_alice_token(&address);

    if args.json {
        print_json(&address, &lookup, &alice_token);
        // A lookup transport failure still emits a well-formed JSON object (with the
        // error noted); exit non-zero so a harness can tell.
        return if lookup.is_ok() { EXIT_OK } else { EXIT_RUNTIME };
    }

    match lookup {
        Ok(b) => {
            print!("{}", render_balance(&address, &b, &alice_token));
            EXIT_OK
        }
        Err(e) => {
            // Offline / read-API unreachable: show the buckets we CAN honestly state
            // (the ALICE token pending state) + a clear "couldn't reach" note, no crash.
            print!("{}", render_offline(&address, &e, &alice_token));
            EXIT_RUNTIME
        }
    }
}

/// The on-chain ALICE-token bucket resolution. Today the public read API does NOT
/// expose an on-chain balance (`paid_acu` is stamped `"0"` — credit-only, pre-launch),
/// and no public read-only chain RPC is wired, so this returns [`AliceToken::Pending`]
/// — the honest "real-money mining not yet enabled" state. It NEVER fabricates a number.
///
/// The one config seam for the fast-follow: if `ALICE_MINER_CHAIN_RPC` is set to an
/// `https://` endpoint, a future build can resolve a real on-chain free balance there;
/// until that path exists we still report `Pending` (we never guess), but we record
/// that an RPC was configured so the JSON/human output is transparent about it.
fn resolve_alice_token(_address: &str) -> AliceToken {
    match std::env::var(alice_miner_core::ENV_CHAIN_RPC_URL) {
        Ok(rpc) if rpc.trim().starts_with("https://") => {
            // A read-only chain RPC is CONFIGURED but the on-chain read path is not yet
            // implemented (real-money mining is not enabled). Stay honest: pending, and
            // note that an RPC was configured (so the user isn't misled into thinking it
            // was consulted for a number we do not have).
            AliceToken::PendingWithRpc
        }
        _ => AliceToken::Pending,
    }
}

/// The on-chain ALICE-token bucket state. There is deliberately NO "amount" variant
/// today — the real token is pre-launch, so we only ever report the honest pending
/// state. (A future `Confirmed { amount }` variant is the flip once a chain read exists.)
#[derive(Debug, Clone, PartialEq, Eq)]
enum AliceToken {
    /// Real-money mining not yet enabled; no on-chain balance exposed. The honest
    /// default.
    Pending,
    /// Same pending state, but a read-only chain RPC was configured (the on-chain
    /// read path is not yet implemented — we still do not fabricate a number).
    PendingWithRpc,
}

impl AliceToken {
    /// The human value string for the ALICE-token bucket (always honest / pending today).
    fn human(&self) -> String {
        let base = tr!(
            "0 · real-money mining not yet enabled",
            "0 · 真钱挖矿未开通"
        );
        match self {
            AliceToken::Pending => base.to_string(),
            AliceToken::PendingWithRpc => format!(
                "{base} · {}",
                tr!("(chain RPC configured; on-chain read pending)", "(已配置链 RPC;链上读取待接入)")
            ),
        }
    }
}

/// The credit (积分) bucket value string, honest per [`CreditState`].
fn credit_value(credit: &CreditState) -> String {
    match credit {
        CreditState::Confirmed { totals, .. } => {
            // The cumulative accepted-share COUNT is the credit magnitude (credit-only:
            // it's a COUNT, never money).
            format!(
                "{} {} (24h {})",
                totals.accepted_total,
                tr!("shares", "份额"),
                totals.accepted_24h,
            )
        }
        CreditState::Confirming => {
            tr!("syncing…", "同步中…").to_string()
        }
        CreditState::NotExposed => {
            tr!("not exposed yet", "暂未公开").to_string()
        }
        CreditState::Error { reason } => {
            format!("— · {}", credit_error_message(reason))
        }
    }
}

/// A localized, honest, non-numeric message for a credit-lookup error (never leaks
/// a dropped value). Mirrors [`CreditError::message`] but is re-stated here in the
/// balance vocabulary so the two variants stay clearly credit-only.
fn credit_error_message(e: &CreditError) -> String {
    match e {
        CreditError::Unreachable => {
            tr!("couldn't reach the credit service", "无法连接积分服务").to_string()
        }
        CreditError::Unparseable => {
            tr!("credit response unavailable", "积分响应不可用").to_string()
        }
        // Deliberately neutral: never hint at the dropped payout number.
        CreditError::PaidAcuNotZero => {
            tr!("credit response withheld (payout is off)", "积分响应被保留(发放未开通)").to_string()
        }
    }
}

/// The PRL-rebate (real PRL) bucket value string. Shows the binding + accrual state;
/// NEVER a fabricated PRL amount (the payout rail is gated OFF).
fn prl_value(prl: Option<&PrlRebateView>) -> String {
    match prl {
        None => tr!("no accrual yet", "暂无累计").to_string(),
        Some(v) => {
            let pct = v
                .rebate_pct
                .map(|p| format!("{}%", p as u64))
                .unwrap_or_else(|| "15%".to_string());
            if v.bound {
                // Bound: show the accrual status + the masked fingerprint (never the raw prl1p).
                let status = v.status.clone().unwrap_or_else(|| {
                    tr!("accruing", "计入中").to_string()
                });
                let fp = v
                    .payout_address_fingerprint
                    .clone()
                    .map(|f| format!(" · {f}"))
                    .unwrap_or_default();
                // The amount is intentionally "—": payout is off (credit-only), so there
                // is no real disbursement to report — never a fabricated number.
                let amount = format!("{pct} — {}", tr!("(payout off)", "(发放未开通)"));
                format!("{} · {} · {amount}{fp}", tr!("bound", "已绑定"), status)
            } else {
                // Unbound: accrual is happening, but no return address is set — nudge.
                format!(
                    "{} · {} · {}",
                    tr!("not bound", "未绑定"),
                    tr!("accruing", "计入中"),
                    tr!(
                        "set a prl1p return address to receive your 15%",
                        "设置 prl1p 返还地址以领取你的 15%"
                    ),
                )
            }
        }
    }
}

/// Render the full three-bucket table for a successful lookup.
fn render_balance(address: &str, b: &BalanceLookup, alice: &AliceToken) -> String {
    let mut out = String::new();
    out.push_str(&format!("\n  {} {}\n", tr!("Balance for", "余额:"), address));
    out.push_str(&format!("  {}\n", "─".repeat(60)));

    // Bucket 1 — Credit (积分).
    out.push_str(&format!(
        "  {}\n      {}\n      {}\n",
        tr!("Credit (积分)", "积分 Credit"),
        credit_value(&b.credit),
        tr!(
            "converts to ALICE at real-money launch",
            "真钱开通后转 ALICE"
        ),
    ));

    // Bucket 2 — PRL rebate (real PRL).
    out.push_str(&format!(
        "\n  {}\n      {}\n      {}\n",
        tr!("PRL rebate (real PRL)", "PRL 返现(真 PRL)"),
        prl_value(b.prl_rebate.as_ref()),
        tr!("to your prl1p address", "到你的 prl1p 地址"),
    ));

    // Bucket 3 — ALICE (real token).
    out.push_str(&format!(
        "\n  {}\n      {}\n",
        tr!("ALICE (real token)", "ALICE 真代币"),
        alice.human(),
    ));

    out.push_str(&format!("  {}\n", "─".repeat(60)));
    // The honest framing footer (credit ≠ fiat; PRL is real returned crypto; ALICE is
    // the real token, pending launch).
    out.push_str(&format!(
        "  {}\n\n",
        tr!(
            "credit is credit-only (not cash); PRL is real returned crypto; ALICE is the real token (pending launch).",
            "积分仅为积分(非现金);PRL 是真实返还的加密货币;ALICE 是真代币(待上线)。"
        ),
    ));
    out
}

/// Render the offline / read-API-unreachable case: the ALICE-token bucket we CAN
/// honestly state, plus a clear "couldn't reach" note for the two read-model buckets.
fn render_offline(address: &str, err: &str, alice: &AliceToken) -> String {
    let mut out = String::new();
    out.push_str(&format!("\n  {} {}\n", tr!("Balance for", "余额:"), address));
    out.push_str(&format!("  {}\n", "─".repeat(60)));
    let unreachable = tr!(
        "couldn't reach the read API — try again",
        "无法连接读取 API — 请稍后重试"
    );
    out.push_str(&format!(
        "  {}: {}\n",
        tr!("Credit (积分)", "积分 Credit"),
        unreachable
    ));
    out.push_str(&format!(
        "  {}: {}\n",
        tr!("PRL rebate (real PRL)", "PRL 返现(真 PRL)"),
        unreachable
    ));
    out.push_str(&format!(
        "  {}: {}\n",
        tr!("ALICE (real token)", "ALICE 真代币"),
        alice.human()
    ));
    out.push_str(&format!("  {}\n", "─".repeat(60)));
    // The transport reason goes to a dim detail line (never a secret — it's a URL/DNS
    // error at most).
    out.push_str(&format!("  ({err})\n\n"));
    out
}

/// Print the `--json` object: the three buckets with the SAME honesty (nulls where
/// unknown; never a fabricated number). A transport failure emits a well-formed
/// object noting the error.
fn print_json(address: &str, lookup: &Result<BalanceLookup, String>, alice: &AliceToken) {
    let credit_json = match lookup {
        Ok(b) => credit_json(&b.credit),
        Err(_) => serde_json::json!({ "state": "unreachable", "shares_total": null, "shares_24h": null }),
    };
    let prl_json = match lookup {
        Ok(b) => prl_json(b.prl_rebate.as_ref()),
        Err(_) => serde_json::json!({ "state": "unreachable", "bound": null }),
    };
    // The ALICE token bucket is always the honest pending state today: amount is null
    // (never fabricated), with a machine `state` the consumer can branch on.
    let alice_json = serde_json::json!({
        "amount": serde_json::Value::Null,
        "state": "pending_real_money_launch",
        "chain_rpc_configured": matches!(alice, AliceToken::PendingWithRpc),
    });
    let obj = serde_json::json!({
        "ok": lookup.is_ok(),
        "address": address,
        "credit": credit_json,
        "prl_rebate": prl_json,
        "alice_token": alice_json,
        "error": lookup.as_ref().err(),
    });
    println!("{}", serde_json::to_string_pretty(&obj).unwrap_or_default());
}

/// The credit bucket as JSON (credit-only counts; nulls where not confirmed).
fn credit_json(credit: &CreditState) -> serde_json::Value {
    match credit {
        CreditState::Confirmed { totals, .. } => serde_json::json!({
            "state": "confirmed",
            "shares_total": totals.accepted_total,
            "shares_24h": totals.accepted_24h,
            "note": "credit-only; converts to ALICE at real-money launch",
        }),
        CreditState::Confirming => serde_json::json!({
            "state": "syncing", "shares_total": null, "shares_24h": null
        }),
        CreditState::NotExposed => serde_json::json!({
            "state": "not_exposed", "shares_total": null, "shares_24h": null
        }),
        CreditState::Error { reason } => serde_json::json!({
            "state": "error", "reason": format!("{reason:?}"), "shares_total": null, "shares_24h": null
        }),
    }
}

/// The PRL-rebate bucket as JSON (binding + accrual state; NO fabricated amount).
fn prl_json(prl: Option<&PrlRebateView>) -> serde_json::Value {
    match prl {
        None => serde_json::json!({ "state": "no_accrual", "bound": false, "amount": null }),
        Some(v) => serde_json::json!({
            "state": "accruing",
            "bound": v.bound,
            "payout_address_fingerprint": v.payout_address_fingerprint,
            "rebate_pct": v.rebate_pct,
            "status": v.status,
            // The real PRL amount is null: payout is gated OFF (credit-only) — never fabricated.
            "amount": serde_json::Value::Null,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alice_miner_core::i18n::{set_lang, Lang};
    use alice_miner_core::{CreditScore, CreditTotals};

    /// These tests mutate the PROCESS-GLOBAL UI language, so they must not run
    /// concurrently (Rust runs a crate's tests in parallel). Funnel them through one
    /// mutex + set the language while holding it. Returns the guard so the caller keeps
    /// the lock for the duration of the test.
    fn lang_guard(l: Lang) -> std::sync::MutexGuard<'static, ()> {
        static LANG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let g = LANG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_lang(l);
        g
    }

    fn confirmed(total: u64, h24: u64) -> CreditState {
        CreditState::Confirmed {
            score: CreditScore::new(0.0),
            totals: CreditTotals {
                accepted_total: total,
                accepted_24h: h24,
                pending_credit: 0.0,
                paid_credit: 0.0,
                lanes: vec![],
            },
        }
    }

    /// The credit bucket renders the cumulative COUNT (credit-only) — never a `$`/paid.
    #[test]
    fn credit_value_is_credit_only_count() {
        let _g = lang_guard(Lang::En);
        let s = credit_value(&confirmed(873, 142));
        assert!(s.contains("873"), "{s}");
        assert!(s.contains("142"), "24h count: {s}");
        let lower = s.to_lowercase();
        for forbidden in ["$", "usd", "paid", "earned"] {
            assert!(!lower.contains(forbidden), "credit leaked `{forbidden}`: {s}");
        }
    }

    /// A bound PRL rebate shows the accrual + fingerprint, and NEVER a fabricated amount.
    #[test]
    fn prl_value_bound_shows_state_not_amount() {
        let _g = lang_guard(Lang::En);
        let v = PrlRebateView {
            bound: true,
            payout_address_fingerprint: Some("prlfp_ab12".into()),
            rebate_pct: Some(15.0),
            status: Some("accruing".into()),
        };
        let s = prl_value(Some(&v));
        assert!(s.contains("bound"), "{s}");
        assert!(s.contains("accruing"), "{s}");
        assert!(s.contains("prlfp_ab12"), "shows fingerprint not raw prl1p: {s}");
        assert!(s.contains("15%"), "{s}");
        // No fabricated amount: the "off" marker is present, no fake number.
        assert!(s.contains("payout off") || s.contains("off"), "{s}");
    }

    /// An unbound rebate nudges the user to set a prl1p return address.
    #[test]
    fn prl_value_unbound_nudges_enrollment() {
        let _g = lang_guard(Lang::En);
        let v = PrlRebateView { bound: false, ..Default::default() };
        let s = prl_value(Some(&v));
        assert!(s.contains("not bound"), "{s}");
        assert!(s.to_lowercase().contains("prl1p"), "nudge mentions prl1p: {s}");
    }

    /// The ALICE-token bucket is ALWAYS the honest pending state today (no fabricated
    /// number), in both env states.
    #[test]
    fn alice_token_is_honest_pending() {
        let _g = lang_guard(Lang::En);
        assert!(AliceToken::Pending.human().starts_with('0'));
        assert!(AliceToken::Pending.human().contains("not yet enabled"));
        assert!(AliceToken::PendingWithRpc.human().contains("chain RPC configured"));
    }

    /// The full render carries all three bucket headers + the honest-framing footer,
    /// and never a `$`/paid/earned anywhere.
    #[test]
    fn render_has_three_buckets_and_no_fiat() {
        let _g = lang_guard(Lang::En);
        let b = BalanceLookup {
            credit: confirmed(10, 10),
            prl_rebate: Some(PrlRebateView {
                bound: false,
                ..Default::default()
            }),
            found: true,
        };
        let out = render_balance("a2xTEST", &b, &AliceToken::Pending);
        assert!(out.contains("Credit (积分)"));
        assert!(out.contains("PRL rebate (real PRL)"));
        assert!(out.contains("ALICE (real token)"));
        assert!(out.contains("credit-only"));
        let lower = out.to_lowercase();
        for forbidden in ["$", "usd", " paid ", "earned"] {
            assert!(!lower.contains(forbidden), "render leaked `{forbidden}`");
        }
    }

    /// The Chinese variant renders localized bucket labels (tr! honored).
    #[test]
    fn render_localizes_to_chinese() {
        let _g = lang_guard(Lang::Zh);
        let b = BalanceLookup {
            credit: confirmed(5, 5),
            prl_rebate: None,
            found: true,
        };
        let out = render_balance("a2xTEST", &b, &AliceToken::Pending);
        assert!(out.contains("积分"), "zh credit label: {out}");
        assert!(out.contains("真代币"), "zh ALICE label: {out}");
        set_lang(Lang::En);
    }
}
