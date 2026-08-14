//! `engines` — which mining engine this client will run, and on whose word.
//!
//! `alice-miner engines [--check] [--json]`
//!
//! The engine is a third-party binary (SRBMiner-MULTI, XMRig, alpha-miner) that we
//! fetch and exec. Two honest questions follow from that, and this command answers
//! both without the user having to read source:
//!
//!   * **Which bytes?** — the pinned SHA-256, the upstream version, and whether
//!     those exact bytes are present and verified in the engine cache right now.
//!   * **On whose word?** — either the pin table compiled into this client, or a
//!     signed engine-pin list (with its epoch), plus the upstream release URL and
//!     when we endorsed it. Endorsement is a human decision recorded in
//!     `ENGINE-TRUST-LOG.md`; this is its receipt.
//!
//! `--check` forces the pin refresh now instead of waiting for the 6-hourly
//! background check — the "an upstream fork just happened, pull the new pin"
//! button. It reports exactly what happened, including the boring outcomes
//! (nothing new; could not reach the list), and never claims success it did not
//! get.

use alice_miner_core::alice_release;
use alice_miner_core::engine_pins::{self, RefreshOutcome};
use alice_miner_core::tr;

use crate::{EXIT_OK, EXIT_RUNTIME};

/// `alice-miner engines` arguments.
#[derive(clap::Args)]
pub struct EnginesArgs {
    /// Check for a newer signed engine-pin list right now (instead of waiting for
    /// the background check). Downloads + verifies the new engine before it takes
    /// effect; a failure leaves the current engine exactly as it is.
    #[arg(long)]
    pub check: bool,
    /// Emit the engine pins as one JSON object (machine-readable).
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: EnginesArgs) -> i32 {
    let refresh = if args.check {
        Some(engine_pins::refresh_now())
    } else {
        None
    };
    let pins = engine_pins::status_for_current_platform();
    let state = engine_pins::load_state();
    let doc = engine_pins::active_doc();

    if args.json {
        let payload = serde_json::json!({
            "pins": pins,
            "list_epoch": doc.as_ref().map(|d| d.epoch),
            "list_issued": doc.as_ref().map(|d| d.issued.clone()),
            "list_url": alice_release::engines_url(),
            "remote_pins_enabled": alice_release::engine_pin_key_status().is_ok(),
            "last_checked_unix": state.last_check_unix,
            "last_ok_unix": state.last_ok_unix,
            "last_error": state.last_error,
            "checked_now": refresh.as_ref().map(describe),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );
        return match refresh {
            Some(o) if o.is_problem() => EXIT_RUNTIME,
            _ => EXIT_OK,
        };
    }

    println!("{}", tr!("Mining engines", "挖矿引擎"));
    println!();
    if pins.is_empty() {
        println!(
            "  {}",
            tr!(
                "no engine is pinned for this platform — no lane can run here.",
                "此平台没有任何被固定校验的引擎 —— 本机无法运行任何通道。"
            )
        );
    }
    for p in &pins {
        let version = p
            .version
            .clone()
            .unwrap_or_else(|| tr!("unknown", "未知").to_string());
        println!("  {}  {} {}", p.kind, p.engine, version);
        println!("    {} {}", tr!("pinned sha256:", "固定 sha256:"), p.sha256);
        println!("    {} {}", tr!("pin source:  ", "pin 来源:  "), p.source);
        if let Some(url) = &p.source_url {
            println!("    {} {url}", tr!("upstream:     ", "上游:      "));
        }
        if let Some(at) = &p.endorsed_at {
            let by = p.endorsed_by.clone().unwrap_or_default();
            println!("    {} {at} {by}", tr!("endorsed:     ", "背书时间:  "));
        }
        println!(
            "    {} {}",
            tr!("on this machine:", "本机状态:"),
            if p.installed {
                tr!("installed and verified", "已安装并校验通过")
            } else {
                tr!(
                    "not downloaded yet (fetched + verified on first use)",
                    "尚未下载(首次使用时下载并校验)"
                )
            }
        );
        println!();
    }

    match &doc {
        Some(d) => println!(
            "  {} {} ({} {})",
            tr!("engine pin list:", "引擎 pin 清单:"),
            format_args!("epoch {}", d.epoch),
            tr!("issued", "签发于"),
            d.issued
        ),
        None => println!(
            "  {}",
            match alice_release::engine_pin_key_status() {
                Ok(()) => tr!(
                    "engine pin list: none active — using the pins built into this client.",
                    "引擎 pin 清单:当前无生效清单 —— 使用本客户端内置的 pin。"
                )
                .to_string(),
                Err(why) => format!(
                    "{} {why}",
                    tr!("engine pin list: disabled —", "引擎 pin 清单:未启用 ——")
                ),
            }
        ),
    }
    if let Some(err) = &state.last_error {
        println!("  {} {err}", tr!("last problem:", "上次问题:"));
    }
    if let Some(outcome) = &refresh {
        println!();
        println!("  {} {}", tr!("check:", "检查:"), describe(outcome));
    }

    match refresh {
        Some(o) if o.is_problem() => EXIT_RUNTIME,
        _ => EXIT_OK,
    }
}

/// One honest line per outcome — including the ones that are not good news.
fn describe(outcome: &RefreshOutcome) -> String {
    match outcome {
        RefreshOutcome::Disabled(why) => format!(
            "{} {why}",
            tr!(
                "remote engine pins are off in this build:",
                "此构建未启用远端引擎 pin:"
            )
        ),
        RefreshOutcome::Updated { epoch, changed } if changed.is_empty() => format!(
            "{} {epoch} ({})",
            tr!(
                "updated to engine pin list epoch",
                "已更新到引擎 pin 清单 epoch"
            ),
            tr!("no engine change on this platform", "本平台引擎无变化")
        ),
        RefreshOutcome::Updated { epoch, changed } => format!(
            "{} {epoch}: {} — {}",
            tr!(
                "updated to engine pin list epoch",
                "已更新到引擎 pin 清单 epoch"
            ),
            changed.join(", "),
            tr!(
                "downloaded and verified; it takes effect the next time a lane starts",
                "已下载并校验通过;下次通道启动时生效"
            )
        ),
        RefreshOutcome::Unchanged { epoch } => format!(
            "{} {epoch}",
            tr!(
                "already on engine pin list epoch",
                "已经是引擎 pin 清单 epoch"
            )
        ),
        RefreshOutcome::Deferred(why) => format!(
            "{} {why}",
            tr!(
                "could not complete the check; the current engine is unchanged —",
                "本次检查未能完成;当前引擎未改变 ——"
            )
        ),
        RefreshOutcome::Rejected(why) => format!(
            "{} {why}",
            tr!(
                "REFUSED the published engine pin list; the current engine is unchanged —",
                "已拒绝已发布的引擎 pin 清单;当前引擎未改变 ——"
            )
        ),
    }
}
