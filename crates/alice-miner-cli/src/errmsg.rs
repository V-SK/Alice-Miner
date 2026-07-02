//! `errmsg` — a small, consistent error-rendering helper for the headless CLI.
//!
//! The problem it solves: the highest-traffic user-facing failures (an engine that
//! won't launch, no usable GPU, an unreachable pool/relay, a PoP handshake failure)
//! reach the user as a RAW technical string from deep in the engine — often English-
//! only, jargon-heavy, and with no next step. This helper gives every such failure a
//! CONSISTENT, bilingual shape:
//!
//! ```text
//!   <what happened, one plain line>
//!     → <what to do, one actionable line>
//! ```
//!
//! and, ONLY when `ALICE_MINER_VERBOSE=1`, a third line with the raw technical detail
//! for a bug report / support:
//!
//! ```text
//!     detail: <the raw engine string>
//! ```
//!
//! It never fabricates: an unrecognized error still renders (a generic "something went
//! wrong" + "run `alice-miner doctor`") with the raw detail behind VERBOSE, so no
//! information is lost. Credit-only + secret-free by construction — it only ever
//! reshapes a string the engine already sanitized (it adds no host/pool/address).

use alice_miner_core::tr;

/// Whether the raw technical detail should be appended (gated on `ALICE_MINER_VERBOSE=1`).
/// Any other value (or unset) hides it behind the clean two-line message.
fn verbose() -> bool {
    std::env::var("ALICE_MINER_VERBOSE")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

/// A classified failure: a plain "what happened" line + an actionable "what to do" line
/// (both localized). The raw detail is carried separately so it can be gated on VERBOSE.
struct Classified {
    what: String,
    action: String,
}

/// Render a raw engine/CLI error string into the consistent bilingual shape (see the
/// module docs). The raw `detail` is appended ONLY under `ALICE_MINER_VERBOSE=1`.
///
/// This is the single entry point the CLI's high-traffic failure sites route through so
/// they read identically. It is pure over `(raw, lang, verbose-env)` and never panics.
pub fn render_error(raw: &str) -> String {
    let c = classify(raw);
    let mut out = format!("{}\n    → {}", c.what, c.action);
    if verbose() && !raw.trim().is_empty() {
        out.push_str(&format!("\n    {}: {}", tr!("detail", "详情"), raw.trim()));
    }
    out
}

/// Classify a raw error string into a bilingual (what happened, what to do) pair by
/// matching the known high-traffic failure signatures. Order matters — the most
/// specific signatures are checked first; an unrecognized string falls through to a
/// safe generic that still points at `doctor`.
fn classify(raw: &str) -> Classified {
    let lower = raw.to_ascii_lowercase();

    // No reward identity / address (the very first thing a fresh user hits).
    if lower.contains("no reward address") || lower.contains("no reward identity") {
        return Classified {
            what: tr!(
                "No reward identity yet — mining has nowhere to send your credit.",
                "尚无奖励身份 — 挖矿没有可发放积分的去向。"
            )
            .into(),
            action: tr!(
                "create one: `alice-miner identity --create` (or `--paste <address>` for watch-only).",
                "请创建一个: `alice-miner identity --create`(或 `--paste <地址>` 用于仅观察)。"
            )
            .into(),
        };
    }

    // Watch-only identity used for a lane that needs the signing key (PoP).
    if lower.contains("watch-only") {
        return Classified {
            what: tr!(
                "This identity is watch-only (an address with no signing key), so it cannot prove key possession for this lane.",
                "此身份为仅观察(只有地址、没有签名密钥),因此无法为此通道证明密钥所有权。"
            )
            .into(),
            action: tr!(
                "import the mnemonic/seed for this address (`alice-miner identity --import`), or mine the CPU-XMR lane (address-only).",
                "请导入该地址的助记词/种子(`alice-miner identity --import`),或改挖 CPU-XMR 通道(仅需地址)。"
            )
            .into(),
        };
    }

    // PoP / proof-of-possession handshake failure (the pearlhash credit gate).
    if lower.contains("pop") || lower.contains("proof-of-possession") || lower.contains("proof of possession") {
        return Classified {
            what: tr!(
                "Proof-of-possession could not be established, so the relay would not credit this lane.",
                "无法完成密钥所有权证明(PoP),因此中继不会为此通道计入积分。"
            )
            .into(),
            action: tr!(
                "check your wallet password and network, then retry; run `alice-miner doctor` to test relay reachability.",
                "请检查钱包密码和网络后重试;运行 `alice-miner doctor` 测试中继可达性。"
            )
            .into(),
        };
    }

    // GPU-not-found / unrunnable GPU lane (compute-capability, no CUDA card, no binary).
    if (lower.contains("gpu") || lower.contains("cuda") || lower.contains("compute capability"))
        && (lower.contains("no ")
            || lower.contains("not ")
            || lower.contains("can't run")
            || lower.contains("cannot run")
            || lower.contains("unsupported")
            || lower.contains("below"))
    {
        return Classified {
            what: tr!(
                "No usable GPU for this lane (or the card can't run this engine).",
                "此通道没有可用的 GPU(或该显卡无法运行此引擎)。"
            )
            .into(),
            action: tr!(
                "run `alice-miner detect` to see supported lanes; a Volta/V100 uses `--lane alpha`, and CPU-XMR always works.",
                "运行 `alice-miner detect` 查看支持的通道;Volta/V100 请用 `--lane alpha`,CPU-XMR 始终可用。"
            )
            .into(),
        };
    }

    // Engine launch / spawn failure (binary missing, not executable, quarantined).
    if lower.contains("failed to start miner")
        || lower.contains("could not start")
        || lower.contains("spawn")
        || lower.contains("no such file")
        || lower.contains("is not available")
        || lower.contains("permission denied")
    {
        return Classified {
            what: tr!(
                "The mining engine could not be launched.",
                "无法启动挖矿引擎。"
            )
            .into(),
            action: tr!(
                "run `alice-miner doctor` (it re-checks the engine); `doctor --fix` can re-download a missing/corrupt engine. On Windows, allow the engine in Defender.",
                "运行 `alice-miner doctor`(它会重新检查引擎);`doctor --fix` 可重新下载缺失/损坏的引擎。Windows 上请在 Defender 中放行引擎。"
            )
            .into(),
        };
    }

    // Pool / relay / network reachability (DNS, connect timeout, firewall).
    if lower.contains("relay")
        || lower.contains("pool")
        || lower.contains("connect")
        || lower.contains("network")
        || lower.contains("dns")
        || lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("unreachable")
        || lower.contains("refused")
    {
        return Classified {
            what: tr!(
                "Could not reach the mining relay (a network / firewall issue).",
                "无法连接到挖矿中继(网络 / 防火墙问题)。"
            )
            .into(),
            action: tr!(
                "check your connection and firewall (the stratum port must be reachable outbound); a VPN or captive portal can block it. `alice-miner doctor` tests this.",
                "请检查网络连接和防火墙(stratum 端口必须可出站访问);VPN 或强制门户网络可能拦截它。`alice-miner doctor` 可测试此项。"
            )
            .into(),
        };
    }

    // Fallthrough: unrecognized — still give a consistent, actionable shape (never a
    // bare dump). The raw detail is available under VERBOSE for a bug report.
    Classified {
        what: tr!(
            "Something went wrong while mining.",
            "挖矿过程中出现问题。"
        )
        .into(),
        action: tr!(
            "run `alice-miner doctor` for a full diagnostic; re-run with ALICE_MINER_VERBOSE=1 to see the technical detail.",
            "运行 `alice-miner doctor` 查看完整诊断;设置 ALICE_MINER_VERBOSE=1 重新运行可查看技术详情。"
        )
        .into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A serialized env guard so the VERBOSE-toggling tests don't race each other (the
    /// crate runs its tests in parallel and they mutate a PROCESS-GLOBAL env var).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_verbose<T>(on: bool, f: impl FnOnce() -> T) -> T {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if on {
            std::env::set_var("ALICE_MINER_VERBOSE", "1");
        } else {
            std::env::remove_var("ALICE_MINER_VERBOSE");
        }
        let out = f();
        std::env::remove_var("ALICE_MINER_VERBOSE");
        out
    }

    /// Every classified message has the two-line "what · → action" shape, and the raw
    /// detail is HIDDEN by default (no VERBOSE).
    #[test]
    fn renders_two_line_shape_and_hides_detail_by_default() {
        with_verbose(false, || {
            let raw = "failed to start miner: No such file or directory (os error 2)";
            let msg = render_error(raw);
            assert!(msg.contains("→"), "has an action arrow: {msg}");
            assert!(msg.lines().count() == 2, "exactly what + action (no detail): {msg}");
            // The raw technical string is NOT shown without VERBOSE.
            assert!(!msg.contains("os error 2"), "raw detail hidden by default: {msg}");
        });
    }

    /// Under ALICE_MINER_VERBOSE=1 the raw detail line is appended.
    #[test]
    fn verbose_appends_raw_detail() {
        with_verbose(true, || {
            let raw = "failed to start miner: No such file or directory (os error 2)";
            let msg = render_error(raw);
            assert!(msg.contains("os error 2"), "raw detail shown under VERBOSE: {msg}");
            assert!(msg.to_lowercase().contains("detail") || msg.contains("详情"), "labelled: {msg}");
        });
    }

    /// The high-traffic signatures each classify to their intended category.
    #[test]
    fn classifies_the_high_traffic_failures() {
        with_verbose(false, || {
            // Engine launch.
            assert!(render_error("failed to start miner: permission denied")
                .to_lowercase()
                .contains("engine"));
            // GPU not found / unrunnable.
            assert!(render_error("GPU-PRL (SRBMiner) can't run on this GPU: CC 7.0 below 7.5")
                .to_lowercase()
                .contains("gpu"));
            // Pool / network.
            let net = render_error("cannot reach the relay hk.aliceprotocol.org:3333: connection refused");
            assert!(net.to_lowercase().contains("relay") || net.to_lowercase().contains("network"));
            // PoP.
            assert!(render_error("could not establish PoP for region us")
                .to_lowercase()
                .contains("possession") || render_error("could not establish PoP for region us").contains("PoP"));
            // No identity.
            assert!(render_error("no reward address: create/import/paste an identity first")
                .to_lowercase()
                .contains("identity"));
        });
    }

    /// An unrecognized error still renders the consistent shape (never a bare dump) and
    /// points at `doctor`.
    #[test]
    fn unknown_error_falls_through_to_a_safe_generic() {
        with_verbose(false, || {
            let msg = render_error("some entirely novel failure 0xdeadbeef");
            assert!(msg.contains("→"), "still has an action: {msg}");
            assert!(msg.contains("doctor"), "points at doctor: {msg}");
            // The novel raw string is not leaked without VERBOSE.
            assert!(!msg.contains("0xdeadbeef"), "raw hidden by default: {msg}");
        });
    }

    /// Credit-only + secret-free: the rendered message never introduces a fiat/paid
    /// token (it only reshapes an already-sanitized engine string).
    #[test]
    fn rendered_error_is_credit_only() {
        with_verbose(false, || {
            for raw in [
                "failed to start miner: x",
                "cannot reach the relay: timeout",
                "no reward address",
            ] {
                let low = render_error(raw).to_lowercase();
                for forbidden in ["$", "usd", "paid", "earned", "payout"] {
                    assert!(!low.contains(forbidden), "leaked `{forbidden}`: {low}");
                }
            }
        });
    }
}
