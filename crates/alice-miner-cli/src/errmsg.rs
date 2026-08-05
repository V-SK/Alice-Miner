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
//!       1. <optional numbered self-check steps>
//! ```
//!
//! and, ONLY when `ALICE_MINER_VERBOSE=1`, a final line with the raw technical detail
//! for a bug report / support:
//!
//! ```text
//!     detail: <the raw engine string>
//! ```
//!
//! ## The rule this module exists to enforce: never guess a cause
//!
//! Up to v0.6.7 EVERY control-plane failure whose text mentioned `/m4/` (or `enroll`,
//! or `challenge`) was rendered as *"the (address, device) pair was not allow-listed"*.
//! That sentence names a SERVER-SIDE authorization decision — but the same code path
//! produces it for a DNS failure, a refused TCP connect, and (the field case that cost
//! a day) an HTTPS connection that a corporate firewall / antivirus HTTPS-scanner
//! terminated before it ever reached us. A miner whose machine could not open a socket
//! was told his account was not approved, and we went looking at relay config.
//!
//! So classification is now TWO stages:
//!
//! 1. [`wire_outcome`] answers *how far did the request actually get?* — purely from
//!    signatures the transport itself emits. It has an explicit [`Wire::Unknown`]
//!    variant, and when it returns that we SAY we cannot tell instead of inventing a
//!    reason.
//! 2. Only once the wire outcome is known do we allow a business-layer sentence. An
//!    HTTP status is the ONLY proof that the server actually answered, so "the server
//!    refused you" is reachable only from [`Wire::Status`].
//!
//! It never fabricates: an unrecognized error still renders (a generic "something went
//! wrong" + "run `alice-miner doctor`") with the raw detail behind VERBOSE, so no
//! information is lost. Credit-only + secret-free by construction — it only ever
//! reshapes a string the engine already sanitized, and the ONLY things it ever echoes
//! back out of the raw string are a 3-digit HTTP status and a strictly-sanitized
//! `reason_code` (never a host, URL, address, or response body).

use alice_miner_core::alice_release::tls::{classify_preflight_error, PreflightOutcome};
use alice_miner_core::tr;

/// Whether the raw technical detail should be appended (gated on `ALICE_MINER_VERBOSE=1`).
/// Any other value (or unset) hides it behind the clean two-line message.
fn verbose() -> bool {
    std::env::var("ALICE_MINER_VERBOSE")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

/// A classified failure: a plain "what happened" line + an actionable "what to do" line
/// (both localized), plus optional numbered self-check steps. The raw detail is carried
/// separately so it can be gated on VERBOSE.
struct Classified {
    what: String,
    action: String,
    /// Numbered self-check steps, rendered under the action. Usually empty — reserved
    /// for the failures where the user genuinely has to try things in order.
    steps: Vec<String>,
}

impl Classified {
    fn new(what: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            what: what.into(),
            action: action.into(),
            steps: Vec::new(),
        }
    }

    fn with_steps(mut self, steps: Vec<String>) -> Self {
        self.steps = steps;
        self
    }
}

/// **How far the request actually got.** Derived ONLY from signatures the transport
/// emits, never from what the caller hoped the request was doing. The whole point of
/// the enum is [`Wire::Unknown`]: an honest "we cannot tell" beats a plausible lie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wire {
    /// The server answered with an HTTP status. This is the ONLY outcome that proves
    /// DNS, TCP **and** the TLS certificate chain all succeeded — we reached the
    /// application layer. Any "the server rejected you" sentence requires this.
    Status(u16),
    /// The TLS handshake or certificate-chain validation failed: the request was
    /// terminated by something between this machine and us, and never arrived.
    TlsBlocked,
    /// DNS, TCP connect, or a read timed out / was refused — the bytes never landed.
    Unreachable,
    /// Bytes came back, but they are not the protocol we speak (a captive portal or
    /// filtering proxy answering in our place looks exactly like this).
    Undecodable,
    /// Nothing in the string says where it failed. We report exactly that.
    Unknown,
}

/// Render a raw engine/CLI error string into the consistent bilingual shape (see the
/// module docs). The raw `detail` is appended ONLY under `ALICE_MINER_VERBOSE=1`.
///
/// This is the single entry point the CLI's high-traffic failure sites route through so
/// they read identically. It is pure over `(raw, lang, verbose-env)` and never panics.
pub fn render_error(raw: &str) -> String {
    let c = classify(raw);
    let mut out = format!("{}\n    → {}", c.what, c.action);
    for (i, step) in c.steps.iter().enumerate() {
        out.push_str(&format!("\n      {}. {}", i + 1, step));
    }
    if verbose() && !raw.trim().is_empty() {
        out.push_str(&format!("\n    {}: {}", tr!("detail", "详情"), raw.trim()));
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Stage 1 — the wire outcome (how far did it get?)
// ─────────────────────────────────────────────────────────────────────────────

/// Pull a 3-digit HTTP status out of the two shapes our HTTP helpers produce:
/// `…: HTTP 403: <body>` (`shard.rs` / `train_worker.rs`, which read the body) and
/// ureq's own `Error::Status` display `…: status code 403` (`pop.rs`).
///
/// Deliberately narrow: `http ` requires the trailing space, so the `https://` in
/// every URL can never be mistaken for a status.
fn http_status(lower: &str) -> Option<u16> {
    for marker in ["http ", "status code "] {
        let mut from = 0usize;
        while let Some(at) = lower[from..].find(marker) {
            let start = from + at + marker.len();
            let digits: String = lower[start..]
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .take(3)
                .collect();
            if digits.len() == 3 {
                if let Ok(code) = digits.parse::<u16>() {
                    if (100..=599).contains(&code) {
                        return Some(code);
                    }
                }
            }
            from = start;
        }
    }
    None
}

/// `true` when the string carries a signature of a failed TLS handshake / certificate
/// chain. Delegates the certificate half to [`classify_preflight_error`] — the SAME
/// predicate `doctor`'s TLS preflight uses, so the two can never disagree about what a
/// trust failure looks like — and adds the two rustls-init phrases ureq emits.
///
/// Note the deliberately narrow `tls handshake`: our OWN copy says "handshake" about
/// the PoP challenge exchange, so a bare `handshake` token would re-create exactly the
/// mislabelling this module exists to remove.
fn looks_like_tls(lower: &str) -> bool {
    matches!(
        classify_preflight_error(lower),
        PreflightOutcome::TlsUntrusted(_)
    ) || lower.contains("tls connection creation failed")
        || lower.contains("tls handshake")
}

/// `true` when the string says the bytes never reached the server (name resolution,
/// TCP connect, or a timeout). Checked only AFTER [`http_status`] and [`looks_like_tls`],
/// so a server-supplied body containing the word "refused" cannot hijack it.
fn looks_unreachable(lower: &str) -> bool {
    [
        "dns failed",
        "dns resolution failed",
        "failed to lookup address",
        "temporary failure in name resolution",
        "name or service not known",
        "nodename nor servname",
        "connection failed",
        "connection refused",
        "connection reset",
        "connection aborted",
        "connect error",
        "network error",
        "network is unreachable",
        "no route to host",
        "unreachable",
        "timed out",
        "timeout",
        "refused",
        "os error 11001", // Windows WSAHOST_NOT_FOUND
        "os error 10060", // Windows WSAETIMEDOUT
        "os error 10061", // Windows WSAECONNREFUSED
    ]
    .iter()
    .any(|t| lower.contains(t))
}

/// `true` when we got a reply we cannot decode — our JSON parse failed, or the payload
/// was well-formed JSON but missing the fields the protocol requires.
fn looks_undecodable(lower: &str) -> bool {
    [
        "parse http",
        "expected value",
        "eof while parsing",
        "invalid type",
        "key must be a string",
        "missing challenge_nonce",
        "missing enroll_nonce",
        "had empty challenge_id",
        "had empty nonce",
        "response missing",
        "response had empty",
    ]
    .iter()
    .any(|t| lower.contains(t))
}

/// Classify **how far the request got**, from the transport's own signatures.
///
/// Order is load-bearing and each step is justified:
///   1. an HTTP status proves the whole stack (DNS + TCP + TLS) worked, so it wins;
///   2. otherwise a TLS signature means we were cut off mid-handshake;
///   3. otherwise a connect/DNS/timeout signature means we never arrived;
///   4. otherwise a decode failure means something answered but not us;
///   5. otherwise — and this is the point — [`Wire::Unknown`].
fn wire_outcome(lower: &str) -> Wire {
    if let Some(code) = http_status(lower) {
        return Wire::Status(code);
    }
    if looks_like_tls(lower) {
        return Wire::TlsBlocked;
    }
    if looks_unreachable(lower) {
        return Wire::Unreachable;
    }
    if looks_undecodable(lower) {
        return Wire::Undecodable;
    }
    Wire::Unknown
}

/// The three region hosts a miner must be able to reach, named in the firewall-allow
/// step. Static text, no secrets.
const REGION_HOSTS_HINT: &str = "us.aliceprotocol.org, asia.aliceprotocol.org, eu.aliceprotocol.org";

/// Extract a server-supplied `reason_code` (or `error` / `code` / `detail`) from a JSON
/// error body and sanitize it hard: ASCII alphanumerics, `_`, `-`, `.` and spaces only,
/// capped at 64 chars. Anything else yields `None` rather than echoing a server string
/// verbatim into the user's terminal (that is also the AM-SEC-007 rule).
fn server_reason(raw: &str) -> Option<String> {
    for key in ["\"reason_code\"", "\"reason\"", "\"error\"", "\"detail\"", "\"code\""] {
        let Some(at) = raw.find(key) else { continue };
        let rest = &raw[at + key.len()..];
        let Some(colon) = rest.find(':') else { continue };
        let after = rest[colon + 1..].trim_start();
        let Some(stripped) = after.strip_prefix('"') else { continue };
        let Some(end) = stripped.find('"') else { continue };
        let value = stripped[..end].trim();
        if value.is_empty() || value.len() > 64 {
            continue;
        }
        if value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' '))
        {
            return Some(value.to_string());
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Stage 2 — the user-facing sentence
// ─────────────────────────────────────────────────────────────────────────────

/// `true` when the failure came from the **control plane** — the HTTPS endpoints that
/// enroll an `(address, device)` pair: `/m4/challenge`, `/m4/verify`, the shard-stage
/// and training register/lease routes, plus the wording the `ai` / `train` call sites
/// prepend. These are the failures the old code blanket-labelled "not allow-listed".
///
/// The tokens are chosen to never appear in a GPU / engine / stratum error — in
/// particular `register` is NOT a token, because CUDA says "too many registers used".
fn touches_control_plane(lower: &str) -> bool {
    lower.contains("/m4/")
        || lower.contains("enroll")
        || lower.contains("allowlist")
        || lower.contains("allow-list")
        || lower.contains("code:24")
        || lower.contains("challenge")
        || lower.contains("/v1/shard/")
        || lower.contains("/v1/train/")
}

/// A LOCAL configuration mistake on the control plane — no request was ever made, so
/// neither "network" nor "not allow-listed" would be true.
fn classify_bad_config() -> Classified {
    Classified::new(
        tr!(
            "The relay / center address this client was told to use is not a valid https URL, so no request was sent.",
            "本客户端被指定的中继 / 中心地址不是合法的 https 地址,因此请求根本没有发出。"
        ),
        tr!(
            "this is a local configuration problem, not a network or account problem: check `--region` (us / asia / eu) and any ALICE_* URL overrides in your environment.",
            "这是本地配置问题,与网络或账号无关:请检查 `--region`(us / asia / eu)以及环境中的 ALICE_* 地址覆盖变量。"
        ),
    )
}

/// Render a control-plane failure ACCORDING TO ITS WIRE OUTCOME. Each arm states only
/// what that outcome actually establishes.
fn classify_control_plane(raw: &str, lower: &str) -> Classified {
    match wire_outcome(lower) {
        // ── (b) The handshake was cut off. The request NEVER reached us, so nothing
        // about the account/allowlist is known — and saying otherwise is the exact bug
        // this module was rewritten to remove.
        Wire::TlsBlocked => Classified::new(
            tr!(
                "The HTTPS connection to our server was intercepted or its certificate could not be verified, so the request never reached us. This is NOT an allow-list or account problem — we never saw it.",
                "与我们服务器之间的 HTTPS 连接被拦截,或证书无法通过验证,因此请求根本没有到达我们这里。这不是允许名单或账号问题 —— 我们从未收到它。"
            ),
            tr!(
                "something between this machine and us is terminating HTTPS (a company firewall, a router, or antivirus \"HTTPS scanning\"). A browser can still open our website because it trusts that interceptor; this client checks the certificate too. Try, in order:",
                "本机与我们之间有设备在中断 HTTPS(公司防火墙、路由器,或杀毒软件的 \"HTTPS 扫描\")。浏览器仍能打开我们的网站,是因为它信任该拦截设备;本客户端同样会校验证书。请按顺序尝试:"
            ),
        )
        .with_steps(vec![
            tr!(
                "retry once on a phone hotspot — if it works there, this network is the cause.",
                "改用手机热点重试一次 —— 如果热点下正常,原因就在当前网络。"
            )
            .into(),
            format!(
                "{} {REGION_HOSTS_HINT}{}",
                tr!(
                    "allow these hosts through the firewall / antivirus HTTPS scanner:",
                    "在防火墙 / 杀毒软件的 HTTPS 扫描中放行这些域名:"
                ),
                tr!(
                    " (or install its root CA into the SYSTEM certificate store).",
                    "(或把其根证书安装到\"系统\"证书库)。"
                )
            ),
            tr!(
                "pin one region explicitly: `--region us` (or `asia` / `eu`). `alice-miner doctor` prints the exact certificate error.",
                "用 `--region us`(或 `asia` / `eu`)显式指定区域。`alice-miner doctor` 会打印确切的证书错误。"
            )
            .into(),
        ]),

        // ── (a) Never got through at all.
        Wire::Unreachable => Classified::new(
            tr!(
                "Could not reach our server at all — the connection never got through (name lookup, connect, or timeout). Nothing is known about your allow-list status.",
                "完全联系不上我们的服务器 —— 连接没有建立(域名解析、连接或超时)。因此你的允许名单状态无从得知。"
            ),
            tr!(
                "check this machine is online and retry; `alice-miner doctor` tests DNS, TCP and HTTPS-certificate trust separately. If other sites work but this does not, a VPN, captive portal or firewall may be blocking outbound HTTPS to us.",
                "请确认这台机器能上网后重试;`alice-miner doctor` 会分别检测 DNS、TCP 与 HTTPS 证书信任。如果其它网站正常而这里不行,可能是 VPN、强制门户或防火墙拦截了到我们的出站 HTTPS。"
            ),
        ),

        // ── (c) The server ANSWERED. Only here may we speak about its decision — and
        // only 401/403 is an authorization decision.
        Wire::Status(code @ (401 | 403)) => {
            let reason = server_reason(raw);
            let what = match &reason {
                Some(r) => tr!(
                    format!("Our server answered and refused to enroll this (address, device) pair (HTTP {code}); the reason it gave: `{r}`. This lane would not be credited."),
                    format!("我们的服务器已应答,并拒绝为这对(地址,设备)注册(HTTP {code});服务端给出的原因:`{r}`。此通道不会计入积分。")
                ),
                None => tr!(
                    format!("Our server answered and refused to enroll this (address, device) pair (HTTP {code}), without giving a machine-readable reason. This lane would not be credited."),
                    format!("我们的服务器已应答,并拒绝为这对(地址,设备)注册(HTTP {code}),且未给出可解析的原因。此通道不会计入积分。")
                ),
            };
            Classified::new(
                what,
                tr!(
                    "the network is fine — this is an authorization decision. Check that the reward address is the one you enrolled and that its identity holds the signing key (import the mnemonic/seed if it is watch-only), then retry.",
                    "网络本身没有问题 —— 这是授权层面的拒绝。请确认奖励地址就是你注册的那个,且该身份持有签名密钥(若为仅观察请导入助记词/种子),然后重试。"
                ),
            )
        }

        Wire::Status(429) => Classified::new(
            tr!(
                "Our server answered and rate-limited this client (HTTP 429). This says nothing about your allow-list status.",
                "我们的服务器已应答,并对本客户端做了限流(HTTP 429)。这与你的允许名单状态无关。"
            ),
            tr!(
                "wait a minute and retry; if a whole fleet shares one IP, stagger the starts.",
                "请稍等一分钟后重试;若整个机群共用一个出口 IP,请把启动时间错开。"
            ),
        ),

        Wire::Status(code) if (500..=599).contains(&code) => Classified::new(
            tr!(
                format!("Our server answered with an error of its own (HTTP {code}) — the problem is on our side, not on this machine."),
                format!("我们的服务器返回了自身的错误(HTTP {code})—— 问题在我们这边,不在这台机器上。")
            ),
            tr!(
                "nothing to change locally; it will retry automatically. If it persists for more than a few minutes, report the HTTP code to support.",
                "本地无需改动,客户端会自动重试。若持续数分钟以上,请把该 HTTP 状态码反馈给支持。"
            ),
        ),

        Wire::Status(code) => {
            let reason = server_reason(raw);
            let what = match &reason {
                Some(r) => tr!(
                    format!("Our server answered and rejected the request (HTTP {code}); the reason it gave: `{r}`. This is NOT necessarily an allow-list decision."),
                    format!("我们的服务器已应答并拒绝了该请求(HTTP {code});服务端给出的原因:`{r}`。这不一定是允许名单层面的判定。")
                ),
                None => tr!(
                    format!("Our server answered and rejected the request (HTTP {code}), without giving a machine-readable reason. This is NOT necessarily an allow-list decision."),
                    format!("我们的服务器已应答并拒绝了该请求(HTTP {code}),且未给出可解析的原因。这不一定是允许名单层面的判定。")
                ),
            };
            Classified::new(
                what,
                tr!(
                    "the network reached us, so retry first; if it repeats, run `alice-miner doctor` and report the HTTP code (re-run with ALICE_MINER_VERBOSE=1 for the full server reply).",
                    "网络已经到达我们这里,请先重试;若反复出现,请运行 `alice-miner doctor` 并反馈该 HTTP 状态码(设置 ALICE_MINER_VERBOSE=1 重新运行可看到完整的服务端回复)。"
                ),
            )
        }

        // ── (d) Something answered, but not in our protocol.
        Wire::Undecodable => Classified::new(
            tr!(
                "Something answered at our server's address, but the reply is not what this client speaks — so we cannot tell whether our server was ever reached.",
                "我们服务器地址上有东西作出了应答,但回复内容不是本客户端能识别的协议 —— 因此无法判断请求是否真的到达了我们的服务器。"
            ),
            tr!(
                "this can happen when a captive portal, proxy or content filter answers in our place. Retry on a different network (a phone hotspot), run `alice-miner doctor`, and re-run with ALICE_MINER_VERBOSE=1 to see the raw reply.",
                "当强制门户、代理或内容过滤设备代替我们应答时就会这样。请换一个网络(如手机热点)重试,运行 `alice-miner doctor`,并设置 ALICE_MINER_VERBOSE=1 重新运行以查看原始回复。"
            ),
        ),

        // ── (e) We do not know. Say exactly that; list what IS known; guess nothing.
        Wire::Unknown => Classified::new(
            tr!(
                "Enrolling with our relay / center failed, and this client cannot tell why.",
                "在我们的中继 / 中心注册失败,而本客户端无法判断原因。"
            ),
            tr!(
                "what is known: the enroll request did not complete. What is NOT known: whether it was a network / HTTPS problem on this machine, or a rejection by our server — the error carries no signature of either. Run `alice-miner doctor` (it tests DNS, TCP and HTTPS-certificate trust separately) and re-run with ALICE_MINER_VERBOSE=1 for the exact technical error.",
                "已知:注册请求没有完成。未知:究竟是本机的网络 / HTTPS 问题,还是服务器的拒绝 —— 该错误里没有任何一方的特征。请运行 `alice-miner doctor`(它会分别检测 DNS、TCP 与 HTTPS 证书信任),并设置 ALICE_MINER_VERBOSE=1 重新运行以获取确切的技术错误。"
            ),
        ),
    }
}

/// Classify a raw error string into a bilingual (what happened, what to do) pair.
///
/// Order matters. Local/identity facts first (they are certain), then anything that
/// touched the control plane (routed through [`classify_control_plane`], which asks the
/// WIRE what happened before it says anything about authorization), then the device /
/// engine families, then the transport-only families, then a safe generic.
fn classify(raw: &str) -> Classified {
    let lower = raw.to_ascii_lowercase();

    // No reward identity / address (the very first thing a fresh user hits).
    if lower.contains("no reward address") || lower.contains("no reward identity") {
        return Classified::new(
            tr!(
                "No reward identity yet — mining has nowhere to send your credit.",
                "尚无奖励身份 — 挖矿没有可发放积分的去向。"
            ),
            tr!(
                "create one: `alice-miner identity --create` (or `--paste <address>` for watch-only).",
                "请创建一个: `alice-miner identity --create`(或 `--paste <地址>` 用于仅观察)。"
            ),
        );
    }

    // Watch-only identity used for a lane that needs the signing key (PoP). A LOCAL
    // fact, established before any request — certain regardless of the network.
    if lower.contains("watch-only") {
        return Classified::new(
            tr!(
                "This identity is watch-only (an address with no signing key), so it cannot prove key possession for this lane.",
                "此身份为仅观察(只有地址、没有签名密钥),因此无法为此通道证明密钥所有权。"
            ),
            tr!(
                "import the mnemonic/seed for this address (`alice-miner identity --import`), or mine the CPU-XMR lane (address-only).",
                "请导入该地址的助记词/种子(`alice-miner identity --import`),或改挖 CPU-XMR 通道(仅需地址)。"
            ),
        );
    }

    // A local URL/region misconfiguration — `pop::require_https` / `is_safe_host` /
    // `verify_url` all fail BEFORE any socket is opened. Previously these fell into the
    // allowlist branch, which told the user the server had judged them when the server
    // had never been contacted.
    if lower.contains("unsafe region host")
        || lower.contains("refusing non-https")
        || lower.contains("missing /m4/challenge suffix")
    {
        return classify_bad_config();
    }

    // Everything that touched the enroll / PoP / stage-register control plane. Routed
    // through the wire-outcome classifier — this is the whole fix.
    if touches_control_plane(&lower) {
        return classify_control_plane(raw, &lower);
    }

    // A possession proof the relay explicitly REJECTED (no control-plane URL in the
    // string, so nothing above caught it). "Rejected" is a stated outcome, not a guess.
    if (lower.contains("proof-of-possession")
        || lower.contains("proof of possession")
        || lower.contains("pop"))
        && (lower.contains("reject") || lower.contains("denied") || lower.contains("invalid"))
    {
        return Classified::new(
            tr!(
                "The relay rejected the proof of key possession, so it would not credit this lane.",
                "中继拒绝了密钥所有权证明(PoP),因此不会为此通道计入积分。"
            ),
            tr!(
                "check that the unlocked identity is the one holding this reward address, then retry; `alice-miner doctor` re-tests the handshake.",
                "请确认已解锁的身份正是持有该奖励地址的那个,然后重试;`alice-miner doctor` 可重新测试该握手。"
            ),
        );
    }

    // A possession proof that failed for an UNSTATED reason. Do not claim the relay
    // decided anything — ask the wire, and fall through to "cannot tell" if it is mute.
    if lower.contains("proof-of-possession")
        || lower.contains("proof of possession")
        || lower.contains("possession")
        || lower.contains("pop ")
        || lower.ends_with("pop")
    {
        return classify_control_plane(raw, &lower);
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
        return Classified::new(
            tr!(
                "No usable GPU for this lane (or the card can't run this engine).",
                "此通道没有可用的 GPU(或该显卡无法运行此引擎)。"
            ),
            tr!(
                "run `alice-miner detect` to see supported lanes; a Volta/V100 uses `--lane alpha`, and CPU-XMR always works.",
                "运行 `alice-miner detect` 查看支持的通道;Volta/V100 请用 `--lane alpha`,CPU-XMR 始终可用。"
            ),
        );
    }

    // Engine launch / spawn failure (binary missing, not executable, quarantined).
    if lower.contains("failed to start miner")
        || lower.contains("could not start")
        || lower.contains("spawn")
        || lower.contains("no such file")
        || lower.contains("is not available")
        || lower.contains("permission denied")
    {
        return Classified::new(
            tr!(
                "The mining engine could not be launched.",
                "无法启动挖矿引擎。"
            ),
            tr!(
                "run `alice-miner doctor` (it re-checks the engine); `doctor --fix` can re-download a missing/corrupt engine. On Windows, allow the engine in Defender.",
                "运行 `alice-miner doctor`(它会重新检查引擎);`doctor --fix` 可重新下载缺失/损坏的引擎。Windows 上请在 Defender 中放行引擎。"
            ),
        );
    }

    // A TLS-trust failure on a NON-control-plane fetch (engine download, update
    // manifest). Same interception, different endpoint — and it must not be reported as
    // a generic "firewall blocking the stratum port", which would send the user to the
    // wrong setting entirely.
    if looks_like_tls(&lower) {
        return Classified::new(
            tr!(
                "An HTTPS download was intercepted, or its certificate could not be verified — the transfer never completed.",
                "一次 HTTPS 下载被拦截,或其证书无法通过验证 —— 传输没有完成。"
            ),
            tr!(
                "this is a certificate-trust problem, not a mining problem: allow github.com and objects.githubusercontent.com through your firewall / antivirus HTTPS scanner, or install its root CA into the SYSTEM certificate store. `alice-miner doctor` prints the exact certificate error.",
                "这是证书信任问题,不是挖矿问题:请在防火墙 / 杀毒软件的 HTTPS 扫描中放行 github.com 与 objects.githubusercontent.com,或把其根证书安装到\"系统\"证书库。`alice-miner doctor` 会打印确切的证书错误。"
            ),
        );
    }

    // Pool / relay / network reachability (DNS, connect timeout, firewall). Reached only
    // once TLS has been ruled out, so the stratum-port advice below is now sound.
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
        return Classified::new(
            tr!(
                "Could not reach the mining relay from this machine.",
                "本机无法连接到挖矿中继。"
            ),
            tr!(
                "check your connection and firewall (the stratum port must be reachable outbound); a VPN or captive portal can block it. `alice-miner doctor` tests this.",
                "请检查网络连接和防火墙(stratum 端口必须可出站访问);VPN 或强制门户网络可能拦截它。`alice-miner doctor` 可测试此项。"
            ),
        );
    }

    // Fallthrough: unrecognized — still give a consistent, actionable shape (never a
    // bare dump), and never a cause. The raw detail is available under VERBOSE.
    Classified::new(
        tr!(
            "Something went wrong while mining, and this client cannot tell what.",
            "挖矿过程中出现问题,而本客户端无法判断具体原因。"
        ),
        tr!(
            "run `alice-miner doctor` for a full diagnostic; re-run with ALICE_MINER_VERBOSE=1 to see the technical detail.",
            "运行 `alice-miner doctor` 查看完整诊断;设置 ALICE_MINER_VERBOSE=1 重新运行可查看技术详情。"
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alice_miner_core::i18n::{set_lang, Lang};

    /// A serialized guard so the VERBOSE-toggling and language-pinning tests don't race
    /// each other. Both `ALICE_MINER_VERBOSE` and the current language are PROCESS
    /// globals, and cargo runs this bin's unit tests on parallel threads — so the lock
    /// is the CRATE-wide one (`main.rs::LANG_TEST_LOCK`), shared with every other module
    /// that pins a language. A module-private mutex would only order `errmsg` against
    /// itself, and `en_mode_never_emits_chinese` would then be at the mercy of whatever
    /// `region` / `balance` / `menu` happened to set.
    use crate::LANG_TEST_LOCK as ENV_LOCK;

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

    /// Run `f` with the process language pinned, restoring English afterwards.
    fn with_lang<T>(lang: Lang, f: impl FnOnce() -> T) -> T {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("ALICE_MINER_VERBOSE");
        set_lang(lang);
        let out = f();
        set_lang(Lang::En);
        out
    }

    fn has_cjk(s: &str) -> bool {
        s.chars().any(|c| {
            matches!(c as u32,
                0x3000..=0x303F | 0x3400..=0x4DBF | 0x4E00..=0x9FFF |
                0xF900..=0xFAFF | 0xFF00..=0xFFEF)
        })
    }

    /// The exact shapes our HTTP helpers emit, so the tests are grounded in real
    /// strings rather than invented ones.
    ///
    /// * `pop.rs` wraps ureq: `POST {url}: {ureq_display}`.
    /// * `shard.rs` / `train_worker.rs` read the body: `POST {url}: HTTP {code}: {body}`.
    /// * a rustls chain failure surfaces as `Connection Failed: tls connection init
    ///   failed: invalid peer certificate: UnknownIssuer`.
    const RAW_TLS_INTERCEPTED: &str = "could not enroll/register this inference stage with the center: POST https://asia.aliceprotocol.org/m4/challenge: https://asia.aliceprotocol.org/m4/challenge: Connection Failed: tls connection init failed: invalid peer certificate: UnknownIssuer";
    const RAW_DNS: &str = "POST https://us.aliceprotocol.org/m4/challenge: https://us.aliceprotocol.org/m4/challenge: Dns Failed: resolve dns name 'us.aliceprotocol.org'";
    const RAW_REFUSED: &str = "POST https://eu.aliceprotocol.org/m4/challenge: https://eu.aliceprotocol.org/m4/challenge: Connection Failed: Connect error: Connection refused (os error 61)";
    const RAW_REFUSED_403: &str = "POST https://api.aliceprotocol.org/v1/shard/stage/register: HTTP 403: {\"reason_code\":\"not_allowlisted\"}";
    const RAW_429: &str = "POST https://asia.aliceprotocol.org/m4/challenge: https://asia.aliceprotocol.org/m4/challenge: status code 429";
    const RAW_502: &str = "POST https://api.aliceprotocol.org/v1/shard/stage/register: HTTP 502: bad gateway";
    const RAW_PORTAL: &str = "parse https://us.aliceprotocol.org/m4/challenge: expected value at line 1 column 1";
    const RAW_MUTE: &str = "could not enroll/register this training worker with the center: something went sideways";

    // ── The regression this whole rewrite exists for ─────────────────────────────

    /// **The bug**: a TLS interception (company firewall / antivirus HTTPS scanning)
    /// used to be rendered as "(address, device) was not allow-listed". It must now
    /// name HTTPS interception, must explicitly DENY the allow-list reading, and must
    /// hand the miner the three self-checks.
    #[test]
    fn tls_interception_is_never_called_an_allowlist_rejection() {
        with_verbose(false, || {
            let msg = render_error(RAW_TLS_INTERCEPTED);
            let low = msg.to_lowercase();
            // It must NOT assert the server judged the user.
            assert!(
                !low.contains("not allow-listed") && !low.contains("was not allow"),
                "must not claim an allow-list decision: {msg}"
            );
            // It must name the real class of cause.
            assert!(low.contains("https"), "names HTTPS: {msg}");
            assert!(
                low.contains("intercept") || low.contains("certificate"),
                "names interception / certificate: {msg}"
            );
            // It must actively correct the old, wrong reading.
            assert!(low.contains("not an allow-list"), "denies the old claim: {msg}");
            // The three self-checks, in order.
            assert!(low.contains("hotspot"), "step 1 hotspot: {msg}");
            assert!(
                low.contains("us.aliceprotocol.org")
                    && low.contains("asia.aliceprotocol.org")
                    && low.contains("eu.aliceprotocol.org"),
                "step 2 names all three hosts: {msg}"
            );
            assert!(low.contains("--region"), "step 3 explicit region: {msg}");
        });
    }

    /// The same raw string in Chinese: the guidance must survive translation, and no
    /// English-mode leak in reverse (see `en_mode_never_emits_chinese`).
    #[test]
    fn tls_interception_reads_correctly_in_chinese() {
        with_lang(Lang::Zh, || {
            let msg = render_error(RAW_TLS_INTERCEPTED);
            assert!(msg.contains("HTTPS"), "names HTTPS: {msg}");
            assert!(msg.contains("拦截"), "names interception: {msg}");
            assert!(!msg.contains("未进入允许名单"), "no allow-list claim: {msg}");
            assert!(msg.contains("热点"), "hotspot self-check: {msg}");
            assert!(msg.contains("--region"), "explicit region self-check: {msg}");
        });
    }

    // ── (a) connect / DNS / timeout ──────────────────────────────────────────────

    #[test]
    fn unreachable_says_unreachable_not_rejected() {
        with_verbose(false, || {
            for raw in [RAW_DNS, RAW_REFUSED] {
                let msg = render_error(raw);
                let low = msg.to_lowercase();
                assert!(
                    low.contains("could not reach our server"),
                    "names unreachable: {msg}"
                );
                // It may MENTION the allow-list — but only to say the status is
                // unknown, never to assert a verdict.
                assert!(
                    !low.contains("was not allow-listed") && !low.contains("refused to enroll"),
                    "no allow-list verdict: {msg}"
                );
                assert!(
                    low.contains("nothing is known about your allow-list status"),
                    "states the unknown: {msg}"
                );
            }
        });
    }

    // ── (c) the server actually answered ─────────────────────────────────────────

    /// 401/403 is the ONLY place the allow-list sentence is reachable — and it carries
    /// the server's own `reason_code`.
    #[test]
    fn http_403_is_the_only_allowlist_verdict_and_carries_the_reason_code() {
        with_verbose(false, || {
            let msg = render_error(RAW_REFUSED_403);
            let low = msg.to_lowercase();
            assert!(low.contains("answered"), "states the server replied: {msg}");
            assert!(low.contains("refused to enroll"), "states the refusal: {msg}");
            assert!(low.contains("403"), "carries the status: {msg}");
            assert!(low.contains("not_allowlisted"), "carries the reason_code: {msg}");
            assert!(low.contains("network is fine"), "clears the network: {msg}");
        });
    }

    /// A 429 is NOT an authorization verdict and must not read like one.
    #[test]
    fn http_429_is_rate_limiting_not_an_allowlist_verdict() {
        with_verbose(false, || {
            let low = render_error(RAW_429).to_lowercase();
            assert!(low.contains("rate-limit"), "names rate limiting: {low}");
            assert!(
                low.contains("says nothing about your allow-list"),
                "explicitly declines the allow-list reading: {low}"
            );
        });
    }

    /// A 5xx is OUR fault and must say so — never "you are not allow-listed".
    #[test]
    fn http_5xx_blames_our_side_not_the_user() {
        with_verbose(false, || {
            let low = render_error(RAW_502).to_lowercase();
            assert!(low.contains("502"), "carries the status: {low}");
            assert!(low.contains("on our side"), "blames our side: {low}");
            assert!(!low.contains("allow-list"), "no allow-list claim: {low}");
        });
    }

    // ── (d) something answered, but not us ───────────────────────────────────────

    #[test]
    fn undecodable_reply_is_hedged_not_asserted() {
        with_verbose(false, || {
            let low = render_error(RAW_PORTAL).to_lowercase();
            assert!(low.contains("cannot tell"), "admits the ambiguity: {low}");
            // The captive-portal explanation is offered as a possibility, never as fact.
            assert!(low.contains("this can happen when"), "hedged: {low}");
            assert!(!low.contains("allow-list"), "no allow-list claim: {low}");
        });
    }

    // ── (e) the honest "we don't know" ───────────────────────────────────────────

    /// A control-plane failure with NO transport signature must say, in words, that it
    /// cannot tell — and must name both hypotheses it is refusing to choose between.
    #[test]
    fn indeterminate_failure_says_it_cannot_tell_and_guesses_nothing() {
        with_verbose(false, || {
            let msg = render_error(RAW_MUTE);
            let low = msg.to_lowercase();
            assert!(low.contains("cannot tell why"), "says it cannot tell: {msg}");
            assert!(low.contains("what is known"), "lists what is known: {msg}");
            assert!(low.contains("what is not known"), "lists what is not: {msg}");
            // Both candidate causes are named as candidates, neither is chosen.
            assert!(low.contains("network"), "names hypothesis A: {msg}");
            assert!(low.contains("rejection by our server"), "names hypothesis B: {msg}");
            // And crucially, it does NOT pick one.
            assert!(!low.contains("was not allow-listed"), "picks no cause: {msg}");
            assert!(low.contains("doctor"), "gives a next step: {msg}");
        });
    }

    /// The generic fallthrough (nothing at all recognized) is honest too.
    #[test]
    fn unknown_error_falls_through_to_a_safe_generic() {
        with_verbose(false, || {
            let msg = render_error("some entirely novel failure 0xdeadbeef");
            assert!(msg.contains("→"), "still has an action: {msg}");
            assert!(msg.contains("doctor"), "points at doctor: {msg}");
            assert!(
                msg.to_lowercase().contains("cannot tell what"),
                "admits ignorance: {msg}"
            );
            assert!(!msg.contains("0xdeadbeef"), "raw hidden by default: {msg}");
        });
    }

    // ── Wire-outcome unit coverage (stage 1 in isolation) ────────────────────────

    #[test]
    fn wire_outcome_reads_each_layer_correctly() {
        let w = |s: &str| wire_outcome(&s.to_ascii_lowercase());
        assert_eq!(w(RAW_TLS_INTERCEPTED), Wire::TlsBlocked);
        assert_eq!(w(RAW_DNS), Wire::Unreachable);
        assert_eq!(w(RAW_REFUSED), Wire::Unreachable);
        assert_eq!(w(RAW_REFUSED_403), Wire::Status(403));
        assert_eq!(w(RAW_429), Wire::Status(429));
        assert_eq!(w(RAW_502), Wire::Status(502));
        assert_eq!(w(RAW_PORTAL), Wire::Undecodable);
        assert_eq!(w(RAW_MUTE), Wire::Unknown);
    }

    /// An HTTP status proves the TLS chain verified, so it must WIN over a body that
    /// happens to contain certificate words — otherwise a server message could make us
    /// blame the user's firewall.
    #[test]
    fn an_http_status_outranks_certificate_words_in_the_body() {
        let raw = "POST https://api.aliceprotocol.org/v1/shard/stage/register: HTTP 400: {\"error\":\"client certificate not supported\"}";
        assert_eq!(wire_outcome(&raw.to_ascii_lowercase()), Wire::Status(400));
        with_verbose(false, || {
            let low = render_error(raw).to_lowercase();
            assert!(low.contains("answered"), "credits the server with replying: {low}");
            assert!(!low.contains("intercept"), "never blames interception: {low}");
        });
    }

    /// `https://` must never be read as an HTTP status, and a bare `http/1.1` must not
    /// either — only `HTTP <ddd>` / `status code <ddd>`.
    #[test]
    fn http_status_parsing_is_not_fooled_by_urls() {
        assert_eq!(http_status("post https://host/m4/challenge: dns failed"), None);
        assert_eq!(http_status("bad status: http/1.1 nonsense"), None);
        assert_eq!(http_status("http 404: not found"), Some(404));
        assert_eq!(http_status("https://h/x: status code 503"), Some(503));
        // Out of range digits are not a status.
        assert_eq!(http_status("http 999: nope"), None);
    }

    /// The `reason_code` echo is sanitized: only tame tokens survive, and an ANSI /
    /// control-character payload is dropped rather than rendered (AM-SEC-007's rule
    /// applied at the one place this module echoes server text).
    #[test]
    fn server_reason_is_sanitized_or_dropped() {
        assert_eq!(
            server_reason("{\"reason_code\":\"device_not_enrolled\"}").as_deref(),
            Some("device_not_enrolled")
        );
        // ANSI escape → dropped entirely.
        assert_eq!(server_reason("{\"reason_code\":\"\u{1b}[2Jok\"}"), None);
        // Over-long → dropped.
        assert_eq!(server_reason(&format!("{{\"error\":\"{}\"}}", "x".repeat(65))), None);
        // Nothing parseable → None (the message then says "without giving a reason").
        assert_eq!(server_reason("HTTP 403: forbidden"), None);
    }

    // ── The families the rewrite must NOT regress ────────────────────────────────

    #[test]
    fn renders_two_line_shape_and_hides_detail_by_default() {
        with_verbose(false, || {
            let raw = "failed to start miner: No such file or directory (os error 2)";
            let msg = render_error(raw);
            assert!(msg.contains("→"), "has an action arrow: {msg}");
            assert!(msg.lines().count() == 2, "exactly what + action (no detail): {msg}");
            assert!(!msg.contains("os error 2"), "raw detail hidden by default: {msg}");
        });
    }

    #[test]
    fn verbose_appends_raw_detail() {
        with_verbose(true, || {
            let raw = "failed to start miner: No such file or directory (os error 2)";
            let msg = render_error(raw);
            assert!(msg.contains("os error 2"), "raw detail shown under VERBOSE: {msg}");
            assert!(msg.to_lowercase().contains("detail") || msg.contains("详情"), "labelled: {msg}");
        });
    }

    #[test]
    fn classifies_the_high_traffic_failures() {
        with_verbose(false, || {
            assert!(render_error("failed to start miner: permission denied")
                .to_lowercase()
                .contains("engine"));
            assert!(render_error("GPU-PRL (SRBMiner) can't run on this GPU: CC 7.0 below 7.5")
                .to_lowercase()
                .contains("gpu"));
            let net = render_error("cannot reach the relay hk.aliceprotocol.org:3333: connection refused");
            assert!(net.to_lowercase().contains("relay") || net.to_lowercase().contains("network"));
            assert!(render_error("no reward address: create/import/paste an identity first")
                .to_lowercase()
                .contains("identity"));
        });
    }

    /// The GPU / engine / stratum-relay families must not be swallowed by the
    /// control-plane router (its tokens are chosen to never appear in them).
    #[test]
    fn control_plane_router_does_not_shadow_other_categories() {
        with_verbose(false, || {
            // "registers" is a CUDA compile phrase, not our `register` route.
            assert!(render_error("CUDA: too many registers used, cannot run on this GPU")
                .to_lowercase()
                .contains("gpu"));
            // A plain stratum-relay reachability error stays in the mining-relay branch.
            let net = render_error("cannot reach the relay hk.aliceprotocol.org:3333: connection refused");
            assert!(net.to_lowercase().contains("mining relay"), "stratum branch: {net}");
            // A stated PoP rejection is still reported as a rejection.
            assert!(render_error("proof-of-possession rejected by relay")
                .to_lowercase()
                .contains("rejected the proof"));
        });
    }

    /// A local URL/region misconfiguration is a CONFIG error — it never reached the
    /// network, so it must claim neither a network nor an authorization cause.
    #[test]
    fn local_misconfiguration_is_not_reported_as_network_or_allowlist() {
        with_verbose(false, || {
            for raw in [
                "unsafe region host: \"bad host\"",
                "refusing non-https control-plane url: http://x/m4/challenge",
            ] {
                let low = render_error(raw).to_lowercase();
                assert!(low.contains("local configuration"), "names config: {low}");
                assert!(!low.contains("allow-list"), "no allow-list claim: {low}");
                assert!(low.contains("--region"), "points at the knob: {low}");
            }
        });
    }

    /// A TLS-trust failure on a NON-control-plane fetch (engine download / update
    /// manifest) must be reported as a certificate problem, not as "the stratum port
    /// is firewalled" — that would send the user to the wrong setting.
    #[test]
    fn non_control_plane_tls_failure_is_not_called_a_stratum_firewall_problem() {
        with_verbose(false, || {
            let low = render_error(
                "download https://objects.githubusercontent.com/x: Connection Failed: tls connection init failed: invalid peer certificate: UnknownIssuer",
            )
            .to_lowercase();
            assert!(low.contains("certificate"), "names the certificate: {low}");
            assert!(!low.contains("stratum"), "not the stratum-port advice: {low}");
        });
    }

    // ── i18n boundary + credit-only ──────────────────────────────────────────────

    /// **English mode must never emit Chinese.** Every branch, including the new ones
    /// and their numbered steps.
    #[test]
    fn en_mode_never_emits_chinese() {
        with_lang(Lang::En, || {
            for raw in [
                RAW_TLS_INTERCEPTED,
                RAW_DNS,
                RAW_REFUSED,
                RAW_REFUSED_403,
                RAW_429,
                RAW_502,
                RAW_PORTAL,
                RAW_MUTE,
                "unsafe region host: \"bad host\"",
                "no reward address",
                "this reward identity is watch-only",
                "proof-of-possession rejected by relay",
                "GPU-PRL can't run on this GPU",
                "failed to start miner: permission denied",
                "cannot reach the relay: timeout",
                "tls connection init failed: invalid peer certificate: UnknownIssuer",
                "some entirely novel failure",
            ] {
                let msg = render_error(raw);
                assert!(!has_cjk(&msg), "EN mode leaked Chinese for {raw:?}: {msg}");
            }
        });
    }

    /// And Chinese mode renders every branch non-empty with the same shape (the mirror
    /// check — a missing ZH variant would otherwise show up only in the field).
    #[test]
    fn zh_mode_renders_every_branch() {
        with_lang(Lang::Zh, || {
            for raw in [
                RAW_TLS_INTERCEPTED,
                RAW_DNS,
                RAW_REFUSED_403,
                RAW_429,
                RAW_502,
                RAW_PORTAL,
                RAW_MUTE,
                "unsafe region host: \"bad host\"",
                "some entirely novel failure",
            ] {
                let msg = render_error(raw);
                assert!(msg.contains("→"), "shape kept for {raw:?}: {msg}");
                assert!(has_cjk(&msg), "ZH mode rendered Chinese for {raw:?}: {msg}");
            }
        });
    }

    /// Credit-only + secret-free: the rendered message never introduces a fiat/paid
    /// token, and never echoes the URL / host / address out of the raw string.
    #[test]
    fn rendered_error_is_credit_only_and_echoes_no_raw_identifiers() {
        with_verbose(false, || {
            for raw in [
                RAW_TLS_INTERCEPTED,
                RAW_DNS,
                RAW_REFUSED_403,
                RAW_MUTE,
                "failed to start miner: x",
                "cannot reach the relay: timeout",
                "no reward address",
            ] {
                let msg = render_error(raw);
                let low = msg.to_lowercase();
                for forbidden in ["$", "usd", "paid", "earned", "payout"] {
                    assert!(!low.contains(forbidden), "leaked `{forbidden}`: {low}");
                }
                // The only hosts that may appear are the STATIC hint list, never a host
                // lifted out of the raw error.
                assert!(!low.contains("api.aliceprotocol.org"), "echoed a raw host: {low}");
                assert!(!low.contains("objects.githubusercontent"), "echoed a raw host: {low}");
            }
        });
    }
}
