//! `alice-miner companion` — hold the M4 possession proof for a BRING-YOUR-OWN
//! (third-party, closed-source) pearlhash miner.
//!
//! The GPU-PRL / GPU-Alpha relays run `REQUIRE_POP=1`: a bare stratum login is
//! rejected (`code:24`). The official client proves possession INTERNALLY (it
//! signs a `/m4/challenge` nonce with your Alice key and `/m4/verify`-enrolls the
//! `(address, device)` pair into the relay's out-of-band allowlist). A THIRD-PARTY
//! miner can't do that — so this companion does it FOR it, WITHOUT running any
//! miner:
//!
//!   1. unlock your Alice signing key locally (the key NEVER leaves this box);
//!   2. run the SAME `pop::establish_pop` handshake the official lane runs —
//!      `/m4/challenge` → sign → `/m4/verify` — enrolling `(your address, device)`
//!      into the region relay's allowlist;
//!   3. repeat on a refresh loop INSIDE the relay's allowlist TTL (server: 1800 s),
//!      so the pair stays authorized for as long as the companion runs.
//!
//! Meanwhile you point your OWN pearlhash rig at the SAME region relay with the
//! login `<your-address>.<device>` and any password. The relay sees the pair on
//! its allowlist (proven by THIS process) and credits the shares to your address.
//!
//! It **NEVER spawns a miner** (no SRBMiner / AlphaMiner / supervisor) — it is a
//! possession-proof keep-alive ONLY. That is the whole point: your rig hashes; the
//! companion holds the proof; the key stays here.
//!
//! ── CREDIT-ONLY / honesty ────────────────────────────────────────────────────
//! Reuses the exact byte-identical PoP core (`alice_miner_core::pop`), shows only
//! PUBLIC Alice relay hosts, prints NO secret (the key is unlocked in-memory only),
//! and its status output carries no fiat / earnings promise — rewards accrue as
//! credit (积分, credit-only), like the rest of the CLI.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use alice_miner_core::lane::{gpu_alpha, gpu_prl, xmr};
use alice_miner_core::pop::{self, OOB_ALLOWLIST_TTL};
use alice_miner_core::tr;
use alice_miner_core::Lane;

use crate::{EXIT_OK, EXIT_RUNTIME, EXIT_USAGE};

/// The resolved companion invocation.
pub struct CompanionFlags {
    /// `prl` (SRBMiner mainline) or `alpha` (Volta/V100). Reject XMR/RVN (open
    /// enrollment — no companion needed).
    pub lane: String,
    /// The device label (the stratum worker suffix your rig logs in with). Absent →
    /// a sanitized hostname default.
    pub device: Option<String>,
    /// Pin a region (`us`/`asia`/`eu`), else the remembered/nearest region is used.
    pub region: Option<String>,
    /// Reward address override (else the active `~/.alice` identity).
    pub address: Option<String>,
    /// Re-enroll cadence in seconds (clamped strictly inside the relay TTL).
    pub refresh_secs: Option<u64>,
    /// Enroll ONCE then exit (for a scripted "prime the allowlist" or a test).
    pub once: bool,
    /// Stop automatically after this many seconds (0 = run until Ctrl-C).
    pub duration_s: u64,
}

/// Default re-enroll cadence: comfortably inside the relay's OOB allowlist TTL
/// (server 1800 s) with wide headroom — ~9 minutes re-enrolls the pair ≈3× before
/// it could expire. A miss (transient network) still leaves ~2 more attempts
/// before the TTL runs out, so an occasional failed refresh never drops the pair.
pub const DEFAULT_REFRESH_SECS: u64 = 540;

/// After a FAILED refresh, retry sooner than the steady cadence so a transient
/// relay/network hiccup recovers well inside the TTL rather than waiting a full
/// interval.
const RETRY_ON_ERROR: Duration = Duration::from_secs(30);

/// Max device-label length (a stratum worker suffix). Well under the relay's
/// 64-char worker-id ceiling, leaving room for the `<address>.` prefix.
const DEVICE_MAX_LEN: usize = 32;

/// Clamp a requested refresh cadence to a SAFE band strictly inside the relay's
/// allowlist TTL. Never returns `>= TTL` (an interval at/over the TTL would let the
/// pair lapse between refreshes) and never returns an absurdly tiny value (which
/// would hammer the control plane). Pure + testable.
pub fn safe_refresh_interval(requested_secs: u64) -> Duration {
    // A hard floor (don't hammer /m4/verify) and a ceiling that keeps at least a
    // ~2× margin before the TTL, so one missed refresh never expires the pair.
    const FLOOR_SECS: u64 = 30;
    let ttl = OOB_ALLOWLIST_TTL.as_secs();
    // Ceiling = half the TTL (a missed refresh still lands with the pair valid).
    let ceil = (ttl / 2).max(FLOOR_SECS);
    let secs = requested_secs.clamp(FLOOR_SECS, ceil);
    Duration::from_secs(secs)
}

/// Validate + normalize a USER-supplied device label into a stratum-safe worker
/// suffix. Accepts `[A-Za-z0-9_-]`, 1..=[`DEVICE_MAX_LEN`] chars. Rejects anything
/// else (including a `.`, which the relay treats as the `address.worker` separator)
/// so the label the companion enrolls is EXACTLY what the miner must present — no
/// silent rewrite that would break the allowlist match. Pure + testable.
pub fn sanitize_device(raw: &str) -> Result<String, String> {
    let t = raw.trim();
    if t.is_empty() {
        return Err(tr!(
            "device name must not be empty",
            "设备名不能为空"
        )
        .to_string());
    }
    if t.len() > DEVICE_MAX_LEN {
        return Err(tr!(
            "device name is too long (max 32 characters)",
            "设备名过长(最多 32 个字符)"
        )
        .to_string());
    }
    if !t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(tr!(
            "device name may only contain letters, digits, '-' and '_'",
            "设备名只能包含字母、数字、'-' 和 '_'"
        )
        .to_string());
    }
    Ok(t.to_string())
}

/// A friendly default device label derived from the machine hostname (env
/// `HOSTNAME` / `COMPUTERNAME`), lenient-sanitized to the worker charset; falls
/// back to `byo-rig` when there is nothing usable. Distinct from
/// [`sanitize_device`] (which is STRICT on explicit user input): here we REPLACE
/// stray chars rather than reject, since a hostname legitimately contains `.`/etc.
pub fn default_device() -> String {
    let raw = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_default();
    let mut s: String = raw
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect();
    // Trim to length + strip separators at the ends.
    s.truncate(DEVICE_MAX_LEN);
    let s = s.trim_matches(|c| c == '-' || c == '_').to_string();
    if s.is_empty() {
        "byo-rig".to_string()
    } else {
        s
    }
}

/// Resolve the companion lane token. Only the PoP-gated pearlhash lanes have a
/// companion: `prl`/`gpu` → GPU-PRL, `alpha` → GPU-Alpha. XMR/RVN are open
/// enrollment (a plain `x` password is accepted) so they are rejected with a clear
/// pointer at `guide`. Pure + testable.
pub fn resolve_companion_lane(s: &str) -> Result<Lane, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "prl" | "gpu" => Ok(Lane::GpuPrl),
        "alpha" => Ok(Lane::GpuAlpha),
        "xmr" | "cpu" | "rvn" => Err(tr!(
            "the companion is only for the PoP-gated pearlhash lanes (prl / alpha). \
             XMR / RVN use open enrollment — point your miner straight at the relay \
             (`alice-miner guide` shows the parameters).",
            "伴侣模式仅用于需要 PoP 的 pearlhash 通道(prl / alpha)。\
             XMR / RVN 使用开放注册 —— 直接把矿机指向中继即可\
             (`alice-miner guide` 会显示参数)。"
        )
        .to_string()),
        other => Err(tr!(
            "unknown companion lane `{lane}` (use: prl | alpha)",
            "未知的伴侣通道 `{lane}`(可用: prl | alpha)"
        )
        .replace("{lane}", other)),
    }
}

/// The client-facing stratum port your rig connects to for a companion lane
/// (`prl` → 3340, `alpha` → 3341). The PoP control plane itself is port-free
/// (`https://<host>/m4/challenge`), so this is only for the connection hint we
/// print. Pure + testable.
pub fn stratum_port(lane: Lane) -> u16 {
    match lane {
        Lane::GpuAlpha => gpu_alpha::ALPHA_RELAY_PORT,
        // GpuPrl (and any other, defensively) → the PRL relay port.
        _ => gpu_prl::GPU_RELAY_PORT,
    }
}

/// Resolve the region relay HOST the companion enrolls against (and the rig must
/// then connect to — the allowlist is per-relay). An explicit `--region us|asia|eu`
/// pins it; `auto`/empty or omitted uses the remembered/nearest region
/// ([`gpu_prl::region_plan`]). Rejects an unknown tag.
fn resolve_region_host(region: Option<&str>) -> Result<String, String> {
    if let Some(raw) = region {
        let v = raw.trim().to_ascii_lowercase();
        // `auto`/blank → fall through to the remembered/nearest region.
        if !matches!(v.as_str(), "" | "auto") {
            let tag = gpu_prl::normalize_region_tag(&v).ok_or_else(|| {
                let tags = gpu_prl::region_tags().join(" | ");
                tr!(
                    "unknown region `{r}` (use: {tags} | auto)",
                    "未知区域 `{r}`(可用: {tags} | auto)"
                )
                .replace("{r}", raw)
                .replace("{tags}", &tags)
            })?;
            return Ok(gpu_prl::host_for_tag(tag)
                .unwrap_or(gpu_prl::REGION_HOSTS[0].1)
                .to_string());
        }
    }
    // Remembered lock / last-good / nearest-by-RTT (same policy the mining lane uses).
    Ok(gpu_prl::region_plan().current().host.clone())
}

/// Run the companion. `unlock` is the OPTIONAL pre-resolved keystore passphrase
/// (the CLI resolves it from prompt/stdin/flag before calling us, exactly like the
/// `ai`/`train` roles); a watch-only identity has no keystore and fails closed with
/// a clear message. Returns a process exit code. NEVER spawns a miner.
pub fn run(flags: CompanionFlags, unlock: Option<Zeroizing<String>>) -> i32 {
    // (1) Lane — pearlhash only.
    let lane = match resolve_companion_lane(&flags.lane) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_USAGE;
        }
    };

    // (2) Reward address — the override or the active identity, validated SS58-300.
    let address = match resolve_address(flags.address.as_deref()) {
        Ok(a) => a,
        Err(code) => return code,
    };

    // (3) Device label (the worker suffix the rig logs in with).
    let device = match flags.device.as_deref() {
        Some(raw) => match sanitize_device(raw) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("error: {e}");
                return EXIT_USAGE;
            }
        },
        None => default_device(),
    };

    // (4) Region host (the allowlist is per-relay; the rig must use the SAME one).
    let region_host = match resolve_region_host(flags.region.as_deref()) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_USAGE;
        }
    };

    // (5) Unlock the signing key IN-MEMORY (never printed / logged / put on argv).
    // A watch-only (pasted-address) identity has no keystore → fails closed here.
    let pw: Option<&str> = unlock.as_ref().map(|z| z.as_str());
    let secrets = match alice_miner_core::engine::resolve_prl_secrets(pw) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_USAGE;
        }
    };

    // (5a) The address we ENROLL must be the one this signing key derives. The relay
    // verifies the possession proof against the ENROLLED address's pubkey, so a
    // `--address` that isn't this box's signing identity yields a signature the relay
    // can't verify: the (address, device) pair is silently never allow-listed and the
    // rig loops forever on `code:24`. Turn that fail-safe dead-end into a loud error
    // BEFORE printing the banner / starting the loop.
    if let Err(e) =
        check_address_matches_signer(&address, &secrets.address, flags.address.is_some())
    {
        eprintln!("error: {e}");
        return EXIT_USAGE;
    }

    let port = stratum_port(lane);
    print_connection_banner(lane, &address, &device, &region_host, port);

    // Ctrl-C / SIGTERM → graceful stop (the refresh loop watches this flag).
    let stop = Arc::new(AtomicBool::new(false));
    {
        let f = stop.clone();
        let _ = ctrlc::set_handler(move || f.store(true, Ordering::SeqCst));
    }

    let interval = safe_refresh_interval(flags.refresh_secs.unwrap_or(DEFAULT_REFRESH_SECS));
    refresh_loop(RefreshCtx {
        region_host: &region_host,
        address: &address,
        device: &device,
        secrets: &secrets,
        interval,
        once: flags.once,
        duration_s: flags.duration_s,
        stop,
    })
}

/// Resolve + validate the reward address (override or active identity). Returns a
/// usage exit code on a missing / invalid address.
fn resolve_address(override_addr: Option<&str>) -> Result<String, i32> {
    let raw = match override_addr {
        Some(a) => a.to_string(),
        None => match alice_miner_core::identity::load_pointer() {
            Some(p) => p.address,
            None => {
                eprintln!(
                    "error: {}",
                    tr!(
                        "no reward identity yet — create/import one (`alice-miner identity --import \"<24 words>\"`) or pass --address.",
                        "尚无奖励身份 —— 请创建/导入一个(`alice-miner identity --import \"<24 个词>\"`)或传入 --address。"
                    )
                );
                return Err(EXIT_USAGE);
            }
        },
    };
    match xmr::validate_alice_address(raw.trim()) {
        Some(canonical) => Ok(canonical),
        None => {
            eprintln!(
                "error: {}",
                tr!(
                    "'{addr}' is not a valid Alice address (must be SS58 format-300).",
                    "'{addr}' 不是有效的 Alice 地址(必须是 SS58 format-300)。"
                )
                .replace("{addr}", raw.trim())
            );
            Err(EXIT_USAGE)
        }
    }
}

/// GUARD — the address the companion enrolls MUST be the one THIS box's signing key
/// derives (SS58 format-300). The companion signs the `/m4` possession proof with the
/// local key, and the relay verifies that signature against the ENROLLED address's
/// pubkey. So enrolling any OTHER address (a `--address` pointing at someone else's
/// address, or a stale pointer) produces a signature the relay can't verify: the
/// `(address, device)` pair is **never** allow-listed and the rig loops forever on
/// `code:24` — a silent, fail-safe dead-end. This makes that dead-end LOUD.
///
/// `enroll_addr` = the address the companion would enroll (a `--address` override,
/// else the active identity). `signer_addr` = the address the unlocked keystore key
/// derives (guaranteed by `unlock_wallet`'s `verify_identity`). `explicit_override`
/// = whether the user passed `--address` (it only shapes the fix hint). Pure +
/// testable (no keystore / network): `Ok(())` = proceed, `Err(msg)` = a usage error.
///
/// NOTE — two DIFFERENT addresses that users conflate: (1) the MINING IDENTITY address
/// (this SS58 — companion signs the PoP with it, credit accrues to it; it MUST equal
/// the local signing key's address); (2) the PRL cashback address (a `prl1p…` set via
/// `identity --set-prl-payout`, where a future 15% PRL return goes) — unrelated, and
/// NOT what `--address` controls.
pub fn check_address_matches_signer(
    enroll_addr: &str,
    signer_addr: &str,
    explicit_override: bool,
) -> Result<(), String> {
    if enroll_addr == signer_addr {
        return Ok(());
    }
    let fix = if explicit_override {
        tr!(
            "You passed --address, but the companion can ONLY enroll the address of THIS box's \
             signing identity. To mine to a DIFFERENT Alice address, switch identity first \
             (`alice-miner identity --import \"<24 words>\"`) and drop --address.",
            "你传入了 --address,但伴侣只能为本机签名身份的地址注册。要挖到另一个 Alice 地址,\
             请先切换身份(`alice-miner identity --import \"<24 个词>\"`)并去掉 --address。"
        )
    } else {
        tr!(
            "This identity's stored address does not match the key in its keystore — re-import \
             it (`alice-miner identity --import \"<24 words>\"`) so the address matches the \
             signing key.",
            "该身份记录的地址与其 keystore 中的密钥不一致 —— 请重新导入\
             (`alice-miner identity --import \"<24 个词>\"`),使地址与签名密钥相符。"
        )
    };
    Err(format!(
        "{head}\n  {l_signer}: {signer_addr}\n  {l_asked}: {enroll_addr}\n  {fix}\n  {note}",
        head = tr!(
            "the companion can only enroll the address that THIS box's signing key derives. The \
             relay verifies the possession proof against the enrolled address, so a mismatched \
             address is never allow-listed (your rig would loop on code:24).",
            "伴侣只能注册本机签名密钥所派生的地址。中继会用被注册的地址来验证所有权证明,因此\
             不匹配的地址永远进不了允许名单(你的矿机会一直卡在 code:24)。"
        ),
        l_signer = tr!("signing identity (this box)", "签名身份(本机)"),
        l_asked = tr!("you asked to enroll", "你请求注册的地址"),
        note = tr!(
            "(A PRL cashback address is a SEPARATE setting — it does not change who mines. Set it \
             with `alice-miner identity --set-prl-payout <prl1p…>`.)",
            "(PRL 返现地址是另一项独立设置 —— 它不改变由谁来挖。用 \
             `alice-miner identity --set-prl-payout <prl1p…>` 设置。)"
        ),
    ))
}

/// Print the copy-paste connection instructions for the user's own rig.
fn print_connection_banner(lane: Lane, address: &str, device: &str, region_host: &str, port: u16) {
    println!(
        "\n{}",
        tr!(
            "Alice Miner — companion (bring-your-own miner)",
            "Alice Miner —— 伴侣模式(自带矿机)"
        )
    );
    println!("{}", "─".repeat(56));
    println!(
        "{}",
        tr!(
            "Point your OWN pearlhash miner at this relay:",
            "把你自己的 pearlhash 矿机指向此中继:"
        )
    );
    println!("  {}:      {region_host} : {port}", tr!("pool", "矿池"));
    println!("  {}: pearlhash", tr!("algorithm", "算法"));
    println!("  {}:     {address}.{device}", tr!("login (user)", "登录名(用户)"));
    println!(
        "  {}:  {}",
        tr!("password", "密码"),
        tr!("anything (this companion holds the authorization)", "任意值(授权由本伴侣持有)")
    );
    println!(
        "\n{}",
        tr!(
            "Your private key stays on THIS machine — it never touches the miner.",
            "你的私钥留在本机 —— 绝不接触矿机。"
        )
    );
    println!(
        "{} ({})",
        tr!(
            "Keep this running while you mine; stop with Ctrl-C.",
            "挖矿期间请保持它运行;按 Ctrl-C 停止。"
        ),
        lane.cli_lane_arg()
    );
    println!("{}", "─".repeat(56));
}

/// Everything the refresh loop needs (grouped so `run` stays flat + clippy-clean).
struct RefreshCtx<'a> {
    region_host: &'a str,
    address: &'a str,
    device: &'a str,
    secrets: &'a alice_miner_core::alice_crypto::WalletSecrets,
    interval: Duration,
    once: bool,
    duration_s: u64,
    stop: Arc<AtomicBool>,
}

/// The possession-proof keep-alive loop: re-run [`pop::establish_pop`] every
/// `interval` (or ONCE for `--once`), printing a status line each time, until
/// Ctrl-C, `--duration-s`, or a fatal error. **Never spawns a miner.**
fn refresh_loop(ctx: RefreshCtx) -> i32 {
    let started = Instant::now();
    let mut cycle: u64 = 0;
    let mut last_ok = false;

    loop {
        cycle += 1;
        // Re-run the SAME handshake the official lane runs: /m4/challenge → sign →
        // /m4/verify (enroll the (address, device) pair into THIS region's allowlist).
        let mut oob_ok = false;
        match pop::establish_pop(
            ctx.region_host,
            ctx.address,
            ctx.device,
            ctx.secrets,
            Some(&mut oob_ok),
        ) {
            Ok(_token) => {
                last_ok = oob_ok;
                print_status(cycle, ctx.region_host, oob_ok, started.elapsed(), ctx.interval, ctx.once);
            }
            Err(e) => {
                // A watch-only key was already rejected up front; a failure HERE is a
                // transient relay/network issue on the FIRST cycle, or a mid-run blip.
                // On `--once` it's fatal; otherwise log + retry sooner than the cadence.
                // The raw handshake string now ALSO goes through the shared friendly
                // renderer (an actionable next step — network / region / identity —
                // instead of a bare technical dump; the raw detail stays available under
                // ALICE_MINER_VERBOSE=1). Presentation only: the retry / exit semantics
                // are unchanged.
                eprintln!(
                    "{}\n{}",
                    tr!("proof refresh failed (will retry)", "证明刷新失败(将重试)"),
                    crate::errmsg::render_error(&e)
                );
                if ctx.once {
                    return EXIT_RUNTIME;
                }
            }
        }

        if ctx.once {
            // One enroll attempted; the relay is the authority for the outcome, so a
            // best-effort OOB `false` is not itself a failure exit (the POST still ran).
            return EXIT_OK;
        }
        if ctx.stop.load(Ordering::SeqCst) {
            break;
        }

        // Sleep until the next refresh (shorter after a failure), waking often to
        // honor Ctrl-C and the optional `--duration-s` stop promptly.
        let this_sleep = if last_ok { ctx.interval } else { RETRY_ON_ERROR.min(ctx.interval) };
        if sleep_watching(&ctx.stop, this_sleep, started, ctx.duration_s) {
            break; // stop requested or duration elapsed
        }
    }

    println!("{}", tr!("Companion stopped.", "伴侣模式已停止。"));
    EXIT_OK
}

/// Print one refresh status line (credit-only, no secret). Shows the region, whether
/// the pair is confirmed on the allowlist, uptime, and when the next refresh lands.
fn print_status(cycle: u64, region_host: &str, oob_ok: bool, uptime: Duration, interval: Duration, once: bool) {
    let state = if oob_ok {
        tr!("in allowlist", "已在允许名单")
    } else {
        // The relay is the authority; a best-effort OOB `false` just means the confirm
        // round-trip didn't land — the enroll POST still ran. Honest wording.
        tr!("enroll sent (confirm pending)", "已发送注册(确认待定)")
    };
    let mut line = format!(
        "[#{cycle}] {}={region_host}  {}: {state}  {}: {}",
        tr!("region", "区域"),
        tr!("proof", "证明"),
        tr!("uptime", "运行时长"),
        fmt_dur(uptime),
    );
    if !once {
        line.push_str(&format!(
            "  {}: ~{}",
            tr!("next", "下次"),
            fmt_dur(interval)
        ));
    }
    println!("{line}");
}

/// Sleep up to `dur`, waking every ~500 ms to check the stop flag and the optional
/// `--duration-s` deadline. Returns `true` if the caller should STOP (Ctrl-C or the
/// duration elapsed), `false` if the full sleep completed normally.
fn sleep_watching(stop: &AtomicBool, dur: Duration, started: Instant, duration_s: u64) -> bool {
    let deadline = Instant::now() + dur;
    let tick = Duration::from_millis(500);
    loop {
        if stop.load(Ordering::SeqCst) {
            return true;
        }
        if duration_s > 0 && started.elapsed() >= Duration::from_secs(duration_s) {
            return true;
        }
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        std::thread::sleep(tick.min(deadline - now));
    }
}

/// Format a duration compactly as `Nm` / `Ns` for the status line (no chrono dep).
fn fmt_dur(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alice_miner_core::i18n::{self, Lang};

    #[test]
    fn sanitize_device_accepts_clean_labels() {
        assert_eq!(sanitize_device("rig-1").unwrap(), "rig-1");
        assert_eq!(sanitize_device("  Node_A2 ").unwrap(), "Node_A2");
        assert_eq!(sanitize_device("byo").unwrap(), "byo");
    }

    #[test]
    fn sanitize_device_rejects_bad_labels() {
        assert!(sanitize_device("").is_err());
        assert!(sanitize_device("   ").is_err());
        // A '.' would collide with the relay's `address.worker` separator.
        assert!(sanitize_device("rig.1").is_err());
        assert!(sanitize_device("has space").is_err());
        assert!(sanitize_device("emoji💥").is_err());
        assert!(sanitize_device(&"x".repeat(DEVICE_MAX_LEN + 1)).is_err());
        // Exactly the max is fine.
        assert!(sanitize_device(&"x".repeat(DEVICE_MAX_LEN)).is_ok());
    }

    #[test]
    fn default_device_is_always_a_valid_worker_label() {
        // Whatever the host env, the default must itself pass the strict sanitizer
        // (so the printed login suffix is always a legal worker name).
        let d = default_device();
        assert!(!d.is_empty());
        assert!(sanitize_device(&d).is_ok(), "default device `{d}` must be a valid label");
    }

    #[test]
    fn companion_lane_only_pearlhash() {
        assert_eq!(resolve_companion_lane("prl").unwrap(), Lane::GpuPrl);
        assert_eq!(resolve_companion_lane("gpu").unwrap(), Lane::GpuPrl);
        assert_eq!(resolve_companion_lane("ALPHA").unwrap(), Lane::GpuAlpha);
        // XMR / RVN are rejected (open enrollment — no companion).
        assert!(resolve_companion_lane("xmr").is_err());
        assert!(resolve_companion_lane("cpu").is_err());
        assert!(resolve_companion_lane("rvn").is_err());
        assert!(resolve_companion_lane("nonsense").is_err());
    }

    #[test]
    fn stratum_port_is_lane_specific() {
        assert_eq!(stratum_port(Lane::GpuPrl), 3340);
        assert_eq!(stratum_port(Lane::GpuAlpha), 3341);
    }

    /// The address the companion enrolls must be the one the LOCAL signing key derives.
    /// When they match (the normal path — `--address` omitted, or `--address` set to
    /// your own identity) the guard proceeds with ZERO behavior change.
    #[test]
    fn address_matching_signer_is_allowed() {
        let a = "a2uJXaVk7Zx4fgk9aRLnhiD2RdpAP4usJxKXpN4vh4hDNoP1C";
        // No override + equal → proceed (the default, unchanged path).
        assert!(check_address_matches_signer(a, a, false).is_ok());
        // Explicit --address equal to the signer → also fine.
        assert!(check_address_matches_signer(a, a, true).is_ok());
    }

    /// The BUG this fixes: a `--address` that isn't the local signing identity used to
    /// enroll silently, PoP-fail, and loop on `code:24` forever. Now it's a LOUD,
    /// actionable usage error (names BOTH addresses, points at the real fix, and
    /// disambiguates the separate PRL cashback address). Asserts only on lang-invariant
    /// substrings, so it needs no lang lock and is robust under parallel test threads.
    #[test]
    fn address_not_matching_signer_is_a_loud_error_not_silent() {
        let asked = "a2uJXaVk7Zx4fgk9aRLnhiD2RdpAP4usJxKXpN4vh4hDNoP1C";
        let signer = "a2vDifferentSignerAddressForThisUnitTestOnlyXXXXXXX";
        let err = check_address_matches_signer(asked, signer, true).unwrap_err();
        // Loud (non-empty) + names both addresses so the user sees the mix-up.
        assert!(!err.is_empty());
        assert!(err.contains(asked), "must name the requested address: {err}");
        assert!(err.contains(signer), "must name the signing address: {err}");
        // Explains the failure mode (not a silent dead-end) and the real fix.
        assert!(err.contains("code:24"), "must name the symptom: {err}");
        assert!(err.contains("--address"), "must reference the offending flag: {err}");
        assert!(err.contains("identity --import"), "must point at switching identity: {err}");
        // Disambiguates the SEPARATE PRL cashback address.
        assert!(err.contains("--set-prl-payout"), "must disambiguate the PRL payout address: {err}");
    }

    /// The "should never happen" pointer-vs-keystore drift (no `--address`): still a
    /// LOUD error, never a silent PoP failure. The hint is about re-importing, not
    /// about dropping --address (there is none).
    #[test]
    fn address_mismatch_without_override_still_errors_clearly() {
        let asked = "a2uJXaVk7Zx4fgk9aRLnhiD2RdpAP4usJxKXpN4vh4hDNoP1C";
        let signer = "a2vSomeOtherSignerAddressForPointerDriftCaseXXXXXXX";
        let err = check_address_matches_signer(asked, signer, false).unwrap_err();
        assert!(err.contains(asked) && err.contains(signer));
        assert!(err.contains("code:24"), "must name the symptom: {err}");
        assert!(err.contains("identity --import"), "must point at re-importing: {err}");
    }

    #[test]
    fn refresh_interval_stays_strictly_inside_the_ttl() {
        let ttl = OOB_ALLOWLIST_TTL.as_secs();
        // The default is well inside the TTL.
        assert!(DEFAULT_REFRESH_SECS < ttl);
        assert!(safe_refresh_interval(DEFAULT_REFRESH_SECS).as_secs() < ttl);
        // A caller asking for something >= TTL is clamped to <= TTL/2 (a missed
        // refresh still lands with the pair valid) — never at/over the TTL.
        let huge = safe_refresh_interval(ttl * 10);
        assert!(huge.as_secs() <= ttl / 2);
        assert!(huge.as_secs() < ttl);
        // A tiny value is floored (don't hammer the control plane).
        assert!(safe_refresh_interval(1).as_secs() >= 30);
        // A reasonable value passes through unchanged.
        assert_eq!(safe_refresh_interval(600).as_secs(), 600);
    }

    /// STRUCTURAL PROOF the companion enrolls but NEVER spawns a miner: its source
    /// references the PoP core but none of the miner-spawn machinery (binary
    /// resolution, launch-plan builders, or the supervisor). A regression that wired
    /// the companion to actually run SRBMiner would trip this.
    #[test]
    fn companion_source_never_spawns_a_miner() {
        let src = include_str!("companion.rs");
        // It DOES use the possession-proof handshake…
        assert!(src.contains("establish_pop"), "companion must use the PoP handshake");
        // …but NEVER the miner-spawn surface.
        for forbidden in [
            "resolve_miner_binary",
            "build_srbminer",
            "build_alphaminer",
            "LaneSupervisor",
            "EngineCommand::Start",
            "Command::Start",
        ] {
            // Allow the substring inside this very assertion list by checking only
            // lines that are not this test's own literal array.
            let hits: Vec<&str> = src
                .lines()
                .filter(|l| l.contains(forbidden) && !l.contains("forbidden") && !l.trim_start().starts_with('"'))
                .collect();
            assert!(
                hits.is_empty(),
                "companion must not reference `{forbidden}` (it must never spawn a miner): {hits:?}"
            );
        }
    }

    /// HONESTY GATE: the connection banner + status line carry no fiat / earnings
    /// token and never a `prl1p` collection address / upstream pool / core IP.
    #[test]
    fn companion_output_is_credit_only_and_leaks_no_secrets() {
        let _g = LANG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for lang in [Lang::En, Lang::Zh] {
            i18n::set_lang(lang);
            // Drive the two user-facing renderers with synthetic values (no key, no net).
            let addr = "a2uJXaVk7Zx4fgk9aRLnhiD2RdpAP4usJxKXpN4vh4hDNoP1C";
            let banner = capture_banner(Lane::GpuPrl, addr, "rig-1", "asia.aliceprotocol.org", 3340);
            let status = capture_status();
            for body in [banner.to_lowercase(), status.to_lowercase()] {
                for forbidden in ["$", "usd", "fiat", "paid", "earned", "已发放", "收益", "利润"] {
                    assert!(
                        !body.contains(&forbidden.to_lowercase()),
                        "companion output must not contain `{forbidden}` (credit-only honesty gate)"
                    );
                }
                assert!(!body.contains("prl1p"), "collection address leaked: {body}");
                assert!(!body.contains("herominers"), "upstream pool leaked");
                assert!(!body.contains("203.0.113"), "core IP leaked");
            }
        }
        i18n::set_lang(Lang::En);
    }

    // ── test helpers that build the exact user strings without stdout/network ──

    /// Rebuild the connection banner text (mirrors `print_connection_banner`'s copy)
    /// so the honesty gate can scan it deterministically.
    fn capture_banner(lane: Lane, address: &str, device: &str, region_host: &str, port: u16) -> String {
        format!(
            "{}\n{}\n  {}: {region_host} : {port}\n  {}: {address}.{device}\n  {}\n  {}\n({})",
            tr!("Alice Miner — companion (bring-your-own miner)", "Alice Miner —— 伴侣模式(自带矿机)"),
            tr!("Point your OWN pearlhash miner at this relay:", "把你自己的 pearlhash 矿机指向此中继:"),
            tr!("pool", "矿池"),
            tr!("login (user)", "登录名(用户)"),
            tr!("anything (this companion holds the authorization)", "任意值(授权由本伴侣持有)"),
            tr!("Your private key stays on THIS machine — it never touches the miner.", "你的私钥留在本机 —— 绝不接触矿机。"),
            lane.cli_lane_arg(),
        )
    }

    fn capture_status() -> String {
        format!(
            "{} {} {}",
            tr!("in allowlist", "已在允许名单"),
            tr!("enroll sent (confirm pending)", "已发送注册(确认待定)"),
            tr!("Companion stopped.", "伴侣模式已停止。"),
        )
    }

    static LANG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
}
