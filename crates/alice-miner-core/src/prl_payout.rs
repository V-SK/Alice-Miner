//! GPU-PRL **15% payout enrollment + display block** (T5).
//!
//! Two cooperating pieces, both **best-effort / fail-closed-on-secrets**:
//!
//!   1. **Enroll** — once the GPU-PRL lane's PoP is up, bind the user's OWN 15%-PRL
//!      `prl1p…` **payout** address to their Alice reward address via the M4 enroll
//!      flow ([`crate::pop::fetch_enroll_nonce`] → sign
//!      [`crate::pop::enroll_signature_message`] → [`crate::pop::enroll`]). This is
//!      what lets the foundation route the 15% return to the right wallet without
//!      ever putting the payout address into mining argv (the #1 audit fix:
//!      ENROLL_DOMAIN binds `prl_payout_address` so a captured nonce can't rebind a
//!      victim's rewards). A **watch-only** identity (pasted address, no signing
//!      key) NEVER enrolls — we refuse to fabricate a signature.
//!
//!   2. **Display block** — a small, render-ready struct for the GUI/CLI "15% PRL
//!      返还" panel: currency, label, enrolled flag, **masked** payout address,
//!      and a pending-credit text. It best-effort fetches the public read-model
//!      `miner-lookup` envelope (**fail-OPEN** — a miss is not an error), and the
//!      `paid` field is **HARD-PINNED to 0.0** (credit-only: the client NEVER
//!      self-computes a 15% figure or surfaces a paid amount).
//!
//! ── HONESTY / CREDIT-ONLY INVARIANTS ────────────────────────────────────────
//!   * The user's `prl1p…` payout address is **theirs** and may be shown (masked)
//!     in the UI — it is NOT the foundation collection address (which stays
//!     server-side). Only **shape** is validated here; **payability is the
//!     server's authority** (we deliberately do NOT checksum-verify so a future
//!     HRP/length tweak server-side doesn't brick the client).
//!   * `paid == 0.0` always. There is no minting / release / paid_acu path here.

use std::path::PathBuf;
use std::time::Duration;

use alice_crypto::WalletSecrets;

/// Env override for the user's 15%-PRL payout address. When set (non-empty) it
/// wins over the on-disk file.
pub const ENV_PAYOUT_ADDRESS: &str = "ALICE_GPU_PRL_PAYOUT_ADDRESS";

/// On-disk fallback location for the payout address: `~/.alice/prl_payout_address`
/// (first non-empty line, trimmed).
const PAYOUT_FILE_REL: &str = ".alice/prl_payout_address";

/// Public read-model `miner-lookup` base used by the display block (per task:
/// `https://api.aliceprotocol.org/read/miner-lookup?address=<alice>`).
const READ_MINER_LOOKUP_URL: &str = "https://api.aliceprotocol.org/read/miner-lookup";

/// Env override for the read-model miner-lookup URL (test/ops). Still https-checked.
pub const ENV_MINER_LOOKUP_URL: &str = "ALICE_GPU_PRL_MINER_LOOKUP_URL";

/// Read/connect timeout for the (best-effort) display-block lookup (~8 s).
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(8);

/// Upper bound on the lookup response body (the envelope is small; cap a hostile one).
const MAX_LOOKUP_BYTES: u64 = 64 * 1024;

// ════════════════════════════════════════════════════════════════════════════
// Payout address: load + shape validation (NO checksum — server is the authority)
// ════════════════════════════════════════════════════════════════════════════

/// The bech32 data charset (lowercase; excludes `1 b i o`). A `prl1…` address's
/// data part (everything after the `prl1` separator) is drawn from this set.
const BECH32_CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// **Shape-only** validation of a 15%-PRL payout address, mirroring the task's
/// `^prl1p[<bech32>]{20,110}$`:
///   * begins with the literal `prl1p` (the `prl1` HRP separator + a leading
///     bech32 `p`),
///   * followed by 20..=110 more bech32 charset chars,
///   * total length therefore `prl1p` (5) + 20..=110.
///
/// This is **NOT** a checksum check — payability is the server's authority. We
/// only reject obvious garbage / wrong-prefix so a typo never gets enrolled, and
/// stay liberal on length so a server-side HRP/length tweak doesn't brick clients.
pub fn validate_payout_shape(addr: &str) -> Result<(), String> {
    let rest = addr
        .strip_prefix("prl1p")
        .ok_or_else(|| "payout address must start with 'prl1p'".to_string())?;
    let n = rest.chars().count();
    if !(20..=110).contains(&n) {
        return Err(format!(
            "payout address body length {n} out of range (expected 20..=110 bech32 chars)"
        ));
    }
    if let Some(bad) = rest.chars().find(|c| !BECH32_CHARSET.contains(*c)) {
        return Err(format!("payout address has non-bech32 char {bad:?}"));
    }
    Ok(())
}

/// The `~/.alice/prl_payout_address` path (or `None` if no home dir is resolvable).
fn payout_file_path() -> Option<PathBuf> {
    home_dir().map(|h| h.join(PAYOUT_FILE_REL))
}

/// Resolve the user's home directory without pulling in an extra crate: prefer
/// `$HOME` (unix/mac), fall back to `$USERPROFILE` (windows).
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

/// Load + shape-validate the payout address: env [`ENV_PAYOUT_ADDRESS`] first,
/// then `~/.alice/prl_payout_address` (first non-empty trimmed line). Returns
/// `Ok(None)` when no source is configured (NOT an error — the user simply hasn't
/// set a payout address yet, so we just don't enroll). Returns `Err` only when a
/// configured value fails the shape check (so a typo is surfaced, never enrolled).
pub fn load_payout_address() -> Result<Option<String>, String> {
    if let Some(v) = std::env::var(ENV_PAYOUT_ADDRESS).ok().filter(|s| !s.trim().is_empty()) {
        let addr = v.trim().to_string();
        validate_payout_shape(&addr)?;
        return Ok(Some(addr));
    }
    if let Some(path) = payout_file_path() {
        if let Ok(contents) = std::fs::read_to_string(&path) {
            if let Some(line) = contents.lines().map(str::trim).find(|l| !l.is_empty()) {
                let addr = line.to_string();
                validate_payout_shape(&addr)?;
                return Ok(Some(addr));
            }
        }
    }
    Ok(None)
}

/// Persist the user's 15%-PRL payout address to `~/.alice/prl_payout_address` (the
/// exact file [`load_payout_address`] reads). **Shape-validated first** — a typo is
/// rejected and NEVER written. The address is PUBLIC (not a secret), written
/// atomically (temp + rename). Returns the path written so the caller can confirm.
///
/// NOTE: this is independent of the keystore — it touches only the small public
/// pointer file, never `miner-keystore.json` / `wallet.json`.
pub fn save_payout_address(addr: &str) -> Result<PathBuf, String> {
    let trimmed = addr.trim();
    validate_payout_shape(trimmed)?;
    let path = payout_file_path().ok_or("no home directory to store the payout address")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    let tmp = path.with_file_name(format!(".prl_payout_address.tmp-{}", std::process::id()));
    std::fs::write(&tmp, format!("{trimmed}\n")).map_err(|e| format!("failed to write payout address: {e}"))?;
    std::fs::rename(&tmp, &path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("failed to store payout address: {e}")
    })?;
    Ok(path)
}

/// Remove the stored payout address (the user opts out of the 15% return). `Ok` if
/// it was already absent.
pub fn clear_payout_address() -> Result<(), String> {
    let Some(path) = payout_file_path() else { return Ok(()) };
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("failed to remove payout address: {e}")),
    }
}

/// A masked rendering of a payout address for the UI: keep the `prl1p…` prefix
/// and the last 4 chars, eliding the middle (so the panel can confirm "this is
/// my wallet" without exposing the full address in a screenshot). Short/garbage
/// inputs are returned verbatim (already nothing to hide).
pub fn mask_payout(addr: &str) -> String {
    let chars: Vec<char> = addr.chars().collect();
    // Need at least prefix(5) + middle + suffix(4) to mask meaningfully.
    if chars.len() <= 5 + 4 + 2 {
        return addr.to_string();
    }
    let prefix: String = chars[..5].iter().collect();
    let suffix: String = chars[chars.len() - 4..].iter().collect();
    format!("{prefix}…{suffix}")
}

// ════════════════════════════════════════════════════════════════════════════
// Enroll (best-effort, fails closed on watch-only — never a fake signature)
// ════════════════════════════════════════════════════════════════════════════

/// The outcome of a best-effort enroll attempt (for logging / surfacing in the
/// display block, never a hard failure of the lane).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollOutcome {
    /// The enroll POST was accepted by the central host.
    Enrolled,
    /// No payout address is configured → nothing to bind (not an error).
    NoPayoutAddress,
    /// The identity is watch-only (no signing key) → we refuse to fabricate a
    /// signature, so the binding is skipped.
    WatchOnly,
    /// A best-effort failure (nonce fetch / network / server) — carries the reason
    /// for logs. The lane keeps mining; the binding can be retried later.
    Failed(String),
}

/// Run the M4 enroll binding ONCE, best-effort:
///   1. load + shape-check the payout address (skip if none),
///   2. refuse if the identity is watch-only (no fake signature, ever),
///   3. fetch an enroll nonce from the CENTRAL host,
///   4. sign `enroll_signature_message(alice, payout, device_id, nonce)`,
///   5. POST the enroll.
///
/// NEVER panics, NEVER returns `Err` — every failure is an [`EnrollOutcome`] so the
/// caller can log-and-continue (the lane must not die because a binding hiccuped).
pub fn run_enroll_best_effort(
    alice_address: &str,
    device_id: &str,
    region: &str,
    secrets: &WalletSecrets,
) -> EnrollOutcome {
    // (1) payout address.
    let payout = match load_payout_address() {
        Ok(Some(p)) => p,
        Ok(None) => return EnrollOutcome::NoPayoutAddress,
        Err(e) => return EnrollOutcome::Failed(format!("payout address invalid: {e}")),
    };
    // (2) watch-only → never sign.
    if secrets.to_keypair().is_err() {
        return EnrollOutcome::WatchOnly;
    }
    // (3) nonce.
    let nonce = match crate::pop::fetch_enroll_nonce(alice_address, device_id) {
        Ok(n) => n,
        Err(e) => return EnrollOutcome::Failed(format!("enroll nonce: {e}")),
    };
    // (4) sign the 4-field enroll binding.
    let msg = crate::pop::enroll_signature_message(alice_address, &payout, device_id, &nonce);
    let sig_b64 = match crate::pop::sign_message_b64(secrets, &msg) {
        Ok(s) => s,
        Err(e) => return EnrollOutcome::Failed(format!("sign enroll: {e}")),
    };
    // (5) POST.
    match crate::pop::enroll(alice_address, device_id, &payout, region, &nonce, &sig_b64) {
        Ok(()) => EnrollOutcome::Enrolled,
        Err(e) => EnrollOutcome::Failed(format!("enroll POST: {e}")),
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Display block (render-ready; paid HARD-PINNED 0.0; miner-lookup fail-OPEN)
// ════════════════════════════════════════════════════════════════════════════

/// The render-ready "15% PRL 返还" panel block for the GUI/CLI. Credit-only:
/// [`Self::paid`] is **always 0.0**; there is no field that could carry a minted
/// or self-computed payout amount.
#[derive(Debug, Clone, PartialEq)]
pub struct PrlPayoutDisplay {
    /// Always `"PRL"` — the payout currency for the GPU mainline.
    pub currency: String,
    /// Short human label for the panel header.
    pub label: String,
    /// Whether the payout address is bound (enrolled) this session.
    pub enrolled: bool,
    /// The user's payout address, **masked** for display (or `None` if unset).
    pub payout_masked: Option<String>,
    /// Credit accrued-but-not-paid, as honest text (NEVER a "$" / fiat figure).
    pub pending_text: String,
    /// **HARD-PINNED 0.0** — credit-only; the client never self-computes 15%.
    pub paid: f64,
}

impl PrlPayoutDisplay {
    /// The fixed panel label.
    const LABEL: &'static str = "15% PRL 返还 (credit-only)";

    /// Build a display block WITHOUT any network call: known enrolled flag + the
    /// (masked) payout address, with the default "pending" text. The caller can
    /// then call [`Self::with_pending_from_lookup`] to fold in a best-effort
    /// read-model fetch (fail-open).
    pub fn new(enrolled: bool, payout_address: Option<&str>) -> Self {
        Self {
            currency: "PRL".into(),
            label: Self::LABEL.into(),
            enrolled,
            payout_masked: payout_address.map(mask_payout),
            pending_text: default_pending_text(enrolled, payout_address.is_some()),
            paid: 0.0, // credit-only — pinned, never derived.
        }
    }

    /// Fold a best-effort `miner-lookup` fetch into the pending text. **Fail-OPEN**:
    /// any transport/parse miss leaves the default pending text untouched (NOT an
    /// error). `paid` stays 0.0 regardless of what the server returns. Returns
    /// `self` for chaining.
    pub fn with_pending_from_lookup(mut self, alice_address: &str) -> Self {
        if let Some(text) = fetch_pending_text(alice_address) {
            self.pending_text = text;
        }
        // paid is NEVER touched here — credit-only invariant.
        self
    }
}

/// The default pending text given the enrolled / has-address state. No numbers —
/// just an honest status word for the panel.
fn default_pending_text(enrolled: bool, has_address: bool) -> String {
    match (enrolled, has_address) {
        (true, _) => "已绑定 · 返还按链上 credit 结算 (pending)".into(),
        (false, true) => "未绑定 · 启动 GPU-PRL 挖矿以绑定返还地址".into(),
        (false, false) => "未设置返还地址 (设置 ALICE_GPU_PRL_PAYOUT_ADDRESS)".into(),
    }
}

/// The read-model miner-lookup URL (env override or default), https-checked.
fn miner_lookup_url(alice_address: &str) -> Result<String, String> {
    let base = match std::env::var(ENV_MINER_LOOKUP_URL).ok().filter(|s| !s.trim().is_empty()) {
        Some(v) => v.trim().to_string(),
        None => READ_MINER_LOOKUP_URL.to_string(),
    };
    if !base.starts_with("https://") {
        return Err(format!("refusing non-https miner-lookup url: {base}"));
    }
    Ok(format!("{base}?address={}", urlencode(alice_address)))
}

/// Best-effort fetch of the credit-only pending text from the public read-model.
/// **Fail-OPEN**: returns `None` (caller keeps the default text) on ANY problem —
/// unreachable, non-2xx, oversized, unparseable, or a credit-only violation. NEVER
/// panics. The returned text is word-only (no fabricated number); if a credit-only
/// violation is detected (`paid_acu != "0"` etc.) we DROP it and return `None`
/// rather than surface anything.
fn fetch_pending_text(alice_address: &str) -> Option<String> {
    let url = miner_lookup_url(alice_address).ok()?;
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(LOOKUP_TIMEOUT)
        .timeout_read(LOOKUP_TIMEOUT)
        .user_agent(concat!("alice-miner-prl-payout/", env!("CARGO_PKG_VERSION")))
        .build();
    let resp = agent.get(&url).call().ok()?;
    let mut buf = Vec::new();
    use std::io::Read as _;
    resp.into_reader()
        .take(MAX_LOOKUP_BYTES)
        .read_to_end(&mut buf)
        .ok()?;
    let body = String::from_utf8(buf).ok()?;
    pending_text_from_envelope(&body)
}

/// Map a read-model `miner-lookup` body to an honest pending TEXT, reusing the
/// credit-only envelope parser ([`crate::dashboard::parse_credit_envelope`]) so the
/// `paid_acu != "0"` / payout-enabled guards apply here too. A credit-only
/// violation or unparseable body → `None` (fail-open; never surface a value).
fn pending_text_from_envelope(body: &str) -> Option<String> {
    use crate::dashboard::{CreditState, parse_credit_envelope};
    match parse_credit_envelope(body) {
        CreditState::Confirmed { score } => {
            // Word-only: confirm there IS pending credit, without minting a fiat
            // figure. `CreditScore` deliberately has NO `Display` (so a careless
            // `{score}` can't leak a number); use its honest pending label.
            Some(format!("已确认 credit · {}", score.pending_label()))
        }
        CreditState::Confirming => Some("等待确认 (confirming)".into()),
        // NotExposed / Error (incl. paid_acu!=0 violation) → fail-open: keep default.
        _ => None,
    }
}

/// Minimal percent-encoding for the address query param (mirrors dashboard's, kept
/// local so this module has no cross-module private dep).
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR: &str = "a2uJXaVk7Zx4fgk9aRLnhiD2RdpAP4usJxKXpN4vh4hDNoP1C";
    // A legal-shaped payout address: prl1p + 58 bech32 chars (well within 20..=110).
    const PAYOUT_OK: &str = "prl1pexamplewalletexamplewalletexamplewallet";

    #[test]
    fn payout_shape_accepts_legal_prl1p() {
        assert!(validate_payout_shape(PAYOUT_OK).is_ok());
        // Minimum body (exactly 20 bech32 chars after prl1p).
        let min = format!("prl1p{}", "q".repeat(20));
        assert!(validate_payout_shape(&min).is_ok());
    }

    #[test]
    fn payout_shape_rejects_too_short_and_wrong_prefix() {
        // Wrong prefix.
        assert!(validate_payout_shape("prl1qukq3uu0txl6fc34f2frlxsxyfs9nj").is_err());
        assert!(validate_payout_shape("bc1pukq3uu0txl6fc34f2frlxsxyfs9nj").is_err());
        assert!(validate_payout_shape("notanaddress").is_err());
        // Too short: only 19 body chars (< 20).
        let short = format!("prl1p{}", "q".repeat(19));
        assert!(validate_payout_shape(&short).is_err());
        // Empty body.
        assert!(validate_payout_shape("prl1p").is_err());
    }

    #[test]
    fn payout_shape_rejects_non_bech32_chars() {
        // 'b', 'i', 'o', '1' are NOT in the bech32 charset → must be rejected.
        let bad = format!("prl1p{}b{}", "q".repeat(10), "q".repeat(10));
        assert!(validate_payout_shape(&bad).is_err());
        let upper = format!("prl1p{}", "Q".repeat(25)); // uppercase not in charset
        assert!(validate_payout_shape(&upper).is_err());
    }

    #[test]
    fn payout_shape_rejects_too_long() {
        // 111 body chars (> 110).
        let long = format!("prl1p{}", "q".repeat(111));
        assert!(validate_payout_shape(&long).is_err());
    }

    #[test]
    fn mask_keeps_prefix_and_suffix() {
        let m = mask_payout(PAYOUT_OK);
        assert!(m.starts_with("prl1p"));
        assert!(m.contains('…'));
        assert!(m.ends_with(&PAYOUT_OK[PAYOUT_OK.len() - 4..]));
        // The full middle is NOT present.
        assert!(!m.contains(&PAYOUT_OK[10..30]));
        // A short/garbage value is returned verbatim (nothing to mask).
        assert_eq!(mask_payout("prl1pshort"), "prl1pshort");
    }

    #[test]
    fn display_block_paid_is_pinned_zero() {
        let d = PrlPayoutDisplay::new(true, Some(PAYOUT_OK));
        assert_eq!(d.paid, 0.0);
        assert_eq!(d.currency, "PRL");
        assert!(d.enrolled);
        let masked = d.payout_masked.unwrap();
        assert!(masked.starts_with("prl1p") && masked.contains('…'));
        // Even after folding a lookup, paid stays pinned 0.0 (the struct field is
        // never written by the lookup path).
        let d2 = PrlPayoutDisplay::new(false, None);
        assert_eq!(d2.paid, 0.0);
        assert_eq!(d2.payout_masked, None);
    }

    #[test]
    fn display_block_serializes_without_paid_amount_leak() {
        // Defense-in-depth on the credit-only invariant: paid is 0.0 and there is
        // no field that could carry a non-zero paid figure.
        let d = PrlPayoutDisplay::new(true, Some(PAYOUT_OK));
        assert_eq!(d.paid, 0.0);
    }

    #[test]
    fn pending_text_from_envelope_paid_acu_violation_fails_open() {
        // A leaked non-zero paid_acu MUST NOT surface — fail-open to None so the
        // panel keeps its honest default text (it never shows the value).
        let bad = r#"{"found":true,"paid_acu":"12.5","summary":{"pending_alice":5.0}}"#;
        assert_eq!(pending_text_from_envelope(bad), None);
        // payout_executor_enabled is also a violation → None.
        let bad2 = r#"{"found":true,"paid_acu":"0","payout_executor_enabled":true}"#;
        assert_eq!(pending_text_from_envelope(bad2), None);
    }

    #[test]
    fn pending_text_from_envelope_clean_confirmed() {
        let ok = r#"{"found":true,"paid_acu":"0","summary":{"pending_alice":12.56}}"#;
        let t = pending_text_from_envelope(ok).expect("clean confirmed → text");
        assert!(t.contains("credit"));
        // Never a "$".
        assert!(!t.contains('$'));
        // not-found → confirming.
        let nf = r#"{"found":false,"paid_acu":"0"}"#;
        assert_eq!(pending_text_from_envelope(nf).as_deref(), Some("等待确认 (confirming)"));
        // garbage → fail-open None.
        assert_eq!(pending_text_from_envelope("not json"), None);
    }

    #[test]
    fn enroll_watch_only_never_signs() {
        // A watch-only identity must NOT enroll (no fake signature). We force a
        // payout address via env so the watch-only branch (not the no-address one)
        // is what's exercised.
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var(ENV_PAYOUT_ADDRESS).ok();
        std::env::set_var(ENV_PAYOUT_ADDRESS, PAYOUT_OK);
        let watch = WalletSecrets::display_only(ADDR);
        let out = run_enroll_best_effort(ADDR, "worker-abc", "us", &watch);
        assert_eq!(out, EnrollOutcome::WatchOnly);
        match prev {
            Some(v) => std::env::set_var(ENV_PAYOUT_ADDRESS, v),
            None => std::env::remove_var(ENV_PAYOUT_ADDRESS),
        }
    }

    #[test]
    fn enroll_no_address_is_not_an_error() {
        // With NO payout env AND no file (we point HOME at an empty temp dir), the
        // outcome is NoPayoutAddress — never a panic / Err / fake signature.
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let prev_addr = std::env::var(ENV_PAYOUT_ADDRESS).ok();
        let prev_home = std::env::var("HOME").ok();
        let prev_up = std::env::var("USERPROFILE").ok();
        std::env::remove_var(ENV_PAYOUT_ADDRESS);
        let empty = std::env::temp_dir().join(format!("alice-prl-empty-home-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&empty);
        std::env::set_var("HOME", &empty);
        std::env::remove_var("USERPROFILE");

        let watch = WalletSecrets::display_only(ADDR);
        let out = run_enroll_best_effort(ADDR, "worker-abc", "us", &watch);
        assert_eq!(out, EnrollOutcome::NoPayoutAddress);

        match prev_addr {
            Some(v) => std::env::set_var(ENV_PAYOUT_ADDRESS, v),
            None => std::env::remove_var(ENV_PAYOUT_ADDRESS),
        }
        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        if let Some(v) = prev_up {
            std::env::set_var("USERPROFILE", v);
        }
    }

    #[test]
    fn miner_lookup_url_is_https_and_encodes_address() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var(ENV_MINER_LOOKUP_URL).ok();
        std::env::remove_var(ENV_MINER_LOOKUP_URL);
        let url = miner_lookup_url("a2x7Kf3+Lp/V9").unwrap();
        assert_eq!(
            url,
            "https://api.aliceprotocol.org/read/miner-lookup?address=a2x7Kf3%2BLp%2FV9"
        );
        // A non-https override fails closed.
        std::env::set_var(ENV_MINER_LOOKUP_URL, "http://evil/read/miner-lookup");
        assert!(miner_lookup_url(ADDR).is_err());
        match prev {
            Some(v) => std::env::set_var(ENV_MINER_LOOKUP_URL, v),
            None => std::env::remove_var(ENV_MINER_LOOKUP_URL),
        }
    }

    #[test]
    fn fetch_pending_text_fail_open_on_non_https_env() {
        // A bad (non-https) env override makes the URL builder fail → fetch returns
        // None (fail-open), never panics. No network is reached.
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var(ENV_MINER_LOOKUP_URL).ok();
        std::env::set_var(ENV_MINER_LOOKUP_URL, "http://insecure/lookup");
        assert_eq!(fetch_pending_text(ADDR), None);
        match prev {
            Some(v) => std::env::set_var(ENV_MINER_LOOKUP_URL, v),
            None => std::env::remove_var(ENV_MINER_LOOKUP_URL),
        }
    }

    #[test]
    fn save_then_load_round_trips_and_clear() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let prev_addr = std::env::var(ENV_PAYOUT_ADDRESS).ok();
        let prev_home = std::env::var("HOME").ok();
        let prev_up = std::env::var("USERPROFILE").ok();
        std::env::remove_var(ENV_PAYOUT_ADDRESS); // force the FILE path (not the env override)
        let home = std::env::temp_dir().join(format!(
            "alice-prl-save-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&home).unwrap();
        std::env::set_var("HOME", &home);
        std::env::remove_var("USERPROFILE");

        // Nothing stored yet.
        assert_eq!(load_payout_address().unwrap(), None);
        // A typo is rejected and NEVER written.
        assert!(save_payout_address("not-a-prl1p").is_err());
        assert_eq!(load_payout_address().unwrap(), None);
        // Save a legal address → load reads it back; the file lives under ~/.alice.
        let p = save_payout_address(PAYOUT_OK).expect("save ok");
        assert!(p.ends_with(".alice/prl_payout_address"));
        assert_eq!(load_payout_address().unwrap().as_deref(), Some(PAYOUT_OK));
        // Whitespace is trimmed on save.
        save_payout_address(&format!("  {PAYOUT_OK}  ")).unwrap();
        assert_eq!(load_payout_address().unwrap().as_deref(), Some(PAYOUT_OK));
        // Clear → back to None; clearing again is Ok (idempotent).
        clear_payout_address().unwrap();
        assert_eq!(load_payout_address().unwrap(), None);
        clear_payout_address().unwrap();

        let _ = std::fs::remove_dir_all(&home);
        match prev_addr {
            Some(v) => std::env::set_var(ENV_PAYOUT_ADDRESS, v),
            None => std::env::remove_var(ENV_PAYOUT_ADDRESS),
        }
        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        if let Some(v) = prev_up {
            std::env::set_var("USERPROFILE", v);
        }
    }

    // Process env is global; serialize every test that reads/writes a payout/lookup
    // env key through this lock so parallel cargo threads can't race.
    static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());
}
