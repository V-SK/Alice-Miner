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
//!     server-side). **Payability is still the server's authority** — but as of
//!     2026-08-04 the server enrol route performs a FULL bech32m verify, so the
//!     client now verifies the SAME checksum **before it signs** (AM-SEC-008).
//!     Rationale for the reversal of the old "shape-only" stance: a mistyped
//!     character used to be signed, POSTed, and only rejected server-side — the
//!     user learned about the typo (if ever) hours later, from a missing rebate.
//!     Catching it locally costs nothing and cannot brick a client, because the
//!     `prl1p…` prefix pins witness-version 1, which BIP-350 defines as bech32m.
//!   * `paid == 0.0` always. There is no minting / release / paid_acu path here.

use std::path::PathBuf;
use std::time::Duration;

use alice_crypto::WalletSecrets;

/// Env override for the user's 15%-PRL payout address. When set (non-empty) it
/// wins over the on-disk file.
pub const ENV_PAYOUT_ADDRESS: &str = "ALICE_GPU_PRL_PAYOUT_ADDRESS";

/// On-disk fallback location for the payout address: `prl_payout_address` inside the
/// Alice home (`~/.alice`, or `$ALICE_IDENTITY_DIR` when set) — first non-empty line,
/// trimmed. See [`payout_file_path`].
const PAYOUT_FILE_NAME: &str = "prl_payout_address";

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

/// **Shape-only** validation of a 15%-PRL payout address, mirroring the server's
/// `^prl1p[<bech32>]{20,103}$` (`alice_acp.prl_wallet.credentials.PRL_ADDRESS_RE`):
///   * begins with the literal `prl1p` (the `prl1` HRP separator + a leading
///     bech32 `p`),
///   * followed by 20..=103 more bech32 charset chars,
///   * total length therefore `prl1p` (5) + 20..=103.
///
/// This is **NOT** a checksum check and NOT a payability check — it is the cheap
/// pre-filter. Every write/sign path calls [`validate_payout_address`], which adds
/// the checksum and the witness-program rule.
pub fn validate_payout_shape(addr: &str) -> Result<(), String> {
    let rest = addr
        .strip_prefix("prl1p")
        .ok_or_else(|| "payout address must start with 'prl1p'".to_string())?;
    let n = rest.chars().count();
    if !(20..=103).contains(&n) {
        return Err(format!(
            "payout address body length {n} out of range (expected 20..=103 bech32 chars)"
        ));
    }
    if let Some(bad) = rest.chars().find(|c| !BECH32_CHARSET.contains(*c)) {
        return Err(format!("payout address has non-bech32 char {bad:?}"));
    }
    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════
// bech32m checksum (BIP-350) — the SAME check the server's enroll route does
// ════════════════════════════════════════════════════════════════════════════

/// The BIP-350 bech32m constant (bech32 v1 uses `1`; witness-v1+ uses this).
const BECH32M_CONST: u32 = 0x2bc8_30a3;

/// BIP-173/350 `bech32_polymod` over 5-bit values. Self-contained (no bech32 dep,
/// matching the workspace's no-new-crate discipline — the same routine already
/// guards `gpu_alpha`'s placeholder invariant).
fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= *g;
            }
        }
    }
    chk
}

/// Verify the **bech32m checksum** of a `prl1…` address. Assumes the shape check
/// already ran (lowercase, `prl1p`-prefixed, charset-clean); returns a user-facing
/// "you probably mistyped a character" error when the checksum does not close.
///
/// A checksum failure is exactly the class of error a human makes — one wrong or
/// transposed character — and bech32m is designed to catch it. This runs BEFORE we
/// sign anything, so a typo can never reach an enroll signature.
pub fn verify_payout_checksum(addr: &str) -> Result<(), String> {
    let sep = addr
        .rfind('1')
        .ok_or_else(|| "payout address has no bech32 separator".to_string())?;
    let (hrp, data) = (&addr[..sep], &addr[sep + 1..]);
    // The checksum itself is the last 6 data chars; anything shorter cannot carry one.
    if data.len() < 6 {
        return Err("payout address is too short to carry a bech32m checksum".to_string());
    }
    let mut values: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
    values.push(0);
    values.extend(hrp.bytes().map(|b| b & 31));
    for c in data.bytes() {
        match BECH32_CHARSET.bytes().position(|x| x == c) {
            Some(i) => values.push(i as u8),
            None => return Err(format!("payout address has non-bech32 char {:?}", c as char)),
        }
    }
    if bech32_polymod(&values) != BECH32M_CONST {
        return Err(crate::tr!(
            "payout address checksum is wrong — you very likely mistyped one character. Copy/paste the whole address from your PRL wallet.",
            "返还地址校验和不对 — 极可能打错了一个字符。请从你的 PRL 钱包完整复制粘贴整个地址。"
        )
        .to_string());
    }
    Ok(())
}

/// Convert a slice of 5-bit bech32 values to 8-bit bytes, **without** padding —
/// BIP-173 `convertbits(data, 5, 8, false)`. Returns `None` when the leftover bits
/// are not a strict, zero-valued remainder (i.e. the data part cannot be a whole
/// number of bytes). This is what makes a "checksum-valid but not a real witness
/// program" string fail instead of silently truncating.
fn convert_bits_5_to_8(values: &[u8]) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(values.len() * 5 / 8);
    for &v in values {
        if v >> 5 != 0 {
            return None;
        }
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    // Leftover must be < 5 bits AND all zero, else this was never a byte string.
    if bits >= 5 || ((acc << (8 - bits)) & 0xff) != 0 {
        return None;
    }
    Some(out)
}

/// Verify the **witness version + program length** — the half of the server's rule
/// that a checksum alone does not cover.
///
/// The server's ONE RULER for "can this address actually be paid" is
/// `alice_acp.prl_payout.txverify.prl_address_to_script` (also exposed as
/// `is_payable_prl_address`, and called from the enroll write boundary via
/// `assert_payable_prl_payout_address`): after the bech32m checksum it requires
/// **witness version 1 and a 32-byte program** — a BIP-86 Taproot output — because
/// that is the only script the offline Go signer will ever pay to.
///
/// Without this check the client would call a string "valid", store it, and sign an
/// enroll for it, while the server refused it — i.e. exactly the "the client says OK
/// and the money still never arrives" failure AM-SEC-008 is about. A checksum-valid
/// short address (`prl1pqqqqqqqqqqqqqqvapaqa`) is the concrete case: real bech32m,
/// zero chance of ever being paid.
pub fn verify_payout_witness_program(addr: &str) -> Result<(), String> {
    let sep = addr
        .rfind('1')
        .ok_or_else(|| "payout address has no bech32 separator".to_string())?;
    let data: Vec<u8> = addr[sep + 1..]
        .bytes()
        .map(|c| BECH32_CHARSET.bytes().position(|x| x == c).map(|i| i as u8))
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(|| "payout address has a non-bech32 char".to_string())?;
    if data.len() < 7 {
        return Err("payout address carries no witness program".to_string());
    }
    let witver = data[0];
    let program = convert_bits_5_to_8(&data[1..data.len() - 6]);
    let ok = witver == 1 && program.as_ref().is_some_and(|p| p.len() == 32);
    if !ok {
        let got = match &program {
            Some(p) => format!("v{witver}, {} bytes", p.len()),
            None => format!("v{witver}, not a whole number of bytes"),
        };
        return Err(crate::tr!(
            "payout address is not a payable PRL destination (needs a witness-v1 32-byte Taproot program; got %GOT%). The rebate can only be paid to a prl1p… Taproot address — copy the receive address from your PRL wallet.",
            "返还地址不是可支付的 PRL 目标(需要 witness-v1 32 字节 Taproot 程序;实际为 %GOT%)。返还只能打到 prl1p… Taproot 地址 —— 请从你的 PRL 钱包复制收款地址。"
        )
        .replace("%GOT%", &got));
    }
    Ok(())
}

/// **Full** validation of a payout address: [`validate_payout_shape`], THEN
/// [`verify_payout_checksum`], THEN [`verify_payout_witness_program`]. This is what
/// every write/sign path uses (AM-SEC-008); `validate_payout_shape` alone remains
/// available for cheap pre-filtering.
///
/// The three steps together are **the same standard the server applies** at its
/// enroll write boundary (shape regex + `is_payable_prl_address`). Keeping them
/// equal is the whole point: a client that says "valid" about an address the server
/// will refuse is a client that lies about where the money is going.
pub fn validate_payout_address(addr: &str) -> Result<(), String> {
    validate_payout_shape(addr)?;
    verify_payout_checksum(addr)?;
    verify_payout_witness_program(addr)
}

/// Render an address in 8-char groups so a human can actually COMPARE it against
/// their wallet before confirming. Used by the pre-sign confirmation prompt — the
/// masked form is for at-a-glance panels, this one is for verification.
pub fn format_for_confirm(addr: &str) -> String {
    let chars: Vec<char> = addr.chars().collect();
    chars
        .chunks(8)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The outcome of the "is this really your address?" gate that runs before an
/// address is stored (and therefore before it is ever signed into an enroll).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayoutConfirm {
    /// Store it — the human said yes, or passed the explicit non-interactive flag.
    Proceed,
    /// Do not store it: the human declined.
    Declined,
    /// Do not store it: nobody could be asked and no explicit flag was given.
    /// The caller must tell the user which flag to add — NEVER assume consent.
    NeedsExplicitFlag,
}

/// Pure decision for the pre-store confirmation (mirrors the keystore-overwrite
/// gate's shape so both are testable without a TTY).
///
///   * `explicit_yes` — the caller passed the "I verified the address" flag; that IS
///     the confirmation, on a TTY or not.
///   * `is_tty` + `answer` — an interactive run: only `y`/`yes` proceeds.
///   * neither — [`PayoutConfirm::NeedsExplicitFlag`]. We never infer consent from
///     silence for a value that decides where money goes.
pub fn decide_payout_confirm(is_tty: bool, explicit_yes: bool, answer: Option<&str>) -> PayoutConfirm {
    if explicit_yes {
        return PayoutConfirm::Proceed;
    }
    if !is_tty {
        return PayoutConfirm::NeedsExplicitFlag;
    }
    match answer.map(|a| a.trim().to_ascii_lowercase()) {
        Some(a) if a == "y" || a == "yes" => PayoutConfirm::Proceed,
        _ => PayoutConfirm::Declined,
    }
}

/// The `~/.alice/prl_payout_address` path.
///
/// Resolved through [`crate::settings::alice_home`], like `settings.json`, the
/// identity pointer, the ai config and the halt records — so `$ALICE_IDENTITY_DIR`
/// moves this file with the rest of `~/.alice`.
///
/// It used to read `$HOME` / `$USERPROFILE` directly and join `.alice/…` itself,
/// which made it the ONE `~/.alice` artifact that ignored the isolation env var: a
/// miner running with a separate identity dir had their payout address written into
/// their real home directory, and every test that touched this path wrote into the
/// developer's actual `$HOME`. With no override set the path is byte-identical to
/// what it always was (`alice_home()` is `dirs::home_dir()/.alice`), so nothing
/// moves for an existing install.
fn payout_file_path() -> PathBuf {
    crate::settings::alice_home().join(PAYOUT_FILE_NAME)
}

/// Load + shape-validate the payout address: env [`ENV_PAYOUT_ADDRESS`] first,
/// then `~/.alice/prl_payout_address` (first non-empty trimmed line). Returns
/// `Ok(None)` when no source is configured (NOT an error — the user simply hasn't
/// set a payout address yet, so we just don't enroll). Returns `Err` only when a
/// configured value fails the shape check (so a typo is surfaced, never enrolled).
pub fn load_payout_address() -> Result<Option<String>, String> {
    if let Some(v) = std::env::var(ENV_PAYOUT_ADDRESS).ok().filter(|s| !s.trim().is_empty()) {
        let addr = v.trim().to_string();
        validate_payout_address(&addr)?;
        return Ok(Some(addr));
    }
    if let Ok(contents) = std::fs::read_to_string(payout_file_path()) {
        if let Some(line) = contents.lines().map(str::trim).find(|l| !l.is_empty()) {
            let addr = line.to_string();
            validate_payout_address(&addr)?;
            return Ok(Some(addr));
        }
    }
    Ok(None)
}

/// Persist the user's 15%-PRL payout address to `~/.alice/prl_payout_address` (the
/// exact file [`load_payout_address`] reads). **Fully validated first** (shape +
/// bech32m checksum, [`validate_payout_address`]) — a typo is rejected and NEVER
/// written. NOTE: this function does NOT ask the human anything; the "is this
/// really your address?" confirmation is the caller's (see [`decide_payout_confirm`]),
/// because only the caller knows whether it has a terminal or an explicit flag. The address is PUBLIC (not a secret), written
/// atomically (temp + rename). Returns the path written so the caller can confirm.
///
/// NOTE: this is independent of the keystore — it touches only the small public
/// pointer file, never `miner-keystore.json` / `wallet.json`.
pub fn save_payout_address(addr: &str) -> Result<PathBuf, String> {
    let trimmed = addr.trim();
    validate_payout_address(trimmed)?;
    let path = payout_file_path();
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
    match std::fs::remove_file(payout_file_path()) {
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
    // (1b) AM-SEC-008 defense-in-depth: re-verify the FULL address (shape + bech32m
    // checksum) immediately before the signing step. `load_payout_address` already
    // validated, but this is the last line before a signature is produced, and a
    // signature over a mistyped address is exactly what we must never emit.
    if let Err(e) = validate_payout_address(&payout) {
        return EnrollOutcome::Failed(format!("payout address invalid: {e}"));
    }
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
    /// The fixed panel label, in the current CLI language. A function (not a
    /// `const`) because [`crate::tr!`] resolves the process-global language at call
    /// time and is not `const`-evaluable.
    pub fn label() -> &'static str {
        crate::tr!("15% PRL return (credit-only)", "15% PRL 返还 (credit-only)")
    }

    /// Build a display block WITHOUT any network call: known enrolled flag + the
    /// (masked) payout address, with the default "pending" text. The caller can
    /// then call [`Self::with_pending_from_lookup`] to fold in a best-effort
    /// read-model fetch (fail-open).
    pub fn new(enrolled: bool, payout_address: Option<&str>) -> Self {
        Self {
            currency: "PRL".into(),
            label: Self::label().into(),
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
///
/// The `(false, true)` line used to read "start GPU-PRL mining to bind the return
/// address", which is advice this panel can never sensibly give: the block is built
/// ONLY from a snapshot that already has a pearlhash lane in its run set
/// (`engine::build_snapshot` → `build_prl_payout_display`), so every reader of that
/// sentence was, by construction, already mining GPU-PRL. It told a miner to do the
/// thing they were doing while the real states behind it — the enrol still in
/// flight, an enrol that failed and will retry on the next start, or a watch-only
/// identity that can never sign one — went unsaid. This layer is only handed a
/// boolean, so it now states exactly what that boolean knows and nothing more.
fn default_pending_text(enrolled: bool, has_address: bool) -> String {
    match (enrolled, has_address) {
        (true, _) => crate::tr!(
            "bound · return settles by on-chain credit (pending)",
            "已绑定 · 返还按链上 credit 结算 (pending)"
        )
        .into(),
        (false, true) => crate::tr!(
            "not bound · the return address is set, but has not been bound to your reward address this session",
            "未绑定 · 返还地址已设置,但本次会话尚未把它绑定到你的奖励地址"
        )
        .into(),
        (false, false) => crate::tr!(
            "no return address set (set ALICE_GPU_PRL_PAYOUT_ADDRESS)",
            "未设置返还地址 (设置 ALICE_GPU_PRL_PAYOUT_ADDRESS)"
        )
        .into(),
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
        .tls_config(alice_release::tls::os_trust_config()) // OS trust store (Windows UnknownIssuer fix)
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
        CreditState::Confirmed { score, .. } => {
            // Word-only: confirm there IS pending credit, without minting a fiat
            // figure. `CreditScore` deliberately has NO `Display` (so a careless
            // `{score}` can't leak a number); use its honest pending label.
            let label = score.pending_label();
            Some(match crate::i18n::lang() {
                crate::i18n::Lang::En => format!("credit confirmed · {label}"),
                crate::i18n::Lang::Zh => format!("已确认 credit · {label}"),
            })
        }
        CreditState::Confirming => {
            Some(crate::tr!("awaiting confirmation (confirming)", "等待确认 (confirming)").into())
        }
        // NotExposed / UpgradeRequired / Error (incl. an inconsistent-payout drop) →
        // fail-open: keep the panel's honest default text.
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
    /// A synthetic but **fully payable** address: checksum-valid bech32m AND a
    /// witness-v1 32-byte program (program bytes `00 01 … 1f`), so it satisfies the
    /// server's `is_payable_prl_address` ruler exactly like a real wallet address.
    ///
    /// It replaces two earlier fixtures that were quietly WRONG:
    ///   * `prl1pexamplewallet…` — shape-legal, checksum-garbage (pre-AM-SEC-008);
    ///   * `prl1pqzry9x8…7kr3mc` — checksum-valid but its data part is not a whole
    ///     number of bytes, so the server would refuse it. Using it as the "OK"
    ///     fixture meant the tests certified an address that can never be paid.
    const PAYOUT_OK: &str = "prl1pqqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0ss8729k";
    /// Shape-legal, checksum-INVALID (one char off): the human-typo case.
    const PAYOUT_BAD_CKSUM: &str = "prl1pexamplewalletexamplewalletexamplewallet";
    /// Checksum-VALID and shape-legal, but **not payable**: witness v1 with an
    /// 8-byte program instead of 32. The server's enroll boundary refuses it, so the
    /// client must too — this is the case the merge review caught.
    const PAYOUT_VALID_CKSUM_UNPAYABLE: &str = "prl1pqqqqqqqqqqqqqqvapaqa";

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
        // 104 body chars (> 103) — the bound now mirrors the server's PRL_ADDRESS_RE.
        let long = format!("prl1p{}", "q".repeat(104));
        assert!(validate_payout_shape(&long).is_err());
        // 103 is still admitted by the shape pre-filter (payability is decided by the
        // checksum + witness rules, not by the length bound).
        let at_bound = format!("prl1p{}", "q".repeat(103));
        assert!(validate_payout_shape(&at_bound).is_ok());
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

    /// The unbound-with-an-address panel line must not tell the miner to start the
    /// mining they are already doing.
    ///
    /// This block is only ever built for a snapshot whose run set already contains a
    /// pearlhash lane, so "start GPU-PRL mining to bind the return address" was shown
    /// exclusively to miners who had GPU-PRL running — while the actual reason
    /// (enrol in flight, enrol failed, or a watch-only identity that cannot sign one)
    /// was never said.
    #[test]
    fn the_unbound_panel_line_does_not_tell_a_mining_rig_to_start_mining() {
        use crate::i18n::{set_lang, Lang, LANG_TEST_LOCK};
        // The language is a PROCESS global shared by every module's tests in this
        // binary, so pinning it takes the crate-wide lang lock — not just this
        // module's env guard, which would only order this test against itself.
        let _l = LANG_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let restore = crate::i18n::lang();

        set_lang(Lang::En);
        let en = PrlPayoutDisplay::new(false, Some(PAYOUT_OK)).pending_text;
        assert!(!en.contains("start GPU-PRL mining"), "no false instruction: {en}");
        assert!(en.contains("not bound"), "still says it is not bound: {en}");
        assert!(en.contains("set"), "…and that the address itself is configured: {en}");

        set_lang(Lang::Zh);
        let zh = PrlPayoutDisplay::new(false, Some(PAYOUT_OK)).pending_text;
        assert!(!zh.contains("启动 GPU-PRL 挖矿"), "no false instruction: {zh}");
        assert!(zh.contains("未绑定"), "still says it is not bound: {zh}");
        assert!(zh.contains("返还地址已设置"), "…and that the address is set: {zh}");

        // The other two states are unchanged and stay distinguishable.
        set_lang(Lang::En);
        assert!(PrlPayoutDisplay::new(true, Some(PAYOUT_OK)).pending_text.contains("bound ·"));
        assert!(PrlPayoutDisplay::new(false, None)
            .pending_text
            .contains("no return address set"));

        set_lang(restore);
    }

    #[test]
    fn display_block_serializes_without_paid_amount_leak() {
        // Defense-in-depth on the credit-only invariant: paid is 0.0 and there is
        // no field that could carry a non-zero paid figure.
        let d = PrlPayoutDisplay::new(true, Some(PAYOUT_OK));
        assert_eq!(d.paid, 0.0);
    }

    #[test]
    fn pending_text_from_envelope_inconsistent_payout_fails_open() {
        // A CONTRADICTORY payout envelope (non-zero paid_acu while the rails read OFF)
        // MUST NOT surface — fail-open to None so the panel keeps its honest default
        // text (it never shows the value). This is the retained #18 guard.
        let bad = r#"{"found":true,"paid_acu":"12.5","summary":{"pending_alice":5.0}}"#;
        assert_eq!(pending_text_from_envelope(bad), None);
        // v0.6.0 note: a rails-ON envelope with paid_acu "0" is now a LEGITIMATE credit
        // state (nothing paid yet), so it confirms — but the surfaced text is still
        // word-only (the honest pending label), NEVER a payout number. Prove no leak.
        let rails_on = r#"{"found":true,"paid_acu":"0","payout_executor_enabled":true,"summary":{"pending_alice":5.0}}"#;
        let t = pending_text_from_envelope(rails_on).expect("rails-on/paid-0 confirms credit");
        assert!(t.contains("credit"));
        assert!(!t.contains('$'), "still word-only, no fiat leak: {t}");
        assert!(!t.contains("12") && !t.contains("5.0"), "never a raw number: {t}");
    }

    #[test]
    fn pending_text_from_envelope_clean_confirmed() {
        // The confirming line is localized and the language is a PROCESS global that
        // other tests flip, so an assertion on the ENGLISH form has to hold the
        // crate-wide language lock (see `i18n::LANG_TEST_LOCK`) rather than trust the
        // default — "default language is English" is only true until someone else's
        // test is mid-中文.
        let _l = crate::i18n::LANG_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let restore = crate::i18n::lang();
        crate::i18n::set_lang(crate::i18n::Lang::En);

        let ok = r#"{"found":true,"paid_acu":"0","summary":{"pending_alice":12.56}}"#;
        let t = pending_text_from_envelope(ok).expect("clean confirmed → text");
        assert!(t.contains("credit"));
        // Never a "$".
        assert!(!t.contains('$'));
        // not-found → confirming.
        let nf = r#"{"found":false,"paid_acu":"0"}"#;
        assert_eq!(
            pending_text_from_envelope(nf).as_deref(),
            Some("awaiting confirmation (confirming)")
        );
        // garbage → fail-open None.
        assert_eq!(pending_text_from_envelope("not json"), None);
        crate::i18n::set_lang(restore);
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
        // With NO payout env AND no file (an empty private identity dir), the
        // outcome is NoPayoutAddress — never a panic / Err / fake signature.
        with_temp_alice_home(|_home| {
            let watch = WalletSecrets::display_only(ADDR);
            let out = run_enroll_best_effort(ADDR, "worker-abc", "us", &watch);
            assert_eq!(out, EnrollOutcome::NoPayoutAddress);
        });
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
        with_temp_alice_home(|home| {
            // Nothing stored yet.
            assert_eq!(load_payout_address().unwrap(), None);
            // A typo is rejected and NEVER written.
            assert!(save_payout_address("not-a-prl1p").is_err());
            assert_eq!(load_payout_address().unwrap(), None);
            // Save a legal address → load reads it back, from the Alice home.
            let p = save_payout_address(PAYOUT_OK).expect("save ok");
            assert_eq!(p, home.join("prl_payout_address"));
            assert_eq!(load_payout_address().unwrap().as_deref(), Some(PAYOUT_OK));
            // Whitespace is trimmed on save.
            save_payout_address(&format!("  {PAYOUT_OK}  ")).unwrap();
            assert_eq!(load_payout_address().unwrap().as_deref(), Some(PAYOUT_OK));
            // Clear → back to None; clearing again is Ok (idempotent).
            clear_payout_address().unwrap();
            assert_eq!(load_payout_address().unwrap(), None);
            clear_payout_address().unwrap();
        });
    }

    /// The payout file must live in the Alice home like every other `~/.alice`
    /// artifact — which means honoring `$ALICE_IDENTITY_DIR`.
    ///
    /// It did not: it resolved `$HOME` / `$USERPROFILE` itself and appended
    /// `.alice/…`, so a miner running with an isolated identity dir had their payout
    /// address written into their real home directory, and every test that touched
    /// this path wrote into the developer's actual `$HOME`.
    #[test]
    fn the_payout_file_follows_alice_identity_dir_not_the_real_home() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let prev_addr = std::env::var(ENV_PAYOUT_ADDRESS).ok();
        let prev_id = std::env::var_os("ALICE_IDENTITY_DIR");
        let prev_home = std::env::var_os("HOME");
        let prev_up = std::env::var_os("USERPROFILE");
        std::env::remove_var(ENV_PAYOUT_ADDRESS); // force the FILE path

        let root = temp_root("alice-prl-iddir");
        let id_dir = root.join("identity");
        let home = root.join("home");
        std::fs::create_dir_all(&id_dir).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        std::env::set_var("ALICE_IDENTITY_DIR", &id_dir);
        std::env::set_var("HOME", &home);
        std::env::set_var("USERPROFILE", &home);

        let written = save_payout_address(PAYOUT_OK).expect("save");
        assert_eq!(
            written,
            id_dir.join("prl_payout_address"),
            "the override is where it must land"
        );
        assert!(written.exists(), "and it must actually be there");
        assert!(
            !home.join(".alice").exists(),
            "nothing may be written under the operator's real home: {}",
            home.display()
        );
        // …and the reader agrees with the writer.
        assert_eq!(load_payout_address().unwrap().as_deref(), Some(PAYOUT_OK));
        clear_payout_address().unwrap();
        assert!(!written.exists(), "clear removes the same file");

        // With NO override the path is what it always was — `<home>/.alice/…` — so an
        // existing install does not lose its address. Asserted on the resolved PATH
        // and not by writing: without the override this test would be writing into
        // (and then deleting from) the real home directory on any platform where
        // `dirs::home_dir()` does not follow `$HOME` — which is the very hazard this
        // fix exists to remove.
        std::env::remove_var("ALICE_IDENTITY_DIR");
        let fallback = payout_file_path();
        assert!(
            fallback.ends_with(".alice/prl_payout_address"),
            "unchanged for an ordinary install: {}",
            fallback.display()
        );

        let _ = std::fs::remove_dir_all(&root);
        match prev_addr {
            Some(v) => std::env::set_var(ENV_PAYOUT_ADDRESS, v),
            None => std::env::remove_var(ENV_PAYOUT_ADDRESS),
        }
        restore("ALICE_IDENTITY_DIR", prev_id);
        restore("HOME", prev_home);
        restore("USERPROFILE", prev_up);
    }

    // ── AM-SEC-008: full bech32m checksum before we ever sign ──────────────────

    /// The three REAL, published `prl1p…` addresses (transit / cold / legacy) must
    /// all verify — if this fails, our checksum implementation is wrong, not the
    /// addresses. This is the anchor that keeps the gate from bricking real users.
    #[test]
    fn checksum_accepts_the_real_published_addresses() {
        for real in [
            "prl1p2v2hrrhzls9ala8wpwjucvfa7znt8q67s35aw6gev7xeknspa0ysul5efx",
            "prl1p32l5m3sw4g5p25qamk8fn7qae7ek6ujtj025g8h9r4mgk0pxf4sqhgwah3",
            "prl1pukq3uu0txl6fc34f2frlxsxyfs9nj30lsa4dkw8vpmfkgv3ck74shvtxsa",
            // The alpha lane's published placeholder (already bech32m-checked there).
            crate::lane::gpu_alpha::DEFAULT_ALPHA_PLACEHOLDER,
        ] {
            assert!(
                validate_payout_address(real).is_ok(),
                "a REAL published address must pass: {real}"
            );
        }
        assert!(validate_payout_address(PAYOUT_OK).is_ok());
    }

    /// AM-SEC-008, second half (merge review 2026-08-04): the client's verdict must
    /// equal the SERVER's. A checksum-valid address with the wrong witness program is
    /// refused by `assert_payable_prl_payout_address` server-side; if the client
    /// called it valid it would store it, sign an enroll for it, and the miner would
    /// only learn the rebate is undeliverable much later — the exact class of silent
    /// lie this batch exists to remove.
    #[test]
    fn checksum_valid_but_unpayable_witness_program_is_refused() {
        // Shape + checksum both pass on their own …
        assert!(validate_payout_shape(PAYOUT_VALID_CKSUM_UNPAYABLE).is_ok());
        assert!(verify_payout_checksum(PAYOUT_VALID_CKSUM_UNPAYABLE).is_ok());
        // … and the full gate still refuses it, naming the real reason.
        let err = validate_payout_address(PAYOUT_VALID_CKSUM_UNPAYABLE).unwrap_err();
        assert!(
            err.contains("Taproot") || err.contains("witness") || err.contains("字节"),
            "the message must name the witness-program rule, not just 'invalid': {err}"
        );
        // NOT the typo message — this address is not mistyped, it is the wrong kind.
        assert!(
            !err.contains("mistyped") && !err.contains("打错"),
            "an unpayable-but-well-typed address must not be blamed on a typo: {err}"
        );
    }

    /// The witness rule must accept every real address and reject only the wrong
    /// shape of program — including the "data part is not a whole number of bytes"
    /// case, which a naive truncating decoder would wave through.
    #[test]
    fn witness_program_rule_matches_the_server_ruler() {
        for payable in [
            "prl1p2v2hrrhzls9ala8wpwjucvfa7znt8q67s35aw6gev7xeknspa0ysul5efx",
            "prl1p32l5m3sw4g5p25qamk8fn7qae7ek6ujtj025g8h9r4mgk0pxf4sqhgwah3",
            "prl1pukq3uu0txl6fc34f2frlxsxyfs9nj30lsa4dkw8vpmfkgv3ck74shvtxsa",
            crate::lane::gpu_alpha::DEFAULT_ALPHA_PLACEHOLDER,
            PAYOUT_OK,
        ] {
            assert!(
                verify_payout_witness_program(payable).is_ok(),
                "a real payable address must pass the witness rule: {payable}"
            );
        }
        // 8-byte program (v1) — checksum-valid, unpayable.
        assert!(verify_payout_witness_program(PAYOUT_VALID_CKSUM_UNPAYABLE).is_err());
        // Checksum-valid, but the data part has a non-zero bit remainder: it is not a
        // byte string at all. (This is the address that used to be our "OK" fixture.)
        let ragged = "prl1pqzry9x8gf2tvdw0s3jn54khce6mua7lqpzry9x8gf2tvdw0s3jn57kr3mc";
        assert!(verify_payout_checksum(ragged).is_ok(), "fixture must be checksum-valid");
        assert!(
            verify_payout_witness_program(ragged).is_err(),
            "a ragged (non-byte-aligned) data part must be refused, not truncated"
        );
    }

    #[test]
    fn convert_bits_rejects_ragged_remainders() {
        // 8 five-bit groups = 40 bits = exactly 5 bytes.
        assert_eq!(convert_bits_5_to_8(&[0; 8]).map(|v| v.len()), Some(5));
        // 1 group = 5 bits: fewer than 8, remainder >= 5 → not a byte string.
        assert!(convert_bits_5_to_8(&[0]).is_none());
        // 2 groups = 10 bits: 1 byte + 2 leftover ZERO bits → accepted (1 byte).
        assert_eq!(convert_bits_5_to_8(&[0, 0]).map(|v| v.len()), Some(1));
        // 2 groups with a non-zero remainder → refused.
        assert!(convert_bits_5_to_8(&[0, 1]).is_none());
        // A value outside 0..=31 is not a 5-bit group at all.
        assert!(convert_bits_5_to_8(&[32]).is_none());
    }

    #[test]
    fn checksum_rejects_shape_legal_garbage_with_a_clear_message() {
        // Shape-legal (right prefix, right charset, right length) but the checksum
        // does not close — the pre-fix code would have SIGNED this.
        assert!(validate_payout_shape(PAYOUT_BAD_CKSUM).is_ok(), "shape alone still passes");
        let err = validate_payout_address(PAYOUT_BAD_CKSUM).unwrap_err();
        assert!(
            err.contains("mistyped") || err.contains("打错"),
            "the message must tell the human it is a typo, not a bare 'invalid': {err}"
        );
    }

    /// Every single-character substitution of a valid address must be caught. This is
    /// the property the whole fix exists for (the miner who typos one char).
    #[test]
    fn checksum_catches_every_single_character_typo() {
        let chars: Vec<char> = PAYOUT_OK.chars().collect();
        let mut checked = 0usize;
        // Only mutate the data part (skip the "prl1" HRP+separator).
        for i in 4..chars.len() {
            for sub in BECH32_CHARSET.chars() {
                if sub == chars[i] {
                    continue;
                }
                let mut m = chars.clone();
                m[i] = sub;
                let typo: String = m.into_iter().collect();
                assert!(
                    validate_payout_address(&typo).is_err(),
                    "single-char typo slipped through at {i}: {typo}"
                );
                checked += 1;
            }
        }
        assert!(checked > 1000, "sanity: the sweep actually ran ({checked} mutations)");
    }

    #[test]
    fn checksum_catches_adjacent_transposition() {
        let chars: Vec<char> = PAYOUT_OK.chars().collect();
        for i in 4..chars.len() - 1 {
            if chars[i] == chars[i + 1] {
                continue; // swapping equal chars is a no-op, not a typo
            }
            let mut m = chars.clone();
            m.swap(i, i + 1);
            let typo: String = m.into_iter().collect();
            assert!(validate_payout_address(&typo).is_err(), "transposition at {i} slipped through");
        }
    }

    #[test]
    fn bad_checksum_is_never_written_and_never_loaded() {
        with_temp_alice_home(|home| {
            // (a) save refuses it and writes nothing.
            assert!(save_payout_address(PAYOUT_BAD_CKSUM).is_err());
            assert_eq!(load_payout_address().unwrap(), None);
            // (b) a file that somehow already holds a bad-checksum address surfaces as
            //     an Err on load — it is NOT silently used to build an enroll signature.
            std::fs::write(home.join("prl_payout_address"), format!("{PAYOUT_BAD_CKSUM}\n"))
                .unwrap();
            assert!(load_payout_address().is_err());
            // (c) and the enroll path reports it instead of signing.
            let watch = WalletSecrets::display_only(ADDR);
            match run_enroll_best_effort(ADDR, "worker-abc", "us", &watch) {
                EnrollOutcome::Failed(e) => assert!(e.contains("payout address invalid")),
                other => panic!("a bad-checksum address must not reach signing: {other:?}"),
            }
        });
    }

    #[test]
    fn confirm_gate_never_infers_consent() {
        // Non-interactive + no flag ⇒ we REFUSE and say which flag is needed.
        assert_eq!(decide_payout_confirm(false, false, None), PayoutConfirm::NeedsExplicitFlag);
        // Non-interactive + explicit flag ⇒ proceed.
        assert_eq!(decide_payout_confirm(false, true, None), PayoutConfirm::Proceed);
        // Interactive: only y/yes proceeds; anything else (incl. EOF) declines.
        assert_eq!(decide_payout_confirm(true, false, Some("y\n")), PayoutConfirm::Proceed);
        assert_eq!(decide_payout_confirm(true, false, Some("YES")), PayoutConfirm::Proceed);
        assert_eq!(decide_payout_confirm(true, false, Some("n")), PayoutConfirm::Declined);
        assert_eq!(decide_payout_confirm(true, false, Some("")), PayoutConfirm::Declined);
        assert_eq!(decide_payout_confirm(true, false, None), PayoutConfirm::Declined);
    }

    #[test]
    fn confirm_rendering_shows_the_whole_address_not_a_mask() {
        let shown = format_for_confirm(PAYOUT_OK);
        // Every character survives (only spaces are added) — the point of the prompt
        // is that the human can compare the FULL string against their wallet.
        assert_eq!(shown.replace(' ', ""), PAYOUT_OK);
        assert!(shown.contains(' '), "grouped for readability");
        assert!(!shown.contains('…'), "the confirm view must NOT be the masked view");
    }

    // Process env is global; serialize every test that reads/writes a payout/lookup
    // env key through this lock so parallel cargo threads can't race.
    static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A fresh, uniquely-named temp directory.
    fn temp_root(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    /// Put a value back, or remove the variable if there was none.
    fn restore(key: &str, prev: Option<std::ffi::OsString>) {
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    /// Run `f` with a private Alice home (`$ALICE_IDENTITY_DIR`) and no payout env
    /// override, so anything the payout file paths touch stays inside it.
    ///
    /// `$ALICE_IDENTITY_DIR` — not `$HOME` — because that is the isolation switch the
    /// whole `~/.alice` family honors, and it is the only one that works on every
    /// platform: `dirs::home_dir()` does NOT follow `$HOME` on Windows, so a test that
    /// isolates itself by pointing `$HOME` at a temp dir is, there, reading and
    /// DELETING the real user's `~/.alice/prl_payout_address`.
    fn with_temp_alice_home<F: FnOnce(&std::path::Path)>(f: F) {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let prev_addr = std::env::var_os(ENV_PAYOUT_ADDRESS);
        let prev_id = std::env::var_os("ALICE_IDENTITY_DIR");
        let home = temp_root("alice-prl-home");
        std::fs::create_dir_all(&home).unwrap();
        std::env::remove_var(ENV_PAYOUT_ADDRESS); // force the FILE path
        std::env::set_var("ALICE_IDENTITY_DIR", &home);

        f(&home);

        restore("ALICE_IDENTITY_DIR", prev_id);
        restore(ENV_PAYOUT_ADDRESS, prev_addr);
        let _ = std::fs::remove_dir_all(&home);
    }
}
