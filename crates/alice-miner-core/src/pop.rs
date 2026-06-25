//! GPU-PRL **Proof-of-Possession (PoP)** client.
//!
//! The miner proves it controls the Alice reward address by signing a
//! server-minted challenge with the SAME sr25519 key the wallet signs real
//! on-chain sends with. Under the live relay's `REQUIRE_POP=1`, only shares from
//! a proven address are credited — so without PoP the GPU-PRL lane earns nothing.
//!
//! Two distinct, domain-separated signatures:
//!   * **login** (`POP_DOMAIN`) — per-connection possession, binds
//!     `(alice_address, device_id, challenge_nonce)`; assembled into the stratum/
//!     OOB token `pop=<challenge_id>:<sig>`.
//!   * **enroll** (`ENROLL_DOMAIN`) — binds the 15%-payout `prl1p…` address to the
//!     Alice address so a captured nonce can never rebind a victim's rewards to an
//!     attacker payout (the #1 audit fix).
//!
//! Every signed-byte layout here is **byte-identical** to the server
//! (`alice_acp.api_chat_gateway.worker_pop` / `…prl_payout_scheduler.m4_enroll_pop`)
//! and to the worker-v1 Python client (`gpu_pop` / `m4_enroll_pop`). The sr25519
//! cross-implementation conformance gate (Python signature verifies in Rust) lives
//! in `alice-crypto/tests/pop_sr25519_conformance.rs`.
//!
//! This module is the headless PoP core (no UI, no lane wiring) so it ports cleanly
//! into the future shared `alice-mining-core` crate.

use std::io::Read as _;
use std::time::Duration;

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use alice_crypto::WalletSecrets;

/// Domain-separation tag for the per-connection worker-pull / stratum-login PoP.
/// Server: `worker_pop.GPU_RELAY_POP_DOMAIN`.
pub const POP_DOMAIN: &str = "alice-acp:worker-pull:proof-of-possession:v1";

/// Domain-separation tag for the M4 enroll payout-binding signature. DISTINCT from
/// [`POP_DOMAIN`] so a login PoP can never be replayed as an enroll (and vice-versa).
/// Server: `m4_enroll_pop.M4_ENROLL_BINDING_DOMAIN`.
pub const ENROLL_DOMAIN: &str = "alice-acp:m4-enroll:bind-payout:v1";

/// The sentinel device component bound when a (legacy) identity supplies no device id.
const DEVICE_SENTINEL: &str = "-";

/// The EXACT bytes signed for a **login** PoP — byte-identical to the server's
/// `possession_signing_message`: domain line, then three `key=value` lines,
/// newline-FRAMED (newline BETWEEN lines, NONE trailing), ASCII. `device_id` `None`
/// binds the `"-"` sentinel (so an address-only proof can never be replayed as a
/// per-device one). The signed field is `challenge_nonce` — NOT `challenge_id`.
pub fn pop_signature_message(
    alice_address: &str,
    device_id: Option<&str>,
    challenge_nonce: &str,
) -> Vec<u8> {
    let dev = device_id.unwrap_or(DEVICE_SENTINEL);
    format!(
        "{POP_DOMAIN}\nalice_address={alice_address}\ndevice_id={dev}\nchallenge_nonce={challenge_nonce}"
    )
    .into_bytes()
}

/// The EXACT bytes signed for an **enroll** payout-binding — byte-identical to the
/// server's `enroll_binding_signing_message`: domain line, then four `key=value`
/// lines, newline-FRAMED (none trailing), ASCII. `device_id` is embedded **verbatim**
/// (no `"-"` sentinel — the enroll flow always supplies a real device id), exactly as
/// the server does; this is DISTINCT from the login message's device normalization.
pub fn enroll_signature_message(
    alice_address: &str,
    prl_payout_address: &str,
    device_id: &str,
    nonce: &str,
) -> Vec<u8> {
    format!(
        "{ENROLL_DOMAIN}\nalice_address={alice_address}\nprl_payout_address={prl_payout_address}\ndevice_id={device_id}\nnonce={nonce}"
    )
    .into_bytes()
}

/// Sign canonical PoP bytes with the Alice sr25519 key; return the 64-byte
/// schnorrkel signature in **standard** base64 (the alphabet the server's
/// `base64.b64decode` expects). Fails closed if `secrets` is display-only / watch-only
/// (no key) — a pasted address can never PoP.
pub fn sign_message_b64(secrets: &WalletSecrets, message: &[u8]) -> Result<String, String> {
    let keypair = secrets.to_keypair()?;
    let sig = keypair.sign(message);
    Ok(base64::engine::general_purpose::STANDARD.encode(sig.0))
}

/// Assemble the stratum/OOB password token `pop=<challenge_id>:<sig>`.
///
/// The relay splits on the FIRST `:` after `pop=`, so `challenge_id` must contain no
/// `:` and no whitespace, and the base64 signature must contain no whitespace — else
/// an injected separator could spoof the token. Fail closed on any violation; this is
/// the client mirror of `gpu_pop.assemble_pop_password`'s injection guard.
pub fn assemble_pop_password(challenge_id: &str, signature_b64: &str) -> Result<String, String> {
    if challenge_id.is_empty()
        || challenge_id.contains(':')
        || challenge_id.chars().any(|c| c.is_whitespace())
    {
        return Err("invalid_challenge_id".into());
    }
    if signature_b64.is_empty() || signature_b64.chars().any(|c| c.is_whitespace()) {
        return Err("invalid_signature".into());
    }
    Ok(format!("pop={challenge_id}:{signature_b64}"))
}

// ════════════════════════════════════════════════════════════════════════════
// HTTPS control plane
//
// Four POST endpoints carry the PoP handshake over HTTPS:
//   * region (per-relay): `m4/challenge` (mint a nonce) + `m4/verify` (best-effort
//     OOB confirm of a login token).
//   * central (`api.aliceprotocol.org`): `m4/enroll/nonce` + `m4/enroll` (bind the
//     15%-payout `prl1p…` address to the Alice address).
//
// HARD RULES (mirror the server's transport guard):
//   * every URL MUST be `https://` — a plaintext url fails closed (a PoP token /
//     payout binding must never cross the wire in the clear).
//   * a small read cap + ~10 s timeout bound a hostile/oversized response.
// All bodies are typed structs serialized with serde_json (compact by default), so
// the on-wire JSON shape is asserted in unit tests with NO network.
// ════════════════════════════════════════════════════════════════════════════

/// Central control-plane host for enroll (payout-binding). Region relays mint
/// login challenges; enroll is always central so the payout map has one authority.
const CENTRAL_HOST: &str = "https://api.aliceprotocol.org";

/// Connect + read timeout for every control-plane call (~10 s, per task).
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound on any control-plane response body. Challenge/enroll payloads are a
/// few hundred bytes; 64 KiB is generous yet caps a hostile/runaway response.
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

/// Env override for the region login-challenge URL (test/ops). When set it REPLACES
/// the derived `https://<host>/m4/challenge`; still required to be `https://`.
const ENV_CHALLENGE_URL: &str = "ALICE_GPU_RELAY_POP_CHALLENGE_URL";
/// Env override for the central enroll-nonce URL.
const ENV_ENROLL_NONCE_URL: &str = "ALICE_GPU_RELAY_ENROLL_NONCE_URL";
/// Env override for the central enroll URL.
const ENV_ENROLL_URL: &str = "ALICE_GPU_RELAY_ENROLL_URL";

/// A server-minted login challenge: an opaque id (echoed back in the `pop=` token)
/// and the nonce whose bytes get signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PopChallenge {
    pub challenge_id: String,
    pub challenge_nonce: String,
}

// ── request bodies (typed → compact JSON, field order fixed here) ──────────────

#[derive(Serialize)]
struct ChallengeRequest<'a> {
    alice_address: &'a str,
    device_id: &'a str,
}

#[derive(Serialize)]
struct VerifyRequest<'a> {
    alice_address: &'a str,
    device_id: &'a str,
    pop: &'a str,
}

#[derive(Serialize)]
struct EnrollNonceRequest<'a> {
    alice_address: &'a str,
    device_id: &'a str,
}

#[derive(Serialize)]
struct EnrollRequest<'a> {
    alice_address: &'a str,
    device_id: &'a str,
    prl_payout_address: &'a str,
    region: &'a str,
    nonce: &'a str,
    signature_b64: &'a str,
}

// ── response shapes ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ChallengeResponse {
    challenge_id: String,
    /// Canonical field.
    #[serde(default)]
    challenge_nonce: Option<String>,
    /// Legacy field name kept for back-compat with older relays.
    #[serde(default)]
    nonce: Option<String>,
}

#[derive(Deserialize)]
struct VerifyResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    verified: bool,
}

#[derive(Deserialize)]
struct EnrollNonceResponse {
    nonce: String,
}

/// Reject any non-`https://` URL — fail closed so a PoP token / payout binding can
/// never be sent in the clear.
fn require_https(url: &str) -> Result<(), String> {
    if url.starts_with("https://") {
        Ok(())
    } else {
        Err(format!("refusing non-https control-plane url: {url}"))
    }
}

/// `true` iff `host` is safe to splice into a URL path: no whitespace, no `/`, and
/// no ASCII control chars (which could smuggle a second path segment or header).
fn is_safe_host(host: &str) -> bool {
    !host.is_empty()
        && !host.contains('/')
        && !host.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(HTTP_TIMEOUT)
        .timeout_read(HTTP_TIMEOUT)
        .user_agent(concat!("alice-miner-pop/", env!("CARGO_PKG_VERSION")))
        .build()
}

/// POST a typed body as compact JSON, read the (capped) response, and parse it into
/// `R`. Caller has already validated the URL is https.
fn post_json<B: Serialize, R: serde::de::DeserializeOwned>(
    url: &str,
    body: &B,
) -> Result<R, String> {
    // Serialize to a compact JSON string ourselves and send with an explicit
    // content-type. ureq's `send_json` needs the `json` feature, which the
    // workspace's default-features=false (tls+gzip only) build intentionally omits.
    let payload = serde_json::to_string(body).map_err(|e| format!("serialize: {e}"))?;
    let resp = agent()
        .post(url)
        .set("Content-Type", "application/json")
        .send_string(&payload)
        .map_err(|e| format!("POST {url}: {e}"))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut buf)
        .map_err(|e| format!("read {url}: {e}"))?;
    serde_json::from_slice(&buf).map_err(|e| format!("parse {url}: {e}"))
}

/// Build the region login-challenge URL `https://<host>/m4/challenge`.
///
/// If [`ENV_CHALLENGE_URL`] is set it REPLACES the derivation (still https-checked).
/// `region_host` is rejected if it contains a `/`, whitespace, or control chars.
pub fn region_challenge_url(region_host: &str) -> Result<String, String> {
    if let Ok(over) = std::env::var(ENV_CHALLENGE_URL) {
        if !over.is_empty() {
            require_https(&over)?;
            return Ok(over);
        }
    }
    if !is_safe_host(region_host) {
        return Err(format!("unsafe region host: {region_host:?}"));
    }
    let url = format!("https://{region_host}/m4/challenge");
    require_https(&url)?;
    Ok(url)
}

/// Derive the OOB verify URL from a challenge URL by swapping the trailing
/// `/m4/challenge` for `/m4/verify`. Fails closed if the suffix is absent (so a
/// caller can never POST a verify to an unrelated path) or the result isn't https.
pub fn verify_url(challenge_url: &str) -> Result<String, String> {
    require_https(challenge_url)?;
    let stem = challenge_url
        .strip_suffix("/m4/challenge")
        .ok_or_else(|| format!("challenge url missing /m4/challenge suffix: {challenge_url}"))?;
    let url = format!("{stem}/m4/verify");
    require_https(&url)?;
    Ok(url)
}

/// POST to the region `m4/challenge` endpoint and return the minted challenge.
/// Reads `challenge_nonce`, falling back to the legacy `nonce` field.
pub fn fetch_challenge(
    challenge_url: &str,
    alice_address: &str,
    device_id: &str,
) -> Result<PopChallenge, String> {
    require_https(challenge_url)?;
    let body = ChallengeRequest {
        alice_address,
        device_id,
    };
    let resp: ChallengeResponse = post_json(challenge_url, &body)?;
    let challenge_nonce = resp
        .challenge_nonce
        .or(resp.nonce)
        .ok_or_else(|| "challenge response missing challenge_nonce/nonce".to_string())?;
    if resp.challenge_id.is_empty() || challenge_nonce.is_empty() {
        return Err("challenge response had empty challenge_id/nonce".into());
    }
    Ok(PopChallenge {
        challenge_id: resp.challenge_id,
        challenge_nonce,
    })
}

/// Best-effort out-of-band confirmation that a login `pop_token` was accepted.
/// **Never panics, never errors** — any transport/parse failure is a `false` so the
/// caller can log-and-continue (the authoritative gate is the relay itself).
pub fn oob_verify(
    verify_url: &str,
    alice_address: &str,
    device_id: &str,
    pop_token: &str,
) -> bool {
    if require_https(verify_url).is_err() {
        return false;
    }
    let body = VerifyRequest {
        alice_address,
        device_id,
        pop: pop_token,
    };
    match post_json::<_, VerifyResponse>(verify_url, &body) {
        Ok(r) => r.ok || r.verified,
        Err(_) => false,
    }
}

/// Fetch an enroll nonce from the CENTRAL host (or [`ENV_ENROLL_NONCE_URL`]).
pub fn fetch_enroll_nonce(alice_address: &str, device_id: &str) -> Result<String, String> {
    let url = enroll_nonce_url()?;
    let body = EnrollNonceRequest {
        alice_address,
        device_id,
    };
    let resp: EnrollNonceResponse = post_json(&url, &body)?;
    if resp.nonce.is_empty() {
        return Err("enroll-nonce response had empty nonce".into());
    }
    Ok(resp.nonce)
}

/// Submit the M4 enroll (payout-binding) to the CENTRAL host (or [`ENV_ENROLL_URL`]).
/// All six fields are carried; a non-2xx response surfaces as an error.
#[allow(clippy::too_many_arguments)]
pub fn enroll(
    alice_address: &str,
    device_id: &str,
    prl_payout_address: &str,
    region: &str,
    nonce: &str,
    signature_b64: &str,
) -> Result<(), String> {
    let url = enroll_url()?;
    let body = EnrollRequest {
        alice_address,
        device_id,
        prl_payout_address,
        region,
        nonce,
        signature_b64,
    };
    // We don't need the body, but a malformed/oversized one still gets capped+read.
    let _resp: serde_json::Value = post_json(&url, &body)?;
    Ok(())
}

/// Central enroll-nonce URL (env override or default), https-checked.
fn enroll_nonce_url() -> Result<String, String> {
    central_url(ENV_ENROLL_NONCE_URL, "/acp/m4/enroll/nonce")
}

/// Central enroll URL (env override or default), https-checked.
fn enroll_url() -> Result<String, String> {
    central_url(ENV_ENROLL_URL, "/acp/m4/enroll")
}

/// Resolve a central URL: the env override (if set & non-empty) else
/// `CENTRAL_HOST + path`. Always https-checked.
fn central_url(env_key: &str, path: &str) -> Result<String, String> {
    if let Ok(over) = std::env::var(env_key) {
        if !over.is_empty() {
            require_https(&over)?;
            return Ok(over);
        }
    }
    let url = format!("{CENTRAL_HOST}{path}");
    require_https(&url)?;
    Ok(url)
}

// ════════════════════════════════════════════════════════════════════════════
// High-level PoP startup sequence (region-bound)
//
// The mining-side orchestration of the four primitives above: given a region
// host, the user's Alice address + device id, and the wallet SIGNING key, run the
// full handshake and return the stratum/OOB password token bound to THAT region.
// Re-used verbatim by (a) the lane's initial start and (b) the supervisor's
// Layer-B rebuild (a failover to a DIFFERENT region must re-challenge + re-sign +
// re-verify because the token is region-bound — a token minted for region A is
// rejected by region B).
// ════════════════════════════════════════════════════════════════════════════

/// The region-bound result of a successful PoP handshake: the assembled password
/// token plus the region host it is bound to (so callers can assert/relog it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PopToken {
    /// `pop=<challenge_id>:<sig>` — rides the stratum `--password`.
    pub password: String,
    /// The region relay host this token was minted+verified against.
    pub region_host: String,
}

/// Run the full region-bound PoP startup sequence for ONE region:
///   1. `fetch_challenge(https://<region_host>/m4/challenge)` → mint a nonce.
///   2. sign `pop_signature_message(alice, Some(device_id), nonce)` with the
///      wallet sr25519 key (fails closed for a watch-only / display-only secret).
///   3. `assemble_pop_password(challenge_id, sig)` → the `pop=…` token.
///   4. best-effort `oob_verify(https://<region_host>/m4/verify, …)` — OOB
///      enrolment into the relay's allowlist (the real authorization). A `false`
///      here is logged-and-continued by the caller (the relay is the authority);
///      it is NOT a hard error so a transient verify hiccup doesn't block mining.
///
/// Returns the [`PopToken`] (password + region) on success. Fails closed (Err) if
/// the signing key is unavailable or the challenge can't be fetched — under the
/// relay's `REQUIRE_POP=1` a missing/garbage token earns nothing, so there is no
/// point launching the miner without a real token.
///
/// `oob_ok_out`, when supplied, receives the best-effort OOB verify result (so the
/// caller can surface "not yet in the allowlist" without a second round-trip).
pub fn establish_pop(
    region_host: &str,
    alice_address: &str,
    device_id: &str,
    secrets: &WalletSecrets,
    oob_ok_out: Option<&mut bool>,
) -> Result<PopToken, String> {
    // (2-pre) Fail closed BEFORE any network if we can't sign — a watch-only /
    // display-only identity can never PoP, so there is nothing to fetch.
    //   (sign_message_b64 also checks this, but checking up front avoids a wasted
    //    challenge round-trip and gives the clearest user-facing error.)
    if secrets.to_keypair().is_err() {
        return Err(
            "this reward identity is watch-only (address pasted, no signing key); the GPU-PRL \
             lane needs a wallet key to prove possession — import the mnemonic/seed instead"
                .into(),
        );
    }

    let challenge_url = region_challenge_url(region_host)?;
    // (1) challenge.
    let challenge = fetch_challenge(&challenge_url, alice_address, device_id)?;
    // (2) sign the nonce (region-agnostic bytes, but minted per region).
    let msg = pop_signature_message(alice_address, Some(device_id), &challenge.challenge_nonce);
    let sig_b64 = sign_message_b64(secrets, &msg)?;
    // (3) assemble.
    let password = assemble_pop_password(&challenge.challenge_id, &sig_b64)?;
    // (4) best-effort OOB confirm (the relay allowlist is the real gate).
    let verify_u = verify_url(&challenge_url)?;
    let ok = oob_verify(&verify_u, alice_address, device_id, &password);
    if let Some(slot) = oob_ok_out {
        *slot = ok;
    }
    Ok(PopToken {
        password,
        region_host: region_host.to_string(),
    })
}

/// OOB allowlist TTL: the relay drops a proven `(address, device)` from its PoP
/// allowlist after this long without a re-verify (server: 1800s). The refresh
/// task must re-challenge+re-verify BEFORE this elapses or the lane silently
/// stops being credited.
pub const OOB_ALLOWLIST_TTL: Duration = Duration::from_secs(1800);

/// Re-verify margin: re-run the PoP handshake when fewer than this many seconds
/// remain on the TTL (so a re-verify always lands with headroom; 300s per task).
pub const OOB_REFRESH_MARGIN: Duration = Duration::from_secs(300);

/// How often the refresh task wakes to check whether a re-verify is due. ~60s per
/// task — cheap, and well inside the [`OOB_REFRESH_MARGIN`] so a due re-verify is
/// never missed by more than one tick.
pub const OOB_REFRESH_TICK: Duration = Duration::from_secs(60);

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vectors from the Python oracle (substrate-interface, ss58_format=300,
    // fixed mnemonic) — same fixture as the crypto conformance gate.
    const ADDR: &str = "a2uJXaVk7Zx4fgk9aRLnhiD2RdpAP4usJxKXpN4vh4hDNoP1C";
    const DEV: &str = "worker-abc123";

    #[test]
    fn login_message_is_byte_exact() {
        let got = pop_signature_message(ADDR, Some(DEV), "nonce-deadbeef-0001");
        let want = format!(
            "alice-acp:worker-pull:proof-of-possession:v1\nalice_address={ADDR}\ndevice_id={DEV}\nchallenge_nonce=nonce-deadbeef-0001"
        );
        assert_eq!(got, want.as_bytes());
        assert_ne!(got.last(), Some(&b'\n'), "no trailing newline");
        assert!(got.is_ascii());
    }

    #[test]
    fn login_message_none_device_binds_sentinel() {
        let got = pop_signature_message(ADDR, None, "n1");
        assert!(String::from_utf8(got).unwrap().contains("device_id=-\n"));
    }

    #[test]
    fn enroll_message_is_byte_exact_and_verbatim_device() {
        let payout = "prl1ptestpayout000000000000000000000000000000000000";
        let got = enroll_signature_message(ADDR, payout, DEV, "enroll-nonce-cafe-0002");
        let want = format!(
            "alice-acp:m4-enroll:bind-payout:v1\nalice_address={ADDR}\nprl_payout_address={payout}\ndevice_id={DEV}\nnonce=enroll-nonce-cafe-0002"
        );
        assert_eq!(got, want.as_bytes());
        // device_id verbatim — no sentinel substitution even for a "-"-looking id.
        let dash = enroll_signature_message(ADDR, payout, "-", "n");
        assert!(String::from_utf8(dash).unwrap().contains("device_id=-\n"));
    }

    #[test]
    fn login_and_enroll_domains_differ() {
        // Same logical fields must produce different signed bytes across flows.
        let login = pop_signature_message(ADDR, Some(DEV), "x");
        let enroll = enroll_signature_message(ADDR, "prl1px", DEV, "x");
        assert_ne!(login, enroll);
        assert!(String::from_utf8(login).unwrap().starts_with(POP_DOMAIN));
        assert!(String::from_utf8(enroll).unwrap().starts_with(ENROLL_DOMAIN));
    }

    #[test]
    fn pop_token_format_and_injection_guards() {
        assert_eq!(
            assemble_pop_password("ch123", "c2lnYmFzZTY0").unwrap(),
            "pop=ch123:c2lnYmFzZTY0"
        );
        // base64 standard padding/+/ are allowed in the signature segment.
        assert!(assemble_pop_password("ch", "ab+/cd==").is_ok());
        // separator injection / whitespace are refused.
        assert!(assemble_pop_password("ch:evil", "sig").is_err());
        assert!(assemble_pop_password("ch id", "sig").is_err());
        assert!(assemble_pop_password("ch", "si g").is_err());
        assert!(assemble_pop_password("", "sig").is_err());
        assert!(assemble_pop_password("ch", "").is_err());
    }

    #[test]
    fn sign_is_standard_base64_64_bytes() {
        // A display-only secrets value has no key → sign must fail closed.
        let watch = WalletSecrets::display_only(ADDR);
        assert!(sign_message_b64(&watch, b"msg").is_err());
    }

    #[test]
    fn establish_pop_fails_closed_for_watch_only_before_any_network() {
        // A watch-only identity (pasted address, no key) must be rejected up front
        // with a clear message — and crucially BEFORE any control-plane call (so a
        // pasted address can never even probe the relay). No network is reached.
        let watch = WalletSecrets::display_only(ADDR);
        let mut ok = true;
        let err = establish_pop(
            "us.aliceprotocol.org",
            ADDR,
            DEV,
            &watch,
            Some(&mut ok),
        )
        .unwrap_err();
        assert!(err.contains("watch-only"), "clear watch-only error: {err}");
        // The oob_ok slot is left untouched (we never reached the verify step).
        assert!(ok, "no network step ran, so the oob flag was not written");
    }

    #[test]
    fn pop_refresh_constants_match_server_ttl() {
        // The TTL/margin/tick must keep a re-verify comfortably inside the window:
        // tick < margin < ttl, and margin leaves real headroom.
        assert_eq!(OOB_ALLOWLIST_TTL, Duration::from_secs(1800));
        assert_eq!(OOB_REFRESH_MARGIN, Duration::from_secs(300));
        assert!(OOB_REFRESH_TICK < OOB_REFRESH_MARGIN);
        assert!(OOB_REFRESH_MARGIN < OOB_ALLOWLIST_TTL);
    }

    // ── HTTPS control plane (NO network — pure URL/JSON logic only) ────────────

    // Process env is global; cargo runs tests on parallel threads. Serialize every
    // test that reads OR writes a control-plane env key through this one lock so two
    // tests can never observe each other's mid-flight override on a shared key.
    static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Run `f` with `key` unset, restoring any prior value afterward. The control-
    /// plane URL builders read process env, so isolate them from the ambient env.
    fn without_env(key: &str, f: impl FnOnce()) {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var(key).ok();
        std::env::remove_var(key);
        f();
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    /// Like [`without_env`] but unsets several keys at once (single lock, no
    /// re-entrancy — the guard is a plain non-reentrant Mutex).
    fn without_env_many(keys: &[&str], f: impl FnOnce()) {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let saved: Vec<(String, Option<String>)> = keys
            .iter()
            .map(|k| (k.to_string(), std::env::var(k).ok()))
            .collect();
        for k in keys {
            std::env::remove_var(k);
        }
        f();
        for (k, prev) in saved {
            match prev {
                Some(v) => std::env::set_var(&k, v),
                None => std::env::remove_var(&k),
            }
        }
    }

    /// Run `f` with `key` set to `val`, restoring any prior value afterward — under
    /// the same lock as [`without_env`].
    fn with_env(key: &str, val: &str, f: impl FnOnce()) {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var(key).ok();
        std::env::set_var(key, val);
        f();
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn region_challenge_url_built_from_host() {
        without_env(ENV_CHALLENGE_URL, || {
            let url = region_challenge_url("relay.us.aliceprotocol.org").unwrap();
            assert_eq!(url, "https://relay.us.aliceprotocol.org/m4/challenge");
        });
    }

    #[test]
    fn verify_url_derived_from_challenge() {
        let v = verify_url("https://relay.us.aliceprotocol.org/m4/challenge").unwrap();
        assert_eq!(v, "https://relay.us.aliceprotocol.org/m4/verify");
        // Only the trailing /m4/challenge is rewritten; an unrelated path fails closed.
        assert!(verify_url("https://relay/other").is_err());
        // Non-https challenge url is refused before any derivation.
        assert!(verify_url("http://relay/m4/challenge").is_err());
    }

    #[test]
    fn non_https_fails_closed() {
        // Env override that is non-https must be rejected (derivation itself is
        // always https, so the env path is where a plaintext url can sneak in).
        with_env(ENV_CHALLENGE_URL, "http://evil/m4/challenge", || {
            assert!(region_challenge_url("ignored.host").is_err());
        });
        // fetch_challenge / oob_verify guard the url too (no network is reached).
        assert!(fetch_challenge("http://relay/m4/challenge", ADDR, DEV).is_err());
        assert!(!oob_verify("http://relay/m4/verify", ADDR, DEV, "pop=x:y"));
    }

    #[test]
    fn region_host_unsafe_chars_fail_closed() {
        without_env(ENV_CHALLENGE_URL, || {
            assert!(region_challenge_url("bad host").is_err()); // whitespace
            assert!(region_challenge_url("evil/extra/path").is_err()); // slash
            assert!(region_challenge_url("ctl\u{0007}host").is_err()); // control char
            assert!(region_challenge_url("ho\nst").is_err()); // newline
            assert!(region_challenge_url("").is_err()); // empty
        });
    }

    #[test]
    fn env_override_replaces_derivation() {
        with_env(ENV_CHALLENGE_URL, "https://override.example/m4/challenge", || {
            // host arg is ignored when the override is present.
            let url = region_challenge_url("ignored").unwrap();
            assert_eq!(url, "https://override.example/m4/challenge");
        });
    }

    #[test]
    fn central_vs_region_host_selection() {
        // Default (no overrides) → both enroll URLs resolve to the central host.
        without_env_many(&[ENV_ENROLL_NONCE_URL, ENV_ENROLL_URL], || {
            assert_eq!(
                enroll_nonce_url().unwrap(),
                "https://api.aliceprotocol.org/acp/m4/enroll/nonce"
            );
            assert_eq!(
                enroll_url().unwrap(),
                "https://api.aliceprotocol.org/acp/m4/enroll"
            );
        });
        // Region challenge points at the relay host, NOT the central host.
        without_env(ENV_CHALLENGE_URL, || {
            assert!(region_challenge_url("relay.hk")
                .unwrap()
                .starts_with("https://relay.hk/"));
        });
        // Central enroll env overrides are honored and https-checked.
        with_env(ENV_ENROLL_URL, "https://staging.example/enroll", || {
            assert_eq!(enroll_url().unwrap(), "https://staging.example/enroll");
        });
        with_env(ENV_ENROLL_URL, "http://insecure/enroll", || {
            assert!(enroll_url().is_err());
        });
    }

    #[test]
    fn challenge_request_body_is_compact_ordered_json() {
        let body = ChallengeRequest {
            alice_address: ADDR,
            device_id: DEV,
        };
        let json = serde_json::to_string(&body).unwrap();
        assert_eq!(
            json,
            format!("{{\"alice_address\":\"{ADDR}\",\"device_id\":\"{DEV}\"}}")
        );
        assert!(!json.contains(' '), "compact: no spaces");
    }

    #[test]
    fn verify_request_body_uses_pop_field() {
        let body = VerifyRequest {
            alice_address: ADDR,
            device_id: DEV,
            pop: "pop=ch1:c2ln",
        };
        let json = serde_json::to_string(&body).unwrap();
        assert_eq!(
            json,
            format!(
                "{{\"alice_address\":\"{ADDR}\",\"device_id\":\"{DEV}\",\"pop\":\"pop=ch1:c2ln\"}}"
            )
        );
    }

    #[test]
    fn enroll_request_body_has_all_six_fields() {
        let body = EnrollRequest {
            alice_address: ADDR,
            device_id: DEV,
            prl_payout_address: "prl1ppayout",
            region: "us",
            nonce: "n-1",
            signature_b64: "c2lnYg==",
        };
        let json = serde_json::to_string(&body).unwrap();
        assert_eq!(
            json,
            format!(
                "{{\"alice_address\":\"{ADDR}\",\"device_id\":\"{DEV}\",\"prl_payout_address\":\"prl1ppayout\",\"region\":\"us\",\"nonce\":\"n-1\",\"signature_b64\":\"c2lnYg==\"}}"
            )
        );
    }

    #[test]
    fn enroll_nonce_request_body_shape() {
        let body = EnrollNonceRequest {
            alice_address: ADDR,
            device_id: DEV,
        };
        let json = serde_json::to_string(&body).unwrap();
        assert_eq!(
            json,
            format!("{{\"alice_address\":\"{ADDR}\",\"device_id\":\"{DEV}\"}}")
        );
    }

    #[test]
    fn challenge_response_parses_canonical_field() {
        let raw = r#"{"challenge_id":"ch-abc","challenge_nonce":"nonce-001"}"#;
        let resp: ChallengeResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(resp.challenge_id, "ch-abc");
        assert_eq!(resp.challenge_nonce.as_deref(), Some("nonce-001"));
        assert_eq!(resp.nonce, None);
    }

    #[test]
    fn challenge_response_legacy_nonce_field_compat() {
        // Older relay returns `nonce` instead of `challenge_nonce`.
        let raw = r#"{"challenge_id":"ch-legacy","nonce":"legacy-nonce-77"}"#;
        let resp: ChallengeResponse = serde_json::from_str(raw).unwrap();
        // The fold logic prefers challenge_nonce, falls back to nonce.
        let chosen = resp.challenge_nonce.or(resp.nonce).unwrap();
        assert_eq!(chosen, "legacy-nonce-77");
    }

    #[test]
    fn verify_response_accepts_ok_or_verified() {
        let ok: VerifyResponse = serde_json::from_str(r#"{"ok":true}"#).unwrap();
        assert!(ok.ok || ok.verified);
        let verified: VerifyResponse = serde_json::from_str(r#"{"verified":true}"#).unwrap();
        assert!(verified.ok || verified.verified);
        let neither: VerifyResponse = serde_json::from_str(r#"{"ok":false}"#).unwrap();
        assert!(!(neither.ok || neither.verified));
        // Missing fields default to false (serde default) → not verified.
        let empty: VerifyResponse = serde_json::from_str(r#"{}"#).unwrap();
        assert!(!(empty.ok || empty.verified));
    }

    #[test]
    fn enroll_nonce_response_parses() {
        let resp: EnrollNonceResponse =
            serde_json::from_str(r#"{"nonce":"enroll-nonce-xyz"}"#).unwrap();
        assert_eq!(resp.nonce, "enroll-nonce-xyz");
    }
}
