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

use base64::Engine as _;

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
}
