//! T1 — PoP sr25519 cross-implementation conformance gate.
//!
//! Proves the load-bearing fact for the GPU-PRL PoP client: a signature produced
//! by this client's sr25519 stack (`subxt_signer`, the SAME key the wallet signs
//! real on-chain sends with) is byte-compatible with the server's verifier
//! (`substrate-interface` / `py-sr25519-bindings`, schnorrkel under signing
//! context `b"substrate"`).
//!
//! The golden vector was produced by the Python oracle (substrate-interface,
//! `KeypairType.SR25519`, `ss58_format=300`) over a FIXED mnemonic:
//!   "bottom drive obey lake curtain smoke basket hold race lonely fit walk"
//! See the spec's §4.1 keystone test. sr25519 signatures are randomized, so we
//! pin *verification* (not signature bytes): the Python signature MUST verify in
//! Rust, and a Rust signature MUST self-verify, both under the pubkey recovered
//! for the address embedded in the signed message.

use subxt_signer::sr25519::{verify, Keypair, PublicKey, Signature};

// ── Golden vector (Python oracle, fixed mnemonic, ss58_format=300) ───────────
const SEED_HEX: &str = "fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e";
const PUBKEY_HEX: &str = "46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a";
const SS58_300_ADDRESS: &str = "a2uJXaVk7Zx4fgk9aRLnhiD2RdpAP4usJxKXpN4vh4hDNoP1C";
const DEVICE_ID: &str = "worker-abc123";
const CHALLENGE_NONCE: &str = "nonce-deadbeef-0001";
const POP_DOMAIN: &str = "alice-acp:worker-pull:proof-of-possession:v1";
// 64-byte sr25519 signature produced by substrate-interface over the message below.
const PY_SIG_HEX: &str = "126fd3a80985ad9c2e0399e58e51688384ff890d033ce24774b13c3913076720f28bcc26b828406640a87cb7325dfafc150217b312dcb4f8bb1dd07dfb51ec8a";

fn arr32(hex_s: &str) -> [u8; 32] {
    hex::decode(hex_s).unwrap().try_into().unwrap()
}
fn arr64(hex_s: &str) -> [u8; 64] {
    hex::decode(hex_s).unwrap().try_into().unwrap()
}

/// The EXACT bytes the Alice key signs — byte-identical to the server's
/// `worker_pop.possession_signing_message` and the client `gpu_pop.pop_signature_message`:
/// domain line, then three `key=value` lines, newline-FRAMED (newline BETWEEN, NONE
/// trailing), ASCII. `device_id` None → sentinel "-".
fn pop_signature_message(alice_address: &str, device_id: Option<&str>, challenge_nonce: &str) -> Vec<u8> {
    let dev = device_id.unwrap_or("-");
    format!("{POP_DOMAIN}\nalice_address={alice_address}\ndevice_id={dev}\nchallenge_nonce={challenge_nonce}")
        .into_bytes()
}

#[test]
fn rust_keypair_derives_same_pubkey_as_python_oracle() {
    let kp = Keypair::from_secret_key(arr32(SEED_HEX)).expect("from_secret_key");
    assert_eq!(
        kp.public_key().0,
        arr32(PUBKEY_HEX),
        "subxt-signer MiniSecret/Ed25519 expansion must match substrate-interface derivation"
    );
}

#[test]
fn message_bytes_match_python_oracle_framing() {
    // Golden message bytes (what the Python oracle signed).
    let golden = format!(
        "{POP_DOMAIN}\nalice_address={SS58_300_ADDRESS}\ndevice_id={DEVICE_ID}\nchallenge_nonce={CHALLENGE_NONCE}"
    );
    let built = pop_signature_message(SS58_300_ADDRESS, Some(DEVICE_ID), CHALLENGE_NONCE);
    assert_eq!(built, golden.as_bytes(), "message builder must be byte-identical to server framing");
    // No trailing newline; ASCII only.
    assert_ne!(built.last(), Some(&b'\n'));
    assert!(built.is_ascii());
}

#[test]
fn python_signature_verifies_in_rust_cross_impl() {
    // THE GATE: a signature made by substrate-interface (the server's stack) must
    // verify under subxt-signer's `verify` (schnorrkel, ctx b"substrate").
    let pubkey = PublicKey(arr32(PUBKEY_HEX));
    let msg = pop_signature_message(SS58_300_ADDRESS, Some(DEVICE_ID), CHALLENGE_NONCE);
    let py_sig = Signature(arr64(PY_SIG_HEX));
    assert!(
        verify(&py_sig, &msg, &pubkey),
        "Python(substrate-interface) signature MUST verify in Rust(subxt-signer) — proves byte-compatible PoP"
    );
}

#[test]
fn rust_signature_self_verifies() {
    let kp = Keypair::from_secret_key(arr32(SEED_HEX)).expect("from_secret_key");
    let msg = pop_signature_message(SS58_300_ADDRESS, Some(DEVICE_ID), CHALLENGE_NONCE);
    let sig = kp.sign(&msg);
    assert!(verify(&sig, &msg, &kp.public_key()), "Rust signature must self-verify");
}

#[test]
fn tampered_message_and_foreign_key_fail() {
    let pubkey = PublicKey(arr32(PUBKEY_HEX));
    let py_sig = Signature(arr64(PY_SIG_HEX));
    // Tampered nonce → verify must fail.
    let tampered = pop_signature_message(SS58_300_ADDRESS, Some(DEVICE_ID), "nonce-WRONG");
    assert!(!verify(&py_sig, &tampered, &pubkey), "tampered message must NOT verify");
    // Foreign key (flip a byte) → must fail.
    let mut foreign = arr32(PUBKEY_HEX);
    foreign[0] ^= 0x01;
    let msg = pop_signature_message(SS58_300_ADDRESS, Some(DEVICE_ID), CHALLENGE_NONCE);
    assert!(!verify(&py_sig, &msg, &PublicKey(foreign)), "foreign pubkey must NOT verify");
}

// ── ENROLL (15% payout binding) — same fixture, distinct domain ──────────────
const ENROLL_DOMAIN: &str = "alice-acp:m4-enroll:bind-payout:v1";
const ENROLL_PAYOUT: &str = "prl1ptestpayout000000000000000000000000000000000000";
const ENROLL_NONCE: &str = "enroll-nonce-cafe-0002";
const PY_ENROLL_SIG_HEX: &str = "5485e9f27b36811dd971a81b0486a485a5fd8696e59644f8f26d6250c061f341524244c649533c115aab3f107d49559a443d7e625c1afac82c3fbf824f5e2286";

/// Enroll binding bytes — 4 `key=value` lines, device_id verbatim, no trailing newline.
fn enroll_signature_message(alice: &str, payout: &str, device_id: &str, nonce: &str) -> Vec<u8> {
    format!("{ENROLL_DOMAIN}\nalice_address={alice}\nprl_payout_address={payout}\ndevice_id={device_id}\nnonce={nonce}")
        .into_bytes()
}

#[test]
fn python_enroll_signature_verifies_in_rust() {
    let pubkey = PublicKey(arr32(PUBKEY_HEX));
    let msg = enroll_signature_message(SS58_300_ADDRESS, ENROLL_PAYOUT, DEVICE_ID, ENROLL_NONCE);
    let py_sig = Signature(arr64(PY_ENROLL_SIG_HEX));
    assert!(
        verify(&py_sig, &msg, &pubkey),
        "Python enroll signature MUST verify in Rust — proves byte-compatible payout binding"
    );
    // A login PoP signature must NOT verify as an enroll binding (domain separation).
    let login_sig = Signature(arr64(PY_SIG_HEX));
    assert!(!verify(&login_sig, &msg, &pubkey), "login sig must NOT satisfy enroll binding");
}
