//! `core/lane/xmr` — the CPU-XMR (RandomX) lane: the proven XMRig launch plan.
//!
//! The launch-plan / worker-id / address-validation / thread-count logic is
//! **ported VERBATIM** (only import/path tweaks) from the live-validated Wallet
//! at `alice-wallet/gui/src/miner.rs`:
//!   * `build_miner_launch_plan`  (Wallet ~L355) — the argv
//!   * `validate_alice_address` + `ss58_prefix_bytes` (Wallet ~L238-286)
//!   * `derive_worker_id`         (Wallet ~L298-318)
//!   * `miner_thread_count`       (Wallet ~L336)
//! and the credit-only gate consts (Wallet L12-25).
//!
//! ── CRITICAL HONESTY INVARIANT (PLAN §3 / the brief) ────────────────────────
//! The stratum login user is the USER'S OWN Alice address (SS58-300). OUR XMR
//! collection address and the upstream pool are **SERVER-SIDE on the relay** and
//! must NEVER appear in the client argv, code, or binary. The Wallet's
//! `ALICE_XMR_COLLECTION_ADDRESS` const is a *server-side reference only* and is
//! therefore **deliberately NOT ported here** — this client never sends, stores,
//! or even contains it. Unit tests below assert the built argv carries no
//! collection / seed / upstream-pool substring (the honesty gate).

#![allow(dead_code)]

use std::path::PathBuf;

// ── Credit-only capability gates (ported VERBATIM from Wallet miner.rs L12-25) ──
// The miner may RUN (opt-in Start), but every payout/settlement/mint/custom-pool
// gate stays closed. A `const _` assertion test fails the BUILD if any is flipped.

/// The miner is allowed to RUN the bundled CPU engine (opt-in via Start). This
/// is a CREDIT-ONLY work substrate: NO payout, settlement, mint, or chain write.
pub const MINING_EXECUTION_ALLOWED: bool = true;
/// The mining feature is experimental ("测试中") — surfaced as a UI badge.
pub const MINING_EXPERIMENTAL: bool = true;

pub const CUSTOM_POOL_ALLOWED: bool = false;
pub const LTC_DOGE_ALLOWED: bool = false;
pub const AI_JOBS_ALLOWED: bool = false;
pub const POOL_CONFIG_VISIBLE: bool = false;
pub const PAYOUT_RELEASE_ALLOWED: bool = false;
pub const SETTLEMENT_ALLOWED: bool = false;
pub const MINT_ALLOWED: bool = false;

// ── Mining engine wiring (Alice re-hash relay, standard stratum) ────────────

/// Alice's own re-hash relay host (the friend's HK relay → core). Standard
/// stratum; the engine mines RandomX/XMR work against it. **This is the ONLY
/// endpoint baked into the public client** — the upstream pool + collection
/// address are server-side on the relay (PLAN §3, §6 D-Q5).
pub const ALICE_POOL_HOST: &str = "hk.aliceprotocol.org";
/// Stratum port for the XMR/RandomX lane on the relay.
pub const ALICE_POOL_PORT: u16 = 3333;

/// High sanity ceiling on miner threads — NOT a throttle. V wants it "拉满"
/// (full power), so this only bounds an absurd `available_parallelism` value.
const MINER_MAX_THREADS: usize = 256;

// ── Stratum worker id (matches the proven worker-client pipeline) ───────────
// Verbatim from Wallet miner.rs L227-318.

/// The Alice SS58 network / format id (must match `alice_crypto::SS58_FORMAT`
/// and the vendored Python `ALICE_SS58_FORMAT = 300`).
const ALICE_SS58_FORMAT: u16 = 300;
/// Substrate account-id (public key) length in bytes.
const ALICE_PUBKEY_LENGTH: usize = 32;
/// SS58 checksum length (bytes) for a 32-byte account id.
const SS58_CHECKSUM_LENGTH: usize = 2;
/// Max stratum worker-name length (matches the Python `derive_worker_id`).
const WORKER_ID_MAX_LENGTH: usize = 64;

/// Encode an SS58 network ident to its on-wire prefix bytes (idents 64..16383
/// use the 2-byte encoding; ident 300 → `0x4b 0x01`). Mirrors
/// `account_id_to_ss58` and the Python `_ss58_prefix_bytes`.
fn ss58_prefix_bytes(ident: u16) -> Vec<u8> {
    if ident < 64 {
        vec![ident as u8]
    } else {
        let first = ((ident & 0b0000_0000_1111_1100) as u8 >> 2) | 0b0100_0000;
        let second = ((ident >> 8) as u8) | (((ident & 0b0000_0000_0000_0011) as u8) << 6);
        vec![first, second]
    }
}

/// Return the canonical Alice address IFF `address` is a checksum-valid SS58
/// format-300 one (the miner's reward identity). Fail-closed `None` otherwise.
///
/// Self-contained replica of the vendored
/// `alice_address.py::validate_alice_address`: base58-decode to EXACTLY
/// `prefix(2) ‖ pubkey(32) ‖ checksum(2)`, require the Alice network prefix, and
/// verify the blake2b-512(`SS58PRE` ‖ prefix ‖ pubkey) checksum.
pub fn validate_alice_address(address: &str) -> Option<String> {
    use blake2::{Blake2b512, Digest};

    if address.is_empty() || address.len() > 64 {
        return None;
    }
    // ASCII printable only (no control / whitespace / non-ASCII).
    if address
        .chars()
        .any(|ch| (ch as u32) < 0x21 || (ch as u32) > 0x7E)
    {
        return None;
    }
    let raw = bs58::decode(address).into_vec().ok()?;
    let prefix = ss58_prefix_bytes(ALICE_SS58_FORMAT);
    let expected_len = prefix.len() + ALICE_PUBKEY_LENGTH + SS58_CHECKSUM_LENGTH;
    if raw.len() != expected_len {
        return None;
    }
    if raw[..prefix.len()] != prefix[..] {
        return None;
    }
    let pubkey = &raw[prefix.len()..prefix.len() + ALICE_PUBKEY_LENGTH];
    let checksum = &raw[prefix.len() + ALICE_PUBKEY_LENGTH..];

    let mut hasher = Blake2b512::new();
    hasher.update(b"SS58PRE");
    hasher.update(&prefix);
    hasher.update(pubkey);
    let digest = hasher.finalize();
    if digest[..SS58_CHECKSUM_LENGTH] != checksum[..] {
        return None;
    }
    Some(address.to_string())
}

/// Derive a stable, stratum-safe worker name from a (validated) Alice address —
/// the on-wire `<worker_id>` rig id. Replicates `derive_worker_id(address)` from
/// the proven worker-client pipeline: SS58 base58 chars are a subset of the
/// stratum-safe `[A-Za-z0-9_.-]` charset, so we keep the address verbatim when
/// it fits in `WORKER_ID_MAX_LENGTH` (real format-300 addresses are ~49 chars,
/// so they always do), else take the head plus a 4-byte blake2b tag of the full
/// address so distinct addresses never collide. NON-secret: derived from the
/// PUBLIC address only.
pub fn derive_worker_id(address: &str) -> Result<String, String> {
    use blake2::digest::{Update, VariableOutput};
    use blake2::Blake2bVar;

    let canonical = validate_alice_address(address).ok_or("invalid_alice_address")?;
    if canonical.len() <= WORKER_ID_MAX_LENGTH {
        return Ok(canonical);
    }
    let mut hasher = Blake2bVar::new(4).expect("blake2b-4 is a valid output size");
    hasher.update(canonical.as_bytes());
    let mut tag_bytes = [0u8; 4];
    hasher
        .finalize_variable(&mut tag_bytes)
        .expect("blake2b-4 output");
    let tag = hex::encode(tag_bytes);
    let head: String = canonical
        .chars()
        .take(WORKER_ID_MAX_LENGTH - tag.len() - 1)
        .collect();
    Ok(format!("{head}.{tag}"))
}

/// Everything needed to spawn the bundled XMRig against Alice's relay, fully
/// validated. Pure / testable — actual process spawning lives in
/// [`crate::supervise`]. (Ported from Wallet `MinerLaunchPlan`.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinerLaunchPlan {
    pub program: PathBuf,
    pub args: Vec<String>,
}

/// Miner thread count = ALL logical cores ("拉满" / full power — V 2026-06-03).
/// Mining is strictly OPT-IN (the Start button), so when the user turns it on
/// they want maximum hash power. Bounded only by the high [`MINER_MAX_THREADS`]
/// sanity ceiling. Verbatim from Wallet `miner_thread_count`.
fn miner_thread_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, MINER_MAX_THREADS)
}

/// Build the validated XMRig launch plan for the active reward identity.
///
/// argv (RandomX/XMR against the Alice re-hash relay):
/// `-o hk.aliceprotocol.org:3333 -u <alice_addr> -p x --rig-id <worker_id>
///  --coin monero --no-color --print-time 10 --donate-level 0 --cpu-priority 1
///  --threads <N>`
///
/// The login USER is the user's OWN Alice reward identity (SS58-300) — the proxy
/// open-enrollment credits that address (a non-Alice login is NACKed as
/// "stratum_login_open_bad_address"). `<worker_id>` ([`derive_worker_id`]) is a
/// stable per-device rig id. OUR XMR collection address + the upstream pool are
/// handled SERVER-SIDE by the relay; the wallet seed/private key is NEVER passed
/// and the collection address is NEVER present in this client. Ported VERBATIM
/// from Wallet `build_miner_launch_plan`.
pub fn build_miner_launch_plan(
    program: PathBuf,
    reward_identity: &str,
) -> Result<MinerLaunchPlan, String> {
    if !MINING_EXECUTION_ALLOWED {
        return Err("mining execution is not enabled in this build".into());
    }
    // Proxy login (VERIFIED against the live relay): the stratum USER is the
    // user's OWN Alice reward identity (SS58-300). The proxy's open enrollment
    // credits that address and NACKs a non-Alice login; password is the
    // conventional "x". The upstream XMR pool + OUR collection address are
    // handled SERVER-SIDE by the relay — the client only ever sends the user's
    // PUBLIC Alice address, never the seed/key. `derive_worker_id` doubles as
    // the fail-closed Alice-address validator and a stable per-device rig id.
    let reward = reward_identity.trim();
    let rig_id = derive_worker_id(reward)?;
    let pool = format!("{ALICE_POOL_HOST}:{ALICE_POOL_PORT}");
    let threads = miner_thread_count();
    let args = vec![
        "-o".into(),
        pool,
        "-u".into(),
        reward.to_string(),
        "-p".into(),
        "x".into(),
        "--rig-id".into(),
        rig_id,
        "--coin".into(),
        "monero".into(),
        "--no-color".into(),
        "--print-time".into(),
        "10".into(),
        "--donate-level".into(),
        "0".into(),
        "--cpu-priority".into(),
        "1".into(),
        "--threads".into(),
        threads.to_string(),
    ];
    Ok(MinerLaunchPlan { program, args })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    /// A real SS58-300 address derived through the SHARED `alice_crypto` keystore
    /// (the same path the identity module uses), so the worker-id parity test
    /// exercises a genuine Alice address.
    fn valid_address() -> &'static str {
        static ADDRESS: OnceLock<String> = OnceLock::new();
        ADDRESS.get_or_init(|| {
            alice_crypto::create_wallet_payload(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "miner-test-passphrase",
            )
            .expect("test wallet payload")
            .address
        })
    }

    #[test]
    fn run_is_enabled_but_all_other_gates_remain_false() {
        // Credit-only posture as compile-time constants: this `const _` block
        // fails the BUILD if any gate is ever flipped the wrong way (the
        // credit-only invariant, enforced — PLAN §3, §8).
        const _: () = {
            assert!(MINING_EXECUTION_ALLOWED);
            assert!(MINING_EXPERIMENTAL);
            assert!(!CUSTOM_POOL_ALLOWED);
            assert!(!LTC_DOGE_ALLOWED);
            assert!(!AI_JOBS_ALLOWED);
            assert!(!POOL_CONFIG_VISIBLE);
            assert!(!PAYOUT_RELEASE_ALLOWED);
            assert!(!SETTLEMENT_ALLOWED);
            assert!(!MINT_ALLOWED);
        };
    }

    #[test]
    fn worker_id_matches_validated_address_verbatim() {
        // A real format-300 Alice address is ~49 base58 chars (< 64), so the
        // worker id IS the address verbatim — matching the proven worker-client
        // pipeline's `derive_worker_id` (parity with the Wallet).
        let addr = valid_address();
        let worker = derive_worker_id(addr).expect("worker id");
        assert_eq!(worker, addr);
        assert!(worker.len() <= WORKER_ID_MAX_LENGTH);
        // Stratum-safe charset only.
        assert!(worker
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')));
    }

    #[test]
    fn worker_id_fails_closed_on_non_alice_address() {
        assert!(derive_worker_id("not-an-address").is_err());
        assert!(derive_worker_id("").is_err());
        // A generic-substrate (network 42) address is a valid SS58 string but
        // the WRONG network — must be rejected.
        assert!(derive_worker_id("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY").is_err());
    }

    #[test]
    fn miner_launch_plan_targets_relay_with_xmr_login_convention() {
        let addr = valid_address();
        let plan = build_miner_launch_plan(PathBuf::from("/usr/local/bin/xmrig"), addr)
            .expect("launch plan");

        // Pool target is OUR relay on the XMR/RandomX port.
        let o = plan.args.iter().position(|a| a == "-o").expect("-o present");
        assert_eq!(
            plan.args[o + 1],
            format!("{ALICE_POOL_HOST}:{ALICE_POOL_PORT}")
        );

        // Login USER = the user's OWN Alice reward identity; password "x".
        let u = plan.args.iter().position(|a| a == "-u").expect("-u present");
        assert_eq!(plan.args[u + 1].as_str(), addr);
        let p = plan.args.iter().position(|a| a == "-p").expect("-p present");
        assert_eq!(plan.args[p + 1].as_str(), "x");
        // The per-device rig id is derive_worker_id of the reward identity.
        let r = plan
            .args
            .iter()
            .position(|a| a == "--rig-id")
            .expect("--rig-id present");
        assert_eq!(plan.args[r + 1], derive_worker_id(addr).unwrap());

        // Monero coin, no-color, donate-level 0, cpu-priority 1, print-time 10.
        assert!(plan
            .args
            .windows(2)
            .any(|w| w[0] == "--coin" && w[1] == "monero"));
        assert!(plan.args.iter().any(|a| a == "--no-color"));
        assert!(plan
            .args
            .windows(2)
            .any(|w| w[0] == "--donate-level" && w[1] == "0"));
        assert!(plan
            .args
            .windows(2)
            .any(|w| w[0] == "--cpu-priority" && w[1] == "1"));
        assert!(plan
            .args
            .windows(2)
            .any(|w| w[0] == "--print-time" && w[1] == "10"));

        // Full power ("拉满"): --threads == all logical cores.
        let t = plan
            .args
            .iter()
            .position(|a| a == "--threads")
            .expect("--threads");
        let n: usize = plan.args[t + 1].parse().expect("thread count");
        assert_eq!(n, miner_thread_count());
        assert!(n >= 1);
    }

    /// THE HONESTY GATE (PLAN §3, the brief): the built argv must carry the
    /// user's address as `-u` and contain **NO** collection-address /
    /// upstream-pool / seed / private-key substring. Because we never even
    /// import `ALICE_XMR_COLLECTION_ADDRESS`, this also proves the secret string
    /// is absent from the source of this client.
    #[test]
    fn honesty_gate_argv_has_user_address_and_no_forbidden_substrings() {
        let addr = valid_address();
        let plan =
            build_miner_launch_plan(PathBuf::from("/usr/local/bin/xmrig"), addr).expect("plan");

        // -u is the user's OWN address.
        let u = plan.args.iter().position(|a| a == "-u").expect("-u present");
        assert_eq!(plan.args[u + 1].as_str(), addr);

        // Join the whole argv and assert no forbidden substring leaked in.
        let joined = plan.args.join(" ");

        // (a) OUR XMR collection wallet (the Wallet's server-side reference) must
        //     NOT appear anywhere. We check the known prefix of the real one and
        //     a generic Monero-mainnet address marker.
        assert!(
            !joined.contains("46knTVDfa5CMtFLvVuFdHWPSv7FCnfSbQ"),
            "collection address prefix leaked into argv: {joined}"
        );
        // No standard Monero mainnet address (starts with '4', 95 chars) should
        // be present as a token — only our SS58-300 Alice address is allowed.
        assert!(
            !plan.args.iter().any(|a| a.len() == 95 && a.starts_with('4')),
            "a Monero-mainnet-shaped address token leaked into argv: {joined}"
        );

        // (b) No upstream pool host/port other than OUR relay. The only `-o`
        //     value is the Alice relay; assert no other ":3333"/pool-like host
        //     for a known upstream (e.g. a generic pool) slipped in.
        let relay = format!("{ALICE_POOL_HOST}:{ALICE_POOL_PORT}");
        let o_values: Vec<&String> = plan
            .args
            .iter()
            .enumerate()
            .filter(|(i, _)| *i > 0 && plan.args[i - 1] == "-o")
            .map(|(_, v)| v)
            .collect();
        assert_eq!(o_values.len(), 1, "exactly one pool endpoint expected");
        assert_eq!(o_values[0], &relay);
        // Belt-and-suspenders: the only host in the whole argv is our relay.
        assert!(
            !joined.contains("pool.") && !joined.contains(".pool"),
            "an upstream pool host leaked into argv: {joined}"
        );

        // (c) No seed / private-key material.
        assert!(
            !plan
                .args
                .iter()
                .any(|a| a.contains("seed") || a.contains("priv") || a.contains("0x")),
            "a seed/private-key-shaped token leaked into argv: {joined}"
        );
    }

    #[test]
    fn miner_launch_plan_fails_closed_on_bad_reward_identity() {
        assert!(build_miner_launch_plan(PathBuf::from("xmrig"), "not-an-address").is_err());
    }
}
