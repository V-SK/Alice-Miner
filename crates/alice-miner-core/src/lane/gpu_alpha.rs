//! `core/lane/gpu_alpha` — the **GPU-Alpha** lane: the **Volta/V100 pearlhash path**
//! via **AlphaMiner** (`alpha-miner` v1.8.3) against Alice's alpha relay on `:3341`
//! (a pearl/v1 transparent proxy to AlphaPool). SRBMiner cannot mine pearlhash on
//! Volta (CC 7.0); alpha-miner can (`backend=volta_sm70`), so this lane covers the
//! V100-class cards [`super::gpu_prl`] (SRBMiner, CC ≥ 7.5) leaves out.
//!
//! Same reward model + 15%-PRL return + credit ledger as GPU-PRL; the differences are
//! all mechanical (the captured real flags, 2026-06-26 V100 run, see
//! `_launch/artifacts/alphaminer-real-logs/`):
//!   * binary: **alpha-miner** ([`crate::binaries::MinerKind::GpuAlpha`]);
//!   * port: **`:3341`** (the alpha relay), not `:3340`;
//!   * login: alpha-miner **REQUIRES a `prl1` `--address`** and REJECTS the `a2…`
//!     Alice address, so the login is `<placeholder_prl1>.<alice>.<device_id>` —
//!     the Alice (credit identity) rides the **worker**, and the address is a PUBLIC
//!     placeholder the relay REWRITES to the foundation deposit (upstream hiding);
//!   * algorithm: pearlhash is the ONLY algo — there is **NO `--algorithm` flag**
//!     (passing one errors `unknown argument`, the real-capture lesson);
//!   * PoP: the stratum `--password` is AlphaPool's plain `x` (the relay/pool own the
//!     `pearl.challenge`); the M4 Proof-of-Possession is **out-of-band** (the same
//!     `establish_pop` HTTP the GPU-PRL lane uses), so NO pop token rides argv here.
//!
//! ── HONESTY INVARIANT ───────────────────────────────────────────────────────
//! The relay host + `:3341` are shown openly (the alpha relay is a public Alice
//! endpoint). What must NEVER appear in client argv/code: the foundation's REAL
//! `prl1` **collection** address (the client carries only the PLACEHOLDER, which the
//! relay swaps server-side), any upstream pool host (AlphaPool), the core IP, or
//! seed/key material. CREDIT-ONLY: same `MINING_EXECUTION_ALLOWED` gate as the other
//! lanes; nothing here mints / pays.

#![allow(dead_code)]

use std::path::PathBuf;

use super::gpu_prl::REGION_HOSTS;
use super::gpu_rvn::GpuLaunchPlan;
use super::xmr::{derive_worker_id, MINING_EXECUTION_ALLOWED};
use super::{GpuSelection, Lane};
use crate::endpoint::{Endpoint, EndpointPlan};

/// Client-facing stratum port for the GPU-Alpha lane on the region relays (the
/// pearl/v1 transparent-proxy listener, distinct from GPU-PRL's `:3340`).
pub const ALPHA_RELAY_PORT: u16 = 3341;

/// Env override for the PUBLIC placeholder `prl1` the client passes as alpha-miner's
/// REQUIRED `--address`. The relay REWRITES it to the foundation's AlphaPool deposit
/// (upstream hiding), so its exact value is immaterial to crediting — but alpha-miner
/// bech32-CHECKSUM-validates it, so the live value must be a syntactically-valid,
/// PUBLIC `prl1` (NEVER the real foundation collection address). V supplies the
/// canonical published placeholder; this env lets the e2e set it without a rebuild.
pub const ENV_ALPHA_PLACEHOLDER: &str = "ALICE_ALPHA_PLACEHOLDER_ADDRESS";

/// The default placeholder `prl1` (overridable via [`ENV_ALPHA_PLACEHOLDER`]). It is
/// a PUBLIC, relay-rewritten stand-in — NOT the foundation collection address (which
/// never lives in the client, per the honesty invariant above).
///
/// This is a **deterministic burn address**: a Taproot (witness v1) output over an
/// all-zeros 32-byte program, bech32m-encoded for the `prl` HRP. It is a
/// syntactically valid `prl1` (so alpha-miner's bech32 checksum check passes) yet is
/// provably NOT a real collection target (no known key, the relay rewrites it server
/// side before any share counts). V may swap in a branded published placeholder at
/// any time via this const or [`ENV_ALPHA_PLACEHOLDER`] — the value is immaterial to
/// crediting. (Codec verified by round-tripping the live transit address, 2026-06-27.)
pub const DEFAULT_ALPHA_PLACEHOLDER: &str =
    "prl1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqen4g90";

/// Resolve the placeholder `prl1` for `--address`: env override, else the default.
pub fn alpha_placeholder_address() -> String {
    std::env::var(ENV_ALPHA_PLACEHOLDER)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_ALPHA_PLACEHOLDER.to_string())
}

/// The region relay [`Endpoint`]s for the GPU-Alpha lane (`:3341`), reusing the
/// shared region host-set. Public Alice endpoints, shown openly.
pub fn region_default_endpoints() -> Vec<Endpoint> {
    REGION_HOSTS
        .iter()
        .map(|(_, host)| Endpoint::plaintext(*host, ALPHA_RELAY_PORT))
        .collect()
}

/// The US-first default region endpoint on `:3341` (the fallback head).
pub fn default_region_endpoint() -> Endpoint {
    Endpoint::plaintext(REGION_HOSTS[0].1, ALPHA_RELAY_PORT)
}

/// Build the validated **alpha-miner** launch plan against ONE region endpoint.
///
/// argv (the REAL captured v1.8.3 flags — NO `--algorithm`):
/// `--pool <host>:3341 --address <placeholder_prl1>
///  --worker <alice>.<device_id> --password x --status-interval 1
///  [--force-backend <backend>] [--devices <csv>]`
///
/// * `reward_identity` — the user's OWN Alice SS58-300 address (the credit identity);
///   [`derive_worker_id`] doubles as the fail-closed validator AND the device-id, so
///   the relay's worker-tail (`<alice>.<device_id>`) equals the OOB-PoP `device_id`.
/// * `region_endpoint` — `host:port` of the active alpha relay (`:3341`).
/// * `placeholder` — the relay-rewritten public placeholder prl1 (`--address`).
/// * `backend` — `Some("volta")` to pin Volta/V100 (or any
///   `turing|ampere|ada|hopper|blackwell|…`); `None` lets alpha-miner auto-detect.
/// * `gpus` — [`GpuSelection::All`] appends no device flag (every card); `Ids`
///   appends `--devices <0-based,csv>` (alpha-miner's CUDA device indices).
///
/// NOTE: the M4 PoP is OUT-OF-BAND (the engine calls `establish_pop` before this);
/// it never rides argv — the `--password` is AlphaPool's plain `x`.
pub fn build_alphaminer_launch_plan(
    program: PathBuf,
    reward_identity: &str,
    region_endpoint: &str,
    placeholder: &str,
    backend: Option<&str>,
    gpus: &GpuSelection,
) -> Result<GpuLaunchPlan, String> {
    if !MINING_EXECUTION_ALLOWED {
        return Err("mining execution is not enabled in this build".into());
    }
    let alice = reward_identity.trim();
    let device_id = derive_worker_id(alice)?; // fail-closed Alice-address validation
    // login = "<placeholder>.<alice>.<device_id>": address rides --address; the Alice
    // credit identity + device-id ride --worker (alpha-miner joins them as ADDR.WORKER).
    let worker = format!("{alice}.{device_id}");
    let mut args = vec![
        "--pool".into(),
        region_endpoint.to_string(),
        "--address".into(),
        placeholder.to_string(),
        "--worker".into(),
        worker,
        "--password".into(),
        "x".into(),
        "--status-interval".into(),
        "1".into(),
    ];
    if let Some(b) = backend {
        args.push("--force-backend".into());
        args.push(b.to_string());
    }
    // Opt-in per-card restriction (alpha-miner's `--devices` = CUDA indices). `All`
    // appends nothing (every card).
    if let Some(csv) = gpus.csv() {
        args.push("--devices".into());
        args.push(csv);
    }
    Ok(GpuLaunchPlan { program, args })
}

/// Build the alpha-miner plan for the ACTIVE endpoint of an [`EndpointPlan`] (rotated
/// to its cursor) — the engine's per-(re)build entry. Mirrors
/// [`super::gpu_prl::build_srbminer_pearl_launch_plan_for`].
pub fn build_alphaminer_launch_plan_for(
    program: PathBuf,
    reward_identity: &str,
    plan: &EndpointPlan,
    placeholder: &str,
    backend: Option<&str>,
    gpus: &GpuSelection,
) -> Result<GpuLaunchPlan, String> {
    let ordered = plan.ordered_from_cursor();
    let Some(active) = ordered.first() else {
        return Err("gpu-alpha launch plan needs at least one endpoint".into());
    };
    let authority = format!("{}:{}", active.host, active.port);
    build_alphaminer_launch_plan(program, reward_identity, &authority, placeholder, backend, gpus)
}

/// The lane id (for the engine + UI). Always [`Lane::GpuAlpha`].
pub const LANE: Lane = Lane::GpuAlpha;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

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
    fn alpha_lane_constants() {
        assert_eq!(ALPHA_RELAY_PORT, 3341);
        assert_eq!(LANE, Lane::GpuAlpha);
        assert_eq!(Lane::GpuAlpha.id(), "alpha");
        assert!(Lane::GpuAlpha.is_prl_lane());
        assert_eq!(region_default_endpoints().len(), 3);
        assert!(region_default_endpoints()
            .iter()
            .all(|e| e.port == 3341 && e.host.ends_with("aliceprotocol.org")));
    }

    #[test]
    fn alphaminer_argv_real_flags_no_algorithm() {
        let addr = valid_address();
        let plan = build_alphaminer_launch_plan(
            PathBuf::from("/opt/alpha-miner"),
            addr,
            "us.aliceprotocol.org:3341",
            "prl1pPLACEHOLDERxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            Some("volta"),
            &GpuSelection::All,
        )
        .expect("plan");
        let a = &plan.args;
        // --pool host:3341
        let pool = a.iter().position(|x| x == "--pool").unwrap();
        assert_eq!(a[pool + 1], "us.aliceprotocol.org:3341");
        // --address <placeholder>  (NOT the alice address)
        let addr_i = a.iter().position(|x| x == "--address").unwrap();
        assert!(a[addr_i + 1].starts_with("prl1p"));
        assert_ne!(a[addr_i + 1], addr);
        // --worker <alice>.<device_id>
        let w = a.iter().position(|x| x == "--worker").unwrap();
        assert_eq!(a[w + 1], format!("{addr}.{}", derive_worker_id(addr).unwrap()));
        // --password x  (PoP is out-of-band, never in argv)
        let pw = a.iter().position(|x| x == "--password").unwrap();
        assert_eq!(a[pw + 1], "x");
        // --force-backend volta + --status-interval 1
        let fb = a.iter().position(|x| x == "--force-backend").unwrap();
        assert_eq!(a[fb + 1], "volta");
        let si = a.iter().position(|x| x == "--status-interval").unwrap();
        assert_eq!(a[si + 1], "1");
        // THE captured lesson: NO --algorithm flag.
        assert!(!a.iter().any(|x| x == "--algorithm"), "alpha-miner has no --algorithm");
        // All cards by default → no --devices.
        assert!(!a.iter().any(|x| x == "--devices"));
    }

    #[test]
    fn alphaminer_argv_auto_backend_and_device_selection() {
        let addr = valid_address();
        // backend=None → no --force-backend (auto-detect).
        let auto = build_alphaminer_launch_plan(
            PathBuf::from("alpha-miner"),
            addr,
            "asia.aliceprotocol.org:3341",
            "prl1pPLACEHOLDER",
            None,
            &GpuSelection::All,
        )
        .unwrap();
        assert!(!auto.args.iter().any(|x| x == "--force-backend"));
        // Ids → --devices 0,1 appended.
        let sel = build_alphaminer_launch_plan(
            PathBuf::from("alpha-miner"),
            addr,
            "asia.aliceprotocol.org:3341",
            "prl1pPLACEHOLDER",
            Some("volta"),
            &GpuSelection::Ids(vec![0, 1]),
        )
        .unwrap();
        let d = sel.args.iter().position(|x| x == "--devices").unwrap();
        assert_eq!(sel.args[d + 1], "0,1");
    }

    #[test]
    fn alpha_plan_fails_closed_on_bad_reward_identity() {
        assert!(build_alphaminer_launch_plan(
            PathBuf::from("alpha-miner"),
            "not-an-address",
            "us.aliceprotocol.org:3341",
            "prl1pPLACEHOLDER",
            Some("volta"),
            &GpuSelection::All,
        )
        .is_err());
    }

    /// THE HONESTY GATE (GPU-Alpha): the relay host + `:3341` are open; the `--address`
    /// is a PUBLIC placeholder prl1 (relay-rewritten). What must NOT leak: the Alice
    /// address as the bech32 --address (it rides --worker), any upstream pool host
    /// (AlphaPool), the core IP, or seed/key material.
    #[test]
    fn honesty_gate_alpha_argv_no_server_side_secrets() {
        let addr = valid_address();
        let plan = build_alphaminer_launch_plan(
            PathBuf::from("alpha-miner"),
            addr,
            "fi.aliceprotocol.org:3341",
            &alpha_placeholder_address(),
            Some("volta"),
            &GpuSelection::All,
        )
        .unwrap();
        let joined = plan.args.join(" ");
        // user's Alice rides the worker; the alpha relay :3341 is the only authority.
        assert!(joined.contains(addr));
        assert!(joined.contains(":3341"));
        // NO upstream pool host / core IP / seed.
        assert!(!joined.contains("alphapool"), "upstream pool host leaked: {joined}");
        assert!(!joined.contains("herominers"));
        assert!(!joined.contains("203.0.113.10"), "core IP leaked: {joined}");
        assert!(!plan.args.iter().any(|a| a.contains("seed") || a.contains("priv") || a.contains("0x")));
        // The only stratum authority is *.aliceprotocol.org:3341.
        let pool = plan.args.iter().position(|x| x == "--pool").unwrap();
        assert!(plan.args[pool + 1].contains("aliceprotocol.org:3341"));
    }

    /// The default placeholder MUST be a checksum-valid bech32m `prl1` — alpha-miner
    /// bech32-validates `--address` and REJECTS a bad checksum, so an invalid default
    /// silently bricks the V100 lane out-of-box. Self-contained BIP-350 verify (no dep)
    /// so this invariant can never regress (it would have caught the old placeholder).
    #[test]
    fn default_placeholder_is_valid_bech32m() {
        const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        const BECH32M_CONST: u32 = 0x2bc8_30a3;
        fn polymod(values: &[u8]) -> u32 {
            const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
            let mut chk: u32 = 1;
            for &v in values {
                let b = chk >> 25;
                chk = ((chk & 0x1ff_ffff) << 5) ^ v as u32;
                for (i, g) in GEN.iter().enumerate() {
                    if (b >> i) & 1 == 1 {
                        chk ^= g;
                    }
                }
            }
            chk
        }
        let addr = DEFAULT_ALPHA_PLACEHOLDER;
        let pos = addr.rfind('1').expect("has a separator");
        let (hrp, data_part) = (&addr[..pos], &addr[pos + 1..]);
        assert_eq!(hrp, "prl", "HRP must be prl");
        let mut values: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
        values.push(0);
        values.extend(hrp.bytes().map(|b| b & 31));
        for c in data_part.bytes() {
            let idx = CHARSET.iter().position(|&x| x == c).expect("valid bech32 char");
            values.push(idx as u8);
        }
        assert_eq!(polymod(&values), BECH32M_CONST, "default placeholder bech32m checksum invalid");
    }

    #[test]
    fn placeholder_env_override() {
        // Default when unset; env override wins (process-global env — guarded).
        static G: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = G.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var(ENV_ALPHA_PLACEHOLDER).ok();
        std::env::remove_var(ENV_ALPHA_PLACEHOLDER);
        assert_eq!(alpha_placeholder_address(), DEFAULT_ALPHA_PLACEHOLDER);
        std::env::set_var(ENV_ALPHA_PLACEHOLDER, "prl1pCUSTOMplaceholder");
        assert_eq!(alpha_placeholder_address(), "prl1pCUSTOMplaceholder");
        match prev {
            Some(v) => std::env::set_var(ENV_ALPHA_PLACEHOLDER, v),
            None => std::env::remove_var(ENV_ALPHA_PLACEHOLDER),
        }
    }
}
