//! `core/lane/gpu_prl` — the **GPU-PRL** lane: the GPU **mainline** (V: "GPU 主线
//! = PRL,展示不隐藏"). It launches **SRBMiner-MULTI** on the `pearlhash` algorithm
//! against Alice's region relays on `:3340`, with a **mandatory M4 Proof-of-
//! Possession** token in the stratum password.
//!
//! This is a DIFFERENT path from [`super::gpu_rvn`] (kawpowminer/KawPoW →
//! `hk:8888`, no PoP): different binary (SRBMiner), algorithm (`pearlhash`), port
//! (`3340`), region host-set (us/asia/fi), and auth model (PoP). Only the
//! *structure* (the [`GpuLaunchPlan`], `derive_worker_id` reuse, the per-lane
//! honesty gate) is shared.
//!
//! ── HONESTY INVARIANT (per V's GPU-PRL direction) ───────────────────────────
//! PRL is shown OPENLY (it is the GPU mainline, not hidden), so `pearlhash` and
//! the region relay hosts MAY appear in argv. What must NEVER appear in the client
//! argv/code/binary: the foundation's `prl1p…` **collection** address (the relay
//! assigns it server-side), any upstream pool host (e.g. herominers), the core IP,
//! or seed/private-key material. The stratum login USER is the user's OWN Alice
//! SS58-300 address; the worker suffix is [`derive_worker_id`]; the password is the
//! PoP token (`pop=<id>:<sig>`, assembled in [`crate::pop`]). The user's own 15%
//! PRL **payout** address is bound via the SEPARATE enroll flow, never in mining argv.
//!
//! **CREDIT-ONLY:** same capability gates as the XMR/RVN lanes
//! (`MINING_EXECUTION_ALLOWED`, `PAYOUT_RELEASE_ALLOWED=false`) — shared from
//! [`crate::lane::xmr`], not redeclared.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use super::gpu_rvn::GpuLaunchPlan;
use super::xmr::{derive_worker_id, MINING_EXECUTION_ALLOWED};
use super::Lane;
use crate::endpoint::{Endpoint, EndpointPlan};

/// SRBMiner's algorithm token for the Alice GPU-PRL lane. argv-only.
const PEARLHASH_ALGO: &str = "pearlhash";

/// Client-facing stratum port for the GPU-PRL lane on the region relays.
pub const GPU_RELAY_PORT: u16 = 3340;

/// The region relay hosts (lowest-RTT wins at runtime; US is the default order
/// head). These ARE public Alice relay endpoints — shown openly.
pub const REGION_HOSTS: [(&str, &str); 3] = [
    ("us", "us.aliceprotocol.org"),
    ("asia", "asia.aliceprotocol.org"),
    ("fi", "fi.aliceprotocol.org"),
];

/// The default region order (US-first) as plaintext [`Endpoint`]s on [`GPU_RELAY_PORT`].
/// Runtime RTT selection reorders these (see the wiring layer); the supervisor's
/// Layer-B cursor advances between them on no-progress.
pub fn region_default_endpoints() -> Vec<Endpoint> {
    REGION_HOSTS
        .iter()
        .map(|(_, host)| Endpoint::plaintext(*host, GPU_RELAY_PORT))
        .collect()
}

/// Build the validated **SRBMiner pearlhash** launch plan against ONE region
/// endpoint.
///
/// argv: `--algorithm pearlhash --pool stratum+tcp://<host>:3340
///        --wallet <alice_addr>.<worker> --password <pop_token>
///        --disable-cpu --log-file <path>`
///
/// * `reward_identity` — the user's OWN Alice SS58-300 address (the stratum login);
///   [`derive_worker_id`] doubles as the fail-closed validator.
/// * `pop_token` — the assembled `pop=<challenge_id>:<sig>` (from [`crate::pop`]);
///   MUST be present under the relay's `REQUIRE_POP=1` (the OOB allowlist is what
///   actually authorizes, but the token rides the password too).
/// * `log_path` — the supervisor-owned log file. SRBMiner emits share/hashrate
///   lines ONLY to `--log-file`, so it is **mandatory** (without it the dashboard
///   reads 0 and health checks false-error).
pub fn build_srbminer_pearl_launch_plan(
    program: PathBuf,
    reward_identity: &str,
    region_endpoint: &str,
    pop_token: &str,
    log_path: &Path,
) -> Result<GpuLaunchPlan, String> {
    if !MINING_EXECUTION_ALLOWED {
        return Err("mining execution is not enabled in this build".into());
    }
    let reward = reward_identity.trim();
    let worker = derive_worker_id(reward)?; // fail-closed Alice-address validation
    let wallet = format!("{reward}.{worker}");
    let pool = format!("stratum+tcp://{region_endpoint}");
    let args = vec![
        "--algorithm".into(),
        PEARLHASH_ALGO.into(),
        "--pool".into(),
        pool,
        "--wallet".into(),
        wallet,
        "--password".into(),
        pop_token.to_string(),
        "--disable-cpu".into(),
        "--log-file".into(),
        log_path.display().to_string(),
    ];
    Ok(GpuLaunchPlan { program, args })
}

/// The `<host>:<port>` authority for an [`Endpoint`] (transport-agnostic — SRBMiner
/// takes the scheme in `--pool stratum+tcp://`; TLS region endpoints are a future
/// additive change).
fn endpoint_authority(ep: &Endpoint) -> String {
    format!("{}:{}", ep.host, ep.port)
}

/// Build the SRBMiner plan for the ACTIVE endpoint of an [`EndpointPlan`] (rotated
/// to its cursor). The engine calls this for the GPU-PRL lane; on a Layer-B
/// supervisor restart the cursor advances to the next region and the wiring layer
/// re-fetches a region-bound PoP token before the rebuild.
pub fn build_srbminer_pearl_launch_plan_for(
    program: PathBuf,
    reward_identity: &str,
    plan: &EndpointPlan,
    pop_token: &str,
    log_path: &Path,
) -> Result<GpuLaunchPlan, String> {
    let ordered = plan.ordered_from_cursor();
    let Some(active) = ordered.first() else {
        return Err("gpu-prl launch plan needs at least one endpoint".into());
    };
    build_srbminer_pearl_launch_plan(
        program,
        reward_identity,
        &endpoint_authority(active),
        pop_token,
        log_path,
    )
}

/// The lane id (for the engine + UI). Always [`Lane::GpuPrl`].
pub const LANE: Lane = Lane::GpuPrl;

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

    fn log_path() -> PathBuf {
        std::env::temp_dir().join("alice-prl-test.log")
    }

    #[test]
    fn prl_lane_constants() {
        assert_eq!(GPU_RELAY_PORT, 3340);
        assert_eq!(LANE, Lane::GpuPrl);
        assert_eq!(Lane::GpuPrl.id(), "prl");
        assert_eq!(region_default_endpoints().len(), 3);
        assert!(region_default_endpoints()
            .iter()
            .all(|e| e.port == 3340 && e.host.ends_with("aliceprotocol.org")));
    }

    #[test]
    fn srbminer_argv_shape_is_pearlhash_wallet_pop_logfile() {
        let addr = valid_address();
        let lp = log_path();
        let plan = build_srbminer_pearl_launch_plan(
            PathBuf::from("/opt/SRBMiner-MULTI"),
            addr,
            "us.aliceprotocol.org:3340",
            "pop=ch123:c2lnYmFzZTY0",
            &lp,
        )
        .expect("plan");
        let a = &plan.args;
        // --algorithm pearlhash
        let alg = a.iter().position(|x| x == "--algorithm").expect("--algorithm");
        assert_eq!(a[alg + 1], "pearlhash");
        // --pool stratum+tcp://us...:3340
        let pool = a.iter().position(|x| x == "--pool").expect("--pool");
        assert_eq!(a[pool + 1], "stratum+tcp://us.aliceprotocol.org:3340");
        // --wallet <addr>.<worker>
        let w = a.iter().position(|x| x == "--wallet").expect("--wallet");
        assert_eq!(a[w + 1], format!("{addr}.{}", derive_worker_id(addr).unwrap()));
        // --password <pop token>
        let pw = a.iter().position(|x| x == "--password").expect("--password");
        assert_eq!(a[pw + 1], "pop=ch123:c2lnYmFzZTY0");
        // --disable-cpu + mandatory --log-file
        assert!(a.iter().any(|x| x == "--disable-cpu"));
        let lf = a.iter().position(|x| x == "--log-file").expect("--log-file mandatory");
        assert_eq!(a[lf + 1], lp.display().to_string());
    }

    /// THE HONESTY GATE (GPU-PRL): pearlhash + region host are OPEN, but no
    /// foundation collection `prl1p…`, no upstream pool host, no core IP, no seed.
    #[test]
    fn honesty_gate_prl_argv_no_server_side_secrets() {
        let addr = valid_address();
        let lp = log_path();
        let plan = build_srbminer_pearl_launch_plan(
            PathBuf::from("/opt/SRBMiner-MULTI"),
            addr,
            "asia.aliceprotocol.org:3340",
            "pop=abc:def",
            &lp,
        )
        .unwrap();
        let joined = plan.args.join(" ");
        // (0) user's own address present; targets a region relay :3340.
        assert!(joined.contains(addr));
        assert!(joined.contains(":3340"));
        // (1) NO prl1p collection/payout address anywhere in mining argv.
        assert!(!joined.contains("prl1p"), "a prl1p address leaked into mining argv: {joined}");
        // (2) NO upstream pool host (e.g. herominers) and NO core IP.
        assert!(!joined.contains("herominers"), "upstream pool host leaked: {joined}");
        assert!(!joined.contains("203.0.113.10"), "core IP leaked: {joined}");
        // (3) only *.aliceprotocol.org hosts appear as a stratum authority.
        for tok in plan.args.iter().filter(|a| a.starts_with("stratum+")) {
            assert!(tok.contains("aliceprotocol.org:"), "non-Alice relay host in argv: {tok}");
        }
        // (4) no seed / private-key material.
        assert!(!plan
            .args
            .iter()
            .any(|a| a.contains("seed") || a.contains("priv") || a.contains("0x")));
    }

    #[test]
    fn prl_plan_fails_closed_on_bad_reward_identity() {
        let lp = log_path();
        assert!(build_srbminer_pearl_launch_plan(
            PathBuf::from("SRBMiner-MULTI"),
            "not-an-address",
            "us.aliceprotocol.org:3340",
            "pop=a:b",
            &lp,
        )
        .is_err());
        // Wrong-network (substrate-42) address rejected.
        assert!(build_srbminer_pearl_launch_plan(
            PathBuf::from("SRBMiner-MULTI"),
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
            "us.aliceprotocol.org:3340",
            "pop=a:b",
            &lp,
        )
        .is_err());
    }

    #[test]
    fn build_for_uses_endpoint_plan_cursor() {
        let addr = valid_address();
        let lp = log_path();
        let mut plan = EndpointPlan::new(vec![
            Endpoint::plaintext("us.aliceprotocol.org", GPU_RELAY_PORT),
            Endpoint::plaintext("asia.aliceprotocol.org", GPU_RELAY_PORT),
        ])
        .unwrap();
        plan.advance(); // cursor → asia
        let lplan = build_srbminer_pearl_launch_plan_for(
            PathBuf::from("SRBMiner-MULTI"),
            addr,
            &plan,
            "pop=a:b",
            &lp,
        )
        .unwrap();
        let pool = lplan.args.iter().position(|x| x == "--pool").unwrap();
        assert_eq!(lplan.args[pool + 1], "stratum+tcp://asia.aliceprotocol.org:3340");
    }

    #[test]
    fn worker_id_shared_with_xmr_lane() {
        let addr = valid_address();
        assert_eq!(
            derive_worker_id(addr).unwrap(),
            super::super::xmr::derive_worker_id(addr).unwrap()
        );
    }
}
