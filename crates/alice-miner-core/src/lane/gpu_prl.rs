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

use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

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

// ════════════════════════════════════════════════════════════════════════════
// Region selection (lowest-RTT-wins, with an operator override)
// ════════════════════════════════════════════════════════════════════════════

/// Env override: force a specific region by its short tag (`us` / `asia` / `fi`).
/// When set to a KNOWN tag it REPLACES the RTT probe; an unknown/empty value is
/// ignored (falls back to the RTT probe).
pub const ENV_REGION: &str = "ALICE_GPU_RELAY_REGION";

/// Per-region TCP-connect timeout for the RTT probe. A region that doesn't
/// answer within this is treated as unreachable (skipped). Kept short so the
/// startup probe over all three regions is bounded (~3×).
const RTT_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

/// Order the region relay [`Endpoint`]s by ascending TCP-connect RTT to their
/// `:3340` stratum port, putting the lowest-latency region first. The full set is
/// always returned (Layer-A failover + the supervisor's Layer-B cursor still want
/// every region) — only the ORDER changes.
///
/// Resolution:
///   1. `$ALICE_GPU_RELAY_REGION=<tag>` (us/asia/fi) → that region is forced to
///      the head (no probe); unknown/empty values are ignored.
///   2. otherwise probe all three with [`probe_rtt`] and sort by latency;
///      unreachable regions sort last (in their default order).
///   3. if EVERY region is unreachable, fall back to the US-first default order
///      (so the lane still launches and the miner's own reconnect can take over).
pub fn select_region_endpoints() -> Vec<Endpoint> {
    let defaults = region_default_endpoints();

    // (1) Operator override by region tag.
    if let Ok(tag) = std::env::var(ENV_REGION) {
        let tag = tag.trim().to_ascii_lowercase();
        if let Some(idx) = REGION_HOSTS.iter().position(|(t, _)| *t == tag) {
            let mut ordered = vec![defaults[idx].clone()];
            ordered.extend(
                defaults
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != idx)
                    .map(|(_, e)| e.clone()),
            );
            return ordered;
        }
        // unknown/empty tag → fall through to the RTT probe.
    }

    // (2) RTT probe each region; sort reachable-first by ascending latency.
    let mut scored: Vec<(Option<Duration>, Endpoint)> = defaults
        .iter()
        .map(|e| (probe_rtt(&e.host, e.port), e.clone()))
        .collect();
    // Stable sort: Some(rtt) ascending first, None (unreachable) last keeping the
    // default relative order among unreachable ones.
    scored.sort_by(|a, b| match (a.0, b.0) {
        (Some(x), Some(y)) => x.cmp(&y),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });

    let ordered: Vec<Endpoint> = scored.into_iter().map(|(_, e)| e).collect();
    // (3) If nothing was reachable the sort is a no-op (all None) → this is exactly
    // the US-first default order, which is the desired fallback.
    if ordered.is_empty() {
        defaults
    } else {
        ordered
    }
}

/// TCP-connect RTT to `host:port`, or `None` if it can't be reached within
/// [`RTT_PROBE_TIMEOUT`]. Resolves the host then times a `connect_timeout` to the
/// FIRST resolved address (the cheapest reachability+latency signal without a
/// full stratum handshake). Never panics.
fn probe_rtt(host: &str, port: u16) -> Option<Duration> {
    let addr = (host, port)
        .to_socket_addrs()
        .ok()?
        .next()?; // first resolved socket addr
    let start = Instant::now();
    match TcpStream::connect_timeout(&addr, RTT_PROBE_TIMEOUT) {
        Ok(stream) => {
            // Close immediately; we only wanted the connect latency.
            drop(stream);
            Some(start.elapsed())
        }
        Err(_) => None,
    }
}

/// Build an [`EndpointPlan`] for the GPU-PRL lane with the regions ordered by
/// lowest RTT (the operator override / probe / US-first fallback from
/// [`select_region_endpoints`]). The engine uses this so the lane's primary
/// (cursor-0) endpoint is the nearest region; Layer-B still advances through the
/// rest on no-progress.
pub fn region_plan_by_rtt() -> EndpointPlan {
    EndpointPlan::new(select_region_endpoints())
        .unwrap_or_else(|_| EndpointPlan::single(default_region_endpoint()))
}

/// The US-first default region endpoint (the ultimate fallback head).
pub fn default_region_endpoint() -> Endpoint {
    Endpoint::plaintext(REGION_HOSTS[0].1, GPU_RELAY_PORT)
}

/// The `<host>:<port>` authority for the ACTIVE (cursor) endpoint of a plan — the
/// region the PoP handshake must target (the token is region-bound). Returns the
/// host (no port) too, since the PoP challenge URL is `https://<host>/m4/challenge`
/// (port-independent control plane).
pub fn active_region_host(plan: &EndpointPlan) -> String {
    plan.current().host.clone()
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

    // Region-selection env override is process-global; serialize the tests that
    // read/write it so parallel cargo threads can't observe each other's value.
    static REGION_ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn region_override_forces_tag_to_head_keeping_full_set() {
        let _g = REGION_ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var(ENV_REGION).ok();
        // Force asia → asia must be cursor-0, all three regions still present.
        std::env::set_var(ENV_REGION, "asia");
        let eps = select_region_endpoints();
        assert_eq!(eps.len(), 3, "the full region set is always returned");
        assert_eq!(eps[0].host, "asia.aliceprotocol.org");
        assert!(eps.iter().all(|e| e.port == GPU_RELAY_PORT));
        // Every default host is still represented (only the ORDER changed).
        for (_, host) in REGION_HOSTS {
            assert!(eps.iter().any(|e| e.host == host), "missing region {host}");
        }
        // Case-insensitive.
        std::env::set_var(ENV_REGION, "FI");
        assert_eq!(select_region_endpoints()[0].host, "fi.aliceprotocol.org");

        match prev {
            Some(v) => std::env::set_var(ENV_REGION, v),
            None => std::env::remove_var(ENV_REGION),
        }
    }

    #[test]
    fn region_override_unknown_tag_does_not_force_head() {
        let _g = REGION_ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var(ENV_REGION).ok();
        // An unknown tag is ignored (falls through to the RTT probe). We can't
        // assert the probe's ORDER offline, but the set must be intact + non-empty
        // and contain exactly the three region hosts.
        std::env::set_var(ENV_REGION, "atlantis");
        let eps = select_region_endpoints();
        assert_eq!(eps.len(), 3);
        for (_, host) in REGION_HOSTS {
            assert!(eps.iter().any(|e| e.host == host));
        }
        match prev {
            Some(v) => std::env::set_var(ENV_REGION, v),
            None => std::env::remove_var(ENV_REGION),
        }
    }

    #[test]
    fn active_region_host_is_cursor_host() {
        let mut plan = EndpointPlan::new(vec![
            Endpoint::plaintext("us.aliceprotocol.org", GPU_RELAY_PORT),
            Endpoint::plaintext("asia.aliceprotocol.org", GPU_RELAY_PORT),
        ])
        .unwrap();
        assert_eq!(active_region_host(&plan), "us.aliceprotocol.org");
        plan.advance();
        assert_eq!(active_region_host(&plan), "asia.aliceprotocol.org");
    }

    #[test]
    fn region_plan_by_rtt_is_relay_only_full_set() {
        let _g = REGION_ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        // Force a deterministic head so this never depends on the network probe.
        let prev = std::env::var(ENV_REGION).ok();
        std::env::set_var(ENV_REGION, "us");
        let plan = region_plan_by_rtt();
        let ordered = plan.ordered_from_cursor();
        assert_eq!(ordered.len(), 3);
        assert!(ordered
            .iter()
            .all(|e| e.host.ends_with("aliceprotocol.org") && e.port == GPU_RELAY_PORT));
        match prev {
            Some(v) => std::env::set_var(ENV_REGION, v),
            None => std::env::remove_var(ENV_REGION),
        }
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
