//! `core/lane/gpu_rvn` — the GPU-RVN (KawPoW) lane: the **KawPowMiner** launch
//! plan against Alice's re-hash relay (PLAN §6 D-GPU-miner: bundle KawPowMiner,
//! GPL-3.0, 0% fee, NVIDIA+AMD, cross-OS; T-Rex only via the
//! `ALICE_MINER_GPU_BIN` override).
//!
//! The arg shape is ported from
//! `Alice-Protocol/miner/mining_internal/trex_runner.py` (`build_trex_command`:
//! `-a kawpow -o stratum+tcp://<host:port> -u <user> -p <pass>`) and adapted to
//! kawpowminer's native ethminer-style `-P stratum+tcp://<user>.<rig>@<host:port>`
//! connection URL (the bundled default). Both forms carry EXACTLY the same
//! information; the honesty invariant below holds for whichever miner runs.
//!
//! ── CRITICAL HONESTY INVARIANT (PLAN §3 / the brief — SAME as the XMR lane) ──
//! The stratum login USER is the USER'S OWN Alice address (SS58-300), reusing
//! [`crate::lane::xmr::validate_alice_address`] + [`crate::lane::xmr::derive_worker_id`].
//! OUR RVN collection address and the upstream pool are **SERVER-SIDE on the
//! relay** and must NEVER appear in the client argv, code, or binary. The proxy's
//! open enrollment credits the user's address; a non-Alice login is NACKed. The
//! wallet seed/private key is NEVER passed. Unit tests below assert the built
//! argv carries the user's address, targets `:8888`, and contains NO
//! collection-address / upstream-pool / seed / private-key substring (the honesty
//! gate, per lane).
//!
//! **CREDIT-ONLY:** RVN is just the clean Alice-validated work substrate (MEMORY
//! GPU-LANE DIRECTION); the miner earns ALICE credit, RVN $/GPU ≈ 0. The same
//! capability gates as the XMR lane apply (`PAYOUT_RELEASE_ALLOWED=false`, …) —
//! they live in [`crate::lane::xmr`] and are shared, not redeclared.

#![allow(dead_code)]

use std::path::PathBuf;

use super::xmr::{derive_worker_id, MINING_EXECUTION_ALLOWED};
use super::{GpuSelection, Lane};
use crate::endpoint::{Endpoint, EndpointPlan};

/// kawpowminer's per-card device-selection flag (ethminer-derived). Appended
/// ONLY for a [`GpuSelection::Ids`] set; its value is the comma-separated 0-based
/// index list (e.g. `0,1,2`). [`GpuSelection::All`] appends nothing (all cards).
///
/// TODO(gpu-box): confirm the exact spelling (`--cuda-devices` vs `--devices`)
/// and the index→card mapping against the bundled kawpowminer build on a real
/// multi-GPU box. This fixes the argv *shape* only; the live correctness check is
/// deferred to the GPU-box e2e (same gate as the earn-proof), not this batch.
const KAWPOWMINER_DEVICES_FLAG: &str = "--cuda-devices";

/// T-Rex's per-card device-selection flag. Same opt-in semantics as
/// [`KAWPOWMINER_DEVICES_FLAG`]; value is the comma-separated 0-based index list.
///
/// TODO(gpu-box): confirm `--devices` spelling + index mapping on a real box.
const TREX_DEVICES_FLAG: &str = "--devices";

// ── Mining engine wiring (Alice re-hash relay, KawPoW/RVN) ──────────────────

/// Alice's own re-hash relay host (the friend's HK relay → core). **The ONLY
/// endpoint baked into the public client** — the upstream RVN pool + collection
/// address are server-side on the relay (PLAN §3, §6 D-Q5). Same host as the XMR
/// lane; different port.
pub const ALICE_POOL_HOST: &str = super::xmr::ALICE_POOL_HOST;
/// Client-facing stratum port for the RVN/KawPoW lane on the relay
/// (8888 → core 4444; MEMORY edge-node + PLAN §6 Q2, confirmed).
pub const ALICE_POOL_PORT: u16 = 8888;

/// The KawPoW algorithm token (kawpowminer / T-Rex both spell it `kawpow`).
const KAWPOW_ALGO: &str = "kawpow";

/// Everything needed to spawn the bundled KawPowMiner against Alice's relay,
/// fully validated. Pure / testable — actual process spawning lives in
/// [`crate::supervise`]. Same shape as the XMR [`crate::lane::xmr::MinerLaunchPlan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuLaunchPlan {
    pub program: PathBuf,
    pub args: Vec<String>,
}

/// The stratum connection URL for kawpowminer's `-P` flag against the DEFAULT
/// relay endpoint: `stratum+tcp://<alice_addr>.<rig_id>@<host>:<port>`. The login
/// user is the user's OWN Alice address; the rig id ([`derive_worker_id`]) is the
/// per-device worker name. NO password segment (the relay's open enrollment
/// needs none; XMR uses `-p x`, kawpowminer encodes the worker in the URL).
fn connection_url(reward: &str, rig_id: &str) -> String {
    format!("stratum+tcp://{reward}.{rig_id}@{ALICE_POOL_HOST}:{ALICE_POOL_PORT}")
}

/// The kawpowminer `-P` connection URL for an ARBITRARY [`Endpoint`] (Layer-A
/// failover): `<scheme>://<alice_addr>.<rig_id>@<host>:<port>`, where `<scheme>`
/// is `stratum+tcp` (plaintext, T0) or `stratum+ssl` (TLS, T1) — transport-aware
/// so M9 is additive. Same credential shape as [`connection_url`].
fn connection_url_for(reward: &str, rig_id: &str, ep: &Endpoint) -> String {
    format!(
        "{}://{reward}.{rig_id}@{}:{}",
        ep.transport.stratum_scheme(),
        ep.host,
        ep.port
    )
}

/// The plain `stratum+tcp://host:port` pool URL (no credentials) — used by the
/// T-Rex-style `-o/-u/-p` arg form. Ported from `trex_runner.py`'s
/// `pool_url = f"stratum+tcp://{route.pool_endpoint}"`.
fn pool_url() -> String {
    format!("stratum+tcp://{ALICE_POOL_HOST}:{ALICE_POOL_PORT}")
}

/// Build the validated **KawPowMiner** launch plan for the active reward
/// identity.
///
/// argv (kawpowminer, ethminer-style — the bundled default):
/// `-P stratum+tcp://<alice_addr>.<rig_id>@hk.aliceprotocol.org:8888
///  --report-hashrate --stratum-protocol 2 --display-interval 10`
///
/// The login USER is the user's OWN Alice reward identity (SS58-300) embedded in
/// the `-P` URL; `<rig_id>` ([`derive_worker_id`]) is a stable per-device worker
/// name. OUR RVN collection address + the upstream pool are handled SERVER-SIDE
/// by the relay; the wallet seed/private key is NEVER passed and the collection
/// address is NEVER present in this client. `derive_worker_id` doubles as the
/// fail-closed Alice-address validator (a non-Alice address fails here).
pub fn build_kawpowminer_launch_plan(
    program: PathBuf,
    reward_identity: &str,
) -> Result<GpuLaunchPlan, String> {
    // Single-endpoint convenience over the multi-endpoint builder so the
    // device-selection / argv shape lives in ONE place. `All` = unchanged argv.
    build_kawpowminer_launch_plan_with_endpoints(
        program,
        reward_identity,
        &[Endpoint::plaintext(ALICE_POOL_HOST, ALICE_POOL_PORT)],
        &GpuSelection::All,
    )
}

/// Build the **KawPowMiner** launch plan with **multi-endpoint failover (Layer A)
/// and transport awareness** — the M4 generalization of
/// [`build_kawpowminer_launch_plan`].
///
/// kawpowminer accepts MULTIPLE `-P` connection URLs and fails over between them
/// itself (its native fast failover). We emit one `-P <url>` per endpoint IN
/// ORDER (the supervisor passes them rotated to the active cursor — see
/// [`EndpointPlan::ordered_from_cursor`]); each URL embeds the user's OWN address
/// + rig id and uses the endpoint's transport scheme (`stratum+tcp`/`stratum+ssl`).
///
/// Same HONESTY invariant as the single-endpoint builder: every `-P` URL targets
/// an Alice-relay endpoint with the user's address as the login; no collection /
/// seed / upstream-pool string is present. (Endpoints come from an
/// [`EndpointPlan`]; the default is relay-only, the only non-relay source is the
/// operator override.)
pub fn build_kawpowminer_launch_plan_with_endpoints(
    program: PathBuf,
    reward_identity: &str,
    endpoints: &[Endpoint],
    gpus: &GpuSelection,
) -> Result<GpuLaunchPlan, String> {
    if !MINING_EXECUTION_ALLOWED {
        return Err("mining execution is not enabled in this build".into());
    }
    if endpoints.is_empty() {
        return Err("kawpowminer launch plan needs at least one endpoint".into());
    }
    let reward = reward_identity.trim();
    let rig_id = derive_worker_id(reward)?; // fail-closed Alice-address validation

    let mut args: Vec<String> = Vec::with_capacity(endpoints.len() * 2 + 6);
    // Layer A: one `-P <url>` per endpoint, in order.
    for ep in endpoints {
        args.push("-P".into());
        args.push(connection_url_for(reward, &rig_id, ep));
    }
    args.extend([
        "--report-hashrate".into(),
        "--stratum-protocol".into(),
        "2".into(),
        "--display-interval".into(),
        "10".into(),
    ]);
    // A5b: opt-in per-card restriction. `All` appends nothing → unchanged argv.
    if let Some(csv) = gpus.csv() {
        args.push(KAWPOWMINER_DEVICES_FLAG.into());
        args.push(csv);
    }
    Ok(GpuLaunchPlan { program, args })
}

/// Convenience: build the kawpowminer plan from an [`EndpointPlan`] (rotated to
/// its current cursor). The engine calls this for the GPU lane.
pub fn build_kawpowminer_launch_plan_for(
    program: PathBuf,
    reward_identity: &str,
    plan: &EndpointPlan,
    gpus: &GpuSelection,
) -> Result<GpuLaunchPlan, String> {
    build_kawpowminer_launch_plan_with_endpoints(
        program,
        reward_identity,
        &plan.ordered_from_cursor(),
        gpus,
    )
}

/// Build a **T-Rex**-style launch plan (the `ALICE_MINER_GPU_BIN` override path).
///
/// argv (ported VERBATIM-in-shape from `trex_runner.py`):
/// `-a kawpow -o stratum+tcp://hk.aliceprotocol.org:8888 -u <alice_addr> -p x
///  -w <rig_id>`
///
/// Same honesty invariant: `-u` is the user's OWN address; the relay host:8888 is
/// the only endpoint; no collection/seed/upstream string. T-Rex puts the login in
/// `-u` (not a URL), the worker in `-w`, and uses a conventional `-p x`.
pub fn build_trex_launch_plan(
    program: PathBuf,
    reward_identity: &str,
    gpus: &GpuSelection,
) -> Result<GpuLaunchPlan, String> {
    if !MINING_EXECUTION_ALLOWED {
        return Err("mining execution is not enabled in this build".into());
    }
    let reward = reward_identity.trim();
    let rig_id = derive_worker_id(reward)?;
    let mut args = vec![
        "-a".into(),
        KAWPOW_ALGO.into(),
        "-o".into(),
        pool_url(),
        "-u".into(),
        reward.to_string(),
        "-p".into(),
        "x".into(),
        "-w".into(),
        rig_id,
    ];
    // A5b: opt-in per-card restriction. `All` appends nothing → unchanged argv.
    if let Some(csv) = gpus.csv() {
        args.push(TREX_DEVICES_FLAG.into());
        args.push(csv);
    }
    Ok(GpuLaunchPlan { program, args })
}

/// The lane id (for the engine + UI). Always [`Lane::GpuRvn`].
pub const LANE: Lane = Lane::GpuRvn;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    /// A real SS58-300 address derived through the SHARED `alice_crypto` keystore,
    /// so the worker-id / honesty tests exercise a genuine Alice address (the same
    /// helper the XMR lane test uses).
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
    fn rvn_lane_targets_relay_on_port_8888() {
        // The client-facing RVN port is 8888 (→ core 4444), NOT the XMR 3333.
        assert_eq!(ALICE_POOL_PORT, 8888);
        assert_eq!(ALICE_POOL_HOST, "hk.aliceprotocol.org");
        assert_ne!(ALICE_POOL_PORT, super::super::xmr::ALICE_POOL_PORT);
    }

    #[test]
    fn kawpowminer_plan_url_has_address_rig_and_8888() {
        let addr = valid_address();
        let plan =
            build_kawpowminer_launch_plan(PathBuf::from("/opt/kawpowminer"), addr).expect("plan");

        // The -P URL carries the user's OWN address, the derived rig id, and the
        // relay :8888.
        let p = plan.args.iter().position(|a| a == "-P").expect("-P present");
        let url = &plan.args[p + 1];
        let rig = derive_worker_id(addr).unwrap();
        assert_eq!(
            url,
            &format!("stratum+tcp://{addr}.{rig}@hk.aliceprotocol.org:8888")
        );
        assert!(url.contains(addr), "login must be the user's own address");
        assert!(url.ends_with(":8888"), "must target the RVN client port 8888");

        // Modern KawPoW stratum + a 10s display cadence.
        assert!(plan
            .args
            .windows(2)
            .any(|w| w[0] == "--stratum-protocol" && w[1] == "2"));
        assert!(plan.args.iter().any(|a| a == "--report-hashrate"));
        assert!(plan
            .args
            .windows(2)
            .any(|w| w[0] == "--display-interval" && w[1] == "10"));
    }

    #[test]
    fn trex_plan_uses_kawpow_o_u_p_w_shape() {
        let addr = valid_address();
        let plan =
            build_trex_launch_plan(PathBuf::from("/opt/t-rex"), addr, &GpuSelection::All)
                .expect("plan");

        // Ported T-Rex shape: -a kawpow -o <pool> -u <addr> -p x -w <rig>.
        assert!(plan.args.windows(2).any(|w| w[0] == "-a" && w[1] == "kawpow"));
        let o = plan.args.iter().position(|a| a == "-o").expect("-o");
        assert_eq!(plan.args[o + 1], "stratum+tcp://hk.aliceprotocol.org:8888");
        let u = plan.args.iter().position(|a| a == "-u").expect("-u");
        assert_eq!(plan.args[u + 1].as_str(), addr);
        let pw = plan.args.iter().position(|a| a == "-p").expect("-p");
        assert_eq!(plan.args[pw + 1].as_str(), "x");
        let w = plan.args.iter().position(|a| a == "-w").expect("-w");
        assert_eq!(plan.args[w + 1], derive_worker_id(addr).unwrap());
        // A5b: the DEFAULT (All) appends no --devices flag (all cards).
        assert!(!plan.args.iter().any(|x| x == "--devices"));
    }

    /// THE HONESTY GATE (PLAN §3, the brief — per lane): both KawPoW arg forms
    /// must carry the user's address, target `:8888`, and contain NO
    /// collection-address / upstream-pool / seed / private-key substring.
    #[test]
    fn honesty_gate_rvn_argv_address_only_no_forbidden_substrings() {
        let addr = valid_address();
        for plan in [
            build_kawpowminer_launch_plan(PathBuf::from("/opt/kawpowminer"), addr).unwrap(),
            build_trex_launch_plan(PathBuf::from("/opt/t-rex"), addr, &GpuSelection::All).unwrap(),
        ] {
            let joined = plan.args.join(" ");

            // (0) The user's OWN address is present.
            assert!(joined.contains(addr), "argv must carry the user's address");

            // (1) The only endpoint is OUR relay on the RVN client port 8888.
            assert!(
                joined.contains(&format!("{ALICE_POOL_HOST}:{ALICE_POOL_PORT}")),
                "argv must target hk.aliceprotocol.org:8888"
            );
            // No OTHER stratum host/port — only our relay appears as a host:port.
            // (a) No generic upstream pool host.
            assert!(
                !joined.contains("pool.") && !joined.contains(".pool"),
                "an upstream pool host leaked into argv: {joined}"
            );
            // (b) The core IP must NEVER face the public client (PLAN §6 D-Q5).
            assert!(
                !joined.contains("203.0.113.10"),
                "the core IP leaked into the public client argv: {joined}"
            );

            // (2) OUR RVN collection wallet must NOT appear. A standard RVN address
            //     is base58, starts with 'R', length ~34 — assert no such token is
            //     present (only our SS58-300 Alice address is allowed).
            assert!(
                !plan
                    .args
                    .iter()
                    .flat_map(|a| a.split(['@', '.', '/', ':']))
                    .any(|tok| tok.len() == 34 && tok.starts_with('R')),
                "an RVN-mainnet-shaped collection address token leaked into argv: {joined}"
            );

            // (3) No seed / private-key material.
            assert!(
                !plan
                    .args
                    .iter()
                    .any(|a| a.contains("seed") || a.contains("priv") || a.contains("0x")),
                "a seed/private-key-shaped token leaked into argv: {joined}"
            );
        }
    }

    #[test]
    fn rvn_plan_fails_closed_on_bad_reward_identity() {
        assert!(build_kawpowminer_launch_plan(PathBuf::from("kawpowminer"), "not-an-address").is_err());
        assert!(build_trex_launch_plan(PathBuf::from("t-rex"), "not-an-address", &GpuSelection::All).is_err());
        // A generic-substrate (network 42) address is the WRONG network → rejected.
        assert!(build_kawpowminer_launch_plan(
            PathBuf::from("kawpowminer"),
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        )
        .is_err());
    }

    /// `derive_worker_id` REUSE (the M3 gate test (d)): the RVN rig id is exactly
    /// the same derivation as the XMR lane's — one worker-id function feeds both.
    #[test]
    fn worker_id_reused_from_xmr_lane() {
        let addr = valid_address();
        let rvn_rig = derive_worker_id(addr).unwrap();
        let xmr_rig = super::super::xmr::derive_worker_id(addr).unwrap();
        assert_eq!(rvn_rig, xmr_rig, "both lanes must derive the same worker id");
        // And it is embedded verbatim in the kawpowminer URL.
        let plan = build_kawpowminer_launch_plan(PathBuf::from("kawpowminer"), addr).unwrap();
        assert!(plan.args.iter().any(|a| a.contains(&rvn_rig)));
    }

    /// M4 Layer A (GPU): the multi-endpoint kawpowminer builder emits one `-P`
    /// URL per endpoint IN ORDER, each embedding the user's address + rig id, so
    /// kawpowminer fails over between them itself.
    #[test]
    fn multi_endpoint_kawpow_emits_one_dash_p_per_endpoint_in_order() {
        let addr = valid_address();
        let rig = derive_worker_id(addr).unwrap();
        let eps = vec![
            Endpoint::plaintext("blackhole.invalid", 65000),
            Endpoint::plaintext(ALICE_POOL_HOST, ALICE_POOL_PORT),
        ];
        let plan = build_kawpowminer_launch_plan_with_endpoints(
            PathBuf::from("kawpowminer"),
            addr,
            &eps,
            &GpuSelection::All,
        )
        .unwrap();
        let p_values: Vec<&String> = plan
            .args
            .iter()
            .enumerate()
            .filter(|(i, _)| *i > 0 && plan.args[i - 1] == "-P")
            .map(|(_, v)| v)
            .collect();
        assert_eq!(p_values.len(), 2);
        // Primary = the bogus endpoint; secondary = the relay. Both carry the
        // user's address + rig id.
        assert_eq!(
            p_values[0],
            &format!("stratum+tcp://{addr}.{rig}@blackhole.invalid:65000")
        );
        assert_eq!(
            p_values[1],
            &format!("stratum+tcp://{addr}.{rig}@{ALICE_POOL_HOST}:{ALICE_POOL_PORT}")
        );
    }

    /// A TLS (T1) endpoint yields a `stratum+ssl://` URL (transport-aware → M9
    /// additive); plaintext yields `stratum+tcp://`.
    #[test]
    fn tls_endpoint_yields_ssl_scheme_in_kawpow_url() {
        let addr = valid_address();
        let eps = vec![Endpoint::tls(ALICE_POOL_HOST, 8889)];
        let plan = build_kawpowminer_launch_plan_with_endpoints(
            PathBuf::from("kawpowminer"),
            addr,
            &eps,
            &GpuSelection::All,
        )
        .unwrap();
        let p = plan.args.iter().position(|a| a == "-P").unwrap();
        assert!(plan.args[p + 1].starts_with("stratum+ssl://"));
        assert!(plan.args[p + 1].ends_with("@hk.aliceprotocol.org:8889"));
    }

    /// `build_kawpowminer_launch_plan_for` rotates the EndpointPlan to its cursor.
    #[test]
    fn build_for_kawpow_endpoint_plan_respects_cursor() {
        let addr = valid_address();
        let mut ep_plan = EndpointPlan::new(vec![
            Endpoint::plaintext("blackhole.invalid", 65000),
            Endpoint::plaintext(ALICE_POOL_HOST, ALICE_POOL_PORT),
        ])
        .unwrap();
        ep_plan.advance(); // cursor → the relay
        let plan = build_kawpowminer_launch_plan_for(
            PathBuf::from("kawpowminer"),
            addr,
            &ep_plan,
            &GpuSelection::All,
        )
        .unwrap();
        let first_p = plan.args.iter().position(|a| a == "-P").unwrap();
        assert!(plan.args[first_p + 1].contains(&format!("@{ALICE_POOL_HOST}:{ALICE_POOL_PORT}")));
    }

    /// HONESTY (multi-endpoint, GPU): a relay-only multi-endpoint plan still
    /// carries the user's address, targets only the relay host, and contains no
    /// core IP / collection / upstream string.
    #[test]
    fn honesty_gate_multi_endpoint_kawpow_relay_only() {
        let addr = valid_address();
        let eps = vec![
            Endpoint::plaintext(ALICE_POOL_HOST, ALICE_POOL_PORT),
            Endpoint::tls(ALICE_POOL_HOST, 8889),
        ];
        let plan = build_kawpowminer_launch_plan_with_endpoints(
            PathBuf::from("kawpowminer"),
            addr,
            &eps,
            &GpuSelection::All,
        )
        .unwrap();
        let joined = plan.args.join(" ");
        assert!(joined.contains(addr));
        assert!(!joined.contains("203.0.113.10"));
        assert!(!joined.contains("pool.") && !joined.contains(".pool"));
        // Only the relay host appears.
        for url in plan.args.iter().filter(|a| a.starts_with("stratum+")) {
            assert!(url.contains(&format!("@{ALICE_POOL_HOST}:")));
        }
    }

    #[test]
    fn multi_endpoint_kawpow_fails_closed_on_empty_and_bad_address() {
        let addr = valid_address();
        assert!(build_kawpowminer_launch_plan_with_endpoints(
            PathBuf::from("kawpowminer"),
            addr,
            &[],
            &GpuSelection::All,
        )
        .is_err());
        let eps = vec![Endpoint::plaintext(ALICE_POOL_HOST, ALICE_POOL_PORT)];
        assert!(build_kawpowminer_launch_plan_with_endpoints(
            PathBuf::from("kawpowminer"),
            "not-an-address",
            &eps,
            &GpuSelection::All,
        )
        .is_err());
    }

    /// A5b REGRESSION GUARD (RVN): with [`GpuSelection::All`] the multi-endpoint
    /// kawpowminer argv is **byte-for-byte identical** to the pre-A5b argv (the
    /// `gpus` param appends nothing for `All`).
    #[test]
    fn kawpow_argv_all_is_unchanged_from_pre_a5b() {
        let addr = valid_address();
        let rig = derive_worker_id(addr).unwrap();
        let eps = vec![Endpoint::plaintext(ALICE_POOL_HOST, ALICE_POOL_PORT)];
        let plan = build_kawpowminer_launch_plan_with_endpoints(
            PathBuf::from("kawpowminer"),
            addr,
            &eps,
            &GpuSelection::All,
        )
        .unwrap();
        let expected: Vec<String> = vec![
            "-P".into(),
            format!("stratum+tcp://{addr}.{rig}@{ALICE_POOL_HOST}:{ALICE_POOL_PORT}"),
            "--report-hashrate".into(),
            "--stratum-protocol".into(),
            "2".into(),
            "--display-interval".into(),
            "10".into(),
        ];
        assert_eq!(plan.args, expected, "GpuSelection::All must not change the kawpow argv");
        // And the single-endpoint convenience builder matches it exactly.
        let single = build_kawpowminer_launch_plan(PathBuf::from("kawpowminer"), addr).unwrap();
        assert_eq!(single.args, expected);
    }

    /// A5b: [`GpuSelection::Ids`] APPENDS `--cuda-devices 0,1` to the kawpowminer
    /// argv (last), leaving the `-P`/flag order intact; the honesty gate holds.
    #[test]
    fn kawpow_argv_ids_appends_cuda_devices_flag() {
        let addr = valid_address();
        let eps = vec![Endpoint::plaintext(ALICE_POOL_HOST, ALICE_POOL_PORT)];
        let plan = build_kawpowminer_launch_plan_with_endpoints(
            PathBuf::from("kawpowminer"),
            addr,
            &eps,
            &GpuSelection::Ids(vec![0, 1]),
        )
        .unwrap();
        let n = plan.args.len();
        assert_eq!(
            &plan.args[n - 2..],
            &["--cuda-devices".to_string(), "0,1".to_string()]
        );
        // Honesty still holds with the digit-only device list appended.
        let joined = plan.args.join(" ");
        assert!(joined.contains(addr));
        assert!(joined.contains(&format!("{ALICE_POOL_HOST}:{ALICE_POOL_PORT}")));
        assert!(!joined.contains("203.0.113.10"));
        assert!(!joined.contains("herominers"));
        assert!(!plan
            .args
            .iter()
            .any(|a| a.contains("seed") || a.contains("priv") || a.contains("0x")));
    }

    /// A5b: T-Rex [`GpuSelection::Ids`] appends `--devices 0,1`; `All` appends none.
    #[test]
    fn trex_argv_ids_appends_devices_flag() {
        let addr = valid_address();
        let plan =
            build_trex_launch_plan(PathBuf::from("t-rex"), addr, &GpuSelection::Ids(vec![0, 1]))
                .unwrap();
        let n = plan.args.len();
        assert_eq!(&plan.args[n - 2..], &["--devices".to_string(), "0,1".to_string()]);
        // Honesty unaffected (digits only).
        let joined = plan.args.join(" ");
        assert!(joined.contains(addr));
        assert!(!plan
            .args
            .iter()
            .any(|a| a.contains("seed") || a.contains("priv") || a.contains("0x")));
    }
}
