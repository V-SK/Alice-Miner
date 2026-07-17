//! `core/lane/gpu_prl` — the **GPU-PRL** lane: the GPU **mainline** (V: "GPU 主线
//! = PRL,展示不隐藏"). It launches **SRBMiner-MULTI** on the `pearlhash` algorithm
//! against Alice's region relays on `:3340`, with a **mandatory M4 Proof-of-
//! Possession** token in the stratum password.
//!
//! This is a DIFFERENT path from [`super::gpu_rvn`] (kawpowminer/KawPoW →
//! `hk:8888`, no PoP): different binary (SRBMiner), algorithm (`pearlhash`), port
//! (`3340`), region host-set (us/asia), and auth model (PoP). Only the
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
use super::{GpuSelection, Lane};
use crate::endpoint::{Endpoint, EndpointPlan};

/// SRBMiner's algorithm token for the Alice GPU-PRL lane. argv-only.
const PEARLHASH_ALGO: &str = "pearlhash";

/// SRBMiner's per-card device-selection flag. argv-only; appended ONLY when the
/// lane is restricted to a [`GpuSelection::Ids`] set (its value is the
/// comma-separated 0-based index list, e.g. `0,1,2`). With [`GpuSelection::All`]
/// no flag is appended at all, so SRBMiner uses every detected card (the
/// pre-A5b default — byte-for-byte unchanged argv).
///
/// CONFIRMED (2026-06-26, SRBMiner-MULTI 3.4.1 `--list-devices` on a real box): the
/// `--gpu-id` value is SRBMiner's OWN global device index across ALL backends
/// (OpenCL + CUDA). It does NOT track nvidia-smi / OS order and CAN include an
/// integrated GPU at id 0 (observed: id 0 = Intel iGPU, id 1 = RTX 3070 Ti, id 2 =
/// RTX 4070 Ti). So a `--gpus` value is the MINER's device id — list them with
/// [`list_srbminer_devices`] (the `gpu-devices` CLI command); they are NOT the
/// `detect` / nvidia-smi indices. The one stable cross-tool key is the PCI address.
const SRBMINER_GPU_ID_FLAG: &str = "--gpu-id";

/// One GPU as SRBMiner-MULTI's `--list-devices` enumerates it. `id` is exactly what
/// `--gpu-id` (and the client's `--gpus`) selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrbGpuDevice {
    /// SRBMiner's global device id (the `--gpu-id` / `--gpus` value).
    pub id: u32,
    /// `"CUDA"` (NVIDIA, pearlhash-capable) or `"OpenCL"` (may be an integrated GPU).
    pub backend: String,
    /// PCI address, e.g. `0000:01:00.0` — the stable key shared with nvidia-smi
    /// (empty if SRBMiner didn't report one).
    pub pci: String,
    /// SRBMiner's device name, e.g. `nvidia_geforce_rtx_3070_ti_laptop_gpu`.
    pub name: String,
}

/// Parse SRBMiner-MULTI `--list-devices` stdout. Real 3.4.1 lines:
///   `GPU1  [CUDA][1] [0000:01:00.0] : nvidia_geforce_rtx_3070_ti_laptop_gpu [ampere] ...`
///   `GPU0  [1][0] [0000:00:02.0] : intel_r__iris_r__xe_graphics [unknown_intel] ...`
/// Header lines (`OPENCL devices`, `CUDA devices`) and any non-`GPU<n>` line ignored.
pub fn parse_srbminer_devices(stdout: &str) -> Vec<SrbGpuDevice> {
    let mut out = Vec::new();
    for raw in stdout.lines() {
        let line = raw.trim();
        let Some(after) = line.strip_prefix("GPU") else {
            continue;
        };
        let id_str: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
        let Ok(id) = id_str.parse::<u32>() else {
            continue;
        };
        let brackets = bracket_contents(line);
        let backend = if brackets.first().map(String::as_str) == Some("CUDA") {
            "CUDA"
        } else {
            "OpenCL"
        }
        .to_string();
        let pci = brackets.iter().find(|b| looks_like_pci(b)).cloned().unwrap_or_default();
        let name = line
            .split(" : ")
            .nth(1)
            .map(|s| s.split(" [").next().unwrap_or(s).trim().to_string())
            .unwrap_or_default();
        out.push(SrbGpuDevice { id, backend, pci, name });
    }
    out
}

/// The contents of each `[...]` on a line, in order.
fn bracket_contents(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'[' {
            if let Some(end) = line[i + 1..].find(']') {
                out.push(line[i + 1..i + 1 + end].trim().to_string());
                i = i + 1 + end + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// A PCI address like `0000:01:00.0` (domain:bus:device.function).
fn looks_like_pci(s: &str) -> bool {
    s.contains(':')
        && s.contains('.')
        && s.chars().all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
}

/// Resolve (download + verify if needed) the SRBMiner-MULTI engine and run it with
/// `--list-devices`, returning the parsed device list. The `id`s match exactly what
/// a GPU-PRL `--gpus` selection passes to `--gpu-id`, so this is the authoritative
/// "which number is which card" source (the `gpu-devices` CLI command).
pub fn list_srbminer_devices() -> Result<Vec<SrbGpuDevice>, String> {
    let bin = crate::binaries::resolve_miner_binary(crate::binaries::MinerKind::GpuPrl)?;
    let output = std::process::Command::new(&bin)
        .arg("--list-devices")
        .output()
        .map_err(|e| format!("running {} --list-devices: {e}", bin.display()))?;
    Ok(parse_srbminer_devices(&String::from_utf8_lossy(&output.stdout)))
}

/// Client-facing stratum port for the GPU-PRL lane on the region relays.
pub const GPU_RELAY_PORT: u16 = 3340;

/// The region relay hosts (lowest-RTT wins at runtime; US is the default order
/// head). These ARE public Alice relay endpoints — shown openly.
///
/// NOTE: the `fi` region (`fi.aliceprotocol.org`) was removed in v0.6.1 — it was
/// never provisioned and resolves NXDOMAIN, so shipping it made clients waste a
/// full RTT-probe timeout on a dead host on every startup. Re-add it here (and in
/// the tests below) if/when a real Finland relay is stood up.
pub const REGION_HOSTS: [(&str, &str); 2] = [
    ("us", "us.aliceprotocol.org"),
    ("asia", "asia.aliceprotocol.org"),
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

/// The known region tag for a relay host (`us.aliceprotocol.org` → `"us"`), or
/// `None` for a host that isn't one of the three region relays (e.g. the XMR/RVN
/// `hk.aliceprotocol.org` relay, or an operator override host). Port-agnostic, so
/// it also recognises the GPU-Alpha relays (same hosts on `:3341`). The supervisor
/// uses this to record the last region that produced an accepted share, purely by
/// the endpoint host — no lane coupling.
pub fn region_tag_for_host(host: &str) -> Option<&'static str> {
    REGION_HOSTS
        .iter()
        .find(|(_, h)| *h == host)
        .map(|(tag, _)| *tag)
}

/// The relay host for a known region tag (`"asia"` → `asia.aliceprotocol.org`).
/// Case-insensitive; `None` for an unknown tag. The inverse of
/// [`region_tag_for_host`].
pub fn host_for_tag(tag: &str) -> Option<&'static str> {
    let tag = tag.trim().to_ascii_lowercase();
    REGION_HOSTS
        .iter()
        .find(|(t, _)| *t == tag)
        .map(|(_, host)| *host)
}

/// Normalise a caller-supplied region tag to a KNOWN tag (`"  ASIA "` → `"asia"`),
/// or `None` when it isn't one of the three regions. Used to validate `--region`
/// input and to sanitise persisted/env values before they steer the plan.
pub fn normalize_region_tag(tag: &str) -> Option<&'static str> {
    let tag = tag.trim().to_ascii_lowercase();
    REGION_HOSTS
        .iter()
        .find(|(t, _)| *t == tag)
        .map(|(t, _)| *t)
}

/// The default region order (`us`, `asia`) as short tags — the canonical
/// list a UI/CLI shows for `--region <tag>`. (`fi` was removed in v0.6.1.)
pub fn region_tags() -> [&'static str; 2] {
    [REGION_HOSTS[0].0, REGION_HOSTS[1].0]
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
///
/// `gpus` selects which physical card(s) to run on (A5b):
/// * [`GpuSelection::All`] (the default) appends **no** device flag — SRBMiner
///   uses every detected card, so the argv is **byte-for-byte identical** to the
///   pre-A5b plan (no multi-GPU regression).
/// * [`GpuSelection::Ids`] appends `--gpu-id <0-based,comma,list>` at the END of
///   the existing argv (the order of the other args is untouched).
pub fn build_srbminer_pearl_launch_plan(
    program: PathBuf,
    reward_identity: &str,
    region_endpoint: &str,
    pop_token: &str,
    log_path: &Path,
    gpus: &GpuSelection,
) -> Result<GpuLaunchPlan, String> {
    if !MINING_EXECUTION_ALLOWED {
        return Err("mining execution is not enabled in this build".into());
    }
    // Defense-in-depth: the pop token rides the `--password` value verbatim. Reject
    // any whitespace / ASCII control char so a malformed token can never inject an
    // extra argv token (the assembler in `pop.rs` already guards this; enforce it at
    // the builder boundary too, regardless of caller). `:`/`=`/base64 stay allowed —
    // they are part of the legit `pop=<id>:<sig>` shape.
    if pop_token
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err("pop token contains whitespace/control characters".into());
    }
    let reward = reward_identity.trim();
    let worker = derive_worker_id(reward)?; // fail-closed Alice-address validation
    let wallet = format!("{reward}.{worker}");
    let pool = format!("stratum+tcp://{region_endpoint}");
    let mut args = vec![
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
    // A5b: opt-in per-card restriction. `All` adds nothing (default = all cards).
    if let Some(csv) = gpus.csv() {
        args.push(SRBMINER_GPU_ID_FLAG.into());
        args.push(csv);
    }
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
    gpus: &GpuSelection,
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
        gpus,
    )
}

// ════════════════════════════════════════════════════════════════════════════
// Region selection (lowest-RTT-wins, with an operator override)
// ════════════════════════════════════════════════════════════════════════════

/// Env override: force a specific region by its short tag (`us` / `asia`).
/// When set to a KNOWN tag it REPLACES the RTT probe; an unknown/empty value is
/// ignored (falls back to the RTT probe).
pub const ENV_REGION: &str = "ALICE_GPU_RELAY_REGION";

/// Per-region TCP-connect timeout for the RTT probe. A region that doesn't
/// answer within this is treated as unreachable (skipped). Kept short so the
/// startup probe over both regions is bounded (~2×).
const RTT_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

/// Order the region relay [`Endpoint`]s by ascending TCP-connect RTT to their
/// `:3340` stratum port, putting the lowest-latency region first. The full set is
/// always returned (Layer-A failover + the supervisor's Layer-B cursor still want
/// every region) — only the ORDER changes.
///
/// Resolution:
///   1. `$ALICE_GPU_RELAY_REGION=<tag>` (us/asia) → that region is forced to
///      the head (no probe); unknown/empty values are ignored.
///   2. otherwise probe both with [`probe_rtt`] and sort by latency;
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

// ════════════════════════════════════════════════════════════════════════════
// Region PERSISTENCE + LOCK (D-line: remember last-good region, lock a region)
// ════════════════════════════════════════════════════════════════════════════

/// How the region primary was resolved for a run — the pure decision, testable
/// without touching settings / env / the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegionDecision {
    /// A user pin (`start --region <tag>`): LOCK to this region. The plan is a
    /// SINGLE endpoint so Layer B can never rotate away — it only retries this
    /// region and reports a clear error if it stays unreachable.
    Locked(&'static str),
    /// Start with this region as the primary but keep the full set (auto-failover
    /// stays available). Sourced from the `ALICE_GPU_RELAY_REGION` operator env or
    /// the remembered last-good region.
    PreferHead(&'static str),
    /// No pin and no hint → the existing lowest-RTT probe order.
    Probe,
}

/// The pure region decision (D-line). Precedence, highest first:
///   1. `lock` — a user pin (`--region <tag>` → `settings.region_lock`). LOCKS.
///   2. `env`  — the `ALICE_GPU_RELAY_REGION` operator override. Prefers-head
///      (unchanged legacy behaviour: reorder, keep the full set).
///   3. `last_good` — the remembered last region that landed an accepted share.
///      Prefers-head so a restart resumes where it was working.
///   4. otherwise → [`RegionDecision::Probe`] (the conservative default — zero
///      surprise for a user with no pin and no history).
///
/// Each input is validated with [`normalize_region_tag`]; an unknown/empty value
/// is ignored (falls through), so a garbage persisted/env value never wedges the
/// lane.
pub fn decide_region(
    lock: Option<&str>,
    env: Option<&str>,
    last_good: Option<&str>,
) -> RegionDecision {
    if let Some(tag) = lock.and_then(normalize_region_tag) {
        return RegionDecision::Locked(tag);
    }
    if let Some(tag) = env.and_then(normalize_region_tag) {
        return RegionDecision::PreferHead(tag);
    }
    if let Some(tag) = last_good.and_then(normalize_region_tag) {
        return RegionDecision::PreferHead(tag);
    }
    RegionDecision::Probe
}

/// The full region set (all region relays) reordered so `tag` is the primary
/// (cursor-0), the rest following in the default `us, asia` order. Deterministic
/// (no probe) — used for the prefer-head decision so a restart resumes on the
/// remembered/forced region immediately, while auto-failover to the others stays
/// available.
pub fn head_first_endpoints(tag: &str) -> Vec<Endpoint> {
    let defaults = region_default_endpoints();
    match REGION_HOSTS.iter().position(|(t, _)| Some(*t) == normalize_region_tag(tag)) {
        Some(idx) => {
            let mut ordered = vec![defaults[idx].clone()];
            ordered.extend(
                defaults
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != idx)
                    .map(|(_, e)| e.clone()),
            );
            ordered
        }
        // Unknown tag → the plain default order (caller should have validated).
        None => defaults,
    }
}

/// Read the `ALICE_GPU_RELAY_REGION` operator env as a KNOWN region tag (or `None`).
fn env_region_tag() -> Option<&'static str> {
    std::env::var(ENV_REGION).ok().as_deref().and_then(normalize_region_tag)
}

/// Build the GPU-PRL [`EndpointPlan`] applying the D-line region policy: a user
/// region LOCK (single region, no auto-failover), else the operator env / remembered
/// last-good region as the primary (full set, auto-failover kept), else the
/// lowest-RTT probe. Reads the persisted [`crate::settings`] (`region_lock`,
/// `last_good_region`) + the `ALICE_GPU_RELAY_REGION` env. The ONE call the engine
/// uses for this lane.
pub fn region_plan() -> EndpointPlan {
    let s = crate::settings::load();
    region_plan_from(
        s.region_lock.as_deref(),
        env_region_tag(),
        s.last_good_region.as_deref(),
    )
}

/// [`region_plan`] with the three inputs passed explicitly (so it is unit-testable
/// without settings/env). Maps the pure [`decide_region`] to a concrete plan.
pub fn region_plan_from(
    lock: Option<&str>,
    env: Option<&str>,
    last_good: Option<&str>,
) -> EndpointPlan {
    match decide_region(lock, env, last_good) {
        RegionDecision::Locked(tag) => {
            // Single-region plan: `can_failover()` is false, so Layer B retries THIS
            // region in place (bounded by the restart budget) and never rotates away.
            let host = host_for_tag(tag).unwrap_or(REGION_HOSTS[0].1);
            EndpointPlan::single(Endpoint::plaintext(host, GPU_RELAY_PORT))
        }
        RegionDecision::PreferHead(tag) => EndpointPlan::new(head_first_endpoints(tag))
            .unwrap_or_else(|_| EndpointPlan::single(default_region_endpoint())),
        RegionDecision::Probe => region_plan_by_rtt(),
    }
}

/// Whether the resolved region policy is a LOCK (no auto-failover). A thin read over
/// the same inputs [`region_plan`] uses — the CLI banner + status labeling use it to
/// tell the user "locked to X" vs "auto (nearest)". Pure over its args.
pub fn is_region_locked(lock: Option<&str>, env: Option<&str>, last_good: Option<&str>) -> bool {
    matches!(decide_region(lock, env, last_good), RegionDecision::Locked(_))
}

// ════════════════════════════════════════════════════════════════════════════
// Region TRANSPARENCY (B-line): show the effective endpoint order WITHOUT probing,
// and flag a REMOVED region host that leaked in from a stale binary / env override.
// ════════════════════════════════════════════════════════════════════════════

/// Region relay hosts that were REMOVED from the v0.6.1 compiled defaults and must
/// NEVER appear in a clean v0.6.1 client's effective PRL endpoints. `fi.aliceprotocol.org`
/// was the Finland relay dropped in v0.6.1 (never provisioned → NXDOMAIN, and it made
/// every startup waste a full RTT-probe timeout on a dead host). If it turns up in the
/// effective set the only sources are a STALE binary/package or an operator
/// `ALICE_MINER_ENDPOINTS_JSON` override — `doctor` names both so a tester can locate it.
pub const REMOVED_REGION_HOSTS: [&str; 1] = ["fi.aliceprotocol.org"];

/// True when any endpoint authority (`host:port`, or a bare host) names a region host
/// that was REMOVED from the compiled defaults (currently only `fi`). Case-insensitive
/// on the host; the port is ignored. Pure — the CLI banner / `doctor` scan the
/// effective endpoints with it to flag a stale binary or an endpoints-JSON override.
pub fn contains_removed_region(authorities: &[String]) -> bool {
    authorities.iter().any(|a| {
        let host = a.split(':').next().unwrap_or(a).trim().to_ascii_lowercase();
        REMOVED_REGION_HOSTS.iter().any(|removed| host == *removed)
    })
}

/// True when arbitrary `text` mentions a removed region relay host (currently `fi`).
/// Used to scan a raw `ALICE_MINER_ENDPOINTS_JSON` override string for a decommissioned
/// host WITHOUT parsing it (the override never steers the PRL region plan, but a `fi`
/// inside it is exactly the "where did Finland come from" signal `doctor` reports).
/// Case-insensitive. Pure.
pub fn text_names_removed_region(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    REMOVED_REGION_HOSTS.iter().any(|removed| lower.contains(removed))
}

/// The effective GPU-PRL endpoint authorities (`host:port`), in the order the D-line
/// policy presents them, computed WITHOUT the RTT probe. This lets the CLI banner and
/// `doctor` SHOW the plan with no network cost and no double-probe (the engine runs the
/// real probe once, at start). Mapping (mirrors [`region_plan_from`]):
///   * LOCK        → the single locked region (no failover).
///   * prefer-head → that region first, then the rest in default order (env / last-good).
///   * PROBE       → the compiled candidate set in default (`us`, `asia`) order — the
///     REAL head is chosen by a live RTT probe at engine start, so a caller SHOWING this
///     order should label it "nearest-first, chosen at start". Pure over its args.
pub fn planned_endpoint_authorities(
    lock: Option<&str>,
    env: Option<&str>,
    last_good: Option<&str>,
) -> Vec<String> {
    let eps = match decide_region(lock, env, last_good) {
        RegionDecision::Locked(tag) => {
            let host = host_for_tag(tag).unwrap_or(REGION_HOSTS[0].1);
            vec![Endpoint::plaintext(host, GPU_RELAY_PORT)]
        }
        RegionDecision::PreferHead(tag) => head_first_endpoints(tag),
        RegionDecision::Probe => region_default_endpoints(),
    };
    eps.iter().map(|e| e.host_port()).collect()
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
        assert_eq!(region_default_endpoints().len(), 2);
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
            &GpuSelection::All,
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
        // A5b: with the DEFAULT GpuSelection::All, NO --gpu-id flag is present
        // (all cards — the pre-A5b default).
        assert!(!a.iter().any(|x| x == "--gpu-id"));
    }

    /// A5b REGRESSION GUARD: with [`GpuSelection::All`] the argv must be
    /// **byte-for-byte identical** to the pre-A5b builder (the new `gpus` param
    /// is purely additive — `All` appends nothing). We pin the exact expected
    /// argv so any accidental reordering / extra flag fails loudly.
    #[test]
    fn srbminer_argv_all_is_unchanged_from_pre_a5b() {
        let addr = valid_address();
        let lp = log_path();
        let plan = build_srbminer_pearl_launch_plan(
            PathBuf::from("/opt/SRBMiner-MULTI"),
            addr,
            "us.aliceprotocol.org:3340",
            "pop=ch:sig",
            &lp,
            &GpuSelection::All,
        )
        .expect("plan");
        let worker = derive_worker_id(addr).unwrap();
        let expected: Vec<String> = vec![
            "--algorithm".into(),
            "pearlhash".into(),
            "--pool".into(),
            "stratum+tcp://us.aliceprotocol.org:3340".into(),
            "--wallet".into(),
            format!("{addr}.{worker}"),
            "--password".into(),
            "pop=ch:sig".into(),
            "--disable-cpu".into(),
            "--log-file".into(),
            lp.display().to_string(),
        ];
        assert_eq!(plan.args, expected, "GpuSelection::All must not change the argv");
    }

    /// A5b: [`GpuSelection::Ids`] APPENDS `--gpu-id 0,1,2` at the end, leaving the
    /// rest of the argv (and its order) exactly as `All` produces it.
    #[test]
    fn srbminer_argv_ids_appends_gpu_id_flag() {
        let addr = valid_address();
        let lp = log_path();
        let plan = build_srbminer_pearl_launch_plan(
            PathBuf::from("/opt/SRBMiner-MULTI"),
            addr,
            "us.aliceprotocol.org:3340",
            "pop=ch:sig",
            &lp,
            &GpuSelection::Ids(vec![0, 1, 2]),
        )
        .expect("plan");
        // The flag is present with the comma-joined index list as its value.
        let g = plan
            .args
            .iter()
            .position(|x| x == "--gpu-id")
            .expect("--gpu-id present for Ids");
        assert_eq!(plan.args[g + 1], "0,1,2");
        // It is APPENDED last (the prior argv is untouched): the two new tokens
        // are exactly the trailing two.
        let n = plan.args.len();
        assert_eq!(&plan.args[n - 2..], &["--gpu-id".to_string(), "0,1,2".to_string()]);
        // A single non-zero index also works (e.g. only the 2nd card).
        let plan1 = build_srbminer_pearl_launch_plan(
            PathBuf::from("/opt/SRBMiner-MULTI"),
            addr,
            "us.aliceprotocol.org:3340",
            "pop=ch:sig",
            &lp,
            &GpuSelection::Ids(vec![1]),
        )
        .unwrap();
        let g1 = plan1.args.iter().position(|x| x == "--gpu-id").unwrap();
        assert_eq!(plan1.args[g1 + 1], "1");
    }

    /// A5b HONESTY: selecting specific cards must NOT introduce any forbidden
    /// substring — `--gpu-id 0,1` is digits only, so the honesty gate (no prl1p
    /// collection address / herominers / core IP / seed) still holds.
    #[test]
    fn honesty_gate_holds_with_gpu_ids_selection() {
        let addr = valid_address();
        let lp = log_path();
        let plan = build_srbminer_pearl_launch_plan(
            PathBuf::from("/opt/SRBMiner-MULTI"),
            addr,
            "asia.aliceprotocol.org:3340",
            "pop=abc:def",
            &lp,
            &GpuSelection::Ids(vec![0, 1]),
        )
        .unwrap();
        let joined = plan.args.join(" ");
        assert!(joined.contains(addr));
        assert!(joined.contains(":3340"));
        assert!(!joined.contains("prl1p"), "a prl1p address leaked: {joined}");
        assert!(!joined.contains("herominers"), "upstream pool host leaked: {joined}");
        assert!(!joined.contains("203.0.113.10"), "core IP leaked: {joined}");
        assert!(!plan
            .args
            .iter()
            .any(|a| a.contains("seed") || a.contains("priv") || a.contains("0x")));
        // Only *.aliceprotocol.org appears as a stratum authority.
        for tok in plan.args.iter().filter(|a| a.starts_with("stratum+")) {
            assert!(tok.contains("aliceprotocol.org:"), "non-Alice relay host: {tok}");
        }
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
            &GpuSelection::All,
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
            &GpuSelection::All,
        )
        .is_err());
        // Wrong-network (substrate-42) address rejected.
        assert!(build_srbminer_pearl_launch_plan(
            PathBuf::from("SRBMiner-MULTI"),
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
            "us.aliceprotocol.org:3340",
            "pop=a:b",
            &lp,
            &GpuSelection::All,
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
            &GpuSelection::All,
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
        // Force asia → asia must be cursor-0, both regions still present.
        std::env::set_var(ENV_REGION, "asia");
        let eps = select_region_endpoints();
        assert_eq!(eps.len(), 2, "the full region set is always returned");
        assert_eq!(eps[0].host, "asia.aliceprotocol.org");
        assert!(eps.iter().all(|e| e.port == GPU_RELAY_PORT));
        // Every default host is still represented (only the ORDER changed).
        for (_, host) in REGION_HOSTS {
            assert!(eps.iter().any(|e| e.host == host), "missing region {host}");
        }
        // Case-insensitive.
        std::env::set_var(ENV_REGION, "US");
        assert_eq!(select_region_endpoints()[0].host, "us.aliceprotocol.org");

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
        // and contain exactly the region hosts.
        std::env::set_var(ENV_REGION, "atlantis");
        let eps = select_region_endpoints();
        assert_eq!(eps.len(), 2);
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
        assert_eq!(ordered.len(), 2);
        assert!(ordered
            .iter()
            .all(|e| e.host.ends_with("aliceprotocol.org") && e.port == GPU_RELAY_PORT));
        match prev {
            Some(v) => std::env::set_var(ENV_REGION, v),
            None => std::env::remove_var(ENV_REGION),
        }
    }

    // ── D-line: region persistence + lock (pure decision, no network) ──────────

    #[test]
    fn region_tag_host_round_trip() {
        assert_eq!(region_tag_for_host("us.aliceprotocol.org"), Some("us"));
        assert_eq!(region_tag_for_host("asia.aliceprotocol.org"), Some("asia"));
        // `fi` was removed in v0.6.1 (never provisioned) → no longer a region relay.
        assert_eq!(region_tag_for_host("fi.aliceprotocol.org"), None);
        // The XMR/RVN relay is NOT a region relay → None (so last-good never records it).
        assert_eq!(region_tag_for_host("hk.aliceprotocol.org"), None);
        assert_eq!(host_for_tag("ASIA"), Some("asia.aliceprotocol.org"));
        assert_eq!(host_for_tag("  fi "), None);
        assert_eq!(host_for_tag("atlantis"), None);
        assert_eq!(normalize_region_tag(" US "), Some("us"));
        assert_eq!(normalize_region_tag("mars"), None);
        assert_eq!(region_tags(), ["us", "asia"]);
    }

    #[test]
    fn decide_region_precedence_lock_env_lastgood_probe() {
        // Lock wins over everything.
        assert_eq!(
            decide_region(Some("asia"), Some("us"), Some("us")),
            RegionDecision::Locked("asia")
        );
        // No lock → env override (prefer-head, keeps full set) beats last-good.
        assert_eq!(
            decide_region(None, Some("us"), Some("asia")),
            RegionDecision::PreferHead("us")
        );
        // No lock, no env → remembered last-good.
        assert_eq!(
            decide_region(None, None, Some("asia")),
            RegionDecision::PreferHead("asia")
        );
        // Nothing → probe (the conservative default: zero surprise).
        assert_eq!(decide_region(None, None, None), RegionDecision::Probe);
        // A garbage value at any tier is ignored (falls through) — never wedges.
        assert_eq!(
            decide_region(Some("mars"), None, Some("asia")),
            RegionDecision::PreferHead("asia")
        );
        assert_eq!(decide_region(Some(""), Some("   "), None), RegionDecision::Probe);
        // `fi` was removed in v0.6.1 → it is now an unknown tag and falls through.
        assert_eq!(decide_region(None, Some("fi"), None), RegionDecision::Probe);
    }

    #[test]
    fn head_first_endpoints_puts_tag_first_keeps_full_set() {
        let eps = head_first_endpoints("asia");
        assert_eq!(eps.len(), 2, "full set retained (failover still possible)");
        assert_eq!(eps[0].host, "asia.aliceprotocol.org");
        assert!(eps.iter().all(|e| e.port == GPU_RELAY_PORT));
        for (_, host) in REGION_HOSTS {
            assert!(eps.iter().any(|e| e.host == host), "missing {host}");
        }
        // An unknown tag degrades to the plain default order (no panic, non-empty).
        let d = head_first_endpoints("atlantis");
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].host, "us.aliceprotocol.org");
    }

    #[test]
    fn region_plan_from_lock_is_single_region_no_failover() {
        let plan = region_plan_from(Some("asia"), None, None);
        assert_eq!(plan.len(), 1, "a lock pins ONE region");
        assert!(!plan.can_failover(), "a locked region never auto-fails-over");
        assert_eq!(plan.current().host, "asia.aliceprotocol.org");
        assert_eq!(plan.current().port, GPU_RELAY_PORT);
        assert!(is_region_locked(Some("asia"), None, None));
    }

    #[test]
    fn region_plan_from_last_good_prefers_head_keeps_failover() {
        // Remembered last-good = asia, no lock, no env → asia primary, full set.
        let plan = region_plan_from(None, None, Some("asia"));
        assert_eq!(plan.len(), 2);
        assert!(plan.can_failover(), "prefer-head keeps auto-failover available");
        assert_eq!(plan.current().host, "asia.aliceprotocol.org");
        assert!(!is_region_locked(None, None, Some("asia")));
    }

    #[test]
    fn region_plan_from_env_override_prefers_head() {
        // The operator env keeps its legacy meaning: reorder head, keep full set.
        let plan = region_plan_from(None, Some("us"), Some("asia"));
        assert_eq!(plan.len(), 2);
        assert!(plan.can_failover());
        assert_eq!(plan.current().host, "us.aliceprotocol.org", "env beats last-good");
    }

    #[test]
    fn conservative_default_no_lock_no_history_is_probe() {
        // Requirement ④: with no `--region` pin and no remembered region, the
        // decision is the existing lowest-RTT Probe (the full failover-capable set —
        // proven by `region_plan_by_rtt_is_relay_only_full_set`). Zero surprise: a
        // user who never touched region behaviour keeps the exact prior behaviour.
        // (Asserted at the pure-decision layer so no live network probe runs here.)
        assert_eq!(decide_region(None, None, None), RegionDecision::Probe);
        assert!(!is_region_locked(None, None, None));
    }

    // ── B-line region TRANSPARENCY helpers ──────────────────────────────────────

    /// The probe-free endpoint order the banner/doctor SHOW matches the real plan for
    /// the two deterministic cases, and lists the compiled candidates for probe.
    #[test]
    fn planned_endpoint_authorities_matches_each_decision() {
        // LOCK → the single locked region only (no failover partner shown).
        let locked = planned_endpoint_authorities(Some("asia"), None, None);
        assert_eq!(locked, vec!["asia.aliceprotocol.org:3340".to_string()]);

        // prefer-head (env) → that region first, then the rest in default order.
        let env = planned_endpoint_authorities(None, Some("asia"), None);
        assert_eq!(
            env,
            vec![
                "asia.aliceprotocol.org:3340".to_string(),
                "us.aliceprotocol.org:3340".to_string(),
            ]
        );

        // prefer-head (last-good) → same shape, sourced from history.
        assert_eq!(planned_endpoint_authorities(None, None, Some("asia")), env);

        // PROBE default (no lock / env / history) → compiled candidates, US-first.
        let probe = planned_endpoint_authorities(None, None, None);
        assert_eq!(
            probe,
            vec![
                "us.aliceprotocol.org:3340".to_string(),
                "asia.aliceprotocol.org:3340".to_string(),
            ]
        );

        // Every authority is a public region relay on :3340 — never a removed host.
        for set in [&locked, &env, &probe] {
            assert!(!contains_removed_region(set), "clean v0.6.1 set has no removed host");
            assert!(set.iter().all(|a| a.ends_with(":3340")));
        }
    }

    /// A clean v0.6.1 client NEVER emits `fi`, and the removed-host detectors fire on a
    /// synthetic authority list / raw endpoints-JSON that DOES name it (the FI signal).
    #[test]
    fn removed_region_detectors_flag_fi_only() {
        // Compiled defaults are fi-free (us/asia only).
        assert!(!contains_removed_region(&planned_endpoint_authorities(None, None, None)));
        for (_, host) in REGION_HOSTS {
            assert!(!REMOVED_REGION_HOSTS.contains(&host), "a live region can't be 'removed'");
        }
        // A leaked fi host (stale binary / override) is caught, port- and case-insensitively.
        assert!(contains_removed_region(&["fi.aliceprotocol.org:3340".to_string()]));
        assert!(contains_removed_region(&["FI.AliceProtocol.org".to_string()]));
        assert!(!contains_removed_region(&["us.aliceprotocol.org:3340".to_string()]));
        // Raw endpoints-JSON scan (never parsed — a plain substring signal).
        assert!(text_names_removed_region(
            "{\"gpu-prl\":[\"fi.aliceprotocol.org:3340\"]}"
        ));
        assert!(!text_names_removed_region(
            "{\"gpu-prl\":[\"asia.aliceprotocol.org:3340\"]}"
        ));
    }

    #[test]
    fn worker_id_shared_with_xmr_lane() {
        let addr = valid_address();
        assert_eq!(
            derive_worker_id(addr).unwrap(),
            super::super::xmr::derive_worker_id(addr).unwrap()
        );
    }

    /// REAL SRBMiner-MULTI 3.4.1 `--list-devices` output (captured on narissa
    /// 2026-06-26). Proves the parser + documents the trap: the iGPU is id 0, so a
    /// `--gpus 0` is NOT the first NVIDIA card (the 3070 Ti is id 1, the 4070 Ti id 2).
    #[test]
    fn parse_srbminer_devices_real_list() {
        let out = "OPENCL devices\n\
            GPU0  [1][0] [0000:00:02.0] : intel_r__iris_r__xe_graphics [unknown_intel] [7092 MB] [CU: 96] [MaxBuf: 3546 MB]\n\
            CUDA devices\n\
            GPU1  [CUDA][1] [0000:01:00.0] : nvidia_geforce_rtx_3070_ti_laptop_gpu [ampere] [CC: 8.6] [SM: 46] [8191 MB]\n\
            GPU2  [CUDA][0] [0000:06:00.0] : nvidia_geforce_rtx_4070_ti [ada] [CC: 8.9] [SM: 60] [12281 MB]\n";
        let d = parse_srbminer_devices(out);
        assert_eq!(d.len(), 3, "header lines ignored, 3 GPUs parsed");
        assert_eq!(d[0], SrbGpuDevice {
            id: 0,
            backend: "OpenCL".into(),
            pci: "0000:00:02.0".into(),
            name: "intel_r__iris_r__xe_graphics".into(),
        });
        assert_eq!(d[1].id, 1);
        assert_eq!(d[1].backend, "CUDA");
        assert_eq!(d[1].pci, "0000:01:00.0");
        assert!(d[1].name.contains("3070_ti"), "{:?}", d[1].name);
        assert_eq!(d[2].id, 2);
        assert_eq!(d[2].backend, "CUDA");
        assert!(d[2].name.contains("4070_ti"));
        // The trap, asserted: the first NVIDIA (CUDA) card is id 1, not 0.
        let first_nvidia = d.iter().find(|x| x.backend == "CUDA").unwrap();
        assert_eq!(first_nvidia.id, 1, "the iGPU occupies id 0");
    }

    #[test]
    fn parse_srbminer_devices_ignores_noise() {
        assert!(parse_srbminer_devices("List of devices:\nDone.\n").is_empty());
        assert!(parse_srbminer_devices("").is_empty());
    }
}
