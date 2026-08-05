//! Shard-stage **inference-worker** client (the `alice-miner ai` role).
//!
//! A GPU miner joins the Alice pipeline-parallel inference swarm as a STAGE node:
//! it registers its public `endpoint` + free VRAM + stake reference with the Alice
//! scheduling center (the acp gateway), heartbeats to stay in the available pool,
//! and pulls a per-node [`LaunchSpec`] once the center forms a swarm that placed it.
//! When placed, it execs the vendored shard engine (`phase0/pipeline.py`) as its
//! pipeline stage — head DRIVES, middle + tail LISTEN + forward.
//!
//! This module is the headless PROTOCOL core (no UI, no subprocess): the PoP
//! signing bytes, the HTTPS control-plane calls, and the argv construction from a
//! pulled launch spec. The subprocess supervision + live status live in the CLI's
//! `ai` command; this crate holds only what must match the server byte-for-byte.
//!
//! ── Server source of truth (matched byte-exact) ─────────────────────────────
//!   * PoP domain + message: `alice_acp.api_chat_gateway.shard_stage_pop`
//!     (`stage_binding_signing_message`) — `domain ‖ alice_address ‖ endpoint ‖
//!     nonce`, newline-framed ASCII, sr25519, base64 in `signature_b64`.
//!   * Routes: `POST /v1/shard/stage/{nonce,register,heartbeat,pull}`
//!     (`alice_acp.shadow_server.http_app`). The nonce response field is
//!     `stage_nonce`; the pull response is `assigned` + `launch_spec` (+ top-level
//!     `model_id` / `device`) or `no_assignment`.
//!   * Launch-spec argv: `StageLaunchSpec.engine_argv()`
//!     (`alice_acp.api_chat_gateway.shard_swarm`).
//!
//! ── CREDIT-ONLY ─────────────────────────────────────────────────────────────
//! Every server response carries `paid_acu:"0"`; this client never reads/writes a
//! reward, and NEVER puts a secret in argv (the swarm PSK rides `SHARD_PSK` in the
//! env only). Registration proves possession with the SAME sr25519 wallet key the
//! PRL lane uses — a watch-only (pasted-address) identity can never register.

use std::io::Read as _;
use std::time::Duration;

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use alice_crypto::WalletSecrets;

/// Domain-separation tag for the shard-stage register/heartbeat binding signature.
/// DISTINCT from the worker-pull / m4-enroll domains so no PoP can be replayed
/// across surfaces. Server: `shard_stage_pop.SHARD_STAGE_BINDING_DOMAIN`.
pub const SHARD_STAGE_DOMAIN: &str = "alice-acp:shard-stage:bind-endpoint:v1";

/// The sr25519 default PoP scheme string the server + client agree on.
pub const SHARD_STAGE_SCHEME_DEFAULT: &str = "sr25519";

/// The env var carrying the shared per-swarm key the engine (`phase0/wire.py`
/// `key_from_env`) reads. It rides the ENV ONLY — NEVER argv/logs — so a captured
/// process table can't leak it. The stage refuses to launch without it set.
pub const SHARD_PSK_ENV: &str = "SHARD_PSK";

/// The EXACT bytes a stage miner signs to authorize a register/heartbeat —
/// byte-identical to the server's `stage_binding_signing_message`: the domain
/// line, then three `key=value` lines, newline-FRAMED (newline BETWEEN lines,
/// NONE trailing), ASCII. `endpoint` is bound so a captured nonce cannot re-point
/// the registration elsewhere; `alice_address` binds possession; `nonce`
/// (single-use, server-issued) blocks pre-compute + replay.
pub fn stage_binding_message(alice_address: &str, endpoint: &str, nonce: &str) -> Vec<u8> {
    format!(
        "{SHARD_STAGE_DOMAIN}\nalice_address={alice_address}\nendpoint={endpoint}\nnonce={nonce}"
    )
    .into_bytes()
}

/// Sign the stage-binding bytes with the Alice sr25519 key; return the 64-byte
/// schnorrkel signature in STANDARD base64 (the alphabet the server's
/// `base64.b64decode` expects). Fails closed if `secrets` is watch-only (no key) —
/// a pasted address can never register a stage.
pub fn sign_message_b64(secrets: &WalletSecrets, message: &[u8]) -> Result<String, String> {
    let keypair = secrets.to_keypair()?;
    let sig = keypair.sign(message);
    Ok(base64::engine::general_purpose::STANDARD.encode(sig.0))
}

// ════════════════════════════════════════════════════════════════════════════
// HTTPS control plane — the four stage routes on the acp gateway.
//
// Base URL is the acp gateway (`--center-url`); the four routes are
// `<base>/v1/shard/stage/{nonce,register,heartbeat,pull}`. Every URL MUST be
// https:// (fail closed — a PoP signature must never cross the wire in the clear),
// with a small read cap + ~10s timeout bounding a hostile/oversized response. All
// bodies are typed structs (compact serde_json), so the on-wire JSON shape is
// asserted in unit tests with NO network.
// ════════════════════════════════════════════════════════════════════════════

/// Connect + read timeout for every control-plane call (~10s, matching `pop.rs`).
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound on any control-plane response body (a launch spec is a few hundred
/// bytes; 64 KiB is generous yet caps a hostile/runaway response).
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

/// AM-SEC-007: how much of a server error body may reach a CLI line / log after
/// sanitisation. A stable `reason_code` is short; 200 chars is plenty and keeps a
/// hostile body from flooding the miner's screen.
const REMOTE_BODY_MAX: usize = 200;

/// Reject any non-`https://` URL — fail closed so a PoP signature can never be sent
/// in the clear.
fn require_https(url: &str) -> Result<(), String> {
    if url.starts_with("https://") {
        Ok(())
    } else {
        Err(format!("refusing non-https center url: {url}"))
    }
}

/// Build `<base>/v1/shard/stage/<leaf>`, trimming a single trailing `/` off the
/// base so both `https://host` and `https://host/` yield the same URL. https-checked.
pub fn stage_route(center_url: &str, leaf: &str) -> Result<String, String> {
    require_https(center_url)?;
    let base = center_url.strip_suffix('/').unwrap_or(center_url);
    let url = format!("{base}/v1/shard/stage/{leaf}");
    require_https(&url)?;
    Ok(url)
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        // Verify against the OS trust store, not ureq's Mozilla-only default, so
        // corporate/AV SSL-inspection CAs are honored (Windows UnknownIssuer fix).
        .tls_config(alice_release::tls::os_trust_config())
        .timeout_connect(HTTP_TIMEOUT)
        .timeout_read(HTTP_TIMEOUT)
        .user_agent(concat!("alice-miner-ai/", env!("CARGO_PKG_VERSION")))
        .build()
}

/// POST a typed body as compact JSON, read the (capped) response, parse into `R`.
/// Caller has already https-checked the URL. A non-2xx surfaces as an `Err` carrying
/// the status + (capped) body so the caller can show the server's secret-free reason.
fn post_json<B: Serialize, R: serde::de::DeserializeOwned>(
    url: &str,
    body: &B,
) -> Result<R, String> {
    // Serialize ourselves + send with an explicit content-type: the workspace's
    // ureq is built default-features=false (tls+gzip only), so `send_json` (needs
    // the `json` feature) is intentionally unavailable — mirrors `pop.rs`.
    let payload = serde_json::to_string(body).map_err(|e| format!("serialize: {e}"))?;
    let resp = match agent()
        .post(url)
        .set("Content-Type", "application/json")
        .send_string(&payload)
    {
        Ok(r) => r,
        // ureq surfaces a non-2xx as `Error::Status`; read its body (capped) so the
        // server's stable reason_code reaches the caller instead of a bare code.
        Err(ureq::Error::Status(code, resp)) => {
            let mut buf = Vec::new();
            let _ = resp
                .into_reader()
                .take(MAX_RESPONSE_BYTES)
                .read_to_end(&mut buf);
            // AM-SEC-007: the body is REMOTE text that ends up in CLI output and
            // logs. Strip ANSI/control chars and bound it before it can repaint a
            // terminal or forge a status line.
            let body = alice_supervise::sanitize_remote_text(
                &String::from_utf8_lossy(&buf),
                REMOTE_BODY_MAX,
            );
            return Err(format!("POST {url}: HTTP {code}: {body}"));
        }
        Err(e) => return Err(format!("POST {url}: {e}")),
    };
    let mut buf = Vec::new();
    resp.into_reader()
        .take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut buf)
        .map_err(|e| format!("read {url}: {e}"))?;
    serde_json::from_slice(&buf).map_err(|e| format!("parse {url}: {e}"))
}

// ── request bodies (typed → compact JSON, field order fixed here) ──────────────

#[derive(Serialize)]
struct NonceRequest<'a> {
    alice_address: &'a str,
    endpoint: &'a str,
}

#[derive(Serialize)]
struct RegisterRequest<'a> {
    alice_address: &'a str,
    endpoint: &'a str,
    free_vram_gb: f64,
    stake_ref: &'a str,
    region: &'a str,
    nonce: &'a str,
    signature_b64: &'a str,
}

#[derive(Serialize)]
struct HeartbeatRequest<'a> {
    alice_address: &'a str,
    endpoint: &'a str,
    nonce: &'a str,
    signature_b64: &'a str,
    /// Optional liveness status ("launching"|"ready"|"error"). A server that
    /// ignores the field is tolerated (it is additive to the register/heartbeat
    /// contract). Skipped entirely when `None` so the wire shape is unchanged for
    /// an older server.
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<&'a str>,
}

#[derive(Serialize)]
struct PullRequest<'a> {
    alice_address: &'a str,
}

// ── response shapes ────────────────────────────────────────────────────────────

/// The nonce-mint response. The canonical field is `stage_nonce`; we also accept a
/// bare `nonce` for forward/back-compat with a server that renames it.
#[derive(Deserialize)]
struct NonceResponse {
    #[serde(default)]
    stage_nonce: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
}

/// The pull response: `status` is "assigned" or "no_assignment". When assigned,
/// `launch_spec` + the top-level `model_id` / `device` are present. `session_ready`
/// is an OPTIONAL additive field (a parallel server task) surfaced in the UI when
/// present; absent on a server that doesn't emit it yet (defaults to `None`).
#[derive(Deserialize)]
struct PullResponse {
    #[serde(default)]
    status: String,
    /// The server's stable, machine-readable reason (e.g.
    /// `shard_stage_no_assignment`). Surfaced verbatim-but-SANITIZED on an
    /// unexpected status so a protocol error names itself instead of hiding.
    #[serde(default)]
    reason_code: Option<String>,
    #[serde(default)]
    model_id: Option<String>,
    #[serde(default)]
    device: Option<String>,
    #[serde(default)]
    launch_spec: Option<LaunchSpec>,
    #[serde(default)]
    session_ready: Option<bool>,
}

/// One stage's placement, as returned inside the pull response's `launch_spec`
/// (the server's `StageLaunchSpec.to_public_dict()`). `model_id` + `device` are
/// NOT in this object — they are top-level on the pull response — so
/// [`PullAssignment`] carries them alongside.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct LaunchSpec {
    pub stage_index: u32,
    pub n_stages: u32,
    pub alice_address: String,
    pub layer_lo: u32,
    pub layer_hi: u32,
    /// "head" | "middle" | "tail".
    pub role: String,
    pub listen_port: u16,
    /// The next stage's `host:port` (the head + middle connect forward; the tail
    /// has `None`).
    #[serde(default)]
    pub next_endpoint: Option<String>,
}

impl LaunchSpec {
    /// `true` for the head stage (drives; connects forward, does not listen).
    pub fn is_head(&self) -> bool {
        self.role == "head"
    }
    /// `true` for the tail stage (only listens; no forward connection).
    pub fn is_tail(&self) -> bool {
        self.role == "tail"
    }
}

/// A resolved swarm placement: the per-node launch spec plus the top-level
/// `model_id` + `device` the pull response carries separately. This is what the
/// supervisor turns into the engine argv.
#[derive(Debug, Clone, PartialEq)]
pub struct PullAssignment {
    pub model_id: String,
    pub device: String,
    pub spec: LaunchSpec,
    /// The server's optional `session_ready` flag (whole-swarm readiness), when it
    /// emits one. `None` on a server that doesn't yet report it.
    pub session_ready: Option<bool>,
}

/// The outcome of a pull: either a placement, or the honest "not placed yet".
#[derive(Debug, Clone, PartialEq)]
pub enum PullOutcome {
    /// The center placed this node — run the spec.
    Assigned(Box<PullAssignment>),
    /// Not (yet) placed into any formed swarm. Keep heartbeating + polling.
    NoAssignment,
}

/// Build the `phase0/pipeline.py` argv from a resolved [`PullAssignment`], EXACTLY
/// as the server's `StageLaunchSpec.engine_argv()` does:
///   `--stage <i> --nstages <N> --model <id> --device <dev>`
///   `[--listen-port <port>]`  (middle + tail only — the head does not listen)
///   `[--next <endpoint>]`     (head + middle only — the tail has no successor)
/// The `SHARD_PSK` is NOT here — it rides the env. The leading `pipeline.py` path
/// is prepended by the caller (it knows the engine dir); this returns the flags.
pub fn engine_argv(a: &PullAssignment) -> Vec<String> {
    let mut argv = vec![
        "--stage".into(),
        a.spec.stage_index.to_string(),
        "--nstages".into(),
        a.spec.n_stages.to_string(),
        "--model".into(),
        a.model_id.clone(),
        "--device".into(),
        a.device.clone(),
    ];
    if !a.spec.is_head() {
        argv.push("--listen-port".into());
        argv.push(a.spec.listen_port.to_string());
    }
    if !a.spec.is_tail() {
        // The server stringifies `next_endpoint` (str(None) → "None" only if the
        // planner ever mis-sets it, but a non-tail always has a real successor);
        // we carry the real endpoint or an empty string so a malformed spec is
        // visible rather than dialing a literal "None".
        argv.push("--next".into());
        argv.push(a.spec.next_endpoint.clone().unwrap_or_default());
    }
    argv
}

/// POST `/v1/shard/stage/nonce` → the single-use `stage_nonce` to sign. Echoes the
/// `alice_address` + `endpoint` the client says it will bind (informational
/// server-side); we only need the nonce back.
pub fn fetch_nonce(center_url: &str, alice_address: &str, endpoint: &str) -> Result<String, String> {
    let url = stage_route(center_url, "nonce")?;
    let body = NonceRequest {
        alice_address,
        endpoint,
    };
    let resp: NonceResponse = post_json(&url, &body)?;
    let nonce = resp
        .stage_nonce
        .or(resp.nonce)
        .filter(|n| !n.is_empty())
        .ok_or("nonce response missing a non-empty stage_nonce")?;
    Ok(nonce)
}

/// POST `/v1/shard/stage/register` — bind this node into the stake-gated swarm
/// registry. Fetches a fresh nonce, signs the stage-binding message over
/// `endpoint`, and submits `{alice_address, endpoint, free_vram_gb, stake_ref,
/// region, nonce, signature_b64}`. Fails closed for a watch-only identity (no key)
/// BEFORE any network. A server reject (bad address / no stake / bad endpoint /
/// bad VRAM / PoP failure) surfaces as an `Err` carrying the stable reason_code.
#[allow(clippy::too_many_arguments)]
pub fn register(
    center_url: &str,
    alice_address: &str,
    endpoint: &str,
    free_vram_gb: f64,
    stake_ref: &str,
    region: &str,
    secrets: &WalletSecrets,
) -> Result<(), String> {
    // Fail closed up front: a watch-only identity can never sign the binding, so
    // there is no point fetching a nonce.
    if secrets.to_keypair().is_err() {
        return Err(
            "this reward identity is watch-only (address pasted, no signing key); the ai role \
             must prove it owns the address to register a stage — import the mnemonic/seed instead"
                .into(),
        );
    }
    let nonce = fetch_nonce(center_url, alice_address, endpoint)?;
    let msg = stage_binding_message(alice_address, endpoint, &nonce);
    let sig_b64 = sign_message_b64(secrets, &msg)?;
    let url = stage_route(center_url, "register")?;
    let body = RegisterRequest {
        alice_address,
        endpoint,
        free_vram_gb,
        stake_ref,
        region,
        nonce: &nonce,
        signature_b64: &sig_b64,
    };
    let _resp: serde_json::Value = post_json(&url, &body)?;
    Ok(())
}

/// POST `/v1/shard/stage/heartbeat` — refresh liveness (same PoP gate as register:
/// a fresh nonce, signed over the bound endpoint). `status` ("launching"|"ready"|
/// "error"), when supplied, is carried as an additive field a newer server records
/// and an older one ignores. Fails closed for a watch-only identity.
pub fn heartbeat(
    center_url: &str,
    alice_address: &str,
    endpoint: &str,
    status: Option<&str>,
    secrets: &WalletSecrets,
) -> Result<(), String> {
    if secrets.to_keypair().is_err() {
        return Err("watch-only identity cannot sign a stage heartbeat".into());
    }
    let nonce = fetch_nonce(center_url, alice_address, endpoint)?;
    let msg = stage_binding_message(alice_address, endpoint, &nonce);
    let sig_b64 = sign_message_b64(secrets, &msg)?;
    let url = stage_route(center_url, "heartbeat")?;
    let body = HeartbeatRequest {
        alice_address,
        endpoint,
        nonce: &nonce,
        signature_b64: &sig_b64,
        status,
    };
    let _resp: serde_json::Value = post_json(&url, &body)?;
    Ok(())
}

/// Probe the center's health for a preflight (`doctor --ai`). GETs `<base>/health`
/// (the acp gateway serves it) with a short timeout. Returns `Ok(desc)` when the
/// host is up + serving (ANY HTTP response, including a gated non-2xx, proves
/// reachability), or `Err(reason)` on a transport failure / non-https URL. Never
/// panics. This is a diagnostic probe only — it signs nothing and reads no reward.
pub fn probe_center_health(center_url: &str) -> Result<String, String> {
    require_https(center_url)?;
    let base = center_url.strip_suffix('/').unwrap_or(center_url);
    let health = format!("{base}/health");
    let agent = ureq::AgentBuilder::new()
        .tls_config(alice_release::tls::os_trust_config()) // OS trust store (Windows UnknownIssuer fix)
        .timeout_connect(Duration::from_secs(5))
        .timeout_read(Duration::from_secs(5))
        .user_agent(concat!("alice-miner-ai/", env!("CARGO_PKG_VERSION")))
        .build();
    match agent.get(&health).call() {
        Ok(_) => Ok(format!("center reachable ({health})")),
        // A non-2xx still proves the host is up + serving (the route may be gated);
        // treat any HTTP response as reachable — only a transport error is a failure.
        Err(ureq::Error::Status(code, _)) => {
            Ok(format!("center reachable ({health} → HTTP {code})"))
        }
        Err(e) => Err(format!("cannot reach the center at {health}: {e}")),
    }
}

/// POST `/v1/shard/stage/pull` — read THIS node's placement. No PoP (a public spec
/// read; identity was proven at register). Returns [`PullOutcome::Assigned`] with
/// the resolved spec + `model_id`/`device`, or [`PullOutcome::NoAssignment`].
pub fn pull(center_url: &str, alice_address: &str) -> Result<PullOutcome, String> {
    let url = stage_route(center_url, "pull")?;
    let body = PullRequest { alice_address };
    let resp: PullResponse = post_json(&url, &body)?;
    parse_pull(resp)
}

/// Turn a parsed pull response into a [`PullOutcome`], validating that an
/// "assigned" status actually carries the launch spec + model/device (a truncated
/// "assigned" with no spec is a protocol error, not a silent no-op).
///
/// **AM-REL-011.** The old code accepted `"assigned"` and mapped *everything else*
/// — including a status string this client has never heard of, and including a
/// server-side error envelope — onto [`PullOutcome::NoAssignment`]. That is the
/// most expensive kind of lie: the miner sat rendering "waiting for the center to
/// place this stage" (a normal, patient-looking state) while the control plane was
/// actually telling it something was wrong, and no operator had any reason to look.
///
/// Now exactly ONE string means not-placed: `no_assignment`. Anything else is
/// returned as an error naming the (sanitized) status + reason_code, so the loop can
/// distinguish "keep polling" from "the protocol broke" and say which.
fn parse_pull(resp: PullResponse) -> Result<PullOutcome, String> {
    match resp.status.as_str() {
        "assigned" => {
            let spec = resp
                .launch_spec
                .ok_or("pull said assigned but carried no launch_spec")?;
            let model_id = resp
                .model_id
                .filter(|m| !m.is_empty())
                .ok_or("pull said assigned but carried no model_id")?;
            let device = resp.device.unwrap_or_else(|| "cuda".to_string());
            // AM-SEC-007 — sanitise at INGEST, not at each render site: `model_id`,
            // `device` and `spec.role` are remote strings that flow into the status
            // dashboard, the logs AND the engine argv. Cleaning them once here means
            // no present or future display path can be repainted by an ANSI/OSC
            // escape smuggled through the control plane.
            let model_id = alice_supervise::sanitize_remote_id(&model_id, alice_supervise::REMOTE_ID_MAX);
            let device = alice_supervise::sanitize_remote_id(&device, alice_supervise::REMOTE_ID_MAX);
            let mut spec = spec;
            spec.role = alice_supervise::sanitize_remote_id(&spec.role, alice_supervise::REMOTE_ID_MAX);
            spec.next_endpoint = spec
                .next_endpoint
                .map(|e| alice_supervise::sanitize_remote_id(&e, alice_supervise::REMOTE_ID_MAX));
            spec.alice_address =
                alice_supervise::sanitize_remote_id(&spec.alice_address, alice_supervise::REMOTE_ID_MAX);
            Ok(PullOutcome::Assigned(Box::new(PullAssignment {
                model_id,
                device,
                spec,
                session_ready: resp.session_ready,
            })))
        }
        // The ONE honest "not placed yet" answer. Keep polling.
        "no_assignment" => Ok(PullOutcome::NoAssignment),
        // Anything else — an unknown protocol value, a renamed status, a server
        // error envelope — is a protocol error. It is NOT "waiting for a placement".
        other => {
            let status = sanitize_reason_code(other);
            let reason = resp
                .reason_code
                .as_deref()
                .map(sanitize_reason_code)
                .filter(|r| !r.is_empty());
            Err(match reason {
                Some(r) => format!(
                    "pull returned an unrecognized status {status:?} (reason_code {r:?}); this \
                     client does not know what that means, so it is NOT being treated as \
                     'waiting for a placement'"
                ),
                None => format!(
                    "pull returned an unrecognized status {status:?} with no reason_code; this \
                     client does not know what that means, so it is NOT being treated as \
                     'waiting for a placement'"
                ),
            })
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Control-plane fault classification (AM-REL-004 / AM-REL-011)
//
// `post_json` renders every failure as a string (`POST <url>: HTTP <code>: <body>`
// or `POST <url>: <transport error>`). The loops need to make DECISIONS from that
// — retry, re-register, or stop pretending to be online — so the string is parsed
// ONCE, here, by a pure function with a full unit table, instead of by ad-hoc
// `e.contains("…")` tests scattered through the CLI.
// ════════════════════════════════════════════════════════════════════════════

/// Reduce a remote string (a `reason_code`, a status value) to something safe to
/// print: lowercase ASCII word characters, `.` `:` `-` only, length-capped.
///
/// Remote text must never reach a terminal unfiltered — an ANSI/OSC payload can
/// repaint the screen and forge a success line. (The broader "sanitize every remote
/// string on its way to the UI" sweep is audit AM-SEC-007; this is the narrow
/// version for the two fields this module itself renders.)
pub fn sanitize_reason_code(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))
        .take(64)
        .collect::<String>()
        .to_ascii_lowercase()
}

/// What KIND of control-plane failure happened — the decision input for the loops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultKind {
    /// The request never got an HTTP answer (DNS, TCP, TLS, timeout). Retryable;
    /// says nothing about our registration.
    Transport,
    /// 401/403 — the PoP was refused. Re-registering is the repair.
    Auth,
    /// 404/409/410 — the server does not know this stage (seat pruned/expired).
    /// Re-registering is the repair.
    SeatGone,
    /// 5xx / 429 — the server is unhappy but our state is probably fine. Retry.
    ServerError,
    /// A well-formed HTTP answer this client cannot interpret (unknown status /
    /// unparseable body). NOT retryable-silently: it must be shown.
    Protocol,
}

/// A parsed control-plane failure: the kind, the HTTP status when there was one,
/// and the server's sanitized `reason_code` when it sent one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault {
    pub kind: FaultKind,
    pub status: Option<u16>,
    pub reason_code: Option<String>,
}

impl Fault {
    /// Whether the repair is to REGISTER again (rather than just retry).
    pub fn needs_reregister(&self) -> bool {
        if matches!(self.kind, FaultKind::Auth | FaultKind::SeatGone) {
            return true;
        }
        // A server that renames its codes must still be understood: any reason_code
        // that SAYS the seat is gone counts, whatever the HTTP status was.
        self.reason_code.as_deref().is_some_and(|r| {
            r.contains("not_registered")
                || r.contains("unregistered")
                || r.contains("unknown_stage")
                || r.contains("stage_not_found")
                || r.contains("expired")
                || r.contains("pruned")
        })
    }

    /// Whether simply trying again later is a reasonable response.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self.kind,
            FaultKind::Transport | FaultKind::ServerError | FaultKind::Auth | FaultKind::SeatGone
        )
    }

    /// A short, sanitized, user-facing description (never the raw remote body).
    pub fn describe(&self) -> String {
        let kind = match self.kind {
            FaultKind::Transport => "cannot reach the center",
            FaultKind::Auth => "the center refused this identity",
            FaultKind::SeatGone => "the center does not know this stage",
            FaultKind::ServerError => "the center returned an error",
            FaultKind::Protocol => "the center's answer could not be understood",
        };
        match (self.status, self.reason_code.as_deref()) {
            (Some(s), Some(r)) => format!("{kind} (HTTP {s}, {r})"),
            (Some(s), None) => format!("{kind} (HTTP {s})"),
            (None, Some(r)) => format!("{kind} ({r})"),
            (None, None) => kind.to_string(),
        }
    }
}

/// Classify a control-plane error string produced by this module. Pure; the whole
/// decision table is unit-tested with no network.
pub fn classify_fault(err: &str) -> Fault {
    let status = parse_http_status(err);
    let reason_code = extract_reason_code(err);
    let kind = match status {
        None => FaultKind::Transport,
        Some(401) | Some(403) => FaultKind::Auth,
        Some(404) | Some(409) | Some(410) => FaultKind::SeatGone,
        Some(429) => FaultKind::ServerError,
        Some(s) if (500..600).contains(&s) => FaultKind::ServerError,
        Some(_) => FaultKind::Protocol,
    };
    Fault {
        kind,
        status,
        reason_code,
    }
}

/// Pull `<code>` out of a `… HTTP <code>: <body>` rendering. `None` when the
/// failure never reached HTTP (a transport error).
fn parse_http_status(err: &str) -> Option<u16> {
    let idx = err.find("HTTP ")?;
    let rest = &err[idx + 5..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// Pull a `"reason_code":"…"` out of a JSON error body, without parsing the whole
/// (possibly hostile) document. Returns the SANITIZED value.
fn extract_reason_code(err: &str) -> Option<String> {
    let key = "\"reason_code\"";
    let start = err.find(key)? + key.len();
    let rest = &err[start..];
    let quote = rest.find('"')? + 1;
    let value: String = rest[quote..].chars().take_while(|c| *c != '"').collect();
    let cleaned = sanitize_reason_code(&value);
    (!cleaned.is_empty()).then_some(cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vectors emitted straight from the Python server source
    // (`shard_stage_pop.stage_binding_signing_message`) — see
    // scratchpad `gen_vector.py` (registers the module in sys.modules, stubs the
    // two heavy imports, execs the pure function). Regenerate with that script if
    // the server framing ever changes; the hex below MUST match byte-for-byte.
    const ADDR: &str = "a2uJXaVk7Zx4fgk9aRLnhiD2RdpAP4usJxKXpN4vh4hDNoP1C";

    #[test]
    fn stage_message_is_byte_exact_ipv4() {
        // Vector 1 from the Python oracle.
        let got = stage_binding_message(ADDR, "203.0.113.7:29501", "stage-nonce-deadbeef-0001");
        let want_hex = "616c6963652d6163703a73686172642d73746167653a62696e642d656e64706f696e743a76310a616c6963655f616464726573733d6132754a5861566b375a783466676b3961524c6e6869443252647041503475734a784b58704e3476683468444e6f5031430a656e64706f696e743d3230332e302e3131332e373a32393530310a6e6f6e63653d73746167652d6e6f6e63652d64656164626565662d30303031";
        assert_eq!(hex::encode(&got), want_hex, "must match the Python oracle byte-for-byte");
        assert_ne!(got.last(), Some(&b'\n'), "no trailing newline");
        assert!(got.is_ascii());
        // The framing the server documents.
        let s = String::from_utf8(got).unwrap();
        assert!(s.starts_with(SHARD_STAGE_DOMAIN));
        assert!(s.contains("\nalice_address="));
        assert!(s.contains("\nendpoint="));
        assert!(s.contains("\nnonce="));
    }

    #[test]
    fn stage_message_is_byte_exact_ipv6() {
        // Vector 2 from the Python oracle (endpoint with a bracketed IPv6 host).
        let got = stage_binding_message(ADDR, "[2001:db8::1]:29600", "n2");
        let want_hex = "616c6963652d6163703a73686172642d73746167653a62696e642d656e64706f696e743a76310a616c6963655f616464726573733d6132754a5861566b375a783466676b3961524c6e6869443252647041503475734a784b58704e3476683468444e6f5031430a656e64706f696e743d5b323030313a6462383a3a315d3a32393630300a6e6f6e63653d6e32";
        assert_eq!(hex::encode(&got), want_hex);
    }

    #[test]
    fn stage_domain_differs_from_worker_and_enroll() {
        // A shard-stage message must not collide with the worker-pull / enroll ones.
        assert_ne!(SHARD_STAGE_DOMAIN, crate::pop::POP_DOMAIN);
        assert_ne!(SHARD_STAGE_DOMAIN, crate::pop::ENROLL_DOMAIN);
    }

    #[test]
    fn sign_fails_closed_for_watch_only() {
        let watch = WalletSecrets::display_only(ADDR);
        assert!(sign_message_b64(&watch, b"msg").is_err());
    }

    #[test]
    fn register_and_heartbeat_fail_closed_before_network_for_watch_only() {
        // A watch-only identity must be rejected up front with a clear message and
        // BEFORE any control-plane call. The https url is well-formed so the only
        // thing that can fail here is the key check.
        let watch = WalletSecrets::display_only(ADDR);
        let e = register(
            "https://api.aliceprotocol.org",
            ADDR,
            "203.0.113.7:29501",
            24.0,
            "enroll:addr",
            "us",
            &watch,
        )
        .unwrap_err();
        assert!(e.contains("watch-only"), "clear watch-only error: {e}");
        let e2 = heartbeat(
            "https://api.aliceprotocol.org",
            ADDR,
            "203.0.113.7:29501",
            Some("ready"),
            &watch,
        )
        .unwrap_err();
        assert!(e2.contains("watch-only"), "clear watch-only error: {e2}");
    }

    // ── URL building (no network) ─────────────────────────────────────────────

    #[test]
    fn stage_route_appends_leaf_and_requires_https() {
        assert_eq!(
            stage_route("https://api.aliceprotocol.org", "register").unwrap(),
            "https://api.aliceprotocol.org/v1/shard/stage/register"
        );
        // A trailing slash on the base is trimmed (no double slash).
        assert_eq!(
            stage_route("https://api.aliceprotocol.org/", "pull").unwrap(),
            "https://api.aliceprotocol.org/v1/shard/stage/pull"
        );
        // Non-https fails closed (a PoP signature must never cross the wire clear).
        assert!(stage_route("http://insecure.example", "nonce").is_err());
    }

    // ── request body shapes (compact ordered JSON) ────────────────────────────

    #[test]
    fn nonce_request_body_shape() {
        let json = serde_json::to_string(&NonceRequest {
            alice_address: ADDR,
            endpoint: "h:1",
        })
        .unwrap();
        assert_eq!(
            json,
            format!("{{\"alice_address\":\"{ADDR}\",\"endpoint\":\"h:1\"}}")
        );
    }

    #[test]
    fn register_request_body_has_all_seven_fields_in_order() {
        let json = serde_json::to_string(&RegisterRequest {
            alice_address: ADDR,
            endpoint: "h:1",
            free_vram_gb: 24.0,
            stake_ref: "enroll:x",
            region: "us",
            nonce: "n-1",
            signature_b64: "c2ln",
        })
        .unwrap();
        assert_eq!(
            json,
            format!(
                "{{\"alice_address\":\"{ADDR}\",\"endpoint\":\"h:1\",\"free_vram_gb\":24.0,\"stake_ref\":\"enroll:x\",\"region\":\"us\",\"nonce\":\"n-1\",\"signature_b64\":\"c2ln\"}}"
            )
        );
    }

    #[test]
    fn heartbeat_status_is_omitted_when_none_and_present_when_set() {
        let none = serde_json::to_string(&HeartbeatRequest {
            alice_address: ADDR,
            endpoint: "h:1",
            nonce: "n",
            signature_b64: "s",
            status: None,
        })
        .unwrap();
        assert!(!none.contains("status"), "None status is omitted: {none}");
        let some = serde_json::to_string(&HeartbeatRequest {
            alice_address: ADDR,
            endpoint: "h:1",
            nonce: "n",
            signature_b64: "s",
            status: Some("ready"),
        })
        .unwrap();
        assert!(some.contains("\"status\":\"ready\""));
    }

    // ── response parsing ──────────────────────────────────────────────────────

    #[test]
    fn nonce_response_prefers_stage_nonce_then_falls_back() {
        let r: NonceResponse =
            serde_json::from_str(r#"{"stage_nonce":"abc","nonce":"legacy"}"#).unwrap();
        assert_eq!(r.stage_nonce.or(r.nonce).unwrap(), "abc");
        let legacy: NonceResponse = serde_json::from_str(r#"{"nonce":"legacy"}"#).unwrap();
        assert_eq!(legacy.stage_nonce.or(legacy.nonce).unwrap(), "legacy");
    }

    #[test]
    fn parse_pull_no_assignment() {
        let resp: PullResponse = serde_json::from_str(
            r#"{"status":"no_assignment","reason_code":"shard_stage_no_assignment","paid_acu":"0"}"#,
        )
        .unwrap();
        assert_eq!(parse_pull(resp).unwrap(), PullOutcome::NoAssignment);
    }

    #[test]
    fn parse_pull_assigned_carries_spec_model_device() {
        // The exact wire shape: top-level model_id/device + a launch_spec object
        // (StageLaunchSpec.to_public_dict), plus the credit-only envelope fields.
        let raw = r#"{
            "status":"assigned",
            "reason_code":"shard_stage_assigned",
            "model_id":"Qwen/Qwen2.5-3B-Instruct",
            "device":"cuda",
            "launch_spec":{
                "stage_index":1,"n_stages":3,"alice_address":"a2addr",
                "layer_lo":12,"layer_hi":24,"role":"middle",
                "listen_port":29501,"next_endpoint":"10.0.0.3:29501"
            },
            "session_ready":true,
            "paid_acu":"0"
        }"#;
        let resp: PullResponse = serde_json::from_str(raw).unwrap();
        match parse_pull(resp).unwrap() {
            PullOutcome::Assigned(a) => {
                assert_eq!(a.model_id, "Qwen/Qwen2.5-3B-Instruct");
                assert_eq!(a.device, "cuda");
                assert_eq!(a.spec.stage_index, 1);
                assert_eq!(a.spec.n_stages, 3);
                assert_eq!(a.spec.role, "middle");
                assert_eq!(a.spec.listen_port, 29501);
                assert_eq!(a.spec.next_endpoint.as_deref(), Some("10.0.0.3:29501"));
                assert_eq!(a.session_ready, Some(true));
            }
            other => panic!("expected assigned, got {other:?}"),
        }
    }

    /// AM-SEC-007 at INGEST: a hostile center answers a pull with terminal-control
    /// payloads in `model_id` / `device` / `role` / `next_endpoint`. They must be
    /// neutralised here, before they can reach the dashboard, the log, OR the engine
    /// argv (`engine_argv` copies `model_id` and `next_endpoint` verbatim).
    #[test]
    fn parse_pull_sanitises_hostile_remote_strings() {
        // NB: every escape below is a JSON \u sequence, so this SOURCE file holds no
        // invisible control bytes; serde_json decodes them into the real ESC/CR/LF/NUL
        // an attacker would actually put on the wire.
        let raw = r#"{
            "status":"assigned",
            "model_id":"m\u001b[2K\rMINING OK",
            "device":"cuda\u001b]8;;https://evil.tld\u0007",
            "launch_spec":{
                "stage_index":1,"n_stages":3,"alice_address":"a2addr\u0000",
                "layer_lo":12,"layer_hi":24,"role":"middle\u001b[31m",
                "listen_port":29501,"next_endpoint":"10.0.0.3:29501\nrole: head"
            }
        }"#;
        let resp: PullResponse = serde_json::from_str(raw).unwrap();
        match parse_pull(resp).unwrap() {
            PullOutcome::Assigned(a) => {
                let surfaces = [
                    a.model_id.clone(),
                    a.device.clone(),
                    a.spec.role.clone(),
                    a.spec.alice_address.clone(),
                    a.spec.next_endpoint.clone().unwrap_or_default(),
                ];
                for s in &surfaces {
                    assert!(
                        !s.chars().any(char::is_control),
                        "a control char reached a display/argv surface: {s:?}"
                    );
                    assert!(!s.contains('\u{1b}'), "ESC survived: {s:?}");
                }
                // Also prove it does not reach the engine argv.
                let argv = engine_argv(&a).join(" ");
                assert!(!argv.chars().any(char::is_control), "control char in argv: {argv:?}");
            }
            other => panic!("expected assigned, got {other:?}"),
        }
    }

    #[test]
    fn parse_pull_assigned_without_spec_is_an_error() {
        let resp: PullResponse =
            serde_json::from_str(r#"{"status":"assigned","model_id":"m"}"#).unwrap();
        assert!(parse_pull(resp).is_err());
    }

    /// AM-REL-011: an UNKNOWN status must surface as a protocol error naming itself,
    /// never as the calm "waiting for a placement" state. This is the regression that
    /// let a real server-side error look like patience for as long as anyone cared to
    /// watch.
    #[test]
    fn parse_pull_unknown_status_is_an_error_not_a_silent_wait() {
        for raw in [
            r#"{"status":"error","reason_code":"shard_swarm_unavailable"}"#,
            r#"{"status":"draining"}"#,
            r#"{"status":""}"#,
            r#"{}"#,
        ] {
            let resp: PullResponse = serde_json::from_str(raw).unwrap();
            let e = parse_pull(resp).unwrap_err();
            assert!(
                e.contains("unrecognized status"),
                "{raw} must be a protocol error, got: {e}"
            );
            assert!(
                e.contains("NOT being treated"),
                "the error must say what it is NOT doing: {e}"
            );
        }
        // …while the ONE honest not-placed answer still means keep polling.
        let ok: PullResponse = serde_json::from_str(r#"{"status":"no_assignment"}"#).unwrap();
        assert_eq!(parse_pull(ok).unwrap(), PullOutcome::NoAssignment);
    }

    /// A hostile status/reason_code cannot repaint the terminal through the error.
    #[test]
    fn parse_pull_sanitizes_remote_strings_in_its_error() {
        let raw = "{\"status\":\"\\u001b[2Jassigned-ish\",\"reason_code\":\"\\u001b]0;pwned\\u0007\"}";
        let resp: PullResponse = serde_json::from_str(raw).unwrap();
        let e = parse_pull(resp).unwrap_err();
        assert!(!e.contains('\u{1b}'), "no ESC may survive into the message: {e:?}");
        assert!(!e.contains('\u{7}'), "no BEL may survive into the message: {e:?}");
    }

    // ── fault classification (AM-REL-004) ─────────────────────────────────────

    #[test]
    fn sanitize_reason_code_strips_control_and_caps_length() {
        assert_eq!(sanitize_reason_code("shard_stage_no_assignment"), "shard_stage_no_assignment");
        assert_eq!(sanitize_reason_code("\u{1b}[31mBAD\u{1b}[0m"), "31mbad0m");
        assert_eq!(sanitize_reason_code("a\nb\tc"), "abc");
        assert_eq!(sanitize_reason_code(&"x".repeat(200)).len(), 64);
        assert_eq!(sanitize_reason_code(""), "");
    }

    #[test]
    fn classify_fault_decision_table() {
        // No HTTP answer at all → transport (retryable, no re-register implied).
        let t = classify_fault("POST https://api/x: Dns Failed: resolve");
        assert_eq!(t.kind, FaultKind::Transport);
        assert_eq!(t.status, None);
        assert!(t.is_retryable());
        assert!(!t.needs_reregister());

        // 401/403 → auth; the repair is to register again.
        for code in [401, 403] {
            let f = classify_fault(&format!("POST https://api/x: HTTP {code}: {{\"detail\":\"no\"}}"));
            assert_eq!(f.kind, FaultKind::Auth, "HTTP {code}");
            assert!(f.needs_reregister());
        }

        // 404/409/410 → the seat is gone.
        for code in [404, 409, 410] {
            let f = classify_fault(&format!("POST https://api/x: HTTP {code}: {{}}"));
            assert_eq!(f.kind, FaultKind::SeatGone, "HTTP {code}");
            assert!(f.needs_reregister());
        }

        // 5xx / 429 → the server's problem; retry, don't re-register.
        for code in [429, 500, 503] {
            let f = classify_fault(&format!("POST https://api/x: HTTP {code}: upstream"));
            assert_eq!(f.kind, FaultKind::ServerError, "HTTP {code}");
            assert!(f.is_retryable());
            assert!(!f.needs_reregister());
        }

        // A 4xx we have no rule for is a PROTOCOL fault — shown, not silently retried.
        let p = classify_fault("POST https://api/x: HTTP 418: teapot");
        assert_eq!(p.kind, FaultKind::Protocol);
        assert!(!p.is_retryable());
    }

    /// The reason_code overrides the status class: a server that renames its codes
    /// still gets us to re-register when it says the seat is gone.
    #[test]
    fn reason_code_can_demand_a_reregister_on_any_status() {
        let f = classify_fault(
            "POST https://api/x: HTTP 400: {\"ok\":false,\"reason_code\":\"shard_stage_not_registered\"}",
        );
        assert_eq!(f.status, Some(400));
        assert_eq!(f.reason_code.as_deref(), Some("shard_stage_not_registered"));
        assert!(f.needs_reregister(), "an explicit not_registered must trigger re-registration");

        // …and a plain server error does NOT.
        let g = classify_fault("POST https://api/x: HTTP 500: {\"reason_code\":\"internal\"}");
        assert!(!g.needs_reregister());
        assert_eq!(g.reason_code.as_deref(), Some("internal"));
    }

    #[test]
    fn fault_describe_never_leaks_raw_body_or_escapes() {
        let f = classify_fault(
            "POST https://api/x: HTTP 403: {\"reason_code\":\"\u{1b}[2Jshard_pop_failed\",\"detail\":\"secret-ish body\"}",
        );
        let d = f.describe();
        assert!(!d.contains('\u{1b}'));
        assert!(!d.contains("secret-ish"), "the raw body must not be echoed: {d}");
        assert!(d.contains("403"));
    }

    // ── argv construction (matches StageLaunchSpec.engine_argv byte-for-byte) ──

    fn spec(role: &str, next: Option<&str>) -> PullAssignment {
        PullAssignment {
            model_id: "Qwen/Qwen2.5-3B-Instruct".into(),
            device: "cuda".into(),
            spec: LaunchSpec {
                stage_index: 0,
                n_stages: 3,
                alice_address: "a2addr".into(),
                layer_lo: 0,
                layer_hi: 12,
                role: role.into(),
                listen_port: 29501,
                next_endpoint: next.map(|s| s.into()),
            },
            session_ready: None,
        }
    }

    #[test]
    fn argv_head_connects_forward_does_not_listen() {
        // Head: --stage 0 --nstages 3 --model M --device cuda --next H:port
        // (no --listen-port; the head drives).
        let mut a = spec("head", Some("10.0.0.2:29501"));
        a.spec.stage_index = 0;
        let argv = engine_argv(&a);
        assert_eq!(
            argv,
            vec![
                "--stage", "0", "--nstages", "3", "--model", "Qwen/Qwen2.5-3B-Instruct",
                "--device", "cuda", "--next", "10.0.0.2:29501"
            ]
        );
        assert!(!argv.iter().any(|s| s == "--listen-port"));
    }

    #[test]
    fn argv_middle_listens_and_forwards() {
        let mut a = spec("middle", Some("10.0.0.3:29501"));
        a.spec.stage_index = 1;
        let argv = engine_argv(&a);
        assert_eq!(
            argv,
            vec![
                "--stage", "1", "--nstages", "3", "--model", "Qwen/Qwen2.5-3B-Instruct",
                "--device", "cuda", "--listen-port", "29501", "--next", "10.0.0.3:29501"
            ]
        );
    }

    #[test]
    fn argv_tail_listens_only() {
        let mut a = spec("tail", None);
        a.spec.stage_index = 2;
        let argv = engine_argv(&a);
        assert_eq!(
            argv,
            vec![
                "--stage", "2", "--nstages", "3", "--model", "Qwen/Qwen2.5-3B-Instruct",
                "--device", "cuda", "--listen-port", "29501"
            ]
        );
        assert!(!argv.iter().any(|s| s == "--next"));
    }
}
