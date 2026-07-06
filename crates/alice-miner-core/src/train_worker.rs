//! Training-coordinator **RLVR-worker** client (the `alice-miner train` role).
//!
//! A GPU miner joins the Alice RLVR coding-task network as a PULL worker: it
//! registers its Alice address + stake reference with the Alice training coordinator
//! (the acp gateway), LEASES one coding task (a `prompt` + `entry_point` + a
//! `held_out_commitment`; the hidden tests NEVER leave the coordinator), produces a
//! CANDIDATE solution with its own GPU/model, and SUBMITS it. The coordinator
//! re-executes the candidate against the hidden tests server-side, forms a verdict,
//! and (credit-only) folds a credit weight.
//!
//! Unlike the shard `ai` stage (a LISTEN worker that binds a public `endpoint`), a
//! training worker has **no listen endpoint** — the network never dials it, it only
//! pulls tasks and pushes candidates. So the PoP binds ONLY `alice_address + nonce`
//! (NOT an endpoint), matching the server's `train_binding_signing_message`.
//!
//! This module is the headless PROTOCOL core (no UI, no subprocess): the PoP signing
//! bytes and the HTTPS control-plane calls (`nonce` / `register` / `lease` /
//! `submit`) with their exact request/response shapes. The subprocess supervision +
//! live status live in the CLI's `train` command; this crate holds only what must
//! match the server byte-for-byte.
//!
//! ── Server source of truth (matched byte-exact) ─────────────────────────────
//!   * PoP domain + message: `alice_acp.train.train_stage_pop`
//!     (`train_binding_signing_message`) — `domain ‖ alice_address ‖ nonce`,
//!     newline-framed ASCII, sr25519, base64 in `signature_b64`.
//!   * Routes: `POST /v1/train/{nonce,register,lease,submit}`
//!     (`alice_acp.shadow_server.http_app`), gated by `ALICE_TRAIN_STAGE_ENABLED`.
//!     The nonce response field is `train_nonce`; register returns `registered`;
//!     lease returns `{task_id, entry_point, prompt, held_out_commitment, lease_id,
//!     expires_at}` (the hidden tests are NEVER sent); submit returns a `verdict` +
//!     credit-only envelope. The submit route is `/v1/train/submit` and is
//!     dispatched to the network path by carrying a `lease_id` in the body.
//!
//! ── CREDIT-ONLY ─────────────────────────────────────────────────────────────
//! Every server response carries `paid_acu:"0"`; this client never reads/writes a
//! reward. Registration proves possession with the SAME sr25519 wallet key the PRL
//! lane uses — a watch-only (pasted-address) identity can never register or submit.

use std::io::Read as _;
use std::time::Duration;

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use alice_crypto::WalletSecrets;

/// Domain-separation tag for the training register/lease/submit binding signature.
/// DISTINCT from the shard-stage / worker-pull / m4-enroll domains so no PoP can be
/// replayed across surfaces. Server: `train_stage_pop.TRAIN_STAGE_BINDING_DOMAIN`.
pub const TRAIN_BINDING_DOMAIN: &str = "alice-acp:train-coordinator:bind-address:v1";

/// The sr25519 default PoP scheme string the server + client agree on.
pub const TRAIN_SCHEME_DEFAULT: &str = "sr25519";

/// The EXACT bytes a training worker signs to authorize a register / lease / submit —
/// byte-identical to the server's `train_binding_signing_message`: the domain line,
/// then two `key=value` lines, newline-FRAMED (newline BETWEEN lines, NONE trailing),
/// ASCII. NO endpoint is bound (a training worker has none — it pulls tasks and pushes
/// candidates; the network never dials it). `alice_address` binds possession; `nonce`
/// (single-use, server-issued) blocks pre-compute + replay.
pub fn train_binding_message(alice_address: &str, nonce: &str) -> Vec<u8> {
    format!("{TRAIN_BINDING_DOMAIN}\nalice_address={alice_address}\nnonce={nonce}").into_bytes()
}

/// Sign the train-binding bytes with the Alice sr25519 key; return the 64-byte
/// schnorrkel signature in STANDARD base64 (the alphabet the server's
/// `base64.b64decode` expects). Fails closed if `secrets` is watch-only (no key) —
/// a pasted address can never register / lease / submit.
pub fn sign_message_b64(secrets: &WalletSecrets, message: &[u8]) -> Result<String, String> {
    let keypair = secrets.to_keypair()?;
    let sig = keypair.sign(message);
    Ok(base64::engine::general_purpose::STANDARD.encode(sig.0))
}

// ════════════════════════════════════════════════════════════════════════════
// HTTPS control plane — the four training routes on the acp gateway.
//
// Base URL is the acp gateway (`--center-url`); the four routes are
// `<base>/v1/train/{nonce,register,lease,submit}`. Every URL MUST be https:// (fail
// closed — a PoP signature must never cross the wire in the clear), with a small read
// cap + ~10s timeout bounding a hostile/oversized response. All bodies are typed
// structs (compact serde_json), so the on-wire JSON shape is asserted in unit tests
// with NO network.
// ════════════════════════════════════════════════════════════════════════════

/// Connect + read timeout for every control-plane call (~10s, matching `shard.rs`).
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound on any control-plane response body. A leased task carries a full coding
/// prompt (potentially a few KiB); 256 KiB is generous yet caps a hostile/runaway
/// response.
const MAX_RESPONSE_BYTES: u64 = 256 * 1024;

/// Reject any non-`https://` URL — fail closed so a PoP signature can never be sent
/// in the clear.
fn require_https(url: &str) -> Result<(), String> {
    if url.starts_with("https://") {
        Ok(())
    } else {
        Err(format!("refusing non-https center url: {url}"))
    }
}

/// Build `<base>/v1/train/<leaf>`, trimming a single trailing `/` off the base so both
/// `https://host` and `https://host/` yield the same URL. https-checked.
pub fn train_route(center_url: &str, leaf: &str) -> Result<String, String> {
    require_https(center_url)?;
    let base = center_url.strip_suffix('/').unwrap_or(center_url);
    let url = format!("{base}/v1/train/{leaf}");
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
        .user_agent(concat!("alice-miner-train/", env!("CARGO_PKG_VERSION")))
        .build()
}

/// POST a typed body as compact JSON, read the (capped) response, parse into `R`.
/// Caller has already https-checked the URL. A non-2xx surfaces as an `Err` carrying
/// the status + (capped) body so the caller can show the server's secret-free
/// reason_code. Mirrors `shard.rs::post_json` exactly (the workspace `ureq` is built
/// without the `json` feature, so we serialize + set the content-type ourselves).
fn post_json<B: Serialize, R: serde::de::DeserializeOwned>(url: &str, body: &B) -> Result<R, String> {
    let payload = serde_json::to_string(body).map_err(|e| format!("serialize: {e}"))?;
    let resp = match agent()
        .post(url)
        .set("Content-Type", "application/json")
        .send_string(&payload)
    {
        Ok(r) => r,
        Err(ureq::Error::Status(code, resp)) => {
            let mut buf = Vec::new();
            let _ = resp
                .into_reader()
                .take(MAX_RESPONSE_BYTES)
                .read_to_end(&mut buf);
            let body = String::from_utf8_lossy(&buf);
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
}

#[derive(Serialize)]
struct RegisterRequest<'a> {
    alice_address: &'a str,
    stake_ref: &'a str,
    /// Optional device hint (informational — the coordinator records it). Skipped
    /// when empty so the wire shape is minimal.
    #[serde(skip_serializing_if = "str::is_empty")]
    device: &'a str,
    /// Optional region hint (informational). Skipped when empty.
    #[serde(skip_serializing_if = "str::is_empty")]
    region: &'a str,
    nonce: &'a str,
    signature_b64: &'a str,
}

#[derive(Serialize)]
struct LeaseRequest<'a> {
    alice_address: &'a str,
    nonce: &'a str,
    signature_b64: &'a str,
}

#[derive(Serialize)]
struct SubmitRequest<'a> {
    lease_id: &'a str,
    alice_address: &'a str,
    candidate_code: &'a str,
    /// The worker's OWN claimed pass rate for the candidate (optional; the server
    /// re-executes regardless). Serialized as a decimal string to match the server's
    /// `Decimal(claimed_raw)` parse. Skipped when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    claimed_pass_rate: Option<&'a str>,
    /// Optional per-device key for the credit fold (defaults server-side to the
    /// address). Skipped when empty.
    #[serde(skip_serializing_if = "str::is_empty")]
    device_key: &'a str,
    nonce: &'a str,
    signature_b64: &'a str,
}

// ── response shapes ────────────────────────────────────────────────────────────

/// The nonce-mint response. The canonical field is `train_nonce`; we also accept a
/// bare `nonce` for forward/back-compat with a server that renames it.
#[derive(Deserialize)]
struct NonceResponse {
    #[serde(default)]
    train_nonce: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
}

/// The lease response's task view — EXACTLY the server's `LeasableTask.public_lease_view()`
/// plus the lease id + expiry. The hidden tests are NEVER present (kept server-side for
/// re-execution). `held_out_commitment` is the anti-overfit seal (sha256 over the parsed
/// cases) — surfaced so a worker can confirm the tests were fixed before it solved.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct LeasedTask {
    pub task_id: String,
    pub entry_point: String,
    pub prompt: String,
    pub held_out_commitment: String,
    pub lease_id: String,
    pub expires_at: String,
}

/// The `lease` response envelope: `ok` gates whether a task was handed out (`ok:true`
/// with the task fields) or none was available / the caller is unregistered
/// (`ok:false` with a `reason_code`). The task fields are flattened onto the response
/// (the server merges `public_lease_view()` into the envelope).
#[derive(Deserialize)]
struct LeaseResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    reason_code: Option<String>,
    #[serde(default)]
    task_id: Option<String>,
    #[serde(default)]
    entry_point: Option<String>,
    #[serde(default)]
    prompt: Option<String>,
    #[serde(default)]
    held_out_commitment: Option<String>,
    #[serde(default)]
    lease_id: Option<String>,
    #[serde(default)]
    expires_at: Option<String>,
}

/// The `submit` response: the coordinator's verdict + the credit-only envelope. `ok`
/// is true only on a `verified` verdict. `verdict` is one of "verified" /
/// "not_verified" / "indeterminate" / "none". `match_rate` is the fraction of hidden
/// cases the candidate passed (a decimal string). `credited` reflects the adapter's
/// env gate too (OFF ⇒ False even on a verified verdict — dormant-complete).
#[derive(Deserialize)]
struct SubmitResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    reason_code: Option<String>,
    #[serde(default)]
    task_id: Option<String>,
    #[serde(default)]
    verdict: Option<String>,
    #[serde(default)]
    verified_reward: Option<String>,
    #[serde(default)]
    max_verifiable_reward: Option<String>,
    #[serde(default)]
    match_rate: Option<String>,
    #[serde(default)]
    quorum_k: Option<u32>,
    #[serde(default)]
    quorum_agree: Option<u32>,
    #[serde(default)]
    credited: bool,
    /// The credit-only envelope's `paid_acu` field, always "0". Read only to ASSERT
    /// the invariant client-side (a server that ever set it non-zero is a protocol
    /// violation the client refuses to render as a reward).
    #[serde(default)]
    paid_acu: Option<String>,
}

/// The outcome of a lease call: a task, or the honest "no task right now".
#[derive(Debug, Clone, PartialEq)]
pub enum LeaseOutcome {
    /// The coordinator handed out a task — solve it + submit.
    Leased(Box<LeasedTask>),
    /// A registered worker with no task available (the corpus is empty / exhausted for
    /// this tick). Keep polling.
    NoTask,
}

/// The parsed verdict of a submit — the honest, credit-only surface the UI shows.
#[derive(Debug, Clone, PartialEq)]
pub struct SubmitVerdict {
    pub task_id: String,
    /// "verified" / "not_verified" / "indeterminate" / "none".
    pub verdict: String,
    pub reason_code: String,
    /// The fraction of hidden cases passed (as reported; a decimal string), when known.
    pub match_rate: Option<String>,
    pub quorum_k: Option<u32>,
    pub quorum_agree: Option<u32>,
    /// Whether the coordinator FOLDED a credit weight (adapter gate ON + verified).
    /// CREDIT-ONLY: this is a weight fold, never a paid amount.
    pub credited: bool,
}

impl SubmitVerdict {
    /// `true` for a `verified` verdict (the candidate passed the hidden-test quorum).
    pub fn is_verified(&self) -> bool {
        self.verdict == "verified"
    }
}

/// POST `/v1/train/nonce` → the single-use `train_nonce` to sign. Echoes the
/// `alice_address` the client says it will bind (informational server-side); we only
/// need the nonce back.
pub fn fetch_nonce(center_url: &str, alice_address: &str) -> Result<String, String> {
    let url = train_route(center_url, "nonce")?;
    let body = NonceRequest { alice_address };
    let resp: NonceResponse = post_json(&url, &body)?;
    resp.train_nonce
        .or(resp.nonce)
        .filter(|n| !n.is_empty())
        .ok_or_else(|| "nonce response missing a non-empty train_nonce".to_string())
}

/// POST `/v1/train/register` — bind this worker into the stake-gated coordinator.
/// Fetches a fresh nonce, signs the train-binding message over `alice_address`, and
/// submits `{alice_address, stake_ref, device?, region?, nonce, signature_b64}`. Fails
/// closed for a watch-only identity (no key) BEFORE any network. A server reject (bad
/// address / no stake / PoP failure / gate OFF) surfaces as an `Err` carrying the
/// stable reason_code.
pub fn register(
    center_url: &str,
    alice_address: &str,
    stake_ref: &str,
    device: &str,
    region: &str,
    secrets: &WalletSecrets,
) -> Result<(), String> {
    // Fail closed up front: a watch-only identity can never sign the binding, so
    // there is no point fetching a nonce.
    if secrets.to_keypair().is_err() {
        return Err(
            "this reward identity is watch-only (address pasted, no signing key); the train role \
             must prove it owns the address to register — import the mnemonic/seed instead"
                .into(),
        );
    }
    let nonce = fetch_nonce(center_url, alice_address)?;
    let msg = train_binding_message(alice_address, &nonce);
    let sig_b64 = sign_message_b64(secrets, &msg)?;
    let url = train_route(center_url, "register")?;
    let body = RegisterRequest {
        alice_address,
        stake_ref,
        device,
        region,
        nonce: &nonce,
        signature_b64: &sig_b64,
    };
    let _resp: serde_json::Value = post_json(&url, &body)?;
    Ok(())
}

/// POST `/v1/train/lease` — lease ONE coding task (same PoP gate as register). Returns
/// [`LeaseOutcome::Leased`] with the prompt / entry / commitment / lease id / expiry, or
/// [`LeaseOutcome::NoTask`] when a REGISTERED worker has nothing to solve this tick. Fails
/// closed for a watch-only identity. The hidden tests are NEVER in the response.
pub fn lease(center_url: &str, alice_address: &str, secrets: &WalletSecrets) -> Result<LeaseOutcome, String> {
    if secrets.to_keypair().is_err() {
        return Err("watch-only identity cannot sign a training lease".into());
    }
    let nonce = fetch_nonce(center_url, alice_address)?;
    let msg = train_binding_message(alice_address, &nonce);
    let sig_b64 = sign_message_b64(secrets, &msg)?;
    let url = train_route(center_url, "lease")?;
    let body = LeaseRequest {
        alice_address,
        nonce: &nonce,
        signature_b64: &sig_b64,
    };
    let resp: LeaseResponse = post_json(&url, &body)?;
    parse_lease(resp)
}

/// Turn a parsed lease response into a [`LeaseOutcome`], validating that an `ok:true`
/// lease actually carries the task fields (a truncated "leased" with no lease id / prompt
/// is a protocol error, not a silent no-op). `ok:false` is the honest "no task"
/// (`train_no_task_available`) OR an unregistered caller (`train_worker_not_registered`);
/// the latter surfaces as an `Err` so the loop re-registers rather than spinning.
fn parse_lease(resp: LeaseResponse) -> Result<LeaseOutcome, String> {
    if resp.ok {
        let lease_id = resp
            .lease_id
            .filter(|s| !s.is_empty())
            .ok_or("lease ok:true but carried no lease_id")?;
        let task_id = resp
            .task_id
            .filter(|s| !s.is_empty())
            .ok_or("lease ok:true but carried no task_id")?;
        let prompt = resp
            .prompt
            .filter(|s| !s.is_empty())
            .ok_or("lease ok:true but carried no prompt")?;
        let entry_point = resp.entry_point.unwrap_or_default();
        let held_out_commitment = resp.held_out_commitment.unwrap_or_default();
        let expires_at = resp.expires_at.unwrap_or_default();
        return Ok(LeaseOutcome::Leased(Box::new(LeasedTask {
            task_id,
            entry_point,
            prompt,
            held_out_commitment,
            lease_id,
            expires_at,
        })));
    }
    // ok:false — distinguish "no task" (a normal, keep-polling state) from
    // "not registered" (a state the loop must repair by re-registering).
    match resp.reason_code.as_deref() {
        Some("train_worker_not_registered") => {
            Err("train_worker_not_registered".to_string())
        }
        _ => Ok(LeaseOutcome::NoTask),
    }
}

/// POST `/v1/train/submit` — submit the candidate solution for a leased task (same PoP
/// gate; the body carries a `lease_id` so the server dispatches the NETWORK path). The
/// coordinator re-executes the candidate against the hidden tests (server-side quorum)
/// and returns a verdict + credit-only envelope. Returns the parsed [`SubmitVerdict`];
/// a lease/candidate reject (unknown/expired/already-submitted lease, empty candidate)
/// surfaces as an `Err` carrying the stable reason_code. Fails closed for watch-only.
#[allow(clippy::too_many_arguments)]
pub fn submit(
    center_url: &str,
    alice_address: &str,
    lease_id: &str,
    candidate_code: &str,
    claimed_pass_rate: Option<&str>,
    device_key: &str,
    secrets: &WalletSecrets,
) -> Result<SubmitVerdict, String> {
    if secrets.to_keypair().is_err() {
        return Err("watch-only identity cannot sign a training submission".into());
    }
    let nonce = fetch_nonce(center_url, alice_address)?;
    let msg = train_binding_message(alice_address, &nonce);
    let sig_b64 = sign_message_b64(secrets, &msg)?;
    let url = train_route(center_url, "submit")?;
    let body = SubmitRequest {
        lease_id,
        alice_address,
        candidate_code,
        claimed_pass_rate,
        device_key,
        nonce: &nonce,
        signature_b64: &sig_b64,
    };
    let resp: SubmitResponse = post_json(&url, &body)?;
    parse_submit(resp)
}

/// Turn a parsed submit response into a [`SubmitVerdict`]. CREDIT-ONLY hard check: a
/// non-"0" `paid_acu` is a protocol violation (the training network mints nothing on
/// this path), refused rather than rendered as a reward.
fn parse_submit(resp: SubmitResponse) -> Result<SubmitVerdict, String> {
    if let Some(paid) = resp.paid_acu.as_deref() {
        if paid != "0" {
            return Err(format!(
                "coordinator returned a non-zero paid_acu ({paid:?}); the training network is \
                 credit-only and mints nothing here — refusing to render it as a reward"
            ));
        }
    }
    let verdict = resp.verdict.unwrap_or_else(|| "none".to_string());
    let reason_code = resp.reason_code.unwrap_or_default();
    // A verdict is always returned on a 200 (verified / not_verified / indeterminate).
    // A lease/candidate reject (unknown lease, expired, already submitted, empty
    // candidate) comes back with ok:false + verdict "none" + a reason_code AND a 400,
    // which `post_json` already surfaced as an Err — so reaching here with verdict
    // "none" and a lease-problem reason means the server accepted the request shape but
    // could not score it; carry it through honestly.
    let _ = resp.ok;
    let _ = resp.verified_reward;
    let _ = resp.max_verifiable_reward;
    Ok(SubmitVerdict {
        task_id: resp.task_id.unwrap_or_default(),
        verdict,
        reason_code,
        match_rate: resp.match_rate,
        quorum_k: resp.quorum_k,
        quorum_agree: resp.quorum_agree,
        credited: resp.credited,
    })
}

/// Probe the center's health for a preflight (`doctor --train`). GETs `<base>/health`
/// with a short timeout. Returns `Ok(desc)` when the host is up + serving (ANY HTTP
/// response, including a gated non-2xx, proves reachability), or `Err(reason)` on a
/// transport failure / non-https URL. Never panics. Diagnostic only — signs nothing.
pub fn probe_center_health(center_url: &str) -> Result<String, String> {
    require_https(center_url)?;
    let base = center_url.strip_suffix('/').unwrap_or(center_url);
    let health = format!("{base}/health");
    let agent = ureq::AgentBuilder::new()
        .tls_config(alice_release::tls::os_trust_config()) // OS trust store (Windows UnknownIssuer fix)
        .timeout_connect(Duration::from_secs(5))
        .timeout_read(Duration::from_secs(5))
        .user_agent(concat!("alice-miner-train/", env!("CARGO_PKG_VERSION")))
        .build();
    match agent.get(&health).call() {
        Ok(_) => Ok(format!("center reachable ({health})")),
        Err(ureq::Error::Status(code, _)) => Ok(format!("center reachable ({health} → HTTP {code})")),
        Err(e) => Err(format!("cannot reach the center at {health}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vectors emitted straight from the Python server source
    // (`train_stage_pop.train_binding_signing_message`) — see scratchpad
    // `gen_train_vector.py`, which reads the DOMAIN constant out of the source file
    // and replicates the pure `f"{DOMAIN}\nalice_address={..}\nnonce={..}".encode(ascii)`.
    // Regenerate with that script if the server framing ever changes; the hex below
    // MUST match byte-for-byte. Command:
    //   python3 scratchpad/gen_train_vector.py
    const ADDR: &str = "a2uJXaVk7Zx4fgk9aRLnhiD2RdpAP4usJxKXpN4vh4hDNoP1C";

    #[test]
    fn train_message_is_byte_exact_v1() {
        // Vector v1 from the Python oracle: nonce "train-nonce-deadbeef-0001".
        let got = train_binding_message(ADDR, "train-nonce-deadbeef-0001");
        let want_hex = "616c6963652d6163703a747261696e2d636f6f7264696e61746f723a62696e642d616464726573733a76310a616c6963655f616464726573733d6132754a5861566b375a783466676b3961524c6e6869443252647041503475734a784b58704e3476683468444e6f5031430a6e6f6e63653d747261696e2d6e6f6e63652d64656164626565662d30303031";
        assert_eq!(hex::encode(&got), want_hex, "must match the Python oracle byte-for-byte");
        assert_ne!(got.last(), Some(&b'\n'), "no trailing newline");
        assert!(got.is_ascii());
        let s = String::from_utf8(got).unwrap();
        assert!(s.starts_with(TRAIN_BINDING_DOMAIN));
        assert!(s.contains("\nalice_address="));
        assert!(s.contains("\nnonce="));
        // A training worker binds NO endpoint (that is the whole point of this domain).
        assert!(!s.contains("endpoint="), "the train binding must not bind an endpoint");
    }

    #[test]
    fn train_message_is_byte_exact_v2() {
        // Vector v2 from the Python oracle: nonce "n2".
        let got = train_binding_message(ADDR, "n2");
        let want_hex = "616c6963652d6163703a747261696e2d636f6f7264696e61746f723a62696e642d616464726573733a76310a616c6963655f616464726573733d6132754a5861566b375a783466676b3961524c6e6869443252647041503475734a784b58704e3476683468444e6f5031430a6e6f6e63653d6e32";
        assert_eq!(hex::encode(&got), want_hex);
    }

    #[test]
    fn train_domain_differs_from_shard_worker_and_enroll() {
        // A train message must not collide with the shard-stage / worker-pull / enroll ones.
        assert_ne!(TRAIN_BINDING_DOMAIN, crate::shard::SHARD_STAGE_DOMAIN);
        assert_ne!(TRAIN_BINDING_DOMAIN, crate::pop::POP_DOMAIN);
        assert_ne!(TRAIN_BINDING_DOMAIN, crate::pop::ENROLL_DOMAIN);
    }

    #[test]
    fn sign_fails_closed_for_watch_only() {
        let watch = WalletSecrets::display_only(ADDR);
        assert!(sign_message_b64(&watch, b"msg").is_err());
    }

    #[test]
    fn register_lease_submit_fail_closed_before_network_for_watch_only() {
        // A watch-only identity must be rejected up front, BEFORE any control-plane call.
        // The https url is well-formed so the only thing that can fail is the key check.
        let watch = WalletSecrets::display_only(ADDR);
        let e = register(
            "https://api.aliceprotocol.org",
            ADDR,
            "enroll:addr",
            "cuda",
            "us",
            &watch,
        )
        .unwrap_err();
        assert!(e.contains("watch-only"), "clear watch-only error: {e}");

        let e2 = lease("https://api.aliceprotocol.org", ADDR, &watch).unwrap_err();
        assert!(e2.contains("watch-only"), "clear watch-only error: {e2}");

        let e3 = submit(
            "https://api.aliceprotocol.org",
            ADDR,
            "lease-abc",
            "def f(): pass",
            None,
            "",
            &watch,
        )
        .unwrap_err();
        assert!(e3.contains("watch-only"), "clear watch-only error: {e3}");
    }

    // ── URL building (no network) ─────────────────────────────────────────────

    #[test]
    fn train_route_appends_leaf_and_requires_https() {
        assert_eq!(
            train_route("https://api.aliceprotocol.org", "register").unwrap(),
            "https://api.aliceprotocol.org/v1/train/register"
        );
        // A trailing slash on the base is trimmed (no double slash).
        assert_eq!(
            train_route("https://api.aliceprotocol.org/", "lease").unwrap(),
            "https://api.aliceprotocol.org/v1/train/lease"
        );
        assert_eq!(
            train_route("https://api.aliceprotocol.org", "submit").unwrap(),
            "https://api.aliceprotocol.org/v1/train/submit"
        );
        // Non-https fails closed (a PoP signature must never cross the wire clear).
        assert!(train_route("http://insecure.example", "nonce").is_err());
    }

    // ── request body shapes (compact ordered JSON) ────────────────────────────

    #[test]
    fn nonce_request_body_shape() {
        let json = serde_json::to_string(&NonceRequest { alice_address: ADDR }).unwrap();
        assert_eq!(json, format!("{{\"alice_address\":\"{ADDR}\"}}"));
    }

    #[test]
    fn register_request_body_orders_fields_and_omits_empty_hints() {
        // Full form: device + region present.
        let full = serde_json::to_string(&RegisterRequest {
            alice_address: ADDR,
            stake_ref: "enroll:x",
            device: "cuda",
            region: "us",
            nonce: "n-1",
            signature_b64: "c2ln",
        })
        .unwrap();
        assert_eq!(
            full,
            format!(
                "{{\"alice_address\":\"{ADDR}\",\"stake_ref\":\"enroll:x\",\"device\":\"cuda\",\"region\":\"us\",\"nonce\":\"n-1\",\"signature_b64\":\"c2ln\"}}"
            )
        );
        // Empty device + region are OMITTED (minimal wire shape).
        let minimal = serde_json::to_string(&RegisterRequest {
            alice_address: ADDR,
            stake_ref: "enroll:x",
            device: "",
            region: "",
            nonce: "n-1",
            signature_b64: "c2ln",
        })
        .unwrap();
        assert!(!minimal.contains("device"), "empty device omitted: {minimal}");
        assert!(!minimal.contains("region"), "empty region omitted: {minimal}");
    }

    #[test]
    fn lease_request_body_shape() {
        let json = serde_json::to_string(&LeaseRequest {
            alice_address: ADDR,
            nonce: "n",
            signature_b64: "s",
        })
        .unwrap();
        assert_eq!(
            json,
            format!("{{\"alice_address\":\"{ADDR}\",\"nonce\":\"n\",\"signature_b64\":\"s\"}}")
        );
    }

    #[test]
    fn submit_request_body_carries_lease_and_omits_optional() {
        // With a claimed rate + device key.
        let with_opt = serde_json::to_string(&SubmitRequest {
            lease_id: "L1",
            alice_address: ADDR,
            candidate_code: "def f():\n    return 1\n",
            claimed_pass_rate: Some("1.0"),
            device_key: "dev-0",
            nonce: "n",
            signature_b64: "s",
        })
        .unwrap();
        assert!(with_opt.contains("\"lease_id\":\"L1\""));
        assert!(with_opt.contains("\"claimed_pass_rate\":\"1.0\""));
        assert!(with_opt.contains("\"device_key\":\"dev-0\""));
        // Without the optional fields → both omitted (minimal shape).
        let minimal = serde_json::to_string(&SubmitRequest {
            lease_id: "L1",
            alice_address: ADDR,
            candidate_code: "x",
            claimed_pass_rate: None,
            device_key: "",
            nonce: "n",
            signature_b64: "s",
        })
        .unwrap();
        assert!(!minimal.contains("claimed_pass_rate"), "None claimed rate omitted: {minimal}");
        assert!(!minimal.contains("device_key"), "empty device_key omitted: {minimal}");
    }

    // ── response parsing ──────────────────────────────────────────────────────

    #[test]
    fn nonce_response_prefers_train_nonce_then_falls_back() {
        let r: NonceResponse =
            serde_json::from_str(r#"{"train_nonce":"abc","nonce":"legacy"}"#).unwrap();
        assert_eq!(r.train_nonce.or(r.nonce).unwrap(), "abc");
        let legacy: NonceResponse = serde_json::from_str(r#"{"nonce":"legacy"}"#).unwrap();
        assert_eq!(legacy.train_nonce.or(legacy.nonce).unwrap(), "legacy");
    }

    #[test]
    fn parse_lease_leased_carries_task_fields() {
        // The exact wire shape: the credit-only envelope + the flattened public_lease_view.
        let raw = r#"{
            "contract_version":"alice_train_coordinator_v1",
            "live_reward_enabled":false,"payout_executor_enabled":false,"paid_acu":"0",
            "ok":true,"reason_code":"train_task_leased",
            "lease_id":"deadbeefcafef00d","expires_at":"2026-07-02T20:00:00+00:00",
            "task_id":"m0-001","entry_point":"run_length_encode",
            "prompt":"Write a Python function run_length_encode(s: str) -> str ...",
            "held_out_commitment":"sha256:abc123"
        }"#;
        let resp: LeaseResponse = serde_json::from_str(raw).unwrap();
        match parse_lease(resp).unwrap() {
            LeaseOutcome::Leased(t) => {
                assert_eq!(t.task_id, "m0-001");
                assert_eq!(t.entry_point, "run_length_encode");
                assert_eq!(t.lease_id, "deadbeefcafef00d");
                assert_eq!(t.held_out_commitment, "sha256:abc123");
                assert!(t.prompt.starts_with("Write a Python function"));
                // The hidden tests are NEVER present — assert the wire never carried them.
                assert!(!raw.contains("\"tests\""), "the lease wire must not carry hidden tests");
            }
            other => panic!("expected leased, got {other:?}"),
        }
    }

    #[test]
    fn parse_lease_no_task_is_keep_polling() {
        let resp: LeaseResponse = serde_json::from_str(
            r#"{"ok":false,"reason_code":"train_no_task_available","paid_acu":"0"}"#,
        )
        .unwrap();
        assert_eq!(parse_lease(resp).unwrap(), LeaseOutcome::NoTask);
    }

    #[test]
    fn parse_lease_not_registered_is_an_error() {
        // An unregistered caller must surface as an Err so the loop re-registers.
        let resp: LeaseResponse = serde_json::from_str(
            r#"{"ok":false,"reason_code":"train_worker_not_registered","paid_acu":"0"}"#,
        )
        .unwrap();
        let e = parse_lease(resp).unwrap_err();
        assert!(e.contains("not_registered"), "surfaces the reason: {e}");
    }

    #[test]
    fn parse_lease_leased_without_lease_id_is_an_error() {
        let resp: LeaseResponse =
            serde_json::from_str(r#"{"ok":true,"task_id":"m0-001","prompt":"p"}"#).unwrap();
        assert!(parse_lease(resp).is_err(), "ok:true with no lease_id is a protocol error");
    }

    #[test]
    fn parse_submit_verified_carries_verdict_and_credit() {
        let raw = r#"{
            "contract_version":"alice_train_coordinator_v1",
            "live_reward_enabled":false,"payout_executor_enabled":false,"paid_acu":"0",
            "ok":true,"reason_code":"train_submission_verified","task_id":"m0-001",
            "verdict":"verified","verified_reward":"1","max_verifiable_reward":"1",
            "match_rate":"1","quorum_k":1,"quorum_agree":1,
            "credited":true,"credit":{"a2addr|train":"1"},
            "train_as_gpu_source_enabled":true
        }"#;
        let resp: SubmitResponse = serde_json::from_str(raw).unwrap();
        let v = parse_submit(resp).unwrap();
        assert!(v.is_verified());
        assert_eq!(v.task_id, "m0-001");
        assert_eq!(v.reason_code, "train_submission_verified");
        assert_eq!(v.match_rate.as_deref(), Some("1"));
        assert_eq!(v.quorum_k, Some(1));
        assert_eq!(v.quorum_agree, Some(1));
        assert!(v.credited);
    }

    #[test]
    fn parse_submit_not_verified_is_honest() {
        let raw = r#"{
            "paid_acu":"0","ok":false,"reason_code":"train_submission_not_verified",
            "task_id":"m0-002","verdict":"not_verified","match_rate":"0.4",
            "quorum_k":1,"quorum_agree":1,"credited":false
        }"#;
        let resp: SubmitResponse = serde_json::from_str(raw).unwrap();
        let v = parse_submit(resp).unwrap();
        assert!(!v.is_verified());
        assert_eq!(v.verdict, "not_verified");
        assert_eq!(v.match_rate.as_deref(), Some("0.4"));
        assert!(!v.credited);
    }

    #[test]
    fn parse_submit_rejects_nonzero_paid_acu() {
        // CREDIT-ONLY invariant: a non-"0" paid_acu is a protocol violation, refused.
        let raw = r#"{"paid_acu":"5","verdict":"verified","task_id":"x","credited":true}"#;
        let resp: SubmitResponse = serde_json::from_str(raw).unwrap();
        let e = parse_submit(resp).unwrap_err();
        assert!(e.contains("paid_acu"), "refuses a non-zero paid_acu: {e}");
    }
}
