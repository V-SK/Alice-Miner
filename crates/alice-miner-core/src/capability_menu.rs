//! Anonymous **participation-menu** client (the `alice-miner ai --menu` wizard).
//!
//! Before a miner picks a way to contribute GPU/CPU to the Alice network, it asks
//! the acp scheduling center ONE anonymous question: *given this hardware, what can
//! this machine do?* The center answers with a three-mode menu — single-GPU
//! **serve**, fleet **shard**, and RLVR **train** — tailored to the advertised
//! runtime + free VRAM. This module is the headless PROTOCOL core for that one
//! call: the request body from a hardware probe, the typed response, and the
//! single https POST. No UI, no subprocess, no key — the endpoint is anonymous
//! (no PoP), so unlike [`crate::shard`] this carries no signing bytes.
//!
//! ── Server source of truth (matched against the live implementation) ─────────
//!   * Route: `POST <base>/v1/worker/menu` (the acp gateway; anonymous).
//!   * Contract tag: `api-chat-worker-pull-http-contract-v1` (surfaced in the
//!     response's `contract_version`; informational — we never gate on it).
//!   * Request: `{runtime, per_gpu_free_vram_gb (PER-GPU, not total), gpu_count,
//!     gpu_model}`. `runtime` is one of `mlx` | `cuda` | `gguf` | `cpu`.
//!   * Response: `worker.capability_menu` with `profile` (the server's echo of the
//!     detected class), `serve` / `shard` / `train` sections, and the credit-only
//!     envelope (`credit_only`, `live_reward_enabled`, `payout_executor_enabled`,
//!     `paid_acu`).
//!
//! ── CREDIT-ONLY ─────────────────────────────────────────────────────────────
//! The response's `paid_acu` is always `"0"` and the reward flags are all `false`;
//! this client only READS the menu (never a reward) and the wizard NEVER prints or
//! implies an earning. The parse is deliberately TOLERANT — every optional field is
//! `Option<T>` with `#[serde(default)]` and unknown fields are ignored — so a purely
//! additive server change (a new tier, a new rung field) never breaks an older client.

use std::io::Read as _;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Connect + read timeout for the menu call (~10s, matching [`crate::shard`] and
/// `pop.rs` — a slow/hostile server can never stall the wizard).
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound on the menu response body. The real menu is a few KiB (four
/// sections, a handful of tiers/rungs); 64 KiB is generous yet caps a
/// hostile/runaway response — the SAME cap [`crate::shard`] uses.
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

// ── request ─────────────────────────────────────────────────────────────────

/// The anonymous menu request: the hardware profile the center tailors the menu
/// to. `per_gpu_free_vram_gb` is PER-GPU (a single card's free VRAM), NOT the
/// fleet total — the server pools the total itself from `gpu_count`. Built purely
/// from a device probe by [`menu_request_from_detect`]; carries NO identity and NO
/// secret (the endpoint is anonymous).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MenuRequest {
    /// The serving runtime this host can offer: `mlx` (Apple), `cuda` (NVIDIA),
    /// `gguf` (llama.cpp-class, e.g. AMD in v1), or `cpu`.
    pub runtime: String,
    /// Free VRAM of a SINGLE card in whole GB (per-GPU, not summed). `0` when it
    /// can't be probed (honest — the server answers accordingly rather than being
    /// misled by a fabricated figure).
    pub per_gpu_free_vram_gb: u64,
    /// Number of same-runtime cards (≥ 1; only `0` is meaningful for `cpu`).
    pub gpu_count: u32,
    /// The GPU (or CPU) model string, possibly empty.
    pub gpu_model: String,
}

// ── response ────────────────────────────────────────────────────────────────

/// The server's echo of the class it derived from the request — surfaced so the
/// wizard can show what the center actually saw (rather than only what the client
/// sent). Every field is optional/defaulted so a trimmed echo still parses.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MenuProfileEcho {
    #[serde(default)]
    pub runtime: String,
    /// The vendor class the server bucketed the host into (e.g. `nvidia`, `apple`).
    #[serde(default)]
    pub gpu_class: String,
    #[serde(default)]
    pub gpu_count: u32,
    #[serde(default)]
    pub per_gpu_free_vram_gb: u64,
    /// The center's pooled figure (`per_gpu × count`) — informational.
    #[serde(default)]
    pub total_free_vram_gb: u64,
    #[serde(default)]
    pub gpu_model: String,
}

/// One offered single-GPU serving tier. `offered_now` is the load-bearing flag:
/// a tier is DISPLAYED whenever it fits the card, but only an `offered_now` tier
/// is dispatchable (would actually receive jobs) — the wizard makes only those
/// selectable and labels the rest "defined, not yet dispatched".
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServeOption {
    /// The stable class id (e.g. `alice_standard_9b`) — what we persist as the tier.
    #[serde(default)]
    pub model_class: String,
    /// The human name shown in the menu (e.g. `Alice`, `Alice Lite`).
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub family: String,
    #[serde(default)]
    pub parameter_billions: u32,
    #[serde(default)]
    pub max_context_tokens: u32,
    #[serde(default)]
    pub runtime: String,
    /// Quantization label (e.g. `q4_k_m`).
    #[serde(default)]
    pub quant: String,
    /// The free-VRAM floor (GB) this tier needs.
    #[serde(default)]
    pub min_free_vram_gb: u64,
    /// The HF repo the artifact is pulled from.
    #[serde(default)]
    pub repo_id: String,
    /// The pinned revision (a 40-hex commit) — reproducible fetch.
    #[serde(default)]
    pub revision: String,
    /// The file within the repo (e.g. the `.gguf` name).
    #[serde(default)]
    pub artifact_subpath: String,
    /// Estimated download size in GB. `Option` because a tier may omit it.
    #[serde(default)]
    pub est_download_gb: Option<f64>,
    /// `true` when `est_download_gb` is an estimate (footnoted in the UI).
    #[serde(default)]
    pub download_size_is_estimate: bool,
    /// Whether this tier is dispatchable right now. When `false` the tier is shown
    /// but NOT selectable (it would never receive a job yet — honest).
    #[serde(default)]
    pub offered_now: bool,
}

/// The single-GPU serving section. `eligible` gates the whole section: when
/// `false` the `options` list is empty, `selected_tier` is `None`, and
/// `reason_code` (+ optional `detail`) explains why honestly.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServeSection {
    #[serde(default)]
    pub mode: String,
    /// Whether ANY serving tier fits this host's runtime + free VRAM.
    #[serde(default)]
    pub eligible: bool,
    #[serde(default)]
    pub runtime: String,
    /// The tier the server would pick by default (largest that fits), if any.
    #[serde(default)]
    pub selected_tier: Option<String>,
    /// Every tier the host COULD serve (both dispatchable and not-yet-dispatched).
    #[serde(default)]
    pub options: Vec<ServeOption>,
    /// A stable machine reason (e.g. `menu_serve_tiers_available`,
    /// `menu_serve_no_tier_fits`, `menu_serve_runtime_not_dispatchable`).
    #[serde(default)]
    pub reason_code: String,
    /// A human detail string on the not-eligible paths (e.g. why a cpu host can't
    /// serve). Absent when eligible.
    #[serde(default)]
    pub detail: Option<String>,
}

/// One fleet-shard rung (a big model the swarm pools VRAM across). A single card
/// can contribute ONE stage of a rung without clearing the aggregate floor alone —
/// so a rung is listed even when `aggregate_fits_solo` is `false`. `status`
/// (`coming` in v1) tags each rung's readiness.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ShardRung {
    #[serde(default)]
    pub rung_id: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub parameter_billions: u32,
    /// The pooled VRAM floor (GB) the whole rung needs across the swarm.
    #[serde(default)]
    pub min_aggregate_vram_gb: u64,
    /// Whether the rung requires a multi-node fleet (a single card is never enough).
    #[serde(default)]
    pub needs_fleet: bool,
    /// Whether the rung is currently backed by a formed swarm.
    #[serde(default)]
    pub backed: bool,
    /// The rung's readiness tag (e.g. `coming`, `live`).
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub repo_id: String,
    #[serde(default)]
    pub revision: String,
    /// Whether THIS host's aggregate VRAM alone clears the rung floor (rare).
    #[serde(default)]
    pub aggregate_fits_solo: bool,
}

/// The fleet-shard section: the rung ladder + this host's aggregate VRAM figure
/// and the explanatory note the wizard translates.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ShardSection {
    #[serde(default)]
    pub mode: String,
    /// This host's aggregate (pooled-across-its-own-cards) free VRAM in GB.
    #[serde(default)]
    pub your_aggregate_free_vram_gb: u64,
    #[serde(default)]
    pub rungs: Vec<ShardRung>,
    /// The server's note about how fleet pooling works (translated conceptually in
    /// the wizard rather than echoed verbatim).
    #[serde(default)]
    pub note: Option<String>,
}

/// The RLVR-training section. `gate_passed` is the hard hardware gate (NVIDIA/CUDA
/// present); `meets_recommended` is ADVISORY only (`recommendation_is_advisory`) —
/// a host below the recommended per-GPU VRAM can still generate, just slower.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TrainSection {
    #[serde(default)]
    pub mode: String,
    /// The name of the hard gate (e.g. `nvidia_cuda_present`).
    #[serde(default)]
    pub hardware_gate: String,
    /// Whether the hard gate passed (no NVIDIA/CUDA → `false`, train unavailable).
    #[serde(default)]
    pub gate_passed: bool,
    /// The advisory per-GPU VRAM the coordinator recommends (GB).
    #[serde(default)]
    pub recommended_min_per_gpu_vram_gb: u64,
    /// Whether this host meets the advisory figure.
    #[serde(default)]
    pub meets_recommended: bool,
    /// Whether the recommendation is advisory (not enforced). Always `true` in v1;
    /// kept as a field so a future hard gate is representable.
    #[serde(default)]
    pub recommendation_is_advisory: bool,
    #[serde(default)]
    pub base_model_parameter_billions: u32,
    /// The generation role's quantization (e.g. `4-bit QLoRA generation role`).
    #[serde(default)]
    pub quantization: String,
}

/// The full three-mode participation menu the center returns. Every section is
/// optional/defaulted so a partial server response (or an older server that omits
/// a whole section) still parses into a usable menu.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CapabilityMenu {
    /// The object tag (`worker.capability_menu`) — informational.
    #[serde(default)]
    pub object: String,
    /// The contract version tag — informational; we never gate on it.
    #[serde(default)]
    pub contract_version: String,
    /// The server's echo of the class it derived from the request.
    #[serde(default)]
    pub profile: MenuProfileEcho,
    #[serde(default)]
    pub serve: ServeSection,
    #[serde(default)]
    pub shard: ShardSection,
    #[serde(default)]
    pub train: TrainSection,
    // ── credit-only envelope (mirrors the rest of the acp control plane) ──
    /// Always `true` — the whole surface is credit-only.
    #[serde(default)]
    pub credit_only: bool,
    /// Always `false` in the current phase (no live reward).
    #[serde(default)]
    pub live_reward_enabled: bool,
    /// Always `false` in the current phase (no payout executor).
    #[serde(default)]
    pub payout_executor_enabled: bool,
    /// Always `"0"` — never a paid figure.
    #[serde(default)]
    pub paid_acu: String,
}

// ── https POST ──────────────────────────────────────────────────────────────

/// Reject any non-`https://` URL — fail closed. Same message style as
/// [`crate::shard`]'s `require_https` (the wizard reuses this shape).
fn require_https(url: &str) -> Result<(), String> {
    if url.starts_with("https://") {
        Ok(())
    } else {
        Err(format!("refusing non-https center url: {url}"))
    }
}

/// Build `<base>/v1/worker/menu`, trimming a single trailing `/` off the base so
/// both `https://host` and `https://host/` yield the same URL. https-checked
/// (identical join discipline to [`crate::shard::stage_route`]).
fn menu_route(center_url: &str) -> Result<String, String> {
    require_https(center_url)?;
    let base = center_url.strip_suffix('/').unwrap_or(center_url);
    let url = format!("{base}/v1/worker/menu");
    require_https(&url)?;
    Ok(url)
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(HTTP_TIMEOUT)
        .timeout_read(HTTP_TIMEOUT)
        .user_agent(concat!("alice-miner-ai/", env!("CARGO_PKG_VERSION")))
        .build()
}

/// POST the menu request as compact JSON and parse the (capped) response. https-only
/// (fail closed before any network). A non-2xx surfaces as an `Err` carrying the
/// status + (capped) body so the miner sees the server's stable reason/message
/// rather than a bare code. Mirrors [`crate::shard`]'s `post_json` exactly (the
/// workspace ureq is built `default-features=false`, so we serialize ourselves +
/// `send_string` with an explicit content-type — `send_json` is unavailable).
pub fn fetch_menu(center_url: &str, req: &MenuRequest) -> Result<CapabilityMenu, String> {
    let url = menu_route(center_url)?;
    let payload = serde_json::to_string(req).map_err(|e| format!("serialize: {e}"))?;
    let resp = match agent()
        .post(&url)
        .set("Content-Type", "application/json")
        .send_string(&payload)
    {
        Ok(r) => r,
        // ureq surfaces a non-2xx as `Error::Status`; read its (capped) body so the
        // server's stable error message/reason_code reaches the miner — a 400 here is
        // `{"error":{...,"message":...},"metadata":{...}}`.
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

// ── request from a device probe (PURE + unit-tested) ─────────────────────────

/// Map a [`crate::detect::DeviceProfile`] (+ an optional NVIDIA free-VRAM hint) to
/// the anonymous [`MenuRequest`] the center tailors the menu to. PURE (no I/O) so
/// the mapping is unit-tested exhaustively; the caller does the probing and passes
/// `nvidia_free_vram_gb` (the largest-single-card FREE figure from
/// `ai::detect_free_vram_gb`, or `None` when undetectable).
///
/// The runtime + per-GPU VRAM rules, per vendor:
///   * **Apple Silicon** → `mlx`, `gpu_count = 1`, `per_gpu_free_vram_gb =
///     memory_gb / 2`. Apple's GPU shares unified memory, so there is no dedicated
///     VRAM figure; we advertise a CONSERVATIVE half of physical RAM as the usable
///     GPU budget — mirroring the acp worker probe's `0.5 × physical` floor (leaving
///     headroom for the OS + the model's non-weight allocations). `gpu_model` is the
///     GPU label, falling back to the CPU model when the GPU label is empty.
///   * **NVIDIA** → `cuda`, `gpu_count = number of enumerated cards (≥ 1)`,
///     `per_gpu_free_vram_gb = floor(nvidia_free_vram_gb)` — the caller's
///     largest-single-card FREE figure, floored to whole GB; `0` when undetectable
///     (honest — the server answers with the no-fit / not-dispatchable path rather
///     than being misled). `gpu_model` is the card name.
///   * **AMD** → `gguf`, `gpu_count = 1`, `per_gpu_free_vram_gb = 0`. v1 has no AMD
///     VRAM probe, so we advertise an honest `0` (the server then serves whatever a
///     0-VRAM gguf host can) rather than guessing. `gpu_model` is the card name.
///   * **no GPU** → `cpu`, `gpu_count = 1`, `per_gpu_free_vram_gb = 0`, `gpu_model`
///     the CPU model. The server's serve section then reports the cpu
///     not-dispatchable reason honestly.
pub fn menu_request_from_detect(
    profile: &crate::detect::DeviceProfile,
    nvidia_free_vram_gb: Option<f64>,
) -> MenuRequest {
    use crate::detect::GpuVendor;

    // Apple Silicon takes precedence over the GPU-vendor match: its GPU is
    // classified `Apple` (unified memory), and the mlx runtime is the Apple path.
    if profile.apple_silicon {
        let gpu_model = if profile.gpu.model.is_empty() {
            profile.cpu_model.clone()
        } else {
            profile.gpu.model.clone()
        };
        return MenuRequest {
            runtime: "mlx".to_string(),
            // Conservative unified-memory heuristic: half of physical RAM is the
            // usable GPU budget (mirrors the acp worker probe's 0.5×physical floor).
            per_gpu_free_vram_gb: (profile.memory_gb / 2) as u64,
            gpu_count: 1,
            gpu_model,
        };
    }

    match profile.gpu.vendor {
        GpuVendor::Nvidia => MenuRequest {
            runtime: "cuda".to_string(),
            per_gpu_free_vram_gb: nvidia_free_vram_gb.map(|v| v.floor() as u64).unwrap_or(0),
            gpu_count: (profile.gpu.gpus.len().max(1)) as u32,
            gpu_model: profile.gpu.model.clone(),
        },
        GpuVendor::Amd => MenuRequest {
            runtime: "gguf".to_string(),
            // v1 has no AMD VRAM probe — advertise an honest 0 rather than a guess.
            per_gpu_free_vram_gb: 0,
            gpu_count: 1,
            gpu_model: profile.gpu.model.clone(),
        },
        // `Apple` here is only reachable on a non-`apple_silicon` box (it isn't in
        // practice), and `None` is the CPU-only case; both map to the honest cpu path.
        GpuVendor::Apple | GpuVendor::None => MenuRequest {
            runtime: "cpu".to_string(),
            per_gpu_free_vram_gb: 0,
            gpu_count: 1,
            gpu_model: profile.cpu_model.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{DeviceProfile, GpuDevice, GpuInfo, GpuVendor, OsFamily};

    /// Build a `DeviceProfile` directly (bypassing the real probe) so the pure
    /// mapping is exercised for every vendor path without shelling out.
    fn profile(
        apple_silicon: bool,
        vendor: GpuVendor,
        gpu_model: &str,
        gpus: Vec<GpuDevice>,
        cpu_model: &str,
        memory_gb: u32,
    ) -> DeviceProfile {
        DeviceProfile {
            os: if apple_silicon {
                OsFamily::Macos
            } else {
                OsFamily::Linux
            },
            arch: "x86_64".to_string(),
            apple_silicon,
            logical_cores: 8,
            cpu_model: cpu_model.to_string(),
            gpu: GpuInfo {
                vendor,
                model: gpu_model.to_string(),
                vram_gb: 0,
                gpus,
                max_compute_cap_x10: None,
            },
            memory_gb,
            display: "test".to_string(),
            warnings: Vec::new(),
        }
    }

    fn gpu_dev(index: u32) -> GpuDevice {
        GpuDevice {
            index,
            name: "NVIDIA GeForce RTX 4090".to_string(),
            vram_gb: 24,
            uuid: format!("GPU-{index}"),
        }
    }

    #[test]
    fn menu_request_apple_silicon_maps_to_mlx_half_ram() {
        // Apple Silicon: mlx, one "card", half of physical RAM as the budget, the
        // GPU label as the model.
        let p = profile(true, GpuVendor::Apple, "Apple M2 Max", vec![], "Apple M2 Max", 96);
        let req = menu_request_from_detect(&p, None);
        assert_eq!(req.runtime, "mlx");
        assert_eq!(req.gpu_count, 1);
        assert_eq!(req.per_gpu_free_vram_gb, 48); // 96 / 2
        assert_eq!(req.gpu_model, "Apple M2 Max");
    }

    #[test]
    fn menu_request_apple_silicon_falls_back_to_cpu_model_when_gpu_label_empty() {
        // Empty GPU label → the CPU model string is used instead (never empty).
        let p = profile(true, GpuVendor::Apple, "", vec![], "Apple M3 Pro", 36);
        let req = menu_request_from_detect(&p, None);
        assert_eq!(req.runtime, "mlx");
        assert_eq!(req.per_gpu_free_vram_gb, 18); // 36 / 2
        assert_eq!(req.gpu_model, "Apple M3 Pro");
    }

    #[test]
    fn menu_request_nvidia_maps_to_cuda_floored_free_vram_and_card_count() {
        // Two cards, a fractional free-VRAM hint → cuda, gpu_count=2, floored VRAM.
        let p = profile(
            false,
            GpuVendor::Nvidia,
            "NVIDIA GeForce RTX 4090",
            vec![gpu_dev(0), gpu_dev(1)],
            "AMD Ryzen 9",
            64,
        );
        let req = menu_request_from_detect(&p, Some(15.87));
        assert_eq!(req.runtime, "cuda");
        assert_eq!(req.gpu_count, 2);
        assert_eq!(req.per_gpu_free_vram_gb, 15); // floor(15.87)
        assert_eq!(req.gpu_model, "NVIDIA GeForce RTX 4090");
    }

    #[test]
    fn menu_request_nvidia_undetectable_vram_is_honest_zero_and_count_floors_at_one() {
        // No free-VRAM hint AND an empty enumeration → honest 0 VRAM, count floors
        // to 1 (the summary said NVIDIA even if per-card enumeration failed).
        let p = profile(
            false,
            GpuVendor::Nvidia,
            "NVIDIA GeForce RTX 4060 Ti",
            vec![],
            "Intel Core i7",
            32,
        );
        let req = menu_request_from_detect(&p, None);
        assert_eq!(req.runtime, "cuda");
        assert_eq!(req.gpu_count, 1);
        assert_eq!(req.per_gpu_free_vram_gb, 0);
        assert_eq!(req.gpu_model, "NVIDIA GeForce RTX 4060 Ti");
    }

    #[test]
    fn menu_request_amd_maps_to_gguf_zero_vram() {
        let p = profile(false, GpuVendor::Amd, "AMD GPU", vec![], "AMD Ryzen 7", 32);
        let req = menu_request_from_detect(&p, None);
        assert_eq!(req.runtime, "gguf");
        assert_eq!(req.gpu_count, 1);
        assert_eq!(req.per_gpu_free_vram_gb, 0);
        assert_eq!(req.gpu_model, "AMD GPU");
    }

    #[test]
    fn menu_request_no_gpu_maps_to_cpu() {
        let p = profile(false, GpuVendor::None, "", vec![], "Intel Xeon", 16);
        let req = menu_request_from_detect(&p, None);
        assert_eq!(req.runtime, "cpu");
        assert_eq!(req.gpu_count, 1);
        assert_eq!(req.per_gpu_free_vram_gb, 0);
        assert_eq!(req.gpu_model, "Intel Xeon");
    }

    // ── request body wire shape (the four documented fields, compact) ─────────

    #[test]
    fn menu_request_serializes_to_the_four_contract_fields() {
        let req = MenuRequest {
            runtime: "cuda".into(),
            per_gpu_free_vram_gb: 16,
            gpu_count: 1,
            gpu_model: "RTX 4060 Ti".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(
            json,
            r#"{"runtime":"cuda","per_gpu_free_vram_gb":16,"gpu_count":1,"gpu_model":"RTX 4060 Ti"}"#
        );
    }

    // ── the full real response fixture round-trips ────────────────────────────

    /// The EXACT live-captured cuda-16GB response (revisions elided to 40-hex
    /// placeholders where the source used `<40-hex>`), with the shard section's
    /// remaining three rungs filled in so the ladder is realistic. Parsing this
    /// asserts the tolerant serde model matches the server byte-for-byte.
    const REAL_MENU_JSON: &str = r#"{
      "object": "worker.capability_menu",
      "contract_version": "api-chat-worker-pull-http-contract-v1",
      "profile": {
        "runtime": "cuda", "gpu_class": "nvidia", "gpu_count": 1,
        "per_gpu_free_vram_gb": 16, "total_free_vram_gb": 16, "gpu_model": "RTX 4060 Ti"
      },
      "serve": {
        "mode": "serve_single_gpu", "eligible": true, "runtime": "cuda",
        "selected_tier": "alice_standard_9b",
        "options": [
          {
            "model_class": "alice_standard_9b", "display_name": "Alice", "family": "general",
            "parameter_billions": 9, "max_context_tokens": 32768, "runtime": "cuda",
            "quant": "q4_k_m", "min_free_vram_gb": 8,
            "repo_id": "v102ss/Alice-Qwen3.5-9B-Code-v0-GGUF",
            "revision": "0123456789abcdef0123456789abcdef01234567",
            "artifact_subpath": "Alice-Qwen3.5-9B-Code-v0-Q4_K_M.gguf",
            "est_download_gb": 5.7, "download_size_is_estimate": true, "offered_now": false
          },
          {
            "model_class": "alice_lite_4b", "display_name": "Alice Lite", "family": "general",
            "parameter_billions": 4, "max_context_tokens": 32768, "runtime": "cuda",
            "quant": "q4_k_m", "min_free_vram_gb": 5,
            "repo_id": "v102ss/Alice-Qwen3-4B-Instruct-2507-Heretic-Light-GGUF",
            "revision": "aa4bf90e83b7acb4fb78881186e7bd623bfc004b",
            "artifact_subpath": "Alice-Qwen3-4B-Instruct-2507-Heretic-Light-Q4_K_M.gguf",
            "est_download_gb": 2.5, "download_size_is_estimate": true, "offered_now": true
          }
        ],
        "reason_code": "menu_serve_tiers_available"
      },
      "shard": {
        "mode": "shard_stage", "your_aggregate_free_vram_gb": 16,
        "rungs": [
          {
            "rung_id": "ladder_122b", "display_name": "Alice Max", "parameter_billions": 122,
            "min_aggregate_vram_gb": 96, "needs_fleet": true, "backed": false, "status": "coming",
            "repo_id": "zai-org/GLM-4.5-Air",
            "revision": "0123456789abcdef0123456789abcdef01234567", "aggregate_fits_solo": false
          },
          {
            "rung_id": "ladder_235b", "display_name": "Alice Max+", "parameter_billions": 235,
            "min_aggregate_vram_gb": 160, "needs_fleet": true, "backed": false, "status": "coming",
            "repo_id": "example/235b",
            "revision": "0123456789abcdef0123456789abcdef01234567", "aggregate_fits_solo": false
          },
          {
            "rung_id": "ladder_671b", "display_name": "Alice Ultra", "parameter_billions": 671,
            "min_aggregate_vram_gb": 480, "needs_fleet": true, "backed": false, "status": "coming",
            "repo_id": "deepseek-ai/DeepSeek-V3",
            "revision": "0123456789abcdef0123456789abcdef01234567", "aggregate_fits_solo": false
          },
          {
            "rung_id": "ladder_744b", "display_name": "Alice Flagship", "parameter_billions": 744,
            "min_aggregate_vram_gb": 560, "needs_fleet": true, "backed": false, "status": "coming",
            "repo_id": "example/glm-5",
            "revision": "0123456789abcdef0123456789abcdef01234567", "aggregate_fits_solo": false
          }
        ],
        "note": "fleet rungs pool same-runtime VRAM across the swarm; a single card can contribute one stage without clearing the aggregate floor alone"
      },
      "train": {
        "mode": "train_rlvr_generation", "hardware_gate": "nvidia_cuda_present",
        "gate_passed": true, "recommended_min_per_gpu_vram_gb": 24, "meets_recommended": false,
        "recommendation_is_advisory": true, "base_model_parameter_billions": 30,
        "quantization": "4-bit QLoRA generation role"
      },
      "credit_only": true, "live_reward_enabled": false,
      "payout_executor_enabled": false, "paid_acu": "0"
    }"#;

    #[test]
    fn full_real_response_round_trips() {
        let menu: CapabilityMenu = serde_json::from_str(REAL_MENU_JSON).expect("parse real menu");
        assert_eq!(menu.object, "worker.capability_menu");
        assert_eq!(
            menu.contract_version,
            "api-chat-worker-pull-http-contract-v1"
        );

        // profile echo
        assert_eq!(menu.profile.gpu_class, "nvidia");
        assert_eq!(menu.profile.total_free_vram_gb, 16);

        // serve section: eligible, two tiers, the selected default, offered_now flags.
        assert!(menu.serve.eligible);
        assert_eq!(menu.serve.selected_tier.as_deref(), Some("alice_standard_9b"));
        assert_eq!(menu.serve.reason_code, "menu_serve_tiers_available");
        assert_eq!(menu.serve.options.len(), 2);
        let standard = &menu.serve.options[0];
        assert_eq!(standard.model_class, "alice_standard_9b");
        assert_eq!(standard.parameter_billions, 9);
        assert_eq!(standard.min_free_vram_gb, 8);
        assert_eq!(standard.est_download_gb, Some(5.7));
        assert!(standard.download_size_is_estimate);
        assert!(!standard.offered_now, "the 9B tier is defined but not yet dispatched");
        let lite = &menu.serve.options[1];
        assert_eq!(lite.model_class, "alice_lite_4b");
        assert_eq!(lite.est_download_gb, Some(2.5));
        assert!(lite.offered_now, "the 4B tier is dispatchable now");
        assert_eq!(
            lite.repo_id,
            "v102ss/Alice-Qwen3-4B-Instruct-2507-Heretic-Light-GGUF"
        );
        assert_eq!(lite.revision.len(), 40, "the pinned revision is a 40-hex commit");

        // shard section: four rungs, all `coming`, the aggregate figure + note.
        assert_eq!(menu.shard.your_aggregate_free_vram_gb, 16);
        assert_eq!(menu.shard.rungs.len(), 4);
        assert!(menu.shard.rungs.iter().all(|r| r.status == "coming"));
        assert!(menu.shard.rungs.iter().all(|r| r.needs_fleet && !r.backed));
        assert_eq!(menu.shard.rungs[0].display_name, "Alice Max");
        assert_eq!(menu.shard.rungs[0].parameter_billions, 122);
        assert_eq!(menu.shard.rungs[0].min_aggregate_vram_gb, 96);
        assert!(menu.shard.note.is_some());

        // train section: gate passed, advisory VRAM not met (but advisory).
        assert!(menu.train.gate_passed);
        assert_eq!(menu.train.hardware_gate, "nvidia_cuda_present");
        assert_eq!(menu.train.recommended_min_per_gpu_vram_gb, 24);
        assert!(!menu.train.meets_recommended);
        assert!(menu.train.recommendation_is_advisory);
        assert_eq!(menu.train.base_model_parameter_billions, 30);

        // credit-only envelope: honest, always zero.
        assert!(menu.credit_only);
        assert!(!menu.live_reward_enabled);
        assert!(!menu.payout_executor_enabled);
        assert_eq!(menu.paid_acu, "0");
    }

    #[test]
    fn not_eligible_serve_section_parses_with_reason_and_detail() {
        // A cpu host: serve not eligible, empty options, null selected_tier, a
        // reason_code + a human detail string.
        let raw = r#"{
          "mode": "serve_single_gpu", "eligible": false, "runtime": "cpu",
          "selected_tier": null, "options": [],
          "reason_code": "menu_serve_runtime_not_dispatchable",
          "detail": "cpu hosts cannot serve on the network yet"
        }"#;
        let serve: ServeSection = serde_json::from_str(raw).expect("parse not-eligible serve");
        assert!(!serve.eligible);
        assert!(serve.options.is_empty());
        assert!(serve.selected_tier.is_none());
        assert_eq!(serve.reason_code, "menu_serve_runtime_not_dispatchable");
        assert_eq!(
            serve.detail.as_deref(),
            Some("cpu hosts cannot serve on the network yet")
        );
    }

    #[test]
    fn unknown_fields_are_ignored_and_missing_sections_default() {
        // A trimmed response with an UNKNOWN top-level field and NO shard/train
        // sections still parses (serde ignores unknowns; the sections default).
        let raw = r#"{
          "object": "worker.capability_menu",
          "some_future_field": {"nested": [1,2,3]},
          "serve": {"mode": "serve_single_gpu", "eligible": false,
                    "reason_code": "menu_serve_no_tier_fits"}
        }"#;
        let menu: CapabilityMenu = serde_json::from_str(raw).expect("tolerant parse");
        assert_eq!(menu.serve.reason_code, "menu_serve_no_tier_fits");
        assert!(menu.serve.options.is_empty());
        // The absent sections default to empty (no rungs, gate not passed).
        assert!(menu.shard.rungs.is_empty());
        assert!(!menu.train.gate_passed);
    }

    // ── https-only fetch (no network) ─────────────────────────────────────────

    #[test]
    fn fetch_menu_rejects_non_https_without_any_network() {
        // An http:// center is refused BEFORE any socket is opened (fail closed).
        let req = MenuRequest {
            runtime: "cpu".into(),
            per_gpu_free_vram_gb: 0,
            gpu_count: 1,
            gpu_model: "test".into(),
        };
        let e = fetch_menu("http://insecure.example", &req).unwrap_err();
        assert!(e.contains("non-https"), "clear non-https error: {e}");
    }

    #[test]
    fn menu_route_appends_leaf_and_requires_https() {
        assert_eq!(
            menu_route("https://api.aliceprotocol.org").unwrap(),
            "https://api.aliceprotocol.org/v1/worker/menu"
        );
        // A trailing slash on the base is trimmed (no double slash).
        assert_eq!(
            menu_route("https://api.aliceprotocol.org/").unwrap(),
            "https://api.aliceprotocol.org/v1/worker/menu"
        );
        assert!(menu_route("http://insecure.example").is_err());
    }
}
