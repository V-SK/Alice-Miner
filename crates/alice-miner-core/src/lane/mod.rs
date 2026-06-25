//! `core/lane` — the per-lane launch-plan builders. M1 ships only the CPU-XMR
//! lane ([`xmr`]); the GPU-RVN (KawPoW) lane is M3. Each lane owns its own
//! verbatim-ported argv builder, address validation, and (later) log parsers.

pub mod gpu_prl;
pub mod gpu_rvn;
pub mod xmr;

/// Which mining lane a [`crate::engine::Command::Start`] selects. CPU→XMR (the
/// proven path), NVIDIA/AMD-GPU→PRL (SRBMiner pearlhash, the **GPU mainline** — PoP
/// + region relay :3340), and GPU→RVN (KawPoW, the earlier relay path, kept).
/// `Ord`/`Hash` are derived so the lane can key the viability matrix's `BTreeMap`
/// (see [`crate::detect::capability`]).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Lane {
    /// CPU RandomX/XMR against `hk.aliceprotocol.org:3333` (the proven path).
    Xmr,
    /// GPU pearlhash/PRL against the region relays `:3340` with mandatory M4 PoP —
    /// the GPU **mainline** (V: "GPU 主线 = PRL,展示不隐藏").
    GpuPrl,
    /// NVIDIA-GPU KawPoW/RVN against `hk.aliceprotocol.org:8888` (the earlier path).
    GpuRvn,
}

impl Lane {
    pub fn label(self) -> &'static str {
        match self {
            Lane::Xmr => "CPU · XMR",
            Lane::GpuPrl => "GPU · PRL",
            Lane::GpuRvn => "GPU · RVN",
        }
    }

    /// Lower-case lane id used on the CLI and in `Snapshot` JSON.
    pub fn id(self) -> &'static str {
        match self {
            Lane::Xmr => "xmr",
            Lane::GpuPrl => "prl",
            Lane::GpuRvn => "gpu",
        }
    }
}
