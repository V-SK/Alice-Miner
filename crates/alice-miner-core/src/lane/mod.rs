//! `core/lane` — the per-lane launch-plan builders. M1 ships only the CPU-XMR
//! lane ([`xmr`]); the GPU-RVN (KawPoW) lane is M3. Each lane owns its own
//! verbatim-ported argv builder, address validation, and (later) log parsers.

pub mod xmr;

/// Which mining lane a [`crate::engine::Command::Start`] selects. M1 supports
/// only [`Lane::Xmr`]; [`Lane::GpuRvn`] is reserved for M3 (declared here so the
/// `Command`/`Snapshot` shape is stable across the engine from M1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lane {
    /// CPU RandomX/XMR against `hk.aliceprotocol.org:3333` (the proven path).
    Xmr,
    /// NVIDIA-GPU KawPoW/RVN — reserved for M3 (not buildable in M1).
    GpuRvn,
}

impl Lane {
    pub fn label(self) -> &'static str {
        match self {
            Lane::Xmr => "CPU · XMR",
            Lane::GpuRvn => "GPU · RVN",
        }
    }

    /// Lower-case lane id used on the CLI and in `Snapshot` JSON.
    pub fn id(self) -> &'static str {
        match self {
            Lane::Xmr => "xmr",
            Lane::GpuRvn => "gpu",
        }
    }
}
