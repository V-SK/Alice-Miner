//! `core/stats` — per-lane log parsers that turn raw miner stdout into the
//! engine's secret-free numbers (hashrate in H/s + accepted/rejected shares).
//!
//! The XMR/RandomX parsers ([`crate::supervise::parse_hashrate_hs`] /
//! [`crate::supervise::parse_share_counts`]) are ported verbatim from the Wallet
//! and live with the supervisor. This module adds [`parse_kawpow`] for the
//! GPU-RVN (KawPoW) lane (M3), generalized from
//! `Alice-Protocol/miner/mining_internal/trex_logs.py` so it tolerates **both**
//! the bundled **kawpowminer** AND **T-Rex** log formats (the two miners the lane
//! can run — KawPowMiner is bundled; T-Rex is the `ALICE_MINER_GPU_BIN`
//! override).

pub mod parse_alpha;
pub mod parse_generic;
pub mod parse_kawpow;
pub mod parse_srbminer;

pub use parse_alpha::parse_alpha;
pub use parse_generic::parse_generic;
pub use parse_kawpow::{parse_kawpow, KawpowSample};
pub use parse_srbminer::parse_srbminer;

use crate::lane::Lane;

/// Which log parser the supervisor drives for a lane's child. Historically the
/// dispatch was keyed on [`Lane`], which is correct for a BUNDLED engine (one
/// engine per lane). A CUSTOM (bring-your-own) miner breaks that 1:1 mapping — a
/// user could run any of several miners on the PRL lane — so the supervisor keys
/// its parser on `ParserKind` instead, derived from the lane for a bundled engine
/// or from the miner's preset for a custom one.
///
/// [`ParserKind::Generic`] is the honest fallback for an UNKNOWN miner format: it
/// scans best-effort and, when it can't recognise a line, leaves the stats `None`
/// ("running, telemetry unavailable") rather than fabricating a number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParserKind {
    /// xmrig / RandomX (`speed 10s/60s/15m`, `(A/R)` shares) — parsed by the
    /// supervisor's own verbatim-from-Wallet line parsers.
    Xmr,
    /// kawpowminer / T-Rex (KawPoW) — [`parse_kawpow`].
    Kawpow,
    /// SRBMiner-MULTI (pearlhash) — [`parse_srbminer`]; writes stats to a log file.
    Srbminer,
    /// alpha-miner (V100/Volta pearlhash, logfmt on stdout) — [`parse_alpha`].
    Alpha,
    /// An UNKNOWN miner format — [`parse_generic`], best-effort + honest.
    Generic,
}

impl ParserKind {
    /// The parser for a BUNDLED engine on `lane` (the historical 1:1 mapping). A
    /// custom miner overrides this with its preset's parser.
    pub fn for_lane(lane: Lane) -> Self {
        match lane {
            Lane::Xmr => ParserKind::Xmr,
            Lane::GpuRvn => ParserKind::Kawpow,
            Lane::GpuPrl => ParserKind::Srbminer,
            Lane::GpuAlpha => ParserKind::Alpha,
        }
    }
}
