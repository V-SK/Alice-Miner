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
pub use parse_srbminer::{parse_srbminer, SrbLine, SrbScope};

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

    /// The stable, publishable NAME of this parser.
    ///
    /// A signed engine-pin entry may carry `"parser": "<id>"`
    /// ([`crate::engine_pins::PinEntry::parser`]) to say which of the formats
    /// *this* client already knows how to read a pinned engine's output in. The
    /// id therefore names compiled-in code, never a description of a format we
    /// might infer: a client that does not have the parser must refuse the
    /// document rather than pick a neighbour (see
    /// [`crate::engine_pins::validate_doc`]). Adding an id is a client release,
    /// on purpose — the same trade the URL allow-list makes.
    pub const fn id(self) -> &'static str {
        match self {
            ParserKind::Xmr => "xmrig",
            ParserKind::Kawpow => "kawpow",
            ParserKind::Srbminer => "srbminer",
            ParserKind::Alpha => "alpha",
            ParserKind::Generic => "generic",
        }
    }

    /// Every parser id this build understands, for error messages and tests.
    pub const KNOWN_IDS: &'static [&'static str] = &[
        "xmrig",
        "kawpow",
        "srbminer",
        "alpha",
        "generic",
    ];

    /// Resolve a published parser id. `None` = this build has no such parser, and
    /// the caller MUST fail closed (never fall back to a guess: reading a fork's
    /// output with the wrong parser is exactly the 2026-08-14 failure — a healthy
    /// GPU displayed `0 H/s · 0A/0R · STALL` while it was landing shares).
    /// Case-insensitive and whitespace-tolerant; nothing else is normalised.
    pub fn from_id(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "xmrig" => Some(ParserKind::Xmr),
            "kawpow" => Some(ParserKind::Kawpow),
            "srbminer" => Some(ParserKind::Srbminer),
            "alpha" => Some(ParserKind::Alpha),
            "generic" => Some(ParserKind::Generic),
            _ => None,
        }
    }
}

#[cfg(test)]
mod parser_id_tests {
    use super::*;

    /// Every variant round-trips through its published id, and `KNOWN_IDS` is the
    /// complete set — so a new parser cannot be added without also becoming
    /// nameable by a signed pin (and vice versa).
    #[test]
    fn parser_ids_round_trip_and_the_known_list_is_complete() {
        let all = [
            ParserKind::Xmr,
            ParserKind::Kawpow,
            ParserKind::Srbminer,
            ParserKind::Alpha,
            ParserKind::Generic,
        ];
        for k in all {
            assert_eq!(ParserKind::from_id(k.id()), Some(k), "round-trip {}", k.id());
            assert!(
                ParserKind::KNOWN_IDS.contains(&k.id()),
                "{} missing from KNOWN_IDS",
                k.id()
            );
        }
        assert_eq!(ParserKind::KNOWN_IDS.len(), all.len());
    }

    /// An id this build does not have resolves to `None` — the caller's cue to
    /// refuse. Near-misses must NOT resolve to a neighbour.
    #[test]
    fn an_unknown_parser_id_never_resolves_to_a_neighbour() {
        for bad in [
            "srbminer-4",
            "srbminer2",
            "srb",
            "pearlhash",
            "",
            "  ",
            "xmr",
        ] {
            assert_eq!(ParserKind::from_id(bad), None, "{bad:?} must not resolve");
        }
        // Case and surrounding whitespace are tolerated; nothing else is.
        assert_eq!(ParserKind::from_id(" SRBMiner "), Some(ParserKind::Srbminer));
    }
}
