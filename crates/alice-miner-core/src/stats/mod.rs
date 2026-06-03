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

pub mod parse_kawpow;

pub use parse_kawpow::{parse_kawpow, KawpowSample};
