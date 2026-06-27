//! Alice Miner — core engine (UI-agnostic).
//!
//! This crate is the single source of truth that both front-ends — the eframe
//! GUI (`alice-miner-gui`) and the headless CLI (`alice-miner-cli`) — drive over
//! a [`engine::Command`]/[`engine::Event`] channel pair, so the two can never
//! drift (PLAN §2.2).
//!
//! Modules:
//!   * [`detect`]     — fail-safe device probe → [`detect::DeviceProfile`] +
//!     [`detect::capability::CapabilityProfile`] (the M3 lane-viability matrix:
//!     NVIDIA/AMD/Apple/CPU detection → which lanes are runnable)
//!   * [`identity`]   — create/import/paste + the `~/.alice/identity.json` pointer
//!   * [`lane`]       — per-lane launch plans ([`lane::xmr`] proven path +
//!     [`lane::gpu_rvn`] KawPoW/RVN, M3)
//!   * [`stats`]      — per-lane log parsers ([`stats::parse_kawpow`], M3)
//!   * [`binaries`]   — resolve the bundled engine (sibling-of-exe + dev fallback)
//!   * [`supervise`]  — [`supervise::LaneSupervisor`]: one supervised child + stats
//!   * [`engine`]     — the worker-thread engine + the credit-only [`engine::Snapshot`]
//!
//! Hard invariants enforced here (PLAN §3, the brief):
//!   * **Credit-only** — [`engine::Snapshot`] has NO `paid_acu` (tested).
//!   * **Honesty gate** — the XMR argv carries the user's OWN address and no
//!     collection-address / upstream-pool / seed substring (tested in [`lane::xmr`]);
//!     the collection address const is never even imported into this crate.
//!   * **Security** — `unlock_wallet` runs exactly once at create/import; mining
//!     consumes only the public address (see [`identity`]).

// Pull the shared crates into the dependency graph + re-export for downstreams.
pub use alice_crypto;
pub use alice_release;
pub use alice_supervise;

pub mod binaries;
pub mod dashboard;
pub mod detect;
pub mod endpoint;
pub mod engine;
pub mod identity;
pub mod keyring;
pub mod lane;
pub mod pop;
pub mod prl_payout;
pub mod service;
pub mod stats;
pub mod supervise;
pub mod terminal;

/// Test-only: a single process-global lock guarding the `ALICE_MINER_*_BIN` env
/// vars. Both [`binaries`] and [`engine`] tests set/read these, and Rust runs
/// tests in a crate in parallel, so they MUST serialize through one mutex (two
/// separate mutexes would not prevent the cross-module race). Lives here so both
/// modules share the exact same lock.
#[cfg(test)]
pub(crate) static MINER_BIN_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Test-only: a single process-global lock guarding the keystore / identity-dir
/// env vars (`ALICE_WALLET_DATA_ROOT` + `ALICE_IDENTITY_DIR`). Both [`identity`]
/// tests and [`engine`] tests point these at temp dirs; like
/// [`MINER_BIN_ENV_LOCK`] they MUST serialize through ONE mutex (separate mutexes
/// don't prevent the cross-module env race). Lives here so both modules share it.
#[cfg(test)]
pub(crate) static IDENTITY_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// Convenient top-level re-exports for the front-ends.
pub use dashboard::{
    CreditError, CreditScore, CreditSource, CreditState, DashboardModel, LaneActivity,
    LocalActivity, PoolStatsClient, Reconciliation,
};
pub use detect::capability::{CapabilityProfile, LaneSupport, LaneViability};
pub use detect::{DeviceProfile, GpuInfo, GpuVendor, OsFamily};
pub use endpoint::{Endpoint, EndpointPlan, Transport};
pub use engine::{Command, EngineHandle, EngineState, Event, IdentitySpec, Snapshot};
pub use identity::{Identity, IdentityPointer};
pub use lane::{GpuSelection, Lane};
pub use prl_payout::{EnrollOutcome, PrlPayoutDisplay};
