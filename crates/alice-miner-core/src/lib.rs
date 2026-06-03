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
pub mod detect;
pub mod engine;
pub mod identity;
pub mod lane;
pub mod stats;
pub mod supervise;

// Convenient top-level re-exports for the front-ends.
pub use detect::capability::{CapabilityProfile, LaneSupport, LaneViability};
pub use detect::{DeviceProfile, GpuInfo, GpuVendor, OsFamily};
pub use engine::{Command, EngineHandle, EngineState, Event, IdentitySpec, Snapshot};
pub use identity::{Identity, IdentityPointer};
pub use lane::Lane;
