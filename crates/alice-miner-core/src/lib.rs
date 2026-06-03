//! Alice Miner — core engine (UI-agnostic).
//!
//! This crate is the single source of truth that both front-ends — the eframe
//! GUI (`alice-miner-gui`) and the headless CLI (`alice-miner-cli`) — drive over
//! a [`engine::Command`]/[`engine::Event`] channel pair, so the two can never
//! drift (PLAN §2.2).
//!
//! M1a modules:
//!   * [`detect`]     — fail-safe device probe → [`detect::DeviceProfile`]
//!   * [`identity`]   — create/import/paste + the `~/.alice/identity.json` pointer
//!   * [`lane`]       — per-lane launch plans (M1: [`lane::xmr`], the proven path)
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
pub mod supervise;

// Convenient top-level re-exports for the front-ends.
pub use detect::{DeviceProfile, OsFamily};
pub use engine::{Command, EngineHandle, EngineState, Event, IdentitySpec, Snapshot};
pub use identity::{Identity, IdentityPointer};
pub use lane::Lane;
