//! Alice Miner — core engine (UI-agnostic).
//!
//! This crate is the single source of truth that both front-ends — the eframe
//! GUI (`alice-miner-gui`) and the headless CLI (`alice-miner-cli`) — drive over
//! a `Command`/`Event` channel pair, so the two can never drift (PLAN §2.2).
//!
//! M0 placeholder: the crate exists to wire the workspace graph and the shared
//! path dependencies (`alice-crypto`, `alice-supervise`, `alice-release`) and to
//! prove they compile together. The real pipeline — device detection, lane
//! selection, the per-lane `LaneSupervisor`, stats collection, the `~/.alice/`
//! identity contract, and the credit-only `Snapshot` (which by construction has
//! NO `paid_acu` field) — lands from M1 onward.

// Pull the shared crates into the dependency graph so M0 proves they build and
// link together as the engine will consume them.
pub use alice_crypto;
pub use alice_release;
pub use alice_supervise;

/// Placeholder for the mining engine handle. Replaced in M1 by the real
/// worker-thread-backed engine exposing `Command`/`Event` channels.
pub struct Engine;
