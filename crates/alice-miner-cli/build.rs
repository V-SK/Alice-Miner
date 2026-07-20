//! Build stamp — capture the EXACT target triple + OS this artifact is compiled
//! for, so `doctor` / `--version` can report which build a user is actually
//! running (a field bug report can then pin the precise artifact instead of
//! guessing). Cargo always sets `TARGET` and `CARGO_CFG_TARGET_OS` for build
//! scripts, keyed per `--target`, so the values are correct even when the release
//! matrix cross-compiles. Cargo auto-detects this file (no Cargo.toml `build =`
//! key needed). Pure diagnostics: it emits two `rustc-env` vars and nothing else —
//! no secret, no reward, no network.
fn main() {
    // `TARGET` = e.g. `aarch64-apple-darwin`; `CARGO_CFG_TARGET_OS` = e.g. `macos`.
    // Both are guaranteed present for a build script; the fallback only guards a
    // pathological invocation and never a normal `cargo build`.
    let triple = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=ALICE_TARGET_TRIPLE={triple}");
    println!("cargo:rustc-env=ALICE_TARGET_OS={os}");
    // Only this file affects the stamp; a different `--target` lands in its own
    // target dir, so the stamp still recomputes per artifact.
    println!("cargo:rerun-if-changed=build.rs");
}
