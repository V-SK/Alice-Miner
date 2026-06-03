# 08 — Packaging, Signing, Auto-Update & Download Page

**Status:** design (research only — no product source touched)
**Scope:** 3-OS packaging for the Alice Miner, reusing the **exact** Wallet
release machinery (ed25519 offline-signed `latest.json` + `SHA256SUMS`, embedded
pubkey verify, ad-hoc macOS codesign, same-repo binary-mirror release, GitHub
Releases, the `wallet.html` download-page pattern on alice-website).

> **The single most important decision is in §0:** the Wallet is **not** Tauri.
> It is egui/eframe Rust with a hand-rolled, fully-proven updater. The Miner
> should reuse that *same Rust crate*, not introduce Tauri. This doc is written
> for the egui/eframe stack and flags exactly what to copy.

---

## 0. Stack decision — reuse the Wallet's updater, do NOT adopt Tauri

The brief says "Tauri (or chosen-stack)", and `alice-wallet/docs/UPDATE-SCHEME.md`
§6 *mentions* a hypothetical "Tauri-updater front-end" for the miner. **That
mention is stale/aspirational.** The shipping Wallet is:

- **egui / eframe** (`eframe = "0.34.1"`, `gui/Cargo.toml:20`) — a pure-Rust
  immediate-mode GUI, single native binary, **no web view, no Node, no
  bundler**.
- A **hand-rolled updater** in `gui/src/update.rs` (≈1500 lines, heavily tested)
  that already implements every primitive Tauri's updater would give us *and
  more* (no-downgrade, `min_supported` hard-block, first-launch health gate +
  last-known-good rollback, TOCTOU re-verify, key-preservation guard).

**Recommendation: the Miner is a second egui/eframe binary that depends on the
same shared crates and copies `update.rs` verbatim** (changing only `PRODUCT`,
`DEFAULT_UPDATE_URL`, `RELEASE_PUBKEY_B64` policy — see §3). Reasons:

| | Reuse egui updater (recommended) | Switch Miner to Tauri |
|---|---|---|
| Code reuse | `update.rs`, `release.sh`, `adhoc_sign_macos.sh`, CI matrix copy 1:1 | rewrite signing to Tauri's `minisign` format; two signing schemes to run |
| Signature format | ed25519 **raw over file bytes** (`openssl pkeyutl -rawin`) | Tauri uses **minisign** (different key, different tool) — splits the offline key story |
| Windows AV | one static `.exe`, easy to reason about | adds WebView2 bootstrapper + NSIS/MSI installer = more AV surface |
| UI polish ("漂亮/流畅") | egui can hit it; Wallet already proves the Alice look in egui | Tauri (HTML/CSS) is easier for *fancy* UI but is a second toolchain |
| Binary size | ~30 MB single file (Wallet's size) | larger; WebView2 runtime dependency on Windows |

The **one** real argument for Tauri is richer CSS-grade UI. If V decides the
miner dashboard must be web-grade and is willing to run a *second* signing format
(minisign alongside ed25519), revisit — but the default and the rest of this doc
assume **egui/eframe + reused `update.rs`**. This keeps **one offline key, one
signing step, one CI matrix** across Wallet + Miner. (Open question O1.)

---

## 1. Repository & crate layout

Mirror the Wallet's `alice-wallet/gui/` layout. New sibling repo **`alice-miner`**
(its own GitHub repo `V-SK/alice-miner`, so its release tags and same-repo binary
mirror don't collide with the Wallet's).

```
alice-miner/
├─ .github/workflows/release.yml        # CI build matrix (copy of Wallet's, §6)
├─ docs/                                 # this design set
├─ gui/                                  # the egui/eframe app crate
│  ├─ Cargo.toml                         # name = "gui", product binary
│  ├─ src/
│  │  ├─ main.rs
│  │  ├─ update.rs        ◄ COPIED verbatim from wallet; change PRODUCT, URL
│  │  ├─ config.rs        ◄ data-root resolver (AliceMiner dir)  (see §5)
│  │  ├─ miner.rs         ◄ XMR launch plan (reused from wallet survey)
│  │  ├─ supervise/…      ◄ MinerSupervisor (reused)
│  │  └─ … (UI, lanes, embedded wallet from the other survey dimensions)
│  ├─ assets/
│  │  ├─ brand/alice-logo.svg            # from wallet assets/brand
│  │  ├─ macos/AliceMiner.icns           # NEW icns (see §4.3), like AliceWallet.icns
│  │  └─ fonts/ …                        # Inter + JetBrains Mono + NotoSansSC
│  ├─ release-assets/                    # committed + fetched bundled binaries
│  │  ├─ aarch64-apple-darwin/
│  │  │  ├─ xmrig                        # COMMITTED (reuse wallet's macOS xmrig, 7 MB)
│  │  │  ├─ kawpowminer                  # COMMITTED or fetched (GPU lane, §2.2)
│  │  │  └─ trex                         # OPTIONAL fallback (NVIDIA, proprietary)
│  │  ├─ x86_64-unknown-linux-gnu/
│  │  │  ├─ xmrig                        # COMMITTED (reuse wallet's linux xmrig, 8 MB)
│  │  │  └─ kawpowminer
│  │  └─ x86_64-pc-windows-msvc/
│  │     └─ kawpowminer.exe              # GPU-only on Windows; NO xmrig.exe (constraint)
│  └─ scripts/
│     ├─ release.sh                      ◄ COPIED from wallet; PRODUCT=alice-miner, bundle GPU miner
│     └─ adhoc_sign_macos.sh             ◄ COPIED verbatim (inner-first, no --deep)
```

**Shared-crate option (preferred but optional):** the crypto survey recommends
an `alice-crypto` library crate, and `update.rs` is equally factorable into an
`alice-release` crate. If we extract `alice-release` (the verify/decide/apply
kernel) into a workspace shared by Wallet + Miner, both products stay byte-for-
byte identical in their trust core and only differ in the embedded constants.
Until that refactor lands, **copy `update.rs` verbatim** (the Wallet's own doc,
UPDATE-SCHEME §6, explicitly blesses copying the kernel). The verify/decide
functions to keep identical: `verify_with_embedded_key`, `parse_verified_manifest`,
`is_newer`, `evaluate`, `verify_artifact_integrity`, `assert_not_in_data_dir`,
`apply_update`, `register_launch`, `adhoc_codesign`.

---

## 2. Bundled miner binaries — what ships per OS

The miner launches external mining engines as child processes (the Wallet already
does this for `xmrig` via `MinerSupervisor`; survey: miner-reuse). Each engine is
a **sibling of the app executable**, resolved exactly like the Wallet resolves
`xmrig`/`solochain-template-node` (`gui/src/node.rs::resolve_miner_binary`):
`<app-dir>/<engine>` on Linux/Windows, `…/Contents/MacOS/<engine>` on macOS.

### 2.1 Per-OS bundle matrix

| Engine | Lane | macOS-arm64 | linux-x86_64 | windows-x86_64 |
|---|---|---|---|---|
| **xmrig** | CPU XMR / RandomX | ✅ bundled (reuse Wallet's, 7 MB) | ✅ bundled (reuse Wallet's, 8 MB) | ❌ **never bundled** (Defender/PUA) → on-demand download or GPU-only |
| **kawpowminer** | GPU RVN / KawPoW | ✅ bundled (build, GPL-3.0) | ✅ bundled | ✅ bundled |
| **t-rex** | GPU RVN (NVIDIA, faster) | optional | optional | optional |
| *(AI lane)* | inference worker | **no binary** — in-process Rust worker_client (survey: ai-earn) | same | same |

Notes:
- The CPU XMR engine reuses the Wallet's *exact* proven binaries already
  committed at `alice-wallet/gui/release-assets/{aarch64-apple-darwin,
  x86_64-unknown-linux-gnu}/xmrig`. Copy those bytes into the Miner's
  `release-assets/` and pin their SHA-256 (§2.3).
- The AI lane needs **no** bundled binary — it is the in-process
  `inference_worker_client` (CPU/GPU compute via the app's own runtime). Nothing
  to package; it dispatches over HTTPS.
- T-Rex is proprietary + NVIDIA-only + 1% dev fee (survey: gpu-miners). Treat it
  as an **optional, operator-supplied** accelerator, not a default bundle. The
  default GPU engine is **kawpowminer** (GPL-3.0, 0% fee, auditable, cross-OS) so
  the bundle stays open-source-clean and AV-friendly.

### 2.2 Windows = GPU-only by default (the XMR/AV constraint)

Per the hard constraint, **Windows must not bundle xmrig**. Concretely:

- The Windows artifact ships **kawpowminer.exe only**. The CPU/XMR lane is
  *disabled at runtime* on Windows unless the user opts in.
- **CPU lane on Windows = on-demand download.** When a Windows user explicitly
  enables the CPU lane, the app downloads `xmrig.exe` from the **same-repo binary
  mirror release** (§5) over HTTPS, **verifies it against a SHA-256 pinned in the
  Miner binary** (fail-closed, exactly like the chain-spec pin in
  `gui/src/node.rs`), then runs it from the app data dir — *not* from the install
  dir. This keeps the shipped installer clean of any miner Defender flags while
  still allowing CPU mining for users who want it.
- UI copy must say plainly: "Windows ships GPU mining out of the box; CPU
  (Monero/RandomX) mining downloads an extra component on first use." (mirrors
  `mine.html`'s honest tone).

### 2.3 Integrity of bundled binaries (fail-closed, reused pattern)

Reuse the Wallet's **pin-and-verify-in-CI** mechanism verbatim
(`release.yml` "Verify staged node binary SHA-256 == pinned" /
"Verify staged chain spec SHA-256 == pinned"):

- Each bundled engine has a per-(triple, engine) SHA-256 **pinned in the Miner
  source** (a `const` table in `miner_binaries.rs`, analogous to the
  `ALICE_MAINNET_SPEC_SHA256` pin in `node.rs`).
- CI stages the engine (committed asset **or** fetched from the binary mirror),
  **hashes it, and aborts the build on mismatch** — a wrong/tampered miner can
  never be packaged.
- The same pin is the gate for the Windows on-demand `xmrig.exe` download (§2.2),
  so even the not-bundled engine is integrity-checked at runtime.

This is the *same* fail-closed philosophy the Wallet uses for its node binary;
it just extends the pin table to cover the mining engines.

---

## 3. Trust anchor — reuse the ed25519 manifest scheme exactly

Copy `update.rs` and keep the verification core byte-identical. Only these
constants change for the Miner:

```rust
// gui/src/update.rs  (Miner copy)
pub const PRODUCT: &str = "alice-miner";                 // was "alice-wallet"
pub const SUPPORTED_SCHEMA: u32 = 1;                      // unchanged
pub const DEFAULT_UPDATE_URL: &str =
    "https://github.com/V-SK/alice-miner/releases/latest/download/latest.json";
pub const UPDATE_URL_ENV: &str = "ALICE_MINER_UPDATE_URL"; // miner's own override
pub const RELEASE_PUBKEY_B64: &str = "<…>";              // see key decision below
```

### 3.1 Manifest (`latest.json`) — identical schema, distinct `product`

Same schema (`schema:1`) and same field semantics as
`alice-wallet/docs/UPDATE-SCHEME.md §2`. The only data difference is
`"product":"alice-miner"` and the artifact filenames. Example:

```json
{
  "schema": 1,
  "product": "alice-miner",
  "version": "0.1.0",
  "min_supported": "0.1.0",
  "released": "2026-06-10T00:00:00Z",
  "notes": "Alice Miner 0.1.0 — one-click CPU/GPU/Mac mining.",
  "artifacts": [
    { "platform": "macos-arm64",   "url": "https://github.com/V-SK/alice-miner/releases/latest/download/AliceMiner-macos-arm64.zip",   "sha256": "<hex>", "size": 0 },
    { "platform": "linux-x86_64",  "url": "https://github.com/V-SK/alice-miner/releases/latest/download/AliceMiner-linux-x86_64.tar.gz", "sha256": "<hex>", "size": 0 },
    { "platform": "windows-x86_64","url": "https://github.com/V-SK/alice-miner/releases/latest/download/AliceMiner-windows-x86_64.zip",  "sha256": "<hex>", "size": 0 }
  ]
}
```

Artifact filenames (mirror the Wallet's `AliceWallet-<platform>.<ext>`):
`AliceMiner-macos-arm64.zip`, `AliceMiner-linux-x86_64.tar.gz`,
`AliceMiner-windows-x86_64.zip`. Platform keys are the **same strings**
`update.rs::current_platform()` already emits — no code change there.

The detached signature is `latest.json.sig` (base64 of the 64-byte raw ed25519
signature over the **exact file bytes**), fetched from the manifest URL + `.sig`,
**verified before any field is parsed** (`verify_with_embedded_key`). `SHA256SUMS`
+ `SHA256SUMS.sig` ship alongside, same as the Wallet.

### 3.2 The signing key — one key for both products (recommended)

`update.rs` enforces `product == PRODUCT` *after* signature verification, so **a
single offline ed25519 key can sign both `alice-wallet` and `alice-miner`
manifests without their being interchangeable** (a wallet build rejects a miner
manifest on the `product` check even though the signature is valid). This is
called out explicitly in UPDATE-SCHEME §6 ("one offline key + one signing step
can serve both products") and §2 ("one signing key can serve multiple products").

**Recommendation: reuse the existing offline key**
(`~/.alice-release/alice-update-ed25519.key`) and embed the **same**
`RELEASE_PUBKEY_B64 = 8P+XmZZFEsUHLmqeB62Xqr5GnwW5K9vf2sQHvRzfi5k=` in the Miner.
One key, one offline ceremony, two products. (Open question O2 — if V prefers
key isolation per product, generate a second ed25519 key, embed its pubkey in the
Miner, and run two signing steps; the code is identical either way.)

Signing is **offline-only**, never in CI — `release.sh` refuses to sign when
`$CI` is set and the CI workflow has **no release job** (it only builds +
uploads). This is reused verbatim.

---

## 4. Per-OS bundle layout

Reuse `alice-wallet/gui/scripts/release.sh` almost verbatim. Change `PRODUCT`,
`artifact_name()`, the `Info.plist` strings, and the bundled-binary staging to
stage the **mining engines** instead of the node. The node bundling logic is
dropped (the Miner runs no chain node). Everything else — staging dirs,
`SHA256SUMS`, `latest.json` generation, the print-sign-steps gate, the
`--sign`/`--publish` flags — is identical.

### 4.1 macOS (`AliceMiner.app`, ad-hoc signed, zipped via `ditto`)

```
AliceMiner.app/
├─ Contents/
│  ├─ Info.plist                    # CFBundleIdentifier org.aliceprotocol.miner, icon AliceMiner
│  ├─ MacOS/
│  │  ├─ AliceMiner                 # the egui binary (from target/<triple>/release/gui)
│  │  ├─ xmrig                      # bundled CPU engine (sibling, resolve_miner_binary)
│  │  └─ kawpowminer                # bundled GPU engine (sibling)
│  └─ Resources/
│     └─ AliceMiner.icns            # app icon → Launchpad/Finder/Dock
```

- `Info.plist`: copy the Wallet's, change `CFBundleName`/`CFBundleDisplayName` to
  *Alice Miner*, `CFBundleIdentifier` to `org.aliceprotocol.miner`,
  `CFBundleExecutable`/`CFBundleIconFile` to `AliceMiner`, keep
  `LSMinimumSystemVersion 11.0` + `NSHighResolutionCapable`.
- **Ad-hoc sign inner-first, then the bundle** via the copied
  `scripts/adhoc_sign_macos.sh` (`--force --timestamp=none -s -`, **no `--deep`**).
  The nested `xmrig` + `kawpowminer` Mach-Os are signed before the bundle is
  sealed — required so Apple Silicon will load them after the user clears
  quarantine. `release.sh` calls the script; the in-app updater re-implements the
  same ordering in `update::adhoc_codesign` so a self-update is byte-equivalent.
  > **Fix-forward note:** the Wallet's `release.yml` macOS step still uses the
  > deprecated `codesign --force --deep` (release.yml:287), while `release.sh`
  > and `update.rs` use the correct inner-first method. The Miner's CI should use
  > the **inner-first script** in CI too (call `scripts/adhoc_sign_macos.sh`),
  > not `--deep`, to stay consistent with the updater. (O3.)
- Zip with `ditto -c -k --keepParent` so bundle metadata + the ad-hoc signature
  survive — the in-app updater extracts with `ditto -x -k` to match.

### 4.2 Linux (`AliceMiner/` dir → `.tar.gz`)

```
AliceMiner/
├─ AliceMiner               # egui binary
├─ xmrig                    # bundled CPU engine (sibling)
├─ kawpowminer              # bundled GPU engine (sibling)
├─ alice-logo.svg
├─ AliceMiner.desktop       # Categories=Utility; (not Finance)
└─ run.sh                   # cd "$(dirname "$0")" && ./AliceMiner
```

No load-time signature requirement; integrity is the ed25519 manifest + SHA-256.
GTK3 + libxkbcommon runtime libs (same as the Wallet, INSTALL.md).

### 4.3 Windows (`AliceMiner\` dir → `.zip`) — **no xmrig.exe**

```
AliceMiner\
├─ AliceMiner.exe           # egui binary (from gui.exe)
├─ kawpowminer.exe          # bundled GPU engine ONLY
└─ alice-logo.svg
```

- **No `xmrig.exe` in the shipped artifact** (the constraint). The Package-Windows
  step explicitly does **not** copy an xmrig. CPU lane = on-demand download +
  pinned-SHA verify at runtime (§2.2).
- Ship as a **plain `.zip` of a folder** (no self-extracting installer, no NSIS/
  MSI). The Wallet does exactly this; it minimizes SmartScreen/AV surface (§7).
- App icon: embed an `.ico` via a `build.rs` + `winres`/`embed-resource` (so the
  `.exe` shows the Alice mark in Explorer/taskbar). The Wallet doesn't do this
  yet; recommended polish for the Miner. (O4.)

### 4.4 Icons to produce (one-time)

- `assets/macos/AliceMiner.icns` — from the brand SVG/PNG, `iconutil` from a
  `.iconset`, same as `AliceWallet.icns` (109 KB committed).
- `assets/windows/AliceMiner.ico` — multi-resolution, for `winres`.
- Both derive from the canonical brand orange `#F97316` "A" mark
  (`alice-wallet/gui/assets/brand/alice-logo.svg`). Consider a subtle lane-color
  accent to distinguish Miner from Wallet at a glance (brand still primary).

---

## 5. GitHub Release + same-repo binary mirror

Two release "tracks" in the `V-SK/alice-miner` repo, mirroring the Wallet:

1. **Product releases** — tag `vX.Y.Z`. Triggers `release.yml` (build matrix).
   The maintainer downloads the per-OS artifacts, **signs offline**, and
   `gh release create vX.Y.Z` uploads:
   `AliceMiner-macos-arm64.zip`, `AliceMiner-linux-x86_64.tar.gz`,
   `AliceMiner-windows-x86_64.zip`, `SHA256SUMS`, `SHA256SUMS.sig`,
   `latest.json`, `latest.json.sig`. The download page + the in-app updater both
   point at `…/releases/latest/download/`.

2. **Binary-mirror release ("node-bin-style")** — tag `miner-bin-v0.1.0`
   (analogous to the Wallet's `node-bin-v0.1.0`). Holds the **heavy / not-
   committed bundled engines** so they don't bloat git:
   `kawpowminer-<platform>`, `trex-<platform>`, and the Windows **on-demand
   `xmrig-windows-x86_64.exe`**. CI's "Stage miner engines" step pulls the right
   asset with `gh release download "$MINER_BIN_REL_TAG" -R "$GITHUB_REPOSITORY"
   -p "$ASSET" -O "$OUT"` (works while the repo is private via `GITHUB_TOKEN`),
   exactly like `release.yml`'s node-binary fetch. The Windows runtime xmrig
   download (§2.2) reads from this same mirror over plain HTTPS.

   - `xmrig` for macOS/linux is small enough to **commit** in `release-assets/`
     (reuse the Wallet's bytes); only Windows xmrig + the GPU engines need the
     mirror.

**Data-root / key-preservation:** the Miner's `config.rs` resolves its own data
root (e.g. `$ALICE_MINER_DATA_ROOT` → `~/.local/share/AliceMiner` /
`%LOCALAPPDATA%\AliceMiner`). The updater's `assert_not_in_data_dir` guard
(reused) refuses to install over the data dir, so the embedded-wallet keystore is
never touched by an update — same invariant the Wallet tests
(`app_swap_leaves_keystore_files_untouched`). **Shared identity note:** the
embedded wallet writes the *active address / keystore* under the shared
`~/.alice/` (per the product brief), which is **outside** any app's data root and
**outside** any install dir — so it is doubly safe from updates.

---

## 6. CI build matrix (`.github/workflows/release.yml`)

Copy the Wallet's workflow; trim the node-binary logic to **miner-engine
staging**, and swap the macOS codesign to the inner-first script (§4.1). Matrix:

```yaml
name: Release
on: { push: { tags: ['v*'] }, workflow_dispatch: {} }
jobs:
  build:
    name: Build ${{ matrix.name }}
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        include:
          - { name: linux-x86_64,  os: ubuntu-22.04,  target: x86_64-unknown-linux-gnu, artifact: AliceMiner-linux-x86_64.tar.gz }
          - { name: windows-x86_64, os: windows-latest, target: x86_64-pc-windows-msvc,  artifact: AliceMiner-windows-x86_64.zip }
          - { name: macos-arm64,   os: macos-latest,   target: aarch64-apple-darwin,     artifact: AliceMiner-macos-arm64.zip }
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { targets: '${{ matrix.target }}' }
      - uses: Swatinem/rust-cache@v2
        with: { workspaces: gui }
      - name: Install Linux deps          # libgtk-3-dev, libxcb-*, libxkbcommon-dev, libssl-dev, libwayland-dev
        if: runner.os == 'Linux'
        run: sudo apt-get update && sudo apt-get install -y libgtk-3-dev libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libxkbcommon-dev libssl-dev libwayland-dev
      - name: Test
        working-directory: gui
        run: cargo test --target ${{ matrix.target }}
      - name: Build
        working-directory: gui
        run: cargo build --release --target ${{ matrix.target }}

      # ── Stage mining engines (committed asset OR binary-mirror fetch) ──
      - name: Stage miner engines
        id: engines
        shell: bash
        env: { GH_TOKEN: '${{ secrets.GITHUB_TOKEN }}', MINER_BIN_REL_TAG: '${{ vars.MINER_BIN_REL_TAG }}' }
        run: |
          set -euo pipefail
          mkdir -p engine-stage
          # committed assets (xmrig for mac/linux, maybe kawpowminer) take precedence
          [ -d "gui/release-assets/${{ matrix.target }}" ] && cp -v gui/release-assets/${{ matrix.target }}/* engine-stage/ 2>/dev/null || true
          TAG="${MINER_BIN_REL_TAG:-miner-bin-v0.1.0}"
          # fetch GPU engine if not committed; NEVER fetch xmrig for windows here (ships GPU-only)
          case "${{ matrix.target }}" in
            x86_64-unknown-linux-gnu) GPU=kawpowminer-linux-x86_64;   OUT=engine-stage/kawpowminer ;;
            x86_64-pc-windows-msvc)   GPU=kawpowminer-windows-x86_64.exe; OUT=engine-stage/kawpowminer.exe ;;
            aarch64-apple-darwin)     GPU=kawpowminer-macos-arm64;    OUT=engine-stage/kawpowminer ;;
          esac
          [ ! -f "$OUT" ] && gh release download "$TAG" -R "$GITHUB_REPOSITORY" -p "$GPU" -O "$OUT" --clobber || true

      # ── Fail-closed SHA-256 pin verify (per engine, like node-spec pin) ──
      - name: Verify staged engines == pinned SHA-256
        shell: bash
        run: gui/scripts/verify_engine_pins.sh "${{ matrix.target }}" engine-stage   # aborts on mismatch

      # ── Package (per-OS, copies engines beside the binary) ──
      - name: Package Linux   (if Linux)    # dir → tar.gz, copy xmrig + kawpowminer
      - name: Package Windows (if Windows)  # dir → zip, copy kawpowminer.exe ONLY (no xmrig.exe)
      - name: Package macOS   (if macOS)    # .app, copy xmrig + kawpowminer, then:
        #   bash gui/scripts/adhoc_sign_macos.sh dist/AliceMiner.app   ← inner-first, NOT --deep
        #   ditto -c -k --keepParent dist/AliceMiner.app "$artifact"

      - uses: actions/upload-artifact@v4
        with: { name: '${{ matrix.artifact }}', path: '${{ matrix.artifact }}' }

  # NO release job — manifest + SHA256SUMS are signed OFFLINE; CI never holds the key.
```

The "no release job" comment from the Wallet is reproduced verbatim: CI ends at
build + upload; the maintainer signs locally and publishes by hand, keeping the
ed25519 key offline.

---

## 7. Windows AV strategy (concrete)

The whole reason Windows is GPU-only-by-default. Concrete measures, in priority
order:

1. **Do not ship a CPU miner in the Windows artifact.** xmrig is the single
   biggest false-positive trigger; keeping it out of the installer means the
   shipped `.zip` contains only `AliceMiner.exe` + `kawpowminer.exe` (GPL, lower
   AV reputation risk than xmrig) + an SVG. This alone removes the worst PUA hit.
2. **CPU lane = explicit, on-demand, pinned download** (§2.2). The user must opt
   in; the app fetches `xmrig.exe` from the binary mirror, **verifies the pinned
   SHA-256 before executing**, and runs it from the data dir. The shipped product
   is never the thing Defender quarantines.
3. **No self-extracting installer.** Ship a plain folder `.zip` (Wallet pattern).
   NSIS/MSI/self-extractors carry their own SmartScreen reputation penalty;
   avoiding them keeps the first-run prompt to the generic "unknown publisher"
   one, which the INSTALL flow already explains.
4. **Honest install docs + "Unblock" guidance.** Mirror `INSTALL.md` Windows
   section: `Unblock-File` the zip before extracting; SmartScreen → *More info →
   Run anyway*; verify SHA-256 with `Get-FileHash`. The download page repeats
   this (§8).
5. **Publish checksums + ed25519 signatures** so users (and AV vendors' "submit
   for analysis") can verify provenance. kawpowminer is GPL-3.0 and source-
   auditable, which helps with false-positive disputes.
6. **No code-signing certificate** (consistent with the Wallet's no-cert stance).
   *If* Windows false-positives prove painful in practice, the lowest-effort
   escalation is an **Authenticode EV certificate** for `AliceMiner.exe` +
   `kawpowminer.exe` only — but that is a paid, out-of-band step and explicitly
   *not* part of the v1 plan (the ed25519 manifest remains the real trust anchor).
   (O5.)
7. **Runtime behavior:** run the engine as a visible child process (the
   `MinerSupervisor` pattern), never as a hidden service — hidden miners are a
   classic malware signature and a heuristic trigger.

---

## 8. Download page on alice-website

### 8.1 Page choice — a dedicated `miner.html` mirroring `wallet.html`

The site already has **`mine.html`** (device picker + manual stratum table +
earnings calculator) whose one-click download buttons are placeholders
(`"package links pending HF distribution metadata"`, mine.html:192/433). The
clean move, matching the Wallet:

- **Create `alice-website/miner.html`** — a near-exact clone of `wallet.html`'s
  three-section download layout (Download / Install & Verify / First Run),
  rebranded for the Miner and pointing at the `V-SK/alice-miner` releases.
- **Wire `mine.html`'s download buttons to `miner.html`** (replace the pending
  placeholder links with real `<a href="/download">` / `/miner` links). `mine.html`
  stays the "choose your device + calculator + ASIC manual" page; `miner.html`
  becomes the actual "download the app + verify it" page — the same split the
  Wallet enjoys (a marketing/landing context vs. the concrete download page).

`vercel.json` already routes `/download → /mine.html` and has `/mine`,
`/miner-dashboard` rewrites; add a rewrite **`/miner → /miner.html`** (and
optionally repoint `/download → /miner.html`, since "download" should land on the
artifact page). The route addition is the only `vercel.json` change.

### 8.2 What to copy from `wallet.html` (the proven pattern)

`wallet.html` is React/JSX rendered in-browser (Babel standalone) with the inline
Alice theme, bilingual EN/ZH (`i18n` object), and these reusable pieces — copy
them 1:1, swapping the constants:

- **Release config block** (wallet.html:164–211) →
  ```js
  const MINER_VERSION = '0.1.0';
  const RELEASE_BASE  = 'https://github.com/V-SK/alice-miner/releases/latest/download';
  const MINER_PLATFORMS = [
    { id:'macos',   os:'macOS',   arch:'Apple Silicon (arm64)', file:'AliceMiner-macos-arm64.zip',   size:'≈ 30 MB', available:true,  match:(ua,p)=>/mac/i.test(p)||/mac os x|macintosh/i.test(ua) },
    { id:'windows', os:'Windows', arch:'10 / 11 · x64',          file:'AliceMiner-windows-x86_64.zip', size:'≈ 22 MB', available:true,  match:(ua,p)=>/win/i.test(p)||/windows/i.test(ua) },
    { id:'linux',   os:'Linux',   arch:'x86_64',                 file:'AliceMiner-linux-x86_64.tar.gz',size:'≈ 30 MB', available:true,  match:(ua,p)=>/linux|x11/i.test(p)||(/linux/i.test(ua)&&!/android/i.test(ua)) },
  ];
  const url = (f)=>`${RELEASE_BASE}/${f}`;
  const SUMS_URL=url('SHA256SUMS'), SUMS_SIG_URL=url('SHA256SUMS.sig'), LATEST_JSON_URL=url('latest.json');
  ```
  *(Set `available:false` on any platform whose artifact isn't published yet —
  the card flips to "Coming soon" with zero other edits, exactly as the Wallet
  does. The Windows size is smaller because it ships GPU-only.)*
- **`detectOS()`** (wallet.html:203–211) — verbatim; returns the matched platform
  id, `null` on mobile so no desktop card is auto-highlighted.
- **The Section-1 download UI** (wallet.html:613–667): the "Recommended for
  <detected OS>" hero card + the three `.plat` cards with
  `detected`/`soon`/`a-badge-live`/`a-badge-soon` states and the download SVG.
  This is the canonical platform-card pattern from the brand-ui survey.
- **The Section-2 Install & Verify accordion** — reuse the macOS (`ditto -x -k`,
  `xattr -dr com.apple.quarantine`), Windows (`Unblock-File`, SmartScreen *Run
  anyway*), Linux (`tar -xzf`, `chmod +x`) steps, and the **verify block**
  (wallet.html:555–565): links to `SHA256SUMS` / `SHA256SUMS.sig` /
  `latest.json`, the `sha256sum -c` / `shasum -a 256 -c` / `Get-FileHash`
  one-liners, and the **ed25519 PEM-rebuild + `openssl pkeyutl -verify -rawin`**
  snippet. Swap `RELEASE_PUBKEY_B64` only if O2 picks a separate miner key
  (default: the same `8P+XmZZF…` value the Wallet shows).
- **A Miner-specific Section-3** instead of the Wallet's node-sync "First Run":
  a short "one-click → pick lane → paste/auto-create Alice address → Start"
  walkthrough, plus the **Windows CPU-lane note** ("GPU mining ships in the box;
  CPU/Monero downloads an extra component on first use") so the AV behavior is
  not a surprise.

### 8.3 Honesty/credit-only copy (reuse mine.html tone)

The page must keep `mine.html`'s pending/credit-only framing: rewards accrue as
**pending (待发放)**, `paid_acu = 0`, payout gated. No payout/claim UI. Earnings,
if shown, are **credit/score**. This matches the hard constraint and the existing
site voice (mine.html:165, 210).

### 8.4 Build/deploy

The site is static HTML deployed on Vercel (`alice-website/package.json`,
`vercel.json`). Adding `miner.html` + one rewrite needs no build-system change;
the per-page inline theme + Tailwind-CDN pattern is identical to `wallet.html`.
The `bin/deploy.sh` mirror is unrelated (it's the site's own deploy helper).

---

## 9. End-to-end release runbook (reused, Miner-flavored)

1. Bump `gui/Cargo.toml` version (the manifest reads it so they never drift).
2. Tag `vX.Y.Z` → CI builds the 3 artifacts (no signing in CI).
3. Download the 3 artifacts to the **offline** signing machine.
4. `scripts/release.sh --version X.Y.Z --base-url https://github.com/V-SK/alice-miner/releases/latest/download --sign`
   → builds (or re-uses) artifacts, writes `SHA256SUMS` + `latest.json`, and
   ed25519-signs both with `~/.alice-release/alice-update-ed25519.key`.
5. `… --publish` (or `gh release create vX.Y.Z …`) uploads artifacts +
   `SHA256SUMS{,.sig}` + `latest.json{,.sig}`.
6. Confirm `miner.html` `MINER_VERSION` + any `available` flags, and that the
   binary-mirror release (`miner-bin-vN`) has the current GPU engine + Windows
   `xmrig.exe` with SHAs matching the in-binary pins.
7. Installed clients pick up `latest.json` on next launch, verify sig → SHA-256 →
   apply with health-gate rollback.

---

## 10. Open questions for V

- **O1 — Stack:** confirm egui/eframe + reused `update.rs` (recommended) vs.
  Tauri. Tauri buys web-grade UI but forces a *second* signing format (minisign)
  and a second toolchain. Default = egui.
- **O2 — Signing key:** reuse the **one** existing offline ed25519 key for both
  Wallet + Miner (recommended; `product` field already isolates them), or mint a
  separate miner key for blast-radius isolation?
- **O3 — macOS codesign in CI:** adopt the inner-first `adhoc_sign_macos.sh` in
  the Miner's CI (recommended) rather than the Wallet CI's deprecated
  `--deep`. (Worth back-porting to the Wallet too — flagged separately.)
- **O4 — Windows `.exe` icon:** add `winres`/`embed-resource` so the taskbar/
  Explorer show the Alice mark (the Wallet doesn't yet). Polish-positive.
- **O5 — Authenticode EV cert:** out of scope for v1 (ed25519 manifest is the
  trust anchor). Hold unless Windows false-positives prove painful in the field.
- **O6 — GPU engine default:** confirm **kawpowminer** (GPL-3.0, 0% fee, cross-OS,
  auditable) as the bundled default, with T-Rex as an optional operator-supplied
  NVIDIA accelerator (matches `gpu-miners` survey recommendation).
- **O7 — Release host:** the Wallet's `DEFAULT_UPDATE_URL` is still the
  `V-SK/alice-wallet` placeholder (UPDATE-SCHEME §7). Pin the Miner's to the real
  public `V-SK/alice-miner` releases repo/CDN before the first signed release.
