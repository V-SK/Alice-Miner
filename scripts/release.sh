#!/usr/bin/env bash
#
# release.sh — cut an Alice MINER release for the unsigned-distribution +
# ed25519 auto-update scheme (mirrors the Wallet's pipeline; PLAN §5 M7, §6
# D-signing). Adapted from alice-wallet/gui/scripts/release.sh.
#
# Pipeline:
#   1. Build the GUI (`alice-miner-gui`) for each requested target.
#   2. Package per-OS (macOS .app -> .zip via ditto; Linux dir -> .tar.gz;
#      Windows dir -> .zip), AD-HOC signing the macOS bundle inner-first
#      (scripts/adhoc_sign_macos.sh — NO --deep). Bundled mining engines are
#      staged from release-assets/<triple>/ and SHA-pin-VERIFIED against
#      release-assets/miners.json before they are packaged (fail-closed).
#   3. Write SHA256SUMS over the artifacts.
#   4. Generate latest.json (the signed update manifest, product:"alice-miner").
#   5. *** OFFLINE, ON A TRUSTED MACHINE ***: ed25519-sign latest.json (+
#      SHA256SUMS) with the release key. This script DOES NOT sign by default; it
#      prints the exact commands and only signs if --sign is passed AND the
#      offline key is present (so CI can never sign).
#   6. Upload artifacts + SHA256SUMS + latest.json + latest.json.sig to a GitHub
#      Release via `gh`.
#
# The ONLY trust anchor is the ed25519 release key (the SAME one the Wallet uses;
# the `product` field isolates the two apps — see alice-release cross-product
# guard). There are NO Apple/Windows code-signing certificates. The Miner verifies
# latest.json.sig against the embedded public key
# (alice-release::RELEASE_PUBKEY_B64) before acting.
#
# BUNDLING POLICY (PLAN §6 D-Windows, D-GPU-miner):
#   * macOS/Linux ship the proven xmrig (CPU-XMR lane) + (when supplied)
#     kawpowminer (GPU-RVN lane), both SHA-pinned.
#   * WINDOWS DOES NOT BUNDLE xmrig.exe (Defender/SmartScreen PUA) — its CPU lane
#     is an on-demand pinned-SHA download at runtime. Windows ships ONLY
#     AliceMiner.exe + kawpowminer.exe + the brand SVG.
#
# Usage:
#   scripts/release.sh [--version X.Y.Z] [--targets "macos-arm64 linux-x86_64 windows-x86_64"]
#                      [--min-supported X.Y.Z] [--notes-file NOTES.md]
#                      [--out dist] [--base-url URL] [--sign] [--publish] [--repo owner/name]
#
# Safe by default: with neither --sign nor --publish it only builds + packages +
# writes SHA256SUMS + latest.json locally, and prints the signing/publish steps.
#
set -euo pipefail

# ── Defaults ────────────────────────────────────────────────────────────────
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_TRIPLE="$(rustc -vV 2>/dev/null | awk -F': ' '/host/ {print $2}')"
GUI_CRATE_DIR="${ROOT_DIR}/crates/alice-miner-gui"
GUI_BIN="alice-miner-gui"   # the workspace [[bin]] name
VERSION=""
MIN_SUPPORTED=""
NOTES_FILE=""
OUT_DIR="${ROOT_DIR}/dist"
TARGETS=""          # platform keys; empty => just the host
DO_SIGN=0
DO_PUBLISH=0
REPO=""             # owner/name for gh; default: gh infers from git remote
PRODUCT="alice-miner"
# Offline private key location (NEVER committed; NEVER read by CI). Shared with
# the Wallet — the manifest `product` field is what isolates the two releases.
RELEASE_KEY="${ALICE_RELEASE_KEY:-${HOME}/.alice-release/alice-update-ed25519.key}"
# Public URL prefix where these artifacts will be downloadable (pinned by V).
# Mirrors alice-release::DEFAULT_UPDATE_URL's directory.
BASE_URL="${ALICE_RELEASE_BASE_URL:-}"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# Read the pinned SHA-256 for (engine-filename, triple) straight from
# release-assets/miners.json so the package step never drifts from the runtime
# integrity check baked into the binary. Echoes the 64-hex pin or "" if none /
# placeholder (all-zero). Uses python3 (already required for the manifest below).
pinned_engine_sha256() {
  local filename="$1" triple="$2"
  python3 - "$filename" "$triple" "${ROOT_DIR}/release-assets/miners.json" <<'PY'
import json, sys
filename, triple, path = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    m = json.load(open(path))
except Exception:
    sys.exit(0)
for e in m.get("engines", []):
    if e.get("filename") == filename and e.get("target") == triple:
        sha = (e.get("sha256") or "").strip().lower()
        if e.get("_placeholder") or len(sha) != 64 or set(sha) == {"0"}:
            sys.exit(0)  # placeholder / no real pin
        print(sha)
        sys.exit(0)
PY
}

# Stage a bundled engine (xmrig | kawpowminer) for `triple` into `dest`, VERIFYING
# its SHA-256 against the pin in miners.json (fail-closed). The source is the
# committed release-assets/<triple>/<filename> OR an ALICE_MINER_<ENGINE>_BIN[_<triple>]
# override. Echoes the staged path on success, "" when the engine is not supplied
# for this triple (the artifact still ships; the lane surfaces "not installed").
# A present-but-unpinned (placeholder) or mismatched binary ABORTS the build.
stage_engine() {
  local engine="$1" triple="$2" dest="$3" want_exe="$4"   # engine: xmrig|kawpowminer
  local fname="${engine}"; [[ "${want_exe}" == "1" ]] && fname="${engine}.exe"
  local src="${ROOT_DIR}/release-assets/${triple}/${fname}"
  if [[ ! -f "${src}" ]]; then
    # explicit per-triple override (a local path), then a generic one.
    local up; up="$(echo "${engine}" | tr 'a-z' 'A-Z')"
    local var="ALICE_MINER_${up}_BIN_$(echo "${triple}" | tr '-' '_')"
    local val="${!var:-}"
    [[ -z "${val}" ]] && { var="ALICE_MINER_${up}_BIN"; val="${!var:-}"; }
    [[ -n "${val}" && -f "${val}" ]] && src="${val}"
  fi
  [[ -f "${src}" ]] || { echo ""; return; }

  local pin act; pin="$(pinned_engine_sha256 "${fname}" "${triple}")"; act="$(sha256_of "${src}")"
  if [[ -z "${pin}" ]]; then
    echo "  !! ${fname} for ${triple} has NO real pin in release-assets/miners.json (placeholder?) — refusing to bundle an unverifiable engine" >&2
    echo "     (commit the real binary + its SHA-256, or supply ALICE_MINER_${up}_BIN; the lane stays 'not installed' until then.)" >&2
    exit 1
  fi
  if [[ "${pin}" != "${act}" ]]; then
    echo "  !! ${fname} SHA-256 mismatch for ${triple}: pinned=${pin} actual=${act} — refusing to bundle" >&2
    exit 1
  fi
  cp "${src}" "${dest}/${fname}"
  [[ "${want_exe}" == "1" ]] || chmod +x "${dest}/${fname}"
  echo "${dest}/${fname}"
}

# Map a platform key -> rust target triple + artifact filename.
target_triple() {
  case "$1" in
    macos-arm64)     echo "aarch64-apple-darwin" ;;
    macos-x86_64)    echo "x86_64-apple-darwin" ;;
    linux-x86_64)    echo "x86_64-unknown-linux-gnu" ;;
    windows-x86_64)  echo "x86_64-pc-windows-msvc" ;;
    *) echo "" ;;
  esac
}
artifact_name() {
  case "$1" in
    macos-arm64)     echo "AliceMiner-macos-arm64.zip" ;;
    macos-x86_64)    echo "AliceMiner-macos-x86_64.zip" ;;
    linux-x86_64)    echo "AliceMiner-linux-x86_64.tar.gz" ;;
    windows-x86_64)  echo "AliceMiner-windows-x86_64.zip" ;;
    *) echo "" ;;
  esac
}

# ── Args ────────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)       VERSION="$2"; shift 2 ;;
    --min-supported) MIN_SUPPORTED="$2"; shift 2 ;;
    --notes-file)    NOTES_FILE="$2"; shift 2 ;;
    --targets)       TARGETS="$2"; shift 2 ;;
    --out)           OUT_DIR="$2"; shift 2 ;;
    --repo)          REPO="$2"; shift 2 ;;
    --base-url)      BASE_URL="$2"; shift 2 ;;
    --sign)          DO_SIGN=1; shift ;;
    --publish)       DO_PUBLISH=1; shift ;;
    -h|--help)       sed -n '2,52p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "${VERSION}" ]]; then
  # Default to the GUI crate version so the manifest never drifts from the binary.
  VERSION="$(grep -m1 '^version' "${GUI_CRATE_DIR}/Cargo.toml" | sed -E 's/version *= *"([^"]+)".*/\1/')"
fi
[[ -z "${MIN_SUPPORTED}" ]] && MIN_SUPPORTED="${VERSION}"
# Default targets to the platform key matching the build host.
if [[ -z "${TARGETS}" ]]; then
  case "${HOST_TRIPLE}" in
    aarch64-apple-darwin)     TARGETS="macos-arm64" ;;
    x86_64-apple-darwin)      TARGETS="macos-x86_64" ;;
    x86_64-unknown-linux-gnu) TARGETS="linux-x86_64" ;;
    *) echo "could not infer target from host '${HOST_TRIPLE}'; pass --targets" >&2; exit 1 ;;
  esac
fi

RELEASED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
NOTES="$( [[ -n "${NOTES_FILE}" && -f "${NOTES_FILE}" ]] && cat "${NOTES_FILE}" || echo "Alice Miner ${VERSION}." )"

echo "── Alice Miner release ${VERSION} ──────────────────────────────────────"
echo "targets       : ${TARGETS}"
echo "min_supported : ${MIN_SUPPORTED}"
echo "out           : ${OUT_DIR}"
echo "base url      : ${BASE_URL:-<unset — set --base-url / ALICE_RELEASE_BASE_URL>}"
echo "sign          : ${DO_SIGN}    publish: ${DO_PUBLISH}"
echo

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

# ── 1+2. Build + package per target ─────────────────────────────────────────
for plat in ${TARGETS}; do
  triple="$(target_triple "${plat}")"
  artifact="$(artifact_name "${plat}")"
  [[ -z "${triple}" || -z "${artifact}" ]] && { echo "unknown platform: ${plat}" >&2; exit 1; }

  echo "Building ${plat} (${triple})…"
  ( cd "${ROOT_DIR}" && cargo build --release --target "${triple}" -p alice-miner-gui )

  stage="${OUT_DIR}/stage-${plat}"
  rm -rf "${stage}"; mkdir -p "${stage}"

  case "${plat}" in
    macos-*)
      app="${stage}/AliceMiner.app"
      mkdir -p "${app}/Contents/MacOS" "${app}/Contents/Resources"
      cp "${ROOT_DIR}/target/${triple}/release/${GUI_BIN}" "${app}/Contents/MacOS/AliceMiner"
      chmod +x "${app}/Contents/MacOS/AliceMiner"
      # Bundled engines beside the binary in MacOS/ (binaries.rs resolves them as
      # siblings of the exe). xmrig = CPU-XMR (proven); kawpowminer = GPU-RVN
      # (when a pinned build is supplied). Each is SHA-pin-verified before copy.
      xb="$(stage_engine xmrig "${triple}" "${app}/Contents/MacOS" 0)"
      [[ -n "${xb}" ]] && echo "  + bundled xmrig (SHA-pinned $(sha256_of "${xb}" | cut -c1-12)…)" \
                       || echo "  ~ no xmrig for ${triple} — CPU lane surfaces 'not installed'"
      kb="$(stage_engine kawpowminer "${triple}" "${app}/Contents/MacOS" 0)"
      [[ -n "${kb}" ]] && echo "  + bundled kawpowminer (SHA-pinned $(sha256_of "${kb}" | cut -c1-12)…)" \
                       || echo "  ~ no kawpowminer for ${triple} — GPU lane stays unavailable"
      # App icon → Resources + CFBundleIconFile so Launchpad/Finder/Dock show the
      # Alice mark on a dark tile (committed assets/macos/AliceMiner.icns).
      icns="${ROOT_DIR}/assets/macos/AliceMiner.icns"
      if [[ -f "${icns}" ]]; then
        cp "${icns}" "${app}/Contents/Resources/AliceMiner.icns"
        echo "  + bundled app icon (AliceMiner.icns)"
      else
        echo "  ~ no app icon (${icns} missing) — run scripts/build_macos_icon.sh first"
      fi
      cat > "${app}/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>Alice Miner</string>
  <key>CFBundleDisplayName</key><string>Alice Miner</string>
  <key>CFBundleIdentifier</key><string>org.aliceprotocol.miner</string>
  <key>CFBundleVersion</key><string>${VERSION}</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundleExecutable</key><string>AliceMiner</string>
  <key>CFBundleIconFile</key><string>AliceMiner</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
      # Ad-hoc sign inner-first then the bundle (NO --deep) — seals the nested
      # engines before the outer bundle (mirrors alice-release::adhoc_codesign).
      "${ROOT_DIR}/scripts/adhoc_sign_macos.sh" "${app}"
      # Zip the bundle preserving metadata (matches the in-app updater's ditto).
      ( cd "${stage}" && ditto -c -k --keepParent "AliceMiner.app" "${OUT_DIR}/${artifact}" )
      ;;
    linux-x86_64)
      d="${stage}/AliceMiner"; mkdir -p "${d}"
      cp "${ROOT_DIR}/target/${triple}/release/${GUI_BIN}" "${d}/AliceMiner"
      chmod +x "${d}/AliceMiner"
      cp "${GUI_CRATE_DIR}/assets/brand/alice-logo.svg" "${d}/"
      # Bundled engines as siblings of the exe (SHA-pin-verified before copy).
      xb="$(stage_engine xmrig "${triple}" "${d}" 0)"
      [[ -n "${xb}" ]] && echo "  + bundled xmrig (SHA-pinned $(sha256_of "${xb}" | cut -c1-12)…)" \
                       || echo "  ~ no xmrig for ${triple} — CPU lane surfaces 'not installed'"
      kb="$(stage_engine kawpowminer "${triple}" "${d}" 0)"
      [[ -n "${kb}" ]] && echo "  + bundled kawpowminer (SHA-pinned $(sha256_of "${kb}" | cut -c1-12)…)" \
                       || echo "  ~ no kawpowminer for ${triple} — GPU lane stays unavailable"
      # GPU-PRL pearlhash mainline (SRBMiner-MULTI): fetched from archive_url and
      # SHA-pin-verified (archive, then extracted binary) by stage_gpu_prl.sh.
      # Fail-closed — any mismatch exits non-zero. NOT committed into git (~18MB).
      "${ROOT_DIR}/scripts/stage_gpu_prl.sh" "${triple}" "${d}"
      cat > "${d}/AliceMiner.desktop" <<EOF
[Desktop Entry]
Name=Alice Miner
Exec=AliceMiner
Icon=alice-logo
Type=Application
Categories=Utility;
EOF
      cat > "${d}/run.sh" <<'EOF'
#!/usr/bin/env bash
cd "$(dirname "$0")" && ./AliceMiner
EOF
      chmod +x "${d}/run.sh"
      ( cd "${stage}" && tar -czf "${OUT_DIR}/${artifact}" "AliceMiner" )
      ;;
    windows-x86_64)
      d="${stage}/AliceMiner"; mkdir -p "${d}"
      cp "${ROOT_DIR}/target/${triple}/release/${GUI_BIN}.exe" "${d}/AliceMiner.exe"
      cp "${GUI_CRATE_DIR}/assets/brand/alice-logo.svg" "${d}/"
      # WINDOWS: NO xmrig.exe (Defender/SmartScreen PUA). The CPU lane is an
      # on-demand pinned-SHA download at runtime (PLAN §6 D-Windows). Only the
      # GPU engine (kawpowminer.exe) is bundled, when a pinned build is supplied.
      kb="$(stage_engine kawpowminer "${triple}" "${d}" 1)"
      [[ -n "${kb}" ]] && echo "  + bundled kawpowminer.exe (SHA-pinned $(sha256_of "${kb}" | cut -c1-12)…)" \
                       || echo "  ~ no kawpowminer.exe for ${triple} — GPU lane stays unavailable"
      # GPU-PRL pearlhash mainline (SRBMiner-MULTI.exe): fetched + SHA-pin-verified
      # by stage_gpu_prl.sh (fail-closed). NOT committed into git.
      "${ROOT_DIR}/scripts/stage_gpu_prl.sh" "${triple}" "${d}"
      echo "  · windows: xmrig.exe intentionally NOT bundled (on-demand download)"
      # zip via `ditto` on a macOS host, else `zip`.
      if command -v ditto >/dev/null 2>&1; then
        ( cd "${stage}" && ditto -c -k --keepParent "AliceMiner" "${OUT_DIR}/${artifact}" )
      else
        ( cd "${stage}" && zip -r "${OUT_DIR}/${artifact}" "AliceMiner" >/dev/null )
      fi
      ;;
  esac
  rm -rf "${stage}"
  echo "  -> ${OUT_DIR}/${artifact}"
done

# ── 3. SHA256SUMS ───────────────────────────────────────────────────────────
echo "Writing SHA256SUMS…"
(
  cd "${OUT_DIR}"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum ./*.zip ./*.tar.gz 2>/dev/null > SHA256SUMS || true
  else
    : > SHA256SUMS
    for f in ./*.zip ./*.tar.gz; do
      [[ -e "$f" ]] || continue
      printf '%s  %s\n' "$(shasum -a 256 "$f" | awk '{print $1}')" "${f#./}" >> SHA256SUMS
    done
  fi
  cat SHA256SUMS
)

# ── 4. latest.json (the signed update manifest) ─────────────────────────────
# The artifacts[] entry per platform: { platform, url, sha256, size }.
echo "Generating latest.json…"
artifacts_json=""
for plat in ${TARGETS}; do
  artifact="$(artifact_name "${plat}")"
  f="${OUT_DIR}/${artifact}"
  [[ -e "${f}" ]] || continue
  sum="$(sha256_of "${f}")"
  size="$(wc -c < "${f}" | tr -d ' ')"
  url="${BASE_URL:+${BASE_URL%/}/}${artifact}"
  entry="$(printf '{"platform":"%s","url":"%s","sha256":"%s","size":%s}' "${plat}" "${url}" "${sum}" "${size}")"
  artifacts_json="${artifacts_json:+${artifacts_json},}${entry}"
done

# NOTE: the manifest BYTES are what gets signed (raw ed25519, no pre-hash). Keep
# this serialization stable; the Miner re-serializes via serde for comparison
# only in tests, never for verification (it verifies the bytes as fetched).
NOTES_ESCAPED="$(printf '%s' "${NOTES}" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')"
cat > "${OUT_DIR}/latest.json" <<JSON
{"schema":1,"product":"${PRODUCT}","version":"${VERSION}","min_supported":"${MIN_SUPPORTED}","released":"${RELEASED}","notes":${NOTES_ESCAPED},"artifacts":[${artifacts_json}]}
JSON
echo "  -> ${OUT_DIR}/latest.json"
cat "${OUT_DIR}/latest.json"; echo

# ── 5. OFFLINE ed25519 signing ──────────────────────────────────────────────
# Sign the RAW bytes of latest.json (and SHA256SUMS), producing detached base64
# signatures. MUST run on a trusted, offline machine holding the release private
# key. The matching public key is embedded in the Miner (RELEASE_PUBKEY_B64).
print_sign_steps() {
  cat <<STEPS

  ── OFFLINE SIGNING (run on the trusted machine holding the release key) ──
  KEY=${RELEASE_KEY}

  # ed25519 raw signature over the manifest bytes -> base64 detached .sig
  openssl pkeyutl -sign -inkey "\$KEY" -rawin \\
      -in  "${OUT_DIR}/latest.json" \\
      -out "${OUT_DIR}/latest.json.sig.bin"
  base64 < "${OUT_DIR}/latest.json.sig.bin" | tr -d '\n' > "${OUT_DIR}/latest.json.sig"

  # (Optional but recommended) also sign SHA256SUMS the same way:
  openssl pkeyutl -sign -inkey "\$KEY" -rawin \\
      -in  "${OUT_DIR}/SHA256SUMS" \\
      -out "${OUT_DIR}/SHA256SUMS.sig.bin"
  base64 < "${OUT_DIR}/SHA256SUMS.sig.bin" | tr -d '\n' > "${OUT_DIR}/SHA256SUMS.sig"

  # Sanity check against the embedded public key (prints 'Signature Verified
  # Successfully'). RELEASE_PUBKEY_B64 is the raw 32 bytes; rebuild a PEM with the
  # fixed ed25519 SPKI prefix, then verify:
  #   PUB=8P+XmZZFEsUHLmqeB62Xqr5GnwW5K9vf2sQHvRzfi5k=    (RELEASE_PUBKEY_B64)
  #   { printf '\\x30\\x2a\\x30\\x05\\x06\\x03\\x2b\\x65\\x70\\x03\\x21\\x00'; \\
  #     printf '%s' "\$PUB" | base64 -d; } | openssl pkey -pubin -inform DER -out alice-update.pub.pem
  #   openssl pkeyutl -verify -pubin -inkey alice-update.pub.pem -rawin \\
  #       -in "${OUT_DIR}/latest.json" -sigfile "${OUT_DIR}/latest.json.sig.bin"
STEPS
}

if [[ "${DO_SIGN}" -eq 1 ]]; then
  if [[ -n "${CI:-}" ]]; then
    echo "REFUSING to sign in CI (the release key is offline-only)." >&2
    exit 1
  fi
  if [[ ! -f "${RELEASE_KEY}" ]]; then
    echo "REFUSING to sign: release key not found at ${RELEASE_KEY}." >&2
    print_sign_steps
    exit 1
  fi
  echo "Signing latest.json + SHA256SUMS with offline key ${RELEASE_KEY}…"
  openssl pkeyutl -sign -inkey "${RELEASE_KEY}" -rawin \
      -in "${OUT_DIR}/latest.json" -out "${OUT_DIR}/latest.json.sig.bin"
  base64 < "${OUT_DIR}/latest.json.sig.bin" | tr -d '\n' > "${OUT_DIR}/latest.json.sig"
  openssl pkeyutl -sign -inkey "${RELEASE_KEY}" -rawin \
      -in "${OUT_DIR}/SHA256SUMS" -out "${OUT_DIR}/SHA256SUMS.sig.bin"
  base64 < "${OUT_DIR}/SHA256SUMS.sig.bin" | tr -d '\n' > "${OUT_DIR}/SHA256SUMS.sig"
  rm -f "${OUT_DIR}/latest.json.sig.bin" "${OUT_DIR}/SHA256SUMS.sig.bin"
  echo "  -> ${OUT_DIR}/latest.json.sig"
  echo "  -> ${OUT_DIR}/SHA256SUMS.sig"
else
  echo "NOTE: not signing (no --sign). The offline signing steps:"
  print_sign_steps
fi

# ── 6. Publish to GitHub Releases ───────────────────────────────────────────
publish_files=( "${OUT_DIR}"/*.zip "${OUT_DIR}"/*.tar.gz "${OUT_DIR}/SHA256SUMS" "${OUT_DIR}/latest.json" )
[[ -f "${OUT_DIR}/latest.json.sig" ]] && publish_files+=( "${OUT_DIR}/latest.json.sig" )
[[ -f "${OUT_DIR}/SHA256SUMS.sig" ]] && publish_files+=( "${OUT_DIR}/SHA256SUMS.sig" )

if [[ "${DO_PUBLISH}" -eq 1 ]]; then
  if [[ ! -f "${OUT_DIR}/latest.json.sig" ]]; then
    echo "REFUSING to publish: latest.json.sig is missing (sign first)." >&2
    exit 1
  fi
  command -v gh >/dev/null 2>&1 || { echo "gh CLI not found" >&2; exit 1; }
  TAG="v${VERSION}"
  repo_args=(); [[ -n "${REPO}" ]] && repo_args=(--repo "${REPO}")
  echo "Creating GitHub release ${TAG}…"
  gh release create "${TAG}" "${repo_args[@]}" \
     --title "Alice Miner ${VERSION}" \
     --notes "${NOTES}" \
     "${publish_files[@]}"
  echo "Published ${TAG} with $(printf '%s ' "${publish_files[@]##*/}")"
else
  echo
  echo "NOTE: not publishing (no --publish). To publish after signing:"
  echo "  gh release create v${VERSION} ${REPO:+--repo ${REPO} }\\"
  echo "     --title \"Alice Miner ${VERSION}\" --notes \"…\" \\"
  echo "     ${publish_files[*]##*/}"
fi

echo
echo "Done. Artifacts in ${OUT_DIR}"
