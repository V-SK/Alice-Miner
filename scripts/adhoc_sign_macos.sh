#!/usr/bin/env bash
#
# adhoc_sign_macos.sh — ad-hoc codesign an Alice Miner macOS bundle (or a bare
# Mach-O binary) INNER-FIRST, then the bundle, WITHOUT `--deep`.
#
# Why inner-first and not `--deep`:
#   `codesign --deep` is deprecated by Apple and signs nested code in an order
#   that does not reliably seal helper Mach-O binaries (the bundled xmrig /
#   kawpowminer engines) before the outer bundle. We instead find every Mach-O
#   under the bundle, sign the deepest ones first, and seal the bundle last so
#   its signature covers already-signed insides. This matches
#   `alice-release::adhoc_codesign` (the self-updater), so an in-app self-update
#   produces a byte-for-byte-equivalent signing result.
#
# Trust model: this is an AD-HOC signature (`-s -`), NOT a Developer ID identity.
# It carries no Apple certificate; it exists only so the binary is runnable on
# Apple Silicon (which refuses unsigned arm64 Mach-O) after the user clears
# quarantine. The real integrity anchor is the ed25519-signed release manifest
# (latest.json.sig), verified against the embedded public key before any artifact
# is signed or run; and each bundled engine's SHA-256 is pinned + checked before
# spawn (release-assets/miners.json → baked into the binary).
#
# Usage:
#   scripts/adhoc_sign_macos.sh path/to/AliceMiner.app
#   scripts/adhoc_sign_macos.sh path/to/bare-binary
#
set -euo pipefail

TARGET="${1:-}"
if [[ -z "${TARGET}" ]]; then
  echo "usage: $0 <AliceMiner.app | binary>" >&2
  exit 2
fi
if [[ ! -e "${TARGET}" ]]; then
  echo "error: no such path: ${TARGET}" >&2
  exit 1
fi
if ! command -v codesign >/dev/null 2>&1; then
  echo "error: codesign not found (run on macOS)" >&2
  exit 1
fi

# Ad-hoc identity; no timestamp (offline / no network dependency).
SIGN_ARGS=(--force --timestamp=none -s -)

sign_one() {
  local path="$1"
  echo "  codesign ${path}"
  codesign "${SIGN_ARGS[@]}" "${path}"
}

if [[ -d "${TARGET}" ]]; then
  # Bundle: sign every nested Mach-O deepest-first, then the bundle itself.
  # Collect Mach-O paths with their depth (slash count), sort by depth desc so
  # children sign before parents, then strip the depth prefix. `file` identifies
  # Mach-O (thin or universal). Newline-delimited is fine: bundle paths produced
  # by our release pipeline contain no newlines.
  echo "Signing nested Mach-O (inner-first) under ${TARGET}…"
  # The bundled mining ENGINES (xmrig / kawpowminer / SRBMiner-MULTI) ship with
  # their OWN committed ad-hoc signature, and the SHA-256 of those exact bytes is
  # the pin baked into the client (release-assets/miners.json). Re-signing them
  # here mutates their bytes — and ad-hoc codesign is NON-deterministic across
  # macos runner images — so the on-disk SHA drifts from the pin and the runtime
  # integrity check fail-closes ("Start does nothing", the v0.3.1 macOS bug).
  # SKIP engine basenames: sign only OUR Mach-O (AliceMiner / alice-miner /
  # alice-miner-cli). The final bundle seal below is NOT --deep, so it records the
  # engines' existing hashes in CodeResources without re-signing the engine bytes.
  is_engine_basename() {
    case "$(basename "$1")" in
      xmrig|xmrig.exe|kawpowminer|kawpowminer.exe|SRBMiner-MULTI|SRBMiner-MULTI.exe) return 0 ;;
      *) return 1 ;;
    esac
  }
  machos=""
  while IFS= read -r f; do
    if file -b "${f}" | grep -q 'Mach-O'; then
      if is_engine_basename "${f}"; then
        echo "  skip engine (keep committed signature == pin): ${f}"
        continue
      fi
      depth=$(printf '%s' "${f}" | tr -cd '/' | wc -c | tr -d ' ')
      machos+="${depth} ${f}"$'\n'
    fi
  done < <(find "${TARGET}" -type f)

  if [[ -n "${machos}" ]]; then
    # Sort by leading depth number (descending), then drop it and sign.
    printf '%s' "${machos}" | sort -rn | while IFS=' ' read -r _depth path; do
      [[ -n "${path}" ]] && sign_one "${path}"
    done
  fi

  echo "Sealing bundle ${TARGET}…"
  sign_one "${TARGET}"
else
  # Bare binary.
  sign_one "${TARGET}"
fi

echo "Verifying signature…"
codesign --verify --verbose=2 "${TARGET}"
echo "OK: ad-hoc signed ${TARGET}"
