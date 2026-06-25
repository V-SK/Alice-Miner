#!/usr/bin/env bash
#
# stage_gpu_prl.sh — fetch + verify + stage the SRBMiner-MULTI (GPU-PRL pearlhash
# mainline) engine for ONE target triple, reading every pin straight from
# release-assets/miners.json so the packaging never drifts from the runtime
# integrity check baked into the binary (binaries.rs / SRBMINER_BINARY_NAME).
#
# Unlike xmrig / kawpowminer (single pre-built asset, SHA-pinned), SRBMiner is
# shipped by the vendor as an archive. The gpu-prl entries in miners.json carry:
#   archive_url             — vendor release archive (github.com/doktor83/...)
#   archive_sha256          — SHA-256 of that archive
#   binary_path_in_archive  — member path of the engine inside the archive
#   sha256                  — SHA-256 of the EXTRACTED binary (== the runtime pin)
#   filename                — on-disk name the resolver expects (SRBMiner-MULTI[.exe])
#
# This script: download archive_url -> verify archive_sha256 -> extract
# binary_path_in_archive -> verify its sha256 -> copy to <dest>/<filename>.
# ANY failure (missing pin, bad archive hash, missing member, bad binary hash)
# aborts with a non-zero exit so a wrong/tampered/placeholder engine can NEVER be
# packaged (fail-closed, never silent). We do NOT commit the ~18-24MB binary into
# git — it is fetched-at-packaging, exactly like kawpowminer.
#
# SRBMiner ships NO macOS build, so GPU-PRL is Linux/Windows ONLY. For
# aarch64-apple-darwin (or any triple with no gpu-prl entry) this is a clean
# no-op (exit 0) — the capability matrix reports GPU-PRL "Unavailable" on Apple.
#
# Usage: scripts/stage_gpu_prl.sh <target-triple> <dest-dir>
#   e.g. scripts/stage_gpu_prl.sh x86_64-unknown-linux-gnu engine-stage
#
# The override escape hatch ALICE_MINER_PRL_BIN[_<triple>] (a local path to an
# already-extracted SRBMiner-MULTI binary) skips the download; the extracted
# binary is STILL SHA-verified against the pin before it is staged.
#
set -euo pipefail

TRIPLE="${1:?usage: stage_gpu_prl.sh <target-triple> <dest-dir>}"
DEST="${2:?usage: stage_gpu_prl.sh <target-triple> <dest-dir>}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${ROOT_DIR}/release-assets/miners.json"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# Emit one TSV line "filename<TAB>sha256<TAB>archive_url<TAB>archive_sha256<TAB>binary_path_in_archive"
# for the gpu-prl entry of TRIPLE, or nothing if there is no such entry. Pins that
# are placeholder / not 64 hex / all-zero are emitted as empty so the caller fails.
prl_entry() {
  python3 - "$MANIFEST" "$TRIPLE" <<'PY'
import json, sys
path, triple = sys.argv[1], sys.argv[2]
m = json.load(open(path))
for e in m.get("engines", []):
    if e.get("kind") == "gpu-prl" and e.get("target") == triple:
        def pin(v):
            v = (v or "").strip().lower()
            return "" if (len(v) != 64 or set(v) == {"0"}) else v
        if e.get("_placeholder"):
            sha = ""
        else:
            sha = pin(e.get("sha256"))
        print("\t".join([
            e.get("filename", ""),
            sha,
            e.get("archive_url", ""),
            pin(e.get("archive_sha256")),
            e.get("binary_path_in_archive", ""),
        ]))
        break
PY
}

line="$(prl_entry)"
if [ -z "${line}" ]; then
  echo "  (no gpu-prl engine for ${TRIPLE} — SRBMiner has no build here; lane stays Unavailable)"
  exit 0
fi

IFS=$'\t' read -r FILENAME BIN_SHA ARCHIVE_URL ARCHIVE_SHA BIN_PATH <<<"${line}"

# Fail-closed on a placeholder / malformed pin (never package an unverifiable engine).
if [ -z "${FILENAME}" ] || [ -z "${BIN_SHA}" ]; then
  echo "::error::gpu-prl for ${TRIPLE}: missing/placeholder binary sha256 in miners.json — refusing to package an unverifiable engine" >&2
  exit 1
fi

mkdir -p "${DEST}"
OUT="${DEST}/${FILENAME}"
if [ -f "${OUT}" ]; then
  echo "  (gpu-prl ${FILENAME} already staged for ${TRIPLE})"
  exit 0
fi

# Override escape hatch: a local path to an already-extracted SRBMiner-MULTI.
# Per-triple var (ALICE_MINER_PRL_BIN_<triple>) wins; else the generic one.
up_triple="$(echo "${TRIPLE}" | tr '-' '_')"
per_triple_var="ALICE_MINER_PRL_BIN_${up_triple}"
override="${!per_triple_var:-${ALICE_MINER_PRL_BIN:-}}"
if [ -n "${override}" ] && [ -f "${override}" ]; then
  act="$(sha256_of "${override}")"
  echo "  gpu-prl override: ${override} (sha256=${act})"
  if [ "${act}" != "${BIN_SHA}" ]; then
    echo "::error::gpu-prl override binary SHA-256 mismatch for ${TRIPLE}: pinned=${BIN_SHA} actual=${act}" >&2
    exit 1
  fi
  cp "${override}" "${OUT}"
  case "${FILENAME}" in *.exe) :;; *) chmod +x "${OUT}";; esac
  echo "  + staged gpu-prl ${FILENAME} from override (SHA-pinned)"
  exit 0
fi

# Need the download path: archive_url + archive_sha256 + binary_path_in_archive.
if [ -z "${ARCHIVE_URL}" ] || [ -z "${ARCHIVE_SHA}" ] || [ -z "${BIN_PATH}" ]; then
  echo "::error::gpu-prl for ${TRIPLE}: incomplete fetch spec in miners.json (archive_url/archive_sha256/binary_path_in_archive) — cannot stage" >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
ARCHIVE="${WORK}/$(basename "${ARCHIVE_URL}")"

echo "  Fetching gpu-prl archive: ${ARCHIVE_URL}"
if command -v curl >/dev/null 2>&1; then
  curl -fL --retry 3 -o "${ARCHIVE}" "${ARCHIVE_URL}"
else
  wget -O "${ARCHIVE}" "${ARCHIVE_URL}"
fi

act_arc="$(sha256_of "${ARCHIVE}")"
echo "  archive sha256: pinned=${ARCHIVE_SHA} fetched=${act_arc}"
if [ "${ARCHIVE_SHA}" != "${act_arc}" ]; then
  echo "::error::gpu-prl archive SHA-256 mismatch for ${TRIPLE} — refusing to extract a tampered archive" >&2
  exit 1
fi

# Extract just the one member (.tar.gz for Linux, .zip for Windows).
EXTRACT_DIR="${WORK}/x"
mkdir -p "${EXTRACT_DIR}"
case "${ARCHIVE}" in
  *.tar.gz|*.tgz) tar -xzf "${ARCHIVE}" -C "${EXTRACT_DIR}" "${BIN_PATH}" ;;
  *.zip)          unzip -o -q "${ARCHIVE}" "${BIN_PATH}" -d "${EXTRACT_DIR}" ;;
  *) echo "::error::unsupported archive type for ${ARCHIVE}" >&2; exit 1 ;;
esac

EXTRACTED="${EXTRACT_DIR}/${BIN_PATH}"
if [ ! -f "${EXTRACTED}" ]; then
  echo "::error::gpu-prl: member ${BIN_PATH} not found in archive for ${TRIPLE}" >&2
  exit 1
fi

act_bin="$(sha256_of "${EXTRACTED}")"
echo "  binary sha256: pinned=${BIN_SHA} extracted=${act_bin}"
if [ "${BIN_SHA}" != "${act_bin}" ]; then
  echo "::error::gpu-prl extracted binary SHA-256 mismatch for ${TRIPLE} — refusing to stage" >&2
  exit 1
fi

cp "${EXTRACTED}" "${OUT}"
case "${FILENAME}" in *.exe) :;; *) chmod +x "${OUT}";; esac
echo "  + staged gpu-prl ${FILENAME} for ${TRIPLE} (SHA-pinned ${BIN_SHA})"
