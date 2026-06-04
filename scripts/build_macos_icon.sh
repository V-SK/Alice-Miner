#!/usr/bin/env bash
#
# build_macos_icon.sh — render assets/macos/AliceMiner.icns from the Alice mark.
#
# Unlike the Wallet (which rasterizes the bare orange-on-transparent SVG), the
# Miner icon composites the mark onto a TASTEFUL DARK ROUNDED-RECT tile with a
# faint warm glow, so Launchpad/Finder/Dock show a premium app icon rather than a
# floating glyph. The mark path is lifted verbatim from
# crates/alice-miner-gui/assets/brand/alice-logo.svg (no new brand invented), so
# the icon and the in-app hero mark are the same artwork.
#
# Pipeline: build a composed SVG → `sips` rasterize to 1024 → `sips` downscale to
# every iconset size → `iconutil -c icns`. Pure macOS tooling (matches the
# Wallet's build_macos_icon.sh shape); run on macOS.
#
# Usage:  scripts/build_macos_icon.sh   ->  prints the .icns path on success.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SVG_SRC="${ROOT_DIR}/crates/alice-miner-gui/assets/brand/alice-logo.svg"
OUT_DIR="${ROOT_DIR}/assets/macos"
ICONSET_DIR="${OUT_DIR}/AliceMiner.iconset"
COMPOSED_SVG="${OUT_DIR}/AliceMiner-icon.svg"
BASE_PNG="${OUT_DIR}/AliceMiner-1024.png"

command -v sips     >/dev/null 2>&1 || { echo "error: sips not found (run on macOS)" >&2; exit 1; }
command -v iconutil >/dev/null 2>&1 || { echo "error: iconutil not found (run on macOS)" >&2; exit 1; }
[[ -f "${SVG_SRC}" ]] || { echo "error: brand SVG not found at ${SVG_SRC}" >&2; exit 1; }

mkdir -p "${OUT_DIR}"
rm -rf "${ICONSET_DIR}"; mkdir -p "${ICONSET_DIR}"

# Compose: dark rounded-rect base + warm radial glow + the Alice mark, scaled to
# 60% of the tile and centered. The mark's own viewBox transform
# (translate(0,1024) scale(0.1,-0.1)) is preserved INSIDE an outer
# translate(204.8) scale(0.6) so the path renders exactly as the brand draws it.
python3 - "${SVG_SRC}" "${COMPOSED_SVG}" <<'PY'
import re, sys
src, out = sys.argv[1], sys.argv[2]
d = re.search(r'<path d="([^"]*)"', open(src).read()).group(1)
svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#1F1F23"/>
      <stop offset="1" stop-color="#121214"/>
    </linearGradient>
    <radialGradient id="glow" cx="0.5" cy="0.46" r="0.5">
      <stop offset="0" stop-color="#F97316" stop-opacity="0.22"/>
      <stop offset="1" stop-color="#F97316" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <rect width="1024" height="1024" rx="232" ry="232" fill="url(#bg)"/>
  <rect width="1024" height="1024" rx="232" ry="232" fill="url(#glow)"/>
  <g transform="translate(204.8,204.8) scale(0.6,0.6)">
    <g transform="translate(0,1024) scale(0.1,-0.1)" fill="#F97316">
      <path d="{d}"/>
    </g>
  </g>
</svg>'''
open(out, "w").write(svg)
PY

sips -s format png "${COMPOSED_SVG}" --out "${BASE_PNG}" >/dev/null

make_icon() { sips -z "$1" "$1" "${BASE_PNG}" --out "${ICONSET_DIR}/$2" >/dev/null; }
make_icon 16   icon_16x16.png
make_icon 32   icon_16x16@2x.png
make_icon 32   icon_32x32.png
make_icon 64   icon_32x32@2x.png
make_icon 128  icon_128x128.png
make_icon 256  icon_128x128@2x.png
make_icon 256  icon_256x256.png
make_icon 512  icon_256x256@2x.png
make_icon 512  icon_512x512.png
make_icon 1024 icon_512x512@2x.png

iconutil -c icns "${ICONSET_DIR}" -o "${OUT_DIR}/AliceMiner.icns"
rm -rf "${ICONSET_DIR}" "${BASE_PNG}" "${COMPOSED_SVG}"

echo "${OUT_DIR}/AliceMiner.icns"
