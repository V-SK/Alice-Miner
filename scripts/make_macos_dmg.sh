#!/usr/bin/env bash
#
# make_macos_dmg.sh — build the drag-to-Applications disk image.
#
# WHY A DMG WHEN WE ALREADY SHIP A ZIP
# ------------------------------------
# Not because the zip is malformed — `ditto -c -k --keepParent` round-trips a
# signed bundle correctly, exec bits and all (scripts/verify_macos_bundle.sh
# proves it every build). The DMG fixes a different, real problem: WHERE the app
# ends up.
#
# A zip is extracted in place, so the overwhelmingly common flow is
# "double-click AliceMiner.app inside ~/Downloads". A quarantined bundle launched
# from ~/Downloads is App-Translocated: macOS runs it from a randomised read-only
# nullfs mount under /private/var/folders/…/AppTranslocation/<UUID>/d/. The
# symptoms are the ones people actually report — "it opens and does nothing",
# "my settings reset every launch", and self-update failing against a read-only
# path. Worse, the translocation mount OUTLIVES the process, so a later `open`
# can resolve a path whose backing bundle has moved, producing LaunchServices
# errors that name the wrong cause.
#
# A DMG makes "drag it into /Applications" the only obvious gesture. Finder's
# drag-copy out of a mounted image is a user-initiated move, which is exactly the
# condition that ends translocation. The app lands somewhere writable and stable,
# and the whole translocation failure class disappears.
#
# WHAT IT DOES NOT DO: it does not get past Gatekeeper. The bundle is still
# ad-hoc signed with no notarization ticket, so the first launch is still refused
# and the user still has to clear quarantine or use Privacy & Security ->
# Open Anyway. Ship the DMG for the install-location win; do not tell anyone it
# fixes the "unidentified developer" wall, because it does not.
#
# Usage:
#   scripts/make_macos_dmg.sh <path/to/AliceMiner.app> <out.dmg> [version]
#
set -euo pipefail

APP="${1:-}"
OUT="${2:-}"
VERSION="${3:-}"

if [[ -z "${APP}" || -z "${OUT}" ]]; then
  echo "usage: $0 <AliceMiner.app> <out.dmg> [version]" >&2
  exit 2
fi
if [[ ! -d "${APP}" ]]; then
  echo "error: not a bundle: ${APP}" >&2
  exit 1
fi
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: hdiutil is macOS-only" >&2
  exit 1
fi

if [[ -z "${VERSION}" ]]; then
  VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "${APP}/Contents/Info.plist" 2>/dev/null || echo "")"
fi
VOLNAME="Alice Miner${VERSION:+ ${VERSION}}"

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/alice-dmg.XXXXXX")"
trap 'rm -rf "${STAGE}"' EXIT

# `ditto` (not cp -R) so the signature, xattrs and modes come across intact.
ditto "${APP}" "${STAGE}/$(basename "${APP}")"
# The /Applications symlink is the whole point of the format: it turns "install"
# into one drag, and that drag is what clears App Translocation.
ln -s /Applications "${STAGE}/Applications"

rm -f "${OUT}"
hdiutil create \
  -volname "${VOLNAME}" \
  -srcfolder "${STAGE}" \
  -fs HFS+ \
  -format UDZO \
  -imagekey zlib-level=9 \
  -ov \
  -quiet \
  "${OUT}"

echo "built ${OUT} (volume: ${VOLNAME})"

# Prove the bundle inside the image is still intact — a DMG that ships a broken
# app is no better than a zip that does.
MNT="$(mktemp -d "${TMPDIR:-/tmp}/alice-dmg-check.XXXXXX")"
if hdiutil attach "${OUT}" -nobrowse -readonly -mountpoint "${MNT}" -quiet; then
  if codesign --verify --deep --strict "${MNT}/$(basename "${APP}")" >/dev/null 2>&1; then
    echo "  ok: signature verifies inside the mounted image"
  else
    echo "  FAIL: signature does not verify inside the mounted image" >&2
    hdiutil detach "${MNT}" -quiet >/dev/null 2>&1 || true
    rmdir "${MNT}" 2>/dev/null || true
    exit 1
  fi
  hdiutil detach "${MNT}" -quiet >/dev/null 2>&1 || true
fi
rmdir "${MNT}" 2>/dev/null || true
