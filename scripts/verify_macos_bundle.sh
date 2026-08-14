#!/usr/bin/env bash
#
# verify_macos_bundle.sh — release-time gate for the macOS artifact.
#
# WHY THIS EXISTS
# ---------------
# Until now nothing in the pipeline ever opened the macOS artifact back up. We
# built `AliceMiner.app`, ad-hoc signed it, `ditto`'d it into a .zip and shipped
# whatever came out. Every property a Mac needs in order to LAUNCH the thing —
# the executable bit on `Contents/MacOS/<CFBundleExecutable>`, that file even
# existing under the name the Info.plist promises, the code signature surviving
# the archive round trip, each nested Mach-O carrying its own signature — was
# assumed, never checked. A break in any of them ships silently and surfaces on
# the user's machine as one of macOS's famously unhelpful errors:
#
#   * `-10827 kLSNoExecutableErr` "The executable is missing" — LaunchServices
#     could not find `Contents/MacOS/<CFBundleExecutable>`. Says "missing" even
#     when a file is plainly there under a DIFFERENT name than the plist claims.
#   * `-47 fBsyErr` from Finder — the generic "could not open" wrapper.
#   * "Launchd job spawn failed" (POSIX 111) — the file is there, the exec bit
#     is not.
#
# So: unpack the artifact exactly the way a user's Mac unpacks it, and assert.
# Anything that would stop a Mac from launching the bundle FAILS THE BUILD here,
# rather than shipping and being diagnosed by a miner over chat.
#
# WHAT THIS CANNOT DO
# -------------------
# It cannot make the app pass Gatekeeper. Alice Miner is AD-HOC signed — no paid
# Apple Developer ID, no notarization ticket — so `spctl --assess` rejects it and
# every user who downloads via a browser has to clear quarantine by hand. That is
# a policy fact about the signing identity, NOT a packaging defect, and no change
# to how we zip can fix it. This script REPORTS that status loudly and honestly;
# it only *enforces* it when run with --require-notarized (i.e. after a Developer
# ID is acquired), so the day we do get one, a regression back to ad-hoc fails
# the build instead of quietly shipping.
#
# Usage:
#   scripts/verify_macos_bundle.sh <artifact.zip|artifact.dmg|AliceMiner.app> [options]
#
# Options:
#   --expect-version X.Y.Z   assert CFBundleShortVersionString == X.Y.Z
#   --expect-arch ARCH       assert the main Mach-O's arch (default: arm64)
#   --source-app PATH        the pre-archive .app; asserts the main executable's
#                            CDHash is byte-identical after the round trip
#   --miners-json PATH       verify bundled engine SHA-256 against these pins
#                            (default: release-assets/miners.json next to the repo)
#   --require-notarized      FAIL (not warn) when the bundle is ad-hoc/unnotarized
#   --keep                   keep the extraction dir (prints the path)
#
set -uo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SELF_DIR}/.." && pwd)"

ARTIFACT=""
EXPECT_VERSION=""
EXPECT_ARCH="arm64"
SOURCE_APP=""
MINERS_JSON="${ROOT_DIR}/release-assets/miners.json"
REQUIRE_NOTARIZED=0
KEEP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --expect-version)   EXPECT_VERSION="${2:-}"; shift 2 ;;
    --expect-arch)      EXPECT_ARCH="${2:-}"; shift 2 ;;
    --source-app)       SOURCE_APP="${2:-}"; shift 2 ;;
    --miners-json)      MINERS_JSON="${2:-}"; shift 2 ;;
    --require-notarized) REQUIRE_NOTARIZED=1; shift ;;
    --keep)             KEEP=1; shift ;;
    -h|--help)          sed -n '1,60p' "$0"; exit 0 ;;
    -*)                 echo "unknown option: $1" >&2; exit 2 ;;
    *)                  ARTIFACT="$1"; shift ;;
  esac
done

if [[ -z "${ARTIFACT}" ]]; then
  echo "usage: $0 <artifact.zip|artifact.dmg|AliceMiner.app> [options]" >&2
  exit 2
fi
if [[ ! -e "${ARTIFACT}" ]]; then
  echo "FAIL: no such artifact: ${ARTIFACT}" >&2
  exit 1
fi
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "FAIL: this gate must run on macOS (needs codesign/ditto/hdiutil)" >&2
  exit 1
fi

FAILURES=0
WARNINGS=0
ok()   { printf '  \033[32mok\033[0m    %s\n' "$*"; }
warn() { printf '  \033[33mWARN\033[0m  %s\n' "$*"; WARNINGS=$((WARNINGS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAILURES=$((FAILURES+1)); }
head2(){ printf '\n\033[1m%s\033[0m\n' "$*"; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/alice-macos-verify.XXXXXX")"
MOUNTED=""
cleanup() {
  [[ -n "${MOUNTED}" ]] && hdiutil detach "${MOUNTED}" -quiet >/dev/null 2>&1
  if [[ "${KEEP}" = 1 ]]; then
    echo "kept extraction: ${WORK}"
  else
    rm -rf "${WORK}"
  fi
}
trap cleanup EXIT

echo "Verifying macOS artifact: ${ARTIFACT}"
echo "  extraction dir: ${WORK}"

# ── 1. Unpack the way a user's Mac unpacks it ────────────────────────────────
head2 "1. unpack"
EXTRACT="${WORK}/x"
mkdir -p "${EXTRACT}"
case "${ARTIFACT}" in
  *.zip)
    # `ditto -x -k` is what Finder's Archive Utility uses. If the exec bit or the
    # signature cannot survive THIS, it cannot survive a double-click either.
    if ditto -x -k "${ARTIFACT}" "${EXTRACT}"; then
      ok "ditto -x -k extracted the zip"
    else
      bad "ditto -x -k failed to extract ${ARTIFACT}"
      exit 1
    fi
    ;;
  *.dmg)
    MOUNTPOINT="${WORK}/mnt"
    mkdir -p "${MOUNTPOINT}"
    if hdiutil attach "${ARTIFACT}" -nobrowse -readonly -mountpoint "${MOUNTPOINT}" -quiet; then
      MOUNTED="${MOUNTPOINT}"
      ok "hdiutil attached the dmg"
    else
      bad "hdiutil attach failed for ${ARTIFACT}"
      exit 1
    fi
    # Copy off the image so the permission/xattr assertions below describe what
    # the user ends up with in /Applications, not the read-only mount.
    ditto "${MOUNTPOINT}" "${EXTRACT}"
    ;;
  *.app|*.app/)
    ditto "${ARTIFACT}" "${EXTRACT}/$(basename "${ARTIFACT%/}")"
    ok "copied the .app directly (no archive round trip exercised)"
    ;;
  *)
    bad "unrecognised artifact type: ${ARTIFACT} (want .zip, .dmg or .app)"
    exit 1
    ;;
esac

# ── 2. Bundle shape ──────────────────────────────────────────────────────────
head2 "2. bundle shape"
APP="${EXTRACT}/AliceMiner.app"
if [[ -d "${APP}" ]]; then
  ok "AliceMiner.app present at the archive root"
else
  found="$(find "${EXTRACT}" -maxdepth 2 -name '*.app' -type d 2>/dev/null | head -1)"
  if [[ -n "${found}" ]]; then
    bad "expected AliceMiner.app at the root, found: ${found#${EXTRACT}/}"
    APP="${found}"
  else
    bad "no .app bundle inside the artifact"
    exit 1
  fi
fi

# `__MACOSX` / AppleDouble `._*` entries mean the archive sequestered resource
# forks. On macOS `ditto -x -k` folds them back into xattrs and deletes the
# directory, so the EXTRACTED tree looks clean either way — the check has to read
# the archive listing, not the extraction. Not fatal (we round-trip fine), but it
# means the packer was not plain `ditto -c -k --keepParent`, and every user who
# unzips with a third-party tool gets visible junk folders. Warn, don't fail.
if [[ "${ARTIFACT}" = *.zip ]]; then
  # NB: capture the listing into a variable first. Piping `zipinfo` straight into
  # `grep -q` under `set -o pipefail` makes the pipeline report FAILURE whenever
  # grep matches early and SIGPIPEs the producer — which inverts the test and
  # reports a dirty archive as clean. (Found the hard way, by this gate passing a
  # deliberately-broken fixture.)
  zip_list="$(zipinfo -1 "${ARTIFACT}" 2>/dev/null || true)"
  if printf '%s\n' "${zip_list}" | grep -E '(^|/)(__MACOSX|\._)' >/dev/null 2>&1; then
    warn "archive contains __MACOSX/AppleDouble entries — not a plain 'ditto -c -k --keepParent' archive"
  else
    ok "archive has no __MACOSX/AppleDouble entries"
  fi

  # The exec bit AS STORED IN THE ARCHIVE. If a packer dropped the unix mode
  # (Windows zippers, `zipfile` with a bare ZipInfo, some GUI archivers), the
  # entry carries no mode, extraction falls back to the umask default, and the
  # bundle arrives non-executable. Section 4 catches the consequence; this names
  # the cause. The `[^/]` must be written `[^\/]`: awk ends a /regex/ literal at
  # the first unescaped slash, even inside a bracket expression.
  # Skip __MACOSX sidecars: their `._x` twins live at the same relative path and
  # are legitimately non-executable, so counting them would raise a FAIL that
  # names the wrong file.
  arch_modes="$(zipinfo "${ARTIFACT}" 2>/dev/null | awk '$NF !~ /(^|\/)__MACOSX\// && $NF ~ /Contents\/MacOS\/[^\/]+$/ {print $1, $NF}' || true)"
  if [[ -z "${arch_modes}" ]]; then
    warn "could not read Contents/MacOS entries from the archive listing"
  elif printf '%s\n' "${arch_modes}" | awk '{ if ($1 !~ /^-rwxr-xr-x/) exit 1 }'; then
    ok "archive stores 0755 on every Contents/MacOS entry"
  else
    bad "archive does NOT store the exec bit on every Contents/MacOS entry:"
    printf '%s\n' "${arch_modes}" | sed 's/^/        /'
  fi
fi
if [[ -d "${EXTRACT}/__MACOSX" ]]; then
  bad "__MACOSX directory survived extraction — users will see it as junk beside the app"
else
  ok "no __MACOSX directory after extraction"
fi
dbl="$(find "${EXTRACT}" -name '._*' -type f 2>/dev/null | head -5)"
if [[ -n "${dbl}" ]]; then
  bad "AppleDouble sidecar files survived extraction (first few): $(echo "${dbl}" | tr '\n' ' ')"
else
  ok "no AppleDouble ._* sidecars after extraction"
fi

# ── 3. Info.plist ────────────────────────────────────────────────────────────
head2 "3. Info.plist"
PLIST="${APP}/Contents/Info.plist"
if [[ ! -f "${PLIST}" ]]; then
  bad "Contents/Info.plist missing — Finder will not treat this as an app at all"
  exit 1
fi
if plutil -lint "${PLIST}" >/dev/null 2>&1; then
  ok "Info.plist parses"
else
  bad "Info.plist does not parse (plutil -lint)"
fi
plist_get() { /usr/libexec/PlistBuddy -c "Print :$1" "${PLIST}" 2>/dev/null; }
CFEXEC="$(plist_get CFBundleExecutable)"
CFID="$(plist_get CFBundleIdentifier)"
CFVER="$(plist_get CFBundleShortVersionString)"
CFTYPE="$(plist_get CFBundlePackageType)"
echo "      CFBundleExecutable=${CFEXEC:-<unset>}  CFBundleIdentifier=${CFID:-<unset>}"
echo "      CFBundleShortVersionString=${CFVER:-<unset>}  CFBundlePackageType=${CFTYPE:-<unset>}"
[[ -n "${CFEXEC}" ]] && ok "CFBundleExecutable set" || bad "CFBundleExecutable unset"
[[ "${CFTYPE}" = "APPL" ]] && ok "CFBundlePackageType=APPL" || bad "CFBundlePackageType is '${CFTYPE}', want APPL"
if [[ -n "${EXPECT_VERSION}" ]]; then
  if [[ "${CFVER}" = "${EXPECT_VERSION}" ]]; then
    ok "version == ${EXPECT_VERSION}"
  else
    bad "CFBundleShortVersionString is '${CFVER}', expected '${EXPECT_VERSION}'"
  fi
fi

# ── 4. THE kLSNoExecutableErr CHECK ──────────────────────────────────────────
# LaunchServices resolves Contents/MacOS/<CFBundleExecutable>. If that exact path
# is absent, macOS reports -10827 "the executable is missing" — regardless of what
# else lives in MacOS/. This is the single assertion that turns that error from a
# user-side mystery into a build failure.
head2 "4. main executable (the -10827 check)"
MAIN="${APP}/Contents/MacOS/${CFEXEC}"
if [[ -f "${MAIN}" ]]; then
  ok "Contents/MacOS/${CFEXEC} exists"
else
  bad "Contents/MacOS/${CFEXEC} DOES NOT EXIST — this ships as -10827 kLSNoExecutableErr"
  echo "        MacOS/ actually contains: $(ls "${APP}/Contents/MacOS" 2>/dev/null | tr '\n' ' ')"
fi

if [[ -f "${MAIN}" ]]; then
  # The exec bit. codesign does not care about it and `file` does not care about
  # it, which is exactly why it can be lost without any other check noticing —
  # and then launchd refuses with "Launchd job spawn failed" (POSIX 111).
  MODE="$(stat -f '%OLp' "${MAIN}")"
  if [[ -x "${MAIN}" ]]; then
    ok "main executable has the exec bit (mode ${MODE})"
  else
    bad "main executable is NOT executable (mode ${MODE}) — launchd will refuse to spawn it"
  fi
  [[ "${MODE}" = "755" ]] && ok "mode is exactly 0755" || warn "mode is ${MODE}, expected 755"

  if file -b "${MAIN}" | grep -q 'Mach-O'; then
    ok "main executable is Mach-O"
  else
    bad "main executable is not Mach-O: $(file -b "${MAIN}")"
  fi
  if lipo -archs "${MAIN}" 2>/dev/null | tr ' ' '\n' | grep -qx "${EXPECT_ARCH}"; then
    ok "arch includes ${EXPECT_ARCH} ($(lipo -archs "${MAIN}" 2>/dev/null))"
  else
    bad "arch is '$(lipo -archs "${MAIN}" 2>/dev/null)', expected ${EXPECT_ARCH}"
  fi
fi

# ── 5. Every Mach-O in the bundle ────────────────────────────────────────────
# A nested Mach-O without the exec bit is a lane that silently cannot spawn
# (the bundled engines are execve'd as siblings of the main binary). A nested
# Mach-O with NO signature at all is refused outright on Apple Silicon.
head2 "5. nested Mach-O binaries"
NESTED_LIST="${WORK}/machos.txt"
: > "${NESTED_LIST}"
while IFS= read -r f; do
  file -b "${f}" 2>/dev/null | grep -q 'Mach-O' && printf '%s\n' "${f}" >> "${NESTED_LIST}"
done < <(find "${APP}" -type f)

if [[ ! -s "${NESTED_LIST}" ]]; then
  bad "no Mach-O binaries found anywhere in the bundle"
fi
while IFS= read -r f; do
  rel="${f#${APP}/}"
  if [[ -x "${f}" ]]; then
    ok "exec bit: ${rel} (mode $(stat -f '%OLp' "${f}"))"
  else
    bad "NOT executable: ${rel} (mode $(stat -f '%OLp' "${f}"))"
  fi
  if codesign -dv "${f}" >/dev/null 2>&1; then
    ok "signed:    ${rel}"
  else
    bad "UNSIGNED:  ${rel} — Apple Silicon refuses to exec an unsigned Mach-O"
  fi
done < "${NESTED_LIST}"

# ── 6. Signature survived the round trip ─────────────────────────────────────
head2 "6. code signature after the archive round trip"
if csout="$(codesign --verify --deep --strict --verbose=2 "${APP}" 2>&1)"; then
  ok "codesign --verify --deep --strict passes on the EXTRACTED copy"
  echo "${csout}" | sed 's/^/        /'
else
  bad "codesign --verify --deep --strict FAILED on the extracted copy"
  echo "${csout}" | sed 's/^/        /'
fi

if [[ -n "${SOURCE_APP}" && -f "${SOURCE_APP}/Contents/MacOS/${CFEXEC}" && -f "${MAIN}" ]]; then
  src_h="$(shasum -a 256 "${SOURCE_APP}/Contents/MacOS/${CFEXEC}" | awk '{print $1}')"
  dst_h="$(shasum -a 256 "${MAIN}" | awk '{print $1}')"
  if [[ "${src_h}" = "${dst_h}" ]]; then
    ok "main executable is byte-identical before/after archiving (${dst_h:0:12}…)"
  else
    bad "main executable MUTATED in transit: pre=${src_h:0:12}… post=${dst_h:0:12}…"
  fi
fi

# Quarantine is what a browser download stamps on every file in the bundle. It
# must not invalidate the seal — if it does, "remove quarantine and retry" (the
# advice we give users) would leave a bundle that cannot be verified.
head2 "7. signature under quarantine (what a browser download does)"
QCOPY="${WORK}/q"
mkdir -p "${QCOPY}"
if ditto "${APP}" "${QCOPY}/AliceMiner.app"; then
  xattr -w -r com.apple.quarantine "0083;00000000;VerifyGate;00000000-0000-0000-0000-000000000000" "${QCOPY}/AliceMiner.app" 2>/dev/null
  if codesign --verify --deep --strict "${QCOPY}/AliceMiner.app" >/dev/null 2>&1; then
    ok "signature still verifies with com.apple.quarantine applied"
  else
    bad "signature FAILS once quarantine is applied — clearing quarantine would not rescue this build"
  fi
  xattr -dr com.apple.quarantine "${QCOPY}/AliceMiner.app" 2>/dev/null
  if codesign --verify --deep --strict "${QCOPY}/AliceMiner.app" >/dev/null 2>&1; then
    ok "signature still verifies after xattr -dr com.apple.quarantine"
  else
    bad "signature FAILS after clearing quarantine"
  fi
fi

# ── 8. Bundled engine SHA-256 pins ───────────────────────────────────────────
head2 "8. bundled engine pins (miners.json)"
if [[ -f "${MINERS_JSON}" ]]; then
  triple_for_arch="aarch64-apple-darwin"
  [[ "${EXPECT_ARCH}" = "x86_64" ]] && triple_for_arch="x86_64-apple-darwin"
  any_engine=0
  for ename in xmrig kawpowminer SRBMiner-MULTI; do
    ef="${APP}/Contents/MacOS/${ename}"
    [[ -f "${ef}" ]] || continue
    any_engine=1
    pin="$(python3 -c 'import json,sys
name,triple,path=sys.argv[1],sys.argv[2],sys.argv[3]
m=json.load(open(path))
e=next((x for x in m["engines"] if x.get("filename")==name and x.get("target")==triple), None)
sha=((e or {}).get("sha256") or "").strip().lower()
print("" if (e is None or e.get("_placeholder") or len(sha)!=64 or set(sha)=={"0"}) else sha)' "${ename}" "${triple_for_arch}" "${MINERS_JSON}" 2>/dev/null)"
    got="$(shasum -a 256 "${ef}" | awk '{print $1}')"
    if [[ -z "${pin}" ]]; then
      bad "${ename} is bundled but has no real pin in miners.json — the client fail-closes at Start"
    elif [[ "${pin}" = "${got}" ]]; then
      ok "${ename} == pin (${got:0:12}…) AFTER the archive round trip"
    else
      bad "${ename} SHA drift: packaged=${got:0:12}… pin=${pin:0:12}… — the client fail-closes at Start"
    fi
  done
  [[ "${any_engine}" = 0 ]] && ok "no bundled engines in this bundle (nothing to pin-check)"
else
  warn "miners.json not found at ${MINERS_JSON} — skipped engine pin check"
fi

# ── 9. Gatekeeper reality, stated plainly ────────────────────────────────────
head2 "9. Gatekeeper / notarization status"
SIGINFO="$(codesign -dv --verbose=4 "${APP}" 2>&1)"
SIGKIND="$(printf '%s\n' "${SIGINFO}" | sed -n 's/^Signature=//p')"
TEAMID="$(printf '%s\n' "${SIGINFO}" | sed -n 's/^TeamIdentifier=//p')"
echo "      Signature=${SIGKIND:-<none>}  TeamIdentifier=${TEAMID:-<none>}"
SPCTL_OUT="$(spctl --assess --type execute --verbose=4 "${APP}" 2>&1)"; SPCTL_RC=$?
echo "      spctl --assess --type execute -> rc=${SPCTL_RC}: ${SPCTL_OUT}"

NOTARIZED=0
if [[ "${SIGKIND}" = "adhoc" || "${TEAMID}" = "not set" || -z "${TEAMID}" ]]; then
  NOTARIZED=0
elif [[ ${SPCTL_RC} -eq 0 ]]; then
  NOTARIZED=1
fi

if [[ ${NOTARIZED} -eq 1 ]]; then
  ok "bundle is Developer-ID signed and accepted by Gatekeeper"
else
  msg="bundle is AD-HOC signed / NOT notarized — Gatekeeper WILL refuse it on a normal user's Mac.
        This is a signing-identity fact, not a packaging bug: no zip/dmg change fixes it.
        Every browser download needs a manual quarantine clear or Privacy & Security -> Open Anyway.
        The only complete fix is an Apple Developer ID certificate + notarytool submission."
  if [[ ${REQUIRE_NOTARIZED} -eq 1 ]]; then
    bad "${msg}"
  else
    warn "${msg}"
  fi
fi

# ── verdict ──────────────────────────────────────────────────────────────────
head2 "verdict"
if [[ ${FAILURES} -eq 0 ]]; then
  echo "  PASS — ${WARNINGS} warning(s), 0 failure(s)"
  echo "  (a PASS means the bundle is well-formed and launchable once quarantine is"
  echo "   cleared; it does NOT mean it passes Gatekeeper — see section 9.)"
  exit 0
else
  echo "  FAIL — ${FAILURES} failure(s), ${WARNINGS} warning(s)"
  echo "  Refusing to ship a macOS bundle a Mac cannot launch."
  exit 1
fi
