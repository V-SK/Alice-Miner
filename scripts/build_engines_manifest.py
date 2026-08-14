#!/usr/bin/env python3
"""build_engines_manifest.py — prepare a signable engine-pin document.

This is the SERVER-SIDE half of "the engine pin can be updated without shipping a
client". It takes the human endorsement input (`release-assets/engines-sources.json`),
independently downloads every upstream artifact, reproduces its SHA-256, and emits
`engines.json` — the exact bytes V then signs OFFLINE with the engine-pin sub-key.

What it deliberately does NOT do:

  * it never signs anything (the sub-key lives in the encrypted image with the
    release key; only V ever touches it, by hand);
  * it never publishes (that is a separate, deliberate `gh release upload`);
  * it never trusts the input file's hashes. If the input declares an expected
    SHA-256 (copied from the vendor's own published checksum), the script FAILS
    unless the bytes it downloaded reproduce it. If the input declares none, the
    script prints the hash it computed and marks it UNCONFIRMED, so the trust-log
    entry cannot pretend a second source existed.

Usage
-----
    python3 scripts/build_engines_manifest.py --epoch 2 [--min-epoch 1] \
        [--sources release-assets/engines-sources.json] [--out dist/engines]

Then, offline, on the machine holding the key (V only):

    KEY=/Volumes/AliceRelease/alice-engine-pin-ed25519.key
    openssl pkeyutl -sign -inkey "$KEY" -rawin \
        -in dist/engines/engines.json -out dist/engines/engines.json.sig.bin
    base64 < dist/engines/engines.json.sig.bin | tr -d '\\n' > dist/engines/engines.json.sig

    # verify against the public key embedded in the client BEFORE publishing
    PUB=<ENGINE_PIN_PUBKEY_B64 from crates/alice-release/src/lib.rs>
    { printf '\\x30\\x2a\\x30\\x05\\x06\\x03\\x2b\\x65\\x70\\x03\\x21\\x00'; \
      printf '%s' "$PUB" | base64 -d; } | openssl pkey -pubin -inform DER -out engine-pin.pub.pem
    openssl pkeyutl -verify -pubin -inkey engine-pin.pub.pem -rawin \
        -in dist/engines/engines.json -sigfile dist/engines/engines.json.sig.bin

    gh release upload <existing tag> dist/engines/engines.json dist/engines/engines.json.sig --clobber

The upload targets the EXISTING latest release, so publishing a pin needs no new
client version — which is the entire point.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import io
import json
import re
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENGINE_PINS_RS = ROOT / "crates/alice-miner-core/src/engine_pins.rs"
DEFAULT_SOURCES = ROOT / "release-assets/engines-sources.json"
DEFAULT_OUT = ROOT / "dist/engines"
DOC_SCHEMA = 1
DOC_PRODUCT = "alice-miner-engines"
MAX_BYTES = 256 * 1024 * 1024


def allowed_prefixes() -> list[str]:
    """Read the URL allow-list out of the CLIENT source, so the publisher and the
    client can never disagree about which hosts are acceptable."""
    text = ENGINE_PINS_RS.read_text(encoding="utf-8")
    m = re.search(r"ALLOWED_URL_PREFIXES: &\[&str\] = &\[(.*?)\];", text, re.S)
    if not m:
        sys.exit(
            "cannot find ALLOWED_URL_PREFIXES in %s — refusing to guess the allow-list"
            % ENGINE_PINS_RS
        )
    prefixes = re.findall(r'"([^"]+)"', m.group(1))
    if not prefixes:
        sys.exit("ALLOWED_URL_PREFIXES parsed as empty — refusing to continue")
    return prefixes


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "alice-engine-pin-builder"})
    with urllib.request.urlopen(req, timeout=120) as r:  # nosec B310 - https enforced below
        data = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        sys.exit(f"{url}: body exceeds {MAX_BYTES} bytes")
    return data


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def extract(url: str, archive: bytes, member: str) -> bytes:
    low = url.lower()
    if low.endswith((".tar.gz", ".tgz")):
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as t:
            f = t.extractfile(member)
            if f is None:
                sys.exit(f"{url}: member {member!r} not found")
            return f.read()
    if low.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(archive)) as z:
            try:
                return z.read(member)
            except KeyError:
                sys.exit(f"{url}: member {member!r} not found")
    sys.exit(f"{url}: unsupported archive format (expected .tar.gz or .zip)")


def build(args: argparse.Namespace) -> int:
    prefixes = allowed_prefixes()
    src = json.loads(Path(args.sources).read_text(encoding="utf-8"))
    engines_in = src.get("engines", [])
    if not engines_in:
        sys.exit(f"{args.sources}: no engines to pin")

    out_engines = []
    unconfirmed = []
    for e in engines_in:
        for field in ("kind", "target", "filename", "version", "source_url", "endorsed_by", "endorsed_at"):
            if not e.get(field):
                sys.exit(f"entry {e.get('kind')}/{e.get('target')}: missing required field {field!r}")
        url = e.get("archive_url") or e.get("binary_url")
        if not url:
            sys.exit(f"entry {e['kind']}/{e['target']}: needs archive_url or binary_url")
        if not any(url.startswith(p) for p in prefixes):
            sys.exit(
                f"entry {e['kind']}/{e['target']}: {url} is not under an allow-listed upstream "
                f"prefix; the client would refuse this list.\nallowed: " + "\n         ".join(prefixes)
            )

        print(f"-- {e['kind']} {e['engine']} {e['version']} ({e['target']})")
        print(f"   fetching {url}")
        blob = fetch(url)
        blob_sha = sha256(blob)

        entry = {
            "kind": e["kind"],
            "engine": e["engine"],
            "version": e["version"],
            "target": e["target"],
            "filename": e["filename"],
            "source_url": e["source_url"],
            "endorsed_by": e["endorsed_by"],
            "endorsed_at": e["endorsed_at"],
        }
        if e.get("notes"):
            entry["notes"] = e["notes"]

        if e.get("archive_url"):
            member = e.get("binary_path_in_archive")
            if not member:
                sys.exit(f"entry {e['kind']}/{e['target']}: archive needs binary_path_in_archive")
            print(f"   archive sha256 {blob_sha}")
            expect_a = (e.get("expected_archive_sha256") or "").lower()
            if expect_a and expect_a != blob_sha:
                sys.exit(
                    f"   ARCHIVE HASH MISMATCH: expected {expect_a}, downloaded {blob_sha}. "
                    "Refusing to build a pin for bytes that are not what was published."
                )
            binary = extract(url, blob, member)
            bin_sha = sha256(binary)
            print(f"   binary  sha256 {bin_sha}  ({len(binary)} bytes, member {member})")
            expect_b = (e.get("expected_binary_sha256") or "").lower()
            if expect_b and expect_b != bin_sha:
                sys.exit(f"   BINARY HASH MISMATCH: expected {expect_b}, extracted {bin_sha}")
            if not expect_a and not expect_b:
                unconfirmed.append(f"{e['kind']}/{e['target']} {e['version']}")
            entry.update(
                {
                    "sha256": bin_sha,
                    "archive_url": url,
                    "archive_sha256": blob_sha,
                    "binary_path_in_archive": member,
                }
            )
        else:
            print(f"   binary  sha256 {blob_sha}  ({len(blob)} bytes)")
            expect_b = (e.get("expected_binary_sha256") or "").lower()
            if expect_b and expect_b != blob_sha:
                sys.exit(f"   BINARY HASH MISMATCH: expected {expect_b}, downloaded {blob_sha}")
            if not expect_b:
                unconfirmed.append(f"{e['kind']}/{e['target']} {e['version']}")
            entry.update({"sha256": blob_sha, "binary_url": url})

        out_engines.append(entry)

    doc = {
        "schema": DOC_SCHEMA,
        "product": DOC_PRODUCT,
        "epoch": args.epoch,
        "min_engine_epoch": args.min_epoch,
        "issued": _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "notes": src.get("notes", ""),
        "engines": out_engines,
    }
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "engines.json"
    # Stable, diffable bytes; the SIGNATURE is over exactly these bytes, so never
    # re-serialize this file after signing.
    body = json.dumps(doc, indent=2, sort_keys=False, ensure_ascii=False) + "\n"
    out_path.write_text(body, encoding="utf-8")

    print()
    print(f"wrote {out_path}  ({len(body.encode())} bytes)")
    print(f"sha256(engines.json) = {sha256(body.encode())}")
    if unconfirmed:
        print()
        print("UNCONFIRMED (no vendor-published checksum was supplied to cross-check):")
        for u in unconfirmed:
            print(f"  - {u}")
        print(
            "  Record this honestly in ENGINE-TRUST-LOG.md: the hash was reproduced from ONE\n"
            "  download, not corroborated by a second published source."
        )
    print()
    print("NEXT (V, offline, by hand — this script never signs and never publishes):")
    print("  see the header of this file for the exact openssl sign + verify commands")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--epoch", type=int, required=True, help="monotonic epoch; MUST be > the published one")
    ap.add_argument("--min-epoch", type=int, default=1, help="oldest epoch clients may keep using")
    ap.add_argument("--sources", default=str(DEFAULT_SOURCES))
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    args = ap.parse_args()
    if args.epoch < 1:
        sys.exit("--epoch starts at 1")
    if args.min_epoch > args.epoch:
        sys.exit("--min-epoch may not exceed --epoch (the client refuses such a list)")
    return build(args)


if __name__ == "__main__":
    raise SystemExit(main())
