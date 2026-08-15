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

What "independently" does and does NOT mean here — read this before writing
"independently verified" anywhere (finding F10):

    This script computes the hash from ITS OWN download, which catches a corrupted
    or truncated transfer and a mistyped hash in the input file. It does NOT
    corroborate AUTHENTICITY. When the `expected_*` hash was copied from a vendor
    `.md5` (or a checksum printed in the release body) published on the SAME GitHub
    release page as the artifact, that is ONE source agreeing with itself: an
    attacker who can replace the asset can replace the checksum beside it. Where a
    genuinely separate channel exists — xmrig's and alpha-miner's `SHA256SUMS`, or
    GitHub's own server-side asset digest — say which, in the trust-log entry. Where
    it does not, the entry says UNCONFIRMED (single source), and
    ENGINE-TRUST-LOG.md carries the accepted-risk paragraph that spells out the
    blast radius.

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
STATS_MOD_RS = ROOT / "crates/alice-miner-core/src/stats/mod.rs"
DEFAULT_SOURCES = ROOT / "release-assets/engines-sources.json"
DEFAULT_OUT = ROOT / "dist/engines"
DOC_SCHEMA = 1
DOC_PRODUCT = "alice-miner-engines"
MAX_BYTES = 256 * 1024 * 1024

# Fields that describe HOW to call an engine, not which bytes it is. Copied
# through verbatim from the endorsement input; the client validates every one of
# them and refuses the whole document if any fails (see `engine_pins`).
INVOCATION_FIELDS = ("algorithm", "extra_args", "parser")
# The deliberate-downgrade marker (finding F8). A pin that moves an engine
# BACKWARDS is refused by every client unless it carries this, with a reason.
DOWNGRADE_FIELDS = ("downgrade", "downgrade_reason")


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


def known_parsers() -> list[str]:
    """Read the log-parser ids out of the CLIENT source, for the same reason as the
    allow-list: a document naming a parser the client does not compile in is refused
    WHOLE, so catching it here beats catching it on a miner's rig."""
    text = STATS_MOD_RS.read_text(encoding="utf-8")
    m = re.search(r"KNOWN_IDS: &'static \[&'static str\] = &\[(.*?)\];", text, re.S)
    if not m:
        sys.exit(
            "cannot find ParserKind::KNOWN_IDS in %s — refusing to guess the parser list"
            % STATS_MOD_RS
        )
    ids = re.findall(r'"([^"]+)"', m.group(1))
    if not ids:
        sys.exit("ParserKind::KNOWN_IDS parsed as empty — refusing to continue")
    return ids


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
    parsers = known_parsers()
    src = json.loads(Path(args.sources).read_text(encoding="utf-8"))
    engines_in = src.get("engines", [])
    if not engines_in:
        sys.exit(f"{args.sources}: no engines to pin")

    out_engines = []
    unconfirmed = []
    downgrades = []
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

        # How to CALL these bytes (finding F6). Optional; absent ⇒ the client uses
        # the invocation compiled into it, which is byte-for-byte what it used
        # before these fields existed.
        for field in INVOCATION_FIELDS:
            if e.get(field) not in (None, "", []):
                entry[field] = e[field]
        if "parser" in entry and entry["parser"] not in parsers:
            sys.exit(
                f"entry {e['kind']}/{e['target']}: parser {entry['parser']!r} is not one the "
                f"client compiles in ({', '.join(parsers)}). The client refuses such a document "
                "WHOLE — adding a parser is a client release."
            )
        if "extra_args" in entry and not isinstance(entry["extra_args"], list):
            sys.exit(f"entry {e['kind']}/{e['target']}: extra_args must be a LIST of argv tokens")

        # The deliberate-downgrade marker (finding F8).
        if e.get("downgrade"):
            reason = (e.get("downgrade_reason") or "").strip()
            if len(reason) < 8:
                sys.exit(
                    f"entry {e['kind']}/{e['target']}: marked as a downgrade with no reason. "
                    "Every miner is shown that reason — write one."
                )
            entry["downgrade"] = True
            entry["downgrade_reason"] = reason
            downgrades.append(f"{e['kind']}/{e['target']} → {e['version']}: {reason}")
        elif e.get("downgrade_reason"):
            sys.exit(
                f"entry {e['kind']}/{e['target']}: has downgrade_reason but downgrade is not "
                "true — say which you mean."
            )

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
    if downgrades:
        print()
        print("DELIBERATE DOWNGRADES in this document — every miner will be shown these:")
        for dgr in downgrades:
            print(f"  - {dgr}")
        print(
            "  A client whose recorded version for that engine is HIGHER refuses an unmarked\n"
            "  downgrade outright. Marked, it is accepted and surfaced loudly by\n"
            "  `alice-miner engines` and `alice-miner doctor`. Make sure the trust-log entry\n"
            "  says the same thing this reason does."
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
