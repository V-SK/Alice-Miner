# Publishing an engine pin (server side)

How a new mining-engine version reaches miners **without shipping a client
release** — and what stops that same path from being an attack.

---

## 0. The one-paragraph version

The client compiles a pin table into its binary (`release-assets/miners.json`).
That table is now a *floor*, not the only source: the client also reads
`engines.json` + `engines.json.sig`, a small document signed with a **separate
engine-pin sub-key**, from the release assets. A pin published there wins over the
floor — but only after the client has downloaded the engine it names and verified
the bytes hash to the pin. Nothing else about the client changes: same
download → verify → atomic install → never-exec-unverified machinery.

## 1. Why this exists

On 2026-08-11 Pearl hard-forked. SRBMiner-MULTI 3.5.3 shipped the same morning,
mandatory; our client pinned 3.4.1 with a compile-time `include_str!`. Every share
after 12:04Z was rejected, for days. And self-update would not have helped:
v0.6.5, v0.6.6 and v0.6.7 all pin the **identical** engine bytes — a miner who
upgraded to the newest client would still have been 100% rejected. The pin table
had to become independently publishable, or the next fork costs the same days.

## 2. Trust split

| | release root key | engine-pin sub-key |
|---|---|---|
| signs | `latest.json` (the client you run) | `engines.json` (which engine bytes are allowed) |
| compromise means | RCE on every miner's machine, unrecoverable for installed versions | attacker can point miners at a different **upstream-hosted** engine build |
| custody | offline, encrypted image, V signs by hand | **identical custody** — same image, same by-hand flow |
| rotation | breaks all older clients (fail-closed) | breaks pin updates only; clients fall back to their built-in floor and keep mining |

The sub-key is strictly weaker by construction, and the client enforces that:

* **URL allow-list** — `crates/alice-miner-core/src/engine_pins.rs`
  `ALLOWED_URL_PREFIXES`. Only the upstream projects' own release paths. The
  sub-key cannot widen it; adding a host is a client release, on purpose.
* **Monotonic `epoch` + `min_engine_epoch`**, persisted per machine — a replayed
  old document is refused, and a publisher can retire everything older.
* **Same version ⇒ same hash, forever** — every `(kind, target, version) → sha`
  ever accepted (including the built-in floor) is remembered; a document that
  re-issues a known version with different bytes is refused **whole**.
* **Verified-before-effective** — the engine is downloaded and hashed before the
  pin takes effect. A hash mismatch refuses the document; a network failure just
  defers it. In both cases the previous pin stays in force and mining continues.
* **Fail-closed everywhere else** — bad signature, unknown schema, wrong product,
  malformed entry, unsafe filename or archive member ⇒ the document is ignored and
  the client says which pins it is actually using.

Honest cost, stated plainly: this puts a second signing key in regular use, and
that key can make every miner fetch a different (upstream-hosted, allow-listed)
binary. The engine already *is* a third-party binary we exec, so the blast radius
is not new — but the frequency of use is. Compensations: offline by-hand signing,
the allow-list, the epoch ratchet, the version↔hash ratchet, and this log.

## 3. Publishing, step by step

**Agent may do 1–3. Only V does 4–5.**

1. **Endorse in the open.** Add the entry to `ENGINE-TRUST-LOG.md`: upstream URL,
   the vendor's own published checksum (or `NONE`), why now, what was tested on
   real hardware. Then add/update the engine in `release-assets/engines-sources.json`.

2. **Reproduce the hashes independently:**

   ```sh
   python3 scripts/build_engines_manifest.py --epoch <N> --min-epoch <M>
   ```

   It reads the allow-list out of the client source (so publisher and client can
   never disagree), downloads every artifact, extracts the pinned member, computes
   both hashes, and **fails** if a declared `expected_*` does not match. Output:
   `dist/engines/engines.json` plus its sha256 on stdout.

   `--epoch` must be strictly greater than the currently published one; clients
   refuse a repeat or a rollback. `--min-epoch` retires everything below it.

3. **Prove it on hardware.** Point a test rig at the candidate before publishing:

   ```sh
   ALICE_MINER_ENGINES_URL=file-served-staging-url alice-miner engines --check
   alice-miner start --lane prl        # confirm ACCEPTED shares, not just "it runs"
   ```

4. **Sign, offline, by hand (V).** With the encrypted image attached:

   ```sh
   KEY=/Volumes/AliceRelease/alice-engine-pin-ed25519.key
   openssl pkeyutl -sign -inkey "$KEY" -rawin \
       -in dist/engines/engines.json -out dist/engines/engines.json.sig.bin
   base64 < dist/engines/engines.json.sig.bin | tr -d '\n' > dist/engines/engines.json.sig
   ```

   Verify against the public key embedded in the client before publishing (the
   full command block is in the header of `scripts/build_engines_manifest.py`).

5. **Upload onto the EXISTING release tag (V):**

   ```sh
   gh release upload <current tag> dist/engines/engines.json dist/engines/engines.json.sig --clobber
   ```

   No new client version, no new tag. Clients pick it up at their next check.

## 4. What miners see

* Background check at start, then every 6 h. A new pin is staged (downloaded +
  verified) immediately and takes effect the next time a lane starts its engine —
  the pin layer never kills a working engine mid-share.
* `alice-miner engines` shows the pinned sha256, upstream version + release URL,
  endorsement date, whether the pin came from the built-in table or a signed list
  (with its epoch), and whether the bytes are installed and verified here.
* `alice-miner engines --check` forces the check now and prints exactly what
  happened — including "could not reach the list" and "REFUSED the list", which
  exit non-zero.

## 5. Bootstrapping (still outstanding)

Two things must happen before any of this is live, and both are V's:

1. **Generate the engine-pin sub-key offline** and put its public half in
   `ENGINE_PIN_PUBKEY_B64` (`crates/alice-release/src/lib.rs`). Until then the
   constant is empty and the client is hard-wired to its built-in pins: it fetches
   nothing, and `alice-miner engines` says so.
2. **Ship one client release** carrying that key. This is the honest limit of
   this layer: *this* fork still needs a client release; every fork after it does
   not.

## 6. Known gaps (tracked, not hidden)

* A newly staged engine applies at the next lane start. Restarting a running
  engine on a pin change is the lane layer's call and is not implemented here.
* The bundled macOS-arm64 xmrig carries no `version` in the floor, so it shows as
  "unknown" in `alice-miner engines`. Fixing it means confirming which upstream
  build those committed bytes are — not guessing.
* The allow-list means an upstream that *yanks* an asset forces a client release.
  Deliberate: the alternative is letting one online key redirect every miner's
  engine download anywhere.
