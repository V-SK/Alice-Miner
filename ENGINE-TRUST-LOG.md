# Engine trust log

Every mining engine this client runs is a **third-party binary** we did not write
and cannot audit line by line (SRBMiner-MULTI is closed-source freeware; XMRig and
alpha-miner ship source but we run the vendor's builds). Running one is a trust
decision, not a technical detail — so it is recorded here, in the open, by hand.

**The rule: a hash gets into `engines-sources.json` only with an entry here
first.** An agent may prepare the evidence and open a PR; the endorsement itself
is V's, and the document that carries it to miners is signed offline by V.

Each entry must state:

| field | meaning |
|---|---|
| engine + version | what upstream calls this build |
| target | the platform triple the bytes are for |
| upstream release URL | the page the artifact was published on |
| vendor-published checksum | what upstream said the bytes hash to (or **NONE** — say so) |
| our independently computed sha256 | what `scripts/build_engines_manifest.py` reproduced from its own download |
| why now | the reason we are changing engines at all |
| tested | what was actually run, on what hardware, with what result |
| endorsed by / date | who decided |

Honest defaults: if upstream published no checksum, the entry says **UNCONFIRMED
(single source)** — one download reproducing its own hash proves nothing about
authenticity. If the engine was not run on real hardware before endorsement, the
entry says so.

---

## epoch 1 — 2026-08-14 — baseline (no change)

The pins already compiled into client v0.6.7, restated as the first signed
engine-pin document so the publishing path is exercised before it is ever needed
in an emergency. **No engine changes.**

| engine | target | our sha256 | vendor checksum |
|---|---|---|---|
| srbminer-multi 3.4.1 | linux-x64 | `9335b57a…96f7` | archive md5 `834f26b9…98e7` (vendor) — matched 2026-06-25 |
| srbminer-multi 3.4.1 | windows-x64 | `e2fa2dd2…b39a` | archive md5 `5962b5e4…70a0` (vendor) — matched 2026-06-25 |
| xmrig 6.26.0 | linux-x64 | `b20f39fc…4b49` | official `SHA256SUMS` — `shasum -c` OK 2026-06-26 |
| xmrig 6.26.0 | windows-x64 | `6fa80698…eeb3` | official `SHA256SUMS` — OK 2026-06-26 |
| alpha-miner 1.8.3 | linux-x64 | `927f50f6…5fdb` | official `SHA256SUMS` — OK 2026-06-26 |
| alpha-miner 1.8.3 | windows-x64 | `9e3b52d6…7081` | official `SHA256SUMS` — OK 2026-06-26 |

Not in the document (no fetch URL exists, so the client keeps its built-in pin):
the bundled macOS-arm64 xmrig, and the two kawpowminer placeholders.

**Why now:** to prove the pipeline end-to-end on a day when nothing is on fire.
**Tested:** these exact bytes are what every v0.6.5–v0.6.7 miner has been running.
**Endorsed by:** V — *pending*. This baseline is prepared, not yet signed.

---

## epoch 2 — PROPOSED, NOT ENDORSED — SRBMiner-MULTI 3.5.3 (Pearl hard fork)

> This section is the open question this whole mechanism was built for. It is
> **not** an endorsement and the hashes below are deliberately absent.

**Why:** Pearl hard-forked its algorithm on 2026-08-11. SRBMiner-MULTI 3.5.3
shipped the same morning (10:39Z) marked MANDATORY. From 12:04Z, 100% of our
GPU-PRL shares have been rejected upstream; the network has been at zero miners
for days. Our client pins 3.4.1 — which, post-fork, cannot produce a valid share.

**What must happen before this becomes epoch 2:**

1. `python3 scripts/build_engines_manifest.py --epoch 2` — downloads the 3.5.3
   artifacts and computes their hashes independently.
2. Cross-check against whatever SRBMiner publishes (the vendor ships per-archive
   `.md5` files). If there is nothing to cross-check against, this entry says
   UNCONFIRMED and V decides with that in front of him.
3. Run it on real hardware and confirm **accepted** shares upstream — a pin that
   swaps one broken engine for another is not a fix.
4. V endorses here, signs `engines.json` offline, uploads it to the release.

**Status:** blocked on 1–3. No hash has been endorsed.
