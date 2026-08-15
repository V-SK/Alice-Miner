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
| tested | what was actually run, on what hardware, with what result — **including the invocation check below** |
| **invocation** | the algorithm token, any extra argv, and the log format — **checked against the real run**, not assumed |
| **direction** | newer than the version it replaces, or a declared downgrade with a reason |
| endorsed by / date | who decided |

Honest defaults: if upstream published no checksum, the entry says **UNCONFIRMED
(single source)** — one download reproducing its own hash proves nothing about
authenticity. If the engine was not run on real hardware before endorsement, the
entry says so.

---

## The invocation check — why "accepted shares" is not enough

**This section exists because the obvious test passed and the client was still
wrong.** On 2026-08-14 a rented RTX 3060 ran SRBMiner-MULTI 3.5.4 against a real
relay and landed **8 accepted shares** — the exact evidence step 3 of
`docs/engine-pin-publishing.md` asks for. It was endorsed on that evidence, and
it was the right call. But throughout that same run the client's own panel read
`0 H/s · 0A/0R · STALL`, and the no-progress watchdog restarted a perfectly
healthy engine on that false reading, because 3.5.4 had reshaped both log lines
the client's parser depends on:

```text
3.4.x   GPU0: 44.99 TH/s [719|1|0|442.94 GH/W]
3.5.x   GPU0 RTX 3060: 44.99 TH/s [T:71C FAN:63% P:169.9W EFF:0.265 CC:1672 MC:7301 A:0 R:0 HW:0]

3.4.x   Average hashrate: … (one window per line)
3.5.x   Average hashrate: 1m 44.99 TH/s | 1h 0.00 H/s | 6h 0.00 H/s | 12h 0.00 H/s
```

An endorsement is therefore **not complete** until all three of these are checked
against the same real run, and the entry says what was seen:

1. **Accepted shares upstream** — the engine mines the live chain. (What step 3
   already asked for.)
2. **The argv we pass is the argv it wants** — the algorithm token is still
   accepted, and no new switch is required. An engine that rejects our command
   line does not start at all, which is loud; one that *silently ignores* a flag
   is not. Check the engine's own startup banner for what it thinks it was asked
   to do.
3. **The client reads its output** — hashrate, accepted and rejected counters all
   move in `alice-miner`'s own display, not just in the engine's log. **A run
   that lands shares while the client shows zeros is a FAILED check**, not a
   cosmetic one: the no-progress watchdog and the acceptance-collapse halt both
   judge a lane on exactly those counters.

Where 2 or 3 needs something new, the pin can carry it — `algorithm`,
`extra_args` and `parser` in `engines-sources.json` (see
`docs/engine-pin-publishing.md` §2a) — and the entry must say which fields it set
and why. Where it needs a parser this client does not have, it needs a **client
release**; say that in the entry rather than endorsing a build the fleet will
mis-read.

---

## Accepted risk: the hash pin faithfully distributes an upstream compromise

Stated plainly, because the pipeline's own wording invites a stronger reading
than it deserves.

`scripts/build_engines_manifest.py` "independently recomputes" each hash from its
**own** download. That catches a corrupted transfer, a truncated artifact, and a
mistyped hash in the endorsement input. It does **not** establish authenticity,
and for SRBMiner-MULTI it never has: the vendor `.md5` we cross-check against is
published on the **same GitHub release page** as the artifact itself. That is one
source agreeing with itself. Anyone who can replace the asset can replace the
checksum beside it, and both of our channels would report the same new number.
(xmrig and alpha-miner publish `SHA256SUMS`, which is better but still the same
account; GitHub's server-side asset digest is a genuinely separate channel and is
worth recording where it is available, as epoch 2 does.)

**Blast radius, if the upstream account is compromised.** SRBMiner-MULTI is
closed source. We cannot audit it, we run the vendor's build, and it runs
**unsandboxed with the miner's full privileges** on every GPU-PRL rig. If an
attacker publishes a malicious build to that release page:

* our pipeline downloads it, computes its hash, and — because the vendor checksum
  beside it agrees — reports it as reproduced;
* the hash goes into `engines.json`, is endorsed, and is signed;
* every client verifies the bytes against that pin **and the verification
  passes**, because the pin is of exactly those bytes;
* the fleet then executes it. The pin does not merely fail to stop this — it
  **distributes it faithfully and at speed**, which is the whole point of the
  mechanism working correctly.

**What actually limits this**, without overstating any of it:

* The URL allow-list means an attacker needs the *upstream vendor's* account, not
  ours; a stolen engine-pin sub-key alone cannot point anywhere else.
* Endorsement is a human step with a real-hardware run in front of it. That
  raises the cost of a *targeted* attack; it does not detect a backdoor in a
  closed-source binary that mines correctly.
* The version ratchet stops the fleet being walked *backwards* into a build with
  a known hole without a declared reason.
* Per-(kind,target,version) hash memory stops the same version being redefined
  later. It does nothing about a *new* version that is malicious from birth.

**What would actually reduce it** — and is not built: a second, independent
retrieval path (a mirror, or a third party's published hash for the same
artifact) before endorsement, and sandboxing the engine so a compromised one
cannot reach the keystore or the network beyond its relay. Until then this risk
is **accepted, not mitigated**, and it applies to every engine in this log.

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

## epoch 2 — SRBMiner-MULTI 3.5.4 (Pearl salted-seed hard fork) — **ENDORSED**

> Supersedes the earlier *PROPOSED, NOT ENDORSED — 3.5.3* draft of this section.
> 3.5.4 (2026-08-12T21:08Z) is a strict superset of the emergency build 3.5.3
> (2026-08-11T10:39Z, "MANDATORY UPDATE"), adding only pearlhash efficiency work
> (2000/3000/4000-series, H100). 3.5.3 itself is **not** endorsed and was never
> hashed — we skipped straight to its superset. The three preconditions written
> into the draft (independent hash, vendor cross-check, real-hardware accepted
> shares) are now all satisfied; the third one is what took a rented GPU.

| field | value |
|---|---|
| engine + version | srbminer-multi **3.5.4** |
| targets | `x86_64-unknown-linux-gnu`, `x86_64-pc-windows-msvc` |
| upstream release URL | https://github.com/doktor83/SRBMiner-Multi/releases/tag/3.5.4 |
| why now | Pearl mainnet hard-forked at height 99000 (`SaltedSeedForkHeight`, block ts 2026-08-11T12:03:43Z): CertificateV3 salts the seeds with keyed BLAKE3. Our pin was 3.4.1, released 2026-06-25 — seven weeks before the spec existed. Last accepted PRL share network-wide: **2026-08-11T12:03:46Z**, three seconds after the fork block. 78 h at 100% rejection, zero miners earning. |

**Hashes — four independent channels agreeing per archive** (vendor `.md5`
release asset; the MD5 printed in the release *body*, a separate channel from the
file; a local `md5`; GitHub's server-side asset digest, which is a sha256 and
equals our own `shasum -a 256`). This is **CONFIRMED**, not "single source".

| target | archive | our archive sha256 | our binary sha256 | vendor md5 |
|---|---|---|---|---|
| linux-x64 | `SRBMiner-Multi-3-5-4-Linux.tar.gz` (18,736,372 B) | `3127ace7c6f9a6ed0f86b1c96020aeac1cf2d32db2acdd78ba307894f48c366a` | `e3eebefd4911c0d656e8e17116338a11abea17588161aa6b23acf2071b8e3f87` (`SRBMiner-Multi-3-5-4/SRBMiner-MULTI`, 19,596,192 B, ELF x86-64) | `0868badbb02b6cdda82c3d3f6fa49833` |
| windows-x64 | `SRBMiner-Multi-3-5-4-win64.zip` (25,368,168 B) | `51c03bd926c62f53c87be298d724543ead244e63cc69dcd55a0c3eb50eb483aa` | `1926cc1d4756506a6fd24360969593ae47fd8397508f93293449a017ec35449e` (`SRBMiner-Multi-3-5-4/SRBMiner-MULTI.exe`, 25,535,488 B, PE32+ x86-64) | `7758f6080dd82a632a56f77f7043196b` |

### Tested — real hardware, real relay, real upstream

**2026-08-14T22:51:08Z → 23:11:08Z (20 min).** Rented Vast.ai RTX 3060 12 GB in
Korea (instance 47743622, $0.0521/h, destroyed immediately after — rent-use-
destroy). Path: rig → `asia.aliceprotocol.org:3340` (plaintext TCP, `PRL_REQUIRE_
POP=1`) → ps-128 `pearl-upstream-proxy:1200` → `prl.kryptex.network:7048`.

The client was **built on the rented box from the pin branch itself**
(`fix/prl-engine-pin-3.5.4-20260814` @ `9e9bb8d`, source tar sha256
`2257684f…c20b40d9`), so the binary that ran is the one the client's own resolver
fetched, hash-checked against the embedded pin (archive **and** extracted binary),
and only then exec'd. Nothing was hand-placed. *(The obvious shortcut — released
v0.6.7 plus `ALICE_MINER_PRL_BIN` — was rejected: `binaries.rs:719` still checks
the override against the **embedded** pin, i.e. 3.4.1, so it only runs with
`ALICE_MINER_ALLOW_UNVERIFIED_BIN=1`. An unverified run cannot endorse a hash.)*

Identity: a throwaway seed generated on the rented box (`openssl rand -hex 32` →
`identity --import-seed`, `ALICE_IDENTITY_DIR` isolated), address `a2uxxE…iVK`.
`identity --create` was never run; V's keystore never left his machine.

Three independent layers, all reading **8**:

1. **Engine.** `Miner version: 3.5.4`; running binary sha256 `e3eebefd…1b8e3f87`
   == pin. Counters **A:8 R:0 HW:0**, eight `GPU0[t0] share accepted [~370 ms]
   [pearlhash]` lines, 44.8 TH/s, zero rejected/invalid.
2. **Relay** (`43.160.226.238`). `prl_relay_m4_challenge` 200 → `prl_relay_m4_
   verify` 200 → `prl_relay_upstream_login_ok`; **zero** reject / upstream_code /
   upstream_reason / Invalid-share events. Captured on the wire at the rig:
   `mining.notify … "height":99953 … "cert_version":3` and
   `{"id":15,"method":"mining.submit",…}` → `{"id":15,"result":true,"error":null}`
   — a post-fork job accepted by the upstream pool, with the relay's
   `cert_version` pass-through fix (tree `209f8982`) working alongside 3.5.4.
3. **Ledger** (ps-128 `prl_share_ledger.sqlite3`). `prl_accepted_shares`
   159375 → 159383; the test address holds exactly **8** rows, pool `gpu`,
   Σ difficulty_milli 16,777,216,000, ts 22:54:15Z–23:09:44Z. The row before
   these was dated **2026-08-11T12:03:46Z** — the fork second. The 78-hour gap in
   that table is closed by this run. Credit poller: `credited: 8 shares`.

**Not proven by this run, stated plainly:** the **Windows** binary is hash-
verified only — it was never executed anywhere, so its "works post-fork" status
is inference from the vendor's release notes, not evidence. **AMD RDNA2 (RX 6xxx)
loses the GPU-PRL lane entirely** — SRBMiner removed RDNA2 pearlhash support in
3.5.0; those rigs will not mine wrongly, the lane just goes unavailable, and this
must be in the miner announcement. One non-blocking client bug surfaced (it did
not affect upstream acceptance): the PRL lane's own share/hashrate counters read
`0A/0R`, `0 H/s`, STALL while the engine was at A:8 and 44.8 TH/s — a suspected
unparsed `TH/s` unit — which tripped the 600 s no-progress watchdog into
restarting the engine at 23:05:24 (it re-enrolled via PoP and kept producing
shares). Fix that before shipping the miner-facing dashboard claim.

### Invocation — checked after the fact, and it did NOT pass

**argv:** unchanged. 3.5.4 still takes `--algorithm pearlhash --pool … --wallet …
--password … --disable-cpu --log-file …`; nothing was rejected or ignored.

**Log format: CHANGED, and the client was reading it wrong throughout the run.**
Both lines the parser depends on were reshaped (see *The invocation check* at the
top of this file). The engine was at `A:8` and 44.8 TH/s while `alice-miner`
displayed `0 H/s · 0A/0R · STALL`, and the 600 s no-progress watchdog restarted
the engine at 23:05:24 on that false reading. The upstream evidence above is
unaffected — the shares were real and were credited — but **this endorsement's
"tested" step, as originally written, did not catch it.** The parser is fixed on
the v0.6.8 branch (`crates/alice-miner-core/src/stats/parse_srbminer.rs`, commit
`631d5e6`) against the verbatim captured lines, and reading the client's own
counters is now step 3 of the endorsement rather than an afterthought.

**Direction:** 3.5.4 > 3.4.1 — an upgrade, no downgrade marker needed.

**Endorsed by:** V — 2026-08-15, on the evidence above (agent prepared it; no
part of the endorsement was self-granted). **Signature still owed:** the pin here
is endorsed, but `engines-sources.json` still carries the 3.4.1 baseline and
`engines.json` has not been signed offline. Until V does that, 3.5.4 reaches
miners only inside a client release (v0.6.8), not through the engine-pin
document. Bumping `engines-sources.json` to the hashes above and running
`scripts/build_engines_manifest.py` is V's next action, and this entry is the
prerequisite that unblocks it.

> ⛔ **Do not publish the epoch-1 baseline document as it stands.**
> `release-assets/engines-sources.json` still describes **3.4.1**, while every
> v0.6.8 client compiles in **3.5.4**. With the version ratchet added for finding
> F8, such a document is now refused **whole** by those clients as an unmarked
> downgrade — correctly, since it is exactly the August outage's pin. Bump
> `engines-sources.json` to the 3.5.4 hashes in this entry **before** the first
> real publish. (A v0.6.7 client, whose floor is 3.4.1, would still accept it —
> so publishing it would split the fleet's behaviour rather than fail uniformly.)
