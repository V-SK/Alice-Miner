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
* **Versions only go forward** — see §2b. A pin that moves an engine backwards is
  refused unless it says so, with a reason.
* **Verified-before-effective** — the engine is downloaded and hashed before the
  pin takes effect. A hash mismatch refuses the document; a network failure just
  defers it. In both cases the previous pin stays in force and mining continues.
* **Fail-closed everywhere else** — bad signature, unknown schema, wrong product,
  malformed entry, unsafe filename or archive member, an algorithm token that is
  really a flag, an algorithm on an engine whose argv has no algorithm slot, an
  extra argument that is not on the reviewed allow-list for that engine, a log
  parser this build does not have ⇒ the document is ignored and the client says
  which pins it is actually using.

Honest cost, stated plainly: this puts a second signing key in regular use, and
that key can make every miner fetch a different (upstream-hosted, allow-listed)
binary. The engine already *is* a third-party binary we exec, so the blast radius
is not new — but the frequency of use is. Compensations: offline by-hand signing,
the allow-list, the epoch ratchet, the version↔hash ratchet, the version-direction
ratchet, and this log. The risk this does **not** cover — an upstream account
compromise, which the pin then distributes faithfully — is written up as an
accepted risk in `ENGINE-TRUST-LOG.md`.

## 2a. The pin carries the CALL, not just the bytes

A pin used to say only *which bytes*. **How to invoke them** and **how to read
their output** were compiled into the client — which meant the headline claim
("every fork after this one needs no release") was not true for a fork that
changed either.

That is not hypothetical. SRBMiner-MULTI 3.5.4 reshaped both log lines our parser
depends on, and on 2026-08-14 a healthy GPU landing accepted shares at 44.8 TH/s
displayed `0 H/s · 0A/0R · STALL` for a whole twenty-minute run while the
no-progress watchdog restarted the engine on that false reading. No `engines.json`
could have fixed it.

So an entry in `engines-sources.json` may now also carry:

| field | what it does | bound |
|---|---|---|
| `algorithm` | replaces the client's compiled-in algorithm token (`pearlhash`) wherever a lane's argv carries one | short ASCII token, never flag-shaped, ≤ 64 chars; **only on `gpu-prl`** — it is the one kind whose argv has an algorithm slot, and setting it on another kind is refused rather than accepted-and-ignored |
| `extra_args` | argv spliced in **before** every flag the client owns | ≤ 16 tokens; **every** token must be a flag on the **reviewed allow-list for that engine kind** (`engine_pins::extra_arg_allowlist`), spelled in exact case, named at most once, and written as ONE token — `--flag` or `--flag=value`, never two list entries. Values are restricted to letters, digits and `. - _ , +` |
| `parser` | which compiled-in log parser reads this engine's output — `xmrig`, `kawpow`, `srbminer`, `alpha`, `generic` | must be an id **this client has**; an unknown id refuses the document whole |

All three are optional. Omitted ⇒ byte-for-byte the behaviour that shipped before
they existed. All three are validated when the document is accepted **and again
at the moment argv is built**, so a lane fails to start rather than launching a
call nobody checked. `scripts/build_engines_manifest.py` reads the parser list out
of the client source (the same trick it uses for the URL allow-list), so a typo is
caught at publish time rather than on a rig. It does **not** yet check `extra_args`
against the allow-list — the client does, so a bad flag is refused on the rig
rather than at publish time. Check it by eye against the table below.

### `extra_args` is an allow-list (changed 2026-08-15 — read this before publishing one)

The first cut of this field policed publisher argv with a **deny**-list of the
flags the client owns, and let everything else through. That is not decidable: it
requires having enumerated every spelling of every credit/transport/write flag of a
third-party binary. It failed on the engine we ship. xmrig 6.26 spells `--user` +
`--pass` also as **`--userpass`**, `--proxy` also as **`-x`**, and `--log-file`
also as **`-l`**; none were on the deny-list, and each was verified against
`release-assets/aarch64-apple-darwin/xmrig` to work:
`--userpass=<attacker>:x` put the attacker's address in the stratum login, `-x
host:port` routed the plaintext session through a chosen host, `-l file` created a
file. No new engine version was needed — re-publishing the current entry with the
flag added is accepted as `Same` and skips staging entirely.

So the rule is inverted, and the allow-list currently reads:

| kind | engine | reviewed flags |
|---|---|---|
| `cpu-xmr` | xmrig | `--randomx-mode`, `--randomx-init`, `--randomx-1gb-pages`, `--randomx-no-numa`, `--randomx-wrmsr`, `--randomx-no-rdmsr`, `--randomx-cache-qos`, `--huge-pages-jit`, `--no-huge-pages`, `--cpu-max-threads-hint`, `--cpu-no-yield`, `--asm`, `--dns-ttl` |
| `gpu-prl` | SRBMiner-MULTI | *(none reviewed)* |
| `gpu-rvn` | kawpowminer | *(none reviewed)* |
| `gpu-alpha` | alpha-miner | *(none reviewed)* |

Empty is deliberate, not an oversight. An entry on that table is a claim that a
human read that engine's own flag documentation and confirmed the flag cannot name
a pool, a login, a proxy, a file or a device. We can make that claim for xmrig
because its binary is in this repo. SRBMiner-MULTI is closed-source and ships no
macOS build; neither it nor alpha-miner nor kawpowminer has been read. **Adding a
flag is a client release**, and that release should carry the evidence (which
version's `--help`, read by whom) the way `ENGINE-TRUST-LOG.md` carries a hash.

What the allow-list guarantees: an alias nobody enumerated cannot pass, because
passing requires being *named*. What it does not: that a reviewed flag stays
harmless on a future version of the same engine — only re-review catches a vendor
repurposing a flag.

### How to WRITE one (changed 2026-08-16 — the old spelling is now refused)

**One token per flag. `--flag`, or `--flag=value`. Exact case. Each flag once.**

```jsonc
"extra_args": ["--randomx-mode=light", "--huge-pages-jit"]   // ✅
"extra_args": ["--randomx-mode", "light"]                    // ❌ refused
"extra_args": ["--Randomx-Mode=light"]                       // ❌ refused (case)
"extra_args": ["--randomx-mode=light", "--randomx-mode=fast"]// ❌ refused (twice)
```

The two-token spelling used to be accepted, and it was the hole. A value sat in a
*positional slot* that was checked only for content and charset — never against the
allow-list or the client-owned deny-list — and whether the engine actually consumed
that slot was our guess about someone else's argv parser. Two ways it was wrong, both
proved live against `release-assets/aarch64-apple-darwin/xmrig`:

* **Arity.** `--randomx-wrmsr` takes an *optional* argument and so consumes nothing;
  `--asm` is printed in that binary's own `--help` but is x86-only and answers
  ``unrecognized option``. `["--randomx-wrmsr", "-o127.0.0.1", "--randomx-wrmsr",
  "-uATTACKER"]` was fully allow-listed, lower-case and colon-free, and xmrig read it
  as a real pool plus a real login. Because `-o` **accumulates**, that pool became
  POOL #1 — the one actually mined.
* **Case.** The lookup case-folded, the emitted token did not. `--RANDOMX-MODE` was a
  reviewed value-taking flag to the client and `unrecognized option` to xmrig, which
  does not abort on one — so it consumed nothing and the "value" behind it became a
  real flag. That generalised the hole from those two flags to all six.

With a value inside its flag's token there is no slot, so a wrong guess about arity —
or about whether the flag exists on this platform at all — is at worst one word the
engine skips, and never a door. (Verified: `--asm=-lFILE`, `--randomx-wrmsr=-lFILE`,
`--randomx-mode=-lFILE`, `--dns-ttl=-lFILE` all left no file behind.)

Two things follow for a publisher. A value may still look flag-shaped when the flag
wants that — `--randomx-wrmsr=-1` is fine, because it is inside the token. And the
value charset is unchanged: letters, digits and `. - _ , +`, so no `:`, `/`, `\` or
`@`, which is what stops a value spelling `host:port`, `user:pass` or a path.

Note also what this fixed for **honest** publishing: `--Randomx-Mode=light` used to be
a document every rig accepted and no engine ever honoured — you would have believed
the fleet moved when it had not. It is now refused at validation, with the correct
spelling in the message.

### What this still does NOT remove

Be precise about this when describing the feature. A **client release** is still
required when:

* the fork's output needs a parser this client does not compile in (adding one is
  code — the pin can only *choose* among parsers already shipped);
* the engine renames or restructures one of the flags the client owns — the pool,
  the wallet/login, the password, the log file, the device selection. Those are
  deliberately not publishable: a key we touch often must not be able to redirect
  where shares go or who is credited;
* the new flag's name contains `seed` or `priv` — the argv honesty gate refuses
  those substrings outright, and we keep it strict (a gate that costs a release
  beats a gate with a hole);
* **the fork needs a switch nobody has reviewed for that engine** — since
  2026-08-15 `extra_args` is an allow-list, so a genuinely new flag is a one-line
  table entry plus a release. This is a real capability the deny-list appeared to
  offer and could not safely keep; the trade is written out above;
* the fork renames the algorithm on any lane except GPU-PRL — that is the only
  lane whose argv carries an algorithm token at all;
* the engine moves to a host outside `ALLOWED_URL_PREFIXES`, or the fork needs a
  new engine *kind* / a new lane.

Everything else — a new version, new bytes, a renamed pearlhash algorithm, a
reviewed tuning switch, a different one of our existing parsers — is a published
document away.

## 2b. Versions only go forward

Nothing used to stop a pin pointing at an **older** upstream build that is still
hosted on an allow-listed page. Every other guard would wave it through: the bytes
are genuine, the hash matches what the client already trusts for that version, and
the epoch went up. Pointing the fleet back at SRBMiner 3.4.1 after the fork is a
one-key replay of the 78-hour August outage; so is any rollback to a build with a
known hole.

The client now remembers, per `(kind, target)`, the **highest version ever in
force** — seeded from the pins compiled into it, so a fresh install is not
downgradeable either — and refuses a document that moves an engine backwards.

Ordering is deliberately conservative (`engine_pins::compare_versions`): a single
optional leading `v` is tolerated and plain dotted-numeric versions are compared
component-wise, with missing trailing components read as `0`. **Anything else is
`Unordered` and is treated exactly like a downgrade** — `3.5.4-rc1`, `3.5.4b`,
`2026.08.14-nightly`, `3.5.4+build7`. Upstream version strings are not ours, and
the client refuses rather than guesses. (Note it does *not* reuse
`alice_release::parse_version`, which truncates `1.4.0-rc1` to `(1,4,0)` — right
for versions we mint, wrong for a third party's, where the suffix may be the whole
difference between two builds.)

**A deliberate downgrade is allowed** — sometimes it is the right call — but it
must be declared:

```json
{ "kind": "gpu-prl", "version": "3.5.0", …,
  "downgrade": true,
  "downgrade_reason": "3.5.4 crashes on RDNA3; reverting while upstream fixes it" }
```

The reason is required (a bare flag is refused) because it is shown verbatim to
every miner by `alice-miner engines` and flagged by `alice-miner doctor`. The
ratchet is **raised, never lowered**: accepting a declared downgrade does not
re-base it, so republishing the older build keeps re-stating the marker rather
than quietly becoming the new normal. `doctor` also warns on a machine-local
regression the document forgot to declare.

Operational consequence worth knowing before it surprises you: an **unorderable**
version string never becomes the new reference either — the ratchet keeps
comparing against the last version it actually understood. So if an upstream moved
permanently to a scheme this client cannot order, *every* publish would need the
marker, and the marker would stop meaning anything. If that happens, the answer is
a client release that teaches `compare_versions` the new scheme — not a standing
`"downgrade": true`. (Plain date versions like `2026.08.14` order fine; it is
suffixes — `-rc1`, `-nightly`, `+build7` — that do not.)

> ⚠️ **Before the first real publish:** `release-assets/engines-sources.json`
> still carries the **3.4.1** baseline while v0.6.8 clients compile in **3.5.4**.
> Those clients will refuse that document whole, as an unmarked downgrade. Bump
> the sources file to the endorsed 3.5.4 hashes first.

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

3. **Prove it on hardware — all three checks, not just the first.** Point a test
   rig at the candidate before publishing:

   ```sh
   ALICE_MINER_ENGINES_URL=file-served-staging-url alice-miner engines --check
   alice-miner start --lane prl
   ```

   and confirm, from that one run:

   1. **accepted shares upstream** — it mines the live chain;
   2. **the argv is the argv it wants** — check the engine's own startup banner;
      nothing rejected, nothing silently ignored;
   3. **the client reads its output** — hashrate and the accepted/rejected
      counters move in `alice-miner`'s own display, not only in the engine's log.

   **Check 1 alone is not enough, and we know that from having done exactly it.**
   The 2026-08-14 endorsement run landed 8 accepted shares while the client showed
   `0 H/s · 0A/0R · STALL` and its watchdog restarted a healthy engine. If check 3
   fails, fix the parser (client release) or name a different compiled-in parser
   in the entry — do not publish. The full write-up is in `ENGINE-TRUST-LOG.md`
   under *The invocation check*.

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
  (with its epoch), whether the bytes are installed and verified here, any
  algorithm / extra argv / parser the pin overrides, and — loudly — a declared
  downgrade with its reason or a version regression this machine can see.
* `alice-miner doctor` carries an `engine version direction` check that WARNs on
  either of those, with the published reason.
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
   not — **subject to the four exceptions listed in §2a**, which are real and
   should be quoted alongside the claim rather than after it.

## 6. Known gaps (tracked, not hidden)

* A newly staged engine applies at the next lane start. Restarting a running
  engine on a pin change is the lane layer's call and is not implemented here.
* The bundled macOS-arm64 xmrig carries no `version` in the floor, so it shows as
  "unknown" in `alice-miner engines`. Fixing it means confirming which upstream
  build those committed bytes are — not guessing.
* The allow-list means an upstream that *yanks* an asset forces a client release.
  Deliberate: the alternative is letting one online key redirect every miner's
  engine download anywhere.
