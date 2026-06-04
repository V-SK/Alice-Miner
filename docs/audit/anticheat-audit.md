# Alice Miner — Client Anti-Cheat / Reward-Credit-Abuse Audit

- **Scope:** the Alice Miner CLIENT (`/Users/v/Alice/alice-miner/`, ~`26f2504`) —
  `alice-miner-core` (lanes, supervise, stats, identity, detect, dashboard,
  endpoint, engine, binaries), `alice-miner-cli`, `alice-miner-gui`,
  `alice-release`, `docs/PLAN.md`.
- **Posture under audit:** credit-only re-hashing proxy pool. The relay validates
  real PoW shares **server-side**; real rewards/payout are **phase-J (OFF)**.
- **Method:** read-only source review + targeted execution of the in-tree
  invariant tests (`cargo test -p alice-miner-core --lib` → **116 passed, 0
  failed**, incl. every honesty / credit-only / argv gate).
- **Cross-reference:** the project's prior **#18 red-team** findings (server-side
  anti-cheat BUILT-but-not-BINDING).
- **Verdict (one line):** **SAFE for credit-only go-live.** The client is a thin,
  honest stratum launcher + read-only dashboard; it asserts nothing the relay
  must trust. The #18 findings are **server-side** obligations that MUST be made
  binding before phase-J real rewards — none of them is the client's to fix.

---

## 0. The architecture in one paragraph (what the client actually is)

The client never implements a mining protocol itself. On **Start** it (a) resolves
the user's **public** Alice address (SS58-300), (b) derives a stratum `worker_id`
from that public address, (c) builds an argv for a **bundled third-party miner**
(`xmrig` for XMR/RandomX, `kawpowminer`/T-Rex for RVN/KawPoW), and (d) spawns that
miner as a supervised child. **The bundled miner speaks stratum directly to the
relay** (`hk.aliceprotocol.org:3333`/`:8888`); the relay (not the client) receives
the stratum `mining.submit`, **re-checks the PoW**, and credits the logged-in
address. The client then **reads the child's stdout**, parses hashrate + accepted/
rejected counts **for local display only**, and shows them in a dashboard whose
"earnings" surface is hard-wired to the string `"pending"`. The only other network
egress in the whole client is the **signed self-updater** (`alice-release`, ureq +
ed25519) and an **optional read-only credit GET** (default `NotExposed`, no call).

Key files: `crates/alice-miner-core/src/lane/{xmr.rs,gpu_rvn.rs}` (argv),
`.../supervise.rs` + `.../stats/parse_kawpow.rs` (parse stdout),
`.../engine.rs` (`Snapshot`), `.../dashboard.rs` (Source A / Source B),
`.../identity.rs` (address only, never a key on the mining path),
`.../endpoint.rs` (relay-only default), `alice-miner-gui/src/ui/{dashboard.rs,strings.rs}`,
`alice-miner-cli/src/dashboard.rs`, `alice-release/src/lib.rs`.

---

## 1. Credit inflation via the client — what does the client SEND that the relay might trust?

**Finding: the client cannot manufacture accepted shares or inflate credit. The
only credit-bearing thing it puts on the wire is the stratum PoW submission of the
*bundled miner*, which the relay re-verifies server-side.** Rated **Informational /
not a client cheat vector** (client side); the corresponding *server* obligation is
HIGH (see below and §5).

What crosses the client→server boundary, and who checks it:

| On-wire item | Source | Can a modified client forge it for credit? |
|---|---|---|
| Stratum login `-u <alice_addr>` | user's public address | No credit value — it only *names* who to credit. Forgery = crediting someone else's address (a **grief/theft** vector, §2), not inflation. |
| Stratum `--rig-id`/worker | `derive_worker_id(addr)` (public) | No — cosmetic sub-label; relay can ignore or re-derive. |
| **Stratum share submissions** (`mining.submit`: job-id, nonce, result hash) | the **bundled miner**, computing real RandomX/KawPoW | **No** — the relay re-runs the hash against the job's target. A fake/over-claimed share fails server PoW verification and is rejected. This is the load-bearing trust anchor. |
| Self-parsed **hashrate** (`hashrate_hs`) | client parses child stdout | **Never sent.** Lives only in `engine::Snapshot` / dashboard. |
| Self-parsed **accepted/rejected counts** | client parses child stdout (`parse_share_counts`, `parse_kawpow`) | **Never sent.** Display-only; the relay keeps its own authoritative count. |

I verified there is **no telemetry / stats-report / "submit my hashrate" path**.
The only network-capable symbols in the entire workspace are `ureq` (in
`alice-release` only) and egui's hyperlink colour; there is **no `TcpStream`,
`UdpSocket`, `reqwest`, `std::net`, `tokio::net`, no `.post(`/report/submit/upload**
anywhere in core/CLI/GUI. The self-parsed `hashrate_hs`/`accepted`/`rejected` are
consumed **only** by `build_snapshot()` → `Snapshot` → the GUI/CLI dashboards.
They are never serialized to a server. So even a client that prints
`accepted (999999/0)` to its own log inflates only its **own UI** — the relay's
credit is driven by the shares it independently validated.

> **The one thing to confirm operationally:** the relay must credit on
> *its own* validated share count, and must **not** expose any endpoint that
> ingests a client-reported hashrate/share figure as authoritative. Today no such
> ingest path exists in the client; the server must keep it that way.

The dashboard self-count is also locally trivially de-syncable from reality
(`parse_share_counts` just reads `(A/R)` from xmrig's *own* log; a forked miner can
print anything). That is **fine** because it is cosmetic — but it is a reason the
relay must never reconcile credit against a client-asserted number.

---

## 2. Proof-of-possession — mining to an Alice address needs no key

**Finding: the client can mine to ANY checksum-valid SS58-300 address with no proof
the user controls it. This is a real *credit-theft / grief* vector — but it is a
SERVER enforcement gap, faithfully reflecting the #18 "no proof-of-possession"
finding. Rated MEDIUM for phase-J; LOW-for-now under credit-only.** **Who fixes:
SERVER.**

Evidence (client side, working as designed):
- `lane::xmr::validate_alice_address` / `derive_worker_id` validate only that the
  string is a checksum-valid **format-300** address (base58 → `prefix‖pubkey‖
  checksum`, blake2b checksum). They prove the address is *well-formed*, **not**
  that the miner holds its key.
- `identity::paste()` is explicitly **watch-only**: "NO keystore, NO unlock — we
  only validate that it is a checksum-valid SS58-300 Alice address". The engine's
  mining path "consumes ONLY the public `address` string … never a password, seed,
  or key" (`identity.rs` header; `engine.rs` `worker_loop` keeps only
  `active_address: Option<String>`).
- The launch plan therefore happily logs in as **anyone's** address.

Cheat vectors this enables (all must be blunted on the relay):
1. **Credit redirection / theft framing:** point your rig at a victim's address.
   Under credit-only this just *gives* the victim credit (harmless-to-griefer);
   under phase-J it could be used to (a) wash credit through addresses you don't
   control, or (b) grief accounting/anti-Sybil heuristics keyed on address.
2. **Crediting an address whose key is lost/unknown** — fine for accounting, but
   means "credited address" ≠ "provably-owned address" at payout time.

Map to #18: this **is** the "no Alice-address proof-of-possession" finding. The
client *correctly* never sends a key (that is the honesty invariant — the seed
must never reach the mining child). Therefore proof-of-possession **must be a
server/payout-time gate**, not a client one:

> **Server MUST enforce before phase-J payout:** a challenge-response /
> signature proof that the payee controls the private key for the credited
> SS58-300 address (e.g. sign a server nonce with the sr25519 key at
> claim/registration), **before** any credit converts to a real reward. The
> client already has the keystore (`alice_crypto::unlock_wallet`) to produce such
> a signature when a future "claim" flow needs it — but **no such proof is wired
> today**, and none is needed for credit-only.

---

## 3. Sybil — can one actor farm credit cheaply via many identities/devices?

**Finding: the client imposes essentially zero cost on minting identities or
device IDs, so Sybil resistance must live entirely on the relay. Rated
MEDIUM (phase-J). Who fixes: SERVER (client offers no usable signal).**

Client-side enablers (cheap to multiply):
- **Identities are free and unlimited.** `identity::create` generates a fresh
  24-word wallet locally with no server registration, rate-limit, stake, or
  captcha; a script can mint thousands of valid SS58-300 addresses offline (and
  `paste` doesn't even need a keystore). The relay's "open enrollment credits the
  logged-in address" means each address is a fresh credit bucket.
- **Worker/device identity is weak.** `derive_worker_id` is a **pure function of
  the public address** — it is not a device fingerprint and provides **no**
  Sybil signal (N devices on one address share a rig-id; one device can rotate
  through N addresses, each yielding a distinct rig-id). There is no `device_id`
  in this client at all on the mining path (the `~/.alice/identity.json` pointer
  is per-install and not transmitted).
- **No client attestation.** No hardware attestation, no TEE, no proof-of-unique-
  device.

Why this is *acceptable for credit-only go-live but not phase-J:* under credit-only
the only resource a Sybil farm consumes is **its own real hashpower** — the relay
still only credits **validated PoW**, so 1000 fake addresses doing 1 GH/s total
earn exactly the credit of 1 address doing 1 GH/s. Sybil buys you nothing except
*spreading* the same work across buckets. It becomes an economic problem only when
(a) credit converts to money (phase-J), or (b) any **per-address bonus / faucet /
minimum-credit / first-share reward** is introduced — at which point splitting work
across many addresses games the per-address curve.

Map to #18 ("Sybil uuid4 device-id"): the #18 device-id weakness is **server-side**
(the relay/ACP minted a `uuid4` device identity an attacker can spoof). This client
is *cleaner* than that — it transmits **no device-id at all**, only the public
address + a deterministic rig-id. So the client neither helps nor hurts; **all**
Sybil mitigation is the relay's:

> **Server MUST (before phase-J or any per-address bonus):** bind credit-to-money
> to a per-address proof-of-possession (§2) + a real anti-Sybil signal (stake,
> KYC-lite, payout-address allow-listing, connection/IP heuristics, or a
> minimum-work threshold per *provably-distinct* identity), and make any
> per-address reward curve resistant to work-splitting. **Do NOT** rely on the
> client's rig-id or any client-asserted device identity.

---

## 4. Honesty / fabrication — does the client ever show fabricated earnings?

**Finding: NO. The credit-only / pending posture is enforced by construction and by
tests, not merely cosmetic. Rated PASS. Who fixes: N/A (already correct).**

Enforced, multi-layer, and test-guarded:
1. **No `paid_acu` (or any payout field) in the wire/serialization type.**
   `engine::Snapshot` has no payout/claim/settlement field; the test
   `snapshot_has_no_paid_acu_field` serializes a fully-populated snapshot and
   asserts the JSON contains none of `paid_acu|paid|payout|claim|settle|settlement|
   mint`.
2. **Confirmed credit is credit-only *by type*.** `dashboard::CreditScore` is a
   newtype with **no `Display`** and no fiat conversion — a careless
   `format!("{score}")` literally won't compile. The only renderable form is
   `pending_label()` ("server-confirmed · pending · 待发放"). The GUI confirms this:
   in `CreditState::Confirmed`, the magnitude is explicitly dropped
   (`let _ = score; // intentionally NOT rendered`).
3. **`paid_acu != "0"` ⇒ drop + error, never display the value.**
   `parse_credit_envelope` returns `Error(PaidAcuNotZero)` (value discarded) if
   `paid_acu != "0"` **or** `payout_executor_enabled` **or** `live_reward_enabled`
   is set. Tested (`source_b_paid_acu_not_zero_flips_to_error_and_drops_value`,
   `source_b_payout_executor_on_is_a_violation`, `client_complete_drops_nonzero_paid_acu_and_backs_off`).
   This is the #18 "fabricated/leaked payout" guard, in code.
4. **No reward projection.** `evaluate_reward_projection`/`estimated_rewards` is
   deliberately **NOT ported** (PLAN §6 D-no-projection). "Est. rewards" always
   renders the constant `REWARD_PENDING_SHORT = "— pending"` — never a number.
5. **Centralized honesty vocabulary, scanned by a test.** `gui/src/ui/strings.rs`
   holds every reward-adjacent string; `no_forbidden_reward_tokens_in_user_strings`
   parses the file's string literals and forbids `$|usd|fiat|paid|earned|已发放`,
   allows `payout/settlement` **only** in a "gated/off/disabled" negative
   disclosure, and forbids `credit`-as-cash. The CLI mirror
   (`cli/src/dashboard.rs`) has the same gate (`rendered_output_is_credit_only_and_leaks_no_secrets`).

**Could a *trivially-modified* client mislead the user?** Yes — anyone can fork the
GUI and paint "you earned $1,000,000". But (a) that misleads only **that user's own
screen**, (b) it changes **nothing** the server credits or pays, and (c) it cannot
extract value because payout is server-gated (phase-J OFF, and §2/§5 govern phase-J).
This is the inherent limit of *any* open-source client and is the right place to
draw the line: **honesty is enforced for the shipped client; trust for value is
enforced on the server.**

---

## 5. Modified-client threat (KEY DELIVERABLE) — the trust boundary

The client is open-source and freely modifiable. Enumerate what a hostile fork can
do, then state exactly what the **server** must verify so a hostile client gains no
unearned credit.

### 5a. What a malicious fork CAN do (and why each is contained today)
| Hostile modification | Effect | Contained by |
|---|---|---|
| Fabricate UI hashrate/shares/earnings | Misleads only the local screen | Server credits validated PoW only; client numbers are never ingested |
| Strip the `paid_acu`/projection guards; show "$X earned" | Local lie | No value path; payout server-gated (phase-J) |
| Log in as **any** SS58-300 address (no key) | Credits an address the user may not own | §2 — server must require proof-of-possession **at payout** |
| Mint unlimited addresses / rig-ids (Sybil) | Many credit buckets | §3 — credit==validated work; Sybil only *splits* work; server gates money |
| Point at a different pool / inject the core IP via `ALICE_MINER_ENDPOINTS_JSON` | Mines elsewhere / reveals operator topology if the operator sets it | Endpoint override is operator-only and absent from the public default (relay-only, no core IP — tested); a fork mining *elsewhere* simply doesn't earn Alice credit |
| Submit junk/over-claimed shares | — | **Rejected by server PoW re-verification** (the anchor) |
| Replay another rig's valid shares | Potential double-credit | §5b item 3 — server must dedup by job + full nonce width (the #18 "nonce-width dedup" finding) |
| Disable donate-level / change threads / swap in T-Rex | Local resource choices | No credit impact |

### 5b. The TRUST BOUNDARY — client-asserted vs server-verified

> **One-liner:** *Everything the client asserts is advisory; the only thing the
> server may trust is a stratum share it has **independently re-validated** as real
> PoW for a real, recent job by a **proof-of-possession-bound** identity —
> deduplicated by job-id + full nonce width — and credit must convert to a real
> reward only after a payout-time key-ownership + anti-Sybil gate.*

The server (relay / credit ledger / phase-J reward path) **MUST** verify, and must
**never trust the client for**, the following — the binding checklist:

1. **PoW validity (server-recomputed).** Re-hash every submitted share against the
   job target server-side; never accept a client "accepted" flag or hashrate. *(In
   place conceptually — the credit anchor; keep it the sole credit source.)*
2. **Job freshness / no stale-or-foreign job.** Bind each share to a job the relay
   actually issued, within its validity window — reject shares for unknown/expired
   jobs.
3. **Per-share de-duplication across the FULL nonce space** (the #18 "KawPoW
   nonce-width dedup 4–6×" + "recount computed-not-applied 64×" findings): dedup on
   (job_id, full nonce, mixhash/result) so a fork cannot resubmit / width-truncate
   to multiply credit. **The recount/dedup must be *applied* to the credited total,
   not merely computed.**
4. **Proof-of-possession at payout (§2).** Before any phase-J payout, require a
   signature over a server nonce by the credited address's sr25519 key. Credit may
   accrue address-agnostically (today), but **money** must require provable key
   ownership.
5. **Anti-Sybil at the money boundary (§3).** A real uniqueness/stake/threshold
   gate on credit→reward; do not key it on client rig-id/device-id.
6. **Server-authoritative credit ledger.** The per-address total lives on the
   server; the client only *reads* it (`NotExposed` today). Never reconcile or
   adjust credit from a client-reported figure.
7. **Logprob/verifier + clawback (AI lane, future).** The #18 "logprob verifier /
   clawback not wired" is an **AI-dispatch** concern (not in this miner client —
   the AI lane is M8/hidden). When the AI lane ships, its verify-window + clawback
   must be server-binding before it credits.

If all of the above are binding on the server, a hostile fork's maximum achievable
gain is **zero unearned credit**: it can lie to its own screen, redirect credit to
addresses (blunted by PoP at payout), and split work across Sybils (blunted by the
money-boundary gate), but it cannot make the relay credit work it did not actually
perform and that the relay did not independently validate.

---

## 6. Cross-reference of the #18 red-team findings — client vs server, mitigated vs open

| #18 finding | Applies to | Client status (this codebase) | Credit-only go-live | Phase-J real rewards |
|---|---|---|---|---|
| **Recount computed-not-applied (64× inflation)** | **Server** | N/A — client sends no count; relay owns credit | OK (no money) | **MUST FIX** — recount/dedup must be *applied* to credited total |
| **KawPoW nonce-width dedup (4–6×)** | **Server** | N/A — client just runs kawpowminer; relay validates | OK (no money) | **MUST FIX** — dedup on full nonce width |
| **Logprob verifier / clawback not wired** | **Server (AI lane)** | N/A — no AI lane in this client (M8/hidden; `AI_JOBS_ALLOWED=false`) | N/A | MUST FIX *when AI lane ships* |
| **No Alice-address proof-of-possession** | **Both** (client *correctly* sends no key; server must gate) | Client mines to any address by design (key never on mining path — honesty invariant) | OK (credit-only; theft = gift) | **MUST FIX** — PoP signature at payout (§2) |
| **Sybil uuid4 device-id** | **Server** | *Cleaner here* — client sends **no** device-id, only public address + deterministic rig-id | OK (Sybil only splits real work) | **MUST FIX** — anti-Sybil at money boundary (§3) |
| **72h gate decorative** | **Server** | N/A — no such gate in this client | OK | MUST FIX if used as a reward control |
| **Hardcoded PRF secret** | **Server** | N/A — not in this client. (Client's only embedded key is the **ed25519 release pubkey** — correct: it's a *public* verify key, fail-closed, rotation = breaking by design) | OK | Server-side: rotate/secure the PRF secret |
| **Single-authority chain** | **Server** | N/A — client is a consumer, not an authority | OK | Governance/architecture decision (server) |

**Reading of the table:** every #18 finding is **server-side** (or "both", where the
client's only obligation is the one it already meets: *never send a key / never send
a credit-bearing count*). **None of the #18 findings is an open client defect for
credit-only go-live.** They are the pre-conditions for *phase-J*, and they live on
the relay/credit/reward path — exactly where #18 placed them.

---

## 7. Verdict + the binding server checklist before phase-J

**Is the client SAFE for credit-only go-live?** **Yes.**
- It cannot manufacture accepted shares (PoW is server-validated; the client only
  launches a real miner and reads its log). §1
- It transmits **no** self-reported hashrate/share/credit figure — those are
  display-only and never reach the server. §1, §4
- Its honesty posture (no `paid_acu`, no projection, `CreditScore` has no fiat
  `Display`, `paid_acu!="0"`⇒drop, centralized strings) is **enforced in code and
  by passing tests** (116/116 core tests green), not cosmetic. §4
- The default endpoint set is relay-only with **no** core IP / collection address /
  upstream pool (operator override is the sole, explicit exception). §5
- The only other egress is a **signed, ed25519-verified** self-updater. §0
- Sybil/no-PoP are real but **inert under credit-only** because credit == the
  attacker's *own* validated work; they buy nothing until money is attached. §2, §3

**What the SERVER-side anti-cheat MUST make BINDING before phase-J real rewards**
(none of these is the client's to fix — they are the trust boundary of §5b):
1. PoW re-validation as the **sole** credit source (keep it; never ingest a
   client-asserted count/hashrate).
2. Job-freshness binding (reject stale/foreign jobs).
3. **Applied** recount + full-nonce-width de-duplication (the #18 64× / 4–6×
   findings — must be applied to the credited total, not merely computed).
4. **Proof-of-possession** (sr25519 signature over a server nonce) at the
   credit→reward boundary (the #18 no-PoP finding).
5. A real **anti-Sybil** gate at the money boundary, not keyed on client
   rig-id/device-id (the #18 Sybil finding).
6. Server-authoritative credit ledger; client read-only.
7. (AI lane only, future M8) logprob verify-window + clawback, server-binding.

**Net:** ship credit-only. Hold phase-J until the seven server-side gates above are
binding. The Miner *client* introduces no new cheat surface and, in two respects
(no device-id transmitted, no key on the mining path), is **cleaner** than the
ACP/relay surface the #18 red-team examined.

---

*Audit performed read-only against `26f2504`. No product code modified. Invariant
tests executed: `cargo test -p alice-miner-core --lib` → 116 passed / 0 failed.*
