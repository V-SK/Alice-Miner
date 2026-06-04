# Alice Miner — Deep Security Audit (pre-public-distribution)

- **Scope:** `/Users/v/Alice/alice-miner/` at committed git HEAD `26f2504` (M6).
- **Crates reviewed:** `alice-crypto`, `alice-miner-core` (engine, identity, lane/xmr,
  lane/gpu_rvn, supervise, endpoint, detect, dashboard, stats, binaries), `alice-supervise`,
  `alice-release` (auto-updater), `alice-miner-cli`, `alice-miner-gui`, `release-assets/miners.json`,
  `docs/PLAN.md`.
- **Method:** read-only static review of all `*.rs` + manifests; ran the security-relevant
  unit suites (`alice-miner-core` 116 tests, `alice-release` 18 tests, `alice-crypto` — all pass),
  dependency-version review against `Cargo.lock`, and targeted greps for secret leakage / argv
  leakage / command-injection / TLS posture.
- **Nature:** READ-ONLY. No product code was modified. This document is the only artifact written.

The bar is the same as the Wallet's pre-release audit. Verdict at the end.

---

## Severity counts

| Severity | Count |
|---|---|
| CRITICAL | 0 |
| HIGH | 1 |
| MEDIUM | 4 |
| LOW | 6 |
| Informational / verified-good | (see §"What is solid") |

The single HIGH is **not exploitable in the shipped product today** (the affected code path is
compiled-in but never invoked) — it is a latent footgun that must be closed *before* the updater is
turned on. No CRITICAL issues. The credit-only honesty posture, the "unlock-once / mining-uses-only-
the-public-address" invariant, and the updater's signature/SHA/no-downgrade/data-dir guards are all
present and unit-proven.

---

## Top findings (one line each)

1. **HIGH** — Auto-updater `DEFAULT_UPDATE_URL` points at the wrong repo + a flagged placeholder, and the whole `alice-release` kernel is compiled-in but **never wired into either front-end** (`alice-release/src/lib.rs:84`; no call site for `check_for_update`/`apply_update`/`register_launch`). Ship-blocker to *resolve a decision on*, not to patch blindly.
2. **MEDIUM** — `resolve_miner_binary` execs the resolved miner without verifying the `miners.json` SHA-256 pin; `miners.json` is documentation-only and **read by no code** (`alice-miner-core/src/binaries.rs:83`, grep: 0 consumers).
3. **MEDIUM** — Bundled-binary resolution trusts a **sibling-of-exe** path and an **env override** with no integrity check; a writable app dir or a planted `ALICE_MINER_*_BIN` runs attacker code with the user's privileges (`binaries.rs:85`, `:104`).
4. **MEDIUM** — `extract_archive` shells out to `tar`/`ditto`/`unzip` on a (verified) archive but does not constrain extraction; a malicious-but-correctly-signed archive could path-traverse on a host where the trust anchor is already compromised (`alice-release/src/lib.rs:712`). Defense-in-depth only.
5. **MEDIUM** — CLI `--password <PASS>` is a plain clap option → visible in the process table (`ps`)/shell history (`alice-miner-cli/src/main.rs:144`).
6. **LOW** — GUI password fields are plain `String`, cleared with `.clear()` (no zeroize) after use (`alice-miner-gui/src/app.rs:85`, `:375`).
7. **LOW** — `child.rs` does not scrub the child's inherited environment (`alice-supervise/src/child.rs:120`); benign today (no secret is ever in this process's env) but worth hardening.
8. **LOW (verified-good, noted)** — updater pubkey is embedded and single-authority; no rotation/quorum path.

---

## Surface-by-surface findings

### 1. Secret / key handling — **PASS** (invariant holds end-to-end)

The brief's invariant — *"unlock exactly once at create/import; mining consumes only the PUBLIC
address"* — holds, and I traced it through every layer.

- **Keystore is the Wallet's, verbatim.** `alice-crypto/src/lib.rs` is the audited Wallet
  `crypto.rs`: V4 keystore, Argon2id KDF (t=3, m=19456, p=1), AES-256-GCM with `version+address`
  AAD, SS58-300. Secret seed is held behind `Arc<SecretSeed>` with a `Drop` that `zeroize()`s
  (`:123`); derived 64-byte seed and BIP-39 entropy are `Zeroizing` (`:576-580`); the AES key is
  `zeroize()`d after every encrypt/decrypt (`:281`, `:366`). The keystore file is written `0o600`
  via temp-file+fsync+rename (`:532-545`). Keystore path = the Wallet path
  (`data_local_dir()/AliceWallet/wallet.json`, honoring `$ALICE_WALLET_DATA_ROOT`) — one keystore,
  never two.
- **`unlock_wallet` runs exactly once.** `identity::create` / `import_mnemonic` / `import_seed_hex`
  each: build payload → write keystore → `unlock_wallet(...)` **once** inside a scoped block that
  derives `address` and immediately drops the `WalletSecrets` (zeroizing) — `identity.rs:113-117`,
  `:159-162`. The password is borrowed, never stored. `engine::run_identity` `zeroize()`s the
  password (and the mnemonic/seed-hex) right after the call returns (`engine.rs:428-446`).
- **`identity.json` holds NO secret.** `IdentityPointer` is `{address, pubkey?, keystore_path?,
  label?, created}` — public only (`identity.rs:36-52`). It is written `0o600` atomically and only
  at create/import/paste, never during mining (`write_pointer`, `:211`). The mining path
  (`engine::worker_loop`) keeps only `active_address: Option<String>` and feeds the lane builders
  only that string (`engine.rs:294`, `:481`, `:529`).
- **Paste is watch-only.** No keystore, no unlock — only `validate_alice_address` then write the
  pointer (`identity.rs:183`).
- **No secret in argv / logs / network.** Verified by code + tests: the XMR/RVN launch plans carry
  only `-u <public addr>` / the `-P` URL `<addr>.<rig_id>@...` (see §2). A repo-wide grep for any
  `println!/eprintln!/log/format` of `password|mnemonic|seed|private|secret` returned **nothing**.
  No code writes the mnemonic/seed anywhere except the encrypted keystore.
- **`sanitize_log_line` is a real backstop.** Strips ANSI, drops control chars, and redacts
  `>=48`-hex runs (`alice-supervise/src/lib.rs:125-199`); applied to every child log line before it
  reaches the snapshot/UI (`supervise.rs:641`).

No finding here. This is the strongest part of the codebase.

---

### 2. Network / argv honesty — **PASS**

- **Address-only login, baked relay only.** Both lanes target `hk.aliceprotocol.org` (`:3333` XMR /
  `:8888` RVN); the login is the user's own SS58-300 address; the rig-id is derived from the public
  address (`lane/xmr.rs:193`, `lane/gpu_rvn.rs:102`). OUR collection address + the upstream pool are
  deliberately **never imported, stored, or emitted** — the Wallet's `ALICE_XMR_COLLECTION_ADDRESS`
  const is intentionally not ported (`lane/xmr.rs:13-20`).
- **Core IP is operator-only.** `203.0.113.10` is never in a compiled default; it can only enter
  via the `ALICE_MINER_ENDPOINTS_JSON` operator override (`endpoint.rs:29`, `:176`). The default
  `EndpointPlan` is relay-only and a malformed override **fails open to the relay default**
  (`:189-195`).
- **Honesty gates are unit-enforced.** `endpoint.rs::default_plan_is_relay_only_no_core_ip`,
  `lane/xmr.rs::honesty_gate_argv_has_user_address_and_no_forbidden_substrings`, and
  `lane/gpu_rvn.rs::honesty_gate_rvn_argv_address_only_no_forbidden_substrings` assert the compiled
  defaults + built argv contain the relay + user address and **NOT** the core IP / Monero-mainnet /
  RVN-mainnet / `pool.` / `seed`/`priv`/`0x` substrings. All pass.
- **Snapshot is credit-only by construction.** `engine::Snapshot` has no `paid_acu`/payout/claim/
  settle/mint field; `snapshot_has_no_paid_acu_field` asserts the serialized JSON. The Source-B
  credit client is `NotExposed` and performs **no network I/O** in v1 (`app.rs:203`,
  `dashboard.rs`). The only network the client does is stratum to the relay (and, once wired, the
  updater fetch — see §3).

No identity- or infra-exfiltration path found.

---

### 3. Auto-updater (`alice-release`) — **1 HIGH + 2 MEDIUM/LOW**

The *cryptographic kernel is correct and well-tested* — but it is currently **dead code** in the
product, and its default config is wrong.

**[HIGH] H-1 — Updater is compiled-in but unwired, and its default URL is a wrong/placeholder repo.**
- `alice-release` is a dependency of `alice-miner-core` and re-exported (`lib.rs:30
  pub use alice_release;`), but a repo-wide grep shows **no front-end call site** for
  `check_for_update`, `apply_update`, `register_launch`, `confirm_health_and_commit`, or `relaunch`
  (only the crate's own `#[cfg(test)]`). The GUI `main.rs` / `app.rs` never arm the first-launch
  health gate at startup, and nothing ever checks for an update. So today the "auto-updater" does
  nothing — there is no in-product way to ship a fix, and (good news) no malicious-update exposure
  either.
- `DEFAULT_UPDATE_URL = "https://github.com/V-SK/alice-wallet/releases/latest/download/latest.json"`
  (`alice-release/src/lib.rs:84`) points at the **Wallet** repo slug and is explicitly marked a
  PLACEHOLDER ("pin it to the real public releases repo before cutting a release"). If the updater
  is wired without fixing this, the Miner would fetch the Wallet's manifest — which is then correctly
  **rejected** by the cross-product guard (`PRODUCT == "alice-miner"`, `parse_verified_manifest`
  `:311`), so it fails closed rather than mis-updating. Still: wrong-by-default config on the trust
  anchor is a HIGH because turning the feature on without auditing this line yields a silently
  broken update channel.
- **Impact:** no live update path; a future enable that forgets these two facts ships a non-functional
  or wrong-repo updater. **Fix:** (a) decide whether the Miner ships with auto-update *on* for v1; if
  yes, wire `register_launch` at GUI startup + a background `check_for_update` and pin
  `DEFAULT_UPDATE_URL` (and `release-assets/.../latest.json`) to the real `alice-miner` releases repo;
  if no, drop the `pub use alice_release` re-export (or gate it behind a feature) so it is not shipped
  as latent attack surface, and document "updates are manual for v1."

**Trust mechanics — verified correct (no finding):**
- ed25519 detached signature over the **exact** manifest bytes, verified with the embedded 32-byte
  pubkey **before** any manifest field is trusted (`verify_with_embedded_key` → `parse_verified_manifest`,
  `:412-413`). Raw ed25519 (not pre-hashed), matching the offline signer. Tampered-manifest and
  wrong-key tests pass (`:1246`, `:1260`).
- **No-downgrade:** `is_newer` is strict `>` (`:338`); equal is not newer. `min_supported` hard-block
  via `evaluate` (`:349`). Schema-too-new fails closed (`:305`). Cross-product guard (`:311`).
- **Artifact integrity:** size + lowercase-hex SHA-256 verified **before** the bytes are written,
  signed, unpacked, or run (`verify_artifact_integrity`, `:430`; `download_and_verify` reads at most
  `size+1` to catch oversize, `:497`; 1 GiB hard cap, `:110`).
- **TOCTOU:** the staged archive is **re-read from disk and re-verified** before extraction
  (`apply_update` `:876-880`).
- **Data-dir guard:** `assert_not_in_data_dir` refuses any install/swap/stage target inside the
  keystore data root, on canonicalized paths, enforced at every mutation site
  (`:459`, `:601`, `:857`, `:861`, `:890`); `app_swap_leaves_keystore_files_untouched` proves keys
  survive a swap.
- **Rollback / health gate:** last-known-good `.lkg` preserved on swap; first-launch `.pending-health`
  marker → `FreshFirstRun` → commit-or-rollback state machine (`:1020-1095`); crash-on-launch rolls
  back. All unit-proven.
- **TLS:** `ureq` is built with `default-features = false, features = ["tls", "gzip"]`, which pulls
  **rustls 0.23.40 + ring 0.17.14 + rustls-webpki** (Cargo.lock); there is **no** `danger`/
  `accept_invalid`/custom-verifier code anywhere in the crate, so certificate validation is on by
  default. No native-tls/openssl. Good.

**[MEDIUM] H-2 — `extract_archive` does not constrain extraction (zip-slip / symlink, defense-in-depth).**
The archive is SHA-verified before extraction, so this is *not* reachable without first breaking the
ed25519 anchor. But `tar -xzf` / `ditto -x -k` / `unzip -o` (`:712-773`) honor whatever paths/symlinks
the archive contains, into a staging dir. If the signing key is ever compromised, an attacker's archive
could write outside `unpacked/` (path traversal) or plant a symlink. **Fix:** prefer `tar
--no-same-owner -o` and consider a Rust extractor with explicit path-prefix + symlink rejection, or at
minimum extract into a fresh dir and validate the located unit's canonical path stays under the staging
root (the `assert_not_in_data_dir` on the *swap* target partially covers the final move, but not the
extraction itself).

**[LOW] H-3 — Single embedded authority, no rotation/quorum.** `RELEASE_PUBKEY_B64` is one key
(`:76`); compromise of the offline signer = full update takeover (within the SHA/no-downgrade
constraints). This is an accepted design tradeoff for a small project and is documented as such, but
note it: there is no threshold/secondary key and no revocation. **Fix (optional, later):** support a
small embedded keyset + a signed "key-rotation" manifest type.

---

### 4. Bundled-binary resolution — **2 MEDIUM**

**[MEDIUM] B-1 — The `miners.json` SHA-256 pin is never verified before exec.**
`resolve_miner_binary` (`binaries.rs:83`) resolves via env-override → sibling-of-exe → dev-fallback
and returns the path **iff `is_file()`** — it never reads `release-assets/miners.json` or compares the
binary's SHA-256 against the pin. A repo-wide grep confirms **`miners.json` is referenced by zero
lines of code** — it is purely documentation/manifest for the offline packaging step. So the
"SHA-pinned engine" guarantee exists only at *packaging* time, not at *runtime*. **Impact:** if the
on-disk miner is swapped after install (see B-2), nothing detects it. **Fix:** load the
target-triple's pinned SHA-256 from a bundled manifest (or bake it into the binary as a `const`) and
verify the resolved file's hash before `spawn_supervised`. This closes B-2 as well.

**[MEDIUM] B-2 — Sibling/override miner path is executed with no integrity check.**
The packaged path runs `…/<exe-dir>/xmrig` (or `kawpowminer`) (`binaries.rs:104`) and the
`ALICE_MINER_{XMR,GPU}_BIN` override runs whatever path is given (`:85`). On macOS/Linux the app dir
is normally not user-writable, but: (a) a non-admin install, a `~/Applications` drop, or any writable
sibling dir lets a local attacker replace the miner with arbitrary code that then runs as the user;
(b) the env override is a trivial planting vector for malware that can set a user's environment.
There is **no path-traversal bug** per se (no `..` is honored from untrusted input — the names are
compile-time constants, and the override is taken literally), and the dev-fallback is `#[cfg(debug_
assertions)]` only (not in release). The risk is purely *substitution*, addressed by B-1's hash
check. **Fix:** verify the SHA-256 pin (B-1); optionally warn/refuse when the override is set in a
release build, or require the override binary to also match a known hash.

**Verified-good:** resolution **never panics** — every failure is a clear, kind-specific
"not installed" `Err` (the GPU lane stays gracefully unavailable). Windows xmrig.exe is
"on-demand" in `miners.json` (downloaded + SHA-verified at runtime) — but note that download/verify
path is **not implemented in code yet** (consistent with B-1: `miners.json` is inert today).

---

### 5. Input validation (address paste + mnemonic/seed import) — **PASS**

- **Address paste:** `validate_alice_address` (`lane/xmr.rs:93`) bounds length (`<=64`), rejects
  non-ASCII-printable, base58-decodes with `.ok()` (no panic on garbage), checks exact length,
  the SS58-300 prefix, and the blake2b checksum. Fail-closed `None`. `paste` rejects empty,
  non-Alice, and wrong-network (generic substrate 42) addresses — `paste_is_watch_only_and_validates`
  proves it.
- **Mnemonic import:** `bip39::Mnemonic::parse` returns `Result` (mapped to a `String` error, no
  panic) (`alice-crypto:571`); a mismatched mnemonic-vs-seed fails the verify (`:276`).
- **Seed-hex import:** trims `0x/0X`, requires exactly 64 hex chars, `hex::decode().map_err(...)`
  (no panic), zeroizes the intermediate buffer on every path including errors
  (`create_wallet_payload_from_seed_hex`, `:314-337`).
- **No `unsafe` indexing on untrusted input.** The miner-stdout parsers (`parse_kawpow.rs`,
  `supervise::parse_*`) use `.parse().ok()`, `find()/split_once()` with `?`, and bounds-checked byte
  walks — no slice-index panics, no integer overflow (values land in `f64`/`u64` via checked parse).
  `parse_slash_counter` even guards `acc <= sub` before `sub - acc`.

Adversarial/malformed input degrades to a clean error or `None`. No panic/crash/UB found.

---

### 6. Process supervision — **PASS (1 LOW)**

- **No arg injection via address/rig-id/worker-id.** Children are spawned with
  `tokio::process::Command::new(program).args(args)` (`child.rs:120-121`) — an exec with an explicit
  argv vector, **no shell**, so a crafted address cannot inject flags or shell metacharacters. And the
  address is already constrained to the SS58 base58 charset + length by `validate_alice_address`
  before it ever reaches argv. The rig-id is derived from that validated address and is asserted to be
  the stratum-safe `[A-Za-z0-9_.-]` set.
- **Own-handle-only lifecycle.** Children run in their own process group (`setpgid(0,0)` via
  `pre_exec`, `child.rs:142`) with `kill_on_drop(true)`; stop is SIGTERM→bounded-wait→SIGKILL on the
  recorded PID only — never `pkill` by name (`child.rs:55-94`). Dual-mine crash-isolation is unit-
  proven (`two_supervisors_are_crash_isolated`). Failover is bounded by `RestartPolicy` (no restart
  storm; `failover_budget_exhaustion_lands_in_error_no_storm`).
- **Child privileges:** the child inherits the parent's (user-level) privileges — no escalation, no
  setuid. Fine.
- **`sanitize_log_line` does not leak.** It is applied to every child line and redacts long hex /
  strips control chars (see §1). It does **not** specifically redact an Alice address — but the
  address is the user's *own public* address (not a secret), and the collection/core strings are never
  present in the child's I/O in the first place, so this is correct.

**[LOW] S-1 — Child environment is not scrubbed.** `spawn_supervised` extends the inherited env with
the (empty) `envs` list but does not clear it (`child.rs:127-133`, with a comment acknowledging this).
Today nothing secret is ever in this process's environment (the password/seed live only on the stack
and in the encrypted keystore), so there is no actual leak. **Fix (hardening):** spawn with
`.env_clear()` then re-add only `PATH`/`HOME`/needed vars, so a future change that ever placed a secret
in the env couldn't leak it to the miner child.

---

### 7. Rust safety / supply chain — **PASS (modern deps)**

- **`unsafe`:** only two FFI declarations + `pre_exec`, all in `alice-supervise/src/child.rs`:
  `extern "C" kill`, `extern "C" setpgid`, and the `cmd.pre_exec(setpgid)` closure (`:91`, `:142`,
  `:183`). Each is a minimal, well-understood libc call on values the process owns (its child's PID;
  `0,0` for the new pgid). No raw-pointer/transmute/uninit `unsafe` anywhere. Acceptable.
- **panic/unwrap/expect:** the high counts per file are almost entirely inside `#[cfg(test)]` modules.
  In non-test code, `unwrap`/`expect` are confined to provably-infallible cases (e.g.
  `Blake2bVar::new(4).expect("4 is a valid output size")`, mutex `.expect("mutex")`, `generate_mnemonic`'s
  `from_entropy(32 bytes).expect(...)`). No `unwrap`/`expect`/`panic!`/indexing is reachable from
  adversarial input (addresses, mnemonics, miner stdout, manifest bytes, endpoint JSON all use
  `Result`/`Option`). Mutex `.expect()`/`unwrap_or_else(into_inner)` could in principle propagate a
  poisoned-lock panic, but a poisoned lock requires a prior panic-while-locked, which the audited paths
  don't produce. **LOW, accepted.**
- **Dependency versions (Cargo.lock), vuln-relevant:**
  - `ed25519-dalek 2.2.0`, `curve25519-dalek 4.1.3` — **past** RUSTSEC-2024-0344 (the Curve25519
    timing-variability advisory was fixed in 4.1.3). Good.
  - `rustls 0.23.40`, `ring 0.17.14`, `rustls-webpki` — current; no native-tls/openssl pulled in.
  - `aes-gcm 0.10.3`, `argon2 0.5.3`, `bip39 2.2.2`, `zeroize 1.8.2`, `subxt-signer 0.50.1`,
    `tokio 1.52.3` — all current, no known-applicable advisory at the stated versions.
  - eframe/egui `0.34.1`, resvg/usvg `0.37` (GUI only) — UI stack; not in the CLI dep tree (the CLI
    has a `no_egui_in_dep_tree` test). No security concern in scope.
  - **Note:** I reviewed versions against known RUSTSEC IDs from memory; a `cargo audit` /
    `cargo deny` run in CI is recommended as the authoritative, continuously-updated check (it was not
    run here as it requires network/advisory-db sync).

---

## Additional findings (input/UX hardening)

**[MEDIUM] U-1 — CLI `--password` is visible in the process table.**
`alice-miner identity --create --password <PASS>` takes the passphrase as a clap option
(`main.rs:144-145`). On a multi-user box, any user can read it via `ps -ef`/`/proc/<pid>/cmdline`,
and it lands in shell history. The code does offer a secure interactive prompt (`rpassword`,
`resolve_password`, `:580`) when `--password` is omitted — that path is fine. **Fix:** keep
`--password` for non-interactive automation but document the exposure prominently, OR remove it in
favor of `--password-stdin` / `--password-file`, and prefer the interactive prompt by default.

**[LOW] U-2 — GUI password fields are not zeroized.** `form_password`/`form_password2` are plain
`String` (`app.rs:85-86`) and are `.clear()`-ed after a successful identity op (`app.rs:375-378`).
`.clear()` does not wipe the backing buffer, and the `String` may have reallocated (leaving copies on
the heap). The downstream engine *does* zeroize the password it receives, so the window is small.
**Fix:** wrap the form password buffers in `zeroize::Zeroizing<String>` (or call `.zeroize()` before
clear).

**[LOW] U-3 — `begin_confirm` uses a time-seeded LCG for the backup-confirm word pick (`app.rs:601`).**
This is *not* a security primitive (the real entropy is in `generate_mnemonic`, which uses
`rand::thread_rng()` / OS CSPRNG correctly). The LCG only decides *which 3 words* to re-prompt for the
anti-skip backup check; predictability there has no security impact. Documented here only to record
that it was reviewed and is intentionally non-cryptographic. **No action needed.**

**[LOW] U-4 — `EndpointPlan::from_env_for` trusts operator JSON hosts verbatim.** The
`ALICE_MINER_ENDPOINTS_JSON` override can name any host:port (by design — operator-only). It is not a
client-facing input and a malformed value fails open to the relay. No DNS/SSRF concern for the public
client (the value isn't attacker-controlled). **No action needed; noted for completeness.**

---

## What is solid (verified-good, no finding)

- The crypto/keystore is the audited Wallet code, byte-for-byte, with correct zeroization and 0600
  perms.
- The "unlock once → mining uses only the public address" invariant holds across identity → engine →
  lane → supervise → child. No secret reaches argv, logs, files (other than the encrypted keystore),
  or the network.
- Honesty gates (no collection address / upstream pool / core IP in defaults or argv) are enforced by
  passing unit tests, and the secret strings are *never even imported* into this crate.
- Credit-only: no `paid_acu`/payout/claim/settle/mint anywhere; Source-B credit is `NotExposed` and
  does zero network I/O.
- The updater's signature + SHA-256 + no-downgrade + min-supported + cross-product + data-dir +
  rollback guards are correct and unit-proven; TLS verification is on (rustls).
- Detection is fail-safe and uses fixed program names + fixed/compile-time args — no command-injection
  surface.
- Process supervision is own-handle-only, shell-free, crash-isolated, and bounded.
- Modern, non-vulnerable dependency versions; minimal `unsafe`; no panic reachable from adversarial
  input.

---

## Go / No-Go

### Verdict: **GO for public (credit-only) distribution**, conditioned on the items below.

The client meets the Wallet's pre-release bar on the things that matter most for a *credit-only*
miner handed to the public: secrets never leave the encrypted keystore, mining is address-only, the
collection address / pool / core IP cannot leak, the snapshot is payout-free, and there is no
command-injection or arg-injection path. There are **no CRITICAL findings** and the single HIGH is a
latent-config / unwired-feature issue, not a live vulnerability.

**Required before flipping the auto-updater on (do NOT enable updates until these are done):**
1. **H-1:** Decide the v1 update posture. If auto-update is ON: wire `register_launch` at GUI startup
   + a background `check_for_update`, and pin `DEFAULT_UPDATE_URL` (and the published `latest.json`)
   to the real `alice-miner` releases repo. If OFF for v1: feature-gate / drop the `alice-release`
   re-export so it isn't shipped as dormant attack surface, and ship manual-update docs.

**Strongly recommended before public release (close the substitution gap):**
2. **B-1 / B-2:** Verify the engine binary's SHA-256 against a bundled/baked pin before `spawn` (and
   finalize the real, non-placeholder hashes in `miners.json` — they are all-zero today for the GPU /
   Windows entries). This is the one place a local attacker can run code as the user.

**Recommended (hardening, can be fast-follow):**
3. **U-1:** Discourage/replace CLI `--password` (process-table exposure) with stdin/file or the
   interactive prompt.
4. **H-2:** Constrain `extract_archive` against zip-slip/symlinks (defense-in-depth for the updater).
5. **S-1 / U-2:** `env_clear()` the miner child; `Zeroizing` the GUI password buffers.
6. Add `cargo audit` / `cargo deny` to CI as the continuously-updated supply-chain check.

Until the auto-updater is wired (H-1) and the runtime binary-pin check lands (B-1/B-2), the product is
safe to distribute **as a manually-updated, credit-only client**, which matches the documented
"DEPLOY HELD for joint launch / credit-only / payout phase-J" posture.

---

*End of report. Read-only audit — no product code modified; this file is the only artifact written.*
