# 03 — Embedded Minimal Wallet + Shared Identity

Status: DESIGN (research only — no product source modified)
Scope dimension: the Miner's embedded minimal wallet, the `~/.alice/` shared-identity
contract, and the security posture that mining touches only the **public address**.

Sibling apps: **Wallet** (`/Users/v/Alice/alice-wallet/gui`, full, exists), **Miner**
(this, `/Users/v/Alice/alice-miner`), **AI** (later, odysseus fork). All three must be
able to create/import a minimal Alice identity so no user is ever blocked by "I have no
address." The reward identity is an SS58-format-300 address; mining needs only that
address (see proven XMR path in `00-grounding`/the miner-reuse survey).

---

## 0. TL;DR of the recommended approach

1. **Extract a shared crate `alice-crypto`** from the Wallet's `gui/src/crypto.rs`
   verbatim (same KDF/AES/SS58/BIP39 constants and `WalletPayload` schema), depended on
   by both the Wallet and the Miner. One mnemonic then unlocks in all three apps because
   the keystore bytes are byte-identical.
2. **Keep the keystore where the Wallet already writes it** —
   `data_local_dir()/AliceWallet/wallet.json` — and treat `~/.alice/` as a small
   **pointer + roster** layer (`identity.json`), NOT the keystore home. This resolves the
   conflict between the brief ("shared `~/.alice/`") and the shipped Wallet reality
   (keystore lives under `AliceWallet/`, `~/.alice/` is only a *legacy read* fallback).
   See §2 and the open question for V.
3. **Mining reads only `identity.json.active_address`** — a plain public SS58 string. The
   keystore is decrypted exactly **once**, at create/import, to derive+verify the address;
   it is **never unlocked during mining**.
4. **Create flow forces a mnemonic-backup confirmation** (a Miner improvement over the
   Wallet's create screen, which shows the phrase without a re-entry gate).

---

## 1. Reuse: the `alice-crypto` shared crate

### 1.1 What we reuse verbatim (do NOT reimplement)

From `/Users/v/Alice/alice-wallet/gui/src/crypto.rs`:

| Item | Source line | Why it must be identical |
|---|---|---|
| `pub struct WalletPayload` | `crypto.rs:35-53` | On-disk JSON schema; one mnemonic ⇒ same file ⇒ all apps read it |
| `create_wallet_payload(mnemonic, password)` | `crypto.rs:258-262` | Create-from-BIP39 |
| `create_wallet_payload_from_seed_hex(seed_hex, password)` | `crypto.rs:266-289` | Import raw 32-byte seed |
| `unlock_wallet(payload, password) -> UnlockOutcome` | `crypto.rs:201-248` | Decrypt + verify + v2→v4 migration |
| `WalletSecrets` (`to_keypair`, `export_private_key_hex`, `display_only`) | `crypto.rs:81-122` | sr25519 keypair / address-only |
| `write_wallet_payload` / `backup_existing_wallet` | `crypto.rs:153-199` | Atomic 0o600 write + `.bak-<ts>` |
| `account_id_to_ss58(pubkey, 300)` (private) | `crypto.rs:538-558` | Address encoding (prefix 300) |
| Constants: `SS58_FORMAT=300`, `CURRENT_WALLET_VERSION=4`, Argon2id `(t=3, m=19456 KiB, p=1)`, `MIN_LEGACY_PBKDF2_ITERATIONS=200_000` | `crypto.rs:18-33` | Byte-for-byte KDF/version compat |

Crate deps to move with it (already in `gui/Cargo.toml`): `aes-gcm 0.10.3`, `argon2 0.5.3`,
`pbkdf2 0.12.2`, `bip39 2.0.0`, `substrate-bip39 0.6.1`, `subxt-signer 0.50.0`
(`sr25519,std`), `bs58 0.5.1`, `blake2 0.10.6`, `sha2 0.10.8`, `base64 0.22.1`,
`hex 0.4.3`, `rand 0.8.5`, `serde`/`serde_json`, `zeroize 1.8.2`.

### 1.2 Crate layout

```
alice-crypto/                         # NEW shared library crate
├── Cargo.toml
└── src/
    ├── lib.rs        # re-exports: WalletPayload, WalletSecrets, UnlockOutcome,
    │                 #   create_wallet_payload, create_wallet_payload_from_seed_hex,
    │                 #   unlock_wallet, write_wallet_payload, backup_existing_wallet,
    │                 #   SS58_FORMAT, CURRENT_WALLET_VERSION, generate_mnemonic()
    ├── keystore.rs   # WalletPayload + encrypt/decrypt + atomic write (crypto.rs:35-53,170-199,388-440)
    ├── derive.rs     # Argon2id + PBKDF2 (crypto.rs:335-379)
    ├── sign.rs       # sr25519 keypair, account_id_to_ss58 (crypto.rs:106-122,538-558)
    └── mnemonic.rs   # generate_mnemonic() + parse → seed (crypto.rs:517-536)
```

**Migration of the Wallet itself** is mechanical and out-of-scope for *this* design (no
product source edits now): the Wallet's `gui/src/crypto.rs` becomes
`pub use alice_crypto::*;` plus its `config::wallet_data_root()` path glue stays in the GUI.
Until that refactor lands, the Miner can depend on `alice-crypto` as a path crate that
**physically copies** the reviewed `crypto.rs` body; the test vectors in `crypto.rs:560-736`
move with it and guarantee parity. No re-derivation of crypto by hand.

### 1.3 One net-new helper: `generate_mnemonic()`

The Wallet generates the phrase in the **view layer** (`gui/src/ui/create.rs:56-64`), not in
`crypto.rs`. To avoid duplicating entropy logic in the Miner, lift it into the crate **exactly
as the Wallet does it** (24 words, 32 bytes from `rand::thread_rng()`, held in `Zeroizing`):

```rust
// alice-crypto/src/mnemonic.rs
use bip39::Mnemonic;
use rand::RngCore;
use zeroize::Zeroizing;

/// Generate a fresh 24-word BIP39 phrase. Mirrors alice-wallet/gui/src/ui/create.rs:56-64
/// (32 bytes of entropy → 24 words). The caller MUST zeroize the returned String after the
/// user confirms backup.
pub fn generate_mnemonic() -> String {
    let mut entropy = Zeroizing::new([0u8; 32]);
    rand::thread_rng().fill_bytes(entropy.as_mut());
    let m = Mnemonic::from_entropy(entropy.as_ref()).expect("32 bytes -> 24-word mnemonic");
    m.words().collect::<Vec<&str>>().join(" ")
}
```

---

## 2. The `~/.alice/` shared-identity contract

### 2.1 Critical reality check (drives the whole contract)

The brief says "SHARED IDENTITY across the 3 apps via `~/.alice/`: identity.json + a shared
encrypted keystore (same format as the Wallet)." But the **shipped Wallet does not put its
keystore in `~/.alice/`**:

- `default_wallet_path()` = `wallet_data_root().join("wallet.json")`
  (`crypto.rs:129-131`).
- `wallet_data_root()` = `dirs::data_local_dir()/AliceWallet` (or
  `$ALICE_WALLET_DATA_ROOT`) (`config.rs:67-75`). On macOS that is
  `~/Library/Application Support/AliceWallet/wallet.json`; on Linux
  `~/.local/share/AliceWallet/wallet.json`; on Windows
  `%LOCALAPPDATA%\AliceWallet\wallet.json`.
- `~/.alice/wallet.json` exists **only as a legacy read fallback** — `legacy_data_dir()`
  (`crypto.rs:466-474`) and `detect_wallet_path()` (`crypto.rs:133-149`), used when the
  primary path is absent and not overridden.

**Therefore "one mnemonic works in all three apps" is satisfied by the keystore being
byte-identical and at a path all three resolve — NOT by inventing a second keystore in
`~/.alice/`.** Two keystores would desync (the 64× footgun: two addresses, user mines to
one, unlocks the other). The Miner **must not** create a competing keystore location.

### 2.2 Decision — two-layer model

- **Layer A — Keystore (the secret):** `wallet.json` at the **Wallet's** path
  (`AliceWallet/wallet.json`, env-overridable via `ALICE_WALLET_DATA_ROOT`). Owned by
  whichever app creates first; read by the others. Schema = `WalletPayload` (§1.1).
- **Layer B — Identity pointer + roster (public only):** `~/.alice/identity.json`. A tiny,
  unencrypted, world-public file that names the **active address** and where its keystore
  lives. This is the cross-app rendezvous the brief asks for, holding **no secrets**.

`~/.alice/` is chosen for Layer B because it is the one home-relative path all three apps
trivially agree on (no per-OS `data_local_dir` divergence), it is exactly what the brief
specifies, and it already has precedent in the Wallet (`legacy_data_dir()`).

### 2.3 `~/.alice/identity.json` schema

```jsonc
{
  "schema": "alice-identity/1",          // bump on breaking change
  "active_address": "a2…",               // SS58 fmt-300; the reward identity miners use
  "label": "Main",                        // user-facing nickname (optional, default "Main")
  "created": "2026-06-03T12:00:00Z",      // RFC3339 UTC, set once at create/import
  "updated": "2026-06-03T12:00:00Z",      // RFC3339 UTC, bumped on any write
  "keystore": {
    "kind": "alice-wallet-json/v4",      // == WalletPayload.version family
    "path": "/Users/v/Library/Application Support/AliceWallet/wallet.json",
    "data_root_env": "ALICE_WALLET_DATA_ROOT" // honored if set, for parity with Wallet
  },
  "source_app": "miner",                  // who last wrote this file: wallet|miner|ai
  "public_key": "0x…"                     // hex pubkey, mirrors WalletPayload.public_key
}
```

Rust type (Miner-owned, in `alice-miner/src/identity.rs`):

```rust
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct AliceIdentity {
    pub schema: String,                 // "alice-identity/1"
    pub active_address: String,         // SS58 fmt-300
    #[serde(default)] pub label: String,
    pub created: String,                // RFC3339
    pub updated: String,                // RFC3339
    pub keystore: KeystoreRef,
    #[serde(default)] pub source_app: String,
    #[serde(default)] pub public_key: String,
}
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct KeystoreRef {
    pub kind: String,                   // "alice-wallet-json/v4"
    pub path: String,                   // absolute path to wallet.json
    #[serde(default)] pub data_root_env: String,
}
```

Functions (`alice-miner/src/identity.rs`):

```rust
pub fn alice_home() -> PathBuf;                 // $ALICE_HOME or dirs::home_dir()/.alice
pub fn identity_path() -> PathBuf;              // alice_home()/identity.json
pub fn read_identity() -> Option<AliceIdentity>;          // None if absent/corrupt
pub fn write_identity(id: &AliceIdentity) -> Result<(), String>; // atomic, 0o600, see §2.5
pub fn active_address() -> Option<String>;      // == read_identity().map(|i| i.active_address)
pub fn keystore_path() -> PathBuf;              // resolve from identity, else Wallet default
```

`alice_home()` adds an `$ALICE_HOME` override (mirrors the Wallet's `ALICE_WALLET_DATA_ROOT`
pattern) so tests and power users can relocate the rendezvous without touching real data.

### 2.4 Read / write rules (the core contract)

**On Miner launch (resolve identity):**
1. `read_identity()`.
   - If present and `active_address` is checksum-valid fmt-300 → **use it; mine.** (Validate
     with the same fail-closed check the miner lane already uses,
     `miner.rs:255-318 validate_alice_address`.)
   - If present but address invalid/corrupt → surface "identity file unreadable; re-link or
     create"; do **not** silently overwrite.
2. If `identity.json` absent → look for an existing keystore via the **Wallet's** resolver
   (`detect_wallet_path()` semantics: primary `AliceWallet/wallet.json`, else legacy
   `~/.alice/wallet.json`).
   - **Keystore found** (Wallet already installed): read its `address` field **without
     unlocking** (the `WalletPayload.address` is plaintext, `crypto.rs:38`). **Adopt** that
     address: write `identity.json` pointing at that keystore, `source_app:"miner"`. Now both
     apps share one address. No password needed, no key touched.
   - **No keystore** → enter the create/import flow (§3). Whoever creates writes BOTH the
     keystore (Layer A) and `identity.json` (Layer B).

**What happens if BOTH Wallet and Miner exist:**
- They share **one** keystore (Layer A) and **one** `identity.json` (Layer B). The Miner
  never creates a second keystore.
- If the Wallet created first, the Miner **adopts** (reads plaintext `address`, writes the
  pointer). If the Miner created first, the Wallet opens the same `wallet.json` via its
  normal resolver and unlocks it with the same mnemonic/password (it ignores
  `identity.json`, which is fine — see §5 migration).
- **Conflict rule:** `identity.json` is the source of truth for *which address to mine to*.
  If `identity.json.active_address` and the keystore's `address` disagree (e.g. the user
  re-imported a different mnemonic in the Wallet), the Miner trusts the **keystore's**
  `address` (the secret-backed truth), shows a one-line "identity updated" notice, and
  rewrites `identity.json` to match. Rationale: the keystore is authoritative because it is
  the thing that can actually sign; the pointer is a cache.

### 2.5 Write discipline

- `identity.json` is written **atomically**: temp file `identity.json.tmp-<pid>` → `fsync` →
  rename (mirrors `write_wallet_payload`, `crypto.rs:176-189`). Mode `0o600` on Unix.
- `~/.alice/` is created with `0o700` on Unix if missing.
- `identity.json` is written on exactly three events: (a) create, (b) import, (c) adopt an
  existing keystore. It is **never** written during mining.
- The keystore (Layer A) is written **only** by the create/import path through
  `alice_crypto::write_wallet_payload`, which already does atomic + 0o600 + `.bak-<ts>`
  backup-before-overwrite (`crypto.rs:153-199`). The Miner reuses `backup_existing_wallet`
  before any import so a stray import can never silently destroy a Wallet keystore.

---

## 3. Minimal UI flow (极简一键, must be 漂亮/流畅)

The miner's first-run gate is a single decision: **do we already have an address?** If yes
(via §2.4 resolution), skip straight to the one-button mining screen. If no, show **one**
screen with two paths.

### 3.1 First-run identity screen (only when no address resolves)

```
        ◆ Alice  (orange logo, #F97316)
   ──────────────────────────────────────
   START MINING IN ONE STEP

   You need an Alice address to receive mining credit.

   [  Create a new address  ]   ← primary (orange, glow on hover)
   [  Import existing phrase ]   ← ghost
   [  Paste an address only  ]   ← text link (watch-only mining, §3.4)
```

Brand: dark `#050505` bg, glass card `rgba(24,24,27,0.62)`, Inter for copy, JetBrains Mono
for the address, status dot green when mining. (See brand-ui survey for tokens.)

### 3.2 CREATE flow (3 steps, forced backup confirm)

> The Wallet's create screen (`ui/create.rs`) shows the phrase but has **no re-entry gate**.
> The Miner brief explicitly requires "force mnemonic backup on create," so the Miner adds a
> confirm step. This is the one intentional UX divergence from the Wallet.

**Step 1 — Password.** Reuse the Wallet's rule exactly: ≥12 chars, confirm field, strength
bar (`ui/create.rs:33-54`). Copy: "This password encrypts your address on this machine."

**Step 2 — Show recovery phrase.** Call `alice_crypto::generate_mnemonic()` → 24 words.
Render as a numbered 24-cell grid (mono), with **Copy** and **I've written it down** (which
is disabled for ~5 s / until scrolled, to discourage skipping). Big amber warning:
"Anyone with these 24 words controls this address. Alice can never recover them."

**Step 3 — Confirm backup (the forced gate).** Ask the user to retype **3 random words**
(e.g. #5, #13, #20) into three inputs. On all-correct:
- `payload = create_wallet_payload(phrase, password)` (`crypto.rs:258`).
- `unlock_wallet(&payload, &password)` once to derive+verify the address & keypair
  (`crypto.rs:201`) — this is the **only** unlock the Miner ever performs.
- `write_wallet_payload(keystore_path(), &payload)` (`crypto.rs:170`).
- `write_identity(&AliceIdentity{ active_address, public_key, created=now, source_app:"miner", … })`.
- **Zeroize** the phrase + password (the worker already does this:
  `app.rs:1652-1676` pattern). Drop `WalletSecrets` (its `Drop` zeroizes,
  `crypto.rs:87-96`).
- → mining screen, "Mining to a2…7f9q · CPU (XMR)".

If words are wrong, inline error, no advance. The phrase stays in a `Zeroizing` buffer in
the view state and is wiped on leaving the flow regardless of success.

### 3.3 IMPORT flow (2 steps)

**Step 1 — Password** (same ≥12-char rule).

**Step 2 — Enter phrase OR raw seed.**
- Mnemonic path: textarea → `create_wallet_payload(phrase, password)` (`crypto.rs:258`).
- Raw-seed path (advanced, collapsed by default): `0x`+64 hex →
  `create_wallet_payload_from_seed_hex(seed_hex, password)` (`crypto.rs:266`).
- Before writing: `backup_existing_wallet(keystore_path())` (`crypto.rs:153`) so an import
  never clobbers a Wallet keystore.
- Then same `unlock`(verify-only) → `write_wallet_payload` → `write_identity` → zeroize →
  mining screen. **No backup-confirm** on import (the user already holds the phrase).

### 3.4 PASTE-ADDRESS-ONLY flow (watch-only mining)

For users who already have an address elsewhere and just want to point the rig at it:
- One input, validate with `validate_alice_address` (fail-closed, `miner.rs:255-318`).
- Write **only** `identity.json` (`active_address` = pasted, `keystore.kind:"none"`,
  `public_key:""`). **No keystore is created.** Mining works (it needs only the address).
- UI badge: "Watch-only · no recovery phrase on this device." If a keystore later appears
  (Wallet installed) for the same address, `keystore.kind` is upgraded on next launch.

This honors the brief's "create OR import" while also covering the relay's open-enrollment
reality, where the login *is* the address (miner-reuse survey: `-u <alice_addr> -p x`).

---

## 4. Security posture — mining touches only the public address

**Invariant: the private key (seed) is decrypted exactly once, at create/import, to derive
and verify the address. It is NEVER read or unlocked during mining.**

- The mining lane consumes a **string**: `identity.active_address`. It is fed to the XMR
  stratum login as `-u <address> -p x --rig-id <worker_id>` (miner-reuse survey;
  `miner.rs:355-396`). No keypair, no seed, no signing is involved on the mining path.
- `unlock_wallet` (the only thing that decrypts the seed) is called **only** in the
  create/import worker, never from the supervisor/stratum code. The `WalletSecrets` it
  returns is used solely to confirm `address == payload.address` (already enforced inside
  `unlock_wallet` via `verify_identity`, `crypto.rs:218,452-464`) and is then dropped; its
  `Drop` zeroizes (`crypto.rs:87-96`). We do **not** persist `WalletSecrets`, hold it in app
  state, or pass it to the miner.
- **No password prompt to start mining.** Because mining needs only the public address,
  the Miner can start hashing on launch with zero unlocks — matching "极简一键."
- The worker-id derived from the address (`derive_worker_id`/`worker_identity`,
  `miner.rs:207-221, 288-318`) is also a pure function of the **public** address; no secret
  input. This doubles as the fail-closed Alice-address validator.
- Keystore file perms 0o600, dir 0o700, atomic writes, backup-before-overwrite — all
  inherited from `alice-crypto` (`crypto.rs:153-199, 484-497`).
- `identity.json` holds **no secret** (address + pubkey + paths are public), so its 0o600 is
  defense-in-depth, not a confidentiality boundary.
- Credit-only: nothing here reads/writes a payout address or reward-claim. The address is a
  reward *identity* only. (Hard constraint; consistent with `paid_acu=0`.)

**Threat note:** because mining never unlocks, a compromised mining process cannot exfiltrate
the seed — it only ever sees the public address. The seed-at-rest is only as strong as the
user's password via Argon2id (t=3, m=19 MiB) — unchanged from the Wallet's posture.

---

## 5. Migration: when the Wallet later opens the same keystore

Three cases, all already safe by construction:

1. **Miner created first, Wallet opens later.** The Wallet's `detect_wallet_path()` finds
   `AliceWallet/wallet.json` (the path the Miner wrote, via `keystore_path()` which defaults
   to the Wallet path). `unlock_wallet` decrypts it normally — same KDF/AAD/version because
   both use `alice-crypto`. The Wallet **ignores** `identity.json` (it has no such concept
   today); harmless. **Action item (separate, not now):** teach the Wallet to also write
   `identity.json` on create/import for full symmetry — until then the Miner keeps the
   pointer fresh by re-reading the keystore `address` on each launch (§2.4 conflict rule).

2. **Wallet created first, Miner opens later.** Miner **adopts** (reads plaintext
   `address`, writes the pointer) — no unlock, no second keystore (§2.4).

3. **v2/v3 → v4 KDF/AAD upgrade.** Handled entirely inside `unlock_wallet`: it returns
   `upgraded_payload` when params are stale (`crypto.rs:235-239, 442-450`). Whichever app
   performs an unlock that yields an upgrade should write it back via
   `write_wallet_payload`. Since the **Miner unlocks only at create/import** (where it writes
   a fresh v4 anyway), in practice the **Wallet** drives runtime upgrades. The Miner's
   create/import always writes `CURRENT_WALLET_VERSION=4`, so it never *downgrades* a file.
   AAD binds (version,address) (`crypto.rs:388-394`), so a v4 ciphertext can't be silently
   relocated onto a different address — protecting both apps.

**Keystore-path divergence guard:** if `$ALICE_WALLET_DATA_ROOT` is set for one app but not
the other, they could resolve different keystore paths. The Miner records the resolved
`keystore.path` (and the env name) into `identity.json` and, on launch, prefers that recorded
path; if it is missing it falls back to the live Wallet resolver. This keeps the two apps on
one file even under env drift. (Open item for V: standardize one env var across all three —
see §6.)

---

## 6. Open questions for V

1. **Keystore home:** confirm we keep the keystore at the Wallet's
   `data_local_dir()/AliceWallet/wallet.json` (recommended; one file, zero desync) and use
   `~/.alice/identity.json` purely as the public pointer/roster — rather than moving the
   keystore itself into `~/.alice/`. The brief's wording implies the keystore lives in
   `~/.alice/`; the shipped Wallet does not. **Recommend: pointer-only `~/.alice/`.**
2. **Env var unification:** should all three apps honor a single `ALICE_HOME` (for the
   pointer) and a single keystore-root env, or keep the Wallet's `ALICE_WALLET_DATA_ROOT`?
3. **Wallet write-back of `identity.json`:** OK to file a follow-up so the Wallet also
   writes `identity.json` on create/import (full symmetry)? Until then the Miner self-heals
   the pointer from the keystore on each launch.
4. **Multi-address roster:** `identity.json` currently names ONE active address. Do we want a
   `roster: []` of known addresses now (Wallet supports profiles, `wallet_profiles.rs`), or
   defer until the AI app needs it?

---

## 7. Build checklist (for the implementer)

- [ ] Create `alice-crypto` crate; move `crypto.rs` body + its tests; add
      `generate_mnemonic()` (§1.3). Verify `cargo test -p alice-crypto` passes the moved
      vectors (`crypto.rs:560-736`).
- [ ] `alice-miner` depends on `alice-crypto` (path dep for now).
- [ ] `alice-miner/src/identity.rs`: `AliceIdentity`/`KeystoreRef` + the 6 functions (§2.3),
      atomic 0o600 writes, `$ALICE_HOME` override.
- [ ] First-run resolver (§2.4): read identity → adopt keystore → else create/import.
- [ ] UI: identity screen + Create(3-step, forced confirm) + Import(2-step) + Paste-only
      (§3), Alice brand tokens.
- [ ] Wire the mining lane to consume **only** `identity::active_address()`; assert no path
      from the supervisor calls `unlock_wallet` (§4).
- [ ] Tests: (a) Miner-then-Wallet round-trip on one `wallet.json`; (b) Wallet-then-Miner
      adopt (no second keystore, no unlock); (c) conflict rule (keystore wins, pointer
      rewritten); (d) paste-only writes no keystore; (e) import backs up an existing
      keystore before overwrite.

---

## 8. File/line citations used

- Keystore + crypto: `/Users/v/Alice/alice-wallet/gui/src/crypto.rs`
  (`WalletPayload` 35-53; `unlock_wallet` 201-248; `create_wallet_payload` 258-262;
  `create_wallet_payload_from_seed_hex` 266-289; `write_wallet_payload` 170-199;
  `backup_existing_wallet` 153-168; default/legacy paths 129-149,466-474; KDF 335-379;
  AAD 388-394; SS58 538-558; tests 560-736).
- Paths/env: `/Users/v/Alice/alice-wallet/gui/src/config.rs` (`wallet_data_root` 67-75;
  `ALICE_WALLET_DATA_ROOT` 7,81-87).
- Mnemonic generation (24 words, 32-byte entropy, Zeroizing):
  `/Users/v/Alice/alice-wallet/gui/src/ui/create.rs:56-64`; password rule 33-54.
- Create/import worker (zeroize discipline): `/Users/v/Alice/alice-wallet/gui/src/app.rs:1652-1716`.
- Address-only mining identity + worker-id (public-only, fail-closed):
  `/Users/v/Alice/alice-wallet/gui/src/miner.rs` (`worker_identity` 207-221;
  `validate_alice_address` 255-318; XMR launch 355-396).
- Deps: `/Users/v/Alice/alice-wallet/gui/Cargo.toml`.
