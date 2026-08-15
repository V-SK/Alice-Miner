//! `core/engine_pins` — the engine SHA-256 pin table, **updatable without a
//! client release**.
//!
//! ## Why this exists (2026-08-11 Pearl hard fork)
//!
//! The GPU-PRL lane pins SRBMiner-MULTI 3.4.1 by SHA-256. On 2026-08-11 Pearl
//! hard-forked the algorithm; SRBMiner 3.5.3 shipped the same morning marked
//! MANDATORY, and from 12:04Z every share our miners produced was rejected
//! upstream. `release-assets/miners.json` is `include_str!`-baked into the
//! binary ([`binaries`](crate::binaries)), so changing one hash meant cutting,
//! signing and shipping a whole client release — and v0.6.5/0.6.6/0.6.7 all pin
//! the *identical* engine bytes, which is why "just self-update" would have
//! fixed nothing at all.
//!
//! This module keeps the engine machinery exactly as it was — download, verify
//! against a pin, atomically install, never exec anything unverified — and moves
//! only the **pin table** onto its own signed, independently publishable
//! document:
//!
//! ```text
//!   engines.json      + engines.json.sig     (detached ed25519)
//!   ── signed by the ENGINE-PIN SUB-KEY, not the release root key ──
//! ```
//!
//! ## Trust model (read this before changing anything)
//!
//! * **Two keys, unequal power.** The release root key signs `latest.json` = the
//!   client bytes you run; its compromise is RCE on every miner. The engine-pin
//!   sub-key ([`alice_release::ENGINE_PIN_PUBKEY_B64`]) signs ONLY this document.
//!   It still matters — the engine is a third-party binary we exec — but it
//!   cannot ship a client, cannot change `min_supported`, and cannot point at a
//!   host outside [`ALLOWED_URL_PREFIXES`], which is compiled in.
//! * **Fail-closed, always.** No signature, bad signature, unknown schema,
//!   malformed entry, non-allow-listed URL, replayed/rolled-back `epoch`, or a
//!   hash that contradicts one we have already seen for the same engine version
//!   ⇒ the document is **rejected whole** and the client keeps using the pins
//!   compiled into it (the *floor*). We never partially apply a document.
//! * **The floor is never bypassed.** A build with no embedded sub-key (the
//!   state of this very commit — the key is generated offline by V) does not
//!   fetch anything: it uses its baked-in pins and says so.
//! * **Verified-before-effective.** A new pin becomes effective only after the
//!   engine bytes it names have been downloaded and hashed to match. A network
//!   failure therefore leaves the *previous* pin in force (mining continues); a
//!   hash MISMATCH rejects the document (loudly) and mining continues on the
//!   previous pin. What never happens: running bytes nobody verified.
//! * **Monotonic epoch.** `epoch` only ever goes up; `min_engine_epoch` lets a
//!   publisher retire everything older. Both are persisted, so an attacker
//!   replaying yesterday's signed document cannot roll an engine back.
//! * **Same version ⇒ same hash, forever.** Every (kind, target, version) → sha
//!   we have ever accepted (including the embedded floor) is remembered. A
//!   document that re-issues a known version with different bytes is rejected —
//!   the sub-key cannot quietly swap an engine under a version we trust.
//! * **Versions only go forward.** Per (kind, target) the highest version ever
//!   accepted is remembered, and a document naming an older one — or one this
//!   client cannot order against it — is rejected UNLESS the entry explicitly
//!   marks itself [`PinEntry::downgrade`] with a reason. Without this the sub-key
//!   could point the fleet back at SRBMiner 3.4.1 (an exact one-key replay of the
//!   August outage) or at any older build with a known hole, using bytes that are
//!   still genuinely hosted on an allow-listed upstream release page. See
//!   [`compare_versions`] for the deliberately conservative ordering rule.
//!
//! ## The pin carries the CALL, not just the bytes (2026-08-14)
//!
//! A pin used to say only *which bytes*; **how to invoke them** and **how to read
//! their output** were compiled in. SRBMiner-MULTI 3.5.4 proved that is not
//! enough: it reshaped both log lines the client's parser depends on, and a
//! healthy GPU landing accepted shares at 44.8 TH/s displayed
//! `0 H/s · 0A/0R · STALL` for a whole twenty-minute run while the no-progress
//! watchdog restarted the engine on that false reading. Publishing a new
//! `engines.json` could not have fixed that — a client release could. That is the
//! exact opposite of this feature's claim.
//!
//! So a signed entry may now also carry [`PinEntry::algorithm`],
//! [`PinEntry::extra_args`] and [`PinEntry::parser`]
//! ([`EngineInvocation`]). All three are **optional**: absent ⇒ byte-for-byte
//! today's compiled-in behaviour. All three are **fail-closed**: an unknown parser
//! id, an implausible algorithm token, an algorithm on a kind whose argv has no
//! algorithm slot, or an extra argument that is not on the reviewed allow-list for
//! that engine rejects the whole document. And all three are re-validated at
//! argv-build time, so the property belongs to the launch path and not only to the
//! acceptance path.
//!
//! ### `extra_args` is an ALLOW-list, and why it had to become one (2026-08-15)
//!
//! The first cut of this feature policed publisher argv with a **deny**-list of
//! flags the client owns ([`CLIENT_OWNED_FLAGS`]) and let everything else through.
//! That is not a decidable rule: it requires us to have enumerated every spelling
//! of every credit/transport/write flag of a third-party binary whose surface we
//! do not control and which changes between versions. It failed on the very engine
//! this repo ships — xmrig 6.26 spells `--user`/`--pass` *also* as `--userpass`,
//! `--proxy` also as `-x`, and `--log-file` also as `-l`; none of those three were
//! on the list, and each was live-verified to redirect credit, transport or writes
//! (see the tests at the bottom of this file).
//!
//! So the rule is inverted. A pin's extra argv may contain **only** flags on a
//! per-engine-kind list that a human has reviewed against that engine's own
//! documented flag surface ([`extra_arg_allowlist`]), each declaring whether it
//! takes a value, with values restricted to a charset that cannot spell a host, a
//! `user:pass` pair or a path. What this **does** guarantee: an alias nobody
//! enumerated cannot pass, because passing requires being named, not requires not
//! being named. What it **does not** guarantee: that a flag we *did* review is
//! harmless on a future version of that engine — a vendor may repurpose a flag, and
//! only re-review catches that. The deny-list stays as a second, independent belt
//! (it can only ever refuse more), and a test asserts the two lists are disjoint so
//! it cannot rot into decoration.
//!
//! ### …and the allow-list is only sound if we stop predicting the parse (2026-08-16)
//!
//! Inverting the list was necessary and not sufficient. A second adversarial pass
//! re-exploited it twice, both proved live against the bundled
//! `release-assets/aarch64-apple-darwin/xmrig`, and both from the same root cause:
//! **the validator held a model of how the engine would parse the argv it approved,
//! and every wrong guess in that model was a bypass.**
//!
//! * *Arity.* A value was accepted in a positional slot after any flag declared
//!   value-taking, and in that slot the allow-list and [`CLIENT_OWNED_FLAGS`] were
//!   never consulted — only the content/charset scans, which `-o127.0.0.1` and
//!   `-uATTACKER` pass cleanly. `--randomx-wrmsr` takes an *optional* argument and so
//!   consumes nothing; `--asm` is not implemented at all on the ARM build (its own
//!   `--help` says otherwise). Either way the "value" reached the engine as a real
//!   option, and — because `-o` accumulates rather than overrides — the publisher's
//!   pool became POOL #1.
//! * *Case.* The lookup case-folded and the emitted token did not, so
//!   `--RANDOMX-MODE` was a value-taking reviewed flag to us and `unrecognized
//!   option` to xmrig, which does not abort on one. It consumed nothing, and the
//!   token our validator had waved through as "just a value" became a real flag.
//!   This generalised the first hole from two flags to all six.
//!
//! So the rule no longer predicts anything. Extra argv is now **one canonical token
//! per reviewed flag**: `--flag` or `--flag=value`, exact case, long form, each flag
//! named at most once, every token checked against both lists. There is no value
//! position, so there is nothing for a mis-guessed arity to leave behind; an
//! unrecognised token is one word the engine skips whole (measured: an inline value
//! cannot escape its token); and a token we accept is byte-for-byte the token the
//! engine matches. The property is: **a token that passes either does what we
//! believe it does, or is refused — it is never silently inert to the engine while
//! opening a door.**
//!
//! The same change closes an honest-operator bug with the same root: `--Randomx-Mode=light`
//! used to be a document every rig accepted and no engine ever honoured — a signed
//! instruction silently dropped, which is the hazard [`KINDS_WITH_ALGORITHM_SLOT`]
//! exists to prevent one field over.
//!
//! What is *not* claimed: that a reviewed flag is harmless on a future build of that
//! engine. Only re-review catches a repurposed flag. What is also not claimed is that
//! `--help` is evidence — on this very binary it documents an option the binary does
//! not implement.
//!
//! The price is stated plainly rather than hidden: a fork that needs a switch we
//! have never reviewed now costs a **client release** (a one-line table entry),
//! where the deny-list would have published it. That is the trade the August
//! outage argues for in the other direction — and it is still the right one,
//! because the deny-list's failure mode was every share on the lane being credited
//! to whoever held the sub-key.
//!
//! **What this does NOT remove**, stated plainly (also in
//! `docs/engine-pin-publishing.md`): a fork whose output needs a parser this
//! client does not compile in, an engine that needs a *different argv shape*
//! (flag renames on the pool/login/password/log-file flags this client owns), an
//! extra switch nobody has reviewed for that engine, a new upstream host, or a new
//! engine kind — each of those still needs a client release.
//!
//! ## What this module deliberately does NOT do
//!
//! It does not decide *when to restart mining*. A newly activated pin is staged
//! and installed; the running engine process is left alone and the next lane
//! start picks it up ([`pin_generation`] lets a supervisor notice). Killing a
//! working engine mid-share is a decision for the lane layer, not the pin layer.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(test)]
use std::sync::Mutex;
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::binaries::{self, MinerKind};

/// The engine-pin document schema this build understands. A document declaring a
/// HIGHER schema is refused (we will not guess at fields we do not know).
pub const DOC_SCHEMA: u32 = 1;

/// The `product` string an engine-pin document must carry. Mirrors the
/// cross-product guard on `latest.json`: a wallet/other document, or a client
/// manifest fed to this parser by a misconfigured URL, is rejected.
pub const DOC_PRODUCT: &str = "alice-miner-engines";

/// How often the client re-checks for a new pin document: at startup, then every
/// 6 h — the same cadence as the client update check.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Hard cap on the document body. It is a small JSON file; anything larger is a
/// misconfigured URL or an attack, not our document.
const DOC_CAP: u64 = 256 * 1024;
/// Hard cap on the detached signature (base64 of 64 bytes + whitespace).
const SIG_CAP: u64 = 4 * 1024;

/// Optional relocation of the whole engines root — the downloaded engine cache
/// AND the pin store (tests / ops). It moves only LOCAL CACHES of things that are
/// re-verified on every use (the document's signature, the engine's SHA-256), so
/// pointing it at a hostile directory buys an attacker nothing.
pub const ENGINES_DIR_ENV: &str = "ALICE_MINER_ENGINES_DIR";

/// URL prefixes an engine-pin document may point at — the upstream projects'
/// official release hosts, compiled into the client. The sub-key cannot widen
/// this; adding a prefix is a client release, on purpose. (If an upstream ever
/// yanks an asset we must ship a client — that cost is the price of not letting
/// one online key redirect every miner's engine download anywhere it likes.)
pub const ALLOWED_URL_PREFIXES: &[&str] = &[
    "https://github.com/doktor83/SRBMiner-Multi/releases/download/",
    "https://github.com/xmrig/xmrig/releases/download/",
    "https://github.com/AlphaMine-Tech/alpha-miner/releases/download/",
    "https://github.com/RavenCommunity/kawpowminer/releases/download/",
];

/// Hard ceiling on [`PinEntry::extra_args`]. A fork needs a flag or two; a list
/// this long is a mistake or an attempt to bury something in the middle of it.
pub const MAX_EXTRA_ARGS: usize = 16;
/// Hard ceiling on one extra-argv token.
const MAX_EXTRA_ARG_LEN: usize = 128;
/// Hard ceiling on [`PinEntry::algorithm`].
const MAX_ALGORITHM_LEN: usize = 64;

/// argv flags the CLIENT owns and a signed pin may never restate. These decide
/// **where shares go, who is credited, what authorises the login, and where the
/// engine writes** — i.e. every property the honesty gate and the reward path
/// depend on. Compared case-insensitively and with any `=value` tail stripped, so
/// `-P`, `--pool=…` and `--POOL` are all caught by one entry.
///
/// **This list is NOT the security boundary, and must never be described as one.**
/// It is a deny-list over a third-party flag surface we do not control, and it was
/// proved incomplete against the engine this repo already ships: xmrig 6.26's
/// `--userpass`, `-x` and `-l` are aliases of three entries below and were absent
/// from it. The boundary is [`extra_arg_allowlist`] — a pin's argv must be *named*
/// there to pass. This list survives as a second, independent belt: it can only
/// ever refuse more, it gives a sharper error when a publisher reaches for an
/// obvious client-owned flag, and the `the_deny_list_and_the_allow_list_can_never_overlap`
/// test pins the two apart so a future allow-list entry cannot quietly re-open one
/// of these.
const CLIENT_OWNED_FLAGS: &[&str] = &[
    // algorithm — carried by `algorithm`, never by a raw flag
    "-a", "--algo", "--algorithm", "--coin",
    // pool / transport
    "-o", "-p", "--pool", "--url", "--server", "--port", "--host", "--tls", "--proxy", "-x",
    // login / credit attribution. `--userpass`/`-O` set BOTH halves of the login in
    // one token — the alias that made the deny-list-only design fail. (`-O` also
    // folds onto `-o` under the case-insensitive compare below.)
    "-u", "--user", "--wallet", "--address", "--worker", "--rig-id", "--pass", "--password",
    "--userpass",
    // where the engine writes, and what it exposes
    "--log-file", "--logfile", "-l", "--config", "-c", "--api-bind", "--api-port", "--http-port",
    "--http-host", "--http-enabled", "--api-enabled",
    // device selection is the user's setting, not the publisher's
    "--gpu-id", "--devices", "--cuda-devices", "--opencl-devices",
    // never let a pin quietly raise the vendor's donation cut
    "--donate-level", "--donate-over-proxy",
];

/// One flag a signed pin is allowed to add to a given engine's argv.
///
/// `flag` is the exact spelling, which must be a **long, lower-case `--flag`** —
/// pinned by [`the_argv_allow_list_is_limited_to_forms_this_rule_can_express`] and
/// re-checked at validation time, because the one-token rule below is only well
/// defined for long options (`-t=4` would give getopt a value of `=4`).
///
/// `takes_value` says whether it must be written `--flag=value`. It is the ONLY
/// spelling accepted: a value never gets an argv token of its own
/// ([`check_extra_args`]). That is what makes a wrong `takes_value` harmless rather
/// than a bypass — either way the engine receives exactly one word it either
/// understands or rejects, with no orphaned second token to re-parse as an option.
/// Verified on the bundled xmrig 6.26: a boolean given a value prints
/// ``option `--randomx-no-numa' doesn't allow an argument`` and carries on; an
/// unknown flag prints `unrecognized option` and carries on; in neither case does a
/// following token change meaning, because there is none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtraArgSpec {
    pub flag: &'static str,
    pub takes_value: bool,
}

const fn boolean(flag: &'static str) -> ExtraArgSpec {
    ExtraArgSpec {
        flag,
        takes_value: false,
    }
}
const fn valued(flag: &'static str) -> ExtraArgSpec {
    ExtraArgSpec {
        flag,
        takes_value: true,
    }
}

/// **xmrig** (`cpu-xmr`). Reviewed 2026-08-15 against `--help` of the exact 6.26.0
/// binary this repo ships (`release-assets/aarch64-apple-darwin/xmrig`). Every
/// entry is a CPU/RandomX tuning knob: none names a pool, a login, a file or a
/// device, none detaches the process (`-B/--background`), exits early
/// (`--dry-run`, `--print-platforms`, `--export-topology`), disables mining
/// (`--no-cpu`) or touches the donation cut — those were considered and left off.
///
/// **2026-08-16, measured rather than read.** `--help` is not a reliable statement
/// of a build's flag surface, and neither is `takes_value` a reliable statement of
/// its arity:
///
/// * `--asm` is printed by this binary's own `--help`, and this binary answers
///   ``unrecognized option `--asm'`` — it is an x86-only option and the help text is
///   shared across platforms. It is kept (it is real and useful on the x86 fleet,
///   which is most of it) and is harmless where it is absent *only because* a value
///   now rides inside its flag's token.
/// * `--randomx-wrmsr` takes an OPTIONAL argument, so it consumes nothing in the
///   two-token spelling; `--randomx-wrmsr=-1` is the form that works.
///
/// Both facts were bypasses while a value could occupy an argv token of its own.
/// Neither is a bypass now, and neither is why the flags are listed here — that is
/// still the review. The lesson recorded for the next reviewer: an entry here is a
/// claim about what a flag CAN do, and it is never a claim that the engine will
/// parse it the way we expect.
const XMRIG_EXTRA_ARGS: &[ExtraArgSpec] = &[
    valued("--randomx-mode"),      // auto | fast | light
    valued("--randomx-init"),      // dataset init threads
    boolean("--randomx-1gb-pages"),
    boolean("--randomx-no-numa"),
    valued("--randomx-wrmsr"),     // MSR tweak value, or -1 to disable (optional_argument)
    boolean("--randomx-no-rdmsr"),
    boolean("--randomx-cache-qos"),
    boolean("--huge-pages-jit"),
    boolean("--no-huge-pages"),
    valued("--cpu-max-threads-hint"),
    boolean("--cpu-no-yield"),
    valued("--asm"),               // auto | none | intel | ryzen | bulldozer (x86 builds only)
    valued("--dns-ttl"),
];

/// The flags a signed pin may add, per engine kind.
///
/// **Empty is the correct, deliberate state for an engine nobody has reviewed.** An
/// entry here is a claim that a human read that engine's own flag documentation and
/// confirmed the flag cannot name a pool, a login, a proxy, a file or a device — the
/// four things a stolen sub-key must never be able to choose. We can make that claim
/// for xmrig because its binary (and therefore its `--help`) is in this repo. We
/// cannot make it for SRBMiner-MULTI, alpha-miner or kawpowminer: SRBMiner is
/// closed-source and ships no macOS build, and neither of the others has been read
/// here. Guessing at their surface is exactly the mistake that produced the
/// deny-list. Populating one of these is a client release, on purpose.
fn extra_arg_allowlist(kind: &str) -> &'static [ExtraArgSpec] {
    match kind {
        "cpu-xmr" => XMRIG_EXTRA_ARGS,
        // SRBMiner-MULTI. UNREVIEWED — see the doc comment above.
        "gpu-prl" => &[],
        // kawpowminer. UNREVIEWED.
        "gpu-rvn" => &[],
        // alpha-miner. UNREVIEWED.
        "gpu-alpha" => &[],
        // An unknown kind never reaches here (validate_entry refuses it first), and
        // if it ever did, "no flags at all" is the fail-closed answer.
        _ => &[],
    }
}

/// The engine kinds whose lane argv actually CARRIES an algorithm token, and for
/// which [`PinEntry::algorithm`] therefore has somewhere to go.
///
/// Only the GPU-PRL lane: alpha-miner has no algorithm flag by design, xmrig is
/// driven by `--coin monero`, and kawpowminer takes none. A pin setting `algorithm`
/// on any other kind used to be accepted and shown by `alice-miner engines` as
/// though it were in force while the argv never mentioned it — a signed instruction
/// silently dropped, which is its own hazard (the publisher believes the fleet moved
/// and it did not). Refused instead.
const KINDS_WITH_ALGORITHM_SLOT: &[&str] = &["gpu-prl"];

// ────────────────────────────────────────────────────────────────────────────
// Trust + fetch seams
//
// Production has exactly one signature key (the embedded sub-key) and one way to
// obtain engine bytes (the audited download path). The `cfg(test)` arms below let
// the test suite drive the whole pipeline offline with a throwaway key and a
// scripted download — they are compiled out of every shipped binary, so no
// release build has a way to be handed a different trust root.
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) fn test_trust_key() -> &'static Mutex<Option<String>> {
    static K: OnceLock<Mutex<Option<String>>> = OnceLock::new();
    K.get_or_init(|| Mutex::new(None))
}

#[cfg(test)]
pub(crate) type TestFetch =
    Box<dyn Fn(&PinEntry) -> Result<Vec<u8>, binaries::FetchFail> + Send + Sync>;

#[cfg(test)]
pub(crate) fn test_fetch_hook() -> &'static Mutex<Option<TestFetch>> {
    static H: OnceLock<Mutex<Option<TestFetch>>> = OnceLock::new();
    H.get_or_init(|| Mutex::new(None))
}

/// Can this build verify a pin document at all?
fn trust_status() -> Result<(), String> {
    #[cfg(test)]
    if test_trust_key()
        .lock()
        .map(|k| k.is_some())
        .unwrap_or(false)
    {
        return Ok(());
    }
    alice_release::engine_pin_key_status()
}

/// Verify a detached signature over the document bytes.
fn verify_doc_sig(doc_bytes: &[u8], sig_b64: &str) -> Result<(), String> {
    #[cfg(test)]
    {
        let key = test_trust_key().lock().ok().and_then(|k| k.clone());
        if let Some(k) = key {
            return alice_release::verify_engine_pin_sig_with(doc_bytes, sig_b64, &k);
        }
    }
    alice_release::verify_engine_pin_sig(doc_bytes, sig_b64)
}

/// Download + verify the engine bytes a pin entry names.
fn stage_fetch(e: &PinEntry) -> Result<Vec<u8>, binaries::FetchFail> {
    #[cfg(test)]
    {
        let hooked = {
            let g = test_fetch_hook().lock();
            match g {
                Ok(g) => g.as_ref().map(|f| f(e)),
                Err(_) => None,
            }
        };
        if let Some(r) = hooked {
            return r;
        }
    }
    binaries::fetch_entry_bytes(e)
}

// ────────────────────────────────────────────────────────────────────────────
// The pin entry — one shape shared by the embedded floor and the signed document
// ────────────────────────────────────────────────────────────────────────────

/// One engine pin: which bytes, for which engine/target, and where to get them.
///
/// This is the SAME shape as an entry in `release-assets/miners.json` (the
/// embedded floor) plus provenance fields the signed document carries, so the
/// resolver has exactly one type to reason about. Unknown fields are ignored;
/// absent fields default — an older client reading a newer document simply does
/// not see the new fields (and a field it needs but cannot find makes the entry
/// unusable, never silently wrong).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinEntry {
    /// Engine kind: `cpu-xmr` | `gpu-rvn` | `gpu-prl` | `gpu-alpha`.
    pub kind: String,
    /// Rust target triple this pin is for, e.g. `x86_64-unknown-linux-gnu`.
    pub target: String,
    /// On-disk engine filename, e.g. `SRBMiner-MULTI` / `SRBMiner-MULTI.exe`.
    pub filename: String,
    /// Lower-case hex SHA-256 of the ENGINE BINARY bytes. The trust anchor.
    pub sha256: String,
    /// Upstream engine name (`srbminer-multi`, `xmrig`, …). Informational.
    #[serde(default)]
    pub engine: Option<String>,
    /// Upstream engine version (`3.5.3`). Load-bearing: (kind,target,version) is
    /// the key of the "same version ⇒ same hash" history check.
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default, rename = "_placeholder")]
    pub placeholder: bool,
    /// Direct URL to the engine binary; fetched bytes are checked against
    /// [`PinEntry::sha256`] before anything is installed.
    #[serde(default)]
    pub binary_url: Option<String>,
    /// URL of an archive containing the engine at [`Self::binary_path_in_archive`].
    #[serde(default)]
    pub archive_url: Option<String>,
    #[serde(default)]
    pub archive_sha256: Option<String>,
    #[serde(default)]
    pub binary_path_in_archive: Option<String>,
    /// Where this build came from upstream (release page URL) — shown to users.
    #[serde(default)]
    pub source_url: Option<String>,
    /// When we endorsed these bytes (RFC3339) and who decided. Endorsement is a
    /// human trust decision recorded in `ENGINE-TRUST-LOG.md`; these fields are
    /// its display copy, NOT its authority.
    #[serde(default)]
    pub endorsed_at: Option<String>,
    #[serde(default)]
    pub endorsed_by: Option<String>,
    /// Free-text provenance note (how the hash was independently reproduced).
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,

    // ── How to CALL these bytes (all optional; absent ⇒ compiled-in behaviour) ──
    /// The algorithm token this engine build wants (`pearlhash`). Substituted for
    /// the client's compiled-in token wherever a lane's argv carries one. Exists so
    /// an upstream that RENAMES its algorithm on a fork does not cost a client
    /// release; it can never widen anything, because it is one bounded token in one
    /// argv slot the client itself places.
    ///
    /// Accepted only on a kind in [`KINDS_WITH_ALGORITHM_SLOT`]. On any other kind
    /// there is no slot to substitute into, so the field would be signed, displayed
    /// as in force, and never reach the engine — refused instead.
    #[serde(default)]
    pub algorithm: Option<String>,
    /// Extra argv spliced in BEFORE every flag the client controls, for a reviewed
    /// tuning switch this engine build wants.
    ///
    /// **One canonical token per flag**: `"--flag"` or `"--flag=value"`, exact case,
    /// each flag at most once. A value never gets a list entry of its own — the
    /// two-token spelling `["--randomx-mode", "light"]` is refused, because a
    /// positional value slot is a slot the engine may decline to consume (module
    /// header, 2026-08-16).
    ///
    /// Bounded by [`extra_arg_allowlist`] — the flag must be one a human has checked
    /// against THAT engine's own flag surface — plus the same credit-only /
    /// anti-leak scan a bring-your-own miner's argv gets
    /// ([`crate::backend::forbidden_in_arg`]) and, as a second belt,
    /// [`CLIENT_OWNED_FLAGS`]. Every one of those applies to every token. It is
    /// deliberately NOT a general "add any switch a fork needs" channel any more:
    /// see the module header for the aliases that broke that version of the rule.
    #[serde(default)]
    pub extra_args: Option<Vec<String>>,
    /// Which compiled-in log parser reads this engine's output
    /// ([`crate::stats::ParserKind::id`]). An id this build does not have refuses
    /// the whole document — never a guess, because guessing is precisely what read
    /// `0 H/s · 0A/0R` off a healthy 44.8 TH/s card on 2026-08-14.
    #[serde(default)]
    pub parser: Option<String>,

    // ── Version ratchet ────────────────────────────────────────────────────────
    /// Set when this entry's version is **not provably newer** than one already in
    /// force on a machine — a deliberate rollback, or a version string this client
    /// cannot order ([`compare_versions`]). Without it such an entry is refused.
    /// Deliberate downgrades are legitimate (a bad upstream build happens); silent
    /// ones are the August outage with a signature on it.
    #[serde(default)]
    pub downgrade: bool,
    /// Why the downgrade — REQUIRED when [`Self::downgrade`] is set, and shown
    /// verbatim by `alice-miner engines` and `doctor`.
    #[serde(default)]
    pub downgrade_reason: Option<String>,
}

impl PinEntry {
    /// A usable (non-placeholder, 64-hex, non-zero) binary pin, lower-cased.
    pub fn real_sha256(&self) -> Option<String> {
        let sha = self.sha256.trim().to_ascii_lowercase();
        if self.placeholder || sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        if sha.chars().all(|c| c == '0') {
            return None;
        }
        Some(sha)
    }

    /// `kind/target/version` — the identity used by the anti-swap history.
    fn history_key(&self) -> Option<String> {
        Some(format!(
            "{}/{}/{}",
            self.kind,
            self.target,
            self.trimmed_version()?
        ))
    }

    /// `kind/target` — the identity the VERSION ratchet is keyed on (one engine
    /// slot on one platform; two targets of the same engine move independently).
    fn version_slot(&self) -> String {
        format!("{}/{}", self.kind, self.target)
    }

    /// The declared upstream version, trimmed; `None` when absent or blank.
    fn trimmed_version(&self) -> Option<String> {
        let v = self.version.as_deref()?.trim();
        (!v.is_empty()).then(|| v.to_string())
    }

    /// How to CALL this engine, re-validated from scratch.
    ///
    /// Deliberately NOT a plain getter: the launch path calls this every time it
    /// builds argv, so the invocation rules hold at the moment the argv is built
    /// and not only at the moment the document was accepted — the same
    /// belt-and-braces the URL allow-list gets (checked in [`validate_entry`] AND
    /// again in [`crate::binaries`]). An `Err` fails the lane start closed; it
    /// never degrades to "launch it anyway with the compiled-in call".
    pub fn invocation(&self) -> Result<EngineInvocation, String> {
        let algorithm = match self.algorithm.as_deref() {
            Some(a) => {
                if !KINDS_WITH_ALGORITHM_SLOT.contains(&self.kind.as_str()) {
                    return Err(format!(
                        "engine pin entry for {} sets an algorithm ({a:?}), but this client's {} \
                         argv carries no algorithm token — it would be accepted, displayed as in \
                         force, and never passed to the engine. Refusing rather than silently \
                         dropping a signed instruction (only {} has an algorithm slot).",
                        self.kind,
                        self.kind,
                        KINDS_WITH_ALGORITHM_SLOT.join(", ")
                    ));
                }
                Some(check_algorithm(a)?)
            }
            None => None,
        };
        let extra_args = match self.extra_args.as_deref() {
            Some(list) => check_extra_args(&self.kind, list)?,
            None => Vec::new(),
        };
        let parser = match self.parser.as_deref() {
            Some(p) => Some(check_parser_id(p)?),
            None => None,
        };
        Ok(EngineInvocation {
            algorithm,
            extra_args,
            parser,
        })
    }

    /// Human one-liner for status output: `srbminer-multi 3.5.3`.
    pub fn label(&self) -> String {
        let engine = self.engine.clone().unwrap_or_else(|| self.kind.clone());
        match self.version.as_deref() {
            Some(v) if !v.is_empty() => format!("{engine} {v}"),
            _ => engine,
        }
    }
}

/// How to CALL a pinned engine — the half of the pin that used to be compiled in.
///
/// Every field is an override: `None`/empty means "use what this client was built
/// with", which is why a document that carries none of them produces byte-identical
/// argv and byte-identical parsing to v0.6.7.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EngineInvocation {
    /// Replaces the lane's compiled-in algorithm token, where the lane's argv has
    /// one. Only ever `Some` for a kind in [`KINDS_WITH_ALGORITHM_SLOT`] (today:
    /// GPU-PRL) — a pin that sets it on a kind whose argv has no algorithm token is
    /// refused rather than accepted-and-ignored.
    pub algorithm: Option<String>,
    /// Placed BEFORE every client-controlled flag, in order — see
    /// [`EngineInvocation::apply_extra_args`] for why that position and not the end.
    pub extra_args: Vec<String>,
    /// Which compiled-in parser reads this engine's output.
    pub parser: Option<crate::stats::ParserKind>,
}

impl EngineInvocation {
    /// Is this the "nothing overridden" invocation? Used by status output so the
    /// common case says nothing rather than printing three empty fields.
    pub fn is_default(&self) -> bool {
        self.algorithm.is_none() && self.extra_args.is_empty() && self.parser.is_none()
    }

    /// Splice this invocation's extra argv into a launch plan's args, **before**
    /// every flag the client built.
    ///
    /// ## Why first — and what "xmrig is last-wins" got wrong
    ///
    /// Ordering is NOT the invariant. Precedence is the engine's choice, not ours,
    /// so whichever end we pick is the winning end for some family of parsers and the
    /// losing end for another. The invariant is [`extra_arg_allowlist`]. This choice
    /// is damage limitation for the case where the allow-list is one day wrong, and
    /// it should therefore be made on measurement, not on a slogan.
    ///
    /// The previous slogan was "xmrig 6.26 is last-wins, so first is where a
    /// publisher token loses". That is only a third of the truth. Measured against
    /// the bundled binary, xmrig has **three** precedence rules, not one:
    ///
    /// 1. **Global scalars** (`--randomx-mode`, …) are last-wins.
    /// 2. **Per-pool options** (`-u`, `-p`, `--userpass`, `--rig-id`, `--keepalive`,
    ///    `--coin`, `--tls`, …) attach to the pool created by the most recent
    ///    PRECEDING `-o`, and to that pool only (see `lane::xmr::POOL_SCOPED_FLAGS`,
    ///    which established this independently from the miner's own `/1/config`).
    /// 3. **`-o`/`--url` ACCUMULATE.** They are not a scalar at all: each one appends
    ///    a pool, and list order is failover priority. POOL #1 is the pool actually
    ///    mined.
    ///
    /// Rule 3 is the one that matters, and it inverts the usual reasoning: splicing
    /// first does not make a publisher `-o` *lose*, it makes it **POOL #1**. Measured
    /// on a loopback listener, with the client's own pool second:
    ///
    /// ```text
    ///   publisher -o FIRST → honest pool never contacted; evil pool got the login
    ///   publisher -o LAST  → honest pool got the login; evil pool never contacted
    /// ```
    ///
    /// So neither end dominates, and the honest question is which end limits more
    /// damage. First does, for two measured reasons:
    ///
    /// * The client's xmrig argv **begins with `-o`** (`lane::xmr::push_pool_group`).
    ///   Publisher argv spliced at index 0 therefore sits before ANY pool exists, and
    ///   rule 2 makes the entire per-pool credit class inert there — measured:
    ///   `--userpass=EVIL:zz` placed first left the login as the client's
    ///   `HONESTWALLET`, while the same token appended replaced it with `EVIL`.
    /// * That class is large (`-u`, `-p`, `-O/--userpass`, `--rig-id`, `--tls`, `-x`,
    ///   `--coin`, …); the class first-splicing exposes is `-o`/`--url` alone, and
    ///   naming a pool requires spelling a host, which the deny-list, the allow-list
    ///   and [`check_extra_arg_value`]'s charset each independently forbid.
    ///
    /// Appending would trade many inert flags for one demoted one. First stays.
    pub fn apply_extra_args(&self, args: &mut Vec<String>) {
        if self.extra_args.is_empty() {
            return;
        }
        args.splice(0..0, self.extra_args.iter().cloned());
    }
}

// ────────────────────────────────────────────────────────────────────────────
// The signed document
// ────────────────────────────────────────────────────────────────────────────

/// The signed engine-pin document (`engines.json`). The signature covers the
/// EXACT bytes of the file, so this struct must never be re-serialized and
/// re-verified — keep the original bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnginesDoc {
    pub schema: u32,
    pub product: String,
    /// Monotonic counter. A document whose epoch is below the highest we have
    /// ever accepted is a replay and is refused.
    pub epoch: u64,
    /// Oldest epoch a client may keep using. Raising it retires every older
    /// document (including a cached one), forcing a fall back to the embedded
    /// floor until a fresh document arrives. Must be `<= epoch`.
    #[serde(default)]
    pub min_engine_epoch: u64,
    /// RFC3339 issue time — informational only (clocks are not a trust anchor).
    #[serde(default)]
    pub issued: String,
    #[serde(default)]
    pub notes: Option<String>,
    pub engines: Vec<PinEntry>,
}

/// Where an effective pin came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinSource {
    /// Compiled into this binary from `release-assets/miners.json` (the floor).
    Embedded,
    /// A verified engine-pin document.
    Remote { epoch: u64, issued: String },
}

impl PinSource {
    pub fn short(&self) -> String {
        match self {
            PinSource::Embedded => "built-in (this client version)".to_string(),
            PinSource::Remote { epoch, .. } => format!("signed engine pin list, epoch {epoch}"),
        }
    }
}

/// A pin plus its provenance, as the resolver sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePin {
    pub entry: PinEntry,
    pub source: PinSource,
}

// ────────────────────────────────────────────────────────────────────────────
// Embedded floor
// ────────────────────────────────────────────────────────────────────────────

/// The pin table compiled into this binary — the floor we fall back to whenever
/// a remote document is absent, unverifiable, stale or malformed. Same file the
/// packaging step reads.
pub const EMBEDDED_MANIFEST: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../release-assets/miners.json"
));

#[derive(Debug, Deserialize)]
struct EmbeddedManifest {
    engines: Vec<PinEntry>,
}

/// All pins compiled into this build.
pub fn embedded_entries() -> Vec<PinEntry> {
    serde_json::from_str::<EmbeddedManifest>(EMBEDDED_MANIFEST)
        .map(|m| m.engines)
        .unwrap_or_default()
}

/// The embedded pin for `(kind, target, filename)`, if any.
pub fn embedded_entry(kind: &str, target: &str, filename: &str) -> Option<PinEntry> {
    embedded_entries()
        .into_iter()
        .find(|e| e.kind == kind && e.target == target && e.filename == filename)
}

// ────────────────────────────────────────────────────────────────────────────
// On-disk state
// ────────────────────────────────────────────────────────────────────────────

/// Persisted, non-secret pin state. Lives beside the engine cache, never in the
/// keystore tree.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PinState {
    #[serde(default)]
    pub schema: u32,
    /// Highest epoch ever accepted, raised further by `min_engine_epoch`. A
    /// document (fresh OR cached) below this is refused — the anti-rollback.
    #[serde(default)]
    pub epoch_floor: u64,
    #[serde(default)]
    pub last_check_unix: u64,
    #[serde(default)]
    pub last_ok_unix: u64,
    /// The last refusal/failure, verbatim, for the status command.
    #[serde(default)]
    pub last_error: Option<String>,
    /// `kind/target/version` → sha256 of every engine build ever accepted.
    #[serde(default)]
    pub seen: std::collections::BTreeMap<String, String>,
    /// `kind/target` → the HIGHEST engine version ever in force on this machine.
    /// Only ever raised, never lowered — including by a deliberate downgrade, so
    /// that re-publishing the older build keeps re-stating its marker rather than
    /// quietly becoming the new normal.
    #[serde(default)]
    pub version_floor: std::collections::BTreeMap<String, String>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `<data_local>/AliceMiner/engines` — the engine cache root (all triples).
pub fn engines_root() -> Result<PathBuf, String> {
    if let Some(over) = std::env::var_os(ENGINES_DIR_ENV) {
        let p = PathBuf::from(over);
        if !p.as_os_str().is_empty() {
            return Ok(p);
        }
    }
    let base = dirs::data_local_dir().ok_or_else(|| {
        "no per-user data directory available for the engine pin store".to_string()
    })?;
    Ok(base.join("AliceMiner").join("engines"))
}

/// Directory holding `engines.json`, `engines.json.sig` and `state.json`.
pub fn pins_dir() -> Result<PathBuf, String> {
    Ok(engines_root()?.join("pins"))
}

fn doc_path() -> Result<PathBuf, String> {
    Ok(pins_dir()?.join("engines.json"))
}
fn sig_path() -> Result<PathBuf, String> {
    Ok(pins_dir()?.join("engines.json.sig"))
}
fn state_path() -> Result<PathBuf, String> {
    Ok(pins_dir()?.join("state.json"))
}

/// Read the persisted state (a missing/corrupt file reads as default — the state
/// is a cache, never a secret, and a fresh default is always safe because the
/// embedded floor is the fallback).
pub fn load_state() -> PinState {
    let Ok(p) = state_path() else {
        return PinState::default();
    };
    let Ok(bytes) = std::fs::read(&p) else {
        return PinState::default();
    };
    serde_json::from_slice::<PinState>(&bytes).unwrap_or_default()
}

fn save_state(st: &PinState) -> Result<(), String> {
    let dir = pins_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let bytes = serde_json::to_vec_pretty(st).map_err(|e| format!("serializing pin state: {e}"))?;
    write_atomic(&dir, &dir.join("state.json"), &bytes)
}

/// Write `bytes` to `dest` via a same-directory temp + rename, so a crash never
/// leaves a half-written document that would later fail verification for the
/// wrong reason.
fn write_atomic(dir: &Path, dest: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let name = dest.file_name().and_then(|n| n.to_str()).unwrap_or("pin");
    let tmp = dir.join(format!(
        ".{name}.partial-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)
        .map_err(|e| format!("creating {}: {e}", tmp.display()))?;
    f.write_all(bytes)
        .map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    drop(f);
    std::fs::rename(&tmp, dest).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("installing {}: {e}", dest.display())
    })
}

// ────────────────────────────────────────────────────────────────────────────
// Validation
// ────────────────────────────────────────────────────────────────────────────

/// Reject a document that this build cannot fully understand or that carries an
/// entry we would not be willing to act on. Whole-document, never per-entry:
/// partially applying a signed list is how you end up running half an attack.
pub fn validate_doc(doc: &EnginesDoc) -> Result<(), String> {
    if doc.schema > DOC_SCHEMA {
        return Err(format!(
            "engine pin list declares schema {} but this client understands at most {DOC_SCHEMA}; \
             refusing to guess (update the client to use it)",
            doc.schema
        ));
    }
    if doc.product != DOC_PRODUCT {
        return Err(format!(
            "engine pin list is for product '{}', not '{DOC_PRODUCT}'",
            doc.product
        ));
    }
    if doc.epoch == 0 {
        return Err("engine pin list has epoch 0 (epochs start at 1)".to_string());
    }
    if doc.min_engine_epoch > doc.epoch {
        return Err(format!(
            "engine pin list is self-contradictory: min_engine_epoch {} > epoch {}",
            doc.min_engine_epoch, doc.epoch
        ));
    }
    if doc.engines.is_empty() {
        return Err("engine pin list contains no engines".to_string());
    }
    let mut seen_slots = std::collections::BTreeSet::new();
    for e in &doc.engines {
        validate_entry(e)?;
        let slot = format!("{}/{}/{}", e.kind, e.target, e.filename);
        if !seen_slots.insert(slot.clone()) {
            return Err(format!("engine pin list has two entries for {slot}"));
        }
    }
    Ok(())
}

fn validate_entry(e: &PinEntry) -> Result<(), String> {
    let known_kind = matches!(
        e.kind.as_str(),
        "cpu-xmr" | "gpu-rvn" | "gpu-prl" | "gpu-alpha"
    );
    if !known_kind {
        return Err(format!(
            "engine pin list names an unknown engine kind '{}'",
            e.kind
        ));
    }
    if e.target.is_empty()
        || !e
            .target
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(format!(
            "engine pin entry has an implausible target '{}'",
            e.target
        ));
    }
    // The filename is used to build a path in the engine cache: it must be a bare
    // file name. Never a separator, never a traversal, never empty.
    let f = &e.filename;
    if f.is_empty()
        || f.len() > 64
        || f.contains('/')
        || f.contains('\\')
        || f.contains("..")
        || f.starts_with('.')
        || Path::new(f)
            .file_name()
            .map(|n| n != f.as_str())
            .unwrap_or(true)
    {
        return Err(format!("engine pin entry has an unsafe filename '{f}'"));
    }
    // How to CALL the bytes — validated for EVERY entry, placeholder or not: an
    // entry that carries an unknown parser id or a forbidden argument is refused
    // even when it pins nothing, because the client would otherwise be quietly
    // ignoring a field the publisher believed was in force.
    e.invocation()?;
    // The downgrade marker must be a decision, not a bare flag: the reason is what
    // `alice-miner engines` and `doctor` show the miner, so an empty one is refused.
    if e.downgrade {
        let reason = e.downgrade_reason.as_deref().unwrap_or("").trim();
        if reason.len() < 8 {
            return Err(format!(
                "engine pin entry {}/{} is marked as a deliberate downgrade but gives no reason; \
                 a downgrade is shown to every miner and must say why",
                e.kind, e.target
            ));
        }
    }
    if e.placeholder {
        // A placeholder carries no usable bytes; it is allowed to exist (the
        // kawpowminer slot) but must not pretend to have a pin.
        return Ok(());
    }
    if e.real_sha256().is_none() {
        return Err(format!(
            "engine pin entry {}/{} has no usable SHA-256 ('{}')",
            e.kind, e.target, e.sha256
        ));
    }
    if e.version
        .as_deref()
        .map(|v| v.trim().is_empty())
        .unwrap_or(true)
    {
        return Err(format!(
            "engine pin entry {}/{} has no version — the anti-swap history needs one",
            e.kind, e.target
        ));
    }
    // Exactly one download shape, and every URL inside the allow-list.
    match (&e.binary_url, &e.archive_url) {
        (Some(b), None) => check_url(b)?,
        (None, Some(a)) => {
            check_url(a)?;
            let sha = e
                .archive_sha256
                .as_deref()
                .map(|s| s.trim().to_ascii_lowercase())
                .unwrap_or_default();
            if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!(
                    "engine pin entry {}/{} has an archive URL but no usable archive_sha256",
                    e.kind, e.target
                ));
            }
            let member = e.binary_path_in_archive.as_deref().unwrap_or("");
            if member.is_empty() || member.starts_with('/') || member.contains("..") {
                return Err(format!(
                    "engine pin entry {}/{} has an unsafe binary_path_in_archive '{member}'",
                    e.kind, e.target
                ));
            }
        }
        (Some(_), Some(_)) => {
            return Err(format!(
                "engine pin entry {}/{} declares both binary_url and archive_url; \
                 refusing an ambiguous download",
                e.kind, e.target
            ))
        }
        (None, None) => {
            return Err(format!(
                "engine pin entry {}/{} has a pin but no download URL — this client could \
                 never obtain the bytes it demands",
                e.kind, e.target
            ))
        }
    }
    Ok(())
}

/// The algorithm token, validated. A miner algorithm name is a short ASCII token
/// (`pearlhash`, `rx/0`, `kawpow`, `ethash`); anything else is refused rather than
/// handed to a process as argv. In particular it may not start with `-` (that
/// would be a FLAG smuggled into the algorithm slot) and may carry no whitespace,
/// quotes, shell metacharacters or control bytes.
fn check_algorithm(a: &str) -> Result<String, String> {
    let t = a.trim();
    if t.is_empty() || t.len() > MAX_ALGORITHM_LEN {
        return Err(format!(
            "engine pin entry declares an implausible algorithm token '{a}' \
             (1..={MAX_ALGORITHM_LEN} characters)"
        ));
    }
    if t.starts_with('-') {
        return Err(format!(
            "engine pin entry's algorithm '{a}' starts with '-': that is a FLAG, not an \
             algorithm name — refusing"
        ));
    }
    let ok = t
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.' | '+'));
    if !ok {
        return Err(format!(
            "engine pin entry's algorithm '{a}' contains characters an algorithm name never has \
             (allowed: letters, digits, and / - _ . +)"
        ));
    }
    Ok(t.to_string())
}

/// The extra argv, validated **against the allow-list for that engine kind**.
///
/// The rule, in one sentence: **every** token must be a reviewed flag for this
/// engine ([`extra_arg_allowlist`]), spelled exactly as reviewed, written as one
/// self-contained argv word, and named at most once.
///
/// There is deliberately **no positional value slot**. The previous version walked
/// the list and accepted any token that followed a flag declared
/// [`ExtraArgSpec::takes_value`], checking it only for content and charset — never
/// against the allow-list or [`CLIENT_OWNED_FLAGS`]. That made the validator's model
/// of the engine's own argv parse load-bearing, and the model was wrong twice over
/// on the very binary this repo ships (see the module header, and the `S3` tests).
/// A value now lives *inside* its flag's token, so:
///
/// * being wrong about a flag's **arity** cannot open a door. There is no second
///   token for a mis-declared flag to leave behind; at worst the engine refuses the
///   one token and says so.
/// * being wrong about a flag's **existence** cannot open a door either — an
///   unrecognised `--flag=value` is one word the engine skips whole. Measured
///   against the bundled xmrig: `--asm=-lFILE`, `--randomx-wrmsr=-lFILE`,
///   `--randomx-mode=-lFILE` and `--dns-ttl=-lFILE` all left no file behind, i.e. an
///   inline value cannot escape its token and be re-parsed as an option.
/// * the **case** we accept is the case the engine sees, so a token we believe is a
///   reviewed flag cannot be inert garbage to the engine.
///
/// What is left for the validator to be wrong about is a reviewed flag doing
/// something we did not think it did — which only re-review catches, and which is
/// stated as the residual risk in the module header rather than papered over.
fn check_extra_args(kind: &str, list: &[String]) -> Result<Vec<String>, String> {
    if list.len() > MAX_EXTRA_ARGS {
        return Err(format!(
            "engine pin entry carries {} extra arguments; at most {MAX_EXTRA_ARGS} are accepted",
            list.len()
        ));
    }
    let allowed = extra_arg_allowlist(kind);
    let mut out: Vec<String> = Vec::with_capacity(list.len());
    let mut seen: Vec<&'static str> = Vec::with_capacity(list.len());
    for raw in list {
        let t = raw.trim();
        if t.is_empty() || t.len() > MAX_EXTRA_ARG_LEN {
            return Err(format!(
                "engine pin entry has an implausible extra argument {raw:?} \
                 (1..={MAX_EXTRA_ARG_LEN} characters)"
            ));
        }
        // One token per token: whitespace/control would let one entry become two
        // argv words on any shell-ish re-parse, and is never legitimate here.
        if t.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control()) {
            return Err(format!(
                "engine pin entry's extra argument {raw:?} contains whitespace or control \
                 characters; give each argv token its own list entry"
            ));
        }

        // Split at the FIRST `=`. A second `=` would land in the value, where the
        // value charset refuses it.
        let (flag, inline_value) = match t.split_once('=') {
            Some((f, v)) => (f, Some(v)),
            None => (t, None),
        };

        // Belt: the deny-list still speaks first, for a sharper message, and stays
        // case-INSENSITIVE — it may only ever refuse more than the rule below.
        if let Some(owned) = CLIENT_OWNED_FLAGS
            .iter()
            .find(|f| f.eq_ignore_ascii_case(flag))
        {
            return Err(format!(
                "engine pin entry's extra argument {raw:?} restates `{owned}`, which this client \
                 controls (pool, login, password, log file, devices). A pin may add switches to an \
                 engine; it may not redirect where shares go or who is credited — refusing the \
                 whole list"
            ));
        }
        check_extra_arg_token_content(raw, t)?;

        // EXACT-CASE lookup: the token we accept must be the token the engine
        // recognises. xmrig does not case-fold and does not abort on an option it
        // does not know — it warns and carries on — so a case-folded match would let
        // us believe a token is a reviewed flag while the engine treats it as noise.
        let Some(spec) = allowed.iter().find(|s| s.flag == flag) else {
            if let Some(near) = allowed.iter().find(|s| s.flag.eq_ignore_ascii_case(flag)) {
                return Err(format!(
                    "engine pin entry's extra argument {raw:?} differs only in CASE from the \
                     reviewed flag `{}`. Engines do not case-fold their argv: this token would be \
                     an unrecognised option to the engine — silently ignored, or worse, ignored \
                     while the rest of the line is re-parsed around it. Write it exactly as \
                     reviewed (`{}`) — refusing the whole list",
                    near.flag, near.flag
                ));
            }
            let known = if allowed.is_empty() {
                "no extra argument at all has been reviewed for this engine yet".to_string()
            } else {
                format!(
                    "reviewed for this engine: {}",
                    allowed
                        .iter()
                        .map(|s| s.flag)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            return Err(format!(
                "engine pin entry's extra argument {raw:?} is not on the reviewed argv allow-list \
                 for engine kind '{kind}' ({known}). Every token must be a reviewed flag — there is \
                 no 'value' position a bare token may sit in. A signed pin may only pass switches a \
                 human has checked against THIS engine's own flag surface — a deny-list cannot be \
                 trusted to have enumerated every alias of a third-party binary (xmrig spells \
                 --user as --userpass, --proxy as -x and --log-file as -l). Adding one is a client \
                 release, on purpose — refusing the whole list"
            ));
        };

        // Fail-closed on a malformed TABLE, not only in the test that pins its shape.
        // The canonical `--flag=value` rule is sound only for long options: `-t=4`
        // would hand getopt a value of `=4`, which is a different parse model again.
        if !spec.flag.starts_with("--") || spec.flag.len() < 4 {
            return Err(format!(
                "engine pin argv allow-list entry `{}` for kind '{kind}' is not a long `--flag`; \
                 the one-token `--flag=value` rule this client enforces is only well defined for \
                 long options — refusing rather than guessing how the engine clusters it",
                spec.flag
            ));
        }

        // One flag, once. Which of two occurrences an engine honours is the engine's
        // business; a repeated flag has no legitimate use in a tuning list, and
        // repeating one is the shape the value-slot exploit needed.
        if seen.contains(&spec.flag) {
            return Err(format!(
                "engine pin entry names `{}` twice. Which occurrence an engine honours is its own \
                 choice, not something this client can check — refusing the whole list",
                spec.flag
            ));
        }
        seen.push(spec.flag);

        match (spec.takes_value, inline_value) {
            (true, Some(v)) => check_extra_arg_value(spec.flag, v)?,
            (true, None) => {
                return Err(format!(
                    "engine pin entry's extra argument {raw:?} needs a value, and a value must ride \
                     INSIDE its flag's token: write it as one token, `{}=value`. The two-token \
                     spelling is refused because whether the engine consumes the next token is the \
                     engine's decision — on the bundled xmrig, `--randomx-wrmsr` and `--asm` consume \
                     nothing, and the token behind them is parsed as a real option",
                    spec.flag
                ))
            }
            (false, Some(_)) => {
                return Err(format!(
                    "engine pin entry's extra argument {raw:?} gives a value to `{}`, which takes \
                     none — refusing rather than guessing what the engine would do with it",
                    spec.flag
                ))
            }
            (false, None) => {}
        }
        out.push(t.to_string());
    }
    Ok(out)
}

/// The content scans EVERY extra-argv token faces: no URL, no filesystem path, and
/// the same credit-only / anti-leak scan a bring-your-own miner's argv gets.
/// Independent of the allow-list, and kept because a token can be shaped wrong in
/// ways the allow-list would never see (an `=` tail it does not look at).
///
/// The whole token is scanned, `--flag=value` included, so the value half gets this
/// as well as the narrower [`check_extra_arg_value`].
fn check_extra_arg_token_content(raw: &str, t: &str) -> Result<(), String> {
    if t.contains("://") {
        return Err(format!(
            "engine pin entry's extra argument {raw:?} carries a URL; the relay endpoints are \
             the client's to choose — refusing"
        ));
    }
    if t.starts_with('/') || t.starts_with('~') || t.contains('\\') || t.contains("..") {
        return Err(format!(
            "engine pin entry's extra argument {raw:?} looks like a filesystem path; a pin may \
             not choose where the engine reads or writes — refusing"
        ));
    }
    if let Some(bad) = crate::backend::forbidden_in_arg(t) {
        return Err(format!(
            "engine pin entry's extra argument {raw:?} is refused by the argv honesty gate \
             ({bad:?}) — refusing the whole list"
        ));
    }
    Ok(())
}

/// Characters an allow-listed flag's VALUE may contain.
///
/// Deliberately narrower than the whole-token scan: a value is the half an attacker
/// would need to name a destination, so it may not contain `:` (host:port,
/// `user:pass`), `/` or `\` (paths, URLs), `@`, or anything else outside this set.
/// Every value the reviewed flags actually take — `light`, `75`, `-1`, `intel`,
/// `auto` — is inside it. A future flag needing a richer value shape is a client
/// release, which is the same price as the flag itself.
///
/// A leading `-` stays legal (`--randomx-wrmsr=-1` needs it) and is safe, because
/// since 2026-08-16 a value only ever exists INSIDE its flag's argv word — measured
/// against the bundled xmrig, `--randomx-wrmsr=-lFILE`, `--asm=-lFILE`,
/// `--randomx-mode=-lFILE` and `--dns-ttl=-lFILE` created no file, i.e. an inline
/// value is never re-parsed as an option.
fn is_extra_arg_value_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ',' | '+')
}

/// One allow-listed flag's value, validated.
fn check_extra_arg_value(flag: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_EXTRA_ARG_LEN {
        return Err(format!(
            "engine pin entry gives `{flag}` an implausible value {value:?} \
             (1..={MAX_EXTRA_ARG_LEN} characters)"
        ));
    }
    if !value.chars().all(is_extra_arg_value_char) {
        return Err(format!(
            "engine pin entry gives `{flag}` the value {value:?}, which contains characters a \
             tuning value never has (allowed: letters, digits, and . - _ , +). A value is where a \
             host:port, a user:pass pair or a path would have to live — refusing"
        ));
    }
    if let Some(bad) = crate::backend::forbidden_in_arg(value) {
        return Err(format!(
            "engine pin entry's value {value:?} for `{flag}` is refused by the argv honesty gate \
             ({bad:?}) — refusing the whole list"
        ));
    }
    Ok(())
}

/// The parser id, resolved against the parsers compiled into THIS build. An id we
/// do not have is refused — never approximated. Reading a fork's output with the
/// nearest parser is what displayed `0 H/s · 0A/0R · STALL` on a healthy card.
fn check_parser_id(p: &str) -> Result<crate::stats::ParserKind, String> {
    crate::stats::ParserKind::from_id(p).ok_or_else(|| {
        format!(
            "engine pin list names log parser '{p}', which this client does not have (it knows: \
             {}). Refusing to guess which parser to use — update the client to a build that has \
             it; until then the pins compiled into this one stay in force.",
            crate::stats::ParserKind::KNOWN_IDS.join(", ")
        )
    })
}

/// How two upstream version strings order — **conservatively**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionOrder {
    Older,
    Same,
    Newer,
    /// The two cannot be ordered by any rule this client is willing to apply.
    /// Callers must treat this exactly like `Older`: refuse, and require an
    /// explicit human marker.
    Unordered,
}

/// Split a version into numeric components, or `None` if it is not a plain
/// dotted-numeric version. A single optional leading `v` is tolerated (`v6.26.0`),
/// because upstream tags carry one and it is not ambiguous.
///
/// Everything else is refused rather than interpreted: `3.5.4-rc1`, `3.5.4b`,
/// `2026.08.14-nightly`, `3.5.4+build7`. `alice_release::parse_version` — which
/// orders OUR OWN releases — happily truncates `1.4.0-rc1` to `(1,4,0)`, and that
/// is right for versions we mint and wrong for a third party's, where the suffix
/// may be the whole difference between two builds.
fn numeric_version_parts(v: &str) -> Option<Vec<u64>> {
    let t = v.trim();
    let t = t.strip_prefix('v').or_else(|| t.strip_prefix('V')).unwrap_or(t);
    if t.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    for seg in t.split('.') {
        // >9 digits cannot be a component of a real version and would risk an
        // overflow surprise; refuse instead of saturating.
        if seg.is_empty() || seg.len() > 9 || !seg.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        parts.push(seg.parse::<u64>().ok()?);
    }
    (!parts.is_empty() && parts.len() <= 8).then_some(parts)
}

/// Order two upstream version strings, refusing to guess.
///
/// * identical strings ⇒ [`VersionOrder::Same`] (whatever the shape);
/// * both plain dotted-numeric ⇒ compared component-wise, missing trailing
///   components read as `0` (`3.5` == `3.5.0`);
/// * anything else ⇒ [`VersionOrder::Unordered`], which callers treat as "not
///   provably newer" and refuse without an explicit marker.
///
/// Upstream version strings are not ours and are not always cleanly ordered, so
/// the only two answers this function is willing to give with confidence are the
/// ones it can prove.
pub fn compare_versions(a: &str, b: &str) -> VersionOrder {
    let (a, b) = (a.trim(), b.trim());
    if a == b {
        return VersionOrder::Same;
    }
    let (Some(pa), Some(pb)) = (numeric_version_parts(a), numeric_version_parts(b)) else {
        return VersionOrder::Unordered;
    };
    for i in 0..pa.len().max(pb.len()) {
        let (x, y) = (
            pa.get(i).copied().unwrap_or(0),
            pb.get(i).copied().unwrap_or(0),
        );
        if x != y {
            return if x > y {
                VersionOrder::Newer
            } else {
                VersionOrder::Older
            };
        }
    }
    // Numerically equal, textually different (`3.5.4` vs `v3.5.4` vs `3.5.4.0`).
    VersionOrder::Same
}

/// A URL is acceptable only if it starts with one of the compiled-in upstream
/// prefixes. Substring games ("https://evil/https://github.com/...") cannot pass
/// a prefix test, and no redirect can widen it because the CHECK is on the URL we
/// choose to request.
pub fn url_is_allowed(url: &str) -> bool {
    ALLOWED_URL_PREFIXES.iter().any(|p| url.starts_with(p))
}

fn check_url(url: &str) -> Result<(), String> {
    if url_is_allowed(url) {
        return Ok(());
    }
    Err(format!(
        "engine pin list points at {url}, which is not one of the upstream release hosts this \
         client accepts; refusing the whole list"
    ))
}

// ────────────────────────────────────────────────────────────────────────────
// The active document (memoised, re-verified on load)
// ────────────────────────────────────────────────────────────────────────────

struct Active {
    doc: EnginesDoc,
}

fn active_cell() -> &'static RwLock<Option<Option<Active>>> {
    static CELL: OnceLock<RwLock<Option<Option<Active>>>> = OnceLock::new();
    // Outer Option = "loaded yet?"; inner Option = "is there an active doc?".
    CELL.get_or_init(|| RwLock::new(None))
}

/// Bumped whenever a new document becomes effective, so a supervisor can notice
/// that the pin under a running engine changed.
static PIN_GENERATION: AtomicU64 = AtomicU64::new(0);

/// A counter that increases every time a new engine-pin document is activated.
pub fn pin_generation() -> u64 {
    PIN_GENERATION.load(Ordering::Relaxed)
}

/// Forget the memoised document (tests, and after an activation).
pub fn invalidate_cache() {
    if let Ok(mut g) = active_cell().write() {
        *g = None;
    }
}

/// Load + re-verify the cached document from disk. Returns `None` (and leaves a
/// reason in the state file) whenever anything is off — the caller then uses the
/// embedded floor.
fn load_active_from_disk() -> Option<Active> {
    // No sub-key in this build ⇒ remote pins are structurally impossible.
    if trust_status().is_err() {
        return None;
    }
    let doc_bytes = std::fs::read(doc_path().ok()?).ok()?;
    let sig = std::fs::read_to_string(sig_path().ok()?).ok()?;
    // Re-verify on EVERY load: the cache lives in a per-user directory, and a
    // signature check is microseconds. A locally tampered file is simply not a
    // document.
    if let Err(e) = verify_doc_sig(&doc_bytes, &sig) {
        record_error(format!(
            "cached engine pin list failed signature check ({e}); using built-in pins"
        ));
        return None;
    }
    let doc: EnginesDoc = match serde_json::from_slice(&doc_bytes) {
        Ok(d) => d,
        Err(e) => {
            record_error(format!(
                "cached engine pin list is unparseable ({e}); using built-in pins"
            ));
            return None;
        }
    };
    if let Err(e) = validate_doc(&doc) {
        record_error(format!("cached engine pin list rejected: {e}"));
        return None;
    }
    let floor = load_state().epoch_floor;
    if doc.epoch < floor {
        record_error(format!(
            "cached engine pin list epoch {} is below the floor {floor} (retired or rolled back); \
             using built-in pins",
            doc.epoch
        ));
        return None;
    }
    Some(Active { doc })
}

fn with_active<T>(f: impl FnOnce(Option<&EnginesDoc>) -> T) -> T {
    {
        let g = active_cell().read().ok();
        if let Some(g) = g {
            if let Some(loaded) = g.as_ref() {
                return f(loaded.as_ref().map(|a| &a.doc));
            }
        }
    }
    let loaded = load_active_from_disk();
    let mut g = match active_cell().write() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    *g = Some(loaded);
    f(g.as_ref().and_then(|o| o.as_ref()).map(|a| &a.doc))
}

/// The active (verified, non-stale) engine-pin document, if any.
pub fn active_doc() -> Option<EnginesDoc> {
    with_active(|d| d.cloned())
}

// ────────────────────────────────────────────────────────────────────────────
// Resolution — what the engine resolver actually calls
// ────────────────────────────────────────────────────────────────────────────

/// The pin in force for `(kind, target, filename)`: the verified remote document
/// wins; otherwise the embedded floor. `None` = this build knows no pin for that
/// slot, which the resolver treats as "cannot verify ⇒ cannot run".
pub fn effective_pin(kind: &str, target: &str, filename: &str) -> Option<EffectivePin> {
    let remote = with_active(|doc| {
        let doc = doc?;
        let entry = doc
            .engines
            .iter()
            .find(|e| e.kind == kind && e.target == target && e.filename == filename)?
            .clone();
        // A placeholder in the remote list is not a pin; fall through to the floor.
        entry.real_sha256()?;
        Some(EffectivePin {
            entry,
            source: PinSource::Remote {
                epoch: doc.epoch,
                issued: doc.issued.clone(),
            },
        })
    });
    remote.or_else(|| {
        embedded_entry(kind, target, filename).map(|entry| EffectivePin {
            entry,
            source: PinSource::Embedded,
        })
    })
}

/// [`effective_pin`] for a [`MinerKind`] on the current build's target triple.
pub fn effective_pin_for(kind: MinerKind) -> Option<EffectivePin> {
    effective_pin(
        kind.manifest_kind(),
        binaries::current_target_triple(),
        kind.binary_name(),
    )
}

/// How to CALL the engine in force for `kind` — the argv/parser overrides the pin
/// carries, re-validated here.
///
/// No pin at all ⇒ the default (empty) invocation: an engine we have no pin for is
/// refused by the resolver long before argv is built, so there is nothing to
/// override. A pin whose invocation does NOT validate ⇒ `Err`, which fails the
/// lane start closed rather than launching with a call we could not check.
pub fn effective_invocation(kind: MinerKind) -> Result<EngineInvocation, String> {
    match effective_pin_for(kind) {
        Some(p) => p.entry.invocation().map_err(|e| {
            format!(
                "the engine pin in force for {} ({}) is unusable: {e}",
                p.entry.label(),
                p.source.short()
            )
        }),
        None => Ok(EngineInvocation::default()),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Refresh
// ────────────────────────────────────────────────────────────────────────────

/// What a refresh attempt did. Every variant is reportable to a user as-is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// This build embeds no engine-pin key: remote pins are off by construction.
    Disabled(String),
    /// Fetched, verified, staged and activated a newer document.
    Updated { epoch: u64, changed: Vec<String> },
    /// The published document is the one we already have.
    Unchanged { epoch: u64 },
    /// We could not reach the pin list (or an engine download failed). The
    /// previously effective pins remain in force — mining is not interrupted.
    Deferred(String),
    /// The document was refused. The previously effective pins remain in force.
    Rejected(String),
}

impl RefreshOutcome {
    pub fn is_problem(&self) -> bool {
        matches!(
            self,
            RefreshOutcome::Deferred(_) | RefreshOutcome::Rejected(_)
        )
    }
}

/// Raise `floors[kind/target]` to `e`'s version when that is provably newer (or
/// when the slot has no floor yet). Never lowers, and never records a version it
/// cannot order — an unorderable string leaves the existing floor alone, so the
/// ratchet keeps comparing against the last version it actually understood.
fn raise_version_floor(
    floors: &mut std::collections::BTreeMap<String, String>,
    e: &PinEntry,
) {
    let Some(v) = e.trimmed_version() else {
        return;
    };
    match floors.get(&e.version_slot()) {
        None => {
            floors.insert(e.version_slot(), v);
        }
        Some(cur) => {
            if compare_versions(&v, cur) == VersionOrder::Newer {
                floors.insert(e.version_slot(), v);
            }
        }
    }
}

fn record_error(msg: String) {
    let mut st = load_state();
    st.schema = 1;
    st.last_error = Some(msg);
    let _ = save_state(&st);
}

/// Fetch, verify, stage and (only then) activate the published engine-pin list.
///
/// Never runs, installs or trusts anything it has not hashed. Any failure leaves
/// the currently effective pins exactly as they were.
pub fn refresh_now() -> RefreshOutcome {
    if let Err(reason) = trust_status() {
        return RefreshOutcome::Disabled(reason);
    }
    let url = alice_release::engines_url();
    let sig_url = format!("{url}.sig");

    let mut st = load_state();
    st.schema = 1;
    st.last_check_unix = now_unix();

    let doc_bytes = match alice_release::https_get_capped(&url, DOC_CAP) {
        Ok(b) => b,
        Err(e) => {
            let msg = format!("could not fetch the engine pin list from {url}: {e}");
            st.last_error = Some(msg.clone());
            let _ = save_state(&st);
            return RefreshOutcome::Deferred(msg);
        }
    };
    let sig = match alice_release::https_get_capped(&sig_url, SIG_CAP) {
        Ok(b) => String::from_utf8(b).unwrap_or_default(),
        Err(e) => {
            let msg = format!("could not fetch the engine pin signature from {sig_url}: {e}");
            st.last_error = Some(msg.clone());
            let _ = save_state(&st);
            return RefreshOutcome::Deferred(msg);
        }
    };

    match apply_document(&doc_bytes, &sig, &mut st) {
        Ok(outcome) => {
            if !outcome.is_problem() {
                st.last_ok_unix = now_unix();
                st.last_error = None;
            }
            let _ = save_state(&st);
            outcome
        }
        Err(msg) => {
            st.last_error = Some(msg.clone());
            let _ = save_state(&st);
            RefreshOutcome::Rejected(msg)
        }
    }
}

/// The verify → validate → anti-replay → anti-swap → stage → activate pipeline,
/// factored out of the network so it is testable end-to-end with bytes in hand.
/// `Err` = rejected; `Ok(Deferred)` = a download we could not complete.
pub fn apply_document(
    doc_bytes: &[u8],
    sig_b64: &str,
    st: &mut PinState,
) -> Result<RefreshOutcome, String> {
    // 1. Signature FIRST — nothing below this line parses untrusted structure.
    verify_doc_sig(doc_bytes, sig_b64).map_err(|e| {
        format!("engine pin list signature check FAILED ({e}); ignoring it entirely")
    })?;
    apply_verified_document(doc_bytes, sig_b64, st)
}

/// As [`apply_document`], for a document whose signature has ALREADY been checked
/// by the caller against a specific key (the test path). Production code must go
/// through [`apply_document`].
fn apply_verified_document(
    doc_bytes: &[u8],
    sig_b64: &str,
    st: &mut PinState,
) -> Result<RefreshOutcome, String> {
    let doc: EnginesDoc = serde_json::from_slice(doc_bytes)
        .map_err(|e| format!("engine pin list is unparseable: {e}"))?;
    validate_doc(&doc)?;

    // 2. Anti-rollback. `epoch_floor` is the highest epoch ever accepted (raised
    //    further by any document's `min_engine_epoch`).
    if doc.epoch < st.epoch_floor {
        return Err(format!(
            "engine pin list epoch {} is below the floor {} already recorded on this machine — \
             refusing a rolled-back list",
            doc.epoch, st.epoch_floor
        ));
    }
    let current_epoch = active_doc().map(|d| d.epoch);
    if let Some(cur) = current_epoch {
        if doc.epoch == cur {
            let same = doc_path()
                .ok()
                .and_then(|p| std::fs::read(p).ok())
                .map(|b| b == doc_bytes)
                .unwrap_or(false);
            if same {
                return Ok(RefreshOutcome::Unchanged { epoch: doc.epoch });
            }
            return Err(format!(
                "engine pin list reuses epoch {} with different content — refusing (an epoch is \
                 published once)",
                doc.epoch
            ));
        }
    }

    // 3. Anti-swap: a version we already trust may never change bytes. The
    //    history is seeded with the pins compiled into this build, so the remote
    //    list cannot redefine "SRBMiner 3.4.1" either.
    let mut history = st.seen.clone();
    for e in embedded_entries() {
        if let (Some(k), Some(sha)) = (e.history_key(), e.real_sha256()) {
            history.entry(k).or_insert(sha);
        }
    }
    for e in &doc.engines {
        let (Some(key), Some(sha)) = (e.history_key(), e.real_sha256()) else {
            continue;
        };
        if let Some(known) = history.get(&key) {
            if !known.eq_ignore_ascii_case(&sha) {
                return Err(format!(
                    "engine pin list changes the bytes of {key}: it claims {sha} but this machine \
                     has already trusted {known} for that exact version — refusing the whole list"
                ));
            }
        }
    }

    // 3b. Version ratchet, per (kind,target): engines go FORWARD. Without this the
    //     sub-key could sign a list pointing back at SRBMiner 3.4.1 — bytes that are
    //     really on an allow-listed upstream page, that hash exactly to what this
    //     machine already trusts for that version, and that cannot mine post-fork
    //     Pearl at all. Every other guard in this file would wave that through: it
    //     is a one-key replay of the 78-hour August outage.
    //
    //     The floor is seeded from the pins compiled into this build for the same
    //     reason the anti-swap history is: a fresh install must not be downgradeable
    //     just because it has no state file yet.
    let mut floors = st.version_floor.clone();
    for e in embedded_entries() {
        raise_version_floor(&mut floors, &e);
    }
    for e in &doc.engines {
        let Some(v) = e.trimmed_version() else {
            continue;
        };
        let Some(floor) = floors.get(&e.version_slot()) else {
            continue; // nothing to ratchet against yet
        };
        let order = compare_versions(&v, floor);
        if matches!(order, VersionOrder::Newer | VersionOrder::Same) {
            continue;
        }
        if e.downgrade {
            continue; // explicitly marked; surfaced loudly by `engines` and `doctor`
        }
        let why = match order {
            VersionOrder::Older => format!(
                "{v} is OLDER than the {floor} this machine already runs"
            ),
            _ => format!(
                "{v} cannot be ordered against the {floor} this machine already runs, so it is \
                 not provably newer"
            ),
        };
        return Err(format!(
            "engine pin list moves {} backwards: {why}. A deliberate downgrade is allowed, but it \
             must say so — set \"downgrade\": true with a \"downgrade_reason\" on that entry, so \
             every miner is told. Refusing the whole list.",
            e.version_slot()
        ));
    }

    // 4. Verified-before-effective: fetch + hash every engine this machine would
    //    actually run under the new list, BEFORE the list becomes effective.
    let mut staged: Vec<(PinEntry, Vec<u8>)> = Vec::new();
    let triple = binaries::current_target_triple();
    for e in &doc.engines {
        if e.target != triple {
            continue;
        }
        let Some(new_sha) = e.real_sha256() else {
            continue;
        };
        let current =
            effective_pin(&e.kind, &e.target, &e.filename).and_then(|p| p.entry.real_sha256());
        if current.as_deref() == Some(new_sha.as_str()) {
            continue; // same bytes as today — nothing to stage
        }
        match stage_fetch(e) {
            Ok(bytes) => staged.push((e.clone(), bytes)),
            Err(binaries::FetchFail::Integrity(msg)) => {
                return Err(format!(
                    "engine pin list REJECTED: the bytes it points at do not hash to the pin it \
                     declares for {} — {msg}. Nothing was installed; the previous engine pin \
                     stays in force.",
                    e.label()
                ))
            }
            Err(binaries::FetchFail::Network(msg)) => {
                return Ok(RefreshOutcome::Deferred(format!(
                    "engine pin list epoch {} is signed and valid, but {} could not be downloaded \
                     ({msg}); keeping the current engine and retrying later",
                    doc.epoch,
                    e.label()
                )))
            }
            Err(binaries::FetchFail::NotFetchable(msg)) => {
                return Err(format!(
                    "engine pin list declares {} in a way this client cannot fetch: {msg}",
                    e.label()
                ))
            }
        }
    }

    // 5. Activate. Engine bytes first (a crash then costs one re-download of the
    //    OLD engine, never an unverified run), then the document, then the state.
    let mut changed = Vec::new();
    for (entry, bytes) in &staged {
        binaries::install_verified_engine(&entry.filename, bytes)
            .map_err(|e| format!("installing {}: {e}", entry.label()))?;
        changed.push(entry.label());
    }
    let dir = pins_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    write_atomic(&dir, &dir.join("engines.json"), doc_bytes)?;
    write_atomic(
        &dir,
        &dir.join("engines.json.sig"),
        sig_b64.trim().as_bytes(),
    )?;

    st.schema = 1;
    st.epoch_floor = st.epoch_floor.max(doc.epoch).max(doc.min_engine_epoch);
    // Persist the ratchet with the SAME seeding the check above used, or a machine
    // whose state file predates this field would record the accepted (possibly
    // downgraded) version as its floor and forget the higher one its own build
    // ships. Raise, never lower — a deliberate downgrade does NOT re-base the
    // ratchet, so republishing the older build re-states its marker every time.
    for e in embedded_entries() {
        raise_version_floor(&mut st.version_floor, &e);
    }
    for e in &doc.engines {
        if let (Some(k), Some(sha)) = (e.history_key(), e.real_sha256()) {
            st.seen.insert(k, sha);
        }
        raise_version_floor(&mut st.version_floor, e);
    }
    save_state(st)?;
    invalidate_cache();
    PIN_GENERATION.fetch_add(1, Ordering::Relaxed);
    Ok(RefreshOutcome::Updated {
        epoch: doc.epoch,
        changed,
    })
}

/// Refresh if the last check is older than [`REFRESH_INTERVAL`]. Cheap no-op
/// otherwise (no network, no lock contention).
pub fn refresh_if_due() -> Option<RefreshOutcome> {
    if trust_status().is_err() {
        return None;
    }
    let st = load_state();
    let age = now_unix().saturating_sub(st.last_check_unix);
    if st.last_check_unix != 0 && age < REFRESH_INTERVAL.as_secs() {
        return None;
    }
    Some(refresh_now())
}

/// How many times the refresher has actually been started in this process.
/// Exactly 0 or 1, forever — see [`background_refresh_starts`].
static REFRESH_STARTS: AtomicU64 = AtomicU64::new(0);

/// How many times [`start_background_refresh`] has claimed the once-per-process
/// start slot. Zero before the first call, one after — never two, no matter how
/// many front-ends, lanes or threads call it.
pub fn background_refresh_starts() -> u64 {
    REFRESH_STARTS.load(Ordering::Relaxed)
}

/// Start the background pin refresher: once at process start, then every
/// [`REFRESH_INTERVAL`]. Idempotent — the second call in a process is a no-op.
///
/// **Call this from `main`, not from the mining path (F15).** It used to have
/// exactly one caller, inside `resolve_miner_binary`, which runs only when a lane
/// starts an engine. That inverted the dependency in the one case that matters:
/// the acceptance guard halts a lane → no engine ever starts → the refresher
/// never runs → the fixed engine pin that would UN-halt this machine is published
/// and never seen. The one mechanism that can rescue a halted fleet automatically
/// was gated behind the very thing that was broken. It now starts with the
/// process, so it runs in a client whose lanes are all halted — or which never
/// mined at all.
///
/// Deliberately off the mining path in the other direction too: a slow or
/// unreachable pin host must never delay the start of mining, so the work happens
/// on its own thread and this call returns immediately. The refreshed pin takes
/// effect when a lane next starts an engine (see the module note about restarts).
pub fn start_background_refresh() {
    static STARTED: OnceLock<()> = OnceLock::new();
    if STARTED.set(()).is_err() {
        return;
    }
    REFRESH_STARTS.fetch_add(1, Ordering::Relaxed);
    // The test suite drives refreshes explicitly and must never spawn a thread
    // that talks to the network (or writes to the real user's pin store) behind
    // a test's back. The slot above is still claimed so the once-only contract
    // itself stays observable under test.
    if cfg!(test) {
        return;
    }
    let _ = std::thread::Builder::new()
        .name("alice-engine-pins".into())
        .spawn(|| loop {
            // `refresh_if_due` and not `refresh_now`: the last-check time is
            // persisted, so a miner in a restart loop (or a user starting and
            // stopping all day) does not hammer the pin host once per process —
            // it still checks within 6 h, which is the guarantee that matters.
            // `alice-miner engines --check` is the manual override.
            if let Some(outcome) = refresh_if_due() {
                log_outcome(&outcome);
            }
            std::thread::sleep(REFRESH_INTERVAL);
        });
}

fn log_outcome(outcome: &RefreshOutcome) {
    match outcome {
        RefreshOutcome::Updated { epoch, changed } if !changed.is_empty() => eprintln!(
            "[alice-miner] engine pin list updated to epoch {epoch}: {} \
             (takes effect the next time a lane starts its engine)",
            changed.join(", ")
        ),
        RefreshOutcome::Updated { epoch, .. } => {
            eprintln!("[alice-miner] engine pin list updated to epoch {epoch} (no engine change on this platform)")
        }
        RefreshOutcome::Rejected(msg) => eprintln!("[alice-miner] engine pin list REFUSED: {msg}"),
        RefreshOutcome::Deferred(msg) => {
            eprintln!("[alice-miner] engine pin check deferred: {msg}")
        }
        RefreshOutcome::Disabled(_) | RefreshOutcome::Unchanged { .. } => {}
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Status (what `alice-miner engines` prints)
// ────────────────────────────────────────────────────────────────────────────

/// A user-facing description of one lane's engine pin.
#[derive(Debug, Clone, Serialize)]
pub struct PinStatus {
    pub kind: String,
    pub engine: String,
    pub version: Option<String>,
    pub sha256: String,
    pub source: String,
    pub source_url: Option<String>,
    pub endorsed_at: Option<String>,
    pub endorsed_by: Option<String>,
    /// Whether the pinned bytes are present and verified in the engine cache.
    pub installed: bool,
    /// The algorithm token the pin overrides the compiled-in one with, if any.
    pub algorithm: Option<String>,
    /// Extra argv the pin adds to this engine's launch, if any.
    pub extra_args: Vec<String>,
    /// The log parser the pin names, if any (else the lane's compiled-in one).
    pub parser: Option<String>,
    /// Set when the pin ITSELF declares it is a deliberate downgrade; carries the
    /// published reason. Loud on purpose: a signed rollback to an older engine is
    /// exactly the shape of the August outage, and the miner is entitled to see
    /// that one was chosen on their behalf and why.
    pub downgrade_reason: Option<String>,
    /// Set when the version now in force is NOT newer than the highest this
    /// machine has recorded for that engine — the machine-local half of the same
    /// question, which fires even if the document forgot to say so.
    pub version_regression_from: Option<String>,
}

/// The engine pins in force on THIS machine, one per lane that has one.
pub fn status_for_current_platform() -> Vec<PinStatus> {
    let floors = load_state().version_floor;
    let mut out = Vec::new();
    for kind in [
        MinerKind::CpuXmr,
        MinerKind::GpuRvn,
        MinerKind::GpuPrl,
        MinerKind::GpuAlpha,
    ] {
        let Some(pin) = effective_pin_for(kind) else {
            continue;
        };
        let Some(sha) = pin.entry.real_sha256() else {
            continue;
        };
        let installed = binaries::engine_cache_dir()
            .map(|d| d.join(kind.binary_name()))
            .ok()
            .filter(|p| p.is_file())
            .map(|p| {
                std::fs::read(&p)
                    .map(|b| alice_release::sha256_hex(&b).eq_ignore_ascii_case(&sha))
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        // Machine-local regression check: is the version in force behind the
        // highest this machine has ever recorded for that slot? This is the half a
        // document cannot talk its way out of — it fires whether or not the entry
        // remembered to declare itself a downgrade.
        let version_regression_from = pin
            .entry
            .trimmed_version()
            .zip(floors.get(&pin.entry.version_slot()))
            .filter(|(v, floor)| {
                matches!(
                    compare_versions(v, floor),
                    VersionOrder::Older | VersionOrder::Unordered
                )
            })
            .map(|(_, floor)| floor.clone());
        // A malformed invocation is reported as "none" here rather than crashing
        // the status command; the LAUNCH path is where it fails closed.
        let inv = pin.entry.invocation().unwrap_or_default();
        out.push(PinStatus {
            kind: pin.entry.kind.clone(),
            engine: pin
                .entry
                .engine
                .clone()
                .unwrap_or_else(|| pin.entry.kind.clone()),
            version: pin.entry.version.clone(),
            sha256: sha,
            source: pin.source.short(),
            source_url: pin.entry.source_url.clone(),
            endorsed_at: pin.entry.endorsed_at.clone(),
            endorsed_by: pin.entry.endorsed_by.clone(),
            installed,
            algorithm: inv.algorithm.clone(),
            extra_args: inv.extra_args.clone(),
            parser: inv.parser.map(|p| p.id().to_string()),
            downgrade_reason: pin
                .entry
                .downgrade
                .then(|| {
                    pin.entry
                        .downgrade_reason
                        .clone()
                        .unwrap_or_else(|| "(no reason published)".to_string())
                }),
            version_regression_from,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed document + its signature, for the pipeline tests. Uses a
    /// throwaway key; production verification is against the embedded sub-key.
    fn sign(doc: &str) -> (Vec<u8>, String, String) {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let sig = sk.sign(doc.as_bytes());
        (
            doc.as_bytes().to_vec(),
            B64.encode(sig.to_bytes()),
            B64.encode(sk.verifying_key().to_bytes()),
        )
    }

    fn doc_json(epoch: u64, sha: &str, version: &str) -> String {
        format!(
            r#"{{"schema":1,"product":"alice-miner-engines","epoch":{epoch},
              "min_engine_epoch":1,"issued":"2026-08-14T00:00:00Z","engines":[
              {{"kind":"gpu-prl","engine":"srbminer-multi","version":"{version}",
                "target":"x86_64-unknown-linux-gnu","filename":"SRBMiner-MULTI",
                "sha256":"{sha}",
                "archive_url":"https://github.com/doktor83/SRBMiner-Multi/releases/download/3.5.3/SRBMiner-Multi-3-5-3-Linux.tar.gz",
                "archive_sha256":"{sha}",
                "binary_path_in_archive":"SRBMiner-Multi-3-5-3/SRBMiner-MULTI",
                "source_url":"https://github.com/doktor83/SRBMiner-Multi/releases/tag/3.5.3",
                "endorsed_at":"2026-08-14T00:00:00Z","endorsed_by":"V"}}]}}"#
        )
    }

    const SHA_A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const SHA_B: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    /// A one-entry document for the **linux gpu-prl** slot — the slot the embedded
    /// floor pins on every host — with `extra_fields` (raw JSON, each ending in a
    /// comma) spliced into the entry.
    ///
    /// Deliberately not `doc_for_this_platform`: these tests exercise validation and
    /// the version ratchet, both of which must behave identically on macOS, Linux
    /// and Windows, and the ratchet is seeded from the floor — which has no gpu-prl
    /// entry for `aarch64-apple-darwin`. Using a fixed linux target also keeps the
    /// staging step out of the way (a non-matching triple is skipped).
    fn linux_prl_doc(epoch: u64, version: &str, sha: &str, extra_fields: &str) -> String {
        format!(
            r#"{{"schema":1,"product":"alice-miner-engines","epoch":{epoch},
              "min_engine_epoch":1,"issued":"2026-08-15T00:00:00Z","engines":[
              {{"kind":"gpu-prl","engine":"srbminer-multi","version":"{version}",
                "target":"x86_64-unknown-linux-gnu","filename":"SRBMiner-MULTI",
                "sha256":"{sha}",
                {extra_fields}
                "archive_url":"https://github.com/doktor83/SRBMiner-Multi/releases/download/{version}/SRBMiner-Multi-Linux.tar.gz",
                "archive_sha256":"{sha}",
                "binary_path_in_archive":"SRBMiner-Multi/SRBMiner-MULTI",
                "source_url":"https://github.com/doktor83/SRBMiner-Multi/releases/tag/{version}",
                "endorsed_at":"2026-08-15T00:00:00Z","endorsed_by":"V"}}]}}"#
        )
    }

    // ── F6: the pin carries the CALL, not just the bytes ───────────────────────

    /// The happy path: a signed entry names the algorithm token and the parser, and
    /// both come back out validated. This is the whole point — SRBMiner 3.5.4
    /// reshaped its output on 2026-08-14 and a published pin could not have said so.
    ///
    /// `extra_args` is exercised separately (and on `cpu-xmr`) since 2026-08-15: it
    /// is now bounded by a per-engine reviewed allow-list, and nothing has been
    /// reviewed for SRBMiner — see `an_unreviewed_extra_flag_is_refused_…`.
    #[test]
    fn a_pin_can_carry_the_algorithm_and_the_parser_it_needs() {
        let doc: EnginesDoc = serde_json::from_str(&linux_prl_doc(
            2,
            "3.6.0",
            SHA_A,
            r#""algorithm":"pearlhash2","parser":"srbminer","#,
        ))
        .unwrap();
        validate_doc(&doc).expect("a document that says how to call the engine is valid");
        let inv = doc.engines[0].invocation().expect("invocation");
        assert_eq!(inv.algorithm.as_deref(), Some("pearlhash2"));
        assert!(inv.extra_args.is_empty());
        assert_eq!(inv.parser, Some(crate::stats::ParserKind::Srbminer));
        assert!(!inv.is_default());

        // …and the extra-argv half, on the engine that has a reviewed list.
        let xmr: EnginesDoc = serde_json::from_str(&linux_xmr_doc(
            2,
            "6.27.0",
            SHA_A,
            r#""extra_args":["--randomx-mode=light"],"parser":"xmrig","#,
        ))
        .unwrap();
        validate_doc(&xmr).expect("a reviewed tuning flag is publishable");
        let inv = xmr.engines[0].invocation().expect("invocation");
        assert_eq!(inv.extra_args, vec!["--randomx-mode=light".to_string()]);
        assert_eq!(inv.parser, Some(crate::stats::ParserKind::Xmr));
    }

    /// A DOCUMENTED limitation, pinned by a test so it cannot rot into a surprise:
    /// the argv honesty gate refuses any token containing `seed` or `priv`, and it
    /// is applied to publisher-supplied extra argv too. A fork whose new flag is
    /// spelled `--salted-seed` — not far-fetched, given the fork that started all
    /// this is `SaltedSeedForkHeight` — therefore still needs a client release. We
    /// keep the strict rule: a gate that refuses a legitimate flag costs a release,
    /// a gate with a hole costs a leak.
    #[test]
    fn an_extra_argument_naming_seed_or_priv_is_refused_even_though_it_may_be_legitimate() {
        for bad in ["--salted-seed", "--seed-mode", "--privkey-cache"] {
            let doc: EnginesDoc = serde_json::from_str(&linux_prl_doc(
                2,
                "3.6.0",
                SHA_A,
                &format!(r#""extra_args":["{bad}"],"#),
            ))
            .unwrap();
            let err = match validate_doc(&doc) {
                Err(e) => e,
                Ok(()) => panic!("extra arg {bad:?} must be refused"),
            };
            assert!(err.contains("honesty gate"), "got: {err}");
        }
    }

    /// A one-entry document for the **linux cpu-xmr** slot. Used by the extra-argv
    /// tests because `cpu-xmr` is the one kind with a NON-EMPTY reviewed allow-list
    /// — so a refusal there proves the rule and not merely "the list is empty".
    fn linux_xmr_doc(epoch: u64, version: &str, sha: &str, extra_fields: &str) -> String {
        format!(
            r#"{{"schema":1,"product":"alice-miner-engines","epoch":{epoch},
              "min_engine_epoch":1,"issued":"2026-08-15T00:00:00Z","engines":[
              {{"kind":"cpu-xmr","engine":"xmrig","version":"{version}",
                "target":"x86_64-unknown-linux-gnu","filename":"xmrig",
                "sha256":"{sha}",
                {extra_fields}
                "archive_url":"https://github.com/xmrig/xmrig/releases/download/v{version}/xmrig-linux-x64.tar.gz",
                "archive_sha256":"{sha}",
                "binary_path_in_archive":"xmrig-{version}/xmrig",
                "source_url":"https://github.com/xmrig/xmrig/releases/tag/v{version}",
                "endorsed_at":"2026-08-15T00:00:00Z","endorsed_by":"V"}}]}}"#
        )
    }

    /// Refuse a one-entry cpu-xmr document carrying `extra_args`, returning the error.
    fn xmr_extra_args_err(args: &[&str]) -> String {
        let doc: EnginesDoc = serde_json::from_str(&linux_xmr_doc(
            2,
            "6.27.0",
            SHA_A,
            &format!(
                r#""extra_args":{},"#,
                serde_json::to_string(args).unwrap()
            ),
        ))
        .unwrap();
        match validate_doc(&doc) {
            Err(e) => e,
            Ok(()) => panic!("extra args {args:?} must be refused"),
        }
    }

    /// The mirror of [`xmr_extra_args_err`]: accept a one-entry cpu-xmr document and
    /// return the argv the launch path would actually splice.
    fn accepted_xmr_extra_args(args: &[&str]) -> Vec<String> {
        let doc: EnginesDoc = serde_json::from_str(&linux_xmr_doc(
            2,
            "6.27.0",
            SHA_A,
            &format!(r#""extra_args":{},"#, serde_json::to_string(args).unwrap()),
        ))
        .unwrap();
        validate_doc(&doc).unwrap_or_else(|e| panic!("extra args {args:?} must be accepted: {e}"));
        doc.engines[0].invocation().unwrap().extra_args
    }

    // ── S2: the argv allow-list (2026-08-15) ───────────────────────────────────

    /// **THE DEFECT.** The deny-list did not name the pinned engine's own documented
    /// aliases, so each of these passed validation and reached xmrig's argv. All
    /// three were verified against the exact binary in
    /// `release-assets/aarch64-apple-darwin/xmrig` before this test was written:
    ///
    /// * `--userpass=<addr>:x` — an alias of `--user`+`--pass`. Appended after the
    ///   client's `-u VICTIM -p x` it WON (xmrig is last-wins): the stratum login
    ///   this miner sent carried the attacker's address. Every share, credited to
    ///   someone else. The value clears the URL/path/honesty scans because an SS58
    ///   address is base58 — no `0x`, no `prl1p`, no pool name.
    /// * `-x <host:port>` — an alias of `--proxy`. The whole plaintext stratum
    ///   session routed through a host of the publisher's choosing.
    /// * `-l <file>` — an alias of `--log-file`. The file was created.
    ///
    /// Note the attack needed no new engine version at all: re-publishing the current
    /// entry byte-for-byte with the flag added is `VersionOrder::Same`, staging is
    /// skipped because the bytes already match, and within one refresh every miner on
    /// the lane relaunches with it.
    #[test]
    fn a_pinned_engines_own_alias_of_a_client_owned_flag_is_refused() {
        // Exactly the argv the live reproduction used.
        for args in [
            vec!["--userpass=5Gw3sAttackerAddress:zz"],
            vec!["--userpass", "5Gw3sAttackerAddress:zz"],
            vec!["-x", "198.51.100.9:1080"],
            vec!["-x=198.51.100.9:1080"],
            vec!["-l", "stolen.log"],
            vec!["-l=stolen.log"],
            // …and the upper-case spellings, since argv parsers rarely case-fold but
            // our comparison must not be the weak link either way.
            vec!["--USERPASS=5Gw3sAttackerAddress:zz"],
            vec!["-O", "5Gw3sAttackerAddress:zz"],
        ] {
            let err = xmr_extra_args_err(&args);
            assert!(
                err.contains("this client controls") || err.contains("not on the reviewed argv"),
                "args {args:?} got: {err}"
            );
        }
    }

    /// The RULE, not the three fixed aliases: a flag no deny-list entry names, that
    /// carries no URL, no path and nothing the honesty gate dislikes, is STILL
    /// refused — because it was never reviewed for this engine. This is the property
    /// that does not depend on us having enumerated a third-party binary's surface,
    /// and it is what makes the next unknown alias a non-event.
    #[test]
    fn an_unreviewed_extra_flag_is_refused_even_though_no_deny_list_entry_names_it() {
        for args in [
            vec!["--verbose"],           // real xmrig flag, deliberately not reviewed
            vec!["--background"],        // detaches the child from our supervisor
            vec!["--dry-run"],           // exits immediately: mining just stops
            vec!["--no-cpu"],            // disables the only backend this lane has
            vec!["--export-topology"],   // writes a file and exits
            vec!["--self-select"],       // (also deny-listed nowhere) block templates
            vec!["--totally-new-fork-switch"],
        ] {
            let err = xmr_extra_args_err(&args);
            assert!(
                err.contains("not on the reviewed argv allow-list"),
                "args {args:?} got: {err}"
            );
        }
        // Same rule on an engine whose reviewed list is EMPTY on purpose: SRBMiner is
        // closed-source and its binary is not in this repo, so nothing has been
        // checked for it. The formerly-blessed example flag is now a client release.
        let doc: EnginesDoc = serde_json::from_str(&linux_prl_doc(
            2,
            "3.6.0",
            SHA_A,
            r#""extra_args":["--pearl-fork-salt","3"],"#,
        ))
        .unwrap();
        let err = validate_doc(&doc).unwrap_err();
        assert!(
            err.contains("no extra argument at all has been reviewed for this engine yet"),
            "got: {err}"
        );
    }

    /// There is no value SLOT any more, so a bare token has nowhere to be legal, and
    /// a half-written flag is refused for the right reason. The inline value is still
    /// held to a charset that cannot spell a destination — that check did not fail,
    /// it was simply never the one an attacker had to beat.
    #[test]
    fn there_is_no_value_slot_and_an_inline_value_cannot_spell_a_destination() {
        // A bare token behind a flag, and a bare token alone: same refusal.
        for args in [
            vec!["--randomx-1gb-pages", "198.51.100.9:1080"],
            vec!["evil.example.com"],
        ] {
            assert!(
                xmr_extra_args_err(&args).contains("not on the reviewed argv allow-list"),
                "a bare token must be refused wherever it sits: {args:?}"
            );
        }
        // A flag that needs a value, written without one.
        assert!(
            xmr_extra_args_err(&["--randomx-mode"]).contains("--randomx-mode=value"),
            "a half-written flag must be refused, and told the canonical spelling"
        );
        // A boolean handed a value.
        let err = xmr_extra_args_err(&["--randomx-1gb-pages=1"]);
        assert!(err.contains("which takes none"), "got: {err}");
        // And the value charset: no host:port, no user:pass, no path.
        for args in [
            vec!["--randomx-mode=198.51.100.9:1080"],
            vec!["--asm=a:b"],
            vec!["--asm=x@y"],
            vec!["--dns-ttl=a/b"],
        ] {
            let err = xmr_extra_args_err(&args);
            assert!(
                err.contains("a tuning value never has"),
                "args {args:?} got: {err}"
            );
        }
    }

    // ── S3: the validator stops modelling the engine's parse (2026-08-16) ──────
    //
    // Everything above assumed the validator could predict how the engine would
    // parse the argv it approved. Two live re-exploits and one measurement say it
    // cannot, so the rule below removes the prediction rather than improving it.
    // Each of these was verified against `release-assets/aarch64-apple-darwin/xmrig`
    // (XMRig 6.26.0) before it was written; the commands are in the doc comments.

    /// **RE-EXPLOIT 1.** A value slot is a hole, because whether a flag consumes the
    /// next token is the ENGINE's decision and the validator was guessing at it.
    ///
    /// Measured, one `-l<file>` probe per value-taking entry, against the bundled
    /// binary (`xmrig --<flag> -lFILE --dry-run -o 127.0.0.1:1 -u H -p x`, then
    /// checking whether FILE appeared):
    ///
    /// ```text
    ///   --randomx-mode            consumed its value
    ///   --randomx-init            consumed its value
    ///   --randomx-wrmsr           FILE CREATED  ← optional_argument: consumes nothing
    ///   --cpu-max-threads-hint    consumed its value
    ///   --asm                     FILE CREATED  ← not implemented on this ARM build
    ///   --dns-ttl                 consumed its value
    /// ```
    ///
    /// Two of six. `--randomx-wrmsr` takes an OPTIONAL argument, so getopt only
    /// accepts it in the `=` form and a following token is left to be parsed as a
    /// real option; `--asm` is printed by this binary's own `--help` but is x86-only
    /// and is `unrecognized option` here — the vendor's documentation is wrong about
    /// the vendor's own flag surface, which is exactly the thing an allow-list review
    /// cannot catch by reading.
    ///
    /// The live capture, with publisher argv spliced first as the client splices it.
    /// Note the PORT-LESS host: that is what clears the value charset, which forbids
    /// `:` — and xmrig supplies the default port itself, so it costs the attacker
    /// nothing (verified: `POOL #1  127.0.0.1` was created and dialled).
    ///
    /// ```text
    /// $ xmrig --randomx-wrmsr -o127.0.0.1 --randomx-wrmsr -uATTACKER_WALLET_5Gw \
    ///         --no-color -o 127.0.0.1:1 -u HONEST -p x
    ///  * POOL #1   127.0.0.1          ← the publisher's
    ///  * POOL #2   127.0.0.1:1        ← the client's
    /// ```
    ///
    /// Every token is on the reviewed allow-list, lower-case, and free of `:`/`/`/`@`.
    /// POOL #1 is the pool xmrig actually mines — verified on a loopback listener,
    /// which received `login: "ATTACKER_WALLET"` while the honest port was never
    /// contacted at all.
    #[test]
    fn a_token_in_a_value_slot_is_not_trusted_to_stay_a_value() {
        // Byte-for-byte the live reproduction.
        xmr_extra_args_err(&[
            "--randomx-wrmsr",
            "-o127.0.0.1",
            "--randomx-wrmsr",
            "-uATTACKER_WALLET_5Gw",
        ]);
        // …and the same shape behind the flags whose arity we happened to get RIGHT.
        // The rule may not depend on which of those two sets a flag is in, because
        // that set is the engine's to change between versions and between platforms.
        for opener in [
            "--randomx-wrmsr",
            "--asm",
            "--randomx-mode",
            "--randomx-init",
            "--cpu-max-threads-hint",
            "--dns-ttl",
        ] {
            for smuggled in ["-o198.51.100.9", "-uATTACKER", "-lstolen.log", "-x198.51.100.9"] {
                let err = xmr_extra_args_err(&[opener, smuggled]);
                assert!(
                    !err.is_empty(),
                    "{opener} {smuggled} must be refused, got: {err}"
                );
            }
        }
    }

    /// **THE GENERAL PROPERTY** behind re-exploit 1, stated so it cannot regress into
    /// "we patched the two flags that were optional_argument": a token is checked the
    /// same way wherever it appears in the list. Anything refused as the FIRST token
    /// is refused as the SECOND token, behind an innocent flag.
    #[test]
    fn every_extra_argv_token_faces_the_same_checks_wherever_it_sits() {
        for smuggled in [
            "-o198.51.100.9",
            "-uATTACKER",
            "-lstolen.log",
            "-x198.51.100.9",
            "--userpass",
            "--verbose",
            "--background",
            "evil.example.com",
        ] {
            let alone = xmr_extra_args_err(&[smuggled]);
            let behind = xmr_extra_args_err(&["--randomx-mode", smuggled]);
            assert!(
                !alone.is_empty() && !behind.is_empty(),
                "{smuggled:?} refused alone ({alone}) must also be refused behind a flag ({behind})"
            );
        }
    }

    /// **RE-EXPLOIT 2.** The lookup case-folded and the emitted token did not, so a
    /// token could be a reviewed value-taking flag to us and inert garbage to the
    /// engine. xmrig does not case-fold and does NOT abort on an unrecognised option:
    ///
    /// ```text
    /// $ xmrig --RANDOMX-MODE -lprobe.log --dry-run -o 127.0.0.1:1 -u AAA -p x
    /// xmrig: unrecognized option `--RANDOMX-MODE'
    ///  * POOL #1   127.0.0.1:1          ← it carried on
    /// $ ls probe.log → created           ← the "value" was parsed as --log-file
    /// ```
    ///
    /// That generalises the hole from the two `optional_argument` flags to ALL of
    /// them, with no dependence on getting an engine's arity right.
    ///
    /// The same bug has an honest-operator face, and it is not an inference — it is
    /// what the engine's own effective config says. Read back from xmrig's HTTP API
    /// (`GET /1/config`, the same technique that established
    /// `lane::xmr::POOL_SCOPED_FLAGS`), with the client's pool block otherwise
    /// identical:
    ///
    /// ```text
    ///   (no extra argv)            randomx.mode = "auto"   huge-pages-jit = false
    ///   --randomx-mode=light
    ///        --huge-pages-jit      randomx.mode = "light"  huge-pages-jit = TRUE
    ///   --randomx-mode=fast        randomx.mode = "fast"
    ///   --RANDOMX-MODE=light       randomx.mode = "auto"   ← SILENTLY IGNORED
    /// ```
    ///
    /// So the canonical spelling is genuinely honoured (the capability survives this
    /// tightening), and the wrongly-cased one is a signed instruction the whole fleet
    /// accepts and no engine ever obeys. Both faces are one fix: the token we accept
    /// is the token the engine recognises, byte for byte.
    #[test]
    fn a_reviewed_flag_spelled_in_another_case_is_refused_not_waved_through() {
        // The exploit shape.
        assert!(!xmr_extra_args_err(&["--RANDOMX-MODE", "-lprobe.log"]).is_empty());
        // The honest-operator shape: a lone, well-formed, wrongly-cased flag.
        for bad in [
            "--Randomx-Mode=light",
            "--RANDOMX-MODE=light",
            "--randomx-MODE=light",
            "--RANDOMX-1GB-PAGES",
            "--Dns-Ttl=30",
        ] {
            let err = xmr_extra_args_err(&[bad]);
            assert!(
                err.contains("case") || err.contains("spelled"),
                "{bad:?} must be refused for its CASE, clearly; got: {err}"
            );
        }
        // …and the exact spelling still works, so this is a spelling rule and not an
        // off switch.
        assert_eq!(
            accepted_xmr_extra_args(&["--randomx-mode=light"]),
            vec!["--randomx-mode=light".to_string()]
        );
    }

    /// The canonical form, which is what removes the value slot: a value-taking flag
    /// is ONE token, `--flag=value`. The two-token spelling is refused — it is the
    /// spelling that created the slot, and for xmrig's `optional_argument` flags it
    /// is not even the spelling that works (`--randomx-wrmsr 5` leaves `5` on the
    /// line; `--randomx-wrmsr=-1` is the documented form).
    #[test]
    fn a_reviewed_flag_and_its_value_must_be_one_canonical_token() {
        for args in [
            vec!["--randomx-1gb-pages"],
            vec!["--randomx-mode=light"],
            vec!["--randomx-wrmsr=-1"], // a value may still look flag-shaped: it is INSIDE the token
            vec!["--cpu-max-threads-hint=75", "--huge-pages-jit"],
            vec!["--asm=intel", "--randomx-no-numa", "--dns-ttl=30"],
        ] {
            assert_eq!(
                accepted_xmr_extra_args(&args),
                args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                "{args:?} is the canonical form and must be accepted unchanged"
            );
        }
        for args in [
            vec!["--randomx-mode", "light"],
            vec!["--cpu-max-threads-hint", "75"],
            vec!["--randomx-wrmsr", "-1"],
            vec!["--asm", "intel"],
        ] {
            let err = xmr_extra_args_err(&args);
            assert!(
                err.contains("--flag=value") || err.contains("one token"),
                "the two-token spelling {args:?} must be refused; got: {err}"
            );
        }
    }

    /// One flag, once. Which of two occurrences an engine honours is another thing
    /// only the engine knows, and a repeated flag has no legitimate use here — so it
    /// is refused rather than resolved. (It is also the shape re-exploit 1 needed
    /// twice over.)
    #[test]
    fn a_reviewed_flag_may_not_be_repeated() {
        let err = xmr_extra_args_err(&["--randomx-mode=light", "--randomx-mode=fast"]);
        assert!(err.contains("twice") || err.contains("more than once"), "got: {err}");
        let err = xmr_extra_args_err(&["--randomx-no-numa", "--dns-ttl=30", "--randomx-no-numa"]);
        assert!(err.contains("twice") || err.contains("more than once"), "got: {err}");
    }

    /// The two tables must never overlap, and the allow-list must be spelled the way
    /// the lookup spells it. Without this a future "harmless" allow-list entry could
    /// silently re-open a flag the deny-list exists to forbid, and the belt would go
    /// on looking like it was holding.
    #[test]
    fn the_deny_list_and_the_allow_list_can_never_overlap() {
        for kind in ALL_ENGINE_KINDS {
            for spec in extra_arg_allowlist(kind) {
                assert!(
                    !CLIENT_OWNED_FLAGS
                        .iter()
                        .any(|f| f.eq_ignore_ascii_case(spec.flag)),
                    "{kind}: `{}` is on BOTH the allow-list and the client-owned deny-list",
                    spec.flag
                );
            }
        }
        // The aliases that broke the deny-list-only design are named there now, too —
        // belt and braces, not the boundary.
        for alias in ["--userpass", "-x", "-l"] {
            assert!(
                CLIENT_OWNED_FLAGS.iter().any(|f| f.eq_ignore_ascii_case(alias)),
                "{alias} must be deny-listed as well"
            );
        }
    }

    /// Every engine kind the pin schema accepts, so a table sweep cannot quietly miss
    /// one that a future release adds.
    const ALL_ENGINE_KINDS: &[&str] = &["cpu-xmr", "gpu-prl", "gpu-rvn", "gpu-alpha"];

    /// The allow-list may only contain flags whose spelling the one-token rule can
    /// actually express. This is a guard, not a defect reproduction: today's table
    /// already satisfies it. It exists because the rule
    /// ([`check_extra_args`]) silently stops being sound the moment someone adds a
    /// SHORT flag — `-t=4` hands getopt a value of `=4`, which is a third parse model
    /// and exactly the kind of guess this whole change removed. The validator refuses
    /// such an entry at run time too; this test makes it a build-time failure.
    #[test]
    fn the_argv_allow_list_is_limited_to_forms_this_rule_can_express() {
        for kind in ALL_ENGINE_KINDS {
            let specs = extra_arg_allowlist(kind);
            for spec in specs {
                assert_eq!(
                    spec.flag,
                    spec.flag.to_ascii_lowercase(),
                    "{kind}: allow-list entries are lower-case: {}",
                    spec.flag
                );
                assert!(
                    spec.flag.starts_with("--") && spec.flag.len() > 3,
                    "{kind}: allow-list entries are LONG flags — the `--flag=value` rule is not \
                     well defined for a short one: {}",
                    spec.flag
                );
                assert!(
                    !spec.flag.contains('=')
                        && !spec.flag.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control()),
                    "{kind}: an allow-list entry is a bare flag, never a flag=value or two words: {}",
                    spec.flag
                );
                assert_eq!(
                    specs.iter().filter(|s| s.flag == spec.flag).count(),
                    1,
                    "{kind}: `{}` is listed twice — the duplicate rule keys on the spec's flag",
                    spec.flag
                );
            }
        }
        // And the run-time belt agrees with the compile-time table: a kind we do not
        // know gets an empty list rather than a guess.
        assert!(extra_arg_allowlist("gpu-something-new").is_empty());
    }

    /// Publisher argv is spliced in BEFORE every flag the client built, not after.
    ///
    /// The reason changed on 2026-08-16 even though the position did not. It used to
    /// be "xmrig is last-wins, so first is where a publisher token loses". Measured,
    /// xmrig has three precedence rules, and the one that decides credit is that
    /// `-o` **accumulates**: spliced first, a publisher `-o` becomes POOL #1 — the
    /// pool actually mined — so first is not simply the losing end.
    ///
    /// First is still right, and this test pins the property that makes it right:
    /// **every publisher token lands before the client's first `-o`**, which is the
    /// position where xmrig's per-pool credit flags (`-u`, `-p`, `--userpass`,
    /// `--rig-id`, `--tls`, …) attach to no pool and do nothing. Measured on a
    /// loopback listener: `--userpass=EVIL:zz` placed first left the stratum login as
    /// the client's own address; appended, it replaced it.
    #[test]
    fn publisher_argv_lands_before_the_clients_first_pool() {
        let doc: EnginesDoc = serde_json::from_str(&linux_xmr_doc(
            2,
            "6.27.0",
            SHA_A,
            r#""extra_args":["--randomx-mode=light","--huge-pages-jit"],"#,
        ))
        .unwrap();
        validate_doc(&doc).expect("a reviewed flag is accepted");
        let inv = doc.engines[0].invocation().unwrap();
        // The shape `lane::xmr::push_pool_group` builds: the pool flag comes first.
        let mut args: Vec<String> = ["-o", "relay:3333", "-u", "VICTIM", "-p", "x"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        inv.apply_extra_args(&mut args);
        assert_eq!(
            args,
            [
                "--randomx-mode=light",
                "--huge-pages-jit",
                "-o",
                "relay:3333",
                "-u",
                "VICTIM",
                "-p",
                "x"
            ],
            "the pin's argv goes FIRST, before any pool exists"
        );
        // THE PROPERTY, not the literal: no publisher token may sit at or after the
        // client's first `-o`, because that is where a per-pool flag would bite.
        let first_pool = args.iter().position(|a| a == "-o").expect("-o present");
        for tok in &inv.extra_args {
            let at = args.iter().position(|a| a == tok).expect("spliced");
            assert!(
                at < first_pool,
                "publisher token {tok:?} must precede the client's first -o"
            );
        }
        // Order among the publisher's own tokens is preserved.
        assert_eq!(&args[0..2], ["--randomx-mode=light", "--huge-pages-jit"]);
    }

    /// **DEFECT 3.** Only the GPU-PRL lane's argv carries an algorithm token. A pin
    /// setting `algorithm` on any other kind used to be accepted and rendered by
    /// `alice-miner engines` as if in force, while the argv never mentioned it —
    /// a signed instruction silently dropped.
    #[test]
    fn an_algorithm_on_a_kind_whose_argv_has_no_algorithm_slot_is_refused() {
        let doc: EnginesDoc = serde_json::from_str(&linux_xmr_doc(
            2,
            "6.27.0",
            SHA_A,
            r#""algorithm":"rx/1","#,
        ))
        .unwrap();
        let err = validate_doc(&doc).unwrap_err();
        assert!(
            err.contains("carries no algorithm token") && err.contains("gpu-prl"),
            "got: {err}"
        );
        // The kind that DOES have the slot still takes it.
        let ok: EnginesDoc = serde_json::from_str(&linux_prl_doc(
            2,
            "3.6.0",
            SHA_A,
            r#""algorithm":"pearlhash2","#,
        ))
        .unwrap();
        validate_doc(&ok).expect("gpu-prl has an algorithm slot");
        assert_eq!(
            ok.engines[0].invocation().unwrap().algorithm.as_deref(),
            Some("pearlhash2")
        );
        // And every kind we claim has no slot is a kind whose builder really has none.
        assert_eq!(KINDS_WITH_ALGORITHM_SLOT, &["gpu-prl"]);
    }

    /// An entry that says nothing about the call is byte-for-byte the compiled-in
    /// behaviour — the compatibility promise that lets this ship without churning
    /// a single existing pin.
    #[test]
    fn a_pin_that_says_nothing_about_the_call_changes_nothing() {
        let doc: EnginesDoc = serde_json::from_str(&doc_json(2, SHA_A, "3.5.5")).unwrap();
        let inv = doc.engines[0].invocation().unwrap();
        assert_eq!(inv, EngineInvocation::default());
        assert!(inv.is_default());
        let mut args = vec!["--pool".to_string(), "x".to_string()];
        inv.apply_extra_args(&mut args);
        assert_eq!(args, vec!["--pool".to_string(), "x".to_string()]);
        // And the embedded floor — every entry of it — is a default invocation, so
        // today's clients build exactly the argv they built before this existed.
        for e in embedded_entries() {
            assert_eq!(
                e.invocation().expect("floor entry validates"),
                EngineInvocation::default(),
                "floor entry {}/{} must not override the call",
                e.kind,
                e.target
            );
        }
    }

    /// A parser id this build does not have refuses the WHOLE document. Never a
    /// guess and never a partial apply: reading a fork's output with the nearest
    /// parser is exactly what showed `0 H/s · 0A/0R · STALL` on a healthy card.
    #[test]
    fn a_parser_id_this_client_does_not_have_refuses_the_whole_document() {
        for bad in ["srbminer-4", "srbminer2", "pearl", ""] {
            let doc: EnginesDoc = serde_json::from_str(&linux_prl_doc(
                2,
                "3.6.0",
                SHA_A,
                &format!(r#""parser":"{bad}","#),
            ))
            .unwrap();
            let err = validate_doc(&doc).unwrap_err();
            assert!(
                err.contains("does not have") && err.contains("Refusing to guess"),
                "parser {bad:?} got: {err}"
            );
        }
    }

    /// The core restriction on publisher-supplied argv: it may add switches to an
    /// engine and may NEVER restate a flag that decides where shares go, who is
    /// credited, what authorises the login, or where the engine writes. Case and an
    /// `=value` tail must not get round it.
    #[test]
    fn extra_argv_may_not_restate_a_flag_the_client_owns() {
        for bad in [
            "--pool",
            "--POOL=stratum+tcp://x:1",
            "-o",
            "-p",
            "-P",
            "--wallet",
            "--user",
            "--password",
            "--log-file",
            "--config",
            "--gpu-id",
            "--donate-level=5",
            "--algorithm",
            "--api-bind",
        ] {
            let doc: EnginesDoc = serde_json::from_str(&linux_prl_doc(
                2,
                "3.6.0",
                SHA_A,
                &format!(r#""extra_args":["{bad}"],"#),
            ))
            .unwrap();
            let err = match validate_doc(&doc) {
                Err(e) => e,
                Ok(()) => panic!("extra arg {bad:?} must be refused"),
            };
            assert!(
                err.contains("this client controls"),
                "extra arg {bad:?} got: {err}"
            );
        }
    }

    /// Extra argv may not carry a URL, a filesystem path, whitespace, or anything
    /// the credit-only / anti-leak gate refuses in a bring-your-own miner's argv.
    #[test]
    fn extra_argv_may_not_carry_a_url_a_path_or_a_leak() {
        let cases: &[(&str, &str)] = &[
            ("--upstream=https://evil.example/x", "carries a URL"),
            ("/etc/cron.d/x", "filesystem path"),
            ("--out=../../../home/v/.ssh/authorized_keys", "filesystem path"),
            ("--x ; rm -rf /", "whitespace or control"),
            ("--payout=prl1p32l5mxxxxxxxxxxxx", "honesty gate"),
            ("--fallback=prl.kryptex.network", "honesty gate"),
        ];
        for (bad, needle) in cases {
            let doc: EnginesDoc = serde_json::from_str(&linux_prl_doc(
                2,
                "3.6.0",
                SHA_A,
                &format!(r#""extra_args":[{}],"#, serde_json::to_string(bad).unwrap()),
            ))
            .unwrap();
            let err = match validate_doc(&doc) {
                Err(e) => e,
                Ok(()) => panic!("extra arg {bad:?} must be refused"),
            };
            assert!(err.contains(needle), "extra arg {bad:?} got: {err}");
        }
        // …and there is a hard ceiling on how many there can be.
        let many: Vec<String> = (0..MAX_EXTRA_ARGS + 1).map(|i| format!("--x{i}")).collect();
        let doc: EnginesDoc = serde_json::from_str(&linux_prl_doc(
            2,
            "3.6.0",
            SHA_A,
            &format!(
                r#""extra_args":{},"#,
                serde_json::to_string(&many).unwrap()
            ),
        ))
        .unwrap();
        assert!(validate_doc(&doc).is_err(), "too many extra args must refuse");
    }

    /// The algorithm slot takes an algorithm NAME. A flag smuggled into it would be
    /// argv this client placed itself, immediately after `--algorithm`.
    #[test]
    fn an_algorithm_token_that_is_really_a_flag_is_refused() {
        for bad in ["--config", "-a", "pearl hash", "pearl;hash", ""] {
            let doc: EnginesDoc = serde_json::from_str(&linux_prl_doc(
                2,
                "3.6.0",
                SHA_A,
                &format!(r#""algorithm":"{bad}","#),
            ))
            .unwrap();
            assert!(
                validate_doc(&doc).is_err(),
                "algorithm {bad:?} must be refused"
            );
        }
    }

    // ── F8: engine versions only go forward ────────────────────────────────────

    /// The comparator answers only what it can prove. Everything it cannot order is
    /// `Unordered`, which callers treat exactly like a downgrade.
    #[test]
    fn compare_versions_orders_only_what_it_can_prove() {
        use VersionOrder::*;
        assert_eq!(compare_versions("3.5.4", "3.4.1"), Newer);
        assert_eq!(compare_versions("3.4.1", "3.5.4"), Older);
        assert_eq!(compare_versions("3.10.0", "3.9.9"), Newer); // not lexicographic
        assert_eq!(compare_versions("3.5.4", "3.5.4"), Same);
        assert_eq!(compare_versions("v6.26.0", "6.26.0"), Same);
        assert_eq!(compare_versions("3.5", "3.5.0"), Same);
        assert_eq!(compare_versions("3.6", "3.5.9"), Newer);
        // Anything with a suffix, a date shape mixed with a semver, or a non-numeric
        // component is refused rather than guessed at. `alice_release::parse_version`
        // would silently truncate the first two of these to (3,5,4).
        for (a, b) in [
            ("3.5.4-rc1", "3.5.4"),
            ("3.5.4b", "3.5.4"),
            ("2026.08.14-nightly", "3.5.4"),
            ("3.5.4+build7", "3.5.4"),
            ("", "3.5.4"),
            ("latest", "3.5.4"),
        ] {
            assert_eq!(compare_versions(a, b), Unordered, "{a} vs {b}");
        }
    }

    /// THE F8 CASE: a signed list pointing back at SRBMiner 3.4.1 after the fork.
    /// Every other guard in this file waves it through — the bytes are real, they
    /// are on an allow-listed upstream page, the hash matches what we already trust
    /// for that version, and the epoch went up. It is a one-key replay of the
    /// 78-hour August outage, and it must be refused.
    #[test]
    fn an_unmarked_engine_downgrade_is_refused() {
        let mut st = PinState::default();
        let bytes = linux_prl_doc(2, "3.4.1", SHA_A, "").into_bytes();
        let err = apply_verified_document(&bytes, "sig", &mut st).unwrap_err();
        assert!(err.contains("moves gpu-prl/x86_64-unknown-linux-gnu backwards"), "got: {err}");
        assert!(err.contains("OLDER than the 3.5.4"), "names both versions: {err}");
        assert!(err.contains("\"downgrade\": true"), "says how to do it on purpose: {err}");
        assert!(err.contains("Refusing the whole list"), "whole-list refusal: {err}");
    }

    /// A version this client cannot order against the one in force is treated
    /// exactly like an older one: refused, not guessed at.
    #[test]
    fn a_version_that_cannot_be_ordered_is_refused_like_a_downgrade() {
        let mut st = PinState::default();
        let bytes = linux_prl_doc(2, "3.5.4-hotfix", SHA_A, "").into_bytes();
        let err = apply_verified_document(&bytes, "sig", &mut st).unwrap_err();
        assert!(err.contains("cannot be ordered against the 3.5.4"), "got: {err}");
    }

    /// A downgrade IS allowed — sometimes it is the right call — but only as a
    /// declared decision with a reason, because that reason is what every miner is
    /// shown.
    #[test]
    fn a_deliberate_downgrade_is_accepted_marked_and_does_not_lower_the_ratchet() {
        let env = TestEnv::new();
        let mut st = load_state();
        let bytes = linux_prl_doc(
            2,
            "3.4.1",
            SHA_A,
            r#""downgrade":true,"downgrade_reason":"3.5.4 crashes on RDNA3; reverting while upstream fixes it","#,
        )
        .into_bytes();
        let out = apply_verified_document(&bytes, "sig", &mut st).expect("marked downgrade");
        assert!(matches!(out, RefreshOutcome::Updated { epoch: 2, .. }), "got {out:?}");

        // The ratchet is RAISED-only: accepting a declared downgrade does not re-base
        // it, so republishing the older build has to keep re-stating the marker
        // rather than quietly becoming the new normal.
        let floors = load_state().version_floor;
        assert_eq!(
            floors
                .get("gpu-prl/x86_64-unknown-linux-gnu")
                .map(String::as_str),
            Some("3.5.4"),
            "a declared downgrade must not lower the ratchet"
        );
        // Proof that it stays armed: the SAME downgrade without the marker, at a
        // higher epoch, is still refused.
        let mut st = load_state();
        let unmarked = linux_prl_doc(3, "3.4.1", SHA_A, "").into_bytes();
        assert!(apply_verified_document(&unmarked, "sig", &mut st).is_err());
        drop(env);
    }

    /// The marker is a decision, not a checkbox: without a reason it is refused,
    /// because the reason is the whole of what a miner gets to judge.
    #[test]
    fn a_downgrade_marker_without_a_reason_is_refused() {
        for fields in [
            r#""downgrade":true,"#,
            r#""downgrade":true,"downgrade_reason":"","#,
            r#""downgrade":true,"downgrade_reason":"   ","#,
            r#""downgrade":true,"downgrade_reason":"oops","#,
        ] {
            let doc: EnginesDoc =
                serde_json::from_str(&linux_prl_doc(2, "3.4.1", SHA_A, fields)).unwrap();
            let err = validate_doc(&doc).unwrap_err();
            assert!(err.contains("gives no reason"), "got: {err}");
        }
    }

    /// Moving FORWARD is untouched — the ratchet must never be a reason a real
    /// emergency upgrade cannot be published.
    #[test]
    fn moving_the_engine_forward_is_unaffected_by_the_ratchet() {
        let env = TestEnv::new();
        let mut st = load_state();
        let bytes = linux_prl_doc(2, "3.6.0", SHA_A, "").into_bytes();
        let out = apply_verified_document(&bytes, "sig", &mut st).expect("an upgrade is accepted");
        assert!(matches!(out, RefreshOutcome::Updated { epoch: 2, .. }), "got {out:?}");
        assert_eq!(
            load_state()
                .version_floor
                .get("gpu-prl/x86_64-unknown-linux-gnu")
                .map(String::as_str),
            Some("3.6.0"),
            "the ratchet follows the upgrade"
        );
        drop(env);
    }

    #[test]
    fn a_valid_document_passes_validation() {
        let doc: EnginesDoc = serde_json::from_str(&doc_json(2, SHA_A, "3.5.3")).unwrap();
        validate_doc(&doc).expect("valid");
    }

    #[test]
    fn tampered_bytes_fail_the_signature() {
        let (bytes, sig, pubkey) = sign(&doc_json(2, SHA_A, "3.5.3"));
        alice_release::verify_engine_pin_sig_with(&bytes, &sig, &pubkey)
            .expect("clean doc verifies");
        let mut tampered = bytes.clone();
        // Flip one hex digit of the pinned hash — the classic swap-the-engine edit.
        let pos = tampered.windows(4).position(|w| w == b"1111").unwrap();
        tampered[pos] = b'9';
        alice_release::verify_engine_pin_sig_with(&tampered, &sig, &pubkey)
            .expect_err("a tampered pin list must NOT verify");
    }

    #[test]
    fn production_verification_is_fail_closed_without_a_subkey() {
        // No test key installed: this exercises the REAL trust root.
        let _e = TestEnv::new();
        // This build embeds no sub-key yet: the production entry point must refuse
        // every document, including a perfectly well-formed one.
        let (bytes, sig, _pk) = sign(&doc_json(2, SHA_A, "3.5.3"));
        if alice_release::ENGINE_PIN_PUBKEY_B64.trim().is_empty() {
            let err = alice_release::verify_engine_pin_sig(&bytes, &sig).unwrap_err();
            assert!(err.contains("no engine-pin public key"), "got: {err}");
            assert!(matches!(refresh_now(), RefreshOutcome::Disabled(_)));
            // …and the resolver still has pins: the embedded floor.
            assert!(!embedded_entries().is_empty(), "embedded floor must exist");
        }
    }

    #[test]
    fn urls_outside_the_upstream_allowlist_are_refused() {
        let mut doc: EnginesDoc = serde_json::from_str(&doc_json(2, SHA_A, "3.5.3")).unwrap();
        doc.engines[0].archive_url =
            Some("https://cdn.attacker.example/SRBMiner-Multi-3-5-3-Linux.tar.gz".into());
        let err = validate_doc(&doc).unwrap_err();
        assert!(
            err.contains("not one of the upstream release hosts"),
            "got: {err}"
        );
        // A prefix-lookalike must not sneak through.
        doc.engines[0].archive_url = Some(
            "https://evil.example/https://github.com/doktor83/SRBMiner-Multi/releases/download/x"
                .into(),
        );
        validate_doc(&doc).unwrap_err();
    }

    #[test]
    fn unsafe_filenames_and_members_are_refused() {
        for bad in ["../../etc/cron.d/x", "sub/dir", ".hidden", ""] {
            let mut doc: EnginesDoc = serde_json::from_str(&doc_json(2, SHA_A, "3.5.3")).unwrap();
            doc.engines[0].filename = bad.to_string();
            assert!(
                validate_doc(&doc).is_err(),
                "filename {bad:?} must be refused"
            );
        }
        let mut doc: EnginesDoc = serde_json::from_str(&doc_json(2, SHA_A, "3.5.3")).unwrap();
        doc.engines[0].binary_path_in_archive = Some("../../../home/v/.ssh/authorized_keys".into());
        assert!(
            validate_doc(&doc).is_err(),
            "traversing archive member must be refused"
        );
    }

    #[test]
    fn a_newer_schema_is_refused_not_guessed() {
        let mut doc: EnginesDoc = serde_json::from_str(&doc_json(2, SHA_A, "3.5.3")).unwrap();
        doc.schema = DOC_SCHEMA + 1;
        let err = validate_doc(&doc).unwrap_err();
        assert!(err.contains("understands at most"), "got: {err}");
    }

    #[test]
    fn a_wrong_product_document_is_refused() {
        let mut doc: EnginesDoc = serde_json::from_str(&doc_json(2, SHA_A, "3.5.3")).unwrap();
        doc.product = "alice-miner".into(); // the CLIENT manifest, fed here by mistake
        assert!(validate_doc(&doc).is_err());
    }

    #[test]
    fn a_document_that_retires_itself_is_refused() {
        let mut doc: EnginesDoc = serde_json::from_str(&doc_json(2, SHA_A, "3.5.3")).unwrap();
        doc.min_engine_epoch = 9;
        assert!(
            validate_doc(&doc).is_err(),
            "min_engine_epoch > epoch is self-contradictory"
        );
    }

    /// The bundled Linux GPU-PRL engine version, read from the embedded floor. Tests
    /// that need "a version the floor already knows" ask for it here instead of
    /// hard-coding one, so bumping the bundled engine can never fail them spuriously.
    fn floor_prl_version() -> String {
        embedded_entries()
            .iter()
            .find(|e| e.kind == "gpu-prl" && e.target == "x86_64-unknown-linux-gnu")
            .and_then(|e| e.version.clone())
            .expect("the floor pins a linux gpu-prl engine with a version")
    }

    /// Anti-rollback: a signed but older document is refused against the floor.
    #[test]
    fn a_rolled_back_epoch_is_refused() {
        let mut st = PinState {
            epoch_floor: 5,
            ..Default::default()
        };
        let bytes = doc_json(4, SHA_A, "3.5.3").into_bytes();
        let err = apply_verified_document(&bytes, "sig", &mut st).unwrap_err();
        assert!(err.contains("below the floor"), "got: {err}");
    }

    /// Anti-swap: the embedded floor's (kind,target,version) → sha is remembered,
    /// so a document re-issuing a version the floor already knows, with different
    /// bytes, is refused whole. The version is taken FROM the floor rather than
    /// written here: pinning a literal made this test fail the moment the bundled
    /// engine was bumped, which is drift in the test, not in the ratchet.
    #[test]
    fn reissuing_a_known_version_with_new_bytes_is_refused() {
        let mut st = PinState::default();
        let known = floor_prl_version();
        let bytes = doc_json(2, SHA_B, &known).into_bytes();
        let err = apply_verified_document(&bytes, "sig", &mut st).unwrap_err();
        assert!(err.contains("changes the bytes of"), "got: {err}");
        assert!(
            err.contains("refusing the whole list"),
            "whole-list refusal: {err}"
        );
    }

    /// The embedded floor parses and carries the engines the resolver needs.
    #[test]
    fn embedded_floor_parses_and_has_real_pins() {
        let entries = embedded_entries();
        assert!(entries.len() >= 8, "floor has every bundled engine");
        let prl = entries
            .iter()
            .find(|e| e.kind == "gpu-prl" && e.target == "x86_64-unknown-linux-gnu")
            .expect("linux gpu-prl pin exists");
        assert!(prl.real_sha256().is_some(), "a real pin, not a placeholder");
        // Which version is bundled is a release decision, not a property this test
        // gets to assert — it only has to BE a version.
        assert!(
            prl.version.as_deref().is_some_and(|v| !v.is_empty()),
            "the pin names its upstream version"
        );
        let kawpow = entries.iter().find(|e| e.kind == "gpu-rvn").unwrap();
        assert!(
            kawpow.real_sha256().is_none(),
            "the all-zero placeholder is not a pin"
        );
    }

    /// With no remote document, the effective pin IS the embedded one.
    #[test]
    fn effective_pin_falls_back_to_the_embedded_floor() {
        let _e = TestEnv::new();
        let got = effective_pin("gpu-prl", "x86_64-unknown-linux-gnu", "SRBMiner-MULTI")
            .expect("floor pin");
        assert_eq!(got.source, PinSource::Embedded);
        assert_eq!(got.entry.version.as_deref(), Some(floor_prl_version().as_str()));
    }

    #[test]
    fn state_round_trips_through_disk() {
        let e = TestEnv::new();
        let mut st = PinState {
            schema: 1,
            epoch_floor: 3,
            ..Default::default()
        };
        st.seen.insert(
            "gpu-prl/x86_64-unknown-linux-gnu/3.5.3".into(),
            SHA_A.into(),
        );
        save_state(&st).expect("save");
        let back = load_state();
        assert_eq!(back.epoch_floor, 3);
        assert_eq!(
            back.seen
                .get("gpu-prl/x86_64-unknown-linux-gnu/3.5.3")
                .map(String::as_str),
            Some(SHA_A)
        );
        assert!(e.dir.join("pins/state.json").is_file());
    }

    /// Every download URL in the embedded floor sits under an allow-listed
    /// upstream prefix. Guards a future edit to `miners.json` that would add a
    /// host the pin path refuses at runtime (a lane that silently can't fetch).
    #[test]
    fn embedded_floor_urls_are_all_allow_listed() {
        for e in embedded_entries() {
            for url in [e.binary_url.as_deref(), e.archive_url.as_deref()]
                .into_iter()
                .flatten()
            {
                assert!(url_is_allowed(url), "floor URL not allow-listed: {url}");
            }
        }
    }

    /// CONTRACT between the publishing script and this parser: the exact bytes
    /// `scripts/build_engines_manifest.py` emits (field order, key names, types)
    /// must validate here. Captured from a real run of the script against the
    /// upstream xmrig 6.26.0 release, so a change on either side breaks this test
    /// rather than a miner's engine.
    #[test]
    fn the_publishing_scripts_output_validates() {
        let produced = r#"{
  "schema": 1,
  "product": "alice-miner-engines",
  "epoch": 1,
  "min_engine_epoch": 1,
  "issued": "2026-08-14T18:34:46Z",
  "notes": "Baseline: the engines compiled into client v0.6.7.",
  "engines": [
    {
      "kind": "cpu-xmr",
      "engine": "xmrig",
      "version": "6.26.0",
      "target": "x86_64-unknown-linux-gnu",
      "filename": "xmrig",
      "source_url": "https://github.com/xmrig/xmrig/releases/tag/v6.26.0",
      "endorsed_by": "V",
      "endorsed_at": "2026-06-26T00:00:00Z",
      "notes": "Cross-checked against xmrig's official SHA256SUMS (shasum -c OK) 2026-06-26.",
      "sha256": "b20f39fc00d242e706b6c30367ad811c676e0575050a4ec2f30104b696944b49",
      "archive_url": "https://github.com/xmrig/xmrig/releases/download/v6.26.0/xmrig-6.26.0-linux-static-x64.tar.gz",
      "archive_sha256": "fc6f8ae5f64e4f17481f7e3be29a1c56949f216a998414188003eae1db20c9e5",
      "binary_path_in_archive": "xmrig-6.26.0/xmrig"
    }
  ]
}
"#;
        let doc: EnginesDoc = serde_json::from_str(produced).expect("parses");
        validate_doc(&doc).expect("and is acceptable");
        // The hashes the script reproduced are the ones this client already pins:
        // running the publisher against today's sources is a no-op, by construction.
        let floor = embedded_entry("cpu-xmr", "x86_64-unknown-linux-gnu", "xmrig").unwrap();
        assert_eq!(doc.engines[0].sha256, floor.sha256);
    }

    /// The SAME contract for the fields the script gained with the invocation and
    /// the downgrade marker: field order, key names and JSON types as
    /// `scripts/build_engines_manifest.py` emits them, so a change on either side
    /// breaks this test rather than a miner's engine.
    ///
    /// The gpu-prl entry is the script's own smoke output, verbatim, with one
    /// edit made on 2026-08-15: its `extra_args` moved to a second `cpu-xmr` entry
    /// carrying a REVIEWED flag, because extra argv became bounded by a per-engine
    /// allow-list that (deliberately) has no SRBMiner entries. Re-spelled on
    /// 2026-08-16 into the canonical one-token form, which is now the only accepted
    /// spelling. Everything the contract is about — the key shape of `extra_args` as
    /// a JSON list of argv tokens — is still exercised.
    #[test]
    fn the_publishing_scripts_invocation_and_downgrade_output_validates() {
        let produced = r#"{
  "schema": 1,
  "product": "alice-miner-engines",
  "epoch": 3,
  "min_engine_epoch": 1,
  "issued": "2026-08-15T00:09:26Z",
  "notes": "smoke",
  "engines": [
    {
      "kind": "gpu-prl",
      "engine": "srbminer-multi",
      "version": "9.9.9",
      "target": "x86_64-unknown-linux-gnu",
      "filename": "SRBMiner-MULTI",
      "source_url": "https://github.com/doktor83/SRBMiner-Multi/releases/tag/9.9.9",
      "endorsed_by": "V",
      "endorsed_at": "2026-08-15T00:00:00Z",
      "algorithm": "pearlhash2",
      "parser": "srbminer",
      "downgrade": true,
      "downgrade_reason": "smoke test of the marker path",
      "sha256": "43224fd816f8416299aeff9d6e4cf5633c34113c9029a8347f95f66256c1a278",
      "archive_url": "https://github.com/doktor83/SRBMiner-Multi/releases/download/9.9.9/x.tar.gz",
      "archive_sha256": "412df2665bd292191586a3194e0212a38aba323ffb85cc983540785bda067fa8",
      "binary_path_in_archive": "SRBMiner-Multi-9-9-9/SRBMiner-MULTI"
    },
    {
      "kind": "cpu-xmr",
      "engine": "xmrig",
      "version": "6.27.0",
      "target": "x86_64-unknown-linux-gnu",
      "filename": "xmrig",
      "source_url": "https://github.com/xmrig/xmrig/releases/tag/v6.27.0",
      "endorsed_by": "V",
      "endorsed_at": "2026-08-15T00:00:00Z",
      "extra_args": [
        "--randomx-mode=light"
      ],
      "parser": "xmrig",
      "sha256": "43224fd816f8416299aeff9d6e4cf5633c34113c9029a8347f95f66256c1a278",
      "archive_url": "https://github.com/xmrig/xmrig/releases/download/v6.27.0/x.tar.gz",
      "archive_sha256": "412df2665bd292191586a3194e0212a38aba323ffb85cc983540785bda067fa8",
      "binary_path_in_archive": "xmrig-6.27.0/xmrig"
    }
  ]
}
"#;
        let doc: EnginesDoc = serde_json::from_str(produced).expect("parses");
        validate_doc(&doc).expect("and is acceptable");
        let e = &doc.engines[0];
        let inv = e.invocation().expect("invocation");
        assert_eq!(inv.algorithm.as_deref(), Some("pearlhash2"));
        assert_eq!(inv.parser, Some(crate::stats::ParserKind::Srbminer));
        assert!(inv.extra_args.is_empty());
        assert!(e.downgrade);
        assert_eq!(
            e.downgrade_reason.as_deref(),
            Some("smoke test of the marker path")
        );
        let xmr = doc.engines[1].invocation().expect("invocation");
        assert_eq!(xmr.extra_args, vec!["--randomx-mode=light".to_string()]);
        assert_eq!(xmr.parser, Some(crate::stats::ParserKind::Xmr));
        assert!(xmr.algorithm.is_none());
    }

    // ── The full pipeline, offline ─────────────────────────────────────────
    //
    // These drive `refresh` end-to-end with a throwaway signing key and a
    // scripted download, so every branch a real hard-fork day would take is
    // covered on every OS with no network.

    /// Redirects the engines root (pins + engine cache) at a scratch dir, installs
    /// the throwaway trust key, and restores everything on drop.
    struct TestEnv {
        dir: PathBuf,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl TestEnv {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let guard = crate::MINER_BIN_ENV_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let dir = std::env::temp_dir().join(format!(
                "alice-pins-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            std::env::set_var(ENGINES_DIR_ENV, &dir);
            invalidate_cache();
            Self { dir, _guard: guard }
        }

        /// Install the throwaway public key as this process's pin trust root.
        fn trust_test_key(&self) {
            let (_b, _s, pk) = sign("x");
            *test_trust_key().lock().unwrap_or_else(|e| e.into_inner()) = Some(pk);
            invalidate_cache();
        }

        fn on_fetch(
            &self,
            f: impl Fn(&PinEntry) -> Result<Vec<u8>, binaries::FetchFail> + Send + Sync + 'static,
        ) {
            *test_fetch_hook().lock().unwrap_or_else(|e| e.into_inner()) = Some(Box::new(f));
        }
    }

    impl Drop for TestEnv {
        fn drop(&mut self) {
            std::env::remove_var(ENGINES_DIR_ENV);
            *test_trust_key().lock().unwrap_or_else(|e| e.into_inner()) = None;
            *test_fetch_hook().lock().unwrap_or_else(|e| e.into_inner()) = None;
            invalidate_cache();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// A document pinning the GPU-PRL engine for THIS machine's triple, so the
    /// staging path runs identically on macOS, Linux and Windows.
    fn doc_for_this_platform(epoch: u64, version: &str, sha: &str) -> String {
        doc_for_this_platform_with(epoch, version, sha, "")
    }

    /// [`doc_for_this_platform`] with raw extra entry fields (each ending in a comma).
    fn doc_for_this_platform_with(
        epoch: u64,
        version: &str,
        sha: &str,
        extra_fields: &str,
    ) -> String {
        let filename = MinerKind::GpuPrl.binary_name();
        let member = if cfg!(windows) {
            "SRBMiner-Multi-3-5-3/SRBMiner-MULTI.exe"
        } else {
            "SRBMiner-Multi-3-5-3/SRBMiner-MULTI"
        };
        let archive = if cfg!(windows) {
            "SRBMiner-Multi-3-5-3-win64.zip"
        } else {
            "SRBMiner-Multi-3-5-3-Linux.tar.gz"
        };
        format!(
            r#"{{"schema":1,"product":"alice-miner-engines","epoch":{epoch},
  "min_engine_epoch":1,"issued":"2026-08-14T00:00:00Z",
  "notes":"Pearl emergency hard fork",
  "engines":[{{"kind":"gpu-prl","engine":"srbminer-multi","version":"{version}",
    "target":"{target}","filename":"{filename}","sha256":"{sha}",
    {extra_fields}
    "archive_url":"https://github.com/doktor83/SRBMiner-Multi/releases/download/3.5.3/{archive}",
    "archive_sha256":"{sha}","binary_path_in_archive":"{member}",
    "source_url":"https://github.com/doktor83/SRBMiner-Multi/releases/tag/3.5.3",
    "endorsed_at":"2026-08-14T09:00:00Z","endorsed_by":"V"}}]}}"#,
            target = binaries::current_target_triple()
        )
    }

    fn sha_of(bytes: &[u8]) -> String {
        alice_release::sha256_hex(bytes)
    }

    /// HAPPY PATH: signed list → staged download → verified bytes → atomic install
    /// → the new pin is what the resolver now enforces, with its provenance.
    #[test]
    fn a_signed_list_stages_verifies_installs_and_becomes_effective() {
        let env = TestEnv::new();
        env.trust_test_key();
        let engine_bytes = b"SRBMiner-MULTI 3.5.3 (pearl fork) payload".to_vec();
        let sha = sha_of(&engine_bytes);
        let json = doc_for_this_platform(2, "3.5.3", &sha);
        let (bytes, sig, _pk) = sign(&json);
        let staged = engine_bytes.clone();
        env.on_fetch(move |_e| Ok(staged.clone()));

        let mut st = load_state();
        let out = apply_document(&bytes, &sig, &mut st).expect("accepted");
        assert!(
            matches!(out, RefreshOutcome::Updated { epoch: 2, .. }),
            "got {out:?}"
        );

        // The engine is on disk, atomically installed, byte-identical to what was
        // verified — and nothing partial is left behind.
        let installed = binaries::engine_cache_dir()
            .unwrap()
            .join(MinerKind::GpuPrl.binary_name());
        assert_eq!(std::fs::read(&installed).unwrap(), engine_bytes);
        let leftovers: Vec<_> = std::fs::read_dir(installed.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("partial"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "no partial file may survive an install"
        );

        // The resolver now enforces the NEW pin, and can say where it came from.
        let pin = effective_pin_for(MinerKind::GpuPrl).expect("effective pin");
        assert_eq!(pin.entry.real_sha256().as_deref(), Some(sha.as_str()));
        assert_eq!(pin.entry.version.as_deref(), Some("3.5.3"));
        assert_eq!(
            pin.source,
            PinSource::Remote {
                epoch: 2,
                issued: "2026-08-14T00:00:00Z".into()
            }
        );
        assert_eq!(pin.entry.endorsed_by.as_deref(), Some("V"));
        assert!(pin
            .entry
            .source_url
            .as_deref()
            .unwrap()
            .contains("SRBMiner-Multi/releases/tag/3.5.3"));

        // Persisted: epoch floor raised, version→hash remembered.
        let st2 = load_state();
        assert_eq!(st2.epoch_floor, 2);
        let key = format!("gpu-prl/{}/3.5.3", binaries::current_target_triple());
        assert_eq!(st2.seen.get(&key).map(String::as_str), Some(sha.as_str()));

        // Status is user-showable and reports the engine as installed.
        let status = status_for_current_platform();
        let prl = status
            .iter()
            .find(|s| s.kind == "gpu-prl")
            .expect("prl status");
        assert!(prl.installed, "the staged engine is present and verified");
        assert!(
            prl.source.contains("epoch 2"),
            "provenance shown: {}",
            prl.source
        );
    }

    /// F6 END TO END: a signed list that says HOW to call the engine, not just
    /// which bytes it is, and the launch path's own resolver
    /// ([`effective_invocation`] — what `engine.rs` calls on every rebuild) hands
    /// back exactly that. Without this the pin could carry the fields and the
    /// client could still launch the compiled-in call.
    #[test]
    fn a_signed_pin_changes_how_the_engine_is_called_not_only_which_bytes_run() {
        let env = TestEnv::new();
        env.trust_test_key();
        // Before: no document, so the compiled-in call is in force.
        assert_eq!(
            effective_invocation(MinerKind::GpuPrl).unwrap(),
            EngineInvocation::default(),
            "the floor overrides nothing"
        );

        let engine_bytes = b"SRBMiner-MULTI 3.6.0 (next fork) payload".to_vec();
        let sha = sha_of(&engine_bytes);
        let json = doc_for_this_platform_with(
            2,
            "3.6.0",
            &sha,
            r#""algorithm":"pearlhash2","parser":"generic","#,
        );
        let (bytes, sig, _pk) = sign(&json);
        let staged = engine_bytes.clone();
        env.on_fetch(move |_e| Ok(staged.clone()));
        let mut st = load_state();
        apply_document(&bytes, &sig, &mut st).expect("accepted");

        let inv = effective_invocation(MinerKind::GpuPrl).expect("invocation in force");
        assert_eq!(inv.algorithm.as_deref(), Some("pearlhash2"));
        assert_eq!(inv.parser, Some(crate::stats::ParserKind::Generic));
        assert!(
            inv.extra_args.is_empty(),
            "no extra argument has been reviewed for SRBMiner"
        );

        // And it is visible to the miner, not just to the launch path.
        let status = status_for_current_platform();
        let prl = status.iter().find(|s| s.kind == "gpu-prl").expect("status");
        assert_eq!(prl.algorithm.as_deref(), Some("pearlhash2"));
        assert_eq!(prl.parser.as_deref(), Some("generic"));
        assert!(prl.extra_args.is_empty());
        assert!(prl.downgrade_reason.is_none());
    }

    /// THE UPGRADE PATH, which is where a validation change usually leaks: a
    /// document that a PREVIOUS build accepted is sitting in the cache, correctly
    /// signed, with an epoch above the floor — and it carries the argv the old
    /// deny-list waved through. Shipping the fix must not leave that document in
    /// force on every machine that already took it.
    ///
    /// It does not, because the cached document is re-validated on every load, and a
    /// document is refused WHOLE: the client falls back to the pins compiled into it
    /// rather than keeping the parts it still likes.
    #[test]
    fn a_document_a_previous_build_accepted_is_refused_after_the_rules_tighten() {
        let env = TestEnv::new();
        env.trust_test_key();
        // Byte-for-byte the attack: an alias of --user/--pass the old deny-list did
        // not name, on the engine whose reviewed list is empty.
        let json = doc_for_this_platform_with(
            2,
            "3.6.0",
            SHA_A,
            r#""extra_args":["--userpass=5Gw3sAttackerAddress:zz"],"#,
        );
        let (bytes, sig, _pk) = sign(&json);
        // Plant it exactly as a previous build would have left it, bypassing the
        // acceptance path (which would refuse it now — that is the point).
        std::fs::create_dir_all(pins_dir().unwrap()).unwrap();
        std::fs::write(doc_path().unwrap(), &bytes).unwrap();
        std::fs::write(sig_path().unwrap(), &sig).unwrap();
        let mut st = load_state();
        st.epoch_floor = 1;
        save_state(&st).unwrap();
        invalidate_cache();

        assert!(
            active_doc().is_none(),
            "a cached document carrying unreviewed argv must not become active"
        );
        // …and whatever pin is in force is the compiled-in floor, not the document's.
        if let Some(p) = effective_pin_for(MinerKind::GpuPrl) {
            assert_eq!(p.source, PinSource::Embedded, "must fall back to the floor");
        }
        assert!(effective_invocation(MinerKind::GpuPrl)
            .expect("the floor invocation is valid")
            .is_default());
        assert!(
            load_state()
                .last_error
                .unwrap_or_default()
                .contains("cached engine pin list rejected"),
            "and the miner is told why"
        );
    }

    /// A DELIBERATE downgrade is surfaced by the same status the CLI and `doctor`
    /// render — with the published reason, verbatim. A signed rollback to an older
    /// engine is the shape of the August outage; it may happen, and it may not be
    /// quiet.
    #[test]
    fn a_deliberate_downgrade_is_loud_in_the_status_a_miner_sees() {
        let env = TestEnv::new();
        env.trust_test_key();
        let engine_bytes = b"SRBMiner-MULTI 3.5.0 payload".to_vec();
        let sha = sha_of(&engine_bytes);
        let json = doc_for_this_platform_with(
            2,
            "3.5.0",
            &sha,
            r#""downgrade":true,"downgrade_reason":"3.5.4 crashes on RDNA3; reverting while upstream fixes it","#,
        );
        let (bytes, sig, _pk) = sign(&json);
        let staged = engine_bytes.clone();
        env.on_fetch(move |_e| Ok(staged.clone()));
        let mut st = load_state();
        apply_document(&bytes, &sig, &mut st).expect("a marked downgrade is accepted");

        let status = status_for_current_platform();
        let prl = status.iter().find(|s| s.kind == "gpu-prl").expect("status");
        assert_eq!(
            prl.downgrade_reason.as_deref(),
            Some("3.5.4 crashes on RDNA3; reverting while upstream fixes it")
        );
    }

    /// A tampered document is refused, and refusal changes NOTHING: no document is
    /// written, the previous (embedded) pin stays in force.
    #[test]
    fn a_tampered_list_is_refused_and_nothing_changes() {
        let env = TestEnv::new();
        env.trust_test_key();
        env.on_fetch(|_e| panic!("a refused list must never trigger a download"));
        let json = doc_for_this_platform(2, "3.5.3", SHA_A);
        let (bytes, sig, _pk) = sign(&json);
        let mut tampered = bytes.clone();
        let pos = tampered.windows(4).position(|w| w == b"1111").unwrap();
        tampered[pos] = b'9';

        let mut st = load_state();
        let err = apply_document(&tampered, &sig, &mut st).unwrap_err();
        assert!(err.contains("signature check FAILED"), "got: {err}");
        assert!(
            !env.dir.join("pins/engines.json").exists(),
            "no document may be written"
        );
        assert!(active_doc().is_none(), "no document may become active");
    }

    /// HASH MISMATCH: the bytes upstream do not match the signed pin. The list is
    /// refused whole, nothing is installed, and — the part that matters — we do NOT
    /// fall back to "mine with the old engine and say nothing".
    #[test]
    fn bytes_that_do_not_match_the_pin_are_refused_without_fallback() {
        let env = TestEnv::new();
        env.trust_test_key();
        let json = doc_for_this_platform(2, "3.5.3", SHA_A);
        let (bytes, sig, _pk) = sign(&json);
        env.on_fetch(|_e| {
            Err(binaries::FetchFail::Integrity(
                "refusing to install SRBMiner-MULTI: downloaded SHA-256 dead… does not match the \
                 pinned 1111…"
                    .into(),
            ))
        });

        let mut st = load_state();
        let err = apply_document(&bytes, &sig, &mut st).unwrap_err();
        assert!(err.contains("do not hash to the pin"), "got: {err}");
        assert!(
            err.contains("Nothing was installed"),
            "says what did NOT happen: {err}"
        );
        assert!(
            !env.dir.join("pins/engines.json").exists(),
            "no document written"
        );
        assert!(
            !binaries::engine_cache_dir()
                .unwrap()
                .join(MinerKind::GpuPrl.binary_name())
                .exists(),
            "no engine installed"
        );
        assert_eq!(
            load_state().epoch_floor,
            0,
            "a refused list must not raise the floor"
        );
        // And the pin the resolver enforces is still the built-in floor.
        let pin = effective_pin("gpu-prl", "x86_64-unknown-linux-gnu", "SRBMiner-MULTI").unwrap();
        assert_eq!(pin.source, PinSource::Embedded);
    }

    /// DOWNLOAD FAILURE (network): keep the current pin, keep mining, retry later —
    /// and be explicit that we deferred rather than silently doing nothing.
    #[test]
    fn a_download_failure_defers_and_keeps_the_current_pin() {
        let env = TestEnv::new();
        env.trust_test_key();
        let json = doc_for_this_platform(2, "3.5.3", SHA_A);
        let (bytes, sig, _pk) = sign(&json);
        env.on_fetch(|_e| Err(binaries::FetchFail::Network("connection timed out".into())));

        let mut st = load_state();
        let out = apply_document(&bytes, &sig, &mut st).expect("deferred, not rejected");
        match &out {
            RefreshOutcome::Deferred(msg) => {
                assert!(msg.contains("could not be downloaded"), "got: {msg}");
                assert!(msg.contains("keeping the current engine"), "got: {msg}");
            }
            other => panic!("expected Deferred, got {other:?}"),
        }
        assert!(!env.dir.join("pins/engines.json").exists(), "not activated");
        assert_eq!(
            load_state().epoch_floor,
            0,
            "floor untouched, so we can retry this epoch"
        );
        assert!(
            out.is_problem(),
            "a deferral is reportable, not a silent no-op"
        );
    }

    /// Re-publishing the SAME epoch with different content is refused; the exact
    /// same bytes are a no-op.
    #[test]
    fn an_epoch_is_published_once() {
        let env = TestEnv::new();
        env.trust_test_key();
        let engine_bytes = b"engine v1".to_vec();
        let json = doc_for_this_platform(2, "3.5.3", &sha_of(&engine_bytes));
        let (bytes, sig, _pk) = sign(&json);
        let staged = engine_bytes.clone();
        env.on_fetch(move |_e| Ok(staged.clone()));
        let mut st = load_state();
        apply_document(&bytes, &sig, &mut st).expect("first accept");

        // Identical bytes → Unchanged.
        let mut st = load_state();
        let out = apply_document(&bytes, &sig, &mut st).expect("idempotent");
        assert!(
            matches!(out, RefreshOutcome::Unchanged { epoch: 2 }),
            "got {out:?}"
        );

        // Same epoch, different content → refused.
        let json2 = doc_for_this_platform(2, "3.5.4", SHA_B);
        let (bytes2, sig2, _pk) = sign(&json2);
        let mut st = load_state();
        let err = apply_document(&bytes2, &sig2, &mut st).unwrap_err();
        assert!(err.contains("reuses epoch"), "got: {err}");
    }

    /// A cached document is re-verified on every load: locally editing the pin
    /// file (the "swap the hash on disk" attack) demotes the client to its
    /// built-in floor instead of trusting the edit.
    #[test]
    fn a_locally_edited_cached_document_is_ignored() {
        let env = TestEnv::new();
        env.trust_test_key();
        let engine_bytes = b"engine v1".to_vec();
        let json = doc_for_this_platform(2, "3.5.3", &sha_of(&engine_bytes));
        let (bytes, sig, _pk) = sign(&json);
        let staged = engine_bytes.clone();
        env.on_fetch(move |_e| Ok(staged.clone()));
        let mut st = load_state();
        apply_document(&bytes, &sig, &mut st).expect("accepted");
        assert!(active_doc().is_some());

        // Edit the cached document in place, as a local attacker would.
        let path = env.dir.join("pins/engines.json");
        let edited = String::from_utf8(std::fs::read(&path).unwrap())
            .unwrap()
            .replace("3.5.3", "9.9.9");
        std::fs::write(&path, edited).unwrap();
        invalidate_cache();
        assert!(
            active_doc().is_none(),
            "an unsigned edit must not be honoured"
        );
        let pin = effective_pin("gpu-prl", "x86_64-unknown-linux-gnu", "SRBMiner-MULTI").unwrap();
        assert_eq!(
            pin.source,
            PinSource::Embedded,
            "demoted to the built-in floor"
        );
    }

    // ── F15: the refresher must not be gated on a lane starting an engine ────

    /// The pin refresher starts ONCE per process, however many callers ask —
    /// front-end startup hooks, and every lane that later resolves an engine.
    ///
    /// It also must not need a lane at all. That was F15: the only caller was
    /// inside `resolve_miner_binary`, which runs when a lane starts an engine —
    /// so a client the acceptance guard had HALTED (which starts no engine, ever)
    /// could never receive the fixed engine pin that would un-halt it. The rescue
    /// path was gated behind the very thing that was broken.
    #[test]
    fn the_pin_refresher_starts_once_per_process_without_any_lane() {
        // Holds the engine-binary env lock, so setting the overrides below cannot
        // race the `binaries` tests.
        let _env = TestEnv::new();

        // No engine is running, no lane exists, nothing has been resolved: the
        // front-end startup hook is enough on its own.
        start_background_refresh();
        assert_eq!(
            background_refresh_starts(),
            1,
            "process start must be enough to arm the refresher"
        );
        for _ in 0..5 {
            start_background_refresh();
        }

        // And every lane that later resolves an engine is a no-op (the belt in
        // `resolve_miner_binary`). The override points at nothing, so resolution
        // fails immediately — AFTER the refresher call, which is the point: the
        // refresher does not depend on an engine being resolvable at all.
        for kind in [MinerKind::CpuXmr, MinerKind::GpuRvn, MinerKind::GpuPrl] {
            std::env::set_var(kind.env_override(), "/no/such/alice/miner/binary");
            assert!(binaries::resolve_miner_binary(kind).is_err());
            std::env::remove_var(kind.env_override());
        }
        assert_eq!(
            background_refresh_starts(),
            1,
            "exactly one refresher, no matter how many callers"
        );
    }

    /// `min_engine_epoch` retires older documents: after a list that raises the
    /// floor, the previously-cached one is no longer honoured.
    #[test]
    fn min_engine_epoch_retires_an_older_cached_document() {
        let env = TestEnv::new();
        env.trust_test_key();
        let engine_bytes = b"engine v1".to_vec();
        let json = doc_for_this_platform(2, "3.5.3", &sha_of(&engine_bytes));
        let (bytes, sig, _pk) = sign(&json);
        let staged = engine_bytes.clone();
        env.on_fetch(move |_e| Ok(staged.clone()));
        let mut st = load_state();
        apply_document(&bytes, &sig, &mut st).expect("accepted");

        // A later list retires everything below epoch 5 — recorded in the floor.
        let mut st = load_state();
        st.epoch_floor = 5;
        save_state(&st).unwrap();
        invalidate_cache();
        assert!(
            active_doc().is_none(),
            "the retired cached document must be dropped"
        );
        let err = load_state().last_error.unwrap_or_default();
        assert!(err.contains("below the floor"), "and it says why: {err}");
    }
}
