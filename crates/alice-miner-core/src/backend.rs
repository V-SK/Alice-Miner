//! `core/backend` — the **pluggable miner backend** (BYO / bring-your-own miner).
//!
//! The client can drive TWO backend sources behind the SAME supervisor + PoP +
//! telemetry shell:
//!   * [`MinerBackend::Bundled`] — the official SHA-pinned engines (SRBMiner /
//!     xmrig / kawpowminer / AlphaMiner), resolved by [`crate::binaries`];
//!   * [`MinerBackend::Custom`] — a user-supplied, possibly CLOSED-SOURCE miner
//!     binary (form A: the CLI fully manages it — spawns + supervises + PoP +
//!     telemetry, exactly like a bundled engine, only the binary + argv shape
//!     differ).
//!
//! The insight (design §2.1): a backend's ONLY job is to produce the `(program,
//! args)` a lane's `RebuildFn` returns. So `Custom` reuses the entire bundled
//! path — region-bound PoP ([`crate::pop::establish_pop`]), the `<alice>.<worker>`
//! login ([`crate::lane::xmr::derive_worker_id`] — the reward-attribution key is
//! UNCHANGED), failover, PoP-refresh — and only swaps the binary and the argv
//! template. The engine builds the argv [`ArgContext`] (pool/wallet/pop/algo/log)
//! and this module renders it per the miner's [`MinerPreset`] or a placeholder
//! [`MinerPreset::Template`].
//!
//! ── TRUST (design §2.6) ──────────────────────────────────────────────────────
//! A custom binary is NOT SHA-pinned — it is the user's own miner. Running it is
//! an EXPLICIT opt-in: [`CustomMiner::acknowledged_unverified`] must be `true`
//! (the wizard takes one `[y/N]`), and [`resolve_custom_binary`] prints a loud
//! warning on EVERY start (the same "you are running an unverified binary"
//! semantics as the `ALICE_MINER_ALLOW_UNVERIFIED_BIN` bundled escape hatch).
//!
//! ── HONESTY (design §2.6 / §7) ───────────────────────────────────────────────
//! The rendered argv is ALWAYS run through [`assert_no_forbidden`] — no `prl1p…`
//! collection address, no upstream-pool host, no core IP, no seed/private-key
//! material, and (for a pearlhash lane) only `*.aliceprotocol.org` relay hosts.
//! This is the SAME credit-only / anti-leak gate the bundled `gpu_prl` argv is
//! tested against, enforced at RUNTIME for the custom path (which isn't pinned).

#![allow(dead_code)]

use std::path::PathBuf;

use crate::binaries::MinerKind;
use crate::lane::Lane;
use crate::stats::ParserKind;

/// A known third-party miner FAMILY. It fixes both the standard-stratum argv shape
/// ([`MinerPreset::render_standard`]) and the telemetry parser
/// ([`MinerPreset::parser_kind`]). [`MinerPreset::Template`] means "ignore the
/// family shape, use the user's [`CustomMiner::arg_template`] with placeholders".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinerPreset {
    /// SRBMiner-MULTI (pearlhash). Writes stats to a `--log-file` (needs tail).
    Srbminer,
    /// xmrig / a RandomX miner.
    Xmrig,
    /// T-Rex (KawPoW / GPU).
    Trex,
    /// lolMiner.
    Lolminer,
    /// GMiner.
    Gminer,
    /// NBMiner.
    Nbminer,
    /// alpha-miner (V100/Volta pearlhash).
    AlphaMiner,
    /// A generic stratum miner with a common `-a/-o/-u/-p` arg shape.
    GenericStratum,
    /// Fully custom argv via [`CustomMiner::arg_template`] placeholders.
    Template,
}

impl MinerPreset {
    /// Parse the persisted / CLI token for a preset. Accepts a few friendly aliases
    /// (`t-rex`, `generic`). Returns `None` for an unknown token.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().replace(['-', '_'], "").as_str() {
            "srbminer" | "srb" => Some(MinerPreset::Srbminer),
            "xmrig" => Some(MinerPreset::Xmrig),
            "trex" => Some(MinerPreset::Trex),
            "lolminer" | "lol" => Some(MinerPreset::Lolminer),
            "gminer" => Some(MinerPreset::Gminer),
            "nbminer" => Some(MinerPreset::Nbminer),
            "alphaminer" | "alpha" => Some(MinerPreset::AlphaMiner),
            "genericstratum" | "generic" | "stratum" => Some(MinerPreset::GenericStratum),
            "template" | "custom" => Some(MinerPreset::Template),
            _ => None,
        }
    }

    /// The canonical persisted token (round-trips with [`MinerPreset::parse`]).
    pub fn id(self) -> &'static str {
        match self {
            MinerPreset::Srbminer => "srbminer",
            MinerPreset::Xmrig => "xmrig",
            MinerPreset::Trex => "trex",
            MinerPreset::Lolminer => "lolminer",
            MinerPreset::Gminer => "gminer",
            MinerPreset::Nbminer => "nbminer",
            MinerPreset::AlphaMiner => "alpha-miner",
            MinerPreset::GenericStratum => "generic-stratum",
            MinerPreset::Template => "template",
        }
    }

    /// The telemetry parser for this family. Known families reuse the proven bundled
    /// parser; everything else (incl. `Template`) is honest best-effort
    /// [`ParserKind::Generic`].
    pub fn parser_kind(self) -> ParserKind {
        match self {
            MinerPreset::Srbminer => ParserKind::Srbminer,
            MinerPreset::Xmrig => ParserKind::Xmr,
            MinerPreset::Trex => ParserKind::Kawpow,
            MinerPreset::AlphaMiner => ParserKind::Alpha,
            MinerPreset::Lolminer
            | MinerPreset::Gminer
            | MinerPreset::Nbminer
            | MinerPreset::GenericStratum
            | MinerPreset::Template => ParserKind::Generic,
        }
    }

    /// Whether this family writes its share/hashrate stats ONLY to a log file (so
    /// the supervisor must tail it) rather than stdout. Only SRBMiner does among the
    /// known families; a `Template` inherits the user's explicit `log_file` flag.
    pub fn writes_stats_to_log_file(self) -> bool {
        matches!(self, MinerPreset::Srbminer)
    }

    /// The Alice lane(s) this miner family can realistically serve — used by
    /// auto-detection to only offer a detected miner for a lane it can actually run
    /// (design §3: family→lane compatibility, "不夸大"). The generic/template shapes
    /// are treated as lane-agnostic (the user picks the lane).
    pub fn compatible_lanes(self) -> &'static [Lane] {
        match self {
            MinerPreset::Srbminer => &[Lane::GpuPrl],
            MinerPreset::Xmrig => &[Lane::Xmr],
            MinerPreset::Trex | MinerPreset::Lolminer | MinerPreset::Gminer | MinerPreset::Nbminer => {
                &[Lane::GpuRvn]
            }
            MinerPreset::AlphaMiner => &[Lane::GpuAlpha],
            MinerPreset::GenericStratum | MinerPreset::Template => {
                &[Lane::Xmr, Lane::GpuPrl, Lane::GpuAlpha, Lane::GpuRvn]
            }
        }
    }

    /// Render the STANDARD stratum argv for this family from `ctx`. These shapes are
    /// best-effort — they cover the common invocation of each miner; a miner that
    /// needs an exact custom argv should use [`MinerPreset::Template`]. `Template`
    /// itself is handled by [`CustomMiner::render_args`], never here.
    fn render_standard(self, ctx: &ArgContext) -> Result<Vec<String>, String> {
        let a = ctx;
        let args: Vec<String> = match self {
            MinerPreset::Srbminer => {
                let log = a.require_log_file("srbminer")?;
                vec![
                    "--algorithm".into(),
                    a.algo.clone(),
                    "--pool".into(),
                    a.pool_url.clone(),
                    "--wallet".into(),
                    a.wallet.clone(),
                    "--password".into(),
                    a.password.clone(),
                    "--disable-cpu".into(),
                    "--log-file".into(),
                    log,
                ]
            }
            MinerPreset::Xmrig => vec![
                "-o".into(),
                a.pool_authority.clone(),
                "-u".into(),
                a.wallet.clone(),
                "-p".into(),
                a.password.clone(),
                "-a".into(),
                a.algo.clone(),
            ],
            MinerPreset::Trex => vec![
                "-a".into(),
                a.algo.clone(),
                "-o".into(),
                a.pool_url.clone(),
                "-u".into(),
                a.wallet.clone(),
                "-p".into(),
                a.password.clone(),
            ],
            MinerPreset::Lolminer => vec![
                "--algo".into(),
                a.algo.clone(),
                "--pool".into(),
                a.pool_url.clone(),
                "--user".into(),
                a.wallet.clone(),
                "--pass".into(),
                a.password.clone(),
            ],
            MinerPreset::Gminer => vec![
                "--algo".into(),
                a.algo.clone(),
                "--server".into(),
                a.host.clone(),
                "--port".into(),
                a.port.to_string(),
                "--user".into(),
                a.wallet.clone(),
                "--pass".into(),
                a.password.clone(),
            ],
            MinerPreset::Nbminer => vec![
                "-a".into(),
                a.algo.clone(),
                "-o".into(),
                a.pool_url.clone(),
                "-u".into(),
                a.wallet.clone(),
                "-p".into(),
                a.password.clone(),
            ],
            MinerPreset::AlphaMiner => vec![
                "--algo".into(),
                a.algo.clone(),
                "--pool".into(),
                a.pool_url.clone(),
                "--user".into(),
                a.wallet.clone(),
                "--pass".into(),
                a.password.clone(),
            ],
            MinerPreset::GenericStratum => vec![
                "-a".into(),
                a.algo.clone(),
                "-o".into(),
                a.pool_url.clone(),
                "-u".into(),
                a.wallet.clone(),
                "-p".into(),
                a.password.clone(),
            ],
            MinerPreset::Template => {
                return Err(
                    "internal: the template preset must be rendered from an arg template".into(),
                )
            }
        };
        Ok(args)
    }
}

/// A user-supplied custom miner backend (form A — the CLI fully manages it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomMiner {
    /// Absolute path to the user's miner binary (validated `is_file` + executable;
    /// NOT SHA-pinned — see [`resolve_custom_binary`]).
    pub path: PathBuf,
    /// Which lane this miner runs (decides relay/port/PoP model + algo).
    pub lane: Lane,
    /// The known family (argv shape + parser), or [`MinerPreset::Template`].
    pub preset: MinerPreset,
    /// A fully custom argv with `{POOL}`/`{WALLET}`/… placeholders — used ONLY when
    /// `preset == Template`.
    pub arg_template: Option<Vec<String>>,
    /// Whether this miner writes its stats ONLY to a log file (needs a tail). `true`
    /// automatically for the SRBMiner family; a `Template`/generic miner can set it.
    pub log_file: bool,
    /// The user's explicit "yes, run my own unverified binary" acknowledgement. A
    /// custom binary is refused ([`resolve_custom_binary`]) until this is `true`.
    pub acknowledged_unverified: bool,
}

impl CustomMiner {
    /// Build a [`CustomMiner`] from its persisted [`crate::settings::CustomMinerConfig`],
    /// validating the lane + preset tokens. Returns `Err` for a garbage config (the
    /// caller then falls back to the bundled engine — a broken setting never wedges a
    /// lane silently, it surfaces a clear error at start).
    pub fn from_config(cfg: &crate::settings::CustomMinerConfig) -> Result<Self, String> {
        let lane = parse_lane_token(&cfg.lane)
            .ok_or_else(|| format!("custom miner: unknown lane `{}`", cfg.lane))?;
        let preset = MinerPreset::parse(&cfg.preset)
            .ok_or_else(|| format!("custom miner: unknown preset `{}`", cfg.preset))?;
        if preset == MinerPreset::Template
            && cfg.arg_template.as_ref().map(|t| t.is_empty()).unwrap_or(true)
        {
            return Err(
                "custom miner: the `template` preset needs a non-empty arg template".into(),
            );
        }
        let log_file = cfg.log_file.unwrap_or(false) || preset.writes_stats_to_log_file();
        Ok(CustomMiner {
            path: PathBuf::from(&cfg.path),
            lane,
            preset,
            arg_template: cfg.arg_template.clone(),
            log_file,
            acknowledged_unverified: cfg.acknowledged_unverified,
        })
    }

    /// The configured custom miner for `lane`, if one is persisted AND targets this
    /// lane. `None` when nothing is configured or it targets a different lane (that
    /// lane then uses the bundled engine). A malformed config is treated as "none"
    /// here (the engine surfaces the parse error via [`CustomMiner::from_config`] on
    /// the configured lane only). The lenient variant — the CLI / tests use it.
    pub fn resolve_for_lane(lane: Lane) -> Option<CustomMiner> {
        let cfg = crate::settings::load().custom_miner?;
        let cm = CustomMiner::from_config(&cfg).ok()?;
        (cm.lane == lane).then_some(cm)
    }

    /// Like [`CustomMiner::resolve_for_lane`], but SURFACES a config error when the
    /// persisted custom miner TARGETS `lane` (so the engine fails start with a clear
    /// message rather than silently running the bundled engine on a broken custom
    /// config). A config that targets a DIFFERENT lane — or has an unparseable lane
    /// token — yields `Ok(None)` (that lane cleanly uses the bundled engine).
    pub fn resolve_for_lane_strict(lane: Lane) -> Result<Option<CustomMiner>, String> {
        let Some(cfg) = crate::settings::load().custom_miner else {
            return Ok(None);
        };
        match parse_lane_token(&cfg.lane) {
            Some(l) if l == lane => Ok(Some(CustomMiner::from_config(&cfg)?)),
            _ => Ok(None),
        }
    }

    /// Whether the supervisor must TAIL a log file for this miner's stats.
    pub fn needs_log_tail(&self) -> bool {
        self.log_file
    }

    /// Render the launch argv for this custom miner from `ctx`, then enforce the
    /// honesty gate ([`assert_no_forbidden`]). The `Template` preset substitutes the
    /// user's `arg_template` placeholders; every other preset uses its standard
    /// stratum shape.
    pub fn render_args(&self, ctx: &ArgContext) -> Result<Vec<String>, String> {
        let args = if self.preset == MinerPreset::Template {
            let tpl = self
                .arg_template
                .as_ref()
                .ok_or("internal: template preset with no arg template")?;
            render_template(tpl, ctx)?
        } else {
            self.preset.render_standard(ctx)?
        };
        assert_no_forbidden(&args, self.lane, ctx)?;
        Ok(args)
    }
}

/// All the values a lane's argv is built from — computed by the engine (pool from
/// the active endpoint, wallet = `<alice>.<worker>`, password = the PoP token or
/// `x`, algo per lane, the supervisor-owned log path) and rendered by a
/// [`MinerPreset`] / template. Carries NO secret (the PoP token is a public
/// signature; the seed never reaches here).
#[derive(Debug, Clone)]
pub struct ArgContext {
    /// `host:port` (for miners that take a bare authority).
    pub pool_authority: String,
    /// `stratum+tcp://host:port` (for miners that take a URL).
    pub pool_url: String,
    /// The relay host on its own (for `--server host --port N` style miners).
    pub host: String,
    /// The relay stratum port.
    pub port: u16,
    /// The stratum login user — `<alice_address>.<worker>` (the reward key).
    pub wallet: String,
    /// The stratum password — the PoP token (`pop=<id>:<sig>`) on a pearlhash lane,
    /// else the conventional `x`.
    pub password: String,
    /// The algorithm token (`pearlhash` / `rx/0` / `kawpow`).
    pub algo: String,
    /// The supervisor-owned log path a file-logging miner must write to (`{LOGFILE}`
    /// / `--log-file`). `None` for a stdout miner.
    pub log_file: Option<PathBuf>,
}

impl ArgContext {
    fn log_file_str(&self) -> Option<String> {
        self.log_file.as_ref().map(|p| p.display().to_string())
    }

    fn require_log_file(&self, who: &str) -> Result<String, String> {
        self.log_file_str()
            .ok_or_else(|| format!("internal: the {who} preset needs a supervisor log path"))
    }
}

/// Substitute the argv placeholders in a user template. Recognised placeholders:
/// `{POOL}` `{POOL_AUTHORITY}` `{HOST}` `{PORT}` `{WALLET}` `{PASSWORD}` `{ALGO}`
/// `{LOGFILE}`. A `{LOGFILE}` reference with no supervisor log path is an error
/// (never a literal `{LOGFILE}` passed to the miner). The template MUST include a
/// pool designator (`{POOL}` or `{HOST}`+`{PORT}`) and `{WALLET}` — so the login +
/// relay are always the values WE supply, never a hardcoded foreign wallet/pool.
fn render_template(tpl: &[String], ctx: &ArgContext) -> Result<Vec<String>, String> {
    let joined = tpl.join(" ");
    let has_pool = joined.contains("{POOL}")
        || joined.contains("{POOL_AUTHORITY}")
        || (joined.contains("{HOST}") && joined.contains("{PORT}"));
    if !has_pool {
        return Err(
            "custom miner template must include {POOL} (or {HOST} and {PORT}) so the relay is \
             the one Alice supplies, not a hardcoded pool"
                .into(),
        );
    }
    if !joined.contains("{WALLET}") {
        return Err(
            "custom miner template must include {WALLET} so credit is attributed to YOUR Alice \
             address (never a hardcoded wallet)"
                .into(),
        );
    }
    let mut out = Vec::with_capacity(tpl.len());
    for tok in tpl {
        let mut t = tok.clone();
        if t.contains("{LOGFILE}") {
            let log = ctx
                .log_file_str()
                .ok_or("custom miner template uses {LOGFILE} but this miner has no log path")?;
            t = t.replace("{LOGFILE}", &log);
        }
        t = t
            .replace("{POOL_AUTHORITY}", &ctx.pool_authority)
            .replace("{POOL}", &ctx.pool_url)
            .replace("{HOST}", &ctx.host)
            .replace("{PORT}", &ctx.port.to_string())
            .replace("{WALLET}", &ctx.wallet)
            .replace("{PASSWORD}", &ctx.password)
            .replace("{ALGO}", &ctx.algo);
        // A stray unknown placeholder (`{FOO}`) is a config error — never pass a
        // literal brace token to the miner.
        if let Some(bad) = leftover_placeholder(&t) {
            return Err(format!(
                "custom miner template has an unknown placeholder `{bad}` (valid: {{POOL}} \
                 {{HOST}} {{PORT}} {{WALLET}} {{PASSWORD}} {{ALGO}} {{LOGFILE}})"
            ));
        }
        out.push(t);
    }
    Ok(out)
}

/// The first `{...}` still present after substitution, or `None`.
fn leftover_placeholder(s: &str) -> Option<String> {
    let start = s.find('{')?;
    let end = s[start..].find('}')? + start;
    Some(s[start..=end].to_string())
}

/// Upstream / third-party pool host markers that must NEVER appear in the client
/// argv (the relay forwards to the real upstream server-side; the client only ever
/// sees `*.aliceprotocol.org`). Lower-case substrings.
const UPSTREAM_POOL_MARKERS: &[&str] = &[
    "herominers",
    "supportxmr",
    "kryptex",
    "f2pool",
    "nanopool",
    "2miners",
    "hiveon",
    "unmineable",
    "zergpool",
    "prohashing",
    "flexpool",
    "ethermine",
    "nicehash",
];

/// THE HONESTY GATE for the custom argv (design §2.6 / §7), enforced at RUNTIME (a
/// custom binary isn't SHA-pinned, so this is where the credit-only / anti-leak
/// invariants are held). Rejects, anywhere in the argv:
///   * a `prl1p…` foundation collection/payout address;
///   * an upstream-pool host ([`UPSTREAM_POOL_MARKERS`]) or the doc core IP;
///   * seed / private-key material (`seed` / `priv` / a `0x…` hex blob);
///
/// And, for a pearlhash (PoP) lane, it requires every stratum host to be
/// `*.aliceprotocol.org`. The PoP password (a public signature we minted) is
/// SCRUBBED out of each token before the substring scan so a legitimate base64
/// signature that happens to contain `0x`/`prl1p` can never false-trip the gate;
/// it is separately checked to carry no whitespace/control (an argv-injection
/// guard, mirroring [`crate::lane::gpu_prl`]).
pub fn assert_no_forbidden(args: &[String], lane: Lane, ctx: &ArgContext) -> Result<(), String> {
    // The password rides `--password`/`-p`; it must not smuggle extra argv tokens.
    if ctx
        .password
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err("custom miner: the PoP password contains whitespace/control characters".into());
    }
    for arg in args {
        // Neutralise the (public) PoP password wherever it is embedded, THEN scan —
        // so a base64 signature containing `0x`/`prl1p` never false-positives.
        let scrubbed = if ctx.password.is_empty() {
            arg.clone()
        } else {
            arg.replace(&ctx.password, "")
        };
        let lower = scrubbed.to_ascii_lowercase();
        if lower.contains("prl1p") {
            return Err(format!(
                "custom miner argv leaks a prl1p collection/payout address ({arg}); the relay \
                 assigns collection server-side — remove it"
            ));
        }
        for marker in UPSTREAM_POOL_MARKERS {
            if lower.contains(marker) {
                return Err(format!(
                    "custom miner argv names an upstream pool host `{marker}` ({arg}); point at \
                     the Alice relay only — it forwards upstream server-side"
                ));
            }
        }
        if lower.contains("203.0.113") {
            return Err(format!("custom miner argv leaks a core IP ({arg})"));
        }
        if scrubbed.contains("seed")
            || scrubbed.contains("priv")
            || contains_hex_key(&scrubbed)
        {
            return Err(format!(
                "custom miner argv looks like it carries seed/private-key material ({arg}); a \
                 miner only needs your PUBLIC address — never a key"
            ));
        }
    }
    // Pearlhash (PoP) lanes: every stratum authority must be an Alice relay.
    if lane.is_prl_lane() {
        for arg in args {
            let lower = arg.to_ascii_lowercase();
            let looks_like_host = lower.starts_with("stratum+")
                || (arg == &ctx.pool_url)
                || (arg == &ctx.pool_authority);
            if looks_like_host && !lower.contains("aliceprotocol.org") {
                return Err(format!(
                    "custom miner argv points at a non-Alice relay host ({arg}); a pearlhash lane \
                     must connect only to *.aliceprotocol.org"
                ));
            }
        }
    }
    Ok(())
}

/// A `0x`-prefixed hex blob long enough to be key material (≥ 16 hex chars). A short
/// `0x` (e.g. in a device id) is NOT flagged; a real private key / seed is.
fn contains_hex_key(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    let mut rest = lower.as_str();
    while let Some(idx) = rest.find("0x") {
        let after = &rest[idx + 2..];
        let hexlen = after.chars().take_while(|c| c.is_ascii_hexdigit()).count();
        if hexlen >= 16 {
            return true;
        }
        rest = &rest[idx + 2..];
    }
    false
}

/// Resolve (validate) a custom miner binary path for execution. Unlike the bundled
/// [`crate::binaries::resolve_miner_binary`], this does NO SHA-pin — a custom miner
/// is the user's own. The trust model is an EXPLICIT opt-in ([`CustomMiner::
/// acknowledged_unverified`]) plus a loud, per-start warning. Validates: an ABSOLUTE
/// path, an existing file, and (on Unix) an executable bit.
pub fn resolve_custom_binary(custom: &CustomMiner) -> Result<PathBuf, String> {
    let p = &custom.path;
    if p.as_os_str().is_empty() {
        return Err("custom miner path is empty".into());
    }
    if !p.is_absolute() {
        return Err(format!(
            "custom miner path must be an absolute path (got `{}`)",
            p.display()
        ));
    }
    if !p.is_file() {
        return Err(format!("custom miner binary not found: {}", p.display()));
    }
    if !custom.acknowledged_unverified {
        return Err(format!(
            "refusing to run the custom (unverified) miner at {}: its integrity is NOT checked. \
             Re-run setup and confirm you want to run your own binary (or pass \
             --i-understand-unverified).",
            p.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(p) {
            if meta.permissions().mode() & 0o111 == 0 {
                return Err(format!(
                    "custom miner binary is not executable: {} (chmod +x it)",
                    p.display()
                ));
            }
        }
    }
    eprintln!(
        "[alice-miner] WARNING: running an UNVERIFIED custom miner from {}. Its integrity is not \
         checked against any signed release — only do this with a binary you trust.",
        p.display()
    );
    Ok(p.clone())
}

/// Map a lane token to a [`Lane`] for the custom-miner config (accepts the same
/// tokens as the CLI `--lane`).
fn parse_lane_token(s: &str) -> Option<Lane> {
    match s.trim().to_ascii_lowercase().as_str() {
        "xmr" | "cpu" => Some(Lane::Xmr),
        "prl" | "gpu" => Some(Lane::GpuPrl),
        "alpha" => Some(Lane::GpuAlpha),
        "rvn" => Some(Lane::GpuRvn),
        _ => None,
    }
}

/// The MINER backend a lane runs — a bundled SHA-pinned engine or a user-supplied
/// custom binary. (The engine dispatches its `RebuildFn` on this.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MinerBackend {
    /// The official SHA-pinned engine for a kind ([`crate::binaries`]).
    Bundled(MinerKind),
    /// A user-supplied, possibly closed-source miner (form A).
    Custom(CustomMiner),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(lane: Lane, password: &str, log: Option<&str>) -> ArgContext {
        ArgContext {
            pool_authority: "us.aliceprotocol.org:3340".into(),
            pool_url: "stratum+tcp://us.aliceprotocol.org:3340".into(),
            host: "us.aliceprotocol.org".into(),
            port: 3340,
            wallet: "a2uJXaVk7Zx4fgk9aRLnhiD2RdpAP4usJxKXpN4vh4hDNoP1C.rig1".into(),
            password: password.into(),
            algo: match lane {
                Lane::GpuPrl | Lane::GpuAlpha => "pearlhash".into(),
                Lane::Xmr => "rx/0".into(),
                Lane::GpuRvn => "kawpow".into(),
            },
            log_file: log.map(PathBuf::from),
        }
    }

    fn custom(preset: MinerPreset, lane: Lane, tpl: Option<Vec<String>>, log_file: bool) -> CustomMiner {
        CustomMiner {
            path: PathBuf::from("/opt/my-miner"),
            lane,
            preset,
            arg_template: tpl,
            log_file,
            acknowledged_unverified: true,
        }
    }

    #[test]
    fn preset_parse_roundtrip() {
        for p in [
            MinerPreset::Srbminer,
            MinerPreset::Xmrig,
            MinerPreset::Trex,
            MinerPreset::Lolminer,
            MinerPreset::Gminer,
            MinerPreset::Nbminer,
            MinerPreset::AlphaMiner,
            MinerPreset::GenericStratum,
            MinerPreset::Template,
        ] {
            assert_eq!(MinerPreset::parse(p.id()), Some(p), "roundtrip {}", p.id());
        }
        // Aliases.
        assert_eq!(MinerPreset::parse("SRB"), Some(MinerPreset::Srbminer));
        assert_eq!(MinerPreset::parse("t-rex"), Some(MinerPreset::Trex));
        assert_eq!(MinerPreset::parse("generic"), Some(MinerPreset::GenericStratum));
        assert_eq!(MinerPreset::parse("nonsense"), None);
    }

    #[test]
    fn preset_parser_kinds_map_known_families() {
        assert_eq!(MinerPreset::Srbminer.parser_kind(), ParserKind::Srbminer);
        assert_eq!(MinerPreset::Xmrig.parser_kind(), ParserKind::Xmr);
        assert_eq!(MinerPreset::Trex.parser_kind(), ParserKind::Kawpow);
        assert_eq!(MinerPreset::AlphaMiner.parser_kind(), ParserKind::Alpha);
        // Unknown-shape families fall to the honest generic parser.
        assert_eq!(MinerPreset::Gminer.parser_kind(), ParserKind::Generic);
        assert_eq!(MinerPreset::Template.parser_kind(), ParserKind::Generic);
    }

    #[test]
    fn srbminer_custom_argv_matches_the_canonical_shape() {
        let cm = custom(MinerPreset::Srbminer, Lane::GpuPrl, None, true);
        let c = ctx(Lane::GpuPrl, "pop=ch:c2ln", Some("/tmp/alice-custom.log"));
        let args = cm.render_args(&c).expect("render");
        // Same pearlhash / pool / wallet / password / log-file shape as the bundled
        // SRBMiner builder — only the binary differs.
        let j = args.join(" ");
        assert!(j.contains("--algorithm pearlhash"));
        assert!(j.contains("--pool stratum+tcp://us.aliceprotocol.org:3340"));
        assert!(j.contains(&format!("--wallet {}", c.wallet)));
        assert!(j.contains("--password pop=ch:c2ln"));
        assert!(j.contains("--log-file /tmp/alice-custom.log"));
    }

    #[test]
    fn template_substitutes_placeholders_and_keeps_attribution() {
        let tpl = vec![
            "--url".into(),
            "{POOL}".into(),
            "--user".into(),
            "{WALLET}".into(),
            "--pass".into(),
            "{PASSWORD}".into(),
            "--algo".into(),
            "{ALGO}".into(),
        ];
        let cm = custom(MinerPreset::Template, Lane::GpuPrl, Some(tpl), false);
        let c = ctx(Lane::GpuPrl, "pop=abc:def", None);
        let args = cm.render_args(&c).expect("render");
        assert_eq!(args[1], "stratum+tcp://us.aliceprotocol.org:3340");
        assert_eq!(args[3], c.wallet); // reward attribution preserved
        assert_eq!(args[5], "pop=abc:def");
        assert_eq!(args[7], "pearlhash");
    }

    #[test]
    fn template_requires_wallet_and_pool_placeholders() {
        // A template that hardcodes a foreign wallet (no {WALLET}) is rejected.
        let tpl = vec!["-o".into(), "{POOL}".into(), "-u".into(), "someoneElse".into()];
        let cm = custom(MinerPreset::Template, Lane::GpuPrl, Some(tpl), false);
        let err = cm.render_args(&ctx(Lane::GpuPrl, "pop=a:b", None)).unwrap_err();
        assert!(err.contains("{WALLET}"), "got: {err}");
        // A template with no pool designator is rejected.
        let tpl2 = vec!["-u".into(), "{WALLET}".into()];
        let cm2 = custom(MinerPreset::Template, Lane::GpuPrl, Some(tpl2), false);
        assert!(cm2.render_args(&ctx(Lane::GpuPrl, "pop=a:b", None)).is_err());
    }

    #[test]
    fn template_unknown_placeholder_is_rejected() {
        let tpl = vec!["-o".into(), "{POOL}".into(), "-u".into(), "{WALLET}".into(), "{BOGUS}".into()];
        let cm = custom(MinerPreset::Template, Lane::GpuPrl, Some(tpl), false);
        let err = cm.render_args(&ctx(Lane::GpuPrl, "pop=a:b", None)).unwrap_err();
        assert!(err.contains("{BOGUS}"), "got: {err}");
    }

    #[test]
    fn honesty_gate_rejects_prl1p_upstream_and_seed() {
        // A hardcoded prl1p collection address in a template literal.
        let tpl = vec!["-o".into(), "{POOL}".into(), "-u".into(), "{WALLET}".into(), "--donate".into(), "prl1pcollectionXXXX".into()];
        let cm = custom(MinerPreset::Template, Lane::GpuPrl, Some(tpl), false);
        assert!(cm.render_args(&ctx(Lane::GpuPrl, "pop=a:b", None)).unwrap_err().contains("prl1p"));

        // A hardcoded upstream pool host (keeps {POOL}+{WALLET} so the earlier
        // structural checks pass and the upstream-host check is what fires).
        let tpl2: Vec<String> = vec!["-o".into(), "{POOL}".into(), "-x".into(), "herominers.com".into(), "-u".into(), "{WALLET}".into()];
        let cm2 = custom(MinerPreset::Template, Lane::GpuPrl, Some(tpl2), false);
        assert!(cm2.render_args(&ctx(Lane::GpuPrl, "pop=a:b", None)).unwrap_err().to_lowercase().contains("herominers"));

        // Seed material in a literal.
        let tpl3 = vec!["-o".into(), "{POOL}".into(), "-u".into(), "{WALLET}".into(), "--seed".into(), "abandon abandon".into()];
        let cm3 = custom(MinerPreset::Template, Lane::GpuPrl, Some(tpl3), false);
        assert!(cm3.render_args(&ctx(Lane::GpuPrl, "pop=a:b", None)).is_err());
    }

    #[test]
    fn honesty_gate_pearlhash_requires_alice_relay() {
        // A template pointing at a non-Alice stratum host on a pearlhash lane.
        let tpl = vec!["-o".into(), "stratum+tcp://evil.example:3340".into(), "-u".into(), "{WALLET}".into(), "{POOL}".into()];
        let cm = custom(MinerPreset::Template, Lane::GpuPrl, Some(tpl), false);
        let err = cm.render_args(&ctx(Lane::GpuPrl, "pop=a:b", None)).unwrap_err();
        assert!(err.to_lowercase().contains("aliceprotocol.org"), "got: {err}");
    }

    #[test]
    fn honesty_gate_password_with_0x_base64_does_not_false_trip() {
        // A realistic-ish PoP token whose base64 signature contains "0x…" must NOT be
        // read as key material (it's scrubbed before the scan).
        let token = "pop=ch7:AbC0xdeadbeefdeadbeef0123456789";
        let cm = custom(MinerPreset::Srbminer, Lane::GpuPrl, None, true);
        let args = cm
            .render_args(&ctx(Lane::GpuPrl, token, Some("/tmp/x.log")))
            .expect("a base64 password with 0x must not false-trip the seed gate");
        assert!(args.join(" ").contains(token));
    }

    #[test]
    fn password_with_whitespace_is_rejected() {
        let cm = custom(MinerPreset::Srbminer, Lane::GpuPrl, None, true);
        let err = cm
            .render_args(&ctx(Lane::GpuPrl, "pop=ch: injected --extra", Some("/tmp/x.log")))
            .unwrap_err();
        assert!(err.to_lowercase().contains("whitespace"), "got: {err}");
    }

    #[test]
    fn from_config_parses_and_defaults_log_file_for_srbminer() {
        let cfg = crate::settings::CustomMinerConfig {
            path: "/opt/srb".into(),
            lane: "prl".into(),
            preset: "srbminer".into(),
            arg_template: None,
            log_file: None,
            acknowledged_unverified: true,
        };
        let cm = CustomMiner::from_config(&cfg).unwrap();
        assert_eq!(cm.lane, Lane::GpuPrl);
        assert_eq!(cm.preset, MinerPreset::Srbminer);
        assert!(cm.needs_log_tail(), "srbminer always needs a log tail");
    }

    #[test]
    fn from_config_rejects_template_without_args() {
        let cfg = crate::settings::CustomMinerConfig {
            path: "/opt/m".into(),
            lane: "prl".into(),
            preset: "template".into(),
            arg_template: None,
            log_file: None,
            acknowledged_unverified: true,
        };
        assert!(CustomMiner::from_config(&cfg).is_err());
    }

    #[test]
    fn resolve_custom_binary_refuses_without_acknowledgement() {
        // A real, existing file but NOT acknowledged → refused.
        let tmp = std::env::temp_dir().join(format!("alice-custom-{}", std::process::id()));
        std::fs::write(&tmp, b"#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&tmp).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&tmp, perm).unwrap();
        }
        let mut cm = custom(MinerPreset::GenericStratum, Lane::GpuPrl, None, false);
        cm.path = tmp.clone();
        cm.acknowledged_unverified = false;
        assert!(resolve_custom_binary(&cm).unwrap_err().contains("unverified"));
        cm.acknowledged_unverified = true;
        assert_eq!(resolve_custom_binary(&cm).unwrap(), tmp);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn resolve_custom_binary_rejects_relative_and_missing() {
        let mut cm = custom(MinerPreset::GenericStratum, Lane::GpuPrl, None, false);
        cm.path = PathBuf::from("relative/miner");
        assert!(resolve_custom_binary(&cm).unwrap_err().contains("absolute"));
        cm.path = PathBuf::from("/no/such/alice/custom/miner");
        assert!(resolve_custom_binary(&cm).unwrap_err().contains("not found"));
    }

    #[test]
    fn contains_hex_key_needs_a_long_blob() {
        assert!(contains_hex_key("0xdeadbeefdeadbeef00")); // >=16 hex
        assert!(!contains_hex_key("device0x1")); // short
        assert!(!contains_hex_key("no hex here"));
    }
}
