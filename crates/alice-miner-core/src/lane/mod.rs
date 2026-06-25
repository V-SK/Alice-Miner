//! `core/lane` — the per-lane launch-plan builders. M1 ships only the CPU-XMR
//! lane ([`xmr`]); the GPU-RVN (KawPoW) lane is M3. Each lane owns its own
//! verbatim-ported argv builder, address validation, and (later) log parsers.

pub mod gpu_prl;
pub mod gpu_rvn;
pub mod xmr;

/// Which mining lane a [`crate::engine::Command::Start`] selects. CPU→XMR (the
/// proven path), GPU→PRL (SRBMiner pearlhash — the **GPU mainline**, PoP-gated,
/// region relays `:3340`), and GPU→RVN (KawPoW, the earlier relay path, kept).
/// `Ord`/`Hash` are derived so the lane can key the viability matrix's `BTreeMap`
/// (see [`crate::detect::capability`]).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Lane {
    /// CPU RandomX/XMR against `hk.aliceprotocol.org:3333` (the proven path).
    Xmr,
    /// GPU pearlhash/PRL against the region relays `:3340` with mandatory M4 PoP —
    /// the GPU **mainline** (V: "GPU 主线 = PRL,展示不隐藏").
    GpuPrl,
    /// NVIDIA-GPU KawPoW/RVN against `hk.aliceprotocol.org:8888` (the earlier path).
    GpuRvn,
}

impl Lane {
    pub fn label(self) -> &'static str {
        match self {
            Lane::Xmr => "CPU · XMR",
            Lane::GpuPrl => "GPU · PRL",
            Lane::GpuRvn => "GPU · RVN",
        }
    }

    /// Lower-case lane id used on the CLI and in `Snapshot` JSON.
    pub fn id(self) -> &'static str {
        match self {
            Lane::Xmr => "xmr",
            Lane::GpuPrl => "prl",
            Lane::GpuRvn => "gpu",
        }
    }
}

/// Which physical GPU(s) a GPU lane should run on (multi-GPU scheduling, A5b).
///
/// **`All` is the default and preserves the existing single-/multi-card behavior
/// BYTE-FOR-BYTE**: when a GPU lane is built with [`GpuSelection::All`] the argv
/// is identical to the pre-A5b argv (SRBMiner / kawpowminer / T-Rex all default
/// to "use every detected card" when no device-selection flag is present). The
/// per-card restriction is therefore a purely **opt-in** addition — passing
/// `--gpus 0,1` (CLI) selects [`GpuSelection::Ids`] and appends the miner's
/// device-selection flag; passing nothing leaves `All` and changes no argv.
///
/// Credit-only / honesty: GPU selection only touches the device-index argv; it
/// adds no endpoint, address, or secret, so the per-lane honesty gate is intact.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuSelection {
    /// Use every detected card (the default — argv is unchanged vs. pre-A5b).
    #[default]
    All,
    /// Restrict the lane to these 0-based device indices (in the given order).
    Ids(Vec<u32>),
}

impl GpuSelection {
    /// Parse a CLI `--gpus` value (a comma-separated list of 0-based device
    /// indices, e.g. `0,1,2`) into a [`GpuSelection`]. An empty / whitespace-only
    /// string is **rejected** (the caller should simply omit the flag to get
    /// [`GpuSelection::All`] rather than pass an empty list). Malformed input
    /// (non-numeric token, duplicate index) is an error so a typo can never
    /// silently degrade to "all cards" or a wrong card-set.
    ///
    /// Returns the parsed indices in the user-supplied order (so the user can
    /// control the miner's primary device order); duplicates are rejected.
    pub fn parse_ids(s: &str) -> Result<Self, String> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err("--gpus needs at least one device index (e.g. --gpus 0,1); \
                        omit the flag entirely to use all cards"
                .into());
        }
        let mut ids: Vec<u32> = Vec::new();
        for tok in trimmed.split(',') {
            let tok = tok.trim();
            if tok.is_empty() {
                return Err(format!(
                    "--gpus has an empty index in `{s}` (use a plain comma-separated list, e.g. 0,1,2)"
                ));
            }
            let id: u32 = tok.parse().map_err(|_| {
                format!("--gpus index `{tok}` is not a non-negative integer (e.g. --gpus 0,1,2)")
            })?;
            if ids.contains(&id) {
                return Err(format!("--gpus lists device {id} more than once"));
            }
            ids.push(id);
        }
        Ok(GpuSelection::Ids(ids))
    }

    /// The comma-separated index list (`"0,1,2"`) for the miner device-selection
    /// flag value; `None` for [`GpuSelection::All`] (no flag appended at all).
    pub fn csv(&self) -> Option<String> {
        match self {
            GpuSelection::All => None,
            GpuSelection::Ids(ids) => Some(
                ids.iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        }
    }
}

#[cfg(test)]
mod gpu_selection_tests {
    use super::*;

    #[test]
    fn default_is_all_and_appends_no_flag_value() {
        assert_eq!(GpuSelection::default(), GpuSelection::All);
        assert_eq!(GpuSelection::All.csv(), None);
    }

    #[test]
    fn parse_ids_accepts_comma_list_in_order() {
        assert_eq!(
            GpuSelection::parse_ids("0,1,2").unwrap(),
            GpuSelection::Ids(vec![0, 1, 2])
        );
        // Whitespace around tokens is tolerated; order is preserved (2 first).
        assert_eq!(
            GpuSelection::parse_ids(" 2, 0 ").unwrap(),
            GpuSelection::Ids(vec![2, 0])
        );
        assert_eq!(
            GpuSelection::Ids(vec![0, 1, 2]).csv().as_deref(),
            Some("0,1,2")
        );
    }

    #[test]
    fn parse_ids_rejects_malformed_input() {
        // Empty / whitespace-only → error (omit the flag for All instead).
        assert!(GpuSelection::parse_ids("").is_err());
        assert!(GpuSelection::parse_ids("   ").is_err());
        // Non-numeric / negative / float tokens.
        assert!(GpuSelection::parse_ids("a").is_err());
        assert!(GpuSelection::parse_ids("0,x,2").is_err());
        assert!(GpuSelection::parse_ids("-1").is_err());
        assert!(GpuSelection::parse_ids("0.5").is_err());
        // Empty index in the middle / trailing comma.
        assert!(GpuSelection::parse_ids("0,,2").is_err());
        assert!(GpuSelection::parse_ids("0,1,").is_err());
        // Duplicate index.
        assert!(GpuSelection::parse_ids("0,1,0").is_err());
    }
}
