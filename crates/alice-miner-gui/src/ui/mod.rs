//! UI module — theme, centralized strings, monoline icons, the Alice Core hero,
//! shared widgets, and the screens (onboarding / home / dashboard), plus the
//! window chrome (titlebar + left icon rail) in [`shell`].

pub mod change_addr;
pub mod chrome;
pub mod dashboard;
pub mod hero;
pub mod home;
pub mod icons;
pub mod onboarding;
pub mod prl_unlock;
pub mod strings;
pub mod theme;
pub mod widgets;

use alice_miner_core::Lane;
use eframe::egui::Color32;

/// UI presentation for a mining [`Lane`]: the chip label (`XMR · RandomX` /
/// `RVN · KawPoW`), the role sub-line, and the accent colour (matching
/// `mine.html`: XMR orange, GPU blue — kept in one place so Home + Dashboard +
/// Settings never disagree).
pub fn lane_chip_label(lane: Lane) -> &'static str {
    match lane {
        Lane::Xmr => "XMR · RandomX",
        // The two pearlhash GPU lanes are a CHOICE on a Turing+ NVIDIA box — they
        // earn the SAME reward, differing only by engine + relay. PRL = SRBMiner →
        // herominers relay; Alpha = AlphaMiner → AlphaPool relay (and the only GPU
        // option on Volta/V100, where SRBMiner can't run). The Alpha label no longer
        // reads "(V100)" since it's now a general engine pick, not Volta-only.
        Lane::GpuPrl => "PRL · pearlhash",
        Lane::GpuAlpha => "Alpha · pearlhash (AlphaPool)",
        Lane::GpuRvn => "RVN · KawPoW",
    }
}

/// The lane's accent colour (the `mine.html` lane palette).
pub fn lane_accent(lane: Lane) -> Color32 {
    match lane {
        Lane::Xmr => theme::THEME.lane_xmr,
        // All GPU lanes share the GPU accent.
        Lane::GpuPrl => theme::THEME.lane_gpu,
        Lane::GpuAlpha => theme::THEME.lane_gpu,
        Lane::GpuRvn => theme::THEME.lane_gpu,
    }
}
