//! `alice-miner guide` — the help-me-choose advisor (Theme: miner onboarding).
//!
//! A read-only, script-friendly ADVISOR that answers "what should I mine, and how
//! do I connect?" in one screen:
//!
//!   1. detect the hardware (CPU / GPU model + vendor) — the SAME fail-safe
//!      [`CapabilityProfile`] probe the GUI / `detect` / `start` use, so the guide
//!      can never disagree with what actually runs;
//!   2. recommend a lane (GPU → PRL or Alpha; CPU → XMR) with ONE sentence of why;
//!   3. give the next step TWO ways:
//!        * mine with the OFFICIAL bundled client (`setup` / `start`), or
//!        * bring your OWN third-party pearlhash/RandomX miner — the exact stratum
//!          connection parameters (host, port, algorithm, login), and — for the
//!          PoP-gated pearlhash lanes — a pointer at `alice-miner companion`, which
//!          holds the possession proof so the private key never leaves this box.
//!
//! The guide is DISTINCT from the `setup` wizard: `setup` walks you through
//! creating/pasting an address and starts mining; `guide` only EXPLAINS the lane
//! choice + connection surface (so it needs no identity and writes nothing). It is
//! deliberately non-interactive (pure print; `--json` for the website) so it drops
//! into a script or a docs page unchanged.
//!
//! ── CREDIT-ONLY / honesty ────────────────────────────────────────────────────
//! Every user string goes through `tr!` and carries NO fiat / earnings promise
//! (`$`/`paid`/`earned`/…). It shows only PUBLIC Alice relay hosts (never the
//! foundation collection address, an upstream pool, or the core IP) and describes
//! rewards only as credit (积分, credit-only), matching the rest of the CLI.

use alice_miner_core::lane::{gpu_alpha, gpu_prl, gpu_rvn, xmr};
use alice_miner_core::tr;
use alice_miner_core::{CapabilityProfile, Lane};

use crate::EXIT_OK;

/// The bring-your-own stratum connection surface for a lane — the exact knobs a
/// third-party miner (SRBMiner, XMRig, …) needs. PUBLIC values only (the relay
/// hosts are shown openly; no collection address / upstream / core IP).
struct ByoConnection {
    /// The miner's `--algorithm` token (e.g. `pearlhash`, `rx/0`).
    algorithm: &'static str,
    /// The region relay hosts to point at (US-first), each on [`Self::port`].
    hosts: Vec<&'static str>,
    /// The client-facing stratum port on those hosts.
    port: u16,
    /// Whether this lane is PoP-gated (`REQUIRE_POP=1`) and therefore needs the
    /// companion to hold the possession proof for a bring-your-own miner. `false`
    /// for the open-enrollment XMR/RVN relays (a plain `x` password is accepted).
    needs_companion: bool,
    /// The `companion --lane` token to run for a PoP-gated lane (empty otherwise).
    companion_lane: &'static str,
}

/// Resolve the bring-your-own connection surface for `lane`. Pure — every value is
/// a compile-time relay constant, so this is fully testable without a device.
fn byo_connection(lane: Lane) -> ByoConnection {
    match lane {
        Lane::GpuPrl => ByoConnection {
            algorithm: "pearlhash",
            hosts: gpu_prl::REGION_HOSTS.iter().map(|(_, h)| *h).collect(),
            port: gpu_prl::GPU_RELAY_PORT,
            needs_companion: true,
            companion_lane: "prl",
        },
        Lane::GpuAlpha => ByoConnection {
            algorithm: "pearlhash",
            hosts: gpu_prl::REGION_HOSTS.iter().map(|(_, h)| *h).collect(),
            port: gpu_alpha::ALPHA_RELAY_PORT,
            needs_companion: true,
            companion_lane: "alpha",
        },
        // XMR / RVN are open-enrollment relays (no PoP): a bring-your-own miner logs
        // in with a plain `x` password. `rx/0` is RandomX's canonical algo token.
        Lane::Xmr => ByoConnection {
            algorithm: "rx/0",
            hosts: vec![xmr::ALICE_POOL_HOST],
            port: xmr::ALICE_POOL_PORT,
            needs_companion: false,
            companion_lane: "",
        },
        Lane::GpuRvn => ByoConnection {
            algorithm: "kawpow",
            // The RVN relay constants (host/port live in the lane module — don't
            // hardcode 8888 here or the two can drift).
            hosts: vec![gpu_rvn::ALICE_POOL_HOST],
            port: gpu_rvn::ALICE_POOL_PORT,
            needs_companion: false,
            companion_lane: "",
        },
    }
}

/// One honest sentence explaining WHY `lane` fits this device (bilingual). Keyed on
/// the lane; the caller only calls it for the recommended lane, so the copy speaks
/// to the device class that produced that recommendation.
fn lane_why(lane: Lane) -> &'static str {
    match lane {
        Lane::GpuPrl => tr!(
            "Your GPU can run SRBMiner pearlhash — the GPU mainline. Shares are credited to your \
             own Alice address via a per-connection possession proof.",
            "你的 GPU 可以运行 SRBMiner pearlhash —— GPU 主线。份额通过每连接的所有权证明,\
             归属到你自己的 Alice 地址(记为积分)。"
        ),
        Lane::GpuAlpha => tr!(
            "Your Volta-class NVIDIA GPU can't run SRBMiner, so AlphaMiner pearlhash is the GPU \
             path here — same possession proof, same credit ledger.",
            "你的 Volta 架构 NVIDIA GPU 无法运行 SRBMiner,所以这里的 GPU 路径是 AlphaMiner \
             pearlhash —— 相同的所有权证明,相同的积分账本。"
        ),
        Lane::Xmr => tr!(
            "Every CPU can run RandomX, so the CPU-XMR lane works on any device — no GPU needed.",
            "每台设备的 CPU 都能运行 RandomX,所以 CPU-XMR 通道在任何设备上都可用 —— 无需 GPU。"
        ),
        Lane::GpuRvn => tr!(
            "The RVN (KawPoW) lane is the earlier NVIDIA path — the pearlhash lanes are the mainline today.",
            "RVN (KawPoW) 通道是较早的 NVIDIA 路径 —— 如今 pearlhash 通道才是主线。"
        ),
    }
}

/// The login-name shape for a lane's stratum auth: `<your-alice-address>.<device>`
/// for the pearlhash lanes (the worker suffix is the PoP device id), or
/// `<your-alice-address>.<worker>` for the open XMR/RVN relays.
fn login_shape(lane: Lane) -> &'static str {
    if lane.is_prl_lane() {
        tr!("<your-alice-address>.<device>", "<你的-alice-地址>.<设备名>")
    } else {
        tr!("<your-alice-address>.<worker>", "<你的-alice-地址>.<worker>")
    }
}

/// Run `alice-miner guide`. Never touches identity/keystore/network and writes
/// nothing — a pure advisor. Returns [`EXIT_OK`].
pub fn run(json: bool) -> i32 {
    let cap = CapabilityProfile::detect();
    if json {
        println!("{}", render_json(&cap));
    } else {
        print!("{}", render_human(&cap));
    }
    EXIT_OK
}

/// The human-readable advisor screen (bilingual). Returns the full body so it is
/// unit-testable without capturing stdout.
fn render_human(cap: &CapabilityProfile) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let rec = cap.recommended_lane();

    let _ = writeln!(out, "\n{}", tr!("Alice Miner — help me choose", "Alice Miner —— 帮我选择"));
    let _ = writeln!(out, "{}", "─".repeat(56));

    // (1) What we detected.
    let _ = writeln!(out, "{}: {}", tr!("Device", "设备"), cap.profile.display);
    let gpu = &cap.profile.gpu;
    let gpu_line = if gpu.model.is_empty() {
        tr!("no dedicated GPU detected", "未检测到独立 GPU").to_string()
    } else {
        format!("{} ({})", gpu.model, gpu.vendor.label())
    };
    let _ = writeln!(out, "{}:    {}", tr!("GPU", "显卡"), gpu_line);

    // (2) Recommendation + one-sentence why.
    let _ = writeln!(
        out,
        "\n{}: {} ({})",
        tr!("Recommended lane", "推荐通道"),
        rec.label(),
        rec.cli_lane_arg()
    );
    let _ = writeln!(out, "  {}", lane_why(rec));

    // The other runnable lanes, so the user knows the alternatives.
    let others: Vec<Lane> = cap
        .viability
        .runnable_lanes()
        .into_iter()
        .filter(|&l| l != rec)
        .collect();
    if !others.is_empty() {
        let list = others
            .iter()
            .map(|l| format!("{} ({})", l.label(), l.cli_lane_arg()))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(out, "  {}: {list}", tr!("also runnable", "也可运行"));
    }

    // (2b) The viability notes. These were computed by `derive_lane_viability` and
    // then rendered NOWHERE — which is how an honest "this card cannot mine this
    // lane" explanation could exist in the matrix and still never reach a miner.
    // They carry the AMD RDNA2 verdict, so they are printed here.
    if !cap.viability.notes.is_empty() {
        let _ = writeln!(out);
        for note in &cap.viability.notes {
            let _ = writeln!(out, "  {} {note}", tr!("Note:", "注意:"));
        }
    }

    // (3a) Next step — the bundled official client.
    let _ = writeln!(out, "\n{}", tr!("Next step — mine with the official client:", "下一步 —— 使用官方客户端挖矿:"));
    let _ = writeln!(
        out,
        "  {}   alice-miner setup",
        tr!("guided one-time setup:", "一次性引导安装:")
    );
    let _ = writeln!(
        out,
        "  {}       alice-miner start --lane {}",
        tr!("or start directly:", "或直接开始:"),
        rec.cli_lane_arg()
    );

    // (3b) Next step — bring your OWN (third-party) miner.
    let conn = byo_connection(rec);
    let _ = writeln!(
        out,
        "\n{}",
        tr!(
            "Next step — bring your OWN miner (third-party, e.g. a closed-source rig):",
            "下一步 —— 使用你自己的矿机(第三方,例如闭源矿机):"
        )
    );
    let host_list = conn.hosts.join(" / ");
    let _ = writeln!(out, "  {}:  {} : {}", tr!("pool (any region)", "矿池(任一区域)"), host_list, conn.port);
    let _ = writeln!(out, "  {}: {}", tr!("algorithm", "算法"), conn.algorithm);
    let _ = writeln!(out, "  {}:     {}", tr!("login (user)", "登录名(用户)"), login_shape(rec));
    if conn.needs_companion {
        let _ = writeln!(
            out,
            "  {}:  {}",
            tr!("password", "密码"),
            tr!("anything — authorization is out-of-band (see below)", "任意值 —— 授权在带外完成(见下)")
        );
        let _ = writeln!(
            out,
            "\n  {}",
            tr!(
                "This lane needs a possession proof. Keep it live WITHOUT exposing your key:",
                "此通道需要所有权证明。在不泄露密钥的情况下保持其有效:"
            )
        );
        let _ = writeln!(out, "    alice-miner companion --lane {}", conn.companion_lane);
        let _ = writeln!(
            out,
            "  {}",
            tr!(
                "It signs the proof locally on a refresh loop; your private key never touches the rig.",
                "它在本机按刷新周期签署证明;你的私钥绝不接触矿机。"
            )
        );
    } else {
        let _ = writeln!(
            out,
            "  {}:  {}",
            tr!("password", "密码"),
            tr!("x (open enrollment — no proof needed)", "x(开放注册 —— 无需证明)")
        );
    }

    let _ = writeln!(
        out,
        "\n{}\n",
        tr!(
            "Rewards accrue as credit (积分, credit-only). No difficulty to set — the server matches the workload to your device.",
            "奖励以积分形式累积(credit-only)。无需设置难度 —— 服务端会自动把工作量匹配到你的设备。"
        )
    );
    out
}

/// The `--json` advisor object (for the website / a script). Machine-clean: the
/// device summary, the recommended + runnable lanes, and the bring-your-own
/// connection surface. Credit-only — no fiat / payout figure.
fn render_json(cap: &CapabilityProfile) -> String {
    let rec = cap.recommended_lane();
    let conn = byo_connection(rec);
    let runnable: Vec<&str> = cap
        .viability
        .runnable_lanes()
        .iter()
        .map(|l| l.cli_lane_arg())
        .collect();
    let obj = serde_json::json!({
        "device": cap.profile.display,
        "cpu_model": cap.profile.cpu_model,
        "gpu_vendor": cap.profile.gpu.vendor.label(),
        "gpu_model": cap.profile.gpu.model,
        "recommended_lane": rec.cli_lane_arg(),
        "runnable_lanes": runnable,
        "bring_your_own": {
            "algorithm": conn.algorithm,
            "hosts": conn.hosts,
            "port": conn.port,
            "login": login_shape(rec),
            "needs_companion": conn.needs_companion,
            "companion_lane": conn.companion_lane,
        },
    });
    serde_json::to_string_pretty(&obj).unwrap_or_else(|_| "{}".to_string())
}

/// Whether `lane` is the one the guide would recommend for a device whose GPU has
/// the given [`LaneSupport`] for the pearlhash lanes — a tiny helper the tests use
/// to assert the recommendation tracks the viability matrix (the guide never
/// re-implements the recommendation; it reads `cap.recommended_lane()`). Present so
/// the mapping is documented + guarded in one place.
#[cfg(test)]
fn recommends(cap: &CapabilityProfile) -> Lane {
    cap.recommended_lane()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alice_miner_core::detect::{DeviceProfile, GpuInfo, GpuVendor, OsFamily};
    use alice_miner_core::i18n::{self, Lang};

    fn profile_with(os: OsFamily, apple_silicon: bool, gpu: GpuInfo) -> DeviceProfile {
        DeviceProfile {
            os,
            arch: if apple_silicon { "aarch64".into() } else { "x86_64".into() },
            apple_silicon,
            logical_cores: 8,
            cpu_model: "Test CPU".into(),
            gpu,
            memory_gb: 32,
            display: "Test CPU · 8 cores".into(),
            warnings: vec![],
            amd_gpu_pci_ids: Vec::new(),
        }
    }

    fn cap_for(profile: DeviceProfile) -> CapabilityProfile {
        CapabilityProfile {
            viability: alice_miner_core::detect::capability::derive_lane_viability(&profile),
            profile,
        }
    }

    fn nvidia_ampere() -> CapabilityProfile {
        cap_for(profile_with(
            OsFamily::Linux,
            false,
            GpuInfo {
                vendor: GpuVendor::Nvidia,
                model: "NVIDIA GeForce RTX 3090".into(),
                vram_gb: 24,
                gpus: Vec::new(),
                max_compute_cap_x10: Some(86),
            },
        ))
    }

    fn nvidia_volta() -> CapabilityProfile {
        cap_for(profile_with(
            OsFamily::Linux,
            false,
            GpuInfo {
                vendor: GpuVendor::Nvidia,
                model: "Tesla V100-PCIE-16GB".into(),
                vram_gb: 16,
                gpus: Vec::new(),
                max_compute_cap_x10: Some(70),
            },
        ))
    }

    /// An AMD box carrying the given PCI device ids — the input that decides
    /// whether GPU-PRL is offered at all (SRBMiner dropped RDNA2 in 3.5.0).
    fn amd_with_ids(model: &str, ids: &[u16]) -> CapabilityProfile {
        let mut p = profile_with(
            OsFamily::Linux,
            false,
            GpuInfo { vendor: GpuVendor::Amd, model: model.into(), vram_gb: 0, gpus: Vec::new(), max_compute_cap_x10: None },
        );
        p.amd_gpu_pci_ids = ids.to_vec();
        cap_for(p)
    }

    /// RX 6800 XT (Navi 21) — RDNA2, the generation upstream dropped.
    fn amd_rdna2() -> CapabilityProfile {
        amd_with_ids("AMD Navi 21", &[0x73BF])
    }

    /// RX 7900 XTX (Navi 31) — RDNA3, still supported.
    fn amd_rdna3() -> CapabilityProfile {
        amd_with_ids("AMD Navi 31", &[0x744C])
    }

    /// An AMD card we cannot place (RX 580 / Polaris 10).
    fn amd_unidentified() -> CapabilityProfile {
        amd_with_ids("AMD GPU [1002:67df]", &[0x67DF])
    }

    fn apple() -> CapabilityProfile {
        cap_for(profile_with(
            OsFamily::Macos,
            true,
            GpuInfo { vendor: GpuVendor::Apple, model: "Apple M2 Max".into(), vram_gb: 0, gpus: Vec::new(), max_compute_cap_x10: None },
        ))
    }

    fn cpu_only() -> CapabilityProfile {
        cap_for(profile_with(
            OsFamily::Linux,
            false,
            GpuInfo { vendor: GpuVendor::None, model: String::new(), vram_gb: 0, gpus: Vec::new(), max_compute_cap_x10: None },
        ))
    }

    /// THE RECOMMENDATION MATRIX: hardware → recommended lane (tracks the viability
    /// matrix). Ampere/AMD-RDNA3 → PRL; Volta → Alpha; Apple/CPU-only → XMR;
    /// AMD RDNA2 and AMD-we-can't-identify → XMR, never PRL.
    ///
    /// ASSERTION CHANGED: this used to read `recommends(&amd()) == Lane::GpuPrl`
    /// against a vendor-only "AMD GPU" profile — which is exactly the profile an
    /// RX 6800 produced, so the test was pinning the bug. It is now split by
    /// architecture.
    #[test]
    fn recommendation_matrix_tracks_hardware() {
        assert_eq!(recommends(&nvidia_ampere()), Lane::GpuPrl);
        assert_eq!(recommends(&amd_rdna3()), Lane::GpuPrl);
        // The RDNA2 card cannot run SRBMiner pearlhash at all → CPU lane.
        assert_eq!(recommends(&amd_rdna2()), Lane::Xmr);
        // An AMD card we could not identify is never chosen FOR the user.
        assert_eq!(recommends(&amd_unidentified()), Lane::Xmr);
        assert_eq!(recommends(&nvidia_volta()), Lane::GpuAlpha);
        assert_eq!(recommends(&apple()), Lane::Xmr);
        assert_eq!(recommends(&cpu_only()), Lane::Xmr);
    }

    /// The advisor screen must SAY why, not just quietly point elsewhere: on an
    /// RDNA2 box it names RDNA2 + the upstream removal, and on an unidentified
    /// AMD box it warns that an RX 6xxx card will not mine. This is the "we would
    /// rather say so than let you find out from a silent lane" promise, rendered.
    #[test]
    fn guide_explains_the_amd_verdict_instead_of_silently_recommending_xmr() {
        i18n::set_lang(Lang::En);
        let rdna2 = render_human(&amd_rdna2());
        assert!(rdna2.contains("RDNA2"), "names the architecture: {rdna2}");
        assert!(rdna2.contains("3.5.0"), "names the upstream removal: {rdna2}");

        let unknown = render_human(&amd_unidentified());
        assert!(
            unknown.contains("could not be identified"),
            "says it could not identify the card: {unknown}"
        );
        assert!(unknown.contains("RX 6000-series"), "warns about RDNA2: {unknown}");
        i18n::set_lang(Lang::En);
    }

    /// The bring-your-own surface is correct + PUBLIC-only per lane: pearlhash lanes
    /// target the region relays (3340/3341) and need the companion; XMR targets the
    /// open relay (3333) and needs no companion.
    #[test]
    fn byo_connection_surface_is_correct_per_lane() {
        let prl = byo_connection(Lane::GpuPrl);
        assert_eq!(prl.algorithm, "pearlhash");
        assert_eq!(prl.port, 3340);
        assert!(prl.needs_companion);
        assert_eq!(prl.companion_lane, "prl");
        assert!(prl.hosts.iter().all(|h| h.ends_with("aliceprotocol.org")));

        let alpha = byo_connection(Lane::GpuAlpha);
        assert_eq!(alpha.port, 3341);
        assert!(alpha.needs_companion);
        assert_eq!(alpha.companion_lane, "alpha");

        let x = byo_connection(Lane::Xmr);
        assert_eq!(x.algorithm, "rx/0");
        assert_eq!(x.port, 3333);
        assert!(!x.needs_companion);
        assert_eq!(x.companion_lane, "");
    }

    /// HONESTY GATE: neither the human screen nor the JSON output carries a fiat /
    /// earnings token, a foundation collection address, an upstream pool host, or the
    /// core IP — for EVERY device class.
    #[test]
    fn guide_output_is_credit_only_and_leaks_no_secrets() {
        for cap in [
            nvidia_ampere(),
            nvidia_volta(),
            amd_rdna3(),
            amd_rdna2(),
            amd_unidentified(),
            apple(),
            cpu_only(),
        ] {
            for lang in [Lang::En, Lang::Zh] {
                i18n::set_lang(lang);
                let human = render_human(&cap).to_lowercase();
                let json = render_json(&cap).to_lowercase();
                for body in [&human, &json] {
                    for forbidden in ["$", "usd", "fiat", "paid", "earned", "已发放", "收益", "利润"] {
                        assert!(
                            !body.contains(&forbidden.to_lowercase()),
                            "guide output must not contain `{forbidden}` (credit-only honesty gate)"
                        );
                    }
                    // No foundation collection address / upstream pool / core IP.
                    assert!(!body.contains("prl1p"), "collection address leaked: {body}");
                    assert!(!body.contains("herominers"), "upstream pool leaked");
                    assert!(!body.contains("supportxmr"), "upstream pool leaked");
                    assert!(!body.contains("203.0.113"), "core IP leaked");
                }
            }
        }
        i18n::set_lang(Lang::En);
    }

    /// The pearlhash recommendation always points the bring-your-own path at the
    /// companion (so a closed-source rig can pass PoP without the key leaving the box).
    #[test]
    fn pearlhash_recommendation_routes_to_companion() {
        let human = {
            i18n::set_lang(Lang::En);
            let h = render_human(&nvidia_ampere());
            i18n::set_lang(Lang::En);
            h
        };
        assert!(human.contains("alice-miner companion --lane prl"));
    }

}
