//! `alice-miner ai --menu` — the **participation wizard**.
//!
//! A single, honest, single-shot flow so a real miner can answer one question:
//! *given this machine, what can it contribute to the Alice network?* It detects
//! the hardware, asks the acp scheduling center's anonymous
//! `POST /v1/worker/menu` endpoint (core [`alice_miner_core::capability_menu`]),
//! renders the returned three-mode menu bilingually, and lets the miner pick +
//! confirm a serving-tier download (persisting the choice) or read the entry-point
//! guidance for the shard / train roles.
//!
//! Design (mirrors the rest of the headless CLI):
//!   * **Bilingual inline.** Every user-facing string is `tr!("en", "中文")` at the
//!     call site (there is no catalog). The prompts go to STDERR (like
//!     `prompt_for_language`); the MENU itself goes to STDOUT so it can be piped.
//!   * **Single-shot + honest.** One fetch, no retry loop — a failure prints the
//!     reason and returns; the miner re-runs. A tier that isn't `offered_now` is
//!     DISPLAYED but not selectable (it would never receive a job yet — we say so).
//!   * **Credit-only.** Nothing here prints or implies an earning. The actual
//!     single-GPU serve spawn lives in `alice-miner serve` (M3); this wizard only
//!     SAVES the choice and points at that command — it never auto-starts anything.

use std::io::{IsTerminal as _, Write as _};

use alice_miner_core::capability_menu::{
    self, CapabilityMenu, MenuRequest, ServeOption,
};
use alice_miner_core::serve_config::{self, ServeConfig};
use alice_miner_core::tr;

use crate::{EXIT_OK, EXIT_RUNTIME};

/// The production acp gateway base URL (the default center when neither a flag nor
/// a saved config supplies one) — the same host the other lanes' control plane uses.
const DEFAULT_CENTER_URL: &str = "https://api.aliceprotocol.org";

/// One selectable menu action, resolved from a [`CapabilityMenu`]. A serve entry is
/// only built for a tier the server marks `offered_now` (a defined-but-undispatched
/// tier is shown in the render but is NOT a `Choice` — it can't receive a job yet).
/// `Shard` / `Train` are always offered as guidance entries.
#[derive(Debug, Clone, PartialEq)]
pub enum Choice {
    /// Commit this machine to serving a single-GPU tier (the boxed option carries
    /// the download coordinates). Only built for an `offered_now` tier.
    Serve(Box<ServeOption>),
    /// Read the shard-stage entry-point guidance.
    Shard,
    /// Read the RLVR-training entry-point guidance.
    Train,
    /// Make no change and exit.
    Quit,
}

/// Build the selectable choice list from a menu, in menu order: each `offered_now`
/// serving tier, then shard, then train, then quit. PURE (no I/O) so the
/// selectability rules are unit-tested. A tier that is defined but not yet
/// dispatched is intentionally ABSENT here (it is rendered, but not chooseable).
pub fn build_choices(menu: &CapabilityMenu) -> Vec<Choice> {
    let mut choices = Vec::new();
    if menu.serve.eligible {
        for opt in &menu.serve.options {
            if opt.offered_now {
                choices.push(Choice::Serve(Box::new(opt.clone())));
            }
        }
    }
    // Shard + train are always offered as guidance (they gate at run time, not here).
    choices.push(Choice::Shard);
    choices.push(Choice::Train);
    choices.push(Choice::Quit);
    choices
}

/// Parse a trimmed selection line against the choice list. Accepts a 1-based index
/// into the list, or the word tokens `shard` / `train` / `q` | `quit`. Returns the
/// resolved [`Choice`], or `None` for empty / unrecognized input (the caller
/// re-prompts once, then gives up politely). PURE + unit-tested.
pub fn parse_selection(input: &str, choices: &[Choice]) -> Option<Choice> {
    let t = input.trim();
    if t.is_empty() {
        return None;
    }
    let lower = t.to_ascii_lowercase();
    // Word tokens first (they're unambiguous regardless of numbering).
    match lower.as_str() {
        "q" | "quit" | "exit" => return Some(Choice::Quit),
        "shard" => {
            return choices.iter().find(|c| **c == Choice::Shard).cloned();
        }
        "train" => {
            return choices.iter().find(|c| **c == Choice::Train).cloned();
        }
        _ => {}
    }
    // Otherwise a 1-based index into the displayed list.
    if let Ok(n) = t.parse::<usize>() {
        if n >= 1 {
            return choices.get(n - 1).cloned();
        }
    }
    None
}

/// Format an estimated download size for display: `~5.7 GB` (one decimal), or a
/// bilingual "size unknown" when the server omitted the estimate. PURE +
/// unit-tested. The `~` + the estimate footnote convey that it is not exact.
pub fn format_download_size(est_download_gb: Option<f64>) -> String {
    match est_download_gb {
        Some(gb) if gb > 0.0 => format!("~{gb:.1} GB"),
        _ => tr!("size unknown", "大小未知").to_string(),
    }
}

/// One rendered line for a serving tier: `<name> (<X>B, <quant>, ~Y.Y GB download*,
/// min <Z> GB VRAM)`. PURE over the option so the render is testable. The trailing
/// `*` marks the download size as an estimate (footnoted below the list).
fn render_serve_option(opt: &ServeOption) -> String {
    format!(
        "{} ({}B, {}, {} {}*, min {} GB VRAM)",
        opt.display_name,
        opt.parameter_billions,
        opt.quant,
        format_download_size(opt.est_download_gb),
        tr!("download", "下载"),
        opt.min_free_vram_gb,
    )
}

/// Run the participation wizard. Returns the process exit code. Single-shot:
/// detect → fetch → render → prompt → act, with no retry loop.
pub fn run(center_url_flag: Option<String>) -> i32 {
    // 1. Resolve the center URL: flag > saved AiConfig > the production default.
    let saved_ai = alice_miner_core::ai_config::load();
    let center_url = center_url_flag
        .or(saved_ai.center_url)
        .unwrap_or_else(|| DEFAULT_CENTER_URL.to_string());
    if !center_url.starts_with("https://") {
        // Same fail-closed shape the core check uses (a non-https center is refused).
        eprintln!(
            "error: {}",
            tr!(
                "refusing a non-https center url (the menu query must not cross the wire in the clear)",
                "拒绝非 https 的调度中心地址(菜单查询不得以明文传输)"
            )
        );
        eprintln!("  {center_url}");
        return EXIT_RUNTIME;
    }

    // 2. Detect hardware (cheap, fail-safe) + the NVIDIA free-VRAM hint. Announce the
    // probe on STDERR first so the user sees progress before the (networked) fetch.
    eprintln!(
        "{}",
        tr!(
            "probing hardware…",
            "正在探测硬件……"
        )
    );
    let profile = alice_miner_core::detect::DeviceProfile::detect();
    let nvidia_free = crate::ai::detect_free_vram_gb("python3");
    let req = capability_menu::menu_request_from_detect(&profile, nvidia_free);

    // 3. One-line summary of what was detected (STDERR — it's status, not the menu).
    eprintln!(
        "{}: runtime={} · {}={} GB · {}={} · {}={}",
        tr!("detected", "检测到"),
        req.runtime,
        tr!("per-GPU VRAM", "单卡显存"),
        req.per_gpu_free_vram_gb,
        tr!("GPU count", "GPU 数量"),
        req.gpu_count,
        tr!("model", "型号"),
        if req.gpu_model.is_empty() {
            tr!("(unknown)", "(未知)")
        } else {
            &req.gpu_model
        },
    );

    let menu = match capability_menu::fetch_menu(&center_url, &req) {
        Ok(m) => m,
        Err(e) => {
            eprintln!(
                "error: {}: {e}",
                tr!(
                    "could not fetch the participation menu from the center",
                    "无法从调度中心获取参与菜单"
                )
            );
            eprintln!(
                "  {}",
                tr!(
                    "check your network + the center url, then re-run: alice-miner ai --menu",
                    "请检查网络与调度中心地址,然后重新运行: alice-miner ai --menu"
                )
            );
            return EXIT_RUNTIME;
        }
    };

    // 4. Render the three-mode menu to STDOUT (bilingual).
    render_menu(&center_url, &req, &menu);

    // 5. Prompt for a selection on STDERR (like prompt_for_language). Non-interactive
    // stdin (a pipe) → we've printed the menu; there's nothing to prompt, exit clean.
    if !std::io::stdin().is_terminal() {
        eprintln!(
            "{}",
            tr!(
                "(non-interactive stdin — menu shown above; re-run in a terminal to choose)",
                "(非交互式 stdin — 上方已显示菜单;请在终端中重新运行以进行选择)"
            )
        );
        return EXIT_OK;
    }

    let choices = build_choices(&menu);
    let choice = match prompt_for_choice(&menu, &choices) {
        Some(c) => c,
        None => {
            // Empty / unrecognized input after one re-prompt → make no change, politely.
            eprintln!(
                "{}",
                tr!(
                    "no change — nothing was selected.",
                    "未做更改 — 未选择任何项。"
                )
            );
            return EXIT_OK;
        }
    };

    // 6-8. Act on the choice.
    match choice {
        Choice::Serve(opt) => act_serve(&center_url, &opt),
        Choice::Shard => {
            print_shard_guidance();
            EXIT_OK
        }
        Choice::Train => {
            print_train_guidance(&menu);
            EXIT_OK
        }
        Choice::Quit => {
            eprintln!(
                "{}",
                tr!("no change — nothing was selected.", "未做更改 — 未选择任何项。")
            );
            EXIT_OK
        }
    }
}

/// Render the whole three-mode menu to STDOUT (bilingual). Pure output; the honest
/// credit-only header names the surface without implying any earning.
fn render_menu(center_url: &str, req: &MenuRequest, menu: &CapabilityMenu) {
    println!(
        "\n{}",
        tr!(
            "Alice — what can this machine do? (credit-only, 积分)",
            "Alice — 这台机器能做什么? (credit-only, 积分)"
        )
    );
    println!(
        "  {}: {}  ·  {}: {}",
        tr!("center", "调度中心"),
        center_url,
        tr!("runtime", "运行时"),
        req.runtime,
    );

    render_serve_section(menu);
    render_shard_section(menu);
    render_train_section(menu);
}

/// Render the single-GPU serve section. When eligible, a numbered list of tiers,
/// each tagged dispatchable-now vs defined-not-yet, with the estimate footnote.
/// When not eligible, the honest reason (mapped from the stable reason_code) + the
/// server's detail string when present.
fn render_serve_section(menu: &CapabilityMenu) {
    println!(
        "\n[{}] {}",
        tr!("Serve", "服务"),
        tr!(
            "run one model on this single GPU",
            "在这张单卡上运行一个模型"
        )
    );
    let serve = &menu.serve;
    if serve.eligible && !serve.options.is_empty() {
        for (i, opt) in serve.options.iter().enumerate() {
            let tag = if opt.offered_now {
                tr!("available now", "现已开放")
            } else {
                tr!("defined, not yet dispatched", "已定义,待开放")
            };
            println!("  {}. {} [{}]", i + 1, render_serve_option(opt), tag);
        }
        println!(
            "  * {}",
            tr!(
                "download size is an estimate",
                "下载大小为估算值"
            )
        );
    } else {
        let reason = match serve.reason_code.as_str() {
            "menu_serve_no_tier_fits" => tr!(
                "no serving tier fits this GPU's free VRAM",
                "没有档位适配这张卡的可用显存"
            ),
            "menu_serve_runtime_not_dispatchable" => tr!(
                "this host's runtime cannot serve on the network yet",
                "该主机的运行时暂不能在网络上服务"
            ),
            _ => tr!(
                "single-GPU serving is not available for this machine",
                "此机器暂不支持单卡服务"
            ),
        };
        println!("  {reason}");
        if let Some(detail) = &serve.detail {
            println!("  ({detail})");
        }
    }
}

/// Render the fleet-shard section: each rung tagged by its status, this host's
/// aggregate figure, and the translated pooling concept.
fn render_shard_section(menu: &CapabilityMenu) {
    println!(
        "\n[{}] {}",
        tr!("Shard", "分片"),
        tr!(
            "contribute one stage of a big model to the swarm",
            "为群贡献大模型的一个 stage"
        )
    );
    let shard = &menu.shard;
    if shard.rungs.is_empty() {
        println!(
            "  {}",
            tr!("no fleet rungs offered", "暂无可参与的分片档位")
        );
    } else {
        for rung in &shard.rungs {
            let tag = match rung.status.as_str() {
                "coming" => tr!("coming", "即将开放"),
                "live" => tr!("live", "已上线"),
                _ => tr!("defined", "已定义"),
            };
            println!(
                "  - {} ({}B, {} {}GB aggregate VRAM) [{}]",
                rung.display_name,
                rung.parameter_billions,
                tr!("needs", "需要"),
                rung.min_aggregate_vram_gb,
                tag,
            );
        }
    }
    println!(
        "  {}: {} GB",
        tr!("your aggregate free VRAM", "你的聚合可用显存"),
        shard.your_aggregate_free_vram_gb
    );
    println!(
        "  {}",
        tr!(
            "swarm pools VRAM across miners; one card can contribute one stage",
            "分片池化多台矿机的显存;单卡即可贡献一个 stage"
        )
    );
}

/// Render the RLVR-training section, honestly: the hard gate, and the advisory
/// per-GPU VRAM figure marked advisory (not enforced).
fn render_train_section(menu: &CapabilityMenu) {
    println!(
        "\n[{}] {}",
        tr!("Train", "训练"),
        tr!(
            "generate RLVR candidates as a training worker",
            "作为训练工作节点生成 RLVR 候选"
        )
    );
    let train = &menu.train;
    if train.gate_passed {
        println!(
            "  {}",
            tr!(
                "hardware gate passed (NVIDIA/CUDA present)",
                "硬件门槛已通过(检测到 NVIDIA/CUDA)"
            )
        );
    } else {
        println!(
            "  {}",
            tr!(
                "hardware gate NOT passed — training generation needs an NVIDIA/CUDA GPU",
                "硬件门槛未通过 — 训练生成需要 NVIDIA/CUDA 显卡"
            )
        );
    }
    let met = if train.meets_recommended {
        tr!("met", "已满足")
    } else {
        tr!("not met", "未满足")
    };
    println!(
        "  {}: {} GB/GPU — {} ({})",
        tr!("recommended VRAM", "建议显存"),
        train.recommended_min_per_gpu_vram_gb,
        met,
        tr!(
            "recommended (advisory, not enforced)",
            "建议值(仅供参考,非硬性门槛)"
        ),
    );
}

/// Interactive selection prompt on STDERR (mirrors `prompt_for_language`): print the
/// numbered choices, read ONE line from stdin, parse it. On empty/unrecognized
/// input re-prompt exactly ONCE, then give up (return `None`). Never loops forever.
fn prompt_for_choice(menu: &CapabilityMenu, choices: &[Choice]) -> Option<Choice> {
    for attempt in 0..2 {
        eprintln!(
            "\n{}",
            tr!("What would you like to do?", "你想做什么?")
        );
        for (i, c) in choices.iter().enumerate() {
            let label = choice_label(c, menu);
            eprintln!("  [{}] {}", i + 1, label);
        }
        eprint!("> ");
        let _ = std::io::stderr().flush();

        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return None;
        }
        if let Some(choice) = parse_selection(&line, choices) {
            return Some(choice);
        }
        if attempt == 0 {
            eprintln!(
                "{}",
                tr!(
                    "unrecognized choice — enter a number, or 'shard' / 'train' / 'q'.",
                    "无法识别的选择 — 请输入序号,或 'shard' / 'train' / 'q'。"
                )
            );
        }
    }
    None
}

/// The one-line label for a choice in the selection prompt (bilingual).
fn choice_label(choice: &Choice, _menu: &CapabilityMenu) -> String {
    match choice {
        Choice::Serve(opt) => format!(
            "{} {}",
            tr!("serve", "服务"),
            opt.display_name
        ),
        Choice::Shard => tr!(
            "shard — contribute one stage to the fleet",
            "分片 — 为群贡献一个 stage"
        )
        .to_string(),
        Choice::Train => tr!(
            "train — run as an RLVR generation worker",
            "训练 — 作为 RLVR 生成节点运行"
        )
        .to_string(),
        Choice::Quit => tr!("quit (no change)", "退出(不做更改)").to_string(),
    }
}

/// Handle a serve-tier choice: show the download confirmation (repo/subpath/size),
/// ask y/N on STDERR, and on yes persist the choice + print the honest "saved — start
/// serving with `alice-miner serve`" message (M3 wired the actual serve role; the
/// wizard still auto-starts nothing). On no, an abort line. Returns the exit code.
fn act_serve(center_url: &str, opt: &ServeOption) -> i32 {
    eprintln!(
        "\n{}",
        tr!("You chose to serve:", "你选择服务:")
    );
    eprintln!("  {}", render_serve_option(opt));
    eprintln!(
        "  {}: {}",
        tr!("download", "下载"),
        opt.repo_id
    );
    if !opt.artifact_subpath.is_empty() {
        eprintln!("    {}", opt.artifact_subpath);
    }
    eprintln!(
        "  {}: {}",
        tr!("estimated size", "预估大小"),
        format_download_size(opt.est_download_gb)
    );
    eprint!(
        "{} [y/N] ",
        tr!(
            "Download this model and save the choice?",
            "下载此模型并保存选择?"
        )
    );
    let _ = std::io::stderr().flush();

    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        eprintln!(
            "{}",
            tr!("aborted — no change.", "已取消 — 未做更改。")
        );
        return EXIT_OK;
    }
    let yes = matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes");
    if !yes {
        eprintln!(
            "{}",
            tr!("aborted — no change.", "已取消 — 未做更改。")
        );
        return EXIT_OK;
    }

    // Persist the PUBLIC serve choice (never a secret). A write failure is surfaced
    // but non-fatal to the honest message below.
    let cfg = ServeConfig {
        schema: 0, // save() stamps the current schema
        center_url: Some(center_url.to_string()),
        tier: Some(opt.model_class.clone()),
        runtime: Some(opt.runtime.clone()),
        repo_id: Some(opt.repo_id.clone()),
        revision: Some(opt.revision.clone()),
        artifact_subpath: Some(opt.artifact_subpath.clone()),
        // The wizard records the MODEL choice only; the worker checkout dir + python
        // are resolved by `alice-miner serve` (flag / env / its own saved fields), so
        // it never overwrites them here.
        worker_dir: None,
        python: None,
    };
    match serve_config::save(&cfg) {
        Ok(path) => {
            println!(
                "{} {} ({})",
                tr!("saved serve choice:", "已保存服务选择:"),
                opt.model_class,
                path.display()
            );
        }
        Err(e) => {
            eprintln!(
                "warning: {}: {e}",
                tr!(
                    "could not persist the serve choice",
                    "无法保存服务选择"
                )
            );
        }
    }
    // HONEST: the single-GPU serve role now EXISTS (`alice-miner serve`). The wizard
    // still does not auto-start anything — it saved the choice and points at the
    // command. Credit-only: this only tells the user how to begin, never an earning.
    println!(
        "{}",
        tr!(
            "selection saved — start serving with: alice-miner serve",
            "选择已保存——运行 alice-miner serve 开始服务"
        )
    );
    EXIT_OK
}

/// Print the shard-stage entry-point guidance (bilingual). Points the miner at the
/// existing `ai` role (the shard-stage worker) with the public host + engine dir.
fn print_shard_guidance() {
    println!(
        "\n{}",
        tr!(
            "To contribute a shard stage, run:",
            "要贡献一个分片 stage,请运行:"
        )
    );
    println!("  alice-miner ai --endpoint <public host:port> --engine-dir <alice-shard-engine checkout>");
    println!(
        "  {}",
        tr!(
            "this registers your GPU as a pipeline stage; the center pools same-runtime VRAM across the swarm and places you.",
            "这会将你的 GPU 注册为流水线 stage;调度中心跨群池化同运行时的显存并为你分配。"
        )
    );
}

/// Print the RLVR-training entry-point guidance (bilingual) + the advisory VRAM note.
fn print_train_guidance(menu: &CapabilityMenu) {
    println!(
        "\n{}",
        tr!(
            "To run as an RLVR training worker, run:",
            "要作为 RLVR 训练节点运行,请运行:"
        )
    );
    println!("  alice-miner train --trainer-dir <dir>");
    println!(
        "  {} {} GB/GPU ({}).",
        tr!(
            "recommended per-GPU VRAM:",
            "建议单卡显存:"
        ),
        menu.train.recommended_min_per_gpu_vram_gb,
        tr!(
            "advisory, not enforced",
            "仅供参考,非硬性门槛"
        )
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use alice_miner_core::capability_menu::{ServeSection, ShardSection, TrainSection};
    use alice_miner_core::i18n::{self, Lang};

    /// Serialize the tests in this module that mutate the PROCESS-GLOBAL language
    /// (Rust runs a crate's tests in parallel). English is the default so most
    /// tests don't touch the global; the ones that do reset it and hold this lock.
    static LANG_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn serve_opt(class: &str, name: &str, offered_now: bool) -> ServeOption {
        ServeOption {
            model_class: class.into(),
            display_name: name.into(),
            family: "general".into(),
            parameter_billions: 4,
            max_context_tokens: 32768,
            runtime: "cuda".into(),
            quant: "q4_k_m".into(),
            min_free_vram_gb: 5,
            repo_id: "v102ss/Example-GGUF".into(),
            revision: "aa4bf90e83b7acb4fb78881186e7bd623bfc004b".into(),
            artifact_subpath: "Example-Q4_K_M.gguf".into(),
            est_download_gb: Some(2.5),
            download_size_is_estimate: true,
            offered_now,
        }
    }

    fn menu_with_serve(eligible: bool, options: Vec<ServeOption>) -> CapabilityMenu {
        CapabilityMenu {
            serve: ServeSection {
                mode: "serve_single_gpu".into(),
                eligible,
                runtime: "cuda".into(),
                selected_tier: options.first().map(|o| o.model_class.clone()),
                options,
                reason_code: "menu_serve_tiers_available".into(),
                detail: None,
            },
            shard: ShardSection::default(),
            train: TrainSection::default(),
            ..Default::default()
        }
    }

    #[test]
    fn build_choices_only_offers_dispatchable_serve_tiers() {
        // One dispatchable + one defined-not-yet → only the dispatchable is a Choice.
        let menu = menu_with_serve(
            true,
            vec![
                serve_opt("alice_standard_9b", "Alice", false),
                serve_opt("alice_lite_4b", "Alice Lite", true),
            ],
        );
        let choices = build_choices(&menu);
        // Serve(lite) + Shard + Train + Quit.
        assert_eq!(choices.len(), 4);
        match &choices[0] {
            Choice::Serve(opt) => assert_eq!(opt.model_class, "alice_lite_4b"),
            other => panic!("expected the dispatchable serve tier first, got {other:?}"),
        }
        assert_eq!(choices[1], Choice::Shard);
        assert_eq!(choices[2], Choice::Train);
        assert_eq!(choices[3], Choice::Quit);
        // The non-dispatchable 9B tier is NOT selectable.
        assert!(!choices
            .iter()
            .any(|c| matches!(c, Choice::Serve(o) if o.model_class == "alice_standard_9b")));
    }

    #[test]
    fn build_choices_empty_serve_still_offers_shard_train_quit() {
        // Not eligible (a cpu host) → no serve choices, but shard/train/quit remain.
        let menu = menu_with_serve(false, vec![]);
        let choices = build_choices(&menu);
        assert_eq!(choices, vec![Choice::Shard, Choice::Train, Choice::Quit]);
    }

    #[test]
    fn build_choices_eligible_but_no_offered_now_has_no_serve_choice() {
        // Eligible with only defined-not-yet tiers → nothing to serve now.
        let menu = menu_with_serve(true, vec![serve_opt("alice_standard_9b", "Alice", false)]);
        let choices = build_choices(&menu);
        assert_eq!(choices, vec![Choice::Shard, Choice::Train, Choice::Quit]);
    }

    #[test]
    fn parse_selection_index_word_tokens_and_invalid() {
        let menu = menu_with_serve(true, vec![serve_opt("alice_lite_4b", "Alice Lite", true)]);
        let choices = build_choices(&menu);
        // 1-based index: [1]=serve, [2]=shard, [3]=train, [4]=quit.
        assert!(matches!(
            parse_selection("1", &choices),
            Some(Choice::Serve(_))
        ));
        assert_eq!(parse_selection("2", &choices), Some(Choice::Shard));
        assert_eq!(parse_selection("3", &choices), Some(Choice::Train));
        assert_eq!(parse_selection("4", &choices), Some(Choice::Quit));
        // Word tokens (case-insensitive, whitespace-tolerant).
        assert_eq!(parse_selection("shard", &choices), Some(Choice::Shard));
        assert_eq!(parse_selection("  TRAIN  ", &choices), Some(Choice::Train));
        assert_eq!(parse_selection("q", &choices), Some(Choice::Quit));
        assert_eq!(parse_selection("quit", &choices), Some(Choice::Quit));
        // Empty / out-of-range / garbage → None (the caller re-prompts / gives up).
        assert_eq!(parse_selection("", &choices), None);
        assert_eq!(parse_selection("   ", &choices), None);
        assert_eq!(parse_selection("0", &choices), None);
        assert_eq!(parse_selection("99", &choices), None);
        assert_eq!(parse_selection("nonsense", &choices), None);
    }

    #[test]
    fn parse_selection_word_token_absent_from_list_is_none() {
        // A menu that (hypothetically) had no shard choice — the token resolves to
        // None rather than a phantom choice. build_choices always includes shard, so
        // construct the list by hand to exercise the guard.
        let choices = vec![Choice::Quit];
        assert_eq!(parse_selection("shard", &choices), None);
        assert_eq!(parse_selection("train", &choices), None);
    }

    #[test]
    fn format_download_size_estimate_and_unknown() {
        let _g = LANG_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        i18n::set_lang(Lang::En);
        assert_eq!(format_download_size(Some(5.7)), "~5.7 GB");
        assert_eq!(format_download_size(Some(2.0)), "~2.0 GB");
        assert_eq!(format_download_size(None), "size unknown");
        assert_eq!(format_download_size(Some(0.0)), "size unknown");
        // The Chinese variant of the unknown case.
        i18n::set_lang(Lang::Zh);
        assert_eq!(format_download_size(None), "大小未知");
        assert_eq!(format_download_size(Some(5.7)), "~5.7 GB");
        i18n::set_lang(Lang::En);
    }

    #[test]
    fn render_serve_option_line_has_the_documented_shape() {
        let _g = LANG_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        i18n::set_lang(Lang::En);
        let line = render_serve_option(&serve_opt("alice_lite_4b", "Alice Lite", true));
        assert_eq!(
            line,
            "Alice Lite (4B, q4_k_m, ~2.5 GB download*, min 5 GB VRAM)"
        );
        i18n::set_lang(Lang::En);
    }

    #[test]
    fn choice_label_serve_names_the_tier() {
        let _g = LANG_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        i18n::set_lang(Lang::En);
        let opt = serve_opt("alice_lite_4b", "Alice Lite", true);
        let c = Choice::Serve(Box::new(opt));
        assert_eq!(choice_label(&c, &CapabilityMenu::default()), "serve Alice Lite");
        i18n::set_lang(Lang::En);
    }
}
