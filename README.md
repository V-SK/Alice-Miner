# Alice Miner

One CLI to **mine** and to **join the Alice AI network**.

`alice-miner` detects your device, manages your Alice reward identity, and puts your
hardware to work in whatever way it can: mine on your **CPU** (RandomX / XMR) or your
**GPU** (pearlhash / PRL), or join the **AI network** — serve consumer inference on your
GPU, contribute to a sharded big model, or run an RLVR training worker. It drives the same
engine as the desktop app, so the two never drift.

> **Credit-only.** Rewards accrue as **credit (积分)** — a cumulative accepted-work count.
> This is **not** cash, and this tool makes **no** earnings, payout, or profit claims. Credit
> converts to the ALICE token only at the real-money launch; until then payout, settlement,
> and on-chain transfer stay gated. The CLI never prints a fiat amount, a "paid"/"earned"
> figure, the collection address, or the upstream pool — by design.

---

## Contents

- [Install](#install)
- [Quickstart](#quickstart)
- [Mining lanes](#mining-lanes)
- [Join the AI network](#join-the-ai-network)
- [Doctor & troubleshooting](#doctor--troubleshooting)
- [Identity & safety](#identity--safety)
- [Links](#links)
- [中文快速上手](#中文快速上手)

---

## Install

### Option A — download the signed release (desktop app)

The signed releases are published at
**https://github.com/V-SK/Alice-Miner/releases** (latest: **v0.5.0**). Each release
ships the **Alice Miner desktop app** for your platform, plus a `SHA256SUMS` manifest and
an ed25519 signature (`latest.json.sig` / `SHA256SUMS.sig`) verified against a key embedded
in the binary.

| Platform            | Asset                              |
| ------------------- | ---------------------------------- |
| macOS (Apple Silicon) | `AliceMiner-macos-arm64.zip`     |
| Linux (x86-64)      | `AliceMiner-linux-x86_64.tar.gz`   |
| Windows (x86-64)    | `AliceMiner-windows-x86_64.zip`    |

Download the asset **and** `SHA256SUMS`, then verify the hash before you open it:

```sh
# macOS / Linux — from the folder you downloaded into
shasum -a 256 -c SHA256SUMS 2>/dev/null | grep OK
# or check a single file by hand:
shasum -a 256 AliceMiner-macos-arm64.zip
```

```powershell
# Windows (PowerShell)
Get-FileHash AliceMiner-windows-x86_64.zip -Algorithm SHA256
```

On macOS the app is ad-hoc signed (no paid Apple certificate), so the first launch needs
**right-click → Open** to get past Gatekeeper. On Windows the CPU engine is fetched on first
run and may trip Defender's PUA heuristic (see the release notes for the exclusion step).

> **Note:** the release assets above are the **desktop app**. A standalone signed
> `alice-miner` CLI binary is not yet a separate release artifact — to run the headless CLI
> today, build it from source (Option B). TODO(V): decide whether to also publish a
> standalone CLI binary + SHA in the release.

### Option B — build the CLI from source

You need a Rust toolchain (stable; CI builds on `dtolnay/rust-toolchain@stable`).

```sh
# 1. Rust (if you don't have it) — https://rustup.rs
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. On Debian/Ubuntu, the OS-keyring dependency needs libdbus headers.
#    (Only required to build; macOS/Windows use the OS keyring directly.)
sudo apt-get install -y libdbus-1-dev pkg-config   # + a C toolchain (build-essential)

# 3. Build the headless CLI
export PATH="$HOME/.cargo/bin:$PATH"
cargo build -p alice-miner-cli --release
```

The binary lands at `target/release/alice-miner-cli`. Every command below is written as
`alice-miner` (its invoked name); run it as `./target/release/alice-miner-cli`, or copy /
symlink it somewhere on your `PATH` as `alice-miner`.

---

## Quickstart

```sh
alice-miner setup                 # 1. guided first-run: detect hardware → set address → start
alice-miner start --lane auto     # 2. mine on the recommended lane (Ctrl-C to stop)
alice-miner balance               # 3. check your credit / PRL / ALICE buckets
alice-miner service --install     # 4. keep mining after you close the window
alice-miner service --logs        # 5. see what the background miner is doing
```

Running the bare binary (`alice-miner`) on a fresh machine launches the same `setup` wizard;
once set up it opens an interactive menu. `setup` also runs fully non-interactively from one
line, which is what the website publishes:

```sh
alice-miner setup --lane auto --address <your-alice-address> --yes
```

---

## Mining lanes

Pick a lane with `--lane`, or use `--lane auto` to let the miner choose the best one for your
device. Run `alice-miner detect` to see which lanes are viable on your hardware. Not sure which
fits? **`alice-miner guide`** detects your hardware, recommends a lane (with one line of *why*),
and shows how to connect — either the bundled client or **your own third-party miner**. See the
full [**mining guide**](docs/mining-guide.md) for the details.

| Lane           | `--lane`        | Hardware                                  | Notes |
| -------------- | --------------- | ----------------------------------------- | ----- |
| CPU · XMR      | `xmr`           | Any CPU (RandomX)                          | Secret-free; always backgrounds. |
| GPU · PRL      | `gpu` / `prl`   | NVIDIA / AMD, compute capability ≥ 7.5 (SRBMiner) | The GPU mainline (pearlhash). Needs a wallet unlock to prove possession. |
| GPU · Alpha    | `alpha`         | Volta / V100 (AlphaMiner)                 | The pearlhash path for cards SRBMiner can't run. |
| GPU · RVN      | `rvn`           | NVIDIA (KawPoW)                           | Legacy lane. |
| Auto           | `auto`          | —                                         | The recommended lane for this device (the default). |
| Dual           | `--dual`        | ≥ 2 viable lanes                          | Runs CPU-XMR **and** GPU-PRL together, crash-isolated. Refuses honestly when fewer than 2 lanes are viable. |

```sh
alice-miner start --lane xmr                 # CPU
alice-miner start --lane gpu                  # GPU pearlhash (prompts for the wallet unlock)
alice-miner start --lane gpu --gpus 0,1       # restrict to specific cards (ids from `detect`)
alice-miner start --dual                      # both lanes at once
alice-miner start --lane xmr --json           # machine-readable Snapshot stream (one line/tick)
```

The GPU-PRL lane needs to unlock your signing key (the relay credits no shares without it).
Prefer the interactive prompt or `--password-stdin` over `--password` on the command line
(which is visible in `ps`).

**Run in the background** so mining survives closing the window:

```sh
alice-miner service --install                 # install + start the background agent (CPU-XMR)
alice-miner service --install --at-login      # ...and restart it at login/boot
alice-miner service --status                  # is it installed / running?
alice-miner service --logs                    # last 50 lines of the background log
alice-miner service --logs --follow           # keep tailing until Ctrl-C
alice-miner service --uninstall               # stop + remove it
```

Backgrounding a **GPU** lane needs an OS keyring (macOS Keychain / Windows Credential Manager
/ Linux Secret Service) to hold the wallet unlock; it is refused on a box with no keyring
(e.g. a headless Linux rig — keep the window open there, or background CPU-XMR instead).

**Watch several rigs** reporting to the same address as one local roster:

```sh
alice-miner start --lane prl --json > rig-a.jsonl    # on box A
alice-miner start --lane xmr --json > rig-b.jsonl    # on box B (shared/NFS path)
alice-miner fleet rig-a.jsonl rig-b.jsonl            # one roster, refreshes live
```

**Bring your own miner.** Already run your own (closed-source / optimized) pearlhash rig? Point
it at Alice and keep the credit routed to your address — **without your private key ever touching
the rig**. `alice-miner companion` holds the proof-of-possession (PoP) for a third-party miner on
a refresh loop; it **never spawns a miner**. Your rig connects with the login `<your-address>.<device>`
and any password. Full walkthrough in the [mining guide → bring your own miner](docs/mining-guide.md#3-bring-your-own-third-party-prl-miner).

```sh
alice-miner companion --lane prl --device rig1     # hold PoP for a bring-your-own PRL rig (Ctrl-C to stop)
alice-miner companion --lane alpha --device volta1 # ...for a Volta / V100 rig
```

---

## Join the AI network

Your GPU can also join the Alice AI network for **credit** (no hashrate, no earnings). Start
with the wizard — it detects your hardware, asks the network what this machine can do, and
lets you pick and confirm a way to contribute:

```sh
alice-miner ai --menu
```

There are three roles. The wizard sets you up for the one that fits your hardware; the
commands below are the direct entry points.

### Serve — single-GPU consumer inference (proven: Linux + NVIDIA)

Run one model on **your single GPU** and answer consumer chat jobs. This is **outbound-only**
— the worker dials the gateway, nothing dials you, so there is no port to open. It spawns the
local Python `alice_acp.worker_client`, so it needs a checkout of the `alice-acp` worker and
**Python 3.11+** with a CUDA `llama-cpp` backend. On first run it downloads the model weights
to `~/.cache/alice/local-models`.

```sh
# You usually pick the model via `alice-miner ai --menu` first, which saves the choice.
alice-miner serve --worker-dir /path/to/alice-acp-minerai
alice-miner serve --worker-dir /path/to/alice-acp-minerai --auto   # probe VRAM, pick+download the largest fitting tier
```

> **Platform:** serving is proven on **Linux + NVIDIA**. macOS / Apple-Silicon (MLX) serving
> is **untested** — treat it as experimental.

### Shard — a stage of a big sharded model (advanced; needs setup)

Run your GPU as one **pipeline-parallel stage** of a large model coordinated by the Alice
scheduling center. Unlike serving, this has a **public `host:port`** the swarm dials, so you
must set up NAT / port-forwarding. It needs a checkout of the shard engine (`phase0/pipeline.py`).

```sh
export SHARD_PSK=<the-shared-swarm-key>        # rides the env, never argv
alice-miner ai --endpoint <public-host:port> --engine-dir /path/to/alice-shard-engine
```

### Train — an RLVR training worker (advanced; needs setup)

Lease a coding task, solve it with your own GPU + model, and submit the candidate; the
coordinator re-executes it against hidden tests and folds a credit weight. Needs a checkout of
the training harness (`run_m0.py` + `code_exec.py`) and, for the default 30B-A3B base, a
~24 GB card with `--four-bit`.

```sh
alice-miner train --trainer-dir /path/to/training-mint-m0
alice-miner train --trainer-dir /path/to/training-mint-m0 --four-bit   # QLoRA-class NF4, ~24 GB floor
```

> The `serve` / `ai` / `train` commands save your resolved flags, so a later bare
> `alice-miner serve` (or `ai` / `train`) replays them. All three are **credit-only**.

---

## Doctor & troubleshooting

When something's stuck, `doctor` prints a PASS / WARN / FAIL line per check **and the exact
fix**. It exits non-zero on any FAIL, so a script can gate `start` on a clean preflight.

```sh
alice-miner doctor                 # diagnose the recommended mining lane
alice-miner doctor --lane gpu      # scope to a specific lane
alice-miner doctor --serve         # diagnose the single-GPU serving role
alice-miner doctor --ai            # diagnose the shard-stage inference role
alice-miner doctor --train         # diagnose the RLVR training role
alice-miner doctor --fix           # apply the SAFE auto-repairs (re-download engine, recreate config)
alice-miner doctor --json          # machine-readable report
```

`doctor --fix` never touches your identity / keystore / wallet — those are only ever printed
as manual steps.

Common things it catches:

- **No identity yet** → run `alice-miner setup` or `alice-miner identity --create`.
- **Python floor for AI roles** → serving needs **Python 3.11+** with the worker package and a
  `llama-cpp` CUDA backend importable; `doctor --serve` checks this.
- **GPU not seen** → make sure `nvidia-smi` works; list the miner's own device ids with
  `alice-miner gpu-devices`.
- **Headless box, no keyring** → you can't background a GPU lane there; keep the window open or
  background CPU-XMR.
- **macOS App Nap** → a hidden window can throttle mining to ~0 H/s; the packaged app defeats
  this automatically, or run a raw binary under `caffeinate -dimsu alice-miner start …`.
- **Windows 中文 mojibake (乱码)** → on a Traditional-Chinese Windows, `cmd.exe` / PowerShell can
  render 中文 output as garbage on **v0.6.0 and earlier**. Workaround: run `chcp 65001` before
  launching. From the next release the miner switches the console to UTF-8 automatically.
  在繁體中文 Windows 上,v0.6.0 及更早版本的 `cmd.exe` / PowerShell 可能將中文輸出顯示為亂碼;
  啟動前先執行 `chcp 65001` 即可,下個版本起程式會自動將主控台切換為 UTF-8。
- **Background logs** → `alice-miner service --logs` (add `--follow` to tail).

Check for a newer signed version any time:

```sh
alice-miner update --check         # report current vs latest (never applies)
alice-miner update                 # check → ask before applying
```

Updates are verified (ed25519 signature + SHA-256) before anything is written.

---

## Identity & safety

Your Alice reward identity lives at `~/.alice/identity.json`.

```sh
alice-miner identity --create               # generate a fresh 24-word identity (prints the mnemonic)
alice-miner identity --show                 # print the active reward address (never a secret)
alice-miner identity --import "<24 words>"  # import from a recovery phrase
alice-miner identity --paste <address>      # watch-only: track an address you own (no keystore)
alice-miner identity --set-prl-payout <prl1p…>   # your 15% PRL return address for a GPU lane
```

- **Back up your 24-word mnemonic** when you `--create` (or generate via `setup`). It is the
  only way to recover your identity — write it down offline; **never** paste it anywhere online
  and **never** share it.
- **Never share your keystore file.** The mnemonic and keystore are secrets; the reward
  **address** (what `identity --show` prints) is public and safe to share.
- Generating an identity **refuses to overwrite** an existing one — it will not silently clobber
  your keystore.
- **Credit-only:** all of the above accrues credit (积分), not cash. No payout, no earnings, no
  profit — payout stays gated until the real-money launch.

---

## Links

- Code & releases: **https://github.com/V-SK/Alice-Miner**
- Website: **https://aliceprotocol.org** <!-- TODO(V): confirm the canonical marketing URL -->
- Mining guide (lanes, choosing, bring-your-own miners): [`docs/mining-guide.md`](docs/mining-guide.md)
- Remote desktop / "white window" fix: [`docs/remote-desktop.md`](docs/remote-desktop.md)
- Published docs URL: TODO(V): add the download page's mining-guide URL

---

## 中文快速上手

`alice-miner` 是一个命令行工具:检测你的设备、管理你的 Alice 奖励身份,并让硬件参与工作 ——
用 **CPU** 挖矿(RandomX / XMR)或 **GPU** 挖矿(pearlhash / PRL),或加入 **AI 网络**
(在你的 GPU 上提供推理服务、参与大模型分片、或运行 RLVR 训练)。

> **仅记积分(credit-only)。** 奖励以**积分**形式累计,**不是现金**,本工具**不做任何**
> 收益、发放或盈利承诺。积分只在真实资金上线时才转换为 ALICE;在此之前发放、结算、链上转账
> 均处于关闭状态。

**安装:** 从 **https://github.com/V-SK/Alice-Miner/releases** 下载对应平台的签名版桌面应用
(并用 `SHA256SUMS` 校验哈希);要用无界面 CLI,请按上文 Option B 从源码构建
(Debian/Ubuntu 需先 `apt-get install -y libdbus-1-dev pkg-config`)。

**五步上手:**

```sh
alice-miner setup                 # 1. 首次引导:检测硬件 → 设置地址 → 开始
alice-miner start --lane auto     # 2. 用推荐 lane 挖矿(Ctrl-C 停止)
alice-miner balance               # 3. 查看积分 / PRL / ALICE 三个奖励桶
alice-miner service --install     # 4. 后台挖矿(关窗后继续)
alice-miner service --logs        # 5. 查看后台日志
```

**挖矿 lane:** `--lane xmr`(CPU)、`--lane gpu`(GPU pearlhash)、`--lane auto`(推荐)、
`--dual`(同时双挖,需 ≥2 个可用 lane)。用 `alice-miner detect` 查看本机可用的 lane。
拿不准选哪个?运行 **`alice-miner guide`**(检测硬件 → 推荐 lane + 为什么 → 如何连接)。

**自带第三方矿机:** 已有自己的(闭源 / 优化)pearlhash 矿机?可把它指向 Alice 并把积分
路由到你的地址,**私钥绝不接触矿机**。`alice-miner companion --lane prl --device rig1` 会替
第三方矿机持有所有权证明(PoP),它**绝不启动矿机**;你的矿机用登录名 `<你的地址>.<设备名>`
+ 任意密码连接。完整步骤见[挖矿指南](docs/mining-guide.md#三自带第三方-prl-矿机重点)。

**加入 AI 网络:** 先运行 `alice-miner ai --menu`(检测硬件 → 网络菜单 → 选择)。三种角色:
`serve`(单卡消费推理,已在 Linux+NVIDIA 验证;需 Python 3.11+)、`ai`(大模型分片,需公网端口)、
`train`(RLVR 训练)。都是仅记积分。

**诊断:** `alice-miner doctor`(挖矿)、`doctor --serve` / `--ai` / `--train`(AI 角色)、
`doctor --fix`(安全自动修复,绝不动身份 / keystore)。

**Windows 中文亂碼:** v0.6.0 及更早版本在繁體中文 Windows 的 `cmd.exe` / PowerShell 下,
中文可能顯示為亂碼;啟動前先執行 `chcp 65001` 即可。下個版本起,程式會自動將主控台(console)
切換為 UTF-8。(On Traditional-Chinese Windows, v0.6.0 and earlier may show 中文 as mojibake in
`cmd.exe` / PowerShell; run `chcp 65001` before launching. The next release does this automatically.)

**身份与安全:** `alice-miner identity --create` 会打印 24 个助记词 —— **请离线备份、切勿分享**;
**切勿分享 keystore**;奖励**地址**是公开的、可安全分享。仅记积分。
