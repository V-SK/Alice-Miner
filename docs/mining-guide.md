# Mining guide — lanes, choosing, and bring-your-own miners

How Alice mining works, how to pick the lane that fits your hardware, and how to
point your **own** third-party (closed-source) miner at the Alice network.

> **Credit-only.** Everything below accrues **credit (积分)** — a cumulative
> accepted-work count. This is **not** cash, and this guide makes **no** earnings,
> payout, or profit claim. Credit converts to the ALICE token only at the
> real-money launch; until then settlement and on-chain transfer stay gated.

New here? Start with [`README.md`](../README.md) for install + the five-command
quickstart, then come back for the detail.

---

## Contents

- [1. How Alice mining works](#1-how-alice-mining-works)
- [2. Choose your lane](#2-choose-your-lane)
- [3. Bring your own third-party PRL miner](#3-bring-your-own-third-party-prl-miner)
- [4. Platform notes & troubleshooting](#4-platform-notes--troubleshooting)
- [中文指南](#中文指南)

---

## 1. How Alice mining works

You do **not** mine a new, untested coin. You mine **real shares of an existing
coin** — Monero (XMR, on your CPU), or a pearlhash coin (PRL, on your GPU) — using
a battle-tested mining engine. Alice sits in front of that work and rewards you for
it.

**What Alice measures.** Every valid share you submit carries a *difficulty* — how
much work it proves. Alice tallies the difficulty-weighted total each address
contributes. You are rewarded for **the work you prove**, not for a promise.

**How ALICE is shared out.** Emission happens in **6-hour rounds**. Each round mints
a fixed batch of ALICE credit and splits it across **three hardware pools**:

| Pool | Share | Who's in it |
| ---- | ----- | ----------- |
| GPU  | 70%   | pearlhash / PRL (and the Alpha path for older cards) |
| CPU  | 15%   | RandomX / XMR |
| ASIC | 15%   | scrypt / LTC-family |

Inside each pool, your slice is your **difficulty-weighted contribution** over the
round — mine more proven work, get a bigger slice of that pool's 70/15/15 share.
There is **no** upstream gate: the round mints its ALICE credit on schedule
regardless of what any upstream returns, so you are credited for showing up and
doing the work.

**The path, from your side.** You never talk to the coin network directly — you talk
to an Alice **regional relay**, which does the plumbing:

```
  your miner ──stratum──▶  Alice regional relay  ──▶  (the coin's network)
                                  │
                                  ▼
                   your accepted shares are tallied
                                  │
                                  ▼
              credited to YOUR Alice address (blake2b-checked)
                                  │
                                  ▼
        every 6h: ALICE credit split 70/15/15, by difficulty weight
```

The relay is the only host you configure. Your reward identity is an **Alice
address**; the login name you connect with is what routes the credit to you (see
§2 and §3).

> **Honest framing.** The network currently runs **credit-only**: rewards accrue as
> a count, and nothing is settled to any currency. When credit becomes claimable is
> a launch decision, not something this tool promises.

---

## 2. Choose your lane

A *lane* is a (hardware, coin, algorithm) combination. The client picks the best one
for your device automatically, or you can force one. **The fastest way to see what
fits your box:**

```sh
alice-miner guide          # detect hardware → recommended lane + why → how to connect
alice-miner guide --json   # the same, machine-readable (for a script or the website)
```

`guide` is a **read-only advisor** — it detects your CPU/GPU, recommends a lane with
one sentence of *why*, and prints the two ways to connect (the official client, or
your own miner). It needs no identity and writes nothing.

### The lanes

| Lane | `--lane` | Hardware | Algorithm | Relay endpoint | Notes |
| ---- | -------- | -------- | --------- | -------------- | ----- |
| **GPU · PRL** | `gpu` / `prl` | NVIDIA (CUDA, cc ≥ 7.5) / AMD (OpenCL) | `pearlhash` | `us` / `asia` / `eu.aliceprotocol.org : 3340` | **The GPU mainline.** PoP-gated (needs a possession proof). |
| **GPU · Alpha** | `alpha` | Volta / V100-class NVIDIA | `pearlhash` | `us` / `asia` / `eu.aliceprotocol.org : 3341` | The pearlhash path for cards SRBMiner can't run. PoP-gated. |
| **CPU · XMR** | `xmr` | Any CPU (RandomX) | `rx/0` | `hk.aliceprotocol.org : 3333` | Open enrollment — no proof, no GPU needed. |
| **GPU · RVN** | `rvn` | NVIDIA (KawPoW) | `kawpow` | `hk.aliceprotocol.org : 8888` | Legacy path; the pearlhash lanes are the mainline today. |
| **ASIC · scrypt** | — | scrypt ASIC (LTC-family) | `scrypt` | *see note* | The 15% ASIC pool. Not yet a self-serve client lane — see below. |

**Hashrate class, not a reward.** Different hardware proves work at very different
rates, and the client shows your live rate in the right units — a CPU reads in
**kH/s**, a pearlhash GPU in the **MH/s–TH/s** range, an ASIC in the **GH/s–TH/s**
range. Run `alice-miner detect` to see your device's viable lanes, or
`alice-miner start … --json` to watch the live rate. We deliberately do **not**
quote an expected reward — credit depends on the whole network's contribution each
round, and nothing is settled to a currency yet.

- **Never use the FI region.** The `fi.aliceprotocol.org` host is a dead zone
  (NXDOMAIN) and was removed in v0.6.1 — the live pearlhash regions are `us`,
  `asia`, and `eu` (EU went live in v0.6.2).
- **AMD is the OpenCL exception.** The `compute capability ≥ 7.5` bar is an NVIDIA
  (CUDA) figure; AMD cards have no CUDA compute-capability number and instead run
  pearlhash through the miner's **OpenCL** backend — so the cc threshold simply does
  not apply to them.

### About the ASIC / scrypt pool

The 15% ASIC pool is a real part of the emission split, and the Alice relay speaks
the scrypt (LTC-family) stratum protocol upstream. But scrypt is **not yet a
self-serve client lane**: the official client does not bundle a scrypt miner (ASICs
run their own firmware anyway), and there is no published self-serve scrypt endpoint
in this release. If you run a scrypt ASIC farm and want to point it at Alice, watch
the [releases page](https://github.com/V-SK/Alice-Miner/releases) and check
`alice-miner guide` in a later version — this section will carry the endpoint when
it goes self-serve.

### Which lane will `guide` recommend?

| Your hardware | Recommended lane |
| ------------- | ---------------- |
| NVIDIA (Turing/Ampere+) or AMD GPU | **GPU · PRL** (pearlhash mainline) |
| Volta / V100-class NVIDIA | **GPU · Alpha** |
| Apple Silicon, or CPU-only / no GPU | **CPU · XMR** |

You can always override with `--lane`, or run two lanes at once with
`alice-miner start --dual` (CPU-XMR **and** GPU-PRL together, crash-isolated).

---

## 3. Bring your own third-party PRL miner

**This is the headline feature of this guide.** You do not have to use the bundled
miner. If you have your **own** pearlhash rig — a hand-tuned build, a closed-source
optimized miner, a farm already pointed at other pools — you can point it at Alice
and have the credit routed to **your** Alice address, **without your private key ever
touching the rig.**

> The bundled client is itself just a supervisor around a third-party stratum miner,
> so "bring your own" is the same shape — you're swapping in your miner and letting a
> small Alice helper hold the proof-of-possession for it.

### Who this is for

- You run an **optimized or closed-source** pearlhash miner and don't want to switch
  engines.
- You run a **farm** and manage the miners with your own tooling.
- You want the Alice reward routing but keep your existing mining setup.

If you just want to mine on one machine, the bundled `alice-miner start --lane gpu`
is simpler — it does all of the below for you internally.

### Why a companion? (proof-of-possession, anti-sybil)

The PRL / Alpha relays run **`REQUIRE_POP=1`**: a bare stratum login is rejected
(`code:24`). Before the relay credits shares to an address, it wants proof that the
connection is really controlled by whoever owns that address — this is an anti-sybil
gate, so nobody can farm credit into an address they don't hold.

The bundled client proves this **internally**: it signs a challenge with your Alice
signing key and enrolls the `(address, device)` pair into the relay's short-lived
allowlist. A third-party miner has no idea how to do that — so
**`alice-miner companion`** does it *for* it. The companion:

1. unlocks your Alice signing key **locally** (the key never leaves the box);
2. runs the same challenge → sign → enroll handshake the official lane runs;
3. repeats on a refresh loop (default ~9 min, comfortably inside the relay's ~1800 s
   allowlist window), keeping the pair authorized for as long as it runs.

It **never spawns a miner** — your rig does the hashing; the companion only holds the
proof. That separation is the whole point: **your rig hashes, the companion proves,
your key stays home.**

### Steps

#### a) Install the official CLI and set your Alice address

Build or download the CLI (see [README → Install](../README.md#install)), then
create or import your reward identity:

```sh
alice-miner identity --create               # generate a fresh 24-word identity (prints the mnemonic — back it up offline)
# ...or bring an address you already own:
alice-miner identity --import "<24 words>"  # import from a recovery phrase
alice-miner identity --show                 # print your active reward address (public, safe to share)
```

Optionally, record where a future 15% PRL return should go (this is a public
`prl1p…` address you control; it stores config for later and pays nothing now —
credit-only):

```sh
alice-miner identity --set-prl-payout <prl1p…>
alice-miner identity --show-prl-payout
```

> A **watch-only** identity (`identity --paste <address>`) has no signing key, so it
> **cannot** run the companion — the possession proof needs the key. Use
> `--create` or `--import` for a bring-your-own setup.

#### b) Start the companion (it holds the proof; it does not mine)

```sh
alice-miner companion --lane prl --device rig1
```

It unlocks your key (prompts for the keystore password; use `--password-stdin` for a
script), then prints a **connection banner** with the exact relay host, port, and
login for your rig — for example:

```
Alice Miner — companion (bring-your-own miner)
────────────────────────────────────────────────────────
Point your OWN pearlhash miner at this relay:
  pool:      asia.aliceprotocol.org : 3340
  algorithm: pearlhash
  login (user):     <your-address>.rig1
  password:  anything (this companion holds the authorization)

Your private key stays on THIS machine — it never touches the miner.
Keep this running while you mine; stop with Ctrl-C. (prl)
```

Options you'll want:

```sh
alice-miner companion --lane prl --device rig1 --region asia   # pin us | asia | eu (default: nearest/remembered)
alice-miner companion --lane alpha --device volta1             # for a Volta / V100 rig (port 3341)
alice-miner companion --lane prl --address <alice-addr>        # pin the address explicitly — it MUST be your own identity's (see below)
alice-miner companion --lane prl --once                        # enroll once and exit (prime a scripted run / a test)
```

> **Two different addresses — don't conflate them.**
> - **Your mining identity address** is the Alice address the companion enrolls. The
>   companion signs the possession proof with **your local signing key**, and the relay
>   verifies that signature against the enrolled address — so the enrolled address
>   **must** be the one your key derives. You **cannot** use `--address` to enroll some
>   *other* address (there's no key to sign for it, so the relay would never allow-list
>   it — the rig would just loop on `code:24`). `--address` only lets you state your own
>   address explicitly; the companion refuses up front if it isn't your signing
>   identity. **To mine to a different address, switch identity** (`identity --import`),
>   not `--address`.
> - **Your PRL cashback address** is a *separate* `prl1p…` address (`identity
>   --set-prl-payout`) where a future 15% PRL return would go. It has nothing to do with
>   who mines or with the companion — setting it does not change your mining identity.

Check the companion is ready before you rely on it:

```sh
alice-miner doctor --lane prl      # includes a "companion (PoP)" readiness check
```

#### c) Point your own pearlhash rig at that relay

Use the exact values the companion's banner printed. In your third-party miner's
config (SRBMiner, or whatever you run), set:

| Field | Value |
| ----- | ----- |
| **pool / host:port** | the host + port from the banner, e.g. `asia.aliceprotocol.org:3340` |
| **algorithm** | `pearlhash` |
| **login / user / wallet** | `<your-alice-address>.<device>` — e.g. `<your-address>.rig1` |
| **password** | anything (e.g. `x`) — authorization is out-of-band, held by the companion |

The `<device>` suffix on the login **must match** the `--device` you gave the
companion (that's the pair the companion enrolled). Use the **same region host** the
companion printed — the allowlist is per-relay, so a rig pointed at a different
region won't be recognized.

That's it. Your rig hashes; the relay sees the enrolled pair (proven by the
companion) and credits the shares to your Alice address.

### FAQ

- **Why do I even need the companion?** The relay is PoP-gated (`REQUIRE_POP=1`) to
  stop anyone crediting shares into an address they don't control. The companion is
  how a third-party miner passes that gate — it proves possession on your behalf.
- **Must the companion stay running the whole time?** **Yes.** The relay's
  authorization is short-lived (~1800 s) and the companion re-proves it on a loop. If
  the companion stops, the pair lapses and the relay stops crediting new shares. Keep
  it running alongside your rig (a service manager / `tmux` / `screen` is fine).
- **Does my private key go on the mining rig?** **No — never.** The key is unlocked
  in memory on the machine running the companion and is used only to sign the proof.
  Your rig connects with a throwaway password; it has no key.
- **Can I run the companion on a different machine than my rig?** Yes. The companion
  only needs your Alice keystore and outbound HTTPS to the relay. Point every rig's
  login at `<your-address>.<device>` for the same address, and pin them all to the
  region the companion enrolled against.
- **Can `--address` enroll a *different* reward address?** **No.** The companion signs
  the proof with your local key, so it can only enroll the address that key derives —
  `--address` just states your own address explicitly (it refuses up front if it isn't
  your signing identity). To mine to a different address, switch identity
  (`identity --import`). A PRL cashback address is a separate setting
  (`identity --set-prl-payout`) and does not change who mines.
- **Do not use the FI region.** `fi.aliceprotocol.org` is a dead zone (NXDOMAIN).
  The live regions are `us`, `asia`, and `eu`.
- **A wrong address is rejected.** The login address is validated (SS58 format-300);
  a typo won't silently credit someone else — it just won't be authorized. Copy it
  from `alice-miner identity --show`.
- **CPU-XMR doesn't need any of this.** XMR is open-enrollment — point your miner
  straight at `hk.aliceprotocol.org:3333`, `rx/0`, login `<address>.<worker>`,
  password `x`. No companion.

---

## 4. Platform notes & troubleshooting

### First stop: `doctor`

`alice-miner doctor` prints a PASS / WARN / FAIL line per check **and the exact
fix**, and exits non-zero on any FAIL so a script can gate on a clean preflight.

```sh
alice-miner doctor                 # diagnose the recommended lane
alice-miner doctor --lane prl      # scope to PRL (includes the companion / PoP check)
alice-miner doctor --fix           # apply SAFE auto-repairs (never touches identity / keystore)
alice-miner doctor --json          # machine-readable report
```

### Windows

- **Antivirus / Defender.** The CPU engine is fetched on first run and can trip
  Defender's PUA heuristic (this is common for all miners). Add the documented
  exclusion from the release notes if the engine is quarantined.
- **中文 mojibake (乱码).** On a Traditional-Chinese Windows, `cmd.exe` / PowerShell
  can render 中文 output as garbage on **v0.6.0 and earlier**. Workaround: run
  `chcp 65001` before launching. From the next release the miner switches the
  console to UTF-8 automatically.
- **Blank white window (desktop app over remote desktop).** If you drive the machine
  over RDP / AnyDesk / TeamViewer / Sunflower and the app opens solid white, see
  [`remote-desktop.md`](remote-desktop.md) — set `ALICE_GUI_RENDERER=wgpu`. The
  headless CLI is immune (no graphics window) and is the recommended path for
  headless rigs anyway.

### macOS

- **Apple Silicon only.** The macOS artifact is `aarch64-apple-darwin` and nothing
  else — there is no Intel (x86_64) macOS build, and Rosetta does not help (it
  translates Intel binaries *for* Apple Silicon, not the reverse). On an Intel Mac
  the app cannot open at all; mine from a Linux or Windows box instead. Minimum
  macOS 11 Big Sur.
- **Install it into `/Applications` — this is required.** Unzip
  `AliceMiner-macos-arm64.zip`, then **drag `AliceMiner.app` into
  `/Applications`** before the first launch. Launched from `~/Downloads`, a
  quarantined app is **App-Translocated**: macOS runs it from a randomized
  read-only mount, which is the usual cause of "it opens and does nothing" and of
  settings not persisting between launches. Moving the bundle clears translocation.
- **Gatekeeper.** The app is ad-hoc signed (no paid Apple Developer certificate),
  so the first launch is refused with "cannot verify the developer". Dismiss that
  dialog, then **System Settings → Privacy & Security → Open Anyway** (confirm with
  *Open*). It launches normally from then on. Equivalent one-liner, **after** the
  app is in `/Applications`:

  ```bash
  xattr -dr com.apple.quarantine /Applications/AliceMiner.app
  ```

  > **`right-click → Open` no longer works.** macOS 15 (Sequoia) removed that
  > Gatekeeper override for apps without a developer certificate. Any guide still
  > teaching it — including earlier revisions of this one — is out of date; use
  > Privacy & Security → Open Anyway.
- **The CLI lives inside the bundle.** There is no separate macOS CLI download:

  ```bash
  /Applications/AliceMiner.app/Contents/MacOS/alice-miner-cli start --lane xmr
  ```
- **App Nap → ~0 H/s.** A hidden window can throttle mining to near zero. The
  packaged app defeats this automatically; a raw CLI binary can be wrapped with
  `caffeinate -dimsu alice-miner start …`.
- **PRL / Alpha on Apple Silicon.** There is no macOS SRBMiner pearlhash build, so the
  pearlhash lanes are unavailable on Apple Silicon — the CPU-XMR lane is the fit
  there (which is why `guide` recommends XMR on a Mac).

### Linux

- **Headless rig, no keyring.** Backgrounding a **GPU** lane needs an OS keyring to
  hold the wallet unlock; a headless box with no Secret Service can't background a
  GPU lane. Keep the window open, background CPU-XMR instead, or use the companion
  pattern (§3) with your own miner.
- **Build dependency.** On Debian/Ubuntu the OS-keyring crate needs `libdbus-1-dev`
  and `pkg-config` (plus a C toolchain) to build the CLI from source.

### Common lane issues

- **`code:24` / login rejected on PRL or Alpha.** The relay is PoP-gated. Run
  `alice-miner companion --lane prl` (or `--lane alpha`) and make sure it's still
  running, that the login `<device>` matches `--device`, and that your rig points at
  the **same region host** the companion enrolled against.
- **GPU not detected.** Confirm `nvidia-smi` works; list the miner's own device ids
  with `alice-miner gpu-devices`.
- **Watch-only can't prove possession.** A pasted-address identity has no signing
  key. `identity --create` or `--import` a real one for a PoP lane / the companion.

---

## 中文指南

Alice 挖矿的运作方式、如何为你的硬件选择通道(lane),以及如何把你**自己的**第三方
(闭源)矿机接入 Alice 网络。

> **仅记积分(credit-only)。** 以下所有奖励都以**积分**形式累计,**不是现金**,本
> 指南**不做任何**收益、发放或盈利承诺。积分只在真实资金上线时才转换为 ALICE;在此
> 之前结算与链上转账均处于关闭状态。

### 一、挖矿如何运作

你挖的**不是**一个全新的、未经检验的币,而是**既有币的真实 share** —— 用 CPU 挖
Monero(XMR),或用 GPU 挖 pearlhash 币(PRL),用的是久经考验的挖矿引擎。Alice 位
于这项工作之前,并为它给你记积分。

- **Alice 度量什么:** 你提交的每个有效 share 都带有*难度*(证明了多少工作量)。
  Alice 按每个地址贡献的难度加权总量记账 —— 你是因**证明的工作**而被奖励,而不是
  因为一个承诺。
- **ALICE 如何分配:** 排放按 **6 小时一轮**进行。每轮铸出一批固定的 ALICE 积分,
  并分到**三个硬件池**:**GPU 70% / CPU 15% / ASIC 15%**。池内你的份额 = 你这一轮
  的**难度加权贡献**。没有上游门槛 —— 无论上游返回什么,每轮都照常按时铸出积分。
- **从你这一侧看的链路(用户视角):**

```
  你的矿机 ──stratum──▶  Alice 区域中继  ──▶  (该币的网络)
                              │
                              ▼
                   你被接受的 share 被计入
                              │
                              ▼
              归属到你自己的 Alice 地址(blake2b 校验)
                              │
                              ▼
        每 6 小时:ALICE 积分按难度加权、70/15/15 分配
```

你只需配置中继这一个地址。你的奖励身份是一个 **Alice 地址**;你连接时用的登录名
决定积分归属到谁(见二、三节)。

> **诚实框定:** 网络当前为 **credit-only**:奖励以计数形式累积,不结算为任何货币。
> 积分何时可领取是上线决策,不是本工具的承诺。

### 二、选择你的通道(lane)

最快的方式是让客户端替你判断:

```sh
alice-miner guide          # 检测硬件 → 推荐通道 + 为什么 → 如何连接
alice-miner guide --json   # 同上,机器可读(供脚本 / 官网使用)
```

`guide` 是**只读顾问** —— 检测 CPU/GPU、用一句话说明推荐理由、并打印两种连接方式
(官方客户端,或你自己的矿机)。它不需要身份、也不写入任何东西。

| 通道 | `--lane` | 硬件 | 算法 | 中继端点 | 说明 |
| ---- | -------- | ---- | ---- | -------- | ---- |
| **GPU · PRL** | `gpu` / `prl` | NVIDIA(CUDA 算力 ≥ 7.5)/ AMD(OpenCL) | `pearlhash` | `us` / `asia` / `eu.aliceprotocol.org : 3340` | **GPU 主线**,需 PoP(所有权证明)。 |
| **GPU · Alpha** | `alpha` | Volta / V100 架构 NVIDIA | `pearlhash` | `us` / `asia` / `eu.aliceprotocol.org : 3341` | SRBMiner 跑不了的卡的 pearlhash 路径,需 PoP。 |
| **CPU · XMR** | `xmr` | 任意 CPU(RandomX) | `rx/0` | `hk.aliceprotocol.org : 3333` | 开放注册,无需证明、无需 GPU。 |
| **GPU · RVN** | `rvn` | NVIDIA(KawPoW) | `kawpow` | `hk.aliceprotocol.org : 8888` | 旧路径;如今 pearlhash 才是主线。 |
| **ASIC · scrypt** | — | scrypt ASIC(LTC 系) | `scrypt` | *见下* | 15% 的 ASIC 池,尚未成为自助客户端通道。 |

- **算力级别,而非任何数字承诺:** 不同硬件的出力天差地别,客户端会用合适的单位显示
  你的实时算力 —— CPU 以 **kH/s**、pearlhash GPU 以 **MH/s–TH/s**、ASIC 以
  **GH/s–TH/s**。用 `alice-miner detect` 查看本机可用通道。我们**刻意不**给出任何
  预期数字 —— 积分取决于每一轮全网的贡献,且尚未结算为任何货币。
- **绝不使用 FI 区域:** `fi.aliceprotocol.org` 是死区(NXDOMAIN),v0.6.1 起已移除
  —— pearlhash 通道现有 `us`、`asia`、`eu` 可用(EU 于 v0.6.2 上线)。
- **AMD 是 OpenCL 例外:** 「算力 ≥ 7.5」是 NVIDIA(CUDA)的指标;AMD 卡没有 CUDA
  算力(compute capability)这个数字,而是通过矿机的 **OpenCL** 后端跑 pearlhash ——
  所以该算力门槛对 AMD 不适用。
- **关于 ASIC / scrypt 池:** 15% 的 ASIC 池是排放的真实组成部分,Alice 中继在上游也
  说 scrypt(LTC 系)stratum 协议。但 scrypt **尚未成为自助客户端通道**:官方客户端
  不打包 scrypt 矿机(ASIC 本就跑自己的固件),本版本也没有公开的自助 scrypt 端点。
  若你有 scrypt ASIC 矿场想接入,请关注
  [发布页](https://github.com/V-SK/Alice-Miner/releases),并在后续版本中查看
  `alice-miner guide` —— 自助上线后本节会给出端点。

### 三、自带第三方 PRL 矿机(重点)

你**不必**使用内置矿机。如果你有**自己的** pearlhash 矿机 —— 手工调优的、闭源优化
的、或已经指向其他矿池的矿场 —— 都可以把它指向 Alice,并把积分路由到**你自己的**
Alice 地址,而且**你的私钥绝不接触矿机**。

> 内置客户端本身也只是一个第三方 stratum 矿机的监督器(supervisor),所以"自带矿机"
> 是同构的 —— 你只是换上自己的矿机,让一个小小的 Alice 助手替它持有所有权证明。

**适合谁:** 跑优化 / 闭源 pearlhash 矿机、用自己工具管理矿场、或想保留现有挖矿设置
但用 Alice 奖励路由的人。若你只想在一台机器上挖,直接用内置的
`alice-miner start --lane gpu` 更简单(上述工作它会在内部替你完成)。

**为什么需要伴侣(companion)—— 所有权证明 / 反女巫:** PRL / Alpha 中继开启了
**`REQUIRE_POP=1`**:裸登录会被拒(`code:24`)。中继在给某地址记 share 前,要求证明
这个连接确实由该地址的持有者控制 —— 这是反女巫门,防止有人把积分刷进自己并不拥有的
地址。内置客户端在**内部**完成证明;第三方矿机不会做这件事,所以
**`alice-miner companion`** 替它来做:① 在**本机**解锁你的 Alice 签名密钥(密钥绝不
离开本机);② 运行与官方通道相同的 挑战 → 签名 → 注册 握手;③ 按刷新周期循环(默认
约 9 分钟,稳稳落在中继约 1800 秒的允许名单窗口内)。它**绝不启动矿机** —— 你的矿机
负责哈希,伴侣只持有证明。

**步骤:**

**a) 安装官方 CLI 并设置你的 Alice 地址**

```sh
alice-miner identity --create               # 生成 24 词助记词(会打印 —— 请离线备份)
alice-miner identity --import "<24 个词>"   # 或导入你已拥有的身份
alice-miner identity --show                 # 打印奖励地址(公开、可安全分享)
# 可选:记录未来 15% PRL 返还地址(你自己的 prl1p… 地址,仅存配置、现在不发放):
alice-miner identity --set-prl-payout <prl1p…>
```

> **watch-only** 身份(`identity --paste <地址>`)没有签名密钥,**无法**运行伴侣 ——
> 所有权证明需要密钥。自带矿机请用 `--create` 或 `--import`。

**b) 启动伴侣(它持有证明,不挖矿)**

```sh
alice-miner companion --lane prl --device rig1
```

它解锁你的密钥(会提示输入 keystore 口令;脚本用 `--password-stdin`),然后打印一段
**连接横幅**,给出你的矿机要用的中继主机、端口和登录名。常用选项:

```sh
alice-miner companion --lane prl --device rig1 --region asia   # 固定 us | asia | eu(默认最近/记忆)
alice-miner companion --lane alpha --device volta1             # Volta / V100 矿机(端口 3341)
alice-miner companion --lane prl --address <alice-地址>        # 显式指定地址 —— 必须是你本机身份的地址(见下方说明)
alice-miner doctor --lane prl                                  # 含 "companion (PoP)" 就绪检查
```

> **两个不同的地址 —— 别混淆。**
> - **挖矿身份地址**是伴侣注册的 Alice 地址。伴侣用**你本机的签名密钥**签署所有权证明,
>   中继会用被注册的地址来验签 —— 所以被注册的地址**必须**是你这把密钥所派生的地址。
>   你**无法**用 `--address` 去注册**别的**地址(你没有那把私钥签不了名,中继永远不会把它
>   加入允许名单 —— 矿机只会一直卡在 `code:24`)。`--address` 只是让你显式写出自己的地址;
>   若它不是你的签名身份,伴侣会当场拒绝。**要挖到另一个地址,请切换身份**
>   (`identity --import`),而不是用 `--address`。
> - **PRL 返现地址**是一个**独立**的 `prl1p…` 地址(`identity --set-prl-payout`),用于将来
>   15% 的 PRL 返还去处。它与由谁来挖、与伴侣都无关 —— 设置它不会改变你的挖矿身份。

**c) 把你自己的 pearlhash 矿机指向该中继**,使用横幅打印的值:

| 字段 | 值 |
| ---- | -- |
| **矿池 / host:port** | 横幅给出的主机+端口,例如 `asia.aliceprotocol.org:3340` |
| **算法** | `pearlhash` |
| **登录名 / user / 钱包** | `<你的-alice-地址>.<设备名>`,例如 `<你的-地址>.rig1` |
| **密码** | 任意值(如 `x`)—— 授权在带外,由伴侣持有 |

登录名里的 `<设备名>` **必须**与你给伴侣的 `--device` 一致(那是伴侣注册的配对);
且矿机要用伴侣打印的**同一区域主机**(允许名单是按中继划分的)。

**常见问题:**

- **为什么必须要伴侣?** 中继是 PoP 门控的,防止有人把 share 记进自己不控制的地址。
  伴侣就是第三方矿机通过这道门的方式。
- **伴侣必须全程常开吗?** **是。** 中继授权是短时的(约 1800 秒),伴侣循环续证。
  伴侣一停,配对失效,中继就不再给新 share 记账。请与矿机一起保持运行。
- **私钥会上矿机吗?** **绝不会。** 密钥只在运行伴侣的机器上于内存中解锁、仅用于签署
  证明;矿机用一个随意密码连接,不持有密钥。
- **能把伴侣跑在与矿机不同的机器上吗?** 可以。伴侣只需你的 keystore 和到中继的出站
  HTTPS。把每台矿机的登录名都指向同一地址的 `<地址>.<设备名>`,并固定到伴侣注册的
  区域。
- **`--address` 能注册一个*不同*的奖励地址吗?** **不能。** 伴侣用你本机的密钥签署证明,
  所以它只能注册这把密钥所派生的地址 —— `--address` 只是让你显式写出自己的地址(若不是你的
  签名身份,伴侣会当场拒绝)。要挖到另一个地址,请切换身份(`identity --import`)。PRL 返现
  地址是另一项独立设置(`identity --set-prl-payout`),不改变由谁来挖。
- **绝不使用 FI 区域:** `fi.aliceprotocol.org` 是死区(NXDOMAIN),只用 `us` / `asia` / `eu`。
- **地址写错会被拒:** 登录地址会做 SS58 format-300 校验,写错不会悄悄记给别人,只是
  不被授权。请从 `alice-miner identity --show` 复制。
- **CPU-XMR 不需要这些:** XMR 是开放注册 —— 直接指向 `hk.aliceprotocol.org:3333`、
  `rx/0`、登录 `<地址>.<worker>`、密码 `x`,无需伴侣。

### 四、平台差异与故障排查

**先跑 `doctor`:** `alice-miner doctor` 逐项打印 PASS / WARN / FAIL **和确切修法**,
有 FAIL 时退出码非零。`--lane prl` 含伴侣 / PoP 检查;`--fix` 应用安全自动修复
(绝不动身份 / keystore);`--json` 机器可读。

- **Windows 杀软 / Defender:** CPU 引擎首次运行时下载,可能触发 Defender 的 PUA 启发
  式(所有矿机通病)。按发布说明加排除项。
- **Windows 中文亂碼:** v0.6.0 及更早版本在繁體中文 Windows 的 `cmd.exe` / PowerShell
  下,中文可能顯示為亂碼;啟動前先執行 `chcp 65001`。下個版本起會自動切到 UTF-8。
- **Windows 远程桌面白屏:** 通过 RDP / AnyDesk / TeamViewer / 向日葵 驱动机器时桌面
  应用若开成纯白,见 [`remote-desktop.md`](remote-desktop.md) —— 设
  `ALICE_GUI_RENDERER=wgpu`。无界面 CLI 不受此影响,也是无头矿机的推荐路径。
- **macOS 仅支持 Apple 芯片:** macOS 产物只有 `aarch64-apple-darwin`,没有 Intel
  (x86_64)构建;Rosetta 也帮不上忙(它是把 Intel 程序翻译到 Apple 芯片上跑,反过来
  不行)。Intel Mac 上这个 App 根本打不开 —— 请改用 Linux 或 Windows 的机器挖矿。最低
  系统 macOS 11 Big Sur。
- **macOS 必须装进 `/Applications`:** 解压 `AliceMiner-macos-arm64.zip` 后,**先把
  `AliceMiner.app` 拖进 `/Applications`** 再首次打开。若直接从 `~/下载` 打开,带隔离
  标记的 App 会被 **App Translocation**(应用位置随机化)从一个随机只读挂载点运行 ——
  这正是「点了没反应」和「设置每次都丢」的常见根因。移动 App 包即可解除。
- **macOS Gatekeeper:** 应用是 ad-hoc 签名(无付费 Apple 证书),首次启动会被拒绝并提示
  「无法验证开发者」。关掉该提示,然后打开**系统设置 → 隐私与安全性 → 仍要打开**(再确认
  一次「打开」),之后即可正常启动。等效的一条命令(**须在 App 已移入 `/Applications`
  之后**执行):

  ```bash
  xattr -dr com.apple.quarantine /Applications/AliceMiner.app
  ```

  > **「右键 → 打开」已经失效。** macOS 15(Sequoia)取消了对无开发者证书 App 的这条
  > Gatekeeper 捷径。任何仍这样教的文档 —— 包括本文的早期版本 —— 都已过时,请用
  > 「隐私与安全性 → 仍要打开」。
- **macOS 的 CLI 就在 App 包里:** 没有单独的 macOS CLI 下载:

  ```bash
  /Applications/AliceMiner.app/Contents/MacOS/alice-miner-cli start --lane xmr
  ```
- **macOS App Nap → 约 0 H/s:** 隐藏窗口会把算力压到近零;打包版自动规避,裸 CLI 可用
  `caffeinate -dimsu alice-miner start …` 包一层。
- **macOS 上的 PRL / Alpha:** 没有 macOS SRBMiner pearlhash 构建,所以 Apple Silicon
  上 pearlhash 通道不可用 —— 这也是 `guide` 在 Mac 上推荐 XMR 的原因。
- **Linux 无头无 keyring:** 后台跑 **GPU** 通道需要 OS keyring 持有钱包解锁;无 Secret
  Service 的无头机器无法后台 GPU 通道 —— 请保持窗口打开、改后台 CPU-XMR、或用自带矿机
  的伴侣模式(第三节)。
- **`code:24` / PRL 登录被拒:** 中继是 PoP 门控的。运行
  `alice-miner companion --lane prl`(或 `--lane alpha`),确认它仍在运行、登录名
  `<设备名>` 与 `--device` 一致、且矿机指向伴侣注册的同一区域主机。

---

> **仅记积分复述:** 本指南全文所述奖励均为积分(积分),不是现金,无收益 / 发放 /
> 盈利承诺 —— 发放在真实资金上线前保持关闭。地址是公开的、可安全分享;助记词与
> keystore 是密钥,请离线备份、切勿分享。
