# Alice Miner — UI/UX Design System & Key Screens

> Status: design spec (research only — no product source touched).
> Scope: the desktop **Alice Miner** client — a dead-simple, *beautiful* one-click miner.
> Sibling app of `alice-wallet/gui` (egui/eframe). Reuses its crypto, XMR supervisor,
> signing/update pipeline; reuses the website's brand system verbatim.
> Companion artifact: **`/Users/v/Alice/alice-miner/docs/design/mockup.html`** (open in a browser).

---

## 0. Design north star

V's bar is **漂亮 / 好看 / 流畅** — beautiful, refined, fluid. Polish is a *hard requirement*, not garnish. Three principles drive every decision:

1. **One glance, one click.** The Home screen must answer "what will happen if I press this?" before the user reads anything. Device + lane are *shown, already decided*. The button is the hero.
2. **Calm, premium, dark.** The existing Alice site is a glass-morphism dark theme with a single orange spine. The Miner is its native desktop sibling — same palette, same logo, same JetBrains-Mono numerals. It should feel like one product family, not a port.
3. **Honest by construction.** Rewards are **pending (待发放)** — never "credit", never "paid", never a fiat figure. The UI is engineered so it is *impossible* to imply a payout (see §7 reward-wording contract). This is a trust signal, and trust is part of "beautiful."

### Rendering stack decision (load-bearing)

The Wallet GUI is **egui / eframe** (immediate-mode Rust). The Miner **reuses the same stack** so it can directly link the Wallet's `crypto.rs`, `miner.rs`, and `supervise/miner_supervisor.rs` (per the crypto + miner-reuse surveys) without a second language/runtime. Therefore this design system is specified **twice over**:

- **Design tokens (§1–§4)** are the canonical source of truth, expressed as the same CSS-variable names the website already uses (`--a-bg`, `--a-brand-500`, …). The mockup renders them literally.
- **egui mapping (§9)** translates every token + component into concrete egui `Color32`, `Stroke`, `CornerRadius`, `Margin`, and named widget fns, so the build is a transcription, not a reinterpretation.

The mockup.html is the **visual contract**: pixel-target for the egui build. If egui and the mockup ever disagree, the mockup wins on look, the tokens win on value.

---

## 1. Color system (dark theme — the only theme)

Lifted verbatim from `/Users/v/Alice/alice-website/assets/alice-theme.html`. Do **not** invent new hues; the orange spine and zinc surfaces are the brand.

### 1.1 Brand orange (the spine)
| Token | Hex | Use |
|---|---|---|
| `--a-brand-50` | `#FFF7ED` | faint wash (rarely) |
| `--a-brand-300` (`--a-text-brand`) | `#FDBA74` | links / active label on dark |
| `--a-brand-400` | `#FB923C` | CPU/XMR lane accent, gradient top |
| **`--a-brand-500`** | **`#F97316`** | **logo + primary action (the spine)** |
| `--a-brand-600` (`--a-brand-strong`) | `#EA580C` | hover / pressed |
| `--a-brand-700` | `#C2410C` | gradient bottom |

### 1.2 Surfaces & lines
| Token | Value | Use |
|---|---|---|
| `--a-bg` | `#050505` | window background |
| `--a-bg-2` | `#0A0A0A` | alt section / sidebar |
| `--a-surface` | `rgba(24,24,27,0.62)` | card / panel glass (zinc-900) |
| `--a-surface-2` | `rgba(39,39,42,0.55)` | hover / nested / selected chip |
| `--a-elevate` | `linear-gradient(180deg, rgba(39,39,42,0.82), rgba(9,9,11,0.82))` | stat tiles |
| `--a-line` | `rgba(63,63,70,0.55)` | default hairline |
| `--a-line-strong` | `rgba(63,63,70,0.82)` | panel / input border |
| `--a-line-brand` | `rgba(249,115,22,0.30)` | brand-emphasis border, focus |

### 1.3 Text
| Token | Hex | Use |
|---|---|---|
| `--a-text` | `#FAFAFA` | primary |
| `--a-text-2` | `#A1A1AA` | secondary |
| `--a-text-3` | `#71717A` | muted / uppercase labels / captions |
| `--a-text-brand` | `#FDBA74` | active / link |

### 1.4 Status & lane colors
Status: `--a-live #22C55E` (mining/online) · `--a-warn #F59E0B` (connecting/checking) · `--a-info #3B82F6` (neutral data) · `--a-violet #A855F7` (AI) · `--a-off #71717A` (idle/disabled). Error uses red `#EF4444` (add as `--a-err`; the site implies it but the Miner needs an explicit fault state).

**Lane colors** (match `mine.html` exactly so web ↔ desktop read identically):
| Lane | Token | Hex | Algo |
|---|---|---|---|
| CPU / XMR | `--lane-xmr` | `#FB923C` | RandomX |
| GPU / RVN | `--lane-gpu` | `#3B82F6` | KawPoW |
| Mac (Apple Silicon) | `--lane-mac` | `#22D3EE` | RandomX |
| ASIC / LTC | `--lane-asic` | `#34D399` | Scrypt (info-only client) |
| AI | `--lane-ai` | `#A855F7` | inference |

Lane color is used as a **2px top-edge accent** on the active device tile and as the `.ldot` dot before a lane label — never as large fills (keeps the orange spine dominant).

---

## 2. Typography

| Family | Token | Role |
|---|---|---|
| **Inter** (400/500/600/700/800) | `--a-font-sans` | all UI text |
| **JetBrains Mono** (400/500/600/700) | `--a-font-mono` | **every number, hashrate, address, hash, share count** |
| Noto Sans SC (subset) | fallback | CJK (zh) |

Fonts ship **bundled** (the Wallet already vendors them at `alice-wallet/gui/assets/fonts/*.ttf`; reuse those exact TTFs in the Miner's egui `FontDefinitions` — no network fetch).

**Scale** (rem; egui pt in §9): display `clamp(2.25rem,4.5vw,3.5rem)` · h1 `2rem` · h2 `1.5rem` · h3 `1.25rem` · lg `1.125rem` · base `1rem` · sm `0.875rem` · xs `0.75rem` · 2xs `0.6875rem`.

**Rules.** Body = Inter 400. Section/stat **labels = uppercase, `letter-spacing 0.12em`, `--a-text-3`, xs**. Eyebrows = uppercase `0.2em`, `--a-text-brand`. **Stat values = JetBrains Mono 600, line-height 1.1.** Addresses/hashes = mono with `overflow-wrap: anywhere`. The hero hashrate number is the one place the display size is used inside the app.

---

## 3. Spacing, radius, layout

**8px base unit.** `--a-sp-1 .25rem` · `-2 .5rem` · `-3 .75rem` · `-4 1rem` · `-6 1.5rem` · `-8 2rem` · `-12 3rem` · `-16 4rem`.

**Radius.** Cards `--a-radius 1rem` (16px) · inputs/badges `--a-radius-sm .625rem` (10px) · hero/primary panels `--a-radius-lg 1.25rem` (20px) · pills `999px`.

**Window & layout.** Desktop app, **min 920×640, default 1040×720** (smaller than the Wallet — the Miner is focused, not a console). Two-zone layout:

```
┌───────────────────────────────────────────────────────────┐
│  ◭ Alice Miner            ● Mining · XMR        ⚙  ?  zh/EN │  titlebar (56px, drag region)
├──────┬────────────────────────────────────────────────────┤
│      │                                                     │
│ rail │                  CONTENT (router)                   │
│ 72px │           Home · Dashboard · Settings               │
│ icons│                                                     │
└──────┴────────────────────────────────────────────────────┘
```

- **Left rail** 72px: logo top; three icon-nav items (Home / Dashboard / Settings) with the active item showing a brand-orange 2px left bar + brand-tinted icon; an `i18n` toggle + version pinned bottom. Tooltips on hover.
- **Top titlebar** 56px: custom (frameless window via egui `viewport`), doubles as the drag region. Right side carries the **global mining status pill** (so state is visible from any screen), settings gear, help, lang.
- **Content** uses `.a-container` rhythm: 24px outer padding, cards gapped 16px, sections 32–48px apart. Max content width ~880px, centered, so it never feels stretched on big monitors.

---

## 4. Elevation, shadow, motion (the "流畅" feel)

**Shadows.** `--a-glow 0 0 24px rgba(249,115,22,.30)` (primary CTA hover, active mining pulse) · `--a-glow-soft 0 0 16px rgba(249,115,22,.18)` · `--a-card 0 1px 0 rgba(255,255,255,.04) inset, 0 8px 24px rgba(0,0,0,.45)` (every card: an inset top highlight + soft depth — this is what makes glass look lit, not flat).

**Motion.** One easing, one duration: `--a-ease cubic-bezier(.22,1,.36,1)`, `--a-dur .2s`. Rules:
- Cards lift `translateY(-2px)` + border → `--a-line-brand` on hover.
- The big **Start button** has a resting `--a-glow-soft`; on hover it brightens to `--a-glow` and the orange deepens to `--a-brand-600`. On press it scales `.985`.
- **Mining = a living pulse**, not a spinner. When active, the status dot and the hero ring run `pulse-glow 3s ease-in-out infinite` (already in the theme). This is the single signature animation — calm, breathing, premium.
- **Connecting** = the warn-amber dot does a faster 1.2s pulse; the hero ring shows an indeterminate sweep (a conic-gradient arc rotating once per 1.4s).
- Number transitions (hashrate, shares) **tween over 300ms** toward the new value instead of snapping (in egui: lerp the displayed float toward target each frame) — this is the difference between "twitchy" and "fluid."
- Respect `prefers-reduced-motion` / an in-app "reduce motion" setting: kill pulses, keep static color states.

Micro-interactions: copy-address shows a 1.2s "Copied ✓" inline swap; toggles slide 150ms; the lane chip that wins selection gets a brief 1-frame brand flash.

---

## 5. Component inventory (shared widget set)

All map to a named egui fn in §9 and to a `.a-*` class in the mockup. This is the kit; screens are assembled from it.

| Component | Class / fn | Notes |
|---|---|---|
| Card | `.a-card` / `card()` | glass surface, 16px radius, 24px pad, card-shadow, hover-lift variant |
| Panel | `.a-panel` / `panel()` | stronger border, no hover (containers) |
| Stat tile | `.a-stat` / `stat_tile()` | elevate gradient; label(2xs upper) + mono value + meta |
| Primary button | `.a-btn-primary` / `btn_primary()` | brand fill, ink text `#1A0A00`, glow on hover |
| Ghost button | `.a-btn-ghost` / `btn_ghost()` | transparent, brand border+text on hover |
| Hero Start button | `.start-btn` / `hero_start()` | the one-click — see §6.2 |
| Input | `.a-input` / `text_input()` | dark, mono, brand focus ring |
| Badge (state pill) | `.a-badge-*` / `badge()` | pending / live / neutral / paid(muted) / error |
| Status dot | `.a-dot-*` / `status_dot()` | online(green) / checking(amber) / offline(zinc) / mining(green pulse) |
| Device tile | `.dev` / `device_tile()` | icon + name + algo + hint; lane top-accent; selected state |
| Lane chip | `.lane-chip` / `lane_chip()` | `●` lane-dot + "XMR · RandomX" |
| Eyebrow | `.a-eyebrow` | uppercase 0.2em brand label above a heading |
| Log console | `.log` / `log_view()` | mono, dim, monoscroll, last-line highlighted |
| Toast | `.toast` / `toast()` | bottom-right, glass, auto-dismiss 3s |
| Hashrate ring | `.hr-ring` / `hashrate_ring()` | conic gauge around the hero number (see §6.3) |

---

## 6. Key screen — HOME (the big one-click)

> The product *is* this screen. Everything else is support.

### 6.1 Layout (idle, address already set)

```
        ALICE MINER · 极简一键
   ┌─────────────────────────────────────────────────┐
   │              [ device auto-detected ]            │   eyebrow
   │                                                  │
   │     🍎  Apple M2 Max · 12 cores                  │   detected device line
   │         ● XMR · RandomX            [change ▾]    │   lane chip + manual override
   │                                                  │
   │              ╭───────────────────╮               │
   │              │                   │               │
   │              │   ▶  START        │   ← hero      │   the one button
   │              │                   │               │
   │              ╰───────────────────╯               │
   │                                                  │
   │   Rewards to  a2x9…7fQk   [copy]   ✎ change      │   reward identity row
   │   ● Idle — press Start to begin                  │   status line
   └─────────────────────────────────────────────────┘
        Rewards accrue as pending (待发放). Payout is gated.   footnote
```

The whole screen is **one tall centered card** (max-width 560px) floating on `--a-bg`, vertically centered. Generous negative space — this is the "calm" that reads as premium. No menus competing with the button.

### 6.2 The hero Start button
- ~200×200 rounded-square (`--a-radius-lg` ×, actually a 28px radius squircle), brand-orange fill with a subtle top-down gradient `--a-brand-400 → --a-brand-600`, ink-dark glyph + label, resting `--a-glow-soft`.
- Idle label: **▶ START** (zh: **▶ 开始**). It is the only saturated-orange object on the screen, so the eye lands on it instantly.
- States below.

### 6.3 Home states (idle / connecting / mining / error)

| State | Hero | Status line | Dot |
|---|---|---|---|
| **Idle** | "▶ START", soft glow, gentle 4s breathing-scale | "Idle — press Start to begin" (zh 待机 — 点击开始) | offline (zinc) |
| **Connecting** | label → "Connecting…", indeterminate conic sweep arc around the squircle (1.4s) | "Connecting to hk.aliceprotocol.org · XMR :3333" | checking (amber, fast pulse) |
| **Mining** | label → "■ STOP"; the squircle is now ringed by a **hashrate gauge** (conic arc, fills relative to a rolling max), pulse-glow breathing; **center shows the live hashrate** in mono (e.g. `8.4 kH/s`) with the word "mining" tiny below | "Mining · M2 Max · 8 threads · 12/0 shares" (mono numerals) | mining (green, pulse) |
| **Error** | label → "Retry"; squircle border turns `--a-err`, glow off | red banner above the button: human message + a "View log" disclosure (e.g. "Lost connection — retrying in 5s" / "No miner binary — Download (38 MB)") | offline + small red |
| **Paused/stopping** | label dims to "Stopping…", non-interactive 5s grace | "Stopping…" | checking |

Mining is **opt-in and obvious**: pressing the button is the only thing that starts it; pressing again stops it (request_stop → 5s SIGTERM→SIGKILL per the supervisor survey). No background/auto-start. While mining, a slim **"Open dashboard →"** ghost link appears under the status line.

### 6.4 Dual-mine affordance
If the device exposes both a usable CPU and a discrete GPU, the lane chip becomes a **two-row stack** ("● XMR · RandomX (CPU)" + "● RVN · KawPoW (GPU)") with a single combined Start. A subtle "DUAL" neutral badge sits by the eyebrow. Default = on when both lanes are viable and the GPU binary is present; a Settings toggle governs it. (Windows: if xmrig isn't bundled, CPU lane shows "Download to enable" — GPU-only otherwise, per the Windows constraint.)

### 6.5 Empty / first-run state
If no Alice address exists in `~/.alice/identity.json`, Home does **not** render the button. Instead the card shows the **onboarding entry** (§8 routes here): a friendly one-liner + two buttons "Create address" / "Import". The button is intentionally gated until an identity exists — you can never reach a confusing "Start with no address" state.

---

## 7. Reward-wording contract (enforced, not stylistic)

From `mine.html` + the theme header + the project constraints, **user-facing**:
- Say **"Alice token rewards" / "Alice 代币奖励"**, and state accrual as **pending / 待发放**.
- **Never** the word *credit* in the UI. Never a `$`/fiat figure. Never "paid"/"已发放" as an active state — the paid badge exists only as a **muted, gated-OFF** style so it can never read as a live payout.
- A persistent, quiet footnote on Home + Dashboard: *"Rewards accrue as pending (待发放). Payout, settlement and on-chain transfer stay gated."* (zh: 贡献以 Alice 代币奖励的待发放状态累计;paid_acu = 0……).
- The dashboard "Estimated rewards" tile reads **`— pending`** until a rate is published (mirrors the calculator's `rate pending`). It shows accrued **score/shares**, framed as contribution, not money.

Implementation guard: a single `reward_label()` helper centralizes these strings (i18n keys), so no screen can hand-roll a non-compliant phrase. Add a unit test asserting the keys never contain `$`, "credit", or an active "paid".

---

## 8. Key screen — ONBOARDING (Create-or-Import)

Reuses the Wallet's `crypto.rs` (`create_wallet_payload`, `unlock_wallet`, SS58-300) and writes the **shared identity** `~/.alice/identity.json` + the shared encrypted keystore (per the crypto survey). The flow is a 3-step wizard inside the Home card frame (no separate window), with a top progress rail (3 dots).

**Step 0 — Choose.** Two big tiles: **Create new address** (recommended badge) / **I have an address (Import)**. A faint line: "One mnemonic works in Wallet, Miner, and AI."

**Create path**
1. **Set password** — single password field + confirm, a strength meter (mono), and a note: "Encrypts your key on this device (Argon2id + AES-256-GCM)." This password unlocks the shared keystore.
2. **Back up your mnemonic** — the 12/24 words shown in a numbered mono grid on a `--a-panel` with a copy button and a stern eyebrow "WRITE THIS DOWN". A checkbox "I saved it" gates Continue. (Force-backup is mandatory.)
3. **Confirm** — re-enter 3 random words (chips to tap, or type). On success: write identity.json + keystore, animate a brand check, route to Home with the button now live.

**Import path**
- A single textarea (mono) accepting a 12/24-word **mnemonic** (primary) — and, behind a "Advanced" disclosure, a raw seed-hex field (maps to `create_wallet_payload_from_seed_hex`). Live validation: word count + BIP39 checksum → green check or inline error. Then the same **set-password** step (to encrypt locally). On success → identity.json + keystore → Home.
- If `~/.alice/` already holds an identity from the Wallet/AI app, onboarding is **skipped entirely** — Home detects the shared identity and just shows the button (read-only consumer of the shared file). A tiny "Using your Alice address ✓" confirmation appears once.

**States.** Field validation inline (never modal). Password mismatch, bad mnemonic, keystore-write failure each show an `--a-err` inline message with a retry. A "Why no payout?" link opens a short explainer reaffirming credit-only.

**Address-only note.** Mining needs only the *address* (reward identity); the private key is generated/stored once and **never unlocked during mining**. The onboarding copy says exactly this, building trust.

---

## 9. Key screen — LIVE DASHBOARD

Reached from the rail or the Home "Open dashboard →" link. This is the "I left it running, how's it doing?" view. Layout = a header strip + a 2×2 stat grid + a lane breakdown + a log console.

```
  Dashboard                                   ● Mining · 02:14:30 uptime
  ───────────────────────────────────────────────────────────────────
  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
  │ HASHRATE     │ │ SHARES (A/R) │ │ ACCEPTED     │ │ EST. REWARDS │
  │ 8.42 kH/s    │ │ 142 / 1      │ │ 99.3%        │ │ — pending    │
  │ ▁▂▃▅▆▇▆▅ 60s │ │ last 12s ago │ │ rolling      │ │ 待发放        │
  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘

  LANES
  ● XMR · RandomX (CPU · 8 threads)   8.42 kH/s   142/1   ▇▇▇▇▇ live
  ● RVN · KawPoW (GPU · idle)         —           —/—     ○ off

  ENDPOINT     hk.aliceprotocol.org : 3333   ● connected · 41ms
  WORKER       a2x9…7fQk   (rig-id derived)         [copy address]

  LOG                                                   [copy] [clear]
  ┌─────────────────────────────────────────────────────────────────┐
  │ [12s] speed 10s/60s/15m 8420 8390 8200 H/s  max 8600 H/s         │
  │ [12s] net  accepted (142/1) diff 24010 (38 ms)                  │
  │ …                                                                 │
  └─────────────────────────────────────────────────────────────────┘
```

**Stat tiles** (the four; mono values, lerped):
1. **Hashrate** — live H/s with auto unit (H/kH/MH/GH), plus a 60-pt sparkline (last 60s of `parse_hashrate_hs`). The hero metric.
2. **Shares (A/R)** — accepted/rejected from `parse_share_counts`; "last share N s ago".
3. **Accepted %** — rolling acceptance; turns amber <97%, red <90%.
4. **Est. rewards** — **`— pending`** + 待发放 (per §7). Never money.

**Lane breakdown** — one row per active lane with its lane-dot color, role (CPU/GPU + threads), per-lane hashrate + shares, and a tiny live/off indicator. Makes dual-mine legible.

**Endpoint + worker** — host:port from the relay constant (`hk.aliceprotocol.org:3333`), a connected dot + latency, and the reward address (truncated, copyable). **Never** renders the collection address or upstream pool (server-side only — constraint honored in the UI by simply not having those fields).

**Log console** — sanitized xmrig stdout (reuse `sanitize_log_line`), mono, dim, the latest line slightly brighter, auto-scroll with a "pause on scroll-up" affordance, copy/clear. This is also the error surface (a red line stays pinned).

**States.** If not mining: tiles show `—`, a soft empty illustration, and a "Start mining" primary button that routes to Home/starts. Connecting: tiles show skeleton shimmer (a 1.2s gradient sweep). Error: the relevant tile + the log border go red; a banner offers Retry / View detail.

---

## 10. Key screen — SETTINGS

Grouped `--a-panel` sections, each row = label + control + helper text. Deliberately short — the product resists knobs.

1. **Identity** — active Alice address (mono, copy), "Reveal mnemonic" (requires password → unlock → show, then re-hide; reuses `unlock_wallet`), "Switch / import address", and a read-only note "Shared with Wallet & AI via ~/.alice".
2. **Mining** — Lane override (Auto ▾ / force CPU / force GPU / dual), **thread count** slider (1…N cores, default = `available_parallelism`, "拉满" full-power default with a note it only runs while you've pressed Start), GPU miner status (bundled KawPowMiner present? / "Download" button), "Start mining when app opens" (default **off** — opt-in only).
3. **Network** — endpoint = `hk.aliceprotocol.org` (read-only primary) + a list of failover endpoints (read-only, "client handles failover"). No collection/upstream fields exist.
4. **Appearance** — language (EN / 中文), Reduce motion, "Open at login" (off by default).
5. **Updates** — current version, channel, "Check for updates" (reuses the Wallet's signed `latest.json` ed25519 pipeline), last-checked time, changelog link.
6. **About** — logo, version, build hash, links (website /mine, docs, license), and the credit-only/pending explainer in full.

**States.** Reveal-mnemonic wrong password → inline error, no lockout drama. Update available → a brand-tinted row with "Update now". Each destructive-ish action (switch address) double-confirms.

---

## 11. egui mapping (build transcription)

So the build is mechanical. Reuse `alice-wallet/gui/src/ui/theme.rs` + `widgets.rs` as the starting point; add Miner-specific widgets.

**Tokens → egui** (in a `theme.rs`):
```
bg            = Color32::from_rgb(0x05,0x05,0x05)
bg_2          = Color32::from_rgb(0x0A,0x0A,0x0A)
surface       = Color32::from_rgba_unmultiplied(24,24,27,158)   // .62 alpha
surface_2     = Color32::from_rgba_unmultiplied(39,39,42,140)
line          = Color32::from_rgba_unmultiplied(63,63,70,140)
line_strong   = Color32::from_rgba_unmultiplied(63,63,70,209)
line_brand    = Color32::from_rgba_unmultiplied(249,115,22,76)
brand_500     = Color32::from_rgb(0xF9,0x73,0x16)
brand_600     = Color32::from_rgb(0xEA,0x58,0x0C)
brand_400     = Color32::from_rgb(0xFB,0x92,0x3C)
text          = Color32::from_rgb(0xFA,0xFA,0xFA)
text_2        = Color32::from_rgb(0xA1,0xA1,0xAA)
text_3        = Color32::from_rgb(0x71,0x71,0x7A)
text_brand    = Color32::from_rgb(0xFD,0xBA,0x74)
live=22C55E warn=F59E0B info=3B82F6 violet=A855F7 err=EF4444
lane_xmr=FB923C lane_gpu=3B82F6 lane_mac=22D3EE lane_asic=34D399 lane_ai=A855F7
radius: card=16 sm=10 lg=20  ;  pad: card=Margin::same(24)
font pt: display≈48, h1=32, h2=24, h3=20, lg=18, base=16, sm=14, xs=12, 2xs=11
```
Fonts: load the 4 bundled TTFs (Inter R/B, JetBrainsMono R/B) + NotoSansSC-Subset into `FontDefinitions`; mono family for all numerals.

**Glass + shadow in egui.** egui has no backdrop blur — approximate: `Frame::none().fill(surface).stroke(Stroke::new(1.0, line)).corner_radius(16).inner_margin(24)` plus a manual drop-shadow via `egui::epaint::Shadow { offset:[0,8], blur:24, spread:0, color: rgba(0,0,0,115) }` and a 1px top inset-highlight line painted manually. The pulse/glow = animate a second translucent stroke whose alpha follows `(time*2π/3).sin()` mapped 76→160 (`ctx.request_repaint()` while mining).

**Suggested file layout (new crate `alice-miner/`):**
```
alice-miner/
  Cargo.toml                 # deps: eframe/egui, + path dep on alice-crypto (extracted), tokio, serde
  src/
    main.rs                  # viewport (frameless 1040x720, min 920x640), font load, app state
    app.rs                   # AliceMinerApp: Screen{Onboard,Home,Dashboard,Settings}, mining FSM
    detect.rs                # device auto-detect → (DeviceClass, Lane[]) ; threads via available_parallelism
    identity.rs              # ~/.alice/identity.json read/write + shared keystore (REUSE alice-crypto)
    mining.rs                # build launch plan (REUSE wallet miner.rs constants + derive_worker_id)
    supervise/               # REUSE wallet miner_supervisor.rs (hashrate/share parsers, SIGTERM grace)
    ui/
      theme.rs               # tokens above (extend wallet theme.rs)
      widgets.rs             # card/stat_tile/badge/status_dot/device_tile/lane_chip/log_view/toast
      hero.rs                # hero_start() squircle + hashrate_ring() conic gauge
      onboarding.rs          # create/import wizard (steps)
      home.rs                # the one-click screen + states
      dashboard.rs           # stat grid + lanes + endpoint + log
      settings.rs            # grouped panels
    i18n.rs                  # EN/zh keys incl. reward_label() guard (REUSE wallet i18n shape)
  assets/
    brand/  (alice-logo.svg/png copied)   fonts/ (4 TTF + NotoSansSC copied)
  docs/design/  (this file + mockup.html)
```

---

## 12. Accessibility, i18n, platform polish
- **Contrast:** body text `#FAFAFA`/`#A1A1AA` on `#050505` clears WCAG AA; brand orange is used for large/bold or fills (ink text on it), not as small body text on dark.
- **Keyboard:** Tab order is button-first; Space/Enter on the hero = start/stop; Esc cancels a wizard step; every control is focusable with a brand focus ring.
- **i18n:** every string is a key; zh is first-class (the website ships full zh). Numbers stay mono in both. CJK uses NotoSansSC fallback.
- **Reduced motion:** a real setting + OS query; disables pulses/sweeps, keeps color states.
- **Frameless window niceties:** custom titlebar with proper drag region, OS traffic-lights (macOS) inset, remembers size/position, sane min-size so the hero never clips.
- **Tray (later, optional):** a menu-bar/tray dot mirroring mining state with Start/Stop/Open — flagged as a follow-up, not v1.

---

## 13. Open questions for V
1. **Tray/menu-bar presence** in v1, or keep it window-only for the first cut? (affects "set and forget" feel)
2. **Default thread count:** truly "拉满" (all cores) on first run, or leave 1–2 cores free so the machine stays usable while idle-mining? (Wallet does full-power; the Miner is more likely left running.)
3. **GPU binary delivery:** bundle KawPowMiner in the macOS/Linux build (per gpu-miners survey) vs. always download-on-demand like Windows xmrig? (size vs. friction vs. AV)
4. **AI-earn lane on Home v1:** show the AI lane as a third selectable lane now (violet), or keep it Dashboard-only/"coming soon" until the inference worker is wired?

---

## 14. Deliverable
- This spec: `/Users/v/Alice/alice-miner/docs/design/06-ui-ux.md`
- Visual contract (open in browser): **`/Users/v/Alice/alice-miner/docs/design/mockup.html`** — self-contained, inline CSS, no deps; renders the **Home** (one-click, idle→mining states) and the **Dashboard** (stat grid, lanes, endpoint, log) using the real Alice tokens.
