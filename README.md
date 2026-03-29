# Alice Miner

Training miner for Alice Protocol. Earn ALICE tokens by contributing compute power.

## Requirements

- Python 3.8+
- 24GB+ RAM/VRAM
- Supports: CUDA / MPS / CPU

## Quick Start

```bash
# 1. Clone
git clone https://github.com/V-SK/Alice-Miner.git
cd Alice-Miner

# 2. Install
pip install -r requirements.txt

# 3. Run
python alice_miner_v2.py --ps-url https://ps.aliceprotocol.org --address YOUR_WALLET_ADDRESS
```

## Device Detection

The miner auto-detects your device: CUDA (NVIDIA) → MPS (Apple Silicon) → CPU.

**Windows users with NVIDIA GPU — if auto-detection fails:**
```bash
python alice_miner_v2.py --address <YOUR_ADDRESS> --device cuda
```

**Override memory detection:**
```bash
python alice_miner_v2.py --address <YOUR_ADDRESS> --device cuda --memory-gb 24
```

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `--address` | ✅ | - | Your wallet address |
| `--ps-url` | ❌ | https://ps.aliceprotocol.org | Parameter Server |

## Staking

Training miners do **NOT** require staking. Just run and earn.

## Wallet

```bash
git clone https://github.com/V-SK/alice-wallet.git
cd alice-wallet && python cli.py create
```
