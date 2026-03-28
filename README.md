# Alice Miner

Training miner for Alice Protocol. Earn ALICE tokens by contributing GPU power.

## Requirements

- Python 3.10+
- NVIDIA GPU with 24GB+ VRAM (RTX 3090/4090/A5000+)
- CUDA 11.8+

## Quick Start

```bash
# 1. Clone
git clone https://github.com/V-SK/Alice-Miner.git
cd Alice-Miner

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run
python alice_miner_v2.py --address YOUR_WALLET_ADDRESS
```

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `--address` | ✅ | - | Your wallet address for rewards |
| `--ps-url` | ❌ | https://ps.aliceprotocol.org | Parameter Server URL |
| `--device` | ❌ | cuda | Device (cuda/cpu/mps) |
| `--max-batches` | ❌ | unlimited | Batches per epoch |

## Staking

Training miners do **NOT** require staking. Just run and earn.

## Create Wallet

```bash
pip install -r https://raw.githubusercontent.com/V-SK/alice-wallet/main/requirements.txt
git clone https://github.com/V-SK/alice-wallet.git
cd alice-wallet && python cli.py create
```

## Hardware Recommendations

| GPU | VRAM | Status |
|-----|------|--------|
| RTX 3090 | 24GB | ✅ Minimum |
| RTX 4090 | 24GB | ✅ Recommended |
| A100 | 40/80GB | ✅ Optimal |
