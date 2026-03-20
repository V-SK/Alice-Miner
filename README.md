# Alice Miner

[中文版 →](README_CN.md)

Mine **ALICE** tokens by training AI. GPU miner for [Alice Protocol](https://aliceprotocol.org) — the decentralized AI training network.

## What is Alice?

Alice is training AI from scratch — no fine-tuning, no corporate models, no dependencies. Every weight is computed by the network's miners. You contribute GPU power, earn ALICE tokens proportional to your gradient quality.

## Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| GPU VRAM | 24 GB | 24 GB+ |
| System RAM | 16 GB | 32 GB |
| Disk | 20 GB | 30 GB |
| Network | 10 Mbps | 50 Mbps+ |
| Python | 3.10+ | 3.11+ |

**Supported GPUs:** Any NVIDIA GPU with 24GB+ VRAM (RTX 3090, 4090, A5000, A6000, etc.)

**Also supported:** Any Apple Silicon Mac (M-chip) with 24GB+ unified memory.

## Quick Start

```bash
# 1. Clone
git clone https://github.com/V-SK/Alice-Miner.git
cd Alice-Miner

# 2. Install dependencies
pip install -r requirements.txt

# For CUDA (recommended):
pip install torch --index-url https://download.pytorch.org/whl/cu121

# 3. Start mining
./start_mining.sh --gpus all
```

On first run, you'll be prompted to either create a new wallet or enter an existing Alice address. A wallet is optional — you just need an address to receive mining rewards.

## Usage

### start_mining.sh (recommended)

```bash
# All GPUs
./start_mining.sh --address a2xxx --gpus all

# Specific GPUs
./start_mining.sh --address a2xxx --gpus 0,1

# Apple Silicon
./start_mining.sh --address a2xxx --gpus mps

# CPU only (not recommended)
./start_mining.sh --address a2xxx --gpus cpu

# Custom PS URL
./start_mining.sh --address a2xxx --gpus all --ps-url https://ps.aliceprotocol.org
```

### Direct Python

```bash
python alice_miner.py \
  --ps-url https://ps.aliceprotocol.org \
  --device cuda \
  --batch-size 2 \
  --precision fp16
```

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--ps-url` | required | Parameter server URL |
| `--device` | auto | `cuda`, `mps`, or `cpu` |
| `--batch-size` | 2 | Training batch size |
| `--precision` | auto | `fp16`, `fp32`, or `auto` |
| `--max-batches` | 10 | Max batches per shard |
| `--seq-len` | 128 | Sequence length |
| `--lr` | 1e-5 | Gradient scale factor |
| `--wallet-path` | ~/.alice/wallet.json | Wallet file path |
| `--model-path` | auto | Skip model download |

## How It Works

1. **Connect** — Miner connects to the Parameter Server and downloads the current model (~13 GB)
2. **Train** — Receives a data shard, trains assigned layers, computes gradients
3. **Submit** — Compresses gradients (TopK 0.1% + zlib) and submits to PS
4. **Score** — Independent validators score gradient quality (loss improvement)
5. **Earn** — ALICE tokens distributed proportional to your score contribution

### Layer Assignment

The miner auto-detects your GPU VRAM and assigns layers:

| VRAM | Layers | Notes |
|------|--------|-------|
| 24 GB (CUDA) | 24 | Most consumer GPUs |
| 40 GB+ (CUDA) | 32 | Full model (A6000, etc.) |
| 32 GB (MPS) | 30 | Apple Silicon Max chips |
| 16 GB (MPS) | 14 | Apple Silicon (experimental) |
| CPU | 4 | Not recommended |

## Rewards

- **Total supply:** 21,000,000 ALICE (never more)
- **Year 1-2 budget:** 5,250,000 ALICE/year, halving every 2 years
- **Per-epoch reward:** ~600 ALICE (epoch ≈ 60 minutes)
- **Trainer share:** 56-90% (dynamic, based on network composition)
- **Infrastructure:** fixed 9% (validators 5% + aggregators 2% + scheduler 2%)
- **Distribution:** proportional to your gradient score vs total score

### Solo vs Pool

| Mode | Effective Hashrate | Notes |
|------|-------------------|-------|
| Solo | 15-25% | Direct submission, higher staleness |
| Pool | 30-45% | Internal aggregation, optimizers, more stable |

Joining a mining pool can roughly **double** your effective contribution.

## Vast.ai Setup

```bash
# Use /dev/shm for model storage (overlay disk is limited)
python alice_miner.py \
  --ps-url https://ps.aliceprotocol.org \
  --model-path /dev/shm/models \
  --device cuda \
  --batch-size 2
```

## Troubleshooting

| Issue | Fix |
|-------|-----|
| OOM (Out of Memory) | `--batch-size 1` or `--precision fp16` |
| Vast.ai disk full | Use `--model-path /dev/shm/models` |
| Slow model download | Pre-download: `wget https://dl.aliceprotocol.org/v{VERSION}_layers_0-31.pt` |
| Connection refused | Check PS status: `curl https://ps.aliceprotocol.org/status` |
| MPS crash | Set `--precision fp16` and `--batch-size 1` |

## Links

- [Website](https://aliceprotocol.org)
- [Whitepaper](https://dl.aliceprotocol.org/whitepaper)
- [PS Status](https://ps.aliceprotocol.org/status)
- [Twitter](https://twitter.com/Alice_AI102)

## License

MIT
