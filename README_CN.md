# Alice Miner（Alice 矿工）

[English →](README.md)

通过训练 AI 赚取 **ALICE** 代币。[Alice Protocol](https://aliceprotocol.org) GPU 矿工 — 去中心化 AI 训练网络。

## Alice 是什么？

Alice 从零开始训练 AI — 不微调、不依赖任何企业模型。每一个权重都由网络矿工计算产出。你贡献 GPU 算力，按梯度质量获得 ALICE 代币奖励。

## 硬件要求

| 项目 | 最低 | 推荐 |
|------|------|------|
| GPU 显存 | 24 GB | 24 GB+ |
| 系统内存 | 16 GB | 32 GB |
| 硬盘 | 20 GB | 30 GB |
| 网络 | 10 Mbps | 50 Mbps+ |
| Python | 3.10+ | 3.11+ |

**支持的 GPU**：任何 24GB+ 显存的 NVIDIA GPU（RTX 3090、4090、A5000、A6000 等）

**同样支持**：任何 24GB+ 统一内存的 Apple Silicon Mac（M芯片）。

## 快速开始

```bash
# 1. 克隆代码
git clone https://github.com/V-SK/Alice-Miner.git
cd Alice-Miner

# 2. 安装依赖
pip install -r requirements.txt

# CUDA 用户（推荐）：
pip install torch --index-url https://download.pytorch.org/whl/cu121

# 3. 开始挖矿
./start_mining.sh --gpus all
```

首次运行会提示你选择：创建新钱包或输入已有地址。钱包是可选的 — 你只需要一个地址来接收挖矿奖励。

## 使用方式

### start_mining.sh（推荐）

```bash
# 所有 GPU
./start_mining.sh --address a2xxx --gpus all

# 指定 GPU
./start_mining.sh --address a2xxx --gpus 0,1

# Apple Silicon
./start_mining.sh --address a2xxx --gpus mps

# 仅 CPU（不推荐）
./start_mining.sh --address a2xxx --gpus cpu

# 自定义 PS 地址
./start_mining.sh --address a2xxx --gpus all --ps-url https://ps.aliceprotocol.org
```

### 直接运行 Python

```bash
python alice_miner.py \
  --ps-url https://ps.aliceprotocol.org \
  --device cuda \
  --batch-size 2 \
  --precision fp16
```

### 参数说明

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--ps-url` | 必填 | 参数服务器地址 |
| `--device` | 自动 | `cuda`、`mps` 或 `cpu` |
| `--batch-size` | 2 | 训练批大小 |
| `--precision` | 自动 | `fp16`、`fp32` 或 `auto` |
| `--max-batches` | 10 | 每个分片最大批次数 |
| `--seq-len` | 128 | 序列长度 |
| `--lr` | 1e-5 | 梯度缩放因子 |
| `--wallet-path` | ~/.alice/wallet.json | 钱包文件路径 |
| `--model-path` | 自动 | 跳过模型下载（指定本地路径） |

## 工作原理

1. **连接** — 矿工连接参数服务器，下载当前模型（约 13 GB）
2. **训练** — 接收数据分片，训练分配的层，计算梯度
3. **提交** — 压缩梯度（TopK 0.1% + zlib）提交到参数服务器
4. **评分** — 独立验证者评估梯度质量（loss 改进程度）
5. **获奖** — 按你的评分占比分配 ALICE 代币

### 层分配

矿工自动检测 GPU 显存并分配训练层数：

| 显存 | 层数 | 说明 |
|------|------|------|
| 24 GB (CUDA) | 24 层 | 大部分消费级 GPU |
| 40 GB+ (CUDA) | 32 层 | 全量模型（A6000 等） |
| 32 GB (MPS) | 30 层 | Apple Silicon Max 芯片 |
| 16 GB (MPS) | 14 层 | Apple Silicon（实验性） |
| CPU | 4 层 | 不推荐 |

## 奖励

- **总供应量**：21,000,000 ALICE（永不增发）
- **第 1-2 年预算**：5,250,000 ALICE/年，每 2 年减半
- **每 epoch 奖励**：约 600 ALICE（epoch ≈ 60 分钟）
- **训练者份额**：56-90%（动态，取决于网络组成）
- **基础设施**：固定 9%（验证者 5% + 聚合者 2% + 调度 2%）
- **分配方式**：按你的梯度评分占总评分的比例

### 单矿工 vs 矿池

| 模式 | 有效算力 | 说明 |
|------|----------|------|
| 单矿工 | 15-25% | 直接提交，staleness 损耗大 |
| 矿池 | 30-45% | 内部聚合，可用优化器，收益更稳定 |

加入矿池可以将有效贡献提升约 **2 倍**。

## Vast.ai 配置

```bash
# 使用 /dev/shm 存储模型（overlay 磁盘空间有限）
python alice_miner.py \
  --ps-url https://ps.aliceprotocol.org \
  --model-path /dev/shm/models \
  --device cuda \
  --batch-size 2
```

## 常见问题

| 问题 | 解决方案 |
|------|----------|
| OOM（显存不足） | `--batch-size 1` 或 `--precision fp16` |
| Vast.ai 磁盘满 | 使用 `--model-path /dev/shm/models` |
| 模型下载慢 | 预下载：`wget https://dl.aliceprotocol.org/v{版本号}_layers_0-31.pt` |
| 连接被拒 | 检查 PS 状态：`curl https://ps.aliceprotocol.org/status` |
| MPS 崩溃 | 设置 `--precision fp16` 和 `--batch-size 1` |

## 链接

- [官网](https://aliceprotocol.org)
- [白皮书](https://dl.aliceprotocol.org/whitepaper)
- [PS 状态](https://ps.aliceprotocol.org/status)
- [Twitter](https://twitter.com/Alice_AI102)

## 开源协议

MIT
