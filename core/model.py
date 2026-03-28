"""Llama Nano model (~100M params) for the Alice AI Training Network MVP."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.checkpoint import checkpoint


class RMSNorm(nn.Module):
    """Root-mean-square normalization used in Llama models."""

    def __init__(self, dim: int, eps: float = 1e-6) -> None:
        super().__init__()
        self.eps = eps
        self.weight = nn.Parameter(torch.ones(dim))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        norm = x.pow(2).mean(-1, keepdim=True)
        x = x * torch.rsqrt(norm + self.eps)
        return x * self.weight


class RotaryEmbedding(nn.Module):
    """Rotary positional embeddings (RoPE) for attention heads."""

    def __init__(self, dim: int, base: float = 10000.0) -> None:
        super().__init__()
        self.dim = dim
        inv_freq = 1.0 / (base ** (torch.arange(0, dim, 2).float() / dim))
        self.register_buffer("inv_freq", inv_freq, persistent=False)
        self._seq_len_cached = 0
        self._cos_cached: Optional[torch.Tensor] = None
        self._sin_cached: Optional[torch.Tensor] = None

    def _build_cache(self, seq_len: int, device: torch.device, dtype: torch.dtype) -> None:
        positions = torch.arange(seq_len, device=device, dtype=self.inv_freq.dtype)
        freqs = torch.einsum("i,j->ij", positions, self.inv_freq)
        cos = freqs.cos().to(dtype=dtype)
        sin = freqs.sin().to(dtype=dtype)
        self._cos_cached = cos
        self._sin_cached = sin
        self._seq_len_cached = seq_len

    def get_cos_sin(self, seq_len: int, device: torch.device, dtype: torch.dtype) -> Tuple[torch.Tensor, torch.Tensor]:
        if self._cos_cached is None or seq_len > self._seq_len_cached:
            self._build_cache(seq_len, device, dtype)
        assert self._cos_cached is not None and self._sin_cached is not None
        return self._cos_cached[:seq_len].to(device=device, dtype=dtype), self._sin_cached[:seq_len].to(
            device=device, dtype=dtype
        )


def _apply_rope(x: torch.Tensor, cos: torch.Tensor, sin: torch.Tensor) -> torch.Tensor:
    """Apply rotary embeddings to queries or keys.

    Args:
        x: (batch, heads, seq, head_dim)
        cos/sin: (seq, head_dim/2)
    """

    cos = cos[None, None, :, :]
    sin = sin[None, None, :, :]
    x_even = x[..., ::2]
    x_odd = x[..., 1::2]
    x_rot_even = x_even * cos - x_odd * sin
    x_rot_odd = x_even * sin + x_odd * cos
    x_rot = torch.stack((x_rot_even, x_rot_odd), dim=-1)
    return x_rot.flatten(-2)


class MultiHeadAttention(nn.Module):
    """Grouped Query Attention (GQA) with RoPE."""

    def __init__(
        self,
        dim: int,
        n_heads: int,
        n_kv_heads: int,
        rope_base: float = 10000.0,
    ) -> None:
        super().__init__()
        if dim % n_heads != 0:
            raise ValueError("dim must be divisible by n_heads")
        if n_heads % n_kv_heads != 0:
            raise ValueError("n_heads must be divisible by n_kv_heads")

        self.dim = dim
        self.n_heads = n_heads
        self.n_kv_heads = n_kv_heads
        self.head_dim = dim // n_heads
        self.rope = RotaryEmbedding(self.head_dim, base=rope_base)

        self.q_proj = nn.Linear(dim, n_heads * self.head_dim, bias=False)
        self.k_proj = nn.Linear(dim, n_kv_heads * self.head_dim, bias=False)
        self.v_proj = nn.Linear(dim, n_kv_heads * self.head_dim, bias=False)
        self.o_proj = nn.Linear(dim, dim, bias=False)

        self._mask: Optional[torch.Tensor] = None

    def _get_causal_mask(self, seq_len: int, device: torch.device) -> torch.Tensor:
        if self._mask is None or self._mask.size(-1) < seq_len or self._mask.device != device:
            mask = torch.tril(torch.ones(seq_len, seq_len, device=device))
            self._mask = mask[None, None, :, :]
        assert self._mask is not None
        return self._mask[:, :, :seq_len, :seq_len]

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        bsz, seq_len, _ = x.size()
        q = self.q_proj(x).view(bsz, seq_len, self.n_heads, self.head_dim)
        k = self.k_proj(x).view(bsz, seq_len, self.n_kv_heads, self.head_dim)
        v = self.v_proj(x).view(bsz, seq_len, self.n_kv_heads, self.head_dim)

        q = q.transpose(1, 2)  # (bsz, n_heads, seq, head_dim)
        k = k.transpose(1, 2)
        v = v.transpose(1, 2)

        cos, sin = self.rope.get_cos_sin(seq_len, device=x.device, dtype=x.dtype)
        q = _apply_rope(q, cos, sin)
        k = _apply_rope(k, cos, sin)

        if self.n_kv_heads != self.n_heads:
            repeat_factor = self.n_heads // self.n_kv_heads
            k = k.repeat_interleave(repeat_factor, dim=1)
            v = v.repeat_interleave(repeat_factor, dim=1)

        attn_scores = torch.matmul(q, k.transpose(-2, -1)) / (self.head_dim**0.5)
        mask = self._get_causal_mask(seq_len, x.device)
        attn_scores = attn_scores.masked_fill(mask == 0, float("-inf"))
        attn_probs = torch.softmax(attn_scores, dim=-1)
        attn_out = torch.matmul(attn_probs, v)

        attn_out = attn_out.transpose(1, 2).contiguous().view(bsz, seq_len, self.dim)
        return self.o_proj(attn_out)


class FeedForward(nn.Module):
    """SwiGLU feed-forward network as used in Llama."""

    def __init__(self, dim: int, hidden_dim: int) -> None:
        super().__init__()
        self.gate = nn.Linear(dim, hidden_dim, bias=False)
        self.up = nn.Linear(dim, hidden_dim, bias=False)
        self.down = nn.Linear(hidden_dim, dim, bias=False)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.down(F.silu(self.gate(x)) * self.up(x))


class TransformerBlock(nn.Module):
    """Single transformer block with RMSNorm, GQA, and RoPE."""

    def __init__(
        self,
        dim: int,
        n_heads: int,
        n_kv_heads: int,
        hidden_dim: int,
        rope_base: float = 10000.0,
    ) -> None:
        super().__init__()
        self.attn_norm = RMSNorm(dim)
        self.attn = MultiHeadAttention(dim, n_heads, n_kv_heads, rope_base=rope_base)
        self.ffn_norm = RMSNorm(dim)
        self.ffn = FeedForward(dim, hidden_dim)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = x + self.attn(self.attn_norm(x))
        x = x + self.ffn(self.ffn_norm(x))
        return x


@dataclass
class LlamaNanoConfig:
    vocab_size: int = 32000
    dim: int = 768
    n_layers: int = 8
    n_heads: int = 12
    n_kv_heads: int = 4
    hidden_dim: int = 3072
    rope_base: float = 10000.0
    max_seq_len: int = 2048


class LlamaNanoModel(nn.Module):
    """A compact Llama-style transformer (~100M params with default config)."""

    def __init__(self, config: LlamaNanoConfig) -> None:
        super().__init__()
        self.config = config
        self.gradient_checkpointing = False
        self.embed = nn.Embedding(config.vocab_size, config.dim)
        self.layers = nn.ModuleList(
            [
                TransformerBlock(
                    dim=config.dim,
                    n_heads=config.n_heads,
                    n_kv_heads=config.n_kv_heads,
                    hidden_dim=config.hidden_dim,
                    rope_base=config.rope_base,
                )
                for _ in range(config.n_layers)
            ]
        )
        self.norm = RMSNorm(config.dim)
        self.lm_head = nn.Linear(config.dim, config.vocab_size, bias=False)

    def gradient_checkpointing_enable(self) -> None:
        self.gradient_checkpointing = True

    def gradient_checkpointing_disable(self) -> None:
        self.gradient_checkpointing = False

    def forward(
        self,
        input_ids: torch.Tensor,
        labels: Optional[torch.Tensor] = None,
    ) -> Tuple[torch.Tensor, Optional[torch.Tensor]]:
        x = self.embed(input_ids)
        for layer in self.layers:
            if self.gradient_checkpointing and self.training and torch.is_grad_enabled():
                x = checkpoint(layer, x, use_reentrant=False)
            else:
                x = layer(x)
        x = self.norm(x)
        logits = self.lm_head(x)

        loss = None
        if labels is not None:
            loss = F.cross_entropy(
                logits.view(-1, logits.size(-1)),
                labels.view(-1),
                ignore_index=-100,
            )
        return logits, loss


def count_parameters(model: nn.Module) -> int:
    """Return the total number of trainable parameters."""

    return sum(p.numel() for p in model.parameters() if p.requires_grad)


class ByteTokenizer:
    """Byte-level tokenizer (UTF-8) with vocab size 256."""

    vocab_size = 256

    def encode(self, text: str) -> list[int]:
        return list(text.encode("utf-8", errors="ignore"))

    def decode(self, ids: list[int]) -> str:
        data = bytes([i & 0xFF for i in ids])
        return data.decode("utf-8", errors="ignore")

# Forward compatibility aliases
AliceConfig = LlamaNanoConfig
AliceForCausalLM = LlamaNanoModel
