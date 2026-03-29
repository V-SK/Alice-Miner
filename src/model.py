"""
Alice-7B Model Architecture
Based on Llama architecture with optimizations for distributed training
"""

import os
import torch
import torch.nn as nn
import torch.nn.functional as F
from dataclasses import dataclass
from typing import Optional, Tuple
import math
from torch.utils.checkpoint import checkpoint


@dataclass
class AliceConfig:
    """Alice-7B model configuration (Genesis model)"""
    # Architecture
    num_layers: int = 32
    hidden_dim: int = 4096
    intermediate_size: int = 11008  # 2.7x hidden for SwiGLU
    num_attention_heads: int = 32
    head_dim: int = 128  # hidden_dim / num_heads
    
    # Vocabulary & Context
    vocab_size: int = 50257  # GPT-2 tokenizer (Alice default)
    max_position_embeddings: int = 2048
    
    # Technical details
    rms_norm_eps: float = 1e-6
    rope_theta: float = 10000.0
    hidden_dropout: float = 0.0
    attention_dropout: float = 0.0
    initializer_range: float = 0.02
    
    def __post_init__(self):
        assert self.hidden_dim % self.num_attention_heads == 0
        assert self.head_dim == self.hidden_dim // self.num_attention_heads


class RMSNorm(nn.Module):
    """Root Mean Square Layer Normalization (faster than LayerNorm)"""
    def __init__(self, hidden_size: int, eps: float = 1e-6):
        super().__init__()
        self.weight = nn.Parameter(torch.ones(hidden_size))
        self.eps = eps

    def forward(self, x):
        variance = x.pow(2).mean(-1, keepdim=True)
        x = x * torch.rsqrt(variance + self.eps)
        return self.weight * x


class RotaryEmbedding(nn.Module):
    """Rotary Position Embedding (RoPE)"""
    def __init__(self, dim: int, max_position_embeddings: int = 2048, base: float = 10000.0):
        super().__init__()
        inv_freq = 1.0 / (base ** (torch.arange(0, dim, 2).float() / dim))
        self.register_buffer("inv_freq", inv_freq)
        self.max_seq_len_cached = max_position_embeddings
        
        # Precompute cos/sin for max sequence length
        t = torch.arange(self.max_seq_len_cached, dtype=self.inv_freq.dtype)
        freqs = torch.einsum("i,j->ij", t, self.inv_freq)
        emb = torch.cat((freqs, freqs), dim=-1)
        self.register_buffer("cos_cached", emb.cos(), persistent=False)
        self.register_buffer("sin_cached", emb.sin(), persistent=False)

    def forward(self, x, seq_len: int):
        return (
            self.cos_cached[:seq_len, ...].to(x.device),
            self.sin_cached[:seq_len, ...].to(x.device),
        )


def rotate_half(x):
    """Helper for RoPE"""
    x1, x2 = x.chunk(2, dim=-1)
    return torch.cat((-x2, x1), dim=-1)


def apply_rotary_pos_emb(q, k, cos, sin):
    """Apply rotary position embeddings to query and key"""
    q_embed = (q * cos) + (rotate_half(q) * sin)
    k_embed = (k * cos) + (rotate_half(k) * sin)
    return q_embed, k_embed


class AliceAttention(nn.Module):
    """Multi-head self-attention with RoPE"""
    def __init__(self, config: AliceConfig):
        super().__init__()
        self.config = config
        self.hidden_size = config.hidden_dim
        self.num_heads = config.num_attention_heads
        self.head_dim = config.head_dim
        
        # Q, K, V projections
        self.q_proj = nn.Linear(self.hidden_size, self.num_heads * self.head_dim, bias=False)
        self.k_proj = nn.Linear(self.hidden_size, self.num_heads * self.head_dim, bias=False)
        self.v_proj = nn.Linear(self.hidden_size, self.num_heads * self.head_dim, bias=False)
        self.o_proj = nn.Linear(self.num_heads * self.head_dim, self.hidden_size, bias=False)
        
        self.rotary_emb = RotaryEmbedding(
            self.head_dim,
            max_position_embeddings=config.max_position_embeddings,
            base=config.rope_theta
        )

    def forward(
        self,
        hidden_states: torch.Tensor,
        attention_mask: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        bsz, seq_len, _ = hidden_states.size()
        
        # Project Q, K, V
        query_states = self.q_proj(hidden_states)
        key_states = self.k_proj(hidden_states)
        value_states = self.v_proj(hidden_states)
        
        # Reshape to (batch, num_heads, seq_len, head_dim)
        query_states = query_states.view(bsz, seq_len, self.num_heads, self.head_dim).transpose(1, 2)
        key_states = key_states.view(bsz, seq_len, self.num_heads, self.head_dim).transpose(1, 2)
        value_states = value_states.view(bsz, seq_len, self.num_heads, self.head_dim).transpose(1, 2)
        
        # Apply RoPE
        cos, sin = self.rotary_emb(value_states, seq_len)
        query_states, key_states = apply_rotary_pos_emb(query_states, key_states, cos, sin)
        
        # Attention
        attn_weights = torch.matmul(query_states, key_states.transpose(2, 3)) / math.sqrt(self.head_dim)
        
        if attention_mask is not None:
            attn_weights = attn_weights + attention_mask
        
        attn_weights = F.softmax(attn_weights, dim=-1, dtype=torch.float32).to(query_states.dtype)
        attn_output = torch.matmul(attn_weights, value_states)
        
        # Reshape back
        attn_output = attn_output.transpose(1, 2).contiguous()
        attn_output = attn_output.reshape(bsz, seq_len, self.hidden_size)
        
        # Output projection
        attn_output = self.o_proj(attn_output)
        
        return attn_output


class AliceMLP(nn.Module):
    """SwiGLU Feed-Forward Network"""
    def __init__(self, config: AliceConfig):
        super().__init__()
        self.gate_proj = nn.Linear(config.hidden_dim, config.intermediate_size, bias=False)
        self.up_proj = nn.Linear(config.hidden_dim, config.intermediate_size, bias=False)
        self.down_proj = nn.Linear(config.intermediate_size, config.hidden_dim, bias=False)

    def forward(self, x):
        # SwiGLU: SiLU(gate) * up
        return self.down_proj(F.silu(self.gate_proj(x)) * self.up_proj(x))


class AliceDecoderLayer(nn.Module):
    """Single Transformer decoder layer"""
    def __init__(self, config: AliceConfig):
        super().__init__()
        self.self_attn = AliceAttention(config)
        self.mlp = AliceMLP(config)
        self.input_layernorm = RMSNorm(config.hidden_dim, eps=config.rms_norm_eps)
        self.post_attention_layernorm = RMSNorm(config.hidden_dim, eps=config.rms_norm_eps)

    def forward(
        self,
        hidden_states: torch.Tensor,
        attention_mask: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        # Self-attention with residual
        residual = hidden_states
        hidden_states = self.input_layernorm(hidden_states)
        hidden_states = self.self_attn(hidden_states, attention_mask)
        hidden_states = residual + hidden_states
        
        # MLP with residual
        residual = hidden_states
        hidden_states = self.post_attention_layernorm(hidden_states)
        hidden_states = self.mlp(hidden_states)
        hidden_states = residual + hidden_states
        
        return hidden_states


class AliceModel(nn.Module):
    """
    Alice-7B Base Model
    
    Total parameters: ~6.74B
    - Embeddings: 32000 × 4096 = 131M
    - 32 × Decoder layers = ~6.5B
    - Output head: 32000 × 4096 = 131M (shared with embeddings)
    """
    def __init__(self, config: AliceConfig):
        super().__init__()
        self.config = config
        self.gradient_checkpointing = False
        
        self.embed_tokens = nn.Embedding(config.vocab_size, config.hidden_dim)
        self.layers = nn.ModuleList([
            AliceDecoderLayer(config) for _ in range(config.num_layers)
        ])
        self.norm = RMSNorm(config.hidden_dim, eps=config.rms_norm_eps)
        
        # Optional: skip the second explicit re-init pass for faster large-model boot.
        # Linear/Embedding modules are already initialized by PyTorch constructors.
        if os.environ.get("ALICE_SKIP_REINIT", "0") != "1":
            self.apply(self._init_weights)

    def gradient_checkpointing_enable(self) -> None:
        self.gradient_checkpointing = True

    def gradient_checkpointing_disable(self) -> None:
        self.gradient_checkpointing = False

    def _init_weights(self, module):
        """Initialize weights following Llama"""
        if isinstance(module, nn.Linear):
            torch.nn.init.normal_(module.weight, mean=0.0, std=self.config.initializer_range)
            if module.bias is not None:
                torch.nn.init.zeros_(module.bias)
        elif isinstance(module, nn.Embedding):
            torch.nn.init.normal_(module.weight, mean=0.0, std=self.config.initializer_range)

    def forward(
        self,
        input_ids: torch.LongTensor,
        attention_mask: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        batch_size, seq_length = input_ids.shape
        
        # Embedding
        hidden_states = self.embed_tokens(input_ids)
        
        # Causal mask (prevent attending to future tokens)
        if attention_mask is None:
            attention_mask = torch.triu(
                torch.ones(seq_length, seq_length, dtype=torch.bool, device=input_ids.device),
                diagonal=1
            )
            attention_mask = attention_mask.masked_fill(attention_mask, float('-inf'))
            attention_mask = attention_mask.unsqueeze(0).unsqueeze(0)  # (1, 1, seq, seq)
        
        # Pass through decoder layers
        for layer in self.layers:
            if self.gradient_checkpointing and self.training and torch.is_grad_enabled():
                hidden_states = checkpoint(layer, hidden_states, attention_mask, use_reentrant=False)
            else:
                hidden_states = layer(hidden_states, attention_mask)
        
        # Final normalization
        hidden_states = self.norm(hidden_states)
        
        return hidden_states


class AliceLMHead(nn.Module):
    """Language Model Head with tied embeddings"""
    def __init__(self, config: AliceConfig, embed_tokens: nn.Embedding):
        super().__init__()
        self.config = config
        # Tie weights with input embeddings (standard practice)
        self.weight = embed_tokens.weight

    def forward(self, hidden_states: torch.Tensor) -> torch.Tensor:
        # hidden_states: (batch, seq_len, hidden_dim)
        # output: (batch, seq_len, vocab_size)
        return F.linear(hidden_states, self.weight)


class AliceForCausalLM(nn.Module):
    """Alice-7B for Language Modeling (complete model with LM head)"""
    def __init__(self, config: AliceConfig):
        super().__init__()
        self.config = config
        self.model = AliceModel(config)
        self.lm_head = AliceLMHead(config, self.model.embed_tokens)

    def gradient_checkpointing_enable(self) -> None:
        self.model.gradient_checkpointing_enable()

    def gradient_checkpointing_disable(self) -> None:
        self.model.gradient_checkpointing_disable()

    def forward(
        self,
        input_ids: torch.LongTensor,
        labels: Optional[torch.LongTensor] = None,
        attention_mask: Optional[torch.Tensor] = None,
    ) -> Tuple[torch.Tensor, Optional[torch.Tensor]]:
        """
        Forward pass with optional loss computation
        
        Args:
            input_ids: (batch, seq_len)
            labels: (batch, seq_len) - if provided, compute loss
            attention_mask: (batch, 1, seq_len, seq_len) - optional
        
        Returns:
            logits: (batch, seq_len, vocab_size)
            loss: scalar (if labels provided)
        """
        hidden_states = self.model(input_ids, attention_mask)
        logits = self.lm_head(hidden_states)
        
        loss = None
        if labels is not None:
            # Shift so that tokens < n predict n
            shift_logits = logits[..., :-1, :].contiguous()
            shift_labels = labels[..., 1:].contiguous()
            loss = F.cross_entropy(
                shift_logits.view(-1, self.config.vocab_size),
                shift_labels.view(-1),
                ignore_index=-100
            )
        
        return logits, loss

    def count_parameters(self):
        """Count total trainable parameters"""
        return sum(p.numel() for p in self.parameters() if p.requires_grad)


def create_alice_7b() -> AliceForCausalLM:
    """Factory function to create Alice-7B model"""
    config = AliceConfig()
    model = AliceForCausalLM(config)
    print(f"Alice-7B initialized:")
    print(f"  Total parameters: {model.count_parameters():,}")
    print(f"  Layers: {config.num_layers}")
    print(f"  Hidden dim: {config.hidden_dim}")
    print(f"  Vocab size: {config.vocab_size}")
    print(f"  Context length: {config.max_position_embeddings}")
    return model


if __name__ == "__main__":
    # Quick test
    model = create_alice_7b()
    
    # Test forward pass
    batch_size = 2
    seq_len = 128
    input_ids = torch.randint(0, 32000, (batch_size, seq_len))
    labels = torch.randint(0, 32000, (batch_size, seq_len))
    
    print("\nTesting forward pass...")
    logits, loss = model(input_ids, labels)
    print(f"  Input shape: {input_ids.shape}")
    print(f"  Logits shape: {logits.shape}")
    print(f"  Loss: {loss.item():.4f}")
    
    print("\nTesting backward pass...")
    loss.backward()
    print("  ✅ Gradients computed successfully")
    
    print("\n✅ Alice-7B model definition complete!")
