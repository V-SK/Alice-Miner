"""Gradient compression for the Alice AI Training Network MVP - Optimized."""
from __future__ import annotations

import base64
import zlib
from typing import Any, Dict, Optional

import numpy as np
import torch


class TopKCompressor:
    """Top-K gradient compressor with binary serialization (binary_v2)."""

    def __init__(self, ratio: float = 0.01, error_feedback: bool = True):
        self.k_ratio = ratio
        self.error_feedback: Dict[str, torch.Tensor] = {}

    def compress(
        self,
        gradients: Dict[str, torch.Tensor],
        prefix: str = "",
    ) -> Dict[str, Any]:
        """Compress gradients using Top-K + binary + zlib + base64."""
        compressed = {}
        compressed["dtype"] = str(gradients[next(iter(gradients))].dtype)
        compressed["fmt"] = "binary_v2"

        for name, grad in gradients.items():
            # Add error feedback from previous round
            if name in self.error_feedback:
                grad = grad + self.error_feedback[name]

            # Flatten and get top-k
            flat = grad.flatten()
            k = max(1, int(flat.numel() * self.k_ratio))

            # Get top-k by magnitude
            abs_flat = flat.abs()
            topk_vals, topk_idx = torch.topk(abs_flat, k)

            # Binary serialization: float16 values + int32 indices
            values_np = flat[topk_idx].to(torch.float16).detach().numpy().astype(np.float16)
            indices_np = topk_idx.to(torch.int32).detach().numpy().astype(np.int32)

            # Pack and zlib compress
            combined = values_np.tobytes() + indices_np.tobytes()
            compressed_bytes = zlib.compress(combined, level=1)

            compressed[name] = {
                "shape": list(grad.shape),
                "k": k,
                "data": base64.b64encode(compressed_bytes).decode("ascii"),
                "fmt": "binary_v2",
            }

            # Store error feedback
            sparse = torch.zeros_like(flat)
            sparse[topk_idx] = flat[topk_idx]
            self.error_feedback[name] = (flat - sparse).view(grad.shape)

        return compressed


def decompress_gradients(
    payload: Dict[str, Any],
    device: Optional[torch.device] = None,
    dtype: Optional[torch.dtype] = None,
) -> Dict[str, torch.Tensor]:
    """Decompress gradients from compressed format (supports binary_v2 and legacy JSON)."""
    if device is None:
        device = torch.device("cpu")
    
    if dtype is None:
        dtype_str = payload.get("dtype", "torch.float32")
        dtype = getattr(torch, dtype_str.split(".")[-1])

    gradients = {}
    for name, data in payload.items():
        if name in ("dtype", "fmt"):
            continue

        shape = data["shape"]
        flat_size = 1
        for dim in shape:
            flat_size *= dim

        sparse = torch.zeros(flat_size, dtype=dtype, device=device)

        if data.get("fmt") == "binary_v2":
            k = data["k"]
            raw = zlib.decompress(base64.b64decode(data["data"]))
            values_bytes = raw[: k * 2]   # float16 = 2 bytes each
            indices_bytes = raw[k * 2 :]  # int32 = 4 bytes each

            values = torch.from_numpy(
                np.frombuffer(values_bytes, dtype=np.float16).copy()
            ).to(dtype).to(device)
            indices = torch.from_numpy(
                np.frombuffer(indices_bytes, dtype=np.int32).astype(np.int64).copy()
            ).to(device)
        else:
            # Legacy JSON format (backward compat)
            indices = torch.tensor(data["indices"], dtype=torch.int64, device=device)
            values = torch.tensor(data["values"], dtype=dtype, device=device)

        sparse[indices] = values
        gradients[name] = sparse.view(shape)

    return gradients
