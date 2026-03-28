"""Gradient compression for the Alice AI Training Network MVP - Optimized."""
from __future__ import annotations

import base64
import os
import tracemalloc
import zlib
from typing import Any, Dict, Optional

import numpy as np
import torch


def _rss_gb() -> float:
    try:
        rss_kb = os.popen(f"ps -o rss= -p {os.getpid()}").read().strip()
        if not rss_kb:
            return 0.0
        return float(int(rss_kb)) / 1024.0 / 1024.0
    except Exception:
        return 0.0


def _log_mem(label: str) -> None:
    if not tracemalloc.is_tracing():
        tracemalloc.start(10)
    cur, peak = tracemalloc.get_traced_memory()
    print(
        f"[MEM] {label}: RSS={_rss_gb():.2f}GB "
        f"TRC_CUR={cur / (1024**2):.1f}MB TRC_PEAK={peak / (1024**2):.1f}MB"
    )


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
            values_np = flat[topk_idx].to(torch.float16).detach().cpu().numpy().astype(np.float16)
            indices_np = topk_idx.to(torch.int32).detach().cpu().numpy().astype(np.int32)

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
    _log_mem("decompress_gradients:start")
    if device is None:
        device = torch.device("cpu")
    
    if dtype is None:
        dtype_str = payload.get("dtype", "torch.float32")
        dtype = getattr(torch, dtype_str.split(".")[-1])

    gradients = {}
    total_dense_bytes = 0
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
            
            # Auto-detect dtype from buffer size
            total = len(raw)
            indices_size = k * 4  # int32 fixed
            values_size = total - indices_size
            bytes_per_value = values_size // k
            
            if bytes_per_value == 2:
                value_dtype = np.float16
            elif bytes_per_value == 4:
                value_dtype = np.float32
            else:
                raise ValueError(f"Unknown dtype: {bytes_per_value} bytes per value")
            
            values_bytes = raw[:values_size]
            indices_bytes = raw[values_size:]

            values = torch.from_numpy(
                np.frombuffer(values_bytes, dtype=value_dtype).copy()
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
        total_dense_bytes += int(sparse.numel()) * int(sparse.element_size())

    print(
        f"[MEMDBG] decompress_gradients tensors={len(gradients)} "
        f"dense_est_mb={total_dense_bytes / (1024**2):.1f}"
    )
    _log_mem("decompress_gradients:end")
    return gradients



def decompress_gradients_sparse(payload, device=None):
    """Decompress gradients but keep sparse representation (indices + values).
    
    Unlike decompress_gradients() which scatters values back into dense tensors
    (costing ~13GB for 7B model), this returns the raw sparse pairs.
    
    Returns:
        Dict[str, dict] where each entry has:
            'indices': torch.Tensor (int64) — positions in flattened param
            'values': torch.Tensor (float32) — gradient values (always fp32)
            'shape': tuple — original parameter shape
    
    Memory cost: ~16MB (same as compressed payload) vs ~13GB for dense.
    """
    import zlib
    import base64
    import numpy as np
    import torch

    if isinstance(payload, bytes):
        import json
        payload = json.loads(payload)

    if isinstance(payload, list):
        # Multi-parameter payload: list of per-parameter dicts
        result = {}
        for item in payload:
            name = item.get("name") or item.get("param_name")
            shape = tuple(item.get("shape", []))
            
            if item.get("fmt") == "binary_v2":
                k = item["k"]
                raw = zlib.decompress(base64.b64decode(item["data"]))
                
                # Auto-detect dtype from buffer size
                total = len(raw)
                indices_size = k * 4  # int32 fixed
                values_size = total - indices_size
                bytes_per_value = values_size // k
                
                if bytes_per_value == 2:
                    value_dtype = np.float16
                elif bytes_per_value == 4:
                    value_dtype = np.float32
                else:
                    raise ValueError(
                        f"Unknown value dtype: {bytes_per_value} bytes/value "
                        f"(expected 2 or 4) for param {name}"
                    )
                
                # Buffer layout: [values (k * 2/4 bytes)] + [indices (k * 4 bytes)]
                values_bytes = raw[:values_size]
                indices_bytes = raw[values_size:]
                
                values = torch.from_numpy(
                    np.frombuffer(values_bytes, dtype=value_dtype).copy()
                ).float()  # Always convert to fp32 for scoring precision
                
                indices = torch.from_numpy(
                    np.frombuffer(indices_bytes, dtype=np.int32).astype(np.int64).copy()
                )
            else:
                # Legacy JSON format
                indices = torch.tensor(item.get("indices", []), dtype=torch.long)
                values = torch.tensor(item.get("values", []), dtype=torch.float32)
            
            if device:
                indices = indices.to(device)
                values = values.to(device)
            
            result[name] = {
                'indices': indices,
                'values': values,
                'shape': shape,
            }
        return result
    
    elif isinstance(payload, dict):
        # Multi-parameter dict payload: {param_name: {shape, fmt, k, data}, ...}
        # Same format as decompress_gradients uses
        result = {}
        for name, data in payload.items():
            if name in ("dtype", "fmt"):
                continue
            
            shape = tuple(data.get("shape", []))
            
            if data.get("fmt") == "binary_v2":
                k = data["k"]
                raw = zlib.decompress(base64.b64decode(data["data"]))
                
                total = len(raw)
                indices_size = k * 4
                values_size = total - indices_size
                bytes_per_value = values_size // k
                
                if bytes_per_value == 2:
                    value_dtype = np.float16
                elif bytes_per_value == 4:
                    value_dtype = np.float32
                else:
                    raise ValueError(f"Unknown value dtype: {bytes_per_value} bytes/value for {name}")
                
                values_bytes = raw[:values_size]
                indices_bytes = raw[values_size:]
                
                values = torch.from_numpy(
                    np.frombuffer(values_bytes, dtype=value_dtype).copy()
                ).float()
                
                indices = torch.from_numpy(
                    np.frombuffer(indices_bytes, dtype=np.int32).astype(np.int64).copy()
                )
            else:
                # Legacy JSON format
                indices = torch.tensor(data.get("indices", []), dtype=torch.long)
                values = torch.tensor(data.get("values", []), dtype=torch.float32)
            
            if device:
                indices = indices.to(device)
                values = values.to(device)
            
            result[name] = {
                "indices": indices,
                "values": values,
                "shape": shape,
            }
        
        return result
    
        raise ValueError(f"Unexpected payload type: {type(payload)}")

