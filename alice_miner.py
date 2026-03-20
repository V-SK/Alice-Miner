#!/usr/bin/env python3
"""
Alice Miner Client V2 - Task-based Architecture with Tiered Training
Requests tasks from PS, downloads shards on-demand, trains assigned layers, and submits gradients.
"""

import argparse
import base64
import contextlib
import fcntl
import hashlib
import json
import logging
import math
import os
import platform
import subprocess
import tempfile
import time
import zlib
from pathlib import Path
from typing import Dict, Optional, List, Tuple, Any

import numpy as np
import requests
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

# Import from alice-project
import sys
sys.path.insert(0, str(Path(__file__).parent))

from core.model import LlamaNanoModel, LlamaNanoConfig
from core.compression import TopKCompressor
from core.secure_wallet import DEFAULT_WALLET_PATH, get_or_create_wallet_for_miner
try:
    from src.model import AliceConfig, AliceForCausalLM
    ALICE_MODEL_AVAILABLE = True
except ImportError:
    ALICE_MODEL_AVAILABLE = False

PROTOCOL_VERSION = "1.0"
DATA_FORMAT = "tensor"
USE_ERROR_FEEDBACK = os.getenv("USE_ERROR_FEEDBACK", "0") == "1"
EF_DTYPE = torch.float16
DEVICE_PROFILE_PATH = Path.home() / ".alice" / "device_profile.json"
DEVICE_PROFILE_VERSION = 1
PIDFILE_PATH = Path.home() / ".alice" / "miner.pid"

def auto_detect_device() -> Tuple[str, float, str]:
    """Auto-detect best available device and memory."""
    if torch.cuda.is_available():
        props = torch.cuda.get_device_properties(0)
        memory_gb = props.total_memory / (1024 ** 3)
        return "cuda", memory_gb, torch.cuda.get_device_name(0)

    if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        try:
            result = subprocess.run(
                ["sysctl", "-n", "hw.memsize"],
                capture_output=True,
                text=True,
                check=False,
            )
            memory_gb = int(result.stdout.strip()) / (1024 ** 3)
        except Exception:
            memory_gb = 16.0
        try:
            chip = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True,
                text=True,
                check=False,
            ).stdout.strip()
        except Exception:
            chip = "Apple Silicon"
        return "mps", memory_gb, chip or "Apple Silicon"

    try:
        import psutil
        memory_gb = psutil.virtual_memory().total / (1024 ** 3)
    except Exception:
        memory_gb = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / (1024 ** 3)
    return "cpu", memory_gb, (platform.processor() or "Unknown CPU")


def calculate_layers(memory_gb: float, device_type: str) -> int:
    """Calculate trainable layers based on available memory."""
    if device_type == "cpu":
        return 4

    if device_type == "mps":
        per_layer_gb = 1.0
        fixed_overhead = 2.0
    else:
        per_layer_gb = 0.85
        fixed_overhead = 1.5

    available = memory_gb - fixed_overhead
    layers = max(4, int(available / per_layer_gb))
    layers = min(layers, 32)
    layers = (layers // 4) * 4
    return max(4, layers)


def select_precision(
    device_type: str,
    memory_gb: float,
    assigned_layers: int,
    requested: str = "auto",
) -> str:
    """
    Select precision mode by hardware profile.

    Default policy:
    - CUDA: FP16 (FP32 only for very large GPUs with small assigned layer count)
    - MPS: FP16
    - CPU: FP32
    """
    req = (requested or "auto").lower()
    if req in ("fp16", "fp32"):
        return req

    if device_type == "cpu":
        return "fp32"
    if device_type == "cuda":
        if memory_gb >= 40.0 and assigned_layers <= 12:
            return "fp32"
        return "fp16"
    if device_type == "mps":
        return "fp16"
    return "fp32"


def with_precision_arg(argv: List[str], precision: str) -> List[str]:
    """Return argv with a normalized --precision argument."""
    out: List[str] = []
    skip_next = False
    for token in argv:
        if skip_next:
            skip_next = False
            continue
        if token == "--precision":
            skip_next = True
            continue
        if token.startswith("--precision="):
            continue
        out.append(token)
    out.extend(["--precision", precision])
    return out


def get_hardware_info(device_override: Optional[str] = None) -> Dict[str, Any]:
    """Detect hardware capabilities with optional device override."""
    detected_device, detected_memory_gb, detected_name = auto_detect_device()
    device_type = (device_override or detected_device).lower()
    device_name = detected_name
    memory_gb = detected_memory_gb

    if device_type == "cuda":
        if torch.cuda.is_available():
            props = torch.cuda.get_device_properties(0)
            memory_gb = props.total_memory / (1024 ** 3)
            device_name = torch.cuda.get_device_name(0)
        else:
            print("⚠️ --device cuda requested but CUDA is unavailable, falling back to CPU")
            device_type = "cpu"
    elif device_type == "mps":
        if not (hasattr(torch.backends, "mps") and torch.backends.mps.is_available()):
            print("⚠️ --device mps requested but MPS is unavailable, falling back to CPU")
            device_type = "cpu"
        else:
            # Keep memory detection from auto-detect path.
            pass
    elif device_type == "cpu":
        pass
    else:
        print(f"⚠️ Unknown --device '{device_type}', using auto-detected device '{detected_device}'")
        device_type = detected_device

    try:
        import psutil
        system_memory_gb = psutil.virtual_memory().total / (1024 ** 3)
        cpu_count = psutil.cpu_count() or 1
    except Exception:
        system_memory_gb = detected_memory_gb if device_type == "cpu" else 16.0
        cpu_count = os.cpu_count() or 1

    if device_type == "cpu":
        memory_gb = system_memory_gb
        device_name = platform.processor() or device_name

    memory_cap_env = os.environ.get("ALICE_MEMORY_CAP_GB")
    if memory_cap_env:
        try:
            cap_gb = float(memory_cap_env)
            if cap_gb > 0:
                memory_gb = min(memory_gb, cap_gb)
        except ValueError:
            pass

    return {
        "device": device_type,
        "device_type": device_type,
        "device_name": device_name,
        "memory_gb": float(memory_gb),
        "system_memory_gb": float(system_memory_gb),
        "cpu_count": int(cpu_count),
    }


def calculate_batch_size(
    device_type: str,
    model_memory_gb: float,
    total_memory_gb: float,
    seq_len: int = 512,
) -> Tuple[int, float, float]:
    """Calculate an initial training batch size from available memory."""
    if device_type == "cpu":
        return 1, 0.0, 0.0

    # Keep headroom for fragmentation, dataloader tensors, and temporary buffers.
    available_gb = max(0.0, total_memory_gb - model_memory_gb - 2.0)
    per_sample_gb = 0.5 * (max(1, seq_len) / 512.0)
    if per_sample_gb <= 0:
        return 1, available_gb, 0.0

    batch_size = max(1, int(available_gb / per_sample_gb))
    batch_size = min(batch_size, 16)
    return batch_size, available_gb, per_sample_gb


def conservative_start_batch(device_type: str, batch_cap: int) -> int:
    """Choose a stability-first starting batch size, then grow gradually."""
    if device_type == "cpu":
        return 1
    if device_type == "mps":
        return max(1, min(batch_cap, 2))
    # CUDA: empirically stable default on 24GB cards.
    return max(1, min(batch_cap, 4))


def memory_required_for_layers(target_layers: int, device_type: str, fallback_memory: float) -> float:
    """Estimate memory cap needed so PS assigns at most target_layers."""
    if device_type == "cpu":
        return fallback_memory
    if device_type == "mps":
        per_layer_gb = 1.0
        fixed_overhead = 2.0
    else:
        per_layer_gb = 0.85
        fixed_overhead = 1.5
    layers = max(4, (int(target_layers) // 4) * 4)
    needed = fixed_overhead + layers * per_layer_gb + 0.05
    return max(4.0, min(float(fallback_memory), needed))


def device_profile_path() -> Path:
    override = os.environ.get("ALICE_DEVICE_PROFILE_PATH")
    if override:
        return Path(override).expanduser()
    return DEVICE_PROFILE_PATH


def device_profile_key(wallet_address: str, capabilities: Dict[str, Any]) -> str:
    device_type = str(capabilities.get("device_type", "unknown")).strip().lower()
    device_name = str(capabilities.get("device_name", "unknown")).strip().lower()
    return f"{wallet_address}|{device_type}|{device_name}"


def load_device_profile(path: Path, key: str) -> Dict[str, Any]:
    try:
        if not path.exists():
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
        profiles = data.get("profiles", {})
        profile = profiles.get(key, {})
        return profile if isinstance(profile, dict) else {}
    except Exception:
        return {}


def save_device_profile(path: Path, key: str, updates: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data: Dict[str, Any] = {"version": DEVICE_PROFILE_VERSION, "profiles": {}}
    try:
        if path.exists():
            existing = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(existing, dict):
                data.update(existing)
    except Exception:
        pass
    profiles = data.get("profiles")
    if not isinstance(profiles, dict):
        profiles = {}
        data["profiles"] = profiles
    current = profiles.get(key, {})
    if not isinstance(current, dict):
        current = {}
    current.update(updates)
    current["updated_at"] = int(time.time())
    profiles[key] = current
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=True, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def get_physical_device_memory_gb(device_type: str, capabilities: Dict[str, Any]) -> float:
    if device_type == "cuda" and torch.cuda.is_available():
        return float(torch.cuda.get_device_properties(0).total_memory / (1024 ** 3))
    if device_type == "mps":
        return float(capabilities.get("system_memory_gb", capabilities.get("memory_gb", 16.0)))
    return float(capabilities.get("system_memory_gb", capabilities.get("memory_gb", 4.0)))


def acquire_single_instance_lock() -> Any:
    """Ensure only one miner instance runs per host user."""
    PIDFILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    lock_fp = PIDFILE_PATH.open("w", encoding="utf-8")
    try:
        fcntl.flock(lock_fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("❌ Another miner instance is already running. Exiting.")
        sys.exit(1)
    lock_fp.write(str(os.getpid()))
    lock_fp.flush()
    os.fsync(lock_fp.fileno())
    return lock_fp


def _auth_headers(auth_token: Optional[str]) -> Dict[str, str]:
    if not auth_token:
        return {}
    return {"Authorization": f"Bearer {auth_token}"}


def register_miner(
    ps_url: str,
    wallet_address: str,
    wallet_keypair: Optional[Any],
    capabilities: Dict[str, Any],
) -> Optional[Dict]:
    """
    Register with PS and report hardware capabilities.
    
    Returns:
        Registration response dict or None if failed
    """
    try:
        resp = requests.post(
            f"{ps_url}/register",
            json={
                "wallet": wallet_address,  # backward-compatible key
                "miner_id": wallet_address,
                "wallet_address": wallet_address,
                "protocol_version": PROTOCOL_VERSION,
                "data_format": DATA_FORMAT,
                "capabilities": {
                    "memory_gb": float(capabilities.get("memory_gb", 0.0)),
                    "device_type": capabilities.get("device_type", "cpu"),
                    "device_name": capabilities.get("device_name", "unknown"),
                    "system_memory_gb": float(capabilities.get("system_memory_gb", 0.0)),
                },
            },
            timeout=10
        )
        if resp.status_code != 200:
            print(f"❌ Registration failed: {resp.status_code} {resp.text}")
            return None

        data = resp.json()
        # Backward compatibility: older PS may still return token directly.
        if data.get("token"):
            print(f"✅ Registered with PS: {wallet_address}")
            print(
                f"   Hardware: {capabilities['device_type']}, "
                f"{capabilities['memory_gb']:.1f}GB device, "
                f"{capabilities['system_memory_gb']:.1f}GB system"
            )
            return data

        challenge = str(data.get("challenge", "")).strip()
        status = str(data.get("status", "")).strip()
        if status != "challenge_required" or not challenge:
            print(f"❌ Registration failed: unexpected response {data}")
            return None

        if wallet_keypair is None:
            print(
                "❌ PS requires signed challenge-response registration. "
                "Raw --wallet bypass cannot sign; use encrypted wallet."
            )
            sys.exit(1)

        sig = wallet_keypair.sign(challenge.encode("utf-8"))
        if isinstance(sig, str):
            sig_hex = sig[2:] if sig.startswith("0x") else sig
        else:
            sig_hex = bytes(sig).hex()
        verify_resp = requests.post(
            f"{ps_url}/register/verify",
            json={
                "miner_id": wallet_address,
                "challenge": challenge,
                "signature": sig_hex,
            },
            timeout=10,
        )
        if verify_resp.status_code == 200:
            verify_data = verify_resp.json()
            print(f"✅ Registered with PS: {wallet_address}")
            print(
                f"   Hardware: {capabilities['device_type']}, "
                f"{capabilities['memory_gb']:.1f}GB device, "
                f"{capabilities['system_memory_gb']:.1f}GB system"
            )
            return verify_data
        print(f"❌ Registration verify failed: {verify_resp.status_code} {verify_resp.text}")
        return None
    except Exception as e:
        print(f"❌ Registration error: {e}")
        return None


def setup_tiered_training(model: nn.Module, assigned_layers: List[int], n_layers: int = 32):
    """
    Setup tiered training: freeze unassigned layers, enable gradient checkpointing.
    
    Args:
        model: LlamaNanoModel
        assigned_layers: List of layer indices to train
        n_layers: Total number of layers in model
    """
    print(f"\n🎯 Setting up tiered training...")
    print(f"   Assigned layers: {assigned_layers} ({len(assigned_layers)}/{n_layers})")
    
    # 1. Freeze all parameters
    for param in model.parameters():
        param.requires_grad = False
    
    # 2. Unfreeze assigned layers
    # Detect layer container
    if hasattr(model, 'model') and hasattr(model.model, 'layers'):
        layers_container = model.model.layers  # AliceForCausalLM
    elif hasattr(model, 'layers'):
        layers_container = model.layers  # LlamaNanoModel
    else:
        layers_container = None
    
    for i in assigned_layers:
        if layers_container is not None and i < len(layers_container):
            for param in layers_container[i].parameters():
                param.requires_grad = True
        else:
            print(f"   ⚠️ Layer {i} not found")
    
    # 3. Enable gradient checkpointing (if model supports it)
    if hasattr(model, 'gradient_checkpointing_enable'):
        model.gradient_checkpointing_enable()
        print(f"   ✅ Gradient checkpointing enabled")
    else:
        print(f"   ⚠️ Gradient checkpointing not available")
    
    # 4. Count trainable parameters
    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total = sum(p.numel() for p in model.parameters())
    
    print(f"   📊 Trainable: {trainable/1e6:.1f}M / {total/1e6:.1f}M ({100*trainable/total:.1f}%)")
    
    return trainable, total


def _assigned_layer_prefixes(model: nn.Module, assigned_layers: List[int]) -> List[str]:
    if hasattr(model, 'model') and hasattr(model.model, 'layers'):
        return [f"model.layers.{i}." for i in assigned_layers]  # AliceForCausalLM
    return [f"layers.{i}." for i in assigned_layers]  # LlamaNanoModel


def _torch_version_at_least(major: int, minor: int) -> bool:
    version_core = torch.__version__.split("+", 1)[0]
    parts = version_core.split(".")
    major_cur = int("".join(ch for ch in parts[0] if ch.isdigit()) or "0")
    minor_cur = int("".join(ch for ch in (parts[1] if len(parts) > 1 else "0") if ch.isdigit()) or "0")
    return (major_cur, minor_cur) >= (major, minor)


def topk_compress(
    grad: torch.Tensor,
    ratio: float = 0.001,
    small_tensor_threshold: int = 10000,
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Compress a single gradient tensor with TopKCompressor and return (indices, values).
    """
    if grad.numel() == 0:
        return np.empty((0,), dtype=np.int32), np.empty((0,), dtype=np.float32)

    effective_ratio = 1.0 if grad.numel() < small_tensor_threshold else ratio
    compressor = TopKCompressor(ratio=effective_ratio, error_feedback=False)
    payload = compressor.compress({"grad": grad.to(torch.float32, copy=False)})
    packed = payload["grad"]
    k = int(packed["k"])

    raw = zlib.decompress(base64.b64decode(packed["data"]))
    indices_size = k * 4
    values_size = len(raw) - indices_size
    bytes_per_value = (values_size // k) if k > 0 else 0

    if bytes_per_value == 2:
        value_dtype = np.float16
    elif bytes_per_value == 4:
        value_dtype = np.float32
    else:
        raise ValueError(f"Unknown TopK value dtype width: {bytes_per_value} bytes")

    values_np = np.frombuffer(raw[:values_size], dtype=value_dtype).astype(np.float32, copy=True)
    indices_np = np.frombuffer(raw[values_size:], dtype=np.int32).astype(np.int32, copy=True)
    return indices_np, values_np


def register_compression_hooks(
    model: nn.Module,
    assigned_layers: List[int],
    ratio: float = 0.001,
    scaler: Optional[torch.cuda.amp.GradScaler] = None,
    grad_scale: float = 1.0,
    small_tensor_threshold: int = 10000,
    use_error_feedback: bool = False,
    residuals: Optional[Dict[str, torch.Tensor]] = None,
) -> Tuple[List[Any], Dict[str, Dict[str, Any]]]:
    """
    Register post-accumulate grad hooks that compress and release gradients per-parameter.
    """
    if not _torch_version_at_least(2, 1):
        raise RuntimeError(
            f"register_post_accumulate_grad_hook requires PyTorch 2.1+, found {torch.__version__}"
        )

    compressed_grads: Dict[str, Dict[str, Any]] = {}
    compressed_grads["__meta__"] = {"raw_bytes": 0, "bad_param": None}
    hooks: List[Any] = []
    prefixes = _assigned_layer_prefixes(model, assigned_layers)

    for name, param in model.named_parameters():
        if not param.requires_grad or not any(name.startswith(p) for p in prefixes):
            continue
        if not hasattr(param, "register_post_accumulate_grad_hook"):
            raise RuntimeError(
                "register_post_accumulate_grad_hook is unavailable in this PyTorch build"
            )

        def _hook(_: torch.Tensor, *, _name: str = name, _param: torch.Tensor = param) -> None:
            grad = _param.grad
            if grad is None:
                return

            meta = compressed_grads["__meta__"]
            meta["raw_bytes"] += int(grad.numel()) * int(grad.element_size())

            if torch.isnan(grad).any() or torch.isinf(grad).any():
                if meta["bad_param"] is None:
                    meta["bad_param"] = _name
                _param.grad = None
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
                return

            work_grad = grad.detach()
            if scaler is not None and scaler.is_enabled():
                scale = float(scaler.get_scale())
                if scale > 0.0:
                    work_grad = work_grad / scale
            if grad_scale != 1.0:
                work_grad = work_grad * float(grad_scale)

            cpu_grad = work_grad.detach().to(device="cpu", dtype=torch.float32)
            if use_error_feedback and residuals is not None:
                residual = residuals.get(_name)
                if residual is not None:
                    cpu_grad = cpu_grad + residual.to(device="cpu", dtype=torch.float32)

            indices_np, values_np = topk_compress(
                cpu_grad,
                ratio=ratio,
                small_tensor_threshold=small_tensor_threshold,
            )

            if use_error_feedback and residuals is not None:
                sent_dense = torch.zeros(cpu_grad.numel(), dtype=torch.float32, device="cpu")
                if indices_np.size > 0:
                    idx_t = torch.from_numpy(indices_np).to(dtype=torch.long)
                    val_t = torch.from_numpy(values_np).to(dtype=torch.float32)
                    sent_dense[idx_t] = val_t
                new_residual = (cpu_grad.flatten() - sent_dense).view_as(cpu_grad).to(dtype=EF_DTYPE, device="cpu")
                residuals[_name] = new_residual

            layer_name = _name.split(".")[2] if _name.startswith("model.layers.") and len(_name.split(".")) > 2 else (_name.split(".")[1] if _name.startswith("layers.") and len(_name.split(".")) > 1 else _name)
            print(f"[EF_SEND] enabled={int(use_error_feedback)} layer={layer_name} sent_nnz={int(indices_np.size)}")

            bucket = compressed_grads.get(_name)
            if bucket is None:
                bucket = {
                    "shape": list(cpu_grad.shape),
                    "numel": int(cpu_grad.numel()),
                    "indices": [],
                    "values": [],
                }
                compressed_grads[_name] = bucket
            bucket["indices"].append(indices_np)
            bucket["values"].append(values_np)

            _param.grad = None
            if torch.cuda.is_available():
                torch.cuda.empty_cache()

        hooks.append(param.register_post_accumulate_grad_hook(_hook))

    return hooks, compressed_grads


def compress_gradients_after_backward(
    model: nn.Module,
    assigned_layers: List[int],
    sparse_parts: Dict[str, Dict[str, Any]],
    device: torch.device,
    ratio: float = 0.001,
    grad_scale: float = 1e-5,
    small_tensor_threshold: int = 10000,
) -> Tuple[int, Optional[str]]:
    """
    Compress each parameter gradient immediately after backward and clear it.

    Stores sparse Top-K parts on CPU for final merge/packing.
    """
    raw_bytes = 0
    bad_param: Optional[str] = None

    prefixes = _assigned_layer_prefixes(model, assigned_layers)

    for name, param in model.named_parameters():
        grad = param.grad
        if grad is None or not any(name.startswith(p) for p in prefixes):
            continue

        raw_bytes += int(grad.numel()) * int(grad.element_size())

        # Validate before compression, then free memory regardless.
        if torch.isnan(grad).any() or torch.isinf(grad).any():
            if bad_param is None:
                bad_param = name
            param.grad = None
            continue

        # Keep selection math in fp32 to avoid fp16 underflow on tiny gradients.
        flat = grad.to(torch.float32).flatten()
        numel = flat.numel()
        if numel == 0:
            param.grad = None
            continue

        if numel < small_tensor_threshold:
            k = numel
            topk_idx = torch.arange(numel, device=flat.device, dtype=torch.long)
        else:
            k = max(1, int(numel * ratio))
            topk_idx = torch.topk(flat.abs(), k, sorted=False).indices

        topk_vals = flat[topk_idx].to(torch.float32)
        if grad_scale != 1.0:
            topk_vals = topk_vals * float(grad_scale)
        values_np = topk_vals.detach().cpu().numpy().astype(np.float32, copy=True)
        indices_np = topk_idx.detach().to(torch.int32).cpu().numpy().astype(np.int32, copy=True)

        bucket = sparse_parts.get(name)
        if bucket is None:
            bucket = {
                "shape": list(grad.shape),
                "numel": int(numel),
                "indices": [],
                "values": [],
            }
            sparse_parts[name] = bucket
        bucket["indices"].append(indices_np)
        bucket["values"].append(values_np)

        # Free this gradient immediately to reduce peak memory.
        param.grad = None

    if device.type == "cuda":
        torch.cuda.empty_cache()
    elif device.type == "mps" and hasattr(torch, "mps") and hasattr(torch.mps, "empty_cache"):
        torch.mps.empty_cache()

    return raw_bytes, bad_param


def finalize_sparse_gradient_parts(
    sparse_parts: Dict[str, Dict[str, Any]],
    ratio: float = 0.001,
) -> Tuple[Dict[str, Any], int]:
    """Merge per-batch sparse parts and emit final binary_v2 payload."""
    compressed: Dict[str, Any] = {
        "dtype": "torch.float32",
        "fmt": "binary_v2",
    }
    grad_count = 0

    for name, bucket in sparse_parts.items():
        indices_chunks = bucket.get("indices", [])
        values_chunks = bucket.get("values", [])
        if not indices_chunks or not values_chunks:
            continue

        all_indices = np.concatenate(indices_chunks).astype(np.int32, copy=False)
        all_values = np.concatenate(values_chunks).astype(np.float32, copy=False)
        if all_indices.size == 0 or all_values.size == 0:
            continue

        # Deduplicate repeated indices across microbatches by summing values.
        order = np.argsort(all_indices, kind="mergesort")
        sorted_indices = all_indices[order]
        sorted_values = all_values[order]
        unique_indices, first_positions = np.unique(sorted_indices, return_index=True)
        summed_values = np.add.reduceat(sorted_values, first_positions).astype(np.float32, copy=False)

        numel = int(bucket["numel"])
        k_cap = max(1, int(numel * ratio))
        if unique_indices.size > k_cap:
            selected = np.argpartition(np.abs(summed_values), -k_cap)[-k_cap:]
            unique_indices = unique_indices[selected]
            summed_values = summed_values[selected]

        k = int(unique_indices.size)
        packed = zlib.compress(
            summed_values.astype(np.float32, copy=False).tobytes()
            + unique_indices.astype(np.int32, copy=False).tobytes(),
            level=1,
        )
        compressed[name] = {
            "shape": bucket["shape"],
            "k": k,
            "data": base64.b64encode(packed).decode("ascii"),
            "fmt": "binary_v2",
        }
        grad_count += 1

    return compressed, grad_count


def compress_gradients_topk_binary_v2(
    gradients: Dict[str, torch.Tensor],
    ratio: float = 0.001,
    small_tensor_threshold: int = 10000,
) -> Dict[str, Any]:
    """
    Compress gradients with GPU-first TopK and binary_v2 output format.
    TopK is computed on the source device; only selected values/indices move to CPU.
    """
    if not gradients:
        return {"dtype": "torch.float32", "fmt": "binary_v2"}

    compressed: Dict[str, Any] = {
        "dtype": "torch.float32",
        "fmt": "binary_v2",
    }

    for name, grad in gradients.items():
        flat = grad.flatten()
        numel = flat.numel()
        if numel == 0:
            continue

        if numel < small_tensor_threshold:
            # Small tensors: keep all values, skip TopK selection.
            k = numel
            topk_idx = torch.arange(numel, device=flat.device, dtype=torch.long)
        else:
            k = max(1, int(numel * ratio))
            topk_idx = torch.topk(flat.abs(), k, sorted=False).indices

        topk_vals = flat[topk_idx].to(torch.float32)
        values_np = topk_vals.detach().cpu().numpy().astype(np.float32, copy=False)
        indices_np = topk_idx.detach().to(torch.int32).cpu().numpy().astype(np.int32, copy=False)

        packed = values_np.tobytes() + indices_np.tobytes()
        packed = zlib.compress(packed, level=1)

        compressed[name] = {
            "shape": list(grad.shape),
            "k": int(k),
            "data": base64.b64encode(packed).decode("ascii"),
            "fmt": "binary_v2",
        }

    return compressed


def check_nan_gradients(gradients: Dict[str, torch.Tensor]) -> Tuple[bool, Optional[str]]:
    """Check if any gradients contain NaN values.
    
    Returns:
        (has_nan, param_name): True and the param name if NaN found, else (False, None)
    """
    for name, grad in gradients.items():
        if torch.isnan(grad).any():
            return True, name
        if torch.isinf(grad).any():
            return True, f"{name} (inf)"
    return False, None


def _validate_delta_tensors(
    state_dict: Dict[str, torch.Tensor],
    delta: Dict[str, torch.Tensor],
) -> Tuple[bool, str]:
    if not isinstance(delta, dict):
        return False, "delta_not_dict"
    for name, diff in delta.items():
        if name not in state_dict:
            return False, f"unknown_key:{name}"
        if not isinstance(diff, torch.Tensor):
            return False, f"invalid_tensor:{name}"
        if tuple(diff.shape) != tuple(state_dict[name].shape):
            return False, (
                f"shape_mismatch:{name}:"
                f"delta={tuple(diff.shape)} expected={tuple(state_dict[name].shape)}"
            )
    return True, "ok"



def apply_delta_update(model_path: Path, delta_data: Dict, from_version: int, to_version: int) -> bool:
    """
    Apply delta update to cached model.
    
    Args:
        model_path: Path to cached model file
        delta_data: Compressed delta from PS
        from_version: Version we're updating from
        to_version: Version we're updating to
    
    Returns:
        True if successful
    """
    from src.compression import decompress_gradients
    
    print(f"🔄 Applying delta update (v{from_version} → v{to_version})...")
    
    try:
        # Load current model
        state_dict = torch.load(model_path, map_location='cpu', weights_only=True)
        
        # Decompress delta (binary_v2 compatible)
        delta = decompress_gradients(delta_data, device=torch.device("cpu"))

        ok, reason = _validate_delta_tensors(state_dict, delta)
        if not ok:
            print(f"   ❌ Delta validation failed: {reason}")
            return False
        
        # Apply delta: new = old + delta
        updated_count = 0
        for name, diff in delta.items():
            if name in state_dict:
                state_dict[name] = state_dict[name] + diff
                updated_count += 1
        
        # Save updated model
        torch.save(state_dict, model_path)
        
        print(f"   ✅ Applied delta to {updated_count} parameters")
        return True
        
    except Exception as e:
        print(f"   ❌ Delta apply failed: {e}")
        return False


def request_delta_update(ps_url: str, from_version: int, auth_token: Optional[str] = None) -> Optional[Dict]:
    """
    Request delta from PS.
    
    Returns:
        Delta response dict if successful, None otherwise
    """
    try:
        resp = requests.get(
            f"{ps_url}/model/delta",
            params={"from_version": from_version},
            headers=_auth_headers(auth_token),
            timeout=120
        )
        
        if resp.status_code == 200:
            data = resp.json()
            data["_payload_bytes"] = len(resp.content)
            if data.get("status") == "ok":
                return data
            elif data.get("status") == "no_changes":
                print(f"   ℹ️ No changes between versions")
                return {"status": "no_changes", "to_version": data.get("to_version")}
        
        # Delta not available, need full download
        return None
        
    except Exception as e:
        print(f"   ⚠️ Delta request failed: {e}")
        return None


def download_model_streaming(ps_url: str, save_path: Path, auth_token: Optional[str] = None) -> bool:
    """Download model using streaming to avoid memory spikes."""
    print("📥 Downloading model (streaming)...")
    tmp_path = None
    
    try:
        with requests.get(
            f"{ps_url}/model",
            stream=True,
            headers=_auth_headers(auth_token),
            timeout=30,
        ) as resp:
            resp.raise_for_status()
            
            # Stream to temp file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pt') as tmp:
                total_bytes = 0
                for chunk in resp.iter_content(chunk_size=8192):
                    tmp.write(chunk)
                    total_bytes += len(chunk)
                    if total_bytes % (10 * 1024 * 1024) == 0:  # Every 10MB
                        print(f"   Downloaded {total_bytes / 1e6:.1f} MB...")
                
                tmp_path = tmp.name
        
        # Load from temp file with weights_only=True (security)
        print(f"📦 Loading model from disk ({total_bytes / 1e6:.1f} MB)...")
        state_dict = torch.load(tmp_path, map_location='cpu', weights_only=True)
        
        # Save to final location
        torch.save(state_dict, save_path)
        os.remove(tmp_path)
        
        print(f"✅ Model saved to {save_path}")
        return True
        
    except Exception as e:
        print(f"❌ Model download failed: {e}")
        # Clean up temp file on failure to prevent disk leaks
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
                print(f"🧹 Cleaned up temp file: {tmp_path}")
            except OSError:
                pass
        return False


def request_task(
    ps_url: str,
    wallet_address: str,
    capabilities: Dict,
    auth_token: Optional[str] = None,
) -> Optional[Dict]:
    """
    Request a training task from PS with hardware capabilities.
    
    Args:
        ps_url: Parameter server URL
        wallet_address: Miner wallet/ID
        capabilities: Hardware info (must include memory_gb)
    
    Returns:
        Task dict with assigned_layers and model_version
    """
    try:
        resp = requests.post(
            f"{ps_url}/task/request",
            json={
                "miner_id": wallet_address,
                "capabilities": capabilities
            },
            headers=_auth_headers(auth_token),
            timeout=10
        )
        
        if resp.status_code == 200:
            task = resp.json()
            assigned_layers = task.get('assigned_layers', list(range(32)))
            print(f"📋 Task assigned: shard {task['shard_id']}, "
                  f"layers {len(assigned_layers)}/32, "
                  f"task_id={task['task_id'][:8]}...")
            return task
        elif resp.status_code == 503:
            print("⏳ No tasks available, waiting...")
            return None
        elif resp.status_code == 400:
            error = resp.json()
            print(f"❌ Task request rejected: {error.get('error')}")
            print(f"   {error.get('message', '')}")
            return None
        else:
            print(f"❌ Task request failed: {resp.status_code} {resp.text}")
            return None
            
    except Exception as e:
        print(f"❌ Task request error: {e}")
        return None


def request_task_detailed(
    ps_url: str,
    wallet_address: str,
    capabilities: Dict,
    auth_token: Optional[str] = None,
) -> Tuple[Optional[Dict], str]:
    """
    Request a task and return a detailed status.

    Returns:
        (task, status) where status is one of:
        - "ok": task available
        - "no_task": PS has no task currently
        - "failed": request/network error
    """
    try:
        resp = requests.post(
            f"{ps_url}/task/request",
            json={
                "miner_id": wallet_address,
                "capabilities": capabilities,
            },
            headers=_auth_headers(auth_token),
            timeout=10,
        )

        if resp.status_code == 200:
            task = resp.json()
            assigned_layers = task.get("assigned_layers", list(range(32)))
            print(
                f"📋 Task assigned: shard {task['shard_id']}, "
                f"layers {len(assigned_layers)}/32, "
                f"task_id={task['task_id'][:8]}..."
            )
            return task, "ok"

        if resp.status_code == 503:
            print("⏳ No tasks available, waiting...")
            return None, "no_task"

        if resp.status_code == 400:
            error = resp.json()
            print(f"❌ Task request rejected: {error.get('error')}")
            print(f"   {error.get('message', '')}")
            return None, "failed"

        print(f"❌ Task request failed: {resp.status_code} {resp.text}")
        return None, "failed"

    except Exception as e:
        print(f"❌ Task request error: {e}")
        return None, "failed"


def request_task_with_retry(
    ps_url: str,
    wallet_address: str,
    capabilities: Dict,
    auth_token: Optional[str] = None,
    retry_delay: int = 15,
    max_attempts: int = 5,
) -> Tuple[Optional[Dict], str]:
    """
    Retry task requests on failures; re-register after repeated failures.

    Returns:
        (task, status) where status is:
        - "ok": task returned
        - "no_task": currently no task
        - "re_register": too many failures, caller should re-register
    """
    fail_count = 0
    while fail_count < max_attempts:
        task, status = request_task_detailed(
            ps_url,
            wallet_address,
            capabilities,
            auth_token=auth_token,
        )
        if status == "ok":
            return task, "ok"
        if status == "no_task":
            return None, "no_task"

        fail_count += 1
        if fail_count < max_attempts:
            print(f"⚠️ Task request failed, retrying in {retry_delay}s... (attempt {fail_count}/{max_attempts})")
            time.sleep(retry_delay)

    print("⚠️ Task request failed repeatedly, will re-register")
    return None, "re_register"


def register_miner_with_retry(
    ps_url: str,
    wallet_address: str,
    wallet_keypair: Optional[Any],
    capabilities: Dict[str, Any],
    retry_seconds: int = 30,
) -> Dict[str, Any]:
    """
    Register forever until success. Raises KeyboardInterrupt to allow graceful exit.
    """
    attempt = 0
    while True:
        attempt += 1
        register_response = register_miner(ps_url, wallet_address, wallet_keypair, capabilities)
        if register_response:
            return register_response
        print(f"⚠️ PS unreachable, retrying in {retry_seconds}s... (attempt {attempt})")
        time.sleep(retry_seconds)


def _best_layer_bucket(requested_layers: int, available_layers: List[int]) -> int:
    requested = max(1, int(requested_layers))
    cleaned_set = set()
    for value in available_layers:
        with contextlib.suppress(TypeError, ValueError):
            v = int(value)
            if v > 0:
                cleaned_set.add(v)
    cleaned = sorted(cleaned_set)
    if not cleaned:
        return max(4, requested)
    for layer_count in cleaned:
        if layer_count >= requested:
            return layer_count
    return cleaned[-1]


def _download_partial_model_from_nginx(
    ps_url: str,
    assigned_layers: List[int],
    model_path: Path,
    auth_token: Optional[str] = None,
) -> Tuple[bool, int]:
    """Try static file download via nginx using /model/info metadata."""
    info_resp = requests.get(
        f"{ps_url}/model/info",
        headers=_auth_headers(auth_token),
        timeout=15,
    )
    info_resp.raise_for_status()
    info = info_resp.json()

    base_url = str(info.get("base_url") or "").rstrip("/")
    version = int(info.get("version", 0))
    available_layers = info.get("available_layers") or [4, 8, 12, 16, 20, 24, 32]
    bucket = _best_layer_bucket(len(assigned_layers), available_layers)
    file_name = f"v{version}_layers_0-{bucket-1}.pt"
    file_url = f"{base_url}/{file_name}"
    print(f"📥 Downloading static model from {file_url}")

    remote_size = 0
    with contextlib.suppress(Exception):
        head = requests.head(file_url, timeout=10)
        if head.status_code == 200:
            remote_size = int(head.headers.get("content-length", "0") or 0)

    # Cache hit: reuse same file if byte size matches.
    if model_path.exists() and remote_size > 0:
        local_size = model_path.stat().st_size
        if remote_size == local_size:
            _ = torch.load(model_path, map_location="cpu", mmap=True, weights_only=True)
            print(f"✅ Reusing cached static model: {model_path.name}")
            return True, local_size

    tmp_path = model_path.with_suffix(model_path.suffix + ".tmp")
    resume_offset = tmp_path.stat().st_size if tmp_path.exists() else 0
    req_headers = {}
    if resume_offset > 0:
        req_headers["Range"] = f"bytes={resume_offset}-"
        print(
            f"↩️ Resuming static download from offset {resume_offset:,}"
            + (f" / {remote_size:,}" if remote_size > 0 else "")
        )

    with requests.get(file_url, headers=req_headers, stream=True, timeout=600) as resp:
        if resp.status_code == 206 and resume_offset > 0:
            mode = "ab"
            content_range = resp.headers.get("Content-Range", "")
            total_hint = content_range.split("/")[-1] if "/" in content_range else "?"
            print(f"✅ HTTP 206 resume accepted ({resume_offset:,} -> total {total_hint})")
        elif resp.status_code == 200:
            if resume_offset > 0:
                print("ℹ️ Server returned HTTP 200, restarting static download from byte 0")
            mode = "wb"
            resume_offset = 0
        else:
            resp.raise_for_status()
            mode = "wb"

        resp.raise_for_status()
        total_bytes = resume_offset
        with open(tmp_path, mode) as f:
            for chunk in resp.iter_content(chunk_size=1024 * 1024):
                if not chunk:
                    continue
                f.write(chunk)
                total_bytes += len(chunk)
                if total_bytes % (100 * 1024 * 1024) == 0:
                    print(f"   Downloaded {total_bytes / 1e9:.2f} GB...")

    print(
        f"✅ Static file assembled: {total_bytes:,} bytes"
        + (f" (expected ~{remote_size:,})" if remote_size > 0 else "")
    )
    _ = torch.load(tmp_path, map_location="cpu", mmap=True, weights_only=True)
    os.replace(tmp_path, model_path)
    return True, total_bytes


def download_partial_model_with_retry(
    ps_url: str,
    assigned_layers: List[int],
    model_path: Path,
    auth_token: Optional[str] = None,
    max_attempts: int = 3,
    retry_delay: int = 10,
) -> Tuple[bool, int]:
    """
    Download assigned layers with retry and corruption check.

    Returns:
        (success, total_bytes)
    """
    tmp_path = model_path.with_suffix(model_path.suffix + ".tmp")

    for attempt in range(1, max_attempts + 1):
        try:
            print(
                f"📥 Downloading partial model ({len(assigned_layers)} layers)... "
                f"(attempt {attempt}/{max_attempts})"
            )

            # Preferred path: nginx static model files.
            try:
                ok, total_bytes = _download_partial_model_from_nginx(
                    ps_url=ps_url,
                    assigned_layers=assigned_layers,
                    model_path=model_path,
                    auth_token=auth_token,
                )
                if ok:
                    print("✅ Static model download success")
                    return True, total_bytes
            except Exception as static_err:
                print(f"⚠️ Static model download failed, fallback to PS API: {static_err}")

            # Fallback path: PS route with best-effort resume.
            resume_offset = tmp_path.stat().st_size if tmp_path.exists() else 0
            req_headers = _auth_headers(auth_token)
            if resume_offset > 0:
                req_headers["Range"] = f"bytes={resume_offset}-"
                print(f"↩️ Resuming fallback /model/layers from offset {resume_offset:,}")

            with requests.post(
                f"{ps_url}/model/layers",
                json={"assigned_layers": assigned_layers},
                headers=req_headers,
                stream=True,
                timeout=600,
            ) as resp:
                if resp.status_code == 206 and resume_offset > 0:
                    mode = "ab"
                    print("✅ Fallback endpoint accepted HTTP 206 resume")
                elif resp.status_code == 200:
                    if resume_offset > 0:
                        print("ℹ️ Fallback endpoint returned HTTP 200, restarting from byte 0")
                    mode = "wb"
                    resume_offset = 0
                elif resp.status_code == 416 and resume_offset > 0:
                    print("ℹ️ Fallback resume offset invalid (416), clearing tmp and retrying")
                    with contextlib.suppress(Exception):
                        tmp_path.unlink()
                    raise requests.HTTPError("HTTP 416 on fallback resume")
                else:
                    resp.raise_for_status()
                    mode = "wb"

                resp.raise_for_status()
                total_bytes = resume_offset
                with open(tmp_path, mode) as f:
                    for chunk in resp.iter_content(chunk_size=8192):
                        if not chunk:
                            continue
                        f.write(chunk)
                        total_bytes += len(chunk)
                        if total_bytes % (100 * 1024 * 1024) == 0:
                            print(f"   Downloaded {total_bytes / 1e9:.2f} GB...")

            _ = torch.load(tmp_path, map_location="cpu", mmap=True, weights_only=True)
            os.replace(tmp_path, model_path)
            return True, total_bytes

        except Exception as e:
            print(f"⚠️ Model download failed, retrying... ({attempt}/{max_attempts}) error={e}")
            if attempt < max_attempts:
                time.sleep(retry_delay)

    return False, 0


def format_uptime(seconds: float) -> str:
    total = int(max(0, seconds))
    hours = total // 3600
    minutes = (total % 3600) // 60
    return f"{hours}h {minutes}m"


def download_shard_streaming(ps_url: str, shard_id: int, auth_token: Optional[str] = None) -> Optional[Dict]:
    """Download a single shard using streaming."""
    try:
        with requests.get(
            f"{ps_url}/task/shard/{shard_id}",
            stream=True,
            headers=_auth_headers(auth_token),
            timeout=30,
        ) as resp:
            resp.raise_for_status()
            
            # Stream to temp file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pt') as tmp:
                for chunk in resp.iter_content(chunk_size=8192):
                    tmp.write(chunk)
                tmp_path = tmp.name
        
        # Load from temp file
        shard_data = torch.load(tmp_path, map_location='cpu', weights_only=True)
        os.remove(tmp_path)
        
        return shard_data
        
    except Exception as e:
        print(f"❌ Shard {shard_id} download failed: {e}")
        return None


def train_shard(
    model: nn.Module,
    shard_data: Dict,
    device: torch.device,
    assigned_layers: List[int],
    batch_size: int = 2,
    seq_len: int = 512,
    max_batches: int = 10,
    scaler: Optional[torch.cuda.amp.GradScaler] = None,
    precision_mode: str = "fp16",
    compression_ratio: float = 0.001,
    grad_scale: float = 1e-5,
) -> Tuple[float, int, int, int, bool, Dict[str, Any], int, int, Optional[str]]:
    """
    Train model on shard and return gradients from assigned layers.
    
    Forward pass runs on full model to compute loss.
    Backward pass only computes gradients for unfrozen (assigned) layers.
    
    Args:
        model: LlamaNanoModel
        shard_data: {'tokens': tensor, 'shard_id': int, 'num_tokens': int}
        device: Training device
        assigned_layers: List of layer indices to train
        batch_size: Batch size for training
        seq_len: Sequence length
        max_batches: Maximum number of batches to train
    
    Returns:
        (
            avg_loss,
            num_batches,
            next_batch_size,
            invalid_loss_batches,
            oom_aborted,
            compressed_gradients,
            raw_bytes,
            grad_count,
            bad_param,
        )
    """
    model.train()
    model.zero_grad(set_to_none=True)
    
    # Extract tokens. Accept both {"tokens": tensor} and raw tensor shard formats.
    if isinstance(shard_data, dict):
        token_tensor = shard_data.get("tokens")
        if token_tensor is None:
            token_tensor = shard_data.get("input_ids")
    elif torch.is_tensor(shard_data):
        token_tensor = shard_data
    else:
        token_tensor = None

    if token_tensor is None:
        raise ValueError(f"Unsupported shard format: {type(shard_data)}")

    tokens = token_tensor.view(-1).long()
    num_tokens = tokens.numel()
    
    print(f"   Shard has {num_tokens:,} tokens, training {max_batches} batches...")
    
    # Prepare sequences
    max_start = max(1, num_tokens - seq_len - 1)
    num_sequences = max_start
    
    # Train in batches
    total_loss = 0.0
    num_batches = 0
    current_batch_size = max(1, int(batch_size))
    start_idx = 0
    oom_retries_at_bs1 = 0
    invalid_loss_batches = 0
    oom_aborted = False
    raw_bytes_total = 0
    bad_param: Optional[str] = None
    sparse_parts: Dict[str, Dict[str, Any]] = {}
    ef_residuals: Dict[str, torch.Tensor] = {}
    if USE_ERROR_FEEDBACK:
        print("INFO: EF enabled, residual buffers use lazy CPU allocation")

    while start_idx < num_sequences:
        # Create batch
        batch_inputs = []
        batch_labels = []
        
        for i in range(current_batch_size):
            offset = start_idx + i * seq_len
            if offset + seq_len + 1 > num_tokens:
                break
            
            chunk = tokens[offset : offset + seq_len + 1]
            batch_inputs.append(chunk[:-1])
            batch_labels.append(chunk[1:])
        
        if len(batch_inputs) == 0:
            break
        
        # Stack batch
        input_ids = torch.stack(batch_inputs).to(device)
        labels = torch.stack(batch_labels).to(device)
        
        use_amp = (
            (device.type == "mps" and precision_mode == "fp16")
            or (device.type == "cuda" and precision_mode == "fp16")
        )
        try:
            if use_amp:
                autocast_ctx = torch.autocast(device_type=device.type, dtype=torch.float16)
            else:
                autocast_ctx = contextlib.nullcontext()

            with autocast_ctx:
                _, loss = model(input_ids, labels)

            if loss is not None:
                if torch.isnan(loss) or torch.isinf(loss):
                    invalid_loss_batches += 1
                    print(f"⚠️ Warning: Invalid loss {loss.item()}, skipping batch")
                    start_idx += len(batch_inputs) * seq_len
                    continue
                hooks: List[Any] = []
                compressed_grads: Dict[str, Dict[str, Any]] = {}
                # Backward pass (only assigned layers will have gradients)
                hooks, compressed_grads = register_compression_hooks(
                    model=model,
                    assigned_layers=assigned_layers,
                    ratio=compression_ratio,
                    scaler=scaler,
                    grad_scale=float(grad_scale),
                    small_tensor_threshold=10000,
                    use_error_feedback=USE_ERROR_FEEDBACK,
                    residuals=ef_residuals,
                )
                try:
                    if (
                        device.type == "cuda"
                        and scaler is not None
                        and scaler.is_enabled()
                        and precision_mode == "fp16"
                    ):
                        scaler.scale(loss).backward()
                    else:
                        loss.backward()
                finally:
                    for h in hooks:
                        h.remove()
                torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                meta = compressed_grads.get("__meta__", {})
                raw_bytes_total += int(meta.get("raw_bytes", 0))
                if bad_param is None and meta.get("bad_param") is not None:
                    bad_param = meta.get("bad_param")
                for name, bucket in compressed_grads.items():
                    if name == "__meta__":
                        continue
                    merged = sparse_parts.get(name)
                    if merged is None:
                        merged = {
                            "shape": bucket["shape"],
                            "numel": bucket["numel"],
                            "indices": [],
                            "values": [],
                        }
                        sparse_parts[name] = merged
                    merged["indices"].extend(bucket.get("indices", []))
                    merged["values"].extend(bucket.get("values", []))
                total_loss += loss.item()
                num_batches += 1
                if USE_ERROR_FEEDBACK and num_batches % 10 == 0 and ef_residuals:
                    residual_norm = sum(float(torch.norm(r.float()).item()) for r in ef_residuals.values())
                    print(f"[EF] step={num_batches} residual_norm={residual_norm:.6f}")
        except torch.cuda.OutOfMemoryError:
            if device.type == "cuda":
                torch.cuda.empty_cache()
            new_batch_size = max(1, current_batch_size // 2)
            if new_batch_size != current_batch_size:
                current_batch_size = new_batch_size
                print(f"⚠️ OOM, reducing batch size to {current_batch_size}")
            else:
                oom_retries_at_bs1 += 1
                print("⚠️ OOM at batch_size=1, retrying...")
                if oom_retries_at_bs1 >= 3:
                    print("⚠️ Repeated OOM at batch_size=1, aborting shard.")
                    oom_aborted = True
                    break
            model.zero_grad(set_to_none=True)
            continue
        except RuntimeError as exc:
            if "out of memory" in str(exc).lower():
                if device.type == "cuda":
                    torch.cuda.empty_cache()
                new_batch_size = max(1, current_batch_size // 2)
                if new_batch_size != current_batch_size:
                    current_batch_size = new_batch_size
                    print(f"⚠️ OOM, reducing batch size to {current_batch_size}")
                else:
                    oom_retries_at_bs1 += 1
                    print("⚠️ OOM at batch_size=1, retrying...")
                    if oom_retries_at_bs1 >= 3:
                        print("⚠️ Repeated OOM at batch_size=1, aborting shard.")
                        oom_aborted = True
                        break
                model.zero_grad(set_to_none=True)
                continue
            raise

        oom_retries_at_bs1 = 0
        start_idx += len(batch_inputs) * seq_len
        
        # Print progress
        if num_batches % 5 == 0:
            avg_loss = total_loss / num_batches
            print(f"   Batch {num_batches}/{max_batches}, avg_loss={avg_loss:.4f}")
        
        # Stop after max_batches
        if num_batches >= max_batches:
            print(f"   ⏹️  Reached max_batches limit ({max_batches})")
            break
    
    avg_loss = total_loss / num_batches if num_batches > 0 else 0.0
    print(f"   ✅ Training complete: {num_batches} batches, avg_loss={avg_loss:.4f}")
    compressed, grad_count = finalize_sparse_gradient_parts(
        sparse_parts=sparse_parts,
        ratio=compression_ratio,
    )
    return (
        avg_loss,
        num_batches,
        current_batch_size,
        invalid_loss_batches,
        oom_aborted,
        compressed,
        raw_bytes_total,
        grad_count,
        bad_param,
    )


def submit_gradient(
    ps_url: str,
    task_id: str,
    task_nonce: str,
    gradient_data: Dict,
    metrics: Dict,
    auth_token: Optional[str] = None,
) -> bool:
    """Submit compressed gradient to PS with retry for transient failures."""
    # Compute hash once to avoid repeated serialization work on retries.
    gradient_bytes = json.dumps(gradient_data, sort_keys=True).encode()
    gradient_hash = hashlib.sha256(gradient_bytes).hexdigest()

    payload = {
        "task_id": task_id,
        "task_nonce": task_nonce,
        "gradient_data": gradient_data,
        "gradient_hash": gradient_hash,
        "metrics": metrics,
    }

    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        try:
            resp = requests.post(
                f"{ps_url}/task/complete",
                json=payload,
                headers=_auth_headers(auth_token),
                timeout=900,
            )

            if resp.status_code == 200:
                result = resp.json()
                print(f"✅ Gradient accepted! Score: {result.get('score', 'N/A'):.4f}")
                return True

            # 4xx usually means semantic rejection; no retry.
            if 400 <= resp.status_code < 500:
                error_data = resp.json() if resp.headers.get("content-type") == "application/json" else {}
                print(f"❌ Gradient rejected: {resp.status_code}")
                print(f"   Reason: {error_data.get('reason', 'Unknown')}")
                print(f"   Score: {error_data.get('score', 'N/A')}")
                return False

            # 5xx can be transient; retry.
            raise requests.exceptions.RequestException(
                f"server_error status={resp.status_code} body={resp.text[:200]}"
            )

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
            if attempt < max_attempts:
                print(f"⚠️ Submission failed, retrying... (attempt {attempt}/{max_attempts}) error={e}")
                time.sleep(10)
            else:
                print("⚠️ Submission failed after 3 attempts, discarding this gradient and requesting next task")
                return False

    return False


def _cleanup_stale_temp_files():
    """Remove leftover .pt temp files from /tmp and .tmp model caches on startup."""
    cleaned = 0

    # 1. /tmp/*.pt — leaked by download_model_streaming (NamedTemporaryFile)
    tmp_dir = Path(tempfile.gettempdir())
    for f in tmp_dir.glob("tmp*.pt"):
        try:
            age_hours = (time.time() - f.stat().st_mtime) / 3600
            if age_hours > 1:  # Only clean files older than 1 hour
                size_mb = f.stat().st_size / (1024 * 1024)
                f.unlink()
                print(f"🧹 Cleaned stale temp: {f.name} ({size_mb:.0f} MB, {age_hours:.1f}h old)")
                cleaned += 1
        except OSError:
            pass

    # 2. *.pt.tmp — stale partial downloads next to model cache
    cwd = Path.cwd()
    for f in list(cwd.glob("*.pt.tmp")) + list(Path.home().glob(".alice/*.pt.tmp")):
        try:
            age_hours = (time.time() - f.stat().st_mtime) / 3600
            if age_hours > 2:  # Partial downloads older than 2 hours are stale
                size_mb = f.stat().st_size / (1024 * 1024)
                f.unlink()
                print(f"🧹 Cleaned stale partial: {f.name} ({size_mb:.0f} MB, {age_hours:.1f}h old)")
                cleaned += 1
        except OSError:
            pass

    if cleaned:
        print(f"🧹 Startup cleanup: removed {cleaned} stale file(s)")
    else:
        print("✅ Startup cleanup: no stale files found")


def main():
    parser = argparse.ArgumentParser(description="Alice Miner V2 - Tiered Training")
    parser.add_argument("--ps-url", required=True, help="Parameter server URL")
    parser.add_argument("--wallet", "--address", default=None, help="Wallet address override")
    parser.add_argument("--wallet-path", type=Path, default=DEFAULT_WALLET_PATH, help="Wallet file path")
    parser.add_argument(
        "--allow-insecure",
        action="store_true",
        default=False,
        help="Allow insecure HTTP connections and wallet bypass (dev/testing only)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=2,
        help="Max batch size cap (default: 2)",
    )
    parser.add_argument(
        "--lr",
        type=float,
        default=1e-5,
        help="Gradient scale factor for submitted updates",
    )
    parser.add_argument("--seq-len", type=int, default=128, help="Sequence length")
    parser.add_argument("--max-batches", type=int, default=10, help="Max batches per shard")
    parser.add_argument("--model-path", type=Path, default=None, help="Pre-downloaded model path (skip download)")
    parser.add_argument("--device", default=None, help="Training device override: cuda|mps|cpu")
    parser.add_argument(
        "--precision",
        default="auto",
        choices=["auto", "fp16", "fp32"],
        help="Precision mode selection",
    )
    args = parser.parse_args()
    args.ps_url = str(args.ps_url).strip().rstrip("/")

    ps_url_lower = args.ps_url.lower()
    if ps_url_lower.startswith("https://"):
        pass
    elif ps_url_lower.startswith("http://"):
        if args.allow_insecure:
            print("[WARNING] ⚠️ Using insecure HTTP connection. NOT for production use.")
        else:
            print("[ERROR] PS URL must use https://. Use --allow-insecure for dev/testing only.")
            sys.exit(1)
    else:
        print("[ERROR] PS URL must start with https:// (or http:// with --allow-insecure).")
        sys.exit(1)

    # Load wallet
    wallet_keypair: Optional[Any] = None
    if args.wallet:
        wallet_address = args.wallet
        print(f"🔑 Using wallet address: {wallet_address}")
    else:
        try:
            wallet = get_or_create_wallet_for_miner(args.wallet_path)
        except RuntimeError as exc:
            print(str(exc))
            return
        wallet_address = wallet.address
        wallet_keypair = wallet.to_keypair()
        del wallet

    # Hold process-wide non-blocking file lock to prevent duplicate miners.
    _lock_fp = acquire_single_instance_lock()

    # Persistent runtime stats for uptime logging.
    miner_start_time = time.time()
    tasks_processed = 0
    shards_trained = 0
    gradients_accepted = 0
    gradients_rejected = 0
    profile_path = device_profile_path()

    # Startup cleanup: remove stale temp files from previous crashed downloads.
    _cleanup_stale_temp_files()

    # Never exit on transient errors; only Ctrl+C stops the miner.
    while True:
        try:
            # Get hardware capabilities (auto-detect unless overridden).
            capabilities = get_hardware_info(args.device)
            profile_key = device_profile_key(wallet_address, capabilities)
            profile = load_device_profile(profile_path, profile_key)

            # Restore learned memory cap (device-local only), then refresh capabilities.
            profile_mem_cap = profile.get("memory_cap_gb")
            if isinstance(profile_mem_cap, (int, float)) and profile_mem_cap > 0:
                os.environ["ALICE_MEMORY_CAP_GB"] = f"{float(profile_mem_cap):.3f}"
                capabilities = get_hardware_info(args.device)

            runtime_seq_len = int(profile.get("stable_seq_len", args.seq_len))
            runtime_seq_len = max(64, min(int(args.seq_len), runtime_seq_len))
            profile_batch_cap = int(profile.get("stable_batch_cap", 0))
            last_oom_ts = float(profile.get("last_oom_ts", 0.0))
            last_upgrade_ts = float(profile.get("last_upgrade_ts", 0.0))
            oom_abort_streak = 0
            upgraded_this_run = False

            # Registration retry forever.
            register_response = register_miner_with_retry(
                args.ps_url,
                wallet_address,
                wallet_keypair,
                capabilities,
                retry_seconds=30,
            )
            auth_token = str(register_response.get("token", "")).strip()
            if not auth_token:
                print("❌ Registration succeeded but no auth token returned; retrying in 30s...")
                time.sleep(30)
                continue

            # Use first assigned task to learn layer assignment + model version.
            print("📥 Requesting task to get layer assignment...")
            pending_task: Optional[Dict[str, Any]] = None
            while pending_task is None:
                task, status = request_task_with_retry(
                    args.ps_url,
                    wallet_address,
                    capabilities,
                    auth_token=auth_token,
                    retry_delay=15,
                    max_attempts=5,
                )
                if status == "ok" and task is not None:
                    pending_task = task
                    break
                if status == "no_task":
                    time.sleep(10)
                    continue
                if status == "re_register":
                    break

            if pending_task is None:
                # Could not acquire task after retries; restart registration flow.
                print("⚠️ Could not acquire task after retries, re-registering...")
                time.sleep(30)
                continue

            assigned_layers = pending_task.get("assigned_layers", [0, 1, 2, 3, 4, 5, 6, 7])
            ps_version = pending_task.get("model_version", 0)
            print(f"   📋 Assigned layers: {assigned_layers}")
            print(f"   📋 PS model version: {ps_version}")

            # Download partial model (only assigned layers) with version caching
            # Use --model-path location when provided (even if file not yet exists)
            if args.model_path:
                model_path = args.model_path
                model_path.parent.mkdir(parents=True, exist_ok=True)
                if model_path.exists():
                    print(f"📁 Using pre-downloaded model: {model_path}")
                    need_download = False
                else:
                    print(f"📁 Using custom model cache path: {model_path}")
                    need_download = True
            else:
                model_path = Path("./miner_model_partial.pt")
                need_download = True
            # Keep metadata next to model cache to avoid cwd mismatch issues.
            meta_path = model_path.with_name("miner_model_meta.json")

            # Check if cached model is still valid
            if model_path.exists() and meta_path.exists():
                try:
                    with open(meta_path, "r") as f:
                        meta = json.load(f)
                    local_version = meta.get("version", -1)
                    local_layers = meta.get("layers", [])
                    if local_version == ps_version and local_layers == assigned_layers:
                        print(f"✅ Cached model valid (version {local_version}, {len(local_layers)} layers)")
                        need_download = False
                    elif local_version + 1 == ps_version and local_layers == assigned_layers:
                        # Try delta update
                        print(f"🔄 Attempting delta update (v{local_version} → v{ps_version})...")
                        delta_resp = request_delta_update(
                            args.ps_url,
                            local_version,
                            auth_token=auth_token,
                        )

                        if delta_resp and delta_resp.get("status") == "ok":
                            delta_data = delta_resp.get("delta")
                            delta_mb = delta_resp.get("_payload_bytes", 0) / (1024 * 1024)
                            meta = delta_resp.get("metadata", {})
                            selected_params = int(meta.get("selected_params", 0))
                            print(
                                f"   📦 Delta received: {delta_mb:.2f}MB, "
                                f"applying to {selected_params} parameters"
                            )
                            if apply_delta_update(model_path, delta_data, local_version, ps_version):
                                with open(meta_path, "w") as f:
                                    json.dump({"version": ps_version, "layers": assigned_layers}, f)
                                print(f"✅ Delta update successful! Now at version {ps_version}")
                                need_download = False
                            else:
                                print("⚠️ Delta apply failed, falling back to full download")
                                need_download = True
                        elif delta_resp and delta_resp.get("status") == "no_changes":
                            with open(meta_path, "w") as f:
                                json.dump({"version": ps_version, "layers": assigned_layers}, f)
                            print(f"✅ No changes, updated version to {ps_version}")
                            need_download = False
                        else:
                            print("⚠️ Delta not available, falling back to full download")
                            need_download = True
                    else:
                        print(
                            f"⚠️ Cache outdated: local v{local_version} vs PS v{ps_version} "
                            "(gap too large or layers changed)"
                        )
                        need_download = True
                except Exception:
                    print("⚠️ Could not read cache metadata, will re-download")
                    need_download = True

            if need_download:
                ok, total_bytes = download_partial_model_with_retry(
                    args.ps_url,
                    assigned_layers=assigned_layers,
                    model_path=model_path,
                    auth_token=auth_token,
                    max_attempts=3,
                    retry_delay=10,
                )
                if not ok:
                    print("❌ Model download failed after retries, restarting in 30s...")
                    time.sleep(30)
                    continue
                with open(meta_path, "w") as f:
                    json.dump({"version": ps_version, "layers": assigned_layers}, f)
                print(f"✅ Partial model downloaded: {total_bytes / 1e9:.2f} GB (version {ps_version})")
            else:
                print(f"✅ Using cached model: {model_path}")

            # Load state_dict to detect assigned_layers if not set
            print("📦 Loading partial model...")
            state_dict = torch.load(model_path, map_location="cpu", mmap=True, weights_only=True)

            if assigned_layers is None:
                # Detect from state_dict
                layer_indices = set()
                for key in state_dict.keys():
                    if "model.layers." in key:
                        parts = key.split(".")
                        if len(parts) > 2 and parts[1] == "layers":
                            layer_indices.add(int(parts[2]))
                assigned_layers = sorted(list(layer_indices))
                print(f"   📋 Detected assigned layers from checkpoint: {assigned_layers}")

            # Create SMALL model with only N layers
            print(f"   Creating {len(assigned_layers)}-layer model...")
            alice_config = AliceConfig()
            # Infer core dimensions from downloaded checkpoint to avoid shape mismatches.
            embed_weight = state_dict.get("model.embed_tokens.weight")
            if not isinstance(embed_weight, torch.Tensor) or embed_weight.ndim != 2:
                raise RuntimeError("Invalid checkpoint: missing model.embed_tokens.weight")
            inferred_vocab, inferred_dim = int(embed_weight.shape[0]), int(embed_weight.shape[1])
            inferred_hidden = int(
                state_dict.get(
                    "model.layers.0.mlp.gate_proj.weight",
                    torch.empty((alice_config.intermediate_size, inferred_dim)),
                ).shape[0]
            )
            inv_freq = state_dict.get("model.layers.0.self_attn.rotary_emb.inv_freq")
            if isinstance(inv_freq, torch.Tensor) and inv_freq.ndim == 1 and int(inv_freq.shape[0]) > 0:
                inferred_heads = max(1, inferred_dim // (2 * int(inv_freq.shape[0])))
            else:
                inferred_heads = alice_config.num_attention_heads

            alice_config.vocab_size = inferred_vocab
            alice_config.hidden_dim = inferred_dim
            alice_config.intermediate_size = inferred_hidden
            alice_config.num_attention_heads = inferred_heads
            alice_config.head_dim = max(1, inferred_dim // max(1, inferred_heads))
            alice_config.num_layers = len(assigned_layers)  # KEY: N layers, not 32

            print(f"DEBUG config.num_layers = {alice_config.num_layers}")
            print(f"DEBUG config.num_hidden_layers = {getattr(alice_config, 'num_hidden_layers', 'NOT SET')}")
            # Build the partial model normally so all buffers are initialized.
            # The meta->to_empty path can leave non-parameter buffers uninitialized
            # when loading with strict=False, which leads to NaN during forward pass.
            model = AliceForCausalLM(alice_config)

            # Map layer indices: assigned_layers -> 0..N-1
            print("   Mapping layer weights...")
            mapped_state = {}
            for k, v in state_dict.items():
                if "model.layers." in k:
                    parts = k.split(".")
                    if parts[0] == "model" and parts[1] == "layers":
                        orig_idx = int(parts[2])
                        if orig_idx in assigned_layers:
                            new_idx = assigned_layers.index(orig_idx)
                            new_key = f"model.layers.{new_idx}." + ".".join(parts[3:])
                            mapped_state[new_key] = v
                else:
                    mapped_state[k] = v

            print("   Loading weights...")
            load_result = model.load_state_dict(mapped_state, strict=False)
            missing_keys = set(load_result.missing_keys)
            unexpected_keys = load_result.unexpected_keys
            if unexpected_keys:
                print(f"   ⚠️ Unexpected keys ignored: {len(unexpected_keys)}")
            if missing_keys:
                print(f"   ⚠️ Missing keys initialized: {len(missing_keys)}")
                for name, param in model.named_parameters():
                    if name not in missing_keys:
                        continue
                    with torch.no_grad():
                        if param.ndim > 1:
                            torch.nn.init.normal_(param, mean=0.0, std=0.02)
                        else:
                            torch.nn.init.zeros_(param)
            del state_dict, mapped_state
            import gc
            gc.collect()

            print(f"   ✅ Loaded {len(assigned_layers)}-layer partial model")
            print(f"DEBUG actual layers = {len(model.model.layers)}")
            print(f"DEBUG params = {sum(p.numel() for p in model.parameters()) / 1e6:.1f}M")

            # Move model to target precision/device.
            n_layers = 32  # Total layers in full model (partial model has fewer)
            device = torch.device(capabilities["device_type"])
            if device.type == "cuda":
                total_memory_gb = torch.cuda.get_device_properties(0).total_memory / 1e9
            elif device.type == "mps":
                total_memory_gb = float(capabilities.get("memory_gb", 16.0))
            else:
                total_memory_gb = float(capabilities.get("system_memory_gb", 0.0))
            precision_mode = select_precision(
                device_type=device.type,
                memory_gb=total_memory_gb,
                assigned_layers=len(assigned_layers),
                requested=args.precision,
            )
            print(f"🎯 Target device: {device}")
            if device.type == "cuda":
                if precision_mode == "fp16":
                    model = model.half()
                else:
                    model = model.float()
                print(f"🚀 Moving model to {device}...")
                try:
                    model = model.to(device)
                except RuntimeError as exc:
                    if "out of memory" not in str(exc).lower():
                        raise
                    print("⚠️ OOM on full model.to(device), falling back to per-parameter transfer...")
                    if precision_mode == "fp16":
                        model = model._apply(lambda t: t.half().to(device))
                    else:
                        model = model._apply(lambda t: t.float().to(device))
            elif device.type == "mps":
                if precision_mode == "fp16":
                    model = model.half()
                else:
                    model = model.float()
                print(f"🚀 Moving model to {device}...")
                model = model.to(device)
            else:
                model = model.float().to(device)

            # Verify model is on correct device
            first_param = next(model.parameters())
            print(f"✅ Model loaded: {sum(p.numel() for p in model.parameters()) / 1e6:.1f}M params")
            print(f"✅ Model device: {first_param.device}")
            expected_dtype = torch.float16 if precision_mode == "fp16" else torch.float32
            if first_param.dtype != expected_dtype:
                print(f"⚠️ Precision mismatch: got {first_param.dtype}, expected {expected_dtype}")

            # Freeze non-assigned layers to keep memory bounded on low-VRAM miners.
            setup_tiered_training(model, assigned_layers, n_layers=n_layers)

            model_memory_gb = sum(p.numel() * p.element_size() for p in model.parameters()) / 1e9
            batch_size_cap, available_gb, per_sample_gb = calculate_batch_size(
                device_type=device.type,
                model_memory_gb=model_memory_gb,
                total_memory_gb=total_memory_gb,
                seq_len=runtime_seq_len,
            )
            dynamic_batch_size = conservative_start_batch(device.type, batch_size_cap)
            if args.batch_size > 0:
                batch_size_cap = max(1, min(batch_size_cap, args.batch_size))
                dynamic_batch_size = max(1, min(dynamic_batch_size, batch_size_cap))
                print(f"📊 Batch size cap overridden by --batch-size: {batch_size_cap}")
            if profile_batch_cap > 0:
                batch_size_cap = max(1, min(batch_size_cap, profile_batch_cap))
                dynamic_batch_size = max(1, min(dynamic_batch_size, batch_size_cap))
                print(f"📊 Batch size cap restored from profile: {batch_size_cap}")
            expected_layers = calculate_layers(float(capabilities.get("memory_gb", total_memory_gb)), device.type)
            precision = precision_mode.upper()
            device_label = "CPU" if device.type == "cpu" else device.type.upper()
            print("🖥️ Hardware detected:")
            print(f"   Device: {device_label} ({capabilities.get('device_name', 'unknown')})")
            print(f"   Memory: {total_memory_gb:.1f} GB")
            print(f"   Layers: {len(assigned_layers)} (auto-calculated)")
            print(
                f"   Batch size: {dynamic_batch_size} "
                f"(available: {available_gb:.1f}GB, per_sample: {per_sample_gb:.1f}GB)"
            )
            print(f"   Batch cap: {batch_size_cap} (gradual ramp enabled)")
            print(f"   Precision: {precision}")
            print(f"   Gradient scale (lr): {args.lr}")
            print(f"   Seq len: {runtime_seq_len}")
            if len(assigned_layers) != expected_layers:
                print(
                    f"⚠️ PS assigned {len(assigned_layers)} layers, "
                    f"local estimate is {expected_layers} layers"
                )

            print("🧪 Startup forward-pass check...")
            try:
                test_seq = max(8, min(runtime_seq_len, 32))
                test_ids = torch.randint(0, alice_config.vocab_size, (1, test_seq), dtype=torch.long, device=device)
                if device.type in ("cuda", "mps") and precision_mode == "fp16":
                    ctx = torch.autocast(device_type=device.type, dtype=torch.float16)
                else:
                    ctx = contextlib.nullcontext()
                with torch.no_grad():
                    with ctx:
                        model(test_ids, test_ids)
                print("✅ Startup forward-pass check passed")
            except (torch.cuda.OutOfMemoryError, RuntimeError) as exc:
                if "out of memory" in str(exc).lower():
                    if precision_mode == "fp32" and device.type in ("cuda", "mps"):
                        print("⚠️ Startup OOM in FP32, retrying with FP16")
                        save_device_profile(
                            profile_path,
                            profile_key,
                            {
                                "precision": "fp16",
                                "last_oom_ts": time.time(),
                                "last_update_reason": "startup_oom_switch_fp16",
                            },
                        )
                        os.execv(
                            sys.executable,
                            [sys.executable] + with_precision_arg(sys.argv, "fp16"),
                        )
                    print("❌ Startup OOM while keeping full assigned layer set; refusing to downshift layers.")
                    raise
                raise

            # DEBUG: Check for NaN/Inf in model weights
            print("🔍 Checking model weights for NaN/Inf...")
            for name, param in model.named_parameters():
                if torch.isnan(param).any():
                    print(f"   ❌ NAN PARAM: {name}")
                if torch.isinf(param).any():
                    print(f"   ❌ INF PARAM: {name}")
            print("   ✅ Weight check complete")

            # Initialize AMP scaler and compression settings
            scaler = (
                torch.cuda.amp.GradScaler(enabled=(precision_mode == "fp16"), init_scale=65536)
                if device.type == "cuda"
                else None
            )
            compression_ratio = 0.001
            stable_shards = 0
            grow_every = 3
            current_lr = args.lr
            min_lr = max(args.lr * 0.1, 1e-8)
            invalid_streak = 0

            # Task loop
            print("\n🚀 Starting training loop...\n")
            while True:
                if pending_task is not None:
                    task = pending_task
                    pending_task = None
                else:
                    task, status = request_task_with_retry(
                        args.ps_url,
                        wallet_address,
                        capabilities,
                        auth_token=auth_token,
                        retry_delay=15,
                        max_attempts=5,
                    )
                    if status == "no_task":
                        time.sleep(10)
                        continue
                    if status == "re_register" or task is None:
                        print("⚠️ Re-registering after repeated task request failures...")
                        break

                task_id = task["task_id"]
                shard_id = task["shard_id"]
                task_nonce = task.get("task_nonce")
                if not isinstance(task_nonce, str) or not task_nonce.strip():
                    print("❌ Task missing task_nonce, requesting next task...")
                    time.sleep(1)
                    continue

                # Download shard
                print(f"📥 Downloading shard {shard_id}...")
                shard_data = download_shard_streaming(
                    args.ps_url,
                    shard_id,
                    auth_token=auth_token,
                )
                if shard_data is None:
                    print("❌ Shard download failed, skipping task")
                    continue

                # Train
                print(f"🎯 Training shard {shard_id} (layers {len(assigned_layers)}/{n_layers})...")
                start_time = time.time()

                avg_loss, num_batches, dynamic_batch_size, invalid_loss_batches, oom_aborted, compressed, raw_bytes, grad_count, bad_param = train_shard(
                    model=model,
                    shard_data=shard_data,
                    device=device,
                    assigned_layers=assigned_layers,
                    batch_size=dynamic_batch_size,
                    seq_len=runtime_seq_len,
                    max_batches=args.max_batches,
                    scaler=scaler,
                    precision_mode=precision_mode,
                    compression_ratio=compression_ratio,
                    grad_scale=current_lr,
                )

                train_time = time.time() - start_time

                had_invalid_loss = invalid_loss_batches > 0
                if num_batches <= 0 or not math.isfinite(avg_loss) or had_invalid_loss:
                    if oom_aborted:
                        oom_abort_streak += 1
                        last_oom_ts = time.time()
                        save_device_profile(
                            profile_path,
                            profile_key,
                            {
                                "last_oom_ts": last_oom_ts,
                                "oom_abort_streak": oom_abort_streak,
                                "stable_layers": int(len(assigned_layers)),
                                "stable_seq_len": int(runtime_seq_len),
                                "stable_batch_cap": int(max(1, batch_size_cap)),
                                "last_update_reason": "runtime_oom_abort",
                            },
                        )
                    else:
                        oom_abort_streak = 0

                    if had_invalid_loss:
                        invalid_streak += 1
                        if current_lr > min_lr:
                            current_lr = max(min_lr, current_lr * 0.5)
                            print(f"   ⚠️ Invalid loss detected, reducing gradient scale to {current_lr:.2e}")
                        elif precision_mode == "fp16" and device.type in ("cuda", "mps"):
                            print("   ⚠️ Invalid loss persists at min gradient scale, switching to FP32")
                            os.execv(
                                sys.executable,
                                [sys.executable] + with_precision_arg(sys.argv, "fp32"),
                            )
                    stable_shards = 0
                    if dynamic_batch_size > 1:
                        dynamic_batch_size = max(1, dynamic_batch_size // 2)
                        print(f"   ⚠️ Stability fallback, reducing batch size to {dynamic_batch_size}")
                    elif oom_aborted:
                        seq_floor = 64 if device.type in ("cuda", "mps") else 32
                        if runtime_seq_len > seq_floor:
                            runtime_seq_len = max(seq_floor, runtime_seq_len // 2)
                            print(f"   ⚠️ OOM fallback, reducing seq_len to {runtime_seq_len}")
                            save_device_profile(
                                profile_path,
                                profile_key,
                                {
                                    "stable_seq_len": int(runtime_seq_len),
                                    "last_oom_ts": last_oom_ts,
                                    "last_update_reason": "runtime_oom_seq_downshift",
                                },
                            )
                        else:
                            print("   ⚠️ OOM persists at min batch/seq; keeping full layer count and skipping this shard.")
                    print("   ⚠️ No training batches completed, skipping submission.")
                    time.sleep(1)
                    continue

                stable_shards += 1
                oom_abort_streak = 0
                invalid_streak = 0
                if dynamic_batch_size < batch_size_cap and stable_shards >= grow_every:
                    dynamic_batch_size += 1
                    stable_shards = 0
                    print(f"   📈 Stable training, increasing batch size to {dynamic_batch_size}")

                shards_trained += 1
                tasks_processed += 1

                if bad_param is not None:
                    invalid_streak += 1
                    if current_lr > min_lr:
                        current_lr = max(min_lr, current_lr * 0.5)
                        print(f"   ⚠️ Gradient NaN/Inf detected, reducing gradient scale to {current_lr:.2e}")
                    elif precision_mode == "fp16" and device.type in ("cuda", "mps"):
                        print("   ⚠️ Gradient NaN/Inf persists at min gradient scale, switching to FP32")
                        os.execv(
                            sys.executable,
                            [sys.executable] + with_precision_arg(sys.argv, "fp32"),
                        )
                    stable_shards = 0
                    if dynamic_batch_size > 1:
                        dynamic_batch_size = max(1, dynamic_batch_size // 2)
                        print(f"   ⚠️ Gradient NaN/Inf fallback, reducing batch size to {dynamic_batch_size}")
                    print(f"   ⚠️ NaN/Inf detected in gradient: {bad_param}")
                    print("   ⏭️  Skipping submission, requesting next task...")
                    time.sleep(1)
                    continue

                compressed_bytes = 0
                for name, meta in compressed.items():
                    if name in ("dtype", "fmt"):
                        continue
                    # Approximate payload bytes without full json.dumps() cost.
                    compressed_bytes += len(meta.get("data", "")) + 96
                ratio_pct = (compressed_bytes / raw_bytes * 100.0) if raw_bytes else 0.0
                print(
                    f"📊 Compression: {raw_bytes / 1024 / 1024:.2f}MB -> "
                    f"{compressed_bytes / 1024 / 1024:.2f}MB ({ratio_pct:.2f}%)"
                )

                # Submit
                metrics = {
                    "training_time": train_time,
                    "shard_id": shard_id,
                    "num_gradients": grad_count,
                    "assigned_layers": assigned_layers,
                    "avg_loss": avg_loss,
                }

                print("📤 Submitting gradient...")
                success = submit_gradient(
                    args.ps_url,
                    task_id,
                    task_nonce,
                    compressed,
                    metrics,
                    auth_token=auth_token,
                )
                if success:
                    gradients_accepted += 1
                    save_device_profile(
                        profile_path,
                        profile_key,
                        {
                            "stable_layers": int(len(assigned_layers)),
                            "stable_seq_len": int(runtime_seq_len),
                            "stable_batch_cap": int(max(1, batch_size_cap)),
                            "precision": precision_mode,
                            "last_success_ts": time.time(),
                            "last_update_reason": "accepted_gradient",
                        },
                    )
                    # After sustained stability, cautiously probe one tier up.
                    if device.type in ("cuda", "mps") and not upgraded_this_run and gradients_accepted >= 10:
                        now = time.time()
                        if (now - last_oom_ts) >= 3600 and (now - last_upgrade_ts) >= 3600:
                            physical_mem_gb = get_physical_device_memory_gb(device.type, capabilities)
                            max_layers_by_hw = calculate_layers(physical_mem_gb, device.type)
                            next_layers = min(max_layers_by_hw, len(assigned_layers) + 4)
                            if next_layers > len(assigned_layers):
                                new_mem_cap = memory_required_for_layers(
                                    target_layers=next_layers,
                                    device_type=device.type,
                                    fallback_memory=float(physical_mem_gb),
                                )
                                last_upgrade_ts = now
                                upgraded_this_run = True
                                os.environ["ALICE_MEMORY_CAP_GB"] = f"{new_mem_cap:.3f}"
                                save_device_profile(
                                    profile_path,
                                    profile_key,
                                    {
                                        "memory_cap_gb": float(new_mem_cap),
                                        "stable_layers": int(next_layers),
                                        "stable_seq_len": int(runtime_seq_len),
                                        "stable_batch_cap": int(max(1, batch_size_cap)),
                                        "last_upgrade_ts": float(last_upgrade_ts),
                                        "last_update_reason": "stability_probe_upgrade",
                                    },
                                )
                                print(
                                    f"📈 Stability probe: requesting {next_layers} layers "
                                    f"(memory cap {new_mem_cap:.2f}GB), restarting miner..."
                                )
                                retry_caps = dict(capabilities)
                                retry_caps["memory_gb"] = float(new_mem_cap)
                                register_miner_with_retry(
                                    args.ps_url,
                                    wallet_address,
                                    wallet_keypair,
                                    retry_caps,
                                    retry_seconds=30,
                                )
                                os.execv(sys.executable, [sys.executable] + sys.argv)
                    print(f"✅ Task {task_id[:8]}... completed in {train_time:.1f}s\n")
                else:
                    gradients_rejected += 1
                    print(f"❌ Task {task_id[:8]}... failed\n")

                if tasks_processed % 10 == 0:
                    uptime = format_uptime(time.time() - miner_start_time)
                    print(
                        f"⏱️ Miner uptime: {uptime} | Shards trained: {shards_trained} | "
                        f"Gradients accepted: {gradients_accepted} | Rejected: {gradients_rejected}"
                    )

                # Small delay before next task
                time.sleep(2)

        except KeyboardInterrupt:
            print("\n🛑 Miner stopped by user")
            return
        except Exception as e:
            print(f"❌ Unexpected error: {e}. Restarting in 30s...")
            import traceback
            traceback.print_exc()
            time.sleep(30)
            continue


if __name__ == "__main__":
    main()
