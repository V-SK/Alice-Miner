#!/usr/bin/env python3
"""Alice training-worker CANDIDATE GENERATOR (shipped by `alice-miner train`).

The `alice-miner train` role leases ONE coding task {prompt, entry_point} from the
Alice training coordinator, then must produce a CANDIDATE SOLUTION for it with the
miner's own GPU/model and submit it. The real RLVR HARNESS (`run_m0.py`) is a
training-LOOP EXPERIMENT over a task SET (base-eval -> GRPO-train -> post-eval ->
GO/NO-GO gate); it has no "solve THIS one task -> emit the solution" mode. So this
thin driver does the honest closest thing: it REUSES run_m0's OWN model loader
(`_load_base`) + prompt renderer (`_render`) and code_exec's `extract_code` to load the
SAME base model at the SAME precision and generate a candidate for the leased prompt,
printing the extracted code between explicit sentinels on stdout.

This driver lives in the miner (not the trainer repo) so the miner ships a single,
auditable generation path; it imports run_m0 + code_exec from the trainer dir (put on
sys.path by the caller / via --trainer-dir), so it can NEVER drift from the harness's
loader precision. CREDIT-ONLY, offline-except-model-download: it reads a task, emits a
candidate, exits. No network, no reward, no coordinator calls (the Rust side owns those).

I/O CONTRACT (stable — the Rust supervisor parses it):
  stdin  : the task JSON  {"prompt": "...", "entry_point": "...", "task_id": "..."}
  stdout : a line "ALICE_TRAIN_CANDIDATE_BEGIN", then the candidate code, then a line
           "ALICE_TRAIN_CANDIDATE_END". Diagnostics go to stderr.
  exit   : 0 on a non-empty candidate; non-zero (with a stderr reason) otherwise.
"""
from __future__ import annotations

import argparse
import json
import sys

BEGIN = "ALICE_TRAIN_CANDIDATE_BEGIN"
END = "ALICE_TRAIN_CANDIDATE_END"


def _log(msg: str) -> None:
    print(f"[alice-train-gen] {msg}", file=sys.stderr, flush=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-model", required=True)
    ap.add_argument("--device", default="cuda")
    ap.add_argument("--max-new", type=int, default=1024)
    ap.add_argument("--temperature", type=float, default=0.2,
                    help="low temp for a deterministic-ish single candidate")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--load-in-4bit", action="store_true")
    ap.add_argument(
        "--multi-gpu",
        choices=["shard"],
        default=None,
        help="spread ONE base across all local GPUs (device_map='auto', naive "
        "pipeline split) so a big MoE that won't fit on one card can still "
        "generate. Matches the harness's base-eval 'shard' layout exactly.",
    )
    args = ap.parse_args()

    # The task arrives on stdin as JSON (never argv — a prompt can be large).
    raw = sys.stdin.read()
    try:
        task = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as e:
        _log(f"could not parse task JSON on stdin: {e}")
        return 2
    prompt = str(task.get("prompt") or "").strip()
    if not prompt:
        _log("task carried no prompt")
        return 2

    # Import the harness's OWN loader + renderer, and code_exec's extractor, from the
    # trainer dir (the caller put it on sys.path). Failing to import is an HONEST error
    # (never a fabricated candidate) — the doctor + Rust side surface it clearly.
    try:
        from run_m0 import _load_base, _render  # type: ignore
        from code_exec import extract_code  # type: ignore
    except Exception as e:  # noqa: BLE001 - report any import failure honestly
        _log(f"could not import run_m0/_code_exec from the trainer dir: {e}")
        return 3

    try:
        import torch  # noqa: F401
        from transformers import AutoTokenizer
    except Exception as e:  # noqa: BLE001
        _log(f"could not import torch/transformers: {e}")
        return 3

    _log(f"loading base model {args.base_model!r} on {args.device} "
         f"(4bit={args.load_in_4bit}, multi_gpu={args.multi_gpu}) ...")
    try:
        tok = AutoTokenizer.from_pretrained(args.base_model)
        if tok.pad_token is None:
            tok.pad_token = tok.eos_token
        tok.padding_side = "left"
        # multi_gpu="shard" -> _load_base resolves device_map="auto" (naive
        # pipeline split across every local GPU), the SAME layout the harness
        # uses for base-eval; generation inputs go to model.device exactly as
        # base-eval does, so the candidate distribution still matches the scorer.
        model = _load_base(args.base_model, device=args.device,
                           four_bit=args.load_in_4bit, for_training=False,
                           multi_gpu=args.multi_gpu)
    except Exception as e:  # noqa: BLE001
        _log(f"model load failed: {e}")
        return 4

    # Render exactly as the harness renders a train/eval prompt (chat template + the M0
    # INSTR wrapper), so the candidate distribution matches what the verifier scored.
    rendered = _render(tok, prompt)

    import torch
    try:
        model.eval()
        if hasattr(model, "config"):
            model.config.use_cache = True
        if args.seed:
            torch.manual_seed(args.seed)
            if torch.cuda.is_available():
                torch.cuda.manual_seed_all(args.seed)
        inputs = tok(rendered, return_tensors="pt", truncation=True,
                     max_length=4096).to(model.device)
        with torch.no_grad():
            out = model.generate(
                **inputs, max_new_tokens=args.max_new,
                do_sample=args.temperature > 0,
                temperature=max(args.temperature, 1e-5), top_p=0.95,
                pad_token_id=tok.pad_token_id or tok.eos_token_id,
            )
        text = tok.decode(out[0][inputs["input_ids"].shape[1]:],
                          skip_special_tokens=True)
    except Exception as e:  # noqa: BLE001
        _log(f"generation failed: {e}")
        return 5

    candidate = extract_code(text).strip()
    if not candidate:
        _log("model produced no extractable code block")
        return 6

    # Emit the candidate between the stable sentinels for the Rust supervisor to parse.
    sys.stdout.write(BEGIN + "\n")
    sys.stdout.write(candidate)
    if not candidate.endswith("\n"):
        sys.stdout.write("\n")
    sys.stdout.write(END + "\n")
    sys.stdout.flush()
    _log(f"emitted a {len(candidate)}-byte candidate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
