#!/usr/bin/env python3
# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Per-operation microbenchmarks for the Python reference implementation.

Mirrors `rust/vectorpin/benches/perf.rs`:

  * hash_text     across text length ∈ {128, 1024, 8192}
  * hash_vector   across vector dim ∈ {384, 768, 1024, 3072}
  * sign (pin)    across vector dim, fixed 1024-char source
  * verify_full   across vector dim, fixed 1024-char source
  * verify_sig    signature-only verification at d=3072

Reports mean / p50 / p95 / p99 in microseconds plus throughput. We
intentionally avoid pytest-benchmark to keep the script standalone and
runnable without dev dependencies.

Usage:
    python scripts/bench_python.py [--iters N] [--warmup N] [--json out.json]
"""

from __future__ import annotations

import argparse
import gc
import json
import platform
import statistics
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from vectorpin import Signer, Verifier, hash_text, hash_vector

VECTOR_DIMS = [384, 768, 1024, 3072]
TEXT_LENS = [128, 1024, 8192]
TEXT_PATTERN = "The quick brown fox jumps over the lazy dog. "


def make_vector(d: int) -> np.ndarray:
    return (np.arange(d, dtype=np.float32) * 0.001).astype(np.float32)


def make_text(n: int) -> str:
    if n <= 0:
        return ""
    repeats = n // len(TEXT_PATTERN) + 1
    return (TEXT_PATTERN * repeats)[:n]


@dataclass
class Result:
    op: str
    param: str
    mean_us: float
    p50_us: float
    p95_us: float
    p99_us: float
    iters: int
    throughput_per_s: float


def _summarize(samples_ns: list[int], op: str, param: str) -> Result:
    samples_us = [s / 1000.0 for s in samples_ns]
    samples_us.sort()
    n = len(samples_us)
    mean = statistics.fmean(samples_us)
    p50 = samples_us[n // 2]
    p95 = samples_us[min(n - 1, int(n * 0.95))]
    p99 = samples_us[min(n - 1, int(n * 0.99))]
    return Result(
        op=op,
        param=param,
        mean_us=mean,
        p50_us=p50,
        p95_us=p95,
        p99_us=p99,
        iters=n,
        throughput_per_s=(1_000_000.0 / mean) if mean > 0 else float("inf"),
    )


def _time_callable(fn, iters: int, warmup: int) -> list[int]:
    """Run fn() iters+warmup times. Return per-call wall times in ns."""
    for _ in range(warmup):
        fn()
    samples: list[int] = []
    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        for _ in range(iters):
            t0 = time.perf_counter_ns()
            fn()
            samples.append(time.perf_counter_ns() - t0)
    finally:
        if gc_was_enabled:
            gc.enable()
    return samples


def bench_hash_text(iters: int, warmup: int) -> list[Result]:
    out = []
    for n in TEXT_LENS:
        text = make_text(n)
        samples = _time_callable(lambda t=text: hash_text(t), iters, warmup)
        out.append(_summarize(samples, "hash_text", f"len={n}"))
    return out


def bench_hash_vector(iters: int, warmup: int) -> list[Result]:
    out = []
    for d in VECTOR_DIMS:
        v = make_vector(d)
        samples = _time_callable(lambda vv=v: hash_vector(vv, "f32"), iters, warmup)
        out.append(_summarize(samples, "hash_vector", f"d={d}"))
    return out


def bench_sign(iters: int, warmup: int) -> list[Result]:
    signer = Signer.generate(key_id="bench")
    text = make_text(1024)
    out = []
    for d in VECTOR_DIMS:
        v = make_vector(d)
        samples = _time_callable(
            lambda vv=v, t=text: signer.pin(source=t, model="text-embedding-3-large", vector=vv),
            iters,
            warmup,
        )
        out.append(_summarize(samples, "sign", f"d={d}"))
    return out


def bench_verify(iters: int, warmup: int) -> list[Result]:
    signer = Signer.generate(key_id="bench")
    verifier = Verifier(public_keys={signer.key_id: signer.public_key_bytes()})
    text = make_text(1024)
    out = []
    for d in VECTOR_DIMS:
        v = make_vector(d)
        pin = signer.pin(source=text, model="text-embedding-3-large", vector=v)
        samples = _time_callable(
            lambda vv=v, t=text, p=pin: verifier.verify(p, source=t, vector=vv),
            iters,
            warmup,
        )
        out.append(_summarize(samples, "verify_full", f"d={d}"))
    return out


def bench_verify_signature_only(iters: int, warmup: int) -> list[Result]:
    signer = Signer.generate(key_id="bench")
    verifier = Verifier(public_keys={signer.key_id: signer.public_key_bytes()})
    text = make_text(1024)
    v = make_vector(3072)
    pin = signer.pin(source=text, model="text-embedding-3-large", vector=v)
    # Verifier.verify with no source/vector args is the signature-only path.
    samples = _time_callable(lambda p=pin: verifier.verify(p), iters, warmup)
    return [_summarize(samples, "verify_signature_only", "d=3072")]


def _print_table(results: list[Result]) -> None:
    cols = ("op", "param", "mean_us", "p50_us", "p95_us", "p99_us", "ops/sec")
    widths = [16, 12, 12, 12, 12, 12, 14]
    header = " ".join(c.ljust(w) for c, w in zip(cols, widths, strict=True))
    print(header)
    print("-" * len(header))
    for r in results:
        row = (
            r.op,
            r.param,
            f"{r.mean_us:.2f}",
            f"{r.p50_us:.2f}",
            f"{r.p95_us:.2f}",
            f"{r.p99_us:.2f}",
            f"{r.throughput_per_s:,.0f}",
        )
        print(" ".join(str(c).ljust(w) for c, w in zip(row, widths, strict=True)))


def _platform_info() -> dict[str, str]:
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "processor": platform.processor() or "unknown",
        "machine": platform.machine(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iters", type=int, default=5000, help="measured iterations per cell")
    parser.add_argument("--warmup", type=int, default=200, help="warmup iterations per cell")
    parser.add_argument("--json", type=Path, default=None, help="write JSON results to this path")
    args = parser.parse_args()

    print("# VectorPin Python microbenchmarks")
    info = _platform_info()
    for k, v in info.items():
        print(f"# {k}: {v}")
    print(f"# iters={args.iters} warmup={args.warmup}")
    print()

    results: list[Result] = []
    bench_fns = (
        bench_hash_text,
        bench_hash_vector,
        bench_sign,
        bench_verify,
        bench_verify_signature_only,
    )
    for fn in bench_fns:
        results.extend(fn(args.iters, args.warmup))

    _print_table(results)

    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "platform": info,
            "iters": args.iters,
            "warmup": args.warmup,
            "results": [asdict(r) for r in results],
        }
        args.json.write_text(json.dumps(payload, indent=2))
        print(f"\nWrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
