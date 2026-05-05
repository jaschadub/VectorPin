#!/usr/bin/env python3
# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Generate cross-language test vectors.

Every language port (Rust, JS, Go) consumes the JSON fixtures this
script writes and asserts that:

  - Recomputing canonical bytes / hashes matches.
  - Signature verification succeeds against the published public key.
  - Negative cases (tampered vector, wrong source) fail with the
    correct error code.

The fixtures use a deterministic signing key seed so output is
reproducible. The seed and key id are NOT secrets — they exist solely
to make the fixtures verifiable across implementations.

Run from the repo root:

    python scripts/generate_test_vectors.py

Outputs land in testvectors/.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import numpy as np

from vectorpin import Pin, Signer

OUT_DIR = Path(__file__).resolve().parent.parent / "testvectors"

# Deterministic key material — fixture purposes only.
DETERMINISTIC_SEED = bytes(range(32))  # 0x00..0x1f
KEY_ID = "test-vectors-2026-05"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_vector(seed: int, dim: int = 16, dtype: str = "f32") -> np.ndarray:
    rng = np.random.default_rng(seed)
    arr = rng.normal(0, 1, size=dim)
    return arr.astype(np.float32 if dtype == "f32" else np.float64)


def main() -> None:
    OUT_DIR.mkdir(exist_ok=True)
    signer = Signer.from_private_bytes(DETERMINISTIC_SEED, key_id=KEY_ID)

    fixtures = []
    for i, (text, model, dim, dtype) in enumerate(
        [
            ("hello world", "test-model-v1", 16, "f32"),
            ("The quick brown fox jumps over the lazy dog.", "text-embedding-3-large", 32, "f32"),
            ("café", "unicode-test-v1", 8, "f32"),  # NFC normalization fixture
            ("multi\nline\ntext", "test-model-v1", 4, "f64"),
        ]
    ):
        vec = make_vector(seed=i, dim=dim, dtype=dtype)
        # Use a fixed timestamp so the pin (and therefore the signature) is
        # bit-for-bit reproducible across runs.
        from datetime import datetime, timezone
        ts = datetime(2026, 5, 5, 12, 0, 0, tzinfo=timezone.utc)
        pin = signer.pin(
            source=text,
            model=model,
            vector=vec,
            vec_dtype=dtype,
            timestamp=ts,
        )
        fixtures.append(
            {
                "name": f"vector_{i}",
                "input": {
                    "source": text,
                    "model": model,
                    "vector_b64": b64url(vec.astype(f"<{'f4' if dtype == 'f32' else 'f8'}").tobytes()),
                    "vec_dtype": dtype,
                    "vec_dim": dim,
                    "timestamp": "2026-05-05T12:00:00Z",
                },
                "expected": {
                    "pin_json": pin.to_json(),
                    "canonical_header_b64": b64url(pin.header.canonicalize()),
                    "vec_hash": pin.header.vec_hash,
                    "source_hash": pin.header.source_hash,
                },
            }
        )

    public_key = b64url(signer.public_key_bytes())
    private_seed = b64url(DETERMINISTIC_SEED)

    out = {
        "version": 1,
        "comment": (
            "Cross-language test vectors for VectorPin protocol v1. "
            "The signing key seed is intentionally public — it exists "
            "only to make these fixtures reproducible. Do not use in "
            "production."
        ),
        "key_id": KEY_ID,
        "public_key_b64": public_key,
        "private_seed_b64": private_seed,
        "fixtures": fixtures,
    }

    fixtures_path = OUT_DIR / "v1.json"
    fixtures_path.write_text(json.dumps(out, indent=2) + "\n")

    # Also dump a NEGATIVE-case fixture: same pin, but the vector has been
    # tampered with. Implementations should detect VECTOR_TAMPERED.
    legit = fixtures[0]
    tampered_vec = make_vector(seed=0, dim=16, dtype="f32")
    tampered_vec[0] += 1e-3  # any change at all
    negative = {
        "name": "tampered_vector",
        "pin_json": legit["expected"]["pin_json"],
        "tampered_vector_b64": b64url(tampered_vec.astype("<f4").tobytes()),
        "expected_error": "vector_tampered",
    }
    (OUT_DIR / "negative_v1.json").write_text(json.dumps(negative, indent=2) + "\n")

    # README so anyone landing in testvectors/ knows what they're for.
    readme = f"""# VectorPin Cross-Language Test Vectors

These JSON fixtures lock down the wire format and signature behavior
of the VectorPin protocol. Every language implementation
(Python, Rust, JS, Go) consumes them in CI.

## Files

- `v1.json` — positive fixtures. Each has an input (source, model,
  vector bytes, dtype, dim, timestamp) and the expected pin JSON,
  canonical header bytes, and component hashes.
- `negative_v1.json` — negative fixture. A pin from `v1.json[0]`
  paired with a vector that was modified after pinning. Verifiers
  must reject with the `vector_tampered` error.

## Reproducing

The signing key is deterministic (seed `{b64url(DETERMINISTIC_SEED)}`,
key id `{KEY_ID}`). Re-running `scripts/generate_test_vectors.py`
must produce byte-for-byte identical output. If your port disagrees,
the canonicalization or signing algorithm is off.

The seed is published intentionally — these fixtures are public test
data, not production keys.
"""
    (OUT_DIR / "README.md").write_text(readme)
    print(f"wrote {fixtures_path}")
    print(f"wrote {OUT_DIR / 'negative_v1.json'}")
    print(f"wrote {OUT_DIR / 'README.md'}")


if __name__ == "__main__":
    main()
