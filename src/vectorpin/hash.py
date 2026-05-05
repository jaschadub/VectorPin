# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Canonical hashing for embeddings, source content, and metadata.

The protocol is built on three reproducible operations:

  1. canonical_vector_bytes(vector, dtype) -> bytes
     Produces a byte sequence that two implementations will agree on for
     the same float32/float64 array.

  2. hash_vector(vector, dtype) -> "sha256:<hex>"
     SHA-256 over the canonical bytes.

  3. hash_text(text) -> "sha256:<hex>"
     SHA-256 over UTF-8 NFC-normalized text bytes.

These are the only places where bytes get mixed with semantics. Every
attestation field is one of: an explicit string, a hash, a timestamp, or
a signature. No implicit serialization.
"""

from __future__ import annotations

import hashlib
import unicodedata

import numpy as np

# ---- vector hashing ----

CanonicalDtype = str  # "f32" | "f64"


def _np_dtype(dtype: CanonicalDtype) -> np.dtype:
    if dtype == "f32":
        return np.dtype("<f4")  # little-endian float32
    if dtype == "f64":
        return np.dtype("<f8")  # little-endian float64
    raise ValueError(f"unsupported canonical dtype: {dtype!r}")


def canonical_vector_bytes(vector: np.ndarray, dtype: CanonicalDtype = "f32") -> bytes:
    """Return reproducible bytes for an embedding vector.

    Always little-endian, always 1-D. The dtype is fixed by the caller so
    two implementations reach the same byte sequence regardless of how the
    array was constructed.
    """
    if vector.ndim != 1:
        raise ValueError(f"expected 1-D vector, got shape {vector.shape}")
    target = _np_dtype(dtype)
    arr = np.ascontiguousarray(vector.astype(target, copy=False))
    return arr.tobytes()


def hash_vector(vector: np.ndarray, dtype: CanonicalDtype = "f32") -> str:
    """Return the canonical hash of an embedding vector as 'sha256:<hex>'."""
    digest = hashlib.sha256(canonical_vector_bytes(vector, dtype)).hexdigest()
    return f"sha256:{digest}"


# ---- text hashing ----


def hash_text(text: str) -> str:
    """Return the canonical hash of a source text chunk as 'sha256:<hex>'.

    Text is normalized to Unicode NFC then encoded as UTF-8 before hashing.
    NFC chosen because it is the form the W3C and most embedding model
    tokenizers expect; this prevents trivial false-mismatches from upstream
    normalization differences.
    """
    nfc = unicodedata.normalize("NFC", text)
    digest = hashlib.sha256(nfc.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def hash_bytes(data: bytes) -> str:
    """SHA-256 over raw bytes, returned as 'sha256:<hex>'."""
    return f"sha256:{hashlib.sha256(data).hexdigest()}"
