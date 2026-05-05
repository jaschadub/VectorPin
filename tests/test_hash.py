# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Hash canonicalization tests."""

import numpy as np
import pytest

from vectorpin.hash import canonical_vector_bytes, hash_bytes, hash_text, hash_vector


def test_hash_text_is_stable():
    assert hash_text("hello") == hash_text("hello")


def test_hash_text_normalizes_nfc():
    # 'é' as single codepoint vs. 'e' + combining acute. NFC normalizes
    # them to the same form, so the hashes should match.
    composed = "café"
    decomposed = "café"
    assert hash_text(composed) == hash_text(decomposed)


def test_hash_text_distinguishes_content():
    assert hash_text("hello") != hash_text("Hello")


def test_canonical_vector_bytes_dtype_is_independent():
    # Same float values produced as f32 or f64-cast-to-f32 should hash equal.
    a = np.array([1.0, 2.0, 3.0], dtype=np.float32)
    b = np.array([1.0, 2.0, 3.0], dtype=np.float64)
    assert canonical_vector_bytes(a, "f32") == canonical_vector_bytes(b, "f32")


def test_canonical_vector_bytes_endianness_is_explicit():
    # Even on little-endian hosts, cast to '<f4' explicitly.
    a = np.array([1.0], dtype=np.float32)
    expected_bytes = a.astype("<f4").tobytes()
    assert canonical_vector_bytes(a, "f32") == expected_bytes


def test_canonical_vector_bytes_rejects_2d():
    a = np.zeros((2, 3), dtype=np.float32)
    with pytest.raises(ValueError, match="1-D"):
        canonical_vector_bytes(a)


def test_canonical_vector_bytes_rejects_unknown_dtype():
    a = np.zeros((3,), dtype=np.float32)
    with pytest.raises(ValueError, match="canonical dtype"):
        canonical_vector_bytes(a, "f16")  # type: ignore[arg-type]


def test_hash_vector_format():
    a = np.array([1.0, 2.0, 3.0], dtype=np.float32)
    h = hash_vector(a)
    assert h.startswith("sha256:")
    assert len(h) == len("sha256:") + 64


def test_hash_vector_changes_on_perturbation():
    a = np.array([1.0, 2.0, 3.0], dtype=np.float32)
    b = a.copy()
    b[0] += 1e-7  # tiny float change
    assert hash_vector(a) != hash_vector(b)


def test_hash_bytes_format():
    h = hash_bytes(b"hello")
    assert h.startswith("sha256:")
    assert len(h) == len("sha256:") + 64
