# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Attestation format and round-trip tests."""

import json

import pytest

from vectorpin.attestation import PROTOCOL_VERSION, Pin, PinHeader


def _header(**overrides) -> PinHeader:
    base = {
        "v": PROTOCOL_VERSION,
        "model": "text-embedding-3-large",
        "source_hash": "sha256:" + "0" * 64,
        "vec_hash": "sha256:" + "1" * 64,
        "vec_dtype": "f32",
        "vec_dim": 3072,
        "ts": "2026-05-05T12:00:00Z",
    }
    base.update(overrides)
    return PinHeader(**base)


def test_canonicalize_is_deterministic():
    h = _header()
    assert h.canonicalize() == h.canonicalize()


def test_canonicalize_is_key_order_independent():
    a = _header(extra={"a": "1", "b": "2"})
    b = _header(extra={"b": "2", "a": "1"})
    assert a.canonicalize() == b.canonicalize()


def test_canonicalize_omits_optional_fields_when_unset():
    raw = _header().canonicalize().decode()
    assert "model_hash" not in raw
    assert "extra" not in raw


def test_canonicalize_includes_optional_fields_when_set():
    h = _header(model_hash="sha256:" + "f" * 64, extra={"region": "us-west"})
    raw = h.canonicalize().decode()
    assert "model_hash" in raw
    assert "extra" in raw
    assert "us-west" in raw


def test_pin_to_json_round_trip():
    pin = Pin(header=_header(), kid="prod-2026-05", sig=b"\x01" * 64)
    restored = Pin.from_json(pin.to_json())
    assert restored == pin


def test_pin_from_dict_rejects_unsupported_version():
    bad = {
        "v": 99,
        "model": "x",
        "source_hash": "sha256:" + "0" * 64,
        "vec_hash": "sha256:" + "1" * 64,
        "vec_dtype": "f32",
        "vec_dim": 1,
        "ts": "2026-05-05T12:00:00Z",
        "kid": "k",
        "sig": "AA",
    }
    with pytest.raises(ValueError, match="version"):
        Pin.from_dict(bad)


def test_pin_json_is_compact():
    """Pin JSON must fit in vector DB metadata fields without fuss."""
    pin = Pin(header=_header(), kid="k", sig=b"\x01" * 64)
    j = pin.to_json()
    parsed = json.loads(j)
    assert "model" in parsed
    # No whitespace, sorted keys
    assert ": " not in j
    assert ", " not in j
