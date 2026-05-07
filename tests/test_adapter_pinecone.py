# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""PineconeAdapter tests.

Pinecone is cloud-only; the integration test is gated on
``PINECONE_API_KEY`` and ``VECTORPIN_PINECONE_INDEX`` env vars and
will write/read to a real index. Mark it ``integration`` so it is
opt-in via ``pytest -m integration``.

A small offline marshalling test runs unconditionally (when the
client library is installed) by exercising ``_record_from_fetch``
against a fake fetch payload — this catches breakage in the v3
client's response shape without requiring credentials.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import numpy as np
import pytest

pinecone = pytest.importorskip("pinecone")

from vectorpin import Pin, Signer, Verifier
from vectorpin.adapters import PIN_METADATA_KEY, PineconeAdapter

# ---- offline tests (no credentials needed) ----


@dataclass
class _FakeVector:
    values: list[float]
    metadata: dict[str, Any]


def test_record_from_fetch_v3_shape():
    """v3 client returns a Vector dataclass with .values and .metadata."""
    signer = Signer.generate(key_id="test-key")
    pin = signer.pin(source="hello", model="m", vector=np.array([1.0, 2.0, 3.0], dtype=np.float32))
    payload = _FakeVector(
        values=[1.0, 2.0, 3.0],
        metadata={"source": "hello", PIN_METADATA_KEY: pin.to_json()},
    )
    adapter = PineconeAdapter(index=None)  # type: ignore[arg-type]
    record = adapter._record_from_fetch("rid-1", payload)
    assert record.id == "rid-1"
    assert record.vector.shape == (3,)
    assert record.pin is not None
    assert record.pin.kid == "test-key"
    assert record.metadata == {"source": "hello"}


def test_record_from_fetch_dict_shape():
    """Older / serialized responses are dicts with the same keys."""
    signer = Signer.generate(key_id="test-key")
    pin = signer.pin(source="hello", model="m", vector=np.array([1.0, 2.0], dtype=np.float32))
    payload = {
        "values": [1.0, 2.0],
        "metadata": {PIN_METADATA_KEY: pin.to_json()},
    }
    adapter = PineconeAdapter(index=None)  # type: ignore[arg-type]
    record = adapter._record_from_fetch("rid-2", payload)
    assert record.id == "rid-2"
    assert record.pin is not None
    assert isinstance(record.pin, Pin)


# ---- live integration test (opt-in) ----


@pytest.mark.integration
def test_pinecone_live_roundtrip():
    api_key = os.environ.get("PINECONE_API_KEY")
    index_name = os.environ.get("VECTORPIN_PINECONE_INDEX")
    if not api_key or not index_name:
        pytest.skip("PINECONE_API_KEY and VECTORPIN_PINECONE_INDEX must be set")

    namespace = os.environ.get("VECTORPIN_PINECONE_NAMESPACE", "vectorpin-test")
    adapter = PineconeAdapter.connect(api_key, index_name, namespace=namespace)
    signer = Signer.generate(key_id="vectorpin-live-test")
    verifier = Verifier(public_keys={signer.key_id: signer.public_key_bytes()})

    rec = adapter.get(os.environ["VECTORPIN_PINECONE_TEST_ID"])
    pin = signer.pin(source="live-roundtrip", model="bench-model", vector=rec.vector)
    adapter.attach_pin(rec.id, pin)
    refreshed = adapter.get(rec.id)
    assert refreshed.pin is not None
    result = verifier.verify(refreshed.pin, source="live-roundtrip", vector=refreshed.vector)
    assert result, f"verify failed: {result.error}"
