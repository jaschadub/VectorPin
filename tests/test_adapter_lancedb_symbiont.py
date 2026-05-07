# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""LanceDBAdapter against the Symbiont default LanceDB schema.

Symbiont's runtime ships LanceDB as the default embedded vector
backend. The schema, defined at
``crates/runtime/src/context/vector_db_lance.rs::build_schema``, uses
these column names and types:

    id            Utf8 non-null     -- chunk identifier
    content       Utf8 non-null     -- the source text
    agent_id      Utf8 nullable     -- agent owner
    vector        FixedSizeList<f32, dim>
    metadata_json Utf8 nullable     -- free-form JSON blob
    source        Utf8 nullable     -- upstream provenance (URL, file path)
    content_type  Utf8 nullable
    created_at    Int64 nullable

Two naming conventions to know when wiring this up:

* The `id` and `vector` columns match LanceDBAdapter's defaults, so no
  override is needed.
* What VectorPin's ``Signer.pin(source=...)`` argument calls "source"
  is Symbiont's ``content`` column. Symbiont reserves the column
  literally named ``source`` for upstream provenance (URL/filename),
  which is unrelated to the VectorPin attestation.

Symbiont does not provision a `vectorpin` column natively; this test
demonstrates the recommended pattern of including it at table-creation
time as a nullable Utf8 column.
"""

from __future__ import annotations

import time

import numpy as np
import pytest

lancedb = pytest.importorskip("lancedb")
pa = pytest.importorskip("pyarrow")

from vectorpin import Signer, Verifier
from vectorpin.adapters import PIN_METADATA_KEY, LanceDBAdapter

# Symbiont default: 384-dim vectors. Tests use 16 dims to keep the
# fixtures small; the schema layout is what matters here, not size.
SYMBIONT_VECTOR_DIM = 16


def _symbiont_schema(dim: int) -> pa.Schema:
    """Symbiont's default LanceDB schema, with `vectorpin` added.

    The trailing column is the one piece Symbiont does not ship by
    default. Operators wiring VectorPin into a Symbiont deployment
    add it at table-creation time (or via Lance's add_columns API on
    an existing table).
    """
    return pa.schema(
        [
            ("id", pa.string()),
            ("content", pa.string()),
            ("agent_id", pa.string()),
            ("vector", pa.list_(pa.float32(), dim)),
            ("metadata_json", pa.string()),
            ("source", pa.string()),
            ("content_type", pa.string()),
            ("created_at", pa.int64()),
            (PIN_METADATA_KEY, pa.string()),
        ]
    )


@pytest.fixture
def symbiont_table(tmp_path):
    db = lancedb.connect(str(tmp_path / "symbiont_context"))
    now = int(time.time())
    rows = [
        {
            "id": "chunk-001",
            "content": "The quick brown fox jumps over the lazy dog.",
            "agent_id": "agent-alpha",
            "vector": [0.1] * SYMBIONT_VECTOR_DIM,
            "metadata_json": '{"chapter": 1}',
            "source": "file:///docs/example.md",
            "content_type": "text/markdown",
            "created_at": now,
            PIN_METADATA_KEY: None,
        },
        {
            "id": "chunk-002",
            "content": "Pack my box with five dozen liquor jugs.",
            "agent_id": "agent-alpha",
            "vector": [0.2] * SYMBIONT_VECTOR_DIM,
            "metadata_json": '{"chapter": 2}',
            "source": "file:///docs/example.md",
            "content_type": "text/markdown",
            "created_at": now,
            PIN_METADATA_KEY: None,
        },
    ]
    return db.create_table(
        "symbiont_context",
        data=rows,
        schema=_symbiont_schema(SYMBIONT_VECTOR_DIM),
    )


def test_iter_yields_symbiont_records_unpinned(symbiont_table):
    """Defaults work: id and vector columns match Symbiont's schema."""
    adapter = LanceDBAdapter(symbiont_table)
    records = list(adapter.iter_records())
    assert {r.id for r in records} == {"chunk-001", "chunk-002"}
    assert all(r.pin is None for r in records)
    for r in records:
        assert r.vector.shape == (SYMBIONT_VECTOR_DIM,)
        assert r.metadata["content_type"] == "text/markdown"
        # Symbiont's `content` column carries the source text we'll pin to.
        assert r.metadata["content"].startswith(("The quick", "Pack my"))


def test_full_roundtrip_against_symbiont_schema(symbiont_table):
    """End-to-end: pin → attach → re-read → verify, using Symbiont columns.

    The mapping that matters is: the source text is in
    ``record.metadata["content"]``, not ``record.metadata["source"]``.
    """
    adapter = LanceDBAdapter(symbiont_table)
    signer = Signer.generate(key_id="symbiont-test-key")
    verifier = Verifier(public_keys={signer.key_id: signer.public_key_bytes()})

    for record in adapter.iter_records():
        pin = signer.pin(
            source=record.metadata["content"],
            model="bench-model",
            vector=record.vector,
            extra={"agent_id": record.metadata["agent_id"]},
        )
        adapter.attach_pin(record.id, pin)

    for record in adapter.iter_records():
        assert record.pin is not None
        result = verifier.verify(
            record.pin,
            source=record.metadata["content"],
            vector=record.vector,
        )
        assert result, f"verify failed for {record.id}: {result.error}"
        # Symbiont's free-form metadata survives the pin attachment.
        assert record.metadata["agent_id"] == "agent-alpha"
        assert record.metadata["source"] == "file:///docs/example.md"


def test_tampering_symbiont_content_is_caught(symbiont_table):
    """If an attacker mutates ``content`` after pinning, source-mismatch fires."""
    adapter = LanceDBAdapter(symbiont_table)
    signer = Signer.generate(key_id="symbiont-test-key")
    verifier = Verifier(public_keys={signer.key_id: signer.public_key_bytes()})

    rec = adapter.get("chunk-001")
    pin = signer.pin(
        source=rec.metadata["content"],
        model="bench-model",
        vector=rec.vector,
    )
    adapter.attach_pin("chunk-001", pin)

    refreshed = adapter.get("chunk-001")
    tampered_content = refreshed.metadata["content"] + " (tampered)"
    result = verifier.verify(refreshed.pin, source=tampered_content, vector=refreshed.vector)
    assert not result
    assert result.error.value == "source_mismatch"


def test_tampering_symbiont_vector_is_caught(symbiont_table):
    """If an attacker mutates ``vector`` after pinning, vector-tampered fires."""
    adapter = LanceDBAdapter(symbiont_table)
    signer = Signer.generate(key_id="symbiont-test-key")
    verifier = Verifier(public_keys={signer.key_id: signer.public_key_bytes()})

    rec = adapter.get("chunk-002")
    pin = signer.pin(
        source=rec.metadata["content"],
        model="bench-model",
        vector=rec.vector,
    )
    adapter.attach_pin("chunk-002", pin)

    refreshed = adapter.get("chunk-002")
    tampered_vector = refreshed.vector.copy()
    tampered_vector[0] = float(np.float32(tampered_vector[0]) + np.float32(1e-3))
    result = verifier.verify(
        refreshed.pin, source=refreshed.metadata["content"], vector=tampered_vector
    )
    assert not result
    assert result.error.value == "vector_tampered"
