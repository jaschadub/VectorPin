# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Chroma adapter.

Chroma's `metadatas` field accepts an arbitrary dict per record, which
is the cleanest possible home for a Pin. Both the in-process /
persistent client and the HTTP client expose the same `Collection`
interface, so this adapter works against either.

Chroma constrains metadata values to scalars (str, int, float, bool),
not nested dicts. We therefore serialize the Pin to JSON and store it
under a single string key — the key is shared across all backends so
operators can swap stores without rewriting metadata.

Install with: pip install 'vectorpin[chroma]'
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

import numpy as np

from vectorpin.adapters.base import PIN_METADATA_KEY, BaseAdapter, PinnedRecord
from vectorpin.attestation import Pin

if TYPE_CHECKING:
    from chromadb.api.models.Collection import Collection


class ChromaAdapter(BaseAdapter):
    """Wraps a Chroma collection for VectorPin reads and writes."""

    def __init__(self, collection: Collection):
        self._collection = collection

    @classmethod
    def connect_persistent(cls, path: str, collection_name: str) -> ChromaAdapter:
        """Open a Chroma collection backed by a local on-disk store."""
        try:
            import chromadb
        except ImportError as e:
            raise ImportError(
                "chromadb not installed. Run: pip install 'vectorpin[chroma]'"
            ) from e
        client = chromadb.PersistentClient(path=path)
        collection = client.get_collection(name=collection_name)
        return cls(collection)

    @classmethod
    def connect_http(
        cls,
        host: str,
        port: int,
        collection_name: str,
        *,
        ssl: bool = False,
        headers: dict[str, str] | None = None,
    ) -> ChromaAdapter:
        """Open a Chroma collection over the HTTP API."""
        try:
            import chromadb
        except ImportError as e:
            raise ImportError(
                "chromadb not installed. Run: pip install 'vectorpin[chroma]'"
            ) from e
        client = chromadb.HttpClient(host=host, port=port, ssl=ssl, headers=headers or {})
        collection = client.get_collection(name=collection_name)
        return cls(collection)

    def iter_records(self, *, batch_size: int = 256) -> Iterator[PinnedRecord]:
        # Chroma's `get()` returns the whole collection; we batch on
        # the Python side with offset/limit to bound memory. Note that
        # the modern client returns `embeddings` as a numpy ndarray, so
        # we cannot use truthy `or []` — use explicit None checks.
        offset = 0
        while True:
            page = self._collection.get(
                limit=batch_size,
                offset=offset,
                include=["embeddings", "metadatas"],
            )
            ids = list(page.get("ids") or [])
            if not ids:
                return
            embeddings = page.get("embeddings")
            if embeddings is None:
                embeddings = []
            metadatas = page.get("metadatas")
            if metadatas is None:
                metadatas = [None] * len(ids)
            for i, rid in enumerate(ids):
                yield self._build_record(rid, embeddings[i], metadatas[i])
            if len(ids) < batch_size:
                return
            offset += len(ids)

    def get(self, record_id: str) -> PinnedRecord:
        page = self._collection.get(
            ids=[record_id],
            include=["embeddings", "metadatas"],
        )
        ids = list(page.get("ids") or [])
        if not ids:
            raise KeyError(record_id)
        embeddings = page.get("embeddings")
        if embeddings is None:
            raise ValueError(f"chroma returned no embeddings for {record_id!r}")
        metadatas = page.get("metadatas")
        metadata = metadatas[0] if metadatas is not None else None
        return self._build_record(ids[0], embeddings[0], metadata)

    def attach_pin(self, record_id: str, pin: Pin) -> None:
        # Read-modify-write: Chroma's update replaces the metadata
        # dict, so we have to merge to preserve any other keys the
        # operator stored alongside the vector.
        existing = self._collection.get(ids=[record_id], include=["metadatas"])
        if not existing.get("ids"):
            raise KeyError(record_id)
        prior = (existing.get("metadatas") or [None])[0] or {}
        merged = dict(prior)
        merged[PIN_METADATA_KEY] = pin.to_json()
        self._collection.update(ids=[record_id], metadatas=[merged])

    # ---- internals ----

    def _build_record(self, rid: Any, embedding: Any, metadata: Any) -> PinnedRecord:
        if embedding is None:
            raise ValueError(
                f"record {rid!r} has no embedding; "
                "ensure include=['embeddings'] was passed and the collection has vectors"
            )
        vector = np.asarray(embedding, dtype=np.float32)
        if vector.ndim != 1:
            raise ValueError(f"embedding for {rid!r} returned non-1D shape {vector.shape}")
        meta = dict(metadata or {})
        pin_payload = meta.pop(PIN_METADATA_KEY, None)
        pin = Pin.from_json(pin_payload) if pin_payload else None
        return PinnedRecord(id=str(rid), vector=vector, pin=pin, metadata=meta)
