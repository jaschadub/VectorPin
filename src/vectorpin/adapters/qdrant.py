# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Qdrant adapter.

Qdrant is the first adapter we ship because it has the cleanest
metadata story (`payload` is a free-form dict) and the most
security-conscious operator community of the OSS vector DBs.

Install with: pip install 'vectorpin[qdrant]'
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

import numpy as np

from vectorpin.adapters.base import PIN_METADATA_KEY, BaseAdapter, PinnedRecord
from vectorpin.attestation import Pin

if TYPE_CHECKING:
    from qdrant_client import QdrantClient


class QdrantAdapter(BaseAdapter):
    """Wraps a Qdrant collection for VectorPin reads and writes."""

    def __init__(self, client: QdrantClient, collection_name: str):
        self._client = client
        self._collection = collection_name

    @classmethod
    def connect(
        cls,
        url: str,
        collection_name: str,
        *,
        api_key: str | None = None,
    ) -> QdrantAdapter:
        """Construct an adapter against a remote Qdrant instance."""
        try:
            from qdrant_client import QdrantClient
        except ImportError as e:
            raise ImportError(
                "qdrant-client not installed. Run: pip install 'vectorpin[qdrant]'"
            ) from e
        client = QdrantClient(url=url, api_key=api_key)
        return cls(client, collection_name)

    def iter_records(self, *, batch_size: int = 256) -> Iterator[PinnedRecord]:
        offset: Any = None
        while True:
            points, offset = self._client.scroll(
                collection_name=self._collection,
                limit=batch_size,
                offset=offset,
                with_payload=True,
                with_vectors=True,
            )
            if not points:
                return
            for p in points:
                yield self._point_to_record(p)
            if offset is None:
                return

    def get(self, record_id: str) -> PinnedRecord:
        points = self._client.retrieve(
            collection_name=self._collection,
            ids=[record_id],
            with_payload=True,
            with_vectors=True,
        )
        if not points:
            raise KeyError(record_id)
        return self._point_to_record(points[0])

    def attach_pin(self, record_id: str, pin: Pin) -> None:
        self._client.set_payload(
            collection_name=self._collection,
            payload={PIN_METADATA_KEY: pin.to_dict()},
            points=[record_id],
        )

    @staticmethod
    def _point_to_record(point: Any) -> PinnedRecord:
        payload = dict(point.payload or {})
        pin_payload = payload.pop(PIN_METADATA_KEY, None)
        pin = Pin.from_dict(pin_payload) if pin_payload else None
        # Qdrant returns vectors as list[float] or None depending on config.
        vector = np.asarray(point.vector, dtype=np.float32) if point.vector is not None else None
        if vector is None:
            raise ValueError(
                f"point {point.id!r} has no vector data; "
                "ensure the collection was queried with with_vectors=True"
            )
        return PinnedRecord(
            id=str(point.id),
            vector=vector,
            pin=pin,
            metadata=payload,
        )
