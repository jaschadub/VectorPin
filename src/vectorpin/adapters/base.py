# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Adapter protocol shared by every vector store backend."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import numpy as np

from vectorpin.attestation import Pin

PIN_METADATA_KEY = "vectorpin"
"""Name of the metadata field that holds the serialized Pin JSON.

Backends that don't have free-form metadata MUST find another way to
attach this value. We do not support storing pins separately from the
vectors they cover — provenance must travel with the data.
"""


@dataclass(frozen=True)
class PinnedRecord:
    """A vector + its attached Pin + arbitrary other metadata."""

    id: str
    vector: np.ndarray
    pin: Pin | None
    metadata: dict[str, Any]


class BaseAdapter(ABC):
    """Read/write interface that adapters implement.

    Adapters must be lazy: an adapter that wraps Qdrant should not
    require Qdrant to be importable just to construct the class. Push
    backend imports into `__init__` of the concrete adapter, not into
    module top level.
    """

    @abstractmethod
    def iter_records(self, *, batch_size: int = 256) -> Iterator[PinnedRecord]:
        """Yield every record in the collection, with its pin if present."""

    @abstractmethod
    def get(self, record_id: str) -> PinnedRecord:
        """Fetch a single record by id."""

    @abstractmethod
    def attach_pin(self, record_id: str, pin: Pin) -> None:
        """Store a Pin in the metadata field of an existing record."""
