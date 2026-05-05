# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Detector protocol — fit on clean, score on suspect."""

from __future__ import annotations

from abc import ABC, abstractmethod

import numpy as np


class BaseDetector(ABC):
    """Anomaly detector trained on a clean baseline."""

    @abstractmethod
    def fit(self, clean: np.ndarray) -> BaseDetector:
        """Train on a batch of known-clean embeddings."""

    @abstractmethod
    def score(self, embeddings: np.ndarray) -> np.ndarray:
        """Per-vector anomaly score; higher = more anomalous."""

    @abstractmethod
    def decide(self, embeddings: np.ndarray, threshold: float | None = None) -> np.ndarray:
        """Per-vector boolean decision (True = flagged as anomalous)."""
