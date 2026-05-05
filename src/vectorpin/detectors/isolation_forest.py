# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Isolation Forest detector — sklearn-backed.

Why this is the default: in the VectorSmuggle empirical study, an
Isolation Forest trained on a small batch of clean embeddings detected
every operating point of every steganographic technique that hides a
non-trivial amount of data, with TPR@1%FPR comfortably above 0.5 for
the noise-based techniques.

Install with: pip install 'vectorpin[detectors]'
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import numpy as np

from vectorpin.detectors.base import BaseDetector

if TYPE_CHECKING:
    from sklearn.ensemble import IsolationForest as SkIsolationForest


class IsolationForestDetector(BaseDetector):
    """Tree-based density-agnostic anomaly detector."""

    def __init__(
        self,
        n_estimators: int = 200,
        contamination: float = 0.05,
        random_state: int = 42,
    ):
        try:
            from sklearn.ensemble import IsolationForest
        except ImportError as e:
            raise ImportError(
                "scikit-learn not installed. Run: pip install 'vectorpin[detectors]'"
            ) from e
        self._model: SkIsolationForest = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )
        self._fitted = False

    def fit(self, clean: np.ndarray) -> IsolationForestDetector:
        self._model.fit(clean)
        self._fitted = True
        return self

    def score(self, embeddings: np.ndarray) -> np.ndarray:
        if not self._fitted:
            raise RuntimeError("detector must be fit() before scoring")
        # sklearn's score_samples is "lower = more abnormal"; flip so the
        # rest of the codebase can treat higher as more anomalous.
        return -self._model.score_samples(embeddings)

    def decide(self, embeddings: np.ndarray, threshold: float | None = None) -> np.ndarray:
        scores = self.score(embeddings)
        if threshold is None:
            return self._model.predict(embeddings) == -1
        return scores > threshold
