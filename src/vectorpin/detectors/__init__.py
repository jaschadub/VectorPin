# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Statistical detectors as a defense-in-depth layer.

Cryptographic pinning catches modifications. Detectors catch tampering
at ingestion time, before pinning would even apply — and they catch
poisoning campaigns that don't modify already-pinned vectors but inject
new tampered ones.

Use both. Pinning is the primary control; detectors are the fallback.
"""

from vectorpin.detectors.base import BaseDetector

__all__ = ["BaseDetector"]
