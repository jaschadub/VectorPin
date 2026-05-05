# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Vector database adapters.

Each adapter knows how to read pins from a specific store's metadata
field and feed them through the Verifier. Adapters are intentionally
thin — they do not own verification policy, only marshalling.
"""

from vectorpin.adapters.base import BaseAdapter, PinnedRecord

__all__ = ["BaseAdapter", "PinnedRecord"]
