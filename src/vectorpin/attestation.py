# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin attestation format and canonicalization.

A Pin is the attestation that travels alongside an embedding in vector
store metadata. It commits to:

  - the source text (by hash)
  - the model that produced the embedding (identifier + optional hash)
  - the embedding itself (by hash)
  - the producer (by signing key id)
  - the time of pinning

The wire form is a compact JSON object. The signature is over a
canonical byte sequence built by `canonicalize()`, NOT over the JSON
encoding — this is so that downstream re-serialization (whitespace,
key order) cannot invalidate signatures.

Protocol version: PROTOCOL_VERSION (currently 1). Older readers MUST
reject unknown versions.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any

PROTOCOL_VERSION = 1


def _b64(data: bytes) -> str:
    """URL-safe base64, no padding — for compactness in wire form."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64dec(s: str) -> bytes:
    """Inverse of _b64; restores stripped padding."""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


@dataclass(frozen=True)
class PinHeader:
    """The signed portion of a Pin.

    Everything except `sig` and `kid` lives here. Two Pins are
    equivalent iff their headers canonicalize to identical bytes.
    """

    v: int
    model: str
    source_hash: str
    vec_hash: str
    vec_dtype: str
    vec_dim: int
    ts: str
    model_hash: str | None = None
    extra: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "v": self.v,
            "model": self.model,
            "source_hash": self.source_hash,
            "vec_hash": self.vec_hash,
            "vec_dtype": self.vec_dtype,
            "vec_dim": self.vec_dim,
            "ts": self.ts,
        }
        if self.model_hash is not None:
            out["model_hash"] = self.model_hash
        if self.extra:
            out["extra"] = dict(sorted(self.extra.items()))
        return out

    def canonicalize(self) -> bytes:
        """Stable byte representation for signing/verifying.

        Uses JSON with sorted keys, no whitespace. This is the form of
        canonicalization that has the best library support across
        languages while still being deterministic.
        """
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")


@dataclass(frozen=True)
class Pin:
    """An attestation binding an embedding to its source and producer."""

    header: PinHeader
    kid: str
    sig: bytes  # raw signature bytes (ed25519 = 64 bytes)

    def to_dict(self) -> dict[str, Any]:
        d = self.header.to_dict()
        d["kid"] = self.kid
        d["sig"] = _b64(self.sig)
        return d

    def to_json(self) -> str:
        """Compact JSON encoding suitable for vector DB metadata fields."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Pin:
        if d.get("v") != PROTOCOL_VERSION:
            raise ValueError(f"unsupported pin version {d.get('v')!r}; expected {PROTOCOL_VERSION}")
        header = PinHeader(
            v=d["v"],
            model=d["model"],
            source_hash=d["source_hash"],
            vec_hash=d["vec_hash"],
            vec_dtype=d["vec_dtype"],
            vec_dim=int(d["vec_dim"]),
            ts=d["ts"],
            model_hash=d.get("model_hash"),
            extra=dict(d.get("extra", {})),
        )
        return cls(header=header, kid=d["kid"], sig=_b64dec(d["sig"]))

    @classmethod
    def from_json(cls, s: str) -> Pin:
        return cls.from_dict(json.loads(s))
