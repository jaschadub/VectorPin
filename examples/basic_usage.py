#!/usr/bin/env python3
# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""End-to-end VectorPin demo.

Generates a key pair in-memory, pins a fake embedding, then walks
through the four interesting cases:

  1. honest verify -> OK
  2. tampered vector -> VECTOR_TAMPERED  (steganography kill shot)
  3. wrong source text -> SOURCE_MISMATCH
  4. forged signature with wrong key -> UNKNOWN_KEY
"""

from __future__ import annotations

import numpy as np

from vectorpin import Pin, Signer, Verifier


def main() -> None:
    rng = np.random.default_rng(42)
    embedding = rng.normal(0, 1, size=128).astype(np.float32)
    source = "The quick brown fox jumps over the lazy dog."

    signer = Signer.generate(key_id="demo-2026-05")
    pin = signer.pin(
        source=source,
        model="text-embedding-3-large",
        vector=embedding,
    )

    print("Pin JSON (this is what you'd store in your vector DB metadata):")
    print(pin.to_json())
    print()

    verifier = Verifier({signer.key_id: signer.public_key()})

    # 1. honest verify
    result = verifier.verify(pin, source=source, vector=embedding)
    print(f"1. honest verify              -> {result.error.value}")

    # 2. tampered vector — the steganographic case
    tampered = embedding.copy()
    tampered[0] += 1e-5  # imperceptible to a human, fatal to the hash
    result = verifier.verify(pin, source=source, vector=tampered)
    print(f"2. tampered vector            -> {result.error.value}")

    # 3. wrong source
    result = verifier.verify(pin, source="different text", vector=embedding)
    print(f"3. wrong source text          -> {result.error.value}")

    # 4. wrong signing key
    rogue = Signer.generate(key_id="demo-2026-05")  # same kid, different keypair
    rogue_pin = rogue.pin(source=source, model="m", vector=embedding)
    # Verifier registry only has the legit public key for that kid.
    result = verifier.verify(rogue_pin)
    print(f"4. forged with wrong key      -> {result.error.value}")

    # JSON round trip — confirms pins survive serialization
    restored = Pin.from_json(pin.to_json())
    assert restored == pin
    print()
    print("Pin round-trip via JSON: OK")


if __name__ == "__main__":
    main()
