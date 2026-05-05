# VectorPin Cross-Language Test Vectors

These JSON fixtures lock down the wire format and signature behavior
of the VectorPin protocol. Every language implementation
(Python, Rust, JS, Go) consumes them in CI.

## Files

- `v1.json` — positive fixtures. Each has an input (source, model,
  vector bytes, dtype, dim, timestamp) and the expected pin JSON,
  canonical header bytes, and component hashes.
- `negative_v1.json` — negative fixture. A pin from `v1.json[0]`
  paired with a vector that was modified after pinning. Verifiers
  must reject with the `vector_tampered` error.

## Reproducing

The signing key is deterministic (seed `AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8`,
key id `test-vectors-2026-05`). Re-running `scripts/generate_test_vectors.py`
must produce byte-for-byte identical output. If your port disagrees,
the canonicalization or signing algorithm is off.

The seed is published intentionally — these fixtures are public test
data, not production keys.
