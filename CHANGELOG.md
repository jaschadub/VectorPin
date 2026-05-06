# Changelog

All notable changes to VectorPin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-05-06

Initial public release. Protocol version: 1.

### Added

#### Core protocol
- `Pin` and `PinHeader` attestation format with sorted-key, no-whitespace
  canonical JSON encoding for deterministic signing.
- SHA-256 over UTF-8 NFC-normalized source text.
- SHA-256 over canonical little-endian f32/f64 vector bytes.
- Ed25519 signing and verification.
- URL-safe base64 (no padding) wire encoding for signatures.
- Wire-format specification at [`docs/spec.md`](docs/spec.md), self-contained
  for cross-language reimplementation.

#### Python implementation (`src/vectorpin/`)
- `Signer.generate(key_id)` and `Signer.from_private_bytes(raw, key_id)`.
- `Signer.pin(source, model, vector)` returning a signed `Pin`.
- `Verifier(public_keys)` with structured `VerificationResult` outcomes:
  `OK`, `UNSUPPORTED_VERSION`, `UNKNOWN_KEY`, `SIGNATURE_INVALID`,
  `VECTOR_TAMPERED`, `SOURCE_MISMATCH`, `MODEL_MISMATCH`, `SHAPE_MISMATCH`.
- Multi-key registry for rotation support.
- `Pin.to_json()` / `Pin.from_json()` round-trip.

#### Rust implementation (`rust/vectorpin/`)
- Byte-for-byte compatible with the Python reference.
- Same canonical bytes, same Ed25519 signatures.
- `Signer`, `Verifier`, `Pin`, `PinHeader` types with the same
  failure-mode taxonomy.
- `cargo test` passes 23 unit tests + 2 cross-language tests + 1 doctest.

#### Cross-language test vectors (`testvectors/`)
- `v1.json`: positive fixtures with deterministic seed, consumed by both
  Python and Rust test suites.
- `negative_v1.json`: tamper-detection fixture.
- CI workflow regenerates fixtures on every Python-side change and
  fails on byte drift, preventing silent compatibility breakage.

#### Adapters and detectors
- `QdrantAdapter`: production Qdrant integration via `qdrant-client`.
  Lazily imported; install with `pip install 'vectorpin[qdrant]'`.
- `IsolationForestDetector` and `OneClassSVMDetector`: defensive
  baselines from sklearn. Lazily imported; install with
  `pip install 'vectorpin[detectors]'`.

#### CLI (`vectorpin`)
- `keygen`: generate Ed25519 key pairs.
- `pin`: sign a (text, vector) pair.
- `verify-pin`: verify a pin against ground-truth source/vector.
- `audit-qdrant`: walk a Qdrant collection and report on every record.

#### Documentation
- README with Python and Rust quick-start.
- `docs/spec.md` — protocol v1 specification.
- `examples/basic_usage.py` and `examples/basic_usage.rs`.
- Companion preprint (Zenodo DOI
  [10.5281/zenodo.20058256](https://doi.org/10.5281/zenodo.20058256))
  documenting the threat model and defended attack class.

### Known limitations

- Adapter coverage is partial: Qdrant only. FAISS, Pinecone, Chroma,
  and pgvector adapters are planned for v0.2.
- TypeScript and Go ports are planned but not yet shipped.
- Record-id and collection-id binding currently lives under the
  `extra` field; promotion to top-level fields is a candidate for
  protocol v1.1.

[0.1.0]: https://github.com/ThirdKeyAI/VectorPin/releases/tag/v0.1.0
