# Changelog

All notable changes to VectorPin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] — 2026-05-07

Patch release. No protocol changes; pins produced by 0.1.0 verify on
0.1.1 and vice-versa. Cross-language test vectors are unchanged from
0.1.0; the seed-based fixtures in `testvectors/v1.json` are byte-for-byte
identical.

### Added

- `audit-lancedb` CLI command. Walks a LanceDB table, verifies every
  pin (signature + vector hash, plus source hash if `--source-column`
  is supplied), and emits a JSON summary. Exit non-zero on any
  verification failure so it composes cleanly into CI / cron.
- `audit-chroma` CLI command. Same shape, against a Chroma collection
  (persistent or HTTP). Optional `--source-metadata-key` flag for
  source-text verification.
- `audit-qdrant` gained an optional `--source-payload-key` flag for
  parity with the new commands. Existing invocations are unaffected
  (signature + vector verification remains the default).

### Documentation

- Comprehensive [docs.rs landing page](https://docs.rs/vectorpin) for
  the Rust crate: overview, architecture table, failure-mode taxonomy,
  threat model, and runnable doctest examples on every public type.
- Doctest count grew from 1 to 12 across `attestation`, `hash`,
  `signer`, and `verifier`. Strict `cargo doc` build now passes under
  `-D missing_docs -D rustdoc::broken_intra_doc_links
  -D rustdoc::missing_crate_level_docs`.
- Crates.io README rewritten to match the docs.rs landing-page tone.
- Repository URL fixed in `pyproject.toml` (was `thirdkey/vectorpin`,
  now `ThirdKeyAI/VectorPin`).
- Author string aligned to `"Jascha Wanger / ThirdKey.ai"` across all
  three packaging configs to match the rest of the Trust Stack.

## [0.1.0] — 2026-05-07

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
- Full unit-test coverage plus cross-language fixtures and one doctest.

#### TypeScript implementation (`typescript/`)
- Third reference implementation, byte-for-byte compatible with
  Python and Rust. Pure JavaScript via `@noble/ed25519` and
  `@noble/hashes`, no native deps; works in Node 20+, Deno, Bun, and
  Cloudflare Workers.
- `Signer.generate(keyId)` / `Signer.fromPrivateBytes(raw, keyId)`.
- `Signer.pin({ source, model, vector, ... })` named-options API.
- `Verifier(publicKeys)` with the same failure-mode taxonomy as the
  Python and Rust ports; string-valued `VerifyErrorCode` matches the
  Python wire-form values.
- `pinToJSON` / `pinFromJSON` round-trip.
- ESM-only, ships TypeScript declarations.

#### Cross-language test vectors (`testvectors/`)
- `v1.json`: positive fixtures with deterministic seed, consumed by
  the Python, Rust, and TypeScript test suites.
- `negative_v1.json`: tamper-detection fixture, consumed by all three
  ports.
- CI workflow regenerates fixtures on every Python-side change and
  fails on byte drift, preventing silent compatibility breakage.

#### Adapters
Lazy-loaded via `__getattr__` on `vectorpin.adapters`; backend client
libraries are only imported when the corresponding adapter is used.
- `LanceDBAdapter` *(default backend)*: embedded, file-based, no
  daemon. Pin lives as a typed string column on the table; Lance's
  versioned commit protocol makes (vector, pin) writes atomic. Matches
  the Symbiont runtime's default vector backend. Install with
  `pip install 'vectorpin[default]'` or `'vectorpin[lancedb]'`.
- `ChromaAdapter`: Chroma `metadatas` field. Install with
  `pip install 'vectorpin[chroma]'`.
- `PineconeAdapter`: Pinecone v5+ client (the package was renamed
  upstream from `pinecone-client` to `pinecone`). Install with
  `pip install 'vectorpin[pinecone]'`.
- `QdrantAdapter`: production Qdrant integration via `qdrant-client`.
  Install with `pip install 'vectorpin[qdrant]'`.

#### Detectors
- `IsolationForestDetector` and `OneClassSVMDetector`: defensive
  baselines from sklearn. Lazily imported; install with
  `pip install 'vectorpin[detectors]'`.

#### CLI (`vectorpin`)
- `keygen`: generate Ed25519 key pairs.
- `pin`: sign a (text, vector) pair.
- `verify-pin`: verify a pin against ground-truth source/vector.
- `audit-qdrant`: walk a Qdrant collection and report on every record.

#### Microbenchmarks
- `rust/vectorpin/benches/perf.rs` (criterion) and
  `scripts/bench_python.py` (`time.perf_counter_ns`). Per-op coverage
  of `hash_text`, `hash_vector`, `sign`, `verify_full`,
  `verify_signature_only` across vector dim ∈ {384, 768, 1024, 3072}
  and text length ∈ {128, 1024, 8192}. Sub-millisecond per vector on
  commodity hardware.

#### Documentation
- README with Python, Rust, and TypeScript quick-start.
- `docs/spec.md` — protocol v1 specification.
- `examples/basic_usage.py` and `examples/basic_usage.rs`.
- Companion preprint (Zenodo DOI
  [10.5281/zenodo.20058256](https://doi.org/10.5281/zenodo.20058256))
  documenting the threat model and defended attack class.

### Known limitations

- Adapter coverage is partial: LanceDB, Chroma, Pinecone, and Qdrant
  ship; FAISS and pgvector are planned for a follow-up release. The
  recommended path for FAISS users is to use `LanceDBAdapter`
  (embedded, has metadata column natively) and treat FAISS as a
  derived index.
- A Go port is planned but not yet shipped.
- Record-id and collection-id binding currently lives under the
  `extra` field; promotion to top-level fields is a candidate for
  protocol v1.1.

[0.1.1]: https://github.com/ThirdKeyAI/VectorPin/releases/tag/v0.1.1
[0.1.0]: https://github.com/ThirdKeyAI/VectorPin/releases/tag/v0.1.0
