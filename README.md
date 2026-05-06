# VectorPin

**Verifiable integrity for AI embedding stores.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Rust stable](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![Status: alpha](https://img.shields.io/badge/status-alpha-orange.svg)](#status)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20058256.svg)](https://doi.org/10.5281/zenodo.20058256)

Vector databases are the new soft underbelly of the AI stack. Models trust them. Agents query them. Compliance audits don't yet ask about them. VectorPin pins every embedding to its source content and the model that produced it, then continuously verifies the store has not been tampered with — including covert steganographic modifications invisible to traditional DLP.

Part of the [ThirdKey](https://thirdkey.ai) Trust Stack, alongside [Symbiont](https://github.com/ThirdKeyAI/Symbiont) (policy-governed agent runtime) and [SchemaPin](https://github.com/ThirdKeyAI/SchemaPin) (cryptographic tool verification).

## Why this matters

Modern RAG systems convert sensitive content into high-dimensional vectors and store them in databases that:

- Don't inspect what gets written
- Don't verify integrity on read
- Treat embeddings as opaque numerical artifacts

That's a giant attack surface. The companion [VectorSmuggle](https://github.com/jaschadub/VectorSmuggle) research project demonstrates that an attacker with write access to a vector pipeline can hide arbitrary data inside embeddings using techniques that pass standard observability:

- Noise injection, rotation, scaling, and offset perturbations
- Cross-model fragmentation
- Steganographic encoding that survives database quantization

Cryptographic pinning is the kill shot for these attacks. Every steganographic technique requires modifying the vector after the model produces it. If each vector ships with a signed attestation binding it to its source text and the producing model, any modification breaks the signature.

## Quick start

### Python

```bash
pip install vectorpin
```

```python
import numpy as np
from vectorpin import Signer, Verifier

# At ingestion time
signer = Signer.generate(key_id="prod-2026-05")
embedding = my_model.embed("The quick brown fox.")
pin = signer.pin(
    source="The quick brown fox.",
    model="text-embedding-3-large",
    vector=embedding,
)
# Store pin.to_json() alongside the embedding in your vector DB metadata.

# At read/audit time
verifier = Verifier({"prod-2026-05": signer.public_key_bytes()})
result = verifier.verify(pin, source="The quick brown fox.", vector=embedding)
if not result.ok:
    print(f"INTEGRITY FAILURE: {result.error.value} — {result.detail}")
```

### Rust

```toml
[dependencies]
vectorpin = "0.1"
```

```rust
use vectorpin::{Signer, Verifier};

let signer = Signer::generate("prod-2026-05".to_string());
let embedding: Vec<f32> = my_model_embed("The quick brown fox.");
let pin = signer.pin(
    "The quick brown fox.",
    "text-embedding-3-large",
    embedding.as_slice(),
)?;

let mut verifier = Verifier::new();
verifier.add_key(signer.key_id(), signer.public_key_bytes());

let result = verifier.verify_full::<&[f32]>(
    &pin,
    Some("The quick brown fox."),
    Some(embedding.as_slice()),
    None,
);
assert!(result.is_ok());
```

The Python and Rust implementations are byte-for-byte compatible. A pin produced by either side verifies on both, enforced by shared test vectors at [`testvectors/v1.json`](testvectors/) consumed in both test suites.

## What VectorPin guarantees

Each Pin commits to:

- **The source text**, by SHA-256 of UTF-8 NFC-normalized bytes.
- **The model**, by identifier (and optionally by content hash).
- **The vector itself**, by SHA-256 of canonical little-endian bytes.
- **The producer**, by Ed25519 signing key.
- **The time**, by RFC 3339 timestamp.

Verification distinguishes failure modes so callers can route them differently:

| Outcome | Meaning |
|---|---|
| `OK` | Signature valid, vector intact, source matches. |
| `SIGNATURE_INVALID` | Pin was forged or re-signed by an attacker. |
| `VECTOR_TAMPERED` | Embedding modified after pinning. **This is the steganography kill shot.** |
| `SOURCE_MISMATCH` | Source text differs from what was pinned. |
| `MODEL_MISMATCH` | Pin was produced by a different embedding model than expected. |
| `UNKNOWN_KEY` | Pin signed by a key not in the verifier's registry. |
| `SHAPE_MISMATCH` / `UNSUPPORTED_VERSION` | Structural problems with the data. |

## CLI

```bash
# Generate a signing key pair
vectorpin keygen --key-id prod-2026-05 --output ./keys

# Pin a single (text, vector) pair (debug/demo)
vectorpin pin \
    --private-key ./keys/prod-2026-05.priv \
    --key-id prod-2026-05 \
    --model text-embedding-3-large \
    --source ./doc.txt \
    --vector ./embedding.npy

# Verify a pin
vectorpin verify-pin \
    --public-key ./keys/prod-2026-05.pub \
    --key-id prod-2026-05 \
    --pin ./pin.json \
    --source ./doc.txt \
    --vector ./embedding.npy

# Audit an entire Qdrant collection
vectorpin audit-qdrant \
    --url http://localhost:6333 \
    --collection my-rag \
    --public-key ./keys/prod-2026-05.pub \
    --key-id prod-2026-05
```

## Vector store integrations

| Backend | Status | Install |
|---|---|---|
| Qdrant | Alpha | `pip install 'vectorpin[qdrant]'` |
| FAISS | Planned | — |
| Pinecone | Planned | — |
| Chroma | Planned | — |
| pgvector | Planned | — |

The [adapter protocol](src/vectorpin/adapters/base.py) is intentionally thin; community contributions for new backends are welcome.

## Statistical detectors

Pinning catches modifications. Detectors catch ingestion-time tampering and poisoning campaigns that inject new tampered vectors. The two are complementary defenses:

```python
from vectorpin.detectors.isolation_forest import IsolationForestDetector

detector = IsolationForestDetector().fit(clean_embeddings)
flagged = detector.decide(suspect_embeddings)
```

In the VectorSmuggle empirical study, this single line of defense flagged every operating point of every distribution-shifting steganographic technique that hides a non-trivial amount of data — but it does not catch orthogonal rotation (which preserves every density feature the detector fits on) and is brittle against attackers who know the detector. Cryptographic pinning is the durable layer; statistical detection is defense-in-depth.

## Threat model

VectorPin is designed against an attacker who can:

- Modify vectors after they are produced (via a poisoned ingestion pipeline, a compromised vector DB, or backup-level access)
- See the public verification key, but not the private signing key
- Replay or selectively delete pins

VectorPin does **not** defend against:

- An attacker with the private signing key (out of scope; key custody is the user's responsibility)
- An attacker who modifies the source documents *before* embedding (use upstream content integrity controls)
- An attacker who uses a legitimate signing key to attest a malicious vector at ingestion time (use upstream input validation)

## Status

Alpha (`v0.1`). Core protocol (`Pin`, `Signer`, `Verifier`) is stable and tested. Python and Rust ports are byte-for-byte compatible and locked together by shared test vectors in CI. Adapter coverage is partial. Hosted attestation service is not yet available.

The protocol version field (`v: 1`) lets future revisions break compatibility cleanly. We will not break existing pins without bumping the major version. See [`docs/spec.md`](docs/spec.md) for the wire-format specification.

## Citation

If you reference VectorPin or the threat model it defends against, please cite the companion preprint:

> Wanger, J. (2026). *VectorSmuggle: Steganographic Exfiltration in Embedding Stores and a Cryptographic Provenance Defense*. Zenodo. <https://doi.org/10.5281/zenodo.20058256>

```bibtex
@misc{wanger2026vectorsmuggle,
  title  = {{VectorSmuggle}: Steganographic Exfiltration in Embedding Stores and a Cryptographic Provenance Defense},
  author = {Wanger, Jascha},
  year   = {2026},
  publisher = {Zenodo},
  doi    = {10.5281/zenodo.20058256},
  url    = {https://doi.org/10.5281/zenodo.20058256}
}
```

## Related work

- [VectorSmuggle](https://github.com/jaschadub/VectorSmuggle) — companion threat-research project demonstrating the attacks VectorPin defends against. Empirical results in the linked Zenodo preprint.
- [Symbiont](https://github.com/ThirdKeyAI/Symbiont) — policy-governed agent runtime; consumes VectorPin attestations to enforce "agents may only retrieve from verified vector stores."
- [SchemaPin](https://github.com/ThirdKeyAI/SchemaPin) — sister project doing the same kind of cryptographic provenance for tool schemas in MCP.
- [sigstore](https://www.sigstore.dev/) — inspired our approach to OSS-friendly cryptographic provenance.

## Contributing

Issues and PRs welcome. For security-sensitive findings, please email `security@thirdkey.ai` rather than filing public issues.

## License

Apache 2.0. See [LICENSE](LICENSE).
