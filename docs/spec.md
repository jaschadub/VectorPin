# VectorPin Protocol Specification

**Version:** 1
**Status:** Draft
**License:** Apache 2.0

This document specifies the wire format, canonicalization, and verification rules for VectorPin attestations. Anyone implementing VectorPin in another language should be able to read this document, ignore the Python reference implementation, and produce signatures and verifications that interoperate.

## 1. Goals

A VectorPin Pin is a compact attestation that travels with an embedding through a vector database. It guarantees that:

- The embedding matches a specific source text.
- The embedding was produced by a specific model.
- The pin was issued by a specific producer.
- None of the above has changed since issuance.

Non-goals: confidentiality, access control, anti-replay across collections.

## 2. Cryptographic primitives

| Primitive | Algorithm |
|---|---|
| Hash | SHA-256 |
| Signature | Ed25519 |
| Encoding | URL-safe base64, no padding |

These are fixed for protocol version 1. Future versions MAY introduce alternatives but MUST bump the version field.

## 3. Canonical hashes

### 3.1 Text hashing

```
hash_text(s) := "sha256:" || hex(SHA-256(UTF-8(NFC(s))))
```

Text MUST be normalized to Unicode NFC before encoding. Implementations MUST reject input that cannot be normalized.

### 3.2 Vector hashing

```
hash_vector(v, dtype) := "sha256:" || hex(SHA-256(canonical_bytes(v, dtype)))
```

Where `canonical_bytes` produces:

1. The vector cast to the specified dtype (`f32` or `f64`).
2. Stored in little-endian byte order.
3. Packed contiguously, 1-D.

Other dtypes are reserved for future protocol versions.

## 4. Pin format

### 4.1 Wire form

A Pin is a JSON object with the following fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `v` | integer | yes | Protocol version. Must equal `1`. |
| `model` | string | yes | Embedding model identifier. |
| `model_hash` | string | no | Optional content hash of the model weights. |
| `source_hash` | string | yes | Hash of the source text (§3.1). |
| `vec_hash` | string | yes | Hash of the embedding (§3.2). |
| `vec_dtype` | string | yes | One of `"f32"` or `"f64"`. |
| `vec_dim` | integer | yes | Embedding dimensionality. |
| `ts` | string | yes | RFC 3339 / ISO 8601 timestamp in UTC, e.g. `"2026-05-05T12:00:00Z"`. |
| `extra` | object | no | String-to-string map of producer-defined fields. |
| `kid` | string | yes | Identifier of the signing key. |
| `sig` | string | yes | Ed25519 signature, URL-safe base64 with no padding. |

### 4.2 Canonicalization for signing

The signature in `sig` is produced over a canonical byte sequence that excludes `kid` and `sig` themselves. The canonical form is JSON with:

- All keys sorted lexicographically.
- No whitespace (separators `","` and `":"`).
- UTF-8 encoding.
- `extra`, if present, with its keys also sorted.
- `model_hash` and `extra` omitted entirely if not set.

This canonical form is fed directly into Ed25519 signing.

### 4.3 Example

```json
{
  "v": 1,
  "model": "text-embedding-3-large",
  "source_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "vec_hash": "sha256:0123...",
  "vec_dtype": "f32",
  "vec_dim": 3072,
  "ts": "2026-05-05T12:00:00Z",
  "kid": "prod-2026-05",
  "sig": "MEUCIQD..."
}
```

## 5. Verification

A verifier MUST:

1. Reject pins whose `v` field is unknown to it.
2. Reject pins whose `kid` is not in its key registry.
3. Reconstruct the canonical byte sequence (§4.2) and verify `sig` against the registered public key for `kid`.
4. If a ground-truth source string was supplied, recompute `hash_text(source)` and compare to `source_hash`.
5. If a ground-truth vector was supplied, recompute `hash_vector(vector, vec_dtype)` and compare to `vec_hash`. Also check that the supplied vector's shape matches `vec_dim`.
6. If an expected model identifier was supplied, compare to `model`.

Verifiers MUST distinguish at least these failure modes (the reference implementation uses the names below; other implementations MAY use different names but MUST distinguish the cases):

- `UNSUPPORTED_VERSION`
- `UNKNOWN_KEY`
- `SIGNATURE_INVALID`
- `VECTOR_TAMPERED`
- `SOURCE_MISMATCH`
- `MODEL_MISMATCH`
- `SHAPE_MISMATCH`

## 6. Storage conventions

Adapter implementations SHOULD store pins under the metadata key `vectorpin`. Backends without free-form metadata fields are out of scope for this version of the protocol — provenance must travel with the data.

## 7. Key rotation

Verifiers MUST support multiple `kid` -> public key mappings simultaneously. Issuers rotate by:

1. Generating a new keypair with a fresh `kid`.
2. Adding the new public key to all relevant verifier registries.
3. Switching production signing to the new private key.
4. Optionally re-pinning the corpus over time.
5. Removing the old public key from registries once re-pinning is complete or the rotation policy expires.

Old pins continue to verify against the old public key during this window.

## 8. Reserved `extra` keys

The `vectorpin.` prefix is reserved by this specification and MUST NOT be used by implementations for any purpose other than the keys defined here. Reserved v1 keys, all optional:

| Key | Type | Meaning |
|---|---|---|
| `vectorpin.collection_id` | string | Identifier of the vector-store collection / index this pin belongs to. |
| `vectorpin.record_id` | string | Identifier of the specific record this pin attests. |
| `vectorpin.tenant_id` | string | Identifier of the multi-tenant logical namespace the pin lives in. |

Implementations that need replay protection (cross-record, cross-collection, or cross-tenant) SHOULD use these reserved keys rather than inventing private names. Because every `extra` entry is signed, the values are tamper-evident.

A v1.1 candidate spec promotes `record_id`, `collection_id`, and `tenant_id` to top-level fields. v1.1 verifiers will accept v1 pins; v1 verifiers will reject v1.1 pins because the protocol-version field changes.

## 9. Security considerations

- **Replay**: Pins are not bound to a specific record id at the wire format level. An attacker who copies a pin from one record to another can pass verification only if the vector and source they paste alongside match the pin. Implementations that need stronger replay protection SHOULD use the reserved `vectorpin.collection_id` / `vectorpin.record_id` / `vectorpin.tenant_id` keys defined in §8.
- **Time**: The `ts` field is informational. Verifiers MAY reject pins outside an acceptable time window but the protocol does not require it.
- **Key custody**: An attacker with the private signing key can produce arbitrary pins. Treat the signing key as a high-value secret.
- **Source-time integrity**: VectorPin attests to the relationship between source and vector at pin time. It does not attest that the source itself was authentic at ingestion.

## 10. Versioning

This is protocol version 1. Future versions MAY:

- Add new optional fields under `extra`-style namespaces.
- Add new dtype identifiers.
- Add new signature/hash algorithms (with corresponding identifiers).

A change is breaking iff a v1 verifier would silently accept a v2 pin as valid when the v2 pin's additional semantics matter. Such changes MUST bump the major version.
