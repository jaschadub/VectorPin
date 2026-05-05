# vectorpin

Rust port of [VectorPin](https://vectorpin.org) — verifiable integrity for AI embedding stores.

Part of the [ThirdKey](https://thirdkey.ai) Trust Stack.

## Why a Rust crate

Symbiont — the Rust-native policy-governed agent runtime in the Trust Stack — needs to verify VectorPin attestations in-process, without a Python sidecar. This crate is the canonical Rust implementation and is bit-for-bit compatible with the Python reference: the same protocol v1 wire format, the same canonical bytes, the same Ed25519 signatures.

Cross-language compatibility is enforced by the test vectors in `../../testvectors/`, which both the Python and Rust test suites consume.

## Quick start

Add to your `Cargo.toml`:

```toml
[dependencies]
vectorpin = "0.1"
```

```rust
use vectorpin::{Signer, Verifier, VerifyError};

fn main() -> anyhow::Result<()> {
    let signer = Signer::generate("prod-2026-05".to_string());

    // Some embedding produced by a model
    let embedding: Vec<f32> = my_model_embed("The quick brown fox.");

    let pin = signer.pin(
        "The quick brown fox.",
        "text-embedding-3-large",
        &embedding,
    )?;

    // Store pin.to_json() alongside the embedding in your vector DB.

    let mut verifier = Verifier::new();
    verifier.add_key(signer.key_id(), signer.public_key_bytes());

    let result = verifier.verify_full(
        &pin,
        Some("The quick brown fox."),
        Some(&embedding),
        None,
    );
    assert!(result.is_ok());
    Ok(())
}
```

## Status

Alpha. Protocol v1 stable; covered by the cross-language test vectors.

## License

Apache 2.0.
