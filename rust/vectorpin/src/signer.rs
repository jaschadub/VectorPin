// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0

//! Pin signing.
//!
//! Wraps an Ed25519 signing key plus a `kid` (key id) so verifiers can
//! route signatures during key rotation. Use [`Signer::generate`] for
//! tests and demos; load production keys from a managed secret store
//! via [`Signer::from_private_bytes`].
//!
//! # Examples
//!
//! ```
//! use vectorpin::Signer;
//!
//! let signer = Signer::generate("prod-2026-05".to_string());
//! let v: Vec<f32> = vec![0.1, 0.2, 0.3];
//! let pin = signer.pin("hello", "text-embedding-3-large", v.as_slice()).unwrap();
//! assert_eq!(pin.kid, "prod-2026-05");
//! assert_eq!(pin.sig.len(), 64); // Ed25519 signature
//! ```
//!
//! For deterministic signing (test fixtures, reproducible CI builds),
//! use [`PinOptions`] to supply an explicit timestamp and dtype:
//!
//! ```
//! use vectorpin::signer::{PinOptions, Signer};
//! use vectorpin::VecDtype;
//!
//! let signer = Signer::generate("test".to_string());
//! let v: Vec<f32> = vec![0.1, 0.2, 0.3];
//! let opts = PinOptions {
//!     dtype: Some(VecDtype::F32),
//!     timestamp: Some("2026-05-05T12:00:00Z".to_string()),
//!     ..PinOptions::default()
//! };
//! let pin = signer
//!     .pin_with_options("hello", "test-model", v.as_slice(), opts)
//!     .unwrap();
//! assert_eq!(pin.header.ts, "2026-05-05T12:00:00Z");
//! ```

use std::collections::BTreeMap;

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};

use crate::attestation::{Pin, PinHeader, PROTOCOL_VERSION};
use crate::hash::{hash_text, hash_vector, VecDtype, VectorRef};

/// Errors raised by signer construction or pinning.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    /// `key_id` was empty.
    #[error("key_id must be non-empty")]
    EmptyKeyId,
    /// Private key bytes were the wrong length (must be 32).
    #[error("private key must be exactly 32 bytes, got {0}")]
    BadKeyLength(usize),
    /// Vector was empty or otherwise unrepresentable.
    #[error("invalid vector: {0}")]
    InvalidVector(&'static str),
}

/// Produces signed [`Pin`] attestations.
///
/// A `Signer` holds one Ed25519 private key plus a stable identifier
/// (`kid`) that gets embedded in every pin it produces. Verifiers use
/// the `kid` to look up the matching public key in their registry, so
/// rotating signing keys is a matter of issuing a new `(kid, key)` pair
/// and accepting both the old and new `kid` values during the rotation
/// window — no protocol changes required.
///
/// # Secret material
///
/// [`Signer::generate`] is for tests, demos, and one-off CLI tools.
/// In production, hold the 32-byte private seed in a managed secrets
/// store (HSM, KMS, sealed env var) and instantiate via
/// [`Signer::from_private_bytes`]. [`Signer::private_key_bytes`] is
/// provided for backup/key-export workflows; treat its output as
/// secret.
pub struct Signer {
    signing_key: SigningKey,
    key_id: String,
}

impl Signer {
    /// Generate a fresh Ed25519 signer. Tests and demos only.
    pub fn generate(key_id: String) -> Self {
        if key_id.is_empty() {
            // Match the contract documented for `from_private_bytes`.
            // Generation in tests is the only path here so this panic is
            // acceptable; from_private_bytes returns Result.
            panic!("key_id must be non-empty");
        }
        let mut rng = rand::rngs::OsRng;
        Signer {
            signing_key: SigningKey::generate(&mut rng),
            key_id,
        }
    }

    /// Load a signer from a 32-byte raw Ed25519 private seed.
    pub fn from_private_bytes(raw: &[u8], key_id: String) -> Result<Self, SignerError> {
        if key_id.is_empty() {
            return Err(SignerError::EmptyKeyId);
        }
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| SignerError::BadKeyLength(raw.len()))?;
        Ok(Signer {
            signing_key: SigningKey::from_bytes(&bytes),
            key_id,
        })
    }

    /// Identifier of the key used to sign — published in produced pins as `kid`.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// 32-byte raw Ed25519 public key. This is what verifiers register.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        VerifyingKey::from(&self.signing_key).to_bytes()
    }

    /// 32-byte raw Ed25519 private seed. Treat as a secret.
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Create a [`Pin`] for `(source, model, vector)`.
    ///
    /// `vector` accepts anything that converts into a [`VectorRef`],
    /// which includes `&[f32]` and `&[f64]`. The dtype written into
    /// the header defaults to the native dtype of the slice.
    pub fn pin<'a>(
        &self,
        source: &str,
        model: &str,
        vector: impl Into<VectorRef<'a>>,
    ) -> Result<Pin, SignerError> {
        self.pin_with_options(source, model, vector, PinOptions::default())
    }

    /// [`Self::pin`] with explicit dtype, model hash, timestamp, and
    /// `extra` map. Used by deterministic test-vector generation.
    pub fn pin_with_options<'a>(
        &self,
        source: &str,
        model: &str,
        vector: impl Into<VectorRef<'a>>,
        opts: PinOptions,
    ) -> Result<Pin, SignerError> {
        let vector = vector.into();
        if vector.is_empty() {
            return Err(SignerError::InvalidVector("empty vector"));
        }

        let dtype = opts.dtype.unwrap_or_else(|| vector.native_dtype());
        let ts = opts.timestamp.unwrap_or_else(now_utc_iso8601);

        let header = PinHeader {
            v: PROTOCOL_VERSION,
            model: model.to_owned(),
            model_hash: opts.model_hash,
            source_hash: hash_text(source),
            vec_hash: hash_vector(vector, dtype),
            vec_dtype: dtype.as_str().to_owned(),
            vec_dim: vector.len() as u32,
            ts,
            extra: opts.extra,
        };

        let signature = self.signing_key.sign(&header.canonicalize());
        Ok(Pin {
            header,
            kid: self.key_id.clone(),
            sig: signature.to_bytes().to_vec(),
        })
    }
}

/// Optional knobs for [`Signer::pin_with_options`].
///
/// Defaults match what `Signer::pin` uses: native dtype, no model hash,
/// current UTC time, no extra metadata.
#[derive(Debug, Default, Clone)]
pub struct PinOptions {
    /// Override the canonical dtype the vector is hashed under.
    pub dtype: Option<VecDtype>,
    /// Optional content hash of the model weights.
    pub model_hash: Option<String>,
    /// Optional explicit timestamp string (must already be in
    /// `YYYY-MM-DDTHH:MM:SSZ` form).
    pub timestamp: Option<String>,
    /// Optional string-to-string `extra` map. Values are signed.
    pub extra: BTreeMap<String, String>,
}

fn now_utc_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    // We avoid pulling in `chrono` for one timestamp; this gives the
    // same `YYYY-MM-DDTHH:MM:SSZ` format the Python reference emits.
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, mo, d, h, mi, se) = unix_to_ymdhms(secs as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{se:02}Z")
}

fn unix_to_ymdhms(t: i64) -> (i32, u32, u32, u32, u32, u32) {
    // Days since 1970-01-01.
    let days = (t.div_euclid(86400)) as i32;
    let secs_of_day = t.rem_euclid(86400) as u32;
    let h = secs_of_day / 3600;
    let mi = (secs_of_day % 3600) / 60;
    let se = secs_of_day % 60;

    // Civil from days, see http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i32 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, h, mi, se)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_round_trip_basic() {
        let signer = Signer::generate("test".into());
        let v: Vec<f32> = vec![1.0, 2.0, 3.0];
        let pin = signer.pin("hello", "model", v.as_slice()).unwrap();
        assert_eq!(pin.kid, "test");
        assert_eq!(pin.header.vec_dim, 3);
        assert_eq!(pin.header.vec_dtype, "f32");
        assert_eq!(pin.sig.len(), 64);
    }

    #[test]
    fn from_private_bytes_rejects_empty_kid() {
        let res = Signer::from_private_bytes(&[0u8; 32], "".into());
        assert!(matches!(res, Err(SignerError::EmptyKeyId)));
    }

    #[test]
    fn from_private_bytes_rejects_bad_length() {
        let res = Signer::from_private_bytes(&[0u8; 16], "k".into());
        assert!(matches!(res, Err(SignerError::BadKeyLength(16))));
    }

    #[test]
    fn private_seed_round_trip() {
        let signer = Signer::generate("k".into());
        let seed = signer.private_key_bytes();
        let restored = Signer::from_private_bytes(&seed, "k".into()).unwrap();
        assert_eq!(signer.public_key_bytes(), restored.public_key_bytes());
    }
}
