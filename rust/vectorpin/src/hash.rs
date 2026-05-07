// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0

//! Canonical hashing for source text and embedding vectors.
//!
//! These three operations are the only places in the protocol where
//! semantic content gets turned into bytes. Any disagreement between
//! the Python, Rust, and TypeScript ports here breaks cross-language
//! verification, so the semantics are pinned down explicitly:
//!
//! * Vectors: little-endian, 1-D, packed `f32` or `f64` bytes.
//! * Text: UTF-8 of the NFC-normalized string.
//! * Output digests: prefixed with `"sha256:"` and lowercase hex.
//!
//! Cross-language byte-for-byte parity for the functions in this module
//! is asserted by `tests/cross_lang.rs` against the shared fixtures in
//! [`testvectors/`](https://github.com/ThirdKeyAI/VectorPin/tree/main/testvectors).
//!
//! # Examples
//!
//! Hashing source text is NFC-normalized so that visually identical
//! strings stored in different Unicode forms hash equal:
//!
//! ```
//! use vectorpin::hash_text;
//!
//! let composed = "caf\u{00e9}";        // 'é' as one codepoint (NFC)
//! let decomposed = "cafe\u{0301}";     // 'e' + combining acute (NFD)
//! assert_eq!(hash_text(composed), hash_text(decomposed));
//! assert!(hash_text("hello").starts_with("sha256:"));
//! ```
//!
//! Hashing a vector requires the dtype the caller wants to commit to.
//! The same numeric values hashed under f32 and f64 produce different
//! digests, by design — the dtype is part of the signed contract:
//!
//! ```
//! use vectorpin::{hash_vector, hash::VectorRef, VecDtype};
//!
//! let v: Vec<f32> = vec![0.1, 0.2, 0.3];
//! let h32 = hash_vector(VectorRef::F32(&v), VecDtype::F32);
//! assert!(h32.starts_with("sha256:"));
//! assert_eq!(h32.len(), "sha256:".len() + 64);
//! ```

use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

/// Canonical scalar dtype identifier carried in the wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VecDtype {
    /// 32-bit IEEE float, little endian.
    F32,
    /// 64-bit IEEE float, little endian.
    F64,
}

impl VecDtype {
    /// Wire form (`"f32"` or `"f64"`) used in the attestation JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            VecDtype::F32 => "f32",
            VecDtype::F64 => "f64",
        }
    }

    /// Parse a wire form back into a [`VecDtype`].
    pub fn parse(s: &str) -> Result<Self, HashError> {
        match s {
            "f32" => Ok(VecDtype::F32),
            "f64" => Ok(VecDtype::F64),
            other => Err(HashError::UnsupportedDtype(other.to_string())),
        }
    }
}

impl std::str::FromStr for VecDtype {
    type Err = HashError;
    fn from_str(s: &str) -> Result<Self, HashError> {
        Self::parse(s)
    }
}

/// Errors produced by canonicalization helpers.
#[derive(Debug, thiserror::Error)]
pub enum HashError {
    /// Vector dimensionality reported by the caller did not match the data.
    #[error("vector dim mismatch: declared {declared}, actual {actual}")]
    DimMismatch {
        /// What the caller said.
        declared: usize,
        /// What the data actually contained.
        actual: usize,
    },
    /// Unsupported scalar dtype identifier.
    #[error("unsupported canonical dtype: {0}")]
    UnsupportedDtype(String),
}

/// Untyped vector view — either f32 or f64 slice — handed to canonicalization.
///
/// Exists so callers can pin a vector without converting to/from a fixed
/// dtype inside the call site. The hash is taken under whatever dtype
/// the caller specifies in the [`PinHeader`](crate::PinHeader).
#[derive(Debug, Clone, Copy)]
pub enum VectorRef<'a> {
    /// Borrowed `f32` slice.
    F32(&'a [f32]),
    /// Borrowed `f64` slice.
    F64(&'a [f64]),
}

impl<'a> VectorRef<'a> {
    /// Length of the underlying slice.
    pub fn len(&self) -> usize {
        match self {
            VectorRef::F32(v) => v.len(),
            VectorRef::F64(v) => v.len(),
        }
    }

    /// True iff the underlying slice is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Native dtype of the underlying slice.
    pub fn native_dtype(&self) -> VecDtype {
        match self {
            VectorRef::F32(_) => VecDtype::F32,
            VectorRef::F64(_) => VecDtype::F64,
        }
    }
}

impl<'a> From<&'a [f32]> for VectorRef<'a> {
    fn from(v: &'a [f32]) -> Self {
        VectorRef::F32(v)
    }
}

impl<'a> From<&'a [f64]> for VectorRef<'a> {
    fn from(v: &'a [f64]) -> Self {
        VectorRef::F64(v)
    }
}

/// Reproducible byte form of an embedding vector.
///
/// Always little-endian, always packed, always under the dtype
/// requested by the caller. The Python, Rust, and TypeScript ports
/// must agree on these bytes byte-for-byte for cross-language
/// verification to work.
///
/// # Example
///
/// ```
/// use vectorpin::{canonical_vector_bytes, hash::VectorRef, VecDtype};
///
/// let v = [1.0_f32];
/// let bytes = canonical_vector_bytes(VectorRef::F32(&v), VecDtype::F32);
/// // 1.0_f32 in IEEE-754 little-endian.
/// assert_eq!(bytes, [0x00, 0x00, 0x80, 0x3f]);
/// ```
pub fn canonical_vector_bytes(vector: VectorRef<'_>, dtype: VecDtype) -> Vec<u8> {
    match (vector, dtype) {
        (VectorRef::F32(v), VecDtype::F32) => f32_le_bytes(v),
        (VectorRef::F64(v), VecDtype::F32) => {
            // Down-cast each f64 to f32 before packing.
            let casted: Vec<f32> = v.iter().map(|&x| x as f32).collect();
            f32_le_bytes(&casted)
        }
        (VectorRef::F32(v), VecDtype::F64) => {
            // Up-cast each f32 to f64 before packing.
            let casted: Vec<f64> = v.iter().map(|&x| x as f64).collect();
            f64_le_bytes(&casted)
        }
        (VectorRef::F64(v), VecDtype::F64) => f64_le_bytes(v),
    }
}

fn f32_le_bytes(v: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 4);
    for x in v {
        out.extend_from_slice(&x.to_le_bytes());
    }
    out
}

fn f64_le_bytes(v: &[f64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 8);
    for x in v {
        out.extend_from_slice(&x.to_le_bytes());
    }
    out
}

/// SHA-256 of a vector's canonical bytes, formatted as `"sha256:<hex>"`.
pub fn hash_vector(vector: VectorRef<'_>, dtype: VecDtype) -> String {
    sha256_prefixed(&canonical_vector_bytes(vector, dtype))
}

/// SHA-256 of a string after Unicode NFC normalization and UTF-8 encoding.
pub fn hash_text(text: &str) -> String {
    let normalized: String = text.nfc().collect();
    sha256_prefixed(normalized.as_bytes())
}

/// SHA-256 over arbitrary bytes, formatted as `"sha256:<hex>"`.
pub fn hash_bytes(data: &[u8]) -> String {
    sha256_prefixed(data)
}

fn sha256_prefixed(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    format!("sha256:{}", hex::encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_text_is_stable() {
        assert_eq!(hash_text("hello"), hash_text("hello"));
    }

    #[test]
    fn hash_text_normalizes_nfc() {
        // Composed vs decomposed "café"
        let composed = "caf\u{00e9}";
        let decomposed = "cafe\u{0301}";
        assert_eq!(hash_text(composed), hash_text(decomposed));
    }

    #[test]
    fn hash_text_distinguishes_content() {
        assert_ne!(hash_text("hello"), hash_text("Hello"));
    }

    #[test]
    fn canonical_vector_bytes_endianness_is_explicit() {
        let v = [1.0_f32];
        let bytes = canonical_vector_bytes(VectorRef::F32(&v), VecDtype::F32);
        assert_eq!(bytes, 1.0_f32.to_le_bytes().to_vec());
    }

    #[test]
    fn vector_dtype_round_trip() {
        assert_eq!(VecDtype::parse("f32").unwrap(), VecDtype::F32);
        assert_eq!(VecDtype::parse("f64").unwrap(), VecDtype::F64);
        assert!(VecDtype::parse("f16").is_err());
    }

    #[test]
    fn hash_vector_format_is_sha256_hex() {
        let v: Vec<f32> = (0..8).map(|i| i as f32).collect();
        let h = hash_vector(VectorRef::F32(&v), VecDtype::F32);
        assert!(h.starts_with("sha256:"));
        assert_eq!(h.len(), "sha256:".len() + 64);
    }
}
