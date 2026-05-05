// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0

//! VectorPin — verifiable integrity for AI embedding stores.
//!
//! This crate implements protocol version 1 of the VectorPin attestation
//! format. It is bit-for-bit compatible with the Python reference
//! implementation: identical canonical bytes, identical signatures.
//! Compatibility is enforced by shared test vectors that both ports
//! consume in CI.
//!
//! # Quick start
//!
//! ```
//! use vectorpin::{Signer, Verifier};
//!
//! let signer = Signer::generate("demo".to_string());
//! let vector: Vec<f32> = vec![1.0, 2.0, 3.0];
//! let pin = signer.pin("hello", "test-model", vector.as_slice()).unwrap();
//!
//! let mut verifier = Verifier::new();
//! verifier.add_key(signer.key_id(), signer.public_key_bytes());
//!
//! let result = verifier.verify_full::<&[f32]>(
//!     &pin, Some("hello"), Some(vector.as_slice()), None,
//! );
//! assert!(result.is_ok());
//! ```

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod attestation;
pub mod hash;
pub mod signer;
pub mod verifier;

pub use attestation::{Pin, PinHeader, PROTOCOL_VERSION};
pub use hash::{canonical_vector_bytes, hash_text, hash_vector, VecDtype};
pub use signer::{Signer, SignerError};
pub use verifier::{Verifier, VerifyError};
