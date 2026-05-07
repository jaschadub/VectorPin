// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0
//
// VectorPin — verifiable integrity for AI embedding stores.
//
// This package is the TypeScript reference implementation of protocol
// version 1 of the VectorPin attestation format. It is byte-for-byte
// compatible with the Python and Rust ports: identical canonical
// bytes, identical signatures. Compatibility is enforced by shared
// test vectors at `testvectors/v1.json` consumed by all three ports.
//
// Quick start:
//
//     import { Signer, Verifier } from 'vectorpin';
//
//     const signer = Signer.generate('demo-2026-05');
//     const vector = new Float32Array([0.1, 0.2, 0.3]);
//     const pin = signer.pin({
//       source: 'hello',
//       model: 'text-embedding-3-large',
//       vector,
//     });
//
//     const verifier = new Verifier({ [signer.keyId]: signer.publicKeyBytes() });
//     const result = verifier.verify(pin, { source: 'hello', vector });
//     if (!result.ok) throw new Error(`verify failed: ${result.error}`);

export {
  canonicalizeHeader,
  canonicalJsonStringify,
  pinFromDict,
  pinFromJSON,
  pinToDict,
  pinToJSON,
  PROTOCOL_VERSION,
  type Pin,
  type PinHeader,
} from './attestation.js';

export {
  canonicalVectorBytes,
  hashBytes,
  hashText,
  hashVector,
  type VecDtype,
  type VectorInput,
} from './hash.js';

export { formatUtcIsoSecond, Signer, type SignerPinOptions } from './signer.js';

export {
  Verifier,
  VerifyErrorCode,
  type VerificationResult,
  type VerifyOptions,
} from './verifier.js';
