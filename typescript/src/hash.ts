// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Canonical hashing for source text and embedding vectors.
//
// These three operations are the only places in the protocol where
// semantic content gets turned into bytes. The Python and Rust ports
// agree on the byte semantics here, so this implementation pins down
// the same contract:
//
//   * Vectors: little-endian, 1-D, packed `f32` or `f64` bytes.
//   * Text: UTF-8 of the NFC-normalized string.
//   * Output digests: prefixed with `"sha256:"` and lowercase hex.

import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex } from '@noble/hashes/utils';

/** Canonical scalar dtype identifier carried in the wire format. */
export type VecDtype = 'f32' | 'f64';

/**
 * A 1-D vector view accepted by the canonicalization helpers. Plain
 * `number[]`, `Float32Array`, and `Float64Array` are all supported
 * — the dtype the caller passes determines how the bytes are packed.
 */
export type VectorInput = readonly number[] | Float32Array | Float64Array;

/**
 * Reproducible byte form of an embedding vector.
 *
 * Always little-endian, always packed, always under the dtype the
 * caller specifies. Two implementations must agree on these bytes
 * byte-for-byte for cross-language verification to work.
 */
export function canonicalVectorBytes(vector: VectorInput, dtype: VecDtype): Uint8Array {
  if (vector.length === 0) {
    throw new Error('cannot canonicalize empty vector');
  }
  const bytesPerElem = dtype === 'f32' ? 4 : 8;
  const out = new Uint8Array(vector.length * bytesPerElem);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  if (dtype === 'f32') {
    for (let i = 0; i < vector.length; i++) {
      // `vector[i]!` is safe — we just bounded i to vector.length.
      view.setFloat32(i * 4, vector[i]!, /* littleEndian */ true);
    }
  } else {
    for (let i = 0; i < vector.length; i++) {
      view.setFloat64(i * 8, vector[i]!, /* littleEndian */ true);
    }
  }
  return out;
}

/** SHA-256 of a vector's canonical bytes, formatted as `"sha256:<hex>"`. */
export function hashVector(vector: VectorInput, dtype: VecDtype = 'f32'): string {
  return sha256Prefixed(canonicalVectorBytes(vector, dtype));
}

/** SHA-256 of a string after Unicode NFC normalization and UTF-8 encoding. */
export function hashText(text: string): string {
  const nfc = text.normalize('NFC');
  return sha256Prefixed(new TextEncoder().encode(nfc));
}

/** SHA-256 over arbitrary bytes, formatted as `"sha256:<hex>"`. */
export function hashBytes(data: Uint8Array): string {
  return sha256Prefixed(data);
}

function sha256Prefixed(data: Uint8Array): string {
  return `sha256:${bytesToHex(sha256(data))}`;
}
