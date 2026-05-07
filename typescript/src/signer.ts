// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Pin signing.
//
// Wraps an Ed25519 signing key plus a `kid` so verifiers can route
// signatures during key rotation. Use Signer.generate() for tests
// and demos; load production keys from a managed secret store.

import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2';
import { randomBytes } from '@noble/hashes/utils';

import {
  canonicalizeHeader,
  PROTOCOL_VERSION,
  type Pin,
  type PinHeader,
} from './attestation.js';
import { hashText, hashVector, type VecDtype, type VectorInput } from './hash.js';

// noble/ed25519 v2 sync API requires a sha512 hookup. Hooking it up
// at module load is fine; it's a pure-JS function reference.
ed25519.etc.sha512Sync = (...m) => sha512(ed25519.etc.concatBytes(...m));

export interface SignerPinOptions {
  /** Source text the embedding was produced from. */
  source: string;
  /** Embedding model identifier, e.g. 'text-embedding-3-large'. */
  model: string;
  /** 1-D embedding. */
  vector: VectorInput;
  /** Canonical dtype to hash under. Defaults to 'f32'. */
  vecDtype?: VecDtype;
  /** Optional content hash of the model weights. */
  modelHash?: string;
  /** Optional explicit timestamp in `YYYY-MM-DDTHH:MM:SSZ` form; defaults to now (UTC). */
  timestamp?: string;
  /** Optional string-to-string metadata committed under the signature. */
  extra?: Record<string, string>;
}

/**
 * Produces signed Pin attestations.
 *
 * A Signer holds one Ed25519 private key. The corresponding public
 * key is published with `keyId` so verifiers can route signatures
 * to the right key during rotation.
 */
export class Signer {
  readonly #privateKey: Uint8Array;
  readonly #keyId: string;

  private constructor(privateKey: Uint8Array, keyId: string) {
    if (!keyId) throw new Error('keyId must be non-empty');
    if (privateKey.length !== 32) {
      throw new Error(`private key must be 32 bytes, got ${privateKey.length}`);
    }
    this.#privateKey = privateKey;
    this.#keyId = keyId;
  }

  /** Generate a fresh Ed25519 signer. Tests and demos only. */
  static generate(keyId: string): Signer {
    return new Signer(randomBytes(32), keyId);
  }

  /** Load a signer from a 32-byte raw Ed25519 private seed. */
  static fromPrivateBytes(raw: Uint8Array, keyId: string): Signer {
    return new Signer(raw, keyId);
  }

  get keyId(): string {
    return this.#keyId;
  }

  /** 32-byte raw Ed25519 public key — what verifiers register. */
  publicKeyBytes(): Uint8Array {
    return ed25519.getPublicKey(this.#privateKey);
  }

  /** 32-byte raw Ed25519 private seed. Treat as a secret. */
  privateKeyBytes(): Uint8Array {
    // Defensive copy so the caller cannot mutate our internal state.
    return new Uint8Array(this.#privateKey);
  }

  /** Create a signed Pin for a (source, model, vector) triple. */
  pin(opts: SignerPinOptions): Pin {
    if (opts.vector.length === 0) {
      throw new Error('cannot pin an empty vector');
    }
    const dtype: VecDtype = opts.vecDtype ?? 'f32';
    const ts = opts.timestamp ?? formatUtcIsoSecond(new Date());
    const header: PinHeader = {
      v: PROTOCOL_VERSION,
      model: opts.model,
      source_hash: hashText(opts.source),
      vec_hash: hashVector(opts.vector, dtype),
      vec_dtype: dtype,
      vec_dim: opts.vector.length,
      ts,
      model_hash: opts.modelHash,
      extra: opts.extra,
    };
    const canonical = canonicalizeHeader(header);
    const sig = ed25519.sign(canonical, this.#privateKey);
    return { header, kid: this.#keyId, sig };
  }
}

/**
 * Format `Date` to `YYYY-MM-DDTHH:MM:SSZ` UTC (second-precision).
 *
 * We avoid `toISOString()` because it includes milliseconds and the
 * Python/Rust ports emit second-precision timestamps. Matching that
 * format keeps cross-language hashes identical for fixtures that
 * supply their own timestamp string.
 */
export function formatUtcIsoSecond(d: Date): string {
  const pad = (n: number, w = 2) => String(n).padStart(w, '0');
  return (
    pad(d.getUTCFullYear(), 4) +
    '-' +
    pad(d.getUTCMonth() + 1) +
    '-' +
    pad(d.getUTCDate()) +
    'T' +
    pad(d.getUTCHours()) +
    ':' +
    pad(d.getUTCMinutes()) +
    ':' +
    pad(d.getUTCSeconds()) +
    'Z'
  );
}
