// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Pin attestation format and canonicalization.
//
// A Pin is the attestation that travels alongside an embedding in
// vector store metadata. It commits to:
//
//   - the source text (by hash)
//   - the model that produced the embedding (identifier + optional hash)
//   - the embedding itself (by hash)
//   - the producer (by signing key id)
//   - the time of pinning
//
// The wire form is a compact JSON object. The signature is over a
// canonical byte sequence built by `canonicalize()`, NOT over the
// JSON encoding — this is so that downstream re-serialization
// (whitespace, key order) cannot invalidate signatures.
//
// Protocol version: PROTOCOL_VERSION (currently 1). Older readers
// MUST reject unknown versions.

import type { VecDtype } from './hash.js';

export const PROTOCOL_VERSION = 1 as const;

/**
 * The signed portion of a Pin.
 *
 * Everything except `sig` and `kid` lives here. Two Pins are
 * equivalent iff their headers canonicalize to identical bytes.
 */
export interface PinHeader {
  readonly v: number;
  readonly model: string;
  readonly source_hash: string;
  readonly vec_hash: string;
  readonly vec_dtype: VecDtype;
  readonly vec_dim: number;
  readonly ts: string;
  readonly model_hash?: string | undefined;
  readonly extra?: Readonly<Record<string, string>> | undefined;
}

/**
 * Build the dict form of a header for JSON serialization. Keys are
 * sorted alphabetically inside `canonicalize`; this function only
 * decides which fields are present.
 */
export function headerToDict(h: PinHeader): Record<string, unknown> {
  const out: Record<string, unknown> = {
    v: h.v,
    model: h.model,
    source_hash: h.source_hash,
    vec_hash: h.vec_hash,
    vec_dtype: h.vec_dtype,
    vec_dim: h.vec_dim,
    ts: h.ts,
  };
  if (h.model_hash !== undefined && h.model_hash !== null) {
    out['model_hash'] = h.model_hash;
  }
  if (h.extra && Object.keys(h.extra).length > 0) {
    // Sort extra by key to match the Python reference output.
    const sortedExtra: Record<string, string> = {};
    for (const k of Object.keys(h.extra).sort()) {
      sortedExtra[k] = h.extra[k]!;
    }
    out['extra'] = sortedExtra;
  }
  return out;
}

/**
 * Stable byte representation for signing/verifying.
 *
 * Uses JSON with sorted keys, no whitespace, raw UTF-8 (non-ASCII
 * passes through unescaped). This is the canonicalization form
 * with the best library support across languages while still being
 * deterministic.
 */
export function canonicalizeHeader(h: PinHeader): Uint8Array {
  return new TextEncoder().encode(canonicalJsonStringify(headerToDict(h)));
}

/** A signed pin attestation. */
export interface Pin {
  readonly header: PinHeader;
  readonly kid: string;
  /** Raw signature bytes (Ed25519 = 64 bytes). */
  readonly sig: Uint8Array;
}

/** Compact JSON encoding suitable for vector DB metadata fields. */
export function pinToJSON(pin: Pin): string {
  return canonicalJsonStringify(pinToDict(pin));
}

/** Plain-object representation; mirrors `Pin.to_dict` in Python. */
export function pinToDict(pin: Pin): Record<string, unknown> {
  const d = headerToDict(pin.header);
  d['kid'] = pin.kid;
  d['sig'] = b64UrlEncodeNoPad(pin.sig);
  return d;
}

export function pinFromJSON(s: string): Pin {
  return pinFromDict(JSON.parse(s) as Record<string, unknown>);
}

export function pinFromDict(d: Record<string, unknown>): Pin {
  if (d['v'] !== PROTOCOL_VERSION) {
    throw new Error(
      `unsupported pin version ${JSON.stringify(d['v'])}; expected ${PROTOCOL_VERSION}`,
    );
  }
  const dtype = d['vec_dtype'];
  if (dtype !== 'f32' && dtype !== 'f64') {
    throw new Error(`unsupported vec_dtype ${JSON.stringify(dtype)}`);
  }
  const extraRaw = d['extra'];
  const extra =
    extraRaw && typeof extraRaw === 'object'
      ? Object.fromEntries(Object.entries(extraRaw as Record<string, unknown>).map(
          ([k, v]) => [k, String(v)],
        ))
      : undefined;
  const header: PinHeader = {
    v: d['v'] as number,
    model: String(d['model']),
    source_hash: String(d['source_hash']),
    vec_hash: String(d['vec_hash']),
    vec_dtype: dtype,
    vec_dim: Number(d['vec_dim']),
    ts: String(d['ts']),
    model_hash: typeof d['model_hash'] === 'string' ? d['model_hash'] : undefined,
    extra,
  };
  const sigStr = d['sig'];
  if (typeof sigStr !== 'string') {
    throw new Error('pin missing sig field');
  }
  return {
    header,
    kid: String(d['kid']),
    sig: b64UrlDecodeNoPad(sigStr),
  };
}

// ---- canonical JSON ----

/**
 * Deterministic JSON encoder matching Python's
 * `json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
 * and Rust's `serde_json` with sorted keys (see attestation::canonicalize).
 *
 * Sorts object keys at every depth, omits whitespace, and emits raw
 * UTF-8 (non-ASCII is not escaped to \uXXXX). We do not need full
 * canonical-JSON [RFC 8785] semantics — the protocol values are
 * scalars and shallow string maps, so a small recursive walk suffices.
 */
export function canonicalJsonStringify(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('cannot canonicalize non-finite number');
    }
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalJsonStringify).join(',') + ']';
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts: string[] = [];
    for (const k of keys) {
      parts.push(JSON.stringify(k) + ':' + canonicalJsonStringify(obj[k]));
    }
    return '{' + parts.join(',') + '}';
  }
  throw new Error(`cannot canonicalize value of type ${typeof value}`);
}

// ---- URL-safe base64 without padding ----

/**
 * URL-safe base64, no padding — matches Python's
 * `base64.urlsafe_b64encode(data).rstrip(b"=")` and Rust's
 * `URL_SAFE_NO_PAD`.
 */
export function b64UrlEncodeNoPad(data: Uint8Array): string {
  // Buffer is available in Node 20+ (the package's minimum); base64url
  // is the standard URL-safe alphabet without padding.
  return Buffer.from(data).toString('base64url');
}

export function b64UrlDecodeNoPad(s: string): Uint8Array {
  // Buffer.from with 'base64url' tolerates missing padding.
  return new Uint8Array(Buffer.from(s, 'base64url'));
}
