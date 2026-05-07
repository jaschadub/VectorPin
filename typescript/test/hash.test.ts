// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0

import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';

import { canonicalVectorBytes, hashBytes, hashText, hashVector } from '../src/hash.js';

describe('hashText', () => {
  it('is stable across calls', () => {
    assert.equal(hashText('hello'), hashText('hello'));
  });

  it('NFC-normalizes its input', () => {
    const composed = 'café'; // é as a single codepoint
    const decomposed = 'café'; // e + combining acute
    assert.equal(hashText(composed), hashText(decomposed));
  });

  it('distinguishes different content', () => {
    assert.notEqual(hashText('hello'), hashText('Hello'));
  });

  it('returns sha256:<hex> form', () => {
    const h = hashText('hello');
    assert.match(h, /^sha256:[0-9a-f]{64}$/);
  });
});

describe('canonicalVectorBytes', () => {
  it('is little-endian for f32', () => {
    const bytes = canonicalVectorBytes([1.0], 'f32');
    // 1.0f32 in IEEE-754 little-endian = 0x00 0x00 0x80 0x3F.
    assert.deepEqual(Array.from(bytes), [0x00, 0x00, 0x80, 0x3f]);
  });

  it('is little-endian for f64', () => {
    const bytes = canonicalVectorBytes([1.0], 'f64');
    // 1.0f64 = 0x00 * 6, 0xF0, 0x3F.
    assert.deepEqual(Array.from(bytes), [0, 0, 0, 0, 0, 0, 0xf0, 0x3f]);
  });

  it('packs Float32Array the same as number[]', () => {
    const v = [0.1, -0.2, 1.5, -3.25];
    const fromArr = canonicalVectorBytes(v, 'f32');
    const fromTyped = canonicalVectorBytes(new Float32Array(v), 'f32');
    assert.deepEqual(Array.from(fromArr), Array.from(fromTyped));
  });

  it('rejects empty vectors', () => {
    assert.throws(() => canonicalVectorBytes([], 'f32'));
  });
});

describe('hashVector', () => {
  it('is stable for the same input', () => {
    const v = new Float32Array([0.1, 0.2, 0.3]);
    assert.equal(hashVector(v, 'f32'), hashVector(v, 'f32'));
  });

  it('changes when a single element changes', () => {
    const a = new Float32Array([0.1, 0.2, 0.3]);
    const b = new Float32Array([0.1, 0.2, 0.30001]);
    assert.notEqual(hashVector(a, 'f32'), hashVector(b, 'f32'));
  });

  it('returns sha256:<hex> form', () => {
    assert.match(hashVector([0.1, 0.2, 0.3], 'f32'), /^sha256:[0-9a-f]{64}$/);
  });
});

describe('hashBytes', () => {
  it('matches hashText for the UTF-8 bytes of an NFC string', () => {
    const s = 'plain ascii';
    assert.equal(hashBytes(new TextEncoder().encode(s)), hashText(s));
  });
});
