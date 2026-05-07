// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0

import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';

import { pinFromJSON, pinToJSON } from '../src/attestation.js';
import { Signer } from '../src/signer.js';
import { Verifier } from '../src/verifier.js';

describe('Signer.pin + Verifier.verify', () => {
  function fixture(keyId = 'k1') {
    const signer = Signer.generate(keyId);
    const verifier = new Verifier({ [signer.keyId]: signer.publicKeyBytes() });
    const vector = new Float32Array(Array.from({ length: 16 }, (_, i) => i * 0.1));
    return { signer, verifier, vector };
  }

  it('honest verify succeeds', () => {
    const { signer, verifier, vector } = fixture();
    const pin = signer.pin({ source: 'hello', model: 'm', vector });
    const result = verifier.verify(pin, { source: 'hello', vector });
    assert.equal(result.ok, true, `unexpected error: ${result.error} - ${result.detail}`);
  });

  it('signature-only verify succeeds when no source/vector supplied', () => {
    const { signer, verifier, vector } = fixture();
    const pin = signer.pin({ source: 'hello', model: 'm', vector });
    assert.equal(verifier.verify(pin).ok, true);
  });

  it('vector tamper is caught', () => {
    const { signer, verifier, vector } = fixture();
    const pin = signer.pin({ source: 'hello', model: 'm', vector });
    const tampered = new Float32Array(vector);
    tampered[0] = vector[0]! + 1e-5;
    const result = verifier.verify(pin, { vector: tampered });
    assert.equal(result.ok, false);
    assert.equal(result.error, 'vector_tampered');
  });

  it('source mismatch is caught', () => {
    const { signer, verifier, vector } = fixture();
    const pin = signer.pin({ source: 'hello', model: 'm', vector });
    const result = verifier.verify(pin, { source: 'HELLO' });
    assert.equal(result.ok, false);
    assert.equal(result.error, 'source_mismatch');
  });

  it('shape mismatch is caught', () => {
    const { signer, verifier, vector } = fixture();
    const pin = signer.pin({ source: 'hello', model: 'm', vector });
    const truncated = new Float32Array(vector.slice(0, 8));
    const result = verifier.verify(pin, { vector: truncated });
    assert.equal(result.ok, false);
    assert.equal(result.error, 'shape_mismatch');
  });

  it('unknown key is caught', () => {
    const rogue = Signer.generate('rogue');
    const prod = Signer.generate('prod');
    const verifier = new Verifier({ [prod.keyId]: prod.publicKeyBytes() });
    const v = new Float32Array([1, 2, 3]);
    const pin = rogue.pin({ source: 'x', model: 'm', vector: v });
    const result = verifier.verify(pin);
    assert.equal(result.ok, false);
    assert.equal(result.error, 'unknown_key');
  });

  it('model mismatch is caught', () => {
    const { signer, verifier, vector } = fixture();
    const pin = signer.pin({ source: 'x', model: 'model-A', vector });
    const result = verifier.verify(pin, { expectedModel: 'model-B' });
    assert.equal(result.ok, false);
    assert.equal(result.error, 'model_mismatch');
  });

  it('rotation: multiple keys can verify', () => {
    const oldSigner = Signer.generate('2026-04');
    const newSigner = Signer.generate('2026-05');
    const verifier = new Verifier({
      [oldSigner.keyId]: oldSigner.publicKeyBytes(),
      [newSigner.keyId]: newSigner.publicKeyBytes(),
    });
    const v = new Float32Array([1, 2, 3]);
    assert.equal(verifier.verify(oldSigner.pin({ source: 'x', model: 'm', vector: v })).ok, true);
    assert.equal(verifier.verify(newSigner.pin({ source: 'x', model: 'm', vector: v })).ok, true);
  });

  it('JSON round-trip preserves the pin', () => {
    const { signer, verifier, vector } = fixture();
    const pin = signer.pin({ source: 'hello', model: 'm', vector });
    const json = pinToJSON(pin);
    const back = pinFromJSON(json);
    assert.equal(verifier.verify(back, { source: 'hello', vector }).ok, true);
    // Compact form, no whitespace.
    assert.ok(!json.includes('\n'));
    assert.ok(!json.includes(': '));
  });

  it('empty keyId is rejected', () => {
    assert.throws(() => Signer.generate(''));
  });

  it('publicKeyBytes returns 32 bytes', () => {
    const signer = Signer.generate('k');
    assert.equal(signer.publicKeyBytes().length, 32);
  });
});
