import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  chachaPolyOpen, chachaPolySeal, exportX25519PublicKeyRaw, generateX25519KeyMaterial,
  hkdfSha256, importX25519PrivateKey, importX25519PublicKeyRaw, x25519SharedSecret,
} from '../dist/e2e/node-crypto.js';
import { runNodeCryptoSelfTest } from '../dist/e2e/node-crypto-self-test.js';

const vectors = JSON.parse(readFileSync(resolve('packages/protocol/test/fixtures/e2e-v1-vectors.json'), 'utf8'));
const decode = (value) => new Uint8Array(Buffer.from(value, 'base64url'));

test('Node 22 production crypto matches the frozen X25519/HKDF/ChaChaPoly vector', () => {
  assert.ok(Number(process.versions.node.split('.')[0]) >= 22);
  assert.deepEqual(x25519SharedSecret(decode(vectors.keys.hostPrivateKeyPkcs8), decode(vectors.keys.watchPublicKey)), decode(vectors.keys.sharedSecret));
  assert.deepEqual(hkdfSha256(decode(vectors.keys.sharedSecret), decode(vectors.transcript.digest), decode(vectors.transcript.pairRootInfo)), decode(vectors.derived.pairRoot));
  for (const fixture of [vectors.event, vectors.session, vectors.reply]) {
    assert.deepEqual(chachaPolyOpen(decode(fixture.dek), decode(fixture.contentNonce), decode(fixture.ciphertext), decode(fixture.contentAAD)), decode(fixture.plaintext));
  }
  assert.equal(runNodeCryptoSelfTest(), true);
});

test('X25519 PKCS#8 and JWK raw public key round trip', () => {
  const material = generateX25519KeyMaterial();
  assert.equal(material.publicKeyRaw.byteLength, 32);
  assert.equal(importX25519PrivateKey(material.privateKeyPkcs8).asymmetricKeyType, 'x25519');
  assert.deepEqual(exportX25519PublicKeyRaw(importX25519PublicKeyRaw(material.publicKeyRaw)), material.publicKeyRaw);
});

test('ChaChaPoly rejects tampered AAD, nonce, ciphertext, and tag', () => {
  const key = decode(vectors.event.dek); const nonce = decode(vectors.event.contentNonce);
  const aad = decode(vectors.event.contentAAD); const plaintext = decode(vectors.event.plaintext);
  const sealed = chachaPolySeal(key, plaintext, aad, nonce);
  assert.deepEqual(sealed.ciphertext, decode(vectors.event.ciphertext));
  const changed = (bytes, index) => { const copy = new Uint8Array(bytes); copy[index] ^= 1; return copy; };
  for (const [candidateNonce, candidateCiphertext, candidateAad] of [
    [changed(nonce, 0), sealed.ciphertext, aad],
    [nonce, changed(sealed.ciphertext, 0), aad],
    [nonce, changed(sealed.ciphertext, sealed.ciphertext.length - 1), aad],
    [nonce, sealed.ciphertext, new Uint8Array(Buffer.concat([aad, Buffer.from('tamper')]))],
  ]) assert.throws(() => chachaPolyOpen(key, candidateNonce, candidateCiphertext, candidateAad));
});

test('generation and epoch tampering fails content-key unwrap authentication', () => {
  const wrapKey = decode(vectors.derived.bridgeToWatchWrapKey);
  assert.deepEqual(chachaPolyOpen(wrapKey, decode(vectors.event.wrapNonce), decode(vectors.event.wrappedDek), decode(vectors.event.wrapAAD)), decode(vectors.event.dek));
  const tamperedGenerationAAD = new Uint8Array(decode(vectors.event.wrapAAD));
  tamperedGenerationAAD[tamperedGenerationAAD.length - 25] ^= 1;
  assert.throws(() => chachaPolyOpen(wrapKey, decode(vectors.event.wrapNonce), decode(vectors.event.wrappedDek), tamperedGenerationAAD));
});

test('invalid and all-zero peer public keys fail closed', () => {
  assert.throws(() => importX25519PublicKeyRaw(Buffer.alloc(31)));
  assert.throws(() => x25519SharedSecret(decode(vectors.keys.hostPrivateKeyPkcs8), Buffer.alloc(32)));
});
