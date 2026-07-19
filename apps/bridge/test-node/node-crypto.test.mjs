import assert from 'node:assert/strict';
import { createHmac, createPrivateKey, createPublicKey, verify } from 'node:crypto';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  chachaPolyOpen, chachaPolySeal, exportX25519PublicKeyRaw, generateX25519KeyMaterial,
  hkdfSha256, importX25519PrivateKey, importX25519PublicKeyRaw, x25519SharedSecret,
} from '../dist/e2e/node-crypto.js';
import { runNodeCryptoSelfTest } from '../dist/e2e/node-crypto-self-test.js';
import {
  buildConfirmationProofBytes, buildEncryptionBindingBytes, buildWrapAAD,
} from '../../../packages/protocol/dist/index.js';

const vectors = JSON.parse(readFileSync(resolve('packages/protocol/test/fixtures/e2e-v1-vectors.json'), 'utf8'));
const decode = (value) => new Uint8Array(Buffer.from(value, 'base64url'));

test('Node 22 production crypto matches the frozen X25519/HKDF/ChaChaPoly vector', () => {
  assert.ok(Number(process.versions.node.split('.')[0]) >= 22);
  assert.deepEqual(x25519SharedSecret(decode(vectors.keys.hostPrivateKeyPkcs8), decode(vectors.keys.watchPublicKey)), decode(vectors.keys.sharedSecret));
  const digest = decode(vectors.transcript.digest);
  const pairRoot = hkdfSha256(decode(vectors.keys.sharedSecret), digest, decode(vectors.transcript.pairRootInfo));
  assert.deepEqual(pairRoot, decode(vectors.derived.pairRoot));
  const utf8 = (value) => new TextEncoder().encode(value);
  const bridgeToWatch = hkdfSha256(pairRoot, digest, utf8('ariava:e2e:v1:wrap:bridge-to-watch'));
  const watchToBridge = hkdfSha256(pairRoot, digest, utf8('ariava:e2e:v1:wrap:watch-to-bridge'));
  const confirmationKey = hkdfSha256(decode(vectors.keys.sharedSecret), digest, utf8('ariava:e2e:v1:confirmation'));
  assert.deepEqual(bridgeToWatch, decode(vectors.derived.bridgeToWatchWrapKey));
  assert.deepEqual(watchToBridge, decode(vectors.derived.watchToBridgeWrapKey));
  assert.deepEqual(confirmationKey, decode(vectors.derived.confirmationKey));
  for (const [role, expected] of [['host', vectors.derived.hostProof], ['watch', vectors.derived.watchProof]]) {
    assert.deepEqual(new Uint8Array(createHmac('sha256', confirmationKey).update(buildConfirmationProofBytes(role, vectors.transcript.digest)).digest()), decode(expected));
  }
  assert.deepEqual(new Uint8Array(createHmac('sha256', confirmationKey).update(decode(vectors.transcript.safetyCodeInput)).digest()), decode(vectors.derived.safetyCodeHmac));
  for (const fixture of [vectors.event, vectors.session, vectors.reply]) {
    assert.deepEqual(chachaPolyOpen(decode(fixture.dek), decode(fixture.contentNonce), decode(fixture.ciphertext), decode(fixture.contentAAD)), decode(fixture.plaintext));
  }
  assert.equal(runNodeCryptoSelfTest(), true);
});

test('frozen binding canonical bytes and Ed25519 signature verify', () => {
  const { canonicalBytes, bindingSignature, ...binding } = vectors.binding;
  const bytes = buildEncryptionBindingBytes(binding);
  assert.deepEqual(bytes, decode(canonicalBytes));
  const seed = Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex');
  const identityKey = createPrivateKeyFromSeed(seed);
  assert.equal(verify(null, bytes, identityKey, decode(bindingSignature)), true);
  assert.equal(verify(null, buildEncryptionBindingBytes({ ...binding, sequence: 2 }), identityKey, decode(bindingSignature)), false);
});

test('X25519 PKCS#8 and JWK raw public key round trip', () => {
  const material = generateX25519KeyMaterial();
  assert.equal(material.publicKeyRaw.byteLength, 32);
  assert.equal(importX25519PrivateKey(material.privateKeyPkcs8).asymmetricKeyType, 'x25519');
  assert.deepEqual(exportX25519PublicKeyRaw(importX25519PublicKeyRaw(material.publicKeyRaw)), material.publicKeyRaw);
});

test('fixture PKCS#8 private keys correspond to their frozen raw public keys', () => {
  for (const [privateValue, publicValue] of [
    [vectors.keys.hostPrivateKeyPkcs8, vectors.keys.hostPublicKey],
    [vectors.keys.watchPrivateKeyPkcs8, vectors.keys.watchPublicKey],
  ]) {
    assert.deepEqual(exportX25519PublicKeyRaw(createPublicKey(importX25519PrivateKey(decode(privateValue)))), decode(publicValue));
  }
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

test('generation and epoch tampering specifically fail content-key unwrap authentication', () => {
  const wrapKey = decode(vectors.derived.bridgeToWatchWrapKey);
  const baseline = {
    direction: 'bridge-to-watch', linkId: vectors.link.linkId, linkGeneration: vectors.link.linkGeneration,
    epoch: vectors.link.epoch, hostId: vectors.link.hostId, watchDeviceId: vectors.link.watchDeviceId,
    senderEncryptionKeyId: 'ekey_host_vector', recipientEncryptionKeyId: 'ekey_watch_vector',
    contentId: vectors.event.contentId, payloadKind: 'event-content-v1',
  };
  assert.deepEqual(buildWrapAAD(baseline), decode(vectors.event.wrapAAD));
  assert.deepEqual(chachaPolyOpen(wrapKey, decode(vectors.event.wrapNonce), decode(vectors.event.wrappedDek), buildWrapAAD(baseline)), decode(vectors.event.dek));
  for (const tampered of [
    { ...baseline, linkGeneration: baseline.linkGeneration + 1 },
    { ...baseline, epoch: baseline.epoch + 1 },
  ]) {
    assert.throws(() => chachaPolyOpen(wrapKey, decode(vectors.event.wrapNonce), decode(vectors.event.wrappedDek), buildWrapAAD(tampered)));
  }
});

test('invalid and all-zero peer public keys fail closed', () => {
  assert.throws(() => importX25519PublicKeyRaw(Buffer.alloc(31)));
  assert.throws(() => x25519SharedSecret(decode(vectors.keys.hostPrivateKeyPkcs8), Buffer.alloc(32)));
});

test('HKDF rejects non-32-byte IKM', () => {
  assert.throws(() => hkdfSha256(Buffer.alloc(31), decode(vectors.transcript.digest), decode(vectors.transcript.pairRootInfo)), /IKM/);
  assert.throws(() => hkdfSha256(Buffer.alloc(33), decode(vectors.transcript.digest), decode(vectors.transcript.pairRootInfo)), /IKM/);
});

function createPrivateKeyFromSeed(seed) {
  return createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
    type: 'pkcs8',
    format: 'der',
  });
}
