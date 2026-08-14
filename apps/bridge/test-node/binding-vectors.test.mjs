import { createHash, createPublicKey, verify } from 'node:crypto';
import test from 'node:test';
import assert from 'node:assert/strict';
import vectors from '../../../packages/protocol/test/fixtures/e2e-v2-vectors.json' with { type: 'json' };
import {
  base64UrlDecode,
  base64UrlEncode,
  buildEncryptionBindingBytes,
  buildLinkTranscriptBytes,
  deriveEncryptionKeyId,
  deriveEntityIdentity,
} from '../../../packages/protocol/dist/index.js';

function mutateBase64Url(value) {
  const bytes = base64UrlDecode(value);
  bytes[Math.floor(bytes.byteLength / 2)] ^= 1;
  return base64UrlEncode(bytes);
}

for (const role of ['host', 'watch']) {
  test(`${role} v2 binding freezes full identity, canonical bytes, signature, and tamper rejection`, async () => {
    const binding = vectors.bindings[role];
    const identityPublicKey = vectors.keys[`${role}IdentityPublicKey`];
    const { canonicalBytes, bindingSignature, ...unsigned } = binding;
    const canonical = buildEncryptionBindingBytes(unsigned);
    const identity = await deriveEntityIdentity(role, identityPublicKey);

    assert.equal(identity.entityId, binding.entityId);
    assert.equal(identity.keyId, binding.identityKeyId);
    assert.equal(identity.fingerprint, binding.entityId.slice(role.length + 1));
    assert.equal(await deriveEncryptionKeyId(binding.publicKey), binding.encryptionKeyId);
    assert.equal(base64UrlEncode(canonical), canonicalBytes);

    const publicKey = createPublicKey({
      key: { kty: 'OKP', crv: 'Ed25519', x: identityPublicKey },
      format: 'jwk',
    });
    assert.equal(verify(null, canonical, publicKey, base64UrlDecode(bindingSignature)), true);
    assert.equal(verify(
      null,
      buildEncryptionBindingBytes({ ...unsigned, sequence: unsigned.sequence + 1 }),
      publicKey,
      base64UrlDecode(bindingSignature),
    ), false);
    assert.equal(verify(null, canonical, publicKey, base64UrlDecode(mutateBase64Url(bindingSignature))), false);
  });
}

test('v2 transcript binds both complete binding digests and rejects either tamper', () => {
  const bindingDigests = {};
  for (const role of ['host', 'watch']) {
    const { canonicalBytes: _, bindingSignature: __, ...unsigned } = vectors.bindings[role];
    bindingDigests[`${role}BindingDigest`] = createHash('sha256')
      .update(buildEncryptionBindingBytes(unsigned)).digest('base64url');
    assert.equal(bindingDigests[`${role}BindingDigest`], vectors.transcript[`${role}BindingDigest`]);
  }
  const transcript = buildLinkTranscriptBytes({ ...vectors.link, ...bindingDigests });
  assert.equal(base64UrlEncode(transcript), vectors.transcript.bytes);
  assert.equal(createHash('sha256').update(transcript).digest('base64url'), vectors.transcript.digest);

  for (const role of ['host', 'watch']) {
    const tampered = {
      ...bindingDigests,
      [`${role}BindingDigest`]: mutateBase64Url(bindingDigests[`${role}BindingDigest`]),
    };
    const tamperedTranscript = buildLinkTranscriptBytes({ ...vectors.link, ...tampered });
    assert.notEqual(base64UrlEncode(tamperedTranscript), vectors.transcript.bytes);
    assert.notEqual(createHash('sha256').update(tamperedTranscript).digest('base64url'), vectors.transcript.digest);
  }
});
