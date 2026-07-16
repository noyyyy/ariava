import { describe, expect, test } from 'bun:test';
import { verify, createPublicKey } from 'node:crypto';
import { base64UrlDecode, buildCanonicalRequest } from '@ariava/protocol';
import { generateHostIdentity, generateHostRotationIdentity } from '../src/identity/host-identity';

const storage = { type: 'linux-json', path: '/tmp/host-identity.json' } as const;

describe('Host identity core', () => {
  test('derives stable Ed25519 IDs and signs canonical requests', async () => {
    const generated = await generateHostIdentity(storage, '2026-07-15T00:00:00.000Z');
    expect(generated.identity.hostId).toBe(`host_${generated.identity.publicKeyFingerprint}`);
    expect(generated.identity.keyId).toBe(`key_${generated.identity.publicKeyFingerprint}`);
    const input = {
      entityType: 'host' as const,
      entityId: generated.identity.hostId,
      keyId: generated.identity.keyId,
      method: 'POST',
      path: '/v2/bridge/enroll',
      querySchema: { parameters: {} },
      contentSha256: '47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU',
      timestamp: '2026-07-15T00:00:00.000Z',
      nonce: 'AAAAAAAAAAAAAAAAAAAAAA',
    };
    const headers = await generated.identity.signer.signRequest(input);
    const spki = Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'),
      Buffer.from(base64UrlDecode(generated.identity.publicKey)),
    ]);
    expect(verify(null, buildCanonicalRequest(input).bytes, createPublicKey({ key: spki, format: 'der', type: 'spki' }), Buffer.from(base64UrlDecode(headers['x-ariava-signature'])))).toBe(true);
  });

  test('rotation keeps host ID while deriving a new key ID', async () => {
    const current = await generateHostIdentity(storage);
    const pending = await generateHostRotationIdentity(current.identity.hostId, storage);
    expect(pending.identity.hostId).toBe(current.identity.hostId);
    expect(pending.identity.keyId).not.toBe(current.identity.keyId);
  });
});
