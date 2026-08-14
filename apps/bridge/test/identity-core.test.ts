import { describe, expect, test } from 'bun:test';
import { verify, createPublicKey } from 'node:crypto';
import { base64UrlDecode, buildCanonicalRequest } from '@ariava/protocol';
import { generateHostIdentity } from '../src/identity/host-identity';

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

  test('import rejects every noncanonical host or key metadata override', async () => {
    const generated = await generateHostIdentity(storage);
    const { getHostIdentityPrivateKey, importHostIdentityPrivateKey } = await import('../src/identity/host-identity');
    const privateKey = getHostIdentityPrivateKey(generated.identity);
    await expect(importHostIdentityPrivateKey(privateKey, storage, generated.identity.createdAt, {
      ...generated.identity, hostId: `host_${'A'.repeat(43)}`,
    })).rejects.toMatchObject({ code: 'ERR_IDENTITY_INVALID' });
    await expect(importHostIdentityPrivateKey(privateKey, storage, generated.identity.createdAt, {
      ...generated.identity, keyId: `key_${'B'.repeat(43)}`,
    })).rejects.toMatchObject({ code: 'ERR_IDENTITY_INVALID' });
  });

  test('reset revoke accepts only exact conclusive outcomes for the canonical key', async () => {
    const generated = await generateHostIdentity(storage);
    const { revokeHostIdentityForReset } = await import('../src/identity/manager');
    const originalFetch = globalThis.fetch;
    const revokedAt = '2026-08-12T00:00:00.000Z';
    try {
      globalThis.fetch = (async () => Response.json({
        entityId: generated.identity.hostId, status: 'revoked', revokedAt,
      })) as typeof fetch;
      expect(await revokeHostIdentityForReset(generated.identity, 'https://relay.test')).toBe('revoked');

      for (const body of [
        { code: 'identity_revoked' },
        { code: 'unknown_or_revoked_key', entityId: generated.identity.hostId, keyId: generated.identity.keyId },
      ]) {
        globalThis.fetch = (async () => Response.json(body, { status: 401 })) as typeof fetch;
        expect(await revokeHostIdentityForReset(generated.identity, 'https://relay.test')).toBe('identity-already-revoked');
      }

      for (const response of [
        () => Response.json({ entityId: generated.identity.hostId, status: 'revoked', revokedAt, extra: true }),
        () => Response.json({ entityId: `host_${'Z'.repeat(43)}`, status: 'revoked', revokedAt }),
        () => Response.json({ entityId: generated.identity.hostId, status: 'revoked', revokedAt: 'not-canonical' }),
        () => Response.json({ code: 'identity_revoked', extra: true }, { status: 401 }),
        () => Response.json({ code: 'unknown_or_revoked_key', entityId: `host_${'Z'.repeat(43)}`, keyId: generated.identity.keyId }, { status: 401 }),
        () => Response.json({ code: 'unknown_or_revoked_key', entityId: generated.identity.hostId, keyId: `key_${'Z'.repeat(43)}` }, { status: 401 }),
        () => Response.json({ code: 'unknown_or_revoked_key', entityId: generated.identity.hostId }, { status: 401 }),
        () => Response.json({ error: 'server unavailable' }, { status: 503 }),
        () => new Response('{malformed', { headers: { 'content-type': 'application/json' } }),
      ]) {
        globalThis.fetch = (async () => response()) as typeof fetch;
        await expect(revokeHostIdentityForReset(generated.identity, 'https://relay.test')).rejects.toBeDefined();
      }

      globalThis.fetch = (async () => { throw new TypeError('network unavailable'); }) as typeof fetch;
      await expect(revokeHostIdentityForReset(generated.identity, 'https://relay.test')).rejects.toBeInstanceOf(TypeError);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('enrollment accepts only an exact active projection for the canonical Host', async () => {
    const generated = await generateHostIdentity(storage);
    const { enrollCurrentIdentity } = await import('../src/identity/manager');
    const originalFetch = globalThis.fetch;
    const metadata = { hostName: 'Host', platform: 'linux' as const, bridgeVersion: '1.0.0' };
    const host = {
      hostId: generated.identity.hostId, ...metadata,
      registeredAt: '2026-08-12T00:00:00.000Z', lastSeenAt: '2026-08-12T00:00:01.000Z',
      bridgeStatus: 'online', status: 'active',
    };
    try {
      globalThis.fetch = (async () => Response.json({ host })) as typeof fetch;
      await expect(enrollCurrentIdentity('https://relay.test', generated.identity, metadata)).resolves.toBeUndefined();

      for (const response of [
        { host, extra: true },
        { host: { ...host, extra: true } },
        { host: { ...host, hostId: `host_${'Z'.repeat(43)}` } },
        { host: { ...host, hostName: 'Other Host' } },
        { host: { ...host, platform: 'macos' } },
        { host: { ...host, bridgeVersion: '2.0.0' } },
        { host: { ...host, status: 'revoked' } },
        { host: { ...host, registeredAt: 'not-canonical' } },
        { host: { ...host, bridgeStatus: 'unknown' } },
        { host: Object.fromEntries(Object.entries(host).filter(([key]) => key !== 'status')) },
      ]) {
        globalThis.fetch = (async () => Response.json(response)) as typeof fetch;
        await expect(enrollCurrentIdentity('https://relay.test', generated.identity, metadata)).rejects.toBeDefined();
      }

      const mismatchedKey = { ...generated.identity, keyId: `key_${'Z'.repeat(43)}` };
      let fetchCalls = 0;
      globalThis.fetch = (async () => { fetchCalls += 1; return Response.json({ host }); }) as typeof fetch;
      await expect(enrollCurrentIdentity('https://relay.test', mismatchedKey, metadata))
        .rejects.toMatchObject({ code: 'ERR_IDENTITY_INVALID' });
      expect(fetchCalls).toBe(0);

      globalThis.fetch = (async () => Response.json({ error: 'server unavailable' }, { status: 503 })) as typeof fetch;
      await expect(enrollCurrentIdentity('https://relay.test', generated.identity, metadata)).rejects.toMatchObject({ status: 503 });
      globalThis.fetch = (async () => { throw new TypeError('network unavailable'); }) as typeof fetch;
      await expect(enrollCurrentIdentity('https://relay.test', generated.identity, metadata)).rejects.toBeInstanceOf(TypeError);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
