import { describe, expect, test } from 'bun:test';
import fixture from './fixtures/ed25519-request-vectors.json';
const vector = fixture.vectors[0];
import {
  IDENTITY_ALGORITHM,
  deriveEntityIdentity,
  derivePublicKeyFingerprint,
  validateHostEnrollmentRequest,
} from '../src';

describe('v2 Ed25519 identity foundation', () => {
  test('derives fixed Host, Watch, key IDs from the raw public key', async () => {
    expect(await derivePublicKeyFingerprint(fixture.publicKey)).toBe(fixture.fingerprint);
    expect(await deriveEntityIdentity('host', fixture.publicKey)).toEqual({
      fingerprint: fixture.fingerprint,
      entityId: vector.entityId,
      keyId: vector.keyId,
    });
    expect(await deriveEntityIdentity('watch', fixture.publicKey)).toEqual({
      fingerprint: fixture.fingerprint,
      entityId: `watch_${fixture.fingerprint}`,
      keyId: vector.keyId,
    });
  });

  test('rejects padded or wrong-sized public keys', async () => {
    await expect(derivePublicKeyFingerprint(`${fixture.publicKey}=`)).rejects.toThrow('unpadded base64url');
    await expect(derivePublicKeyFingerprint('AA')).rejects.toThrow('exactly 32 bytes');
  });

  test('cryptographically validates ownerless macOS and Linux enrollment bodies', async () => {
    for (const platform of ['macos', 'linux'] as const) {
      const result = await validateHostEnrollmentRequest({
        hostId: vector.entityId,
        keyId: vector.keyId,
        algorithm: IDENTITY_ALGORITHM,
        publicKey: fixture.publicKey,
        hostName: 'Build Host',
        platform,
        bridgeVersion: '0.2.0',
      });
      expect(result.success).toBe(true);
      expect(result.value?.platform).toBe(platform);
    }
  });

  test('rejects v1 owner/token fields and invalid public enrollment values', async () => {
    const result = await validateHostEnrollmentRequest({
      hostId: '',
      keyId: vector.keyId,
      algorithm: IDENTITY_ALGORITHM,
      publicKey: fixture.publicKey,
      hostName: '',
      platform: 'windows',
      bridgeVersion: '0.2.0',
      ownerUserId: 'demo-user',
      hostAuthToken: 'secret',
    });
    expect(result.success).toBe(false);
    expect(result.issues.join('\n')).toContain('ownerUserId is unsupported');
    expect(result.issues.join('\n')).toContain('hostAuthToken is unsupported');
    expect(result.issues.join('\n')).toContain('platform must be macos or linux');
  });


  test('binds both submitted IDs to the raw public-key fingerprint', async () => {
    const wrong = 'A'.repeat(43);
    const result = await validateHostEnrollmentRequest({
      hostId: `host_${wrong}`,
      keyId: `key_${wrong}`,
      algorithm: IDENTITY_ALGORITHM,
      publicKey: fixture.publicKey,
      hostName: 'Build Host',
      platform: 'linux',
      bridgeVersion: '0.2.0',
    });
    expect(result.success).toBe(false);
    expect(result.issues.join('\n')).toContain('hostId does not match publicKey fingerprint');
    expect(result.issues.join('\n')).toContain('keyId does not match publicKey fingerprint');
  });

  test('rejects inherited and accessor enrollment fields', async () => {
    const inherited = Object.create({ hostId: vector.entityId }) as Record<string, unknown>;
    Object.assign(inherited, {
      keyId: vector.keyId, algorithm: IDENTITY_ALGORITHM, publicKey: fixture.publicKey, hostName: 'Host', platform: 'macos', bridgeVersion: '0.2.0',
    });
    expect((await validateHostEnrollmentRequest(inherited)).issues).toContain('hostId is required');

    const accessor = {
      hostId: vector.entityId, keyId: vector.keyId, algorithm: IDENTITY_ALGORITHM, publicKey: fixture.publicKey, hostName: 'Host', platform: 'macos',
      get bridgeVersion() { return '0.2.0'; },
    };
    expect((await validateHostEnrollmentRequest(accessor)).issues).toContain('bridgeVersion must be an own data property');
  });
});
