import { afterEach, describe, expect, test } from 'bun:test';
import { createHmac, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, sign } from 'node:crypto';
import { mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  base64UrlDecode,
  base64UrlEncode,
  buildConfirmationProofBytes,
  buildEncryptionBindingBytes,
  buildLinkTranscriptBytes,
  contentSha256,
  deriveEncryptionKeyId,
  deriveEntityIdentity,
  E2E_SUITE_V1,
  type E2EConfirmationSubmissionV1,
  type E2EPendingLinkProjectionV1,
  type EncryptionKeyBindingV1,
} from '@ariava/protocol';
import { createHostEncryptionBinding, generateHostEncryptionIdentity, type HostIdentity } from '../src/identity';
import { LocalLinkKeyring } from '../src/e2e/link-keyring';
import { runHostSafetyCodeActivation } from '../src/e2e/host-safety-code-activation';

const roots: string[] = [];
afterEach(() => roots.splice(0).forEach((root) => rmSync(root, { recursive: true, force: true })));

describe('host Safety Code activation after pair', () => {
  test('prints Safety Code, waits for match, polls for Watch proof, then activates', async () => {
    const dir = join(tmpdir(), `ariava-safety-${crypto.randomUUID()}`);
    roots.push(dir);
    mkdirSync(dir, { mode: 0o700 });

    const hostEd = generateKeyPairSync('ed25519');
    const hostIdentityPublicKey = hostEd.publicKey.export({ format: 'jwk' }).x as string;
    const hostEntity = await deriveEntityIdentity('host', hostIdentityPublicKey);
    const encryptionIdentity = generateHostEncryptionIdentity(hostEntity.entityId);
    const hostIdentity = {
      identityVersion: 2 as const,
      hostId: hostEntity.entityId,
      keyId: hostEntity.keyId,
      algorithm: 'Ed25519' as const,
      publicKey: hostIdentityPublicKey,
      publicKeyFingerprint: `fp_${hostEntity.keyId.slice(4, 20)}`,
      createdAt: '2026-07-20T00:00:00.000Z',
      privateKeyStorage: { type: 'linux-json' as const, path: join(dir, 'host-identity.json') },
      signer: {
        entityId: hostEntity.entityId,
        keyId: hostEntity.keyId,
        async sign(bytes: Uint8Array) {
          return base64UrlEncode(sign(null, bytes, hostEd.privateKey));
        },
        async signRequest() {
          throw new Error('not used in this test');
        },
      },
    } satisfies HostIdentity;
    const hostBinding = await createHostEncryptionBinding(hostIdentity, encryptionIdentity);

    const watchEd = generateKeyPairSync('ed25519');
    const watchIdentityPublicKey = watchEd.publicKey.export({ format: 'jwk' }).x as string;
    const watchEntity = await deriveEntityIdentity('watch', watchIdentityPublicKey);
    const watchX = generateKeyPairSync('x25519');
    const watchPublicKey = watchX.publicKey.export({ format: 'jwk' }).x as string;
    const watchEncryptionKeyId = await deriveEncryptionKeyId(watchPublicKey);
    const watchUnsigned = {
      version: 1 as const,
      entityType: 'watch' as const,
      entityId: watchEntity.entityId,
      identityKeyId: watchEntity.keyId,
      encryptionKeyId: watchEncryptionKeyId,
      suite: E2E_SUITE_V1,
      publicKey: watchPublicKey,
      sequence: 1,
      createdAt: '2026-07-20T00:00:00.000Z',
    };
    const watchBinding: EncryptionKeyBindingV1 = {
      ...watchUnsigned,
      bindingSignature: base64UrlEncode(sign(null, buildEncryptionBindingBytes(watchUnsigned), watchEd.privateKey)),
    };

    const hostDigest = await contentSha256(buildEncryptionBindingBytes((({ bindingSignature: _, ...rest }) => rest)(hostBinding)));
    const watchDigest = await contentSha256(buildEncryptionBindingBytes(watchUnsigned));
    const linkId = 'link_test_safety_code_1';
    const linkGeneration = 1;
    const epoch = 1;
    const transcriptDigest = await contentSha256(buildLinkTranscriptBytes({
      linkId,
      hostId: hostEntity.entityId,
      watchDeviceId: watchEntity.entityId,
      linkGeneration,
      epoch,
      hostBindingDigest: hostDigest,
      watchBindingDigest: watchDigest,
    }));

    const projection: E2EPendingLinkProjectionV1 = {
      linkId,
      hostId: hostEntity.entityId,
      watchDeviceId: watchEntity.entityId,
      linkGeneration,
      epoch,
      hostBinding,
      hostIdentityPublicKey,
      watchBinding,
      watchIdentityPublicKey,
      transcriptDigest,
      confirmationExpiresAt: new Date(Date.now() + 300_000).toISOString(),
      state: 'pending_confirmation',
    };

    const shared = new Uint8Array(diffieHellman({
      privateKey: createPrivateKey({ key: Buffer.from(encryptionIdentity.privateKeyPkcs8), type: 'pkcs8', format: 'der' }),
      publicKey: createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: watchPublicKey }, format: 'jwk' }),
    }));
    const confirmationKey = new Uint8Array(hkdfSync(
      'sha256',
      Buffer.from(shared),
      Buffer.from(base64UrlDecode(transcriptDigest, 32, 'transcript')),
      Buffer.from('ariava:e2e:v1:confirmation'),
      32,
    ));
    const watchProof = base64UrlEncode(
      createHmac('sha256', confirmationKey).update(buildConfirmationProofBytes('watch', transcriptDigest)).digest(),
    );

    let confirmCalls = 0;
    const transport = {
      async confirmLink(_linkId: string, request: E2EConfirmationSubmissionV1) {
        confirmCalls += 1;
        expect(request.linkId).toBe(linkId);
        if (confirmCalls === 1) return { state: 'pending_confirmation' };
        return {
          state: 'confirmations_complete',
          peerConfirmationProof: {
            linkId,
            linkGeneration,
            epoch,
            transcriptDigest,
            confirmationProof: watchProof,
          },
        };
      },
      async activateLink(id: string, request: { peerRole: string; peerProofDigest: string }) {
        expect(id).toBe(linkId);
        expect(request.peerRole).toBe('watch');
        expect(request.peerProofDigest).toBe(await contentSha256(new TextEncoder().encode(watchProof)));
        return { state: 'host_activated' };
      },
    };

    const lines: string[] = [];
    const keyring = new LocalLinkKeyring(join(dir, 'pins.json'), encryptionIdentity);
    let now = 0;
    const outcome = await runHostSafetyCodeActivation({
      projection,
      hostIdentity: encryptionIdentity,
      hostBinding,
      keyring,
      transport,
      write: (line) => lines.push(line),
      confirmMatch: async () => true,
      sleep: async () => { now += 10; },
      now: () => now,
      peerWaitMs: 1_000,
      peerPollMs: 1,
    });

    expect(outcome).toBe('activated');
    expect(confirmCalls).toBe(2);
    expect(lines.some((line) => line.startsWith('Safety Code:'))).toBe(true);
    expect(lines.join('\n')).toContain('Pairing complete');
    expect(keyring.listActive()).toHaveLength(1);
    expect(keyring.listActive()[0]?.watchDeviceId).toBe(watchEntity.entityId);
  });

  test('skips when pair response has no E2E projection', async () => {
    const dir = join(tmpdir(), `ariava-safety-skip-${crypto.randomUUID()}`);
    roots.push(dir);
    mkdirSync(dir, { mode: 0o700 });
    const host = generateHostEncryptionIdentity(`host_${'H'.repeat(43)}`);
    const keyring = new LocalLinkKeyring(join(dir, 'pins.json'), host);
    const lines: string[] = [];
    const outcome = await runHostSafetyCodeActivation({
      projection: undefined,
      alreadyPaired: false,
      hostIdentity: host,
      hostBinding: {
        version: 1,
        entityType: 'host',
        entityId: host.hostId,
        identityKeyId: `key_${'I'.repeat(43)}`,
        encryptionKeyId: host.encryptionKeyId,
        suite: E2E_SUITE_V1,
        publicKey: host.publicKey,
        sequence: 1,
        createdAt: host.createdAt,
        bindingSignature: base64UrlEncode(new Uint8Array(64)),
      },
      keyring,
      transport: {
        confirmLink: async () => ({ state: 'pending_confirmation' }),
        activateLink: async () => ({ state: 'host_activated' }),
      },
      write: (line) => lines.push(line),
      confirmMatch: async () => true,
    });
    expect(outcome).toBe('skipped-no-e2e');
    expect(lines.join('\n')).toContain('Safety Code activation was skipped');
  });
});
