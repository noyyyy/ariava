import { afterEach, describe, expect, test } from 'bun:test';
import { mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { base64UrlEncode, buildEncryptionBindingBytes, contentSha256, deriveEntityIdentity, E2E_SUITE_V1, type EncryptionKeyBindingV1 } from '@ariava/protocol';
import { generateKeyPairSync, sign } from 'node:crypto';
import { generateHostEncryptionIdentity } from '../src/identity';
import { LocalLinkKeyring, prepareHostActivation, verifyBindingWithIdentityPublicKey } from '../src/e2e/link-keyring';

const roots: string[] = [];
afterEach(() => roots.splice(0).forEach((root) => rmSync(root, { recursive: true, force: true })));

describe('verified local E2E pins', () => {
  test('persists active pin and rejects generation rollback', async () => {
    const dir = join(tmpdir(), `ariava-keyring-${crypto.randomUUID()}`); roots.push(dir); mkdirSync(dir, { mode: 0o700 });
    const host = generateHostEncryptionIdentity(`host_${'H'.repeat(43)}`);
    const binding = fakeBinding(`watch_${'W'.repeat(43)}`, 2);
    const keyring = new LocalLinkKeyring(join(dir, 'pins.json'), host);
    keyring.persistActive({ version: 1, status: 'active', linkId: 'link-2', hostId: host.hostId, watchDeviceId: `watch_${'W'.repeat(43)}`,
      linkGeneration: 2, epoch: 1, transcriptDigest: base64UrlEncode(new Uint8Array(32)), watchBinding: binding,
      watchBindingDigest: base64UrlEncode(new Uint8Array(32)), peerProofDigest: base64UrlEncode(new Uint8Array(32)), activatedAt: new Date().toISOString() });
    expect(new LocalLinkKeyring(join(dir, 'pins.json'), host).listActive()).toHaveLength(1);
    expect(() => keyring.persistActive({ ...keyring.listActive()[0]!, linkId: 'old', linkGeneration: 1 })).toThrow('rollback');
    const next = { ...keyring.listActive()[0]!, linkId: 'link-3', epoch: 2, activatedAt: '2026-07-20T00:01:00.000Z' };
    keyring.persistActive(next);
    expect(keyring.listRetiring()).toHaveLength(1);
    const old = keyring.listRetiring()[0]!;
    expect(await keyring.authorize({ commandId: 'cmd', hostId: host.hostId, sessionId: 's', type: 'interrupt', payload: {},
      issuedAt: '2026-07-19T00:00:00.000Z', expiresAt: new Date(Date.now() + 60_000).toISOString(), nonce: 'n',
      watchDeviceId: old.watchDeviceId, linkId: old.linkId, linkGeneration: old.linkGeneration, epoch: old.epoch })).toBe(true);
    expect(await keyring.authorize({ commandId: 'cmd2', hostId: host.hostId, sessionId: 's', type: 'interrupt', payload: {},
      issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60_000).toISOString(), nonce: 'n',
      watchDeviceId: old.watchDeviceId, linkId: old.linkId, linkGeneration: old.linkGeneration, epoch: old.epoch })).toBe(false);
  });

  test('retains a retiring pin through the maximum content/command reference and prunes only after both expire', () => {
    const dir = join(tmpdir(), `ariava-retention-${crypto.randomUUID()}`); roots.push(dir); mkdirSync(dir, { mode: 0o700 });
    const host = generateHostEncryptionIdentity(`host_${'H'.repeat(43)}`);
    const keyring = new LocalLinkKeyring(join(dir, 'pins.json'), host);
    const watchDeviceId = `watch_${'W'.repeat(43)}`;
    const first = { version: 1 as const, status: 'active' as const, linkId: 'link-retained', hostId: host.hostId, watchDeviceId,
      linkGeneration: 1, epoch: 1, transcriptDigest: base64UrlEncode(new Uint8Array(32)), watchBinding: fakeBinding(watchDeviceId, 1),
      watchBindingDigest: base64UrlEncode(new Uint8Array(32)), peerProofDigest: base64UrlEncode(new Uint8Array(32)), activatedAt: '2026-07-20T00:00:00.000Z' };
    keyring.persistActive(first);
    keyring.persistActive({ ...first, linkId: 'link-current', epoch: 2, activatedAt: '2026-07-20T00:01:00.000Z' });
    const referenceKey = 'link-retained:1:1';
    expect(keyring.pruneRetiring({ contentRetainedThrough: { [referenceKey]: '2026-07-20T00:10:00.000Z' }, commandRetainedThrough: { [referenceKey]: '2026-07-20T00:20:00.000Z' } }, '2026-07-20T00:15:00.000Z')).toEqual([]);
    expect(keyring.listRetiring()).toHaveLength(1);
    expect(keyring.pruneRetiring({ contentRetainedThrough: { [referenceKey]: '2026-07-20T00:10:00.000Z' }, commandRetainedThrough: { [referenceKey]: '2026-07-20T00:20:00.000Z' } }, '2026-07-20T00:20:00.001Z')).toHaveLength(1);
    expect(keyring.listRetiring()).toEqual([]);
    expect(keyring.referencedHostEncryptionKeyIds()).toEqual(new Set([host.encryptionKeyId]));
  });

  test('scopes unlink revocation to the requested generation and compromise revokes every retained pin immediately', () => {
    const dir = join(tmpdir(), `ariava-revoke-${crypto.randomUUID()}`); roots.push(dir); mkdirSync(dir, { mode: 0o700 });
    const host = generateHostEncryptionIdentity(`host_${'H'.repeat(43)}`);
    const keyring = new LocalLinkKeyring(join(dir, 'pins.json'), host);
    const watchDeviceId = `watch_${'W'.repeat(43)}`;
    const base = { version: 1 as const, status: 'active' as const, hostId: host.hostId, watchDeviceId, epoch: 1,
      transcriptDigest: base64UrlEncode(new Uint8Array(32)), watchBinding: fakeBinding(watchDeviceId, 1),
      watchBindingDigest: base64UrlEncode(new Uint8Array(32)), peerProofDigest: base64UrlEncode(new Uint8Array(32)), activatedAt: '2026-07-20T00:00:00.000Z' };
    keyring.persistActive({ ...base, linkId: 'generation-1', linkGeneration: 1 });
    keyring.persistActive({ ...base, linkId: 'generation-2', linkGeneration: 2 });
    keyring.revokeWatch(watchDeviceId, 1);
    expect(keyring.getUsable('generation-1', 1, 1)).toBeUndefined();
    expect(keyring.getUsable('generation-2', 2, 1)).toBeDefined();
    expect(keyring.revokeCompromisedEncryptionKey(host.encryptionKeyId)).toBe(1);
    expect(keyring.listActive()).toEqual([]);
    expect(keyring.listRetiring()).toEqual([]);
    expect(keyring.referencedHostEncryptionKeyIds()).toEqual(new Set());
  });

  test('binding verifier checks Ed25519 signature rather than Relay state', async () => {
    const pair = generateKeyPairSync('ed25519');
    const jwk = pair.publicKey.export({ format: 'jwk' });
    const raw = jwk.x!; const derived = await deriveEntityIdentity('watch', raw);
    const unsigned = { version: 1 as const, entityType: 'watch' as const, entityId: derived.entityId, identityKeyId: derived.keyId,
      encryptionKeyId: fakeBinding(derived.entityId, 1).encryptionKeyId, suite: E2E_SUITE_V1,
      publicKey: fakeBinding(derived.entityId, 1).publicKey, sequence: 1, createdAt: '2026-07-20T00:00:00.000Z' };
    const binding = { ...unsigned, bindingSignature: base64UrlEncode(sign(null, buildEncryptionBindingBytes(unsigned), pair.privateKey)) };
    expect(verifyBindingWithIdentityPublicKey(binding, raw)).toBe(true);
    expect(verifyBindingWithIdentityPublicKey({ ...binding, sequence: 2 }, raw)).toBe(false);
  });
});

function fakeBinding(watchDeviceId: string, sequence: number): EncryptionKeyBindingV1 {
  const pair = generateKeyPairSync('x25519'); const publicKey = pair.publicKey.export({ format: 'jwk' }).x!;
  return { version: 1, entityType: 'watch', entityId: watchDeviceId, identityKeyId: `key_${'A'.repeat(43)}`,
    encryptionKeyId: `ekey_${'B'.repeat(43)}`, suite: E2E_SUITE_V1, publicKey, sequence,
    createdAt: '2026-07-20T00:00:00.000Z', bindingSignature: base64UrlEncode(new Uint8Array(64)) };
}
