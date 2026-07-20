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
