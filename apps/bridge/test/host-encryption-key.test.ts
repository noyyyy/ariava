import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, test } from 'bun:test';
import { generateHostIdentity } from '../src/identity/host-identity';
import { createHostEncryptionBinding, generateHostEncryptionIdentity, importHostEncryptionPrivateKey } from '../src/identity/host-encryption-key';
import { LinuxEncryptionKeyStore } from '../src/identity/linux-encryption-key-store';
import { createRuntimeHostEncryptionIdentityStore, hostEncryptionIdentityPath } from '../src/identity/runtime-store';
import { deriveEncryptionKeyId } from '@ariava/protocol';

const hostId = `host_${'A'.repeat(43)}`;

describe('Host encryption identity', () => {
  test('generates independent X25519 JWK/raw and PKCS#8 material', () => {
    const identity = generateHostEncryptionIdentity(hostId, 1, '2026-07-20T00:00:00.000Z');
    expect(identity.publicKey).toHaveLength(43);
    expect(identity.encryptionKeyId).toMatch(/^ekey_[A-Za-z0-9_-]{43}$/u);
    expect(importHostEncryptionPrivateKey(identity).asymmetricKeyType).toBe('x25519');
  });

  test('persists only hardened PKCS#8 evidence and fails on Host mismatch', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'ariava-e2e-')), 'encryption.json');
    const store = new LinuxEncryptionKeyStore(path);
    const first = store.loadOrCreate(hostId);
    expect(store.load()).toEqual(first);
    expect(readFileSync(path, 'utf8')).not.toContain('BEGIN PRIVATE KEY');
    expect(() => store.loadOrCreate(`host_${'B'.repeat(43)}`)).toThrow(/another Host/);
  });

  test('derives and validates the key ID and runtime store lifecycle', async () => {
    const root = mkdtempSync(join(tmpdir(), 'ariava-e2e-runtime-'));
    const identityPath = join(root, 'identity.json');
    const store = createRuntimeHostEncryptionIdentityStore(identityPath, 'linux');
    const first = store.loadOrCreate(hostId);
    expect(first.encryptionKeyId).toBe(await deriveEncryptionKeyId(first.publicKey));
    expect(hostEncryptionIdentityPath(identityPath)).toBe(`${identityPath}.e2e.json`);
    const reset = store.replaceForReset(`host_${'B'.repeat(43)}`);
    expect(reset.hostId).not.toBe(first.hostId);
    expect(reset.encryptionKeyId).not.toBe(first.encryptionKeyId);
    const record = JSON.parse(readFileSync(hostEncryptionIdentityPath(identityPath), 'utf8'));
    record.encryptionKeyId = `ekey_${'Z'.repeat(43)}`;
    writeFileSync(hostEncryptionIdentityPath(identityPath), JSON.stringify(record), { mode: 0o600 });
    expect(() => store.load()).toThrow(/key ID/);
  });

  test('signs a binding with the independent Ed25519 identity', async () => {
    const material = await generateHostIdentity({ type: 'linux-json', path: '/tmp/identity.json' }, '2026-07-20T00:00:00.000Z');
    const encryption = generateHostEncryptionIdentity(material.identity.hostId, 1, '2026-07-20T00:00:00.000Z');
    const binding = await createHostEncryptionBinding(material.identity, encryption);
    expect(binding.entityId).toBe(material.identity.hostId);
    expect(binding.identityKeyId).toBe(material.identity.keyId);
    expect(binding.bindingSignature).toHaveLength(86);
  });
});
