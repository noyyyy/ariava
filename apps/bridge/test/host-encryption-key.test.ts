import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, spyOn, test } from 'bun:test';
import * as crypto from 'node:crypto';
import { generateHostIdentity } from '../src/identity/host-identity';
import { createHostEncryptionBinding, generateHostEncryptionIdentity, importHostEncryptionPrivateKey } from '../src/identity/host-encryption-key';
import { LinuxEncryptionKeyStore } from '../src/identity/linux-encryption-key-store';
import { createRuntimeHostEncryptionIdentityStore, hostEncryptionIdentityPath } from '../src/identity/runtime-store';
import { MacOSEncryptionKeyStore } from '../src/identity/macos-encryption-key-store';
import { FakeKeychain } from './fixtures/fake-keychain';
import { deriveEncryptionKeyId } from '@ariava/protocol';

const hostId = `host_${'A'.repeat(43)}`;

describe('Host encryption identity', () => {
  test('generates independent X25519 JWK/raw and PKCS#8 material', () => {
    const identity = generateHostEncryptionIdentity(hostId, 1, '2026-07-20T00:00:00.000Z');
    expect(identity.publicKey).toHaveLength(43);
    expect(identity.encryptionKeyId).toMatch(/^ekey_[A-Za-z0-9_-]{43}$/u);
    expect(importHostEncryptionPrivateKey(identity).asymmetricKeyType).toBe('x25519');
  });

  test('rejects malformed Host IDs before X25519 generation', () => {
    const generateKeyPair = spyOn(crypto, 'generateKeyPairSync');
    try {
      for (const malformedHostId of ['host-invalid', `watch_${'A'.repeat(43)}`, `host_${'A'.repeat(42)}`, `host_${'A'.repeat(44)}`]) {
        expect(() => generateHostEncryptionIdentity(malformedHostId)).toThrow(/Host ID must be canonical/);
      }
      expect(generateKeyPair).not.toHaveBeenCalled();
    } finally {
      generateKeyPair.mockRestore();
    }
  });

  test('invalid Host IDs cannot read, generate, or mutate Linux encryption-key storage', () => {
    const root = mkdtempSync(join(tmpdir(), 'ariava-e2e-invalid-host-linux-'));
    const path = join(root, 'encryption.json');
    const store = new LinuxEncryptionKeyStore(path);
    const generateKeyPair = spyOn(crypto, 'generateKeyPairSync');
    try {
      for (const mutate of [
        () => store.loadOrCreate('host-invalid'),
        () => store.replaceCurrent('host-invalid'),
        () => store.replaceForReset('host-invalid'),
      ]) {
        expect(mutate).toThrow(/Host ID must be canonical/);
        expect(generateKeyPair).not.toHaveBeenCalled();
        expect(readdirSync(root)).toEqual([]);
      }
    } finally {
      generateKeyPair.mockRestore();
    }
  });

  test('invalid Host IDs cannot read, generate, or mutate macOS metadata or Keychain storage', () => {
    const root = mkdtempSync(join(tmpdir(), 'ariava-e2e-invalid-host-macos-'));
    const path = join(root, 'encryption.json');
    const keychain = new FakeKeychain();
    const store = new MacOSEncryptionKeyStore(path, keychain);
    const generateKeyPair = spyOn(crypto, 'generateKeyPairSync');
    const randomUUID = spyOn(crypto, 'randomUUID');
    try {
      for (const mutate of [
        () => store.loadOrCreate('host-invalid'),
        () => store.replaceCurrent('host-invalid'),
        () => store.replaceForReset('host-invalid'),
        () => store.recoverReset('host-invalid', 'reset_invalid'),
      ]) {
        expect(mutate).toThrow(/Host ID must be canonical/);
        expect(generateKeyPair).not.toHaveBeenCalled();
        expect(randomUUID).not.toHaveBeenCalled();
        expect(keychain.calls).toEqual([]);
        expect(keychain.items.size).toBe(0);
        expect(readdirSync(root)).toEqual([]);
      }
    } finally {
      generateKeyPair.mockRestore();
      randomUUID.mockRestore();
    }
  });

  test('persists hardened schema v2, retains historical identities, and prunes only unreferenced keys', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'ariava-e2e-')), 'encryption.json');
    const store = new LinuxEncryptionKeyStore(path);
    const first = store.loadOrCreate(hostId);
    const second = store.replaceCurrent(hostId);
    expect(second.encryptionKeyId).not.toBe(first.encryptionKeyId);
    expect(store.load()).toEqual(second);
    expect(store.identity(first.encryptionKeyId)).toEqual(first);
    expect(store.retainedIdentityIds()).toEqual(new Set([first.encryptionKeyId, second.encryptionKeyId]));
    expect(JSON.parse(readFileSync(path, 'utf8'))).toMatchObject({ version: 2, currentKeyId: second.encryptionKeyId });
    expect(readFileSync(path, 'utf8')).not.toContain('BEGIN PRIVATE KEY');
    expect(store.prune(new Set([first.encryptionKeyId]))).toEqual([]);
    expect(store.prune(new Set())).toEqual([first.encryptionKeyId]);
    expect(store.identity(first.encryptionKeyId)).toBeNull();
    expect(() => store.loadOrCreate(`host_${'B'.repeat(43)}`)).toThrow(/another Host/);
  });

  test('rejects malformed, duplicate, foreign-Host, and rollback Linux schema v2 evidence', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'ariava-e2e-invalid-')), 'encryption.json');
    const store = new LinuxEncryptionKeyStore(path);
    const first = store.loadOrCreate(hostId);
    const second = store.replaceCurrent(hostId);
    const original = JSON.parse(readFileSync(path, 'utf8'));
    for (const mutate of [
      (record: any) => record.identities.push(record.identities[0]),
      (record: any) => { record.identities[0].hostId = `host_${'Z'.repeat(43)}`; },
      (record: any) => { record.currentKeyId = first.encryptionKeyId; },
      (record: any) => { record.unknown = true; },
    ]) {
      const record = structuredClone(original); mutate(record);
      writeFileSync(path, JSON.stringify(record), { mode: 0o600 });
      expect(() => store.load()).toThrow();
    }
    expect(second.sequence).toBeGreaterThan(first.sequence);
  });

  test('macOS metadata retains exact historical accounts and prunes without enumeration', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'ariava-e2e-macos-')), 'encryption.json');
    const keychain = new FakeKeychain();
    const store = new MacOSEncryptionKeyStore(path, keychain);
    const first = store.loadOrCreate(hostId);
    const second = store.replaceCurrent(hostId);
    const firstAccount = `host-e2e:${first.encryptionKeyId}`;
    const secondAccount = `host-e2e:${second.encryptionKeyId}`;
    const foreignAccount = `host-e2e:ekey_${'Z'.repeat(43)}`;
    keychain.items.set(foreignAccount, new Uint8Array([1, 2, 3]));
    expect(store.identity(first.encryptionKeyId)).toEqual(first);
    expect(keychain.items.has(firstAccount)).toBe(true);
    expect(keychain.items.has(secondAccount)).toBe(true);
    expect(store.prune(new Set([first.encryptionKeyId]))).toEqual([]);
    expect(store.prune(new Set())).toEqual([first.encryptionKeyId]);
    expect(keychain.items.has(firstAccount)).toBe(false);
    expect(keychain.items.has(secondAccount)).toBe(true);
    expect(keychain.items.has(foreignAccount)).toBe(true);
    expect(keychain.calls.some((call) => call.action === 'unsupported')).toBe(false);
  });

  test('macOS metadata rejects malformed, duplicate, foreign-Host, and rollback evidence', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'ariava-e2e-macos-invalid-')), 'encryption.json');
    const keychain = new FakeKeychain();
    const store = new MacOSEncryptionKeyStore(path, keychain);
    const first = store.loadOrCreate(hostId);
    store.replaceCurrent(hostId);
    const original = JSON.parse(readFileSync(path, 'utf8'));
    for (const mutate of [
      (record: any) => record.identities.push(record.identities[0]),
      (record: any) => { record.identities[0].hostId = `host_${'Z'.repeat(43)}`; },
      (record: any) => { record.currentKeyId = first.encryptionKeyId; },
      (record: any) => { record.hostId = 'host-malformed'; record.identities.forEach((identity: any) => { identity.hostId = 'host-malformed'; }); },
      (record: any) => { record.unknown = true; },
    ]) {
      writeFileSync(path, JSON.stringify(original), { mode: 0o600 });
      const record = structuredClone(original); mutate(record);
      writeFileSync(path, JSON.stringify(record), { mode: 0o600 });
      expect(() => store.load()).toThrow();
    }
  });

  test('macOS prune journal retries exact failed deletions without enumeration or orphaning', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'ariava-e2e-macos-prune-')), 'encryption.json');
    const keychain = new FakeKeychain();
    const store = new MacOSEncryptionKeyStore(path, keychain);
    const first = store.loadOrCreate(hostId);
    const second = store.replaceCurrent(hostId);
    const firstAccount = `host-e2e:${first.encryptionKeyId}`;
    keychain.deleteResultForAccount = (account) => account === firstAccount
      ? { status: 1, stderr: 'injected delete failure' } : undefined;
    expect(() => store.prune(new Set())).toThrow(/delete/);
    expect(existsSync(`${path}.pruning`)).toBe(true);
    expect(JSON.parse(readFileSync(path, 'utf8')).identities).toHaveLength(2);
    expect(keychain.items.has(firstAccount)).toBe(true);
    keychain.deleteResultForAccount = undefined;
    const restarted = new MacOSEncryptionKeyStore(path, keychain);
    expect(restarted.load()?.encryptionKeyId).toBe(second.encryptionKeyId);
    expect(existsSync(`${path}.pruning`)).toBe(false);
    expect(keychain.items.has(firstAccount)).toBe(false);
    expect(keychain.calls.some((call) => call.action === 'unsupported')).toBe(false);
  });

  test('macOS prune journal resumes after a crash following one exact deletion', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'ariava-e2e-macos-prune-crash-')), 'encryption.json');
    const keychain = new FakeKeychain();
    const initial = new MacOSEncryptionKeyStore(path, keychain);
    const first = initial.loadOrCreate(hostId);
    const second = initial.replaceCurrent(hostId);
    const third = initial.replaceCurrent(hostId);
    let deletes = 0;
    const crashing = new MacOSEncryptionKeyStore(path, keychain, { afterPruneDelete() {
      deletes += 1;
      if (deletes === 1) throw new Error('crash after exact prune deletion');
    } });
    expect(() => crashing.prune(new Set())).toThrow('crash after exact prune deletion');
    expect(existsSync(`${path}.pruning`)).toBe(true);
    const restarted = new MacOSEncryptionKeyStore(path, keychain);
    expect(restarted.load()?.encryptionKeyId).toBe(third.encryptionKeyId);
    expect(restarted.retainedIdentityIds()).toEqual(new Set([third.encryptionKeyId]));
    expect(keychain.items.has(`host-e2e:${first.encryptionKeyId}`)).toBe(false);
    expect(keychain.items.has(`host-e2e:${second.encryptionKeyId}`)).toBe(false);
  });

  test('macOS whole-domain reset removes every historical key account', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'ariava-e2e-macos-reset-domain-')), 'encryption.json');
    const keychain = new FakeKeychain();
    const store = new MacOSEncryptionKeyStore(path, keychain);
    const first = store.loadOrCreate(hostId);
    const second = store.replaceCurrent(hostId);
    const third = store.replaceCurrent(hostId);
    const replacement = store.replaceForReset(`host_${'B'.repeat(43)}`);
    expect(store.retainedIdentityIds()).toEqual(new Set([replacement.encryptionKeyId]));
    for (const identity of [first, second, third]) expect(keychain.items.has(`host-e2e:${identity.encryptionKeyId}`)).toBe(false);
    expect(keychain.items.has(`host-e2e:${replacement.encryptionKeyId}`)).toBe(true);
  });

  test('whole-domain reset removes historical identities and keeps only the replacement Host key', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'ariava-e2e-reset-')), 'encryption.json');
    const store = new LinuxEncryptionKeyStore(path);
    const first = store.loadOrCreate(hostId);
    const second = store.replaceCurrent(hostId);
    const replacement = store.replaceForReset(`host_${'B'.repeat(43)}`);
    expect(store.retainedIdentityIds()).toEqual(new Set([replacement.encryptionKeyId]));
    expect(store.identity(first.encryptionKeyId)).toBeNull();
    expect(store.identity(second.encryptionKeyId)).toBeNull();
  });

  test('migrates exact valid Linux v1 evidence to schema v2 after cryptographic validation', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'ariava-e2e-v1-')), 'encryption.json');
    const identity = generateHostEncryptionIdentity(hostId, 1, '2026-07-20T00:00:00.000Z');
    writeFileSync(path, JSON.stringify({ ...identity, privateKeyPkcs8: Buffer.from(identity.privateKeyPkcs8).toString('base64url') }), { mode: 0o600 });
    const store = new LinuxEncryptionKeyStore(path);
    expect(store.load()).toEqual(identity);
    expect(JSON.parse(readFileSync(path, 'utf8'))).toMatchObject({ version: 2, hostId, currentKeyId: identity.encryptionKeyId });
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
    record.identities[0].encryptionKeyId = `ekey_${'Z'.repeat(43)}`;
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
