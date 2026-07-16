import { afterEach, describe, expect, test } from 'bun:test';
import { chmodSync, lstatSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HostIdentityError } from '../src/identity/errors';
import { generateHostRotationIdentity } from '../src/identity/host-identity';
import { LinuxJsonHostIdentityStore } from '../src/identity/linux-json-store';

const roots: string[] = [];
function root(): string { const value = mkdtempSync(join(tmpdir(), 'ariava-identity-')); chmodSync(value, 0o700); roots.push(value); return value; }
afterEach(() => { for (const value of roots.splice(0)) rmSync(value, { recursive: true, force: true }); });

describe('LinuxJsonHostIdentityStore', () => {
  test('creates 0600 identity and rejects metadata/key mismatch', async () => {
    const path = join(root(), 'host-identity.json');
    const store = new LinuxJsonHostIdentityStore(path);
    expect(await store.load()).toBeNull();
    const identity = await store.createFirstRun();
    expect(lstatSync(path).mode & 0o777).toBe(0o600);
    expect((await store.load())?.hostId).toBe(identity.hostId);
    expect(await store.inspect()).toMatchObject({
      status: 'ready', hostId: identity.hostId, keyId: identity.keyId, algorithm: 'Ed25519',
      publicKeyFingerprint: identity.publicKeyFingerprint, storageType: 'linux-json',
      storageReference: { type: 'linux-json', path }, path, ownerIntegrity: true,
      permissionIntegrity: true, metadataIntegrity: true, pendingRotation: false,
    });
    const record = JSON.parse(readFileSync(path, 'utf8'));
    record.keyId = `key_${'A'.repeat(43)}`;
    writeFileSync(path, JSON.stringify(record), { mode: 0o600 });
    await expect(store.load()).rejects.toMatchObject({ code: 'ERR_IDENTITY_INVALID' });
  });

  test('preserves current and pending keys until promote', async () => {
    const path = join(root(), 'host-identity.json');
    const store = new LinuxJsonHostIdentityStore(path);
    const current = await store.createFirstRun();
    const pending = await generateHostRotationIdentity(current.hostId, { type: 'linux-json', path });
    await store.stageRotation({ operationId: 'rotation-1', issuedAt: new Date().toISOString(), identity: pending.identity });
    const record = JSON.parse(readFileSync(path, 'utf8'));
    expect(record.privateKeyPkcs8).toBeString();
    expect(record.pendingRotation.identity.privateKeyPkcs8).toBeString();
    expect((await store.inspect()).status).toBe('rotation-pending');
    expect((await store.load())?.keyId).toBe(current.keyId);
    expect((await store.promoteRotation('rotation-1')).keyId).toBe(pending.identity.keyId);
    expect(JSON.parse(readFileSync(path, 'utf8')).pendingRotation).toBeUndefined();

    const secondPending = await generateHostRotationIdentity(pending.identity.hostId, { type: 'linux-json', path });
    await store.stageRotation({ operationId: 'rotation-2', issuedAt: new Date().toISOString(), identity: secondPending.identity });
    await store.abortRotation('rotation-2');
    expect((await store.inspect()).status).toBe('ready');
  });

  test('same operationId with a different key is rejected and original pending remains', async () => {
    const path = join(root(), 'host-identity.json');
    const store = new LinuxJsonHostIdentityStore(path);
    const current = await store.createFirstRun();
    const first = await generateHostRotationIdentity(current.hostId, { type: 'linux-json', path });
    const second = await generateHostRotationIdentity(current.hostId, { type: 'linux-json', path });
    const issuedAt = new Date().toISOString();
    await store.stageRotation({ operationId: 'same-op', issuedAt, identity: first.identity });
    await expect(store.stageRotation({ operationId: 'same-op', issuedAt, identity: second.identity })).rejects.toMatchObject({ code: 'ERR_IDENTITY_INVALID' });
    expect(JSON.parse(readFileSync(path, 'utf8')).pendingRotation.identity.keyId).toBe(first.identity.keyId);
  });

  test('dangling symlink is identity evidence and cannot be first-created over', async () => {
    const base = root();
    const path = join(base, 'host-identity.json');
    symlinkSync(join(base, 'missing-target'), path);
    const store = new LinuxJsonHostIdentityStore(path);
    await expect(store.load()).rejects.toMatchObject({ code: 'ERR_IDENTITY_PERMISSIONS' });
    await expect(store.createFirstRun()).rejects.toMatchObject({ code: 'ERR_IDENTITY_RESET_REQUIRED' });
  });

  test('rejects permissive files and symlinks', async () => {
    const base = root();
    const path = join(base, 'host-identity.json');
    const store = new LinuxJsonHostIdentityStore(path);
    await store.createFirstRun();
    chmodSync(path, 0o640);
    await expect(store.load()).rejects.toMatchObject({ code: 'ERR_IDENTITY_PERMISSIONS' });
    expect(await store.inspect()).toMatchObject({ status: 'invalid', ownerIntegrity: false, permissionIntegrity: false, metadataIntegrity: false });
    chmodSync(path, 0o600);
    const link = join(base, 'link.json');
    symlinkSync(path, link);
    await expect(new LinuxJsonHostIdentityStore(link).load()).rejects.toMatchObject({ code: 'ERR_IDENTITY_PERMISSIONS' });
  });

  test('requires absolute paths', () => {
    expect(() => new LinuxJsonHostIdentityStore('identity.json')).toThrow(HostIdentityError);
  });
});
