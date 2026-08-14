import { afterEach, describe, expect, test } from 'bun:test';
import { chmodSync, lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HostIdentityError } from '../src/identity/errors';
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
      permissionIntegrity: true, metadataIntegrity: true,
    });
    const record = JSON.parse(readFileSync(path, 'utf8'));
    record.keyId = `key_${'A'.repeat(43)}`;
    writeFileSync(path, JSON.stringify(record), { mode: 0o600 });
    await expect(store.load()).rejects.toMatchObject({ code: 'ERR_IDENTITY_INVALID' });
  });

  test('normal load rejects exact pending evidence while reset-only inspection recognizes it', async () => {
    const path = join(root(), 'host-identity.json');
    const store = new LinuxJsonHostIdentityStore(path);
    await store.createFirstRun();
    const record = JSON.parse(readFileSync(path, 'utf8'));
    record.pendingRotation = {
      operationId: 'op_pending', issuedAt: new Date().toISOString(), identity: { ...record },
    };
    writeFileSync(path, JSON.stringify(record), { mode: 0o600 });
    await expect(store.load()).rejects.toMatchObject({ code: 'ERR_IDENTITY_INVALID' });
    expect(await store.inspect()).toMatchObject({ status: 'invalid' });
    const { inspectResetOnlyLegacyIdentityEvidence } = await import('../src/cli/operations/identity-reset-legacy-evidence');
    expect(inspectResetOnlyLegacyIdentityEvidence(store)).toMatchObject({
      classification: 'old-identity-unreadable', oldHostId: record.hostId, oldKeyId: record.keyId,
      source: { kind: 'linux-json', resourcePath: path }, cleanup: null,
    });
  });

  test('missing private key in the exact known schema is reset-only old-identity-unreadable', async () => {
    const path = join(root(), 'host-identity.json');
    const store = new LinuxJsonHostIdentityStore(path);
    await store.createFirstRun();
    const record = JSON.parse(readFileSync(path, 'utf8'));
    delete record.privateKeyPkcs8;
    writeFileSync(path, JSON.stringify(record), { mode: 0o600 });
    await expect(store.load()).rejects.toMatchObject({ code: 'ERR_IDENTITY_INVALID' });
    const { inspectResetOnlyLegacyIdentityEvidence } = await import('../src/cli/operations/identity-reset-legacy-evidence');
    expect(inspectResetOnlyLegacyIdentityEvidence(store)).toMatchObject({
      classification: 'old-identity-unreadable', oldHostId: record.hostId, oldKeyId: record.keyId,
      source: { kind: 'linux-json', resourcePath: path }, cleanup: null,
    });
  });

  test('reset-only inspection blocks unknown and malformed evidence without changing bytes', async () => {
    const path = join(root(), 'host-identity.json');
    const store = new LinuxJsonHostIdentityStore(path);
    await store.createFirstRun();
    const record = JSON.parse(readFileSync(path, 'utf8'));
    record.unknown = 'not-approved';
    const bytes = JSON.stringify(record);
    writeFileSync(path, bytes, { mode: 0o600 });
    const { inspectResetOnlyLegacyIdentityEvidence } = await import('../src/cli/operations/identity-reset-legacy-evidence');
    expect(() => inspectResetOnlyLegacyIdentityEvidence(store)).toThrow();
    expect(readFileSync(path, 'utf8')).toBe(bytes);
  });

  test('reset-only inspection rejects a Host ID not derived from the bound public key without effects', async () => {
    const base = root();
    const path = join(base, 'host-identity.json');
    const store = new LinuxJsonHostIdentityStore(path);
    await store.createFirstRun();
    const record = JSON.parse(readFileSync(path, 'utf8'));
    record.hostId = `host_${'A'.repeat(43)}`;
    const bytes = JSON.stringify(record);
    writeFileSync(path, bytes, { mode: 0o600 });
    const entries = readdirSync(base);
    const { inspectResetOnlyLegacyIdentityEvidence } = await import('../src/cli/operations/identity-reset-legacy-evidence');
    expect(() => inspectResetOnlyLegacyIdentityEvidence(store)).toThrow(expect.objectContaining({
      code: 'ERR_IDENTITY_RESET_REQUIRED',
    }));
    expect(readFileSync(path, 'utf8')).toBe(bytes);
    expect(readdirSync(base)).toEqual(entries);
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
