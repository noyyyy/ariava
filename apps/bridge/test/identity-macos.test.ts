import { afterEach, describe, expect, test } from 'bun:test';
import { chmodSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateHostRotationIdentity } from '../src/identity/host-identity';
import {
  MACOS_IDENTITY_KEYCHAIN_SERVICE,
  MACOS_SECURITY_PATH,
  MacOSKeychainHostIdentityStore,
  type KeychainCommandRunner,
  type KeychainCommandResult,
} from '../src/identity/macos-keychain-store';

class FakeKeychain implements KeychainCommandRunner {
  readonly calls: Array<{ command: string; args: readonly string[]; stdin?: Uint8Array }> = [];
  readonly items = new Map<string, Uint8Array>();

  run(command: string, args: readonly string[], stdin?: Uint8Array): KeychainCommandResult {
    this.calls.push({ command, args, stdin });
    if (args.length === 1 && args[0] === '-i' && stdin) {
      const script = Buffer.from(stdin).toString('utf8');
      const account = /-a "([^"]+)"/u.exec(script)?.[1];
      const hex = /-X ([0-9a-f]+)/u.exec(script)?.[1];
      if (!account || !hex) return { status: 1, stdout: new Uint8Array(), stderr: 'invalid stdin' };
      if (!script.includes(' -U ') && this.items.has(account)) return { status: 45, stdout: new Uint8Array(), stderr: 'item already exists' };
      this.items.set(account, Buffer.from(hex, 'hex'));
      return { status: 0, stdout: new Uint8Array(), stderr: '' };
    }
    const account = args[args.indexOf('-a') + 1];
    if (args[0] === 'find-generic-password') {
      const value = this.items.get(account);
      return value ? { status: 0, stdout: value, stderr: '' } : { status: 44, stdout: new Uint8Array(), stderr: 'could not be found' };
    }
    if (args[0] === 'delete-generic-password') {
      this.items.delete(account);
      return { status: 0, stdout: new Uint8Array(), stderr: '' };
    }
    return { status: 1, stdout: new Uint8Array(), stderr: 'unsupported' };
  }
}

const roots: string[] = [];
function metadataPath(): string { const root = mkdtempSync(join(tmpdir(), 'ariava-macos-')); chmodSync(root, 0o700); roots.push(root); return join(root, 'identity-metadata.json'); }
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

describe('MacOSKeychainHostIdentityStore', () => {
  test('writes secret only through security -i stdin and verifies readback', async () => {
    const runner = new FakeKeychain();
    const store = new MacOSKeychainHostIdentityStore(metadataPath(), runner);
    const identity = await store.createFirstRun();
    const write = runner.calls.find((call) => call.args.length === 1 && call.args[0] === '-i')!;
    expect(write.command).toBe(MACOS_SECURITY_PATH);
    expect(write.args).toEqual(['-i']);
    expect(write.stdin?.byteLength).toBeGreaterThan(0);
    expect(write.args.join(' ')).not.toContain('PRIVATE');
    expect(runner.items.has(identity.hostId)).toBe(true);
    expect((await store.load())?.keyId).toBe(identity.keyId);
    expect(await store.inspect()).toMatchObject({
      status: 'ready', storageType: 'macos-keychain', hostId: identity.hostId, keyId: identity.keyId,
      algorithm: 'Ed25519', publicKeyFingerprint: identity.publicKeyFingerprint,
      storageReference: { type: 'macos-keychain', service: MACOS_IDENTITY_KEYCHAIN_SERVICE, account: identity.hostId },
      ownerIntegrity: true, permissionIntegrity: true, metadataIntegrity: true, pendingRotation: false,
    });
  });

  test('keeps pending key in approved hostId.pending item until promote', async () => {
    const runner = new FakeKeychain();
    const store = new MacOSKeychainHostIdentityStore(metadataPath(), runner);
    const current = await store.createFirstRun();
    const pending = await generateHostRotationIdentity(current.hostId, {
      type: 'macos-keychain', service: MACOS_IDENTITY_KEYCHAIN_SERVICE, account: `${current.hostId}.pending`,
    });
    await store.stageRotation({ operationId: 'rotation-1', issuedAt: new Date().toISOString(), identity: pending.identity });
    expect(runner.items.has(current.hostId)).toBe(true);
    expect(runner.items.has(`${current.hostId}.pending`)).toBe(true);
    expect((await store.load())?.keyId).toBe(current.keyId);
    expect(await store.inspect()).toMatchObject({
      status: 'rotation-pending', pendingRotation: true, pendingOperationId: 'rotation-1',
      storageReference: { type: 'macos-keychain', service: MACOS_IDENTITY_KEYCHAIN_SERVICE, account: current.hostId },
    });
    expect((await store.promoteRotation('rotation-1')).keyId).toBe(pending.identity.keyId);
    expect(runner.items.has(`${current.hostId}.pending`)).toBe(false);

    const secondPending = await generateHostRotationIdentity(current.hostId, {
      type: 'macos-keychain', service: MACOS_IDENTITY_KEYCHAIN_SERVICE, account: `${current.hostId}.pending`,
    });
    await store.stageRotation({ operationId: 'rotation-2', issuedAt: new Date().toISOString(), identity: secondPending.identity });
    await store.abortRotation('rotation-2');
    expect(runner.items.has(`${current.hostId}.pending`)).toBe(false);
  });

  test('requires an absolute secure metadata path before any Keychain write', async () => {
    const runner = new FakeKeychain();
    expect(() => new MacOSKeychainHostIdentityStore('relative.json', runner)).toThrow();
    expect(runner.calls).toHaveLength(0);
  });

  test('detects orphan Keychain evidence when metadata is absent', async () => {
    const runner = new FakeKeychain();
    const path = metadataPath();
    const store = new MacOSKeychainHostIdentityStore(path, runner);
    await store.createFirstRun();
    rmSync(path);
    await expect(store.load()).rejects.toMatchObject({ code: 'ERR_IDENTITY_RESET_REQUIRED' });
    await expect(store.createFirstRun()).rejects.toMatchObject({ code: 'ERR_IDENTITY_RESET_REQUIRED' });
  });

  test('same operationId with a different key is rejected', async () => {
    const runner = new FakeKeychain();
    const store = new MacOSKeychainHostIdentityStore(metadataPath(), runner);
    const current = await store.createFirstRun();
    const storage = { type: 'macos-keychain' as const, service: MACOS_IDENTITY_KEYCHAIN_SERVICE, account: `${current.hostId}.pending` };
    const first = await generateHostRotationIdentity(current.hostId, storage);
    const second = await generateHostRotationIdentity(current.hostId, storage);
    const issuedAt = new Date().toISOString();
    await store.stageRotation({ operationId: 'same-op', issuedAt, identity: first.identity });
    await expect(store.stageRotation({ operationId: 'same-op', issuedAt, identity: second.identity })).rejects.toMatchObject({ code: 'ERR_IDENTITY_INVALID' });
  });

  test('fails closed when Keychain read is unavailable', async () => {
    const runner = new FakeKeychain();
    const path = metadataPath();
    const store = new MacOSKeychainHostIdentityStore(path, runner);
    await store.createFirstRun();
    runner.items.clear();
    await expect(store.load()).rejects.toMatchObject({ code: 'ERR_IDENTITY_MISSING' });
  });

  for (const phase of ['afterSentinel', 'afterKeyWrite', 'afterKeyVerification', 'afterIndexWrite'] as const) {
    test(`interrupted first creation at ${phase} remains reset-required on restart`, async () => {
      const runner = new FakeKeychain();
      const path = metadataPath();
      const store = new MacOSKeychainHostIdentityStore(path, runner, { [phase]: () => { throw new Error(`injected ${phase}`); } });
      await expect(store.createFirstRun()).rejects.toThrow(`injected ${phase}`);
      expect(JSON.parse(readFileSync(`${path}.creating`, 'utf8'))).toMatchObject({
        schema: 'ariava-macos-identity-creation-v1', phase: 'creating',
      });
      const restarted = new MacOSKeychainHostIdentityStore(path, runner);
      await expect(restarted.load()).rejects.toMatchObject({ code: 'ERR_IDENTITY_RESET_REQUIRED' });
      await expect(restarted.createFirstRun()).rejects.toMatchObject({ code: 'ERR_IDENTITY_RESET_REQUIRED' });
    });
  }

  test('interruption after durable metadata recovers the same identity without replacement', async () => {
    const runner = new FakeKeychain();
    const path = metadataPath();
    let createdHostId: string | undefined;
    const store = new MacOSKeychainHostIdentityStore(path, runner, {
      afterMetadataWrite() {
        createdHostId = JSON.parse(readFileSync(path, 'utf8')).current.hostId;
        throw new Error('injected afterMetadataWrite');
      },
    });
    await expect(store.createFirstRun()).rejects.toThrow('injected afterMetadataWrite');
    const restarted = new MacOSKeychainHostIdentityStore(path, runner);
    expect((await restarted.load())?.hostId).toBe(createdHostId);
    await expect(restarted.createFirstRun()).rejects.toMatchObject({ code: 'ERR_IDENTITY_RESET_REQUIRED' });
  });

  test('metadata left by interrupted creation with a missing key is reset-required', async () => {
    const runner = new FakeKeychain();
    const path = metadataPath();
    const store = new MacOSKeychainHostIdentityStore(path, runner, {
      afterMetadataWrite() { throw new Error('injected after metadata'); },
    });
    await expect(store.createFirstRun()).rejects.toThrow('injected after metadata');
    const metadata = JSON.parse(readFileSync(path, 'utf8'));
    runner.items.delete(metadata.current.hostId);
    await expect(new MacOSKeychainHostIdentityStore(path, runner).load()).rejects.toMatchObject({
      code: 'ERR_IDENTITY_RESET_REQUIRED',
    });
  });
});
