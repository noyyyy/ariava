import { afterEach, describe, expect, test } from 'bun:test';
import { chmodSync, copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRuntimeHostIdentityStore } from '../src/identity/runtime-store';
import {
  MACOS_IDENTITY_KEYCHAIN_SERVICE,
  MACOS_IDENTITY_EVIDENCE_ACCOUNTS,
  MACOS_SECURITY_PATH,
  MacOSKeychainHostIdentityStore,
  type KeychainCommandRunner,
} from '../src/identity/macos-keychain-store';
import { FakeKeychain } from './fixtures/fake-keychain';

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
      ownerIntegrity: true, permissionIntegrity: true, metadataIntegrity: true,
    });
  });

  test('decodes hexadecimal security -w output before validating key material', async () => {
    const runner = new FakeKeychain();
    const store = new MacOSKeychainHostIdentityStore(metadataPath(), runner);
    const identity = await store.createFirstRun();
    expect((await store.load())?.keyId).toBe(identity.keyId);
  });

  test('isolates default and dev evidence and key accounts in the same service', async () => {
    const runner = new FakeKeychain();
    const defaultPath = metadataPath();
    const devPath = metadataPath();
    const defaultStore = new MacOSKeychainHostIdentityStore(defaultPath, runner);
    const devStore = new MacOSKeychainHostIdentityStore(devPath, runner, {}, 'dev');

    const defaultIdentity = await defaultStore.createFirstRun();
    const devIdentity = await devStore.createFirstRun();

    expect(defaultStore.evidenceAccount).toBe(MACOS_IDENTITY_EVIDENCE_ACCOUNTS.default);
    expect(devStore.evidenceAccount).toBe(MACOS_IDENTITY_EVIDENCE_ACCOUNTS.dev);
    expect(defaultIdentity.hostId).not.toBe(devIdentity.hostId);
    expect(runner.items.has(MACOS_IDENTITY_EVIDENCE_ACCOUNTS.default)).toBe(true);
    expect(runner.items.has(MACOS_IDENTITY_EVIDENCE_ACCOUNTS.dev)).toBe(true);
    expect(runner.items.has(defaultIdentity.hostId)).toBe(true);
    expect(runner.items.has(devIdentity.hostId)).toBe(true);
    expect(JSON.parse(readFileSync(defaultPath, 'utf8')).current.hostId).toBe(defaultIdentity.hostId);
    expect(JSON.parse(readFileSync(devPath, 'utf8')).current.hostId).toBe(devIdentity.hostId);

    const defaultEvidence = runner.items.get(MACOS_IDENTITY_EVIDENCE_ACCOUNTS.default);
    const defaultKey = runner.items.get(defaultIdentity.hostId);
    const { inspectResetOnlyLegacyIdentityEvidence } = await import('../src/cli/operations/identity-reset-legacy-evidence');
    inspectResetOnlyLegacyIdentityEvidence(devStore);
    await devStore.resetAfterExplicitConfirmation();

    expect(runner.items.get(MACOS_IDENTITY_EVIDENCE_ACCOUNTS.default)).toEqual(defaultEvidence);
    expect(runner.items.get(defaultIdentity.hostId)).toEqual(defaultKey);
    expect((await defaultStore.load())?.hostId).toBe(defaultIdentity.hostId);
  });

  test('runtime store factory preserves default selection and accepts the closed dev selection', () => {
    const defaultStore = createRuntimeHostIdentityStore(metadataPath(), 'darwin');
    const devStore = createRuntimeHostIdentityStore(metadataPath(), 'darwin', 'dev');

    expect(defaultStore).toBeInstanceOf(MacOSKeychainHostIdentityStore);
    expect(devStore).toBeInstanceOf(MacOSKeychainHostIdentityStore);
    expect((defaultStore as MacOSKeychainHostIdentityStore).evidenceAccount).toBe(MACOS_IDENTITY_EVIDENCE_ACCOUNTS.default);
    expect((devStore as MacOSKeychainHostIdentityStore).evidenceAccount).toBe(MACOS_IDENTITY_EVIDENCE_ACCOUNTS.dev);
  });

  test('dev creation rollback never changes default evidence or key accounts', async () => {
    const runner = new FakeKeychain();
    const defaultStore = new MacOSKeychainHostIdentityStore(metadataPath(), runner);
    const defaultIdentity = await defaultStore.createFirstRun();
    const defaultEvidence = runner.items.get(MACOS_IDENTITY_EVIDENCE_ACCOUNTS.default);
    const defaultKey = runner.items.get(defaultIdentity.hostId);
    const devStore = new MacOSKeychainHostIdentityStore(metadataPath(), runner, {
      afterIndexWrite() { throw new Error('injected dev rollback'); },
    }, 'dev');

    await expect(devStore.createFirstRun()).rejects.toThrow('injected dev rollback');

    expect(runner.items.has(MACOS_IDENTITY_EVIDENCE_ACCOUNTS.dev)).toBe(false);
    expect(runner.items.get(MACOS_IDENTITY_EVIDENCE_ACCOUNTS.default)).toEqual(defaultEvidence);
    expect(runner.items.get(defaultIdentity.hostId)).toEqual(defaultKey);
    expect((await defaultStore.load())?.hostId).toBe(defaultIdentity.hostId);
  });

  test('dev fails closed on copied default metadata and preserves every default artifact', async () => {
    const runner = new FakeKeychain();
    const defaultPath = metadataPath();
    const crossedDevPath = metadataPath();
    const defaultStore = new MacOSKeychainHostIdentityStore(defaultPath, runner);
    const defaultIdentity = await defaultStore.createFirstRun();
    copyFileSync(defaultPath, crossedDevPath);

    const defaultMetadata = readFileSync(defaultPath);
    const crossedMetadata = readFileSync(crossedDevPath);
    const defaultEvidence = runner.items.get(MACOS_IDENTITY_EVIDENCE_ACCOUNTS.default);
    const defaultCurrent = runner.items.get(defaultIdentity.hostId);
    const crossedDevStore = new MacOSKeychainHostIdentityStore(crossedDevPath, runner, {}, 'dev');

    await expect(crossedDevStore.load()).rejects.toMatchObject({ code: 'ERR_IDENTITY_RESET_REQUIRED' });
    await expect(crossedDevStore.resetAfterExplicitConfirmation()).rejects.toMatchObject({ code: 'ERR_IDENTITY_RESET_REQUIRED' });

    expect(runner.items.has(MACOS_IDENTITY_EVIDENCE_ACCOUNTS.dev)).toBe(false);
    expect(runner.items.get(MACOS_IDENTITY_EVIDENCE_ACCOUNTS.default)).toEqual(defaultEvidence);
    expect(runner.items.get(defaultIdentity.hostId)).toEqual(defaultCurrent);
    expect(readFileSync(defaultPath)).toEqual(defaultMetadata);
    expect(readFileSync(crossedDevPath)).toEqual(crossedMetadata);
  });

  test('missing selected evidence rejects metadata without changing it or its key', async () => {
    const runner = new FakeKeychain();
    const devPath = metadataPath();
    const devStore = new MacOSKeychainHostIdentityStore(devPath, runner, {}, 'dev');
    const identity = await devStore.createFirstRun();
    const metadata = readFileSync(devPath);
    const current = runner.items.get(identity.hostId);
    runner.items.delete(MACOS_IDENTITY_EVIDENCE_ACCOUNTS.dev);

    await expect(devStore.load()).rejects.toMatchObject({ code: 'ERR_IDENTITY_RESET_REQUIRED' });
    await expect(devStore.resetAfterExplicitConfirmation()).rejects.toMatchObject({ code: 'ERR_IDENTITY_RESET_REQUIRED' });

    expect(readFileSync(devPath)).toEqual(metadata);
    expect(runner.items.get(identity.hostId)).toEqual(current);
    expect(runner.items.has(MACOS_IDENTITY_EVIDENCE_ACCOUNTS.dev)).toBe(false);
  });

  test('malformed metadata blocks reset-only replacement and preserves exact accounts', async () => {
    const runner = new FakeKeychain();
    const path = metadataPath();
    const store = new MacOSKeychainHostIdentityStore(path, runner);
    const previous = await store.createFirstRun();
    const previousKey = runner.snapshot(previous.hostId);
    const bytes = '{bad json';
    writeFileSync(path, bytes);
    const { inspectResetOnlyLegacyIdentityEvidence } = await import('../src/cli/operations/identity-reset-legacy-evidence');
    expect(() => inspectResetOnlyLegacyIdentityEvidence(store)).toThrow();
    await expect(store.resetAfterExplicitConfirmation('reset_malformed')).rejects.toMatchObject({ code: 'ERR_IDENTITY_RESET_REQUIRED' });
    expect(readFileSync(path, 'utf8')).toBe(bytes);
    expect(runner.snapshot(previous.hostId)).toEqual(previousKey);
  });

  test('recognized pending metadata is reset-only and deletes only exact referenced accounts', async () => {
    const runner = new FakeKeychain();
    const path = metadataPath();
    const store = new MacOSKeychainHostIdentityStore(path, runner);
    const previous = await store.createFirstRun();
    const metadata = JSON.parse(readFileSync(path, 'utf8'));
    const pendingAccount = `${previous.hostId}.pending`;
    runner.items.set(pendingAccount, runner.snapshot(previous.hostId));
    const unrelated = `host_${'Z'.repeat(43)}`;
    runner.items.set(unrelated, new Uint8Array([1, 2, 3]));
    metadata.pending = {
      operationId: 'op_pending', issuedAt: new Date().toISOString(),
      identity: { ...metadata.current, privateKeyStorage: { ...metadata.current.privateKeyStorage, account: pendingAccount } },
    };
    writeFileSync(path, JSON.stringify(metadata), { mode: 0o600 });
    await expect(store.load()).rejects.toMatchObject({ code: 'ERR_IDENTITY_INVALID' });
    const { inspectResetOnlyLegacyIdentityEvidence } = await import('../src/cli/operations/identity-reset-legacy-evidence');
    expect(inspectResetOnlyLegacyIdentityEvidence(store)).toMatchObject({
      classification: 'old-identity-unreadable', oldHostId: previous.hostId, oldKeyId: previous.keyId,
    });
    const replacement = await store.resetAfterExplicitConfirmation('reset_pending');
    store.completeExplicitReset('reset_pending');
    expect(replacement.hostId).not.toBe(previous.hostId);
    expect(runner.items.has(previous.hostId)).toBe(false);
    expect(runner.items.has(pendingAccount)).toBe(false);
    expect(runner.items.get(unrelated)).toEqual(new Uint8Array([1, 2, 3]));
  });

  test.each([
    ['foreign current account', (metadata: any) => { metadata.current.privateKeyStorage.account = `host_${'F'.repeat(43)}`; }],
    ['coordinated foreign Host/account tuple', (metadata: any) => {
      metadata.current.hostId = `host_${'F'.repeat(43)}`;
      metadata.current.privateKeyStorage.account = metadata.current.hostId;
    }],
    ['reserved evidence current account', (metadata: any) => { metadata.current.privateKeyStorage.account = MACOS_IDENTITY_EVIDENCE_ACCOUNTS.default; }],
    ['unknown pending account', (metadata: any) => {
      metadata.pending = { operationId: 'op_pending', issuedAt: new Date().toISOString(), identity: {
        ...metadata.current, privateKeyStorage: { ...metadata.current.privateKeyStorage, account: `host_${'P'.repeat(43)}.pending` },
      } };
    }],
  ])('reset-only decoder rejects %s without deleting any account', async (_label, mutate) => {
    const runner = new FakeKeychain();
    const path = metadataPath();
    const store = new MacOSKeychainHostIdentityStore(path, runner);
    const previous = await store.createFirstRun();
    const metadata = JSON.parse(readFileSync(path, 'utf8'));
    mutate(metadata);
    writeFileSync(path, JSON.stringify(metadata), { mode: 0o600 });
    const before = new Map([...runner.items].map(([account, bytes]) => [account, new Uint8Array(bytes)]));
    const { inspectResetOnlyLegacyIdentityEvidence } = await import('../src/cli/operations/identity-reset-legacy-evidence');
    expect(() => inspectResetOnlyLegacyIdentityEvidence(store)).toThrow();
    await expect(store.resetAfterExplicitConfirmation('reset_rejected')).rejects.toMatchObject({ code: 'ERR_IDENTITY_RESET_REQUIRED' });
    expect(runner.items).toEqual(before);
    expect(runner.items.has(previous.hostId)).toBe(true);
  });

  test('exact creation sentinel must match current metadata tuple before cleanup', async () => {
    const runner = new FakeKeychain();
    const path = metadataPath();
    const store = new MacOSKeychainHostIdentityStore(path, runner);
    const previous = await store.createFirstRun();
    writeFileSync(`${path}.creating`, JSON.stringify({
      schema: 'ariava-macos-identity-creation-v1', phase: 'creating',
      hostId: previous.hostId, keyId: `key_${'M'.repeat(43)}`,
    }), { mode: 0o600 });
    const before = new Map([...runner.items].map(([account, bytes]) => [account, new Uint8Array(bytes)]));
    const { inspectResetOnlyLegacyIdentityEvidence } = await import('../src/cli/operations/identity-reset-legacy-evidence');
    expect(() => inspectResetOnlyLegacyIdentityEvidence(store)).toThrow();
    await expect(store.resetAfterExplicitConfirmation('reset_mismatch')).rejects.toMatchObject({ code: 'ERR_IDENTITY_RESET_REQUIRED' });
    expect(runner.items).toEqual(before);
  });

  test('metadata-absent creation evidence requires matching Host and key suffixes', async () => {
    const runner = new FakeKeychain();
    const path = metadataPath();
    const store = new MacOSKeychainHostIdentityStore(path, runner);
    const previous = await store.createFirstRun();
    rmSync(path);
    writeFileSync(`${path}.creating`, JSON.stringify({
      schema: 'ariava-macos-identity-creation-v1', phase: 'creating',
      hostId: previous.hostId, keyId: `key_${'M'.repeat(43)}`,
    }), { mode: 0o600 });
    const before = new Map([...runner.items].map(([account, bytes]) => [account, new Uint8Array(bytes)]));
    const { inspectResetOnlyLegacyIdentityEvidence } = await import('../src/cli/operations/identity-reset-legacy-evidence');
    expect(() => inspectResetOnlyLegacyIdentityEvidence(store)).toThrow(expect.objectContaining({
      code: 'ERR_IDENTITY_RESET_REQUIRED',
    }));
    await expect(store.resetAfterExplicitConfirmation('reset_mismatched_creation')).rejects.toMatchObject({
      code: 'ERR_IDENTITY_RESET_REQUIRED',
    });
    expect(runner.items).toEqual(before);
  });

  test('unknown creation sentinel schema blocks cleanup without deleting accounts', async () => {
    const runner = new FakeKeychain();
    const path = metadataPath();
    const store = new MacOSKeychainHostIdentityStore(path, runner);
    const previous = await store.createFirstRun();
    writeFileSync(`${path}.creating`, JSON.stringify({
      schema: 'ariava-macos-identity-creation-v2', phase: 'creating', hostId: previous.hostId, keyId: previous.keyId,
    }), { mode: 0o600 });
    const before = new Map([...runner.items].map(([account, bytes]) => [account, new Uint8Array(bytes)]));
    const { inspectResetOnlyLegacyIdentityEvidence } = await import('../src/cli/operations/identity-reset-legacy-evidence');
    expect(() => inspectResetOnlyLegacyIdentityEvidence(store)).toThrow();
    await expect(store.resetAfterExplicitConfirmation('reset_unknown_sentinel')).rejects.toMatchObject({ code: 'ERR_IDENTITY_RESET_REQUIRED' });
    expect(runner.items).toEqual(before);
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

  test('reports locked Keychain as recoverable instead of invalid identity evidence', async () => {
    const runner = new FakeKeychain();
    const path = metadataPath();
    const store = new MacOSKeychainHostIdentityStore(path, runner);
    await store.createFirstRun();
    const lockedRunner: KeychainCommandRunner = {
      run: () => ({ status: 36, stdout: new Uint8Array(), stderr: '' }),
    };
    const lockedStore = new MacOSKeychainHostIdentityStore(path, lockedRunner);

    await expect(lockedStore.inspect()).rejects.toMatchObject({
      code: 'ERR_IDENTITY_KEYCHAIN_LOCKED',
      message: 'macOS login Keychain is locked or unavailable in this session.',
    });
    await expect(lockedStore.load()).rejects.toMatchObject({ code: 'ERR_IDENTITY_KEYCHAIN_LOCKED' });
  });


  test('fails closed when Keychain read is unavailable', async () => {
    const runner = new FakeKeychain();
    const path = metadataPath();
    const store = new MacOSKeychainHostIdentityStore(path, runner);
    await store.createFirstRun();
    runner.items.clear();
    await expect(store.load()).rejects.toMatchObject({ code: 'ERR_IDENTITY_RESET_REQUIRED' });
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

  test('locked Keychain remains recoverable when a creation sentinel is present', async () => {
    const runner = new FakeKeychain();
    const path = metadataPath();
    const store = new MacOSKeychainHostIdentityStore(path, runner, {
      afterMetadataWrite() { throw new Error('injected after metadata'); },
    });
    await expect(store.createFirstRun()).rejects.toThrow('injected after metadata');
    const lockedRunner: KeychainCommandRunner = {
      run: () => ({ status: 1, stdout: new Uint8Array(), stderr: 'User interaction is not allowed.' }),
    };

    await expect(new MacOSKeychainHostIdentityStore(path, lockedRunner).load()).rejects.toMatchObject({
      code: 'ERR_IDENTITY_KEYCHAIN_LOCKED',
    });
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
