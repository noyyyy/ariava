import { afterEach, describe, expect, test } from 'bun:test';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createProfileCliContext } from '../src/cli/context';
import { initializeProfile } from '../src/cli/operations/initialize';
import { resetHostDomain } from '../src/cli/operations/host-domain-reset';
import { loadHostDomainResetJournal } from '../src/cli/operations/host-domain-reset-journal';
import { createDevProfile } from '../src/cli/profiles/dev';
import type { AriavaUserConfig } from '../src/host-manager/config';
import { MacOSEncryptionKeyStore } from '../src/identity/macos-encryption-key-store';
import { MacOSKeychainHostIdentityStore } from '../src/identity/macos-keychain-store';
import { FakeKeychain } from './fixtures/fake-keychain';

const roots: string[] = [];
const originalHome = process.env.HOME;
const originalXdg = process.env.XDG_CONFIG_HOME;

afterEach(() => {
  if (originalHome === undefined) delete process.env.HOME; else process.env.HOME = originalHome;
  if (originalXdg === undefined) delete process.env.XDG_CONFIG_HOME; else process.env.XDG_CONFIG_HOME = originalXdg;
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixture() {
  const home = mkdtempSync(join(tmpdir(), 'ariava-reset-keychain-cleanup-'));
  roots.push(home);
  process.env.HOME = home;
  process.env.XDG_CONFIG_HOME = join(home, 'xdg');
  const profile = createDevProfile();
  mkdirSync(profile.resources.root, { recursive: true, mode: 0o700 });
  const keychain = new FakeKeychain();
  let config: AriavaUserConfig = {};
  let signingReplacements = 0;
  let encryptionReplacements = 0;
  const context = createProfileCliContext({
    profile,
    platform: 'darwin',
    hostName: () => 'keychain-reset-test',
    generateSecret: () => 'a'.repeat(64),
    config: {
      load: () => structuredClone(config),
      save: (next) => { config = structuredClone(next); },
    },
    identity: {
      create: (resources) => new MacOSKeychainHostIdentityStore(
        resources.identityMetadataPath, keychain, {}, resources.identityProfile,
      ),
    },
    encryptionIdentity: {
      create: (resources) => {
        const store = new MacOSEncryptionKeyStore(resources.encryptionIdentityPath, keychain);
        const replace = store.replaceForReset.bind(store);
        store.replaceForReset = (hostId, operationId) => {
          encryptionReplacements += 1;
          return replace(hostId, operationId);
        };
        return store;
      },
    },
  });
  const dependencies = {
    bridgeVersion: 'test',
    revoke: async () => 'revoked' as const,
    replace: async (store: ReturnType<typeof context.identity.create>, operationId: string) => {
      signingReplacements += 1;
      return store.resetAfterExplicitConfirmation(operationId);
    },
    enroll: async () => {},
  };
  return {
    context,
    dependencies,
    keychain,
    profile,
    counts: () => ({ signingReplacements, encryptionReplacements }),
  };
}

describe('macOS Host-domain reset exact Keychain cleanup', () => {
  test('retries exact old Ed25519 account deletion before journal completion', async () => {
    const value = fixture();
    await initializeProfile(value.context);
    const oldIdentity = await value.context.identity.create(value.profile.resources, 'darwin').load();
    const oldAccount = oldIdentity!.hostId;
    const foreignAccount = `host_${'Z'.repeat(43)}`;
    value.keychain.items.set(foreignAccount, Buffer.from('foreign-signing-key'));
    let failDelete = true;
    value.keychain.deleteResultForAccount = (account) => account === oldAccount && failDelete
      ? { status: 36, stderr: 'User interaction is not allowed.' }
      : undefined;

    await expect(resetHostDomain(value.context, value.dependencies)).rejects.toMatchObject({
      code: 'ERR_HOST_RESET_RECOVERY_REQUIRED',
      data: { phase: 'signing-replacement-pending', retryable: true },
    });
    const journal = loadHostDomainResetJournal(value.profile.resources)!;
    expect(journal.oldHostId).toBe(oldAccount);
    expect(value.keychain.snapshot(oldAccount)).toBeDefined();
    expect(value.keychain.snapshot(foreignAccount)).toEqual(Buffer.from('foreign-signing-key'));
    const replacementAfterFailure = await value.context.identity.create(value.profile.resources, 'darwin').load();

    failDelete = false;
    const result = await resetHostDomain(value.context, value.dependencies);
    expect(result.hostId).toBe(replacementAfterFailure!.hostId);
    expect(value.counts()).toEqual({ signingReplacements: 1, encryptionReplacements: 1 });
    expect(value.keychain.snapshot(oldAccount)).toBeUndefined();
    expect(value.keychain.snapshot(foreignAccount)).toEqual(Buffer.from('foreign-signing-key'));
    expect(value.keychain.callsFor(oldAccount).filter((call) => call.action === 'delete')).toHaveLength(2);
    expect(existsSync(value.profile.resources.hostDomainResetJournalPath)).toBe(false);
  });

  test('retries exact old X25519 account deletion without another replacement', async () => {
    const value = fixture();
    await initializeProfile(value.context);
    const oldEncryption = value.context.encryptionIdentity.create(value.profile.resources, 'darwin').load();
    const oldAccount = `host-e2e:${oldEncryption!.encryptionKeyId}`;
    const foreignAccount = `host-e2e:key_${'Z'.repeat(43)}`;
    value.keychain.items.set(foreignAccount, Buffer.from('foreign-encryption-key'));
    let failDelete = true;
    value.keychain.deleteResultForAccount = (account) => account === oldAccount && failDelete
      ? { status: 36, stderr: 'User interaction is not allowed.' }
      : undefined;

    await expect(resetHostDomain(value.context, value.dependencies)).rejects.toMatchObject({
      code: 'ERR_HOST_RESET_RECOVERY_REQUIRED',
      data: { phase: 'signing-identity-replaced', retryable: true },
    });
    expect(value.keychain.snapshot(oldAccount)).toBeDefined();
    expect(value.keychain.snapshot(foreignAccount)).toEqual(Buffer.from('foreign-encryption-key'));
    const replacementAfterFailure = value.context.encryptionIdentity.create(value.profile.resources, 'darwin').load();

    failDelete = false;
    const result = await resetHostDomain(value.context, value.dependencies);
    expect(result.hostId).toBe(replacementAfterFailure!.hostId);
    expect(value.counts()).toEqual({ signingReplacements: 1, encryptionReplacements: 1 });
    expect(value.keychain.snapshot(oldAccount)).toBeUndefined();
    expect(value.keychain.snapshot(foreignAccount)).toEqual(Buffer.from('foreign-encryption-key'));
    expect(value.keychain.callsFor(oldAccount).filter((call) => call.action === 'delete')).toHaveLength(2);
    expect(existsSync(value.profile.resources.hostDomainResetJournalPath)).toBe(false);
  });
  test.each([
    [{ status: 44, stderr: 'security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.' }, undefined],
    [{ status: 1, stderr: 'authorization denied; item could not be found' }, 'ERR_IDENTITY_PERMISSIONS'],
    [{ status: 44, stderr: 'authorization denied' }, 'ERR_IDENTITY_PERMISSIONS'],
  ] as const)('strictly classifies exact Ed25519 deletion result %#', (deleteResult, expectedCode) => {
    const value = fixture();
    const account = `host_${'A'.repeat(43)}`;
    value.keychain.deleteResultForAccount = (candidate) => candidate === account ? deleteResult : undefined;
    const store = new MacOSKeychainHostIdentityStore(
      value.profile.resources.identityMetadataPath, value.keychain, {}, 'dev',
    );

    if (expectedCode === undefined) {
      expect(() => store.deleteAfterHostReplacement(account)).not.toThrow();
    } else {
      expect(() => store.deleteAfterHostReplacement(account)).toThrow(expect.objectContaining({ code: expectedCode }));
    }
    expect(value.keychain.callsFor(account).filter((call) => call.action === 'delete')).toHaveLength(1);
  });

  test.each([
    [{ status: 44, stderr: 'security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.' }, undefined],
    [{ status: 1, stderr: 'authorization denied; item could not be found' }, 'ERR_IDENTITY_PERMISSIONS'],
    [{ status: 44, stderr: 'authorization denied' }, 'ERR_IDENTITY_PERMISSIONS'],
    [{ status: 36, stderr: '' }, 'ERR_IDENTITY_KEYCHAIN_LOCKED'],
    [{ status: 1, stderr: 'authorization denied' }, 'ERR_IDENTITY_PERMISSIONS'],
    [{ status: null, stderr: '', error: new Error('spawn failed') }, 'ERR_IDENTITY_PERMISSIONS'],
  ] as const)('classifies exact X25519 deletion result %#', (deleteResult, expectedCode) => {
    const value = fixture();
    const encryptionKeyId = `ekey_${'A'.repeat(43)}`;
    const account = `host-e2e:${encryptionKeyId}`;
    value.keychain.deleteResultForAccount = (candidate) => candidate === account ? deleteResult : undefined;
    const store = new MacOSEncryptionKeyStore(value.profile.resources.encryptionIdentityPath, value.keychain);

    if (expectedCode === undefined) {
      expect(() => store.deleteAfterHostReplacement(encryptionKeyId)).not.toThrow();
    } else {
      expect(() => store.deleteAfterHostReplacement(encryptionKeyId)).toThrow(expect.objectContaining({ code: expectedCode }));
    }
    expect(value.keychain.callsFor(account).filter((call) => call.action === 'delete')).toHaveLength(1);
  });

  test.each([
    [{ status: 44, stderr: 'authorization denied; item could not be found' }, 'ERR_IDENTITY_PERMISSIONS'],
    [{ status: 36, stderr: 'User interaction is not allowed.' }, 'ERR_IDENTITY_KEYCHAIN_LOCKED'],
    [{ status: 1, stderr: 'authorization denied' }, 'ERR_IDENTITY_PERMISSIONS'],
    [{ status: null, stderr: '', error: new Error('spawn failed') }, 'ERR_IDENTITY_PERMISSIONS'],
  ] as const)('classifies X25519 read failure %# without reporting missing identity', (readResult, expectedCode) => {
    const value = fixture();
    const encryptionKeyId = `ekey_${'A'.repeat(43)}`;
    const account = `host-e2e:${encryptionKeyId}`;
    const metadata = {
      version: 1, hostId: `host_${'B'.repeat(43)}`, encryptionKeyId,
      publicKey: 'A'.repeat(43), sequence: 1, createdAt: '2026-08-11T00:00:00.000Z', account,
    };
    writeFileSync(
      value.profile.resources.encryptionIdentityPath, JSON.stringify(metadata), { mode: 0o600 },
    );
    value.keychain.readResultForAccount = (candidate) => candidate === account ? readResult : undefined;
    const store = new MacOSEncryptionKeyStore(value.profile.resources.encryptionIdentityPath, value.keychain);

    expect(() => store.load()).toThrow(expect.objectContaining({ code: expectedCode }));
  });

});
