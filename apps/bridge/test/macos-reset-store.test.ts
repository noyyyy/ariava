import { afterEach, describe, expect, test } from 'bun:test';
import { chmodSync, existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MacOSEncryptionKeyStore } from '../src/identity/macos-encryption-key-store';
import {
  MACOS_IDENTITY_EVIDENCE_ACCOUNTS,
  MacOSKeychainHostIdentityStore,
} from '../src/identity/macos-keychain-store';
import { FakeKeychain } from './fixtures/fake-keychain';

const roots: string[] = [];
function pathFor(name: string): string {
  const root = mkdtempSync(join(tmpdir(), 'ariava-macos-reset-store-'));
  chmodSync(root, 0o700);
  roots.push(root);
  return join(root, name);
}
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

describe('macOS reset store crash recovery', () => {
  test('Ed25519 retry adopts the operation-bound candidate inserted before metadata', async () => {
    const keychain = new FakeKeychain();
    const path = pathFor('identity.json');
    const initial = new MacOSKeychainHostIdentityStore(path, keychain);
    const oldIdentity = await initial.createFirstRun();
    let interrupted = false;
    const crashing = new MacOSKeychainHostIdentityStore(path, keychain, {
      afterResetKeyWrite() { interrupted = true; throw new Error('crash after reset key insertion'); },
    });

    await expect(crashing.resetAfterExplicitConfirmation('reset_operation_1')).rejects.toThrow('crash after reset key insertion');
    expect(interrupted).toBe(true);
    const candidateAccounts = [...keychain.items.keys()].filter((account) => account.startsWith('host_') && account !== oldIdentity.hostId);
    expect(candidateAccounts).toHaveLength(1);
    const candidateAccount = candidateAccounts[0]!;

    const restarted = new MacOSKeychainHostIdentityStore(path, keychain);
    const replacement = await restarted.resetAfterExplicitConfirmation('reset_operation_1');
    expect(replacement.hostId).toBe(candidateAccount);
    expect(keychain.items.has(oldIdentity.hostId)).toBe(false);
    expect([...keychain.items.keys()].sort()).toEqual([
      MACOS_IDENTITY_EVIDENCE_ACCOUNTS.default,
      candidateAccount,
    ].sort());
    expect((await restarted.recoverExplicitReset('reset_operation_1'))?.hostId).toBe(candidateAccount);
    restarted.completeExplicitReset('reset_operation_1');
    expect(existsSync(`${path}.resetting`)).toBe(false);
  });

  test('X25519 retry adopts the operation-bound candidate inserted before metadata', () => {
    const keychain = new FakeKeychain();
    const path = pathFor('identity.e2e.json');
    const oldHostId = `host_${'A'.repeat(43)}`;
    const newHostId = `host_${'B'.repeat(43)}`;
    const initial = new MacOSEncryptionKeyStore(path, keychain);
    const oldIdentity = initial.loadOrCreate(oldHostId);
    const crashing = new MacOSEncryptionKeyStore(path, keychain, {
      afterResetKeyWrite() { throw new Error('crash after encryption key insertion'); },
    });

    expect(() => crashing.replaceForReset(newHostId, 'reset_operation_2')).toThrow('crash after encryption key insertion');
    const candidateAccounts = [...keychain.items.keys()].filter((account) => account.startsWith('host-e2e:') && account !== `host-e2e:${oldIdentity.encryptionKeyId}`);
    expect(candidateAccounts).toHaveLength(1);
    const candidateAccount = candidateAccounts[0]!;

    const restarted = new MacOSEncryptionKeyStore(path, keychain);
    const replacement = restarted.replaceForReset(newHostId, 'reset_operation_2');
    expect(`host-e2e:${replacement.encryptionKeyId}`).toBe(candidateAccount);
    expect(keychain.items.has(`host-e2e:${oldIdentity.encryptionKeyId}`)).toBe(false);
    expect([...keychain.items.keys()]).toEqual([candidateAccount]);
    restarted.completeReset('reset_operation_2');
    expect(existsSync(`${path}.resetting`)).toBe(false);
  });

  test('malformed reset sentinels fail closed before Keychain mutation', async () => {
    const keychain = new FakeKeychain();
    const path = pathFor('identity.json');
    const store = new MacOSKeychainHostIdentityStore(path, keychain);
    await store.createFirstRun();
    writeFileSync(`${path}.resetting`, '{"schema":"unsafe"}\n', { mode: 0o600 });
    keychain.resetCalls();

    await expect(store.resetAfterExplicitConfirmation('reset_operation_3')).rejects.toMatchObject({ code: 'ERR_IDENTITY_RESET_REQUIRED' });
    expect(keychain.calls).toHaveLength(0);
  });
});
