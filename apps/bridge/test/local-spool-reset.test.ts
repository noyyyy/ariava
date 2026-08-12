import { afterEach, describe, expect, test } from 'bun:test';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { base64UrlEncode } from '@ariava/protocol';
import {
  LinuxSpoolKeyStore,
  MacOSSpoolKeyStore,
  spoolKeyIdForKey,
} from '../src/e2e/local-spool';
import { FakeKeychain } from './fixtures/fake-keychain';

const roots: string[] = [];
const hostId = `host_${'A'.repeat(43)}`;
const otherHostId = `host_${'B'.repeat(43)}`;
const key = new Uint8Array(32).fill(7);

function root(): string {
  const value = mkdtempSync(join(tmpdir(), 'ariava-spool-reset-'));
  chmodSync(value, 0o700);
  roots.push(value);
  return value;
}
afterEach(() => { for (const value of roots.splice(0)) rmSync(value, { recursive: true, force: true }); });

describe('Host replacement local-spool key removal', () => {
  test('removes exact valid Linux v1 and v2 records and treats absence idempotently', () => {
    for (const record of [
      { version: 1, hostId, key: base64UrlEncode(key) },
      { version: 2, hostId, keyId: spoolKeyIdForKey(key), key: base64UrlEncode(key) },
    ]) {
      const path = join(root(), 'host.spool-key.json');
      writeFileSync(path, JSON.stringify(record), { mode: 0o600 });
      const store = new LinuxSpoolKeyStore(path);
      store.removeForHostReplacement(hostId);
      expect(existsSync(path)).toBe(false);
      expect(() => store.removeForHostReplacement(hostId)).not.toThrow();
    }
  });

  test('Linux rejects mismatched, malformed, unknown, invalid, and unsafe evidence without deletion', () => {
    const cases: Array<[string, unknown]> = [
      ['host mismatch', { version: 1, hostId: otherHostId, key: base64UrlEncode(key) }],
      ['unknown', { version: 1, hostId, key: base64UrlEncode(key), extra: true }],
      ['invalid key', { version: 1, hostId, key: 'bad' }],
      ['invalid key ID', { version: 2, hostId, keyId: 'bad', key: base64UrlEncode(key) }],
    ];
    for (const [label, record] of cases) {
      const path = join(root(), 'host.spool-key.json');
      writeFileSync(path, JSON.stringify(record), { mode: 0o600 });
      expect(() => new LinuxSpoolKeyStore(path).removeForHostReplacement(hostId), label).toThrow();
      expect(existsSync(path), label).toBe(true);
    }

    const permissive = join(root(), 'permissive.json');
    writeFileSync(permissive, JSON.stringify({ version: 1, hostId, key: base64UrlEncode(key) }), { mode: 0o644 });
    expect(() => new LinuxSpoolKeyStore(permissive).removeForHostReplacement(hostId)).toThrow();
    expect(existsSync(permissive)).toBe(true);

    const target = join(root(), 'target.json');
    writeFileSync(target, JSON.stringify({ version: 1, hostId, key: base64UrlEncode(key) }), { mode: 0o600 });
    const link = join(root(), 'link.json');
    symlinkSync(target, link);
    expect(() => new LinuxSpoolKeyStore(link).removeForHostReplacement(hostId)).toThrow();
    expect(readFileSync(target, 'utf8')).toContain(hostId);

    const directory = join(root(), 'directory.json');
    mkdirSync(directory, { mode: 0o700 });
    expect(() => new LinuxSpoolKeyStore(directory).removeForHostReplacement(hostId)).toThrow();
    expect(existsSync(directory)).toBe(true);
  });

  test('Linux foreign-owner spool key fails closed through injected uid', () => {
    const path = join(root(), 'foreign-owner.json');
    writeFileSync(path, JSON.stringify({ version: 1, hostId, key: base64UrlEncode(key) }), { mode: 0o600 });
    const foreignUid = (process.getuid?.() ?? 0) + 1;
    expect(() => new LinuxSpoolKeyStore(path, foreignUid).removeForHostReplacement(hostId)).toThrow();
    expect(existsSync(path)).toBe(true);
    expect(readFileSync(path, 'utf8')).toContain(hostId);
  });

  test('macOS deletes only the exact evidence account then removes evidence', () => {
    for (const version of [1, 2] as const) {
      const evidencePath = join(root(), 'host.spool.json');
      const account = `host-spool:${hostId}`;
      const evidence = version === 1
        ? { version, hostId, account }
        : { version, hostId, account, keyId: spoolKeyIdForKey(key) };
      writeFileSync(evidencePath, JSON.stringify(evidence), { mode: 0o600 });
      const keychain = new FakeKeychain();
      keychain.items.set(account, key);

      new MacOSSpoolKeyStore(evidencePath, keychain).removeForHostReplacement(hostId);

      expect(keychain.calls).toHaveLength(1);
      expect(keychain.calls[0]).toMatchObject({
        action: 'delete',
        args: ['delete-generic-password', '-s', 'io.noyx.ariava.local-spool-v1', '-a', account],
        account,
      });
      expect(keychain.items.has(account)).toBe(false);
      expect(existsSync(evidencePath)).toBe(false);
    }
  });

  test('macOS accepts only definitive absence and retains evidence on uncertain failure', () => {
    const account = `host-spool:${hostId}`;
    const makeEvidence = (): string => {
      const path = join(root(), 'host.spool.json');
      writeFileSync(path, JSON.stringify({ version: 1, hostId, account }), { mode: 0o600 });
      return path;
    };

    const missingPath = makeEvidence();
    const missing = new FakeKeychain();
    missing.deleteResult = {
      status: 44,
      stderr: 'security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.',
    };
    new MacOSSpoolKeyStore(missingPath, missing).removeForHostReplacement(hostId);
    expect(existsSync(missingPath)).toBe(false);

    for (const result of [
      { status: 36, stderr: 'User interaction is not allowed.' },
      { status: 1, stderr: 'ambiguous failure' },
      { status: 44, stderr: 'different status text' },
      { status: 44, stderr: 'authorization denied; item could not be found' },
    ]) {
      const evidencePath = makeEvidence();
      const keychain = new FakeKeychain();
      keychain.deleteResult = result;
      expect(() => new MacOSSpoolKeyStore(evidencePath, keychain).removeForHostReplacement(hostId)).toThrow();
      expect(existsSync(evidencePath)).toBe(true);
    }
  });

  test('macOS removes well-formed historical evidence without deleting its unrelated Keychain item', () => {
    for (const version of [1, 2] as const) {
      const evidencePath = join(root(), 'host.spool.json');
      const account = `host-spool:${otherHostId}`;
      const evidence = version === 1
        ? { version, hostId: otherHostId, account }
        : { version, hostId: otherHostId, account, keyId: spoolKeyIdForKey(key) };
      writeFileSync(evidencePath, JSON.stringify(evidence), { mode: 0o600 });
      const keychain = new FakeKeychain();
      keychain.items.set(account, key);

      new MacOSSpoolKeyStore(evidencePath, keychain).removeForHostReplacement(hostId);

      expect(keychain.calls).toHaveLength(0);
      expect(keychain.items.has(account)).toBe(true);
      expect(existsSync(evidencePath)).toBe(false);
    }
  });

  test('macOS without trusted old Host proof removes only well-formed evidence', () => {
    const evidencePath = join(root(), 'host.spool.json');
    const account = `host-spool:${hostId}`;
    writeFileSync(evidencePath, JSON.stringify({ version: 1, hostId, account }), { mode: 0o600 });
    const keychain = new FakeKeychain();
    keychain.items.set(account, key);

    new MacOSSpoolKeyStore(evidencePath, keychain).removeForHostReplacement();

    expect(keychain.calls).toHaveLength(0);
    expect(keychain.items.has(account)).toBe(true);
    expect(existsSync(evidencePath)).toBe(false);
  });

  test('macOS rejects malformed evidence before Keychain access', () => {
    const evidencePath = join(root(), 'host.spool.json');
    const keychain = new FakeKeychain();
    for (const evidence of [
      { version: 1, hostId, account: `host-spool:${otherHostId}` },
      { version: 1, hostId, account: `host-spool:${hostId}`, extra: true },
      { version: 2, hostId, account: `host-spool:${hostId}`, keyId: 'invalid' },
    ]) {
      writeFileSync(evidencePath, JSON.stringify(evidence), { mode: 0o600 });
      expect(() => new MacOSSpoolKeyStore(evidencePath, keychain).removeForHostReplacement(hostId)).toThrow();
      expect(keychain.calls).toHaveLength(0);
      expect(existsSync(evidencePath)).toBe(true);
    }
  });
});

describe('macOS local-spool initial read classification', () => {
  test.each([
    ['locked', { status: 36, stderr: 'User interaction is not allowed.' }],
    ['authorization', { status: 1, stderr: 'authorization denied' }],
    ['spawn', { status: null, stderr: '', error: new Error('spawn failed') }],
    ['contradictory 44', { status: 44, stderr: 'authorization denied; item could not be found' }],
    ['noncanonical 44', { status: 44, stderr: 'different status text' }],
  ] as const)('%s fails before writes or evidence mutation', (_label, readResult) => {
    const evidencePath = join(root(), 'host.spool.json');
    const keychain = new FakeKeychain();
    keychain.readResultForAccount = () => readResult;
    const store = new MacOSSpoolKeyStore(evidencePath, keychain);

    expect(() => store.loadOrCreate(hostId)).toThrow(/read is uncertain/);
    expect(keychain.calls.filter((call) => call.action === 'write')).toHaveLength(0);
    expect(existsSync(evidencePath)).toBe(false);
  });
});
