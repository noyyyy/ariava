import test from 'node:test';
import assert from 'node:assert/strict';
import { lstatSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  LocalEncryptedSpool,
  LinuxSpoolKeyStore,
  MacOSSpoolKeyStore,
  spoolKeyIdForKey,
} from '../dist/e2e/local-spool.js';

test('production Node seals local retry spool without plaintext persistence', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ariava-node-spool-'));
  try {
    const path = join(dir, 'spool.json');
    const spool = new LocalEncryptedSpool(path, 'host-test', new LinuxSpoolKeyStore(join(dir, 'key.json')));
    spool.enqueue({ spoolItemId: 'item', sessionId: 'session', eventId: 'event', payloadKind: 'event-upload-v2',
      createdAt: '2026-07-20T00:00:00.000Z', plaintext: new TextEncoder().encode('NODE_SPOOL_SECRET_MARKER') });
    assert.doesNotMatch(readFileSync(path, 'utf8'), /NODE_SPOOL_SECRET_MARKER/);
    assert.equal(new TextDecoder().decode(spool.open(spool.list()[0])), 'NODE_SPOOL_SECRET_MARKER');
    assert.throws(() => spool.open({ ...spool.list()[0], sessionId: 'moved' }));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('recovery preserves every byte across a transient key-store outage and succeeds on retry', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ariava-node-spool-outage-'));
  try {
    const path = join(dir, 'spool.json');
    const key = new Uint8Array(32).fill(9);
    const spool = new LocalEncryptedSpool(path, 'host-test', { loadOrCreate: () => new Uint8Array(key) });
    spool.enqueue({ spoolItemId: 'item', sessionId: 'session', eventId: 'event', payloadKind: 'event-upload-v2',
      createdAt: '2026-07-20T00:00:00.000Z', plaintext: new TextEncoder().encode('RETRY_ME') });
    const before = readFileSync(path);
    let unavailable = true;
    const restarted = new LocalEncryptedSpool(path, 'host-test', { loadOrCreate: () => {
      if (unavailable) throw new Error('temporary key-store outage');
      return new Uint8Array(key);
    } });
    assert.throws(() => restarted.recoverUnreadable(), /recovery is required/);
    assert.deepEqual(readFileSync(path), before);
    assert.equal(restarted.list().length, 1);
    unavailable = false;
    assert.deepEqual(restarted.recoverUnreadable(), { droppedUnreadableItems: 0 });
    assert.equal(new TextDecoder().decode(restarted.open(restarted.list()[0])), 'RETRY_ME');
    assert.deepEqual(readFileSync(path), before);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('recovery quarantines only ciphertext that fails authentication with a known-good key', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ariava-node-spool-corrupt-'));
  try {
    const path = join(dir, 'spool.json');
    const keyStore = { loadOrCreate: () => new Uint8Array(32).fill(9) };
    const spool = new LocalEncryptedSpool(path, 'host-test', keyStore);
    for (const id of ['good', 'bad']) spool.enqueue({ spoolItemId: id, sessionId: 'session', eventId: id,
      payloadKind: 'event-upload-v2', createdAt: '2026-07-20T00:00:00.000Z', plaintext: new TextEncoder().encode(id) });
    const file = JSON.parse(readFileSync(path, 'utf8'));
    const corrupt = file.items.find((item) => item.spoolItemId === 'bad');
    const bytes = Buffer.from(corrupt.ciphertext, 'base64url');
    bytes[bytes.length - 1] ^= 1;
    corrupt.ciphertext = bytes.toString('base64url');
    const serialized = `${JSON.stringify(file)}\n`;
    writeFileSync(path, serialized, { mode: 0o600 });
    const restarted = new LocalEncryptedSpool(path, 'host-test', keyStore);
    assert.deepEqual(restarted.recoverUnreadable(), { droppedUnreadableItems: 1 });
    assert.deepEqual(restarted.list().map((item) => item.spoolItemId), ['good']);
    assert.equal(new TextDecoder().decode(restarted.open(restarted.list()[0])), 'good');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('missing Linux key never creates a replacement and restored-key retry preserves exact spool bytes', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ariava-node-spool-missing-key-'));
  try {
    const path = join(dir, 'spool.json');
    const keyPath = join(dir, 'key.json');
    const backupPath = join(dir, 'key.backup.json');
    const spool = new LocalEncryptedSpool(path, 'host-test', new LinuxSpoolKeyStore(keyPath));
    spool.enqueue({ spoolItemId: 'item', sessionId: 'session', eventId: 'event', payloadKind: 'event-upload-v2',
      createdAt: '2026-07-20T00:00:00.000Z', plaintext: new TextEncoder().encode('RESTORE_ME') });
    const spoolBytes = readFileSync(path);
    const keyBytes = readFileSync(keyPath);
    renameSync(keyPath, backupPath);
    const restarted = new LocalEncryptedSpool(path, 'host-test', new LinuxSpoolKeyStore(keyPath));
    assert.throws(() => restarted.recoverUnreadable(), /key is missing; recovery is required/);
    assert.throws(() => readFileSync(keyPath), /ENOENT/);
    assert.deepEqual(readFileSync(path), spoolBytes);
    writeFileSync(keyPath, keyBytes, { mode: 0o600 });
    assert.deepEqual(restarted.recoverUnreadable(), { droppedUnreadableItems: 0 });
    assert.equal(new TextDecoder().decode(restarted.open(restarted.list()[0])), 'RESTORE_ME');
    assert.deepEqual(readFileSync(path), spoolBytes);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('replaced Linux key fails before item quarantine and original-key retry restores every item exactly', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ariava-node-spool-replaced-key-'));
  try {
    const path = join(dir, 'spool.json');
    const keyPath = join(dir, 'key.json');
    const spool = new LocalEncryptedSpool(path, 'host-test', new LinuxSpoolKeyStore(keyPath));
    for (const id of ['one', 'two']) spool.enqueue({ spoolItemId: id, sessionId: 'session', eventId: id,
      payloadKind: 'event-upload-v2', createdAt: '2026-07-20T00:00:00.000Z', plaintext: new TextEncoder().encode(id) });
    const spoolBytes = readFileSync(path);
    const keyBytes = readFileSync(keyPath);
    rmSync(keyPath);
    const replacementSpool = new LocalEncryptedSpool(join(dir, 'replacement-spool.json'), 'host-test', new LinuxSpoolKeyStore(keyPath));
    replacementSpool.enqueue({ spoolItemId: 'replacement', sessionId: 'session', eventId: 'replacement', payloadKind: 'event-upload-v2',
      createdAt: '2026-07-20T00:00:00.000Z', plaintext: new TextEncoder().encode('replacement') });
    const restarted = new LocalEncryptedSpool(path, 'host-test', new LinuxSpoolKeyStore(keyPath));
    assert.throws(() => restarted.recoverUnreadable(), /recovery is required/);
    assert.deepEqual(readFileSync(path), spoolBytes);
    assert.deepEqual(restarted.list().map((item) => item.spoolItemId), ['one', 'two']);
    writeFileSync(keyPath, keyBytes, { mode: 0o600 });
    assert.deepEqual(restarted.recoverUnreadable(), { droppedUnreadableItems: 0 });
    assert.deepEqual(restarted.list().map((item) => item.spoolItemId), ['one', 'two']);
    assert.deepEqual(readFileSync(path), spoolBytes);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('empty persisted spool never creates a replacement Linux key and restored key recovers exact bytes', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ariava-node-spool-empty-key-'));
  try {
    const path = join(dir, 'spool.json'); const keyPath = join(dir, 'key.json'); const backupPath = join(dir, 'key.backup.json');
    const initial = new LocalEncryptedSpool(path, 'host-test', new LinuxSpoolKeyStore(keyPath));
    initial.enqueue({ spoolItemId: 'item', sessionId: 'session', eventId: 'event', payloadKind: 'event-upload-v2',
      createdAt: '2026-07-20T00:00:00.000Z', plaintext: new TextEncoder().encode('temporary') });
    initial.remove('item');
    const spoolBytes = readFileSync(path); const keyBytes = readFileSync(keyPath);
    renameSync(keyPath, backupPath);
    const restarted = new LocalEncryptedSpool(path, 'host-test', new LinuxSpoolKeyStore(keyPath));
    assert.throws(() => restarted.recoverUnreadable(), /key is missing; recovery is required/);
    assert.equal(lstatSync(keyPath, { throwIfNoEntry: false }), undefined);
    assert.deepEqual(readFileSync(path), spoolBytes);
    writeFileSync(keyPath, keyBytes, { mode: 0o600 });
    assert.deepEqual(restarted.recoverUnreadable(), { droppedUnreadableItems: 0 });
    assert.deepEqual(readFileSync(path), spoolBytes);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

class FakeMacKeychain {
  items = new Map();
  writes = 0;
  run(_command, args, stdin) {
    if (args[0] === 'find-generic-password') {
      const value = this.items.get(args[args.indexOf('-a') + 1]);
      return value ? { status: 0, stdout: Buffer.from(`${Buffer.from(value).toString('hex')}\n`), stderr: '' }
        : { status: 44, stdout: new Uint8Array(), stderr: 'missing' };
    }
    if (args[0] === '-i' && stdin) {
      const script = Buffer.from(stdin).toString('utf8');
      const account = /-a '([^']+)'/u.exec(script)?.[1]; const hex = /-X ([0-9a-f]+)/u.exec(script)?.[1];
      if (!account || !hex || this.items.has(account)) return { status: 45, stdout: new Uint8Array(), stderr: 'exists' };
      this.items.set(account, Buffer.from(hex, 'hex')); this.writes += 1;
      return { status: 0, stdout: new Uint8Array(), stderr: '' };
    }
    return { status: 1, stdout: new Uint8Array(), stderr: 'unsupported' };
  }
}

test('macOS Keychain insertion crash reconstructs evidence without replacing the key and replays idempotently', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ariava-node-spool-macos-crash-'));
  try {
    const evidencePath = join(dir, 'spool-evidence.json'); const runner = new FakeMacKeychain();
    const crashing = new MacOSSpoolKeyStore(evidencePath, runner, { afterTemporaryWrite: () => { throw new Error('crash'); } });
    assert.throws(() => crashing.loadOrCreate('host-test'), /atomic write failed/);
    const account = 'host-spool:host-test'; const original = Buffer.from(runner.items.get(account));
    assert.equal(runner.writes, 1); assert.equal(lstatSync(evidencePath, { throwIfNoEntry: false }), undefined);
    const recovered = new MacOSSpoolKeyStore(evidencePath, runner).loadOrCreate('host-test');
    assert.deepEqual(Buffer.from(recovered), original); assert.equal(runner.writes, 1);
    const evidenceBytes = readFileSync(evidencePath);
    const replay = new MacOSSpoolKeyStore(evidencePath, runner).loadOrCreate('host-test');
    assert.deepEqual(Buffer.from(replay), original); assert.deepEqual(readFileSync(evidencePath), evidenceBytes);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('macOS spool evidence mismatch and fsync/promotion failures fail closed without key replacement', () => {
  for (const boundary of ['afterFileSync', 'afterPromotion', 'afterDirectorySync']) {
    const dir = mkdtempSync(join(tmpdir(), `ariava-node-spool-macos-${boundary}-`));
    try {
      const evidencePath = join(dir, 'spool-evidence.json'); const runner = new FakeMacKeychain();
      const account = 'host-spool:host-test'; const original = Buffer.alloc(32, 7); runner.items.set(account, original);
      const store = new MacOSSpoolKeyStore(evidencePath, runner, { [boundary]: () => { throw new Error(boundary); } });
      assert.throws(() => store.loadOrCreate('host-test'), /recovery failed/);
      assert.deepEqual(runner.items.get(account), original); assert.equal(runner.writes, 0);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }
  const dir = mkdtempSync(join(tmpdir(), 'ariava-node-spool-macos-mismatch-'));
  try {
    const evidencePath = join(dir, 'spool-evidence.json'); const runner = new FakeMacKeychain();
    const account = 'host-spool:host-test'; const original = Buffer.alloc(32, 7); runner.items.set(account, original);
    writeFileSync(evidencePath, `${JSON.stringify({ version: 2, hostId: 'host-test', account, keyId: spoolKeyIdForKey(Buffer.alloc(32, 8)) })}\n`, { mode: 0o600 });
    const before = readFileSync(evidencePath);
    assert.throws(() => new MacOSSpoolKeyStore(evidencePath, runner).loadOrCreate('host-test'), /metadata is invalid/);
    assert.deepEqual(runner.items.get(account), original); assert.deepEqual(readFileSync(evidencePath), before);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
