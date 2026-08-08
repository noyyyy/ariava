import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, lstatSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { acquireRuntimeLock, runtimeLockPathForState } from '../dist/runtime-lock.js';
import { BridgeDaemon } from '../dist/daemon.js';
import { BridgeStateStore } from '../dist/state-store.js';

function dependencies(pid, processStart, inspection) {
  return {
    uid: process.getuid(), pid, now: () => new Date('2026-08-08T00:00:00.000Z'),
    ownerToken: () => 'a'.repeat(48), currentProcessStart: () => processStart,
    inspector: { inspect: () => inspection },
  };
}

function config(root) {
  return {
    hostId: 'host-test', hostName: 'test', hostPlatform: 'linux', relayBaseUrl: 'http://relay.invalid',
    statePath: join(root, 'state.json'), identityPath: join(root, 'identity.json'), configPath: join(root, 'config.json'),
    runtimePlatform: 'linux', pollIntervalMs: 60_000, bridgeVersion: 'test',
    agentAdapter: { port: 0, secret: 'test', configPath: join(root, 'adapter.json') },
  };
}

test('runtime lock is owner-only, token-owned, and rejects a second daemon and ordinary writer', () => {
  const root = mkdtempSync(join(tmpdir(), 'ariava-runtime-lock-exclusive-')); chmodSync(root, 0o700);
  try {
    const first = new BridgeDaemon(config(root), []);
    const lockPath = runtimeLockPathForState(config(root).statePath);
    const stat = lstatSync(lockPath); assert.equal(stat.mode & 0o777, 0o600);
    assert.throws(() => new BridgeDaemon(config(root), []), /runtime lock/i);
    assert.throws(() => new BridgeStateStore(config(root).statePath), /runtime lock/i);
    first.stop();
    assert.equal(lstatSync(lockPath, { throwIfNoEntry: false }), undefined);
    const replacement = new BridgeDaemon(config(root), []); replacement.stop();
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('runtime lock release rejects token replacement without deleting the replacement', () => {
  const root = mkdtempSync(join(tmpdir(), 'ariava-runtime-lock-token-')); chmodSync(root, 0o700);
  try {
    const statePath = join(root, 'state.json');
    const lock = acquireRuntimeLock(statePath, dependencies(101, 'start-a', { status: 'alive', processStart: 'start-a' }));
    const replacement = { ...lock.record, ownerToken: 'b'.repeat(48) };
    writeFileSync(lock.path, `${JSON.stringify(replacement)}\n`, { mode: 0o600 });
    assert.throws(() => lock.release(), /runtime lock/i);
    assert.deepEqual(JSON.parse(readFileSync(lock.path, 'utf8')), replacement);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('runtime lock stale recovery requires demonstrably gone process identity and fails closed on ambiguity', () => {
  for (const inspection of [{ status: 'absent' }, { status: 'alive', processStart: 'reused-start' }]) {
    const root = mkdtempSync(join(tmpdir(), 'ariava-runtime-lock-stale-')); chmodSync(root, 0o700);
    try {
      const statePath = join(root, 'state.json'); const path = runtimeLockPathForState(statePath);
      writeFileSync(path, `${JSON.stringify({ schemaVersion: 1, pid: 100, processStart: 'old-start', createdAt: '2026-08-07T00:00:00.000Z', ownerToken: 'c'.repeat(48) })}\n`, { mode: 0o600 });
      const lock = acquireRuntimeLock(statePath, dependencies(101, 'new-start', inspection));
      assert.equal(lock.record.processStart, 'new-start'); lock.release();
    } finally { rmSync(root, { recursive: true, force: true }); }
  }
  for (const mode of ['unprovable', 'symlink', 'permissions']) {
    const root = mkdtempSync(join(tmpdir(), 'ariava-runtime-lock-closed-')); chmodSync(root, 0o700);
    try {
      const statePath = join(root, 'state.json'); const path = runtimeLockPathForState(statePath);
      const bytes = `${JSON.stringify({ schemaVersion: 1, pid: 100, processStart: 'old-start', createdAt: '2026-08-07T00:00:00.000Z', ownerToken: 'c'.repeat(48) })}\n`;
      if (mode === 'symlink') { writeFileSync(`${path}.real`, bytes, { mode: 0o600 }); symlinkSync(`${path}.real`, path); }
      else writeFileSync(path, bytes, { mode: mode === 'permissions' ? 0o644 : 0o600 });
      const before = readFileSync(path);
      assert.throws(() => acquireRuntimeLock(statePath, dependencies(101, 'new-start', { status: 'unprovable' })), /runtime lock/i);
      assert.deepEqual(readFileSync(path), before);
    } finally { rmSync(root, { recursive: true, force: true }); }
  }
});
