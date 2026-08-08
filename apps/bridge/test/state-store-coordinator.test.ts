import { afterEach, describe, expect, test } from 'bun:test';
import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { CanonicalSessionState, HostProjection } from '@ariava/protocol';
import { acquireRuntimeCoordinator, RUNTIME_COORDINATOR_ACTIVE_ERROR } from '../src/runtime-lock';
import { BridgeStateStore } from '../src/state-store';

const roots: string[] = [];
const stores: BridgeStateStore[] = [];

function root(name: string): string {
  const path = mkdtempSync(join(tmpdir(), `ariava-state-coordinator-${name}-`));
  chmodSync(path, 0o700);
  roots.push(path);
  return path;
}

function open(path: string): BridgeStateStore {
  const store = new BridgeStateStore(path);
  stores.push(store);
  return store;
}

function host(): HostProjection {
  return {
    hostId: 'host-1', hostName: 'Host A', platform: 'linux', bridgeVersion: 'test',
    registeredAt: '2026-08-08T00:00:00.000Z', lastSeenAt: '2026-08-08T00:00:01.000Z', bridgeStatus: 'online',
  };
}

function session(): CanonicalSessionState {
  return {
    sessionId: 'session-1', hostId: 'host-1', provider: 'pi', projectName: 'project', nameText: 'Session A',
    status: 'idle', updatedAt: '2026-08-08T00:00:01.000Z',
  };
}

afterEach(() => {
  for (const store of stores.splice(0)) store.dispose();
  for (const path of roots.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe('same-process Bridge state coordinator', () => {
  test('rejects a symlink-equivalent second store without overwriting and reopens persisted state after disposal', () => {
    const runtimeRoot = root('alias');
    const aliasRoot = `${runtimeRoot}-alias`;
    roots.push(aliasRoot);
    symlinkSync(runtimeRoot, aliasRoot, 'dir');
    const statePath = join(runtimeRoot, 'state.json');
    const aliasStatePath = join(aliasRoot, 'state.json');
    const first = open(statePath);
    first.setHost(host());
    first.replaceDriverSessions('pi', [session()]);

    expect(() => new BridgeStateStore(aliasStatePath)).toThrow(RUNTIME_COORDINATOR_ACTIVE_ERROR);
    expect(first.getHost()?.hostId).toBe('host-1');
    expect(first.listSessions().map((value) => value.sessionId)).toEqual(['session-1']);

    first.dispose();
    const reopened = open(statePath);
    expect(reopened.getHost()).toEqual(host());
    expect(reopened.listSessions()).toEqual([session()]);
  });

  test('allows exactly one of two concurrent constructions for one runtime', async () => {
    const statePath = join(root('concurrent'), 'state.json');
    const results = await Promise.allSettled([
      Promise.resolve().then(() => open(statePath)),
      Promise.resolve().then(() => open(statePath)),
    ]);
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    const rejected = results.find((result) => result.status === 'rejected');
    expect(rejected).toMatchObject({ status: 'rejected', reason: expect.objectContaining({ message: RUNTIME_COORDINATOR_ACTIVE_ERROR }) });
  });

  test('constructor failure releases coordinator registration and runtime lock', () => {
    const statePath = join(root('constructor-failure'), 'state.json');
    writeFileSync(statePath, '{invalid json', { mode: 0o600 });
    expect(() => new BridgeStateStore(statePath)).toThrow('Bridge state file is invalid or insecure');
    rmSync(statePath);

    const replacement = open(statePath);
    replacement.setHost(host());
    expect(replacement.getHost()).toEqual(host());
  });

  test('explicit coordinator remains registered until its owner disposes it', () => {
    const statePath = join(root('explicit'), 'state.json');
    const coordinator = acquireRuntimeCoordinator(statePath);
    const store = new BridgeStateStore(statePath, undefined, { runtimeCoordinator: coordinator });
    stores.push(store);
    store.setHost(host());
    store.dispose();
    expect(() => new BridgeStateStore(statePath)).toThrow(RUNTIME_COORDINATOR_ACTIVE_ERROR);
    coordinator.dispose();
    const reopened = open(statePath);
    expect(reopened.getHost()).toEqual(host());
  });


  test('keeps separate runtime paths and pathless in-memory stores independent', () => {
    const runtimeRoot = root('separate');
    const first = open(join(runtimeRoot, 'first.json'));
    const second = open(join(runtimeRoot, 'second.json'));
    first.setHost(host());
    expect(second.getHost()).toBeNull();

    const memoryA = new BridgeStateStore('', () => {});
    const memoryB = new BridgeStateStore('', () => {});
    stores.push(memoryA, memoryB);
    expect(memoryA.listSessions()).toEqual([]);
    expect(memoryB.listSessions()).toEqual([]);
  });
});
