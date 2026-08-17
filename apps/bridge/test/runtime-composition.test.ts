import { afterEach, describe, expect, test } from 'bun:test';
import { existsSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadBridgeConfig } from '../src/daemon';
import {
  createBridgeDaemonShell,
  type BridgeDaemonShell,
} from '../src/daemon/runtime-composition';
import { AgentAdapterClient } from '../src/agent-adapter/client';
import { AgentAdapterServer } from '../src/agent-adapter/server';
import { CommandRouter } from '../src/command-router';
import { BridgeStateStore } from '../src/state-store';
import type { BridgeConfig } from '../src/types';

const roots: string[] = [];
const shells: BridgeDaemonShell[] = [];

afterEach(() => {
  for (const shell of shells.splice(0)) {
    shell.stateStore.dispose();
    shell.runtimeCoordinator.dispose();
  }
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function fixture(name: string): { root: string; statePath: string; config: BridgeConfig } {
  const root = join(tmpdir(), `bridge-runtime-composition-${name}-${Date.now()}-${roots.length}`);
  roots.push(root);
  mkdirSync(root, { mode: 0o700 });
  const statePath = join(root, 'state.json');
  const config = loadBridgeConfig();
  Object.assign(config, {
    hostId: `host-${name}`,
    statePath,
    identityPath: join(root, 'identity.json'),
    configPath: join(root, 'config.json'),
    relayBaseUrl: 'http://relay.invalid',
    agentAdapter: { ...config.agentAdapter, port: 0, configPath: join(root, 'adapter.json') },
  });
  return { root, statePath, config };
}

describe('createBridgeDaemonShell', () => {
  test('post-coordinator/pre-store failure disposes the claimed coordinator exactly once and leaks no claim', () => {
    const { root, statePath, config } = fixture('pre-store');
    const order: string[] = [];
    let coordinatorDisposes = 0;
    let seamCalls = 0;
    expect(() => createBridgeDaemonShell({
      config,
      onRegistryMutation: () => {},
      hooks: {
        beforeStateStoreConstruction: (coordinator) => {
          seamCalls += 1;
          const original = coordinator.dispose.bind(coordinator);
          coordinator.dispose = () => {
            coordinatorDisposes += 1;
            order.push('coordinator');
            original();
          };
          throw new Error('injected pre-store failure');
        },
      },
    })).toThrow('injected pre-store failure');
    expect(seamCalls).toBe(1);
    // No state store was constructed, so only the coordinator is rolled back.
    expect(coordinatorDisposes).toBe(1);
    expect(order).toEqual(['coordinator']);
    expect(existsSync(`${statePath}.runtime.lock`)).toBe(false);
    expect(existsSync(statePath)).toBe(false);
    expect(existsSync(`${statePath}.spool.json`)).toBe(false);
    // Retry proves the claim was released exactly once (no leaked PROCESS map entry).
    const retried = createBridgeDaemonShell({ config, onRegistryMutation: () => {} });
    shells.push(retried);
    expect(existsSync(`${statePath}.runtime.lock`)).toBe(true);
    expect(existsSync(join(root, 'adapter.json'))).toBe(false);
  });

  test('construction failure after the deferred store reverse-rolls back store then coordinator exactly once', () => {
    const { statePath, config } = fixture('registry-clock');
    const order: string[] = [];
    let storeDisposes = 0;
    let coordinatorDisposes = 0;
    const originalStoreDispose = BridgeStateStore.prototype.dispose;
    BridgeStateStore.prototype.dispose = function (this: BridgeStateStore): void {
      storeDisposes += 1;
      order.push('state-store');
      originalStoreDispose.call(this);
    };
    try {
      let registryClockCalls = 0;
      expect(() => createBridgeDaemonShell({
        config,
        onRegistryMutation: () => {},
        registryNow: () => {
          registryClockCalls += 1;
          throw new Error('injected registry clock failure');
        },
        hooks: {
          beforeStateStoreConstruction: (coordinator) => {
            const original = coordinator.dispose.bind(coordinator);
            coordinator.dispose = () => {
              coordinatorDisposes += 1;
              order.push('coordinator');
              original();
            };
          },
        },
      })).toThrow('injected registry clock failure');
      expect(registryClockCalls).toBe(1);
      expect(storeDisposes).toBe(1);
      expect(coordinatorDisposes).toBe(1);
      expect(order).toEqual(['state-store', 'coordinator']);
      expect(existsSync(`${statePath}.runtime.lock`)).toBe(false);
    } finally {
      BridgeStateStore.prototype.dispose = originalStoreDispose;
    }
    const retried = createBridgeDaemonShell({ config, onRegistryMutation: () => {} });
    shells.push(retried);
    expect(existsSync(`${statePath}.runtime.lock`)).toBe(true);
  });

  test('shell owns constructed resources, borrows injected drivers, and performs no activation work', () => {
    const { root, statePath, config } = fixture('ownership');
    const injectedDriver = { name: 'probe', listSessions: async () => [] };
    const shell = createBridgeDaemonShell({
      config,
      drivers: [injectedDriver],
      onRegistryMutation: () => {},
    });
    shells.push(shell);
    expect(shell.ownership).toEqual({
      runtimeCoordinator: 'owned',
      stateStore: 'owned',
      adapterRegistry: 'owned',
      adapterClient: 'owned',
      adapterServer: 'owned',
      router: 'owned',
      drivers: 'borrowed',
    });
    expect(shell.drivers).toEqual([injectedDriver]);
    expect(shell.adapterClient).toBeInstanceOf(AgentAdapterClient);
    expect(shell.adapterServer).toBeInstanceOf(AgentAdapterServer);
    expect(shell.router).toBeInstanceOf(CommandRouter);
    // Constructor-shell timing freeze (spec §6.1): the coordinator is claimed
    // synchronously, but no activation work happens here.
    expect(existsSync(`${statePath}.runtime.lock`)).toBe(true);
    expect(existsSync(statePath)).toBe(false);
    expect(existsSync(`${statePath}.spool.json`)).toBe(false);
    expect(existsSync(join(root, 'adapter.json'))).toBe(false);
    // The default driver is shell-owned AgentAdapterDriver; injected drivers stay borrowed.
    const defaulted = createBridgeDaemonShell({
      config: fixture('default-driver').config,
      onRegistryMutation: () => {},
    });
    shells.push(defaulted);
    expect(defaulted.ownership.drivers).toBe('owned');
    expect(defaulted.drivers).toHaveLength(1);
    expect(defaulted.drivers[0]?.name).toBe('agent-adapter');
  });
});
