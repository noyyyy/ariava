import { afterEach, describe, expect, test } from 'bun:test';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AGENT_ADAPTER_PROTOCOL_VERSION } from '@ariava/protocol';
import type { AgentAdapterDiscoveryFile } from '../src/agent-adapter/config';
import { loadBridgeConfig } from '../src/daemon';
import {
  activateBridgeDaemonServer,
  activateBridgeRuntime,
  createBridgeDaemonShell,
  type BridgeDaemonShell,
} from '../src/daemon/runtime-composition';
import { LocalLinkKeyring } from '../src/e2e/link-keyring';
import { LinuxJsonHostIdentityStore, publicIdentityMetadata, type HostIdentity } from '../src/identity';
import { RelayClient } from '../src/relay-client';
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

async function fixture(name: string): Promise<{ identity: HostIdentity; config: BridgeConfig; shell: BridgeDaemonShell }> {
  const root = mkdtempSync(join(tmpdir(), `ariava-runtime-activation-${name}-`));
  roots.push(root);
  const identityPath = join(root, 'identity.json');
  const identityStore = new LinuxJsonHostIdentityStore(identityPath);
  const identity = await identityStore.createFirstRun();
  const statePath = join(root, 'state.json');
  const config = loadBridgeConfig();
  Object.assign(config, {
    runtimePlatform: 'linux', hostPlatform: 'linux', hostId: identity.hostId, identity: publicIdentityMetadata(identity),
    relayBaseUrl: 'http://relay.invalid', pollIntervalMs: 60_000,
    configPath: join(root, 'config.json'), statePath, identityPath,
    agentAdapter: { ...config.agentAdapter, port: 0, configPath: join(root, 'adapter.json') },
  });
  const shell = createBridgeDaemonShell({ config, onRegistryMutation: () => {} });
  shells.push(shell);
  return { identity, config, shell };
}

describe('activateBridgeRuntime', () => {
  test('preserves the activation sequence and returns an explicit owned bundle', async () => {
    const { identity, config, shell } = await fixture('sequence');
    const order: string[] = [];
    const commits: string[][] = [];
    let recovered: { client: unknown; keyring: unknown } | undefined;
    const active = await activateBridgeRuntime({
      config,
      stateStore: shell.stateStore,
      signal: () => new AbortController().signal,
      verifyFilesystem: () => { order.push('verify-filesystem'); },
      loadValidatedIdentity: async () => { order.push('identity'); return identity; },
      onDroppedUnreadableItems: (count) => { order.push(`spool:${count}`); },
      runCommandRecovery: async (relayClient, keyring) => {
        order.push('recovery');
        recovered = { client: relayClient, keyring };
      },
      onEventFailure: () => {},
      commit: (partial) => { commits.push(Object.keys(partial)); },
    });
    expect(order).toEqual(['verify-filesystem', 'identity', 'spool:0', 'recovery']);
    // Each resource is published at its exact baseline assignment point.
    expect(commits).toEqual([
      ['encryptionStore'],
      ['encryptionIdentity'],
      ['keyringMigrationContext'],
      ['keyring'],
      ['relayClient'],
      ['uploadActions'],
    ]);
    // Best-effort command recovery receives exactly the bundle instances.
    expect(recovered?.client).toBe(active.relayClient);
    expect(recovered?.keyring).toBe(active.keyring);
    expect(active.relayClient).toBeInstanceOf(RelayClient);
    expect(active.keyring).toBeInstanceOf(LocalLinkKeyring);
    expect(active.encryptionStore).toBeDefined();
    expect(active.encryptionIdentity.encryptionKeyId).toBeTruthy();
    expect(typeof active.uploadActions.flushPendingEvents).toBe('function');
    expect(typeof active.uploadActions.publishAuthoritativeSnapshots).toBe('function');
    expect(typeof active.uploadActions.publishRecipientChangeSnapshots).toBe('function');
    expect(active.ownership).toEqual({
      relayClient: 'owned',
      encryptionStore: 'owned',
      encryptionIdentity: 'owned',
      keyring: 'owned',
      keyringMigrationContext: 'owned',
      uploadActions: 'owned',
    });
    // Host-bound spool preflight actually ran during activation.
    expect(existsSync(`${config.statePath}.spool.json`)).toBe(true);
    expect(existsSync(`${config.identityPath}.spool-key.json`)).toBe(true);
  });

  test('never disposes shell resources on failure; the caller owns rollback', async () => {
    const { config, shell } = await fixture('no-rollback');
    let storeDisposes = 0;
    const originalStoreDispose = shell.stateStore.dispose.bind(shell.stateStore);
    shell.stateStore.dispose = () => { storeDisposes += 1; originalStoreDispose(); };
    let coordinatorDisposes = 0;
    const originalCoordinatorDispose = shell.runtimeCoordinator.dispose.bind(shell.runtimeCoordinator);
    shell.runtimeCoordinator.dispose = () => { coordinatorDisposes += 1; originalCoordinatorDispose(); };
    await expect(activateBridgeRuntime({
      config,
      stateStore: shell.stateStore,
      signal: () => new AbortController().signal,
      verifyFilesystem: () => {},
      loadValidatedIdentity: async () => { throw new Error('injected identity failure'); },
      onDroppedUnreadableItems: () => {},
      runCommandRecovery: async () => {},
      onEventFailure: () => {},
      commit: () => {},
    })).rejects.toThrow('injected identity failure');
    expect(storeDisposes).toBe(0);
    expect(coordinatorDisposes).toBe(0);
    // The failure happened before spool preflight; the claim stays owned by the caller.
    expect(existsSync(`${config.statePath}.spool.json`)).toBe(false);
    expect(existsSync(`${config.statePath}.runtime.lock`)).toBe(true);
  });

  test('a post-keyring pin-validation failure publishes keyring but never the Relay client', async () => {
    const { identity, config, shell } = await fixture('partial-visibility');
    const commits: string[][] = [];
    shell.stateStore.validateCommandExecutionPins = () => { throw new Error('pin validation failed'); };
    await expect(activateBridgeRuntime({
      config,
      stateStore: shell.stateStore,
      signal: () => new AbortController().signal,
      verifyFilesystem: () => {},
      loadValidatedIdentity: async () => identity,
      onDroppedUnreadableItems: () => {},
      runCommandRecovery: async () => {},
      onEventFailure: () => {},
      commit: (partial) => { commits.push(Object.keys(partial)); },
    })).rejects.toThrow('pin validation failed');
    expect(commits).toEqual([
      ['encryptionStore'],
      ['encryptionIdentity'],
      ['keyringMigrationContext'],
      ['keyring'],
    ]);
  });
});

describe('activateBridgeDaemonServer', () => {
  test('starts the adapter server before writing discovery evidence', async () => {
    const { config } = await fixture('server');
    const order: string[] = [];
    let evidence: AgentAdapterDiscoveryFile | undefined;
    await activateBridgeDaemonServer({
      adapterServer: {
        url: 'http://127.0.0.1:43210',
        start: async () => { order.push('server-start'); },
      },
      config,
      writeDiscovery: (e) => { order.push('discovery'); evidence = e; },
    });
    expect(order).toEqual(['server-start', 'discovery']);
    expect(evidence).toEqual({
      url: 'http://127.0.0.1:43210',
      secret: config.agentAdapter.secret,
      protocolVersion: AGENT_ADAPTER_PROTOCOL_VERSION,
      provider: 'pi',
      profileId: 'default',
      hostId: config.hostId,
    });
  });

  test('start failure retains the runtime and never writes discovery', async () => {
    const { config } = await fixture('server-fail');
    let discoveryWrites = 0;
    await expect(activateBridgeDaemonServer({
      adapterServer: {
        url: 'http://127.0.0.1:0',
        start: async () => { throw new Error('injected adapter server start failure'); },
      },
      config,
      writeDiscovery: () => { discoveryWrites += 1; },
    })).rejects.toThrow('injected adapter server start failure');
    expect(discoveryWrites).toBe(0);
  });
});
