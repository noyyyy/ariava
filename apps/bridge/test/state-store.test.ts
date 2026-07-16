import { afterEach, describe, expect, test } from 'bun:test';
import { chmodSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BridgeStateStore } from '../src/state-store';
import type { CanonicalSessionState, HostProjection } from '@ariava/protocol';

const paths: string[] = [];

afterEach(() => {
  for (const path of paths.splice(0)) {
    rmSync(path, { recursive: true, force: true });
  }
});

describe('BridgeStateStore', () => {
  test('stores hosts without persisting legacy claim-code fields', () => {
    const root = join(tmpdir(), `bridge-store-${Date.now()}`);
    paths.push(root);
    const statePath = join(root, 'state.json');
    const store = new BridgeStateStore(statePath);

    const host: HostProjection = {
      hostId: 'host-1',
      hostName: 'Test Mac',
      platform: 'macos',
      bridgeVersion: '0.1.2',
      registeredAt: '2026-07-04T09:00:00Z',
      lastSeenAt: '2026-07-04T09:00:01Z',
      bridgeStatus: 'online',
      claimCode: 'LEGACY1',
      claimCodeExpiresAt: '2026-07-04T09:10:00Z',
    };

    store.setHost(host);

    expect(store.getHost()).toEqual({
      hostId: 'host-1',
      hostName: 'Test Mac',
      platform: 'macos',
      bridgeVersion: '0.1.2',
      registeredAt: '2026-07-04T09:00:00Z',
      lastSeenAt: '2026-07-04T09:00:01Z',
      bridgeStatus: 'online',
    });
    expect(JSON.parse(readFileSync(statePath, 'utf8')).host).toEqual({
      hostId: 'host-1',
      hostName: 'Test Mac',
      platform: 'macos',
      bridgeVersion: '0.1.2',
      registeredAt: '2026-07-04T09:00:00Z',
      lastSeenAt: '2026-07-04T09:00:01Z',
      bridgeStatus: 'online',
    });
  });

  test('migrates legacy persisted hosts by removing claim-code fields on load', () => {
    const root = join(tmpdir(), `bridge-store-${Date.now()}`);
    paths.push(root);
    const statePath = join(root, 'state.json');

    mkdirSync(root, { recursive: true, mode: 0o700 });
    writeFileSync(
      statePath,
      JSON.stringify({
        host: {
          hostId: 'host-legacy',
          hostName: 'Legacy Mac',
          platform: 'macos',
          bridgeVersion: '0.1.2',
              registeredAt: '2026-07-04T09:00:00Z',
          lastSeenAt: '2026-07-04T09:00:01Z',
          bridgeStatus: 'online',
          claimCode: 'LEGACY1',
          claimCodeExpiresAt: '2026-07-04T09:10:00Z',
        },
      }),
    );
    chmodSync(statePath, 0o600);

    const store = new BridgeStateStore(statePath);

    expect(store.getHost()).toEqual({
      hostId: 'host-legacy',
      hostName: 'Legacy Mac',
      platform: 'macos',
      bridgeVersion: '0.1.2',
      registeredAt: '2026-07-04T09:00:00Z',
      lastSeenAt: '2026-07-04T09:00:01Z',
      bridgeStatus: 'online',
    });
    expect(JSON.parse(readFileSync(statePath, 'utf8')).host).toEqual({
      hostId: 'host-legacy',
      hostName: 'Legacy Mac',
      platform: 'macos',
      bridgeVersion: '0.1.2',
      registeredAt: '2026-07-04T09:00:00Z',
      lastSeenAt: '2026-07-04T09:00:01Z',
      bridgeStatus: 'online',
    });
  });

  test('fails closed on insecure legacy state permissions', () => {
    const root = join(tmpdir(), `bridge-store-${Date.now()}`);
    paths.push(root);
    const statePath = join(root, 'state.json');

    mkdirSync(root, { recursive: true, mode: 0o700 });
    writeFileSync(
      statePath,
      JSON.stringify({
        host: {
          hostId: 'host-readonly',
          hostName: 'Readonly Mac',
          platform: 'macos',
          bridgeVersion: '0.1.2',
              registeredAt: '2026-07-04T09:00:00Z',
          lastSeenAt: '2026-07-04T09:00:01Z',
          bridgeStatus: 'online',
          claimCode: 'LEGACY1',
          claimCodeExpiresAt: '2026-07-04T09:10:00Z',
        },
      }),
    );
    chmodSync(statePath, 0o400);

    try {
      expect(() => new BridgeStateStore(statePath)).toThrow('Bridge state file is invalid or insecure');
    } finally {
      chmodSync(statePath, 0o600);
    }
  });

  test('fails closed on dangling state symlink evidence', () => {
    const root = join(tmpdir(), `bridge-store-${Date.now()}`);
    paths.push(root);
    mkdirSync(root, { mode: 0o700 });
    const statePath = join(root, 'state.json');
    symlinkSync(join(root, 'missing.json'), statePath);
    expect(() => new BridgeStateStore(statePath)).toThrow('Bridge state file is invalid or insecure');
  });

  test('stores sessions by driver and removes stale ones', () => {
    const root = join(tmpdir(), `bridge-store-${Date.now()}`);
    paths.push(root);
    const store = new BridgeStateStore(join(root, 'state.json'));

    const session: CanonicalSessionState = {
      sessionId: 'pane-1',
      hostId: 'host-1',
      provider: 'pi',
      project: 'proj',
      title: 'Fix deploy script',
      status: 'blocked',
      summary: 'Needs help',
      updatedAt: '2026-06-28T12:00:00Z',
    };

    store.replaceDriverSessions('pi', [session]);
    expect(store.listSessions()).toHaveLength(1);
    store.replaceDriverSessions('pi', []);
    expect(store.listSessions()).toHaveLength(0);
  });
  test('persists pending handles monotonically and migrates legacy pending reads', () => {
    const root = join(tmpdir(), `bridge-store-${Date.now()}`);
    paths.push(root);
    const statePath = join(root, 'state.json');
    const store = new BridgeStateStore(statePath);

    store.queuePendingSessionHandle({
      hostId: 'host-1', sessionId: 'sess-1', handledThroughEventId: 'evt-2',
      handledThroughEventCreatedAt: '2026-07-16T00:00:02Z', handledAt: '2026-07-16T00:00:03Z',
      action: 'pi_input', updatedAt: '2026-07-16T00:00:03Z',
    });
    store.queuePendingSessionHandle({
      hostId: 'host-1', sessionId: 'sess-1', handledThroughEventId: 'evt-1',
      handledThroughEventCreatedAt: '2026-07-16T00:00:01Z', handledAt: '2026-07-16T00:00:04Z',
      action: 'pi_input', updatedAt: '2026-07-16T00:00:04Z',
    });
    expect(store.peekPendingSessionHandles()[0]?.handledThroughEventId).toBe('evt-2');

    const reloaded = new BridgeStateStore(statePath);
    expect(reloaded.peekPendingSessionHandles()[0]?.handledThroughEventId).toBe('evt-2');
    reloaded.removePendingSessionHandle('host-1', 'sess-1', 'evt-1');
    expect(reloaded.peekPendingSessionHandles()).toHaveLength(1);
    reloaded.removePendingSessionHandle('host-1', 'sess-1', 'evt-2');
    expect(reloaded.peekPendingSessionHandles()).toHaveLength(0);

    writeFileSync(statePath, JSON.stringify({
      pendingReads: {
        'host-1:sess-2': { hostId: 'host-1', sessionId: 'sess-2', latestReadEventId: 'evt-legacy',
          readAt: '2026-07-16T00:00:05Z', source: 'bridge_recovery', updatedAt: '2026-07-16T00:00:05Z' },
      },
    }));
    chmodSync(statePath, 0o600);
    const migrated = new BridgeStateStore(statePath);
    expect(migrated.peekPendingSessionHandles()).toEqual([{
      hostId: 'host-1', sessionId: 'sess-2', handledThroughEventId: 'evt-legacy',
      handledThroughEventCreatedAt: undefined, handledAt: '2026-07-16T00:00:05Z',
      action: 'bridge_recovery', updatedAt: '2026-07-16T00:00:05Z',
    }]);
  });
});
