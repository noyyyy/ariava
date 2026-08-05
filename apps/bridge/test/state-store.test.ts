import { afterEach, describe, expect, mock, test } from 'bun:test';
import { chmodSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BridgeStateStore } from '../src/state-store';
import type { CanonicalSessionState, HostProjection } from '@ariava/protocol';

mock.module('../src/e2e/node-crypto', () => ({
  chachaPolySeal: (_key: Uint8Array, plaintext: Uint8Array) => ({ nonce: new Uint8Array(12).fill(1), ciphertext: new Uint8Array([...plaintext, ...new Uint8Array(16)]) }),
  chachaPolyOpen: (_key: Uint8Array, _nonce: Uint8Array, ciphertext: Uint8Array) => ciphertext.slice(0, -16),
}));

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
  test('initializes snapshot state without discarding a complete legacy state file', () => {
    const root = join(tmpdir(), `bridge-store-${Date.now()}`); paths.push(root);
    const statePath = join(root, 'state.json');
    mkdirSync(root, { recursive: true, mode: 0o700 });
    const legacy = {
      host: null,
      sessions: { 'sess-1': { sessionId: 'sess-1', hostId: 'host-1', provider: 'pi', projectName: 'p', nameText: 'n', stateLabel: 'Ready', status: 'idle', updatedAt: '2026-07-20T00:00:00.000Z' } },
      sessionDrivers: { 'sess-1': 'pi' },
      recentEvents: [{ eventId: 'evt-recent', hostId: 'host-1', sessionId: 'sess-1', provider: 'pi', type: 'done', status: 'done', typeLabel: 'Done', createdAt: '2026-07-20T00:00:01.000Z' }],
      pendingEvents: [{ eventId: 'evt-pending', hostId: 'host-1', sessionId: 'sess-1', provider: 'pi', type: 'need_human', status: 'blocked', typeLabel: 'Needs attention', createdAt: '2026-07-20T00:00:02.000Z' }],
      pendingHandles: { 'host-1:sess-1': { hostId: 'host-1', sessionId: 'sess-1', handledThroughEventId: 'evt-recent', handledAt: '2026-07-20T00:00:03.000Z', action: 'pi_input', updatedAt: '2026-07-20T00:00:03.000Z' } },
      commandResults: { 'cmd-1': { commandId: 'cmd-1', hostId: 'host-1', sessionId: 'sess-1', accepted: true, status: 'executed', message: 'ok', updatedAt: '2026-07-20T00:00:04.000Z' } },
      seenCommands: { 'cmd-1': '2026-07-20T00:00:04.000Z' },
    };
    writeFileSync(statePath, JSON.stringify(legacy)); chmodSync(statePath, 0o600);
    const store = new BridgeStateStore(statePath);
    expect(store.listSessions()).toEqual(Object.values(legacy.sessions));
    expect(store.peekPendingEvents()).toEqual(legacy.pendingEvents);
    expect(store.peekPendingSessionHandles()).toEqual(Object.values(legacy.pendingHandles));
    expect(store.getCommandResult('cmd-1')).toEqual(legacy.commandResults['cmd-1']);
    expect(store.hasSeenCommand('cmd-1')).toBe(true);
    expect(store.getCurrentSessionsSnapshotState()).toEqual({ version: 1, lastAllocatedRevision: 0, lastAcceptedRevision: 0 });
    const persisted = JSON.parse(readFileSync(statePath, 'utf8'));
    expect(persisted.recentEvents).toEqual(legacy.recentEvents);
    expect(persisted.currentSessionsSnapshot).toEqual({ version: 1, lastAllocatedRevision: 0, lastAcceptedRevision: 0 });
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

  test('canonicalizes rebuildable three-event plaintext pending state during encrypted spool upgrade', () => {
    const root = join(tmpdir(), `bridge-store-${Date.now()}`); paths.push(root);
    const statePath = join(root, 'state.json');
    mkdirSync(root, { recursive: true, mode: 0o700 });
    const base = { hostId: 'host-1', sessionId: 'sess-1', provider: 'pi', status: 'blocked', typeLabel: 'Legacy', agentText: 'preserved', createdAt: '2026-07-20T00:00:00.000Z' };
    writeFileSync(statePath, JSON.stringify({ pendingEvents: [
      { ...base, eventId: 'legacy-blocked', type: 'blocked' },
      { ...base, eventId: 'legacy-question', type: 'question_requested', actionablePrompt: { promptId: 'p1', type: 'question', label: 'Choose deployment target', options: ['staging-target'] } },
      { ...base, eventId: 'canonical-done', type: 'done', status: 'done', typeLabel: 'Old done label' },
    ] }));
    chmodSync(statePath, 0o600);
    const store = new BridgeStateStore(statePath);
    const report = store.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
    expect(report).toEqual({ droppedUnreadableItems: 0 });
    expect(store.peekPendingEvents()).toEqual([
      expect.objectContaining({ eventId: 'legacy-blocked', type: 'need_human', status: 'blocked', typeLabel: 'Needs attention', agentText: 'preserved' }),
      expect.objectContaining({ eventId: 'legacy-question', type: 'need_human', status: 'blocked', typeLabel: 'Needs attention', actionablePrompt: { promptId: 'p1', type: 'question', label: 'Choose deployment target', options: ['staging-target'] } }),
      expect.objectContaining({ eventId: 'canonical-done', type: 'done', status: 'done', typeLabel: 'Task complete' }),
    ]);
  });

  test('fails closed on old inflight wire state without deleting encrypted evidence', () => {
    const root = join(tmpdir(), `bridge-store-${Date.now()}`); paths.push(root);
    const statePath = join(root, 'state.json');
    const keyStore = { loadOrCreate: () => new Uint8Array(32).fill(7) };
    const store = new BridgeStateStore(statePath);
    store.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux', keyStore);
    store.queuePendingEvent({ eventId: 'legacy-blocked', hostId: 'host-1', sessionId: 'sess-1', provider: 'pi', type: 'blocked', status: 'blocked', typeLabel: 'Legacy', agentText: 'old', createdAt: '2026-07-20T00:00:00.000Z' } as any);
    store.persistInflightEventUpload('legacy-blocked', 'sess-1', { event: { type: 'blocked', status: 'blocked' }, session: {} });
    const restarted = new BridgeStateStore(statePath);
    expect(() => restarted.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux', keyStore)).toThrow(/obsolete inflight event upload requires explicit recovery/);
    expect(restarted.getInflightEventUpload('legacy-blocked')).toEqual({ event: { type: 'blocked', status: 'blocked' }, session: {} });
  });

  test('fails closed on legacy plaintext pending lifecycle state without rewriting its revision lower bound', () => {
    const root = join(tmpdir(), `bridge-store-${Date.now()}`); paths.push(root);
    const statePath = join(root, 'state.json');
    mkdirSync(root, { recursive: true, mode: 0o700 });
    const legacy = { currentSessionsSnapshot: { version: 1, lastAllocatedRevision: 3, lastAcceptedRevision: 2, pending: {
      digest: 'legacy', contentDigest: 'legacy-content', request: { hostId: 'host-1', revision: 7, observedAt: '2026-07-20T00:00:00.000Z',
        sessions: [{ sessionId: 'sess-1', projectName: 'protected-marker' }] } } } };
    writeFileSync(statePath, JSON.stringify(legacy)); chmodSync(statePath, 0o600);
    expect(() => new BridgeStateStore(statePath)).toThrow('Bridge state file is invalid or insecure');
    expect(JSON.parse(readFileSync(statePath, 'utf8'))).toEqual(legacy);
  });

  test('fails closed without digest proof and leaves protected pending bytes untouched', () => {
    const root = join(tmpdir(), `bridge-store-${Date.now()}`); paths.push(root);
    const statePath = join(root, 'state.json'); mkdirSync(root, { recursive: true, mode: 0o700 });
    const bytes = JSON.stringify({ currentSessionsSnapshot: { version: 1, lastAllocatedRevision: 9, lastAcceptedRevision: 4, pending: {
      request: { hostId: 'host-1', revision: 9, observedAt: '2026-07-20T00:00:00.000Z', recipientSetVersion: 1,
        sessions: [{ sessionId: 'sess-1', sessionRevision: 1, nameText: 'protected-marker' }] } } } });
    writeFileSync(statePath, bytes); chmodSync(statePath, 0o600);
    expect(() => new BridgeStateStore(statePath)).toThrow('Bridge state file is invalid or insecure');
    expect(readFileSync(statePath, 'utf8')).toBe(bytes);
  });

  test('fails closed on non-positive persisted member session revisions', () => {
    const root = join(tmpdir(), `bridge-store-${Date.now()}`); paths.push(root);
    const statePath = join(root, 'state.json'); mkdirSync(root, { recursive: true, mode: 0o700 });
    const persisted = { currentSessionsSnapshot: { version: 1, lastAllocatedRevision: 3, lastAcceptedRevision: 2, pending: {
      digest: 'digest', contentDigest: 'content', request: { hostId: 'host-1', revision: 3, observedAt: '2026-07-20T00:00:00.000Z',
        recipientSetVersion: 1, sessions: [{ sessionId: 'sess-1', sessionRevision: 0 }] } } } };
    writeFileSync(statePath, JSON.stringify(persisted)); chmodSync(statePath, 0o600);
    expect(() => new BridgeStateStore(statePath)).toThrow('Bridge state file is invalid or insecure');
  });
});
