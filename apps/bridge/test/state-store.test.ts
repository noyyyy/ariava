import { afterEach, describe, expect, mock, test } from 'bun:test';
import { chmodSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BridgeStateStore } from '../src/state-store';
import { spoolPathForState } from '../src/e2e/local-spool';
import type { CanonicalEvent, CanonicalSessionState, HostProjection } from '@ariava/protocol';

const paths: string[] = [];
const LEGACY_AT = '2026-08-07T00:00:00.000Z';

function exactLegacyState() {
  const session = {
    sessionId: 'sess-1', hostId: 'host-1', provider: 'pi', projectName: 'project', nameText: 'name',
    stateLabel: 'Done', status: 'done', updatedAt: LEGACY_AT, lastEventId: 'evt-1',
  };
  const event = {
    eventId: 'evt-1', hostId: 'host-1', sessionId: 'sess-1', provider: 'pi', type: 'done', status: 'done',
    typeLabel: 'Done', agentText: 'legacy event', createdAt: LEGACY_AT,
  };
  return {
    host: { hostId: 'host-1', hostName: 'Legacy', platform: 'linux', bridgeVersion: '0.1.0',
      registeredAt: LEGACY_AT, lastSeenAt: LEGACY_AT, bridgeStatus: 'online', claimCode: 'LEGACY1' },
    sessions: { 'sess-1': session }, sessionDrivers: { 'sess-1': 'pi' }, reconciledDrivers: { pi: true },
    recentEvents: [event], pendingEvents: [event], sessionRevisions: { 'sess-1': 4 }, recipientSetVersion: 3,
    eventUploadCompletions: { 'evt-1': { version: 1, eventId: 'evt-1', sessionId: 'sess-1', revision: 4,
      eventContentId: 'event-content', sessionContentId: 'session-content', committedAt: LEGACY_AT } },
    producerEventReservations: { ['sess-1\nfingerprint']: { version: 1, eventId: 'evt-1', sessionId: 'sess-1',
      fingerprint: 'fingerprint', createdAt: LEGACY_AT } },
    terminalCancellations: { 'evt-1': { version: 1, eventId: 'evt-1', sessionId: 'sess-1',
      fingerprint: 'fingerprint', removeSession: false, createdAt: LEGACY_AT } },
    pendingHandles: { 'host-1:sess-1': { hostId: 'host-1', sessionId: 'sess-1', handledThroughEventId: 'evt-1',
      handledAt: LEGACY_AT, action: 'pi_input', updatedAt: LEGACY_AT } },
    commandResults: { command: { commandId: 'command', hostId: 'host-1', sessionId: 'sess-1', accepted: true,
      status: 'executed', message: 'done', updatedAt: LEGACY_AT } }, seenCommands: { command: LEGACY_AT },
    currentSessionsSnapshot: { version: 1, lastAllocatedRevision: 8, lastAcceptedRevision: 7,
      lastAcceptedDigest: 'digest', lastAcceptedContentDigest: 'content', lastAcceptedRecipientSetVersion: 3 },
  };
}


mock.module('../src/e2e/node-crypto', () => ({
  chachaPolySeal: (_key: Uint8Array, plaintext: Uint8Array) => ({
    nonce: new Uint8Array(12).fill(1), ciphertext: new Uint8Array([...plaintext, ...new Uint8Array(16)]),
  }),
  chachaPolyOpen: (_key: Uint8Array, _nonce: Uint8Array, ciphertext: Uint8Array) => ciphertext.slice(0, -16),
}));

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

  test('resets recognized schema-less state instead of preserving legacy Host fields', () => {
    const root = join(tmpdir(), `bridge-store-${Date.now()}`); paths.push(root);
    const statePath = join(root, 'state.json');
    mkdirSync(root, { recursive: true, mode: 0o700 });
    const legacy = { ...exactLegacyState(), host: { ...exactLegacyState().host, claimCode: 'LEGACY1' } };
    writeFileSync(statePath, JSON.stringify(legacy), { mode: 0o600 });
    chmodSync(statePath, 0o600);

    expect(() => new BridgeStateStore(statePath)).toThrow('Bridge state file is invalid or insecure');
    const store = new BridgeStateStore(statePath, undefined, { deferRuntimePreflight: true });
    store.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux', {
      loadOrCreate: () => new Uint8Array(32).fill(7),
    });

    expect(store.getHost()).toBeNull();
    expect(store.listSessions()).toEqual([]);
    expect(store.peekPendingEvents()).toEqual([]);
    expect(store.peekPendingSessionHandles()).toEqual([]);
    const persisted = JSON.parse(readFileSync(statePath, 'utf8'));
    expect(persisted.schemaVersion).toBe(3);
    expect(persisted).not.toHaveProperty('pendingEvents');
    expect(persisted).not.toHaveProperty('pendingReads');
    expect(store.getRuntimeHealth()).toEqual({ status: 'healthy', drivers: [] });
    expect(persisted.runtimeHealth).toEqual({ status: 'healthy', drivers: [] });
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
  test('breaking preflight clears every recognized legacy runtime family', () => {
    const root = join(tmpdir(), `bridge-store-${Date.now()}`); paths.push(root);
    const statePath = join(root, 'state.json');
    mkdirSync(root, { recursive: true, mode: 0o700 });
    const legacy = exactLegacyState();
    writeFileSync(statePath, JSON.stringify(legacy), { mode: 0o600 });
    const store = new BridgeStateStore(statePath, undefined, { deferRuntimePreflight: true });
    store.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux', {
      loadOrCreate: () => new Uint8Array(32).fill(7),
    });

    expect(store.listSessions()).toEqual([]);
    expect(store.peekPendingEvents()).toEqual([]);
    expect(store.peekPendingSessionHandles()).toEqual([]);
    expect(store.getCommandResult('command')).toBeUndefined();
    expect(store.hasSeenCommand('command')).toBe(false);
    expect(store.getRecipientSetVersion()).toBeUndefined();
    expect(store.getCurrentSessionsSnapshotState()).toEqual({ version: 1, lastAllocatedRevision: 0, lastAcceptedRevision: 0 });
  });

  test('persists current pending handles monotonically and resets legacy pending reads', () => {
    const root = join(tmpdir(), `bridge-store-${Date.now()}`); paths.push(root);
    const statePath = join(root, 'state.json');
    const store = new BridgeStateStore(statePath);

    store.replaceDriverSessions('pi', [{
      sessionId: 'sess-1', hostId: 'host-1', provider: 'pi', projectName: 'project', nameText: 'Task',
      status: 'idle', updatedAt: '2026-07-16T00:00:02Z', lastEventId: 'evt-2',
    }]);
    store.appendRecentEvent({
      eventId: 'evt-1', hostId: 'host-1', sessionId: 'sess-1', provider: 'pi', type: 'done', status: 'idle',
      agentText: 'First', createdAt: '2026-07-16T00:00:01Z',
    });
    store.appendRecentEvent({
      eventId: 'evt-2', hostId: 'host-1', sessionId: 'sess-1', provider: 'pi', type: 'done', status: 'idle',
      agentText: 'Second', createdAt: '2026-07-16T00:00:02Z',
    });
    store.queuePendingSessionHandle({
      hostId: 'host-1', sessionId: 'sess-1', handledThroughEventId: 'evt-2',
      handledThroughEventCreatedAt: '2026-07-16T00:00:02Z', handledAt: '2026-07-16T00:00:03Z',
      action: 'pi_input', updatedAt: '2026-07-16T00:00:03Z',
    });
    expect(() => store.queuePendingSessionHandle({
      hostId: 'host-1', sessionId: 'sess-1', handledThroughEventId: 'evt-1',
      handledThroughEventCreatedAt: '2026-07-16T00:00:01Z', handledAt: '2026-07-16T00:00:04Z',
      action: 'pi_input', updatedAt: '2026-07-16T00:00:04Z',
    })).toThrow(/older than/u);
    expect(store.peekPendingSessionHandles()[0]?.handledThroughEventId).toBe('evt-2');

    store.dispose();
    const reloaded = new BridgeStateStore(statePath);
    expect(reloaded.peekPendingSessionHandles()[0]?.handledThroughEventId).toBe('evt-2');
    reloaded.removePendingSessionHandle('host-1', 'sess-1', 'evt-1');
    expect(reloaded.peekPendingSessionHandles()).toHaveLength(1);
    reloaded.removePendingSessionHandle('host-1', 'sess-1', 'evt-2');
    expect(reloaded.peekPendingSessionHandles()).toHaveLength(0);
    reloaded.dispose();

    const orphanBytes = JSON.stringify({ pendingReads: {
      'host-1:sess-2': { hostId: 'host-1', sessionId: 'sess-2', latestReadEventId: 'evt-legacy',
        readAt: LEGACY_AT, source: 'pi_local_interaction', updatedAt: LEGACY_AT },
    } });
    writeFileSync(statePath, orphanBytes, { mode: 0o600 });
    let keyAccessed = false;
    const reset = new BridgeStateStore(statePath, undefined, { deferRuntimePreflight: true });
    expect(() => reset.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux', {
      loadOrCreate: () => { keyAccessed = true; return new Uint8Array(32).fill(7); },
    })).toThrow('Bridge runtime preflight failed closed');
    expect(keyAccessed).toBe(false);
    expect(readFileSync(statePath, 'utf8')).toBe(orphanBytes);
  });

  test('rejects an orphan legacy pending publication byte-identically', () => {
    const root = join(tmpdir(), `bridge-store-${Date.now()}`); paths.push(root);
    const statePath = join(root, 'state.json'); mkdirSync(root, { recursive: true, mode: 0o700 });
    const bytes = JSON.stringify({ currentSessionsSnapshot: {
      version: 1, lastAllocatedRevision: 3, lastAcceptedRevision: 2, pending: {
        request: { hostId: 'host-1', revision: 3, observedAt: LEGACY_AT, recipientSetVersion: 1,
          sessions: [{ sessionId: 'sess-1', sessionRevision: 1 }] },
        digest: 'digest', contentDigest: 'content',
      },
    } });
    writeFileSync(statePath, bytes, { mode: 0o600 });
    let keyAccessed = false;
    const store = new BridgeStateStore(statePath, undefined, { deferRuntimePreflight: true });
    expect(() => store.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux', {
      loadOrCreate: () => { keyAccessed = true; return new Uint8Array(32).fill(7); },
    })).toThrow('Bridge runtime preflight failed closed');
    expect(keyAccessed).toBe(false);
    expect(readFileSync(statePath, 'utf8')).toBe(bytes);
  });

  test('fails closed on unprovable legacy input and preserves exact bytes', () => {
    const root = join(tmpdir(), `bridge-store-${Date.now()}`); paths.push(root);
    const statePath = join(root, 'state.json'); mkdirSync(root, { recursive: true, mode: 0o700 });
    const bytes = '{"pendingEvents":[],"unknownProtectedFamily":{"marker":"protected"}}\n';
    writeFileSync(statePath, bytes, { mode: 0o600 });
    let keyAccessed = false;
    const store = new BridgeStateStore(statePath, undefined, { deferRuntimePreflight: true });
    expect(() => store.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux', {
      loadOrCreate: () => { keyAccessed = true; return new Uint8Array(32).fill(7); },
    })).toThrow();
    expect(keyAccessed).toBe(false);
    expect(readFileSync(statePath, 'utf8')).toBe(bytes);
  });


  test('keeps event tuple atomic across key-store, spool-file, and state-file failures', () => {
    const root = join(tmpdir(), `bridge-store-atomic-${Date.now()}`); paths.push(root);
    mkdirSync(root, { recursive: true, mode: 0o700 });
    const statePath = join(root, 'state.json');
    const keyStore = { loadOrCreate: () => new Uint8Array(32).fill(7) };
    const event = {
      eventId: 'evt-atomic', hostId: 'host-1', sessionId: 'sess-1', provider: 'pi', type: 'done', status: 'idle',
      agentText: 'Finished', projectName: 'project', contextText: 'Task · project',
      workingDirectory: '/project', hbaseSessionKey: 'sess-1', harnessProvider: 'pi', createdAt: '2026-08-07T00:00:01.000Z',
    } satisfies CanonicalEvent;
    const session = {
      sessionId: 'sess-1', hostId: 'host-1', provider: 'pi', projectName: 'project', nameText: 'Task',
      latestActivityText: 'Finished', workingDirectory: '/project', hbaseSessionKey: 'sess-1', harnessProvider: 'pi',
      status: 'idle', updatedAt: event.createdAt, lastEventId: event.eventId,
    } satisfies CanonicalSessionState;

    const keyFailure = new BridgeStateStore(statePath);
    expect(() => keyFailure.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux', {
      loadOrCreate: () => { throw new Error('key failure'); },
    })).toThrow();
    expect(keyFailure.peekPendingUploads()).toEqual([]);
    expect(keyFailure.listSessions()).toEqual([]);

    keyFailure.dispose();
    const spoolFailurePath = spoolPathForState(statePath);
    const spoolFailure = new BridgeStateStore(statePath);
    spoolFailure.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux', keyStore);
    rmSync(spoolFailurePath);
    mkdirSync(spoolFailurePath, { mode: 0o700 });
    expect(() => spoolFailure.queuePendingEvent(event, session)).toThrow();
    expect(spoolFailure.peekPendingUploads()).toEqual([]);
    expect(spoolFailure.listSessions()).toEqual([]);
    spoolFailure.dispose();
    rmSync(spoolFailurePath, { recursive: true, force: true });
    rmSync(statePath);

    const writes = { fail: true };
    const journaled = new BridgeStateStore(statePath, (path, value) => {
      if (writes.fail) throw new Error('state write failure');
      writeFileSync(path, JSON.stringify(value), { mode: 0o600 });
    });
    journaled.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux', keyStore);
    expect(() => journaled.queuePendingEvent(event, session)).toThrow('state write failure');
    expect(journaled.peekPendingUploads()).toEqual([{ event, session }]);
    expect(journaled.listSessions()).toEqual([]);
    writes.fail = false;

    journaled.dispose();
    const restarted = new BridgeStateStore(statePath);
    restarted.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux', keyStore);
    expect(restarted.peekPendingUploads()).toEqual([{ event, session }]);
    expect(restarted.listSessions()).toEqual([session]);
    const persisted = JSON.parse(readFileSync(statePath, 'utf8'));
    expect(persisted.recentEvents).toEqual([event]);
    expect(persisted.sessions['sess-1']).toEqual(session);
  });

  test('rejects persisted current Events containing legacy typeLabel', () => {
    const root = join(tmpdir(), `bridge-store-event-keys-${Date.now()}`); paths.push(root);
    const statePath = join(root, 'state.json');
    const store = new BridgeStateStore(statePath);
    store.appendRecentEvent({
      eventId: 'evt-current', hostId: 'host-1', sessionId: 'sess-1', provider: 'pi', type: 'done', status: 'idle',
      agentText: 'Done', createdAt: LEGACY_AT,
    });
    store.dispose();
    const persisted = JSON.parse(readFileSync(statePath, 'utf8'));
    persisted.recentEvents[0].typeLabel = 'Task complete';
    writeFileSync(statePath, JSON.stringify(persisted), { mode: 0o600 });
    expect(() => new BridgeStateStore(statePath)).toThrow('Bridge state file is invalid or insecure');
  });

  test('rejects orphan and foreign handle cursors without mutation', () => {
    const root = join(tmpdir(), `bridge-store-handle-binding-${Date.now()}`); paths.push(root);
    const store = new BridgeStateStore(join(root, 'state.json'));
    store.replaceDriverSessions('pi', [{
      sessionId: 'sess-1', hostId: 'host-1', provider: 'pi', projectName: 'project', nameText: 'Task',
      status: 'idle', updatedAt: LEGACY_AT, lastEventId: 'evt-1',
    }]);
    store.appendRecentEvent({
      eventId: 'evt-1', hostId: 'host-1', sessionId: 'sess-other', provider: 'pi', type: 'done', status: 'idle',
      agentText: 'Foreign', createdAt: LEGACY_AT,
    });
    const handle = { hostId: 'host-1', sessionId: 'sess-1', handledAt: LEGACY_AT, action: 'pi_input' as const, updatedAt: LEGACY_AT };
    expect(() => store.queuePendingSessionHandle({ ...handle, handledThroughEventId: 'missing' })).toThrow(/durable Event/u);
    expect(() => store.queuePendingSessionHandle({ ...handle, handledThroughEventId: 'evt-1' })).toThrow(/same Host and Session/u);
    expect(store.peekPendingSessionHandles()).toEqual([]);
  });

  test('retains handle Event evidence after Session removal and through restart', () => {
    const root = join(tmpdir(), `bridge-store-handle-history-${Date.now()}`); paths.push(root);
    const statePath = join(root, 'state.json');
    const store = new BridgeStateStore(statePath);
    store.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux', {
      loadOrCreate: () => new Uint8Array(32).fill(7),
    });
    store.replaceDriverSessions('pi', [{
      sessionId: 'sess-1', hostId: 'host-1', provider: 'pi', projectName: 'project', nameText: 'Task',
      status: 'idle', updatedAt: LEGACY_AT, lastEventId: 'evt-bound',
    }]);
    store.appendRecentEvent({
      eventId: 'evt-bound', hostId: 'host-1', sessionId: 'sess-1', provider: 'pi', type: 'done', status: 'idle',
      agentText: 'Done', createdAt: LEGACY_AT,
    });
    store.queuePendingSessionHandle({
      hostId: 'host-1', sessionId: 'sess-1', handledThroughEventId: 'evt-bound', handledAt: LEGACY_AT,
      action: 'pi_input', updatedAt: LEGACY_AT,
    });
    store.replaceDriverSessions('pi', []);
    store.dispose();
    const restarted = new BridgeStateStore(statePath, undefined, { deferRuntimePreflight: true });
    restarted.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux', {
      loadOrCreate: () => new Uint8Array(32).fill(7),
    });
    expect(restarted.listSessions()).toEqual([]);
    expect(restarted.peekPendingSessionHandles()).toEqual([expect.objectContaining({
      handledThroughEventId: 'evt-bound', handledThroughEventCreatedAt: LEGACY_AT,
    })]);
  });

  test('releases handle Event evidence for normal bounded eviction after delivery', () => {
    const root = join(tmpdir(), `bridge-store-handle-eviction-${Date.now()}`); paths.push(root);
    const store = new BridgeStateStore(join(root, 'state.json'));
    store.replaceDriverSessions('pi', [{
      sessionId: 'sess-1', hostId: 'host-1', provider: 'pi', projectName: 'project', nameText: 'Task',
      status: 'idle', updatedAt: LEGACY_AT, lastEventId: 'evt-bound',
    }]);
    store.appendRecentEvent({
      eventId: 'evt-bound', hostId: 'host-1', sessionId: 'sess-1', provider: 'pi', type: 'done', status: 'idle',
      agentText: 'Done', createdAt: LEGACY_AT,
    });
    store.queuePendingSessionHandle({
      hostId: 'host-1', sessionId: 'sess-1', handledThroughEventId: 'evt-bound', handledAt: LEGACY_AT,
      action: 'pi_input', updatedAt: LEGACY_AT,
    });
    for (let index = 0; index < 200; index += 1) {
      store.appendRecentEvent({
        eventId: `evt-new-${index}`, hostId: 'host-1', sessionId: 'sess-1', provider: 'pi', type: 'done', status: 'idle',
        agentText: 'New', createdAt: `2026-08-08T00:${String(Math.floor(index / 60)).padStart(2, '0')}:${String(index % 60).padStart(2, '0')}.000Z`,
      });
    }
    expect(JSON.parse(readFileSync(join(root, 'state.json'), 'utf8')).recentEvents.some((event: { eventId: string }) => event.eventId === 'evt-bound')).toBe(true);
    store.removePendingSessionHandle('host-1', 'sess-1', 'evt-bound');
    store.appendRecentEvent({
      eventId: 'evt-new-final', hostId: 'host-1', sessionId: 'sess-1', provider: 'pi', type: 'done', status: 'idle',
      agentText: 'Newest', createdAt: '2026-08-09T00:00:00.000Z',
    });
    expect(JSON.parse(readFileSync(join(root, 'state.json'), 'utf8')).recentEvents.some((event: { eventId: string }) => event.eventId === 'evt-bound')).toBe(false);
  });

  test('preserves bounded command history after Session removal and restart', () => {
    const root = join(tmpdir(), `bridge-store-command-history-${Date.now()}`); paths.push(root);
    const statePath = join(root, 'state.json');
    const store = new BridgeStateStore(statePath);
    store.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux', {
      loadOrCreate: () => new Uint8Array(32).fill(7),
    });
    store.replaceDriverSessions('pi', [{
      sessionId: 'sess-1', hostId: 'host-1', provider: 'pi', projectName: 'project', nameText: 'Task',
      status: 'idle', updatedAt: LEGACY_AT,
    }]);
    for (let index = 0; index < 201; index += 1) {
      const commandId = `cmd-${index}`;
      const result = { commandId, hostId: 'host-1', sessionId: 'sess-1', accepted: index % 2 === 0,
        status: index % 2 === 0 ? 'executed' as const : 'rejected' as const, message: 'recorded',
        updatedAt: `2026-08-07T00:${String(Math.floor(index / 60)).padStart(2, '0')}:${String(index % 60).padStart(2, '0')}.000Z` };
      store.rememberCommandResult(result, result);
    }
    store.replaceDriverSessions('pi', []);
    expect(store.getCommandResult('cmd-0')).toBeUndefined();
    expect(store.getCommandResult('cmd-200')).toMatchObject({ status: 'executed' });
    store.dispose();
    const restarted = new BridgeStateStore(statePath, undefined, { deferRuntimePreflight: true });
    restarted.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux', {
      loadOrCreate: () => new Uint8Array(32).fill(7),
    });
    expect(restarted.listSessions()).toEqual([]);
    expect(restarted.getCommandResult('cmd-1')).toMatchObject({ status: 'rejected' });
    expect(restarted.getCommandResult('cmd-200')).toMatchObject({ status: 'executed' });
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
