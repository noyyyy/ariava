import { afterEach, describe, expect, mock, test } from 'bun:test';
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  COMMAND_RECEIPT_RETENTION_MS, BridgeStateStore, runtimeMigrationIntentPathForState, runtimeSchemaFloorPathForState,
} from '../src/state-store';
import { spoolPathForState } from '../src/e2e/local-spool';
import { buildEncryptedCommandEnvelopeBindingBytes, contentSha256, type CanonicalEvent, type CanonicalSessionState,
  type CommandReceiptEnvelopeV1, type EncryptedCommandEnvelopeV1, type HostProjection } from '@ariava/protocol';

const LEGACY_AT = '2026-08-07T00:00:00.000Z';
const encryptedCommand = {
  commandId: 'command-v4', hostId: 'host-1', sessionId: 'sess-1', type: 'interrupt', issuedAt: LEGACY_AT,
  expiresAt: '2026-08-07T00:05:00.000Z', nonce: 'nonce-v4', watchDeviceId: 'watch-1', linkId: 'link-1',
  linkGeneration: 1, epoch: 1, payload: {
    content: { version: 1, suite: 'x25519-hkdf-sha256-chachapoly-v1', contentId: 'content-command',
      payloadKind: 'interrupt-content-v1', nonce: 'A'.repeat(16), ciphertext: 'A'.repeat(67) },
    keyWrap: { version: 1, suite: 'x25519-hkdf-sha256-chachapoly-v1', contentId: 'content-command', linkId: 'link-1',
      linkGeneration: 1, epoch: 1, senderEncryptionKeyId: `ekey_${'W'.repeat(43)}`,
      recipientEncryptionKeyId: `ekey_${'H'.repeat(43)}`, nonce: 'B'.repeat(16), ciphertext: 'C'.repeat(64) },
  },
} as const satisfies EncryptedCommandEnvelopeV1;
const pinReference = { version: 1, linkId: 'link-1', linkGeneration: 1, epoch: 1, transcriptDigest: 'T'.repeat(43),
  hostEncryptionKeyId: `ekey_${'H'.repeat(43)}`, watchEncryptionKeyId: `ekey_${'W'.repeat(43)}` } as const;
const claimedAt = '2026-08-07T00:00:01.000Z';
const terminalResult = { commandId: 'command-v4', hostId: 'host-1', sessionId: 'sess-1', accepted: true,
  status: 'executed', updatedAt: '2026-08-07T00:00:02.000Z' } as const;

async function commandDigest(command: EncryptedCommandEnvelopeV1): Promise<string> {
  return contentSha256(buildEncryptedCommandEnvelopeBindingBytes(command));
}

function receipt(commandDigestValue: string): CommandReceiptEnvelopeV1 {
  return { version: 1, hostId: 'host-1', watchDeviceId: 'watch-1', sessionId: 'sess-1', commandId: 'command-v4',
    commandType: 'interrupt', commandDigest: commandDigestValue, completedAt: terminalResult.updatedAt, linkId: 'link-1',
    linkGeneration: 1, epoch: 1, content: { version: 1, suite: 'x25519-hkdf-sha256-chachapoly-v1',
      contentId: 'content-receipt', payloadKind: 'command-receipt-content-v1', nonce: 'D'.repeat(16), ciphertext: 'E'.repeat(192) },
    keyWrap: { version: 1, suite: 'x25519-hkdf-sha256-chachapoly-v1', contentId: 'content-receipt', linkId: 'link-1',
      linkGeneration: 1, epoch: 1, senderEncryptionKeyId: pinReference.hostEncryptionKeyId,
      recipientEncryptionKeyId: pinReference.watchEncryptionKeyId, nonce: 'F'.repeat(16), ciphertext: 'G'.repeat(64) } };
}

const paths: string[] = [];

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

function pathHas(path: string): boolean { return existsSync(path); }

function downgradeCurrentRuntimeToV3(statePath: string): void {
  rmSync(runtimeSchemaFloorPathForState(statePath), { force: true });
  const prior = JSON.parse(readFileSync(statePath, 'utf8'));
  prior.schemaVersion = 3;
  delete prior.commandExecutions;
  prior.commandResults = { legacy: { commandId: 'legacy', hostId: 'host-1', sessionId: 'sess-1', accepted: true,
    status: 'executed', message: 'must disappear', updatedAt: LEGACY_AT } };
  prior.seenCommands = { legacy: LEGACY_AT };
  writeFileSync(statePath, `${JSON.stringify(prior, null, 2)}\n`, { mode: 0o600 });
  const spoolPath = spoolPathForState(statePath);
  const spool = JSON.parse(readFileSync(spoolPath, 'utf8'));
  spool.runtimeStateSchemaVersion = 3;
  writeFileSync(spoolPath, `${JSON.stringify(spool, null, 2)}\n`, { mode: 0o600 });
}

function seedV3Runtime(statePath: string): void {
  const root = join(statePath, '..');
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const seed = new BridgeStateStore(statePath);
  seed.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
  seed.setHost({ hostId: 'host-1', hostName: 'Host', platform: 'linux', bridgeVersion: '1',
    registeredAt: LEGACY_AT, lastSeenAt: LEGACY_AT, bridgeStatus: 'online' });
  seed.replaceDriverSessions('pi', [{ sessionId: 'sess-1', hostId: 'host-1', provider: 'pi', projectName: 'project',
    nameText: 'Task', status: 'idle', updatedAt: LEGACY_AT, lastEventId: 'evt-1' }]);
  seed.appendRecentEvent({ eventId: 'evt-1', hostId: 'host-1', sessionId: 'sess-1', provider: 'pi', type: 'done',
    status: 'idle', agentText: 'preserved', createdAt: LEGACY_AT });
  seed.queuePendingSessionHandle({ hostId: 'host-1', sessionId: 'sess-1', handledThroughEventId: 'evt-1',
    handledAt: LEGACY_AT, action: 'pi_input', updatedAt: LEGACY_AT });
  seed.dispose();
  downgradeCurrentRuntimeToV3(statePath);
}

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
    expect(persisted.schemaVersion).toBe(4);
    expect(persisted).not.toHaveProperty('pendingEvents');
    expect(persisted).not.toHaveProperty('pendingReads');
    expect(store.getRuntimeHealth()).toEqual({ status: 'healthy', drivers: [] });
    expect(persisted.runtimeHealth).toEqual({ status: 'healthy', drivers: [] });
  });

  test('migrates exact v3 metadata to v4 while dropping legacy command state', () => {
    const root = join(tmpdir(), `bridge-store-v3-migration-${Date.now()}`); paths.push(root);
    const statePath = join(root, 'state.json');
    seedV3Runtime(statePath);
    const migrated = new BridgeStateStore(statePath, undefined, { deferRuntimePreflight: true });
    migrated.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
    expect(migrated.getHost()?.hostName).toBe('Host');
    expect(migrated.listSessions().map((session) => session.sessionId)).toEqual(['sess-1']);
    expect(migrated.peekPendingSessionHandles()).toHaveLength(1); expect(migrated.listCommandExecutions()).toEqual([]);
    const persisted = JSON.parse(readFileSync(statePath, 'utf8'));
    expect(persisted).toMatchObject({ schemaVersion: 4, commandExecutions: {} });
    expect(persisted).not.toHaveProperty('commandResults'); expect(persisted).not.toHaveProperty('seenCommands');
    expect(JSON.parse(readFileSync(runtimeSchemaFloorPathForState(statePath), 'utf8'))).toEqual({
      version: 1, hostId: 'host-1', minSchemaVersion: 4, statePath, spoolPath: spoolPathForState(statePath),
    });
  });

  test.each(['intent', 'spool', 'state', 'floor', 'cleanup'] as const)('resumes v3 migration after a crash at %s', (boundary) => {
    const root = join(tmpdir(), `bridge-store-v3-crash-${boundary}-${Date.now()}`); paths.push(root);
    const statePath = join(root, 'state.json'); seedV3Runtime(statePath);
    const migration = new BridgeStateStore(statePath, undefined, { deferRuntimePreflight: true });
    const targetPath = boundary === 'intent' ? runtimeMigrationIntentPathForState(statePath)
      : boundary === 'spool' ? spoolPathForState(statePath)
      : boundary === 'state' ? statePath : runtimeSchemaFloorPathForState(statePath);
    let crashed = false;
    expect(() => migration.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux',
      { loadOrCreate: () => new Uint8Array(32).fill(7) }, undefined, {
        write: boundary === 'cleanup' ? undefined : { afterDirectorySync: (path) => {
          if (!crashed && path === targetPath) { crashed = true; throw new Error(`crash-${boundary}`); }
        } },
        remove: boundary === 'cleanup' ? { afterUnlink: () => { if (!crashed) { crashed = true; throw new Error('crash-cleanup'); } } } : undefined,
      })).toThrow();
    migration.dispose();
    const intentPath = runtimeMigrationIntentPathForState(statePath);
    if (boundary === 'intent') {
      expect(pathHas(intentPath)).toBe(false);
      expect(JSON.parse(readFileSync(statePath, 'utf8')).schemaVersion).toBe(3);
      const retry = new BridgeStateStore(statePath, undefined, { deferRuntimePreflight: true });
      retry.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
      expect(JSON.parse(readFileSync(statePath, 'utf8')).schemaVersion).toBe(4);
      return;
    }
    expect(pathHas(intentPath)).toBe(boundary !== 'cleanup');
    const resumed = new BridgeStateStore(statePath, undefined, { deferRuntimePreflight: true });
    resumed.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
    expect(resumed.listCommandExecutions()).toEqual([]);
    expect(JSON.parse(readFileSync(statePath, 'utf8'))).toMatchObject({ schemaVersion: 4, commandExecutions: {} });
    expect(JSON.parse(readFileSync(spoolPathForState(statePath), 'utf8')).runtimeStateSchemaVersion).toBe(4);
    expect(JSON.parse(readFileSync(runtimeSchemaFloorPathForState(statePath), 'utf8')).minSchemaVersion).toBe(4);
    expect(pathHas(intentPath)).toBe(false);
  });

  test('preserved schema floor rejects member rollback, missing members, and corrupt or foreign floors', () => {
    const root = join(tmpdir(), `bridge-store-floor-rollback-${Date.now()}`); paths.push(root);
    const statePath = join(root, 'state.json'); seedV3Runtime(statePath);
    const migrated = new BridgeStateStore(statePath, undefined, { deferRuntimePreflight: true });
    migrated.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
    migrated.dispose();
    const stateV4 = readFileSync(statePath); const spoolV4 = readFileSync(spoolPathForState(statePath));
    const floorV4 = readFileSync(runtimeSchemaFloorPathForState(statePath));
    const stateV3 = JSON.parse(stateV4.toString('utf8')); stateV3.schemaVersion = 3; delete stateV3.commandExecutions;
    stateV3.commandResults = {}; stateV3.seenCommands = {};
    const spoolV3 = JSON.parse(spoolV4.toString('utf8')); spoolV3.runtimeStateSchemaVersion = 3;
    const candidates: Array<() => void> = [
      () => writeFileSync(statePath, `${JSON.stringify(stateV3, null, 2)}\n`, { mode: 0o600 }),
      () => writeFileSync(spoolPathForState(statePath), `${JSON.stringify(spoolV3, null, 2)}\n`, { mode: 0o600 }),
      () => rmSync(statePath), () => rmSync(spoolPathForState(statePath)),
      () => writeFileSync(runtimeSchemaFloorPathForState(statePath), '{bad json', { mode: 0o600 }),
      () => writeFileSync(runtimeSchemaFloorPathForState(statePath), `${JSON.stringify({ ...JSON.parse(floorV4.toString('utf8')), hostId: 'host-foreign' })}\n`, { mode: 0o600 }),
    ];
    for (const mutate of candidates) {
      writeFileSync(statePath, stateV4, { mode: 0o600 }); writeFileSync(spoolPathForState(statePath), spoolV4, { mode: 0o600 });
      writeFileSync(runtimeSchemaFloorPathForState(statePath), floorV4, { mode: 0o600 }); mutate();
      const store = new BridgeStateStore(statePath, undefined, { deferRuntimePreflight: true });
      expect(() => store.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux',
        { loadOrCreate: () => new Uint8Array(32).fill(7) })).toThrow('Bridge runtime preflight failed closed');
      store.dispose();
    }
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
  function producerTombstoneFixture(label: string, registerSession = true) {
    const root = join(tmpdir(), `bridge-store-producer-${label}-${Date.now()}`);
    paths.push(root);
    const statePath = join(root, 'state.json');
    const identityPath = join(root, 'identity.json');
    const keyStore = { loadOrCreate: () => new Uint8Array(32).fill(7) };
    const event = {
      eventId: 'evt-completed', hostId: 'host-1', sessionId: 'sess-1', provider: 'pi', type: 'done', status: 'idle',
      agentText: 'Done', createdAt: LEGACY_AT,
    } satisfies CanonicalEvent;
    const session = {
      sessionId: event.sessionId, hostId: event.hostId, provider: event.provider, projectName: 'project', nameText: 'Task',
      status: 'idle', updatedAt: LEGACY_AT, lastEventId: event.eventId,
    } satisfies CanonicalSessionState;
    const reservation = {
      version: 1 as const, eventId: event.eventId, sessionId: event.sessionId, fingerprint: 'fingerprint',
      createdAt: event.createdAt,
    };
    const store = new BridgeStateStore(statePath);
    store.initializeEncryptedSpool(event.hostId, identityPath, 'linux', keyStore);
    if (registerSession) store.replaceDriverSessions('pi', [session]);
    store.appendRecentEvent(event);
    store.reserveProducerEvent(reservation);
    return { root, statePath, identityPath, keyStore, store, event, session, reservation };
  }

  test.each(['reconcile', 'unregister'] as const)('retains completed producer dedupe tombstones through %s Session removal and restart', (removal) => {
    const { statePath, identityPath, keyStore, store, session, reservation } = producerTombstoneFixture(`history-${removal}`);
    if (removal === 'reconcile') store.replaceDriverSessions('pi', []);
    else expect(store.removeSession(session.sessionId, 'pi')).toBe(true);
    store.dispose();

    const restarted = new BridgeStateStore(statePath, undefined, { deferRuntimePreflight: true });
    expect(() => restarted.initializeEncryptedSpool('host-1', identityPath, 'linux', keyStore)).not.toThrow();
    expect(restarted.listSessions()).toEqual([]);
    expect(restarted.getProducerEventReservation(session.sessionId, reservation.fingerprint)).toEqual(reservation);
    restarted.dispose();
  });

  test('retains completed producer dedupe tombstones after their Event history is evicted', () => {
    const { statePath, identityPath, keyStore, store, event, reservation } = producerTombstoneFixture('eviction');
    store.replaceDriverSessions('pi', []);
    for (let index = 0; index < 201; index += 1) {
      store.appendRecentEvent({
        eventId: `evt-new-${index}`, hostId: 'host-1', sessionId: 'other', provider: 'pi', type: 'done', status: 'idle',
        agentText: 'New', createdAt: new Date(Date.parse(LEGACY_AT) + index + 1).toISOString(),
      });
    }
    expect(JSON.parse(readFileSync(statePath, 'utf8')).recentEvents.some(
      (candidate: { eventId: string }) => candidate.eventId === event.eventId,
    )).toBe(false);
    store.dispose();

    const restarted = new BridgeStateStore(statePath, undefined, { deferRuntimePreflight: true });
    expect(() => restarted.initializeEncryptedSpool('host-1', identityPath, 'linux', keyStore)).not.toThrow();
    expect(restarted.getProducerEventReservation(event.sessionId, reservation.fingerprint)?.eventId).toBe(event.eventId);
    restarted.dispose();
  });

  test('fails closed on a producer tombstone that conflicts with retained Event evidence', () => {
    const { statePath, identityPath, keyStore, store } = producerTombstoneFixture('corruption', false);
    store.dispose();

    const persisted = JSON.parse(readFileSync(statePath, 'utf8'));
    persisted.producerEventReservations['sess-1\nfingerprint'].createdAt = '2026-08-07T00:00:01.000Z';
    writeFileSync(statePath, JSON.stringify(persisted), { mode: 0o600 });

    const restarted = new BridgeStateStore(statePath, undefined, { deferRuntimePreflight: true });
    expect(() => restarted.initializeEncryptedSpool('host-1', identityPath, 'linux', keyStore))
      .toThrow('Bridge runtime preflight failed closed');
    restarted.dispose();
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
    expect(store.getCommandExecution('command')).toBeUndefined();
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
    rmSync(runtimeSchemaFloorPathForState(statePath), { force: true });

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

  test('enforces atomic command claim and orphan recovery transitions', async () => {
    const root = join(tmpdir(), `bridge-store-command-v4-${Date.now()}`); paths.push(root);
    const statePath = join(root, 'state.json');
    const store = new BridgeStateStore(statePath);
    const digest = await commandDigest(encryptedCommand);
    const claim = { originalEncryptedCommand: encryptedCommand, commandDigest: digest, pinReference, claimedAt };
    expect(store.claimCommandExecution(claim).status).toBe('claimed');
    expect(store.claimCommandExecution(claim).status).toBe('duplicate');
    const conflictingCommand = { ...encryptedCommand, nonce: 'different-nonce' };
    expect(store.claimCommandExecution({ ...claim, originalEncryptedCommand: conflictingCommand,
      commandDigest: await commandDigest(conflictingCommand) })).toEqual({ status: 'conflict' });
    const nonceConflictCommand = { ...encryptedCommand, commandId: 'other-command' };
    expect(store.claimCommandExecution({ ...claim, originalEncryptedCommand: nonceConflictCommand,
      commandDigest: await commandDigest(nonceConflictCommand) })).toEqual({ status: 'conflict' });
    expect(store.markCommandDispatchStarted(encryptedCommand.commandId, '2026-08-07T00:00:01.500Z').state).toBe('dispatch_started');
    store.dispose();
    const restarted = new BridgeStateStore(statePath);
    expect(restarted.recoverOrphanedCommandExecutions()).toBe(1);
    expect(restarted.getCommandExecution(encryptedCommand.commandId)).toMatchObject({ state: 'outcome_unknown' });
    expect(() => restarted.persistTerminalReceiptBlocked(encryptedCommand.commandId, terminalResult)).toThrow();
  });

  test('validates every persisted execution against the exact retained pin before recovery', async () => {
    const root = join(tmpdir(), `bridge-store-pin-validation-${Date.now()}`); paths.push(root);
    const statePath = join(root, 'state.json');
    const seeded = new BridgeStateStore(statePath);
    seeded.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
    const digest = await commandDigest(encryptedCommand);
    seeded.claimCommandExecution({ originalEncryptedCommand: encryptedCommand, commandDigest: digest, pinReference, claimedAt });
    seeded.dispose();
    for (const resolved of [undefined, { ...pinReference, transcriptDigest: 'Z'.repeat(43) },
      { ...pinReference, hostEncryptionKeyId: `ekey_${'X'.repeat(43)}` },
      { ...pinReference, watchEncryptionKeyId: `ekey_${'Y'.repeat(43)}` }]) {
      const store = new BridgeStateStore(statePath, undefined, { deferRuntimePreflight: true });
      store.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
      expect(() => store.recoverOrphanedCommandExecutions()).toThrow('pins are unavailable');
      expect(() => store.validateCommandExecutionPins({ resolvePinReference: () => resolved })).toThrow('unavailable or inconsistent');
      expect(() => store.recoverOrphanedCommandExecutions()).toThrow('pins are unavailable');
      store.dispose();
    }
    const valid = new BridgeStateStore(statePath, undefined, { deferRuntimePreflight: true });
    valid.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
    valid.validateCommandExecutionPins({ resolvePinReference: () => pinReference });
    expect(valid.recoverOrphanedCommandExecutions()).toBe(1);
  });

  test('allows unavailable pins only for durable terminal command states', async () => {
    const root = join(tmpdir(), `bridge-store-terminal-pin-validation-${Date.now()}`); paths.push(root);
    const statePath = join(root, 'state.json');
    const seeded = new BridgeStateStore(statePath);
    seeded.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
    const digest = await commandDigest(encryptedCommand);
    seeded.claimCommandExecution({ originalEncryptedCommand: encryptedCommand, commandDigest: digest, pinReference, claimedAt });
    seeded.persistTerminalReceiptBlocked(encryptedCommand.commandId, terminalResult);
    seeded.dispose();
    const restarted = new BridgeStateStore(statePath, undefined, { deferRuntimePreflight: true });
    restarted.initializeEncryptedSpool('host-1', join(root, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
    expect(() => restarted.validateCommandExecutionPins({ resolvePinReference: () => undefined })).toThrow('unavailable or inconsistent');
    expect(() => restarted.validateCommandExecutionPins(
      { resolvePinReference: () => undefined }, { allowUnavailableForTerminal: true },
    )).not.toThrow();
    expect(restarted.getCommandExecution(encryptedCommand.commandId)?.state).toBe('terminal_receipt_blocked');
    restarted.dispose();
  });

  test('rejects a seventh command terminal result field before and during durable recovery', async () => {
    const root = join(tmpdir(), `bridge-store-terminal-result-exact-${Date.now()}`); paths.push(root);
    const statePath = join(root, 'state.json');
    const store = new BridgeStateStore(statePath);
    const digest = await commandDigest(encryptedCommand);
    store.claimCommandExecution({ originalEncryptedCommand: encryptedCommand, commandDigest: digest, pinReference, claimedAt });
    const inexactResult = { ...terminalResult, correlationId: 'forbidden' };
    expect(() => store.persistTerminalReceiptBlocked(encryptedCommand.commandId, inexactResult as any)).toThrow(
      'command terminal result binding is invalid',
    );
    expect(store.getCommandExecution(encryptedCommand.commandId)?.state).toBe('claimed');
    store.persistTerminalReceiptBlocked(encryptedCommand.commandId, terminalResult);
    store.dispose();
    const persisted = JSON.parse(readFileSync(statePath, 'utf8'));
    persisted.commandExecutions[encryptedCommand.commandId].terminalResult.correlationId = 'forbidden';
    writeFileSync(statePath, JSON.stringify(persisted), { mode: 0o600 });
    expect(() => new BridgeStateStore(statePath)).toThrow('Bridge state file is invalid or insecure');
  });

  test('persists receipt-blocked and terminal outbox states atomically and monotonically', async () => {
    const root = join(tmpdir(), `bridge-store-terminal-v4-${Date.now()}`); paths.push(root);
    const store = new BridgeStateStore(join(root, 'state.json'));
    const digest = await commandDigest(encryptedCommand);
    store.claimCommandExecution({ originalEncryptedCommand: encryptedCommand, commandDigest: digest, pinReference, claimedAt });
    const blocked = store.persistTerminalReceiptBlocked(encryptedCommand.commandId, terminalResult);
    expect(blocked).toMatchObject({ state: 'terminal_receipt_blocked', terminalResult });
    expect(blocked).not.toHaveProperty('receiptOutbox');
    const envelope = receipt(digest);
    const canonicalBody = JSON.stringify(envelope);
    const receiptDigest = await contentSha256((await import('@ariava/protocol')).buildCommandReceiptEnvelopeBindingBytes(envelope));
    const terminal = store.persistTerminalCommandReceipt(encryptedCommand.commandId, terminalResult, { receipt: envelope, canonicalBody, receiptDigest });
    expect(terminal).toMatchObject({ state: 'terminal', receiptOutbox: { state: 'pending', canonicalBody, receiptDigest } });
    expect(store.markCommandReceiptOutbox(encryptedCommand.commandId, 'acknowledged').receiptOutbox?.state).toBe('acknowledged');
    expect(() => store.markCommandReceiptOutbox(encryptedCommand.commandId, 'undeliverable')).toThrow();
    const secondCommand = { ...encryptedCommand, commandId: 'command-undeliverable', nonce: 'nonce-undeliverable' };
    const secondResult = { ...terminalResult, commandId: secondCommand.commandId };
    const secondDigest = await commandDigest(secondCommand);
    store.claimCommandExecution({ originalEncryptedCommand: secondCommand, commandDigest: secondDigest, pinReference, claimedAt });
    const secondReceipt = { ...receipt(secondDigest), commandId: secondCommand.commandId, commandDigest: secondDigest };
    const secondBody = JSON.stringify(secondReceipt);
    const secondReceiptDigest = await contentSha256((await import('@ariava/protocol')).buildCommandReceiptEnvelopeBindingBytes(secondReceipt));
    store.persistTerminalCommandReceipt(secondCommand.commandId, secondResult, {
      receipt: secondReceipt, canonicalBody: secondBody, receiptDigest: secondReceiptDigest,
    });
    expect(store.markCommandReceiptOutbox(secondCommand.commandId, 'undeliverable').receiptOutbox?.state).toBe('undeliverable');
  });

  test('maps every persisted execution state to its exact pin retention category', async () => {
    const expected = {
      claimed: 'executionRetainedThrough', dispatch_started: 'executionRetainedThrough',
      outcome_unknown: 'executionRetainedThrough', terminal_receipt_blocked: 'terminalReceiptRetainedThrough',
      pending: 'pendingOutboxRetainedThrough', acknowledged: 'terminalReceiptRetainedThrough',
      undeliverable: 'undeliverableOutboxRetainedThrough',
    } as const;
    for (const [state, category] of Object.entries(expected)) {
      const root = join(tmpdir(), `bridge-store-retention-${state}-${crypto.randomUUID()}`); paths.push(root);
      const store = new BridgeStateStore(join(root, 'state.json'));
      const command = { ...structuredClone(encryptedCommand), commandId: `command-${state}`, nonce: `nonce-${state}` };
      const result = { ...terminalResult, commandId: command.commandId };
      const digest = await commandDigest(command);
      store.claimCommandExecution({ originalEncryptedCommand: command, commandDigest: digest, pinReference, claimedAt });
      if (state === 'dispatch_started') store.markCommandDispatchStarted(command.commandId, '2026-08-07T00:00:01.500Z');
      if (state === 'outcome_unknown') store.markCommandOutcomeUnknown(command.commandId);
      if (state === 'terminal_receipt_blocked') store.persistTerminalReceiptBlocked(command.commandId, result);
      if (state === 'pending' || state === 'acknowledged' || state === 'undeliverable') {
        const envelope = { ...receipt(digest), commandId: command.commandId, commandDigest: digest };
        store.persistTerminalCommandReceipt(command.commandId, result, {
          receipt: envelope, canonicalBody: JSON.stringify(envelope),
          receiptDigest: await contentSha256((await import('@ariava/protocol')).buildCommandReceiptEnvelopeBindingBytes(envelope)),
        });
        if (state !== 'pending') store.markCommandReceiptOutbox(command.commandId, state);
      }
      const retainThrough = category === 'executionRetainedThrough'
        ? '2026-08-07T00:10:00.000Z' : '2026-09-06T00:00:02.000Z';
      expect(store.commandExecutionPinRetentionReferences()).toEqual({
        [category]: { 'link-1:1:1': retainThrough },
      });
      store.dispose();
    }
  });

  test('prunes executions atomically only after their state-derived retention boundary and survives restart', async () => {
    const root = join(tmpdir(), `bridge-store-prune-${crypto.randomUUID()}`); paths.push(root);
    const statePath = join(root, 'state.json');
    const store = new BridgeStateStore(statePath);
    const digest = await commandDigest(encryptedCommand);
    store.claimCommandExecution({ originalEncryptedCommand: encryptedCommand, commandDigest: digest, pinReference, claimedAt });
    const expiryBoundary = new Date(Date.parse(encryptedCommand.expiresAt) + 300_000).toISOString();
    expect(store.pruneEligibleCommandExecutions(expiryBoundary)).toEqual([]);
    expect(store.getCommandExecution(encryptedCommand.commandId)).toBeDefined();
    store.dispose();
    const restarted = new BridgeStateStore(statePath);
    expect(restarted.pruneEligibleCommandExecutions(new Date(Date.parse(expiryBoundary) + 1).toISOString())).toHaveLength(1);
    expect(restarted.getCommandExecution(encryptedCommand.commandId)).toBeUndefined();
    restarted.dispose();
  });

  test('retains every terminal outbox state through terminal updatedAt plus exactly 30 days', async () => {
    for (const state of ['pending', 'acknowledged', 'undeliverable'] as const) {
      const root = join(tmpdir(), `bridge-store-terminal-prune-${state}-${crypto.randomUUID()}`); paths.push(root);
      const store = new BridgeStateStore(join(root, 'state.json'));
      const command = { ...structuredClone(encryptedCommand), commandId: `command-${state}`, nonce: `nonce-${state}` };
      const result = { ...terminalResult, commandId: command.commandId };
      const digest = await commandDigest(command);
      store.claimCommandExecution({ originalEncryptedCommand: command, commandDigest: digest, pinReference, claimedAt });
      const envelope = { ...receipt(digest), commandId: command.commandId, commandDigest: digest };
      store.persistTerminalCommandReceipt(command.commandId, result, {
        receipt: envelope, canonicalBody: JSON.stringify(envelope),
        receiptDigest: await contentSha256((await import('@ariava/protocol')).buildCommandReceiptEnvelopeBindingBytes(envelope)),
      });
      if (state !== 'pending') store.markCommandReceiptOutbox(command.commandId, state);
      const boundary = new Date(Date.parse(result.updatedAt) + COMMAND_RECEIPT_RETENTION_MS).toISOString();
      expect(store.pruneEligibleCommandExecutions(boundary)).toEqual([]);
      expect(store.pruneEligibleCommandExecutions(new Date(Date.parse(boundary) + 1).toISOString())).toHaveLength(1);
      store.dispose();
    }
  });

  test('rejects corrupt or illegal persisted v4 command combinations', async () => {
    const root = join(tmpdir(), `bridge-store-corrupt-v4-${Date.now()}`); paths.push(root);
    const statePath = join(root, 'state.json');
    const store = new BridgeStateStore(statePath);
    const digest = await commandDigest(encryptedCommand);
    store.claimCommandExecution({ originalEncryptedCommand: encryptedCommand, commandDigest: digest, pinReference, claimedAt });
    store.dispose();
    const original = JSON.parse(readFileSync(statePath, 'utf8'));
    for (const mutate of [
      (state: any) => { state.commandExecutions['command-v4'].commandDigest = 'Z'.repeat(43); },
      (state: any) => { state.commandExecutions['command-v4'].state = 'terminal'; },
      (state: any) => { state.commandExecutions['command-v4'].terminalResult = terminalResult; },
      (state: any) => { state.commandExecutions['command-v4'].extra = true; },
    ]) {
      const candidate = structuredClone(original); mutate(candidate); writeFileSync(statePath, JSON.stringify(candidate), { mode: 0o600 });
      expect(() => new BridgeStateStore(statePath)).toThrow('Bridge state file is invalid or insecure');
    }
  });

  test('direct current-state load rejects duplicate nonces and invalid session-driver relationships', async () => {
    const root = join(tmpdir(), `bridge-store-direct-relationships-${Date.now()}`); paths.push(root);
    const statePath = join(root, 'state.json');
    const store = new BridgeStateStore(statePath);
    store.replaceDriverSessions('pi', [{ sessionId: 'sess-1', hostId: 'host-1', provider: 'pi', projectName: 'project',
      nameText: 'Task', status: 'idle', updatedAt: LEGACY_AT }]);
    const digest = await commandDigest(encryptedCommand);
    store.claimCommandExecution({ originalEncryptedCommand: encryptedCommand, commandDigest: digest, pinReference, claimedAt });
    store.dispose();
    const original = JSON.parse(readFileSync(statePath, 'utf8'));
    const duplicate = structuredClone(original);
    const secondCommand = { ...structuredClone(encryptedCommand), commandId: 'command-second' };
    duplicate.commandExecutions['command-second'] = { ...structuredClone(duplicate.commandExecutions['command-v4']),
      originalEncryptedCommand: secondCommand, commandDigest: await commandDigest(secondCommand) };
    const badKey = structuredClone(original); badKey.sessionDrivers = { wrong: 'pi' };
    const badProvider = structuredClone(original); badProvider.sessionDrivers['sess-1'] = 'other';
    for (const candidate of [duplicate, badKey, badProvider]) {
      writeFileSync(statePath, `${JSON.stringify(candidate, null, 2)}\n`, { mode: 0o600 });
      expect(() => new BridgeStateStore(statePath)).toThrow('Bridge state file is invalid or insecure');
    }
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
