import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, lstatSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  BRIDGE_RUNTIME_STATE_SCHEMA_VERSION,
  BridgeStateStore,
  runtimeResetIntentPathForState,
} from '../dist/state-store.js';
import { base64UrlEncode } from '../../../packages/protocol/dist/index.js';
import { LinuxSpoolKeyStore, spoolKeyIdForKey, spoolPathForState } from '../dist/e2e/local-spool.js';
import { BridgeDaemon } from '../dist/daemon.js';
import { EncryptedUploadOrchestrator } from '../dist/e2e/upload-orchestrator.js';
import { generateHostEncryptionIdentity } from '../dist/identity/host-encryption-key.js';

const HOST_ID = 'host-test';
const CREATED_AT = '2026-08-07T00:00:00.000Z';
const OLD_KINDS = [
  'event-source-v1',
  'event-dead-letter-v1',
  'session-source-v1',
  'event-upload-v1',
  'session-upload-v1',
];

function oldState() {
  const session = {
    sessionId: 'session', hostId: HOST_ID, provider: 'pi', projectName: 'project', nameText: 'name',
    stateLabel: 'Done', status: 'done', updatedAt: CREATED_AT, lastEventId: 'event',
  };
  const event = {
    eventId: 'event', hostId: HOST_ID, sessionId: 'session', provider: 'pi', type: 'done', status: 'done',
    typeLabel: 'Task complete', agentText: 'legacy protected event', createdAt: CREATED_AT,
  };
  return {
    schemaVersion: 1,
    host: {
      hostId: HOST_ID, hostName: 'Legacy Host', platform: 'linux', bridgeVersion: '0.2.0',
      registeredAt: CREATED_AT, lastSeenAt: CREATED_AT, bridgeStatus: 'online',
    },
    sessions: { session },
    sessionDrivers: { session: 'pi' },
    reconciledDrivers: { pi: true },
    recentEvents: [event],
    pendingEvents: [event],
    sessionRevisions: { session: 7 },
    recipientSetVersion: 9,
    spoolMigration: { version: 1, remainingEventIds: ['event'], startedAt: CREATED_AT },
    eventUploadCompletions: { event: {
      version: 1, eventId: 'event', sessionId: 'session', revision: 7,
      eventContentId: 'event-content', sessionContentId: 'session-content', committedAt: CREATED_AT,
    } },
    producerEventReservations: { ['session\nfingerprint']: {
      version: 1, eventId: 'event', sessionId: 'session', fingerprint: 'fingerprint', createdAt: CREATED_AT,
    } },
    terminalCancellations: { event: {
      version: 1, sessionId: 'session', eventId: 'event', fingerprint: 'fingerprint',
      removeSession: false, createdAt: CREATED_AT,
    } },
    pendingHandles: { [`${HOST_ID}:session`]: {
      hostId: HOST_ID, sessionId: 'session', handledThroughEventId: 'event', handledAt: CREATED_AT,
      action: 'pi_input', updatedAt: CREATED_AT,
    } },
    pendingReads: { [`${HOST_ID}:session`]: {
      hostId: HOST_ID, sessionId: 'session', latestReadEventId: 'event', readAt: CREATED_AT,
      source: 'pi_local_interaction', updatedAt: CREATED_AT,
    } },
    commandResults: { command: {
      commandId: 'command', hostId: HOST_ID, sessionId: 'session', accepted: true,
      status: 'executed', message: 'done', updatedAt: CREATED_AT,
    } },
    seenCommands: { command: CREATED_AT },
    currentSessionsSnapshot: {
      version: 1, lastAllocatedRevision: 8, lastAcceptedRevision: 7, lastAcceptedDigest: 'digest',
      lastAcceptedContentDigest: 'content-digest', lastAcceptedRecipientSetVersion: 9,
      pending: {
        request: { hostId: HOST_ID, revision: 8, observedAt: CREATED_AT, recipientSetVersion: 9,
          sessions: [{ sessionId: 'session', sessionRevision: 7 }] },
        digest: 'pending-digest', contentDigest: 'pending-content-digest',
      },
    },
  };
}

function oldSpoolBinding(kind) {
  if (kind.startsWith('session-')) {
    return { spoolItemId: kind === 'session-source-v1' ? 'session' : 'inflight:session:session' };
  }
  if (kind === 'event-source-v1') return { spoolItemId: 'event', eventId: 'event' };
  if (kind === 'event-dead-letter-v1') return { spoolItemId: 'dead-letter:event:event', eventId: 'event' };
  return { spoolItemId: 'inflight:event:event', eventId: 'event' };
}

function standaloneSpoolBinding(kind) {
  if (kind === 'session-source-v2') return { spoolItemId: 'session' };
  if (kind === 'session-upload-v2') return { spoolItemId: 'inflight:session:session' };
  if (kind === 'event-dead-letter-v2') return { spoolItemId: 'dead-letter:event:event', eventId: 'event' };
  if (kind === 'event-upload-v2') return { spoolItemId: 'inflight:event:event', eventId: 'event' };
  if (kind === 'terminal-cancellation-v2') return { spoolItemId: 'cancel:terminal:event', eventId: 'event' };
  return { spoolItemId: 'event', eventId: 'event' };
}

function spoolItem(kind, binding = oldSpoolBinding(kind)) {
  return {
    version: 1, ...binding, hostId: HOST_ID, sessionId: 'session', payloadKind: kind,
    nonce: base64UrlEncode(new Uint8Array(12).fill(1)),
    ciphertext: base64UrlEncode(new Uint8Array(16).fill(2)), aadVersion: 1, createdAt: CREATED_AT,
  };
}

function setupOldRuntime() {
  const dir = mkdtempSync(join(tmpdir(), 'ariava-runtime-reset-'));
  const statePath = join(dir, 'state.json');
  const identityPath = join(dir, 'identity.json');
  const keyPath = `${identityPath}.spool-key.json`;
  const spoolPath = spoolPathForState(statePath);
  const key = new Uint8Array(32).fill(7);
  writeFileSync(keyPath, `${JSON.stringify({ version: 1, hostId: HOST_ID, key: base64UrlEncode(key) })}\n`, { mode: 0o600 });
  const items = OLD_KINDS.map((kind) => spoolItem(kind));
  writeFileSync(spoolPath, `${JSON.stringify({ version: 1, items })}\n`, { mode: 0o600 });
  writeFileSync(statePath, `${JSON.stringify(oldState())}\n`, { mode: 0o600 });
  chmodSync(statePath, 0o600);
  const preserved = {
    identityPath,
    configPath: join(dir, 'config.json'),
    secretPath: join(dir, 'agent-secret.json'),
    keyringPath: `${identityPath}.e2e-keyring.json`,
    spoolKeyPath: keyPath,
    servicePath: join(dir, 'ariava.service'),
  };
  for (const [name, path] of Object.entries(preserved)) {
    if (path !== keyPath) writeFileSync(path, `PRESERVE_${name}\n`, { mode: 0o600 });
    chmodSync(path, 0o600);
  }
  return {
    dir,
    statePath,
    identityPath,
    spoolPath,
    keyPath,
    preserved,
    preservedBytes: Object.fromEntries(Object.entries(preserved).map(([name, path]) => [name, readFileSync(path)])),
  };
}

function setupObsoleteRuntime() {
  const fixture = setupOldRuntime();
  const epoch = '00000000-0000-4000-8000-000000000002';
  const state = {
    schemaVersion: 2, runtimeResetEpoch: epoch,
    host: { hostId: HOST_ID, hostName: 'Obsolete Host', platform: 'linux', bridgeVersion: '0.2.0',
      registeredAt: CREATED_AT, lastSeenAt: CREATED_AT, bridgeStatus: 'online' },
    sessions: { session: { sessionId: 'session', hostId: HOST_ID, provider: 'pi', projectName: 'project',
      nameText: 'name', status: 'idle', updatedAt: CREATED_AT, lastEventId: 'event' } },
    sessionDrivers: { session: 'pi' }, reconciledDrivers: { pi: true },
    recentEvents: [{ eventId: 'event', hostId: HOST_ID, sessionId: 'session', provider: 'pi', type: 'done',
      status: 'idle', typeLabel: 'Task complete', agentText: 'OBSOLETE_EVENT', createdAt: CREATED_AT }],
    sessionRevisions: { session: 7 }, recipientSetVersion: 9, pendingHandles: {},
    commandResults: { command: { commandId: 'command', hostId: HOST_ID, sessionId: 'session', accepted: true,
      status: 'executed', message: 'obsolete', updatedAt: CREATED_AT } }, seenCommands: { command: CREATED_AT },
    currentSessionsSnapshot: { version: 1, lastAllocatedRevision: 0, lastAcceptedRevision: 0 },
    runtimeHealth: { status: 'healthy', drivers: [] },
  };
  const keyId = spoolKeyIdForKey(new Uint8Array(32).fill(7));
  const spool = { version: 2, runtimeStateSchemaVersion: 2, runtimeResetEpoch: epoch, hostId: HOST_ID, keyId,
    items: [spoolItem('event-source-v2', standaloneSpoolBinding('event-source-v2'))] };
  writeFileSync(fixture.statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 });
  writeFileSync(fixture.spoolPath, `${JSON.stringify(spool)}\n`, { mode: 0o600 });
  return fixture;
}

function openDeferred(statePath) {
  return new BridgeStateStore(statePath, undefined, { deferRuntimePreflight: true });
}

function initialize(fixture, hook) {
  const store = openDeferred(fixture.statePath);
  try {
    store.initializeEncryptedSpool(HOST_ID, fixture.identityPath, 'linux', undefined, hook);
    return store;
  } catch (error) {
    store.dispose();
    throw error;
  }
}

function assertReset(fixture, store) {
  const state = JSON.parse(readFileSync(fixture.statePath, 'utf8'));
  const spool = JSON.parse(readFileSync(fixture.spoolPath, 'utf8'));
  assert.equal(state.schemaVersion, BRIDGE_RUNTIME_STATE_SCHEMA_VERSION);
  assert.equal(spool.runtimeStateSchemaVersion, BRIDGE_RUNTIME_STATE_SCHEMA_VERSION);
  assert.equal(state.runtimeResetEpoch, spool.runtimeResetEpoch);
  assert.equal(state.host, null);
  for (const key of [
    'sessions', 'sessionDrivers', 'reconciledDrivers', 'sessionRevisions', 'pendingHandles', 'commandResults', 'seenCommands',
  ]) assert.deepEqual(state[key], {}, key);
  for (const key of ['recipientSetVersion', 'eventUploadCompletions', 'producerEventReservations', 'terminalCancellations']) {
    assert.equal(state[key], undefined, key);
  }
  assert.deepEqual(state.recentEvents, []);
  assert.deepEqual(state.currentSessionsSnapshot, { version: 1, lastAllocatedRevision: 0, lastAcceptedRevision: 0 });
  assert.deepEqual(spool.items, []);
  assert.deepEqual(store.listSessions(), []);
  assert.deepEqual(store.peekPendingEvents(), []);
  assert.deepEqual(store.peekPendingSessionHandles(), []);
  assert.equal(store.getCommandResult('command'), undefined);
  assert.equal(store.hasSeenCommand('command'), false);
  assert.equal(store.getRecipientSetVersion(), undefined);
  assert.equal(store.getCurrentSessionsSnapshotState().lastAllocatedRevision, 0);
  assert.equal(lstatSync(runtimeResetIntentPathForState(fixture.statePath), { throwIfNoEntry: false }), undefined);
  for (const [name, path] of Object.entries(fixture.preserved)) {
    assert.deepEqual(readFileSync(path), fixture.preservedBytes[name], name);
  }
}

test('valid schema 2 runtime is recognized only to reset atomically to empty schema 3', () => {
  const fixture = setupObsoleteRuntime();
  try {
    const store = initialize(fixture);
    assertReset(fixture, store);
    assert.doesNotMatch(readFileSync(fixture.statePath, 'utf8'), /OBSOLETE_EVENT|obsolete/);
    assert.doesNotMatch(readFileSync(fixture.spoolPath, 'utf8'), /event-source-v2/);
  } finally { rmSync(fixture.dir, { recursive: true, force: true }); }
});

for (const [name, mutate] of [
  ['typeLabel missing', ({ state }) => { delete state.recentEvents[0].typeLabel; }],
  ['typeLabel malformed', ({ state }) => { state.recentEvents[0].typeLabel = 7; }],
  ['Host mismatch', ({ state }) => { state.sessions.session.hostId = 'foreign-host'; }],
  ['epoch mismatch', ({ spool }) => { spool.runtimeResetEpoch = '00000000-0000-4000-8000-000000000003'; }],
  ['key mismatch', ({ spool }) => { spool.keyId = 'A'.repeat(43); }],
  ['Event relationship mismatch', ({ spool }) => { spool.items[0].sessionId = 'orphan'; }],
]) {
  test(`malformed or mismatched schema 2 ${name} fails closed without mutation`, () => {
    const fixture = setupObsoleteRuntime();
    try {
      const state = JSON.parse(readFileSync(fixture.statePath, 'utf8'));
      const spool = JSON.parse(readFileSync(fixture.spoolPath, 'utf8'));
      mutate({ state, spool });
      const stateBytes = Buffer.from(`${JSON.stringify(state)}\n`);
      const spoolBytes = Buffer.from(`${JSON.stringify(spool)}\n`);
      writeFileSync(fixture.statePath, stateBytes, { mode: 0o600 });
      writeFileSync(fixture.spoolPath, spoolBytes, { mode: 0o600 });
      let keyAccessed = false;
      assert.throws(() => openDeferred(fixture.statePath).initializeEncryptedSpool(HOST_ID, fixture.identityPath, 'linux', {
        loadOrCreate: () => { keyAccessed = true; return new Uint8Array(32).fill(7); },
      }), /preflight failed closed/i);
      assert.equal(keyAccessed, name === 'key mismatch');
      assert.deepEqual(readFileSync(fixture.statePath), stateBytes);
      assert.deepEqual(readFileSync(fixture.spoolPath), spoolBytes);
      assert.equal(lstatSync(runtimeResetIntentPathForState(fixture.statePath), { throwIfNoEntry: false }), undefined);
    } finally { rmSync(fixture.dir, { recursive: true, force: true }); }
  });
}

test('interrupted schema 2 to 3 reset resumes without preserving obsolete records', () => {
  const fixture = setupObsoleteRuntime();
  try {
    assert.throws(() => initialize(fixture, (phase) => {
      if (phase === 'after-spool') throw new Error('crash:after-spool');
    }), /preflight failed closed/i);
    const intent = JSON.parse(readFileSync(runtimeResetIntentPathForState(fixture.statePath), 'utf8'));
    assert.deepEqual([intent.fromSchemaVersion, intent.toSchemaVersion], [2, 3]);
    const store = initialize(fixture);
    assertReset(fixture, store);
    assert.doesNotMatch(readFileSync(fixture.statePath, 'utf8'), /OBSOLETE_EVENT|obsolete/);
  } finally { rmSync(fixture.dir, { recursive: true, force: true }); }
});


test('interrupted legacy reset intent remains explicitly schema 1 to 2 before schema 3 cutover', () => {
  const fixture = setupOldRuntime();
  try {
    assert.throws(() => initialize(fixture, (phase) => {
      if (phase === 'after-intent') throw new Error('crash:after-intent');
    }), /preflight failed closed/i);
    const intent = JSON.parse(readFileSync(runtimeResetIntentPathForState(fixture.statePath), 'utf8'));
    assert.deepEqual([intent.fromSchemaVersion, intent.toSchemaVersion], [1, 2]);
    const store = initialize(fixture);
    assertReset(fixture, store);
  } finally { rmSync(fixture.dir, { recursive: true, force: true }); }
});


test('recognized prior runtime resets every JSON family and encrypted sidecar kind without replay', () => {
  const fixture = setupOldRuntime();
  try {
    const store = initialize(fixture);
    assertReset(fixture, store);
    for (const kind of OLD_KINDS) assert.doesNotMatch(readFileSync(fixture.spoolPath, 'utf8'), new RegExp(kind));
    assert.equal(JSON.parse(readFileSync(fixture.spoolPath, 'utf8')).keyId, spoolKeyIdForKey(new Uint8Array(32).fill(7)));
  } finally { rmSync(fixture.dir, { recursive: true, force: true }); }
});

test('recognized standalone v2 sidecar kinds trigger reset without payload decode', () => {
  const kinds = [
    'event-source-v2', 'event-reservation-v2', 'event-dead-letter-v2', 'session-source-v2',
    'event-upload-v2', 'session-upload-v2', 'terminal-cancellation-v2',
  ];
  for (const payloadKind of kinds) {
    const fixture = setupOldRuntime();
    try {
      rmSync(fixture.statePath);
      const keyId = spoolKeyIdForKey(new Uint8Array(32).fill(7));
      writeFileSync(fixture.spoolPath, `${JSON.stringify({
        version: 2, runtimeStateSchemaVersion: 2, runtimeResetEpoch: 'standalone', hostId: HOST_ID, keyId,
        items: [spoolItem(payloadKind, standaloneSpoolBinding(payloadKind))],
      })}\n`, { mode: 0o600 });
      assertReset(fixture, initialize(fixture));
    } finally { rmSync(fixture.dir, { recursive: true, force: true }); }
  }
});

test('recognized prior state-only and spool-only remnants both reset', () => {
  for (const missing of ['state', 'spool']) {
    const fixture = setupOldRuntime();
    try {
      rmSync(missing === 'state' ? fixture.statePath : fixture.spoolPath);
      const store = initialize(fixture);
      assertReset(fixture, store);
    } finally { rmSync(fixture.dir, { recursive: true, force: true }); }
  }
});

test('recognized prior runtime legitimacy matrix fails before key access byte-identically', () => {
  const mutations = [
    ['startup Host projection', ({ state }) => { state.host.hostId = 'foreign-host'; }],
    ['Session Host ownership', ({ state }) => { state.sessions.session.hostId = 'foreign-host'; }],
    ['Session map key', ({ state }) => { state.sessions.wrong = state.sessions.session; delete state.sessions.session; }],
    ['Session driver orphan', ({ state }) => { state.sessionDrivers.orphan = 'pi'; }],
    ['reconciled driver map key', ({ state }) => { state.reconciledDrivers[''] = true; }],
    ['recent Event Host ownership', ({ state }) => { state.recentEvents[0].hostId = 'foreign-host'; }],
    ['recent Event Session reference', ({ state }) => { state.recentEvents[0].sessionId = 'orphan'; }],
    ['recent Event cross-Session reference', ({ state }) => { state.sessions.other = { ...state.sessions.session, sessionId: 'other' }; state.recentEvents[0].sessionId = 'other'; }],
    ['pending Event duplicate ID', ({ state }) => { state.pendingEvents.push(structuredClone(state.pendingEvents[0])); }],
    ['spool migration Event reference', ({ state }) => { state.spoolMigration.remainingEventIds = ['orphan']; }],
    ['Session revision invalid cursor', ({ state }) => { state.sessionRevisions.orphan = 0; }],
    ['completion map key', ({ state }) => { state.eventUploadCompletions.wrong = state.eventUploadCompletions.event; delete state.eventUploadCompletions.event; }],
    ['completion Event reference', ({ state }) => { state.eventUploadCompletions.event.eventId = 'orphan'; }],
    ['completion Session reference', ({ state }) => { state.eventUploadCompletions.event.sessionId = 'orphan'; }],
    ['completion cross-Session Event reference', ({ state }) => { state.sessions.other = { ...state.sessions.session, sessionId: 'other' }; state.eventUploadCompletions.event.sessionId = 'other'; }],
    ['completion phase ordering', ({ state }) => { state.eventUploadCompletions.event.inflightRemoved = true; }],
    ['reservation fingerprint map key', ({ state }) => { state.producerEventReservations.wrong = state.producerEventReservations['session\nfingerprint']; delete state.producerEventReservations['session\nfingerprint']; }],
    ['reservation Event reference', ({ state }) => { state.producerEventReservations['session\nfingerprint'].eventId = 'orphan'; }],
    ['reservation Session reference', ({ state }) => { state.producerEventReservations['session\nfingerprint'].sessionId = 'orphan'; }],
    ['reservation cross-Session Event reference', ({ state }) => { state.sessions.other = { ...state.sessions.session, sessionId: 'other' }; const reservation = state.producerEventReservations['session\nfingerprint']; delete state.producerEventReservations['session\nfingerprint']; reservation.sessionId = 'other'; state.producerEventReservations['other\nfingerprint'] = reservation; }],
    ['cancellation journal map key', ({ state }) => { state.terminalCancellations.wrong = state.terminalCancellations.event; delete state.terminalCancellations.event; }],
    ['cancellation Event reference', ({ state }) => { state.terminalCancellations.event.eventId = 'orphan'; }],
    ['cancellation Session reference', ({ state }) => { state.terminalCancellations.event.sessionId = 'orphan'; }],
    ['cancellation cross-Session Event reference', ({ state }) => { state.sessions.other = { ...state.sessions.session, sessionId: 'other' }; state.terminalCancellations.event.sessionId = 'other'; }],
    ['cancellation fingerprint relationship', ({ state }) => { state.terminalCancellations.event.fingerprint = 'mismatch'; }],
    ['pending handle map key', ({ state }) => { state.pendingHandles.wrong = state.pendingHandles[`${HOST_ID}:session`]; delete state.pendingHandles[`${HOST_ID}:session`]; }],
    ['pending handle Host ownership', ({ state }) => { state.pendingHandles[`${HOST_ID}:session`].hostId = 'foreign-host'; }],
    ['pending handle Event reference', ({ state }) => { state.pendingHandles[`${HOST_ID}:session`].handledThroughEventId = 'orphan'; }],
    ['pending handle cross-Session Event reference', ({ state }) => { state.sessions.other = { ...state.sessions.session, sessionId: 'other' }; const handle = state.pendingHandles[`${HOST_ID}:session`]; delete state.pendingHandles[`${HOST_ID}:session`]; handle.sessionId = 'other'; state.pendingHandles[`${HOST_ID}:other`] = handle; }],
    ['pending read map key', ({ state }) => { state.pendingReads.wrong = state.pendingReads[`${HOST_ID}:session`]; delete state.pendingReads[`${HOST_ID}:session`]; }],
    ['pending read Session reference', ({ state }) => { state.pendingReads[`${HOST_ID}:session`].sessionId = 'orphan'; }],
    ['pending read cross-Session Event reference', ({ state }) => { state.sessions.other = { ...state.sessions.session, sessionId: 'other' }; const read = state.pendingReads[`${HOST_ID}:session`]; delete state.pendingReads[`${HOST_ID}:session`]; read.sessionId = 'other'; state.pendingReads[`${HOST_ID}:other`] = read; }],
    ['command result reproduction Host', ({ state }) => { state.commandResults.command.hostId = 'foreign-host'; }],
    ['command result map key', ({ state }) => { state.commandResults.wrong = state.commandResults.command; delete state.commandResults.command; }],
    ['command result cross-Session Event reference', ({ state }) => { state.sessions.other = { ...state.sessions.session, sessionId: 'other', lastEventId: 'event' }; state.commandResults.command.sessionId = 'other'; }],
    ['command dedupe timestamp', ({ state }) => { state.seenCommands.command = 'different'; }],
    ['command dedupe orphan', ({ state }) => { state.seenCommands.orphan = CREATED_AT; }],
    ['publication accepted revision', ({ state }) => { state.currentSessionsSnapshot.lastAcceptedRevision = 9; }],
    ['publication pending Host', ({ state }) => { state.currentSessionsSnapshot.pending.request.hostId = 'foreign-host'; }],
    ['publication pending Session reference', ({ state }) => { state.currentSessionsSnapshot.pending.request.sessions[0].sessionId = 'orphan'; }],
    ['publication recipient marker', ({ state }) => { state.recipientSetVersion = 8; }],
    ['spool item Host ownership', ({ spool }) => { spool.items[0].hostId = 'foreign-host'; }],
    ['spool item duplicate ID', ({ spool }) => { spool.items[1].spoolItemId = spool.items[0].spoolItemId; }],
    ['Event source ID', ({ spool }) => { spool.items.find((item) => item.payloadKind === 'event-source-v1').spoolItemId = 'wrong'; }],
    ['Event source Session reference', ({ spool }) => { spool.items.find((item) => item.payloadKind === 'event-source-v1').sessionId = 'orphan'; }],
    ['dead-letter Event ID', ({ spool }) => { spool.items.find((item) => item.payloadKind === 'event-dead-letter-v1').eventId = 'orphan'; }],
    ['Session source reference', ({ spool }) => { spool.items.find((item) => item.payloadKind === 'session-source-v1').sessionId = 'orphan'; }],
    ['Event upload reference', ({ spool }) => { spool.items.find((item) => item.payloadKind === 'event-upload-v1').eventId = 'orphan'; }],
    ['Session upload reference', ({ spool }) => { spool.items.find((item) => item.payloadKind === 'session-upload-v1').sessionId = 'orphan'; }],
  ];
  for (const [name, mutate] of mutations) {
    const fixture = setupOldRuntime();
    try {
      const state = JSON.parse(readFileSync(fixture.statePath, 'utf8'));
      const spool = JSON.parse(readFileSync(fixture.spoolPath, 'utf8'));
      mutate({ state, spool });
      const stateBytes = Buffer.from(`${JSON.stringify(state)}\n`);
      const spoolBytes = Buffer.from(`${JSON.stringify(spool)}\n`);
      writeFileSync(fixture.statePath, stateBytes, { mode: 0o600 });
      writeFileSync(fixture.spoolPath, spoolBytes, { mode: 0o600 });
      let keyAccessed = false;
      assert.throws(() => openDeferred(fixture.statePath).initializeEncryptedSpool(HOST_ID, fixture.identityPath, 'linux', {
        loadOrCreate: () => { keyAccessed = true; return new Uint8Array(32).fill(7); },
      }), /preflight failed closed/i, name);
      assert.equal(keyAccessed, false, name);
      assert.deepEqual(readFileSync(fixture.statePath), stateBytes, name);
      assert.deepEqual(readFileSync(fixture.spoolPath), spoolBytes, name);
      assert.equal(lstatSync(runtimeResetIntentPathForState(fixture.statePath), { throwIfNoEntry: false }), undefined, name);
    } finally { rmSync(fixture.dir, { recursive: true, force: true }); }
  }
});

for (const boundary of ['before-intent', 'after-intent', 'after-spool', 'after-state', 'after-cleanup']) {
  test(`runtime reset recovers deterministically after ${boundary} crash`, () => {
    const fixture = setupOldRuntime();
    const stateBefore = readFileSync(fixture.statePath);
    const spoolBefore = readFileSync(fixture.spoolPath);
    let crashed = false;
    try {
      assert.throws(() => initialize(fixture, (phase) => {
        if (!crashed && phase === boundary) { crashed = true; throw new Error(`crash:${phase}`); }
      }), /preflight failed closed/i);
      assert.equal(crashed, true);
      if (boundary === 'before-intent') {
        assert.deepEqual(readFileSync(fixture.statePath), stateBefore);
        assert.deepEqual(readFileSync(fixture.spoolPath), spoolBefore);
      }
      const recovered = initialize(fixture);
      assertReset(fixture, recovered);
    } finally { rmSync(fixture.dir, { recursive: true, force: true }); }
  });
}

test('reset recovery rejects member tampering before key access', () => {
  const fixture = setupOldRuntime();
  try {
    assert.throws(() => initialize(fixture, (phase) => {
      if (phase === 'after-intent') throw new Error('crash:after-intent');
    }), /preflight failed closed/i);
    writeFileSync(fixture.statePath, '{"tampered":true}\n', { mode: 0o600 });
    const stateBytes = readFileSync(fixture.statePath);
    const spoolBytes = readFileSync(fixture.spoolPath);
    let keyAccessed = false;
    assert.throws(() => openDeferred(fixture.statePath).initializeEncryptedSpool(HOST_ID, fixture.identityPath, 'linux', {
      loadOrCreate: () => { keyAccessed = true; return new Uint8Array(32); },
    }), /preflight failed closed/i);
    assert.equal(keyAccessed, false);
    assert.deepEqual(readFileSync(fixture.statePath), stateBytes);
    assert.deepEqual(readFileSync(fixture.spoolPath), spoolBytes);
  } finally { rmSync(fixture.dir, { recursive: true, force: true }); }
});

test('unknown state schema fails closed before key access and preserves exact bytes', () => {
  const fixture = setupOldRuntime();
  try {
    const bytes = Buffer.from('{"schemaVersion":999,"protected":"UNKNOWN"}\n');
    writeFileSync(fixture.statePath, bytes, { mode: 0o600 });
    let keyAccessed = false;
    const store = openDeferred(fixture.statePath);
    assert.throws(() => store.initializeEncryptedSpool(HOST_ID, fixture.identityPath, 'linux', {
      loadOrCreate: () => { keyAccessed = true; return new Uint8Array(32); },
    }), /schema|runtime/i);
    assert.equal(keyAccessed, false);
    assert.deepEqual(readFileSync(fixture.statePath), bytes);
  } finally { rmSync(fixture.dir, { recursive: true, force: true }); }
});

test('malformed current v2 state fails before key access and preserves state and spool bytes', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ariava-runtime-malformed-current-'));
  const statePath = join(dir, 'state.json');
  const identityPath = join(dir, 'identity.json');
  try {
    const initialized = initialize({ dir, statePath, identityPath });
    initialized.dispose();
    const state = JSON.parse(readFileSync(statePath, 'utf8'));
    state.sessions = { session: { marker: 'malformed-current-session' } };
    const stateBytes = Buffer.from(`${JSON.stringify(state)}\n`);
    const spoolBytes = readFileSync(spoolPathForState(statePath));
    writeFileSync(statePath, stateBytes, { mode: 0o600 });
    let keyAccessed = false;
    assert.throws(() => openDeferred(statePath).initializeEncryptedSpool(HOST_ID, identityPath, 'linux', {
      loadOrCreate: () => { keyAccessed = true; return new Uint8Array(32); },
    }), /preflight failed closed/i);
    assert.equal(keyAccessed, false);
    assert.deepEqual(readFileSync(statePath), stateBytes);
    assert.deepEqual(readFileSync(spoolPathForState(statePath)), spoolBytes);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('malformed and unknown spool metadata fail closed without decoding or rewriting bytes', () => {
  for (const replacement of ['{"version":2,"items":', JSON.stringify({ version: 2, hostId: HOST_ID, keyId: 'x', items: [{ payloadKind: 'unknown-v2' }] })]) {
    const fixture = setupOldRuntime();
    try {
      const stateBytes = readFileSync(fixture.statePath);
      const spoolBytes = Buffer.from(`${replacement}\n`);
      writeFileSync(fixture.spoolPath, spoolBytes, { mode: 0o600 });
      let keyAccessed = false;
      assert.throws(() => openDeferred(fixture.statePath).initializeEncryptedSpool(HOST_ID, fixture.identityPath, 'linux', {
        loadOrCreate: () => { keyAccessed = true; return new Uint8Array(32); },
      }), /spool|runtime/i);
      assert.equal(keyAccessed, false);
      assert.deepEqual(readFileSync(fixture.statePath), stateBytes);
      assert.deepEqual(readFileSync(fixture.spoolPath), spoolBytes);
    } finally { rmSync(fixture.dir, { recursive: true, force: true }); }
  }
});

test('malformed reset intent and key mismatch fail closed with original runtime bytes unchanged', () => {
  for (const mode of ['intent', 'key']) {
    const fixture = setupOldRuntime();
    try {
      const stateBytes = readFileSync(fixture.statePath);
      const spoolBytes = readFileSync(fixture.spoolPath);
      if (mode === 'intent') writeFileSync(runtimeResetIntentPathForState(fixture.statePath), '{"version":1}\n', { mode: 0o600 });
      else {
        const key = JSON.parse(readFileSync(fixture.keyPath, 'utf8'));
        key.hostId = 'wrong-host';
        writeFileSync(fixture.keyPath, `${JSON.stringify(key)}\n`, { mode: 0o600 });
      }
      assert.throws(() => initialize(fixture), /preflight failed closed/i);
      assert.deepEqual(readFileSync(fixture.statePath), stateBytes);
      assert.deepEqual(readFileSync(fixture.spoolPath), spoolBytes);
    } finally { rmSync(fixture.dir, { recursive: true, force: true }); }
  }
});

test('insecure state or spool symlink fails closed without changing the regular-file peer', () => {
  for (const target of ['state', 'spool']) {
    const fixture = setupOldRuntime();
    try {
      const peerPath = target === 'state' ? fixture.spoolPath : fixture.statePath;
      const peerBytes = readFileSync(peerPath);
      const targetPath = target === 'state' ? fixture.statePath : fixture.spoolPath;
      const realPath = `${targetPath}.real`;
      rmSync(targetPath);
      writeFileSync(realPath, 'PROTECTED\n', { mode: 0o600 });
      symlinkSync(realPath, targetPath);
      assert.throws(() => initialize(fixture), /invalid|insecure|secure|runtime/i);
      assert.deepEqual(readFileSync(peerPath), peerBytes);
      assert.equal(readFileSync(realPath, 'utf8'), 'PROTECTED\n');
    } finally { rmSync(fixture.dir, { recursive: true, force: true }); }
  }
});

test('reset intent symlink or insecure permissions fail closed without runtime mutation', () => {
  for (const mode of ['symlink', 'permissions']) {
    const fixture = setupOldRuntime();
    try {
      const stateBytes = readFileSync(fixture.statePath);
      const spoolBytes = readFileSync(fixture.spoolPath);
      const intentPath = runtimeResetIntentPathForState(fixture.statePath);
      if (mode === 'symlink') {
        const target = `${intentPath}.real`;
        writeFileSync(target, '{}\n', { mode: 0o600 });
        symlinkSync(target, intentPath);
      } else {
        writeFileSync(intentPath, '{}\n', { mode: 0o644 });
      }
      assert.throws(() => initialize(fixture), /preflight failed closed/i);
      assert.deepEqual(readFileSync(fixture.statePath), stateBytes);
      assert.deepEqual(readFileSync(fixture.spoolPath), spoolBytes);
    } finally { rmSync(fixture.dir, { recursive: true, force: true }); }
  }
});

test('fresh install creates matching current empty state and spool', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ariava-runtime-fresh-'));
  const fixture = { dir, statePath: join(dir, 'state.json'), identityPath: join(dir, 'identity.json') };
  try {
    const store = initialize(fixture);
    assertReset({ ...fixture, spoolPath: spoolPathForState(fixture.statePath), preserved: {}, preservedBytes: {} }, store);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('current v2 restart preserves valid runtime and uses key-verifier behavior', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ariava-runtime-current-'));
  const statePath = join(dir, 'state.json');
  const identityPath = join(dir, 'identity.json');
  try {
    const first = initialize({ dir, statePath, identityPath });
    first.replaceDriverSessions('pi', [{
      sessionId: 'session', hostId: HOST_ID, provider: 'pi', projectName: 'project', nameText: 'name',
      status: 'working', updatedAt: CREATED_AT,
    }]);
    first.persistInflightSessionUpload('session', { protected: 'CURRENT_V2' });
    const stateBytes = readFileSync(statePath);
    const spoolBytes = readFileSync(spoolPathForState(statePath));
    first.dispose();
    const restarted = initialize({ dir, statePath, identityPath });
    assert.equal(restarted.listSessions()[0]?.sessionId, 'session');
    assert.deepEqual(restarted.getInflightSessionUpload('session'), { protected: 'CURRENT_V2' });
    assert.deepEqual(readFileSync(statePath), stateBytes);
    assert.deepEqual(readFileSync(spoolPathForState(statePath)), spoolBytes);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

function sha256(bytes) { return createHash('sha256').update(bytes).digest('base64url'); }

test('forged reset intents cannot bless unknown source bytes and preserve every member byte', () => {
  for (const member of ['state', 'spool']) {
    const fixture = setupOldRuntime();
    try {
      assert.throws(() => initialize(fixture, (phase) => {
        if (phase === 'after-intent') throw new Error('crash:after-intent');
      }), /preflight failed closed/i);
      const intentPath = runtimeResetIntentPathForState(fixture.statePath);
      const intent = JSON.parse(readFileSync(intentPath, 'utf8'));
      const forged = Buffer.from(`{"unknownProtectedFamily":"FORGED_${member}"}\n`);
      const memberPath = member === 'state' ? fixture.statePath : fixture.spoolPath;
      writeFileSync(memberPath, forged, { mode: 0o600 });
      intent[`${member}SourceHash`] = sha256(forged);
      writeFileSync(intentPath, `${JSON.stringify(intent, null, 2)}\n`, { mode: 0o600 });
      const before = { state: readFileSync(fixture.statePath), spool: readFileSync(fixture.spoolPath), intent: readFileSync(intentPath) };
      let keyAccessed = false;
      assert.throws(() => openDeferred(fixture.statePath).initializeEncryptedSpool(HOST_ID, fixture.identityPath, 'linux', {
        loadOrCreate: () => { keyAccessed = true; return new Uint8Array(32).fill(7); },
      }), /preflight failed closed/i);
      assert.equal(keyAccessed, false);
      assert.deepEqual(readFileSync(fixture.statePath), before.state);
      assert.deepEqual(readFileSync(fixture.spoolPath), before.spool);
      assert.deepEqual(readFileSync(intentPath), before.intent);
    } finally { rmSync(fixture.dir, { recursive: true, force: true }); }
  }
});

test('reset intent path or Host rebinding is rejected before key access without mutation', () => {
  for (const field of ['statePath', 'spoolPath', 'intentPath', 'hostId']) {
    const fixture = setupOldRuntime();
    try {
      assert.throws(() => initialize(fixture, (phase) => {
        if (phase === 'after-intent') throw new Error('crash:after-intent');
      }), /preflight failed closed/i);
      const intentPath = runtimeResetIntentPathForState(fixture.statePath);
      const intent = JSON.parse(readFileSync(intentPath, 'utf8'));
      intent[field] = field === 'hostId' ? 'foreign-host' : join(fixture.dir, `foreign-${field}`);
      writeFileSync(intentPath, `${JSON.stringify(intent, null, 2)}\n`, { mode: 0o600 });
      const stateBytes = readFileSync(fixture.statePath); const spoolBytes = readFileSync(fixture.spoolPath);
      let keyAccessed = false;
      assert.throws(() => openDeferred(fixture.statePath).initializeEncryptedSpool(HOST_ID, fixture.identityPath, 'linux', {
        loadOrCreate: () => { keyAccessed = true; return new Uint8Array(32).fill(7); },
      }), /preflight failed closed/i);
      assert.equal(keyAccessed, false);
      assert.deepEqual(readFileSync(fixture.statePath), stateBytes);
      assert.deepEqual(readFileSync(fixture.spoolPath), spoolBytes);
    } finally { rmSync(fixture.dir, { recursive: true, force: true }); }
  }
});

test('current state requires its exact current spool, including the empty-state case', () => {
  for (const mode of ['missing-empty', 'missing-nonempty', 'truncated', 'swapped']) {
    const dir = mkdtempSync(join(tmpdir(), `ariava-current-spool-${mode}-`));
    const statePath = join(dir, 'state.json'); const identityPath = join(dir, 'identity.json');
    try {
      const store = initialize({ dir, statePath, identityPath });
      if (mode === 'missing-nonempty') store.replaceDriverSessions('pi', [{
        sessionId: 'session', hostId: HOST_ID, provider: 'pi', projectName: 'project', nameText: 'name',
        status: 'working', updatedAt: CREATED_AT,
      }]);
      const stateBytes = readFileSync(statePath); const spoolPath = spoolPathForState(statePath);
      if (mode.startsWith('missing')) rmSync(spoolPath);
      else if (mode === 'truncated') writeFileSync(spoolPath, '{"version":2,"items":', { mode: 0o600 });
      else {
        const spool = JSON.parse(readFileSync(spoolPath, 'utf8')); spool.runtimeResetEpoch = '00000000-0000-4000-8000-000000000000';
        writeFileSync(spoolPath, `${JSON.stringify(spool)}\n`, { mode: 0o600 });
      }
      const spoolBytes = mode.startsWith('missing') ? undefined : readFileSync(spoolPath);
      let keyAccessed = false;
      store.dispose();
      assert.throws(() => openDeferred(statePath).initializeEncryptedSpool(HOST_ID, identityPath, 'linux', {
        loadOrCreate: () => { keyAccessed = true; return new Uint8Array(32).fill(7); },
      }), /preflight failed closed/i);
      assert.equal(keyAccessed, false); assert.deepEqual(readFileSync(statePath), stateBytes);
      if (spoolBytes) assert.deepEqual(readFileSync(spoolPath), spoolBytes);
      else assert.equal(lstatSync(spoolPath, { throwIfNoEntry: false }), undefined);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }
});

for (const lifecycle of ['unregister', 'ttl']) {
  test(`historical Events and revision cursors survive ${lifecycle} reconciliation and restart without reactivation`, () => {
    const dir = mkdtempSync(join(tmpdir(), `ariava-current-history-${lifecycle}-`));
    const statePath = join(dir, 'state.json'); const identityPath = join(dir, 'identity.json');
    try {
      const store = initialize({ dir, statePath, identityPath });
      const terminal = { sessionId: 'session', hostId: HOST_ID, provider: 'pi', projectName: 'project', nameText: 'name',
        status: 'idle', updatedAt: CREATED_AT, lastEventId: 'event' };
      const event = { eventId: 'event', hostId: HOST_ID, sessionId: 'session', provider: 'pi', type: 'done', status: 'idle',
        agentText: 'done', createdAt: CREATED_AT };
      store.queuePendingEvent(event, terminal); store.commitSessionRevision('session', 1); store.removePendingEvent('event');
      const commandResult = { commandId: `command-${lifecycle}`, hostId: HOST_ID, sessionId: 'session', accepted: true,
        status: 'executed', message: lifecycle, updatedAt: CREATED_AT };
      store.rememberCommandResult(commandResult, commandResult);
      if (lifecycle === 'unregister') assert.equal(store.removeSession('session', 'pi'), true);
      else store.replaceDriverSessions('pi', []);
      const before = readFileSync(statePath);
      store.dispose();
      const restarted = initialize({ dir, statePath, identityPath });
      assert.deepEqual(restarted.listSessions(), []);
      assert.equal(restarted.currentSessionRevision('session'), 1);
      assert.equal(JSON.parse(readFileSync(statePath, 'utf8')).recentEvents[0].eventId, 'event');
      assert.deepEqual(restarted.getCommandResult(commandResult.commandId), commandResult);
      assert.equal(restarted.hasSeenCommand(commandResult.commandId), true);
      assert.deepEqual(readFileSync(statePath), before);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
}


test('current state Host and relationship adversarial matrix fails before key access byte-identically', () => {
  const mutations = [
    ['foreign Host projection', (state) => { state.host = { hostId: 'foreign', hostName: 'x', platform: 'linux', bridgeVersion: '1', registeredAt: CREATED_AT, lastSeenAt: CREATED_AT, bridgeStatus: 'online' }; }],
    ['foreign Session Host', (state) => { state.sessions.session.hostId = 'foreign'; }],
    ['Session map key mismatch', (state) => { state.sessions.other = state.sessions.session; delete state.sessions.session; }],
    ['orphan Session driver', (state) => { state.sessionDrivers.orphan = 'pi'; }],
    ['empty Session driver', (state) => { state.sessionDrivers.session = ''; }],
    ['foreign Event Host', (state) => { state.recentEvents[0].hostId = 'foreign'; }],
    ['orphan Event Session', (state) => { state.recentEvents[0].sessionId = 'orphan'; }],
    ['duplicate Event ID', (state) => { state.recentEvents.push(structuredClone(state.recentEvents[0])); }],
    ['non-terminal NeedHuman error', (state) => {
      state.recentEvents[0] = {
        ...state.recentEvents[0], type: 'need_human', status: 'need_human',
        needHuman: { reason: 'error', error: {
          kind: 'provider_failure', message: 'Provider failed.', retryExhausted: false,
        } },
      };
    }],
    ['invalid historical revision', (state) => { state.sessionRevisions.orphan = 0; }],
    ['handle map mismatch', (state) => { state.pendingHandles.wrong = state.pendingHandles[`${HOST_ID}:session`]; delete state.pendingHandles[`${HOST_ID}:session`]; }],
    ['foreign handle Host', (state) => { state.pendingHandles[`${HOST_ID}:session`].hostId = 'foreign'; }],
    ['orphan handle Event', (state) => { state.pendingHandles[`${HOST_ID}:session`].handledThroughEventId = 'orphan'; }],
    ['command result key mismatch', (state) => { state.commandResults.other = state.commandResults.command; delete state.commandResults.command; }],
    ['foreign command result Host', (state) => { state.commandResults.command.hostId = 'foreign'; }],
    ['seen command mismatch', (state) => { state.seenCommands.command = 'different'; }],
    ['orphan seen command', (state) => { state.seenCommands.orphan = CREATED_AT; }],
    ['reservation fingerprint key mismatch', (state) => { state.producerEventReservations = { wrong: { version: 1, eventId: 'event', sessionId: 'session', fingerprint: 'fingerprint', createdAt: CREATED_AT } }; }],
    ['orphan reservation Session', (state) => { state.producerEventReservations = { ['orphan\nfingerprint']: { version: 1, eventId: 'event', sessionId: 'orphan', fingerprint: 'fingerprint', createdAt: CREATED_AT } }; }],
    ['cancellation map key mismatch', (state) => { state.terminalCancellations = { wrong: { version: 1, eventId: 'event', sessionId: 'session', fingerprint: 'fingerprint', removeSession: false, createdAt: CREATED_AT } }; }],
    ['orphan retained cancellation Session', (state) => { state.terminalCancellations = { event: { version: 1, eventId: 'event', sessionId: 'orphan', fingerprint: 'fingerprint', removeSession: false, createdAt: CREATED_AT } }; }],
    ['publication fields without accepted revision', (state) => { state.currentSessionsSnapshot.lastAcceptedDigest = 'digest'; }],
    ['accepted publication missing recipient relationship', (state) => { state.currentSessionsSnapshot = { version: 1, lastAllocatedRevision: 1, lastAcceptedRevision: 1, lastAcceptedDigest: 'd', lastAcceptedContentDigest: 'c', lastAcceptedRecipientSetVersion: 2 }; state.recipientSetVersion = 1; }],
  ];
  for (const [name, mutate] of mutations) {
    const dir = mkdtempSync(join(tmpdir(), 'ariava-current-matrix-'));
    const statePath = join(dir, 'state.json'); const identityPath = join(dir, 'identity.json');
    try {
      const store = initialize({ dir, statePath, identityPath });
      const terminal = { sessionId: 'session', hostId: HOST_ID, provider: 'pi', projectName: 'project', nameText: 'name',
        status: 'idle', updatedAt: CREATED_AT, lastEventId: 'event' };
      const event = { eventId: 'event', hostId: HOST_ID, sessionId: 'session', provider: 'pi', type: 'done', status: 'idle',
        agentText: 'done', createdAt: CREATED_AT };
      store.queuePendingEvent(event, terminal);
      store.queuePendingSessionHandle({ hostId: HOST_ID, sessionId: 'session', handledThroughEventId: 'event',
        handledAt: CREATED_AT, action: 'pi_input', updatedAt: CREATED_AT });
      const commandResult = { commandId: 'command', hostId: HOST_ID, sessionId: 'session', accepted: true,
        status: 'executed', message: 'done', updatedAt: CREATED_AT };
      store.rememberCommandResult(commandResult, commandResult);
      const state = JSON.parse(readFileSync(statePath, 'utf8')); mutate(state);
      const stateBytes = Buffer.from(`${JSON.stringify(state)}\n`); writeFileSync(statePath, stateBytes, { mode: 0o600 });
      const spoolBytes = readFileSync(spoolPathForState(statePath)); let keyAccessed = false;
      store.dispose();
      assert.throws(() => openDeferred(statePath).initializeEncryptedSpool(HOST_ID, identityPath, 'linux', {
        loadOrCreate: () => { keyAccessed = true; return new Uint8Array(32).fill(7); },
      }), /preflight failed closed/i, name);
      assert.equal(keyAccessed, false, name); assert.deepEqual(readFileSync(statePath), stateBytes, name);
      assert.deepEqual(readFileSync(spoolPathForState(statePath)), spoolBytes, name);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }
});

test('recognized reset repopulates only live v2 Agent Adapter Sessions through publication reconciliation', async () => {
  const fixture = setupOldRuntime();
  try {
    const daemon = new BridgeDaemon({
      hostId: HOST_ID, hostName: 'Test', hostPlatform: 'linux', relayBaseUrl: 'http://relay.invalid',
      statePath: fixture.statePath, identityPath: fixture.identityPath, configPath: fixture.preserved.configPath,
      runtimePlatform: 'linux', pollIntervalMs: 60_000, bridgeVersion: 'test',
      agentAdapter: { port: 0, secret: 'test', configPath: fixture.preserved.secretPath },
    }, []);
    const state = daemon.stateStore;
    state.initializeEncryptedSpool(HOST_ID, fixture.identityPath, 'linux');
    const registry = daemon.adapterRegistry;
    registry.register({ sessionId: 'live-1', provider: 'pi', projectName: 'live-project', cwd: '/live', nameText: 'Live one' });
    registry.register({ sessionId: 'live-2', provider: 'pi', projectName: 'live-project', cwd: '/live', nameText: 'Live two' });
    const live = registry.listSessions(); state.replaceDriverSessions('pi', live);
    const published = [];
    const orchestrator = new EncryptedUploadOrchestrator(state, {
      publishEncryptedSession: async (session) => { published.push(session); },
      reconcileEncryptedSession: async () => false,
      recipientSnapshot: async () => ({ version: 1, hostId: HOST_ID, recipientSetVersion: 1, recipients: [] }),
    }, generateHostEncryptionIdentity(HOST_ID), { reconcileRecipients: () => [] });
    assert.equal(await orchestrator.publishRecipientChangeSnapshots(
      { version: 1, hostId: HOST_ID, recipientSetVersion: 1, recipients: [] }, [],
    ), true);
    assert.deepEqual(published.map((item) => item.sessionId).sort(), ['live-1', 'live-2']);
    assert.ok(published.every((item) => item.hostId === HOST_ID && item.provider === 'pi'));
    assert.deepEqual(state.listSessions().map((item) => item.sessionId).sort(), ['live-1', 'live-2']);
    assert.deepEqual(state.peekPendingEvents(), []); assert.equal(state.getCommandResult('command'), undefined);
    assert.doesNotMatch(readFileSync(fixture.statePath, 'utf8'), /legacy protected event|pending-digest|"command":/);
    registry.dispose();
  } finally { rmSync(fixture.dir, { recursive: true, force: true }); }
});

const secureWriteCrashChild = String.raw`
  import { BridgeStateStore } from './apps/bridge/dist/state-store.js';
  const [statePath, identityPath, member, boundary] = process.argv.slice(1);
  const store = new BridgeStateStore(statePath, undefined, { deferRuntimePreflight: true });
  const suffix = member === 'intent' ? '.runtime-reset.json' : member === 'spool' ? '.spool.json' : 'state.json';
  const crash = (path) => { if (path.endsWith(suffix)) process.kill(process.pid, 'SIGKILL'); };
  store.initializeEncryptedSpool('host-test', identityPath, 'linux', undefined, undefined, { write: { [boundary]: crash } });
`;

for (const member of ['intent', 'spool', 'state']) {
  for (const boundary of ['afterTemporaryWrite', 'afterFileSync', 'afterPromotion', 'afterDirectorySync']) {
    test(`subprocess crash at ${member} ${boundary} restarts without mixed replay`, () => {
      const fixture = setupOldRuntime();
      try {
        const result = spawnSync(process.execPath, ['--input-type=module', '--eval', secureWriteCrashChild,
          fixture.statePath, fixture.identityPath, member, boundary], { cwd: process.cwd(), encoding: 'utf8' });
        assert.equal(result.signal, 'SIGKILL', result.stderr);
        const recovered = initialize(fixture);
        assertReset(fixture, recovered);
        assert.doesNotMatch(readFileSync(fixture.statePath, 'utf8'), /legacy protected event|pending-digest/);
        assert.doesNotMatch(readFileSync(fixture.spoolPath, 'utf8'), /event-source-v1|event-upload-v1/);
      } finally { rmSync(fixture.dir, { recursive: true, force: true }); }
    });
  }
}

const secureCleanupCrashChild = String.raw`
  import { BridgeStateStore } from './apps/bridge/dist/state-store.js';
  const [statePath, identityPath, boundary] = process.argv.slice(1);
  const store = new BridgeStateStore(statePath, undefined, { deferRuntimePreflight: true });
  store.initializeEncryptedSpool('host-test', identityPath, 'linux', undefined, undefined, {
    remove: { [boundary]: () => process.kill(process.pid, 'SIGKILL') },
  });
`;

for (const boundary of ['afterUnlink', 'afterDirectorySync']) {
  test(`subprocess crash at reset intent cleanup ${boundary} restarts without mixed replay`, () => {
    const fixture = setupOldRuntime();
    try {
      const result = spawnSync(process.execPath, ['--input-type=module', '--eval', secureCleanupCrashChild,
        fixture.statePath, fixture.identityPath, boundary], { cwd: process.cwd(), encoding: 'utf8' });
      assert.equal(result.signal, 'SIGKILL', result.stderr);
      const recovered = initialize(fixture);
      assertReset(fixture, recovered);
      assert.doesNotMatch(readFileSync(fixture.statePath, 'utf8'), /legacy protected event|pending-digest/);
      assert.doesNotMatch(readFileSync(fixture.spoolPath, 'utf8'), /event-source-v1|event-upload-v1/);
    } finally { rmSync(fixture.dir, { recursive: true, force: true }); }
  });
}
