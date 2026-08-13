import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { E2E_SUITE_V1, base64UrlEncode } from '../../../packages/protocol/dist/index.js';
import { BridgeDaemon } from '../dist/daemon.js';
import { EncryptedUploadOrchestrator } from '../dist/e2e/upload-orchestrator.js';
import { generateHostEncryptionIdentity } from '../dist/identity/host-encryption-key.js';
import { RelayClientError } from '../dist/relay-client.js';
import { LocalLinkKeyring } from '../dist/e2e/link-keyring.js';
import { BridgeStateStore } from '../dist/state-store.js';

const dirs = [];
test.afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

function session(hostId, id) {
  return { sessionId: id, hostId, provider: 'pi', projectName: `project-${id}`, nameText: `name-${id}`,
    latestActivityText: `activity-${id}`, status: 'idle', updatedAt: '2026-07-20T00:00:00.000Z' };
}
function event(hostId, id = 'event-1', sessionId = 'session-1') {
  return { eventId: id, hostId, sessionId, provider: 'pi', type: 'done', status: 'idle',
    agentText: `SECRET-${id}`, projectName: `project-${sessionId}`, contextText: `name-${sessionId} · project-${sessionId}`,
    hbaseSessionKey: sessionId, harnessProvider: 'pi', createdAt: '2026-07-20T00:00:01.000Z' };
}
function responseError(reason) { return new Response(JSON.stringify({ reason }), { status: 409, headers: { 'content-type': 'application/json' } }); }
async function unwrap(response) {
  if (!response.ok) {
    const text = await response.text();
    let body;
    try { body = JSON.parse(text); } catch { body = undefined; }
    throw new RelayClientError(response.status, body?.reason ?? body?.error ?? text, body);
  }
  return response.status === 204 ? undefined : response.json();
}

async function fixture(handler, sessions = []) {
  const root = mkdtempSync(join(tmpdir(), 'ariava-daemon-e2e-')); dirs.push(root); chmodSync(root, 0o700);
  const identityPath = join(root, 'identity.json'); const hostId = `host_${'H'.repeat(43)}`;
  const runtimeEncryptionIdentity = generateHostEncryptionIdentity(hostId);
  const watchId = `watch_${'W'.repeat(43)}`; const watch = generateHostEncryptionIdentity(watchId);
  const binding = { version: 1, entityType: 'watch', entityId: watchId, identityKeyId: `key_${'A'.repeat(43)}`,
    encryptionKeyId: watch.encryptionKeyId, suite: E2E_SUITE_V1, publicKey: watch.publicKey, sequence: 1,
    createdAt: '2026-07-20T00:00:00.000Z', bindingSignature: base64UrlEncode(new Uint8Array(64)) };
  const linkId = 'link-1'; const keyring = new LocalLinkKeyring(`${identityPath}.e2e-keyring.json`, runtimeEncryptionIdentity);
  keyring.persistActive({ version: 1, status: 'active', linkId, hostId, watchDeviceId: watchId,
    linkGeneration: 1, epoch: 1, transcriptDigest: base64UrlEncode(new Uint8Array(32)), watchBinding: binding,
    watchBindingDigest: base64UrlEncode(new Uint8Array(32)), peerProofDigest: base64UrlEncode(new Uint8Array(32)), activatedAt: '2026-07-20T00:00:00.000Z' });
  const snapshots = (version) => ({ version: 1, hostId, recipientSetVersion: version, recipients: [{
    linkId, linkGeneration: 1, watchDeviceId: watchId, epoch: 1, state: 'active', watchBinding: binding }] });
  const config = { hostId, relayBaseUrl: 'http://relay.invalid', statePath: join(root, 'state.json'), identityPath };
  const state = new BridgeStateStore(config.statePath);
  state.initializeEncryptedSpool(config.hostId, config.identityPath, 'linux');
  state.replaceDriverSessions('test', sessions);
  state.setRecipientSetVersion(1);
  const calls = [];
  const invoke = async (path, body) => {
    calls.push({ path, body });
    return unwrap(await handler({ path, body, calls, snapshots }));
  };
  const client = {
    recipientSnapshot: () => invoke('/v2/bridge/e2e/recipients', undefined),
    publishEncryptedEvent: (event, session) => invoke('/v2/bridge/e2e/events', { event, session }),
    reconcileEncryptedEvent: (event, session) => invoke('/v2/bridge/e2e/events/reconcile', { event, session }),
    publishEncryptedSession: (session) => invoke('/v2/bridge/e2e/sessions', { session }),
    reconcileEncryptedSession: (session) => invoke('/v2/bridge/e2e/sessions/reconcile', { session }).then((value) => value.committed),
  };
  const recipients = keyring.reconcileRecipients(snapshots(1));
  const orchestrator = (stateStore = state, hooks) => new EncryptedUploadOrchestrator(stateStore, client, runtimeEncryptionIdentity, keyring, hooks);
  return { root, config, state, calls, snapshots, recipients, client, keyring, runtimeEncryptionIdentity, orchestrator, restore: () => {} };
}

async function seedEvent(f, value) {
  const terminal = {
    sessionId: value.sessionId, hostId: value.hostId, provider: value.provider, projectName: value.projectName,
    nameText: `name-${value.sessionId}`, latestActivityText: value.agentText, status: 'idle',
    updatedAt: value.createdAt, lastEventId: value.eventId, hbaseSessionKey: value.hbaseSessionKey,
    harnessProvider: value.harnessProvider,
  };
  f.state.queuePendingEvent(value, terminal);
}

function tamperSpoolCiphertexts(spoolPath, predicate) {
  const file = JSON.parse(readFileSync(spoolPath, 'utf8'));
  let tampered = 0;
  for (const item of file.items) {
    if (!predicate(item)) continue;
    const bytes = Buffer.from(item.ciphertext, 'base64url');
    bytes[0] ^= 1;
    item.ciphertext = bytes.toString('base64url');
    tampered += 1;
  }
  assert.ok(tampered > 0);
  writeFileSync(spoolPath, `${JSON.stringify(file)}\n`, { mode: 0o600 });
  return tampered;
}

function terminalSessionFor(sourceEvent) {
  return {
    sessionId: sourceEvent.sessionId, hostId: sourceEvent.hostId, provider: 'pi', projectName: sourceEvent.projectName,
    nameText: `name-${sourceEvent.sessionId}`, latestActivityText: sourceEvent.agentText, status: 'idle',
    updatedAt: sourceEvent.createdAt, lastEventId: sourceEvent.eventId, hbaseSessionKey: sourceEvent.hbaseSessionKey,
    harnessProvider: sourceEvent.harnessProvider,
  };
}

function createDurableCancellation(label) {
  const root = mkdtempSync(join(tmpdir(), `ariava-cancel-${label}-`));
  dirs.push(root);
  chmodSync(root, 0o700);
  const statePath = join(root, 'state.json');
  const identityPath = join(root, 'identity.json');
  const spoolPath = `${statePath}.spool.json`;
  const hostId = `host_${'H'.repeat(43)}`;
  const keyStore = { loadOrCreate: () => new Uint8Array(32).fill(7) };
  const store = new BridgeStateStore(statePath);
  store.initializeEncryptedSpool(hostId, identityPath, 'linux', keyStore);
  const sourceEvent = event(hostId, `event-${label}`, `session-${label}`);
  const terminal = terminalSessionFor(sourceEvent);
  store.reserveProducerEventTuple(sourceEvent, terminal, 'fingerprint');
  store.reserveProducerEvent({
    version: 1, eventId: sourceEvent.eventId, sessionId: sourceEvent.sessionId,
    fingerprint: 'fingerprint', createdAt: sourceEvent.createdAt,
  });
  const removeMany = store.spool.removeMany.bind(store.spool);
  store.spool.removeMany = () => { throw new Error('cleanup unavailable'); };
  try {
    store.cancelTerminalEvent({ eventId: sourceEvent.eventId, sessionId: sourceEvent.sessionId,
      fingerprint: 'fingerprint', removeSession: true });
  } finally {
    store.spool.removeMany = removeMany;
  }
  return { statePath, identityPath, spoolPath, hostId, keyStore, store, sourceEvent, terminal };
}

test('BridgeDaemon delegates encrypted uploads to the production orchestrator', async () => {
  const f = await fixture(({ path, snapshots }) => {
    if (path === '/v2/bridge/e2e/recipients') return Response.json(snapshots(1));
    if (path === '/v2/bridge/e2e/sessions' || path === '/v2/bridge/e2e/events') return Response.json({ ok: true });
    throw new Error(path);
  });
  try {
    const daemon = Object.create(BridgeDaemon.prototype);
    daemon.stateStore = f.state; daemon.relayClient = f.client; daemon.encryptionIdentity = f.runtimeEncryptionIdentity; daemon.keyring = f.keyring; daemon.startupValidated = true;
    f.state.replaceDriverSessions('test', [session(f.config.hostId, 'delegate-session')]);
    await seedEvent(f, event(f.config.hostId, 'delegate-event', 'delegate-session'));
    assert.equal(await daemon.flushEncryptedUploadsForTest(), 1);
    assert.ok(f.calls.some((call) => call.path === '/v2/bridge/e2e/events'));
  } finally { f.restore(); }
});

test('BridgeDaemon persists one envelope and reuses byte-identical bytes after an ambiguous response', async () => {
  let uploaded; let attempts = 0; const f = await fixture(({ path, body, snapshots }) => {
    if (path === '/v2/bridge/e2e/recipients') return Response.json(snapshots(1));
    if (path === '/v2/bridge/e2e/events') { attempts += 1; if (!uploaded) uploaded = body; else assert.deepEqual(body, uploaded);
      return attempts === 1 ? new Response('ambiguous', { status: 500 }) : Response.json({ ok: true }); }
    throw new Error(path);
  });
  try {
    await seedEvent(f, event(f.config.hostId)); const uploader = f.orchestrator();
    assert.equal(await uploader.flushPendingEvents(), 0);
    assert.equal(await uploader.flushPendingEvents(), 1);
    assert.equal(attempts, 2);
  } finally { f.restore(); }
});

test('BridgeDaemon reconciles an ambiguous committed event response before replacing its envelope', async () => {
  let uploaded; let attempts = 0; const f = await fixture(({ path, body, snapshots }) => {
    if (path === '/v2/bridge/e2e/recipients') return Response.json(snapshots(1));
    if (path === '/v2/bridge/e2e/events') { attempts += 1; uploaded ??= body;
      return attempts === 1 ? responseError('encrypted_upload_conflict') : Response.json({ ok: true }); }
    if (path === '/v2/bridge/e2e/events/reconcile') { assert.deepEqual(body, uploaded); return Response.json({ committed: true }); }
    throw new Error(path);
  });
  try {
    await seedEvent(f, event(f.config.hostId));
    assert.equal(await f.orchestrator().flushPendingEvents(), 1); assert.equal(attempts, 1);
  } finally { f.restore(); }
});

for (const phase of ['journaled', 'revision-committed', 'inflight-removed', 'source-removed']) {
  test(`event completion restart converges after ${phase}`, async () => {
    let published;
    const f = await fixture(({ path, body, snapshots }) => {
      if (path === '/v2/bridge/e2e/recipients') return Response.json(snapshots(1));
      if (path === '/v2/bridge/e2e/events') { published ??= body; assert.deepEqual(body, published); return Response.json({ ok: true }); }
      throw new Error(path);
    });
    try {
      await seedEvent(f, event(f.config.hostId)); let crashed = false;
      const uploader = f.orchestrator(undefined, { eventCompletionStep: (at) => { if (!crashed && at === phase) { crashed = true; throw new Error(`crash:${at}`); } } });
      await assert.rejects(uploader.flushPendingEvents(), new RegExp(`crash:${phase}`));
      f.state.dispose();
      const restartedState = new BridgeStateStore(f.config.statePath);
      restartedState.initializeEncryptedSpool(f.config.hostId, f.config.identityPath, 'linux');
      assert.equal(restartedState.currentSessionRevision('session-1'), 1);
      assert.equal(restartedState.peekPendingUploads().length, 0);
      assert.equal(restartedState.getInflightEventUpload('event-1'), undefined);
      const persisted = JSON.parse(readFileSync(f.config.statePath, 'utf8'));
      assert.equal(persisted.eventUploadCompletions, undefined);
    } finally { f.restore(); }
  });
}

for (const { name, removedItemId } of [
  { name: 'inflight-remove-before-flag', removedItemId: 'inflight:event:event-1' },
  { name: 'source-remove-before-flag', removedItemId: 'event-1' },
]) {
  test(`event completion restart repairs ${name}`, async () => {
    const f = await fixture(({ path, snapshots }) => {
      if (path === '/v2/bridge/e2e/recipients') return Response.json(snapshots(1));
      if (path === '/v2/bridge/e2e/events') return Response.json({ ok: true });
      throw new Error(path);
    });
    try {
      await seedEvent(f, event(f.config.hostId));
      f.state.replaceDriverSessions('pi', []);
      const uploader = f.orchestrator();
      const originalWriteState = f.state.writeState;
      let failNextStateWrite = false;
      f.state.writeState = (path, value) => {
        if (failNextStateWrite) { failNextStateWrite = false; throw new Error(`crash:${name}`); }
        originalWriteState(path, value);
      };
      const spool = f.state.spool;
      const originalRemove = spool.remove.bind(spool);
      spool.remove = (itemId) => {
        originalRemove(itemId);
        if (itemId === removedItemId) failNextStateWrite = true;
      };
      await assert.rejects(uploader.flushPendingEvents(), new RegExp(`crash:${name}`));
      f.state.dispose();
      const restarted = new BridgeStateStore(f.config.statePath);
      restarted.initializeEncryptedSpool(f.config.hostId, f.config.identityPath, 'linux');
      assert.equal(restarted.currentSessionRevision('session-1'), 1);
      assert.equal(restarted.peekPendingUploads().length, 0);
      assert.equal(restarted.getInflightEventUpload('event-1'), undefined);
      assert.equal(JSON.parse(readFileSync(f.config.statePath, 'utf8')).eventUploadCompletions, undefined);
      restarted.dispose();
    } finally { f.restore(); }
  });
}

for (const { name, unreadableItemIds, inflightRemains } of [
  { name: 'source', unreadableItemIds: ['event-1'], inflightRemains: true },
  { name: 'source-and-inflight', unreadableItemIds: ['event-1', 'inflight:event:event-1'], inflightRemains: false },
]) {
  test(`event completion restart survives a second crash after unreadable ${name} recovery`, async () => {
    const f = await fixture(({ path, snapshots }) => {
      if (path === '/v2/bridge/e2e/recipients') return Response.json(snapshots(1));
      if (path === '/v2/bridge/e2e/events') return Response.json({ ok: true });
      throw new Error(path);
    });
    try {
      await seedEvent(f, event(f.config.hostId));
      await assert.rejects(f.orchestrator(undefined, {
        eventCompletionStep: (phase) => { if (phase === 'journaled') throw new Error('crash:journaled'); },
      }).flushPendingEvents(), /crash:journaled/);
      f.state.dispose();
      const spoolPath = `${f.config.statePath}.spool.json`;
      assert.equal(tamperSpoolCiphertexts(spoolPath, (item) => unreadableItemIds.includes(item.spoolItemId)),
        unreadableItemIds.length);

      const interrupted = new BridgeStateStore(f.config.statePath);
      assert.throws(() => interrupted.initializeEncryptedSpool(
        f.config.hostId, f.config.identityPath, 'linux', undefined, undefined, {
          recoveryStep: () => { throw new Error('crash:after-unreadable-recovery'); },
        },
      ), /crash:after-unreadable-recovery/);
      interrupted.dispose();
      const afterRecovery = JSON.parse(readFileSync(spoolPath, 'utf8'));
      assert.equal(afterRecovery.items.some((item) => item.spoolItemId === 'event-1'), false);
      assert.equal(afterRecovery.items.some((item) => item.spoolItemId === 'inflight:event:event-1'), inflightRemains);

      const restarted = new BridgeStateStore(f.config.statePath);
      assert.deepEqual(restarted.initializeEncryptedSpool(f.config.hostId, f.config.identityPath, 'linux'),
        { droppedUnreadableItems: 0 });
      assert.equal(restarted.currentSessionRevision('session-1'), 1);
      assert.equal(restarted.peekPendingUploads().length, 0);
      assert.equal(restarted.getInflightEventUpload('event-1'), undefined);
      assert.equal(JSON.parse(readFileSync(f.config.statePath, 'utf8')).eventUploadCompletions, undefined);
      restarted.dispose();
    } finally { f.restore(); }
  });
}

test('restart finishes durable cancellation after dropping an unreadable cancellation journal', () => {
  const { statePath, identityPath, spoolPath, hostId, keyStore, store, sourceEvent } =
    createDurableCancellation('cancel');
  store.dispose();
  assert.equal(tamperSpoolCiphertexts(spoolPath, (item) => item.payloadKind === 'terminal-cancellation-v2'), 1);

  const restarted = new BridgeStateStore(statePath);
  assert.deepEqual(restarted.initializeEncryptedSpool(hostId, identityPath, 'linux', keyStore),
    { droppedUnreadableItems: 1 });
  assert.equal(restarted.getSession(sourceEvent.sessionId), undefined);
  assert.deepEqual(restarted.peekPendingEvents(), []);
  assert.equal(restarted.getTerminalEventCancellation(sourceEvent.sessionId), undefined);
  assert.doesNotMatch(JSON.stringify(JSON.parse(readFileSync(statePath, 'utf8'))), /event-cancel/);
  restarted.dispose();
});

for (const { name, unreadableKinds, reservationRemains, journalRemains } of [
  { name: 'source', unreadableKinds: ['event-reservation-v2'], reservationRemains: false, journalRemains: true },
  { name: 'journal', unreadableKinds: ['terminal-cancellation-v2'], reservationRemains: true, journalRemains: false },
  { name: 'source-and-journal', unreadableKinds: ['event-reservation-v2', 'terminal-cancellation-v2'],
    reservationRemains: false, journalRemains: false },
]) {
  test(`durable cancellation restart survives a second crash after unreadable ${name} recovery`, () => {
    const { statePath, identityPath, spoolPath, hostId, keyStore, store, sourceEvent } =
      createDurableCancellation(name);
    store.dispose();
    assert.equal(tamperSpoolCiphertexts(spoolPath, (item) => unreadableKinds.includes(item.payloadKind)),
      unreadableKinds.length);

    const interrupted = new BridgeStateStore(statePath);
    assert.throws(() => interrupted.initializeEncryptedSpool(hostId, identityPath, 'linux', keyStore, undefined, {
      recoveryStep: () => { throw new Error('crash:after-unreadable-recovery'); },
    }), /crash:after-unreadable-recovery/);
    interrupted.dispose();
    const afterRecovery = JSON.parse(readFileSync(spoolPath, 'utf8'));
    assert.equal(afterRecovery.items.some((item) => item.payloadKind === 'event-reservation-v2'), reservationRemains);
    assert.equal(afterRecovery.items.some((item) => item.payloadKind === 'terminal-cancellation-v2'), journalRemains);

    const restarted = new BridgeStateStore(statePath);
    assert.deepEqual(restarted.initializeEncryptedSpool(hostId, identityPath, 'linux', keyStore),
      { droppedUnreadableItems: 0 });
    assert.equal(restarted.getSession(sourceEvent.sessionId), undefined);
    assert.deepEqual(restarted.peekPendingEvents(), []);
    assert.equal(restarted.getTerminalEventCancellation(sourceEvent.sessionId), undefined);
    assert.doesNotMatch(JSON.stringify(JSON.parse(readFileSync(statePath, 'utf8'))), new RegExp(sourceEvent.eventId));
    restarted.dispose();
  });
}

test('durable cancellation rejects a readable source with a mismatched fingerprint before mutation', () => {
  const { statePath, identityPath, spoolPath, hostId, keyStore, store, sourceEvent, terminal } =
    createDurableCancellation('source-conflict');
  store.spool.replace([sourceEvent.eventId], [{
    spoolItemId: sourceEvent.eventId, sessionId: sourceEvent.sessionId, eventId: sourceEvent.eventId,
    payloadKind: 'event-reservation-v2', createdAt: sourceEvent.createdAt,
    plaintext: new TextEncoder().encode(JSON.stringify({
      event: sourceEvent, session: terminal, producerFingerprint: 'wrong',
    })),
  }]);
  store.dispose();
  const stateBytes = readFileSync(statePath);
  const spoolBytes = readFileSync(spoolPath);

  const restarted = new BridgeStateStore(statePath);
  assert.throws(() => restarted.initializeEncryptedSpool(hostId, identityPath, 'linux', keyStore),
    /producer fingerprint is invalid|source conflicts with state/);
  restarted.dispose();
  assert.deepEqual(readFileSync(statePath), stateBytes);
  assert.deepEqual(readFileSync(spoolPath), spoolBytes);
});

test('all-session recipient refresh replaces stale inflight on two consecutive recipient versions', async () => {
  const s1 = session('placeholder', 's1'); const s2 = session('placeholder', 's2'); let version = 1; const attempts = new Map();
  const f = await fixture(({ path, body, snapshots }) => {
    if (path === '/v2/bridge/e2e/recipients') return Response.json(snapshots(version));
    if (path === '/v2/bridge/e2e/sessions/reconcile') return Response.json({ committed: false });
    if (path === '/v2/bridge/e2e/sessions') {
      const key = body.session.sessionId; const count = (attempts.get(key) ?? 0) + 1; attempts.set(key, count);
      if (count === 1) { version = 2; return responseError('e2e_recipient_set_changed'); }
      if (count === 2) { version = 3; return responseError('e2e_recipient_set_changed'); }
      assert.equal(body.session.recipientSetVersion, 3); return Response.json({ ok: true });
    }
    throw new Error(path);
  }, []);
  try {
    const state = f.state;
    state.initializeEncryptedSpool(f.config.hostId, f.config.identityPath, 'linux');
    state.replaceDriverSessions('test', [
      { ...s1, hostId: f.config.hostId }, { ...s2, hostId: f.config.hostId },
    ]);
    const ok = await f.orchestrator(state).publishRecipientChangeSnapshots(f.snapshots(1), f.recipients);
    assert.equal(ok, true);
    assert.deepEqual([...attempts.keys()].sort(), ['s1', 's2']);
    assert.equal(attempts.get('s1'), 3); assert.equal(attempts.get('s2'), 3);
    state.dispose();
    const restarted = new BridgeStateStore(f.config.statePath);
    restarted.initializeEncryptedSpool(f.config.hostId, f.config.identityPath, 'linux');
    assert.equal(restarted.currentSessionRevision('s1'), 1); assert.equal(restarted.currentSessionRevision('s2'), 1);
    assert.deepEqual(restarted.listInflightSessionIds(), []);
  } finally { f.restore(); }
});

test('recipient refresh publishes current+1 when the ambiguous old-version upload reconciles committed', async () => {
  let version = 1; let reconcileCalls = 0; const attempts = [];
  const f = await fixture(({ path, body, snapshots }) => {
    if (path === '/v2/bridge/e2e/recipients') return Response.json(snapshots(version));
    if (path === '/v2/bridge/e2e/sessions/reconcile') { reconcileCalls += 1; return Response.json({ committed: true }); }
    if (path === '/v2/bridge/e2e/sessions') {
      attempts.push({ version: body.session.recipientSetVersion, revision: body.session.revision });
      if (attempts.length === 1) { version = 2; return responseError('e2e_recipient_set_changed'); }
      assert.equal(body.session.recipientSetVersion, 2); assert.equal(body.session.revision, 2);
      return Response.json({ ok: true });
    }
    throw new Error(path);
  });
  try {
    const state = f.state;
    state.initializeEncryptedSpool(f.config.hostId, f.config.identityPath, 'linux');
    state.replaceDriverSessions('test', [session(f.config.hostId, 'ambiguous-session')]);
    const ok = await f.orchestrator(state).publishRecipientChangeSnapshots(f.snapshots(1), f.recipients);
    assert.equal(ok, true); assert.equal(reconcileCalls, 1);
    assert.deepEqual(attempts, [{ version: 1, revision: 1 }, { version: 2, revision: 2 }]);
    assert.equal(state.currentSessionRevision('ambiguous-session'), 2);
    assert.equal(state.getRecipientSetVersion(), 2);
    assert.equal(state.getInflightSessionUpload('ambiguous-session'), undefined);
  } finally { f.restore(); }
});
