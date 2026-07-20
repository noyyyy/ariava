import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
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
    latestActivityText: `activity-${id}`, stateLabel: 'Blocked', status: 'blocked', updatedAt: '2026-07-20T00:00:00.000Z' };
}
function event(hostId, id = 'event-1', sessionId = 'session-1') {
  return { eventId: id, hostId, sessionId, provider: 'pi', type: 'blocked', status: 'blocked', typeLabel: 'Blocked',
    assistantText: `SECRET-${id}`, createdAt: '2026-07-20T00:00:01.000Z' };
}
function responseError(reason) { return new Response(JSON.stringify({ reason }), { status: 409, headers: { 'content-type': 'application/json' } }); }
async function unwrap(response) {
  if (!response.ok) throw new RelayClientError(response.status, await response.text());
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
  const state = new BridgeStateStore(config.statePath); state.replaceDriverSessions('test', sessions);
  state.initializeEncryptedSpool(config.hostId, config.identityPath, 'linux');
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
  f.state.queuePendingEvent(value);
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
    const state = new BridgeStateStore(f.config.statePath); state.replaceDriverSessions('test', [
      { ...s1, hostId: f.config.hostId }, { ...s2, hostId: f.config.hostId },
    ]); state.initializeEncryptedSpool(f.config.hostId, f.config.identityPath, 'linux');
    const ok = await f.orchestrator(state).publishRecipientChangeSnapshots(f.snapshots(1), f.recipients);
    assert.equal(ok, true);
    assert.deepEqual([...attempts.keys()].sort(), ['s1', 's2']);
    assert.equal(attempts.get('s1'), 3); assert.equal(attempts.get('s2'), 3);
    const restarted = new BridgeStateStore(f.config.statePath); restarted.initializeEncryptedSpool(f.config.hostId, f.config.identityPath, 'linux');
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
    const state = new BridgeStateStore(f.config.statePath);
    state.replaceDriverSessions('test', [session(f.config.hostId, 'ambiguous-session')]);
    state.initializeEncryptedSpool(f.config.hostId, f.config.identityPath, 'linux');
    const ok = await f.orchestrator(state).publishRecipientChangeSnapshots(f.snapshots(1), f.recipients);
    assert.equal(ok, true); assert.equal(reconcileCalls, 1);
    assert.deepEqual(attempts, [{ version: 1, revision: 1 }, { version: 2, revision: 2 }]);
    assert.equal(state.currentSessionRevision('ambiguous-session'), 2);
    assert.equal(state.getRecipientSetVersion(), 2);
    assert.equal(state.getInflightSessionUpload('ambiguous-session'), undefined);
  } finally { f.restore(); }
});
