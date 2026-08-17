import { afterEach, describe, expect, mock, test } from 'bun:test';
import { mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { CanonicalEvent, CanonicalSessionState, EncryptedSessionSnapshotUploadV3 } from '@ariava/protocol';

mock.module('../src/e2e/node-crypto', () => ({
  ChaChaPolyAuthenticationError: class ChaChaPolyAuthenticationError extends Error {},
  chachaPolySeal: (_key: Uint8Array, plaintext: Uint8Array) => ({ nonce: new Uint8Array(12).fill(1), ciphertext: new Uint8Array([...plaintext, ...new Uint8Array(16)]) }),
  chachaPolyOpen: (_key: Uint8Array, _nonce: Uint8Array, ciphertext: Uint8Array) => ciphertext.slice(0, -16),
  generateX25519KeyMaterial: () => ({ privateKeyPkcs8: new Uint8Array(48).fill(2), publicKeyRaw: new Uint8Array(32).fill(3) }),
  x25519SharedSecret: () => new Uint8Array(32).fill(4),
  hkdfSha256: () => new Uint8Array(32).fill(5),
}));

const { createEncryptedUploadActions, DEFAULT_ENCRYPTED_UPLOAD_CRYPTO } = await import('../src/e2e/upload-actions');
const { BridgeStateStore } = await import('../src/state-store');
const { eventSourceDigest, sessionSourceDigest } = await import('../src/e2e/upload-preflight');

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

/** Mirrors the removed compatibility facade's constructor shape; binds the single actions implementation. */
function createOrchestrator(
  stateStore: any,
  relayClient: any,
  keyring: any,
  hooks?: Parameters<typeof createEncryptedUploadActions>[0]['hooks'],
) {
  return createEncryptedUploadActions({ stateStore, relayClient, crypto: DEFAULT_ENCRYPTED_UPLOAD_CRYPTO, keyring, hooks });
}

function fixture() {
  const root = join(tmpdir(), `bridge-inflight-conv-${Date.now()}-${roots.length}`); roots.push(root); mkdirSync(root, { mode: 0o700 });
  const store = new BridgeStateStore(join(root, 'state.json'));
  store.initializeEncryptedSpool('host-test', join(root, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
  return store;
}

function terminalSession(overrides: Partial<CanonicalSessionState> = {}): CanonicalSessionState {
  return {
    sessionId: 'session-test', hostId: 'host-test', provider: 'pi', projectName: 'secret-project', nameText: 'Session',
    latestActivityText: 'terminal activity', workingDirectory: '/secret/project',
    harnessProvider: 'pi', status: 'idle', updatedAt: '2026-08-07T00:00:01.000Z',
    lastEventId: 'event-test', ...overrides,
  } as CanonicalSessionState;
}

function doneEvent(overrides: Partial<CanonicalEvent> = {}): CanonicalEvent {
  return {
    eventId: 'event-test', hostId: 'host-test', sessionId: 'session-test', provider: 'pi', type: 'done', status: 'idle',
    agentText: 'terminal activity', projectName: 'secret-project',
    workingDirectory: '/secret/project', harnessProvider: 'pi',
    createdAt: '2026-08-07T00:00:01.000Z', ...overrides,
  } as CanonicalEvent;
}

/** Realistic legacy raw Event+Session upload shape (E2EEventAndSessionUploadV3). */
const SUITE = 'x25519-hkdf-sha256-chachapoly-v1' as const;
function eventUpload(eventId: string): Record<string, unknown> {
  return {
    event: { eventId, hostId: 'host-test', sessionId: 'session-test', provider: 'pi', type: 'done', status: 'idle',
      createdAt: '2026-08-07T00:00:01.000Z', recipientSetVersion: 1,
      content: { version: 1, suite: SUITE, contentId: `event-${eventId}`, payloadKind: 'event-content-v3',
        nonce: 'A'.repeat(16), ciphertext: 'B'.repeat(24) },
      keyWraps: [] },
    session: { hostId: 'host-test', sessionId: 'session-test', provider: 'pi', status: 'idle',
      updatedAt: '2026-08-07T00:00:01.000Z', lastEventId: eventId, revision: 1, recipientSetVersion: 1,
      content: { version: 1, suite: SUITE, contentId: `session-${eventId}`, payloadKind: 'session-content-v3',
        nonce: 'C'.repeat(16), ciphertext: 'D'.repeat(24) },
      keyWraps: [] },
  };
}

function sessionUpload(): EncryptedSessionSnapshotUploadV3 {
  return { hostId: 'host-test', sessionId: 'session-test', provider: 'pi', status: 'idle',
    updatedAt: '2026-08-07T00:00:01.000Z', revision: 1, recipientSetVersion: 1,
    content: { version: 1, suite: SUITE, contentId: 'session-content', payloadKind: 'session-content-v3',
      nonce: 'E'.repeat(16), ciphertext: 'F'.repeat(24) },
    keyWraps: [] } as unknown as EncryptedSessionSnapshotUploadV3;
}

function rawInflightRecord(store: BridgeStateStore, itemId: string): Record<string, unknown> {
  const item = (store as any).spool.get(itemId);
  if (!item) return undefined as unknown as Record<string, unknown>;
  const raw = (store as any).spool.open(item);
  try { return JSON.parse(new TextDecoder('utf-8').decode(raw)); } finally { raw.fill(0); }
}

function makeClient(overrides: Record<string, unknown> = {}) {
  const reconcileEventCalls: Array<{ eventId: string; committed: boolean }> = [];
  const base = {
    recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }),
    publishEncryptedEvent: async () => ({}),
    publishEncryptedSession: async () => ({}),
    reconcileEncryptedEvent: async (eventUploadValue: { content: { contentId: string } }) => {
      const call = { eventId: eventUploadValue.content.contentId, committed: false };
      reconcileEventCalls.push(call);
      return { committed: call.committed };
    },
    reconcileEncryptedSession: async () => false,
  };
  return { ...base, ...overrides, reconcileEventCalls };
}

const emptyKeyring = { reconcileRecipients: () => [] } as any;

describe('§4.5.5 online legacy-inflight conversion', () => {
  test('uncommitted legacy Event inflight is wrapped in a V2 source-digest record without re-encryption', async () => {
    const store = fixture();
    const event = doneEvent(); const session = terminalSession();
    store.queuePendingEvent(event, session);
    store.persistInflightEventUpload(event.eventId, session.sessionId, eventUpload(event.eventId));
    const client = makeClient();
    const orchestrator = createOrchestrator(store, client as any, emptyKeyring);

    expect(await orchestrator.convertLegacyInflightToV2()).toBe(true);
    const record = rawInflightRecord(store, `inflight:event:${event.eventId}`);
    expect(record.version).toBe(2);
    expect(record.sourceDigest).toBe(eventSourceDigest(event, session));
    expect(record.upload).toEqual(eventUpload(event.eventId));
    expect(store.getInflightEventUpload(event.eventId)).toEqual(eventUpload(event.eventId));
    expect(client.reconcileEventCalls).toHaveLength(1);
    expect(client.reconcileEventCalls[0].eventId).toBe('event-event-test');
  });

  test('committed legacy Event inflight completes old evidence first and removes inflight and source', async () => {
    const store = fixture();
    const event = doneEvent(); const session = terminalSession();
    store.queuePendingEvent(event, session);
    store.persistInflightEventUpload(event.eventId, session.sessionId, eventUpload(event.eventId));
    const client = makeClient({
      reconcileEncryptedEvent: async () => ({ committed: true }),
    });
    const orchestrator = createOrchestrator(store, client as any, emptyKeyring);

    expect(await orchestrator.convertLegacyInflightToV2()).toBe(true);
    // Full completion consumes the journal and removes inflight + source; the
    // committed revision advances the Session cursor (§4.5.5 committed evidence
    // converges completion/revision first).
    expect(store.hasEventUploadCompletion(event.eventId)).toBe(false);
    expect((store as any).spool.get(`inflight:event:${event.eventId}`)).toBeUndefined();
    expect((store as any).spool.get(event.eventId)).toBeUndefined();
    expect(store.currentSessionRevision(session.sessionId)).toBe(1);
  });

  test('uncommitted legacy Session inflight is wrapped in a V2 source-digest record', async () => {
    const store = fixture();
    store.replaceDriverSessions('pi', [terminalSession()]);
    store.persistInflightSessionUpload('session-test', sessionUpload());
    const client = makeClient();
    const orchestrator = createOrchestrator(store, client as any, emptyKeyring);

    expect(await orchestrator.convertLegacyInflightToV2()).toBe(true);
    const record = rawInflightRecord(store, 'inflight:session:session-test');
    expect(record.version).toBe(2);
    expect(record.sourceDigest).toBe(sessionSourceDigest(terminalSession()));
    expect(record.upload).toEqual(sessionUpload());
  });

  test('committed legacy Session inflight commits the revision and removes the inflight', async () => {
    const store = fixture();
    store.replaceDriverSessions('pi', [terminalSession()]);
    store.persistInflightSessionUpload('session-test', sessionUpload());
    const client = makeClient({ reconcileEncryptedSession: async () => true });
    const orchestrator = createOrchestrator(store, client as any, emptyKeyring);

    expect(await orchestrator.convertLegacyInflightToV2()).toBe(true);
    expect(store.currentSessionRevision('session-test')).toBe(1);
    expect((store as any).spool.get('inflight:session:session-test')).toBeUndefined();
  });

  test('network-unknown legacy inflight stays byte-preserved and defers', async () => {
    const store = fixture();
    const event = doneEvent(); const session = terminalSession();
    store.queuePendingEvent(event, session);
    store.persistInflightEventUpload(event.eventId, session.sessionId, eventUpload(event.eventId));
    const before = rawInflightRecord(store, `inflight:event:${event.eventId}`);
    const client = makeClient({
      reconcileEncryptedEvent: async () => { throw new Error('relay unavailable'); },
    });
    const orchestrator = createOrchestrator(store, client as any, emptyKeyring);

    expect(await orchestrator.convertLegacyInflightToV2()).toBe(false);
    const after = rawInflightRecord(store, `inflight:event:${event.eventId}`);
    expect(after).toEqual(before);
    expect(after.version).toBeUndefined(); // still the legacy raw form
    expect(store.hasEventUploadCompletion(event.eventId)).toBe(false);
  });

  test('V2 inflight records are skipped without a reconcile round-trip', async () => {
    const store = fixture();
    const event = doneEvent(); const session = terminalSession();
    store.queuePendingEvent(event, session);
    store.persistInflightEventUpload(event.eventId, session.sessionId, eventUpload(event.eventId), eventSourceDigest(event, session));
    const before = rawInflightRecord(store, `inflight:event:${event.eventId}`);
    const client = makeClient();
    const orchestrator = createOrchestrator(store, client as any, emptyKeyring);

    expect(await orchestrator.convertLegacyInflightToV2()).toBe(true);
    expect(client.reconcileEventCalls).toHaveLength(0);
    expect(rawInflightRecord(store, `inflight:event:${event.eventId}`)).toEqual(before);
  });

  test('malformed source with legacy inflight is skipped so the §5.2 flow reconciles it', async () => {
    const store = fixture();
    const event = doneEvent(); const session = terminalSession();
    (store as any).spool.enqueue({
      spoolItemId: event.eventId, sessionId: session.sessionId, eventId: event.eventId, payloadKind: 'event-source-v3',
      createdAt: '2026-08-07T00:00:01.000Z', plaintext: new TextEncoder().encode('{ not json'),
    });
    store.persistInflightEventUpload(event.eventId, session.sessionId, eventUpload(event.eventId));
    const before = rawInflightRecord(store, `inflight:event:${event.eventId}`);
    const client = makeClient();
    const orchestrator = createOrchestrator(store, client as any, emptyKeyring);

    expect(await orchestrator.convertLegacyInflightToV2()).toBe(true);
    expect(client.reconcileEventCalls).toHaveLength(0);
    expect(rawInflightRecord(store, `inflight:event:${event.eventId}`)).toEqual(before);
  });

  test('conversion is idempotent across repeated passes', async () => {
    const store = fixture();
    const event = doneEvent(); const session = terminalSession();
    store.queuePendingEvent(event, session);
    store.persistInflightEventUpload(event.eventId, session.sessionId, eventUpload(event.eventId));
    const client = makeClient();
    const orchestrator = createOrchestrator(store, client as any, emptyKeyring);

    expect(await orchestrator.convertLegacyInflightToV2()).toBe(true);
    const first = rawInflightRecord(store, `inflight:event:${event.eventId}`);
    expect(await orchestrator.convertLegacyInflightToV2()).toBe(true);
    const second = rawInflightRecord(store, `inflight:event:${event.eventId}`);
    expect(second).toEqual(first);
    expect(second.version).toBe(2);
    // The second pass skips the now-V2 record (one reconcile from the first pass only).
    expect(client.reconcileEventCalls).toHaveLength(1);
  });

  test('source-less legacy Event inflight: uncommitted reconcile fails closed with bytes preserved', async () => {
    const store = fixture();
    store.persistInflightEventUpload('event-orphan', 'session-test', eventUpload('event-orphan'));
    const before = rawInflightRecord(store, 'inflight:event:event-orphan');
    const client = makeClient(); // uncommitted
    const orchestrator = createOrchestrator(store, client as any, emptyKeyring);

    expect(await orchestrator.convertLegacyInflightToV2()).toBe(false);
    expect(rawInflightRecord(store, 'inflight:event:event-orphan')).toEqual(before);
    expect(store.hasEventUploadCompletion('event-orphan')).toBe(false);
  });

  test('source-less legacy Event inflight: committed reconcile completes old evidence', async () => {
    const store = fixture();
    store.persistInflightEventUpload('event-orphan', 'session-test', eventUpload('event-orphan'));
    const client = makeClient({ reconcileEncryptedEvent: async () => ({ committed: true }) });
    const orchestrator = createOrchestrator(store, client as any, emptyKeyring);

    expect(await orchestrator.convertLegacyInflightToV2()).toBe(true);
    expect(store.hasEventUploadCompletion('event-orphan')).toBe(false); // journal fully consumed
    expect((store as any).spool.get('inflight:event:event-orphan')).toBeUndefined();
    expect(store.currentSessionRevision('session-test')).toBe(1);
  });

  test('Session inflight with no runtime Session: uncommitted reconcile fails closed, committed completes', async () => {
    const store = fixture();
    store.persistInflightSessionUpload('session-test', sessionUpload()); // correctly bound, but no runtime Session exists
    const client = makeClient(); // uncommitted
    expect(await createOrchestrator(store, client as any, emptyKeyring).convertLegacyInflightToV2()).toBe(false);
    expect(store.getLegacyInflightSessionUpload('session-test')).toBeDefined(); // raw evidence preserved
    expect(store.currentSessionRevision('session-test')).toBe(0);

    const committing = makeClient({ reconcileEncryptedSession: async () => true });
    expect(await createOrchestrator(store, committing as any, emptyKeyring).convertLegacyInflightToV2()).toBe(true);
    expect(store.currentSessionRevision('session-test')).toBe(1);
    expect((store as any).spool.get('inflight:session:session-test')).toBeUndefined();
  });

  test('cross-bound Session inflight (inner sessionId != outer key) fails closed byte-preserved', async () => {
    const store = fixture();
    // Write-time binding checks reject cross-bound writes, so simulate the
    // persisted evidence directly (legacy raw form under the wrong outer key).
    const crossBound = sessionUpload(); // inner sessionId: session-test
    (store as any).spool.enqueue({ spoolItemId: 'inflight:session:session-ghost', sessionId: 'session-ghost',
      payloadKind: 'session-upload-v3', createdAt: new Date().toISOString(),
      plaintext: new TextEncoder().encode(JSON.stringify(crossBound)) });
    const before = rawInflightRecord(store, 'inflight:session:session-ghost');
    const client = makeClient({ reconcileEncryptedSession: async () => true }); // even a committed answer must not advance the wrong cursor
    const orchestrator = createOrchestrator(store, client as any, emptyKeyring);

    expect(await orchestrator.convertLegacyInflightToV2()).toBe(false);
    expect(rawInflightRecord(store, 'inflight:session:session-ghost')).toEqual(before); // byte-preserved
    expect(store.currentSessionRevision('session-ghost')).toBe(0); // wrong cursor untouched
    expect(store.currentSessionRevision('session-test')).toBe(0); // inner Session cursor untouched
    // The publication flow fails closed on the same evidence.
    expect(() => store.getInflightSessionUpload('session-ghost')).toThrow(TypeError);
    expect(() => store.persistInflightSessionUpload('session-ghost', sessionUpload())).toThrow(TypeError);
  });

  test('flushPendingEvents stops when conversion cannot converge on source-less legacy evidence', async () => {
    const store = fixture();
    store.setRecipientSetVersion(1);
    store.persistInflightEventUpload('event-orphan', 'session-test', eventUpload('event-orphan'));
    const client = makeClient(); // uncommitted → conversion defers → drain stops
    const orchestrator = createOrchestrator(store, client as any, emptyKeyring);

    expect(await orchestrator.flushPendingEvents()).toBe(0);
    expect(store.getQuarantinedEventRecord('event-orphan')).toBeUndefined();
    expect(rawInflightRecord(store, 'inflight:event:event-orphan').version).toBeUndefined();
  });
});
