import { afterEach, describe, expect, mock, test } from 'bun:test';
import { mkdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { CanonicalEvent, CanonicalSessionState } from '@ariava/protocol';
import { ChaChaPolyAuthenticationError } from '../src/e2e/node-crypto';

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
  const root = join(tmpdir(), `bridge-pending-${Date.now()}-${roots.length}`); roots.push(root); mkdirSync(root, { mode: 0o700 });
  const store = new BridgeStateStore(join(root, 'state.json'));
  store.initializeEncryptedSpool('host-test', join(root, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
  return store;
}

function durableFixture() {
  const root = join(tmpdir(), `bridge-pending-${Date.now()}-${roots.length}`); roots.push(root); mkdirSync(root, { mode: 0o700 });
  const statePath = join(root, 'state.json'); const identityPath = join(root, 'identity.json');
  const store = new BridgeStateStore(statePath);
  store.initializeEncryptedSpool('host-test', identityPath, 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
  return { statePath, identityPath, store };
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

function eventN(n: number, overrides: Partial<CanonicalEvent> = {}): CanonicalEvent {
  return { ...doneEvent(), eventId: `event-${n}`, sessionId: `session-${n}`, ...overrides };
}

function sessionN(n: number): CanonicalSessionState {
  return { ...terminalSession(), sessionId: `session-${n}`, lastEventId: `event-${n}` };
}

function enqueueGood(store: BridgeStateStore, n: number): void {
  store.queuePendingEvent(eventN(n), sessionN(n));
}

function enqueueRawSource(store: BridgeStateStore, eventId: string, sessionId: string, payload: Uint8Array): void {
  (store as any).spool.enqueue({
    spoolItemId: eventId, sessionId, eventId, payloadKind: 'event-source-v3',
    createdAt: '2026-08-07T00:00:01.000Z', plaintext: payload,
  });
}

function replaceSource(store: BridgeStateStore, eventId: string, sessionId: string, payload: Uint8Array): void {
  (store as any).spool.replace([eventId], [{
    spoolItemId: eventId, sessionId, eventId, payloadKind: 'event-source-v3',
    createdAt: '2026-08-07T00:00:01.000Z', plaintext: payload,
  }]);
}

function replaceInflight(store: BridgeStateStore, eventId: string, sessionId: string, payload: Uint8Array): void {
  const inflightId = `inflight:event:${eventId}`;
  (store as any).spool.replace([inflightId], [{
    spoolItemId: inflightId, sessionId, eventId, payloadKind: 'event-upload-v3',
    createdAt: '2026-08-07T00:00:01.000Z', plaintext: payload,
  }]);
}

function readRawSpool(store: BridgeStateStore, spoolItemId: string): Uint8Array {
  const spool = (store as any).spool;
  const item = spool.get(spoolItemId);
  if (!item) throw new Error(`missing spool item: ${spoolItemId}`);
  return spool.open(item);
}

const encoder = new TextEncoder();

const okClient = {
  recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }),
  publishEncryptedEvent: async () => {},
  publishEncryptedSession: async () => {},
};
const emptyKeyring = { reconcileRecipients: () => [] } as any;

describe('PendingEventProcessor §5.2/§5.4 queue isolation', () => {
  test('64 KiB+1 canonical Event is dead-lettered while two later good Events flush', async () => {
    const store = fixture();
    store.setRecipientSetVersion(1);
    const failures: any[] = [];
    const oversized = doneEvent({ eventId: 'event-bad', agentText: 'a'.repeat(65_500) });
    store.queuePendingEvent(oversized, { ...terminalSession(), lastEventId: 'event-bad' } as any);
    enqueueGood(store, 0);
    enqueueGood(store, 1);
    const orchestrator = createOrchestrator(store, okClient as any, emptyKeyring, { eventFailure: (f) => failures.push(f) });
    expect(await orchestrator.flushPendingEvents()).toBe(2);
    const dead = store.getQuarantinedEventRecord('event-bad') as any;
    expect(dead).toMatchObject({ version: 2, eventId: 'event-bad', reasonCode: 'protected-content-invalid' });
    expect(typeof dead.sourceArchive.bytes).toBe('string');
    expect(failures).toEqual([{ eventId: 'event-bad', sessionId: 'session-test', outcome: 'quarantined', category: 'local-validation' }]);
    expect(store.peekPendingUploads()).toEqual([]);
  });

  test('near-limit legal canonical Event (64 KiB of agentText) passes and uploads', async () => {
    const store = fixture();
    store.setRecipientSetVersion(1);
    enqueueGood(store, 0);
    const legal = doneEvent({ eventId: 'event-big', agentText: 'a'.repeat(64_000) });
    store.queuePendingEvent(legal, { ...terminalSession(), lastEventId: 'event-big' } as any);
    const uploads: any[] = [];
    const client = { ...okClient, publishEncryptedEvent: async (event: any, session: any) => { uploads.push({ event, session }); } };
    expect(await createOrchestrator(store, client as any, emptyKeyring).flushPendingEvents()).toBe(2);
    expect(uploads.some((u) => u.event.eventId === 'event-big')).toBe(true);
  });

  test('queue-head invalid JSON source is dead-lettered; good Event behind it still flushes', async () => {
    const store = fixture();
    store.setRecipientSetVersion(1);
    enqueueRawSource(store, 'bad', 'session-bad', encoder.encode('{ definitely not json'));
    enqueueGood(store, 1);
    const orchestrator = createOrchestrator(store, okClient as any, emptyKeyring);
    expect(await orchestrator.flushPendingEvents()).toBe(1);
    const dead = store.getQuarantinedEventRecord('bad') as any;
    expect(dead).toMatchObject({ version: 2, eventId: 'bad', reasonCode: 'source-json-invalid' });
    expect(store.listPendingEventDescriptors()).toEqual([]);
  });

  test('malformed source survives startup reconciliation (no eager-decode crash) and is quarantined at flush', async () => {
    const { statePath, identityPath, store } = durableFixture();
    store.setRecipientSetVersion(1);
    enqueueRawSource(store, 'bad', 'session-bad', new Uint8Array([0xff, 0xfe, 0x00]));
    enqueueGood(store, 1);
    store.dispose();
    const restarted = new BridgeStateStore(statePath);
    restarted.initializeEncryptedSpool('host-test', identityPath, 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
    restarted.setRecipientSetVersion(1);
    expect(restarted.listPendingEventDescriptors().map((d) => d.eventId).sort()).toEqual(['bad', 'event-1']);
    const orchestrator = createOrchestrator(restarted, okClient as any, emptyKeyring);
    expect(await orchestrator.flushPendingEvents()).toBe(1);
    const dead = restarted.getQuarantinedEventRecord('bad') as any;
    expect(dead).toMatchObject({ version: 2, eventId: 'bad', reasonCode: 'source-utf8-invalid' });
  });

  test('malformed source + inflight: committed reconcile completes old evidence instead of dead-lettering', async () => {
    const store = fixture();
    store.setRecipientSetVersion(1);
    enqueueGood(store, 1);
    let offline = true; let reconciles = 0;
    const client = {
      recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }),
      publishEncryptedEvent: async () => { if (offline) throw new Error('offline'); },
    };
    const orchestrator = createOrchestrator(store, client as any, emptyKeyring);
    expect(await orchestrator.flushPendingEvents()).toBe(0); // inflight created, publish deferred
    expect(store.getInflightEventUpload('event-1')).toBeDefined();
    replaceSource(store, 'event-1', 'session-1', encoder.encode('{ corrupted source'));
    const reconcilingClient = {
      ...okClient,
      reconcileEncryptedEvent: async () => { reconciles += 1; return { committed: true }; },
    };
    expect(await createOrchestrator(store, reconcilingClient as any, emptyKeyring).flushPendingEvents()).toBe(1);
    expect(reconciles).toBe(1);
    expect(store.getQuarantinedEventRecord('event-1')).toBeUndefined();
    expect(store.getInflightEventUpload('event-1')).toBeUndefined();
    expect(store.peekPendingUploads()).toEqual([]);
    expect(store.currentSessionRevision('session-1')).toBe(1);
  });

  test('malformed source + uncommitted inflight dead-letters both with the inflight archive', async () => {
    const store = fixture();
    store.setRecipientSetVersion(1);
    enqueueGood(store, 1);
    let offline = true;
    const client = {
      recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }),
      publishEncryptedEvent: async () => { if (offline) throw new Error('offline'); },
    };
    expect(await createOrchestrator(store, client as any, emptyKeyring).flushPendingEvents()).toBe(0);
    replaceSource(store, 'event-1', 'session-1', encoder.encode('{ corrupted source'));
    const reconcilingClient = {
      ...okClient,
      reconcileEncryptedEvent: async () => ({ committed: false }),
    };
    expect(await createOrchestrator(store, reconcilingClient as any, emptyKeyring).flushPendingEvents()).toBe(0);
    const dead = store.getQuarantinedEventRecord('event-1') as any;
    expect(dead).toMatchObject({ version: 2, eventId: 'event-1', reasonCode: 'source-json-invalid' });
    expect(typeof dead.inflightArchive?.bytes).toBe('string');
    expect(store.getInflightEventUpload('event-1')).toBeUndefined();
  });

  test('malformed inflight with no journal preserves both records as recovery-required', async () => {
    const store = fixture();
    store.setRecipientSetVersion(1);
    enqueueGood(store, 1);
    let offline = true;
    const client = {
      recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }),
      publishEncryptedEvent: async () => { if (offline) throw new Error('offline'); },
    };
    expect(await createOrchestrator(store, client as any, emptyKeyring).flushPendingEvents()).toBe(0);
    replaceInflight(store, 'event-1', 'session-1', encoder.encode('{ broken inflight'));
    expect(await createOrchestrator(store, okClient as any, emptyKeyring).flushPendingEvents()).toBe(0);
    expect(store.getQuarantinedEventRecord('event-1')).toBeUndefined();
    expect(store.peekPendingUploads().map((p) => p.event.eventId)).toEqual(['event-1']);
    expect(store.getInflightEventUpload('event-1')).toBeUndefined(); // unwrap of malformed wrapper is not a valid upload
  });

  test('completion journal wins over a pending source: recovery without re-publish', async () => {
    const store = fixture();
    store.setRecipientSetVersion(1);
    enqueueGood(store, 1);
    store.beginEventUploadCompletion({
      version: 1, eventId: 'event-1', sessionId: 'session-1', revision: 1,
      eventContentId: 'c-event', sessionContentId: 'c-session', committedAt: '2026-08-07T00:00:01.000Z',
    });
    let publishes = 0;
    const client = { ...okClient, publishEncryptedEvent: async () => { publishes += 1; } };
    expect(await createOrchestrator(store, client as any, emptyKeyring).flushPendingEvents()).toBe(1);
    expect(publishes).toBe(0);
    expect(store.peekPendingUploads()).toEqual([]);
    expect(store.currentSessionRevision('session-1')).toBe(1);
  });

  test('V2 digest mismatch: committed reconcile completes old evidence', async () => {
    const store = fixture();
    store.setRecipientSetVersion(1);
    enqueueGood(store, 1);
    let offline = true; let reconciles = 0;
    const client = {
      recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }),
      publishEncryptedEvent: async () => { if (offline) throw new Error('offline'); },
    };
    expect(await createOrchestrator(store, client as any, emptyKeyring).flushPendingEvents()).toBe(0);
    // Immutable source replaced under the same eventId with different content → digest mismatch.
    replaceSource(store, 'event-1', 'session-1', encoder.encode(JSON.stringify({ event: eventN(1, { agentText: 'different content' }), session: sessionN(1) })));
    const reconcilingClient = {
      ...okClient,
      reconcileEncryptedEvent: async () => { reconciles += 1; return { committed: true }; },
    };
    expect(await createOrchestrator(store, reconcilingClient as any, emptyKeyring).flushPendingEvents()).toBe(1);
    expect(reconciles).toBe(1);
    expect(store.getQuarantinedEventRecord('event-1')).toBeUndefined();
    expect(store.peekPendingUploads()).toEqual([]);
  });

  test('V2 digest mismatch: uncommitted reconcile is recovery-required, never dead-lettered', async () => {
    const store = fixture();
    store.setRecipientSetVersion(1);
    enqueueGood(store, 1);
    let offline = true; let reconciles = 0;
    const client = {
      recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }),
      publishEncryptedEvent: async () => { if (offline) throw new Error('offline'); },
    };
    expect(await createOrchestrator(store, client as any, emptyKeyring).flushPendingEvents()).toBe(0);
    replaceSource(store, 'event-1', 'session-1', encoder.encode(JSON.stringify({ event: eventN(1, { agentText: 'different content' }), session: sessionN(1) })));
    const reconcilingClient = {
      ...okClient,
      reconcileEncryptedEvent: async () => { reconciles += 1; return { committed: false }; },
    };
    expect(await createOrchestrator(store, reconcilingClient as any, emptyKeyring).flushPendingEvents()).toBe(0);
    expect(reconciles).toBe(1);
    expect(store.getQuarantinedEventRecord('event-1')).toBeUndefined();
    expect(store.peekPendingUploads().map((p) => p.event.eventId)).toEqual(['event-1']);
  });

  test('oversized bundled terminal Session (production root cause) dead-letters only that Event', async () => {
    const store = fixture();
    store.setRecipientSetVersion(1);
    enqueueGood(store, 1);
    const bigSession = { ...terminalSession(), lastEventId: 'event-bad-session', openingText: 'a'.repeat(64 * 1024) } as any;
    store.queuePendingEvent(doneEvent({ eventId: 'event-bad-session', sessionId: 'session-test' }), bigSession);
    expect(await createOrchestrator(store, okClient as any, emptyKeyring).flushPendingEvents()).toBe(1);
    const dead = store.getQuarantinedEventRecord('event-bad-session') as any;
    expect(dead).toMatchObject({ version: 2, eventId: 'event-bad-session', reasonCode: 'protected-content-invalid' });
    expect(store.peekPendingUploads()).toEqual([]);
  });

  test('quarantine write failure defers and keeps source retryable (fault injection)', async () => {
    const { statePath, identityPath, store } = durableFixture();
    store.dispose();
    let attempts = 0; const failures: any[] = [];
    const throwing = new (class extends BridgeStateStore {
      quarantinePendingEventRaw(_descriptor: any, _reason: any, _inflight?: Uint8Array): boolean {
        attempts += 1;
        throw new Error('injected quarantine write failure');
      }
    })(statePath);
    throwing.initializeEncryptedSpool('host-test', identityPath, 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
    throwing.setRecipientSetVersion(1);
    enqueueRawSource(throwing, 'bad', 'session-bad', encoder.encode('{ not json'));
    enqueueGood(throwing, 1);
    expect(await createOrchestrator(throwing as any, okClient as any, emptyKeyring, { eventFailure: (f) => failures.push(f) }).flushPendingEvents()).toBe(0);
    expect(attempts).toBe(1);
    expect(failures).toEqual([{ eventId: 'bad', sessionId: 'session-bad', outcome: 'retry-deferred', category: 'local-spool-record' }]);
    throwing.dispose();
    const restarted = new BridgeStateStore(statePath);
    restarted.initializeEncryptedSpool('host-test', identityPath, 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
    restarted.setRecipientSetVersion(1);
    expect(await createOrchestrator(restarted, okClient as any, emptyKeyring).flushPendingEvents()).toBe(1);
    expect(restarted.getQuarantinedEventRecord('bad')).toMatchObject({ version: 2, eventId: 'bad', reasonCode: 'source-json-invalid' });
  });

  test('internal TypeError from the storage layer fails closed and is never quarantined', async () => {
    const { statePath, identityPath, store } = durableFixture();
    store.dispose();
    const throwing = new (class extends BridgeStateStore {
      loadPendingEventParts(_descriptor: any): any { throw new TypeError('internal keyring fault'); }
    })(statePath);
    throwing.initializeEncryptedSpool('host-test', identityPath, 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
    throwing.setRecipientSetVersion(1);
    enqueueGood(throwing, 1);
    const orchestrator = createOrchestrator(throwing as any, okClient as any, emptyKeyring);
    await expect(orchestrator.flushPendingEvents()).rejects.toThrow('internal keyring fault');
    expect(throwing.getQuarantinedEventRecord('event-1')).toBeUndefined();
    expect(throwing.peekPendingUploads().map((p) => p.event.eventId)).toEqual(['event-1']);
  });

  test('spool AEAD authentication failure fails closed and is never quarantined', async () => {
    const { statePath, identityPath, store } = durableFixture();
    store.dispose();
    const throwing = new (class extends BridgeStateStore {
      loadPendingEventParts(_descriptor: any): any { throw new ChaChaPolyAuthenticationError('auth'); }
    })(statePath);
    throwing.initializeEncryptedSpool('host-test', identityPath, 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
    throwing.setRecipientSetVersion(1);
    enqueueGood(throwing, 1);
    const orchestrator = createOrchestrator(throwing as any, okClient as any, emptyKeyring);
    await expect(orchestrator.flushPendingEvents()).rejects.toThrow();
    expect(throwing.getQuarantinedEventRecord('event-1')).toBeUndefined();
    expect(throwing.peekPendingUploads().map((p) => p.event.eventId)).toEqual(['event-1']);
  });

  test('V2 wrapper round-trips through restart: digest and upload preserved, getter unwraps', async () => {
    const { statePath, identityPath, store } = durableFixture();
    store.setRecipientSetVersion(1);
    enqueueGood(store, 1);
    let offline = true;
    const client = {
      recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }),
      publishEncryptedEvent: async () => { if (offline) throw new Error('offline'); },
    };
    expect(await createOrchestrator(store, client as any, emptyKeyring).flushPendingEvents()).toBe(0);
    const inflight = store.getInflightEventUpload('event-1') as any;
    expect(inflight).toBeDefined();
    expect(inflight.event.eventId).toBe('event-1');
    store.dispose();
    const restarted = new BridgeStateStore(statePath);
    restarted.initializeEncryptedSpool('host-test', identityPath, 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
    restarted.setRecipientSetVersion(1);
    const reopened = restarted.getInflightEventUpload('event-1') as any;
    expect(reopened).toEqual(inflight);
    const parts = restarted.loadPendingEventParts({ eventId: 'event-1', sessionId: 'session-1' }) as any;
    expect(parts.ok).toBe(true);
    expect(parts.inflight.kind).toBe('v2');
    expect(parts.inflight.sourceDigest).toMatch(/^[A-Za-z0-9_-]{43}$/);
    (parts.inflight as { raw: Uint8Array }).raw.fill(0);
  });

  test.each([
    ['V2 outer wrapper', (wrapper: any) => { wrapper.unknown = true; }],
    ['V2 upload tuple', (wrapper: any) => { wrapper.upload.unknown = true; }],
    ['encrypted Event upload', (wrapper: any) => { wrapper.upload.event.unknown = true; }],
  ])('%s rejects unknown keys as recovery-required and preserves source/inflight bytes', async (_label, mutate) => {
    const store = fixture();
    store.setRecipientSetVersion(1);
    enqueueGood(store, 1);
    const offlineClient = { ...okClient, publishEncryptedEvent: async () => { throw new Error('offline'); } };
    expect(await createOrchestrator(store, offlineClient as any, emptyKeyring).flushPendingEvents()).toBe(0);
    const wrapper = JSON.parse(new TextDecoder().decode(readRawSpool(store, 'inflight:event:event-1')));
    mutate(wrapper);
    const malformed = encoder.encode(JSON.stringify(wrapper));
    const expectedMalformed = malformed.slice();
    replaceInflight(store, 'event-1', 'session-1', malformed);
    const sourceBefore = readRawSpool(store, 'event-1');
    expect(await createOrchestrator(store, okClient as any, emptyKeyring).flushPendingEvents()).toBe(0);
    expect(store.getQuarantinedEventRecord('event-1')).toBeUndefined();
    expect(readRawSpool(store, 'event-1')).toEqual(sourceBefore);
    expect(readRawSpool(store, 'inflight:event:event-1')).toEqual(expectedMalformed);
  });

  test('pending source outer tuple rejects unknown keys and archives the exact raw bytes', async () => {
    const store = fixture();
    store.setRecipientSetVersion(1);
    const raw = encoder.encode(JSON.stringify({ event: eventN(1), session: sessionN(1), unknown: true }));
    const expectedRaw = raw.slice();
    enqueueRawSource(store, 'event-1', 'session-1', raw);
    expect(await createOrchestrator(store, okClient as any, emptyKeyring).flushPendingEvents()).toBe(0);
    const dead = store.getQuarantinedEventRecord('event-1') as any;
    expect(dead).toMatchObject({ version: 2, reasonCode: 'source-json-invalid' });
    const { base64UrlDecode } = await import('@ariava/protocol');
    expect(base64UrlDecode(dead.sourceArchive.bytes, undefined, 'source archive')).toEqual(expectedRaw);
  });

  test('cross-bound V2 inflight (B upload under A key) is recovery-required, never completes A', async () => {
    const store = fixture();
    store.setRecipientSetVersion(1);
    enqueueGood(store, 1);
    // A structurally valid tuple for event-2 persisted under event-1's inflight key.
    const foreign = {
      event: { eventId: 'event-2', hostId: 'host-test', sessionId: 'session-2', provider: 'pi', type: 'done', status: 'idle',
        createdAt: '2026-08-07T00:00:01.000Z', recipientSetVersion: 1,
        content: { version: 1, suite: 'x25519-hkdf-sha256-chachapoly-v1', contentId: 'c-e2', payloadKind: 'event-content-v3',
          nonce: 'A'.repeat(16), ciphertext: 'B'.repeat(24) },
        keyWraps: [] },
      session: { hostId: 'host-test', sessionId: 'session-2', provider: 'pi', status: 'idle',
        updatedAt: '2026-08-07T00:00:01.000Z', lastEventId: 'event-2', revision: 1, recipientSetVersion: 1,
        content: { version: 1, suite: 'x25519-hkdf-sha256-chachapoly-v1', contentId: 'c-s2', payloadKind: 'session-content-v3',
          nonce: 'C'.repeat(16), ciphertext: 'D'.repeat(24) },
        keyWraps: [] },
    };
    store.persistInflightEventUpload('event-1', 'session-1', foreign, 'A'.repeat(43));
    expect(await createOrchestrator(store, okClient as any, emptyKeyring).flushPendingEvents()).toBe(0);
    expect(store.getQuarantinedEventRecord('event-1')).toBeUndefined();
    expect(store.peekPendingUploads().map((p) => p.event.eventId)).toEqual(['event-1']);
    expect(store.currentSessionRevision('session-1')).toBe(0);
  });

  test('shallow {event:{},session:{}} inflight is recovery-required, never crashes the queue', async () => {
    const store = fixture();
    store.setRecipientSetVersion(1);
    enqueueGood(store, 1);
    store.persistInflightEventUpload('event-1', 'session-1', { event: {}, session: {} });
    expect(await createOrchestrator(store, okClient as any, emptyKeyring).flushPendingEvents()).toBe(0);
    expect(store.getQuarantinedEventRecord('event-1')).toBeUndefined();
    expect(store.peekPendingUploads().map((p) => p.event.eventId)).toEqual(['event-1']);
  });

  test('internally valid source tuple bound to a foreign spool key is dead-lettered as binding-invalid', async () => {
    const store = fixture();
    store.setRecipientSetVersion(1);
    enqueueGood(store, 1);
    // Tuple B (event-2/session-2) stored under descriptor A (event-1/session-1):
    // internally consistent but not bound to the outer descriptor.
    replaceSource(store, 'event-1', 'session-1', encoder.encode(JSON.stringify({ event: eventN(2), session: sessionN(2) })));
    expect(await createOrchestrator(store, okClient as any, emptyKeyring).flushPendingEvents()).toBe(0);
    const dead = store.getQuarantinedEventRecord('event-1') as any;
    expect(dead).toMatchObject({ version: 2, eventId: 'event-1', reasonCode: 'event-session-binding-invalid' });
    expect(store.peekPendingUploads()).toEqual([]);
  });
});
