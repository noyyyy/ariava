import { afterEach, describe, expect, mock, test } from 'bun:test';
import { mkdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { base64UrlDecode, type CanonicalEvent, type CanonicalSessionState } from '@ariava/protocol';

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
const { RelayClientError } = await import('../src/relay-client');

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

/** Mirrors the removed compatibility facade's constructor shape; binds the single actions implementation. */
function createOrchestrator(
  stateStore: any,
  relayClient: any,
  keyring: { reconcileRecipients(snapshot: any): any[] } = { reconcileRecipients: () => [] },
  hooks?: Parameters<typeof createEncryptedUploadActions>[0]['hooks'],
) {
  return createEncryptedUploadActions({ stateStore, relayClient, crypto: DEFAULT_ENCRYPTED_UPLOAD_CRYPTO, keyring, hooks });
}

function fixture() {
  const root = join(tmpdir(), `bridge-upload-${Date.now()}-${roots.length}`); roots.push(root); mkdirSync(root, { mode: 0o700 });
  const store = new BridgeStateStore(join(root, 'state.json'));
  store.initializeEncryptedSpool('host-test', join(root, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
  return store;
}

function rawSpoolBytes(store: InstanceType<typeof BridgeStateStore>, spoolItemId: string): Uint8Array {
  const spool = (store as any).spool;
  const item = spool.get(spoolItemId);
  if (!item) throw new Error(`missing spool item: ${spoolItemId}`);
  return spool.open(item);
}

function terminalSession(overrides: Partial<CanonicalSessionState> = {}): CanonicalSessionState {
  return {
    sessionId: 'session-test', hostId: 'host-test', provider: 'pi', projectName: 'secret-project', nameText: 'Session',
    latestActivityText: 'terminal activity', workingDirectory: '/secret/project',
    harnessProvider: 'pi', status: 'idle', updatedAt: '2026-08-07T00:00:01.000Z',
    lastEventId: 'event-test', ...overrides,
  };
}

function doneEvent(overrides: Partial<CanonicalEvent> = {}): CanonicalEvent {
  return {
    eventId: 'event-test', hostId: 'host-test', sessionId: 'session-test', provider: 'pi', type: 'done', status: 'idle',
    agentText: 'terminal activity', projectName: 'secret-project',
    workingDirectory: '/secret/project', harnessProvider: 'pi',
    createdAt: '2026-08-07T00:00:01.000Z', ...overrides,
  } as CanonicalEvent;
}

function needHumanEvent(): CanonicalEvent {
  return {
    ...doneEvent(), type: 'need_human', status: 'need_human',
    needHuman: { reason: 'error', error: { kind: 'provider_failure', message: 'Sanitized provider failure.', providerCode: 'E_PROVIDER', retryExhausted: true } },
  };
}

const identity = { version: 1 as const, hostId: 'host-test', encryptionKeyId: 'ekey-test', publicKey: '',
  privateKeyPkcs8: new Uint8Array(), sequence: 1, createdAt: '2026-08-01T00:00:00.000Z' };
function recipient(index: number, hostIdentity = identity) {
  return {
    linkId: `link-${index}`, linkGeneration: 1, watchDeviceId: `watch-${index}`, epoch: index, state: 'active' as const,
    transcriptDigest: 'A'.repeat(43), hostIdentity,
    hostBinding: { version: 1 as const, entityType: 'host' as const, entityId: hostIdentity.hostId, identityKeyId: 'key-host',
      encryptionKeyId: hostIdentity.encryptionKeyId, publicKey: hostIdentity.publicKey, sequence: hostIdentity.sequence,
      createdAt: hostIdentity.createdAt, bindingSignature: 'B'.repeat(86) },
    watchBinding: { version: 1 as const, entityType: 'watch' as const, entityId: `watch-${index}`,
      identityKeyId: `key-${index}`, encryptionKeyId: `ekey-watch-${index}`, publicKey: 'A'.repeat(43),
      sequence: 1, createdAt: '2026-08-01T00:00:00.000Z', bindingSignature: 'B'.repeat(86) },
  };
}

function openMockedContent(content: { ciphertext: string }): any {
  const ciphertext = base64UrlDecode(content.ciphertext, undefined, 'test ciphertext');
  return JSON.parse(new TextDecoder().decode(ciphertext.slice(0, -16)));
}

describe('EncryptedUploadActions canonical Event binding', () => {
  test('uploads the exact terminal Session snapshot even after the authoritative Session changes', async () => {
    const store = fixture();
    const terminal = terminalSession();
    store.replaceDriverSessions('pi', [terminal]);
    store.queuePendingEvent(doneEvent(), terminal);
    store.replaceDriverSessions('pi', [{ ...terminal, status: 'working', latestActivityText: 'new work',
      updatedAt: '2026-08-07T00:00:02.000Z', lastEventId: undefined }]);
    store.setRecipientSetVersion(1);
    const uploads: any[] = [];
    const client = {
      recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }),
      publishEncryptedEvent: async (event: any, session: any) => { uploads.push({ event, session }); },
    };
    const flushed = await createOrchestrator(store, client as any, { reconcileRecipients: () => [] } as any).flushPendingEvents();
    expect(flushed).toBe(1);
    expect(uploads[0].event).toMatchObject({ type: 'done', status: 'idle', content: { payloadKind: 'event-content-v3' } });
    expect(uploads[0].session).toMatchObject({ status: 'idle', updatedAt: terminal.updatedAt, lastEventId: 'event-test', content: { payloadKind: 'session-content-v3' } });
    expect(openMockedContent(uploads[0].session.content)).toEqual({ version: 3, projectName: 'secret-project', nameText: 'Session', latestActivityText: 'terminal activity', workingDirectory: '/secret/project', harnessProvider: 'pi' });
  });

  test('rejects Event persistence without a real matching terminal Session snapshot', () => {
    const store = fixture();
    expect(() => store.queuePendingEvent(doneEvent(), { ...terminalSession(), sessionId: 'other' })).toThrow(/terminal Session/u);
    expect(() => store.queuePendingEvent(doneEvent(), { ...terminalSession(), status: 'working' })).toThrow(/terminal Session/u);
    expect(store.peekPendingUploads()).toEqual([]);
  });

  test('recipient churn re-encrypts the original type, status, protected reason, and terminal snapshot', async () => {
    const store = fixture();
    const terminal = terminalSession({ status: 'need_human' });
    store.replaceDriverSessions('pi', [terminal]);
    store.queuePendingEvent(needHumanEvent(), terminal);
    store.setRecipientSetVersion(1);
    let version = 1; let attempts = 0; const uploads: any[] = [];
    const client = {
      recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: version, recipients: [] }),
      publishEncryptedEvent: async (event: any, session: any) => {
        attempts += 1; uploads.push({ event, session });
        if (attempts === 1) { version = 2; throw new RelayClientError(409, 'recipient changed', { error: 'e2e_recipient_set_changed' }); }
      },
      reconcileEncryptedEvent: async () => ({ committed: false }),
    };
    const keyring = { reconcileRecipients: () => [recipient(version)] };
    expect(await createOrchestrator(store, client as any, keyring as any).flushPendingEvents()).toBe(1);
    const retried = uploads[1];
    expect(retried.event).toMatchObject({ type: 'need_human', status: 'need_human', recipientSetVersion: 2 });
    expect(retried.session).toMatchObject({ status: 'need_human', lastEventId: 'event-test', recipientSetVersion: 2 });
    expect(openMockedContent(retried.event.content)).toMatchObject({
      version: 3, needHuman: { reason: 'error', error: { providerCode: 'E_PROVIDER', retryExhausted: true } },
    });
    expect(retried.event.notificationPreviews[0]).toMatchObject({ eventType: 'need_human', content: { payloadKind: 'notification-preview-v2' } });
  });

  test('uses each mixed historical pin identity for Event, Session, and notification wraps', async () => {
    const store = fixture();
    const terminal = terminalSession();
    store.replaceDriverSessions('pi', [terminal]);
    store.queuePendingEvent(doneEvent(), terminal);
    store.setRecipientSetVersion(1);
    const historical = { ...identity, encryptionKeyId: 'ekey-historical', sequence: 1 };
    const current = { ...identity, encryptionKeyId: 'ekey-current', sequence: 2 };
    const recipients = [recipient(1, historical), recipient(2, current)];
    let published: any;
    const client = {
      recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }),
      publishEncryptedEvent: async (event: any, session: any) => { published = { event, session }; },
    };
    const keyring = { reconcileRecipients: () => recipients };
    expect(await createOrchestrator(store, client as any, keyring as any).flushPendingEvents()).toBe(1);
    expect(published.event.keyWraps.map((wrap: any) => wrap.senderEncryptionKeyId)).toEqual(['ekey-historical', 'ekey-current']);
    expect(published.session.keyWraps.map((wrap: any) => wrap.senderEncryptionKeyId)).toEqual(['ekey-historical', 'ekey-current']);
    expect(published.event.notificationPreviews.map((preview: any) => preview.keyWrap.senderEncryptionKeyId))
      .toEqual(['ekey-historical', 'ekey-current']);
  });

  test('transient retry preserves one inflight v3 tuple rather than rebuilding classification', async () => {
    const store = fixture(); const terminal = terminalSession();
    store.replaceDriverSessions('pi', [terminal]); store.queuePendingEvent(doneEvent(), terminal); store.setRecipientSetVersion(1);
    const published: any[] = []; let offline = true;
    const client = {
      recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }),
      publishEncryptedEvent: async (event: any, session: any) => { published.push({ event, session }); if (offline) throw new Error('offline'); },
    };
    const orchestrator = createOrchestrator(store, client as any, { reconcileRecipients: () => [] } as any);
    expect(await orchestrator.flushPendingEvents()).toBe(0);
    const inflight = store.getInflightEventUpload('event-test');
    offline = false;
    expect(await orchestrator.flushPendingEvents()).toBe(1);
    expect(published[1]).toEqual(inflight);
  });

  test('same-version recipient conflict defers once without ciphertext churn or hot loop', async () => {
    const store = fixture();
    store.replaceDriverSessions('pi', [terminalSession()]);
    let recipientReads = 0;
    let publishAttempts = 0;
    let reconcileAttempts = 0;
    const client = {
      recipientSnapshot: async () => {
        recipientReads += 1;
        return { version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] };
      },
      publishEncryptedSession: async () => {
        publishAttempts += 1;
        throw new RelayClientError(409, 'recipient changed', { error: 'e2e_recipient_set_changed' });
      },
      reconcileEncryptedSession: async () => { reconcileAttempts += 1; return false; },
    };
    const orchestrator = createOrchestrator(
      store, client as any, { reconcileRecipients: () => [] } as any,
    );

    expect(await orchestrator.flushPendingEvents()).toBe(0);
    const inflight = store.getInflightSessionUpload('session-test');
    expect(inflight).toBeDefined();
    expect({ recipientReads, publishAttempts, reconcileAttempts }).toEqual({
      recipientReads: 2, publishAttempts: 1, reconcileAttempts: 1,
    });

    const beforeRetry = structuredClone(inflight);
    expect(await orchestrator.flushPendingEvents()).toBe(0);
    expect(store.getInflightSessionUpload('session-test')).toEqual(beforeRetry);
    expect({ recipientReads, publishAttempts, reconcileAttempts }).toEqual({
      recipientReads: 4, publishAttempts: 2, reconcileAttempts: 2,
    });
  });

  test('no-recipient authority performs one bounded snapshot pass and does not hot-loop', async () => {
    const store = fixture(); const terminal = terminalSession();
    store.replaceDriverSessions('pi', [terminal]); store.queuePendingEvent(doneEvent(), terminal);
    let recipientReads = 0; let snapshotUploads = 0; let eventUploads = 0;
    const client = {
      recipientSnapshot: async () => { recipientReads += 1; return { version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }; },
      publishEncryptedSession: async () => { snapshotUploads += 1; },
      publishEncryptedEvent: async () => { eventUploads += 1; },
    };
    expect(await createOrchestrator(store, client as any, { reconcileRecipients: () => [] } as any).flushPendingEvents()).toBe(1);
    expect({ recipientReads, snapshotUploads, eventUploads }).toEqual({ recipientReads: 1, snapshotUploads: 1, eventUploads: 1 });
  });
});
function durableFixture() {
  const root = join(tmpdir(), `bridge-upload-${Date.now()}-${roots.length}`); roots.push(root); mkdirSync(root, { mode: 0o700 });
  const statePath = join(root, 'state.json'); const identityPath = join(root, 'identity.json');
  const store = new BridgeStateStore(statePath);
  store.initializeEncryptedSpool('host-test', identityPath, 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
  return { statePath, identityPath, store };
}

describe('EncryptedUploadActions Event completion journal fault injection', () => {
  const completionPhases = ['journaled', 'revision-committed', 'inflight-removed', 'source-removed', 'journal-removed'] as const;

  test('fires every completion stage in the frozen order on success', async () => {
    const store = fixture(); const terminal = terminalSession();
    store.replaceDriverSessions('pi', [terminal]); store.queuePendingEvent(doneEvent(), terminal); store.setRecipientSetVersion(1);
    const phases: string[] = [];
    const client = {
      recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }),
      publishEncryptedEvent: async () => {},
    };
    const orchestrator = createOrchestrator(store, client as any, { reconcileRecipients: () => [] } as any, {
      eventCompletionStep: (phase, eventId) => { phases.push(phase); expect(eventId).toBe('event-test'); },
    });
    expect(await orchestrator.flushPendingEvents()).toBe(1);
    expect(phases).toEqual([...completionPhases]);
  });

  test('a fault at any completion stage leaves durable state that restart completes exactly once', async () => {
    for (const faultPhase of completionPhases) {
      const { statePath, identityPath, store } = durableFixture();
      const terminal = terminalSession(); store.replaceDriverSessions('pi', [terminal]); store.queuePendingEvent(doneEvent(), terminal); store.setRecipientSetVersion(1);
      let publishes = 0; const phases: string[] = [];
      const client = {
        recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }),
        publishEncryptedEvent: async () => { publishes += 1; },
      };
      const orchestrator = createOrchestrator(store, client as any, { reconcileRecipients: () => [] } as any, {
        eventCompletionStep: (phase) => {
          phases.push(phase);
          if (phase === faultPhase) throw new Error(`injected fault at ${faultPhase}`);
        },
      });
      await expect(orchestrator.flushPendingEvents()).rejects.toThrow(`injected fault at ${faultPhase}`);
      expect(publishes).toBe(1);

      // Restart over the same durable state: journal recovery must finish every
      // remaining stage exactly once, with no re-publish, no revision jump, no quarantine.
      store.dispose();
      const restarted = new BridgeStateStore(statePath);
      restarted.initializeEncryptedSpool('host-test', identityPath, 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
      expect(restarted.peekPendingUploads()).toEqual([]);
      expect(restarted.getInflightEventUpload('event-test')).toBeUndefined();
      expect(restarted.getInflightSessionUpload('session-test')).toBeUndefined();
      expect(restarted.currentSessionRevision('session-test')).toBe(1);
      expect(restarted.getQuarantinedEventRecord('event-test')).toBeUndefined();
      const persisted = JSON.parse(readFileSync(statePath, 'utf8'));
      expect(persisted.eventUploadCompletions).toBeUndefined();

      const republished: any[] = [];
      const resumedClient = {
        recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }),
        publishEncryptedEvent: async (event: any, session: any) => { republished.push({ event, session }); },
      };
      const resumed = createOrchestrator(restarted, resumedClient as any, { reconcileRecipients: () => [] } as any);
      expect(await resumed.flushPendingEvents()).toBe(0);
      expect(republished).toEqual([]);
      expect(restarted.currentSessionRevision('session-test')).toBe(1);
      expect(restarted.getQuarantinedEventRecord('event-test')).toBeUndefined();
      const afterResume = JSON.parse(readFileSync(statePath, 'utf8'));
      expect(afterResume.eventUploadCompletions).toBeUndefined();
    }
  });
});

describe('EncryptedUploadActions recipient-change no-progress fail-closed (§8.1)', () => {
  test('authoritative same-version conflict with reconcile committed advances and clears stale inflight evidence', async () => {
    const store = fixture();
    const terminal = terminalSession();
    store.replaceDriverSessions('pi', [terminal]);
    let publishes = 0; let reconciles = 0; let recipientReads = 0; const failures: any[] = [];
    const snapshot = { version: 1 as const, hostId: 'host-test', recipientSetVersion: 1, recipients: [] };
    const client = {
      publishEncryptedSession: async () => {
        publishes += 1;
        if (publishes === 1) throw new RelayClientError(409, 'recipient changed', { error: 'e2e_recipient_set_changed' });
      },
      reconcileEncryptedSession: async () => { reconciles += 1; return true; },
      recipientSnapshot: async () => { recipientReads += 1; return snapshot; },
    };
    const orchestrator = createOrchestrator(store, client as any, { reconcileRecipients: () => [] } as any, {
      eventFailure: (failure) => failures.push(failure),
    });
    const result = await orchestrator.publishAuthoritativeSnapshots(snapshot, [], [terminal]);
    expect(result).toMatchObject({ type: 'published', recipientSetVersion: 1 });
    expect(result?.type === 'published' && result.revisions.get('session-test')).toBe(2);
    expect({ publishes, reconciles, recipientReads }).toEqual({ publishes: 2, reconciles: 1, recipientReads: 1 });
    expect(store.currentSessionRevision('session-test')).toBe(2);
    expect(store.getInflightSessionUpload('session-test')).toBeUndefined();
    expect(failures).toEqual([]);
  });

  test('recipient-change same-version conflict with reconcile committed advances and clears stale inflight evidence', async () => {
    const store = fixture();
    const terminal = terminalSession();
    store.replaceDriverSessions('pi', [terminal]);
    let publishes = 0; let reconciles = 0; let recipientReads = 0; const failures: any[] = [];
    const snapshot = { version: 1 as const, hostId: 'host-test', recipientSetVersion: 1, recipients: [] };
    const client = {
      publishEncryptedSession: async () => {
        publishes += 1;
        if (publishes === 1) throw new RelayClientError(409, 'recipient changed', { error: 'e2e_recipient_set_changed' });
      },
      reconcileEncryptedSession: async () => { reconciles += 1; return true; },
      recipientSnapshot: async () => { recipientReads += 1; return snapshot; },
    };
    const orchestrator = createOrchestrator(store, client as any, { reconcileRecipients: () => [] } as any, {
      eventFailure: (failure) => failures.push(failure),
    });
    expect(await orchestrator.publishRecipientChangeSnapshots(snapshot, [])).toBe(true);
    expect({ publishes, reconciles, recipientReads }).toEqual({ publishes: 2, reconciles: 1, recipientReads: 1 });
    expect(store.currentSessionRevision('session-test')).toBe(2);
    expect(store.getInflightSessionUpload('session-test')).toBeUndefined();
    expect(store.getRecipientSetVersion()).toBe(1);
    expect(failures).toEqual([]);
  });

  test('repeated authoritative same-version reconcile-committed conflict fails closed after one revision advance', async () => {
    const store = fixture();
    const terminal = terminalSession();
    store.replaceDriverSessions('pi', [terminal]);
    let publishes = 0; let reconciles = 0; let recipientReads = 0;
    const snapshot = { version: 1 as const, hostId: 'host-test', recipientSetVersion: 1, recipients: [] };
    const client = {
      publishEncryptedSession: async () => {
        publishes += 1;
        throw new RelayClientError(409, 'recipient changed', { error: 'e2e_recipient_set_changed' });
      },
      reconcileEncryptedSession: async () => { reconciles += 1; return true; },
      recipientSnapshot: async () => { recipientReads += 1; return snapshot; },
    };
    const orchestrator = createOrchestrator(store, client as any, { reconcileRecipients: () => [] } as any);

    expect(await orchestrator.publishAuthoritativeSnapshots(snapshot, [], [terminal])).toEqual({ type: 'fail-closed' });
    expect({ publishes, reconciles, recipientReads }).toEqual({ publishes: 2, reconciles: 2, recipientReads: 2 });
    expect(store.currentSessionRevision('session-test')).toBe(1);
    expect((store.getInflightSessionUpload('session-test') as any)?.revision).toBe(2);
    expect(store.getRecipientSetVersion()).toBeUndefined();
  });

  test('repeated recipient-change same-version reconcile-committed conflict fails closed after one revision advance', async () => {
    const store = fixture();
    store.replaceDriverSessions('pi', [terminalSession()]);
    let publishes = 0; let reconciles = 0; let recipientReads = 0; const failures: any[] = [];
    const snapshot = { version: 1 as const, hostId: 'host-test', recipientSetVersion: 1, recipients: [] };
    const client = {
      publishEncryptedSession: async () => {
        publishes += 1;
        throw new RelayClientError(409, 'recipient changed', { error: 'e2e_recipient_set_changed' });
      },
      reconcileEncryptedSession: async () => { reconciles += 1; return true; },
      recipientSnapshot: async () => { recipientReads += 1; return snapshot; },
    };
    const orchestrator = createOrchestrator(store, client as any, { reconcileRecipients: () => [] } as any, {
      eventFailure: (failure) => failures.push(failure),
    });

    expect(await orchestrator.publishRecipientChangeSnapshots(snapshot, [])).toBe(false);
    expect({ publishes, reconciles, recipientReads }).toEqual({ publishes: 2, reconciles: 2, recipientReads: 2 });
    expect(store.currentSessionRevision('session-test')).toBe(1);
    expect((store.getInflightSessionUpload('session-test') as any)?.revision).toBe(2);
    expect(store.getRecipientSetVersion()).toBeUndefined();
    expect(failures).toEqual([{ eventId: 'pending-events', sessionId: 'unknown', outcome: 'retry-deferred', status: 409, category: 'recipient-set' }]);
  });

  test('same recipient-set version after refresh fails closed with bounded calls and no revision jump', async () => {
    const { statePath, identityPath, store } = durableFixture();
    const terminal = terminalSession(); store.replaceDriverSessions('pi', [terminal]);
    let publishes = 0; let reconciles = 0; let recipientReads = 0; const failures: any[] = [];
    const snapshot = { version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] };
    const client = {
      publishEncryptedSession: async () => { publishes += 1; throw new RelayClientError(409, 'recipient changed', { error: 'e2e_recipient_set_changed' }); },
      reconcileEncryptedSession: async () => { reconciles += 1; return false; },
      recipientSnapshot: async () => { recipientReads += 1; return snapshot; },
    };
    const orchestrator = createOrchestrator(store, client as any, { reconcileRecipients: () => [] } as any, {
      eventFailure: (failure) => failures.push(failure),
    });
    expect(await orchestrator.publishRecipientChangeSnapshots(snapshot, [])).toBe(false);
    expect({ publishes, reconciles, recipientReads }).toEqual({ publishes: 1, reconciles: 1, recipientReads: 1 });
    // Fail closed: inflight evidence preserved, no revision committed, no source removed.
    expect(store.getInflightSessionUpload('session-test')).toBeDefined();
    expect(store.currentSessionRevision('session-test')).toBe(0);
    expect(store.getQuarantinedEventRecord('event-test')).toBeUndefined();
    // Desensitized deferred failure only: category recipient-set, no message/error text.
    expect(failures).toEqual([{ eventId: 'pending-events', sessionId: 'unknown', outcome: 'retry-deferred', status: 409, category: 'recipient-set' }]);
    expect(JSON.stringify(failures)).not.toMatch(/recipient changed|message|secret|ciphertext/u);

    // Restart-recoverable: a later sync under a NEW recipient version re-encrypts and commits exactly once.
    store.dispose();
    const restarted = new BridgeStateStore(statePath);
    restarted.initializeEncryptedSpool('host-test', identityPath, 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
    expect(restarted.getInflightSessionUpload('session-test')).toBeDefined();
    expect(restarted.currentSessionRevision('session-test')).toBe(0);
    let firstPublish = true; let publishes2 = 0; let reconciles2 = 0; let reads2 = 0;
    const snapshot2 = { version: 1, hostId: 'host-test', recipientSetVersion: 2, recipients: [] };
    const client2 = {
      publishEncryptedSession: async (session: any) => {
        publishes2 += 1;
        if (firstPublish) { firstPublish = false; throw new RelayClientError(409, 'recipient changed', { error: 'e2e_recipient_set_changed' }); }
        expect(session.recipientSetVersion).toBe(2);
      },
      reconcileEncryptedSession: async () => { reconciles2 += 1; return false; },
      recipientSnapshot: async () => { reads2 += 1; return snapshot2; },
    };
    const resumed = createOrchestrator(restarted, client2 as any, { reconcileRecipients: () => [] } as any);
    expect(await resumed.publishRecipientChangeSnapshots(snapshot2, [])).toBe(true);
    expect({ publishes2, reconciles2, reads2 }).toEqual({ publishes2: 2, reconciles2: 1, reads2: 1 });
    expect(restarted.currentSessionRevision('session-test')).toBe(1);
    expect(restarted.getInflightSessionUpload('session-test')).toBeUndefined();
    expect(restarted.getRecipientSetVersion()).toBe(2);
    expect(restarted.getQuarantinedEventRecord('event-test')).toBeUndefined();
  });
});

describe('EncryptedUploadActions permanent Event conflict quarantine', () => {
  test('permanent conflict quarantines the Event with the exact category and preserves restart safety', async () => {
    const store = fixture(); const terminal = terminalSession();
    store.replaceDriverSessions('pi', [terminal]); store.queuePendingEvent(doneEvent(), terminal); store.setRecipientSetVersion(1);
    const sourceBefore = rawSpoolBytes(store, 'event-test');
    const failures: any[] = [];
    const client = {
      recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }),
      publishEncryptedEvent: async () => { throw new RelayClientError(409, 'stale', { reason: 'session_revision_stale' }); },
      reconcileEncryptedEvent: async () => ({ committed: false }),
    };
    const orchestrator = createOrchestrator(store, client as any, { reconcileRecipients: () => [] } as any, {
      eventFailure: (failure) => failures.push(failure),
    });
    expect(await orchestrator.flushPendingEvents()).toBe(0);
    const record = store.getQuarantinedEventRecord('event-test') as any;
    expect(record).toMatchObject({
      version: 2, eventId: 'event-test', sessionId: 'session-test', reasonCode: 'relay-permanent-conflict',
      sourceArchive: { encoding: 'base64url' }, inflightArchive: { encoding: 'base64url' },
    });
    expect(base64UrlDecode(record.sourceArchive.bytes, undefined, 'source archive')).toEqual(sourceBefore);
    expect(JSON.parse(new TextDecoder().decode(base64UrlDecode(record.inflightArchive.bytes, undefined, 'inflight archive'))))
      .toMatchObject({ version: 2, upload: { event: { eventId: 'event-test' }, session: { sessionId: 'session-test' } } });
    expect(failures).toEqual([{ eventId: 'event-test', sessionId: 'session-test', outcome: 'quarantined', status: 409, category: 'session-revision' }]);
    expect(store.peekPendingUploads()).toEqual([]);
    expect(store.getInflightEventUpload('event-test')).toBeUndefined();
  });

  test('a quarantine write failure defers and keeps the source and inflight retryable', async () => {
    const { statePath, identityPath, store } = durableFixture();
    store.dispose(); // release the runtime coordinator lock before the throwing subclass reuses statePath
    const terminal = terminalSession();
    let quarantineAttempts = 0; const failures: any[] = [];
    const client = {
      recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }),
      publishEncryptedEvent: async () => { throw new RelayClientError(409, 'stale', { reason: 'session_revision_stale' }); },
      reconcileEncryptedEvent: async () => ({ committed: false }),
    };
    const throwingQuarantine = new (class extends BridgeStateStore {
      quarantinePendingEventRaw(_descriptor: any, _reason: any, _inflight?: Uint8Array): boolean {
        quarantineAttempts += 1;
        throw new Error('injected quarantine write failure');
      }
    })(statePath);
    throwingQuarantine.initializeEncryptedSpool('host-test', identityPath, 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
    throwingQuarantine.replaceDriverSessions('pi', [terminal]); throwingQuarantine.queuePendingEvent(doneEvent(), terminal); throwingQuarantine.setRecipientSetVersion(1);
    const orchestrator = createOrchestrator(throwingQuarantine as any, client as any, { reconcileRecipients: () => [] } as any, {
      eventFailure: (failure) => failures.push(failure),
    });
    expect(await orchestrator.flushPendingEvents()).toBe(0);
    expect(quarantineAttempts).toBe(1);
    expect(failures).toEqual([{ eventId: 'event-test', sessionId: 'session-test', outcome: 'retry-deferred', status: 409, category: 'local-spool-record' }]);
    // Source and inflight evidence remain retryable: restart succeeds once the failure clears.
    throwingQuarantine.dispose();
    const restarted = new BridgeStateStore(statePath);
    restarted.initializeEncryptedSpool('host-test', identityPath, 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
    const okClient = {
      recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }),
      publishEncryptedEvent: async () => {},
    };
    expect(await createOrchestrator(restarted, okClient as any, { reconcileRecipients: () => [] } as any).flushPendingEvents()).toBe(1);
    expect(restarted.currentSessionRevision('session-test')).toBe(1);
    expect(restarted.getQuarantinedEventRecord('event-test')).toBeUndefined();
  });

  test('reconcile network error on a permanent conflict defers and preserves all evidence (never quarantines unknown state)', async () => {
    const store = fixture(); const terminal = terminalSession();
    store.replaceDriverSessions('pi', [terminal]); store.queuePendingEvent(doneEvent(), terminal); store.setRecipientSetVersion(1);
    const failures: any[] = [];
    const client = {
      recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }),
      publishEncryptedEvent: async () => { throw new RelayClientError(409, 'stale', { reason: 'session_revision_stale' }); },
      reconcileEncryptedEvent: async () => { throw new Error('relay unreachable'); },
    };
    const orchestrator = createOrchestrator(store, client as any, { reconcileRecipients: () => [] } as any, {
      eventFailure: (failure) => failures.push(failure),
    });
    expect(await orchestrator.flushPendingEvents()).toBe(0);
    // The Relay may have committed the Event; nothing may be deleted or dead-lettered.
    expect(store.getQuarantinedEventRecord('event-test')).toBeUndefined();
    expect(store.getInflightEventUpload('event-test')).toBeDefined();
    expect(store.peekPendingUploads().map((p) => p.event.eventId)).toEqual(['event-test']);
    expect(failures.some((f) => f.outcome === 'retry-deferred')).toBe(true);
  });

  test('refresh-retry permanent conflict reconciles exactly before quarantining', async () => {
    const store = fixture(); const terminal = terminalSession();
    store.replaceDriverSessions('pi', [terminal]); store.queuePendingEvent(doneEvent(), terminal); store.setRecipientSetVersion(1);
    let publishes = 0; let reconciles = 0;
    const client = {
      recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }),
      publishEncryptedEvent: async () => {
        publishes += 1;
        if (publishes === 1) throw new RelayClientError(409, 'recipient changed', { reason: 'e2e_recipient_set_changed' });
        throw new RelayClientError(409, 'stale', { reason: 'session_revision_stale' });
      },
      reconcileEncryptedEvent: async () => { reconciles += 1; return { committed: false }; },
    };
    const orchestrator = createOrchestrator(store, client as any, { reconcileRecipients: () => [] } as any);
    expect(await orchestrator.flushPendingEvents()).toBe(0);
    // Quarantine only after an exact reconcile proved uncommitted on BOTH conflicts.
    expect(reconciles).toBe(2);
    expect(store.getQuarantinedEventRecord('event-test')).toBeDefined();
  });

  test('refresh-retry reconcile error defers instead of quarantining', async () => {
    const store = fixture(); const terminal = terminalSession();
    store.replaceDriverSessions('pi', [terminal]); store.queuePendingEvent(doneEvent(), terminal); store.setRecipientSetVersion(1);
    let publishes = 0; let reconciles = 0;
    const client = {
      recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }),
      publishEncryptedEvent: async () => {
        publishes += 1;
        if (publishes === 1) throw new RelayClientError(409, 'recipient changed', { reason: 'e2e_recipient_set_changed' });
        throw new RelayClientError(409, 'stale', { reason: 'session_revision_stale' });
      },
      reconcileEncryptedEvent: async () => { reconciles += 1; if (reconciles === 1) return { committed: false }; throw new Error('relay unreachable'); },
    };
    const orchestrator = createOrchestrator(store, client as any, { reconcileRecipients: () => [] } as any);
    expect(await orchestrator.flushPendingEvents()).toBe(0);
    expect(reconciles).toBe(2);
    expect(store.getQuarantinedEventRecord('event-test')).toBeUndefined();
    expect(store.getInflightEventUpload('event-test')).toBeDefined();
  });
});

async function authoritativeOutcome() {
  const store = fixture();
  const session = terminalSession();
  store.replaceDriverSessions('pi', [session]);
  const initialSnapshot = { version: 1 as const, hostId: 'host-test', recipientSetVersion: 1, recipients: [] };
  const refreshedSnapshot = { ...initialSnapshot, recipientSetVersion: 2 };
  const trace: string[] = [];
  let publishes = 0;
  const relayClient = {
    publishEncryptedSession: async (upload: any) => {
      publishes += 1;
      trace.push(`publish:${upload.revision}:${upload.recipientSetVersion}`);
      if (publishes === 1) {
        throw new RelayClientError(409, 'recipient changed', { error: 'e2e_recipient_set_changed' });
      }
    },
    reconcileEncryptedSession: async (upload: any) => {
      trace.push(`reconcile:${upload.revision}:${upload.recipientSetVersion}`);
      return true;
    },
    recipientSnapshot: async () => {
      trace.push('recipient-snapshot');
      return refreshedSnapshot;
    },
  };
  const outcome = await createOrchestrator(store, relayClient)
    .publishAuthoritativeSnapshots(initialSnapshot, [], [session]);
  return {
    outcome: outcome.type === 'published'
      ? { ...outcome, revisions: [...outcome.revisions] }
      : outcome,
    trace,
    currentRevision: store.currentSessionRevision(session.sessionId),
    inflightPresent: store.getInflightSessionUpload(session.sessionId) !== undefined,
    recipientSetVersion: store.getRecipientSetVersion(),
  };
}

async function recipientChangeOutcome() {
  const store = fixture();
  const session = terminalSession();
  store.replaceDriverSessions('pi', [session]);
  const snapshot = { version: 1 as const, hostId: 'host-test', recipientSetVersion: 1, recipients: [] };
  const trace: string[] = [];
  const relayClient = {
    publishEncryptedSession: async (upload: any) => {
      trace.push(`publish:${upload.revision}:${upload.recipientSetVersion}`);
    },
  };
  const outcome = await createOrchestrator(store, relayClient)
    .publishRecipientChangeSnapshots(snapshot, []);
  return {
    outcome,
    trace,
    currentRevision: store.currentSessionRevision(session.sessionId),
    inflightPresent: store.getInflightSessionUpload(session.sessionId) !== undefined,
    recipientSetVersion: store.getRecipientSetVersion(),
  };
}

async function completionJournalOutcome() {
  const store = fixture();
  const session = terminalSession();
  store.replaceDriverSessions('pi', [session]);
  store.queuePendingEvent(doneEvent(), session);
  store.setRecipientSetVersion(1);
  const trace: string[] = [];
  const phases: string[] = [];
  const relayClient = {
    recipientSnapshot: async () => {
      trace.push('recipient-snapshot');
      return { version: 1 as const, hostId: 'host-test', recipientSetVersion: 1, recipients: [] };
    },
    publishEncryptedEvent: async () => { trace.push('publish-event'); },
  };
  const flushed = await createOrchestrator(store, relayClient, undefined, {
    eventCompletionStep: (phase, eventId) => phases.push(`${phase}:${eventId}`),
  }).flushPendingEvents();
  return {
    flushed,
    trace,
    phases,
    currentRevision: store.currentSessionRevision(session.sessionId),
    pendingCount: store.peekPendingUploads().length,
    inflightPresent: store.getInflightEventUpload('event-test') !== undefined,
    completionPresent: store.hasEventUploadCompletion('event-test'),
  };
}

async function quarantineOutcome() {
  const store = fixture();
  const session = terminalSession();
  store.replaceDriverSessions('pi', [session]);
  store.queuePendingEvent(doneEvent(), session);
  store.setRecipientSetVersion(1);
  const trace: string[] = [];
  const failures: any[] = [];
  const relayClient = {
    recipientSnapshot: async () => {
      trace.push('recipient-snapshot');
      return { version: 1 as const, hostId: 'host-test', recipientSetVersion: 1, recipients: [] };
    },
    publishEncryptedEvent: async () => {
      trace.push('publish-event');
      throw new RelayClientError(409, 'stale', { reason: 'session_revision_stale' });
    },
    reconcileEncryptedEvent: async () => {
      trace.push('reconcile-event');
      return { committed: false };
    },
  };
  const flushed = await createOrchestrator(store, relayClient, undefined, {
    eventFailure: (failure) => failures.push(failure),
  }).flushPendingEvents();
  const quarantined = store.getQuarantinedEventRecord('event-test') as any;
  return {
    flushed,
    trace,
    failures,
    quarantine: quarantined && {
      eventId: quarantined.eventId,
      sessionId: quarantined.sessionId,
      reasonCode: quarantined.reasonCode,
    },
    pendingCount: store.peekPendingUploads().length,
    inflightPresent: store.getInflightEventUpload('event-test') !== undefined,
  };
}

describe('createEncryptedUploadActions workflow invariants', () => {
  test('authoritative publication preserves recipient-conflict reconcile and revision ordering', async () => {
    expect(await authoritativeOutcome()).toEqual({
      outcome: { type: 'published', recipientSetVersion: 2, revisions: [['session-test', 2]] },
      trace: ['publish:1:1', 'reconcile:1:1', 'recipient-snapshot', 'publish:2:2'],
      currentRevision: 2,
      inflightPresent: false,
      recipientSetVersion: 2,
    });
  });

  test('recipient-change publication preserves its standalone commit behavior', async () => {
    expect(await recipientChangeOutcome()).toEqual({
      outcome: true,
      trace: ['publish:1:1'],
      currentRevision: 1,
      inflightPresent: false,
      recipientSetVersion: 1,
    });
  });

  test('Event flush preserves completion-journal hook ordering', async () => {
    expect(await completionJournalOutcome()).toEqual({
      flushed: 1,
      trace: ['recipient-snapshot', 'publish-event'],
      phases: [
        'journaled:event-test',
        'revision-committed:event-test',
        'inflight-removed:event-test',
        'source-removed:event-test',
        'journal-removed:event-test',
      ],
      currentRevision: 1,
      pendingCount: 0,
      inflightPresent: false,
      completionPresent: false,
    });
  });

  test('Event flush preserves permanent-conflict reconcile and quarantine behavior', async () => {
    expect(await quarantineOutcome()).toEqual({
      flushed: 0,
      trace: ['recipient-snapshot', 'publish-event', 'reconcile-event'],
      failures: [{
        eventId: 'event-test',
        sessionId: 'session-test',
        outcome: 'quarantined',
        status: 409,
        category: 'session-revision',
      }],
      quarantine: {
        eventId: 'event-test',
        sessionId: 'session-test',
        reasonCode: 'relay-permanent-conflict',
      },
      pendingCount: 0,
      inflightPresent: false,
    });
  });
});
