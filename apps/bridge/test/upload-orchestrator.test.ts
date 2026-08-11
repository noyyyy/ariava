import { afterEach, describe, expect, mock, test } from 'bun:test';
import { mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { base64UrlDecode, type CanonicalEvent, type CanonicalSessionState } from '@ariava/protocol';

mock.module('../src/e2e/node-crypto', () => ({
  chachaPolySeal: (_key: Uint8Array, plaintext: Uint8Array) => ({ nonce: new Uint8Array(12).fill(1), ciphertext: new Uint8Array([...plaintext, ...new Uint8Array(16)]) }),
  chachaPolyOpen: (_key: Uint8Array, _nonce: Uint8Array, ciphertext: Uint8Array) => ciphertext.slice(0, -16),
  generateX25519KeyMaterial: () => ({ privateKeyPkcs8: new Uint8Array(48).fill(2), publicKeyRaw: new Uint8Array(32).fill(3) }),
  x25519SharedSecret: () => new Uint8Array(32).fill(4),
  hkdfSha256: () => new Uint8Array(32).fill(5),
}));

const { EncryptedUploadOrchestrator } = await import('../src/e2e/upload-orchestrator');
const { BridgeStateStore } = await import('../src/state-store');
const { RelayClientError } = await import('../src/relay-client');

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

function fixture() {
  const root = join(tmpdir(), `bridge-upload-${Date.now()}-${roots.length}`); roots.push(root); mkdirSync(root, { mode: 0o700 });
  const store = new BridgeStateStore(join(root, 'state.json'));
  store.initializeEncryptedSpool('host-test', join(root, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
  return store;
}

function terminalSession(overrides: Partial<CanonicalSessionState> = {}): CanonicalSessionState {
  return {
    sessionId: 'session-test', hostId: 'host-test', provider: 'pi', projectName: 'secret-project', nameText: 'Session',
    latestActivityText: 'terminal activity', workingDirectory: '/secret/project', hbaseSessionKey: 'hbase-secret',
    harnessProvider: 'pi', status: 'idle', updatedAt: '2026-08-07T00:00:01.000Z',
    lastEventId: 'event-test', ...overrides,
  };
}

function doneEvent(overrides: Partial<CanonicalEvent> = {}): CanonicalEvent {
  return {
    eventId: 'event-test', hostId: 'host-test', sessionId: 'session-test', provider: 'pi', type: 'done', status: 'idle',
    agentText: 'terminal activity', projectName: 'secret-project',
    workingDirectory: '/secret/project', hbaseSessionKey: 'hbase-secret', harnessProvider: 'pi',
    createdAt: '2026-08-07T00:00:01.000Z', ...overrides,
  } as CanonicalEvent;
}

function needHumanEvent(): CanonicalEvent {
  return {
    ...doneEvent(), type: 'need_human', status: 'need_human',
    needHuman: { reason: 'error', error: { kind: 'provider_failure', message: 'Sanitized provider failure.', providerCode: 'E_PROVIDER', retryExhausted: true } },
  };
}

function recipient(index: number) {
  return {
    linkId: `link-${index}`, linkGeneration: 1, watchDeviceId: `watch-${index}`, epoch: index, state: 'active' as const,
    transcriptDigest: 'A'.repeat(43),
    watchBinding: { version: 1 as const, entityType: 'watch' as const, entityId: `watch-${index}`,
      identityKeyId: `key-${index}`, encryptionKeyId: `ekey-watch-${index}`, publicKey: 'A'.repeat(43),
      sequence: 1, createdAt: '2026-08-01T00:00:00.000Z', bindingSignature: 'B'.repeat(86) },
  };
}

const identity = { version: 1, hostId: 'host-test', encryptionKeyId: 'ekey-test', publicKey: '',
  privateKeyPkcs8: new Uint8Array(), sequence: 1, createdAt: '2026-08-01T00:00:00.000Z' };

function openMockedContent(content: { ciphertext: string }): any {
  const ciphertext = base64UrlDecode(content.ciphertext, undefined, 'test ciphertext');
  return JSON.parse(new TextDecoder().decode(ciphertext.slice(0, -16)));
}

describe('EncryptedUploadOrchestrator canonical Event binding', () => {
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
    const flushed = await new EncryptedUploadOrchestrator(store, client as any, identity, { reconcileRecipients: () => [] } as any).flushPendingEvents();
    expect(flushed).toBe(1);
    expect(uploads[0].event).toMatchObject({ type: 'done', status: 'idle', content: { payloadKind: 'event-content-v2' } });
    expect(uploads[0].session).toMatchObject({ status: 'idle', updatedAt: terminal.updatedAt, lastEventId: 'event-test', content: { payloadKind: 'session-content-v2' } });
    expect(openMockedContent(uploads[0].session.content)).toMatchObject({ version: 2, latestActivityText: 'terminal activity' });
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
    expect(await new EncryptedUploadOrchestrator(store, client as any, identity, keyring as any).flushPendingEvents()).toBe(1);
    const retried = uploads[1];
    expect(retried.event).toMatchObject({ type: 'need_human', status: 'need_human', recipientSetVersion: 2 });
    expect(retried.session).toMatchObject({ status: 'need_human', lastEventId: 'event-test', recipientSetVersion: 2 });
    expect(openMockedContent(retried.event.content)).toMatchObject({
      version: 2, needHuman: { reason: 'error', error: { providerCode: 'E_PROVIDER', retryExhausted: true } },
    });
    expect(retried.event.notificationPreviews[0]).toMatchObject({ eventType: 'need_human', content: { payloadKind: 'notification-preview-v2' } });
  });

  test('transient retry preserves one inflight v2 tuple rather than rebuilding classification', async () => {
    const store = fixture(); const terminal = terminalSession();
    store.replaceDriverSessions('pi', [terminal]); store.queuePendingEvent(doneEvent(), terminal); store.setRecipientSetVersion(1);
    const published: any[] = []; let offline = true;
    const client = {
      recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }),
      publishEncryptedEvent: async (event: any, session: any) => { published.push({ event, session }); if (offline) throw new Error('offline'); },
    };
    const orchestrator = new EncryptedUploadOrchestrator(store, client as any, identity, { reconcileRecipients: () => [] } as any);
    expect(await orchestrator.flushPendingEvents()).toBe(0);
    const inflight = store.getInflightEventUpload('event-test');
    offline = false;
    expect(await orchestrator.flushPendingEvents()).toBe(1);
    expect(published[1]).toEqual(inflight);
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
    expect(await new EncryptedUploadOrchestrator(store, client as any, identity, { reconcileRecipients: () => [] } as any).flushPendingEvents()).toBe(1);
    expect({ recipientReads, snapshotUploads, eventUploads }).toEqual({ recipientReads: 1, snapshotUploads: 1, eventUploads: 1 });
  });
});
