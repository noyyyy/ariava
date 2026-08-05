import { afterEach, describe, expect, mock, test } from 'bun:test';
import { mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { base64UrlDecode } from '@ariava/protocol';

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

function openMockedContent(content: { ciphertext: string }): unknown {
  const ciphertext = base64UrlDecode(content.ciphertext, undefined, 'test ciphertext');
  return JSON.parse(new TextDecoder().decode(ciphertext.slice(0, -16)));
}

function recipient(index: number) {
  return {
    linkId: `link-${index}`, linkGeneration: 1, watchDeviceId: `watch-${index}`, epoch: index, state: 'active' as const, transcriptDigest: 'A'.repeat(43),
    watchBinding: { version: 1 as const, entityType: 'watch' as const, entityId: `watch-${index}`, identityKeyId: `key-${index}`,
      encryptionKeyId: `ekey-watch-${index}`, publicKey: 'A'.repeat(43), sequence: 1, issuedAt: '2026-08-01T00:00:00.000Z', bindingSignature: 'B'.repeat(86) },
  };
}

describe('EncryptedUploadOrchestrator', () => {
  test('uploads a queued historical Event with the latest canonical Session snapshot', async () => {
    const root = join(tmpdir(), `bridge-upload-orchestrator-${Date.now()}`); roots.push(root); mkdirSync(root, { mode: 0o700 });
    const stateStore = new BridgeStateStore(join(root, 'state.json'));
    stateStore.initializeEncryptedSpool('host-test', join(root, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
    const workingSession = { sessionId: 'session-test', hostId: 'host-test', provider: 'pi', projectName: 'project', nameText: 'Session',
      latestActivityText: 'historical working activity', stateLabel: 'Working', status: 'working' as const, updatedAt: '2026-08-01T00:00:00.000Z' };
    stateStore.replaceDriverSessions('pi', [workingSession]);
    stateStore.queuePendingEvent({ eventId: 'event-working', hostId: 'host-test', sessionId: 'session-test', provider: 'pi', type: 'blocked', status: 'blocked',
      typeLabel: 'Blocked', agentText: 'historical event content', createdAt: '2026-08-01T00:00:01.000Z' });
    stateStore.replaceDriverSessions('pi', [{ ...workingSession, latestActivityText: 'latest blocked activity', stateLabel: 'Blocked', status: 'blocked', updatedAt: '2026-08-01T00:00:02.000Z' }]);

    const eventUploads: any[] = []; const sessionUploads: any[] = [];
    const client = {
      recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }),
      publishEncryptedSession: async (session: any) => { sessionUploads.push(session); },
      publishEncryptedEvent: async (event: any, session: any) => { eventUploads.push({ event, session }); },
    };
    const keyring = { reconcileRecipients: () => [] };
    const identity = { version: 1, hostId: 'host-test', encryptionKeyId: 'ekey-test', publicKey: '', privateKeyPkcs8: new Uint8Array(), sequence: 1, createdAt: '2026-08-01T00:00:00.000Z' };

    const flushed = await new EncryptedUploadOrchestrator(stateStore, client as any, identity, keyring as any).flushPendingEvents();

    expect(flushed).toBe(1);
    expect(eventUploads).toHaveLength(1);
    expect(eventUploads[0].event).toMatchObject({ eventId: 'event-working', status: 'blocked', notificationPreviews: [] });
    expect(openMockedContent(eventUploads[0].event.content)).toEqual({ version: 1, agentText: 'historical event content' });
    expect(eventUploads[0].session).toMatchObject({ sessionId: 'session-test', status: 'blocked', updatedAt: '2026-08-01T00:00:02.000Z', revision: 2 });
    expect(openMockedContent(eventUploads[0].session.content)).toEqual({ version: 1, projectName: 'project', nameText: 'Session', latestActivityText: 'latest blocked activity' });
    expect(sessionUploads.map((session) => ({ revision: session.revision, status: session.status }))).toEqual([{ revision: 1, status: 'blocked' }]);
  });
  test('rebuilds stale inflight event before its first publish under current recipient authority', async () => {
    const root = join(tmpdir(), `bridge-upload-stale-${Date.now()}`); roots.push(root); mkdirSync(root, { mode: 0o700 });
    const stateStore = new BridgeStateStore(join(root, 'state.json'));
    stateStore.initializeEncryptedSpool('host-test', join(root, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
    const session = { sessionId: 'session-test', hostId: 'host-test', provider: 'pi', projectName: 'secret-project', nameText: 'Session',
      stateLabel: 'Blocked', status: 'blocked' as const, updatedAt: '2026-08-01T00:00:00.000Z' };
    stateStore.replaceDriverSessions('pi', [session]);
    stateStore.queuePendingEvent({ eventId: 'event-test', hostId: 'host-test', sessionId: 'session-test', provider: 'pi', type: 'blocked', status: 'blocked',
      typeLabel: 'Blocked', agentText: 'secret-agent-text', createdAt: '2026-08-01T00:00:01.000Z' });
    let version = 1; const published: any[] = []; let reject = true;
    const client = {
      recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: version, recipients: [] }),
      publishEncryptedSession: async () => {},
      publishEncryptedEvent: async (event: any, uploadedSession: any) => { published.push({ event, session: uploadedSession }); if (reject) throw new Error('offline'); },
    };
    const keyring = { reconcileRecipients: () => version === 1 ? [recipient(1)] : [recipient(2)] };
    const identity = { version: 1, hostId: 'host-test', encryptionKeyId: 'ekey-test', publicKey: '', privateKeyPkcs8: new Uint8Array(), sequence: 1, createdAt: '2026-08-01T00:00:00.000Z' };
    const orchestrator = new EncryptedUploadOrchestrator(stateStore, client as any, identity, keyring as any);
    expect(await orchestrator.flushPendingEvents()).toBe(0);
    published.length = 0; version = 2; reject = false;
    expect(await orchestrator.flushPendingEvents()).toBe(1);
    expect(published).toHaveLength(1);
    expect(published[0].event.recipientSetVersion).toBe(2);
    expect(published[0].session.recipientSetVersion).toBe(2);
    expect(published[0].event.notificationPreviews.map((item: any) => item.watchDeviceId)).toEqual(['watch-2']);
    expect(JSON.stringify(published[0])).not.toContain('watch-1');
  });

  test('upload path emits only two opaque eligible recipient previews and no selected plaintext', async () => {
    const root = join(tmpdir(), `bridge-upload-preview-${Date.now()}`); roots.push(root); mkdirSync(root, { mode: 0o700 });
    const stateStore = new BridgeStateStore(join(root, 'state.json'));
    stateStore.initializeEncryptedSpool('host-test', join(root, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
    stateStore.replaceDriverSessions('pi', [{ sessionId: 'session-test', hostId: 'host-test', provider: 'pi', projectName: 'secret-project', nameText: 'Session',
      stateLabel: 'Blocked', status: 'blocked', updatedAt: '2026-08-01T00:00:00.000Z' }]);
    stateStore.queuePendingEvent({ eventId: 'event-test', hostId: 'host-test', sessionId: 'session-test', provider: 'pi', type: 'blocked', status: 'blocked',
      typeLabel: 'Blocked', agentText: 'secret-agent-text', createdAt: '2026-08-01T00:00:01.000Z' });
    let body = '';
    const client = { recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 3, recipients: [] }),
      publishEncryptedSession: async () => {}, publishEncryptedEvent: async (event: any, session: any) => { body = JSON.stringify({ event, session }); } };
    const eligible = [recipient(1), recipient(2)];
    const keyring = { reconcileRecipients: () => eligible };
    const identity = { version: 1, hostId: 'host-test', encryptionKeyId: 'ekey-test', publicKey: '', privateKeyPkcs8: new Uint8Array(), sequence: 1, createdAt: '2026-08-01T00:00:00.000Z' };
    expect(await new EncryptedUploadOrchestrator(stateStore, client as any, identity, keyring as any).flushPendingEvents()).toBe(1);
    const uploaded = JSON.parse(body);
    expect(uploaded.event.notificationPreviews.map((item: any) => item.watchDeviceId)).toEqual(['watch-1', 'watch-2']);
    expect(new Set(uploaded.event.notificationPreviews.map((item: any) => item.content.contentId)).size).toBe(2);
    expect(body).not.toContain('secret-project'); expect(body).not.toContain('secret-agent-text'); expect(body).not.toContain('Ariava needs your attention.');
  });

  test('oversized preview construction does not block encrypted event upload', async () => {
    const root = join(tmpdir(), `bridge-upload-oversized-${Date.now()}`); roots.push(root); mkdirSync(root, { mode: 0o700 });
    const stateStore = new BridgeStateStore(join(root, 'state.json'));
    stateStore.initializeEncryptedSpool('host-test', join(root, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
    stateStore.replaceDriverSessions('pi', [{ sessionId: 'session-test', hostId: 'host-test', provider: 'pi', projectName: '界'.repeat(100), nameText: 'Session',
      stateLabel: 'Blocked', status: 'blocked', updatedAt: '2026-08-01T00:00:00.000Z' }]);
    stateStore.queuePendingEvent({ eventId: 'event-test', hostId: 'host-test', sessionId: 'session-test', provider: 'pi', type: 'blocked', status: 'blocked',
      typeLabel: 'Blocked', agentText: 'publish me', createdAt: '2026-08-01T00:00:01.000Z' });
    const published: any[] = []; const client = { recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }),
      publishEncryptedSession: async () => {}, publishEncryptedEvent: async (event: any) => { published.push(event); } };
    const identity = { version: 1, hostId: 'host-test', encryptionKeyId: 'ekey-test', publicKey: '', privateKeyPkcs8: new Uint8Array(), sequence: 1, createdAt: '2026-08-01T00:00:00.000Z' };
    expect(await new EncryptedUploadOrchestrator(stateStore, client as any, identity, { reconcileRecipients: () => [recipient(1)] } as any).flushPendingEvents()).toBe(1);
    expect(published).toHaveLength(1); expect(published[0].notificationPreviews).toEqual([]);
  });

  test('keeps a queued Event and its inflight upload after a transient failure', async () => {
    const root = join(tmpdir(), `bridge-upload-retry-${Date.now()}`); roots.push(root); mkdirSync(root, { mode: 0o700 });
    const stateStore = new BridgeStateStore(join(root, 'state.json'));
    stateStore.initializeEncryptedSpool('host-test', join(root, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
    stateStore.setRecipientSetVersion(1);
    stateStore.replaceDriverSessions('pi', [{ sessionId: 'session-retry', hostId: 'host-test', provider: 'pi', projectName: 'project',
      nameText: 'Retry', stateLabel: 'Done', status: 'done', updatedAt: '2026-08-01T00:00:00.000Z' }]);
    stateStore.queuePendingEvent({ eventId: 'event-retry', hostId: 'host-test', sessionId: 'session-retry', provider: 'pi',
      type: 'done', status: 'done', typeLabel: 'Done', agentText: 'retry later', createdAt: '2026-08-01T00:00:01.000Z' });
    const failures: any[] = [];
    const client = {
      recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }),
      publishEncryptedEvent: async () => { throw new Error('network unavailable'); },
    };
    const orchestrator = new EncryptedUploadOrchestrator(stateStore, client as any,
      { version: 1, hostId: 'host-test', encryptionKeyId: 'ekey-test', publicKey: '', privateKeyPkcs8: new Uint8Array(), sequence: 1, createdAt: '2026-08-01T00:00:00.000Z' },
      { reconcileRecipients: () => [] } as any, { eventFailure: (failure: any) => failures.push(failure) });

    expect(await orchestrator.flushPendingEvents()).toBe(0);
    expect(stateStore.peekPendingUploads().map(({ event }) => event.eventId)).toEqual(['event-retry']);
    expect(stateStore.getInflightEventUpload('event-retry')).toBeDefined();
    expect(failures).toEqual([{ eventId: 'event-retry', sessionId: 'session-retry', outcome: 'retry-deferred', category: 'network' }]);
  });

  test('quarantines a permanently conflicting head Event without losing it and continues the queue', async () => {
    const root = join(tmpdir(), `bridge-upload-poison-${Date.now()}`); roots.push(root); mkdirSync(root, { mode: 0o700 });
    const stateStore = new BridgeStateStore(join(root, 'state.json'));
    stateStore.initializeEncryptedSpool('host-test', join(root, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
    stateStore.setRecipientSetVersion(1);
    const sessions = [
      { sessionId: 'session-poison', hostId: 'host-test', provider: 'pi', projectName: 'project', nameText: 'Poison', stateLabel: 'Done', status: 'done' as const, updatedAt: '2026-08-01T00:00:00.000Z' },
      { sessionId: 'session-good', hostId: 'host-test', provider: 'pi', projectName: 'project', nameText: 'Good', stateLabel: 'Done', status: 'done' as const, updatedAt: '2026-08-01T00:00:00.000Z' },
    ];
    stateStore.replaceDriverSessions('pi', sessions);
    stateStore.queuePendingEvent({ eventId: 'event-poison', hostId: 'host-test', sessionId: 'session-poison', provider: 'pi',
      type: 'done', status: 'done', typeLabel: 'Done', agentText: 'old event', createdAt: '2026-08-01T00:00:01.000Z' });
    stateStore.queuePendingEvent({ eventId: 'event-good', hostId: 'host-test', sessionId: 'session-good', provider: 'pi',
      type: 'done', status: 'done', typeLabel: 'Done', agentText: 'new event', createdAt: '2026-08-01T00:00:02.000Z' });
    const snapshot = async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] });
    const identity = { version: 1, hostId: 'host-test', encryptionKeyId: 'ekey-test', publicKey: '', privateKeyPkcs8: new Uint8Array(), sequence: 1, createdAt: '2026-08-01T00:00:00.000Z' };
    const keyring = { reconcileRecipients: () => [] };
    const uploads: string[] = []; const failures: any[] = [];
    const client = {
      recipientSnapshot: snapshot,
      publishEncryptedEvent: async (event: any) => {
        uploads.push(event.eventId);
        if (event.eventId === 'event-poison') throw new RelayClientError(409, 'session revision stale', { error: 'session_revision_stale' });
      },
      reconcileEncryptedEvent: async () => ({ committed: false }),
    };
    const flushed = await new EncryptedUploadOrchestrator(stateStore, client as any, identity, keyring as any,
      { eventFailure: (failure: any) => failures.push(failure) }).flushPendingEvents();

    expect(flushed).toBe(1);
    expect(uploads).toEqual(['event-poison', 'event-good']);
    expect(stateStore.peekPendingUploads()).toEqual([]);
    expect(stateStore.getInflightEventUpload('event-poison')).toBeUndefined();
    expect(stateStore.getQuarantinedEventRecord('event-poison')).toMatchObject({
      version: 1, eventId: 'event-poison', sessionId: 'session-poison', reason: 'session_revision_stale',
      source: { event: { eventId: 'event-poison', agentText: 'old event' } },
      inflight: { event: { eventId: 'event-poison' } },
    });
    expect(failures).toEqual([{ eventId: 'event-poison', sessionId: 'session-poison', outcome: 'quarantined', status: 409, category: 'session-revision' }]);
  });

  test('does not quarantine transient HTTP failures carrying conflict-like reasons', async () => {
    for (const status of [429, 500, 503]) {
      const root = join(tmpdir(), `bridge-upload-http-${status}-${Date.now()}`); roots.push(root); mkdirSync(root, { mode: 0o700 });
      const stateStore = new BridgeStateStore(join(root, 'state.json'));
      stateStore.initializeEncryptedSpool('host-test', join(root, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
      stateStore.setRecipientSetVersion(1);
      stateStore.replaceDriverSessions('pi', [{ sessionId: `session-${status}`, hostId: 'host-test', provider: 'pi', projectName: 'project',
        nameText: 'Retry', stateLabel: 'Done', status: 'done', updatedAt: '2026-08-01T00:00:00.000Z' }]);
      stateStore.queuePendingEvent({ eventId: `event-${status}`, hostId: 'host-test', sessionId: `session-${status}`, provider: 'pi',
        type: 'done', status: 'done', typeLabel: 'Done', agentText: 'retry later', createdAt: '2026-08-01T00:00:01.000Z' });
      const client = {
        recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }),
        publishEncryptedEvent: async () => { throw new RelayClientError(status, 'temporary failure', { error: 'session_revision_gap' }); },
      };
      expect(await new EncryptedUploadOrchestrator(stateStore, client as any,
        { version: 1, hostId: 'host-test', encryptionKeyId: 'ekey-test', publicKey: '', privateKeyPkcs8: new Uint8Array(), sequence: 1, createdAt: '2026-08-01T00:00:00.000Z' },
        { reconcileRecipients: () => [] } as any).flushPendingEvents()).toBe(0);
      expect(stateStore.peekPendingUploads().map(({ event }) => event.eventId)).toEqual([`event-${status}`]);
      expect(stateStore.getInflightEventUpload(`event-${status}`)).toBeDefined();
      expect(stateStore.getQuarantinedEventRecord(`event-${status}`)).toBeUndefined();
    }
  });

  test('quarantines when recipient refresh retry exposes a permanent revision conflict', async () => {
    const root = join(tmpdir(), `bridge-upload-recipient-stale-${Date.now()}`); roots.push(root); mkdirSync(root, { mode: 0o700 });
    const stateStore = new BridgeStateStore(join(root, 'state.json'));
    stateStore.initializeEncryptedSpool('host-test', join(root, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
    stateStore.setRecipientSetVersion(1);
    stateStore.replaceDriverSessions('pi', [{ sessionId: 'session-recipient-stale', hostId: 'host-test', provider: 'pi', projectName: 'project',
      nameText: 'Recipient stale', stateLabel: 'Done', status: 'done', updatedAt: '2026-08-01T00:00:00.000Z' }]);
    stateStore.queuePendingEvent({ eventId: 'event-recipient-stale', hostId: 'host-test', sessionId: 'session-recipient-stale', provider: 'pi',
      type: 'done', status: 'done', typeLabel: 'Done', agentText: 'preserve me', createdAt: '2026-08-01T00:00:01.000Z' });
    let snapshotVersion = 1; let attempts = 0;
    const client = {
      recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: snapshotVersion, recipients: [] }),
      publishEncryptedEvent: async () => {
        attempts += 1;
        if (attempts === 1) { snapshotVersion = 2; throw new RelayClientError(409, 'recipient changed', { error: 'e2e_recipient_set_changed' }); }
        throw new RelayClientError(409, 'session stale', { error: 'session_revision_stale' });
      },
      reconcileEncryptedEvent: async () => ({ committed: false }),
    };
    expect(await new EncryptedUploadOrchestrator(stateStore, client as any,
      { version: 1, hostId: 'host-test', encryptionKeyId: 'ekey-test', publicKey: '', privateKeyPkcs8: new Uint8Array(), sequence: 1, createdAt: '2026-08-01T00:00:00.000Z' },
      { reconcileRecipients: () => [] } as any).flushPendingEvents()).toBe(0);
    expect(attempts).toBe(2);
    expect(stateStore.peekPendingUploads()).toEqual([]);
    expect(stateStore.getQuarantinedEventRecord('event-recipient-stale')).toMatchObject({
      reason: 'session_revision_stale', source: { event: { eventId: 'event-recipient-stale', agentText: 'preserve me' } },
    });
  });

  test('classifies encrypted content conflicts as quarantined event-content records', async () => {
    const root = join(tmpdir(), `bridge-upload-content-conflict-${Date.now()}`); roots.push(root); mkdirSync(root, { mode: 0o700 });
    const stateStore = new BridgeStateStore(join(root, 'state.json'));
    stateStore.initializeEncryptedSpool('host-test', join(root, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
    stateStore.setRecipientSetVersion(1);
    stateStore.replaceDriverSessions('pi', [{ sessionId: 'session-content', hostId: 'host-test', provider: 'pi', projectName: 'project',
      nameText: 'Content conflict', stateLabel: 'Done', status: 'done', updatedAt: '2026-08-01T00:00:00.000Z' }]);
    stateStore.queuePendingEvent({ eventId: 'event-content', hostId: 'host-test', sessionId: 'session-content', provider: 'pi',
      type: 'done', status: 'done', typeLabel: 'Done', agentText: 'preserve content', createdAt: '2026-08-01T00:00:01.000Z' });
    const failures: any[] = [];
    const client = {
      recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }),
      publishEncryptedEvent: async () => { throw new RelayClientError(409, 'content conflict', { error: 'encrypted event conflict' }); },
      reconcileEncryptedEvent: async () => ({ committed: false }),
    };
    expect(await new EncryptedUploadOrchestrator(stateStore, client as any,
      { version: 1, hostId: 'host-test', encryptionKeyId: 'ekey-test', publicKey: '', privateKeyPkcs8: new Uint8Array(), sequence: 1, createdAt: '2026-08-01T00:00:00.000Z' },
      { reconcileRecipients: () => [] } as any, { eventFailure: (failure: any) => failures.push(failure) }).flushPendingEvents()).toBe(0);
    expect(stateStore.getQuarantinedEventRecord('event-content')).toMatchObject({ source: { event: { agentText: 'preserve content' } } });
    expect(failures).toEqual([{ eventId: 'event-content', sessionId: 'session-content', outcome: 'quarantined', status: 409, category: 'event-content' }]);
  });

  test('keeps source and inflight records when encrypted quarantine persistence fails', async () => {
    const root = join(tmpdir(), `bridge-upload-quarantine-failure-${Date.now()}`); roots.push(root); mkdirSync(root, { mode: 0o700 });
    const stateStore = new BridgeStateStore(join(root, 'state.json'));
    let keyUnavailable = false;
    const keyStore = { loadOrCreate: () => { if (keyUnavailable) throw new Error('spool key unavailable'); return new Uint8Array(32).fill(7); } };
    stateStore.initializeEncryptedSpool('host-test', join(root, 'identity.json'), 'linux', keyStore);
    stateStore.setRecipientSetVersion(1);
    stateStore.replaceDriverSessions('pi', [{ sessionId: 'session-quarantine-failure', hostId: 'host-test', provider: 'pi', projectName: 'project',
      nameText: 'Quarantine failure', stateLabel: 'Done', status: 'done', updatedAt: '2026-08-01T00:00:00.000Z' }]);
    stateStore.queuePendingEvent({ eventId: 'event-quarantine-failure', hostId: 'host-test', sessionId: 'session-quarantine-failure', provider: 'pi',
      type: 'done', status: 'done', typeLabel: 'Done', agentText: 'must remain', createdAt: '2026-08-01T00:00:01.000Z' });
    const client = {
      recipientSnapshot: async () => ({ version: 1, hostId: 'host-test', recipientSetVersion: 1, recipients: [] }),
      publishEncryptedEvent: async () => { keyUnavailable = true; throw new RelayClientError(409, 'session stale', { error: 'session_revision_stale' }); },
      reconcileEncryptedEvent: async () => ({ committed: false }),
    };
    expect(await new EncryptedUploadOrchestrator(stateStore, client as any,
      { version: 1, hostId: 'host-test', encryptionKeyId: 'ekey-test', publicKey: '', privateKeyPkcs8: new Uint8Array(), sequence: 1, createdAt: '2026-08-01T00:00:00.000Z' },
      { reconcileRecipients: () => [] } as any).flushPendingEvents()).toBe(0);
    keyUnavailable = false;
    expect(stateStore.peekPendingUploads().map(({ event }) => event.eventId)).toEqual(['event-quarantine-failure']);
    expect(stateStore.getInflightEventUpload('event-quarantine-failure')).toBeDefined();
    expect(stateStore.getQuarantinedEventRecord('event-quarantine-failure')).toBeUndefined();
  });
});
