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

});
