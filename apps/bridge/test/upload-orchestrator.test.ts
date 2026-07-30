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

describe('EncryptedUploadOrchestrator', () => {
  test('uploads a queued historical Event with the latest canonical Session snapshot', async () => {
    const root = join(tmpdir(), `bridge-upload-orchestrator-${Date.now()}`); roots.push(root); mkdirSync(root, { mode: 0o700 });
    const stateStore = new BridgeStateStore(join(root, 'state.json'));
    stateStore.initializeEncryptedSpool('host-test', join(root, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
    const workingSession = { sessionId: 'session-test', hostId: 'host-test', provider: 'pi', projectName: 'project', nameText: 'Session',
      latestActivityText: 'historical working activity', stateLabel: 'Working', status: 'working' as const, updatedAt: '2026-08-01T00:00:00.000Z' };
    stateStore.replaceDriverSessions('pi', [workingSession]);
    stateStore.queuePendingEvent({ eventId: 'event-working', hostId: 'host-test', sessionId: 'session-test', provider: 'pi', type: 'working', status: 'working',
      typeLabel: 'Working', assistantText: 'historical event content', createdAt: '2026-08-01T00:00:01.000Z' });
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
    expect(eventUploads[0].event).toMatchObject({ eventId: 'event-working', status: 'working' });
    expect(openMockedContent(eventUploads[0].event.content)).toEqual({ version: 1, assistantText: 'historical event content' });
    expect(eventUploads[0].session).toMatchObject({ sessionId: 'session-test', status: 'blocked', updatedAt: '2026-08-01T00:00:02.000Z', revision: 2 });
    expect(openMockedContent(eventUploads[0].session.content)).toEqual({ version: 1, projectName: 'project', nameText: 'Session', latestActivityText: 'latest blocked activity' });
    expect(sessionUploads.map((session) => ({ revision: session.revision, status: session.status }))).toEqual([{ revision: 1, status: 'blocked' }]);
  });
});
