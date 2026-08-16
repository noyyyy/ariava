import { describe, expect, test } from 'bun:test';
import {
  contentSha256,
  type CanonicalRequestInput,
  type CommandReceiptEnvelopeV1,
  type EncryptedCommandEnvelopeV1,
  type SignedRequestHeaders,
} from '@ariava/protocol';
import { RelayClient, RelayTransportError } from '../src/relay-client';
import type { HostRequestSigner } from '../src/identity';

const emptySignature = 'A'.repeat(86);
const hostId = `host_${'A'.repeat(43)}`;
const watchId = `watch_${'C'.repeat(43)}`;
const sessionId = `session_${'D'.repeat(43)}`;

class RecordingSigner implements HostRequestSigner {
  entityId = hostId;
  keyId = `key_${'B'.repeat(43)}`;
  inputs: CanonicalRequestInput[] = [];
  sign = async () => emptySignature;
  async signRequest(input: CanonicalRequestInput): Promise<SignedRequestHeaders> {
    this.inputs.push(input);
    return {
      'x-ariava-entity-id': this.entityId, 'x-ariava-key-id': this.keyId,
      'x-ariava-timestamp': input.timestamp, 'x-ariava-nonce': input.nonce,
      'x-ariava-content-sha256': input.contentSha256, 'x-ariava-signature': emptySignature,
    };
  }
}

const enrollment = { hostId, keyId: `key_${'B'.repeat(43)}`, algorithm: 'Ed25519', publicKey: 'A'.repeat(43), hostName: 'Host', platform: 'linux', bridgeVersion: '1.0.0' } as const;
const metadata = { hostName: 'Host', platform: 'linux', bridgeVersion: '1.0.0' } as const;
const event = { eventId: 'evt_1', hostId, sessionId, provider: 'pi', type: 'done', status: 'idle', agentText: 'Finished', createdAt: '2026-07-15T00:00:00.000Z' } as any;
const session = { sessionId, hostId, provider: 'pi', projectName: 'p', nameText: 'n', status: 'idle', updatedAt: '2026-07-15T00:00:00.000Z' } as any;
const snapshot = { hostId, revision: 1, observedAt: '2026-07-15T00:00:00.000Z', recipientSetVersion: 1, sessions: [{ sessionId, sessionRevision: 1 }] } as any;
const encryptedCommand = {
  commandId: 'cmd_encrypted', hostId, sessionId, type: 'interrupt', issuedAt: '2026-07-15T00:00:00.000Z',
  expiresAt: '2026-07-15T00:05:00.000Z', nonce: 'nonce_encrypted', watchDeviceId: watchId, linkId: 'link_test',
  linkGeneration: 1, epoch: 1, payload: {
    content: { version: 1, suite: 'x25519-hkdf-sha256-chachapoly-v1', contentId: 'content_command',
      payloadKind: 'interrupt-content-v1', nonce: 'A'.repeat(16), ciphertext: 'A'.repeat(67) },
    keyWrap: { version: 1, suite: 'x25519-hkdf-sha256-chachapoly-v1', contentId: 'content_command',
      linkId: 'link_test', linkGeneration: 1, epoch: 1, senderEncryptionKeyId: `ekey_${'C'.repeat(43)}`,
      recipientEncryptionKeyId: `ekey_${'D'.repeat(43)}`, nonce: 'B'.repeat(16), ciphertext: 'E'.repeat(64) },
  },
} as const satisfies EncryptedCommandEnvelopeV1;
const linkId = 'link_test';
const confirmation = { linkId, linkGeneration: 1, epoch: 1, transcriptDigest: 'A'.repeat(43), confirmationProof: 'B'.repeat(43) };
const activation = { linkId, linkGeneration: 1, epoch: 1, transcriptDigest: 'A'.repeat(43), peerRole: 'watch', peerProofDigest: 'C'.repeat(43), activatedAt: '2026-07-20T00:00:00.000Z' } as const;
const encryptedUpload = { event: { encrypted: true, notificationPreviews: [{ watchDeviceId: watchId, content: { ciphertext: 'opaque' }, keyWrap: { ciphertext: 'opaque-wrap' } }] }, session: { encrypted: true } } as any;

const linkedWatch = {
  watchDeviceId: watchId,
  pairedAt: '2026-07-15T00:00:00.000Z',
  lastSeenAt: '2026-07-15T00:00:00.000Z',
  linkGeneration: 7,
};
const cases: Array<{ name: string; method: string; path: string; body?: unknown; invoke(client: RelayClient): Promise<unknown> }> = [
  { name: 'enroll', method: 'POST', path: '/v2/bridge/enroll', body: enrollment, invoke: (c) => c.enrollHost(enrollment) },
  { name: 'metadata update', method: 'PUT', path: '/v2/bridge/registration', body: metadata, invoke: (c) => c.updateHost(metadata) },
  { name: 'heartbeat', method: 'PUT', path: '/v2/bridge/registration', body: metadata, invoke: (c) => c.heartbeat(metadata) },
  { name: 'pair', method: 'POST', path: '/v2/bridge/pair-watch', body: { pairingCode: 'PEYX7K' }, invoke: (c) => c.pairWatch('peyx7k') },
  { name: 'list watches', method: 'GET', path: '/v2/bridge/watches', invoke: (c) => c.listWatches() },
  { name: 'remove watch', method: 'DELETE', path: `/v2/bridge/watches/${watchId}`, body: { linkGeneration: 7 }, invoke: (c) => c.removeWatch(watchId, 7) },
  { name: 'event', method: 'POST', path: '/v2/bridge/events', body: { event, session }, invoke: (c) => c.publishEvent(event, session) },
  { name: 'current sessions', method: 'PUT', path: '/v2/bridge/e2e/sessions/current', body: snapshot, invoke: (c) => c.replaceE2ECurrentSessions(snapshot) },
  { name: 'recipient snapshot', method: 'GET', path: '/v2/bridge/e2e/recipients', invoke: (c) => c.recipientSnapshot() },
  { name: 'encrypted event', method: 'POST', path: '/v2/bridge/e2e/events', body: encryptedUpload, invoke: (c) => c.publishEncryptedEvent(encryptedUpload.event, encryptedUpload.session) },
  { name: 'E2E confirmation', method: 'POST', path: `/v2/bridge/e2e/links/${linkId}/confirm`, body: confirmation, invoke: (c) => c.confirmLink(linkId, confirmation) },
  { name: 'E2E activation', method: 'POST', path: `/v2/bridge/e2e/links/${linkId}/activate`, body: activation, invoke: (c) => c.activateLink(linkId, activation) },
  { name: 'encrypted session', method: 'POST', path: '/v2/bridge/e2e/sessions', body: { session: encryptedUpload.session }, invoke: (c) => c.publishEncryptedSession(encryptedUpload.session) },
  { name: 'encrypted event reconcile', method: 'POST', path: '/v2/bridge/e2e/events/reconcile', body: encryptedUpload, invoke: (c) => c.reconcileEncryptedEvent(encryptedUpload.event, encryptedUpload.session) },
  { name: 'encrypted session reconcile', method: 'POST', path: '/v2/bridge/e2e/sessions/reconcile', body: { session: encryptedUpload.session }, invoke: (c) => c.reconcileEncryptedSession(encryptedUpload.session) },
  { name: 'read', method: 'POST', path: `/v2/bridge/sessions/${sessionId}/read`, body: { latestReadEventId: 'evt_1', readAt: '2026-07-15T00:00:00.000Z', source: 'bridge_recovery' }, invoke: (c) => c.markSessionRead(sessionId, { latestReadEventId: 'evt_1', readAt: '2026-07-15T00:00:00.000Z', source: 'bridge_recovery' }) },
  { name: 'command pull', method: 'POST', path: '/v2/bridge/commands/pull', body: { hostId, limit: 20 }, invoke: (c) => c.pullCommands(hostId, 20) },
  { name: 'revoke', method: 'POST', path: '/v2/bridge/revoke', body: {}, invoke: (c) => c.revokeIdentity() },
];

describe('RelayClient signed v2 requests', () => {
  for (const entry of cases) {
    test(`${entry.name} signs the exact method, path, empty query, and serialized body`, async () => {
      const signer = new RecordingSigner();
      let request: Request | undefined;
      const client = new RelayClient({
        baseUrl: 'https://relay.example/', signer,
        now: () => new Date('2026-07-15T00:00:00.000Z'), nonce: () => 'A'.repeat(22),
        fetch: async (input, init) => {
          request = new Request(input, init);
          if (entry.name === 'list watches') return Response.json({ watches: [linkedWatch] });
          if (entry.name === 'enroll') return Response.json({ host: {
            hostId, hostName: 'Host', platform: 'linux', bridgeVersion: '1.0.0',
            registeredAt: '2026-07-15T00:00:00.000Z', lastSeenAt: '2026-07-15T00:00:00.000Z',
            bridgeStatus: 'online', status: 'active',
          } });
          if (entry.name === 'revoke') return Response.json({
            entityId: hostId, status: 'revoked', revokedAt: '2026-07-15T00:00:00.000Z',
          });
          if (entry.name === 'recipient snapshot') return Response.json({
            hostId, recipientSetVersion: 1, recipients: [],
          });
          if (entry.name === 'command pull') return Response.json({ commands: [encryptedCommand] });
          return Response.json({ ok: true });
        },
      });
      await entry.invoke(client);
      expect(request!.method).toBe(entry.method);
      expect(new URL(request!.url).pathname).toBe(entry.path);
      expect(new URL(request!.url).search).toBe('');
      expect(request!.headers.has('authorization')).toBe(false);
      expect(request!.headers.has('x-host-auth')).toBe(false);
      const text = await request!.text();
      expect(text).toBe(entry.body === undefined ? '' : JSON.stringify(entry.body));
      expect(signer.inputs).toHaveLength(1);
      expect(signer.inputs[0]).toMatchObject({ method: entry.method, path: entry.path, query: '' });
      expect(signer.inputs[0]!.contentSha256).toBe(await contentSha256(text));
    });
  }

  test('exact-decodes encrypted command pulls all-or-nothing', async () => {
    const reply = { ...structuredClone(encryptedCommand), commandId: 'cmd_reply', type: 'reply',
      targetAlertEventId: 'event_alert', payload: { ...structuredClone(encryptedCommand.payload),
        content: { ...structuredClone(encryptedCommand.payload.content), payloadKind: 'reply-content-v1' } } } as unknown as EncryptedCommandEnvelopeV1;
    const valid = [encryptedCommand, reply];
    const sparse = [encryptedCommand, reply]; delete sparse[1];
    const topLevelNullPrototype = Object.assign(Object.create(null), { commands: valid });
    const malformed = [
      null, [], {}, { commands: [], extra: true }, { commands: 'not-an-array' },
      { commands: Array.from({ length: 21 }, () => encryptedCommand) },
      { commands: [{ ...encryptedCommand, extra: true }] },
      { commands: [{ ...encryptedCommand, issuedAt: '2026-07-15T00:00:00Z' }] },
      { commands: [{ ...encryptedCommand, payload: {} }] },
      { commands: [{ ...encryptedCommand, payload: { ...encryptedCommand.payload, extra: true } }] },
      { commands: [{ commandId: 'plain', hostId, sessionId, type: 'reply', payload: { text: 'plaintext' },
        issuedAt: encryptedCommand.issuedAt, expiresAt: encryptedCommand.expiresAt, nonce: 'plain', watchDeviceId: watchId }] },
      { commands: [{ commandId: 'legacy-interrupt', hostId, sessionId, type: 'interrupt', payload: {},
        issuedAt: encryptedCommand.issuedAt, expiresAt: encryptedCommand.expiresAt, nonce: 'legacy', watchDeviceId: watchId }] },
      { commands: [encryptedCommand, { ...encryptedCommand, payload: {} }] },
      { commands: sparse },
    ];
    const pull = async (body: unknown) => new RelayClient({
      baseUrl: 'https://relay.example', signer: new RecordingSigner(),
      fetch: async () => Response.json(body),
    }).pullCommands(hostId, 20);
    expect(await pull({ commands: valid })).toEqual(valid);
    expect(await pull(topLevelNullPrototype)).toEqual(valid);
    for (const candidate of malformed) await expect(pull(candidate)).rejects.toThrow('command pull response is invalid');
    await expect(pull({ commands: valid })).resolves.toHaveLength(2);
  });

  test('exact-decodes linked Watch generations before unlink selection', async () => {
    const list = async (body: unknown) => new RelayClient({
      baseUrl: 'https://relay.example', signer: new RecordingSigner(), fetch: async () => Response.json(body),
    }).listWatches();
    expect(await list({ watches: [linkedWatch] })).toEqual({ watches: [linkedWatch] });
    for (const malformed of [
      { watches: [{ ...linkedWatch, linkGeneration: 0 }] },
      { watches: [{ ...linkedWatch, linkGeneration: 1.5 }] },
      { watches: [{ ...linkedWatch, extra: true }] },
      { watches: [{ watchDeviceId: watchId, pairedAt: linkedWatch.pairedAt, lastSeenAt: linkedWatch.lastSeenAt }] },
      { watches: [linkedWatch, linkedWatch] },
      { watches: {} },
      { watches: [linkedWatch], extra: true },
    ]) await expect(list(malformed)).rejects.toThrow('linked Watches response is invalid');
  });

  test('exact-decodes recipient snapshots before authority reconciliation', async () => {
    const valid = { hostId, recipientSetVersion: 1, recipients: [] };
    const snapshot = async (body: unknown) => new RelayClient({
      baseUrl: 'https://relay.example', signer: new RecordingSigner(), fetch: async () => Response.json(body),
    }).recipientSnapshot();
    expect(await snapshot(valid)).toEqual(valid);
    for (const malformed of [
      { ...valid, extra: true },
      { ...valid, recipientSetVersion: 0 },
      { ...valid, recipients: {}, },
      { ...valid, recipients: [{ linkId: 'link', linkGeneration: 1, watchDeviceId: watchId, epoch: 1, state: 'active', watchBinding: {} }] },
    ]) await expect(snapshot(malformed)).rejects.toThrow('recipient snapshot response is invalid');
  });

  test('exact-decodes enrollment and revoke responses', async () => {
    const responses = [
      { invoke: (client: RelayClient) => client.enrollHost(enrollment), body: { host: {
        hostId, hostName: 'Host', platform: 'linux', bridgeVersion: '1.0.0',
        registeredAt: '2026-07-15T00:00:00.000Z', lastSeenAt: '2026-07-15T00:00:00.000Z',
        bridgeStatus: 'online', status: 'active', extra: true,
      } } },
      { invoke: (client: RelayClient) => client.revokeIdentity(), body: {
        entityId: hostId, status: 'revoked', revokedAt: '2026-07-15T00:00:00.000Z', extra: true,
      } },
    ];
    for (const candidate of responses) {
      const client = new RelayClient({
        baseUrl: 'https://relay.example', signer: new RecordingSigner(),
        fetch: async () => Response.json(candidate.body),
      });
      await expect(candidate.invoke(client)).rejects.toBeInstanceOf(TypeError);
    }
  });

  test('rejects invalid pairing codes before signing or sending a request', () => {
    for (const pairingCode of ['ABCDEFGH', 'ABCD-EFGH', ' PEYX7K', 'PEYX7K ']) {
      const signer = new RecordingSigner();
      let fetchCalls = 0;
      const client = new RelayClient({
        baseUrl: 'https://relay.example/',
        signer,
        fetch: async () => { fetchCalls += 1; return Response.json({ ok: true }); },
      });

      expect(() => client.pairWatch(pairingCode)).toThrow('exactly 6 Crockford symbols');
      expect(fetchCalls).toBe(0);
      expect(signer.inputs).toHaveLength(0);
    }
  });

  test('submits the exact persisted receipt bytes and fails closed on malformed success', async () => {
    const fixture = await import('../../../packages/protocol/test/fixtures/command-e2e-v1-vectors.json');
    const receipt = structuredClone(fixture.default.receipt.envelope) as CommandReceiptEnvelopeV1;
    const canonicalBody = JSON.stringify(receipt);
    let wireBody = '';
    const signer = new RecordingSigner();
    const client = new RelayClient({
      baseUrl: 'https://relay.example', signer,
      fetch: async (_input, init) => {
        wireBody = await new Response(init?.body).text();
        return Response.json({ ok: true });
      },
    });
    await expect(client.submitCommandReceipt(canonicalBody)).resolves.toBeUndefined();
    expect(wireBody).toBe(canonicalBody);
    expect(signer.inputs[0]?.contentSha256).toBe(await contentSha256(canonicalBody));

    for (const response of [Response.json({ ok: false }), Response.json({ ok: true, extra: true }), new Response('', { status: 500 })]) {
      const malformed = new RelayClient({
        baseUrl: 'https://relay.example', signer: new RecordingSigner(), fetch: async () => response.clone(),
      });
      await expect(malformed.submitCommandReceipt(canonicalBody)).rejects.toThrow();
    }
  });

  test('uses restricted path targets for session reads and watch removal', () => {
    const client = new RelayClient({ baseUrl: 'https://relay.example', signer: new RecordingSigner(), fetch: async () => Response.json({ ok: true }) });
    expect(() => client.removeWatch('../watch', 1)).toThrow();
    expect(() => client.removeWatch(watchId, 0)).toThrow('positive safe integer');
    expect(() => client.markSessionRead('session%2Fbad', { latestReadEventId: 'evt', readAt: new Date().toISOString(), source: 'bridge_recovery' })).toThrow();
  });

  test.each([200, 503])('classifies status %d response-body stream failures as transport errors', async (status) => {
    const client = new RelayClient({
      baseUrl: 'https://relay.example', signer: new RecordingSigner(),
      fetch: async () => new Response(new ReadableStream({
        start(controller) { controller.error(new TypeError('socket interrupted')); },
      }), { status }),
    });
    await expect(client.updateHost(metadata)).rejects.toBeInstanceOf(RelayTransportError);
  });

  test('keeps malformed Relay JSON outside the transport-error taxonomy', async () => {
    const client = new RelayClient({
      baseUrl: 'https://relay.example', signer: new RecordingSigner(),
      fetch: async () => new Response('{not-json', { status: 200 }),
    });
    try {
      await client.updateHost(metadata);
      throw new Error('expected malformed JSON failure');
    } catch (error) {
      expect(error).not.toBeInstanceOf(RelayTransportError);
      expect(error).toBeInstanceOf(SyntaxError);
    }
  });
});
