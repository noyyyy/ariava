import { describe, expect, test } from 'bun:test';
import { contentSha256, type CanonicalRequestInput, type SignedRequestHeaders } from '@ariava/protocol';
import { RelayClient } from '../src/relay-client';
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
const event = { eventId: 'evt_1', hostId, sessionId, provider: 'pi', type: 'working', status: 'working', typeLabel: 'Working', createdAt: '2026-07-15T00:00:00.000Z' } as any;
const session = { sessionId, hostId, provider: 'pi', projectName: 'p', nameText: 'n', stateLabel: 'Working', status: 'working', updatedAt: '2026-07-15T00:00:00.000Z' } as any;
const commandResult = { commandId: 'cmd_1', hostId, sessionId, type: 'interrupt', status: 'completed', completedAt: '2026-07-15T00:00:00.000Z' } as any;
const rotation = { rotation: { operationId: 'op_12345678-1234-4123-8123-123456789abc', entityId: hostId, oldKeyId: `key_${'B'.repeat(43)}`, newKeyId: `key_${'E'.repeat(43)}`, newPublicKey: 'E'.repeat(43), issuedAt: '2026-07-15T00:00:00.000Z' }, oldKeyAuthorizationSignature: emptySignature, newKeyProofSignature: emptySignature } as any;

const cases: Array<{ name: string; method: string; path: string; body?: unknown; invoke(client: RelayClient): Promise<unknown> }> = [
  { name: 'enroll', method: 'POST', path: '/v2/bridge/enroll', body: enrollment, invoke: (c) => c.enrollHost(enrollment) },
  { name: 'metadata update', method: 'PUT', path: '/v2/bridge/registration', body: metadata, invoke: (c) => c.updateHost(metadata) },
  { name: 'heartbeat', method: 'PUT', path: '/v2/bridge/registration', body: metadata, invoke: (c) => c.heartbeat(metadata) },
  { name: 'pair', method: 'POST', path: '/v2/bridge/pair-watch', body: { pairingCode: 'PEYX7K' }, invoke: (c) => c.pairWatch('PEYX7K') },
  { name: 'list watches', method: 'GET', path: '/v2/bridge/watches', invoke: (c) => c.listWatches() },
  { name: 'remove watch', method: 'DELETE', path: `/v2/bridge/watches/${watchId}`, body: {}, invoke: (c) => c.removeWatch(watchId) },
  { name: 'event', method: 'POST', path: '/v2/bridge/events', body: { event, session }, invoke: (c) => c.publishEvent(event, session) },
  { name: 'read', method: 'POST', path: `/v2/bridge/sessions/${sessionId}/read`, body: { latestReadEventId: 'evt_1', readAt: '2026-07-15T00:00:00.000Z', source: 'bridge_recovery' }, invoke: (c) => c.markSessionRead(sessionId, { latestReadEventId: 'evt_1', readAt: '2026-07-15T00:00:00.000Z', source: 'bridge_recovery' }) },
  { name: 'command pull', method: 'POST', path: '/v2/bridge/commands/pull', body: { hostId, limit: 20 }, invoke: (c) => c.pullCommands(hostId, 20) },
  { name: 'command result', method: 'POST', path: '/v2/bridge/commands/result', body: commandResult, invoke: (c) => c.submitCommandResult(commandResult) },
  { name: 'rotation', method: 'POST', path: '/v2/bridge/keys/rotate', body: rotation, invoke: (c) => c.rotateKey(rotation) },
  { name: 'rotation recovery', method: 'GET', path: `/v2/bridge/keys/rotations/${rotation.rotation.operationId}`, invoke: (c) => c.recoverRotation(rotation.rotation.operationId) },
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
        fetch: async (input, init) => { request = new Request(input, init); return Response.json({ ok: true }); },
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

  test('normalizes lowercase pairing codes before signing and sending', async () => {
    const signer = new RecordingSigner();
    let request: Request | undefined;
    const client = new RelayClient({
      baseUrl: 'https://relay.example/', signer,
      now: () => new Date('2026-07-15T00:00:00.000Z'), nonce: () => 'A'.repeat(22),
      fetch: async (input, init) => { request = new Request(input, init); return Response.json({ ok: true }); },
    });

    await client.pairWatch('peyx7k');

    expect(await request!.json()).toEqual({ pairingCode: 'PEYX7K' });
    expect(signer.inputs).toHaveLength(1);
  });

  test('rejects invalid pairing codes before signing or making a network request', () => {
    for (const pairingCode of ['ABCDEFGH', 'ABCD-EFGH', ' PEYX7K', 'PEYX7K ']) {
      const signer = new RecordingSigner();
      let fetchCalls = 0;
      const client = new RelayClient({
        baseUrl: 'https://relay.example/', signer,
        fetch: async () => { fetchCalls += 1; return Response.json({ ok: true }); },
      });

      expect(() => client.pairWatch(pairingCode)).toThrow('exactly 6 Crockford symbols');
      expect(signer.inputs).toHaveLength(0);
      expect(fetchCalls).toBe(0);
    }
  });

  test('uses restricted path targets for session reads and watch removal', () => {
    const client = new RelayClient({ baseUrl: 'https://relay.example', signer: new RecordingSigner(), fetch: async () => Response.json({ ok: true }) });
    expect(() => client.removeWatch('../watch')).toThrow();
    expect(() => client.markSessionRead('session%2Fbad', { latestReadEventId: 'evt', readAt: new Date().toISOString(), source: 'bridge_recovery' })).toThrow();
  });
});
