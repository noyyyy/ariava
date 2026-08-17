import { afterEach, beforeEach, describe, expect, mock, test } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AgentAdapterClient } from '../../src/agent-adapter/client';
import { AgentAdapterRegistry } from '../../src/agent-adapter/registry';
import { AgentAdapterServer } from '../../src/agent-adapter/server';
import { BridgeStateStore } from '../../src/state-store';
import {
  AGENT_ADAPTER_PROTOCOL_HEADER,
  AGENT_ADAPTER_PROTOCOL_VERSION,
  isAgentAdapterDriverInstanceId,
  type CommandEnvelope,
  type CommandResult,
} from '@ariava/protocol';
import { AGENT_ADAPTER_OWNER_HEADERS } from '../../src/agent-adapter/registry-types';

mock.module('../../src/e2e/node-crypto', () => ({
  ChaChaPolyAuthenticationError: class ChaChaPolyAuthenticationError extends Error {},
  chachaPolySeal: (_key: Uint8Array, plaintext: Uint8Array) => ({
    nonce: new Uint8Array(12).fill(1), ciphertext: new Uint8Array([...plaintext, ...new Uint8Array(16)]),
  }),
  chachaPolyOpen: (_key: Uint8Array, _nonce: Uint8Array, ciphertext: Uint8Array) => ciphertext.slice(0, -16),
}));

describe('AgentAdapterServer', () => {
  let dir: string;
  let store: BridgeStateStore;
  let registry: AgentAdapterRegistry;
  let server: AgentAdapterServer;
  let secret: string;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'bridge-server-'));
    store = new BridgeStateStore(join(dir, 'state.json'));
    store.initializeEncryptedSpool('host-1', join(dir, 'identity.json'), 'linux', {
      loadOrCreate: () => new Uint8Array(32).fill(7),
    });
    registry = new AgentAdapterRegistry('host-1', store);
    secret = 'test-secret-token';
    server = new AgentAdapterServer({ port: 0, secret, hostId: 'host-1' }, registry);
    await server.start();
  });

  afterEach(() => {
    server.stop();
    rmSync(dir, { recursive: true, force: true });
  });

  function url(path: string): string {
    return `${server.url}${path}`;
  }

  /** 16 zero bytes as unpadded base64url: a valid protocol-4 driver instance id. */
  const DRIVER_INSTANCE_ID = 'AAAAAAAAAAAAAAAAAAAAAA';
  /** 16 zero bytes as unpadded base64url: a valid producer Event id. */
  const PRODUCER_EVENT_ID = 'AAAAAAAAAAAAAAAAAAAAAA';
  /** Valid 128-bit producer Event orders (32 lowercase hex chars, zero invalid). */
  const ORDER_1 = '00000000000000000000000000000001';
  const ORDER_2 = '00000000000000000000000000000002';

  /** The last directly-registered owner lease; ownerHeaders() defaults to it. */
  let activeLease = '';

  function headers(): Record<string, string> {
    return {
      authorization: `Bearer ${secret}`,
      'content-type': 'application/json',
      [AGENT_ADAPTER_PROTOCOL_HEADER]: String(AGENT_ADAPTER_PROTOCOL_VERSION),
    };
  }

  function registerDirect(registry: AgentAdapterRegistry, overrides: Record<string, unknown> = {}): string {
    const session = registry.register({
      sessionId: 'sess-1', provider: 'pi', projectName: 'p', nameText: 'p', cwd: '/', driverInstanceId: DRIVER_INSTANCE_ID,
      ...overrides,
    } as Parameters<typeof registry.register>[0]);
    activeLease = session.ownerLease;
    return session.ownerLease;
  }

  function ownerHeaders(lease: string = activeLease): Record<string, string> {
    if (!lease) throw new Error('ownerHeaders() called before any registration produced a lease');
    return { ...headers(),
      [AGENT_ADAPTER_OWNER_HEADERS.driverInstance]: DRIVER_INSTANCE_ID,
      [AGENT_ADAPTER_OWNER_HEADERS.ownerLease]: lease };
  }


  test('rejects requests without a bearer token', async () => {
    const response = await fetch(url('/v2/agent/sessions'), { method: 'POST', body: '{}' });
    expect(response.status).toBe(401);
  });

  test('requires the exact Agent Adapter protocol version after authentication', async () => {
    const missing = await fetch(url('/v2/health'), {
      headers: { authorization: `Bearer ${secret}` },
    });
    expect(missing.status).toBe(426);
    const wrong = await fetch(url('/v2/health'), {
      headers: { authorization: `Bearer ${secret}`, [AGENT_ADAPTER_PROTOCOL_HEADER]: '1' },
    });
    expect(wrong.status).toBe(426);
  });

  test('rejects v2 before parsing a malformed body and accepts v3', async () => {
    const rejected = await fetch(url('/v2/agent/sessions'), {
      method: 'POST',
      headers: { ...headers(), [AGENT_ADAPTER_PROTOCOL_HEADER]: '2' },
      body: '{not-json',
    });
    expect(rejected.status).toBe(426);
    expect(registry.listSessions()).toEqual([]);

    const accepted = await fetch(url('/v2/agent/sessions'), {
      method: 'POST', headers: headers(), body: JSON.stringify({
        sessionId: 'v3-session', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p', driverInstanceId: DRIVER_INSTANCE_ID,
      }),
    });
    expect(accepted.status).toBe(201);
  });

  test('rejects malformed authenticated client input as 400 across parser families', async () => {
    registry.register({ sessionId: 'sess-1', provider: 'pi', projectName: 'p', nameText: 'p', cwd: '/', driverInstanceId: DRIVER_INSTANCE_ID });
    const cases = [
      ['/v2/agent/sessions', '{bad-json'],
      ['/v2/agent/sessions', '[]'],
      ['/v2/agent/sessions/sess-1/events', '[]'],
      ['/v2/agent/sessions/sess-1/heartbeat', JSON.stringify({ status: 'invalid' })],
      ['/v2/agent/sessions/sess-1/heartbeat', JSON.stringify({ status: 'idle', harnessProvider: 'other' })],
      ['/v2/agent/sessions/sess-1/handle', JSON.stringify({ handledThroughEventId: 1 })],
      ['/v2/agent/sessions/sess-1/commands/cmd-1/result', JSON.stringify({ commandId: 'cmd-1', accepted: 'yes' })],
    ] as const;
    for (const [path, body] of cases) {
      const response = await fetch(url(path), { method: 'POST', headers: headers(), body });
      expect(response.status).toBe(400);
    }
  });

  test('preserves genuine server faults as 500', async () => {
    const original = registry.register.bind(registry);
    registry.register = (() => { throw new Error('persistence unavailable'); }) as typeof registry.register;
    try {
      const response = await fetch(url('/v2/agent/sessions'), {
        method: 'POST', headers: headers(), body: JSON.stringify({
          sessionId: 'fault', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p', driverInstanceId: DRIVER_INSTANCE_ID,
        }),
      });
      expect(response.status).toBe(500);
      expect(await response.json()).toEqual({ error: { code: 'INTERNAL_ERROR', retryable: false } });
    } finally { registry.register = original; }
  });

  test('preserves internal TypeErrors as 500', async () => {
    const original = registry.register.bind(registry);
    registry.register = (() => { throw new TypeError('internal registry type fault'); }) as typeof registry.register;
    try {
      const response = await fetch(url('/v2/agent/sessions'), {
        method: 'POST', headers: headers(), body: JSON.stringify({
          sessionId: 'fault', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p', driverInstanceId: DRIVER_INSTANCE_ID,
        }),
      });
      expect(response.status).toBe(500);
      expect(await response.json()).toEqual({ error: { code: 'INTERNAL_ERROR', retryable: false } });
    } finally { registry.register = original; }

    const typeFaultServer = new AgentAdapterServer(
      { port: 0, secret, hostId: 'host-1' }, registry, () => { throw new TypeError('internal health type fault'); },
    );
    await typeFaultServer.start();
    try {
      const response = await fetch(`${typeFaultServer.url}/v2/health`, { headers: headers() });
      expect(response.status).toBe(500);
      expect(await response.json()).toEqual({ error: { code: 'INTERNAL_ERROR', retryable: false } });
    } finally { typeFaultServer.stop(); }
  });

  test('health is authenticated and returns only minimal Host evidence', async () => {
    const unauthenticated = await fetch(url('/v2/health'));
    expect(unauthenticated.status).toBe(401);

    const response = await fetch(url('/v2/health'), { headers: headers() });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true, hostId: 'host-1', health: { status: 'healthy', drivers: [] },
    });
  });

  test('health exposes exact bounded degraded evidence without protected diagnostics', async () => {
    const degraded = new AgentAdapterServer(
      { port: 0, secret, hostId: 'host-1' },
      registry,
      () => ({
        status: 'degraded',
        drivers: [{
          driver: 'pi', code: 'driver_reconciliation_failed', count: 3,
          firstSeenAt: '2026-08-10T00:00:00.000Z', lastSeenAt: '2026-08-10T00:00:15.000Z',
          nextRetryAt: '2026-08-10T00:00:30.000Z',
        }],
        relayPresence: {
          code: 'relay_presence_refresh_failed', count: 1,
          firstSeenAt: '2026-08-10T00:00:00.000Z', lastSeenAt: '2026-08-10T00:00:00.000Z',
          nextRetryAt: '2026-08-10T00:00:15.000Z',
        },
      }),
    );
    await degraded.start();
    try {
      const body = await (await fetch(`${degraded.url}/v2/health`, { headers: headers() })).json();
      expect(body).toEqual({
        ok: true, hostId: 'host-1', health: {
          status: 'degraded',
          drivers: [{
            driver: 'pi', code: 'driver_reconciliation_failed', count: 3,
            firstSeenAt: '2026-08-10T00:00:00.000Z', lastSeenAt: '2026-08-10T00:00:15.000Z',
            nextRetryAt: '2026-08-10T00:00:30.000Z',
          }],
          relayPresence: {
            code: 'relay_presence_refresh_failed', count: 1,
            firstSeenAt: '2026-08-10T00:00:00.000Z', lastSeenAt: '2026-08-10T00:00:00.000Z',
            nextRetryAt: '2026-08-10T00:00:15.000Z',
          },
        },
      });
      expect(JSON.stringify(body)).not.toMatch(/error|stack|ciphertext|token|credential|path/iu);
    } finally { degraded.stop(); }
  });

  test('registers a session', async () => {
    const response = await fetch(url('/v2/agent/sessions'), {
      method: 'POST',
      headers: headers(),
      body: JSON.stringify({
        sessionId: 'sess-1', provider: 'pi', projectName: 'deploy-tools', cwd: '/tmp', nameText: 'Deploy tools', driverInstanceId: DRIVER_INSTANCE_ID,
      }),
    });

    expect(response.status).toBe(201);
    const body = (await response.json()) as { sessionId: string; registeredAt: string; ownership: 'owned'; ownerLease: string };
    expect(body.sessionId).toBe('sess-1');
    expect(typeof body.registeredAt).toBe('string');
    expect(body.ownership).toBe('owned');
    expect(typeof body.ownerLease).toBe('string');
  });

  test.each([
    ['project alias', { sessionId: 'legacy-project', provider: 'pi', project: 'p', cwd: '/', nameText: 'p' }],
    ['title alias', { sessionId: 'legacy-title', provider: 'pi', projectName: 'p', cwd: '/', title: 'p' }],
    ['summary alias', { sessionId: 'legacy-summary', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p', summary: 'old' }],
    ['retired session key', { sessionId: 'legacy-key', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p', hbaseSessionKey: 'legacy-key' }],
  ])('rejects removed register %s', async (_name, body) => {
    const response = await fetch(url('/v2/agent/sessions'), {
      method: 'POST', headers: headers(), body: JSON.stringify(body),
    });
    expect(response.status).toBe(400);
  });

  test('unregisters a session', async () => {
    const ownerLease = registerDirect(registry);

    const response = await fetch(url('/v2/agent/sessions/sess-1'), {
      method: 'DELETE',
      headers: ownerHeaders(ownerLease),
    });

    expect(response.status).toBe(200);
    expect(registry.listSessions()).toHaveLength(0);
  });

  test('unregistered Event is typed client input before mutation while internal TypeError remains 500', async () => {
    const event = {
      sessionId: 'missing', provider: 'pi', type: 'done', status: 'idle', agentText: 'Done',
      projectName: 'p', workingDirectory: '/', harnessProvider: 'pi', createdAt: '2026-08-07T00:00:01.000Z',
    };
    const beforeStore = structuredClone(store.listSessions());
    const unregistered = await fetch(url('/v2/agent/sessions/missing/events'), {
      method: 'POST', headers: headers(), body: JSON.stringify({
        producerEventId: PRODUCER_EVENT_ID, producerEventOrder: ORDER_1, event,
      }),
    });
    expect(unregistered.status).toBe(400);
    expect(store.listSessions()).toEqual(beforeStore);
    expect(store.peekPendingEvents()).toEqual([]);

    const ownerLease = registerDirect(registry, { sessionId: 'fault' });
    const original = store.getProducerEventReservation.bind(store);
    store.getProducerEventReservation = (() => { throw new TypeError('internal event state fault'); }) as typeof store.getProducerEventReservation;
    try {
      const fault = await fetch(url('/v2/agent/sessions/fault/events'), {
        method: 'POST', headers: ownerHeaders(ownerLease), body: JSON.stringify({
          producerEventId: PRODUCER_EVENT_ID, producerEventOrder: ORDER_1, event: { ...event, sessionId: 'fault' },
        }),
      });
    } finally { store.getProducerEventReservation = original; }
  });

  test('decodes exact native session and command path identities once across all routes', async () => {
    const sessionId = ' native% id?# ';
    const commandId = ' command% id?# ';
    const encodedSessionId = encodeURIComponent(sessionId);
    const encodedCommandId = encodeURIComponent(commandId);
    const register = await fetch(url('/v2/agent/sessions'), {
      method: 'POST', headers: headers(), body: JSON.stringify({
        sessionId, provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p', status: 'working', driverInstanceId: DRIVER_INSTANCE_ID,
      }),
    });
    expect(register.status).toBe(201);
    const registeredBody = await register.json() as { ownerLease: string };

    const heartbeat = await fetch(url(`/v2/agent/sessions/${encodedSessionId}/heartbeat`), {
      method: 'POST', headers: ownerHeaders(registeredBody.ownerLease), body: JSON.stringify({ status: 'working', latestActivityText: 'Exact' }),
    });
    expect(heartbeat.status).toBe(200);
    const event = {
      sessionId, provider: 'pi', type: 'done', status: 'idle', agentText: 'Done',
      projectName: 'p', workingDirectory: '/', harnessProvider: 'pi', createdAt: '2026-08-07T00:00:01.000Z',
    };
    const pushed = await fetch(url(`/v2/agent/sessions/${encodedSessionId}/events`), {
      method: 'POST', headers: ownerHeaders(registeredBody.ownerLease), body: JSON.stringify({
        producerEventId: PRODUCER_EVENT_ID, producerEventOrder: ORDER_1, event,
      }),
    });
    const { eventId } = await pushed.json() as { eventId: string };
    const handled = await fetch(url(`/v2/agent/sessions/${encodedSessionId}/handle`), {
      method: 'POST', headers: ownerHeaders(registeredBody.ownerLease), body: JSON.stringify({ handledThroughEventId: eventId }),
    });
    expect(handled.status).toBe(200);
    expect(await handled.json()).toMatchObject({ sessionId });

    registry.enqueueCommand({
      commandId, hostId: 'host-1', sessionId, type: 'reply', payload: {},
      issuedAt: '2026-06-30T09:59:00Z', expiresAt: '2026-06-30T10:05:00Z', nonce: 'exact', watchDeviceId: 'watch-1',
    });
    const polled = await fetch(url(`/v2/agent/sessions/${encodedSessionId}/commands?timeout=0`), {
      headers: ownerHeaders(registeredBody.ownerLease),
    });
    expect(polled.status).toBe(200);
    expect((await polled.json() as { command: CommandEnvelope }).command).toMatchObject({ sessionId, commandId });
    const result: CommandResult = {
      commandId, hostId: 'host-1', sessionId, accepted: true, status: 'executed',
      updatedAt: '2026-06-30T10:00:00.000Z',
    };
    const submitted = await fetch(url(`/v2/agent/sessions/${encodedSessionId}/commands/${encodedCommandId}/result`), {
      method: 'POST', headers: ownerHeaders(registeredBody.ownerLease), body: JSON.stringify(result),
    });
    expect(submitted.status).toBe(200);
    expect(await registry.waitForResult(commandId, { timeoutMs: 50 })).toEqual(result);
    const removed = await fetch(url(`/v2/agent/sessions/${encodedSessionId}`), { method: 'DELETE', headers: ownerHeaders(registeredBody.ownerLease) });
    expect(removed.status).toBe(200);
    expect(registry.hasSession(sessionId)).toBe(false);
  });

  test.each([
    '/v2/agent/sessions/%ZZ',
    '/v2/agent/sessions/%ZZ/heartbeat',
    '/v2/agent/sessions/%ZZ/events',
    '/v2/agent/sessions/%ZZ/handle',
    '/v2/agent/sessions/%ZZ/commands',
    '/v2/agent/sessions/valid/commands/%ZZ/result',
  ])('returns 400 for malformed encoded path identity %s', async (path) => {
    const response = await fetch(url(path), {
      method: path.endsWith('/commands') ? 'GET' : path.endsWith('%ZZ') ? 'DELETE' : 'POST',
      headers: headers(), body: path.endsWith('/commands') || path.endsWith('%ZZ') ? undefined : '{}',
    });
    expect(response.status).toBe(400);
  });

  test('accepts only the exact complete canonical producer DTO', async () => {
    registerDirect(registry, { status: 'working' });
    const canonical = {
      sessionId: 'sess-1', provider: 'pi', type: 'done', status: 'idle',
      agentText: 'Finished', projectName: 'p', workingDirectory: '/', harnessProvider: 'pi', createdAt: '2026-08-07T00:00:01.000Z',
    };

    const accepted = await fetch(url('/v2/agent/sessions/sess-1/events'), {
      method: 'POST', headers: ownerHeaders(), body: JSON.stringify({
        producerEventId: PRODUCER_EVENT_ID, producerEventOrder: ORDER_1, event: canonical,
      }),
    });
    expect(accepted.status).toBe(200);
    expect(store.peekPendingEvents()[0]).toMatchObject({ type: 'done', status: 'idle', hostId: 'host-1' });
    expect(registry.listSessions()[0]).toMatchObject({ status: 'idle', lastEventId: expect.any(String) });
  });

  test.each([
    ['omitted type', { sessionId: 'sess-1', provider: 'pi', status: 'idle', agentText: 'Finished', createdAt: '2026-08-07T00:00:01.000Z' }],
    ['legacy type', { sessionId: 'sess-1', provider: 'pi', type: 'blocked', status: 'blocked', agentText: 'Blocked', createdAt: '2026-08-07T00:00:01.000Z' }],
    ['legacy typeLabel', { sessionId: 'sess-1', provider: 'pi', type: 'done', status: 'idle', typeLabel: 'Task complete', agentText: 'Finished', createdAt: '2026-08-07T00:00:01.000Z' }],
    ['excess field', { sessionId: 'sess-1', provider: 'pi', type: 'done', status: 'idle', agentText: 'Finished', createdAt: '2026-08-07T00:00:01.000Z', extra: true }],
    ['malformed NeedHuman', { sessionId: 'sess-1', provider: 'pi', type: 'need_human', status: 'need_human', agentText: 'Failed', needHuman: { reason: 'error', error: { kind: 'provider_failure', message: 'Bearer secret', retryExhausted: true } }, createdAt: '2026-08-07T00:00:01.000Z' }],
    ['retired actionablePrompt', { sessionId: 'sess-1', provider: 'pi', type: 'done', status: 'idle', agentText: 'Finished', projectName: 'p', workingDirectory: '/', harnessProvider: 'pi', actionablePrompt: {}, createdAt: '2026-08-07T00:00:01.000Z' }],
    ['retired contextText', { sessionId: 'sess-1', provider: 'pi', type: 'done', status: 'idle', agentText: 'Finished', projectName: 'p', workingDirectory: '/', harnessProvider: 'pi', contextText: 'p', createdAt: '2026-08-07T00:00:01.000Z' }],
    ['retired correlationId', { sessionId: 'sess-1', provider: 'pi', type: 'done', status: 'idle', agentText: 'Finished', projectName: 'p', workingDirectory: '/', harnessProvider: 'pi', correlationId: 'old', createdAt: '2026-08-07T00:00:01.000Z' }],
    ['retired hbaseSessionKey', { sessionId: 'sess-1', provider: 'pi', type: 'done', status: 'idle', agentText: 'Finished', projectName: 'p', workingDirectory: '/', harnessProvider: 'pi', hbaseSessionKey: 'old', createdAt: '2026-08-07T00:00:01.000Z' }],
  ])('rejects %s without mutating the Session', async (_name, body) => {
    registerDirect(registry, { status: 'working' });
    const before = registry.listSessions()[0];
    const response = await fetch(url('/v2/agent/sessions/sess-1/events'), {
      method: 'POST', headers: ownerHeaders(), body: JSON.stringify({
        producerEventId: PRODUCER_EVENT_ID, producerEventOrder: ORDER_1, event: body,
      }),
    });
    expect(response.status).toBe(400);
    expect(registry.listSessions()[0]).toEqual(before);
    expect(store.peekPendingEvents()).toEqual([]);
  });

  test('handles a session and rejects the removed read route', async () => {
    registerDirect(registry);

    const canonical = (agentText: string, createdAt: string) => ({
      sessionId: 'sess-1', provider: 'pi', type: 'done', status: 'idle',
      agentText, projectName: 'p', workingDirectory: '/', harnessProvider: 'pi', createdAt,
    });
    const eventId = registry.pushEvent('sess-1', canonical('First', '2026-07-16T00:00:02.000Z'));
    const response = await fetch(url('/v2/agent/sessions/sess-1/handle'), {
      method: 'POST', headers: ownerHeaders(),
      body: JSON.stringify({ handledThroughEventId: eventId, handledAt: '2026-07-16T00:00:02Z', action: 'pi_input' }),
    });
    expect(store.peekPendingSessionHandles()[0]).toMatchObject({
      handledThroughEventId: eventId, handledThroughEventCreatedAt: '2026-07-16T00:00:02.000Z', action: 'pi_input',
    });

    const removed = await fetch(url('/v2/agent/sessions/sess-1/read'), {
      method: 'POST', headers: ownerHeaders(),
      body: JSON.stringify({ latestReadEventId: eventId, readAt: '2026-07-16T00:00:03Z', source: 'bridge_recovery' }),
    });
    expect(removed.status).toBe(404);

    for (const legacyBody of [
      { handledThroughEventId: eventId, latestReadEventId: eventId },
      { handledThroughEventId: eventId, action: 'watch_reply' },
      { handledThroughEventId: eventId, actorId: 'host-spoofed' },
      { handledThroughEventId: eventId, handledByIdentityId: 'host-spoofed' },
    ]) {
      const rejected = await fetch(url('/v2/agent/sessions/sess-1/handle'), {
        method: 'POST', headers: ownerHeaders(), body: JSON.stringify(legacyBody),
      });
      expect(rejected.status).toBe(400);
    }
  });

  test('heartbeats update session status', async () => {
    registerDirect(registry);

    const response = await fetch(url('/v2/agent/sessions/sess-1/heartbeat'), {
      method: 'POST',
      headers: ownerHeaders(),
      body: JSON.stringify({ status: 'working', latestActivityText: 'Still running' }),
    });

    expect(response.status).toBe(200);
    const session = registry.listSessions()[0];
    expect(session?.status).toBe('working');
    expect(session?.latestActivityText).toBe('Still running');
  });

  test('rejects the removed heartbeat summary alias', async () => {
    registerDirect(registry, { sessionId: 'sess-alias' });
    const response = await fetch(url('/v2/agent/sessions/sess-alias/heartbeat'), {
      method: 'POST', headers: ownerHeaders(), body: JSON.stringify({ status: 'working', summary: 'legacy' }),
    });
    expect(response.status).toBe(400);
  });

  test('rejects heartbeat owner fields before any semantic mutation', async () => {
    registerDirect(registry, { sessionId: 'owner-heartbeat', provider: 'adapter', harnessProvider: 'pi', status: 'idle' });
    const beforeSession = structuredClone(registry.listSessions()[0]);
    const beforeStore = structuredClone(store.listSessions());
    const response = await fetch(url('/v2/agent/sessions/owner-heartbeat/heartbeat'), {
      method: 'POST', headers: ownerHeaders(), body: JSON.stringify({ status: 'working', harnessProvider: 'other' }),
    });
    expect(response.status).toBe(400);
    expect(registry.listSessions()[0]).toEqual(beforeSession);
    expect(store.listSessions()).toEqual(beforeStore);
    expect(store.peekPendingEvents()).toEqual([]);
    expect(store.peekPendingSessionHandles()).toEqual([]);
  });

  test('heartbeat JSON null explicitly clears optional semantic text', async () => {
    registerDirect(registry, { sessionId: 'sess-clear', openingText: 'Old task', latestActivityText: 'Old activity' });

    const response = await fetch(url('/v2/agent/sessions/sess-clear/heartbeat'), {
      method: 'POST',
      headers: ownerHeaders(),
      body: JSON.stringify({ status: 'idle', openingText: null, latestActivityText: null }),
    });

    expect(response.status).toBe(200);
    const session = registry.listSessions()[0];
    expect(session?.openingText).toBeUndefined();
    expect(session?.latestActivityText).toBeUndefined();
  });

  test('register with an oversized Session returns 400 before any mutation', async () => {
    const response = await fetch(url('/v2/agent/sessions'), {
      method: 'POST',
      headers: headers(),
      body: JSON.stringify({ sessionId: 'big', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'n', openingText: 'a'.repeat(65_500), driverInstanceId: DRIVER_INSTANCE_ID }),
    });
    expect(response.status).toBe(400);
    expect(store.listSessions().some((s) => s.sessionId === 'big')).toBe(false);
    expect(registry.listSessions().some((s) => s.sessionId === 'big')).toBe(false);
  });

  test('heartbeat with an oversized Session returns 400 and leaves the Session unchanged', async () => {
    registerDirect(registry);
    const response = await fetch(url('/v2/agent/sessions/sess-1/heartbeat'), {
      method: 'POST',
      headers: ownerHeaders(),
      body: JSON.stringify({ status: 'working', latestActivityText: 'a'.repeat(65_500) }),
    });
    expect(response.status).toBe(400);
    expect(registry.listSessions()[0]?.status).toBe('idle');
  });

  test('returns enqueued command during short poll', async () => {
    registerDirect(registry);

    const command: CommandEnvelope = {
      commandId: 'cmd-1',
      hostId: 'host-1',
      sessionId: 'sess-1',
      type: 'reply',
      payload: { text: 'Continue' },
      issuedAt: '2026-06-30T10:00:00Z',
      expiresAt: '2026-06-30T10:05:00Z',
      nonce: 'n-1',
      watchDeviceId: 'watch-1',
    };

    new AgentAdapterClient(registry).enqueueCommand(command);
    const response = await fetch(url('/v2/agent/sessions/sess-1/commands?timeout=0'), {
      method: 'GET',
      headers: ownerHeaders(),
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as { command: CommandEnvelope };
    expect(body.command.commandId).toBe('cmd-1');
  });

  test('returns 204 immediately when no command is queued during short poll', async () => {
    registerDirect(registry);

    const startedAt = Date.now();
    const response = await fetch(url('/v2/agent/sessions/sess-1/commands?timeout=0'), {
      method: 'GET',
      headers: ownerHeaders(),
    });

    expect(response.status).toBe(204);
    expect(Date.now() - startedAt).toBeLessThan(200);
  });

  test('submits command result', async () => {
    registerDirect(registry);

    const command: CommandEnvelope = {
      commandId: 'cmd-1', hostId: 'host-1', sessionId: 'sess-1', type: 'reply', payload: {},
      issuedAt: '2026-06-30T09:59:00Z', expiresAt: '2026-06-30T10:05:00Z', nonce: 'n-1', watchDeviceId: 'watch-1',
    };
    registry.enqueueCommand(command);
    const result: CommandResult = {
      commandId: 'cmd-1',
      hostId: 'host-1',
      sessionId: 'sess-1',
      accepted: true,
      status: 'executed',
      updatedAt: '2026-06-30T10:00:00.000Z',
    };

    const response = await fetch(url('/v2/agent/sessions/sess-1/commands/cmd-1/result'), {
      method: 'POST',
      headers: ownerHeaders(),
      body: JSON.stringify(result),
    });

    expect(response.status).toBe(200);
    const resolved = await registry.waitForResult('cmd-1', { timeoutMs: 50 });
    expect(resolved).toEqual(result);
  });

  test('unauthenticated result submission cannot mutate pending command state', async () => {
    registerDirect(registry);
    const command: CommandEnvelope = {
      commandId: 'cmd-unauth-result', hostId: 'host-1', sessionId: 'sess-1', type: 'interrupt', payload: {},
      issuedAt: '2026-06-30T09:59:00Z', expiresAt: '2026-06-30T10:05:00Z', nonce: 'n-unauth', watchDeviceId: 'watch-1',
    };
    registry.enqueueCommand(command);
    await registry.dequeueCommand(command.sessionId, 0);
    const result = { commandId: command.commandId, hostId: command.hostId, sessionId: command.sessionId,
      accepted: true, status: 'executed', updatedAt: '2026-06-30T10:00:00.000Z' };
    const response = await fetch(url(`/v2/agent/sessions/${command.sessionId}/commands/${command.commandId}/result`), {
      method: 'POST',
      headers: { 'content-type': 'application/json', [AGENT_ADAPTER_PROTOCOL_HEADER]: String(AGENT_ADAPTER_PROTOCOL_VERSION) },
      body: JSON.stringify(result),
    });

    expect(response.status).toBe(401);
    expect(registry.hasPendingCommandWork(command.sessionId)).toBe(true);
    expect(() => registry.resolveCommand(command.commandId, result, command.sessionId)).not.toThrow();
    expect(await registry.waitForResult(command.commandId, { timeoutMs: 50 })).toEqual(result);
  });

  test.each([
    ['path Session', '/v2/agent/sessions/sess-other/commands/cmd-1/result', { hostId: 'host-1', sessionId: 'sess-1' }],
    ['result Session', '/v2/agent/sessions/sess-1/commands/cmd-1/result', { hostId: 'host-1', sessionId: 'sess-other' }],
    ['result Host', '/v2/agent/sessions/sess-1/commands/cmd-1/result', { hostId: 'host-other', sessionId: 'sess-1' }],
    ['command ID', '/v2/agent/sessions/sess-1/commands/cmd-other/result', { hostId: 'host-1', sessionId: 'sess-1' }],
  ])('rejects mismatched %s result and leaves the command pending', async (_name, path, binding) => {
    let ownerLease = registerDirect(registry);
    if (path.startsWith('/v2/agent/sessions/sess-other/')) {
      // The path Session must itself be owned so the mismatch surfaces at result
      // binding validation (400) rather than as an unknown-owner 404.
      const otherSession = registry.register({
        sessionId: 'sess-other', provider: 'pi', projectName: 'p', nameText: 'p', cwd: '/', driverInstanceId: DRIVER_INSTANCE_ID,
      } as Parameters<typeof registry.register>[0]);
      ownerLease = otherSession.ownerLease;
    }
    const command: CommandEnvelope = {
      commandId: 'cmd-1', hostId: 'host-1', sessionId: 'sess-1', type: 'reply', payload: {},
      issuedAt: '2026-06-30T09:59:00Z', expiresAt: '2026-06-30T10:05:00Z', nonce: 'n-1', watchDeviceId: 'watch-1',
    };
    registry.enqueueCommand(command);
    await registry.dequeueCommand('sess-1', 0);
    const response = await fetch(url(path), { method: 'POST', headers: ownerHeaders(ownerLease), body: JSON.stringify({
      commandId: path.includes('cmd-other') ? 'cmd-other' : 'cmd-1', ...binding, accepted: true, status: 'executed',
      updatedAt: '2026-06-30T10:00:00.000Z',
    }) });
    expect(response.status).toBe(400);
    expect(registry.hasPendingCommandWork('sess-1')).toBe(true);
    const valid = { commandId: 'cmd-1', hostId: 'host-1', sessionId: 'sess-1', accepted: true,
      status: 'executed' as const, updatedAt: '2026-06-30T10:00:00.000Z' };
    registry.resolveCommand('cmd-1', valid, 'sess-1');
    expect(await registry.waitForResult('cmd-1', { timeoutMs: 50 })).toEqual(valid);
  });
  test('returns 409 for live owner collision without changing command-facing state', async () => {
    registerDirect(registry);
    const command: CommandEnvelope = {
      commandId: 'cmd-provider', hostId: 'host-1', sessionId: 'sess-1', type: 'reply', payload: {},
      issuedAt: '2026-06-30T09:59:00Z', expiresAt: '2026-06-30T10:05:00Z', nonce: 'n-provider', watchDeviceId: 'watch-1',
    };
    registry.enqueueCommand(command);
    const beforeSession = structuredClone(registry.listSessions()[0]);
    const beforeStore = structuredClone(store.listSessions());

    const response = await fetch(url('/v2/agent/sessions'), {
      method: 'POST', headers: headers(), body: JSON.stringify({
        sessionId: 'sess-1', provider: 'other', projectName: 'other', nameText: 'other', cwd: '/other', driverInstanceId: DRIVER_INSTANCE_ID,
      }),
    });

    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({ error: { code: 'IDENTITY_CONFLICT', retryable: false } });
    expect(registry.listSessions()[0]).toEqual(beforeSession);
    expect(store.listSessions()).toEqual(beforeStore);
    expect(registry.hasPendingCommandWork('sess-1')).toBe(true);
    expect((await registry.dequeueCommand('sess-1', 0))?.commandId).toBe(command.commandId);
  });

  test.each([
    ['message', { message: 'internal detail' }],
    ['reason', { reason: 'driver detail' }],
    ['detail', { detail: 'private detail' }],
    ['error', { error: 'private error' }],
    ['queued', { accepted: true, status: 'queued' }],
    ['delivered', { accepted: true, status: 'delivered' }],
    ['illegal combination', { accepted: false, status: 'executed' }],
    ['non-canonical timestamp', { updatedAt: '2026-06-30T10:00:00Z' }],
  ])('rejects non-terminal or diagnostic command result: %s', async (_label, override) => {
    registerDirect(registry);
    const command: CommandEnvelope = {
      commandId: 'cmd-exact', hostId: 'host-1', sessionId: 'sess-1', type: 'interrupt', payload: {},
      issuedAt: '2026-06-30T09:59:00.000Z', expiresAt: '2026-06-30T10:05:00.000Z', nonce: 'n-exact', watchDeviceId: 'watch-1',
    };
    registry.enqueueCommand(command);
    await registry.dequeueCommand('sess-1', 0);
    const response = await fetch(url('/v2/agent/sessions/sess-1/commands/cmd-exact/result'), {
      method: 'POST', headers: ownerHeaders(), body: JSON.stringify({
        commandId: command.commandId, hostId: command.hostId, sessionId: command.sessionId, accepted: true,
        status: 'executed', updatedAt: '2026-06-30T10:00:00.000Z', ...override,
      }),
    });
    expect(response.status).toBe(400);
    expect(registry.hasPendingCommandWork('sess-1')).toBe(true);
  });

  test('awaits bind readiness and reports an occupied port', async () => {
    const occupied = new AgentAdapterServer({ port: 0, secret, hostId: 'host-1' }, registry);
    await occupied.start();
    const port = Number(new URL(occupied.url).port);
    const conflicting = new AgentAdapterServer({ port, secret, hostId: 'host-1' }, registry);
    try {
      await expect(conflicting.start()).rejects.toMatchObject({ code: 'EADDRINUSE' });
    } finally {
      conflicting.stop();
      occupied.stop();
    }
  });

  test('stop completes an active command long poll without waiting for its timeout', async () => {
    registerDirect(registry);
    const request = fetch(url('/v2/agent/sessions/sess-1/commands?timeout=120000'), {
      method: 'GET',
      headers: ownerHeaders(),
    });
    await Bun.sleep(10);
    server.stop();
    const result = await Promise.race([
      request.then((response) => response.status).catch(() => 0),
      Bun.sleep(500).then(() => -1),
    ]);
    expect(result).not.toBe(-1);
  });

  describe('protocol-4 owner-header enforcement and error envelope (§6)', () => {
    test('owner routes reject missing or malformed owner headers with 400 before parsing', async () => {
      registerDirect(registry);
      const canonical = {
        sessionId: 'sess-1', provider: 'pi', type: 'done', status: 'idle',
        agentText: 'Done', projectName: 'p', workingDirectory: '/', harnessProvider: 'pi', createdAt: '2026-08-07T00:00:01.000Z',
      };
      const cases = [
        ['/v2/agent/sessions/sess-1/events', 'POST', { producerEventId: PRODUCER_EVENT_ID, producerEventOrder: ORDER_1, event: canonical }],
        ['/v2/agent/sessions/sess-1/heartbeat', 'POST', { status: 'working' }],
        ['/v2/agent/sessions/sess-1', 'DELETE', undefined],
        ['/v2/agent/sessions/sess-1/commands?timeout=0', 'GET', undefined],
      ] as const;
      for (const [path, method, body] of cases) {
        const headersOnly = await fetch(url(path), {
          method, headers: { ...headers(), ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
          body: body === undefined ? undefined : JSON.stringify(body),
        });
        expect(headersOnly.status, `${method} ${path} without owner headers`).toBe(400);
        expect(await headersOnly.json()).toEqual({ error: { code: 'INVALID_REQUEST', retryable: false } });
      }
      // Malformed header values are rejected the same way.
      const malformed = await fetch(url('/v2/agent/sessions/sess-1/heartbeat'), {
        method: 'POST', headers: { ...headers(), 'x-ariava-driver-instance': '', 'x-ariava-owner-lease': activeLease },
        body: JSON.stringify({ status: 'working' }),
      });
      expect(malformed.status).toBe(400);
      expect(await malformed.json()).toEqual({ error: { code: 'INVALID_REQUEST', retryable: false } });
    });

    test('a stale or wrong owner lease is rejected with 409 STALE_OWNER (not retryable)', async () => {
      registerDirect(registry);
      const stale = await fetch(url('/v2/agent/sessions/sess-1/heartbeat'), {
        method: 'POST', headers: ownerHeaders('a-different-lease'), body: JSON.stringify({ status: 'working' }),
      });
      expect(stale.status).toBe(409);
      expect(await stale.json()).toEqual({ error: { code: 'STALE_OWNER', retryable: false } });
    });

    test('a second live driver instance registering the same Session gets 409 OWNER_CONFLICT (retryable)', async () => {
      registerDirect(registry);
      const otherInstance = 'AQEBAQEBAQEBAQEBAQEBAQ';
      const conflict = await fetch(url('/v2/agent/sessions'), {
        method: 'POST', headers: headers(), body: JSON.stringify({
          sessionId: 'sess-1', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p', driverInstanceId: otherInstance,
        }),
      });
      expect(conflict.status).toBe(409);
      expect(await conflict.json()).toEqual({ error: { code: 'OWNER_CONFLICT', retryable: true } });
      // The original owner's lease still works: nothing was mutated.
      const stillMine = await fetch(url('/v2/agent/sessions/sess-1/heartbeat'), {
        method: 'POST', headers: ownerHeaders(), body: JSON.stringify({ status: 'working' }),
      });
      expect(stillMine.status).toBe(200);
    });

    test('register 201 returns ownership owned + the exact ownerLease used by owner routes', async () => {
      const register = await fetch(url('/v2/agent/sessions'), {
        method: 'POST', headers: headers(), body: JSON.stringify({
          sessionId: 'lease-holder', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p', driverInstanceId: DRIVER_INSTANCE_ID,
        }),
      });
      expect(register.status).toBe(201);
      const body = await register.json() as { ownership: string; ownerLease: string };
      expect(body.ownership).toBe('owned');
      const heartbeat = await fetch(url('/v2/agent/sessions/lease-holder/heartbeat'), {
        method: 'POST', headers: ownerHeaders(body.ownerLease), body: JSON.stringify({ status: 'working' }),
      });
      expect(heartbeat.status).toBe(200);
    });

    test('Event wire shape: duplicate replay returns the original eventId, order conflicts map to 409 ORDER_CONFLICT', async () => {
      registerDirect(registry);
      const canonical = {
        sessionId: 'sess-1', provider: 'pi', type: 'done', status: 'idle',
        agentText: 'Done', projectName: 'p', workingDirectory: '/', harnessProvider: 'pi', createdAt: '2026-08-07T00:00:01.000Z',
      };
      const wire = { producerEventId: PRODUCER_EVENT_ID, producerEventOrder: ORDER_1, event: canonical };
      const first = await fetch(url('/v2/agent/sessions/sess-1/events'), {
        method: 'POST', headers: ownerHeaders(), body: JSON.stringify(wire),
      });
      expect(first.status).toBe(200);
      const firstBody = await first.json() as { eventId: string; disposition: string };
      expect(firstBody.disposition).toBe('committed');
      const replay = await fetch(url('/v2/agent/sessions/sess-1/events'), {
        method: 'POST', headers: ownerHeaders(), body: JSON.stringify(wire),
      });
      expect(replay.status).toBe(200);
      const replayBody = await replay.json() as { eventId: string; disposition: string };
      expect(replayBody.disposition).toBe('duplicate');
      expect(replayBody.eventId).toBe(firstBody.eventId);
      const orderConflict = await fetch(url('/v2/agent/sessions/sess-1/events'), {
        method: 'POST', headers: ownerHeaders(), body: JSON.stringify({
          producerEventId: PRODUCER_EVENT_ID, producerEventOrder: ORDER_1,
          event: { ...canonical, agentText: 'Different content' },
        }),
      });
      expect(orderConflict.status).toBe(409);
      expect(await orderConflict.json()).toEqual({ error: { code: 'ORDER_CONFLICT', retryable: false } });
    });
  });
});
