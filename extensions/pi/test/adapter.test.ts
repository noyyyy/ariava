import { afterEach, describe, expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  AGENT_ADAPTER_PROTOCOL_HEADER,
  AGENT_ADAPTER_PROTOCOL_VERSION,
  isAgentAdapterProducerEventId,
  isAgentAdapterProducerEventOrder,
  producerEventOrderAsBigInt,
  type CommandEnvelope,
} from '@ariava/protocol';
import {
  AGENT_ADAPTER_OWNER_HEADERS,
  AGENT_ADAPTER_REQUEST_BODY_BYTES,
  AgentAdapterClient,
  resolveAgentAdapterConfigPath,
} from '../src/adapter';
import type { PiSessionInfo } from '../src/session';

const originalFetch = globalThis.fetch;
const originalDiscoveryPath = process.env.ARIAVA_AGENT_ADAPTER_CONFIG_PATH;
const temporaryDirectories: string[] = [];

afterEach(() => {
  globalThis.fetch = originalFetch;
  if (originalDiscoveryPath === undefined) delete process.env.ARIAVA_AGENT_ADAPTER_CONFIG_PATH;
  else process.env.ARIAVA_AGENT_ADAPTER_CONFIG_PATH = originalDiscoveryPath;
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function makeSession(sessionId = 'session-1'): PiSessionInfo {
  return {
    sessionId, provider: 'pi', projectName: 'demo', cwd: '/tmp/demo', nameText: 'Demo session',
    openingText: 'Start task', latestActivityText: 'Working', status: 'idle', pid: 1234,
  };
}

function makeCommand(sessionId = 'session-1', commandId = 'command-1'): CommandEnvelope {
  return {
    commandId, hostId: 'host-1', sessionId, type: 'reply', payload: { text: 'Continue' },
    issuedAt: '2026-08-12T00:00:00.000Z', expiresAt: '2026-08-12T00:01:00.000Z',
    nonce: 'nonce-1', watchDeviceId: 'watch-1',
  };
}

function discovery(secret = 'secret') {
  return {
    url: 'http://127.0.0.1:7272',
    secret,
    protocolVersion: AGENT_ADAPTER_PROTOCOL_VERSION,
    provider: 'pi' as const,
    profileId: 'profile-1',
    hostId: 'host-1',
  };
}

const OWNER_LEASE_A = Buffer.alloc(32, 1).toString('base64url');
const OWNER_LEASE_B = Buffer.alloc(32, 2).toString('base64url');

function registerResponse(sessionId = 'session-1', ownerLease = OWNER_LEASE_A): Response {
  return jsonResponse(201, {
    sessionId,
    registeredAt: '2026-08-12T00:00:00.000Z',
    ownership: 'owned',
    ownerLease,
  });
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

type CapturedRequest = {
  method: string;
  path: string;
  headers: Headers;
  body?: unknown;
};

function captureRequests(responder: (request: CapturedRequest, index: number) => Response | Promise<Response>) {
  const requests: CapturedRequest[] = [];
  globalThis.fetch = (async (input, init) => {
    const request: CapturedRequest = {
      method: init?.method ?? 'GET',
      path: `${new URL(String(input)).pathname}${new URL(String(input)).search}`,
      headers: new Headers(init?.headers),
      body: init?.body === undefined ? undefined : JSON.parse(String(init.body)),
    };
    requests.push(request);
    return responder(request, requests.length - 1);
  }) as typeof fetch;
  return requests;
}

function expectOwnerHeaders(request: CapturedRequest, expectedLease: string, expectedInstance?: string): string {
  expect(request.headers.get(AGENT_ADAPTER_PROTOCOL_HEADER)).toBe('4');
  expect(request.headers.get(AGENT_ADAPTER_OWNER_HEADERS.ownerLease)).toBe(expectedLease);
  const instance = request.headers.get(AGENT_ADAPTER_OWNER_HEADERS.driverInstance);
  expect(instance).toMatch(/^[A-Za-z0-9_-]{22}$/);
  if (expectedInstance !== undefined) expect(instance).toBe(expectedInstance);
  return instance!;
}

describe('AgentAdapterClient protocol-4 transport', () => {
  test('uses only /v2 and binds every owner route to one stable driver instance and lease', async () => {
    const lease = OWNER_LEASE_A;
    const command = makeCommand();
    const requests = captureRequests((_request, index) => {
      if (index === 0) return registerResponse(command.sessionId, lease);
      if (index === 1) return jsonResponse(200, { ok: true });
      if (index === 2) return jsonResponse(200, {
        ok: true, hostId: command.hostId, sessionId: command.sessionId, handledThroughEventId: 'event-1',
      });
      if (index === 3) return jsonResponse(200, { command });
      if (index === 4) return jsonResponse(200, { ok: true });
      return jsonResponse(200, { ok: true });
    });
    const client = new AgentAdapterClient({ baseUrl: discovery().url, secret: discovery().secret });
    await client.registerSession(makeSession());
    await client.heartbeat(command.sessionId, 'working', 'Busy');
    await client.handleSession(command.sessionId, { handledThroughEventId: 'event-1' });
    await client.pollCommands(command.sessionId, 0);
    await client.submitResult(command.commandId, {
      commandId: command.commandId, hostId: command.hostId, sessionId: command.sessionId,
      accepted: false, status: 'rejected', updatedAt: '2026-08-12T00:00:01.000Z',
    });
    await client.unregisterSession(command.sessionId);

    expect(requests.map((request) => request.path)).toEqual([
      '/v2/agent/sessions',
      '/v2/agent/sessions/session-1/heartbeat',
      '/v2/agent/sessions/session-1/handle',
      '/v2/agent/sessions/session-1/commands?timeout=0',
      '/v2/agent/sessions/session-1/commands/command-1/result',
      '/v2/agent/sessions/session-1',
    ]);
    expect(requests.every((request) => !request.path.includes('/v1/'))).toBe(true);
    expect((requests[0]!.body as Record<string, unknown>).driverInstanceId).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(requests[0]!.headers.has(AGENT_ADAPTER_OWNER_HEADERS.ownerLease)).toBe(false);
    const instance = expectOwnerHeaders(requests[1]!, lease);
    for (const request of requests.slice(2)) expectOwnerHeaders(request, lease, instance);
    expect(requests[2]!.body).toEqual({ handledThroughEventId: 'event-1', action: 'local_input' });
  });

  test('re-register and heartbeat recovery reuse the same driver instance and adopt the successor lease', async () => {
    const firstLease = OWNER_LEASE_A;
    const secondLease = OWNER_LEASE_B;
    const requests = captureRequests((_request, index) => {
      if (index === 0) return registerResponse('session-1', firstLease);
      if (index === 1) return jsonResponse(409, { error: { code: 'STALE_OWNER', retryable: false } });
      if (index === 2) return registerResponse('session-1', secondLease);
      return jsonResponse(200, { ok: true });
    });
    const client = new AgentAdapterClient({ baseUrl: discovery().url, secret: discovery().secret });
    const session = makeSession();
    await client.registerSession(session);
    await client.heartbeat(session.sessionId, 'working', 'Recovered', session);

    const firstInstance = (requests[0]!.body as Record<string, string>).driverInstanceId;
    expect((requests[2]!.body as Record<string, string>).driverInstanceId).toBe(firstInstance);
    expectOwnerHeaders(requests[1]!, firstLease, firstInstance);
    expectOwnerHeaders(requests[3]!, secondLease, firstInstance);
  });

  test('poll never reacquires or replays after SESSION_NOT_FOUND', async () => {
    const requests = captureRequests((_request, index) => index === 0
      ? registerResponse()
      : jsonResponse(404, { error: { code: 'SESSION_NOT_FOUND', retryable: false } }));
    const client = new AgentAdapterClient({ baseUrl: discovery().url, secret: discovery().secret });
    await client.registerSession(makeSession());
    await expect(client.pollCommands('session-1', 0)).rejects.toThrow('failed: 404');
    expect(requests).toHaveLength(2);
    expect(requests.filter((request) => request.path === '/v2/agent/sessions')).toHaveLength(1);
  });

  test.each([
    ['poll', async (client: AgentAdapterClient) => client.pollCommands('session-1', 0)],
    ['handle', async (client: AgentAdapterClient) => client.handleSession('session-1', { handledThroughEventId: 'event-1' })],
    ['unregister', async (client: AgentAdapterClient) => client.unregisterSession('session-1')],
  ])('%s transport failure is attempted exactly once', async (_label, operation) => {
    let attempts = 0;
    globalThis.fetch = (async () => {
      attempts += 1;
      if (attempts === 1) return registerResponse();
      throw new Error('transport uncertain');
    }) as typeof fetch;
    const client = new AgentAdapterClient({ baseUrl: discovery().url, secret: discovery().secret });
    await client.registerSession(makeSession());
    await expect(operation(client)).rejects.toThrow('transport uncertain');
    expect(attempts).toBe(2);
  });

  test('a dequeued command result never switches to a successor lease', async () => {
    const oldLease = OWNER_LEASE_A;
    const newLease = OWNER_LEASE_B;
    const command = makeCommand();
    const requests = captureRequests((_request, index) => {
      if (index === 0) return registerResponse(command.sessionId, oldLease);
      if (index === 1) return jsonResponse(200, { command });
      if (index === 2) return registerResponse(command.sessionId, newLease);
      return jsonResponse(409, { error: { code: 'COMMAND_OUTCOME_UNKNOWN', retryable: false } });
    });
    const client = new AgentAdapterClient({ baseUrl: discovery().url, secret: discovery().secret });
    const session = makeSession();
    await client.registerSession(session);
    await client.pollCommands(session.sessionId, 0);
    await client.registerSession(session);
    await expect(client.submitResult(command.commandId, {
      commandId: command.commandId, hostId: command.hostId, sessionId: command.sessionId,
      accepted: false, status: 'rejected', updatedAt: '2026-08-12T00:00:01.000Z',
    })).resolves.toBeUndefined();
    expectOwnerHeaders(requests[3]!, oldLease);
    expect(requests).toHaveLength(4);
  });

  test('Event publication sends owner-bound v2 bodies once with valid increasing in-memory order', async () => {
    const requests = captureRequests((request, index) => {
      if (index === 0) return registerResponse();
      const body = request.body as { producerEventId: string; producerEventOrder: string };
      return jsonResponse(200, {
        eventId: `event-${index}`,
        producerEventId: body.producerEventId,
        producerEventOrder: body.producerEventOrder,
        disposition: 'committed',
      });
    });
    const client = new AgentAdapterClient({ baseUrl: discovery().url, secret: discovery().secret });
    await client.registerSession(makeSession());
    expect(client.eventPublicationEnabled).toBe(true);
    const event = {
      sessionId: 'session-1', provider: 'pi' as const, type: 'done' as const, status: 'idle' as const,
      agentText: 'Done', createdAt: '2026-08-12T00:00:00.000Z',
    };
    await expect(client.pushEvent(event)).resolves.toEqual({ eventId: 'event-1' });
    await expect(client.pushEvent({ ...event, createdAt: '2026-08-12T00:00:01.000Z' }))
      .resolves.toEqual({ eventId: 'event-2' });

    expect(requests.map((request) => request.path)).toEqual([
      '/v2/agent/sessions',
      '/v2/agent/sessions/session-1/events',
      '/v2/agent/sessions/session-1/events',
    ]);
    const instance = expectOwnerHeaders(requests[1]!, OWNER_LEASE_A);
    expectOwnerHeaders(requests[2]!, OWNER_LEASE_A, instance);
    const first = requests[1]!.body as { producerEventId: string; producerEventOrder: string; event: unknown };
    const second = requests[2]!.body as { producerEventId: string; producerEventOrder: string; event: unknown };
    expect(isAgentAdapterProducerEventId(first.producerEventId)).toBe(true);
    expect(isAgentAdapterProducerEventId(second.producerEventId)).toBe(true);
    expect(isAgentAdapterProducerEventOrder(first.producerEventOrder)).toBe(true);
    expect(isAgentAdapterProducerEventOrder(second.producerEventOrder)).toBe(true);
    expect(producerEventOrderAsBigInt(first.producerEventOrder)! >= (1n << 127n)).toBe(true);
    expect(producerEventOrderAsBigInt(second.producerEventOrder)! > producerEventOrderAsBigInt(first.producerEventOrder)!).toBe(true);
    expect(first.event).toEqual(event);
  });

  test.each([
    ['transport uncertainty', () => { throw new Error('transport uncertain'); }, 'transport uncertain'],
    ['ORDER_CONFLICT', () => jsonResponse(409, { error: { code: 'ORDER_CONFLICT', retryable: false } }), 'failed: 409'],
  ])('Event %s is attempted once without retry', async (_label, failure, expectedError) => {
    let requests = 0;
    globalThis.fetch = (async () => {
      requests += 1;
      if (requests === 1) return registerResponse();
      return failure();
    }) as typeof fetch;
    const client = new AgentAdapterClient({ baseUrl: discovery().url, secret: discovery().secret });
    await client.registerSession(makeSession());
    await expect(client.pushEvent({
      sessionId: 'session-1', provider: 'pi', type: 'done', status: 'idle', agentText: 'Done',
      createdAt: '2026-08-12T00:00:00.000Z',
    })).rejects.toThrow(expectedError);
    expect(requests).toBe(2);
  });

  test('producer preflight permits exact 256 KiB and rejects cap+1 before fetch', async () => {
    let fetches = 0;
    globalThis.fetch = (async () => { fetches += 1; return jsonResponse(200, {}); }) as typeof fetch;
    const client = new AgentAdapterClient({ baseUrl: discovery().url, secret: discovery().secret });
    const bodyAt = (bytes: number) => ({ value: 'x'.repeat(bytes - '{"value":""}'.length) });
    await expect((client as any).requestWithDiscovery(discovery(), 'POST', '/test', bodyAt(AGENT_ADAPTER_REQUEST_BODY_BYTES)))
      .resolves.toBeInstanceOf(Response);
    await expect((client as any).requestWithDiscovery(discovery(), 'POST', '/test', bodyAt(AGENT_ADAPTER_REQUEST_BODY_BYTES + 1)))
      .rejects.toThrow('256 KiB');
    expect(fetches).toBe(1);
  });
});

describe('AgentAdapterClient discovery', () => {
  test('accepts exactly six Pi keys and rejects missing, unknown, wrong provider/version, and non-loopback files before network', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'pi-discovery-'));
    temporaryDirectories.push(directory);
    const path = join(directory, 'agent-adapter.json');
    let networkRequests = 0;
    globalThis.fetch = (async () => { networkRequests += 1; return registerResponse(); }) as typeof fetch;

    writeFileSync(path, JSON.stringify(discovery()));
    await expect(new AgentAdapterClient({ configPath: path }).registerSession(makeSession())).resolves.toMatchObject({ sessionId: 'session-1' });
    expect(networkRequests).toBe(1);

    const invalid = [
      { url: discovery().url, secret: 'secret', protocolVersion: 4, provider: 'pi', profileId: 'profile-1' },
      { ...discovery(), extra: true },
      { ...discovery(), provider: 'codex' },
      { ...discovery(), protocolVersion: 3 },
      { ...discovery(), url: 'http://example.com:7272' },
    ];
    for (const candidate of invalid) {
      writeFileSync(path, JSON.stringify(candidate));
      await expect(new AgentAdapterClient({ configPath: path }).registerSession(makeSession()))
        .rejects.toThrow('Invalid agent adapter discovery file');
    }
    expect(networkRequests).toBe(1);
  });

  test('401 heartbeat rereads discovery, re-registers with the same instance, then retries safely', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'pi-discovery-rotate-'));
    temporaryDirectories.push(directory);
    const path = join(directory, 'agent-adapter.json');
    writeFileSync(path, JSON.stringify(discovery('old-secret')));
    const requests = captureRequests((_request, index) => {
      if (index === 0) return registerResponse();
      if (index === 1) {
        writeFileSync(path, JSON.stringify(discovery('new-secret')));
        return jsonResponse(401, { error: { code: 'UNAUTHORIZED', retryable: false } });
      }
      if (index === 2) return registerResponse('session-1', OWNER_LEASE_B);
      return jsonResponse(200, { ok: true });
    });
    const client = new AgentAdapterClient({ configPath: path });
    const session = makeSession();
    await client.registerSession(session);
    await client.heartbeat(session.sessionId, 'working', 'Busy', session);
    const instance = (requests[0]!.body as Record<string, string>).driverInstanceId;
    expect((requests[2]!.body as Record<string, string>).driverInstanceId).toBe(instance);
    expect(requests[0]!.headers.get('authorization')).toBe('Bearer old-secret');
    expect(requests[2]!.headers.get('authorization')).toBe('Bearer new-secret');
    expect(requests[3]!.headers.get('authorization')).toBe('Bearer new-secret');
  });

  test('resolves explicit, environment, and default discovery paths', () => {
    const explicit = '/tmp/explicit-agent-adapter.json';
    process.env.ARIAVA_AGENT_ADAPTER_CONFIG_PATH = '/tmp/environment-agent-adapter.json';
    expect(resolveAgentAdapterConfigPath(explicit)).toBe(explicit);
    expect(resolveAgentAdapterConfigPath()).toBe('/tmp/environment-agent-adapter.json');
    process.env.ARIAVA_AGENT_ADAPTER_CONFIG_PATH = '   ';
    expect(resolveAgentAdapterConfigPath()).toBe(join(homedir(), '.config', 'ariava', 'agent-adapter.json'));
  });

  test('lease remains in memory and is absent from discovery and register body', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'pi-discovery-memory-'));
    temporaryDirectories.push(directory);
    const path = join(directory, 'agent-adapter.json');
    writeFileSync(path, JSON.stringify(discovery()));
    const requests = captureRequests(() => registerResponse());
    const client = new AgentAdapterClient({ configPath: path });
    await client.registerSession(makeSession());
    expect(readFileSync(path, 'utf8')).toBe(JSON.stringify(discovery()));
    expect(requests[0]!.body).not.toHaveProperty('ownerLease');
    expect(requests[0]!.body).not.toHaveProperty('profileId');
    expect(requests[0]!.body).not.toHaveProperty('hostId');
  });
});
