import { afterEach, beforeEach, describe, expect, mock, test } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AgentAdapterRegistry } from '../../src/agent-adapter/registry';
import { AgentAdapterServer } from '../../src/agent-adapter/server';
import { BridgeStateStore } from '../../src/state-store';
import { AGENT_ADAPTER_LIMITS } from '../../src/agent-adapter/registry-types';
import { AGENT_ADAPTER_PROTOCOL_HEADER, AGENT_ADAPTER_PROTOCOL_VERSION } from '@ariava/protocol';

mock.module('../../src/e2e/node-crypto', () => ({
  ChaChaPolyAuthenticationError: class ChaChaPolyAuthenticationError extends Error {},
  chachaPolySeal: (_key: Uint8Array, plaintext: Uint8Array) => ({
    nonce: new Uint8Array(12).fill(1), ciphertext: new Uint8Array([...plaintext, ...new Uint8Array(16)]),
  }),
  chachaPolyOpen: (_key: Uint8Array, _nonce: Uint8Array, ciphertext: Uint8Array) => ciphertext.slice(0, -16),
}));

const CAP = AGENT_ADAPTER_LIMITS.requestBodyBytes;

/** 16 zero bytes as unpadded base64url: a valid protocol-4 driver instance id. */
const DRIVER_INSTANCE_ID = 'AAAAAAAAAAAAAAAAAAAAAA';
/** JSON whose raw UTF-8 byte length is exactly `byteLength` bytes. */
function jsonBodyOfExactBytes(byteLength: number): string {
  const prefix = '{"sessionId":"';
  const suffix = '"}';
  const pad = byteLength - Buffer.byteLength(prefix) - Buffer.byteLength(suffix);
  if (pad < 0) throw new Error(`cannot build a ${byteLength}-byte JSON body`);
  return `${prefix}${'x'.repeat(pad)}${suffix}`;
}

function validRegisterBody(sessionId = 'sess-1'): string {
  return JSON.stringify({
    sessionId, provider: 'pi', projectName: 'project', cwd: '/project', nameText: 'Task', status: 'working', driverInstanceId: DRIVER_INSTANCE_ID,
  });
}

describe('AgentAdapterServer request body cap (§3.4)', () => {
  let dir: string;
  let store: BridgeStateStore;
  let registry: AgentAdapterRegistry;
  let server: AgentAdapterServer;
  let secret: string;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'bridge-body-limit-'));
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

  function headers(): Record<string, string> {
    return {
      authorization: `Bearer ${secret}`,
      'content-type': 'application/json',
      [AGENT_ADAPTER_PROTOCOL_HEADER]: String(AGENT_ADAPTER_PROTOCOL_VERSION),
    };
  }

  function rawPost(body: Buffer, overrides: Record<string, string> = {}): Promise<{ status: number; body: string }> {
    return new Promise((resolve, reject) => {
      const req = httpRequest(url('/v2/agent/sessions'), {
        method: 'POST',
        headers: { ...headers(), ...overrides },
      }, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body: data }));
      });
      req.on('error', reject);
      req.write(body);
      req.end();
    });
  }

  test('reads a request body at exactly the 256 KiB cap (validation proceeds)', async () => {
    const body = jsonBodyOfExactBytes(CAP);
    expect(Buffer.byteLength(body)).toBe(CAP);
    const response = await fetch(url('/v2/agent/sessions'), { method: 'POST', headers: headers(), body });
    // Read and parsed successfully; route-level validation then fails on missing keys -> 400, not 413.
    expect(response.status).toBe(400);
    expect(await response.text()).not.toContain('exceeds');
  });

  test('rejects one byte over the cap with 413 before any mutation', async () => {
    const body = jsonBodyOfExactBytes(CAP + 1);
    const response = await fetch(url('/v2/agent/sessions'), { method: 'POST', headers: headers(), body });
    expect(response.status).toBe(413);
    expect(registry.listSessions()).toEqual([]);
    expect(store.peekPendingUploads()).toEqual([]);
  });

  test('rejects chunked bodies that overflow the cap with 413', async () => {
    const chunk = Buffer.alloc(CAP / 2, 'a');
    const overflow = Buffer.from('b');
    const response = await new Promise<{ status: number; body: string }>((resolve, reject) => {
      const req = httpRequest(url('/v2/agent/sessions'), {
        method: 'POST',
        headers: { ...headers(), 'transfer-encoding': 'chunked' },
      }, (res) => {
        let data = '';
        res.on('data', (c) => { data += c; });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body: data }));
      });
      req.on('error', reject);
      req.write(chunk);
      req.write(chunk);
      req.write(overflow);
      req.end();
    });
    expect(response.status).toBe(413);
    expect(registry.listSessions()).toEqual([]);
  });

  test('enforces the cap on actual accumulated bytes even when Content-Length is present', async () => {
    const body = Buffer.from(jsonBodyOfExactBytes(CAP + 1024));
    const response = await rawPost(body, { 'content-length': String(body.byteLength) });
    expect(response.status).toBe(413);
    expect(registry.listSessions()).toEqual([]);
  });

  test('stays healthy and stops accumulating/parsing after an overflow', async () => {
    const oversized = jsonBodyOfExactBytes(CAP + 1);
    const rejected = await fetch(url('/v2/agent/sessions'), { method: 'POST', headers: headers(), body: oversized });
    expect(rejected.status).toBe(413);
    const accepted = await fetch(url('/v2/agent/sessions'), { method: 'POST', headers: headers(), body: validRegisterBody() });
    expect(accepted.status).toBe(201);
  });

  test('maps oversized canonical Event content to 400 (not 500) before any spool mutation', async () => {
    const registered = await fetch(url('/v2/agent/sessions'), { method: 'POST', headers: headers(), body: validRegisterBody() });
    expect(registered.status).toBe(201);
    const { ownerLease } = await registered.json() as { ownerLease: string };
    const oversizedEvent = JSON.stringify({
      sessionId: 'sess-1', provider: 'pi', type: 'done', status: 'idle',
      agentText: 'a'.repeat(64 * 1024),
      projectName: 'project', workingDirectory: '/project', harnessProvider: 'pi',
      createdAt: '2026-08-07T00:00:01.000Z',
    });
    const response = await fetch(url('/v2/agent/sessions/sess-1/events'), {
      method: 'POST', headers: { ...headers(),
        'x-ariava-driver-instance': DRIVER_INSTANCE_ID, 'x-ariava-owner-lease': ownerLease },
      body: JSON.stringify({
        producerEventId: 'AAAAAAAAAAAAAAAAAAAAAA', producerEventOrder: '00000000000000000000000000000001', event: JSON.parse(oversizedEvent),
      }),
    });
    expect(response.status).toBe(400);
    expect(store.peekPendingUploads()).toEqual([]);
  });

  test('rejects malformed UTF-8 with 400 (never lossily accepted) before any mutation', async () => {
    // A byte-complete JSON skeleton whose string value contains a lone 0xFF byte:
    // a lossy utf8 decode would replace it with U+FFFD and accept the body as
    // a (misshapen) register request; the fatal decoder must reject it first.
    const malformed = Buffer.concat([
      Buffer.from('{"sessionId":"sess-'),
      Buffer.from([0xff]),
      Buffer.from('","provider":"pi","projectName":"p","nameText":"n","status":"working","cwd":"/x"}'),
    ]);
    const response = await rawPost(malformed);
    expect(response.status).toBe(400);
    expect(JSON.parse(response.body)).toEqual({ error: { code: 'INVALID_REQUEST', retryable: false } });
    expect(registry.listSessions()).toEqual([]);
    expect(store.peekPendingUploads()).toEqual([]);
  });

  test('responds 413 immediately once the cap is exceeded mid-stream, before the client finishes its body', async () => {
    const chunk = Buffer.alloc(CAP / 2, 'a');
    const overflow = Buffer.from('b');
    let request: import('node:http').ClientRequest | undefined;
    const responsePromise = new Promise<{ status: number; body: string }>((resolve, reject) => {
      request = httpRequest(url('/v2/agent/sessions'), {
        method: 'POST', headers: { ...headers(), 'transfer-encoding': 'chunked' },
      }, (res) => {
        let data = '';
        res.on('data', (c) => { data += c; });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body: data }));
      });
      request.on('error', reject);
      request.write(chunk);
      request.write(chunk);
      request.write(overflow);
      // NOTE: req.end() is intentionally NOT called — the server must answer now.
    });
    const timed = await Promise.race([
      responsePromise,
      new Promise<{ status: number; body: string }>((resolve) => setTimeout(() => resolve({ status: -1, body: 'timeout' }), 3_000)),
    ]);
    expect(timed.status).toBe(413);
    expect(registry.listSessions()).toEqual([]);
    request?.destroy();
  });

  test('enforces well-formed ≤256 UTF-8-byte identifiers in bodies and paths before mutation', async () => {
    const exactMultibyte = 'é'.repeat(128);
    const accepted = await fetch(url('/v2/agent/sessions'), { method: 'POST', headers: headers(), body: validRegisterBody(exactMultibyte) });
    expect(accepted.status).toBe(201);
    expect(registry.hasSession(exactMultibyte)).toBe(true);

    const overMultibyte = 'é'.repeat(129);
    const oversizedBody = await fetch(url('/v2/agent/sessions'), { method: 'POST', headers: headers(), body: validRegisterBody(overMultibyte) });
    expect(oversizedBody.status).toBe(400);
    expect(registry.hasSession(overMultibyte)).toBe(false);

    const loneSurrogateBody = await fetch(url('/v2/agent/sessions'), {
      method: 'POST', headers: headers(), body: validRegisterBody('\ud800'),
    });
    expect(loneSurrogateBody.status).toBe(400);
    expect(registry.listSessions()).toHaveLength(1);

    const oversizedPath = await fetch(url(`/v2/agent/sessions/${'x'.repeat(257)}/heartbeat`), {
      method: 'POST', headers: headers(), body: JSON.stringify({ status: 'working' }),
    });
    expect(oversizedPath.status).toBe(400);
    expect(registry.listSessions()).toHaveLength(1);
    expect(store.peekPendingUploads()).toEqual([]);
  });

  test('rejects encoded, double-encoded, and malformed slash path identities before mutation', async () => {
    const nativeId = 'a/b';
    expect((await fetch(url('/v2/agent/sessions'), { method: 'POST', headers: headers(), body: validRegisterBody(nativeId) })).status).toBe(201);
    for (const pathId of ['a%2Fb', 'a%2fb', 'a%252Fb', 'a%ZZb']) {
      const response = await fetch(url(`/v2/agent/sessions/${pathId}`), { method: 'DELETE', headers: headers() });
      expect(response.status).toBe(400);
      expect(registry.hasSession(nativeId)).toBe(true);
    }
    expect(registry.listSessions()).toHaveLength(1);
    expect(store.peekPendingUploads()).toEqual([]);
  });
});
