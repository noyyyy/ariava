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
  type CommandEnvelope,
  type CommandResult,
} from '@ariava/protocol';

mock.module('../../src/e2e/node-crypto', () => ({
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

  function headers(): Record<string, string> {
    return {
      authorization: `Bearer ${secret}`,
      'content-type': 'application/json',
      [AGENT_ADAPTER_PROTOCOL_HEADER]: String(AGENT_ADAPTER_PROTOCOL_VERSION),
    };
  }

  test('rejects requests without a bearer token', async () => {
    const response = await fetch(url('/v1/agent/sessions'), { method: 'POST', body: '{}' });
    expect(response.status).toBe(401);
  });

  test('requires the exact Agent Adapter protocol version after authentication', async () => {
    const missing = await fetch(url('/v1/health'), {
      headers: { authorization: `Bearer ${secret}` },
    });
    expect(missing.status).toBe(426);
    const wrong = await fetch(url('/v1/health'), {
      headers: { authorization: `Bearer ${secret}`, [AGENT_ADAPTER_PROTOCOL_HEADER]: '1' },
    });
    expect(wrong.status).toBe(426);
  });

  test('health is authenticated and returns only minimal Host evidence', async () => {
    const unauthenticated = await fetch(url('/v1/health'));
    expect(unauthenticated.status).toBe(401);

    const response = await fetch(url('/v1/health'), { headers: headers() });
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
      const body = await (await fetch(`${degraded.url}/v1/health`, { headers: headers() })).json();
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
    const response = await fetch(url('/v1/agent/sessions'), {
      method: 'POST',
      headers: headers(),
      body: JSON.stringify({
        sessionId: 'sess-1', provider: 'pi', projectName: 'deploy-tools', cwd: '/tmp', nameText: 'Deploy tools',
      }),
    });

    expect(response.status).toBe(201);
    const body = (await response.json()) as { sessionId: string; registeredAt: string };
    expect(body.sessionId).toBe('sess-1');
    expect(typeof body.registeredAt).toBe('string');
  });

  test.each([
    ['project alias', { sessionId: 'legacy-project', provider: 'pi', project: 'p', cwd: '/', nameText: 'p' }],
    ['title alias', { sessionId: 'legacy-title', provider: 'pi', projectName: 'p', cwd: '/', title: 'p' }],
    ['summary alias', { sessionId: 'legacy-summary', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p', summary: 'old' }],
  ])('rejects removed register %s', async (_name, body) => {
    const response = await fetch(url('/v1/agent/sessions'), {
      method: 'POST', headers: headers(), body: JSON.stringify(body),
    });
    expect(response.status).toBe(400);
  });

  test('unregisters a session', async () => {
    registry.register({ sessionId: 'sess-1', provider: 'pi', projectName: 'p', nameText: 'p', cwd: '/' });

    const response = await fetch(url('/v1/agent/sessions/sess-1'), {
      method: 'DELETE',
      headers: headers(),
    });

    expect(response.status).toBe(200);
    expect(registry.listSessions()).toHaveLength(0);
  });

  test('accepts only the exact complete canonical producer DTO', async () => {
    registry.register({ sessionId: 'sess-1', provider: 'pi', projectName: 'p', nameText: 'p', cwd: '/', status: 'working' });
    const canonical = {
      sessionId: 'sess-1', provider: 'pi', type: 'done', status: 'idle',
      agentText: 'Finished', projectName: 'p', contextText: 'p', workingDirectory: '/',
      hbaseSessionKey: 'sess-1', harnessProvider: 'pi', createdAt: '2026-08-07T00:00:01.000Z',
    };

    const accepted = await fetch(url('/v1/agent/sessions/sess-1/events'), {
      method: 'POST', headers: headers(), body: JSON.stringify(canonical),
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
  ])('rejects %s without mutating the Session', async (_name, body) => {
    registry.register({ sessionId: 'sess-1', provider: 'pi', projectName: 'p', nameText: 'p', cwd: '/', status: 'working' });
    const before = registry.listSessions()[0];
    const response = await fetch(url('/v1/agent/sessions/sess-1/events'), {
      method: 'POST', headers: headers(), body: JSON.stringify(body),
    });
    expect(response.status).toBe(400);
    expect(registry.listSessions()[0]).toEqual(before);
    expect(store.peekPendingEvents()).toEqual([]);
  });

  test('handles a session and rejects the removed read route', async () => {
    registry.register({ sessionId: 'sess-1', provider: 'pi', projectName: 'p', nameText: 'p', cwd: '/' });

    const canonical = (agentText: string, createdAt: string) => ({
      sessionId: 'sess-1', provider: 'pi', type: 'done', status: 'idle',
      agentText, projectName: 'p', contextText: 'p', workingDirectory: '/',
      hbaseSessionKey: 'sess-1', harnessProvider: 'pi', createdAt,
    });
    const eventId = registry.pushEvent('sess-1', canonical('First', '2026-07-16T00:00:02.000Z'));
    const response = await fetch(url('/v1/agent/sessions/sess-1/handle'), {
      method: 'POST', headers: headers(),
      body: JSON.stringify({ handledThroughEventId: eventId, handledAt: '2026-07-16T00:00:02Z', action: 'pi_input' }),
    });
    expect(response.status).toBe(200);
    expect(store.peekPendingSessionHandles()[0]).toMatchObject({
      handledThroughEventId: eventId, handledThroughEventCreatedAt: '2026-07-16T00:00:02.000Z', action: 'pi_input',
    });

    const removed = await fetch(url('/v1/agent/sessions/sess-1/read'), {
      method: 'POST', headers: headers(),
      body: JSON.stringify({ latestReadEventId: eventId, readAt: '2026-07-16T00:00:03Z', source: 'bridge_recovery' }),
    });
    expect(removed.status).toBe(404);

    for (const legacyBody of [
      { handledThroughEventId: eventId, latestReadEventId: eventId },
      { handledThroughEventId: eventId, action: 'watch_reply' },
      { handledThroughEventId: eventId, actorId: 'host-spoofed' },
      { handledThroughEventId: eventId, handledByIdentityId: 'host-spoofed' },
    ]) {
      const rejected = await fetch(url('/v1/agent/sessions/sess-1/handle'), {
        method: 'POST', headers: headers(), body: JSON.stringify(legacyBody),
      });
      expect(rejected.status).toBe(400);
    }
  });

  test('heartbeats update session status', async () => {
    registry.register({ sessionId: 'sess-1', provider: 'pi', projectName: 'p', nameText: 'p', cwd: '/' });

    const response = await fetch(url('/v1/agent/sessions/sess-1/heartbeat'), {
      method: 'POST',
      headers: headers(),
      body: JSON.stringify({ status: 'working', latestActivityText: 'Still running' }),
    });

    expect(response.status).toBe(200);
    const session = registry.listSessions()[0];
    expect(session?.status).toBe('working');
    expect(session?.latestActivityText).toBe('Still running');
  });

  test('rejects the removed heartbeat summary alias', async () => {
    registry.register({ sessionId: 'sess-alias', provider: 'pi', projectName: 'p', nameText: 'p', cwd: '/' });
    const response = await fetch(url('/v1/agent/sessions/sess-alias/heartbeat'), {
      method: 'POST', headers: headers(), body: JSON.stringify({ status: 'working', summary: 'legacy' }),
    });
    expect(response.status).toBe(400);
  });

  test('heartbeat JSON null explicitly clears optional semantic text', async () => {
    registry.register({
      sessionId: 'sess-clear', provider: 'pi', projectName: 'p', nameText: 'p', cwd: '/',
      openingText: 'Old task', latestActivityText: 'Old activity',
    });

    const response = await fetch(url('/v1/agent/sessions/sess-clear/heartbeat'), {
      method: 'POST',
      headers: headers(),
      body: JSON.stringify({ status: 'idle', openingText: null, latestActivityText: null }),
    });

    expect(response.status).toBe(200);
    const session = registry.listSessions()[0];
    expect(session?.openingText).toBeUndefined();
    expect(session?.latestActivityText).toBeUndefined();
  });

  test('returns enqueued command during short poll', async () => {
    registry.register({ sessionId: 'sess-1', provider: 'pi', projectName: 'p', nameText: 'p', cwd: '/' });

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
    const response = await fetch(url('/v1/agent/sessions/sess-1/commands?timeout=0'), {
      method: 'GET',
      headers: headers(),
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as { command: CommandEnvelope };
    expect(body.command.commandId).toBe('cmd-1');
  });

  test('returns 204 immediately when no command is queued during short poll', async () => {
    registry.register({ sessionId: 'sess-1', provider: 'pi', projectName: 'p', nameText: 'p', cwd: '/' });

    const startedAt = Date.now();
    const response = await fetch(url('/v1/agent/sessions/sess-1/commands?timeout=0'), {
      method: 'GET',
      headers: headers(),
    });

    expect(response.status).toBe(204);
    expect(Date.now() - startedAt).toBeLessThan(200);
  });

  test('submits command result', async () => {
    registry.register({ sessionId: 'sess-1', provider: 'pi', projectName: 'p', nameText: 'p', cwd: '/' });

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
      message: 'Done',
      updatedAt: '2026-06-30T10:00:00Z',
    };

    const response = await fetch(url('/v1/agent/sessions/sess-1/commands/cmd-1/result'), {
      method: 'POST',
      headers: headers(),
      body: JSON.stringify(result),
    });

    expect(response.status).toBe(200);
    const resolved = await registry.waitForResult('cmd-1', { timeoutMs: 50 });
    expect(resolved).toEqual(result);
  });

  test.each([
    ['path Session', '/v1/agent/sessions/sess-other/commands/cmd-1/result', { hostId: 'host-1', sessionId: 'sess-1' }],
    ['result Session', '/v1/agent/sessions/sess-1/commands/cmd-1/result', { hostId: 'host-1', sessionId: 'sess-other' }],
    ['result Host', '/v1/agent/sessions/sess-1/commands/cmd-1/result', { hostId: 'host-other', sessionId: 'sess-1' }],
    ['command ID', '/v1/agent/sessions/sess-1/commands/cmd-other/result', { hostId: 'host-1', sessionId: 'sess-1' }],
  ])('rejects mismatched %s result and leaves the command pending', async (_name, path, binding) => {
    registry.register({ sessionId: 'sess-1', provider: 'pi', projectName: 'p', nameText: 'p', cwd: '/' });
    const command: CommandEnvelope = {
      commandId: 'cmd-1', hostId: 'host-1', sessionId: 'sess-1', type: 'reply', payload: {},
      issuedAt: '2026-06-30T09:59:00Z', expiresAt: '2026-06-30T10:05:00Z', nonce: 'n-1', watchDeviceId: 'watch-1',
    };
    registry.enqueueCommand(command);
    await registry.dequeueCommand('sess-1', 0);
    const response = await fetch(url(path), { method: 'POST', headers: headers(), body: JSON.stringify({
      commandId: path.includes('cmd-other') ? 'cmd-other' : 'cmd-1', ...binding, accepted: true, status: 'executed',
      message: 'Done', updatedAt: '2026-06-30T10:00:00Z',
    }) });
    expect(response.status).toBe(400);
    expect(registry.hasPendingCommandWork('sess-1')).toBe(true);
    const valid = { commandId: 'cmd-1', hostId: 'host-1', sessionId: 'sess-1', accepted: true,
      status: 'executed' as const, message: 'Done', updatedAt: '2026-06-30T10:00:00Z' };
    registry.resolveCommand('cmd-1', valid, 'sess-1');
    expect(await registry.waitForResult('cmd-1', { timeoutMs: 50 })).toEqual(valid);
  });
  test('rejects provider rebinding and accepts a valid retry', async () => {
    registry.register({ sessionId: 'sess-1', provider: 'pi', projectName: 'p', nameText: 'p', cwd: '/' });
    const command: CommandEnvelope = {
      commandId: 'cmd-provider', hostId: 'host-1', sessionId: 'sess-1', type: 'reply', payload: {},
      issuedAt: '2026-06-30T09:59:00Z', expiresAt: '2026-06-30T10:05:00Z', nonce: 'n-provider', watchDeviceId: 'watch-1',
    };
    registry.enqueueCommand(command);
    await registry.dequeueCommand('sess-1', 0);
    registry.register({ sessionId: 'sess-1', provider: 'other', projectName: 'p', nameText: 'p', cwd: '/' });
    const result = { commandId: command.commandId, hostId: command.hostId, sessionId: command.sessionId, accepted: true,
      status: 'executed' as const, message: 'Done', updatedAt: '2026-06-30T10:00:00Z' };
    expect(() => registry.resolveCommand(command.commandId, result, 'sess-1')).toThrow(/registered Session/u);
    expect(registry.hasPendingCommandWork('sess-1')).toBe(true);
    registry.register({ sessionId: 'sess-1', provider: 'pi', projectName: 'p', nameText: 'p', cwd: '/' });
    expect(() => registry.resolveCommand(command.commandId, result, 'sess-1')).not.toThrow();
    expect(await registry.waitForResult(command.commandId, { timeoutMs: 50 })).toEqual(result);
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
    registry.register({ sessionId: 'sess-1', provider: 'pi', projectName: 'p', nameText: 'p', cwd: '/' });
    const request = fetch(url('/v1/agent/sessions/sess-1/commands?timeout=120000'), {
      method: 'GET',
      headers: headers(),
    });
    await Bun.sleep(10);
    server.stop();
    const result = await Promise.race([
      request.then((response) => response.status).catch(() => 0),
      Bun.sleep(500).then(() => -1),
    ]);
    expect(result).not.toBe(-1);
  });

});
