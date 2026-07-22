import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AgentAdapterClient } from '../../src/agent-adapter/client';
import { AgentAdapterRegistry } from '../../src/agent-adapter/registry';
import { AgentAdapterServer } from '../../src/agent-adapter/server';
import { BridgeStateStore } from '../../src/state-store';
import type { CommandEnvelope, CommandResult } from '@ariava/protocol';

describe('AgentAdapterServer', () => {
  let dir: string;
  let store: BridgeStateStore;
  let registry: AgentAdapterRegistry;
  let server: AgentAdapterServer;
  let secret: string;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'bridge-server-'));
    store = new BridgeStateStore(join(dir, 'state.json'));
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
    };
  }

  test('rejects requests without a bearer token', async () => {
    const response = await fetch(url('/v1/agent/sessions'), { method: 'POST', body: '{}' });
    expect(response.status).toBe(401);
  });

  test('health is authenticated and returns only minimal Host evidence', async () => {
    const unauthenticated = await fetch(url('/v1/health'));
    expect(unauthenticated.status).toBe(401);

    const response = await fetch(url('/v1/health'), { headers: headers() });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true, hostId: 'host-1' });
  });

  test('registers a session', async () => {
    const response = await fetch(url('/v1/agent/sessions'), {
      method: 'POST',
      headers: headers(),
      body: JSON.stringify({ sessionId: 'sess-1', provider: 'pi', project: 'deploy-tools', cwd: '/tmp' }),
    });

    expect(response.status).toBe(201);
    const body = (await response.json()) as { sessionId: string; registeredAt: string };
    expect(body.sessionId).toBe('sess-1');
    expect(typeof body.registeredAt).toBe('string');
  });

  test('unregisters a session', async () => {
    registry.register({ sessionId: 'sess-1', provider: 'pi', project: 'p', cwd: '/' });

    const response = await fetch(url('/v1/agent/sessions/sess-1'), {
      method: 'DELETE',
      headers: headers(),
    });

    expect(response.status).toBe(200);
    expect(registry.listSessions()).toHaveLength(0);
  });

  test('pushes an event for a registered session', async () => {
    registry.register({ sessionId: 'sess-1', provider: 'pi', project: 'p', cwd: '/' });

    const response = await fetch(url('/v1/agent/sessions/sess-1/events'), {
      method: 'POST',
      headers: headers(),
      body: JSON.stringify({ type: 'working', status: 'working', assistantText: 'Running' }),
    });

    expect(response.status).toBe(200);
    const pending = store.peekPendingEvents();
    expect(pending).toHaveLength(1);
    expect(pending[0]?.type).toBe('working');
  });

  test('handles a session and keeps read as a bounded trusted-source alias', async () => {
    registry.register({ sessionId: 'sess-1', provider: 'pi', project: 'p', cwd: '/' });

    const response = await fetch(url('/v1/agent/sessions/sess-1/handle'), {
      method: 'POST', headers: headers(),
      body: JSON.stringify({ handledThroughEventId: 'evt-2', handledAt: '2026-07-16T00:00:02Z', action: 'pi_input' }),
    });
    expect(response.status).toBe(200);
    expect(store.peekPendingSessionHandles()[0]).toMatchObject({ handledThroughEventId: 'evt-2', action: 'pi_input' });

    const alias = await fetch(url('/v1/agent/sessions/sess-1/read'), {
      method: 'POST', headers: headers(),
      body: JSON.stringify({ latestReadEventId: 'evt-3', readAt: '2026-07-16T00:00:03Z', source: 'bridge_recovery' }),
    });
    expect(alias.status).toBe(200);
    expect(store.peekPendingSessionHandles()[0]).toMatchObject({ handledThroughEventId: 'evt-3', action: 'bridge_recovery' });

    const rejected = await fetch(url('/v1/agent/sessions/sess-1/read'), {
      method: 'POST', headers: headers(),
      body: JSON.stringify({ latestReadEventId: 'evt-4', source: 'watch_view' }),
    });
    expect(rejected.status).toBe(500);
    expect(store.peekPendingSessionHandles()[0]?.handledThroughEventId).toBe('evt-3');
  });

  test('heartbeats update session status', async () => {
    registry.register({ sessionId: 'sess-1', provider: 'pi', project: 'p', cwd: '/' });

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

  test('heartbeat JSON null explicitly clears optional semantic text', async () => {
    registry.register({
      sessionId: 'sess-clear', provider: 'pi', project: 'p', cwd: '/',
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
    registry.register({ sessionId: 'sess-1', provider: 'pi', project: 'p', cwd: '/' });

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
    registry.register({ sessionId: 'sess-1', provider: 'pi', project: 'p', cwd: '/' });

    const startedAt = Date.now();
    const response = await fetch(url('/v1/agent/sessions/sess-1/commands?timeout=0'), {
      method: 'GET',
      headers: headers(),
    });

    expect(response.status).toBe(204);
    expect(Date.now() - startedAt).toBeLessThan(200);
  });

  test('submits command result', async () => {
    registry.register({ sessionId: 'sess-1', provider: 'pi', project: 'p', cwd: '/' });

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
    registry.register({ sessionId: 'sess-1', provider: 'pi', project: 'p', cwd: '/' });
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
