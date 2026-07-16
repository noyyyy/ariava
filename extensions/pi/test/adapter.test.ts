import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { CommandEnvelope, CommandResult } from '@ariava/protocol';
import type { AgentAdapterRegistry } from '../../../apps/bridge/src/agent-adapter/registry';
import { AgentAdapterClient } from '../src/adapter';
import type { PiSessionInfo } from '../src/session';

describe('AgentAdapterClient', () => {
  let dir: string;
  let secret: string;
  let baseUrl: string;
  let client: AgentAdapterClient;
  let registry: AgentAdapterRegistry;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'pi-adapter-'));
    secret = 'test-secret';

    const { AgentAdapterRegistry: Registry } = await import('../../../apps/bridge/src/agent-adapter/registry');
    const { AgentAdapterServer } = await import('../../../apps/bridge/src/agent-adapter/server');
    const { BridgeStateStore } = await import('../../../apps/bridge/src/state-store');

    const store = new BridgeStateStore(join(dir, 'state.json'));
    registry = new Registry('host-1', store);
    const server = new AgentAdapterServer({ port: 0, secret, hostId: 'host-1' }, registry);
    server.start();
    baseUrl = server.url;

    client = new AgentAdapterClient({ baseUrl, secret });

    afterEach(() => {
      server.stop();
      rmSync(dir, { recursive: true, force: true });
    });
  });

  function makeSession(sessionId: string): PiSessionInfo {
    return {
      sessionId,
      provider: 'pi',
      projectName: 'demo',
      cwd: '/tmp/demo',
      nameText: 'Demo session',
      openingText: 'Start task',
      latestActivityText: 'Working',
      stateLabel: 'Unknown',
      status: 'unknown',
      pid: 1234,
    };
  }

  test('registerSession', async () => {
    const result = await client.registerSession(makeSession('sess-1'));
    expect(result.sessionId).toBe('sess-1');
    expect(typeof result.registeredAt).toBe('string');
  });

  test('unregisterSession', async () => {
    await client.registerSession(makeSession('sess-1'));
    await client.unregisterSession('sess-1');
    expect(registry.listSessions()).toHaveLength(0);
  });

  test('pushEvent', async () => {
    const session = makeSession('sess-1');
    await client.registerSession(session);

    const result = await client.pushEvent({
      sessionId: session.sessionId,
      type: 'working',
      status: 'working',
      assistantText: 'Running tests',
    });

    expect(typeof result.eventId).toBe('string');
  });

  test('handleSession', async () => {
    const session = makeSession('sess-1');
    await client.registerSession(session);
    const result = await client.handleSession(session.sessionId, {
      handledThroughEventId: 'evt-1', handledAt: '2026-07-16T00:00:00Z', action: 'pi_input',
    });
    expect(result).toMatchObject({ ok: true, hostId: 'host-1', sessionId: 'sess-1', handledThroughEventId: 'evt-1' });
  });

  test('heartbeat', async () => {
    const session = makeSession('sess-1');
    await client.registerSession(session);
    await expect(client.heartbeat(session.sessionId, 'working', 'Busy')).resolves.toBeUndefined();
  });

  test('pollCommands returns enqueued command', async () => {
    const { AgentAdapterClient: BridgeClient } = await import('../../../apps/bridge/src/agent-adapter/client');
    const bridgeClient = new BridgeClient(registry);

    const command: CommandEnvelope = {
      commandId: 'cmd-1',
      hostId: 'host-1',
      sessionId: 'sess-1',
      type: 'reply',
      payload: { text: 'Continue' },
      issuedAt: '2026-06-30T10:00:00Z',
      expiresAt: '2026-06-30T10:05:00Z',
      nonce: 'n1',
      watchDeviceId: 'watch-1',
    };

    await client.registerSession(makeSession('sess-1'));

    const poll = client.pollCommands('sess-1', 500);
    await new Promise((resolve) => setTimeout(resolve, 50));
    bridgeClient.enqueueCommand(command);

    const resolved = await poll;
    expect(resolved?.commandId).toBe('cmd-1');
  });

  test('submitResult', async () => {
    await client.registerSession(makeSession('sess-1'));

    const result: CommandResult = {
      commandId: 'cmd-1',
      hostId: 'host-1',
      sessionId: 'sess-1',
      accepted: true,
      status: 'executed',
      message: 'done',
      updatedAt: '2026-06-30T10:00:00Z',
    };

    await client.submitResult('cmd-1', result);
    const resolved = await registry.waitForResult('cmd-1', { timeoutMs: 100 });
    expect(resolved).toEqual(result);
  });

  test('reads discovery file', async () => {
    const configPath = join(dir, 'agent-adapter.json');
    writeFileSync(configPath, JSON.stringify({ url: baseUrl, secret }));

    const fileClient = new AgentAdapterClient({ configPath });
    const result = await fileClient.registerSession(makeSession('sess-2'));
    expect(result.sessionId).toBe('sess-2');
  });

  test('reloads discovery file after adapter auth is rejected', async () => {
    const configPath = join(dir, 'agent-adapter.json');
    writeFileSync(configPath, JSON.stringify({ url: baseUrl, secret: 'stale-secret' }));

    const fileClient = new AgentAdapterClient({ configPath });
    await expect(fileClient.heartbeat('sess-1', 'working', 'Busy')).rejects.toThrow('Unauthorized');

    await client.registerSession(makeSession('sess-1'));
    writeFileSync(configPath, JSON.stringify({ url: baseUrl, secret }));

    await expect(fileClient.heartbeat('sess-1', 'working', 'Busy')).resolves.toBeUndefined();
  });
});
