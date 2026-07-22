import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import type { CommandEnvelope, CommandResult } from '@ariava/protocol';
import type { AgentAdapterRegistry } from '../../../apps/bridge/src/agent-adapter/registry';
import { AgentAdapterClient, resolveAgentAdapterConfigPath } from '../src/adapter';
import type { PiSessionInfo } from '../src/session';

describe('AgentAdapterClient', () => {
  let dir: string;
  let secret: string;
  let baseUrl: string;
  let client: AgentAdapterClient;
  let registry: AgentAdapterRegistry;
  let stopServer: (() => void) | undefined;

  const originalDiscoveryPath = process.env.ARIAVA_AGENT_ADAPTER_CONFIG_PATH;
  beforeEach(async () => {
    delete process.env.ARIAVA_AGENT_ADAPTER_CONFIG_PATH;
    dir = mkdtempSync(join(tmpdir(), 'pi-adapter-'));
    secret = 'test-secret';

    const { AgentAdapterRegistry: Registry } = await import('../../../apps/bridge/src/agent-adapter/registry');
    const { AgentAdapterServer } = await import('../../../apps/bridge/src/agent-adapter/server');
    const { BridgeStateStore } = await import('../../../apps/bridge/src/state-store');

    const store = new BridgeStateStore(join(dir, 'state.json'));
    registry = new Registry('host-1', store);
    const server = new AgentAdapterServer({ port: 0, secret, hostId: 'host-1' }, registry);
    await server.start();
    stopServer = () => server.stop();
    baseUrl = server.url;

    client = new AgentAdapterClient({ baseUrl, secret });
  });

  afterEach(() => {
    stopServer?.();
    stopServer = undefined;
    rmSync(dir, { recursive: true, force: true });
    if (originalDiscoveryPath === undefined) {
      delete process.env.ARIAVA_AGENT_ADAPTER_CONFIG_PATH;
    } else {
      process.env.ARIAVA_AGENT_ADAPTER_CONFIG_PATH = originalDiscoveryPath;
    }
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
      stateLabel: 'Ready',
      status: 'idle',
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

  test('heartbeat updates an idle session to working', async () => {
    const session = makeSession('sess-1');
    await client.registerSession(session);
    expect(registry.listSessions()[0]?.status).toBe('idle');

    await expect(client.heartbeat(session.sessionId, 'working', 'Busy')).resolves.toBeUndefined();
    expect(registry.listSessions()[0]).toMatchObject({ status: 'working', latestActivityText: 'Busy' });
  });

  test('heartbeat full semantic snapshot explicitly clears optional branch text', async () => {
    const session = makeSession('sess-clear');
    await client.registerSession(session);
    await client.heartbeat(session.sessionId, 'idle', null, {
      ...session,
      openingText: undefined,
      latestActivityText: undefined,
    });

    expect(registry.listSessions()[0]).toMatchObject({ status: 'idle' });
    expect(registry.listSessions()[0]?.openingText).toBeUndefined();
    expect(registry.listSessions()[0]?.latestActivityText).toBeUndefined();
  });

  test('heartbeat re-registers and retries semantic update after a Bridge registry restart', async () => {
    const session = makeSession('sess-restart');
    await client.registerSession(session);
    registry.unregister(session.sessionId);

    await expect(client.heartbeat(session.sessionId, 'working', 'Recovered activity', {
      ...session,
      status: 'working',
      latestActivityText: 'Recovered activity',
    })).resolves.toBeUndefined();

    expect(registry.listSessions()[0]).toMatchObject({
      sessionId: session.sessionId, status: 'working', latestActivityText: 'Recovered activity',
    });
  });

  test('command polling re-registers after a Bridge registry restart', async () => {
    const session = makeSession('sess-poll-restart');
    await client.registerSession(session);
    registry.unregister(session.sessionId);

    await expect(client.pollCommands(session.sessionId, 0, session)).resolves.toBeNull();
    expect(registry.listSessions()[0]).toMatchObject({ sessionId: session.sessionId, status: 'idle' });
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

  test('explicit discovery path takes precedence over environment selection', async () => {
    const explicitConfigPath = join(dir, 'explicit-agent-adapter.json');
    writeFileSync(explicitConfigPath, JSON.stringify({ url: baseUrl, secret }));
    process.env.ARIAVA_AGENT_ADAPTER_CONFIG_PATH = join(dir, 'missing-environment-discovery.json');

    const fileClient = new AgentAdapterClient({ configPath: explicitConfigPath });
    const result = await fileClient.registerSession(makeSession('sess-explicit'));

    expect(result.sessionId).toBe('sess-explicit');
  });

  test('reads discovery path selected from the process environment', async () => {
    const environmentConfigPath = join(dir, 'environment-agent-adapter.json');
    writeFileSync(environmentConfigPath, JSON.stringify({ url: baseUrl, secret }));
    process.env.ARIAVA_AGENT_ADAPTER_CONFIG_PATH = environmentConfigPath;

    const fileClient = new AgentAdapterClient();
    const result = await fileClient.registerSession(makeSession('sess-environment'));

    expect(result.sessionId).toBe('sess-environment');
  });

  test('uses the production discovery path when the environment selection is absent or empty', () => {
    delete process.env.ARIAVA_AGENT_ADAPTER_CONFIG_PATH;
    const defaultPath = join(homedir(), '.config', 'ariava', 'agent-adapter.json');
    expect(resolveAgentAdapterConfigPath()).toBe(defaultPath);

    process.env.ARIAVA_AGENT_ADAPTER_CONFIG_PATH = '   ';
    expect(resolveAgentAdapterConfigPath()).toBe(defaultPath);
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

  test('reloads the same environment-selected discovery file after a 401', async () => {
    const environmentConfigPath = join(dir, 'dev-agent-adapter.json');
    writeFileSync(environmentConfigPath, JSON.stringify({ url: baseUrl, secret: 'stale-secret' }));
    process.env.ARIAVA_AGENT_ADAPTER_CONFIG_PATH = environmentConfigPath;

    const fileClient = new AgentAdapterClient();
    await expect(fileClient.heartbeat('sess-1', 'working', 'Busy')).rejects.toThrow('Unauthorized');

    await client.registerSession(makeSession('sess-1'));
    writeFileSync(environmentConfigPath, JSON.stringify({ url: baseUrl, secret }));
    process.env.ARIAVA_AGENT_ADAPTER_CONFIG_PATH = join(dir, 'production-agent-adapter.json');

    await expect(fileClient.heartbeat('sess-1', 'working', 'Busy')).resolves.toBeUndefined();
  });
});
