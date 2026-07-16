import { describe, expect, test } from 'bun:test';
import type { CanonicalSessionState, CommandEnvelope, CommandResult } from '@ariava/protocol';
import type { AgentAdapterClient } from '../../src/agent-adapter/client';
import { PaiDriver, timeoutResult } from '../../src/drivers/pi';
import type { DriverCommandContext } from '../../src/types';

function buildCommand(overrides: Partial<CommandEnvelope> = {}): CommandEnvelope {
  return {
    commandId: 'cmd-1',
    hostId: 'host-1',
    sessionId: 'sess-1',
    type: 'reply',
    payload: { text: 'Continue' },
    issuedAt: '2026-06-30T10:00:00Z',
    expiresAt: '2026-06-30T10:05:00Z',
    nonce: 'nonce-1',
    watchDeviceId: 'watch-1',
    ...overrides,
  };
}

function buildSession(): CanonicalSessionState {
  return {
    sessionId: 'sess-1',
    hostId: 'host-1',
    provider: 'pi',
    projectName: 'demo',
    nameText: 'Demo session',
    status: 'working',
    latestActivityText: 'working',
    stateLabel: 'In progress',
    updatedAt: '2026-06-30T10:00:00Z',
  };
}

describe('PaiDriver', () => {
  test('listSessions returns adapter sessions', async () => {
    const sessions: CanonicalSessionState[] = [buildSession()];
    const adapter: AgentAdapterClient = {
      listSessions: async () => sessions,
      enqueueCommand: () => {},
      waitForResult: async () => undefined,
    } as unknown as AgentAdapterClient;

    const driver = new PaiDriver(adapter, 'host-1');
    expect(await driver.listSessions('host-1')).toEqual(sessions);
  });

  test('executeCommand enqueues command and returns resolved result', async () => {
    const command = buildCommand();
    const resolved: CommandResult = {
      commandId: command.commandId,
      hostId: command.hostId,
      sessionId: command.sessionId,
      accepted: true,
      status: 'executed',
      message: 'Sent to pi',
      updatedAt: '2026-06-30T10:00:01Z',
    };

    let enqueued: CommandEnvelope | undefined;
    const adapter: AgentAdapterClient = {
      listSessions: async () => [],
      enqueueCommand: (cmd) => {
        enqueued = cmd;
      },
      waitForResult: async () => resolved,
    } as unknown as AgentAdapterClient;

    const driver = new PaiDriver(adapter, 'host-1');
    const ctx: DriverCommandContext = { command, session: buildSession() };
    const result = await driver.executeCommand(ctx);

    expect(enqueued).toBe(command);
    expect(result).toEqual(resolved);
  });

  test('executeCommand returns timeout result when no result arrives', async () => {
    const command = buildCommand();
    let enqueued: CommandEnvelope | undefined;
    const adapter: AgentAdapterClient = {
      listSessions: async () => [],
      enqueueCommand: (cmd) => {
        enqueued = cmd;
      },
      waitForResult: async () => undefined,
    } as unknown as AgentAdapterClient;

    const driver = new PaiDriver(adapter, 'host-1');
    const ctx: DriverCommandContext = { command, session: buildSession() };
    const result = await driver.executeCommand(ctx);

    expect(enqueued).toBe(command);
    expect(result.status).toBe('failed');
    expect(result.accepted).toBe(false);
    expect(result.message).toContain('did not respond');
  });

  test('timeoutResult helper builds expected failed result', () => {
    const command = buildCommand();
    const result = timeoutResult(command);

    expect(result.commandId).toBe(command.commandId);
    expect(result.hostId).toBe(command.hostId);
    expect(result.sessionId).toBe(command.sessionId);
    expect(result.accepted).toBe(false);
    expect(result.status).toBe('failed');
    expect(result.updatedAt).toMatch(/\d{4}-/);
  });
});
