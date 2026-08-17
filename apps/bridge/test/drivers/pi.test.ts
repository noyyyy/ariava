import { describe, expect, test } from 'bun:test';
import type { CanonicalSessionState, CommandEnvelope, CommandResult } from '@ariava/protocol';
import type { AgentAdapterClient } from '../../src/agent-adapter/client';
import { CommandDispatchOutcomeUnknownError, AgentAdapterDriver } from '../../src/drivers/pi';
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
    updatedAt: '2026-06-30T10:00:00Z',
  };
}

describe('AgentAdapterDriver', () => {
  test('listSessions returns adapter sessions', async () => {
    const sessions: CanonicalSessionState[] = [buildSession()];
    const adapter: AgentAdapterClient = {
      listSessions: async () => sessions,
      enqueueCommand: () => {},
      waitForResult: async () => undefined,
    } as unknown as AgentAdapterClient;

    const driver = new AgentAdapterDriver(adapter, 'host-1');
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
      updatedAt: '2026-06-30T10:00:01.000Z',
    };

    let enqueued: CommandEnvelope | undefined;
    const adapter: AgentAdapterClient = {
      listSessions: async () => [],
      assertCommandDispatchReady: () => {},
      enqueueCommand: (cmd) => {
        enqueued = cmd;
      },
      waitForResult: async () => resolved,
    } as unknown as AgentAdapterClient;

    const driver = new AgentAdapterDriver(adapter, 'host-1');
    const ctx: DriverCommandContext = { command, session: buildSession() };
    driver.preflightCommandDispatch(ctx);
    driver.releaseCommandDispatch(ctx);
    const result = await driver.executeCommand(ctx);

    expect(enqueued).toBe(command);
    expect(result).toBe(resolved);
  });

  test('executeCommand reports outcome unknown when no authenticated result arrives', async () => {
    const command = buildCommand();
    let enqueued: CommandEnvelope | undefined;
    let abandoned: string | undefined;
    const adapter: AgentAdapterClient = {
      listSessions: async () => [],
      assertCommandDispatchReady: () => {},
      enqueueCommand: (cmd) => { enqueued = cmd; },
      waitForResult: async () => undefined,
      abandonCommand: (commandId) => { abandoned = commandId; },
    } as unknown as AgentAdapterClient;
    const driver = new AgentAdapterDriver(adapter, 'host-1');
    const ctx: DriverCommandContext = { command, session: buildSession() };
    driver.preflightCommandDispatch(ctx);
    driver.releaseCommandDispatch(ctx);
    await expect(driver.executeCommand(ctx)).rejects.toBeInstanceOf(CommandDispatchOutcomeUnknownError);
    expect(enqueued).toBe(command);
    expect(abandoned).toBe(command.commandId);
  });

  test('executeCommand converts result waiter disconnects and throws to outcome uncertainty', async () => {
    const command = buildCommand();
    for (const failure of [new Error('adapter disconnected'), new TypeError('poll canceled')]) {
      let abandoned: string | undefined;
      const adapter = {
        assertCommandDispatchReady: () => {},
        enqueueCommand: () => {},
        waitForResult: async () => { throw failure; },
        abandonCommand: (commandId: string) => { abandoned = commandId; },
      } as unknown as AgentAdapterClient;
      const driver = new AgentAdapterDriver(adapter, 'host-1');
      const ctx: DriverCommandContext = { command, session: buildSession() };
      driver.preflightCommandDispatch(ctx);
      driver.releaseCommandDispatch(ctx);

      await expect(driver.executeCommand(ctx)).rejects.toEqual(new CommandDispatchOutcomeUnknownError());
      expect(abandoned).toBe(command.commandId);
    }
  });
});
