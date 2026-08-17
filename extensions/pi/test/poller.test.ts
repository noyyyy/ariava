import { afterEach, describe, expect, test } from 'bun:test';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { CommandEnvelope } from '@ariava/protocol';
import type {
  AgentAdapter,
  AgentAdapterCommandResult,
  CommandExecutionOutcome,
} from '../src/adapter-interface';
import { startCommandPoller } from '../src/poller';

const originalLogPath = process.env.ARIAVA_PI_LOG_PATH;
const temporaryDirectories: string[] = [];

afterEach(() => {
  if (originalLogPath === undefined) delete process.env.ARIAVA_PI_LOG_PATH;
  else process.env.ARIAVA_PI_LOG_PATH = originalLogPath;
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function makeCommand(overrides: Partial<CommandEnvelope> = {}): CommandEnvelope {
  return {
    commandId: 'cmd-1', hostId: 'host-1', sessionId: 'session-1', type: 'reply', payload: { text: 'Continue' },
    issuedAt: '2026-08-12T00:00:00.000Z', expiresAt: '2026-08-12T00:01:00.000Z',
    nonce: 'n', watchDeviceId: 'watch-1', ...overrides,
  };
}

function rejected(command = makeCommand()): AgentAdapterCommandResult {
  return {
    commandId: command.commandId,
    hostId: command.hostId,
    sessionId: command.sessionId,
    accepted: false,
    status: 'rejected',
    updatedAt: '2026-08-12T00:00:01.000Z',
  };
}

function executed(command = makeCommand()): AgentAdapterCommandResult {
  return {
    commandId: command.commandId,
    hostId: command.hostId,
    sessionId: command.sessionId,
    accepted: true,
    status: 'executed',
    updatedAt: '2026-08-12T00:00:01.000Z',
  };
}

function terminal(command = makeCommand()): CommandExecutionOutcome {
  return { kind: 'terminal', result: rejected(command) };
}

async function waitFor(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (predicate()) return;
    await Bun.sleep(5);
  }
  throw new Error('Timed out waiting for poller condition');
}

function captureLog(): string {
  const directory = mkdtempSync(join(tmpdir(), 'pi-poller-log-'));
  temporaryDirectories.push(directory);
  const path = join(directory, 'extension.log');
  process.env.ARIAVA_PI_LOG_PATH = path;
  return path;
}

describe('startCommandPoller', () => {
  test('submits only an exact deterministic pre-call rejection', async () => {
    const command = makeCommand();
    const submitted: AgentAdapterCommandResult[] = [];
    let polls = 0;
    const adapter = {
      pollCommands: async () => (++polls === 1 ? command : null),
      submitResult: async (_commandId: string, result: AgentAdapterCommandResult) => { submitted.push(result); },
    } as unknown as AgentAdapter;
    const poller = startCommandPoller({
      sessionId: command.sessionId,
      client: adapter,
      onCommand: async () => terminal(command),
    }, 10);
    await waitFor(() => submitted.length === 1);
    poller.stop();
    expect(submitted).toEqual([rejected(command)]);
  });

  test('submits an executed result exactly once', async () => {
    const command = makeCommand();
    const submitted: AgentAdapterCommandResult[] = [];
    let polls = 0;
    const adapter = {
      pollCommands: async () => (++polls === 1 ? command : null),
      submitResult: async (_commandId: string, result: AgentAdapterCommandResult) => { submitted.push(result); },
    } as unknown as AgentAdapter;
    const poller = startCommandPoller({
      sessionId: command.sessionId,
      client: adapter,
      onCommand: async () => ({ kind: 'terminal', result: executed(command) }),
    }, 10);
    await waitFor(() => submitted.length === 1);
    await Bun.sleep(30);
    poller.stop();
    expect(submitted).toEqual([executed(command)]);
  });

  test('outcome_unknown submits no wire result and releases local dequeue state', async () => {
    const command = makeCommand();
    let polls = 0;
    let submissions = 0;
    const abandoned: string[] = [];
    const adapter = {
      pollCommands: async () => (++polls === 1 ? command : null),
      submitResult: async () => { submissions += 1; },
      abandonCommand: (commandId: string) => abandoned.push(commandId),
    } as unknown as AgentAdapter;
    const poller = startCommandPoller({
      sessionId: command.sessionId,
      client: adapter,
      onCommand: async () => ({ kind: 'outcome_unknown' }),
    }, 10);
    await waitFor(() => abandoned.length === 1);
    poller.stop();
    expect(submissions).toBe(0);
    expect(abandoned).toEqual([command.commandId]);
  });

  test('handler throw after dequeue never fabricates or retries a result', async () => {
    const logPath = captureLog();
    const command = makeCommand({ payload: { text: 'private text' } });
    let polls = 0;
    let submissions = 0;
    const abandoned: string[] = [];
    const adapter = {
      pollCommands: async () => (++polls === 1 ? command : null),
      submitResult: async () => { submissions += 1; },
      abandonCommand: (commandId: string) => abandoned.push(commandId),
    } as unknown as AgentAdapter;
    const poller = startCommandPoller({
      sessionId: command.sessionId,
      client: adapter,
      onCommand: async () => { throw new Error('private driver error'); },
    }, 10);
    await waitFor(() => existsSync(logPath));
    poller.stop();
    expect(submissions).toBe(0);
    expect(abandoned).toEqual([command.commandId]);
    const capture = readFileSync(logPath, 'utf8');
    expect(capture).toContain('command_dispatch_failed');
    expect(capture).not.toContain('private text');
    expect(capture).not.toContain('private driver error');
  });

  test.each([
    ['failed', { kind: 'terminal', result: { ...rejected(), status: 'failed' } }],
    ['unknown wire status', { kind: 'terminal', result: { ...rejected(), status: 'outcome_unknown' } }],
    ['diagnostic field', { kind: 'terminal', result: { ...rejected(), message: 'private result' } }],
  ])('does not submit forbidden %s outcomes', async (_label, invalid) => {
    const logPath = captureLog();
    let polls = 0;
    let submissions = 0;
    const adapter = {
      pollCommands: async () => (++polls === 1 ? makeCommand() : null),
      submitResult: async () => { submissions += 1; },
      abandonCommand: () => undefined,
    } as unknown as AgentAdapter;
    const poller = startCommandPoller({
      sessionId: 'session-1',
      client: adapter,
      onCommand: async () => invalid as unknown as CommandExecutionOutcome,
    }, 10);
    await waitFor(() => existsSync(logPath));
    poller.stop();
    expect(submissions).toBe(0);
    expect(readFileSync(logPath, 'utf8')).toContain('command_result_invalid');
    expect(readFileSync(logPath, 'utf8')).not.toContain('private result');
  });

  test('result submission is attempted once and never replayed after rejection', async () => {
    const logPath = captureLog();
    let polls = 0;
    let submitAttempts = 0;
    const adapter = {
      pollCommands: async () => (++polls === 1 ? makeCommand() : null),
      submitResult: async () => { submitAttempts += 1; throw new Error('late unknown'); },
    } as unknown as AgentAdapter;
    const poller = startCommandPoller({
      sessionId: 'session-1', client: adapter, onCommand: async () => terminal(),
    }, 10);
    await waitFor(() => existsSync(logPath));
    await Bun.sleep(30);
    poller.stop();
    expect(submitAttempts).toBe(1);
    expect(readFileSync(logPath, 'utf8')).toContain('command_result_submit_failed');
  });

  test('stop during a possible side effect suppresses result submission', async () => {
    const command = makeCommand();
    let polls = 0;
    let started = false;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let submissions = 0;
    const abandoned: string[] = [];
    const adapter = {
      pollCommands: async () => (++polls === 1 ? command : null),
      submitResult: async () => { submissions += 1; },
      abandonCommand: (commandId: string) => abandoned.push(commandId),
    } as unknown as AgentAdapter;
    const poller = startCommandPoller({
      sessionId: command.sessionId,
      client: adapter,
      onCommand: async () => { started = true; await gate; return terminal(command); },
    }, 10);
    await waitFor(() => started);
    poller.stop();
    release();
    await waitFor(() => abandoned.length === 1);
    expect(submissions).toBe(0);
  });
});
