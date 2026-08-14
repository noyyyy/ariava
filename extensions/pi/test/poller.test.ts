import { afterEach, describe, expect, test } from 'bun:test';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { CommandEnvelope } from '@ariava/protocol';
import type { AgentAdapter, AgentAdapterCommandResult } from '../src/adapter-interface';
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
    commandId: 'cmd-1',
    hostId: 'host-1',
    sessionId: 'session-1',
    type: 'reply',
    payload: { text: 'Continue' },
    issuedAt: '2026-08-12T00:00:00.000Z',
    expiresAt: '2026-08-12T00:01:00.000Z',
    nonce: 'n',
    watchDeviceId: 'watch-1',
    ...overrides,
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
  test('dispatches and submits the exact terminal result', async () => {
    const command = makeCommand();
    const submitted: AgentAdapterCommandResult[] = [];
    let callCount = 0;
    const adapter = {
      pollCommands: async () => (++callCount === 1 ? command : null),
      submitResult: async (_commandId: string, result: AgentAdapterCommandResult) => {
        submitted.push(result);
      },
    } as unknown as AgentAdapter;
    const dispatched: CommandEnvelope[] = [];
    const poller = startCommandPoller({
      sessionId: command.sessionId,
      client: adapter,
      onCommand: async (polled) => {
        dispatched.push(polled);
        return executed(polled);
      },
    }, 10);

    await waitFor(() => submitted.length === 1);
    poller.stop();

    expect(dispatched).toEqual([command]);
    expect(submitted).toEqual([executed(command)]);
    expect(Object.keys(submitted[0]!).sort()).toEqual([
      'accepted', 'commandId', 'hostId', 'sessionId', 'status', 'updatedAt',
    ]);
  });

  test('waits after an empty poll and uses immediate server checks', async () => {
    const command = makeCommand();
    const intervals: number[] = [];
    const timeouts: number[] = [];
    let callCount = 0;
    let submitted = false;
    const adapter = {
      pollCommands: async (_sessionId: string, timeoutMs: number) => {
        timeouts.push(timeoutMs);
        intervals.push(Date.now());
        callCount += 1;
        if (callCount === 1) return null;
        return callCount === 2 ? command : null;
      },
      submitResult: async () => { submitted = true; },
    } as unknown as AgentAdapter;
    const poller = startCommandPoller({
      sessionId: command.sessionId,
      client: adapter,
      onCommand: async () => executed(command),
    }, 20);

    await waitFor(() => submitted);
    poller.stop();

    expect(timeouts.length).toBeGreaterThanOrEqual(2);
    expect(timeouts.every((timeout) => timeout === 0)).toBe(true);
    expect(intervals.length).toBeGreaterThanOrEqual(2);
    expect(intervals[1]! - intervals[0]!).toBeGreaterThanOrEqual(15);
  });

  test('invalid dequeued commands are not dispatched and log no untrusted command fields', async () => {
    const logPath = captureLog();
    const invalid = {
      ...makeCommand(),
      commandId: 'plaintext-shaped-untrusted-id',
      payload: { text: 'invalid command plaintext' },
      extra: 'ciphertext_private_marker',
    } as unknown as CommandEnvelope;
    let polls = 0;
    let dispatched = false;
    const adapter = {
      pollCommands: async () => (++polls === 1 ? invalid : null),
      submitResult: async () => undefined,
    } as unknown as AgentAdapter;
    const poller = startCommandPoller({
      sessionId: 'session-1',
      client: adapter,
      onCommand: async () => {
        dispatched = true;
        return executed();
      },
    }, 10);

    await waitFor(() => existsSync(logPath));
    poller.stop();

    expect(dispatched).toBe(false);
    expect(JSON.parse(readFileSync(logPath, 'utf8'))).toEqual({ event: 'command_dispatch_failed' });
  });

  test('throw after dequeue never submits a fabricated failed result and logs no private text', async () => {
    const logPath = captureLog();
    const command = makeCommand({ payload: { text: 'command plaintext marker' } });
    let polls = 0;
    let submissions = 0;
    const adapter = {
      pollCommands: async () => (++polls === 1 ? command : null),
      submitResult: async () => { submissions += 1; },
    } as unknown as AgentAdapter;
    const poller = startCommandPoller({
      sessionId: command.sessionId,
      client: adapter,
      onCommand: async () => { throw new Error('private driver error marker'); },
    }, 10);

    await waitFor(() => existsSync(logPath));
    poller.stop();

    expect(submissions).toBe(0);
    const capture = readFileSync(logPath, 'utf8');
    expect(capture).toContain('command_dispatch_failed');
    expect(capture).toContain(command.commandId);
    expect(capture).not.toContain('command plaintext marker');
    expect(capture).not.toContain('private driver error marker');
  });

  test.each([
    ['diagnostic field', { ...executed(), message: 'private result text' }],
    ['queued status', { ...executed(), status: 'queued' }],
    ['delivered status', { ...executed(), status: 'delivered' }],
    ['unknown status', { ...executed(), status: 'unknown' }],
    ['correlation field', { ...executed(), correlationId: 'correlation-1' }],
  ])('rejects %s returned by a command handler without submitting', async (_label, invalid) => {
    const logPath = captureLog();
    let polls = 0;
    let submissions = 0;
    const adapter = {
      pollCommands: async () => (++polls === 1 ? makeCommand() : null),
      submitResult: async () => { submissions += 1; },
    } as unknown as AgentAdapter;
    const poller = startCommandPoller({
      sessionId: 'session-1',
      client: adapter,
      onCommand: async () => invalid as AgentAdapterCommandResult,
    }, 10);

    await waitFor(() => existsSync(logPath));
    poller.stop();

    expect(submissions).toBe(0);
    const capture = readFileSync(logPath, 'utf8');
    expect(capture).toContain('command_result_invalid');
    expect(capture).not.toContain('private result text');
  });

  test('late result submission rejection logs only the event code and opaque command ID', async () => {
    const logPath = captureLog();
    const command = makeCommand({ payload: { text: 'late command plaintext' } });
    let polls = 0;
    let submitAttempted = false;
    const adapter = {
      pollCommands: async () => (++polls === 1 ? command : null),
      submitResult: async () => {
        submitAttempted = true;
        throw new Error('late result private server detail');
      },
    } as unknown as AgentAdapter;
    const poller = startCommandPoller({
      sessionId: command.sessionId,
      client: adapter,
      onCommand: async () => executed(command),
    }, 10);

    await waitFor(() => submitAttempted && existsSync(logPath));
    poller.stop();

    const entry = JSON.parse(readFileSync(logPath, 'utf8')) as Record<string, unknown>;
    expect(entry).toEqual({
      event: 'command_result_submit_failed',
      commandId: command.commandId,
    });
    const capture = JSON.stringify(entry);
    expect(capture).not.toContain('late command plaintext');
    expect(capture).not.toContain('late result private server detail');
  });

  test('stop during an in-flight poll prevents late command dispatch', async () => {
    let resolvePoll!: (command: CommandEnvelope) => void;
    const pendingPoll = new Promise<CommandEnvelope>((resolve) => { resolvePoll = resolve; });
    let dispatched = false;
    let submitted = false;
    const adapter = {
      pollCommands: async () => pendingPoll,
      submitResult: async () => { submitted = true; },
    } as unknown as AgentAdapter;
    const poller = startCommandPoller({
      sessionId: 'session-1',
      client: adapter,
      onCommand: async () => {
        dispatched = true;
        return executed();
      },
    }, 10);

    poller.stop();
    resolvePoll(makeCommand());
    await Bun.sleep(20);

    expect(dispatched).toBe(false);
    expect(submitted).toBe(false);
  });

  test.each(['resolve', 'throw'] as const)('stop during executing side effect suppresses late handler %s', async (outcome) => {
    const logPath = captureLog();
    const command = makeCommand({ payload: { text: 'canceled command plaintext' } });
    let polls = 0;
    let handlerStarted = false;
    let releaseHandler!: () => void;
    const handlerGate = new Promise<void>((resolve) => { releaseHandler = resolve; });
    let submissions = 0;
    const adapter = {
      pollCommands: async () => (++polls === 1 ? command : null),
      submitResult: async () => { submissions += 1; },
    } as unknown as AgentAdapter;
    const poller = startCommandPoller({
      sessionId: command.sessionId,
      client: adapter,
      onCommand: async () => {
        handlerStarted = true;
        await handlerGate;
        if (outcome === 'throw') throw new Error('late private handler error');
        return executed(command);
      },
    }, 10);

    await waitFor(() => handlerStarted);
    poller.stop();
    releaseHandler();
    await waitFor(() => existsSync(logPath));
    await Bun.sleep(10);

    expect(submissions).toBe(0);
    const entry = JSON.parse(readFileSync(logPath, 'utf8')) as Record<string, unknown>;
    expect(entry).toEqual({ event: 'command_dispatch_canceled', commandId: command.commandId });
    const capture = JSON.stringify(entry);
    expect(capture).not.toContain('canceled command plaintext');
    expect(capture).not.toContain('late private handler error');
  });
});
