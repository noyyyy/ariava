import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, setDefaultTimeout, test } from 'bun:test';
import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';
import type { AgentAdapter, AgentAdapterEvent } from '../src/adapter-interface';
import ariavaPiExtension from '../src/index';

setDefaultTimeout(60_000);

const QUIET_WAIT_MS = 1_650;
type Handler = (event: any, ctx: ExtensionContext) => Promise<void> | void;
type PushedEvent = AgentAdapterEvent;
type HeartbeatCall = { sessionId: string; status: string; latestActivityText?: string | null };
function makeAdapter(pushedEvents: PushedEvent[], overrides: Partial<AgentAdapter> = {}): AgentAdapter {
  let eventSequence = 0;
  return {
    registerSession: async (session) => ({ sessionId: session.sessionId, registeredAt: '2026-07-20T00:00:00Z' }),
    unregisterSession: async () => undefined,
    pushEvent: async (event) => {
      pushedEvents.push(event as PushedEvent);
      eventSequence += 1;
      return { eventId: `event-${eventSequence}` };
    },
    handleSession: async (sessionId, request) => ({
      ok: true,
      hostId: 'host-1',
      sessionId,
      handledThroughEventId: request.handledThroughEventId,
    }),
    heartbeat: async () => undefined,
    pollCommands: async () => null,
    submitResult: async () => undefined,
    ...overrides,
  };
}

function createHarness(options: {
  sessionId?: string;
  leafId?: string;
  adapter?: Partial<AgentAdapter>;
  userText?: string;
} = {}) {
  const handlers = new Map<string, Handler>();
  const pushedEvents: PushedEvent[] = [];
  const heartbeats: HeartbeatCall[] = [];
  const runtime = { idle: true, pending: false };
  let sessionId = options.sessionId ?? 'sess-1';
  let leafId = options.leafId ?? 'leaf-1';
  const transcript: unknown[] = options.userText
    ? [{ role: 'user', content: [{ type: 'text', text: options.userText }] }]
    : [];
  const pi = {
    on: (eventName: string, handler: Handler) => handlers.set(eventName, handler),
  } as unknown as ExtensionAPI;
  const ctx = {
    cwd: '/tmp/demo',
    hasUI: true,
    sessionManager: {
      getSessionId: () => sessionId,
      getLeafId: () => leafId,
      buildSessionContext: () => ({ messages: transcript }),
    },
    isIdle: () => runtime.idle,
    hasPendingMessages: () => runtime.pending,
  } as unknown as ExtensionContext;

  ariavaPiExtension(pi, makeAdapter(pushedEvents, {
    ...options.adapter,
    heartbeat: async (heartbeatSessionId, status, latestActivityText) => {
      heartbeats.push({ sessionId: heartbeatSessionId, status, latestActivityText });
      await options.adapter?.heartbeat?.(heartbeatSessionId, status, latestActivityText);
    },
  }));

  return {
    pushedEvents,
    heartbeats,
    runtime,
    ctx,
    setSessionId: (value: string) => { sessionId = value; },
    setLeafId: (value: string) => { leafId = value; },
    emit: async (name: string, event: unknown = {}, eventCtx: ExtensionContext = ctx) => {
      const handler = handlers.get(name);
      if (!handler) throw new Error(`Missing handler ${name}`);
      await handler(event, eventCtx);
    },
    start: async () => {
      await handlers.get('session_start')?.({}, ctx);
    },
    shutdown: async () => {
      await handlers.get('session_shutdown')?.({ reason: 'quit' }, ctx);
    },
    terminalEvents: () => pushedEvents,
  };
}

function assistantMessage(options: {
  text?: string;
  stopReason?: string;
  errorText?: string;
  error?: unknown;
}): Record<string, unknown> {
  const message: Record<string, unknown> = {
    role: 'assistant',
    content: options.text === undefined ? [] : [{ type: 'text', text: options.text }],
    timestamp: Date.now(),
  };
  if ('stopReason' in options) message.stopReason = options.stopReason;
  if (options.errorText !== undefined) message.errorMessage = options.errorText;
  if (options.error !== undefined) message.error = options.error;
  return message;
}

async function end(harness: ReturnType<typeof createHarness>, options: {
  text?: string;
  stopReason?: string;
  errorText?: string;
  error?: unknown;
  assistantFound?: boolean;
  withoutStart?: boolean;
}) {
  if (!options.withoutStart) await harness.emit('agent_start');
  const messages = options.assistantFound === false
    ? [{ role: 'user', content: [{ type: 'text', text: 'No assistant response yet.' }] }]
    : [assistantMessage(options)];
  await harness.emit('agent_end', { messages });
}

async function settleAndWait(harness: ReturnType<typeof createHarness>) {
  await harness.emit('agent_settled', {});
  await Bun.sleep(QUIET_WAIT_MS);
}

function lastTerminal(harness: ReturnType<typeof createHarness>): PushedEvent | undefined {
  return harness.terminalEvents().at(-1);
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((promiseResolve) => {
    resolve = promiseResolve;
  });
  return { promise, resolve };
}

async function waitForFile(path: string): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      if (readFileSync(path, 'utf8').length > 0) return;
    } catch {}
    await Bun.sleep(10);
  }
  throw new Error(`Timed out waiting for ${path}`);
}

describe('ariavaPiExtension settled lifecycle', () => {
  test('registers agent_settled and no compact lifecycle hooks', () => {
    const registeredEvents: string[] = [];
    const pi = {
      on: (eventName: string) => registeredEvents.push(eventName),
    } as unknown as ExtensionAPI;

    expect(() => ariavaPiExtension(pi)).not.toThrow();
    expect(registeredEvents).toEqual([
      'session_start',
      'session_shutdown',
      'input',
      'agent_start',
      'agent_end',
      'agent_settled',
      'session_tree',
    ]);
    expect(registeredEvents).not.toContain('session_before_compact');
    expect(registeredEvents).not.toContain('session_compact');
  });

  test('agent_end alone remains working past the quiet-window duration', async () => {
    const harness = createHarness();
    await harness.start();
    await harness.emit('agent_start');
    await end(harness, { stopReason: 'stop', text: 'Low-level result only.', withoutStart: true });

    await Bun.sleep(QUIET_WAIT_MS);
    expect(harness.terminalEvents()).toEqual([]);
    expect(harness.pushedEvents).toEqual([]);
    await harness.shutdown();
  });

  test('agent_start updates working status without inventing running activity text', async () => {
    const harness = createHarness();
    await harness.start();

    await harness.emit('agent_start');

    expect(harness.heartbeats.at(-1)).toEqual({
      sessionId: 'sess-1',
      status: 'working',
      latestActivityText: null,
    });
    expect(harness.pushedEvents).toEqual([]);
    await harness.shutdown();
  });

  test.each([
    ['context overflow recovery', 'Your input exceeds the context window.', 'Final recovered answer.'],
    ['ordinary retry recovery', 'network timeout', 'Recovered after retry.'],
    ['length continuation', undefined, 'Complete output after continuation.'],
  ])('%s replaces the earlier low-level result before settled', async (_name, earlierError, finalText) => {
    const harness = createHarness();
    await harness.start();
    await harness.emit('agent_start');
    await end(harness, earlierError
      ? { stopReason: 'error', errorText: earlierError, withoutStart: true }
      : { stopReason: 'length', text: 'Partial output that must not leak.', withoutStart: true });
    expect(harness.terminalEvents()).toEqual([]);

    await harness.emit('agent_start');
    await end(harness, { stopReason: 'stop', text: finalText, withoutStart: true });
    await harness.emit('agent_settled');
    expect(harness.terminalEvents()).toEqual([]);
    await Bun.sleep(QUIET_WAIT_MS);

    expect(harness.terminalEvents()).toHaveLength(1);
    expect(lastTerminal(harness)).toMatchObject({ type: 'done', agentText: finalText });
    expect(lastTerminal(harness)?.agentText).not.toContain(earlierError ?? 'Partial output');
    await harness.shutdown();
  });

  test.each([
    ['initial idle', async (harness: ReturnType<typeof createHarness>) => {
      await harness.emit('agent_settled');
    }],
    ['end without start', async (harness: ReturnType<typeof createHarness>) => {
      await end(harness, { stopReason: 'stop', text: 'Unpaired initial end.', withoutStart: true });
    }],
    ['recovery idle', async (harness: ReturnType<typeof createHarness>) => {
      await harness.emit('agent_settled');
      await end(harness, { stopReason: 'stop', text: 'Unpaired recovery end.', withoutStart: true });
    }],
    ['late prior-run end', async (harness: ReturnType<typeof createHarness>) => {
      await harness.emit('agent_start');
      await harness.emit('agent_settled');
      await end(harness, { stopReason: 'stop', text: 'Late prior-run end.', withoutStart: true });
    }],
  ])('%s produces no terminal event without a current running generation', async (_name, exercise) => {
    const harness = createHarness();
    await harness.start();
    await exercise(harness);
    await harness.emit('agent_settled');
    await Bun.sleep(QUIET_WAIT_MS);

    expect(harness.terminalEvents()).toEqual([]);
    await harness.shutdown();
  });

  test.each([
    ['unrecovered context overflow', { stopReason: 'error', error: { code: 'context_length_exceeded', message: 'Context overflow remained final.' } }, 'context_overflow'],
    ['exhausted ordinary retry', { stopReason: 'error', errorText: 'Final provider failure.' }, 'provider_failure'],
    ['error fallback', { stopReason: 'error' }, 'provider_failure'],
    ['final length', { stopReason: 'length', text: 'Incomplete response.' }, 'response_length'],
    ['final tool use', { stopReason: 'toolUse' }, 'incomplete_tool_use'],
  ])('%s emits canonical protected error only after settled and quiet flush', async (_name, result, kind) => {
    const harness = createHarness();
    await harness.start();
    await end(harness, result);
    expect(harness.terminalEvents()).toEqual([]);
    await harness.emit('agent_settled');
    expect(harness.terminalEvents()).toEqual([]);
    await Bun.sleep(QUIET_WAIT_MS);

    expect(harness.terminalEvents()).toHaveLength(1);
    expect(lastTerminal(harness)).toMatchObject({
      type: 'need_human',
      status: 'need_human',
      needHuman: { reason: 'error', error: { kind, retryExhausted: true } },
    });
    await harness.shutdown();
  });

  test('unknown structured stop reason is sanitized without becoming a legacy blocker', async () => {
    const harness = createHarness();
    await harness.start();
    const unsafeReason = ` future\u0000\u0085\n\t re\u202Eas\u2066on\uFEFF ${'x'.repeat(160)} `;
    await end(harness, { stopReason: unsafeReason, text: 'Provider partial output.' });
    await settleAndWait(harness);

    const terminal = lastTerminal(harness);
    expect(terminal).toMatchObject({
      type: 'need_human',
      status: 'need_human',
      needHuman: { reason: 'error', error: { kind: 'unknown', retryExhausted: true } },
    });
    expect(terminal?.needHuman?.reason === 'error' ? terminal.needHuman.error.message : '').not.toMatch(
      /[\u0000-\u001F\u007F-\u009F\p{Cf}]/u,
    );
    expect(terminal?.agentText).not.toContain('Provider partial output');
    await harness.shutdown();
  });

  test('a format-control-only unknown reason uses the generic error fallback', async () => {
    const harness = createHarness();
    await harness.start();
    await end(harness, { stopReason: '\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069\uFEFF' });
    await settleAndWait(harness);
    expect(lastTerminal(harness)).toMatchObject({
      type: 'need_human',
      status: 'need_human',
      needHuman: {
        reason: 'error',
        error: { kind: 'unknown', message: 'Pi stopped for an unsupported reason.', retryExhausted: true },
      },
    });
    await harness.shutdown();
  });

  test.each([
    ['question', 'Can you confirm the deployment target?', 'need_human', 'need_human', 'question'],
    ['explicit blocker', 'I need your credentials before continuing.', 'need_human', 'need_human', 'blocked'],
    ['ordinary completion', 'All requested changes are complete.', 'done', 'idle', undefined],
  ])('stable stop text retains internal %s classification behind canonical output', async (
    _name, text, expectedType, expectedStatus, expectedReason,
  ) => {
    const harness = createHarness({ userText: 'Please complete the task.' });
    await harness.start();
    await end(harness, { stopReason: 'stop', text });
    await settleAndWait(harness);

    expect(lastTerminal(harness)).toMatchObject({
      type: expectedType,
      status: expectedStatus,
      agentText: text,
      humanText: 'Please complete the task.',
      ...(expectedReason ? { needHuman: { reason: expectedReason } } : {}),
    });
    expect(lastTerminal(harness)).not.toHaveProperty('eventId');
    expect(lastTerminal(harness)).not.toHaveProperty('hostId');
    expect(lastTerminal(harness)?.createdAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    await harness.shutdown();
  });

  test('assistant with omitted stopReason follows stable stop-text classification', async () => {
    const harness = createHarness();
    await harness.start();
    await end(harness, { text: 'Omitted reason completed normally.' });
    await settleAndWait(harness);
    expect(lastTerminal(harness)).toMatchObject({
      type: 'done', status: 'idle', agentText: 'Omitted reason completed normally.',
    });
    await harness.shutdown();
  });

  test('final aborted and missing assistant results are suppressed', async () => {
    const aborted = createHarness({ sessionId: 'sess-aborted' });
    const missing = createHarness({ sessionId: 'sess-missing' });
    await aborted.start();
    await end(aborted, { stopReason: 'aborted' });
    await aborted.emit('agent_settled');
    await missing.start();
    await end(missing, { assistantFound: false });
    await missing.emit('agent_settled');
    await Bun.sleep(QUIET_WAIT_MS);

    expect(aborted.terminalEvents()).toEqual([]);
    expect(missing.terminalEvents()).toEqual([]);
    await aborted.shutdown();
    await missing.shutdown();
  });

  test('aborted agent_settled records heartbeat failure without rejecting the pi lifecycle', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'pi-aborted-heartbeat-'));
    const logPath = join(directory, 'extension.log');
    const originalLogPath = process.env.ARIAVA_PI_LOG_PATH;
    process.env.ARIAVA_PI_LOG_PATH = logPath;
    const harness = createHarness({
      adapter: {
        heartbeat: async (_sessionId, status) => {
          if (status === 'idle') throw new Error('local bridge unavailable');
        },
      },
    });
    try {
      await harness.start();
      await end(harness, { stopReason: 'aborted' });

      await expect(harness.emit('agent_settled')).resolves.toBeUndefined();
      await waitForFile(logPath);
      expect(readFileSync(logPath, 'utf8')).toContain('heartbeat aborted session');
      expect(readFileSync(logPath, 'utf8')).toContain('local bridge unavailable');
      expect(harness.terminalEvents()).toEqual([]);
      await harness.shutdown();
    } finally {
      if (originalLogPath === undefined) delete process.env.ARIAVA_PI_LOG_PATH;
      else process.env.ARIAVA_PI_LOG_PATH = originalLogPath;
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test('queued follow-up runner sequence classifies only the final low-level result', async () => {
    const harness = createHarness();
    await harness.start();
    await harness.emit('agent_start');
    await end(harness, {
      stopReason: 'stop',
      text: 'Intermediate answer before queued follow-up.',
      withoutStart: true,
    });
    expect(harness.terminalEvents()).toEqual([]);

    // The runner withholds agent_settled while its queued follow-up drains.
    await harness.emit('agent_start');
    await end(harness, {
      stopReason: 'stop',
      text: 'Final answer after queued follow-up.',
      withoutStart: true,
    });
    expect(harness.terminalEvents()).toEqual([]);
    await harness.emit('agent_settled');
    expect(harness.terminalEvents()).toEqual([]);
    await Bun.sleep(QUIET_WAIT_MS);

    expect(harness.terminalEvents()).toEqual([
      expect.objectContaining({ type: 'done', agentText: 'Final answer after queued follow-up.' }),
    ]);
    await harness.shutdown();
  });

  test('input and a new agent_start invalidate quiet-window candidates', async () => {
    const harness = createHarness();
    await harness.start();
    await end(harness, { stopReason: 'stop', text: 'Stale after input.' });
    await harness.emit('agent_settled');
    await harness.emit('input');

    await end(harness, { stopReason: 'stop', text: 'Stale after a new run.' });
    await harness.emit('agent_settled');
    await harness.emit('agent_start');
    await Bun.sleep(QUIET_WAIT_MS);

    expect(harness.terminalEvents()).toEqual([]);
    await harness.shutdown();
  });

  test.each(['steer', 'followUp'] as const)(
    'streaming %s input preserves the active generation through end and settled',
    async (streamingBehavior) => {
      const harness = createHarness();
      await harness.start();
      await harness.emit('agent_start');
      await harness.emit('input', {
        type: 'input',
        text: `Queued ${streamingBehavior} input`,
        source: 'interactive',
        streamingBehavior,
      });
      await end(harness, {
        stopReason: 'stop',
        text: `Completed after ${streamingBehavior}.`,
        withoutStart: true,
      });
      await settleAndWait(harness);

      expect(harness.terminalEvents()).toEqual([
        expect.objectContaining({ type: 'done', agentText: `Completed after ${streamingBehavior}.` }),
      ]);
      await harness.shutdown();
    },
  );

  test('genuinely idle input invalidates the active generation and terminal result', async () => {
    const harness = createHarness();
    await harness.start();
    await harness.emit('agent_start');
    await harness.emit('input', { type: 'input', text: 'New idle input', source: 'interactive' });
    await end(harness, { stopReason: 'stop', text: 'Stale after idle input.', withoutStart: true });
    await harness.emit('agent_settled');
    await Bun.sleep(QUIET_WAIT_MS);

    expect(harness.terminalEvents()).toEqual([]);
    await harness.shutdown();
  });

  test.each([
    ['non-idle runtime', false, false],
    ['new pending messages', true, true],
  ])('%s invalidates rather than reschedules a stale candidate', async (_name, idle, pending) => {
    const harness = createHarness();
    await harness.start();
    await end(harness, { stopReason: 'stop', text: `Stale ${_name}.` });
    await harness.emit('agent_settled');
    harness.runtime.idle = idle;
    harness.runtime.pending = pending;
    await Bun.sleep(QUIET_WAIT_MS);
    expect(harness.terminalEvents()).toEqual([]);

    harness.runtime.idle = true;
    harness.runtime.pending = false;
    await Bun.sleep(QUIET_WAIT_MS);
    expect(harness.terminalEvents()).toEqual([]);
    await harness.shutdown();
  });

  test('duplicate and late settled events cannot duplicate a candidate or emitted alert', async () => {
    const harness = createHarness();
    await harness.start();
    await end(harness, { stopReason: 'stop', text: 'Exactly once terminal.' });
    await harness.emit('agent_settled');
    await harness.emit('agent_settled');
    await Bun.sleep(QUIET_WAIT_MS);
    await harness.emit('agent_settled');
    await Bun.sleep(30);

    expect(harness.terminalEvents()).toHaveLength(1);
    await harness.shutdown();
  });

  test('session_tree clears the stored result and pending candidate', async () => {
    const harness = createHarness();
    await harness.start();
    await end(harness, { stopReason: 'stop', text: 'Old branch result.' });
    await harness.emit('agent_settled');
    harness.setLeafId('leaf-2');
    await harness.emit('session_tree', { newLeafId: 'leaf-2' });
    await Bun.sleep(QUIET_WAIT_MS);
    expect(harness.terminalEvents()).toEqual([]);

    await harness.emit('agent_settled');
    await Bun.sleep(30);
    expect(harness.terminalEvents()).toEqual([]);
    await harness.shutdown();
  });

  test('shutdown and session replacement reject stale candidates and old-session events', async () => {
    const harness = createHarness({ sessionId: 'sess-old' });
    await harness.start();
    await end(harness, { stopReason: 'stop', text: 'Old session result.' });
    await harness.emit('agent_settled');
    await harness.shutdown();

    harness.setSessionId('sess-new');
    await harness.start();
    const oldCtx = {
      ...harness.ctx,
      sessionManager: {
        getSessionId: () => 'sess-old',
        getLeafId: () => 'leaf-old',
        buildSessionContext: () => ({ messages: [] }),
      },
    } as unknown as ExtensionContext;
    await harness.emit('agent_end', { messages: [assistantMessage({ stopReason: 'stop', text: 'Late old result.' })] }, oldCtx);
    await harness.emit('agent_settled', {}, oldCtx);
    await Bun.sleep(QUIET_WAIT_MS);

    expect(harness.terminalEvents()).toEqual([]);
    await harness.shutdown();
  });

  test('session_start clears the prior state quiet timer before replacement', async () => {
    const originalSetTimeout = globalThis.setTimeout;
    const originalClearTimeout = globalThis.clearTimeout;
    let quietTimer: unknown;
    const clearedTimers: unknown[] = [];
    globalThis.setTimeout = ((callback: TimerHandler, delay?: number, ...args: unknown[]) => {
      const timer = originalSetTimeout(callback, delay, ...args);
      if (delay === 1_500) quietTimer = timer;
      return timer;
    }) as typeof setTimeout;
    globalThis.clearTimeout = ((timer: ReturnType<typeof setTimeout>) => {
      clearedTimers.push(timer);
      originalClearTimeout(timer);
    }) as typeof clearTimeout;

    const harness = createHarness();
    try {
      await harness.start();
      await end(harness, { stopReason: 'stop', text: 'Pending old session timer.' });
      await harness.emit('agent_settled');
      expect(quietTimer).toBeDefined();

      await harness.start();
      expect(clearedTimers).toContain(quietTimer!);
    } finally {
      await harness.shutdown();
      globalThis.setTimeout = originalSetTimeout;
      globalThis.clearTimeout = originalClearTimeout;
    }
  });
});

describe('unchanged extension integration behavior', () => {
  test('session_start does not wait for adapter registration and warns in TUI after 5 seconds', async () => {
    const notifications: Array<{ message: string; level?: string }> = [];
    let resolveRegistration!: (value: { sessionId: string; registeredAt: string }) => void;
    const registration = new Promise<{ sessionId: string; registeredAt: string }>((resolve) => {
      resolveRegistration = resolve;
    });
    const registeredSessions: Array<{ sessionId: string }> = [];
    const harness = createHarness({
      adapter: {
        registerSession: (session) => {
          registeredSessions.push(session);
          return registration;
        },
      },
    });
    (harness.ctx as unknown as { ui: { notify: (message: string, level?: string) => void } }).ui = {
      notify: (message, level) => notifications.push({ message, level }),
    };

    await expect(Promise.race([
      harness.start().then(() => 'returned'),
      Bun.sleep(50).then(() => 'timeout'),
    ])).resolves.toBe('returned');
    expect(registeredSessions).toHaveLength(1);

    await Bun.sleep(5_100);
    expect(notifications).toEqual([{
      level: 'warning',
      message: 'Ariava bridge did not register this pi session within 5s. Check that the selected local bridge profile is running and its Agent Adapter discovery file is available.',
    }]);

    resolveRegistration({ sessionId: 'sess-1', registeredAt: '2026-07-08T00:00:00Z' });
    await harness.shutdown();
  });

  test('retries adapter registration in background until bridge accepts the session', async () => {
    let attempts = 0;
    const harness = createHarness({
      adapter: {
        registerSession: async () => {
          attempts += 1;
          if (attempts < 2) {
            throw new Error('Agent Adapter POST /v1/agent/sessions failed: 401 {"error":"Unauthorized"}');
          }
          return { sessionId: 'sess-1', registeredAt: '2026-07-08T00:00:00Z' };
        },
      },
    });

    await harness.start();
    await Bun.sleep(1_100);
    expect(attempts).toBeGreaterThanOrEqual(2);
    await harness.shutdown();
  });

  test('session_shutdown does not wait for adapter unregister', async () => {
    let unregisterStarted = false;
    const harness = createHarness({
      adapter: {
        unregisterSession: () => {
          unregisterStarted = true;
          return new Promise(() => undefined);
        },
      },
    });
    await harness.start();

    await expect(Promise.race([
      harness.shutdown().then(() => 'returned'),
      Bun.sleep(50).then(() => 'timeout'),
    ])).resolves.toBe('returned');
    expect(unregisterStarted).toBe(true);
  });

  test('session_start and agent_start do not wait for adapter delivery', async () => {
    let registrationStarted = false;
    let heartbeatStarted = false;
    let pushStarted = false;
    const harness = createHarness({
      adapter: {
        registerSession: () => {
          registrationStarted = true;
          return new Promise(() => undefined);
        },
        heartbeat: () => {
          heartbeatStarted = true;
          return new Promise(() => undefined);
        },
        pushEvent: () => {
          pushStarted = true;
          return new Promise(() => undefined);
        },
      },
    });

    await expect(Promise.race([
      harness.start().then(() => 'returned'),
      Bun.sleep(50).then(() => 'timeout'),
    ])).resolves.toBe('returned');
    await expect(Promise.race([
      harness.emit('agent_start').then(() => 'returned'),
      Bun.sleep(50).then(() => 'timeout'),
    ])).resolves.toBe('returned');
    expect(registrationStarted).toBe(true);
    expect(heartbeatStarted).toBe(true);
    expect(pushStarted).toBe(false);
    await harness.shutdown();
  });

  test('session_tree updates local state without pushing any Watch event', async () => {
    const harness = createHarness();
    await harness.start();
    await harness.emit('agent_start');
    const eventCountBeforeTreeSwitch = harness.pushedEvents.length;
    expect(eventCountBeforeTreeSwitch).toBe(0);

    harness.setLeafId('leaf-2');
    await harness.emit('session_tree', { newLeafId: 'leaf-2' });
    await Bun.sleep(10);

    expect(harness.pushedEvents).toHaveLength(eventCountBeforeTreeSwitch);
    await harness.shutdown();
  });

  test('local input handles the most recent emitted terminal alert', async () => {
    const handled: Array<{ sessionId: string; eventId: string; action?: string }> = [];
    const harness = createHarness({
      adapter: {
        handleSession: async (sessionId, request) => {
          handled.push({ sessionId, eventId: request.handledThroughEventId, action: request.action });
          return { ok: true, hostId: 'host-1', sessionId, handledThroughEventId: request.handledThroughEventId };
        },
      },
    });
    await harness.start();
    await end(harness, { stopReason: 'stop', text: 'Ready for local acknowledgement.' });
    await settleAndWait(harness);
    await harness.emit('input');
    await Bun.sleep(20);

    expect(handled).toEqual([{ sessionId: 'sess-1', eventId: 'event-1', action: 'pi_input' }]);
    await harness.shutdown();
  });

  test('retries one immutable terminal Event after a non-2xx failure and commits only after ACK', async () => {
    const attempts: PushedEvent[] = [];
    const handled: string[] = [];
    const harness = createHarness({
      adapter: {
        pushEvent: async (event) => {
          attempts.push(structuredClone(event));
          if (attempts.length === 1) {
            throw new Error('Agent Adapter POST /events failed: 503 unavailable');
          }
          return { eventId: 'durable-event' };
        },
        handleSession: async (sessionId, request) => {
          handled.push(request.handledThroughEventId);
          return { ok: true, hostId: 'host-1', sessionId, handledThroughEventId: request.handledThroughEventId };
        },
      },
    });
    await harness.start();
    await end(harness, { stopReason: 'stop', text: 'Durably delivered once.' });
    await harness.emit('agent_settled');
    await Bun.sleep(QUIET_WAIT_MS + 400);

    expect(attempts).toHaveLength(2);
    expect(attempts[1]).toEqual(attempts[0]);
    expect(attempts[0]).toMatchObject({ type: 'done', status: 'idle', agentText: 'Durably delivered once.' });
    await harness.emit('input');
    await Bun.sleep(20);
    expect(handled).toEqual(['durable-event']);
    await harness.shutdown();
  });

  test('late push response cannot restore a branch-cleared candidate', async () => {
    const pushed = deferred<{ eventId: string }>();
    const handled: string[] = [];
    const harness = createHarness({
      adapter: {
        pushEvent: () => pushed.promise,
        handleSession: async (sessionId, request) => {
          handled.push(request.handledThroughEventId);
          return { ok: true, hostId: 'host-1', sessionId, handledThroughEventId: request.handledThroughEventId };
        },
      },
    });
    await harness.start();
    await end(harness, { stopReason: 'stop', text: 'Old branch event.' });
    await settleAndWait(harness);
    harness.setLeafId('leaf-2');
    await harness.emit('session_tree', { newLeafId: 'leaf-2' });
    pushed.resolve({ eventId: 'old-branch-event' });
    await Bun.sleep(20);
    await harness.emit('input', { type: 'input', text: 'New branch input', source: 'interactive' });
    await Bun.sleep(20);

    expect(handled).toEqual([]);
    await harness.shutdown();
  });

  test('late older push response cannot overwrite a newer event candidate', async () => {
    const pushes = [deferred<{ eventId: string }>(), deferred<{ eventId: string }>()];
    const handled: string[] = [];
    let pushIndex = 0;
    const harness = createHarness({
      adapter: {
        pushEvent: () => pushes[pushIndex++]!.promise,
        handleSession: async (sessionId, request) => {
          handled.push(request.handledThroughEventId);
          return { ok: true, hostId: 'host-1', sessionId, handledThroughEventId: request.handledThroughEventId };
        },
      },
    });
    await harness.start();
    await end(harness, { stopReason: 'stop', text: 'First delivered event.' });
    await settleAndWait(harness);
    await end(harness, { stopReason: 'stop', text: 'Newer delivered event.' });
    await settleAndWait(harness);
    pushes[1]!.resolve({ eventId: 'newer-event' });
    await Bun.sleep(20);
    pushes[0]!.resolve({ eventId: 'older-event' });
    await Bun.sleep(20);
    await harness.emit('input', { type: 'input', text: 'Acknowledge latest', source: 'interactive' });
    await Bun.sleep(20);

    expect(handled).toEqual(['newer-event']);
    await harness.shutdown();
  });

  test('input during push await reconciles immediately without restoring stale terminal state', async () => {
    const pushed = deferred<{ eventId: string }>();
    const handled: string[] = [];
    const harness = createHarness({
      adapter: {
        pushEvent: () => pushed.promise,
        handleSession: async (sessionId, request) => {
          handled.push(request.handledThroughEventId);
          return { ok: true, hostId: 'host-1', sessionId, handledThroughEventId: request.handledThroughEventId };
        },
      },
    });
    await harness.start();
    await end(harness, { stopReason: 'stop', text: 'Delivered before local input.' });
    await settleAndWait(harness);
    await harness.emit('input', { type: 'input', text: 'Input during delivery', source: 'interactive' });
    pushed.resolve({ eventId: 'delayed-event' });
    await Bun.sleep(20);

    expect(handled).toEqual(['delayed-event']);
    await harness.emit('input', { type: 'input', text: 'Later input', source: 'interactive' });
    await Bun.sleep(20);
    expect(handled).toEqual(['delayed-event']);
    await harness.shutdown();
  });

  test('input during deferred push retries a failed handle without restoring a stale candidate', async () => {
    const pushed = deferred<{ eventId: string }>();
    const handleAttempts: string[] = [];
    let failFirstHandle = true;
    const harness = createHarness({
      adapter: {
        pushEvent: () => pushed.promise,
        handleSession: async (sessionId, request) => {
          handleAttempts.push(request.handledThroughEventId);
          if (failFirstHandle) {
            failFirstHandle = false;
            throw new Error('transient handle failure');
          }
          return { ok: true, hostId: 'host-1', sessionId, handledThroughEventId: request.handledThroughEventId };
        },
      },
    });
    await harness.start();
    await end(harness, { stopReason: 'stop', text: 'Delivered before retryable local input.' });
    await settleAndWait(harness);
    await harness.emit('input', { type: 'input', text: 'Input during delivery', source: 'interactive' });
    pushed.resolve({ eventId: 'retryable-delayed-event' });
    await Bun.sleep(20);

    expect(handleAttempts).toEqual(['retryable-delayed-event']);
    await harness.emit('input', { type: 'input', text: 'Retry local acknowledgement', source: 'interactive' });
    await Bun.sleep(20);
    expect(handleAttempts).toEqual(['retryable-delayed-event', 'retryable-delayed-event']);

    await harness.emit('input', { type: 'input', text: 'No stale acknowledgement', source: 'interactive' });
    await Bun.sleep(20);
    expect(handleAttempts).toEqual(['retryable-delayed-event', 'retryable-delayed-event']);
    await harness.shutdown();
  });

  test('install helper uses pi package installation with legacy copy fallback', () => {
    const script = readFileSync(new URL('../../../scripts/install-pi-extension.sh', import.meta.url), 'utf8');
    expect(script).toContain('DEFAULT_SOURCE="${REPO_ROOT}/extensions/pi/bundle"');
    expect(script).toContain('pi install "${SOURCE}"');
    expect(script).toContain('--legacy-copy');
    expect(script).toContain('rsync -a --delete --exclude=\'.DS_Store\'');
    expect(script).not.toContain('"${REPO_ROOT}/extensions/pi/" "${EXT_DIR}/"');
    expect(script).not.toContain('bun install');
    expect(script).not.toContain('npm install');
  });

  test('extension manifest remains configured as a pi package source', () => {
    const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
      name?: string;
      private?: boolean;
      pi?: { extensions?: string[] };
    };
    expect(manifest.name).toBe('@ariava/pi-extension');
    expect(manifest.private).toBe(true);
    expect(manifest.pi?.extensions).toEqual(['./index.ts']);
  });

  test('shared npm release orchestrator always includes the generated pi extension package', () => {
    const shell = readFileSync(new URL('../../../scripts/publish-npm-safe.sh', import.meta.url), 'utf8');
    const release = readFileSync(new URL('../../../scripts/npm-release-lib.mjs', import.meta.url), 'utf8');

    expect(shell).toContain('npm-release.mjs');
    expect(shell).not.toContain('--include-pi-extension');
    expect(release).toContain("'@ariava/pi-extension'");
    expect(release).toContain("join(root, 'extensions/pi/bundle')");
    expect(release).toContain("['publish', join(resolve(options.directory), artifact.filename)");
  });

  test('release bundle manifest is publishable as an npm pi package', () => {
    const manifest = JSON.parse(readFileSync(new URL('../bundle/package.json', import.meta.url), 'utf8')) as {
      name?: string;
      private?: boolean;
      files?: string[];
      keywords?: string[];
      homepage?: string;
      repository?: { type?: string; url?: string };
      pi?: { extensions?: string[] };
    };

    expect(manifest.name).toBe('@ariava/pi-extension');
    expect(manifest.private).toBeUndefined();
    expect(manifest.keywords).toContain('pi-package');
    expect(manifest.files).toContain('index.js');
    expect(manifest.pi?.extensions).toEqual(['./index.js']);
    expect(manifest.homepage).toBe('https://github.com/noyyyy/ariava');
    expect(manifest.repository).toEqual({
      type: 'git',
      url: 'git+https://github.com/noyyyy/ariava.git',
    });
  });
});
