import { readFileSync } from 'node:fs';
import { describe, expect, setDefaultTimeout, test } from 'bun:test';
import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';
import type { AgentAdapter } from '../src/adapter-interface';
import ariavaPiExtension from '../src/index';

setDefaultTimeout(60_000);

const QUIET_WAIT_MS = 1_650;
type Handler = (event: any, ctx: ExtensionContext) => Promise<void> | void;
type PushedEvent = { type?: string; status?: string; assistantText?: string; userMessageText?: string };

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

  ariavaPiExtension(pi, makeAdapter(pushedEvents, options.adapter));

  return {
    pushedEvents,
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
    terminalEvents: () => pushedEvents.filter((event) =>
      event.type === 'done' || event.type === 'blocked' || event.type === 'question_requested'),
  };
}

function assistantMessage(options: {
  text?: string;
  stopReason?: string;
  errorText?: string;
}): Record<string, unknown> {
  const message: Record<string, unknown> = {
    role: 'assistant',
    content: options.text === undefined ? [] : [{ type: 'text', text: options.text }],
    timestamp: Date.now(),
  };
  if ('stopReason' in options) message.stopReason = options.stopReason;
  if (options.errorText !== undefined) message.errorMessage = options.errorText;
  return message;
}

async function end(harness: ReturnType<typeof createHarness>, options: {
  text?: string;
  stopReason?: string;
  errorText?: string;
  assistantFound?: boolean;
}) {
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
    await end(harness, { stopReason: 'stop', text: 'Low-level result only.' });

    await Bun.sleep(QUIET_WAIT_MS);
    expect(harness.terminalEvents()).toEqual([]);
    expect(harness.pushedEvents.at(-1)?.type).toBe('working');
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
      ? { stopReason: 'error', errorText: earlierError }
      : { stopReason: 'length', text: 'Partial output that must not leak.' });
    expect(harness.terminalEvents()).toEqual([]);

    await harness.emit('agent_start');
    await end(harness, { stopReason: 'stop', text: finalText });
    await harness.emit('agent_settled');
    expect(harness.terminalEvents()).toEqual([]);
    await Bun.sleep(QUIET_WAIT_MS);

    expect(harness.terminalEvents()).toHaveLength(1);
    expect(lastTerminal(harness)).toMatchObject({ type: 'done', assistantText: finalText });
    expect(lastTerminal(harness)?.assistantText).not.toContain(earlierError ?? 'Partial output');
    await harness.shutdown();
  });

  test.each([
    ['unrecovered context overflow', { stopReason: 'error', errorText: 'Context overflow remained final.' }, 'Context overflow remained final.'],
    ['exhausted ordinary retry', { stopReason: 'error', errorText: 'Final provider failure.' }, 'Final provider failure.'],
    ['error fallback', { stopReason: 'error' }, 'Pi stopped after an unrecovered error.'],
    ['final length', { stopReason: 'length', text: 'Incomplete response.' }, 'Pi stopped after reaching the response length limit.'],
    ['final tool use', { stopReason: 'toolUse' }, 'Pi stopped while waiting to use a tool.'],
  ])('%s becomes blocked only after settled and quiet flush', async (_name, result, preview) => {
    const harness = createHarness();
    await harness.start();
    await end(harness, result);
    expect(harness.terminalEvents()).toEqual([]);
    await harness.emit('agent_settled');
    expect(harness.terminalEvents()).toEqual([]);
    await Bun.sleep(QUIET_WAIT_MS);

    expect(harness.terminalEvents()).toHaveLength(1);
    expect(lastTerminal(harness)).toMatchObject({ type: 'blocked', assistantText: preview });
    expect(harness.terminalEvents().some((event) => event.type === 'done')).toBe(false);
    await harness.shutdown();
  });

  test('unknown non-empty reason removes C0/C1 and Unicode format controls before blocked delivery', async () => {
    const harness = createHarness();
    await harness.start();
    const unsafeReason = ` future\u0000\u0085\n\t re\u202Eas\u2066on\uFEFF ${'x'.repeat(160)} `;
    await end(harness, { stopReason: unsafeReason, text: 'Provider partial output.' });
    await settleAndWait(harness);

    const terminal = lastTerminal(harness);
    expect(terminal?.type).toBe('blocked');
    expect(terminal?.assistantText).toStartWith('Pi stopped for an unsupported reason: future reason ');
    expect(terminal?.assistantText).not.toMatch(/[\u0000-\u001F\u007F-\u009F\p{Cf}]/u);
    expect(terminal?.assistantText?.length).toBeLessThanOrEqual(122);
    expect(terminal?.assistantText).not.toContain('Provider partial output');
    await harness.shutdown();
  });

  test('a format-control-only unknown reason uses the generic unsupported-reason fallback', async () => {
    const harness = createHarness();
    await harness.start();
    await end(harness, { stopReason: '\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069\uFEFF' });
    await settleAndWait(harness);
    expect(lastTerminal(harness)).toMatchObject({
      type: 'blocked',
      assistantText: 'Pi stopped for an unsupported reason.',
    });
    await harness.shutdown();
  });

  test.each([
    ['question', 'Can you confirm the deployment target?', 'question_requested'],
    ['explicit blocker', 'I need your credentials before continuing.', 'blocked'],
    ['ordinary completion', 'All requested changes are complete.', 'done'],
  ])('stable stop text retains %s classification', async (_name, text, expectedType) => {
    const harness = createHarness({ userText: 'Please complete the task.' });
    await harness.start();
    await end(harness, { stopReason: 'stop', text });
    await settleAndWait(harness);

    expect(lastTerminal(harness)).toMatchObject({
      type: expectedType,
      assistantText: text,
      userMessageText: 'Please complete the task.',
    });
    await harness.shutdown();
  });

  test('assistant with omitted stopReason follows stable stop-text classification', async () => {
    const harness = createHarness();
    await harness.start();
    await end(harness, { text: 'Omitted reason completed normally.' });
    await settleAndWait(harness);
    expect(lastTerminal(harness)).toMatchObject({ type: 'done', assistantText: 'Omitted reason completed normally.' });
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

  test('queued follow-up runner sequence classifies only the final low-level result', async () => {
    const harness = createHarness();
    await harness.start();
    await harness.emit('agent_start');
    await end(harness, { stopReason: 'stop', text: 'Intermediate answer before queued follow-up.' });
    expect(harness.terminalEvents()).toEqual([]);

    // The runner withholds agent_settled while its queued follow-up drains.
    await harness.emit('agent_start');
    await end(harness, { stopReason: 'stop', text: 'Final answer after queued follow-up.' });
    expect(harness.terminalEvents()).toEqual([]);
    await harness.emit('agent_settled');
    expect(harness.terminalEvents()).toEqual([]);
    await Bun.sleep(QUIET_WAIT_MS);

    expect(harness.terminalEvents()).toEqual([
      expect.objectContaining({ type: 'done', assistantText: 'Final answer after queued follow-up.' }),
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
    let pushStarted = false;
    const harness = createHarness({
      adapter: {
        registerSession: () => {
          registrationStarted = true;
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
    expect(pushStarted).toBe(true);
    await harness.shutdown();
  });

  test('session_tree updates local state without pushing any Watch event', async () => {
    const harness = createHarness();
    await harness.start();
    await harness.emit('agent_start');
    const eventCountBeforeTreeSwitch = harness.pushedEvents.length;
    expect(eventCountBeforeTreeSwitch).toBe(1);

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

    expect(handled).toEqual([{ sessionId: 'sess-1', eventId: 'event-2', action: 'pi_input' }]);
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

  test('safe npm publish script always includes the generated pi extension package', () => {
    const script = readFileSync(new URL('../../../scripts/publish-npm-safe.sh', import.meta.url), 'utf8');

    expect(script).not.toContain('--include-pi-extension');
    expect(script).toContain('Pack/publish the generated @ariava/pi-extension package');
    expect(script).toContain('bun run build:pi-bundle');
    expect(script).toContain('PI_EXTENSION_PACKAGE_NAME="@ariava/pi-extension"');
    expect(script).toContain('npm publish --access public');
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
