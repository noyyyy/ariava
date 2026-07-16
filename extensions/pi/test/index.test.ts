import { readFileSync } from 'node:fs';
import { describe, expect, test, setDefaultTimeout } from 'bun:test';
import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';
import type { AgentAdapter } from '../src/adapter-interface';
import ariavaPiExtension from '../src/index';
import type { PiSessionInfo } from '../src/session';

setDefaultTimeout(20_000);

function makeSessionContext(overrides: Partial<ExtensionContext> = {}): ExtensionContext {
  return {
    cwd: '/tmp/demo',
    hasUI: true,
    sessionManager: {
      getSessionId: () => 'sess-1',
    },
    ...overrides,
  } as unknown as ExtensionContext;
}

function makeAdapter(overrides: Partial<AgentAdapter> = {}): AgentAdapter {
  return {
    registerSession: async () => ({ sessionId: 'sess-1', registeredAt: '2026-07-08T00:00:00Z' }),
    unregisterSession: async () => undefined,
    pushEvent: async () => ({ eventId: 'event-1' }),
    handleSession: async () => ({ ok: true, hostId: 'host-1', sessionId: 'sess-1', handledThroughEventId: 'event-1' }),
    heartbeat: async () => undefined,
    pollCommands: async () => null,
    submitResult: async () => undefined,
    ...overrides,
  };
}

describe('ariavaPiExtension', () => {
  test('registers only lifecycle handlers during extension loading', () => {
    const registeredEvents: string[] = [];
    const pi = {
      on: (eventName: string) => {
        registeredEvents.push(eventName);
      },
      getSessionName: () => {
        throw new Error('Extension runtime not initialized. Action methods cannot be called during extension loading.');
      },
    } as unknown as ExtensionAPI;

    expect(() => ariavaPiExtension(pi)).not.toThrow();
    expect(registeredEvents).toEqual(['session_start', 'session_shutdown', 'input', 'agent_start', 'agent_end', 'session_tree']);
  });

  test('session_start does not wait for adapter registration and warns in TUI after 5 seconds', async () => {
    const handlers = new Map<string, (event: unknown, ctx: ExtensionContext) => Promise<void> | void>();
    const notifications: Array<{ message: string; level?: string }> = [];
    const pi = {
      on: (eventName: string, handler: (event: unknown, ctx: ExtensionContext) => Promise<void> | void) => {
        handlers.set(eventName, handler);
      },
    } as unknown as ExtensionAPI;

    let resolveRegistration!: (value: { sessionId: string; registeredAt: string }) => void;
    const registration = new Promise<{ sessionId: string; registeredAt: string }>((resolve) => {
      resolveRegistration = resolve;
    });
    const registeredSessions: PiSessionInfo[] = [];
    const adapter = makeAdapter({
      registerSession: (session) => {
        registeredSessions.push(session);
        return registration;
      },
    });

    ariavaPiExtension(pi, adapter);
    const sessionStart = handlers.get('session_start');
    expect(sessionStart).toBeDefined();

    const result = sessionStart!({}, makeSessionContext({
      ui: {
        notify: (message: string, level?: string) => {
          notifications.push({ message, level });
        },
      },
    } as Partial<ExtensionContext>));

    await expect(Promise.race([
      Promise.resolve(result).then(() => 'returned'),
      new Promise((resolve) => setTimeout(() => resolve('timeout'), 50)),
    ])).resolves.toBe('returned');
    expect(registeredSessions).toHaveLength(1);

    await new Promise((resolve) => setTimeout(resolve, 5_100));
    expect(notifications).toEqual([
      {
        message: 'Ariava bridge did not register this pi session within 5s. Watch integration may be unavailable; check the local bridge on 127.0.0.1:7272.',
        level: 'warning',
      },
    ]);

    resolveRegistration({ sessionId: 'sess-1', registeredAt: '2026-07-08T00:00:00Z' });
  });

  test('retries adapter registration in background until bridge accepts the session', async () => {
    const handlers = new Map<string, (event: unknown, ctx: ExtensionContext) => Promise<void> | void>();
    const pi = {
      on: (eventName: string, handler: (event: unknown, ctx: ExtensionContext) => Promise<void> | void) => {
        handlers.set(eventName, handler);
      },
    } as unknown as ExtensionAPI;

    let attempts = 0;
    const adapter = makeAdapter({
      registerSession: async () => {
        attempts += 1;
        if (attempts < 2) {
          throw new Error('Agent Adapter POST /v1/agent/sessions failed: 401 {"error":"Unauthorized"}');
        }
        return { sessionId: 'sess-1', registeredAt: '2026-07-08T00:00:00Z' };
      },
    });

    ariavaPiExtension(pi, adapter);
    await handlers.get('session_start')!({}, makeSessionContext());

    await new Promise((resolve) => setTimeout(resolve, 1_100));
    expect(attempts).toBeGreaterThanOrEqual(2);
  });

  test('agent_start does not wait for watch event delivery', async () => {
    const handlers = new Map<string, (event: unknown, ctx: ExtensionContext) => Promise<void> | void>();
    const pi = {
      on: (eventName: string, handler: (event: unknown, ctx: ExtensionContext) => Promise<void> | void) => {
        handlers.set(eventName, handler);
      },
    } as unknown as ExtensionAPI;

    let pushStarted = false;
    const adapter = makeAdapter({
      pushEvent: () => {
        pushStarted = true;
        return new Promise(() => undefined);
      },
    });

    ariavaPiExtension(pi, adapter);
    await handlers.get('session_start')!({}, makeSessionContext());
    const result = handlers.get('agent_start')!({}, makeSessionContext());

    await expect(Promise.race([
      Promise.resolve(result).then(() => 'returned'),
      new Promise((resolve) => setTimeout(() => resolve('timeout'), 50)),
    ])).resolves.toBe('returned');
    expect(pushStarted).toBe(true);
  });

  test('session_shutdown does not wait for adapter unregister', async () => {
    const handlers = new Map<string, (event: unknown, ctx: ExtensionContext) => Promise<void> | void>();
    const pi = {
      on: (eventName: string, handler: (event: unknown, ctx: ExtensionContext) => Promise<void> | void) => {
        handlers.set(eventName, handler);
      },
    } as unknown as ExtensionAPI;

    let unregisterStarted = false;
    const adapter = makeAdapter({
      unregisterSession: () => {
        unregisterStarted = true;
        return new Promise(() => undefined);
      },
    });

    ariavaPiExtension(pi, adapter);
    await handlers.get('session_start')!({}, makeSessionContext());
    const result = handlers.get('session_shutdown')!({ reason: 'quit' }, makeSessionContext());

    await expect(Promise.race([
      Promise.resolve(result).then(() => 'returned'),
      new Promise((resolve) => setTimeout(() => resolve('timeout'), 50)),
    ])).resolves.toBe('returned');
    expect(unregisterStarted).toBe(true);
  });

  test('session_tree updates local state without pushing watch events', async () => {
    const handlers = new Map<string, (event: unknown, ctx: ExtensionContext) => Promise<void> | void>();
    const pushedEvents: unknown[] = [];
    const pi = {
      on: (eventName: string, handler: (event: unknown, ctx: ExtensionContext) => Promise<void> | void) => {
        handlers.set(eventName, handler);
      },
    } as unknown as ExtensionAPI;
    const adapter = makeAdapter({
      pushEvent: async (event) => {
        pushedEvents.push(event);
        return { eventId: 'event-1' };
      },
    });

    ariavaPiExtension(pi, adapter);
    await handlers.get('session_start')!({}, makeSessionContext({
      sessionManager: {
        getSessionId: () => 'sess-1',
        getLeafId: () => 'leaf-1',
      },
    } as Partial<ExtensionContext>));
    await handlers.get('agent_start')!({}, makeSessionContext({
      sessionManager: {
        getSessionId: () => 'sess-1',
        getLeafId: () => 'leaf-1',
      },
    } as Partial<ExtensionContext>));
    expect(pushedEvents).toHaveLength(1);

    await handlers.get('session_tree')!({ newLeafId: 'leaf-2' }, makeSessionContext({
      sessionManager: {
        getSessionId: () => 'sess-1',
        getLeafId: () => 'leaf-2',
      },
    } as Partial<ExtensionContext>));

    expect(pushedEvents).toHaveLength(1);
  });


  test('local input handles the most recent pending alert', async () => {
    const handlers = new Map<string, (event: unknown, ctx: ExtensionContext) => Promise<void> | void>();
    const handled: Array<{ sessionId: string; request: { handledThroughEventId: string; handledThroughEventCreatedAt?: string; action?: string } }> = [];
    const pi = {
      on: (eventName: string, handler: (event: unknown, ctx: ExtensionContext) => Promise<void> | void) => handlers.set(eventName, handler),
    } as unknown as ExtensionAPI;
    const adapter = makeAdapter({
      pushEvent: async () => ({ eventId: 'event-latest' }),
      handleSession: async (sessionId, request) => {
        handled.push({ sessionId, request });
        return { ok: true, hostId: 'host-1', sessionId, handledThroughEventId: request.handledThroughEventId };
      },
    });

    ariavaPiExtension(pi, adapter);
    const ctx = makeSessionContext();
    await handlers.get('session_start')!({}, ctx);
    await handlers.get('agent_end')!({}, ctx);
    await new Promise((resolve) => setTimeout(resolve, 1_700));
    await handlers.get('input')!({}, ctx);
    await new Promise((resolve) => setTimeout(resolve, 25));

    expect(handled).toHaveLength(1);
    expect(handled[0]).toMatchObject({
      sessionId: 'sess-1',
      request: {
        handledThroughEventId: 'event-latest',
        action: 'pi_input',
      },
    });
    expect(typeof handled[0]?.request.handledThroughEventCreatedAt).toBe('string');
  });

  test('terminal alert carries assistant reply and latest user message separately', async () => {
    const handlers = new Map<string, (event: unknown, ctx: ExtensionContext) => Promise<void> | void>();
    const pushedEvents: unknown[] = [];
    const pi = {
      on: (eventName: string, handler: (event: unknown, ctx: ExtensionContext) => Promise<void> | void) => {
        handlers.set(eventName, handler);
      },
    } as unknown as ExtensionAPI;
    const adapter = makeAdapter({
      pushEvent: async (event) => {
        pushedEvents.push(event);
        return { eventId: 'event-1' };
      },
    });

    ariavaPiExtension(pi, adapter);
    const ctx = makeSessionContext({
      sessionManager: {
        getSessionId: () => 'sess-1',
        buildSessionContext: () => ({
          messages: [
            { role: 'user', content: [{ type: 'text', text: 'Please fix the watch alert sections.' }] },
            {
              role: 'assistant',
              content: [{ type: 'text', text: 'I found the alert detail view and will update it.' }],
              api: 'anthropic-messages',
              provider: 'anthropic',
              model: 'claude-sonnet-4-20250514',
              usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
              stopReason: 'stop',
              timestamp: Date.now(),
            },
          ],
        }),
      },
    } as unknown as Partial<ExtensionContext>);

    await handlers.get('session_start')!({}, ctx);
    await handlers.get('agent_end')!({}, ctx);
    await new Promise((resolve) => setTimeout(resolve, 1_700));

    const terminalEvent = pushedEvents.find((event) => (event as { type?: string }).type === 'done') as {
      assistantText?: string;
      userMessageText?: string;
    };
    expect(terminalEvent.assistantText).toBe('I found the alert detail view and will update it.');
    expect(terminalEvent.userMessageText).toBe('Please fix the watch alert sections.');
  });
  test('agent_end error enters recovery hold and blocks only after timeout', async () => {
    const previousHoldMs = process.env.ARIAVA_PI_RECOVERY_HOLD_MS;
    process.env.ARIAVA_PI_RECOVERY_HOLD_MS = '40';
    try {
      const handlers = new Map<string, (event: unknown, ctx: ExtensionContext) => Promise<void> | void>();
      const pushedEvents: unknown[] = [];
      const pi = {
        on: (eventName: string, handler: (event: unknown, ctx: ExtensionContext) => Promise<void> | void) => {
          handlers.set(eventName, handler);
        },
      } as unknown as ExtensionAPI;
      const adapter = makeAdapter({
        pushEvent: async (event) => {
          pushedEvents.push(event);
          return { eventId: 'event-1' };
        },
      });

      ariavaPiExtension(pi, adapter);
      const ctx = makeSessionContext({
        sessionManager: {
          getSessionId: () => 'sess-1',
          buildSessionContext: () => ({
            messages: [
              { role: 'user', content: [{ type: 'text', text: 'Please continue.' }] },
            ],
          }),
        },
      } as unknown as Partial<ExtensionContext>);

      await handlers.get('session_start')!({}, ctx);
      await handlers.get('agent_end')!({
        messages: [
          {
            role: 'assistant',
            content: [],
            api: 'anthropic-messages',
            provider: 'anthropic',
            model: 'claude-sonnet-4-20250514',
            usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
            stopReason: 'error',
            errorMessage: 'stream_read_error',
            timestamp: Date.now(),
          },
        ],
      }, ctx);

      expect(pushedEvents.some((event) => (event as { type?: string }).type === 'done')).toBe(false);
      expect(pushedEvents.some((event) => (event as { type?: string }).type === 'blocked')).toBe(false);
      expect(pushedEvents.some((event) => (event as { type?: string; assistantText?: string }).type === 'working'
        && (event as { assistantText?: string }).assistantText === 'stream_read_error')).toBe(true);

      await new Promise((resolve) => setTimeout(resolve, 70));
      expect(pushedEvents.some((event) => (event as { type?: string; assistantText?: string }).type === 'blocked'
        && (event as { assistantText?: string }).assistantText === 'stream_read_error')).toBe(true);
    } finally {
      if (previousHoldMs === undefined) {
        delete process.env.ARIAVA_PI_RECOVERY_HOLD_MS;
      } else {
        process.env.ARIAVA_PI_RECOVERY_HOLD_MS = previousHoldMs;
      }
    }
  });

  test('agent_start clears pending recovery hold before it blocks', async () => {
    const previousHoldMs = process.env.ARIAVA_PI_RECOVERY_HOLD_MS;
    process.env.ARIAVA_PI_RECOVERY_HOLD_MS = '40';
    try {
      const handlers = new Map<string, (event: unknown, ctx: ExtensionContext) => Promise<void> | void>();
      const pushedEvents: unknown[] = [];
      const pi = {
        on: (eventName: string, handler: (event: unknown, ctx: ExtensionContext) => Promise<void> | void) => {
          handlers.set(eventName, handler);
        },
      } as unknown as ExtensionAPI;
      const adapter = makeAdapter({
        pushEvent: async (event) => {
          pushedEvents.push(event);
          return { eventId: 'event-1' };
        },
      });
      ariavaPiExtension(pi, adapter);
      const ctx = makeSessionContext();

      await handlers.get('session_start')!({}, ctx);
      await handlers.get('agent_end')!({
        messages: [{ role: 'assistant', content: [], stopReason: 'error', errorMessage: 'network timeout', timestamp: Date.now() }],
      }, ctx);
      await handlers.get('agent_start')!({}, ctx);
      await new Promise((resolve) => setTimeout(resolve, 70));

      expect(pushedEvents.filter((event) => (event as { type?: string }).type === 'blocked')).toEqual([]);
    } finally {
      if (previousHoldMs === undefined) delete process.env.ARIAVA_PI_RECOVERY_HOLD_MS;
      else process.env.ARIAVA_PI_RECOVERY_HOLD_MS = previousHoldMs;
    }
  });

  test('session_tree clears pending recovery hold before it blocks', async () => {
    const previousHoldMs = process.env.ARIAVA_PI_RECOVERY_HOLD_MS;
    process.env.ARIAVA_PI_RECOVERY_HOLD_MS = '40';
    try {
      const handlers = new Map<string, (event: unknown, ctx: ExtensionContext) => Promise<void> | void>();
      const pushedEvents: unknown[] = [];
      const pi = {
        on: (eventName: string, handler: (event: unknown, ctx: ExtensionContext) => Promise<void> | void) => {
          handlers.set(eventName, handler);
        },
      } as unknown as ExtensionAPI;
      const adapter = makeAdapter({
        pushEvent: async (event) => {
          pushedEvents.push(event);
          return { eventId: 'event-1' };
        },
      });
      ariavaPiExtension(pi, adapter);
      const ctx = makeSessionContext({
        sessionManager: {
          getSessionId: () => 'sess-1',
          getLeafId: () => 'leaf-1',
        },
      } as unknown as Partial<ExtensionContext>);

      await handlers.get('session_start')!({}, ctx);
      await handlers.get('agent_end')!({
        messages: [{ role: 'assistant', content: [], stopReason: 'error', errorMessage: 'network timeout', timestamp: Date.now() }],
      }, ctx);
      await handlers.get('session_tree')!({ newLeafId: 'leaf-2' }, makeSessionContext({
        sessionManager: {
          getSessionId: () => 'sess-1',
          getLeafId: () => 'leaf-2',
        },
      } as unknown as Partial<ExtensionContext>));
      await new Promise((resolve) => setTimeout(resolve, 70));

      expect(pushedEvents.filter((event) => (event as { type?: string }).type === 'blocked')).toEqual([]);
    } finally {
      if (previousHoldMs === undefined) delete process.env.ARIAVA_PI_RECOVERY_HOLD_MS;
      else process.env.ARIAVA_PI_RECOVERY_HOLD_MS = previousHoldMs;
    }
  });

  test('session_shutdown clears pending recovery hold before it blocks', async () => {
    const previousHoldMs = process.env.ARIAVA_PI_RECOVERY_HOLD_MS;
    process.env.ARIAVA_PI_RECOVERY_HOLD_MS = '40';
    try {
      const handlers = new Map<string, (event: unknown, ctx: ExtensionContext) => Promise<void> | void>();
      const pushedEvents: unknown[] = [];
      const pi = {
        on: (eventName: string, handler: (event: unknown, ctx: ExtensionContext) => Promise<void> | void) => {
          handlers.set(eventName, handler);
        },
      } as unknown as ExtensionAPI;
      const adapter = makeAdapter({
        pushEvent: async (event) => {
          pushedEvents.push(event);
          return { eventId: 'event-1' };
        },
      });
      ariavaPiExtension(pi, adapter);
      const ctx = makeSessionContext();

      await handlers.get('session_start')!({}, ctx);
      await handlers.get('agent_end')!({
        messages: [{ role: 'assistant', content: [], stopReason: 'error', errorMessage: 'network timeout', timestamp: Date.now() }],
      }, ctx);
      await handlers.get('session_shutdown')!({ reason: 'quit' }, ctx);
      await new Promise((resolve) => setTimeout(resolve, 70));

      expect(pushedEvents.filter((event) => (event as { type?: string }).type === 'blocked')).toEqual([]);
    } finally {
      if (previousHoldMs === undefined) delete process.env.ARIAVA_PI_RECOVERY_HOLD_MS;
      else process.env.ARIAVA_PI_RECOVERY_HOLD_MS = previousHoldMs;
    }
  });

  test('agent_end length enters recovery hold instead of done', async () => {
    const handlers = new Map<string, (event: unknown, ctx: ExtensionContext) => Promise<void> | void>();
    const pushedEvents: unknown[] = [];
    const pi = {
      on: (eventName: string, handler: (event: unknown, ctx: ExtensionContext) => Promise<void> | void) => {
        handlers.set(eventName, handler);
      },
    } as unknown as ExtensionAPI;
    const adapter = makeAdapter({
      pushEvent: async (event) => {
        pushedEvents.push(event);
        return { eventId: 'event-1' };
      },
    });
    ariavaPiExtension(pi, adapter);
    const ctx = makeSessionContext();

    await handlers.get('session_start')!({}, ctx);
    await handlers.get('agent_end')!({
      messages: [{ role: 'assistant', content: [{ type: 'text', text: 'Partial output' }], stopReason: 'length', timestamp: Date.now() }],
    }, ctx);

    expect(pushedEvents.some((event) => (event as { type?: string }).type === 'done')).toBe(false);
    expect(pushedEvents.some((event) => (event as { type?: string }).type === 'working')).toBe(true);
  });

  test('agent_end toolUse emits blocked', async () => {
    const handlers = new Map<string, (event: unknown, ctx: ExtensionContext) => Promise<void> | void>();
    const pushedEvents: unknown[] = [];
    const pi = {
      on: (eventName: string, handler: (event: unknown, ctx: ExtensionContext) => Promise<void> | void) => {
        handlers.set(eventName, handler);
      },
    } as unknown as ExtensionAPI;
    const adapter = makeAdapter({
      pushEvent: async (event) => {
        pushedEvents.push(event);
        return { eventId: 'event-1' };
      },
    });
    ariavaPiExtension(pi, adapter);
    const ctx = makeSessionContext();

    await handlers.get('session_start')!({}, ctx);
    await handlers.get('agent_end')!({
      messages: [{ role: 'assistant', content: [], stopReason: 'toolUse', timestamp: Date.now() }],
    }, ctx);
    await new Promise((resolve) => setTimeout(resolve, 1_700));

    expect(pushedEvents.some((event) => (event as { type?: string }).type === 'done')).toBe(false);
    expect(pushedEvents.some((event) => (event as { type?: string; assistantText?: string }).type === 'blocked'
      && (event as { assistantText?: string }).assistantText === 'Agent stopped while waiting to use a tool')).toBe(true);
  });

  test('agent_end aborted does not emit done', async () => {
    const handlers = new Map<string, (event: unknown, ctx: ExtensionContext) => Promise<void> | void>();
    const pushedEvents: unknown[] = [];
    const pi = {
      on: (eventName: string, handler: (event: unknown, ctx: ExtensionContext) => Promise<void> | void) => {
        handlers.set(eventName, handler);
      },
    } as unknown as ExtensionAPI;
    const adapter = makeAdapter({
      pushEvent: async (event) => {
        pushedEvents.push(event);
        return { eventId: 'event-1' };
      },
    });
    ariavaPiExtension(pi, adapter);
    const ctx = makeSessionContext();

    await handlers.get('session_start')!({}, ctx);
    await handlers.get('agent_end')!({
      messages: [{ role: 'assistant', content: [], stopReason: 'aborted', timestamp: Date.now() }],
    }, ctx);
    await new Promise((resolve) => setTimeout(resolve, 1_700));

    expect(pushedEvents.some((event) => (event as { type?: string }).type === 'done')).toBe(false);
    expect(pushedEvents.filter((event) => ['done', 'blocked', 'question_requested'].includes(String((event as { type?: string }).type)))).toEqual([]);
  });

  test('/new session replacement clears pending terminal alerts before they reach the watch', async () => {
    const handlers = new Map<string, (event: unknown, ctx: ExtensionContext) => Promise<void> | void>();
    const pushedEvents: unknown[] = [];
    const unregisteredSessions: string[] = [];
    const pi = {
      on: (eventName: string, handler: (event: unknown, ctx: ExtensionContext) => Promise<void> | void) => {
        handlers.set(eventName, handler);
      },
    } as unknown as ExtensionAPI;
    const adapter = makeAdapter({
      pushEvent: async (event) => {
        pushedEvents.push(event);
        return { eventId: 'event-1' };
      },
      unregisterSession: async (sessionId) => {
        unregisteredSessions.push(sessionId);
      },
    });

    ariavaPiExtension(pi, adapter);
    const ctx = makeSessionContext({
      sessionManager: {
        getSessionId: () => 'sess-1',
        buildSessionContext: () => ({
          messages: [
            { role: 'user', content: [{ type: 'text', text: 'Please update the bridge.' }] },
            {
              role: 'assistant',
              content: [{ type: 'text', text: 'I updated the bridge.' }],
              api: 'anthropic-messages',
              provider: 'anthropic',
              model: 'claude-sonnet-4-20250514',
              usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
              stopReason: 'stop',
              timestamp: Date.now(),
            },
          ],
        }),
      },
    } as unknown as Partial<ExtensionContext>);

    await handlers.get('session_start')!({}, ctx);
    await handlers.get('agent_end')!({}, ctx);
    await handlers.get('session_shutdown')!({ reason: 'new' }, ctx);
    await new Promise((resolve) => setTimeout(resolve, 1_700));

    expect(unregisteredSessions).toEqual(['sess-1']);
    expect(pushedEvents.filter((event) => ['done', 'blocked', 'question_requested'].includes(String((event as { type?: string }).type)))).toEqual([]);
  });

  test('ignores late agent_end from a replaced previous session', async () => {
    const handlers = new Map<string, (event: unknown, ctx: ExtensionContext) => Promise<void> | void>();
    const pushedEvents: unknown[] = [];
    const pi = {
      on: (eventName: string, handler: (event: unknown, ctx: ExtensionContext) => Promise<void> | void) => {
        handlers.set(eventName, handler);
      },
    } as unknown as ExtensionAPI;
    const adapter = makeAdapter({
      pushEvent: async (event) => {
        pushedEvents.push(event);
        return { eventId: 'event-1' };
      },
    });

    ariavaPiExtension(pi, adapter);
    const oldCtx = makeSessionContext({
      sessionManager: {
        getSessionId: () => 'sess-old',
        buildSessionContext: () => ({
          messages: [
            { role: 'user', content: [{ type: 'text', text: 'Please do something slow.' }] },
            {
              role: 'assistant',
              content: [{ type: 'text', text: 'I was interrupted but still produced a late end event.' }],
              api: 'anthropic-messages',
              provider: 'anthropic',
              model: 'claude-sonnet-4-20250514',
              usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
              stopReason: 'stop',
              timestamp: Date.now(),
            },
          ],
        }),
      },
    } as unknown as Partial<ExtensionContext>);
    const newCtx = makeSessionContext({
      sessionManager: {
        getSessionId: () => 'sess-new',
      },
    } as unknown as Partial<ExtensionContext>);

    await handlers.get('session_start')!({}, oldCtx);
    await handlers.get('session_shutdown')!({ reason: 'new' }, oldCtx);
    await handlers.get('session_start')!({ reason: 'new' }, newCtx);

    await handlers.get('agent_end')!({}, oldCtx);
    await new Promise((resolve) => setTimeout(resolve, 1_700));

    expect(pushedEvents.filter((event) => ['done', 'blocked', 'question_requested'].includes(String((event as { type?: string }).type)))).toEqual([]);
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
      pi?: { extensions?: string[] };
    };

    expect(manifest.name).toBe('@ariava/pi-extension');
    expect(manifest.private).toBeUndefined();
    expect(manifest.keywords).toContain('pi-package');
    expect(manifest.files).toContain('index.js');
    expect(manifest.pi?.extensions).toEqual(['./index.js']);
  });
});
