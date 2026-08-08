import { describe, expect, mock, test } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { CommandEnvelope, CommandResult } from '@ariava/protocol';
import { AgentAdapterRegistry, type AgentAdapterEventInput } from '../../src/agent-adapter/registry';
import { BridgeStateStore } from '../../src/state-store';

mock.module('../../src/e2e/node-crypto', () => ({
  chachaPolySeal: (_key: Uint8Array, plaintext: Uint8Array) => ({
    nonce: new Uint8Array(12).fill(1), ciphertext: new Uint8Array([...plaintext, ...new Uint8Array(16)]),
  }),
  chachaPolyOpen: (_key: Uint8Array, _nonce: Uint8Array, ciphertext: Uint8Array) => ciphertext.slice(0, -16),
}));

function initializedStore(dir: string): BridgeStateStore {
  const store = new BridgeStateStore(join(dir, 'state.json'));
  store.initializeEncryptedSpool('host-1', join(dir, 'identity.json'), 'linux', {
    loadOrCreate: () => new Uint8Array(32).fill(7),
  });
  return store;
}

function makeStore(): { store: BridgeStateStore; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), 'bridge-registry-'));
  return {
    store: initializedStore(dir),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

function doneEvent(overrides: Partial<AgentAdapterEventInput> = {}): AgentAdapterEventInput {
  return {
    sessionId: 'sess-1',
    provider: 'pi',
    type: 'done',
    status: 'idle',
    typeLabel: 'Task complete',
    agentText: 'Finished successfully',
    projectName: 'project',
    contextText: 'Task · project',
    workingDirectory: '/project',
    hbaseSessionKey: 'sess-1',
    harnessProvider: 'pi',
    createdAt: '2026-08-07T00:00:01.000Z',
    ...overrides,
  } as AgentAdapterEventInput;
}

function needHumanEvent(overrides: Partial<AgentAdapterEventInput> = {}): AgentAdapterEventInput {
  return {
    sessionId: 'sess-1',
    provider: 'pi',
    type: 'need_human',
    status: 'need_human',
    typeLabel: 'Needs attention',
    agentText: 'Which environment should I target?',
    projectName: 'project',
    contextText: 'Task · project',
    workingDirectory: '/project',
    hbaseSessionKey: 'sess-1',
    harnessProvider: 'pi',
    actionablePrompt: { promptId: 'question-1', type: 'question', label: 'Reply' },
    needHuman: { reason: 'question' },
    createdAt: '2026-08-07T00:00:02.000Z',
    ...overrides,
  } as AgentAdapterEventInput;
}

function makeCommand(sessionId: string): CommandEnvelope {
  return {
    commandId: `cmd-${sessionId}`,
    hostId: 'host-1',
    sessionId,
    type: 'reply',
    payload: {},
    issuedAt: '2099-06-30T10:00:00.000Z',
    expiresAt: '2099-06-30T10:05:00.000Z',
    nonce: 'n-1',
    watchDeviceId: 'watch-1',
  };
}

function register(registry: AgentAdapterRegistry): void {
  registry.register({
    sessionId: 'sess-1', provider: 'pi', projectName: 'project', cwd: '/project', nameText: 'Task',
    status: 'working', latestActivityText: 'Running',
  });
}

describe('AgentAdapterRegistry canonical ingest', () => {
  test('register and unregister remain transactional across persistence failures and restart', () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-registry-transaction-'));
    try {
      const statePath = join(dir, 'state.json');
      let failWrites = true;
      const store = new BridgeStateStore(statePath, (path, value) => {
        if (failWrites) throw new Error('state persistence failed');
        writeFileSync(path, JSON.stringify(value), { mode: 0o600 });
      });
      store.initializeEncryptedSpool('host-1', join(dir, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
      const registry = new AgentAdapterRegistry('host-1', store);
      expect(() => register(registry)).toThrow('state persistence failed');
      expect(registry.hasSession('sess-1')).toBe(false);
      expect(store.getDriverNameForSession('sess-1')).toBeUndefined();
      failWrites = false;
      register(registry);
      expect(registry.hasSession('sess-1')).toBe(true);
      expect(store.getDriverNameForSession('sess-1')).toBe('pi');
      failWrites = true;
      expect(() => registry.unregister('sess-1')).toThrow('state persistence failed');
      expect(registry.hasSession('sess-1')).toBe(true);
      expect(store.getDriverNameForSession('sess-1')).toBe('pi');
      failWrites = false;
      expect(registry.unregister('sess-1')).toBe(true);
      store.dispose();
      const restarted = new BridgeStateStore(statePath);
      expect(restarted.getDriverNameForSession('sess-1')).toBeUndefined();
      expect(restarted.listSessions()).toEqual([]);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('deduplicates the complete producer DTO immediately, after delay, and after restart', () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-registry-dedupe-'));
    try {
      const store = initializedStore(dir);
      const registry = new AgentAdapterRegistry('host-1', store);
      register(registry);
      const producer = doneEvent({ correlationId: 'loop-1' });
      const first = registry.pushEvent('sess-1', producer);
      expect(registry.pushEvent('sess-1', producer)).toBe(first);
      const persisted = JSON.parse(readFileSync(join(dir, 'state.json'), 'utf8'));
      expect(JSON.stringify(persisted.producerEventReservations)).not.toContain('Finished successfully');
      expect(Object.values(persisted.producerEventReservations)[0]).toEqual(expect.objectContaining({
        version: 1, eventId: first, sessionId: 'sess-1', fingerprint: expect.any(String),
      }));
      expect(registry.pushEvent('sess-1', doneEvent({ correlationId: 'loop-2' }))).not.toBe(first);
      expect(registry.pushEvent('sess-1', doneEvent({ correlationId: 'loop-1', createdAt: '2026-08-07T00:00:03.000Z' }))).not.toBe(first);
      const delayed = needHumanEvent({ correlationId: 'delayed-1' });
      registry.enqueueCommand(makeCommand('sess-1'));
      const delayedId = registry.pushEvent('sess-1', delayed);
      expect(registry.pushEvent('sess-1', delayed)).toBe(delayedId);
      store.dispose();
      const restartedStore = initializedStore(dir);
      const restarted = new AgentAdapterRegistry('host-1', restartedStore);
      register(restarted);
      expect(restarted.pushEvent('sess-1', producer)).toBe(first);
      expect(restarted.pushEvent('sess-1', delayed)).toBe(delayedId);
      expect(restartedStore.peekPendingEvents().some((event) => event.eventId === delayedId)).toBe(true);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('canonicalizes nested producer fields for immediate, delayed, and restart dedupe', () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-registry-nested-dedupe-'));
    try {
      const store = initializedStore(dir);
      const registry = new AgentAdapterRegistry('host-1', store);
      register(registry);
      const first = needHumanEvent({
        correlationId: 'nested-immediate',
        actionablePrompt: { promptId: 'question-1', type: 'question', label: 'Reply', expiresAt: '2026-08-07T00:05:00.000Z' },
        needHuman: { reason: 'error', error: { kind: 'provider_failure', message: 'Provider failed safely.', providerCode: 'E_PROVIDER', retryExhausted: true } },
      });
      const reordered = needHumanEvent({
        correlationId: 'nested-immediate',
        actionablePrompt: { expiresAt: '2026-08-07T00:05:00.000Z', label: 'Reply', type: 'question', promptId: 'question-1' },
        needHuman: { error: { retryExhausted: true, providerCode: 'E_PROVIDER', message: 'Provider failed safely.', kind: 'provider_failure' }, reason: 'error' },
      });
      const immediateId = registry.pushEvent('sess-1', first);
      expect(registry.pushEvent('sess-1', reordered)).toBe(immediateId);
      expect(registry.pushEvent('sess-1', {
        ...structuredClone(reordered),
        actionablePrompt: { ...structuredClone(reordered.actionablePrompt!), label: 'Different prompt' },
      })).not.toBe(immediateId);
      expect(registry.pushEvent('sess-1', {
        ...structuredClone(reordered),
        needHuman: { reason: 'error', error: { ...structuredClone((reordered.needHuman as any).error), message: 'Different error' } },
      })).not.toBe(immediateId);

      const delayed = { ...structuredClone(first), correlationId: 'nested-delayed', createdAt: '2026-08-07T00:00:04.000Z' };
      const delayedReordered = { ...structuredClone(reordered), correlationId: 'nested-delayed', createdAt: '2026-08-07T00:00:04.000Z' };
      registry.enqueueCommand(makeCommand('sess-1'));
      const delayedId = registry.pushEvent('sess-1', delayed);
      expect(registry.pushEvent('sess-1', delayedReordered)).toBe(delayedId);

      store.dispose();
      const restarted = new AgentAdapterRegistry('host-1', initializedStore(dir));
      register(restarted);
      expect(restarted.pushEvent('sess-1', reordered)).toBe(immediateId);
      expect(restarted.pushEvent('sess-1', delayedReordered)).toBe(delayedId);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('restart recovers a reservation whose metadata response was lost', () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-registry-reservation-restart-'));
    try {
      const statePath = join(dir, 'state.json');
      let writes = 0;
      const store = new BridgeStateStore(statePath, (path, value) => {
        writes += 1;
        if (writes === 2) throw new Error('lost reservation metadata response');
        writeFileSync(path, JSON.stringify(value), { mode: 0o600 });
      });
      store.initializeEncryptedSpool('host-1', join(dir, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
      const registry = new AgentAdapterRegistry('host-1', store);
      register(registry);
      const producer = doneEvent({ correlationId: 'lost-response' });
      expect(() => registry.pushEvent('sess-1', producer)).toThrow('lost reservation metadata response');
      store.dispose();
      const restartedStore = initializedStore(dir);
      const restarted = new AgentAdapterRegistry('host-1', restartedStore);
      register(restarted);
      const eventId = restarted.pushEvent('sess-1', producer);
      expect(eventId).toMatch(/^evt_/u);
      expect(restartedStore.peekPendingEvents().map((event) => event.eventId)).toEqual([eventId]);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('dispose cancels retries and prevents writes after shutdown', async () => {
    const { store, cleanup } = makeStore();
    try {
      const callbacks: Array<() => void> = [];
      const canceled: unknown[] = [];
      const scheduler = { schedule(callback: () => void) { callbacks.push(callback); return callbacks.length; },
        cancel(handle: unknown) { canceled.push(handle); } };
      const registry = new AgentAdapterRegistry('host-1', store, () => {}, () => new Date(), scheduler);
      register(registry);
      const command = makeCommand('sess-1');
      registry.enqueueCommand(command);
      registry.pushEvent('sess-1', doneEvent());
      await registry.dequeueCommand('sess-1', 0);
      store.queuePendingEvent = (() => { throw new Error('unavailable'); }) as typeof store.queuePendingEvent;
      registry.resolveCommand(command.commandId, { commandId: command.commandId, hostId: command.hostId,
        sessionId: command.sessionId, accepted: true, status: 'executed', message: 'ok', updatedAt: '2026-08-07T00:00:03.000Z' });
      expect(callbacks).toHaveLength(1);
      registry.dispose();
      expect(canceled).toEqual([1]);
      let writes = 0;
      store.queuePendingEvent = (() => { writes += 1; }) as typeof store.queuePendingEvent;
      callbacks[0]!();
      expect(writes).toBe(0);
    } finally { cleanup(); }
  });

  test.each(['dispose', 'unregister'] as const)('cancels and safely settles result waiters on %s', async (action) => {
    const { store, cleanup } = makeStore();
    try {
      const callbacks: Array<() => void> = [];
      const canceled: symbol[] = [];
      const resultScheduler = {
        schedule(callback: () => void) { const handle = Symbol('result-waiter'); callbacks.push(callback); return handle; },
        cancel(handle: unknown) { canceled.push(handle as symbol); },
      };
      const registry = new AgentAdapterRegistry(
        'host-1', store, () => {}, () => new Date(), undefined, resultScheduler,
      );
      register(registry);
      const command = makeCommand('sess-1');
      registry.enqueueCommand(command);
      const waiting = [
        registry.waitForResult(command.commandId, { timeoutMs: 60_000 }),
        registry.waitForResult(command.commandId, { timeoutMs: 60_000 }),
      ];
      if (action === 'dispose') registry.dispose();
      else registry.unregister('sess-1');
      await expect(Promise.all(waiting)).resolves.toEqual([undefined, undefined]);
      expect(canceled).toHaveLength(2);
      callbacks.forEach((callback) => callback());
      const lateResult = {
        commandId: command.commandId, hostId: command.hostId, sessionId: command.sessionId, accepted: true,
        status: 'executed' as const, message: 'late', updatedAt: '2026-08-07T00:00:03.000Z',
      };
      if (action === 'dispose') expect(() => registry.resolveCommand(command.commandId, lateResult)).not.toThrow();
      else expect(() => registry.resolveCommand(command.commandId, lateResult)).toThrow(/queued adapter command/u);
      expect((registry as any).results.size).toBe(0);
    } finally { cleanup(); }
  });
  test('registers, heartbeats, and lists a canonical Session', () => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store);
      register(registry);
      registry.heartbeat('sess-1', 'working', 'Running tests');
      expect(registry.listSessions()[0]).toMatchObject({
        sessionId: 'sess-1', hostId: 'host-1', provider: 'pi', status: 'working',
        latestActivityText: 'Running tests', workingDirectory: '/project',
      });
    } finally { cleanup(); }
  });

  test('accepts the complete pi DTO, adds only Bridge identity, and atomically binds done to idle', () => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store, () => {}, () => new Date('2026-08-07T00:00:03.000Z'));
      register(registry);
      const eventId = registry.pushEvent('sess-1', doneEvent());
      expect(eventId).toMatch(/^evt_/u);
      expect(registry.listSessions()[0]).toMatchObject({
        status: 'idle', latestActivityText: 'Finished successfully', lastEventId: eventId,
      });
      expect(store.peekPendingUploads()).toEqual([{
        event: { ...doneEvent(), eventId, hostId: 'host-1' },
        session: expect.objectContaining({ sessionId: 'sess-1', status: 'idle', lastEventId: eventId }),
      }]);
    } finally { cleanup(); }
  });

  test('binds need_human to a need_human terminal Session and preserves protected reason', () => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store);
      register(registry);
      registry.pushEvent('sess-1', needHumanEvent({
        needHuman: { reason: 'error', error: { kind: 'provider_failure', message: 'Provider failed safely.', providerCode: 'E_PROVIDER', retryExhausted: true } },
      }));
      expect(registry.listSessions()[0]).toMatchObject({ status: 'need_human' });
      expect(store.peekPendingEvents()[0]).toMatchObject({
        type: 'need_human', status: 'need_human',
        needHuman: { reason: 'error', error: { providerCode: 'E_PROVIDER', retryExhausted: true } },
      });
    } finally { cleanup(); }
  });

  test.each([
    ['omitted type', (({ type: _type, ...value }) => value)(doneEvent())],
    ['legacy type', { ...doneEvent(), type: 'blocked', status: 'blocked' }],
    ['mismatched pair', { ...doneEvent(), type: 'done', status: 'need_human' }],
    ['missing needHuman', { ...needHumanEvent(), needHuman: undefined }],
    ['malformed error', { ...needHumanEvent(), needHuman: { reason: 'error', error: { kind: 'provider_failure', message: 'Authorization: Bearer secret', retryExhausted: true } } }],
    ['producer eventId', { ...doneEvent(), eventId: 'producer-event' }],
    ['producer hostId', { ...doneEvent(), hostId: 'producer-host' }],
    ['excess field', { ...doneEvent(), unknownField: true }],
    ...(['projectName', 'contextText', 'workingDirectory', 'hbaseSessionKey', 'harnessProvider'] as const).map((key) => [
      `omitted ${key}`, Object.fromEntries(Object.entries(doneEvent()).filter(([field]) => field !== key)),
    ]),
    ['oversized protected payload', { ...doneEvent(), agentText: 'x'.repeat(33_000) }],
  ])('rejects %s before Session mutation or Event persistence', (_name, candidate) => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store);
      register(registry);
      const before = registry.listSessions()[0];
      expect(() => registry.pushEvent('sess-1', candidate as never)).toThrow(/canonical|unsupported|required|invalid/u);
      expect(registry.listSessions()[0]).toEqual(before);
      expect(store.peekPendingEvents()).toEqual([]);
    } finally { cleanup(); }
  });

  test('rejects a DTO whose path Session disagrees with its body Session', () => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store);
      register(registry);
      expect(() => registry.pushEvent('sess-1', doneEvent({ sessionId: 'sess-other' }))).toThrow(/sessionId/u);
      expect(registry.listSessions()[0]?.status).toBe('working');
    } finally { cleanup(); }
  });

  test.each([
    ['provider', { provider: 'other' }],
    ['projectName', { projectName: 'other' }],
    ['contextText', { contextText: 'other' }],
    ['workingDirectory', { workingDirectory: '/other' }],
    ['hbaseSessionKey', { hbaseSessionKey: 'other' }],
    ['harnessProvider', { harnessProvider: 'other' }],
  ])('rejects mismatched %s before allocating or persisting an Event', (_name, override) => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store);
      register(registry);
      const before = registry.listSessions()[0];
      expect(() => registry.pushEvent('sess-1', doneEvent(override as never))).toThrow(/match/u);
      expect(registry.listSessions()[0]).toEqual(before);
      expect(store.peekPendingEvents()).toEqual([]);
    } finally { cleanup(); }
  });

  test('delays every canonical terminal Event during command work and flushes the latest exact pair', async () => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store);
      register(registry);
      const command = makeCommand('sess-1');
      registry.enqueueCommand(command);
      registry.pushEvent('sess-1', doneEvent({ agentText: 'First terminal' }));
      registry.pushEvent('sess-1', needHumanEvent({ agentText: 'Latest terminal' }));
      expect(store.peekPendingEvents()).toEqual([]);
      expect(registry.listSessions()[0]).toMatchObject({ status: 'working', latestActivityText: 'Running', lastEventId: undefined });

      await registry.dequeueCommand('sess-1', 0);
      const result: CommandResult = {
        commandId: command.commandId, hostId: command.hostId, sessionId: command.sessionId,
        accepted: true, status: 'executed', message: 'ok', updatedAt: '2026-08-07T00:00:03.000Z',
      };
      registry.resolveCommand(command.commandId, result);
      expect(store.peekPendingEvents()).toEqual([
        expect.objectContaining({ type: 'need_human', status: 'need_human', agentText: 'Latest terminal' }),
      ]);
      expect(store.peekPendingUploads()[0]?.session).toMatchObject({ status: 'need_human' });
    } finally { cleanup(); }
  });

  test('persists the immediate immutable Event and snapshot before committing Session mutation', () => {
    const { store, cleanup } = makeStore();
    try {
      const mutations: string[] = [];
      const registry = new AgentAdapterRegistry('host-1', store, (reason) => mutations.push(reason));
      register(registry);
      mutations.length = 0;
      const before = registry.listSessions()[0];
      const original = store.queuePendingEvent.bind(store);
      let attempted: Parameters<typeof store.queuePendingEvent> | undefined;
      store.queuePendingEvent = ((event, session) => {
        attempted = [event, session];
        expect(registry.listSessions()[0]).toEqual(before);
        expect(mutations).toEqual([]);
        throw new Error('spool unavailable');
      }) as typeof store.queuePendingEvent;
      expect(() => registry.pushEvent('sess-1', doneEvent())).toThrow(/spool unavailable/u);
      expect(registry.listSessions()[0]).toEqual(before);
      expect(store.peekPendingEvents()).toEqual([]);
      expect(mutations).toEqual([]);
      expect(attempted?.[0]).toMatchObject({ type: 'done', status: 'idle' });
      expect(attempted?.[1]).toMatchObject({ status: 'idle', lastEventId: attempted?.[0].eventId });
      expect(Object.isFrozen(attempted?.[0])).toBe(true);
      expect(Object.isFrozen(attempted?.[1])).toBe(true);
      store.queuePendingEvent = original;
    } finally { cleanup(); }
  });

  test('reuses one Event ID and immutable tuple on immediate producer retry', () => {
    const { store, cleanup } = makeStore();
    try {
      const scheduler = { schedule: () => Symbol('retry'), cancel: () => {} };
      const registry = new AgentAdapterRegistry('host-1', store, () => {}, () => new Date(), scheduler);
      register(registry);
      const original = store.queuePendingEvent.bind(store);
      const attempts: Parameters<typeof store.queuePendingEvent>[] = [];
      let fail = true;
      store.queuePendingEvent = ((event, session, fingerprint) => {
        attempts.push([event, session, fingerprint]);
        if (fail) { fail = false; throw new Error('state write failed'); }
        original(event, session, fingerprint);
      }) as typeof store.queuePendingEvent;
      const producer = doneEvent();
      expect(() => registry.pushEvent('sess-1', producer)).toThrow('state write failed');
      const eventId = attempts[0]![0].eventId;
      expect(registry.pushEvent('sess-1', producer)).toBe(eventId);
      expect(attempts[1]![0]).toBe(attempts[0]![0]);
      expect(attempts[1]![1]).toBe(attempts[0]![1]);
      expect(store.peekPendingEvents()).toHaveLength(1);
    } finally { cleanup(); }
  });

  test('automatically retries an immutable delayed tuple with bounded backoff and no hot loop', async () => {
    const { store, cleanup } = makeStore();
    try {
      const callbacks: Array<{ callback: () => void; delayMs: number; handle: symbol }> = [];
      const canceled: symbol[] = [];
      const scheduler = {
        schedule(callback: () => void, delayMs: number) {
          const handle = Symbol(`retry-${callbacks.length}`); callbacks.push({ callback, delayMs, handle }); return handle;
        },
        cancel(handle: unknown) { canceled.push(handle as symbol); },
      };
      const mutations: string[] = [];
      const registry = new AgentAdapterRegistry('host-1', store, (reason) => mutations.push(reason), () => new Date(), scheduler);
      register(registry);
      mutations.length = 0;
      const command = makeCommand('sess-1');
      registry.enqueueCommand(command);
      const producerEvent = needHumanEvent({ agentText: 'Delayed question' });
      const eventId = registry.pushEvent('sess-1', producerEvent);
      (producerEvent.actionablePrompt as { label: string }).label = 'Mutated producer prompt';
      (producerEvent.needHuman as { reason: string }).reason = 'blocked';
      const before = registry.listSessions()[0];
      await registry.dequeueCommand('sess-1', 0);

      const original = store.queuePendingEvent.bind(store);
      const attempts: Parameters<typeof store.queuePendingEvent>[] = [];
      let failures = 2;
      store.queuePendingEvent = ((event, session, fingerprint) => {
        attempts.push([event, session, fingerprint]);
        if (failures-- > 0) throw new Error('spool unavailable');
        original(event, session, fingerprint);
      }) as typeof store.queuePendingEvent;
      registry.resolveCommand(command.commandId, {
        commandId: command.commandId, hostId: command.hostId, sessionId: command.sessionId,
        accepted: true, status: 'executed', message: 'ok', updatedAt: '2026-08-07T00:00:03.000Z',
      });
      expect(callbacks.map(({ delayMs }) => delayMs)).toEqual([100]);
      expect(registry.listSessions()[0]).toEqual(before);
      expect(callbacks).toHaveLength(1);

      callbacks[0]!.callback();
      expect(callbacks.map(({ delayMs }) => delayMs)).toEqual([100, 500]);
      expect(callbacks).toHaveLength(2);
      callbacks[1]!.callback();

      expect(attempts).toHaveLength(3);
      expect(attempts.every(([event]) => event === attempts[0]![0])).toBe(true);
      expect(attempts.every(([, session]) => session === attempts[0]![1])).toBe(true);
      expect(attempts[0]![0]).toMatchObject({
        eventId, agentText: 'Delayed question', actionablePrompt: { label: 'Reply' }, needHuman: { reason: 'question' },
      });
      expect(store.peekPendingUploads()[0]).toEqual(JSON.parse(JSON.stringify({ event: attempts[0]![0], session: attempts[0]![1] })));
      expect(registry.listSessions()[0]).toMatchObject({ status: 'need_human', lastEventId: eventId });
      expect(mutations).toEqual(['semantic']);
      expect(canceled).toEqual([]);
      expect(callbacks).toHaveLength(2);
    } finally { cleanup(); }
  });

  test.each(['unregister', 'context-change', 'newer-terminal'] as const)('cancels delayed retry on %s', async (action) => {
    const { store, cleanup } = makeStore();
    try {
      const callbacks: Array<{ callback: () => void; handle: symbol }> = [];
      const canceled: symbol[] = [];
      const scheduler = {
        schedule(callback: () => void) { const handle = Symbol('retry'); callbacks.push({ callback, handle }); return handle; },
        cancel(handle: unknown) { canceled.push(handle as symbol); },
      };
      const registry = new AgentAdapterRegistry('host-1', store, () => {}, () => new Date(), scheduler);
      register(registry);
      const command = makeCommand('sess-1');
      registry.enqueueCommand(command);
      registry.pushEvent('sess-1', doneEvent());
      await registry.dequeueCommand('sess-1', 0);
      store.queuePendingEvent = (() => { throw new Error('unavailable'); }) as typeof store.queuePendingEvent;
      registry.resolveCommand(command.commandId, {
        commandId: command.commandId, hostId: command.hostId, sessionId: command.sessionId, accepted: true,
        status: 'executed', message: 'ok', updatedAt: '2026-08-07T00:00:03.000Z',
      });
      expect(callbacks).toHaveLength(1);
      if (action === 'unregister') registry.unregister('sess-1');
      else if (action === 'context-change') registry.heartbeat('sess-1', 'working', undefined, { projectName: 'other' });
      else { registry.enqueueCommand(makeCommand('sess-1')); registry.pushEvent('sess-1', needHumanEvent({ agentText: 'New terminal' })); }
      expect(canceled).toEqual([callbacks[0]!.handle]);
      callbacks[0]!.callback();
      expect(callbacks).toHaveLength(1);
    } finally { cleanup(); }
  });

  test.each(['intent-write', 'state-commit'] as const)('aborted cancellation at %s preserves the exact retry tuple and Event ID', async (boundary) => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store, () => {}, () => new Date(), {
        schedule: () => Symbol('retry'), cancel: () => {},
      });
      register(registry);
      const command = makeCommand('sess-1');
      registry.enqueueCommand(command);
      const producer = doneEvent({ correlationId: `cancel-${boundary}` });
      const eventId = registry.pushEvent('sess-1', producer);
      await registry.dequeueCommand('sess-1', 0);
      const originalQueuePendingEvent = store.queuePendingEvent.bind(store);
      store.queuePendingEvent = (() => { throw new Error('retry unavailable'); }) as typeof store.queuePendingEvent;
      registry.resolveCommand(command.commandId, {
        commandId: command.commandId, hostId: command.hostId, sessionId: command.sessionId, accepted: true,
        status: 'executed', message: 'ok', updatedAt: '2026-08-07T00:00:03.000Z',
      });
      const spool = (store as any).spool;
      const originalEnqueue = spool.enqueue.bind(spool);
      const originalWriteState = (store as any).writeState;
      if (boundary === 'intent-write') spool.enqueue = () => { throw new Error('intent write failed'); };
      else (store as any).writeState = () => { throw new Error('state commit failed'); };
      expect(() => registry.unregister('sess-1')).toThrow(boundary === 'intent-write' ? 'intent write failed' : 'state commit failed');
      expect(registry.hasSession('sess-1')).toBe(true);
      expect(store.getDriverNameForSession('sess-1')).toBe('pi');
      expect(store.getTerminalEventCancellation('sess-1')?.eventId).toBe(eventId);
      spool.enqueue = originalEnqueue;
      (store as any).writeState = originalWriteState;
      store.queuePendingEvent = originalQueuePendingEvent;
      expect(registry.pushEvent('sess-1', producer)).toBe(eventId);
    } finally { cleanup(); }
  });

  test.each(['spool-remove', 'journal-cleanup'] as const)('committed cancellation survives %s failure and restart never replays the Event', async (boundary) => {
    const dir = mkdtempSync(join(tmpdir(), `bridge-registry-cancel-${boundary}-`));
    try {
      const statePath = join(dir, 'state.json');
      const store = initializedStore(dir);
      const registry = new AgentAdapterRegistry('host-1', store, () => {}, () => new Date(), {
        schedule: () => Symbol('retry'), cancel: () => {},
      });
      register(registry);
      const command = makeCommand('sess-1');
      registry.enqueueCommand(command);
      const eventId = registry.pushEvent('sess-1', doneEvent({ correlationId: boundary }));
      await registry.dequeueCommand('sess-1', 0);
      store.queuePendingEvent = (() => { throw new Error('retry unavailable'); }) as typeof store.queuePendingEvent;
      registry.resolveCommand(command.commandId, { commandId: command.commandId, hostId: command.hostId,
        sessionId: command.sessionId, accepted: true, status: 'executed', message: 'ok', updatedAt: '2026-08-07T00:00:03.000Z' });
      const spool = (store as any).spool;
      if (boundary === 'spool-remove') spool.removeMany = () => { throw new Error('spool remove failed'); };
      else {
        const originalWriteState = (store as any).writeState;
        let writes = 0;
        (store as any).writeState = (path: string, value: unknown) => {
          writes += 1;
          if (writes === 2) throw new Error('journal cleanup failed');
          originalWriteState(path, value);
        };
      }
      expect(registry.unregister('sess-1')).toBe(true);
      expect(registry.hasSession('sess-1')).toBe(false);
      expect(store.peekPendingEvents()).toEqual([]);
      store.dispose();
      const restarted = initializedStore(dir);
      expect(restarted.peekPendingEvents()).toEqual([]);
      expect(restarted.getSession('sess-1')).toBeUndefined();
      expect(restarted.getTerminalEventCancellation('sess-1')).toBeUndefined();
      expect(JSON.stringify(JSON.parse(readFileSync(statePath, 'utf8')))).not.toContain(eventId);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('state rename success followed by write error adopts the committed cancellation side', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-registry-cancel-late-write-'));
    try {
      const statePath = join(dir, 'state.json');
      let failAfterWrite = false;
      const store = new BridgeStateStore(statePath, (path, value) => {
        writeFileSync(path, JSON.stringify(value), { mode: 0o600 });
        if (failAfterWrite) { failAfterWrite = false; throw new Error('late state write failure'); }
      });
      store.initializeEncryptedSpool('host-1', join(dir, 'identity.json'), 'linux', { loadOrCreate: () => new Uint8Array(32).fill(7) });
      const registry = new AgentAdapterRegistry('host-1', store, () => {}, () => new Date(), { schedule: () => Symbol('retry'), cancel: () => {} });
      register(registry);
      const command = makeCommand('sess-1');
      registry.enqueueCommand(command);
      registry.pushEvent('sess-1', doneEvent({ correlationId: 'late-write' }));
      await registry.dequeueCommand('sess-1', 0);
      store.queuePendingEvent = (() => { throw new Error('retry unavailable'); }) as typeof store.queuePendingEvent;
      registry.resolveCommand(command.commandId, { commandId: command.commandId, hostId: command.hostId, sessionId: command.sessionId,
        accepted: true, status: 'executed', message: 'ok', updatedAt: '2026-08-07T00:00:03.000Z' });
      failAfterWrite = true;
      expect(registry.unregister('sess-1')).toBe(true);
      expect(registry.hasSession('sess-1')).toBe(false);
      store.dispose();
      const restarted = initializedStore(dir);
      expect(restarted.getSession('sess-1')).toBeUndefined();
      expect(restarted.peekPendingEvents()).toEqual([]);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('restart reconciles a committed cancellation after a failed cleanup retry', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-registry-cancel-recovery-'));
    try {
      const store = initializedStore(dir);
      const registry = new AgentAdapterRegistry('host-1', store, () => {}, () => new Date(), {
        schedule: () => Symbol('retry'), cancel: () => {},
      });
      register(registry);
      const command = makeCommand('sess-1');
      registry.enqueueCommand(command);
      const eventId = registry.pushEvent('sess-1', doneEvent({ correlationId: 'recovery-retry' }));
      await registry.dequeueCommand('sess-1', 0);
      store.queuePendingEvent = (() => { throw new Error('retry unavailable'); }) as typeof store.queuePendingEvent;
      registry.resolveCommand(command.commandId, { commandId: command.commandId, hostId: command.hostId,
        sessionId: command.sessionId, accepted: true, status: 'executed', message: 'ok', updatedAt: '2026-08-07T00:00:03.000Z' });
      const spool = (store as any).spool;
      const originalRemoveMany = spool.removeMany.bind(spool);
      spool.removeMany = () => { throw new Error('cleanup unavailable'); };
      expect(registry.unregister('sess-1')).toBe(true);
      expect(store.peekPendingEvents()).toEqual([]);
      spool.removeMany = originalRemoveMany;
      expect(() => (store as any).reconcileTerminalCancellations()).not.toThrow();
      store.dispose();
      const restarted = initializedStore(dir);
      expect(restarted.peekPendingEvents()).toEqual([]);
      expect(restarted.getSession('sess-1')).toBeUndefined();
      expect(JSON.stringify(JSON.parse(readFileSync(join(dir, 'state.json'), 'utf8')))).not.toContain(eventId);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

});
