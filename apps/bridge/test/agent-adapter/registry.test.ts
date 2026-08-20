import { describe, expect, mock, test } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { CommandEnvelope, CommandResult } from '@ariava/protocol';
import {
  AgentAdapterRegistry,
  AgentAdapterRequestValidationError,
  type AgentAdapterEventInput,
} from '../../src/agent-adapter/registry';
import { OWNER_LEASE_TTL_MS, SESSION_TTL_MS } from '../../src/agent-adapter/registry-types';
import { BridgeStateStore, runtimeSchemaFloorPathForState } from '../../src/state-store';
import { spoolPathForState } from '../../src/e2e/local-spool';

mock.module('../../src/e2e/node-crypto', () => ({
  ChaChaPolyAuthenticationError: class ChaChaPolyAuthenticationError extends Error {},
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
    agentText: 'Finished successfully',
    projectName: 'project',
    workingDirectory: '/project',
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
    agentText: 'Which environment should I target?',
    projectName: 'project',
    workingDirectory: '/project',
    harnessProvider: 'pi',
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

/** 16 zero bytes as unpadded base64url: a valid protocol-4 driver instance id. */
const DRIVER_INSTANCE_ID = 'AAAAAAAAAAAAAAAAAAAAAA';

function register(registry: AgentAdapterRegistry): void {
  registry.register({
    sessionId: 'sess-1', provider: 'pi', projectName: 'project', cwd: '/project', nameText: 'Task',
    status: 'working', latestActivityText: 'Running', driverInstanceId: DRIVER_INSTANCE_ID,
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
      expect(store.getDriverNameForSession('sess-1')).toBe('agent-adapter');
      failWrites = true;
      expect(() => registry.unregister('sess-1')).toThrow('state persistence failed');
      expect(registry.hasSession('sess-1')).toBe(true);
      expect(store.getDriverNameForSession('sess-1')).toBe('agent-adapter');
      failWrites = false;
      expect(registry.unregister('sess-1')).toBe(true);
      store.dispose();
      const restarted = new BridgeStateStore(statePath);
      expect(restarted.getDriverNameForSession('sess-1')).toBeUndefined();
      expect(restarted.listSessions()).toEqual([]);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('keeps normalized owner immutable across restart using persisted Session authority', () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-registry-owner-restart-'));
    try {
      const store = initializedStore(dir);
      const first = new AgentAdapterRegistry('host-1', store);
      first.register({
        sessionId: 'owned-session', provider: 'adapter', harnessProvider: 'pi', projectName: 'p', cwd: '/', nameText: 'p', driverInstanceId: DRIVER_INSTANCE_ID,
      });
      const beforeDrivers = store.getDriverNameForSession('owned-session');
      const beforeEvents = structuredClone(store.peekPendingEvents());
      const beforeHandles = structuredClone(store.peekPendingSessionHandles());
      store.dispose();

      const restartedStore = initializedStore(dir);
      const restarted = new AgentAdapterRegistry('host-1', restartedStore);
      expect(() => restarted.register({
        sessionId: 'owned-session', provider: 'adapter', harnessProvider: 'pi', projectName: 'p', cwd: '/', nameText: 'p', driverInstanceId: DRIVER_INSTANCE_ID,
      })).not.toThrow();
      const afterSameOwner = readFileSync(join(dir, 'state.json'), 'utf8');
      const sessionsAfterSameOwner = structuredClone(restartedStore.listSessions());
      expect(() => restarted.register({
        sessionId: 'owned-session', provider: 'adapter', harnessProvider: 'codex', projectName: 'other', cwd: '/other', nameText: 'other', driverInstanceId: DRIVER_INSTANCE_ID,
      })).toThrow(expect.objectContaining({ code: 'session_id_collision' }));
      expect(readFileSync(join(dir, 'state.json'), 'utf8')).toBe(afterSameOwner);
      expect(restartedStore.listSessions()).toEqual(sessionsAfterSameOwner);
      expect(restartedStore.getDriverNameForSession('owned-session')).toBe(beforeDrivers);
      expect(restartedStore.peekPendingEvents()).toEqual(beforeEvents);
      expect(restartedStore.peekPendingSessionHandles()).toEqual(beforeHandles);
      expect(restarted.hasPendingCommandWork('owned-session')).toBe(false);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('preserves normalized owner through schema 3 to 4 migration and rejects collision before mutation', () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-registry-owner-migration-'));
    const statePath = join(dir, 'state.json');
    const spoolPath = spoolPathForState(statePath);
    try {
      const schema4Store = initializedStore(dir);
      const original = new AgentAdapterRegistry('host-1', schema4Store);
      original.register({
        sessionId: 'migrated-owner', provider: 'adapter', harnessProvider: 'pi',
        projectName: 'project', cwd: '/project', nameText: 'Migrated owner', driverInstanceId: DRIVER_INSTANCE_ID,
      });
      schema4Store.dispose();

      const schema3State = JSON.parse(readFileSync(statePath, 'utf8'));
      const schema3Spool = JSON.parse(readFileSync(spoolPath, 'utf8'));
      schema3State.schemaVersion = 3;
      delete schema3State.commandExecutions;
      schema3State.commandResults = {};
      schema3State.seenCommands = {};
      // Historical schema 3 coupled sessionDrivers[id] to canonical provider.
      // The live schema 4 persist writes 'agent-adapter'; rewrite the forged
      // v3 source back to that coupling so isPriorStateRecordV3 can accept it.
      schema3State.sessionDrivers = Object.fromEntries(
        Object.entries(schema3State.sessions as Record<string, { provider: string }>).map(([sessionId, session]) => [
          sessionId, session.provider,
        ]),
      );
      schema3Spool.runtimeStateSchemaVersion = 3;
      rmSync(runtimeSchemaFloorPathForState(statePath), { force: true });
      writeFileSync(statePath, `${JSON.stringify(schema3State)}\n`, { mode: 0o600 });
      writeFileSync(spoolPath, `${JSON.stringify(schema3Spool)}\n`, { mode: 0o600 });

      const migratedStore = new BridgeStateStore(statePath, undefined, { deferRuntimePreflight: true });
      migratedStore.initializeEncryptedSpool('host-1', join(dir, 'identity.json'), 'linux', {
        loadOrCreate: () => new Uint8Array(32).fill(7),
      });
      expect(JSON.parse(readFileSync(statePath, 'utf8'))).toMatchObject({ schemaVersion: 4 });
      expect(migratedStore.listSessions()).toEqual([expect.objectContaining({
        sessionId: 'migrated-owner', provider: 'adapter', harnessProvider: 'pi',
      })]);
      migratedStore.dispose();

      const restartedStore = initializedStore(dir);
      const restarted = new AgentAdapterRegistry('host-1', restartedStore);
      const stateBeforeCollision = readFileSync(statePath);
      const spoolBeforeCollision = readFileSync(spoolPath);
      const sessionsBeforeCollision = structuredClone(restartedStore.listSessions());
      const driversBeforeCollision = restartedStore.getDriverNameForSession('migrated-owner');
      const eventsBeforeCollision = structuredClone(restartedStore.peekPendingEvents());
      const handlesBeforeCollision = structuredClone(restartedStore.peekPendingSessionHandles());

      expect(() => restarted.register({
        sessionId: 'migrated-owner', provider: 'adapter', harnessProvider: 'codex',
        projectName: 'other', cwd: '/other', nameText: 'Conflicting owner', driverInstanceId: DRIVER_INSTANCE_ID,
      })).toThrow(expect.objectContaining({ code: 'session_id_collision' }));
      expect(readFileSync(statePath)).toEqual(stateBeforeCollision);
      expect(readFileSync(spoolPath)).toEqual(spoolBeforeCollision);
      expect(restartedStore.listSessions()).toEqual(sessionsBeforeCollision);
      expect(restartedStore.getDriverNameForSession('migrated-owner')).toBe(driversBeforeCollision);
      expect(restartedStore.peekPendingEvents()).toEqual(eventsBeforeCollision);
      expect(restartedStore.peekPendingSessionHandles()).toEqual(handlesBeforeCollision);
      expect(restarted.hasPendingCommandWork('migrated-owner')).toBe(false);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('registration checks persisted owner even when live state reports the requested owner', () => {
    const { store, cleanup } = makeStore();
    try {
      const persisted = new AgentAdapterRegistry('host-1', store);
      persisted.register({ sessionId: 'masked-owner', provider: 'persisted', projectName: 'p', cwd: '/', nameText: 'p', driverInstanceId: DRIVER_INSTANCE_ID });
      const registry = new AgentAdapterRegistry('host-1', store);
      (registry as any).sessions.set('masked-owner', {
        sessionId: 'masked-owner', provider: 'requested', projectName: 'live', cwd: '/live', nameText: 'live',
        hostId: 'host-1', registeredAt: '2026-08-07T00:00:00.000Z', lastHeartbeatAt: '2026-08-07T00:00:00.000Z',
        status: 'idle', semanticUpdatedAt: '2026-08-07T00:00:00.000Z',
      });
      const beforeSessions = structuredClone(store.listSessions());
      expect(() => registry.register({
        sessionId: 'masked-owner', provider: 'requested', projectName: 'new', cwd: '/new', nameText: 'new', driverInstanceId: DRIVER_INSTANCE_ID,
      })).toThrow(expect.objectContaining({ code: 'session_id_collision' }));
      expect(store.listSessions()).toEqual(beforeSessions);
      expect(store.peekPendingEvents()).toEqual([]);
      expect(store.peekPendingSessionHandles()).toEqual([]);
      expect(registry.hasPendingCommandWork('masked-owner')).toBe(false);
    } finally { cleanup(); }
  });

  test('rejects an unregistered Event with a typed error before mutation', () => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store);
      const beforeSessions = structuredClone(store.listSessions());
      expect(() => registry.pushEvent('missing', doneEvent({ sessionId: 'missing' })))
        .toThrow(AgentAdapterRequestValidationError);
      expect(store.listSessions()).toEqual(beforeSessions);
      expect(store.peekPendingEvents()).toEqual([]);
      expect(store.peekPendingSessionHandles()).toEqual([]);
    } finally { cleanup(); }
  });

  test('deduplicates the complete producer DTO immediately, after delay, and after restart', () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-registry-dedupe-'));
    try {
      const store = initializedStore(dir);
      const registry = new AgentAdapterRegistry('host-1', store);
      register(registry);
      const producer = doneEvent();
      const first = registry.pushEvent('sess-1', producer);
      expect(registry.pushEvent('sess-1', producer)).toBe(first);
      const persisted = JSON.parse(readFileSync(join(dir, 'state.json'), 'utf8'));
      expect(JSON.stringify(persisted.producerEventReservations)).not.toContain('Finished successfully');
      expect(Object.values(persisted.producerEventReservations)[0]).toEqual(expect.objectContaining({
        version: 1, eventId: first, sessionId: 'sess-1', fingerprint: expect.any(String),
      }));
      expect(registry.pushEvent('sess-1', doneEvent({ agentText: 'Different content' }))).not.toBe(first);
      expect(registry.pushEvent('sess-1', doneEvent({ createdAt: '2026-08-07T00:00:03.000Z' }))).not.toBe(first);
      const delayed = needHumanEvent({ createdAt: '2026-08-07T00:00:04.000Z' });
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
        needHuman: { reason: 'error', error: { kind: 'provider_failure', message: 'Provider failed safely.', providerCode: 'E_PROVIDER', retryExhausted: true } },
      });
      const reordered = needHumanEvent({
        needHuman: { error: { retryExhausted: true, providerCode: 'E_PROVIDER', message: 'Provider failed safely.', kind: 'provider_failure' }, reason: 'error' },
      });
      const immediateId = registry.pushEvent('sess-1', first);
      expect(registry.pushEvent('sess-1', reordered)).toBe(immediateId);
      expect(registry.pushEvent('sess-1', {
        ...structuredClone(reordered),
        needHuman: { reason: 'error', error: { ...structuredClone((reordered.needHuman as any).error), message: 'Different error' } },
      })).not.toBe(immediateId);

      const delayed = { ...structuredClone(first), createdAt: '2026-08-07T00:00:04.000Z' };
      const delayedReordered = { ...structuredClone(reordered), createdAt: '2026-08-07T00:00:04.000Z' };
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
      const producer = doneEvent();
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
        sessionId: command.sessionId, accepted: true, status: 'executed', updatedAt: '2026-08-07T00:00:03.000Z' });
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
        status: 'executed' as const, updatedAt: '2026-08-07T00:00:03.000Z',
      };
      expect(() => registry.resolveCommand(command.commandId, lateResult)).toThrow(/queued adapter command/u);
      expect((registry as any).results.size).toBe(0);
      expect((registry as any).resultWaiters.size).toBe(0);
      expect((registry as any).resultWaiterTimers.size).toBe(0);
      expect((registry as any).commandSessions.size).toBe(0);
      if (action === 'dispose') {
        expect((registry as any).commandQueues.size).toBe(0);
        expect((registry as any).inFlightCommands.size).toBe(0);
      }
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

  test('rejects need_human heartbeat and register until a terminal Event supplies lastEventId', () => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store);
      expect(() => registry.register({
        sessionId: 'sess-1', provider: 'pi', projectName: 'project', cwd: '/project', nameText: 'Task',
        status: 'need_human', latestActivityText: 'Which environment?', driverInstanceId: DRIVER_INSTANCE_ID,
      })).toThrow(AgentAdapterRequestValidationError);
      expect(registry.listSessions()).toEqual([]);
      register(registry);
      const before = registry.listSessions()[0];
      expect(() => registry.heartbeat('sess-1', 'need_human', 'Which environment?'))
        .toThrow(AgentAdapterRequestValidationError);
      expect(registry.listSessions()[0]).toEqual(before);
      const eventId = registry.pushEvent('sess-1', needHumanEvent());
      expect(registry.heartbeat('sess-1', 'need_human', 'Which environment?')).toMatchObject({
        status: 'need_human', lastEventId: eventId,
      });
    } finally { cleanup(); }
  });

  test('defers need_human heartbeat status while its terminal Event is delayed by command work', () => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store);
      register(registry);
      registry.enqueueCommand(makeCommand('sess-1'));
      const eventId = registry.pushEvent('sess-1', needHumanEvent());

      expect(registry.heartbeat('sess-1', 'need_human', 'Which environment?')).toMatchObject({
        status: 'working',
        latestActivityText: 'Which environment?',
        lastEventId: undefined,
      });
      expect(store.peekPendingEvents()).toEqual([]);
      expect(eventId).toMatch(/^evt_/u);
    } finally { cleanup(); }
  });

  test('restores a delayed terminal Event when need_human re-registers after restart', () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-registry-delayed-terminal-restart-'));
    try {
      const store = initializedStore(dir);
      const original = new AgentAdapterRegistry('host-1', store);
      register(original);
      original.enqueueCommand(makeCommand('sess-1'));
      const eventId = original.pushEvent('sess-1', needHumanEvent());
      expect(store.getSession('sess-1')).toMatchObject({ status: 'working', lastEventId: undefined });
      expect(store.peekPendingEvents()).toEqual([]);
      store.dispose();

      const restartedStore = initializedStore(dir);
      const restarted = new AgentAdapterRegistry('host-1', restartedStore);
      expect(restarted.register({
        sessionId: 'sess-1', provider: 'pi', projectName: 'project', cwd: '/project', nameText: 'Task',
        status: 'need_human', latestActivityText: 'Which environment?', driverInstanceId: DRIVER_INSTANCE_ID,
      })).toMatchObject({ status: 'need_human', lastEventId: eventId });
      expect(restartedStore.peekPendingEvents()).toEqual([
        expect.objectContaining({ eventId, sessionId: 'sess-1', status: 'need_human' }),
      ]);
      expect(restartedStore.getSession('sess-1')).toMatchObject({ status: 'need_human', lastEventId: eventId });
      restartedStore.dispose();
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('does not restore a delayed terminal Event across producer context changes', () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-registry-delayed-terminal-context-'));
    try {
      const store = initializedStore(dir);
      const original = new AgentAdapterRegistry('host-1', store);
      register(original);
      original.enqueueCommand(makeCommand('sess-1'));
      original.pushEvent('sess-1', needHumanEvent());
      store.dispose();

      const restartedStore = initializedStore(dir);
      const restarted = new AgentAdapterRegistry('host-1', restartedStore);
      expect(() => restarted.register({
        sessionId: 'sess-1', provider: 'pi', projectName: 'other', cwd: '/other', nameText: 'Task',
        status: 'need_human', latestActivityText: 'Which environment?', driverInstanceId: DRIVER_INSTANCE_ID,
      })).toThrow(AgentAdapterRequestValidationError);
      expect(restartedStore.peekPendingEvents()).toEqual([]);
      expect(restartedStore.getSession('sess-1')).toMatchObject({ status: 'working' });
      expect(restartedStore.getSession('sess-1')?.lastEventId).toBeUndefined();
      restartedStore.dispose();
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('restores a committed need_human Event after owner TTL removed its canonical Session', () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-registry-terminal-owner-loss-'));
    try {
      const store = initializedStore(dir);
      const original = new AgentAdapterRegistry('host-1', store);
      register(original);
      const eventId = original.pushEvent('sess-1', needHumanEvent());
      expect(store.getSession('sess-1')).toMatchObject({ status: 'need_human', lastEventId: eventId });
      expect(original.unregister('sess-1', 'ttl')).toBe(true);
      expect(store.getSession('sess-1')).toBeUndefined();
      expect(store.getProducerEventCheckpoint('sess-1')).toBeUndefined();
      store.dispose();

      const restartedStore = initializedStore(dir);
      const restarted = new AgentAdapterRegistry('host-1', restartedStore);
      expect(restarted.register({
        sessionId: 'sess-1', provider: 'pi', projectName: 'project', cwd: '/project', nameText: 'Task',
        status: 'need_human', latestActivityText: 'Which environment?', driverInstanceId: DRIVER_INSTANCE_ID,
      })).toMatchObject({ status: 'need_human', lastEventId: eventId });
      expect(restartedStore.getSession('sess-1')).toMatchObject({ status: 'need_human', lastEventId: eventId });
      expect(restartedStore.peekPendingEvents()).toEqual([
        expect.objectContaining({ eventId, type: 'need_human', status: 'need_human' }),
      ]);
      restartedStore.dispose();
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('restores an uploaded need_human Event without queueing it again after owner TTL', () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-registry-uploaded-terminal-owner-loss-'));
    try {
      const store = initializedStore(dir);
      const original = new AgentAdapterRegistry('host-1', store);
      register(original);
      const eventId = original.pushEvent('sess-1', needHumanEvent());
      store.removePendingEvent(eventId);
      expect(store.peekPendingEvents()).toEqual([]);
      expect(original.unregister('sess-1', 'ttl')).toBe(true);
      expect(store.getSession('sess-1')).toBeUndefined();
      store.dispose();

      const restartedStore = initializedStore(dir);
      const restarted = new AgentAdapterRegistry('host-1', restartedStore);
      expect(restarted.register({
        sessionId: 'sess-1', provider: 'pi', projectName: 'project', cwd: '/project', nameText: 'Task',
        status: 'need_human', latestActivityText: 'Which environment?', driverInstanceId: DRIVER_INSTANCE_ID,
      })).toMatchObject({ status: 'need_human', lastEventId: eventId });
      expect(restartedStore.getSession('sess-1')).toMatchObject({ status: 'need_human', lastEventId: eventId });
      expect(restartedStore.peekPendingEvents()).toEqual([]);
      restartedStore.dispose();
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('restores a committed lastEventId for same-context need_human re-registration after restart', () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-registry-terminal-restart-'));
    try {
      const store = initializedStore(dir);
      const original = new AgentAdapterRegistry('host-1', store);
      register(original);
      const eventId = original.pushEvent('sess-1', needHumanEvent());
      store.dispose();

      const restartedStore = initializedStore(dir);
      const restarted = new AgentAdapterRegistry('host-1', restartedStore);
      expect(restarted.register({
        sessionId: 'sess-1', provider: 'pi', projectName: 'project', cwd: '/project', nameText: 'Task',
        status: 'need_human', latestActivityText: 'Which environment?', driverInstanceId: DRIVER_INSTANCE_ID,
      })).toMatchObject({ status: 'need_human', lastEventId: eventId });
      expect(restartedStore.getSession('sess-1')).toMatchObject({ status: 'need_human', lastEventId: eventId });
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('does not restore a committed lastEventId across producer context changes', () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-registry-terminal-context-'));
    try {
      const store = initializedStore(dir);
      const original = new AgentAdapterRegistry('host-1', store);
      register(original);
      original.pushEvent('sess-1', needHumanEvent());
      store.dispose();

      const restarted = new AgentAdapterRegistry('host-1', initializedStore(dir));
      expect(() => restarted.register({
        sessionId: 'sess-1', provider: 'pi', projectName: 'other', cwd: '/other', nameText: 'Task',
        status: 'need_human', latestActivityText: 'Which environment?', driverInstanceId: DRIVER_INSTANCE_ID,
      })).toThrow(AgentAdapterRequestValidationError);
      expect(restarted.listSessions()).toEqual([]);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('live re-registration clears a committed cursor across status or producer-context changes and restart', () => {
    for (const change of [
      { status: 'working' as const, projectName: 'project', cwd: '/project' },
      { status: 'need_human' as const, projectName: 'other', cwd: '/other' },
    ]) {
      const dir = mkdtempSync(join(tmpdir(), 'bridge-registry-live-reregister-'));
      try {
        const store = initializedStore(dir);
        const registry = new AgentAdapterRegistry('host-1', store);
        register(registry);
        registry.pushEvent('sess-1', needHumanEvent());
        const input = {
          sessionId: 'sess-1', provider: 'pi', projectName: change.projectName, cwd: change.cwd, nameText: 'Task',
          status: change.status, latestActivityText: 'new state', driverInstanceId: DRIVER_INSTANCE_ID,
        };
        if (change.status === 'need_human') {
          expect(() => registry.register(input)).toThrow(AgentAdapterRequestValidationError);
        } else {
          expect(registry.register(input)).toMatchObject({ status: 'working', lastEventId: undefined });
          expect(store.getSession('sess-1')).toMatchObject({ status: 'working', lastEventId: undefined });
          store.dispose();
          const restarted = new AgentAdapterRegistry('host-1', initializedStore(dir));
          expect(restarted.register(input)).toMatchObject({ status: 'working', lastEventId: undefined });
        }
      } finally { rmSync(dir, { recursive: true, force: true }); }
    }
  });

  test('context-changing re-registration atomically cancels a delayed terminal tuple and persists its replacement', () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-registry-reregister-cancel-'));
    const input = {
      sessionId: 'sess-1', provider: 'pi', projectName: 'other', cwd: '/other', nameText: 'Task',
      status: 'working' as const, latestActivityText: 'new context', driverInstanceId: DRIVER_INSTANCE_ID,
    };
    try {
      const store = initializedStore(dir);
      const registry = new AgentAdapterRegistry('host-1', store);
      register(registry);
      registry.enqueueCommand(makeCommand('sess-1'));
      registry.pushEvent('sess-1', needHumanEvent());
      expect(registry.register(input)).toMatchObject({
        projectName: 'other', cwd: '/other', status: 'working', lastEventId: undefined,
      });
      expect(store.getTerminalEventCancellation('sess-1')).toBeUndefined();
      expect(store.getSession('sess-1')).toMatchObject({
        projectName: 'other', workingDirectory: '/other', status: 'working', lastEventId: undefined,
      });
      store.dispose();

      const restartedStore = initializedStore(dir);
      const restarted = new AgentAdapterRegistry('host-1', restartedStore);
      expect(restarted.register(input)).toMatchObject({
        projectName: 'other', cwd: '/other', status: 'working', lastEventId: undefined,
      });
      expect(restartedStore.peekPendingEvents()).toEqual([]);
    } finally { rmSync(dir, { recursive: true, force: true }); }
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

  test('emits a handle mutation only after the durable handle is persisted', () => {
    const { store, cleanup } = makeStore();
    try {
      const mutationReasons: string[] = [];
      const registry = new AgentAdapterRegistry('host-1', store, (reason) => mutationReasons.push(reason));
      register(registry);
      const eventId = registry.pushEvent('sess-1', doneEvent());
      mutationReasons.length = 0;

      registry.handleSession('sess-1', { handledThroughEventId: eventId, action: 'pi_input' });

      expect(store.peekPendingSessionHandles()).toHaveLength(1);
      expect(mutationReasons).toEqual(['handle']);
    } finally { cleanup(); }
  });

  test('does not mutate or commit a pending handle when state persistence fails', () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-registry-handle-failure-'));
    const statePath = join(dir, 'state.json');
    let shouldFailWrites = false;
    try {
      const store = new BridgeStateStore(statePath, (path, value) => {
        if (shouldFailWrites) throw new Error('handle persistence failed');
        writeFileSync(path, JSON.stringify(value), { mode: 0o600 });
      });
      store.initializeEncryptedSpool('host-1', join(dir, 'identity.json'), 'linux', {
        loadOrCreate: () => new Uint8Array(32).fill(7),
      });
      const mutationReasons: string[] = [];
      const registry = new AgentAdapterRegistry('host-1', store, (reason) => mutationReasons.push(reason));
      register(registry);
      const eventId = registry.pushEvent('sess-1', doneEvent());
      mutationReasons.length = 0;
      const persistedStateBeforeFailure = readFileSync(statePath, 'utf8');
      shouldFailWrites = true;

      expect(() => registry.handleSession('sess-1', { handledThroughEventId: eventId, action: 'pi_input' }))
        .toThrow('handle persistence failed');
      expect(mutationReasons).toEqual([]);
      expect(store.peekPendingSessionHandles()).toEqual([]);
      expect(readFileSync(statePath, 'utf8')).toBe(persistedStateBeforeFailure);
    } finally { rmSync(dir, { recursive: true, force: true }); }
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
    ['legacy typeLabel', { ...doneEvent(), typeLabel: 'Task complete' }],
    ...(['projectName', 'workingDirectory', 'harnessProvider'] as const).map((key) => [
      `omitted ${key}`, Object.fromEntries(Object.entries(doneEvent()).filter(([field]) => field !== key)),
    ]),
    ['retired actionablePrompt', { ...doneEvent(), actionablePrompt: { promptId: 'old', type: 'question', label: 'Reply' } }],
    ['retired contextText', { ...doneEvent(), contextText: 'old' }],
    ['retired correlationId', { ...doneEvent(), correlationId: 'old' }],
    ['retired hbaseSessionKey', { ...doneEvent(), hbaseSessionKey: 'old' }],
    ['oversized protected payload', { ...doneEvent(), agentText: 'x'.repeat(65_600) }],
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
    ['workingDirectory', { workingDirectory: '/other' }],
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
        accepted: true, status: 'executed', updatedAt: '2026-08-07T00:00:03.000Z',
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
        accepted: true, status: 'executed', updatedAt: '2026-08-07T00:00:03.000Z',
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
        eventId, agentText: 'Delayed question', needHuman: { reason: 'question' },
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
        status: 'executed', updatedAt: '2026-08-07T00:00:03.000Z',
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
      const producer = doneEvent({ agentText: `cancel-` });
      const eventId = registry.pushEvent('sess-1', producer);
      await registry.dequeueCommand('sess-1', 0);
      const originalQueuePendingEvent = store.queuePendingEvent.bind(store);
      store.queuePendingEvent = (() => { throw new Error('retry unavailable'); }) as typeof store.queuePendingEvent;
      registry.resolveCommand(command.commandId, {
        commandId: command.commandId, hostId: command.hostId, sessionId: command.sessionId, accepted: true,
        status: 'executed', updatedAt: '2026-08-07T00:00:03.000Z',
      });
      const spool = (store as any).spool;
      const originalEnqueue = spool.enqueue.bind(spool);
      const originalWriteState = (store as any).writeState;
      if (boundary === 'intent-write') spool.enqueue = () => { throw new Error('intent write failed'); };
      else (store as any).writeState = () => { throw new Error('state commit failed'); };
      expect(() => registry.unregister('sess-1')).toThrow(boundary === 'intent-write' ? 'intent write failed' : 'state commit failed');
      expect(registry.hasSession('sess-1')).toBe(true);
      expect(store.getDriverNameForSession('sess-1')).toBe('agent-adapter');
      expect(store.getTerminalEventCancellation('sess-1')?.eventId).toBe(eventId);
      spool.enqueue = originalEnqueue;
      (store as any).writeState = originalWriteState;
      store.queuePendingEvent = originalQueuePendingEvent;
      expect(registry.pushEvent('sess-1', producer)).toBe(eventId);
    } finally { cleanup(); }
  });

  test('restart completes cancellation whose spool intent committed before state metadata', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-registry-cancel-intent-only-'));
    try {
      const statePath = join(dir, 'state.json');
      const store = initializedStore(dir);
      const registry = new AgentAdapterRegistry('host-1', store, () => {}, () => new Date(), {
        schedule: () => Symbol('retry'), cancel: () => {},
      });
      register(registry);
      const command = makeCommand('sess-1');
      registry.enqueueCommand(command);
      const eventId = registry.pushEvent('sess-1', doneEvent());
      await registry.dequeueCommand('sess-1', 0);
      store.queuePendingEvent = (() => { throw new Error('retry unavailable'); }) as typeof store.queuePendingEvent;
      registry.resolveCommand(command.commandId, { commandId: command.commandId, hostId: command.hostId,
        sessionId: command.sessionId, accepted: true, status: 'executed', updatedAt: '2026-08-07T00:00:03.000Z' });
      (store as any).writeState = () => { throw new Error('state commit failed'); };
      expect(() => registry.unregister('sess-1')).toThrow('state commit failed');
      store.dispose();

      const restarted = initializedStore(dir);
      expect(restarted.getSession('sess-1')).toBeUndefined();
      expect(restarted.peekPendingEvents()).toEqual([]);
      expect(JSON.stringify(JSON.parse(readFileSync(statePath, 'utf8')))).not.toContain(eventId);
      restarted.dispose();
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
  test.each(['missing-source', 'wrong-session'] as const)(
    'restart rejects a terminal cancellation intent with %s reservation evidence without rewriting state',
    async (mutation) => {
      const dir = mkdtempSync(join(tmpdir(), `bridge-registry-cancel-${mutation}-`));
      try {
        const statePath = join(dir, 'state.json');
        const store = initializedStore(dir);
        const registry = new AgentAdapterRegistry('host-1', store, () => {}, () => new Date(), {
          schedule: () => Symbol('retry'), cancel: () => {},
        });
        register(registry);
        const command = makeCommand('sess-1');
        registry.enqueueCommand(command);
        const eventId = registry.pushEvent('sess-1', doneEvent({ agentText: mutation }));
        await registry.dequeueCommand('sess-1', 0);
        store.queuePendingEvent = (() => { throw new Error('retry unavailable'); }) as typeof store.queuePendingEvent;
        registry.resolveCommand(command.commandId, { commandId: command.commandId, hostId: command.hostId,
          sessionId: command.sessionId, accepted: true, status: 'executed', updatedAt: '2026-08-07T00:00:03.000Z' });
        (store as any).writeState = () => { throw new Error('state commit failed'); };
        expect(() => registry.unregister('sess-1')).toThrow('state commit failed');
        store.dispose();

        const originalState = readFileSync(statePath, 'utf8');
        const spoolPath = spoolPathForState(statePath);
        const spool = JSON.parse(readFileSync(spoolPath, 'utf8')) as {
          items: Array<{ spoolItemId: string; sessionId: string; eventId?: string; payloadKind: string }>;
        };
        if (mutation === 'missing-source') {
          spool.items = spool.items.filter((item) => item.spoolItemId !== eventId);
        } else {
          const source = spool.items.find((item) => item.spoolItemId === eventId);
          if (!source) throw new Error('expected reservation source');
          source.sessionId = 'sess-other';
        }
        writeFileSync(spoolPath, `${JSON.stringify(spool, null, 2)}\n`, { mode: 0o600 });

        expect(() => initializedStore(dir)).toThrow('Bridge runtime preflight failed closed');
        expect(readFileSync(statePath, 'utf8')).toBe(originalState);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    },
  );


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
      const eventId = registry.pushEvent('sess-1', doneEvent({ agentText: boundary }));
      await registry.dequeueCommand('sess-1', 0);
      store.queuePendingEvent = (() => { throw new Error('retry unavailable'); }) as typeof store.queuePendingEvent;
      registry.resolveCommand(command.commandId, { commandId: command.commandId, hostId: command.hostId,
        sessionId: command.sessionId, accepted: true, status: 'executed', updatedAt: '2026-08-07T00:00:03.000Z' });
      const spool = (store as any).spool;
      let cleanupFailureInjected = false;
      if (boundary === 'spool-remove') spool.removeMany = () => { throw new Error('spool remove failed'); };
      else {
        const originalWriteState = (store as any).writeState;
        (store as any).writeState = (path: string, value: { terminalCancellations?: unknown }) => {
          if (!cleanupFailureInjected && value.terminalCancellations === undefined) {
            cleanupFailureInjected = true;
            throw new Error('journal cleanup failed');
          }
          originalWriteState(path, value);
        };
      }
      expect(registry.unregister('sess-1')).toBe(true);
      expect(registry.hasSession('sess-1')).toBe(false);
      expect(store.peekPendingEvents()).toEqual([]);
      if (boundary === 'journal-cleanup') expect(cleanupFailureInjected).toBe(true);
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
      registry.pushEvent('sess-1', doneEvent());
      await registry.dequeueCommand('sess-1', 0);
      store.queuePendingEvent = (() => { throw new Error('retry unavailable'); }) as typeof store.queuePendingEvent;
      registry.resolveCommand(command.commandId, { commandId: command.commandId, hostId: command.hostId, sessionId: command.sessionId,
        accepted: true, status: 'executed', updatedAt: '2026-08-07T00:00:03.000Z' });
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
      const eventId = registry.pushEvent('sess-1', doneEvent());
      await registry.dequeueCommand('sess-1', 0);
      store.queuePendingEvent = (() => { throw new Error('retry unavailable'); }) as typeof store.queuePendingEvent;
      registry.resolveCommand(command.commandId, { commandId: command.commandId, hostId: command.hostId,
        sessionId: command.sessionId, accepted: true, status: 'executed', updatedAt: '2026-08-07T00:00:03.000Z' });
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

  test('abandon clears in-flight work and rejects late results without storing terminal evidence', async () => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store);
      register(registry);
      const command = makeCommand('sess-1');
      registry.enqueueCommand(command);
      await registry.dequeueCommand('sess-1', 0);
      expect(registry.hasPendingCommandWork('sess-1')).toBe(true);
      registry.abandonCommand(command.commandId);
      expect(registry.hasPendingCommandWork('sess-1')).toBe(false);
      const late = { commandId: command.commandId, hostId: command.hostId, sessionId: command.sessionId,
        accepted: true as const, status: 'executed' as const, updatedAt: '2026-08-07T00:00:03.000Z' };
      expect(() => registry.resolveCommand(command.commandId, late)).toThrow(/queued adapter command/u);
      expect((registry as any).results.size).toBe(0);
    } finally { cleanup(); }
  });

  test('heartbeat context-change cancel write failure preserves the live Session and mutation ordering', () => {
    const { store, cleanup } = makeStore();
    try {
      const mutations: string[] = [];
      const registry = new AgentAdapterRegistry('host-1', store, (reason) => mutations.push(reason));
      register(registry);
      const command = makeCommand('sess-1');
      registry.enqueueCommand(command);
      registry.pushEvent('sess-1', doneEvent({ createdAt: '2026-08-07T00:00:10.000Z' }));
      mutations.length = 0;
      const original = store.cancelTerminalEvent.bind(store);
      store.cancelTerminalEvent = (() => { throw new Error('cancel write failed'); }) as typeof store.cancelTerminalEvent;
      expect(() => registry.heartbeat('sess-1', 'working', undefined, { projectName: 'other' }))
        .toThrow('cancel write failed');
      store.cancelTerminalEvent = original;
      expect(registry.listSessions()[0]).toMatchObject({ projectName: 'project' });
      expect(mutations).toEqual([]);
      expect((registry as any).delayedTerminalEvents.size).toBe(1);
    } finally { cleanup(); }
  });

  test('restart with a persisted reservation but no spool tuple returns the existing Event ID', () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-registry-reservation-no-tuple-'));
    try {
      const statePath = join(dir, 'state.json');
      const store = initializedStore(dir);
      const registry = new AgentAdapterRegistry('host-1', store);
      register(registry);
      registry.enqueueCommand(makeCommand('sess-1'));
      const producer = doneEvent({ createdAt: '2026-08-07T00:00:11.000Z' });
      const eventId = registry.pushEvent('sess-1', producer);
      const spoolPath = spoolPathForState(statePath);
      const spool = JSON.parse(readFileSync(spoolPath, 'utf8')) as { items: Array<{ eventId?: string }> };
      spool.items = spool.items.filter((item) => item.eventId !== eventId);
      writeFileSync(spoolPath, `${JSON.stringify(spool, null, 2)}\n`, { mode: 0o600 });
      store.dispose();
      const restarted = initializedStore(dir);
      const reg2 = new AgentAdapterRegistry('host-1', restarted);
      register(reg2);
      expect(reg2.pushEvent('sess-1', producer)).toBe(eventId);
      expect(restarted.peekPendingEvents()).toEqual([]);
      restarted.dispose();
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('abandoning an in-flight command releases the command-gated terminal Event', async () => {
    const { store, cleanup } = makeStore();
    try {
      const registry = new AgentAdapterRegistry('host-1', store);
      register(registry);
      const command = makeCommand('sess-1');
      registry.enqueueCommand(command);
      const eventId = registry.pushEvent('sess-1', doneEvent({ createdAt: '2026-08-07T00:00:12.000Z' }));
      await registry.dequeueCommand('sess-1', 0);
      expect(store.peekPendingEvents()).toEqual([]);
      registry.abandonCommand(command.commandId);
      expect(registry.hasPendingCommandWork('sess-1')).toBe(false);
      expect(store.peekPendingEvents()).toEqual([expect.objectContaining({ eventId })]);
    } finally { cleanup(); }
  });

  describe('Session content limit enforcement (§3.4)', () => {
    test('register with an oversized canonical Session is rejected before any mutation', () => {
      const { store, cleanup } = makeStore();
      try {
        const registry = new AgentAdapterRegistry('host-1', store);
        const before = store.listSessions();
        expect(() => registry.register({
          sessionId: 'big', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'n',
          openingText: 'a'.repeat(65_500), driverInstanceId: DRIVER_INSTANCE_ID,
        })).toThrow(AgentAdapterRequestValidationError);
        expect(store.listSessions()).toEqual(before);
        expect(registry.listSessions().some((s) => s.sessionId === 'big')).toBe(false);
      } finally { cleanup(); }
    });

    test('heartbeat with an oversized canonical Session is rejected before mutation and the Session is unchanged', () => {
      const { store, cleanup } = makeStore();
      try {
        const registry = new AgentAdapterRegistry('host-1', store);
        register(registry);
        const before = registry.listSessions()[0];
        expect(() => registry.heartbeat('sess-1', 'working', 'a'.repeat(65_500))).toThrow(AgentAdapterRequestValidationError);
        expect(registry.listSessions()[0]).toEqual(before);
        expect(store.peekPendingEvents()).toEqual([]);
      } finally { cleanup(); }
    });

    test('register with a legal large canonical Session is accepted', () => {
      const { store, cleanup } = makeStore();
      try {
        const registry = new AgentAdapterRegistry('host-1', store);
        const accepted = registry.register({
          sessionId: 'ok', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'n',
          openingText: 'a'.repeat(64_000), driverInstanceId: DRIVER_INSTANCE_ID,
        });
        expect(accepted.sessionId).toBe('ok');
        expect(store.listSessions().some((s) => s.sessionId === 'ok')).toBe(true);
      } finally { cleanup(); }
    });
  });

  describe('owner lease, TTL, and producer source tuple semantics (Spec 08-16 §6)', () => {
    const OTHER_INSTANCE = 'BBBBBBBBBBBBBBBBBBBBBB';
    const OCCUPANCY_TTL_MS = 6_000;

    function newRegistry(store: BridgeStateStore, monotonicStart = 1_000_000): { registry: AgentAdapterRegistry; advance: (ms: number) => void } {
      let clock = monotonicStart;
      const advance = (ms: number): void => { clock += ms; };
      const registry = new AgentAdapterRegistry('host-1', store, () => {}, () => new Date(),
        undefined as never, undefined as never, () => clock);
      return { registry, advance };
    }

    test('re-registering from the same live driver instance keeps the same owner lease', () => {
      const { store, cleanup } = makeStore();
      try {
        const { registry } = newRegistry(store);
        const first = registry.register({
          sessionId: 'same-instance', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p', driverInstanceId: DRIVER_INSTANCE_ID,
        });
        const second = registry.register({
          sessionId: 'same-instance', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p', driverInstanceId: DRIVER_INSTANCE_ID,
        });
        expect(second.ownerLease).toBe(first.ownerLease);
      } finally { cleanup(); }
    });

    test('a different live driver instance is rejected with OWNER_CONFLICT while the lease is current', () => {
      const { store, cleanup } = makeStore();
      try {
        const { registry } = newRegistry(store);
        registry.register({
          sessionId: 'owner-conflict', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p', driverInstanceId: DRIVER_INSTANCE_ID,
        });
        expect(() => registry.register({
          sessionId: 'owner-conflict', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p', driverInstanceId: OTHER_INSTANCE,
        })).toThrow(expect.objectContaining({ code: 'owner_conflict' }));
        expect(registry.listSessions().some((s) => s.sessionId === 'owner-conflict')).toBe(true);
      } finally { cleanup(); }
    });

    test('owner occupancy TTL is 6000ms and is not aliased to the 45s recovery deadline', () => {
      expect(OWNER_LEASE_TTL_MS).toBe(6_000);
      expect(SESSION_TTL_MS).toBe(45_000);
      expect(OWNER_LEASE_TTL_MS).not.toBe(SESSION_TTL_MS);
    });

    test('occupancy equal to 6000ms remains valid and a contender still gets OWNER_CONFLICT', () => {
      const { store, cleanup } = makeStore();
      try {
        const { registry, advance } = newRegistry(store);
        const owned = registry.register({
          sessionId: 'exact-boundary', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p',
          driverInstanceId: DRIVER_INSTANCE_ID,
        });
        advance(OCCUPANCY_TTL_MS);
        expect(() => registry.register({
          sessionId: 'exact-boundary', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p',
          driverInstanceId: OTHER_INSTANCE,
        })).toThrow(expect.objectContaining({ code: 'owner_conflict' }));
        expect(registry.hasSession('exact-boundary')).toBe(true);
        expect(registry.assertCurrentOwner('exact-boundary', DRIVER_INSTANCE_ID, owned.ownerLease)).toBeUndefined();
      } finally { cleanup(); }
    });

    test('after 6000ms plus 1ms without heartbeat a contender acquires a new owner lease', () => {
      const { store, cleanup } = makeStore();
      try {
        const { registry, advance } = newRegistry(store);
        const owned = registry.register({
          sessionId: 'ttl-plus-one', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p',
          driverInstanceId: DRIVER_INSTANCE_ID,
        });
        advance(OCCUPANCY_TTL_MS + 1);
        const contender = registry.register({
          sessionId: 'ttl-plus-one', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p',
          driverInstanceId: OTHER_INSTANCE,
        });
        expect(contender.ownerLease).not.toBe(owned.ownerLease);
        expect(contender.driverInstanceId).toBe(OTHER_INSTANCE);
      } finally { cleanup(); }
    });

    test('a successful heartbeat refreshes occupancy so 5000ms later a contender still conflicts', () => {
      const { store, cleanup } = makeStore();
      try {
        const { registry, advance } = newRegistry(store);
        const owned = registry.register({
          sessionId: 'hb-refresh', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p',
          driverInstanceId: DRIVER_INSTANCE_ID, status: 'idle',
        });
        // Advance first so lastOwnerLeaseMonotonic must change on heartbeat.
        // Without a refresh, t=10_000 after register would already be past 6s occupancy.
        advance(5_000);
        const afterHeartbeat = registry.heartbeat('hb-refresh', 'working', 'still alive');
        expect(afterHeartbeat?.ownerLease).toBe(owned.ownerLease);
        advance(5_000);
        expect(() => registry.register({
          sessionId: 'hb-refresh', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p',
          driverInstanceId: OTHER_INSTANCE,
        })).toThrow(expect.objectContaining({ code: 'owner_conflict' }));
        advance(1_001);
        const contender = registry.register({
          sessionId: 'hb-refresh', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p',
          driverInstanceId: OTHER_INSTANCE,
        });
        expect(contender.ownerLease).not.toBe(owned.ownerLease);
      } finally { cleanup(); }
    });

    test('unregister releases occupancy immediately without waiting 6s', () => {
      const { store, cleanup } = makeStore();
      try {
        const { registry } = newRegistry(store);
        const owned = registry.register({
          sessionId: 'unreg-now', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p',
          driverInstanceId: DRIVER_INSTANCE_ID,
        });
        expect(registry.unregister('unreg-now')).toBe(true);
        const successor = registry.register({
          sessionId: 'unreg-now', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p',
          driverInstanceId: OTHER_INSTANCE,
        });
        expect(successor.ownerLease).not.toBe(owned.ownerLease);
        expect(successor.driverInstanceId).toBe(OTHER_INSTANCE);
      } finally { cleanup(); }
    });

    test('command recovery deadline stays 45s and does not become occupancy 6s', () => {
      const { store, cleanup } = makeStore();
      try {
        let wall = 1_000_000;
        const persisted = [{
          sessionId: 'ghost',
          hostId: 'host-1',
          provider: 'pi',
          projectName: 'p',
          nameText: 'p',
          status: 'idle' as const,
          updatedAt: '2026-08-19T00:00:00.000Z',
        }];
        const registry = new AgentAdapterRegistry(
          'host-1',
          store,
          () => {},
          () => new Date(wall),
          undefined as never,
          undefined as never,
          () => 1_000_000,
        );
        expect(registry.isAuthoritativeSetReady(persisted)).toBe(false);
        wall += 6_001;
        expect(registry.isAuthoritativeSetReady(persisted)).toBe(false);
        wall = 1_000_000 + SESSION_TTL_MS + 1;
        expect(registry.isAuthoritativeSetReady(persisted)).toBe(true);
      } finally { cleanup(); }
    });

    test('after the TTL elapses without activity a contender may acquire: lazy revocation', () => {
      const { store, cleanup } = makeStore();
      try {
        const { registry, advance } = newRegistry(store);
        registry.register({
          sessionId: 'ttl-takeover', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p', driverInstanceId: DRIVER_INSTANCE_ID,
        });
        advance(OCCUPANCY_TTL_MS + 1);
        const contender = registry.register({
          sessionId: 'ttl-takeover', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p', driverInstanceId: OTHER_INSTANCE,
        });
        expect(contender.ownerLease).not.toBe(DRIVER_INSTANCE_ID);
        // Same-instance re-register across TTL also rotates the lease.
        advance(OCCUPANCY_TTL_MS + 1);
        const rotated = registry.register({
          sessionId: 'ttl-takeover', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p', driverInstanceId: OTHER_INSTANCE,
        });
        expect(rotated.ownerLease).not.toBe(contender.ownerLease);
      } finally { cleanup(); }
    });

    test('assertCurrentOwner fails closed on a stale lease: wrong instance, wrong lease, expired', () => {
      const { store, cleanup } = makeStore();
      try {
        const { registry, advance } = newRegistry(store);
        const owned = registry.register({
          sessionId: 'stale-owner', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p', driverInstanceId: DRIVER_INSTANCE_ID,
        });
        // Wrong lease for the same instance.
        expect(() => registry.assertCurrentOwner('stale-owner', DRIVER_INSTANCE_ID, 'not-the-lease'))
          .toThrow(expect.objectContaining({ code: 'stale_owner' }));
        // Unknown session is a distinct 404-class error, not stale.
        expect(() => registry.assertCurrentOwner('missing', DRIVER_INSTANCE_ID, owned.ownerLease))
          .toThrow(expect.objectContaining({ code: 'session_not_found' }));
        // Correct lease before TTL passes.
        expect(() => registry.assertCurrentOwner('stale-owner', DRIVER_INSTANCE_ID, owned.ownerLease)).not.toThrow();
        // After the TTL elapses the live lease is revoked.
        advance(OCCUPANCY_TTL_MS + 1);
        expect(() => registry.assertCurrentOwner('stale-owner', DRIVER_INSTANCE_ID, owned.ownerLease))
          .toThrow(expect.objectContaining({ code: 'stale_owner' }));
        expect(registry.hasSession('stale-owner')).toBe(false);
      } finally { cleanup(); }
    });

    test('replay after restart recovers an accepted delayed tuple and promotes it atomically', () => {
      const dir = mkdtempSync(join(tmpdir(), 'bridge-registry-source-replay-'));
      const source = {
        producerEventId: 'AAAAAAAAAAAAAAAAAAAAAA',
        producerEventOrder: '00000000000000000000000000000001',
        event: {
          sessionId: 'tuple-session', provider: 'pi', type: 'done', status: 'idle',
          agentText: 'Done', projectName: 'p', workingDirectory: '/', harnessProvider: 'pi',
          createdAt: '2026-08-07T00:00:01.000Z',
        },
      } as const;
      try {
        const store = initializedStore(dir);
        const original = new AgentAdapterRegistry('host-1', store);
        original.register({
          sessionId: 'tuple-session', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p',
          status: 'working', driverInstanceId: DRIVER_INSTANCE_ID,
        });
        original.enqueueCommand(makeCommand('tuple-session'));
        const accepted = original.pushEventSource('tuple-session', source);
        expect(store.peekPendingEvents()).toEqual([]);
        store.dispose();

        const restartedStore = initializedStore(dir);
        const restarted = new AgentAdapterRegistry('host-1', restartedStore);
        restarted.register({
          sessionId: 'tuple-session', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p',
          status: 'working', driverInstanceId: DRIVER_INSTANCE_ID,
        });
        const replay = restarted.pushEventSource('tuple-session', source);
        expect(replay).toEqual({ ...accepted, disposition: 'duplicate' });
        expect(restarted.listSessions()[0]).toMatchObject({ status: 'idle', lastEventId: accepted.eventId });
        expect(restartedStore.peekPendingEvents()).toHaveLength(1);
      } finally { rmSync(dir, { recursive: true, force: true }); }
    });

    test('producer source tuple: duplicate replay returns the original eventId, order conflicts fail closed', () => {
      const { store, cleanup } = makeStore();
      try {
        const { registry } = newRegistry(store);
        registry.register({
          sessionId: 'tuple-session', provider: 'pi', projectName: 'p', cwd: '/', nameText: 'p', driverInstanceId: DRIVER_INSTANCE_ID,
        });
        const canonical = {
          sessionId: 'tuple-session', provider: 'pi', type: 'done', status: 'idle',
          agentText: 'Done', projectName: 'p', workingDirectory: '/', harnessProvider: 'pi', createdAt: '2026-08-07T00:00:01.000Z',
        };
        const first = registry.pushEventSource('tuple-session', {
          producerEventId: 'AAAAAAAAAAAAAAAAAAAAAA', producerEventOrder: '00000000000000000000000000000001', event: canonical,
        });
        expect(first.disposition).toBe('committed');
        // Exact replay of the same tuple is a duplicate carrying the original eventId.
        const replay = registry.pushEventSource('tuple-session', {
          producerEventId: 'AAAAAAAAAAAAAAAAAAAAAA', producerEventOrder: '00000000000000000000000000000001', event: canonical,
        });
        expect(replay.disposition).toBe('duplicate');
        expect(replay.eventId).toBe(first.eventId);
        // Same tuple, different content fingerprint: order/fingerprint conflict, zero mutation.
        const before = structuredClone(store.listSessions());
        expect(() => registry.pushEventSource('tuple-session', {
          producerEventId: 'AAAAAAAAAAAAAAAAAAAAAA', producerEventOrder: '00000000000000000000000000000001',
          event: { ...canonical, agentText: 'Different' },
        })).toThrow(expect.objectContaining({ code: 'order_conflict' }));
        expect(store.listSessions()).toEqual(before);
        // A non-strictly-increasing order is also an order conflict.
        expect(() => registry.pushEventSource('tuple-session', {
          producerEventId: 'AQEBAQEBAQEBAQEBAQEBAQ', producerEventOrder: '00000000000000000000000000000001', event: canonical,
        })).toThrow(expect.objectContaining({ code: 'order_conflict' }));
        // A strictly larger order with the same immutable content reuses the same
        // content-addressed eventId while advancing the source checkpoint.
        const next = registry.pushEventSource('tuple-session', {
          producerEventId: 'AQEBAQEBAQEBAQEBAQEBAQ', producerEventOrder: '00000000000000000000000000000002', event: canonical,
        });
        expect(next.disposition).toBe('committed');
        expect(next.eventId).toBe(first.eventId);
      } finally { cleanup(); }
    });
  });
});
